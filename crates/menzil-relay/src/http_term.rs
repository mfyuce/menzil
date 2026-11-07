//! The HTTP/1.1 terminator of terminated shares (protocol.md 6.3, expose design slice S-E9b).
//!
//! The front door (`crate::front_door`) terminates TLS for `<label>.t.H` and hands the plain
//! byte stream here, together with a way to open the share's `http:<label>` stream on its node.
//! [`serve`] reads requests from the client one at a time, checks and rewrites each, forwards it
//! over that one node stream, reads the response, checks and rewrites it and gives it back. It
//! is its own strict parser on top of `httparse`: a request it is not sure about is refused and
//! the connection closed, never repaired and passed on.
//!
//! # Requests
//!
//! * The head is at most [`MAX_HEAD`] (16 KiB, `431` past it) with at most [`MAX_HEADERS`] (64,
//!   `431`) headers, complete within [`HttpLimits::head_timeout`] (10 s) of its first byte
//!   (`408`); a client that sends nothing is closed at once (first request: after the same 10 s;
//!   later requests: after [`HttpLimits::keepalive_idle`]).
//! * Only CRLF ends a line: a bare LF, a bare CR, a NUL, any other control byte in a value, a
//!   header line that starts with white space (obs-fold) and a header name with white space
//!   before the colon are `400`.
//! * Only `HTTP/1.1` (`505` otherwise; `HTTP/0.9` has no version and is a `400`). The target is
//!   origin form (starts with `/`, visible ASCII only); absolute form, authority form
//!   (`CONNECT`) and `*` are `400`.
//! * Exactly one `Host`, equal to the SNI name after the optional `:port` is removed
//!   (case-insensitive); a malformed one is `400`, another name `421`. The connection is closed
//!   after either answer.
//! * Body framing is decided once: one `Content-Length` of 1 to 18 ASCII digits, or exactly one
//!   `Transfer-Encoding` whose whole value is `chunked` (lowercase; every other spelling or
//!   list is `501`), never both and never a duplicate (`400`). The framing is re-emitted in
//!   canonical form (`Content-Length: n`, or chunks re-encoded without extensions; trailers are
//!   read within a bound and dropped), so what the node's server sees is what was checked here.
//! * `Expect` is refused with `417` (the relay does not do the 100-continue dance), and
//!   `Upgrade` or `Connection: upgrade` with `501`: WebSocket through the terminator is not in
//!   this slice.
//! * Hop headers the client may have supplied are removed: `Connection` and every header it
//!   names, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Upgrade`, `Forwarded`, `X-Forwarded-*`,
//!   `X-Real-IP`, `Via`, `X-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`,
//!   `X-Cluster-Client-IP`, `Client-IP`, `X-Originating-IP`. `Connection` naming `Host`,
//!   `Content-Length` or `Transfer-Encoding` is `400`. The relay then adds one
//!   `X-Forwarded-For` (the real client address) and `X-Forwarded-Proto: https`.
//!
//! # Responses
//!
//! The node's response head is held to the same line rules (a violation is `502`, and so is a
//! head over [`MAX_HEAD`], more than [`RESPONSE_MAX_HEADERS`] headers, an interim `1xx`, a bad or
//! doubled framing header, or a head that does not come in time). Hop-by-hop headers are
//! removed as above. A `Set-Cookie` keeps its `Domain` attribute only if it names exactly the
//! share's own name; every other `Domain` (the share domain, `t.H`, a tenant's zone, any parent
//! of the name, a subdomain, an empty one) is removed from the cookie, which then stays host
//! only. The cookie itself is kept. A response without framing ends with the node's stream and
//! so does the client connection.
//!
//! # Streams and limits
//!
//! One node stream per client connection, opened when the first valid request head is in hand
//! (so a connection that never sends one costs the node nothing), and one request in flight:
//! the next head is read only when the response is complete. Bodies move through a 16 KiB
//! buffer in both directions; nothing is held back whole. A read or write that makes no progress
//! for [`HttpLimits::body_idle`] ends the connection. The node's stream is charged to the
//! tenant by the principal like any other (`crate::principal`).

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

/// The most bytes of a request or response head, the blank line included.
pub(crate) const MAX_HEAD: usize = 16 * 1024;
/// The most headers of a request.
pub(crate) const MAX_HEADERS: usize = 64;
/// The most headers of a response.
pub(crate) const RESPONSE_MAX_HEADERS: usize = 128;
/// The buffer bodies move through, and the size of one read.
const IO_BUFFER: usize = 16 * 1024;
/// The longest chunk-size line, or trailer line, accepted.
const MAX_CHUNK_LINE: usize = 128;
/// The most bytes of trailers read (and dropped) after the last chunk.
const MAX_TRAILER: usize = 8 * 1024;
/// How long an error answer may take to be written.
const REPLY_WRITE: Duration = Duration::from_secs(1);

/// The terminator's time limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpLimits {
    /// From its first byte to the end of a head (and the wait for the first request's first byte).
    pub head_timeout: Duration,
    /// How long a kept alive connection may wait for its next request's first byte.
    pub keepalive_idle: Duration,
    /// How long a body read or write, or the wait for the node's response, may make no progress.
    pub body_idle: Duration,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            head_timeout: Duration::from_secs(10),
            keepalive_idle: Duration::from_secs(60),
            body_idle: Duration::from_secs(120),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Buffered reading
// ---------------------------------------------------------------------------------------------

/// A byte stream with what was read from it and not used yet.
struct Conn<T> {
    io: T,
    buf: Vec<u8>,
}

enum ReadFail {
    /// End of stream or an I/O error.
    Closed,
    TimedOut,
}

impl<T: AsyncRead + Unpin> Conn<T> {
    fn new(io: T) -> Self {
        Self {
            io,
            buf: Vec::new(),
        }
    }

    /// Reads once, waiting at most `wait`; returns the bytes added (never 0).
    async fn fill(&mut self, wait: Duration) -> Result<usize, ReadFail> {
        let mut tmp = [0u8; IO_BUFFER];
        match timeout(wait, self.io.read(&mut tmp)).await {
            Err(_) => Err(ReadFail::TimedOut),
            Ok(Ok(0) | Err(_)) => Err(ReadFail::Closed),
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                Ok(n)
            }
        }
    }

    /// One line ended by CRLF, without it. A bare CR or LF, or a line over `max`, is malformed.
    async fn line(&mut self, max: usize, wait: Duration) -> Result<Vec<u8>, BodyFail> {
        loop {
            if let Some(lf) = self.buf.iter().position(|b| *b == b'\n') {
                if lf == 0 || self.buf[lf - 1] != b'\r' || lf - 1 > max {
                    return Err(BodyFail::Malformed);
                }
                let mut line: Vec<u8> = self.buf.drain(..=lf).collect();
                line.truncate(lf - 1);
                if line.contains(&b'\r') {
                    return Err(BodyFail::Malformed);
                }
                return Ok(line);
            }
            if self.buf.len() > max + 1 {
                return Err(BodyFail::Malformed);
            }
            self.fill(wait).await.map_err(BodyFail::from)?;
        }
    }
}

enum HeadFail {
    /// Nothing to answer: the peer left, or never began.
    Closed,
    /// It began and did not finish in time (408).
    TimedOut,
    /// Over the head limit (431).
    TooLarge,
    /// Not a head we accept (400).
    Malformed,
}

/// Whether `bytes[from..]` holds a NUL, a bare LF or a bare CR; `from` moves to what is settled.
/// A CR at the very end waits for the next byte.
fn framing_ok(bytes: &[u8], from: &mut usize) -> bool {
    let mut i = *from;
    while i < bytes.len() {
        match bytes[i] {
            0 => return false,
            b'\n' if i == 0 || bytes[i - 1] != b'\r' => return false,
            b'\r' => {
                if i + 1 == bytes.len() {
                    break;
                }
                if bytes[i + 1] != b'\n' {
                    return false;
                }
            }
            _ => {}
        }
        i += 1;
    }
    *from = i;
    true
}

/// The checks of a whole head: line endings, NUL, obs-fold.
fn head_lines_ok(head: &[u8]) -> bool {
    let mut from = 0;
    if !framing_ok(head, &mut from) || from != head.len() {
        return false;
    }
    // A line (after the first) that starts with white space continues the one before it.
    !head
        .windows(3)
        .any(|w| w[0] == b'\r' && w[1] == b'\n' && (w[2] == b' ' || w[2] == b'\t'))
}

fn find_end(bytes: &[u8], from: usize) -> Option<usize> {
    let start = from.saturating_sub(3);
    bytes[start..]
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| start + p + 4)
}

/// Reads one head (up to and including the blank line) from `conn`, leaving what follows in its
/// buffer.
async fn read_head<T: AsyncRead + Unpin>(
    conn: &mut Conn<T>,
    first_wait: Duration,
    head_timeout: Duration,
) -> Result<Vec<u8>, HeadFail> {
    let mut started = (!conn.buf.is_empty()).then(Instant::now);
    let mut framed = 0;
    let mut searched = 0;
    loop {
        if let Some(end) = find_end(&conn.buf, searched) {
            if end > MAX_HEAD {
                return Err(HeadFail::TooLarge);
            }
            let head: Vec<u8> = conn.buf.drain(..end).collect();
            if !head_lines_ok(&head) {
                return Err(HeadFail::Malformed);
            }
            return Ok(head);
        }
        searched = conn.buf.len();
        if !framing_ok(&conn.buf, &mut framed) {
            return Err(HeadFail::Malformed);
        }
        if conn.buf.len() >= MAX_HEAD {
            return Err(HeadFail::TooLarge);
        }
        let wait = match started {
            None => first_wait,
            Some(at) => (at + head_timeout).saturating_duration_since(Instant::now()),
        };
        if wait.is_zero() {
            return Err(HeadFail::TimedOut);
        }
        match conn.fill(wait).await {
            Ok(_) => {
                started.get_or_insert_with(Instant::now);
            }
            Err(ReadFail::Closed) => return Err(HeadFail::Closed),
            Err(ReadFail::TimedOut) => {
                return Err(if started.is_some() {
                    HeadFail::TimedOut
                } else {
                    HeadFail::Closed
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing and rewriting
// ---------------------------------------------------------------------------------------------

/// How a body is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    /// A response that ends with the node's stream.
    UntilClose,
}

/// A request that passed every check, ready for the node.
struct RequestPlan {
    /// The head to send, blank line included.
    head: Vec<u8>,
    body: Framing,
    /// The client asked to close after this exchange.
    close: bool,
    is_head: bool,
}

/// A response that passed every check, ready for the client.
struct ResponsePlan {
    head: Vec<u8>,
    body: Framing,
    /// The connection ends after this response.
    close: bool,
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = v {
        v = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = v {
        v = rest;
    }
    v
}

fn value_ok(v: &[u8]) -> bool {
    v.iter().all(|b| *b == b'\t' || (*b >= 0x20 && *b != 0x7f))
}

fn parse_len(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 18 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

fn is_token(v: &[u8]) -> bool {
    !v.is_empty()
        && v.iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

/// Headers that are the hop's own, or that name the client for the node: never passed.
fn is_stripped(lower: &str) -> bool {
    matches!(
        lower,
        "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "content-length"
            | "upgrade"
            | "forwarded"
            | "x-real-ip"
            | "via"
            | "x-client-ip"
            | "true-client-ip"
            | "cf-connecting-ip"
            | "x-cluster-client-ip"
            | "client-ip"
            | "x-originating-ip"
    ) || lower.starts_with("x-forwarded")
        || lower.starts_with("proxy-")
}

/// The tokens of the `Connection` headers: `(named headers, close, upgrade)`; `None` if one is not a
/// token or names a framing header.
fn connection_tokens(values: &[Vec<u8>]) -> Option<(Vec<String>, bool, bool)> {
    let mut named = Vec::new();
    let (mut close, mut upgrade) = (false, false);
    for value in values {
        for token in value.split(|b| *b == b',') {
            let token = trim_ows(token);
            if token.is_empty() {
                continue;
            }
            if !is_token(token) {
                return None;
            }
            let lower = String::from_utf8_lossy(token).to_ascii_lowercase();
            match lower.as_str() {
                "close" => close = true,
                "upgrade" => upgrade = true,
                "keep-alive" => {}
                "host" | "content-length" | "transfer-encoding" => return None,
                _ => named.push(lower),
            }
        }
    }
    Some((named, close, upgrade))
}

/// Which status answers a request that fails a check.
type Reject = u16;

/// The `Host` value without its port, lowercase; `None` if it is not `name` or `name:digits`.
fn host_name(value: &[u8]) -> Option<String> {
    let (name, port) = match value.iter().rposition(|b| *b == b':') {
        Some(p) => (&value[..p], Some(&value[p + 1..])),
        None => (value, None),
    };
    if let Some(port) = port
        && (port.is_empty() || port.len() > 5 || !port.iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    if name.is_empty()
        || !name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.')
    {
        return None;
    }
    Some(String::from_utf8_lossy(name).to_ascii_lowercase())
}

/// Checks a request head and builds what goes to the node.
fn process_request(head: &[u8], sni: &str, client_ip: &str) -> Result<RequestPlan, Reject> {
    let mut storage = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut storage);
    match req.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Err(httparse::Error::TooManyHeaders) => return Err(431),
        _ => return Err(400),
    }
    if req.version != Some(1) {
        return Err(505);
    }
    let (Some(method), Some(path)) = (req.method, req.path) else {
        return Err(400);
    };
    if method == "CONNECT"
        || !path.starts_with('/')
        || !path.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(400);
    }
    let mut host: Option<&[u8]> = None;
    let (mut length, mut chunked) = (None, false);
    let mut connection: Vec<Vec<u8>> = Vec::new();
    let mut te_seen = false;
    for header in req.headers.iter() {
        if !value_ok(header.value) {
            return Err(400);
        }
        let value = trim_ows(header.value);
        match header.name.to_ascii_lowercase().as_str() {
            "host" => {
                if host.replace(value).is_some() {
                    return Err(400);
                }
            }
            "content-length" => {
                if length.replace(parse_len(value).ok_or(400u16)?).is_some() {
                    return Err(400);
                }
            }
            "transfer-encoding" => {
                if std::mem::replace(&mut te_seen, true) {
                    return Err(400);
                }
                if value != b"chunked" {
                    return Err(501);
                }
                chunked = true;
            }
            "connection" => connection.push(value.to_vec()),
            "expect" => return Err(417),
            "upgrade" => return Err(501),
            _ => {}
        }
    }
    if length.is_some() && chunked {
        return Err(400);
    }
    let (named, close, upgrade) = connection_tokens(&connection).ok_or(400u16)?;
    if upgrade {
        return Err(501);
    }
    let host = host_name(host.ok_or(400u16)?).ok_or(400u16)?;
    if host != sni {
        return Err(421);
    }
    let body = match (length, chunked) {
        (Some(n), _) => Framing::Length(n),
        (None, true) => Framing::Chunked,
        (None, false) => Framing::None,
    };

    let mut out = Vec::with_capacity(head.len() + 128);
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    for header in req.headers.iter() {
        let lower = header.name.to_ascii_lowercase();
        if is_stripped(&lower) || named.contains(&lower) {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(trim_ows(header.value));
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("X-Forwarded-For: {client_ip}\r\n").as_bytes());
    out.extend_from_slice(b"X-Forwarded-Proto: https\r\n");
    match body {
        Framing::Length(n) => out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes()),
        Framing::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
        _ => {}
    }
    out.extend_from_slice(b"\r\n");
    Ok(RequestPlan {
        head: out,
        body,
        close,
        is_head: method == "HEAD",
    })
}

/// `value` of a `Set-Cookie` without any `Domain` attribute other than `host` itself.
fn clean_set_cookie(value: &[u8], host: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    for (i, segment) in value.split(|b| *b == b';').enumerate() {
        if i == 0 {
            out.extend_from_slice(segment);
            continue;
        }
        let attribute = trim_ows(segment);
        let (name, val) = match attribute.iter().position(|b| *b == b'=') {
            Some(p) => (trim_ows(&attribute[..p]), trim_ows(&attribute[p + 1..])),
            None => (attribute, &[][..]),
        };
        if name.eq_ignore_ascii_case(b"domain") {
            let mut domain = val.to_ascii_lowercase();
            while domain.first() == Some(&b'.') {
                domain.remove(0);
            }
            while domain.last() == Some(&b'.') {
                domain.pop();
            }
            if domain != host.as_bytes() {
                continue;
            }
        }
        out.extend_from_slice(b"; ");
        out.extend_from_slice(attribute);
    }
    out
}

/// Checks a response head and builds what goes to the client; `None` is a 502.
fn process_response(head: &[u8], is_head: bool, host: &str) -> Option<ResponsePlan> {
    let mut storage = [httparse::EMPTY_HEADER; RESPONSE_MAX_HEADERS];
    let mut res = httparse::Response::new(&mut storage);
    match res.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        _ => return None,
    }
    let version = res.version?;
    let code = res.code?;
    if version > 1 || !(200..=599).contains(&code) {
        return None;
    }
    let (mut length, mut chunked, mut te_seen) = (None, false, false);
    let mut connection: Vec<Vec<u8>> = Vec::new();
    for header in res.headers.iter() {
        if !value_ok(header.value) {
            return None;
        }
        let value = trim_ows(header.value);
        match header.name.to_ascii_lowercase().as_str() {
            "content-length" => {
                if length.replace(parse_len(value)?).is_some() {
                    return None;
                }
            }
            "transfer-encoding" => {
                if std::mem::replace(&mut te_seen, true) || value != b"chunked" {
                    return None;
                }
                chunked = true;
            }
            "connection" => connection.push(value.to_vec()),
            "upgrade" => return None,
            _ => {}
        }
    }
    if length.is_some() && chunked {
        return None;
    }
    let (named, close_token, upgrade) = connection_tokens(&connection)?;
    if upgrade {
        return None;
    }
    let no_body = is_head || code == 204 || code == 304;
    let body = if no_body {
        Framing::None
    } else if chunked {
        Framing::Chunked
    } else if let Some(n) = length {
        Framing::Length(n)
    } else {
        Framing::UntilClose
    };
    let close = close_token || version == 0 || body == Framing::UntilClose;
    let reason = res
        .reason
        .filter(|r| r.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b)))
        .unwrap_or("");

    let mut out = Vec::with_capacity(head.len() + 64);
    out.extend_from_slice(format!("HTTP/1.1 {code} {reason}\r\n").as_bytes());
    for header in res.headers.iter() {
        let lower = header.name.to_ascii_lowercase();
        if is_stripped(&lower) || named.contains(&lower) {
            continue;
        }
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        if lower == "set-cookie" {
            out.extend_from_slice(&clean_set_cookie(trim_ows(header.value), host));
        } else {
            out.extend_from_slice(trim_ows(header.value));
        }
        out.extend_from_slice(b"\r\n");
    }
    if let Some(n) = length
        && !chunked
    {
        out.extend_from_slice(format!("Content-Length: {n}\r\n").as_bytes());
    }
    if chunked {
        out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
    }
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Some(ResponsePlan {
        head: out,
        body,
        close,
    })
}

fn reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        408 => "Request Timeout",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

// ---------------------------------------------------------------------------------------------
// Moving bytes
// ---------------------------------------------------------------------------------------------

enum BodyFail {
    /// The source ended or failed.
    Closed,
    TimedOut,
    /// The framing is not valid.
    Malformed,
    /// The destination ended, failed or stalled.
    Sink,
}

impl From<ReadFail> for BodyFail {
    fn from(fail: ReadFail) -> Self {
        match fail {
            ReadFail::Closed => Self::Closed,
            ReadFail::TimedOut => Self::TimedOut,
        }
    }
}

async fn put<D: AsyncWrite + Unpin>(
    dst: &mut D,
    bytes: &[u8],
    wait: Duration,
) -> Result<(), BodyFail> {
    match timeout(wait, dst.write_all(bytes)).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(BodyFail::Sink),
    }
}

/// Moves `n` bytes from `src` to `dst`.
async fn copy_exact<S, D>(
    src: &mut Conn<S>,
    dst: &mut D,
    mut n: u64,
    wait: Duration,
) -> Result<(), BodyFail>
where
    S: AsyncRead + Unpin,
    D: AsyncWrite + Unpin,
{
    while n > 0 {
        if src.buf.is_empty() {
            src.fill(wait).await?;
        }
        let take = usize::try_from(n).map_or(src.buf.len(), |n| n.min(src.buf.len()));
        let piece: Vec<u8> = src.buf.drain(..take).collect();
        put(dst, &piece, wait).await?;
        n -= take as u64;
    }
    Ok(())
}

/// Moves a body framed as `framing` from `src` to `dst`; chunked bodies are re-encoded (no
/// extensions, trailers dropped).
async fn copy_body<S, D>(
    src: &mut Conn<S>,
    dst: &mut D,
    framing: Framing,
    wait: Duration,
) -> Result<(), BodyFail>
where
    S: AsyncRead + Unpin,
    D: AsyncWrite + Unpin,
{
    match framing {
        Framing::None => Ok(()),
        Framing::Length(n) => copy_exact(src, dst, n, wait).await,
        Framing::UntilClose => loop {
            if src.buf.is_empty() {
                match src.fill(wait).await {
                    Ok(_) => {}
                    Err(ReadFail::Closed) => return Ok(()),
                    Err(ReadFail::TimedOut) => return Err(BodyFail::TimedOut),
                }
            }
            let piece = std::mem::take(&mut src.buf);
            put(dst, &piece, wait).await?;
        },
        Framing::Chunked => loop {
            let line = src.line(MAX_CHUNK_LINE, wait).await?;
            if line.is_empty() || line.len() > 16 || !line.iter().all(u8::is_ascii_hexdigit) {
                return Err(BodyFail::Malformed);
            }
            let size = u64::from_str_radix(&String::from_utf8_lossy(&line), 16)
                .map_err(|_| BodyFail::Malformed)?;
            if size == 0 {
                let mut trailer = 0usize;
                loop {
                    let line = src.line(MAX_CHUNK_LINE, wait).await?;
                    if line.is_empty() {
                        break;
                    }
                    trailer += line.len() + 2;
                    if trailer > MAX_TRAILER {
                        return Err(BodyFail::Malformed);
                    }
                }
                return put(dst, b"0\r\n\r\n", wait).await;
            }
            put(dst, format!("{size:x}\r\n").as_bytes(), wait).await?;
            copy_exact(src, dst, size, wait).await?;
            if !src.line(0, wait).await?.is_empty() {
                return Err(BodyFail::Malformed);
            }
            put(dst, b"\r\n", wait).await?;
        },
    }
}

/// Answers `code` with no body and closes.
async fn reply<T: AsyncWrite + Unpin>(io: &mut T, code: u16) {
    let text = format!(
        "HTTP/1.1 {code} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        reason(code)
    );
    let _ = timeout(REPLY_WRITE, io.write_all(text.as_bytes())).await;
    let _ = timeout(REPLY_WRITE, io.flush()).await;
    let _ = timeout(REPLY_WRITE, io.shutdown()).await;
}

// ---------------------------------------------------------------------------------------------
// The connection
// ---------------------------------------------------------------------------------------------

/// Serves one client connection (TLS already terminated) for the share named `host` (the SNI
/// name): reads requests from `client`, forwards them over the node stream `open` gives (called
/// at most once, when the first valid request is in hand; `None` is a 502), and writes the
/// responses. `still_served` is asked before each request is forwarded; `false` closes the
/// connection. Returns when the connection is over.
pub(crate) async fn serve<C, N, O, Fut>(
    client: C,
    host: &str,
    client_ip: IpAddr,
    limits: HttpLimits,
    mut still_served: impl FnMut() -> bool,
    open: O,
) where
    C: AsyncRead + AsyncWrite + Unpin,
    N: AsyncRead + AsyncWrite + Unpin,
    O: FnOnce() -> Fut,
    Fut: Future<Output = Option<N>>,
{
    let ip = client_ip.to_canonical().to_string();
    let mut client = Conn::new(client);
    let mut node: Option<Conn<N>> = None;
    let mut open = Some(open);
    let mut first = true;
    loop {
        let wait = if first {
            limits.head_timeout
        } else {
            limits.keepalive_idle
        };
        first = false;
        let head = match read_head(&mut client, wait, limits.head_timeout).await {
            Ok(head) => head,
            Err(HeadFail::Closed) => break,
            Err(HeadFail::TimedOut) => {
                reply(&mut client.io, 408).await;
                return;
            }
            Err(HeadFail::TooLarge) => {
                reply(&mut client.io, 431).await;
                return;
            }
            Err(HeadFail::Malformed) => {
                reply(&mut client.io, 400).await;
                return;
            }
        };
        let plan = match process_request(&head, host, &ip) {
            Ok(plan) => plan,
            Err(code) => {
                reply(&mut client.io, code).await;
                return;
            }
        };
        if !still_served() {
            return;
        }
        if node.is_none() {
            let opened = match open.take() {
                Some(open) => open().await,
                None => None,
            };
            match opened {
                Some(stream) => node = Some(Conn::new(stream)),
                None => {
                    reply(&mut client.io, 502).await;
                    return;
                }
            }
        }
        let Some(node_conn) = node.as_mut() else {
            return;
        };
        if put(&mut node_conn.io, &plan.head, limits.body_idle)
            .await
            .is_err()
        {
            reply(&mut client.io, 502).await;
            return;
        }
        match copy_body(&mut client, &mut node_conn.io, plan.body, limits.body_idle).await {
            Ok(()) => {}
            Err(BodyFail::Malformed) => {
                reply(&mut client.io, 400).await;
                return;
            }
            Err(_) => return,
        }
        if timeout(limits.body_idle, node_conn.io.flush())
            .await
            .is_err()
        {
            return;
        }
        let head = match read_head(node_conn, limits.body_idle, limits.head_timeout).await {
            Ok(head) => head,
            Err(_) => {
                reply(&mut client.io, 502).await;
                return;
            }
        };
        let Some(response) = process_response(&head, plan.is_head, host) else {
            reply(&mut client.io, 502).await;
            return;
        };
        if put(&mut client.io, &response.head, limits.body_idle)
            .await
            .is_err()
        {
            return;
        }
        if copy_body(node_conn, &mut client.io, response.body, limits.body_idle)
            .await
            .is_err()
        {
            return;
        }
        if timeout(limits.body_idle, client.io.flush()).await.is_err() {
            return;
        }
        // Bytes the node sent beyond its response are a desynchronised stream: end it.
        if response.close || plan.close || !node_conn.buf.is_empty() {
            break;
        }
    }
    let _ = timeout(REPLY_WRITE, client.io.shutdown()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{DuplexStream, duplex};

    const HOST: &str = "web.t.s.example.test";
    const IP: &str = "203.0.113.7";

    fn limits() -> HttpLimits {
        HttpLimits {
            head_timeout: Duration::from_millis(400),
            keepalive_idle: Duration::from_millis(600),
            body_idle: Duration::from_millis(800),
        }
    }

    /// What one connection did.
    struct Outcome {
        /// Everything the client got.
        client: Vec<u8>,
        /// Everything the node got.
        node: Vec<u8>,
        /// How often the node stream was opened.
        opened: usize,
    }

    /// Runs one connection: the client writes `request` and then closes its writing side; the
    /// fake node answers `reply` as soon as it has the first bytes (and never opens if the
    /// terminator refuses before forwarding).
    async fn exchange(request: &[u8], reply: &[u8]) -> Outcome {
        exchange_with(request, reply, limits(), || true).await
    }

    async fn exchange_with(
        request: &[u8],
        reply: &[u8],
        limits: HttpLimits,
        still: impl FnMut() -> bool + Send + 'static,
    ) -> Outcome {
        let (mut test_client, srv_client) = duplex(1 << 20);
        let (srv_node, mut test_node) = duplex(1 << 20);
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&opened);
        let server = tokio::spawn(async move {
            serve(
                srv_client,
                HOST,
                IP.parse().unwrap(),
                limits,
                still,
                move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Some(srv_node)
                },
            )
            .await;
        });
        let reply = reply.to_vec();
        let node = tokio::spawn(async move {
            let mut seen = Vec::new();
            let mut sent = false;
            let mut chunk = [0u8; 4096];
            loop {
                match test_node.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        seen.extend_from_slice(&chunk[..n]);
                        if !sent {
                            sent = true;
                            let _ = test_node.write_all(&reply).await;
                        }
                    }
                }
            }
            seen
        });
        test_client.write_all(request).await.unwrap();
        test_client.shutdown().await.unwrap();
        let mut client = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), test_client.read_to_end(&mut client))
            .await;
        server.await.unwrap();
        let node = node.await.unwrap();
        Outcome {
            client,
            node,
            opened: opened.load(Ordering::SeqCst),
        }
    }

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

    fn status(out: &Outcome) -> String {
        String::from_utf8_lossy(&out.client)
            .lines()
            .next()
            .unwrap_or("")
            .to_string()
    }

    /// A request refused before the node saw anything, with `code`.
    async fn refused(request: &[u8], code: u16) {
        let out = exchange(request, OK).await;
        assert!(
            status(&out).starts_with(&format!("HTTP/1.1 {code} ")),
            "wanted {code} for {:?}, got {:?}",
            String::from_utf8_lossy(request),
            String::from_utf8_lossy(&out.client)
        );
        assert_eq!(out.opened, 0, "the node stream was opened");
        assert!(out.node.is_empty());
        assert!(
            String::from_utf8_lossy(&out.client).contains("Connection: close"),
            "the connection is closed after a refusal"
        );
    }

    fn get(extra: &str) -> Vec<u8> {
        format!("GET /x HTTP/1.1\r\nHost: {HOST}\r\n{extra}\r\n").into_bytes()
    }

    fn sent(out: &Outcome) -> String {
        String::from_utf8_lossy(&out.node).to_string()
    }

    #[tokio::test]
    async fn a_plain_request_is_forwarded_and_answered() {
        let out = exchange(&get("Accept: */*\r\n"), OK).await;
        assert!(out.client.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(out.client.ends_with(b"\r\n\r\nok"));
        let node = sent(&out);
        assert!(node.starts_with("GET /x HTTP/1.1\r\n"), "{node}");
        assert!(node.contains(&format!("Host: {HOST}\r\n")));
        assert!(node.contains("Accept: */*\r\n"));
        assert!(node.contains(&format!("X-Forwarded-For: {IP}\r\n")));
        assert!(node.contains("X-Forwarded-Proto: https\r\n"));
        assert_eq!(out.opened, 1);
    }

    #[tokio::test]
    async fn content_length_with_transfer_encoding_is_refused_in_both_orders() {
        // CL.TE and TE.CL.
        refused(
            &get("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n"),
            400,
        )
        .await;
        refused(
            &get("Transfer-Encoding: chunked\r\nContent-Length: 4\r\n"),
            400,
        )
        .await;
    }

    #[tokio::test]
    async fn transfer_encoding_must_be_exactly_chunked() {
        // TE.TE obfuscations.
        for te in [
            "Transfer-Encoding: Chunked\r\n",
            "Transfer-Encoding: CHUNKED\r\n",
            "Transfer-Encoding: chunked, identity\r\n",
            "Transfer-Encoding: identity, chunked\r\n",
            "Transfer-Encoding: xchunked\r\n",
            "Transfer-Encoding: chunked;x=1\r\n",
            "Transfer-Encoding: identity\r\n",
            "Transfer-Encoding:\r\n",
        ] {
            refused(&get(te), 501).await;
        }
        // Whitespace before the colon is not a header name; a vertical tab is not white space.
        refused(&get("Transfer-Encoding : chunked\r\n"), 400).await;
        refused(&get("Transfer-Encoding: chunked\x0b\r\n"), 400).await;
        refused(&get("Transfer-Encoding\t: chunked\r\n"), 400).await;
        // Two of them.
        refused(
            &get("Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n"),
            400,
        )
        .await;
    }

    #[tokio::test]
    async fn a_bad_or_doubled_content_length_is_refused() {
        refused(&get("Content-Length: 1\r\nContent-Length: 1\r\n"), 400).await;
        refused(&get("Content-Length: 1\r\nContent-Length: 2\r\n"), 400).await;
        refused(&get("Content-Length: 1, 1\r\n"), 400).await;
        refused(&get("Content-Length: +1\r\n"), 400).await;
        refused(&get("Content-Length: -1\r\n"), 400).await;
        refused(&get("Content-Length: 0x10\r\n"), 400).await;
        refused(&get("Content-Length: \r\n"), 400).await;
        refused(&get("Content-Length: 99999999999999999999\r\n"), 400).await;
        refused(&get("Content-Length: 1 2\r\n"), 400).await;
    }

    #[tokio::test]
    async fn obs_fold_and_bare_line_endings_are_refused() {
        refused(&get("X-A: b\r\n c\r\n"), 400).await;
        refused(&get("X-A: b\r\n\tc\r\n"), 400).await;
        refused(format!("GET /x HTTP/1.1\nHost: {HOST}\n\n").as_bytes(), 400).await;
        refused(
            format!("GET /x HTTP/1.1\r\nHost: {HOST}\nX-A: b\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET /x HTTP/1.1\r\nHost: {HOST}\r\nX-A: b\rc\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(&get("X-A: b\0c\r\n"), 400).await;
        refused(&get("X-A: b\x01c\r\n"), 400).await;
        refused(&get("X-A: b\x7fc\r\n"), 400).await;
    }

    #[tokio::test]
    async fn a_request_that_is_not_http_1_1_origin_form_is_refused() {
        refused(b"GET /x\r\n\r\n", 400).await;
        refused(
            format!("GET /x HTTP/1.0\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            505,
        )
        .await;
        refused(
            format!("GET /x HTTP/2.0\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET http://{HOST}/x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("OPTIONS * HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET x HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
    }

    #[tokio::test]
    async fn header_injection_through_the_path_or_host_is_refused() {
        // A path never carries a space or a control byte (httparse and the visible ASCII rule).
        refused(
            format!("GET /a b HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET /a\x01b HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET /\u{e9} HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        // Host with characters outside a name, or one more header folded into it.
        refused(
            format!("GET / HTTP/1.1\r\nHost: {HOST}\x01\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET / HTTP/1.1\r\nHost: {HOST} X-Evil: 1\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET / HTTP/1.1\r\nHost: {HOST},evil.test\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        refused(
            format!("GET / HTTP/1.1\r\nHost: {HOST}:80x\r\n\r\n").as_bytes(),
            400,
        )
        .await;
        // The percent encoded CRLF stays a path byte: it is passed as is and never decoded.
        let out = exchange(
            format!("GET /a%0d%0aX-Evil:%201 HTTP/1.1\r\nHost: {HOST}\r\n\r\n").as_bytes(),
            OK,
        )
        .await;
        assert!(sent(&out).starts_with("GET /a%0d%0aX-Evil:%201 HTTP/1.1\r\n"));
        assert!(!sent(&out).contains("\r\nX-Evil"));
    }

    #[tokio::test]
    async fn host_must_equal_the_sni_name() {
        // Missing, doubled, other names, a parent, a longer name, a trailing dot.
        refused(b"GET / HTTP/1.1\r\n\r\n", 400).await;
        refused(&get(&format!("Host: {HOST}\r\n")), 400).await;
        for other in [
            "other.t.s.example.test",
            "s.example.test",
            "t.s.example.test",
            "x.web.t.s.example.test",
            "web.s.example.test",
            "web.t.s.example.test.",
            "web.t.s.example.test.evil.test",
        ] {
            refused(
                format!("GET / HTTP/1.1\r\nHost: {other}\r\n\r\n").as_bytes(),
                421,
            )
            .await;
        }
        // Case and a port are not a difference.
        for ok in [
            HOST.to_ascii_uppercase(),
            format!("{HOST}:443"),
            format!("{}:8443", HOST.to_ascii_uppercase()),
        ] {
            let out = exchange(
                format!("GET / HTTP/1.1\r\nHost: {ok}\r\n\r\n").as_bytes(),
                OK,
            )
            .await;
            assert!(out.client.starts_with(b"HTTP/1.1 200 OK"), "{ok}");
        }
        // Absolute form pointing elsewhere with a good Host is refused above; a different
        // authority in Host with the SNI right never reaches the node.
        let out = exchange(b"GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n", OK).await;
        assert_eq!(out.opened, 0);
    }

    #[tokio::test]
    async fn expect_and_upgrade_are_refused() {
        refused(&get("Expect: 100-continue\r\n"), 417).await;
        refused(&get("Upgrade: websocket\r\nConnection: Upgrade\r\n"), 501).await;
        refused(&get("Connection: upgrade\r\n"), 501).await;
        refused(&get("Upgrade: h2c\r\n"), 501).await;
    }

    #[tokio::test]
    async fn the_head_has_a_size_a_header_count_and_a_time() {
        // 16 KiB head limit.
        let mut big = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nX-A: ").into_bytes();
        big.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        big.extend_from_slice(b"\r\n\r\n");
        refused(&big, 431).await;
        // Exactly at the limit is fine.
        let prefix = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nX-A: ");
        let fill = MAX_HEAD - prefix.len() - 4;
        let mut fits = prefix.into_bytes();
        fits.extend(std::iter::repeat_n(b'a', fill));
        fits.extend_from_slice(b"\r\n\r\n");
        assert_eq!(fits.len(), MAX_HEAD);
        let out = exchange(&fits, OK).await;
        assert!(out.client.starts_with(b"HTTP/1.1 200"), "at the limit");
        // 64 headers (Host included) are fine, 65 are not.
        let many = |n: usize| {
            let mut head = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\n");
            for i in 0..n - 1 {
                head.push_str(&format!("X-{i}: v\r\n"));
            }
            head.push_str("\r\n");
            head.into_bytes()
        };
        let out = exchange(&many(64), OK).await;
        assert!(out.client.starts_with(b"HTTP/1.1 200"), "64 headers");
        refused(&many(65), 431).await;
    }

    #[tokio::test]
    async fn a_dribbled_head_is_cut_off_at_the_head_timeout() {
        // Slowloris: a byte at a time, each well inside the idle time, never finishing.
        let (mut test_client, srv_client) = duplex(1 << 16);
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&opened);
        let server = tokio::spawn(async move {
            serve::<_, DuplexStream, _, _>(
                srv_client,
                HOST,
                IP.parse().unwrap(),
                limits(),
                || true,
                move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    None
                },
            )
            .await;
        });
        let started = Instant::now();
        let dribble = tokio::spawn(async move {
            let head = format!("GET / HTTP/1.1\r\nHost: {HOST}\r\nX-A: ");
            for b in head.bytes().chain(std::iter::repeat(b'a')).take(2_000) {
                if test_client.write_all(&[b]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            test_client
        });
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("the terminator never cut the dribbled head off")
            .unwrap();
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(350) && took < Duration::from_millis(2_000),
            "ended after {took:?}"
        );
        assert_eq!(opened.load(Ordering::SeqCst), 0);
        dribble.abort();
    }

    #[tokio::test]
    async fn a_silent_connection_is_closed_without_an_answer() {
        let (mut test_client, srv_client) = duplex(1 << 16);
        let server = tokio::spawn(async move {
            serve::<_, DuplexStream, _, _>(
                srv_client,
                HOST,
                IP.parse().unwrap(),
                limits(),
                || true,
                || async { None },
            )
            .await;
        });
        server.await.unwrap();
        let mut got = Vec::new();
        test_client.read_to_end(&mut got).await.unwrap();
        assert!(got.is_empty(), "{got:?}");
    }

    #[tokio::test]
    async fn client_supplied_hop_and_address_headers_are_replaced() {
        let out = exchange(
            &get(
                "Forwarded: for=6.6.6.6\r\nX-Forwarded-For: 6.6.6.6\r\nX-Forwarded-Proto: http\r\n\
                 X-Forwarded-Host: evil.test\r\nX-Forwarded-Port: 1\r\nX-Real-IP: 6.6.6.6\r\n\
                 Via: 1.1 evil\r\nTrue-Client-IP: 6.6.6.6\r\nCF-Connecting-IP: 6.6.6.6\r\n\
                 X-Client-IP: 6.6.6.6\r\nKeep-Alive: timeout=5\r\nProxy-Authorization: x\r\n\
                 TE: trailers\r\nTrailer: X\r\nConnection: X-Secret, keep-alive\r\n\
                 X-Secret: s\r\nX-Keep: kept\r\n",
            ),
            OK,
        )
        .await;
        let node = sent(&out);
        let lower = node.to_ascii_lowercase();
        for gone in [
            "forwarded:",
            "6.6.6.6",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-real-ip",
            "via:",
            "true-client-ip",
            "cf-connecting-ip",
            "x-client-ip",
            "keep-alive",
            "proxy-authorization",
            "te:",
            "trailer",
            "connection",
            "x-secret",
        ] {
            assert!(!lower.contains(gone), "{gone} survived in {node}");
        }
        assert_eq!(lower.matches("x-forwarded-for").count(), 1);
        assert_eq!(lower.matches("x-forwarded-proto").count(), 1);
        assert!(node.contains(&format!("X-Forwarded-For: {IP}\r\n")));
        assert!(node.contains("X-Forwarded-Proto: https\r\n"));
        assert!(node.contains("X-Keep: kept\r\n"));
    }

    #[tokio::test]
    async fn connection_may_not_name_a_framing_header_or_host() {
        refused(&get("Connection: Content-Length\r\n"), 400).await;
        refused(&get("Connection: transfer-encoding\r\n"), 400).await;
        refused(&get("Connection: host\r\n"), 400).await;
        refused(&get("Connection: bad token\r\n"), 400).await;
    }

    #[tokio::test]
    async fn a_content_length_body_is_forwarded_whole_and_no_more() {
        let out = exchange(
            format!("POST /p HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 5\r\n\r\nhello")
                .as_bytes(),
            OK,
        )
        .await;
        assert!(sent(&out).contains("Content-Length: 5\r\n"));
        assert!(sent(&out).ends_with("\r\n\r\nhello"));
        // Bytes after the body are the next request, not part of this one: here a smuggled
        // request that is itself refused (Host differs) never reaches the node.
        let smuggled = format!(
            "POST /p HTTP/1.1\r\nHost: {HOST}\r\nContent-Length: 5\r\n\r\nhelloGET /admin HTTP/1.1\r\nHost: evil.test\r\n\r\n"
        );
        let out = exchange(smuggled.as_bytes(), OK).await;
        assert!(!sent(&out).contains("/admin"));
        assert!(String::from_utf8_lossy(&out.client).contains("421"));
    }

    #[tokio::test]
    async fn a_chunked_body_is_re_encoded_without_extensions_or_trailers() {
        let request = format!(
            "POST /p HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n\
             5\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n"
        );
        let out = exchange(request.as_bytes(), OK).await;
        let node = sent(&out);
        assert!(node.contains("Transfer-Encoding: chunked\r\n"));
        assert!(
            node.ends_with("\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"),
            "{node}"
        );
        assert!(!node.contains("X-Trailer"));
        assert!(out.client.starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn a_malformed_chunked_body_is_refused() {
        for body in [
            "5;ext=1\r\nhello\r\n0\r\n\r\n",
            "+5\r\nhello\r\n0\r\n\r\n",
            "0x5\r\nhello\r\n0\r\n\r\n",
            "\r\nhello\r\n0\r\n\r\n",
            "5\r\nhelloXX0\r\n\r\n",
            "5\nhello\r\n0\r\n\r\n",
            "ffffffffffffffffff\r\nhello\r\n",
            "zz\r\nhello\r\n0\r\n\r\n",
        ] {
            let request = format!(
                "POST /p HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
            );
            let out = exchange(request.as_bytes(), OK).await;
            assert!(
                String::from_utf8_lossy(&out.client).starts_with("HTTP/1.1 400"),
                "{body:?} -> {:?}",
                String::from_utf8_lossy(&out.client)
            );
        }
    }

    #[tokio::test]
    async fn a_response_is_cleaned_before_the_client_sees_it() {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close, X-Hidden\r\n\
                      Keep-Alive: timeout=1\r\nX-Hidden: h\r\nX-Shown: s\r\nTrailer: t\r\n\r\nok";
        let out = exchange(&get(""), reply).await;
        let text = String::from_utf8_lossy(&out.client).to_string();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("X-Shown: s\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(!text.to_ascii_lowercase().contains("x-hidden"));
        assert!(!text.to_ascii_lowercase().contains("keep-alive"));
        assert!(!text.to_ascii_lowercase().contains("trailer"));
        assert!(text.ends_with("\r\n\r\nok"));
    }

    #[tokio::test]
    async fn a_response_that_would_split_or_confuse_framing_is_a_502() {
        for reply in [
            // bare LF, bare CR, NUL, obs-fold in the response head
            &b"HTTP/1.1 200 OK\nContent-Length: 0\n\n"[..],
            b"HTTP/1.1 200 OK\r\nX-A: b\nX-B: c\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: b\rX-B: c\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: b\0\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX-A: b\r\n c\r\nContent-Length: 0\r\n\r\n",
            // both framings, doubled or odd length, odd encodings
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nok",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            // interim and switching statuses
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            // not a response
            b"garbage\r\n\r\n",
            b"HTTP/2 200\r\n\r\n",
        ] {
            let out = exchange(&get(""), reply).await;
            assert!(
                String::from_utf8_lossy(&out.client).starts_with("HTTP/1.1 502"),
                "{:?} -> {:?}",
                String::from_utf8_lossy(reply),
                String::from_utf8_lossy(&out.client)
            );
        }
    }

    #[tokio::test]
    async fn an_oversized_response_head_is_a_502() {
        let mut reply = b"HTTP/1.1 200 OK\r\nX-A: ".to_vec();
        reply.extend(std::iter::repeat_n(b'a', MAX_HEAD));
        reply.extend_from_slice(b"\r\nContent-Length: 0\r\n\r\n");
        let out = exchange(&get(""), &reply).await;
        assert!(String::from_utf8_lossy(&out.client).starts_with("HTTP/1.1 502"));
    }

    async fn cookie(set: &str) -> String {
        let reply = format!("HTTP/1.1 200 OK\r\nSet-Cookie: {set}\r\nContent-Length: 0\r\n\r\n");
        let out = exchange(&get(""), reply.as_bytes()).await;
        let text = String::from_utf8_lossy(&out.client).to_string();
        text.lines()
            .find(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
            .unwrap_or("")
            .to_string()
    }

    #[tokio::test]
    async fn a_set_cookie_domain_above_the_name_is_dropped() {
        // The attribute goes, the cookie stays host only.
        for domain in [
            "s.example.test",
            ".s.example.test",
            "t.s.example.test",
            "ali.s.example.test",
            "ali.t.s.example.test",
            "example.test",
            "test",
            "WEB.t.s.example.test.evil",
            "t.s.example.test.",
            "",
        ] {
            let line = cookie(&format!("a=b; Path=/; Domain={domain}; Secure")).await;
            assert_eq!(line, "Set-Cookie: a=b; Path=/; Secure", "Domain={domain}");
        }
        // The name itself is the one Domain kept, in any case, with or without a dot.
        let line = cookie(&format!("a=b; domain=.{}", HOST.to_ascii_uppercase())).await;
        assert!(line.to_ascii_lowercase().contains("domain=."), "{line}");
        // Other attributes and the value are untouched; `domain` inside the value is not an attribute.
        assert_eq!(
            cookie("domain=s.example.test; HttpOnly").await,
            "Set-Cookie: domain=s.example.test; HttpOnly"
        );
        assert_eq!(cookie("a=b").await, "Set-Cookie: a=b");
    }

    #[tokio::test]
    async fn a_chunked_response_is_re_encoded_and_a_head_response_has_no_body() {
        let reply = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        let out = exchange(&get(""), reply).await;
        assert!(
            out.client
                .ends_with(b"Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"),
            "{:?}",
            String::from_utf8_lossy(&out.client)
        );
        let head = format!("HEAD / HTTP/1.1\r\nHost: {HOST}\r\n\r\n");
        let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
        let out = exchange(head.as_bytes(), reply).await;
        assert!(out.client.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(out.client.ends_with(b"Content-Length: 1000\r\n\r\n"));
    }

    #[tokio::test]
    async fn a_response_without_framing_ends_with_the_connection() {
        let reply = b"HTTP/1.1 200 OK\r\n\r\nuntil the end";
        let out = exchange(&get(""), reply).await;
        let text = String::from_utf8_lossy(&out.client).to_string();
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\nuntil the end"), "{text}");
    }

    async fn head_of(stream: &mut DuplexStream) -> Vec<u8> {
        let mut got = Vec::new();
        let mut one = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut one).await.unwrap();
            got.push(one[0]);
        }
        got
    }

    #[tokio::test]
    async fn two_requests_share_one_node_stream_one_at_a_time() {
        let (mut test_client, srv_client) = duplex(1 << 16);
        let (srv_node, mut test_node) = duplex(1 << 16);
        let opened = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&opened);
        let server = tokio::spawn(async move {
            serve(
                srv_client,
                HOST,
                IP.parse().unwrap(),
                limits(),
                || true,
                move || async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Some(srv_node)
                },
            )
            .await;
        });
        for i in 0..2 {
            test_client
                .write_all(&get(&format!("X-N: {i}\r\n")))
                .await
                .unwrap();
            let seen = head_of(&mut test_node).await;
            assert!(String::from_utf8_lossy(&seen).contains(&format!("X-N: {i}")));
            test_node.write_all(OK).await.unwrap();
            let answer = head_of(&mut test_client).await;
            assert!(answer.starts_with(b"HTTP/1.1 200"));
            let mut body = [0u8; 2];
            test_client.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"ok");
        }
        assert_eq!(opened.load(Ordering::SeqCst), 1);
        // An idle connection is closed after the keep alive time.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), test_client.read_to_end(&mut rest))
            .await
            .expect("closed by the idle time");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connection_close_ends_the_connection_after_the_response() {
        let out = exchange(&[get("Connection: close\r\n"), get("")].concat(), OK).await;
        assert_eq!(
            out.client
                .windows(15)
                .filter(|w| *w == b"HTTP/1.1 200 OK")
                .count(),
            1
        );
        assert!(!sent(&out).contains("Connection"));
        assert_eq!(
            sent(&out).matches("GET /x").count(),
            1,
            "the second request is not read"
        );
    }

    #[tokio::test]
    async fn bytes_the_node_sends_beyond_its_response_end_the_connection() {
        // A second response sitting behind the first must never be taken as the answer to the
        // next pipelined request.
        let reply = [
            OK,
            &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nSMUGL"[..],
        ]
        .concat();
        let out = exchange(&[get("X-N: 1\r\n"), get("X-N: 2\r\n")].concat(), &reply).await;
        let text = String::from_utf8_lossy(&out.client).to_string();
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(!text.contains("SMUGL"), "{text}");
        assert!(!sent(&out).contains("X-N: 2"), "the second request went on");
    }

    #[tokio::test]
    async fn a_request_that_is_no_longer_served_closes_without_reaching_the_node() {
        let out = exchange_with(&get(""), OK, limits(), || false).await;
        assert!(out.client.is_empty());
        assert_eq!(out.opened, 0);
    }

    #[tokio::test]
    async fn a_node_that_cannot_be_opened_is_a_502() {
        let (mut test_client, srv_client) = duplex(1 << 16);
        let server = tokio::spawn(async move {
            serve::<_, DuplexStream, _, _>(
                srv_client,
                HOST,
                IP.parse().unwrap(),
                limits(),
                || true,
                || async { None },
            )
            .await;
        });
        test_client.write_all(&get("")).await.unwrap();
        let mut got = Vec::new();
        test_client.read_to_end(&mut got).await.unwrap();
        assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.1 502"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_node_that_never_answers_ends_at_the_body_idle_time() {
        let (mut test_client, srv_client) = duplex(1 << 16);
        let (srv_node, _test_node) = duplex(1 << 16);
        let server = tokio::spawn(async move {
            serve(
                srv_client,
                HOST,
                IP.parse().unwrap(),
                limits(),
                || true,
                move || async move { Some(srv_node) },
            )
            .await;
        });
        test_client.write_all(&get("")).await.unwrap();
        let started = Instant::now();
        let mut got = Vec::new();
        test_client.read_to_end(&mut got).await.unwrap();
        assert!(String::from_utf8_lossy(&got).starts_with("HTTP/1.1 502"));
        assert!(started.elapsed() >= Duration::from_millis(700));
        server.await.unwrap();
    }

    #[test]
    fn the_defaults_are_the_named_figures() {
        let d = HttpLimits::default();
        assert_eq!(d.head_timeout, Duration::from_secs(10));
        assert_eq!(d.keepalive_idle, Duration::from_secs(60));
        assert_eq!(d.body_idle, Duration::from_secs(120));
        assert_eq!(MAX_HEAD, 16 * 1024);
        assert_eq!(MAX_HEADERS, 64);
    }
}
