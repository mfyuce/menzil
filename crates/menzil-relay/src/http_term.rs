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
//! * `Expect` is refused with `417` (the relay does not do the 100-continue dance). `Upgrade` or
//!   `Connection: upgrade` is `501`, except a WebSocket handshake that passes every check of
//!   "WebSocket" below (and a handshake that is a WebSocket one by its `Upgrade` header but
//!   fails a check is `400`).
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
//! # WebSocket
//!
//! Only WebSocket (RFC 6455) is switched to: a request is an upgrade only if the method is
//! `GET`, there is exactly one `Upgrade` header whose whole value is `websocket` (any case), a
//! `Connection` token list containing `upgrade` (and no `close`, and no `Sec-WebSocket-*` name in
//! it), exactly one `Sec-WebSocket-Key` that is the base64 of 16 bytes, exactly one
//! `Sec-WebSocket-Version` of `13`, and no body (no `Transfer-Encoding`, `Content-Length` absent
//! or 0). Any other `Upgrade` (`h2c`, a list, a second header, another token) is `501`; a
//! `websocket` upgrade that fails one of the rest is `400`; nothing of either reaches the node.
//! The relay sends the node `Connection: Upgrade` and `Upgrade: websocket` in canonical form and
//! passes `Sec-WebSocket-Key`, `-Version`, `-Protocol`, `-Extensions` and `Origin` as they came
//! (the relay does not interpret them: checking `Origin` against cross-site WebSocket hijacking
//! is the application's job). The relay computes the `Sec-WebSocket-Accept` it wants itself.
//!
//! Anything the client sends after the head and before the node's `101` has been read closes the
//! connection (nothing of it is forwarded). The node's answer to an upgrade request is a `101`
//! only if it has `Upgrade: websocket`, `Connection` with `upgrade`, exactly the expected
//! `Sec-WebSocket-Accept`, no framing header and no `Sec-WebSocket-*` name in `Connection`;
//! a `101` to a request that was not an upgrade, any other `101`, and every other `1xx` is `502`.
//! A final answer to an upgrade request (`200`, `401`, `404`...) is an ordinary response and the
//! connection stays HTTP.
//!
//! After a valid `101` the connection is a pipe: what the node sent behind the head goes to the
//! client first, then each side's bytes go to the other with no more HTTP. End of file on one
//! side shuts that direction down and the other has [`HttpLimits::half_close_drain`] to finish;
//! a reset or error on either side ends the client connection without a `close_notify` (a clean
//! end of both sides is the only one that has it). No bytes either way for
//! [`HttpLimits::upgrade_idle`] (5 minutes) ends it. There is no cap on the total lifetime. The
//! name is asked again whether it is still served every [`HttpLimits::upgrade_recheck`] (30
//! seconds), against the target the connection opened for. The bytes are charged to the tenant
//! through the node stream like any body, and the client connection keeps its place in the
//! per client and per name figures of the front door until it ends.
//!
//! # Streams and limits
//!
//! One node stream per client connection, opened when the first valid request head is in hand
//! (so a connection that never sends one costs the node nothing), and one request in flight:
//! the next head is read only when the response is complete. Bodies move through a 16 KiB
//! buffer in both directions; nothing is held back whole. A read or write that makes no progress
//! for [`HttpLimits::body_idle`] ends the connection. The node's stream is charged to the
//! tenant by the principal like any other (`crate::principal`).
//!
//! The name is asked whether it is still served before each request and, every
//! [`HttpLimits::upgrade_recheck`], while a request body goes to the node, while the node's
//! answer is awaited and while a response body goes to the client (`Watch`, one clock for the
//! connection): a no ends the connection at once with no `close_notify`, so a long upload, an
//! event stream or a long poll does not outlive the name's holder.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
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
/// No byte either way for this long ends an upgraded connection (WebSocket pings keep it alive).
pub(crate) const WS_IDLE: Duration = Duration::from_secs(5 * 60);
/// After one side of an upgraded connection ended, the other direction may go on this long.
pub(crate) const WS_HALF_CLOSE_DRAIN: Duration = Duration::from_secs(30);
/// An upgraded connection asks this often whether its name is still served.
pub(crate) const WS_RECHECK: Duration = Duration::from_secs(30);
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
    /// How long an upgraded (WebSocket) connection may move no byte in either direction.
    pub upgrade_idle: Duration,
    /// How long one direction of an upgraded connection may go on after the other has ended.
    pub half_close_drain: Duration,
    /// How often an upgraded connection asks whether its name is still served.
    pub upgrade_recheck: Duration,
}

impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            head_timeout: Duration::from_secs(10),
            keepalive_idle: Duration::from_secs(60),
            body_idle: Duration::from_secs(120),
            upgrade_idle: WS_IDLE,
            half_close_drain: WS_HALF_CLOSE_DRAIN,
            upgrade_recheck: WS_RECHECK,
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
    /// The peer ended its side cleanly (a read of 0 bytes).
    Eof,
    /// An I/O error or a reset: what was read is not known to be complete.
    Error,
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
            Ok(Ok(0)) => Err(ReadFail::Eof),
            Ok(Err(_)) => Err(ReadFail::Error),
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&tmp[..n]);
                Ok(n)
            }
        }
    }

    /// One line ended by CRLF, without it, if the buffer holds one (`None`: more bytes are
    /// needed). A bare CR or LF, or a line over `max`, is malformed.
    fn take_line(&mut self, max: usize) -> Result<Option<Vec<u8>>, BodyFail> {
        if let Some(lf) = self.buf.iter().position(|b| *b == b'\n') {
            if lf == 0 || self.buf[lf - 1] != b'\r' || lf - 1 > max {
                return Err(BodyFail::Malformed);
            }
            let mut line: Vec<u8> = self.buf.drain(..=lf).collect();
            line.truncate(lf - 1);
            if line.contains(&b'\r') {
                return Err(BodyFail::Malformed);
            }
            return Ok(Some(line));
        }
        if self.buf.len() > max + 1 {
            return Err(BodyFail::Malformed);
        }
        Ok(None)
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
            Err(ReadFail::Eof | ReadFail::Error) => return Err(HeadFail::Closed),
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
    /// The `Sec-WebSocket-Key` of a WebSocket handshake that passed every check.
    ws_key: Option<String>,
}

/// A response that passed every check, ready for the client.
struct ResponsePlan {
    head: Vec<u8>,
    body: Framing,
    /// The connection ends after this response.
    close: bool,
    /// A valid `101` for the WebSocket handshake: the connection becomes a pipe.
    upgraded: bool,
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
    // CGI and WSGI servers fold `_` and `-` in header names (`X_Forwarded_For` is
    // `X-Forwarded-For` to them): the comparison folds them too.
    let folded = lower.replace('_', "-");
    let lower = folded.as_str();
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
    let mut upgrade_seen = false;
    let (mut ws_keys, mut ws_versions): (Vec<&[u8]>, Vec<&[u8]>) = (Vec::new(), Vec::new());
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
            // One header whose whole value is the token `websocket`: anything else is an
            // upgrade the relay does not do.
            "upgrade" => {
                if std::mem::replace(&mut upgrade_seen, true)
                    || !value.eq_ignore_ascii_case(b"websocket")
                {
                    return Err(501);
                }
            }
            // CGI and WSGI servers fold `_` and `-` in header names, so `Sec_WebSocket_Key`
            // counts as the same header (a doubled key or version is a `400`; expose round 4,
            // N1).
            other => match other.replace('_', "-").as_str() {
                "sec-websocket-key" => ws_keys.push(value),
                "sec-websocket-version" => ws_versions.push(value),
                _ => {}
            },
        }
    }
    if length.is_some() && chunked {
        return Err(400);
    }
    let (named, close, connection_upgrade) = connection_tokens(&connection).ok_or(400u16)?;
    if connection_upgrade && !upgrade_seen {
        return Err(501);
    }
    let host = host_name(host.ok_or(400u16)?).ok_or(400u16)?;
    if host != sni {
        return Err(421);
    }
    let ws_key = if upgrade_seen {
        let ask = WebSocketAsk {
            method,
            length,
            chunked,
            close,
            connection_upgrade,
            named: &named,
            keys: &ws_keys,
            versions: &ws_versions,
        };
        Some(ask.key().ok_or(400u16)?)
    } else {
        None
    };
    let body = match (length, chunked) {
        _ if ws_key.is_some() => Framing::None,
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
    if ws_key.is_some() {
        out.extend_from_slice(b"Connection: Upgrade\r\nUpgrade: websocket\r\n");
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
        ws_key,
    })
}

/// What a request that carries `Upgrade: websocket` has to be to be switched.
struct WebSocketAsk<'a> {
    method: &'a str,
    length: Option<u64>,
    chunked: bool,
    close: bool,
    connection_upgrade: bool,
    named: &'a [String],
    keys: &'a [&'a [u8]],
    versions: &'a [&'a [u8]],
}

impl WebSocketAsk<'_> {
    /// The `Sec-WebSocket-Key` if the handshake passes every check (`None` is a `400`).
    fn key(&self) -> Option<String> {
        let no_body = !self.chunked && matches!(self.length, None | Some(0));
        // A `Connection` that names a `Sec-WebSocket-*` header would have the relay strip it.
        let names_ws = self
            .named
            .iter()
            .any(|n| n.replace('_', "-").starts_with("sec-websocket-"));
        let [key] = self.keys else { return None };
        if self.method != "GET"
            || !self.connection_upgrade
            || self.close
            || !no_body
            || names_ws
            || self.versions != [&b"13"[..]]
            || !websocket_key_ok(key)
        {
            return None;
        }
        String::from_utf8(key.to_vec()).ok()
    }
}

/// Whether `key` is the base64 (padded, canonical) of exactly 16 bytes.
fn websocket_key_ok(key: &[u8]) -> bool {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .is_ok_and(|bytes| bytes.len() == 16)
}

/// The `Sec-WebSocket-Accept` a node must answer for `key` (RFC 6455 4.2.2).
fn websocket_accept(key: &str) -> String {
    tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes())
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
fn process_response(
    head: &[u8],
    is_head: bool,
    host: &str,
    ws_key: Option<&str>,
) -> Option<ResponsePlan> {
    let mut storage = [httparse::EMPTY_HEADER; RESPONSE_MAX_HEADERS];
    let mut res = httparse::Response::new(&mut storage);
    match res.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        _ => return None,
    }
    let version = res.version?;
    let code = res.code?;
    if version > 1 || (code != 101 && !(200..=599).contains(&code)) {
        return None;
    }
    let (mut length, mut chunked, mut te_seen) = (None, false, false);
    let mut connection: Vec<Vec<u8>> = Vec::new();
    let (mut upgrades, mut accepts): (Vec<&[u8]>, Vec<&[u8]>) = (Vec::new(), Vec::new());
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
            "upgrade" => upgrades.push(value),
            "sec-websocket-accept" => accepts.push(value),
            _ => {}
        }
    }
    if length.is_some() && chunked {
        return None;
    }
    let (named, close_token, connection_upgrade) = connection_tokens(&connection)?;
    if code == 101 {
        // Only for a WebSocket handshake the relay itself passed, and only if it is one.
        let expected = websocket_accept(ws_key?);
        let valid = version == 1
            && upgrades.len() == 1
            && upgrades[0].eq_ignore_ascii_case(b"websocket")
            && connection_upgrade
            && !close_token
            && accepts == [expected.as_bytes()]
            && length.is_none()
            && !chunked
            && !named.iter().any(|n| n.starts_with("sec-websocket-"));
        if !valid {
            return None;
        }
        return Some(switching_protocols(&res, host, &named));
    }
    if !upgrades.is_empty() || connection_upgrade {
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
        upgraded: false,
    })
}

/// The `101` that goes to the client: the node's head without its hop headers, with
/// `Upgrade: websocket` and `Connection: Upgrade` in canonical form.
fn switching_protocols(
    res: &httparse::Response<'_, '_>,
    host: &str,
    named: &[String],
) -> ResponsePlan {
    let reason = res
        .reason
        .filter(|r| r.bytes().all(|b| b == b'\t' || (0x20..0x7f).contains(&b)))
        .unwrap_or("");
    let mut out = format!("HTTP/1.1 101 {reason}\r\n").into_bytes();
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
    out.extend_from_slice(b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    ResponsePlan {
        head: out,
        body: Framing::None,
        close: true,
        upgraded: true,
    }
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
    /// The source ended before the body was complete.
    Closed,
    /// The source failed (an I/O error or a reset).
    Failed,
    TimedOut,
    /// The framing is not valid.
    Malformed,
    /// The destination ended, failed or stalled.
    Sink,
}

impl From<ReadFail> for BodyFail {
    fn from(fail: ReadFail) -> Self {
        match fail {
            ReadFail::Eof => Self::Closed,
            ReadFail::Error => Self::Failed,
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
                    // Only a clean end of the node's stream ends a body framed by the close;
                    // a reset is a failure (the client must not take it for a complete body).
                    Err(ReadFail::Eof) => return Ok(()),
                    Err(ReadFail::Error) => return Err(BodyFail::Failed),
                    Err(ReadFail::TimedOut) => return Err(BodyFail::TimedOut),
                }
            }
            let piece = std::mem::take(&mut src.buf);
            put(dst, &piece, wait).await?;
        },
        Framing::Chunked => copy_chunked(src, dst, wait).await,
    }
}

/// Where `copy_chunked` is in a chunked body.
enum ChunkState {
    /// Waiting for a chunk-size line.
    Size,
    /// Inside a chunk's data: this many bytes left.
    Data(u64),
    /// Waiting for the CRLF after a chunk's data.
    DataEnd,
    /// After the last chunk: trailer lines, so many bytes so far.
    Trailer(usize),
}

/// Moves a chunked body, re-encoded (no extensions, trailers dropped). The output is gathered
/// and written once for each read of the source, not once for each piece of each chunk: a body of
/// one byte chunks costs one write for a read's worth of chunks, not three writes each.
async fn copy_chunked<S, D>(src: &mut Conn<S>, dst: &mut D, wait: Duration) -> Result<(), BodyFail>
where
    S: AsyncRead + Unpin,
    D: AsyncWrite + Unpin,
{
    let mut out: Vec<u8> = Vec::new();
    let mut state = ChunkState::Size;
    loop {
        let progressed = match state {
            ChunkState::Size => match src.take_line(MAX_CHUNK_LINE)? {
                None => false,
                Some(line) => {
                    if line.is_empty() || line.len() > 16 || !line.iter().all(u8::is_ascii_hexdigit)
                    {
                        return Err(BodyFail::Malformed);
                    }
                    let size = u64::from_str_radix(&String::from_utf8_lossy(&line), 16)
                        .map_err(|_| BodyFail::Malformed)?;
                    if size == 0 {
                        state = ChunkState::Trailer(0);
                    } else {
                        out.extend_from_slice(format!("{size:x}\r\n").as_bytes());
                        state = ChunkState::Data(size);
                    }
                    true
                }
            },
            ChunkState::Data(left) => {
                if src.buf.is_empty() {
                    false
                } else {
                    let take =
                        usize::try_from(left).map_or(src.buf.len(), |n| n.min(src.buf.len()));
                    out.extend(src.buf.drain(..take));
                    let left = left - take as u64;
                    state = if left == 0 {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left)
                    };
                    true
                }
            }
            ChunkState::DataEnd => match src.take_line(0)? {
                None => false,
                Some(line) => {
                    if !line.is_empty() {
                        return Err(BodyFail::Malformed);
                    }
                    out.extend_from_slice(b"\r\n");
                    state = ChunkState::Size;
                    true
                }
            },
            ChunkState::Trailer(seen) => match src.take_line(MAX_CHUNK_LINE)? {
                None => false,
                Some(line) if line.is_empty() => {
                    out.extend_from_slice(b"0\r\n\r\n");
                    return put(dst, &out, wait).await;
                }
                Some(line) => {
                    let seen = seen + line.len() + 2;
                    if seen > MAX_TRAILER {
                        return Err(BodyFail::Malformed);
                    }
                    state = ChunkState::Trailer(seen);
                    true
                }
            },
        };
        if !progressed {
            // Out of input: pass on what is gathered, then read once more.
            if !out.is_empty() {
                put(dst, &out, wait).await?;
                out.clear();
            }
            src.fill(wait).await?;
        }
    }
}

/// When an upgraded connection last moved a byte, and when its first direction ended.
struct Pace {
    last_moved: Mutex<Instant>,
    first_end: Mutex<Option<Instant>>,
    /// Woken when a direction ends, so that the drain time is counted from then.
    ended_signal: tokio::sync::Notify,
}

impl Pace {
    fn new() -> Self {
        Self {
            last_moved: Mutex::new(Instant::now()),
            first_end: Mutex::new(None),
            ended_signal: tokio::sync::Notify::new(),
        }
    }

    fn moved(&self) {
        *self
            .last_moved
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Instant::now();
    }

    fn last_moved(&self) -> Instant {
        *self
            .last_moved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// A direction ended: the first one is noted.
    fn ended(&self) {
        self.first_end
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(Instant::now);
        self.ended_signal.notify_one();
    }

    fn first_end(&self) -> Option<Instant> {
        *self
            .first_end
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Moves bytes from `src` to `dst` until `src` ends. `Ok` is a clean end (`dst` is shut down, a
/// `close_notify` on TLS); `Err` is a reset, an error or a stall, and `dst` is left as it is.
async fn pump<R, W>(src: &mut R, dst: &mut W, stall: Duration, pace: &Pace) -> Result<(), ()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; IO_BUFFER];
    loop {
        match src.read(&mut buf).await {
            Ok(0) => {
                pace.ended();
                return match timeout(stall, dst.shutdown()).await {
                    Ok(Ok(())) => Ok(()),
                    _ => Err(()),
                };
            }
            Ok(n) => {
                pace.moved();
                let moved = timeout(stall, async {
                    dst.write_all(&buf[..n]).await?;
                    dst.flush().await
                })
                .await;
                if !matches!(moved, Ok(Ok(()))) {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    }
}

/// Asks whether the name is still served: before each request, and every
/// [`HttpLimits::upgrade_recheck`] while a body or an upgraded connection moves (expose round 4,
/// M1: a long exchange must not outlive the name's holder). One clock for the whole connection:
/// every question, whichever place asks it, puts the next one `every` later.
struct Watch<F> {
    every: Duration,
    due: Instant,
    still_served: F,
}

impl<F: FnMut() -> bool> Watch<F> {
    fn new(every: Duration, still_served: F) -> Self {
        Self {
            every,
            due: Instant::now() + every,
            still_served,
        }
    }

    /// Asks now.
    fn ask(&mut self) -> bool {
        self.due = Instant::now() + self.every;
        (self.still_served)()
    }

    /// Runs `work`, asking at each due time; `None` if the answer was no (`work` is dropped
    /// where it stood: the caller ends the connection without a clean close). No task, no
    /// timer beyond the one `sleep_until` of the wait, so an exchange shorter than the interval
    /// pays one timer entry and nothing else.
    async fn run<T>(&mut self, work: impl Future<Output = T>) -> Option<T> {
        let mut work = std::pin::pin!(work);
        loop {
            tokio::select! {
                biased;
                () = tokio::time::sleep_until(self.due) => {
                    if !self.ask() {
                        return None;
                    }
                }
                out = &mut work => return Some(out),
            }
        }
    }
}

/// The upgraded connection: `client` and `node` are joined, byte for byte, in both directions,
/// until both sides have ended (clean: each direction was shut down), one of them fails (no
/// `close_notify` to the client), nothing moves for [`HttpLimits::upgrade_idle`], one side's end
/// is not followed by the other's within [`HttpLimits::half_close_drain`], or the name is no
/// longer served (asked every [`HttpLimits::upgrade_recheck`]). Every end but the clean one drops
/// both streams as they are.
async fn pipe<C, N>(client: C, node: N, limits: HttpLimits, watch: &mut Watch<impl FnMut() -> bool>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    N: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(client);
    let (mut node_read, mut node_write) = tokio::io::split(node);
    let pace = Pace::new();
    let up = pump(&mut client_read, &mut node_write, limits.body_idle, &pace);
    let down = pump(&mut node_read, &mut client_write, limits.body_idle, &pace);
    let mut both = std::pin::pin!(futures_util::future::try_join(up, down));
    let moving = async {
        loop {
            let mut wake = pace.last_moved() + limits.upgrade_idle;
            if let Some(at) = pace.first_end() {
                wake = wake.min(at + limits.half_close_drain);
            }
            tokio::select! {
                _ = &mut both => return,
                () = pace.ended_signal.notified() => {}
                _ = tokio::time::sleep_until(wake) => {}
            }
            let now = Instant::now();
            if now >= pace.last_moved() + limits.upgrade_idle {
                return;
            }
            if pace
                .first_end()
                .is_some_and(|at| now >= at + limits.half_close_drain)
            {
                return;
            }
        }
    };
    // Every end but the clean one is a return; so is a name no longer served.
    let _ = watch.run(moving).await;
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
/// responses. `still_served` is asked before each request is forwarded and every
/// [`HttpLimits::upgrade_recheck`] while a body (either way), the node's answer or an upgraded
/// connection is moving; `false` ends the connection at once, without a `close_notify`. Returns
/// when the connection is over.
pub(crate) async fn serve<C, N, O, Fut>(
    client: C,
    host: &str,
    client_ip: IpAddr,
    limits: HttpLimits,
    still_served: impl FnMut() -> bool,
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
    let mut watch = Watch::new(limits.upgrade_recheck, still_served);
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
        // Bytes behind an upgrade request's head are pipelined: the connection ends before the
        // request goes anywhere.
        if plan.ws_key.is_some() && !client.buf.is_empty() {
            reply(&mut client.io, 400).await;
            return;
        }
        if !watch.ask() {
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
        match watch
            .run(copy_body(
                &mut client,
                &mut node_conn.io,
                plan.body,
                limits.body_idle,
            ))
            .await
        {
            Some(Ok(())) => {}
            Some(Err(BodyFail::Malformed)) => {
                reply(&mut client.io, 400).await;
                return;
            }
            // A failure, or a name no longer served: no more bytes of the client go to the node.
            Some(Err(_)) | None => return,
        }
        if timeout(limits.body_idle, node_conn.io.flush())
            .await
            .is_err()
        {
            return;
        }
        let node_head = read_head(node_conn, limits.body_idle, limits.head_timeout);
        let head = if plan.ws_key.is_some() {
            // Until the node's answer is in hand the client has nothing more to say: a byte
            // (or an end) from it closes the connection and nothing of it is forwarded.
            let mut probe = [0u8; 1];
            tokio::select! {
                head = watch.run(node_head) => head,
                read = client.io.read(&mut probe) => {
                    if matches!(read, Ok(n) if n > 0) {
                        reply(&mut client.io, 400).await;
                    }
                    return;
                }
            }
        } else {
            watch.run(node_head).await
        };
        // A node that answers after the name moved away is not heard: nothing of it goes on.
        let Some(head) = head else { return };
        let head = match head {
            Ok(head) => head,
            Err(_) => {
                reply(&mut client.io, 502).await;
                return;
            }
        };
        let Some(response) = process_response(&head, plan.is_head, host, plan.ws_key.as_deref())
        else {
            reply(&mut client.io, 502).await;
            return;
        };
        if put(&mut client.io, &response.head, limits.body_idle)
            .await
            .is_err()
        {
            return;
        }
        if response.upgraded {
            // What the node sent behind its head is already the client's: first.
            let ahead = std::mem::take(&mut node_conn.buf);
            let moved = timeout(limits.body_idle, async {
                client.io.write_all(&ahead).await?;
                client.io.flush().await
            })
            .await;
            if !matches!(moved, Ok(Ok(()))) || !client.buf.is_empty() {
                return;
            }
            if let Some(node_conn) = node.take() {
                pipe(client.io, node_conn.io, limits, &mut watch).await;
            }
            return;
        }
        // An error, or a name no longer served, ends the connection with no clean close.
        if !watch
            .run(copy_body(
                node_conn,
                &mut client.io,
                response.body,
                limits.body_idle,
            ))
            .await
            .is_some_and(|copied| copied.is_ok())
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
            ..HttpLimits::default()
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
        // A WebSocket handshake that lacks its key and version is no handshake (400, the
        // checks are in `websocket`); an upgrade to anything else is 501.
        refused(&get("Upgrade: websocket\r\nConnection: Upgrade\r\n"), 400).await;
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
        assert_eq!(d.upgrade_idle, Duration::from_secs(300));
        assert_eq!(d.half_close_drain, Duration::from_secs(30));
        assert_eq!(d.upgrade_recheck, Duration::from_secs(30));
        assert_eq!(MAX_HEAD, 16 * 1024);
        assert_eq!(MAX_HEADERS, 64);
    }

    // -----------------------------------------------------------------------------------------
    // Expose round 3: H1 (a reset is not an end), L1 (underscore names), M3 (chunk writes)
    // -----------------------------------------------------------------------------------------

    mod round3 {
        use super::*;
        use std::pin::Pin;
        use std::task::{Context, Poll};

        /// A node that answers `out`, then ends its stream: with a reset (`reset`) or cleanly.
        struct EndingNode {
            out: Vec<u8>,
            pos: usize,
            reset: bool,
        }

        impl AsyncRead for EndingNode {
            fn poll_read(
                mut self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                if self.pos < self.out.len() {
                    let n = (self.out.len() - self.pos).min(buf.remaining());
                    let start = self.pos;
                    buf.put_slice(&self.out[start..start + n]);
                    self.pos += n;
                    return Poll::Ready(Ok(()));
                }
                if self.reset {
                    Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "stream reset",
                    )))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
        }

        impl AsyncWrite for EndingNode {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }

        /// The client side; counts the clean closes (over TLS a shutdown is a close_notify).
        struct ClientSide {
            inner: DuplexStream,
            clean: Arc<AtomicUsize>,
        }

        impl AsyncRead for ClientSide {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for ClientSide {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Pin::new(&mut self.inner).poll_write(cx, buf)
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.clean.fetch_add(1, Ordering::SeqCst);
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }

        /// What the client got, and how often the terminator closed its side cleanly.
        async fn ending_case(response: &[u8], reset: bool) -> (String, usize) {
            let (mut c, srv_c) = duplex(1 << 16);
            let clean = Arc::new(AtomicUsize::new(0));
            let client_io = ClientSide {
                inner: srv_c,
                clean: Arc::clone(&clean),
            };
            let node = EndingNode {
                out: response.to_vec(),
                pos: 0,
                reset,
            };
            let server = tokio::spawn(async move {
                serve(
                    client_io,
                    HOST,
                    IP.parse().unwrap(),
                    limits(),
                    || true,
                    move || async move { Some(node) },
                )
                .await;
            });
            c.write_all(&get("")).await.unwrap();
            let mut got = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), c.read_to_end(&mut got)).await;
            server.await.unwrap();
            (
                String::from_utf8_lossy(&got).to_string(),
                clean.load(Ordering::SeqCst),
            )
        }

        const UNTIL_CLOSE: &[u8] =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nPART-OF-A-LARGER-FILE";

        #[tokio::test]
        async fn a_node_stream_reset_does_not_end_an_until_close_body_cleanly() {
            let (got, clean) = ending_case(UNTIL_CLOSE, true).await;
            assert!(got.ends_with("PART-OF-A-LARGER-FILE"), "{got:?}");
            assert_eq!(
                clean, 0,
                "a reset must not look like a complete body: no close_notify"
            );
        }

        #[tokio::test]
        async fn a_clean_end_of_the_node_stream_still_ends_an_until_close_body_cleanly() {
            let (got, clean) = ending_case(UNTIL_CLOSE, false).await;
            assert!(got.ends_with("PART-OF-A-LARGER-FILE"), "{got:?}");
            assert_eq!(clean, 1, "the end of a close framed body is a clean close");
        }

        #[tokio::test]
        async fn a_node_stream_reset_inside_a_length_or_chunked_body_is_not_a_clean_close() {
            let (_, clean) = ending_case(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nPART-OF-A-LARGER-FILE",
                true,
            )
            .await;
            assert_eq!(clean, 0);
            let (_, clean) = ending_case(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n",
                true,
            )
            .await;
            assert_eq!(clean, 0);
            // the clean end of a short length body is no better
            let (_, clean) = ending_case(
                b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nPART-OF-A-LARGER-FILE",
                false,
            )
            .await;
            assert_eq!(clean, 0);
        }

        #[tokio::test]
        async fn address_headers_spelled_with_underscores_do_not_reach_the_node() {
            let out = exchange(
                &get(
                    "X-Forwarded_For: 6.6.6.6\r\nX_Forwarded_For: 6.6.6.7\r\nX-Real_IP: 6.6.6.8\r\n\
                     True_Client_IP: 6.6.6.9\r\nForwarded_For: 6.6.6.10\r\nProxy_Authorization: x\r\n\
                     Content_Length: 99\r\nTransfer_Encoding: chunked\r\nX_Accepted: yes\r\n",
                ),
                OK,
            )
            .await;
            let node = sent(&out);
            for name in [
                "6.6.6.6",
                "6.6.6.7",
                "6.6.6.8",
                "6.6.6.9",
                "Proxy_Authorization",
                "Content_Length",
                "Transfer_Encoding",
            ] {
                assert!(!node.contains(name), "{name} reached the node:\n{node}");
            }
            // an unrelated header with an underscore is still passed
            assert!(node.contains("X_Accepted: yes\r\n"), "{node}");
        }

        /// A node stream that counts write calls.
        struct Counting {
            inner: DuplexStream,
            writes: Arc<AtomicUsize>,
        }

        impl AsyncRead for Counting {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, buf)
            }
        }

        impl AsyncWrite for Counting {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                let r = Pin::new(&mut self.inner).poll_write(cx, buf);
                if let Poll::Ready(Ok(_)) = r {
                    self.writes.fetch_add(1, Ordering::SeqCst);
                }
                r
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }

        #[tokio::test]
        async fn many_tiny_chunks_cost_one_node_write_for_each_read_not_three_for_each_chunk() {
            const N: usize = 10_000;
            let mut req =
                format!("POST /x HTTP/1.1\r\nHost: {HOST}\r\nTransfer-Encoding: chunked\r\n\r\n")
                    .into_bytes();
            for _ in 0..N {
                req.extend_from_slice(b"1\r\nx\r\n");
            }
            req.extend_from_slice(b"0\r\n\r\n");
            let (mut test_client, srv_client) = duplex(1 << 22);
            let (srv_node, mut test_node) = duplex(1 << 22);
            let writes = Arc::new(AtomicUsize::new(0));
            let node_io = Counting {
                inner: srv_node,
                writes: Arc::clone(&writes),
            };
            let server = tokio::spawn(async move {
                serve(
                    srv_client,
                    HOST,
                    IP.parse().unwrap(),
                    limits(),
                    || true,
                    move || async move { Some(node_io) },
                )
                .await;
            });
            let node = tokio::spawn(async move {
                let mut seen = Vec::new();
                let mut chunk = [0u8; 65536];
                loop {
                    match test_node.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            seen.extend_from_slice(&chunk[..n]);
                            if seen.ends_with(b"0\r\n\r\n") {
                                let _ = test_node.write_all(OK).await;
                            }
                        }
                    }
                }
                seen
            });
            test_client.write_all(&req).await.unwrap();
            test_client.shutdown().await.unwrap();
            let mut client = Vec::new();
            let _ =
                tokio::time::timeout(Duration::from_secs(5), test_client.read_to_end(&mut client))
                    .await;
            server.await.unwrap();
            let seen = node.await.unwrap();
            assert!(client.starts_with(b"HTTP/1.1 200 OK"), "{client:?}");
            // the body is the same as before: every chunk, re-encoded
            let body_start = seen.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(&seen[body_start..body_start + 6], b"1\r\nx\r\n");
            assert!(seen.ends_with(b"1\r\nx\r\n0\r\n\r\n"));
            assert_eq!(seen.len() - body_start, N * 6 + 5);
            // the body is 60 KB: a handful of reads of the client's stream, so a handful of writes
            let writes = writes.load(Ordering::SeqCst);
            assert!(writes <= 16, "{writes} node writes for {N} chunks");
        }
    }

    // -----------------------------------------------------------------------------------------
    // WebSocket (HTTP/1.1 Upgrade)
    // -----------------------------------------------------------------------------------------

    mod websocket {
        use super::*;
        use std::pin::Pin;
        use std::sync::atomic::AtomicBool;
        use std::task::{Context, Poll};
        use tokio::sync::mpsc;
        use tokio::task::JoinHandle;

        /// The key and accept of RFC 6455 4.2.2, and a second pair computed independently.
        const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
        const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        const KEY2: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
        const ACCEPT2: &str = "C/0nmHhBztSRGR1CwL6Tf4ZjwpY=";

        /// What a scripted peer does next.
        enum Feed {
            Data(Vec<u8>),
            Eof,
            Reset,
        }

        /// One end of the terminator as the test scripts it: reads what the test feeds, records
        /// what the terminator writes, and counts the clean shutdowns (a `close_notify` on TLS).
        struct Chan {
            rx: mpsc::UnboundedReceiver<Feed>,
            pending: Vec<u8>,
            state: Option<bool>,
            out: mpsc::UnboundedSender<Vec<u8>>,
            shutdowns: Arc<AtomicUsize>,
        }

        impl AsyncRead for Chan {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                loop {
                    if !self.pending.is_empty() {
                        let n = self.pending.len().min(buf.remaining());
                        let rest = self.pending.split_off(n);
                        let head = std::mem::replace(&mut self.pending, rest);
                        buf.put_slice(&head);
                        return Poll::Ready(Ok(()));
                    }
                    match self.state {
                        Some(true) => {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "reset",
                            )));
                        }
                        Some(false) => return Poll::Ready(Ok(())),
                        None => {}
                    }
                    match self.rx.poll_recv(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Some(Feed::Data(bytes))) => self.pending = bytes,
                        Poll::Ready(Some(Feed::Eof) | None) => self.state = Some(false),
                        Poll::Ready(Some(Feed::Reset)) => self.state = Some(true),
                    }
                }
            }
        }

        impl AsyncWrite for Chan {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                let _ = self.out.send(buf.to_vec());
                Poll::Ready(Ok(buf.len()))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                self.shutdowns.fetch_add(1, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
        }

        /// The test's side of a [`Chan`].
        struct Ends {
            feed: mpsc::UnboundedSender<Feed>,
            out: mpsc::UnboundedReceiver<Vec<u8>>,
            shutdowns: Arc<AtomicUsize>,
            seen: Vec<u8>,
            used: usize,
        }

        fn chan() -> (Chan, Ends) {
            let (feed, rx) = mpsc::unbounded_channel();
            let (out_tx, out) = mpsc::unbounded_channel();
            let shutdowns = Arc::new(AtomicUsize::new(0));
            (
                Chan {
                    rx,
                    pending: Vec::new(),
                    state: None,
                    out: out_tx,
                    shutdowns: Arc::clone(&shutdowns),
                },
                Ends {
                    feed,
                    out,
                    shutdowns,
                    seen: Vec::new(),
                    used: 0,
                },
            )
        }

        impl Ends {
            fn send(&self, bytes: &[u8]) {
                let _ = self.feed.send(Feed::Data(bytes.to_vec()));
            }
            fn eof(&self) {
                let _ = self.feed.send(Feed::Eof);
            }
            fn reset(&self) {
                let _ = self.feed.send(Feed::Reset);
            }
            fn closes(&self) -> usize {
                self.shutdowns.load(Ordering::SeqCst)
            }
            /// Everything written so far that was not taken yet (waits for nothing).
            async fn pending(&mut self) -> Vec<u8> {
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
                while let Ok(more) = self.out.try_recv() {
                    self.seen.extend_from_slice(&more);
                }
                let got = self.seen[self.used..].to_vec();
                self.used = self.seen.len();
                got
            }
            /// Waits until `n` more bytes were written, and takes them.
            async fn take(&mut self, n: usize) -> Vec<u8> {
                let waited = tokio::time::timeout(Duration::from_secs(20), async {
                    while self.seen.len() - self.used < n {
                        match self.out.recv().await {
                            Some(more) => self.seen.extend_from_slice(&more),
                            None => break,
                        }
                    }
                })
                .await;
                assert!(waited.is_ok(), "timed out waiting for {n} bytes");
                assert!(
                    self.seen.len() - self.used >= n,
                    "the stream ended with {} of {n} bytes: {:?}",
                    self.seen.len() - self.used,
                    String::from_utf8_lossy(&self.seen[self.used..])
                );
                let got = self.seen[self.used..self.used + n].to_vec();
                self.used += n;
                got
            }
            /// Waits until the written bytes contain a blank line, and takes them up to it.
            async fn head(&mut self) -> Vec<u8> {
                let waited = tokio::time::timeout(Duration::from_secs(20), async {
                    loop {
                        if let Some(at) = self.seen[self.used..]
                            .windows(4)
                            .position(|w| w == b"\r\n\r\n")
                        {
                            return at + 4;
                        }
                        match self.out.recv().await {
                            Some(more) => self.seen.extend_from_slice(&more),
                            None => return self.seen.len() - self.used,
                        }
                    }
                })
                .await
                .expect("timed out waiting for a head");
                let got = self.seen[self.used..self.used + waited].to_vec();
                self.used += waited;
                got
            }
        }

        struct Rig {
            client: Ends,
            node: Ends,
            server: JoinHandle<()>,
            opened: Arc<AtomicUsize>,
            served: Arc<AtomicBool>,
        }

        fn rig(limits: HttpLimits) -> Rig {
            let (client_io, client) = chan();
            let (node_io, node) = chan();
            let opened = Arc::new(AtomicUsize::new(0));
            let served = Arc::new(AtomicBool::new(true));
            let counter = Arc::clone(&opened);
            let still = Arc::clone(&served);
            let server = tokio::spawn(async move {
                serve(
                    client_io,
                    HOST,
                    IP.parse().unwrap(),
                    limits,
                    move || still.load(Ordering::SeqCst),
                    move || async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Some(node_io)
                    },
                )
                .await;
            });
            Rig {
                client,
                node,
                server,
                opened,
                served,
            }
        }

        async fn settle() {
            for _ in 0..40 {
                tokio::task::yield_now().await;
            }
        }

        impl Rig {
            /// Whether the connection is over (after the tasks ran as far as they can).
            async fn over(&mut self) -> bool {
                settle().await;
                self.server.is_finished()
            }
            /// Sends the handshake, lets the node answer `reply`, and gives what the client got
            /// of it (its head).
            async fn switch(&mut self, request: &[u8], reply: &[u8]) -> Vec<u8> {
                self.client.send(request);
                let seen = self.node.head().await;
                assert!(seen.starts_with(b"GET /chat HTTP/1.1\r\n"), "{seen:?}");
                self.node.send(reply);
                self.client.head().await
            }
            async fn ok(&mut self) -> Vec<u8> {
                self.switch(&ws_head("GET", &GOOD, &[], &[]), &accept_reply(ACCEPT, ""))
                    .await
            }
        }

        const GOOD: [&str; 4] = [
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version: 13",
        ];

        /// A handshake request: `base` without the headers named in `skip`, then `add`.
        fn ws_head(method: &str, base: &[&str], skip: &[&str], add: &[&str]) -> Vec<u8> {
            let mut head = format!("{method} /chat HTTP/1.1\r\nHost: {HOST}\r\n");
            for line in base {
                let name = line.split(':').next().unwrap();
                if !skip.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                    head.push_str(line);
                    head.push_str("\r\n");
                }
            }
            for line in add {
                head.push_str(line);
                head.push_str("\r\n");
            }
            head.push_str("\r\n");
            head.into_bytes()
        }

        fn accept_reply(accept: &str, extra: &str) -> Vec<u8> {
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n{extra}\r\n"
            )
            .into_bytes()
        }

        fn text(bytes: &[u8]) -> String {
            String::from_utf8_lossy(bytes).to_string()
        }

        #[test]
        fn the_accept_value_and_the_key_check_are_rfc_6455s() {
            assert_eq!(websocket_accept(KEY), ACCEPT);
            assert_eq!(websocket_accept(KEY2), ACCEPT2);
            assert!(websocket_key_ok(KEY.as_bytes()));
            assert!(websocket_key_ok(KEY2.as_bytes()));
            for bad in [
                "",
                "AQIDBAUGBwgJCgsMDQ4P",     // 15 bytes
                "AQIDBAUGBwgJCgsMDQ4PEBE=", // 17 bytes
                "AQIDBAUGBwgJCgsMDQ4PEA",   // no padding
                "AQIDBAUGBwgJCgsMDQ4PEB==", // trailing bits set
                "AQIDBAUGBwgJCgsMDQ4PEA== ",
                "not base64 at all!!!!!!",
                "AQIDBAUGBwgJCgsMDQ4PEA==AQIDBAUGBwgJCgsMDQ4PEA==",
            ] {
                assert!(!websocket_key_ok(bad.as_bytes()), "{bad:?}");
            }
        }

        /// Expose round 4, N1: a CGI backend folds `_` to `-`, so the underscore spellings of the
        /// handshake headers are the same headers as far as the checks go.
        #[test]
        fn underscore_spellings_of_the_handshake_headers_are_the_same_headers() {
            // Alone, they are the key and the version: the handshake passes.
            let head = ws_head(
                "GET",
                &GOOD,
                &["Sec-WebSocket-Key", "Sec-WebSocket-Version"],
                &[
                    &format!("Sec_WebSocket_Key: {KEY}"),
                    "SEC_WEBSOCKET_VERSION: 13",
                ],
            );
            let Ok(plan) = process_request(&head, HOST, IP) else {
                panic!("the handshake is accepted")
            };
            assert_eq!(plan.ws_key.as_deref(), Some(KEY));
            // Beside the others they double them (the table of refusals has the 400s); a lone
            // wrong underscore version is a wrong version.
            let head = ws_head(
                "GET",
                &GOOD,
                &["Sec-WebSocket-Version"],
                &["Sec_WebSocket_Version: 8"],
            );
            assert_eq!(process_request(&head, HOST, IP).err(), Some(400));
            // Protocol and extensions follow the hyphen spelling's rule: they pass as they came.
            let head = ws_head(
                "GET",
                &GOOD,
                &[],
                &[
                    "Sec_WebSocket_Protocol: chat",
                    "Sec_WebSocket_Extensions: permessage-deflate",
                ],
            );
            let Ok(plan) = process_request(&head, HOST, IP) else {
                panic!("the handshake is accepted")
            };
            let sent = text(&plan.head);
            assert!(sent.contains("Sec_WebSocket_Protocol: chat\r\n"), "{sent}");
            assert!(
                sent.contains("Sec_WebSocket_Extensions: permessage-deflate\r\n"),
                "{sent}"
            );
        }

        #[tokio::test]
        async fn a_handshake_is_forwarded_in_canonical_form_and_the_connection_becomes_a_pipe() {
            let mut rig = rig(limits());
            let request = ws_head(
                "GET",
                &GOOD,
                &["Upgrade", "Connection"],
                &[
                    "Upgrade: WebSocket",
                    "Connection: keep-alive, Upgrade, X-Secret",
                    "X-Secret: s",
                    "Sec-WebSocket-Protocol: chat, superchat",
                    "Sec-WebSocket-Extensions: permessage-deflate",
                    "Origin: https://evil.example",
                    "X-Forwarded-For: 6.6.6.6",
                    "X_Forwarded_For: 6.6.6.6",
                    "Keep-Alive: timeout=5",
                    "Content-Length: 0",
                    "X-Keep: kept",
                ],
            );
            rig.client.send(&request);
            let seen = text(&rig.node.head().await);
            assert!(seen.starts_with("GET /chat HTTP/1.1\r\n"), "{seen}");
            assert!(
                seen.contains("\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"),
                "{seen}"
            );
            for kept in [
                &format!("Sec-WebSocket-Key: {KEY}\r\n"),
                "Sec-WebSocket-Version: 13\r\n",
                "Sec-WebSocket-Protocol: chat, superchat\r\n",
                "Sec-WebSocket-Extensions: permessage-deflate\r\n",
                "Origin: https://evil.example\r\n",
                "X-Keep: kept\r\n",
                &format!("X-Forwarded-For: {IP}\r\n"),
                "X-Forwarded-Proto: https\r\n",
            ] {
                assert!(seen.contains(kept), "{kept} missing in {seen}");
            }
            let lower = seen.to_ascii_lowercase();
            assert_eq!(lower.matches("upgrade:").count(), 1, "{seen}");
            assert_eq!(lower.matches("connection:").count(), 1, "{seen}");
            for gone in [
                "6.6.6.6",
                "keep-alive",
                "x-secret",
                "content-length",
                "websocket\r\nconn",
            ] {
                assert!(!lower.contains(gone), "{gone} survived in {seen}");
            }
            assert_eq!(lower.matches("x-forwarded-for").count(), 1);
            // The node answers; bytes of its first frame sit right behind its head, and its own
            // hop headers, a cookie for a parent domain and a subprotocol are dealt with.
            let reply = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade, X-Node-Hop\r\nX-Node-Hop: h\r\n\
                 Sec-WebSocket-Accept: {ACCEPT}\r\nSec-WebSocket-Protocol: chat\r\n\
                 Set-Cookie: s=1; Domain=evil.example; Path=/\r\n\
                 Keep-Alive: timeout=1\r\nVia: 1.1 node\r\n\r\n"
            )
            .into_bytes();
            let mut wire = reply.clone();
            wire.extend_from_slice(b"\x81\x05hello");
            rig.node.send(&wire);
            let head = text(&rig.client.head().await);
            assert!(
                head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"),
                "{head}"
            );
            assert!(head.contains("\r\nUpgrade: websocket\r\n"));
            assert!(head.contains("\r\nConnection: Upgrade\r\n"));
            assert!(head.contains(&format!("Sec-WebSocket-Accept: {ACCEPT}\r\n")));
            assert!(head.contains("Sec-WebSocket-Protocol: chat\r\n"));
            assert!(head.contains("Set-Cookie: s=1; Path=/\r\n"), "{head}");
            let lower = head.to_ascii_lowercase();
            for gone in ["keep-alive", "via:", "evil.example", "x-node-hop"] {
                assert!(!lower.contains(gone), "{gone} in {head}");
            }
            assert_eq!(rig.client.take(7).await, b"\x81\x05hello");
            // Frames of several sizes, in both directions, in order, byte for byte.
            let mut up = Vec::new();
            let mut down = Vec::new();
            for (i, size) in [1usize, 2, 125, 126, 16_383, 16_384, 16_385, 100_000]
                .into_iter()
                .enumerate()
            {
                let frame: Vec<u8> = (0..size).map(|n| (n + i) as u8).collect();
                rig.client.send(&frame);
                up.extend_from_slice(&frame);
                let frame: Vec<u8> = (0..size).map(|n| (n * 3 + i) as u8).collect();
                rig.node.send(&frame);
                down.extend_from_slice(&frame);
            }
            assert!(rig.node.take(up.len()).await == up, "client to node");
            assert!(rig.client.take(down.len()).await == down, "node to client");
            assert_eq!(rig.opened.load(Ordering::SeqCst), 1);
            assert!(!rig.over().await);
            assert_eq!(rig.client.closes() + rig.node.closes(), 0);
        }

        #[tokio::test]
        async fn the_accept_is_computed_for_the_key_that_was_sent() {
            // A node that answers the accept of the other key is refused: the relay does not
            // take the value from the node, it computes it.
            let mut rig = rig(limits());
            let request = ws_head(
                "GET",
                &GOOD,
                &["Sec-WebSocket-Key"],
                &[&format!("Sec-WebSocket-Key: {KEY2}")],
            );
            rig.client.send(&request);
            rig.node.head().await;
            rig.node.send(&accept_reply(ACCEPT, ""));
            assert!(text(&rig.client.head().await).starts_with("HTTP/1.1 502"));
            let mut rig = self::rig(limits());
            rig.client.send(&request);
            rig.node.head().await;
            rig.node.send(&accept_reply(ACCEPT2, ""));
            assert!(text(&rig.client.head().await).starts_with("HTTP/1.1 101"));
        }

        #[tokio::test]
        async fn a_zero_content_length_is_no_body_and_is_not_forwarded() {
            let mut rig = rig(limits());
            rig.client
                .send(&ws_head("GET", &GOOD, &[], &["Content-Length: 0"]));
            let seen = text(&rig.node.head().await);
            assert!(
                !seen.to_ascii_lowercase().contains("content-length"),
                "{seen}"
            );
        }

        #[tokio::test]
        async fn every_upgrade_that_is_not_a_clean_websocket_handshake_is_refused_before_the_node()
        {
            let cases: Vec<(&str, Vec<u8>, u16)> = vec![
                (
                    "h2c",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Upgrade", "Sec-WebSocket-Key", "Sec-WebSocket-Version"],
                        &["Upgrade: h2c", "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA"],
                    ),
                    501,
                ),
                (
                    "a list",
                    ws_head("GET", &GOOD, &["Upgrade"], &["Upgrade: websocket, h2c"]),
                    501,
                ),
                (
                    "another token",
                    ws_head("GET", &GOOD, &["Upgrade"], &["Upgrade: websockets"]),
                    501,
                ),
                (
                    "a doubled header",
                    ws_head("GET", &GOOD, &[], &["Upgrade: websocket"]),
                    501,
                ),
                (
                    "a doubled header with h2c second",
                    ws_head("GET", &GOOD, &[], &["Upgrade: h2c"]),
                    501,
                ),
                (
                    "Connection: upgrade with no Upgrade header",
                    ws_head("GET", &GOOD, &["Upgrade"], &[]),
                    501,
                ),
                (
                    "a Content-Length body",
                    ws_head("GET", &GOOD, &[], &["Content-Length: 4"]),
                    400,
                ),
                (
                    "chunked",
                    ws_head("GET", &GOOD, &[], &["Transfer-Encoding: chunked"]),
                    400,
                ),
                (
                    "a body with a smuggled request behind it",
                    [
                        ws_head("GET", &GOOD, &[], &["Content-Length: 31"]),
                        b"GET /admin HTTP/1.1\r\nHost: x\r\n".to_vec(),
                    ]
                    .concat(),
                    400,
                ),
                (
                    "a key of 15 bytes",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Sec-WebSocket-Key"],
                        &["Sec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4P"],
                    ),
                    400,
                ),
                (
                    "a key of 17 bytes",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Sec-WebSocket-Key"],
                        &["Sec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEBE="],
                    ),
                    400,
                ),
                (
                    "a key that is not base64",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Sec-WebSocket-Key"],
                        &["Sec-WebSocket-Key: !!!!!!!!!!!!!!!!!!!!!!=="],
                    ),
                    400,
                ),
                (
                    "an empty key",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Sec-WebSocket-Key"],
                        &["Sec-WebSocket-Key:"],
                    ),
                    400,
                ),
                (
                    "no key",
                    ws_head("GET", &GOOD, &["Sec-WebSocket-Key"], &[]),
                    400,
                ),
                (
                    "two keys",
                    ws_head(
                        "GET",
                        &GOOD,
                        &[],
                        &["Sec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEA=="],
                    ),
                    400,
                ),
                (
                    "an underscore spelling of the key beside the key",
                    ws_head(
                        "GET",
                        &GOOD,
                        &[],
                        &["Sec_WebSocket_Key: AQIDBAUGBwgJCgsMDQ4PEA=="],
                    ),
                    400,
                ),
                (
                    "an underscore spelling of the version beside the version",
                    ws_head("GET", &GOOD, &[], &["Sec_WebSocket_Version: 8"]),
                    400,
                ),
                (
                    "a mixed spelling of the key beside the key",
                    ws_head(
                        "GET",
                        &GOOD,
                        &[],
                        &["sec_websocket-KEY: AQIDBAUGBwgJCgsMDQ4PEA=="],
                    ),
                    400,
                ),
                (
                    "a Connection that names the underscore spelling of a Sec-WebSocket header",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Connection"],
                        &["Connection: Upgrade, Sec_WebSocket_Key"],
                    ),
                    400,
                ),
                (
                    "version 12",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Sec-WebSocket-Version"],
                        &["Sec-WebSocket-Version: 12"],
                    ),
                    400,
                ),
                (
                    "version 013",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Sec-WebSocket-Version"],
                        &["Sec-WebSocket-Version: 013"],
                    ),
                    400,
                ),
                (
                    "a list of versions",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Sec-WebSocket-Version"],
                        &["Sec-WebSocket-Version: 13, 8"],
                    ),
                    400,
                ),
                (
                    "two versions",
                    ws_head("GET", &GOOD, &[], &["Sec-WebSocket-Version: 13"]),
                    400,
                ),
                (
                    "no version",
                    ws_head("GET", &GOOD, &["Sec-WebSocket-Version"], &[]),
                    400,
                ),
                (
                    "no Connection header",
                    ws_head("GET", &GOOD, &["Connection"], &[]),
                    400,
                ),
                (
                    "Connection without upgrade",
                    ws_head("GET", &GOOD, &["Connection"], &["Connection: keep-alive"]),
                    400,
                ),
                (
                    "Connection: Upgrade, close",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Connection"],
                        &["Connection: Upgrade, close"],
                    ),
                    400,
                ),
                (
                    "Connection naming the key",
                    ws_head(
                        "GET",
                        &GOOD,
                        &["Connection"],
                        &["Connection: Upgrade, Sec-WebSocket-Key"],
                    ),
                    400,
                ),
                ("POST", ws_head("POST", &GOOD, &[], &[]), 400),
                ("HEAD", ws_head("HEAD", &GOOD, &[], &[]), 400),
                ("OPTIONS", ws_head("OPTIONS", &GOOD, &[], &[]), 400),
                (
                    "a handshake with Expect",
                    ws_head("GET", &GOOD, &[], &["Expect: 100-continue"]),
                    417,
                ),
                (
                    "the wrong Host",
                    ws_head("GET", &GOOD, &[], &[]).replace_host("evil.test"),
                    421,
                ),
            ];
            for (what, request, code) in cases {
                let out = exchange(&request, OK).await;
                assert!(
                    status(&out).starts_with(&format!("HTTP/1.1 {code} ")),
                    "{what}: wanted {code}, got {:?}",
                    text(&out.client)
                );
                assert_eq!(out.opened, 0, "{what}: the node stream was opened");
                assert!(out.node.is_empty(), "{what}: the node saw {:?}", out.node);
            }
            // HTTP/1.0 with an upgrade is still the version error.
            let out = exchange(
                format!(
                    "GET /chat HTTP/1.0\r\nHost: {HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                )
                .as_bytes(),
                OK,
            )
            .await;
            assert!(status(&out).starts_with("HTTP/1.1 505"));
        }

        trait ReplaceHost {
            fn replace_host(self, host: &str) -> Vec<u8>;
        }

        impl ReplaceHost for Vec<u8> {
            fn replace_host(self, host: &str) -> Vec<u8> {
                text(&self).replace(HOST, host).into_bytes()
            }
        }

        #[tokio::test]
        async fn bytes_pipelined_behind_the_handshake_close_the_connection_and_go_nowhere() {
            // In the same write as the head: the request is not forwarded at all.
            let out = exchange(
                &[
                    ws_head("GET", &GOOD, &[], &[]),
                    b"\x81\x84abcdsmuggled".to_vec(),
                ]
                .concat(),
                &accept_reply(ACCEPT, ""),
            )
            .await;
            assert!(
                status(&out).starts_with("HTTP/1.1 400"),
                "{:?}",
                text(&out.client)
            );
            assert_eq!(out.opened, 0);
            assert!(out.node.is_empty());
            // After the head and before the 101: the client is answered 400 and closed; what it
            // sent is never forwarded, and the 101 that comes later reaches nobody.
            let mut rig = rig(limits());
            rig.client.send(&ws_head("GET", &GOOD, &[], &[]));
            let forwarded = rig.node.head().await;
            assert!(forwarded.starts_with(b"GET /chat"));
            rig.client.send(b"\x81\x84abcdsmuggled");
            assert!(rig.over().await, "the connection must end");
            assert!(text(&rig.client.pending().await).starts_with("HTTP/1.1 400"));
            rig.node.send(&accept_reply(ACCEPT, ""));
            assert!(
                rig.node.pending().await.is_empty(),
                "nothing more reached the node"
            );
        }

        #[tokio::test]
        async fn a_client_that_leaves_before_the_101_ends_the_connection() {
            let mut rig = rig(limits());
            rig.client.send(&ws_head("GET", &GOOD, &[], &[]));
            rig.node.head().await;
            rig.client.eof();
            assert!(rig.over().await);
            assert!(
                rig.client.pending().await.is_empty(),
                "no answer to a client that left"
            );
            // A reset is the same.
            let mut rig = self::rig(limits());
            rig.client.send(&ws_head("GET", &GOOD, &[], &[]));
            rig.node.head().await;
            rig.client.reset();
            assert!(rig.over().await);
        }

        /// The node's answer to a handshake, and what the client got of it.
        async fn answered(reply: &[u8]) -> String {
            let mut rig = rig(limits());
            rig.client.send(&ws_head("GET", &GOOD, &[], &[]));
            rig.node.head().await;
            rig.node.send(reply);
            assert!(rig.over().await, "the connection must end");
            let got = text(&rig.client.pending().await);
            assert_eq!(rig.client.closes(), 1, "a refusal is a clean close: {got}");
            got
        }

        #[tokio::test]
        async fn a_101_that_is_not_exactly_the_websocket_answer_is_a_502() {
            let good = |extra: &str| accept_reply(ACCEPT, extra);
            let replies: Vec<(&str, Vec<u8>)> = vec![
                ("a wrong accept", accept_reply("AAAAAAAAAAAAAAAAAAAAAAAAAAA=", "")),
                (
                    "an accept of another case",
                    accept_reply(&ACCEPT.to_ascii_lowercase(), ""),
                ),
                (
                    "no accept",
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
                        .to_vec(),
                ),
                ("two accepts", good(&format!("Sec-WebSocket-Accept: {ACCEPT}\r\n"))),
                (
                    "no Upgrade",
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
                    )
                    .into_bytes(),
                ),
                (
                    "Upgrade: h2c",
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
                    )
                    .into_bytes(),
                ),
                ("two Upgrades", good("Upgrade: websocket\r\n")),
                (
                    "no Connection",
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
                    )
                    .into_bytes(),
                ),
                (
                    "Connection: close",
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade, close\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
                    )
                    .into_bytes(),
                ),
                (
                    "Connection naming the accept",
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade, Sec-WebSocket-Accept\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
                    )
                    .into_bytes(),
                ),
                ("a Content-Length", good("Content-Length: 0\r\n")),
                ("a Content-Length of 5", good("Content-Length: 5\r\n")),
                ("chunked", good("Transfer-Encoding: chunked\r\n")),
                (
                    "HTTP/1.0",
                    format!(
                        "HTTP/1.0 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n"
                    )
                    .into_bytes(),
                ),
                ("a bare LF", good("X-A: b\n")),
                ("102", b"HTTP/1.1 102 Processing\r\n\r\n".to_vec()),
                ("100", b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
                ("103", b"HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n".to_vec()),
                ("199", b"HTTP/1.1 199 Odd\r\n\r\n".to_vec()),
                (
                    "a 200 that carries the upgrade headers",
                    format!(
                        "HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\nContent-Length: 0\r\n\r\n"
                    )
                    .into_bytes(),
                ),
            ];
            for (what, reply) in replies {
                let got = answered(&reply).await;
                assert!(got.starts_with("HTTP/1.1 502"), "{what}: {got}");
                assert!(!got.contains("101"), "{what}: {got}");
            }
        }

        #[tokio::test]
        async fn a_101_nobody_asked_for_is_a_502() {
            let valid = accept_reply(ACCEPT, "");
            // A plain request.
            let out = exchange(&get(""), &valid).await;
            assert!(
                status(&out).starts_with("HTTP/1.1 502"),
                "{:?}",
                text(&out.client)
            );
            assert!(!text(&out.client).contains("101"));
            // A request with `Sec-WebSocket-Key` but no `Upgrade` is a plain request too.
            let out = exchange(&get(&format!("Sec-WebSocket-Key: {KEY}\r\n")), &valid).await;
            assert!(status(&out).starts_with("HTTP/1.1 502"));
            // The second request on a connection that had a plain first one: the upgrade
            // state belongs to the request, not to the connection.
            let mut rig = rig(limits());
            rig.client.send(&get(""));
            rig.node.head().await;
            rig.node.send(OK);
            rig.client.take(OK.len()).await;
            rig.client.send(&get("Sec-WebSocket-Key: x\r\n"));
            rig.node.head().await;
            rig.node.send(&valid);
            assert!(text(&rig.client.head().await).starts_with("HTTP/1.1 502"));
        }

        #[tokio::test]
        async fn a_final_answer_to_a_handshake_is_an_ordinary_response_and_the_connection_stays_http()
         {
            for reply in [
                &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..],
                b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\nno",
                b"HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nno\r\n0\r\n\r\n",
            ] {
                let mut rig = rig(limits());
                let head = rig.switch(&ws_head("GET", &GOOD, &[], &[]), reply).await;
                assert!(!text(&head).contains("101"), "{}", text(&head));
                // The body follows, the connection is kept alive, and the next request is an
                // ordinary one on the same node stream.
                let body_len = if reply.starts_with(b"HTTP/1.1 404") {
                    12
                } else {
                    2
                };
                rig.client.take(body_len).await;
                rig.client.send(&get("X-N: 2\r\n"));
                let second = text(&rig.node.head().await);
                assert!(second.contains("X-N: 2"), "{second}");
                assert!(!second.to_ascii_lowercase().contains("upgrade"), "{second}");
                rig.node.send(OK);
                assert!(text(&rig.client.head().await).starts_with("HTTP/1.1 200"));
                assert_eq!(rig.opened.load(Ordering::SeqCst), 1);
                assert!(!rig.over().await);
            }
        }

        #[tokio::test]
        async fn a_reset_of_the_node_in_the_pipe_ends_the_client_without_a_close_notify() {
            let mut rig = rig(limits());
            rig.ok().await;
            rig.node.send(b"frame");
            assert_eq!(rig.client.take(5).await, b"frame");
            rig.node.reset();
            assert!(rig.over().await);
            assert_eq!(rig.client.closes(), 0, "a reset is not a clean end");
        }

        #[tokio::test]
        async fn a_reset_of_the_client_in_the_pipe_ends_the_connection_without_a_clean_end() {
            let mut rig = rig(limits());
            rig.ok().await;
            rig.client.send(b"frame");
            assert_eq!(rig.node.take(5).await, b"frame");
            rig.client.reset();
            assert!(rig.over().await);
            assert_eq!(rig.client.closes(), 0);
            assert_eq!(
                rig.node.closes(),
                0,
                "the node's stream is dropped, not closed"
            );
        }

        #[tokio::test]
        async fn a_reset_right_behind_the_head_still_delivers_what_the_head_carried() {
            let mut rig = rig(limits());
            rig.client.send(&ws_head("GET", &GOOD, &[], &[]));
            rig.node.head().await;
            let mut wire = accept_reply(ACCEPT, "");
            wire.extend_from_slice(b"first");
            rig.node.send(&wire);
            rig.node.reset();
            rig.client.head().await;
            assert_eq!(rig.client.take(5).await, b"first");
            assert!(rig.over().await);
            assert_eq!(rig.client.closes(), 0);
        }

        #[tokio::test]
        async fn a_clean_end_of_the_node_lets_the_client_finish_and_both_ends_are_clean() {
            let mut rig = rig(limits());
            rig.ok().await;
            rig.node.send(b"bye");
            rig.node.eof();
            assert_eq!(rig.client.take(3).await, b"bye");
            settle().await;
            assert_eq!(
                rig.client.closes(),
                1,
                "that direction is shut down cleanly"
            );
            assert_eq!(rig.node.closes(), 0);
            assert!(!rig.over().await, "the other direction may still drain");
            rig.client.send(b"last words");
            assert_eq!(rig.node.take(10).await, b"last words");
            rig.client.eof();
            assert!(rig.over().await);
            assert_eq!(rig.client.closes(), 1);
            assert_eq!(rig.node.closes(), 1);
        }

        #[tokio::test]
        async fn a_clean_end_of_the_client_lets_the_node_finish() {
            let mut rig = rig(limits());
            rig.ok().await;
            rig.client.eof();
            settle().await;
            assert_eq!(rig.node.closes(), 1);
            assert_eq!(rig.client.closes(), 0);
            rig.node.send(b"reply");
            assert_eq!(rig.client.take(5).await, b"reply");
            rig.node.eof();
            assert!(rig.over().await);
            assert_eq!((rig.client.closes(), rig.node.closes()), (1, 1));
        }

        #[tokio::test]
        async fn a_reset_after_one_clean_end_is_no_clean_end() {
            let mut rig = rig(limits());
            rig.ok().await;
            rig.node.eof();
            settle().await;
            rig.client.reset();
            assert!(rig.over().await);
            assert_eq!(rig.node.closes(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn the_other_direction_has_the_drain_time_after_one_side_ended() {
            let mut rig = rig(HttpLimits::default());
            rig.ok().await;
            rig.node.eof();
            settle().await;
            tokio::time::advance(Duration::from_secs(29)).await;
            assert!(!rig.over().await, "29 s after the end of one side");
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(rig.over().await, "30 s after the end of one side");
            assert_eq!(
                rig.client.closes(),
                1,
                "only the clean end of the node's side"
            );
            assert_eq!(rig.node.closes(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn five_quiet_minutes_end_the_connection_and_traffic_in_either_direction_restarts_them()
         {
            let mut rig = rig(HttpLimits::default());
            rig.ok().await;
            tokio::time::advance(Duration::from_secs(299)).await;
            assert!(!rig.over().await, "299 s of silence");
            // One byte from the node, 299 s in: the count starts again.
            rig.node.send(b"p");
            assert_eq!(rig.client.take(1).await, b"p");
            tokio::time::advance(Duration::from_secs(299)).await;
            assert!(!rig.over().await);
            // And one from the client.
            rig.client.send(b"q");
            assert_eq!(rig.node.take(1).await, b"q");
            tokio::time::advance(Duration::from_secs(299)).await;
            assert!(!rig.over().await);
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(rig.over().await, "300 s without a byte");
            assert_eq!(
                rig.client.closes(),
                0,
                "the end of an idle connection is not a clean end"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn there_is_no_cap_on_the_total_lifetime_of_a_busy_connection() {
            let mut rig = rig(HttpLimits::default());
            rig.ok().await;
            for _ in 0..30 {
                tokio::time::advance(Duration::from_secs(120)).await;
                rig.node.send(b"p");
                assert_eq!(rig.client.take(1).await, b"p");
            }
            assert!(!rig.over().await, "an hour of pings");
        }

        #[tokio::test(start_paused = true)]
        async fn a_name_that_is_no_longer_served_cuts_the_pipe_within_thirty_seconds() {
            let mut rig = rig(HttpLimits::default());
            rig.ok().await;
            rig.node.send(b"p");
            assert_eq!(rig.client.take(1).await, b"p");
            rig.served.store(false, Ordering::SeqCst);
            tokio::time::advance(Duration::from_secs(29)).await;
            assert!(!rig.over().await, "asked every 30 s, not before");
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(rig.over().await);
            assert_eq!(rig.client.closes(), 0, "a cut pipe is not a clean end");
            assert_eq!(rig.node.closes(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn a_name_that_is_served_is_asked_again_and_again_and_stays() {
            let mut rig = rig(HttpLimits::default());
            rig.ok().await;
            for _ in 0..20 {
                tokio::time::advance(Duration::from_secs(31)).await;
                rig.node.send(b"p");
                rig.client.take(1).await;
            }
            assert!(!rig.over().await);
            // And it is asked at all while the pipe is busy: a withdrawal during traffic cuts it.
            rig.served.store(false, Ordering::SeqCst);
            for _ in 0..2 {
                tokio::time::advance(Duration::from_secs(16)).await;
                rig.node.send(b"p");
                settle().await;
            }
            assert!(rig.over().await);
        }

        // ---- ordinary exchanges are re-checked while a body moves (expose round 4, M1) ----
        // (the rig and its clock are the WebSocket's: the same `upgrade_recheck` of 30 s)

        const CHUNKED_POST: &[u8] = b"POST /up HTTP/1.1\r\nHost: web.t.s.example.test\r\n\
            Transfer-Encoding: chunked\r\n\r\n";
        const LENGTH_POST: &[u8] = b"POST /up HTTP/1.1\r\nHost: web.t.s.example.test\r\n\
            Content-Length: 100000\r\n\r\n";
        const GET_EVENTS: &[u8] = b"GET /events HTTP/1.1\r\nHost: web.t.s.example.test\r\n\r\n";

        /// The request is forwarded and the first `body` bytes of it are at the node.
        async fn upload(rig: &mut Rig, request: &[u8], body: &[u8]) {
            rig.client.send(request);
            rig.client.send(body);
            let head = rig.node.head().await;
            assert!(head.starts_with(b"POST /up HTTP/1.1\r\n"));
            assert_eq!(rig.node.take(body.len()).await, body);
        }

        /// A request body of a name that stops being served ends the connection within the
        /// interval, whatever the framing, and the bytes sent after that go nowhere.
        async fn a_request_body_case(request: &[u8], first: &[u8], more: &[u8]) {
            let mut rig = rig(HttpLimits::default());
            upload(&mut rig, request, first).await;
            rig.served.store(false, Ordering::SeqCst);
            tokio::time::advance(Duration::from_secs(29)).await;
            assert!(!rig.over().await, "asked every 30 s, not before");
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(rig.over().await, "cut within the interval");
            rig.client.send(more);
            assert!(
                rig.node.pending().await.is_empty(),
                "nothing of the client reaches the node after the cut"
            );
            assert_eq!(rig.client.closes(), 0, "a cut is not a clean end");
            assert_eq!(rig.node.closes(), 0);
            assert_eq!(rig.client.pending().await, b"", "and no answer is written");
        }

        #[tokio::test(start_paused = true)]
        async fn a_chunked_request_body_is_cut_when_the_name_is_no_longer_served() {
            a_request_body_case(CHUNKED_POST, b"5\r\nhello\r\n", b"6\r\ncookie\r\n").await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_content_length_request_body_is_cut_when_the_name_is_no_longer_served() {
            a_request_body_case(LENGTH_POST, b"hello", b"cookie").await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_request_body_of_a_name_still_served_goes_on_past_many_rechecks() {
            let mut rig = rig(HttpLimits::default());
            upload(&mut rig, CHUNKED_POST, b"5\r\nhello\r\n").await;
            for _ in 0..20 {
                tokio::time::advance(Duration::from_secs(31)).await;
                rig.client.send(b"1\r\nx\r\n");
                assert_eq!(rig.node.take(6).await, b"1\r\nx\r\n");
            }
            assert!(!rig.over().await, "ten minutes of upload, asked 20 times");
            // It ends the way an upload does: the answer, and the connection is kept.
            rig.client.send(b"0\r\n\r\n");
            rig.node.take(5).await;
            rig.node
                .send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            assert!(rig.client.head().await.starts_with(b"HTTP/1.1 200 OK"));
            assert_eq!(rig.client.take(2).await, b"ok");
            assert!(!rig.over().await);
        }

        /// A response body of a name that stops being served ends the connection within the
        /// interval, whatever the framing, with no clean end.
        async fn a_response_body_case(response_head: &[u8], first: &[u8], more: &[u8]) {
            let mut rig = rig(HttpLimits::default());
            rig.client.send(GET_EVENTS);
            rig.node.head().await;
            rig.node.send(response_head);
            rig.node.send(first);
            rig.client.head().await;
            rig.client.take(first.len()).await;
            rig.served.store(false, Ordering::SeqCst);
            tokio::time::advance(Duration::from_secs(29)).await;
            assert!(!rig.over().await, "asked every 30 s, not before");
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(rig.over().await, "cut within the interval");
            rig.node.send(more);
            assert!(
                rig.client.pending().await.is_empty(),
                "nothing more of the old holder reaches the client"
            );
            assert_eq!(rig.client.closes(), 0, "a cut is not a clean end");
        }

        #[tokio::test(start_paused = true)]
        async fn a_chunked_response_body_is_cut_when_the_name_is_no_longer_served() {
            a_response_body_case(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
                b"5\r\nhello\r\n",
                b"5\r\nagain\r\n",
            )
            .await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_content_length_response_body_is_cut_when_the_name_is_no_longer_served() {
            a_response_body_case(
                b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n",
                b"hello",
                b"again",
            )
            .await;
        }

        #[tokio::test(start_paused = true)]
        async fn an_until_close_response_body_is_cut_when_the_name_is_no_longer_served() {
            a_response_body_case(b"HTTP/1.1 200 OK\r\n\r\n", b"hello", b"again").await;
        }

        #[tokio::test(start_paused = true)]
        async fn a_response_body_of_a_name_still_served_goes_on_past_many_rechecks() {
            let mut rig = rig(HttpLimits::default());
            rig.client.send(GET_EVENTS);
            rig.node.head().await;
            rig.node.send(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\r\n",
            );
            rig.client.head().await;
            for _ in 0..20 {
                tokio::time::advance(Duration::from_secs(31)).await;
                rig.node.send(b"1\r\nx\r\n");
                assert_eq!(rig.client.take(6).await, b"1\r\nx\r\n");
            }
            assert!(!rig.over().await, "ten minutes of events, asked 20 times");
            rig.node.send(b"0\r\n\r\n");
            rig.client.take(5).await;
            assert!(
                !rig.over().await,
                "a finished exchange keeps the connection"
            );
        }

        #[tokio::test(start_paused = true)]
        async fn a_wait_for_the_nodes_answer_ends_when_the_name_is_no_longer_served() {
            let mut rig = rig(HttpLimits::default());
            rig.client.send(GET_EVENTS);
            rig.node.head().await;
            rig.served.store(false, Ordering::SeqCst);
            tokio::time::advance(Duration::from_secs(29)).await;
            assert!(!rig.over().await, "asked every 30 s, not before");
            tokio::time::advance(Duration::from_secs(2)).await;
            assert!(rig.over().await, "well before the 120 s body idle time");
            rig.node
                .send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            assert!(
                rig.client.pending().await.is_empty(),
                "neither an answer of the old holder nor a 502 is written"
            );
            assert_eq!(rig.client.closes(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn a_wait_for_the_websockets_101_ends_when_the_name_is_no_longer_served() {
            let mut rig = rig(HttpLimits::default());
            rig.client.send(&ws_head("GET", &GOOD, &[], &[]));
            rig.node.head().await;
            rig.served.store(false, Ordering::SeqCst);
            tokio::time::advance(Duration::from_secs(31)).await;
            assert!(rig.over().await);
            rig.node.send(&accept_reply(ACCEPT, ""));
            assert!(rig.client.pending().await.is_empty());
        }

        #[tokio::test]
        async fn the_serve_future_lives_as_long_as_the_pipe_so_the_front_doors_slot_is_kept() {
            // The front door drops its connection slot when `serve` returns.
            let mut rig = rig(limits());
            rig.ok().await;
            for _ in 0..5 {
                rig.node.send(b"p");
                rig.client.take(1).await;
                assert!(!rig.over().await);
            }
            rig.client.eof();
            rig.node.eof();
            assert!(rig.over().await);
        }
    }
}
