//! HTTP `CONNECT` on the proxy port (protocol.md 8; slice 2a): a strict request head parser, the
//! authority canonicalization, the fixed responses and the reader that keeps the bytes a client
//! sent behind its head.
//!
//! The rules are those of `docs/private/egress-slice2-design.md` 1.2 and 1.3. In short: the
//! request line is exactly `CONNECT authority HTTP/1.1` (or `HTTP/1.0`) and the head ends only at
//! `CRLF CRLF` (a bare LF or a lone CR anywhere in it is a `400`, so the proxy and anything in
//! front of it agree on where the head ends); no folded header, no whitespace before the colon,
//! at most [`MAX_HEADERS`] header lines and [`MAX_HEAD`] bytes; a body header
//! (`Transfer-Encoding`, or `Content-Length` other than `0`) is a `400`; `Host` is optional but
//! must equal the authority; the destination is taken from the request line only and goes through
//! the exit's own [`Target::canonicalize`], so the client never accepts what the exit refuses
//! nor the reverse. No name is resolved here. Header values are never logged.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use menzil_node::egress::{Host, Target};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

/// The most bytes of a request head (request line, headers and the final blank line).
pub const MAX_HEAD: usize = 8 * 1024;
/// The most header lines.
pub const MAX_HEADERS: usize = 64;

/// The success response: no headers (a `2xx` to `CONNECT` carries no `Content-Length`).
pub const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection established\r\n\r\n";

/// Why a head is refused, each with a fixed status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// 400.
    BadRequest,
    /// 405: a method other than `CONNECT`.
    MethodNotAllowed,
    /// 431: too large a head, or too many header lines.
    HeaderTooLarge,
}

impl Refusal {
    /// The status code.
    pub fn status(self) -> u16 {
        match self {
            Refusal::BadRequest => 400,
            Refusal::MethodNotAllowed => 405,
            Refusal::HeaderTooLarge => 431,
        }
    }
}

/// An accepted request: the destination in the exit's canonical text (an address as `std::net`
/// prints it, IPv6 without brackets; a name lowercase), and the port, 1 to 65535.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connect {
    pub host: String,
    pub port: u16,
}

/// The reason phrase and the fixed body of a refusal status.
fn words(status: u16) -> (&'static str, &'static str) {
    match status {
        400 => ("Bad Request", "menzil proxy: bad request\n"),
        403 => ("Forbidden", "menzil proxy: not allowed\n"),
        405 => (
            "Method Not Allowed",
            "menzil proxy: only CONNECT is supported\n",
        ),
        408 => ("Request Timeout", "menzil proxy: request timed out\n"),
        431 => (
            "Request Header Fields Too Large",
            "menzil proxy: request head too large\n",
        ),
        503 => ("Service Unavailable", "menzil proxy: try again later\n"),
        _ => (
            "Bad Gateway",
            "menzil proxy: the exit could not be reached\n",
        ),
    }
}

/// A refusal response: the same bytes for the same status whatever the cause (the exit's text
/// never reaches the client), always closing the connection.
pub fn response(status: u16) -> Vec<u8> {
    let (reason, body) = words(status);
    let allow = if status == 405 {
        "Allow: CONNECT\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n{allow}Connection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A `tchar` of RFC 9110 5.6.2.
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// `bytes` without leading and trailing SP and HTAB.
fn trim_ows(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

/// `host:port` of a request line, to the destination the exit is sent. Strict: a port of 1 to 5
/// digits (no sign, no leading zero, 1 to 65535), a host that is a bracketed IPv6 literal (the
/// inside has a `:`), an IPv4 literal or a name, printable ASCII only, no userinfo, no zone, no
/// percent; then the ASCII letters are folded to lower case (as the SOCKS path does) and the
/// exit's own [`Target::canonicalize`] decides. Anything else is a `400`.
pub fn parse_authority(text: &str) -> Result<Connect, Refusal> {
    use Refusal::BadRequest;
    if text.is_empty() || !text.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(BadRequest);
    }
    if text.contains(['@', '%', '/', '?', '#']) {
        return Err(BadRequest);
    }
    let (host, port) = text.rsplit_once(':').ok_or(BadRequest)?;
    if port.is_empty()
        || port.len() > 5
        || !port.bytes().all(|b| b.is_ascii_digit())
        || port.starts_with('0')
    {
        return Err(BadRequest);
    }
    let port: u32 = port.parse().map_err(|_| BadRequest)?;
    let port = u16::try_from(port).map_err(|_| BadRequest)?;
    let host = if let Some(inside) = host.strip_prefix('[') {
        let inside = inside.strip_suffix(']').ok_or(BadRequest)?;
        if !inside.contains(':') || inside.contains(['[', ']']) {
            return Err(BadRequest);
        }
        inside
    } else {
        if host.contains([':', '[', ']']) {
            return Err(BadRequest);
        }
        host
    };
    let host = host.to_ascii_lowercase();
    let target = Target::canonicalize(&host, port).map_err(|_| BadRequest)?;
    let host = match target.host() {
        Host::Addr(ip) => ip.to_string(),
        Host::Name(name) => name.as_str().to_string(),
    };
    Ok(Connect {
        host,
        port: target.port(),
    })
}

/// Splits `bytes` at every CRLF. A lone CR or LF left inside a line is the caller's to refuse.
fn split_crlf(bytes: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\r' && bytes[i + 1] == b'\n' {
            lines.push(&bytes[start..i]);
            start = i + 2;
            i += 2;
        } else {
            i += 1;
        }
    }
    lines.push(&bytes[start..]);
    lines
}

/// A whole head (ending at its `CRLF CRLF`), to the request it makes, or the refusal.
pub fn parse_head(head: &[u8]) -> Result<Connect, Refusal> {
    use Refusal::{BadRequest, HeaderTooLarge, MethodNotAllowed};
    if head.len() > MAX_HEAD {
        return Err(HeaderTooLarge);
    }
    let body = head.strip_suffix(b"\r\n\r\n").ok_or(BadRequest)?;
    let lines = split_crlf(body);
    if lines
        .iter()
        .any(|line| line.contains(&b'\r') || line.contains(&b'\n'))
    {
        return Err(BadRequest);
    }
    if lines.len() - 1 > MAX_HEADERS {
        return Err(HeaderTooLarge);
    }
    // Request line.
    let parts: Vec<&[u8]> = lines[0].split(|&b| b == b' ').collect();
    if parts[0] != b"CONNECT" {
        let token = !parts[0].is_empty() && parts[0].iter().all(|&b| is_token_byte(b));
        return Err(if token { MethodNotAllowed } else { BadRequest });
    }
    if parts.len() != 3 || !matches!(parts[2], b"HTTP/1.1" | b"HTTP/1.0") {
        return Err(BadRequest);
    }
    let authority = std::str::from_utf8(parts[1]).map_err(|_| BadRequest)?;
    let connect = parse_authority(authority)?;
    // Header lines.
    let mut host: Option<&[u8]> = None;
    let mut length_seen = false;
    for line in &lines[1..] {
        let colon = line.iter().position(|&b| b == b':').ok_or(BadRequest)?;
        let (name, value) = (&line[..colon], trim_ows(&line[colon + 1..]));
        if name.is_empty() || !name.iter().all(|&b| is_token_byte(b)) {
            return Err(BadRequest);
        }
        if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(BadRequest);
        }
        match name.to_ascii_lowercase().as_slice() {
            b"host" => {
                if host.replace(value).is_some() {
                    return Err(BadRequest);
                }
            }
            b"transfer-encoding" => return Err(BadRequest),
            b"content-length" => {
                if value != b"0" || length_seen {
                    return Err(BadRequest);
                }
                length_seen = true;
            }
            _ => {}
        }
    }
    if let Some(host) = host
        && !host.eq_ignore_ascii_case(authority.as_bytes())
    {
        return Err(BadRequest);
    }
    Ok(connect)
}

/// Why [`read_head`] did not produce a request.
#[derive(Debug, PartialEq, Eq)]
pub enum HeadError {
    /// The head is refused with this status.
    Refused(Refusal),
    /// The client went away or the connection failed.
    Gone,
}

/// Whether `buf[from..limit]` holds a bare LF or a lone CR (a CR as the very last byte of `buf`
/// may still be followed by its LF, so it is not one yet).
fn bare_line_ending(buf: &[u8], from: usize, limit: usize) -> bool {
    (from..limit).any(|i| match buf[i] {
        b'\n' => i == 0 || buf[i - 1] != b'\r',
        b'\r' => i + 1 < buf.len() && buf[i + 1] != b'\n',
        _ => false,
    })
}

/// Reads a head whose first byte `first` has been read already, to its `CRLF CRLF`, no further:
/// returns the request and the bytes that came behind the head (the first bytes of the tunnel).
/// A bare LF or lone CR is refused as soon as it is read, a head past [`MAX_HEAD`] bytes without
/// its end is a `431`. The caller bounds the time.
pub async fn read_head<R: AsyncRead + Unpin>(
    read: &mut R,
    first: u8,
) -> Result<(Connect, Vec<u8>), HeadError> {
    let mut buf = vec![0u8; MAX_HEAD];
    buf[0] = first;
    let mut len = 1;
    let mut checked = 0;
    let mut searched = 0;
    loop {
        let end = buf[..len]
            .windows(4)
            .skip(searched)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + searched + 4);
        searched = len.saturating_sub(3);
        let limit = end.unwrap_or(len);
        if bare_line_ending(&buf[..len], checked, limit) {
            return Err(HeadError::Refused(Refusal::BadRequest));
        }
        checked = limit.saturating_sub(1);
        if let Some(end) = end {
            let connect = parse_head(&buf[..end]).map_err(HeadError::Refused)?;
            return Ok((connect, buf[end..len].to_vec()));
        }
        if len == MAX_HEAD {
            return Err(HeadError::Refused(Refusal::HeaderTooLarge));
        }
        match read.read(&mut buf[len..]).await {
            Ok(0) | Err(_) => return Err(HeadError::Gone),
            Ok(n) => len += n,
        }
    }
}

/// A reader that gives `head` first and then what `inner` gives: the bytes behind the request
/// head, which belong to the tunnel.
pub struct Prefixed<'a, R> {
    head: Vec<u8>,
    at: usize,
    inner: &'a mut R,
}

impl<'a, R> Prefixed<'a, R> {
    pub fn new(head: Vec<u8>, inner: &'a mut R) -> Self {
        Self { head, at: 0, inner }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Prefixed<'_, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.at < this.head.len() {
            let n = buf.remaining().min(this.head.len() - this.at);
            buf.put_slice(&this.head[this.at..this.at + n]);
            this.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(line: &str, headers: &[&str]) -> Vec<u8> {
        let mut out = format!("{line}\r\n");
        for h in headers {
            out.push_str(h);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.into_bytes()
    }

    fn ok(host: &str, port: u16) -> Result<Connect, Refusal> {
        Ok(Connect {
            host: host.to_string(),
            port,
        })
    }

    #[test]
    fn a_plain_connect_is_accepted_in_both_versions_with_or_without_headers() {
        let good = "CONNECT example.org:443 HTTP/1.1";
        assert_eq!(parse_head(&head(good, &[])), ok("example.org", 443));
        assert_eq!(
            parse_head(&head("CONNECT example.org:443 HTTP/1.0", &[])),
            ok("example.org", 443)
        );
        assert_eq!(
            parse_head(&head(
                good,
                &[
                    "Host: example.org:443",
                    "User-Agent: x",
                    "Proxy-Connection: keep-alive",
                    "Proxy-Authorization: Basic c2VjcmV0",
                    "Content-Length: 0",
                ]
            )),
            ok("example.org", 443)
        );
        // Host is compared without regard to case; the optional white space is trimmed.
        assert_eq!(
            parse_head(&head(good, &["HOST:\t EXAMPLE.org:443 "])),
            ok("example.org", 443)
        );
    }

    #[test]
    fn the_request_line_is_checked_exactly() {
        use Refusal::*;
        let cases: Vec<(&str, Refusal)> = vec![
            ("CONNECT example.org:443 HTTP/2.0", BadRequest),
            ("CONNECT example.org:443 HTTP/1.2", BadRequest),
            ("CONNECT example.org:443 http/1.1", BadRequest),
            ("CONNECT example.org:443", BadRequest),
            ("CONNECT example.org:443 HTTP/1.1 x", BadRequest),
            // extra spaces
            ("CONNECT  example.org:443 HTTP/1.1", BadRequest),
            ("CONNECT example.org:443  HTTP/1.1", BadRequest),
            (" CONNECT example.org:443 HTTP/1.1", BadRequest),
            ("CONNECT example.org:443 HTTP/1.1 ", BadRequest),
            // method
            ("connect example.org:443 HTTP/1.1", MethodNotAllowed),
            ("Connect example.org:443 HTTP/1.1", MethodNotAllowed),
            ("CONNECTX example.org:443 HTTP/1.1", MethodNotAllowed),
            ("GET http://example.org/ HTTP/1.1", MethodNotAllowed),
            ("POST / HTTP/1.1", MethodNotAllowed),
            // not authority-form
            ("CONNECT http://example.org:443/ HTTP/1.1", BadRequest),
            ("CONNECT http://example.org:443 HTTP/1.1", BadRequest),
            ("CONNECT / HTTP/1.1", BadRequest),
            ("CONNECT * HTTP/1.1", BadRequest),
            ("CONNECT example.org HTTP/1.1", BadRequest),
            ("CONNECT user@example.org:443 HTTP/1.1", BadRequest),
        ];
        for (line, want) in cases {
            assert_eq!(parse_head(&head(line, &[])), Err(want), "{line:?}");
        }
        assert_eq!(parse_head(b"\r\n\r\n"), Err(BadRequest));
        assert_eq!(
            parse_head(b"\r\nCONNECT example.org:443 HTTP/1.1\r\n\r\n"),
            Err(BadRequest)
        );
    }

    #[test]
    fn authorities_are_canonicalized_like_the_exit() {
        let good: Vec<(&str, &str, u16)> = vec![
            ("example.org:443", "example.org", 443),
            ("EXAMPLE.Org:443", "example.org", 443),
            ("93.184.216.34:80", "93.184.216.34", 80),
            ("[2001:db8::1]:443", "2001:db8::1", 443),
            ("[2001:DB8::1]:443", "2001:db8::1", 443),
            // an IPv4 mapped address goes out as the IPv4 one, as the exit reads it
            ("[::ffff:1.2.3.4]:80", "1.2.3.4", 80),
            ("[::ffff:7f00:1]:80", "127.0.0.1", 80),
            ("a:1", "a", 1),
            ("a:65535", "a", 65535),
        ];
        for (text, host, port) in good {
            assert_eq!(parse_authority(text), ok(host, port), "{text}");
        }
        let bad = [
            "example.org:0",
            "example.org:00443",
            "example.org:0443",
            "example.org:65536",
            "example.org:+443",
            "example.org:-1",
            "example.org:443x",
            "example.org:",
            "example.org:123456",
            ":443",
            "[::1]",
            "[::1:443",
            "::1:443",
            "2001:db8::1:443",
            "[1.2.3.4]:80",
            "[example.org]:80",
            "[fe80::1%25eth0]:80",
            "[fe80::1%eth0]:80",
            "[[::1]]:80",
            "127.1:80",
            "0x7f.1:80",
            "01.2.3.4:80",
            "1.2.3:80",
            "example.org.:80",
            "a..b:80",
            "exa mple.org:80",
            "exämple.org:80",
            "exa\tmple:80",
            "a@b.example:80",
            "a%41.example:80",
        ];
        for text in bad {
            assert_eq!(parse_authority(text), Err(Refusal::BadRequest), "{text}");
        }
        // Over the exit's own limits: a name of 254 bytes.
        let long = format!("{}:80", "a".repeat(254));
        assert_eq!(parse_authority(&long), Err(Refusal::BadRequest));
    }

    #[test]
    fn the_client_verdict_is_the_exits_verdict() {
        // Whatever passes the local syntax checks must get the exit's own answer.
        for text in [
            "example.org",
            "EXAMPLE.org",
            "127.0.0.1",
            "127.1",
            "0x7f.0.0.1",
            "1.2.3.4",
            "a.b.c1",
            "a.b.1",
            "xn--bcher-kva.example",
            "a-.b",
            "a.-b",
            "localhost",
        ] {
            let authority = format!("{text}:80");
            let exit = Target::canonicalize(&text.to_ascii_lowercase(), 80);
            assert_eq!(
                parse_authority(&authority).is_ok(),
                exit.is_ok(),
                "{authority}"
            );
        }
    }

    #[test]
    fn smuggling_shaped_heads_are_refused() {
        use Refusal::*;
        let line = "CONNECT example.org:443 HTTP/1.1";
        let cases: Vec<(&str, Vec<&str>)> = vec![
            (
                "two hosts",
                vec!["Host: example.org:443", "host: example.org:443"],
            ),
            ("host mismatch", vec!["Host: example.org:444"]),
            ("host of another name", vec!["Host: evil.example:443"]),
            ("host without port", vec!["Host: example.org"]),
            ("empty host", vec!["Host:"]),
            ("transfer-encoding", vec!["Transfer-Encoding: chunked"]),
            (
                "transfer-encoding odd case",
                vec!["tRaNsFeR-eNcOdInG: identity"],
            ),
            ("content-length 5", vec!["Content-Length: 5"]),
            ("content-length empty", vec!["Content-Length:"]),
            ("content-length 00", vec!["Content-Length: 00"]),
            ("content-length +0", vec!["Content-Length: +0"]),
            (
                "content-length twice",
                vec!["Content-Length: 0", "Content-Length: 0"],
            ),
            ("folded header", vec!["X-A: b", " continued"]),
            ("folded with tab", vec!["X-A: b", "\tcontinued"]),
            ("space before colon", vec!["Host : example.org:443"]),
            ("no colon", vec!["garbage"]),
            ("empty name", vec![": value"]),
            ("nul in value", vec!["X-A: a\0b"]),
            ("ctl in value", vec!["X-A: a\x01b"]),
            ("del in value", vec!["X-A: a\x7fb"]),
            ("bad name byte", vec!["X(A): b"]),
        ];
        for (what, headers) in cases {
            assert_eq!(parse_head(&head(line, &headers)), Err(BadRequest), "{what}");
        }
    }

    #[test]
    fn bare_line_endings_never_make_a_head() {
        use Refusal::BadRequest;
        let cases: [&[u8]; 8] = [
            b"CONNECT example.org:443 HTTP/1.1\n\n",
            b"CONNECT example.org:443 HTTP/1.1\r\n\n",
            b"CONNECT example.org:443 HTTP/1.1\n\r\n",
            b"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\n\r\n\r\n",
            b"CONNECT example.org:443 HTTP/1.1\r\nX: a\rb\r\n\r\n",
            b"CONNECT example.org:443 HTTP/1.1\r\nX: a\nb\r\n\r\n",
            b"CONNECT example.org:443 HTTP/1.1\r\r\n\r\n",
            b"CONNECT example.org:443\rHTTP/1.1\r\n\r\n",
        ];
        for bytes in cases {
            assert_eq!(parse_head(bytes), Err(BadRequest), "{bytes:?}");
        }
    }

    #[test]
    fn size_and_count_caps_hold_at_the_edge() {
        use Refusal::*;
        let line = "CONNECT example.org:443 HTTP/1.1";
        let one = ["X-A: b"];
        // 64 header lines pass, 65 do not.
        let many = |n: usize| -> Vec<u8> {
            let headers: Vec<&str> = one.iter().copied().cycle().take(n).collect();
            head(line, &headers)
        };
        assert!(parse_head(&many(MAX_HEADERS)).is_ok());
        assert_eq!(parse_head(&many(MAX_HEADERS + 1)), Err(HeaderTooLarge));
        // A head of exactly 8 KiB passes, one byte more does not.
        let exact = |total: usize| -> Vec<u8> {
            let base = head(line, &["X-A: "]).len();
            let filler = "b".repeat(total - base);
            head(line, &[&format!("X-A: {filler}")])
        };
        assert_eq!(exact(MAX_HEAD).len(), MAX_HEAD);
        assert!(parse_head(&exact(MAX_HEAD)).is_ok());
        assert_eq!(parse_head(&exact(MAX_HEAD + 1)), Err(HeaderTooLarge));
    }

    async fn read(bytes: &[u8]) -> Result<(Connect, Vec<u8>), HeadError> {
        let mut input = &bytes[1..];
        read_head(&mut input, bytes[0]).await
    }

    #[tokio::test]
    async fn the_reader_stops_at_the_head_and_keeps_what_follows() {
        let mut bytes = head(
            "CONNECT example.org:443 HTTP/1.1",
            &["Host: example.org:443"],
        );
        bytes.extend_from_slice(b"\x16\x03\x01 client hello \r\n\r\nGET / HTTP/1.1\r\n\r\n");
        let (connect, rest) = read(&bytes).await.unwrap();
        assert_eq!(connect.host, "example.org");
        assert_eq!(
            rest,
            b"\x16\x03\x01 client hello \r\n\r\nGET / HTTP/1.1\r\n\r\n"
        );
        // Bare LF in what follows the head is the tunnel's, not a fault.
        let mut bytes = head("CONNECT example.org:443 HTTP/1.1", &[]);
        bytes.extend_from_slice(b"a\nb\rc");
        assert_eq!(read(&bytes).await.unwrap().1, b"a\nb\rc");
    }

    #[tokio::test]
    async fn the_reader_refuses_without_waiting_for_an_end_that_cannot_come() {
        // A bare LF head never has a CRLF CRLF: refused at once, not at the deadline.
        let got = read(b"CONNECT example.org:443 HTTP/1.1\n\n").await;
        assert_eq!(got, Err(HeadError::Refused(Refusal::BadRequest)));
        let got = read(b"CONNECT example.org:443 HTTP/1.1\r\nX: a\rb").await;
        assert_eq!(got, Err(HeadError::Refused(Refusal::BadRequest)));
        // 8 KiB and one byte of headers, no end in the first 8 KiB: 431.
        let mut big = b"CONNECT example.org:443 HTTP/1.1\r\nX: ".to_vec();
        big.resize(MAX_HEAD + 1, b'a');
        assert_eq!(
            read(&big).await,
            Err(HeadError::Refused(Refusal::HeaderTooLarge))
        );
        // Input that ends inside the head.
        assert_eq!(
            read(b"CONNECT example.org:443 HTTP/1.1\r\n").await,
            Err(HeadError::Gone)
        );
        assert_eq!(read(b"C").await, Err(HeadError::Gone));
    }

    #[tokio::test]
    async fn the_end_of_the_head_is_found_across_read_boundaries() {
        use tokio::io::AsyncWriteExt;
        let bytes = head("CONNECT example.org:443 HTTP/1.1", &["X-A: b"]);
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            for byte in bytes[1..].iter() {
                client.write_all(&[*byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            client.write_all(b"tail").await.unwrap();
        });
        let (connect, _rest) = read_head(&mut server, b'C').await.unwrap();
        assert_eq!(connect.port, 443);
        writer.await.unwrap();
    }

    #[test]
    fn refusals_are_fixed_bytes() {
        for status in [400, 403, 405, 408, 431, 502, 503] {
            let bytes = response(status);
            let text = String::from_utf8(bytes.clone()).unwrap();
            assert!(text.starts_with(&format!("HTTP/1.1 {status} ")), "{text}");
            assert!(text.contains("\r\nConnection: close\r\n"), "{text}");
            let (head, body) = text.split_once("\r\n\r\n").unwrap();
            assert!(head.contains(&format!("Content-Length: {}", body.len())));
            assert_eq!(head.contains("Allow: CONNECT"), status == 405, "{status}");
            assert_eq!(bytes, response(status));
        }
    }
}
