//! HTTP CONNECT tunneling through an optional forward proxy (protocol.md
//! 3.1 step 2), phase-1 slice: Basic auth only, one 407 retry on the same
//! kept-alive connection with the first response body drained. NTLM,
//! Negotiate, and PAC/WPAD discovery are phase 2.

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::CarrierError;
use crate::proxy::ProxyCredentials;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const DRAIN_CHUNK_BYTES: usize = 4096;

/// Opens a `TcpStream` positioned exactly after any proxy negotiation,
/// ready for TLS: directly to `(target_host, target_port)` when `proxy`
/// is `None`, otherwise through a CONNECT tunnel via `proxy`.
pub async fn dial_tcp(
    proxy: Option<(&str, u16, Option<&ProxyCredentials>)>,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, CarrierError> {
    match proxy {
        None => low_latency(TcpStream::connect((target_host, target_port)).await?),
        Some((proxy_host, proxy_port, creds)) => {
            // Set on the connection to the proxy: once CONNECT succeeds
            // that same socket carries everything after it.
            let mut stream = low_latency(TcpStream::connect((proxy_host, proxy_port)).await?)?;
            connect_tunnel(&mut stream, target_host, target_port, creds).await?;
            Ok(stream)
        }
    }
}

/// Turns off Nagle's algorithm (TODO.md, found by two external model
/// reviews on 2026-10-04): this protocol sends a steady stream of small
/// records (L3 PING/PONG, L4 KEEP, `yamux` window updates, a single
/// interactive keystroke under S2 reach), and Nagle holds a small write
/// back until the peer's delayed ACK arrives (typically 40-200 ms),
/// adding that to each of them on top of whatever the tunnel costs.
/// Nothing in this protocol relies on small writes being coalesced:
/// every record is already a whole WebSocket message.
fn low_latency(stream: TcpStream) -> Result<TcpStream, CarrierError> {
    stream.set_nodelay(true)?;
    Ok(stream)
}

struct ConnectResponse {
    status: u16,
    proxy_authenticate: Vec<String>,
    content_length: Option<usize>,
}

async fn connect_tunnel(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    creds: Option<&ProxyCredentials>,
) -> Result<(), CarrierError> {
    let (resp, leftover) = send_connect(stream, target_host, target_port, None).await?;
    if resp.status == 200 {
        drain_body(stream, resp.content_length, leftover.len()).await?;
        return Ok(());
    }
    if resp.status != 407 {
        drain_body(stream, resp.content_length, leftover.len()).await?;
        return Err(CarrierError::Connect(format!(
            "proxy CONNECT failed with status {}",
            resp.status
        )));
    }
    drain_body(stream, resp.content_length, leftover.len()).await?;

    let schemes = challenge_schemes(&resp.proxy_authenticate);
    if !schemes.iter().any(|s| s.eq_ignore_ascii_case("Basic")) {
        return Err(CarrierError::UnsupportedProxyAuth(schemes.join(", ")));
    }
    let Some(creds) = creds else {
        return Err(CarrierError::UnsupportedProxyAuth(
            "Basic (no proxy credentials configured)".to_string(),
        ));
    };

    let (resp2, leftover2) = send_connect(stream, target_host, target_port, Some(creds)).await?;
    drain_body(stream, resp2.content_length, leftover2.len()).await?;
    if resp2.status == 200 {
        Ok(())
    } else {
        Err(CarrierError::Connect(format!(
            "proxy authentication failed (status {})",
            resp2.status
        )))
    }
}

async fn send_connect(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
    creds: Option<&ProxyCredentials>,
) -> Result<(ConnectResponse, Vec<u8>), CarrierError> {
    let mut request = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(c) = creds {
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", c.username, c.password));
        request.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    read_response_head(stream).await
}

/// Reads and parses the CONNECT response's status line and headers,
/// returning them alongside any body bytes that were already read past
/// the header terminator (so the caller can account for them when
/// draining the rest of the body by `Content-Length`).
async fn read_response_head(
    stream: &mut TcpStream,
) -> Result<(ConnectResponse, Vec<u8>), CarrierError> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        let complete = {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut resp = httparse::Response::new(&mut headers);
            let parsed = resp
                .parse(&buf)
                .map_err(|e| CarrierError::Connect(format!("malformed proxy response: {e}")))?;
            match parsed {
                httparse::Status::Complete(header_len) => {
                    let status = resp.code.ok_or_else(|| {
                        CarrierError::Connect("proxy response missing status code".to_string())
                    })?;
                    let mut proxy_authenticate = Vec::new();
                    let mut content_length = None;
                    for h in resp.headers.iter() {
                        if h.name.eq_ignore_ascii_case("Proxy-Authenticate") {
                            proxy_authenticate.push(String::from_utf8_lossy(h.value).into_owned());
                        }
                        if h.name.eq_ignore_ascii_case("Content-Length") {
                            content_length = std::str::from_utf8(h.value)
                                .ok()
                                .and_then(|v| v.trim().parse::<usize>().ok());
                        }
                    }
                    Some((status, proxy_authenticate, content_length, header_len))
                }
                httparse::Status::Partial => None,
            }
        };

        if let Some((status, proxy_authenticate, content_length, header_len)) = complete {
            let leftover = buf.split_off(header_len);
            return Ok((
                ConnectResponse {
                    status,
                    proxy_authenticate,
                    content_length,
                },
                leftover,
            ));
        }

        if buf.len() > MAX_HEADER_BYTES {
            return Err(CarrierError::Connect(
                "proxy response headers too large".to_string(),
            ));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(CarrierError::Connect(
                "proxy closed the connection before completing its response".to_string(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Drains a CONNECT error response's body (by `Content-Length`, if any)
/// before reusing the connection, per protocol.md 3.1 step 2: "all 407
/// legs of one authentication run on one kept alive connection with
/// response bodies drained." A response with no `Content-Length` is
/// assumed bodyless; chunked CONNECT-error bodies are not a realistic
/// shape this handles.
async fn drain_body(
    stream: &mut TcpStream,
    content_length: Option<usize>,
    already_read: usize,
) -> Result<(), CarrierError> {
    let Some(len) = content_length else {
        // No declared body length, yet we already read bytes past the
        // header terminator: an HTTP/1.1 CONNECT response has no body
        // without Content-Length, so those bytes are unaccounted for.
        // Erroring here (rather than silently dropping them) matters
        // because a genuine `Some` case correctly replays `already_read`
        // into the remaining count below; only the `None` case had no
        // such accounting, so unread bytes would otherwise vanish before
        // TLS ever sees them.
        if already_read > 0 {
            return Err(CarrierError::Connect(
                "proxy response had trailing bytes with no Content-Length to account for them"
                    .to_string(),
            ));
        }
        return Ok(());
    };
    let mut remaining = len.saturating_sub(already_read);
    let mut sink = [0u8; DRAIN_CHUNK_BYTES];
    while remaining > 0 {
        let take = remaining.min(sink.len());
        stream.read_exact(&mut sink[..take]).await?;
        remaining -= take;
    }
    Ok(())
}

fn challenge_schemes(values: &[String]) -> Vec<String> {
    values
        .iter()
        .filter_map(|v| v.split_whitespace().next().map(str::to_string))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn fake_proxy(listener: TcpListener, responses: Vec<&'static str>) -> Vec<String> {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut requests = Vec::new();
        for response in responses {
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            requests.push(String::from_utf8_lossy(&buf[..n]).into_owned());
            sock.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    }

    #[tokio::test]
    async fn a_direct_dial_disables_nagle() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap() });

        let stream = dial_tcp(None, "127.0.0.1", addr.port()).await.unwrap();
        assert!(stream.nodelay().unwrap());
        drop(accepted.await.unwrap());
    }

    #[tokio::test]
    async fn a_dial_through_a_proxy_disables_nagle_on_the_proxy_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_proxy(
            listener,
            vec!["HTTP/1.1 200 Connection Established\r\n\r\n"],
        ));

        let stream = dial_tcp(Some(("127.0.0.1", addr.port(), None)), "relay.example", 443)
            .await
            .unwrap();
        assert!(stream.nodelay().unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_succeeds_on_200() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_proxy(
            listener,
            vec!["HTTP/1.1 200 Connection Established\r\n\r\n"],
        ));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        connect_tunnel(&mut stream, "relay.example", 443, None)
            .await
            .unwrap();

        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("CONNECT relay.example:443 HTTP/1.1\r\n"));
    }

    #[tokio::test]
    async fn unsupported_challenge_scheme_is_a_hard_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_proxy(
            listener,
            vec![
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n",
            ],
        ));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let err = connect_tunnel(&mut stream, "relay.example", 443, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CarrierError::UnsupportedProxyAuth(_)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn basic_challenge_retries_and_succeeds() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_proxy(
            listener,
            vec![
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 5\r\n\r\nnopes",
                "HTTP/1.1 200 Connection Established\r\n\r\n",
            ],
        ));

        let creds = ProxyCredentials {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        let mut stream = TcpStream::connect(addr).await.unwrap();
        connect_tunnel(&mut stream, "relay.example", 443, Some(&creds))
            .await
            .unwrap();

        let requests = server.await.unwrap();
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].contains("Proxy-Authorization"));
        assert!(requests[1].contains("Proxy-Authorization: Basic "));
    }

    #[tokio::test]
    async fn basic_offered_but_no_credentials_is_a_hard_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(fake_proxy(
            listener,
            vec![
                "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n",
            ],
        ));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let err = connect_tunnel(&mut stream, "relay.example", 443, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CarrierError::UnsupportedProxyAuth(_)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn trailing_bytes_with_no_content_length_are_an_error_not_silently_dropped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            // No Content-Length, yet bytes follow the header terminator in
            // the same write: a compliant proxy never does this for a 200
            // CONNECT response, but the client must not silently discard
            // them as if they belonged to nothing.
            sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nunexpected")
                .await
                .unwrap();
        });

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let err = connect_tunnel(&mut stream, "relay.example", 443, None)
            .await
            .unwrap_err();
        assert!(matches!(err, CarrierError::Connect(_)));
        server.await.unwrap();
    }
}
