//! Accepting inbound connections on the relay's own hostname (protocol.md
//! 3, mirrored server-side; 6.2's "SNI equal to the relay's own host name
//! is handled as section 3").
//!
//! SNI-based routing to advertised blind share names (the rest of 6.2) is
//! `crate::front_door`, which reads the ClientHello before this runs: this
//! only completes the L3 WebSocket upgrade for the relay's own hostname,
//! on a socket whose first bytes may have been read and put back
//! (`crate::prefixed`). Accepting many
//! connections concurrently and driving a session per connection is
//! session-registry logic for a later crate (TODO.md L3e), not this one
//! — [`Listener::accept`] hands back one connection at a time for the
//! caller to do that with.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::connection::InboundConnection;
use crate::error::RelayError;
use crate::prefixed::{PrefixedTcp, Replay};

/// Accepts inbound connections on one bound address, completing TLS and
/// the L3 WebSocket upgrade for each.
pub struct Listener {
    tcp: TcpListener,
    upgrader: Arc<Upgrader>,
}

/// The TLS acceptor and expected path: everything the TLS plus WebSocket
/// upgrade needs, shared (`Arc`) so a spawned handshake task can own it
/// without borrowing the [`Listener`].
pub(crate) struct Upgrader {
    acceptor: TlsAcceptor,
    expected_path: String,
    /// The page to answer a plain HTTP request with; without one such a request is dropped.
    fallback: Option<FallbackPage>,
}

impl Listener {
    /// Binds `addr` and prepares to accept connections that present
    /// `tls_config` and upgrade to WebSocket at `expected_path`
    /// (typically [`menzil_carrier::DEFAULT_PATH`], but the
    /// operator-configured path itself, protocol.md 3.1 step 4, is this
    /// crate's caller's business, not this type's).
    pub async fn bind(
        addr: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        expected_path: impl Into<String>,
    ) -> Result<Self, RelayError> {
        let tcp = TcpListener::bind(addr).await?;
        Ok(Self {
            tcp,
            upgrader: Arc::new(Upgrader {
                acceptor: TlsAcceptor::from(tls_config),
                expected_path: expected_path.into(),
                fallback: None,
            }),
        })
    }

    /// [`Self::bind`] with the listening socket's send buffer set to `send_buffer` bytes, which
    /// the accepted sockets inherit: a peer that never reads blocks the relay's writes after a
    /// few kilobytes instead of a few megabytes (tests of stalled writers).
    #[cfg(test)]
    pub(crate) async fn bind_with_send_buffer(
        addr: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
        expected_path: impl Into<String>,
        send_buffer: u32,
    ) -> Result<Self, RelayError> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.set_send_buffer_size(send_buffer)?;
        socket.bind(addr)?;
        let tcp = socket.listen(1024)?;
        Ok(Self {
            tcp,
            upgrader: Arc::new(Upgrader {
                acceptor: TlsAcceptor::from(tls_config),
                expected_path: expected_path.into(),
                fallback: None,
            }),
        })
    }

    /// Answers a plain HTTP request on this listener (one that is not a WebSocket upgrade, such
    /// as a browser opening the relay's name) with `page`. Call it right after `bind`, before the
    /// listener is shared. A WebSocket upgrade is handled exactly as without a page.
    pub fn with_fallback_page(mut self, page: FallbackPage) -> Self {
        Arc::get_mut(&mut self.upgrader)
            .expect("the listener is not shared yet")
            .fallback = Some(page);
        self
    }

    /// The address actually bound; useful when `addr` used an ephemeral
    /// port (`:0`).
    pub fn local_addr(&self) -> Result<SocketAddr, RelayError> {
        Ok(self.tcp.local_addr()?)
    }

    /// Accepts one inbound TCP connection and sets `TCP_NODELAY`; nothing
    /// else. This never waits on the peer, so a loop around it cannot be
    /// stalled by a client that connects and then says nothing; the TLS
    /// and WebSocket steps are [`Listener::handshake`], which a caller
    /// bounds in time and number itself (see `Relay::serve`). The peer's
    /// address comes back with the socket: the admission caps
    /// (`crate::admission`) are counted per address.
    pub async fn accept_tcp(&self) -> Result<(TcpStream, SocketAddr), RelayError> {
        let (tcp, peer) = self.tcp.accept().await?;
        // Nagle off, for the same reason as on the dialing side (see
        // `menzil_carrier::connect`'s `low_latency`): the relay's writes
        // are the small records of every session it serves.
        tcp.set_nodelay(true)?;
        Ok((tcp, peer))
    }

    /// Completes TLS, then the L3 WebSocket upgrade, on a socket from
    /// [`Listener::accept_tcp`]: a request to any path but the one this
    /// `Listener` was bound with, or one that doesn't offer the
    /// `menzil.v1` subprotocol, gets a minimal 404 (protocol.md 3.1 step
    /// 4, 13's "minimal 404 page" row for phase 1) rather than completing
    /// the upgrade. There is no timeout in here: a peer that stalls
    /// stalls this future, so the caller must wrap it in one.
    pub async fn handshake(&self, tcp: TcpStream) -> Result<InboundConnection, RelayError> {
        self.upgrader.handshake(tcp).await
    }

    /// [`Listener::accept_tcp`] then [`Listener::handshake`] inline, with
    /// no timeout: one peer that stalls the handshake stalls this call.
    /// A server loop should use the two halves instead.
    pub async fn accept(&self) -> Result<InboundConnection, RelayError> {
        let (tcp, _peer) = self.accept_tcp().await?;
        self.handshake(tcp).await
    }

    /// A shared handle on the handshake half, for spawned tasks.
    pub(crate) fn upgrader(&self) -> Arc<Upgrader> {
        Arc::clone(&self.upgrader)
    }
}

/// The WebSocket limits of an accepted connection. A message is one L3 record or one Noise
/// handshake message, never more than [`menzil_carrier::MAX_MESSAGE_BYTES`] (protocol.md 3.3),
/// so that is the bound for a message and for a single frame. tungstenite's defaults (64 MiB a
/// message, 16 MiB a frame) would let any peer, before it has proven anything, make the relay
/// buffer megabytes per connection.
fn websocket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(menzil_carrier::MAX_MESSAGE_BYTES))
        .max_frame_size(Some(menzil_carrier::MAX_MESSAGE_BYTES))
}

/// The most a fallback page may be.
pub const FALLBACK_PAGE_MAX_BYTES: usize = 64 * 1024;

/// The most bytes read to find out what an inbound request is (the head of an HTTP request).
const SNIFF_HEAD_MAX: usize = 8 * 1024;

/// A static HTML page for a plain HTTP request to the relay's own host name (a browser opening
/// `https://<relay>/`, or a site rating crawler), so the name is not an empty reply. Only `GET`
/// and `HEAD` of `/` and `/index.html` are answered with it; any other path is a bare 404 and any
/// other method 405. A WebSocket upgrade never sees it. The page is read once, at start.
#[derive(Clone)]
pub struct FallbackPage {
    html: Arc<Vec<u8>>,
}

impl FallbackPage {
    /// A page of at most [`FALLBACK_PAGE_MAX_BYTES`] that is not empty.
    pub fn new(html: Vec<u8>) -> Result<Self, RelayError> {
        if html.is_empty() || html.len() > FALLBACK_PAGE_MAX_BYTES {
            return Err(RelayError::TlsSetup(format!(
                "the fallback page must be 1 to {FALLBACK_PAGE_MAX_BYTES} bytes, it is {}",
                html.len()
            )));
        }
        Ok(Self {
            html: Arc::new(html),
        })
    }

    /// Reads the head of the first request on `tls`. A WebSocket upgrade request goes on to the
    /// upgrade with its bytes put back; anything else is answered here and ends in
    /// [`RelayError::AnsweredPlainHttp`]; a head that is not one complete, parseable request
    /// within [`SNIFF_HEAD_MAX`] bytes is dropped without an answer.
    async fn sniff<S>(&self, mut tls: S) -> Result<Replay<S>, RelayError>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let mut head: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            if head.len() >= SNIFF_HEAD_MAX {
                return Err(RelayError::Closed);
            }
            let n = tls.read(&mut chunk).await?;
            if n == 0 {
                return Err(RelayError::Closed);
            }
            head.extend_from_slice(&chunk[..n]);
        }
        let mut storage = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut storage);
        let parsed = req.parse(&head);
        if !matches!(parsed, Ok(httparse::Status::Complete(_))) {
            return Err(RelayError::Closed);
        }
        let upgrades = req.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("upgrade")
                && std::str::from_utf8(h.value).is_ok_and(|v| {
                    v.split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("websocket"))
                })
        });
        if upgrades {
            return Ok(Replay::new(head, tls));
        }
        let answer = self.answer(req.method.unwrap_or(""), req.path.unwrap_or(""));
        tls.write_all(&answer).await?;
        tls.flush().await?;
        let _ = tls.shutdown().await;
        Err(RelayError::AnsweredPlainHttp)
    }

    /// The whole HTTP/1.1 response to a plain request, always `Connection: close`.
    fn answer(&self, method: &str, path: &str) -> Vec<u8> {
        const COMMON: &str = "Connection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'\r\n";
        let head_only = method == "HEAD";
        if method != "GET" && !head_only {
            return format!(
                "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\n{COMMON}\r\n"
            )
            .into_bytes();
        }
        let path = path.split(['?', '#']).next().unwrap_or("");
        if path != "/" && path != "/index.html" {
            return format!("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n{COMMON}\r\n")
                .into_bytes();
        }
        let mut out = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: max-age=300\r\n{COMMON}\r\n",
            self.html.len()
        )
        .into_bytes();
        if !head_only {
            out.extend_from_slice(&self.html);
        }
        out
    }
}

impl Upgrader {
    /// TLS, then the WebSocket upgrade. (A peer over its connection rate is not answered at all:
    /// refusing it with HTTP 429 would take the TLS handshake first, see `crate::admission`.)
    pub(crate) async fn handshake(&self, tcp: TcpStream) -> Result<InboundConnection, RelayError> {
        self.handshake_prefixed(PrefixedTcp::plain(tcp)).await
    }

    /// [`Self::handshake`] on a socket some of whose first bytes were read already and are put
    /// back in front (the front door read the ClientHello, `crate::front_door`).
    pub(crate) async fn handshake_prefixed(
        &self,
        tcp: PrefixedTcp,
    ) -> Result<InboundConnection, RelayError> {
        let tls = self.acceptor.accept(tcp).await?;
        let tls = match &self.fallback {
            None => Replay::new(Vec::new(), tls),
            Some(page) => page.sniff(tls).await?,
        };
        let expected_path = self.expected_path.clone();
        // `validate_upgrade` only has borrowed access to the request
        // inside the callback tungstenite drives; the offered
        // subprotocol string it validates has to escape that closure to
        // reach `InboundConnection`, so it's captured into this shared
        // slot rather than returned from the callback (whose `Ok` type
        // is fixed by `accept_hdr_async`'s own signature). `Arc<Mutex<_>>`
        // rather than `Rc<RefCell<_>>`: the closure is `move`d into
        // `accept_hdr_async`, whose bounds this crate doesn't control, so
        // this stays correct whether or not that requires `Send`.
        let offered = Arc::new(std::sync::Mutex::new(None));
        let offered_for_closure = Arc::clone(&offered);
        let ws = tokio_tungstenite::accept_hdr_async_with_config(
            tls,
            // `accept_hdr_async`'s callback trait requires exactly
            // `Result<Response, ErrorResponse>` (an `http::Response`,
            // over 100 bytes) — not a type this crate controls, so the
            // large-error case can't be avoided at this boundary the way
            // `validate_upgrade` avoids it internally by boxing.
            #[allow(clippy::result_large_err)] // callback type fixed by tungstenite
            move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                let outcome = validate_upgrade(req, resp, &expected_path).map_err(|e| *e)?;
                *offered_for_closure.lock().unwrap() = Some(outcome.offered_subprotocol);
                Ok(outcome.response)
            },
            Some(websocket_config()),
        )
        .await?;
        let offered_subprotocol = offered
            .lock()
            .unwrap()
            .take()
            .expect("validate_upgrade always records the offered subprotocol before Ok");
        Ok(InboundConnection::new(
            ws,
            offered_subprotocol,
            menzil_carrier::SUBPROTOCOL.to_string(),
        ))
    }
}

/// [`validate_upgrade`]'s success case: the response to send, plus the
/// exact subprotocol string the client offered (for the L3 prologue,
/// protocol.md 4.1).
struct UpgradeOutcome {
    response: Response,
    offered_subprotocol: String,
}

fn validate_upgrade(
    req: &Request,
    mut resp: Response,
    expected_path: &str,
) -> Result<UpgradeOutcome, Box<ErrorResponse>> {
    if req.uri().path() != expected_path {
        return Err(not_found());
    }
    let offered_header = req
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok());
    let offers_menzil = offered_header.is_some_and(|offered| {
        offered
            .split(',')
            .map(str::trim)
            .any(|p| p == menzil_carrier::SUBPROTOCOL)
    });
    if !offers_menzil {
        return Err(not_found());
    }
    resp.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        menzil_carrier::SUBPROTOCOL
            .parse()
            .expect("SUBPROTOCOL is a valid header value"),
    );
    Ok(UpgradeOutcome {
        response: resp,
        // `offers_menzil` is only true when `offered_header` is `Some`.
        offered_subprotocol: offered_header
            .expect("offers_menzil being true implies offered_header is Some")
            .to_string(),
    })
}

fn not_found() -> Box<ErrorResponse> {
    Box::new(
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(None)
            .expect("a minimal 404 with no body always builds"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::{self_signed_cert, test_client};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    async fn bind_test_listener() -> (Listener, rustls::pki_types::CertificateDer<'static>) {
        let (chain, key) = self_signed_cert("localhost");
        let cert = chain[0].clone();
        let config = crate::tls::server_config(chain, key).unwrap();
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), config, "/_menzil/v1")
            .await
            .unwrap();
        (listener, cert)
    }

    #[tokio::test]
    async fn live_round_trip_over_real_tls_and_websocket() {
        let (listener, cert) = bind_test_listener().await;
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            assert!(
                conn.tcp_nodelay().unwrap(),
                "an accepted socket must have Nagle's algorithm off"
            );
            let msg = conn.recv().await.unwrap();
            assert_eq!(msg, b"hello from client");
            conn.send(b"hello from relay".to_vec()).await.unwrap();
        });

        let mut client = test_client(addr, cert, "/_menzil/v1").await;
        client
            .send(Message::Binary(b"hello from client".to_vec().into()))
            .await
            .unwrap();
        let reply = client.next().await.unwrap().unwrap();
        assert_eq!(reply.into_data(), b"hello from relay".as_slice());

        server.await.unwrap();
    }

    #[tokio::test]
    async fn wrong_path_gets_404_and_does_not_upgrade() {
        let (listener, cert) = bind_test_listener().await;
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move { listener.accept().await });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = crate::tests_support::test_tls_connector(cert)
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let result = tokio_tungstenite::client_async("wss://localhost/not-menzil", tls).await;
        assert!(result.is_err());
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn missing_subprotocol_gets_404_and_does_not_upgrade() {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;

        let (listener, cert) = bind_test_listener().await;
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move { listener.accept().await });

        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = crate::tests_support::test_tls_connector(cert)
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        // No Sec-WebSocket-Protocol header at all.
        let request = "wss://localhost/_menzil/v1".into_client_request().unwrap();
        let result = tokio_tungstenite::client_async(request, tls).await;
        assert!(result.is_err());
        assert!(server.await.unwrap().is_err());
    }

    /// MT4: both the message and the single frame are bounded by the record limit (a message
    /// can be split into many frames, so the frame bound alone would not bound it).
    #[test]
    fn the_websocket_limits_are_the_record_limit_for_message_and_frame() {
        let config = websocket_config();
        assert_eq!(
            config.max_message_size,
            Some(menzil_carrier::MAX_MESSAGE_BYTES)
        );
        assert_eq!(
            config.max_frame_size,
            Some(menzil_carrier::MAX_MESSAGE_BYTES)
        );
        assert!(!config.accept_unmasked_frames);
    }

    /// MT4: a message is bounded by `MAX_MESSAGE_BYTES` at the WebSocket layer, so a peer that
    /// has proven nothing cannot make the relay buffer more than one record's worth.
    #[tokio::test]
    async fn a_message_over_the_record_limit_is_refused_by_the_websocket_layer() {
        let (listener, cert) = bind_test_listener().await;
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            let exact = conn.recv().await.unwrap();
            let over = conn.recv().await;
            (exact.len(), over)
        });

        let mut client = test_client(addr, cert, "/_menzil/v1").await;
        let limit = menzil_carrier::MAX_MESSAGE_BYTES;
        client
            .send(Message::Binary(vec![7u8; limit].into()))
            .await
            .unwrap();
        // The client's own limit is the 64 MiB default: it can send this, the relay cannot read it.
        let _ = client
            .send(Message::Binary(vec![7u8; limit + 1].into()))
            .await;

        let (exact_len, over) = server.await.unwrap();
        assert_eq!(exact_len, limit, "a record of exactly the limit is read");
        assert!(
            matches!(
                over,
                Err(RelayError::WebSocket(
                    tokio_tungstenite::tungstenite::Error::Capacity(_)
                ))
            ),
            "one byte over the limit must be a capacity error, got {over:?}"
        );
    }

    /// One TLS connection to `addr` that sends `request` and returns what comes back until the
    /// relay ends it (what a failed read leaves is what was read).
    async fn raw_exchange(
        addr: SocketAddr,
        cert: rustls::pki_types::CertificateDer<'static>,
        request: &[u8],
    ) -> Vec<u8> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = crate::tests_support::test_tls_connector(cert)
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        tls.write_all(request).await.unwrap();
        let mut out = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&chunk[..n]),
            }
        }
        out
    }

    fn page() -> FallbackPage {
        FallbackPage::new(b"<h1>hello</h1>".to_vec()).unwrap()
    }

    #[tokio::test]
    async fn a_plain_request_gets_the_fallback_page_and_other_requests_get_bare_answers() {
        let (listener, cert) = bind_test_listener().await;
        let listener = listener.with_fallback_page(page());
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..6 {
                let r = listener.accept().await;
                assert!(
                    matches!(r, Err(RelayError::AnsweredPlainHttp)),
                    "a plain request ends the handshake without a session"
                );
            }
        });
        let get = raw_exchange(
            addr,
            cert.clone(),
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .await;
        let get = String::from_utf8(get).unwrap();
        assert!(get.starts_with("HTTP/1.1 200 OK\r\n"), "{get}");
        assert!(get.contains("Content-Length: 14\r\n"), "{get}");
        assert!(get.contains("Connection: close\r\n"), "{get}");
        assert!(get.ends_with("\r\n\r\n<h1>hello</h1>"), "{get}");

        let query = raw_exchange(
            addr,
            cert.clone(),
            b"GET /index.html?x=1 HTTP/1.1\r\nHost: h\r\n\r\n",
        )
        .await;
        assert!(
            String::from_utf8(query)
                .unwrap()
                .starts_with("HTTP/1.1 200 OK")
        );

        let head = String::from_utf8(
            raw_exchange(addr, cert.clone(), b"HEAD / HTTP/1.1\r\nHost: h\r\n\r\n").await,
        )
        .unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
        assert!(
            head.contains("Content-Length: 14\r\n"),
            "a HEAD names the length"
        );
        assert!(!head.contains("<h1>"), "a HEAD carries no body");

        let other = String::from_utf8(
            raw_exchange(
                addr,
                cert.clone(),
                b"GET /admin HTTP/1.1\r\nHost: h\r\n\r\n",
            )
            .await,
        )
        .unwrap();
        assert!(other.starts_with("HTTP/1.1 404 Not Found"), "{other}");
        assert!(!other.contains("<h1>"));

        let post = String::from_utf8(
            raw_exchange(
                addr,
                cert.clone(),
                b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
            )
            .await,
        )
        .unwrap();
        assert!(
            post.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "{post}"
        );
        assert!(post.contains("Allow: GET, HEAD\r\n"), "{post}");

        // A WebSocket upgrade key without the `websocket` token is a plain request too.
        let upgrade_other = String::from_utf8(
            raw_exchange(
                addr,
                cert,
                b"GET / HTTP/1.1\r\nHost: h\r\nUpgrade: h2c\r\n\r\n",
            )
            .await,
        )
        .unwrap();
        assert!(
            upgrade_other.starts_with("HTTP/1.1 200 OK"),
            "{upgrade_other}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn the_websocket_upgrade_is_unchanged_with_a_fallback_page() {
        let (listener, cert) = bind_test_listener().await;
        let listener = listener.with_fallback_page(page());
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut conn = listener.accept().await.unwrap();
            assert!(conn.tcp_nodelay().unwrap());
            assert_eq!(conn.recv().await.unwrap(), b"hello from client");
            conn.send(b"hello from relay".to_vec()).await.unwrap();
        });
        let mut client = test_client(addr, cert, "/_menzil/v1").await;
        client
            .send(Message::Binary(b"hello from client".to_vec().into()))
            .await
            .unwrap();
        let reply = client.next().await.unwrap().unwrap();
        assert_eq!(reply.into_data(), b"hello from relay".as_slice());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_path_websocket_still_gets_404_with_a_fallback_page() {
        let (listener, cert) = bind_test_listener().await;
        let listener = listener.with_fallback_page(page());
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = crate::tests_support::test_tls_connector(cert)
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                tcp,
            )
            .await
            .unwrap();
        let result = tokio_tungstenite::client_async("wss://localhost/not-menzil", tls).await;
        assert!(result.is_err());
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn without_a_page_a_plain_request_gets_no_answer_at_all() {
        let (listener, cert) = bind_test_listener().await;
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { listener.accept().await });
        let answer = raw_exchange(addr, cert, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
        assert!(answer.is_empty(), "nothing is sent: {answer:?}");
        assert!(server.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn an_oversize_or_unparseable_head_is_dropped_without_an_answer() {
        let (listener, cert) = bind_test_listener().await;
        let listener = listener.with_fallback_page(page());
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let r = listener.accept().await;
                assert!(matches!(r, Err(RelayError::Closed)), "not a plain close");
            }
        });
        // 9000 bytes without the end of a head.
        let big = vec![b'a'; 9000];
        assert!(raw_exchange(addr, cert.clone(), &big).await.is_empty());
        // The end of a head, but not a request.
        assert!(
            raw_exchange(addr, cert, b"\x01\x02 not http\r\n\r\n")
                .await
                .is_empty()
        );
        server.await.unwrap();
    }

    #[test]
    fn the_fallback_page_must_be_between_one_byte_and_the_cap() {
        assert!(FallbackPage::new(Vec::new()).is_err());
        assert!(FallbackPage::new(vec![b'x'; FALLBACK_PAGE_MAX_BYTES]).is_ok());
        assert!(FallbackPage::new(vec![b'x'; FALLBACK_PAGE_MAX_BYTES + 1]).is_err());
    }
}
