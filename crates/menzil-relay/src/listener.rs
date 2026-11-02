//! Accepting inbound connections on the relay's own hostname (protocol.md
//! 3, mirrored server-side; 6.2's "SNI equal to the relay's own host name
//! is handled as section 3").
//!
//! SNI-based routing to advertised blind share names (the rest of 6.2) is
//! phase 2 (protocol.md 13) and not built here: this only completes the
//! L3 WebSocket upgrade for the relay's own hostname. Accepting many
//! connections concurrently and driving a session per connection is
//! session-registry logic for a later crate (TODO.md L3e), not this one
//! — [`Listener::accept`] hands back one connection at a time for the
//! caller to do that with.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::connection::InboundConnection;
use crate::error::RelayError;

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
            }),
        })
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
        self.upgrader.handshake(tcp, false).await
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

impl Upgrader {
    /// TLS, then the WebSocket upgrade. With `rate_limited` the upgrade is refused with
    /// HTTP 429 whatever the request says (the peer is over its connection rate,
    /// `crate::admission`): TLS has to be completed to speak HTTP at all, but nothing past the
    /// request head is read.
    pub(crate) async fn handshake(
        &self,
        tcp: TcpStream,
        rate_limited: bool,
    ) -> Result<InboundConnection, RelayError> {
        let tls = self.acceptor.accept(tcp).await?;
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
            move |req: &Request, resp: Response| -> Result<Response, ErrorResponse> {
                if rate_limited {
                    return Err(too_many_requests());
                }
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

fn too_many_requests() -> ErrorResponse {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", "60")
        .body(None)
        .expect("a minimal 429 with no body always builds")
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

    /// MT4: a peer over its connection rate is refused at the upgrade with HTTP 429, whatever
    /// path it asks for, and a Retry-After says when to come back.
    #[tokio::test]
    async fn a_rate_limited_upgrade_gets_429() {
        let (listener, cert) = bind_test_listener().await;
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let tcp = listener.accept_tcp().await.unwrap().0;
            listener.upgrader().handshake(tcp, true).await.map(|_| ())
        });
        let result = crate::tests_support::try_test_client(addr, cert, "/_menzil/v1").await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(response.headers().get("Retry-After").unwrap(), "60");
            }
            Err(other) => panic!("expected an HTTP 429, got {other:?}"),
            Ok(_) => panic!("a rate limited upgrade must not complete"),
        }
        assert!(server.await.unwrap().is_err());
    }
}
