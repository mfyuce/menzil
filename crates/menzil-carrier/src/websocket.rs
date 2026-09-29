//! The WebSocket upgrade (protocol.md 3.1 step 4, 3.3) over an
//! already-connected, already-TLS-wrapped stream: binary messages only,
//! no compression extensions negotiated.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{WebSocketStream, client_async};

use crate::error::CarrierError;

/// The menzil L3 WebSocket subprotocol (protocol.md 3.1 step 4).
pub const SUBPROTOCOL: &str = "menzil.v1";

/// The offered and server-selected subprotocol strings, which the L3
/// Noise prologue binds into itself (protocol.md 4.1) once that layer
/// exists.
#[derive(Debug, Clone)]
pub struct HandshakeOutcome {
    /// What we offered: always [`SUBPROTOCOL`].
    pub offered_subprotocol: String,
    /// What the server selected, if it echoed a `Sec-WebSocket-Protocol`
    /// response header.
    pub selected_subprotocol: Option<String>,
}

/// Performs the WebSocket client handshake on `stream`, which must
/// already be connected (and, in production, TLS-wrapped) to `host`.
/// `tokio_tungstenite::client_async` itself validates the response is a
/// proper 101 upgrade with a correct `Sec-WebSocket-Accept`; a failure
/// there propagates as [`CarrierError::WebSocket`].
pub async fn upgrade<S>(
    stream: S,
    host: &str,
    path: &str,
) -> Result<(WebSocketStream<S>, HandshakeOutcome), CarrierError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = format!("wss://{host}{path}")
        .into_client_request()
        .map_err(CarrierError::WebSocket)?;
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        SUBPROTOCOL
            .parse()
            .expect("SUBPROTOCOL is a valid header value"),
    );

    let (ws, response) = client_async(request, stream).await?;

    let selected_subprotocol = response
        .headers()
        .get("Sec-WebSocket-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    Ok((
        ws,
        HandshakeOutcome {
            offered_subprotocol: SUBPROTOCOL.to_string(),
            selected_subprotocol,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    #[tokio::test]
    async fn upgrade_sends_expected_path_and_subprotocol_and_reads_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // Assert from inside the callback rather than capturing data
            // out of it by mutable reference: a failure here panics the
            // spawned task, which `server.await` below surfaces.
            let callback = |req: &Request, resp: Response| {
                assert_eq!(req.uri().path(), "/_menzil/v1");
                let subprotocol = req
                    .headers()
                    .get("Sec-WebSocket-Protocol")
                    .and_then(|v| v.to_str().ok());
                assert_eq!(subprotocol, Some(SUBPROTOCOL));
                let mut resp = resp;
                resp.headers_mut()
                    .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.parse().unwrap());
                Ok(resp)
            };
            tokio_tungstenite::accept_hdr_async(sock, callback)
                .await
                .unwrap();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (_ws, outcome) = upgrade(tcp, "relay.example", "/_menzil/v1").await.unwrap();

        server.await.unwrap();
        assert_eq!(outcome.offered_subprotocol, SUBPROTOCOL);
        assert_eq!(outcome.selected_subprotocol.as_deref(), Some(SUBPROTOCOL));
    }

    #[tokio::test]
    async fn non_upgrade_response_is_reported_as_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await.unwrap();
            sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let result = upgrade(tcp, "relay.example", "/not-menzil").await;
        assert!(result.is_err());
        server.await.unwrap();
    }
}
