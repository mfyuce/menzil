//! An accepted inbound connection (protocol.md 3.3): binary-message
//! send/receive, mirroring `menzil_carrier::Carrier`'s send/recv shape
//! exactly so a later session event loop can treat either uniformly.

use futures_util::{SinkExt, StreamExt};
use menzil_carrier::MAX_MESSAGE_BYTES;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::error::RelayError;

/// One accepted, upgraded connection to the relay's own hostname.
pub struct InboundConnection {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    /// The exact `Sec-WebSocket-Protocol` request header value the client
    /// sent, byte for byte. The L3 Noise prologue (protocol.md 4.1) binds
    /// this in; it must match whatever string the client itself used to
    /// build its own prologue, so this is the raw header value, not an
    /// assumption that it was exactly [`menzil_carrier::SUBPROTOCOL`]
    /// (our own client never sends anything else, but a byte-for-byte
    /// echo is correct regardless of what any client sends).
    pub offered_subprotocol: String,
    /// The `Sec-WebSocket-Protocol` response header value this relay
    /// echoed back. [`crate::listener::Listener`] only ever completes an
    /// upgrade by echoing [`menzil_carrier::SUBPROTOCOL`], so this is
    /// always that value, but it is threaded through explicitly rather
    /// than assumed for the same reason as `offered_subprotocol`.
    pub selected_subprotocol: String,
}

impl InboundConnection {
    pub(crate) fn new(
        ws: WebSocketStream<TlsStream<TcpStream>>,
        offered_subprotocol: String,
        selected_subprotocol: String,
    ) -> Self {
        Self {
            ws,
            offered_subprotocol,
            selected_subprotocol,
        }
    }

    /// Sends one binary L3 record (protocol.md 3.3: "one message is one
    /// L3 record"). Errors if `payload` exceeds
    /// [`menzil_carrier::MAX_MESSAGE_BYTES`] without sending anything.
    pub async fn send(&mut self, payload: Vec<u8>) -> Result<(), RelayError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(RelayError::PayloadTooLarge {
                len: payload.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        self.ws.send(Message::Binary(payload.into())).await?;
        Ok(())
    }

    /// Receives the next binary L3 record, transparently skipping
    /// WebSocket-level ping/pong control frames (liveness is measured at
    /// L3, not with these, per protocol.md 3.3). Errors on a text message
    /// (protocol.md 3.3: "binary messages only") or a closed connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>, RelayError> {
        loop {
            let msg = self.ws.next().await.ok_or(RelayError::Closed)??;
            match msg {
                Message::Binary(bytes) => return Ok(bytes.to_vec()),
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => return Err(RelayError::Closed),
                Message::Text(_) => return Err(RelayError::UnexpectedMessageType),
                Message::Frame(_) => return Err(RelayError::UnexpectedMessageType),
            }
        }
    }
}
