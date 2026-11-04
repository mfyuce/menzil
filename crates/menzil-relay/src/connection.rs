//! An accepted inbound connection (protocol.md 3.3): binary-message
//! send/receive, mirroring `menzil_carrier::Carrier`'s send/recv shape
//! exactly so a later session event loop can treat either uniformly.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use menzil_carrier::MAX_MESSAGE_BYTES;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::error::RelayError;

/// How long one send may take before the peer is taken to have stopped reading and the
/// connection is closed (round T3, M2). One send is one record of at most 64 KiB, so this asks
/// a peer for about 13 KB/s at worst; before ATTACH the (shorter) time left until the ATTACH
/// deadline applies instead, see [`InboundConnection::limit_sends_until`].
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// A send not finished by this instant (if it is earlier than [`WRITE_TIMEOUT`] from the
    /// start of the send) is abandoned: before ATTACH it is the ATTACH deadline, so a peer that
    /// never reads cannot hold a session open past it.
    send_until: Option<Instant>,
    /// How long one send may take: [`WRITE_TIMEOUT`] unless the relay was given another.
    write_timeout: Duration,
    /// Set when a send timed out. The WebSocket sink may hold a half written message then, so
    /// nothing more is sent, and [`Self::recv`] reports the connection closed: the session loop
    /// ends the session.
    broken: bool,
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
            send_until: None,
            write_timeout: WRITE_TIMEOUT,
            broken: false,
        }
    }

    /// Sets how long one send may take (the relay's `SessionTimeouts::write`).
    pub(crate) fn set_write_timeout(&mut self, timeout: Duration) {
        self.write_timeout = timeout;
    }

    /// Bounds every later send by `deadline` too (the session passes the ATTACH deadline
    /// before ATTACH and `None` after it); each send is always bounded by [`WRITE_TIMEOUT`].
    pub(crate) fn limit_sends_until(&mut self, deadline: Option<Instant>) {
        self.send_until = deadline;
    }

    /// Whether a send timed out: the connection is finished and the session is to end.
    pub(crate) fn is_broken(&self) -> bool {
        self.broken
    }

    /// Whether the underlying TCP socket has Nagle's algorithm turned off.
    #[cfg(test)]
    pub(crate) fn tcp_nodelay(&self) -> std::io::Result<bool> {
        self.ws.get_ref().get_ref().0.nodelay()
    }

    /// Sends one binary L3 record (protocol.md 3.3: "one message is one
    /// L3 record"). Errors if `payload` exceeds
    /// [`menzil_carrier::MAX_MESSAGE_BYTES`] without sending anything, and with
    /// [`RelayError::WriteTimeout`] (after which the connection is finished) if the peer has not
    /// taken the record within [`WRITE_TIMEOUT`], or before the send deadline set with
    /// `limit_sends_until`.
    pub async fn send(&mut self, payload: Vec<u8>) -> Result<(), RelayError> {
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(RelayError::PayloadTooLarge {
                len: payload.len(),
                max: MAX_MESSAGE_BYTES,
            });
        }
        if self.broken {
            return Err(RelayError::WriteTimeout);
        }
        let mut until = Instant::now() + self.write_timeout;
        if let Some(deadline) = self.send_until {
            until = until.min(deadline);
        }
        match tokio::time::timeout_at(until, self.ws.send(Message::Binary(payload.into()))).await {
            Ok(sent) => Ok(sent?),
            Err(_elapsed) => {
                self.broken = true;
                Err(RelayError::WriteTimeout)
            }
        }
    }

    /// Receives the next binary L3 record, transparently skipping
    /// WebSocket-level ping/pong control frames (liveness is measured at
    /// L3, not with these, per protocol.md 3.3). Errors on a text message
    /// (protocol.md 3.3: "binary messages only") or a closed connection.
    pub async fn recv(&mut self) -> Result<Vec<u8>, RelayError> {
        if self.broken {
            return Err(RelayError::Closed);
        }
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
