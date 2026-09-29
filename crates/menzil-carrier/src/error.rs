//! Errors this crate's carrier operations can produce.

use thiserror::Error;

/// Everything that can go wrong reaching the relay: bad connection info,
/// proxy resolution and CONNECT failures, TLS setup, and the WebSocket
/// upgrade (protocol.md 3).
#[derive(Debug, Error)]
pub enum CarrierError {
    /// Connection information (protocol.md 3.2) failed to parse.
    #[error("invalid connection info: {0}")]
    ConnectionInfo(String),

    /// The proxy CONNECT tunnel could not be established.
    #[error("proxy CONNECT failed: {0}")]
    Connect(String),

    /// A 407 offered no scheme this phase supports (protocol.md 3.1 step
    /// 2: "a 407 with no supported scheme is a hard error").
    #[error("proxy requires unsupported authentication scheme(s): {0}")]
    UnsupportedProxyAuth(String),

    /// TLS configuration could not be built (platform verifier setup, an
    /// invalid server name, or similar).
    #[error("tls setup error: {0}")]
    TlsSetup(String),

    /// The TLS handshake or a subsequent TLS operation failed.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    /// The WebSocket handshake or framing failed.
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// The server did not complete the WebSocket upgrade.
    #[error("websocket upgrade rejected: {0}")]
    UpgradeRejected(String),

    /// A received message was not a WebSocket binary message
    /// (protocol.md 3.3: "binary messages only").
    #[error("received a non-binary websocket message")]
    UnexpectedMessageType,

    /// A message exceeded the Noise message size limit (protocol.md 3.3).
    #[error("message of {len} bytes exceeds the {max} byte carrier payload limit")]
    PayloadTooLarge {
        /// The size of the message that was rejected.
        len: usize,
        /// The limit it exceeded.
        max: usize,
    },

    /// The underlying connection closed.
    #[error("carrier connection closed")]
    Closed,

    /// A lower level I/O error (TCP connect, read, or write).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
