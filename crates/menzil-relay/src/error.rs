//! Errors this crate's relay-side inbound transport operations can
//! produce.

use thiserror::Error;

/// Everything that can go wrong accepting a connection to the relay's own
/// hostname: TLS setup, the TLS handshake, and the WebSocket upgrade
/// (protocol.md 3, mirrored server-side).
#[derive(Debug, Error)]
pub enum RelayError {
    /// TLS configuration could not be built from the supplied certificate
    /// and key material.
    #[error("tls setup error: {0}")]
    TlsSetup(String),

    /// The TLS handshake or a subsequent TLS operation failed.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),

    /// The WebSocket handshake or framing failed.
    #[error("websocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    /// A received message was not a WebSocket binary message
    /// (protocol.md 3.3: "binary messages only").
    #[error("received a non-binary websocket message")]
    UnexpectedMessageType,

    /// A message exceeded the Noise message size limit
    /// ([`menzil_carrier::MAX_MESSAGE_BYTES`], protocol.md 3.3).
    #[error("message of {len} bytes exceeds the {max} byte relay payload limit")]
    PayloadTooLarge {
        /// The size of the message that was rejected.
        len: usize,
        /// The limit it exceeded.
        max: usize,
    },

    /// The underlying connection closed.
    #[error("relay connection closed")]
    Closed,

    /// A lower level I/O error (TCP accept, read, or write).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The Noise handshake or transport cipher failed, or a HELLO/
    /// WELCOME payload could not be encoded or decoded.
    #[error("session error: {0}")]
    Session(#[from] menzil_session::SessionError),

    /// A signed wire value (a HELLO's NodeCert, a Roster) failed to
    /// decode, or its signature did not verify.
    #[error("proto error: {0}")]
    Proto(#[from] menzil_proto::ProtoError),

    /// A raw 32-byte key (a NetworkId used as a Roster's owning key, or a
    /// NodeId used as a NodeCert's self-signing key) was not a valid
    /// Ed25519 public key.
    #[error("invalid ed25519 public key: {0}")]
    InvalidPublicKey(#[from] ed25519_dalek::SignatureError),

    /// HELLO failed the checks protocol.md 4.1 assigns the relay (NodeCert
    /// verification, serial/timestamp monotonicity, claimed-network
    /// membership). The relay's own response (an ERROR record, best
    /// effort) has already been attempted by the time this is returned;
    /// this is only the local record of why the connection is being
    /// closed.
    #[error("HELLO rejected ({code:?}): {message}")]
    HelloRejected {
        /// The registry code sent back to the node.
        code: menzil_proto::ErrorCode,
        /// Free-text detail, also sent back to the node.
        message: String,
    },
}
