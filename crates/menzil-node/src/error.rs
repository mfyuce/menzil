//! Errors from dialing, handshaking with, and staying attached to a relay
//! (protocol.md 3, 4.1, 4.2).

use thiserror::Error;

/// Everything that can go wrong running a node-side L3 relay session.
#[derive(Debug, Error)]
pub enum NodeError {
    /// The carrier (L0 to L2) failed: proxy, TLS, or the WebSocket
    /// upgrade.
    #[error("carrier error: {0}")]
    Carrier(#[from] menzil_carrier::CarrierError),

    /// The Noise handshake or transport cipher failed, or a HELLO/WELCOME
    /// payload could not be encoded or decoded.
    #[error("session error: {0}")]
    Session(#[from] menzil_session::SessionError),

    /// A wire value failed to decode, or a signature did not verify.
    #[error("proto error: {0}")]
    Proto(#[from] menzil_proto::ProtoError),

    /// The relay completed the WebSocket upgrade without echoing a
    /// `Sec-WebSocket-Protocol` response header, so there is no
    /// `selected_subprotocol` string to bind into the L3 prologue
    /// (protocol.md 3.1 step 4, 4.1).
    #[error("relay did not select the {subprotocol} subprotocol")]
    SubprotocolNotSelected {
        /// The subprotocol this node offered.
        subprotocol: String,
    },

    /// WELCOME's `relay_cert` self-signature did not verify against the
    /// NodeId claimed in this node's connection information.
    #[error("relay certificate signature invalid: {0}")]
    RelayCertSignature(#[from] ed25519_dalek::SignatureError),

    /// WELCOME's `relay_cert` did not match the relay this node dialed
    /// (protocol.md 4.1: "the node verifies `relay_cert.node_id` equals
    /// the `id` of its connection information and `relay_cert.x25519_pub`
    /// equals the relay static key of the handshake").
    #[error("relay identity mismatch: {0}")]
    RelayIdentityMismatch(&'static str),

    /// The relay presented a certificate with a lower serial than the highest this node has
    /// verified for it (design note A3): a stolen older key answering, or an old backup restored.
    #[error(
        "relay rollback: this node holds serial {stored} for the relay, it presented serial {presented}"
    )]
    RelayRollback {
        /// The highest serial this node has verified for the relay.
        stored: u32,
        /// The serial the relay presented now.
        presented: u32,
    },

    /// The relay's certificate is past its `not_after`.
    #[error(
        "the relay's certificate expired at {not_after}; its operator must run `menzil relay renew-cert`"
    )]
    RelayCertExpired {
        /// The end of the certificate's window, Unix seconds.
        not_after: u64,
    },

    /// The relay's certificate starts more than an hour from now.
    #[error("the relay's certificate is not valid until {not_before} (this clock may be wrong)")]
    RelayCertNotYetValid {
        /// The start of the certificate's window, Unix seconds.
        not_before: u64,
    },

    /// The relay ended the session with GOAWAY (protocol.md 4.2); carries
    /// the `retry_after_ms` hint a reconnect loop should honor.
    #[error("relay sent GOAWAY: {reason}")]
    Goaway {
        /// The relay's stated reason.
        reason: String,
        /// How long the relay asked us to wait before reconnecting.
        retry_after_ms: u32,
    },

    /// No authenticated record arrived for two ping intervals (protocol.md
    /// 3.3: "a link is dead when no authenticated record has arrived for
    /// two ping intervals").
    #[error("link idle too long, presumed dead")]
    LinkDead,

    /// The acceptance predicate of protocol.md 2.3 refused the documents offered (see
    /// [`menzil_proto::trust::check_bundle`]). The reason is for the local log; a peer is told
    /// [`menzil_proto::trust::Reason::code`].
    #[error("documents refused: {0:?}")]
    DocumentRejected(menzil_proto::trust::Reason),

    /// A signed document (a Roster) exceeded
    /// [`menzil_proto::MAX_DOC_BYTES`] once encoded. Refused before it is
    /// stored — see `menzil-relay`'s identical
    /// `RelayError::DocumentTooLarge` for why this must be caught here
    /// rather than only discovered later, mid-panic, while trying to
    /// propagate it.
    #[error("document of {len} bytes exceeds the {max} byte limit")]
    DocumentTooLarge {
        /// The size that was rejected.
        len: usize,
        /// The limit it exceeded.
        max: usize,
    },
}
