//! A relay's own identity: the signed [`NodeCert`] binding its
//! [`NodeId`](menzil_proto::NodeId) to an X25519 static key (protocol.md
//! 2.2), plus that key's private half for the Noise handshake. A relay
//! is a node and has a NodeCert too (protocol.md 2.2).
//!
//! Generating and persisting this is a separate, not-yet-built concern,
//! the same as `menzil-node`'s `LocalIdentity`; this type only carries it,
//! already assembled. Kept as its own small type rather than shared with
//! `menzil-node`'s `LocalIdentity` (same two fields): the two crates play
//! different roles (initiator vs. responder) and neither depends on the
//! other, so sharing a two-field data type would cost a dependency edge
//! or a new tiny shared crate for no real benefit.

use menzil_proto::NodeCert;

/// What a relay needs of its own identity to run an L3 handshake
/// (protocol.md 4.1) and answer with WELCOME.
#[derive(Clone)]
pub struct RelayIdentity {
    /// This relay's own certificate, sent as WELCOME's `relay_cert`.
    pub node_cert: NodeCert,
    /// The X25519 private key `node_cert`'s `x25519_pub` is bound to.
    pub x25519_private: [u8; 32],
}

impl std::fmt::Debug for RelayIdentity {
    /// Redacts `x25519_private`: a derived `Debug` would print the raw
    /// private key, and this type is exactly the kind of thing that ends
    /// up in a `tracing::debug!(?relay_identity, ...)` by accident.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayIdentity")
            .field("node_cert", &self.node_cert)
            .field("x25519_private", &"<redacted>")
            .finish()
    }
}
