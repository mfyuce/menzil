//! A node's local identity: the signed [`NodeCert`] binding its
//! [`NodeId`](menzil_proto::NodeId) to an X25519 static key (protocol.md
//! 2.2), plus that key's private half for the Noise handshake.
//!
//! Generating and persisting this — the Ed25519 keypair, file
//! permissions, NodeCert issuance and rotation (protocol.md 2.2) — is a
//! separate, not-yet-built concern; this type only carries what
//! [`crate::Session`] needs to run a handshake, supplied already
//! assembled by the caller. This follows the same precedent
//! `menzil-relay` set for its own TLS certificate material: "certificate
//! and key material is supplied to this crate already loaded."

use menzil_proto::NodeCert;

/// What a node needs of its own identity to run an L3 handshake
/// (protocol.md 4.1).
#[derive(Clone)]
pub struct LocalIdentity {
    /// This node's own certificate, sent as HELLO's `node_cert`.
    pub node_cert: NodeCert,
    /// The X25519 private key `node_cert`'s `x25519_pub` is bound to.
    pub x25519_private: [u8; 32],
}

impl std::fmt::Debug for LocalIdentity {
    /// Redacts `x25519_private`: a derived `Debug` would print the raw
    /// private key, and this type is exactly the kind of thing that ends
    /// up in a `tracing::debug!(?identity, ...)` by accident.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("node_cert", &self.node_cert)
            .field("x25519_private", &"<redacted>")
            .finish()
    }
}
