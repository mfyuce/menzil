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

impl Drop for RelayIdentity {
    /// Wipes the X25519 private key when the identity goes (a clone wipes its own copy).
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.x25519_private);
    }
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

/// The relay's previous static key, kept for a window after a rotation so that nodes that still
/// dial IK with it are answered (design note `relay-key-and-invites-design.md` A5). One deep.
/// It is answered only with `retire_at` still in the future and a certificate whose window has
/// not ended; the holder drops it at start and at each reload once either has passed.
#[derive(Clone)]
pub struct PreviousKey {
    /// The previous certificate, sent as `relay_cert` of a session this key answers.
    pub node_cert: NodeCert,
    /// The X25519 private key `node_cert`'s `x25519_pub` is bound to.
    pub x25519_private: [u8; 32],
    /// Unix seconds after which this key answers nothing.
    pub retire_at: u64,
}

/// Whether a previous key whose certificate is `cert` and whose window ends at `retire_at` may
/// answer a handshake at `now`: `retire_at` is still ahead, and the certificate decodes and has
/// not expired. The one rule, for the running relay and for the file the commands read.
pub fn previous_key_answers(cert: &NodeCert, retire_at: u64, now: u64) -> bool {
    retire_at > now && cert.decode().is_ok_and(|body| body.not_after > now)
}

impl PreviousKey {
    /// Whether this key may answer a handshake at `now` ([`previous_key_answers`]).
    pub fn answers_at(&self, now: u64) -> bool {
        previous_key_answers(&self.node_cert, self.retire_at, now)
    }
}

impl Drop for PreviousKey {
    /// Wipes the X25519 private key when the key goes.
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.x25519_private);
    }
}

impl std::fmt::Debug for PreviousKey {
    /// Redacts `x25519_private`, like [`RelayIdentity`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreviousKey")
            .field("node_cert", &self.node_cert)
            .field("retire_at", &self.retire_at)
            .field("x25519_private", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{NodeCertBody, NodeId, PROTOCOL_VERSION, X25519PublicKey};

    fn previous(retire_at: u64, not_after: u64) -> PreviousKey {
        let key = SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: NodeId::from(key.verifying_key().to_bytes()),
            x25519_pub: X25519PublicKey::from([3u8; 32]),
            serial: 1,
            not_before: 0,
            not_after,
        };
        PreviousKey {
            node_cert: NodeCert::sign(&key, &body).unwrap(),
            x25519_private: [3u8; 32],
            retire_at,
        }
    }

    #[test]
    fn a_previous_key_answers_only_before_retire_at_and_before_its_cert_ends() {
        let now = 1_000;
        // retire_at is exclusive: at `now` it has passed.
        assert!(!previous(now, 5_000).answers_at(now));
        assert!(previous(now + 1, 5_000).answers_at(now));
        assert!(!previous(now - 1, 5_000).answers_at(now));
        // The certificate's `not_after` is exclusive too.
        assert!(!previous(5_000, now).answers_at(now));
        assert!(previous(5_000, now + 1).answers_at(now));
        assert!(!previous(5_000, now - 1).answers_at(now));
    }

    #[test]
    fn the_debug_output_of_a_previous_key_does_not_show_the_private_key() {
        let text = format!("{:?}", previous(10, 20));
        assert!(text.contains("<redacted>"));
        assert!(!text.contains("[3, 3, 3"));
    }
}
