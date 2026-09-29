//! Node identity: the Ed25519 [`NodeId`](crate::bytes::NodeId) and the
//! [`NodeCert`] that binds it to a Noise static key (protocol.md 2.2).

use serde::{Deserialize, Serialize};

use crate::bytes::{NodeId, X25519PublicKey};
use crate::signed::{Signed, SignedBody, TAG_NODECERT};

/// ```text
/// NodeCert = Signed("nodecert"){ v: 1, node_id: bytes32, x25519_pub: bytes32,
///     serial: u32, not_before: u64, not_after: u64 }
/// ```
/// (protocol.md 2.2)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCertBody {
    /// Document schema version.
    pub v: u16,
    /// The node identity this certificate speaks for.
    pub node_id: NodeId,
    /// The X25519 static key bound to `node_id` for the Noise handshakes.
    pub x25519_pub: X25519PublicKey,
    /// Increases by one on every rotation; verifiers reject a lower
    /// serial than the highest they have accepted for this `node_id`.
    pub serial: u32,
    /// Start of the validity window, Unix seconds.
    pub not_before: u64,
    /// End of the validity window, Unix seconds. At most 400 days after
    /// `not_before` (protocol.md 2.2); that bound is a policy check for
    /// the issuer, not enforced by this type.
    pub not_after: u64,
}

impl SignedBody for NodeCertBody {
    const TAG: &'static str = TAG_NODECERT;
}

/// A signed, verifiable node identity certificate.
pub type NodeCert = Signed<NodeCertBody>;

impl NodeCertBody {
    /// Whether `now` (Unix seconds) falls within `[not_before, not_after]`.
    /// A pure check against the document's own fields; it does not know
    /// about serial history or revocation, which are session state kept
    /// by relays and nodes, not by this crate.
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now <= self.not_after
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sample() -> NodeCertBody {
        NodeCertBody {
            v: crate::PROTOCOL_VERSION,
            node_id: NodeId::from([1u8; 32]),
            x25519_pub: X25519PublicKey::from([2u8; 32]),
            serial: 1,
            not_before: 1_700_000_000,
            not_after: 1_700_000_000 + 400 * 86_400,
        }
    }

    #[test]
    fn node_cert_signs_verifies_and_decodes() {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let body = sample();
        let cert = NodeCert::sign(&signing_key, &body).unwrap();
        cert.verify(&signing_key.verifying_key()).unwrap();
        assert_eq!(cert.decode().unwrap(), body);
    }

    #[test]
    fn is_valid_at_checks_the_window() {
        let body = sample();
        assert!(!body.is_valid_at(body.not_before - 1));
        assert!(body.is_valid_at(body.not_before));
        assert!(body.is_valid_at(body.not_after));
        assert!(!body.is_valid_at(body.not_after + 1));
    }
}
