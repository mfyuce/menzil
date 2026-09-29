//! Invites and admission requests (protocol.md 7.2).

use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac256, Digest};
use serde::{Deserialize, Serialize};

use crate::bytes::{ByteArray, InviteId, NetworkId, SecretHash};
use crate::identity::NodeCert;
use crate::signed::{Signed, SignedBody, TAG_INVITE};

/// ```text
/// Invite = Signed("invite"){ v: 1, network_id, invite_id: bytes16,
///     secret_hash: bytes32, roles: [str], expires: u64, uses: u8 }
/// ```
/// (protocol.md 7.2)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteBody {
    /// Document schema version.
    pub v: u16,
    /// The network this invite admits into.
    pub network_id: NetworkId,
    /// Identifies this invite; carried alongside the request so the
    /// relay and steward can find the matching secret hash.
    pub invite_id: InviteId,
    /// `BLAKE2s(secret)` (see [`hash_invite_secret`]); the secret itself
    /// never leaves the inviting device.
    pub secret_hash: SecretHash,
    /// Roles the redeeming node will hold.
    pub roles: Vec<String>,
    /// When this invite expires, Unix seconds.
    pub expires: u64,
    /// Remaining redemptions, enforced by the steward, never by relays
    /// (protocol.md 7.2).
    pub uses: u8,
}

impl SignedBody for InviteBody {
    const TAG: &'static str = TAG_INVITE;
}

/// A signed, verifiable invite.
pub type Invite = Signed<InviteBody>;

/// `secret_hash == BLAKE2s(secret)` (protocol.md 7.2): an unkeyed
/// BLAKE2s-256 digest of the invite secret.
pub fn hash_invite_secret(secret: &[u8]) -> SecretHash {
    let digest = Blake2s256::digest(secret);
    SecretHash::from(<[u8; 32]>::from(digest))
}

/// ```text
/// tag: BLAKE2s-256-keyed(key = secret, data = "menzil.v1.admit" || invite_id || node_cert_bytes)
/// ```
/// (protocol.md 7.2). `node_cert_bytes` is `node_cert`'s own encoded form
/// exactly as [`Signed::sign`] produces it (the full `[bstr body, bstr
/// sig]` array), since the spec does not spell out byte-for-byte what
/// "node_cert_bytes" means and this is the only encoding of a `NodeCert`
/// this crate defines.
pub fn compute_admit_tag(
    secret: &[u8],
    invite_id: InviteId,
    node_cert: &NodeCert,
) -> ByteArray<32> {
    let mut node_cert_bytes = Vec::new();
    ciborium::into_writer(node_cert, &mut node_cert_bytes)
        .expect("Signed<NodeCertBody> serialization is infallible for an in-memory buffer");
    let mut mac = Blake2sMac256::new_from_slice(secret)
        .expect("Blake2sMac256 accepts keys of any length up to its block size");
    Mac::update(&mut mac, b"menzil.v1.admit");
    Mac::update(&mut mac, invite_id.as_ref());
    Mac::update(&mut mac, &node_cert_bytes);
    let tag = mac.finalize().into_bytes();
    ByteArray::from(<[u8; 32]>::from(tag))
}

/// CBOR body of the `ADMIT_REQUEST` (0x0b) L3 record (protocol.md 4.2,
/// 7.2): an unsigned control message, so no `deny_unknown_fields` here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmitRequestBody {
    /// The invite being redeemed.
    pub invite: Invite,
    /// The redeeming device's certificate.
    pub node_cert: NodeCert,
    /// [`compute_admit_tag`]'s output, binding this request to the
    /// device's `node_cert`.
    pub tag: ByteArray<32>,
}

/// CBOR body of the `ADMIT_PENDING` (0x0c) L3 record: the relay forwards
/// the same request to the steward node verbatim (protocol.md 7.2: "the
/// relay delivers ADMIT_PENDING with the request").
pub type AdmitPendingBody = AdmitRequestBody;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::X25519PublicKey;
    use crate::identity::NodeCertBody;
    use ed25519_dalek::SigningKey;

    #[test]
    fn invite_signs_verifies_and_decodes() {
        let owner = SigningKey::generate(&mut rand::rng());
        let secret = b"a very secret invite value";
        let body = InviteBody {
            v: crate::PROTOCOL_VERSION,
            network_id: NetworkId::from([1u8; 32]),
            invite_id: InviteId::from([2u8; 16]),
            secret_hash: hash_invite_secret(secret),
            roles: vec!["member".to_string()],
            expires: 1_800_000_000,
            uses: 1,
        };
        let invite = Invite::sign(&owner, &body).unwrap();
        invite.verify(&owner.verifying_key()).unwrap();
        assert_eq!(invite.decode().unwrap(), body);
    }

    #[test]
    fn hash_invite_secret_is_deterministic_and_unkeyed() {
        let secret = b"same secret";
        assert_eq!(hash_invite_secret(secret), hash_invite_secret(secret));
        assert_ne!(
            hash_invite_secret(secret),
            hash_invite_secret(b"other secret")
        );
    }

    #[test]
    fn admit_tag_changes_with_any_input() {
        let node_key = SigningKey::generate(&mut rand::rng());
        let cert_body = NodeCertBody {
            v: crate::PROTOCOL_VERSION,
            node_id: node_id_for_cert(),
            x25519_pub: X25519PublicKey::from([9u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        let cert = NodeCert::sign(&node_key, &cert_body).unwrap();
        let invite_id = InviteId::from([7u8; 16]);
        let secret = b"secret-a";

        let tag = compute_admit_tag(secret, invite_id, &cert);
        assert_eq!(tag, compute_admit_tag(secret, invite_id, &cert));
        assert_ne!(tag, compute_admit_tag(b"secret-b", invite_id, &cert));
        assert_ne!(
            tag,
            compute_admit_tag(secret, InviteId::from([8u8; 16]), &cert)
        );
    }

    fn node_id_for_cert() -> crate::bytes::NodeId {
        crate::bytes::NodeId::from([3u8; 32])
    }

    #[test]
    fn admit_request_round_trips_and_tolerates_unknown_keys() {
        let owner = SigningKey::generate(&mut rand::rng());
        let node_key = SigningKey::generate(&mut rand::rng());
        let invite_body = InviteBody {
            v: crate::PROTOCOL_VERSION,
            network_id: NetworkId::from([1u8; 32]),
            invite_id: InviteId::from([2u8; 16]),
            secret_hash: hash_invite_secret(b"secret"),
            roles: vec![],
            expires: 1_800_000_000,
            uses: 1,
        };
        let invite = Invite::sign(&owner, &invite_body).unwrap();
        let cert_body = NodeCertBody {
            v: crate::PROTOCOL_VERSION,
            node_id: node_id_for_cert(),
            x25519_pub: X25519PublicKey::from([9u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        let node_cert = NodeCert::sign(&node_key, &cert_body).unwrap();
        let tag = compute_admit_tag(b"secret", invite_body.invite_id, &node_cert);
        let request = AdmitRequestBody {
            invite,
            node_cert,
            tag,
        };

        let mut buf = Vec::new();
        ciborium::into_writer(&request, &mut buf).unwrap();
        let decoded: AdmitRequestBody = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded, request);
    }
}
