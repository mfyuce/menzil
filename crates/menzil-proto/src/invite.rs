//! Invites and admission requests (protocol.md 7.2).

use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac256, Digest};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::bytes::{ByteArray, InviteId, NetworkId, NodeId, SecretHash, Tai64N};
use crate::error::{ErrorCode, ProtoError};
use crate::identity::NodeCert;
use crate::network::Roster;
use crate::signed::{Signed, SignedBody, TAG_INVITE};

/// ```text
/// Invite = Signed("invite"){ v: 1, network_id, invite_id: bytes16,
///     secret_hash: bytes32, roles: [str], expires: u64, uses: u8,
///     name?: str }
/// ```
/// (protocol.md 7.2). `roles` must be empty in version 1
/// ([`InviteBody::check_roles_empty`]); `name` is optional and, when set,
/// fixes the device name ([`InviteBody::check_request_name`]).
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
    /// A device name the invite fixes: the request's `name` must equal it.
    /// Absent when the redeemer chooses. Not written when `None`, so an
    /// invite without it keeps the bytes it had before the field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl SignedBody for InviteBody {
    const TAG: &'static str = TAG_INVITE;
}

/// Why an invite or a request failed one of the body level checks that every
/// party (issuer command, relay, redeemer) applies the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum InviteCheckError {
    /// `roles` is not empty (protocol.md 7.2: empty in version 1).
    #[error("an invite must carry no roles in version 1")]
    RolesNotEmpty,
    /// The invite fixes a name and the request's name differs.
    #[error("the request name is not the name the invite fixes")]
    NameMismatch,
}

impl InviteBody {
    /// `roles` must be empty in version 1, for owner and steward invites alike.
    pub fn check_roles_empty(&self) -> Result<(), InviteCheckError> {
        if self.roles.is_empty() {
            Ok(())
        } else {
            Err(InviteCheckError::RolesNotEmpty)
        }
    }

    /// When the invite fixes a name, `request_name` must equal it exactly
    /// (byte for byte; case folding and `check_name` are the caller's own
    /// separate checks). An invite without a fixed name accepts any.
    pub fn check_request_name(&self, request_name: &str) -> Result<(), InviteCheckError> {
        match &self.name {
            Some(fixed) if fixed != request_name => Err(InviteCheckError::NameMismatch),
            _ => Ok(()),
        }
    }
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
/// tag: BLAKE2s-256-keyed(key = secret,
///     data = "menzil.v1.admit" || invite_id || node_cert_bytes || 0x00 || name)
/// ```
/// (protocol.md 7.2). `node_cert_bytes` is `node_cert`'s own encoded form
/// exactly as [`Signed::sign`] produces it (the full `[bstr body, bstr
/// sig]` array), since the spec does not spell out byte-for-byte what
/// "node_cert_bytes" means and this is the only encoding of a `NodeCert`
/// this crate defines. `name` is the device name of the request, so a relay
/// cannot rename the device.
pub fn compute_admit_tag(
    secret: &[u8],
    invite_id: InviteId,
    node_cert: &NodeCert,
    name: &str,
) -> ByteArray<32> {
    let mac = admit_mac(secret, invite_id, node_cert, name);
    let tag = mac.finalize().into_bytes();
    ByteArray::from(<[u8; 32]>::from(tag))
}

/// Checks `tag` against [`compute_admit_tag`]'s output in constant time.
pub fn verify_admit_tag(
    secret: &[u8],
    invite_id: InviteId,
    node_cert: &NodeCert,
    name: &str,
    tag: &ByteArray<32>,
) -> bool {
    admit_mac(secret, invite_id, node_cert, name)
        .verify_slice(tag.as_ref())
        .is_ok()
}

fn admit_mac(
    secret: &[u8],
    invite_id: InviteId,
    node_cert: &NodeCert,
    name: &str,
) -> Blake2sMac256 {
    let mut node_cert_bytes = Vec::new();
    ciborium::into_writer(node_cert, &mut node_cert_bytes)
        .expect("Signed<NodeCertBody> serialization is infallible for an in-memory buffer");
    let mut mac = Blake2sMac256::new_from_slice(secret)
        .expect("Blake2sMac256 accepts keys of any length up to its block size");
    Mac::update(&mut mac, b"menzil.v1.admit");
    Mac::update(&mut mac, invite_id.as_ref());
    Mac::update(&mut mac, &node_cert_bytes);
    Mac::update(&mut mac, &[0x00]);
    Mac::update(&mut mac, name.as_bytes());
    mac
}

/// CBOR body of the `ADMIT_REQUEST` (0x0b) L3 record (protocol.md 4.2,
/// 7.2): an unsigned control message, so no `deny_unknown_fields` here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmitRequestBody {
    /// The invite being redeemed.
    pub invite: Invite,
    /// The redeeming device's certificate.
    pub node_cert: NodeCert,
    /// The device's name in the network (checked with `check_name` by the
    /// issuer); covered by `tag`.
    pub name: String,
    /// [`compute_admit_tag`]'s output, binding this request to the
    /// device's `node_cert` and `name`.
    pub tag: ByteArray<32>,
}

/// CBOR body of the `ADMIT_PENDING` (0x0c) L3 record: the relay forwards
/// the same request to the steward node verbatim (protocol.md 7.2: "the
/// relay delivers ADMIT_PENDING with the request").
pub type AdmitPendingBody = AdmitRequestBody;

/// CBOR body of the `ADMIT_RESULT` (0x0d) L3 record (protocol.md 7.2), relay
/// to node: exactly one of `{ roster, base_roster? }`, `{ pending: true }`,
/// `{ refused: u16 }`. Decoding is strict: unknown keys, no variant, two
/// variants, `pending: false` and a `base_roster` without a `roster` are all
/// refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitResultBody {
    /// The admitted network's Roster (and, when a steward signed it, the
    /// owner signed base it extends). Never a Policy: the device gets that by
    /// the issuer's push.
    Admitted {
        /// The Roster that lists the device.
        roster: Roster,
        /// The owner signed base of a steward signed Roster.
        base_roster: Option<Roster>,
    },
    /// The issuer is not reachable yet; the device waits and asks again.
    Pending,
    /// The issuer refused; the code says why (an [`ErrorCode`] number).
    Refused(u16),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmitResultWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    roster: Option<Roster>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    base_roster: Option<Roster>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refused: Option<u16>,
}

impl Serialize for AdmitResultBody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            Self::Admitted {
                roster,
                base_roster,
            } => AdmitResultWire {
                roster: Some(roster.clone()),
                base_roster: base_roster.clone(),
                pending: None,
                refused: None,
            },
            Self::Pending => AdmitResultWire {
                roster: None,
                base_roster: None,
                pending: Some(true),
                refused: None,
            },
            Self::Refused(code) => AdmitResultWire {
                roster: None,
                base_roster: None,
                pending: None,
                refused: Some(*code),
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AdmitResultBody {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let wire = AdmitResultWire::deserialize(deserializer)?;
        match wire {
            AdmitResultWire {
                roster: Some(roster),
                base_roster,
                pending: None,
                refused: None,
            } => Ok(Self::Admitted {
                roster,
                base_roster,
            }),
            AdmitResultWire {
                roster: None,
                base_roster: None,
                pending: Some(true),
                refused: None,
            } => Ok(Self::Pending),
            AdmitResultWire {
                roster: None,
                base_roster: None,
                pending: None,
                refused: Some(code),
            } => Ok(Self::Refused(code)),
            _ => Err(D::Error::custom(
                "ADMIT_RESULT must hold exactly one of roster, pending: true, refused",
            )),
        }
    }
}

/// The bytes an `ADMIT_LISTEN` proof signs (protocol.md 7.2):
/// `"menzil.v1.admit-listen" || 0x00 || relay NodeId || session NodeId ||
/// HELLO timestamp`. The relay id, the session's NodeId and the session's
/// HELLO timestamp make a captured proof useless on another relay or session.
pub fn admit_listen_signing_bytes(
    relay: NodeId,
    session: NodeId,
    hello_timestamp: Tai64N,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(b"menzil.v1.admit-listen".len() + 1 + 32 + 32 + 12);
    msg.extend_from_slice(b"menzil.v1.admit-listen");
    msg.push(0x00);
    msg.extend_from_slice(relay.as_ref());
    msg.extend_from_slice(session.as_ref());
    msg.extend_from_slice(hello_timestamp.as_ref());
    msg
}

/// CBOR body of the `ADMIT_LISTEN` (0x10) L3 record, node to relay: the
/// issuer's registration for a network's `ADMIT_PENDING`, proved by
/// `sig = Ed25519(signer, admit_listen_signing_bytes(..))`. Whether `signer`
/// is the network's owner or a steward with `admit` is the relay's check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitListenBody {
    /// The network the issuer serves.
    pub network_id: NetworkId,
    /// The owner key or the steward key that signed the proof.
    pub signer: ByteArray<32>,
    /// The proof signature.
    pub sig: ByteArray<64>,
}

impl AdmitListenBody {
    /// Signs the proof for a session on a relay.
    pub fn sign(
        network_id: NetworkId,
        signing_key: &ed25519_dalek::SigningKey,
        relay: NodeId,
        session: NodeId,
        hello_timestamp: Tai64N,
    ) -> Self {
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&admit_listen_signing_bytes(relay, session, hello_timestamp));
        Self {
            network_id,
            signer: ByteArray::from(signing_key.verifying_key().to_bytes()),
            sig: ByteArray::from(sig.to_bytes()),
        }
    }

    /// Verifies the signature (`verify_strict`) of `signer` over the bytes of
    /// this relay, session and HELLO timestamp.
    pub fn verify(
        &self,
        relay: NodeId,
        session: NodeId,
        hello_timestamp: Tai64N,
    ) -> Result<(), ProtoError> {
        let key = VerifyingKey::from_bytes(&self.signer.0)?;
        let signature = Signature::from_bytes(&self.sig.0);
        key.verify_strict(
            &admit_listen_signing_bytes(relay, session, hello_timestamp),
            &signature,
        )
        .map_err(ProtoError::from)
    }
}

/// CBOR body of the `ADMIT_REFUSED` (0x11) L3 record, node to relay: the
/// registered issuer's refusal of one request; the relay turns it into
/// ADMIT_RESULT `{ refused: code }` for that device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitRefusedBody {
    /// The invite of the refused request.
    pub invite_id: InviteId,
    /// The device whose request is refused.
    pub node_id: NodeId,
    /// Why.
    pub code: ErrorCode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::X25519PublicKey;
    use crate::identity::NodeCertBody;
    use crate::network::RosterBody;
    use crate::record::{Record, RecordType};
    use ed25519_dalek::SigningKey;

    fn node_id_for_cert() -> NodeId {
        NodeId::from([3u8; 32])
    }

    fn cert_with(key: &SigningKey, serial: u32) -> NodeCert {
        let cert_body = NodeCertBody {
            v: crate::PROTOCOL_VERSION,
            node_id: node_id_for_cert(),
            x25519_pub: X25519PublicKey::from([9u8; 32]),
            serial,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        NodeCert::sign(key, &cert_body).unwrap()
    }

    fn invite_body(roles: Vec<String>, name: Option<String>) -> InviteBody {
        InviteBody {
            v: crate::PROTOCOL_VERSION,
            network_id: NetworkId::from([1u8; 32]),
            invite_id: InviteId::from([2u8; 16]),
            secret_hash: hash_invite_secret(b"secret"),
            roles,
            expires: 1_800_000_000,
            uses: 1,
            name,
        }
    }

    fn sample_roster(seq: u64) -> Roster {
        let key = SigningKey::from_bytes(&[11u8; 32]);
        Roster::sign(
            &key,
            &RosterBody {
                v: crate::PROTOCOL_VERSION,
                network_id: NetworkId::from([6u8; 32]),
                seq,
                issued: 0,
                expires: 1_000_000_000,
                members: vec![],
                revoked: vec![],
                stewards: vec![],
                labels: vec![],
            },
        )
        .unwrap()
    }

    fn cbor<T: Serialize>(value: &T) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(value, &mut buf).unwrap();
        buf
    }

    fn decode_strict<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
        crate::strict::check_definite_lengths(bytes)?;
        ciborium::from_reader(bytes).map_err(|e| ProtoError::Decode(e.to_string()))
    }

    #[test]
    fn invite_signs_verifies_and_decodes() {
        let owner = SigningKey::generate(&mut rand::rng());
        let body = invite_body(vec![], Some("laptop".to_string()));
        let invite = Invite::sign(&owner, &body).unwrap();
        invite.verify(&owner.verifying_key()).unwrap();
        assert_eq!(invite.decode().unwrap(), body);
    }

    #[test]
    fn an_invite_without_a_fixed_name_does_not_write_the_key() {
        let without = cbor(&invite_body(vec![], None));
        let with = cbor(&invite_body(vec![], Some("a".to_string())));
        // Map of 7 entries (0xa7) against 8 (0xa8); the name key only in the latter.
        assert_eq!(without[0], 0xa7);
        assert_eq!(with[0], 0xa8);
        assert!(!without.windows(4).any(|w| w == b"name"));
        assert!(with.windows(4).any(|w| w == b"name"));
        let back: InviteBody = decode_strict(&without).unwrap();
        assert_eq!(back.name, None);
        let back: InviteBody = decode_strict(&with).unwrap();
        assert_eq!(back.name.as_deref(), Some("a"));
    }

    #[test]
    fn invite_body_refuses_unknown_keys() {
        let mut bytes = cbor(&invite_body(vec![], None));
        bytes[0] = 0xa8;
        bytes.extend_from_slice(&cbor(&"extra"));
        bytes.extend_from_slice(&cbor(&1u8));
        assert!(decode_strict::<InviteBody>(&bytes).is_err());
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
    fn roles_must_be_empty() {
        assert_eq!(invite_body(vec![], None).check_roles_empty(), Ok(()));
        assert_eq!(
            invite_body(vec!["member".to_string()], None).check_roles_empty(),
            Err(InviteCheckError::RolesNotEmpty)
        );
    }

    #[test]
    fn a_fixed_name_must_equal_the_request_name() {
        let fixed = invite_body(vec![], Some("laptop".to_string()));
        assert_eq!(fixed.check_request_name("laptop"), Ok(()));
        assert_eq!(
            fixed.check_request_name("Laptop"),
            Err(InviteCheckError::NameMismatch)
        );
        assert_eq!(
            fixed.check_request_name("laptop2"),
            Err(InviteCheckError::NameMismatch)
        );
        assert_eq!(
            fixed.check_request_name(""),
            Err(InviteCheckError::NameMismatch)
        );
        let open = invite_body(vec![], None);
        assert_eq!(open.check_request_name("anything"), Ok(()));
        assert_eq!(open.check_request_name(""), Ok(()));
    }

    #[test]
    fn admit_tag_matches_the_spelled_out_construction() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let cert = cert_with(&key, 1);
        let invite_id = InviteId::from([7u8; 16]);
        let mut data = b"menzil.v1.admit".to_vec();
        data.extend_from_slice(invite_id.as_ref());
        data.extend_from_slice(&cbor(&cert));
        data.push(0x00);
        data.extend_from_slice(b"laptop");
        let mut mac = Blake2sMac256::new_from_slice(b"secret-a").unwrap();
        Mac::update(&mut mac, &data);
        let expected = ByteArray::from(<[u8; 32]>::from(mac.finalize().into_bytes()));
        assert_eq!(
            compute_admit_tag(b"secret-a", invite_id, &cert, "laptop"),
            expected
        );
    }

    #[test]
    fn admit_tag_changes_with_any_input() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let cert = cert_with(&key, 1);
        let invite_id = InviteId::from([7u8; 16]);
        let secret = b"secret-a";

        let tag = compute_admit_tag(secret, invite_id, &cert, "laptop");
        assert_eq!(tag, compute_admit_tag(secret, invite_id, &cert, "laptop"));
        assert_ne!(
            tag,
            compute_admit_tag(b"secret-b", invite_id, &cert, "laptop")
        );
        assert_ne!(
            tag,
            compute_admit_tag(secret, InviteId::from([8u8; 16]), &cert, "laptop")
        );
        assert_ne!(
            tag,
            compute_admit_tag(secret, invite_id, &cert_with(&key, 2), "laptop")
        );
        assert_ne!(tag, compute_admit_tag(secret, invite_id, &cert, "laptoq"));
        // Name boundary: a prefix, the empty name and a trailing byte all differ.
        let a = compute_admit_tag(secret, invite_id, &cert, "a");
        assert_ne!(a, compute_admit_tag(secret, invite_id, &cert, "ab"));
        assert_ne!(a, compute_admit_tag(secret, invite_id, &cert, ""));
        assert_ne!(a, compute_admit_tag(secret, invite_id, &cert, "a\0"));
    }

    #[test]
    fn verify_admit_tag_accepts_only_the_exact_tag() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let cert = cert_with(&key, 1);
        let invite_id = InviteId::from([7u8; 16]);
        let tag = compute_admit_tag(b"s", invite_id, &cert, "n");
        assert!(verify_admit_tag(b"s", invite_id, &cert, "n", &tag));
        assert!(!verify_admit_tag(b"s", invite_id, &cert, "m", &tag));
        assert!(!verify_admit_tag(b"t", invite_id, &cert, "n", &tag));
        let mut bad = tag.0;
        bad[31] ^= 1;
        assert!(!verify_admit_tag(
            b"s",
            invite_id,
            &cert,
            "n",
            &ByteArray::from(bad)
        ));
    }

    fn sample_request() -> AdmitRequestBody {
        let owner = SigningKey::from_bytes(&[4u8; 32]);
        let node_key = SigningKey::from_bytes(&[5u8; 32]);
        let invite = Invite::sign(&owner, &invite_body(vec![], None)).unwrap();
        let node_cert = cert_with(&node_key, 1);
        let tag = compute_admit_tag(b"secret", InviteId::from([2u8; 16]), &node_cert, "laptop");
        AdmitRequestBody {
            invite,
            node_cert,
            name: "laptop".to_string(),
            tag,
        }
    }

    #[test]
    fn admit_request_round_trips_with_its_name_and_golden_keys() {
        let request = sample_request();
        let buf = cbor(&request);
        let decoded: AdmitRequestBody = decode_strict(&buf).unwrap();
        assert_eq!(decoded, request);
        // Four keys, in declaration order, the name a text string.
        assert_eq!(buf[0], 0xa4);
        let name_entry = [&[0x64u8][..], b"name", &[0x66], b"laptop"].concat();
        assert!(buf.windows(name_entry.len()).any(|w| w == name_entry));
    }

    #[test]
    fn admit_request_without_a_name_is_refused() {
        #[derive(Serialize)]
        struct Old {
            invite: Invite,
            node_cert: NodeCert,
            tag: ByteArray<32>,
        }
        let r = sample_request();
        let old = Old {
            invite: r.invite,
            node_cert: r.node_cert,
            tag: r.tag,
        };
        assert!(decode_strict::<AdmitRequestBody>(&cbor(&old)).is_err());
    }

    #[test]
    fn admit_result_round_trips_every_variant_with_golden_bytes() {
        let roster = sample_roster(1);
        let base = sample_roster(2);
        for body in [
            AdmitResultBody::Admitted {
                roster: roster.clone(),
                base_roster: None,
            },
            AdmitResultBody::Admitted {
                roster: roster.clone(),
                base_roster: Some(base.clone()),
            },
            AdmitResultBody::Pending,
            AdmitResultBody::Refused(30),
            AdmitResultBody::Refused(0),
        ] {
            let buf = cbor(&body);
            assert_eq!(decode_strict::<AdmitResultBody>(&buf).unwrap(), body);
        }
        // Golden: { pending: true } and { refused: 30 }.
        assert_eq!(
            cbor(&AdmitResultBody::Pending),
            [&[0xa1, 0x67][..], b"pending", &[0xf5]].concat()
        );
        assert_eq!(
            cbor(&AdmitResultBody::Refused(30)),
            [&[0xa1, 0x67][..], b"refused", &[0x18, 30]].concat()
        );
        // One key without a base, two with.
        assert_eq!(
            cbor(&AdmitResultBody::Admitted {
                roster: roster.clone(),
                base_roster: None
            })[0],
            0xa1
        );
        let with_base = cbor(&AdmitResultBody::Admitted {
            roster,
            base_roster: Some(base),
        });
        assert_eq!(with_base[0], 0xa2);
    }

    #[derive(Serialize)]
    struct Loose {
        #[serde(skip_serializing_if = "Option::is_none")]
        roster: Option<Roster>,
        #[serde(skip_serializing_if = "Option::is_none")]
        base_roster: Option<Roster>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pending: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        refused: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        extra: Option<u8>,
    }

    fn loose() -> Loose {
        Loose {
            roster: None,
            base_roster: None,
            pending: None,
            refused: None,
            extra: None,
        }
    }

    #[test]
    fn admit_result_refuses_anything_but_exactly_one_variant() {
        let roster = sample_roster(1);
        let bad = |l: Loose| decode_strict::<AdmitResultBody>(&cbor(&l)).is_err();
        // Empty.
        assert!(bad(loose()));
        // Two variants.
        assert!(bad(Loose {
            roster: Some(roster.clone()),
            pending: Some(true),
            ..loose()
        }));
        assert!(bad(Loose {
            roster: Some(roster.clone()),
            refused: Some(1),
            ..loose()
        }));
        assert!(bad(Loose {
            pending: Some(true),
            refused: Some(1),
            ..loose()
        }));
        // pending: false is not a variant.
        assert!(bad(Loose {
            pending: Some(false),
            ..loose()
        }));
        // A base without a roster, beside pending or refused.
        assert!(bad(Loose {
            base_roster: Some(roster.clone()),
            ..loose()
        }));
        assert!(bad(Loose {
            base_roster: Some(roster.clone()),
            pending: Some(true),
            ..loose()
        }));
        // Unknown key, alone and beside a valid variant.
        assert!(bad(Loose {
            extra: Some(1),
            ..loose()
        }));
        assert!(bad(Loose {
            pending: Some(true),
            extra: Some(1),
            ..loose()
        }));
        // Wrong types.
        let wrong_refused = [&[0xa1, 0x67][..], b"refused", &[0x61, b'x']].concat();
        assert!(decode_strict::<AdmitResultBody>(&wrong_refused).is_err());
        let too_big = [&[0xa1, 0x67][..], b"refused", &[0x1a, 0, 1, 0, 0]].concat();
        assert!(decode_strict::<AdmitResultBody>(&too_big).is_err());
        // The control: one valid variant passes the same helper.
        assert!(!bad(Loose {
            pending: Some(true),
            ..loose()
        }));
    }

    fn ts(byte: u8) -> Tai64N {
        Tai64N::from([byte; 12])
    }

    #[test]
    fn listen_signing_bytes_are_golden_and_change_with_each_input() {
        let relay = NodeId::from([1u8; 32]);
        let session = NodeId::from([2u8; 32]);
        let bytes = admit_listen_signing_bytes(relay, session, ts(3));
        let expected = [
            &b"menzil.v1.admit-listen"[..],
            &[0x00],
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 12],
        ]
        .concat();
        assert_eq!(bytes, expected);
        assert_ne!(
            bytes,
            admit_listen_signing_bytes(NodeId::from([9u8; 32]), session, ts(3))
        );
        assert_ne!(
            bytes,
            admit_listen_signing_bytes(relay, NodeId::from([9u8; 32]), ts(3))
        );
        assert_ne!(bytes, admit_listen_signing_bytes(relay, session, ts(4)));
        // Swapping relay and session differs too.
        assert_ne!(bytes, admit_listen_signing_bytes(session, relay, ts(3)));
    }

    #[test]
    fn listen_proof_verifies_only_for_its_relay_session_and_timestamp() {
        let key = SigningKey::from_bytes(&[8u8; 32]);
        let network = NetworkId::from([1u8; 32]);
        let relay = NodeId::from([1u8; 32]);
        let session = NodeId::from([2u8; 32]);
        let body = AdmitListenBody::sign(network, &key, relay, session, ts(3));
        assert_eq!(body.signer.0, key.verifying_key().to_bytes());
        body.verify(relay, session, ts(3)).unwrap();
        assert!(
            body.verify(NodeId::from([9u8; 32]), session, ts(3))
                .is_err()
        );
        assert!(body.verify(relay, NodeId::from([9u8; 32]), ts(3)).is_err());
        assert!(body.verify(relay, session, ts(4)).is_err());
        // A different signer key with the same signature fails.
        let mut other = body.clone();
        other.signer = ByteArray::from(
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(other.verify(relay, session, ts(3)).is_err());
        // A flipped signature bit fails.
        let mut flipped = body.clone();
        flipped.sig.0[0] ^= 1;
        assert!(flipped.verify(relay, session, ts(3)).is_err());
    }

    #[test]
    fn admit_listen_and_refused_round_trip_and_refuse_bad_shapes() {
        let listen = AdmitListenBody {
            network_id: NetworkId::from([1u8; 32]),
            signer: ByteArray::from([2u8; 32]),
            sig: ByteArray::from([3u8; 64]),
        };
        let buf = cbor(&listen);
        assert_eq!(buf[0], 0xa3);
        assert_eq!(decode_strict::<AdmitListenBody>(&buf).unwrap(), listen);
        // Unknown key.
        let mut extra = buf.clone();
        extra[0] = 0xa4;
        extra.extend_from_slice(&cbor(&"x"));
        extra.extend_from_slice(&cbor(&1u8));
        assert!(decode_strict::<AdmitListenBody>(&extra).is_err());
        // Wrong lengths: a 31 byte signer, a 63 byte signature.
        #[derive(Serialize)]
        struct Raw<'a> {
            network_id: NetworkId,
            #[serde(with = "serde_bytes_like")]
            signer: &'a [u8],
            #[serde(with = "serde_bytes_like")]
            sig: &'a [u8],
        }
        mod serde_bytes_like {
            pub fn serialize<S: serde::Serializer>(v: &&[u8], s: S) -> Result<S::Ok, S::Error> {
                s.serialize_bytes(v)
            }
        }
        let short_signer = Raw {
            network_id: NetworkId::from([1u8; 32]),
            signer: &[2u8; 31],
            sig: &[3u8; 64],
        };
        assert!(decode_strict::<AdmitListenBody>(&cbor(&short_signer)).is_err());
        let short_sig = Raw {
            network_id: NetworkId::from([1u8; 32]),
            signer: &[2u8; 32],
            sig: &[3u8; 63],
        };
        assert!(decode_strict::<AdmitListenBody>(&cbor(&short_sig)).is_err());
        let good_raw = Raw {
            network_id: NetworkId::from([1u8; 32]),
            signer: &[2u8; 32],
            sig: &[3u8; 64],
        };
        assert_eq!(
            decode_strict::<AdmitListenBody>(&cbor(&good_raw)).unwrap(),
            listen
        );

        let refused = AdmitRefusedBody {
            invite_id: InviteId::from([4u8; 16]),
            node_id: NodeId::from([5u8; 32]),
            code: ErrorCode::NameTaken,
        };
        let buf = cbor(&refused);
        assert_eq!(buf[0], 0xa3);
        assert_eq!(decode_strict::<AdmitRefusedBody>(&buf).unwrap(), refused);
        // The code is a plain number: 30.
        let code_entry = [&[0x64u8][..], b"code", &[0x18, 30]].concat();
        assert!(buf.windows(code_entry.len()).any(|w| w == code_entry));
        let mut extra = buf.clone();
        extra[0] = 0xa4;
        extra.extend_from_slice(&cbor(&"x"));
        extra.extend_from_slice(&cbor(&1u8));
        assert!(decode_strict::<AdmitRefusedBody>(&extra).is_err());
        // Missing key.
        let missing = [
            &[0xa2, 0x69][..],
            b"invite_id",
            &[0x50],
            &[4u8; 16],
            &[0x67],
            b"node_id",
            &[0x58, 32],
            &[5u8; 32],
        ]
        .concat();
        assert!(decode_strict::<AdmitRefusedBody>(&missing).is_err());
    }

    #[test]
    fn the_new_records_dispatch_by_their_type_bytes() {
        let listen = Record::AdmitListen(AdmitListenBody {
            network_id: NetworkId::from([1u8; 32]),
            signer: ByteArray::from([2u8; 32]),
            sig: ByteArray::from([3u8; 64]),
        });
        let refused = Record::AdmitRefused(AdmitRefusedBody {
            invite_id: InviteId::from([4u8; 16]),
            node_id: NodeId::from([5u8; 32]),
            code: ErrorCode::BadInvite,
        });
        assert_eq!(listen.encode()[0], 0x10);
        assert_eq!(refused.encode()[0], 0x11);
        assert_eq!(Record::decode(&listen.encode()).unwrap(), listen);
        assert_eq!(Record::decode(&refused.encode()).unwrap(), refused);
        assert_eq!(RecordType::try_from(0x10).unwrap(), RecordType::AdmitListen);
        assert_eq!(
            RecordType::try_from(0x11).unwrap(),
            RecordType::AdmitRefused
        );
        assert!(matches!(
            RecordType::try_from(0x12),
            Err(ProtoError::UnknownRecordType(0x12))
        ));
        // A body of the wrong record type is refused, not reinterpreted.
        let mut crossed = refused.encode();
        crossed[0] = 0x10;
        assert!(Record::decode(&crossed).is_err());
    }
}
