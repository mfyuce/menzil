//! The Noise handshake payloads HELLO and WELCOME (protocol.md 4.1).
//!
//! These ride inside the Noise handshake messages themselves (message 1
//! for IK, message 3 for XX, carrying HELLO; message 2, carrying WELCOME)
//! rather than the section 4.2 record framing, and are not [`Signed`]:
//! `"hello"` and `"welcome"` are not among section 2.1's closed list of
//! signed `type` tags, since their authenticity comes from the Noise
//! handshake itself, not a CBOR-level signature. Like the plain record
//! bodies in [`crate::record`], they are unsigned control messages, so
//! decoding tolerates unknown keys (protocol.md 1) rather than denying
//! them the way every [`Signed`] body does. Driving the handshake itself
//! (choosing IK vs XX, the prologue, message sequencing, the checks
//! protocol.md 4.1 describes against a held Roster) is session behavior
//! and belongs to whichever crate runs it, not here.
//!
//! [`Signed`]: crate::signed::Signed

use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::{NetworkId, Tai64N};
use crate::error::ProtoError;
use crate::identity::NodeCert;
use crate::strict;

fn encode_body<T: Serialize>(body: &T) -> Result<Vec<u8>, ProtoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(body, &mut buf).map_err(|e| ProtoError::Encode(e.to_string()))?;
    Ok(buf)
}

fn decode_body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    strict::check_definite_lengths(bytes)?;
    ciborium::from_reader(bytes).map_err(|e| ProtoError::Decode(e.to_string()))
}

/// A capability string from the registry in `menzil-proto` (protocol.md
/// 4.1): `"dgram"` (the node accepts datagram channels), `"docs"` (the
/// node serves `menzil:docs`), `"share-blind"` and `"share-terminated"`
/// (the node can host shares of that mode). "Unknown strings are
/// ignored": `Unknown` preserves one verbatim rather than failing to
/// decode it, the same tolerance [`crate::ErrorCode::Unknown`] gives an
/// unrecognized error code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// The node accepts datagram channels (protocol.md 5.4).
    Dgram,
    /// The node serves `menzil:docs` (protocol.md 5.5).
    Docs,
    /// The node can host a blind-mode public share (protocol.md 6.2).
    ShareBlind,
    /// The node can host a terminated-mode public share (protocol.md
    /// 6.3).
    ShareTerminated,
    /// A capability string this build does not recognize, preserved
    /// verbatim.
    Unknown(String),
}

impl Capability {
    /// The literal wire string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Dgram => "dgram",
            Self::Docs => "docs",
            Self::ShareBlind => "share-blind",
            Self::ShareTerminated => "share-terminated",
            Self::Unknown(s) => s,
        }
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "dgram" => Self::Dgram,
            "docs" => Self::Docs,
            "share-blind" => Self::ShareBlind,
            "share-terminated" => Self::ShareTerminated,
            _ => Self::Unknown(s),
        })
    }
}

/// `limits` (WELCOME, protocol.md 4.1): per-session ceilings the relay
/// states at handshake time. Defaults live in protocol.md 10, not here:
/// this type only carries whatever numbers a given relay actually sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum L3 record payload size, bytes.
    pub max_record: u32,
    /// Maximum concurrent peers this node may reach through this relay.
    pub max_peers: u32,
    /// Initial credit per peer, bytes (protocol.md 4.2).
    pub credit: u32,
}

/// ```text
/// HELLO (node -> relay) final handshake message from the node carries
///     CBOR{ v: 1, node_cert: NodeCert, networks: [NetworkId], timestamp: bytes12 (TAI64N),
///           roster_seq: { NetworkId: u64 }, caps: [str], e2e_protos: [u8] }
/// ```
/// (protocol.md 4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloBody {
    /// Document schema version.
    pub v: u16,
    /// The sending node's certificate.
    pub node_cert: NodeCert,
    /// Networks this node claims membership in; empty to redeem an
    /// invite only (protocol.md 4.1).
    pub networks: Vec<NetworkId>,
    /// Strictly greater than the last timestamp this relay accepted from
    /// this node id (protocol.md 4.1) — replay defense, not a claim of
    /// exact wall-clock accuracy; see [`Tai64N`]'s docs.
    pub timestamp: Tai64N,
    /// The newest Roster `seq` this node already holds, per network, so
    /// the relay knows whether to push a newer one (protocol.md 4.3).
    pub roster_seq: HashMap<NetworkId, u64>,
    /// Capabilities this node offers.
    pub caps: Vec<Capability>,
    /// `e2e_proto` tags this node supports (protocol.md 4.2, 9).
    pub e2e_protos: Vec<u8>,
}

impl HelloBody {
    /// Encodes this payload for embedding in the Noise handshake message
    /// (definite-length CBOR; see [`crate::signed::Signed::sign`]'s docs
    /// for why ciborium's serializer already guarantees that).
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        encode_body(self)
    }

    /// Strictly decodes a HELLO payload out of a Noise handshake message:
    /// the same definite-length check every CBOR body in this crate gets,
    /// but tolerating unknown keys (protocol.md 1), since HELLO is an
    /// unsigned control message, not a [`crate::signed::Signed`] body.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        decode_body(bytes)
    }
}

/// ```text
/// WELCOME (relay -> node) final handshake message from the relay carries
///     CBOR{ v: 1, relay_cert: NodeCert, session: u32, time: u64,
///           limits: { max_record: u32, max_peers: u32, credit: u32 }, rosters: { NetworkId: u64 } }
/// ```
/// (protocol.md 4.1). protocol.md 9 says the supported `e2e_proto` tags
/// are bound into "both handshake payloads", but this literal WELCOME
/// shape has no `e2e_protos` field — a real inconsistency between
/// sections 4.1 and 9 that this type does not silently resolve either
/// way; it follows 4.1's literal shape, the one that actually enumerates
/// WELCOME's fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WelcomeBody {
    /// Document schema version.
    pub v: u16,
    /// The relay's certificate.
    pub relay_cert: NodeCert,
    /// The relay's identifier for this session. protocol.md 4.1 states
    /// the field but not its further use; nothing here presumes one.
    pub session: u32,
    /// Informational only; never extends any document's validity
    /// (protocol.md 4.1).
    pub time: u64,
    /// Per-session ceilings.
    pub limits: Limits,
    /// This relay's current Roster `seq` per network, so the node knows
    /// whether to push a newer one (protocol.md 4.3).
    pub rosters: HashMap<NetworkId, u64>,
}

impl WelcomeBody {
    /// Encodes this payload for embedding in the Noise handshake message.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        encode_body(self)
    }

    /// Strictly decodes a WELCOME payload; see [`HelloBody::decode`]'s
    /// docs for the same unknown-key tolerance and why.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        decode_body(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{ByteArray, NodeId, X25519PublicKey};
    use crate::identity::NodeCertBody;
    use ed25519_dalek::SigningKey;
    use serde::Serialize as SerdeSerialize;

    fn sample_cert() -> NodeCert {
        let key = SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: crate::PROTOCOL_VERSION,
            node_id: NodeId::from([1u8; 32]),
            x25519_pub: X25519PublicKey::from([2u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }

    fn sample_hello() -> HelloBody {
        let mut roster_seq = HashMap::new();
        roster_seq.insert(NetworkId::from([9u8; 32]), 3u64);
        HelloBody {
            v: crate::PROTOCOL_VERSION,
            node_cert: sample_cert(),
            networks: vec![NetworkId::from([9u8; 32])],
            timestamp: Tai64N::from([7u8; 12]),
            roster_seq,
            caps: vec![
                Capability::Dgram,
                Capability::Unknown("future-cap".to_string()),
            ],
            e2e_protos: vec![0x01],
        }
    }

    #[test]
    fn hello_round_trips_with_networks_caps_and_roster_seq() {
        let hello = sample_hello();
        let encoded = hello.encode().unwrap();
        let decoded = HelloBody::decode(&encoded).unwrap();
        assert_eq!(decoded, hello);
    }

    #[test]
    fn welcome_round_trips() {
        let mut rosters = HashMap::new();
        rosters.insert(NetworkId::from([9u8; 32]), 5u64);
        let welcome = WelcomeBody {
            v: crate::PROTOCOL_VERSION,
            relay_cert: sample_cert(),
            session: 42,
            time: 1_700_000_000,
            limits: Limits {
                max_record: 65_535,
                max_peers: 100,
                credit: 1_048_576,
            },
            rosters,
        };
        let encoded = welcome.encode().unwrap();
        let decoded = WelcomeBody::decode(&encoded).unwrap();
        assert_eq!(decoded, welcome);
    }

    #[test]
    fn hello_tolerates_an_unknown_key_unlike_a_signed_body() {
        // Shaped like HelloBody but with one extra key, hand-encoded
        // since HelloBody itself can't produce this shape.
        #[derive(SerdeSerialize)]
        struct HelloPlusExtra {
            v: u16,
            node_cert: NodeCert,
            networks: Vec<NetworkId>,
            timestamp: Tai64N,
            roster_seq: HashMap<NetworkId, u64>,
            caps: Vec<Capability>,
            e2e_protos: Vec<u8>,
            from_a_future_version: bool,
        }
        let hello = sample_hello();
        let with_extra = HelloPlusExtra {
            v: hello.v,
            node_cert: hello.node_cert.clone(),
            networks: hello.networks.clone(),
            timestamp: hello.timestamp,
            roster_seq: hello.roster_seq.clone(),
            caps: hello.caps.clone(),
            e2e_protos: hello.e2e_protos.clone(),
            from_a_future_version: true,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&with_extra, &mut buf).unwrap();

        let decoded = HelloBody::decode(&buf).unwrap();
        assert_eq!(decoded, hello);
    }

    #[test]
    fn capability_unknown_string_round_trips() {
        let mut buf = Vec::new();
        ciborium::into_writer(&"a-future-capability", &mut buf).unwrap();
        let decoded: Capability = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(
            decoded,
            Capability::Unknown("a-future-capability".to_string())
        );
        assert_eq!(decoded.as_str(), "a-future-capability");
    }

    #[test]
    fn capability_named_variants_round_trip() {
        for cap in [
            Capability::Dgram,
            Capability::Docs,
            Capability::ShareBlind,
            Capability::ShareTerminated,
        ] {
            let mut buf = Vec::new();
            ciborium::into_writer(&cap, &mut buf).unwrap();
            let decoded: Capability = ciborium::from_reader(&buf[..]).unwrap();
            assert_eq!(decoded, cap);
        }
    }

    #[test]
    fn hello_decode_rejects_indefinite_length() {
        // Reuses the same raw-bytes strictness contract every other CBOR
        // body in this crate gets (see crate::strict's own tests for the
        // byte-level construction); here it's enough to confirm HELLO's
        // decode path actually calls it: an indefinite-length outer map
        // (0xbf ... 0xff) must be rejected before serde ever sees it.
        let bytes = [0xbfu8, 0xff];
        assert!(HelloBody::decode(&bytes).is_err());
    }

    #[test]
    fn tai64n_encodes_as_a_twelve_byte_cbor_string() {
        let ts = Tai64N::from([1u8; 12]);
        let mut buf = Vec::new();
        ciborium::into_writer(&ts, &mut buf).unwrap();
        let expected = {
            let mut b = Vec::new();
            ciborium::into_writer(&ByteArray::<12>([1u8; 12]), &mut b).unwrap();
            b
        };
        assert_eq!(buf, expected);
    }
}
