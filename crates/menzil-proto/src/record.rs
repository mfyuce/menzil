//! L3 relay session records (protocol.md 4.2): `u8 type | body`.
//!
//! Only some rows carry a CBOR body (protocol.md marks those explicitly,
//! e.g. "CBOR (4.4)" or `CBOR{...}`); the rest (ATTACH, SEND, RECV, PING,
//! PONG, REKEY, DOC) are a fixed concatenation of raw fields, exactly as
//! written in the section 4.2 table, and are encoded/decoded by hand
//! here rather than through serde. protocol.md does not state a byte
//! order for those raw multi-byte integers (DOC's `index`/`count`); this
//! module uses big-endian throughout, the conventional choice for a wire
//! protocol that does not say otherwise.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bytes::{DocId, NodeId};
use crate::error::{ErrorCode, ProtoError};
use crate::invite::{AdmitPendingBody, AdmitRequestBody};
use crate::network::{Policy, Roster};
use crate::service::ServiceId;
use crate::strict;

/// The `type` byte from protocol.md 4.2's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// `ATTACH`: node to relay, empty body, makes the session routable.
    Attach = 0x00,
    /// `SEND`: node to relay.
    Send = 0x01,
    /// `RECV`: relay to node.
    Recv = 0x02,
    /// `ADVERTISE`: node to relay, CBOR (protocol.md 4.4).
    Advertise = 0x03,
    /// `ADVERTISE_ACK`: relay to node, CBOR.
    AdvertiseAck = 0x04,
    /// `DOC`: both directions.
    Doc = 0x05,
    /// `PEER_STATE`: relay to node, CBOR.
    PeerState = 0x06,
    /// `CREDIT`: relay to node, CBOR.
    Credit = 0x07,
    /// `PING`: both directions.
    Ping = 0x08,
    /// `PONG`: both directions.
    Pong = 0x09,
    /// `REKEY`: both directions, empty body.
    Rekey = 0x0a,
    /// `ADMIT_REQUEST`: node to relay, CBOR (protocol.md 7.2).
    AdmitRequest = 0x0b,
    /// `ADMIT_PENDING`: relay to steward node, CBOR.
    AdmitPending = 0x0c,
    /// `ADMIT_RESULT`: relay to node, CBOR.
    AdmitResult = 0x0d,
    /// `ERROR`: both directions, CBOR.
    Error = 0x0e,
    /// `GOAWAY`: relay to node, CBOR.
    Goaway = 0x0f,
}

impl TryFrom<u8> for RecordType {
    type Error = ProtoError;

    // `Result<Self, Self::Error>` is ambiguous here: RecordType has its own
    // `Error` variant, and Rust cannot tell that apart from the associated
    // type of the same name. Spelling out `ProtoError` sidesteps it.
    fn try_from(value: u8) -> Result<Self, ProtoError> {
        match value {
            0x00 => Ok(Self::Attach),
            0x01 => Ok(Self::Send),
            0x02 => Ok(Self::Recv),
            0x03 => Ok(Self::Advertise),
            0x04 => Ok(Self::AdvertiseAck),
            0x05 => Ok(Self::Doc),
            0x06 => Ok(Self::PeerState),
            0x07 => Ok(Self::Credit),
            0x08 => Ok(Self::Ping),
            0x09 => Ok(Self::Pong),
            0x0a => Ok(Self::Rekey),
            0x0b => Ok(Self::AdmitRequest),
            0x0c => Ok(Self::AdmitPending),
            0x0d => Ok(Self::AdmitResult),
            0x0e => Ok(Self::Error),
            0x0f => Ok(Self::Goaway),
            // Per protocol.md section 9: "Unknown L3 record types produce
            // ERROR unknown_type without closing the session." This
            // distinguishes that case for the caller; sending the ERROR
            // record back is a session-level concern, not this crate's.
            other => Err(ProtoError::UnknownRecordType(other)),
        }
    }
}

/// `mode: "blind" | "terminated"` (protocol.md 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareMode {
    /// The relay never sees the plaintext.
    Blind,
    /// The relay terminates TLS and HTTP for this share.
    Terminated,
}

impl ShareMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blind => "blind",
            Self::Terminated => "terminated",
        }
    }
}

impl Serialize for ShareMode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ShareMode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "blind" => Ok(Self::Blind),
            "terminated" => Ok(Self::Terminated),
            other => Err(serde::de::Error::custom(format!(
                "unknown share mode {other:?}"
            ))),
        }
    }
}

/// One entry of [`AdvertiseBody`]'s `shares` list (protocol.md 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Share {
    /// The public name being advertised.
    pub name: String,
    /// Blind or terminated.
    pub mode: ShareMode,
    /// The local service this name routes to.
    pub service: ServiceId,
    /// ALPN protocol ids this node terminates for a blind name; empty
    /// means any (protocol.md 4.4). Ignored for terminated shares.
    pub alpn: Vec<String>,
}

/// `ADVERTISE = CBOR{ v: 1, shares: [...], accept_peers: bool }`
/// (protocol.md 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertiseBody {
    /// Document schema version.
    pub v: u16,
    /// Names this node asks the relay to route to it.
    pub shares: Vec<Share>,
    /// Whether this node accepts peer (non-relay-principal) streams.
    pub accept_peers: bool,
}

/// One rejected entry of an [`AdvertiseAckBody`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedShare {
    /// The name that was rejected.
    pub name: String,
    /// Why, as free text.
    pub reason: String,
}

/// `ADVERTISE_ACK = CBOR{ accepted: [str], rejected: [{name, reason}] }`
/// (protocol.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertiseAckBody {
    /// Names accepted as advertised.
    pub accepted: Vec<String>,
    /// Names rejected, with a reason each.
    pub rejected: Vec<RejectedShare>,
}

/// `doc_type` for a [`DocBody`]. protocol.md leaves the numeric mapping
/// to this crate's registry, the same way it does for [`ErrorCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DocType {
    /// The document is a [`Roster`].
    Roster = 0,
    /// The document is a [`Policy`].
    Policy = 1,
}

impl TryFrom<u8> for DocType {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Roster),
            1 => Ok(Self::Policy),
            other => Err(ProtoError::MalformedRecord(format!(
                "unknown DOC doc_type {other}"
            ))),
        }
    }
}

/// `DOC = u8 doc_type | bytes16 doc_id | u16 index | u16 count | chunk`
/// (protocol.md 4.2): one chunk of a chunked Roster or Policy transfer.
/// `chunk` is a raw byte slice of the document's own encoded bytes;
/// reassembling and CBOR-decoding it into a [`Roster`]/[`Policy`] happens
/// above this crate, once every chunk for a `doc_id` has arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocBody {
    /// Which document type this chunk belongs to.
    pub doc_type: DocType,
    /// Correlates chunks of the same transfer.
    pub doc_id: DocId,
    /// This chunk's position, zero-based.
    pub index: u16,
    /// Total chunk count for this transfer.
    pub count: u16,
    /// This chunk's raw bytes.
    pub chunk: Vec<u8>,
}

/// `PEER_STATE = CBOR{ node_id, online: bool, direct: [Addr] }`
/// (protocol.md 4.2). `direct` is always empty in phase 1 (protocol.md
/// 13 marks direct addresses as a phase 3 feature); [`Addr`] exists only
/// to give the field a concrete, minimal shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerStateBody {
    /// Which node this is about.
    pub node_id: NodeId,
    /// Whether it is currently attached.
    pub online: bool,
    /// Direct (non-relayed) addresses; unused in phase 1.
    pub direct: Vec<Addr>,
}

/// A minimal placeholder address shape for [`PeerStateBody::direct`],
/// unused until the phase 3 direct path exists (protocol.md 13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Addr {
    /// Host, as a literal address or name.
    pub host: String,
    /// Port.
    pub port: u16,
}

/// `CREDIT = CBOR{ peer: node_id, bytes: u32 }` (protocol.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditBody {
    /// Which peer this credit grant is for.
    pub peer: NodeId,
    /// How many additional bytes may be sent to that peer.
    pub bytes: u32,
}

/// `ADMIT_RESULT` (protocol.md 4.2, 7.2): either freshly issued
/// documents, or a pending marker while the steward is unreachable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AdmitResult {
    /// `{ roster: Roster, policy: Policy }`
    Granted {
        /// The redeemer's new roster.
        roster: Roster,
        /// The redeemer's new policy.
        policy: Policy,
    },
    /// `{ pending: true }`
    Pending {
        /// Always `true` on the wire; use [`AdmitResult::pending`] rather
        /// than constructing this directly.
        pending: bool,
    },
}

impl AdmitResult {
    /// Builds the `{ pending: true }` form.
    pub fn pending() -> Self {
        Self::Pending { pending: true }
    }
}

/// `ERROR = CBOR{ code: u16, msg: str }` (protocol.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The registry code (see [`ErrorCode`]).
    pub code: ErrorCode,
    /// Free-text detail.
    pub msg: String,
}

/// `GOAWAY = CBOR{ reason: str, retry_after_ms: u32 }` (protocol.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoawayBody {
    /// Why the session is ending.
    pub reason: String,
    /// How long to wait before reconnecting.
    pub retry_after_ms: u32,
}

/// One L3 record: the `u8 type` byte plus its body (protocol.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// See [`RecordType::Attach`].
    Attach,
    /// See [`RecordType::Send`].
    Send {
        /// Destination node.
        dst: NodeId,
        /// Which L4 protocol `payload` belongs to.
        e2e_proto: u8,
        /// Bit 0 = droppable (datagram class); protocol.md 4.2.
        flags: u8,
        /// Opaque L4 bytes; the relay never inspects this.
        payload: Vec<u8>,
    },
    /// See [`RecordType::Recv`].
    Recv {
        /// Source node.
        src: NodeId,
        /// Which L4 protocol `payload` belongs to.
        e2e_proto: u8,
        /// Bit 0 = droppable (datagram class); protocol.md 4.2.
        flags: u8,
        /// Opaque L4 bytes; the relay never inspects this.
        payload: Vec<u8>,
    },
    /// See [`RecordType::Advertise`].
    Advertise(AdvertiseBody),
    /// See [`RecordType::AdvertiseAck`].
    AdvertiseAck(AdvertiseAckBody),
    /// See [`RecordType::Doc`].
    Doc(DocBody),
    /// See [`RecordType::PeerState`].
    PeerState(PeerStateBody),
    /// See [`RecordType::Credit`].
    Credit(CreditBody),
    /// See [`RecordType::Ping`].
    Ping {
        /// Echoed back unchanged in the matching PONG.
        nonce: [u8; 8],
    },
    /// See [`RecordType::Pong`].
    Pong {
        /// The nonce from the PING this answers.
        nonce: [u8; 8],
    },
    /// See [`RecordType::Rekey`].
    Rekey,
    /// See [`RecordType::AdmitRequest`].
    AdmitRequest(AdmitRequestBody),
    /// See [`RecordType::AdmitPending`].
    AdmitPending(AdmitPendingBody),
    /// See [`RecordType::AdmitResult`].
    AdmitResult(AdmitResult),
    /// See [`RecordType::Error`].
    Error(ErrorBody),
    /// See [`RecordType::Goaway`].
    Goaway(GoawayBody),
}

fn encode_cbor_body<T: Serialize>(record_type: RecordType, body: &T) -> Vec<u8> {
    let mut buf = vec![record_type as u8];
    ciborium::into_writer(body, &mut buf).expect("CBOR encoding into a Vec<u8> writer cannot fail");
    buf
}

fn decode_cbor_body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    strict::check_definite_lengths(bytes)?;
    ciborium::from_reader(bytes).map_err(|e| ProtoError::Decode(e.to_string()))
}

/// Length of the raw `bytes32 node_id | u8 e2e_proto | u8 flags` prefix
/// shared by SEND and RECV, before the opaque payload.
const SEND_RECV_PREFIX_LEN: usize = 32 + 1 + 1;

fn encode_send_recv(
    record_type: RecordType,
    node_id: &NodeId,
    e2e_proto: u8,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + SEND_RECV_PREFIX_LEN + payload.len());
    buf.push(record_type as u8);
    buf.extend_from_slice(node_id.as_ref());
    buf.push(e2e_proto);
    buf.push(flags);
    buf.extend_from_slice(payload);
    buf
}

fn decode_send_recv(bytes: &[u8]) -> Result<(NodeId, u8, u8, Vec<u8>), ProtoError> {
    if bytes.len() < SEND_RECV_PREFIX_LEN {
        return Err(ProtoError::MalformedRecord(format!(
            "SEND/RECV body shorter than its {SEND_RECV_PREFIX_LEN}-byte prefix"
        )));
    }
    let node_id =
        NodeId::from(<[u8; 32]>::try_from(&bytes[0..32]).expect("slice is exactly 32 bytes"));
    let e2e_proto = bytes[32];
    let flags = bytes[33];
    let payload = bytes[SEND_RECV_PREFIX_LEN..].to_vec();
    Ok((node_id, e2e_proto, flags, payload))
}

const DOC_HEADER_LEN: usize = 1 + 16 + 2 + 2;

fn require_empty(bytes: &[u8], what: &str) -> Result<(), ProtoError> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(ProtoError::MalformedRecord(format!(
            "{what} must have an empty body, got {} bytes",
            bytes.len()
        )))
    }
}

impl Record {
    /// Encodes this record as `u8 type | body`, per protocol.md 4.2.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Attach => vec![RecordType::Attach as u8],
            Self::Send {
                dst,
                e2e_proto,
                flags,
                payload,
            } => encode_send_recv(RecordType::Send, dst, *e2e_proto, *flags, payload),
            Self::Recv {
                src,
                e2e_proto,
                flags,
                payload,
            } => encode_send_recv(RecordType::Recv, src, *e2e_proto, *flags, payload),
            Self::Advertise(body) => encode_cbor_body(RecordType::Advertise, body),
            Self::AdvertiseAck(body) => encode_cbor_body(RecordType::AdvertiseAck, body),
            Self::Doc(body) => {
                let mut buf = Vec::with_capacity(1 + DOC_HEADER_LEN + body.chunk.len());
                buf.push(RecordType::Doc as u8);
                buf.push(body.doc_type as u8);
                buf.extend_from_slice(body.doc_id.as_ref());
                buf.extend_from_slice(&body.index.to_be_bytes());
                buf.extend_from_slice(&body.count.to_be_bytes());
                buf.extend_from_slice(&body.chunk);
                buf
            }
            Self::PeerState(body) => encode_cbor_body(RecordType::PeerState, body),
            Self::Credit(body) => encode_cbor_body(RecordType::Credit, body),
            Self::Ping { nonce } => {
                let mut buf = vec![RecordType::Ping as u8];
                buf.extend_from_slice(nonce);
                buf
            }
            Self::Pong { nonce } => {
                let mut buf = vec![RecordType::Pong as u8];
                buf.extend_from_slice(nonce);
                buf
            }
            Self::Rekey => vec![RecordType::Rekey as u8],
            Self::AdmitRequest(body) => encode_cbor_body(RecordType::AdmitRequest, body),
            Self::AdmitPending(body) => encode_cbor_body(RecordType::AdmitPending, body),
            Self::AdmitResult(body) => encode_cbor_body(RecordType::AdmitResult, body),
            Self::Error(body) => encode_cbor_body(RecordType::Error, body),
            Self::Goaway(body) => encode_cbor_body(RecordType::Goaway, body),
        }
    }

    /// Decodes a record from `u8 type | body`. An unrecognized type byte
    /// is [`ProtoError::UnknownRecordType`], which a caller maps to
    /// sending back ERROR `unknown_type` (protocol.md section 9) at the
    /// session layer; this crate only makes the failure distinguishable.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let (&type_byte, rest) = bytes
            .split_first()
            .ok_or_else(|| ProtoError::MalformedRecord("empty record".to_string()))?;
        match RecordType::try_from(type_byte)? {
            RecordType::Attach => {
                require_empty(rest, "ATTACH")?;
                Ok(Self::Attach)
            }
            RecordType::Send => {
                let (dst, e2e_proto, flags, payload) = decode_send_recv(rest)?;
                Ok(Self::Send {
                    dst,
                    e2e_proto,
                    flags,
                    payload,
                })
            }
            RecordType::Recv => {
                let (src, e2e_proto, flags, payload) = decode_send_recv(rest)?;
                Ok(Self::Recv {
                    src,
                    e2e_proto,
                    flags,
                    payload,
                })
            }
            RecordType::Advertise => Ok(Self::Advertise(decode_cbor_body(rest)?)),
            RecordType::AdvertiseAck => Ok(Self::AdvertiseAck(decode_cbor_body(rest)?)),
            RecordType::Doc => {
                if rest.len() < DOC_HEADER_LEN {
                    return Err(ProtoError::MalformedRecord(format!(
                        "DOC body shorter than its {DOC_HEADER_LEN}-byte header"
                    )));
                }
                let doc_type = DocType::try_from(rest[0])?;
                let doc_id = DocId::from(
                    <[u8; 16]>::try_from(&rest[1..17]).expect("slice is exactly 16 bytes"),
                );
                let index = u16::from_be_bytes([rest[17], rest[18]]);
                let count = u16::from_be_bytes([rest[19], rest[20]]);
                let chunk = rest[DOC_HEADER_LEN..].to_vec();
                Ok(Self::Doc(DocBody {
                    doc_type,
                    doc_id,
                    index,
                    count,
                    chunk,
                }))
            }
            RecordType::PeerState => Ok(Self::PeerState(decode_cbor_body(rest)?)),
            RecordType::Credit => Ok(Self::Credit(decode_cbor_body(rest)?)),
            RecordType::Ping => Ok(Self::Ping {
                nonce: <[u8; 8]>::try_from(rest).map_err(|_| {
                    ProtoError::MalformedRecord("PING nonce must be 8 bytes".to_string())
                })?,
            }),
            RecordType::Pong => Ok(Self::Pong {
                nonce: <[u8; 8]>::try_from(rest).map_err(|_| {
                    ProtoError::MalformedRecord("PONG nonce must be 8 bytes".to_string())
                })?,
            }),
            RecordType::Rekey => {
                require_empty(rest, "REKEY")?;
                Ok(Self::Rekey)
            }
            RecordType::AdmitRequest => Ok(Self::AdmitRequest(decode_cbor_body(rest)?)),
            RecordType::AdmitPending => Ok(Self::AdmitPending(decode_cbor_body(rest)?)),
            RecordType::AdmitResult => Ok(Self::AdmitResult(decode_cbor_body(rest)?)),
            RecordType::Error => Ok(Self::Error(decode_cbor_body(rest)?)),
            RecordType::Goaway => Ok(Self::Goaway(decode_cbor_body(rest)?)),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Attach => "ATTACH",
            Self::Send => "SEND",
            Self::Recv => "RECV",
            Self::Advertise => "ADVERTISE",
            Self::AdvertiseAck => "ADVERTISE_ACK",
            Self::Doc => "DOC",
            Self::PeerState => "PEER_STATE",
            Self::Credit => "CREDIT",
            Self::Ping => "PING",
            Self::Pong => "PONG",
            Self::Rekey => "REKEY",
            Self::AdmitRequest => "ADMIT_REQUEST",
            Self::AdmitPending => "ADMIT_PENDING",
            Self::AdmitResult => "ADMIT_RESULT",
            Self::Error => "ERROR",
            Self::Goaway => "GOAWAY",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{InviteId, NetworkId, SecretHash, X25519PublicKey};
    use crate::identity::{NodeCert, NodeCertBody};
    use crate::invite::{AdmitRequestBody, hash_invite_secret};
    use crate::invite::{Invite, InviteBody};
    use crate::network::{PolicyBody, RosterBody};
    use ed25519_dalek::SigningKey;

    fn sample_node_cert() -> NodeCert {
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

    fn sample_invite() -> Invite {
        let key = SigningKey::generate(&mut rand::rng());
        let body = InviteBody {
            v: crate::PROTOCOL_VERSION,
            network_id: NetworkId::from([3u8; 32]),
            invite_id: InviteId::from([4u8; 16]),
            secret_hash: SecretHash::from([5u8; 32]),
            roles: vec![],
            expires: 1_000_000_000,
            uses: 1,
        };
        Invite::sign(&key, &body).unwrap()
    }

    fn sample_roster() -> Roster {
        let key = SigningKey::generate(&mut rand::rng());
        let body = RosterBody {
            v: crate::PROTOCOL_VERSION,
            network_id: NetworkId::from([6u8; 32]),
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(&key, &body).unwrap()
    }

    fn sample_policy() -> Policy {
        let key = SigningKey::generate(&mut rand::rng());
        let body = PolicyBody {
            v: crate::PROTOCOL_VERSION,
            network_id: NetworkId::from([7u8; 32]),
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![],
            certs: vec![],
            grants: vec![],
            egress: vec![],
            accept: vec![],
        };
        Policy::sign(&key, &body).unwrap()
    }

    fn all_sample_records() -> Vec<Record> {
        vec![
            Record::Attach,
            Record::Send {
                dst: NodeId::from([1u8; 32]),
                e2e_proto: 0x01,
                flags: 0,
                payload: vec![1, 2, 3],
            },
            Record::Recv {
                src: NodeId::from([2u8; 32]),
                e2e_proto: 0x01,
                flags: 1,
                payload: vec![],
            },
            Record::Advertise(AdvertiseBody {
                v: crate::PROTOCOL_VERSION,
                shares: vec![Share {
                    name: "example".to_string(),
                    mode: ShareMode::Blind,
                    service: "tcp:ssh".parse().unwrap(),
                    alpn: vec!["h2".to_string()],
                }],
                accept_peers: true,
            }),
            Record::AdvertiseAck(AdvertiseAckBody {
                accepted: vec!["example".to_string()],
                rejected: vec![RejectedShare {
                    name: "taken".to_string(),
                    reason: "label_taken".to_string(),
                }],
            }),
            Record::Doc(DocBody {
                doc_type: DocType::Roster,
                doc_id: DocId::from([9u8; 16]),
                index: 0,
                count: 1,
                chunk: vec![0xaa, 0xbb],
            }),
            Record::PeerState(PeerStateBody {
                node_id: NodeId::from([3u8; 32]),
                online: true,
                direct: vec![],
            }),
            Record::Credit(CreditBody {
                peer: NodeId::from([4u8; 32]),
                bytes: 1_048_576,
            }),
            Record::Ping { nonce: [1; 8] },
            Record::Pong { nonce: [2; 8] },
            Record::Rekey,
            Record::AdmitRequest(AdmitRequestBody {
                invite: sample_invite(),
                node_cert: sample_node_cert(),
                tag: crate::bytes::ByteArray::from(<[u8; 32]>::from(hash_invite_secret(
                    b"whatever",
                ))),
            }),
            Record::AdmitPending(AdmitRequestBody {
                invite: sample_invite(),
                node_cert: sample_node_cert(),
                tag: crate::bytes::ByteArray::from([0u8; 32]),
            }),
            Record::AdmitResult(AdmitResult::Granted {
                roster: sample_roster(),
                policy: sample_policy(),
            }),
            Record::AdmitResult(AdmitResult::pending()),
            Record::Error(ErrorBody {
                code: ErrorCode::Forbidden,
                msg: "no grant".to_string(),
            }),
            Record::Goaway(GoawayBody {
                reason: "superseded".to_string(),
                retry_after_ms: 1000,
            }),
        ]
    }

    #[test]
    fn every_record_type_round_trips() {
        for record in all_sample_records() {
            let encoded = record.encode();
            let decoded = Record::decode(&encoded).unwrap_or_else(|e| {
                panic!("failed to decode {record:?}: {e}");
            });
            assert_eq!(decoded, record, "round trip mismatch for {record:?}");
        }
    }

    #[test]
    fn unknown_type_byte_is_distinguishable() {
        let err = Record::decode(&[0xff]).unwrap_err();
        assert!(matches!(err, ProtoError::UnknownRecordType(0xff)));
    }

    #[test]
    fn attach_rejects_nonempty_body() {
        let err = Record::decode(&[RecordType::Attach as u8, 0x00]).unwrap_err();
        assert!(matches!(err, ProtoError::MalformedRecord(_)));
    }

    #[test]
    fn empty_input_is_rejected() {
        assert!(Record::decode(&[]).is_err());
    }

    #[test]
    fn doc_record_uses_big_endian_index_and_count() {
        let doc = Record::Doc(DocBody {
            doc_type: DocType::Policy,
            doc_id: DocId::from([1u8; 16]),
            index: 0x0102,
            count: 0x0304,
            chunk: vec![],
        });
        let encoded = doc.encode();
        // type(1) + doc_type(1) + doc_id(16) = 18, then index, then count.
        assert_eq!(encoded[18], 0x01);
        assert_eq!(encoded[19], 0x02);
        assert_eq!(encoded[20], 0x03);
        assert_eq!(encoded[21], 0x04);
    }
}
