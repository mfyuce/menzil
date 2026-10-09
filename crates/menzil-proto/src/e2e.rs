//! L4 end to end session wire formats (protocol.md 5.1, 5.2): the
//! Noise-indexed frame headers, the handshake payload, and the plaintext
//! of a `data` frame's five record kinds.
//!
//! This is deliberately symmetric to [`crate::record`]'s treatment of L3:
//! fixed, WireGuard-style binary framing where protocol.md gives one
//! (`init`/`resp`/`data`, the five `kind | body` records), CBOR only
//! where it says so (the handshake payload, CLOSE's body). The embedded
//! Noise handshake messages and the `data` frame's `ciphertext` are
//! opaque `Vec<u8>` here, the same way [`crate::record::Record::Send`]
//! and `Recv` carry L4 bytes opaquely: running Noise itself (this crate
//! has no `snow` dependency), the reliable class's contiguity rule, the
//! datagram class's replay window, REKEY/KEEP timing, and yamux framing
//! of MUX bodies are all session behavior for TODO.md's `menzil-e2e` and
//! `menzil-stream` crates, not here.
//!
//! **A spec reading worth recording explicitly**, since it shapes
//! [`E2eHandshakePayload`]: protocol.md 5.1 gives one CBOR shape under
//! the heading "Handshake payloads" but then immediately says "There is
//! no application data in message 1." Read literally (the same way
//! [`crate::handshake::WelcomeBody`]'s own doc comment resolves a
//! similar section 4.1-vs-9 tension by following the more specific
//! sentence rather than silently picking a side), that means this type
//! is only ever encoded into `resp` (Noise message 2, responder to
//! initiator): `init` (message 1) carries a bare Noise handshake message
//! and nothing else. One consequence worth flagging for whoever builds
//! `menzil:docs` (TODO.md L4j): only the initiator receives a
//! `roster_seq`/`policy_seq` to compare against its own, so only it can
//! act on protocol.md 5.5's "the side with the older documents opens a
//! stream" by that mechanism alone; the responder finding out it is
//! behind needs either a future session where it initiates, or the
//! steward's own separate push (5.5's second sentence), not the
//! handshake comparison symmetrically. This type's own shape does not
//! resolve that; it only encodes/decodes the one CBOR body the spec
//! actually gives.

use serde::{Deserialize, Serialize};

use crate::bytes::NetworkId;
use crate::error::{ErrorCode, ProtoError};
use crate::identity::NodeCert;
use crate::record::require_empty;
use crate::strict;

/// One of the three fixed-header L4 frames (protocol.md 5.1). This is
/// what a `menzil-e2e` session encrypts/decrypts into and out of an L3
/// [`crate::record::Record::Send`]/`Recv` payload (tagged `e2e_proto`
/// `0x01`, decision 0001) — it is not itself an L3 record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E2eFrame {
    /// `init`: the initiator's Noise message 1, opening a session in
    /// `network_id` under its own freshly chosen `sender_index`.
    Init {
        /// The initiator's local index for this (still pending) session.
        sender_index: u32,
        /// The network this session's authorization is scoped to
        /// (protocol.md 5.1's prologue; the v0.2 changelog's "every
        /// authorization is scoped to one network").
        network_id: NetworkId,
        /// The raw Noise `Ik` message 1 bytes. No application payload is
        /// carried here; see this module's doc comment.
        noise_msg1: Vec<u8>,
    },
    /// `resp`: the responder's Noise message 2, completing the
    /// handshake and announcing its own local index. The two indices read
    /// the way they do in `init` and `data`: `sender_index` is the one the
    /// sender of this frame chose, `receiver_index` the one its receiver
    /// chose.
    Resp {
        /// The responder's own freshly chosen local index: what the
        /// initiator must stamp as `receiver_index` on every `data` frame
        /// it sends for this session.
        sender_index: u32,
        /// The initiator's own index, echoed back from the `init` this
        /// answers (that `init`'s `sender_index`).
        receiver_index: u32,
        /// The raw Noise `Ik` message 2 bytes, carrying
        /// [`E2eHandshakePayload`] as its payload.
        noise_msg2: Vec<u8>,
    },
    /// `data`: a post-handshake transport message in either direction.
    Data {
        /// The recipient's own local index, naming which session (and
        /// which direction of it) this decrypts against.
        receiver_index: u32,
        /// The 64 bit counter (protocol.md 5.2): top bit selects the
        /// class, see [`RecordClass`]; also the Noise transport nonce.
        counter: u64,
        /// AEAD ciphertext; decrypts to a `u8 kind | body`
        /// ([`E2eDataBody`]).
        ciphertext: Vec<u8>,
    },
}

/// The `u8` tag distinguishing [`E2eFrame`]'s three shapes (protocol.md
/// 5.1). Kept separate from `E2eFrame` itself the same way
/// [`crate::record::RecordType`] is kept separate from
/// [`crate::record::Record`]: a variant that carries fields cannot also
/// carry its own `= 0x01`-style discriminant, so the fixed tag values
/// live on this fieldless sibling instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum E2eFrameTag {
    /// See [`E2eFrame::Init`].
    Init = 0x01,
    /// See [`E2eFrame::Resp`].
    Resp = 0x02,
    /// See [`E2eFrame::Data`].
    Data = 0x03,
}

impl TryFrom<u8> for E2eFrameTag {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, ProtoError> {
        match value {
            0x01 => Ok(Self::Init),
            0x02 => Ok(Self::Resp),
            0x03 => Ok(Self::Data),
            other => Err(ProtoError::UnknownE2eFrameTag(other)),
        }
    }
}

impl E2eFrame {
    /// Encodes this frame as `u8 tag | ...`, per protocol.md 5.1.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Init {
                sender_index,
                network_id,
                noise_msg1,
            } => {
                let mut buf = Vec::with_capacity(1 + 4 + 32 + noise_msg1.len());
                buf.push(E2eFrameTag::Init as u8);
                buf.extend_from_slice(&sender_index.to_be_bytes());
                buf.extend_from_slice(network_id.as_ref());
                buf.extend_from_slice(noise_msg1);
                buf
            }
            Self::Resp {
                sender_index,
                receiver_index,
                noise_msg2,
            } => {
                let mut buf = Vec::with_capacity(1 + 4 + 4 + noise_msg2.len());
                buf.push(E2eFrameTag::Resp as u8);
                buf.extend_from_slice(&sender_index.to_be_bytes());
                buf.extend_from_slice(&receiver_index.to_be_bytes());
                buf.extend_from_slice(noise_msg2);
                buf
            }
            Self::Data {
                receiver_index,
                counter,
                ciphertext,
            } => {
                let mut buf = Vec::with_capacity(1 + 4 + 8 + ciphertext.len());
                buf.push(E2eFrameTag::Data as u8);
                buf.extend_from_slice(&receiver_index.to_be_bytes());
                buf.extend_from_slice(&counter.to_be_bytes());
                buf.extend_from_slice(ciphertext);
                buf
            }
        }
    }

    /// Decodes a frame previously produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let (&tag, rest) = bytes
            .split_first()
            .ok_or_else(|| ProtoError::MalformedRecord("empty L4 frame".to_string()))?;
        match E2eFrameTag::try_from(tag)? {
            E2eFrameTag::Init => {
                if rest.len() < 4 + 32 {
                    return Err(ProtoError::MalformedRecord(
                        "init frame shorter than its sender_index+network_id prefix".to_string(),
                    ));
                }
                let sender_index = u32::from_be_bytes(rest[0..4].try_into().expect("checked len"));
                let network_id =
                    NetworkId::from(<[u8; 32]>::try_from(&rest[4..36]).expect("checked len"));
                Ok(Self::Init {
                    sender_index,
                    network_id,
                    noise_msg1: rest[36..].to_vec(),
                })
            }
            E2eFrameTag::Resp => {
                if rest.len() < 4 + 4 {
                    return Err(ProtoError::MalformedRecord(
                        "resp frame shorter than its sender_index+receiver_index prefix"
                            .to_string(),
                    ));
                }
                let sender_index = u32::from_be_bytes(rest[0..4].try_into().expect("checked len"));
                let receiver_index =
                    u32::from_be_bytes(rest[4..8].try_into().expect("checked len"));
                Ok(Self::Resp {
                    sender_index,
                    receiver_index,
                    noise_msg2: rest[8..].to_vec(),
                })
            }
            E2eFrameTag::Data => {
                if rest.len() < 4 + 8 {
                    return Err(ProtoError::MalformedRecord(
                        "data frame shorter than its receiver_index+counter prefix".to_string(),
                    ));
                }
                let receiver_index =
                    u32::from_be_bytes(rest[0..4].try_into().expect("checked len"));
                let counter = u64::from_be_bytes(rest[4..12].try_into().expect("checked len"));
                Ok(Self::Data {
                    receiver_index,
                    counter,
                    ciphertext: rest[12..].to_vec(),
                })
            }
        }
    }
}

fn encode_body<T: Serialize>(body: &T) -> Result<Vec<u8>, ProtoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(body, &mut buf).map_err(|e| ProtoError::Encode(e.to_string()))?;
    Ok(buf)
}

fn decode_body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    strict::check_definite_lengths(bytes)?;
    ciborium::from_reader(bytes).map_err(|e| ProtoError::Decode(e.to_string()))
}

/// `CBOR{ v: 1, node_cert: NodeCert, roster_seq: u64, policy_seq: u64,
/// e2e_protos: [u8] }` (protocol.md 5.1). See this module's doc comment:
/// carried in `resp` only, not `init`. Unsigned (not a
/// [`crate::signed::Signed`] body — its authenticity comes from the
/// Noise transcript, not a CBOR-level signature) and, like
/// [`crate::handshake::HelloBody`]/`WelcomeBody`, tolerates unknown keys
/// rather than denying them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct E2eHandshakePayload {
    /// Document schema version.
    pub v: u16,
    /// The responder's certificate, sent live as a defense in depth
    /// check alongside whatever the initiator already holds from Policy
    /// (protocol.md 5.1's checks paragraph).
    pub node_cert: NodeCert,
    /// The responder's currently held Roster `seq` for `network_id`
    /// (protocol.md 5.5).
    pub roster_seq: u64,
    /// The responder's currently held Policy `seq` for `network_id`
    /// (protocol.md 5.5).
    pub policy_seq: u64,
    /// `e2e_proto` tags the responder supports (protocol.md 5.1).
    pub e2e_protos: Vec<u8>,
}

impl E2eHandshakePayload {
    /// Encodes this payload for embedding as `resp`'s Noise message 2
    /// payload.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        encode_body(self)
    }

    /// Strictly decodes a handshake payload out of a Noise message,
    /// tolerating unknown keys; see [`crate::handshake::HelloBody::decode`]'s
    /// docs for the same contract.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        decode_body(bytes)
    }
}

/// Which of the two counter classes a `data` frame's 64 bit `counter`
/// belongs to (protocol.md 5.2): selected by the top bit, independent
/// per session and per direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordClass {
    /// Carries MUX, CLOSE, KEEP, REKEY. Must arrive contiguous
    /// (`counter == last + 1`); any gap, duplicate, or reordering ends
    /// the session (protocol.md 5.2) — enforcing that is session
    /// behavior, not this type's job.
    Reliable,
    /// Carries DGRAM, tolerated within a 2048 record replay window
    /// (protocol.md 5.2, phase 2 per protocol.md 13 — see TODO.md).
    Datagram,
}

impl RecordClass {
    const TOP_BIT: u64 = 1 << 63;

    /// Which class `counter` (as it appears on the wire) belongs to.
    pub fn of_counter(counter: u64) -> Self {
        if counter & Self::TOP_BIT == 0 {
            Self::Reliable
        } else {
            Self::Datagram
        }
    }

    /// The counter's value within its class, both classes counting from
    /// zero (protocol.md 5.2): `counter` with the class's top bit
    /// stripped off.
    pub fn sequence_of(counter: u64) -> u64 {
        counter & !Self::TOP_BIT
    }

    /// Builds a wire `counter` for `sequence` in this class: the top bit
    /// set for [`Self::Datagram`], clear for [`Self::Reliable`].
    pub fn wire_counter(self, sequence: u64) -> u64 {
        let sequence = sequence & !Self::TOP_BIT;
        match self {
            Self::Reliable => sequence,
            Self::Datagram => sequence | Self::TOP_BIT,
        }
    }
}

/// `kind` byte of a `data` frame's decrypted plaintext (protocol.md 5.2).
/// A closed, spec-fixed registry unlike [`crate::ErrorCode`]: per
/// protocol.md 9, "unknown L4 kinds close the session" outright, so
/// there is no tolerated `Unknown` fallback here the way an unrecognized
/// [`crate::ErrorCode`] or [`crate::handshake::Capability`] gets one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum E2eDataKind {
    /// One yamux frame (protocol.md 5.3); opaque to this crate.
    Mux = 0x01,
    /// `u16 channel | datagram bytes` (protocol.md 5.4).
    Dgram = 0x02,
    /// `CBOR{ code: u16, msg: str }`.
    Close = 0x03,
    /// Empty; sent every 20s when idle.
    Keep = 0x04,
    /// Empty; triggers the receiver's own `Rekey()`.
    Rekey = 0x05,
}

impl E2eDataKind {
    /// Which [`RecordClass`] this kind's counter must use (protocol.md
    /// 5.2's table).
    pub fn class(self) -> RecordClass {
        match self {
            Self::Mux | Self::Close | Self::Keep | Self::Rekey => RecordClass::Reliable,
            Self::Dgram => RecordClass::Datagram,
        }
    }
}

impl TryFrom<u8> for E2eDataKind {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, ProtoError> {
        match value {
            0x01 => Ok(Self::Mux),
            0x02 => Ok(Self::Dgram),
            0x03 => Ok(Self::Close),
            0x04 => Ok(Self::Keep),
            0x05 => Ok(Self::Rekey),
            other => Err(ProtoError::UnknownE2eDataKind(other)),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CloseBody {
    code: ErrorCode,
    msg: String,
}

/// The decrypted plaintext of one L4 `data` frame: `u8 kind | body`
/// (protocol.md 5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E2eDataBody {
    /// One yamux frame, carried opaquely ([`crate::e2e`]'s doc comment:
    /// no yamux dependency here).
    Mux(Vec<u8>),
    /// A datagram on `channel` (protocol.md 5.4).
    Dgram {
        /// The channel this datagram belongs to.
        channel: u16,
        /// The datagram's own bytes.
        bytes: Vec<u8>,
    },
    /// Ends the session or a stream/channel with a reason.
    Close {
        /// A reason from the [`ErrorCode`] registry, e.g. `no_grant`
        /// (protocol.md 5.1) or `grant_removed` (protocol.md 5.3).
        code: ErrorCode,
        /// A human-readable detail.
        msg: String,
    },
    /// Liveness ping, sent every 20s when otherwise idle.
    Keep,
    /// Triggers the receiver's own `Rekey()` (protocol.md 5.2).
    Rekey,
}

impl E2eDataBody {
    /// This body's [`E2eDataKind`].
    pub fn kind(&self) -> E2eDataKind {
        match self {
            Self::Mux(_) => E2eDataKind::Mux,
            Self::Dgram { .. } => E2eDataKind::Dgram,
            Self::Close { .. } => E2eDataKind::Close,
            Self::Keep => E2eDataKind::Keep,
            Self::Rekey => E2eDataKind::Rekey,
        }
    }

    /// Encodes this body as `u8 kind | body`. This is the plaintext that
    /// a `menzil-e2e` session then encrypts into an
    /// [`E2eFrame::Data`]'s `ciphertext`.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut buf = vec![self.kind() as u8];
        match self {
            Self::Mux(frame) => buf.extend_from_slice(frame),
            Self::Dgram { channel, bytes } => {
                buf.extend_from_slice(&channel.to_be_bytes());
                buf.extend_from_slice(bytes);
            }
            Self::Close { code, msg } => {
                let body = CloseBody {
                    code: *code,
                    msg: msg.clone(),
                };
                ciborium::into_writer(&body, &mut buf)
                    .map_err(|e| ProtoError::Encode(e.to_string()))?;
            }
            Self::Keep | Self::Rekey => {}
        }
        Ok(buf)
    }

    /// Decodes a body previously produced by [`Self::encode`] (the
    /// decrypted plaintext of an [`E2eFrame::Data`]).
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let (&kind_byte, rest) = bytes
            .split_first()
            .ok_or_else(|| ProtoError::MalformedRecord("empty L4 data record".to_string()))?;
        match E2eDataKind::try_from(kind_byte)? {
            E2eDataKind::Mux => Ok(Self::Mux(rest.to_vec())),
            E2eDataKind::Dgram => {
                if rest.len() < 2 {
                    return Err(ProtoError::MalformedRecord(
                        "DGRAM body shorter than its 2-byte channel prefix".to_string(),
                    ));
                }
                let channel = u16::from_be_bytes([rest[0], rest[1]]);
                Ok(Self::Dgram {
                    channel,
                    bytes: rest[2..].to_vec(),
                })
            }
            E2eDataKind::Close => {
                strict::check_definite_lengths(rest)?;
                let body: CloseBody =
                    ciborium::from_reader(rest).map_err(|e| ProtoError::Decode(e.to_string()))?;
                Ok(Self::Close {
                    code: body.code,
                    msg: body.msg,
                })
            }
            E2eDataKind::Keep => {
                require_empty(rest, "KEEP")?;
                Ok(Self::Keep)
            }
            E2eDataKind::Rekey => {
                require_empty(rest, "REKEY")?;
                Ok(Self::Rekey)
            }
        }
    }
}

/// `u8 tag | u32 receiver_index | u64 counter` (protocol.md 5.1's `data`
/// layout, minus `ciphertext`).
const E2E_DATA_FRAME_PREFIX_LEN: usize = 1 + 4 + 8;

/// `ChaCha20-Poly1305`'s AEAD tag for the *L4* Noise session specifically
/// (protocol.md 5.1's cipher suite) — a tag separate from, and in
/// addition to, the *L3* session's own ([`crate::record::L3_AEAD_TAG_LEN`]):
/// an L4 `data` frame's `ciphertext` travels *inside* an L3 SEND/RECV
/// record that is itself independently AEAD-protected end to end between
/// node and relay, not in place of that protection.
///
/// A real bug this crate shipped and then caught on its own: an earlier
/// version of [`max_e2e_data_plaintext`] accounted for this tag alone and
/// missed the L3 one entirely, overstating the true budget by exactly 16
/// bytes (TODO.md L4b's own review, which found it while live-verifying
/// [`crate::record::max_send_payload`] against a real relay).
const L4_AEAD_TAG_LEN: usize = 16;

/// The largest [`E2eDataBody`] plaintext that fits in one L4 `data`
/// frame once wrapped in an L3 SEND/RECV record bound by `max_record`
/// (WELCOME `limits.max_record`, protocol.md 4.1, 10): what
/// [`crate::record::max_send_payload`] leaves for a SEND's own payload,
/// minus the `data` frame's own prefix and its own (L4-level) AEAD tag.
/// Saturates at 0 rather than underflowing for a `max_record` too small
/// to carry a single L4 data record regardless. Enforcing this against
/// an actual outbound body is session behavior (TODO.md L4d), not this
/// function's job; it only states the budget.
pub fn max_e2e_data_plaintext(max_record: u32) -> usize {
    crate::record::max_send_payload(max_record)
        .saturating_sub(E2E_DATA_FRAME_PREFIX_LEN + L4_AEAD_TAG_LEN)
}

/// The exact encoded size of an [`E2eFrame::Data`] whose plaintext (an
/// [`E2eDataBody::encode`] result, kind byte included) is `plaintext_len`
/// bytes: the frame's own prefix plus that plaintext plus the L4 AEAD tag.
/// This is also the L3 SEND payload length such a frame becomes, so a
/// caller can work out what a record will cost against the node's send
/// queue and the relay's credit *before* encrypting it (TODO.md L4h5: an
/// L4 session must reserve queue space before `menzil-e2e` assigns the
/// record a counter, since a record refused after that can only end the
/// session). Pinned against real encryption by a test in `menzil-e2e`.
pub const fn e2e_data_frame_len(plaintext_len: usize) -> usize {
    E2E_DATA_FRAME_PREFIX_LEN + plaintext_len + L4_AEAD_TAG_LEN
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::{NodeId, X25519PublicKey};
    use crate::identity::NodeCertBody;
    use ed25519_dalek::SigningKey;

    fn sample_cert() -> NodeCert {
        let key = SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: crate::PROTOCOL_VERSION,
            node_id: NodeId::from([3u8; 32]),
            x25519_pub: X25519PublicKey::from([4u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }

    #[test]
    fn init_frame_round_trips() {
        let frame = E2eFrame::Init {
            sender_index: 0x0102_0304,
            network_id: NetworkId::from([9u8; 32]),
            noise_msg1: vec![1, 2, 3, 4, 5],
        };
        let encoded = frame.encode();
        assert_eq!(encoded[0], 0x01);
        assert_eq!(E2eFrame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn resp_frame_round_trips() {
        let frame = E2eFrame::Resp {
            sender_index: 9,
            receiver_index: 7,
            noise_msg2: vec![10, 11, 12],
        };
        let encoded = frame.encode();
        assert_eq!(encoded[0], 0x02);
        assert_eq!(E2eFrame::decode(&encoded).unwrap(), frame);
        // protocol.md 5.1's layout: `sender_index` (the responder's own)
        // first, then `receiver_index` (the initiator's, echoed).
        assert_eq!(
            encoded,
            vec![0x02, 0, 0, 0, 9, 0, 0, 0, 7, 10, 11, 12],
            "sender_index first, receiver_index second"
        );
    }

    #[test]
    fn data_frame_round_trips() {
        let frame = E2eFrame::Data {
            receiver_index: 42,
            counter: RecordClass::Datagram.wire_counter(5),
            ciphertext: vec![0xaa; 20],
        };
        let encoded = frame.encode();
        assert_eq!(encoded[0], 0x03);
        assert_eq!(E2eFrame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn decode_rejects_unknown_tag() {
        let err = E2eFrame::decode(&[0x7f, 0, 0]).unwrap_err();
        assert!(matches!(err, ProtoError::UnknownE2eFrameTag(0x7f)));
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert!(E2eFrame::decode(&[]).is_err());
    }

    #[test]
    fn decode_rejects_truncated_init_and_resp_and_data() {
        assert!(E2eFrame::decode(&[0x01, 0, 0]).is_err());
        assert!(E2eFrame::decode(&[0x02, 0, 0]).is_err());
        assert!(E2eFrame::decode(&[0x03, 0, 0]).is_err());
    }

    #[test]
    fn handshake_payload_round_trips() {
        let payload = E2eHandshakePayload {
            v: crate::PROTOCOL_VERSION,
            node_cert: sample_cert(),
            roster_seq: 3,
            policy_seq: 7,
            e2e_protos: vec![0x01],
        };
        let encoded = payload.encode().unwrap();
        assert_eq!(E2eHandshakePayload::decode(&encoded).unwrap(), payload);
    }

    #[test]
    fn handshake_payload_rejects_indefinite_length() {
        assert!(E2eHandshakePayload::decode(&[0xbf, 0xff]).is_err());
    }

    #[test]
    fn record_class_round_trips_through_the_top_bit() {
        assert_eq!(RecordClass::of_counter(0), RecordClass::Reliable);
        assert_eq!(
            RecordClass::of_counter(RecordClass::Reliable.wire_counter(u64::MAX)),
            RecordClass::Reliable,
            "Reliable must never set the top bit even if asked to"
        );
        let datagram_wire = RecordClass::Datagram.wire_counter(5);
        assert_eq!(
            RecordClass::of_counter(datagram_wire),
            RecordClass::Datagram
        );
        assert_eq!(RecordClass::sequence_of(datagram_wire), 5);
        assert_eq!(datagram_wire, (1u64 << 63) | 5);
    }

    #[test]
    fn data_kind_class_matches_protocol_md_5_2s_table() {
        assert_eq!(E2eDataKind::Mux.class(), RecordClass::Reliable);
        assert_eq!(E2eDataKind::Close.class(), RecordClass::Reliable);
        assert_eq!(E2eDataKind::Keep.class(), RecordClass::Reliable);
        assert_eq!(E2eDataKind::Rekey.class(), RecordClass::Reliable);
        assert_eq!(E2eDataKind::Dgram.class(), RecordClass::Datagram);
    }

    #[test]
    fn data_kind_rejects_unknown_byte_with_no_fallback() {
        for byte in [0x00u8, 0x06, 0xff] {
            let err = E2eDataKind::try_from(byte).unwrap_err();
            assert!(matches!(err, ProtoError::UnknownE2eDataKind(b) if b == byte));
        }
    }

    #[test]
    fn mux_body_round_trips_opaquely() {
        let body = E2eDataBody::Mux(vec![1, 2, 3, 4]);
        let encoded = body.encode().unwrap();
        assert_eq!(encoded[0], 0x01);
        assert_eq!(E2eDataBody::decode(&encoded).unwrap(), body);
    }

    #[test]
    fn dgram_body_round_trips() {
        let body = E2eDataBody::Dgram {
            channel: 0x1234,
            bytes: vec![9, 9, 9],
        };
        let encoded = body.encode().unwrap();
        assert_eq!(E2eDataBody::decode(&encoded).unwrap(), body);
    }

    #[test]
    fn dgram_body_rejects_short_channel_prefix() {
        assert!(E2eDataBody::decode(&[0x02, 0x00]).is_err());
    }

    #[test]
    fn close_body_round_trips() {
        let body = E2eDataBody::Close {
            code: ErrorCode::NoGrant,
            msg: "no grant for this node".to_string(),
        };
        let encoded = body.encode().unwrap();
        assert_eq!(E2eDataBody::decode(&encoded).unwrap(), body);
    }

    #[test]
    fn keep_and_rekey_round_trip_empty() {
        for body in [E2eDataBody::Keep, E2eDataBody::Rekey] {
            let encoded = body.encode().unwrap();
            assert_eq!(encoded.len(), 1, "kind byte only, empty body");
            assert_eq!(E2eDataBody::decode(&encoded).unwrap(), body);
        }
    }

    #[test]
    fn keep_rejects_a_non_empty_body() {
        assert!(E2eDataBody::decode(&[0x04, 0x00]).is_err());
    }

    #[test]
    fn data_body_decode_rejects_empty_input() {
        assert!(E2eDataBody::decode(&[]).is_err());
    }

    #[test]
    fn max_plaintext_matches_the_worked_out_overhead() {
        // max_send_payload(65_535) = 65_484 (1 L3 type tag + 34
        // SEND_RECV_PREFIX_LEN + 16 L3 AEAD tag subtracted; its own
        // tests pin this number against a live-verified figure). Then
        // 13 (data frame prefix) + 16 (the *separate* L4 AEAD tag) more:
        // 65_484 - 13 - 16 = 65_455.
        assert_eq!(crate::record::max_send_payload(65_535), 65_484);
        assert_eq!(max_e2e_data_plaintext(65_535), 65_455);
    }

    #[test]
    fn max_plaintext_saturates_instead_of_underflowing() {
        assert_eq!(max_e2e_data_plaintext(0), 0);
        assert_eq!(max_e2e_data_plaintext(10), 0);
    }
}
