//! L5 stream opening (protocol.md 5.3): the `OPEN`/`OPEN_ACK` headers a
//! yamux stream's initiator and responder exchange before it becomes a
//! byte pipe.
//!
//! Kept separate from [`crate::e2e`] (L4) on purpose, mirroring decision
//! 0001's own stated reason for the split: "The L5 OPEN and OPEN_ACK
//! headers and the service model are defined independently of the mux
//! so that the QUIC change stays below them." Whether `target` may be
//! non-null for a given `service`, whether `meta` came from a trusted
//! relay principal, and what actually answers an OPEN are session
//! behavior for TODO.md's `menzil-stream`/`menzil-node` (L4g, L4i), not
//! this module — it only encodes and decodes the two headers.

use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ProtoError};
use crate::service::ServiceId;
use crate::strict;

const LEN_PREFIX_BYTES: usize = 2;

fn encode_len_prefixed<T: Serialize>(body: &T) -> Result<Vec<u8>, ProtoError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(body, &mut cbor).map_err(|e| ProtoError::Encode(e.to_string()))?;
    let len = u16::try_from(cbor.len()).map_err(|_| {
        ProtoError::Encode(format!(
            "body of {} bytes exceeds the u16 len prefix",
            cbor.len()
        ))
    })?;
    let mut buf = Vec::with_capacity(LEN_PREFIX_BYTES + cbor.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&cbor);
    Ok(buf)
}

fn decode_len_prefixed<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    if bytes.len() < LEN_PREFIX_BYTES {
        return Err(ProtoError::MalformedRecord(
            "body shorter than its 2-byte len prefix".to_string(),
        ));
    }
    let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let body = &bytes[LEN_PREFIX_BYTES..];
    if body.len() != len {
        return Err(ProtoError::MalformedRecord(format!(
            "declared len {len} does not match the {} body bytes given",
            body.len()
        )));
    }
    strict::check_definite_lengths(body)?;
    ciborium::from_reader(body).map_err(|e| ProtoError::Decode(e.to_string()))
}

/// The optional `transport` of an OPEN `target` (egress slice 2b1): absent
/// means TCP, `"udp"` asks for a datagram channel. Any other string is a
/// decode error. Unsigned, like the rest of OPEN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpenTransport {
    /// A UDP target, carried on an L4 datagram channel.
    #[serde(rename = "udp")]
    Udp,
}

/// `target: { host: str, port: u16, transport?: "udp" }` (protocol.md 5.3),
/// present only when `service` is `egress:*`. A TCP target omits
/// `transport`, so its encoding is byte identical to the one before the key
/// existed. Unlike [`OpenBody`], the target refuses unknown keys: a receiver
/// that does not understand a key must not silently serve the OPEN as
/// something else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTarget {
    /// The requested host, sent as a name (resolved at the exit,
    /// protocol.md 8) — never pre-resolved here.
    pub host: String,
    /// The requested port.
    pub port: u16,
    /// `None` for TCP (the key is then absent on the wire), `Some(Udp)`
    /// for a datagram channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<OpenTransport>,
}

/// `meta: { client_ip: str | null, sni: str | null }` (protocol.md 5.3):
/// always present as a map, its two fields individually nullable.
/// Honored only when the sender is the relay principal (protocol.md
/// 6.1) — a member-sent `meta` is ignored, not rejected; that check is
/// session behavior, not this type's job.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct OpenMeta {
    /// The original client's address, from the relay principal only.
    pub client_ip: Option<String>,
    /// The ClientHello SNI that routed this share, from the relay
    /// principal only.
    pub sni: Option<String>,
}

/// `OPEN = u16 len | CBOR{ v: 1, service: ServiceId, target: {...} |
/// null, meta: {...} }` (protocol.md 5.3). Unsigned, like
/// [`crate::handshake::HelloBody`]: tolerates unknown keys rather than
/// denying them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenBody {
    /// Document schema version.
    pub v: u16,
    /// The service this stream is opening.
    pub service: ServiceId,
    /// Must be `None` unless `service` is `egress:*` (protocol.md 5.3);
    /// enforcing that is the responder's job, not this type's.
    pub target: Option<OpenTarget>,
    /// Relay-principal-only metadata; see [`OpenMeta`].
    pub meta: OpenMeta,
}

impl OpenBody {
    /// Encodes this header as `u16 len | CBOR`, a complete self-delimited
    /// buffer ready to write to a fresh yamux stream.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        encode_len_prefixed(self)
    }

    /// Decodes a header previously produced by [`Self::encode`]: the
    /// full `u16 len | CBOR` buffer, not just the CBOR part. A caller
    /// reading from a live stream reads the first two bytes to learn how
    /// many more to read before calling this (this crate has no async
    /// I/O of its own to do that read).
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        decode_len_prefixed(bytes)
    }
}

/// `OPEN_ACK = u16 len | CBOR{ ok: bool, code: u16, msg: str, channel:
/// u16 | null }` (protocol.md 5.3). `code` reuses the
/// [`crate::ErrorCode`] registry rather than a disjoint numbering the
/// spec never actually specifies for this field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAckBody {
    /// Whether the stream was accepted.
    pub ok: bool,
    /// A reason code, meaningful mainly when `ok` is false; a compliant
    /// peer may still send a named code (rather than a placeholder) on
    /// success.
    pub code: ErrorCode,
    /// A human-readable detail.
    pub msg: String,
    /// The allocated datagram channel id (protocol.md 5.4), only when
    /// this OPEN named a `udp:` service or `egress:*` with a UDP target.
    pub channel: Option<u16>,
}

impl OpenAckBody {
    /// Encodes this header as `u16 len | CBOR`.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        encode_len_prefixed(self)
    }

    /// Decodes a header previously produced by [`Self::encode`]; see
    /// [`OpenBody::decode`]'s docs for the same full-buffer contract.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        decode_len_prefixed(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceKind;

    fn sample_open() -> OpenBody {
        OpenBody {
            v: crate::PROTOCOL_VERSION,
            service: ServiceId::new(ServiceKind::Tcp, "ssh"),
            target: None,
            meta: OpenMeta::default(),
        }
    }

    #[test]
    fn open_round_trips_without_target_or_meta() {
        let open = sample_open();
        let encoded = open.encode().unwrap();
        assert_eq!(OpenBody::decode(&encoded).unwrap(), open);
    }

    #[test]
    fn open_round_trips_with_target_and_meta() {
        let open = OpenBody {
            v: crate::PROTOCOL_VERSION,
            service: ServiceId::new(ServiceKind::Egress, "*"),
            target: Some(OpenTarget {
                host: "example.com".to_string(),
                port: 443,
                transport: None,
            }),
            meta: OpenMeta {
                client_ip: Some("203.0.113.5".to_string()),
                sni: Some("example.com".to_string()),
            },
        };
        let encoded = open.encode().unwrap();
        assert_eq!(OpenBody::decode(&encoded).unwrap(), open);
    }

    #[test]
    fn open_len_prefix_matches_the_cbor_body_length() {
        let open = sample_open();
        let encoded = open.encode().unwrap();
        let declared = u16::from_be_bytes([encoded[0], encoded[1]]) as usize;
        assert_eq!(declared, encoded.len() - 2);
    }

    #[test]
    fn open_decode_rejects_a_declared_length_mismatch() {
        let open = sample_open();
        let mut encoded = open.encode().unwrap();
        let last = encoded.len() - 1;
        encoded.truncate(last); // one byte short of what the prefix declares
        assert!(OpenBody::decode(&encoded).is_err());
    }

    #[test]
    fn open_decode_rejects_indefinite_length_cbor() {
        let mut bytes = vec![0x00, 0x02];
        bytes.extend_from_slice(&[0xbf, 0xff]);
        assert!(OpenBody::decode(&bytes).is_err());
    }

    #[test]
    fn open_decode_rejects_input_shorter_than_the_len_prefix() {
        assert!(OpenBody::decode(&[0x00]).is_err());
    }

    #[test]
    fn open_ack_round_trips_ok_with_channel() {
        let ack = OpenAckBody {
            ok: true,
            code: ErrorCode::Unknown(0),
            msg: String::new(),
            channel: Some(4),
        };
        let encoded = ack.encode().unwrap();
        assert_eq!(OpenAckBody::decode(&encoded).unwrap(), ack);
    }

    #[test]
    fn open_ack_round_trips_refusal_without_channel() {
        let ack = OpenAckBody {
            ok: false,
            code: ErrorCode::GrantRemoved,
            msg: "grant removed".to_string(),
            channel: None,
        };
        let encoded = ack.encode().unwrap();
        assert_eq!(OpenAckBody::decode(&encoded).unwrap(), ack);
    }

    /// The CBOR a TCP `target` encoded to before the `transport` key
    /// existed (`{ "host": "example.com", "port": 443 }`), written out by
    /// hand: a map of two, text keys in struct order.
    fn v0_4_target_cbor() -> Vec<u8> {
        let mut b = vec![0xa2, 0x64];
        b.extend_from_slice(b"host");
        b.push(0x6b);
        b.extend_from_slice(b"example.com");
        b.push(0x64);
        b.extend_from_slice(b"port");
        b.extend_from_slice(&[0x19, 0x01, 0xbb]);
        b
    }

    #[test]
    fn an_open_target_without_transport_is_byte_identical_to_v0_4() {
        let target = OpenTarget {
            host: "example.com".to_string(),
            port: 443,
            transport: None,
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&target, &mut cbor).unwrap();
        assert_eq!(cbor, v0_4_target_cbor());
        // And the whole OPEN: the target value sits inside unchanged.
        let open = OpenBody {
            v: crate::PROTOCOL_VERSION,
            service: ServiceId::new(ServiceKind::Egress, "*"),
            target: Some(target),
            meta: OpenMeta::default(),
        };
        let encoded = open.encode().unwrap();
        assert!(
            encoded
                .windows(cbor.len())
                .any(|w| w == v0_4_target_cbor().as_slice()),
            "a TCP target must encode exactly as before"
        );
        assert!(!encoded.windows(9).any(|w| w == b"transport"));
        // A v0.4 sender's bytes (no transport key) decode with None.
        let decoded: OpenTarget = ciborium::from_reader(v0_4_target_cbor().as_slice()).unwrap();
        assert_eq!(decoded.transport, None);
        assert_eq!(OpenBody::decode(&encoded).unwrap(), open);
    }

    #[test]
    fn an_open_target_with_udp_round_trips() {
        let open = OpenBody {
            v: crate::PROTOCOL_VERSION,
            service: ServiceId::new(ServiceKind::Egress, "*"),
            target: Some(OpenTarget {
                host: "example.com".to_string(),
                port: 53,
                transport: Some(OpenTransport::Udp),
            }),
            meta: OpenMeta::default(),
        };
        let encoded = open.encode().unwrap();
        assert!(encoded.windows(3).any(|w| w == b"udp"));
        assert_eq!(OpenBody::decode(&encoded).unwrap(), open);
    }

    fn target_cbor(entries: &[(&str, ciborium::Value)]) -> Vec<u8> {
        let map = ciborium::Value::Map(
            entries
                .iter()
                .map(|(k, v)| (ciborium::Value::Text((*k).to_string()), v.clone()))
                .collect(),
        );
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    #[test]
    fn open_target_refuses_unknown_transport_and_unknown_keys() {
        use ciborium::Value;
        let host = ("host", Value::Text("example.com".into()));
        let port = ("port", Value::Integer(443.into()));
        let decode = |entries: &[(&str, Value)]| {
            ciborium::from_reader::<OpenTarget, _>(target_cbor(entries).as_slice())
        };
        // "udp" is accepted.
        let ok = decode(&[
            host.clone(),
            port.clone(),
            ("transport", Value::Text("udp".into())),
        ]);
        assert_eq!(ok.unwrap().transport, Some(OpenTransport::Udp));
        // Any other transport value is refused, whatever its case or type.
        for bad in [
            Value::Text("tcp".into()),
            Value::Text("UDP".into()),
            Value::Text("quic".into()),
            Value::Text(String::new()),
            Value::Integer(17.into()),
        ] {
            assert!(
                decode(&[host.clone(), port.clone(), ("transport", bad.clone())]).is_err(),
                "{bad:?}"
            );
        }
        // An explicit null reads as absent (TCP); no sender emits it.
        let null = decode(&[host.clone(), port.clone(), ("transport", Value::Null)]);
        assert_eq!(null.unwrap().transport, None);
        // Any unknown key is refused.
        assert!(decode(&[host.clone(), port.clone(), ("extra", Value::Bool(true))]).is_err());
        assert!(
            decode(&[
                host.clone(),
                port.clone(),
                ("transport", Value::Text("udp".into())),
                ("zone", Value::Text("x".into())),
            ])
            .is_err()
        );
        // The refusal reaches a whole OPEN.
        let mut bytes = Vec::new();
        let open = Value::Map(vec![
            (Value::Text("v".into()), Value::Integer(1.into())),
            (
                Value::Text("service".into()),
                Value::Text("egress:*".into()),
            ),
            (
                Value::Text("target".into()),
                Value::Map(vec![
                    (Value::Text("host".into()), Value::Text("h".into())),
                    (Value::Text("port".into()), Value::Integer(1.into())),
                    (Value::Text("transport".into()), Value::Text("sctp".into())),
                ]),
            ),
            (
                Value::Text("meta".into()),
                Value::Map(vec![
                    (Value::Text("client_ip".into()), Value::Null),
                    (Value::Text("sni".into()), Value::Null),
                ]),
            ),
        ]);
        ciborium::into_writer(&open, &mut bytes).unwrap();
        let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&bytes);
        assert!(OpenBody::decode(&framed).is_err());
    }
}
