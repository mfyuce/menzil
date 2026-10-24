//! The `menzil:docs` messages and their framing (protocol.md 5.5): `fetch`, `push`, `doc`, `end`
//! and `result`, each sent as `u32 len | CBOR` with the length big endian.
//!
//! This module only describes bytes: it has no I/O. The rules that must run before anything is
//! allocated or read are here as pure functions the I/O layer calls in the right place:
//! [`check_frame_len`] bounds a length prefix before a buffer exists for it, and
//! [`MessageCounter`] refuses the seventh message of a stream before its header is read.
//!
//! The CBOR is strict as in section 2.1: definite lengths and no trailing bytes
//! ([`crate::strict`]), no unknown keys and no duplicate keys (serde), and every key present, a
//! nullable one as an explicit `null`, never left out. A `v` other than 1 is refused.

use std::time::Duration;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};
use thiserror::Error;

use crate::error::ErrorCode;
use crate::strict;

/// The largest frame body (the CBOR after the length prefix): one document of
/// [`crate::MAX_DOC_BYTES`] plus 1,024 bytes for the message around it.
pub const MAX_FRAME_LEN: usize = 1_049_600;

/// Bytes of the length prefix.
pub const FRAME_HEADER_LEN: usize = 4;

/// The most messages one side may send on a stream, and so the most a receiver admits: `push`,
/// four documents and `end` make six.
pub const MAX_MESSAGES: usize = 6;

/// The time one `menzil:docs` stream may take, from its first byte to its last.
pub const STREAM_DEADLINE: Duration = Duration::from_secs(30);

/// The only message version.
pub const VERSION: u16 = 1;

/// Failures of the framing and the message decoding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DocsError {
    /// A length prefix (or an outgoing frame) is over [`MAX_FRAME_LEN`].
    #[error("frame of {len} bytes exceeds the {max} byte limit")]
    FrameTooLarge {
        /// The length claimed.
        len: usize,
        /// The limit it exceeded.
        max: usize,
    },
    /// A receiver was offered more than [`MAX_MESSAGES`] messages on one stream.
    #[error("more than {max} messages on one stream")]
    TooManyMessages {
        /// The limit.
        max: usize,
    },
    /// The frame is not one strict CBOR message of this section.
    #[error("message does not decode: {0}")]
    Decode(String),
    /// A `fetch` or `push` with a `v` other than [`VERSION`].
    #[error("unsupported message version {0}")]
    Version(u16),
    /// A message could not be encoded.
    #[error("message does not encode: {0}")]
    Encode(String),
}

/// What a `doc` message carries. The order of the variants is the order they are sent in: the
/// bases first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocKind {
    /// The owner signed Roster a steward signed Roster was made from.
    BaseRoster,
    /// The owner signed Policy a steward signed Policy was made from.
    BasePolicy,
    /// A Roster.
    Roster,
    /// A Policy.
    Policy,
}

/// What a receiver did with one document of a push (`result.roster`, `result.policy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 0: adopted.
    Adopted,
    /// 1: already held, or older than what is held.
    Held,
    /// 2: rejected, with the `code` of the `result`.
    Rejected,
    /// 3: not sent.
    NotSent,
}

impl Outcome {
    /// The wire number.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Adopted => 0,
            Self::Held => 1,
            Self::Rejected => 2,
            Self::NotSent => 3,
        }
    }

    /// The outcome for a wire number, `None` for one the registry does not have.
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(Self::Adopted),
            1 => Some(Self::Held),
            2 => Some(Self::Rejected),
            3 => Some(Self::NotSent),
            _ => None,
        }
    }
}

impl Serialize for Outcome {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(self.as_u8())
    }
}

impl<'de> Deserialize<'de> for Outcome {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = u8::deserialize(deserializer)?;
        Self::from_u8(n).ok_or_else(|| de::Error::custom(format!("unknown result outcome {n}")))
    }
}

/// One `menzil:docs` message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// `fetch`: the opener asks for what is newer than the seqs it holds. `base_seq` is the `seq`
    /// of the base of its steward signed Roster, `policy_base_seq` that of its steward signed
    /// Policy (null for an owner signed one), if it holds any.
    Fetch {
        /// The seq of the Roster the opener holds.
        roster_seq: Option<u64>,
        /// The seq of the Policy the opener holds.
        policy_seq: Option<u64>,
        /// The seq of the base of the Roster the opener holds.
        base_seq: Option<u64>,
        /// The seq of the base of the Policy the opener holds.
        policy_base_seq: Option<u64>,
    },
    /// `push`: the opener sends documents.
    Push,
    /// `doc`: the verbatim encoding of one signed document.
    Doc {
        /// Which document.
        kind: DocKind,
        /// Its bytes.
        doc: Vec<u8>,
    },
    /// `end`: the sender has no more documents; the seqs are what it holds.
    End {
        /// The seq of the sender's Roster.
        roster_seq: Option<u64>,
        /// The seq of the sender's Policy.
        policy_seq: Option<u64>,
    },
    /// `result`: the receiver's answer to a push.
    Result {
        /// What became of the Roster.
        roster: Outcome,
        /// What became of the Policy.
        policy: Outcome,
        /// Why, when an outcome is [`Outcome::Rejected`].
        code: Option<ErrorCode>,
        /// The seq of the Roster the receiver holds afterwards.
        roster_seq: Option<u64>,
        /// The seq of the Policy the receiver holds afterwards.
        policy_seq: Option<u64>,
    },
}

/// The shape on the wire: an internally tagged map. Kept private so that `v` is not something a
/// caller can get wrong.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase", deny_unknown_fields)]
enum Wire {
    Fetch {
        v: u16,
        #[serde(deserialize_with = "required")]
        roster_seq: Option<u64>,
        #[serde(deserialize_with = "required")]
        policy_seq: Option<u64>,
        #[serde(deserialize_with = "required")]
        base_seq: Option<u64>,
        #[serde(deserialize_with = "required")]
        policy_base_seq: Option<u64>,
    },
    Push {
        v: u16,
    },
    Doc {
        kind: DocKind,
        #[serde(with = "bstr")]
        doc: Vec<u8>,
    },
    End {
        #[serde(deserialize_with = "required")]
        roster_seq: Option<u64>,
        #[serde(deserialize_with = "required")]
        policy_seq: Option<u64>,
    },
    Result {
        roster: Outcome,
        policy: Outcome,
        #[serde(deserialize_with = "required")]
        code: Option<ErrorCode>,
        #[serde(deserialize_with = "required")]
        roster_seq: Option<u64>,
        #[serde(deserialize_with = "required")]
        policy_seq: Option<u64>,
    },
}

/// A nullable field that must be present: with `deserialize_with` serde reports a missing key
/// instead of reading it as `None`.
fn required<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// A CBOR byte string (not an array of integers, which serde's default for `Vec<u8>` is).
mod bstr {
    use super::*;

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
        }
        deserializer.deserialize_byte_buf(V)
    }
}

impl From<&Message> for Wire {
    fn from(message: &Message) -> Self {
        match message {
            Message::Fetch {
                roster_seq,
                policy_seq,
                base_seq,
                policy_base_seq,
            } => Wire::Fetch {
                v: VERSION,
                roster_seq: *roster_seq,
                policy_seq: *policy_seq,
                base_seq: *base_seq,
                policy_base_seq: *policy_base_seq,
            },
            Message::Push => Wire::Push { v: VERSION },
            Message::Doc { kind, doc } => Wire::Doc {
                kind: *kind,
                doc: doc.clone(),
            },
            Message::End {
                roster_seq,
                policy_seq,
            } => Wire::End {
                roster_seq: *roster_seq,
                policy_seq: *policy_seq,
            },
            Message::Result {
                roster,
                policy,
                code,
                roster_seq,
                policy_seq,
            } => Wire::Result {
                roster: *roster,
                policy: *policy,
                code: *code,
                roster_seq: *roster_seq,
                policy_seq: *policy_seq,
            },
        }
    }
}

impl Wire {
    fn into_message(self) -> Result<Message, DocsError> {
        Ok(match self {
            Wire::Fetch {
                v,
                roster_seq,
                policy_seq,
                base_seq,
                policy_base_seq,
            } => {
                check_version(v)?;
                Message::Fetch {
                    roster_seq,
                    policy_seq,
                    base_seq,
                    policy_base_seq,
                }
            }
            Wire::Push { v } => {
                check_version(v)?;
                Message::Push
            }
            Wire::Doc { kind, doc } => Message::Doc { kind, doc },
            Wire::End {
                roster_seq,
                policy_seq,
            } => Message::End {
                roster_seq,
                policy_seq,
            },
            Wire::Result {
                roster,
                policy,
                code,
                roster_seq,
                policy_seq,
            } => Message::Result {
                roster,
                policy,
                code,
                roster_seq,
                policy_seq,
            },
        })
    }
}

fn check_version(v: u16) -> Result<(), DocsError> {
    if v == VERSION {
        Ok(())
    } else {
        Err(DocsError::Version(v))
    }
}

/// Checks a length prefix against [`MAX_FRAME_LEN`] and returns the length to read. The caller
/// allocates its buffer only after this has returned `Ok`.
pub fn check_frame_len(prefix: u32) -> Result<usize, DocsError> {
    let len = prefix as usize;
    if len > MAX_FRAME_LEN {
        return Err(DocsError::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    Ok(len)
}

/// Counts the messages received on one stream; the seventh is refused.
#[derive(Debug, Default)]
pub struct MessageCounter {
    seen: usize,
}

impl MessageCounter {
    /// A counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Admits one more message, or refuses it when [`MAX_MESSAGES`] have been admitted already.
    /// Call it before reading the message's header.
    pub fn admit(&mut self) -> Result<(), DocsError> {
        if self.seen >= MAX_MESSAGES {
            return Err(DocsError::TooManyMessages { max: MAX_MESSAGES });
        }
        self.seen += 1;
        Ok(())
    }

    /// How many messages have been admitted.
    pub fn seen(&self) -> usize {
        self.seen
    }
}

/// Encodes `message` as `u32 len | CBOR`, ready to write.
pub fn encode_frame(message: &Message) -> Result<Vec<u8>, DocsError> {
    let mut cbor = Vec::new();
    ciborium::into_writer(&Wire::from(message), &mut cbor)
        .map_err(|e| DocsError::Encode(e.to_string()))?;
    if cbor.len() > MAX_FRAME_LEN {
        return Err(DocsError::FrameTooLarge {
            len: cbor.len(),
            max: MAX_FRAME_LEN,
        });
    }
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + cbor.len());
    frame.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
    frame.extend_from_slice(&cbor);
    Ok(frame)
}

/// Decodes one frame body (the CBOR, without the length prefix) strictly.
pub fn decode_message(body: &[u8]) -> Result<Message, DocsError> {
    strict::check_definite_lengths(body).map_err(|e| DocsError::Decode(e.to_string()))?;
    let wire: Wire = ciborium::from_reader(body).map_err(|e| DocsError::Decode(e.to_string()))?;
    wire.into_message()
}

#[cfg(test)]
mod tests;
