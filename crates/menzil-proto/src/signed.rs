//! `Signed(type)` (protocol.md 2.1): the CBOR array `[bstr body, bstr
//! sig]` that every owner-signed document (NodeCert, Roster, Policy,
//! Invite, Steward) is wrapped in.

use std::fmt;
use std::marker::PhantomData;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::{DeserializeOwned, Deserializer, Error as DeError, SeqAccess, Visitor};
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};

use crate::error::ProtoError;
use crate::strict;

/// `type` tag for [`crate::identity::NodeCertBody`].
pub const TAG_NODECERT: &str = "nodecert";
/// `type` tag for [`crate::network::RosterBody`].
pub const TAG_ROSTER: &str = "roster";
/// `type` tag for [`crate::network::PolicyBody`].
pub const TAG_POLICY: &str = "policy";
/// `type` tag for [`crate::invite::InviteBody`].
pub const TAG_INVITE: &str = "invite";
/// `type` tag for [`crate::network::StewardBody`].
pub const TAG_STEWARD: &str = "steward";
/// `type` tag reserved by protocol.md 2.1 for a future software-release
/// document; no body type implements it yet, so nothing references this
/// constant internally.
#[allow(dead_code)]
pub const TAG_RELEASE: &str = "release";

/// A body type that can be wrapped in [`Signed`]; supplies the domain
/// separation tag from protocol.md 2.1's closed list.
pub trait SignedBody: Serialize + DeserializeOwned {
    /// This body's `type` tag.
    const TAG: &'static str;
}

/// `Signed(type) = CBOR array [ bstr body, bstr sig ]`, where
/// `sig = Ed25519("menzil.v1." || type || 0x00 || body)` (protocol.md
/// 2.1).
///
/// The encoded body bytes are kept verbatim, never re-encoded: "a
/// verifier keeps and forwards the signed bytes verbatim." `T` is
/// therefore only ever materialized on demand, via [`Signed::decode`],
/// which also runs the strict CBOR check before typed decoding.
pub struct Signed<T> {
    body_bytes: Vec<u8>,
    signature: [u8; 64],
    _marker: PhantomData<T>,
}

impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            body_bytes: self.body_bytes.clone(),
            signature: self.signature,
            _marker: PhantomData,
        }
    }
}

impl<T> fmt::Debug for Signed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("body_bytes", &hex_preview(&self.body_bytes))
            .field("signature", &hex_preview(&self.signature))
            .finish()
    }
}

impl<T> PartialEq for Signed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.body_bytes == other.body_bytes && self.signature == other.signature
    }
}

impl<T> Eq for Signed<T> {}

fn hex_preview(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

impl<T: SignedBody> Signed<T> {
    /// Encodes `body` (definite-length CBOR; ciborium's serializer always
    /// knows struct/seq/map sizes up front) and signs the domain
    /// separated message over the resulting bytes.
    pub fn sign(signing_key: &SigningKey, body: &T) -> Result<Self, ProtoError> {
        let mut body_bytes = Vec::new();
        ciborium::into_writer(body, &mut body_bytes)
            .map_err(|e| ProtoError::Encode(e.to_string()))?;
        let signature = signing_key.sign(&Self::signed_message(&body_bytes));
        Ok(Self {
            body_bytes,
            signature: signature.to_bytes(),
            _marker: PhantomData,
        })
    }

    /// Verifies the signature over the stored body bytes against
    /// `verifying_key`, using the malleability-resistant `verify_strict`.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), ProtoError> {
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify_strict(&Self::signed_message(&self.body_bytes), &signature)
            .map_err(ProtoError::from)
    }

    /// Strictly decodes the stored body bytes into `T`: the raw
    /// structural scan (definite lengths only) first, then a
    /// `deny_unknown_fields` typed decode.
    pub fn decode(&self) -> Result<T, ProtoError> {
        strict::check_definite_lengths(&self.body_bytes)?;
        ciborium::from_reader(&self.body_bytes[..]).map_err(|e| ProtoError::Decode(e.to_string()))
    }

    fn signed_message(body_bytes: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(b"menzil.v1.".len() + T::TAG.len() + 1 + body_bytes.len());
        msg.extend_from_slice(b"menzil.v1.");
        msg.extend_from_slice(T::TAG.as_bytes());
        msg.push(0x00);
        msg.extend_from_slice(body_bytes);
        msg
    }
}

impl<T> Signed<T> {
    /// The exact encoded body bytes, kept verbatim for verbatim
    /// forwarding (protocol.md 2.1).
    pub fn body_bytes(&self) -> &[u8] {
        &self.body_bytes
    }

    /// The raw 64-byte Ed25519 signature.
    pub fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Serializes as a plain CBOR byte string, bypassing serde's generic
/// sequence-of-integers handling for `&[u8]`.
struct RawBytes<'a>(&'a [u8]);

impl Serialize for RawBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// Deserializes a plain CBOR byte string into an owned buffer, the
/// counterpart to [`RawBytes`].
struct RawBytesBuf(Vec<u8>);

impl<'de> Deserialize<'de> for RawBytesBuf {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = RawBytesBuf;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a byte string")
            }

            fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(RawBytesBuf(v.to_vec()))
            }

            fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
                Ok(RawBytesBuf(v.to_vec()))
            }

            fn visit_byte_buf<E: DeError>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(RawBytesBuf(v))
            }
        }
        deserializer.deserialize_bytes(V)
    }
}

impl<T> Serialize for Signed<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(2))?;
        seq.serialize_element(&RawBytes(&self.body_bytes))?;
        seq.serialize_element(&RawBytes(&self.signature))?;
        seq.end()
    }
}

struct SignedVisitor<T>(PhantomData<T>);

impl<'de, T> Visitor<'de> for SignedVisitor<T> {
    type Value = Signed<T>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a 2-element array [body: bstr, sig: bstr]")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let body: RawBytesBuf = seq
            .next_element()?
            .ok_or_else(|| DeError::invalid_length(0, &self))?;
        let sig: RawBytesBuf = seq
            .next_element()?
            .ok_or_else(|| DeError::invalid_length(1, &self))?;
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(DeError::invalid_length(3, &self));
        }
        let signature: [u8; 64] = sig
            .0
            .try_into()
            .map_err(|_| DeError::custom("Signed: signature must be exactly 64 bytes"))?;
        Ok(Signed {
            body_bytes: body.0,
            signature,
            _marker: PhantomData,
        })
    }
}

impl<'de, T> Deserialize<'de> for Signed<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_seq(SignedVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};

    #[derive(Debug, Clone, PartialEq, Eq, SerdeSerialize, SerdeDeserialize)]
    #[serde(deny_unknown_fields)]
    struct Greeting {
        v: u16,
        text: String,
    }

    impl SignedBody for Greeting {
        const TAG: &'static str = "greeting-test-only";
    }

    fn keypair() -> SigningKey {
        SigningKey::generate(&mut rand::rng())
    }

    #[test]
    fn sign_verify_decode_round_trips() {
        let signing_key = keypair();
        let body = Greeting {
            v: 1,
            text: "hello".to_string(),
        };
        let signed = Signed::sign(&signing_key, &body).unwrap();
        signed.verify(&signing_key.verifying_key()).unwrap();
        assert_eq!(signed.decode().unwrap(), body);
    }

    #[test]
    fn signed_round_trips_through_cbor_as_two_element_array() {
        let signing_key = keypair();
        let body = Greeting {
            v: 1,
            text: "hi".to_string(),
        };
        let signed = Signed::sign(&signing_key, &body).unwrap();

        let mut buf = Vec::new();
        ciborium::into_writer(&signed, &mut buf).unwrap();
        let decoded: Signed<Greeting> = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded, signed);
        decoded.verify(&signing_key.verifying_key()).unwrap();
        assert_eq!(decoded.decode().unwrap(), body);
    }

    #[test]
    fn tampering_with_body_bytes_fails_verification() {
        let signing_key = keypair();
        let body = Greeting {
            v: 1,
            text: "hello".to_string(),
        };
        let mut signed = Signed::sign(&signing_key, &body).unwrap();
        let last = signed.body_bytes.len() - 1;
        signed.body_bytes[last] ^= 0xff;
        assert!(signed.verify(&signing_key.verifying_key()).is_err());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signing_key = keypair();
        let other_key = keypair();
        let body = Greeting {
            v: 1,
            text: "hello".to_string(),
        };
        let signed = Signed::sign(&signing_key, &body).unwrap();
        assert!(signed.verify(&other_key.verifying_key()).is_err());
    }

    #[test]
    fn decode_rejects_unknown_field() {
        // A body CBOR-shaped like Greeting but with an extra key.
        #[derive(SerdeSerialize)]
        struct GreetingPlusExtra {
            v: u16,
            text: String,
            extra: bool,
        }
        let signing_key = keypair();
        let mut body_bytes = Vec::new();
        ciborium::into_writer(
            &GreetingPlusExtra {
                v: 1,
                text: "hi".to_string(),
                extra: true,
            },
            &mut body_bytes,
        )
        .unwrap();
        let msg = {
            let mut m = b"menzil.v1.".to_vec();
            m.extend_from_slice(Greeting::TAG.as_bytes());
            m.push(0x00);
            m.extend_from_slice(&body_bytes);
            m
        };
        let signature = signing_key.sign(&msg).to_bytes();
        let signed: Signed<Greeting> = Signed {
            body_bytes,
            signature,
            _marker: PhantomData,
        };
        signed.verify(&signing_key.verifying_key()).unwrap();
        assert!(signed.decode().is_err());
    }
}
