//! Fixed-size byte arrays that (de)serialize as CBOR byte strings (major
//! type 2), and the named identifier types built from them.
//!
//! A plain `[u8; N]` would serialize through serde's generic array impl as
//! a CBOR array of N small integers; every type here instead calls
//! `serialize_bytes`/`deserialize_bytes` so the wire form is a single CBOR
//! byte string, matching every `bytesNN` field in protocol.md.

use std::fmt;

use serde::de::{Deserialize, Deserializer, Error as DeError, Visitor};
use serde::ser::{Serialize, Serializer};

/// A fixed-size byte array encoded as a CBOR byte string.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> ByteArray<N> {
    /// Returns the underlying array.
    pub fn into_inner(self) -> [u8; N] {
        self.0
    }

    /// Formats the full value as lowercase hex.
    pub fn to_hex(&self) -> String {
        use fmt::Write as _;
        let mut s = String::with_capacity(N * 2);
        for byte in self.0 {
            let _ = write!(s, "{byte:02x}");
        }
        s
    }
}

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> From<ByteArray<N>> for [u8; N] {
    fn from(value: ByteArray<N>) -> Self {
        value.0
    }
}

impl<const N: usize> AsRef<[u8]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> fmt::Debug for ByteArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteArray<{N}>({})", self.to_hex())
    }
}

impl<const N: usize> fmt::Display for ByteArray<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl<const N: usize> Serialize for ByteArray<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

struct ByteArrayVisitor<const N: usize>;

impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
    type Value = ByteArray<N>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a byte string of length {N}")
    }

    fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
        <[u8; N]>::try_from(v)
            .map(ByteArray)
            .map_err(|_| E::invalid_length(v.len(), &self))
    }

    fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }

    fn visit_byte_buf<E: DeError>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&v)
    }
}

impl<'de, const N: usize> Deserialize<'de> for ByteArray<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(ByteArrayVisitor)
    }
}

/// Declares a nominal newtype around a fixed-width [`ByteArray`] so that,
/// for example, a `NodeId` and a `NetworkId` cannot be interchanged even
/// though both are 32 bytes wide.
macro_rules! byte_array_newtype {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub ByteArray<$len>);

        impl $name {
            /// Formats the full value as lowercase hex.
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl From<[u8; $len]> for $name {
            fn from(bytes: [u8; $len]) -> Self {
                Self(ByteArray(bytes))
            }
        }

        impl From<$name> for [u8; $len] {
            fn from(value: $name) -> Self {
                value.0.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                ByteArray::<$len>::deserialize(deserializer).map($name)
            }
        }
    };
}

byte_array_newtype!(
    /// A node's Ed25519 public key (protocol.md 2.2), the identity every
    /// role verifies against.
    NodeId,
    32
);

byte_array_newtype!(
    /// The X25519 static key a [`NodeCert`](crate::identity::NodeCert)
    /// binds to a [`NodeId`] for the Noise handshakes (protocol.md 2.2).
    X25519PublicKey,
    32
);

byte_array_newtype!(
    /// A network's owning Ed25519 public key (protocol.md 2.3). Distinct
    /// from [`NodeId`] even though both are 32 bytes: a network is never a
    /// node.
    NetworkId,
    32
);

byte_array_newtype!(
    /// Identifier of an [`Invite`](crate::invite::Invite) (protocol.md
    /// 7.2).
    InviteId,
    16
);

byte_array_newtype!(
    /// Correlation id for the chunks of one DOC transfer (protocol.md
    /// 4.2). Chosen by the sender; carries no meaning beyond reassembly.
    DocId,
    16
);

byte_array_newtype!(
    /// An unkeyed BLAKE2s-256 digest, used for
    /// [`Invite`](crate::invite::Invite)'s `secret_hash` (protocol.md 7.2).
    SecretHash,
    32
);

byte_array_newtype!(
    /// A steward's public key (protocol.md 2.3). The spec gives `bytes32`
    /// with no stated key type, so this is kept distinct from
    /// [`X25519PublicKey`] rather than assumed to be one.
    StewardKey,
    32
);

byte_array_newtype!(
    /// A TAI64N timestamp (protocol.md 4.1): `HELLO`'s `timestamp` field.
    /// Kept as an opaque 12-byte wire value; the only property protocol.md
    /// 4.1 actually relies on is monotonicity per node id ("rejects a
    /// timestamp not greater than the last accepted"), not exact TAI
    /// accuracy, and constructing one from the current time or comparing
    /// two is session behavior, not a wire concern, so no such helpers
    /// live here.
    Tai64N,
    12
);

impl NodeId {
    /// A short fingerprint of at least 80 bits (protocol.md 2.2): the
    /// first 10 bytes as lowercase hex. [`fmt::Display`] gives the full id
    /// for when that is what's wanted instead.
    pub fn fingerprint(&self) -> String {
        use fmt::Write as _;
        let bytes: &[u8] = self.as_ref();
        let mut s = String::with_capacity(20);
        for byte in &bytes[..10] {
            let _ = write!(s, "{byte:02x}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_array_round_trips_through_cbor() {
        let value = ByteArray::<4>([1, 2, 3, 4]);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        // A CBOR byte string of length 4: major type 2, definite length 4.
        assert_eq!(buf, vec![0x44, 1, 2, 3, 4]);
        let decoded: ByteArray<4> = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn byte_array_rejects_wrong_length() {
        let value = ByteArray::<4>([1, 2, 3, 4]);
        let mut buf = Vec::new();
        ciborium::into_writer(&value, &mut buf).unwrap();
        let result: Result<ByteArray<5>, _> = ciborium::from_reader(&buf[..]);
        assert!(result.is_err());
    }

    #[test]
    fn node_id_and_network_id_are_distinct_types() {
        let node = NodeId::from([7u8; 32]);
        let network = NetworkId::from([7u8; 32]);
        assert_eq!(node.as_ref(), network.as_ref());
        // Not the same type: this would not compile if it were.
        // let _: NodeId = network;
    }

    #[test]
    fn node_id_fingerprint_is_first_ten_bytes() {
        let mut raw = [0u8; 32];
        raw[..10].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5]);
        let node = NodeId::from(raw);
        assert_eq!(node.fingerprint(), "deadbeef000102030405");
        assert_eq!(node.fingerprint().len(), 20);
    }
}
