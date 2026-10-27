//! The secret keys a node and a network owner hold.

use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::SigningKey;
use menzil_proto::{
    NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, StewardKey, X25519PublicKey,
};
use rand::Rng;
use zeroize::Zeroize;

use crate::AdminError;

/// How long a node certificate may be valid: protocol.md 2.2 says at most 400 days, and no
/// verifier enforces it, so the issuers do.
pub const MAX_CERT_LIFETIME_SECS: u64 = 400 * 24 * 60 * 60;

/// A node's secret material: the Ed25519 key its [`NodeId`] is the public
/// half of, and the X25519 key the Noise handshakes use (protocol.md 2.2).
/// They are independent: the X25519 key can be replaced by a certificate
/// with a higher serial while the NodeId stays.
#[derive(Clone)]
pub struct NodeKeys {
    signing: SigningKey,
    x25519_private: [u8; 32],
}

impl Drop for NodeKeys {
    /// The Ed25519 half wipes itself (`ed25519-dalek`); this wipes the X25519 half.
    fn drop(&mut self) {
        self.x25519_private.zeroize();
    }
}

impl std::fmt::Debug for NodeKeys {
    /// Prints the NodeId only: a derived `Debug` would put the private keys in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeKeys")
            .field("node_id", &self.node_id())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl NodeKeys {
    /// The length of [`Self::secret_bytes`].
    pub const SECRET_LEN: usize = 64;

    /// Fresh random keys.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut rand::rng());
        let mut x25519_private = [0u8; 32];
        rand::rng().fill_bytes(&mut x25519_private);
        Self {
            signing,
            x25519_private,
        }
    }

    /// The keys back from [`Self::secret_bytes`]. Any 32 bytes are a valid
    /// X25519 private key and any 32 bytes a valid Ed25519 seed, so the only
    /// thing to check is the length.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, AdminError> {
        let bytes: &[u8; Self::SECRET_LEN] =
            bytes.try_into().map_err(|_| AdminError::BadKeyLength {
                expected: Self::SECRET_LEN,
                found: bytes.len(),
            })?;
        let (seed, x25519) = bytes.split_at(32);
        Ok(Self {
            signing: SigningKey::from_bytes(seed.try_into().expect("32 bytes")),
            x25519_private: x25519.try_into().expect("32 bytes"),
        })
    }

    /// The Ed25519 seed followed by the X25519 private key: what a key file holds.
    pub fn secret_bytes(&self) -> [u8; Self::SECRET_LEN] {
        let mut out = [0u8; Self::SECRET_LEN];
        out[..32].copy_from_slice(&self.signing.to_bytes());
        out[32..].copy_from_slice(&self.x25519_private);
        out
    }

    /// The node's identity: its Ed25519 public key.
    pub fn node_id(&self) -> NodeId {
        NodeId::from(self.signing.verifying_key().to_bytes())
    }

    /// The Ed25519 key that signs this node's certificates.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }

    /// The X25519 private key for the Noise handshakes.
    pub fn x25519_private(&self) -> [u8; 32] {
        self.x25519_private
    }

    /// The X25519 public key a certificate binds to the NodeId.
    pub fn x25519_public(&self) -> X25519PublicKey {
        X25519PublicKey::from(MontgomeryPoint::mul_base_clamped(self.x25519_private).to_bytes())
    }

    /// A self-signed certificate (protocol.md 2.2) binding the NodeId to the
    /// X25519 key. `serial` goes up by one with every rotation; the window from `not_before` to
    /// `not_after` may not be longer than [`MAX_CERT_LIFETIME_SECS`] (400 days), which nothing
    /// else enforces.
    pub fn issue_cert(
        &self,
        serial: u32,
        not_before: u64,
        not_after: u64,
    ) -> Result<NodeCert, AdminError> {
        if not_after.saturating_sub(not_before) > MAX_CERT_LIFETIME_SECS {
            return Err(AdminError::CertLifetimeTooLong);
        }
        let body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: self.node_id(),
            x25519_pub: self.x25519_public(),
            serial,
            not_before,
            not_after,
        };
        Ok(NodeCert::sign(&self.signing, &body)?)
    }

    /// The renewal of `current` (protocol.md 2.2) with the same keys: the serial is one above
    /// the highest of `current`'s and `listed_max` (the highest serial of this node in any
    /// Policy held), `not_before` is one day before `now` (a peer whose clock is behind still
    /// sees it valid) and `not_after` is 400 days after that. Refused with
    /// [`AdminError::SerialExhausted`] when the serial cannot go up, and with
    /// [`AdminError::CertDoesNotVerify`] when `current` is not this node's certificate.
    pub fn next_cert(
        &self,
        current: &NodeCert,
        listed_max: Option<u32>,
        now: u64,
    ) -> Result<NodeCert, AdminError> {
        let body = current.decode()?;
        if body.node_id != self.node_id() {
            return Err(AdminError::CertDoesNotVerify);
        }
        let serial = body
            .serial
            .max(listed_max.unwrap_or(0))
            .checked_add(1)
            .ok_or(AdminError::SerialExhausted)?;
        let not_before = now.saturating_sub(24 * 60 * 60);
        self.issue_cert(
            serial,
            not_before,
            not_before.saturating_add(MAX_CERT_LIFETIME_SECS),
        )
    }
}

/// The key a network is named after: its public half is the
/// [`NetworkId`] (protocol.md 2.3), and every Roster and Policy of the
/// network is signed with it. Losing it ends the network, and a stolen one
/// is unrecoverable (protocol.md 7.3), so keep it offline.
#[derive(Clone)]
pub struct OwnerKey {
    signing: SigningKey,
}

impl std::fmt::Debug for OwnerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerKey")
            .field("network_id", &self.network_id())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl OwnerKey {
    /// The length of [`Self::secret_bytes`].
    pub const SECRET_LEN: usize = 32;

    /// A fresh random owner key, which is a new network.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut rand::rng()),
        }
    }

    /// The key back from [`Self::secret_bytes`].
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, AdminError> {
        let seed: &[u8; Self::SECRET_LEN] =
            bytes.try_into().map_err(|_| AdminError::BadKeyLength {
                expected: Self::SECRET_LEN,
                found: bytes.len(),
            })?;
        Ok(Self {
            signing: SigningKey::from_bytes(seed),
        })
    }

    /// The Ed25519 seed: what an owner key file holds.
    pub fn secret_bytes(&self) -> [u8; Self::SECRET_LEN] {
        self.signing.to_bytes()
    }

    /// The network this key owns.
    pub fn network_id(&self) -> NetworkId {
        NetworkId::from(self.signing.verifying_key().to_bytes())
    }

    /// The key documents are signed with.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

/// The secret half of a steward key (protocol.md 2.3, 7.3): the Ed25519 key a device signs
/// re-issues and admissions with on the owner's behalf. The device that will use it makes it
/// and keeps it; the owner only ever sees the public half ([`Self::public`]), in a request
/// token, and lists it in a `Steward` entry (`delegate_steward`). Named apart from
/// [`menzil_proto::StewardKey`], which is the public key.
#[derive(Clone)]
pub struct StewardSecret {
    signing: SigningKey,
}

impl std::fmt::Debug for StewardSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StewardSecret")
            .field("public", &self.public())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl StewardSecret {
    /// The length of [`Self::secret_bytes`].
    pub const SECRET_LEN: usize = 32;

    /// A fresh random steward key.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut rand::rng()),
        }
    }

    /// The key back from [`Self::secret_bytes`].
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, AdminError> {
        let seed: &[u8; Self::SECRET_LEN] =
            bytes.try_into().map_err(|_| AdminError::BadKeyLength {
                expected: Self::SECRET_LEN,
                found: bytes.len(),
            })?;
        Ok(Self {
            signing: SigningKey::from_bytes(seed),
        })
    }

    /// The Ed25519 seed: what a steward key file holds.
    pub fn secret_bytes(&self) -> [u8; Self::SECRET_LEN] {
        self.signing.to_bytes()
    }

    /// The public key the owner lists in the `Steward` entry.
    pub fn public(&self) -> StewardKey {
        StewardKey::from(self.signing.verifying_key().to_bytes())
    }

    /// The key documents are signed with.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_keys_round_trip_through_their_secret_bytes() {
        let keys = NodeKeys::generate();
        let again = NodeKeys::from_secret_bytes(&keys.secret_bytes()).unwrap();
        assert_eq!(again.node_id(), keys.node_id());
        assert_eq!(again.x25519_public(), keys.x25519_public());
        assert_eq!(again.x25519_private(), keys.x25519_private());
        assert_eq!(again.secret_bytes(), keys.secret_bytes());
    }

    #[test]
    fn two_generated_nodes_differ_in_both_keys() {
        let (a, b) = (NodeKeys::generate(), NodeKeys::generate());
        assert_ne!(a.node_id(), b.node_id());
        assert_ne!(a.x25519_public(), b.x25519_public());
    }

    #[test]
    fn the_ed25519_and_x25519_halves_are_independent() {
        // Swapping the halves of two key files swaps nothing else: the two
        // keys are not derived from one another.
        let (a, b) = (NodeKeys::generate(), NodeKeys::generate());
        let mut mixed = a.secret_bytes();
        mixed[32..].copy_from_slice(&b.x25519_private());
        let mixed = NodeKeys::from_secret_bytes(&mixed).unwrap();
        assert_eq!(mixed.node_id(), a.node_id());
        assert_eq!(mixed.x25519_public(), b.x25519_public());
    }

    #[test]
    fn the_x25519_public_key_is_the_one_snow_derives() {
        // The Noise implementation this project handshakes with must agree
        // that the certificate's public key belongs to the private one: a
        // handshake between two such keys completes.
        let params: snow::params::NoiseParams =
            "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
        let (initiator, responder) = (NodeKeys::generate(), NodeKeys::generate());
        let mut i = snow::Builder::new(params.clone())
            .local_private_key(&initiator.x25519_private())
            .unwrap()
            .remote_public_key(&<[u8; 32]>::from(responder.x25519_public()))
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut r = snow::Builder::new(params)
            .local_private_key(&responder.x25519_private())
            .unwrap()
            .build_responder()
            .unwrap();
        let mut buf = [0u8; 256];
        let mut out = [0u8; 256];
        let n = i.write_message(&[], &mut buf).unwrap();
        r.read_message(&buf[..n], &mut out).unwrap();
        let n = r.write_message(&[], &mut buf).unwrap();
        i.read_message(&buf[..n], &mut out).unwrap();
        assert!(i.is_handshake_finished() && r.is_handshake_finished());
        // And the initiator's static key as the responder learned it.
        assert_eq!(
            r.get_remote_static().unwrap(),
            &<[u8; 32]>::from(initiator.x25519_public())[..]
        );
    }

    #[test]
    fn a_node_cert_verifies_against_the_node_id_and_binds_the_x25519_key() {
        let keys = NodeKeys::generate();
        let cert = keys.issue_cert(3, 100, 200).unwrap();
        let body = cert.decode().unwrap();
        cert.verify(
            &ed25519_dalek::VerifyingKey::from_bytes(&<[u8; 32]>::from(keys.node_id())).unwrap(),
        )
        .unwrap();
        assert_eq!(body.node_id, keys.node_id());
        assert_eq!(body.x25519_pub, keys.x25519_public());
        assert_eq!(
            (body.serial, body.not_before, body.not_after),
            (3, 100, 200)
        );
    }

    /// protocol.md 2.2: a certificate is valid for at most 400 days, and no verifier checks.
    #[test]
    fn a_certificate_valid_for_longer_than_400_days_is_not_issued() {
        let keys = NodeKeys::generate();
        let day = 24 * 60 * 60;
        keys.issue_cert(1, 1000, 1000 + 400 * day).unwrap();
        assert_eq!(MAX_CERT_LIFETIME_SECS, 400 * day);
        for not_after in [1000 + 400 * day + 1, u64::MAX] {
            assert!(matches!(
                keys.issue_cert(1, 1000, not_after),
                Err(AdminError::CertLifetimeTooLong)
            ));
        }
        assert!(matches!(
            keys.issue_cert(7, 0, u64::MAX),
            Err(AdminError::CertLifetimeTooLong)
        ));
    }

    #[test]
    fn secret_bytes_of_the_wrong_length_are_refused() {
        for len in [0, 31, 33, 63, 65] {
            assert!(matches!(
                NodeKeys::from_secret_bytes(&vec![0u8; len]),
                Err(AdminError::BadKeyLength { expected: 64, found }) if found == len
            ));
        }
        for len in [0, 31, 33, 64] {
            assert!(matches!(
                OwnerKey::from_secret_bytes(&vec![0u8; len]),
                Err(AdminError::BadKeyLength { expected: 32, found }) if found == len
            ));
        }
        // And the message names the right length for each kind of key.
        let node = NodeKeys::from_secret_bytes(&[0u8; 5])
            .unwrap_err()
            .to_string();
        let owner = OwnerKey::from_secret_bytes(&[0u8; 5])
            .unwrap_err()
            .to_string();
        assert!(
            node.contains("64") && owner.contains("32"),
            "{node} / {owner}"
        );
    }

    #[test]
    fn debug_output_never_shows_secret_bytes() {
        let keys = NodeKeys::generate();
        let owner = OwnerKey::generate();
        let shown = format!("{keys:?} {owner:?}");
        assert!(shown.contains("redacted"));
        for secret in [keys.secret_bytes().to_vec(), owner.secret_bytes().to_vec()] {
            let hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
            assert!(!shown.contains(&hex));
            assert!(!shown.contains(&format!("{secret:?}")));
        }
    }

    #[test]
    fn an_owner_key_names_its_network() {
        let owner = OwnerKey::generate();
        let again = OwnerKey::from_secret_bytes(&owner.secret_bytes()).unwrap();
        assert_eq!(again.network_id(), owner.network_id());
        assert_eq!(
            <[u8; 32]>::from(owner.network_id()),
            owner.signing_key().verifying_key().to_bytes()
        );
    }

    #[test]
    fn a_steward_key_round_trips_and_never_shows_its_secret() {
        let key = StewardSecret::generate();
        let again = StewardSecret::from_secret_bytes(&key.secret_bytes()).unwrap();
        assert_eq!(again.public(), key.public());
        assert_ne!(StewardSecret::generate().public(), key.public());
        assert_eq!(
            <[u8; 32]>::from(key.public()),
            key.signing_key().verifying_key().to_bytes()
        );
        for len in [0, 31, 33, 64] {
            assert!(matches!(
                StewardSecret::from_secret_bytes(&vec![0u8; len]),
                Err(AdminError::BadKeyLength { expected: 32, found }) if found == len
            ));
        }
        let shown = format!("{key:?}");
        assert!(shown.contains("redacted"));
        let hex: String = key
            .secret_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!shown.contains(&hex));
    }
}
