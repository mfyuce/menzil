//! A node's local identity: the signed [`NodeCert`] binding its
//! [`NodeId`](menzil_proto::NodeId) to an X25519 static key (protocol.md
//! 2.2), plus that key's private half for the Noise handshake.
//!
//! Generating and persisting this — the Ed25519 keypair, file
//! permissions, NodeCert issuance and rotation (protocol.md 2.2) — is a
//! separate, not-yet-built concern; this type only carries what
//! [`crate::Session`] needs to run a handshake, supplied already
//! assembled by the caller. This follows the same precedent
//! `menzil-relay` set for its own TLS certificate material: "certificate
//! and key material is supplied to this crate already loaded."

use std::sync::{Arc, PoisonError, RwLock};

use ed25519_dalek::VerifyingKey;
use menzil_proto::trust::NODE_CERT_MAX_LIFETIME;
use menzil_proto::{NodeCert, ProtoError};

/// What a node needs of its own identity to run an L3 handshake
/// (protocol.md 4.1).
#[derive(Clone)]
pub struct LocalIdentity {
    /// This node's own certificate, sent as HELLO's `node_cert`.
    pub node_cert: NodeCert,
    /// The X25519 private key `node_cert`'s `x25519_pub` is bound to.
    pub x25519_private: [u8; 32],
}

impl std::fmt::Debug for LocalIdentity {
    /// Redacts `x25519_private`: a derived `Debug` would print the raw
    /// private key, and this type is exactly the kind of thing that ends
    /// up in a `tracing::debug!(?identity, ...)` by accident.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("node_cert", &self.node_cert)
            .field("x25519_private", &"<redacted>")
            .finish()
    }
}

/// Why [`IdentityCell::set`] refused a certificate. The cell is left as it was.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentityError {
    /// The offered certificate, or the one the cell holds, does not decode.
    #[error("a node certificate does not decode: {0}")]
    Undecodable(String),
    /// The offered certificate is for another `node_id`.
    #[error("the offered certificate is for another node_id")]
    OtherNode,
    /// The offered certificate binds another X25519 static key (a new key is a new identity).
    #[error("the offered certificate binds another x25519_pub")]
    OtherKey,
    /// The offered serial is not above the current one.
    #[error("the offered serial {offered} is not above the current serial {current}")]
    NotNewer {
        /// The serial the cell holds.
        current: u32,
        /// The serial offered.
        offered: u32,
    },
    /// The offered certificate is not signed by its own `node_id`.
    #[error("the offered certificate does not carry a valid signature by its node_id")]
    BadSignature,
    /// The offered certificate's validity window does not contain now.
    #[error("the offered certificate is not valid now")]
    NotValidNow,
    /// The offered certificate's window is over 400 days, or ends before it starts. Every
    /// steward and verifier refuses such a certificate, so the node must not present it.
    #[error("the offered certificate's validity window is over 400 days or ends before it starts")]
    WindowTooLong,
}

impl From<ProtoError> for IdentityError {
    fn from(error: ProtoError) -> Self {
        Self::Undecodable(error.to_string())
    }
}

struct Current {
    identity: Arc<LocalIdentity>,
    /// The serial of `identity.node_cert`; 0 (fails every floor) if the cert does not decode,
    /// which [`crate::Node::start`] and [`crate::RouterConfig::new`] refuse before it matters.
    serial: u32,
}

impl Current {
    fn new(identity: LocalIdentity) -> Self {
        let serial = identity.node_cert.decode().map_or(0, |body| body.serial);
        Self {
            identity: Arc::new(identity),
            serial,
        }
    }
}

/// The node's current [`LocalIdentity`], shared by everything that presents or checks the
/// node's own certificate: the HELLO builder (read at each connect), the router's handshake
/// payload, the standing checks (the serial). A clone is another handle to the same cell. A
/// reader takes the current value at each use and keeps it only for that use; no lock is held
/// across an `.await` (the lock is taken inside non-async functions only).
///
/// A renewal replaces the certificate through [`Self::set`], which accepts nothing but a newer
/// certificate of the same node and key (cert-rotation design, Q9).
#[derive(Clone)]
pub struct IdentityCell(Arc<RwLock<Current>>);

impl IdentityCell {
    /// A cell holding `identity`.
    pub fn new(identity: LocalIdentity) -> Self {
        Self(Arc::new(RwLock::new(Current::new(identity))))
    }

    /// The identity as it is now.
    pub fn get(&self) -> Arc<LocalIdentity> {
        Arc::clone(&self.read().identity)
    }

    /// The serial of the certificate as it is now.
    pub fn serial(&self) -> u32 {
        self.read().serial
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Current> {
        self.0.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the certificate with `new_cert` (the private key stays). Accepted only when it
    /// is for the same `node_id` and `x25519_pub`, has a strictly higher serial, carries a valid
    /// signature by its `node_id`, is valid at `now` (Unix seconds) and has a window of at most
    /// [`NODE_CERT_MAX_LIFETIME`] (what every verifier requires). Anything else returns
    /// an error and changes nothing.
    pub fn set(&self, new_cert: NodeCert, now: u64) -> Result<(), IdentityError> {
        let offered = new_cert.decode()?;
        // The write lock covers check and swap, so two renewals cannot both pass against the
        // same current serial.
        let mut guard = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let current = guard.identity.node_cert.decode()?;
        if offered.node_id != current.node_id {
            return Err(IdentityError::OtherNode);
        }
        if offered.x25519_pub != current.x25519_pub {
            return Err(IdentityError::OtherKey);
        }
        if offered.serial <= current.serial {
            return Err(IdentityError::NotNewer {
                current: current.serial,
                offered: offered.serial,
            });
        }
        let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(offered.node_id))
            .map_err(|_| IdentityError::BadSignature)?;
        new_cert
            .verify(&key)
            .map_err(|_| IdentityError::BadSignature)?;
        if !offered.is_valid_at(now) {
            return Err(IdentityError::NotValidNow);
        }
        if offered.not_after < offered.not_before
            || offered.not_after - offered.not_before > NODE_CERT_MAX_LIFETIME
        {
            return Err(IdentityError::WindowTooLong);
        }
        *guard = Current::new(LocalIdentity {
            node_cert: new_cert,
            x25519_private: guard.identity.x25519_private,
        });
        Ok(())
    }
}

impl From<LocalIdentity> for IdentityCell {
    fn from(identity: LocalIdentity) -> Self {
        Self::new(identity)
    }
}

impl std::fmt::Debug for IdentityCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("IdentityCell").field(&*self.get()).finish()
    }
}

/// Where a standing check reads the serial of this node's own certificate: a fixed number
/// (tests, callers without renewals) or the [`IdentityCell`], read at each use.
#[derive(Clone, Debug)]
pub struct OwnSerial(OwnSerialSource);

#[derive(Clone, Debug)]
enum OwnSerialSource {
    Fixed(u32),
    Cell(IdentityCell),
}

impl OwnSerial {
    /// The serial now.
    pub fn get(&self) -> u32 {
        match &self.0 {
            OwnSerialSource::Fixed(serial) => *serial,
            OwnSerialSource::Cell(cell) => cell.serial(),
        }
    }
}

impl From<u32> for OwnSerial {
    fn from(serial: u32) -> Self {
        Self(OwnSerialSource::Fixed(serial))
    }
}

impl From<IdentityCell> for OwnSerial {
    fn from(cell: IdentityCell) -> Self {
        Self(OwnSerialSource::Cell(cell))
    }
}

impl From<&IdentityCell> for OwnSerial {
    fn from(cell: &IdentityCell) -> Self {
        Self(OwnSerialSource::Cell(cell.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{NodeCertBody, NodeId, PROTOCOL_VERSION, X25519PublicKey};

    const NOW: u64 = 1_000_000;

    struct Who {
        signing: SigningKey,
        node_id: NodeId,
        x25519: X25519PublicKey,
    }

    fn who(seed: u8) -> Who {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        Who {
            node_id: NodeId::from(signing.verifying_key().to_bytes()),
            signing,
            x25519: X25519PublicKey::from([seed.wrapping_add(100); 32]),
        }
    }

    fn cert(who: &Who, serial: u32, not_before: u64, not_after: u64) -> NodeCert {
        NodeCert::sign(
            &who.signing,
            &NodeCertBody {
                v: PROTOCOL_VERSION,
                node_id: who.node_id,
                x25519_pub: who.x25519,
                serial,
                not_before,
                not_after,
            },
        )
        .unwrap()
    }

    fn cell_of(who: &Who, serial: u32) -> IdentityCell {
        IdentityCell::new(LocalIdentity {
            node_cert: cert(who, serial, 0, 2 * NOW),
            x25519_private: [7u8; 32],
        })
    }

    /// The cell still holds serial `serial` and the same bytes it held.
    fn assert_unchanged(cell: &IdentityCell, before: &NodeCert, serial: u32) {
        assert_eq!(cell.serial(), serial);
        assert_eq!(&cell.get().node_cert, before);
    }

    #[test]
    fn set_takes_a_higher_serial_of_the_same_node_and_key() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let newer = cert(&me, 4, NOW - 10, NOW + 1000);
        cell.set(newer.clone(), NOW).unwrap();
        assert_eq!(cell.serial(), 4);
        assert_eq!(cell.get().node_cert, newer);
        // The private key stays.
        assert_eq!(cell.get().x25519_private, [7u8; 32]);
        // A clone is the same cell.
        let other = cell.clone();
        other.set(cert(&me, 9, 0, 2 * NOW), NOW).unwrap();
        assert_eq!(cell.serial(), 9);
    }

    #[test]
    fn set_refuses_another_node_id() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let before = cell.get().node_cert.clone();
        let stranger = who(2);
        let offered = cert(&stranger, 4, 0, 2 * NOW);
        assert_eq!(cell.set(offered, NOW), Err(IdentityError::OtherNode));
        assert_unchanged(&cell, &before, 3);
    }

    #[test]
    fn set_refuses_another_x25519_key() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let before = cell.get().node_cert.clone();
        let rekeyed = Who {
            signing: me.signing.clone(),
            node_id: me.node_id,
            x25519: X25519PublicKey::from([55u8; 32]),
        };
        let offered = cert(&rekeyed, 4, 0, 2 * NOW);
        assert_eq!(cell.set(offered, NOW), Err(IdentityError::OtherKey));
        assert_unchanged(&cell, &before, 3);
    }

    #[test]
    fn set_refuses_a_lower_serial() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let before = cell.get().node_cert.clone();
        assert_eq!(
            cell.set(cert(&me, 2, 0, 2 * NOW), NOW),
            Err(IdentityError::NotNewer {
                current: 3,
                offered: 2
            })
        );
        assert_unchanged(&cell, &before, 3);
    }

    #[test]
    fn set_refuses_an_equal_serial() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let before = cell.get().node_cert.clone();
        // Same serial, different window: still not a renewal.
        assert_eq!(
            cell.set(cert(&me, 3, 5, 2 * NOW + 5), NOW),
            Err(IdentityError::NotNewer {
                current: 3,
                offered: 3
            })
        );
        assert_unchanged(&cell, &before, 3);
    }

    #[test]
    fn set_refuses_a_bad_signature() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let before = cell.get().node_cert.clone();
        // The right node_id and key in the body, signed by another key.
        let forger = who(9);
        let forged = NodeCert::sign(
            &forger.signing,
            &NodeCertBody {
                v: PROTOCOL_VERSION,
                node_id: me.node_id,
                x25519_pub: me.x25519,
                serial: 4,
                not_before: 0,
                not_after: 2 * NOW,
            },
        )
        .unwrap();
        assert_eq!(cell.set(forged, NOW), Err(IdentityError::BadSignature));
        assert_unchanged(&cell, &before, 3);
    }

    #[test]
    fn set_refuses_a_cert_not_valid_now() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let before = cell.get().node_cert.clone();
        let future = cert(&me, 4, NOW + 1, NOW + 100);
        assert_eq!(cell.set(future, NOW), Err(IdentityError::NotValidNow));
        let past = cert(&me, 4, 0, NOW - 1);
        assert_eq!(cell.set(past, NOW), Err(IdentityError::NotValidNow));
        assert_unchanged(&cell, &before, 3);
        // The window ends are inclusive, like `NodeCertBody::is_valid_at`.
        cell.set(cert(&me, 4, NOW, NOW), NOW).unwrap();
        assert_eq!(cell.serial(), 4);
    }

    #[test]
    fn set_refuses_a_window_over_the_maximum_lifetime() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let before = cell.get().node_cert.clone();
        // Ten years, valid now: every steward and verifier would refuse it.
        let ten_years = cert(&me, 4, 0, 10 * 365 * 86_400);
        assert_eq!(cell.set(ten_years, NOW), Err(IdentityError::WindowTooLong));
        assert_unchanged(&cell, &before, 3);
        // One second over the bound.
        let over = cert(&me, 4, 0, NODE_CERT_MAX_LIFETIME + 1);
        assert_eq!(cell.set(over, NOW), Err(IdentityError::WindowTooLong));
        assert_unchanged(&cell, &before, 3);
        // Exactly the bound is fine.
        cell.set(cert(&me, 4, 0, NODE_CERT_MAX_LIFETIME), NOW)
            .unwrap();
        assert_eq!(cell.serial(), 4);
    }

    #[test]
    fn own_serial_follows_the_cell_and_a_fixed_number_stays() {
        let me = who(1);
        let cell = cell_of(&me, 3);
        let from_cell = OwnSerial::from(&cell);
        let fixed = OwnSerial::from(3u32);
        assert_eq!((from_cell.get(), fixed.get()), (3, 3));
        cell.set(cert(&me, 4, 0, 2 * NOW), NOW).unwrap();
        assert_eq!((from_cell.get(), fixed.get()), (4, 3));
    }
}
