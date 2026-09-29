//! This node's own held Rosters (protocol.md 2.3, 4.3): "A node keeps
//! the newest Roster and Policy it has verified; it never accepts a
//! lower seq, and a reinstalled node accepts the first seq it
//! verifies." Policy is out of scope here (end to end only, protocol.md
//! 4.3, 5.5) — this only ever holds Rosters.
//!
//! Persists only for this process's lifetime (no on-disk store exists
//! yet, the same flagged gap `menzil-node`'s identity and replay-defense
//! state already carry). Meant to be owned by the caller across
//! reconnects, unlike a [`crate::Session`] (rebuilt on every reconnect
//! attempt): what this node already holds should survive a dropped link,
//! not be forgotten and relearned every time.

use std::collections::HashMap;
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;
use menzil_proto::{NetworkId, ProtoError, Roster, RosterBody};

use crate::error::NodeError;

/// This node's held Rosters, at most one per network.
#[derive(Default)]
pub struct RosterStore {
    by_network: RwLock<HashMap<NetworkId, (Roster, RosterBody)>>,
}

impl RosterStore {
    /// An empty store, holding nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `roster`'s signature against its own claimed
    /// `network_id`, then stores it unless a Roster already held for
    /// that network has an equal or higher `seq` (protocol.md 2.3: "it
    /// never accepts a lower seq"). Returns whether it was actually
    /// stored.
    ///
    /// Rejects a Roster whose encoded form exceeds
    /// [`menzil_proto::MAX_DOC_BYTES`] before ever storing it — see
    /// `menzil-relay`'s identical `RosterStore::set` for why.
    pub fn set(&self, roster: &Roster) -> Result<bool, NodeError> {
        let body = roster.decode()?;
        let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.network_id))
            .map_err(ProtoError::from)?;
        roster.verify(&verifying_key)?;
        let encoded_len = roster.encode().len();
        if encoded_len > menzil_proto::MAX_DOC_BYTES {
            return Err(NodeError::DocumentTooLarge {
                len: encoded_len,
                max: menzil_proto::MAX_DOC_BYTES,
            });
        }

        let mut guard = self.by_network.write().unwrap();
        if let Some((_, existing)) = guard.get(&body.network_id)
            && body.seq <= existing.seq
        {
            return Ok(false);
        }
        guard.insert(body.network_id, (roster.clone(), body));
        Ok(true)
    }

    /// The currently held signed Roster for `network_id`, if any — the
    /// verbatim bytes DOC propagation sends on (protocol.md 2.1, 4.3).
    pub fn get(&self, network_id: &NetworkId) -> Option<Roster> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|(signed, _)| signed.clone())
    }

    /// The currently held `seq` for `network_id`, if any — what HELLO's
    /// `roster_seq` (protocol.md 4.1) reports for a claimed network this
    /// node already holds something for.
    pub fn seq(&self, network_id: &NetworkId) -> Option<u64> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|(_, body)| body.seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::RosterMember;

    fn signed_roster(owner: &SigningKey, network_id: NetworkId, seq: u64) -> Roster {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id: menzil_proto::NodeId::from([9u8; 32]),
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    #[test]
    fn set_then_get_and_seq_round_trip() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = RosterStore::new();
        let roster = signed_roster(&owner, network_id, 4);
        assert!(store.set(&roster).unwrap());
        assert_eq!(store.get(&network_id), Some(roster));
        assert_eq!(store.seq(&network_id), Some(4));
    }

    #[test]
    fn an_unheld_network_reports_none() {
        let store = RosterStore::new();
        assert_eq!(store.seq(&NetworkId::from([1u8; 32])), None);
        assert_eq!(store.get(&NetworkId::from([1u8; 32])), None);
    }

    #[test]
    fn a_roster_not_signed_by_its_own_claimed_network_id_is_rejected() {
        let owner = SigningKey::generate(&mut rand::rng());
        let wrong_id = NetworkId::from([0x11; 32]);
        let store = RosterStore::new();
        assert!(store.set(&signed_roster(&owner, wrong_id, 1)).is_err());
        assert!(store.get(&wrong_id).is_none());
    }

    #[test]
    fn a_lower_or_equal_seq_does_not_replace_the_held_roster() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = RosterStore::new();
        assert!(store.set(&signed_roster(&owner, network_id, 5)).unwrap());
        assert!(!store.set(&signed_roster(&owner, network_id, 5)).unwrap());
        assert!(!store.set(&signed_roster(&owner, network_id, 3)).unwrap());
        assert_eq!(store.seq(&network_id), Some(5));
    }

    #[test]
    fn a_higher_seq_replaces_the_held_roster() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = RosterStore::new();
        store.set(&signed_roster(&owner, network_id, 1)).unwrap();
        assert!(store.set(&signed_roster(&owner, network_id, 2)).unwrap());
        assert_eq!(store.seq(&network_id), Some(2));
    }

    #[test]
    fn a_roster_over_the_document_size_limit_is_rejected_not_stored() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let members: Vec<RosterMember> = (0..40_000)
            .map(|i| RosterMember {
                node_id: menzil_proto::NodeId::from([(i % 256) as u8; 32]),
                min_serial: i,
            })
            .collect();
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members,
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        let roster = Roster::sign(&owner, &body).unwrap();
        assert!(roster.encode().len() > menzil_proto::MAX_DOC_BYTES);

        let store = RosterStore::new();
        let err = store.set(&roster).unwrap_err();
        assert!(matches!(err, NodeError::DocumentTooLarge { .. }));
        assert!(store.get(&network_id).is_none());
    }
}
