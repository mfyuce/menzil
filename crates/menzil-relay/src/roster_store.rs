//! The relay's held Rosters (protocol.md 2.3, 4.3): "Relays keep the
//! newest Roster per network they are configured to serve (by
//! NetworkId) and refuse Rosters of other networks."
//!
//! How a Roster gets into this store over the wire (DOC records, in
//! both directions) is TODO.md L3f's job, not here: this only verifies
//! and holds whatever it's handed — an operator seeding a relay's
//! initial Rosters out of band today, or a DOC handler calling
//! [`RosterStore::set`] once L3f exists — and answers the queries HELLO
//! validation (protocol.md 4.1) needs against it.

use std::collections::HashMap;
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;
use menzil_proto::{NetworkId, NodeId, Roster, RosterBody};

use crate::error::RelayError;

/// The relay's held Rosters, at most one per network. Each is verified
/// against its own claimed `network_id` (protocol.md 2.3: `NetworkId`
/// *is* the network owner's Ed25519 public key) before it is accepted;
/// only the decoded body is retained; L3f will need to keep the signed
/// bytes too, for forwarding them verbatim (protocol.md 2.1), but nothing
/// in this item reads a Roster back out for that, so it isn't stored yet.
#[derive(Default)]
pub struct RosterStore {
    by_network: RwLock<HashMap<NetworkId, RosterBody>>,
}

impl RosterStore {
    /// An empty store, serving no networks yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `roster`'s signature against its own claimed
    /// `network_id`, then stores it — unless a Roster already held for
    /// that network has an equal or higher `seq` (protocol.md 2.3: "it
    /// never accepts a lower seq"; equal is treated the same as lower,
    /// since there is nothing newer to adopt).
    pub fn set(&self, roster: &Roster) -> Result<(), RelayError> {
        let body = roster.decode()?;
        let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.network_id))?;
        roster.verify(&verifying_key)?;

        let mut guard = self.by_network.write().unwrap();
        if let Some(existing) = guard.get(&body.network_id)
            && body.seq <= existing.seq
        {
            return Ok(());
        }
        guard.insert(body.network_id, body);
        Ok(())
    }

    /// The currently held Roster body for `network_id`, if any.
    pub fn get(&self, network_id: &NetworkId) -> Option<RosterBody> {
        self.by_network.read().unwrap().get(network_id).cloned()
    }

    /// Every held network's current `seq`, for WELCOME's `rosters` field
    /// (protocol.md 4.1, 4.3).
    pub fn seqs(&self) -> HashMap<NetworkId, u64> {
        self.by_network
            .read()
            .unwrap()
            .iter()
            .map(|(id, body)| (*id, body.seq))
            .collect()
    }

    /// The strictest `min_serial` this NodeId is subject to, across
    /// every network's Roster this relay holds where it is listed as a
    /// member (protocol.md 4.1: "rejects a serial lower than... any
    /// Roster's `min_serial` for that node" — read as every held
    /// Roster, not only whichever networks a given HELLO happens to
    /// claim: a stale, compromised NodeCert should not become usable
    /// again just by a HELLO that omits the network where it was
    /// flagged).
    pub fn min_serial_for(&self, node_id: &NodeId) -> Option<u32> {
        self.by_network
            .read()
            .unwrap()
            .values()
            .filter_map(|body| {
                body.members
                    .iter()
                    .find(|member| &member.node_id == node_id)
                    .map(|member| member.min_serial)
            })
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{Roster, RosterBody, RosterMember};

    fn signed_roster(owner: &SigningKey, network_id: NetworkId, seq: u64) -> Roster {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id: NodeId::from([9u8; 32]),
                min_serial: 3,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    #[test]
    fn set_then_get_round_trips() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = RosterStore::new();
        store.set(&signed_roster(&owner, network_id, 1)).unwrap();
        let body = store.get(&network_id).unwrap();
        assert_eq!(body.seq, 1);
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
        store.set(&signed_roster(&owner, network_id, 5)).unwrap();
        store.set(&signed_roster(&owner, network_id, 5)).unwrap();
        store.set(&signed_roster(&owner, network_id, 3)).unwrap();
        assert_eq!(store.get(&network_id).unwrap().seq, 5);
    }

    #[test]
    fn a_higher_seq_replaces_the_held_roster() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = RosterStore::new();
        store.set(&signed_roster(&owner, network_id, 1)).unwrap();
        store.set(&signed_roster(&owner, network_id, 2)).unwrap();
        assert_eq!(store.get(&network_id).unwrap().seq, 2);
    }

    #[test]
    fn min_serial_for_finds_the_strictest_across_networks() {
        let owner_a = SigningKey::generate(&mut rand::rng());
        let owner_b = SigningKey::generate(&mut rand::rng());
        let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
        let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);

        let store = RosterStore::new();
        let body_a = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id: network_a,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id,
                min_serial: 2,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        let body_b = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id: network_b,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id,
                min_serial: 7,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        store
            .set(&Roster::sign(&owner_a, &body_a).unwrap())
            .unwrap();
        store
            .set(&Roster::sign(&owner_b, &body_b).unwrap())
            .unwrap();

        assert_eq!(store.min_serial_for(&node_id), Some(7));
        assert_eq!(store.min_serial_for(&NodeId::from([1u8; 32])), None);
    }
}
