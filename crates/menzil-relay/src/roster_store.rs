//! The relay's held Rosters (protocol.md 2.3, 4.3): "Relays keep the
//! newest Roster per network they are configured to serve (by
//! NetworkId) and refuse Rosters of other networks."
//!
//! How a Roster gets into this store over the wire (DOC records, in
//! both directions, TODO.md L3f) is `crate::doc`'s job, not here: this
//! only verifies and holds whatever it's handed — an operator seeding a
//! relay's initial Rosters out of band, or the DOC handler calling
//! [`RosterStore::set`] once a transfer completes — and answers the
//! queries HELLO validation (protocol.md 4.1) and DOC propagation
//! (protocol.md 4.3) need against it.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;
use menzil_proto::{NetworkId, NodeId, Roster, RosterBody};

use crate::error::RelayError;

/// The relay's held Rosters, at most one per network. Each is verified
/// against its own claimed `network_id` (protocol.md 2.3: `NetworkId`
/// *is* the network owner's Ed25519 public key) before it is accepted.
/// The signed `Roster` itself is kept, not just its decoded body: DOC
/// propagation (protocol.md 4.3) forwards the signed bytes verbatim
/// (protocol.md 2.1), never re-encoding them.
#[derive(Default)]
pub struct RosterStore {
    by_network: RwLock<HashMap<NetworkId, (Roster, RosterBody)>>,
}

impl RosterStore {
    /// An empty store, serving no networks yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `roster`'s signature against its own claimed
    /// `network_id`, then stores it unless a Roster already held for
    /// that network has an equal or higher `seq` (protocol.md 2.3: "it
    /// never accepts a lower seq"; equal is treated the same as lower,
    /// since there is nothing newer to adopt). Returns whether it was
    /// actually stored, so a caller knows whether this is genuinely news
    /// worth propagating (protocol.md 4.3) or a stale/duplicate resend.
    ///
    /// Rejects a Roster whose encoded form exceeds
    /// [`menzil_proto::MAX_DOC_BYTES`] before ever storing it: a Roster
    /// this large could never actually be forwarded over DOC
    /// (`menzil_proto::split_into_doc_records` treats that limit as a
    /// hard invariant, not something it can fail gracefully on), so
    /// storing it anyway would only defer the failure to every later
    /// attempt at propagating or catching a member up on it.
    pub fn set(&self, roster: &Roster) -> Result<bool, RelayError> {
        let body = roster.decode()?;
        let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.network_id))?;
        roster.verify(&verifying_key)?;
        let encoded_len = roster.encode().len();
        if encoded_len > menzil_proto::MAX_DOC_BYTES {
            return Err(RelayError::DocumentTooLarge {
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

    /// The currently held Roster body for `network_id`, if any.
    pub fn get(&self, network_id: &NetworkId) -> Option<RosterBody> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|(_, body)| body.clone())
    }

    /// The currently held *signed* Roster for `network_id`, if any — the
    /// verbatim bytes DOC propagation sends on (protocol.md 2.1, 4.3).
    pub fn signed(&self, network_id: &NetworkId) -> Option<Roster> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|(signed, _)| signed.clone())
    }

    /// Every held network's current `seq`, for WELCOME's `rosters` field
    /// (protocol.md 4.1, 4.3).
    pub fn seqs(&self) -> HashMap<NetworkId, u64> {
        self.by_network
            .read()
            .unwrap()
            .iter()
            .map(|(id, (_, body))| (*id, body.seq))
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
            .filter_map(|(_, body)| {
                body.members
                    .iter()
                    .find(|member| &member.node_id == node_id)
                    .map(|member| member.min_serial)
            })
            .max()
    }

    /// Every name granted to `node_id` in the Roster of any of
    /// `networks` this relay holds (protocol.md 4.4: "the Roster of one
    /// of the node's networks lists that name for this NodeId in
    /// labels" — read as one of the networks *this node itself claimed*,
    /// the same restriction `min_serial_for`'s own doc comment discusses
    /// for a different check: a relay may happen to serve a network this
    /// node never claimed in HELLO, and that network's Roster granting
    /// the name to this NodeId must not let it claim the name through a
    /// session that never asked to be part of that network at all).
    /// Names come back ASCII-lowercased, for case-insensitive membership
    /// testing by the caller: two Rosters could otherwise grant what a
    /// viewer would consider "the same" name to two different nodes just
    /// by differing in case.
    ///
    /// A network's `labels` only counts if `node_id` is *currently* a
    /// member of that same Roster and not revoked from it — mirroring
    /// `crate::hello::check_hello`'s own membership/revocation checks
    /// (checked in the same order, revocation first: a Roster naming a
    /// node in both `revoked` and `members` is possible to construct,
    /// nothing here assumes an owner's tooling always keeps `labels` in
    /// sync with a later revocation, and revocation must still win).
    /// protocol.md 4.4's "lists that name for this NodeId in labels" is
    /// read together with 2.3's membership model, not as a bare,
    /// unconditional lookup into `labels` alone: a `labels` entry
    /// surviving a Roster update that also revoked or dropped the same
    /// NodeId must not still authorize a claim.
    ///
    /// Returns the whole set in one call rather than answering one name
    /// at a time, so a caller validating a whole ADVERTISE body's share
    /// list only pays for one scan of the held Rosters, not one scan per
    /// share (see `crate::advertise::LabelRegistry::advertise`'s own doc
    /// comment for why the difference mattered in practice).
    pub fn labels_granted_to(&self, networks: &[NetworkId], node_id: &NodeId) -> HashSet<String> {
        let guard = self.by_network.read().unwrap();
        networks
            .iter()
            .filter_map(|id| guard.get(id))
            .filter(|(_, body)| {
                !body
                    .revoked
                    .iter()
                    .any(|revoked| &revoked.node_id == node_id)
                    && body.members.iter().any(|member| &member.node_id == node_id)
            })
            .flat_map(|(_, body)| body.labels.iter())
            .filter(|label| &label.node_id == node_id)
            .map(|label| label.name.to_ascii_lowercase())
            .collect()
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
        assert!(store.set(&signed_roster(&owner, network_id, 1)).unwrap());
        let body = store.get(&network_id).unwrap();
        assert_eq!(body.seq, 1);
    }

    #[test]
    fn signed_returns_the_verbatim_roster() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = RosterStore::new();
        let roster = signed_roster(&owner, network_id, 1);
        store.set(&roster).unwrap();
        assert_eq!(store.signed(&network_id).unwrap(), roster);
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
        assert_eq!(store.get(&network_id).unwrap().seq, 5);
    }

    #[test]
    fn a_higher_seq_replaces_the_held_roster() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = RosterStore::new();
        store.set(&signed_roster(&owner, network_id, 1)).unwrap();
        assert!(store.set(&signed_roster(&owner, network_id, 2)).unwrap());
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

    #[test]
    fn a_roster_over_the_document_size_limit_is_rejected_not_stored() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        // Comfortably over menzil_proto::MAX_DOC_BYTES (1 MiB) once
        // encoded; a real Roster this large could never be sent back out
        // over DOC (`split_into_doc_records` panics past that limit), so
        // `set` must catch it before storing, not after.
        let members: Vec<RosterMember> = (0..40_000)
            .map(|i| RosterMember {
                node_id: NodeId::from([(i % 256) as u8; 32]),
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
        assert!(matches!(err, RelayError::DocumentTooLarge { .. }));
        assert!(store.get(&network_id).is_none());
    }

    fn roster_with_label(owner: &SigningKey, network_id: NetworkId, node_id: NodeId) -> Roster {
        roster_with_label_and_status(owner, network_id, node_id, true, false)
    }

    fn roster_with_label_and_status(
        owner: &SigningKey,
        network_id: NetworkId,
        node_id: NodeId,
        is_member: bool,
        is_revoked: bool,
    ) -> Roster {
        use menzil_proto::{Label, RevokedMember};
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: if is_member {
                vec![RosterMember {
                    node_id,
                    min_serial: 1,
                }]
            } else {
                vec![]
            },
            revoked: if is_revoked {
                vec![RevokedMember { node_id, since: 0 }]
            } else {
                vec![]
            },
            stewards: vec![],
            labels: vec![Label {
                name: "Example".to_string(),
                node_id,
            }],
        };
        Roster::sign(owner, &body).unwrap()
    }

    #[test]
    fn labels_granted_to_finds_a_claim_in_one_of_the_given_networks() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);
        let store = RosterStore::new();
        store
            .set(&roster_with_label(&owner, network_id, node_id))
            .unwrap();

        let granted = store.labels_granted_to(&[network_id], &node_id);
        assert!(granted.contains("example"), "{granted:?}");
    }

    #[test]
    fn labels_granted_to_lowercases_the_name() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);
        let store = RosterStore::new();
        // `roster_with_label` grants the mixed-case "Example".
        store
            .set(&roster_with_label(&owner, network_id, node_id))
            .unwrap();

        let granted = store.labels_granted_to(&[network_id], &node_id);
        assert_eq!(granted, HashSet::from(["example".to_string()]));
    }

    #[test]
    fn labels_granted_to_excludes_a_different_node_id() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);
        let other = NodeId::from([8u8; 32]);
        let store = RosterStore::new();
        store
            .set(&roster_with_label(&owner, network_id, node_id))
            .unwrap();

        assert!(store.labels_granted_to(&[network_id], &other).is_empty());
    }

    #[test]
    fn labels_granted_to_ignores_a_network_not_in_the_given_list() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);
        let unclaimed_other_network = NetworkId::from([0x22; 32]);
        let store = RosterStore::new();
        store
            .set(&roster_with_label(&owner, network_id, node_id))
            .unwrap();

        // The relay holds a Roster granting this label, but the caller
        // did not list `network_id` among the node's own claimed
        // networks (e.g. its HELLO never claimed it) — must not count.
        assert!(
            store
                .labels_granted_to(&[unclaimed_other_network], &node_id)
                .is_empty()
        );
        assert!(store.labels_granted_to(&[], &node_id).is_empty());
    }

    #[test]
    fn labels_granted_to_excludes_a_revoked_node_even_if_still_labeled() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);
        let store = RosterStore::new();
        // A Roster that names the same node in both `members` and
        // `revoked` (an owner's tooling might not always keep `labels`
        // in sync with a later revocation) — revocation must still win,
        // the same as `check_hello` checks it before membership.
        store
            .set(&roster_with_label_and_status(
                &owner, network_id, node_id, true, true,
            ))
            .unwrap();

        assert!(store.labels_granted_to(&[network_id], &node_id).is_empty());
    }

    #[test]
    fn labels_granted_to_excludes_a_node_no_longer_a_member() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);
        let store = RosterStore::new();
        // Not a member and not explicitly revoked either: a `labels`
        // entry surviving a member's outright removal must not still
        // authorize a claim.
        store
            .set(&roster_with_label_and_status(
                &owner, network_id, node_id, false, false,
            ))
            .unwrap();

        assert!(store.labels_granted_to(&[network_id], &node_id).is_empty());
    }
}
