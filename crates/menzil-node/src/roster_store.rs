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
use std::sync::{Arc, RwLock, RwLockWriteGuard};

use ed25519_dalek::VerifyingKey;
use menzil_proto::trust::{Bundle, HeldRoster, HeldView, Signer, Verdict, check_bundle};
use menzil_proto::{NetworkId, ProtoError, Roster, RosterBody};

use crate::error::NodeError;

/// This node's held Rosters, at most one per network. The decoded
/// [`RosterBody`] is kept behind an [`Arc`] (not inline) so [`Self::body`]
/// is a cheap pointer clone regardless of document size — a red-team
/// review of `crate::policy_store` (TODO.md L4c) measured an inline clone
/// of a near-[`menzil_proto::MAX_DOC_BYTES`] document at several
/// milliseconds, a real cost once something calls this on every OPEN
/// rather than only at the rate-limited L4 handshake.
#[derive(Default)]
pub struct RosterStore {
    by_network: RwLock<HashMap<NetworkId, Held>>,
}

/// One held Roster: the signed form, its decoded body, who signed it and, when a steward did,
/// the owner signed base it was made from (a steward signed Roster is never held without it).
pub(crate) struct Held {
    signed: Roster,
    body: Arc<RosterBody>,
    base: Option<Roster>,
    signer: Signer,
    view: HeldRoster,
}

impl Held {
    /// The entry for `roster`, signed by `signer`, from `base` when a steward signed it.
    /// The caller has already verified both (see [`check_bundle`]).
    pub(crate) fn new(
        roster: &Roster,
        base: Option<&Roster>,
        signer: Signer,
    ) -> Result<Self, NodeError> {
        let view = HeldRoster::new(roster, base).map_err(NodeError::DocumentRejected)?;
        Ok(Self {
            signed: roster.clone(),
            body: Arc::new(roster.decode()?),
            base: base.cloned(),
            signer,
            view,
        })
    }

    pub(crate) fn seq(&self) -> u64 {
        self.body.seq
    }

    pub(crate) fn view(&self) -> &HeldRoster {
        &self.view
    }
}

/// The write guard of a [`RosterStore`], for [`crate::DocStore`], which takes it before the
/// Policy store's so that a Roster and Policy pair is adopted atomically.
pub(crate) type RosterMap = HashMap<NetworkId, Held>;

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
    ///
    /// For documents the owner signed and for tests and fixtures only: it checks neither the
    /// time rules of protocol.md 2.3 nor a pair. A steward signed Roster never passes it (the
    /// network key did not sign it). Everything this build adopts at run time goes through
    /// [`crate::DocStore::adopt`] or [`Self::adopt_owner`].
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
        if let Some(existing) = guard.get(&body.network_id)
            && body.seq <= existing.seq()
        {
            return Ok(false);
        }
        guard.insert(body.network_id, Held::new(roster, None, Signer::Owner)?);
        Ok(true)
    }

    /// Adopts `roster` if the network key signed it and it passes the acceptance predicate of
    /// protocol.md 2.3 at `now` (Unix seconds): newer than the held one, `issued` at most an
    /// hour ahead, `expires - issued` at most 14 days, not expired. Returns whether it was
    /// stored. A Roster a steward signed is refused (`MissingBase`): it is only adopted as part
    /// of a pair, by [`crate::DocStore::adopt`].
    pub fn adopt_owner(&self, roster: &Roster, now: u64) -> Result<bool, NodeError> {
        let network_id = roster.decode()?.network_id;
        let bundle = Bundle {
            roster: Some(roster.clone()),
            ..Bundle::default()
        };
        let encoded_len = roster.encode().len();
        if encoded_len > menzil_proto::MAX_DOC_BYTES {
            return Err(NodeError::DocumentTooLarge {
                len: encoded_len,
                max: menzil_proto::MAX_DOC_BYTES,
            });
        }
        let mut guard = self.by_network.write().unwrap();
        let view = HeldView {
            network_id,
            roster: guard.get(&network_id).map(|held| held.view().clone()),
            policy_seq: None,
        };
        match check_bundle(&view, &bundle, now) {
            Verdict::Adopt(adoption) => {
                guard.insert(network_id, Held::new(roster, None, adoption.signer)?);
                Ok(true)
            }
            Verdict::Held => Ok(false),
            Verdict::Reject(reason) => Err(NodeError::DocumentRejected(reason)),
        }
    }

    /// The write guard, for [`crate::DocStore`].
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, RosterMap> {
        self.by_network.write().unwrap()
    }

    /// The owner signed base a held steward signed Roster was made from. `None` when the
    /// held Roster is the owner's own, or nothing is held.
    pub fn base(&self, network_id: &NetworkId) -> Option<Roster> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .and_then(|held| held.base.clone())
    }

    /// Who signed the held Roster for `network_id`, if any is held.
    pub fn signer(&self, network_id: &NetworkId) -> Option<Signer> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|held| held.signer)
    }

    /// The currently held signed Roster for `network_id`, if any — the
    /// verbatim bytes DOC propagation sends on (protocol.md 2.1, 4.3).
    pub fn get(&self, network_id: &NetworkId) -> Option<Roster> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|held| held.signed.clone())
    }

    /// The currently held `seq` for `network_id`, if any — what HELLO's
    /// `roster_seq` (protocol.md 4.1) reports for a claimed network this
    /// node already holds something for.
    pub fn seq(&self, network_id: &NetworkId) -> Option<u64> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(Held::seq)
    }

    /// The currently held, decoded [`RosterBody`] for `network_id`, if
    /// any — for a caller (`crate::policy_store`) that needs to inspect
    /// `members`, `revoked`, or `expires` directly rather than only `seq`
    /// or the verbatim signed form. An [`Arc`] clone out from under the
    /// lock rather than a guard, matching [`Self::get`]; cheap regardless
    /// of call frequency (see this struct's own doc comment).
    pub fn body(&self, network_id: &NetworkId) -> Option<Arc<RosterBody>> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|held| held.body.clone())
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
