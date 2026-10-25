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
use std::sync::{Arc, RwLock};

use ed25519_dalek::VerifyingKey;
use menzil_proto::trust::{Bundle, HeldRoster, HeldView, Reason, Verdict, check_bundle};
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
    by_network: RwLock<HashMap<NetworkId, Held>>,
    /// Called after [`Self::adopt`] has stored a Roster (see [`Self::set_on_adopted`]).
    on_adopted: RwLock<Option<AdoptedHook>>,
}

/// The function a caller sets with [`RosterStore::set_on_adopted`]: the Roster just stored and,
/// for a steward signed one, its base.
type AdoptedHook = Arc<dyn Fn(&Roster, Option<&Roster>) + Send + Sync>;

/// One held Roster. A Roster a steward signed is held together with the owner signed base it
/// was made from, never without it: DOC propagation sends the base first (protocol.md 4.3),
/// and the base is what the next steward Roster is compared with.
struct Held {
    signed: Roster,
    body: RosterBody,
    base: Option<Roster>,
    view: HeldRoster,
    /// How many of the leading `members` carry a `min_serial` that counts: all of an owner
    /// signed Roster's, and for a steward signed one only those of its base. A steward appends
    /// members and cannot be checked against their certificates here (the relay holds Rosters
    /// only), so the `min_serial` it writes for them binds nothing, least of all across networks
    /// (the sixth red-team round, M4).
    counted: usize,
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
        if let Some(existing) = guard.get(&body.network_id)
            && body.seq <= existing.body.seq
        {
            return Ok(false);
        }
        let view = HeldRoster::new(roster, None).map_err(RelayError::DocumentRejected)?;
        guard.insert(
            body.network_id,
            Held {
                signed: roster.clone(),
                counted: body.members.len(),
                body,
                base: None,
                view,
            },
        );
        Ok(true)
    }

    /// Sets the function [`Self::adopt`] calls, once the lock is released, each time it has
    /// stored a Roster (arguments: the Roster and its base, a steward signed Roster's only).
    /// The library keeps no file paths: the caller decides whether, and where, an adopted
    /// Roster is kept, so that a restart does not roll the relay back to what it started with.
    /// One hook; a second call replaces the first. [`Self::set`] (fixtures) does not call it.
    pub fn set_on_adopted(&self, hook: impl Fn(&Roster, Option<&Roster>) + Send + Sync + 'static) {
        *self.on_adopted.write().unwrap() = Some(Arc::new(hook));
    }

    /// Adopts `roster` if the acceptance predicate of protocol.md 2.3
    /// ([`menzil_proto::trust::check_bundle`]) says so at `now` (Unix
    /// seconds): newer than the held one, `issued` at most an hour ahead,
    /// `expires - issued` at most 14 days, not expired, and either signed by
    /// the network key or signed by the steward its `base` names. `base` is
    /// the owner signed Roster a steward signed `roster` was made from
    /// (ignored for an owner signed one). A steward signed Roster with no
    /// base, or the wrong one, is refused, and nothing is stored. Returns
    /// whether `roster` was stored, like [`Self::set`].
    ///
    /// The relay holds Rosters only, so the predicate sees no Policy. This
    /// is what the DOC handler and the operator's reload call; [`Self::set`]
    /// stays for the owner's own documents in tests.
    pub fn adopt(
        &self,
        roster: &Roster,
        base: Option<&Roster>,
        now: u64,
    ) -> Result<bool, RelayError> {
        let network_id = roster.decode()?.network_id;
        let encoded_len = [Some(roster), base]
            .into_iter()
            .flatten()
            .map(|doc| doc.encode().len())
            .max()
            .unwrap_or(0);
        if encoded_len > menzil_proto::MAX_DOC_BYTES {
            return Err(RelayError::DocumentTooLarge {
                len: encoded_len,
                max: menzil_proto::MAX_DOC_BYTES,
            });
        }
        let bundle = Bundle {
            base_roster: base.cloned(),
            roster: Some(roster.clone()),
            ..Bundle::default()
        };
        let mut guard = self.by_network.write().unwrap();
        let view = HeldView {
            network_id,
            roster: guard.get(&network_id).map(|held| held.view.clone()),
            policy_seq: None,
        };
        let adoption = match check_bundle(&view, &bundle, now) {
            Verdict::Adopt(adoption) => adoption,
            Verdict::Held => return Ok(false),
            Verdict::Reject(reason) => return Err(RelayError::DocumentRejected(reason)),
        };
        // A steward signed Roster is held only with its base.
        let base = match (adoption.signer, base) {
            (menzil_proto::trust::Signer::Owner, _) => None,
            (menzil_proto::trust::Signer::Steward { .. }, Some(base)) => Some(base),
            (menzil_proto::trust::Signer::Steward { .. }, None) => {
                return Err(RelayError::DocumentRejected(Reason::MissingBase));
            }
        };
        let view = HeldRoster::new(roster, base).map_err(RelayError::DocumentRejected)?;
        let body = roster.decode()?;
        let counted = match base {
            Some(base) => base.decode()?.members.len().min(body.members.len()),
            None => body.members.len(),
        };
        guard.insert(
            network_id,
            Held {
                signed: roster.clone(),
                body,
                base: base.cloned(),
                view,
                counted,
            },
        );
        drop(guard);
        // The Roster is held whatever the hook does: a panic in it is logged, never passed on
        // to the adoption.
        let hook = self.on_adopted.read().unwrap().clone();
        if let Some(hook) = hook
            && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(roster, base)))
                .is_err()
        {
            tracing::warn!(%network_id, "the on adopted hook panicked; the Roster is held all the same");
        }
        Ok(true)
    }

    /// The owner signed base the held Roster for `network_id` was made
    /// from, when a steward signed it; sent before the Roster itself to
    /// anyone it is passed on to (protocol.md 4.3).
    pub fn base(&self, network_id: &NetworkId) -> Option<Roster> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .and_then(|held| held.base.clone())
    }

    /// The currently held Roster body for `network_id`, if any.
    pub fn get(&self, network_id: &NetworkId) -> Option<RosterBody> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|held| held.body.clone())
    }

    /// The currently held *signed* Roster for `network_id`, if any — the
    /// verbatim bytes DOC propagation sends on (protocol.md 2.1, 4.3).
    pub fn signed(&self, network_id: &NetworkId) -> Option<Roster> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|held| held.signed.clone())
    }

    /// The held signed Roster and its base, read under one lock, so that a concurrent adoption
    /// cannot pair a Roster with the base of another (the sixth red-team round, N1).
    pub fn signed_with_base(&self, network_id: &NetworkId) -> Option<(Roster, Option<Roster>)> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|held| (held.signed.clone(), held.base.clone()))
    }

    /// Every held network's current `seq`, for WELCOME's `rosters` field
    /// (protocol.md 4.1, 4.3).
    pub fn seqs(&self) -> HashMap<NetworkId, u64> {
        self.by_network
            .read()
            .unwrap()
            .iter()
            .map(|(id, held)| (*id, held.body.seq))
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
    ///
    /// Within one Roster a NodeId listed more than once counts at its
    /// highest `min_serial`, not at whichever entry comes first: nothing
    /// rejects duplicate `members` entries, and protocol.md 7.3's
    /// compromise response ("`min_serial` raised") must not be silently
    /// defeated by a stale, lower entry that happens to be listed ahead of
    /// the raised one (TODO.md, found by L4c's red-team review; the
    /// node-side `PolicyStore` already did this).
    pub fn min_serial_for(&self, node_id: &NodeId) -> Option<u32> {
        self.by_network
            .read()
            .unwrap()
            .values()
            .filter_map(|held| {
                held.body
                    .members
                    .iter()
                    .take(held.counted)
                    .filter(|member| &member.node_id == node_id)
                    .map(|member| member.min_serial)
                    .max()
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
            .map(|held| &held.body)
            .filter(|body| {
                !body
                    .revoked
                    .iter()
                    .any(|revoked| &revoked.node_id == node_id)
                    && body.members.iter().any(|member| &member.node_id == node_id)
            })
            .flat_map(|body| body.labels.iter())
            .filter(|label| &label.node_id == node_id)
            .map(|label| label.name.to_ascii_lowercase())
            .collect()
    }

    /// Whether one of `src`'s own claimed networks (`src_claimed`, its
    /// HELLO's `networks`) has a Roster this relay holds that is not yet
    /// expired at `now` and lists both `src` and `dst` as current,
    /// unrevoked members (protocol.md 4.2's forwarding rule: "`src` and
    /// `dst` are both listed and unrevoked in one common, unexpired
    /// Roster the relay holds").
    ///
    /// Deliberately asymmetric — requiring only `src` to have claimed the
    /// network, not `dst` too — and this is a *correction* of this
    /// method's own original, symmetric design (which required both
    /// sides to have claimed it, reasoning from protocol.md 4.1's "a node
    /// may claim no network; it may then only redeem an invite"). An
    /// opus red team review found that reading, combined with checking
    /// `dst`'s attachment before authorization, created a presence
    /// oracle: since the symmetric check needed `dst`'s own claimed
    /// networks, `crate::forward::ForwardTable::forward` had to fetch
    /// `dst`'s attachment state *before* it could even run this check,
    /// letting anyone who can complete a bare handshake — including a
    /// revoked ex-member, since a zero-claim HELLO gets no roster
    /// scrutiny at all — learn whether an arbitrary known NodeId is
    /// currently online, with no standing of their own required. This
    /// version needs only `src`'s already-known claims, so
    /// `crate::forward::ForwardTable::forward` can and does check this
    /// *before* ever touching `dst`'s attachment state: an unauthorized
    /// `src` (one with no claimed network whose Roster also lists `dst`)
    /// gets `Forbidden` whether `dst` exists, is attached, or is offline,
    /// leaking nothing.
    ///
    /// This still honors 4.1's "may only redeem an invite" sentence — a
    /// `src` with no claimed networks at all can never satisfy this
    /// (`src_claimed` empty means nothing to iterate) — while no longer
    /// also requiring `dst` to have separately re-claimed the same
    /// network in its own *current* HELLO: RECV records carry no
    /// network_id for `dst` to attribute them to, and protocol.md 5.1
    /// makes the end-to-end (L4) handshake the actual authority on
    /// membership and grants, verified independently by each peer against
    /// its own held Roster and Policy — this check exists to keep an
    /// unrelated stranger from using the relay as a delivery vector
    /// against an arbitrary target, not to duplicate L4's own
    /// authorization.
    ///
    /// This is also where a claimed network's Roster `expires` is finally
    /// checked at all: neither `check_hello` (protocol.md 4.1) nor
    /// [`RosterStore::labels_granted_to`] (protocol.md 4.4) do, both
    /// deliberately, each leaving it to "forwarding" per protocol.md 2.3
    /// — this is that forwarding.
    pub fn grants_forwarding(
        &self,
        src: &NodeId,
        src_claimed: &[NetworkId],
        dst: &NodeId,
        now: u64,
    ) -> bool {
        let guard = self.by_network.read().unwrap();
        src_claimed.iter().any(|network_id| {
            guard
                .get(network_id)
                .map(|held| &held.body)
                .is_some_and(|body| {
                    body.expires > now
                        && is_unrevoked_member(body, src)
                        && is_unrevoked_member(body, dst)
                })
        })
    }
}

/// Revocation checked before, and independently of, membership — the
/// same order `crate::hello::check_hello` and
/// `RosterStore::labels_granted_to` already use, for the same reason: a
/// Roster naming a node in both `members` and `revoked` at once is
/// possible to construct, and revocation must still win.
fn is_unrevoked_member(body: &RosterBody, node_id: &NodeId) -> bool {
    !body
        .revoked
        .iter()
        .any(|revoked| &revoked.node_id == node_id)
        && body.members.iter().any(|member| &member.node_id == node_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::trust::Reason;
    use menzil_proto::{Roster, RosterBody, RosterMember};

    use crate::tests_support::StewardNet;

    const NOW: u64 = 1_800_000_000;

    fn node(n: u8) -> NodeId {
        NodeId::from([n; 32])
    }

    fn refused(result: Result<bool, RelayError>) -> Reason {
        match result {
            Err(RelayError::DocumentRejected(reason)) => reason,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    /// A relay holding the owner signed base at seq 10, as an operator seeds it.
    fn seeded(net: &StewardNet) -> RosterStore {
        let store = RosterStore::new();
        store.adopt(&net.base, None, NOW).unwrap();
        store
    }

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
    fn min_serial_for_takes_the_highest_of_duplicate_entries_within_one_roster() {
        // protocol.md 7.3's compromise response is "min_serial raised". A
        // Roster listing the same NodeId twice (nothing in this crate or
        // `menzil-proto` rejects that) must not let a stale, lower entry
        // that happens to come first silently defeat the raised one: the
        // old `find` honored whichever was first. Both orders, since the
        // answer must not depend on it. The node-side twin
        // (`menzil-node`'s `roster_standing`) already takes the maximum.
        let node_id = NodeId::from([9u8; 32]);
        let other = NodeId::from([4u8; 32]);
        for members in [
            vec![(node_id, 2), (node_id, 9), (other, 1)],
            vec![(node_id, 9), (other, 1), (node_id, 2)],
        ] {
            let owner = SigningKey::generate(&mut rand::rng());
            let network_id = NetworkId::from(owner.verifying_key().to_bytes());
            let body = RosterBody {
                v: menzil_proto::PROTOCOL_VERSION,
                network_id,
                seq: 1,
                issued: 0,
                expires: 1_000_000_000,
                members: members
                    .iter()
                    .map(|&(node_id, min_serial)| RosterMember {
                        node_id,
                        min_serial,
                    })
                    .collect(),
                revoked: vec![],
                stewards: vec![],
                labels: vec![],
            };
            let store = RosterStore::new();
            store.set(&Roster::sign(&owner, &body).unwrap()).unwrap();
            assert_eq!(store.min_serial_for(&node_id), Some(9), "{members:?}");
            assert_eq!(store.min_serial_for(&other), Some(1), "{members:?}");
        }
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

    fn roster_for_pair(
        owner: &SigningKey,
        network_id: NetworkId,
        a: NodeId,
        b: NodeId,
        expires: u64,
    ) -> Roster {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires,
            members: vec![
                RosterMember {
                    node_id: a,
                    min_serial: 1,
                },
                RosterMember {
                    node_id: b,
                    min_serial: 1,
                },
            ],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    #[test]
    fn grants_forwarding_is_true_when_src_claimed_a_network_whose_roster_lists_both() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let store = RosterStore::new();
        store
            .set(&roster_for_pair(&owner, network_id, a, b, 4_000_000_000))
            .unwrap();

        assert!(store.grants_forwarding(&a, &[network_id], &b, 1_000));
    }

    #[test]
    fn grants_forwarding_is_false_once_the_roster_has_expired() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let store = RosterStore::new();
        store
            .set(&roster_for_pair(&owner, network_id, a, b, 500))
            .unwrap();

        assert!(!store.grants_forwarding(&a, &[network_id], &b, 1_000));
    }

    #[test]
    fn grants_forwarding_is_false_when_src_claimed_nothing() {
        // protocol.md 4.1: "a node may claim no network; it may then
        // only redeem an invite" — an empty `src_claimed` can never find
        // a network to check, regardless of what either side's Roster
        // membership actually is.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let store = RosterStore::new();
        store
            .set(&roster_for_pair(&owner, network_id, a, b, 4_000_000_000))
            .unwrap();

        assert!(!store.grants_forwarding(&a, &[], &b, 1_000));
    }

    #[test]
    fn grants_forwarding_does_not_require_dst_to_have_separately_claimed_it() {
        // Deliberate, corrected behavior (see `grants_forwarding`'s own
        // doc comment): only `src`'s claim is consulted. `dst` need not
        // have claimed this network in its own (possibly unrelated, e.g.
        // invite-redemption-only) current HELLO to be a legitimate
        // forwarding target, as long as the Roster `src` claimed still
        // lists `dst` as an unrevoked member.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let store = RosterStore::new();
        store
            .set(&roster_for_pair(&owner, network_id, a, b, 4_000_000_000))
            .unwrap();

        assert!(store.grants_forwarding(&a, &[network_id], &b, 1_000));
    }

    #[test]
    fn grants_forwarding_is_false_for_a_revoked_dst_even_if_still_listed() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let mut roster = roster_for_pair(&owner, network_id, a, b, 4_000_000_000)
            .decode()
            .unwrap();
        roster.revoked.push(menzil_proto::RevokedMember {
            node_id: b,
            since: 0,
        });
        let store = RosterStore::new();
        store.set(&Roster::sign(&owner, &roster).unwrap()).unwrap();

        assert!(!store.grants_forwarding(&a, &[network_id], &b, 1_000));
    }

    #[test]
    fn grants_forwarding_is_false_for_a_revoked_src_even_if_still_listed() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let mut roster = roster_for_pair(&owner, network_id, a, b, 4_000_000_000)
            .decode()
            .unwrap();
        roster.revoked.push(menzil_proto::RevokedMember {
            node_id: a,
            since: 0,
        });
        let store = RosterStore::new();
        store.set(&Roster::sign(&owner, &roster).unwrap()).unwrap();

        assert!(!store.grants_forwarding(&a, &[network_id], &b, 1_000));
    }

    #[test]
    fn grants_forwarding_ignores_a_network_src_never_claimed() {
        let owner_a = SigningKey::generate(&mut rand::rng());
        let owner_b = SigningKey::generate(&mut rand::rng());
        let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
        let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let store = RosterStore::new();
        // `a` is a member of both networks' Rosters, but only claims
        // network_a in its own HELLO; network_b's Roster (which also
        // lists both `a` and `b`) must not count just because `a`
        // happens to be a member of it too.
        store
            .set(&roster_for_pair(&owner_a, network_a, a, b, 4_000_000_000))
            .unwrap();
        store
            .set(&roster_for_pair(&owner_b, network_b, a, b, 4_000_000_000))
            .unwrap();

        assert!(store.grants_forwarding(&a, &[network_a, network_b], &b, 1_000));
        // Claiming only an unrelated third network finds nothing.
        let unclaimed = NetworkId::from([0x55; 32]);
        assert!(!store.grants_forwarding(&a, &[unclaimed], &b, 1_000));
    }

    #[test]
    fn a_steward_roster_without_its_base_is_refused_and_not_stored() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        let renewal = net.renewal(&net.steward, 11);
        assert_eq!(
            refused(store.adopt(&renewal, None, NOW)),
            Reason::MissingBase
        );
        assert_eq!(store.get(&net.network_id).unwrap().seq, 10);
    }

    #[test]
    fn a_steward_roster_with_its_base_is_adopted_and_held_with_the_base() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        assert!(store.base(&net.network_id).is_none());
        let renewal = net.renewal(&net.steward, 11);
        assert!(store.adopt(&renewal, Some(&net.base), NOW).unwrap());
        assert_eq!(store.signed(&net.network_id).unwrap(), renewal);
        assert_eq!(store.base(&net.network_id).unwrap(), net.base);
    }

    #[test]
    fn an_owner_signed_roster_needs_no_base_and_drops_the_held_one() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        let renewal = net.renewal(&net.steward, 11);
        store.adopt(&renewal, Some(&net.base), NOW).unwrap();
        let owner_next = net.renewal(&net.owner, 11 + menzil_proto::trust::STEWARD_SEQ_SPAN);
        assert!(store.adopt(&owner_next, None, NOW).unwrap());
        assert!(store.base(&net.network_id).is_none());
        assert_eq!(
            store.get(&net.network_id).unwrap().seq,
            11 + menzil_proto::trust::STEWARD_SEQ_SPAN
        );
    }

    /// Round 6, M4: a steward of network A appends a member of network B with the highest
    /// `min_serial`; the relay, which scans every held Roster for `min_serial`, must not then
    /// refuse that node's HELLO. What a steward appends does not count.
    #[test]
    fn a_steward_cannot_lock_a_node_of_another_network_out_with_a_min_serial() {
        use menzil_proto::RosterMember;
        let now = crate::tests_support::real_now();
        let victim = NodeId::from([0x77u8; 32]);
        let a = StewardNet::new(10, now, node(1));
        let b = StewardNet::new(20, now, victim);
        let store = RosterStore::new();
        store.adopt(&a.base, None, now).unwrap();
        store.adopt(&b.base, None, now).unwrap();
        assert_eq!(store.min_serial_for(&victim), Some(1));
        let mut body = a.base.decode().unwrap();
        body.seq = 11;
        body.issued = now;
        body.expires = now + 7 * crate::tests_support::DAY;
        body.members.push(RosterMember {
            node_id: victim,
            min_serial: u32::MAX,
        });
        let steward_roster = Roster::sign(&a.steward, &body).unwrap();
        assert!(store.adopt(&steward_roster, Some(&a.base), now).unwrap());
        assert_eq!(store.min_serial_for(&victim), Some(1));
        // The base members of a steward signed Roster still count.
        assert_eq!(store.min_serial_for(&node(1)), Some(1));
    }

    #[test]
    fn a_steward_roster_from_a_base_older_than_the_held_base_is_refused() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        store
            .adopt(&net.renewal(&net.steward, 11), Some(&net.base), NOW)
            .unwrap();
        let older = net.rebase(5);
        let renewal = older.renewal(&older.steward, 12);
        assert_eq!(
            refused(store.adopt(&renewal, Some(&older.base), NOW)),
            Reason::BaseOlderThanHeld
        );
        assert_eq!(store.get(&net.network_id).unwrap().seq, 11);
    }

    #[test]
    fn a_steward_roster_with_a_base_of_another_network_is_refused() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        let stranger = StewardNet::new(10, NOW, node(1));
        let renewal = net.renewal(&net.steward, 11);
        assert_eq!(
            refused(store.adopt(&renewal, Some(&stranger.base), NOW)),
            Reason::WrongNetwork
        );
        assert_eq!(store.get(&net.network_id).unwrap().seq, 10);
    }

    #[test]
    fn the_time_rules_apply_to_what_is_adopted() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        // The renewal is valid at NOW but expired a month later.
        let renewal = net.renewal(&net.owner, 11);
        assert_eq!(
            refused(store.adopt(&renewal, None, NOW + 40 * crate::tests_support::DAY)),
            Reason::Expired
        );
    }

    type Seen = std::sync::Arc<std::sync::Mutex<Vec<(u64, Option<u64>)>>>;

    /// A hook that records the `seq` of each Roster and of its base.
    fn recording(store: &RosterStore) -> Seen {
        let seen: Seen = Seen::default();
        let sink = seen.clone();
        store.set_on_adopted(move |roster, base| {
            let base_seq = base.map(|b| b.decode().unwrap().seq);
            sink.lock()
                .unwrap()
                .push((roster.decode().unwrap().seq, base_seq));
        });
        seen
    }

    #[test]
    fn the_hook_hears_of_each_adopted_roster_with_its_base_and_of_nothing_else() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        let seen = recording(&store);
        // A steward signed Roster: the base goes with it.
        let renewal = net.renewal(&net.steward, 11);
        assert!(store.adopt(&renewal, Some(&net.base), NOW).unwrap());
        assert_eq!(*seen.lock().unwrap(), vec![(11, Some(10))]);
        // Held (nothing newer) and refused (a stranger's signature, no base) say nothing.
        assert!(!store.adopt(&renewal, Some(&net.base), NOW).unwrap());
        let stranger = SigningKey::generate(&mut rand::rng());
        let forged = net.renewal(&stranger, 12);
        assert!(store.adopt(&forged, Some(&net.base), NOW).is_err());
        assert!(
            store
                .adopt(&net.renewal(&net.steward, 13), None, NOW)
                .is_err()
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
        // An owner signed one comes with no base.
        assert!(
            store
                .adopt(&net.renewal(&net.owner, 14), None, NOW)
                .unwrap()
        );
        assert_eq!(seen.lock().unwrap()[1], (14, None));
    }

    #[test]
    fn a_hook_that_panics_does_not_undo_the_adoption() {
        let net = StewardNet::new(10, NOW, node(1));
        let store = seeded(&net);
        store.set_on_adopted(|_, _| panic!("the disk is on fire"));
        assert!(
            store
                .adopt(&net.renewal(&net.steward, 11), Some(&net.base), NOW)
                .unwrap()
        );
        assert_eq!(store.get(&net.network_id).unwrap().seq, 11);
        assert!(store.base(&net.network_id).is_some());
    }
}
