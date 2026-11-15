//! DOC handling at L3, node side (protocol.md 4.3): what a completed DOC transfer from the
//! relay does to this node's [`RosterStore`]. Pure logic, no I/O and no clock of its own, so
//! `Engine::accept_doc` is thin glue around [`accept_completed`].
//!
//! The relay sends the owner signed base Roster (`DocType::BaseRoster`) ahead of a steward
//! signed Roster. A base is kept pending by (network, base seq), at most [`MAX_PENDING_BASES`] per
//! session, until the Roster that follows it; the Roster is then judged with the pending base
//! of its network that it follows (the largest seq below its own, within the span) by the
//! acceptance predicate of protocol.md 2.3 (`RosterStore::adopt_roster`). A base never counts
//! alone and a base is used up by the Roster that uses it (an owner signed Roster discards the
//! bases at or below its seq). The relay
//! is only semi trusted, so keeping a base is cheap (strict decode, claimed network, cap) and
//! every signature is checked when the Roster arrives. Mirrors the relay's `doc.rs`.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use menzil_proto::trust::STEWARD_SEQ_SPAN;
use menzil_proto::{DocType, NetworkId, ProtoError, Roster};

use crate::error::NodeError;
use crate::roster_store::RosterStore;

/// The most bases a session may have pending at once, over all networks and seqs.
const MAX_PENDING_BASES: usize = 8;

/// The base Rosters a session was sent that wait for the Roster they belong to, keyed by
/// (network, base seq): the relay's fan out may interleave bases and Rosters of several
/// pushers. Owned by the session's `Engine`, so it dies with the session.
#[derive(Debug, Default)]
pub(crate) struct PendingBases {
    by_key: HashMap<(NetworkId, u64), Roster>,
}

impl PendingBases {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Keeps `base` (whose seq is `base_seq`) for `network_id`; the same (network, seq)
    /// replaces the old entry and is always kept. Returns false, keeping nothing, when
    /// [`MAX_PENDING_BASES`] other entries are already pending.
    pub(crate) fn keep(&mut self, network_id: NetworkId, base_seq: u64, base: Roster) -> bool {
        let key = (network_id, base_seq);
        if !self.by_key.contains_key(&key) && self.by_key.len() >= MAX_PENDING_BASES {
            return false;
        }
        self.by_key.insert(key, base);
        true
    }

    /// For a steward Roster of `network_id` at `roster_seq`: the pending base with the largest
    /// seq below `roster_seq` and within the steward span, removed together with every pending
    /// base of that network at or below its seq (used up or superseded). None when no base is
    /// a candidate (nothing is removed then).
    pub(crate) fn take(&mut self, network_id: &NetworkId, roster_seq: u64) -> Option<Roster> {
        let best = self
            .by_key
            .keys()
            .filter(|(n, b)| {
                n == network_id
                    && *b < roster_seq
                    && roster_seq <= b.saturating_add(STEWARD_SEQ_SPAN)
            })
            .map(|(_, b)| *b)
            .max()?;
        let base = self.by_key.remove(&(*network_id, best));
        self.discard_through(network_id, best);
        base
    }

    /// Removes every pending base of `network_id` with seq at or below `seq`.
    pub(crate) fn discard_through(&mut self, network_id: &NetworkId, seq: u64) {
        self.by_key.retain(|(n, b), _| n != network_id || *b > seq);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_key.len()
    }
}

/// What one completed DOC transfer did.
#[derive(Debug)]
pub(crate) enum L3DocOutcome {
    /// A base was kept for the Roster that follows it; nothing else to do.
    Nothing,
    /// The Roster was stored (it is the newest this node holds): the relay holds at least `seq`.
    Adopted(NetworkId, u64),
    /// The Roster verified but this node already holds one as new or newer: the relay holds at
    /// least `seq`.
    Held(NetworkId, u64),
    /// The Roster did not pass the acceptance predicate (or a size limit). Never raises what
    /// the relay is known to hold.
    Rejected(NodeError),
    /// The payload did not decode as a Roster.
    Undecodable(ProtoError),
    /// Not kept or not judged, with the reason for the log: a network this node did not claim,
    /// or a base over the cap.
    Dropped(&'static str),
    /// A `doc_type` that is not acted on at L3 (Policy is end to end only).
    Ignored(DocType),
}

/// Handles one reassembled transfer of `doc_type` for the networks in `claimed`, at `now`
/// (Unix seconds).
pub(crate) fn accept_completed(
    doc_type: DocType,
    bytes: &[u8],
    claimed: &[NetworkId],
    pending: &mut PendingBases,
    store: &RosterStore,
    now: u64,
) -> L3DocOutcome {
    if doc_type != DocType::Roster && doc_type != DocType::BaseRoster {
        return L3DocOutcome::Ignored(doc_type);
    }
    let roster = match Roster::decode_strict(bytes) {
        Ok(roster) => roster,
        Err(err) => return L3DocOutcome::Undecodable(err),
    };
    let body = match roster.decode() {
        Ok(body) => body,
        Err(err) => return L3DocOutcome::Undecodable(err),
    };
    let network_id = body.network_id;
    if !claimed.contains(&network_id) {
        return L3DocOutcome::Dropped("a DOC for a network this node does not claim");
    }
    if doc_type == DocType::BaseRoster {
        return if pending.keep(network_id, body.seq, roster) {
            L3DocOutcome::Nothing
        } else {
            L3DocOutcome::Dropped("too many pending base Rosters")
        };
    }
    // An owner signed Roster needs no base and discards the bases at or below its seq; a
    // steward Roster is judged with the pending base it follows, which is then used up.
    let owner_signed = VerifyingKey::from_bytes(&<[u8; 32]>::from(network_id))
        .is_ok_and(|owner| roster.verify(&owner).is_ok());
    let base = if owner_signed {
        pending.discard_through(&network_id, body.seq);
        None
    } else {
        pending.take(&network_id, body.seq)
    };
    match store.adopt_roster(&roster, base.as_ref(), now) {
        Ok(true) => L3DocOutcome::Adopted(network_id, body.seq),
        Ok(false) => L3DocOutcome::Held(network_id, body.seq),
        Err(err) => L3DocOutcome::Rejected(err),
    }
}

#[cfg(test)]
pub(crate) mod fixture {
    use ed25519_dalek::SigningKey;
    use menzil_proto::{
        NodeId, PROTOCOL_VERSION, Roster, RosterBody, RosterMember, Steward, StewardBody,
        StewardKey,
    };

    pub(crate) const DAY: u64 = 86_400;

    /// A network at base `seq` 10 with one steward, built around `now`.
    pub(crate) struct Fix {
        pub(crate) owner: SigningKey,
        pub(crate) steward: SigningKey,
        pub(crate) network_id: menzil_proto::NetworkId,
        pub(crate) now: u64,
        pub(crate) body: RosterBody,
        pub(crate) base: Roster,
    }

    impl Fix {
        pub(crate) fn new(now: u64) -> Self {
            let owner = SigningKey::generate(&mut rand::rng());
            let steward = SigningKey::generate(&mut rand::rng());
            let network_id = menzil_proto::NetworkId::from(owner.verifying_key().to_bytes());
            let entry = Steward::sign(
                &owner,
                &StewardBody {
                    v: PROTOCOL_VERSION,
                    network_id,
                    steward_pub: StewardKey::from(steward.verifying_key().to_bytes()),
                    may: vec!["renew".to_string()],
                    not_after: now + 30 * DAY,
                },
            )
            .unwrap();
            let body = RosterBody {
                v: PROTOCOL_VERSION,
                network_id,
                seq: 10,
                issued: now - DAY,
                expires: now + 5 * DAY,
                members: vec![RosterMember {
                    node_id: NodeId::from([1u8; 32]),
                    min_serial: 1,
                }],
                revoked: vec![],
                stewards: vec![entry],
                labels: vec![],
            };
            Self {
                base: Roster::sign(&owner, &body).unwrap(),
                owner,
                steward,
                network_id,
                now,
                body,
            }
        }

        /// A Roster at `seq` issued at `now`, signed by `signer`.
        pub(crate) fn roster(&self, signer: &SigningKey, seq: u64) -> Roster {
            let mut body = self.body.clone();
            body.seq = seq;
            body.issued = self.now;
            body.expires = self.now + 7 * DAY;
            Roster::sign(signer, &body).unwrap()
        }

        pub(crate) fn steward_roster(&self, seq: u64) -> Roster {
            self.roster(&self.steward, seq)
        }

        /// An owner signed base of the same network at `seq` (different members).
        pub(crate) fn other_base(&self, seq: u64) -> Roster {
            let mut body = self.body.clone();
            body.seq = seq;
            body.members.clear();
            Roster::sign(&self.owner, &body).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;
    use menzil_proto::StewardKey;
    use menzil_proto::trust::{Reason, Signer};

    const NOW: u64 = 1_800_000_000;

    fn run(
        fix: &Fix,
        dt: DocType,
        doc: &Roster,
        claimed: &[NetworkId],
        pending: &mut PendingBases,
        store: &RosterStore,
    ) -> L3DocOutcome {
        accept_completed(dt, &doc.encode(), claimed, pending, store, fix.now)
    }

    fn base_then_roster(
        fix: &Fix,
        store: &RosterStore,
        pending: &mut PendingBases,
        r: &Roster,
    ) -> L3DocOutcome {
        let c = [fix.network_id];
        assert!(matches!(
            run(fix, DocType::BaseRoster, &fix.base, &c, pending, store),
            L3DocOutcome::Nothing
        ));
        run(fix, DocType::Roster, r, &c, pending, store)
    }

    #[test]
    fn base_then_steward_roster_is_adopted_with_the_base() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let r = fix.steward_roster(11);
        let out = base_then_roster(&fix, &store, &mut pending, &r);
        assert!(
            matches!(out, L3DocOutcome::Adopted(n, 11) if n == fix.network_id),
            "{out:?}"
        );
        assert_eq!(store.base(&fix.network_id), Some(fix.base.clone()));
        assert_eq!(
            store.signer(&fix.network_id),
            Some(Signer::Steward {
                key: StewardKey::from(fix.steward.verifying_key().to_bytes()),
                base_seq: 10
            })
        );
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn a_base_alone_is_never_adopted_even_when_it_is_a_newer_owner_roster() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id];
        let out = run(
            &fix,
            DocType::BaseRoster,
            &fix.base,
            &c,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Nothing));
        assert!(store.get(&fix.network_id).is_none());
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn a_steward_roster_without_a_base_is_missing_base() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let out = run(
            &fix,
            DocType::Roster,
            &fix.steward_roster(11),
            &[fix.network_id],
            &mut pending,
            &store,
        );
        assert!(
            matches!(
                out,
                L3DocOutcome::Rejected(NodeError::DocumentRejected(Reason::MissingBase))
            ),
            "{out:?}"
        );
        assert!(store.get(&fix.network_id).is_none());
    }

    #[test]
    fn a_wrong_base_is_rejected_and_nothing_adopted() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id];
        run(
            &fix,
            DocType::BaseRoster,
            &fix.other_base(10),
            &c,
            &mut pending,
            &store,
        );
        let out = run(
            &fix,
            DocType::Roster,
            &fix.steward_roster(11),
            &c,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Rejected(_)), "{out:?}");
        assert!(store.get(&fix.network_id).is_none());
    }

    #[test]
    fn a_base_is_used_up_by_the_roster_that_follows_it() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id];
        let out = base_then_roster(&fix, &store, &mut pending, &fix.steward_roster(11));
        assert!(matches!(out, L3DocOutcome::Adopted(..)));
        let out = run(
            &fix,
            DocType::Roster,
            &fix.steward_roster(12),
            &c,
            &mut pending,
            &store,
        );
        assert!(
            matches!(
                out,
                L3DocOutcome::Rejected(NodeError::DocumentRejected(Reason::MissingBase))
            ),
            "{out:?}"
        );
        assert_eq!(store.seq(&fix.network_id), Some(11));
    }

    #[test]
    fn an_owner_roster_discards_a_pending_base() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id];
        run(
            &fix,
            DocType::BaseRoster,
            &fix.base,
            &c,
            &mut pending,
            &store,
        );
        let out = run(
            &fix,
            DocType::Roster,
            &fix.roster(&fix.owner, 11),
            &c,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(..)), "{out:?}");
        assert_eq!(pending.len(), 0);
        let out = run(
            &fix,
            DocType::Roster,
            &fix.steward_roster(12),
            &c,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Rejected(_)), "{out:?}");
    }

    #[test]
    fn a_base_for_another_claimed_network_does_not_serve_this_roster() {
        let fix = Fix::new(NOW);
        let other = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id, other.network_id];
        let out = run(
            &other,
            DocType::BaseRoster,
            &other.base,
            &c,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Nothing));
        let out = run(
            &fix,
            DocType::Roster,
            &fix.steward_roster(11),
            &c,
            &mut pending,
            &store,
        );
        assert!(
            matches!(
                out,
                L3DocOutcome::Rejected(NodeError::DocumentRejected(Reason::MissingBase))
            ),
            "{out:?}"
        );
        assert_eq!(
            pending.len(),
            1,
            "the other network's base is still pending"
        );
        assert!(pending.take(&other.network_id, 11).is_some());
    }

    #[test]
    fn a_base_for_an_unclaimed_network_is_not_kept() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let out = run(
            &fix,
            DocType::BaseRoster,
            &fix.base,
            &[],
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Dropped(_)));
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn a_stale_base_older_than_the_held_base_is_rejected() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id];
        // Held: steward Roster 12 on a base at seq 10... a newer base: owner seq 20 then steward 21.
        let mut body = fix.body.clone();
        body.seq = 20;
        let newer_base = Roster::sign(&fix.owner, &body).unwrap();
        run(
            &fix,
            DocType::BaseRoster,
            &newer_base,
            &c,
            &mut pending,
            &store,
        );
        let out = run(
            &fix,
            DocType::Roster,
            &fix.steward_roster(21),
            &c,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(..)), "{out:?}");
        // The relay now replays the old base (seq 10) with a steward Roster above 21.
        let out = base_then_roster(&fix, &store, &mut pending, &fix.steward_roster(22));
        assert!(matches!(out, L3DocOutcome::Rejected(_)), "{out:?}");
        assert_eq!(store.seq(&fix.network_id), Some(21));
        assert_eq!(store.base(&fix.network_id), Some(newer_base));
    }

    #[test]
    fn the_cap_refuses_a_ninth_key_and_the_same_key_replaces() {
        let fixes: Vec<Fix> = (0..9).map(|_| Fix::new(NOW)).collect();
        let claimed: Vec<NetworkId> = fixes.iter().map(|f| f.network_id).collect();
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        for f in &fixes[..8] {
            let out = run(
                f,
                DocType::BaseRoster,
                &f.base,
                &claimed,
                &mut pending,
                &store,
            );
            assert!(matches!(out, L3DocOutcome::Nothing));
        }
        let out = run(
            &fixes[8],
            DocType::BaseRoster,
            &fixes[8].base,
            &claimed,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Dropped(_)), "{out:?}");
        assert_eq!(pending.len(), 8);
        assert!(pending.take(&fixes[8].network_id, 11).is_none());
        // A replacement for an already pending network is kept.
        let out = run(
            &fixes[0],
            DocType::BaseRoster,
            &fixes[0].other_base(10),
            &claimed,
            &mut pending,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Nothing));
        assert_eq!(pending.len(), 8);
        assert_eq!(
            pending
                .take(&fixes[0].network_id, 12)
                .map(|r| r.decode().unwrap().members.len()),
            Some(0)
        );
    }

    #[test]
    fn an_expired_base_under_a_valid_steward_roster_is_adopted() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id];
        // The base expired 5 days after NOW; the steward Roster is issued at `later`.
        let later = NOW + 6 * DAY;
        let mut body = fix.body.clone();
        body.seq = 11;
        body.issued = later;
        body.expires = later + DAY;
        let r = Roster::sign(&fix.steward, &body).unwrap();
        run(
            &fix,
            DocType::BaseRoster,
            &fix.base,
            &c,
            &mut pending,
            &store,
        );
        let out = accept_completed(
            DocType::Roster,
            &r.encode(),
            &c,
            &mut pending,
            &store,
            later,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(_, 11)), "{out:?}");
    }

    #[test]
    fn other_doc_types_are_ignored_and_garbage_is_undecodable() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let c = [fix.network_id];
        let out = accept_completed(DocType::Policy, b"x", &c, &mut pending, &store, NOW);
        assert!(matches!(out, L3DocOutcome::Ignored(DocType::Policy)));
        let out = accept_completed(DocType::Roster, b"junk", &c, &mut pending, &store, NOW);
        assert!(matches!(out, L3DocOutcome::Undecodable(_)));
    }

    #[test]
    fn an_equal_roster_is_held_not_adopted() {
        let fix = Fix::new(NOW);
        let (store, mut pending) = (RosterStore::new(), PendingBases::new());
        let r = fix.steward_roster(11);
        assert!(matches!(
            base_then_roster(&fix, &store, &mut pending, &r),
            L3DocOutcome::Adopted(..)
        ));
        let out = base_then_roster(&fix, &store, &mut pending, &r);
        assert!(matches!(out, L3DocOutcome::Held(_, 11)), "{out:?}");
    }

    fn feed(
        fix: &Fix,
        dt: DocType,
        doc: &Roster,
        p: &mut PendingBases,
        st: &RosterStore,
    ) -> L3DocOutcome {
        run(fix, dt, doc, &[fix.network_id], p, st)
    }

    #[test]
    fn interleaved_fan_outs_adopt_both_rosters() {
        let fix = Fix::new(NOW);
        let (store, mut p) = (RosterStore::new(), PendingBases::new());
        let b12 = fix.roster(&fix.owner, 12);
        assert!(matches!(
            feed(&fix, DocType::BaseRoster, &fix.base, &mut p, &store),
            L3DocOutcome::Nothing
        ));
        assert!(matches!(
            feed(&fix, DocType::BaseRoster, &b12, &mut p, &store),
            L3DocOutcome::Nothing
        ));
        let out = feed(
            &fix,
            DocType::Roster,
            &fix.steward_roster(11),
            &mut p,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(_, 11)), "{out:?}");
        let out = feed(
            &fix,
            DocType::Roster,
            &fix.steward_roster(13),
            &mut p,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(_, 13)), "{out:?}");
        assert_eq!(store.seq(&fix.network_id), Some(13));
        assert_eq!(store.base(&fix.network_id), Some(b12));
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn in_order_fan_outs_adopt_both_rosters() {
        let fix = Fix::new(NOW);
        let (store, mut p) = (RosterStore::new(), PendingBases::new());
        let b12 = fix.roster(&fix.owner, 12);
        feed(&fix, DocType::BaseRoster, &fix.base, &mut p, &store);
        let out = feed(
            &fix,
            DocType::Roster,
            &fix.steward_roster(11),
            &mut p,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(_, 11)), "{out:?}");
        feed(&fix, DocType::BaseRoster, &b12, &mut p, &store);
        let out = feed(
            &fix,
            DocType::Roster,
            &fix.steward_roster(13),
            &mut p,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(_, 13)), "{out:?}");
    }

    #[test]
    fn a_pending_base_above_the_roster_is_not_used_and_stays() {
        let fix = Fix::new(NOW);
        let (store, mut p) = (RosterStore::new(), PendingBases::new());
        let b12 = fix.roster(&fix.owner, 12);
        feed(&fix, DocType::BaseRoster, &b12, &mut p, &store);
        let out = feed(
            &fix,
            DocType::Roster,
            &fix.steward_roster(11),
            &mut p,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Rejected(_)), "{out:?}");
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn a_base_far_outside_the_span_is_not_chosen() {
        let fix = Fix::new(NOW);
        let (store, mut p) = (RosterStore::new(), PendingBases::new());
        feed(&fix, DocType::BaseRoster, &fix.base, &mut p, &store);
        let far = 10 + STEWARD_SEQ_SPAN + 1;
        let out = feed(
            &fix,
            DocType::Roster,
            &fix.steward_roster(far),
            &mut p,
            &store,
        );
        assert!(
            matches!(
                out,
                L3DocOutcome::Rejected(NodeError::DocumentRejected(Reason::MissingBase))
            ),
            "{out:?}"
        );
        assert_eq!(p.len(), 1, "an unusable base is not consumed");
    }

    #[test]
    fn take_picks_the_largest_seq_below_and_discards_the_lower_ones() {
        let fix = Fix::new(NOW);
        let mut p = PendingBases::new();
        for s in [10u64, 12, 14] {
            assert!(p.keep(fix.network_id, s, fix.other_base(s)));
        }
        let got = p.take(&fix.network_id, 13).unwrap();
        assert_eq!(got.decode().unwrap().seq, 12);
        assert_eq!(p.len(), 1);
        assert_eq!(
            p.take(&fix.network_id, 15).unwrap().decode().unwrap().seq,
            14
        );
    }

    #[test]
    fn an_owner_roster_discards_only_bases_at_or_below_it() {
        let fix = Fix::new(NOW);
        let (store, mut p) = (RosterStore::new(), PendingBases::new());
        feed(&fix, DocType::BaseRoster, &fix.base, &mut p, &store);
        feed(
            &fix,
            DocType::BaseRoster,
            &fix.roster(&fix.owner, 14),
            &mut p,
            &store,
        );
        let out = feed(
            &fix,
            DocType::Roster,
            &fix.roster(&fix.owner, 11),
            &mut p,
            &store,
        );
        assert!(matches!(out, L3DocOutcome::Adopted(..)), "{out:?}");
        assert_eq!(p.len(), 1, "the base above stays");
    }

    #[test]
    fn the_cap_counts_distinct_seqs_of_one_network() {
        let fix = Fix::new(NOW);
        let mut p = PendingBases::new();
        for s in 10..18u64 {
            assert!(p.keep(fix.network_id, s, fix.other_base(s)));
        }
        assert!(!p.keep(fix.network_id, 18, fix.other_base(18)));
        assert!(p.keep(fix.network_id, 12, fix.other_base(12)));
        assert_eq!(p.len(), 8);
    }
}
