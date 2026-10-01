//! This node's own held Policies (protocol.md 2.3, 5.5) and the
//! membership/grant evaluation built on top of them (TODO.md L4c):
//! `roster_store.rs`'s own doc comment flagged Policy as explicitly out
//! of scope there ("end to end only") — this is that scope, now filled
//! in. Mirrors [`crate::RosterStore`] closely (same seq discipline, same
//! size limit, same "persists only for this process's lifetime" caveat)
//! since Roster and Policy are "always issued together with the same
//! `seq`" (protocol.md 2.3), but kept as a genuinely separate store, not
//! folded into `RosterStore`: a relay only ever holds Rosters (Policy
//! "is delivered end to end between members and never to a relay"), so
//! merging the two types here would blur a distinction the spec itself
//! draws and `menzil-relay` already depends on.
//!
//! [`PolicyStore::check_membership`] and [`PolicyStore::has_grant`]
//! implement the two checks protocol.md 5.1's "Checks" paragraph and
//! 5.3's grant-gate sentence name, as pure, synchronous, no-I/O
//! functions — reusable by whichever of L4d/e/g/h first drives an actual
//! L4 handshake or OPEN. `has_grant` also independently re-checks the
//! Roster (not just the Policy) for `from`'s own standing — see its own
//! doc comment; a red-team review of this module (2026-10-01, opus,
//! fresh agent, live-verified every finding by running code, not just
//! reading it) found that without this, a Roster revocation that has not
//! yet been matched by a corresponding Policy update (the normal
//! revocation window: the Roster arrives by relay DOC, protocol.md 4.3,
//! while the Policy only ever travels end to end, 5.5, and nothing
//! implements that push yet, TODO.md L4j) would leave a stale grant
//! usable, contradicting 7.3 ("peers close its L4 sessions on receipt
//! and refuse new ones").
//!
//! Deliberately NOT built here: section 8's egress allow/deny evaluation
//! (its own separate, not-yet-started TODO line); live re-evaluation
//! when a Policy or Roster changes mid-session, or when a grant's own
//! `expires` passes while a stream is already open (protocol.md 5.3's
//! last sentence; TODO.md L4k) — these functions only ever answer "right
//! now, with whatever is currently held," never watch for a later
//! change, and (the same review) found that `check_membership`'s two
//! `RosterStore`/`PolicyStore` reads are themselves two independent
//! snapshots, not one atomic one — a `set()` landing on either store
//! between them is a real, if vanishingly narrow (sub-microsecond lock
//! hold times either side; the review's own concurrent stress test found
//! it live only once in 210 million checks, and only after artificially
//! widening the window 1000x), race, the same already-accepted class of
//! gap `menzil-relay/src/forward.rs`'s own doc comment describes for an
//! analogous check-then-act window there; the responder's own
//! cert-identity check ("the initiator's `node_id` equals the RECV `src`
//! and its static key matches") — that is `menzil-e2e`'s job against the
//! Noise handshake itself, not a Policy question; and per-verifier
//! "highest serial accepted" memory (protocol.md 2.2: "verifiers reject
//! a lower serial than the highest they have accepted for this
//! `node_id`") across repeated calls — `check_membership` only compares
//! a serial against the Roster's own `min_serial` floor, the same way
//! `menzil-relay`'s `hello::check_hello` and `menzil-node`'s own L3 side
//! already separate "below the Roster's stated floor" from "below what I
//! personally last saw"; the latter needs a persistent per-peer store
//! this crate does not yet have for L4 (the L3 side's own identical gap
//! is flagged in DONE.md's L3d/L3e entries) — surfaced as its own
//! TODO.md line rather than silently assumed covered by this one.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ed25519_dalek::VerifyingKey;
use menzil_proto::{
    ErrorCode, NetworkId, NodeId, NodeOrWildcard, Policy, PolicyBody, PolicyMember, Principal,
    PrincipalTarget, ProtoError, RosterBody, ServiceId,
};

use crate::error::NodeError;
use crate::roster_store::RosterStore;

/// This node's held Policies, at most one per network. The decoded
/// [`PolicyBody`] is kept behind an [`Arc`], for the same reason as
/// [`crate::RosterStore`]'s identical choice — see its doc comment.
#[derive(Default)]
pub struct PolicyStore {
    by_network: RwLock<HashMap<NetworkId, (Policy, Arc<PolicyBody>)>>,
}

impl PolicyStore {
    /// An empty store, holding nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies `policy`'s signature against its own claimed
    /// `network_id`, then stores it unless a Policy already held for
    /// that network has an equal or higher `seq` (protocol.md 2.3: "it
    /// never accepts a lower seq") — identical discipline to
    /// [`RosterStore::set`], see its doc comment for why. Returns
    /// whether it was actually stored.
    ///
    /// Rejects a Policy whose encoded form exceeds
    /// [`menzil_proto::MAX_DOC_BYTES`] before ever storing it, same as
    /// `RosterStore::set` and `menzil-relay`'s identical check.
    pub fn set(&self, policy: &Policy) -> Result<bool, NodeError> {
        let body = policy.decode()?;
        let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.network_id))
            .map_err(ProtoError::from)?;
        policy.verify(&verifying_key)?;
        let encoded_len = policy.encode().len();
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
        guard.insert(body.network_id, (policy.clone(), Arc::new(body)));
        Ok(true)
    }

    /// The currently held signed Policy for `network_id`, if any — the
    /// verbatim bytes a `menzil:docs` push (protocol.md 5.5; TODO.md
    /// L4j) will eventually send on, the same way `RosterStore::get`
    /// serves DOC(roster) propagation today.
    pub fn get(&self, network_id: &NetworkId) -> Option<Policy> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|(signed, _)| signed.clone())
    }

    /// The currently held `seq` for `network_id`, if any — what an L4
    /// handshake payload's `policy_seq` (protocol.md 5.1) reports for a
    /// network this node already holds a Policy for.
    pub fn seq(&self, network_id: &NetworkId) -> Option<u64> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|(_, body)| body.seq)
    }

    /// The currently held, decoded [`PolicyBody`] for `network_id`, if
    /// any. `pub` for the same reason as [`RosterStore::body`]: a future
    /// caller inspecting `members`/`grants`/`egress`/`accept` directly
    /// (section 8's egress evaluation, `menzil:docs` display) shouldn't
    /// have to re-decode the verbatim signed form itself.
    pub fn body(&self, network_id: &NetworkId) -> Option<Arc<PolicyBody>> {
        self.by_network
            .read()
            .unwrap()
            .get(network_id)
            .map(|(_, body)| body.clone())
    }

    /// protocol.md 5.1's per-side membership and serial check: whether
    /// `node_id` is an unrevoked member of `network_id` in both an
    /// unexpired Roster (held by `rosters`) and an unexpired Policy
    /// (held here), and `cert_serial` (from the NodeCert the caller
    /// already decoded and verified — not this function's concern) is
    /// not below the Roster's `min_serial` for it.
    ///
    /// Checks one node at a time rather than a pair: protocol.md 5.1
    /// says "both are unrevoked members," but the two sides' own checks
    /// are otherwise identical, so the caller (not yet built; L4h) calls
    /// this once per side rather than this function hard-coding an
    /// initiator/responder shape it doesn't actually need to know about.
    /// Checked only against `network_id`'s own documents, not (unlike
    /// `menzil-relay`'s `RosterStore::min_serial_for`) the strictest
    /// `min_serial` across every network this node happens to hold
    /// documents for — protocol.md 5.1 scopes the whole "Checks"
    /// paragraph to one session's one named network, and a node's
    /// standing in an unrelated network has no stated bearing on this
    /// one; a deliberate reading, recorded here because the relay-side
    /// equivalent genuinely does read differently (relay, §4.1: a
    /// serial's floor is "any held Roster's min_serial for that node",
    /// unqualified by network — because one relay session simultaneously
    /// speaks for every network the node claimed, where an L4 session
    /// speaks for exactly one).
    ///
    /// Returns the specific [`ErrorCode`] a failure maps to, reusing the
    /// shared L3/L4 registry rather than inventing a parallel one — the
    /// same call `menzil-proto`'s `OpenAckBody::code` already made (see
    /// DONE.md's L4a entry). Two reuses this registry doesn't have a
    /// dedicated entry for, both flagged here rather than silently
    /// decided: a Policy (as opposed to Roster) expiry also reports
    /// `RosterExpired` — there is no separate `policy_expired` code, and
    /// since the two documents are always issued together at the same
    /// `seq`, protocol.md does not appear to anticipate them disagreeing
    /// on `expires` either, though this type does not itself enforce
    /// that; and a serial below the Roster's `min_serial` reports
    /// `StaleSerial`, whose existing doc comment frames it as a HELLO/L3
    /// concept ("not higher than one already seen") — reused here for
    /// the closest matching L4 concept (protocol.md 5.1 names no code
    /// for this check at all; in fact protocol.md 5.1 never actually
    /// states what, if anything, the responder sends back when this
    /// whole check fails — only the separate grant-gate sentence right
    /// after it gets an explicit wire answer, CLOSE `no_grant`; flagged
    /// for whoever builds the wire-facing caller, not resolved here).
    ///
    /// **Caution for that future caller, recorded here because a
    /// red-team review raised it directly**: this `Err`'s distinct
    /// variants (`UnknownNetwork` vs `RosterExpired` vs `NotMember` vs
    /// `Revoked` vs `StaleSerial`) are useful for local diagnostics, but
    /// putting one on the wire verbatim would let a peer with no real
    /// standing distinguish "you don't hold this network at all" from
    /// "you do, but I'm not in it" from "I'm in it but revoked" —
    /// exactly the class of oracle `menzil-relay/src/forward.rs`'s own
    /// finding M2 closed off by making `RosterStore::grants_forwarding`
    /// return a bare `bool` instead. A wire-facing caller should collapse
    /// this to one uniform outward answer, the same way `forward.rs`
    /// does, and keep the detail only in local logs.
    pub fn check_membership(
        &self,
        rosters: &RosterStore,
        network_id: &NetworkId,
        node_id: &NodeId,
        cert_serial: u32,
        now: u64,
    ) -> Result<(), ErrorCode> {
        let roster = rosters.body(network_id).ok_or(ErrorCode::UnknownNetwork)?;
        let policy = self.body(network_id).ok_or(ErrorCode::UnknownNetwork)?;

        if roster.expires <= now || policy.expires <= now {
            return Err(ErrorCode::RosterExpired);
        }

        let min_serial = roster_standing(&roster, node_id)?;

        if !policy.members.iter().any(|m| &m.node_id == node_id) {
            return Err(ErrorCode::NotMember);
        }

        if cert_serial < min_serial {
            return Err(ErrorCode::StaleSerial);
        }

        Ok(())
    }

    /// protocol.md 5.1's handshake grant gate ("the responder... decides
    /// whether any grant exists for the initiator on this node"; pass
    /// `service: None`) and 5.3's per-OPEN grant check ("evaluates the
    /// grant for `(network, initiator)` on `(this node, service)`"; pass
    /// `service: Some(id)`) — the same underlying question, narrowed by
    /// one optional filter, so both call sites share one implementation
    /// rather than two that could drift apart.
    ///
    /// Also independently re-checks `from`'s own Roster standing
    /// (present, unrevoked, in an unexpired Roster) before ever
    /// consulting `rosters` — *not* redundant with a caller that already
    /// ran [`Self::check_membership`] once at handshake time: by the
    /// time an OPEN arrives, possibly long into a session, the Roster
    /// may have moved on (added this session 2026-10-01 after a
    /// red-team review demonstrated the gap directly: a Roster revoking
    /// `from` while the held Policy, not yet updated to match — the
    /// ordinary revocation window, since Rosters and Policies propagate
    /// over entirely different channels, 4.3 vs. 5.5 — still names a
    /// live grant for it, made `has_grant` return `true` before this
    /// check existed). This function does not, however, re-check
    /// `cert_serial` against `min_serial`: nothing calling it at OPEN
    /// time is expected to have a fresh serial in hand the way handshake
    /// time does, and a stale-cert concern is what re-handshaking
    /// (protocol.md 5.1/5.2, not this check) exists to force.
    ///
    /// A grant matches when: its `from` resolves to `from` (either a
    /// direct `Principal::Node` match, or a `Principal::Role` the Policy
    /// lists `from` as holding); its `to_node` resolves to `to_node`
    /// (an exact match or the `"*"` wildcard); it is not itself expired;
    /// and, only when `service` is given, at least one of its `services`
    /// patterns matches that service ([`ServiceId::matches_pattern`]) —
    /// when `service` is `None` (the handshake gate), a grant with an
    /// empty `services` list does not count as "any grant exists": an
    /// empty list can authorize nothing at all, so treating it as
    /// sufficient to pass the gate would let an initiator complete a
    /// full session (5.1: otherwise "the initiator learns nothing
    /// further") on a grant that can never actually open anything.
    /// Section 8's egress allow/deny rules are a separate, later check
    /// this function does not make — it only answers whether an
    /// `egress:*` grant exists at all, the same as for any other
    /// service.
    ///
    /// Defensively also requires `grant.from.network_id == *network_id`:
    /// `Principal` carries its own `network_id` field (protocol.md 2.3),
    /// independent of the `PolicyBody.network_id` this store already
    /// indexed by to find `grant` in the first place, and nothing in the
    /// wire type stops the two from disagreeing. Honoring a grant whose
    /// embedded Principal names a different network than the Policy
    /// document it was found in would let that document mint standing
    /// in a network it was never signed for; this check closes that off
    /// rather than assuming an owner-signed document never does it by
    /// accident or otherwise.
    pub fn has_grant(
        &self,
        rosters: &RosterStore,
        network_id: &NetworkId,
        from: &NodeId,
        to_node: &NodeId,
        service: Option<&ServiceId>,
        now: u64,
    ) -> bool {
        let Some(policy) = self.body(network_id) else {
            return false;
        };
        let Some(roster) = rosters.body(network_id) else {
            return false;
        };
        if roster.expires <= now || policy.expires <= now {
            return false;
        }
        if roster_standing(&roster, from).is_err() {
            return false;
        }

        policy.grants.iter().any(|grant| {
            grant.from.network_id == *network_id
                && principal_matches(&grant.from, from, &policy.members)
                && to_node_matches(&grant.to_node, to_node)
                && grant.expires.is_none_or(|expires| expires > now)
                && match service {
                    None => !grant.services.is_empty(),
                    Some(service) => grant
                        .services
                        .iter()
                        .any(|pattern| service.matches_pattern(pattern)),
                }
        })
    }
}

/// `node_id`'s standing in `roster` right now: `Ok(min_serial)` — the
/// *highest* `min_serial` among every entry naming `node_id`, not merely
/// the first found — if it is present and not revoked, else the specific
/// [`ErrorCode`] (`Revoked`, checked first and independently of
/// membership, the same order `menzil-relay`'s `is_unrevoked_member` and
/// `check_hello` already use and for the same reason: a Roster naming a
/// node in both `members` and `revoked` at once is possible to
/// construct, and revocation must still win; or `NotMember`).
///
/// Taking the max rather than the first matching entry matters: a Roster
/// is not specified to forbid duplicate `node_id` entries in `members`,
/// and protocol.md 7.3's compromise response ("gets `min_serial` raised
/// in the Roster") is meant to win even if an older, lower-`min_serial`
/// entry for the same node also still lingers in the list — a plain
/// `.find()` (what `menzil-relay`'s own analogous `min_serial_for`
/// currently does, within one network — a pre-existing, identical gap
/// there, not fixed as part of this item since it is a different crate's
/// already-shipped code) would silently honor whichever entry happens to
/// come first, which could be the stale, lower one.
fn roster_standing(roster: &RosterBody, node_id: &NodeId) -> Result<u32, ErrorCode> {
    if roster.revoked.iter().any(|r| &r.node_id == node_id) {
        return Err(ErrorCode::Revoked);
    }
    roster
        .members
        .iter()
        .filter(|m| &m.node_id == node_id)
        .map(|m| m.min_serial)
        .max()
        .ok_or(ErrorCode::NotMember)
}

/// Whether `principal` names `candidate`: directly (`Principal::Node`),
/// or by a role `candidate` holds per `members` (`Principal::Role`) —
/// protocol.md 2.3: "`Principal` is `{ network_id, node_id }` or
/// `{ network_id, role }`."
fn principal_matches(principal: &Principal, candidate: &NodeId, members: &[PolicyMember]) -> bool {
    match &principal.target {
        PrincipalTarget::Node(node_id) => node_id == candidate,
        PrincipalTarget::Role(role) => members
            .iter()
            .any(|member| &member.node_id == candidate && member.roles.iter().any(|r| r == role)),
    }
}

/// Whether `to_node` names `candidate`: directly, or via the `"*"`
/// wildcard (protocol.md 2.3: `to_node: node_id | "*"`).
fn to_node_matches(to_node: &NodeOrWildcard, candidate: &NodeId) -> bool {
    match to_node {
        NodeOrWildcard::Node(node_id) => node_id == candidate,
        NodeOrWildcard::Any => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{AcceptEntry, EgressRule, Grant, RevokedMember, Roster, RosterMember};

    fn network_id_for(owner: &SigningKey) -> NetworkId {
        NetworkId::from(owner.verifying_key().to_bytes())
    }

    fn signed_roster(
        owner: &SigningKey,
        network_id: NetworkId,
        seq: u64,
        members: Vec<RosterMember>,
        revoked: Vec<RevokedMember>,
        expires: u64,
    ) -> Roster {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq,
            issued: 0,
            expires,
            members,
            revoked,
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    /// A single-member, non-revoked, far-future-expiry Roster — the
    /// common case most `has_grant` tests need just to clear the new
    /// Roster-standing check, without caring about Roster specifics.
    fn roster_with_members(
        owner: &SigningKey,
        network_id: NetworkId,
        members: Vec<NodeId>,
    ) -> Roster {
        signed_roster(
            owner,
            network_id,
            1,
            members
                .into_iter()
                .map(|node_id| RosterMember {
                    node_id,
                    min_serial: 1,
                })
                .collect(),
            vec![],
            4_000_000_000,
        )
    }

    fn policy_body(
        network_id: NetworkId,
        seq: u64,
        members: Vec<PolicyMember>,
        grants: Vec<Grant>,
        expires: u64,
    ) -> PolicyBody {
        PolicyBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq,
            issued: 0,
            expires,
            members,
            certs: vec![],
            grants,
            egress: Vec::<EgressRule>::new(),
            accept: Vec::<AcceptEntry>::new(),
        }
    }

    fn signed_policy(owner: &SigningKey, body: PolicyBody) -> Policy {
        Policy::sign(owner, &body).unwrap()
    }

    #[test]
    fn set_then_get_and_seq_round_trip() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let store = PolicyStore::new();
        let body = policy_body(network_id, 4, vec![], vec![], 1_000_000_000);
        let policy = signed_policy(&owner, body);
        assert!(store.set(&policy).unwrap());
        assert_eq!(store.get(&network_id), Some(policy));
        assert_eq!(store.seq(&network_id), Some(4));
    }

    #[test]
    fn a_policy_not_signed_by_its_own_claimed_network_id_is_rejected() {
        let owner = SigningKey::generate(&mut rand::rng());
        let wrong_id = NetworkId::from([0x11; 32]);
        let store = PolicyStore::new();
        let body = policy_body(wrong_id, 1, vec![], vec![], 1_000_000_000);
        assert!(store.set(&signed_policy(&owner, body)).is_err());
        assert!(store.get(&wrong_id).is_none());
    }

    #[test]
    fn a_lower_or_equal_seq_does_not_replace_the_held_policy() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let store = PolicyStore::new();
        let b5 = policy_body(network_id, 5, vec![], vec![], 1_000_000_000);
        assert!(store.set(&signed_policy(&owner, b5)).unwrap());
        let b5_again = policy_body(network_id, 5, vec![], vec![], 1_000_000_000);
        assert!(!store.set(&signed_policy(&owner, b5_again)).unwrap());
        let b3 = policy_body(network_id, 3, vec![], vec![], 1_000_000_000);
        assert!(!store.set(&signed_policy(&owner, b3)).unwrap());
        assert_eq!(store.seq(&network_id), Some(5));
    }

    #[test]
    fn a_higher_seq_replaces_the_held_policy() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![], 1_000_000_000),
            ))
            .unwrap();
        assert!(
            store
                .set(&signed_policy(
                    &owner,
                    policy_body(network_id, 2, vec![], vec![], 1_000_000_000),
                ))
                .unwrap()
        );
        assert_eq!(store.seq(&network_id), Some(2));
    }

    #[test]
    fn a_policy_over_the_document_size_limit_is_rejected_not_stored() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let members: Vec<PolicyMember> = (0..20_000)
            .map(|i| PolicyMember {
                node_id: NodeId::from([(i % 256) as u8; 32]),
                name: format!("member-{i}"),
                roles: vec![],
            })
            .collect();
        let body = policy_body(network_id, 1, members, vec![], 1_000_000_000);
        let policy = signed_policy(&owner, body);
        assert!(policy.encode().len() > menzil_proto::MAX_DOC_BYTES);

        let store = PolicyStore::new();
        let err = store.set(&policy).unwrap_err();
        assert!(matches!(err, NodeError::DocumentTooLarge { .. }));
        assert!(store.get(&network_id).is_none());
    }

    struct Fixture {
        rosters: RosterStore,
        policies: PolicyStore,
        network_id: NetworkId,
        a: NodeId,
        b: NodeId,
    }

    /// A network with two members `a` and `b`, Roster `min_serial: 3`
    /// for `a`, Policy listing `a` with role `"admin"` — neither
    /// revoked, neither document expired by default.
    fn fixture() -> Fixture {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);

        let rosters = RosterStore::new();
        rosters
            .set(&signed_roster(
                &owner,
                network_id,
                1,
                vec![
                    RosterMember {
                        node_id: a,
                        min_serial: 3,
                    },
                    RosterMember {
                        node_id: b,
                        min_serial: 1,
                    },
                ],
                vec![],
                4_000_000_000,
            ))
            .unwrap();

        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &owner,
                policy_body(
                    network_id,
                    1,
                    vec![
                        PolicyMember {
                            node_id: a,
                            name: "alice".to_string(),
                            roles: vec!["admin".to_string()],
                        },
                        PolicyMember {
                            node_id: b,
                            name: "bob".to_string(),
                            roles: vec![],
                        },
                    ],
                    vec![],
                    4_000_000_000,
                ),
            ))
            .unwrap();

        Fixture {
            rosters,
            policies,
            network_id,
            a,
            b,
        }
    }

    #[test]
    fn check_membership_passes_for_a_member_meeting_min_serial() {
        let f = fixture();
        assert!(
            f.policies
                .check_membership(&f.rosters, &f.network_id, &f.a, 3, 1_000)
                .is_ok()
        );
    }

    #[test]
    fn check_membership_passes_for_the_fixtures_other_member_too() {
        // `b` has no role and the fixture's default `min_serial: 1` — a
        // second, independent passing case so the fixture's own second
        // member is actually exercised, not only ever used to populate
        // the documents `a`'s checks run against.
        let f = fixture();
        assert!(
            f.policies
                .check_membership(&f.rosters, &f.network_id, &f.b, 1, 1_000)
                .is_ok()
        );
    }

    #[test]
    fn check_membership_fails_unknown_network() {
        let f = fixture();
        let other = NetworkId::from([0x22; 32]);
        assert_eq!(
            f.policies
                .check_membership(&f.rosters, &other, &f.a, 3, 1_000)
                .unwrap_err(),
            ErrorCode::UnknownNetwork
        );
    }

    #[test]
    fn check_membership_fails_when_only_the_policy_is_missing() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let node_id = NodeId::from([1u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![node_id]))
            .unwrap();
        let policies = PolicyStore::new();
        assert_eq!(
            policies
                .check_membership(&rosters, &network_id, &node_id, 1, 1_000)
                .unwrap_err(),
            ErrorCode::UnknownNetwork
        );
    }

    #[test]
    fn check_membership_fails_revoked() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&signed_roster(
                &owner,
                network_id,
                1,
                vec![RosterMember {
                    node_id: a,
                    min_serial: 1,
                }],
                vec![RevokedMember {
                    node_id: a,
                    since: 500,
                }],
                4_000_000_000,
            ))
            .unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &owner,
                policy_body(
                    network_id,
                    1,
                    vec![PolicyMember {
                        node_id: a,
                        name: "alice".to_string(),
                        roles: vec![],
                    }],
                    vec![],
                    4_000_000_000,
                ),
            ))
            .unwrap();
        assert_eq!(
            policies
                .check_membership(&rosters, &network_id, &a, 1, 1_000)
                .unwrap_err(),
            ErrorCode::Revoked
        );
    }

    #[test]
    fn check_membership_fails_not_member_of_roster() {
        let f = fixture();
        let stranger = NodeId::from([0x33; 32]);
        assert_eq!(
            f.policies
                .check_membership(&f.rosters, &f.network_id, &stranger, 1, 1_000)
                .unwrap_err(),
            ErrorCode::NotMember
        );
    }

    #[test]
    fn check_membership_fails_not_member_of_roster_even_when_present_in_the_policy() {
        // Pins the Roster-membership requirement specifically: `c` is a
        // real Policy member here, so only the Roster-side check can
        // produce `NotMember` for it — unlike the plain-stranger test
        // above, which a mutant deleting the Roster check entirely would
        // still pass via the (unaffected) Policy-side check.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let c = NodeId::from([0x44; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![]))
            .unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &owner,
                policy_body(
                    network_id,
                    1,
                    vec![PolicyMember {
                        node_id: c,
                        name: "carol".to_string(),
                        roles: vec![],
                    }],
                    vec![],
                    4_000_000_000,
                ),
            ))
            .unwrap();
        assert_eq!(
            policies
                .check_membership(&rosters, &network_id, &c, 1, 1_000)
                .unwrap_err(),
            ErrorCode::NotMember
        );
    }

    #[test]
    fn check_membership_fails_not_member_of_policy_even_if_in_the_roster() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a]))
            .unwrap();
        // Policy for this network exists but never lists `a`.
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![], 4_000_000_000),
            ))
            .unwrap();
        assert_eq!(
            policies
                .check_membership(&rosters, &network_id, &a, 1, 1_000)
                .unwrap_err(),
            ErrorCode::NotMember
        );
    }

    #[test]
    fn check_membership_fails_roster_expired() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&signed_roster(
                &owner,
                network_id,
                1,
                vec![RosterMember {
                    node_id: a,
                    min_serial: 1,
                }],
                vec![],
                500, // expires well before `now` below
            ))
            .unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &owner,
                policy_body(
                    network_id,
                    1,
                    vec![PolicyMember {
                        node_id: a,
                        name: "alice".to_string(),
                        roles: vec![],
                    }],
                    vec![],
                    4_000_000_000,
                ),
            ))
            .unwrap();
        assert_eq!(
            policies
                .check_membership(&rosters, &network_id, &a, 1, 1_000)
                .unwrap_err(),
            ErrorCode::RosterExpired
        );
    }

    #[test]
    fn check_membership_fails_policy_expired_even_though_the_roster_is_fine() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a]))
            .unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &owner,
                policy_body(
                    network_id,
                    1,
                    vec![PolicyMember {
                        node_id: a,
                        name: "alice".to_string(),
                        roles: vec![],
                    }],
                    vec![],
                    500, // expires well before `now` below
                ),
            ))
            .unwrap();
        assert_eq!(
            policies
                .check_membership(&rosters, &network_id, &a, 1, 1_000)
                .unwrap_err(),
            ErrorCode::RosterExpired
        );
    }

    #[test]
    fn check_membership_fails_stale_serial() {
        let f = fixture();
        // `a`'s Roster min_serial is 3 (see `fixture`).
        assert_eq!(
            f.policies
                .check_membership(&f.rosters, &f.network_id, &f.a, 2, 1_000)
                .unwrap_err(),
            ErrorCode::StaleSerial
        );
    }

    #[test]
    fn check_membership_uses_the_highest_min_serial_among_duplicate_roster_entries() {
        // protocol.md 7.3's compromise response ("min_serial raised")
        // must win even if a stale, lower-min_serial entry for the same
        // node also still lingers in the Roster's `members` list.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&signed_roster(
                &owner,
                network_id,
                1,
                vec![
                    RosterMember {
                        node_id: a,
                        min_serial: 1,
                    },
                    RosterMember {
                        node_id: a,
                        min_serial: 5,
                    },
                ],
                vec![],
                4_000_000_000,
            ))
            .unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &owner,
                policy_body(
                    network_id,
                    1,
                    vec![PolicyMember {
                        node_id: a,
                        name: "alice".to_string(),
                        roles: vec![],
                    }],
                    vec![],
                    4_000_000_000,
                ),
            ))
            .unwrap();
        assert_eq!(
            policies
                .check_membership(&rosters, &network_id, &a, 3, 1_000)
                .unwrap_err(),
            ErrorCode::StaleSerial,
            "the higher duplicate entry's min_serial (5) must be the one enforced, not the lower \
             one (1) that happens to come first"
        );
        assert!(
            policies
                .check_membership(&rosters, &network_id, &a, 5, 1_000)
                .is_ok()
        );
    }

    #[test]
    fn has_grant_false_with_no_policy_for_the_network() {
        let policies = PolicyStore::new();
        let rosters = RosterStore::new();
        let other = NetworkId::from([0x44; 32]);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        assert!(!policies.has_grant(&rosters, &other, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_true_for_a_direct_node_principal_with_no_service_filter() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a, b]))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
        assert!(store.has_grant(
            &rosters,
            &network_id,
            &a,
            &b,
            Some(&"tcp:ssh".parse().unwrap()),
            1_000
        ));
        assert!(!store.has_grant(
            &rosters,
            &network_id,
            &a,
            &b,
            Some(&"tcp:web".parse().unwrap()),
            1_000
        ));
    }

    #[test]
    fn has_grant_true_via_role_membership() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let admin = NodeId::from([1u8; 32]);
        let target = NodeId::from([2u8; 32]);
        let not_admin = NodeId::from([3u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(
                &owner,
                network_id,
                vec![admin, not_admin],
            ))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Role("admin".to_string()),
            },
            to_node: NodeOrWildcard::Any,
            services: vec!["egress:*".parse().unwrap()],
            expires: None,
        };
        let members = vec![
            PolicyMember {
                node_id: admin,
                name: "alice".to_string(),
                roles: vec!["admin".to_string()],
            },
            PolicyMember {
                node_id: not_admin,
                name: "bob".to_string(),
                roles: vec!["user".to_string()],
            },
        ];
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, members, vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(store.has_grant(&rosters, &network_id, &admin, &target, None, 1_000));
        // `not_admin` is a real Policy member (unlike a bare stranger)
        // but holds the wrong role — a mutant that compared only "holds
        // *some* role" rather than "holds *this* role" would wrongly
        // pass this.
        assert!(!store.has_grant(&rosters, &network_id, &not_admin, &target, None, 1_000));
    }

    #[test]
    fn has_grant_false_once_the_grant_itself_expires() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a, b]))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: Some(500),
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(store.has_grant(&rosters, &network_id, &a, &b, None, 100));
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_false_once_the_policy_itself_is_expired() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a, b]))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 500),
            ))
            .unwrap();
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_false_when_to_node_names_someone_else() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let someone_else = NodeId::from([3u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a]))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(someone_else),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_ignores_a_grant_whose_principal_names_a_foreign_network() {
        // Defensive check documented on `has_grant`: a Grant's own
        // `Principal.network_id` disagreeing with the Policy document's
        // `network_id` it was found in must not be honored.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let foreign_network = NetworkId::from([0x55; 32]);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a]))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id: foreign_network,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_false_for_an_empty_services_list_with_no_service_filter() {
        // A grant that authorizes nothing concrete must not count as
        // "any grant exists" for the handshake gate either — otherwise
        // an initiator could complete a full L4 session on a grant that
        // can never actually open anything.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![a]))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec![],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_false_when_the_roster_has_revoked_from_even_though_the_policy_still_grants() {
        // The scenario a red-team review demonstrated directly: the
        // normal revocation window (Roster updates propagate over the
        // relay, protocol.md 4.3; the Policy only end to end, 5.5, and
        // nothing pushes it automatically yet) must not leave a stale
        // Policy grant usable once the Roster says `a` is revoked.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&signed_roster(
                &owner,
                network_id,
                2,
                vec![RosterMember {
                    node_id: a,
                    min_serial: 1,
                }],
                vec![RevokedMember {
                    node_id: a,
                    since: 500,
                }],
                4_000_000_000,
            ))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                // Policy is seq 1 — deliberately behind the Roster's seq
                // 2 above, modeling the lag the Roster/Policy propagation
                // split allows.
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_false_when_from_is_not_a_roster_member_at_all() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(&owner, network_id, vec![b]))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }

    #[test]
    fn has_grant_false_when_the_roster_itself_is_expired() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = network_id_for(&owner);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&signed_roster(
                &owner,
                network_id,
                1,
                vec![RosterMember {
                    node_id: a,
                    min_serial: 1,
                }],
                vec![],
                500, // expires well before `now` below
            ))
            .unwrap();
        let grant = Grant {
            from: Principal {
                network_id,
                target: PrincipalTarget::Node(a),
            },
            to_node: NodeOrWildcard::Node(b),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        };
        let store = PolicyStore::new();
        store
            .set(&signed_policy(
                &owner,
                policy_body(network_id, 1, vec![], vec![grant], 4_000_000_000),
            ))
            .unwrap();
        assert!(!store.has_grant(&rosters, &network_id, &a, &b, None, 1_000));
    }
}
