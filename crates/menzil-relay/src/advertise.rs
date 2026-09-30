//! ADVERTISE / ADVERTISE_ACK label claiming, relay side, against a held
//! Roster (protocol.md 4.4; TODO.md L3g), phase 1 scope only per
//! protocol.md 13's phase table: "4.4 label claims and quotas | claims in
//! Roster | quotas, custom domains, quarantine". Deliberately not here:
//!
//! - Per-network quotas (20 names, 5 new per week) and the 90-day-unused
//!   release / 180-day quarantine cycle — phase 2.
//! - Custom domains (a fully qualified name verified by its own
//!   `_menzil.<domain>` DNS TXT record) — phase 2; a `name` containing a
//!   dot is rejected here as not yet supported, not treated as a bare
//!   label under the relay's own domain.
//! - The operator's static-label-pinning alternative protocol.md 4.4
//!   describes for a personal relay ("the operator may instead pin
//!   labels statically in the relay configuration"), which bypasses
//!   claims and quotas entirely — no configuration surface exists for it
//!   yet (protocol.md 11 is informative only), tracked as a gap, not
//!   built here.
//! - Actually routing a ClientHello or a forwarded stream to whichever
//!   node currently holds a name (protocol.md 6.2, 6.3): this only
//!   validates a claim and remembers who currently holds it, for a
//!   future consumer that doesn't exist yet to build on.
//!
//! What phase 1 *does* need beyond the bare "claims in Roster" rule: two
//! different attached nodes must not both be actively serving the same
//! name at once (there would be no way for a future router to decide
//! which one a stream goes to), so this also tracks which NodeId
//! currently holds each accepted name, in memory, and refuses a second,
//! different node's claim while the first is still active. That is live
//! conflict avoidance, not a persistent quota or quarantine: claims are
//! session-scoped, not durable across a reconnect (`crate::session`
//! calls [`LabelRegistry::clear_for`] both right after a fresh attach
//! and on a genuine detach — see its own doc comment for why both), and
//! this has none of the 90-day-grace machinery phase 2 will eventually
//! add: a name is free again the moment its holder's session ends, for
//! any reason, which is only safe on a relay where every attached node
//! is already trusted not to race for another's name (see this crate's
//! `advertise` module's gap notes in DONE.md for the multi-tenant
//! caveat this implies).
//!
//! `crate::session` also only ever calls [`LabelRegistry::advertise`]
//! for a session it has independently confirmed is still the *current*
//! one for that NodeId (`SessionRegistry::is_current`) — ADVERTISE
//! received before ATTACH, or from a connection already superseded by a
//! newer one for the same NodeId, is never processed here at all. A red
//! team review found that a pre-attach ADVERTISE, left unguarded, both
//! bypassed the attach-time reset above (nothing ever detaches a
//! session that never attached) and could leak a claim forever if that
//! connection then simply disappeared.
//!
//! One narrower race from that same review is deliberately left open,
//! not fixed: `is_current` is checked, then acted on, as two separate
//! steps rather than one atomic one, so a session that was current at
//! the moment of its own check could in principle still be superseded,
//! by a *second* session that both attaches and sends its own ADVERTISE,
//! before the first session's own call into this module actually runs —
//! letting the stale one's write land after the fresh one's. Closing
//! this fully would mean giving `SessionRegistry` and `LabelRegistry` a
//! single shared lock, a bigger change than this gap's narrowness (it
//! needs two racing connections for the same NodeId within a tiny
//! window, not merely a slow reconnect) justified; it is the same class
//! of already-accepted gap `SessionRegistry::attach`'s own doc comment
//! describes ("callers do not wait for the old session to actually
//! finish leaving"), not a new one introduced here.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use menzil_proto::{
    AdvertiseAckBody, AdvertiseBody, ErrorCode, NetworkId, NodeId, RejectedShare, Share,
};

use crate::roster_store::RosterStore;

/// protocol.md 4.4's fixed reserved list ("`www`, `mail`, `admin`, `api`,
/// `relay`, `t`"); "the operator's own names" is the config-surface
/// extension this module's doc comment flags as not yet built.
pub const DEFAULT_RESERVED_LABELS: &[&str] = &["www", "mail", "admin", "api", "relay", "t"];

/// A defensive, implementation-only bound — protocol.md never states one
/// — on how many shares a single ADVERTISE may carry. Without it, a
/// single record near the L3 payload limit can carry thousands of
/// shares; validating each one against a large held Roster while
/// holding [`LabelRegistry`]'s write lock turned out to cost whole
/// seconds in practice (a red team review measured it), and even after
/// [`LabelRegistry::advertise`] was changed to look up all of a node's
/// grants in one pass instead of one Roster scan per share, echoing that
/// many rejections back still risks an ADVERTISE_ACK bigger than the
/// Noise transport can send in one record. An ADVERTISE over this cap is
/// refused outright, as a whole, with a single fixed-size rejection and
/// no effect on this node's existing claims — 64 is generously above
/// the still-unbuilt phase-2 quota (20 accepted names total), so no
/// legitimate caller should ever hit it.
const MAX_SHARES_PER_ADVERTISE: usize = 64;

/// The longest a share `name` is ever echoed back in a [`RejectedShare`],
/// regardless of why it was rejected. A name long enough to fail the LDH
/// length check can still be most of a whole L3 record (tens of
/// kilobytes); echoing it back verbatim would risk the ACK itself
/// exceeding the transport's own size limit for a single oversized
/// share, the same failure mode [`MAX_SHARES_PER_ADVERTISE`] guards
/// against for *many* shares.
const MAX_ECHOED_NAME_BYTES: usize = 96;

/// One node's currently accepted advertisement: exactly what its most
/// recent successful [`LabelRegistry::advertise`] call accepted, kept for
/// a future consumer (routing, TODO.md L3h's `accept_peers` check) —
/// nothing in this build reads `shares` yet.
struct NodeAdvertisement {
    shares: Vec<Share>,
    accept_peers: bool,
}

/// Which currently-attached node, if any, actively holds each accepted
/// label name, plus each node's own currently accepted advertisement.
/// Keyed and compared case-insensitively (ASCII-lowercased on the way
/// in): labels are user-facing hostnames, and DNS treats `Foo`/`foo` as
/// the same name.
#[derive(Default)]
pub struct LabelRegistry {
    by_label: RwLock<HashMap<String, NodeId>>,
    by_node: RwLock<HashMap<NodeId, NodeAdvertisement>>,
}

/// Truncates `name` to [`MAX_ECHOED_NAME_BYTES`] at a valid UTF-8 char
/// boundary (walking backward from the byte limit, which always
/// terminates: 0 is always a boundary), marking that it was cut.
fn truncate_for_echo(name: &str) -> String {
    if name.len() <= MAX_ECHOED_NAME_BYTES {
        return name.to_string();
    }
    let mut end = MAX_ECHOED_NAME_BYTES;
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &name[..end])
}

fn reject(name: &str, reason: impl Into<String>) -> RejectedShare {
    RejectedShare {
        name: truncate_for_echo(name),
        reason: reason.into(),
    }
}

/// `None` if `name` passes phase-1 syntax; otherwise the reason it never
/// reaches the Roster-claim or conflict checks at all. A name containing
/// a dot is a custom domain (protocol.md 4.4), not a bare LDH label,
/// checked and rejected before the LDH rule so its reason says why it is
/// unsupported rather than merely calling it malformed.
fn syntax_problem(name: &str) -> Option<&'static str> {
    if name.contains('.') {
        return Some("custom domains are not supported yet");
    }
    let bytes = name.as_bytes();
    let valid_ldh_label = (1..=63).contains(&bytes.len())
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-');
    if valid_ldh_label {
        None
    } else {
        Some(
            "not a valid label: 1-63 ASCII letters, digits or hyphens, \
             not starting or ending with a hyphen",
        )
    }
}

impl LabelRegistry {
    /// No claims active yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates every entry of `body.shares` for `node_id` (an already
    /// attached, currently-registered session, having claimed
    /// `claimed_networks` in its own HELLO — verifying that is the
    /// caller's job, see `crate::session`) against `rosters` and
    /// [`DEFAULT_RESERVED_LABELS`], records the accepted set as this
    /// node's new active advertisement — replacing whatever it had
    /// before, in full, including dropping this node's own prior claims
    /// of any name not present in `body.shares` this time — and returns
    /// the ADVERTISE_ACK to send back. `accept_peers` is always recorded
    /// as given, whether or not any share was accepted: protocol.md 4.2
    /// and 6.1 treat it as a property of the node itself, not of its
    /// shares, so a client-only node that advertises no shares at all
    /// must still be able to opt out of peer streams.
    ///
    /// protocol.md 4.4 does not say whether a later ADVERTISE is
    /// incremental or restates the node's complete current intent; this
    /// treats it as the latter, the simpler spec-silent choice and the
    /// one consistent with WELCOME's own `rosters` field being a full
    /// snapshot rather than a diff.
    ///
    /// `body.shares.len()` over [`MAX_SHARES_PER_ADVERTISE`] refuses the
    /// whole request at once, before touching any state — this node's
    /// existing claims, if any, are left exactly as they were.
    pub fn advertise(
        &self,
        rosters: &RosterStore,
        claimed_networks: &[NetworkId],
        node_id: &NodeId,
        body: &AdvertiseBody,
    ) -> AdvertiseAckBody {
        if body.shares.len() > MAX_SHARES_PER_ADVERTISE {
            return AdvertiseAckBody {
                accepted: vec![],
                rejected: vec![RejectedShare {
                    name: String::new(),
                    reason: format!(
                        "too many shares in one ADVERTISE (max {MAX_SHARES_PER_ADVERTISE})"
                    ),
                }],
            };
        }

        // Computed once, up front, outside any lock this method itself
        // holds: see `MAX_SHARES_PER_ADVERTISE`'s doc comment for why a
        // per-share Roster scan mattered in practice.
        let granted = rosters.labels_granted_to(claimed_networks, node_id);

        let mut accepted = Vec::new();
        let mut accepted_shares = Vec::new();
        let mut rejected = Vec::new();
        let mut seen = HashSet::new();

        let mut by_label = self.by_label.write().unwrap();
        // Release this node's own previous claims first, so re-claiming
        // the same name in this new ADVERTISE never conflicts with
        // itself, and a name it drops this time is immediately free for
        // someone else to claim.
        by_label.retain(|_, owner| *owner != *node_id);

        for share in &body.shares {
            let key = share.name.to_ascii_lowercase();
            if let Some(reason) = syntax_problem(&share.name) {
                rejected.push(reject(&share.name, reason));
                continue;
            }
            if DEFAULT_RESERVED_LABELS.contains(&key.as_str()) {
                rejected.push(reject(&share.name, "reserved name"));
                continue;
            }
            if !granted.contains(&key) {
                rejected.push(reject(&share.name, ErrorCode::LabelUnclaimed.name()));
                continue;
            }
            if !seen.insert(key.clone()) {
                rejected.push(reject(&share.name, "duplicate name in this ADVERTISE"));
                continue;
            }
            // Any entry still in `by_label` at this key belongs to some
            // other node: this node's own prior claims were already
            // stripped above, and an earlier share in this same request
            // sharing this key would already have been caught by the
            // `seen` check just above.
            if by_label.contains_key(&key) {
                rejected.push(reject(&share.name, ErrorCode::LabelTaken.name()));
                continue;
            }
            by_label.insert(key, *node_id);
            accepted.push(share.name.clone());
            accepted_shares.push(share.clone());
        }
        drop(by_label);

        self.by_node.write().unwrap().insert(
            *node_id,
            NodeAdvertisement {
                shares: accepted_shares,
                accept_peers: body.accept_peers,
            },
        );

        AdvertiseAckBody { accepted, rejected }
    }

    /// Releases every label `node_id` currently holds. `crate::session`
    /// calls this from two places, for two different reasons:
    ///
    /// - Right after a session newly attaches for `node_id` (before that
    ///   session gets a chance to send its own ADVERTISE), so claims are
    ///   session-scoped, not silently inherited across a reconnect — a
    ///   fresh session must re-ADVERTISE to reclaim anything, rather
    ///   than a stale superseded session's old claims (and its
    ///   `accept_peers` value) carrying over unasked-for. protocol.md
    ///   4.4 does not say whether claims survive a reconnect; this is
    ///   the safer of the two spec-silent choices, chosen after a red
    ///   team review found the alternative let a new session inherit an
    ///   old one's `accept_peers: false` it never itself asked for.
    /// - On a genuine detach (`SessionRegistry::detach` returned `true`:
    ///   the session that just ended was still the current one for this
    ///   NodeId, not one that already lost a supersede race), so a node
    ///   that goes fully idle eventually frees its names for someone
    ///   else — a session that lost a supersede race must not clear the
    ///   newer session's own, already-reasserted claims out from under
    ///   it, which is exactly what checking `detach`'s return guards.
    pub fn clear_for(&self, node_id: &NodeId) {
        self.by_label
            .write()
            .unwrap()
            .retain(|_, owner| *owner != *node_id);
        self.by_node.write().unwrap().remove(node_id);
    }

    /// Whether `node_id` currently accepts peer streams: `true` unless
    /// its most recently accepted advertisement explicitly set
    /// `accept_peers: false` (protocol.md 4.2's forwarding rule only
    /// blocks on that explicit case, so a node that never sent ADVERTISE
    /// at all, or whose ADVERTISE had every share rejected, still
    /// defaults to `true`). TODO.md L3h's job to actually call this.
    pub fn accepts_peers(&self, node_id: &NodeId) -> bool {
        self.by_node
            .read()
            .unwrap()
            .get(node_id)
            .map(|advertisement| advertisement.accept_peers)
            .unwrap_or(true)
    }

    /// `node_id`'s currently accepted shares — whatever its most recent
    /// successful [`LabelRegistry::advertise`] call accepted, or empty if
    /// it never has or everything was rejected. TODO.md L3h's (SNI/ALPN
    /// routing) and the future terminated-share-serving item's job to
    /// actually call this; nothing in this build does yet.
    pub fn shares_for(&self, node_id: &NodeId) -> Vec<Share> {
        self.by_node
            .read()
            .unwrap()
            .get(node_id)
            .map(|advertisement| advertisement.shares.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use menzil_proto::{Label, Roster, RosterBody, RosterMember, ShareMode};

    use super::*;

    fn seed_roster(
        rosters: &RosterStore,
        owner: &SigningKey,
        network_id: NetworkId,
        node_id: NodeId,
        labels: Vec<Label>,
    ) {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id,
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![],
            labels,
        };
        rosters.set(&Roster::sign(owner, &body).unwrap()).unwrap();
    }

    fn share(name: &str) -> Share {
        Share {
            name: name.to_string(),
            mode: ShareMode::Blind,
            service: "tcp:ssh".parse().unwrap(),
            alpn: vec![],
        }
    }

    fn advertise_body(names: &[&str], accept_peers: bool) -> AdvertiseBody {
        AdvertiseBody {
            v: menzil_proto::PROTOCOL_VERSION,
            shares: names.iter().map(|n| share(n)).collect(),
            accept_peers,
        }
    }

    struct Fixture {
        rosters: RosterStore,
        network_id: NetworkId,
        node_id: NodeId,
    }

    fn fixture_with_labels(labels: Vec<&str>) -> Fixture {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let node_id = NodeId::from([9u8; 32]);
        let rosters = RosterStore::new();
        seed_roster(
            &rosters,
            &owner,
            network_id,
            node_id,
            labels
                .into_iter()
                .map(|name| Label {
                    name: name.to_string(),
                    node_id,
                })
                .collect(),
        );
        Fixture {
            rosters,
            network_id,
            node_id,
        }
    }

    #[test]
    fn a_claimed_name_is_accepted() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );
        assert_eq!(ack.accepted, vec!["example"]);
        assert!(ack.rejected.is_empty());
    }

    #[test]
    fn a_name_not_claimed_in_any_held_roster_is_rejected_as_unclaimed() {
        let f = fixture_with_labels(vec![]);
        let registry = LabelRegistry::new();
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );
        assert!(ack.accepted.is_empty());
        assert_eq!(ack.rejected[0].reason, ErrorCode::LabelUnclaimed.name());
    }

    #[test]
    fn a_name_claimed_only_in_a_network_this_node_did_not_claim_is_rejected() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        // Deliberately not passing `f.network_id` here, as if this
        // node's own HELLO never claimed that network.
        let ack = registry.advertise(
            &f.rosters,
            &[],
            &f.node_id,
            &advertise_body(&["example"], true),
        );
        assert!(ack.accepted.is_empty());
        assert_eq!(ack.rejected[0].reason, ErrorCode::LabelUnclaimed.name());
    }

    #[test]
    fn a_reserved_name_is_rejected_even_if_claimed() {
        let f = fixture_with_labels(vec!["api"]);
        let registry = LabelRegistry::new();
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["api"], true),
        );
        assert!(ack.accepted.is_empty());
        assert_eq!(ack.rejected[0].reason, "reserved name");
    }

    #[test]
    fn an_invalid_ldh_label_is_rejected() {
        let f = fixture_with_labels(vec!["-bad-"]);
        let registry = LabelRegistry::new();
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["-bad-"], true),
        );
        assert!(ack.accepted.is_empty());
        assert!(ack.rejected[0].reason.contains("not a valid label"));
    }

    #[test]
    fn a_custom_domain_name_is_rejected_as_unsupported() {
        let f = fixture_with_labels(vec!["example.com"]);
        let registry = LabelRegistry::new();
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example.com"], true),
        );
        assert!(ack.accepted.is_empty());
        assert_eq!(
            ack.rejected[0].reason,
            "custom domains are not supported yet"
        );
    }

    #[test]
    fn a_duplicate_name_in_one_advertise_is_accepted_once_and_rejected_after() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example", "example"], true),
        );
        assert_eq!(ack.accepted, vec!["example"]);
        assert_eq!(ack.rejected[0].reason, "duplicate name in this ADVERTISE");
        assert_eq!(
            registry.shares_for(&f.node_id).len(),
            1,
            "only the genuinely accepted share may be stored, not the rejected duplicate too"
        );
    }

    #[test]
    fn the_rejected_duplicate_itself_is_never_stored_even_when_it_differs_from_the_accepted_one() {
        // Same name, deliberately different `mode`, so storing the wrong
        // one of the two would be observable: the duplicate check only
        // compares `name`, so a naive "keep every share whose name is in
        // `accepted`" filter would keep both.
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        let body = AdvertiseBody {
            v: menzil_proto::PROTOCOL_VERSION,
            shares: vec![
                Share {
                    mode: ShareMode::Blind,
                    ..share("example")
                },
                Share {
                    mode: ShareMode::Terminated,
                    ..share("example")
                },
            ],
            accept_peers: true,
        };
        registry.advertise(&f.rosters, &[f.network_id], &f.node_id, &body);

        let shares = registry.shares_for(&f.node_id);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].mode, ShareMode::Blind);
    }

    #[test]
    fn too_many_shares_in_one_advertise_is_refused_as_a_whole() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );

        let names: Vec<String> = (0..=MAX_SHARES_PER_ADVERTISE)
            .map(|i| format!("name{i}"))
            .collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&name_refs, false),
        );
        assert!(ack.accepted.is_empty());
        assert_eq!(ack.rejected.len(), 1);
        assert!(ack.rejected[0].reason.contains("too many shares"));

        // This node's earlier, valid claim must be untouched: an
        // over-cap request is refused before it can affect any state.
        let shares = registry.shares_for(&f.node_id);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "example");
        assert!(registry.accepts_peers(&f.node_id));
    }

    #[test]
    fn an_oversized_name_is_truncated_in_the_ack_not_echoed_verbatim() {
        let rosters = RosterStore::new();
        let registry = LabelRegistry::new();
        let huge_name = "a".repeat(5000);
        let ack = registry.advertise(
            &rosters,
            &[],
            &NodeId::from([1u8; 32]),
            &advertise_body(&[&huge_name], true),
        );
        assert_eq!(ack.rejected.len(), 1);
        assert!(
            ack.rejected[0].name.len() < 200,
            "echoed name was {} bytes",
            ack.rejected[0].name.len()
        );
    }

    #[test]
    fn a_second_different_node_cannot_claim_a_name_another_node_actively_holds() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let holder = NodeId::from([1u8; 32]);
        let challenger = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        // One Roster, both nodes members, and — protocol.md 4.4 never
        // forbids an owner's own Roster from granting what a viewer
        // would consider "the same" name to two different NodeIds — the
        // same name claimed for both. Nothing about a `RosterStore`
        // (one held Roster per network) rejects this; it is this live,
        // in-memory conflict check's job to still only let one of them
        // actually hold it at a time.
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![
                RosterMember {
                    node_id: holder,
                    min_serial: 1,
                },
                RosterMember {
                    node_id: challenger,
                    min_serial: 1,
                },
            ],
            revoked: vec![],
            stewards: vec![],
            labels: vec![
                Label {
                    name: "example".to_string(),
                    node_id: holder,
                },
                Label {
                    name: "example".to_string(),
                    node_id: challenger,
                },
            ],
        };
        rosters.set(&Roster::sign(&owner, &body).unwrap()).unwrap();

        let registry = LabelRegistry::new();
        let holder_ack = registry.advertise(
            &rosters,
            &[network_id],
            &holder,
            &advertise_body(&["example"], true),
        );
        assert_eq!(holder_ack.accepted, vec!["example"]);

        let challenger_ack = registry.advertise(
            &rosters,
            &[network_id],
            &challenger,
            &advertise_body(&["example"], true),
        );
        assert!(challenger_ack.accepted.is_empty());
        assert_eq!(
            challenger_ack.rejected[0].reason,
            ErrorCode::LabelTaken.name()
        );
    }

    #[test]
    fn re_advertising_drops_a_name_no_longer_included_and_frees_it() {
        let f = fixture_with_labels(vec!["one", "two"]);
        let registry = LabelRegistry::new();
        registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["one", "two"], true),
        );
        let ack = registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["one"], true),
        );
        assert_eq!(ack.accepted, vec!["one"]);

        // "two" is free again: a different node can now claim it, drawn
        // from a fresh Roster that grants it to that other node.
        let owner = SigningKey::generate(&mut rand::rng());
        let other_network = NetworkId::from(owner.verifying_key().to_bytes());
        let other_node = NodeId::from([7u8; 32]);
        seed_roster(
            &f.rosters,
            &owner,
            other_network,
            other_node,
            vec![Label {
                name: "two".to_string(),
                node_id: other_node,
            }],
        );
        let other_ack = registry.advertise(
            &f.rosters,
            &[other_network],
            &other_node,
            &advertise_body(&["two"], true),
        );
        assert_eq!(other_ack.accepted, vec!["two"]);
    }

    #[test]
    fn clear_for_releases_a_nodes_claims_for_another_node_to_take() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );
        registry.clear_for(&f.node_id);

        let owner = SigningKey::generate(&mut rand::rng());
        let other_network = NetworkId::from(owner.verifying_key().to_bytes());
        let other_node = NodeId::from([7u8; 32]);
        seed_roster(
            &f.rosters,
            &owner,
            other_network,
            other_node,
            vec![Label {
                name: "example".to_string(),
                node_id: other_node,
            }],
        );
        let ack = registry.advertise(
            &f.rosters,
            &[other_network],
            &other_node,
            &advertise_body(&["example"], true),
        );
        assert_eq!(ack.accepted, vec!["example"]);
    }

    #[test]
    fn accepts_peers_defaults_to_true_before_any_advertise() {
        let registry = LabelRegistry::new();
        assert!(registry.accepts_peers(&NodeId::from([1u8; 32])));
    }

    #[test]
    fn accepts_peers_reflects_the_most_recent_advertise() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], false),
        );
        assert!(!registry.accepts_peers(&f.node_id));

        registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );
        assert!(registry.accepts_peers(&f.node_id));
    }

    #[test]
    fn shares_for_reflects_the_accepted_set_and_is_empty_for_an_unknown_node() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        assert!(registry.shares_for(&f.node_id).is_empty());

        registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );
        let shares = registry.shares_for(&f.node_id);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].name, "example");
    }

    #[test]
    fn accept_peers_is_honored_even_when_every_share_was_rejected() {
        let f = fixture_with_labels(vec![]);
        let registry = LabelRegistry::new();
        // Nothing here is claimed in any held Roster, so the one share
        // is rejected — but `accept_peers` is a property of the node
        // itself (protocol.md 4.2, 6.1), independent of which shares
        // succeeded, and must still be recorded, not silently dropped
        // back to the "never advertised" default.
        registry.advertise(
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], false),
        );
        assert!(!registry.accepts_peers(&f.node_id));
    }

    #[test]
    fn accept_peers_is_honored_with_no_shares_at_all() {
        let rosters = RosterStore::new();
        let registry = LabelRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        registry.advertise(&rosters, &[], &node_id, &advertise_body(&[], false));
        assert!(!registry.accepts_peers(&node_id));
    }
}
