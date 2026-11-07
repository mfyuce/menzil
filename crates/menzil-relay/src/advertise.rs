//! ADVERTISE / ADVERTISE_ACK label claiming, relay side, against a held
//! Roster (protocol.md 4.4; TODO.md L3g; multi tenant design 2.2 and 2.3, slice MT9).
//!
//! # Names per tenant
//!
//! A Roster's `labels.name` stays one LDH label. The relay composes the full name from the label
//! and the tenant of the network whose Roster granted it: the default tenant's `app` is `app`
//! (`app.H`), tenant `ali`'s is `app.ali` (`app.ali.H`), and a label the operator granted a
//! tenant through `extra_names` is the flat `app` (`app.H`) of that tenant. The registry is keyed
//! by full name, so a tenant can never produce a name in another tenant's zone, a collision
//! (`label_taken`) exists only inside one tenant, and the answer to a tenant never depends on
//! what another tenant holds (design 2.4 rule I5; closes threats A5 and A6). A node that holds
//! one label in two tenants' networks gets it in both zones; the ACK lists the full names in
//! `names` (relative to the relay's share domain).
//!
//! Per tenant with figures (the `friend` class): `names` held in all and `new_names_per_week`
//! accepted for the first time in any 7 days; over either, the share is rejected with reason
//! `over_quota`. The default tenant and the `personal` class have no figures. The durable side
//! (first accepted and last advertised times, the 90 day release, the 180 day quarantine) is
//! [`crate::NameState`], which this registry owns; the relay binary keeps it in
//! `relay/names.state` through [`LabelRegistry::set_on_change`].
//!
//! # Not here
//!
//! - Custom domains (a fully qualified name verified by its own `_menzil.<domain>` DNS TXT
//!   record) are phase 2; a `name` containing a dot is rejected as not yet supported.
//! - Terminated shares have no zone of their own yet (`<label>.t.H`, design 2.2): a share is a
//!   share whatever its mode, as before, until the share path (TBD 8) is built.
//! - The operator's static-label-pinning alternative protocol.md 4.4 describes for a personal
//!   relay is not built.
//! - Routing a ClientHello or a forwarded stream to whichever node holds a name (protocol.md 6.2,
//!   6.3): this only validates a claim and remembers who holds it.
//!
//! # Claims are session scoped
//!
//! Two different attached nodes must not both be serving the same full name at once, so this
//! also tracks which NodeId currently holds each accepted name, in memory: claims are not
//! durable across a reconnect (`crate::session` calls [`LabelRegistry::clear_for`] both right
//! after a fresh attach and on a genuine detach), a name is free for another node of its tenant
//! the moment its holder's session ends, and the durable record of the name (the quota, the
//! release clock) outlives the session.
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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use menzil_proto::{
    AdvertiseAckBody, AdvertiseBody, ErrorCode, NetworkId, NodeId, RejectedShare, Share,
};

use crate::names::{Claim, NameFigures, NameRefusal, NameState};
use crate::roster_store::RosterStore;
use crate::tenant::{TenantBook, TenantId};

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
/// the quota of 20 names per tenant, so no legitimate caller should ever hit it.
const MAX_SHARES_PER_ADVERTISE: usize = 64;

/// The longest a share `name` is ever echoed back in a [`RejectedShare`],
/// regardless of why it was rejected. A name long enough to fail the LDH
/// length check can still be most of a whole L3 record (tens of
/// kilobytes); echoing it back verbatim would risk the ACK itself
/// exceeding the transport's own size limit for a single oversized
/// share, the same failure mode [`MAX_SHARES_PER_ADVERTISE`] guards
/// against for *many* shares.
const MAX_ECHOED_NAME_BYTES: usize = 96;

/// The reason a name is rejected for a tenant that is at one of its figures.
const OVER_QUOTA: &str = "over_quota";
/// The reason a name is rejected while it is in quarantine for another network.
const QUARANTINED: &str = "quarantined";
/// The reason for a name that is reserved (protocol.md 4.4) or belongs to another tenant's
/// first level label (a slug, an operator grant).
const RESERVED: &str = "reserved name";

/// One node's currently accepted advertisement: exactly what its most
/// recent successful [`LabelRegistry::advertise`] call accepted, kept for
/// a future consumer (routing, TODO.md L3h's `accept_peers` check) —
/// nothing in this build reads `shares` yet.
struct NodeAdvertisement {
    shares: Vec<Share>,
    accept_peers: bool,
}

/// A held full name as the front door routes it ([`LabelRegistry::held_name`]).
#[derive(Debug, Clone)]
pub(crate) struct HeldName {
    /// The attached node that holds the name.
    pub(crate) node: NodeId,
    /// The slug of the tenant of the name's record; `None` is the default tenant.
    pub(crate) tenant: Option<String>,
    /// The network whose Roster granted the label when the name was last accepted.
    pub(crate) network: NetworkId,
    /// The holder's accepted share for the label.
    pub(crate) share: Share,
}

/// What the registry calls with the name state after every change that must reach the disk.
type OnChange = Arc<dyn Fn(&NameState) + Send + Sync>;

/// The label lock's content: who holds each full name now, and the durable state behind the
/// quotas and the release clock.
#[derive(Default)]
struct Inner {
    /// Which currently attached node holds each accepted full name.
    holders: HashMap<String, NodeId>,
    state: NameState,
    /// Networks the operator removed whose names a live session kept at the time
    /// ([`LabelRegistry::network_removed`]): [`LabelRegistry::sweep`] releases those names once
    /// the session is gone, although no Roster of the network is held.
    removed_networks: HashSet<NetworkId>,
    on_change: Option<OnChange>,
}

impl Inner {
    /// Tells the keeper if `changed`. Runs under the lock so that two changes reach it in the
    /// order they happened; the callback only queues a snapshot (no I/O).
    fn notify(&self, changed: bool) {
        if changed && let Some(on_change) = &self.on_change {
            on_change(&self.state);
        }
    }
}

/// Which currently-attached node, if any, actively holds each accepted
/// full name, plus each node's own currently accepted advertisement and the durable name state.
/// Keyed and compared case-insensitively (ASCII-lowercased on the way
/// in): labels are user-facing hostnames, and DNS treats `Foo`/`foo` as
/// the same name.
#[derive(Default)]
pub struct LabelRegistry {
    inner: Mutex<Inner>,
    by_node: RwLock<HashMap<NodeId, NodeAdvertisement>>,
    /// Called by [`Self::advertise`] once the lock free part is decided and before the label
    /// lock is taken (tests only).
    #[cfg(test)]
    decided_hook: std::sync::Mutex<Option<std::sync::Arc<dyn Fn() + Send + Sync>>>,
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

/// One full name a share could become, in one tenant's zone.
struct Candidate {
    /// Relative to the relay's share domain: `app` or `app.ali`.
    full: String,
    /// The tenant's slug; `None` is the default tenant.
    tenant: Option<String>,
    /// The network whose Roster grants the label.
    network: NetworkId,
    /// The tenant's name figures, if it has any.
    figures: Option<NameFigures>,
}

/// What the checks that need no lock decided about one share (see [`LabelRegistry::advertise`]).
enum Verdict<'a> {
    Rejected(RejectedShare),
    /// Passed every check but the ones that need the label lock; carries one entry per tenant
    /// zone the label could land in, in the order of the node's claims (an entry already refused
    /// carries its reason).
    Free(&'a Share, Vec<Result<Candidate, &'static str>>),
}

fn reject(name: &str, reason: impl Into<String>) -> RejectedShare {
    RejectedShare {
        name: truncate_for_echo(name),
        reason: reason.into(),
    }
}

/// The full names `label` (granted by `networks`) could be, one per tenant zone.
fn candidates(
    label: &str,
    networks: &[NetworkId],
    book: &TenantBook,
) -> Vec<Result<Candidate, &'static str>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut reserved = false;
    for network in networks {
        let tenant = book.tenant_of(network);
        let (full, slug) = match &tenant.id {
            TenantId::Default => {
                // Flat names exclude every slug, quarantined slug and operator grant (rule 4).
                if book.reserves_flat_name(label) {
                    if !std::mem::replace(&mut reserved, true) {
                        out.push(Err(RESERVED));
                    }
                    continue;
                }
                (label.to_string(), None)
            }
            TenantId::Named(slug) => {
                let full = if tenant.extra_names.iter().any(|name| name == label) {
                    label.to_string()
                } else {
                    format!("{label}.{slug}")
                };
                (full, Some(slug.to_string()))
            }
        };
        if !seen.insert(full.clone()) {
            continue;
        }
        out.push(Ok(Candidate {
            full,
            tenant: slug,
            network: *network,
            figures: book.figures_of(&tenant.id).map(|f| NameFigures {
                names: f.names,
                new_per_week: f.new_names_per_week,
            }),
        }));
    }
    out
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
    /// No claims active yet, no name state.
    pub fn new() -> Self {
        Self::default()
    }

    /// The label lock; a poisoned lock is still a usable registry (nothing under it can leave
    /// the maps half changed across a panic point).
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the durable name state with `state` (the relay binary loads the file at start).
    /// Only the relay's part is taken: a slug quarantine is the operator's, see
    /// [`NameState::relay_part`]. Nothing is reported to [`Self::set_on_change`].
    pub fn load_state(&self, state: &NameState) {
        self.lock().state = state.relay_part();
    }

    /// Sets what is called, with the whole name state, after every change that must reach the
    /// disk. It runs under the label lock, so it must only queue the snapshot, never do I/O.
    pub fn set_on_change(&self, on_change: impl Fn(&NameState) + Send + Sync + 'static) {
        self.lock().on_change = Some(Arc::new(on_change));
    }

    /// A copy of the durable name state now.
    pub fn state(&self) -> NameState {
        self.lock().state.clone()
    }

    /// Validates every entry of `body.shares` for `node_id` (an already
    /// attached, currently-registered session, having claimed
    /// `claimed_networks` in its own HELLO — verifying that is the
    /// caller's job, see `crate::session`) against `rosters`, `book`
    /// and [`DEFAULT_RESERVED_LABELS`], records the accepted set as this
    /// node's new active advertisement — replacing whatever it had
    /// before, in full, including dropping this node's own prior claims
    /// of any name not present in `body.shares` this time — and returns
    /// the ADVERTISE_ACK to send back. `now` is the Unix time in seconds, for the quotas and
    /// the release clock. `accept_peers` is always recorded
    /// as given, whether or not any share was accepted: protocol.md 4.2
    /// and 6.1 treat it as a property of the node itself, not of its
    /// shares, so a client-only node that advertises no shares at all
    /// must still be able to opt out of peer streams.
    ///
    /// A share is accepted if at least one of the full names it could be (one per tenant zone
    /// among the networks that grant the label) is; `names` in the ACK lists the full names.
    /// A share rejected in every zone carries the reason of the first.
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
        book: &TenantBook,
        claimed_networks: &[NetworkId],
        node_id: &NodeId,
        body: &AdvertiseBody,
        now: u64,
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
                names: vec![],
            };
        }

        // Everything that depends only on the request, the Rosters, the tenants and the fixed
        // rules is decided here, with no lock of this registry held (multi tenant threat A11,
        // isolation rule I6): one lookup of the node's grants (see `MAX_SHARES_PER_ADVERTISE`
        // for why not one Roster scan per share), then syntax, reserved names, grants,
        // duplicates and the tenant zones per share, in request order. What is left,
        // `Verdict::Free`, is a name that would be accepted but for another node holding it, a
        // quarantine or a quota; those are the things the label lock decides.
        let granted = rosters.labels_granted_by(claimed_networks, node_id);
        let mut seen = HashSet::new();
        let verdicts: Vec<Verdict<'_>> = body
            .shares
            .iter()
            .map(|share| {
                let key = share.name.to_ascii_lowercase();
                if let Some(reason) = syntax_problem(&share.name) {
                    return Verdict::Rejected(reject(&share.name, reason));
                }
                if DEFAULT_RESERVED_LABELS.contains(&key.as_str()) {
                    return Verdict::Rejected(reject(&share.name, "reserved name"));
                }
                let Some(granters) = granted.get(&key) else {
                    return Verdict::Rejected(reject(
                        &share.name,
                        ErrorCode::LabelUnclaimed.name(),
                    ));
                };
                if !seen.insert(key.clone()) {
                    return Verdict::Rejected(reject(
                        &share.name,
                        "duplicate name in this ADVERTISE",
                    ));
                }
                Verdict::Free(share, candidates(&key, granters, book))
            })
            .collect();
        #[cfg(test)]
        {
            let hook = self.decided_hook.lock().unwrap().clone();
            if let Some(hook) = hook {
                hook();
            }
        }

        let mut accepted = Vec::new();
        let mut accepted_shares = Vec::new();
        let mut rejected = Vec::new();
        let mut names = Vec::new();

        let mut guard = self.lock();
        let Inner { holders, state, .. } = &mut *guard;
        // The clock first: names unadvertised for 90 days are released, held ones stamped.
        let mut changed = state.sweep(now, |full| holders.contains_key(full));
        // Release this node's own previous claims first, so re-claiming
        // the same name in this new ADVERTISE never conflicts with
        // itself, and a name it drops this time is immediately free for
        // someone else to claim (it was advertised until now).
        let own: Vec<String> = holders
            .iter()
            .filter(|(_, owner)| **owner == *node_id)
            .map(|(full, _)| full.clone())
            .collect();
        for full in own {
            holders.remove(&full);
            changed |= state.touch(&full, now);
        }

        for verdict in verdicts {
            let (share, candidates) = match verdict {
                Verdict::Rejected(rejection) => {
                    rejected.push(rejection);
                    continue;
                }
                Verdict::Free(share, candidates) => (share, candidates),
            };
            let mut first_reason: Option<&'static str> = None;
            let mut any = false;
            for candidate in candidates {
                let candidate = match candidate {
                    Ok(candidate) => candidate,
                    Err(reason) => {
                        first_reason.get_or_insert(reason);
                        continue;
                    }
                };
                // Any entry still in `holders` at this key belongs to some other node of the
                // same tenant (the key names the zone): this node's own prior claims were
                // already stripped above, and an earlier share in this same request sharing
                // this label was already caught by the duplicate check.
                if holders.contains_key(&candidate.full) {
                    first_reason.get_or_insert(ErrorCode::LabelTaken.name());
                    continue;
                }
                let claim = Claim {
                    full: &candidate.full,
                    tenant: candidate.tenant.as_deref(),
                    network: candidate.network,
                };
                let (verdict, state_changed) = state.accept(&claim, candidate.figures, now);
                changed |= state_changed;
                match verdict {
                    Ok(()) => {
                        holders.insert(candidate.full.clone(), *node_id);
                        names.push(candidate.full);
                        any = true;
                    }
                    Err(refusal) => {
                        first_reason.get_or_insert(match refusal {
                            NameRefusal::OtherTenant => RESERVED,
                            NameRefusal::Quarantined => QUARANTINED,
                            NameRefusal::OverQuota => OVER_QUOTA,
                        });
                    }
                }
            }
            if any {
                accepted.push(share.name.clone());
                accepted_shares.push(share.clone());
            } else {
                rejected.push(reject(
                    &share.name,
                    first_reason.unwrap_or(ErrorCode::LabelUnclaimed.name()),
                ));
            }
        }
        guard.notify(changed);
        drop(guard);

        self.by_node.write().unwrap().insert(
            *node_id,
            NodeAdvertisement {
                shares: accepted_shares,
                accept_peers: body.accept_peers,
            },
        );

        AdvertiseAckBody {
            accepted,
            rejected,
            names,
        }
    }

    /// Sets the function [`Self::advertise`] calls between deciding and locking (tests only).
    #[cfg(test)]
    fn set_decided_hook(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.decided_hook.lock().unwrap() = Some(std::sync::Arc::new(hook));
    }

    /// The periodic pass (the relay binary runs it at each reload): names held by a session
    /// are stamped as advertised, names unadvertised for 90 days are released (a flat one into
    /// quarantine for 180 days), ended quarantines are dropped, and a name whose Roster no
    /// longer carries the label in any network of its tenant is released (protocol.md 4.4: "a
    /// name is released by an owner signed Roster that drops it"). A name whose granting
    /// network has no Roster held at the moment is left alone, and so is a name a session holds.
    pub fn sweep(&self, rosters: &RosterStore, book: &TenantBook, now: u64) {
        let index = rosters.label_index();
        let held_networks: HashSet<NetworkId> = rosters.networks().into_iter().collect();
        let mut guard = self.lock();
        let Inner {
            holders,
            state,
            removed_networks,
            ..
        } = &mut *guard;
        let mut changed = state.sweep(now, |full| holders.contains_key(full));
        removed_networks.retain(|network| !held_networks.contains(network));
        changed |= state.release_where(now, |full, record| {
            if holders.contains_key(full)
                || !(held_networks.contains(&record.network)
                    || removed_networks.contains(&record.network))
            {
                return false;
            }
            let label = full.split('.').next().unwrap_or(full);
            let listed = index.get(label).is_some_and(|networks| {
                networks
                    .iter()
                    .any(|network| book.id_of(network).slug() == record.tenant.as_deref())
            });
            !listed
        });
        guard.notify(changed);
    }

    /// Drops every holder entry whose grant is gone: the Roster now held for the network of the
    /// name's record no longer lists the label for the holder (dropped, given to another node,
    /// the node revoked or unlisted, or no Roster of the network held at all). The relay runs it
    /// on every Roster change ([`crate::Relay`] watches [`RosterStore::subscribe`]), so that a
    /// label the owner moved stops routing public traffic to the old holder and the new
    /// grantee's claim is no longer refused `label_taken` (expose round 2, M1). Like
    /// [`Self::clear_for`] the name is stamped as advertised at `now`: its release clock starts
    /// when its holder loses it. The holder's session is not touched, and nothing here makes it
    /// claim again: it does so with its next ADVERTISE, which the Roster decides afresh.
    /// Returns how many entries were dropped.
    pub fn release_ungranted(&self, rosters: &RosterStore, now: u64) -> usize {
        let mut guard = self.lock();
        let Inner { holders, state, .. } = &mut *guard;
        let mut changed = false;
        let before = holders.len();
        holders.retain(|full, node| {
            let granted = state.names.get(full).is_some_and(|record| {
                let label = full.split('.').next().unwrap_or(full);
                rosters.label_granted(&record.network, node, label)
            });
            if !granted {
                changed |= state.touch(full, now);
            }
            granted
        });
        let dropped = before - holders.len();
        guard.notify(changed);
        dropped
    }

    /// The relay no longer serves `network` (the operator removed it; the caller has removed it
    /// from `rosters` already): every name its Roster granted is released at `now`; a flat one
    /// is quarantined for 180 days, bound to the network, a name in a tenant's zone is simply
    /// gone (a removed tenant's slug is quarantined by the command that removes it).
    ///
    /// A name another network of the same tenant still grants is not released but moves to that
    /// network, and a name a session holds now is left alone, as [`Self::sweep`] leaves them
    /// (round T5, L4); the sweep releases it after the session has gone. `book` is the tenant book the networks are attributed with.
    pub fn network_removed(
        &self,
        rosters: &RosterStore,
        book: &TenantBook,
        network: &NetworkId,
        now: u64,
    ) {
        let index = rosters.label_index();
        let mut guard = self.lock();
        let Inner {
            holders,
            state,
            removed_networks,
            ..
        } = &mut *guard;
        let mut changed = false;
        let mut rebind: Vec<(String, NetworkId)> = Vec::new();
        for (full, record) in &state.names {
            if record.network != *network {
                continue;
            }
            let label = full.split('.').next().unwrap_or(full);
            let other = index.get(label).and_then(|networks| {
                networks.iter().find(|candidate| {
                    *candidate != network
                        && book.id_of(candidate).slug() == record.tenant.as_deref()
                })
            });
            if let Some(other) = other {
                rebind.push((full.clone(), *other));
            }
        }
        for (full, other) in rebind {
            if let Some(record) = state.names.get_mut(&full) {
                record.network = other;
                changed = true;
            }
        }
        let mut kept = false;
        changed |= state.release_where(now, |full, record| {
            let release = record.network == *network && !holders.contains_key(full);
            kept |= record.network == *network && !release;
            release
        });
        if kept {
            // The sweep releases those once their sessions have ended.
            removed_networks.insert(*network);
        }
        guard.notify(changed);
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
    ///
    /// The names it held are stamped as advertised at `now`: the 90 day release clock of a name
    /// starts when its holder leaves, not when it last sent ADVERTISE.
    pub fn clear_for(&self, node_id: &NodeId, now: u64) {
        let mut guard = self.lock();
        let Inner { holders, state, .. } = &mut *guard;
        let mut changed = false;
        holders.retain(|full, owner| {
            if *owner != *node_id {
                return true;
            }
            changed |= state.touch(full, now);
            false
        });
        guard.notify(changed);
        drop(guard);
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

    /// Who holds the full name `full` (relative to the share domain, lowercase: `app` or
    /// `app.ali`) right now, for the front door (`crate::front_door`): the attached node whose
    /// ADVERTISE this session got the name accepted, the tenant slug and network of the name's
    /// record, and the share of that node whose label the name carries. `None` if nobody holds
    /// it, if it is not a held name of the durable state, if its first level label is in
    /// quarantine at `now`, or if the holder's current advertisement no longer lists the share.
    /// The three answers (unknown, unheld, quarantined) are one on purpose: the front door
    /// answers them all the same way.
    pub(crate) fn held_name(&self, full: &str, now: u64) -> Option<HeldName> {
        let (node, record) = {
            let guard = self.lock();
            let node = *guard.holders.get(full)?;
            let record = guard.state.names.get(full)?.clone();
            let first_level = full.rsplit('.').next().unwrap_or(full);
            if guard
                .state
                .quarantine
                .get(first_level)
                .is_some_and(|q| q.until() > now)
            {
                return None;
            }
            (node, record)
        };
        let label = full.split('.').next().unwrap_or(full);
        let share = self
            .by_node
            .read()
            .unwrap()
            .get(&node)?
            .shares
            .iter()
            .find(|share| share.name.eq_ignore_ascii_case(label))?
            .clone();
        Some(HeldName {
            node,
            tenant: record.tenant,
            network: record.network,
            share,
        })
    }

    /// Every full name held now, as [`LabelRegistry::held_name`] would answer it at `now` (the
    /// relay's ACME looks for the terminated ones).
    pub(crate) fn held_names(&self, now: u64) -> Vec<(String, HeldName)> {
        let fulls: Vec<String> = self.lock().holders.keys().cloned().collect();
        fulls
            .into_iter()
            .filter_map(|full| self.held_name(&full, now).map(|held| (full, held)))
            .collect()
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

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 24 * 60 * 60;

    /// ADVERTISE on a relay without tenants (the default tenant only), at [`NOW`].
    fn adv(
        registry: &LabelRegistry,
        rosters: &RosterStore,
        networks: &[NetworkId],
        node_id: &NodeId,
        body: &AdvertiseBody,
    ) -> AdvertiseAckBody {
        registry.advertise(
            rosters,
            &TenantBook::default(),
            networks,
            node_id,
            body,
            NOW,
        )
    }

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
        let ack = adv(
            &registry,
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
        let ack = adv(
            &registry,
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
        let ack = adv(
            &registry,
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
        let ack = adv(
            &registry,
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
        let ack = adv(
            &registry,
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
        let ack = adv(
            &registry,
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
        let ack = adv(
            &registry,
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
        adv(&registry, &f.rosters, &[f.network_id], &f.node_id, &body);

        let shares = registry.shares_for(&f.node_id);
        assert_eq!(shares.len(), 1);
        assert_eq!(shares[0].mode, ShareMode::Blind);
    }

    #[test]
    fn too_many_shares_in_one_advertise_is_refused_as_a_whole() {
        let f = fixture_with_labels(vec!["example"]);
        let registry = LabelRegistry::new();
        adv(
            &registry,
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );

        let names: Vec<String> = (0..=MAX_SHARES_PER_ADVERTISE)
            .map(|i| format!("name{i}"))
            .collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let ack = adv(
            &registry,
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
        let ack = adv(
            &registry,
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
        let holder_ack = adv(
            &registry,
            &rosters,
            &[network_id],
            &holder,
            &advertise_body(&["example"], true),
        );
        assert_eq!(holder_ack.accepted, vec!["example"]);

        let challenger_ack = adv(
            &registry,
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
        adv(
            &registry,
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["one", "two"], true),
        );
        let ack = adv(
            &registry,
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
        let other_ack = adv(
            &registry,
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
        adv(
            &registry,
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], true),
        );
        registry.clear_for(&f.node_id, NOW);

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
        let ack = adv(
            &registry,
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
        adv(
            &registry,
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example"], false),
        );
        assert!(!registry.accepts_peers(&f.node_id));

        adv(
            &registry,
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

        adv(
            &registry,
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
        adv(
            &registry,
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
        adv(
            &registry,
            &rosters,
            &[],
            &node_id,
            &advertise_body(&[], false),
        );
        assert!(!registry.accepts_peers(&node_id));
    }

    /// MT5, isolation rule I6: the checks that need no label lock are decided before it is
    /// taken, so a request full of names to reject (or a slow Roster lookup) never holds up
    /// another node's claim. The hook runs between deciding and locking: neither label lock
    /// may be held there.
    #[test]
    fn the_label_lock_is_not_held_while_a_request_is_judged() {
        let f = fixture_with_labels(vec!["example", "other"]);
        let registry = std::sync::Arc::new(LabelRegistry::new());
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let registry = std::sync::Arc::clone(&registry);
            let calls = std::sync::Arc::clone(&calls);
            let probe = std::sync::Arc::clone(&registry);
            probe.set_decided_hook(move || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert!(
                    registry.inner.try_lock().is_ok(),
                    "the label lock was already held while the request was judged"
                );
            });
        }
        let ack = adv(
            &registry,
            &f.rosters,
            &[f.network_id],
            &f.node_id,
            &advertise_body(&["example", "www", "nope", "other"], true),
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(ack.accepted, vec!["example", "other"]);
        let reasons: Vec<&str> = ack.rejected.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            reasons,
            ["www", "nope"],
            "rejections keep the request order"
        );
    }

    // ---- MT9: names per tenant (multi tenant design 2.2 and 2.3) ----

    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;

    use crate::names::{NameState, QuarantineKind, RELEASE_DAYS};
    use crate::tenant::{Class, Slug, TenantSpec};

    /// A network with an owner key whose Roster the tests replace by raising `seq`.
    struct Net {
        owner: SigningKey,
        id: NetworkId,
        seq: u64,
    }

    impl Net {
        fn new() -> Self {
            let owner = SigningKey::generate(&mut rand::rng());
            let id = NetworkId::from(owner.verifying_key().to_bytes());
            Self { owner, id, seq: 0 }
        }

        /// Publishes the next Roster of this network: `members` are listed, `labels` granted.
        fn publish(
            &mut self,
            rosters: &RosterStore,
            members: &[NodeId],
            labels: &[(&str, NodeId)],
        ) {
            self.seq += 1;
            let body = RosterBody {
                v: menzil_proto::PROTOCOL_VERSION,
                network_id: self.id,
                seq: self.seq,
                issued: 0,
                expires: 4_000_000_000,
                members: members
                    .iter()
                    .map(|&node_id| RosterMember {
                        node_id,
                        min_serial: 1,
                    })
                    .collect(),
                revoked: vec![],
                stewards: vec![],
                labels: labels
                    .iter()
                    .map(|&(name, node_id)| Label {
                        name: name.to_string(),
                        node_id,
                    })
                    .collect(),
            };
            assert!(
                rosters
                    .set(&Roster::sign(&self.owner, &body).unwrap())
                    .unwrap()
            );
        }
    }

    fn node(n: u8) -> NodeId {
        NodeId::from([n; 32])
    }

    /// One tenant for [`book`]: slug, networks, figure overrides, `extra_names`.
    type TenantArgs<'a> = (&'a str, Vec<NetworkId>, &'a [(&'a str, u64)], &'a [&'a str]);

    fn book(tenants: Vec<TenantArgs<'_>>) -> TenantBook {
        let specs = tenants
            .into_iter()
            .enumerate()
            .map(|(i, (slug, networks, figures, extra))| TenantSpec {
                slug: Slug::parse(slug).unwrap(),
                networks,
                class: Class::Friend,
                overrides: figures
                    .iter()
                    .map(|&(key, value)| (key.to_string(), value))
                    .collect::<BTreeMap<_, _>>(),
                terminated: false,
                extra_names: extra.iter().map(|n| n.to_string()).collect(),
                added: 1 + i as u64,
            })
            .collect();
        let book = TenantBook::build(specs, vec![], &Default::default(), &Default::default());
        assert!(book.refused().is_empty(), "{:?}", book.refused());
        book
    }

    fn at(
        registry: &LabelRegistry,
        rosters: &RosterStore,
        book: &TenantBook,
        networks: &[NetworkId],
        node_id: &NodeId,
        names: &[&str],
        now: u64,
    ) -> AdvertiseAckBody {
        registry.advertise(
            rosters,
            book,
            networks,
            node_id,
            &advertise_body(names, true),
            now,
        )
    }

    fn reasons(ack: &AdvertiseAckBody) -> Vec<(String, String)> {
        ack.rejected
            .iter()
            .map(|r| (r.name.clone(), r.reason.clone()))
            .collect()
    }

    /// The default tenant keeps flat names and the ACK says so; a tenant's label lands in its
    /// own zone, and a label the operator granted it is the flat name (rule 2, 10).
    #[test]
    fn the_full_name_is_the_label_in_the_zone_of_the_granting_tenant() {
        let rosters = RosterStore::new();
        let (mut flat, mut ali, mut bob) = (Net::new(), Net::new(), Net::new());
        let (n_flat, n_ali, n_bob) = (node(1), node(2), node(3));
        flat.publish(&rosters, &[n_flat], &[("app", n_flat)]);
        ali.publish(&rosters, &[n_ali], &[("app", n_ali)]);
        bob.publish(&rosters, &[n_bob], &[("blog", n_bob), ("app", n_bob)]);
        let book = book(vec![
            ("ali", vec![ali.id], &[], &[]),
            ("bob", vec![bob.id], &[], &["blog"]),
        ]);
        let registry = LabelRegistry::new();
        let a = at(
            &registry,
            &rosters,
            &book,
            &[flat.id],
            &n_flat,
            &["app"],
            NOW,
        );
        assert_eq!(
            (a.accepted, a.names),
            (vec!["app".to_string()], vec!["app".to_string()])
        );
        let a = at(&registry, &rosters, &book, &[ali.id], &n_ali, &["App"], NOW);
        assert_eq!(a.accepted, vec!["App"]);
        assert_eq!(a.names, vec!["app.ali"]);
        let a = at(
            &registry,
            &rosters,
            &book,
            &[bob.id],
            &n_bob,
            &["app", "blog"],
            NOW,
        );
        assert_eq!(
            a.names,
            vec!["app.bob", "blog"],
            "an operator grant is the flat name"
        );
        assert!(a.rejected.is_empty());
    }

    /// Rules 3 and 5, threats A5 and A6: tenant `beta` can never get a name in `alpha`'s zone, and
    /// what `beta`'s node is told does not move with anything `alpha` holds, owes or has
    /// quarantined.
    #[test]
    fn a_tenant_never_gets_a_name_in_another_zone_and_its_answer_does_not_depend_on_it() {
        // The same request from beta's node in two worlds that differ only in alpha's state.
        let ask = |alpha_busy: bool| {
            let rosters = RosterStore::new();
            let (mut alpha, mut beta) = (Net::new(), Net::new());
            let (a1, a2, b1) = (node(1), node(2), node(3));
            alpha.publish(
                &rosters,
                &[a1, a2],
                &[("app", a1), ("app", a2), ("one", a1), ("two", a1)],
            );
            beta.publish(&rosters, &[b1], &[("app", b1)]);
            // The same short figures for both tenants.
            let figures: &[(&str, u64)] = &[("names", 3), ("new_names_per_week", 3)];
            let book = book(vec![
                ("alpha", vec![alpha.id], figures, &[]),
                ("beta", vec![beta.id], figures, &[]),
            ]);
            let registry = LabelRegistry::new();
            if alpha_busy {
                // alpha holds `app` with a1, is at its figure (3 names) and has a name
                // released; a2 asks for the same label.
                assert_eq!(
                    at(
                        &registry,
                        &rosters,
                        &book,
                        &[alpha.id],
                        &a1,
                        &["app", "one", "two"],
                        NOW
                    )
                    .names
                    .len(),
                    3
                );
                let taken = at(&registry, &rosters, &book, &[alpha.id], &a2, &["app"], NOW);
                assert_eq!(
                    reasons(&taken),
                    [("app".to_string(), "label_taken".to_string())]
                );
            }
            let ack = at(
                &registry,
                &rosters,
                &book,
                &[beta.id],
                &b1,
                &["app", "nope"],
                NOW + 5,
            );
            // Its own grant of `app` is only ever in its own zone.
            assert!(
                ack.names.iter().all(|n| !n.ends_with(".alpha")),
                "{:?}",
                ack.names
            );
            ack
        };
        let quiet = ask(false);
        let busy = ask(true);
        assert_eq!(quiet.names, vec!["app.beta"]);
        assert_eq!(
            quiet, busy,
            "beta's answer does not depend on alpha's state"
        );
    }

    /// A node that is a member of two tenants' networks gets only the zones whose owners granted
    /// the label; a label granted by one owner never lands in the other's zone (rule 3), and one
    /// granted by both lands in both (rule 6).
    #[test]
    fn a_label_is_given_only_in_the_zones_whose_owners_granted_it() {
        let rosters = RosterStore::new();
        let (mut alpha, mut beta) = (Net::new(), Net::new());
        let n = node(1);
        alpha.publish(&rosters, &[n], &[("only-a", n), ("both", n)]);
        beta.publish(&rosters, &[n], &[("both", n)]);
        let book = book(vec![
            ("alpha", vec![alpha.id], &[], &[]),
            ("beta", vec![beta.id], &[], &[]),
        ]);
        let registry = LabelRegistry::new();
        let ack = at(
            &registry,
            &rosters,
            &book,
            &[alpha.id, beta.id],
            &n,
            &["only-a", "both", "none"],
            NOW,
        );
        assert_eq!(ack.names, vec!["only-a.alpha", "both.alpha", "both.beta"]);
        assert_eq!(ack.accepted, vec!["only-a", "both"]);
        assert_eq!(
            reasons(&ack),
            [("none".to_string(), "label_unclaimed".to_string())]
        );
    }

    /// Rule 5: two nodes of one tenant that are granted one label: the first attached holds it,
    /// the second gets `label_taken`; another tenant's node with the same label is unaffected.
    #[test]
    fn label_taken_exists_only_inside_one_tenant() {
        let rosters = RosterStore::new();
        let (mut alpha, mut beta) = (Net::new(), Net::new());
        let (a1, a2, b1) = (node(1), node(2), node(3));
        alpha.publish(&rosters, &[a1, a2], &[("app", a1), ("app", a2)]);
        beta.publish(&rosters, &[b1], &[("app", b1)]);
        let book = book(vec![
            ("alpha", vec![alpha.id], &[], &[]),
            ("beta", vec![beta.id], &[], &[]),
        ]);
        let registry = LabelRegistry::new();
        assert_eq!(
            at(&registry, &rosters, &book, &[alpha.id], &a1, &["app"], NOW).names,
            ["app.alpha"]
        );
        let second = at(&registry, &rosters, &book, &[alpha.id], &a2, &["app"], NOW);
        assert!(second.names.is_empty());
        assert_eq!(
            reasons(&second),
            [("app".to_string(), "label_taken".to_string())]
        );
        assert_eq!(
            at(&registry, &rosters, &book, &[beta.id], &b1, &["app"], NOW).names,
            ["app.beta"]
        );
    }

    /// The default tenant's flat names exclude every slug, quarantined slug and operator grant,
    /// and a grant is the granted tenant's only (rule 4 and 10).
    #[test]
    fn flat_names_exclude_every_slug_and_grant() {
        let rosters = RosterStore::new();
        let (mut flat, mut ali) = (Net::new(), Net::new());
        let (f, a) = (node(1), node(2));
        flat.publish(
            &rosters,
            &[f],
            &[("alice", f), ("blog", f), ("gone", f), ("free", f)],
        );
        ali.publish(&rosters, &[a], &[("blog", a)]);
        // A slug in quarantine, as the operator's command leaves it.
        let quarantined: std::collections::HashSet<String> = ["gone".to_string()].into();
        let named = TenantBook::build(
            vec![TenantSpec {
                slug: Slug::parse("alice").unwrap(),
                networks: vec![ali.id],
                class: Class::Friend,
                overrides: BTreeMap::new(),
                terminated: false,
                extra_names: vec!["blog".to_string()],
                added: 1,
            }],
            vec![],
            &Default::default(),
            &quarantined,
        );
        let registry = LabelRegistry::new();
        let ack = at(
            &registry,
            &rosters,
            &named,
            &[flat.id],
            &f,
            &["alice", "blog", "gone", "free"],
            NOW,
        );
        assert_eq!(ack.names, vec!["free"]);
        assert_eq!(
            reasons(&ack),
            [
                ("alice".to_string(), "reserved name".to_string()),
                ("blog".to_string(), "reserved name".to_string()),
                ("gone".to_string(), "reserved name".to_string()),
            ]
        );
        // The tenant holds its grant.
        assert_eq!(
            at(&registry, &rosters, &named, &[ali.id], &a, &["blog"], NOW).names,
            ["blog"]
        );
    }

    /// Rule 7: 5 names accepted for the first time in any 7 days, then `over_quota`; a name
    /// already held is never refused; the window moves on after 7 days.
    #[test]
    fn at_most_five_new_names_in_seven_days_per_tenant() {
        let rosters = RosterStore::new();
        let mut alpha = Net::new();
        let n = node(1);
        let labels: Vec<String> = (0..8).map(|i| format!("l{i}")).collect();
        let grants: Vec<(&str, NodeId)> = labels.iter().map(|l| (l.as_str(), n)).collect();
        alpha.publish(&rosters, &[n], &grants);
        let book = book(vec![("alpha", vec![alpha.id], &[], &[])]);
        let registry = LabelRegistry::new();
        let all: Vec<&str> = labels.iter().map(String::as_str).collect();
        let first = at(&registry, &rosters, &book, &[alpha.id], &n, &all[..6], NOW);
        assert_eq!(first.names.len(), 5, "{first:?}");
        assert_eq!(
            reasons(&first),
            [("l5".to_string(), "over_quota".to_string())]
        );
        // The same request later in the week: the five are held, the sixth still waits.
        let again = at(
            &registry,
            &rosters,
            &book,
            &[alpha.id],
            &n,
            &all[..6],
            NOW + 7 * DAY - 1,
        );
        assert_eq!(again.names.len(), 5);
        assert_eq!(reasons(&again).len(), 1);
        // 7 days after the first five, the sixth goes in.
        let later = at(
            &registry,
            &rosters,
            &book,
            &[alpha.id],
            &n,
            &all[..6],
            NOW + 7 * DAY,
        );
        assert_eq!(later.names.len(), 6, "{later:?}");
        assert!(later.rejected.is_empty());
    }

    /// Rule 7: 20 names in all (the friend default), counting an operator grant.
    #[test]
    fn at_most_twenty_names_per_tenant_and_a_grant_counts() {
        let rosters = RosterStore::new();
        let mut alpha = Net::new();
        let n = node(1);
        let labels: Vec<String> = (0..21).map(|i| format!("l{i}")).collect();
        let grants: Vec<(&str, NodeId)> = labels.iter().map(|l| (l.as_str(), n)).collect();
        alpha.publish(&rosters, &[n], &grants);
        // l0 is a flat grant. The weekly figure is raised so that only the 20 binds.
        let figures: &[(&str, u64)] = &[("new_names_per_week", 100)];
        let book = book(vec![("alpha", vec![alpha.id], figures, &["l0"])]);
        let registry = LabelRegistry::new();
        let all: Vec<&str> = labels.iter().map(String::as_str).collect();
        let ack = at(&registry, &rosters, &book, &[alpha.id], &n, &all, NOW);
        assert_eq!(ack.names.len(), 20, "{ack:?}");
        assert_eq!(ack.names[0], "l0", "the grant is a flat name and counted");
        assert_eq!(
            reasons(&ack),
            [("l20".to_string(), "over_quota".to_string())]
        );
        // Another tenant is not touched by it.
        let mut beta = Net::new();
        let m = node(2);
        beta.publish(&rosters, &[m], &[("l0", m)]);
        let two = TenantBook::build(
            vec![
                TenantSpec {
                    slug: Slug::parse("alpha").unwrap(),
                    networks: vec![alpha.id],
                    class: Class::Friend,
                    overrides: figures.iter().map(|&(k, v)| (k.to_string(), v)).collect(),
                    terminated: false,
                    extra_names: vec!["l0".to_string()],
                    added: 1,
                },
                TenantSpec {
                    slug: Slug::parse("beta").unwrap(),
                    networks: vec![beta.id],
                    class: Class::Friend,
                    overrides: BTreeMap::new(),
                    terminated: false,
                    extra_names: vec![],
                    added: 2,
                },
            ],
            vec![],
            &Default::default(),
            &Default::default(),
        );
        assert_eq!(
            at(&registry, &rosters, &two, &[beta.id], &m, &["l0"], NOW).names,
            ["l0.beta"]
        );
    }

    /// The default tenant has no figures: today's relay.
    #[test]
    fn the_default_tenant_has_no_name_quota() {
        let rosters = RosterStore::new();
        let mut flat = Net::new();
        let n = node(1);
        let labels: Vec<String> = (0..30).map(|i| format!("l{i}")).collect();
        let grants: Vec<(&str, NodeId)> = labels.iter().map(|l| (l.as_str(), n)).collect();
        flat.publish(&rosters, &[n], &grants);
        let registry = LabelRegistry::new();
        let all: Vec<&str> = labels.iter().map(String::as_str).collect();
        // 30 names in one go; the per ADVERTISE bound is 64.
        let ack = at(
            &registry,
            &rosters,
            &TenantBook::default(),
            &[flat.id],
            &n,
            &all,
            NOW,
        );
        assert_eq!(ack.names.len(), 30);
        assert!(ack.rejected.is_empty());
    }

    /// Rule 8 and 9: a name not advertised for 90 days is released; a flat one is quarantined
    /// for 180 days and goes back only to the network that held it; a tenant's zone name is free
    /// again at once.
    #[test]
    fn a_released_flat_name_is_quarantined_and_a_zone_name_is_free_again() {
        let rosters = RosterStore::new();
        let (mut flat, mut other, mut ali) = (Net::new(), Net::new(), Net::new());
        let (f, o, a) = (node(1), node(2), node(3));
        flat.publish(&rosters, &[f], &[("app", f)]);
        other.publish(&rosters, &[o], &[("app", o)]);
        ali.publish(&rosters, &[a], &[("app", a)]);
        let book = book(vec![("ali", vec![ali.id], &[], &[])]);
        let registry = LabelRegistry::new();
        assert_eq!(
            at(&registry, &rosters, &book, &[flat.id], &f, &["app"], NOW).names,
            ["app"]
        );
        assert_eq!(
            at(&registry, &rosters, &book, &[ali.id], &a, &["app"], NOW).names,
            ["app.ali"]
        );
        registry.clear_for(&f, NOW);
        registry.clear_for(&a, NOW);

        // 89 days later nothing is released; at 90 days the pass releases both.
        registry.sweep(&rosters, &book, NOW + RELEASE_DAYS * DAY - 1);
        assert_eq!(registry.state().names.len(), 2);
        let t90 = NOW + RELEASE_DAYS * DAY;
        registry.sweep(&rosters, &book, t90);
        let state = registry.state();
        assert!(state.names.is_empty(), "{state:?}");
        assert_eq!(state.quarantine["app"].kind, QuarantineKind::Flat);
        assert!(!state.quarantine.contains_key("app.ali"));

        // A different network cannot take the flat name for 180 days; the one that held it can.
        let theirs = at(
            &registry,
            &rosters,
            &book,
            &[other.id],
            &o,
            &["app"],
            t90 + 1,
        );
        assert_eq!(
            reasons(&theirs),
            [("app".to_string(), "quarantined".to_string())]
        );
        // The zone name was free at once.
        assert_eq!(
            at(&registry, &rosters, &book, &[ali.id], &a, &["app"], t90 + 1).names,
            ["app.ali"]
        );
        registry.clear_for(&a, t90 + 1);
        let after = t90 + 180 * DAY;
        assert_eq!(
            at(&registry, &rosters, &book, &[other.id], &o, &["app"], after).names,
            ["app"]
        );
    }

    /// The 90 day clock starts when the holder leaves, and a name a session holds is never
    /// released however long it is held.
    #[test]
    fn a_held_name_is_not_released_and_the_clock_starts_when_the_holder_leaves() {
        let rosters = RosterStore::new();
        let mut flat = Net::new();
        let f = node(1);
        flat.publish(&rosters, &[f], &[("app", f)]);
        let book = TenantBook::default();
        let registry = LabelRegistry::new();
        at(&registry, &rosters, &book, &[flat.id], &f, &["app"], NOW);
        let long = NOW + 200 * DAY;
        registry.sweep(&rosters, &book, long);
        assert_eq!(
            registry.state().names["app"].last,
            long,
            "stamped while held"
        );
        registry.clear_for(&f, long + 10 * DAY);
        registry.sweep(&rosters, &book, long + 10 * DAY + RELEASE_DAYS * DAY - 1);
        assert!(registry.state().names.contains_key("app"));
        registry.sweep(&rosters, &book, long + 10 * DAY + RELEASE_DAYS * DAY);
        assert!(registry.state().names.is_empty());
    }

    /// protocol.md 4.4: an owner signed Roster that drops the label releases the name (not while
    /// a session holds it, and not while the Roster of its network is not held).
    #[test]
    fn a_roster_that_drops_a_label_releases_its_name() {
        let rosters = RosterStore::new();
        let mut ali = Net::new();
        let n = node(1);
        ali.publish(&rosters, &[n], &[("app", n), ("keep", n)]);
        let book = book(vec![("ali", vec![ali.id], &[], &[])]);
        let registry = LabelRegistry::new();
        at(
            &registry,
            &rosters,
            &book,
            &[ali.id],
            &n,
            &["app", "keep"],
            NOW,
        );
        ali.publish(&rosters, &[n], &[("keep", n)]);
        registry.sweep(&rosters, &book, NOW + 60);
        assert_eq!(
            registry.state().names.len(),
            2,
            "held by a session: left alone"
        );
        registry.clear_for(&n, NOW + 61);
        registry.sweep(&rosters, &book, NOW + 62);
        let names: Vec<String> = registry.state().names.keys().cloned().collect();
        assert_eq!(names, ["keep.ali"]);
    }

    /// An operator removing a network releases its names: a flat one is quarantined for the
    /// network that held it.
    #[test]
    fn a_removed_network_releases_its_names() {
        let rosters = RosterStore::new();
        let (mut flat, mut ali) = (Net::new(), Net::new());
        let (f, a) = (node(1), node(2));
        flat.publish(&rosters, &[f], &[("app", f)]);
        ali.publish(&rosters, &[a], &[("app", a)]);
        let book = book(vec![("ali", vec![ali.id], &[], &[])]);
        let registry = LabelRegistry::new();
        at(&registry, &rosters, &book, &[flat.id], &f, &["app"], NOW);
        at(&registry, &rosters, &book, &[ali.id], &a, &["app"], NOW);
        // The removal ends the sessions that claimed the networks; their names are free then.
        registry.clear_for(&f, NOW);
        registry.clear_for(&a, NOW);
        registry.network_removed(&rosters, &book, &flat.id, NOW + 1);
        registry.network_removed(&rosters, &book, &ali.id, NOW + 1);
        let state = registry.state();
        assert!(state.names.is_empty());
        assert_eq!(state.quarantine["app"].network, Some(flat.id));
        assert_eq!(state.quarantine.len(), 1);
    }

    /// The state reaches the keeper when it changes, in order, and not for a re-advertise that
    /// changes nothing.
    #[test]
    fn the_keeper_is_told_of_changes_and_only_of_changes() {
        let rosters = RosterStore::new();
        let mut flat = Net::new();
        let f = node(1);
        flat.publish(&rosters, &[f], &[("app", f)]);
        let seen: std::sync::Arc<StdMutex<Vec<NameState>>> = Default::default();
        let registry = LabelRegistry::new();
        {
            let seen = std::sync::Arc::clone(&seen);
            registry.set_on_change(move |state| seen.lock().unwrap().push(state.clone()));
        }
        let book = TenantBook::default();
        at(&registry, &rosters, &book, &[flat.id], &f, &["app"], NOW);
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(seen.lock().unwrap()[0].names.contains_key("app"));
        // An hour later, the same ADVERTISE: nothing new to keep.
        at(
            &registry,
            &rosters,
            &book,
            &[flat.id],
            &f,
            &["app"],
            NOW + 3600,
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
        // A day later the stamp moves.
        at(
            &registry,
            &rosters,
            &book,
            &[flat.id],
            &f,
            &["app"],
            NOW + DAY,
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert_eq!(seen.lock().unwrap()[1].names["app"].last, NOW + DAY);
    }

    /// A state loaded at start is what the registry judges with: a quarantine from before the
    /// restart still holds, a loaded record still counts against the quota.
    #[test]
    fn a_loaded_state_is_judged_like_one_built_in_this_run() {
        let rosters = RosterStore::new();
        let (mut flat, mut other) = (Net::new(), Net::new());
        let (f, o) = (node(1), node(2));
        flat.publish(&rosters, &[f], &[("app", f)]);
        other.publish(&rosters, &[o], &[("app", o)]);
        let book = TenantBook::default();
        let first = LabelRegistry::new();
        at(&first, &rosters, &book, &[flat.id], &f, &["app"], NOW);
        first.clear_for(&f, NOW);
        first.sweep(&rosters, &book, NOW + RELEASE_DAYS * DAY);
        let text = first.state().render();

        let restarted = LabelRegistry::new();
        restarted.load_state(&NameState::parse(&text).unwrap());
        let later = NOW + RELEASE_DAYS * DAY + 10 * DAY;
        let theirs = at(
            &restarted,
            &rosters,
            &book,
            &[other.id],
            &o,
            &["app"],
            later,
        );
        assert_eq!(
            reasons(&theirs),
            [("app".to_string(), "quarantined".to_string())]
        );
        assert_eq!(
            at(&restarted, &rosters, &book, &[flat.id], &f, &["app"], later).names,
            ["app"]
        );
    }

    // ---- round T5 ----

    /// Round T5, M2 (the reviewer's probe, asserting the fixed behaviour): dropping names from
    /// the Roster so that the sweep releases them, and claiming new ones, does not get round
    /// the 5 new names in 7 days.
    #[test]
    fn t5_weekly_figure_holds_across_a_release_cycle() {
        let rosters = RosterStore::new();
        let mut ali = Net::new();
        let n = node(2);
        let book = book(vec![("ali", vec![ali.id], &[], &[])]);
        let registry = LabelRegistry::new();
        let mut total_new = 0;
        let mut last_reasons = Vec::new();
        for round in 0..6u64 {
            let labels: Vec<String> = (0..5).map(|i| format!("r{round}x{i}")).collect();
            let pairs: Vec<(&str, NodeId)> = labels.iter().map(|l| (l.as_str(), n)).collect();
            ali.publish(&rosters, &[n], &pairs);
            let now = NOW + round * 20;
            registry.clear_for(&n, now);
            registry.sweep(&rosters, &book, now);
            let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
            let ack = at(&registry, &rosters, &book, &[ali.id], &n, &refs, now);
            total_new += ack.names.len();
            last_reasons = reasons(&ack);
        }
        assert_eq!(
            total_new, 5,
            "five new names in the week, whatever was released"
        );
        assert!(last_reasons.iter().all(|(_, why)| why == "over_quota"));
        // A week after the first acceptances the figure lets go again.
        ali.publish(&rosters, &[n], &[("later", n)]);
        registry.clear_for(&n, NOW + 8 * DAY);
        registry.sweep(&rosters, &book, NOW + 8 * DAY);
        let ack = at(
            &registry,
            &rosters,
            &book,
            &[ali.id],
            &n,
            &["later"],
            NOW + 8 * DAY,
        );
        assert_eq!(ack.names, ["later.ali"]);
    }

    /// Round T5, L4: a removed network's name that another network of the tenant still grants
    /// moves to that network and is neither released nor quarantined; the live holder keeps it.
    #[test]
    fn t5_network_removed_keeps_a_name_another_network_still_grants() {
        let rosters = RosterStore::new();
        let (mut d1, mut d2) = (Net::new(), Net::new());
        let n = node(4);
        d1.publish(&rosters, &[n], &[("app", n)]);
        d2.publish(&rosters, &[n], &[("app", n)]);
        let book = TenantBook::default();
        let registry = LabelRegistry::new();
        let first = at(
            &registry,
            &rosters,
            &book,
            &[d1.id, d2.id],
            &n,
            &["app"],
            NOW,
        );
        assert_eq!(first.names, ["app"]);
        assert_eq!(registry.state().names["app"].network, d1.id);
        assert!(rosters.remove(&d1.id));
        registry.network_removed(&rosters, &book, &d1.id, NOW + 10);
        let state = registry.state();
        assert_eq!(
            state.names["app"].network, d2.id,
            "moved to the network that grants it"
        );
        assert!(state.quarantine.is_empty());
        // The node comes back through the second network: nothing refuses it.
        registry.clear_for(&n, NOW + 15);
        let back = at(&registry, &rosters, &book, &[d2.id], &n, &["app"], NOW + 20);
        assert_eq!(back.names, ["app"]);
    }

    /// Round T5, L4: a name a live session holds is not released at the removal (the sweep does
    /// not release such names either); once the session has gone the sweep releases it, into
    /// quarantine bound to the removed network.
    #[test]
    fn t5_network_removed_leaves_a_held_name_to_the_sweep() {
        let rosters = RosterStore::new();
        let mut d1 = Net::new();
        let n = node(5);
        d1.publish(&rosters, &[n], &[("app", n)]);
        let book = TenantBook::default();
        let registry = LabelRegistry::new();
        at(&registry, &rosters, &book, &[d1.id], &n, &["app"], NOW);
        assert!(rosters.remove(&d1.id));
        registry.network_removed(&rosters, &book, &d1.id, NOW + 10);
        assert!(
            registry.state().names.contains_key("app"),
            "a session still holds it"
        );
        registry.sweep(&rosters, &book, NOW + 11);
        assert!(
            registry.state().names.contains_key("app"),
            "held: left alone"
        );
        registry.clear_for(&n, NOW + 12);
        registry.sweep(&rosters, &book, NOW + 13);
        let state = registry.state();
        assert!(state.names.is_empty());
        assert_eq!(state.quarantine["app"].network, Some(d1.id));
    }
}
