//! When a node asks for, or gives, documents over `menzil:docs` (protocol.md 5.5, 7.3; TODO.md
//! L4j S6): the triggers on top of the [`crate::docs`] library and the access rules of
//! [`crate::docs_access`].
//!
//! * **A session came up and this node was the initiator** ([`DocsSync::reconcile`]): the
//!   responder's `roster_seq` and `policy_seq` are in its handshake payload, so the initiator
//!   compares them with its own ([`plan_sync`]): the responder newer, fetch; older, push; each
//!   ahead in one, push and then fetch. The seqs are the peer's own claim, a hint for choosing a
//!   direction and nothing else: whatever arrives is judged by [`crate::DocStore::adopt`].
//! * **A docs only session this node initiated** ([`DocsSync::docs_only_push`]): the responder
//!   cannot vouch for this node's key yet, so it takes one push. When that push was adopted the
//!   node starts one new handshake, because the responder now holds a Policy that vouches for it
//!   ([`REHANDSHAKE_WINDOW`] keeps that to one try, however the peer answers).
//! * **A Roster newer than the Policy** ([`DocsSync::run_roster_watch`]): the Policy is fetched
//!   from peers that have a live session with a known `policy_seq` at the Roster's `seq`, then
//!   (in the same round) from members of the Policy, three asked in all, after a random wait of up to a minute so that a
//!   network does not ask one peer all at once ([`pick_for_policy`]).
//! * **Documents about to expire** ([`DocsSync::run_expiry`]): when the held pair expires within
//!   24 hours, every 30 to 90 minutes (random each time) a fetch from up to three peers, those with
//!   a live session first ([`pick_for_expiry`]), stopping at the first that brought something.
//! * **The issuer pushes** ([`push_to_members`]): both documents to every unrevoked member, eight
//!   at a time, a member that does not answer retried after 1, 5 and 30 minutes and 2 hours.
//!
//! Every wait and every limit is a constant or a pure function here, so each rule is tested
//! alone; the flows are tested over the routers of `l4_router/tests.rs`.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::future::join_all;
use futures_util::io::AsyncWriteExt;
use menzil_proto::docs::Outcome;
use menzil_proto::{NetworkId, NodeId};
use thiserror::Error;
use tokio::sync::{Semaphore, broadcast};
use tokio::time::Instant;

use crate::admission::{docs_service, is_unrevoked_roster_member};
use crate::docs::{
    DocsParams, DocsSink, DocsStreamError, FetchReport, HeldDocs, PushResult, STREAM_DEADLINE,
    StoreDocs, bundle_to_push, fetch, push,
};
use crate::l4_router::{EnsureError, RouterHandle};
use crate::l4_session::L4SessionHandle;
use crate::l5_stream::{OpenStreamError, open};
use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;

/// Peers one catch-up round asks, at most (protocol.md 5.5: "up to three").
pub(crate) const PEER_CAP: usize = 3;
/// Members an issuer pushes to at the same time.
pub(crate) const PUSH_AT_ONCE: usize = 8;
/// The waits before an issuer's retries, in order: after 1 minute, then 5, then 30, then 2 hours
/// (each wait starts when the attempt before it failed); then the member is given up on for that
/// `seq`.
pub(crate) const PUSH_RETRY: [Duration; 4] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(30 * 60),
    Duration::from_secs(2 * 60 * 60),
];
/// How close to its expiry a held pair has to be for the member to start asking (24 hours).
pub(crate) const EXPIRY_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
/// The shortest wait between two expiry rounds (30 minutes).
pub(crate) const EXPIRY_INTERVAL_MIN: Duration = Duration::from_secs(30 * 60);
/// The longest wait between two expiry rounds (90 minutes).
pub(crate) const EXPIRY_INTERVAL_MAX: Duration = Duration::from_secs(90 * 60);
/// The longest random wait before a Policy fetch that follows a newer Roster (60 seconds).
pub const POLICY_JITTER_MAX: Duration = Duration::from_secs(60);
/// A docs only session's push that was adopted is followed by one new handshake; a second docs
/// only session to the same peer within this window gets no further one.
pub(crate) const REHANDSHAKE_WINDOW: Duration = Duration::from_secs(60);
/// How many times a Policy catch-up repeats because the Roster moved on while it ran.
const CATCH_UP_ROUNDS: usize = 4;

/// What a node's sync tasks may be told, for a test or an embedder that wants other timing.
#[derive(Debug, Clone, Copy)]
pub struct SyncConfig {
    /// The longest random wait before a fetch of the Policy that follows a newer Roster, and
    /// before the first expiry check after the node starts. Default [`POLICY_JITTER_MAX`].
    pub policy_jitter_max: Duration,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            policy_jitter_max: POLICY_JITTER_MAX,
        }
    }
}

/// Why one docs exchange with a peer failed (for the log).
#[derive(Debug, Error)]
pub(crate) enum SyncError {
    #[error("no session: {0}")]
    Session(#[from] EnsureError),
    #[error("opening the stream: {0}")]
    Open(#[from] OpenStreamError),
    #[error("the exchange: {0}")]
    Docs(#[from] DocsStreamError),
}

// ----------------------------------------------------------------------
// Pure rules
// ----------------------------------------------------------------------

/// A value in `0..=max`, spread evenly over the whole range of `r` (so `0` gives `0` and
/// `u64::MAX` gives exactly `max`).
fn scale(max: Duration, r: u64) -> Duration {
    let nanos = max.as_nanos();
    let scaled = (u128::from(r) * (nanos + 1)) >> 64;
    Duration::new(
        u64::try_from(scaled / 1_000_000_000).unwrap_or(u64::MAX),
        u32::try_from(scaled % 1_000_000_000).unwrap_or(0),
    )
}

/// The random wait before a Policy fetch: `0..=max`.
pub(crate) fn policy_jitter(max: Duration, r: u64) -> Duration {
    scale(max, r)
}

/// The random wait between two expiry rounds: `30..=90` minutes.
pub(crate) fn expiry_interval(r: u64) -> Duration {
    EXPIRY_INTERVAL_MIN + scale(EXPIRY_INTERVAL_MAX - EXPIRY_INTERVAL_MIN, r)
}

/// Whether a pair that expires at `expires` (Unix seconds) is within `window` of `now`: also
/// true for one that has expired already.
pub(crate) fn expires_within(expires: u64, now: u64, window: Duration) -> bool {
    expires <= now.saturating_add(window.as_secs())
}

/// How far the Policy is behind the Roster: the Roster's `seq` when the Policy is older than it
/// (or there is none), `None` when the Policy has caught up or there is no Roster.
pub(crate) fn policy_behind(roster_seq: Option<u64>, policy_seq: Option<u64>) -> Option<u64> {
    let roster = roster_seq?;
    match policy_seq {
        Some(policy) if policy >= roster => None,
        _ => Some(roster),
    }
}

/// What to do with a session's peer, from the seqs of both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SyncPlan {
    /// Neither is ahead.
    Nothing,
    /// The peer is ahead: fetch.
    Fetch,
    /// This node is ahead: push.
    Push,
    /// Each is ahead in one document: push, then fetch.
    PushThenFetch,
}

/// Compares what this node holds with what the peer says it holds (its handshake payload: the
/// peer's own claim, which only picks a direction). A side that holds nothing is behind any
/// side that holds something.
pub(crate) fn plan_sync(
    ours: HeldDocs,
    peer_roster: Option<u64>,
    peer_policy: Option<u64>,
) -> SyncPlan {
    let peer_ahead = peer_roster > ours.roster_seq || peer_policy > ours.policy_seq;
    let we_ahead = ours.roster_seq > peer_roster || ours.policy_seq > peer_policy;
    match (peer_ahead, we_ahead) {
        (false, false) => SyncPlan::Nothing,
        (true, false) => SyncPlan::Fetch,
        (false, true) => SyncPlan::Push,
        (true, true) => SyncPlan::PushThenFetch,
    }
}

/// Whom to ask for the Policy of a Roster at `roster_seq`, three in all, none twice: first the
/// peers with a live session whose known `policy_seq` is at least that, then `members` in the
/// same round (a live peer's claim is only its own word: one that claims the Policy and gives
/// none must not be the only one asked). `live` and `members` come in the order to try (the
/// caller shuffles).
pub(crate) fn pick_for_policy(
    live: &[(NodeId, Option<u64>)],
    members: &[NodeId],
    roster_seq: u64,
) -> Vec<NodeId> {
    let sure = live
        .iter()
        .filter(|(_, policy_seq)| policy_seq.is_some_and(|seq| seq >= roster_seq))
        .map(|(peer, _)| peer);
    let mut picked: Vec<NodeId> = Vec::new();
    for peer in sure.chain(members) {
        if picked.len() == PEER_CAP {
            break;
        }
        if !picked.contains(peer) {
            picked.push(*peer);
        }
    }
    picked
}

/// Whom to ask when the held documents are about to expire: the peers with a live session first,
/// then members, three in all, none twice.
pub(crate) fn pick_for_expiry(live: &[NodeId], members: &[NodeId]) -> Vec<NodeId> {
    let mut picked: Vec<NodeId> = Vec::new();
    for peer in live.iter().chain(members) {
        if picked.len() == PEER_CAP {
            break;
        }
        if !picked.contains(peer) {
            picked.push(*peer);
        }
    }
    picked
}

/// The peers a docs only handshake was followed up for lately: at most one new handshake per
/// peer and network within [`REHANDSHAKE_WINDOW`].
#[derive(Default)]
pub(crate) struct RehandshakeGuard {
    tried: HashMap<(NodeId, NetworkId), Instant>,
}

impl RehandshakeGuard {
    /// Whether a new handshake with `peer` may start at `now`; if so, it is written down.
    pub(crate) fn allow(&mut self, peer: NodeId, network_id: NetworkId, now: Instant) -> bool {
        self.tried
            .retain(|_, at| now.saturating_duration_since(*at) < REHANDSHAKE_WINDOW);
        if self.tried.contains_key(&(peer, network_id)) {
            return false;
        }
        self.tried.insert((peer, network_id), now);
        true
    }
}

/// The two exchanges a plan is made of, for [`run_plan`].
pub(crate) trait Exchange {
    /// Pushes what is held.
    fn push(&mut self) -> impl Future<Output = ()>;
    /// Fetches what the peer holds that is newer.
    fn fetch(&mut self) -> impl Future<Output = ()>;
}

/// Carries out `plan` in its order: the push first, then the fetch.
pub(crate) async fn run_plan<E: Exchange>(plan: SyncPlan, exchange: &mut E) {
    if matches!(plan, SyncPlan::Push | SyncPlan::PushThenFetch) {
        exchange.push().await;
    }
    if matches!(plan, SyncPlan::Fetch | SyncPlan::PushThenFetch) {
        exchange.fetch().await;
    }
}

/// What one fetch from one peer came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// Something newer was adopted.
    Adopted,
    /// The peer had nothing newer.
    Nothing,
    /// No session, or the exchange failed.
    Failed,
}

/// Asks `peers` one after the other with `attempt`, stopping after the first for which `stop`
/// says so. Returns how many were asked.
pub(crate) async fn fetch_round<A, Fut>(
    peers: &[NodeId],
    mut attempt: A,
    mut stop: impl FnMut(Attempt) -> bool,
) -> usize
where
    A: FnMut(NodeId) -> Fut,
    Fut: Future<Output = Attempt>,
{
    let mut asked = 0;
    for peer in peers {
        asked += 1;
        if stop(attempt(*peer).await) {
            break;
        }
    }
    asked
}

// ----------------------------------------------------------------------
// The issuer's push
// ----------------------------------------------------------------------

/// What one push to one member came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PushStep {
    /// The member adopted the documents or already held them.
    Done,
    /// The member refused the documents: logged, never retried.
    Rejected,
    /// No session, or no answer: retried on the schedule.
    NoAnswer,
    /// Nothing to be done now or later (the member cannot be dialed from here, there is nothing to
    /// push): not retried.
    Skip,
}

/// How [`push_to_members`] talks to a member.
pub(crate) trait MemberPusher {
    /// Pushes the held documents to `member` once.
    fn push(&self, member: NodeId) -> impl Future<Output = PushStep> + Send;
    /// Whether the documents being pushed are still the ones held: a retry waits for nothing
    /// that a newer issue has overtaken.
    fn current(&self) -> bool;
}

/// What an issuer's push to all members came to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PushReport {
    /// Members that adopted the documents or already held them.
    pub done: usize,
    /// Members that refused the documents.
    pub rejected: usize,
    /// Members given up on: never answered within the schedule, could not be dialed, or the
    /// documents were overtaken by newer ones.
    pub gave_up: usize,
}

/// Pushes to every one of `members`, `at_once` at a time. A member that does not answer is tried
/// again after each wait of `retry` in turn (the wait counted from the failed attempt, no slot
/// held while waiting), and then given up on. A retry is dropped when `pusher` says the documents
/// are no longer the current ones.
pub(crate) async fn push_to_members<P: MemberPusher + Sync>(
    pusher: &P,
    members: &[NodeId],
    at_once: usize,
    retry: &[Duration],
) -> PushReport {
    let slots = Semaphore::new(at_once);
    let results = join_all(members.iter().map(|member| {
        let slots = &slots;
        async move {
            let mut waits = retry.iter();
            loop {
                let step = {
                    let _slot = slots
                        .acquire()
                        .await
                        .expect("the semaphore is never closed");
                    pusher.push(*member).await
                };
                match step {
                    PushStep::Done => return PushStep::Done,
                    PushStep::Rejected => return PushStep::Rejected,
                    PushStep::Skip => return PushStep::Skip,
                    PushStep::NoAnswer => {
                        let Some(wait) = waits.next() else {
                            return PushStep::NoAnswer;
                        };
                        tokio::time::sleep(*wait).await;
                        if !pusher.current() {
                            return PushStep::Skip;
                        }
                    }
                }
            }
        }
    }))
    .await;
    let mut report = PushReport::default();
    for step in results {
        match step {
            PushStep::Done => report.done += 1,
            PushStep::Rejected => report.rejected += 1,
            PushStep::NoAnswer | PushStep::Skip => report.gave_up += 1,
        }
    }
    report
}

/// Whether a failed session attempt is worth another try later.
pub(crate) fn step_for_ensure_error(error: EnsureError) -> PushStep {
    match error {
        // The docs only session the dial produced pushes by itself ([`DocsSync::docs_only_push`]).
        EnsureError::DocsOnly => PushStep::Done,
        EnsureError::Timeout
        | EnsureError::NotAttached
        | EnsureError::Detached
        | EnsureError::SessionEnded
        | EnsureError::TableFull => PushStep::NoAnswer,
        EnsureError::UnknownPeer
        | EnsureError::SelfPeer
        | EnsureError::NotAMember
        | EnsureError::Refused
        | EnsureError::RouterGone
        | EnsureError::ShuttingDown => PushStep::Skip,
    }
}

/// What the member's `result` means for the issuer.
pub(crate) fn step_for_result(result: &PushResult) -> PushStep {
    if result.roster == Outcome::Rejected || result.policy == Outcome::Rejected {
        PushStep::Rejected
    } else {
        PushStep::Done
    }
}

// ----------------------------------------------------------------------
// The running parts
// ----------------------------------------------------------------------

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn params(network_id: NetworkId) -> DocsParams {
    DocsParams {
        network_id,
        now: unix_now(),
        deadline: STREAM_DEADLINE,
    }
}

/// A session this node has up, as far as the sync tasks care.
struct Live {
    /// Tells a session from the one that replaced it for the same peer.
    id: u64,
    /// The peer's Roster `seq` as last learned (handshake payload, a fetch's `end`, a push's
    /// `result`): the peer's claim.
    roster_seq: Option<u64>,
    /// As above, for the Policy.
    policy_seq: Option<u64>,
}

/// The sync tasks of one node: shared by its sessions (see the module docs).
pub struct DocsSync {
    router: RouterHandle,
    rosters: Arc<RosterStore>,
    policies: Arc<PolicyStore>,
    local: NodeId,
    config: SyncConfig,
    /// Keyed by peer, network and whether this node was the initiator of the session: a session
    /// the peer started never replaces or removes the entry of one this node started.
    live: Mutex<HashMap<(NodeId, NetworkId, bool), Live>>,
    next_id: AtomicU64,
    rehandshaken: Mutex<RehandshakeGuard>,
    catching_up: Mutex<HashSet<NetworkId>>,
}

/// Removes a network from [`DocsSync::catching_up`] when its round ends, however it ends.
struct CatchUpGuard<'a> {
    sync: &'a DocsSync,
    network_id: NetworkId,
}

impl Drop for CatchUpGuard<'_> {
    fn drop(&mut self) {
        self.sync
            .catching_up
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.network_id);
    }
}

impl DocsSync {
    /// The sync tasks of a node with these stores, asking sessions of `router`.
    pub fn new(
        router: RouterHandle,
        rosters: Arc<RosterStore>,
        policies: Arc<PolicyStore>,
        local: NodeId,
        config: SyncConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            router,
            rosters,
            policies,
            local,
            config,
            live: Mutex::default(),
            next_id: AtomicU64::new(0),
            rehandshaken: Mutex::default(),
            catching_up: Mutex::default(),
        })
    }

    fn docs(&self, network_id: NetworkId) -> StoreDocs<'_> {
        StoreDocs::new(&self.rosters, &self.policies, network_id)
    }

    // ---- live sessions ------------------------------------------------

    /// Notes a session this node initiated that came up; returns its id for [`Self::forget`].
    #[cfg(test)]
    pub(crate) fn register(
        &self,
        peer: NodeId,
        network_id: NetworkId,
        roster_seq: Option<u64>,
        policy_seq: Option<u64>,
    ) -> u64 {
        self.register_as(peer, network_id, true, roster_seq, policy_seq)
    }

    /// Notes a session that came up, started by this node (`initiator`) or by the peer; returns
    /// its id for [`Self::forget`].
    pub(crate) fn register_as(
        &self,
        peer: NodeId,
        network_id: NetworkId,
        initiator: bool,
        roster_seq: Option<u64>,
        policy_seq: Option<u64>,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.live.lock().unwrap_or_else(|e| e.into_inner()).insert(
            (peer, network_id, initiator),
            Live {
                id,
                roster_seq,
                policy_seq,
            },
        );
        id
    }

    /// Notes that session `id` ended (a newer one for the same peer stays, and so does the
    /// session of the other role).
    pub(crate) fn forget(&self, peer: NodeId, network_id: NetworkId, id: u64) {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        live.retain(|key, entry| !(key.0 == peer && key.1 == network_id && entry.id == id));
    }

    fn note_peer_seqs(
        &self,
        peer: NodeId,
        network_id: NetworkId,
        roster_seq: Option<u64>,
        policy_seq: Option<u64>,
    ) {
        // What the peer says it holds is about the peer, whichever session carried it.
        for ((p, n, _), entry) in self
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
        {
            if *p == peer && *n == network_id {
                entry.roster_seq = roster_seq.or(entry.roster_seq);
                entry.policy_seq = policy_seq.or(entry.policy_seq);
            }
        }
    }

    /// The peers with a session up in `network_id`, with the Policy `seq` each is known to hold,
    /// in random order.
    pub(crate) fn live_peers(&self, network_id: NetworkId) -> Vec<(NodeId, Option<u64>)> {
        let mut by_peer: HashMap<NodeId, Option<u64>> = HashMap::new();
        for ((peer, network, _), entry) in
            self.live.lock().unwrap_or_else(|e| e.into_inner()).iter()
        {
            if *network == network_id {
                let seq = by_peer.entry(*peer).or_default();
                *seq = (*seq).max(entry.policy_seq);
            }
        }
        let mut peers: Vec<(NodeId, Option<u64>)> = by_peer.into_iter().collect();
        fastrand::shuffle(&mut peers);
        peers
    }

    /// The members this node could ask (in the Policy and unrevoked in the Roster, not itself),
    /// in random order.
    pub(crate) fn member_peers(&self, network_id: NetworkId) -> Vec<NodeId> {
        let Some(policy) = self.policies.body(&network_id) else {
            return Vec::new();
        };
        let mut members: Vec<NodeId> = policy
            .members
            .iter()
            .map(|member| member.node_id)
            .filter(|node| {
                *node != self.local && is_unrevoked_roster_member(&self.rosters, &network_id, node)
            })
            .collect();
        fastrand::shuffle(&mut members);
        members
    }

    // ---- one exchange -------------------------------------------------

    /// Fetches over `handle`: the opener closes its side when it has read the answer.
    async fn fetch_over(&self, handle: &L4SessionHandle) -> Result<FetchReport, SyncError> {
        let network_id = handle.network_id();
        let mut stream = open(handle, docs_service(), None).await?;
        let result = fetch(&mut stream, self.docs(network_id), &params(network_id)).await;
        match result {
            Ok(report) => {
                let _ = stream.close().await;
                self.note_peer_seqs(
                    handle.peer(),
                    network_id,
                    report.peer_roster_seq,
                    report.peer_policy_seq,
                );
                Ok(report)
            }
            Err(error) => {
                stream.reset();
                Err(error.into())
            }
        }
    }

    /// Pushes what is held over `handle`; `Ok(None)` when there is nothing to push (no unexpired
    /// Roster). The opener closes its side after reading `result` (a docs only responder waits
    /// for that before it closes the session).
    async fn push_over(&self, handle: &L4SessionHandle) -> Result<Option<PushResult>, SyncError> {
        let network_id = handle.network_id();
        let params = params(network_id);
        let bundle = bundle_to_push(&self.docs(network_id), params.now);
        if bundle.roster.is_none() {
            return Ok(None);
        }
        let mut stream = open(handle, docs_service(), None).await?;
        match push(&mut stream, &bundle, &params).await {
            Ok(result) => {
                let _ = stream.close().await;
                self.note_peer_seqs(
                    handle.peer(),
                    network_id,
                    result.roster_seq,
                    result.policy_seq,
                );
                Ok(Some(result))
            }
            Err(error) => {
                stream.reset();
                Err(error.into())
            }
        }
    }

    /// One fetch from `peer`, with the session found or made.
    async fn fetch_from(&self, peer: NodeId, network_id: NetworkId) -> Attempt {
        // A fetch is the one dial that expired documents of our own may not stand in the way of.
        let handle = match self.router.ensure_session_for_docs(peer, network_id).await {
            Ok(handle) => handle,
            Err(error) => {
                tracing::debug!(%peer, %error, "no session to fetch documents over");
                return Attempt::Failed;
            }
        };
        match self.fetch_over(&handle).await {
            Ok(report) if report.adopted.roster || report.adopted.policy => Attempt::Adopted,
            Ok(_) => Attempt::Nothing,
            Err(error) => {
                tracing::debug!(%peer, %error, "fetching documents failed");
                Attempt::Failed
            }
        }
    }

    // ---- trigger: a session came up -----------------------------------

    /// The initiator side of a session that came up: compares the responder's seqs with ours
    /// and fetches, pushes, or pushes and then fetches ([`plan_sync`]). Nothing here delays the
    /// session, which was handed out already.
    pub(crate) async fn reconcile(
        &self,
        handle: L4SessionHandle,
        peer_roster: Option<u64>,
        peer_policy: Option<u64>,
    ) {
        let network_id = handle.network_id();
        let plan = plan_sync(self.docs(network_id).held(), peer_roster, peer_policy);
        run_plan(plan, &mut OverSession { sync: self, handle }).await;
    }

    /// The initiator side of a docs only session: one push, and when it was adopted one new
    /// handshake (never a second within [`REHANDSHAKE_WINDOW`], whatever the peer answers).
    pub(crate) async fn docs_only_push(&self, handle: L4SessionHandle) {
        let (peer, network_id) = (handle.peer(), handle.network_id());
        match self.push_over(&handle).await {
            Ok(Some(result))
                if result.roster == Outcome::Adopted || result.policy == Outcome::Adopted =>
            {
                self.rehandshake(peer, network_id).await;
            }
            Ok(other) => {
                tracing::debug!(%peer, ?other, "the push on a docs only session was not adopted");
            }
            Err(error) => tracing::debug!(%peer, %error, "pushing on a docs only session failed"),
        }
    }

    /// Starts one handshake with `peer`, unless one was started for it a moment ago. A session
    /// that comes up is announced like any other.
    pub(crate) async fn rehandshake(&self, peer: NodeId, network_id: NetworkId) {
        let allowed = self
            .rehandshaken
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allow(peer, network_id, Instant::now());
        if !allowed {
            return;
        }
        if let Err(error) = self.router.ensure_session(peer, network_id).await {
            tracing::debug!(%peer, %error, "the handshake after a docs only push did not come up");
        }
    }

    // ---- trigger: a Roster newer than the Policy ---------------------

    /// Fetches the Policy of the held Roster: after a random wait, from the peers
    /// [`pick_for_policy`] names, stopping once the Policy has caught up. One round per network
    /// at a time; if the Roster moved on while it ran, another follows.
    pub(crate) async fn catch_up_policy(self: Arc<Self>, network_id: NetworkId) {
        if !self
            .catching_up
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(network_id)
        {
            return;
        }
        let _guard = CatchUpGuard {
            sync: &self,
            network_id,
        };
        for _ in 0..CATCH_UP_ROUNDS {
            let Some(target) = self.policy_behind(network_id) else {
                return;
            };
            tokio::time::sleep(policy_jitter(
                self.config.policy_jitter_max,
                fastrand::u64(..),
            ))
            .await;
            // The wait may have brought the Policy, or a newer Roster.
            let Some(target) = self.policy_behind(network_id).map(|now| now.max(target)) else {
                return;
            };
            let peers = pick_for_policy(
                &self.live_peers(network_id),
                &self.member_peers(network_id),
                target,
            );
            let this = Arc::clone(&self);
            let stopper = Arc::clone(&self);
            fetch_round(
                &peers,
                move |peer| {
                    let this = Arc::clone(&this);
                    async move { this.fetch_from(peer, network_id).await }
                },
                move |_| stopper.policy_behind(network_id).is_none(),
            )
            .await;
            if self.rosters.seq(&network_id) == Some(target) {
                // Nothing newer came meanwhile: this round is all there is.
                return;
            }
        }
    }

    fn policy_behind(&self, network_id: NetworkId) -> Option<u64> {
        policy_behind(
            self.rosters.seq(&network_id),
            self.policies.seq(&network_id),
        )
    }

    /// Looks at every network in `networks` now and after every newer Roster stored, and starts
    /// a Policy catch-up for one whose Policy is behind. Runs until the stores are gone.
    pub(crate) async fn run_roster_watch(self: Arc<Self>, networks: Vec<NetworkId>) {
        let mut changes = self.rosters.subscribe();
        for network_id in &networks {
            self.start_catch_up(*network_id);
        }
        loop {
            match changes.recv().await {
                Ok(network_id) => {
                    if networks.contains(&network_id) {
                        self.start_catch_up(network_id);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    for network_id in &networks {
                        self.start_catch_up(*network_id);
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    }

    fn start_catch_up(self: &Arc<Self>, network_id: NetworkId) {
        if self.policy_behind(network_id).is_some() {
            tokio::spawn(Arc::clone(self).catch_up_policy(network_id));
        }
    }

    // ---- trigger: documents about to expire --------------------------

    /// When the held pair expires, the earlier of the two documents' `expires`.
    fn held_expiry(&self, network_id: NetworkId) -> Option<u64> {
        let roster = self.rosters.body(&network_id)?;
        let policy = self.policies.body(&network_id)?;
        Some(roster.expires.min(policy.expires))
    }

    /// One expiry round if the held pair is within [`EXPIRY_WINDOW`] of expiring: a fetch from
    /// the peers [`pick_for_expiry`] names, stopping at the first that brought something.
    pub(crate) async fn expiry_round(self: &Arc<Self>, network_id: NetworkId) -> usize {
        let Some(expires) = self.held_expiry(network_id) else {
            return 0;
        };
        if !expires_within(expires, unix_now(), EXPIRY_WINDOW) {
            return 0;
        }
        let live: Vec<NodeId> = self
            .live_peers(network_id)
            .into_iter()
            .map(|(peer, _)| peer)
            .collect();
        let peers = pick_for_expiry(&live, &self.member_peers(network_id));
        let this = Arc::clone(self);
        fetch_round(
            &peers,
            move |peer| {
                let this = Arc::clone(&this);
                async move { this.fetch_from(peer, network_id).await }
            },
            |attempt| attempt == Attempt::Adopted,
        )
        .await
    }

    /// The expiry timer of one network: a first look after a short random wait, then one every
    /// [`expiry_interval`].
    pub(crate) async fn run_expiry(self: Arc<Self>, network_id: NetworkId) {
        tokio::time::sleep(policy_jitter(
            self.config.policy_jitter_max,
            fastrand::u64(..),
        ))
        .await;
        loop {
            self.expiry_round(network_id).await;
            tokio::time::sleep(expiry_interval(fastrand::u64(..))).await;
        }
    }

    // ---- the issuer's push --------------------------------------------

    /// The unrevoked members of the held Roster other than this node.
    pub(crate) fn push_targets(&self, network_id: NetworkId) -> Vec<NodeId> {
        let Some(roster) = self.rosters.body(&network_id) else {
            return Vec::new();
        };
        roster
            .members
            .iter()
            .map(|member| member.node_id)
            .filter(|node| {
                *node != self.local && is_unrevoked_roster_member(&self.rosters, &network_id, node)
            })
            .collect()
    }

    /// Pushes the held Roster and Policy to every unrevoked member of `network_id`
    /// ([`push_to_members`]). Runs for up to the length of the retry schedule: spawn it.
    pub async fn push_to_members(self: &Arc<Self>, network_id: NetworkId) -> PushReport {
        let members = self.push_targets(network_id);
        let pusher = IssuerPush {
            sync: Arc::clone(self),
            network_id,
            seq: self.rosters.seq(&network_id),
        };
        push_to_members(&pusher, &members, PUSH_AT_ONCE, &PUSH_RETRY).await
    }
}

/// The exchanges of [`DocsSync::reconcile`], over one session.
struct OverSession<'a> {
    sync: &'a DocsSync,
    handle: L4SessionHandle,
}

impl Exchange for OverSession<'_> {
    async fn push(&mut self) {
        let peer = self.handle.peer();
        match self.sync.push_over(&self.handle).await {
            Ok(Some(result)) => {
                tracing::debug!(%peer, ?result, "pushed documents to a peer that was behind");
            }
            Ok(None) => {}
            Err(error) => tracing::debug!(%peer, %error, "pushing documents failed"),
        }
    }

    async fn fetch(&mut self) {
        let peer = self.handle.peer();
        match self.sync.fetch_over(&self.handle).await {
            Ok(report) => {
                tracing::debug!(%peer, adopted = ?report.adopted, "fetched documents from a peer that was ahead");
            }
            Err(error) => tracing::debug!(%peer, %error, "fetching documents failed"),
        }
    }
}

/// The issuer's push of one network, as a [`MemberPusher`].
struct IssuerPush {
    sync: Arc<DocsSync>,
    network_id: NetworkId,
    /// The Roster `seq` being pushed.
    seq: Option<u64>,
}

impl MemberPusher for IssuerPush {
    async fn push(&self, member: NodeId) -> PushStep {
        let handle = match self
            .sync
            .router
            .ensure_session(member, self.network_id)
            .await
        {
            Ok(handle) => handle,
            Err(error) => return step_for_ensure_error(error),
        };
        match self.sync.push_over(&handle).await {
            Ok(Some(result)) => {
                let step = step_for_result(&result);
                if step == PushStep::Rejected {
                    tracing::error!(%member, ?result, "a member refused the documents pushed to it");
                }
                step
            }
            Ok(None) => PushStep::Skip,
            Err(error) => {
                tracing::debug!(%member, %error, "pushing documents to a member failed");
                PushStep::NoAnswer
            }
        }
    }

    fn current(&self) -> bool {
        self.sync.rosters.seq(&self.network_id) == self.seq
    }
}

#[cfg(test)]
mod tests;
