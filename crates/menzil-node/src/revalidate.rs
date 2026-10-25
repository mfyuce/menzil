//! Live re evaluation of grants and sessions (protocol.md 5.3, L4k).
//!
//! One [`Revalidator`] per node, not one per session. [`crate::node`]'s `serve_session` registers
//! every session it serves (full, docs only responder, docs only initiator) and forgets it when
//! its accept loop ends, so no handle outlives its session. [`Revalidator::run`] is the task
//! that asks, for every network with a live session, whether each session may go on:
//!
//! * a **full session** that fails [`session_standing`] (the peer or this node revoked,
//!   unlisted, below its `min_serial`, the peer's certificate or this node's own gone, expired or
//!   below the floor) is closed with
//!   CLOSE `grant_removed`; one that passes has its served streams asked again
//!   ([`AcceptedStreams::recheck`]), and the ones whose grant is gone are reset;
//! * a **docs only session** is judged by the Roster alone ([`docs_only_standing`]) and closed
//!   the same way when that fails; it carries no granted stream to recheck.
//!
//! The detail of why stays in the local log (TOBEDECIDED 30 T1); the wire carries one uniform
//! `grant_removed`.
//!
//! **When it looks**: on every notice of a newer Roster or Policy (the stores' broadcast
//! channels; a lagged receiver means "every network"), on every registration (a session that
//! came up after the documents changed is checked at once), at the next instant one answer may
//! change, and in any case every [`SWEEP_INTERVAL`] as a safety net. That instant is computed
//! per network after each pass ([`next_deadline`]): the earliest future grant `expires`, Roster
//! or Policy `expires`, or first second a live peer's certificate is no longer valid. A
//! deadline farther away than the sweep interval is not waited for: a sweep comes first and
//! recomputes it. The wall clock is read afresh on every pass, so a clock that jumps costs at
//! most one sweep interval.
//!
//! **Docs only sessions and the window before a Policy arrives** (TODO.md, K2 edge cases): a
//! node whose Roster lists it but whose older Policy does not is exactly who a docs only push
//! is for. Judging that session by the full standing would end it the moment it began (and
//! would refuse the very push it exists for), so the docs only rules look at the Roster only,
//! here and in [`crate::PolicyAuthorizer::docs_only`]. A revoked peer or a revoked self still
//! ends it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use menzil_proto::{ErrorCode, NetworkId, NodeId, PolicyBody, RosterBody, X25519PublicKey};
use tokio::sync::{Notify, broadcast};
use tokio::time::MissedTickBehavior;

use crate::admission::{PolicyAuthorizer, docs_only_standing, session_standing};
use crate::cert_index::CertIndex;
use crate::l4_router::grant_removed_close;
use crate::l4_session::L4SessionHandle;
use crate::l5_stream::AcceptedStreams;
use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;

/// How often every network with a live session is looked at whatever else happened (T11).
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// Added to a wait for a deadline so that the wall clock has surely reached it on waking.
const WAKE_MARGIN: Duration = Duration::from_millis(50);

/// What kind of session is registered, and what the revalidator needs for it.
pub(crate) enum Kind {
    /// An ordinary session: judged by [`session_standing`], its served streams asked again
    /// with `authorizer` (the one the session's accept loop uses).
    Full {
        streams: AcceptedStreams,
        authorizer: PolicyAuthorizer,
    },
    /// A docs only session, either role: judged by the Roster alone.
    DocsOnly,
}

struct LiveSession {
    peer: NodeId,
    network_id: NetworkId,
    peer_static: X25519PublicKey,
    handle: L4SessionHandle,
    kind: Kind,
}

/// What a pass decides for one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// End the session with CLOSE `grant_removed`; the code is for the local log.
    Close(ErrorCode),
    /// Ask the session's served streams again.
    Recheck,
}

#[derive(Default)]
struct State {
    next_id: u64,
    sessions: HashMap<u64, LiveSession>,
    /// Networks that got a session since the last pass.
    pending: HashSet<NetworkId>,
}

/// The one task and registry of a node. See the module docs.
pub(crate) struct Revalidator {
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    local: NodeId,
    local_serial: u32,
    /// This node's own static key, for its certificate in the Policy (round 11 N1).
    local_static: X25519PublicKey,
    sweep: Duration,
    state: Mutex<State>,
    wake: Notify,
    passes: AtomicU64,
    /// Test hook: the next pass panics (the supervision test).
    #[cfg(test)]
    pub(crate) panic_next_pass: std::sync::atomic::AtomicBool,
    /// Test hook: the thread the last pass ran on.
    #[cfg(test)]
    pub(crate) last_pass_thread: Mutex<Option<std::thread::ThreadId>>,
    /// Test hook: called before each session is judged.
    #[cfg(test)]
    pub(crate) judge_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl Revalidator {
    pub(crate) fn new(
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        local: NodeId,
        local_serial: u32,
        local_static: X25519PublicKey,
    ) -> Arc<Self> {
        Self::with_sweep(
            policies,
            rosters,
            local,
            local_serial,
            local_static,
            SWEEP_INTERVAL,
        )
    }

    /// [`Self::new`] with another sweep interval (tests shorten it).
    pub(crate) fn with_sweep(
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        local: NodeId,
        local_serial: u32,
        local_static: X25519PublicKey,
        sweep: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            policies,
            rosters,
            local,
            local_serial,
            local_static,
            sweep,
            state: Mutex::new(State::default()),
            wake: Notify::new(),
            passes: AtomicU64::new(0),
            #[cfg(test)]
            panic_next_pass: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            last_pass_thread: Mutex::new(None),
            #[cfg(test)]
            judge_hook: Mutex::new(None),
        })
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes a session that came up and has it looked at at once: the documents may have
    /// changed between the router's decision and now. Returns its id for [`Self::forget`].
    pub(crate) fn register(
        &self,
        peer: NodeId,
        network_id: NetworkId,
        peer_static: X25519PublicKey,
        handle: L4SessionHandle,
        kind: Kind,
    ) -> u64 {
        let id = {
            let mut state = self.state();
            let id = state.next_id;
            state.next_id += 1;
            state.sessions.insert(
                id,
                LiveSession {
                    peer,
                    network_id,
                    peer_static,
                    handle,
                    kind,
                },
            );
            state.pending.insert(network_id);
            id
        };
        self.wake.notify_one();
        id
    }

    /// Drops session `id` (its accept loop ended), and with it the handle and the stream
    /// registry it held.
    pub(crate) fn forget(&self, id: u64) {
        self.state().sessions.remove(&id);
    }

    /// How many sessions are registered.
    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.state().sessions.len()
    }

    /// Whether the registry lock is free right now, for tests.
    #[cfg(test)]
    pub(crate) fn state_is_free(&self) -> bool {
        self.state.try_lock().is_ok()
    }

    /// How many network passes have run, for tests.
    #[cfg(test)]
    pub(crate) fn passes(&self) -> u64 {
        self.passes.load(Ordering::SeqCst)
    }

    fn networks_with_sessions(&self) -> HashSet<NetworkId> {
        self.state()
            .sessions
            .values()
            .map(|session| session.network_id)
            .collect()
    }

    fn take_pending(&self) -> HashSet<NetworkId> {
        std::mem::take(&mut self.state().pending)
    }

    /// What is to be done for each session of `network_id` by the documents held now, at `now`
    /// (Unix seconds). A session that needs nothing is not listed. Ordered by registration.
    ///
    /// The registry lock is held only to copy out who the sessions are; the judging, which
    /// reads the stores and checks a signature per session, runs without it (round 11 L1), so
    /// `register` and `forget` never wait for a pass.
    pub(crate) fn plan(&self, network_id: &NetworkId, now: u64) -> Vec<(u64, Action)> {
        let mut sessions: Vec<(u64, NodeId, X25519PublicKey, bool)> = self
            .state()
            .sessions
            .iter()
            .filter(|(_, session)| &session.network_id == network_id)
            .map(|(id, session)| {
                (
                    *id,
                    session.peer,
                    session.peer_static,
                    matches!(session.kind, Kind::Full { .. }),
                )
            })
            .collect();
        sessions.sort_by_key(|(id, ..)| *id);
        self.judge(network_id, &sessions, now)
    }

    /// The standing of each of `sessions` (id, peer, peer static key, full or docs only). Takes
    /// no lock of the registry.
    fn judge(
        &self,
        network_id: &NetworkId,
        sessions: &[(u64, NodeId, X25519PublicKey, bool)],
        now: u64,
    ) -> Vec<(u64, Action)> {
        #[cfg(test)]
        let hook = self
            .judge_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        sessions
            .iter()
            .filter_map(|(id, peer, peer_static, full)| {
                #[cfg(test)]
                if let Some(hook) = &hook {
                    hook();
                }
                let action = if *full {
                    Some(
                        match session_standing(
                            &self.policies,
                            &self.rosters,
                            network_id,
                            peer,
                            peer_static,
                            &self.local,
                            self.local_serial,
                            &self.local_static,
                            now,
                        ) {
                            Ok(()) => Action::Recheck,
                            Err(reason) => Action::Close(reason),
                        },
                    )
                } else {
                    docs_only_standing(
                        &self.rosters,
                        network_id,
                        peer,
                        &self.local,
                        self.local_serial,
                    )
                    .err()
                    .map(Action::Close)
                };
                action.map(|action| (*id, action))
            })
            .collect()
    }

    /// Carries out `plan`; returns how many sessions were closed and how many served streams
    /// were reset. Nothing is held locked while a session or a stream is told.
    fn apply(&self, plan: &[(u64, Action)]) -> (usize, usize) {
        struct Todo {
            peer: NodeId,
            network_id: NetworkId,
            handle: L4SessionHandle,
            action: Action,
            recheck: Option<(AcceptedStreams, PolicyAuthorizer)>,
        }
        let todo: Vec<Todo> = {
            let state = self.state();
            plan.iter()
                .filter_map(|(id, action)| {
                    let session = state.sessions.get(id)?;
                    Some(Todo {
                        peer: session.peer,
                        network_id: session.network_id,
                        handle: session.handle.clone(),
                        action: *action,
                        recheck: match &session.kind {
                            Kind::Full {
                                streams,
                                authorizer,
                            } => Some((streams.clone(), authorizer.clone())),
                            Kind::DocsOnly => None,
                        },
                    })
                })
                .collect()
        };
        let (mut closed, mut reset) = (0, 0);
        for item in todo {
            match item.action {
                Action::Close(reason) => {
                    tracing::info!(
                        peer = %item.peer,
                        network_id = %item.network_id,
                        ?reason,
                        "session ended: the peer or this node lost its standing"
                    );
                    item.handle.close(Some(grant_removed_close()));
                    closed += 1;
                }
                Action::Recheck => {
                    if let Some((streams, authorizer)) = item.recheck {
                        let stopped = streams.recheck(&authorizer);
                        if stopped > 0 {
                            tracing::info!(
                                peer = %item.peer,
                                network_id = %item.network_id,
                                stopped,
                                "streams reset: their grant is gone"
                            );
                        }
                        reset += stopped;
                    }
                }
            }
        }
        (closed, reset)
    }

    /// The first instant, in Unix seconds, after `now` at which an answer for `network_id` may
    /// change, if there is one: see [`next_deadline`]. This node's own certificate counts when a
    /// full session is live (round 11 N1: its `not_after` ends them).
    pub(crate) fn deadline(&self, network_id: &NetworkId, now: u64) -> Option<u64> {
        let mut peers: Vec<(NodeId, X25519PublicKey)> = self
            .state()
            .sessions
            .values()
            .filter(|session| {
                &session.network_id == network_id && matches!(session.kind, Kind::Full { .. })
            })
            .map(|session| (session.peer, session.peer_static))
            .collect();
        if !peers.is_empty() {
            peers.push((self.local, self.local_static));
        }
        let roster = self.rosters.body(network_id)?;
        let view = self.policies.view(network_id)?;
        next_deadline(&roster, &view.body, &view.certs, &peers, now)
    }

    /// One pass over `network_id`: plan, apply, and the new deadline (none when nothing is
    /// worth waiting for within the sweep interval).
    fn pass(&self, network_id: &NetworkId) -> Option<u64> {
        self.passes.fetch_add(1, Ordering::SeqCst);
        #[cfg(test)]
        {
            *self
                .last_pass_thread
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(std::thread::current().id());
            if self.panic_next_pass.swap(false, Ordering::SeqCst) {
                panic!("test: a pass panics");
            }
        }
        let now = unix_now();
        let plan = self.plan(network_id, now);
        self.apply(&plan);
        let horizon = now.saturating_add(self.sweep.as_secs());
        self.deadline(network_id, now).filter(|at| *at <= horizon)
    }

    /// Runs until the task is dropped, and keeps running after a panic: the work is done by
    /// [`Self::run_once`] in a task of its own, and when that one panics the panic is logged and
    /// a new one starts with every network looked at (a panic ends all re evaluation for the
    /// life of the node otherwise). Dropping or aborting this future stops the inner task too.
    pub(crate) async fn run(self: Arc<Self>) {
        let mut everything = false;
        loop {
            let inner = tokio::spawn(Arc::clone(&self).run_once(everything));
            let _stop = AbortOnDrop(inner.abort_handle());
            match inner.await {
                Ok(()) => return,
                Err(error) if error.is_panic() => {
                    tracing::error!(
                        "the revalidator panicked; it is restarted and every network looked at"
                    );
                    everything = true;
                }
                // Cancelled from outside: nothing more to watch.
                Err(_) => return,
            }
        }
    }

    /// The loop itself. Subscribes to both stores first, so a change that lands while a pass
    /// runs is seen by the next wake. `everything` starts with a pass over every network that
    /// has a session (a restart after a panic).
    async fn run_once(self: Arc<Self>, everything: bool) {
        let mut roster_rx = self.rosters.subscribe();
        let mut policy_rx = self.policies.subscribe();
        let mut sweep = tokio::time::interval(self.sweep);
        sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
        sweep.tick().await; // the first tick is immediate
        let mut deadlines: HashMap<NetworkId, u64> = HashMap::new();
        let mut first = everything;
        loop {
            let next = deadlines.values().min().copied();
            let mut due: HashSet<NetworkId> = HashSet::new();
            let mut all = false;
            if std::mem::take(&mut first) {
                all = true;
            } else {
                tokio::select! {
                    changed = roster_rx.recv() => {
                        if !note_change(changed, &mut due, &mut all) {
                            return;
                        }
                    }
                    changed = policy_rx.recv() => {
                        if !note_change(changed, &mut due, &mut all) {
                            return;
                        }
                    }
                    () = self.wake.notified() => {}
                    _ = sweep.tick() => all = true,
                    () = sleep_until_unix(next) => {}
                }
            }
            // Whatever else arrived meanwhile is one pass, not many.
            drain(&mut roster_rx, &mut due, &mut all);
            drain(&mut policy_rx, &mut due, &mut all);
            due.extend(self.take_pending());
            if all {
                due.extend(self.networks_with_sessions());
            }
            let now = unix_now();
            due.extend(
                deadlines
                    .iter()
                    .filter(|(_, at)| **at <= now)
                    .map(|(network_id, _)| *network_id),
            );
            for network_id in due {
                // A pass reads the stores and checks a signature per session: not on a runtime
                // worker (round 11 L1).
                let this = Arc::clone(&self);
                let passed = tokio::task::spawn_blocking(move || this.pass(&network_id)).await;
                let outcome = match passed {
                    Ok(next) => next,
                    Err(error) => match error.try_into_panic() {
                        // Let the supervisor in `run` log it and start over.
                        Ok(panic) => std::panic::resume_unwind(panic),
                        Err(_) => return,
                    },
                };
                match outcome {
                    Some(at) => {
                        deadlines.insert(network_id, at);
                    }
                    None => {
                        deadlines.remove(&network_id);
                    }
                }
            }
        }
    }
}

/// Files one `recv` result of a store's change channel: the network named, or every network
/// after a lag. `false` when the channel is closed (the store is gone; nothing more to watch).
fn note_change(
    changed: Result<NetworkId, broadcast::error::RecvError>,
    due: &mut HashSet<NetworkId>,
    all: &mut bool,
) -> bool {
    match changed {
        Ok(network_id) => {
            due.insert(network_id);
            true
        }
        Err(broadcast::error::RecvError::Lagged(_)) => {
            *all = true;
            true
        }
        Err(broadcast::error::RecvError::Closed) => false,
    }
}

/// Takes every notice already waiting on `rx` into `due` (or `all`, after a lag).
fn drain(rx: &mut broadcast::Receiver<NetworkId>, due: &mut HashSet<NetworkId>, all: &mut bool) {
    loop {
        match rx.try_recv() {
            Ok(network_id) => {
                due.insert(network_id);
            }
            Err(broadcast::error::TryRecvError::Lagged(_)) => *all = true,
            Err(_) => return,
        }
    }
}

/// Aborts a task when dropped.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Sleeps until the wall clock reaches `at` (Unix seconds), plus a small margin; forever for
/// `None`. Already past: returns at once.
async fn sleep_until_unix(at: Option<u64>) {
    let Some(at) = at else {
        std::future::pending::<()>().await;
        return;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let wait = Duration::from_secs(at).saturating_sub(now);
    if wait.is_zero() {
        return;
    }
    tokio::time::sleep(wait + WAKE_MARGIN).await;
}

/// The first instant after `now`, in Unix seconds, at which a session's standing or a stream's
/// grant in this network may change by the mere passing of time: the earliest of
///
/// * a grant's `expires` (a grant holds while `expires > now`, so it is gone at `expires`),
/// * the Roster's and the Policy's `expires` (`has_grant` fails from then on),
/// * the second after the `not_after` of the certificate a live peer's session key is vouched
///   for by (valid while `now <= not_after`); `peers` also carries this node itself (its own
///   certificate in the Policy is part of its standing, round 11 N1).
///
/// `None` when nothing lies ahead. A certificate that is already gone or cannot be resolved has
/// no future instant: the pass that finds it closes the session.
pub(crate) fn next_deadline(
    roster: &RosterBody,
    policy: &PolicyBody,
    certs: &CertIndex,
    peers: &[(NodeId, X25519PublicKey)],
    now: u64,
) -> Option<u64> {
    let grants = policy.grants.iter().filter_map(|grant| grant.expires);
    let documents = [roster.expires, policy.expires];
    let certs = peers.iter().filter_map(|(peer, peer_static)| {
        certs
            .resolve(peer, peer_static, now)
            .and_then(|cert| cert.not_after.checked_add(1))
    });
    grants
        .chain(documents)
        .chain(certs)
        .filter(|at| *at > now)
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{
        Grant, NodeCert, NodeCertBody, NodeOrWildcard, PROTOCOL_VERSION, Principal, PrincipalTarget,
    };

    struct Fixture {
        roster: RosterBody,
        policy: PolicyBody,
        peer: NodeId,
        peer_static: X25519PublicKey,
    }

    fn fixture(not_after: u64) -> Fixture {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let peer_key = SigningKey::generate(&mut rand::rng());
        let peer = NodeId::from(peer_key.verifying_key().to_bytes());
        let peer_static = X25519PublicKey::from([7u8; 32]);
        let cert = NodeCert::sign(
            &peer_key,
            &NodeCertBody {
                v: PROTOCOL_VERSION,
                node_id: peer,
                x25519_pub: peer_static,
                serial: 1,
                not_before: 0,
                not_after,
            },
        )
        .unwrap();
        let roster = RosterBody {
            v: PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 5_000,
            members: vec![],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        let policy = PolicyBody {
            v: PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 6_000,
            members: vec![],
            certs: vec![cert],
            grants: vec![],
            egress: vec![],
            accept: vec![],
        };
        Fixture {
            roster,
            policy,
            peer,
            peer_static,
        }
    }

    /// `next_deadline` for the fixture, with the index of its certificates.
    fn deadline_of(f: &Fixture, peers: &[(NodeId, X25519PublicKey)], now: u64) -> Option<u64> {
        next_deadline(
            &f.roster,
            &f.policy,
            &CertIndex::build(&f.policy.certs),
            peers,
            now,
        )
    }

    fn grant_expiring(f: &Fixture, expires: Option<u64>) -> Grant {
        Grant {
            from: Principal {
                network_id: f.policy.network_id,
                target: PrincipalTarget::Node(f.peer),
            },
            to_node: NodeOrWildcard::Any,
            services: vec!["tcp:app".parse().unwrap()],
            expires,
        }
    }

    #[test]
    fn nothing_ahead_gives_no_deadline() {
        let mut f = fixture(u64::MAX);
        f.roster.expires = 100;
        f.policy.expires = 100;
        f.policy.grants = vec![grant_expiring(&f, None), grant_expiring(&f, Some(50))];
        assert_eq!(deadline_of(&f, &[], 100), None);
        assert_eq!(
            deadline_of(&f, &[(f.peer, f.peer_static)], 100),
            None,
            "a certificate valid until the end of time has no end to wait for"
        );
    }

    #[test]
    fn the_earliest_future_grant_expiry_wins_and_past_ones_and_never_are_ignored() {
        let mut f = fixture(u64::MAX);
        f.policy.grants = vec![
            grant_expiring(&f, Some(900)),
            grant_expiring(&f, None),
            grant_expiring(&f, Some(300)),
            grant_expiring(&f, Some(50)),
        ];
        assert_eq!(deadline_of(&f, &[], 100), Some(300));
        // The expiry itself is no longer ahead: from that second the grant is gone.
        assert_eq!(deadline_of(&f, &[], 300), Some(900));
    }

    #[test]
    fn a_documents_expiry_is_a_deadline() {
        let mut f = fixture(u64::MAX);
        f.roster.expires = 700;
        f.policy.expires = 800;
        assert_eq!(deadline_of(&f, &[], 100), Some(700));
        f.roster.expires = 900;
        assert_eq!(deadline_of(&f, &[], 100), Some(800));
    }

    #[test]
    fn a_live_peers_certificate_ends_the_second_after_its_not_after() {
        let f = fixture(400);
        let peers = [(f.peer, f.peer_static)];
        assert_eq!(deadline_of(&f, &peers, 100), Some(401));
        // A key that backs no session is no reason to wake.
        let other = [(f.peer, X25519PublicKey::from([8u8; 32]))];
        assert_eq!(deadline_of(&f, &other, 100), Some(5_000));
        // Past its end the certificate resolves no more: the pass closes the session.
        assert_eq!(deadline_of(&f, &peers, 401), Some(5_000));
    }

    #[test]
    fn the_deadline_is_the_minimum_over_all_sources() {
        let mut f = fixture(450);
        f.policy.grants = vec![grant_expiring(&f, Some(500))];
        let peers = [(f.peer, f.peer_static)];
        assert_eq!(deadline_of(&f, &peers, 100), Some(451));
        f.policy.grants = vec![grant_expiring(&f, Some(200))];
        assert_eq!(deadline_of(&f, &peers, 100), Some(200));
    }

    #[test]
    fn a_notice_names_its_network_and_a_lag_means_every_network() {
        let (mut due, mut all) = (HashSet::new(), false);
        let network = NetworkId::from([3u8; 32]);
        assert!(note_change(Ok(network), &mut due, &mut all));
        assert!(due.contains(&network) && !all);
        assert!(note_change(
            Err(broadcast::error::RecvError::Lagged(5)),
            &mut due,
            &mut all
        ));
        assert!(all);
        assert!(!note_change(
            Err(broadcast::error::RecvError::Closed),
            &mut due,
            &mut all
        ));
    }

    #[tokio::test]
    async fn draining_a_lagged_receiver_asks_for_every_network() {
        let (tx, mut rx) = broadcast::channel::<NetworkId>(4);
        for i in 0..10u8 {
            tx.send(NetworkId::from([i; 32])).unwrap();
        }
        let (mut due, mut all) = (HashSet::new(), false);
        drain(&mut rx, &mut due, &mut all);
        assert!(all, "a receiver that fell behind lost notices");
        // What is left after the lag is still taken.
        assert!(!due.is_empty());
        let (mut due, mut all) = (HashSet::new(), false);
        drain(&mut rx, &mut due, &mut all);
        assert!(due.is_empty() && !all, "and then there is nothing");
    }
}
