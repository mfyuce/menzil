//! The relay's top-level runtime state and accept loop (protocol.md 3,
//! 4.1): bundles the shared state every accepted connection needs (this
//! relay's own identity, its held Rosters, per-NodeId replay-defense
//! history, and the attached-session registry) and runs
//! [`Listener::accept_tcp`] in a loop, spawning one task per connection
//! that runs the handshake under a timeout and an in-flight limit.

use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::sync::Semaphore;

use menzil_proto::{Limits, NodeId, X25519PublicKey};

use crate::admission::{Admission, AdmissionLimits};
use crate::advertise::LabelRegistry;
use crate::endpoint::RelayEndpoint;
use crate::forward::{ForwardTable, RelaySendOutcome};
use crate::identity::RelayIdentity;
use crate::listener::Listener;
use crate::log_throttle::LogThrottle;
use crate::node_history::NodeHistory;
use crate::principal::PrincipalConfig;
use crate::rate::SessionRates;
use crate::registry::SessionRegistry;
use crate::roster_store::RosterStore;
use crate::session;
use crate::tenant::{RelayQuota, TenantBook, TenantId, TenantUsage};

/// The session numbers a relay hands out: WELCOME's `session` and the key of the registry's
/// supersede and teardown rules (equality is all they use).
///
/// The number a stranger reads in WELCOME must not be a relay wide connection counter, which
/// would show it how many connections every tenant opened in between (the first multi tenant
/// red-team round, L1). The relay counts internally, one step per accepted socket, and sends
/// that count through a keyed permutation of the 32 bit space: a four round Feistel network over
/// two 16 bit halves whose round function is SipHash keyed from the process's random state (a
/// pseudo random permutation by Luby and Rackoff). A permutation never repeats a value, so two
/// live sessions cannot share a number (before 2^32 connections, as with the plain counter), and
/// no collision handling or table of live ids is needed. The key is drawn at start and never
/// leaves the process; logs and the registry carry the sent number, the counter is not kept.
struct SessionIds {
    counter: AtomicU32,
    keys: RandomState,
}

impl SessionIds {
    fn new() -> Self {
        Self {
            counter: AtomicU32::new(1),
            keys: RandomState::new(),
        }
    }

    /// The number for the next accepted socket.
    fn next(&self) -> u32 {
        self.permute(self.counter.fetch_add(1, Ordering::Relaxed))
    }

    fn permute(&self, value: u32) -> u32 {
        let (mut left, mut right) = ((value >> 16) as u16, value as u16);
        for round in 0u8..4 {
            let mixed = self.keys.hash_one((round, right)) as u16;
            (left, right) = (right, left ^ mixed);
        }
        (u32::from(left) << 16) | u32::from(right)
    }
}

/// The time limits of a session once its connection is up: how long it has to ATTACH after
/// HELLO, and how long one send may take (round T3, M2). The relay's own figures are
/// [`crate::session::ATTACH_DEADLINE`] and [`crate::connection::WRITE_TIMEOUT`]; tests shorten
/// them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SessionTimeouts {
    pub(crate) attach: Duration,
    pub(crate) write: Duration,
}

impl Default for SessionTimeouts {
    fn default() -> Self {
        Self {
            attach: session::ATTACH_DEADLINE,
            write: crate::connection::WRITE_TIMEOUT,
        }
    }
}

/// A relay's shared runtime state: cheap to clone (every field is an
/// `Arc`, or `Copy`), so each accepted connection's spawned task gets
/// its own handle without contending on anything but the state itself.
#[derive(Clone)]
pub struct Relay {
    pub(crate) identity: Arc<RelayIdentity>,
    pub(crate) rosters: Arc<RosterStore>,
    pub(crate) history: Arc<NodeHistory>,
    pub(crate) registry: Arc<SessionRegistry>,
    pub(crate) admission: Arc<Admission>,
    pub(crate) labels: Arc<LabelRegistry>,
    pub(crate) forwarding: Arc<ForwardTable>,
    pub(crate) limits: Limits,
    pub(crate) rates: SessionRates,
    pub(crate) timeouts: SessionTimeouts,
    /// Throttles every warn line a peer's traffic can cause (isolation rule I7).
    pub(crate) log: Arc<LogThrottle>,
    /// Which tenant owns which network (MT6).
    tenants: Arc<RwLock<Arc<TenantBook>>>,
    /// The counters behind the tenants' session and Roster figures (MT7).
    pub(crate) usage: Arc<TenantUsage>,
    next_session_id: Arc<SessionIds>,
    /// This relay's own NodeId (from its NodeCert): the `dst` of the frames the relay takes
    /// itself (`crate::endpoint`) and the `src` of the ones it sends. `None` only if the
    /// certificate does not decode, and then nothing is ever treated as addressed to the relay.
    relay_id: Option<NodeId>,
    /// Where SENDs to `relay_id` go.
    pub(crate) endpoint: Arc<RelayEndpoint>,
    /// The figures of the relay principal (`crate::principal`), read when a `Principal` is made.
    principal: PrincipalConfig,
}

/// An attached node as the relay's own endpoint needs it: the L3 session it is attached by and
/// the X25519 static key of the NodeCert it presented in HELLO, read together from one
/// registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttachedNode {
    /// The L3 session id (WELCOME's `session`).
    pub session_id: u32,
    /// The static key the node's L3 session was authenticated with.
    pub x25519_pub: X25519PublicKey,
}

impl Relay {
    /// A relay with `identity` and `limits`, serving no networks yet:
    /// seed Rosters through [`Relay::rosters`] before or while calling
    /// [`Relay::serve`]. protocol.md 10 gives no stated default for
    /// `Limits.max_peers` (only `max_record` and `credit` have one), so
    /// `limits.max_peers` is always the caller's explicit choice, never
    /// invented here.
    ///
    /// `limits.credit` and `limits.max_record` are the two exceptions,
    /// each clamped (never raised, only ever lowered) before being
    /// stored — not inventing a value where the caller gave none, but
    /// correcting an internally-inconsistent one.
    ///
    /// `credit` is clamped to [`crate::forward::MAX_QUEUE_BYTES`]: an
    /// opus red team review (finding M1) caught that WELCOME advertised
    /// whatever `credit` the caller passed, unclamped, while
    /// `crate::forward::ForwardTable` separately clamped its own ledger
    /// to the same figure — so a caller configuring `credit` above the
    /// queue's own byte cap got a relay that told a node it had more
    /// credit than the relay would actually honor, killing an entirely
    /// compliant node's session the first time it believed WELCOME.
    /// Clamping once, here, is what keeps WELCOME and the ledger unable
    /// to disagree by construction.
    ///
    /// `max_record` is clamped to `menzil_carrier::MAX_MESSAGE_BYTES`
    /// (65,535 — the same figure protocol.md 10 states as `max_record`'s
    /// own default), a gap TODO.md L4b's own second review round found
    /// live: nothing stopped an operator from configuring `max_record`
    /// *above* what `Carrier::send` will actually transmit in one L2
    /// message, and WELCOME would then advertise a size a node could
    /// believe, try, and have fail to even encrypt — tearing down an
    /// otherwise healthy session the same way an unclamped `credit`
    /// once did (finding M1). Unlike `credit`, this is not a caller
    /// choice with a legitimate reason to exceed the clamp — 65,535 is
    /// the wire's own hard ceiling (`menzil-carrier::carrier::MAX_MESSAGE_BYTES`),
    /// not merely this crate's own policy, so clamping here can only
    /// ever correct a misconfiguration, never narrow a legitimate one.
    pub fn new(identity: RelayIdentity, mut limits: Limits) -> Self {
        limits.credit = limits.credit.min(crate::forward::MAX_QUEUE_BYTES as u32);
        limits.max_record = limits
            .max_record
            .min(menzil_carrier::MAX_MESSAGE_BYTES as u32);
        let tenants = Arc::new(RwLock::new(Arc::new(TenantBook::default())));
        let relay_id = identity.node_cert.decode().ok().map(|body| body.node_id);
        Self {
            identity: Arc::new(identity),
            rosters: Arc::new(RosterStore::new()),
            history: Arc::new(NodeHistory::new()),
            registry: Arc::new(SessionRegistry::new()),
            admission: Arc::new(Admission::new(AdmissionLimits::default())),
            labels: Arc::new(LabelRegistry::new()),
            // The data plane judges tenants by the same book the relay swaps (MT8).
            forwarding: Arc::new(ForwardTable::with_tenants(Arc::clone(&tenants))),
            limits,
            rates: SessionRates::default(),
            timeouts: SessionTimeouts::default(),
            log: Arc::new(LogThrottle::default()),
            tenants,
            usage: TenantUsage::new(),
            next_session_id: Arc::new(SessionIds::new()),
            relay_id,
            endpoint: Arc::new(RelayEndpoint::default()),
            principal: PrincipalConfig::default(),
        }
    }

    /// This relay's own NodeId.
    pub fn relay_id(&self) -> Option<NodeId> {
        self.relay_id
    }

    /// Whether `node` is this relay itself.
    pub(crate) fn is_relay(&self, node: &NodeId) -> bool {
        self.relay_id.as_ref() == Some(node)
    }

    /// Where the SENDs nodes address to this relay's NodeId arrive. Subscribe to take them.
    pub fn endpoint(&self) -> &RelayEndpoint {
        &self.endpoint
    }

    /// The L3 session `node` is attached by and the static key it was authenticated with, or
    /// `None` if it is not attached. The key is the one the NodeCert of that session's HELLO
    /// carried, so an L4 session opened to the node over it pins the right key.
    pub fn attached_node(&self, node: &NodeId) -> Option<AttachedNode> {
        self.registry
            .attachment_of(node)
            .map(|attachment| AttachedNode {
                session_id: attachment.session_id,
                x25519_pub: attachment.x25519_pub,
            })
    }

    /// Sends one frame to the attached `dst` as this relay (`src` is the relay's NodeId, stamped
    /// here), through the relay's virtual pair toward that node: the 4 MiB queue, credit and
    /// drain accounting of any pair, and the bandwidth and volume of `tenant`, the tenant of the
    /// name the traffic is for. No Roster is consulted and no pair or destination count is
    /// taken (`ForwardTable::forward_from_relay`).
    ///
    /// `session_id` is the L3 session of `dst` the caller checked its path against (see
    /// [`Self::attached_node`]): a frame goes only if that is still the session `dst` is attached
    /// by, and is `PeerOffline` otherwise, so that a re-attach between the caller's check and the
    /// send cannot carry a frame of the old L4 session to the new attachment.
    pub fn send_as_relay(
        &self,
        tenant: &TenantId,
        dst: &NodeId,
        session_id: u32,
        e2e_proto: u8,
        flags: u8,
        payload: Vec<u8>,
    ) -> RelaySendOutcome {
        let Some(relay_id) = self.relay_id.as_ref() else {
            return RelaySendOutcome::PeerOffline;
        };
        self.forwarding.forward_from_relay(
            &self.registry,
            &self.limits,
            relay_id,
            tenant,
            dst,
            session_id,
            e2e_proto,
            flags,
            payload,
        )
    }

    /// This relay with `limits` as its admission caps (connections per address per minute,
    /// unattached sessions per address and per NodeId, attached sessions in all) instead of
    /// [`AdmissionLimits::default`]. Call it before [`Relay::serve`] and before cloning the
    /// relay: it replaces the counters. A relay behind a reverse proxy sees one peer address
    /// for everyone and must raise the per address figures (see `crate::admission`).
    #[must_use]
    pub fn with_admission_limits(mut self, limits: AdmissionLimits) -> Self {
        self.admission = Arc::new(Admission::new(limits));
        self
    }

    /// This relay with `rates` as its per session allowances (ADVERTISE records and completed
    /// DOC transfers per minute, and how many unusable transfers end a session) instead of
    /// [`SessionRates::default`]. Call it before [`Relay::serve`] and before cloning the relay.
    #[must_use]
    pub fn with_session_rates(mut self, rates: SessionRates) -> Self {
        self.rates = rates;
        self
    }

    /// This relay with `config` as the figures of its relay principal (sessions per tenant and
    /// in all, idle time, session age; [`PrincipalConfig::default`] otherwise). Call it before
    /// [`crate::Principal::new`] and before cloning the relay.
    #[must_use]
    pub fn with_principal_config(mut self, config: PrincipalConfig) -> Self {
        self.principal = config;
        self
    }

    /// The figures a [`crate::Principal`] made from this relay uses.
    pub fn principal_config(&self) -> PrincipalConfig {
        self.principal
    }

    /// This relay with other session time limits (tests).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_timeouts(mut self, timeouts: SessionTimeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// The tenants this relay knows now: a snapshot, one tenant (the default) until
    /// [`Relay::set_tenants`] is called.
    pub fn tenants(&self) -> Arc<TenantBook> {
        Arc::clone(&self.tenants.read().unwrap())
    }

    /// Replaces the tenants (the operator's tenant files, read at start and at each reload).
    /// Every clone of this relay sees the new book.
    pub fn set_tenants(&self, book: TenantBook) {
        *self.tenants.write().unwrap() = Arc::new(book);
    }

    /// What the tenants allow of a DOC(roster) transfer now (Roster size, adoptions per network).
    pub(crate) fn roster_quota(&self, submitter: NodeId) -> RelayQuota<'_> {
        RelayQuota {
            book: self.tenants(),
            usage: &self.usage,
            submitter,
        }
    }

    /// The label registry: who holds which full name, and the durable name state behind the
    /// quotas and the 90 day release (the relay binary loads and keeps it, see
    /// [`LabelRegistry`]).
    pub fn labels(&self) -> &LabelRegistry {
        &self.labels
    }

    /// This relay's held Rosters. An operator or test harness seeds the
    /// very first Roster for a network directly through this handle
    /// (`crate::doc`'s DOC handling, protocol.md 4.3, only ever *updates*
    /// a network already held this way — see `crate::doc::accept_roster_chunk`'s
    /// docs for why introducing a brand new network is deliberately not
    /// possible over the wire).
    pub fn rosters(&self) -> &RosterStore {
        &self.rosters
    }

    /// [`Relay::serve_with`] with [`AcceptConfig::default`].
    pub async fn serve(&self, listener: &Listener) {
        self.serve_with(listener, AcceptConfig::default()).await
    }

    /// Accepts connections from `listener` forever. The loop only does
    /// the TCP accept ([`Listener::accept_tcp`]); each socket then gets
    /// its own task, which runs the TLS and WebSocket handshake under
    /// `config.handshake_timeout`, then HELLO validation (protocol.md
    /// 4.1) and the attached liveness/REKEY loop (protocol.md 3.3, 4.2).
    ///
    /// At most `config.max_inflight_handshakes` handshakes run at once.
    /// A socket that arrives when none is free is dropped at once, so
    /// the loop never waits on a peer and memory stays bounded; a
    /// handshake slot is freed when the handshake ends (done, failed or
    /// timed out), not when the session does. A single connection's own
    /// accept or handshake failure is logged and does not stop this
    /// loop; only ending the process does.
    pub async fn serve_with(&self, listener: &Listener, config: AcceptConfig) {
        let slots = Arc::new(Semaphore::new(config.max_inflight_handshakes));
        let upgrader = listener.upgrader();
        loop {
            let (tcp, peer) = match listener.accept_tcp().await {
                Ok(accepted) => accepted,
                Err(err) => {
                    tracing::warn!(error = %err, "relay failed to accept a connection");
                    // A persistent error (no file descriptors left) must not spin the loop.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            // Per address caps first (MT4, threats A9 and A14, round T3 M4): a peer over its
            // unattached share, its handshakes in flight or its connection rate is dropped
            // before TLS, without an answer and without a handshake permit (a permit is for a
            // peer that may handshake; answering a rate limited one with HTTP 429 would cost
            // the TLS handshake first). The slot is held until the session attaches or ends.
            let Some(mut ip_slot) = self.admission.admit_connection(peer.ip()) else {
                tracing::debug!(peer = %peer.ip(), "peer is over its admission share or connection rate; dropping a new connection");
                continue;
            };
            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                tracing::debug!(
                    limit = config.max_inflight_handshakes,
                    "too many handshakes in flight; dropping a new connection"
                );
                continue;
            };
            let session_id = self.next_session_id.next();
            let relay = self.clone();
            let upgrader = Arc::clone(&upgrader);
            let timeout = config.handshake_timeout;
            tokio::spawn(async move {
                let handshake = tokio::time::timeout(timeout, upgrader.handshake(tcp)).await;
                // The permit (and the peer's handshake count) is for the handshake only: free
                // it before the session starts, not when the session ends.
                drop(permit);
                ip_slot.end_handshake();
                let conn = match handshake {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(err)) => {
                        tracing::debug!(error = %err, "inbound handshake failed");
                        return;
                    }
                    Err(_elapsed) => {
                        tracing::debug!(?timeout, "inbound handshake timed out");
                        return;
                    }
                };
                session::handle_connection(conn, relay, session_id, ip_slot).await;
            });
        }
    }
}

/// How long one inbound TLS plus WebSocket handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many inbound handshakes may be in flight at once; further new
/// sockets are dropped until one finishes.
pub const MAX_INFLIGHT_HANDSHAKES: usize = 256;

/// The limits [`Relay::serve_with`] puts on connections that have not yet
/// finished their handshake. [`Default`] is [`HANDSHAKE_TIMEOUT`] and
/// [`MAX_INFLIGHT_HANDSHAKES`].
#[derive(Debug, Clone, Copy)]
pub struct AcceptConfig {
    /// A handshake not finished after this long is abandoned and its
    /// socket closed.
    pub handshake_timeout: Duration,
    /// The most handshakes in flight at once.
    pub max_inflight_handshakes: usize,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: HANDSHAKE_TIMEOUT,
            max_inflight_handshakes: MAX_INFLIGHT_HANDSHAKES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First multi tenant round, L1: the numbers sent out are distinct, are not the plain
    /// counter, never step by one, and do not rise with the connections.
    #[test]
    fn session_numbers_do_not_reveal_how_many_connections_came_between() {
        let ids = SessionIds::new();
        let drawn: Vec<u32> = (0..50).map(|_| ids.next()).collect();
        let distinct: std::collections::HashSet<_> = drawn.iter().collect();
        assert_eq!(distinct.len(), drawn.len(), "a number is never reused");
        assert!(
            drawn.windows(2).all(|w| w[1] != w[0].wrapping_add(1)),
            "consecutive connections must not get consecutive numbers: {drawn:?}"
        );
        assert!(
            drawn.windows(2).any(|w| w[1] < w[0]),
            "the numbers must not rise with the connection count: {drawn:?}"
        );
        assert_ne!(drawn[0], 1, "the first number is not the bare counter");
    }

    #[test]
    fn the_session_number_mapping_is_a_permutation_keyed_per_process() {
        let a = SessionIds::new();
        let b = SessionIds::new();
        // Distinct inputs, distinct outputs (a sample; the Feistel shape guarantees it).
        let outputs: std::collections::HashSet<u32> =
            (0..20_000u32).map(|n| a.permute(n)).collect();
        assert_eq!(outputs.len(), 20_000);
        // Another key gives another mapping.
        assert!((0..16u32).any(|n| a.permute(n) != b.permute(n)));
    }
}
