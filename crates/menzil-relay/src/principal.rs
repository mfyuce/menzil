//! The relay as an L4 initiator (expose design 1 and 3, slice S-E3): the relay principal
//! (protocol.md 6.1) opens streams to a node's shared services over an end to end session of its
//! own.
//!
//! One [`Principal`] per relay. [`Principal::open`] opens, lazily, one L4 session per
//! `(node, network)` with the relay's own identity (its `RelayIdentity` key and `NodeCert`, a
//! `Noise_IK` handshake of `menzil-e2e` with `init.network_id` = the `network` the caller
//! passes, which a later slice takes from the `NameRecord` of the name being served), multiplexes
//! streams on it with yamux (`menzil-stream`) and writes the OPEN header with `meta` set by the
//! relay and `target` always null. The relay is not a member of any network and is added to no
//! Roster or Policy; whether the node takes the session is the node's business (its `[[share]]`
//! consent, slice S-E4).
//!
//! Frames leave through [`crate::Relay::send_as_relay`] (the virtual pair of S-E2) and arrive
//! through the subscription to [`crate::RelayEndpoint`]; the principal owns that subscription, so
//! there is one principal per relay. A single dispatcher task reads every inbound frame and hands
//! it to a session only if all of these hold, and drops it (returning its credit) otherwise:
//!
//! * `e2e_proto` is 0x01 and the frame is a `resp` or `data` whose `receiver_index` names a
//!   session of this principal (an `init` is never expected);
//! * its sender is the node that session is with (a member that learned the index cannot feed a
//!   session);
//! * its L3 session id is the one the L4 session is pinned to **and** the one the node is
//!   attached by now. A frame of an older L3 session of the node (it re-attached) therefore never
//!   reaches any session: protocol.md 5.1 pins an L4 session to the relay path it was initiated
//!   over, and the credit such a frame carried is not owed to the new session either (the
//!   endpoint's ticket scopes it to the session that spent it).
//!
//! The session task then discards whatever does not fit its own state: a `data` while it is still
//! waiting for the `resp`, a `resp` after it, a frame that does not decrypt (dropped, as in
//! `menzil-node`; only an authenticated violation ends the session).
//!
//! # Lifecycle
//!
//! A session ends when: the node's L3 session id changes or the node detaches (path pin,
//! observed on every send and on every tick, [`PrincipalConfig::tick`]); it had no stream for
//! [`PrincipalConfig::idle_timeout`] (5 minutes); it is [`PrincipalConfig::max_session_age`]
//! old (24 hours); the node closes it or stays silent for 40 seconds (`menzil_e2e::Liveness`);
//! or a record violates protocol.md 5.2. Idle and age end it with a best effort CLOSE
//! (`shutting_down`; the registry has no code for "idle", and the node's reaction to any CLOSE is
//! the same).
//!
//! The 24 hour rehandshake of protocol.md 5.2 is **not** a handover here. `menzil-e2e` has no
//! scheduling for it (only REKEY and KEEP), and the node side does not keep an old session
//! alive while a new one proves itself (TBD 6, L4e2/L4h8). So at 24 hours the principal ends the
//! session (the node resets the streams on it) and the next [`Principal::open`] starts a fresh
//! one. KEEP and REKEY (hourly, or every 2^20 records) are sent by the schedules of
//! `menzil-e2e`.
//!
//! # Bounds
//!
//! At most [`PrincipalConfig::max_per_tenant`] (256) sessions for one tenant and
//! [`PrincipalConfig::max_total`] (2,048) in all, handshakes in progress included; a session over
//! either is refused as [`PrincipalError::TenantCap`] / [`PrincipalError::RelayCap`] and no
//! handshake is started. Both are settable with [`PrincipalConfig`] builders and
//! `Relay::with_principal_config`.
//!
//! Streams are bounded too, because what a session buffers grows with them (measured, expose
//! round 1 M2: about 290 KiB a stream held on the relay's side, one 256 KiB window and the
//! sender queue beside it, so 448 streams of one session are about 126 MiB). One session holds
//! at most [`PrincipalConfig::max_streams_per_session`] (64) streams (`menzil-stream`'s table
//! for a principal session is that size, and its receive windows never grow past 256 KiB:
//! `MuxLimits`), refused as [`PrincipalError::StreamLimit`]; the sessions of one tenant together
//! at most [`PrincipalConfig::max_streams_per_tenant`] (1,024), refused as
//! [`PrincipalError::TenantStreamCap`]. A stream gives its place back when it is dropped or its
//! session ends.
//!
//! Inbound frames are held as the `yamux` guard of the record they carry
//! (`StreamMux::feed_inbound_guarded`), so the node's credit comes back only when `yamux` has
//! read the bytes: a slow stream slows the node instead of growing the relay.
//!
//! Outbound, every frame is charged to the tenant of the session (the tenant of the name that
//! opened it). A reliable frame that the pair refuses as `Full` or `Throttled` is not dropped:
//! it is held (yamux pauses behind it, inbound goes on) and retried every
//! [`SEND_RETRY`], for at most [`PrincipalConfig::send_wait`]; past that the session ends.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use menzil_e2e::{E2eError, E2eInitiatorHandshake, E2eTransport, Liveness, RekeySchedule};
use menzil_proto::{
    E2eDataBody, E2eFrame, ErrorCode, NetworkId, NodeId, OpenBody, OpenMeta, PROTOCOL_VERSION,
    ServiceId, ServiceKind, X25519PublicKey,
};
use menzil_stream::{Mode, MuxLimits, OpenError, Stream, StreamMux, StreamMuxError, initiate_open};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::endpoint::InboundFrame;
use crate::forward::RelaySendOutcome;
use crate::relay::Relay;
use crate::tenant::TenantId;

/// `e2e_proto` tag of this project's own L4 (decision 0001).
const E2E_PROTO_TAG: u8 = 0x01;

/// How long a reliable frame that the relay's pair refused (`Full`, `Throttled`) waits before it
/// is offered again.
pub const SEND_RETRY: Duration = Duration::from_millis(20);

/// How long an L4 session may have no stream before the relay ends it.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Principal sessions for one tenant.
pub const DEFAULT_MAX_PER_TENANT: usize = 256;
/// Principal sessions in all.
pub const DEFAULT_MAX_TOTAL: usize = 2_048;
/// The age at which an L4 session is ended (protocol.md 5.2's 24 hour handshake).
pub const DEFAULT_MAX_SESSION_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// How long the node has to answer `init`.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long OPEN has to be answered (protocol.md 5.3).
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a reliable frame may wait for room before the session is ended.
pub const DEFAULT_SEND_WAIT: Duration = Duration::from_secs(30);
/// How often a session looks at its timers and at the node's attachment.
pub const DEFAULT_TICK: Duration = Duration::from_secs(1);
/// Streams on one principal session. About 290 KiB each on the relay's side when nobody reads
/// them (measured, see the module docs): 64 are about 18 MiB.
pub const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 64;
/// Streams on all the principal sessions of one tenant: about 290 MiB at the measured cost.
pub const DEFAULT_MAX_STREAMS_PER_TENANT: usize = 1_024;

/// The figures of the principal. [`Default`] is the design's; tests shorten the times. Every
/// `with_*` returns the changed copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrincipalConfig {
    /// A session with no stream this long is ended.
    pub idle_timeout: Duration,
    /// Sessions (handshakes included) for one tenant.
    pub max_per_tenant: usize,
    /// Sessions (handshakes included) in all.
    pub max_total: usize,
    /// A session this old is ended; the next open starts a fresh one.
    pub max_session_age: Duration,
    /// The time the node has to answer `init`.
    pub handshake_timeout: Duration,
    /// The time the node has to answer OPEN.
    pub open_timeout: Duration,
    /// The longest a reliable frame waits for room (`Full`/`Throttled`) before the session ends.
    pub send_wait: Duration,
    /// The period of the timer checks (idle, age, KEEP, REKEY, path pin).
    pub tick: Duration,
    /// Streams one session holds at once (at least 1, at most `menzil-stream`'s 448); also the
    /// size of its `yamux` table, with receive windows that never grow.
    pub max_streams_per_session: usize,
    /// Streams all the sessions of one tenant hold at once.
    pub max_streams_per_tenant: usize,
}

impl Default for PrincipalConfig {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            max_per_tenant: DEFAULT_MAX_PER_TENANT,
            max_total: DEFAULT_MAX_TOTAL,
            max_session_age: DEFAULT_MAX_SESSION_AGE,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            open_timeout: DEFAULT_OPEN_TIMEOUT,
            send_wait: DEFAULT_SEND_WAIT,
            tick: DEFAULT_TICK,
            max_streams_per_session: DEFAULT_MAX_STREAMS_PER_SESSION,
            max_streams_per_tenant: DEFAULT_MAX_STREAMS_PER_TENANT,
        }
    }
}

impl PrincipalConfig {
    /// With `limit` sessions per tenant.
    #[must_use]
    pub fn with_max_per_tenant(mut self, limit: usize) -> Self {
        self.max_per_tenant = limit;
        self
    }

    /// With `limit` sessions in all.
    #[must_use]
    pub fn with_max_total(mut self, limit: usize) -> Self {
        self.max_total = limit;
        self
    }

    /// With `idle` as the idle timeout.
    #[must_use]
    pub fn with_idle_timeout(mut self, idle: Duration) -> Self {
        self.idle_timeout = idle;
        self
    }

    /// With `age` as the session age at which a session is ended.
    #[must_use]
    pub fn with_max_session_age(mut self, age: Duration) -> Self {
        self.max_session_age = age;
        self
    }

    /// With `timeout` for the L4 handshake.
    #[must_use]
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// With `timeout` for OPEN.
    #[must_use]
    pub fn with_open_timeout(mut self, timeout: Duration) -> Self {
        self.open_timeout = timeout;
        self
    }

    /// With `wait` as the longest a reliable frame waits for room.
    #[must_use]
    pub fn with_send_wait(mut self, wait: Duration) -> Self {
        self.send_wait = wait;
        self
    }

    /// With `tick` as the period of the timer checks.
    #[must_use]
    pub fn with_tick(mut self, tick: Duration) -> Self {
        self.tick = tick;
        self
    }

    /// What a principal session's `yamux` connection is built with: the session's stream cap
    /// as its table, and receive windows that never grow (the relay must not be made to buffer
    /// more than the initial window of each stream).
    pub(crate) fn mux_limits(&self) -> MuxLimits {
        MuxLimits {
            max_live_streams: self.max_streams_per_session,
            window_growth: false,
        }
    }

    /// With `limit` streams per session.
    #[must_use]
    pub fn with_max_streams_per_session(mut self, limit: usize) -> Self {
        self.max_streams_per_session = limit;
        self
    }

    /// With `limit` streams per tenant.
    #[must_use]
    pub fn with_max_streams_per_tenant(mut self, limit: usize) -> Self {
        self.max_streams_per_tenant = limit;
        self
    }
}

/// Why [`Principal::open`] gave no stream.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalError {
    /// The relay's own NodeCert does not decode, so it has no NodeId to speak as.
    #[error("the relay has no usable identity")]
    NoIdentity,
    /// The node is not attached to this relay.
    #[error("the node is not attached to this relay")]
    NotAttached,
    /// The relay may open `tls:`, `http:`, `acme-http:` and `tcp:` services only (protocol.md
    /// 6.1).
    #[error("the relay principal may not open this kind of service")]
    ServiceNotAllowed,
    /// The tenant has `limit` principal sessions already.
    #[error("the tenant already has {limit} principal sessions")]
    TenantCap {
        /// The figure in force.
        limit: usize,
    },
    /// The relay has `limit` principal sessions already.
    #[error("the relay already has {limit} principal sessions")]
    RelayCap {
        /// The figure in force.
        limit: usize,
    },
    /// A session with this node on this network exists for another tenant: a network belongs to
    /// one tenant, so this is a caller error.
    #[error("the network's session belongs to another tenant")]
    TenantMismatch,
    /// The node did not answer `init` in time (it stays silent for a network it does not know,
    /// a share it did not advertise, a relay it does not trust).
    #[error("the node did not answer the L4 handshake in time")]
    HandshakeTimeout,
    /// The `resp` was unusable (wrong key or certificate, unsupported protocol, docs only).
    #[error("the L4 handshake failed: {0}")]
    HandshakeFailed(String),
    /// The L4 session ended (path change, idle, age, the node's CLOSE, a violation) before the
    /// stream could be opened.
    #[error("the L4 session ended")]
    SessionEnded,
    /// The session holds as many streams as [`PrincipalConfig::max_streams_per_session`] allows.
    #[error("the session holds as many streams as it may")]
    StreamLimit,
    /// The tenant's sessions hold `limit` streams already.
    #[error("the tenant already holds {limit} principal streams")]
    TenantStreamCap {
        /// The figure in force.
        limit: usize,
    },
    /// The node answered OPEN_ACK `ok: false`.
    #[error("the node refused the stream: {code:?} {msg}")]
    Refused {
        /// The refusal code.
        code: ErrorCode,
        /// The node's text.
        msg: String,
    },
    /// OPEN_ACK did not come in time.
    #[error("the node did not answer OPEN in time")]
    OpenTimeout,
    /// The OPEN header could not be encoded.
    #[error("could not encode OPEN: {0}")]
    Encode(String),
    /// The node's OPEN_ACK did not decode.
    #[error("the node's OPEN_ACK was malformed: {0}")]
    Protocol(String),
}

type Key = (NodeId, NetworkId);

/// What a session shows the callers waiting for it.
#[derive(Clone)]
enum Phase {
    Handshaking,
    Ready(StreamMux),
    Failed(PrincipalError),
}

struct SessionEntry {
    index: u32,
    tenant: TenantId,
    /// The L3 session this L4 session is pinned to.
    l3_session: u32,
    ready: watch::Receiver<Phase>,
    /// Dropping the entry (the session was replaced, the principal went away) ends the task.
    _kill: oneshot::Sender<()>,
}

struct Route {
    src: NodeId,
    l3_session: u32,
    tx: mpsc::UnboundedSender<InboundFrame>,
}

#[derive(Default)]
struct State {
    sessions: HashMap<Key, SessionEntry>,
    by_index: HashMap<u32, Route>,
    per_tenant: HashMap<TenantId, usize>,
    total: usize,
    /// Streams being opened (the place is taken before the stream exists), per tenant.
    opening: HashMap<TenantId, usize>,
}

impl State {
    /// Removes the session `index` of `key` and gives its places back; `None` if `key` holds
    /// another session (or none) by now, so a late call from an old task changes nothing.
    fn remove(&mut self, key: &Key, index: u32) -> Option<SessionEntry> {
        if self
            .sessions
            .get(key)
            .is_none_or(|entry| entry.index != index)
        {
            return None;
        }
        let entry = self.sessions.remove(key)?;
        self.by_index.remove(&index);
        self.total = self.total.saturating_sub(1);
        if let Some(count) = self.per_tenant.get_mut(&entry.tenant) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.per_tenant.remove(&entry.tenant);
            }
        }
        Some(entry)
    }
}

struct Shared {
    relay: Relay,
    relay_id: Option<NodeId>,
    config: PrincipalConfig,
    state: Mutex<State>,
    /// Why each session ended, as `Debug` text (tests only).
    #[cfg(test)]
    ends: Mutex<Vec<String>>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hands one frame from the endpoint to the session it belongs to, or drops it (which
    /// returns its credit). See the module documentation for the rules.
    fn route(&self, frame: InboundFrame) {
        if frame.e2e_proto != E2E_PROTO_TAG {
            return;
        }
        let Some(index) = receiver_index(&frame.payload) else {
            return;
        };
        let state = self.lock();
        let Some(route) = state.by_index.get(&index) else {
            return;
        };
        // Only the node the session is with.
        if route.src != frame.src {
            return;
        }
        // Only the L3 session the L4 session is pinned to: a stale frame of an older one is
        // not for it.
        if frame.session_id != route.l3_session {
            return;
        }
        // And only while the node is still attached by that session.
        let Some(attached) = self.relay.attached_node(&frame.src) else {
            return;
        };
        if attached.session_id != route.l3_session {
            return;
        }
        let _ = route.tx.send(frame);
    }
}

/// The `receiver_index` of a `resp` or `data` frame, read without decoding it.
fn receiver_index(payload: &[u8]) -> Option<u32> {
    let at = match payload.first()? {
        0x02 if payload.len() >= 9 => 5,
        0x03 if payload.len() >= 13 => 1,
        _ => return None,
    };
    Some(u32::from_be_bytes(payload[at..at + 4].try_into().ok()?))
}

/// Ends the dispatcher and every session when the last [`Principal`] handle goes.
struct Guard {
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.task.abort();
        // Dropping the entries ends the session tasks.
        *self.shared.lock() = State::default();
    }
}

/// The relay as an L4 initiator. Cheap to clone; see the module documentation.
#[derive(Clone)]
pub struct Principal {
    shared: Arc<Shared>,
    _guard: Arc<Guard>,
}

impl Principal {
    /// The principal of `relay` with the relay's own [`PrincipalConfig`]. Subscribes to the
    /// relay's endpoint (replacing any earlier subscriber) and spawns the dispatcher, so it
    /// must be called inside a tokio runtime.
    pub fn new(relay: &Relay) -> Self {
        Self::with_config(relay, relay.principal_config())
    }

    /// [`Self::new`] with `config` instead of the relay's.
    pub fn with_config(relay: &Relay, config: PrincipalConfig) -> Self {
        let shared = Arc::new(Shared {
            relay: relay.clone(),
            relay_id: relay.relay_id(),
            config,
            state: Mutex::new(State::default()),
            #[cfg(test)]
            ends: Mutex::new(Vec::new()),
        });
        let mut inbound = relay.endpoint().subscribe();
        let weak: Weak<Shared> = Arc::downgrade(&shared);
        let task = tokio::spawn(async move {
            while let Some(frame) = inbound.recv().await {
                let Some(shared) = weak.upgrade() else {
                    break;
                };
                shared.route(frame);
            }
        });
        Self {
            _guard: Arc::new(Guard {
                shared: Arc::clone(&shared),
                task,
            }),
            shared,
        }
    }

    /// The figures in force.
    pub fn config(&self) -> PrincipalConfig {
        self.shared.config
    }

    /// Why the sessions that have ended ended, as `Debug` text (tests only).
    #[cfg(test)]
    pub(crate) fn session_ends(&self) -> Vec<String> {
        self.shared
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many sessions (handshakes included) exist now.
    pub fn session_count(&self) -> usize {
        self.shared.lock().total
    }

    /// How many sessions (handshakes included) `tenant` has now.
    pub fn tenant_session_count(&self, tenant: &TenantId) -> usize {
        self.shared
            .lock()
            .per_tenant
            .get(tenant)
            .copied()
            .unwrap_or(0)
    }

    /// Opens a stream to `service` on `node` over the L4 session for `(node, network)`,
    /// starting that session (an `init` with `network_id = network`) if there is none. `tenant`
    /// is the tenant of the name the traffic is for: it is charged for the bytes and counts the
    /// session against its cap. `meta` goes into OPEN as given (`target` is always null).
    ///
    /// The returned stream is positioned after OPEN_ACK: what is written goes to the node's
    /// service and what is read comes from it. Dropping it before a clean close resets it.
    pub async fn open(
        &self,
        tenant: &TenantId,
        node: NodeId,
        network: NetworkId,
        service: ServiceId,
        meta: OpenMeta,
    ) -> Result<Stream, PrincipalError> {
        if !matches!(
            service.kind,
            ServiceKind::Tls | ServiceKind::Http | ServiceKind::AcmeHttp | ServiceKind::Tcp
        ) {
            return Err(PrincipalError::ServiceNotAllowed);
        }
        // A session that ends between "found" and "opened" is replaced once.
        let mut retried = false;
        loop {
            let mux = self.session_for(tenant, node, network).await?;
            let _place = self.reserve_stream(tenant)?;
            match self.open_stream(&mux, &service, &meta).await {
                Err(PrincipalError::SessionEnded) if !retried => retried = true,
                other => return other,
            }
        }
    }

    /// Takes a place among the tenant's streams for one being opened: the streams its sessions
    /// hold now plus those other callers are opening must be below the cap. The place is given
    /// back when the open is over (the stream then counts as a live one, or is gone).
    fn reserve_stream(&self, tenant: &TenantId) -> Result<StreamPlace, PrincipalError> {
        let limit = self.shared.config.max_streams_per_tenant;
        let mut state = self.shared.lock();
        let live: usize = state
            .sessions
            .values()
            .filter(|entry| entry.tenant == *tenant)
            .map(|entry| match &*entry.ready.borrow() {
                Phase::Ready(mux) => mux.live_streams(),
                _ => 0,
            })
            .sum();
        let opening = state.opening.get(tenant).copied().unwrap_or(0);
        if live + opening >= limit {
            return Err(PrincipalError::TenantStreamCap { limit });
        }
        *state.opening.entry(tenant.clone()).or_insert(0) += 1;
        Ok(StreamPlace {
            shared: Arc::clone(&self.shared),
            tenant: tenant.clone(),
        })
    }

    /// The mux of the ready session for `(node, network)`, started if need be.
    async fn session_for(
        &self,
        tenant: &TenantId,
        node: NodeId,
        network: NetworkId,
    ) -> Result<StreamMux, PrincipalError> {
        let relay_id = self.shared.relay_id.ok_or(PrincipalError::NoIdentity)?;
        let mut ready = {
            let mut state = self.shared.lock();
            let attached = self
                .shared
                .relay
                .attached_node(&node)
                .ok_or(PrincipalError::NotAttached)?;
            let key = (node, network);
            let existing = state
                .sessions
                .get(&key)
                .map(|entry| (entry.index, entry.l3_session, entry.tenant.clone()));
            match existing {
                Some((_, l3_session, held)) if l3_session == attached.session_id => {
                    if held != *tenant {
                        return Err(PrincipalError::TenantMismatch);
                    }
                    state.sessions[&key].ready.clone()
                }
                other => {
                    // A session pinned to an older L3 session of the node is over.
                    if let Some((index, _, _)) = other {
                        state.remove(&key, index);
                    }
                    self.start_session(&mut state, tenant, key, relay_id, attached)?
                }
            }
        };
        loop {
            let phase = ready.borrow_and_update().clone();
            match phase {
                Phase::Ready(mux) => return Ok(mux),
                Phase::Failed(error) => return Err(error),
                Phase::Handshaking => {}
            }
            if ready.changed().await.is_err() {
                return Err(PrincipalError::SessionEnded);
            }
        }
    }

    /// Takes a place for a new session and spawns its task. Called with the state locked.
    fn start_session(
        &self,
        state: &mut State,
        tenant: &TenantId,
        key: Key,
        relay_id: NodeId,
        attached: crate::relay::AttachedNode,
    ) -> Result<watch::Receiver<Phase>, PrincipalError> {
        let config = self.shared.config;
        if state.total >= config.max_total {
            return Err(PrincipalError::RelayCap {
                limit: config.max_total,
            });
        }
        let held = state.per_tenant.get(tenant).copied().unwrap_or(0);
        if held >= config.max_per_tenant {
            return Err(PrincipalError::TenantCap {
                limit: config.max_per_tenant,
            });
        }
        let index = loop {
            let candidate = fastrand::u32(..);
            if !state.by_index.contains_key(&candidate) {
                break candidate;
            }
        };
        let (frames_tx, frames_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = watch::channel(Phase::Handshaking);
        let (kill_tx, kill_rx) = oneshot::channel();
        state.total += 1;
        *state.per_tenant.entry(tenant.clone()).or_insert(0) += 1;
        state.by_index.insert(
            index,
            Route {
                src: key.0,
                l3_session: attached.session_id,
                tx: frames_tx,
            },
        );
        state.sessions.insert(
            key,
            SessionEntry {
                index,
                tenant: tenant.clone(),
                l3_session: attached.session_id,
                ready: ready_rx.clone(),
                _kill: kill_tx,
            },
        );
        let session = Session {
            shared: Arc::clone(&self.shared),
            key,
            tenant: tenant.clone(),
            index,
            l3_session: attached.session_id,
            node_static: attached.x25519_pub,
            relay_id,
        };
        tokio::spawn(session.run(frames_rx, ready_tx, kill_rx));
        Ok(ready_rx)
    }

    /// OPEN on a fresh yamux stream of `mux`.
    async fn open_stream(
        &self,
        mux: &StreamMux,
        service: &ServiceId,
        meta: &OpenMeta,
    ) -> Result<Stream, PrincipalError> {
        let open_timeout = self.shared.config.open_timeout;
        let mut stream = match tokio::time::timeout(open_timeout, mux.open()).await {
            Err(_) => return Err(PrincipalError::OpenTimeout),
            Ok(Err(StreamMuxError::StreamLimit(_))) => return Err(PrincipalError::StreamLimit),
            Ok(Err(_)) => return Err(PrincipalError::SessionEnded),
            Ok(Ok(stream)) => stream,
        };
        let open = OpenBody {
            v: PROTOCOL_VERSION,
            service: service.clone(),
            // The relay principal never names a target (protocol.md 6.1).
            target: None,
            meta: meta.clone(),
        };
        // A timed out or failed exchange leaves the stream unusable: it is dropped (reset).
        let ack = match tokio::time::timeout(open_timeout, initiate_open(&mut stream, &open)).await
        {
            Err(_) => return Err(PrincipalError::OpenTimeout),
            Ok(Err(OpenError::Io(_))) => return Err(PrincipalError::SessionEnded),
            Ok(Err(OpenError::Encode(error))) => {
                return Err(PrincipalError::Encode(error.to_string()));
            }
            Ok(Err(OpenError::Malformed(error))) => {
                return Err(PrincipalError::Protocol(error.to_string()));
            }
            Ok(Ok(ack)) => ack,
        };
        if !ack.ok {
            return Err(PrincipalError::Refused {
                code: ack.code,
                msg: ack.msg,
            });
        }
        Ok(stream)
    }
}

/// A place among a tenant's streams held while one is being opened; gives it back on drop.
struct StreamPlace {
    shared: Arc<Shared>,
    tenant: TenantId,
}

impl Drop for StreamPlace {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        if let Some(count) = state.opening.get_mut(&self.tenant) {
            *count -= 1;
            if *count == 0 {
                state.opening.remove(&self.tenant);
            }
        }
    }
}

/// Why a session task stopped; for the logs, and for what the waiting callers are told. The
/// payloads are read by the `Debug` line of `Session::run` only.
#[derive(Debug)]
#[allow(dead_code)]
enum End {
    /// The entry was dropped (replaced, or the principal went away).
    Killed,
    /// The node detached or re-attached: the path the session was pinned to is gone.
    PathChanged,
    /// No stream for the idle timeout.
    Idle,
    /// The session reached the age at which a new handshake is due.
    Aged,
    /// Nothing heard from the node for the dead peer time.
    PeerDead,
    /// The node sent CLOSE.
    PeerClosed(ErrorCode),
    /// The yamux driver ended.
    DriverEnded,
    /// yamux refused a record the node sent.
    Feed(StreamMuxError),
    /// An authenticated record broke protocol.md 5.2.
    Decrypt(E2eError),
    /// Our own record could not be encrypted.
    Encrypt(E2eError),
    /// A reliable frame found no room for the whole send wait.
    SendStalled,
    /// The pair could not carry the frame (a droppable outcome for a reliable frame, or an
    /// unknown protocol: neither happens by construction).
    SendFailed(RelaySendOutcome),
    /// The handshake failed or timed out.
    Handshake(PrincipalError),
}

impl End {
    /// What a caller still waiting is told.
    fn error(&self) -> PrincipalError {
        match self {
            Self::Handshake(error) => error.clone(),
            _ => PrincipalError::SessionEnded,
        }
    }
}

struct Session {
    shared: Arc<Shared>,
    key: Key,
    tenant: TenantId,
    index: u32,
    l3_session: u32,
    node_static: X25519PublicKey,
    relay_id: NodeId,
}

/// The state of an established session that the loop and its helpers share.
struct Live {
    transport: E2eTransport,
    liveness: Liveness,
    rekey: RekeySchedule,
    /// An encrypted frame that found no room yet, with when it first waited. While it is held
    /// nothing else is encrypted (the counters are consumed in order) and yamux is not read.
    staged: Option<(Vec<u8>, Instant)>,
}

/// What offering one encoded frame to the pair came to.
enum Offered {
    Sent,
    Wait,
    Fatal(End),
}

fn clock_now() -> std::time::Instant {
    Instant::now().into_std()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Session {
    async fn run(
        self,
        mut frames: mpsc::UnboundedReceiver<InboundFrame>,
        ready: watch::Sender<Phase>,
        mut kill: oneshot::Receiver<()>,
    ) {
        let end = tokio::select! {
            biased;
            _ = &mut kill => End::Killed,
            end = self.drive(&mut frames, &ready) => end,
        };
        tracing::debug!(node = %self.key.0, ?end, "principal session ended");
        #[cfg(test)]
        self.shared
            .ends
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(format!("{end:?}"));
        // Places first, so a caller woken by the failure below can start a new session.
        self.shared.lock().remove(&self.key, self.index);
        let _ = ready.send(Phase::Failed(end.error()));
    }

    /// The whole life of the session; returns why it ended.
    async fn drive(
        &self,
        frames: &mut mpsc::UnboundedReceiver<InboundFrame>,
        ready: &watch::Sender<Phase>,
    ) -> End {
        let config = self.shared.config;
        let transport = match self.handshake(frames).await {
            Ok(transport) => transport,
            Err(error) => return End::Handshake(error),
        };
        let max_record = self.shared.relay.limits.max_record;
        let (mux, inbound_streams, mut outbound, driver) =
            menzil_stream::new_with_limits(Mode::Client, max_record, config.mux_limits());
        // The relay serves nothing: a stream the node opens is reset on arrival.
        drop(inbound_streams);
        let mut driver = Box::pin(driver);
        let mut live = Live {
            transport,
            liveness: Liveness::new(clock_now()),
            rekey: RekeySchedule::new(clock_now()),
            staged: None,
        };
        let _ = ready.send(Phase::Ready(mux.clone()));

        let started = Instant::now();
        let mut idle_since: Option<Instant> = None;
        // `interval` panics on a zero period.
        let mut ticker = tokio::time::interval(config.tick.max(Duration::from_millis(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let retry = tokio::time::sleep(SEND_RETRY);
        tokio::pin!(retry);
        loop {
            let step: Result<(), End> = tokio::select! {
                result = &mut driver => {
                    tracing::debug!(?result, "principal yamux driver ended");
                    Err(End::DriverEnded)
                }
                frame = frames.recv() => match frame {
                    Some(frame) => self.on_inbound(&mut live, &mux, frame),
                    None => Err(End::Killed),
                },
                bytes = outbound.next_frame(), if live.staged.is_none() => match bytes {
                    Some(bytes) => self.emit(&mut live, &E2eDataBody::Mux(bytes)),
                    None => Err(End::DriverEnded),
                },
                () = &mut retry, if live.staged.is_some() => {
                    retry.as_mut().reset(Instant::now() + SEND_RETRY);
                    self.retry_staged(&mut live)
                }
                _ = ticker.tick() => {
                    self.on_tick(&mut live, &mux, started, &mut idle_since)
                }
            };
            if let Err(end) = step {
                if matches!(end, End::Idle | End::Aged) {
                    self.close(
                        &mut live,
                        ErrorCode::ShuttingDown,
                        "session ended by the relay",
                    );
                }
                return end;
            }
        }
    }

    /// The L4 handshake: `init` out, `resp` in, and the checks on the `resp`.
    async fn handshake(
        &self,
        frames: &mut mpsc::UnboundedReceiver<InboundFrame>,
    ) -> Result<E2eTransport, PrincipalError> {
        let relay = &self.shared.relay;
        let (node, network) = self.key;
        let (mut handshake, init) = E2eInitiatorHandshake::start(
            &relay.identity.x25519_private,
            &self.node_static,
            network,
            self.relay_id,
            node,
            self.index,
        )
        .map_err(|error| PrincipalError::HandshakeFailed(error.to_string()))?;
        let deadline = Instant::now() + self.shared.config.handshake_timeout;
        let init = init.encode();
        loop {
            if !self.path_intact() {
                return Err(PrincipalError::NotAttached);
            }
            match relay.send_as_relay(
                &self.tenant,
                &node,
                self.l3_session,
                E2E_PROTO_TAG,
                0,
                init.clone(),
            ) {
                RelaySendOutcome::Queued => break,
                RelaySendOutcome::Full | RelaySendOutcome::Throttled => {
                    if Instant::now() >= deadline {
                        return Err(PrincipalError::HandshakeTimeout);
                    }
                    tokio::time::sleep(SEND_RETRY).await;
                }
                RelaySendOutcome::PeerOffline => return Err(PrincipalError::NotAttached),
                RelaySendOutcome::Dropped | RelaySendOutcome::UnknownE2e => {
                    return Err(PrincipalError::HandshakeFailed(
                        "the relay could not send the init".to_string(),
                    ));
                }
            }
        }
        // The first `resp` decides; anything else that arrives before it is not for a pending
        // initiation and is dropped.
        let resp = loop {
            let frame = match tokio::time::timeout_at(deadline, frames.recv()).await {
                Err(_) => return Err(PrincipalError::HandshakeTimeout),
                Ok(None) => return Err(PrincipalError::SessionEnded),
                Ok(Some(frame)) => frame,
            };
            if let Ok(resp @ E2eFrame::Resp { .. }) = E2eFrame::decode(&frame.payload) {
                break resp;
            }
        };
        let (transport, payload, responder_static) = handshake
            .finish(&resp, relay.limits.max_record)
            .map_err(|error| PrincipalError::HandshakeFailed(error.to_string()))?;
        let fail = |what: &str| Err(PrincipalError::HandshakeFailed(what.to_string()));
        if responder_static != self.node_static {
            return fail("the negotiated key is not the node's attached key");
        }
        if !payload.e2e_protos.contains(&E2E_PROTO_TAG) {
            return fail("the node does not speak this L4 protocol");
        }
        if payload.docs_only {
            return fail("the node offered a documents only session");
        }
        let Ok(body) = payload.node_cert.decode() else {
            return fail("the node's certificate does not decode");
        };
        let Ok(verifying_key) = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id)) else {
            return fail("the node's certificate names no valid key");
        };
        if payload.node_cert.verify(&verifying_key).is_err() || !body.is_valid_at(unix_now()) {
            return fail("the node's certificate does not verify");
        }
        if body.node_id != node || body.x25519_pub != responder_static {
            return fail("the node's certificate is not for the node and key dialed");
        }
        Ok(transport)
    }

    /// Whether the node is still attached by the L3 session this one is pinned to.
    fn path_intact(&self) -> bool {
        self.shared
            .relay
            .attached_node(&self.key.0)
            .is_some_and(|attached| attached.session_id == self.l3_session)
    }

    /// One frame the dispatcher routed here.
    fn on_inbound(&self, live: &mut Live, mux: &StreamMux, frame: InboundFrame) -> Result<(), End> {
        let Ok(E2eFrame::Data {
            receiver_index,
            counter,
            ciphertext,
        }) = E2eFrame::decode(&frame.payload)
        else {
            // Not a `data` for a live session: dropped.
            return Ok(());
        };
        if receiver_index != self.index {
            return Ok(());
        }
        match live.transport.decrypt_data(counter, &ciphertext) {
            Ok(body) => {
                live.liveness.note_received(clock_now());
                match body {
                    E2eDataBody::Mux(bytes) => {
                        // The frame is the guard: its credit goes back to the node once yamux
                        // has read the record.
                        mux.feed_inbound_guarded(bytes, Box::new(frame))
                            .map_err(End::Feed)
                    }
                    E2eDataBody::Close { code, msg } => {
                        tracing::debug!(?code, %msg, "the node closed the principal session");
                        Err(End::PeerClosed(code))
                    }
                    E2eDataBody::Keep | E2eDataBody::Rekey | E2eDataBody::Dgram { .. } => Ok(()),
                }
            }
            // Unauthenticated or corrupt: only the sender of a genuine record may end a
            // session, so this is dropped (menzil_e2e::transport).
            Err(E2eError::UnauthenticatedDatagramCounter | E2eError::Noise(_)) => Ok(()),
            Err(error) => Err(End::Decrypt(error)),
        }
    }

    /// Encrypts `body` as the next record and offers it to the pair; a refusal for want of room
    /// stages it. Only called with nothing staged.
    fn emit(&self, live: &mut Live, body: &E2eDataBody) -> Result<(), End> {
        debug_assert!(live.staged.is_none());
        let frame = live.transport.encrypt_data(body).map_err(End::Encrypt)?;
        let bytes = frame.encode();
        match self.offer(&bytes) {
            Offered::Sent => {
                live.liveness.note_sent(clock_now());
                live.rekey.note_sent();
                Ok(())
            }
            Offered::Wait => {
                live.staged = Some((bytes, Instant::now()));
                Ok(())
            }
            Offered::Fatal(end) => Err(end),
        }
    }

    /// Offers the staged frame again; the session ends if it has waited for the whole send wait.
    fn retry_staged(&self, live: &mut Live) -> Result<(), End> {
        let Some((bytes, since)) = live.staged.take() else {
            return Ok(());
        };
        match self.offer(&bytes) {
            Offered::Sent => {
                live.liveness.note_sent(clock_now());
                live.rekey.note_sent();
                Ok(())
            }
            Offered::Wait => {
                if since.elapsed() >= self.shared.config.send_wait {
                    return Err(End::SendStalled);
                }
                live.staged = Some((bytes, since));
                Ok(())
            }
            Offered::Fatal(end) => Err(end),
        }
    }

    /// One reliable frame to the node through the relay's pair, charged to the tenant. The path
    /// is checked first, so a frame of this session never goes out over another L3 session.
    fn offer(&self, bytes: &[u8]) -> Offered {
        if !self.path_intact() {
            return Offered::Fatal(End::PathChanged);
        }
        match self.shared.relay.send_as_relay(
            &self.tenant,
            &self.key.0,
            self.l3_session,
            E2E_PROTO_TAG,
            0,
            bytes.to_vec(),
        ) {
            RelaySendOutcome::Queued => Offered::Sent,
            RelaySendOutcome::Full | RelaySendOutcome::Throttled => Offered::Wait,
            RelaySendOutcome::PeerOffline => Offered::Fatal(End::PathChanged),
            other @ (RelaySendOutcome::Dropped | RelaySendOutcome::UnknownE2e) => {
                Offered::Fatal(End::SendFailed(other))
            }
        }
    }

    /// A best effort CLOSE: no waiting, no retry, nothing staged.
    fn close(&self, live: &mut Live, code: ErrorCode, msg: &str) {
        if live.staged.is_some() {
            return;
        }
        let body = E2eDataBody::Close {
            code,
            msg: msg.to_string(),
        };
        if let Ok(frame) = live.transport.encrypt_data(&body) {
            let _ = self.offer(&frame.encode());
        }
    }

    /// The timers: path pin, age, idle, dead peer, REKEY and KEEP.
    fn on_tick(
        &self,
        live: &mut Live,
        mux: &StreamMux,
        started: Instant,
        idle_since: &mut Option<Instant>,
    ) -> Result<(), End> {
        let config = self.shared.config;
        let now = Instant::now();
        if !self.path_intact() {
            return Err(End::PathChanged);
        }
        if now.saturating_duration_since(started) >= config.max_session_age {
            return Err(End::Aged);
        }
        if mux.live_streams() == 0 {
            let since = *idle_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= config.idle_timeout {
                return Err(End::Idle);
            }
        } else {
            *idle_since = None;
        }
        let std_now = clock_now();
        if live.liveness.is_dead(std_now) {
            return Err(End::PeerDead);
        }
        if live.staged.is_some() {
            return Ok(());
        }
        if live.rekey.due(std_now) {
            self.emit(live, &E2eDataBody::Rekey)?;
            live.rekey.note_rekeyed(std_now);
        } else if live.liveness.should_send_keep(std_now) {
            self.emit(live, &E2eDataBody::Keep)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
