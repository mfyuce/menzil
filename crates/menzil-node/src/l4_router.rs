//! The L4 frame demux and handshake orchestration (protocol.md 5.1, 5.2;
//! TODO.md L4h6): the one place that turns the L3 layer's epoch-tagged
//! `RECV`s into L4 sessions, and callers' wishes for a session to a peer
//! into handshakes. It joins L4h1 ([`SessionEvent`]s and epoch-tagged
//! sends), L4h2 (the admission checks), L4h3 (one actor per session) and
//! L4e1 (`menzil-e2e`'s [`SessionTable`]: indices, the simultaneous-open
//! tie-break, replacement, the 10-per-minute handshake limit) and adds the
//! orchestration none of them has.
//!
//! **Two layers.** [`Engine`] is where every decision lives and every
//! branch is tested: synchronous, no `await`, driven one input at a time
//! (an L3 event, a caller's request, a session actor's notice, the clock).
//! It sends frames and spawns session actors directly (both non-blocking:
//! a `try_send` and a `tokio::spawn`), so it needs a runtime but never
//! waits on one. [`new_router`] wraps it in the thin task that feeds it
//! from its four sources. Nothing here owns a socket; the L3 session
//! ([`crate::run_session`]) stays the only thing that does.
//!
//! **What the router does with each L3 `RECV`** (protocol.md 4.2, 5.1):
//!
//! * Anything that is not `e2e_proto` 0x01 is not ours and is passed on
//!   untouched ([`RouterParts::passthrough`]); a 0x01 record with the
//!   droppable flag set is dropped (the datagram class is phase 2);
//!   anything that does not decode as an `E2eFrame` is dropped.
//! * `init`: first, an `init` that repeats byte for byte the one that
//!   created the slot's candidate or current session is dropped (a peer
//!   never repeats an `init`; only a relay can, and answering the copy
//!   would leave the initiator with a session the responder no longer
//!   routes). Then the cheap decision ([`SessionTable::on_inbound_init`]:
//!   self, the rate limit, the simultaneous-open tie-break, the table
//!   being full), then, only if we hold the network's documents, the
//!   responder handshake, then L4h2's checks ([`decide_responder_admission`]),
//!   then a reserved index, `resp`, and a session actor installed as a
//!   *candidate*. A failed check answers nothing at all (L4h2's judgment
//!   call 1); a member with no grant gets the handshake and then CLOSE
//!   `no_grant` (protocol.md 5.1) from an actor that is never installed,
//!   so it cannot displace a session or abandon an initiation of ours. An
//!   `init` claiming to come from the attached relay's own NodeId is
//!   refused outright, and so is asking for a session with it: the relay
//!   principal (protocol.md 6.1) has no network, no Policy and no
//!   certificate to check it against, and what an `expose` session with it
//!   will be is TOBEDECIDED item 8.
//! * `resp`: matched to our pending initiation by the echoed index and the
//!   RECV source, then the initiator handshake, L4h2's checks
//!   ([`decide_initiator_admission`]) and a check that the responder
//!   offers the one `e2e_proto` we speak (protocol.md 9: downgrade is
//!   detected, not assumed away), then the session actor is installed as
//!   `current` and whoever waited is told.
//! * `data`: routed by `receiver_index` and refused unless the RECV source
//!   is the session's peer (protocol.md 5.1: "dialed NodeId, RECV source
//!   and prologue must agree"). Delivered in the order received, which is
//!   the order [`L4SessionHandle::feed_inbound`] requires.
//!
//! **Asking for a session** ([`RouterHandle::ensure_session`]): a session
//! to that peer in that network that is already `current` is returned at
//! once; if one is being established (our own `init` is out, or the peer's
//! `init` created a candidate that has not yet seen a record) the caller
//! waits for it, so any number of concurrent callers share one handshake;
//! otherwise the router resolves the peer's cert from our own Policy
//! ([`resolve_dial_cert`]), reserves an index and sends `init`. If no
//! `resp` arrives within the table's `pending_timeout` the `init` is sent
//! again, fresh (a new index and a new ephemeral key, not a retransmission:
//! the responder keeps no replay protection to make a retransmission
//! safe to reason about), up to [`HANDSHAKE_ATTEMPTS`] times in all, and
//! then the waiters are told `Timeout`. protocol.md names neither the
//! timeout nor the retry, and ERROR `peer_offline` carries no destination,
//! so a timeout is the only failure signal there is (TODO.md L4h6's own
//! flag).
//!
//! **Epochs** (protocol.md 5.1's path pinning). A session belongs to the L3
//! attachment it was opened under: on [`SessionEvent::Detached`] every
//! session of that epoch is dropped from the table (dropping its entry
//! drops the `epoch_ended` sender the actor watches, which ends it as
//! `EpochEnded`), every pending initiation is abandoned and every waiter is
//! told `Detached`. Nothing carries over to the next attachment; the next
//! [`RouterHandle::ensure_session`] starts a fresh handshake, which a peer
//! that still holds the old session treats as a replacement.
//!
//! **A replacement keeps the old session until the new one proves itself**
//! (protocol.md 5.1) on the responder side: a session created by a peer's
//! `init` is a candidate, receives like any session, and is promoted to
//! `current` only when the first record on it authenticates, which the
//! actor reports as [`SessionNotice::FirstRecord`]; the old `current` is
//! then closed. On the initiator side the new session is `current` the
//! moment its `resp` authenticates and the old one is closed at once (the
//! one place the table takes a side on TOBEDECIDED item 6; see
//! `menzil-e2e`'s `table` docs).
//!
//! **Not paced** (TODO.md L4h6b): [`L4SessionHandle::feed_inbound`] is
//! unbounded, so a peer that floods a session while we are slow to read it
//! makes this node buffer without limit; see that line and `menzil-stream`'s
//! `record_io` docs for why a simple byte cap at this layer would misfire.
//! Everything else here is bounded: the table by its entry cap, handshakes
//! by the per-peer limit, unproven state by timeouts, waiters by their own
//! deadline.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use menzil_e2e::{
    E2eInitiatorHandshake, E2eResponderHandshake, IgnoreReason, InitDecision, Promoted,
    RegisterError, Removed, RespLookup, Role, Route, SessionIndex, SessionTable, SlotState,
    TableConfig,
};
use menzil_proto::{E2eFrame, ErrorCode, Limits, NetworkId, NodeId, ProtoError, Record};
use menzil_stream::Mode;
use tokio::sync::{mpsc, oneshot, watch};

use crate::admission::{
    HandshakeAdmission, InitiatorAdmission, decide_initiator_admission, decide_responder_admission,
    resolve_dial_cert,
};
use crate::identity::LocalIdentity;
use crate::l4_session::{
    CloseReason, E2E_PROTO_TAG, L4SessionAcceptor, L4SessionConfig, L4SessionHandle, SessionNotice,
    SessionObserver, new as new_l4_session,
};
use crate::outbound::{Epoch, OutboundSend, SendBudgets};
use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;
use crate::session::SessionEvent;

/// How many `init`s are sent for one [`RouterHandle::ensure_session`]
/// before its waiters are told [`EnsureError::Timeout`]: the first and two
/// retries. This project's own choice (protocol.md names none).
pub const HANDSHAKE_ATTEMPTS: u32 = 3;

/// How often the router checks the table's timeouts. The shortest of them
/// is 10 s, so this granularity costs nothing observable.
const TICK: std::time::Duration = std::time::Duration::from_secs(1);

/// How many non-L4 events may wait for [`RouterParts::passthrough`]'s
/// reader before further ones are dropped.
const PASSTHROUGH_CAPACITY: usize = 64;

/// How many [`RouterHandle::ensure_session`] calls may be waiting to be
/// taken up by the router task at once.
const COMMAND_CAPACITY: usize = 64;

/// How many handshake frames the router keeps for a later try when the
/// outbound channel is full (see [`Engine::send`]). Past this the oldest is
/// dropped: its handshake's own timeout and retry cover it.
const MAX_UNSENT: usize = 32;

/// Lets a log line through at most once a second and counts what it held
/// back, so that a peer who can make the router refuse something at link
/// speed cannot make it write a line each time.
struct LogThrottle {
    last: Option<Instant>,
    held_back: u64,
}

impl LogThrottle {
    const INTERVAL: Duration = Duration::from_secs(1);

    fn new() -> Self {
        Self {
            last: None,
            held_back: 0,
        }
    }

    /// `Some(n)` if a line may be written now, `n` being how many were held
    /// back since the last one; `None` if this one is held back.
    fn allow(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < Self::INTERVAL => {
                self.held_back += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.held_back))
            }
        }
    }
}

/// Why [`RouterHandle::ensure_session`] gave no session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnsureError {
    /// No L3 attachment right now: there is nothing to send an `init`
    /// over.
    #[error("not attached to a relay")]
    NotAttached,
    /// Our own Policy and Roster give no cert to dial that peer with in
    /// that network: not a member, revoked, below the serial floor, or the
    /// network is not held (see [`resolve_dial_cert`]).
    #[error("no valid cert for that peer in that network")]
    UnknownPeer,
    /// The peer is this node.
    #[error("cannot open a session to ourselves")]
    SelfPeer,
    /// This node is not a member in good standing of that network by its
    /// own documents (not listed, revoked, below the serial floor, or the
    /// documents have expired), so it does not dial out; the responder side
    /// refuses in the same position (protocol.md 5.1: both parties must be
    /// unrevoked members).
    #[error("this node is not a member in good standing of that network")]
    NotAMember,
    /// The session table is full.
    #[error("the session table is full")]
    TableFull,
    /// No `resp` arrived after [`HANDSHAKE_ATTEMPTS`] tries.
    #[error("the peer did not answer")]
    Timeout,
    /// The handshake finished or the peer answered, but a check failed: a
    /// `resp` that did not decrypt, a cert or membership check
    /// ([`decide_initiator_admission`]), or a peer that does not speak our
    /// `e2e_proto`. Why is logged, never returned: see L4h2's judgment
    /// call 1.
    #[error("the handshake was refused")]
    Refused,
    /// The L3 attachment ended while the caller waited.
    #[error("the relay session ended while waiting")]
    Detached,
    /// The session the caller was waiting for ended before it came up.
    #[error("the session ended before it came up")]
    SessionEnded,
    /// The router task is gone.
    #[error("the L4 router is not running")]
    RouterGone,
}

/// A session that came up, for whoever serves its streams (TODO.md L4h7):
/// the handle to open streams on, and the acceptor to accept the peer's
/// (L4h4's `accept_loop`).
pub struct SessionReady {
    /// The peer.
    pub peer: NodeId,
    /// The network its authorization is scoped to.
    pub network_id: NetworkId,
    /// Which side of the handshake this node was.
    pub role: Role,
    /// The L3 attachment the session is pinned to.
    pub epoch: Epoch,
    /// To open streams and to close.
    pub handle: L4SessionHandle,
    /// To accept the streams the peer opens and to learn why the session
    /// ended.
    pub acceptor: L4SessionAcceptor,
    /// The peer's `roster_seq` from its handshake payload. Only the
    /// initiator learns it: message 1 carries no payload (protocol.md
    /// 5.1), so a responder-side session has `None`. For `menzil:docs`
    /// (TODO.md L4j).
    pub peer_roster_seq: Option<u64>,
    /// As [`Self::peer_roster_seq`], for the Policy.
    pub peer_policy_seq: Option<u64>,
}

impl std::fmt::Debug for SessionReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionReady")
            .field("peer", &self.peer)
            .field("network_id", &self.network_id)
            .field("role", &self.role)
            .field("epoch", &self.epoch)
            .field("peer_roster_seq", &self.peer_roster_seq)
            .field("peer_policy_seq", &self.peer_policy_seq)
            .finish_non_exhaustive()
    }
}

/// What a [`Router`](RouterParts) needs from its owner.
pub struct RouterConfig {
    identity: LocalIdentity,
    local_node_id: NodeId,
    local_cert_serial: u32,
    relay_node_id: NodeId,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    budgets: SendBudgets,
    table: TableConfig,
}

impl RouterConfig {
    /// `identity` is this node's own (its cert says who it is);
    /// `relay_node_id` is the relay it is attached to, whose `init`s are
    /// refused; `policies`/`rosters` are the stores the admission checks
    /// read; `budgets` is the node's one [`SendBudgets`], from which every
    /// session to a peer takes `for_peer(peer)`. Fails only if the local
    /// cert does not decode.
    pub fn new(
        identity: LocalIdentity,
        relay_node_id: NodeId,
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        budgets: SendBudgets,
    ) -> Result<Self, ProtoError> {
        let body = identity.node_cert.decode()?;
        Ok(Self {
            local_node_id: body.node_id,
            local_cert_serial: body.serial,
            identity,
            relay_node_id,
            policies,
            rosters,
            budgets,
            table: TableConfig::default(),
        })
    }

    /// Replaces the session table's limits and timeouts (the defaults are
    /// `menzil_e2e::TableConfig::default()`).
    pub fn with_table_config(mut self, table: TableConfig) -> Self {
        self.table = table;
        self
    }
}

/// Asks the router for sessions. Cheap to clone.
#[derive(Clone)]
pub struct RouterHandle {
    commands: mpsc::Sender<Command>,
}

impl RouterHandle {
    /// A session to `peer` in `network_id`: the one that is already up, or
    /// the one that comes up from a handshake this call starts or joins.
    /// See this module's docs.
    pub async fn ensure_session(
        &self,
        peer: NodeId,
        network_id: NetworkId,
    ) -> Result<L4SessionHandle, EnsureError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Ensure {
                peer,
                network_id,
                reply,
            })
            .await
            .map_err(|_| EnsureError::RouterGone)?;
        answer.await.map_err(|_| EnsureError::RouterGone)?
    }
}

/// Everything [`new_router`] hands back.
pub struct RouterParts {
    /// To ask for sessions.
    pub handle: RouterHandle,
    /// Every session that comes up, from either side, in the order they do.
    pub ready: mpsc::UnboundedReceiver<SessionReady>,
    /// The events the router did not consume: every L3 record that is not
    /// an L4 `RECV` (ADVERTISE_ACK, ADMIT_*, ERROR, ...), a `RECV` with
    /// another `e2e_proto`, and a copy of every `Attached` and `Detached`.
    /// Bounded; when its reader falls behind, further events are dropped
    /// (with a warning), never the router stalled.
    pub passthrough: mpsc::Receiver<SessionEvent>,
    /// The epoch the router is attached under right now, `None` between
    /// attachments. Updated as the router handles `Attached` and
    /// `Detached`, so a caller that wants to wait for the relay can wait
    /// on this instead of reading `passthrough`.
    pub attachment: watch::Receiver<Option<Epoch>>,
    /// The router itself: spawn it. It ends when `events` closes.
    pub task: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

/// Builds a router over `events` (what [`crate::run_session`] delivers)
/// and `outbound` (what it takes), which must be that same call's
/// channels. The router takes over reading `events`; anything else that
/// needed them reads [`RouterParts::passthrough`] instead.
pub fn new_router(
    config: RouterConfig,
    outbound: mpsc::Sender<OutboundSend>,
    events: mpsc::Receiver<SessionEvent>,
) -> RouterParts {
    let (commands_tx, commands_rx) = mpsc::channel(COMMAND_CAPACITY);
    let (ready_tx, ready) = mpsc::unbounded_channel();
    let (passthrough_tx, passthrough) = mpsc::channel(PASSTHROUGH_CAPACITY);
    let (notices_tx, notices_rx) = mpsc::unbounded_channel();
    let (attachment_tx, attachment) = watch::channel(None);
    let engine = Engine::new(
        config,
        outbound,
        ready_tx,
        notices_tx,
        attachment_tx,
        || fastrand::u32(..),
    );
    let task = Box::pin(run_router(
        engine,
        events,
        commands_rx,
        notices_rx,
        passthrough_tx,
    ));
    RouterParts {
        handle: RouterHandle {
            commands: commands_tx,
        },
        ready,
        passthrough,
        attachment,
        task,
    }
}

enum Command {
    Ensure {
        peer: NodeId,
        network_id: NetworkId,
        reply: oneshot::Sender<Result<L4SessionHandle, EnsureError>>,
    },
}

/// The wall and monotonic clocks as one value, so the engine takes the
/// time as a parameter and a test supplies its own.
#[derive(Clone, Copy)]
struct Now {
    instant: Instant,
    unix: u64,
}

impl Now {
    fn capture() -> Self {
        Self {
            // tokio's clock rather than `Instant::now()`: identical
            // outside a test and following the virtual clock inside one
            // that pauses it.
            instant: tokio::time::Instant::now().into_std(),
            unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

type SessionTask = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
type Waiter = oneshot::Sender<Result<L4SessionHandle, EnsureError>>;

/// A caller waiting for a session, and when it gives up.
struct Waiting {
    reply: Waiter,
    deadline: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Attached {
    epoch: Epoch,
    limits: Limits,
}

/// How a session came to be.
enum Origin {
    /// We sent the `init`.
    Initiated,
    /// The peer's `init` created it. That `init`'s `sender_index` and Noise
    /// message are kept, to tell a repeat of it from a new one (see
    /// [`Engine::is_repeated_init`]).
    Answered {
        sender_index: u32,
        noise_msg1: Vec<u8>,
    },
}

/// What the table routes `data` to.
struct Entry {
    handle: L4SessionHandle,
    peer: NodeId,
    network: NetworkId,
    epoch: Epoch,
    /// Tells a late notice from a session whose index has since been
    /// reused from the new one's: see [`tag_of`].
    generation: u32,
    /// For a session an `init` of the peer's created: that `init`'s
    /// `sender_index` and Noise message, to tell a repeat of it from a new
    /// one (see [`Engine::is_repeated_init`]). `None` for one we initiated.
    init: Option<(u32, Vec<u8>)>,
    /// Dropped with the entry, which is what ends the actor as
    /// `EpochEnded` (the actor treats a closed sender like a message).
    _epoch_ended: oneshot::Sender<()>,
}

/// What an `init` of ours that is out keeps for when its `resp` comes, or
/// when it does not.
struct Pending {
    hs: E2eInitiatorHandshake,
    peer: NodeId,
    network: NetworkId,
    attempt: u32,
    epoch: Epoch,
}

fn tag_of(generation: u32, index: SessionIndex) -> u64 {
    (u64::from(generation) << 32) | u64::from(index)
}

fn untag(tag: u64) -> (u32, SessionIndex) {
    ((tag >> 32) as u32, (tag & 0xffff_ffff) as u32)
}

/// Every decision in this module. See the module docs.
struct Engine {
    identity: LocalIdentity,
    local_node_id: NodeId,
    local_cert_serial: u32,
    relay_node_id: NodeId,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    budgets: SendBudgets,
    table: SessionTable<Entry, Pending>,
    waiters: HashMap<(NodeId, NetworkId), Vec<Waiting>>,
    /// How long a caller waits at most: the whole retry chain.
    waiter_timeout: Duration,
    attached: Option<Attached>,
    outbound: mpsc::Sender<OutboundSend>,
    ready: mpsc::UnboundedSender<SessionReady>,
    notices: mpsc::UnboundedSender<(u64, SessionNotice)>,
    /// Mirrors `attached`'s epoch for [`RouterParts::attachment`].
    attachment: watch::Sender<Option<Epoch>>,
    /// Handshake frames the outbound channel had no room for, oldest first.
    unsent: VecDeque<OutboundSend>,
    /// For the line about refused `init`s.
    refused_log: LogThrottle,
    next_generation: u32,
}

impl Engine {
    /// `index_source` supplies candidate session indices: random in
    /// production, fixed in the one test that needs an index to be reused.
    /// An index is only a routing label here (every frame is authenticated,
    /// and `data` is accepted only from the session's own peer), so
    /// randomness is not what protects a session; it keeps a stale frame
    /// addressed to an earlier session from being routed to a new one, and
    /// keeps the index from counting this node's sessions (see
    /// `menzil-e2e`'s `table`).
    fn new(
        config: RouterConfig,
        outbound: mpsc::Sender<OutboundSend>,
        ready: mpsc::UnboundedSender<SessionReady>,
        notices: mpsc::UnboundedSender<(u64, SessionNotice)>,
        attachment: watch::Sender<Option<Epoch>>,
        index_source: impl FnMut() -> u32 + Send + 'static,
    ) -> Self {
        let waiter_timeout = config.table.pending_timeout * HANDSHAKE_ATTEMPTS;
        Self {
            identity: config.identity,
            local_node_id: config.local_node_id,
            local_cert_serial: config.local_cert_serial,
            relay_node_id: config.relay_node_id,
            policies: config.policies,
            rosters: config.rosters,
            budgets: config.budgets,
            table: SessionTable::new(config.local_node_id, config.table, index_source),
            waiters: HashMap::new(),
            waiter_timeout,
            attached: None,
            outbound,
            ready,
            notices,
            attachment,
            unsent: VecDeque::new(),
            refused_log: LogThrottle::new(),
            next_generation: 1,
        }
    }

    // ------------------------------------------------------------------
    // L3 events
    // ------------------------------------------------------------------

    fn on_attached(&mut self, epoch: Epoch, limits: Limits) {
        self.attached = Some(Attached { epoch, limits });
        self.attachment.send_replace(Some(epoch));
    }

    fn on_detached(&mut self, epoch: Epoch) {
        // `run_session` delivers a `Detached` only for the attachment it
        // belongs to and before the next `Attached`, so this is always the
        // current one; a stale one is still handled as itself rather than
        // allowed to fail the callers of the attachment that is current.
        let current = self.attached.is_some_and(|a| a.epoch == epoch);
        if current {
            self.attached = None;
            self.attachment.send_replace(None);
        }
        // Dropping each entry drops its `epoch_ended` sender, which ends
        // the actor as `EpochEnded`; no CLOSE is worth trying over a dead
        // L3 session.
        drop(self.table.remove_where(|entry| entry.epoch == epoch));
        drop(
            self.table
                .remove_pending_where(|pending| pending.epoch == epoch),
        );
        self.unsent.retain(|request| request.epoch != epoch);
        // Nothing of that epoch is left to wait for.
        if current {
            for (_, waiting) in std::mem::take(&mut self.waiters) {
                for waiter in waiting {
                    let _ = waiter.reply.send(Err(EnsureError::Detached));
                }
            }
        }
    }

    /// Handles one L3 record. Returns it back if it is not for the router.
    fn on_record(&mut self, epoch: Epoch, record: Record, now: Now) -> Option<Record> {
        let Record::Recv {
            src,
            e2e_proto,
            flags,
            payload,
        } = record
        else {
            return Some(record);
        };
        if e2e_proto != E2E_PROTO_TAG {
            return Some(Record::Recv {
                src,
                e2e_proto,
                flags,
                payload,
            });
        }
        if flags & 0x01 != 0 {
            // The droppable (datagram) class: phase 2.
            return None;
        }
        let Some(attached) = self.attached.filter(|a| a.epoch == epoch) else {
            // Not the attachment we are on (a record of one that has
            // already ended can only be stale).
            return None;
        };
        let Ok(frame) = E2eFrame::decode(&payload) else {
            tracing::debug!(%src, "dropped an L4 record that is not an E2eFrame");
            return None;
        };
        match frame {
            E2eFrame::Init {
                sender_index,
                network_id,
                noise_msg1,
            } => self.on_init(attached, src, sender_index, network_id, noise_msg1, now),
            E2eFrame::Resp { .. } => self.on_resp(attached, src, frame, now),
            E2eFrame::Data {
                receiver_index,
                counter,
                ciphertext,
            } => {
                if let Route::Session { handle, .. } = self.table.route(receiver_index, &src) {
                    handle.handle.feed_inbound(counter, ciphertext);
                }
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Responder: an `init` from a peer
    // ------------------------------------------------------------------

    fn on_init(
        &mut self,
        attached: Attached,
        src: NodeId,
        sender_index: u32,
        network_id: NetworkId,
        noise_msg1: Vec<u8>,
        now: Now,
    ) {
        if src == self.relay_node_id {
            tracing::debug!("refused an init from the attached relay's own NodeId");
            return;
        }
        if self.is_repeated_init(&src, &network_id, sender_index, &noise_msg1) {
            tracing::debug!(%src, "ignored a repeated L4 init");
            return;
        }
        match self.table.on_inbound_init(src, network_id, now.instant) {
            InitDecision::Respond { .. } => {}
            InitDecision::Ignore(reason) => {
                // Only worth a line when it is not routine: a rate limited
                // peer is either misbehaving or a bug of ours.
                if matches!(reason, IgnoreReason::RateLimited | IgnoreReason::Full) {
                    if let Some(held_back) = self.refused_log.allow(now.instant) {
                        tracing::warn!(%src, ?reason, held_back, "ignored an L4 init");
                    }
                } else {
                    tracing::debug!(%src, ?reason, "ignored an L4 init");
                }
                return;
            }
        }
        // The cheap part of the checks before the expensive one: a network
        // we hold no documents for cannot admit anyone, and finding that out
        // after the Diffie Hellmans would hand a stranger that work for free.
        let (Some(roster_seq), Some(policy_seq)) = (
            self.rosters.seq(&network_id),
            self.policies.seq(&network_id),
        ) else {
            tracing::debug!(%src, "ignored an L4 init for a network we hold no documents for");
            return;
        };
        let msg1_copy = noise_msg1.clone();
        let init = E2eFrame::Init {
            sender_index,
            network_id,
            noise_msg1,
        };
        let Ok(hs) = E2eResponderHandshake::start(
            &self.identity.x25519_private,
            src,
            self.local_node_id,
            &init,
        ) else {
            tracing::debug!(%src, "ignored an L4 init that did not decrypt");
            return;
        };
        let no_grant = match decide_responder_admission(
            &self.policies,
            &self.rosters,
            &network_id,
            &src,
            hs.initiator_static(),
            &self.local_node_id,
            self.local_cert_serial,
            now.unix,
        ) {
            HandshakeAdmission::Allow => false,
            HandshakeAdmission::AllowNoGrant => true,
            HandshakeAdmission::Refuse { reason } => {
                // Local logs only; nothing goes on the wire (L4h2, judgment
                // call 1).
                tracing::debug!(%src, ?reason, "refused an L4 init");
                return;
            }
        };
        let Ok(index) = self.table.reserve_index(now.instant) else {
            return;
        };
        let Ok((transport, resp)) = hs.finish(
            self.identity.node_cert.clone(),
            roster_seq,
            policy_seq,
            vec![E2E_PROTO_TAG],
            index,
            attached.limits.max_record,
        ) else {
            self.table.release_index(index);
            return;
        };

        if no_grant {
            // protocol.md 5.1: a member with no grant gets the handshake
            // and then CLOSE `no_grant`, and learns nothing further. That
            // session exists only to say so, so it is never installed:
            // installed, it would become the slot's candidate, abandon an
            // initiation of our own that the peer's `init` beat in the
            // tie-break, and answer the callers waiting on it with a
            // session that is closed at once. The index stays reserved
            // until the table takes it back, so no live session is given
            // it meanwhile and the peer's frames for it find nothing.
            let (entry, _acceptor, task) = self.make_session(
                index,
                src,
                network_id,
                Origin::Answered {
                    sender_index,
                    noise_msg1: msg1_copy,
                },
                transport,
                attached,
            );
            self.send(src, attached.epoch, resp.encode());
            tokio::spawn(task);
            entry.handle.close(Some(CloseReason {
                code: ErrorCode::NoGrant,
                msg: "no grant".to_string(),
            }));
            return;
        }

        let (entry, acceptor, task) = self.make_session(
            index,
            src,
            network_id,
            Origin::Answered {
                sender_index,
                noise_msg1: msg1_copy,
            },
            transport,
            attached,
        );
        let handle = entry.handle.clone();
        match self.table.install_session(
            index,
            src,
            network_id,
            Role::Responder,
            entry,
            now.instant,
        ) {
            Ok(installed) => {
                // Our own initiation lost the tie-break: its state is
                // dropped, and whoever waits on it waits on this session
                // instead (their `waiters` entry is keyed by the slot, not
                // by the initiation).
                drop(installed.abandoned);
                if let Some((_, superseded)) = installed.superseded_candidate {
                    superseded.handle.close(None);
                }
            }
            Err((error, _)) => {
                tracing::warn!(%src, ?error, "could not install a responder session");
                return;
            }
        }
        self.send(src, attached.epoch, resp.encode());
        tokio::spawn(task);
        let _ = self.ready.send(SessionReady {
            peer: src,
            network_id,
            role: Role::Responder,
            epoch: attached.epoch,
            handle,
            acceptor,
            peer_roster_seq: None,
            peer_policy_seq: None,
        });
    }

    /// Whether this `init` is, byte for byte, the one that created the
    /// candidate or current session its slot holds. A peer never repeats an
    /// `init` (every attempt has a fresh ephemeral key), so only a relay
    /// that duplicates or replays one can: answering it again would bring
    /// up a second candidate that supersedes the first, and the initiator,
    /// who completed with the first `resp`, would then hold a session the
    /// responder no longer routes. Costs a lookup and a comparison, so it
    /// runs before the rate limit and before any handshake work.
    fn is_repeated_init(
        &self,
        src: &NodeId,
        network: &NetworkId,
        sender_index: u32,
        noise_msg1: &[u8],
    ) -> bool {
        let slot = self.table.slot(src, network);
        [slot.candidate, slot.current]
            .into_iter()
            .flatten()
            .filter_map(|index| self.table.get(index))
            .any(|entry| {
                entry
                    .init
                    .as_ref()
                    .is_some_and(|(index, msg1)| *index == sender_index && msg1 == noise_msg1)
            })
    }

    // ------------------------------------------------------------------
    // Initiator: our own `init`, and the `resp` to it
    // ------------------------------------------------------------------

    fn ensure(&mut self, peer: NodeId, network: NetworkId, reply: Waiter, now: Now) {
        if peer == self.local_node_id {
            let _ = reply.send(Err(EnsureError::SelfPeer));
            return;
        }
        if peer == self.relay_node_id {
            // The relay principal has no network and no cert to dial; what
            // an `expose` session with it will be is TOBEDECIDED item 8.
            // Inbound `init`s from it are refused for the same reason.
            let _ = reply.send(Err(EnsureError::UnknownPeer));
            return;
        }
        let slot = self.table.slot(&peer, &network);
        if let Some(index) = slot.current
            && let Some(entry) = self.table.get(index)
        {
            let _ = reply.send(Ok(entry.handle.clone()));
            return;
        }
        if self.attached.is_none() {
            let _ = reply.send(Err(EnsureError::NotAttached));
            return;
        }
        if slot.pending.is_none()
            && slot.candidate.is_none()
            && let Err(error) = self.begin_initiation(peer, network, 1, now)
        {
            let _ = reply.send(Err(error));
            return;
        }
        self.waiters
            .entry((peer, network))
            .or_default()
            .push(Waiting {
                reply,
                deadline: now.instant + self.waiter_timeout,
            });
    }

    /// Sends one `init` to `peer`. The caller has checked there is no
    /// pending initiation or candidate for the slot.
    fn begin_initiation(
        &mut self,
        peer: NodeId,
        network: NetworkId,
        attempt: u32,
        now: Now,
    ) -> Result<(), EnsureError> {
        let attached = self.attached.ok_or(EnsureError::NotAttached)?;
        if let Err(reason) = self.policies.check_membership(
            &self.rosters,
            &network,
            &self.local_node_id,
            self.local_cert_serial,
            now.unix,
        ) {
            tracing::debug!(
                ?reason,
                "not dialing: this node's own standing check failed"
            );
            // A network we hold no documents for is unknown to the caller,
            // not a question of this node's standing in it.
            return Err(if matches!(reason, ErrorCode::UnknownNetwork) {
                EnsureError::UnknownPeer
            } else {
                EnsureError::NotAMember
            });
        }
        let cert = resolve_dial_cert(&self.policies, &self.rosters, &network, &peer, now.unix)
            .ok_or(EnsureError::UnknownPeer)?;
        let index = self
            .table
            .reserve_index(now.instant)
            .map_err(|_| EnsureError::TableFull)?;
        let (hs, init) = match E2eInitiatorHandshake::start(
            &self.identity.x25519_private,
            &cert.x25519_pub,
            network,
            self.local_node_id,
            peer,
            index,
        ) {
            Ok(started) => started,
            Err(error) => {
                tracing::warn!(%peer, %error, "could not start an L4 handshake");
                self.table.release_index(index);
                return Err(EnsureError::UnknownPeer);
            }
        };
        let pending = Pending {
            hs,
            peer,
            network,
            attempt,
            epoch: attached.epoch,
        };
        match self
            .table
            .register_pending(index, peer, network, pending, now.instant)
        {
            Ok(()) => {
                self.send(peer, attached.epoch, init.encode());
                Ok(())
            }
            // Another initiation or the peer's own candidate got there
            // first; the caller waits for that one.
            Err((RegisterError::AlreadyPending | RegisterError::CandidateExists, _)) => Ok(()),
            Err((RegisterError::SelfPeer, _)) => Err(EnsureError::SelfPeer),
            Err((RegisterError::NotReserved, _)) => Err(EnsureError::TableFull),
        }
    }

    fn on_resp(&mut self, attached: Attached, src: NodeId, resp: E2eFrame, now: Now) {
        let E2eFrame::Resp { receiver_index, .. } = &resp else {
            return;
        };
        let RespLookup::Matched {
            index,
            peer,
            network,
            state,
        } = self
            .table
            .take_pending_for_resp(*receiver_index, &src, now.instant)
        else {
            return;
        };
        let key = (peer, network);
        let (transport, payload, responder_static) =
            match state.hs.finish(&resp, attached.limits.max_record) {
                Ok(finished) => finished,
                Err(error) => {
                    tracing::debug!(%peer, %error, "an L4 resp did not complete the handshake");
                    self.table.release_index(index);
                    self.fail_waiters(&key, EnsureError::Refused);
                    return;
                }
            };
        // protocol.md 9: the supported `e2e_proto` tags travel in the
        // handshake payload so that a downgrade is detected.
        if !payload.e2e_protos.contains(&E2E_PROTO_TAG) {
            tracing::debug!(%peer, "the peer does not speak our L4 protocol");
            self.table.release_index(index);
            self.fail_waiters(&key, EnsureError::Refused);
            return;
        }
        if let InitiatorAdmission::Refuse { reason } = decide_initiator_admission(
            &self.policies,
            &self.rosters,
            &network,
            &peer,
            &responder_static,
            &payload,
            now.unix,
        ) {
            tracing::debug!(%peer, ?reason, "refused an L4 resp");
            self.table.release_index(index);
            self.fail_waiters(&key, EnsureError::Refused);
            return;
        }
        let (entry, acceptor, task) =
            self.make_session(index, peer, network, Origin::Initiated, transport, attached);
        let handle = entry.handle.clone();
        match self
            .table
            .install_session(index, peer, network, Role::Initiator, entry, now.instant)
        {
            Ok(installed) => {
                if let Some((_, replaced)) = installed.replaced {
                    replaced.handle.close(None);
                }
            }
            Err((error, _)) => {
                tracing::warn!(%peer, ?error, "could not install an initiator session");
                self.fail_waiters(&key, EnsureError::Refused);
                return;
            }
        }
        tokio::spawn(task);
        let _ = self.ready.send(SessionReady {
            peer,
            network_id: network,
            role: Role::Initiator,
            epoch: attached.epoch,
            handle: handle.clone(),
            acceptor,
            peer_roster_seq: Some(payload.roster_seq),
            peer_policy_seq: Some(payload.policy_seq),
        });
        self.resolve_waiters(&key, &handle);
    }

    // ------------------------------------------------------------------
    // Sessions' own notices, and the clock
    // ------------------------------------------------------------------

    fn on_notice(&mut self, tag: u64, notice: SessionNotice) {
        let (generation, index) = untag(tag);
        let Some(entry) = self.table.get(index) else {
            return;
        };
        if entry.generation != generation {
            // From a session whose index has since been reused.
            return;
        }
        let key = (entry.peer, entry.network);
        match notice {
            SessionNotice::FirstRecord => {
                let handle = entry.handle.clone();
                if let Some(Promoted { retired }) = self.table.promote(index) {
                    if let Some((_, old)) = retired {
                        old.handle.close(None);
                    }
                    self.resolve_waiters(&key, &handle);
                }
            }
            SessionNotice::Ended => {
                if let Some(Removed::Session { .. }) = self.table.remove(index) {
                    self.fail_orphans(&key);
                }
            }
        }
    }

    fn on_tick(&mut self, now: Now) {
        self.flush_unsent();
        let expired = self.table.expire(now.instant);
        for (_, pending) in expired.pending {
            let key = (pending.peer, pending.network);
            // A caller that stopped listening does not count: it must not
            // keep an initiation going.
            let still_wanted = self
                .waiters
                .get(&key)
                .is_some_and(|waiting| waiting.iter().any(|w| !w.reply.is_closed()));
            let same_attachment = self.attached.is_some_and(|a| a.epoch == pending.epoch);
            if still_wanted && same_attachment && pending.attempt < HANDSHAKE_ATTEMPTS {
                let slot = self.table.slot(&pending.peer, &pending.network);
                if slot.pending.is_none() && slot.candidate.is_none() && slot.current.is_none() {
                    match self.begin_initiation(
                        pending.peer,
                        pending.network,
                        pending.attempt + 1,
                        now,
                    ) {
                        Ok(()) => continue,
                        Err(error) => {
                            self.fail_waiters(&key, error);
                            continue;
                        }
                    }
                }
                // Something else came up for the slot meanwhile; its own
                // events will settle the waiters.
                continue;
            }
            self.fail_waiters(&key, EnsureError::Timeout);
        }
        for (_, candidate) in expired.candidates {
            let key = (candidate.peer, candidate.network);
            candidate.handle.close(None);
            self.fail_orphans(&key);
        }
        // Last, so that when a caller's time is up in the same tick as the
        // thing it waited on, the more telling answer (`SessionEnded`) wins.
        self.expire_waiters(now.instant);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Builds the actor for an established handshake. The caller installs
    /// the returned entry in the table and spawns the task.
    fn make_session(
        &mut self,
        index: SessionIndex,
        peer: NodeId,
        network: NetworkId,
        origin: Origin,
        transport: menzil_e2e::E2eTransport,
        attached: Attached,
    ) -> (Entry, L4SessionAcceptor, SessionTask) {
        let (mode, init) = match origin {
            Origin::Initiated => (Mode::Client, None),
            Origin::Answered {
                sender_index,
                noise_msg1,
            } => (Mode::Server, Some((sender_index, noise_msg1))),
        };
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        let (epoch_ended_tx, epoch_ended_rx) = oneshot::channel();
        let (handle, acceptor, task) = new_l4_session(
            L4SessionConfig {
                transport,
                peer,
                network_id: network,
                mode,
                max_record: attached.limits.max_record,
                epoch: attached.epoch,
                send_budget: self.budgets.for_peer(peer),
                observer: Some(SessionObserver::new(
                    self.notices.clone(),
                    tag_of(generation, index),
                )),
            },
            self.outbound.clone(),
            epoch_ended_rx,
        );
        (
            Entry {
                handle,
                peer,
                network,
                epoch: attached.epoch,
                generation,
                init,
                _epoch_ended: epoch_ended_tx,
            },
            acceptor,
            Box::pin(task),
        )
    }

    /// Sends one L4 frame as an epoch-tagged reliable SEND. Never waits, but
    /// does not lose the frame to a full `outbound` either: the session
    /// actors share that channel, and with bulk transfers running over a
    /// slow link it is full for stretches, so a frame it has no room for
    /// waits in [`Self::unsent`] (behind anything already waiting there, so
    /// frames keep their order) and goes out on a later tick.
    fn send(&mut self, dst: NodeId, epoch: Epoch, payload: Vec<u8>) {
        let (outcome, _) = oneshot::channel();
        let request = OutboundSend {
            dst,
            e2e_proto: E2E_PROTO_TAG,
            flags: 0,
            payload,
            epoch,
            outcome,
            permit: None,
        };
        if !self.unsent.is_empty() {
            self.hold_back(request);
            return;
        }
        match self.outbound.try_send(request) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(request)) => self.hold_back(request),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!(%dst, "the L3 session is gone; an L4 handshake frame is dropped");
            }
        }
    }

    fn hold_back(&mut self, request: OutboundSend) {
        if self.unsent.len() >= MAX_UNSENT {
            self.unsent.pop_front();
            tracing::debug!("dropped the oldest held back L4 handshake frame");
        }
        self.unsent.push_back(request);
    }

    /// Sends the held back frames, oldest first, until the channel is full
    /// again.
    fn flush_unsent(&mut self) {
        while let Some(request) = self.unsent.pop_front() {
            match self.outbound.try_send(request) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(request)) => {
                    self.unsent.push_front(request);
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.unsent.clear();
                    break;
                }
            }
        }
    }

    fn resolve_waiters(&mut self, key: &(NodeId, NetworkId), handle: &L4SessionHandle) {
        for waiter in self.waiters.remove(key).unwrap_or_default() {
            let _ = waiter.reply.send(Ok(handle.clone()));
        }
    }

    fn fail_waiters(&mut self, key: &(NodeId, NetworkId), error: EnsureError) {
        for waiter in self.waiters.remove(key).unwrap_or_default() {
            let _ = waiter.reply.send(Err(error));
        }
    }

    /// Gives up on the callers whose time is up and forgets the ones that
    /// stopped listening. Nothing else bounds a caller that waits on a
    /// candidate: each fresh `init` from the peer (or a relay replaying one)
    /// replaces the candidate and restarts its own timer, so without a
    /// deadline of its own such a caller would wait as long as they kept
    /// coming. A caller that was cancelled must not keep an initiation alive
    /// either.
    fn expire_waiters(&mut self, now: Instant) {
        self.waiters.retain(|_, waiting| {
            let mut kept = Vec::with_capacity(waiting.len());
            for waiter in waiting.drain(..) {
                if waiter.reply.is_closed() {
                    continue;
                }
                if now >= waiter.deadline {
                    let _ = waiter.reply.send(Err(EnsureError::Timeout));
                    continue;
                }
                kept.push(waiter);
            }
            *waiting = kept;
            !waiting.is_empty()
        });
    }

    /// Tells the waiters of a slot that has nothing left that could still
    /// come up.
    fn fail_orphans(&mut self, key: &(NodeId, NetworkId)) {
        if self.table.slot(&key.0, &key.1) == SlotState::default() {
            self.fail_waiters(key, EnsureError::SessionEnded);
        }
    }
}

// ----------------------------------------------------------------------
// The task
// ----------------------------------------------------------------------

async fn run_router(
    mut engine: Engine,
    mut events: mpsc::Receiver<SessionEvent>,
    mut commands: mpsc::Receiver<Command>,
    mut notices: mpsc::UnboundedReceiver<(u64, SessionNotice)>,
    passthrough: mpsc::Sender<SessionEvent>,
) {
    let mut tick = tokio::time::interval(TICK);
    let mut commands_open = true;
    let mut dropped_log = LogThrottle::new();
    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else { break };
                match event {
                    SessionEvent::Attached { epoch, limits } => {
                        engine.on_attached(epoch, limits);
                        forward(&passthrough, SessionEvent::Attached { epoch, limits }, &mut dropped_log);
                    }
                    SessionEvent::Detached { epoch } => {
                        engine.on_detached(epoch);
                        forward(&passthrough, SessionEvent::Detached { epoch }, &mut dropped_log);
                    }
                    SessionEvent::Record { epoch, record } => {
                        if let Some(record) = engine.on_record(epoch, *record, Now::capture()) {
                            forward(&passthrough, SessionEvent::Record { epoch, record: Box::new(record) }, &mut dropped_log);
                        }
                    }
                }
            }
            command = commands.recv(), if commands_open => {
                match command {
                    Some(Command::Ensure { peer, network_id, reply }) => {
                        engine.ensure(peer, network_id, reply, Now::capture());
                    }
                    // Every handle dropped: nobody can ask for a session
                    // any more, but the peers' `init`s still need serving.
                    None => commands_open = false,
                }
            }
            Some((tag, notice)) = notices.recv() => {
                engine.on_notice(tag, notice);
            }
            _ = tick.tick() => {
                engine.on_tick(Now::capture());
            }
        }
    }
}

/// Hands an event the router does not consume to its reader, dropping it
/// (with a warning, at most once a second) rather than waiting if the
/// reader is behind.
fn forward(passthrough: &mpsc::Sender<SessionEvent>, event: SessionEvent, log: &mut LogThrottle) {
    if let Err(error) = passthrough.try_send(event)
        && let Some(held_back) = log.allow(Instant::now())
    {
        tracing::warn!(%error, held_back, "dropped an L3 event nobody was reading");
    }
}

#[cfg(test)]
mod tests;
