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
//!   droppable flag set is read only if its counter is datagram class (`crate::channels`): the
//!   class comes from the counter, and the flag on an `init`, a `resp` or a reliable `data` is
//!   a protocol violation that drops the record (protocol.md 4.2);
//!   anything that does not decode as an `E2eFrame` is dropped.
//! * `init`: first, an `init` that repeats byte for byte the one that
//!   created the slot's candidate or current session is dropped (a peer
//!   never repeats an `init`; only a relay can, and answering the copy
//!   would leave the initiator with a session the responder no longer
//!   routes). Then the cheap decision ([`SessionTable::on_inbound_init`]:
//!   self, the rate limit, the simultaneous-open tie-break, the table
//!   being full), then, only if we hold the network's documents, the
//!   check that the RECV `src` is an unrevoked member in our Roster (before
//!   any Diffie Hellman: a stranger or a revoked member gets silence and
//!   costs nothing), then the responder handshake, then L4h2's checks
//!   ([`decide_responder_admission`]). A failed check answers nothing at
//!   all (L4h2's judgment call 1). A member with no grant gets a normal
//!   session (what it may open is decided per stream, protocol.md 5.3). A
//!   member the Roster lists but the Policy cannot vouch for (no cert for
//!   its key, not listed, or our documents have expired) completes the
//!   handshake with `docs_only: true` and gets a *docs only* session:
//!   installed under [`docs_only_slot`] so it can displace nothing, at most
//!   [`MAX_DOCS_ONLY_SESSIONS`] of them and one per peer, announced on
//!   [`RouterParts::ready`] with [`SessionReady::docs_only`], and ended with
//!   CLOSE `docs_only` after [`DOCS_ONLY_LIFETIME`] (or sooner by whoever
//!   serves its one push). An `init` claiming to come from the attached
//!   relay's own NodeId is the relay principal (protocol.md 6.1, expose design
//!   S-E4) and takes a path of its own, [`Engine::on_relay_init`]: never a
//!   member's checks (the relay is no member), and silence unless the node
//!   holds unexpired documents for the `init`'s network and stands well in them, the
//!   relay accepted a share of this node that the network's Roster grants it, and, after the
//!   handshake's Diffie Hellmans, the initiator's static key is the one the L3 session of
//!   this very attachment negotiated with the relay ([`SessionEvent::Attached`]'s
//!   `relay_static`). Asking for a session *with* the relay is still refused: the node never
//!   dials the relay principal.
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
//! **Inbound data is bounded, not paced** (TODO.md L4h6b). Each session holds
//! at most [`L4_INBOUND_BUDGET_PER_SESSION`] bytes of `data` records that
//! `yamux` has not processed yet (counted from [`L4SessionHandle::feed_inbound`]
//! to the moment `yamux` reads the record, through the actor and through
//! `menzil-stream`'s queue) plus stream data `yamux` has received and the
//! application has not read yet (the same counter, fed by a `BufferMeter`). A record that does not fit ends that session
//! at once ([`Engine::end_overflowed`]): closed with `rate_limited`,
//! removed, nothing else touched. All sessions together hold at most
//! [`L4_INBOUND_CEILING_PER_NODE`] (`RouterConfig::with_inbound_ceiling`): a record that
//! would pass it ends the session holding the most unread data (the arriving one only when it
//! holds the most), closed `rate_limited` too, and is then queued itself. Datagrams are
//! counted apart (`DGRAM_CEILING_PER_NODE`, 64 MiB): past it a datagram is dropped, no
//! session ends and none gives way. The router never waits for a session.
//! Stopping it from reading `events` instead would hold every other peer's
//! traffic behind one session, as often as a member can finish a handshake,
//! and `run_session` reads the relay socket only while no event is waiting,
//! so the relay's PINGs would go unanswered and the node's own liveness
//! clock would stand still; a wait past the 50 s window tears the
//! attachment down, and every session with it, when reading resumes. The
//! budget is sized above the whole receive window we grant a peer, so a peer
//! that respects the windows does not reach it (a peer cutting its data
//! into tiny frames can: each record is charged its overhead). Everything
//! else here is bounded too: the table by its entry cap, handshakes by the
//! per-peer limit, unproven state by timeouts, waiters by their own
//! deadline.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use menzil_e2e::{
    E2eError, E2eInitiatorHandshake, E2eResponderHandshake, IgnoreReason, InitDecision, Poll,
    Promoted, RegisterError, Removed, ReplaceDurations, ReplaceSchedule, RespLookup, Role, Route,
    SessionIndex, SessionTable, SlotState, TableConfig,
};
use menzil_proto::{
    ContinueBody, E2eDataBody, E2eFrame, ErrorCode, Limits, NetworkId, NodeId, ProtoError, Record,
    RecordClass, X25519PublicKey, continue_binding,
};
use menzil_stream::Mode;
use tokio::sync::{mpsc, oneshot, watch};

use crate::admission::{
    HandshakeAdmission, InitiatorAdmission, decide_initiator_admission,
    decide_initiator_admission_for_docs, decide_responder_admission, is_unrevoked_roster_member,
    relay_principal_standing, resolve_dial_cert, resolve_dial_cert_for_docs, session_standing,
};
use crate::identity::IdentityCell;
use crate::l4_session::{
    CloseReason, E2E_PROTO_TAG, FIRST_GENERATION, FeedRefused, Generation, HandoverRole,
    L4_INBOUND_BUDGET_PER_SESSION, L4_INBOUND_CEILING_PER_NODE, L4SessionAcceptor, L4SessionConfig,
    L4SessionHandle, NodeInbound, SessionNotice, SessionObserver, new as new_l4_session,
    new_with_datagrams as new_l4_session_with_datagrams,
};
use crate::outbound::{Epoch, OutboundSend, SendBudgets};
use crate::policy_store::PolicyStore;
use crate::relay_serve::accepted_shares;
use crate::roster_store::RosterStore;
use crate::session::SessionEvent;
use crate::shares::ShareBook;

/// How many `init`s are sent for one [`RouterHandle::ensure_session`]
/// before its waiters are told [`EnsureError::Timeout`]: the first and two
/// retries. This project's own choice (protocol.md names none).
pub const HANDSHAKE_ATTEMPTS: u32 = 3;

/// How often the router checks the table's timeouts. The shortest of them
/// is 10 s, so this granularity costs nothing observable.
const TICK: std::time::Duration = std::time::Duration::from_secs(1);

/// How many docs only sessions this node answers at once, one per peer at most
/// (protocol.md 5.5). An `init` that would be the ninth is not answered.
pub const MAX_DOCS_ONLY_SESSIONS: usize = 8;

/// How long a docs only session may live (protocol.md 5.1): the responder ends it
/// with CLOSE `docs_only` after this, if the push has not ended it sooner. The
/// initiator side keeps the same limit on its end, so that a responder that never
/// closes cannot keep an actor of ours alive.
pub const DOCS_ONLY_LIFETIME: Duration = Duration::from_secs(30);

/// The table slot docs only sessions live in. A docs only session is installed
/// under this network instead of the real one, so that it can neither become the
/// `current` or `candidate` session of the peer's real slot (a relay can forge the
/// `src` of any Roster member, and its `init` would then displace that member's
/// real session) nor abandon an initiation of ours to that peer. All bytes `0xff`
/// is not the encoding of any owner key (a NetworkId is a canonical Ed25519 public
/// key), so no real network shares it.
fn docs_only_slot() -> NetworkId {
    NetworkId::from([0xff; 32])
}

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
    /// The peer completed the handshake but admitted this node for a
    /// `menzil:docs` push only (`docs_only` in its handshake payload, protocol.md
    /// 5.1): it holds no certificate for this node's key, does not list it in its
    /// Policy, or its documents have expired. No session for streams exists; the
    /// docs only session itself is announced on [`RouterParts::ready`] with
    /// [`SessionReady::docs_only`] set, for whoever pushes (TODO.md L4j S6).
    #[error("the peer admitted this node for a documents push only")]
    DocsOnly,
    /// The L3 attachment ended while the caller waited.
    #[error("the relay session ended while waiting")]
    Detached,
    /// The session the caller was waiting for ended before it came up.
    #[error("the session ended before it came up")]
    SessionEnded,
    /// The router task is gone.
    #[error("the L4 router is not running")]
    RouterGone,
    /// [`RouterHandle::stop`] was called: the node is on its way out and
    /// opens no new session.
    #[error("this node is shutting down")]
    ShuttingDown,
}

/// A session that came up, for whoever serves its streams (TODO.md L4h7):
/// the handle to open streams on, and the acceptor to accept the peer's
/// (L4h4's `accept_loop`).
pub struct SessionReady {
    /// The peer.
    pub peer: NodeId,
    /// The network its authorization is scoped to.
    pub network_id: NetworkId,
    /// The peer's Noise static key the session was set up with: the key of the NodeCert in
    /// the Policy that vouches for the session, which [`crate::admission`]'s standing check
    /// looks up again whenever the documents change (L4k).
    pub peer_static: X25519PublicKey,
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
    /// A docs only session (protocol.md 5.1): the responder admitted the initiator
    /// for one `menzil:docs` push only. Such a session is never handed to
    /// [`RouterHandle::ensure_session`] callers, is not in the peer's real slot and
    /// ends at [`DOCS_ONLY_LIFETIME`] at the latest. Serve it with the docs only
    /// rules (the responder), or push on it (the initiator).
    pub docs_only: bool,
    /// The session is the relay principal's (protocol.md 6.1, expose design S-E4): `peer` is
    /// the attached relay's NodeId, `peer_static` the relay's static key, `network_id` the
    /// network of the share it serves. It is never in the member rules: serve it with
    /// [`crate::RelayAuthorizer`]'s rules only (public shares, no documents, no grants).
    pub relay_principal: bool,
}

impl std::fmt::Debug for SessionReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionReady")
            .field("peer", &self.peer)
            .field("network_id", &self.network_id)
            .field("peer_static", &self.peer_static)
            .field("role", &self.role)
            .field("epoch", &self.epoch)
            .field("peer_roster_seq", &self.peer_roster_seq)
            .field("peer_policy_seq", &self.peer_policy_seq)
            .field("docs_only", &self.docs_only)
            .field("relay_principal", &self.relay_principal)
            .finish_non_exhaustive()
    }
}

/// How long a router-held candidate waits for its first reliable record before it is dropped
/// (protocol.md 5.2, re-handshake design section 3). The session table keeps the candidate's
/// index reserved at most for its own `reservation_timeout`; the engine raises that to this.
pub const HELD_CANDIDATE_TIMEOUT: Duration = Duration::from_secs(30);

/// The 24 hour replacement of full sessions (protocol.md 5.2) and the continuation of the
/// streams across it (re-handshake design, slice R3). The defaults are the protocol's; the
/// fields are overridable for tests only (a live test cannot wait a day).
#[derive(Debug, Clone)]
pub struct ReplaceConfig {
    /// The schedule of the chain initiator's replacement `init`s and of the hard age cap both
    /// sides enforce ([`ReplaceDurations::default`]: due at 24 h minus up to 30 min, cap 24 h
    /// 30 min).
    pub durations: ReplaceDurations,
    /// Offer `held` in a `resp` and answer a matching one with CONTINUE. `false` behaves like a
    /// build that predates the continuation: no `held` is offered, a `held` is ignored, the
    /// replacement starts afresh and the streams reset. Test flag.
    pub continuation: bool,
    /// How long a router-held candidate waits for its first reliable record
    /// ([`HELD_CANDIDATE_TIMEOUT`]).
    pub held_timeout: Duration,
}

impl Default for ReplaceConfig {
    fn default() -> Self {
        Self {
            durations: ReplaceDurations::default(),
            continuation: true,
            held_timeout: HELD_CANDIDATE_TIMEOUT,
        }
    }
}

/// What a [`Router`](RouterParts) needs from its owner.
pub struct RouterConfig {
    identity: IdentityCell,
    local_node_id: NodeId,
    local_static: X25519PublicKey,
    relay_node_id: NodeId,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    budgets: SendBudgets,
    table: TableConfig,
    inbound_budget: usize,
    inbound_ceiling: usize,
    shares: ShareBook,
    replace: ReplaceConfig,
}

impl RouterConfig {
    /// `identity` is this node's own (its cert says who it is; given a bare
    /// [`LocalIdentity`](crate::LocalIdentity) it is a cell of its own, given the node's
    /// [`IdentityCell`] the router follows its renewals: the `resp` payload and the serial of
    /// every standing check are read from it at each use);
    /// `relay_node_id` is the relay it is attached to, whose `init`s are the relay principal's
    /// (see [`Engine::on_relay_init`]); `policies`/`rosters` are the stores the admission checks
    /// read; `budgets` is the node's one [`SendBudgets`], from which every
    /// session to a peer takes `for_peer(peer)`. Fails only if the local
    /// cert does not decode.
    pub fn new(
        identity: impl Into<IdentityCell>,
        relay_node_id: NodeId,
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        budgets: SendBudgets,
    ) -> Result<Self, ProtoError> {
        let identity = identity.into();
        let body = identity.get().node_cert.decode()?;
        Ok(Self {
            local_node_id: body.node_id,
            local_static: body.x25519_pub,
            identity,
            relay_node_id,
            policies,
            rosters,
            budgets,
            table: TableConfig::default(),
            inbound_budget: L4_INBOUND_BUDGET_PER_SESSION,
            inbound_ceiling: L4_INBOUND_CEILING_PER_NODE,
            shares: ShareBook::new(),
            replace: ReplaceConfig::default(),
        })
    }

    /// Replaces the figures of the 24 hour replacement and the continuation switch (the
    /// default is [`ReplaceConfig::default`]); for tests, which cannot wait a day.
    pub fn with_replace(mut self, replace: ReplaceConfig) -> Self {
        self.replace = replace;
        self
    }

    /// The node's [`ShareBook`], which the relay principal's `init`s are judged against (expose
    /// design S-E4). The default is an empty book of its own, which accepts no relay `init`.
    pub fn with_shares(mut self, shares: ShareBook) -> Self {
        self.shares = shares;
        self
    }

    /// Replaces the session table's limits and timeouts (the defaults are
    /// `menzil_e2e::TableConfig::default()`).
    pub fn with_table_config(mut self, table: TableConfig) -> Self {
        self.table = table;
        self
    }

    /// Replaces how many bytes of unprocessed inbound records plus unread stream data each
    /// session may hold (the default is [`L4_INBOUND_BUDGET_PER_SESSION`]); a session
    /// past it is ended, see [`L4SessionHandle::feed_inbound`].
    pub fn with_inbound_budget(mut self, bytes: usize) -> Self {
        self.inbound_budget = bytes;
        self
    }

    /// Replaces how many bytes of unprocessed inbound records plus unread stream data all
    /// sessions may hold together (the
    /// default is [`L4_INBOUND_CEILING_PER_NODE`], TBD 75): past it the session holding the
    /// most gives way. The per session budget is clamped to it, so one honest session never
    /// meets the node ceiling before its own.
    pub fn with_inbound_ceiling(mut self, bytes: usize) -> Self {
        self.inbound_ceiling = clamp_ceiling(bytes);
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
        self.ensure_with(peer, network_id, false).await
    }

    /// [`Self::ensure_session`] for a dial whose purpose is `menzil:docs` (to fetch newer
    /// documents): a node whose own documents have expired may dial with them, only the expiry
    /// part of the standing checks is relaxed (TOBEDECIDED 25). Every other use of a session
    /// keeps the refusal. A call that joins a handshake already out takes that one's purpose.
    pub async fn ensure_session_for_docs(
        &self,
        peer: NodeId,
        network_id: NetworkId,
    ) -> Result<L4SessionHandle, EnsureError> {
        self.ensure_with(peer, network_id, true).await
    }

    async fn ensure_with(
        &self,
        peer: NodeId,
        network_id: NetworkId,
        docs: bool,
    ) -> Result<L4SessionHandle, EnsureError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Ensure {
                peer,
                network_id,
                docs,
                reply,
            })
            .await
            .map_err(|_| EnsureError::RouterGone)?;
        answer.await.map_err(|_| EnsureError::RouterGone)?
    }

    /// Whether a full session to `peer` in `network_id` is up now and in good standing by the
    /// documents held now. Starts no handshake and closes nothing (unlike
    /// [`Self::ensure_session`]); a router that is gone or stopping says `false`.
    pub async fn has_session(&self, peer: NodeId, network_id: NetworkId) -> bool {
        let (reply, answer) = oneshot::channel();
        if self
            .commands
            .send(Command::Standing {
                peer,
                network_id,
                reply,
            })
            .await
            .is_err()
        {
            return false;
        }
        answer.await.unwrap_or(false)
    }

    /// Ends every session with `reason` as its CLOSE, drops every initiation
    /// that is out and tells every caller still waiting for a session
    /// [`EnsureError::ShuttingDown`]; from then on the router answers no
    /// `init` and starts no handshake. Returns once the sessions' actors have
    /// ended, which is when each has handed its CLOSE to the L3 session's
    /// outbound channel (the L3 session still has to write it), or after
    /// `within`: `true` if every one ended in time. Meant for a node on its
    /// way out ([`crate::Node::close_gracefully`]); there is no undoing it.
    pub async fn stop(&self, reason: CloseReason, within: Duration) -> bool {
        let (done, finished) = oneshot::channel();
        if self
            .commands
            .send(Command::Stop { reason, done })
            .await
            .is_err()
        {
            // No router: no session to close.
            return true;
        }
        matches!(tokio::time::timeout(within, finished).await, Ok(Ok(())))
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

/// What a session is for, which decides whether it has datagram channels.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionKind {
    /// A member session: streams, and datagram channels.
    Member,
    /// Admitted for one `menzil:docs` push.
    DocsOnly,
    /// The attached relay's session (protocol.md 6.1).
    RelayPrincipal,
}

enum Command {
    Ensure {
        peer: NodeId,
        network_id: NetworkId,
        /// The dial's purpose is `menzil:docs`.
        docs: bool,
        reply: oneshot::Sender<Result<L4SessionHandle, EnsureError>>,
    },
    /// Whether a session in good standing is up, asking for nothing and changing nothing.
    Standing {
        peer: NodeId,
        network_id: NetworkId,
        reply: oneshot::Sender<bool>,
    },
    Stop {
        reason: CloseReason,
        /// Resolved when every session closed for it has ended.
        done: oneshot::Sender<()>,
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
    /// The relay's static key of this attachment (see [`SessionEvent::Attached`]).
    relay_static: X25519PublicKey,
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

/// The session that gives way when the node wide ceiling is crossed: the one holding the most
/// unread data (ties to the lower index), among the sessions of `own_network` (the arriving
/// session's) when any of them holds something, else among all (TBD 76 b). `None` when nothing
/// holds anything.
fn pick_victim(
    sessions: &[(SessionIndex, NetworkId, usize)],
    own_network: Option<NetworkId>,
) -> Option<SessionIndex> {
    let largest = |scope: Option<NetworkId>| {
        sessions
            .iter()
            .filter(|(_, network, held)| *held > 0 && scope.is_none_or(|n| *network == n))
            .max_by_key(|&&(index, _, held)| (held, std::cmp::Reverse(index)))
            .map(|&(index, ..)| index)
    };
    largest(own_network).or_else(|| largest(None))
}

/// The smallest node wide ceiling that is honoured: the per session floor `l4_session` raises
/// every session's budget to, `2 x (max_record + 128)` with `max_record` at its largest
/// (Noise's 65,535 byte message). A lower ceiling would be raised again per session, so a lone
/// honest session would end on a few records and `make_room`'s all zero branch would be
/// reachable.
const MIN_INBOUND_CEILING: usize = 2 * (65_535 + 128);

fn clamp_ceiling(bytes: usize) -> usize {
    bytes.max(MIN_INBOUND_CEILING)
}

/// Takes a session's charges out of the node wide counter. EVERY path that removes a session
/// from the table must call this on the removed entry (its actor ends on its own time, and
/// what it still holds must not count against others, nor make `make_room` pick an innocent
/// victim). Idempotent.
fn release_inbound(entry: &Entry) {
    if entry.is_label() {
        // A routing label of a session that lives on under another entry: the charges are
        // that session's.
        return;
    }
    entry.handle.detach_inbound();
}

/// What the table routes `data` to.
struct Entry {
    handle: L4SessionHandle,
    peer: NodeId,
    network: NetworkId,
    /// The peer's Noise static key for this session (see [`SessionReady::peer_static`]).
    peer_static: X25519PublicKey,
    epoch: Epoch,
    /// Tells a late notice from a session whose index has since been
    /// reused from the new one's: see [`tag_of`].
    generation: u32,
    /// For a session an `init` of the peer's created: that `init`'s
    /// `sender_index` and Noise message, to tell a repeat of it from a new
    /// one (see [`Engine::is_repeated_init`]). `None` for one we initiated.
    init: Option<(u32, Vec<u8>)>,
    /// A docs only session: installed under [`docs_only_slot`], tracked in
    /// [`Engine::docs_only`], never offered for sending or promoted.
    docs_only: bool,
    /// What the session is for.
    kind: SessionKind,
    /// Which side of the handshake this node was for the session now routed under this entry
    /// (the chain initiator, who starts the replacements, is the [`Role::Initiator`]).
    role: Role,
    /// The `receiver_index` this node stamps on frames to the peer for this session: what the
    /// responder's `resp` said as `sender_index`, which a later `held` offer is compared with.
    peer_index: u32,
    /// The Noise handshake hash of the session routed under this entry: CONTINUE's `binding`
    /// is computed from it.
    handshake_hash: [u8; 32],
    /// The tag the actor's notices carry: constant for the actor's whole life, while
    /// the table index it is routed under changes at every continued replacement
    /// ([`Age::index`]).
    tag: u64,
    /// Which of the actor's transports frames routed under this entry belong to
    /// ([`L4SessionHandle::feed_inbound_gen`]).
    transport_gen: Generation,
    /// A second routing label for an actor that another entry holds: it routes the frames of
    /// a replacement transport during a cutover, and becomes the session's entry when the
    /// cutover is confirmed ([`SessionTable::commit_alias`]). Its charges are the actor's, and
    /// ending it ends nothing. Cleared when the alias becomes the session's entry
    /// ([`Engine::commit_cutover`]), hence the atomic: the table hands out `&Entry` only.
    alias: AtomicBool,
    /// Dropped with the last entry of the actor, which is what ends it as
    /// `EpochEnded` (the actor treats a closed sender like a message). Shared by an actor's
    /// aliases, so that the entry a commit retires cannot end the actor that lives on.
    _epoch_ended: Arc<oneshot::Sender<()>>,
}

impl Entry {
    /// Whether this entry is only a routing label of an actor another entry holds.
    fn is_label(&self) -> bool {
        self.alias.load(Ordering::Relaxed)
    }
}

/// What an `init` of ours that is out keeps for when its `resp` comes, or
/// when it does not.
struct Pending {
    hs: E2eInitiatorHandshake,
    peer: NodeId,
    network: NetworkId,
    attempt: u32,
    epoch: Epoch,
    /// The dial's purpose is `menzil:docs`: the expiry of the held documents is not held
    /// against it.
    docs: bool,
    /// An `init` that replaces the full session whose actor carries this tag (the 24 hour
    /// replacement, [`Engine::begin_replacement`]); nobody waits for it.
    replaces: Option<u64>,
}

/// What the engine keeps about a full member session beside its table entry: its age. Both
/// sides end a session at the hard cap ([`ReplaceDurations::hard_cap`]); the chain initiator
/// also starts its replacement from a schedule.
struct Age {
    /// The table index the session is routed under now (it changes at every continued
    /// replacement, the tag does not).
    index: SessionIndex,
    peer: NodeId,
    network: NetworkId,
    /// When the keys the session sends and receives on now were agreed.
    started: Instant,
    hard_cap_at: Instant,
    /// The chain initiator's replacement schedule; `None` for the responder, and for an
    /// initiator while a cutover runs.
    schedule: Option<ReplaceSchedule>,
    /// A continued replacement waiting for CONTINUE_ACK (the initiator's side only: the
    /// responder switches at once).
    cutover: Option<Cutover>,
}

/// An initiator's continued replacement between its CONTINUE and the peer's CONTINUE_ACK.
struct Cutover {
    /// The alias in the table that routes the replacement transport's frames.
    alias: SessionIndex,
    /// What [`L4SessionHandle::hand_over`] numbered the replacement transport; the cutover is
    /// over when [`L4SessionHandle::settled_generation`] reaches it.
    generation: Generation,
    /// When the replacement's `resp` arrived: the new session's age starts here.
    since: Instant,
}

/// A responder side candidate the router holds itself because a session of the slot stays
/// current until the candidate's first reliable record says whether it continues it (CONTINUE)
/// or replaces it (anything else). It has no actor and sends nothing; its index stays reserved
/// in the table.
struct Held {
    transport: menzil_e2e::E2eTransport,
    peer: NodeId,
    network: NetworkId,
    peer_static: X25519PublicKey,
    epoch: Epoch,
    /// The `held` value offered in its `resp`: the table index of the slot's current session.
    offered: SessionIndex,
    /// The `init` that created it, to tell a repeat of it from a new one.
    init: (u32, Vec<u8>),
    created: Instant,
}

fn tag_of(generation: u32, index: SessionIndex) -> u64 {
    (u64::from(generation) << 32) | u64::from(index)
}

fn untag(tag: u64) -> (u32, SessionIndex) {
    ((tag >> 32) as u32, (tag & 0xffff_ffff) as u32)
}

/// Every decision in this module. See the module docs.
struct Engine {
    /// Read at each use: a renewal replaces the certificate under a running router.
    identity: IdentityCell,
    local_node_id: NodeId,
    /// This node's own static key, for its certificate in the Policy (round 11 N1).
    local_static: X25519PublicKey,
    relay_node_id: NodeId,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    shares: ShareBook,
    budgets: SendBudgets,
    inbound_budget: usize,
    /// Unread inbound data of every session together ([`L4_INBOUND_CEILING_PER_NODE`]).
    node_inbound: Arc<NodeInbound>,
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
    unsent: VecDeque<(OutboundSend, oneshot::Sender<()>)>,
    /// For the line about refused `init`s.
    refused_log: LogThrottle,
    /// For the line about a session ended for passing its inbound budget:
    /// its own, so that a peer making `init`s fail (up to a line a second)
    /// cannot hide it.
    overflow_log: LogThrottle,
    next_generation: u32,
    /// Set by [`RouterHandle::stop`]: no new work from then on.
    stopping: bool,
    /// The tags of the sessions [`Self::on_stop`] closed whose actors have
    /// not reported their end yet.
    closing: HashSet<u64>,
    /// The docs only sessions in the table, by index.
    docs_only: HashMap<SessionIndex, DocsOnly>,
    /// The 24 hour replacement and the continuation (test overridable).
    replace: ReplaceConfig,
    /// The age of every full member session, by the tag of its actor.
    ages: HashMap<u64, Age>,
    /// The candidates the router holds itself (see [`Held`]), by their reserved index.
    held: HashMap<SessionIndex, Held>,
    /// The router-held candidate of each slot (at most one), by slot.
    held_slot: HashMap<(NodeId, NetworkId), SessionIndex>,
    /// How many responder handshakes got as far as the Noise work (the Diffie
    /// Hellmans), for the test that pins that a stranger costs none.
    #[cfg(test)]
    handshakes_started: usize,
}

/// What the engine keeps about a docs only session beside its table entry.
struct DocsOnly {
    role: Role,
    peer: NodeId,
    /// When the session is ended with CLOSE `docs_only`.
    deadline: Instant,
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
        // A router-held candidate keeps its index only reserved; the reservation must outlast
        // the candidate's own timeout.
        let mut table_config = config.table;
        table_config.reservation_timeout = table_config
            .reservation_timeout
            .max(config.replace.held_timeout);
        Self {
            identity: config.identity,
            local_node_id: config.local_node_id,
            local_static: config.local_static,
            relay_node_id: config.relay_node_id,
            policies: config.policies,
            rosters: config.rosters,
            shares: config.shares,
            budgets: config.budgets,
            inbound_budget: config
                .inbound_budget
                .min(clamp_ceiling(config.inbound_ceiling)),
            node_inbound: Arc::new(NodeInbound::new(clamp_ceiling(config.inbound_ceiling))),
            table: SessionTable::new(config.local_node_id, table_config, index_source),
            waiters: HashMap::new(),
            waiter_timeout,
            attached: None,
            outbound,
            ready,
            notices,
            attachment,
            unsent: VecDeque::new(),
            refused_log: LogThrottle::new(),
            overflow_log: LogThrottle::new(),
            next_generation: 1,
            stopping: false,
            closing: HashSet::new(),
            docs_only: HashMap::new(),
            replace: config.replace,
            ages: HashMap::new(),
            held: HashMap::new(),
            held_slot: HashMap::new(),
            #[cfg(test)]
            handshakes_started: 0,
        }
    }

    // ------------------------------------------------------------------
    // L3 events
    // ------------------------------------------------------------------

    fn on_attached(&mut self, epoch: Epoch, limits: Limits, relay_static: X25519PublicKey) {
        self.attached = Some(Attached {
            epoch,
            limits,
            relay_static,
        });
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
        for (index, entry) in self.table.remove_where(|entry| entry.epoch == epoch) {
            release_inbound(&entry);
            self.docs_only.remove(&index);
        }
        drop(
            self.table
                .remove_pending_where(|pending| pending.epoch == epoch),
        );
        // The router-held candidates of that epoch: nothing carries over to the next one.
        let gone: Vec<SessionIndex> = self
            .held
            .iter()
            .filter(|(_, held)| held.epoch == epoch)
            .map(|(&index, _)| index)
            .collect();
        for index in gone {
            self.drop_held(index);
        }
        self.unsent.retain(|(request, _)| request.epoch != epoch);
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
        // The L3 `flags` droppable bit is the relay's hint, written by the relay and open to
        // being flipped by it: the class of a record is its counter's top bit (protocol.md
        // 5.2), which `feed_inbound` reads. A datagram without the bit is still a datagram;
        // the bit on a record that is not one is checked below.
        if self.stopping {
            // Nothing is answered or routed any more: the sessions are closed
            // and a new `init` would only start one that is never served.
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
        // A droppable flag on a record that is not datagram class is a protocol violation
        // (protocol.md 4.2, TBD 72): the record is dropped. The session is not ended here; a
        // dropped reliable `data` leaves a counter gap that ends it at the next record. A
        // datagram counter without the flag is still a datagram.
        if flags & 0x01 != 0 {
            let datagram = matches!(
                &frame,
                E2eFrame::Data { counter, .. }
                    if RecordClass::of_counter(*counter) == RecordClass::Datagram
            );
            if !datagram {
                tracing::debug!(%src, "dropped a non datagram L4 record flagged droppable");
                return None;
            }
        }
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
                if self.held.contains_key(&receiver_index) {
                    // A candidate of a replacement the router holds itself.
                    self.on_held_record(receiver_index, src, counter, ciphertext, now);
                    return None;
                }
                // The frame goes to the transport of the generation its index belongs to
                // (a continued replacement has two indices for one actor for a while).
                let (refused, generation, label_of) = match self.table.route(receiver_index, &src) {
                    Route::Session { handle, .. } => (
                        handle
                            .handle
                            .feed_inbound_gen(handle.transport_gen, counter, ciphertext)
                            .err(),
                        handle.transport_gen,
                        handle.is_label().then_some((handle.peer, handle.network)),
                    ),
                    Route::Unknown | Route::WrongSource => (None, FIRST_GENERATION, None),
                };
                // An alias is a label: the session that must end is the slot's current.
                let owner = match label_of {
                    Some((peer, network)) => self
                        .table
                        .slot(&peer, &network)
                        .current
                        .unwrap_or(receiver_index),
                    None => receiver_index,
                };
                match refused {
                    None => {}
                    Some(FeedRefused::Session(_)) => self.end_overflowed(owner, now),
                    Some(FeedRefused::Node {
                        counter,
                        ciphertext,
                    }) => self.make_room(owner, generation, counter, ciphertext, now),
                }
            }
        }
        None
    }

    /// Ends the session at `index`, whose unread inbound data passed its
    /// budget (TODO.md L4h6b): the frame that did not fit was dropped, so
    /// the peer's counter has a gap and the session cannot go on. Closed
    /// with `rate_limited` and removed from the table at once, in one step
    /// like a session the router replaced: no further frame for it is
    /// routed (so nothing more piles up, however long its actor takes to
    /// notice), a request for that peer dials afresh, and the actor's own
    /// `Ended` later finds nothing to remove.
    fn end_overflowed(&mut self, index: SessionIndex, now: Now) {
        self.end_session_for(index, now, false);
    }

    /// The node wide ceiling refused the record `(counter, ciphertext)` that arrived for
    /// session `arriving` (TBD 75): the session holding the most unread inbound data gives way,
    /// preferring the arriving session's own network and taking the largest of all networks only
    /// when that network holds nothing (TBD 76 b); the arriving one included (ties go to the lower index; when nothing holds anything the
    /// arriving one, since ending another frees nothing). If the victim is another session it
    /// is ended first, which takes its charges out of the node counter
    /// ([`L4SessionHandle::detach_inbound`]), and then the record is charged without the
    /// ceiling check, which may leave the node one record over it; the next refusal evicts
    /// again; during the scan it can only grow back up to what was just released (one record per driver). If the victim is the arriving session the record is dropped
    /// with it (its counter has a gap anyway).
    fn make_room(
        &mut self,
        arriving: SessionIndex,
        generation: Generation,
        counter: u64,
        ciphertext: Vec<u8>,
        now: Now,
    ) {
        let held: Vec<(SessionIndex, NetworkId, usize)> = self
            .table
            .sessions()
            .map(|(index, entry)| (index, entry.network, entry.handle.inbound_in_use()))
            .collect();
        let own_network = held
            .iter()
            .find(|(index, ..)| *index == arriving)
            .map(|&(_, network, _)| network);
        let victim = pick_victim(&held, own_network).unwrap_or(arriving);
        self.end_session_for(victim, now, true);
        if victim == arriving {
            return;
        }
        let refused = match self.table.get(arriving) {
            Some(entry) => entry
                .handle
                .feed_inbound_over_ceiling_gen(generation, counter, ciphertext)
                .is_err(),
            None => false,
        };
        if refused {
            self.end_overflowed(arriving, now);
        }
    }

    /// Removes the session at `index` from the table, detaches its charges, closes it
    /// `rate_limited` and fails whoever waited for it. `node_wide` says which limit it passed
    /// (it only changes the log line and the close message).
    fn end_session_for(&mut self, index: SessionIndex, now: Now, node_wide: bool) {
        let Some(Removed::Session { handle, .. }) = self.table.remove(index) else {
            return;
        };
        let (peer, network) = (handle.peer, handle.network);
        release_inbound(&handle);
        let was_docs_only = self.docs_only.remove(&index).is_some();
        if let Some(held_back) = self.overflow_log.allow(now.instant) {
            // The records are charged before they are decrypted, so what
            // piled up may be junk a relay forwarded under this peer's name:
            // the line does not say the peer did it.
            if node_wide {
                tracing::warn!(
                    %peer,
                    ceiling = self.node_inbound.ceiling(),
                    held_back,
                    "ended the L4 session holding the most unread inbound data: this node's \
                     total passed its ceiling (the peer, or a relay forwarding records in \
                     its name)"
                );
            } else {
                tracing::warn!(
                    %peer,
                    budget = self.inbound_budget,
                    held_back,
                    "ended an L4 session whose unread inbound data passed its budget \
                     (the peer, or a relay forwarding records in its name)"
                );
            }
        }
        handle.handle.close(Some(CloseReason {
            code: ErrorCode::RateLimited,
            msg: if node_wide {
                "this node's unread inbound data passed its ceiling"
            } else {
                "unread inbound data passed the session budget"
            }
            .to_string(),
        }));
        if !was_docs_only {
            self.fail_orphans(&(peer, network));
        }
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
            self.on_relay_init(attached, sender_index, network_id, noise_msg1, now);
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
        // A Roster alone is enough to answer (a node admitted by an invite waits for its Policy,
        // protocol.md 5.1): the admission decision below refuses all but its Roster members, and
        // those only docs only. `policy_seq` is 0 while there is no Policy.
        let Some(roster_seq) = self.rosters.seq(&network_id) else {
            tracing::debug!(%src, "ignored an L4 init for a network we hold no documents for");
            return;
        };
        let policy_seq = self.policies.seq(&network_id).unwrap_or(0);
        // Before any Diffie Hellman (protocol.md 5.1): the RECV `src` must be an
        // unrevoked member in the Roster we hold, expired or not. A stranger and a
        // revoked member alike get silence and cost nothing but their entry in the
        // table's rate limit. What an unrevoked member may then do is decided
        // below, and per stream later.
        if !is_unrevoked_roster_member(&self.rosters, &network_id, &src) {
            tracing::debug!(%src, "ignored an L4 init from a node that is not an unrevoked Roster member");
            return;
        }
        let msg1_copy = noise_msg1.clone();
        let init = E2eFrame::Init {
            sender_index,
            network_id,
            noise_msg1,
        };
        #[cfg(test)]
        {
            self.handshakes_started += 1;
        }
        let Ok(hs) = E2eResponderHandshake::start(
            &self.identity.get().x25519_private,
            src,
            self.local_node_id,
            &init,
        ) else {
            tracing::debug!(%src, "ignored an L4 init that did not decrypt");
            return;
        };
        let peer_static = *hs.initiator_static();
        let docs_only = match decide_responder_admission(
            &self.policies,
            &self.rosters,
            &network_id,
            &src,
            &peer_static,
            &self.local_node_id,
            self.identity.serial(),
            now.unix,
        ) {
            HandshakeAdmission::Allow | HandshakeAdmission::AllowNoGrant => {
                // A session this node's own standing would end at the first re evaluation is
                // not started: without its own certificate in the Policy (round 11 N1) it can
                // only take the docs push that brings the documents it lacks.
                let own = self.own_cert_standing(&network_id, now.unix);
                if let Err(reason) = own {
                    tracing::debug!(%src, ?reason, "answering an L4 init docs only: own certificate");
                }
                own.is_err()
            }
            HandshakeAdmission::DocsOnly { reason } => {
                tracing::debug!(%src, ?reason, "answering an L4 init docs only");
                true
            }
            HandshakeAdmission::Refuse { reason } => {
                // Local logs only; nothing goes on the wire (L4h2, judgment
                // call 1).
                tracing::debug!(%src, ?reason, "refused an L4 init");
                return;
            }
        };
        if docs_only {
            self.answer_docs_only(attached, src, network_id, sender_index, msg1_copy, hs, now);
            return;
        }
        let Ok(index) = self.table.reserve_index(now.instant) else {
            return;
        };
        // A full session of this peer that this peer started stays current while a candidate
        // proves itself: offer it as `held`, so that a peer that still holds its half can
        // continue the streams (protocol.md 5.2).
        let offer = self.held_offer_for(&src, &network_id, &peer_static, attached.epoch);
        let cert = self.identity.get().node_cert.clone();
        let finished = match offer {
            Some(held) => hs.finish_offering_held(
                cert,
                roster_seq,
                policy_seq,
                vec![E2E_PROTO_TAG],
                held,
                index,
                attached.limits.max_record,
            ),
            None => hs.finish(
                cert,
                roster_seq,
                policy_seq,
                vec![E2E_PROTO_TAG],
                index,
                attached.limits.max_record,
            ),
        };
        let Ok((transport, resp)) = finished else {
            self.table.release_index(index);
            return;
        };
        if let Some(offered) = offer {
            self.install_held(
                attached,
                index,
                Held {
                    transport,
                    peer: src,
                    network: network_id,
                    peer_static,
                    epoch: attached.epoch,
                    offered,
                    init: (sender_index, msg1_copy),
                    created: now.instant,
                },
                resp,
            );
            return;
        }
        // An ordinary candidate supersedes whatever the router held for this slot.
        if let Some(stale) = self.held_slot.get(&(src, network_id)).copied() {
            self.drop_held(stale);
        }

        // A member with no grant is admitted like any other (protocol.md 5.1):
        // what it may open is decided per stream, and `menzil:docs` needs no
        // grant at all.
        let (entry, acceptor, task) = self.make_session(
            index,
            src,
            network_id,
            peer_static,
            Origin::Answered {
                sender_index,
                noise_msg1: msg1_copy,
            },
            transport,
            attached,
            SessionKind::Member,
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
                    release_inbound(&superseded);
                    superseded.handle.close(None);
                }
            }
            Err((error, _)) => {
                tracing::warn!(%src, ?error, "could not install a responder session");
                return;
            }
        }
        let resp_placed = self.send_gated(src, attached.epoch, resp.encode());
        tokio::spawn(async move {
            // Nothing of this session goes out before its `resp` is in `outbound` (see
            // `send_gated`); a dropped frame lets it run on.
            if let Some(placed) = resp_placed {
                let _ = placed.await;
            }
            task.await
        });
        let _ = self.ready.send(SessionReady {
            peer: src,
            network_id,
            peer_static,
            role: Role::Responder,
            epoch: attached.epoch,
            handle,
            acceptor,
            peer_roster_seq: None,
            peer_policy_seq: None,
            docs_only: false,
            relay_principal: false,
        });
    }

    /// An `init` whose RECV `src` is the attached relay's own NodeId: the relay principal
    /// (protocol.md 6.1, expose design S-E4). The relay is no member of any network, so none of
    /// a member's checks apply; what stands in their place, in this order, each before the next
    /// and all of them before any Diffie Hellman or allocation but the last:
    ///
    /// 1. a repeat of the `init` that made the slot's session is dropped (as for a member);
    /// 2. the table's handshake rate limit for this peer and its entry cap (the relay counts as
    ///    one peer: ten sessions a minute in all, however many networks it serves);
    /// 3. this node holds a Roster and Policy for the `init`'s network, both unexpired, and
    ///    stands well in them (listed, unrevoked, serial at or above its floor, its own
    ///    certificate listed for its own static key): [`relay_principal_standing`];
    /// 4. the book holds an accepted share that this network's Roster grants this node
    ///    ([`accepted_shares`]: the book is per relay attachment and names no network, the
    ///    Roster's `labels` are what ties a share to a network);
    /// 5. the responder handshake runs, and the initiator's static key must equal the relay's
    ///    static key of the current L3 attachment. A member that puts the relay's NodeId in its
    ///    own `init` (it cannot make the relay stamp it, but the prologue only needs the claim)
    ///    holds another key and gets silence, like every refusal here.
    ///
    /// The `resp` carries this node's own certificate, the Roster `seq` it holds and a Policy
    /// `seq` of 0: the relay is never told what the Policy holds. The session is installed in
    /// the slot of (relay, network) and announced with [`SessionReady::relay_principal`]; it
    /// belongs to the attachment it came up under like any other and ends with it.
    fn on_relay_init(
        &mut self,
        attached: Attached,
        sender_index: u32,
        network_id: NetworkId,
        noise_msg1: Vec<u8>,
        now: Now,
    ) {
        let src = self.relay_node_id;
        if self.is_repeated_init(&src, &network_id, sender_index, &noise_msg1) {
            tracing::debug!("ignored a repeated init from the relay principal");
            return;
        }
        match self.table.on_inbound_init(src, network_id, now.instant) {
            InitDecision::Respond { .. } => {}
            InitDecision::Ignore(reason) => {
                if matches!(reason, IgnoreReason::RateLimited | IgnoreReason::Full) {
                    if let Some(held_back) = self.refused_log.allow(now.instant) {
                        tracing::warn!(
                            ?reason,
                            held_back,
                            "ignored an L4 init from the relay principal"
                        );
                    }
                } else {
                    tracing::debug!(?reason, "ignored an L4 init from the relay principal");
                }
                return;
            }
        }
        let Some(roster_seq) = self.rosters.seq(&network_id) else {
            tracing::debug!(
                "ignored a relay principal init for a network we hold no documents for"
            );
            return;
        };
        if let Err(reason) = relay_principal_standing(
            &self.policies,
            &self.rosters,
            &network_id,
            &self.local_node_id,
            self.identity.serial(),
            &self.local_static,
            now.unix,
        ) {
            tracing::debug!(
                ?reason,
                "ignored a relay principal init: own standing or documents"
            );
            return;
        }
        if accepted_shares(
            &self.shares,
            &self.rosters,
            &network_id,
            &self.local_node_id,
        )
        .is_empty()
        {
            tracing::debug!("ignored a relay principal init: no accepted share for that network");
            return;
        }
        let msg1_copy = noise_msg1.clone();
        let init = E2eFrame::Init {
            sender_index,
            network_id,
            noise_msg1,
        };
        #[cfg(test)]
        {
            self.handshakes_started += 1;
        }
        let Ok(hs) = E2eResponderHandshake::start(
            &self.identity.get().x25519_private,
            src,
            self.local_node_id,
            &init,
        ) else {
            tracing::debug!("ignored a relay principal init that did not decrypt");
            return;
        };
        let peer_static = *hs.initiator_static();
        if peer_static != attached.relay_static {
            tracing::debug!("ignored an init in the relay's name from another static key");
            return;
        }
        let Ok(index) = self.table.reserve_index(now.instant) else {
            return;
        };
        let Ok((transport, resp)) = hs.finish(
            self.identity.get().node_cert.clone(),
            roster_seq,
            // The Policy is never shown to a relay.
            0,
            vec![E2E_PROTO_TAG],
            index,
            attached.limits.max_record,
        ) else {
            self.table.release_index(index);
            return;
        };
        let (entry, acceptor, task) = self.make_session(
            index,
            src,
            network_id,
            peer_static,
            Origin::Answered {
                sender_index,
                noise_msg1: msg1_copy,
            },
            transport,
            attached,
            SessionKind::RelayPrincipal,
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
                drop(installed.abandoned);
                if let Some((_, superseded)) = installed.superseded_candidate {
                    release_inbound(&superseded);
                    superseded.handle.close(None);
                }
            }
            Err((error, _)) => {
                tracing::warn!(?error, "could not install a relay principal session");
                return;
            }
        }
        let resp_placed = self.send_gated(src, attached.epoch, resp.encode());
        tokio::spawn(async move {
            // Nothing of this session goes out before its `resp` is in `outbound` (see
            // `send_gated`); a dropped frame lets it run on.
            if let Some(placed) = resp_placed {
                let _ = placed.await;
            }
            task.await
        });
        let _ = self.ready.send(SessionReady {
            peer: src,
            network_id,
            peer_static,
            role: Role::Responder,
            epoch: attached.epoch,
            handle,
            acceptor,
            peer_roster_seq: None,
            peer_policy_seq: None,
            docs_only: false,
            relay_principal: true,
        });
    }

    /// Completes the handshake of an `init` that [`decide_responder_admission`]
    /// admitted docs only (protocol.md 5.1, 5.5), `docs_only: true` in the payload.
    /// The session is installed under [`docs_only_slot`], at most
    /// [`MAX_DOCS_ONLY_SESSIONS`] of them and one per peer (a new `init` of a peer
    /// replaces its earlier docs only session), and is ended with CLOSE
    /// `docs_only` at [`DOCS_ONLY_LIFETIME`] (or sooner by whoever serves the
    /// push). Past the cap the `init` is not answered.
    #[allow(clippy::too_many_arguments)]
    fn answer_docs_only(
        &mut self,
        attached: Attached,
        src: NodeId,
        network_id: NetworkId,
        sender_index: u32,
        noise_msg1: Vec<u8>,
        hs: E2eResponderHandshake,
        now: Now,
    ) {
        let Some(roster_seq) = self.rosters.seq(&network_id) else {
            return;
        };
        let policy_seq = self.policies.seq(&network_id).unwrap_or(0);
        let peer_static = *hs.initiator_static();
        let others = self
            .docs_only
            .values()
            .filter(|docs| docs.role == Role::Responder && docs.peer != src)
            .count();
        if others >= MAX_DOCS_ONLY_SESSIONS {
            if let Some(held_back) = self.refused_log.allow(now.instant) {
                tracing::warn!(%src, held_back, "ignored an L4 init: the docs only sessions are full");
            }
            return;
        }
        let Ok(index) = self.table.reserve_index(now.instant) else {
            return;
        };
        let Ok((transport, resp)) = hs.finish_docs_only(
            self.identity.get().node_cert.clone(),
            roster_seq,
            policy_seq,
            vec![E2E_PROTO_TAG],
            index,
            attached.limits.max_record,
        ) else {
            self.table.release_index(index);
            return;
        };
        let (entry, acceptor, task) = self.make_session(
            index,
            src,
            network_id,
            peer_static,
            Origin::Answered {
                sender_index,
                noise_msg1,
            },
            transport,
            attached,
            SessionKind::DocsOnly,
        );
        let handle = entry.handle.clone();
        match self.table.install_session(
            index,
            src,
            docs_only_slot(),
            Role::Responder,
            entry,
            now.instant,
        ) {
            Ok(installed) => {
                if let Some((old, superseded)) = installed.superseded_candidate {
                    self.docs_only.remove(&old);
                    release_inbound(&superseded);
                    superseded.handle.close(None);
                }
            }
            Err((error, _)) => {
                tracing::warn!(%src, ?error, "could not install a docs only session");
                return;
            }
        }
        self.docs_only.insert(
            index,
            DocsOnly {
                role: Role::Responder,
                peer: src,
                deadline: now.instant + DOCS_ONLY_LIFETIME,
            },
        );
        let resp_placed = self.send_gated(src, attached.epoch, resp.encode());
        tokio::spawn(async move {
            // Nothing of this session goes out before its `resp` is in `outbound` (see
            // `send_gated`); a dropped frame lets it run on.
            if let Some(placed) = resp_placed {
                let _ = placed.await;
            }
            task.await
        });
        let _ = self.ready.send(SessionReady {
            peer: src,
            network_id,
            peer_static,
            role: Role::Responder,
            epoch: attached.epoch,
            handle,
            acceptor,
            peer_roster_seq: None,
            peer_policy_seq: None,
            docs_only: true,
            relay_principal: false,
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
        let real = self.table.slot(src, network);
        let aside = self.table.slot(src, &docs_only_slot());
        let held = self
            .held_slot
            .get(&(*src, *network))
            .and_then(|index| self.held.get(index))
            .is_some_and(|held| held.init.0 == sender_index && held.init.1 == noise_msg1);
        held || [real.candidate, real.current, aside.candidate]
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
    // Responder: a replacement of a session this peer started (protocol.md 5.2)
    // ------------------------------------------------------------------

    /// What to offer as `held` in the `resp` to an `init` of `src`: the table index of the
    /// slot's current session, when that is a full member session **this peer started** (we
    /// answered it: the roles never swap, so only the chain initiator's replacements can
    /// continue it), on the attachment the `init` arrived on, with the static key of this
    /// `init`, and nothing else is in flight for the slot (no unproven candidate, no cutover).
    /// `None` also when the continuation is switched off.
    fn held_offer_for(
        &self,
        src: &NodeId,
        network: &NetworkId,
        peer_static: &X25519PublicKey,
        epoch: Epoch,
    ) -> Option<SessionIndex> {
        if !self.replace.continuation {
            return None;
        }
        let slot = self.table.slot(src, network);
        if slot.candidate.is_some() || slot.alias.is_some() {
            return None;
        }
        let current = slot.current?;
        let entry = self.table.get(current)?;
        (entry.kind == SessionKind::Member
            && !entry.docs_only
            && !entry.is_label()
            && entry.role == Role::Responder
            && entry.epoch == epoch
            && entry.peer_static == *peer_static)
            .then_some(current)
    }

    /// Keeps `held` as the slot's router-held candidate (a newer one for the slot replaces it)
    /// and answers its `init` with `resp`. No actor, nothing is sent on it, and nobody is told
    /// of a new session: the current one carries on until the first reliable record.
    fn install_held(
        &mut self,
        attached: Attached,
        index: SessionIndex,
        held: Held,
        resp: E2eFrame,
    ) {
        let key = (held.peer, held.network);
        if let Some(stale) = self.held_slot.insert(key, index) {
            self.drop_held(stale);
            self.held_slot.insert(key, index);
        }
        let peer = held.peer;
        self.held.insert(index, held);
        self.send(peer, attached.epoch, resp.encode());
    }

    /// Takes a router-held candidate out (its index stays reserved in the table).
    fn take_held(&mut self, index: SessionIndex) -> Option<Held> {
        let held = self.held.remove(&index)?;
        if self.held_slot.get(&(held.peer, held.network)) == Some(&index) {
            self.held_slot.remove(&(held.peer, held.network));
        }
        Some(held)
    }

    /// Forgets a router-held candidate and gives its index back.
    fn drop_held(&mut self, index: SessionIndex) {
        if self.take_held(index).is_some() {
            self.table.release_index(index);
        }
    }

    /// A `data` record for a router-held candidate. **A candidate is proved by its first
    /// reliable record** (protocol.md 5.2): a datagram before it is dropped, a record that does
    /// not authenticate is dropped and the candidate waits on, and the first reliable record
    /// that does decides, by what it is:
    ///
    /// * a CONTINUE: judged by [`Self::continue_verdict`], then the candidate's transport goes
    ///   to the current session's actor ([`Self::commit_continue`]) or the candidate is refused;
    /// * anything else (the peer does not continue: it restarted, or predates the
    ///   continuation): today's replacement, a new actor with this transport that gets the
    ///   record ([`Self::replace_from_held`]).
    fn on_held_record(
        &mut self,
        index: SessionIndex,
        src: NodeId,
        counter: u64,
        ciphertext: Vec<u8>,
        now: Now,
    ) {
        let Some(held) = self.held.get(&index) else {
            return;
        };
        if held.peer != src {
            // Data is accepted only from the session's own peer (protocol.md 5.1).
            return;
        }
        if RecordClass::of_counter(counter) == RecordClass::Datagram {
            return;
        }
        let epoch = held.epoch;
        if !self.attached.is_some_and(|a| a.epoch == epoch) {
            self.drop_held(index);
            return;
        }
        let Some(mut held) = self.take_held(index) else {
            return;
        };
        // Read the record without consuming it: a record that does not authenticate proves
        // nothing and the candidate keeps waiting; one that does is either a CONTINUE (the
        // transport is then consumed here) or any other first record, which the new actor
        // reads afresh from the untouched transport (today's replacement).
        let plaintext = match held.transport.peek_raw(counter, &ciphertext) {
            Ok(plaintext) => plaintext,
            Err(E2eError::UnauthenticatedDatagramCounter | E2eError::Noise(_)) => {
                self.held_slot.insert((held.peer, held.network), index);
                self.held.insert(index, held);
                return;
            }
            Err(error) => {
                tracing::debug!(%src, %error, "dropped a replacement candidate: its first record is out of order");
                self.table.release_index(index);
                return;
            }
        };
        match ContinueBody::decode(&plaintext) {
            Ok(body) => {
                // Consume the counter the peek left alone; it cannot fail after the peek.
                if held.transport.decrypt_raw(counter, &ciphertext).is_err() {
                    self.table.release_index(index);
                    return;
                }
                self.judge_continue(held, index, body, now);
            }
            Err(_) => self.replace_from_held(held, index, counter, ciphertext, now),
        }
    }

    /// Whether a CONTINUE that arrived on candidate `held` may take over the slot's current
    /// session; the table index of that session if so (protocol.md 5.2): the slot's current is
    /// still the one that was offered, `prior` names it, `binding` is its handshake's, it is a
    /// full member session this peer started on the candidate's attachment with the
    /// candidate's static key, no other handover is under way, and **both ends are in good
    /// standing right now** (the check the Revalidator's next pass would make, made
    /// synchronously at the commit).
    fn continue_verdict(
        &self,
        held: &Held,
        body: &ContinueBody,
        now: Now,
    ) -> Result<SessionIndex, ContinueRefusal> {
        let slot = self.table.slot(&held.peer, &held.network);
        let current = slot
            .current
            .ok_or(ContinueRefusal::Mismatch("no current session to continue"))?;
        if current != held.offered {
            return Err(ContinueRefusal::Mismatch(
                "the current session is not the one that was offered",
            ));
        }
        if body.prior != held.offered {
            return Err(ContinueRefusal::Mismatch(
                "CONTINUE names a session that is not the current one",
            ));
        }
        let entry = self
            .table
            .get(current)
            .ok_or(ContinueRefusal::Mismatch("no current session to continue"))?;
        if entry.kind != SessionKind::Member
            || entry.docs_only
            || entry.is_label()
            || entry.role != Role::Responder
            || entry.epoch != held.epoch
            || entry.peer_static != held.peer_static
            || slot.alias.is_some()
        {
            return Err(ContinueRefusal::Mismatch(
                "the current session is not this peer's full session on this attachment",
            ));
        }
        if body.binding != continue_binding(&entry.handshake_hash) {
            return Err(ContinueRefusal::Mismatch(
                "CONTINUE's binding is not the current session's",
            ));
        }
        session_standing(
            &self.policies,
            &self.rosters,
            &held.network,
            &held.peer,
            &entry.peer_static,
            &self.local_node_id,
            self.identity.serial(),
            &self.local_static,
            now.unix,
        )
        .map_err(|_| ContinueRefusal::Standing)?;
        Ok(current)
    }

    /// Acts on a CONTINUE read on candidate `held`: hands the candidate's transport to the
    /// current session's actor, or refuses (CLOSE `handover_failed` on the candidate; when
    /// `prior` named this slot's current session, that session ends too, because the peer has
    /// already moved its yamux state; a session of another slot is never touched).
    fn judge_continue(&mut self, held: Held, index: SessionIndex, body: ContinueBody, now: Now) {
        match self.continue_verdict(&held, &body, now) {
            Ok(current) => self.commit_continue(held, index, current, &body, now),
            Err(refusal) => {
                let (peer, network) = (held.peer, held.network);
                let close = match refusal {
                    ContinueRefusal::Mismatch(why) => {
                        tracing::info!(%peer, why, "refused a CONTINUE");
                        handover_failed_close(why)
                    }
                    ContinueRefusal::Standing => {
                        tracing::info!(%peer, "refused a CONTINUE: a party is not in good standing");
                        grant_removed_close()
                    }
                };
                self.refuse_held(held, index, &close);
                if let Some(current) = self
                    .table
                    .slot(&peer, &network)
                    .current
                    .filter(|current| *current == body.prior)
                {
                    self.end_session(current, close);
                }
            }
        }
    }

    /// The CONTINUE passed: `held`'s transport becomes the current session's replacement
    /// transport (the actor answers CONTINUE_ACK and switches when it reaches the item behind
    /// the old records already queued), and the candidate's index becomes the session's entry
    /// in place of the old one at once: the peer sent every old record before its CONTINUE and
    /// the relay keeps the order, so nothing more is due on the old index.
    fn commit_continue(
        &mut self,
        held: Held,
        index: SessionIndex,
        current: SessionIndex,
        body: &ContinueBody,
        now: Now,
    ) {
        let Held {
            transport,
            peer,
            network,
            peer_static,
            epoch,
            init,
            ..
        } = held;
        let Some(old) = self.table.get(current) else {
            self.table.release_index(index);
            return;
        };
        let (handle, tag, generation, epoch_ended) = (
            old.handle.clone(),
            old.tag,
            old.generation,
            Arc::clone(&old._epoch_ended),
        );
        let (peer_index, handshake_hash) = (transport.peer_index(), *transport.handshake_hash());
        let replacement = handle.hand_over(
            transport,
            HandoverRole::Responder {
                continue_sent: body.sent,
            },
        );
        let label = Entry {
            handle,
            peer,
            network,
            peer_static,
            epoch,
            generation,
            init: Some(init),
            docs_only: false,
            kind: SessionKind::Member,
            role: Role::Responder,
            peer_index,
            handshake_hash,
            tag,
            transport_gen: replacement,
            alias: AtomicBool::new(true),
            _epoch_ended: epoch_ended,
        };
        if let Err((error, label)) =
            self.table
                .install_alias(index, peer, network, label, now.instant)
        {
            // Not reachable (the verdict looked at the slot a moment ago), but the actor has
            // the replacement transport: end the session rather than leave it half switched.
            tracing::warn!(%peer, ?error, "could not install the alias of a continued session");
            label.handle.close(Some(handover_failed_close(
                "the replacement could not be routed",
            )));
            self.end_session(
                current,
                handover_failed_close("the replacement could not be routed"),
            );
            return;
        }
        self.commit_cutover(index, tag, now.instant, false);
        tracing::info!(%peer, "replaced an L4 session: its streams continue (responder)");
    }

    /// Makes alias `index` the entry of the actor `tag`: the table hands the old entry back (it
    /// is only dropped: the actor lives on under the alias and the old entry's end-of-epoch
    /// guard is shared) and the session's age starts again from `since`.
    fn commit_cutover(&mut self, index: SessionIndex, tag: u64, since: Instant, initiator: bool) {
        if let Some((_, old)) = self.table.commit_alias(index) {
            drop(old);
        }
        if let Some(entry) = self.table.get(index) {
            entry.alias.store(false, Ordering::Relaxed);
        }
        if let Some(age) = self.ages.get_mut(&tag) {
            age.index = index;
            age.started = since;
            age.hard_cap_at = since + self.replace.durations.hard_cap;
            age.cutover = None;
            // Only the chain initiator starts replacements, from the new session's own age.
            age.schedule = initiator.then(|| {
                let max = self.replace.durations.max_jitter;
                ReplaceSchedule::with_durations(
                    since,
                    Duration::from_secs_f64(fastrand::f64() * max.as_secs_f64()),
                    self.replace.durations.clone(),
                )
            });
        }
    }

    /// Refuses a candidate: CLOSE on its transport (its first record, which the peer, waiting
    /// for CONTINUE_ACK, reads) and its index back.
    fn refuse_held(&mut self, mut held: Held, index: SessionIndex, close: &CloseReason) {
        if let Ok(frame) = held.transport.encrypt_data(&E2eDataBody::Close {
            code: close.code,
            msg: close.msg.clone(),
        }) {
            self.send(held.peer, held.epoch, frame.encode());
        }
        self.table.release_index(index);
    }

    /// The candidate's first record is not a CONTINUE (a peer that restarted or predates the
    /// continuation): today's replacement (protocol.md 5.1). A new actor takes the candidate's
    /// transport and the record, and the old current session is retired when that first record
    /// authenticates ([`SessionNotice::FirstRecord`]).
    fn replace_from_held(
        &mut self,
        held: Held,
        index: SessionIndex,
        counter: u64,
        ciphertext: Vec<u8>,
        now: Now,
    ) {
        let Some(attached) = self.attached.filter(|a| a.epoch == held.epoch) else {
            self.table.release_index(index);
            return;
        };
        // The candidate waited for its first record, in which time the documents may have
        // changed: a peer or a node that no longer stands gets no session out of it (the same
        // check a handed out session passes, protocol.md 5.3).
        if session_standing(
            &self.policies,
            &self.rosters,
            &held.network,
            &held.peer,
            &held.peer_static,
            &self.local_node_id,
            self.identity.serial(),
            &self.local_static,
            now.unix,
        )
        .is_err()
        {
            tracing::info!(peer = %held.peer, "refused a replacement candidate: a party is not in good standing");
            self.refuse_held(held, index, &grant_removed_close());
            return;
        }
        let Held {
            transport,
            peer,
            network,
            peer_static,
            init,
            ..
        } = held;
        let (entry, acceptor, task) = self.make_session(
            index,
            peer,
            network,
            peer_static,
            Origin::Answered {
                sender_index: init.0,
                noise_msg1: init.1,
            },
            transport,
            attached,
            SessionKind::Member,
        );
        let handle = entry.handle.clone();
        match self
            .table
            .install_session(index, peer, network, Role::Responder, entry, now.instant)
        {
            Ok(installed) => {
                drop(installed.abandoned);
                if let Some((_, superseded)) = installed.superseded_candidate {
                    release_inbound(&superseded);
                    superseded.handle.close(None);
                }
            }
            Err((error, _)) => {
                tracing::warn!(%peer, ?error, "could not install a replacement session");
                return;
            }
        }
        tokio::spawn(task);
        let _ = self.ready.send(SessionReady {
            peer,
            network_id: network,
            peer_static,
            role: Role::Responder,
            epoch: attached.epoch,
            handle: handle.clone(),
            acceptor,
            peer_roster_seq: None,
            peer_policy_seq: None,
            docs_only: false,
            relay_principal: false,
        });
        match handle.feed_inbound(counter, ciphertext) {
            Ok(()) => {}
            Err(FeedRefused::Session(_)) => self.end_overflowed(index, now),
            Err(FeedRefused::Node {
                counter,
                ciphertext,
            }) => self.make_room(index, FIRST_GENERATION, counter, ciphertext, now),
        }
    }

    /// Removes the session at `index` from the table and ends it with `reason` as its CLOSE,
    /// like every router initiated end: removed at once, so that the next request dials afresh.
    fn end_session(&mut self, index: SessionIndex, reason: CloseReason) {
        let Some(Removed::Session { handle: entry, .. }) = self.table.remove(index) else {
            return;
        };
        release_inbound(&entry);
        let key = (entry.peer, entry.network);
        // The CLOSE goes before the entry is dropped: dropping it ends the actor as
        // `EpochEnded`, which the CLOSE must outrank.
        entry.handle.close(Some(reason));
        drop(entry);
        self.fail_orphans(&key);
    }

    // ------------------------------------------------------------------
    // Initiator: our own `init`, and the `resp` to it
    // ------------------------------------------------------------------

    /// Whether the held Policy lists this node's own certificate (round 11 N1), for the
    /// documents held now.
    fn own_cert_standing(&self, network: &NetworkId, now: u64) -> Result<(), ErrorCode> {
        let roster = self
            .rosters
            .body(network)
            .ok_or(ErrorCode::UnknownNetwork)?;
        let view = self
            .policies
            .view(network)
            .ok_or(ErrorCode::UnknownNetwork)?;
        crate::admission::own_cert_standing(
            &roster,
            &view.certs,
            &self.local_node_id,
            &self.local_static,
            now,
        )
    }

    /// Whether the slot has a current session that `ensure` would hand out (read only).
    fn has_standing_session(&self, peer: NodeId, network: NetworkId, now: Now) -> bool {
        if self.stopping {
            return false;
        }
        let Some(index) = self.table.slot(&peer, &network).current else {
            return false;
        };
        let Some(entry) = self.table.get(index) else {
            return false;
        };
        session_standing(
            &self.policies,
            &self.rosters,
            &network,
            &peer,
            &entry.peer_static,
            &self.local_node_id,
            self.identity.serial(),
            &self.local_static,
            now.unix,
        )
        .is_ok()
    }

    fn ensure(&mut self, peer: NodeId, network: NetworkId, docs: bool, reply: Waiter, now: Now) {
        if self.stopping {
            let _ = reply.send(Err(EnsureError::ShuttingDown));
            return;
        }
        if peer == self.local_node_id {
            let _ = reply.send(Err(EnsureError::SelfPeer));
            return;
        }
        if peer == self.relay_node_id {
            // The relay principal is the relay's to initiate (TOBEDECIDED item 8, expose
            // design S-E4): it has no network and no cert in any Policy to dial, and a
            // node that dialed it would offer the relay a session it never asked for.
            let _ = reply.send(Err(EnsureError::UnknownPeer));
            return;
        }
        let slot = self.table.slot(&peer, &network);
        if let Some(index) = slot.current
            && let Some(entry) = self.table.get(index)
        {
            // A session is handed out only while both ends are still in good standing by
            // the documents held now (protocol.md 5.3, TOBEDECIDED 30 T16): between an
            // adoption and the pass that re evaluates every session, a caller must not get a
            // session the new documents would end. One that fails is closed, uniformly, and
            // the caller falls through to a fresh dial, which the dial checks then settle.
            let standing = session_standing(
                &self.policies,
                &self.rosters,
                &network,
                &peer,
                &entry.peer_static,
                &self.local_node_id,
                self.identity.serial(),
                &self.local_static,
                now.unix,
            );
            match standing {
                Ok(()) => {
                    let _ = reply.send(Ok(entry.handle.clone()));
                    return;
                }
                Err(reason) => {
                    tracing::info!(%peer, ?reason, "closing a session that is no longer in good standing");
                    if let Some(Removed::Session { handle: entry, .. }) = self.table.remove(index) {
                        release_inbound(&entry);
                        // The CLOSE goes before the entry is dropped: dropping it ends the
                        // actor as `EpochEnded`, which the CLOSE must outrank.
                        entry.handle.close(Some(grant_removed_close()));
                    }
                }
            }
        }
        let slot = self.table.slot(&peer, &network);
        if self.attached.is_none() {
            let _ = reply.send(Err(EnsureError::NotAttached));
            return;
        }
        if slot.pending.is_none()
            && slot.candidate.is_none()
            && let Err(error) = self.begin_initiation(peer, network, 1, docs, None, now)
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
        docs: bool,
        replaces: Option<u64>,
        now: Now,
    ) -> Result<(), EnsureError> {
        let attached = self.attached.ok_or(EnsureError::NotAttached)?;
        if let Err(reason) = crate::admission::membership(
            &self.policies,
            &self.rosters,
            &network,
            &self.local_node_id,
            self.identity.serial(),
            now.unix,
            !docs,
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
        // A full session dial also needs this node's own certificate to stand (listed in the
        // held Policy, valid now, serial not below min_serial): otherwise the session would
        // open and the first revalidation pass would close it. A docs-only dial keeps the
        // current behaviour: it exists to fetch or push documents when the standing is
        // incomplete.
        if !docs && let Err(reason) = self.own_cert_standing(&network, now.unix) {
            tracing::debug!(
                ?reason,
                "not dialing: this node's own certificate does not stand"
            );
            return Err(if matches!(reason, ErrorCode::UnknownNetwork) {
                EnsureError::UnknownPeer
            } else {
                EnsureError::NotAMember
            });
        }
        let resolve = if docs {
            resolve_dial_cert_for_docs
        } else {
            resolve_dial_cert
        };
        let cert = resolve(&self.policies, &self.rosters, &network, &peer, now.unix)
            .ok_or(EnsureError::UnknownPeer)?;
        let index = self
            .table
            .reserve_index(now.instant)
            .map_err(|_| EnsureError::TableFull)?;
        let (hs, init) = match E2eInitiatorHandshake::start(
            &self.identity.get().x25519_private,
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
            docs,
            replaces,
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
            mut state,
        } = self
            .table
            .take_pending_for_resp(*receiver_index, &src, now.instant)
        else {
            return;
        };
        let key = (peer, network);
        // A replacement of a session that is still there (the 24 hour re-handshake): nobody
        // waits for it, and a failure of it goes to its schedule, not to a caller. One whose
        // session has gone meanwhile is an ordinary dial.
        let replacing = state
            .replaces
            .filter(|_| self.table.slot(&peer, &network).current.is_some());
        let (transport, payload, responder_static) =
            match state.hs.finish(&resp, attached.limits.max_record) {
                Ok(finished) => finished,
                Err(error) => {
                    tracing::debug!(%peer, %error, "an L4 resp did not complete the handshake");
                    self.table.release_index(index);
                    self.resp_failed(&key, replacing, EnsureError::Refused, now);
                    return;
                }
            };
        // protocol.md 9: the supported `e2e_proto` tags travel in the
        // handshake payload so that a downgrade is detected.
        if !payload.e2e_protos.contains(&E2E_PROTO_TAG) {
            tracing::debug!(%peer, "the peer does not speak our L4 protocol");
            self.table.release_index(index);
            self.resp_failed(&key, replacing, EnsureError::Refused, now);
            return;
        }
        let decide = if state.docs {
            decide_initiator_admission_for_docs
        } else {
            decide_initiator_admission
        };
        if let InitiatorAdmission::Refuse { reason } = decide(
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
            self.resp_failed(&key, replacing, EnsureError::Refused, now);
            return;
        }
        if payload.docs_only {
            // The peer will take a push and nothing else. The session is no use
            // to the callers waiting for one, so they are told so, and it is kept
            // aside (protocol.md 5.1, 5.5) for whoever pushes on it.
            self.keep_docs_only_initiator(
                attached,
                index,
                peer,
                network,
                responder_static,
                transport,
                (payload.roster_seq, payload.policy_seq),
                now,
            );
            // For a replacement: no replacement now. The old session carries on (until its
            // documents or the hard cap end it) and the schedule retries.
            self.resp_failed(&key, replacing, EnsureError::DocsOnly, now);
            return;
        }
        // The peer holds the session this one replaces, and says so: continue its streams.
        let transport = match (replacing, payload.held) {
            (Some(tag), Some(held)) if self.replace.continuation => {
                match self.continue_replacement(
                    attached,
                    tag,
                    held,
                    index,
                    (peer, network),
                    responder_static,
                    transport,
                    now,
                ) {
                    Ok(()) => return,
                    Err(transport) => *transport,
                }
            }
            _ => transport,
        };
        if replacing.is_some() {
            tracing::info!(%peer, "replaced an L4 session afresh: its streams are reset (initiator)");
        }
        let (entry, acceptor, task) = self.make_session(
            index,
            peer,
            network,
            responder_static,
            Origin::Initiated,
            transport,
            attached,
            SessionKind::Member,
        );
        let handle = entry.handle.clone();
        match self
            .table
            .install_session(index, peer, network, Role::Initiator, entry, now.instant)
        {
            Ok(installed) => {
                if let Some((_, replaced)) = installed.replaced {
                    release_inbound(&replaced);
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
            peer_static: responder_static,
            role: Role::Initiator,
            epoch: attached.epoch,
            handle: handle.clone(),
            acceptor,
            peer_roster_seq: Some(payload.roster_seq),
            peer_policy_seq: Some(payload.policy_seq),
            docs_only: false,
            relay_principal: false,
        });
        self.resolve_waiters(&key, &handle);
    }

    /// A `resp` that did not lead to a session: a caller waiting for the dial is told, a
    /// replacement goes back to its schedule.
    fn resp_failed(
        &mut self,
        key: &(NodeId, NetworkId),
        replacing: Option<u64>,
        error: EnsureError,
        now: Now,
    ) {
        match replacing {
            Some(tag) => self.replacement_failed(tag, now),
            None => self.fail_waiters(key, error),
        }
    }

    /// The attempt in flight of the replacement of the session of actor `tag` failed: retry by
    /// the schedule.
    fn replacement_failed(&mut self, tag: u64, now: Now) {
        if let Some(schedule) = self
            .ages
            .get_mut(&tag)
            .and_then(|age| age.schedule.as_mut())
        {
            schedule.attempt_failed(now.instant);
        }
    }

    /// The `resp` of a replacement `init` of ours offered `held` (protocol.md 5.2). If it names
    /// the session this node holds as the peer's index for its old session, on this attachment
    /// and with the same static key, and nothing else is under way, **the new transport goes to
    /// the old session's actor** (it sends CONTINUE as the first record on it) and the new index
    /// is installed as an alias that routes the replacement's frames to that actor; the cutover
    /// ends when the actor has accepted CONTINUE_ACK ([`Self::replace_tick`]). Anything else
    /// gives the transport back: the caller starts the replacement afresh, as before.
    #[allow(clippy::too_many_arguments)]
    fn continue_replacement(
        &mut self,
        attached: Attached,
        tag: u64,
        held: u32,
        index: SessionIndex,
        (peer, network): (NodeId, NetworkId),
        responder_static: X25519PublicKey,
        transport: menzil_e2e::E2eTransport,
        now: Now,
    ) -> Result<(), Box<menzil_e2e::E2eTransport>> {
        let Some(age) = self.ages.get(&tag) else {
            return Err(Box::new(transport));
        };
        let current = age.index;
        let slot = self.table.slot(&peer, &network);
        if age.cutover.is_some() || slot.current != Some(current) || slot.alias.is_some() {
            return Err(Box::new(transport));
        }
        let Some(entry) = self.table.get(current) else {
            return Err(Box::new(transport));
        };
        if entry.tag != tag
            || entry.kind != SessionKind::Member
            || entry.is_label()
            || entry.role != Role::Initiator
            || entry.epoch != attached.epoch
            || entry.peer_static != responder_static
            || entry.peer_index != held
        {
            return Err(Box::new(transport));
        }
        // The old session must be one the documents held now still stand behind.
        if session_standing(
            &self.policies,
            &self.rosters,
            &network,
            &peer,
            &entry.peer_static,
            &self.local_node_id,
            self.identity.serial(),
            &self.local_static,
            now.unix,
        )
        .is_err()
        {
            return Err(Box::new(transport));
        }
        let (handle, generation, epoch_ended) = (
            entry.handle.clone(),
            entry.generation,
            Arc::clone(&entry._epoch_ended),
        );
        let (peer_index, handshake_hash) = (transport.peer_index(), *transport.handshake_hash());
        let replacement = handle.hand_over(transport, HandoverRole::Initiator { prior: held });
        let label = Entry {
            handle,
            peer,
            network,
            peer_static: responder_static,
            epoch: attached.epoch,
            generation,
            init: None,
            docs_only: false,
            kind: SessionKind::Member,
            role: Role::Initiator,
            peer_index,
            handshake_hash,
            tag,
            transport_gen: replacement,
            alias: AtomicBool::new(true),
            _epoch_ended: epoch_ended,
        };
        if let Err((error, label)) =
            self.table
                .install_alias(index, peer, network, label, now.instant)
        {
            // Not reachable (looked at a moment ago); the actor has the transport, so end it.
            tracing::warn!(%peer, ?error, "could not install the alias of a continued session");
            label.handle.close(Some(handover_failed_close(
                "the replacement could not be routed",
            )));
            self.end_session(
                current,
                handover_failed_close("the replacement could not be routed"),
            );
            return Ok(());
        }
        if let Some(age) = self.ages.get_mut(&tag) {
            age.cutover = Some(Cutover {
                alias: index,
                generation: replacement,
                since: now.instant,
            });
            if let Some(schedule) = age.schedule.as_mut() {
                schedule.succeeded();
            }
        }
        Ok(())
    }

    /// Installs the initiator side of a docs only session under
    /// [`docs_only_slot`] and announces it on `ready` with `docs_only` set.
    #[allow(clippy::too_many_arguments)]
    fn keep_docs_only_initiator(
        &mut self,
        attached: Attached,
        index: SessionIndex,
        peer: NodeId,
        network: NetworkId,
        peer_static: X25519PublicKey,
        transport: menzil_e2e::E2eTransport,
        peer_seqs: (u64, u64),
        now: Now,
    ) {
        let (entry, acceptor, task) = self.make_session(
            index,
            peer,
            network,
            peer_static,
            Origin::Initiated,
            transport,
            attached,
            SessionKind::DocsOnly,
        );
        let handle = entry.handle.clone();
        match self.table.install_session(
            index,
            peer,
            docs_only_slot(),
            Role::Initiator,
            entry,
            now.instant,
        ) {
            Ok(installed) => {
                if let Some((old, replaced)) = installed.replaced {
                    self.docs_only.remove(&old);
                    release_inbound(&replaced);
                    replaced.handle.close(None);
                }
            }
            Err((error, _)) => {
                tracing::warn!(%peer, ?error, "could not install a docs only session");
                return;
            }
        }
        self.docs_only.insert(
            index,
            DocsOnly {
                role: Role::Initiator,
                peer,
                deadline: now.instant + DOCS_ONLY_LIFETIME,
            },
        );
        tokio::spawn(task);
        let _ = self.ready.send(SessionReady {
            peer,
            network_id: network,
            peer_static,
            role: Role::Initiator,
            epoch: attached.epoch,
            handle,
            acceptor,
            peer_roster_seq: Some(peer_seqs.0),
            peer_policy_seq: Some(peer_seqs.1),
            docs_only: true,
            relay_principal: false,
        });
    }

    // ------------------------------------------------------------------
    // Stopping
    // ------------------------------------------------------------------

    /// Closes everything with `reason` and refuses new work (see
    /// [`RouterHandle::stop`]). Each session is closed and removed in one
    /// step, like one the router replaced: the CLOSE it was told to send
    /// outranks the epoch ending that dropping its entry signals.
    fn on_stop(&mut self, reason: &CloseReason) {
        self.stopping = true;
        for (_, waiting) in std::mem::take(&mut self.waiters) {
            for waiter in waiting {
                let _ = waiter.reply.send(Err(EnsureError::ShuttingDown));
            }
        }
        drop(self.table.remove_pending_where(|_| true));
        self.unsent.clear();
        self.docs_only.clear();
        for index in self.held.keys().copied().collect::<Vec<_>>() {
            self.drop_held(index);
        }
        self.ages.clear();
        for (_, entry) in self.table.remove_where(|_| true) {
            self.closing.insert(entry.tag);
            release_inbound(&entry);
            entry.handle.close(Some(reason.clone()));
        }
    }

    // ------------------------------------------------------------------
    // Sessions' own notices, and the clock
    // ------------------------------------------------------------------

    fn on_notice(&mut self, tag: u64, notice: SessionNotice) {
        if matches!(notice, SessionNotice::Ended) && self.closing.remove(&tag) {
            // A session `on_stop` closed: it is out of the table already.
            return;
        }
        let (generation, first_index) = untag(tag);
        // A continued replacement moves the actor to another table index; its notices keep the
        // tag of the first one.
        let index = self.ages.get(&tag).map_or(first_index, |age| age.index);
        let Some(entry) = self.table.get(index) else {
            return;
        };
        if entry.generation != generation {
            // From a session whose index has since been reused.
            return;
        }
        let key = (entry.peer, entry.network);
        if entry.docs_only {
            // Never promoted, and nobody waits on it: only its end matters.
            if matches!(notice, SessionNotice::Ended) {
                self.docs_only.remove(&index);
                if let Some(Removed::Session { handle, .. }) = self.table.remove(index) {
                    release_inbound(&handle);
                }
            }
            return;
        }
        match notice {
            SessionNotice::FirstRecord => {
                let handle = entry.handle.clone();
                if let Some(Promoted { retired }) = self.table.promote(index) {
                    if let Some((_, old)) = retired {
                        tracing::info!(peer = %key.0, "replaced an L4 session afresh: its streams are reset (responder)");
                        release_inbound(&old);
                        old.handle.close(None);
                    }
                    self.resolve_waiters(&key, &handle);
                }
            }
            SessionNotice::Ended => {
                self.ages.remove(&tag);
                if let Some(Removed::Session { handle, .. }) = self.table.remove(index) {
                    release_inbound(&handle);
                    self.fail_orphans(&key);
                }
            }
        }
    }

    fn on_tick(&mut self, now: Now) {
        self.flush_unsent();
        self.end_docs_only_sessions(now.instant);
        // Before the table's own expiry: a cutover that has just settled must become the
        // session's entry before its alias can time out.
        self.replace_tick(now);
        let expired = self.table.expire(now.instant);
        for (_, pending) in expired.pending {
            if let Some(tag) = pending.replaces
                && self
                    .table
                    .slot(&pending.peer, &pending.network)
                    .current
                    .is_some()
            {
                // A replacement `init` nobody answered: the schedule retries it.
                self.replacement_failed(tag, now);
                continue;
            }
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
                        pending.docs,
                        None,
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
        for (alias, _) in expired.aliases {
            // A cutover that did not settle in time: its replacement index no longer routes,
            // so the session cannot go on (the actor would wait for an ACK that cannot reach
            // it).
            let stuck = self
                .ages
                .iter()
                .find(|(_, age)| age.cutover.as_ref().is_some_and(|c| c.alias == alias))
                .map(|(_, age)| age.index);
            if let Some(index) = stuck {
                tracing::info!("a continued replacement did not settle in time: the session ends");
                self.end_session(
                    index,
                    handover_failed_close("the replacement did not settle in time"),
                );
            }
        }
        for (index, candidate) in expired.candidates {
            release_inbound(&candidate);
            let key = (candidate.peer, candidate.network);
            if self.docs_only.remove(&index).is_some() {
                candidate.handle.close(Some(docs_only_close()));
                continue;
            }
            candidate.handle.close(None);
            self.fail_orphans(&key);
        }
        // Last, so that when a caller's time is up in the same tick as the
        // thing it waited on, the more telling answer (`SessionEnded`) wins.
        self.expire_waiters(now.instant);
    }

    /// The clock's part of the 24 hour replacement (protocol.md 5.2), once a tick:
    ///
    /// * forgets the ages of sessions that are gone and the router-held candidates whose time
    ///   is up (their indices go back to the table);
    /// * ends a session at the hard cap with CLOSE `session_expired` (either side);
    /// * for the chain initiator, confirms a cutover whose CONTINUE_ACK the actor accepted
    ///   ([`L4SessionHandle::settled_generation`]): the replacement's alias becomes the session's
    ///   entry and its age starts again;
    /// * for the chain initiator, sends the replacement `init` when the schedule says so.
    fn replace_tick(&mut self, now: Now) {
        let timeout = self.replace.held_timeout;
        let stale: Vec<SessionIndex> = self
            .held
            .iter()
            .filter(|(_, held)| now.instant.saturating_duration_since(held.created) >= timeout)
            .map(|(&index, _)| index)
            .collect();
        for index in stale {
            tracing::debug!("dropped a replacement candidate that saw no first record in time");
            self.drop_held(index);
        }
        let tags: Vec<u64> = self.ages.keys().copied().collect();
        for tag in tags {
            let Some(age) = self.ages.get(&tag) else {
                continue;
            };
            let (index, peer, network, hard_cap_at) =
                (age.index, age.peer, age.network, age.hard_cap_at);
            let live = self
                .table
                .get(index)
                .is_some_and(|entry| entry.tag == tag && !entry.is_label());
            if !live {
                self.ages.remove(&tag);
                continue;
            }
            if now.instant >= hard_cap_at {
                tracing::info!(%peer, "an L4 session reached its age cap and ends");
                self.ages.remove(&tag);
                if let Some(Removed::Session { handle: entry, .. }) = self.table.remove(index) {
                    release_inbound(&entry);
                    entry.handle.expire();
                    drop(entry);
                    self.fail_orphans(&(peer, network));
                }
                continue;
            }
            // A cutover whose ACK the actor accepted.
            let settled = age.cutover.as_ref().and_then(|cutover| {
                let handle = &self.table.get(index)?.handle;
                (handle.settled_generation() == cutover.generation)
                    .then_some((cutover.alias, cutover.since))
            });
            if let Some((alias, since)) = settled {
                self.commit_cutover(alias, tag, since, true);
                tracing::info!(%peer, "replaced an L4 session: its streams continue (initiator)");
                continue;
            }
            // The replacement `init`, from the schedule.
            let age = self.ages.get_mut(&tag).expect("looked up above");
            if age.cutover.is_some() {
                continue;
            }
            let Some(schedule) = age.schedule.as_mut() else {
                continue;
            };
            if schedule.poll(now.instant) == Poll::Start {
                schedule.begin_attempt(now.instant);
                if !self.begin_replacement(tag, now)
                    && let Some(schedule) = self
                        .ages
                        .get_mut(&tag)
                        .and_then(|age| age.schedule.as_mut())
                {
                    schedule.attempt_failed(now.instant);
                }
            }
        }
    }

    /// Sends the `init` that replaces the full session of actor `tag`, on the attachment the
    /// session belongs to. `false` when nothing was sent (the slot is not in the plain state
    /// a replacement needs, the attachment changed, a standing check failed), which the caller
    /// counts as a failed attempt.
    fn begin_replacement(&mut self, tag: u64, now: Now) -> bool {
        if self.stopping {
            return false;
        }
        let Some(age) = self.ages.get(&tag) else {
            return false;
        };
        let (peer, network, index) = (age.peer, age.network, age.index);
        let slot = self.table.slot(&peer, &network);
        if slot.current != Some(index)
            || slot.pending.is_some()
            || slot.candidate.is_some()
            || slot.alias.is_some()
        {
            return false;
        }
        let epoch = match self.table.get(index) {
            Some(entry) => entry.epoch,
            None => return false,
        };
        if !self.attached.is_some_and(|a| a.epoch == epoch) {
            return false;
        }
        match self.begin_initiation(peer, network, 1, false, Some(tag), now) {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(%peer, %error, "not replacing an L4 session now");
                false
            }
        }
    }

    /// Ends the docs only sessions whose time is up with CLOSE `docs_only`
    /// (protocol.md 5.1).
    fn end_docs_only_sessions(&mut self, now: Instant) {
        let due: Vec<SessionIndex> = self
            .docs_only
            .iter()
            .filter(|(_, docs)| now >= docs.deadline)
            .map(|(&index, _)| index)
            .collect();
        for index in due {
            self.docs_only.remove(&index);
            if let Some(Removed::Session { handle, .. }) = self.table.remove(index) {
                release_inbound(&handle);
                handle.handle.close(Some(docs_only_close()));
            }
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Builds the actor for an established handshake. The caller installs
    /// the returned entry in the table and spawns the task.
    // The flag is one more independent input of a session's construction.
    #[allow(clippy::too_many_arguments)]
    fn make_session(
        &mut self,
        index: SessionIndex,
        peer: NodeId,
        network: NetworkId,
        peer_static: X25519PublicKey,
        origin: Origin,
        transport: menzil_e2e::E2eTransport,
        attached: Attached,
        kind: SessionKind,
    ) -> (Entry, L4SessionAcceptor, SessionTask) {
        let docs_only = kind == SessionKind::DocsOnly;
        let (mode, init, role) = match origin {
            Origin::Initiated => (Mode::Client, None, Role::Initiator),
            Origin::Answered {
                sender_index,
                noise_msg1,
            } => (
                Mode::Server,
                Some((sender_index, noise_msg1)),
                Role::Responder,
            ),
        };
        let peer_index = transport.peer_index();
        let handshake_hash = *transport.handshake_hash();
        let generation = self.next_generation;
        self.next_generation = self.next_generation.wrapping_add(1);
        let (epoch_ended_tx, epoch_ended_rx) = oneshot::channel();
        let config = L4SessionConfig {
            transport,
            peer,
            network_id: network,
            mode,
            max_record: attached.limits.max_record,
            epoch: attached.epoch,
            send_budget: self.budgets.for_peer(peer),
            inbound_budget: self.inbound_budget,
            node_inbound: Some(Arc::clone(&self.node_inbound)),
            observer: Some(SessionObserver::new(
                self.notices.clone(),
                tag_of(generation, index),
            )),
        };
        // Datagram channels (protocol.md 5.4) belong to member sessions only: a docs only
        // session serves one `menzil:docs` push and the relay principal's session serves public
        // shares, so both drop every datagram.
        let (handle, acceptor, task): (_, _, SessionTask) = match kind {
            SessionKind::Member => {
                let (h, a, t) =
                    new_l4_session_with_datagrams(config, self.outbound.clone(), epoch_ended_rx);
                (h, a, Box::pin(t))
            }
            SessionKind::DocsOnly | SessionKind::RelayPrincipal => {
                let (h, a, t) = new_l4_session(config, self.outbound.clone(), epoch_ended_rx);
                (h, a, Box::pin(t))
            }
        };
        let tag = tag_of(generation, index);
        if kind == SessionKind::Member {
            // Both sides end a full member session at the hard cap; the chain initiator also
            // replaces it from a schedule (protocol.md 5.2). A docs only session ends after
            // thirty seconds, the relay principal's with its attachment (slice R4).
            let started = Now::capture().instant;
            let schedule = (role == Role::Initiator).then(|| {
                let max = self.replace.durations.max_jitter;
                ReplaceSchedule::with_durations(
                    started,
                    Duration::from_secs_f64(fastrand::f64() * max.as_secs_f64()),
                    self.replace.durations.clone(),
                )
            });
            self.ages.insert(
                tag,
                Age {
                    index,
                    peer,
                    network,
                    started,
                    hard_cap_at: started + self.replace.durations.hard_cap,
                    schedule,
                    cutover: None,
                },
            );
        }
        (
            Entry {
                handle,
                peer,
                network,
                peer_static,
                epoch: attached.epoch,
                generation,
                init,
                docs_only,
                kind,
                role,
                peer_index,
                handshake_hash,
                tag,
                transport_gen: FIRST_GENERATION,
                alias: AtomicBool::new(false),
                _epoch_ended: Arc::new(epoch_ended_tx),
            },
            acceptor,
            task,
        )
    }

    /// Sends one L4 frame as an epoch-tagged reliable SEND. Never waits, but
    /// does not lose the frame to a full `outbound` either: the session
    /// actors share that channel, and with bulk transfers running over a
    /// slow link it is full for stretches, so a frame it has no room for
    /// waits in [`Self::unsent`] (behind anything already waiting there, so
    /// frames keep their order) and goes out on a later tick.
    fn send(&mut self, dst: NodeId, epoch: Epoch, payload: Vec<u8>) {
        drop(self.send_gated(dst, epoch, payload));
    }

    /// [`Self::send`]; when the frame had to wait in [`Self::unsent`], the receiver that
    /// resolves once it has been put into `outbound` (or dropped, which resolves it with an
    /// error). A responder holds its session task back until then: the task writes to
    /// `outbound` itself, so a `resp` waiting in `unsent` would otherwise be overtaken by the
    /// session's first `data` record (the initiator would see data before its `resp`). `None`
    /// when the frame was placed at once: nothing can overtake it.
    fn send_gated(
        &mut self,
        dst: NodeId,
        epoch: Epoch,
        payload: Vec<u8>,
    ) -> Option<oneshot::Receiver<()>> {
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
            return Some(self.hold_back(request));
        }
        match self.outbound.try_send(request) {
            Ok(()) => None,
            Err(mpsc::error::TrySendError::Full(request)) => Some(self.hold_back(request)),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!(%dst, "the L3 session is gone; an L4 handshake frame is dropped");
                None
            }
        }
    }

    fn hold_back(&mut self, request: OutboundSend) -> oneshot::Receiver<()> {
        if self.unsent.len() >= MAX_UNSENT {
            self.unsent.pop_front();
            tracing::debug!("dropped the oldest held back L4 handshake frame");
        }
        let (placed, placed_rx) = oneshot::channel();
        self.unsent.push_back((request, placed));
        placed_rx
    }

    /// Sends the held back frames, oldest first, until the channel is full
    /// again.
    fn flush_unsent(&mut self) {
        while let Some((request, placed)) = self.unsent.pop_front() {
            match self.outbound.try_send(request) {
                Ok(()) => {
                    let _ = placed.send(());
                }
                Err(mpsc::error::TrySendError::Full(request)) => {
                    self.unsent.push_front((request, placed));
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
    let mut events_open = true;
    let mut dropped_log = LogThrottle::new();
    // Who waits for the sessions `Command::Stop` closed to end.
    let mut stop_done: Vec<oneshot::Sender<()>> = Vec::new();
    loop {
        tokio::select! {
            event = events.recv(), if events_open => {
                let Some(event) = event else {
                    if engine.stopping {
                        // The L3 session ended because it was told to (a
                        // graceful stop): the callers that ask now are still
                        // told why, until every handle is gone.
                        events_open = false;
                        continue;
                    }
                    break;
                };
                match event {
                    SessionEvent::Attached { epoch, limits, relay_static } => {
                        engine.on_attached(epoch, limits, relay_static);
                        forward(&passthrough, SessionEvent::Attached { epoch, limits, relay_static }, &mut dropped_log);
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
                    Some(Command::Ensure { peer, network_id, docs, reply }) => {
                        engine.ensure(peer, network_id, docs, reply, Now::capture());
                    }
                    Some(Command::Standing { peer, network_id, reply }) => {
                        let _ = reply.send(engine.has_standing_session(peer, network_id, Now::capture()));
                    }
                    Some(Command::Stop { reason, done }) => {
                        engine.on_stop(&reason);
                        stop_done.push(done);
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
        if engine.stopping && engine.closing.is_empty() {
            for done in stop_done.drain(..) {
                let _ = done.send(());
            }
        }
        if !events_open && !commands_open {
            break;
        }
    }
}

/// Why a CONTINUE was refused ([`Engine::continue_verdict`]).
enum ContinueRefusal {
    /// A check of the CONTINUE against the slot failed; the text says which.
    Mismatch(&'static str),
    /// A party is not in good standing by the documents held now.
    Standing,
}

/// The CLOSE of a handover that did not match (protocol.md 5.2, `handover_failed`).
fn handover_failed_close(why: &str) -> CloseReason {
    CloseReason {
        code: ErrorCode::HandoverFailed,
        msg: why.to_string(),
    }
}

/// The CLOSE that ends a docs only session (protocol.md 5.1).
fn docs_only_close() -> CloseReason {
    CloseReason {
        code: ErrorCode::DocsOnly,
        msg: "docs only session over".to_string(),
    }
}

/// The CLOSE of a session whose standing is gone (protocol.md 5.3): one reason for every
/// cause, the detail stays in the local log (TOBEDECIDED 30 T1).
pub(crate) fn grant_removed_close() -> CloseReason {
    CloseReason {
        code: ErrorCode::GrantRemoved,
        msg: "grant removed".to_string(),
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
