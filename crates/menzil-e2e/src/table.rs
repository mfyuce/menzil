//! The L4 peer/session table (TODO.md L4e1): local session indices, which
//! of a peer's handshakes and sessions is which, the simultaneous-open
//! tie-break, replacement of an established session, and per-peer handshake
//! rate limiting (protocol.md 5.1, 5.2).
//!
//! **Sans-IO, and generic over what it routes to.** The table owns no
//! transport and no handshake state of its own: `H` is whatever the caller
//! routes decrypted-or-not `data` frames to (in `menzil-node`, a handle on
//! the per-session actor) and `P` is whatever the caller needs back when an
//! initiation resolves or is abandoned (the `E2eInitiatorHandshake`, plus
//! whoever is waiting on it). Time (`now`) and randomness (the index
//! source) are passed in, so a test needs neither a clock nor a
//! generator. It says what to do with a frame; it never touches one.
//!
//! **Indices.** Every `init`, `resp` and `data` frame is routed by a
//! 32-bit index the *receiver* chose (protocol.md 5.1). One namespace
//! holds all of this node's: an index is `Reserved` (taken, handshake in
//! flight), `Pending` (our `init` sent, `resp` awaited) or a `Session`.
//! They come from the caller's source (random in production) and are
//! retried on collision, so two live things never share one. An index is
//! only a routing label (every frame is authenticated, so guessing one buys
//! an injector nothing); random ones keep a stale frame addressed to an
//! earlier session from being routed to a new one, and keep the index from
//! counting this node's sessions.
//!
//! **Slots.** A peer and a network name a *slot* (protocol.md 5.1: every
//! authorization is scoped to one network, and the network is in the
//! prologue), holding at most one `current` session (the one to send on),
//! one `candidate` (a responder-side session still waiting for its first
//! `data` record to decrypt) and one `pending` initiation. `pending` and
//! `candidate` never coexist, so there is never a question which of two
//! unproven sessions a slot is waiting on: [`SessionTable::register_pending`]
//! refuses while a candidate exists and installing a responder session
//! abandons a pending initiation.
//!
//! **Simultaneous open** (protocol.md 5.1: "the session initiated by the
//! lower NodeId (byte wise) is kept"). When an `init` arrives while we have
//! a pending initiation to the same peer in the same network, the side with
//! the lower NodeId wins: if that is us we ignore their `init` (they will
//! abandon theirs when ours reaches them), otherwise we answer theirs and
//! our pending initiation is abandoned **when their session is installed**,
//! not when their `init` is first seen: an `init` that then fails the
//! handshake or the membership checks must not cost us a legitimate
//! initiation. The abandoned state is handed back so whoever waited on it
//! can wait on the new session instead. Not handled, deliberately: an `init`
//! from the higher side that was already in flight when the lower side's
//! own initiation completed arrives with no pending left to resolve; it is
//! answered as a replacement, creates a candidate that never sees data and
//! expires after `candidate_timeout`. Harmless, bounded by the rate limit,
//! and not worth a grace period.
//!
//! **Replacement** (protocol.md 5.1, 5.2: "A responder keeps its current
//! session with a peer until a data record on the new session decrypts").
//! A responder-side session always starts as a `candidate`, and routes
//! `data` like any session, but is not offered for sending until
//! [`SessionTable::promote`] (called when the first record on it
//! authenticates) makes it `current` and hands the old one back as
//! `retired`. An initiator-side session is `current` the moment its `resp`
//! authenticates (that decryption is the proof), and the old `current`, if
//! any, comes back as `replaced` at once. **That is the one place this
//! table takes a side on TOBEDECIDED item 6**: the old session is not kept
//! receive-valid for a grace period after an initiator-side replacement. It
//! need not be under "every stream resets daily" (the old session's streams
//! die with it either way, which is the only behavior the current wire can
//! express), and "streams survive" is a change to the handshake payload
//! that has not been decided; TODO.md L4e2 adds the grace period if item 6
//! needs one.
//!
//! **Authenticating the source.** [`SessionTable::route`] refuses a `data`
//! frame whose RECV `src` is not the peer that session belongs to
//! (protocol.md 5.1: dialed NodeId, RECV source and prologue must agree).
//! A relay can still *replay* or reorder frames of a real session; that is
//! the reliable-class counter's job, one layer down.
//!
//! **Bounded.** At most [`TableConfig::max_entries`] entries of any kind;
//! unproven state expires ([`SessionTable::expire`]); and `init` floods are
//! turned away by the per-peer [`HandshakeLimiter`] before any handshake
//! work is done.

use std::collections::HashMap;
use std::collections::hash_map::Entry as MapEntry;
use std::time::{Duration, Instant};

use menzil_proto::{NetworkId, NodeId};

use crate::limiter::{
    DEFAULT_HANDSHAKE_WINDOW, DEFAULT_HANDSHAKES_PER_WINDOW, DEFAULT_MAX_TRACKED_PEERS,
    HandshakeLimiter,
};

/// A node's own name for a session: the `receiver_index` peers put in the
/// frames they send it.
pub type SessionIndex = u32;

/// How many random indices [`SessionTable::reserve_index`] tries before
/// giving up. With a working source and at most a few thousand entries in a
/// 2^32 space a second try is already vanishingly rare; this only bounds the
/// loop against a broken source.
const MAX_INDEX_ATTEMPTS: u32 = 32;

/// The knobs of a [`SessionTable`]. Every default is this project's own
/// choice except the handshake limit (protocol.md 5.1: 10 per minute per
/// peer), which the spec names; protocol.md says nothing about the rest.
#[derive(Debug, Clone)]
pub struct TableConfig {
    /// Entries of every kind (reserved, pending, sessions). Default 4096.
    pub max_entries: usize,
    /// How long a reserved index may sit without being installed or
    /// released before [`SessionTable::expire`] takes it back. Default 10 s.
    pub reservation_timeout: Duration,
    /// How long an `init` of ours may wait for its `resp`. Default 10 s,
    /// the same as protocol.md 5.3's OPEN timeout.
    pub pending_timeout: Duration,
    /// How long a responder-side session may wait for its first `data`
    /// record. The initiator's session actor sends its first record the
    /// moment it starts, so this is long. Default 30 s.
    pub candidate_timeout: Duration,
    /// Inbound `init`s allowed per peer per [`Self::handshake_window`].
    /// Default 10 (protocol.md 5.1).
    pub handshakes_per_window: usize,
    /// The window for [`Self::handshakes_per_window`]. Default 60 s.
    pub handshake_window: Duration,
    /// Distinct peers the limiter tracks. Default 4096.
    pub max_tracked_peers: usize,
}

impl Default for TableConfig {
    fn default() -> Self {
        Self {
            max_entries: 4096,
            reservation_timeout: Duration::from_secs(10),
            pending_timeout: Duration::from_secs(10),
            candidate_timeout: Duration::from_secs(30),
            handshakes_per_window: DEFAULT_HANDSHAKES_PER_WINDOW,
            handshake_window: DEFAULT_HANDSHAKE_WINDOW,
            max_tracked_peers: DEFAULT_MAX_TRACKED_PEERS,
        }
    }
}

/// Which side of the handshake this node was for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We sent the `init`.
    Initiator,
    /// We answered it.
    Responder,
}

/// Whether a session is the one to send on yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// Offered for sending ([`SessionTable::current`]).
    Current,
    /// A responder-side session still waiting for its first record to
    /// decrypt ([`SessionTable::promote`]).
    Candidate,
}

/// Why the table could not allocate or accept something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TableError {
    /// [`TableConfig::max_entries`] reached.
    #[error("the session table is full")]
    Full,
    /// The index source returned only indices already in use, several times
    /// in a row: a broken source, not a busy table.
    #[error("no free session index after repeated attempts")]
    NoFreeIndex,
}

/// Why [`SessionTable::register_pending`] or [`SessionTable::install_session`]
/// refused. In every case the index it was given is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The index is not one this table reserved for the caller (never
    /// reserved, expired, or already used).
    #[error("that index is not reserved")]
    NotReserved,
    /// The peer is this node.
    #[error("cannot open a session to ourselves")]
    SelfPeer,
    /// An initiation to this peer in this network is already pending: wait
    /// for it ([`SessionTable::slot`]) instead of starting another.
    #[error("an initiation to this peer in this network is already pending")]
    AlreadyPending,
    /// The peer's own `init` already created a candidate session here: wait
    /// for it to be promoted instead of starting a competing one.
    #[error("a session from this peer in this network is already awaiting its first record")]
    CandidateExists,
}

/// What a slot currently holds. See the module docs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SlotState {
    /// The session to send on.
    pub current: Option<SessionIndex>,
    /// A responder-side session waiting for its first record.
    pub candidate: Option<SessionIndex>,
    /// Our own `init`, awaiting a `resp`.
    pub pending: Option<SessionIndex>,
}

/// Why an inbound `init` is not to be answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgnoreReason {
    /// The `init` claims to come from this node itself.
    SelfPeer,
    /// The peer exceeded its handshake rate limit.
    RateLimited,
    /// Both sides initiated and this node's NodeId is the lower one, so its
    /// own initiation is the one kept (protocol.md 5.1).
    SimultaneousOpenWeWin,
    /// The table is full.
    Full,
}

/// What to do with an inbound `init`: the cheap decision, made before any
/// Diffie Hellman is spent on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitDecision {
    /// Run the handshake and, if it and the membership checks pass,
    /// [`SessionTable::reserve_index`] and
    /// [`SessionTable::install_session`] the result.
    Respond {
        /// A session with this peer in this network is already `current`:
        /// the new one will replace it once it is promoted.
        replaces_current: bool,
        /// We have a pending initiation to this peer which installing the
        /// new session will abandon (we lost the tie-break).
        abandons_pending: bool,
    },
    /// Drop it silently.
    Ignore(IgnoreReason),
}

/// What [`SessionTable::take_pending_for_resp`] found for an incoming
/// `resp`.
#[derive(Debug)]
pub enum RespLookup<P> {
    /// Our pending initiation. It is no longer pending; its index stays
    /// reserved for the caller to [`SessionTable::install_session`] under
    /// (or [`SessionTable::release_index`]).
    Matched {
        /// The index (the `sender_index` we sent in `init`).
        index: SessionIndex,
        /// The peer it was for.
        peer: NodeId,
        /// The network it was for.
        network: NetworkId,
        /// What the caller registered with it.
        state: P,
    },
    /// No pending initiation has that index.
    Unknown,
    /// The index is a pending initiation, but to a different peer than the
    /// one the `resp` came from. Left pending.
    WrongSource,
}

/// Where a `data` frame goes.
#[derive(Debug)]
pub enum Route<'a, H> {
    /// The session it belongs to.
    Session {
        /// The index (the frame's own `receiver_index`).
        index: SessionIndex,
        /// The handle registered with it.
        handle: &'a H,
        /// Whether it is already the session to send on.
        status: SessionStatus,
    },
    /// No session has that index.
    Unknown,
    /// The index is a session, but of a different peer than the frame's
    /// RECV `src`. Drop it.
    WrongSource,
}

/// What installing a session displaced.
#[derive(Debug)]
pub struct Installed<H, P> {
    /// An initiator-side install: the previous `current` session, now gone
    /// from the table. End it.
    pub replaced: Option<(SessionIndex, H)>,
    /// A responder-side install: our own pending initiation to this peer,
    /// abandoned because we lost the tie-break. Whoever waited on it should
    /// wait on the new session.
    pub abandoned: Option<(SessionIndex, P)>,
    /// A responder-side install: an earlier candidate that never saw a
    /// record, superseded by this one. End it.
    pub superseded_candidate: Option<(SessionIndex, H)>,
}

/// What [`SessionTable::promote`] did.
#[derive(Debug)]
pub struct Promoted<H> {
    /// The session that was `current` before, now gone from the table.
    /// End it.
    pub retired: Option<(SessionIndex, H)>,
}

/// What [`SessionTable::remove`] took out.
#[derive(Debug)]
pub enum Removed<H, P> {
    /// An index that was reserved but never installed.
    Reserved,
    /// A pending initiation, abandoned.
    Pending(P),
    /// A session.
    Session {
        /// The handle registered with it.
        handle: H,
        /// Which side we were.
        role: Role,
        /// Whether it had been promoted.
        status: SessionStatus,
    },
}

/// What [`SessionTable::expire`] gave up on.
#[derive(Debug)]
pub struct Expired<H, P> {
    /// Initiations that never got a `resp`.
    pub pending: Vec<(SessionIndex, P)>,
    /// Responder-side sessions that never saw a record. End them.
    pub candidates: Vec<(SessionIndex, H)>,
}

impl<H, P> Default for Expired<H, P> {
    fn default() -> Self {
        Self {
            pending: Vec::new(),
            candidates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SlotKey {
    peer: NodeId,
    network: NetworkId,
}

#[derive(Debug, Default)]
struct Slot {
    current: Option<SessionIndex>,
    candidate: Option<SessionIndex>,
    pending: Option<SessionIndex>,
}

impl Slot {
    fn is_empty(&self) -> bool {
        self.current.is_none() && self.candidate.is_none() && self.pending.is_none()
    }
}

#[derive(Debug)]
enum Entry<H, P> {
    Reserved {
        since: Instant,
    },
    Pending {
        key: SlotKey,
        since: Instant,
        state: P,
    },
    Session {
        key: SlotKey,
        role: Role,
        status: SessionStatus,
        since: Instant,
        handle: H,
    },
}

/// See the module docs.
pub struct SessionTable<H, P> {
    local: NodeId,
    config: TableConfig,
    index_source: Box<dyn FnMut() -> u32 + Send>,
    entries: HashMap<SessionIndex, Entry<H, P>>,
    slots: HashMap<SlotKey, Slot>,
    limiter: HandshakeLimiter,
}

impl<H, P> std::fmt::Debug for SessionTable<H, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionTable")
            .field("entries", &self.entries.len())
            .field("slots", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl<H, P> SessionTable<H, P> {
    /// A table for the node `local`. `index_source` supplies candidate
    /// session indices; it should be random (see the module docs) and need
    /// not avoid collisions, the table retries.
    pub fn new(
        local: NodeId,
        config: TableConfig,
        index_source: impl FnMut() -> u32 + Send + 'static,
    ) -> Self {
        let limiter = HandshakeLimiter::new(
            config.handshakes_per_window,
            config.handshake_window,
            config.max_tracked_peers,
        );
        Self {
            local,
            config,
            index_source: Box::new(index_source),
            entries: HashMap::new(),
            slots: HashMap::new(),
            limiter,
        }
    }

    // ------------------------------------------------------------------
    // Indices
    // ------------------------------------------------------------------

    /// Takes a free index and holds it for the caller, who must follow with
    /// [`Self::register_pending`], [`Self::install_session`] or
    /// [`Self::release_index`] (an index that is not, comes back by itself
    /// after [`TableConfig::reservation_timeout`]).
    pub fn reserve_index(&mut self, now: Instant) -> Result<SessionIndex, TableError> {
        if self.entries.len() >= self.config.max_entries {
            return Err(TableError::Full);
        }
        for _ in 0..MAX_INDEX_ATTEMPTS {
            let candidate = (self.index_source)();
            if let MapEntry::Vacant(slot) = self.entries.entry(candidate) {
                slot.insert(Entry::Reserved { since: now });
                return Ok(candidate);
            }
        }
        Err(TableError::NoFreeIndex)
    }

    /// Gives back an index that [`Self::reserve_index`] handed out and the
    /// caller did not use. Does nothing for any other index.
    pub fn release_index(&mut self, index: SessionIndex) {
        if matches!(self.entries.get(&index), Some(Entry::Reserved { .. })) {
            self.entries.remove(&index);
        }
    }

    // ------------------------------------------------------------------
    // Our own initiations
    // ------------------------------------------------------------------

    /// What `peer` and `network` currently have: the caller's guide to
    /// whether to initiate, wait or just send.
    pub fn slot(&self, peer: &NodeId, network: &NetworkId) -> SlotState {
        self.slots
            .get(&SlotKey {
                peer: *peer,
                network: *network,
            })
            .map_or_else(SlotState::default, |slot| SlotState {
                current: slot.current,
                candidate: slot.candidate,
                pending: slot.pending,
            })
    }

    /// The session to send on for `peer` in `network`, if there is one.
    pub fn current(&self, peer: &NodeId, network: &NetworkId) -> Option<(SessionIndex, &H)> {
        let index = self.slot(peer, network).current?;
        match self.entries.get(&index) {
            Some(Entry::Session { handle, .. }) => Some((index, handle)),
            _ => None,
        }
    }

    /// Records that our `init` went out under `index` (from
    /// [`Self::reserve_index`]), with whatever `state` the caller needs
    /// when it resolves. On refusal the index is released and `state` is
    /// handed back.
    pub fn register_pending(
        &mut self,
        index: SessionIndex,
        peer: NodeId,
        network: NetworkId,
        state: P,
        now: Instant,
    ) -> Result<(), (RegisterError, P)> {
        if !matches!(self.entries.get(&index), Some(Entry::Reserved { .. })) {
            return Err((RegisterError::NotReserved, state));
        }
        let refusal = if peer == self.local {
            Some(RegisterError::SelfPeer)
        } else {
            let key = SlotKey { peer, network };
            match self.slots.get(&key) {
                Some(slot) if slot.pending.is_some() => Some(RegisterError::AlreadyPending),
                Some(slot) if slot.candidate.is_some() => Some(RegisterError::CandidateExists),
                _ => None,
            }
        };
        if let Some(error) = refusal {
            self.entries.remove(&index);
            return Err((error, state));
        }
        let key = SlotKey { peer, network };
        self.slots.entry(key).or_default().pending = Some(index);
        self.entries.insert(
            index,
            Entry::Pending {
                key,
                since: now,
                state,
            },
        );
        Ok(())
    }

    /// Matches an incoming `resp` (whose `receiver_index` echoes the index we
    /// sent in `init`) from RECV `src` to our pending initiation. A match
    /// stops being pending and its index becomes reserved for the caller to
    /// finish the handshake under; a `resp` from the wrong peer leaves the
    /// initiation pending.
    pub fn take_pending_for_resp(
        &mut self,
        echoed_index: SessionIndex,
        src: &NodeId,
        now: Instant,
    ) -> RespLookup<P> {
        let key = match self.entries.get(&echoed_index) {
            Some(Entry::Pending { key, .. }) => *key,
            _ => return RespLookup::Unknown,
        };
        if key.peer != *src {
            return RespLookup::WrongSource;
        }
        let Some(Entry::Pending { state, .. }) = self
            .entries
            .insert(echoed_index, Entry::Reserved { since: now })
        else {
            unreachable!("the entry was just seen to be Pending");
        };
        self.clear_slot_pending(&key, echoed_index);
        RespLookup::Matched {
            index: echoed_index,
            peer: key.peer,
            network: key.network,
            state,
        }
    }

    // ------------------------------------------------------------------
    // Inbound init
    // ------------------------------------------------------------------

    /// The decision for an inbound `init` from RECV `src` in `network`:
    /// rate limit, self, tie-break. Counts against the peer's handshake
    /// limit whatever it decides after that. Changes nothing else; see the
    /// module docs for why the tie-break's losing side is only abandoned
    /// later, by [`Self::install_session`].
    pub fn on_inbound_init(
        &mut self,
        peer: NodeId,
        network: NetworkId,
        now: Instant,
    ) -> InitDecision {
        if peer == self.local {
            return InitDecision::Ignore(IgnoreReason::SelfPeer);
        }
        if !self.limiter.allow(&peer, now) {
            return InitDecision::Ignore(IgnoreReason::RateLimited);
        }
        let slot = self.slots.get(&SlotKey { peer, network });
        let abandons_pending = slot.is_some_and(|slot| slot.pending.is_some());
        if abandons_pending && self.local.as_ref() < peer.as_ref() {
            return InitDecision::Ignore(IgnoreReason::SimultaneousOpenWeWin);
        }
        if self.entries.len() >= self.config.max_entries {
            return InitDecision::Ignore(IgnoreReason::Full);
        }
        InitDecision::Respond {
            replaces_current: slot.is_some_and(|slot| slot.current.is_some()),
            abandons_pending,
        }
    }

    // ------------------------------------------------------------------
    // Sessions
    // ------------------------------------------------------------------

    /// Turns a reserved index (from [`Self::reserve_index`], or handed
    /// back by [`Self::take_pending_for_resp`]) into a session with `peer`
    /// in `network`, registered with `handle`. What it displaces comes back
    /// in [`Installed`]. On refusal the index is released and `handle`
    /// handed back.
    ///
    /// As [`Role::Initiator`] the session is `current` at once and the old
    /// `current` is replaced. As [`Role::Responder`] it is a `candidate`
    /// (the old `current` stays), an older candidate is superseded, and our
    /// own pending initiation to this peer, if any, is abandoned.
    pub fn install_session(
        &mut self,
        index: SessionIndex,
        peer: NodeId,
        network: NetworkId,
        role: Role,
        handle: H,
        now: Instant,
    ) -> Result<Installed<H, P>, (RegisterError, H)> {
        if !matches!(self.entries.get(&index), Some(Entry::Reserved { .. })) {
            return Err((RegisterError::NotReserved, handle));
        }
        if peer == self.local {
            self.entries.remove(&index);
            return Err((RegisterError::SelfPeer, handle));
        }
        let key = SlotKey { peer, network };
        let mut installed = Installed {
            replaced: None,
            abandoned: None,
            superseded_candidate: None,
        };
        match role {
            Role::Initiator => {
                let old = self.slots.entry(key).or_default().current.replace(index);
                installed.replaced = old.and_then(|old| self.take_session(old));
                self.entries.insert(
                    index,
                    Entry::Session {
                        key,
                        role,
                        status: SessionStatus::Current,
                        since: now,
                        handle,
                    },
                );
            }
            Role::Responder => {
                let slot = self.slots.entry(key).or_default();
                let pending = slot.pending.take();
                let candidate = slot.candidate.replace(index);
                installed.abandoned =
                    pending.and_then(|pending| match self.entries.remove(&pending) {
                        Some(Entry::Pending { state, .. }) => Some((pending, state)),
                        _ => None,
                    });
                installed.superseded_candidate =
                    candidate.and_then(|candidate| self.take_session(candidate));
                self.entries.insert(
                    index,
                    Entry::Session {
                        key,
                        role,
                        status: SessionStatus::Candidate,
                        since: now,
                        handle,
                    },
                );
            }
        }
        Ok(installed)
    }

    /// Routes an incoming `data` frame: `receiver_index` is the frame's,
    /// `src` the RECV source.
    pub fn route(&self, receiver_index: SessionIndex, src: &NodeId) -> Route<'_, H> {
        match self.entries.get(&receiver_index) {
            Some(Entry::Session {
                key,
                status,
                handle,
                ..
            }) => {
                if key.peer == *src {
                    Route::Session {
                        index: receiver_index,
                        handle,
                        status: *status,
                    }
                } else {
                    Route::WrongSource
                }
            }
            _ => Route::Unknown,
        }
    }

    /// The first record on candidate `index` authenticated: it becomes the
    /// session to send on, and the one it replaces is handed back to end.
    /// `None` if `index` is not a candidate (already promoted, gone, or
    /// not a session).
    pub fn promote(&mut self, index: SessionIndex) -> Option<Promoted<H>> {
        let key = match self.entries.get_mut(&index) {
            Some(Entry::Session { key, status, .. }) if *status == SessionStatus::Candidate => {
                *status = SessionStatus::Current;
                *key
            }
            _ => return None,
        };
        let slot = self
            .slots
            .get_mut(&key)
            .expect("a session entry always has its slot");
        debug_assert_eq!(slot.candidate, Some(index));
        slot.candidate = None;
        let old = slot.current.replace(index);
        Some(Promoted {
            retired: old.and_then(|old| self.take_session(old)),
        })
    }

    // ------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------

    /// Removes whatever `index` is: the caller learned a session actor
    /// ended, or gave up on an initiation.
    pub fn remove(&mut self, index: SessionIndex) -> Option<Removed<H, P>> {
        match self.entries.remove(&index)? {
            Entry::Reserved { .. } => Some(Removed::Reserved),
            Entry::Pending { key, state, .. } => {
                self.clear_slot_pending(&key, index);
                Some(Removed::Pending(state))
            }
            Entry::Session {
                key,
                role,
                status,
                handle,
                ..
            } => {
                self.clear_slot_session(&key, index);
                Some(Removed::Session {
                    handle,
                    role,
                    status,
                })
            }
        }
    }

    /// Removes every session whose handle `pred` accepts and returns them
    /// (e.g. everything pinned to an L3 attachment that just ended, which
    /// the caller encodes in `H`). Pending initiations are not touched:
    /// they carry no handle, and [`Self::expire`] gets them.
    pub fn remove_where(&mut self, mut pred: impl FnMut(&H) -> bool) -> Vec<(SessionIndex, H)> {
        let doomed: Vec<SessionIndex> = self
            .entries
            .iter()
            .filter_map(|(&index, entry)| match entry {
                Entry::Session { handle, .. } if pred(handle) => Some(index),
                _ => None,
            })
            .collect();
        doomed
            .into_iter()
            .filter_map(|index| self.take_session(index))
            .collect()
    }

    /// The handle registered for session `index`, if `index` is a session.
    pub fn get(&self, index: SessionIndex) -> Option<&H> {
        match self.entries.get(&index) {
            Some(Entry::Session { handle, .. }) => Some(handle),
            _ => None,
        }
    }

    /// Removes every pending initiation whose state `pred` accepts and
    /// returns them (e.g. everything sent under an L3 attachment that just
    /// ended: its `resp` can no longer arrive). The counterpart of
    /// [`Self::remove_where`], which leaves pending initiations alone.
    pub fn remove_pending_where(
        &mut self,
        mut pred: impl FnMut(&P) -> bool,
    ) -> Vec<(SessionIndex, P)> {
        let doomed: Vec<SessionIndex> = self
            .entries
            .iter()
            .filter_map(|(&index, entry)| match entry {
                Entry::Pending { state, .. } if pred(state) => Some(index),
                _ => None,
            })
            .collect();
        doomed
            .into_iter()
            .filter_map(|index| match self.remove(index) {
                Some(Removed::Pending(state)) => Some((index, state)),
                _ => None,
            })
            .collect()
    }

    /// Gives up on everything unproven for longer than its timeout, and
    /// forgets limiter entries that expired. Returns what the caller must
    /// act on.
    pub fn expire(&mut self, now: Instant) -> Expired<H, P> {
        self.limiter.sweep(now);
        let mut reserved = Vec::new();
        let mut pending = Vec::new();
        let mut candidates = Vec::new();
        for (&index, entry) in &self.entries {
            let (since, timeout, bucket) = match entry {
                Entry::Reserved { since } => (*since, self.config.reservation_timeout, 0),
                Entry::Pending { since, .. } => (*since, self.config.pending_timeout, 1),
                Entry::Session {
                    since,
                    status: SessionStatus::Candidate,
                    ..
                } => (*since, self.config.candidate_timeout, 2),
                Entry::Session { .. } => continue,
            };
            if now.saturating_duration_since(since) >= timeout {
                match bucket {
                    0 => reserved.push(index),
                    1 => pending.push(index),
                    _ => candidates.push(index),
                }
            }
        }
        for index in reserved {
            self.entries.remove(&index);
        }
        let mut expired = Expired::default();
        for index in pending {
            if let Some(Removed::Pending(state)) = self.remove(index) {
                expired.pending.push((index, state));
            }
        }
        for index in candidates {
            if let Some(session) = self.take_session(index) {
                expired.candidates.push(session);
            }
        }
        expired
    }

    /// Entries of every kind.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is held at all (no entries, no slots).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.slots.is_empty()
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /// Removes session `index` from `entries` and from its slot, returning
    /// its handle (paired with the index for the callers that collect them).
    fn take_session(&mut self, index: SessionIndex) -> Option<(SessionIndex, H)> {
        match self.entries.remove(&index)? {
            Entry::Session { key, handle, .. } => {
                self.clear_slot_session(&key, index);
                Some((index, handle))
            }
            other => {
                // Not a session: put it back untouched.
                self.entries.insert(index, other);
                None
            }
        }
    }

    fn clear_slot_pending(&mut self, key: &SlotKey, index: SessionIndex) {
        if let Some(slot) = self.slots.get_mut(key) {
            if slot.pending == Some(index) {
                slot.pending = None;
            }
            if slot.is_empty() {
                self.slots.remove(key);
            }
        }
    }

    fn clear_slot_session(&mut self, key: &SlotKey, index: SessionIndex) {
        if let Some(slot) = self.slots.get_mut(key) {
            if slot.current == Some(index) {
                slot.current = None;
            }
            if slot.candidate == Some(index) {
                slot.candidate = None;
            }
            if slot.is_empty() {
                self.slots.remove(key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Table = SessionTable<u32, &'static str>;

    fn id(seed: u8) -> NodeId {
        NodeId::from([seed; 32])
    }

    fn net(seed: u8) -> NetworkId {
        NetworkId::from([seed; 32])
    }

    /// 101, 102, 103, ...: never collides with itself, so a test that is
    /// not about collisions never meets one.
    fn counter() -> impl FnMut() -> u32 + Send + 'static {
        let mut n = 100;
        move || {
            n += 1;
            n
        }
    }

    fn table_for(local: NodeId) -> Table {
        SessionTable::new(local, TableConfig::default(), counter())
    }

    fn table() -> Table {
        table_for(id(1))
    }

    /// Every promise the module docs make about how the maps relate, checked
    /// after each operation of the longer tests.
    fn check_invariants(t: &Table) {
        for (key, slot) in &t.slots {
            assert!(!slot.is_empty(), "an empty slot was kept");
            assert!(
                !(slot.pending.is_some() && slot.candidate.is_some()),
                "pending and candidate coexist"
            );
            if let Some(i) = slot.current {
                match t.entries.get(&i) {
                    Some(Entry::Session {
                        key: k,
                        status: SessionStatus::Current,
                        ..
                    }) => assert_eq!(k, key),
                    other => panic!("slot.current {i} points at {other:?}"),
                }
            }
            if let Some(i) = slot.candidate {
                match t.entries.get(&i) {
                    Some(Entry::Session {
                        key: k,
                        status: SessionStatus::Candidate,
                        ..
                    }) => assert_eq!(k, key),
                    other => panic!("slot.candidate {i} points at {other:?}"),
                }
            }
            if let Some(i) = slot.pending {
                match t.entries.get(&i) {
                    Some(Entry::Pending { key: k, .. }) => assert_eq!(k, key),
                    other => panic!("slot.pending {i} points at {other:?}"),
                }
            }
        }
        for (&i, entry) in &t.entries {
            match entry {
                Entry::Reserved { .. } => {}
                Entry::Pending { key, .. } => {
                    assert_eq!(t.slots.get(key).and_then(|s| s.pending), Some(i));
                }
                Entry::Session { key, status, .. } => {
                    let slot = t.slots.get(key).expect("a session has its slot");
                    match status {
                        SessionStatus::Current => assert_eq!(slot.current, Some(i)),
                        SessionStatus::Candidate => assert_eq!(slot.candidate, Some(i)),
                    }
                }
            }
        }
        assert!(t.entries.len() <= t.config.max_entries);
    }

    fn pending(t: &mut Table, peer: NodeId, network: NetworkId, now: Instant) -> SessionIndex {
        let index = t.reserve_index(now).unwrap();
        t.register_pending(index, peer, network, "pending", now)
            .map_err(|(e, _)| e)
            .unwrap();
        index
    }

    fn session(
        t: &mut Table,
        peer: NodeId,
        network: NetworkId,
        role: Role,
        handle: u32,
        now: Instant,
    ) -> (SessionIndex, Installed<u32, &'static str>) {
        let index = t.reserve_index(now).unwrap();
        let installed = t
            .install_session(index, peer, network, role, handle, now)
            .map_err(|(e, _)| e)
            .unwrap();
        check_invariants(t);
        (index, installed)
    }

    // --- indices ---------------------------------------------------------

    #[test]
    fn a_colliding_index_is_retried_not_handed_out_twice() {
        let mut seq = vec![5u32, 5, 5, 6].into_iter();
        let mut t: Table = SessionTable::new(id(1), TableConfig::default(), move || {
            seq.next().expect("the test supplies enough")
        });
        let now = Instant::now();
        assert_eq!(t.reserve_index(now), Ok(5));
        assert_eq!(t.reserve_index(now), Ok(6), "5 is taken, so it tries again");
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn a_source_that_only_collides_gives_up_instead_of_looping() {
        let mut t: Table = SessionTable::new(id(1), TableConfig::default(), || 7);
        let now = Instant::now();
        assert_eq!(t.reserve_index(now), Ok(7));
        assert_eq!(t.reserve_index(now), Err(TableError::NoFreeIndex));
    }

    #[test]
    fn the_table_refuses_to_grow_past_max_entries() {
        let mut t: Table = SessionTable::new(
            id(1),
            TableConfig {
                max_entries: 2,
                ..TableConfig::default()
            },
            counter(),
        );
        let now = Instant::now();
        t.reserve_index(now).unwrap();
        t.reserve_index(now).unwrap();
        assert_eq!(t.reserve_index(now), Err(TableError::Full));
    }

    #[test]
    fn release_index_frees_a_reservation_and_touches_nothing_else() {
        let mut t = table();
        let now = Instant::now();
        let reserved = t.reserve_index(now).unwrap();
        let pending_index = pending(&mut t, id(2), net(9), now);
        let (session_index, _) = session(&mut t, id(3), net(9), Role::Initiator, 1, now);
        t.release_index(pending_index);
        t.release_index(session_index);
        t.release_index(999);
        assert_eq!(t.len(), 3, "only a reservation can be released");
        t.release_index(reserved);
        assert_eq!(t.len(), 2);
        check_invariants(&t);
    }

    #[test]
    fn an_unused_reservation_comes_back_by_itself() {
        let mut t = table();
        let t0 = Instant::now();
        t.reserve_index(t0).unwrap();
        assert!(t.expire(t0 + Duration::from_secs(9)).pending.is_empty());
        assert_eq!(t.len(), 1);
        t.expire(t0 + Duration::from_secs(10));
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
    }

    // --- our own initiations ---------------------------------------------

    #[test]
    fn register_pending_needs_a_reserved_index_and_hands_the_state_back_when_refused() {
        let mut t = table();
        let now = Instant::now();
        let (error, state) = t
            .register_pending(42, id(2), net(9), "state", now)
            .unwrap_err();
        assert_eq!(error, RegisterError::NotReserved);
        assert_eq!(state, "state");
        assert!(t.is_empty());
    }

    #[test]
    fn a_second_initiation_to_the_same_peer_and_network_is_refused_and_its_index_released() {
        let mut t = table();
        let now = Instant::now();
        let first = pending(&mut t, id(2), net(9), now);
        let second = t.reserve_index(now).unwrap();
        let (error, state) = t
            .register_pending(second, id(2), net(9), "again", now)
            .unwrap_err();
        assert_eq!(error, RegisterError::AlreadyPending);
        assert_eq!(state, "again");
        assert_eq!(t.len(), 1, "the refused index is released");
        assert_eq!(t.slot(&id(2), &net(9)).pending, Some(first));
        // Another network, or another peer, is a different slot.
        pending(&mut t, id(2), net(8), now);
        pending(&mut t, id(3), net(9), now);
        check_invariants(&t);
    }

    #[test]
    fn we_do_not_initiate_to_ourselves() {
        let mut t = table();
        let now = Instant::now();
        let index = t.reserve_index(now).unwrap();
        let (error, _) = t
            .register_pending(index, id(1), net(9), "me", now)
            .unwrap_err();
        assert_eq!(error, RegisterError::SelfPeer);
        let index = t.reserve_index(now).unwrap();
        let (error, _) = t
            .install_session(index, id(1), net(9), Role::Initiator, 7, now)
            .unwrap_err();
        assert_eq!(error, RegisterError::SelfPeer);
        assert!(t.is_empty());
    }

    #[test]
    fn we_do_not_initiate_over_a_candidate_the_peers_own_init_created() {
        let mut t = table();
        let now = Instant::now();
        session(&mut t, id(2), net(9), Role::Responder, 1, now);
        let index = t.reserve_index(now).unwrap();
        let (error, _) = t
            .register_pending(index, id(2), net(9), "late", now)
            .unwrap_err();
        assert_eq!(error, RegisterError::CandidateExists);
        check_invariants(&t);
    }

    #[test]
    fn a_resp_from_the_right_peer_resolves_the_initiation_and_the_index_stays_ours() {
        let mut t = table();
        let now = Instant::now();
        let index = pending(&mut t, id(2), net(9), now);
        match t.take_pending_for_resp(index, &id(2), now) {
            RespLookup::Matched {
                index: i,
                peer,
                network,
                state,
            } => {
                assert_eq!((i, peer, network, state), (index, id(2), net(9), "pending"));
            }
            other => panic!("expected a match, got {other:?}"),
        }
        assert_eq!(t.slot(&id(2), &net(9)), SlotState::default());
        // Reserved for the caller to finish under; a second resp finds nothing.
        assert!(matches!(
            t.take_pending_for_resp(index, &id(2), now),
            RespLookup::Unknown
        ));
        let installed = t
            .install_session(index, id(2), net(9), Role::Initiator, 11, now)
            .map_err(|(e, _)| e)
            .unwrap();
        assert!(installed.replaced.is_none());
        assert_eq!(t.current(&id(2), &net(9)), Some((index, &11)));
        check_invariants(&t);
    }

    #[test]
    fn a_resp_from_another_peer_does_not_consume_the_initiation() {
        let mut t = table();
        let now = Instant::now();
        let index = pending(&mut t, id(2), net(9), now);
        assert!(matches!(
            t.take_pending_for_resp(index, &id(3), now),
            RespLookup::WrongSource
        ));
        assert_eq!(t.slot(&id(2), &net(9)).pending, Some(index));
        assert!(matches!(
            t.take_pending_for_resp(index, &id(2), now),
            RespLookup::Matched { .. }
        ));
    }

    #[test]
    fn a_resp_naming_anything_but_a_pending_initiation_is_unknown() {
        let mut t = table();
        let now = Instant::now();
        let reserved = t.reserve_index(now).unwrap();
        let (established, _) = session(&mut t, id(2), net(9), Role::Initiator, 1, now);
        for index in [reserved, established, 424242] {
            assert!(matches!(
                t.take_pending_for_resp(index, &id(2), now),
                RespLookup::Unknown
            ));
        }
    }

    #[test]
    fn an_initiator_session_replaces_the_previous_current_at_once() {
        let mut t = table();
        let now = Instant::now();
        let (old, _) = session(&mut t, id(2), net(9), Role::Initiator, 1, now);
        let (new, installed) = session(&mut t, id(2), net(9), Role::Initiator, 2, now);
        assert_eq!(installed.replaced, Some((old, 1)));
        assert_eq!(t.current(&id(2), &net(9)), Some((new, &2)));
        assert!(matches!(t.route(old, &id(2)), Route::Unknown));
        assert_eq!(t.len(), 1);
    }

    // --- inbound init ------------------------------------------------------

    #[test]
    fn a_fresh_init_is_answered() {
        let mut t = table();
        assert_eq!(
            t.on_inbound_init(id(2), net(9), Instant::now()),
            InitDecision::Respond {
                replaces_current: false,
                abandons_pending: false
            }
        );
    }

    #[test]
    fn an_init_from_ourselves_is_ignored() {
        let mut t = table();
        assert_eq!(
            t.on_inbound_init(id(1), net(9), Instant::now()),
            InitDecision::Ignore(IgnoreReason::SelfPeer)
        );
    }

    #[test]
    fn an_eleventh_init_in_a_minute_from_one_peer_is_ignored() {
        let mut t = table();
        let t0 = Instant::now();
        for i in 0..10 {
            assert!(
                matches!(
                    t.on_inbound_init(id(2), net(9), t0 + Duration::from_secs(i)),
                    InitDecision::Respond { .. }
                ),
                "init {i}"
            );
        }
        assert_eq!(
            t.on_inbound_init(id(2), net(9), t0 + Duration::from_secs(20)),
            InitDecision::Ignore(IgnoreReason::RateLimited)
        );
        // Another peer, and the same peer a window later, are unaffected.
        assert!(matches!(
            t.on_inbound_init(id(3), net(9), t0 + Duration::from_secs(20)),
            InitDecision::Respond { .. }
        ));
        assert!(matches!(
            t.on_inbound_init(id(2), net(9), t0 + Duration::from_secs(60)),
            InitDecision::Respond { .. }
        ));
    }

    #[test]
    fn the_limit_is_per_peer_across_networks() {
        // The cost being rationed is the peer's handshakes, whatever
        // network each one names.
        let mut t = table();
        let t0 = Instant::now();
        for network in 0..10 {
            assert!(matches!(
                t.on_inbound_init(id(2), net(network), t0),
                InitDecision::Respond { .. }
            ));
        }
        assert_eq!(
            t.on_inbound_init(id(2), net(77), t0),
            InitDecision::Ignore(IgnoreReason::RateLimited)
        );
    }

    #[test]
    fn an_init_over_an_established_session_is_a_replacement() {
        let mut t = table();
        let now = Instant::now();
        session(&mut t, id(2), net(9), Role::Initiator, 1, now);
        assert_eq!(
            t.on_inbound_init(id(2), net(9), now),
            InitDecision::Respond {
                replaces_current: true,
                abandons_pending: false
            }
        );
        // Not for a different network.
        assert_eq!(
            t.on_inbound_init(id(2), net(8), now),
            InitDecision::Respond {
                replaces_current: false,
                abandons_pending: false
            }
        );
    }

    #[test]
    fn a_full_table_ignores_inits() {
        let mut t: Table = SessionTable::new(
            id(1),
            TableConfig {
                max_entries: 1,
                ..TableConfig::default()
            },
            counter(),
        );
        let now = Instant::now();
        t.reserve_index(now).unwrap();
        assert_eq!(
            t.on_inbound_init(id(2), net(9), now),
            InitDecision::Ignore(IgnoreReason::Full)
        );
    }

    // --- simultaneous open -------------------------------------------------

    #[test]
    fn the_lower_node_id_keeps_its_own_initiation() {
        // id(1) < id(2) byte-wise, and we are id(1): ours wins.
        let mut t = table_for(id(1));
        let now = Instant::now();
        let index = pending(&mut t, id(2), net(9), now);
        assert_eq!(
            t.on_inbound_init(id(2), net(9), now),
            InitDecision::Ignore(IgnoreReason::SimultaneousOpenWeWin)
        );
        assert_eq!(
            t.slot(&id(2), &net(9)).pending,
            Some(index),
            "ours is untouched"
        );
        check_invariants(&t);
    }

    #[test]
    fn the_higher_node_id_answers_and_loses_its_own_initiation_only_when_the_session_is_installed()
    {
        let mut t = table_for(id(2));
        let now = Instant::now();
        let ours = pending(&mut t, id(1), net(9), now);
        assert_eq!(
            t.on_inbound_init(id(1), net(9), now),
            InitDecision::Respond {
                replaces_current: false,
                abandons_pending: true
            }
        );
        // Deciding to answer changes nothing yet: if their init then fails
        // the handshake or the membership checks, our initiation stands.
        assert_eq!(t.slot(&id(1), &net(9)).pending, Some(ours));
        let (theirs, installed) = session(&mut t, id(1), net(9), Role::Responder, 5, now);
        assert_eq!(installed.abandoned, Some((ours, "pending")));
        assert_eq!(t.slot(&id(1), &net(9)).pending, None);
        assert_eq!(t.slot(&id(1), &net(9)).candidate, Some(theirs));
    }

    #[test]
    fn byte_order_decides_by_the_first_differing_byte_of_the_whole_node_id() {
        let mut low = [7u8; 32];
        let mut high = [7u8; 32];
        low[31] = 1;
        high[31] = 2;
        let (low, high) = (NodeId::from(low), NodeId::from(high));
        let now = Instant::now();

        let mut at_low = table_for(low);
        pending(&mut at_low, high, net(9), now);
        assert_eq!(
            at_low.on_inbound_init(high, net(9), now),
            InitDecision::Ignore(IgnoreReason::SimultaneousOpenWeWin)
        );

        let mut at_high = table_for(high);
        pending(&mut at_high, low, net(9), now);
        assert!(matches!(
            at_high.on_inbound_init(low, net(9), now),
            InitDecision::Respond {
                abandons_pending: true,
                ..
            }
        ));
    }

    #[test]
    fn two_nodes_that_initiate_at_once_end_up_with_the_lower_ones_session_and_nothing_else() {
        // The property the tie-break exists for, end to end across two
        // tables: both sides initiate, both `init`s cross, and each side
        // ends up with exactly one session, the one the lower NodeId made.
        let (low_id, high_id) = (id(1), id(2));
        let mut low = table_for(low_id);
        let mut high = table_for(high_id);
        let n = net(9);
        let now = Instant::now();

        let low_index = pending(&mut low, high_id, n, now);
        let high_index = pending(&mut high, low_id, n, now);

        // The two `init`s cross.
        let at_low = low.on_inbound_init(high_id, n, now);
        let at_high = high.on_inbound_init(low_id, n, now);
        assert_eq!(
            at_low,
            InitDecision::Ignore(IgnoreReason::SimultaneousOpenWeWin)
        );
        assert!(matches!(
            at_high,
            InitDecision::Respond {
                abandons_pending: true,
                ..
            }
        ));

        // High answers low's init as the responder, abandoning its own.
        let (high_local, installed) = session(&mut high, low_id, n, Role::Responder, 20, now);
        assert_eq!(installed.abandoned.map(|(i, _)| i), Some(high_index));

        // Low gets high's `resp` for its own initiation and completes it.
        let RespLookup::Matched { index, .. } = low.take_pending_for_resp(low_index, &high_id, now)
        else {
            panic!("low's initiation must still be there to resolve");
        };
        low.install_session(index, high_id, n, Role::Initiator, 10, now)
            .map_err(|(e, _)| e)
            .unwrap();

        // Low's first record reaches high: the candidate is promoted.
        assert!(matches!(
            high.route(high_local, &low_id),
            Route::Session {
                status: SessionStatus::Candidate,
                ..
            }
        ));
        let promoted = high.promote(high_local).unwrap();
        assert!(promoted.retired.is_none());

        for (table, peer) in [(&low, high_id), (&high, low_id)] {
            check_invariants(table);
            assert_eq!(table.len(), 1, "one session per side, nothing left over");
            assert_eq!(table.slot(&peer, &n).pending, None);
            assert_eq!(table.slot(&peer, &n).candidate, None);
            assert!(table.slot(&peer, &n).current.is_some());
        }
    }

    // --- replacement and promotion ----------------------------------------

    #[test]
    fn a_responder_session_waits_as_a_candidate_until_its_first_record() {
        let mut t = table();
        let now = Instant::now();
        let (index, _) = session(&mut t, id(2), net(9), Role::Responder, 3, now);
        assert_eq!(
            t.current(&id(2), &net(9)),
            None,
            "not offered for sending yet"
        );
        match t.route(index, &id(2)) {
            Route::Session {
                index: i,
                handle,
                status,
            } => assert_eq!((i, *handle, status), (index, 3, SessionStatus::Candidate)),
            other => panic!("expected the candidate, got {other:?}"),
        }
        let promoted = t.promote(index).unwrap();
        assert!(promoted.retired.is_none());
        assert_eq!(t.current(&id(2), &net(9)), Some((index, &3)));
        assert!(t.promote(index).is_none(), "already promoted");
        check_invariants(&t);
    }

    #[test]
    fn the_old_session_stays_current_until_the_new_one_is_promoted_and_is_then_retired() {
        let mut t = table();
        let now = Instant::now();
        let (old, _) = session(&mut t, id(2), net(9), Role::Initiator, 1, now);
        let (new, installed) = session(&mut t, id(2), net(9), Role::Responder, 2, now);
        assert!(installed.replaced.is_none() && installed.superseded_candidate.is_none());
        // Both route; the old one is still the one to send on.
        assert_eq!(t.current(&id(2), &net(9)), Some((old, &1)));
        assert!(matches!(t.route(old, &id(2)), Route::Session { .. }));
        assert!(matches!(t.route(new, &id(2)), Route::Session { .. }));

        let promoted = t.promote(new).unwrap();
        assert_eq!(promoted.retired, Some((old, 1)));
        assert_eq!(t.current(&id(2), &net(9)), Some((new, &2)));
        assert!(matches!(t.route(old, &id(2)), Route::Unknown));
        assert_eq!(t.len(), 1);
        check_invariants(&t);
    }

    #[test]
    fn a_newer_candidate_supersedes_one_that_never_saw_a_record() {
        let mut t = table();
        let now = Instant::now();
        let (first, _) = session(&mut t, id(2), net(9), Role::Responder, 1, now);
        let (second, installed) = session(&mut t, id(2), net(9), Role::Responder, 2, now);
        assert_eq!(installed.superseded_candidate, Some((first, 1)));
        assert_eq!(t.slot(&id(2), &net(9)).candidate, Some(second));
        assert!(matches!(t.route(first, &id(2)), Route::Unknown));
    }

    #[test]
    fn promote_only_acts_on_a_candidate() {
        let mut t = table();
        let now = Instant::now();
        let reserved = t.reserve_index(now).unwrap();
        let pending_index = pending(&mut t, id(2), net(9), now);
        let (current, _) = session(&mut t, id(3), net(9), Role::Initiator, 1, now);
        for index in [reserved, pending_index, current, 99999] {
            assert!(t.promote(index).is_none());
        }
        check_invariants(&t);
    }

    // --- routing ------------------------------------------------------------

    #[test]
    fn data_is_only_routed_from_the_peer_the_session_belongs_to() {
        let mut t = table();
        let now = Instant::now();
        let (index, _) = session(&mut t, id(2), net(9), Role::Initiator, 1, now);
        assert!(matches!(t.route(index, &id(2)), Route::Session { .. }));
        assert!(matches!(t.route(index, &id(3)), Route::WrongSource));
        assert!(matches!(t.route(index + 1, &id(2)), Route::Unknown));
    }

    #[test]
    fn data_for_a_pending_or_reserved_index_is_unknown() {
        let mut t = table();
        let now = Instant::now();
        let reserved = t.reserve_index(now).unwrap();
        let pending_index = pending(&mut t, id(2), net(9), now);
        assert!(matches!(t.route(reserved, &id(2)), Route::Unknown));
        assert!(matches!(t.route(pending_index, &id(2)), Route::Unknown));
    }

    // --- lifecycle ----------------------------------------------------------

    #[test]
    fn remove_takes_out_each_kind_and_leaves_no_slot_behind() {
        let mut t = table();
        let now = Instant::now();
        let reserved = t.reserve_index(now).unwrap();
        let pending_index = pending(&mut t, id(2), net(9), now);
        let (current, _) = session(&mut t, id(3), net(9), Role::Initiator, 1, now);
        let (candidate, _) = session(&mut t, id(4), net(9), Role::Responder, 2, now);

        assert!(matches!(t.remove(reserved), Some(Removed::Reserved)));
        assert!(matches!(
            t.remove(pending_index),
            Some(Removed::Pending("pending"))
        ));
        assert!(matches!(
            t.remove(current),
            Some(Removed::Session {
                handle: 1,
                role: Role::Initiator,
                status: SessionStatus::Current
            })
        ));
        assert!(matches!(
            t.remove(candidate),
            Some(Removed::Session {
                handle: 2,
                role: Role::Responder,
                status: SessionStatus::Candidate
            })
        ));
        assert!(t.remove(candidate).is_none());
        assert!(t.is_empty(), "no entry and no slot left over");
    }

    #[test]
    fn remove_where_takes_out_matching_sessions_and_nothing_else() {
        let mut t = table();
        let now = Instant::now();
        let (a, _) = session(&mut t, id(2), net(9), Role::Initiator, 10, now);
        let (b, _) = session(&mut t, id(3), net(9), Role::Initiator, 11, now);
        let (c, _) = session(&mut t, id(4), net(9), Role::Responder, 12, now);
        let pending_index = pending(&mut t, id(5), net(9), now);

        let mut removed = t.remove_where(|handle| *handle >= 11);
        removed.sort();
        assert_eq!(
            removed,
            vec![
                (b.min(c), if b < c { 11 } else { 12 }),
                (b.max(c), if b < c { 12 } else { 11 })
            ]
        );
        assert!(matches!(t.route(a, &id(2)), Route::Session { .. }));
        assert_eq!(t.slot(&id(5), &net(9)).pending, Some(pending_index));
        check_invariants(&t);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn expire_gives_up_on_unproven_state_after_its_timeout_and_never_on_a_current_session() {
        let mut t = table();
        let t0 = Instant::now();
        let pending_index = pending(&mut t, id(2), net(9), t0);
        let (candidate, _) = session(&mut t, id(3), net(9), Role::Responder, 7, t0);
        let (current, _) = session(&mut t, id(4), net(9), Role::Initiator, 8, t0);

        let early = t.expire(t0 + Duration::from_secs(9));
        assert!(early.pending.is_empty() && early.candidates.is_empty());

        let at_pending_timeout = t.expire(t0 + Duration::from_secs(10));
        assert_eq!(at_pending_timeout.pending, vec![(pending_index, "pending")]);
        assert!(at_pending_timeout.candidates.is_empty());
        assert_eq!(t.slot(&id(2), &net(9)), SlotState::default());

        let at_candidate_timeout = t.expire(t0 + Duration::from_secs(30));
        assert_eq!(at_candidate_timeout.candidates, vec![(candidate, 7)]);

        let much_later = t.expire(t0 + Duration::from_secs(86_400));
        assert!(much_later.pending.is_empty() && much_later.candidates.is_empty());
        assert!(matches!(t.route(current, &id(4)), Route::Session { .. }));
        check_invariants(&t);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn a_promoted_candidate_is_no_longer_subject_to_the_candidate_timeout() {
        let mut t = table();
        let t0 = Instant::now();
        let (index, _) = session(&mut t, id(2), net(9), Role::Responder, 1, t0);
        t.promote(index).unwrap();
        let expired = t.expire(t0 + Duration::from_secs(3600));
        assert!(expired.candidates.is_empty());
        assert_eq!(t.current(&id(2), &net(9)), Some((index, &1)));
    }

    #[test]
    fn get_returns_the_handle_of_a_session_and_nothing_else() {
        let mut t = table();
        let now = Instant::now();
        let reserved = t.reserve_index(now).unwrap();
        let pending_index = pending(&mut t, id(2), net(9), now);
        let (current, _) = session(&mut t, id(3), net(9), Role::Initiator, 11, now);
        let (candidate, _) = session(&mut t, id(4), net(9), Role::Responder, 12, now);
        assert_eq!(t.get(current), Some(&11));
        assert_eq!(t.get(candidate), Some(&12));
        assert_eq!(t.get(reserved), None);
        assert_eq!(t.get(pending_index), None);
        assert_eq!(t.get(424242), None);
    }

    #[test]
    fn remove_pending_where_takes_matching_initiations_and_leaves_sessions_alone() {
        let mut t = table();
        let now = Instant::now();
        let keep = t.reserve_index(now).unwrap();
        t.register_pending(keep, id(2), net(9), "keep", now)
            .map_err(|(e, _)| e)
            .unwrap();
        let drop_a = t.reserve_index(now).unwrap();
        t.register_pending(drop_a, id(3), net(9), "drop", now)
            .map_err(|(e, _)| e)
            .unwrap();
        let drop_b = t.reserve_index(now).unwrap();
        t.register_pending(drop_b, id(4), net(9), "drop", now)
            .map_err(|(e, _)| e)
            .unwrap();
        let (established, _) = session(&mut t, id(5), net(9), Role::Initiator, 1, now);

        let mut removed = t.remove_pending_where(|state| *state == "drop");
        removed.sort();
        let mut expected = vec![(drop_a, "drop"), (drop_b, "drop")];
        expected.sort();
        assert_eq!(removed, expected);
        assert_eq!(t.slot(&id(2), &net(9)).pending, Some(keep));
        assert_eq!(t.slot(&id(3), &net(9)), SlotState::default());
        assert!(matches!(
            t.route(established, &id(5)),
            Route::Session { .. }
        ));
        check_invariants(&t);
        assert_eq!(t.len(), 2);
    }

    // --- a long random walk -------------------------------------------------

    /// xorshift64*: enough randomness for a walk, and reproducible by seed
    /// without depending on a particular `rand` API.
    struct Walk(u64);
    impl Walk {
        fn next(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            (self.0.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 33) as usize % bound
        }
    }

    #[test]
    fn the_table_stays_consistent_through_a_long_random_walk() {
        for seed in 1..=8u64 {
            let mut rng = Walk(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut source = Walk(seed ^ 0xDEAD_BEEF);
            // A small index space makes collisions and reuse common.
            let mut t: Table = SessionTable::new(
                id(5),
                TableConfig {
                    max_entries: 24,
                    ..TableConfig::default()
                },
                move || source.next(40) as u32,
            );
            let t0 = Instant::now();
            let mut now = t0;
            let mut reserved: Vec<SessionIndex> = Vec::new();
            let mut live: Vec<SessionIndex> = Vec::new();
            for step in 0..3000u32 {
                now += Duration::from_millis(rng.next(4000) as u64);
                let peer = id(1 + rng.next(8) as u8); // includes our own id(5)
                let network = net(rng.next(3) as u8);
                match rng.next(10) {
                    0 | 1 => {
                        if let Ok(index) = t.reserve_index(now) {
                            reserved.push(index);
                        }
                    }
                    2 => {
                        if let Some(index) = reserved.pop() {
                            let _ = t.register_pending(index, peer, network, "p", now);
                            live.push(index);
                        }
                    }
                    3 => {
                        if let Some(index) = reserved.pop() {
                            let role = if rng.next(2) == 0 {
                                Role::Initiator
                            } else {
                                Role::Responder
                            };
                            let _ = t.install_session(index, peer, network, role, step, now);
                            live.push(index);
                        }
                    }
                    4 => {
                        if !live.is_empty() {
                            let index = live[rng.next(live.len())];
                            if let RespLookup::Matched { index, .. } =
                                t.take_pending_for_resp(index, &peer, now)
                            {
                                reserved.push(index);
                            }
                        }
                    }
                    5 => {
                        if !live.is_empty() {
                            let index = live[rng.next(live.len())];
                            let _ = t.promote(index);
                        }
                    }
                    6 => {
                        if !live.is_empty() {
                            let index = live.swap_remove(rng.next(live.len()));
                            let _ = t.remove(index);
                        }
                    }
                    7 => {
                        let _ = t.remove_where(|handle| handle % 3 == 0);
                    }
                    8 => {
                        let _ = t.expire(now);
                    }
                    _ => {
                        let _ = t.on_inbound_init(peer, network, now);
                    }
                }
                check_invariants(&t);
            }
            // Whatever is left can be removed, leaving nothing behind.
            for index in 0..40u32 {
                let _ = t.remove(index);
            }
            assert!(t.is_empty(), "seed {seed}: {t:?}");
        }
    }
}
