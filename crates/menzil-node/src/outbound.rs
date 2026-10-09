//! Node-side outbound SEND queueing and credit accounting (protocol.md
//! 4.2's flow-control paragraph, this node's own side of it) — the gap
//! `session`'s own module doc comment already pointed at (TODO.md
//! L3g, L4): nothing before this let a caller send anything into a
//! running L3 session at all. Pure logic, no I/O:
//! [`crate::session::Session`] drains [`OutboundQueue::next_ready_to_send`]
//! and actually writes to the wire; this only decides what is ready and
//! in what order, mirroring `menzil_session::CreditLedger` and
//! `session::Engine`'s own no-I/O discipline.
//!
//! One shared FIFO across every destination, not a queue per peer: a
//! scan-and-skip strategy (find the first sendable item, not necessarily
//! the front) keeps one credit-exhausted peer from blocking a different
//! peer's traffic without needing a round-robin cursor across however
//! many peers happen to be active. Within one destination's own sends,
//! order is still strict FIFO: once the earliest queued item for a
//! destination is found not sendable, every later item for that same
//! destination is skipped too in the same scan, not just that one item —
//! otherwise a smaller, later reliable send could pass a larger, earlier
//! one the moment credit covers the smaller but not yet the larger,
//! reordering class-0 traffic protocol.md 5.2 requires to arrive
//! contiguous (TODO.md L4b's own review, live-reproduced against a real
//! relay). A droppable item is never blocked by an earlier reliable
//! item for the same destination, or vice versa: the two classes use
//! independent counters end to end (protocol.md 5.2), so there is
//! nothing to preserve order *between* them, only within each.
//!
//! Admission (`enqueue`) bounds three things, all using the same
//! `QueuedSend::charge` (not a send's raw `payload.len()` — TODO.md
//! L4b's own review, finding 9: counting the unfloored length let an
//! unbounded number of near-empty sends occupy real memory while
//! reporting zero budget used) — a per-record size cap
//! ([`OutboundQueue::max_payload`], below what the wire can carry at
//! all), a per-destination occupancy cap ([`MAX_QUEUED_BYTES_PER_DST`],
//! so one congested peer cannot consume the whole shared budget and
//! block *admission* for every other peer, not only drain ordering —
//! the same review, finding 2), and the shared [`MAX_QUEUED_BYTES`]
//! total as a last-resort memory bound. This is simpler than
//! `menzil-relay::forward`'s own two-tier design on purpose: that
//! module lets reliable skip its occupancy check entirely, gated by
//! credit alone — a choice that makes sense at relay scale, where many
//! concurrent (source, destination) pairs each holding their own
//! credit-bounded queue could otherwise be bounded only by their
//! number, not a single shared cap. A node's own peer count is small
//! enough in practice that the simpler, uniform rule is preferred here
//! instead, and is called out explicitly since it is a real, deliberate
//! difference from the precedent, not an oversight.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use menzil_proto::{MIN_SEND_CHARGE_BYTES, NodeId, Record, max_send_payload};
use menzil_session::CreditLedger;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

/// One attachment to the relay (protocol.md 5.1's path pinning), counting
/// from 1 and incrementing on every successful
/// [`crate::session::Session::connect`] within one
/// [`crate::session::run_session`] call; never reused or decremented. An
/// L4 session built on top belongs to exactly the epoch it was opened
/// under — see [`crate::session::SessionEvent::Attached`] — and must end
/// rather than silently carry over to a later one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Epoch(u64);

impl Epoch {
    /// The well-known value for this node's very first attachment —
    /// also the value a caller should tag an [`OutboundSend`] with when
    /// queueing it before ever having observed a
    /// [`crate::session::SessionEvent::Attached`] at all (e.g. a probe
    /// sent before the node has dialed for the first time): correct as
    /// long as that first attachment is still outstanding, and safely
    /// refused with [`EnqueueOutcome::WrongEpoch`] rather than silently
    /// sent if a reconnect actually happened before it was drained.
    pub fn first() -> Self {
        Epoch(1)
    }

    /// The next attachment's epoch; only [`crate::session::run_session`]
    /// itself calls this, once per detach — a caller always learns its
    /// current epoch from an `Attached` event, never by predicting one.
    pub(crate) fn next(self) -> Self {
        Epoch(self.0 + 1)
    }
}

/// Total bytes this queue holds across every destination before a
/// further reliable enqueue is refused, and beyond which a droppable
/// enqueue is silently dropped instead. This crate's own choice,
/// mirroring `menzil-relay::forward::MAX_QUEUE_BYTES`'s 4 MiB: a relay
/// would not accept more than that from any one (source, destination)
/// pair anyway, so holding more than that locally, waiting to send,
/// could never actually be delivered regardless.
pub(crate) const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

/// Each destination's own share of [`MAX_QUEUED_BYTES`], capped
/// separately so one congested peer cannot consume the whole shared
/// budget and block *admission* for every other peer (TODO.md L4b's own
/// review, finding 2, live-reproduced against a real relay). Deliberately
/// *not* tied to WELCOME's own `limits.credit`
/// (`OutboundQueue::initial_credit`): a relay may configure that
/// arbitrarily small, and this queue's own admission rule must still
/// hold at least one minimum-charge item per destination regardless (a
/// cap smaller than [`MIN_SEND_CHARGE_BYTES`] would refuse every send
/// for a low-credit peer outright, defeating the entire point of
/// queueing one to wait for more credit rather than refusing it).
///
/// Three quarters, not a flat quarter — the same review's own live
/// measurement is why: an even split across a hypothetical 4 peers
/// noticeably *worsened* the single-busy-peer case (far more drops than
/// the old, unbounded-per-peer behavior ever produced, since one busy
/// peer using the old scheme could occupy the entire shared budget by
/// itself). Three quarters still leaves a full quarter — 1 MiB at the
/// default [`MAX_QUEUED_BYTES`] — guaranteed for *every other* peer
/// combined, closing the cross-peer starvation finding 2 is actually
/// about, while a single busy peer keeps nearly all of its old headroom.
/// This remains a real, documented trade-off, not a complete fix: the
/// deeper gap the same review measured — a refused or dropped send had
/// no way to tell its caller beyond a log line, `EnqueueOutcome` was
/// silently discarded by `run_session` — is closed by `OutboundSend`'s
/// own `outcome` oneshot (TODO.md L4h1).
const MAX_QUEUED_BYTES_PER_DST: usize = 3 * MAX_QUEUED_BYTES / 4;

/// One queued SEND, not yet written to the wire.
struct QueuedSend {
    dst: NodeId,
    e2e_proto: u8,
    flags: u8,
    payload: Vec<u8>,
    /// Held for exactly as long as this item occupies the queue: dropped
    /// when [`OutboundQueue::next_ready_to_send`] removes it (it is not
    /// moved into the returned [`Record`]), and with the whole queue on a
    /// reconnect. See [`SendBudget`].
    _permit: Option<SendPermit>,
}

impl QueuedSend {
    /// Bit 0 of `flags` is droppable (protocol.md 4.2); reliable is the
    /// absence of that bit, not a separate flag of its own.
    fn is_reliable(&self) -> bool {
        self.flags & 0x01 == 0
    }

    /// What this send costs against credit (if reliable) and against
    /// every occupancy budget this queue tracks (regardless of class):
    /// `payload.len()` floored at [`MIN_SEND_CHARGE_BYTES`], the exact
    /// number `menzil-relay` charges for the RECV this SEND becomes, so
    /// the two sides' views of remaining credit can never drift apart
    /// over a run of near-empty sends, and so a flood of near-empty
    /// droppable sends cannot occupy real memory while reporting zero
    /// budget used (TODO.md L4b's own review, finding 9).
    fn charge(&self) -> u32 {
        (self.payload.len() as u32).max(MIN_SEND_CHARGE_BYTES)
    }
}

/// A caller's request to send one SEND record (protocol.md 4.2) through
/// a running L3 session; handed to [`crate::session::run_session`]
/// through its `outbound` channel. Not [`Clone`]: `outcome` is a
/// single-use handle.
#[derive(Debug)]
pub struct OutboundSend {
    /// The destination peer.
    pub dst: NodeId,
    /// Which L4 protocol `payload` belongs to.
    pub e2e_proto: u8,
    /// Bit 0 = droppable (datagram class); protocol.md 4.2.
    pub flags: u8,
    /// Opaque L4 bytes.
    pub payload: Vec<u8>,
    /// Which attachment this was produced for (protocol.md 5.1's path
    /// pinning). Refused with [`EnqueueOutcome::WrongEpoch`], never sent,
    /// once a *different* epoch is current by the time this is drained
    /// from `outbound` — most often a send queued while reconnecting,
    /// which before this type gained the field would go out on
    /// whichever L3 session happened to attach next, as if nothing had
    /// happened (TODO.md L4h1). See [`Epoch::first`] for what to use
    /// before this node's very first attachment.
    pub epoch: Epoch,
    /// Resolved with this send's admission outcome, exactly once, for
    /// every send `run_session` actually drains from its `outbound`
    /// channel (TODO.md L4h1; L4b's own deferred half of its finding 2,
    /// where this was only ever logged and discarded) — the one
    /// exception being `run_session` itself returning or being aborted
    /// while this is still waiting to be admitted: either still
    /// buffered, undrained, in the `outbound` channel itself, or already
    /// drained but held in `run_session`'s own small pre-attach queue
    /// (a send tagged for an epoch that has not attached yet). Either
    /// way it is simply dropped, along with its `outcome` sender, never
    /// resolved at all, which a waiting [`oneshot::Receiver`] observes
    /// as a disconnect, not a hang. Resolving a oneshot nobody
    /// is listening for is not an error either — dropping the paired
    /// `Receiver` is the normal way to opt out, not a bug — but a
    /// caller that *is* listening must be told apart `Accepted` from
    /// every refusal: an L4 record refused here after `menzil-e2e`
    /// already assigned it a counter can only end that L4 session,
    /// never be retried in place.
    pub outcome: oneshot::Sender<EnqueueOutcome>,
    /// Queue space this send reserved *before* it was produced (see
    /// [`SendBudget`]), handed on to the [`OutboundQueue`] with the send
    /// and released when the queue lets it go, or immediately if the send
    /// is refused or never drained. `None` for a send that did not
    /// reserve any: small control records (KEEP, REKEY, CLOSE) and every
    /// non-L4 caller. A send that holds one is not refused for lack of
    /// queue space ([`EnqueueOutcome::QueueFull`]) **as long as the sends
    /// that hold none stay within what the budgets leave free** (the
    /// queue's caps minus [`L4_SEND_BUDGET_PER_DST`] / [`L4_SEND_BUDGET_TOTAL`]):
    /// the queue does not enforce that split, it only holds today because
    /// the permit-less senders are tiny and rare (TODO.md, L4h5's review).
    pub permit: Option<SendPermit>,
}

/// Outcome of [`OutboundQueue::enqueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Accepted: queued (and possibly already sendable, drained by the
    /// caller's own next [`OutboundQueue::next_ready_to_send`] call).
    Accepted,
    /// `payload` is larger than [`OutboundQueue::max_payload`] and could
    /// never fit in a single L3 SEND record regardless of credit or
    /// queue occupancy (TODO.md L4b's own review, finding 8, live-
    /// verified against a real relay: an oversized SEND fails to
    /// encrypt and tears down the whole L3 session, not just this one
    /// record). The caller must split or otherwise never produce a
    /// payload this large; retrying the same bytes can never succeed.
    TooLarge,
    /// A droppable send discarded rather than queued because either
    /// this destination's own share, or the shared [`MAX_QUEUED_BYTES`]
    /// total, is already spoken for (protocol.md 5.2: datagram-class
    /// traffic tolerates loss).
    Dropped,
    /// A reliable send refused because either this destination's own
    /// share, or the shared [`MAX_QUEUED_BYTES`] total, is already
    /// spoken for. Unlike [`Self::Dropped`], this is a caller-visible
    /// backpressure signal (TODO.md L4h1's own `OutboundSend::outcome`)
    /// for data this queue will not silently lose by discarding — but
    /// "retry" means a fresh [`OutboundSend`], not this exact one
    /// resubmitted: for a caller whose payload already carries an
    /// `menzil-e2e`-assigned counter, this specific record can only end
    /// that L4 session, the same as [`Self::WrongEpoch`] and
    /// [`Self::TooLarge`] (TODO.md L4h1's own text is explicit that none
    /// of the three are retried in place).
    QueueFull,
    /// Refused before this queue was even consulted: the
    /// [`OutboundSend`] this came from was tagged with an
    /// [`Epoch`] that is no longer the current attachment (TODO.md
    /// L4h1) — most often a send queued while reconnecting, which
    /// would otherwise go out on the *next* L3 session as if nothing
    /// had happened, the same path-pinning violation protocol.md 5.1
    /// forbids. Retrying under the new epoch, if the caller still wants
    /// to, is a fresh send with a fresh outcome, not an automatic retry
    /// of this one.
    WrongEpoch,
}

/// What L4 sessions may, all together, have queued in this node's
/// [`OutboundQueue`] for one destination at a time (TODO.md L4h5). One
/// mebibyte is WELCOME's default per-peer credit (protocol.md 4.1): the
/// relay will not let more than that out the door per round trip anyway,
/// so queuing more than a credit window of bulk data ahead of it adds
/// latency for everything sharing the session (a keystroke queued behind
/// it waits for all of it, `yamux` being FIFO across streams) and no
/// throughput. Well under the queue's own per-destination cap
/// ([`MAX_QUEUED_BYTES_PER_DST`]), so that what is left over covers every
/// send that does not reserve space first.
pub(crate) const L4_SEND_BUDGET_PER_DST: usize = 1024 * 1024;

/// What L4 sessions may have queued across *all* destinations at once.
/// Below [`MAX_QUEUED_BYTES`] for the same reason as
/// [`L4_SEND_BUDGET_PER_DST`]: two busy peers can each use their whole
/// share; beyond that peers wait for each other. A peer that has stopped
/// reading but is still attached (the relay gives up on it only after its
/// own 50 s liveness window) keeps its share, and a third peer's staged
/// frames then time out after 35 s instead of being refused at once as
/// the queue's own 3/4 + 1/4 split would have.
pub(crate) const L4_SEND_BUDGET_TOTAL: usize = 2 * 1024 * 1024;

const _: () = {
    assert!(L4_SEND_BUDGET_PER_DST < MAX_QUEUED_BYTES_PER_DST);
    assert!(L4_SEND_BUDGET_TOTAL < MAX_QUEUED_BYTES);
    assert!(L4_SEND_BUDGET_PER_DST <= L4_SEND_BUDGET_TOTAL);
};

/// A node's send budgets, one per destination peer plus a shared total
/// (TODO.md L4h5). Cheap to clone; every clone is the same budgets.
///
/// **Why this exists**: once `menzil-e2e` has assigned an L4 record a
/// counter, that record can never be dropped or retried without ending its
/// session (the receiving side sees a gap). Until this existed, the
/// [`OutboundQueue`] refusing such a record for lack of room
/// ([`EnqueueOutcome::QueueFull`]) did exactly that, and *ordinary* bulk
/// transfer reached it: the windows `yamux` grants a few busy streams add
/// up to more than the queue holds (measured live over a healthy relay:
/// 32 concurrent 512 KiB transfers, and `tests/l4_bulk.rs` keeps the
/// smallest size that still overflowed the old queue, 16 of 256 KiB). A
/// session now
/// reserves the space a record will occupy, waiting if there is none,
/// *before* encrypting it, and the reservation travels with the record
/// ([`OutboundSend::permit`]) until the queue sends it, so reserved
/// sends alone can never overfill the queue and none of them is refused
/// for lack of room. That is a guarantee about reserved sends only: the
/// queue still admits sends that reserved nothing up to its full caps, so
/// the guarantee holds while those stay within the headroom the budgets
/// leave (see [`OutboundSend::permit`]). Everything above the budget
/// simply waits, which is what backpressure to the stream writers means.
///
/// One [`SendBudget`] per destination *peer*, not per session: several L4
/// sessions to one `NodeId` (one per shared network, or a replacement's
/// brief overlap) share one L3 queue allowance, so they must share one
/// budget — hence this registry, which hands every caller asking for the
/// same peer the same budget.
#[derive(Clone)]
pub struct SendBudgets {
    inner: Arc<SendBudgetsInner>,
}

struct SendBudgetsInner {
    total: Arc<Semaphore>,
    per_peer: Mutex<HashMap<NodeId, Arc<Semaphore>>>,
}

impl SendBudgets {
    /// Fresh budgets at the default sizes.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SendBudgetsInner {
                total: Arc::new(Semaphore::new(L4_SEND_BUDGET_TOTAL)),
                per_peer: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The budget for sends to `peer`: the same one on every call for the
    /// same peer. (Entries are never removed — one small allocation per
    /// peer ever contacted, which is a handful on the networks this
    /// project targets.)
    pub fn for_peer(&self, peer: NodeId) -> SendBudget {
        let mut per_peer = self
            .inner
            .per_peer
            .lock()
            .expect("no code path panics while holding this lock");
        let dst = per_peer
            .entry(peer)
            .or_insert_with(|| Arc::new(Semaphore::new(L4_SEND_BUDGET_PER_DST)))
            .clone();
        SendBudget {
            dst,
            total: Arc::clone(&self.inner.total),
        }
    }
}

impl Default for SendBudgets {
    fn default() -> Self {
        Self::new()
    }
}

/// One destination's share of [`SendBudgets`]. See there for what it is
/// for.
#[derive(Clone)]
pub struct SendBudget {
    dst: Arc<Semaphore>,
    total: Arc<Semaphore>,
}

impl SendBudget {
    /// Waits until `bytes` of queue space is free, both for this
    /// destination and overall, and reserves it until the returned
    /// [`SendPermit`] is dropped. `bytes` should be what the record will
    /// be charged in the queue (`QueuedSend::charge`: its payload
    /// length, floored at [`MIN_SEND_CHARGE_BYTES`]); asking for more
    /// than a whole budget is clamped to it, since that could otherwise
    /// never be granted.
    ///
    /// Cancel-safe: dropping the future before it completes gives back
    /// whatever it had already taken. Waiters are served in arrival
    /// order, so a busy session cannot starve another one sharing the
    /// budget. The destination share is taken first, then the total;
    /// nothing ever waits on the destination share while holding total
    /// space, and queue space is only ever released by sending, never by
    /// another waiter, so this cannot deadlock.
    pub async fn acquire(&self, bytes: usize) -> SendPermit {
        let bytes = bytes.min(L4_SEND_BUDGET_PER_DST);
        let bytes = u32::try_from(bytes).expect("L4_SEND_BUDGET_PER_DST fits in u32");
        let dst = Arc::clone(&self.dst)
            .acquire_many_owned(bytes)
            .await
            .expect("send budget semaphores are never closed");
        let total = Arc::clone(&self.total)
            .acquire_many_owned(bytes)
            .await
            .expect("send budget semaphores are never closed");
        SendPermit {
            bytes: bytes as usize,
            _dst: dst,
            _total: total,
        }
    }
}

/// Queue space reserved through a [`SendBudget`], released on drop.
#[derive(Debug)]
pub struct SendPermit {
    bytes: usize,
    _dst: OwnedSemaphorePermit,
    _total: OwnedSemaphorePermit,
}

impl SendPermit {
    /// How many bytes of queue space this reserves.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// Per-destination credit plus one shared pending-send FIFO, all in
/// memory only and meant to be rebuilt fresh on every new attach —
/// mirroring `menzil-relay::forward::ForwardTable::clear_for`'s own
/// per-attach reset, the fix for L3h's finding H2 (stale credit
/// silently outliving a reconnect). [`crate::session::run_session`]
/// constructs a new one inside its own per-attempt scope for exactly
/// this reason; nothing here does it automatically.
pub struct OutboundQueue {
    initial_credit: u32,
    /// The largest single SEND `payload` this queue will admit (see
    /// [`crate::outbound`]'s own module doc comment on
    /// [`EnqueueOutcome::TooLarge`]).
    max_payload: usize,
    credit: HashMap<NodeId, CreditLedger>,
    queue: VecDeque<QueuedSend>,
    queued_bytes: usize,
    /// Each destination's own share of `queued_bytes`, capped
    /// separately at [`MAX_QUEUED_BYTES_PER_DST`] so one congested peer
    /// cannot consume the whole shared budget and block *admission* for
    /// every other peer (TODO.md L4b's own review, finding 2).
    queued_bytes_per_dst: HashMap<NodeId, usize>,
}

impl OutboundQueue {
    /// `initial_credit` is WELCOME's `limits.credit` (protocol.md 4.1):
    /// the same starting balance applies freshly to every destination
    /// this queue first sends to, not only ones already known when this
    /// is constructed. `max_record` is WELCOME's `limits.max_record`,
    /// used to compute [`Self::max_payload`] once, up front, rather than
    /// on every [`Self::enqueue`] call.
    pub fn new(initial_credit: u32, max_record: u32) -> Self {
        Self {
            initial_credit,
            max_payload: max_send_payload(max_record),
            credit: HashMap::new(),
            queue: VecDeque::new(),
            queued_bytes: 0,
            queued_bytes_per_dst: HashMap::new(),
        }
    }

    /// Applies an incoming CREDIT record (protocol.md 4.2): grants more
    /// credit for sending to `peer`, *if* this queue already has a
    /// ledger for `peer` — a CREDIT for a peer this queue has never
    /// enqueued a reliable send to is necessarily stale (from a
    /// relationship that predates the current attach:
    /// [`crate::session::run_session`] always constructs a fresh queue,
    /// with no ledgers at all, on every new attach, and [`Self::enqueue`]
    /// always seeds a ledger the first time it admits a reliable send to
    /// a destination — see [`Self::enqueue`]'s own doc comment) and is
    /// ignored rather than seeding a fresh, wrong balance for it
    /// (TODO.md L4b's own review, finding 4a: seeding at the grant alone
    /// rather than `initial_credit` left a genuinely fresh peer
    /// permanently short the first time a stale CREDIT happened to
    /// arrive before this queue's own first send to it).
    pub fn note_credit(&mut self, peer: NodeId, bytes: u32) {
        if let Some(ledger) = self.credit.get_mut(&peer) {
            ledger.grant(bytes);
        }
    }

    /// Queues one SEND, or refuses/drops/rejects it per
    /// [`EnqueueOutcome`]'s own docs. Beyond the size and occupancy
    /// checks [`EnqueueOutcome`] documents, does not itself check
    /// whether `dst` currently has enough credit for this specific item
    /// — only [`Self::next_ready_to_send`] does, at drain time, which is
    /// what actually lets a peer's send wait here for credit that has
    /// not arrived yet without refusing it outright.
    pub fn enqueue(
        &mut self,
        dst: NodeId,
        e2e_proto: u8,
        flags: u8,
        payload: Vec<u8>,
    ) -> EnqueueOutcome {
        self.enqueue_with_permit(dst, e2e_proto, flags, payload, None)
    }

    /// Like [`Self::enqueue`], for a send that reserved its space first
    /// ([`OutboundSend::permit`]): `permit` is kept for as long as the
    /// send stays queued, and dropped at once if it is refused instead.
    pub fn enqueue_with_permit(
        &mut self,
        dst: NodeId,
        e2e_proto: u8,
        flags: u8,
        payload: Vec<u8>,
        permit: Option<SendPermit>,
    ) -> EnqueueOutcome {
        if payload.len() > self.max_payload {
            return EnqueueOutcome::TooLarge;
        }
        let send = QueuedSend {
            dst,
            e2e_proto,
            flags,
            payload,
            _permit: permit,
        };
        let reliable = send.is_reliable();
        if reliable {
            let initial = self.initial_credit;
            self.credit
                .entry(send.dst)
                .or_insert_with(|| CreditLedger::new(initial));
        }

        let charge = send.charge() as usize;
        let per_dst_used = *self.queued_bytes_per_dst.get(&send.dst).unwrap_or(&0);
        if per_dst_used + charge > MAX_QUEUED_BYTES_PER_DST
            || self.queued_bytes + charge > MAX_QUEUED_BYTES
        {
            return if reliable {
                EnqueueOutcome::QueueFull
            } else {
                EnqueueOutcome::Dropped
            };
        }

        self.queued_bytes += charge;
        *self.queued_bytes_per_dst.entry(send.dst).or_insert(0) += charge;
        self.queue.push_back(send);
        EnqueueOutcome::Accepted
    }

    /// Whether `send` could go out right now: always true for droppable
    /// (once queued at all — admission already decided whether it was
    /// worth queueing), true for reliable only if `dst`'s ledger
    /// currently covers `QueuedSend::charge`.
    fn is_sendable(&self, send: &QueuedSend) -> bool {
        if !send.is_reliable() {
            return true;
        }
        self.credit
            .get(&send.dst)
            .is_some_and(|ledger| ledger.remaining() >= send.charge())
    }

    /// Whether [`Self::next_ready_to_send`] would return a record right
    /// now. Lets a caller that writes one record at a time (see
    /// `run_session`) make "something is ready to write" a condition of its
    /// own `select!` arm, so the slow write is one step among the others
    /// instead of a run that locks them all out until it finishes.
    pub fn has_ready_to_send(&self) -> bool {
        self.ready_index().is_some()
    }

    /// Where the item [`Self::next_ready_to_send`] would take sits in the
    /// queue: the first one (by original order) that is sendable right
    /// now, with every later item for a destination skipped once an
    /// earlier reliable one for it was found not sendable (this module's
    /// own doc comment on per-destination order). The one definition both
    /// callers share, so they cannot disagree.
    fn ready_index(&self) -> Option<usize> {
        let mut blocked_reliable_dsts: HashSet<NodeId> = HashSet::new();
        self.queue.iter().position(|send| {
            if !send.is_reliable() {
                return true;
            }
            if blocked_reliable_dsts.contains(&send.dst) {
                return false;
            }
            if self.is_sendable(send) {
                true
            } else {
                blocked_reliable_dsts.insert(send.dst);
                false
            }
        })
    }

    /// The next record ready to actually go out, if any: the first
    /// queued item (by original order) that is sendable right now,
    /// preserving each destination's own relative order (see this
    /// module's own doc comment). Consumes credit for a reliable send
    /// and releases its share of both occupancy budgets as a side
    /// effect of returning it — a caller that calls this but then fails
    /// to actually write the bytes (the connection dies mid-drain) has
    /// already spent that credit locally with nothing to give it back;
    /// [`crate::session::run_session`] resets this queue's credit
    /// entirely on the next fresh attach regardless, the same scope of
    /// loss protocol.md 4.2 already accepts for a session that just
    /// ends.
    pub fn next_ready_to_send(&mut self) -> Option<Record> {
        let index = self.ready_index()?;
        let send = self
            .queue
            .remove(index)
            .expect("index was just found by ready_index");

        let charge = send.charge() as usize;
        self.queued_bytes -= charge;
        if let Some(per_dst) = self.queued_bytes_per_dst.get_mut(&send.dst) {
            *per_dst -= charge;
        }
        if send.is_reliable() {
            let ledger = self
                .credit
                .get_mut(&send.dst)
                .expect("is_sendable confirmed a ledger exists for a reliable send");
            ledger
                .consume(send.charge())
                .expect("is_sendable already confirmed enough credit for this exact charge");
        }
        Some(Record::Send {
            dst: send.dst,
            e2e_proto: send.e2e_proto,
            flags: send.flags,
            payload: send.payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> NodeId {
        NodeId::from([seed; 32])
    }

    fn unwrap_send(record: Record) -> (NodeId, u8, u8, Vec<u8>) {
        match record {
            Record::Send {
                dst,
                e2e_proto,
                flags,
                payload,
            } => (dst, e2e_proto, flags, payload),
            other => panic!("expected Record::Send, got {other:?}"),
        }
    }

    const RELIABLE: u8 = 0x00;
    const DROPPABLE: u8 = 0x01;

    /// `max_record` large enough that [`OutboundQueue::max_payload`]
    /// never interferes with a test that is not specifically about
    /// [`EnqueueOutcome::TooLarge`].
    fn q(initial_credit: u32) -> OutboundQueue {
        OutboundQueue::new(initial_credit, u32::MAX)
    }

    #[test]
    fn a_fresh_peer_is_seeded_with_initial_credit_on_first_enqueue() {
        let mut q = q(100);
        assert_eq!(
            q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 50]),
            EnqueueOutcome::Accepted
        );
        let (dst, _, _, payload) = unwrap_send(q.next_ready_to_send().unwrap());
        assert_eq!(dst, peer(1));
        assert_eq!(payload.len(), 50);
    }

    #[test]
    fn enqueue_never_reseeds_an_already_known_peer() {
        let mut q = q(1000);
        // Spend some credit first.
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 900]);
        q.next_ready_to_send().unwrap();
        // A second enqueue for the same peer must not reset it back to
        // the full 1000: only 100 remains, so a 200-byte send is not
        // sendable.
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 200]);
        assert!(q.next_ready_to_send().is_none());
    }

    #[test]
    fn note_credit_on_a_never_enqueued_peer_is_ignored() {
        // Regression test for finding 4a: a CREDIT for a peer this
        // queue has never enqueued a reliable send to is necessarily
        // stale (see `note_credit`'s own doc comment) and must not seed
        // a ledger at all, let alone at the bare grant amount.
        let mut q = q(1000);
        q.note_credit(peer(1), 500);
        assert_eq!(
            q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 750]),
            EnqueueOutcome::Accepted
        );
        // Seeded at initial_credit (1000), unaffected by the earlier,
        // ignored grant of 500 — a 750-byte send must succeed.
        assert!(q.next_ready_to_send().is_some());
    }

    #[test]
    fn note_credit_adds_to_an_existing_balance() {
        let mut q = q(0);
        // Establish a real ledger first (note_credit alone no longer
        // seeds one — see the regression test above).
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1]);
        q.next_ready_to_send(); // not sendable yet (0 credit); leaves the ledger at 0
        q.note_credit(peer(1), 50);
        // A second grant must add to the first (50 + 30 = 80), not
        // overwrite it back down to 30.
        q.note_credit(peer(1), 30);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 80]);
        assert!(q.next_ready_to_send().is_some());
    }

    #[test]
    fn a_reliable_send_beyond_credit_is_queued_not_refused() {
        let mut q = q(10);
        assert_eq!(
            q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1000]),
            EnqueueOutcome::Accepted,
            "admission does not check per-item credit sufficiency"
        );
        assert!(q.next_ready_to_send().is_none(), "not enough credit yet");
    }

    #[test]
    fn a_blocked_send_becomes_ready_once_credit_arrives() {
        let mut q = q(10);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 100]);
        assert!(q.next_ready_to_send().is_none());
        q.note_credit(peer(1), 100);
        assert!(q.next_ready_to_send().is_some());
    }

    #[test]
    fn a_credit_exhausted_peer_does_not_block_a_different_peers_send() {
        let mut q = q(10);
        // peer(1) has no credit for this; queued first.
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1000]);
        // peer(2) has plenty; queued second.
        q.note_credit(peer(2), 1000); // no-op: peer(2) has no ledger yet
        q.enqueue(peer(2), 0x01, RELIABLE, vec![0; 100]);
        q.note_credit(peer(2), 1000); // now seeded by the enqueue above

        let (dst, ..) = unwrap_send(q.next_ready_to_send().unwrap());
        assert_eq!(
            dst,
            peer(2),
            "peer(1)'s stuck send must not block peer(2)'s"
        );
        assert!(
            q.next_ready_to_send().is_none(),
            "peer(1)'s send is still blocked, nothing else queued"
        );
    }

    #[test]
    fn order_is_preserved_among_one_peers_own_sends() {
        let mut q = q(1000);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![1]);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![2]);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![3]);
        let first = unwrap_send(q.next_ready_to_send().unwrap()).3;
        let second = unwrap_send(q.next_ready_to_send().unwrap()).3;
        let third = unwrap_send(q.next_ready_to_send().unwrap()).3;
        assert_eq!((first, second, third), (vec![1], vec![2], vec![3]));
    }

    #[test]
    fn a_later_smaller_send_never_passes_an_earlier_blocked_one_for_the_same_peer() {
        // Regression test for finding 1 (live-reproduced by TODO.md
        // L4b's own review against a real relay): remaining credit that
        // covers a later, smaller item but not an earlier, larger one
        // for the *same* destination must not let the smaller one out
        // first — protocol.md 5.2 requires class-0 traffic to arrive
        // contiguous, and the relay ends the session on any reordering.
        let mut q = q(100);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 90]); // earlier, larger
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 10]); // later, smaller
        // Only 100 credit total: the larger item alone exactly fits,
        // but is still first in line.
        let (_, _, _, payload) = unwrap_send(q.next_ready_to_send().unwrap());
        assert_eq!(payload.len(), 90, "the earlier, larger item must go first");
    }

    #[test]
    fn a_droppable_send_never_waits_behind_a_blocked_reliable_send_for_the_same_peer() {
        // The two classes use independent counters end to end
        // (protocol.md 5.2), so a droppable item for a destination with
        // a blocked reliable item ahead of it must not be held up by
        // it — only reliable-to-reliable order is preserved.
        let mut q = q(0);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 100]); // blocked: no credit
        q.enqueue(peer(1), 0x01, DROPPABLE, vec![9]);
        let (_, _, flags, payload) = unwrap_send(q.next_ready_to_send().unwrap());
        assert_eq!(flags, DROPPABLE);
        assert_eq!(payload, vec![9]);
    }

    #[test]
    fn next_ready_to_send_consumes_credit() {
        let mut q = q(1000);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1000]);
        q.next_ready_to_send().unwrap();
        // Nothing left: a further send of even 1 byte still charges the
        // MIN_SEND_CHARGE_BYTES floor, which now exceeds what remains.
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1]);
        assert!(q.next_ready_to_send().is_none());
    }

    #[test]
    fn near_empty_payload_still_charges_the_floor() {
        let mut q = q(MIN_SEND_CHARGE_BYTES - 1);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1]);
        assert!(
            q.next_ready_to_send().is_none(),
            "a 1-byte payload must still cost MIN_SEND_CHARGE_BYTES, not 1"
        );
    }

    #[test]
    fn droppable_send_is_not_gated_by_credit_at_all() {
        let mut q = q(0);
        assert_eq!(
            q.enqueue(peer(1), 0x01, DROPPABLE, vec![0; 1000]),
            EnqueueOutcome::Accepted
        );
        assert!(q.next_ready_to_send().is_some());
    }

    #[test]
    fn oversized_payload_is_rejected_as_too_large() {
        // Regression test for finding 8: the default max_record (65,535)
        // allows at most 65,484 bytes of SEND payload
        // (`menzil_proto::max_send_payload`, itself live-verified); one
        // byte more must be rejected outright, not queued to fail later
        // at encrypt time and tear down the whole session.
        let mut q = OutboundQueue::new(u32::MAX, 65_535);
        assert_eq!(
            q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 65_484]),
            EnqueueOutcome::Accepted
        );
        assert_eq!(
            q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 65_485]),
            EnqueueOutcome::TooLarge
        );
        assert_eq!(
            q.enqueue(peer(1), 0x01, DROPPABLE, vec![0; 65_485]),
            EnqueueOutcome::TooLarge,
            "the size cap applies regardless of class"
        );
    }

    #[test]
    fn reliable_enqueue_past_the_per_destination_cap_is_refused() {
        // Regression test for finding 2: one destination's own backlog
        // must not be able to consume more than its own share
        // (`MAX_QUEUED_BYTES_PER_DST`) of the shared budget, so a
        // *different* destination still has admission room left.
        // `initial_credit` is huge here so credit is never the limiting
        // factor — only the per-destination occupancy cap is.
        let mut q = q(u32::MAX);
        loop {
            match q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1]) {
                EnqueueOutcome::Accepted => {}
                EnqueueOutcome::QueueFull => break,
                other => panic!("unexpected outcome while filling peer(1): {other:?}"),
            }
        }
        // peer(2) has sent nothing yet: still has its own full share.
        assert_eq!(
            q.enqueue(peer(2), 0x01, RELIABLE, vec![0; 100]),
            EnqueueOutcome::Accepted,
            "peer(1)'s full backlog must not block admission for peer(2)"
        );
    }

    #[test]
    fn droppable_enqueue_past_the_per_destination_cap_is_dropped_not_refused() {
        let mut q = q(0);
        loop {
            match q.enqueue(peer(1), 0x01, DROPPABLE, vec![0; 1]) {
                EnqueueOutcome::Accepted => {}
                EnqueueOutcome::Dropped => break,
                other => panic!("unexpected outcome while filling peer(1): {other:?}"),
            }
        }
    }

    #[test]
    fn next_ready_to_send_is_none_on_an_empty_queue() {
        let mut q = q(1000);
        assert!(q.next_ready_to_send().is_none());
    }

    #[test]
    fn e2e_proto_and_flags_round_trip_through_the_queue() {
        let mut q = q(1000);
        q.enqueue(peer(1), 0x42, DROPPABLE, vec![9, 9]);
        let (_, e2e_proto, flags, payload) = unwrap_send(q.next_ready_to_send().unwrap());
        assert_eq!(e2e_proto, 0x42);
        assert_eq!(flags, DROPPABLE);
        assert_eq!(payload, vec![9, 9]);
    }

    #[test]
    fn next_ready_to_send_releases_both_the_shared_and_per_destination_budget() {
        // Regression test for finding 9 (the removal side): admission
        // and removal must agree on charging `charge()`, not raw
        // `payload.len()`, or the two budgets drift apart over a run of
        // near-empty sends. A 1-byte send occupies MIN_SEND_CHARGE_BYTES
        // either way; draining it must free exactly that much, not 1
        // byte, so a further MIN_SEND_CHARGE_BYTES-sized send still
        // fits under a tight cap.
        let mut q = q(MIN_SEND_CHARGE_BYTES);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1]);
        q.next_ready_to_send().unwrap();
        assert_eq!(
            q.enqueue(
                peer(1),
                0x01,
                RELIABLE,
                vec![0; MIN_SEND_CHARGE_BYTES as usize]
            ),
            EnqueueOutcome::Accepted,
            "the first send's floored charge must have been fully released, not just its 1 byte"
        );
    }
    // --- TODO.md L4h5: send budgets ---------------------------------------

    use std::time::Duration;
    use tokio::time::timeout;

    /// Whether `fut` completes within a short wait — i.e. whether the
    /// budget it asks for is available right now.
    async fn is_immediately_granted(budget: &SendBudget, bytes: usize) -> bool {
        timeout(Duration::from_millis(50), budget.acquire(bytes))
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn a_permit_is_held_while_its_send_is_queued_and_released_when_the_send_leaves() {
        let budget = SendBudgets::new().for_peer(peer(1));
        let permit = budget.acquire(1000).await;
        let mut q = q(1_000_000);
        assert_eq!(
            q.enqueue_with_permit(peer(1), 0x01, RELIABLE, vec![0; 1000], Some(permit)),
            EnqueueOutcome::Accepted
        );
        assert!(
            !is_immediately_granted(&budget, L4_SEND_BUDGET_PER_DST).await,
            "the reservation must be held for as long as the send sits in the queue"
        );
        q.next_ready_to_send().unwrap();
        assert!(
            is_immediately_granted(&budget, L4_SEND_BUDGET_PER_DST).await,
            "the reservation must be released when the send leaves the queue"
        );
    }

    #[tokio::test]
    async fn a_send_waiting_for_credit_keeps_its_reservation() {
        // Released on leaving the queue, not on being admitted to it: a
        // send that can't go out yet (no credit) still occupies the queue.
        let budget = SendBudgets::new().for_peer(peer(1));
        let permit = budget.acquire(1000).await;
        let mut q = q(100); // far less credit than the send needs
        q.enqueue_with_permit(peer(1), 0x01, RELIABLE, vec![0; 1000], Some(permit));
        assert!(q.next_ready_to_send().is_none());
        assert!(!is_immediately_granted(&budget, L4_SEND_BUDGET_PER_DST).await);
        q.note_credit(peer(1), 10_000);
        q.next_ready_to_send().unwrap();
        assert!(is_immediately_granted(&budget, L4_SEND_BUDGET_PER_DST).await);
    }

    #[tokio::test]
    async fn a_refused_enqueue_releases_its_permit_at_once() {
        let budget = SendBudgets::new().for_peer(peer(1));
        let mut small = OutboundQueue::new(1_000_000, 200); // max_payload well under 1000
        let permit = budget.acquire(1000).await;
        assert_eq!(
            small.enqueue_with_permit(peer(1), 0x01, RELIABLE, vec![0; 1000], Some(permit)),
            EnqueueOutcome::TooLarge
        );
        assert!(is_immediately_granted(&budget, L4_SEND_BUDGET_PER_DST).await);
    }

    #[tokio::test]
    async fn dropping_the_queue_releases_every_queued_permit() {
        // A reconnect rebuilds the queue (`run_session`'s per-attach
        // reset); whatever was still queued must not stay reserved.
        let budget = SendBudgets::new().for_peer(peer(1));
        let mut q = q(0); // no credit: nothing ever leaves
        for _ in 0..4 {
            let permit = budget.acquire(100_000).await;
            q.enqueue_with_permit(peer(1), 0x01, RELIABLE, vec![0; 100_000], Some(permit));
        }
        assert!(!is_immediately_granted(&budget, L4_SEND_BUDGET_PER_DST).await);
        drop(q);
        assert!(is_immediately_granted(&budget, L4_SEND_BUDGET_PER_DST).await);
    }

    #[tokio::test]
    async fn acquire_waits_for_space_and_proceeds_when_it_is_freed() {
        let budget = SendBudgets::new().for_peer(peer(1));
        let hog = budget.acquire(L4_SEND_BUDGET_PER_DST).await;
        let waiter = {
            let budget = budget.clone();
            tokio::spawn(async move { budget.acquire(4096).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiter.is_finished(),
            "must wait while the budget is exhausted"
        );
        drop(hog);
        timeout(Duration::from_secs(5), waiter)
            .await
            .expect("must be woken when space is freed")
            .unwrap();
    }

    #[tokio::test]
    async fn one_peer_has_one_budget_however_it_is_asked_for() {
        let budgets = SendBudgets::new();
        let first = budgets.for_peer(peer(1));
        let _hog = first.acquire(L4_SEND_BUDGET_PER_DST).await;
        // The same peer asked for again, or through a clone of the
        // registry, is the same allowance: several L4 sessions to one
        // peer share one L3 per-destination queue allowance.
        assert!(!is_immediately_granted(&budgets.for_peer(peer(1)), 1).await);
        assert!(!is_immediately_granted(&budgets.clone().for_peer(peer(1)), 1).await);
        // A different peer has its own.
        assert!(is_immediately_granted(&budgets.for_peer(peer(2)), 1).await);
    }

    #[tokio::test]
    async fn the_total_is_shared_across_peers() {
        let budgets = SendBudgets::new();
        let p1 = budgets.for_peer(peer(1));
        let p2 = budgets.for_peer(peer(2));
        let p3 = budgets.for_peer(peer(3));
        let a = p1.acquire(L4_SEND_BUDGET_PER_DST).await;
        let _b = p2.acquire(L4_SEND_BUDGET_PER_DST).await;
        assert_eq!(
            L4_SEND_BUDGET_TOTAL,
            2 * L4_SEND_BUDGET_PER_DST,
            "this test's premise"
        );
        assert!(
            !is_immediately_granted(&p3, 1).await,
            "two busy peers have used the whole total; a third waits"
        );
        drop(a);
        assert!(is_immediately_granted(&p3, 1).await);
    }

    #[tokio::test]
    async fn a_request_larger_than_a_whole_budget_is_clamped_not_stuck() {
        let budget = SendBudgets::new().for_peer(peer(1));
        let permit = timeout(
            Duration::from_secs(1),
            budget.acquire(10 * L4_SEND_BUDGET_PER_DST),
        )
        .await
        .expect("an impossible request must be clamped, not wait forever");
        assert_eq!(permit.bytes(), L4_SEND_BUDGET_PER_DST);
    }

    #[tokio::test]
    async fn a_cancelled_acquire_gives_back_what_it_had_already_taken() {
        // The destination share is taken before the total one; a waiter
        // that gives up between the two must not leave the first held.
        let budgets = SendBudgets::new();
        let (p1, p2, p3) = (
            budgets.for_peer(peer(1)),
            budgets.for_peer(peer(2)),
            budgets.for_peer(peer(3)),
        );
        let _a = p1.acquire(L4_SEND_BUDGET_PER_DST).await;
        let _b = p2.acquire(L4_SEND_BUDGET_PER_DST).await; // total now exhausted
        assert!(
            timeout(Duration::from_millis(50), p3.acquire(4096))
                .await
                .is_err(),
            "peer 3 gets its destination share, then waits on the total"
        );
        assert_eq!(
            p3.dst.available_permits(),
            L4_SEND_BUDGET_PER_DST,
            "the cancelled waiter must give its destination share back"
        );
    }
    // --- TODO.md L4h5 review follow-up: has_ready_to_send ----------------

    #[test]
    fn has_ready_to_send_is_false_for_an_empty_queue() {
        assert!(!q(100).has_ready_to_send());
    }

    #[test]
    fn has_ready_to_send_follows_credit() {
        let mut q = q(100);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 1000]);
        assert!(
            !q.has_ready_to_send(),
            "a reliable send that credit does not cover is queued, not ready"
        );
        q.note_credit(peer(1), 10_000);
        assert!(q.has_ready_to_send());
        q.next_ready_to_send().unwrap();
        assert!(!q.has_ready_to_send());
    }

    #[test]
    fn has_ready_to_send_never_disagrees_with_next_ready_to_send() {
        // A mixed queue: one peer blocked on credit (so everything behind
        // its first item is skipped too), another peer sendable, and a
        // droppable item. Walk it until empty, asking before each take.
        let mut q = q(100);
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 500]); // blocked: 100 credit
        q.enqueue(peer(1), 0x01, RELIABLE, vec![0; 10]); // behind a blocked item
        q.enqueue(peer(2), 0x01, RELIABLE, vec![0; 50]); // sendable
        q.enqueue(peer(1), 0x01, DROPPABLE, vec![0; 10]); // droppable, never blocked
        let mut taken = 0;
        loop {
            let predicted = q.has_ready_to_send();
            let actual = q.next_ready_to_send();
            assert_eq!(predicted, actual.is_some(), "after {taken} taken");
            if actual.is_none() {
                break;
            }
            taken += 1;
        }
        // Peer 2's send and the droppable one go out; peer 1's two reliable
        // sends stay queued behind the one credit does not cover.
        assert_eq!(taken, 2);
        q.note_credit(peer(1), 10_000);
        assert!(q.has_ready_to_send());
    }
}
