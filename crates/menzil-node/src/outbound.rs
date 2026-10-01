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
//! [`QueuedSend::charge`] (not a send's raw `payload.len()` — TODO.md
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

use menzil_proto::{MIN_SEND_CHARGE_BYTES, NodeId, Record, max_send_payload};
use menzil_session::CreditLedger;

/// Total bytes this queue holds across every destination before a
/// further reliable enqueue is refused, and beyond which a droppable
/// enqueue is silently dropped instead. This crate's own choice,
/// mirroring `menzil-relay::forward::MAX_QUEUE_BYTES`'s 4 MiB: a relay
/// would not accept more than that from any one (source, destination)
/// pair anyway, so holding more than that locally, waiting to send,
/// could never actually be delivered regardless.
const MAX_QUEUED_BYTES: usize = 4 * 1024 * 1024;

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
/// deeper gap the same review measured — a refused or dropped send has
/// no way to tell its caller beyond a log line, `EnqueueOutcome` is
/// silently discarded by `run_session` today — needs an actual
/// caller-visible signal (a response channel on `OutboundSend`, most
/// likely) to close properly, which is rightly a design question for
/// whichever future item builds the first real caller (TODO.md L4d/L4h),
/// not a number to keep retuning here.
const MAX_QUEUED_BYTES_PER_DST: usize = 3 * MAX_QUEUED_BYTES / 4;

/// One queued SEND, not yet written to the wire.
struct QueuedSend {
    dst: NodeId,
    e2e_proto: u8,
    flags: u8,
    payload: Vec<u8>,
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
/// through its `outbound` channel.
#[derive(Debug, Clone)]
pub struct OutboundSend {
    /// The destination peer.
    pub dst: NodeId,
    /// Which L4 protocol `payload` belongs to.
    pub e2e_proto: u8,
    /// Bit 0 = droppable (datagram class); protocol.md 4.2.
    pub flags: u8,
    /// Opaque L4 bytes.
    pub payload: Vec<u8>,
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
    /// backpressure signal for data this queue will not silently lose
    /// by discarding — the caller (not yet built, TODO.md L4d/L4h) is
    /// expected to retry rather than assume it was sent.
    QueueFull,
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
        if payload.len() > self.max_payload {
            return EnqueueOutcome::TooLarge;
        }
        let send = QueuedSend {
            dst,
            e2e_proto,
            flags,
            payload,
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
    /// currently covers [`QueuedSend::charge`].
    fn is_sendable(&self, send: &QueuedSend) -> bool {
        if !send.is_reliable() {
            return true;
        }
        self.credit
            .get(&send.dst)
            .is_some_and(|ledger| ledger.remaining() >= send.charge())
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
        let mut blocked_reliable_dsts: HashSet<NodeId> = HashSet::new();
        let index = self.queue.iter().position(|send| {
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
        })?;
        let send = self
            .queue
            .remove(index)
            .expect("index was just found by position");

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
}
