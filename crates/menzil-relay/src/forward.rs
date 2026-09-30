//! SEND -> RECV forwarding, credit enforcement, and bounded
//! per-(source,destination) queues (protocol.md 4.2's flow-control
//! paragraph; TODO.md L3h), on top of L3a through L3g's already-built
//! session lifecycle, roster store, and label registry.
//!
//! protocol.md 4.2's forwarding rule: "the relay forwards a SEND as a
//! RECV to `dst` only if `src` and `dst` are both listed and unrevoked in
//! one common, unexpired Roster the relay holds, `dst` is online and
//! attached, and `dst` has not set `accept_peers: false` in its
//! ADVERTISE. Otherwise ERROR `forbidden` or `peer_offline` goes back to
//! the sender." [`ForwardTable::forward`] checks authorization
//! (`crate::roster_store::RosterStore::grants_forwarding`, then
//! `accept_peers`) *before* `dst`'s attachment — deliberately the
//! opposite order from a first, since-corrected draft of this module,
//! which checked attachment first and let an unauthorized sender probe
//! any known NodeId's online status; see `grants_forwarding`'s own doc
//! comment for the full story (an opus red team review's finding M2).
//!
//! This is also where a claimed network's Roster `expires` is finally
//! checked (protocol.md 2.3: "Once `expires` has passed, relays stop
//! forwarding for that network") — both `crate::hello::check_hello`
//! (TODO.md L3e) and `crate::advertise::LabelRegistry` (TODO.md L3g)
//! deliberately left this exact check to "the separate, later flow
//! control item," i.e. this one; see either module's own doc comment.
//!
//! Credit (protocol.md 4.2): a reliable SEND consumes the sending node's
//! per-destination credit (`menzil_session::CreditLedger`, already built
//! in L3b); it is granted back — and a CREDIT record sent to the
//! original sender — once the resulting RECV record is actually handed
//! to the destination's own connection to send (`crate::session`'s drain
//! of [`ForwardItem`], via [`ForwardTable::drained`]), not merely
//! admitted into this relay's internal accounting. The CREDIT record
//! itself travels back to `src` over [`SessionRegistry::deliver`]'s
//! reliable, unbounded channel (via a [`ForwardItem::Credit`]), not
//! [`SessionRegistry::send_to`]'s lossy, bounded control-plane one — a
//! second red-team finding (H3): granting the ledger and then losing the
//! CREDIT record under load left a compliant sender's own view of its
//! credit permanently short, with nothing to ever resync it.
//!
//! A pair's initial credit is [`menzil_proto::Limits::credit`] clamped to
//! never exceed [`MAX_QUEUE_BYTES`] (below) — both here (defensively, so
//! this module's own guarantee never depends on a caller remembering to
//! clamp) and, so WELCOME's advertised limit and this table's actual
//! ledger never disagree, once more in [`crate::relay::Relay::new`] (a
//! third finding, M1: an unclamped WELCOME let an operator's
//! large-`credit` misconfiguration kill an entirely compliant node the
//! instant it used the credit WELCOME told it it had).
//!
//! Queues: one bounded byte budget per (source, destination) NodeId pair,
//! [`MAX_QUEUE_BYTES`] (protocol.md 10's "Per destination queue: 4 MiB",
//! read as protocol.md 4.2 itself states it more precisely — per pair,
//! not shared across every source of one destination); a NodeId's own
//! pairs are reset — not merely left to accumulate garbage — every time
//! it freshly attaches, via [`ForwardTable::clear_for`] (a fourth
//! finding, H2: protocol.md 4.2 scopes both the queue and, by the same
//! paragraph, credit to "(source session, destination session)", but the
//! original design kept `PairState` keyed for the lifetime of a NodeId
//! across reconnects — a reconnecting node's fresh WELCOME credit landed
//! on top of, or was silently shrunk by, whatever its *previous* session
//! had left behind). `crate::session` calls this the same way, and right
//! after, it already calls `crate::advertise::LabelRegistry::clear_for`
//! on a fresh attach.
//!
//! Reliable and droppable SENDs share the same [`MAX_QUEUE_BYTES`] budget
//! (`PairState::queued_bytes`), but reliable's own ceiling is its credit
//! ledger alone (never refused purely for shared occupancy, matching
//! protocol.md naming droppable, not reliable, as the class that yields)
//! — so droppable admission reserves `PairState::initial_credit` worth of
//! headroom for reliable's worst case up front, rather than comparing
//! against the raw [`MAX_QUEUE_BYTES`] (a fifth finding, L1: comparing
//! against the raw cap let droppable fill nearly all of it and reliable
//! then add its own full credit on top, overshooting the documented bound
//! by up to `initial_credit`). The record itself travels straight to the
//! destination's own outbound channel ([`SessionRegistry::deliver`]) —
//! "the queue" here is a byte budget gating admission into that channel,
//! not a second buffer this module holds data in.
//!
//! Every admission — reliable or droppable — charges at least
//! [`MIN_FORWARD_CHARGE_BYTES`] against credit and the queue budget,
//! never the raw `payload.len()` alone (a sixth finding, H4: a zero- or
//! near-zero-length payload cost real, unbounded relay heap — one queued
//! [`ForwardItem`] per SEND — while charging nothing against either
//! limit, since `0` always fits under any cap and `CreditLedger::consume(0)`
//! never fails; a single attached, otherwise-unremarkable member could
//! grow the relay's memory without bound this way). No valid L4 record is
//! ever actually empty (protocol.md 5.2's shortest kind, KEEP, is still
//! one byte), so this floor costs nothing to a real client and closes the
//! gap for a hostile or buggy one.
//!
//! Droppable SENDs are additionally rate limited by a per-pair token
//! bucket (protocol.md 10: "Datagram token bucket per (source,
//! destination): 20 Mbit/s, 256 KiB burst"), independent of the shared
//! byte budget above; a droppable SEND refused by either is silently
//! dropped, no ERROR sent back (protocol.md never says otherwise for the
//! datagram class, and every other droppable-specific mechanism here is
//! already best effort by design).
//!
//! `e2e_proto` values other than the two protocol.md 4.2 defines (`0x01`
//! menzil Noise, `0x02` reserved for QUIC) are refused with ERROR
//! `unknown_e2e` without closing the session (protocol.md 9's treatment
//! of an unrecognized record type, extended the same way to an
//! unrecognized tag within an otherwise-recognized one) — the relay never
//! interprets `payload` regardless of which of the two defined tags it
//! carries ("The relay never inspects payloads").
//!
//! Not built, real gaps: `PairState` entries for a NodeId that never
//! reconnects again are never removed (only reset on a *fresh* attach —
//! matching every other per-NodeId in-memory store this crate already
//! has, none of which age out either, an unbounded-over-long-uptime
//! concern only for a relay serving many distinct, short-lived
//! identities, not a personal relay's small, stable set); the
//! sender-side output ordering protocol.md 4.2 states ("control records,
//! then reliable SEND, then droppable SEND") is a node's own outgoing
//! queue discipline, not restated here for the relay's *own* outbound
//! multiplexing of RECV against PING/REKEY/DOC/ADVERTISE_ACK —
//! `crate::session`'s `tokio::select!` treats every branch with no
//! priority between them, so a busy data plane could in principle delay
//! this relay's own control traffic to the same peer, or (an opus
//! review's own gap note) stall a connection's liveness/REKEY/supersede
//! handling entirely if writing a queued record blocks indefinitely on a
//! peer that stopped reading — a real fix needs a priority queue and a
//! write timeout on the send side, a bigger change than this item's own
//! scope, and not new to L3h (every existing best-effort `conn.send()` in
//! `crate::session` already shares the same no-timeout characteristic); a
//! narrow race also exists between [`ForwardTable::forward`] confirming a
//! destination is attached and actually handing off to it (see
//! [`ForwardTable::forward`]'s own doc comment) — the same
//! already-accepted class of race `SessionRegistry::attach`'s and
//! `crate::advertise`'s own doc comments describe elsewhere in this
//! crate, not a new one introduced here; a member's NodeCert serial is
//! validated only at HELLO time, not re-checked against `NodeHistory`'s
//! current high-water mark on every SEND, so a Roster update raising
//! `min_serial` for an already-attached session's NodeId does not cut off
//! its forwarding immediately, only on its next HELLO.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use menzil_proto::{ErrorBody, ErrorCode, Limits, NetworkId, NodeId, Record};
use menzil_session::CreditLedger;

use crate::advertise::LabelRegistry;
use crate::registry::SessionRegistry;
use crate::roster_store::RosterStore;

/// protocol.md 10: "Per destination queue: 4 MiB" (protocol.md 4.2: "one
/// bounded queue per (source session, destination session)"). `pub(crate)`
/// so [`crate::relay::Relay::new`] can clamp `Limits::credit` against the
/// same figure this module itself clamps against (finding M1).
pub(crate) const MAX_QUEUE_BYTES: usize = 4 * 1024 * 1024;

/// protocol.md 10: "Datagram token bucket per (source, destination): 20
/// Mbit/s, 256 KiB burst".
const DGRAM_BUCKET_RATE_BYTES_PER_SEC: f64 = 20_000_000.0 / 8.0;
const DGRAM_BUCKET_BURST_BYTES: f64 = 256.0 * 1024.0;

/// The minimum this module ever charges a single SEND against credit and
/// the shared queue budget, regardless of its actual `payload.len()`
/// (finding H4). Comfortably above the L3 SEND/RECV wire framing itself
/// (35 bytes: `type | dst/src | e2e_proto | flags`) plus the Noise AEAD
/// tag (16 bytes) — i.e. above the real minimum cost of one record on the
/// wire — and a `ForwardItem` in memory costs more than this many bytes
/// of heap regardless, so this also keeps the number of items a fixed
/// credit/queue budget can ever admit bounded to a sane figure rather
/// than however many zero-length records fit in a `u32`.
const MIN_FORWARD_CHARGE_BYTES: u32 = 64;

/// A byte-metered token bucket, refilled lazily from elapsed wall-clock
/// time on each [`TokenBucket::try_take`] call (no background timer),
/// matching this crate's other pure, caller-supplies-`now` primitives
/// (`menzil_session::Liveness`, `RekeySchedule`).
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(now: Instant) -> Self {
        Self {
            tokens: DGRAM_BUCKET_BURST_BYTES,
            last_refill: now,
        }
    }

    /// Refills for the time elapsed since the last call (capped at the
    /// burst size), then takes `amount` bytes if enough are available.
    fn try_take(&mut self, amount: usize, now: Instant) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * DGRAM_BUCKET_RATE_BYTES_PER_SEC).min(DGRAM_BUCKET_BURST_BYTES);
        self.last_refill = now;
        let amount = amount as f64;
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// Per (source, destination) NodeId pair state: `src`'s reliable credit
/// for sending to `dst`, how many bytes of the pair's shared queue budget
/// are currently in use (admitted but not yet handed off to `dst`'s own
/// connection to send), and `src`'s droppable token bucket for `dst`.
struct PairState {
    credit: CreditLedger,
    /// The clamped credit this pair started with — stored (not just
    /// consumed from) so droppable admission can reserve this much
    /// headroom for reliable's worst case (finding L1; see this module's
    /// own doc comment).
    initial_credit: u32,
    queued_bytes: usize,
    dgram_bucket: TokenBucket,
}

impl PairState {
    fn new(initial_credit: u32, now: Instant) -> Self {
        let initial_credit = initial_credit.min(MAX_QUEUE_BYTES as u32);
        Self {
            credit: CreditLedger::new(initial_credit),
            initial_credit,
            queued_bytes: 0,
            dgram_bucket: TokenBucket::new(now),
        }
    }
}

/// One item handed to [`SessionRegistry::deliver`]: either a RECV record
/// to actually send, with enough bookkeeping for `crate::session`'s drain
/// loop to call [`ForwardTable::drained`] once it is sent, or a CREDIT
/// record to send as-is. Both travel the same reliable, unbounded channel
/// — CREDIT deliberately does not use [`SessionRegistry::send_to`]'s
/// lossy one (finding H3; see this module's own doc comment).
pub(crate) enum ForwardItem {
    /// Deliver `record` (always a `Record::Recv { .. }`) to this
    /// session's connection to send. Boxed per clippy's own
    /// `large_enum_variant` lint: `Record`'s largest variant is much
    /// bigger than `ForwardItem::Credit`'s fixed fields, and this enum is
    /// exactly the thing an admitted SEND is turned into and queued as
    /// (finding H4's own concern about per-item memory cost), so keeping
    /// it small matters more here than in most places `Record` appears.
    Recv {
        record: Box<Record>,
        src: NodeId,
        /// The amount actually charged against credit/queue budget for
        /// this record ([`MIN_FORWARD_CHARGE_BYTES`]-floored) — not
        /// necessarily `record`'s own payload length — so
        /// [`ForwardTable::drained`] releases and grants back exactly
        /// what was reserved.
        charge: u32,
        reliable: bool,
    },
    /// Send this CREDIT record as-is (protocol.md 4.2).
    Credit { peer: NodeId, bytes: u32 },
}

/// What [`ForwardTable::forward`] decided.
#[derive(Debug)]
pub(crate) enum ForwardOutcome {
    /// Handed off to `dst`'s connection to send.
    Queued,
    /// A droppable SEND was silently discarded (token bucket exhausted,
    /// or the shared per-pair queue was full) — no ERROR is owed.
    Dropped,
    /// Refused; the caller should send `.0` back to `src` and keep the
    /// session open (protocol.md 9's treatment of an unrecognized record
    /// applied the same way here).
    Refused(ErrorBody),
    /// A reliable SEND exceeded its available credit: a protocol
    /// violation (protocol.md 4.2). The caller should send `.0` back to
    /// `src` and then end the session.
    CreditViolation(ErrorBody),
}

/// Per-(source,destination) credit ledgers, queue budgets, and droppable
/// token buckets (protocol.md 4.2's flow-control paragraph; TODO.md L3h).
#[derive(Default)]
pub(crate) struct ForwardTable {
    pairs: Mutex<HashMap<(NodeId, NodeId), PairState>>,
}

impl ForwardTable {
    /// No pairs seen yet.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Validates and, if accepted, forwards one SEND from `src` (an
    /// already-attached, currently-registered session claiming
    /// `src_claimed` in its own HELLO — confirming that is the caller's
    /// job, see `crate::session`) to `dst`, per protocol.md 4.2's
    /// forwarding rule and flow-control paragraph (see this module's own
    /// doc comment for the full reasoning behind each check and the
    /// credit/queue model below).
    ///
    /// Checked in order: `e2e_proto` is one of the two defined tags; `src`
    /// is authorized to reach `dst` at all
    /// (`RosterStore::grants_forwarding`, which needs only `src`'s own
    /// claims — deliberately checked *before* `dst`'s attachment, see
    /// `grants_forwarding`'s own doc comment for why the order matters);
    /// `dst` is currently attached; `dst` has not opted out via
    /// `accept_peers: false`; then, only once every one of those passes,
    /// the credit/queue/token-bucket admission this module's own doc
    /// comment describes.
    ///
    /// A narrow, deliberately accepted race: `dst`'s attachment is
    /// confirmed, then acted on, as two separate steps, so `dst` could in
    /// principle detach in between — handled by rolling back whatever
    /// this call had already reserved (credit, queue bytes) and reporting
    /// [`ErrorCode::PeerOffline`] rather than silently leaking it, but not
    /// otherwise prevented; the same already-accepted class of gap
    /// `SessionRegistry::attach`'s and `crate::advertise`'s own doc
    /// comments describe for an analogous check-then-act window elsewhere
    /// in this crate.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn forward(
        &self,
        rosters: &RosterStore,
        registry: &SessionRegistry,
        labels: &LabelRegistry,
        limits: &Limits,
        src: &NodeId,
        src_claimed: &[NetworkId],
        dst: &NodeId,
        e2e_proto: u8,
        flags: u8,
        payload: Vec<u8>,
        now_unix: u64,
    ) -> ForwardOutcome {
        if e2e_proto != 0x01 && e2e_proto != 0x02 {
            return ForwardOutcome::Refused(ErrorBody {
                code: ErrorCode::UnknownE2e,
                msg: format!("unrecognized e2e_proto {e2e_proto:#04x}"),
            });
        }

        // Authorization first, using only `src`'s own already-known
        // claims — never `dst`'s attachment state (finding M2: checking
        // attachment before authorization let anyone probe any NodeId's
        // online status with no standing of their own).
        if !rosters.grants_forwarding(src, src_claimed, dst, now_unix) {
            return ForwardOutcome::Refused(ErrorBody {
                code: ErrorCode::Forbidden,
                msg: "sender has no claimed, unexpired network membership in common with the destination"
                    .to_string(),
            });
        }

        if !registry.is_attached(dst) {
            return ForwardOutcome::Refused(ErrorBody {
                code: ErrorCode::PeerOffline,
                msg: "destination is not attached".to_string(),
            });
        }
        if !labels.accepts_peers(dst) {
            return ForwardOutcome::Refused(ErrorBody {
                code: ErrorCode::Forbidden,
                msg: "destination is not accepting peer traffic".to_string(),
            });
        }

        let reliable = flags & 0x01 == 0;
        let charge = (payload.len() as u32).max(MIN_FORWARD_CHARGE_BYTES);
        let now = Instant::now();
        {
            let mut pairs = self.pairs.lock().unwrap();
            let pair = pairs
                .entry((*src, *dst))
                .or_insert_with(|| PairState::new(limits.credit, now));

            if reliable {
                if let Err(err) = pair.credit.consume(charge) {
                    return ForwardOutcome::CreditViolation(ErrorBody {
                        code: ErrorCode::CreditExceeded,
                        msg: err.to_string(),
                    });
                }
            } else {
                // Droppable admission reserves `initial_credit` worth of
                // headroom for reliable's own worst case up front, rather
                // than comparing against the raw `MAX_QUEUE_BYTES` — see
                // this module's own doc comment (finding L1) for why
                // comparing against the raw cap let the two classes
                // combine past the documented bound.
                let droppable_ceiling =
                    MAX_QUEUE_BYTES.saturating_sub(pair.initial_credit as usize);
                if pair.queued_bytes + charge as usize > droppable_ceiling
                    || !pair.dgram_bucket.try_take(charge as usize, now)
                {
                    return ForwardOutcome::Dropped;
                }
            }
            pair.queued_bytes += charge as usize;
        }

        let delivered = registry.deliver(
            dst,
            ForwardItem::Recv {
                record: Box::new(Record::Recv {
                    src: *src,
                    e2e_proto,
                    flags,
                    payload,
                }),
                src: *src,
                charge,
                reliable,
            },
        );
        if delivered {
            return ForwardOutcome::Queued;
        }

        // `dst` disconnected between the `is_attached` check above and
        // this handoff (see this method's own doc comment) — undo what
        // was reserved so this pair's accounting does not leak credit or
        // queue budget nothing will ever drain.
        let mut pairs = self.pairs.lock().unwrap();
        if let Some(pair) = pairs.get_mut(&(*src, *dst)) {
            pair.queued_bytes = pair.queued_bytes.saturating_sub(charge as usize);
            if reliable {
                pair.credit.grant(charge);
            }
        }
        ForwardOutcome::Refused(ErrorBody {
            code: ErrorCode::PeerOffline,
            msg: "destination disconnected before delivery".to_string(),
        })
    }

    /// Call once a [`ForwardItem::Recv`] has actually been handed to
    /// `dst`'s own connection to send — or once it's known it never will
    /// be, because that connection ended with items still queued
    /// (`crate::session`'s teardown drain; finding H1) — passing the
    /// exact `charge`/`reliable` it was admitted with: frees its share of
    /// the pair's queue budget and, if it was reliable, grants `charge`
    /// bytes of credit back to `src` and hands `registry` a
    /// [`ForwardItem::Credit`] for `src`'s own connection to send
    /// (protocol.md 4.2: "replenished as bytes are written to the
    /// destination socket") — over the same reliable channel the RECV
    /// record itself traveled on, not [`SessionRegistry::send_to`]'s
    /// lossy one (finding H3). A no-op on the ledger if the pair is
    /// somehow unknown (it cannot be, in practice: [`ForwardTable::forward`]
    /// always creates it before a [`ForwardItem`] naming that pair can
    /// exist); if `src` is no longer attached to receive the CREDIT
    /// record, [`SessionRegistry::deliver`] silently drops it, which is
    /// fine — a `src` that is gone has nothing left to tell.
    pub(crate) fn drained(
        &self,
        registry: &SessionRegistry,
        src: &NodeId,
        dst: &NodeId,
        charge: u32,
        reliable: bool,
    ) {
        {
            let mut pairs = self.pairs.lock().unwrap();
            if let Some(pair) = pairs.get_mut(&(*src, *dst)) {
                pair.queued_bytes = pair.queued_bytes.saturating_sub(charge as usize);
                if reliable {
                    pair.credit.grant(charge);
                }
            }
        }
        if reliable {
            registry.deliver(
                src,
                ForwardItem::Credit {
                    peer: *dst,
                    bytes: charge,
                },
            );
        }
    }

    /// Resets every pair involving `node_id`, in either role, to a clean
    /// slate — called right after a fresh [`SessionRegistry::attach`] for
    /// `node_id` (`crate::session`, mirroring its identical, pre-existing
    /// call to `crate::advertise::LabelRegistry::clear_for`), so credit
    /// and queue-budget state are scoped to a session's own lifetime, not
    /// silently inherited across a reconnect (finding H2: protocol.md 4.2
    /// scopes both to "(source session, destination session)", but
    /// without this, a reconnecting node's fresh WELCOME credit could
    /// land on top of, or be shrunk by, its previous session's leftover
    /// ledger state — either an accounting windfall or a spurious
    /// `credit_exceeded` kill of an entirely compliant reconnect).
    ///
    /// `node_id` needs clearing in both roles: as `dst`, because every
    /// pair targeting it represents "this destination session"'s own
    /// queue and must restart with it; as `src`, because its own fresh
    /// WELCOME grants it a new per-peer credit baseline that must replace
    /// (not add to or be capped by) whatever it had consumed and not yet
    /// been granted back in a previous session.
    pub(crate) fn clear_for(&self, node_id: &NodeId) {
        self.pairs
            .lock()
            .unwrap()
            .retain(|(src, dst), _| src != node_id && dst != node_id);
    }

    /// The credit `src` currently has remaining to send to `dst`, or
    /// `None` if this pair has never sent anything. Exposed for tests
    /// (crate-visible so the live end-to-end suite can use it too).
    #[cfg(test)]
    pub(crate) fn remaining_credit(&self, src: &NodeId, dst: &NodeId) -> Option<u32> {
        self.pairs
            .lock()
            .unwrap()
            .get(&(*src, *dst))
            .map(|pair| pair.credit.remaining())
    }

    /// `src`->`dst`'s current shared queue occupancy, or `None` if this
    /// pair has never sent anything. Exposed for tests.
    #[cfg(test)]
    pub(crate) fn queued_bytes(&self, src: &NodeId, dst: &NodeId) -> Option<usize> {
        self.pairs
            .lock()
            .unwrap()
            .get(&(*src, *dst))
            .map(|pair| pair.queued_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{Roster, RosterBody, RosterMember};

    fn test_limits() -> Limits {
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: 1_048_576,
        }
    }

    fn roster_with_members(
        owner: &SigningKey,
        network_id: NetworkId,
        members: Vec<NodeId>,
        expires: u64,
    ) -> Roster {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires,
            members: members
                .into_iter()
                .map(|node_id| RosterMember {
                    node_id,
                    min_serial: 1,
                })
                .collect(),
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    /// [`SessionRegistry::attach`]'s return value: dropping it closes the
    /// receivers, which would make [`SessionRegistry::deliver`] report
    /// `dst` as unreachable even though it is still registered — [`Fixture`]
    /// holds one for `src` and one for `dst` for exactly as long as it
    /// itself lives, so a test's `table.forward(...)` calls see a real,
    /// still-open destination throughout.
    type AttachHandles = (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::mpsc::Receiver<Record>,
        tokio::sync::mpsc::UnboundedReceiver<ForwardItem>,
    );

    struct Fixture {
        rosters: RosterStore,
        registry: SessionRegistry,
        labels: LabelRegistry,
        network_id: NetworkId,
        src: NodeId,
        dst: NodeId,
        _src_handles: AttachHandles,
        _dst_handles: AttachHandles,
    }

    fn fixture(expires: u64) -> Fixture {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let src = NodeId::from([1u8; 32]);
        let dst = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(
                &owner,
                network_id,
                vec![src, dst],
                expires,
            ))
            .unwrap();
        let registry = SessionRegistry::new();
        let src_handles = registry.attach(src, 1, vec![network_id]);
        let dst_handles = registry.attach(dst, 2, vec![network_id]);
        Fixture {
            rosters,
            registry,
            labels: LabelRegistry::new(),
            network_id,
            src,
            dst,
            _src_handles: src_handles,
            _dst_handles: dst_handles,
        }
    }

    fn reliable_send(payload_len: usize) -> (u8, u8, Vec<u8>) {
        (0x01, 0x00, vec![0u8; payload_len])
    }

    fn droppable_send(payload_len: usize) -> (u8, u8, Vec<u8>) {
        (0x01, 0x01, vec![0u8; payload_len])
    }

    #[test]
    fn a_reliable_send_to_an_attached_common_member_is_queued() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(1_000);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        assert!(matches!(outcome, ForwardOutcome::Queued));
    }

    #[test]
    fn an_unknown_e2e_proto_is_refused_without_touching_credit() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            0x03,
            0x00,
            vec![1, 2, 3],
            1_000,
        );
        match outcome {
            ForwardOutcome::Refused(err) => assert_eq!(err.code, ErrorCode::UnknownE2e),
            _ => panic!("expected Refused(UnknownE2e)"),
        }
        assert!(table.remaining_credit(&f.src, &f.dst).is_none());
    }

    #[test]
    fn a_send_to_an_authorized_but_unattached_node_is_peer_offline() {
        // `offline_member` is a legitimate, authorized Roster member
        // (unlike the unrelated stranger in
        // `a_send_to_an_unattached_stranger_with_no_standing_is_forbidden_not_peer_offline`)
        // who simply never attached — this is the case that must still
        // reach PeerOffline, now that authorization is checked first
        // (finding M2).
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let src = NodeId::from([1u8; 32]);
        let offline_member = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(
                &owner,
                network_id,
                vec![src, offline_member],
                4_000_000_000,
            ))
            .unwrap();
        let registry = SessionRegistry::new();
        let _src_handles = registry.attach(src, 1, vec![network_id]);
        let labels = LabelRegistry::new();
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(10);

        let outcome = table.forward(
            &rosters,
            &registry,
            &labels,
            &test_limits(),
            &src,
            &[network_id],
            &offline_member,
            e2e,
            flags,
            payload,
            1_000,
        );
        match outcome {
            ForwardOutcome::Refused(err) => assert_eq!(err.code, ErrorCode::PeerOffline),
            _ => panic!("expected Refused(PeerOffline)"),
        }
    }

    #[test]
    fn no_common_roster_membership_is_forbidden() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let src = NodeId::from([1u8; 32]);
        let dst = NodeId::from([2u8; 32]);
        // Only `src` is a member of the one Roster this relay holds.
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(
                &owner,
                network_id,
                vec![src],
                4_000_000_000,
            ))
            .unwrap();
        let registry = SessionRegistry::new();
        let _s = registry.attach(src, 1, vec![network_id]);
        let _d = registry.attach(dst, 2, vec![network_id]);
        let labels = LabelRegistry::new();
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(10);

        let outcome = table.forward(
            &rosters,
            &registry,
            &labels,
            &test_limits(),
            &src,
            &[network_id],
            &dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        match outcome {
            ForwardOutcome::Refused(err) => assert_eq!(err.code, ErrorCode::Forbidden),
            _ => panic!("expected Refused(Forbidden)"),
        }
    }

    #[test]
    fn a_send_to_an_unattached_stranger_with_no_standing_is_forbidden_not_peer_offline() {
        // Regression test for finding M2: a `src` with no authorization
        // at all must get the same answer (Forbidden) whether `dst`
        // exists, is attached, or is offline — never a distinguishing
        // PeerOffline that would leak `dst`'s online status to someone
        // with no standing to ask.
        let rosters = RosterStore::new();
        let registry = SessionRegistry::new();
        let labels = LabelRegistry::new();
        let table = ForwardTable::new();
        let prober = NodeId::from([1u8; 32]);
        let offline_target = NodeId::from([2u8; 32]);
        let (e2e, flags, payload) = reliable_send(10);

        let outcome = table.forward(
            &rosters,
            &registry,
            &labels,
            &test_limits(),
            &prober,
            &[],
            &offline_target,
            e2e,
            flags,
            payload,
            1_000,
        );
        match outcome {
            ForwardOutcome::Refused(err) => assert_eq!(err.code, ErrorCode::Forbidden),
            _ => panic!("expected Refused(Forbidden), not a PeerOffline leak"),
        }
    }

    #[test]
    fn an_expired_roster_no_longer_justifies_forwarding() {
        // protocol.md 2.3: "Once expires has passed, relays stop
        // forwarding for that network" — hello.rs and advertise.rs both
        // deliberately defer this exact check to here.
        let f = fixture(500); // expires well before `now_unix` below
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(10);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000, // now > expires
        );
        match outcome {
            ForwardOutcome::Refused(err) => assert_eq!(err.code, ErrorCode::Forbidden),
            _ => panic!("expected Refused(Forbidden) for an expired roster"),
        }
    }

    #[test]
    fn a_src_that_claimed_nothing_cannot_forward_at_all() {
        // protocol.md 4.1: "a node may claim no network; it may then
        // only redeem an invite".
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(10);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[], // claims nothing
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        match outcome {
            ForwardOutcome::Refused(err) => assert_eq!(err.code, ErrorCode::Forbidden),
            _ => panic!("expected Refused(Forbidden)"),
        }
    }

    #[test]
    fn a_destination_that_opted_out_of_peer_traffic_is_forbidden() {
        let f = fixture(4_000_000_000);
        // Simulate `dst`'s own prior ADVERTISE with accept_peers: false.
        f.labels.advertise(
            &f.rosters,
            &[f.network_id],
            &f.dst,
            &menzil_proto::AdvertiseBody {
                v: menzil_proto::PROTOCOL_VERSION,
                shares: vec![],
                accept_peers: false,
            },
        );
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(10);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        match outcome {
            ForwardOutcome::Refused(err) => assert_eq!(err.code, ErrorCode::Forbidden),
            _ => panic!("expected Refused(Forbidden)"),
        }
    }

    #[test]
    fn a_reliable_send_beyond_credit_is_a_credit_violation() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let limits = Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: 100,
        };
        let (e2e, flags, payload) = reliable_send(101);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &limits,
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        match outcome {
            ForwardOutcome::CreditViolation(err) => assert_eq!(err.code, ErrorCode::CreditExceeded),
            _ => panic!("expected CreditViolation"),
        }
    }

    #[test]
    fn credit_initial_value_is_clamped_to_the_queue_byte_cap() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let limits = Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: u32::MAX,
        };
        let (e2e, flags, payload) = reliable_send(1);
        table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &limits,
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        let remaining = table.remaining_credit(&f.src, &f.dst).unwrap();
        assert!(
            (remaining as usize) < MAX_QUEUE_BYTES,
            "an operator-configured credit larger than the queue cap must be clamped"
        );
    }

    #[test]
    fn drained_grants_credit_back_only_for_reliable_traffic() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(1_000);
        table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        let after_send = table.remaining_credit(&f.src, &f.dst).unwrap();
        assert_eq!(after_send, test_limits().credit - 1_000);

        table.drained(&f.registry, &f.src, &f.dst, 1_000, true);
        let after_drain = table.remaining_credit(&f.src, &f.dst).unwrap();
        assert_eq!(after_drain, test_limits().credit);
    }

    #[test]
    fn drained_delivers_a_credit_item_to_srcs_own_channel() {
        let registry = SessionRegistry::new();
        let src = NodeId::from([1u8; 32]);
        let dst = NodeId::from([2u8; 32]);
        let (_supersede_rx, _outbound_rx, mut forward_rx) = registry.attach(src, 1, vec![]);
        let table = ForwardTable::new();

        table.drained(&registry, &src, &dst, 500, true);

        match forward_rx.try_recv() {
            Ok(ForwardItem::Credit { peer, bytes }) => {
                assert_eq!(peer, dst);
                assert_eq!(bytes, 500);
            }
            Ok(ForwardItem::Recv { .. }) => panic!("expected a Credit item, got a Recv item"),
            Err(_) => panic!("expected a Credit item, got nothing"),
        }
    }

    #[test]
    fn drained_does_not_deliver_a_credit_item_for_droppable_traffic() {
        let registry = SessionRegistry::new();
        let src = NodeId::from([1u8; 32]);
        let dst = NodeId::from([2u8; 32]);
        let (_supersede_rx, _outbound_rx, mut forward_rx) = registry.attach(src, 1, vec![]);
        let table = ForwardTable::new();

        table.drained(&registry, &src, &dst, 500, false);

        assert!(
            forward_rx.try_recv().is_err(),
            "droppable traffic was never credited in the first place, so draining it must not \
             send a CREDIT record either"
        );
    }

    #[test]
    fn a_droppable_send_past_the_dgram_token_bucket_is_silently_dropped() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        // Larger than the 256 KiB burst: can never be admitted no matter
        // how it refills.
        let (e2e, flags, payload) = droppable_send(300 * 1024);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        assert!(matches!(outcome, ForwardOutcome::Dropped));
    }

    #[test]
    fn a_droppable_send_is_never_credited() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = droppable_send(10);
        table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        // A droppable send must never touch the credit ledger at all —
        // only its (shared) queue-byte accounting.
        assert_eq!(
            table.remaining_credit(&f.src, &f.dst).unwrap(),
            test_limits().credit
        );
    }

    #[test]
    fn droppable_is_dropped_once_reliable_traffic_fills_its_share_of_the_shared_queue() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let limits = Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: MAX_QUEUE_BYTES as u32,
        };
        let (e2e, flags, payload) = reliable_send(MAX_QUEUE_BYTES);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &limits,
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        assert!(matches!(outcome, ForwardOutcome::Queued));

        // Reliable's full credit (== the whole queue cap here) is now in
        // flight, leaving droppable's reserved headroom at exactly zero.
        let (e2e, flags, payload) = droppable_send(1);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &limits,
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        assert!(matches!(outcome, ForwardOutcome::Dropped));
    }

    #[test]
    fn combined_reliable_and_droppable_never_exceed_the_queue_cap() {
        // Regression test for finding L1: droppable fills up first, then
        // reliable adds its own full credit on top; the combined total
        // must still never exceed MAX_QUEUE_BYTES.
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let credit = 1_048_576u32; // the default, well under the cap
        let limits = Limits {
            max_record: 65_535,
            max_peers: 10,
            credit,
        };
        // Fill as much droppable as the reserved-headroom scheme allows,
        // one MIN_FORWARD_CHARGE_BYTES-sized send at a time.
        loop {
            let (e2e, flags, payload) = droppable_send(1);
            match table.forward(
                &f.rosters,
                &f.registry,
                &f.labels,
                &limits,
                &f.src,
                &[f.network_id],
                &f.dst,
                e2e,
                flags,
                payload,
                1_000,
            ) {
                ForwardOutcome::Queued => {}
                ForwardOutcome::Dropped => break,
                other => panic!("unexpected outcome while filling droppable: {other:?}"),
            }
        }
        let (e2e, flags, payload) = reliable_send(credit as usize);
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &limits,
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        assert!(matches!(outcome, ForwardOutcome::Queued));

        let total = table.queued_bytes(&f.src, &f.dst).unwrap();
        assert!(
            total <= MAX_QUEUE_BYTES,
            "combined reliable+droppable occupancy {total} exceeded the {MAX_QUEUE_BYTES} cap"
        );
    }

    #[test]
    fn a_zero_length_payload_still_charges_the_minimum_floor() {
        // Regression test for finding H4: a payload cheaper than
        // MIN_FORWARD_CHARGE_BYTES must still consume at least that much
        // credit, not zero — otherwise an unbounded number of them could
        // be admitted for free.
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let outcome = table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            0x01,
            0x00,
            vec![],
            1_000,
        );
        assert!(matches!(outcome, ForwardOutcome::Queued));
        assert_eq!(
            table.remaining_credit(&f.src, &f.dst).unwrap(),
            test_limits().credit - MIN_FORWARD_CHARGE_BYTES
        );
    }

    #[test]
    fn clear_for_resets_a_pair_where_node_id_is_the_source() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(1_000);
        table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        assert!(table.remaining_credit(&f.src, &f.dst).unwrap() < test_limits().credit);

        table.clear_for(&f.src);
        assert!(table.remaining_credit(&f.src, &f.dst).is_none());
    }

    #[test]
    fn clear_for_resets_a_pair_where_node_id_is_the_destination() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(1_000);
        table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        table.clear_for(&f.dst);
        assert!(table.remaining_credit(&f.src, &f.dst).is_none());
    }

    #[test]
    fn clear_for_does_not_affect_unrelated_pairs() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let stranger = NodeId::from([99u8; 32]);
        let (e2e, flags, payload) = reliable_send(1_000);
        table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.src,
            &[f.network_id],
            &f.dst,
            e2e,
            flags,
            payload,
            1_000,
        );
        table.clear_for(&stranger);
        assert!(table.remaining_credit(&f.src, &f.dst).is_some());
    }
}
