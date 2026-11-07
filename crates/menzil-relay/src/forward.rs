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
//! the sender." Isolation rule I4 adds that `dst`'s registration must have
//! claimed one of the networks that authorized `src`, and that every
//! failure after authorization is the same `peer_offline`.
//! [`ForwardTable::forward`] checks authorization
//! (`crate::roster_store::RosterStore::grants_forwarding`) *before* `dst`'s
//! attachment, deliberately the
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
//! A NodeId's pairs are also removed when its session ends and that
//! session was still the registered one (`crate::session` calls
//! [`ForwardTable::clear_for`] from `SessionRegistry::detach_then`, only
//! when the detach actually removed the registration, so a superseded
//! session's late teardown never touches its replacement's pairs). What
//! stays: a pair `(X, A)` that `X` creates in the instant after `A` has
//! detached (a SEND racing the teardown) lives until `A` or `X` next
//! attaches or detaches; and `drained` for a pair that is already gone
//! is a deliberate no-op.
//!
//! Tenant quotas (multi tenant design 2.3, slice MT8; threat A8). A pair counts against the
//! tenant of the network that authorized it, the first network of the sender's HELLO list that
//! the destination's registration also claimed. A tenant with figures is held to its number of
//! live pairs, to the destinations of one sending NodeId, and to the droppable bytes queued over
//! all its pairs; the relay as a whole is held to `Limits::max_peers` destinations per sending
//! NodeId. Only the creation of a NEW pair is ever refused (ERROR `over_quota`, credit
//! reimbursed, the session kept): a pair that exists keeps working whatever the tenant's counts
//! are, so a quota reached by abuse never cuts a legitimate conversation. Bandwidth is not a
//! refusal at all: [`ForwardTable::drained`] charges the tenant's bucket and volume counter
//! (`crate::shaping`) and, while the tenant is over its rate, the CREDIT that goes back to the
//! sender is held and released later by a timer, fairly among the tenant's senders
//! (`crate::shaping`), so the sender only waits. Droppable bytes are paid from the same bucket at
//! admission and dropped when the bucket is empty or in debt, so droppable traffic never delays
//! reliable CREDIT (T4 M1). A tenant without
//! figures (the default tenant, the `personal` class) is never shaped and never counted out.
//!
//! Accepted limit (round T4, N2): a pair keeps the tenant it was attributed to when it was made.
//! A tenant file edited by hand to move a network to another tenant (or to the default) leaves
//! the live pairs shaped, or unshaped, by the old tenant until a node reconnects (every pair of a
//! node goes with its session). Only an operator edit can cause it.
//!
//! A session evicted from a network ([`ForwardTable::revoke_sender`]) has the pairs IT made marked
//! and removed (a newer session of the same NodeId has pairs of its own, which are left alone;
//! T4 M2); the RECVs it had queued toward destinations are dropped unsent by the destination's
//! drain loop (a revocation is not delayed by what was already queued; T2 N2).
//!
//! Not built, real gaps: the
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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::Instant;

use menzil_proto::{ErrorBody, ErrorCode, Limits, NetworkId, NodeId, Record};
use menzil_session::CreditLedger;

use crate::advertise::LabelRegistry;
use crate::registry::SessionRegistry;
use crate::roster_store::RosterStore;
use crate::shaping::{Credit, Shapers};
use crate::tenant::{Figures, TenantBook, TenantId};

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
///
/// Promoted to `menzil_proto::MIN_SEND_CHARGE_BYTES` (TODO.md L4b) so
/// the node side's own local credit tracking floors a reliable SEND's
/// charge by the exact same number rather than an independently
/// maintained copy that could silently drift from what this module
/// actually enforces.
/// The one message of every `peer_offline` this module sends for a SEND (isolation rule I4):
/// destination offline, online without a claimed network in common, closed to peers, or gone
/// before delivery all read the same.
const PEER_OFFLINE_MSG: &str = "destination is not attached";

/// What a sender is told when a new pair would exceed a tenant or relay figure (design 2.3). It
/// names no tenant, figure or number: the sender knows its own networks, the rest is the
/// operator's.
const OVER_QUOTA_MSG: &str = "this relay's limit on devices talking to each other for your network is reached; try again later";

const MIN_FORWARD_CHARGE_BYTES: u32 = menzil_proto::MIN_SEND_CHARGE_BYTES;

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
    /// Distinguishes *this* `PairState` instance from any other that has
    /// ever occupied the same `(src, dst)` map key (TODO.md L4b's own
    /// review: a stale [`ForwardItem::Recv`] admitted under a pair that
    /// [`ForwardTable::clear_for`] has since reset — `src` reconnected in
    /// the meantime — must not apply its [`ForwardTable::drained`] effects
    /// to the *new* `PairState` that replaced it: crediting `charge` back
    /// to a fresh ledger that never actually spent it overstates `src`'s
    /// real balance, and a CREDIT record for it corrupts `src`'s own
    /// fresh, unrelated local tracking). Assigned once, at construction,
    /// from [`ForwardTable`]'s own monotonic counter; never compared for
    /// ordering, only equality.
    generation: u64,
    /// The droppable part of `queued_bytes`, also counted in the tenant's droppable total.
    droppable_bytes: usize,
    /// The session of `src` that made this pair, so that the eviction of that session marks and
    /// removes only its own pairs ([`ForwardTable::revoke_sender`], round T4 M2).
    src_session: u32,
    /// What the queued items of this pair carry with them: the tenant to charge and whether the
    /// sender was evicted.
    shared: Arc<PairShared>,
    /// Whether the pair is in the tenant, sender and relay counts. A member pair is; the relay's
    /// own virtual pair ([`ForwardTable::forward_from_relay`]) is not, so it never takes a
    /// tenant's `forwarding_pairs`, `destinations_per_node` or droppable total, and
    /// [`PairTable::uncount`] and `settle` leave the counts alone for it.
    counted: bool,
}

impl PairState {
    fn new(
        initial_credit: u32,
        now: Instant,
        generation: u64,
        tenant: TenantId,
        src_session: u32,
    ) -> Self {
        let initial_credit = initial_credit.min(MAX_QUEUE_BYTES as u32);
        Self {
            credit: CreditLedger::new(initial_credit),
            initial_credit,
            queued_bytes: 0,
            dgram_bucket: TokenBucket::new(now),
            generation,
            droppable_bytes: 0,
            src_session,
            shared: Arc::new(PairShared::new(tenant)),
            counted: true,
        }
    }

    /// The relay's own pair toward one node: no sender session, not in any count.
    fn new_virtual(initial_credit: u32, now: Instant, generation: u64, tenant: TenantId) -> Self {
        Self {
            counted: false,
            ..Self::new(initial_credit, now, generation, tenant, 0)
        }
    }
}

/// What every queued [`ForwardItem::Recv`] of one pair shares with the pair: which tenant its
/// bytes are charged to when they leave, and whether its sender has been evicted (T2 N2). It
/// outlives the pair itself (an item holds a reference), so a pair reset by a reconnect still
/// knows whom to charge and whether to drop.
#[derive(Debug)]
pub(crate) struct PairShared {
    tenant: TenantId,
    revoked: AtomicBool,
}

impl PairShared {
    fn new(tenant: TenantId) -> Self {
        Self {
            tenant,
            revoked: AtomicBool::new(false),
        }
    }

    /// A pair of no tenant, for tests that build items by hand.
    #[cfg(test)]
    pub(crate) fn untracked() -> Self {
        Self::new(TenantId::Default)
    }

    /// Whether the sender of this pair was evicted: the destination's drain loop does not send
    /// what it queued.
    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

/// Which data plane figure refused a new pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataQuota {
    /// The tenant's live pairs.
    Pairs,
    /// The tenant's destinations of one sending NodeId.
    DestinationsPerNode,
    /// The relay's `max_peers` destinations of one sending NodeId, announced in WELCOME.
    MaxPeers,
}

/// The counts behind the pair figures, kept with the pairs themselves so that creating and
/// removing a pair move them in the same critical section (nothing leaks on any path).
#[derive(Default)]
struct PairTable {
    pairs: HashMap<(NodeId, NodeId), PairState>,
    /// Per tenant: live pairs and queued droppable bytes. An entry exists while it has pairs.
    per_tenant: HashMap<TenantId, TenantPairs>,
    /// Per (tenant, sending NodeId): its live pairs, which are its distinct destinations.
    per_sender: HashMap<(TenantId, NodeId), usize>,
    /// Per sending NodeId over all tenants, for `max_peers`.
    per_src: HashMap<NodeId, usize>,
}

#[derive(Default)]
struct TenantPairs {
    pairs: usize,
    droppable_bytes: usize,
}

impl PairTable {
    /// Which figure, if any, a NEW pair of `src` in `tenant` would exceed.
    fn quota_for_new_pair(
        &self,
        tenant: &TenantId,
        src: &NodeId,
        figures: Option<&Figures>,
        max_peers: u32,
    ) -> Option<DataQuota> {
        if let Some(figures) = figures {
            let held = self.per_tenant.get(tenant).map_or(0, |t| t.pairs);
            if held as u64 >= figures.forwarding_pairs {
                return Some(DataQuota::Pairs);
            }
            let sender = self
                .per_sender
                .get(&(tenant.clone(), *src))
                .copied()
                .unwrap_or(0);
            if sender as u64 >= figures.destinations_per_node {
                return Some(DataQuota::DestinationsPerNode);
            }
        }
        let total = self.per_src.get(src).copied().unwrap_or(0);
        if total >= max_peers as usize {
            return Some(DataQuota::MaxPeers);
        }
        None
    }

    /// Takes a pair's place in the counts.
    fn count(&mut self, tenant: &TenantId, src: &NodeId) {
        self.per_tenant.entry(tenant.clone()).or_default().pairs += 1;
        *self.per_sender.entry((tenant.clone(), *src)).or_default() += 1;
        *self.per_src.entry(*src).or_default() += 1;
    }

    /// Gives a removed pair's place back, with the droppable bytes it still had queued.
    fn uncount(&mut self, src: &NodeId, pair: &PairState) {
        if !pair.counted {
            return;
        }
        let tenant = &pair.shared.tenant;
        if let Some(held) = self.per_tenant.get_mut(tenant) {
            held.pairs = held.pairs.saturating_sub(1);
            held.droppable_bytes = held.droppable_bytes.saturating_sub(pair.droppable_bytes);
            if held.pairs == 0 {
                self.per_tenant.remove(tenant);
            }
        }
        let sender = (tenant.clone(), *src);
        if let Some(held) = self.per_sender.get_mut(&sender) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                self.per_sender.remove(&sender);
            }
        }
        if let Some(held) = self.per_src.get_mut(src) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                self.per_src.remove(src);
            }
        }
    }

    /// Removes every pair `node_id` is in, in either role.
    fn remove_involving(&mut self, node_id: &NodeId) {
        let keys: Vec<(NodeId, NodeId)> = self
            .pairs
            .keys()
            .filter(|(src, dst)| src == node_id || dst == node_id)
            .copied()
            .collect();
        for key in keys {
            if let Some(pair) = self.pairs.remove(&key) {
                self.uncount(&key.0, &pair);
            }
        }
    }
}

/// One item handed to [`SessionRegistry::deliver`]: either a RECV record
/// to actually send, with enough bookkeeping for `crate::session`'s drain
/// loop to call [`ForwardTable::drained`] once it is sent, or a CREDIT
/// record to send as-is. Both travel the same reliable, unbounded channel
/// — CREDIT deliberately does not use [`SessionRegistry::send_to`]'s
/// lossy one (finding H3; see this module's own doc comment).
#[derive(Debug)]
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
        /// The `(src, dst)` `PairState`'s generation at admission time
        /// (see [`PairState::generation`]'s own doc comment); carried
        /// through so [`ForwardTable::drained`] can tell whether *this
        /// pair's own* bookkeeping (`queued_bytes`, `credit`) is still the
        /// same instance this item was admitted against, or has since
        /// been reset and recreated by a reconnect on either side.
        generation: u64,
        /// `src`'s own `SessionRegistry` session id at admission time —
        /// deliberately a *different* question from `generation` above.
        /// `generation` resets whenever *either* `src` or `dst`
        /// reconnects (`ForwardTable::clear_for` clears a pair in both
        /// roles), but a CREDIT record is owed to `src` regardless of
        /// what `dst` does: `src`'s own local credit tracking
        /// (`menzil-node::outbound::OutboundQueue`) spent this charge
        /// under a ledger scoped to `src`'s own session, not to any
        /// particular incarnation of the pair, and has no visibility
        /// into `dst`'s reconnects at all. [`ForwardTable::drained`]
        /// checks this against [`SessionRegistry::is_current`] to decide
        /// whether to emit the CREDIT record at all — independently of
        /// whether `generation` says this pair's own internal ledger
        /// should be touched (TODO.md L4b's own second review round,
        /// which live-reproduced a real bug in the first version of this
        /// fix: gating the CREDIT record on `generation` alone meant a
        /// `dst`-only reconnect could permanently strand `src`'s credit
        /// for items that were in flight at the time, even though `src`
        /// itself never reconnected and had every right to be reimbursed).
        src_session_id: u32,
        /// The pair's tenant and eviction mark (see [`PairShared`]).
        shared: Arc<PairShared>,
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
    /// A NEW pair would exceed a tenant or relay figure (design 2.3): refused like
    /// [`ForwardOutcome::Refused`] (the caller sends `error` and keeps the session; credit was
    /// reimbursed), and the caller also tells the operator, throttled, which tenant is full.
    OverQuota {
        error: ErrorBody,
        tenant: TenantId,
        quota: DataQuota,
    },
}

/// What [`ForwardTable::forward_from_relay`] decided about one frame the relay sends to a node.
/// The relay is a trusted sender: nothing here is an ERROR for a peer, the caller (the expose
/// principal) acts on it. `Queued` and `Dropped` are final; the others say why nothing was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySendOutcome {
    /// Handed to the node's connection to send.
    Queued,
    /// A droppable frame was discarded (the pair's queue, its token bucket or the name tenant's
    /// bucket had no room). Silent, as for a member's droppable SEND.
    Dropped,
    /// A reliable frame did not fit the pair's credit (the 4 MiB queue is full of what the node
    /// has not been sent yet). Nothing was queued; try again once the node's connection drained.
    Full,
    /// A reliable frame was held back because the name tenant's bandwidth bucket is in debt
    /// (the shaping every member of that tenant lives under). Nothing was queued; try again
    /// later.
    Throttled,
    /// The node is not attached.
    PeerOffline,
    /// `e2e_proto` is neither 0x01 nor 0x02.
    UnknownE2e,
}

/// What admitting one SEND to its pair decided, before anything is told to a session (the pair
/// table's lock is never held while the registry is used: `SessionRegistry::detach_then` takes
/// the registry's lock first and the pair table's second).
enum Early {
    Dropped,
    CreditViolation(ErrorBody),
    OverQuota(TenantId, DataQuota),
}

/// Per-(source,destination) credit ledgers, queue budgets, and droppable
/// token buckets (protocol.md 4.2's flow-control paragraph; TODO.md L3h).
pub(crate) struct ForwardTable {
    pairs: Mutex<PairTable>,
    /// Source of [`PairState::generation`] values: incremented every time
    /// a `PairState` is actually constructed, never reset, never reused —
    /// uniqueness across the table's lifetime is all `drained`'s
    /// equality check needs.
    next_generation: AtomicU64,
    /// The relay's tenants, shared with `Relay` (a reload is seen by the next SEND).
    tenants: Arc<RwLock<Arc<TenantBook>>>,
    /// The bandwidth bucket and volume counter of each tenant that has figures.
    shapers: Shapers,
}

impl Default for ForwardTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardTable {
    /// No pairs seen yet, one default tenant without figures.
    pub(crate) fn new() -> Self {
        Self::with_tenants(Arc::new(RwLock::new(Arc::new(TenantBook::default()))))
    }

    /// No pairs seen yet, judging tenants by `tenants` (the handle the relay swaps its book in).
    pub(crate) fn with_tenants(tenants: Arc<RwLock<Arc<TenantBook>>>) -> Self {
        Self {
            pairs: Mutex::new(PairTable::default()),
            next_generation: AtomicU64::new(0),
            tenants,
            shapers: Shapers::default(),
        }
    }

    fn book(&self) -> Arc<TenantBook> {
        Arc::clone(&self.tenants.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn table(&self) -> MutexGuard<'_, PairTable> {
        self.pairs.lock().unwrap_or_else(PoisonError::into_inner)
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
    /// `dst` is currently attached, its registration claimed one of the networks that authorized
    /// `src`, and it has not opted out via `accept_peers: false` (all three answer the same
    /// `peer_offline`, isolation rule I4); then, only once every one of those passes,
    /// the credit/queue/token-bucket admission this module's own doc
    /// comment describes.
    ///
    /// A narrow, deliberately accepted race: `dst`'s attachment is
    /// confirmed, then acted on, as two separate steps, so `dst` could in
    /// principle detach, or re-attach with other claims, in between. The hand-off goes only to
    /// the session whose claims were checked, so a re-attached `dst` never receives what its
    /// new claims were not checked for. Handled by rolling back whatever
    /// this call had already reserved (credit, queue bytes) and reporting
    /// [`ErrorCode::PeerOffline`] rather than silently leaking it, but not
    /// otherwise prevented; the same already-accepted class of gap
    /// `SessionRegistry::attach`'s and `crate::advertise`'s own doc
    /// comments describe for an analogous check-then-act window elsewhere
    /// in this crate.
    ///
    /// Every refusal (`Refused`, including this method's own internal
    /// disconnect-race rollback) also reimburses `src` for `charge` when
    /// the send was reliable (TODO.md L4b's own review): `src`'s *local*
    /// credit tracking has no ACK to wait for — protocol.md 4.2 gives it
    /// no way to learn a SEND's outcome before spending the credit it
    /// optimistically charges the moment a record is handed to the wire
    /// (`menzil-node::outbound::OutboundQueue::next_ready_to_send`) — so
    /// this relay's own ledger never actually being touched by a refusal
    /// is not enough; `src` must be told to put the credit back too, and
    /// ERROR carries no destination for it to do that itself. A
    /// `CreditViolation` is deliberately exempt: it ends `src`'s session
    /// (the caller's job, once this returns), and there is no reason to
    /// reimburse a session about to close.
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
        let reliable = flags & 0x01 == 0;
        let charge = (payload.len() as u32).max(MIN_FORWARD_CHARGE_BYTES);
        let reimburse = || {
            if reliable {
                registry.deliver(
                    src,
                    ForwardItem::Credit {
                        peer: *dst,
                        bytes: charge,
                    },
                );
            }
        };
        let refuse = |code: ErrorCode, msg: String| {
            reimburse();
            ForwardOutcome::Refused(ErrorBody { code, msg })
        };

        if e2e_proto != 0x01 && e2e_proto != 0x02 {
            return refuse(
                ErrorCode::UnknownE2e,
                format!("unrecognized e2e_proto {e2e_proto:#04x}"),
            );
        }

        // Authorization first, using only `src`'s own already-known
        // claims — never `dst`'s attachment state (finding M2: checking
        // attachment before authorization let anyone probe any NodeId's
        // online status with no standing of their own).
        let authorizing = rosters.grants_forwarding(src, src_claimed, dst, now_unix);
        if authorizing.is_empty() {
            return refuse(
                ErrorCode::Forbidden,
                "sender has no claimed, unexpired network membership in common with the destination"
                    .to_string(),
            );
        }

        // Isolation rule I4. `src`'s claims authorizing `dst` in some Roster is not enough: the
        // owner of that Roster may have listed another tenant's node without its consent. `dst`
        // must be attached, its current registration must have claimed one of the authorizing
        // networks (claims and session id read together, one registry read lock), and it must
        // accept peers. Every way of failing this is the same answer, byte for byte, so the
        // reply never says whether `dst` is offline, elsewhere, or closed to peers.
        let target = registry
            .attachment_of(dst)
            .filter(|attachment| {
                attachment
                    .claimed_networks
                    .iter()
                    .any(|network| authorizing.contains(network))
            })
            .filter(|_| labels.accepts_peers(dst));
        let Some(target) = target else {
            return refuse(ErrorCode::PeerOffline, PEER_OFFLINE_MSG.to_string());
        };

        // The pair's tenant: the first network of the sender's HELLO list that the destination
        // also claimed (design 2.1). The filter above guarantees there is one.
        let pair_network = authorizing
            .iter()
            .find(|network| target.claimed_networks.contains(network))
            .unwrap_or(&authorizing[0]);

        // `src` is necessarily attached right now — this call is
        // processing a SEND it just sent — so `None` here would mean it
        // detached in the instant between; using a sentinel rather than
        // panicking, `is_current` then correctly reports `false` for it
        // regardless (no registration at all is no more "current" than a
        // mismatched id), which is the same fail-safe direction
        // `ForwardTable::drained` already needs for a genuine reconnect.
        let src_session_id = registry.attached_session_id(src).unwrap_or(u32::MAX);

        let book = self.book();
        let admitted = self.admit(
            &book,
            limits,
            src,
            dst,
            src_session_id,
            pair_network,
            reliable,
            charge,
            Instant::now(),
        );
        let (generation, shared) = match admitted {
            Ok(admitted) => admitted,
            Err(Early::Dropped) => return ForwardOutcome::Dropped,
            Err(Early::CreditViolation(error)) => return ForwardOutcome::CreditViolation(error),
            Err(Early::OverQuota(tenant, quota)) => {
                reimburse();
                return ForwardOutcome::OverQuota {
                    error: ErrorBody {
                        code: ErrorCode::OverQuota,
                        msg: OVER_QUOTA_MSG.to_string(),
                    },
                    tenant,
                    quota,
                };
            }
        };

        let delivered = registry.deliver_to_session(
            dst,
            target.session_id,
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
                generation,
                src_session_id,
                shared: Arc::clone(&shared),
            },
        );
        if delivered {
            return ForwardOutcome::Queued;
        }

        // `dst` disconnected, or re-attached (a registration whose claims were never checked),
        // between the attachment read above and this handoff: undo what
        // was reserved so this pair's accounting does not leak credit or
        // queue budget nothing will ever drain. This is exactly what a
        // drained item does, including its `generation` and `is_current`
        // guards: the pair may have been reset (a reconnect of `src` or
        // `dst`) since the reservation, and then the new pair's ledger and
        // the new session of `src` must not be touched.
        self.released(
            registry,
            src,
            dst,
            charge,
            reliable,
            generation,
            src_session_id,
            &shared,
        );
        ForwardOutcome::Refused(ErrorBody {
            code: ErrorCode::PeerOffline,
            msg: PEER_OFFLINE_MSG.to_string(),
        })
    }

    /// Call once a [`ForwardItem::Recv`] has actually been handed to
    /// `dst`'s own connection to send — or once it's known it never will
    /// be, because that connection ended with items still queued
    /// (`crate::session`'s teardown drain; finding H1) — passing the
    /// exact `charge`/`reliable`/`generation`/`src_session_id` it was
    /// admitted with. Two independent questions, gated separately (see
    /// [`ForwardItem::Recv::src_session_id`]'s own doc comment for the
    /// full story of why these must not be the same check):
    ///
    /// 1. Does *this pair's own* bookkeeping (`queued_bytes`, and
    ///    `credit` if reliable) still get touched? Only if `generation`
    ///    still matches the `PairState` on file — `ForwardTable::clear_for`
    ///    can remove and later recreate this exact `(src, dst)` key (a
    ///    reconnect by *either* side), and applying a stale item's
    ///    effects to whatever fresh instance now occupies that key would
    ///    corrupt it regardless of direction: granting `charge` back
    ///    overstates a fresh ledger that never actually spent it, and
    ///    subtracting `charge` from a fresh `queued_bytes` (already 0, or
    ///    already counting unrelated fresh admissions) corrupts it the
    ///    same way.
    /// 2. Does `src` get sent a CREDIT record at all? Only if
    ///    `src_session_id` still names `src`'s *current* session
    ///    ([`SessionRegistry::is_current`]) — regardless of what answer
    ///    question 1 got. `src`'s own local credit tracking has no
    ///    visibility into `dst`'s reconnects and is owed reimbursement
    ///    for a charge it genuinely spent as long as `src` itself is
    ///    still the same session; only `src`'s *own* reconnect (a fresh
    ///    ledger with nothing to do with what the old one spent) makes
    ///    reimbursing it wrong.
    ///
    /// A `src` that is still attached but happens to have no ledger at
    /// all for this exact pair cannot occur in practice
    /// ([`ForwardTable::forward`] always creates the pair, and so its
    /// generation, before a [`ForwardItem`] naming it can exist); a `src`
    /// no longer attached at all is the ordinary, harmless case
    /// [`SessionRegistry::deliver`] already handles by silently dropping
    /// the record — nothing left to tell.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn drained(
        &self,
        registry: &SessionRegistry,
        src: &NodeId,
        dst: &NodeId,
        charge: u32,
        reliable: bool,
        generation: u64,
        src_session_id: u32,
        shared: &PairShared,
    ) {
        self.settle(
            registry,
            src,
            dst,
            charge,
            reliable,
            generation,
            src_session_id,
            shared,
            true,
        );
    }

    /// [`Self::drained`] for an item that was never sent to `dst`: the destination went away, or
    /// the sender was evicted and its queued data is dropped. Everything is released as for a
    /// sent one, except that the bytes are not charged to the tenant's bandwidth or volume (they
    /// did not travel) and the sender's CREDIT, if it is still owed, is not delayed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn released(
        &self,
        registry: &SessionRegistry,
        src: &NodeId,
        dst: &NodeId,
        charge: u32,
        reliable: bool,
        generation: u64,
        src_session_id: u32,
        shared: &PairShared,
    ) {
        self.settle(
            registry,
            src,
            dst,
            charge,
            reliable,
            generation,
            src_session_id,
            shared,
            false,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn settle(
        &self,
        registry: &SessionRegistry,
        src: &NodeId,
        dst: &NodeId,
        charge: u32,
        reliable: bool,
        generation: u64,
        src_session_id: u32,
        shared: &PairShared,
        sent: bool,
    ) {
        {
            let mut guard = self.table();
            let PairTable {
                pairs, per_tenant, ..
            } = &mut *guard;
            if let Some(pair) = pairs.get_mut(&(*src, *dst))
                && pair.generation == generation
            {
                pair.queued_bytes = pair.queued_bytes.saturating_sub(charge as usize);
                if reliable {
                    pair.credit.grant(charge);
                } else {
                    // The droppable bytes admitted for this pair and not yet released, also in
                    // the tenant's total.
                    let freed = pair.droppable_bytes.min(charge as usize);
                    pair.droppable_bytes -= freed;
                    if pair.counted
                        && let Some(held) = per_tenant.get_mut(&shared.tenant)
                    {
                        held.droppable_bytes = held.droppable_bytes.saturating_sub(freed);
                    }
                }
            }
        }
        // Whether `src` is owed a CREDIT record now: its session is still the one that spent the
        // charge (see `ForwardItem::Recv::src_session_id`). Bandwidth may postpone it.
        let mut grant_now = reliable && registry.is_current(src, src_session_id);
        // Droppable bytes were paid at admission (`Shaper::try_take`), reliable ones are paid here.
        if sent
            && reliable
            && let Some(figures) = self.book().figures_of(&shared.tenant).copied()
        {
            let shaper = self.shapers.of(&shared.tenant, &figures);
            let owed = grant_now.then_some((*src, *dst, src_session_id));
            match shaper.charge(&figures, charge, owed, tokio::time::Instant::now()) {
                Credit::Now | Credit::None => {}
                Credit::Held { start_timer } => {
                    grant_now = false;
                    if start_timer {
                        match tokio::runtime::Handle::try_current() {
                            Ok(runtime) => {
                                runtime.spawn(shaper.flush(registry.clone()));
                            }
                            // No runtime, no timer: grant what is held rather than keep it for
                            // ever (delay is never loss).
                            Err(_) => shaper.release_all(registry),
                        }
                    }
                }
            }
        }
        if grant_now {
            registry.deliver(
                src,
                ForwardItem::Credit {
                    peer: *dst,
                    bytes: charge,
                },
            );
        }
    }

    /// Admits one SEND of `charge` bytes from `src` to `dst` into its pair, creating the pair
    /// if it is new. A NEW pair is refused when its tenant (or the relay) is at a figure
    /// ([`PairTable::quota_for_new_pair`]); an existing pair is never refused for a count. Runs
    /// under the pair table's lock and touches nothing else.
    #[allow(clippy::too_many_arguments)]
    fn admit(
        &self,
        book: &TenantBook,
        limits: &Limits,
        src: &NodeId,
        dst: &NodeId,
        src_session: u32,
        pair_network: &NetworkId,
        reliable: bool,
        charge: u32,
        now: Instant,
    ) -> Result<(u64, Arc<PairShared>), Early> {
        let mut guard = self.table();
        let table = &mut *guard;
        let key = (*src, *dst);
        if !table.pairs.contains_key(&key) {
            let tenant = book
                .pair_tenant(std::slice::from_ref(pair_network))
                .cloned()
                .unwrap_or(TenantId::Default);
            if let Some(quota) =
                table.quota_for_new_pair(&tenant, src, book.figures_of(&tenant), limits.max_peers)
            {
                return Err(Early::OverQuota(tenant, quota));
            }
            table.count(&tenant, src);
            let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
            table.pairs.insert(
                key,
                PairState::new(limits.credit, now, generation, tenant, src_session),
            );
        }
        let PairTable {
            pairs, per_tenant, ..
        } = table;
        let Some(pair) = pairs.get_mut(&key) else {
            unreachable!("the pair was found or inserted above under the same lock");
        };
        let generation = pair.generation;
        let shared = Arc::clone(&pair.shared);

        if reliable {
            if let Err(err) = pair.credit.consume(charge) {
                return Err(Early::CreditViolation(ErrorBody {
                    code: ErrorCode::CreditExceeded,
                    msg: err.to_string(),
                }));
            }
        } else {
            // Droppable admission reserves `initial_credit` worth of
            // headroom for reliable's own worst case up front, rather
            // than comparing against the raw `MAX_QUEUE_BYTES` — see
            // this module's own doc comment (finding L1) for why
            // comparing against the raw cap let the two classes
            // combine past the documented bound.
            let droppable_ceiling = MAX_QUEUE_BYTES.saturating_sub(pair.initial_credit as usize);
            // The tenant's droppable cap over all its pairs (design 2.3): a droppable SEND
            // over it is silently dropped, as one over the pair's own ceiling.
            let tenant_cap = book
                .figures_of(&shared.tenant)
                .map(|figures| figures.droppable_mib.saturating_mul(1 << 20) as usize);
            let tenant_held = per_tenant
                .get(&shared.tenant)
                .map_or(0, |held| held.droppable_bytes);
            if pair.queued_bytes + charge as usize > droppable_ceiling
                || tenant_cap.is_some_and(|cap| tenant_held + charge as usize > cap)
                || !pair.dgram_bucket.try_take(charge as usize, now)
            {
                return Err(Early::Dropped);
            }
            // The tenant's bandwidth (round T4, M1): droppable bytes are paid from the bucket
            // now, never on credit; a bucket that is empty or in debt drops the record. Last, so
            // a record refused above takes nothing from the tenant.
            if let Some(figures) = book.figures_of(&shared.tenant)
                && !self.shapers.of(&shared.tenant, figures).try_take(
                    figures,
                    charge,
                    tokio::time::Instant::now(),
                )
            {
                return Err(Early::Dropped);
            }
            pair.droppable_bytes += charge as usize;
            if let Some(held) = per_tenant.get_mut(&shared.tenant) {
                held.droppable_bytes += charge as usize;
            }
        }
        pair.queued_bytes += charge as usize;
        Ok((generation, shared))
    }

    /// Sends one frame from the relay itself (`src` = `relay_id` on the wire) to `dst`, through
    /// the relay's virtual pair toward that node. It is the data plane's half of the expose
    /// principal (the relay's own L4 session): the same queue, accounting and shaping a member
    /// SEND gets, minus everything that only makes sense between two members.
    ///
    /// Kept: the pair's credit ledger and its 4 MiB queue (a reliable frame past the credit is
    /// `Full`, a droppable one past the headroom or the token bucket is `Dropped`), the
    /// drain-based release ([`ForwardTable::drained`] and [`ForwardTable::released`] settle it
    /// like any item), and the bandwidth and volume of the tenant of the NAME the traffic is for
    /// (`tenant`, which the caller resolves from the name; the relay's own pair has no network).
    /// The bucket is charged when the frame is handed to the node's connection; a reliable frame
    /// is refused as `Throttled` while that bucket is in debt (the relay's own sender has no
    /// CREDIT record to delay, so it is told instead), and a droppable one is paid from the
    /// bucket at admission, as for a member.
    ///
    /// Skipped: the Roster and membership check (the relay is not a member; the node's own
    /// consent to the traffic is checked on the node, not here), `accept_peers` (a node closed
    /// to peers still serves its own shares), and every count: the virtual pair is not in the
    /// tenant's `forwarding_pairs`, `destinations_per_node` or droppable total, nor in the
    /// relay's `max_peers` (see [`PairState::counted`]). The pair goes when `dst` next attaches
    /// or detaches ([`ForwardTable::clear_for`]), like every pair of that node.
    ///
    /// The tenant of a frame travels with the frame (a pair per node, but a tenant per call), so
    /// two names of one node in two tenants are each charged to their own.
    ///
    /// `session_id` is the L3 session of `dst` the caller expects; another one attached now
    /// makes the frame `PeerOffline` (the L4 session of the caller is pinned to the old one).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn forward_from_relay(
        &self,
        registry: &SessionRegistry,
        limits: &Limits,
        relay_id: &NodeId,
        tenant: &TenantId,
        dst: &NodeId,
        session_id: u32,
        e2e_proto: u8,
        flags: u8,
        payload: Vec<u8>,
    ) -> RelaySendOutcome {
        if e2e_proto != 0x01 && e2e_proto != 0x02 {
            return RelaySendOutcome::UnknownE2e;
        }
        let reliable = flags & 0x01 == 0;
        let charge = (payload.len() as u32).max(MIN_FORWARD_CHARGE_BYTES);
        // A frame to the relay itself would be a pair (relay, relay) that nothing drains.
        if dst == relay_id {
            return RelaySendOutcome::PeerOffline;
        }
        let Some(target) = registry.attachment_of(dst) else {
            return RelaySendOutcome::PeerOffline;
        };
        // The caller's L4 session is pinned to one L3 session of `dst`; once that is not the
        // current attachment the frame is not for the node that is attached now.
        if target.session_id != session_id {
            return RelaySendOutcome::PeerOffline;
        }
        let book = self.book();
        if reliable
            && let Some(figures) = book.figures_of(tenant)
            && self
                .shapers
                .of(tenant, figures)
                .in_debt(figures, tokio::time::Instant::now())
        {
            return RelaySendOutcome::Throttled;
        }
        let (generation, shared) = match self.admit_virtual(
            &book,
            limits,
            relay_id,
            dst,
            tenant,
            reliable,
            charge,
            Instant::now(),
        ) {
            Ok(admitted) => admitted,
            Err(outcome) => return outcome,
        };
        let delivered = registry.deliver_to_session(
            dst,
            target.session_id,
            ForwardItem::Recv {
                record: Box::new(Record::Recv {
                    // Stamped here, never taken from a caller or a wire field.
                    src: *relay_id,
                    e2e_proto,
                    flags,
                    payload,
                }),
                src: *relay_id,
                charge,
                reliable,
                generation,
                // The relay has no session in the registry, so no CREDIT is ever owed to it.
                src_session_id: 0,
                shared: Arc::clone(&shared),
            },
        );
        if delivered {
            return RelaySendOutcome::Queued;
        }
        // `dst` went away between the read and the hand-off: give back what was reserved.
        self.released(
            registry, relay_id, dst, charge, reliable, generation, 0, &shared,
        );
        RelaySendOutcome::PeerOffline
    }

    /// [`Self::admit`] for the relay's virtual pair toward `dst`: the pair is made without
    /// quota and without counts, and the tenant of this one frame is recorded on it.
    #[allow(clippy::too_many_arguments)]
    fn admit_virtual(
        &self,
        book: &TenantBook,
        limits: &Limits,
        relay_id: &NodeId,
        dst: &NodeId,
        tenant: &TenantId,
        reliable: bool,
        charge: u32,
        now: Instant,
    ) -> Result<(u64, Arc<PairShared>), RelaySendOutcome> {
        let mut guard = self.table();
        let key = (*relay_id, *dst);
        let pair = guard.pairs.entry(key).or_insert_with(|| {
            let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
            PairState::new_virtual(limits.credit, now, generation, tenant.clone())
        });
        // The items already queued keep the `PairShared` they were admitted with.
        if pair.shared.tenant != *tenant {
            pair.shared = Arc::new(PairShared::new(tenant.clone()));
        }
        let generation = pair.generation;
        let shared = Arc::clone(&pair.shared);
        if reliable {
            if pair.credit.consume(charge).is_err() {
                return Err(RelaySendOutcome::Full);
            }
        } else {
            let droppable_ceiling = MAX_QUEUE_BYTES.saturating_sub(pair.initial_credit as usize);
            if pair.queued_bytes + charge as usize > droppable_ceiling
                || !pair.dgram_bucket.try_take(charge as usize, now)
            {
                return Err(RelaySendOutcome::Dropped);
            }
            if let Some(figures) = book.figures_of(tenant)
                && !self.shapers.of(tenant, figures).try_take(
                    figures,
                    charge,
                    tokio::time::Instant::now(),
                )
            {
                return Err(RelaySendOutcome::Dropped);
            }
            pair.droppable_bytes += charge as usize;
        }
        pair.queued_bytes += charge as usize;
        Ok((generation, shared))
    }

    /// `src`'s session `session_id` has been evicted from a network (it is ending): what that
    /// session already queued toward destinations must not be delivered there (T2 N2), so the
    /// pairs it made are marked ([`PairShared::is_revoked`], checked by the destinations' drain
    /// loops) and removed, with their counts. Only pairs made by this session are touched: a
    /// newer session of the same NodeId has pairs of its own (round T4 M2), and the mark cannot
    /// outlive the pair it is on, so a later pair of `src` never inherits it. Items already
    /// queued keep the marked [`PairShared`] and are dropped unsent.
    pub(crate) fn revoke_sender(&self, src: &NodeId, session_id: u32) {
        let mut guard = self.table();
        let keys: Vec<(NodeId, NodeId)> = guard
            .pairs
            .iter()
            .filter(|((from, _), pair)| from == src && pair.src_session == session_id)
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            if let Some(pair) = guard.pairs.remove(&key) {
                pair.shared.revoked.store(true, Ordering::Release);
                guard.uncount(&key.0, &pair);
            }
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
        self.table().remove_involving(node_id);
    }

    /// The credit `src` currently has remaining to send to `dst`, or
    /// `None` if this pair has never sent anything. Exposed for tests
    /// (crate-visible so the live end-to-end suite can use it too).
    #[cfg(test)]
    pub(crate) fn remaining_credit(&self, src: &NodeId, dst: &NodeId) -> Option<u32> {
        self.table()
            .pairs
            .get(&(*src, *dst))
            .map(|pair| pair.credit.remaining())
    }

    /// Creates a fresh `src`->`dst` pair as `forward` would. Exposed for
    /// tests that need pair state without a live session.
    #[cfg(test)]
    pub(crate) fn insert_test_pair(&self, src: &NodeId, dst: &NodeId) {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut table = self.table();
        table.count(&TenantId::Default, src);
        table.pairs.insert(
            (*src, *dst),
            PairState::new(1024, Instant::now(), generation, TenantId::Default, 0),
        );
    }

    /// [`Self::insert_test_pair`] counted for `tenant` (tests of the status export).
    #[cfg(test)]
    pub(crate) fn insert_test_pair_for(&self, tenant: &TenantId, src: &NodeId, dst: &NodeId) {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed);
        let mut table = self.table();
        table.count(tenant, src);
        table.pairs.insert(
            (*src, *dst),
            PairState::new(1024, Instant::now(), generation, tenant.clone(), 0),
        );
    }

    /// `src`->`dst`'s credit and queue figures for tests of the virtual pair:
    /// (remaining credit, queued bytes, counted).
    #[cfg(test)]
    pub(crate) fn pair_figures(&self, src: &NodeId, dst: &NodeId) -> Option<(u32, usize, bool)> {
        self.table()
            .pairs
            .get(&(*src, *dst))
            .map(|pair| (pair.credit.remaining(), pair.queued_bytes, pair.counted))
    }

    /// How many pairs involve `node_id`, in either role. Exposed for
    /// tests (teardown must leave none behind).
    #[cfg(test)]
    pub(crate) fn pair_count_for(&self, node_id: &NodeId) -> usize {
        self.table()
            .pairs
            .keys()
            .filter(|(src, dst)| src == node_id || dst == node_id)
            .count()
    }

    /// `src`->`dst`'s current shared queue occupancy, or `None` if this
    /// pair has never sent anything. Exposed for tests.
    #[cfg(test)]
    pub(crate) fn queued_bytes(&self, src: &NodeId, dst: &NodeId) -> Option<usize> {
        self.table()
            .pairs
            .get(&(*src, *dst))
            .map(|pair| pair.queued_bytes)
    }

    /// `src`->`dst`'s current `PairState::generation`, or `None` if this
    /// pair has never sent anything. Exposed for tests, so a test can
    /// call [`Self::drained`] with the actual current value rather than
    /// assuming this table's internal numbering.
    #[cfg(test)]
    pub(crate) fn generation_of(&self, src: &NodeId, dst: &NodeId) -> Option<u64> {
        self.table()
            .pairs
            .get(&(*src, *dst))
            .map(|pair| pair.generation)
    }

    /// `src`->`dst`'s [`PairShared`], for tests that call [`Self::drained`] by hand.
    #[cfg(test)]
    pub(crate) fn shared_of(&self, src: &NodeId, dst: &NodeId) -> Option<Arc<PairShared>> {
        self.table()
            .pairs
            .get(&(*src, *dst))
            .map(|pair| Arc::clone(&pair.shared))
    }

    /// Live forwarding pairs per tenant (the operator's status export).
    pub(crate) fn pair_counts(&self) -> HashMap<TenantId, usize> {
        self.table()
            .per_tenant
            .iter()
            .map(|(tenant, held)| (tenant.clone(), held.pairs))
            .collect()
    }

    /// The bytes charged in `tenant`'s volume period and the time that period still runs, if the
    /// tenant has moved data (the operator's status export).
    pub(crate) fn volume_status(
        &self,
        tenant: &TenantId,
        now: tokio::time::Instant,
    ) -> Option<(u64, std::time::Duration)> {
        self.shapers.volume_status(tenant, now)
    }

    /// The counts of `tenant`: live pairs and queued droppable bytes (tests).
    #[cfg(test)]
    pub(crate) fn tenant_counts(&self, tenant: &TenantId) -> (usize, usize) {
        self.table()
            .per_tenant
            .get(tenant)
            .map_or((0, 0), |held| (held.pairs, held.droppable_bytes))
    }

    /// Every count table is empty (tests: nothing leaks once all pairs are gone).
    #[cfg(test)]
    pub(crate) fn counts_are_empty(&self) -> bool {
        let table = self.table();
        table.per_tenant.is_empty() && table.per_sender.is_empty() && table.per_src.is_empty()
    }

    /// Counts a tenant's whole volume allowance as used, so that its bucket runs at the floor
    /// rate from now on (tests: reaching the floor takes the tenant's volume otherwise).
    #[cfg(test)]
    pub(crate) fn use_up_volume(&self, tenant: &TenantId, figures: &Figures) {
        self.shapers
            .of(tenant, figures)
            .add_volume(figures.volume_gib.saturating_mul(1 << 30));
    }

    /// The bucket and volume counter of `tenant`, if it has moved data (tests).
    #[cfg(test)]
    pub(crate) fn shaper_of(&self, tenant: &TenantId) -> Option<crate::shaping::Shaper> {
        self.shapers.get(tenant)
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
    fn a_destination_that_opted_out_of_peer_traffic_is_peer_offline() {
        let f = fixture(4_000_000_000);
        // Simulate `dst`'s own prior ADVERTISE with accept_peers: false.
        f.labels.advertise(
            &f.rosters,
            &crate::tenant::TenantBook::default(),
            &[f.network_id],
            &f.dst,
            &menzil_proto::AdvertiseBody {
                v: menzil_proto::PROTOCOL_VERSION,
                shares: vec![],
                accept_peers: false,
            },
            0,
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
            ForwardOutcome::Refused(err) => {
                assert_eq!(err.code, ErrorCode::PeerOffline);
                assert_eq!(err.msg, PEER_OFFLINE_MSG);
            }
            _ => panic!("expected Refused(PeerOffline)"),
        }
    }

    /// Two tenants on one relay: `owner_x` lists `s` and `d` in its own Roster (the hostile case:
    /// `d` never joined X), while `d` really belongs to the other tenant's network Y.
    struct Foreign {
        rosters: RosterStore,
        registry: SessionRegistry,
        labels: LabelRegistry,
        table: ForwardTable,
        network_x: NetworkId,
        network_y: NetworkId,
        s: NodeId,
        d: NodeId,
        s_handles: AttachHandles,
    }

    fn foreign() -> Foreign {
        let owner_x = SigningKey::generate(&mut rand::rng());
        let owner_y = SigningKey::generate(&mut rand::rng());
        let network_x = NetworkId::from(owner_x.verifying_key().to_bytes());
        let network_y = NetworkId::from(owner_y.verifying_key().to_bytes());
        let s = NodeId::from([1u8; 32]);
        let d = NodeId::from([2u8; 32]);
        let rosters = RosterStore::new();
        rosters
            .set(&roster_with_members(
                &owner_x,
                network_x,
                vec![s, d],
                4_000_000_000,
            ))
            .unwrap();
        rosters
            .set(&roster_with_members(
                &owner_y,
                network_y,
                vec![d],
                4_000_000_000,
            ))
            .unwrap();
        let registry = SessionRegistry::new();
        let s_handles = registry.attach(s, 1, vec![network_x]);
        Foreign {
            rosters,
            registry,
            labels: LabelRegistry::new(),
            table: ForwardTable::new(),
            network_x,
            network_y,
            s,
            d,
            s_handles,
        }
    }

    impl Foreign {
        /// One reliable SEND of 10 bytes from `s` (claiming X) to `d`.
        fn send(&self) -> ForwardOutcome {
            let (e2e, flags, payload) = reliable_send(10);
            self.table.forward(
                &self.rosters,
                &self.registry,
                &self.labels,
                &test_limits(),
                &self.s,
                &[self.network_x],
                &self.d,
                e2e,
                flags,
                payload,
                1_000,
            )
        }

        /// The refusal of [`Self::send`], asserting it is a refusal that put the credit back to
        /// `s` and left no pair behind.
        fn refusal(&mut self) -> ErrorBody {
            let ForwardOutcome::Refused(body) = self.send() else {
                panic!("expected a refusal")
            };
            match self.s_handles.2.try_recv() {
                Ok(ForwardItem::Credit { peer, bytes }) => {
                    assert_eq!(peer, self.d);
                    assert_eq!(bytes, MIN_FORWARD_CHARGE_BYTES.max(10));
                }
                _ => panic!("a refused reliable SEND must reimburse the sender"),
            }
            assert!(self.s_handles.2.try_recv().is_err(), "exactly one CREDIT");
            assert_eq!(
                self.table.remaining_credit(&self.s, &self.d),
                None,
                "a refusal reserves nothing"
            );
            body
        }
    }

    #[test]
    fn a_foreign_owner_listing_a_node_gets_the_same_peer_offline_whether_it_is_online_or_not() {
        // Isolation rule I4 (attack A4): X's owner lists d without d's consent. d belongs to Y.
        let mut f = foreign();

        // d offline.
        let offline = f.refusal();
        assert_eq!(offline.code, ErrorCode::PeerOffline);

        // d online, claiming only Y.
        let mut d_handles = f.registry.attach(f.d, 2, vec![f.network_y]);
        let online = f.refusal();

        // d online, claiming only Y, and closed to peers.
        f.labels.advertise(
            &f.rosters,
            &crate::tenant::TenantBook::default(),
            &[f.network_y],
            &f.d,
            &menzil_proto::AdvertiseBody {
                v: menzil_proto::PROTOCOL_VERSION,
                shares: vec![],
                accept_peers: false,
            },
            0,
        );
        assert!(!f.labels.accepts_peers(&f.d));
        let closed = f.refusal();

        assert_eq!(offline, online, "online must read like offline");
        assert_eq!(offline, closed, "closed to peers must read like offline");
        assert_eq!(offline.msg, PEER_OFFLINE_MSG);
        assert!(d_handles.2.try_recv().is_err(), "d received nothing");
    }

    #[test]
    fn a_node_that_claims_the_foreign_network_too_is_reached_only_on_the_networks_in_common() {
        let mut f = foreign();
        // d claims Y and X; s claims only X: X authorizes and d claimed it.
        let mut d_handles = f.registry.attach(f.d, 2, vec![f.network_y, f.network_x]);
        assert!(matches!(f.send(), ForwardOutcome::Queued));
        assert!(matches!(
            d_handles.2.try_recv(),
            Ok(ForwardItem::Recv { .. })
        ));

        // Networks that s did not claim never authorize, even if d claimed them and both are
        // listed: s claims X only, the Roster of Y lists only d.
        drop(d_handles);
        let _again = f.registry.attach(f.d, 3, vec![f.network_y]);
        let ForwardOutcome::Refused(body) = f.send() else {
            panic!("expected a refusal")
        };
        assert_eq!(body.code, ErrorCode::PeerOffline);
        let _ = f.s_handles.2.try_recv();
    }

    #[test]
    fn a_network_that_only_the_destination_claimed_does_not_count() {
        // Both are listed in X and in Z; s claims X, d claims Z only. Each side claims a network
        // that lists both, but no network is claimed by both.
        let owner_x = SigningKey::generate(&mut rand::rng());
        let owner_z = SigningKey::generate(&mut rand::rng());
        let network_x = NetworkId::from(owner_x.verifying_key().to_bytes());
        let network_z = NetworkId::from(owner_z.verifying_key().to_bytes());
        let (s, d) = (NodeId::from([1u8; 32]), NodeId::from([2u8; 32]));
        let rosters = RosterStore::new();
        for (owner, id) in [(&owner_x, network_x), (&owner_z, network_z)] {
            rosters
                .set(&roster_with_members(owner, id, vec![s, d], 4_000_000_000))
                .unwrap();
        }
        let registry = SessionRegistry::new();
        let _s = registry.attach(s, 1, vec![network_x]);
        let _d = registry.attach(d, 2, vec![network_z]);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(10);
        let outcome = table.forward(
            &rosters,
            &registry,
            &LabelRegistry::new(),
            &test_limits(),
            &s,
            &[network_x],
            &d,
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

    /// Three networks A, B and C, owned by three owners. `s` and `d` are listed in A and in C,
    /// `d` also in B. `s` claims `s_claims`; `d` is attached claiming `d_claims`. Returns the
    /// outcome of one SEND from `s` to `d` and what `d`'s connection was handed.
    fn send_across_claims(
        s_claims: fn(&[NetworkId; 3]) -> Vec<NetworkId>,
        d_claims: fn(&[NetworkId; 3]) -> Vec<NetworkId>,
    ) -> (ForwardOutcome, Option<ForwardItem>) {
        let owners: Vec<SigningKey> = (0..3)
            .map(|_| SigningKey::generate(&mut rand::rng()))
            .collect();
        let nets: [NetworkId; 3] =
            std::array::from_fn(|i| NetworkId::from(owners[i].verifying_key().to_bytes()));
        let (s, d) = (NodeId::from([1u8; 32]), NodeId::from([2u8; 32]));
        let rosters = RosterStore::new();
        // A and C list both; B lists only d.
        for (i, members) in [vec![s, d], vec![d], vec![s, d]].into_iter().enumerate() {
            rosters
                .set(&roster_with_members(
                    &owners[i],
                    nets[i],
                    members,
                    4_000_000_000,
                ))
                .unwrap();
        }
        let registry = SessionRegistry::new();
        let _s = registry.attach(s, 1, s_claims(&nets));
        let mut d_handles = registry.attach(d, 2, d_claims(&nets));
        let (e2e, flags, payload) = reliable_send(10);
        let outcome = ForwardTable::new().forward(
            &rosters,
            &registry,
            &LabelRegistry::new(),
            &test_limits(),
            &s,
            &s_claims(&nets),
            &d,
            e2e,
            flags,
            payload,
            1_000,
        );
        (outcome, d_handles.2.try_recv().ok())
    }

    /// MT3 / round T2: the claims check of `forward` (`.any(|network| authorizing.contains(..))`).
    /// A authorizes `s` -> `d` (both listed, `s` claims it), and `d` is attached claiming only B,
    /// a network `s` has no part in: the answer is `peer_offline` and `d` is handed nothing.
    /// Dropping the check delivers, inverting it refuses the legitimate cases below.
    #[test]
    fn a_destination_attached_with_only_a_network_that_does_not_authorize_gets_nothing() {
        let (outcome, handed) = send_across_claims(|n| vec![n[0]], |n| vec![n[1]]);
        match outcome {
            ForwardOutcome::Refused(err) => {
                assert_eq!(err.code, ErrorCode::PeerOffline);
                assert_eq!(err.msg, PEER_OFFLINE_MSG);
            }
            _ => panic!("expected Refused(PeerOffline)"),
        }
        assert!(handed.is_none(), "the destination was handed a record");
    }

    #[test]
    fn a_destination_claiming_the_authorizing_network_among_others_is_reached() {
        // d claims B first and A second: one common claimed network is enough, wherever it is.
        let (outcome, handed) = send_across_claims(|n| vec![n[0]], |n| vec![n[1], n[0]]);
        assert!(
            matches!(outcome, ForwardOutcome::Queued),
            "{:?}",
            outcome_name(&outcome)
        );
        assert!(matches!(handed, Some(ForwardItem::Recv { .. })));
    }

    #[test]
    fn any_one_of_several_authorizing_networks_is_enough_not_only_the_first() {
        // s claims A and C, both list both nodes (two authorizing networks); d claims only the
        // last of them, then only the first.
        let (outcome, handed) = send_across_claims(|n| vec![n[0], n[2]], |n| vec![n[2]]);
        assert!(
            matches!(outcome, ForwardOutcome::Queued),
            "{:?}",
            outcome_name(&outcome)
        );
        assert!(matches!(handed, Some(ForwardItem::Recv { .. })));
        let (outcome, handed) = send_across_claims(|n| vec![n[0], n[2]], |n| vec![n[0]]);
        assert!(
            matches!(outcome, ForwardOutcome::Queued),
            "{:?}",
            outcome_name(&outcome)
        );
        assert!(matches!(handed, Some(ForwardItem::Recv { .. })));
    }

    fn outcome_name(outcome: &ForwardOutcome) -> &'static str {
        match outcome {
            ForwardOutcome::Queued => "Queued",
            ForwardOutcome::Dropped => "Dropped",
            ForwardOutcome::Refused(_) => "Refused",
            ForwardOutcome::CreditViolation(_) => "CreditViolation",
            ForwardOutcome::OverQuota { .. } => "OverQuota",
        }
    }

    #[test]
    fn members_of_a_common_claimed_network_forward_both_ways() {
        let f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        for (from, to, claim) in [(f.src, f.dst, f.network_id), (f.dst, f.src, f.network_id)] {
            let (e2e, flags, payload) = reliable_send(10);
            let outcome = table.forward(
                &f.rosters,
                &f.registry,
                &f.labels,
                &test_limits(),
                &from,
                &[claim],
                &to,
                e2e,
                flags,
                payload,
                1_000,
            );
            assert!(matches!(outcome, ForwardOutcome::Queued));
        }
    }

    #[test]
    fn a_destination_that_reattaches_with_other_claims_is_judged_by_the_new_claims() {
        let mut f = foreign();
        let _first = f.registry.attach(f.d, 2, vec![f.network_x]);
        assert!(matches!(f.send(), ForwardOutcome::Queued));

        let _second = f.registry.attach(f.d, 3, vec![f.network_y]);
        f.table.clear_for(&f.d);
        let _ = f.s_handles.2.try_recv();
        assert_eq!(f.refusal().code, ErrorCode::PeerOffline);

        let mut third = f.registry.attach(f.d, 4, vec![f.network_x, f.network_y]);
        f.table.clear_for(&f.d);
        assert!(matches!(f.send(), ForwardOutcome::Queued));
        assert!(matches!(third.2.try_recv(), Ok(ForwardItem::Recv { .. })));
    }

    #[test]
    fn a_refusal_on_a_droppable_send_reimburses_nothing_and_looks_the_same() {
        let mut f = foreign();
        let (e2e, flags, payload) = droppable_send(10);
        let outcome = f.table.forward(
            &f.rosters,
            &f.registry,
            &f.labels,
            &test_limits(),
            &f.s,
            &[f.network_x],
            &f.d,
            e2e,
            flags,
            payload,
            1_000,
        );
        let ForwardOutcome::Refused(body) = outcome else {
            panic!("expected a refusal")
        };
        assert_eq!(body.code, ErrorCode::PeerOffline);
        assert_eq!(body.msg, PEER_OFFLINE_MSG);
        assert!(f.s_handles.2.try_recv().is_err());
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

        let generation = table.generation_of(&f.src, &f.dst).unwrap();
        let src_session_id = f.registry.attached_session_id(&f.src).unwrap();
        table.drained(
            &f.registry,
            &f.src,
            &f.dst,
            1_000,
            true,
            generation,
            src_session_id,
            &table.shared_of(&f.src, &f.dst).unwrap(),
        );
        let after_drain = table.remaining_credit(&f.src, &f.dst).unwrap();
        assert_eq!(after_drain, test_limits().credit);
    }

    #[test]
    fn drained_delivers_a_credit_item_to_srcs_own_channel() {
        // `drained` only ever applies its effects to a pair `forward`
        // itself already created (see `drained`'s own doc comment on the
        // generation check added for TODO.md L4b), so this test goes
        // through a real `forward` call first rather than fabricating a
        // bare `drained` call against a table that never admitted
        // anything.
        let mut f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(500);
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
        // Drain the RECV item `forward` itself already queued for `dst`,
        // so it cannot be mistaken for `drained`'s own CREDIT item below.
        assert!(matches!(
            f._dst_handles.2.try_recv(),
            Ok(ForwardItem::Recv { .. })
        ));

        let generation = table.generation_of(&f.src, &f.dst).unwrap();
        let src_session_id = f.registry.attached_session_id(&f.src).unwrap();
        table.drained(
            &f.registry,
            &f.src,
            &f.dst,
            500,
            true,
            generation,
            src_session_id,
            &table.shared_of(&f.src, &f.dst).unwrap(),
        );

        match f._src_handles.2.try_recv() {
            Ok(ForwardItem::Credit { peer, bytes }) => {
                assert_eq!(peer, f.dst);
                assert_eq!(bytes, 500);
            }
            Ok(ForwardItem::Recv { .. }) => panic!("expected a Credit item, got a Recv item"),
            Err(_) => panic!("expected a Credit item, got nothing"),
        }
    }

    #[test]
    fn drained_does_not_deliver_a_credit_item_for_droppable_traffic() {
        let mut f = fixture(4_000_000_000);
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(10);
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
        assert!(matches!(
            f._dst_handles.2.try_recv(),
            Ok(ForwardItem::Recv { .. })
        ));
        let generation = table.generation_of(&f.src, &f.dst).unwrap();
        let src_session_id = f.registry.attached_session_id(&f.src).unwrap();

        table.drained(
            &f.registry,
            &f.src,
            &f.dst,
            500,
            false,
            generation,
            src_session_id,
            &table.shared_of(&f.src, &f.dst).unwrap(),
        );

        assert!(
            f._src_handles.2.try_recv().is_err(),
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

    #[test]
    fn a_refused_reliable_send_reimburses_the_senders_local_credit_tracking() {
        // Regression test for TODO.md L4b's own review: `src`'s local
        // credit tracking (`menzil-node::outbound::OutboundQueue`)
        // optimistically spends `charge` the moment it hands a reliable
        // SEND to the wire, with no ACK to wait for and no way to learn
        // in advance whether the relay will actually forward it. Every
        // refusal must reimburse it via a CREDIT record, or its local
        // view of its own credit permanently drifts low — exactly what
        // the review live-reproduced against a peer that went offline.
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
        let (_supersede_rx, _outbound_rx, mut forward_rx) =
            registry.attach(src, 1, vec![network_id]);
        let labels = LabelRegistry::new();
        let table = ForwardTable::new();
        let (e2e, flags, payload) = reliable_send(1_234);

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
        assert!(matches!(
            outcome,
            ForwardOutcome::Refused(ErrorBody {
                code: ErrorCode::PeerOffline,
                ..
            })
        ));

        match forward_rx.try_recv() {
            Ok(ForwardItem::Credit { peer, bytes }) => {
                assert_eq!(peer, offline_member);
                assert_eq!(bytes, 1_234);
            }
            Ok(ForwardItem::Recv { .. }) => panic!("expected a Credit item, got a Recv item"),
            Err(_) => panic!("expected a Credit reimbursement, got nothing"),
        }
    }

    #[test]
    fn a_refused_droppable_send_reimburses_nothing() {
        // The mirror of the test above: a droppable SEND never consumed
        // any of `src`'s local credit in the first place (protocol.md
        // 4.2: only reliable SENDs are credited), so a refusal of one
        // must not fabricate a CREDIT record either.
        let rosters = RosterStore::new();
        let registry = SessionRegistry::new();
        let src = NodeId::from([1u8; 32]);
        let (_supersede_rx, _outbound_rx, mut forward_rx) = registry.attach(src, 1, vec![]);
        let labels = LabelRegistry::new();
        let table = ForwardTable::new();
        let (e2e, flags, payload) = droppable_send(10);

        // No roster at all: refused as Forbidden, the very first check
        // after the e2e_proto one.
        let outcome = table.forward(
            &rosters,
            &registry,
            &labels,
            &test_limits(),
            &src,
            &[],
            &NodeId::from([2u8; 32]),
            e2e,
            flags,
            payload,
            1_000,
        );
        assert!(matches!(
            outcome,
            ForwardOutcome::Refused(ErrorBody {
                code: ErrorCode::Forbidden,
                ..
            })
        ));
        assert!(forward_rx.try_recv().is_err());
    }

    #[test]
    fn a_credit_violation_reimburses_nothing() {
        // Unlike every other refusal, CreditViolation ends `src`'s
        // session (the caller's job once `forward` returns it) — there
        // is nothing to reimburse a session that is about to close, and
        // doing so would be meaningless besides.
        let mut f = fixture(4_000_000_000);
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
        assert!(matches!(outcome, ForwardOutcome::CreditViolation(_)));
        assert!(f._src_handles.2.try_recv().is_err());
    }

    #[test]
    fn a_stale_pair_generation_drain_never_touches_a_fresh_pairs_own_ledger() {
        // Regression test for TODO.md L4b's own review (finding 4b): a
        // `ForwardItem::Recv` admitted under one `PairState` generation,
        // drained only after `clear_for` plus a fresh `forward` recreated
        // the same `(src, dst)` key, must not apply its effects to the
        // *new* generation's own bookkeeping — neither granting credit
        // it never actually spent against the fresh ledger, nor
        // shrinking the fresh queue occupancy. Whether the wire CREDIT
        // record itself still reaches `src` is a separate question,
        // gated on `src`'s own session currency, not this pair's
        // generation — see the two tests below, added after this fix's
        // first version turned out to have a real bug of its own (a
        // second review round, live-reproduced): gating the CREDIT
        // record on the pair's generation alone meant a `dst`-only
        // reconnect could permanently strand `src`'s credit too, even
        // though `src` itself never reconnected.
        let mut f = fixture(4_000_000_000);
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
        let stale_generation = table.generation_of(&f.src, &f.dst).unwrap();
        let src_session_id = f.registry.attached_session_id(&f.src).unwrap();

        // `src` reconnects: its pairs are cleared (mirroring
        // `crate::session`'s real call on a fresh attach), then it sends
        // again, creating a fresh `PairState` — a fresh generation — at
        // the same key.
        table.clear_for(&f.src);
        let (e2e, flags, payload) = reliable_send(1);
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
        let fresh_generation = table.generation_of(&f.src, &f.dst).unwrap();
        assert_ne!(
            stale_generation, fresh_generation,
            "a pair recreated after clear_for must get a new generation"
        );
        let fresh_credit_before = table.remaining_credit(&f.src, &f.dst).unwrap();
        let fresh_queued_before = table.queued_bytes(&f.src, &f.dst).unwrap();
        while f._dst_handles.2.try_recv().is_ok() {}

        // The stale item, admitted before the reconnect, finally drains.
        table.drained(
            &f.registry,
            &f.src,
            &f.dst,
            1_000,
            true,
            stale_generation,
            src_session_id,
            &table.shared_of(&f.src, &f.dst).unwrap(),
        );

        assert_eq!(
            table.remaining_credit(&f.src, &f.dst).unwrap(),
            fresh_credit_before,
            "a stale drain must not grant credit to the fresh generation's own ledger"
        );
        assert_eq!(
            table.queued_bytes(&f.src, &f.dst).unwrap(),
            fresh_queued_before,
            "a stale drain must not shrink the fresh generation's own queue occupancy"
        );
    }

    #[test]
    fn a_stale_drain_still_credits_src_when_only_dst_reconnected() {
        // The regression this fix's second round exists for: `dst`
        // reconnecting resets the (src, dst) pair too (`clear_for`
        // clears a NodeId's pairs in both roles), but `src` itself never
        // reconnected — its own local credit tracking has no visibility
        // into `dst`'s reconnects at all and genuinely spent this
        // charge, so it is still owed reimbursement regardless of what
        // happened to the pair's own generation.
        let mut f = fixture(4_000_000_000);
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
        let stale_generation = table.generation_of(&f.src, &f.dst).unwrap();
        let stale_shared = table.shared_of(&f.src, &f.dst).unwrap();
        let src_session_id = f.registry.attached_session_id(&f.src).unwrap();
        while f._dst_handles.2.try_recv().is_ok() {}

        // `dst` reconnects: a fresh registry session and, via
        // `clear_for(dst)` (mirroring `crate::session`'s real call on a
        // fresh attach), a fresh `PairState` for (src, dst). `src`
        // itself is untouched throughout.
        let _new_dst_handles = f.registry.attach(f.dst, 99, vec![f.network_id]);
        table.clear_for(&f.dst);

        // The item admitted before dst's reconnect finally drains (dst's
        // old connection either handed it off just before tearing down,
        // or tore down with it still queued — either way, from src's own
        // perspective this charge was genuinely spent and is genuinely
        // owed back).
        table.drained(
            &f.registry,
            &f.src,
            &f.dst,
            1_000,
            true,
            stale_generation,
            src_session_id,
            &stale_shared,
        );

        match f._src_handles.2.try_recv() {
            Ok(ForwardItem::Credit { peer, bytes }) => {
                assert_eq!(peer, f.dst);
                assert_eq!(bytes, 1_000);
            }
            other => {
                panic!("expected src to be reimbursed regardless of dst's reconnect, got {other:?}")
            }
        }
    }

    #[test]
    fn a_stale_drain_does_not_credit_a_superseded_src_session() {
        // The genuine positive case finding 4a/4b's original fix was
        // for: `src` itself reconnects (a real new `SessionRegistry`
        // session, not just a `ForwardTable` reset), so its *local*
        // ledger is fresh and has nothing to do with what the old
        // session spent; a stale drain must not credit the new session
        // for the old one's spending.
        let mut f = fixture(4_000_000_000);
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
        let stale_generation = table.generation_of(&f.src, &f.dst).unwrap();
        let stale_src_session_id = f.registry.attached_session_id(&f.src).unwrap();
        while f._dst_handles.2.try_recv().is_ok() {}

        // `src` reconnects: a genuinely new registry session id.
        let _new_src_handles =
            f.registry
                .attach(f.src, stale_src_session_id + 1, vec![f.network_id]);

        table.drained(
            &f.registry,
            &f.src,
            &f.dst,
            1_000,
            true,
            stale_generation,
            stale_src_session_id,
            &table.shared_of(&f.src, &f.dst).unwrap(),
        );

        assert!(
            f._src_handles.2.try_recv().is_err(),
            "the old, superseded src session must not receive a credit meant for whatever \
             session is current"
        );
    }
}

#[cfg(test)]
mod quota_tests;
