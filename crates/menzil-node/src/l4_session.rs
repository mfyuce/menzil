//! The per-L4-session actor (protocol.md 5.1's transport, 5.2's records
//! and counters, 5.3's stream layer riding on top via `menzil-stream`) —
//! TODO.md L4h3. Given an already-finished `menzil_e2e::E2eTransport`
//! plus this session's identity context, [`new`] builds one actor that
//! owns a `menzil_stream` yamux connection and the L4
//! `RekeySchedule`/`Liveness` clocks, pumping `menzil-stream`'s
//! `OutboundFrames` through `encrypt_data(Mux)` into epoch-tagged
//! reliable SENDs (protocol.md 5.1's path pinning, TODO.md L4h1), and
//! feeding decrypted `Mux` bodies back into the connection's
//! `feed_inbound` — plus REKEY/KEEP on their own schedules, and a
//! uniform way to end the session for any of the reasons protocol.md 5.2
//! or this node's own L3 layer can produce.
//!
//! **What this module is not**: it does not allocate `sender_index`/
//! `receiver_index`, run the Noise handshake itself, decide where an
//! inbound `E2eFrame::Data` destined for this session comes from, or
//! decide what an ended session means for L5 streams already open on it
//! (TODO.md L4e1/L4h6/L4h7, none built yet) — those are a caller's job.
//! [`new`] takes an already-finished transport and expects its caller to
//! route inbound `Data` frames to [`L4SessionHandle::feed_inbound`]
//! itself, in the exact order `menzil-e2e`'s own reliable-class counter
//! would accept them (this module does not re-check that order; see
//! `menzil_stream::StreamMux::feed_inbound`'s own doc comment for the
//! identical caution one layer below, which this module already
//! satisfies for *its* caller — `menzil-stream` — by construction, since
//! [`run`] only ever calls it from inside its own single sequential
//! decrypt loop).
//!
//! **No internal `tokio::spawn`**, matching every other async crate this
//! one builds on (`menzil-stream`'s own `Driver`, `menzil-node::
//! session::run_session`): [`new`] returns a plain future the caller
//! spawns, not something this module spawns itself. That future also
//! drives `menzil-stream`'s own `Driver` internally (as one branch of its
//! own `tokio::select!`) rather than asking its caller to spawn a
//! *second* task — one L4 session, one task.
//!
//! **Why `&mut driver` inside a `loop { select! {...} }` is safe here
//! despite `menzil_stream::StreamMuxError::DriverGone`'s own warning that
//! a resolved `Driver` must never be polled again**: the `Driver` branch
//! is the only one in [`run`]'s loop that `break`s immediately rather
//! than falling through to another iteration — once it resolves, this
//! function never reaches `select!` again, so `driver` is never touched
//! past that point (it is dropped, along with everything else `run` owns,
//! the moment the function returns). An opus red-team review specifically
//! hunted for the same hazard on every *other* reused `&mut future` in
//! this loop (`epoch_ended`, and whether a branch that loses a race while
//! also ready could be mis-handled on a later poll) by forcing exactly
//! that race hundreds of times under three different scenarios — none
//! panicked or hung; every `select!` pattern here is irrefutable, so a
//! branch that ever returns `Ready` is always the one `tokio::select!`
//! takes. The flake that motivated the hunt (below) turned out to have a
//! different, simpler cause.
//!
//! **The end conditions, and how each is detected** (every one maps to a
//! distinct [`EndReason`] variant, used only for this session's own
//! caller-visible bookkeeping — menzil-e2e/`menzil-stream` already handle
//! whether a *reason* reaches the peer, e.g. [`EndReason::PeerClosed`]
//! versus this side proactively sending its own CLOSE via
//! [`L4SessionHandle::close`]): a post-authentication `E2eError`
//! (`EndReason::Decrypt`, from `decrypt_data` — never for
//! `UnauthenticatedDatagramCounter` or a bare `Noise` decrypt failure,
//! both of which only drop one frame, per `menzil_e2e::transport`'s own
//! doc comment on why that ordering matters); `feed_inbound` failing
//! (`EndReason::StreamMuxFeedFailed`); the `Driver` resolving
//! (`EndReason::DriverEnded`, carrying its own result either way — a
//! clean `Ok(())` still ends this L4 session, since protocol.md 5.2 ties
//! yamux state to one L4 session's lifetime, decision 0001); a peer CLOSE
//! (`EndReason::PeerClosed`, its code becoming the end reason);
//! `Liveness::is_dead` (`EndReason::PeerDead`); this side's own encrypt
//! or outbound-admission path failing (`EndReason::EncryptFailed`,
//! `EndReason::SendRefused`, `EndReason::OutboundGone` — see
//! [`enqueue_send`]'s own doc comment for why a refused *reliable* L4
//! record can only end the session, never retry in place); the L3 epoch
//! this session was opened under ending (`EndReason::EpochEnded`, fired
//! by whoever constructed this session once they observe `SessionEvent::
//! Detached` for it — not yet anyone, since L4h6/L4h7 do not exist; a
//! test fires it directly); this side proactively ending the session
//! itself ([`L4SessionHandle::close`], `EndReason::ClosedLocally`); and
//! the caller dropping [`L4SessionHandle`] entirely without ever calling
//! `close()` (`EndReason::HandleDropped` — see the paragraph on that
//! below). [`EndReason::ActorGone`] is not a `run()`-detected condition
//! at all; it is [`L4SessionAcceptor::closed`]'s own fallback for "the
//! actor is gone and never told me why" (a panic, an aborted task), kept
//! distinct from [`EndReason::OutboundGone`] rather than overloading that
//! variant's meaning — a red-team review found the original code did
//! exactly that overload.
//!
//! **Why dropping the handle must end the session immediately, not drift
//! into a 40-second `PeerDead` wait — and why `command_rx` alone, not
//! `inbound_data_rx`, is what actually decides that**: an earlier version
//! of this module treated `inbound_data_rx`/`command_rx` both returning
//! `None` (every sender lives on [`L4SessionHandle`], so both close
//! together) the same as "no more inbound data for now, everything else
//! still matters" — correct for either channel alone being momentarily
//! quiet, wrong once *both* are closed for good: with every clone of
//! the handle gone, nothing can ever open a new stream, feed inbound
//! data, or close intentionally again, so the session cannot usefully
//! continue — the separate [`L4SessionAcceptor`] can still observe why
//! (`closed()`), and `accept()` itself drains to `None` once the actor's
//! own `Driver` ends alongside it, but accepting a *new* stream stops
//! being possible from that point on too.
//! The bug was not just the eventual outcome but the path there: both
//! `recv()` calls return `Ready(None)` immediately and forever once
//! closed, so the loop's `continue` on each spun on every single
//! iteration — live-measured by a red-team review at roughly a 60x
//! throughput hit to a sibling task on the same runtime — all the way
//! until `PeerDead` finally fired.
//!
//! The first fix simply `break`s on whichever channel reports closed
//! first — correct for the throughput problem, but a second red-team
//! review found it introduced a real regression: [`L4SessionHandle::
//! close`]`(Some(reason))` immediately followed by dropping the handle
//! (the natural shape for, e.g., a future L4h6's own "CLOSE `no_grant`
//! and end") lost the CLOSE about 81% of the time in a live
//! reproduction, because `tokio::select!` checks branches in a
//! randomized order each call and the inbound branch, having nothing
//! queued, reports closed just as readily as the command branch reports
//! its already-queued `Close` — whichever is checked (or chosen, when
//! both are ready) first wins, and `inbound_data_rx` winning threw the
//! queued `Close` away unseen. Fixed by making the two asymmetric:
//! seeing `inbound_data_rx` close only disables that one branch
//! (`inbound_closed`, a `select!` precondition) rather than ending
//! anything, while `command_rx` closing is what actually breaks with
//! [`EndReason::HandleDropped`] — correct because an `mpsc` receiver
//! only ever reports closed once every item already queued ahead of
//! that point has been yielded, so a `Close` queued right before the
//! handle drops is now guaranteed to be delivered first, regardless of
//! which branch `select!` happens to check or choose first.
//!
//! **Why liveness must only be touched on a *successful* decrypt**: an
//! earlier version of this module called `Liveness::note_received` once,
//! unconditionally, after the whole inbound `match` — including the arm
//! that drops a frame that never authenticated at all
//! (`UnauthenticatedDatagramCounter`/a bare `Noise` failure). A red-team
//! review demonstrated live that this lets anyone able to deliver frames
//! to this session's receiver index (per decision 0001, that includes
//! the relay the L3 session rides over) defeat dead-peer detection
//! entirely with one garbage frame a second, indefinitely — the exact
//! "pre-authentication input must never drive a consequential decision"
//! hazard `menzil_e2e::transport`'s own doc comment already states for
//! this crate's *decrypt* ordering, reintroduced one layer up for
//! *liveness* specifically. Fixed: `note_received` now runs only inside
//! `decrypt_data`'s `Ok(..)` arm, matching `Liveness::note_received`'s
//! own documented contract ("whenever any data record is successfully
//! decrypted").
//!
//! **Why outbound frames are queued without waiting for their own
//! admission outcome, unlike CLOSE**: an earlier version of this module
//! ran every outbound record — `Mux` frames included — through one
//! helper that encrypted, sent, and then *awaited* that send's own
//! outcome before ever pulling the next frame from `menzil_stream::
//! OutboundFrames`. A red-team review demonstrated live that this alone
//! — no congestion, no credit starvation, nothing TODO.md's own L4h5
//! line anticipates — is enough to end an otherwise perfectly healthy
//! session under ordinary bulk transfer: a single `Driver` poll can move
//! up to eleven frames per actively writing stream into `menzil-stream`'s
//! own `RecordIo`, whose outbound channel then held only 256
//! (`OUTBOUND_FRAME_BUDGET`, which was then enforced as a hard failure,
//! not backpressure; it pauses `yamux` now, see below); pulling
//! frames out of it one at a time, each gated on a full encrypt-send-
//! admit round trip through this node's own L3 layer, could not keep up,
//! and the live reproduction needed as little as 9-16ms of sustained
//! writing to exhaust the budget and end the session with a
//! `menzil-stream`-reported connection error. [`enqueue_send`] pushes
//! each send's outcome receiver onto a `FuturesUnordered`
//! (`pending_outcomes`, polled by its own separate `select!` branch)
//! instead of awaiting it inline, so pulling the next frame is never
//! serialized behind the previous one's own round trip — only
//! `outbound.send` itself (handing the record to this node's own L3
//! layer, not waiting to learn whether it was admitted) still blocks
//! pulling the next frame, which is exactly the backpressure point a
//! bounded channel is for. REKEY/KEEP (infrequent, not throughput
//! critical) go through this same path too, for consistency; CLOSE does
//! not queue into `pending_outcomes` at all — seeing its own outcome
//! cannot change a decision already made to end the session, so it is
//! sent fully best effort (see [`L4SessionHandle::close`]).
//!
//! **What closed the rest of it (TODO.md L4h5)**: a second red-team
//! review found that ordinary bulk transfer could still end a session
//! after the change above, at a higher bar (this module's own regression
//! test passed at 16-20 concurrent streams and failed at 23 and up), by
//! two mechanisms: backlog building up *across* several `select!`
//! iterations (`yamux` auto-tunes a stream's receive window upward, so
//! more than the channel's capacity can be in flight whatever the actor's
//! drain rate), and a *single* `Driver` poll emitting more frames than
//! the channel holds before this actor ever runs, which nothing inside
//! this module could fix since the actor cannot interrupt a poll. Both
//! were one thing underneath: `menzil-stream`'s channel failing the whole
//! connection when full. It now pauses `yamux` instead, so neither can
//! end anything.
//!
//! That moved the failure one hop down, where a live test against a real
//! relay (`tests/l4_bulk.rs`, which keeps the smallest size that still
//! overflowed the old queue, 16 streams of 256 KiB; the first measurement
//! was 32 of 512 KiB) found it: with the stream layer waiting
//! properly, such transfers over a *healthy* relay still
//! ended the sending session with [`EndReason::SendRefused`]
//! (`QueueFull`) and the receiver with a counter-gap `Decrypt` error —
//! the windows `yamux` grants a few busy streams add up to more than the
//! node's own send queue holds (3 MiB per destination), and once
//! `menzil-e2e` has given an L4 record its counter, that record being
//! refused can only end the session. So a `Mux` frame no longer goes
//! straight from `menzil-stream` to `outbound`: it is *staged* (pulled
//! out, not yet encrypted) until the queue space it will occupy has been
//! reserved through the node's shared [`SendBudget`], and the reservation
//! travels with the record until the queue sends it. See [`Staged`] for
//! why the wait is its own `select!` branch and why nothing else is
//! pulled meanwhile — that chain, an unpulled frame leaving the channel
//! full, `yamux` paused, every stream writer waiting in turn, is the
//! backpressure. KEEP, REKEY and CLOSE (tiny, rare) do not reserve:
//! the budget is sized below the queue's caps with room left over for
//! them.
//!
//! **Why both the send itself and each individual outcome wait are
//! bounded by [`SEND_OUTCOME_TIMEOUT`]**: `outbound` is a bounded
//! channel; a first red-team review found that with it full and nothing
//! draining it, `outbound.send(..).await` itself — not merely the
//! subsequent wait for an admission outcome — blocked with no bound at
//! all, in code that wrapped only the *second* half. Fixing that
//! alongside the point above (not waiting for the outcome inline at all
//! any more) dropped the outcome-side bound entirely as a side effect:
//! pushing a bare `oneshot::Receiver` onto `pending_outcomes`, with
//! nothing wrapping *that* wait, meant an admission outcome that simply
//! never arrived left the session running with no bound whatsoever — a
//! second red-team review caught this live (still alive past 50
//! simulated seconds with ten held, unanswered outcomes) along with this
//! doc comment's own claim, by that point no longer true, of one shared
//! bound. Fixed properly this time: each item pushed onto
//! `pending_outcomes` is itself wrapped in its own `tokio::time::
//! timeout(SEND_OUTCOME_TIMEOUT, ..)`, so every individual outcome
//! carries its own bound no matter how many are in flight together. In
//! real use this is bounded by how long `run_session`'s own drain loop
//! can be stalled on any *one* record (`session::SEND_TIMEOUT`, 30s) —
//! [`SEND_OUTCOME_TIMEOUT`] is set a little past that so a stall
//! `run_session` is about to recover from on its own is not pre-empted by
//! this module's own, separate timeout first. A *whole* drain pass,
//! rather than one record, used to be able to exceed this bound: a slow
//! uplink delayed each request's admission behind every earlier write
//! (found by L4h5's red-team review, reproduced at 12 KiB/s as
//! [`EndReason::OutboundGone`] after about 35s). `run_session` now admits
//! everything waiting before it writes, and writes one record per
//! iteration, so an outcome waits at most for the write in progress,
//! which `SEND_TIMEOUT` bounds below this constant.
//! **This bites on literally every session's first poll, not just under
//! contention**:
//! `yamux::Connection::new` produces an outbound frame of its own before
//! anything else happens (confirmed live, tracing which branch fires —
//! not documented by `menzil-stream` itself), so `outbound_frames`'s own
//! branch runs, and sends through, `enqueue_send` immediately. A test
//! building a session with nothing draining `outbound` at all hits
//! exactly this wait; real usage never does, since `run_session` always
//! drains its own `outbound`, including an immediate `refuse_stale` on
//! every send throughout a detach — so a test needing the session to end
//! quickly for some other reason must still provide that drain, not
//! shorten this module's own timeout to fit.
//!
//! **Why `L4SessionAcceptor::closed` returns `Arc<EndReason>` and
//! caches it, rather than taking the receiver and returning `EndReason`
//! directly**: the original version panicked the second time it was
//! called, reasoning that a second observer meant two callers that
//! should share one. A red-team review found a single, perfectly
//! ordinary caller already trips this: `loop { select! { r = acceptor.
//! closed() => ..., _ = other => {} } }` calls `acceptor.closed()` fresh
//! on every iteration of that loop (`select!` re-evaluates a branch
//! expression that is not a reused `&mut` binding each time it runs),
//! so losing just one race against `other` before the session has
//! actually ended was enough to panic on the very next iteration. Fixed
//! by polling the held receiver by `&mut` (never taking it out) and
//! caching the resolved value in an `Arc` once seen, so a repeated or
//! even a cancelled-and-retried call is answered the same way every
//! time, without needing [`EndReason`] itself to implement `Clone`
//! (several of its variants wrap types, like `menzil_e2e::E2eError`,
//! that do not).
//!
//! **The inbound side is bounded, not paced (TODO.md L4h6b)**. An earlier
//! version of [`L4SessionHandle::feed_inbound`] sent into an unbounded
//! channel: in a live measurement ten thousand 16 KiB calls landed in 29 ms
//! and grew the process by roughly 78 MB while the actor was busy
//! elsewhere, and `menzil-stream`'s own queue below it was unbounded too (a
//! peer that stops reading from its relay while it floods bare Pings keeps
//! `yamux` from reading for up to 35 s; 200,000 Pings grew the process by
//! 15 MiB with no plateau). Now every record is charged to the session's
//! budget when it is fed and the charge is given back when `yamux` has read
//! it; the stream data `yamux` then holds until the application reads it is
//! charged to the same counter (a `BufferMeter`, patch 5 of the vendored
//! `yamux`), so one session never holds more than
//! [`L4_INBOUND_BUDGET_PER_SESSION`] of records not yet processed by the
//! stream layer plus stream data received but not yet read, and a record
//! past that is refused with [`InboundOverflow`] and ends the session. That
//! constant's docs say what is counted and why the caller is not made to
//! wait instead.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use menzil_e2e::{E2eError, E2eTransport, Liveness, RekeySchedule};
use menzil_proto::{
    ContinueAckBody, ContinueBody, E2eDataBody, E2eFrame, ErrorCode, MIN_SEND_CHARGE_BYTES,
    NetworkId, NodeId, RecordClass, continue_binding, e2e_data_frame_len,
};
use menzil_stream::{Mode, RECEIVE_WINDOW_GRANT, Stream, StreamMuxError};
use tokio::sync::{mpsc, oneshot};

use crate::channels::{
    ChannelTable, DGRAM_BUDGET_PER_SESSION, DGRAM_CEILING_PER_NODE, DGRAM_SEND_QUEUE, DgramOut,
};
use crate::outbound::{EnqueueOutcome, Epoch, OutboundSend, SendBudget, SendPermit};

/// The current time as a `std::time::Instant`, read through tokio's clock.
/// Identical in production; a test that pauses and advances tokio's clock
/// then moves this session's liveness and rekey schedules with it (the
/// sans-IO types in `menzil-e2e` take a `std::time::Instant`, which tokio's
/// paused clock would otherwise leave behind).
fn clock_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// `e2e_proto` tag for this project's own L4 (decision 0001); every other
/// call site in this workspace that needs it today (L3's HELLO/ATTACH
/// catch-up, this crate's own tests) inlines the same literal rather than
/// importing a shared constant, since none exists yet — matched here for
/// consistency rather than introducing one unilaterally.
pub(crate) const E2E_PROTO_TAG: u8 = 0x01;

/// protocol.md 4.2's flags bit 0; 0 means reliable. Every record this
/// module ever sends is reliable-class (protocol.md 5.2's table: MUX,
/// CLOSE, KEEP and REKEY all are — only DGRAM is droppable, and
/// `E2eTransport::encrypt_data` already refuses to encode one at all, see
/// [`crate::l4_session`]'s own doc comment on what this module is not).
const RELIABLE_FLAGS: u8 = 0x00;

/// protocol.md 4.2's flags bit 0 set: the droppable class, which is where a DGRAM record
/// goes. The receiver routes by the counter's class, not by this flag (the relay writes it
/// and can flip it); it is the relay's hint for what it may drop under pressure.
const DROPPABLE_FLAGS: u8 = 0x01;

/// How long [`enqueue_send`] waits for `outbound` to accept one send, and
/// separately how long it then waits for that send's own admission
/// outcome, and how long a [`Staged`] frame waits for send-queue space
/// (TODO.md L4h5), before giving up on this session entirely — see this
/// module's own doc comment for why a bound is needed for each and why
/// this particular value.
const SEND_OUTCOME_TIMEOUT: Duration = Duration::from_secs(35);

/// How long [`L4SessionHandle::close`]'s own best-effort CLOSE send waits
/// for `outbound` to accept it — deliberately much shorter than
/// [`SEND_OUTCOME_TIMEOUT`]: this session is ending either way, so
/// telling the peer why must not delay that by much.
const CLOSE_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// How often [`run`]'s own loop checks the liveness/rekey clocks when
/// nothing else has woken it — mirrors `session::TICK`'s identical
/// reasoning: both clocks operate on scales of seconds, so this
/// granularity costs nothing observable, and a fixed interval (not a
/// re-armed `sleep`) keeps sustained inbound or outbound traffic from
/// starving the check indefinitely.
const CLOCK_TICK: Duration = Duration::from_secs(1);

/// How long an initiator that switched to the replacement transport waits for CONTINUE_ACK
/// (protocol.md 5.2): the actor's own dead-peer window (`menzil_e2e::Liveness`, 40 s). The old
/// transport keeps receiving meanwhile; without an ACK by then the session ends with CLOSE
/// `handover_failed`.
const HANDOVER_ACK_WINDOW: Duration = Duration::from_secs(40);

/// Upper bound on [`CloseReason::msg`] as actually sent, regardless of
/// how much a given session's own plaintext budget would allow — see
/// [`close_msg_limit`] for why the real, enforced limit is often smaller
/// than this. Mirrors `menzil-stream::open`'s own `MAX_REFUSAL_MSG_BYTES`
/// for the analogous OPEN_ACK refusal: generous for any real human-
/// readable text, never unbounded.
const MAX_CLOSE_MSG_BYTES: usize = 1024;

/// The longest `CloseReason::msg` this session can actually encrypt at
/// `max_record`, capped at [`MAX_CLOSE_MSG_BYTES`] even when the budget
/// would allow more. An earlier version of this module clamped to the
/// fixed constant alone regardless of `max_record` — a red-team review
/// found live that this still exceeded what a tight `max_record` (1024,
/// say — well below protocol.md's own 65,535 default, but not forbidden)
/// could actually carry, silently dropping the whole CLOSE record
/// (`encrypt_data`'s own `BodyTooLarge` failure, swallowed by this
/// module's own best-effort send) rather than sending a shorter one. The
/// margin reserved beyond the raw message bytes (`CLOSE_BODY_OVERHEAD`)
/// covers the kind byte, the CBOR map header, and the `code`/`msg` field
/// names `CloseBody`'s own derived `Serialize` impl writes alongside the
/// message — generous rather than exact, and checked live by this
/// module's own tests rather than hand-derived to the byte.
fn close_msg_limit(max_record: u32) -> usize {
    const CLOSE_BODY_OVERHEAD: usize = 64;
    MAX_CLOSE_MSG_BYTES
        .min(menzil_proto::max_e2e_data_plaintext(max_record).saturating_sub(CLOSE_BODY_OVERHEAD))
}

/// What this side asks the peer to know about why it is ending the
/// session, if anything — see [`L4SessionHandle::close`].
#[derive(Debug, Clone)]
pub struct CloseReason {
    /// Reused from the shared L3/L4 [`ErrorCode`] registry, the same
    /// choice every other wire-facing refusal in this workspace makes
    /// rather than inventing a parallel one.
    pub code: ErrorCode,
    /// A human-readable detail; sent truncated to at most
    /// [`close_msg_limit`] bytes for this session's own `max_record`.
    pub msg: String,
}

/// `msg` cut to `limit` bytes at a valid UTF-8 boundary (walking
/// backward from the limit, which always terminates: 0 is always a
/// boundary), marking that it was cut — the same shape `menzil-stream::
/// open`'s own `clamp_refusal_msg` already uses for OPEN_ACK.
fn clamp_close_msg(msg: &str, limit: usize) -> String {
    if msg.len() <= limit {
        return msg.to_string();
    }
    let mut end = limit;
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &msg[..end])
}

/// Why one [`run`] actor ended — see this module's own doc comment for
/// the full list and how each is detected. Local diagnostics only: this
/// type is never itself put on the wire (only [`CloseReason`], when this
/// side chooses to send one, is). Deliberately not [`Clone`]/`PartialEq`
/// (several variants wrap types, like [`E2eError`], that are neither) —
/// [`L4SessionAcceptor::closed`] wraps it in an [`Arc`] instead so a
/// repeated or cancelled-and-retried call can still share one answer.
#[derive(Debug)]
pub enum EndReason {
    /// The peer sent a `data` record of kind CLOSE.
    PeerClosed {
        /// The code it carried.
        code: ErrorCode,
        /// The message it carried.
        msg: String,
    },
    /// [`L4SessionHandle::close`] was called; `None` if with no reason to
    /// send.
    ClosedLocally(Option<CloseReason>),
    /// A post-authentication `menzil_e2e::E2eError` from `decrypt_data`
    /// (contiguity violation, class mismatch, or an undecodable kind —
    /// never a pre-authentication one; see this module's own doc
    /// comment).
    Decrypt(E2eError),
    /// This side's own `encrypt_data` call failed — see [`enqueue_send`]'s
    /// doc comment.
    EncryptFailed(E2eError),
    /// `menzil_stream::StreamMux::feed_inbound` refused an inbound `Mux`
    /// body.
    StreamMuxFeedFailed(StreamMuxError),
    /// `menzil_stream::Driver` resolved, cleanly or not — either way ends
    /// this L4 session (decision 0001: yamux state is tied to one L4
    /// session's lifetime).
    DriverEnded(Result<(), StreamMuxError>),
    /// `menzil_e2e::Liveness::is_dead`: no authenticated record has
    /// arrived from the peer for the L4 dead-peer window.
    PeerDead,
    /// A reliable `OutboundSend` this session produced was refused —
    /// never retried in place; see [`enqueue_send`]'s own doc comment.
    SendRefused(EnqueueOutcome),
    /// The outbound path to this node's own L3 layer is gone: either the
    /// `outbound` channel itself closed, or a send's own `outcome`
    /// disconnected or timed out ([`SEND_OUTCOME_TIMEOUT`]) — see
    /// [`enqueue_send`]'s doc comment. Functionally overlaps with
    /// [`Self::EpochEnded`] (both mean "the L3 session underneath is no
    /// longer usable") but is reported separately since it is detected a
    /// different way, through this session's own sends rather than a
    /// direct notification.
    OutboundGone,
    /// This session's own L3 epoch ended (protocol.md 5.1's path
    /// pinning) — reported by whoever constructed this session via the
    /// `epoch_ended` channel passed to [`new`], not detected internally.
    /// If [`L4SessionHandle::close`] had already queued a close when the
    /// epoch ended (or the channel was dropped, which counts the same),
    /// that close is the reason instead: [`Self::ClosedLocally`].
    EpochEnded,
    /// Every live clone of [`L4SessionHandle`] was dropped without any
    /// of them calling [`L4SessionHandle::close`] first — see this
    /// module's own doc comment on why this ends the session immediately
    /// rather than drifting into a [`Self::PeerDead`] wait. A caller that
    /// means to hold a clone indefinitely just to call
    /// [`L4SessionHandle::feed_inbound`] (a future L4h6's own demux
    /// table, say) should know this variant can then never fire for that
    /// session — there is always at least one live clone.
    HandleDropped,
    /// A re-handshake cutover did not match (protocol.md 5.2): a CONTINUE or CONTINUE_ACK count
    /// differed from what this side received on the old transport, the first record on the
    /// replacement transport was not the expected one, the CONTINUE_ACK did not arrive within
    /// the liveness window, or a handover was asked for out of order. This side sent CLOSE
    /// `handover_failed` (28) on the transport it sends on and the streams are reset like at
    /// any session end. The text says which check failed (local diagnostics, also the CLOSE
    /// message).
    HandoverFailed(&'static str),
    /// [`L4SessionAcceptor::closed`]'s own fallback when the actor ended
    /// (or never ran at all — a panic, an aborted task) without itself
    /// reporting why. Never produced by [`run`] itself; see this
    /// module's own doc comment for why this is kept distinct from
    /// [`Self::OutboundGone`].
    ActorGone,
}

/// What a session actor tells whoever built it, through a
/// [`SessionObserver`] (TODO.md L4h6: the peer/session table needs both to
/// do its job, and neither is visible from outside the actor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionNotice {
    /// The first record on this session authenticated: it decrypted, so
    /// the peer on the other end really holds the session's keys.
    /// Sent once. protocol.md 5.1: "A responder keeps its current session
    /// with a peer until a data record on the new session decrypts" — this
    /// is that moment, and the table's `promote` is what it triggers.
    FirstRecord,
    /// The actor is done, for whatever reason (why is on
    /// [`L4SessionAcceptor::closed`]) — including when its task is
    /// dropped or aborted before it finished, which is why this is sent
    /// from a drop guard and not from the end of [`run`]. Sent last.
    Ended,
}

/// Where a session actor reports [`SessionNotice`]s: every notice goes down
/// `tx` together with `tag`, whatever the caller needs to tell sessions
/// apart by (the peer/session table packs a local index and a generation
/// into it, so a late notice from a session whose index has since been
/// reused is told from the new one's).
#[derive(Debug, Clone)]
pub struct SessionObserver {
    tx: mpsc::UnboundedSender<(u64, SessionNotice)>,
    tag: u64,
}

impl SessionObserver {
    /// An observer sending `(tag, notice)` on `tx`. Unbounded on purpose:
    /// a session sends at most two notices in its life.
    pub fn new(tx: mpsc::UnboundedSender<(u64, SessionNotice)>, tag: u64) -> Self {
        Self { tx, tag }
    }

    fn notify(&self, notice: SessionNotice) {
        // Nobody listening any more is not the actor's problem.
        let _ = self.tx.send((self.tag, notice));
    }
}

/// Sends [`SessionNotice::Ended`] when dropped, which is when the session's
/// future finishes or is dropped without ever finishing (or starting): see
/// [`new`], which owns it for exactly that reason.
struct EndGuard(Option<SessionObserver>);

impl Drop for EndGuard {
    fn drop(&mut self) {
        if let Some(observer) = &self.0 {
            observer.notify(SessionNotice::Ended);
        }
    }
}

/// What one L4 session may hold of inbound `data` records that `yamux` has
/// not processed yet, plus stream data `yamux` has received but the
/// application has not read yet (TODO.md L4h6b, T1), in bytes: the whole receive window we grant
/// a peer ([`RECEIVE_WINDOW_GRANT`], about 144 MiB) plus an eighth and 1 MiB
/// for what rides on top of the payload, about 163 MiB.
///
/// **What it counts.** Every `data` record handed to
/// [`L4SessionHandle::feed_inbound`] is charged (ciphertext length plus a
/// fixed allowance for the allocation and queue slot it occupies) and the
/// charge travels with the record: through the actor's queue, through
/// decryption, and into `menzil-stream`'s queue as the guard of
/// `StreamMux::feed_inbound_guarded`, until `yamux` has read the record's
/// last byte. So it counts exactly the bytes this node holds for a peer
/// without anything having looked at them, which is the one place a peer's
/// traffic is not already limited by something else: what `yamux` has read
/// is held by its receive windows (in payload bytes, which the vendored
/// `yamux` keeps within a small factor of memory: see `menzil-stream`'s
/// `config_for`), and what we hold toward the peer is held
/// by [`SendBudget`].
///
/// **Stream data not yet read (T1).** The stream layer is built with a `BufferMeter` (the
/// `InboundBudget` itself): every byte `yamux` queues for a stream's reader is charged to this
/// same counter (payload bytes, not heap) and given back when the reader takes it, the stream
/// is dropped or reset, or the connection ends. The charge changes hands from record to
/// stream data; it is never created twice. The meter never refuses (it cannot, `yamux` has
/// the bytes already): only [`InboundBudget::reserve`] enforces, so the ending rule is
/// unchanged. Heap for the stream data part can be about twice what is charged.
///
/// **Why that size.** It is a ceiling for a peer that ignores flow control,
/// so it must sit above everything a peer that respects it can have in
/// flight, or it ends honest sessions. That is the whole grant, and
/// `yamux` does not read while a reply (the Pong to the peer's RTT Ping,
/// sent every 10 s on a busy connection) waits for room in the outbound
/// channel, which happens whenever this node's own sends back up behind a
/// slow uplink or a peer that is slow to take them. The L4h6b review
/// measured the failure of an earlier 32 MiB figure: with 400 streams
/// sending at once, a 20 s stall ended the session. A record is charged
/// its ciphertext plus 128 bytes whatever its size, so a peer that cuts
/// its data into tiny frames reaches the ceiling with a fraction of its
/// windows; that is intended, it is memory the peer makes us hold. An
/// operator who prefers a lower ceiling on a small machine can set one
/// ([`L4SessionConfig::inbound_budget`], `RouterConfig::with_inbound_budget`)
/// and accepts that a peer filling all its windows during a stall is then
/// ended.
///
/// **Why a record past the ceiling ends the session instead of waiting.**
/// The router that calls `feed_inbound` serves every peer on one task and
/// one L3 connection. Making it wait for one session (stop reading
/// `events`) would hold every other peer's traffic behind that one for as
/// long as it lasts, and one member could cause it as often as it can
/// complete a handshake (10 a minute). `run_session` also does not read the
/// relay socket while an event is waiting, so the relay's PINGs go
/// unanswered and the node's own liveness clock (it runs inside the read)
/// stands still; a wait past the 50 s window (protocol.md 3.3) makes that
/// check fire when reading resumes, and the attachment is torn down with
/// every session on it. A record that cannot be queued cannot be dropped
/// either (the counter gap ends the session, protocol.md 5.2), so the
/// session ends, now, and only that one.
///
/// The total across sessions is bounded by [`L4_INBOUND_CEILING_PER_NODE`].
pub const L4_INBOUND_BUDGET_PER_SESSION: usize =
    RECEIVE_WINDOW_GRANT + RECEIVE_WINDOW_GRANT / 8 + 1024 * 1024;

// A ceiling below the grant would end peers that do what they were told.
const _: () =
    assert!(L4_INBOUND_BUDGET_PER_SESSION > RECEIVE_WINDOW_GRANT + RECEIVE_WINDOW_GRANT / 16);

/// What a record is charged on top of its ciphertext's length: the
/// allocation, the queue slot and the permit it occupies while it waits. A
/// 29-byte Ping took about 96 bytes of memory in the actor's channel and
/// about 128 in `menzil-stream`'s queue (measured by the L4h6b review); a
/// record waits in one of the two at a time, so 128 covers either, and
/// charging only the payload would let a flood of tiny records hold several
/// times the budget.
const INBOUND_RECORD_OVERHEAD: usize = 128;

/// The most one Noise message can be (and so the most ciphertext one record
/// can carry). The relay names `max_record` in WELCOME and the node does not
/// validate it, so nothing sized from it may be trusted to be at most this.
const NOISE_MESSAGE_LIMIT: usize = 65_535;

/// What all of one node's L4 sessions may hold together of unread inbound `data` records, in
/// bytes (TBD 75): 1 GiB, six sessions stalled with their whole window. The per session budget
/// ([`L4_INBOUND_BUDGET_PER_SESSION`]) times the 4,096 sessions a table allows would be 650 GiB.
/// Past it the session holding the most gives way (the victim choice is the router's).
///
/// **Scope.** This ceiling counts records not yet processed by the stream layer AND stream
/// data `yamux` has received but the application has not read yet (the `BufferMeter` on the
/// session's [`InboundBudget`]); both move one charge between them. Only a record's arrival
/// enforces it (the session holding the most gives way); stream data that `yamux` already
/// holds is charged without a check. Memory for the stream data part can be about twice the
/// charge (heap, not payload).
pub const L4_INBOUND_CEILING_PER_NODE: usize = 1 << 30;

/// The top bit of a session's counter: the session has been detached ([`InboundBudget::detach`]),
/// its charges already left the node counter, and its permits must not subtract again.
const DETACHED: usize = 1 << (usize::BITS - 1);

/// The node wide total of the unread inbound charges of every session built with it
/// ([`L4SessionConfig::node_inbound`]), against a ceiling. Increments only happen on the
/// router task (`feed_inbound`), decrements (a permit's drop) on any thread; atomics, no lock.
#[derive(Debug)]
pub struct NodeInbound {
    in_use: AtomicUsize,
    ceiling: usize,
    /// The datagram class's own node wide counter ([`DGRAM_CEILING_PER_NODE`]): past it a
    /// datagram is dropped, nothing else happens. `None` on the counter itself.
    dgram: Option<Arc<NodeInbound>>,
}

impl NodeInbound {
    /// A counter at zero with `ceiling` bytes.
    pub fn new(ceiling: usize) -> Self {
        Self {
            in_use: AtomicUsize::new(0),
            ceiling,
            dgram: Some(Arc::new(Self {
                in_use: AtomicUsize::new(0),
                ceiling: DGRAM_CEILING_PER_NODE,
                dgram: None,
            })),
        }
    }

    /// The same counter with another datagram node cap (tests: the real one is 64 MiB).
    #[cfg(test)]
    pub(crate) fn with_dgram_ceiling(mut self, bytes: usize) -> Self {
        self.dgram = Some(Arc::new(Self {
            in_use: AtomicUsize::new(0),
            ceiling: bytes,
            dgram: None,
        }));
        self
    }

    /// What every session's unread inbound datagrams hold together right now.
    pub fn dgram_in_use(&self) -> usize {
        self.dgram.as_ref().map_or(0, |d| d.in_use())
    }

    /// What every session built with this counter holds right now.
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Relaxed)
    }

    /// The ceiling in bytes.
    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Adds `charge`; with `enforce`, refuses (and adds nothing) if that would pass the ceiling.
    fn add(&self, charge: usize, enforce: bool) -> bool {
        let mut current = self.in_use.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(charge) else {
                return false;
            };
            if enforce && next > self.ceiling {
                return false;
            }
            match self.in_use.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }
}

/// Why [`InboundBudget::reserve`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The session's own budget.
    Session,
    /// The node wide ceiling.
    Node,
}

/// The counter behind [`L4_INBOUND_BUDGET_PER_SESSION`], one per session,
/// shared by every clone of its [`L4SessionHandle`].
#[derive(Clone, Debug)]
pub(crate) struct InboundBudget {
    /// The charges, with [`DETACHED`] in the top bit.
    in_use: Arc<AtomicUsize>,
    ceiling: usize,
    node: Option<Arc<NodeInbound>>,
}

impl InboundBudget {
    pub(crate) fn new(ceiling: usize) -> Self {
        Self {
            in_use: Arc::new(AtomicUsize::new(0)),
            ceiling,
            node: None,
        }
    }

    /// The same budget, also counted in `node`.
    pub(crate) fn with_node(mut self, node: Option<Arc<NodeInbound>>) -> Self {
        self.node = node;
        self
    }

    /// What is charged right now (tests).
    #[cfg(test)]
    pub(crate) fn in_use_for_tests(&self) -> usize {
        self.used()
    }

    /// What is charged right now, without the detach bit.
    pub(crate) fn used(&self) -> usize {
        self.in_use.load(Ordering::Relaxed) & !DETACHED
    }

    /// Charges `charge` bytes: refused with [`Refused::Session`] if that would pass this
    /// session's ceiling, and, when `enforce_node`, with [`Refused::Node`] if it would pass the
    /// node's. Without `enforce_node` the node counter is charged regardless.
    ///
    /// Must only be called from the one task that increments (the router): it is what makes
    /// "reserve the session, then the node" and [`Self::detach`] not interleave.
    pub(crate) fn reserve(
        &self,
        charge: usize,
        enforce_node: bool,
    ) -> Result<InboundPermit, Refused> {
        let mut current = self.in_use.load(Ordering::Relaxed);
        let detached = loop {
            let detached = current & DETACHED;
            let next_used = (current & !DETACHED)
                .checked_add(charge)
                .ok_or(Refused::Session)?;
            if next_used > self.ceiling {
                return Err(Refused::Session);
            }
            match self.in_use.compare_exchange_weak(
                current,
                next_used | detached,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break detached != 0,
                Err(actual) => current = actual,
            }
        };
        // A detached session's charges are not in the node counter, and its permits skip it.
        if let Some(node) = self.node.as_ref().filter(|_| !detached)
            && !node.add(charge, enforce_node)
        {
            self.in_use.fetch_sub(charge, Ordering::AcqRel);
            return Err(Refused::Node);
        }
        Ok(InboundPermit {
            in_use: Arc::clone(&self.in_use),
            node: self.node.clone(),
            charge,
        })
    }

    /// Takes everything this session holds out of the node counter now, and keeps its permits
    /// from doing so later (a session whose actor is slow to end must not make others give way).
    /// Returns what was taken out; zero on a repeat or without a node counter. The drop of a
    /// permit and this are ordered on the same atomic: a drop before the `fetch_or` took its
    /// own charge out of the node counter, one after sees the bit and leaves it.
    pub(crate) fn detach(&self) -> usize {
        let prev = self.in_use.fetch_or(DETACHED, Ordering::AcqRel);
        if prev & DETACHED != 0 {
            return 0;
        }
        let held = prev & !DETACHED;
        if let Some(node) = &self.node {
            node.in_use.fetch_sub(held, Ordering::AcqRel);
        }
        held
    }
}

/// The stream layer's meter (T1): stream data `yamux` holds unread is charged to the session
/// and node counters exactly like a record's permit, and given back the same way.
///
/// `buffered` charges the node first and the session second: if a concurrent
/// [`InboundBudget::detach`] has already taken the session's charges out of the node counter,
/// the node charge is taken back again. The other order lets `detach` subtract a `held` that
/// includes a charge the node never received, which can wrap the node counter below zero.
impl menzil_stream::BufferMeter for InboundBudget {
    fn buffered(&self, n: usize) {
        if let Some(node) = &self.node {
            node.add(n, false);
        }
        let prev = self.in_use.fetch_add(n, Ordering::AcqRel);
        if prev & DETACHED != 0
            && let Some(node) = &self.node
        {
            node.in_use.fetch_sub(n, Ordering::AcqRel);
        }
    }

    fn consumed(&self, n: usize) {
        let prev = self.in_use.fetch_sub(n, Ordering::AcqRel);
        if prev & DETACHED == 0
            && let Some(node) = &self.node
        {
            node.in_use.fetch_sub(n, Ordering::AcqRel);
        }
    }
}

/// A charge on an [`InboundBudget`], given back on drop.
pub(crate) struct InboundPermit {
    in_use: Arc<AtomicUsize>,
    node: Option<Arc<NodeInbound>>,
    charge: usize,
}

impl Drop for InboundPermit {
    fn drop(&mut self) {
        let prev = self.in_use.fetch_sub(self.charge, Ordering::AcqRel);
        if prev & DETACHED == 0
            && let Some(node) = &self.node
        {
            node.in_use.fetch_sub(self.charge, Ordering::AcqRel);
        }
    }
}

/// [`L4SessionHandle::feed_inbound`] refused a reliable record, which is handed back where
/// that is useful. Either way the record is not queued, the peer's counter has a gap, and the
/// session cannot go on.
#[derive(Debug, PartialEq, Eq)]
pub enum FeedRefused {
    /// This session's own budget is spent.
    Session(InboundOverflow),
    /// The node wide ceiling ([`L4_INBOUND_CEILING_PER_NODE`]) would be passed. The record is
    /// handed back so the router can retry it after making room
    /// ([`L4SessionHandle::feed_inbound_over_ceiling`]).
    Node {
        /// The record's counter.
        counter: u64,
        /// The record's ciphertext.
        ciphertext: Vec<u8>,
    },
}

/// [`L4SessionHandle::feed_inbound`] was refused: this session already holds
/// as much unread inbound data as its budget allows
/// ([`L4_INBOUND_BUDGET_PER_SESSION`]). The record is dropped, which leaves
/// a gap in the peer's counter, so the session cannot go on: the caller
/// ends it (that constant's docs say why it is not made to wait).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("this session already holds {budget} bytes of inbound data nothing has read yet")]
pub struct InboundOverflow {
    /// The session's budget in bytes.
    pub budget: usize,
}

/// A command sent to [`run`] through [`L4SessionHandle`].
enum Command {
    Close(Option<CloseReason>),
}

/// Everything [`new`] needs beyond the already-finished transport itself.
pub struct L4SessionConfig {
    /// The finished L4 Noise transport (`menzil_e2e::E2eInitiatorHandshake::
    /// finish` or `E2eResponderHandshake::finish`).
    pub transport: E2eTransport,
    /// The peer this session talks to — `OutboundSend::dst`.
    pub peer: NodeId,
    /// The network this session's authorization is scoped to (protocol.md
    /// 5.1) — not used by this module's own logic, only carried for a
    /// caller to read back off [`L4SessionHandle::network_id`] (e.g. to
    /// build a `menzil_node::PolicyAuthorizer` for this session, TODO.md
    /// L4h4).
    pub network_id: NetworkId,
    /// `yamux`'s own client/server split — [`Mode::Client`] if this node
    /// was the L4 initiator (sent `init`), [`Mode::Server`] if it was the
    /// responder (protocol.md 5.1; see `menzil_stream::new`'s own doc
    /// comment).
    pub mode: Mode,
    /// This L4 session's own record ceiling (WELCOME's `limits.max_record`,
    /// protocol.md 4.1) — the same value `transport` was itself built
    /// with, needed again here to size the `menzil_stream` connection
    /// (`menzil_stream::new`'s own second argument) and to bound a CLOSE
    /// message ([`close_msg_limit`]).
    pub max_record: u32,
    /// Which L3 attachment this session was opened under (protocol.md
    /// 5.1's path pinning) — stamped on every `OutboundSend` this session
    /// produces.
    pub epoch: Epoch,
    /// Where this session reserves queue space in this node's L3
    /// `OutboundQueue` before producing each `Mux` record (TODO.md L4h5;
    /// see [`SendBudget`] for why). **Every L4 session to the same `peer`
    /// must share one**, since they share one per-destination queue
    /// allowance: take it from one [`crate::SendBudgets`] per node,
    /// `for_peer(peer)`.
    pub send_budget: SendBudget,
    /// Told when the first record authenticates and when the actor ends
    /// (see [`SessionNotice`]); `None` if nobody needs to know.
    pub observer: Option<SessionObserver>,
    /// How many bytes of inbound `data` records this session may hold
    /// before `yamux` has read them; [`L4SessionHandle::feed_inbound`]
    /// refuses past it. [`L4_INBOUND_BUDGET_PER_SESSION`] unless a test or
    /// an operator needs another. Raised to hold at least two records of
    /// the largest size that can exist (`max_record`, but never more than
    /// Noise's 65,535), so that a record the wire allows can always be
    /// queued.
    pub inbound_budget: usize,
    /// The node wide counter this session's unread inbound data is also charged to; `None`
    /// for a session built without a router.
    pub node_inbound: Option<Arc<NodeInbound>>,
}

/// A cloneable handle to one running [`run`] actor's send side: open
/// outbound streams, feed in inbound `Data` frames this session's
/// receiver index routes here, and close with a reason. Cheap to clone
/// (every field already is: [`menzil_stream::StreamMux::open`] is itself
/// `Clone`, and both channel senders are `mpsc` senders) — every clone
/// talks to the same [`run`] actor, so one can be handed to a task that
/// needs to open or feed inbound data while a *different* task drives
/// [`L4SessionAcceptor::accept`] on the other half this session's [`new`]
/// returns, which cannot itself be cloned (see that type's own doc
/// comment for why). A round-2 red-team review found the original,
/// unsplit handle made that impossible: `accept`'s `&mut self` borrowed
/// the whole struct, including this send side, so nothing else could
/// open, feed, or close while an accept loop was running.
#[derive(Clone)]
pub struct L4SessionHandle {
    peer: NodeId,
    network_id: NetworkId,
    stream_mux: menzil_stream::StreamMux,
    inbound_data_tx: mpsc::UnboundedSender<InboundItem>,
    inbound_budget: InboundBudget,
    /// The datagrams' own budget ([`DGRAM_BUDGET_PER_SESSION`]): what is past it is dropped,
    /// never an [`InboundOverflow`].
    dgram_budget: InboundBudget,
    /// The channels of a member session; `None` for a docs only or relay principal session,
    /// which drop every datagram.
    channels: Option<ChannelTable>,
    command_tx: mpsc::UnboundedSender<Command>,
    /// The newest generation [`Self::hand_over`] handed out; shared by every clone.
    last_generation: Arc<AtomicU32>,
    /// The newest generation whose cutover completed, written by the actor
    /// ([`Self::settled_generation`]).
    settled_generation: Arc<AtomicU32>,
    /// The early bytes the peer offered in its handshake payload (protocol.md 5.1, 5.3): how
    /// many application bytes an OPEN on this session may carry. 0 until [`Self::set_peer_early`]
    /// (a responder side session, or a peer that offered none). Shared by every clone.
    peer_early: Arc<AtomicU32>,
}

/// The most early bytes (protocol.md 5.3) a responder offers and an initiator sends on one OPEN.
pub const EARLY_MAX: u32 = 16_384;

/// Names which of a session's transports a routed `data` frame belongs to (protocol.md 5.2,
/// the re-handshake handover). The transport a session is built with is generation
/// [`FIRST_GENERATION`] (0); each [`L4SessionHandle::hand_over`] returns the next one. The
/// router knows which one a frame is for from the `receiver_index` it matched, and passes it
/// to [`L4SessionHandle::feed_inbound_gen`]; the actor decrypts every record with the keys of
/// exactly that transport and drops one whose transport it no longer (or not yet) holds.
pub type Generation = u32;

/// The first generation: the transport a session starts with.
pub const FIRST_GENERATION: Generation = 0;

/// Which side of a handover this actor is (protocol.md 5.2; see [`L4SessionHandle::hand_over`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoverRole {
    /// This side started the replacement (the chain initiator). `prior` is the `held` index
    /// the responder offered in `resp`. The actor sends CONTINUE as the first reliable record
    /// of the new transport, and expects CONTINUE_ACK as the first one back.
    Initiator {
        /// The responder's `held` value, which CONTINUE echoes.
        prior: u32,
    },
    /// This side answers. The caller (the router) already decrypted and verified the peer's
    /// CONTINUE on the new transport (`prior`, `binding`, slot and standing: not the actor's
    /// business) and passes the `sent` it carried. The actor, when it reaches the item in its
    /// queue (so after every old record already queued), checks the count against what it
    /// received on the old transport and answers CONTINUE_ACK.
    Responder {
        /// The `sent` of the peer's CONTINUE: how many reliable records it sent on the old
        /// transport.
        continue_sent: u64,
    },
}

/// The ordered handover item in the actor's inbound queue (see [`L4SessionHandle::hand_over`]).
struct Handover {
    generation: Generation,
    transport: E2eTransport,
    role: HandoverRole,
}

/// What travels through the actor's ordered inbound queue: routed `data` frames with the
/// permit that counts their bytes while they wait, and, between them, handovers. One queue
/// for both is what puts a handover after every old record queued before it.
enum InboundItem {
    Record {
        generation: Generation,
        counter: u64,
        ciphertext: Vec<u8>,
        permit: InboundPermit,
    },
    /// Boxed: a transport is much larger than a record's fields.
    Handover(Box<Handover>),
}

impl L4SessionHandle {
    /// This session's peer.
    pub fn peer(&self) -> NodeId {
        self.peer
    }

    /// This session's network (see [`L4SessionConfig::network_id`]).
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// The early bytes the peer offered (0: none; protocol.md 5.3).
    pub fn peer_early(&self) -> u32 {
        self.peer_early.load(Ordering::Relaxed)
    }

    /// Records the peer's offer, read from its handshake payload; clamped to [`EARLY_MAX`].
    pub fn set_peer_early(&self, offered: u32) {
        self.peer_early
            .store(offered.min(EARLY_MAX), Ordering::Relaxed);
    }

    /// Opens a new outbound L5 stream (protocol.md 5.3's OPEN/OPEN_ACK
    /// exchange runs on top of this, TODO.md L4h4 — this crate stops at
    /// the raw stream).
    pub async fn open_stream(&self) -> Result<Stream, StreamMuxError> {
        self.stream_mux.open().await
    }

    /// Hands this session one inbound `data` frame's already-routed
    /// `counter`/`ciphertext` (an `E2eFrame::Data` whose `receiver_index`
    /// a caller already matched to this session — TODO.md L4h6, not this
    /// module's job). Must be called in the exact order `menzil-e2e`'s
    /// own reliable-class counter would accept them — this module
    /// trusts its caller the same way `menzil_stream::StreamMux::
    /// feed_inbound` trusts *this* module for the same property one
    /// layer up. A no-op, not an error, once this session has already
    /// ended: nothing further this frame could still affect.
    ///
    /// Never waits, and is bounded (TODO.md L4h6b): the frame is charged to
    /// this session's budget until `yamux` has read it
    /// ([`L4_INBOUND_BUDGET_PER_SESSION`]), and past the budget this
    /// returns [`InboundOverflow`] and drops the frame. The
    /// session cannot go on after that (the peer's counter now has a gap),
    /// so the caller must end it; the actor is told nothing and will
    /// itself end as soon as it sees the close the caller sends, or the
    /// session's removal.
    ///
    /// **A datagram class counter (top bit set, protocol.md 5.2) takes another path and never
    /// fails**: it is dropped at once when this session has no channels (docs only and relay
    /// principal sessions), and otherwise charged to the datagrams' own budget
    /// ([`DGRAM_BUDGET_PER_SESSION`]) and queued in the same ordered queue as the reliable
    /// records, so the actor sees a datagram and a REKEY in the order they arrived. One past
    /// that budget is dropped and the session lives: a datagram that goes missing leaves no gap
    /// anyone depends on. The class is read from the counter, never from the L3 flag.
    pub fn feed_inbound(&self, counter: u64, ciphertext: Vec<u8>) -> Result<(), FeedRefused> {
        self.feed(FIRST_GENERATION, counter, ciphertext, true)
    }

    /// [`Self::feed_inbound`] for a frame of the transport `generation` (see [`Generation`]):
    /// what the router calls for a session that may have been handed over. `feed_inbound` is
    /// this with [`FIRST_GENERATION`]. A frame of a generation the actor no longer holds (or
    /// not yet) is dropped by the actor when it reaches it, a datagram counted in
    /// [`crate::channels::Dropped::handover`].
    pub fn feed_inbound_gen(
        &self,
        generation: Generation,
        counter: u64,
        ciphertext: Vec<u8>,
    ) -> Result<(), FeedRefused> {
        self.feed(generation, counter, ciphertext, true)
    }

    /// [`Self::feed_inbound`] without the node wide check: the node counter is charged even past
    /// its ceiling (by at most this record), the session's own budget still applies. For the
    /// router, after it made room by ending another session. A datagram is never refused.
    pub fn feed_inbound_over_ceiling(
        &self,
        counter: u64,
        ciphertext: Vec<u8>,
    ) -> Result<(), FeedRefused> {
        self.feed(FIRST_GENERATION, counter, ciphertext, false)
    }

    /// [`Self::feed_inbound_over_ceiling`] for a frame of the transport `generation`.
    pub fn feed_inbound_over_ceiling_gen(
        &self,
        generation: Generation,
        counter: u64,
        ciphertext: Vec<u8>,
    ) -> Result<(), FeedRefused> {
        self.feed(generation, counter, ciphertext, false)
    }

    /// Queues the replacement transport of a re-handshake for the actor (protocol.md 5.2,
    /// slice R2) and returns its [`Generation`], the tag [`Self::feed_inbound_gen`] must use
    /// for every frame that arrives under the new transport's index from now on. **Router task
    /// only**, and in the same order as the frames are fed: the generation is numbered here and
    /// the actor checks it is the next one.
    ///
    /// The item rides the same ordered queue as the inbound records, so the actor reaches it
    /// after every record fed before this call; that order is what the responder's count check
    /// relies on. The actor then keeps the old transport for receiving only until the cutover
    /// completes (initiator: until CONTINUE_ACK arrives; responder: at once), sends everything
    /// from the switch on the new transport and never again anything on the old one, and ends
    /// the session with CLOSE `handover_failed` if a count or the first record does not match.
    /// Everything that is not a transport (yamux, streams, channels, budgets, liveness) stays.
    /// A no-op once the session has ended.
    pub fn hand_over(&self, transport: E2eTransport, role: HandoverRole) -> Generation {
        let generation = self.last_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let _ = self
            .inbound_data_tx
            .send(InboundItem::Handover(Box::new(Handover {
                generation,
                transport,
                role,
            })));
        generation
    }

    /// The newest [`Generation`] whose cutover is complete: for a responder, when it switched
    /// (it sent CONTINUE_ACK and dropped the old transport); for an initiator, when it accepted
    /// CONTINUE_ACK and dropped the old transport. [`FIRST_GENERATION`] until then. Once it
    /// equals the generation [`Self::hand_over`] returned, nothing more arrives under the old
    /// transport's index that matters (the router may release it) and the next replacement may
    /// be handed over.
    pub fn settled_generation(&self) -> Generation {
        self.settled_generation.load(Ordering::Acquire)
    }

    /// Ends this session because it reached its hard age cap (protocol.md 5.2): CLOSE
    /// `session_expired` on the transport the session sends on now, then the end. The caller
    /// owns the clock and the cap; this only names the reason. Same as
    /// [`Self::close`] with that code.
    pub fn expire(&self) {
        self.close(Some(CloseReason {
            code: ErrorCode::SessionExpired,
            msg: "the session reached its age cap".to_string(),
        }));
    }

    /// Takes this session's charges out of the node counter at once, for a session the router
    /// gave up on whose actor has not ended yet (see [`InboundBudget::detach`]). Router task
    /// only. Idempotent.
    pub fn detach_inbound(&self) {
        self.inbound_budget.detach();
    }

    fn feed(
        &self,
        generation: Generation,
        counter: u64,
        ciphertext: Vec<u8>,
        enforce_node: bool,
    ) -> Result<(), FeedRefused> {
        if RecordClass::of_counter(counter) == RecordClass::Datagram {
            if self.channels.is_none() {
                return Ok(());
            }
            let charge = ciphertext.len().saturating_add(INBOUND_RECORD_OVERHEAD);
            // The node wide datagram cap is always enforced: a refusal (the session's own
            // budget or the node's) drops the datagram, never anything else.
            if let Ok(permit) = self.dgram_budget.reserve(charge, true) {
                let _ = self.inbound_data_tx.send(InboundItem::Record {
                    generation,
                    counter,
                    ciphertext,
                    permit,
                });
            }
            return Ok(());
        }
        let charge = ciphertext.len().saturating_add(INBOUND_RECORD_OVERHEAD);
        let permit = match self.inbound_budget.reserve(charge, enforce_node) {
            Ok(permit) => permit,
            Err(Refused::Session) => {
                return Err(FeedRefused::Session(InboundOverflow {
                    budget: self.inbound_budget.ceiling,
                }));
            }
            Err(Refused::Node) => {
                return Err(FeedRefused::Node {
                    counter,
                    ciphertext,
                });
            }
        };
        // A send to an actor that is gone hands the message back inside the
        // error; dropping it gives the charge back.
        let _ = self.inbound_data_tx.send(InboundItem::Record {
            generation,
            counter,
            ciphertext,
            permit,
        });
        Ok(())
    }

    /// The datagram channels of this session, or `None` for a session that carries none (a docs
    /// only or relay principal session, or one built with [`new`]).
    pub fn channels(&self) -> Option<&ChannelTable> {
        self.channels.as_ref()
    }

    /// How many bytes of inbound datagrams this session holds right now (the actor's queue and
    /// the channels' sinks), against [`DGRAM_BUDGET_PER_SESSION`].
    pub fn dgram_in_use(&self) -> usize {
        self.dgram_budget.used()
    }

    /// How many bytes of inbound records this session holds right now that
    /// `yamux` has not read yet (what [`Self::feed_inbound`] charges).
    pub fn inbound_in_use(&self) -> usize {
        self.inbound_budget.used()
    }

    /// The most [`Self::inbound_in_use`] can reach before
    /// [`Self::feed_inbound`] refuses: the configured budget, or the floor
    /// described on [`L4SessionConfig::inbound_budget`] if that was lower.
    pub fn inbound_budget(&self) -> usize {
        self.inbound_budget.ceiling
    }

    /// Ends this session, optionally telling the peer why first — a
    /// [`CloseReason`] is sent as a best-effort `data` record of kind
    /// CLOSE (bounded by [`CLOSE_SEND_TIMEOUT`], and simply not sent at
    /// all if it fails to even encrypt) before the session actually
    /// ends; whether it actually reaches the peer is never this call's
    /// problem to report, since the session is ending either way.
    /// Fire-and-forget: a no-op, not an error, if the session has
    /// already ended on its own. Await [`L4SessionAcceptor::closed`]
    /// separately for confirmation.
    pub fn close(&self, reason: Option<CloseReason>) {
        let _ = self.command_tx.send(Command::Close(reason));
    }
}

/// The unique other half of one running [`run`] actor, from [`new`]:
/// accept inbound L5 streams the peer opened, and observe why the
/// session ended. Not [`Clone`] — unlike [`L4SessionHandle`]'s fields,
/// this type's `menzil_stream::Inbound` and `oneshot::Receiver` are not
/// `Clone` themselves (a yamux `Stream` can only ever be delivered to one
/// accepter, and an end reason can only ever be taken out of one
/// `oneshot` channel), so this half stays single-owner — the caller
/// driving an accept loop (TODO.md L4h4's `accept_loop`) owns it for as
/// long as that loop runs. `peer`/`network_id` are duplicated from
/// [`L4SessionHandle`] (both are cheap `Copy` session properties) so a
/// caller holding only this half never needs the other one just to read
/// them.
pub struct L4SessionAcceptor {
    peer: NodeId,
    network_id: NetworkId,
    inbound: menzil_stream::Inbound,
    // Never set back to `None`/consumed once seen resolved — `closed()`
    // checks `ended_cached` first and never touches this again past
    // that point, so there is no second state for it to hold (a round-2
    // red-team review flagged the previous `Option<..>` wrapper here as
    // vestigial for exactly this reason).
    ended_rx: oneshot::Receiver<EndReason>,
    ended_cached: Option<Arc<EndReason>>,
}

impl L4SessionAcceptor {
    /// This session's peer — see [`L4SessionHandle::peer`].
    pub fn peer(&self) -> NodeId {
        self.peer
    }

    /// This session's network — see [`L4SessionHandle::network_id`].
    pub fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Waits for the next inbound L5 stream the peer opened, or `None`
    /// once this session has ended.
    pub async fn accept(&mut self) -> Option<Stream> {
        self.inbound.accept().await
    }

    /// Waits for this session to end, returning why. Safe to call more
    /// than once, including from inside a `select!`-driven loop that
    /// re-evaluates this call on every iteration — see this module's own
    /// doc comment for why an earlier version of this method was not.
    pub async fn closed(&mut self) -> Arc<EndReason> {
        if let Some(reason) = &self.ended_cached {
            return Arc::clone(reason);
        }
        let reason = Arc::new((&mut self.ended_rx).await.unwrap_or(EndReason::ActorGone));
        self.ended_cached = Some(Arc::clone(&reason));
        reason
    }
}

/// Builds one L4 session actor: the send-side handle, the unique
/// acceptor, plus the future a caller must `tokio::spawn` for anything on
/// either one to make progress (see this module's own doc comment on why
/// this crate never spawns it itself). That future's own output is `()`,
/// not [`EndReason`] — the actor sends its end reason to
/// [`L4SessionAcceptor::closed`] itself (the one place a caller should
/// actually observe it) before returning, the same split
/// `menzil_stream::Driver` leaves to a `JoinHandle` versus
/// `StreamMuxError` any other method call on a dead driver reports
/// instead. `outbound` is a clone of the same channel a running
/// `menzil_node::session::run_session` reads `OutboundSend`s from — this
/// session's own sends ride it exactly like any other caller's, tagged
/// with `config.epoch`. `epoch_ended` resolves (or is simply dropped)
/// once whoever constructed this session observes `SessionEvent::
/// Detached` for that same epoch — see this module's own doc comment on
/// why that is reported directly rather than only inferred from a later
/// refused send.
pub fn new(
    config: L4SessionConfig,
    outbound: mpsc::Sender<OutboundSend>,
    epoch_ended: oneshot::Receiver<()>,
) -> (
    L4SessionHandle,
    L4SessionAcceptor,
    impl Future<Output = ()> + Send + 'static,
) {
    build(config, false, outbound, epoch_ended)
}

/// [`new`] for a member session: the same actor, with datagram channels (protocol.md 5.4,
/// [`L4SessionHandle::channels`]). A session built with [`new`] has none and drops every
/// datagram, which is what a docs only session and the relay principal's session must do.
pub fn new_with_datagrams(
    config: L4SessionConfig,
    outbound: mpsc::Sender<OutboundSend>,
    epoch_ended: oneshot::Receiver<()>,
) -> (
    L4SessionHandle,
    L4SessionAcceptor,
    impl Future<Output = ()> + Send + 'static,
) {
    build(config, true, outbound, epoch_ended)
}

fn build(
    config: L4SessionConfig,
    datagrams: bool,
    outbound: mpsc::Sender<OutboundSend>,
    epoch_ended: oneshot::Receiver<()>,
) -> (
    L4SessionHandle,
    L4SessionAcceptor,
    impl Future<Output = ()> + Send + 'static,
) {
    let (dgram_rx, channels) = if datagrams {
        let (tx, rx) = mpsc::channel::<DgramOut>(DGRAM_SEND_QUEUE);
        let table = ChannelTable::new(
            config.mode == Mode::Client,
            tx,
            config.transport.max_dgram_payload(),
        );
        (Some(rx), Some(table))
    } else {
        (None, None)
    };
    let (inbound_data_tx, inbound_data_rx) = mpsc::unbounded_channel();
    // At least two records of the largest size that can exist, so that one
    // the wire allows can always be queued; sized from the smaller of
    // `max_record` and what Noise allows, because the relay sets `max_record`.
    let largest_record = (config.max_record as usize).min(NOISE_MESSAGE_LIMIT);
    let inbound_budget = InboundBudget::new(
        config
            .inbound_budget
            .max(2 * (largest_record + INBOUND_RECORD_OVERHEAD)),
    )
    .with_node(config.node_inbound.clone());
    let (stream_mux, inbound, outbound_frames, driver) = menzil_stream::new_metered(
        config.mode,
        config.max_record,
        menzil_stream::MuxLimits::default(),
        Arc::new(inbound_budget.clone()),
    );
    let dgram_node = config
        .node_inbound
        .as_ref()
        .and_then(|node| node.dgram.clone());
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let (ended_tx, ended_rx) = oneshot::channel();
    let settled_generation = Arc::new(AtomicU32::new(FIRST_GENERATION));

    let handle = L4SessionHandle {
        peer: config.peer,
        network_id: config.network_id,
        stream_mux: stream_mux.clone(),
        inbound_data_tx,
        inbound_budget,
        dgram_budget: InboundBudget::new(DGRAM_BUDGET_PER_SESSION).with_node(dgram_node),
        channels: channels.clone(),
        command_tx,
        last_generation: Arc::new(AtomicU32::new(FIRST_GENERATION)),
        settled_generation: settled_generation.clone(),
        peer_early: Arc::new(AtomicU32::new(0)),
    };
    let acceptor = L4SessionAcceptor {
        peer: config.peer,
        network_id: config.network_id,
        inbound,
        ended_rx,
        ended_cached: None,
    };

    // Built here, outside `run`, and moved into the future that wraps it:
    // a guard created inside `run`'s body would never exist if the task
    // were dropped before its first poll (an `abort()` right after
    // spawning, found by this module's own test), and then no `Ended`
    // would ever be sent.
    let end_guard = EndGuard(config.observer.clone());
    let task = run(
        config.transport,
        config.peer,
        config.epoch,
        config.max_record,
        stream_mux,
        outbound_frames,
        driver,
        outbound,
        config.send_budget,
        config.observer,
        inbound_data_rx,
        command_rx,
        epoch_ended,
        ended_tx,
        dgram_rx,
        channels,
        settled_generation,
    );
    let task = async move {
        let _end_guard = end_guard;
        task.await;
    };

    (handle, acceptor, task)
}

/// One outbound `Mux` frame that [`run`] has pulled out of
/// `menzil-stream` but not yet encrypted, because the space it will
/// occupy in this node's send queue is not free yet (TODO.md L4h5).
///
/// **Why a frame waits here, un-encrypted, instead of being encrypted and
/// handed to `outbound` straight away**: once `menzil-e2e` has given a
/// record a counter it can never be dropped or retried without ending the
/// session, and the node's `OutboundQueue` refuses a reliable record when
/// it is full. Ordinary bulk transfer fills it (the receive windows of a
/// few busy streams add up to more than it holds), so before this existed
/// a perfectly healthy session ended with [`EndReason::SendRefused`]
/// ([`EnqueueOutcome::QueueFull`]). Reserving the space first through the
/// shared [`SendBudget`] means that never happens to a reserved record;
/// everything beyond the budget just waits.
///
/// **Why the wait is a `select!` branch rather than an `.await` inside the
/// loop body**: it can last as long as the peer takes to give credit back,
/// and this actor must keep decrypting inbound records, answering its own
/// clocks, and noticing a `close()` the whole time (a blocking wait here
/// would leave it deaf, and its liveness clock would eventually declare a
/// perfectly alive peer dead).
///
/// **Why nothing else is staged behind it**: while a frame is staged, the
/// next one is not pulled from `menzil-stream` at all. Its bounded
/// outbound channel then fills and pauses `yamux` (`menzil-stream`'s
/// `record_io` module), and every stream writer ends up waiting in turn:
/// that chain *is* the backpressure.
struct Staged {
    frame: Vec<u8>,
    /// Resolves to the reserved space, or `Err` once
    /// [`SEND_OUTCOME_TIMEOUT`] passes without any being freed.
    reservation:
        Pin<Box<dyn Future<Output = Result<SendPermit, tokio::time::error::Elapsed>> + Send>>,
}

impl Staged {
    fn new(frame: Vec<u8>, budget: &SendBudget) -> Self {
        // Exactly what the node's queue will charge for this record once
        // encrypted: its encoded length, floored at the same minimum
        // (`OutboundQueue`'s own `QueuedSend::charge`).
        let charge = e2e_data_frame_len(1 + frame.len()).max(MIN_SEND_CHARGE_BYTES as usize);
        let budget = budget.clone();
        Self {
            frame,
            reservation: Box::pin(tokio::time::timeout(SEND_OUTCOME_TIMEOUT, async move {
                budget.acquire(charge).await
            })),
        }
    }
}

/// Encrypts `body` and hands it to `outbound` as an epoch-tagged reliable
/// SEND, without waiting for its own admission outcome — pushes the
/// outcome receiver onto `pending_outcomes` instead, for [`run`]'s own
/// separate `select!` branch to notice a refusal without that wait
/// serializing how fast outbound frames can be pumped. See this module's
/// own doc comment for why: once `menzil_e2e::E2eTransport::encrypt_data`
/// has assigned `body` a reliable-class counter, that specific record can
/// never be retried in place (the same rule `crate::outbound`'s own
/// `EnqueueOutcome` already states for `TooLarge`/`QueueFull`/
/// `WrongEpoch`), so a refusal discovered later must still end the
/// session the same way an encrypt failure or a channel closing would —
/// just not by blocking every other frame behind this one's own round
/// trip in the meantime. Updates `liveness`/`rekey` as soon as `outbound`
/// accepts the send (not once its outcome is actually known — see this
/// module's own doc comment on why that no longer matters here).
///
/// Returns `Some(reason)` if this call itself must end the session
/// outright: an encrypt failure, or `outbound` neither accepting this
/// send nor rejecting it outright within [`SEND_OUTCOME_TIMEOUT`] (that
/// bound covers the send itself now, not only the later wait for its
/// outcome — see this module's own doc comment on why both needed one).
// 8 genuinely independent inputs (the session's own mutable state, its
// fixed identity, and where to route the outcome) — see
// `decide_responder_admission`'s identical note on why a struct purely
// to dodge this count would be ceremony, not a real grouping, for a
// private function with a small, fixed set of call sites.
#[allow(clippy::too_many_arguments)]
async fn enqueue_send(
    transport: &mut E2eTransport,
    liveness: &mut Liveness,
    rekey: &mut RekeySchedule,
    outbound: &mpsc::Sender<OutboundSend>,
    peer: NodeId,
    epoch: Epoch,
    body: E2eDataBody,
    permit: Option<SendPermit>,
    pending_outcomes: &mut FuturesUnordered<
        tokio::time::Timeout<oneshot::Receiver<EnqueueOutcome>>,
    >,
) -> Option<EndReason> {
    let is_rekey = matches!(body, E2eDataBody::Rekey);
    let frame = match transport.encrypt_data(&body) {
        Ok(frame) => frame,
        Err(err) => return Some(EndReason::EncryptFailed(err)),
    };
    enqueue_frame(
        frame,
        is_rekey,
        liveness,
        rekey,
        outbound,
        peer,
        epoch,
        permit,
        pending_outcomes,
    )
    .await
}

/// The second half of [`enqueue_send`]: hands an already encrypted reliable frame to `outbound`
/// (the handover records are encrypted by `E2eTransport::encrypt_raw`, not `encrypt_data`).
#[allow(clippy::too_many_arguments)]
async fn enqueue_frame(
    frame: E2eFrame,
    is_rekey: bool,
    liveness: &mut Liveness,
    rekey: &mut RekeySchedule,
    outbound: &mpsc::Sender<OutboundSend>,
    peer: NodeId,
    epoch: Epoch,
    permit: Option<SendPermit>,
    pending_outcomes: &mut FuturesUnordered<
        tokio::time::Timeout<oneshot::Receiver<EnqueueOutcome>>,
    >,
) -> Option<EndReason> {
    let payload = frame.encode();
    debug_assert!(
        permit
            .as_ref()
            .is_none_or(|p| p.bytes() >= payload.len().max(MIN_SEND_CHARGE_BYTES as usize)),
        "a reservation must cover what the queue will charge for this record"
    );
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let req = OutboundSend {
        dst: peer,
        e2e_proto: E2E_PROTO_TAG,
        flags: RELIABLE_FLAGS,
        payload,
        epoch,
        outcome: outcome_tx,
        permit,
    };
    match tokio::time::timeout(SEND_OUTCOME_TIMEOUT, outbound.send(req)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return Some(EndReason::OutboundGone),
    }
    let now = clock_now();
    liveness.note_sent(now);
    if is_rekey {
        rekey.note_rekeyed(now);
    } else {
        rekey.note_sent();
    }
    // Each pushed item carries its own `SEND_OUTCOME_TIMEOUT` bound: see the module docs.
    pending_outcomes.push(tokio::time::timeout(SEND_OUTCOME_TIMEOUT, outcome_rx));
    None
}

/// Sends the CLOSE record for a locally requested end. Best effort, fully:
/// a short, separate timeout, and an encrypt failure or a refusal is simply
/// not retried or reported — the session is ending either way, and nothing
/// about that outcome could change what happens next. See this module's own
/// doc comment for why CLOSE specifically skips `pending_outcomes` rather
/// than only skipping the wait.
async fn send_close(
    transport: &mut E2eTransport,
    outbound: &mpsc::Sender<OutboundSend>,
    peer: NodeId,
    epoch: Epoch,
    max_record: u32,
    close: &CloseReason,
) {
    let limit = close_msg_limit(max_record);
    let Ok(frame) = transport.encrypt_data(&E2eDataBody::Close {
        code: close.code,
        msg: clamp_close_msg(&close.msg, limit),
    }) else {
        return;
    };
    let (outcome_tx, _outcome_rx) = oneshot::channel();
    let req = OutboundSend {
        dst: peer,
        e2e_proto: E2E_PROTO_TAG,
        flags: RELIABLE_FLAGS,
        payload: frame.encode(),
        epoch,
        outcome: outcome_tx,
        permit: None,
    };
    let _ = tokio::time::timeout(CLOSE_SEND_TIMEOUT, outbound.send(req)).await;
}

/// The old transport of an initiator that has switched sending to the replacement and waits
/// for CONTINUE_ACK (protocol.md 5.2). **Receive only, and only until the ACK:** nothing is
/// ever encrypted on it after the switch (there is deliberately no way to reach its encrypt
/// side from the actor's send paths: they all use the actor's current `transport`). Dropped
/// (its keys zeroize) when the ACK is accepted or the session ends.
struct Retiring {
    generation: Generation,
    transport: E2eTransport,
    /// When the wait for CONTINUE_ACK ends the session ([`HANDOVER_ACK_WINDOW`]).
    ack_deadline: Instant,
}

/// Counts one datagram dropped because of a cutover.
fn note_handover_drop(channels: &Option<ChannelTable>) {
    if let Some(channels) = channels {
        channels.note_handover_drop();
    }
}

/// Sends CLOSE `handover_failed` on `transport` (best effort, like every CLOSE) and returns the
/// reason the session then ends with. `transport` is the one this side sends on now, or, for a
/// responder that refuses before switching, the replacement transport (nothing was sent on it
/// yet, so the CLOSE is its first record, which the initiator waiting for CONTINUE_ACK reads).
async fn fail_handover(
    transport: &mut E2eTransport,
    outbound: &mpsc::Sender<OutboundSend>,
    peer: NodeId,
    epoch: Epoch,
    max_record: u32,
    why: &'static str,
) -> EndReason {
    let close = CloseReason {
        code: ErrorCode::HandoverFailed,
        msg: why.to_string(),
    };
    send_close(transport, outbound, peer, epoch, max_record, &close).await;
    EndReason::HandoverFailed(why)
}

/// Decrypts and acts on one `data` frame of `transport` (the session's current transport, or an
/// initiator's retiring one): the original inbound handling of [`run`], unchanged. A datagram
/// class counter takes the datagram path (its own replay window, every failure short of an
/// authenticated malformed body drops the one frame); a reliable one is decrypted, feeds
/// liveness only on success, and its body is acted on. Returns the reason the session must end.
#[allow(clippy::too_many_arguments)]
fn process_inbound(
    transport: &mut E2eTransport,
    counter: u64,
    ciphertext: Vec<u8>,
    permit: InboundPermit,
    liveness: &mut Liveness,
    first_record_noted: &mut bool,
    observer: &Option<SessionObserver>,
    stream_mux: &menzil_stream::StreamMux,
    channels: &Option<ChannelTable>,
) -> Option<EndReason> {
    if RecordClass::of_counter(counter) == RecordClass::Datagram {
        // The datagram class (protocol.md 5.2): its own window and its own
        // failure rules. Everything short of an authenticated, malformed body
        // drops the one frame; none of those feeds liveness.
        let channels = channels.as_ref()?;
        match transport.decrypt_dgram(counter, &ciphertext) {
            Ok((channel, bytes)) => {
                liveness.note_received(clock_now());
                if !*first_record_noted {
                    *first_record_noted = true;
                    if let Some(observer) = observer {
                        observer.notify(SessionNotice::FirstRecord);
                    }
                }
                drop(ciphertext);
                // Whatever the channel does with it, `permit` goes with the
                // datagram: into the sink, or back to the budget on a drop.
                channels.deliver(channel, bytes, permit);
            }
            Err(
                E2eError::Noise(_)
                | E2eError::NotADatagramCounter
                | E2eError::ReservedDatagramCounter
                | E2eError::DatagramReplayed
                | E2eError::DatagramTooOld,
            ) => {}
            Err(err) => return Some(EndReason::Decrypt(err)),
        }
        return None;
    }
    match transport.decrypt_data(counter, &ciphertext) {
        Ok(body) => {
            // Only here, never in the `Err` arms below: see this module's own
            // doc comment on why liveness must not be fed by input that never
            // authenticated at all.
            liveness.note_received(clock_now());
            if !*first_record_noted {
                *first_record_noted = true;
                if let Some(observer) = observer {
                    observer.notify(SessionNotice::FirstRecord);
                }
            }
            match body {
                E2eDataBody::Mux(bytes) => {
                    // The record's charge goes on with its bytes and is given
                    // back when `yamux` has read them. Every other arm, and a
                    // frame that did not decrypt, lets `permit` go at the end.
                    if let Err(err) = stream_mux.feed_inbound_guarded(bytes, Box::new(permit)) {
                        return Some(EndReason::StreamMuxFeedFailed(err));
                    }
                }
                E2eDataBody::Close { code, msg } => {
                    return Some(EndReason::PeerClosed { code, msg });
                }
                // REKEY: `decrypt_data` already applied `rekey_incoming`
                // itself; nothing further beyond the liveness activity above.
                E2eDataBody::Keep | E2eDataBody::Rekey => {}
                E2eDataBody::Dgram { .. } => unreachable!(
                    "decrypt_data refuses every datagram-class counter before \
                     decryption, so no Dgram body can ever reach this match"
                ),
            }
            None
        }
        Err(E2eError::UnauthenticatedDatagramCounter | E2eError::Noise(_)) => {
            // Pre-authentication (or never-authenticated) failures only drop
            // the one frame, see this module's own doc comment.
            None
        }
        Err(err) => Some(EndReason::Decrypt(err)),
    }
}

/// What an initiator makes of one frame of the replacement transport while it still waits for
/// CONTINUE_ACK.
enum AckStep {
    /// Dropped (a datagram before the session is proved, or a frame that did not
    /// authenticate); keep waiting.
    Wait,
    /// A valid CONTINUE_ACK: the old transport can go.
    Done,
    /// The peer ended the session instead (its CLOSE was the first record).
    PeerEnded(EndReason),
    /// Anything else: CLOSE `handover_failed` and end.
    Fail(&'static str),
    /// A post authentication error from the transport: end like [`EndReason::Decrypt`].
    Error(EndReason),
}

/// **The first reliable record on the replacement transport must be CONTINUE_ACK** (protocol.md
/// 5.2: a candidate is proved by its first reliable record; a datagram that arrives first is
/// dropped and counted). Its `sent` must equal the number of reliable records received on the
/// old transport so far (checked, never trusted: the old transport receives in queue order, so
/// every record the responder sent before its ACK has been counted by now).
fn expect_continue_ack(
    new: &mut E2eTransport,
    old: &E2eTransport,
    counter: u64,
    ciphertext: &[u8],
    liveness: &mut Liveness,
    channels: &Option<ChannelTable>,
) -> AckStep {
    if RecordClass::of_counter(counter) == RecordClass::Datagram {
        note_handover_drop(channels);
        return AckStep::Wait;
    }
    let plaintext = match new.decrypt_raw(counter, ciphertext) {
        Ok(plaintext) => plaintext,
        Err(E2eError::UnauthenticatedDatagramCounter | E2eError::Noise(_)) => {
            return AckStep::Wait;
        }
        Err(err) => return AckStep::Error(EndReason::Decrypt(err)),
    };
    liveness.note_received(clock_now());
    if let Ok(ack) = ContinueAckBody::decode(&plaintext) {
        return if ack.sent == old.reliable_received() {
            AckStep::Done
        } else {
            AckStep::Fail("CONTINUE_ACK count differs from the records received on the old session")
        };
    }
    // The responder refusing the handover answers with CLOSE as its first record.
    if let Ok(E2eDataBody::Close { code, msg }) = E2eDataBody::decode(&plaintext) {
        return AckStep::PeerEnded(EndReason::PeerClosed { code, msg });
    }
    AckStep::Fail("the first record on the replacement session is not CONTINUE_ACK")
}

/// Acts on one [`Handover`] item (protocol.md 5.2; [`L4SessionHandle::hand_over`] has the
/// overview). Returns the reason the session must end, if any.
///
/// **Switch point.** In both roles the replacement transport is encrypted into the first record
/// (CONTINUE or CONTINUE_ACK) before `transport` is replaced, and from the replacement on every
/// send of this actor (MUX, KEEP, REKEY, CLOSE, DGRAM) goes through the one `transport`
/// variable, so nothing can be encrypted on the old transport afterwards. The counters, the
/// datagram replay window and the rekey schedule start afresh with the new transport (the
/// schedule is replaced here; the counters and window are the new transport's own).
///
/// **Initiator.** CONTINUE carries `prior`, the old transport's `reliable_sent` and
/// [`continue_binding`] of the old handshake hash, as counter 0 of the new transport. The old
/// transport moves into `retiring` and keeps receiving until [`expect_continue_ack`] accepts.
///
/// **Responder.** The old transport's `reliable_received` must equal the peer's `sent`: the
/// item sits behind every old record already queued, so equality is the exact condition "all
/// of them arrived". Otherwise CLOSE `handover_failed` and the end. Else CONTINUE_ACK (`sent` =
/// old `reliable_sent`) is counter 0 of the new transport, sending switches, and the old
/// transport is dropped at once (a late record of it is dropped by the generation check).
#[allow(clippy::too_many_arguments)]
async fn handle_handover(
    handover: Handover,
    transport: &mut E2eTransport,
    retiring: &mut Option<Retiring>,
    current_generation: &mut Generation,
    settled_generation: &AtomicU32,
    liveness: &mut Liveness,
    rekey: &mut RekeySchedule,
    outbound: &mpsc::Sender<OutboundSend>,
    peer: NodeId,
    epoch: Epoch,
    max_record: u32,
    pending_outcomes: &mut FuturesUnordered<
        tokio::time::Timeout<oneshot::Receiver<EnqueueOutcome>>,
    >,
) -> Option<EndReason> {
    let Handover {
        generation,
        transport: mut new,
        role,
    } = handover;
    // Out of order: the next transport is always the next generation, and one cutover at a
    // time (the old transport of the last one is still waiting for its ACK).
    if generation != current_generation.wrapping_add(1) || retiring.is_some() {
        let why = "a handover arrived out of order";
        return Some(fail_handover(transport, outbound, peer, epoch, max_record, why).await);
    }
    let record = match role {
        HandoverRole::Initiator { prior } => ContinueBody {
            prior,
            sent: transport.reliable_sent(),
            binding: continue_binding(transport.handshake_hash()),
        }
        .encode(),
        HandoverRole::Responder { continue_sent } => {
            if transport.reliable_received() != continue_sent {
                let why = "CONTINUE count differs from the records received on the old session";
                return Some(fail_handover(&mut new, outbound, peer, epoch, max_record, why).await);
            }
            ContinueAckBody {
                sent: transport.reliable_sent(),
            }
            .encode()
        }
    };
    let frame = match new.encrypt_raw(&record) {
        Ok(frame) => frame,
        Err(err) => return Some(EndReason::EncryptFailed(err)),
    };
    // The switch: from here on only `new` is ever encrypted on.
    let old = std::mem::replace(transport, new);
    *current_generation = generation;
    *rekey = RekeySchedule::new(clock_now());
    if matches!(role, HandoverRole::Initiator { .. }) {
        *retiring = Some(Retiring {
            generation: generation.wrapping_sub(1),
            transport: old,
            ack_deadline: clock_now() + HANDOVER_ACK_WINDOW,
        });
    } else {
        drop(old);
        settled_generation.store(generation, Ordering::Release);
    }
    enqueue_frame(
        frame,
        false,
        liveness,
        rekey,
        outbound,
        peer,
        epoch,
        None,
        pending_outcomes,
    )
    .await
}

/// Ends a session's channels when its actor future ends or is dropped.
struct CloseChannelsOnDrop(Option<ChannelTable>);

impl Drop for CloseChannelsOnDrop {
    fn drop(&mut self) {
        if let Some(channels) = &self.0 {
            channels.close_all();
        }
    }
}

/// Encrypts one datagram and hands it to `outbound` as an epoch-tagged droppable SEND (flags
/// bit 0, no permit: a datagram is never credited). **Every failure drops the datagram and
/// nothing else**: an encrypt refusal (too large, the counter ceiling, a `snow` error), a full
/// `outbound`, or an `outbound` that is gone. Unlike [`enqueue_send`] the admission outcome is
/// not watched (its receiver is dropped), so a `QueueFull` or `WrongEpoch` from the node's
/// queue cannot end the session either: a gap in the datagram sequence is harmless, and the
/// counter was never a reliable one.
// The same independent inputs as `enqueue_send`.
#[allow(clippy::too_many_arguments)]
fn send_dgram(
    transport: &mut E2eTransport,
    rekey: &mut RekeySchedule,
    outbound: &mpsc::Sender<OutboundSend>,
    peer: NodeId,
    epoch: Epoch,
    channel: u16,
    bytes: &[u8],
) {
    let frame = match transport.encrypt_dgram(channel, bytes) {
        Ok(frame) => frame,
        Err(err) => {
            tracing::debug!(%peer, error = %err, "a datagram was not sent: it did not encrypt");
            return;
        }
    };
    let (outcome, _unwatched) = oneshot::channel();
    let req = OutboundSend {
        dst: peer,
        e2e_proto: E2E_PROTO_TAG,
        flags: DROPPABLE_FLAGS,
        payload: frame.encode(),
        epoch,
        outcome,
        permit: None,
    };
    if outbound.try_send(req).is_ok() {
        // `liveness.note_sent` is NOT called: a datagram is droppable and its outcome is not
        // watched, so a relay that drops every one of them must not silence the KEEP that
        // tells the peer this side is alive (red team round E3, M1).
        rekey.note_sent();
    } else {
        tracing::debug!(%peer, "a datagram was dropped: the send queue is full or gone");
    }
}

/// The actor itself — see this module's own doc comment for the overall
/// shape and why each branch ends the session the way it does.
#[allow(clippy::too_many_arguments)] // assembled once, entirely from `new`; see
// `decide_responder_admission`'s own identical note on why a struct purely to
// dodge this count would be ceremony, not a real grouping, for a private function
// with exactly one call site.
async fn run(
    mut transport: E2eTransport,
    peer: NodeId,
    epoch: Epoch,
    max_record: u32,
    stream_mux: menzil_stream::StreamMux,
    mut outbound_frames: menzil_stream::OutboundFrames,
    driver: menzil_stream::Driver,
    outbound: mpsc::Sender<OutboundSend>,
    send_budget: SendBudget,
    observer: Option<SessionObserver>,
    mut inbound_data_rx: mpsc::UnboundedReceiver<InboundItem>,
    mut command_rx: mpsc::UnboundedReceiver<Command>,
    epoch_ended: oneshot::Receiver<()>,
    ended_tx: oneshot::Sender<EndReason>,
    mut dgram_rx: Option<mpsc::Receiver<DgramOut>>,
    channels: Option<ChannelTable>,
    settled_generation: Arc<AtomicU32>,
) {
    // However this future ends (or is dropped), the channels end with it.
    let _channels_end = CloseChannelsOnDrop(channels.clone());
    let mut first_record_noted = false;
    tokio::pin!(driver);
    tokio::pin!(epoch_ended);
    let now = clock_now();
    let mut liveness = Liveness::new(now);
    let mut rekey = RekeySchedule::new(now);
    let mut clock = tokio::time::interval(CLOCK_TICK);
    let mut pending_outcomes: FuturesUnordered<
        tokio::time::Timeout<oneshot::Receiver<EnqueueOutcome>>,
    > = FuturesUnordered::new();
    // Set once `inbound_data_rx` first reports closed — see this
    // module's own doc comment on why that alone must not end the
    // session the way `command_rx` closing does.
    let mut inbound_closed = false;
    // The one outbound `Mux` frame pulled from `menzil-stream` that is
    // still waiting for send-queue space — see [`Staged`].
    let mut staged: Option<Staged> = None;
    // The transport generation this actor sends and receives on now, and, for an initiator
    // between its switch and the ACK, the old transport kept for receiving (see [`Retiring`]).
    let mut generation_now: Generation = FIRST_GENERATION;
    let mut retiring: Option<Retiring> = None;

    let reason = loop {
        tokio::select! {
            result = &mut driver => {
                break EndReason::DriverEnded(result);
            }

            // Only while nothing is staged: the next frame is not even
            // pulled out of `menzil-stream` until the previous one has
            // its queue space, which is what lets that crate's bounded
            // outbound channel fill up and pause `yamux` — see [`Staged`].
            frame = outbound_frames.next_frame(), if staged.is_none() => {
                let Some(frame) = frame else {
                    // Every `StreamMux` clone dropped — in practice
                    // unreachable while this function still holds its
                    // own (`stream_mux`, kept alive for exactly this
                    // reason), but harmless if it ever did happen: the
                    // `driver` branch above already covers the real end
                    // condition this would otherwise imply.
                    continue;
                };
                staged = Some(Staged::new(frame, &send_budget));
            }

            // The staged frame got its space. Encrypting only now keeps
            // every counter this session assigns attached to a record
            // that is certain to be handed on, in order.
            reserved = async {
                staged.as_mut().expect("guarded by the precondition below").reservation.as_mut().await
            }, if staged.is_some() => {
                let Staged { frame, .. } = staged.take().expect("guarded by the precondition");
                let Ok(permit) = reserved else {
                    // No space for `SEND_OUTCOME_TIMEOUT`: nothing is
                    // draining this node's queue to the peer, the same
                    // dead path every other bound in this module reports.
                    break EndReason::OutboundGone;
                };
                if let Some(reason) = enqueue_send(
                    &mut transport, &mut liveness, &mut rekey, &outbound, peer, epoch,
                    E2eDataBody::Mux(frame), Some(permit), &mut pending_outcomes,
                ).await {
                    break reason;
                }
            }

            outcome = pending_outcomes.next(), if !pending_outcomes.is_empty() => {
                match outcome {
                    Some(Ok(Ok(EnqueueOutcome::Accepted))) => {}
                    Some(Ok(Ok(other))) => break EndReason::SendRefused(other),
                    Some(Ok(Err(_))) => break EndReason::OutboundGone,
                    Some(Err(_)) => break EndReason::OutboundGone,
                    None => unreachable!("this branch only runs while pending_outcomes is non-empty"),
                }
            }

            inbound = inbound_data_rx.recv(), if !inbound_closed => {
                let Some(item) = inbound else {
                    // Unlike `command_rx` below, this alone does not
                    // mean the handle is gone for good — see this
                    // module's own doc comment on why only disabling
                    // this branch, not breaking, is what lets a
                    // `close(Some(reason))` already queued into
                    // `command_rx` right before the handle dropped
                    // still be delivered.
                    inbound_closed = true;
                    continue;
                };
                let (generation, counter, ciphertext, permit) = match item {
                    InboundItem::Record { generation, counter, ciphertext, permit } => {
                        (generation, counter, ciphertext, permit)
                    }
                    InboundItem::Handover(handover) => {
                        if let Some(reason) = handle_handover(
                            *handover, &mut transport, &mut retiring, &mut generation_now,
                            &settled_generation, &mut liveness, &mut rekey, &outbound, peer, epoch, max_record,
                            &mut pending_outcomes,
                        ).await {
                            break reason;
                        }
                        continue;
                    }
                };
                let is_dgram = RecordClass::of_counter(counter) == RecordClass::Datagram;
                // Route by generation: every record is decrypted with the keys of the
                // transport it was sent under, and a record of a transport this actor does
                // not hold is dropped (a datagram counted).
                if generation == generation_now {
                    if let Some(old) = &retiring {
                        // An initiator that switched and waits for CONTINUE_ACK: the first
                        // reliable record on the new transport must be that ACK.
                        match expect_continue_ack(
                            &mut transport, &old.transport, counter, &ciphertext, &mut liveness,
                            &channels,
                        ) {
                            AckStep::Wait => {}
                            AckStep::Done => {
                                retiring = None;
                                settled_generation.store(generation_now, Ordering::Release);
                            }
                            AckStep::PeerEnded(reason) | AckStep::Error(reason) => break reason,
                            AckStep::Fail(why) => {
                                break fail_handover(
                                    &mut transport, &outbound, peer, epoch, max_record, why,
                                ).await;
                            }
                        }
                    } else if let Some(reason) = process_inbound(
                        &mut transport, counter, ciphertext, permit, &mut liveness,
                        &mut first_record_noted, &observer, &stream_mux, &channels,
                    ) {
                        break reason;
                    }
                } else if let Some(old) = retiring.as_mut().filter(|r| r.generation == generation) {
                    // The old transport still receives until the ACK: processed normally,
                    // so its records count toward `reliable_received`.
                    if let Some(reason) = process_inbound(
                        &mut old.transport, counter, ciphertext, permit, &mut liveness,
                        &mut first_record_noted, &observer, &stream_mux, &channels,
                    ) {
                        break reason;
                    }
                } else if is_dgram {
                    // A datagram of a transport not held any more (an old one after the
                    // switch) or not yet (a replacement that is not proved): dropped, counted.
                    note_handover_drop(&channels);
                } else if generation.wrapping_sub(generation_now) < u32::MAX / 2 {
                    // A reliable record of a replacement transport the router has not handed
                    // over yet: a gap that cannot be closed, so the session ends.
                    break fail_handover(
                        &mut transport, &outbound, peer, epoch, max_record,
                        "a record of a transport that was not handed over yet",
                    ).await;
                } else {
                    // A reliable record of a retired transport arriving after the switch
                    // (the peer's old records all came before its ACK or CONTINUE, so only
                    // a misbehaving relay or router produces one): dropped.
                    tracing::debug!(%peer, "a record of a retired transport was dropped");
                }
            }

            out = async {
                dgram_rx.as_mut().expect("guarded by the precondition below").recv().await
            }, if dgram_rx.is_some() => {
                let Some((channel, bytes)) = out else {
                    // Every sender is gone: no channel can send any more.
                    dgram_rx = None;
                    continue;
                };
                send_dgram(
                    &mut transport, &mut rekey, &outbound, peer, epoch, channel, &bytes,
                );
            }

            command = command_rx.recv() => {
                let Some(Command::Close(reason)) = command else {
                    // The authoritative "handle is gone" signal — see
                    // this module's own doc comment. An `mpsc` receiver
                    // only ever reports closed once every item already
                    // queued ahead of that has been yielded, so a
                    // `close(Some(reason))` call that raced the handle's
                    // own drop is guaranteed to have already been
                    // delivered, as its own `Command::Close`, by the
                    // time this arm can ever run.
                    break EndReason::HandleDropped;
                };
                if let Some(close) = &reason {
                    send_close(&mut transport, &outbound, peer, epoch, max_record, close).await;
                }
                break EndReason::ClosedLocally(reason);
            }

            _ = &mut epoch_ended => {
                // A close the owner already asked for outranks the epoch
                // ending. The router closes a session it replaced and
                // drops its entry in one step, which makes this branch and
                // `command` ready together, and `select!` picks among
                // ready branches at random: without this look at the
                // queue, the reason a replaced session reports would be a
                // coin toss.
                if let Ok(Command::Close(reason)) = command_rx.try_recv() {
                    if let Some(close) = &reason {
                        send_close(&mut transport, &outbound, peer, epoch, max_record, close)
                            .await;
                    }
                    break EndReason::ClosedLocally(reason);
                }
                break EndReason::EpochEnded;
            }

            _ = clock.tick() => {
                let now = clock_now();
                if retiring.as_ref().is_some_and(|r| now >= r.ack_deadline) {
                    break fail_handover(
                        &mut transport, &outbound, peer, epoch, max_record,
                        "no CONTINUE_ACK within the liveness window",
                    ).await;
                }
                if liveness.is_dead(now) {
                    break EndReason::PeerDead;
                }
                let due = if rekey.due(now) {
                    Some(E2eDataBody::Rekey)
                } else if liveness.should_send_keep(now) {
                    Some(E2eDataBody::Keep)
                } else {
                    None
                };
                if let Some(body) = due
                    && let Some(reason) = enqueue_send(
                        &mut transport, &mut liveness, &mut rekey, &outbound, peer, epoch, body,
                        None, &mut pending_outcomes,
                    ).await
                {
                    break reason;
                }
            }
        }
    };
    let _ = ended_tx.send(reason);
}

#[cfg(test)]
mod tests {
    use super::*;
    use menzil_e2e::{E2eInitiatorHandshake, E2eResponderHandshake};
    use menzil_proto::{E2eFrame, NodeCert, NodeCertBody, X25519PublicKey};

    fn ik_params() -> snow::params::NoiseParams {
        "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
    }

    fn fresh_keypair() -> ([u8; 32], X25519PublicKey) {
        let kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        let private = <[u8; 32]>::try_from(kp.private).unwrap();
        let public = X25519PublicKey::from(<[u8; 32]>::try_from(kp.public).unwrap());
        (private, public)
    }

    fn sample_cert(node_id: NodeId) -> NodeCert {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id,
            x25519_pub: X25519PublicKey::from([9u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 4_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }

    /// One side's identities and finished transport, plus everything
    /// needed to build an [`L4SessionHandle`]/task pair for it directly
    /// (`outbound_tx`/`epoch_ended_rx` are consumed by [`new`];
    /// `outbound_rx`/`epoch_ended_tx` are the test's own levers on it).
    /// Building both sides this way (rather than only through
    /// [`TwoSessions`]) is what lets a test pick exactly one side's
    /// `max_record`, or skip wiring a peer up entirely.
    struct OneSide {
        transport: E2eTransport,
        peer: NodeId,
        network_id: NetworkId,
        mode: Mode,
    }

    fn two_sides(network_seed: u8, max_record: u32) -> (OneSide, OneSide) {
        two_sides_indexed(network_seed, max_record, 1, 2)
    }

    /// [`two_sides`] with the two sides' own `sender_index` values chosen: a replacement
    /// session between the same two nodes (same `network_seed`) with other indices and other
    /// keys, which is what a re-handshake produces.
    fn two_sides_indexed(
        network_seed: u8,
        max_record: u32,
        a_index: u32,
        b_index: u32,
    ) -> (OneSide, OneSide) {
        let (a_priv, a_pub) = fresh_keypair();
        let (b_priv, b_pub) = fresh_keypair();
        let network_id = NetworkId::from([network_seed; 32]);
        let a_node = NodeId::from([network_seed.wrapping_add(0x10); 32]);
        let b_node = NodeId::from([network_seed.wrapping_add(0x20); 32]);

        let (mut a_hs, init) =
            E2eInitiatorHandshake::start(&a_priv, &b_pub, network_id, a_node, b_node, a_index)
                .unwrap();
        let b_hs = E2eResponderHandshake::start(&b_priv, a_node, b_node, &init).unwrap();
        let (b_transport, resp) = b_hs
            .finish(sample_cert(b_node), 0, 0, vec![], b_index, max_record)
            .unwrap();
        let (a_transport, _payload, _b_static) = a_hs.finish(&resp, max_record).unwrap();
        let _ = a_pub;

        (
            OneSide {
                transport: a_transport,
                peer: b_node,
                network_id,
                mode: Mode::Client,
            },
            OneSide {
                transport: b_transport,
                peer: a_node,
                network_id,
                mode: Mode::Server,
            },
        )
    }

    /// Builds one [`L4SessionHandle`]/[`L4SessionAcceptor`]/task triple
    /// from `side`, returning both halves, the raw `outbound` receiver
    /// (for a test to drain itself, or hand to [`pump`]), and the
    /// `epoch_ended` sender (kept by the caller so the paired receiver
    /// does not immediately disconnect — see [`TwoSessions`]'s own field
    /// doc comment for why that matters).
    fn one_session(
        side: OneSide,
        max_record: u32,
    ) -> (
        L4SessionHandle,
        L4SessionAcceptor,
        mpsc::Receiver<OutboundSend>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let budget = crate::outbound::SendBudgets::new().for_peer(side.peer);
        one_session_with_budget(side, max_record, budget)
    }

    /// [`one_session`], for a test that needs to hold the send budget
    /// itself (to exhaust it, or to watch it being released).
    fn one_session_with_budget(
        side: OneSide,
        max_record: u32,
        send_budget: SendBudget,
    ) -> (
        L4SessionHandle,
        L4SessionAcceptor,
        mpsc::Receiver<OutboundSend>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        one_session_observed(side, max_record, send_budget, None)
    }

    /// [`one_session_with_budget`], for a test that watches the actor's
    /// [`SessionNotice`]s.
    fn one_session_observed(
        side: OneSide,
        max_record: u32,
        send_budget: SendBudget,
        observer: Option<SessionObserver>,
    ) -> (
        L4SessionHandle,
        L4SessionAcceptor,
        mpsc::Receiver<OutboundSend>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (epoch_ended_tx, epoch_ended_rx) = oneshot::channel();
        let (handle, acceptor, task) = new(
            L4SessionConfig {
                transport: side.transport,
                peer: side.peer,
                network_id: side.network_id,
                mode: side.mode,
                max_record,
                epoch: Epoch::first(),
                send_budget,
                observer,
                inbound_budget: L4_INBOUND_BUDGET_PER_SESSION,
                node_inbound: None,
            },
            outbound_tx,
            epoch_ended_rx,
        );
        (
            handle,
            acceptor,
            outbound_rx,
            epoch_ended_tx,
            tokio::spawn(task),
        )
    }

    /// Runs a full live `menzil_e2e` handshake and builds one
    /// [`L4SessionHandle`]/task pair per side, each fed by the *other*
    /// side's own outbound `OutboundSend`s directly — no L3 session, no
    /// relay, exactly the "two sessions, one per side, no table needed"
    /// shape TODO.md's own L4h3 line asks for. `max_record` is generous
    /// (WELCOME's own wire ceiling) unless a test needs otherwise.
    struct TwoSessions {
        a: L4SessionHandle,
        a_acceptor: L4SessionAcceptor,
        b: L4SessionHandle,
        b_acceptor: L4SessionAcceptor,
        // Kept alive so each task's `outbound` channel has a live
        // receiver draining it into the *other* side's inbound feed.
        _pump_a_to_b: tokio::task::JoinHandle<()>,
        _pump_b_to_a: tokio::task::JoinHandle<()>,
        _task_a: tokio::task::JoinHandle<()>,
        _task_b: tokio::task::JoinHandle<()>,
        // Kept alive so the paired `epoch_ended` receiver each actor
        // holds does not immediately observe a disconnect — `run`
        // treats that the same as an explicit epoch-ended notification
        // (see this module's own doc comment on `new`), so a sender
        // dropped this early would end the session before a test ever
        // gets to use it.
        _a_epoch_ended_tx: oneshot::Sender<()>,
        _b_epoch_ended_tx: oneshot::Sender<()>,
    }

    /// Spawns a task that drains `rx` (one side's own `OutboundSend`
    /// stream) and, for each one, decodes the `E2eFrame::Data` it
    /// carries and feeds it straight into `dst`'s inbound side — the
    /// in-process stand-in for "the L3 relay delivered this SEND as a
    /// RECV," skipping L3 entirely. Always resolves the admission
    /// outcome `Accepted`, the same answer a real, healthy
    /// `OutboundQueue` with ample credit would give. Takes `dst` by
    /// value (a cloned [`L4SessionHandle`], cheap since `Clone` is just
    /// cloning its own two channel senders and a `StreamMux`) rather
    /// than borrowing the handle for the pump task's whole lifetime.
    fn pump(
        mut rx: mpsc::Receiver<OutboundSend>,
        dst: L4SessionHandle,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let frame = E2eFrame::decode(&req.payload).expect("this module's own encoding");
                if let E2eFrame::Data {
                    counter,
                    ciphertext,
                    ..
                } = frame
                {
                    dst.feed_inbound(counter, ciphertext)
                        .expect("within the inbound budget");
                }
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        })
    }

    fn two_sessions_with_max_record(max_record: u32) -> TwoSessions {
        let (a_side, b_side) = two_sides(1, max_record);
        let (a_handle, a_acceptor, a_outbound_rx, a_epoch_ended_tx, task_a) =
            one_session(a_side, max_record);
        let (b_handle, b_acceptor, b_outbound_rx, b_epoch_ended_tx, task_b) =
            one_session(b_side, max_record);

        let pump_a_to_b = pump(a_outbound_rx, b_handle.clone());
        let pump_b_to_a = pump(b_outbound_rx, a_handle.clone());

        TwoSessions {
            a: a_handle,
            a_acceptor,
            b: b_handle,
            b_acceptor,
            _pump_a_to_b: pump_a_to_b,
            _pump_b_to_a: pump_b_to_a,
            _task_a: task_a,
            _task_b: task_b,
            _a_epoch_ended_tx: a_epoch_ended_tx,
            _b_epoch_ended_tx: b_epoch_ended_tx,
        }
    }

    /// [`two_sessions_with_max_record`], with an observer on each side.
    fn two_observed_sessions(
        a_observer: Option<SessionObserver>,
        b_observer: Option<SessionObserver>,
    ) -> TwoSessions {
        let max_record = 65_535;
        let (a_side, b_side) = two_sides(1, max_record);
        let budget_for = |side: &OneSide| crate::outbound::SendBudgets::new().for_peer(side.peer);
        let (a_budget, b_budget) = (budget_for(&a_side), budget_for(&b_side));
        let (a_handle, a_acceptor, a_outbound_rx, a_epoch_ended_tx, task_a) =
            one_session_observed(a_side, max_record, a_budget, a_observer);
        let (b_handle, b_acceptor, b_outbound_rx, b_epoch_ended_tx, task_b) =
            one_session_observed(b_side, max_record, b_budget, b_observer);
        let pump_a_to_b = pump(a_outbound_rx, b_handle.clone());
        let pump_b_to_a = pump(b_outbound_rx, a_handle.clone());
        TwoSessions {
            a: a_handle,
            a_acceptor,
            b: b_handle,
            b_acceptor,
            _pump_a_to_b: pump_a_to_b,
            _pump_b_to_a: pump_b_to_a,
            _task_a: task_a,
            _task_b: task_b,
            _a_epoch_ended_tx: a_epoch_ended_tx,
            _b_epoch_ended_tx: b_epoch_ended_tx,
        }
    }

    fn two_sessions() -> TwoSessions {
        two_sessions_with_max_record(65_535)
    }

    #[tokio::test]
    async fn open_stream_on_one_side_is_accepted_on_the_other() {
        use futures_util::io::AsyncWriteExt;
        let mut sessions = two_sessions();
        // `yamux` only actually notifies the peer once something is
        // written to a newly opened stream — a bare `open()` with
        // nothing ever written produces no observable frame on the
        // other side at all, confirmed live (the naive version of this
        // test, calling only `open()`/`accept()`, hung past its own 5s
        // timeout). `accept()` is started *before* `a_side` runs, not
        // after both resolve, so the two can actually make progress
        // concurrently via `tokio::join!` rather than `accept()` only
        // ever being polled once `open()` has already fully finished.
        let a_side = async {
            let mut stream = sessions.a.open_stream().await.unwrap();
            stream.write_all(b"x").await.unwrap();
            stream.flush().await.unwrap();
        };
        let b_side = sessions.b_acceptor.accept();
        let (opened, accepted) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), a_side),
            tokio::time::timeout(Duration::from_secs(5), b_side),
        );
        opened.unwrap();
        assert!(accepted.unwrap().is_some());
    }

    #[tokio::test]
    async fn bytes_written_on_one_sides_stream_arrive_on_the_other() {
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
        let mut sessions = two_sessions();
        // See the previous test's own doc comment on why `accept()`
        // must be started concurrently with, not strictly after, the
        // side that opens and writes.
        let a_side = async {
            let mut stream = sessions.a.open_stream().await.unwrap();
            stream
                .write_all(b"hello over two l4 sessions")
                .await
                .unwrap();
            stream.flush().await.unwrap();
        };
        let b_side = async {
            let mut stream = sessions.b_acceptor.accept().await.unwrap();
            let mut buf = [0u8; 26];
            stream.read_exact(&mut buf).await.unwrap();
            buf
        };
        let (_, buf) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), a_side),
            tokio::time::timeout(Duration::from_secs(5), b_side),
        );
        assert_eq!(&buf.unwrap(), b"hello over two l4 sessions");
    }

    #[tokio::test]
    async fn bulk_transfer_over_many_streams_does_not_end_the_session() {
        // Regression test for a red-team-found High: an earlier version
        // of `enqueue_send` (then `send_data`) awaited each outbound
        // frame's own admission outcome before pulling the next one from
        // `menzil_stream::OutboundFrames`, which alone — no congestion,
        // no credit starvation — was enough to exhaust that crate's own
        // outbound budget (then 256 frames and a hard failure) and end
        // the session under perfectly ordinary bulk transfer; live-reproduced there in well under
        // 100ms across a range of stream counts and sizes. 16 concurrent
        // streams of 1 MiB each is comfortably inside the range that
        // reproduced it every time.
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
        // These bounds exist to catch a hang, not slowness. Moving 16 MiB
        // through two sessions in a debug build (unoptimized crypto, two
        // passes per byte) takes about 9.5 s on a quiet machine, with the
        // code before and after L4h5 alike, so the 10 s each of them used
        // to carry failed under any load at all (found when a full
        // workspace run failed once: HEAD fails this test 3 runs in 5 with
        // a dozen busy-loops running, and the current code 4 in 5).
        const BULK_PATIENCE: Duration = Duration::from_secs(120);
        const STREAMS: usize = 16;
        const BYTES_PER_STREAM: usize = 1024 * 1024;
        let mut sessions = two_sessions();

        let mut writers = Vec::new();
        for _ in 0..STREAMS {
            let mut stream = sessions.a.open_stream().await.unwrap();
            writers.push(tokio::spawn(async move {
                let payload = vec![0xABu8; BYTES_PER_STREAM];
                stream.write_all(&payload).await.unwrap();
                stream.flush().await.unwrap();
            }));
        }

        let mut readers = Vec::new();
        for _ in 0..STREAMS {
            let mut stream = tokio::time::timeout(BULK_PATIENCE, sessions.b_acceptor.accept())
                .await
                .unwrap()
                .unwrap();
            readers.push(tokio::spawn(async move {
                let mut buf = vec![0u8; BYTES_PER_STREAM];
                stream.read_exact(&mut buf).await.unwrap();
                buf
            }));
        }

        for writer in writers {
            tokio::time::timeout(BULK_PATIENCE, writer)
                .await
                .expect("write must not stall")
                .unwrap();
        }
        for reader in readers {
            let buf = tokio::time::timeout(BULK_PATIENCE, reader)
                .await
                .expect("read must not stall")
                .unwrap();
            assert_eq!(buf, vec![0xABu8; BYTES_PER_STREAM]);
        }
    }

    #[tokio::test]
    async fn closing_one_side_with_a_reason_ends_the_other_as_peer_closed() {
        let mut sessions = two_sessions();
        sessions.a.close(Some(CloseReason {
            code: ErrorCode::GrantRemoved,
            msg: "revoked".to_string(),
        }));
        let a_end = tokio::time::timeout(Duration::from_secs(5), sessions.a_acceptor.closed())
            .await
            .unwrap();
        assert!(matches!(a_end.as_ref(), EndReason::ClosedLocally(Some(_))));
        let b_end = tokio::time::timeout(Duration::from_secs(5), sessions.b_acceptor.closed())
            .await
            .unwrap();
        match b_end.as_ref() {
            EndReason::PeerClosed { code, msg } => {
                assert_eq!(*code, ErrorCode::GrantRemoved);
                assert_eq!(msg, "revoked");
            }
            other => panic!("expected PeerClosed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn closing_with_no_reason_sends_nothing_but_still_ends_locally() {
        let mut sessions = two_sessions();
        sessions.a.close(None);
        let a_end = tokio::time::timeout(Duration::from_secs(5), sessions.a_acceptor.closed())
            .await
            .unwrap();
        assert!(matches!(a_end.as_ref(), EndReason::ClosedLocally(None)));
        // `b` never receives a CLOSE and is otherwise perfectly healthy;
        // confirm it has NOT also ended by now (a bounded wait for
        // *something*, not a hang: `open_stream` still completes, and
        // specifically succeeds — a red-team review found an earlier
        // version of this assertion checked only that the *timeout*
        // didn't fire, which is equally true of `Ok(Err(DriverGone))`).
        let still_alive =
            tokio::time::timeout(Duration::from_millis(200), sessions.b.open_stream()).await;
        assert!(
            matches!(still_alive, Ok(Ok(_))),
            "b must not end just because a closed with no reason: {still_alive:?}"
        );
    }

    #[tokio::test]
    async fn closed_is_safe_to_call_repeatedly_from_a_select_loop() {
        // Regression test for a red-team-found Medium: `select! { r =
        // acceptor.closed() => ..., _ = other => {} }` calls `closed()`
        // fresh on every loop iteration (it is not a reused `&mut`
        // binding), so losing even one race against `other` before the
        // session ends used to panic on the very next iteration.
        let mut sessions = two_sessions();
        sessions.a.close(None);
        let mut observed = None;
        let mut ticks = tokio::time::interval(Duration::from_millis(1));
        for _ in 0..50 {
            tokio::select! {
                reason = sessions.a_acceptor.closed() => {
                    observed = Some(reason);
                    break;
                }
                _ = ticks.tick() => {}
            }
        }
        assert!(matches!(
            observed.as_deref(),
            Some(EndReason::ClosedLocally(None))
        ));
        // And a further call still answers the same way rather than
        // panicking.
        let again = sessions.a_acceptor.closed().await;
        assert!(matches!(again.as_ref(), EndReason::ClosedLocally(None)));
    }

    #[tokio::test]
    async fn dropping_the_handle_ends_the_session_immediately() {
        // Regression test for a red-team-found Medium: an earlier
        // version `continue`d on a closed inbound/command channel,
        // spinning (a live-measured ~60x throughput hit to a sibling
        // task on the same runtime) until `Liveness::is_dead` finally
        // fired, tens of seconds later, rather than ending immediately.
        // Keeps the acceptor (a round-2 red-team review noted the
        // handle/acceptor split, absent when this test was first
        // written, now lets it assert the exact reason too, not only
        // the prompt bound).
        let (a_side, _b_side) = two_sides(5, 65_535);
        let (handle, mut acceptor, _outbound_rx, _epoch_ended_tx, task) =
            one_session(a_side, 65_535);
        drop(handle);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("must end promptly, not drift into a later ~40s PeerDead wait")
            .unwrap();
        let reason = acceptor.closed().await;
        assert!(matches!(reason.as_ref(), EndReason::HandleDropped));
    }

    #[tokio::test]
    async fn an_unauthenticated_frame_does_not_refresh_liveness() {
        // Regression test for a red-team-found Medium, and a real
        // security-relevant one: an earlier version called
        // `Liveness::note_received` unconditionally after the whole
        // inbound `match`, including the arm that drops a frame that
        // never authenticated at all — letting anyone able to deliver
        // frames to this session's receiver index (the relay included,
        // per decision 0001) defeat dead-peer detection indefinitely
        // with one garbage frame a second. This test cannot wait out the
        // full ~40s `Liveness::DEAD_AFTER` window (menzil-e2e has no
        // time-mocking hook to shorten it), so it instead pins the
        // *mechanism*: a frame that fails to authenticate must not reach
        // `decrypt_data`'s `Ok` arm, which is the only place `run` now
        // calls `note_received` at all. Feeding a frame whose `counter`
        // never matches the real cipher state (so it cannot possibly
        // decrypt) and confirming the session is still healthy
        // afterward — not ended by `Decrypt`, which a genuinely
        // authenticated-but-out-of-sequence frame *would* trigger —
        // demonstrates the frame was correctly dropped pre-auth rather
        // than silently accepted. The full dead-peer timing itself is
        // covered by `menzil_e2e::liveness`'s own unit tests and was
        // independently confirmed live by this item's own red-team
        // review (two separate runs, ~40.0s each).
        let mut sessions = two_sessions();
        sessions
            .a
            .feed_inbound(999, vec![0xffu8; 32])
            .expect("within the inbound budget");
        // If that frame had wrongly been treated as authenticated (or
        // worse, actually ended the session), the next real traffic
        // would fail; it does not.
        let a_side = async {
            let mut stream = sessions.a.open_stream().await.unwrap();
            use futures_util::io::AsyncWriteExt;
            stream.write_all(b"still alive").await.unwrap();
            stream.flush().await.unwrap();
        };
        let b_side = sessions.b_acceptor.accept();
        let (opened, accepted) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(5), a_side),
            tokio::time::timeout(Duration::from_secs(5), b_side),
        );
        opened.unwrap();
        assert!(accepted.unwrap().is_some());
    }

    #[tokio::test]
    async fn a_refused_send_ends_the_session_as_send_refused() {
        let (a_side, _b_side) = two_sides(6, 65_535);
        let (_handle, mut acceptor, mut outbound_rx, _epoch_ended_tx, task) =
            one_session(a_side, 65_535);
        // Answer the very first send (yamux's own initial frame, see
        // this module's own doc comment) with an explicit refusal rather
        // than `Accepted`; the receiver then drops (the spawned task
        // ending), so nothing else this session might still send blocks
        // on a full channel instead of also failing promptly.
        let _refuse = tokio::spawn(async move {
            if let Some(req) = outbound_rx.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::QueueFull);
            }
        });
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("must not hang")
            .unwrap();
        let observed = acceptor.closed().await;
        assert!(matches!(
            observed.as_ref(),
            EndReason::SendRefused(EnqueueOutcome::QueueFull)
        ));
    }

    #[tokio::test]
    async fn closing_with_a_reason_then_dropping_the_handle_still_delivers_the_close() {
        // Regression test for a round-2-found Medium: the `HandleDropped`
        // fix's first version broke as soon as `inbound_data_rx` alone
        // reported closed, racing ahead of `command_rx`'s own
        // already-queued `Close` roughly 4 times out of 5 (confirmed
        // live by that review: 243/300 lost). `TwoSessions` cannot
        // reproduce this at all: each side's pump holds its own clone
        // of the *other* side's `inbound_data_tx`, so `inbound_data_rx`
        // never actually closes just because one side's own handle
        // drops. This test instead builds one side directly via
        // `one_session`, where nothing else holds a clone of anything
        // the handle owns, so dropping it closes both `inbound_data_rx`
        // and `command_rx` at once — the shape the bug actually needed.
        // Run repeatedly (not just once) since the bug was probabilistic.
        for _ in 0..30 {
            let (a_side, b_side) = two_sides(9, 65_535);
            let mut b_transport = b_side.transport;
            let (handle, _acceptor, mut outbound_rx, _epoch_ended_tx, task) =
                one_session(a_side, 65_535);
            handle.close(Some(CloseReason {
                code: ErrorCode::GrantRemoved,
                msg: "bye".to_string(),
            }));
            drop(handle);

            let close_seen = tokio::time::timeout(Duration::from_secs(2), async {
                while let Some(req) = outbound_rx.recv().await {
                    let frame = E2eFrame::decode(&req.payload).unwrap();
                    let _ = req.outcome.send(EnqueueOutcome::Accepted);
                    if let E2eFrame::Data {
                        counter,
                        ciphertext,
                        ..
                    } = frame
                        && let Ok(E2eDataBody::Close { .. }) =
                            b_transport.decrypt_data(counter, &ciphertext)
                    {
                        return true;
                    }
                }
                false
            })
            .await
            .expect("must not hang");
            assert!(
                close_seen,
                "the queued CLOSE must still be delivered even though the handle dropped \
                 immediately after close()"
            );
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn an_unresolved_outcome_ends_the_session_via_timeout() {
        // Regression test for a round-2-found Low: decoupling the
        // outcome wait from the send itself (point H1) had silently
        // dropped the bound on the wait entirely — confirmed live by
        // that review (held, never-answered outcomes left the session
        // running past 50s, where the pre-H1-fix code would have ended
        // at 35s). This test cannot wait out the real 35s
        // `SEND_OUTCOME_TIMEOUT` (no time-mocking hook exists for
        // `menzil_e2e::Liveness` either, see this module's own liveness
        // test for the identical constraint), so it uses
        // `tokio::time::pause`/`advance` instead: virtual time, not
        // wall-clock time, satisfies the bound.
        tokio::time::pause();
        let (a_side, _b_side) = two_sides(11, 65_535);
        let (handle, _acceptor, mut outbound_rx, _epoch_ended_tx, task) =
            one_session(a_side, 65_535);
        // Accept every send into the channel (so each one's own
        // `outbound.send` succeeds) but never resolve any outcome —
        // `yamux::Connection::new`'s own initial frame (see this
        // module's own doc comment) is enough to exercise this without
        // this test needing to open a stream itself.
        let _hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Some(req) = outbound_rx.recv().await {
                held.push(req);
            }
            held
        });
        // Advance in small steps, yielding between each, rather than one
        // large jump: a single `advance(SEND_OUTCOME_TIMEOUT + 1s)` did
        // not reliably drive the freshly spawned `task` far enough
        // along to reach the point of actually registering its own
        // timer before the jump — confirmed live by tracing `task.
        // is_finished()` at each step. Stepping (and explicitly
        // yielding first, so `task` gets to run under real scheduling
        // before virtual time moves again) is the reliable pattern.
        let deadline = SEND_OUTCOME_TIMEOUT + Duration::from_secs(1);
        let step = Duration::from_millis(500);
        let mut elapsed = Duration::ZERO;
        while elapsed < deadline && !task.is_finished() {
            tokio::task::yield_now().await;
            tokio::time::advance(step).await;
            elapsed += step;
        }
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("must not hang once virtual time has passed SEND_OUTCOME_TIMEOUT")
            .unwrap();
        let _ = handle;
    }

    #[tokio::test]
    async fn a_contiguity_violation_ends_the_session_as_decrypt() {
        // Drives the initiator's raw `E2eTransport` directly (bypassing
        // its own actor entirely — only the responder runs as one),
        // encrypting two real records and feeding the responder's actor
        // the *second* one first: genuinely authenticated (real cipher,
        // real nonce), but out of sequence.
        let (a_side, b_side) = two_sides(7, 65_535);
        let mut a_transport = a_side.transport;
        let (handle, mut acceptor, mut outbound_rx, _epoch_ended_tx, task) =
            one_session(b_side, 65_535);
        let _drain = tokio::spawn(async move {
            while let Some(req) = outbound_rx.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        });

        let _frame0 = a_transport.encrypt_data(&E2eDataBody::Keep).unwrap();
        let frame1 = a_transport.encrypt_data(&E2eDataBody::Keep).unwrap();
        let menzil_proto::E2eFrame::Data {
            counter: c1,
            ciphertext: ct1,
            ..
        } = frame1
        else {
            unreachable!()
        };
        handle
            .feed_inbound(c1, ct1)
            .expect("within the inbound budget");

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("must not hang")
            .unwrap();
        let reason = acceptor.closed().await;
        assert!(
            matches!(
                reason.as_ref(),
                EndReason::Decrypt(E2eError::ReliableContiguityViolation {
                    expected: 0,
                    actual: 1
                })
            ),
            "expected a contiguity violation (0 expected, 1 actual), got {reason:?}"
        );
    }

    #[tokio::test]
    async fn an_oversized_body_ends_the_session_as_encrypt_failed() {
        // At a `max_record` this small, even yamux's own first,
        // automatic outbound frame cannot fit this session's plaintext
        // budget.
        let (a_side, _b_side) = two_sides(8, 90);
        let (_handle, _acceptor, mut outbound_rx, _epoch_ended_tx, task) = one_session(a_side, 90);
        let _drain = tokio::spawn(async move {
            while let Some(req) = outbound_rx.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        });
        let reason = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap();
        reason.unwrap();
    }

    // `EndReason::DriverEnded`'s own two paths (`Ok(())` via a peer
    // `GoAway`, `Err(TooManyStreams)` via a 513th stream) are not
    // reproducible through this module's own public API without
    // reaching into `menzil_stream` internals this crate deliberately
    // does not expose (no "send a GoAway" or "open past the stream cap"
    // method exists above the raw `Stream`/`StreamMux` level). Both were
    // verified live by this item's own red-team review, which found no
    // bug in either path; `menzil-stream`'s own test suite separately
    // covers `Driver`'s two resolutions directly.

    #[tokio::test]
    async fn reliable_send_failure_ends_the_session_as_outbound_gone() {
        let (a_side, _b_side) = two_sides(4, 65_535);
        let (handle, mut acceptor, outbound_rx, _epoch_ended_tx, task) =
            one_session(a_side, 65_535);
        drop(outbound_rx);

        // Opening a stream makes yamux itself produce an outbound Mux
        // frame, which this session tries (and, with no receiver left on
        // `outbound`, fails) to send.
        let _ = handle.open_stream().await;
        let reason = tokio::time::timeout(Duration::from_secs(5), acceptor.closed())
            .await
            .unwrap();
        assert!(matches!(reason.as_ref(), EndReason::OutboundGone));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn the_epoch_ending_ends_the_session() {
        let (a_side, _b_side) = two_sides(2, 65_535);
        let (_handle, mut acceptor, mut outbound_rx, epoch_ended_tx, task) =
            one_session(a_side, 65_535);
        // `yamux::Connection::new` produces an initial outbound frame of
        // its own (confirmed live, tracing which `select!` branch fired
        // on a failing run of this exact test) — this session's own
        // `run` loop processes it inline through `enqueue_send`'s own
        // bounded send. With nothing draining `outbound` at all (as the
        // first version of this test did), that send runs to its own
        // [`SEND_OUTCOME_TIMEOUT`] before `run` ever gets back to
        // noticing `epoch_ended` — not unbounded, but comfortably past
        // this test's own 5s budget. A background drain, exactly what a
        // real `run_session` always provides, is what this test needs
        // instead of a tighter deadline on the session itself.
        let _drain = tokio::spawn(async move {
            while let Some(req) = outbound_rx.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        });

        let _ = epoch_ended_tx.send(());
        let reason = tokio::time::timeout(Duration::from_secs(5), acceptor.closed())
            .await
            .unwrap();
        assert!(matches!(reason.as_ref(), EndReason::EpochEnded));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_close_already_queued_when_the_epoch_ends_is_the_reason() {
        // The router closes a session it replaced and drops its entry, the
        // epoch sender with it, in one step, so the actor finds `command`
        // and `epoch_ended` ready together and `select!` picks between them
        // at random. One run proves little (the old behaviour reported
        // `EpochEnded` about one time in eight); sixty-four make a
        // regression a near certain failure.
        for round in 0..64 {
            let (a_side, _b_side) = two_sides(3, 65_535);
            let (handle, mut acceptor, mut outbound_rx, epoch_ended_tx, task) =
                one_session(a_side, 65_535);
            let _drain = tokio::spawn(async move {
                while let Some(req) = outbound_rx.recv().await {
                    let _ = req.outcome.send(EnqueueOutcome::Accepted);
                }
            });
            // No await between the two: the actor sees them together.
            handle.close(None);
            drop(epoch_ended_tx);
            let reason = tokio::time::timeout(Duration::from_secs(5), acceptor.closed())
                .await
                .unwrap();
            assert!(
                matches!(reason.as_ref(), EndReason::ClosedLocally(None)),
                "round {round}: {reason:?}"
            );
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_close_with_a_reason_still_reaches_the_peer_when_the_epoch_ends_with_it() {
        for round in 0..32 {
            let mut sessions = two_sessions();
            sessions.a.close(Some(CloseReason {
                code: ErrorCode::GrantRemoved,
                msg: "revoked".to_string(),
            }));
            drop(sessions._a_epoch_ended_tx);
            let a_end = tokio::time::timeout(Duration::from_secs(5), sessions.a_acceptor.closed())
                .await
                .unwrap();
            assert!(
                matches!(a_end.as_ref(), EndReason::ClosedLocally(Some(_))),
                "round {round}: {a_end:?}"
            );
            let b_end = tokio::time::timeout(Duration::from_secs(5), sessions.b_acceptor.closed())
                .await
                .expect("the CLOSE must still be sent");
            match b_end.as_ref() {
                EndReason::PeerClosed { code, msg } => {
                    assert_eq!(*code, ErrorCode::GrantRemoved, "round {round}");
                    assert_eq!(msg, "revoked", "round {round}");
                }
                other => panic!("round {round}: expected PeerClosed, got {other:?}"),
            }
        }
    }

    // --- TODO.md L4h5: the send budget -----------------------------------

    /// A [`SendBudget`] for `peer` whose whole per-destination allowance
    /// is held by the returned permit: until that is dropped, nothing can
    /// reserve any queue space through (any clone of) the budget.
    async fn exhausted_budget(peer: NodeId) -> (SendBudget, SendPermit) {
        let budget = crate::outbound::SendBudgets::new().for_peer(peer);
        let hog = budget
            .acquire(crate::outbound::L4_SEND_BUDGET_PER_DST)
            .await;
        (budget, hog)
    }

    #[tokio::test]
    async fn an_exhausted_send_budget_holds_frames_back_but_the_session_stays_responsive() {
        // `yamux::Connection::new` produces a frame of its own the moment
        // the session starts (see this module's own doc comment), so the
        // very first frame is already waiting for queue space here — no
        // stream needs opening.
        let (a_side, _b_side) = two_sides(20, 65_535);
        let (budget, hog) = exhausted_budget(a_side.peer).await;
        let (handle, mut acceptor, mut outbound_rx, _epoch_ended_tx, task) =
            one_session_with_budget(a_side, 65_535, budget);

        assert!(
            tokio::time::timeout(Duration::from_millis(300), outbound_rx.recv())
                .await
                .is_err(),
            "a frame must not be encrypted and sent while it has no queue space"
        );

        // The wait must not leave the actor deaf: a `close()` issued
        // while a frame is staged still ends the session promptly.
        handle.close(None);
        let reason = tokio::time::timeout(Duration::from_secs(5), acceptor.closed())
            .await
            .expect("a staged frame must not stop the actor noticing a close()");
        assert!(matches!(reason.as_ref(), EndReason::ClosedLocally(None)));
        drop(hog);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("must not hang")
            .unwrap();
    }

    #[tokio::test]
    async fn freeing_queue_space_lets_the_held_back_frame_through_with_its_reservation() {
        let (a_side, _b_side) = two_sides(21, 65_535);
        let (budget, hog) = exhausted_budget(a_side.peer).await;
        let (_handle, _acceptor, mut outbound_rx, _epoch_ended_tx, _task) =
            one_session_with_budget(a_side, 65_535, budget);

        assert!(
            tokio::time::timeout(Duration::from_millis(200), outbound_rx.recv())
                .await
                .is_err()
        );
        drop(hog);

        let req = tokio::time::timeout(Duration::from_secs(5), outbound_rx.recv())
            .await
            .expect("the frame must go out once space is free")
            .expect("the channel is still open");
        let permit = req
            .permit
            .as_ref()
            .expect("a Mux frame must travel with the queue space it reserved");
        assert!(
            permit.bytes() >= req.payload.len().max(MIN_SEND_CHARGE_BYTES as usize),
            "the reservation must cover what the queue will charge ({} < {})",
            permit.bytes(),
            req.payload.len()
        );
    }

    #[tokio::test]
    async fn a_reservation_that_never_comes_ends_the_session_as_outbound_gone() {
        // Nothing frees queue space for `SEND_OUTCOME_TIMEOUT`: the same
        // dead path every other bound in this module reports. Virtual
        // time, stepped the same way and for the same reason as
        // `an_unresolved_outcome_ends_the_session_via_timeout`.
        tokio::time::pause();
        let (a_side, _b_side) = two_sides(22, 65_535);
        let (budget, _hog) = exhausted_budget(a_side.peer).await;
        let (_handle, mut acceptor, _outbound_rx, _epoch_ended_tx, task) =
            one_session_with_budget(a_side, 65_535, budget);

        let deadline = SEND_OUTCOME_TIMEOUT + Duration::from_secs(1);
        let step = Duration::from_millis(500);
        let mut elapsed = Duration::ZERO;
        while elapsed < deadline && !task.is_finished() {
            tokio::task::yield_now().await;
            tokio::time::advance(step).await;
            elapsed += step;
        }
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("must not hang once virtual time has passed SEND_OUTCOME_TIMEOUT")
            .unwrap();
        let reason = acceptor.closed().await;
        assert!(matches!(reason.as_ref(), EndReason::OutboundGone));
    }

    #[tokio::test]
    async fn queue_space_is_given_back_when_the_consumer_drops_the_send() {
        // The budget must not leak: a send that is dropped (the queue
        // sent it, refused it, or was torn down with its L3 session) frees
        // exactly what it reserved.
        let (a_side, _b_side) = two_sides(23, 65_535);
        let peer = a_side.peer;
        let budgets = crate::outbound::SendBudgets::new();
        let (_handle, _acceptor, mut outbound_rx, _epoch_ended_tx, _task) =
            one_session_with_budget(a_side, 65_535, budgets.for_peer(peer));

        let req = tokio::time::timeout(Duration::from_secs(5), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let held = req.permit.as_ref().unwrap().bytes();
        assert!(held > 0);
        // While the send is alive its reservation is taken...
        let remaining = crate::outbound::L4_SEND_BUDGET_PER_DST - held;
        let probe = budgets.for_peer(peer);
        let _fits = tokio::time::timeout(Duration::from_millis(200), probe.acquire(remaining))
            .await
            .expect("everything but the reservation is still free");
        assert!(
            tokio::time::timeout(Duration::from_millis(200), probe.acquire(held))
                .await
                .is_err(),
            "the reservation must still be held while the send is alive"
        );
        // ...and gone with it.
        drop(req);
        drop(_fits);
        tokio::time::timeout(
            Duration::from_secs(5),
            probe.acquire(crate::outbound::L4_SEND_BUDGET_PER_DST),
        )
        .await
        .expect("dropping the send must give its whole reservation back");
    }
    // --- TODO.md L4h6: SessionObserver notices -----------------------------

    #[tokio::test]
    async fn the_first_authenticated_record_is_reported_once() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut sessions = two_observed_sessions(None, Some(SessionObserver::new(tx, 77)));

        // `yamux` sends a frame of its own the moment a session starts, so
        // B's first record arrives without anyone opening a stream.
        let first = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("B must see A's first record")
            .unwrap();
        assert_eq!(first, (77, SessionNotice::FirstRecord));

        // Real traffic afterwards must not repeat it.
        let mut stream = sessions.a.open_stream().await.unwrap();
        futures_util::io::AsyncWriteExt::write_all(&mut stream, b"hello")
            .await
            .unwrap();
        let _accepted = tokio::time::timeout(Duration::from_secs(5), sessions.b_acceptor.accept())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        while let Ok((tag, notice)) = rx.try_recv() {
            assert_eq!(tag, 77);
            assert_ne!(notice, SessionNotice::FirstRecord, "reported twice");
        }
    }

    #[tokio::test]
    async fn the_end_of_a_session_is_reported_last() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sessions = two_observed_sessions(Some(SessionObserver::new(tx, 5)), None);
        sessions.a.close(None);
        let mut notices = Vec::new();
        loop {
            let (tag, notice) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("a closed session must report that it ended")
                .expect("the actor holds the sender until it is done");
            assert_eq!(tag, 5);
            notices.push(notice);
            if notice == SessionNotice::Ended {
                break;
            }
        }
        // Nothing follows `Ended`: the actor's sender is gone with it.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .map(|n| n.is_none())
                .unwrap_or(false)
        );
        assert_eq!(notices.last(), Some(&SessionNotice::Ended));
    }

    // --- TODO.md L4h6b: the inbound budget -------------------------------

    fn yamux_ping(nonce: u32) -> Vec<u8> {
        // A SYN-flagged Ping on stream id 0: `yamux` answers with an ACK.
        let mut frame = vec![0u8, 2, 0, 1, 0, 0, 0, 0];
        frame.extend_from_slice(&nonce.to_be_bytes());
        frame
    }

    /// A session built by [`new`] directly, whose actor is never polled:
    /// the consumer that sleeps. Everything fed to its handle just queues.
    fn sleeping_session(
        seed: u8,
        inbound_budget: usize,
    ) -> (
        L4SessionHandle,
        impl Future<Output = ()> + Send + 'static,
        mpsc::Receiver<OutboundSend>,
        oneshot::Sender<()>,
    ) {
        sleeping_session_on(seed, inbound_budget, None)
    }

    /// [`sleeping_session`] counted in a node wide counter.
    fn sleeping_session_on(
        seed: u8,
        inbound_budget: usize,
        node_inbound: Option<Arc<NodeInbound>>,
    ) -> (
        L4SessionHandle,
        impl Future<Output = ()> + Send + 'static,
        mpsc::Receiver<OutboundSend>,
        oneshot::Sender<()>,
    ) {
        let (_a_side, b_side) = two_sides(seed, 65_535);
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (epoch_tx, epoch_rx) = oneshot::channel();
        let (handle, _acceptor, task) = new(
            L4SessionConfig {
                transport: b_side.transport,
                peer: b_side.peer,
                network_id: b_side.network_id,
                mode: b_side.mode,
                max_record: 65_535,
                epoch: Epoch::first(),
                send_budget: crate::outbound::SendBudgets::new().for_peer(b_side.peer),
                observer: None,
                inbound_budget,
                node_inbound,
            },
            outbound_tx,
            epoch_rx,
        );
        (handle, task, outbound_rx, epoch_tx)
    }

    #[tokio::test]
    async fn a_sleeping_consumer_cannot_make_the_handle_hold_more_than_the_budget() {
        // Before TODO.md L4h6b, 10,000 records of 16 KiB fed to a session
        // whose actor was not running grew the process by 156 MiB (measured
        // in this module's debug build): the channel was unbounded. Now the
        // handle stops taking records at the budget, whatever the consumer
        // does.
        const BUDGET: usize = 1024 * 1024;
        const RECORD: usize = 16 * 1024;
        let (handle, task, _outbound_rx, _epoch_tx) = sleeping_session(30, BUDGET);

        let charge = RECORD + INBOUND_RECORD_OVERHEAD;
        let fits = BUDGET / charge;
        let mut accepted = 0usize;
        let mut refused = None;
        for counter in 0..10_000u64 {
            match handle.feed_inbound(counter, vec![0xAB; RECORD]) {
                Ok(()) => accepted += 1,
                Err(error) => {
                    refused = Some(error);
                    break;
                }
            }
        }

        assert_eq!(accepted, fits, "exactly what fits in {BUDGET} bytes");
        assert_eq!(
            refused,
            Some(FeedRefused::Session(InboundOverflow { budget: BUDGET }))
        );
        assert_eq!(handle.inbound_in_use(), fits * charge);
        // Still refused while nothing is consumed, and nothing is added.
        assert!(handle.feed_inbound(fits as u64, vec![0u8; RECORD]).is_err());
        assert_eq!(handle.inbound_in_use(), fits * charge);

        // The charge is given back when the records are: dropping the
        // actor drops the queue they wait in.
        drop(task);
        assert_eq!(handle.inbound_in_use(), 0);
        // And the handle works again as far as the budget goes (the actor
        // is gone, so the record is simply dropped).
        assert!(handle.feed_inbound(0, vec![0u8; RECORD]).is_ok());
        assert_eq!(handle.inbound_in_use(), 0);
    }

    #[tokio::test]
    async fn a_record_is_charged_for_its_overhead_not_only_its_payload() {
        // A flood of tiny records must hit the budget in proportion to the
        // memory they take, not to their payload: a Ping is 29 bytes.
        const BUDGET: usize = 1024 * 1024;
        let (handle, _task, _outbound_rx, _epoch_tx) = sleeping_session(32, BUDGET);

        let mut accepted = 0usize;
        while handle.feed_inbound(accepted as u64, vec![0u8; 29]).is_ok() {
            accepted += 1;
            assert!(accepted < 100_000, "never refused");
        }

        assert_eq!(accepted, BUDGET / (29 + INBOUND_RECORD_OVERHEAD));
        assert!(accepted < BUDGET / 29 / 2, "charged by payload alone");
    }

    #[tokio::test]
    async fn the_budget_is_never_smaller_than_two_records() {
        // A budget asked for below what two maximum-size records need would
        // refuse a record the wire allows: it is raised.
        let (handle, _task, _outbound_rx, _epoch_tx) = sleeping_session(33, 1);

        assert!(handle.feed_inbound(0, vec![0u8; 65_000]).is_ok());
        assert!(handle.feed_inbound(1, vec![0u8; 65_000]).is_ok());
    }

    #[tokio::test]
    async fn what_yamux_has_read_is_given_back_and_a_working_session_stays_at_zero() {
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
        let mut sessions = two_sessions();
        let mut opened = sessions.a.open_stream().await.unwrap();
        let payload = vec![7u8; 600 * 1024];
        let writer = tokio::spawn(async move {
            opened.write_all(&payload).await.unwrap();
            opened.flush().await.unwrap();
            opened
        });
        let mut accepted =
            tokio::time::timeout(Duration::from_secs(10), sessions.b_acceptor.accept())
                .await
                .unwrap()
                .unwrap();
        let mut received = vec![0u8; 600 * 1024];
        tokio::time::timeout(Duration::from_secs(10), accepted.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        let _opened = writer.await.unwrap();

        // Everything delivered, nothing left charged on either side.
        for _ in 0..500 {
            if sessions.a.inbound_in_use() == 0 && sessions.b.inbound_in_use() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "still charged after the transfer: a {} b {}",
            sessions.a.inbound_in_use(),
            sessions.b.inbound_in_use()
        );
    }

    #[tokio::test]
    async fn a_record_that_fills_the_budget_exactly_is_accepted() {
        // The boundary: a ceiling is a number of bytes that may be held, so
        // the record that brings the total to it fits and the next does not.
        const BUDGET: usize = 1024 * 1024;
        const CHARGE: usize = 16 * 1024;
        let (handle, _task, _outbound_rx, _epoch_tx) = sleeping_session(35, BUDGET);

        let record = vec![0u8; CHARGE - INBOUND_RECORD_OVERHEAD];
        for counter in 0..(BUDGET / CHARGE) as u64 {
            assert!(
                handle.feed_inbound(counter, record.clone()).is_ok(),
                "record {counter} must fit"
            );
        }
        assert_eq!(handle.inbound_in_use(), BUDGET);
        assert!(handle.feed_inbound(9999, vec![]).is_err());
    }

    #[tokio::test]
    async fn the_budget_covers_the_whole_window_grant_in_full_size_frames() {
        // The reason the ceiling is where it is (L4h6b review, finding 1): a
        // peer that respects the receive windows may have all of them in
        // flight while our `yamux` is not reading. Full-size frames are
        // charged their payload plus a yamux header, the kind byte, the
        // Noise tag and the allowance; down to 4 KiB frames the whole grant
        // still fits.
        for frame_payload in [16 * 1024usize, 8 * 1024, 4 * 1024] {
            let frames = RECEIVE_WINDOW_GRANT.div_ceil(frame_payload);
            let charged = frames * (frame_payload + 12 + 1 + 16 + INBOUND_RECORD_OVERHEAD);
            assert!(
                charged <= L4_INBOUND_BUDGET_PER_SESSION,
                "{frame_payload}-byte frames: the grant charges {charged}, the budget is {L4_INBOUND_BUDGET_PER_SESSION}"
            );
        }
    }

    #[tokio::test]
    async fn the_relay_cannot_raise_the_budget_through_max_record() {
        // WELCOME's `max_record` comes from the relay and nothing validates
        // it. The floor of two records is sized from at most Noise's limit,
        // so a huge value neither lifts the ceiling nor overflows the sum.
        for max_record in [u32::MAX, 1 << 30] {
            let (_a_side, b_side) = two_sides(36, 65_535);
            let (outbound_tx, _outbound_rx) = mpsc::channel(64);
            let (_epoch_tx, epoch_rx) = oneshot::channel();
            let (small, _acceptor, _task) = new(
                L4SessionConfig {
                    transport: b_side.transport,
                    peer: b_side.peer,
                    network_id: b_side.network_id,
                    mode: b_side.mode,
                    max_record,
                    epoch: Epoch::first(),
                    send_budget: crate::outbound::SendBudgets::new().for_peer(b_side.peer),
                    observer: None,
                    inbound_budget: 1,
                    node_inbound: None,
                },
                outbound_tx,
                epoch_rx,
            );
            assert_eq!(
                small.inbound_budget(),
                2 * (65_535 + INBOUND_RECORD_OVERHEAD),
                "max_record {max_record}"
            );
        }
    }

    /// Settles (briefly, in real time) until the session holds nothing.
    async fn drains_to_zero(handle: &L4SessionHandle) -> bool {
        for _ in 0..500 {
            if handle.inbound_in_use() == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.inbound_in_use() == 0
    }

    #[tokio::test]
    async fn every_kind_of_record_gives_its_charge_back() {
        // A charge that is not given back is a budget that fills for good: a
        // relay could do that with junk. Each way a record can end must
        // release it: KEEP, REKEY and a Mux frame yamux reads, a frame that
        // does not decrypt, and a datagram-class counter.
        let (a_side, b_side) = two_sides(37, 65_535);
        let mut peer = a_side.transport;
        let (handle, _acceptor, mut outbound_rx, _epoch_tx, _task) = one_session(b_side, 65_535);
        // Something must take what the session sends, or it stalls.
        tokio::spawn(async move {
            while let Some(request) = outbound_rx.recv().await {
                let _ = request.outcome.send(EnqueueOutcome::Accepted);
            }
        });
        let feed = |body: E2eDataBody, peer: &mut E2eTransport| {
            let E2eFrame::Data {
                counter,
                ciphertext,
                ..
            } = peer.encrypt_data(&body).unwrap()
            else {
                unreachable!()
            };
            handle.feed_inbound(counter, ciphertext).unwrap();
        };

        feed(E2eDataBody::Keep, &mut peer);
        assert!(drains_to_zero(&handle).await, "KEEP kept its charge");

        // Not the next counter, and not authentic: dropped with its charge,
        // and the session goes on.
        handle.feed_inbound(1, vec![0xAB; 64]).unwrap();
        assert!(
            drains_to_zero(&handle).await,
            "a junk frame kept its charge"
        );
        handle.feed_inbound(1 << 63, vec![0xAB; 64]).unwrap();
        assert!(
            drains_to_zero(&handle).await,
            "a datagram-class frame kept its charge"
        );

        feed(E2eDataBody::Rekey, &mut peer);
        assert!(drains_to_zero(&handle).await, "REKEY kept its charge");

        feed(E2eDataBody::Mux(yamux_ping(7)), &mut peer);
        assert!(drains_to_zero(&handle).await, "a Mux frame kept its charge");
    }

    #[tokio::test]
    async fn a_ping_flood_at_a_paused_yamux_is_cut_off_at_the_budget() {
        // The L4h5 review's scenario, end to end through the actor: the
        // peer authenticates fine and sends bare yamux Pings, and nothing
        // we send can leave (the send budget is held), so `yamux` stops
        // reading after a few dozen Pings and the rest wait unread. Before
        // TODO.md L4h6b nothing bounded that: 200,000 Pings grew the
        // process by 15 MiB with no plateau, until the 35 s reservation
        // timeout ended the session.
        const BUDGET: usize = 512 * 1024;
        let (a_side, b_side) = two_sides(31, 65_535);
        let mut attacker = a_side.transport;
        let (send_budget, _hog) = exhausted_budget(b_side.peer).await;
        let (outbound_tx, _outbound_rx) = mpsc::channel(64);
        let (_epoch_tx, epoch_rx) = oneshot::channel();
        let (handle, mut acceptor, task) = new(
            L4SessionConfig {
                transport: b_side.transport,
                peer: b_side.peer,
                network_id: b_side.network_id,
                mode: b_side.mode,
                max_record: 65_535,
                epoch: Epoch::first(),
                send_budget,
                observer: None,
                inbound_budget: BUDGET,
                node_inbound: None,
            },
            outbound_tx,
            epoch_rx,
        );
        let task = tokio::spawn(task);

        let charge = 29 + INBOUND_RECORD_OVERHEAD;
        let mut fed = 0u32;
        let overflow = loop {
            let E2eFrame::Data {
                counter,
                mut ciphertext,
                ..
            } = attacker
                .encrypt_data(&E2eDataBody::Mux(yamux_ping(fed)))
                .unwrap()
            else {
                unreachable!()
            };
            // The router gets an exact-size Vec out of `E2eFrame::decode`.
            ciphertext.shrink_to_fit();
            if let Err(error) = handle.feed_inbound(counter, ciphertext) {
                break error;
            }
            fed += 1;
            if fed.is_multiple_of(256) {
                tokio::task::yield_now().await;
            }
            assert!(fed < 50_000, "the flood was never cut off");
        };

        assert_eq!(
            overflow,
            FeedRefused::Session(InboundOverflow { budget: BUDGET })
        );
        // What was accepted is what fits plus what `yamux` read before it
        // paused (a few dozen: the channel of replies it writes into holds
        // 64 frames plus the one the actor staged).
        let fits = (BUDGET / charge) as u32;
        assert!(
            fed >= fits,
            "{fed} accepted, fewer than the {fits} that fit"
        );
        assert!(
            fed < fits + 400,
            "{fed} accepted: the budget did not bound what yamux left unread"
        );
        assert!(handle.inbound_in_use() <= BUDGET);

        // The caller ends the session, as the router does; the charge goes
        // when the actor does.
        handle.close(None);
        let reason = tokio::time::timeout(Duration::from_secs(5), acceptor.closed())
            .await
            .expect("a close must end a session with a staged frame and a full queue");
        assert!(matches!(reason.as_ref(), EndReason::ClosedLocally(None)));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(handle.inbound_in_use(), 0);
    }

    #[tokio::test]
    async fn the_end_is_reported_even_when_the_actor_task_is_aborted() {
        // A task that is aborted (or panics) never reaches the end of
        // `run`, so `Ended` has to come from a drop guard.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let sessions = two_observed_sessions(Some(SessionObserver::new(tx, 9)), None);
        sessions._task_a.abort();
        loop {
            let (_, notice) = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("an aborted actor must still report that it ended")
                .unwrap();
            if notice == SessionNotice::Ended {
                break;
            }
        }
    }

    // ------------------------------------------------------------------
    // Datagrams (protocol.md 5.2, 5.4)
    // ------------------------------------------------------------------

    /// [`one_session`] with datagram channels, and an outbound channel of `capacity`.
    fn dgram_session(
        side: OneSide,
        max_record: u32,
        capacity: usize,
    ) -> (
        L4SessionHandle,
        L4SessionAcceptor,
        mpsc::Receiver<OutboundSend>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let send_budget = crate::outbound::SendBudgets::new().for_peer(side.peer);
        let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
        let (epoch_ended_tx, epoch_ended_rx) = oneshot::channel();
        let (handle, acceptor, task) = new_with_datagrams(
            L4SessionConfig {
                transport: side.transport,
                peer: side.peer,
                network_id: side.network_id,
                mode: side.mode,
                max_record,
                epoch: Epoch::first(),
                send_budget,
                observer: None,
                inbound_budget: L4_INBOUND_BUDGET_PER_SESSION,
                node_inbound: None,
            },
            outbound_tx,
            epoch_ended_rx,
        );
        (
            handle,
            acceptor,
            outbound_rx,
            epoch_ended_tx,
            tokio::spawn(task),
        )
    }

    /// Both sides with datagram channels; the test reads each side's outbound itself and
    /// forwards what it wants.
    struct DgramPair {
        a: L4SessionHandle,
        a_acceptor: L4SessionAcceptor,
        a_out: mpsc::Receiver<OutboundSend>,
        b: L4SessionHandle,
        b_acceptor: L4SessionAcceptor,
        b_out: mpsc::Receiver<OutboundSend>,
        _keep: (
            oneshot::Sender<()>,
            oneshot::Sender<()>,
            tokio::task::JoinHandle<()>,
            tokio::task::JoinHandle<()>,
        ),
    }

    fn dgram_pair() -> DgramPair {
        let (a_side, b_side) = two_sides(7, 65_535);
        let (a, a_acceptor, a_out, a_tx, a_task) = dgram_session(a_side, 65_535, 64);
        let (b, b_acceptor, b_out, b_tx, b_task) = dgram_session(b_side, 65_535, 64);
        DgramPair {
            a,
            a_acceptor,
            a_out,
            b,
            b_acceptor,
            b_out,
            _keep: (a_tx, b_tx, a_task, b_task),
        }
    }

    /// Reads `rx` until a droppable SEND shows up, answering every one `Accepted`; the
    /// reliable ones before it are returned too.
    async fn next_droppable(rx: &mut mpsc::Receiver<OutboundSend>) -> (OutboundSend, usize) {
        let mut reliable = 0;
        loop {
            let req = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("a datagram should have been sent")
                .expect("the session is running");
            if req.flags & 0x01 != 0 {
                return (req, reliable);
            }
            reliable += 1;
            let _ = req.outcome.send(EnqueueOutcome::Accepted);
        }
    }

    /// Answers `req` `Accepted` and feeds its frame to `dst` as the router would.
    fn deliver(dst: &L4SessionHandle, req: OutboundSend) {
        let _ = req.outcome.send(EnqueueOutcome::Accepted);
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = E2eFrame::decode(&req.payload).unwrap()
        else {
            panic!("not a data frame");
        };
        dst.feed_inbound(counter, ciphertext).unwrap();
    }

    #[tokio::test]
    async fn a_dgram_leaves_as_a_droppable_send() {
        let mut pair = dgram_pair();
        // A is the session initiator: even ids; B registers it as the peer's.
        let mut a_channel = pair.a.channels().unwrap().allocate().unwrap();
        assert_eq!(a_channel.id() % 2, 0);
        let mut b_channel = pair
            .b
            .channels()
            .unwrap()
            .register_remote(a_channel.id())
            .unwrap();
        a_channel.send(b"hello").unwrap();
        let (req, _reliable_before) = next_droppable(&mut pair.a_out).await;
        assert_eq!(req.flags, 0x01, "bit 0 is the droppable class");
        assert!(req.permit.is_none(), "a datagram is never credited");
        assert_eq!(req.dst, pair.a.peer());
        let E2eFrame::Data { counter, .. } = E2eFrame::decode(&req.payload).unwrap() else {
            panic!("not a data frame");
        };
        assert_eq!(counter >> 63, 1, "a datagram class counter");
        deliver(&pair.b, req);
        let got = tokio::time::timeout(Duration::from_secs(5), b_channel.recv())
            .await
            .expect("delivered")
            .unwrap();
        assert_eq!(got, b"hello");
        // And back the other way, on the same channel id.
        b_channel.send(b"pong").unwrap();
        let (req, _) = next_droppable(&mut pair.b_out).await;
        deliver(&pair.a, req);
        let got = tokio::time::timeout(Duration::from_secs(5), a_channel.recv())
            .await
            .expect("delivered")
            .unwrap();
        assert_eq!(got, b"pong");
        let _ = &pair.a_acceptor;
        let _ = &pair.b_acceptor;
    }

    #[tokio::test]
    async fn an_unknown_channel_datagram_is_dropped_and_the_session_lives() {
        let mut pair = dgram_pair();
        // A sends on a channel B never registered.
        let a_channel = pair.a.channels().unwrap().allocate().unwrap();
        a_channel.send(b"nobody listens").unwrap();
        let (req, _) = next_droppable(&mut pair.a_out).await;
        deliver(&pair.b, req);
        let b_table = pair.b.channels().unwrap().clone();
        for _ in 0..100 {
            if b_table.dropped().unknown_channel == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(b_table.dropped().unknown_channel, 1);
        assert_eq!(pair.b.dgram_in_use(), 0, "its charge was given back");
        // Nothing was sent back (no CLOSE, no error record, no datagram), and neither side
        // ended.
        let mut sent_by_b = Vec::new();
        while let Ok(Some(req)) =
            tokio::time::timeout(Duration::from_millis(300), pair.b_out.recv()).await
        {
            sent_by_b.push(req.flags);
            let _ = req.outcome.send(EnqueueOutcome::Accepted);
        }
        assert!(
            sent_by_b.iter().all(|flags| flags & 0x01 == 0),
            "B answered a datagram with a datagram: {sent_by_b:?}"
        );
        for acceptor in [&mut pair.a_acceptor, &mut pair.b_acceptor] {
            assert!(
                tokio::time::timeout(Duration::from_millis(200), acceptor.closed())
                    .await
                    .is_err(),
                "the session ended"
            );
        }
    }

    #[tokio::test]
    async fn datagrams_over_the_session_budget_are_dropped_and_the_session_lives() {
        let (a_side, b_side) = two_sides(8, 65_535);
        let (a, _a_acceptor, _a_out, _a_tx, _a_task) = dgram_session(a_side, 65_535, 64);
        let (b, mut b_acceptor, mut b_out, _b_tx, _b_task) = dgram_session(b_side, 65_535, 64);
        // The actor of `b` cannot run while this test does not await, so what is fed piles up
        // in its queue: junk of the datagram class, 16 KiB at a time.
        let per_record = 16 * 1024 + INBOUND_RECORD_OVERHEAD;
        let fits = DGRAM_BUDGET_PER_SESSION / per_record;
        for n in 0..(fits as u64 * 3) {
            b.feed_inbound((1u64 << 63) | n, vec![0xAB; 16 * 1024])
                .expect("a datagram over its budget is dropped, never an overflow");
        }
        assert!(b.dgram_in_use() <= DGRAM_BUDGET_PER_SESSION);
        assert!(b.dgram_in_use() >= fits * per_record - per_record);
        assert_eq!(
            b.inbound_in_use(),
            0,
            "the reliable budget is a different one"
        );
        // The actor now reads all of it (none authenticates) and gives every charge back.
        for _ in 0..100 {
            if b.dgram_in_use() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(b.dgram_in_use(), 0);
        // The session lives and still carries a stream.
        let drain = tokio::spawn(async move {
            while let Some(req) = b_out.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(200), b_acceptor.closed())
                .await
                .is_err()
        );
        drain.abort();
        let _ = a;
    }

    #[tokio::test]
    async fn docs_only_and_relay_principal_sessions_drop_datagrams() {
        // A session built with `new` has no channels: the router builds docs only and relay
        // principal sessions that way.
        let (a_side, b_side) = two_sides(9, 65_535);
        let (handle, mut acceptor, _out, _tx, _task) = one_session(b_side, 65_535);
        assert!(handle.channels().is_none());
        let _ = a_side;
        for n in 0..50u64 {
            handle
                .feed_inbound((1u64 << 63) | n, vec![0xAB; 1024])
                .expect("never an error");
        }
        assert_eq!(
            handle.dgram_in_use(),
            0,
            "dropped on arrival: nothing is queued or charged"
        );
        assert_eq!(handle.inbound_in_use(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), acceptor.closed())
                .await
                .is_err(),
            "the session lives"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_forged_datagram_does_not_feed_liveness() {
        // The peer sends nothing; a forged datagram arrives every 5 s (a relay can put frames
        // on this receiver index). If one counted as an authenticated record, the 40 s
        // dead-peer clock would never run out.
        let (_a_side, b_side) = two_sides(10, 65_535);
        let (handle, mut acceptor, mut out, _tx, _task) = dgram_session(b_side, 65_535, 64);
        let drain = tokio::spawn(async move {
            while let Some(req) = out.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        });
        let ended = async {
            for n in 0..40u64 {
                handle
                    .feed_inbound((1u64 << 63) | n, vec![0xCD; 64])
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        };
        tokio::select! {
            reason = acceptor.closed() => {
                assert!(matches!(reason.as_ref(), EndReason::PeerDead), "{reason:?}");
            }
            () = ended => panic!("forged datagrams kept a silent peer alive for 200 s"),
        }
        drain.abort();
    }

    #[tokio::test]
    async fn a_datagram_enqueue_failure_drops_without_ending_the_session() {
        // The function level: a full outbound and a closed one both drop and return.
        let (mut a_side, _b_side) = two_sides(11, 65_535);
        let peer = a_side.peer;
        let now = clock_now();
        let mut rekey = RekeySchedule::new(now);
        let (full_tx, _full_rx) = mpsc::channel(1);
        let filler = || {
            let (outcome, _rx) = oneshot::channel();
            OutboundSend {
                dst: peer,
                e2e_proto: E2E_PROTO_TAG,
                flags: 0,
                payload: vec![],
                epoch: Epoch::first(),
                outcome,
                permit: None,
            }
        };
        full_tx.try_send(filler()).unwrap();
        send_dgram(
            &mut a_side.transport,
            &mut rekey,
            &full_tx,
            peer,
            Epoch::first(),
            2,
            b"dropped, the queue is full",
        );
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        send_dgram(
            &mut a_side.transport,
            &mut rekey,
            &closed_tx,
            peer,
            Epoch::first(),
            2,
            b"dropped, nobody is there",
        );
        // A datagram the transport refuses (too large) is dropped too.
        send_dgram(
            &mut a_side.transport,
            &mut rekey,
            &closed_tx,
            peer,
            Epoch::first(),
            2,
            &vec![0u8; 70_000],
        );

        // The session level: the node's queue refuses every datagram (QueueFull) and the
        // session neither ends nor misses a beat for it.
        let (a_side, b_side) = two_sides(12, 65_535);
        let (a, mut a_acceptor, mut a_out, _a_tx, _a_task) = dgram_session(a_side, 65_535, 64);
        let (b, mut b_acceptor, b_out, _b_tx, _b_task) = dgram_session(b_side, 65_535, 64);
        let to_b = pump(
            {
                let (relay_tx, relay_rx) = mpsc::channel(64);
                tokio::spawn(async move {
                    while let Some(req) = a_out.recv().await {
                        if req.flags & 0x01 != 0 {
                            let _ = req.outcome.send(EnqueueOutcome::QueueFull);
                        } else if relay_tx.send(req).await.is_err() {
                            break;
                        }
                    }
                });
                relay_rx
            },
            b.clone(),
        );
        let to_a = pump(b_out, a.clone());
        let channel = a.channels().unwrap().allocate().unwrap();
        for _ in 0..20 {
            channel.send(&[1; 100]).unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Reliable traffic still flows both ways.
        let mut opened = a.open_stream().await.unwrap();
        use futures_util::io::AsyncWriteExt;
        opened.write_all(b"still alive").await.unwrap();
        opened.flush().await.unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(5), b_acceptor.accept())
            .await
            .expect("the stream arrives");
        assert!(accepted.is_some());
        for acceptor in [&mut a_acceptor, &mut b_acceptor] {
            assert!(
                tokio::time::timeout(Duration::from_millis(200), acceptor.closed())
                    .await
                    .is_err(),
                "a refused datagram ended a session"
            );
        }
        to_a.abort();
        to_b.abort();
    }

    // Regression (red team round E3, M1): a side that sends only datagrams, all dropped on the way (a relay bucket
    // or tenant droppable cap), must still keep its peer alive with KEEP.
    #[tokio::test(start_paused = true)]
    async fn a_datagram_only_sender_whose_datagrams_are_dropped_keeps_the_peer_alive() {
        let pair = dgram_pair();
        let DgramPair {
            a,
            a_acceptor: _aa,
            mut a_out,
            b,
            b_acceptor: mut bacc,
            mut b_out,
            _keep,
        } = pair;
        let a_channel = a.channels().unwrap().allocate().unwrap();
        let b2 = b.clone();
        let reliable_from_a = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let r2 = reliable_from_a.clone();
        let fwd_a = tokio::spawn(async move {
            while let Some(req) = a_out.recv().await {
                if req.flags & 0x01 != 0 {
                    // The relay drops every droppable SEND of A.
                    let _ = req.outcome.send(EnqueueOutcome::Accepted);
                    continue;
                }
                r2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                deliver(&b2, req);
            }
        });
        let a2 = a.clone();
        let fwd_b = tokio::spawn(async move {
            while let Some(req) = b_out.recv().await {
                deliver(&a2, req);
            }
        });
        let sender = async {
            for _ in 0..24u32 {
                let _ = a_channel.send(&[0u8; 100]);
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        };
        tokio::select! {
            reason = bacc.closed() => {
                panic!("B ended at a datagram-only sender: {reason:?}; reliable records A sent: {}",
                    reliable_from_a.load(std::sync::atomic::Ordering::SeqCst));
            }
            () = sender => {}
        }
        fwd_a.abort();
        fwd_b.abort();
    }

    // --- TBD 75 step 1: the node wide counter ------------------------------

    fn node_and_budgets(ceiling: usize, n: usize) -> (Arc<NodeInbound>, Vec<InboundBudget>) {
        let node = Arc::new(NodeInbound::new(ceiling));
        let budgets = (0..n)
            .map(|_| InboundBudget::new(usize::MAX >> 2).with_node(Some(Arc::clone(&node))))
            .collect();
        (node, budgets)
    }

    /// T7: a drop after `detach` leaves the node counter alone, a drop before it lowers it
    /// once, and `detach` takes out exactly what was still held.
    #[test]
    fn a_permit_dropped_after_detach_does_not_lower_the_node_counter_again() {
        let (node, budgets) = node_and_budgets(10_000, 2);
        let (a, b) = (&budgets[0], &budgets[1]);
        let early = a.reserve(100, true).unwrap();
        let late = a.reserve(200, true).unwrap();
        let other = b.reserve(50, true).unwrap();
        assert_eq!(node.in_use(), 350);
        // Dropped before the detach: lowers the node counter once.
        drop(early);
        assert_eq!(node.in_use(), 250);
        assert_eq!(a.detach(), 200);
        assert_eq!(node.in_use(), 50);
        // Dropped after: the node counter is not touched, the session's is.
        drop(late);
        assert_eq!(node.in_use(), 50);
        assert_eq!(a.used(), 0);
        assert_eq!(a.detach(), 0, "a second detach takes nothing out");
        assert_eq!(node.in_use(), 50);
        drop(other);
        assert_eq!(node.in_use(), 0);
    }

    /// A reservation made after the detach charges the session only.
    #[test]
    fn a_detached_session_is_not_charged_to_the_node() {
        let (node, budgets) = node_and_budgets(10_000, 1);
        let a = &budgets[0];
        let held = a.reserve(100, true).unwrap();
        a.detach();
        let after = a.reserve(300, true).unwrap();
        assert_eq!(a.used(), 400);
        assert_eq!(node.in_use(), 0);
        drop(held);
        drop(after);
        assert_eq!(a.used(), 0);
        assert_eq!(node.in_use(), 0);
    }

    /// A refusal by the node adds nothing to the session or the node; `enforce_node = false`
    /// charges past the ceiling; the session's own budget is checked first and wins.
    #[test]
    fn a_router_node_counter_carries_the_production_ceilings() {
        let node = NodeInbound::new(L4_INBOUND_CEILING_PER_NODE);
        assert_eq!(node.ceiling(), 1 << 30);
        let dgram = node.dgram.as_ref().expect("a datagram counter");
        assert_eq!(dgram.ceiling(), 64 << 20);
        assert_eq!(dgram.ceiling(), crate::channels::DGRAM_CEILING_PER_NODE);
    }

    #[test]
    fn a_node_refusal_leaves_both_counters_as_they_were() {
        let (node, _) = node_and_budgets(1000, 0);
        let a = InboundBudget::new(5000).with_node(Some(Arc::clone(&node)));
        let held = a.reserve(900, true).unwrap();
        assert!(matches!(a.reserve(200, true), Err(Refused::Node)));
        assert_eq!(a.used(), 900);
        assert_eq!(node.in_use(), 900);
        let forced = a.reserve(200, false).unwrap();
        assert_eq!(node.in_use(), 1100);
        assert_eq!(a.used(), 1100);
        assert!(matches!(a.reserve(5000, true), Err(Refused::Session)));
        assert_eq!(node.in_use(), 1100);
        drop(held);
        drop(forced);
        assert_eq!(node.in_use(), 0);
        assert_eq!(a.used(), 0);
    }

    /// `feed_inbound` through the handles: the node refusal hands the record back, the forced
    /// feed takes it, and the detach and the drain leave the counters exact (T4).
    #[tokio::test]
    async fn feed_inbound_refuses_at_the_node_ceiling_and_the_accounting_stays_exact() {
        const RECORD: usize = 1000;
        let charge = RECORD + INBOUND_RECORD_OVERHEAD;
        // Room for five charges in the node, plenty in each session.
        let node = Arc::new(NodeInbound::new(5 * charge));
        let (a, a_task, _a_out, _a_end) =
            sleeping_session_on(1, 100 * charge, Some(Arc::clone(&node)));
        let (b, b_task, _b_out, _b_end) =
            sleeping_session_on(2, 100 * charge, Some(Arc::clone(&node)));
        for counter in 0..3 {
            a.feed_inbound(counter, vec![1; RECORD]).unwrap();
        }
        for counter in 0..2 {
            b.feed_inbound(counter, vec![2; RECORD]).unwrap();
        }
        assert_eq!(node.in_use(), 5 * charge);
        // The sixth does not fit: refused, handed back untouched, nothing charged.
        let record = vec![3; RECORD];
        match b.feed_inbound(2, record.clone()) {
            Err(FeedRefused::Node {
                counter,
                ciphertext,
            }) => {
                assert_eq!(counter, 2);
                assert_eq!(ciphertext, record);
            }
            other => panic!("expected a node refusal, got {other:?}"),
        }
        assert_eq!(node.in_use(), 5 * charge);
        assert_eq!(b.inbound_in_use(), 2 * charge);
        // The forced feed takes it past the ceiling, once.
        b.feed_inbound_over_ceiling(2, record).unwrap();
        assert_eq!(node.in_use(), 6 * charge);
        assert_eq!(b.inbound_in_use(), 3 * charge);
        // Detach A: its charges leave the node counter at once, its own stay until drained.
        a.detach_inbound();
        a.detach_inbound();
        assert_eq!(node.in_use(), 3 * charge);
        assert_eq!(a.inbound_in_use(), 3 * charge);
        // A detached session no longer counts, so B can feed within the ceiling again.
        b.feed_inbound(3, vec![4; RECORD]).unwrap();
        assert_eq!(node.in_use(), 4 * charge);
        // Drain: the actors are never polled, so dropping the tasks drops the queued permits.
        drop(a_task);
        drop(b_task);
        assert_eq!(a.inbound_in_use(), 0);
        assert_eq!(b.inbound_in_use(), 0);
        assert_eq!(node.in_use(), 0);
    }

    /// T8: four threads drop 10,000 permits each while this thread detaches, over and over;
    /// the node counter ends at 0 and is never seen above what was reserved.
    #[test]
    fn concurrent_drops_and_a_detach_leave_the_node_counter_at_zero() {
        const THREADS: usize = 4;
        const PERMITS: usize = 10_000;
        for round in 0..20 {
            let (node, budgets) = node_and_budgets(usize::MAX >> 2, 1);
            let budget = budgets[0].clone();
            let mut lots: Vec<Vec<InboundPermit>> = (0..THREADS)
                .map(|_| {
                    (0..PERMITS)
                        .map(|_| budget.reserve(7, true).unwrap())
                        .collect()
                })
                .collect();
            assert_eq!(node.in_use(), THREADS * PERMITS * 7);
            let barrier = Arc::new(std::sync::Barrier::new(THREADS + 1));
            let handles: Vec<_> = lots
                .drain(..)
                .map(|lot| {
                    let barrier = Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        for permit in lot {
                            drop(permit);
                        }
                    })
                })
                .collect();
            barrier.wait();
            // Detach somewhere in the middle of the drops.
            for _ in 0..(round * 50) {
                std::hint::spin_loop();
            }
            budget.detach();
            for handle in handles {
                handle.join().unwrap();
            }
            assert_eq!(node.in_use(), 0, "round {round}");
            assert_eq!(budget.used(), 0, "round {round}");
        }
    }

    // --- T1c: the stream layer's meter on the same counters ------------------

    /// U3: `buffered` and `consumed` interleaved with permits and a detach, in every order
    /// that matters: the node ends at 0 and the session counter is exact at each step.
    #[test]
    fn the_buffer_meter_shares_the_counters_with_permits_across_a_detach() {
        use menzil_stream::BufferMeter;
        let (node, budgets) = node_and_budgets(10_000, 2);
        let (a, b) = (&budgets[0], &budgets[1]);
        let permit = a.reserve(100, true).unwrap();
        a.buffered(40);
        b.buffered(5);
        assert_eq!((a.used(), node.in_use()), (140, 145));
        // Charged without a check, past the node ceiling too.
        a.buffered(20_000);
        assert_eq!((a.used(), node.in_use()), (20_140, 20_145));
        a.consumed(20_000);
        assert_eq!((a.used(), node.in_use()), (140, 145));
        // Detach takes out exactly what is held (permit and stream data alike).
        assert_eq!(a.detach(), 140);
        assert_eq!(node.in_use(), 5);
        // After the detach: buffered charges the session only, consumed too.
        a.buffered(60);
        assert_eq!((a.used(), node.in_use()), (200, 5));
        a.consumed(30);
        assert_eq!((a.used(), node.in_use()), (170, 5));
        drop(permit);
        assert_eq!((a.used(), node.in_use()), (70, 5));
        a.consumed(40);
        a.consumed(30);
        assert_eq!((a.used(), node.in_use()), (0, 5));
        b.consumed(5);
        assert_eq!((b.used(), node.in_use()), (0, 0));
    }

    /// U3 stress: four threads buffer and consume while this thread detaches; the node
    /// counter never wraps (never seen above 1 << 62) and ends at 0, the session's too.
    #[test]
    fn the_buffer_meter_never_wraps_the_node_counter_against_a_detach() {
        use menzil_stream::BufferMeter;
        const THREADS: usize = 4;
        const ROUNDS: usize = 20_000;
        for round in 0..20 {
            let (node, budgets) = node_and_budgets(usize::MAX >> 2, 1);
            let budget = budgets[0].clone();
            let barrier = Arc::new(std::sync::Barrier::new(THREADS + 2));
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let (budget, barrier) = (budget.clone(), Arc::clone(&barrier));
                    std::thread::spawn(move || {
                        barrier.wait();
                        for _ in 0..ROUNDS {
                            budget.buffered(7);
                            budget.consumed(7);
                        }
                    })
                })
                .collect();
            let sampler = {
                let (node, barrier) = (Arc::clone(&node), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut worst = 0;
                    for _ in 0..ROUNDS {
                        worst = worst.max(node.in_use());
                    }
                    worst
                })
            };
            barrier.wait();
            for _ in 0..(round * 50) {
                std::hint::spin_loop();
            }
            budget.detach();
            for handle in handles {
                handle.join().unwrap();
            }
            let worst = sampler.join().unwrap();
            assert!(
                worst < (1 << 62),
                "round {round}: node counter wrapped ({worst})"
            );
            assert_eq!(node.in_use(), 0, "round {round}");
            assert_eq!(budget.used(), 0, "round {round}");
        }
    }

    // ------------------------------------------------------------------
    // Re-handshake handover (protocol.md 5.2, slice R2)
    // ------------------------------------------------------------------

    use std::collections::HashMap;
    use std::sync::Mutex;

    const HSEED: u8 = 7;

    /// The own index of side A (the initiator) in generation `g`, and of side B. Every
    /// generation has its own pair, so a frame's `receiver_index` names its transport.
    fn a_idx(g: u32) -> u32 {
        1 + 2 * g
    }
    fn b_idx(g: u32) -> u32 {
        2 + 2 * g
    }

    /// One direction of the in memory network between two actors, which also plays the router
    /// of the receiving side: it maps a frame's `receiver_index` to a generation, decrypts the
    /// first reliable record of a replacement candidate itself (CONTINUE) and hands the
    /// transport over (R3's job in production), and can hold, stash or log frames.
    #[derive(Default)]
    struct LinkState {
        gens: HashMap<u32, Generation>,
        candidates: HashMap<u32, E2eTransport>,
        hold_all: bool,
        hold_reliable: bool,
        held: Vec<Vec<u8>>,
        stash_dgrams: bool,
        stashed: Vec<(u32, u64, Vec<u8>)>,
        /// Added to the `sent` of a CONTINUE before it is passed on (a lying relay or peer).
        sent_offset: i64,
        /// `(receiver_index, counter, datagram class)` of every frame, in order.
        log: Vec<(u32, u64, bool)>,
        candidate_dgrams: u32,
    }

    struct Link {
        dst: L4SessionHandle,
        st: Mutex<LinkState>,
    }

    impl Link {
        fn route(&self, payload: Vec<u8>) {
            let mut st = self.st.lock().unwrap();
            let E2eFrame::Data { counter, .. } = E2eFrame::decode(&payload).unwrap() else {
                panic!("not data");
            };
            let dgram = RecordClass::of_counter(counter) == RecordClass::Datagram;
            if st.hold_all || (st.hold_reliable && !dgram) {
                st.held.push(payload);
                return;
            }
            self.route_now(&mut st, payload);
        }

        fn route_now(&self, st: &mut LinkState, payload: Vec<u8>) {
            let E2eFrame::Data {
                receiver_index,
                counter,
                ciphertext,
            } = E2eFrame::decode(&payload).unwrap()
            else {
                panic!("not data");
            };
            let dgram = RecordClass::of_counter(counter) == RecordClass::Datagram;
            st.log.push((receiver_index, counter, dgram));
            if dgram && st.stash_dgrams {
                st.stashed.push((receiver_index, counter, ciphertext));
                return;
            }
            if let Some(&g) = st.gens.get(&receiver_index) {
                self.dst
                    .feed_inbound_gen(g, counter, ciphertext)
                    .expect("within the inbound budget");
            } else if st.candidates.contains_key(&receiver_index) {
                if dgram {
                    st.candidate_dgrams += 1;
                    return;
                }
                let mut t = st.candidates.remove(&receiver_index).unwrap();
                let plain = t.decrypt_raw(counter, &ciphertext).expect("first record");
                let cont = ContinueBody::decode(&plain).expect("CONTINUE");
                let sent = (cont.sent as i64 + st.sent_offset) as u64;
                let g = self.dst.hand_over(
                    t,
                    HandoverRole::Responder {
                        continue_sent: sent,
                    },
                );
                st.gens.insert(receiver_index, g);
            } else {
                panic!("a frame for an unknown index {receiver_index}");
            }
        }

        fn release(&self) {
            let mut st = self.st.lock().unwrap();
            st.hold_all = false;
            st.hold_reliable = false;
            let held = std::mem::take(&mut st.held);
            for payload in held {
                self.route_now(&mut st, payload);
            }
        }

        fn log(&self) -> Vec<(u32, u64, bool)> {
            self.st.lock().unwrap().log.clone()
        }
    }

    fn link_pump(
        mut rx: mpsc::Receiver<OutboundSend>,
        link: Arc<Link>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
                link.route(req.payload);
            }
        })
    }

    /// Two member actors joined by two [`Link`]s, A the initiator.
    #[allow(clippy::type_complexity)]
    struct Rig {
        a: L4SessionHandle,
        a_acceptor: L4SessionAcceptor,
        b: L4SessionHandle,
        b_acceptor: L4SessionAcceptor,
        a_to_b: Arc<Link>,
        b_to_a: Arc<Link>,
        _keep: (
            oneshot::Sender<()>,
            oneshot::Sender<()>,
            tokio::task::JoinHandle<()>,
            tokio::task::JoinHandle<()>,
            tokio::task::JoinHandle<()>,
            tokio::task::JoinHandle<()>,
        ),
    }

    fn rig() -> Rig {
        let (a_side, b_side) = two_sides_indexed(HSEED, 65_535, a_idx(0), b_idx(0));
        let (a, a_acceptor, a_out, a_tx, a_task) = dgram_session(a_side, 65_535, 64);
        let (b, b_acceptor, b_out, b_tx, b_task) = dgram_session(b_side, 65_535, 64);
        let a_to_b = Arc::new(Link {
            dst: b.clone(),
            st: Mutex::new(LinkState::default()),
        });
        let b_to_a = Arc::new(Link {
            dst: a.clone(),
            st: Mutex::new(LinkState::default()),
        });
        a_to_b.st.lock().unwrap().gens.insert(b_idx(0), 0);
        b_to_a.st.lock().unwrap().gens.insert(a_idx(0), 0);
        let p1 = link_pump(a_out, a_to_b.clone());
        let p2 = link_pump(b_out, b_to_a.clone());
        Rig {
            a,
            a_acceptor,
            b,
            b_acceptor,
            a_to_b,
            b_to_a,
            _keep: (a_tx, b_tx, a_task, b_task, p1, p2),
        }
    }

    impl Rig {
        /// Starts replacement number `n` (1, 2, ...): the new transports (fresh keys, indices
        /// of generation `n`) go to A as initiator; B's side is the candidate its link's
        /// router decrypts the CONTINUE of.
        fn start_cutover(&self, n: u32) {
            let (a_side, b_side) = two_sides_indexed(HSEED, 65_535, a_idx(n), b_idx(n));
            self.a_to_b
                .st
                .lock()
                .unwrap()
                .candidates
                .insert(b_idx(n), b_side.transport);
            let mut gens = self.b_to_a.st.lock().unwrap();
            // The tag A will give it; `hand_over` numbers it n.
            gens.gens.insert(a_idx(n), n);
            drop(gens);
            let g = self.a.hand_over(
                a_side.transport,
                HandoverRole::Initiator {
                    prior: b_idx(n - 1),
                },
            );
            assert_eq!(g, n);
        }

        async fn wait_settled(&self, n: u32) {
            for _ in 0..1000 {
                if self.a.settled_generation() == n && self.b.settled_generation() == n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!(
                "cutover {n} did not settle: a {} b {}",
                self.a.settled_generation(),
                self.b.settled_generation()
            );
        }

        async fn cutover(&self, n: u32) {
            self.start_cutover(n);
            self.wait_settled(n).await;
        }

        fn assert_alive(&mut self) {
            assert!(self.a_acceptor.ended_rx.try_recv().is_err(), "side A ended");
            assert!(self.b_acceptor.ended_rx.try_recv().is_err(), "side B ended");
        }
    }

    fn prng_bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed | 1;
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.extend_from_slice(&x.to_le_bytes());
        }
        out.truncate(n);
        out
    }

    /// After the first frame of generation `n` in `log` (CONTINUE or CONTINUE_ACK, which must
    /// be counter 0), no frame of generation `n - 1` follows: nothing is ever sent on the old
    /// transport after the switch.
    fn assert_nothing_on_old_after_switch(log: &[(u32, u64, bool)], old: u32, new: u32) {
        let first_new = log
            .iter()
            .position(|(idx, _, _)| *idx == new)
            .expect("the new transport carried something");
        assert_eq!(log[first_new].1, 0, "the first record on the new transport");
        assert!(!log[first_new].2, "and it is reliable");
        assert!(
            !log[first_new..].iter().any(|(idx, _, _)| *idx == old),
            "a frame was sent on the old transport after the switch"
        );
    }

    async fn streams_across_cutovers(cutovers: u32) {
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
        const CHUNK: usize = 16 * 1024;
        const BYTES: usize = 64 * CHUNK;
        let mut rig = rig();
        let ab = prng_bytes(11, BYTES);
        let ba = prng_bytes(22, BYTES);
        let progress = Arc::new(AtomicUsize::new(0));

        // A -> B on a stream A opens.
        let mut s1 = rig.a.open_stream().await.unwrap();
        let data = ab.clone();
        let writer_ab = tokio::spawn(async move {
            for chunk in data.chunks(CHUNK) {
                s1.write_all(chunk).await.unwrap();
                s1.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
            s1.close().await.unwrap();
        });
        let mut b_acceptor = std::mem::replace(
            &mut rig.b_acceptor,
            // A placeholder that is never used: the real one moved into the reader task.
            placeholder_acceptor(),
        );
        let p = progress.clone();
        let reader_ab = tokio::spawn(async move {
            let mut s = b_acceptor.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                p.fetch_add(n, Ordering::SeqCst);
            }
            (got, b_acceptor)
        });
        // B -> A on a stream B opens.
        let mut s2 = rig.b.open_stream().await.unwrap();
        let data = ba.clone();
        let writer_ba = tokio::spawn(async move {
            for chunk in data.chunks(CHUNK) {
                s2.write_all(chunk).await.unwrap();
                s2.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(3)).await;
            }
            s2.close().await.unwrap();
        });
        let mut a_acceptor = std::mem::replace(&mut rig.a_acceptor, placeholder_acceptor());
        let p = progress.clone();
        let reader_ba = tokio::spawn(async move {
            let mut s = a_acceptor.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = s.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                p.fetch_add(n, Ordering::SeqCst);
            }
            (got, a_acceptor)
        });

        let total = 2 * BYTES;
        for k in 1..=cutovers {
            let threshold = (k as usize) * total / (cutovers as usize + 1);
            let mut waited = 0;
            while progress.load(Ordering::SeqCst) < threshold {
                tokio::time::sleep(Duration::from_millis(2)).await;
                waited += 1;
                assert!(waited < 30_000, "the transfer stalled before cutover {k}");
            }
            assert!(
                progress.load(Ordering::SeqCst) < total,
                "cutover {k} must happen while bytes are in flight"
            );
            rig.cutover(k).await;
        }
        let (got_ab, _b_acc) = tokio::time::timeout(Duration::from_secs(120), reader_ab)
            .await
            .expect("the A to B stream finishes")
            .unwrap();
        let (got_ba, _a_acc) = tokio::time::timeout(Duration::from_secs(120), reader_ba)
            .await
            .expect("the B to A stream finishes")
            .unwrap();
        writer_ab.await.unwrap();
        writer_ba.await.unwrap();
        assert!(got_ab == ab, "A to B bytes differ across the cutovers");
        assert!(got_ba == ba, "B to A bytes differ across the cutovers");
        assert_eq!(rig.a.settled_generation(), cutovers);
        assert_eq!(rig.b.settled_generation(), cutovers);
        for n in 1..=cutovers {
            assert_nothing_on_old_after_switch(&rig.a_to_b.log(), b_idx(n - 1), b_idx(n));
            assert_nothing_on_old_after_switch(&rig.b_to_a.log(), a_idx(n - 1), a_idx(n));
        }
        // Neither session ended.
        assert!(rig.a.dgram_in_use() == 0 && rig.b.dgram_in_use() == 0);
    }

    /// An acceptor of a session that does not exist, to leave behind where a test moves the
    /// real one out of the [`Rig`].
    fn placeholder_acceptor() -> L4SessionAcceptor {
        let (a_side, _b) = two_sides(99, 65_535);
        let (_h, acceptor, _out, _tx, _task) = one_session(a_side, 65_535);
        acceptor
    }

    #[tokio::test]
    async fn streams_with_bytes_in_flight_both_ways_survive_one_cutover() {
        streams_across_cutovers(1).await;
    }

    #[tokio::test]
    async fn streams_with_bytes_in_flight_both_ways_survive_three_consecutive_cutovers() {
        streams_across_cutovers(3).await;
    }

    #[tokio::test]
    async fn records_queued_before_the_handover_are_all_delivered_before_the_switch() {
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
        let mut rig = rig();
        // Everything A sends is held in the network; A writes, then starts the cutover, so
        // the CONTINUE queues behind the data.
        rig.a_to_b.st.lock().unwrap().hold_all = true;
        let mut s = rig.a.open_stream().await.unwrap();
        let payload = prng_bytes(5, 150_000);
        s.write_all(&payload).await.unwrap();
        s.flush().await.unwrap();
        for _ in 0..500 {
            if rig.a_to_b.st.lock().unwrap().held.len() >= 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let data_frames = rig.a_to_b.st.lock().unwrap().held.len();
        assert!(data_frames >= 4, "the data is queued");
        rig.start_cutover(1);
        for _ in 0..500 {
            if rig.a_to_b.st.lock().unwrap().held.len() > data_frames {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            rig.a_to_b.st.lock().unwrap().held.len() > data_frames,
            "the CONTINUE is queued behind the data"
        );
        let b_reader = tokio::spawn({
            let mut acc = std::mem::replace(&mut rig.b_acceptor, placeholder_acceptor());
            async move {
                let mut s = acc.accept().await.unwrap();
                let mut got = vec![0u8; 150_000];
                s.read_exact(&mut got).await.unwrap();
                (got, acc)
            }
        });
        rig.a_to_b.release();
        rig.wait_settled(1).await;
        let (got, _acc) = tokio::time::timeout(Duration::from_secs(30), b_reader)
            .await
            .unwrap()
            .unwrap();
        assert!(got == payload);
    }

    #[tokio::test]
    async fn a_datagram_across_the_switch_is_dropped_and_counted_and_datagrams_resume() {
        let rig = rig();
        let mut a_channel = rig.a.channels().unwrap().allocate().unwrap();
        let mut b_channel = rig
            .b
            .channels()
            .unwrap()
            .register_remote(a_channel.id())
            .unwrap();
        // 1. A datagram sent on the old transport but held back past the cutover.
        rig.a_to_b.st.lock().unwrap().stash_dgrams = true;
        a_channel.send(b"old").unwrap();
        for _ in 0..500 {
            if !rig.a_to_b.st.lock().unwrap().stashed.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(rig.a_to_b.st.lock().unwrap().stashed.len(), 1);
        rig.a_to_b.st.lock().unwrap().stash_dgrams = false;
        // 2. B's ACK held back: B (settled) sends a datagram on the new transport, which A,
        // still waiting for the ACK, must drop.
        rig.b_to_a.st.lock().unwrap().hold_reliable = true;
        rig.start_cutover(1);
        for _ in 0..500 {
            if rig.b.settled_generation() == 1 && !rig.b_to_a.st.lock().unwrap().held.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(rig.b.settled_generation(), 1);
        b_channel.send(b"new, before the ack").unwrap();
        for _ in 0..500 {
            if rig.a.channels().unwrap().dropped().handover == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(rig.a.channels().unwrap().dropped().handover, 1);
        rig.b_to_a.release();
        rig.wait_settled(1).await;
        // 3. The stale old datagram reaches B after the switch: dropped, counted, not delivered.
        let (idx, counter, ct) = rig.a_to_b.st.lock().unwrap().stashed.remove(0);
        assert_eq!(idx, b_idx(0));
        rig.b.feed_inbound_gen(0, counter, ct).unwrap();
        // 4. A datagram of a generation not handed over yet.
        rig.b
            .feed_inbound_gen(5, (1u64 << 63) | 7, vec![0xAB; 40])
            .unwrap();
        for _ in 0..500 {
            if rig.b.channels().unwrap().dropped().handover == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(rig.b.channels().unwrap().dropped().handover, 2);
        assert!(
            b_channel.try_recv().is_none(),
            "nothing was delivered twice or at all"
        );
        // 5. Datagrams work again under the new keys, both ways (fresh replay window).
        a_channel.send(b"after").unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), b_channel.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"after");
        b_channel.send(b"back").unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), a_channel.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, b"back");
        let mut rig = rig;
        rig.assert_alive();
    }

    #[tokio::test]
    async fn yamux_mode_and_channel_parity_are_unchanged_by_a_cutover() {
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
        let mut rig = rig();
        let before_a = rig.a.channels().unwrap().allocate().unwrap();
        let before_b = rig.b.channels().unwrap().allocate().unwrap();
        assert_eq!(before_a.id() % 2, 0, "the L4 initiator allocates even ids");
        assert_eq!(before_b.id() % 2, 1);
        let s_a = rig.a.open_stream().await.unwrap();
        let s_b = rig.b.open_stream().await.unwrap();
        assert_eq!(s_a.id() % 2, 1, "yamux client ids are odd");
        assert_eq!(s_b.id() % 2, 0, "yamux server ids are even");
        drop((s_a, s_b));
        rig.cutover(1).await;
        let after_a = rig.a.channels().unwrap().allocate().unwrap();
        let after_b = rig.b.channels().unwrap().allocate().unwrap();
        assert_eq!(after_a.id() % 2, 0);
        assert_eq!(after_b.id() % 2, 1);
        assert_ne!(after_a.id(), before_a.id());
        // New streams after the cutover keep the roles: A's are odd, B's even, and each side
        // accepts the other's.
        let mut n_a = rig.a.open_stream().await.unwrap();
        let mut n_b = rig.b.open_stream().await.unwrap();
        assert_eq!(n_a.id() % 2, 1);
        assert_eq!(n_b.id() % 2, 0);
        n_a.write_all(b"a2b").await.unwrap();
        n_a.flush().await.unwrap();
        n_b.write_all(b"b2a").await.unwrap();
        n_b.flush().await.unwrap();
        let mut got = [0u8; 3];
        let mut accepted = tokio::time::timeout(Duration::from_secs(5), rig.b_acceptor.accept())
            .await
            .unwrap()
            .unwrap();
        accepted.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"a2b");
        let mut accepted = tokio::time::timeout(Duration::from_secs(5), rig.a_acceptor.accept())
            .await
            .unwrap()
            .unwrap();
        accepted.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"b2a");
        rig.assert_alive();
    }

    #[tokio::test]
    async fn expire_ends_both_sides_with_session_expired_before_and_after_a_cutover() {
        for cutover in [false, true] {
            let rig = rig();
            if cutover {
                rig.cutover(1).await;
            }
            rig.a.expire();
            let mut rig = rig;
            let b_end = tokio::time::timeout(Duration::from_secs(5), rig.b_acceptor.closed())
                .await
                .unwrap();
            assert!(
                matches!(
                    b_end.as_ref(),
                    EndReason::PeerClosed { code, .. } if *code == ErrorCode::SessionExpired
                ),
                "{b_end:?}"
            );
            let a_end = rig.a_acceptor.closed().await;
            assert!(
                matches!(
                    a_end.as_ref(),
                    EndReason::ClosedLocally(Some(c)) if c.code == ErrorCode::SessionExpired
                ),
                "{a_end:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_count_the_peer_lies_about_ends_both_sides_with_handover_failed() {
        let rig = rig();
        // The CONTINUE reaches B claiming one record more than A sent on the old session.
        rig.a_to_b.st.lock().unwrap().sent_offset = 1;
        rig.start_cutover(1);
        let mut rig = rig;
        let b_end = tokio::time::timeout(Duration::from_secs(5), rig.b_acceptor.closed())
            .await
            .unwrap();
        assert!(
            matches!(b_end.as_ref(), EndReason::HandoverFailed(_)),
            "{b_end:?}"
        );
        // A reads B's CLOSE as the first record on the new transport.
        let a_end = tokio::time::timeout(Duration::from_secs(5), rig.a_acceptor.closed())
            .await
            .unwrap();
        assert!(
            matches!(
                a_end.as_ref(),
                EndReason::PeerClosed { code, .. } if *code == ErrorCode::HandoverFailed
            ),
            "{a_end:?}"
        );
    }

    // ---- one actor against a hand driven peer ----

    type Seen = Arc<Mutex<Vec<(u32, u64, Vec<u8>)>>>;

    /// One actor and the test as its peer: the test holds the peer's old and new transports,
    /// feeds frames itself and reads what the actor sent.
    struct Solo {
        handle: L4SessionHandle,
        acceptor: L4SessionAcceptor,
        out: Option<mpsc::Receiver<OutboundSend>>,
        seen: Seen,
        peer_old: E2eTransport,
        peer_new: E2eTransport,
        actor_new: Option<E2eTransport>,
        /// `receiver_index` the actor stamps on its old and on its new frames.
        old_idx: u32,
        new_idx: u32,
        _tx: oneshot::Sender<()>,
        _task: tokio::task::JoinHandle<()>,
    }

    fn solo(initiator: bool) -> Solo {
        let (a0, b0) = two_sides_indexed(HSEED, 65_535, a_idx(0), b_idx(0));
        let (a1, b1) = two_sides_indexed(HSEED, 65_535, a_idx(1), b_idx(1));
        let (actor, peer_old, actor_new, peer_new, old_idx, new_idx) = if initiator {
            (
                a0,
                b0.transport,
                a1.transport,
                b1.transport,
                b_idx(0),
                b_idx(1),
            )
        } else {
            (
                b0,
                a0.transport,
                b1.transport,
                a1.transport,
                a_idx(0),
                a_idx(1),
            )
        };
        let (handle, acceptor, out, tx, task) = dgram_session(actor, 65_535, 64);
        Solo {
            handle,
            acceptor,
            out: Some(out),
            seen: Arc::new(Mutex::new(Vec::new())),
            peer_old,
            peer_new,
            actor_new: Some(actor_new),
            old_idx,
            new_idx,
            _tx: tx,
            _task: task,
        }
    }

    impl Solo {
        /// Starts answering every send `Accepted` and recording what it carried.
        fn collect(&mut self) {
            let mut out = self.out.take().expect("collect once");
            let seen = self.seen.clone();
            tokio::spawn(async move {
                while let Some(req) = out.recv().await {
                    let _ = req.outcome.send(EnqueueOutcome::Accepted);
                    if let E2eFrame::Data {
                        receiver_index,
                        counter,
                        ciphertext,
                    } = E2eFrame::decode(&req.payload).unwrap()
                    {
                        seen.lock()
                            .unwrap()
                            .push((receiver_index, counter, ciphertext));
                    }
                }
            });
        }

        /// Waits until the actor has sent a frame under the new index and returns the number
        /// of frames it sent under the old one before it, and the new frames so far.
        async fn first_new_frame(&self) -> (usize, Vec<(u64, Vec<u8>)>) {
            for _ in 0..1000 {
                {
                    let seen = self.seen.lock().unwrap();
                    if seen.iter().any(|(idx, _, _)| *idx == self.new_idx) {
                        let old = seen
                            .iter()
                            .take_while(|(idx, _, _)| *idx == self.old_idx)
                            .count();
                        let new = seen
                            .iter()
                            .filter(|(idx, _, _)| *idx == self.new_idx)
                            .map(|(_, c, ct)| (*c, ct.clone()))
                            .collect();
                        return (old, new);
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("the actor never sent under the new index");
        }

        fn feed_old_keep(&mut self) {
            let E2eFrame::Data {
                counter,
                ciphertext,
                ..
            } = self.peer_old.encrypt_data(&E2eDataBody::Keep).unwrap()
            else {
                panic!()
            };
            self.handle
                .feed_inbound_gen(0, counter, ciphertext)
                .unwrap();
        }

        fn feed_new(&mut self, generation: Generation, body: &E2eDataBody) {
            let E2eFrame::Data {
                counter,
                ciphertext,
                ..
            } = self.peer_new.encrypt_data(body).unwrap()
            else {
                panic!()
            };
            self.handle
                .feed_inbound_gen(generation, counter, ciphertext)
                .unwrap();
        }

        fn feed_new_raw(&mut self, generation: Generation, plain: &[u8]) {
            let E2eFrame::Data {
                counter,
                ciphertext,
                ..
            } = self.peer_new.encrypt_raw(plain).unwrap()
            else {
                panic!()
            };
            self.handle
                .feed_inbound_gen(generation, counter, ciphertext)
                .unwrap();
        }

        /// The actor's last record on the new transport must be its CLOSE: the peer's new
        /// transport decrypts the actor's new records in order from the `skip`th on (records
        /// before it were read already) and the last one is returned.
        fn close_on_new(&mut self, skip: usize) -> (ErrorCode, String) {
            let records: Vec<(u64, Vec<u8>)> = self
                .seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(idx, _, _)| *idx == self.new_idx)
                .skip(skip)
                .map(|(_, c, ct)| (*c, ct.clone()))
                .collect();
            let mut last = None;
            for (counter, ct) in &records {
                last = Some(self.peer_new.decrypt_data(*counter, ct).unwrap());
            }
            match last.expect("a record on the new transport") {
                E2eDataBody::Close { code, msg } => (code, msg),
                other => panic!("not a CLOSE: {other:?}"),
            }
        }

        /// [`Self::ended`] with a tight bound: for a test whose point is that the session
        /// ends at once, not by the slower ACK window or liveness fallback.
        async fn ended_at_once(&mut self) -> Arc<EndReason> {
            tokio::time::timeout(Duration::from_secs(3), self.acceptor.closed())
                .await
                .expect("the session ends at once, not by a timeout")
        }

        async fn ended(&mut self) -> Arc<EndReason> {
            tokio::time::timeout(Duration::from_secs(60), self.acceptor.closed())
                .await
                .expect("the session ends")
        }

        fn is_alive(&mut self) -> bool {
            self.acceptor.ended_rx.try_recv().is_err()
        }

        async fn settled(&self, n: Generation) {
            for _ in 0..1000 {
                if self.handle.settled_generation() == n {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            panic!("never settled at {n}");
        }
    }

    /// CONTINUE as the peer's router would see it: decrypt the actor's first new frame with
    /// the peer's new transport.
    fn decode_continue(peer_new: &mut E2eTransport, counter: u64, ct: &[u8]) -> ContinueBody {
        let plain = peer_new.decrypt_raw(counter, ct).unwrap();
        ContinueBody::decode(&plain).unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn initiator_sends_continue_first_accepts_the_ack_and_drops_the_old_transport() {
        let mut s = solo(true);
        s.collect();
        // One old record before the handover, one after the switch (it keeps counting).
        s.feed_old_keep();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let new = s.actor_new.take().unwrap();
        let g = s
            .handle
            .hand_over(new, HandoverRole::Initiator { prior: 77 });
        assert_eq!(g, 1);
        let (old_sent, new_frames) = s.first_new_frame().await;
        let (counter, ct) = &new_frames[0];
        assert_eq!(*counter, 0, "CONTINUE is the first record");
        let cont = decode_continue(&mut s.peer_new, *counter, ct);
        assert_eq!(cont.prior, 77);
        assert_eq!(
            cont.sent, old_sent as u64,
            "all it sent on the old transport"
        );
        assert_eq!(cont.binding, continue_binding(s.peer_old.handshake_hash()));
        // An old record that arrives after the switch is processed and counted.
        s.feed_old_keep();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            s.handle.settled_generation(),
            0,
            "not settled before the ACK"
        );
        s.feed_new_raw(1, &ContinueAckBody { sent: 2 }.encode());
        s.settled(1).await;
        // The old transport is gone: 50 s later (past the ACK window) the session lives, the
        // peer being kept alive on the new transport; a late old record is dropped.
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            s.feed_new(1, &E2eDataBody::Keep);
        }
        s.feed_old_keep();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(s.is_alive(), "ended: {:?}", s.acceptor.ended_cached);
        // And the new transport carries the session: a CLOSE on it ends it.
        s.feed_new(
            1,
            &E2eDataBody::Close {
                code: ErrorCode::NoGrant,
                msg: String::new(),
            },
        );
        let end = s.ended().await;
        assert!(
            matches!(end.as_ref(), EndReason::PeerClosed { .. }),
            "{end:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn initiator_ends_with_handover_failed_when_the_ack_count_is_wrong() {
        for wrong in [1u64, 3] {
            let mut s = solo(true);
            s.collect();
            s.feed_old_keep();
            s.feed_old_keep();
            tokio::time::sleep(Duration::from_millis(50)).await;
            let new = s.actor_new.take().unwrap();
            s.handle
                .hand_over(new, HandoverRole::Initiator { prior: 2 });
            let (_, new_frames) = s.first_new_frame().await;
            decode_continue(&mut s.peer_new, new_frames[0].0, &new_frames[0].1);
            s.feed_new_raw(1, &ContinueAckBody { sent: wrong }.encode());
            let end = s.ended().await;
            assert!(
                matches!(end.as_ref(), EndReason::HandoverFailed(_)),
                "{end:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Its CLOSE is the second record on the new transport (CONTINUE was the first).
            let (code, _) = s.close_on_new(1);
            assert_eq!(code, ErrorCode::HandoverFailed);
            assert_eq!(s.handle.settled_generation(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn initiator_ends_when_the_first_record_on_the_new_transport_is_not_the_ack() {
        for variant in 0..3 {
            let mut s = solo(true);
            s.collect();
            let new = s.actor_new.take().unwrap();
            s.handle
                .hand_over(new, HandoverRole::Initiator { prior: 2 });
            let (_, new_frames) = s.first_new_frame().await;
            decode_continue(&mut s.peer_new, new_frames[0].0, &new_frames[0].1);
            match variant {
                0 => s.feed_new(1, &E2eDataBody::Keep),
                1 => s.feed_new(1, &E2eDataBody::Mux(vec![0; 12])),
                // A CONTINUE (not an ACK) is as wrong as anything else.
                _ => s.feed_new_raw(
                    1,
                    &ContinueBody {
                        prior: 2,
                        sent: 0,
                        binding: [0; 32],
                    }
                    .encode(),
                ),
            }
            let end = s.ended_at_once().await;
            assert!(
                matches!(end.as_ref(), EndReason::HandoverFailed(_)),
                "variant {variant}: {end:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            let (code, _) = s.close_on_new(1);
            assert_eq!(code, ErrorCode::HandoverFailed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn initiator_reads_the_responders_refusal_as_the_peers_close() {
        let mut s = solo(true);
        s.collect();
        let new = s.actor_new.take().unwrap();
        s.handle
            .hand_over(new, HandoverRole::Initiator { prior: 2 });
        let (_, new_frames) = s.first_new_frame().await;
        decode_continue(&mut s.peer_new, new_frames[0].0, &new_frames[0].1);
        s.feed_new(
            1,
            &E2eDataBody::Close {
                code: ErrorCode::HandoverFailed,
                msg: "no".into(),
            },
        );
        let end = s.ended().await;
        assert!(
            matches!(end.as_ref(), EndReason::PeerClosed { code, .. } if *code == ErrorCode::HandoverFailed),
            "{end:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn initiator_ends_when_no_ack_comes_within_the_liveness_window() {
        let mut s = solo(true);
        s.collect();
        let new = s.actor_new.take().unwrap();
        s.handle
            .hand_over(new, HandoverRole::Initiator { prior: 2 });
        let (_, new_frames) = s.first_new_frame().await;
        decode_continue(&mut s.peer_new, new_frames[0].0, &new_frames[0].1);
        // The peer keeps talking on the old transport (so it is alive) but never ACKs.
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            s.feed_old_keep();
        }
        assert!(s.is_alive(), "30 s is inside the window");
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            s.feed_old_keep();
        }
        let end = s.ended().await;
        assert!(
            matches!(end.as_ref(), EndReason::HandoverFailed(_)),
            "{end:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (code, _) = s.close_on_new(1);
        assert_eq!(code, ErrorCode::HandoverFailed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_second_handover_before_the_ack_and_a_record_of_a_future_transport_end_the_session() {
        let mut s = solo(true);
        s.collect();
        let new = s.actor_new.take().unwrap();
        s.handle
            .hand_over(new, HandoverRole::Initiator { prior: 2 });
        let (_, _) = s.first_new_frame().await;
        let (_a2, b2) = two_sides_indexed(HSEED, 65_535, a_idx(2), b_idx(2));
        s.handle
            .hand_over(b2.transport, HandoverRole::Initiator { prior: 4 });
        let end = s.ended().await;
        assert!(
            matches!(end.as_ref(), EndReason::HandoverFailed(_)),
            "{end:?}"
        );

        let mut s = solo(true);
        s.collect();
        // A reliable record of generation 1 before generation 1 was handed over.
        s.handle.feed_inbound_gen(1, 0, vec![0u8; 40]).unwrap();
        let end = s.ended().await;
        assert!(
            matches!(end.as_ref(), EndReason::HandoverFailed(_)),
            "{end:?}"
        );
    }

    /// The responder side of a solo test: the peer's CONTINUE is read by the test, as the
    /// router does, before the handover item goes in.
    fn responder_handover(s: &mut Solo, old_records: u64, claimed: u64) {
        for _ in 0..old_records {
            s.feed_old_keep();
        }
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = s
            .peer_new
            .encrypt_raw(
                &ContinueBody {
                    prior: s.old_idx,
                    sent: claimed,
                    binding: continue_binding(s.peer_old.handshake_hash()),
                }
                .encode(),
            )
            .unwrap()
        else {
            panic!()
        };
        let mut new = s.actor_new.take().unwrap();
        new.decrypt_raw(counter, &ciphertext).unwrap();
        s.handle.hand_over(
            new,
            HandoverRole::Responder {
                continue_sent: claimed,
            },
        );
    }

    #[tokio::test(start_paused = true)]
    async fn responder_acks_switches_sends_only_on_the_new_transport_and_drops_the_old() {
        let mut s = solo(false);
        s.collect();
        responder_handover(&mut s, 3, 3);
        let (old_sent, new_frames) = s.first_new_frame().await;
        let (counter, ct) = &new_frames[0];
        assert_eq!(*counter, 0, "the ACK is the first record");
        let plain = s.peer_new.decrypt_raw(*counter, ct).unwrap();
        let ack = ContinueAckBody::decode(&plain).unwrap();
        assert_eq!(
            ack.sent, old_sent as u64,
            "all it sent on the old transport"
        );
        s.settled(1).await;
        // From the switch on, everything it sends is on the new transport: a stream, KEEPs
        // (time passes), a CLOSE.
        let mut stream = s.handle.open_stream().await.unwrap();
        {
            use futures_util::io::AsyncWriteExt;
            stream.write_all(b"after the switch").await.unwrap();
            stream.flush().await.unwrap();
        }
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_secs(10)).await;
            s.feed_new(1, &E2eDataBody::Keep);
        }
        // A record of the old transport after the switch is dropped, the session lives.
        s.feed_old_keep();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(s.is_alive());
        s.handle.close(Some(CloseReason {
            code: ErrorCode::NoGrant,
            msg: "bye".into(),
        }));
        let end = s.ended().await;
        assert!(
            matches!(end.as_ref(), EndReason::ClosedLocally(_)),
            "{end:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let seen = s.seen.lock().unwrap().clone();
        let first_new = seen.iter().position(|(i, _, _)| *i == s.new_idx).unwrap();
        assert!(
            seen[first_new..].iter().all(|(i, _, _)| *i == s.new_idx),
            "a frame was sent on the old transport after the switch"
        );
        assert!(
            seen.len() > first_new + 2,
            "the stream and the CLOSE were sent"
        );
        drop(seen);
        // The CLOSE decrypts under the new keys, in order after the ACK and the data.
        let n_new = s
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(i, _, _)| *i == s.new_idx)
            .count();
        // Records 1..n_new-1 are Mux/Keep: decrypt them in order to reach the CLOSE.
        let new_records: Vec<_> = s
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(i, _, _)| *i == s.new_idx)
            .map(|(_, c, ct)| (*c, ct.clone()))
            .collect();
        let mut last = None;
        for (c, ct) in new_records.iter().skip(1) {
            last = Some(s.peer_new.decrypt_data(*c, ct).unwrap());
        }
        assert!(n_new >= 3);
        assert!(
            matches!(last, Some(E2eDataBody::Close { code, .. }) if code == ErrorCode::NoGrant)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn responder_ends_with_handover_failed_when_the_count_differs() {
        for (received, claimed) in [(3u64, 4u64), (3, 2), (0, 1)] {
            let mut s = solo(false);
            s.collect();
            responder_handover(&mut s, received, claimed);
            let end = s.ended().await;
            assert!(
                matches!(end.as_ref(), EndReason::HandoverFailed(_)),
                "{end:?}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
            // Nothing was sent on the old transport after the refusal, and the CLOSE is the
            // first record on the new transport.
            let (code, _) = s.close_on_new(0);
            assert_eq!(code, ErrorCode::HandoverFailed);
            assert_eq!(s.handle.settled_generation(), 0);
        }
    }
}
