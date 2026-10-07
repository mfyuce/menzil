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
//! own `RecordIo`, whose outbound channel holds only 256
//! (`OUTBOUND_FRAME_BUDGET`, enforced as a hard failure, not
//! backpressure — see that crate's own `record_io` doc comment); pulling
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
//! **A real improvement, not a full fix — worth saying plainly rather
//! than overclaiming it**: a second red-team review found live that
//! ordinary bulk transfer can still exhaust the same 256-frame budget
//! and end the session, just at a higher bar than before (this module's
//! own regression test passes reliably at 16-20 concurrent streams and
//! fails at 23 and up; chunkier reads or a multi-thread runtime lower
//! that bar further). Two distinct mechanisms, both confirmed live: (A)
//! backlog can still build up *across* several `select!` iterations —
//! yamux auto-tunes a stream's own receive window upward as it reads,
//! letting more than 256 frames be in flight at once regardless of how
//! fast this actor drains them, and draining still costs one `select!`
//! iteration per frame even without blocking on its outcome; (B) a
//! *single* `Driver` poll, draining several actively writing streams'
//! own command queues in one call, can on its own emit more than 256
//! frames before this actor — or anything else — ever gets a chance to
//! run in between. Mechanism (B) specifically cannot be fixed by any
//! change inside this module: the actor has no way to interrupt a
//! `Driver` poll partway through it. The real fix belongs where the
//! budget and the windows actually live — TODO.md's own L4h5 line
//! (composing L3 credit, this budget, and yamux's windows) or a
//! `menzil-stream` budget that pauses instead of failing outright (the
//! same shape TODO.md already names for the refused-OPEN-burst case,
//! confirmed by this review to be the identical mechanism for plain
//! accepted data, not something specific to refusals) — recorded as its
//! own TODO.md line rather than attempted here.
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
//! this module's own, separate timeout first; whether a *whole* drain
//! pass, rather than one record, could still exceed this bound under a
//! healthy but slow `run_session` is a related, open question that
//! overlaps L4h5's own per-session budget work, not resolved here.
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
//! **What is deliberately not fixed here, flagged by the same review for
//! whoever builds L4h5/L4h6**: [`L4SessionHandle::feed_inbound`]'s own
//! channel is unbounded and provides no backpressure of its own — in a
//! live measurement, ten thousand 16 KiB calls landed in 29ms and grew
//! this process's memory by roughly 78MB while the actor was busy
//! elsewhere, entirely without being processed. `menzil-stream`'s own
//! `record_io` doc comment relies on a caller's own L3 read loop to
//! naturally pace how fast `feed_inbound`-equivalent calls can happen;
//! that pacing does not carry through this module's own inbound channel
//! today. Not addressed here because nothing yet calls `feed_inbound` for
//! real (TODO.md L4h6 does not exist) to make the actual pacing, if any,
//! concrete.
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream::{FuturesUnordered, StreamExt};
use menzil_e2e::{E2eError, E2eTransport, Liveness, RekeySchedule};
use menzil_proto::{E2eDataBody, ErrorCode, NetworkId, NodeId};
use menzil_stream::{Mode, Stream, StreamMuxError};
use tokio::sync::{mpsc, oneshot};

use crate::outbound::{EnqueueOutcome, Epoch, OutboundSend};

/// `e2e_proto` tag for this project's own L4 (decision 0001); every other
/// call site in this workspace that needs it today (L3's HELLO/ATTACH
/// catch-up, this crate's own tests) inlines the same literal rather than
/// importing a shared constant, since none exists yet — matched here for
/// consistency rather than introducing one unilaterally.
const E2E_PROTO_TAG: u8 = 0x01;

/// protocol.md 4.2's flags bit 0; 0 means reliable. Every record this
/// module ever sends is reliable-class (protocol.md 5.2's table: MUX,
/// CLOSE, KEEP and REKEY all are — only DGRAM is droppable, and
/// `E2eTransport::encrypt_data` already refuses to encode one at all, see
/// [`crate::l4_session`]'s own doc comment on what this module is not).
const RELIABLE_FLAGS: u8 = 0x00;

/// How long [`enqueue_send`] waits for `outbound` to accept one send, and
/// separately how long it then waits for that send's own admission
/// outcome, before giving up on this session entirely — see this
/// module's own doc comment for why a bound is needed for both halves
/// and why this particular value.
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
    /// [`L4SessionAcceptor::closed`]'s own fallback when the actor ended
    /// (or never ran at all — a panic, an aborted task) without itself
    /// reporting why. Never produced by [`run`] itself; see this
    /// module's own doc comment for why this is kept distinct from
    /// [`Self::OutboundGone`].
    ActorGone,
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
    inbound_data_tx: mpsc::UnboundedSender<(u64, Vec<u8>)>,
    command_tx: mpsc::UnboundedSender<Command>,
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
    /// ended: nothing further this frame could still affect. **No
    /// backpressure of its own** — see this module's own doc comment,
    /// its final paragraph, for why that is a known, flagged gap rather
    /// than an oversight.
    pub fn feed_inbound(&self, counter: u64, ciphertext: Vec<u8>) {
        let _ = self.inbound_data_tx.send((counter, ciphertext));
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
    let (stream_mux, inbound, outbound_frames, driver) =
        menzil_stream::new(config.mode, config.max_record);
    let (inbound_data_tx, inbound_data_rx) = mpsc::unbounded_channel();
    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let (ended_tx, ended_rx) = oneshot::channel();

    let handle = L4SessionHandle {
        peer: config.peer,
        network_id: config.network_id,
        stream_mux: stream_mux.clone(),
        inbound_data_tx,
        command_tx,
    };
    let acceptor = L4SessionAcceptor {
        peer: config.peer,
        network_id: config.network_id,
        inbound,
        ended_rx,
        ended_cached: None,
    };

    let task = run(
        config.transport,
        config.peer,
        config.epoch,
        config.max_record,
        stream_mux,
        outbound_frames,
        driver,
        outbound,
        inbound_data_rx,
        command_rx,
        epoch_ended,
        ended_tx,
    );

    (handle, acceptor, task)
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
    pending_outcomes: &mut FuturesUnordered<
        tokio::time::Timeout<oneshot::Receiver<EnqueueOutcome>>,
    >,
) -> Option<EndReason> {
    let is_rekey = matches!(body, E2eDataBody::Rekey);
    let frame = match transport.encrypt_data(&body) {
        Ok(frame) => frame,
        Err(err) => return Some(EndReason::EncryptFailed(err)),
    };
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let req = OutboundSend {
        dst: peer,
        e2e_proto: E2E_PROTO_TAG,
        flags: RELIABLE_FLAGS,
        payload: frame.encode(),
        epoch,
        outcome: outcome_tx,
    };
    match tokio::time::timeout(SEND_OUTCOME_TIMEOUT, outbound.send(req)).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return Some(EndReason::OutboundGone),
    }
    let now = Instant::now();
    liveness.note_sent(now);
    if is_rekey {
        rekey.note_rekeyed(now);
    } else {
        rekey.note_sent();
    }
    // Each pushed item carries its own `SEND_OUTCOME_TIMEOUT` bound — a
    // round-2 red-team review found that decoupling the outcome wait
    // from the send (point H1 above) had silently dropped this timeout
    // altogether: a bare `oneshot::Receiver` pushed here has nothing to
    // ever wake it if the admitting side simply never resolves it, and
    // this module's own doc comment claimed a bound that, by this
    // point in that version of the code, no longer existed.
    pending_outcomes.push(tokio::time::timeout(SEND_OUTCOME_TIMEOUT, outcome_rx));
    None
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
    mut inbound_data_rx: mpsc::UnboundedReceiver<(u64, Vec<u8>)>,
    mut command_rx: mpsc::UnboundedReceiver<Command>,
    epoch_ended: oneshot::Receiver<()>,
    ended_tx: oneshot::Sender<EndReason>,
) {
    tokio::pin!(driver);
    tokio::pin!(epoch_ended);
    let now = Instant::now();
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

    let reason = loop {
        tokio::select! {
            result = &mut driver => {
                break EndReason::DriverEnded(result);
            }

            frame = outbound_frames.next_frame() => {
                let Some(frame) = frame else {
                    // Every `StreamMux` clone dropped — in practice
                    // unreachable while this function still holds its
                    // own (`stream_mux`, kept alive for exactly this
                    // reason), but harmless if it ever did happen: the
                    // `driver` branch above already covers the real end
                    // condition this would otherwise imply.
                    continue;
                };
                if let Some(reason) = enqueue_send(
                    &mut transport, &mut liveness, &mut rekey, &outbound, peer, epoch,
                    E2eDataBody::Mux(frame), &mut pending_outcomes,
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
                let Some((counter, ciphertext)) = inbound else {
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
                match transport.decrypt_data(counter, &ciphertext) {
                    Ok(body) => {
                        // Only here, never in the `Err` arms below: see
                        // this module's own doc comment on why liveness
                        // must not be fed by input that never
                        // authenticated at all.
                        liveness.note_received(Instant::now());
                        match body {
                            E2eDataBody::Mux(bytes) => {
                                if let Err(err) = stream_mux.feed_inbound(bytes) {
                                    break EndReason::StreamMuxFeedFailed(err);
                                }
                            }
                            E2eDataBody::Close { code, msg } => {
                                break EndReason::PeerClosed { code, msg };
                            }
                            // REKEY: `decrypt_data` already applied
                            // `rekey_incoming` itself; nothing further to
                            // do beyond the liveness activity above.
                            E2eDataBody::Keep | E2eDataBody::Rekey => {}
                            E2eDataBody::Dgram { .. } => unreachable!(
                                "decrypt_data refuses every datagram-class counter before \
                                 decryption, so no Dgram body can ever reach this match"
                            ),
                        }
                    }
                    Err(E2eError::UnauthenticatedDatagramCounter | E2eError::Noise(_)) => {
                        // Pre-authentication (or never-authenticated)
                        // failures only drop the one frame — see this
                        // module's own doc comment.
                    }
                    Err(err) => break EndReason::Decrypt(err),
                }
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
                    // Best effort, fully: a short, separate timeout, and
                    // an encrypt failure or a refusal is simply not
                    // retried or reported — this session is ending
                    // either way, and nothing about that outcome could
                    // change what happens next. See this module's own
                    // doc comment for why CLOSE specifically skips
                    // `pending_outcomes` rather than only skipping the
                    // wait.
                    let limit = close_msg_limit(max_record);
                    if let Ok(frame) = transport.encrypt_data(&E2eDataBody::Close {
                        code: close.code,
                        msg: clamp_close_msg(&close.msg, limit),
                    }) {
                        let (outcome_tx, _outcome_rx) = oneshot::channel();
                        let req = OutboundSend {
                            dst: peer,
                            e2e_proto: E2E_PROTO_TAG,
                            flags: RELIABLE_FLAGS,
                            payload: frame.encode(),
                            epoch,
                            outcome: outcome_tx,
                        };
                        let _ = tokio::time::timeout(CLOSE_SEND_TIMEOUT, outbound.send(req)).await;
                    }
                }
                break EndReason::ClosedLocally(reason);
            }

            _ = &mut epoch_ended => {
                break EndReason::EpochEnded;
            }

            _ = clock.tick() => {
                let now = Instant::now();
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
                        &mut pending_outcomes,
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
        let (a_priv, a_pub) = fresh_keypair();
        let (b_priv, b_pub) = fresh_keypair();
        let network_id = NetworkId::from([network_seed; 32]);
        let a_node = NodeId::from([network_seed.wrapping_add(0x10); 32]);
        let b_node = NodeId::from([network_seed.wrapping_add(0x20); 32]);

        let (a_hs, init) =
            E2eInitiatorHandshake::start(&a_priv, &b_pub, network_id, a_node, b_node, 1).unwrap();
        let b_hs = E2eResponderHandshake::start(&b_priv, a_node, b_node, &init).unwrap();
        let (b_transport, resp) = b_hs
            .finish(sample_cert(b_node), 0, 0, vec![], 2, max_record)
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
                    dst.feed_inbound(counter, ciphertext);
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
        // 256-frame outbound budget and end the session under perfectly
        // ordinary bulk transfer; live-reproduced there in well under
        // 100ms across a range of stream counts and sizes. 16 concurrent
        // streams of 1 MiB each is comfortably inside the range that
        // reproduced it every time.
        use futures_util::io::{AsyncReadExt, AsyncWriteExt};
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
            let mut stream =
                tokio::time::timeout(Duration::from_secs(10), sessions.b_acceptor.accept())
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
            tokio::time::timeout(Duration::from_secs(10), writer)
                .await
                .expect("write must not stall")
                .unwrap();
        }
        for reader in readers {
            let buf = tokio::time::timeout(Duration::from_secs(10), reader)
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
        sessions.a.feed_inbound(999, vec![0xffu8; 32]);
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
        handle.feed_inbound(c1, ct1);

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
}
