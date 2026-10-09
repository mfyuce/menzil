//! Wires a `yamux::Connection<RecordIo>` into the handles a caller
//! actually uses: [`StreamMux`] (open outbound streams, feed inbound
//! `Mux` records in), [`Inbound`] (accept streams the peer opened),
//! [`OutboundFrames`] (collect the frames this side needs to send), and
//! [`Driver`] (the background task that makes all of the above happen).
//!
//! **Why a background task at all, rather than something synchronous
//! like `menzil-session`/`menzil-e2e`**: see [`crate`]'s own doc comment
//! for the full reasoning. In short, `yamux::Connection` is
//! `futures`-native and must be polled to make progress on an
//! `AsyncRead + AsyncWrite` resource it owns; this crate gives it a
//! fabricated in-memory one ([`crate::record_io::RecordIo`]) and accepts
//! being async itself rather than fighting that shape, matching
//! `menzil-node` (its only realistic caller, per TODO.md's L4h), which is
//! already tokio-based.
//!
//! **Why `Connection::poll_new_outbound` and `poll_next_inbound` cannot
//! simply be called concurrently from two different places**: both take
//! `&mut Connection<T>` and internally replace its whole state
//! (`yamux` 0.14.1's `connection.rs`). [`Driver`] is therefore the single
//! owner of the `Connection`, serializing both concerns itself; opening a
//! stream from [`StreamMux`] is a request/reply handed across a channel
//! to it, the shape this crate's own `yamux` version expects a caller to
//! build (it has no built-in `Control` handle, unlike some other yamux
//! wrapper crates).

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_channel::{mpsc, oneshot};
use futures_util::stream::StreamExt;
use yamux::{Config, Connection, Mode, Stream};

use crate::error::StreamMuxError;
use crate::frame_format::{HEADER_LEN, is_exactly_one_frame};
use crate::record_io::RecordIo;

/// `yamux` 0.14.1's own default (`DEFAULT_SPLIT_SEND_SIZE` in its
/// `lib.rs`), duplicated here since that constant is private to that
/// crate. See [`config_for`]'s doc comment for why this crate needs its
/// value at all. Re-check this against `yamux`'s source if the
/// `Cargo.toml` pin on it ever moves.
const YAMUX_DEFAULT_SPLIT_SEND_SIZE: usize = 16 * 1024;

/// The most streams one connection may hold at once, accepted and
/// outbound together: `yamux` 0.14.1's own default, stated here so the
/// receive-window arithmetic in [`config_for`] does not silently change if
/// that default ever does. Reaching it is fatal to the whole connection
/// (`yamux` ends it, taking every healthy stream along), which is why the
/// layers above should stay well clear of it — TODO.md L4h5.
const MAX_STREAMS: usize = 512;

/// The largest receive window one stream may auto-tune up to: protocol.md
/// 5.3's "tuned upward to 16 MiB within a per session budget". Where that
/// "budget" is the connection-wide growth allowance described on
/// [`config_for`].
const MAX_STREAM_RECEIVE_WINDOW: usize = 16 * 1024 * 1024;

type OpenReply = oneshot::Sender<Result<Stream, StreamMuxError>>;

/// A yamux-multiplexed L4 session's control handle: open outbound
/// streams, and feed it `Mux`-kind [`menzil_proto::E2eDataBody`] records
/// this side has already decrypted. Cheap to clone; every clone talks to
/// the same [`Driver`].
#[derive(Clone)]
pub struct StreamMux {
    open_tx: mpsc::UnboundedSender<OpenReply>,
    inbound_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl StreamMux {
    /// Opens a new outbound yamux stream. Resolves once [`Driver`] has
    /// actually created it locally; this crate stops at the raw stream
    /// (no OPEN/OPEN_ACK exchange — TODO.md L4g builds that on top, not
    /// in it). Always fails as [`StreamMuxError::DriverGone`], never as
    /// [`StreamMuxError::Connection`] directly: a refusal inside `yamux`
    /// itself (stream ids exhausted, too many streams already) ends the
    /// whole connection, not just this one call (see [`Driver`]'s own doc
    /// comment), so by the time this returns, `DriverGone` is simply the
    /// more accurate answer — the real error is what [`Driver`]'s own
    /// future resolves with, for whoever is awaiting that.
    pub async fn open(&self) -> Result<Stream, StreamMuxError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.open_tx
            .unbounded_send(reply_tx)
            .map_err(|_| StreamMuxError::DriverGone)?;
        reply_rx.await.map_err(|_| StreamMuxError::DriverGone)?
    }

    /// Hands `Driver`'s local `yamux::Connection` one inbound `Mux`-kind
    /// body's raw bytes — already decrypted and counter-checked by
    /// `menzil-e2e`, so this is the untrusted-peer-input boundary this
    /// crate specifically owns. Checked against
    /// [`crate::frame_format::is_exactly_one_frame`] first: protocol.md
    /// 5.3 states a `Mux` body *is* one yamux frame, so a record that
    /// isn't exactly one well-formed frame is a peer not speaking this
    /// crate's wire shape, reported rather than guessed at
    /// ([`StreamMuxError::MalformedFrame`]).
    ///
    /// **Ordering contract this crate cannot itself check, found by a
    /// 2026-10-02 red team review**: records must reach this method in
    /// the exact order `menzil-e2e`'s own L4 reliable-class counter
    /// delivered them in. This crate has no counter of its own to verify
    /// that against — two records fed out of order (confirmed live: two
    /// genuinely well-formed frames fed through two different
    /// [`StreamMux`] clones in swapped order) are accepted without error
    /// and silently corrupt whatever stream they belonged to, the exact
    /// harm protocol.md's own reliable-class contiguity rule exists to
    /// prevent one layer below. In practice a caller that decrypts one L3
    /// session's records in a single sequential loop and forwards each
    /// `Mux` body immediately satisfies this for free; `StreamMux` being
    /// [`Clone`] is for spreading *`open()`* across callers, not for
    /// feeding inbound records from more than one place.
    ///
    /// Any error this returns ([`StreamMuxError::MalformedFrame`] or
    /// [`StreamMuxError::DriverGone`]) must be treated as fatal to the L4
    /// session this connection rides on, the same contract
    /// `menzil_e2e::E2eTransport`'s own errors carry: this crate has
    /// already queued nothing and changed no state on this path, but the
    /// caller has, by now, consumed an L4 counter it cannot un-consume
    /// without ending the session.
    ///
    /// Synchronous and never blocks: a successful call only ever queues
    /// `record` for [`Driver`] to actually process on its next poll — see
    /// [`crate::record_io`]'s doc comment for why this particular queue
    /// is still unbounded even though [`OutboundFrames`]'s is not.
    pub fn feed_inbound(&self, record: Vec<u8>) -> Result<(), StreamMuxError> {
        is_exactly_one_frame(&record).map_err(StreamMuxError::MalformedFrame)?;
        self.inbound_tx
            .unbounded_send(record)
            .map_err(|_| StreamMuxError::DriverGone)
    }
}

/// Newly accepted inbound yamux streams — ones the peer opened, which
/// this crate does not itself interpret (no OPEN/OPEN_ACK handling here,
/// see TODO.md L4g). Dropping this does not stop already-open streams
/// from working; it only means [`Driver`] silently drops (closing) any
/// *new* one it accepts afterward, for lack of anywhere to send it — see
/// [`Driver`]'s own doc comment.
pub struct Inbound {
    rx: mpsc::UnboundedReceiver<Stream>,
}

impl Inbound {
    /// Waits for the next inbound stream, or `None` once [`Driver`] has
    /// stopped running (the connection closed cleanly or hit a fatal
    /// error — [`Driver::poll`]'s own `Output` is where that error itself
    /// surfaces, not here).
    pub async fn accept(&mut self) -> Option<Stream> {
        self.rx.next().await
    }
}

/// Produces one yamux frame's raw bytes at a time, ready to carry as
/// [`menzil_proto::E2eDataBody::Mux`] — see [`crate::record_io`]'s doc
/// comment for where these come from and the bound on this channel.
/// **A caller that stops calling [`Self::next_frame`] pauses the
/// connection, it does not break it**: once the channel is full `yamux`
/// stops producing frames (every stream writer then waits in turn) and
/// resumes when draining does. So a caller may take its time, or wait
/// before pulling the next frame for a reason of its own (`menzil-node`
/// waits for send-queue space), with no failure and no loss. Draining
/// fast enough to keep a connection busy is the caller's concern, not a
/// correctness one.
pub struct OutboundFrames {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl OutboundFrames {
    /// Waits for the next outbound frame, or `None` once nothing will
    /// ever produce another one. In practice this means every
    /// [`StreamMux`] clone for this connection has been dropped — that
    /// alone ends [`Driver`] regardless of whether any [`Stream`] handle
    /// is still held (dropping the last `StreamMux` drops this
    /// connection's only inbound feed; `RecordIo` then reads back as EOF,
    /// which `yamux` treats as the connection closing — see
    /// [`crate::record_io`]'s own doc comment). A held `Stream` on an
    /// already-ended `Driver` does not hang: it simply reads back as EOF
    /// and fails to write, the same as on any other closed connection.
    pub async fn next_frame(&mut self) -> Option<Vec<u8>> {
        self.rx.next().await
    }
}

/// Drives one yamux connection. Must be polled to completion — in
/// practice `tokio::spawn`ed, since [`StreamMux::open`], [`Inbound::accept`],
/// [`OutboundFrames::next_frame`], and reading or writing on any [`Stream`]
/// this produces all make progress only while this is being polled (see
/// this module's own doc comment on why `yamux::Connection` needs exactly
/// one dedicated owner).
///
/// Resolves when the underlying connection closes — cleanly (`Ok(())`,
/// e.g. every `StreamMux` clone dropped, or a peer `GoAway`: `yamux`
/// 0.14.1 does not distinguish a graceful `GoAway` from one carrying
/// `protocol_error`/`internal_error`, collapsing both to the same
/// `Ok(())`, confirmed live by a 2026-10-02 red team review — not fixable
/// at this layer without the wire-level code `yamux` itself already
/// discarded by the time this crate sees anything) — or with a fatal
/// [`StreamMuxError`] (this side's own `poll_new_outbound` failing, e.g.
/// too many streams, or a decode/`Io` error on either side's bytes).
/// **Either resolution tears down every [`Stream`] this connection ever
/// produced**, not just ones not yet handed out: `yamux`'s own internal
/// `Cleanup`/`Closed` transition runs on every path, confirmed live by
/// the same review (reads on already-open streams return EOF, writes fail
/// with `WriteZero`) — a caller must not assume a still-held `Stream`
/// stays usable once `Driver` has resolved. Deciding what an ended
/// `Driver` means for the L4 session it rode on (protocol.md 5.2 ties
/// yamux state to one L4 session's lifetime — decision 0001), and
/// building any explicit "end this session now" control beyond dropping
/// every `StreamMux` clone, is TODO.md L4h's job, not this crate's — this
/// crate exposes no such method itself yet.
pub struct Driver {
    connection: Connection<RecordIo>,
    open_requests: mpsc::UnboundedReceiver<OpenReply>,
    pending_open_reply: Option<OpenReply>,
    inbound_tx: mpsc::UnboundedSender<Stream>,
}

impl Future for Driver {
    type Output = Result<(), StreamMuxError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            if this.pending_open_reply.is_none()
                && let Poll::Ready(Some(reply)) = this.open_requests.poll_next_unpin(cx)
            {
                this.pending_open_reply = Some(reply);
            }
            if let Some(reply) = this.pending_open_reply.take() {
                match this.connection.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        // A dropped receiver only means `StreamMux::open`'s
                        // caller stopped waiting (e.g. it was cancelled);
                        // the stream `yamux` just created is then simply
                        // dropped here, closing it the same way dropping
                        // any other unused `Stream` handle would.
                        let _ = reply.send(Ok(stream));
                        // Without this, a *second* `open()` request already
                        // sitting in `open_requests` when this one resolved
                        // would hang until some unrelated event happens to
                        // wake this `Driver` again — `UnboundedReceiver`
                        // only registers a waker on a `Pending` poll, and
                        // the one above (which found this reply) did not
                        // produce one. Confirmed live by a 2026-10-02 red
                        // team review before this `continue` existed: two
                        // concurrent `open()` calls on an otherwise idle
                        // connection, the second hanging indefinitely.
                        continue;
                    }
                    Poll::Ready(Err(e)) => {
                        // `yamux` 0.14.1 always transitions to `Cleanup`
                        // (then `Closed`) on *any* `poll_new_outbound`
                        // error (confirmed against its own
                        // `connection.rs`), so the whole connection is
                        // already dead, not just this one `open()` call —
                        // the same review confirmed live that silently
                        // reporting only to this one caller let a refused
                        // 513th stream (yamux's own 512-stream cap) drop
                        // 512 already-open, healthy streams with no error
                        // surfaced anywhere. Dropping `reply` without
                        // sending resolves this caller's `open()` as
                        // `StreamMuxError::DriverGone`, accurate since this
                        // `Driver` is about to actually stop; the real
                        // error goes out through `Driver`'s own `Output`
                        // instead, for whoever is awaiting that.
                        drop(reply);
                        return Poll::Ready(Err(e.into()));
                    }
                    Poll::Pending => this.pending_open_reply = Some(reply),
                }
            }

            match this.connection.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    // A dropped `Inbound` means nobody is listening for
                    // *new* streams anymore; streams already handed out
                    // keep working regardless, so this is not fatal to
                    // the connection — only to this one freshly accepted
                    // stream, dropped (closing it) for lack of anywhere
                    // to send it.
                    let _ = this.inbound_tx.unbounded_send(stream);
                    continue;
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e.into())),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => {}
            }

            return Poll::Pending;
        }
    }
}

/// Builds a fresh yamux connection adapter for one L4 session. Returns,
/// in order: [`StreamMux`] (open outbound streams, feed inbound records
/// in), [`Inbound`] (accept streams the peer opens), [`OutboundFrames`]
/// (collect frames to send), and [`Driver`], which a caller must run (in
/// practice `tokio::spawn`) for any of the first three to make progress.
///
/// `mode` is yamux's own client/server split, used only to keep each
/// side's locally chosen stream ids disjoint (odd vs. even); it is not
/// protocol.md 5.1's initiator/responder distinction, only needs to agree
/// with it: the L4 initiator (who sent `init`) must pass [`Mode::Client`],
/// the responder [`Mode::Server`]. Observed while testing this crate, for
/// whichever future item (TODO.md L4g) assigns meaning to stream ids:
/// `yamux` 0.14.1's [`Mode::Client`] accepts a peer-opened stream with id
/// `0` without complaint, so `0` is not a safe sentinel for "no stream"
/// the way it is for yamux's own internal `CONNECTION_ID`.
///
/// `max_record` is this L4 session's own record ceiling — ultimately
/// WELCOME's `limits.max_record` (protocol.md 4.1), the same value
/// `menzil_e2e::E2eTransport` was itself built with — used only to shrink
/// yamux's own `split_send_size` when necessary, never to grow it: see
/// [`config_for`]. It does *not* otherwise tune how much data a stream or
/// this connection may buffer — see [`config_for`]'s own doc comment for
/// the gap that leaves.
pub fn new(mode: Mode, max_record: u32) -> (StreamMux, Inbound, OutboundFrames, Driver) {
    let (record_io, inbound_tx, outbound_rx) = RecordIo::new();
    let (open_tx, open_requests) = mpsc::unbounded();
    let (stream_inbound_tx, stream_inbound_rx) = mpsc::unbounded();

    let connection = Connection::new(record_io, config_for(max_record), mode);

    let stream_mux = StreamMux {
        open_tx,
        inbound_tx,
    };
    let inbound = Inbound {
        rx: stream_inbound_rx,
    };
    let outbound = OutboundFrames { rx: outbound_rx };
    let driver = Driver {
        connection,
        open_requests,
        pending_open_reply: None,
        inbound_tx: stream_inbound_tx,
    };

    (stream_mux, inbound, outbound, driver)
}

/// yamux's own built-in default data-frame payload size (16 KiB,
/// [`YAMUX_DEFAULT_SPLIT_SEND_SIZE`]) exists upstream to limit head of
/// line blocking across streams and keep small, time-sensitive frames
/// (window updates, pings) from queuing behind one large data write — see
/// that constant's own doc comment. This function keeps it whenever it
/// already fits inside one `Mux` record for `max_record`; only a
/// `max_record` too small for that default forces a smaller
/// `split_send_size`, computed so that every data frame `yamux` produces
/// fits in one record (one byte for `menzil_proto::E2eDataBody::Mux`'s
/// own kind-byte prefix, [`HEADER_LEN`] bytes for yamux's own frame
/// header, both subtracted from
/// `menzil_proto::max_e2e_data_plaintext(max_record)`), clamped to at
/// least one byte so the arithmetic never panics. That guarantee holds
/// for any `max_record` an actual L4 handshake could produce (a
/// 2026-10-02 red team review measured the real encoded `init` payload at
/// 133 bytes, putting the smallest *possible* session's `max_record`
/// around 184 — `menzil-e2e`'s own handshake would not even complete
/// below that); it does *not* hold all the way down to `max_record`
/// values with no realistic session behind them at all (the same review
/// found the true breakeven at 94, below which `split_send_size` ends up
/// too small for yamux to make any real progress with, one byte at a
/// time) — this function still returns a `Config` rather than erroring in
/// that case, since "unusably slow" and "impossible" are different
/// claims and nothing downstream has ever asked this function to tell
/// them apart.
///
/// **The receive-window ceiling (TODO.md L4h5, closing the L4f review's
/// finding that protocol.md 5.3's 16 MiB ceiling was "fully unenforced,
/// not merely untuned")**: `yamux` 0.14.1 has no per-stream ceiling, only
/// a connection-wide `max_connection_receive_window` (1 GiB by default;
/// one stream over a simulated 50&nbsp;ms RTT was seen reaching a
/// 48&nbsp;MiB grant with nothing intervening). Its meaning, read from
/// `flow_control.rs`: every stream is guaranteed [`yamux::DEFAULT_CREDIT`]
/// (256 KiB) for each of the [`MAX_STREAMS`] slots, and only what the
/// configured total has *left over* after that — the "growth budget",
/// shared by all streams on the connection — may be spent on auto-tuning
/// any stream's window above its 256 KiB. One stream can claim all of it,
/// so choosing the growth budget as `MAX_STREAM_RECEIVE_WINDOW - 256 KiB`
/// caps **every** stream at [`MAX_STREAM_RECEIVE_WINDOW`] (protocol.md
/// 5.3's 16 MiB), however few streams are open, and caps the *sum* of all
/// growth at the same figure: the "per session budget". The most this
/// session can ever be made to buffer unread is then the guaranteed share
/// of every stream slot plus that one growth budget — about 144 MiB, down
/// from the 1 GiB it was (128 MiB guaranteed plus 896 MiB of growth).
/// That is the deliberate answer to protocol.md 14's open item 2 for
/// phase 1: the *policy* of when a window grows is still `yamux`'s own
/// (double when the sender used half of it within two round trips), only
/// its ceiling is ours.
///
/// This is a receive-side figure, independent of the send-side queue
/// budgets (`menzil-node`'s `SendBudget`): how much a peer may have in
/// flight *toward* us is what we grant it; how much we have queued toward
/// the peer is what the peer grants us, held to a different, lower number
/// by `SendBudget` regardless of what any peer grants.
fn config_for(max_record: u32) -> Config {
    let record_budget = menzil_proto::max_e2e_data_plaintext(max_record);
    let max_body_for_this_session = record_budget
        .saturating_sub(1)
        .saturating_sub(HEADER_LEN)
        .max(1);
    let split_send_size = YAMUX_DEFAULT_SPLIT_SEND_SIZE.min(max_body_for_this_session);

    let guaranteed = MAX_STREAMS * yamux::DEFAULT_CREDIT as usize;
    let growth_budget = MAX_STREAM_RECEIVE_WINDOW - yamux::DEFAULT_CREDIT as usize;

    let mut cfg = Config::default();
    cfg.set_split_send_size(split_send_size);
    cfg.set_max_num_streams(MAX_STREAMS);
    cfg.set_max_connection_receive_window(Some(guaranteed + growth_budget));
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Config`'s fields are all private, but it does implement `Debug`
    /// (a 2026-10-02 red team review's own observation) — this reads
    /// `split_send_size`'s actual configured value back out of that,
    /// rather than only proving `config_for` doesn't panic the way this
    /// module's tests previously did.
    fn configured_split_send_size(cfg: &Config) -> usize {
        let debug = format!("{cfg:?}");
        let marker = "split_send_size: ";
        let start = debug
            .find(marker)
            .expect("yamux::Config's Debug format changed shape; update this test helper")
            + marker.len();
        let end = debug[start..]
            .find(|c: char| !c.is_ascii_digit())
            .map_or(debug.len(), |i| start + i);
        debug[start..end]
            .parse()
            .expect("split_send_size's Debug value was not a plain integer")
    }

    #[test]
    fn a_generous_max_record_keeps_yamuxs_own_default_split_size() {
        // 65_535 is WELCOME's own wire ceiling (the Noise message limit),
        // the same generous default `menzil_e2e`'s own tests use.
        let budget = menzil_proto::max_e2e_data_plaintext(65_535);
        assert!(
            budget - 1 - HEADER_LEN > YAMUX_DEFAULT_SPLIT_SEND_SIZE,
            "this test's premise (a generous max_record easily beats yamux's own 16 KiB \
             default) no longer holds — re-check config_for's clamp direction"
        );
        assert_eq!(
            configured_split_send_size(&config_for(65_535)),
            YAMUX_DEFAULT_SPLIT_SEND_SIZE
        );
    }

    #[test]
    fn a_small_max_record_shrinks_the_split_size_to_fit_one_record() {
        let max_record = 1024u32;
        let budget = menzil_proto::max_e2e_data_plaintext(max_record);
        let expected = budget.saturating_sub(1).saturating_sub(HEADER_LEN).max(1);
        assert!(
            expected < YAMUX_DEFAULT_SPLIT_SEND_SIZE,
            "this test's premise (max_record small enough to actually force shrinking) \
             no longer holds for max_record={max_record}: budget={budget}"
        );
        assert_eq!(
            configured_split_send_size(&config_for(max_record)),
            expected
        );
    }

    /// Reads one numeric `Config` field back out of its `Debug` output —
    /// see [`configured_split_send_size`] for why that is the only way.
    fn configured_usize(cfg: &Config, field: &str) -> usize {
        let debug = format!("{cfg:?}");
        let marker = format!("{field}: ");
        let start = debug
            .find(&marker)
            .unwrap_or_else(|| panic!("yamux::Config's Debug format lost `{field}`"))
            + marker.len();
        let rest = &debug[start..];
        // `Some(123)` for an `Option`, a bare `123` otherwise.
        let rest = rest.strip_prefix("Some(").unwrap_or(rest);
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().expect("a plain integer")
    }

    #[test]
    fn one_stream_can_grow_to_the_spec_ceiling_and_no_further() {
        // protocol.md 5.3: 256 KiB initially, tuned up to 16 MiB. The
        // growth budget (what the connection total leaves after every
        // stream slot's guaranteed 256 KiB) is the most any single stream
        // can add to its own window, so it must be exactly the difference.
        let cfg = config_for(65_535);
        let total = configured_usize(&cfg, "max_connection_receive_window");
        let slots = configured_usize(&cfg, "max_num_streams");
        let growth = total - slots * yamux::DEFAULT_CREDIT as usize;
        assert_eq!(slots, MAX_STREAMS);
        assert_eq!(
            yamux::DEFAULT_CREDIT as usize + growth,
            MAX_STREAM_RECEIVE_WINDOW,
            "a lone stream's ceiling"
        );
    }

    #[test]
    fn a_zero_max_record_clamps_to_one_byte_rather_than_panicking() {
        assert_eq!(menzil_proto::max_e2e_data_plaintext(0), 0);
        assert_eq!(configured_split_send_size(&config_for(0)), 1);
    }
}
