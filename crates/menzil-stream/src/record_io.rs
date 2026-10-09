//! The in-memory stand-in for a real socket that `yamux::Connection` runs
//! over in this crate ([`crate`]'s own doc comment explains why a real
//! socket is never involved at all: everything this crate touches is
//! already just `Mux`-kind [`menzil_proto::E2eDataBody`] records, handed
//! to and from a caller that owns the actual encrypted transport one
//! layer below, in `menzil-e2e`).
//!
//! [`RecordIo`] turns `yamux`'s own byte-oriented
//! `AsyncRead`/`AsyncWrite` expectations into exactly what this crate
//! actually has on each side: a channel of already-decrypted inbound
//! frames to read from, and a channel of freshly produced outbound frames
//! to hand to whatever encrypts and sends them. The inbound side needs
//! only to reassemble `poll_read`'s byte-at-a-time contract out of
//! whole frames it is fed (`yamux`'s own frame reader tolerates arbitrary
//! chunking, same as any `AsyncRead` consumer must); the outbound side is
//! where this crate's one real piece of protocol logic lives — see
//! [`crate::frame_format`]'s doc comment for why `poll_write`'s input
//! cannot simply be forwarded as-is and has to be re-split into
//! individual frames by parsing yamux's own wire header.
//!
//! **Outbound backpressure: a full channel pauses `yamux`, it never ends
//! the connection** (TODO.md L4h5). A 2026-10-02 red team review of this
//! crate found that an earlier version queued outbound frames on an
//! *unbounded* channel, reasoning (wrongly — the review's own live tests
//! disproved it) that L3's own send queue and credit system (TODO.md L4b)
//! would bound it from below. Two concrete, confirmed counterexamples: an
//! authenticated peer flooding this side with a million bare `Ping`
//! frames queued a million `Pong` replies before this side's own L3
//! credit ever entered the picture; and a peer granting a generous
//! flow-control window on a stream, combined with a *local* writer that
//! keeps writing while nothing drains [`crate::OutboundFrames`] (e.g.
//! because the L3 session is itself credit-starved), queued unbounded
//! local data the same way. Neither scenario needs a malicious peer in
//! the "attacker breaks the protocol" sense — both are well-formed yamux
//! traffic.
//!
//! That review's fix was a bounded channel whose [`RecordIo::poll_write`]
//! *failed* the moment the channel was full, on the stated belief that
//! `yamux`'s `Active::poll` does not expect a socket write to stall while
//! the connection still makes other progress. Three later reviews
//! (TODO.md L4h3's rounds 1 and 2, L4h4's round 2) each found that this
//! hard failure ended perfectly healthy sessions under ordinary load —
//! 23 or more concurrently writing streams, or 129 concurrently refused
//! OPENs, were enough, because a single `Driver` poll can drain several
//! streams' own command queues into this channel before anything
//! downstream gets to run — and TODO.md L4h5 re-read `yamux` 0.14.1's
//! source to check the belief itself, which turned out to be wrong for
//! this version: `Active::poll` (`connection.rs`) only starts writing a
//! frame when `Sink::poll_ready` on its `frame::Io` is ready, holds at
//! most one `pending_write_frame` and one `pending_read_frame` (the reply
//! to a Ping, or a GoAway), and polls neither the per-stream command
//! channels (while a write frame is pending) nor the socket's read side
//! (while a reply is pending) until they are written. A `Pending` write is
//! the ordinary case for a real TCP socket with a full send buffer, and
//! `yamux` already turns it into exactly the backpressure this crate
//! needs: every stream writer eventually blocks on its own bounded command
//! channel, and a Ping flood stops being *read* until the Pong goes out,
//! so `yamux`'s own queues stay bounded without this crate failing
//! anything. So [`RecordIo::poll_write`] now returns `Poll::Pending`, with
//! the consumer's drain as its wakeup, when the channel has no room for a
//! frame the write would complete, and the connection simply stalls until
//! [`crate::OutboundFrames`] is drained again. Nothing is lost and nothing
//! ends.
//!
//! Two properties make that safe, and are what the tests in this file and
//! `tests/backpressure.rs` pin down:
//!
//! * **A `Pending` write consumes nothing.** `yamux` re-presents the same
//!   slice on its next poll (`frame::Io::poll_ready` indexes
//!   `&buffer[*offset..]`), so any byte a `Pending` return had already
//!   taken would be written twice. The previous implementation took the
//!   bytes first and only then discovered the channel was full, which is
//!   also the root cause of TODO.md's "misleading `unsupported yamux frame
//!   version N`" line: the retried body bytes were re-parsed as a header.
//!   [`RecordIo::poll_write`] therefore decides *before* touching
//!   [`RecordIo::outbound_partial`] whether the bytes it is about to take
//!   complete a frame, and reserves room for that frame first.
//! * **At most one frame is ever under construction.** A write call takes
//!   only as many bytes as finish the frame in progress (a partial write
//!   is legal `AsyncWrite` behavior and `yamux` loops on it), so there is
//!   never a queue of completed-but-unsent frames to bound, and memory
//!   held here stays at one frame however a caller chunks its writes.
//!
//! The channel's capacity is [`OUTBOUND_FRAME_BUDGET`] frames (plus the
//! one slot every `futures` mpsc sender is guaranteed). It is no longer a
//! fatal limit, only how much may sit between `yamux` and whatever drains
//! [`crate::OutboundFrames`] — which is also latency: a frame queued behind
//! a full channel of bulk data waits for all of it, since `yamux`'s output
//! is FIFO across streams.
//!
//! The *inbound* direction (fed by [`crate::StreamMux::feed_inbound`])
//! is deliberately left unbounded still, on narrower reasoning the same
//! review flagged as worth stating explicitly rather than assuming: each
//! inbound record already corresponds to one L4 reliable-class counter
//! `menzil-e2e` only advances after a successful decrypt, so a caller
//! cannot "re-queue" a `feed_inbound` call it already made without
//! violating that counter's own contiguity — meaning an inbound bound
//! cannot be a `Poll::Pending`-style retry either, only an immediate
//! fatal rejection at the point of the call (which
//! [`crate::StreamMux::feed_inbound`]'s malformed-frame check already
//! gives a shape for). This crate does not add that bound yet, but
//! **the argument it was left on is no longer true**, found by TODO.md
//! L4h5's own review: it said no growth scenario existed and that a
//! caller's own read loop paces `feed_inbound`, nothing a remote peer
//! controls. That held while a stalled outbound channel failed the whole
//! connection (the stall could not last). Now that it pauses `yamux`
//! instead, there is a window: while a Pong (or GoAway) is pending,
//! `yamux` stops reading its input (`Active::poll` only reads while
//! `pending_read_frame` is empty), and a peer that stops reading from its
//! relay connection starves this side of credit, which keeps a frame
//! staged in `menzil-node`'s actor and the channel full for up to its 35 s
//! reservation timeout; meanwhile the actor keeps decrypting and calling
//! `feed_inbound`, and the peer's flood (bare Pings are enough) piles up
//! here, limited only by link speed times that timeout. The
//! `a_ping_flood_with_nothing_draining...` test shows the mechanism (50,000
//! Pings fed, at most 65 Pongs out, the rest unread inbound); the
//! end-to-end path is reasoning, not a measured run. Not fixed here: the
//! bound belongs with the caller that can pace its source (TODO.md L4h6,
//! which now carries this scenario), or as the immediate fatal rejection
//! sketched above.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_channel::mpsc;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::StreamExt;

use crate::frame_format::{FrameFormatError, HEADER_LEN, declared_frame_len};

/// How many outbound frames may sit in the channel between
/// [`RecordIo::poll_write`] and whatever drains [`crate::OutboundFrames`]
/// before `yamux` is paused — see this module's own doc comment for why a
/// full channel pauses rather than fails.
///
/// Sized for latency, not for throughput (TODO.md L4h5). Backpressure
/// makes any size safe, and a larger one buys nothing: at `yamux`'s
/// default 16 KiB split size this is about 1 MiB of frames, one WELCOME
/// credit window (protocol.md 4.1's default), which is already as much as
/// the relay would let through per round trip — and every byte that waits
/// here delays everything queued behind it, `yamux`'s output being FIFO
/// across streams (a keystroke on one stream waits for the bulk data of
/// another that got here first). It was 256 (about 4 MiB) while this
/// limit was a hard failure and the number had to be big enough not to
/// trip. A session configured with a smaller `max_record` (see
/// [`crate::driver::config_for`]) packs more, smaller frames into the
/// same count, so the memory bound only gets tighter.
const OUTBOUND_FRAME_BUDGET: usize = 64;

/// The `T` in this crate's `yamux::Connection<T>`. See this module's own
/// doc comment.
pub(crate) struct RecordIo {
    inbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// The most recently received frame not yet fully consumed by
    /// `poll_read`, and how far into it we already are — avoids an O(n)
    /// shift on every partial read the way draining from the front of a
    /// `VecDeque<u8>` would.
    inbound_current: Vec<u8>,
    inbound_pos: usize,
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// The leading bytes of the one frame `yamux` is currently writing,
    /// accepted by `poll_write` but not yet complete. Never holds more
    /// than that one frame (see this module's own doc comment), and never
    /// holds a *complete* frame: the moment a write completes one it is
    /// handed to `outbound_tx` and this is emptied.
    outbound_partial: Vec<u8>,
}

impl RecordIo {
    /// Builds a fresh adapter plus the two channel ends a caller needs to
    /// actually feed it inbound frames and collect outbound ones: `Self`
    /// is the only part `yamux::Connection::new` ever sees.
    pub(crate) fn new() -> (
        Self,
        mpsc::UnboundedSender<Vec<u8>>,
        mpsc::Receiver<Vec<u8>>,
    ) {
        let (inbound_tx, inbound_rx) = mpsc::unbounded();
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_FRAME_BUDGET);
        (
            Self {
                inbound_rx,
                inbound_current: Vec::new(),
                inbound_pos: 0,
                outbound_tx,
                outbound_partial: Vec::new(),
            },
            inbound_tx,
            outbound_rx,
        )
    }

    /// How many leading bytes of `buf` belong to the frame currently under
    /// construction (the one `outbound_partial` already holds the start
    /// of), and whether taking exactly that many completes it. Looks at
    /// `outbound_partial` and `buf` without changing either.
    fn frame_share(&self, buf: &[u8]) -> Result<(usize, bool), FrameFormatError> {
        let have = self.outbound_partial.len();

        // The frame's declared length is known as soon as its 12 header
        // bytes are, and those may straddle `outbound_partial` and `buf`
        // (yamux writes a header and its body as separate calls, but this
        // type does not rely on how it chunks them).
        let mut header = [0u8; HEADER_LEN];
        let from_partial = have.min(HEADER_LEN);
        header[..from_partial].copy_from_slice(&self.outbound_partial[..from_partial]);
        let from_buf = (HEADER_LEN - from_partial).min(buf.len());
        header[from_partial..from_partial + from_buf].copy_from_slice(&buf[..from_buf]);

        match declared_frame_len(&header[..from_partial + from_buf])? {
            // Not even the header is complete after taking all of `buf`:
            // every byte belongs to this frame and none of them finishes
            // it.
            None => Ok((buf.len(), false)),
            Some(total) => {
                // `have < total` always holds here: `outbound_partial` is
                // emptied the moment it completes a frame, and never takes
                // more than the frame in progress needs.
                let needed = total - have;
                if buf.len() >= needed {
                    Ok((needed, true))
                } else {
                    Ok((buf.len(), false))
                }
            }
        }
    }
}

impl AsyncRead for RecordIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.inbound_pos >= this.inbound_current.len() {
            match this.inbound_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(frame)) => {
                    this.inbound_current = frame;
                    this.inbound_pos = 0;
                }
                // Every `StreamMux` clone (the only inbound feeder) was
                // dropped: there is nothing more this side will ever
                // receive. A clean EOF, not an error — `yamux`'s own
                // reader treats this exactly like a closed socket.
                Poll::Ready(None) => return Poll::Ready(Ok(0)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let remaining = &this.inbound_current[this.inbound_pos..];
        let n = buf.len().min(remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        this.inbound_pos += n;
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for RecordIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // `yamux::Connection` is the only writer this type ever has, so a
        // malformed header here is this crate's own bug (or a mismatch
        // against a future `yamux` version that changed its wire format),
        // never peer input — still surfaced as a normal I/O error rather
        // than a panic, since a caller may well choose to treat it the
        // same as any other fatal connection error.
        let (take, completes) = match this.frame_share(buf) {
            Ok(share) => share,
            Err(e) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("menzil-stream's own yamux::Connection wrote a malformed frame: {e}"),
                )));
            }
        };

        if completes {
            // Reserve room for the frame these bytes finish *before*
            // taking any of them: a `Pending` return must leave this type
            // exactly as it was (see this module's own doc comment).
            match this.outbound_tx.poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(_)) => {
                    // Nobody will ever read another frame (the
                    // `OutboundFrames` handle for this session was
                    // dropped, e.g. because the L4 session already ended)
                    // — dropping this one below is correct, not a write
                    // failure `yamux`'s own `Sink` impl should see and
                    // react to.
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        this.outbound_partial.extend_from_slice(&buf[..take]);
        if completes {
            let frame = std::mem::take(&mut this.outbound_partial);
            // Cannot fail for lack of room (reserved above); a
            // disconnected receiver is the same swallow-and-succeed case.
            let _ = this.outbound_tx.start_send(frame);
        }
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Nothing is ever buffered here beyond one frame still being
        // assembled, which is not flushable by definition (a partial
        // frame is not a unit anything downstream can send).
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use std::time::Duration;

    fn ping(id: u32) -> Vec<u8> {
        let mut buf = vec![0u8, 2, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&id.to_be_bytes());
        buf
    }

    /// Writes `ping(0)`, `ping(1)`, ... until one would have to wait,
    /// returning how many were accepted. `now_or_never` polls once with a
    /// no-op waker, so `None` means that write returned `Pending`.
    fn fill_until_pending(io: &mut RecordIo) -> u32 {
        let mut accepted = 0;
        loop {
            match io.write(&ping(accepted)).now_or_never() {
                Some(Ok(n)) => {
                    assert_eq!(n, 12);
                    accepted += 1;
                }
                Some(Err(e)) => panic!("a full channel must pause the write, not fail it: {e}"),
                None => return accepted,
            }
            assert!(
                accepted < OUTBOUND_FRAME_BUDGET as u32 * 2,
                "the channel never filled up"
            );
        }
    }

    #[tokio::test]
    async fn a_write_larger_than_one_frame_splits_into_each_complete_frame() {
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();

        // Two bare Ping frames (header-only, tag 2) back to back, written
        // in one `write_all` call — `yamux` itself never actually does
        // this (it writes a header then a body as separate calls, see
        // this crate's own `frame_format` doc comment), but `RecordIo`
        // must not assume that and should still split correctly either
        // way, since it reassembles from raw bytes, not write-call
        // boundaries.
        let mut both = ping(1);
        both.extend_from_slice(&ping(2));
        io.write_all(&both).await.unwrap();

        assert_eq!(outbound_rx.next().await.unwrap(), ping(1));
        assert_eq!(outbound_rx.next().await.unwrap(), ping(2));
    }

    #[tokio::test]
    async fn a_write_spanning_two_frames_takes_only_the_first() {
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();
        let mut both = ping(1);
        both.extend_from_slice(&ping(2));

        // A partial write is legal `AsyncWrite` behavior (`write_all` and
        // `yamux` both loop on it) and is what keeps "this call completes
        // a frame" and "that frame has somewhere to go" a single decision.
        assert_eq!(io.write(&both).await.unwrap(), 12);
        assert_eq!(outbound_rx.next().await.unwrap(), ping(1));
        assert!(outbound_rx.next().now_or_never().is_none());
    }

    #[tokio::test]
    async fn a_write_split_across_many_small_calls_still_reassembles_one_frame() {
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();
        let mut frame = vec![0u8, 0, 0, 0, 0, 0, 0, 0]; // Data, stream 0
        frame.extend_from_slice(&4u32.to_be_bytes()); // body len 4
        frame.extend_from_slice(b"abcd");

        for byte in &frame {
            io.write_all(std::slice::from_ref(byte)).await.unwrap();
        }

        assert_eq!(outbound_rx.next().await.unwrap(), frame);
    }

    #[tokio::test]
    async fn feeding_one_frame_then_reading_in_small_pieces_reassembles_it() {
        let (mut io, inbound_tx, _outbound_rx) = RecordIo::new();
        let frame = vec![1, 2, 3, 4, 5];
        inbound_tx.unbounded_send(frame.clone()).unwrap();

        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        for _ in 0..frame.len() {
            let n = io.read(&mut byte).await.unwrap();
            assert_eq!(n, 1);
            out.push(byte[0]);
        }
        assert_eq!(out, frame);
    }

    #[tokio::test]
    async fn dropping_every_inbound_feeder_reads_back_as_a_clean_eof() {
        let (mut io, inbound_tx, _outbound_rx) = RecordIo::new();
        drop(inbound_tx);
        let mut buf = [0u8; 8];
        assert_eq!(io.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn a_full_channel_pauses_the_write_instead_of_failing_it() {
        // `_outbound_rx` is deliberately never drained: the scenario a
        // 2026-10-02 red team review of this crate confirmed as a real,
        // unbounded memory-growth risk before any bound existed (DONE.md's
        // L4f entry), and which the hard-failure bound that followed
        // answered by ending healthy sessions instead (TODO.md L4h3/L4h5).
        // The channel holds its budget plus the one slot every `futures`
        // sender is guaranteed.
        let (mut io, _inbound_tx, _outbound_rx) = RecordIo::new();
        let accepted = fill_until_pending(&mut io);
        assert!(
            (OUTBOUND_FRAME_BUDGET as u32..=OUTBOUND_FRAME_BUDGET as u32 + 1).contains(&accepted),
            "expected about {OUTBOUND_FRAME_BUDGET} frames to fit, got {accepted}"
        );
        // Still paused, not failed, however many more times it is asked.
        for _ in 0..10 {
            assert!(io.write(&ping(9_999)).now_or_never().is_none());
        }
    }

    #[tokio::test]
    async fn a_paused_write_consumes_nothing_and_resumes_with_no_duplicate_or_gap() {
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();
        let accepted = fill_until_pending(&mut io);
        assert!(
            io.outbound_partial.is_empty(),
            "a Pending write must take no bytes"
        );

        // Make room for exactly one frame, then retry the very same write.
        assert_eq!(outbound_rx.next().await.unwrap(), ping(0));
        assert_eq!(io.write(&ping(accepted)).await.unwrap(), 12);

        // Everything arrives exactly once, in order.
        let mut received = Vec::new();
        for _ in 1..=accepted {
            received.push(outbound_rx.next().await.unwrap());
        }
        let expected: Vec<Vec<u8>> = (1..=accepted).map(ping).collect();
        assert_eq!(received, expected);
        assert!(outbound_rx.next().now_or_never().is_none());
    }

    #[tokio::test]
    async fn a_data_frame_whose_body_write_pauses_resumes_with_the_same_body() {
        // The shape behind TODO.md's "unsupported yamux frame version N"
        // line: `yamux` writes a Data frame's header and body as two calls.
        // The old implementation took the body bytes before discovering
        // the channel was full, so the retry re-appended them and the
        // duplicate was parsed as a header whose first byte (here 0xAB)
        // was reported as the frame version.
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();
        let accepted = fill_until_pending(&mut io);

        let mut header = vec![0u8, 0, 0, 0, 0, 0, 0, 0]; // Data, stream 0
        header.extend_from_slice(&4u32.to_be_bytes());
        // The header alone completes nothing, so it needs no room.
        assert_eq!(io.write(&header).now_or_never().unwrap().unwrap(), 12);
        // The body completes the frame, so it must wait.
        assert!(io.write(b"\xABcde").now_or_never().is_none());
        assert_eq!(
            io.outbound_partial, header,
            "the paused body must not be half-taken"
        );

        assert_eq!(outbound_rx.next().await.unwrap(), ping(0));
        assert_eq!(io.write(b"\xABcde").await.unwrap(), 4);

        for expected in (1..accepted).map(ping) {
            assert_eq!(outbound_rx.next().await.unwrap(), expected);
        }
        let mut frame = header;
        frame.extend_from_slice(b"\xABcde");
        assert_eq!(outbound_rx.next().await.unwrap(), frame);
    }

    #[tokio::test]
    async fn a_waiting_writer_is_woken_by_the_consumer_draining() {
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();
        const FRAMES: u32 = OUTBOUND_FRAME_BUDGET as u32 + 50;

        let writer = tokio::spawn(async move {
            for i in 0..FRAMES {
                io.write_all(&ping(i)).await.unwrap();
            }
        });

        // Give the writer time to hit the full channel and park on it.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !writer.is_finished(),
            "the writer must be waiting on the full channel"
        );

        for i in 0..FRAMES {
            // Bounded too: if the writer's wakeup were lost it would stop
            // producing after the channel's capacity, and an unbounded
            // `next().await` here would hang the test instead of failing
            // it (found by L4h5's review, by mutation).
            let frame = tokio::time::timeout(Duration::from_secs(5), outbound_rx.next())
                .await
                .expect("a parked writer must be woken by draining (lost wakeup)")
                .unwrap();
            assert_eq!(frame, ping(i));
        }
        tokio::time::timeout(Duration::from_secs(5), writer)
            .await
            .expect("a parked writer must be woken by draining (lost wakeup)")
            .unwrap();
    }

    #[tokio::test]
    async fn draining_outbound_frames_makes_room_for_more() {
        // The budget is on *backlog*, not on total frames ever sent:
        // draining keeps a long-lived, well-behaved connection writing
        // indefinitely.
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();
        for i in 0..(OUTBOUND_FRAME_BUDGET as u32 * 4) {
            io.write_all(&ping(i)).await.unwrap();
            assert_eq!(outbound_rx.next().await.unwrap(), ping(i));
        }
    }

    #[tokio::test]
    async fn a_dropped_outbound_receiver_swallows_frames_instead_of_failing_the_write() {
        let (mut io, _inbound_tx, outbound_rx) = RecordIo::new();
        drop(outbound_rx);
        for i in 0..(OUTBOUND_FRAME_BUDGET as u32 * 2) {
            io.write_all(&ping(i)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_malformed_header_is_an_invalid_data_error() {
        let (mut io, _inbound_tx, _outbound_rx) = RecordIo::new();
        let err = io.write_all(&[7u8, 0, 0, 0]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_empty_write_is_a_no_op() {
        let (mut io, _inbound_tx, _outbound_rx) = RecordIo::new();
        assert_eq!(io.write(&[]).await.unwrap(), 0);
    }
}
