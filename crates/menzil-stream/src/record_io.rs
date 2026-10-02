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
//! **Outbound backpressure, and why it is a hard cap rather than
//! smooth `Poll::Pending` backpressure**: a 2026-10-02 red team review of
//! this crate found that an earlier version of this module queued
//! outbound frames on an *unbounded* channel, reasoning (wrongly — the
//! review's own live tests disproved it) that L3's own send queue and
//! credit system (TODO.md L4b) would bound it from below. Two concrete,
//! confirmed counterexamples: an authenticated peer flooding this side
//! with a million bare `Ping` frames queues a million `Pong` replies
//! before this side's own L3 credit ever enters the picture (pongs are
//! generated and queued by `yamux` itself, synchronously, regardless of
//! whether anything downstream is draining them); and a peer granting a
//! generous flow-control window on a stream, combined with a *local*
//! writer that keeps writing while nothing drains
//! [`crate::OutboundFrames`] (e.g. because the L3 session is itself
//! credit-starved), queues unbounded local data the same way. Neither
//! scenario needs a malicious peer in the "attacker breaks the protocol"
//! sense — both are well-formed yamux traffic this crate has no way to
//! refuse without a bound of its own. [`OUTBOUND_FRAME_BUDGET`] is that
//! bound: [`RecordIo::poll_write`] fails outright, as a normal I/O error,
//! the moment the channel genuinely has no room, rather than returning
//! `Poll::Pending` and waiting for room to free up. A hard failure was
//! chosen over smooth backpressure deliberately: `yamux`'s own internal
//! actor (`Active::poll`, see `yamux` 0.14.1's `connection.rs`) does not
//! expect writing to its socket to stall indefinitely while still making
//! other progress, and this crate has no way to pause just the one peer
//! responsible without pausing the whole connection anyway — so the
//! response this crate actually gives is the same one protocol.md 4.2
//! already gives a reliable SEND beyond its own credit: end the session,
//! surfaced through the normal `yamux` → [`crate::StreamMuxError::Connection`]
//! → [`crate::Driver`] error path, not a bespoke one.
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
//! gives a shape for). This crate does not add that bound yet because,
//! unlike the outbound direction, no concrete growth scenario for it was
//! found: in practice a caller's own read loop over a real, flow
//! controlled L3 session is what paces how fast `feed_inbound` can ever
//! be called, not anything a remote peer directly controls. If a future
//! caller's own pacing ever turns out not to hold that in practice, the
//! fix belongs here, following the same shape as the outbound one.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures_channel::mpsc;
use futures_util::io::{AsyncRead, AsyncWrite};
use futures_util::stream::StreamExt;

use crate::frame_format::leading_frame_len;

/// How many outbound frames may sit in the channel between
/// [`RecordIo::poll_write`] and whatever drains [`crate::OutboundFrames`]
/// before this side treats the backlog as fatal — see this module's own
/// doc comment for why a hard cap, not smooth backpressure. Chosen to
/// land in roughly the same order of magnitude as L3's own per-destination
/// queue default (protocol.md 4.2: "default 4 MiB"): at `yamux`'s default
/// 16 KiB split size this is about 4 MiB of frames, though a session
/// configured with a smaller `max_record` (see [`crate::driver::config_for`])
/// packs more, smaller frames into the same budget. Not yet exposed as a
/// caller-configurable parameter — nothing has needed to tune it yet; a
/// natural follow-up if a future caller (TODO.md L4h) does.
const OUTBOUND_FRAME_BUDGET: usize = 256;

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
    /// Bytes `yamux` has written that do not yet add up to one complete
    /// frame (or did, and were already drained out to `outbound_tx`,
    /// leaving a next frame's leading bytes behind).
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
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.outbound_partial.extend_from_slice(buf);
        loop {
            match leading_frame_len(&this.outbound_partial) {
                Ok(Some(len)) => {
                    let frame: Vec<u8> = this.outbound_partial.drain(..len).collect();
                    match this.outbound_tx.try_send(frame) {
                        Ok(()) => {}
                        Err(e) if e.is_disconnected() => {
                            // Nobody will ever read another frame (the
                            // `OutboundFrames` handle for this session was
                            // dropped, e.g. because the L4 session already
                            // ended) — dropping this one here is correct,
                            // not a write failure `yamux`'s own `Sink`
                            // impl should see and react to.
                        }
                        Err(_) => {
                            // Full, not disconnected: see this module's
                            // own doc comment on `OUTBOUND_FRAME_BUDGET`
                            // for why this is a hard, immediate failure
                            // rather than `Poll::Pending`.
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "menzil-stream's outbound frame budget ({OUTBOUND_FRAME_BUDGET}) \
                                 is exhausted: nothing is draining OutboundFrames fast enough"
                            ))));
                        }
                    }
                }
                Ok(None) => break,
                // `yamux::Connection` is the only writer this type ever
                // has, so a malformed header here is this crate's own
                // bug (or a mismatch against a future `yamux` version
                // that changed its wire format), never peer input —
                // still surfaced as a normal I/O error rather than a
                // panic, since a caller may well choose to treat it the
                // same as any other fatal connection error.
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "menzil-stream's own yamux::Connection wrote a malformed frame: {e}"
                        ),
                    )));
                }
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};

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
        fn ping(id: u32) -> Vec<u8> {
            let mut buf = vec![0u8, 2, 0, 0, 0, 0, 0, 0];
            buf.extend_from_slice(&id.to_be_bytes());
            buf
        }
        let mut both = ping(1);
        both.extend_from_slice(&ping(2));
        io.write_all(&both).await.unwrap();

        assert_eq!(outbound_rx.next().await.unwrap(), ping(1));
        assert_eq!(outbound_rx.next().await.unwrap(), ping(2));
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
    async fn poll_write_fails_once_the_outbound_budget_is_exhausted() {
        // `_outbound_rx` is deliberately never drained: modeling the
        // scenario a 2026-10-02 red team review of this crate confirmed
        // as a real, unbounded memory-growth risk before
        // `OUTBOUND_FRAME_BUDGET` existed (DONE.md's L4f entry) — an
        // authenticated peer whose traffic (e.g. a Ping flood) makes
        // `yamux` itself produce outbound frames faster than anything
        // reads `OutboundFrames`. Without a bound this loop ran forever;
        // with one it must fail well within twice the budget.
        let (mut io, _inbound_tx, _outbound_rx) = RecordIo::new();
        fn ping(id: u32) -> Vec<u8> {
            let mut buf = vec![0u8, 2, 0, 0, 0, 0, 0, 0];
            buf.extend_from_slice(&id.to_be_bytes());
            buf
        }
        let mut failed = false;
        for i in 0..(OUTBOUND_FRAME_BUDGET as u32 * 2) {
            if io.write_all(&ping(i)).await.is_err() {
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "writing twice the outbound budget's worth of frames, with nothing draining \
             them, must eventually fail rather than growing memory without bound"
        );
    }

    #[tokio::test]
    async fn draining_outbound_frames_makes_room_for_more() {
        // The budget is on *backlog*, not on total frames ever sent:
        // draining keeps a long-lived, well-behaved connection writing
        // indefinitely.
        let (mut io, _inbound_tx, mut outbound_rx) = RecordIo::new();
        fn ping(id: u32) -> Vec<u8> {
            let mut buf = vec![0u8, 2, 0, 0, 0, 0, 0, 0];
            buf.extend_from_slice(&id.to_be_bytes());
            buf
        }
        for i in 0..(OUTBOUND_FRAME_BUDGET as u32 * 4) {
            io.write_all(&ping(i)).await.unwrap();
            assert_eq!(outbound_rx.next().await.unwrap(), ping(i));
        }
    }
}
