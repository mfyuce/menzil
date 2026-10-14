//! The stream type this crate hands out.
//!
//! A [`Stream`] is a `yamux::Stream` of the vendored `yamux` (`vendor/yamux/PATCHES.md`) with
//! four things added, each one something the stock type cannot express (TODO.md, TOBEDECIDED
//! item 11):
//!
//! * **A stream that is not closed on purpose is aborted.** [`Stream::reset`] aborts it in every
//!   state, and so does dropping it unless [`AsyncWriteExt::close`](futures_util::io::AsyncWriteExt::close)
//!   completed first. Stock `yamux` sends an RST on drop only while the stream is fully open:
//!   after the peer's half close it answers with a FIN, a clean end, so a panic, an early
//!   return or a cancelled future that owns the stream would end it looking complete. Here a
//!   clean end is something a stream's owner has to ask for with `close`; every other end is an
//!   RST (protocol.md 5.2, 5.3).
//! * **Reading a reset stream is an error, not an end of file.** `yamux` reports a FIN, an RST
//!   and a connection that went away all as `Ok(0)`. A reader that gets `Ok(0)` from this type
//!   has seen the peer's FIN and nothing else (the data it read is whole); an RST or a lost
//!   connection reads as [`io::ErrorKind::ConnectionReset`] once the data that arrived before
//!   it is consumed. Writing to, flushing and closing a reset stream fail the same way, and so
//!   does a write after the connection was lost.
//! * **A stream can be watched for its teardown** without polling it:
//!   [`Stream::torn_down`] completes when the peer's RST arrives or the connection goes away
//!   under a stream that is not over, also one the peer had half-closed. Reading and writing
//!   register a waker only while they are pending, so an owner that has read the peer's FIN
//!   and waits for its local target, or whose write to that target is blocked, would never
//!   learn that the stream is gone (the second L4i review).
//! * **Every live stream holds a slot of its connection's count**, released when the stream is
//!   dropped, so [`StreamMux::live_streams`](crate::StreamMux::live_streams) can say how many
//!   handles are in use. (What bounds the streams a connection holds is `yamux`'s own table
//!   size, which also counts dropped streams that have not been flushed yet: see
//!   [`MAX_LIVE_STREAMS`](crate::MAX_LIVE_STREAMS).)

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};

/// The live streams of one connection and the inbound ones it refused. Only the
/// [`Driver`](crate::Driver) takes slots; they are given back from any thread.
#[derive(Debug, Default)]
pub(crate) struct StreamCounters {
    live: AtomicUsize,
    refused_inbound: AtomicUsize,
}

impl StreamCounters {
    pub(crate) fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    pub(crate) fn refused_inbound(&self) -> usize {
        self.refused_inbound.load(Ordering::Relaxed)
    }

    pub(crate) fn note_refused_inbound(&self) {
        self.refused_inbound.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn take_slot(self: &Arc<Self>) -> Slot {
        self.live.fetch_add(1, Ordering::AcqRel);
        Slot(self.clone())
    }
}

/// One live stream's share of the count; gives it back on drop.
#[derive(Debug)]
pub(crate) struct Slot(Arc<StreamCounters>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A yamux stream. See the module documentation.
#[derive(Debug)]
pub struct Stream {
    inner: yamux::Stream,
    /// `poll_close` has completed: this side's end was asked for, so dropping the stream is
    /// not an abort.
    closed: bool,
    _slot: Slot,
}

fn reset_error() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "the stream was reset")
}

impl Stream {
    pub(crate) fn new(inner: yamux::Stream, slot: Slot) -> Self {
        Stream {
            inner,
            closed: false,
            _slot: slot,
        }
    }

    /// Aborts the stream: the peer receives an RST whatever state the stream is in (unless it is
    /// closed already), its pending writes fail and its reads end in an error. Data this side
    /// had already written goes out first. Dropping a stream that was not closed does the same;
    /// this is for saying so on purpose: a local target that failed, a grant that was removed,
    /// a node shutting down.
    pub fn reset(self) {
        self.inner.reset_on_drop();
    }

    /// Whether the peer reset the stream, or the connection went away while the peer had not
    /// closed its side. Reading such a stream ends in [`io::ErrorKind::ConnectionReset`]; this
    /// is for a caller that wants to ask without reading.
    pub fn is_reset(&self) -> bool {
        self.inner.is_reset()
    }

    /// A future that completes when the stream is torn down: the peer reset it, or the
    /// connection went away while the stream was not yet closed in both directions (a peer's FIN
    /// does not count as closed in both). It does not complete for a stream that ended cleanly,
    /// and it completes at once for one that was torn down already. It is a handle of its own,
    /// so it can be awaited next to a task that holds the stream mutably; use one watcher per
    /// stream at a time, and drop it with the stream (it keeps the stream's shared state alive).
    pub fn torn_down(&self) -> TornDown {
        TornDown(self.inner.torn_down())
    }

    /// The stream's identifier on its connection, for logs.
    pub fn id(&self) -> u32 {
        self.inner.id().val()
    }

    /// A failure of a write, flush or close, as the error kind it should have: a reset, if the
    /// stream was reset or if it stopped being writable under a side that never closed it (the
    /// connection went away). A write after this side's own close keeps `yamux`'s error: that
    /// one is a mistake of the caller, not a reset.
    fn map_write_error(&self, error: io::Error) -> io::Error {
        if self.inner.is_reset() || (!self.closed && error.kind() == io::ErrorKind::WriteZero) {
            reset_error()
        } else {
            error
        }
    }
}

/// See [`Stream::torn_down`].
#[derive(Debug)]
pub struct TornDown(yamux::TornDown);

impl Future for TornDown {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.closed {
            self.inner.reset_on_drop();
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            // `yamux` returns `Ok(0)` only once the data that arrived before the end is read, so
            // asking now cannot cut data off. An empty `buf` also reads as `Ok(0)`: not an end.
            Poll::Ready(Ok(0)) if !buf.is_empty() && self.inner.is_reset() => {
                Poll::Ready(Err(reset_error()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.map_write_error(error))),
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) if self.inner.is_reset() => Poll::Ready(Err(reset_error())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.map_write_error(error))),
            other => other,
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_close(cx) {
            // `yamux` answers `Ok` for a stream that is closed already, a reset one included.
            Poll::Ready(Ok(())) if self.inner.is_reset() => Poll::Ready(Err(reset_error())),
            Poll::Ready(Ok(())) => {
                self.closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.map_write_error(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}
