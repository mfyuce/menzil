//! Standard output as `menzil stdio` uses it: a stream's end has to reach the program reading it.
//!
//! `tokio::io::Stdout::shutdown` only flushes; the descriptor stays open until the process exits.
//! A ProxyCommand's parent (ssh) waits for end of file on the pipe, and `stdio` goes on forwarding
//! its input after the stream's peer has finished (a peer that finished first may still be
//! reading), so the end of file has to be real while the process lives on: shutting down closes
//! descriptor 1 by pointing it at `/dev/null`, which releases the pipe.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncWrite, Stdout};

/// Standard output whose [`shutdown`](AsyncWrite::poll_shutdown) really closes it.
pub struct ClosingStdout {
    inner: Stdout,
}

impl ClosingStdout {
    /// This process's standard output.
    pub fn new() -> Self {
        Self {
            inner: tokio::io::stdout(),
        }
    }
}

impl Default for ClosingStdout {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncWrite for ClosingStdout {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Everything written is out before the descriptor goes.
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        Poll::Ready(close_stdout())
    }
}

/// Replaces descriptor 1 by `/dev/null`: the pipe or file it was is released, and anything
/// written afterwards goes nowhere.
#[cfg(unix)]
fn close_stdout() -> io::Result<()> {
    let null = std::fs::File::open("/dev/null")?;
    rustix::stdio::dup2_stdout(&null).map_err(io::Error::from)
}

#[cfg(not(unix))]
fn close_stdout() -> io::Result<()> {
    Ok(())
}
