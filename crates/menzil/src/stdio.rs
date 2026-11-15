//! Standard output as `menzil stdio` uses it: a stream's end has to reach the program reading it.
//!
//! `tokio::io::Stdout::shutdown` only flushes; the descriptor stays open until the process exits.
//! A ProxyCommand's parent (ssh) waits for end of file on the pipe, and `stdio` goes on forwarding
//! its input after the stream's peer has finished (a peer that finished first may still be
//! reading), so the end of file has to be real while the process lives on: shutting down closes
//! descriptor 1 by pointing it at `/dev/null`, which releases the pipe. When descriptor 1 is a
//! socket that descriptor 0 holds as well (inetd, systemd's `Accept=yes`, socat's EXEC), pointing
//! it elsewhere releases nothing, so the socket's writing side is shut down first.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncWrite, Stdout};

use crate::text;

/// What `menzil stdio` prints to standard error when the stream was reset, after `menzil: `:
/// the agent's reason (a single printable line) and, since a reset may be the other device
/// cutting this one off on purpose, what that looks like ([`text::CUT_OFF`]).
pub fn reset_message(why: &str) -> String {
    format!(
        "the connection was reset: {}. If the service did not fail, {}",
        text::one_line(why, 300),
        text::CUT_OFF
    )
}

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
/// written afterwards goes nowhere. If it is a socket, its writing side is shut down first: the
/// program on the other end is told the stream is over even while another descriptor of this
/// process (0, for a socket used both ways) keeps the socket open (the fourth red-team round, L4:
/// before this, such a program waited for an end of file that came only when the process exited).
/// For a pipe or a file the call says "not a socket" and changes nothing.
#[cfg(unix)]
fn close_stdout() -> io::Result<()> {
    let _ = socket2::SockRef::from(&std::io::stdout()).shutdown(std::net::Shutdown::Write);
    // Looked at before descriptor 1 is replaced: afterwards the two no longer match.
    let merged = stderr_is_the_same_pipe(&std::io::stdout(), &std::io::stderr());
    let null = std::fs::File::open("/dev/null")?;
    rustix::stdio::dup2_stdout(&null).map_err(io::Error::from)?;
    if merged {
        // `ssh -o ProxyCommand='menzil stdio %h/ssh 2>&1'`: descriptor 2 holds the pipe that
        // descriptor 1 just let go of, so the reader would see no end of file until the process
        // exits. What is printed to standard error after this point goes nowhere.
        rustix::stdio::dup2_stderr(&null).map_err(io::Error::from)?;
    }
    Ok(())
}

/// Whether `out` and `err` are one and the same pipe (a FIFO with the same device and inode).
/// A terminal or a file that both point at stays as it is: messages must still reach it, and
/// closing descriptor 1 releases nothing the reader waits on there.
#[cfg(unix)]
fn stderr_is_the_same_pipe(out: &impl std::os::fd::AsFd, err: &impl std::os::fd::AsFd) -> bool {
    use rustix::fs::{FileType, fstat};
    let (Ok(out), Ok(err)) = (fstat(out), fstat(err)) else {
        return false;
    };
    FileType::from_raw_mode(out.st_mode) == FileType::Fifo
        && out.st_dev == err.st_dev
        && out.st_ino == err.st_ino
}

#[cfg(not(unix))]
fn close_stdout() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn two_ends_of_one_pipe_are_the_same_pipe_but_not_two_pipes_or_a_file() {
        let (reader, writer) = std::io::pipe().unwrap();
        let again = writer.try_clone().unwrap();
        assert!(stderr_is_the_same_pipe(&writer, &again));
        let (_reader2, writer2) = std::io::pipe().unwrap();
        assert!(!stderr_is_the_same_pipe(&writer, &writer2), "two pipes");
        // The reading end of the same pipe is another file description of the same inode: the
        // two are one FIFO, which is the point (a `2>&1` has both on the writing end).
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(!stderr_is_the_same_pipe(&file, &file), "not a pipe");
        drop(reader);
    }

    #[test]
    fn a_reset_is_explained_in_plain_words_on_one_safe_line() {
        let message = reset_message("the stream was reset\n\u{1b}[2J");
        assert!(message.starts_with("the connection was reset: the stream was reset "));
        assert!(message.contains("revoked") && message.contains("taken back"));
        assert!(message.contains("grant_removed"));
        assert!(message.contains("`menzil status`"));
        assert!(
            !message.contains('\n') && !message.contains('\u{1b}'),
            "{message:?}"
        );
    }
}
