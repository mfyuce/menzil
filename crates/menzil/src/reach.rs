//! `menzil reach`: a local listener whose every connection is carried to a service of another
//! member through the agent.
//!
//! A connection ends the way its stream does. When the stream ends cleanly in both directions,
//! the connection is closed with a FIN. In every other case (the stream was reset, the agent
//! refused or is not running, the process is told to stop) the connection is *reset*, an RST on
//! the wire, so that the program on it cannot take a truncated answer for a whole one
//! (protocol.md 5.2, "never with a clean end of file"). The connection's halves are borrowed
//! from it, never owned by the bridge: dropping an owned write half shuts it down, a FIN, and a
//! FIN is read as end of file before the reset that follows it is seen.
//!
//! A connection is made to reset when it is closed from the moment it is accepted, and made to
//! close with a FIN only when its stream ended cleanly in both directions. Resetting each
//! abnormal path by hand is not enough (the fourth red-team round, M1: a failed `accept` ended
//! `run`, the connections in flight were dropped without their reset and every one read a clean
//! end of file after a truncated answer); with the reset as the default, no way out that nobody
//! thought of (a task aborted, a panic, the process killed) can do that.
//!
//! The listener is a TCP address ([`run`]) or a Unix socket ([`run_unix`]). A TCP listener on
//! 127.0.0.1 is open to every user of the machine, who then get this user's grants (as with
//! `ssh -L`); a Unix socket is private to this user: mode 0600, a path nobody else can change
//! (every link in it made by this user or root, every directory on the way owned by this user
//! or root and closed to others unless sticky: [`node_cmd::prepare_socket_directory`]), and the
//! uid of whoever connects is checked again on accept (TOBEDECIDED 15; the fifth red-team round,
//! M1). What a Unix socket cannot be relied on to do is reset: closing one reads as end of file
//! at the other end whether the stream ended cleanly or not (on Linux a connection closed while
//! it holds data its owner never read is shown as `ECONNRESET`, which `reach` cannot arrange),
//! so a program that must tell a truncated answer from a whole one has to use the TCP form.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::agent::{self, End};
use crate::home::FileLock;
use crate::node_cmd::{self, FileIdentity, SocketKind};
use crate::text;

/// How many connections are carried at once.
pub const MAX_CONNECTIONS: usize = 128;
/// How long a stop waits for the connections to be reset.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long `run` waits after a failed `accept` before it tries again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
/// How often a failing `accept` is reported.
const ACCEPT_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// The socket `menzil reach --unix` listens on.
pub const REACH_SOCKET: SocketKind = SocketKind {
    what: "the reach socket",
    setting: "the `--unix` option",
    holder: "another `menzil reach`",
};

/// A connection that is carried: its halves are borrowed for the bridge, and closing it is made
/// to reset or to end cleanly where the kind of socket can do both.
trait Connection: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// Once, when it is accepted.
    fn prepare(&self);
    /// Makes closing it send an RST (`true`) or the usual orderly end after what is queued
    /// (`false`). A socket without a reset leaves it as it is.
    fn reset_on_close(&self, reset: bool);
}

impl Connection for TcpStream {
    fn prepare(&self) {
        let _ = self.set_nodelay(true);
    }

    fn reset_on_close(&self, reset: bool) {
        let linger = reset.then_some(Duration::ZERO);
        let _ = socket2::SockRef::from(self).set_linger(linger);
    }
}

/// A Unix socket has no reset to send: closing it reads as end of file at the other end,
/// whether the stream ended cleanly or not (see the module documentation).
impl Connection for UnixStream {
    fn prepare(&self) {}

    fn reset_on_close(&self, _reset: bool) {}
}

/// Where connections come from: a listener, or (in the tests) one that fails on purpose.
trait Accept {
    type Connection: Connection;

    /// The next connection, and who is on the other end in a few words, for the log.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Connection, String)>> + Send;
}

impl Accept for TcpListener {
    type Connection = TcpStream;

    async fn accept(&self) -> io::Result<(TcpStream, String)> {
        let (connection, peer) = TcpListener::accept(self).await?;
        Ok((connection, peer.to_string()))
    }
}

/// A Unix socket whose connections are accepted only from processes of one user.
struct UserSocket {
    listener: UnixListener,
    uid: u32,
}

impl Accept for UserSocket {
    type Connection = UnixStream;

    async fn accept(&self) -> io::Result<(UnixStream, String)> {
        loop {
            let (connection, _) = self.listener.accept().await?;
            match connection.peer_cred() {
                Ok(peer) if peer.uid() == self.uid => {
                    let who = match peer.pid() {
                        Some(pid) => format!("process {pid}"),
                        None => "a local process".to_string(),
                    };
                    return Ok((connection, who));
                }
                Ok(peer) => eprintln!(
                    "menzil: a process of another user (uid {}) connected to the reach socket, closing it",
                    peer.uid()
                ),
                Err(error) => eprintln!(
                    "menzil: could not tell who connected to the reach socket, closing it: {}",
                    text::one_line(&error.to_string(), 300)
                ),
            }
        }
    }
}

/// Carries every connection `listener` accepts to `target` until `stop` completes, then resets
/// whatever is still open. An `accept` that fails (out of descriptors, a connection aborted while
/// it was queued) is reported and tried again after a short wait; it never ends `run`, which would
/// take the connections in flight with it.
pub async fn run(
    socket: &Path,
    target: &str,
    listener: TcpListener,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    run_on(socket, target, listener, stop).await
}

/// A Unix socket `reach` listens on, with what it needs to leave nothing behind. Dropping it (the
/// end of [`run_unix`], an error, a task aborted) removes the socket file if the path still names
/// it, and the lock file; the lock is released last.
pub struct UnixSocket {
    listener: Option<UnixListener>,
    path: PathBuf,
    identity: FileIdentity,
    lock_path: PathBuf,
    lock_identity: FileIdentity,
    _lock: FileLock,
}

impl UnixSocket {
    /// Where the socket is.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for UnixSocket {
    fn drop(&mut self) {
        // Only the files this run made: the path may lead somewhere else by now (the fifth
        // red-team round, M1), and removing by name would delete somebody else's file. The lock
        // file goes while its lock is still held.
        node_cmd::remove_if_unchanged(&self.path, self.identity);
        node_cmd::remove_if_unchanged(&self.lock_path, self.lock_identity);
    }
}

/// The lock file of a socket: next to it, with `.lock` added.
fn lock_path(socket: &Path) -> PathBuf {
    let mut name = socket.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Binds `path` as a socket only this user can use (see [`node_cmd::prepare_socket_directory`]
/// for what that takes). A lock next to it says whether a `reach` is running there: asking the
/// socket instead (connecting to it) would make the running `reach` carry the question to its
/// service as a connection (the fifth red-team round, N2).
pub async fn bind_unix(path: &Path) -> Result<UnixSocket> {
    node_cmd::prepare_socket_directory(path, &REACH_SOCKET).await?;
    let lock_path = lock_path(path);
    let Some(lock) = FileLock::try_acquire(&lock_path)? else {
        anyhow::bail!(
            "{} is already listening on {}",
            REACH_SOCKET.holder,
            path.display()
        );
    };
    let lock_identity = node_cmd::file_identity(&lock_path)
        .with_context(|| format!("looking at {}", lock_path.display()))?;
    let bound = async {
        let listener = node_cmd::bind_in_prepared_directory(path, &REACH_SOCKET).await?;
        let identity = node_cmd::file_identity(path)
            .with_context(|| format!("looking at {}", path.display()))?;
        Ok::<_, anyhow::Error>((listener, identity))
    }
    .await;
    match bound {
        Ok((listener, identity)) => Ok(UnixSocket {
            listener: Some(listener),
            path: path.to_path_buf(),
            identity,
            lock_path,
            lock_identity,
            _lock: lock,
        }),
        Err(error) => {
            node_cmd::remove_if_unchanged(&lock_path, lock_identity);
            Err(error)
        }
    }
}

/// [`run`] on a Unix socket: connections from processes of other users are closed unanswered. The
/// socket file and its lock are removed when this ends (see [`UnixSocket`]).
pub async fn run_unix(
    socket: &Path,
    target: &str,
    mut bound: UnixSocket,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    let uid = agent::current_uid()
        .await
        .context("finding out which user this is")?;
    let listener = bound
        .listener
        .take()
        .expect("a bound socket holds its listener until it is run");
    run_on(socket, target, UserSocket { listener, uid }, stop).await
}

async fn run_on<L: Accept>(
    socket: &Path,
    target: &str,
    listener: L,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut last_report: Option<Instant> = None;
    tokio::pin!(stop);
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut stop => break,
        };
        let (connection, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                if last_report.is_none_or(|at| at.elapsed() >= ACCEPT_REPORT_INTERVAL) {
                    eprintln!(
                        "menzil: accepting a connection failed, trying again: {}",
                        text::one_line(&error.to_string(), 300)
                    );
                    last_report = Some(Instant::now());
                }
                tokio::select! {
                    () = tokio::time::sleep(ACCEPT_RETRY) => {}
                    () = &mut stop => break,
                }
                continue;
            }
        };
        connection.prepare();
        connection.reset_on_close(true);
        // Finished connections out of the set, so that it does not grow with every one served.
        while connections.try_join_next().is_some() {}
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            eprintln!("menzil: too many connections, refusing one from {peer}");
            continue;
        };
        let (socket, target, mut stop) =
            (socket.to_path_buf(), target.to_string(), stop_rx.clone());
        connections.spawn(async move {
            carry(connection, peer, &socket, &target, &mut stop).await;
            drop(permit);
        });
    }
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(STOP_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

/// One connection, to its end.
async fn carry<C: Connection>(
    mut connection: C,
    peer: String,
    socket: &Path,
    target: &str,
    stop: &mut watch::Receiver<bool>,
) {
    let outcome = {
        // Borrowed halves: dropping an owned write half would shut it down (a FIN).
        let (mut read, mut write) = tokio::io::split(&mut connection);
        tokio::select! {
            outcome = agent::connect_and_bridge(socket, target, &mut read, &mut write) => Some(outcome),
            _ = stop.wait_for(|stopped| *stopped) => None,
        }
    };
    match outcome {
        // Both directions ended and the output was shut down: now, and only now, closing is a
        // clean end (a FIN after whatever is still queued).
        Some(Ok(End::Clean)) => connection.reset_on_close(false),
        // Every other end leaves the connection as it was accepted: closing resets it.
        Some(Ok(End::Reset(why))) => {
            eprintln!(
                "menzil: a connection from {peer} was reset: {}",
                text::one_line(&why, 300)
            );
        }
        Some(Err(error)) => {
            eprintln!("menzil: {}", text::one_line(&format!("{error:#}"), 600));
        }
        None => {}
    }
}

#[cfg(test)]
mod tests;
