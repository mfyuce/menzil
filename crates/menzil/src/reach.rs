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

use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::agent::{self, End};
use crate::text;

/// How many connections are carried at once.
pub const MAX_CONNECTIONS: usize = 128;
/// How long a stop waits for the connections to be reset.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long `run` waits after a failed `accept` before it tries again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
/// How often a failing `accept` is reported.
const ACCEPT_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Where connections come from: a listener, or (in the tests) one that fails on purpose.
trait Accept {
    fn accept(
        &self,
    ) -> impl std::future::Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send;
}

impl Accept for TcpListener {
    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        TcpListener::accept(self).await
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
    stop: impl std::future::Future<Output = ()>,
) -> Result<()> {
    run_on(socket, target, listener, stop).await
}

async fn run_on<L: Accept>(
    socket: &Path,
    target: &str,
    listener: L,
    stop: impl std::future::Future<Output = ()>,
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
        reset_on_close(&connection, true);
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
async fn carry(
    mut connection: TcpStream,
    peer: SocketAddr,
    socket: &Path,
    target: &str,
    stop: &mut watch::Receiver<bool>,
) {
    let _ = connection.set_nodelay(true);
    let outcome = {
        let (mut read, mut write) = connection.split();
        tokio::select! {
            outcome = agent::connect_and_bridge(socket, target, &mut read, &mut write) => Some(outcome),
            _ = stop.wait_for(|stopped| *stopped) => None,
        }
    };
    match outcome {
        // Both directions ended and the output was shut down: now, and only now, closing is a
        // clean end (a FIN after whatever is still queued).
        Some(Ok(End::Clean)) => reset_on_close(&connection, false),
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

/// Makes closing `connection` send an RST (`reset`) or the usual FIN after the queued data.
fn reset_on_close(connection: &TcpStream, reset: bool) {
    let linger = reset.then_some(Duration::ZERO);
    let _ = socket2::SockRef::from(connection).set_linger(linger);
}

#[cfg(test)]
mod tests;
