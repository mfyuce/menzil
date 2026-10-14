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

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

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

/// Carries every connection `listener` accepts to `target` until `stop` completes, then resets
/// whatever is still open.
pub async fn run(
    socket: &Path,
    target: &str,
    listener: TcpListener,
    stop: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(stop);
    loop {
        let (connection, peer) = tokio::select! {
            accepted = listener.accept() => accepted?,
            () = &mut stop => break,
        };
        // Finished connections out of the set, so that it does not grow with every one served.
        while connections.try_join_next().is_some() {}
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            eprintln!("menzil: too many connections, refusing one from {peer}");
            reset(&connection);
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
        // Both directions ended and the output was shut down: closing now is a clean end.
        Some(Ok(End::Clean)) => {}
        Some(Ok(End::Reset(why))) => {
            eprintln!(
                "menzil: a connection from {peer} was reset: {}",
                text::one_line(&why, 300)
            );
            reset(&connection);
        }
        Some(Err(error)) => {
            eprintln!("menzil: {}", text::one_line(&format!("{error:#}"), 600));
            reset(&connection);
        }
        None => reset(&connection),
    }
}

/// Makes closing `connection` send an RST instead of a FIN.
fn reset(connection: &TcpStream) {
    let _ = socket2::SockRef::from(connection).set_linger(Some(Duration::ZERO));
}

#[cfg(test)]
mod tests;
