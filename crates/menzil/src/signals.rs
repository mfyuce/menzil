//! Waiting for the signals that ask a process to stop.
//!
//! `systemctl stop`, `docker stop` and `kill` send SIGTERM, a closing terminal sends SIGHUP, and
//! ctrl-c is SIGINT. A process that handles only the last one is killed by the others with its
//! sockets still open, and the kernel closes them with a FIN: every connection it carried ends
//! as if it had finished, however much was cut off (protocol.md 5.2, 5.3). All three have to take
//! the same path, the one that resets what was in flight.

use std::io;

/// Completes when the process is asked to stop; says which signal it was.
#[cfg(unix)]
pub async fn shutdown() -> io::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    Ok(tokio::select! {
        _ = interrupt.recv() => "interrupt",
        _ = terminate.recv() => "terminate",
        _ = hangup.recv() => "hangup",
    })
}

/// Completes when the process is asked to stop; says which signal it was.
#[cfg(not(unix))]
pub async fn shutdown() -> io::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("interrupt")
}
