//! Waiting for the signals that ask a process to stop.
//!
//! `systemctl stop`, `docker stop` and `kill` send SIGTERM, a closing terminal sends SIGHUP, and
//! ctrl-c is SIGINT. A process that handles only the last one is killed by the others with its
//! sockets still open, and the kernel closes them with a FIN: every connection it carried ends
//! as if it had finished, however much was cut off (protocol.md 5.2, 5.3). All three have to take
//! the same path, the one that resets what was in flight.

use std::io;

/// The signals that ask a process to stop, caught from the moment this is made. Until one is
/// made a signal has its default action, which ends the process on the spot: a process that has
/// slow work before it waits for a signal (the node attaching to its relay) makes it first
/// (the fourth red-team round, N3: the handlers were installed only after the attach wait of up
/// to 60 s, and a signal in that time left the agent socket behind).
pub struct Shutdown {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    hangup: tokio::signal::unix::Signal,
}

impl Shutdown {
    /// Starts catching the signals. Must be called inside the runtime. A signal that arrives
    /// before [`wait`](Self::wait) is called is kept for it.
    #[cfg(unix)]
    pub fn catch() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    /// Starts catching the signals.
    #[cfg(not(unix))]
    pub fn catch() -> io::Result<Self> {
        Ok(Self {})
    }

    /// Completes when the process is asked to stop; says which signal it was.
    #[cfg(unix)]
    pub async fn wait(&mut self) -> io::Result<&'static str> {
        Ok(tokio::select! {
            _ = self.interrupt.recv() => "interrupt",
            _ = self.terminate.recv() => "terminate",
            _ = self.hangup.recv() => "hangup",
        })
    }

    /// Completes when the process is asked to stop; says which signal it was.
    #[cfg(not(unix))]
    pub async fn wait(&mut self) -> io::Result<&'static str> {
        tokio::signal::ctrl_c().await?;
        Ok("interrupt")
    }
}

/// Completes when the process is asked to stop; says which signal it was. The signals are
/// caught from the first poll, so use [`Shutdown::catch`] when work comes before the wait.
pub async fn shutdown() -> io::Result<&'static str> {
    Shutdown::catch()?.wait().await
}
