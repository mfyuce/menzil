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
    // Windows: Ctrl+C, Ctrl+Break, the console window closing and logoff or shutdown take the
    // same path as SIGINT, SIGHUP and SIGTERM do (D11 W3).
    #[cfg(not(unix))]
    interrupt: tokio::signal::windows::CtrlC,
    #[cfg(not(unix))]
    break_: tokio::signal::windows::CtrlBreak,
    #[cfg(not(unix))]
    close: tokio::signal::windows::CtrlClose,
    #[cfg(not(unix))]
    shutdown: tokio::signal::windows::CtrlShutdown,
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
        use tokio::signal::windows;
        Ok(Self {
            interrupt: tokio::signal::windows::ctrl_c()?,
            break_: windows::ctrl_break()?,
            close: windows::ctrl_close()?,
            shutdown: windows::ctrl_shutdown()?,
        })
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
        Ok(tokio::select! {
            _ = self.interrupt.recv() => "interrupt",
            _ = self.break_.recv() => "break",
            _ = self.close.recv() => "hangup",
            _ = self.shutdown.recv() => "terminate",
        })
    }
}

/// Completes when the process is asked to stop; says which signal it was. The signals are
/// caught from the first poll, so use [`Shutdown::catch`] when work comes before the wait.
pub async fn shutdown() -> io::Result<&'static str> {
    Shutdown::catch()?.wait().await
}

/// Makes `log` open its file again on every SIGUSR1: the signal for log rotation (move the file
/// away, then `kill -USR1`). SIGHUP is not used: here it stops the process. Must be called
/// inside the runtime; does nothing for a disabled log or off Unix.
pub fn reopen_audit_on_usr1(log: &menzil_audit::AuditLog) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if !log.enabled() {
            return;
        }
        let Ok(mut usr1) = signal(SignalKind::user_defined1()) else {
            tracing::warn!("cannot catch SIGUSR1: the audit file is not reopened on rotation");
            return;
        };
        let log = log.clone();
        tokio::spawn(async move {
            while usr1.recv().await.is_some() {
                if !log.reopen() {
                    tracing::warn!("the audit queue is full: SIGUSR1 reopen not queued");
                }
            }
        });
    }
    #[cfg(not(unix))]
    let _ = log;
}
