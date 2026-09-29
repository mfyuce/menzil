//! Best-effort `TCP_NOTSENT_LOWAT` tuning (protocol.md 3.3): keeps the
//! kernel send buffer shallow so a queued control record can preempt a
//! queued SEND, "where available" — never fatal to connecting.

use socket2::SockRef;
use tokio::net::TcpStream;

/// Low enough that a just-queued control record reaches the wire
/// promptly, without hurting throughput on a bulk SEND.
const LOWAT_BYTES: u32 = 16 * 1024;

/// Applies the watermark to `stream`, logging and continuing on any
/// failure (unsupported platform, or the syscall itself failing).
pub fn apply(stream: &TcpStream) {
    let sock = SockRef::from(stream);
    if let Err(err) = set_notsent_lowat(&sock, LOWAT_BYTES) {
        tracing::debug!(%err, "TCP_NOTSENT_LOWAT unavailable, continuing without it");
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_notsent_lowat(sock: &SockRef<'_>, bytes: u32) -> std::io::Result<()> {
    sock.set_tcp_notsent_lowat(bytes)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn set_notsent_lowat(_sock: &SockRef<'_>, _bytes: u32) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}
