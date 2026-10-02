//! Errors from driving this crate's yamux adapter.

use thiserror::Error;

use crate::frame_format::FrameFormatError;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum StreamMuxError {
    /// `yamux` itself gave up on the connection (a decode error, the
    /// stream-id space exhausted, too many open streams, and so on — see
    /// [`yamux::ConnectionError`]'s own variants). The connection is dead
    /// either way; what a caller should do about the L4 session it rides
    /// on (end it, since protocol.md 5.2 ties yamux state to one L4
    /// session's lifetime) is that caller's call, not this crate's.
    #[error("yamux connection error: {0}")]
    Connection(#[from] yamux::ConnectionError),
    /// An inbound `Mux`-kind [`menzil_proto::E2eDataBody`] did not decode
    /// as exactly one well-formed yamux frame — see
    /// [`crate::frame_format`]'s doc comment for why this crate checks
    /// that at all, given `yamux`'s own reader would also reject a
    /// genuinely malformed frame on its own. A spec-conformance violation
    /// by the peer (protocol.md 5.3: "body = one yamux frame"), not
    /// necessarily malicious — still reported as an error here rather
    /// than silently forwarding a multi-frame or partial-frame buffer,
    /// since this crate has no way to split the first case or complete
    /// the second.
    #[error("an inbound record did not decode as exactly one well-formed yamux frame: {0}")]
    MalformedFrame(FrameFormatError),
    /// The background [`crate::Driver`] this handle was created alongside
    /// is no longer running — in practice, dropped (the ordinary case: a
    /// `tokio::spawn`ed `Driver` is dropped once its future resolves).
    /// [`crate::StreamMux::open`] and [`crate::Inbound::accept`] report
    /// this rather than hanging forever on a reply that will now never
    /// arrive. **Not a complete guarantee**, found by a 2026-10-02 red
    /// team review: a `Driver` kept alive (not dropped) and simply never
    /// polled again after its own `poll` already returned `Ready` — a
    /// caller driving it by hand (`&mut driver` in a `select!`, say,
    /// rather than `tokio::spawn`) rather than letting it drop — leaves
    /// its internal channels technically open with nobody left to
    /// service them, and [`crate::StreamMux::open`] then waits forever
    /// instead of seeing this. A `Driver` that has resolved should always
    /// actually be dropped, the same contract polling any
    /// [`std::future::Future`] again after it resolves already carries.
    #[error("this stream multiplexer's driver task is no longer running")]
    DriverGone,
}
