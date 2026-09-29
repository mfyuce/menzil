//! Errors from driving the L3 Noise handshake, transport, or the pure
//! primitives in this crate.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The underlying Noise handshake or transport cipher failed (bad
    /// input, decryption failure, wrong turn, exhausted nonce space, and
    /// so on — see `snow::Error`'s own variants).
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    /// A HELLO or WELCOME payload, or a `Record`, failed to encode or
    /// decode.
    #[error("proto error: {0}")]
    Proto(#[from] menzil_proto::ProtoError),
    /// [`crate::CreditLedger::consume`] would have taken the balance
    /// negative (protocol.md 4.2: "a reliable SEND beyond credit is a
    /// protocol violation").
    #[error("credit exceeded: tried to consume {requested} of {remaining} remaining")]
    CreditExceeded {
        /// The amount that was requested.
        requested: u32,
        /// The balance actually available.
        remaining: u32,
    },
}
