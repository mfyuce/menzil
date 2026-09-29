//! The L3 relay-session core (protocol.md 1, 3.3, 4.1, 4.2): the Noise
//! `IK`/`XX` handshake, post-handshake record encrypt/decrypt, and small
//! pure primitives for credit accounting, PING/PONG liveness, and hourly
//! REKEY timing.
//!
//! Synchronous and runtime-agnostic: no `tokio`, no networking, no async
//! I/O. Wiring this to a real connection — dialing through
//! `menzil-carrier` on the node side, accepting connections on the relay
//! side, actually driving the handshake and transport over a socket, the
//! relay's multi-session registry and forwarding/queueing policy — is
//! session behavior for other, not-yet-built crates (TODO.md L3c
//! through L3g), not here.

#![forbid(unsafe_code)]

mod credit;
mod error;
mod handshake;
mod liveness;
mod rekey;
mod transport;

pub use credit::CreditLedger;
pub use error::SessionError;
pub use handshake::{
    HandshakePattern, NodeHandshake, RelayHandshake, RelayHandshakeAwaitingHello,
    RelayHandshakeStep, prologue,
};
pub use liveness::Liveness;
pub use rekey::RekeySchedule;
pub use transport::Transport;
