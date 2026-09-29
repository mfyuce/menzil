//! Relay-side inbound transport for menzil (protocol.md 1, 3, 6.2's own
//! hostname case).
//!
//! Accepts TLS+WebSocket connections to the relay's own hostname and
//! completes the L3 upgrade, mirroring `menzil-carrier`'s client-side
//! shape so a session layer can treat either uniformly. Deliberately not
//! here:
//!
//! - SNI-based routing to advertised blind share names (protocol.md 6.2;
//!   phase 2 per protocol.md 13).
//! - ACME certificate provisioning (protocol.md 11); certificate and key
//!   material is supplied to this crate already loaded.
//! - The multi-session registry, HELLO validation, and
//!   forwarding/credit/queue logic (TODO.md L3e).
//! - Relay-terminated HTTP serving for terminated shares (its own
//!   TODO.md line, protocol.md 6.3).

#![forbid(unsafe_code)]

mod connection;
mod error;
mod hello;
mod identity;
mod listener;
mod node_history;
mod registry;
mod relay;
mod roster_store;
mod session;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod tests_support;
mod tls;

pub use connection::InboundConnection;
pub use error::RelayError;
pub use hello::{HelloRejection, check_hello};
pub use identity::RelayIdentity;
pub use listener::Listener;
pub use node_history::{HistoryViolation, NodeHistory};
pub use registry::SessionRegistry;
pub use relay::Relay;
pub use roster_store::RosterStore;
pub use tls::server_config;
