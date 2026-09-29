//! Node and client roles for menzil.
//!
//! The node-side L3 relay session (protocol.md 3, 4.1, 4.2; TODO.md
//! L3d): dial via `menzil-carrier`, run the Noise handshake via
//! `menzil-session`, verify the relay's identity, send ATTACH, and stay
//! attached — reconnecting through `menzil_carrier::Backoff`, honoring
//! GOAWAY's `retry_after_ms` hint, replying to PING, and rekeying on its
//! own hourly schedule.
//!
//! Not here: interpreting anything the relay forwards beyond PING/REKEY/
//! GOAWAY (SEND/RECV/ADVERTISE*/DOC/PEER_STATE/CREDIT/ADMIT_* — later
//! items' job, TODO.md L3f, L3g, L4), the local service registry, the
//! SOCKS executor, and the SSH stdio mode the client-side commands need
//! (protocol.md 8, 12) — those are still to come. Generating and
//! persisting a node's own identity (protocol.md 2.2) is also a separate,
//! not-yet-built concern; [`LocalIdentity`] only carries it, already
//! assembled, the same way `menzil-relay` takes its TLS certificate
//! material already loaded.

#![forbid(unsafe_code)]

mod error;
mod identity;
mod session;

pub use error::NodeError;
pub use identity::LocalIdentity;
pub use session::{Session, SessionConfig, run_session};
