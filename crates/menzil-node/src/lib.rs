//! Node and client roles for menzil.
//!
//! The node-side L3 relay session (protocol.md 3, 4.1, 4.2; TODO.md
//! L3d): dial via `menzil-carrier`, run the Noise handshake via
//! `menzil-session`, verify the relay's identity, send ATTACH, and stay
//! attached — reconnecting through `menzil_carrier::Backoff`, honoring
//! GOAWAY's `retry_after_ms` hint, replying to PING, and rekeying on its
//! own hourly schedule.
//!
//! DOC(roster) propagation both directions (protocol.md 4.3; TODO.md L3f)
//! is handled transparently by [`Session`]/`Engine`, the same way PING/
//! REKEY/GOAWAY already were — see `session`'s module doc comment and
//! [`RosterStore`]. The node side of the SEND/RECV/CREDIT data plane
//! (protocol.md 4.2; TODO.md L4b) is in [`outbound`] and wired up inside
//! [`run_session`]. [`PolicyStore`] (protocol.md 2.3, 5.1, 5.3; TODO.md
//! L4c) holds this node's verified Policies and answers membership/
//! grant questions, but — unlike `RosterStore` — is not yet wired into
//! `run_session`/`Engine` at all: nothing drives an L4 handshake or OPEN
//! yet for it to gate (`menzil-e2e`/`menzil-stream`, TODO.md L4d/f/g, and
//! the runtime wiring that joins them, L4h). Not here: interpreting
//! SEND/RECV/ADVERTISE*/PEER_STATE/ADMIT_* payloads themselves, the
//! local service registry, the SOCKS executor, and the SSH stdio mode
//! the client-side commands need (protocol.md 5, 8, 12) — those are
//! still to come. Generating and persisting a node's own identity
//! (protocol.md 2.2) is also a separate, not-yet-built concern;
//! [`LocalIdentity`] only carries it, already assembled, the same way
//! `menzil-relay` takes its TLS certificate material already loaded.

#![forbid(unsafe_code)]

mod error;
mod identity;
mod outbound;
mod policy_store;
mod roster_store;
mod session;

pub use error::NodeError;
pub use identity::LocalIdentity;
pub use outbound::{EnqueueOutcome, OutboundQueue, OutboundSend};
pub use policy_store::PolicyStore;
pub use roster_store::RosterStore;
pub use session::{Session, SessionConfig, run_session};
