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
//! [`run_session`], which also surfaces each L3 attachment as an
//! [`Epoch`] through [`SessionEvent`] (protocol.md 5.1's path pinning;
//! TODO.md L4h1) for whatever L4 layer ends up built on top of it.
//! [`PolicyStore`] (protocol.md 2.3, 5.1, 5.3; TODO.md
//! L4c) holds this node's verified Policies and answers membership/
//! grant questions. [`admission`] (TODO.md L4h2) is the glue from those
//! questions to protocol.md 5.1's handshake checks/grant gate and 5.3's
//! per-OPEN grant check (a `menzil_stream::Authorizer` impl) — still,
//! like `PolicyStore` itself, not yet wired into `run_session`/`Engine`:
//! nothing drives an actual L4 handshake or OPEN yet to call it
//! (`menzil-e2e`/`menzil-stream` exist, TODO.md L4d/f/g, but the runtime
//! wiring that joins them to this, L4h, is still mostly ahead). Not here: interpreting
//! SEND/RECV/ADVERTISE*/PEER_STATE/ADMIT_* payloads themselves, the
//! local service registry, the SOCKS executor, and the SSH stdio mode
//! the client-side commands need (protocol.md 5, 8, 12) — those are
//! still to come. Generating and persisting a node's own identity
//! (protocol.md 2.2) is also a separate, not-yet-built concern;
//! [`LocalIdentity`] only carries it, already assembled, the same way
//! `menzil-relay` takes its TLS certificate material already loaded.

#![forbid(unsafe_code)]

mod admission;
mod error;
mod identity;
mod outbound;
mod policy_store;
mod roster_store;
mod session;

pub use admission::{
    HandshakeAdmission, InitiatorAdmission, PolicyAuthorizer, decide_initiator_admission,
    decide_responder_admission,
};
pub use error::NodeError;
pub use identity::LocalIdentity;
pub use outbound::{EnqueueOutcome, Epoch, OutboundQueue, OutboundSend};
pub use policy_store::PolicyStore;
pub use roster_store::RosterStore;
pub use session::{Session, SessionConfig, SessionEvent, run_session};
