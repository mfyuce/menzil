//! The L4 end to end session (protocol.md 5.1, 5.2): one `Noise_IK`
//! session between two peers, sans I/O.
//!
//! A new crate, not an extension of `menzil-session`
//! (TODO.md L4d's own scoping note, DONE.md 2026-09-30): that crate's
//! `lib.rs` scopes itself explicitly to "the L3 relay-session core" and
//! its `Transport` is typed to L3's own CBOR `Record` enum with an
//! implicit single Noise nonce, while L4 needs explicit dual-class
//! counters (protocol.md 5.2's top-bit split), `IK` only (never `XX` —
//! an L4 initiator always already knows its peer's current NodeCert from
//! Policy, protocol.md 5.1), a different prologue, and REKEY on a
//! different schedule (record-count as well as time). Reusing L3's types
//! for a mechanically different job was judged to cost more clarity than
//! the duplication of a handful of small, pure helpers costs.
//!
//! Synchronous and runtime-agnostic, matching `menzil-session`'s own
//! discipline: no `tokio`, no networking, no knowledge of the L3 session
//! that actually carries an `E2eFrame` as a SEND/RECV payload (decision
//! 0001's `e2e_proto` tag `0x01`), and — just as deliberately — no
//! dependency on `menzil-node`'s `PolicyStore` (TODO.md L4c). Every check
//! protocol.md 5.1's "Checks" paragraph names (serial not below
//! `min_serial`, unrevoked membership, an unexpired Roster and Policy,
//! whether any grant exists) needs Policy/Roster state this crate never
//! holds; it only surfaces the raw material a caller needs to run those
//! checks itself — the negotiated peer static key, the handshake
//! payload's unverified `node_cert` — the same division of labor
//! `menzil_session::handshake`'s `NodeHandshake::finish`-style methods
//! already draw for L3, mirrored here.
//!
//! What protocol.md 5.1/5.2 do settle, and this crate implements
//! directly: the two-message `Noise_IK_25519_ChaChaPoly_BLAKE2s`
//! handshake with its own prologue and the asymmetric handshake-payload
//! placement (message 2 only — see [`handshake`]'s doc comment); explicit
//! per-direction counters via `snow`'s
//! [`StatelessTransportState`](snow::StatelessTransportState) rather than
//! its auto-incrementing one, since the two counter classes interleave
//! non-monotonically as raw nonces (see [`transport`]'s doc comment);
//! the reliable class's strict contiguity rule, checked only *after*
//! successful decryption (see [`transport`]'s doc comment on why that
//! order matters); and REKEY/KEEP scheduling ([`rekey`], [`liveness`]).
//!
//! What protocol.md 5.2/13 defer to phase 2, and this crate does not
//! implement even though the wire-level class split ships now regardless
//! (already built into `menzil_proto::RecordClass`): a working
//! send/receive path for the datagram class. [`transport::E2eTransport`]
//! refuses to send one (`E2eError::DatagramUnsupported`) and refuses an
//! *incoming* one before even attempting to decrypt it, not after
//! (`E2eError::UnauthenticatedDatagramCounter` — deliberately a
//! *different* error from the send-side one, since this one must never
//! be treated as session-fatal the way every other error
//! `decrypt_data` can return must be; see [`transport`]'s doc comment):
//! there is no replay window built yet to check an incoming one
//! against, so attempting decryption first would accept (and leave
//! accepted) a record this crate cannot actually protect against
//! replay. The companion check protocol.md 5.2's table also implies —
//! an authenticated reliable-class frame whose own *kind* turns out to
//! belong to the datagram class anyway — is caught too
//! (`E2eError::RecordClassMismatch`), found by this crate's own
//! red-team review rather than present from the start.
//!
//! What protocol.md 5.1/5.2 name but leave to a *different*,
//! cross-session sub-item, not [`transport`]/[`handshake`]: allocating
//! `sender_index`/`receiver_index` and avoiding collisions among
//! concurrent sessions (those two modules take both as caller-supplied
//! parameters), the simultaneous-open tie-break, replacing an established
//! session, and per-peer handshake rate limiting all live in [`table`]
//! and [`limiter`] (TODO.md L4e1, also sans-IO and generic over what it
//! routes to). Still not built: the mandatory 24-hour full re-handshake
//! and the old-session-stays-valid handover (TODO.md L4e2; TOBEDECIDED
//! item 6 blocks it, not this crate); and deciding what to *do* about a
//! dead session, as opposed to detecting one (see [`liveness`]'s doc
//! comment: this crate tracks send and receive activity separately and
//! exposes `is_dead`, the receive side of which is a documented judgment
//! call — protocol.md does not state a number for it at L4 the way it
//! does for L3 in section 3.3).
//!
//! **A red-team review round** (this crate's own, before anything else
//! builds on it) found and fixed five further issues beyond the ones
//! already described above: a genuine design bug in [`liveness`] (an
//! inbound-only activity model, copied from L3's PING/PONG, silently
//! breaks for KEEP specifically because KEEP has no reply — fixed by
//! tracking send-idleness separately, WireGuard's own "passive
//! keepalive" shape); a missing L4 plaintext budget check in
//! `encrypt_data` despite `menzil_proto::max_e2e_data_plaintext`'s own
//! doc comment assigning that enforcement to this crate by name
//! (`E2eError::BodyTooLarge`); REKEY application moved from a
//! separate caller-driven step into `encrypt_data`/`decrypt_data`
//! themselves, since the two were never actually independent decisions
//! and a caller that forgot the second step would silently desync both
//! sides with no visible symptom until the next real record failed to
//! decrypt; the all-zero/degenerate static key rejection described
//! above; and a send-side counter ceiling at `2^63`
//! (`E2eError::ReliableCounterExhausted`), astronomically unreachable
//! but a real, if purely theoretical, correctness gap otherwise. One
//! finding was deliberately left unfixed and is documented where it
//! lives instead ([`handshake`]'s doc comment: `E2eInitiatorHandshake::finish`
//! consumes `self` even on a failed `resp`).

#![forbid(unsafe_code)]

mod error;
mod handshake;
mod limiter;
mod liveness;
mod rekey;
mod table;
mod transport;

pub use error::E2eError;
pub use handshake::{E2eInitiatorHandshake, E2eResponderHandshake, prologue};
pub use limiter::{
    DEFAULT_HANDSHAKE_WINDOW, DEFAULT_HANDSHAKES_PER_WINDOW, DEFAULT_MAX_TRACKED_PEERS,
    HandshakeLimiter,
};
pub use liveness::Liveness;
pub use rekey::RekeySchedule;
pub use table::{
    Expired, IgnoreReason, InitDecision, Installed, Promoted, RegisterError, Removed, RespLookup,
    Role, Route, SessionIndex, SessionStatus, SessionTable, SlotState, TableConfig, TableError,
};
pub use transport::E2eTransport;
