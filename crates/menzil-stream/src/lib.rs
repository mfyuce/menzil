//! The yamux adapter over L4 `Mux` records (protocol.md 5.3; L5 per
//! protocol.md 1; decision 0001 already settles yamux, not QUIC, as
//! phase 1's stream multiplexer).
//!
//! **Scope** (TODO.md L4f, depends on L4a only): wraps the `yamux` crate
//! so that one `yamux::Connection` runs entirely over already-decrypted,
//! already-counter-checked [`menzil_proto::E2eDataBody::Mux`] bodies —
//! never a real socket, never `menzil-e2e` or `menzil-session` types
//! directly (this crate does not depend on `menzil-e2e` at all; a caller
//! decrypts a `data` frame itself, and only ever hands this crate the
//! `Vec<u8>` out of a decoded `E2eDataBody::Mux(_)`, or receives one back
//! to encrypt as a fresh one). What this crate deliberately does *not* do,
//! left to later TODO.md items building on top of it: the OPEN/OPEN_ACK
//! exchange and the `Authorizer`/`ServiceHandler` service model (L4g);
//! joining this into a running node, path-pinning it to an L3 epoch, or
//! deciding what an ended [`Driver`] means for the L4 session it rode on
//! (L4h); dispatching an opened stream to a local `tcp:`/`http:`/`tls:`
//! target (L4i). [`StreamMux::feed_inbound`]/[`OutboundFrames::next_frame`]
//! are this crate's only seam to whatever carries `Mux` records over the
//! wire — intentionally not even aware that the carrier is Noise over a
//! relay-forwarded SEND/RECV record, so a future QUIC-based L4 (decision
//! 0001's `e2e_proto 0x02`) could in principle reuse the OPEN/OPEN_ACK and
//! service-model layer above this crate without this crate itself
//! changing, by swapping its concrete [`Stream`] type for a QUIC one —
//! the structural goal decision 0001 states directly ("the L5 OPEN and
//! OPEN_ACK headers and the service model are defined independently of
//! the mux so that the QUIC change stays below them").
//!
//! **Why this crate is async (`futures`-native) rather than sans-IO like
//! `menzil-session`/`menzil-e2e`**: those two crates are synchronous and
//! runtime-agnostic because their actual job (a Noise handshake and
//! transport cipher) has no inherent concurrency or I/O of its own — a
//! caller drives them one call at a time against bytes it already has in
//! hand. A stream multiplexer's job is the opposite: juggling an
//! unbounded number of concurrently readable/writable logical streams
//! against one ordered byte sequence is exactly what an async runtime
//! exists to schedule, and the `yamux` crate (the dependency decision
//! 0001 already settled on) is itself built on `futures`'s
//! `AsyncRead`/`AsyncWrite`/`Stream` traits, owning whatever resource
//! implements them and expecting to be polled to drive it. Re-flattening
//! that into a synchronous, poll-free shape would mean this crate
//! reimplementing a small task executor around `yamux`'s own internals
//! just to avoid the word "async" — more code, more risk, no actual gain,
//! since this crate's only realistic caller (`menzil-node`, TODO.md L4h)
//! is already tokio-based. The compromise this crate actually takes:
//! depend on `futures-util` (the trait definitions and channel types),
//! never on `tokio` directly, so nothing here is tied to one specific
//! executor — [`Driver`] is a plain [`std::future::Future`] any runtime
//! can spawn.
//!
//! **Why `yamux::Connection` runs over a fabricated in-memory resource
//! ([`record_io::RecordIo`]) instead of something like `tokio::io::duplex`
//! wrapping raw bytes**: protocol.md 5.3's wire table states a `Mux` body
//! *is* one yamux frame, not an arbitrary byte-stream chunk. **What that
//! alignment actually buys, corrected by a 2026-10-02 red team review of
//! this crate against this doc comment's own earlier, slightly wrong
//! claim**: it is *not* what makes relay-level reordering or drops safe —
//! the 2026-09-26 red team review's finding 1 is about this project's own
//! L4 reliable-class contiguity check (`menzil-e2e`, one layer below this
//! crate), which holds regardless of whether records happen to align with
//! frames, since it rejects a gap or reorder before this crate ever sees
//! the result either way. Record/frame alignment is a protocol.md 5.3
//! wire-conformance rule in its own right, and — because this crate has
//! no counter of its own and *trusts* [`StreamMux::feed_inbound`] to be
//! called in exactly the order records were authenticated in (see that
//! method's own doc comment for the gap this leaves: a caller that
//! violates this ordering corrupts a stream silently, confirmed live by
//! the same review) — validating that each inbound record really is
//! *exactly* one frame is the one conformance check this crate can still
//! make on its own, independent of ordering. A generic byte-pipe would
//! also have made splitting itself an accident of buffering rather than a
//! guarantee — observed directly while building this crate: `yamux`
//! 0.14.1 writes a Data frame's 12 byte header and its body as two
//! *separate* `poll_write` calls (confirmed in its own `src/frame/io.rs`),
//! so "one write call, one frame" is already false for the one frame kind
//! most records actually carry. [`RecordIo`] therefore parses yamux's own
//! wire header itself ([`frame_format::leading_frame_len`], necessary
//! because `yamux` 0.14.1 keeps that parsing private to its own crate) to
//! reassemble complete frames out of however `yamux` actually chunks its
//! writes, and [`StreamMux::feed_inbound`] separately validates that an
//! inbound record really is exactly one such frame before handing it to
//! `yamux`'s own reader.
//!
//! **A known gap, not yet closed**: this crate re-exports `yamux::Stream`
//! directly rather than wrapping it, which means it also inherits that
//! type's limits — notably, no way to force-reset a stream once this side
//! has already half-closed it (`yamux` 0.14.1 only sends `RST` on drop
//! while a stream is still fully `Open`). TODO.md's L4k (live grant
//! revocation) and L4i (the abnormal-end reset-not-EOF rule) will likely
//! need that and will not get it from this crate as it stands today —
//! found by the same 2026-10-02 review, left for whichever of those items
//! actually needs it to decide how (a newtype wrapping [`Stream`], most
//! likely), rather than guessed at here.

#![forbid(unsafe_code)]

mod driver;
mod error;
mod frame_format;
mod record_io;

pub use driver::{Driver, Inbound, OutboundFrames, StreamMux, new};
pub use error::StreamMuxError;
pub use frame_format::FrameFormatError;
pub use yamux::{Mode, Stream};
