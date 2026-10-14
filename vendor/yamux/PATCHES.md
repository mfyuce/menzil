# Vendored yamux 0.14.1

This directory is the source of the `yamux` crate, version 0.14.1, as published on
crates.io (upstream commit `cc3d0e89f615ef4f329f7a246c95a8ff1e8cc12d` of
github.com/libp2p/rust-yamux, whose `yamux/src` is also what its release commit `6610cff`
holds), with the four patches below. `menzil-stream` depends on it by
path. Licence: Apache-2.0 OR MIT, copyright Parity Technologies (UK) Ltd.; the texts are
`LICENSE-APACHE` and `LICENSE-MIT` in this directory, copied from the upstream commit. Why
the crate is vendored and not used from the registry: `docs/spec/decisions/0002-vendored-yamux.md`.

`menzil.patch` is the complete difference to the published source (`a/` is the published
crate, `b/` this directory), so a reviewer reads the change in one place: about 190 added lines
outside tests (105 of them code, the rest comments and blanks), 16 removed, and 186 lines of
unit tests. Everything the patch does
not touch is byte for byte what crates.io serves, the manifest included, so the dev-dependencies
in it do not match what the crate's own tests need (see Tests).

The directory is listed under `exclude` in the workspace `Cargo.toml`: `cargo clippy` and
`cargo test --workspace` do not look at it, so the lint settings of this project do not apply
and the patch stays small. `cargo fmt --all` does follow path dependencies and formats it
with the repository's `rustfmt.toml`; upstream's code already conforms, so only lines added by
the patch can change, and `menzil.patch` has to be regenerated when they do.

## Patch 1: short data bodies share a chunk (`src/chunks.rs`)

yamux counts a stream's receive window in payload bytes, but `Chunks::push` kept every data
frame's body as a `Vec` of its own in a queue of its own. A one-byte frame cost about 65 bytes
of heap against one byte of window (measured: 249,000 one-byte frames held 16.3 MB). A peer
entitled to the window of every stream could cut its data into one-byte frames and pin about
65 times what the window says, gigabytes per session, by never being read from.

Now a body shorter than 1,024 bytes is appended to the last chunk when that chunk stays
within 8,192 bytes (the whole `Vec`, consumed bytes included, is compared, so a chunk that a
reader keeps up with still fills and is replaced). Every chunk but the first and the last then
holds at least 1,024 bytes, or follows one holding more than 7,168, so the number of chunks is
at most `bytes / 1024 + bytes / 7168 + 2`.

The memory held is about the window, at most about twice it: appending to a body that is an
exact fit doubles its capacity, so frames alternating 1,024 bytes and one byte hold 2.05 bytes
of heap per byte of payload (measured), one-byte frames 1.007. For the 144 MiB a session can
be made to leave unread that is up to about 295 MiB, against several gigabytes before. The
bytes a reader sees are unchanged; only the boundaries of the `Packet`s that the
`futures::Stream` implementation of `Stream` returns move, and the `AsyncRead` implementation,
which is all this project uses, cannot tell.

## Patch 2: abort a stream on drop, and tell a reset from a FIN (`src/connection/stream.rs`, `src/connection.rs`)

Upstream cannot abort a stream whose state is not fully open. Dropping a stream sends an RST
only while it is open; after the stream's own `poll_close` it sends nothing (a peer that is
out of credit waits forever), and after the peer's FIN it sends a FIN, which the peer reads
as a clean end. And a reader cannot tell a FIN, an RST and a connection that went away apart:
all three are `Ok(0)`. protocol.md 5.2 wants an abnormal end to be visible, never a clean end of
file, and per stream revocation (5.3) needs to end a stream whatever state it is in.

- `Stream::reset_on_drop(&self)` marks the stream; dropping it then makes the connection send
  an RST in every state except an already closed stream. Frames the stream had queued go out
  first. The mark cannot be taken back. (`menzil_stream::Stream::reset` is this plus the drop,
  and its own `Drop` marks every stream that was not closed on purpose.)
- `Stream::is_reset(&self)` is true after the peer's RST, and after the connection was dropped
  or failed while the peer had not closed its side with a FIN. It is false for a FIN, also one
  followed by the end of the connection, and false when an RST arrives for a stream that had
  ended cleanly already.

The wire format is unchanged: an RST is a data frame with the RST flag, which every yamux
implementation understands. A connection shut down with `Connection::poll_close` is not
covered by `is_reset`; `menzil-stream` never uses that call.

## Patch 3: a full table refuses a stream instead of ending the connection (`src/connection.rs`)

Upstream answers a stream the peer opens when the table holds `max_num_streams` with a GoAway,
which ends the session for the peer and every stream on it, and the table is fuller than the
streams in use: a dropped stream stays in it until its last frames are written, and while the
uplink is stalled they are not (the first yamux review reproduced a session ending at 212 live handles,
`crates/menzil-stream/tests/stream_limit.rs`). Now an inbound stream that finds the table full
is refused with an RST for its id and the connection goes on (`Action::Refuse`, the same single
pending slot a Pong uses, so reading pauses until the RST is written). The two GoAway
constructors this leaves unused are marked `allow(dead_code)`.

`Connection::num_streams()` returns the size of the table, which is what `max_num_streams`
limits, so a caller can refuse its own opens before a local open at the cap, which is still
fatal in `yamux`, ends the session. `menzil-stream` does (`MAX_LIVE_STREAMS`).

## Patch 4: a stream can be watched for its teardown (`src/connection/stream.rs`, `src/connection.rs`, `src/lib.rs`)

`poll_read` and `poll_write` register a waker only while they are pending, and the connection
wakes only the wakers that are registered when an RST arrives or the connection goes away. An
owner that is not polling the stream is never told. `menzil-node` serves a stream by copying
between it and a local socket: after the peer's FIN, while the target is silent, and while a
write to a target that does not read is blocked, nothing polls the stream, so the peer's RST or
the loss of the session woke nobody and the target's socket stayed open (the second L4i review,
M1: five experiments, none noticed in five seconds).

`Stream::torn_down(&self) -> TornDown` returns a future with a waker of its own (`Shared` gets
`torn_down` and `torn_down_waker`; the connection calls `mark_torn_down` where it already sets
`reset_by_remote`, and in `drop_all_streams`). It completes when the remote's RST arrives, on a
data frame or a window update, or when the connection goes away, for a stream that is not closed
in both directions yet. That is wider than `is_reset` in one place on purpose: a connection lost
under a stream the remote had half-closed does not read as a reset (everything the remote sent
was whole), but the owner can no longer finish the stream and has to be told. A stream that ended
cleanly never completes it, not for a late RST and not for the connection ending afterwards. It
completes at once if the stream was torn down before it was made. It is a separate handle so it
can be awaited next to a task that holds the stream mutably; there is room for one waker, so use
one at a time, and drop it with the stream (it shares the stream's state, the unread data
included). Nothing on the wire changes.

## Memory this does not bound

The windows (and patch 1) bound what a peer can have us hold of *its* data. Other memory is
outside them, measured with the counting allocator of `tests/small_frames.rs`: a fixed 917
bytes per stream (0.45 MiB at 512), and our own outbound data per stream when the peer stops
reading, 183,028 bytes from `yamux`'s per-stream channel of 10 frames of 16 KiB, about 78 MiB at
448 streams, counted by no budget (`SendBudget` sits after the outbound frame queue). With the
inbound queue budget of `menzil-node` (163 MiB) and the 295 MiB above, a hostile member can make
one session hold roughly 540 MiB. Another session is unaffected. What a node holds in kernel
socket buffers for the local targets it serves is outside this figure; `LocalServices` fixes it
(`menzil-node/src/serve.rs`: 128 KiB asked for each of the two buffers, so at most about 512 KiB
a connection, and 256 connections at most unless configured otherwise).

## Tests

- `crates/menzil-stream/tests/small_frames.rs` (patch 1, end to end, through a counting
  allocator; fails against the registry crate with 65 bytes per frame; also a reader that keeps
  pace and the 2.5 times bound for the worst pattern), `stream_reset.rs` (patch 2 and the
  `Stream` wrapper, over real connections), `stream_limit.rs` (patch 3 and the limit) and
  `torn_down.rs` (patch 4: a watcher that nothing else polls, for an RST, a lost connection, a
  half-closed stream, an RST on a window update, a clean end, a watcher moved between tasks). All
  run with `cargo test --workspace`.
- `src/chunks.rs` has unit tests for patch 1. The crates.io package cannot run its own tests:
  they need `quickcheck-ext`, a path dependency of upstream's workspace that is not published.
  To run them and upstream's own suite against these sources, take the upstream commit above,
  replace its `yamux/src` with this directory's `src`, and run `cargo test -p yamux --lib -p
  test-harness --tests` (with a `CARGO_TARGET_DIR` of its own). The last time this was done
  (2026-10-13, with patch 4) all of it passed: the unit tests (14: 5 upstream, 9 for patch 1) and
  upstream's integration tests `ack_backlog`, `ack_timing` and `poll_api` (property tests over
  random message sizes included).
- Regenerate `menzil.patch` with `diff -ruN a b` after any change here, `a` being the published
  crate.

## Updating or dropping the patches

The patches are small and independent of the project; they are candidates for upstream pull
requests. When a published yamux has equivalents, delete this directory, delete the `exclude`
line and the `path` in `crates/menzil-stream/Cargo.toml`, and run the three test files above
against the registry crate. `dropping_a_stream_after_its_own_close_still_sends_nothing` in
`stream_reset.rs` pins the upstream behavior patch 2 works around, so it fails when upstream
changes that behavior. To move to a newer yamux, apply `menzil.patch` to it and re run the
checks in Tests.
