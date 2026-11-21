# Vendored yamux 0.14.1

This directory is the source of the `yamux` crate, version 0.14.1, as published on
crates.io (upstream commit `cc3d0e89f615ef4f329f7a246c95a8ff1e8cc12d` of
github.com/libp2p/rust-yamux, whose `yamux/src` is also what its release commit `6610cff`
holds), with the six patches below. `menzil-stream` depends on it by
path. Licence: Apache-2.0 OR MIT, copyright Parity Technologies (UK) Ltd.; the texts are
`LICENSE-APACHE` and `LICENSE-MIT` in this directory, copied from the upstream commit. Why
the crate is vendored and not used from the registry: `docs/spec/decisions/0002-vendored-yamux.md`.

`menzil.patch` is the complete difference to the published source (`a/` is the published
crate, `b/` this directory), so a reviewer reads the change in one place: 606 added lines
and 47 removed in all (comments, blanks and unit tests included; patch 5 alone is about 420 of
the added lines, about 190 of them unit tests). Everything the patch does
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

## Patch 5: the unread bytes of every stream can be metered, and the frame cap is configurable (`src/lib.rs`, `src/chunks.rs`, `src/connection/stream.rs`, `src/connection.rs`, `src/frame/io.rs`)

The receive windows (and patch 1) bound what one stream may hold, but a caller that runs many
connections has no way to see, let alone bound, the sum of the bytes its streams hold received
and not yet read. `menzil-node` counts unprocessed L4 records against a per session budget and
a node wide ceiling (C1), and the stream data buffered inside yamux was outside both (round C1,
M1).

- `trait BufferMeter { fn buffered(&self, n: usize); fn consumed(&self, n: usize); }` and the
  `Config` setter `set_buffer_meter(Option<Arc<dyn BufferMeter>>)` (default none). Every stream
  of the connection reports to it: `Chunks` calls `buffered` for every byte that joins the
  receive queue (the coalescing path of patch 1 included) and `consumed` for every byte that
  leaves it, with the exact change of `Chunks::len()` each time, never a zero report. A `Drop`
  of `Chunks` reports what is left as consumed, so a stream dropped with unread data, an RST
  that discards it and a connection that goes away all balance the account. The meter runs with
  the stream's lock held: it must be cheap and must not call back into yamux.
- `Chunks::read_into(&mut [u8]) -> usize` replaces the `front_mut().advance` loop of
  `Stream::poll_read` (same behavior, one place that reports); `front_mut` is gone.
- `Config::set_max_frame_body(usize)` (default 1 MiB, upstream's `MAX_FRAME_BODY_LEN`, which is
  removed): a data frame whose header claims a longer body is a connection error
  (`FrameDecodeError::FrameTooLarge`) before the body is allocated. A receiver limit, not a wire
  change: a peer that sends bigger frames than this receiver accepts is cut off, so callers set
  it at or above what their own senders produce (`split_send_size`).

Defaults leave behavior unchanged. Nothing on the wire changes.

## Patch 6: a grown receive window is given back when the stream does not use it (`src/connection/stream/flow_control.rs`, `src/connection/rtt.rs` test helper)

Upstream (and this directory before patch 6) never lowers a stream's `max_receive_window`; the
growth returns to the connection's budget only when the stream is dropped. A long lived stream that
once moved a bulk transfer (an SSH session, a WebSocket) kept its grown maximum for life, and with
`menzil-stream`'s per session growth budget (15.75 MiB) a few of them left every later stream at the
initial 256 KiB (design note `docs/private/yamux-window-design.md`, section 2).

Now, when a window update is due (half the maximum has been read) and the previous update was at
least `max(1 s, 4 x RTT)` ago, the credit that would be granted is not granted: the maximum falls by
that amount (not below `DEFAULT_CREDIT`) and the same amount goes back to the shared counter. The
sender keeps every byte of credit it already holds; the maximum never drops below credit outstanding
plus data buffered, so an honest peer is never cut off and `assert_invariants` still holds. A stream
that fills half its window in less than that keeps it. Wire format unchanged, receiver only. One
step per due update; a stream idle for long converges to 256 KiB over successive updates.

Tests (`shrink_tests` in the same file, in `cargo test --lib`): an idle grown window returns its whole
growth to the counter and grants only `DEFAULT_CREDIT`; a shrink with credit outstanding and unread
data stays at or above their sum; a fast stream keeps its window. Mutants: `if false &&` on the
condition and dropping the counter return both fail the first test.

## Memory this does not bound

The windows (and patch 1) bound what a peer can have us hold of *its* data. Patch 5 makes
that data visible to a node wide account (`BufferMeter`) and the frame body cap configurable,
but yamux itself still enforces nothing beyond the windows: a caller that does not install a
meter and a smaller `max_frame_body` has the figures below. Other memory is
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
- `src/chunks.rs` has unit tests for patch 1 and for patch 5 (U1: a fixed seed pseudo random
  sequence of push, pop and `read_into` against a counting meter, `meter == len()` after every
  operation and 0 after the drop; the coalescing path and a reader in the middle of a chunk
  separately), `src/frame/io.rs` one for the configurable frame cap (a header claiming 70,000
  bytes against a cap of 65,535 is `FrameTooLarge`, a body of exactly the cap is read). The
  quickcheck based tests and `Arbitrary` impls of upstream (`lib.rs`, `connection/rtt.rs`,
  `frame/header.rs`, `frame/io.rs` property test, `flow_control.rs`) are behind `#[cfg(all(test,
  upstream_quickcheck))]` since 2026-11-15 (patch 5 follow up, round T1d N1): quickcheck is not a
  dependency of the published package (it needs `quickcheck-ext`, a path dependency of upstream's
  workspace), so without the gate `cargo test --lib` did not even compile and the unit tests above
  never ran. Now `cd vendor/yamux && CARGO_TARGET_DIR=<own> cargo test --offline --lib` runs 18
  tests (2 upstream, 12 chunks, 1 frame cap, 3 window shrink); `docs/private/tools/gate.sh` runs it after the
  workspace tests. Remove the `Cargo.lock` cargo leaves in this directory (the directory is
  excluded from the workspace).
- To run upstream's own suite against these sources, take the upstream commit above, replace its
  `yamux/src` with this directory's `src`, and run `RUSTFLAGS="--cfg upstream_quickcheck" cargo
  test -p yamux --lib -p test-harness --tests` (with a `CARGO_TARGET_DIR` of its own; without the
  cfg the quickcheck modules are skipped). The last time this was done (2026-10-13, with patch 4,
  before the cfg gate existed) all of it passed: the unit tests (14: 5 upstream, 9 for patch 1)
  and upstream's integration tests `ack_backlog`, `ack_timing` and `poll_api` (property tests
  over random message sizes included). Patches 5 and its cfg gate have not been run against the
  upstream commit (not available offline): that run is still owed.
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
