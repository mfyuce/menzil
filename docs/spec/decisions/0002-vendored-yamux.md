# 0002. Vendor yamux 0.14.1 with four small patches

Date: 2026-10-13. Status: proposed and applied in the working tree, to be confirmed before the first release. To be revisited with the criteria of decision 0001 after phase 1.

## Context

Decision 0001 puts yamux inside the end to end records as the stream multiplexer for phase 1. Four defects of yamux 0.14.1 were found by red team reviews of the code built on it, and none of them can be fixed from outside the crate.

1. A stream cannot be reset in most states. Dropping a stream sends an RST only while the stream is fully open. After the stream's own close it sends nothing, so a peer that is blocked on credit waits forever. After the peer's half close it sends a FIN, so the peer reads a truncated reply as a complete one. A reader also cannot tell a FIN, an RST and a lost connection apart; all three read as end of file. protocol.md 5.2 requires that an abnormal end is visible, and per stream revocation (5.3) needs to end a stream whatever state it is in.
2. The receive window counts payload bytes, not memory. Every data frame body is kept as a `Vec` of its own in a queue of its own, which costs about 65 bytes of heap for a one byte frame (measured: 249,000 one byte frames held 16.3 MB). A peer entitled to the windows of 512 streams (144 MiB) could pin gigabytes by cutting its data into small frames and never being read from. The service side of a node makes that reachable.
3. The stream cap ends sessions. A local open at 512 streams ends the connection, and a stream the peer opens at 512 is answered with a GoAway, which ends the session for the peer. The table is fuller than the streams in use, because a dropped stream stays in it until its last frames are written and, with the uplink stalled, they are not: the first review of this change reproduced a session ending at 212 live handles.
4. A stream's owner is told about an RST or a lost connection only while it happens to be polling the stream. `poll_read` and `poll_write` register a waker only while they are pending, and a node that serves a stream by copying between it and a local socket stops polling the stream after the peer's FIN while the target is silent, and while a write to a target that does not read is blocked. The peer's RST or the loss of the session then wakes nobody and the target's socket stays open, for ever (the second review, reproduced in five experiments).

## Options

1. Accept all four and document them. The first leaves truncation invisible to applications, the second leaves a node's memory in the hands of any member with a grant, the third lets an honest burst on a slow uplink end a session, the fourth leaks a descriptor, a task and kernel buffers per aborted stream.
2. Work around them outside yamux. For the memory: parse every inbound frame header in front of yamux, keep a per stream list of unread frames, and release the charge from a hook in the stream's read path; that duplicates yamux's own bookkeeping and breaks silently if the two ever disagree. For the reset: an in band abort in the stream header protocol, which is a wire change. For the cap: nothing outside can see the table. For the teardown: a task per stream that polls it with an empty read would register the waker, but a stream that has ended reads as end of file without registering one, which is exactly the state in question.
3. Replace yamux, with a multiplexer of our own or with QUIC streams. Decision 0001 already plans QUIC for the direct path; doing it now for the relay path means redoing the stream adapter and its review rounds before anything is served.
4. Patch yamux and carry the patch.

## Decision

Option 4. The crate lives in `vendor/yamux` as published on crates.io, with a patch of about 190 added lines outside its tests, 105 of them code (`vendor/yamux/menzil.patch`, described in `vendor/yamux/PATCHES.md`):

1. Data bodies shorter than 1 KiB are appended to the previous chunk of the stream's buffer. Memory held is then at most about twice the window (measured: 254 KB for the 249,000 frames, and 2.05 bytes per byte for the worst pattern, frames alternating 1 KiB and one byte).
2. `Stream::reset_on_drop` makes dropping the stream send an RST in every state except an already closed stream, and `Stream::is_reset` tells a reader whether the end it just saw was an RST or a lost connection rather than a FIN.
3. A stream the peer opens when the table is full is refused with an RST and the connection goes on, and `Connection::num_streams` exposes the table size so that a caller can refuse its own opens first.
4. `Stream::torn_down` returns a future, with a waker of its own, that completes when the peer's RST arrives or the connection goes away under a stream that is not closed in both directions yet, whether or not the peer had half-closed it.

`menzil-stream` builds on them: its `Stream` aborts when dropped unless it was closed on purpose, reading or writing a reset stream is `ConnectionReset`, a connection holds at most 448 streams counted as yamux counts them, and `Stream::torn_down` is what a node serving a stream races against its copy.

The wire format does not change: an RST is a standard yamux frame.

## Consequences

- Security fixes of yamux have to be merged by hand. The vendored crate is about 4,000 lines and the patch is separate, so that is a diff of a few files.
- The crate is outside the cargo workspace, so the lint settings and the test runs of this project do not apply to it and the patch stays reviewable (the formatter does follow it). `PATCHES.md` says how to run the upstream test suite against it.
- The memory a hostile member can make one session hold is bounded but not small: about 163 MiB of unread inbound records, about 295 MiB of yamux buffers (twice 144 MiB) and, in total over the 448 streams, about 78 MiB of our own outbound data when the peer does not read (183,028 bytes a stream), roughly 540 MiB. It is per session; another session is unaffected. A node-wide ceiling is a separate item. The kernel buffers of the sockets a node serves to are outside this figure and are fixed and capped by the node (`menzil-node/src/serve.rs`).
- The patches are independent of this project and are candidates for pull requests to rust-yamux. When a published release has equivalents, the directory goes away.
- A move to QUIC streams for the direct path (decision 0001) removes these problems there; QUIC has RESET_STREAM and per stream accounting by construction.

## Related

`protocol.md` sections 5.2 and 5.3. `vendor/yamux/PATCHES.md`. Decision 0001.
