//! Two independent `menzil_stream` connections, wired directly to each
//! other's [`menzil_stream::StreamMux::feed_inbound`] /
//! [`menzil_stream::OutboundFrames::next_frame`] — standing in for
//! whatever a caller otherwise decrypts/encrypts each frame through
//! (`menzil-e2e`, out of scope for this crate, see its own doc comment).
//! This, not the unit tests in `src/`, is the test that actually matters:
//! a real `yamux::Connection` pair multiplexing real streams end to end
//! through this crate's own [`RecordIo`](../src/record_io.rs) adapter,
//! the same role `menzil_e2e::transport::tests::run_live_handshake` and
//! `menzil-node`'s `live_session.rs` play for their own crates.

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_stream::{Inbound, Mode, OutboundFrames, StreamMux};

/// Ferries every frame `from`'s connection produces into `to`'s
/// connection, until `from`'s side has nothing left to ever send (every
/// sender-side handle on that connection dropped). Stands in for an L4
/// session's own send path (menzil-e2e encrypt + L3 SEND) and receive
/// path (L3 RECV + menzil-e2e decrypt) at once, minus the encryption —
/// exactly the seam this crate's own doc comment says it is deliberately
/// unaware of.
async fn pump(mut from: OutboundFrames, to: StreamMux) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

/// Builds one connected pair, with both drivers and both pumps already
/// spawned onto the current tokio runtime.
fn connected_pair(max_record: u32) -> (StreamMux, Inbound, StreamMux, Inbound) {
    let (mux_a, inbound_a, outbound_a, driver_a) = menzil_stream::new(Mode::Client, max_record);
    let (mux_b, inbound_b, outbound_b, driver_b) = menzil_stream::new(Mode::Server, max_record);

    tokio::spawn(driver_a);
    tokio::spawn(driver_b);
    tokio::spawn(pump(outbound_a, mux_b.clone()));
    tokio::spawn(pump(outbound_b, mux_a.clone()));

    (mux_a, inbound_a, mux_b, inbound_b)
}

#[tokio::test]
async fn a_payload_many_times_larger_than_one_yamux_frame_round_trips_exactly() {
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);

    // Several times yamux's own 16 KiB default split size, so this can
    // only pass if `RecordIo` correctly reassembles a write that `yamux`
    // itself split across many separate Data frames (each one a separate
    // `menzil_stream::OutboundFrames` item, by this crate's own
    // one-frame-per-record invariant) back into one byte stream on the
    // receiving side.
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();

    let mut stream_a = mux_a
        .open()
        .await
        .expect("open never fails on a fresh connection");
    let write_payload = payload.clone();
    let writer = tokio::spawn(async move {
        stream_a.write_all(&write_payload).await.unwrap();
        stream_a.flush().await.unwrap();
        stream_a.close().await.unwrap();
    });

    let mut stream_b = inbound_b
        .accept()
        .await
        .expect("the peer must see the stream `mux_a.open()` created");
    let mut received = Vec::new();
    stream_b.read_to_end(&mut received).await.unwrap();

    writer.await.unwrap();
    assert_eq!(received, payload);
}

#[tokio::test]
async fn concurrent_streams_do_not_cross_contaminate_bytes() {
    let (mux_a, _inbound_a, _mux_b, mut inbound_b) = connected_pair(65_535);

    // Each stream's payload is built from its own index so that any
    // misrouting (stream 1's bytes landing in stream 0's, say) shows up
    // as a content mismatch, not just a length mismatch.
    const STREAMS: u8 = 5;
    let mut writers = Vec::new();
    for i in 0..STREAMS {
        let mut stream = mux_a.open().await.unwrap();
        let payload = vec![i; 50_000];
        writers.push(tokio::spawn(async move {
            stream.write_all(&payload).await.unwrap();
            stream.flush().await.unwrap();
            stream.close().await.unwrap();
        }));
    }

    let mut received_tasks = Vec::new();
    for _ in 0..STREAMS {
        let mut stream = inbound_b
            .accept()
            .await
            .expect("every opened stream must be seen");
        received_tasks.push(tokio::spawn(async move {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.unwrap();
            buf
        }));
    }

    for writer in writers {
        writer.await.unwrap();
    }
    let mut received: Vec<Vec<u8>> = Vec::new();
    for task in received_tasks {
        received.push(task.await.unwrap());
    }

    // Streams may be accepted in any order; match each received payload
    // back to the tag it must have come from rather than assuming index
    // `i` on one side lines up with index `i` on the other.
    for buf in &received {
        let tag = buf[0];
        assert!(
            buf.iter().all(|&b| b == tag),
            "stream tagged {tag} had mixed content"
        );
        assert_eq!(buf.len(), 50_000);
    }
    let mut tags: Vec<u8> = received.iter().map(|b| b[0]).collect();
    tags.sort_unstable();
    assert_eq!(tags, (0..STREAMS).collect::<Vec<_>>());
}

#[tokio::test]
async fn feed_inbound_rejects_a_record_that_is_not_exactly_one_frame() {
    let (mux_a, _inbound_a, _mux_b, _inbound_b) = connected_pair(65_535);

    assert!(mux_a.feed_inbound(vec![]).is_err());
    assert!(mux_a.feed_inbound(vec![0u8; 5]).is_err()); // shorter than one header
    let mut too_long = vec![0u8, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // one bare Ping frame
    too_long.push(0xff); // plus trailing garbage
    assert!(mux_a.feed_inbound(too_long).is_err());
}

/// Regression test for a lost-wakeup bug a 2026-10-02 red team review
/// found and this crate's `Driver::poll` then fixed (see its own doc
/// comment on the `continue` after a successful `open()` reply): without
/// that fix, a second `open()` request already queued when the first one
/// resolves waits for some unrelated event to wake `Driver` again, which
/// may never happen on an otherwise idle connection. No peer or pump is
/// needed here — opening a stream is a purely local operation.
#[tokio::test]
async fn several_concurrent_opens_on_an_idle_connection_all_resolve_promptly() {
    let (mux, _inbound, _outbound, driver) = menzil_stream::new(Mode::Client, 65_535);
    tokio::spawn(driver);

    let mut opens = Vec::new();
    for _ in 0..8 {
        let mux = mux.clone();
        opens.push(tokio::spawn(async move { mux.open().await }));
    }

    for open in opens {
        tokio::time::timeout(std::time::Duration::from_secs(2), open)
            .await
            .expect("open() must resolve promptly, not hang on a lost wakeup")
            .unwrap()
            .expect("opening a stream on a fresh, idle connection must succeed");
    }
}

// A live regression test for the companion fix (refusing an open() at
// yamux's own stream cap must end `Driver` with an error, not leave it
// silently "running" a connection yamux already tore down internally —
// see `Driver::poll`'s own doc comment) was attempted here and dropped:
// reaching yamux 0.14.1's real 512-stream table cap first requires
// getting past its *separate*, lower 256-stream unacknowledged-outbound
// cap (`MAX_ACK_BACKLOG`), and two different attempts at a peer that
// acknowledges fast enough both still timed out for reasons not fully
// understood (yamux's own ack/credit interaction needs more direct
// investigation than this test attempted). The fix itself does not rest
// on this test: it is verified directly by reading yamux 0.14.1's own
// `connection.rs`, which shows every `poll_new_outbound` error
// unconditionally transitioning the connection to `Cleanup` — see
// `Driver::poll`'s own doc comment for the exact citation.
