//! A stream can be reset whatever state it is in, and reading a reset stream
//! is an error, not an end of file (`vendor/yamux/PATCHES.md`, patch 2;
//! `menzil_stream::Stream`; TOBEDECIDED item 11).
//!
//! Registry `yamux` 0.14.1 has neither. Dropping a stream sends an RST only
//! while the stream is still fully open: after the stream's own close it
//! sends nothing, so a peer blocked on credit hangs, and after the peer's FIN
//! it answers with a FIN, so the peer sees a clean end. And a FIN, an RST and
//! a connection that went away all read as plain end of file. protocol.md 5.2
//! wants abnormal ends visible ("never with a clean end of file"), and a node
//! that has just found its local target dead after the client half-closed is
//! exactly the state where a drop is silent.

use std::io;
use std::time::Duration;

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_stream::{Inbound, Mode, OutboundFrames, Stream, StreamMux};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

async fn pump(mut from: OutboundFrames, to: StreamMux) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

/// Two connected sides: `a` is the client (odd stream ids), `b` the server.
struct Pair {
    mux_a: StreamMux,
    mux_b: StreamMux,
    inbound_b: Inbound,
    pump_to_b: JoinHandle<()>,
}

fn pair() -> Pair {
    let (mux_a, _inbound_a, outbound_a, driver_a) = menzil_stream::new(Mode::Client, 65_535);
    let (mux_b, inbound_b, outbound_b, driver_b) = menzil_stream::new(Mode::Server, 65_535);
    tokio::spawn(driver_a);
    tokio::spawn(driver_b);
    let pump_to_b = tokio::spawn(pump(outbound_a, mux_b.clone()));
    tokio::spawn(pump(outbound_b, mux_a.clone()));
    Pair {
        mux_a,
        mux_b,
        inbound_b,
        pump_to_b,
    }
}

impl Pair {
    /// Ends `b`'s connection the way a vanished peer does: nothing will ever
    /// be fed to it again.
    fn cut_b(self) {
        self.pump_to_b.abort();
        drop(self.mux_b);
    }
}

async fn accept(inbound: &mut Inbound) -> Stream {
    timeout(WAIT, inbound.accept())
        .await
        .expect("a stream must arrive")
        .expect("the connection must be alive")
}

/// Reads until the stream ends, however it ends: what arrived, and how it ended.
async fn read_all(stream: &mut Stream) -> (Vec<u8>, io::Result<usize>) {
    let mut got = Vec::new();
    let result = timeout(WAIT, stream.read_to_end(&mut got))
        .await
        .expect("the stream must end");
    (got, result)
}

/// The stream must end with a FIN.
async fn read_clean(stream: &mut Stream) -> Vec<u8> {
    let (got, result) = read_all(stream).await;
    result.expect("a FIN is a clean end of file");
    got
}

/// The stream must end with a reset; what arrived before it is returned.
async fn read_reset(stream: &mut Stream) -> Vec<u8> {
    let (got, result) = read_all(stream).await;
    assert_eq!(
        result.expect_err("a reset is not a clean end").kind(),
        io::ErrorKind::ConnectionReset
    );
    got
}

#[tokio::test]
async fn a_fin_is_a_clean_end_on_both_sides() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut b).await, b"request");
    assert!(!b.is_reset(), "a FIN is not a reset");

    b.write_all(b"response").await.unwrap();
    b.close().await.unwrap();
    assert_eq!(read_clean(&mut a).await, b"response");
    assert!(!a.is_reset());

    // Both sides are closed: nothing is left to abort, and nothing is sent
    // that could disturb the connection.
    a.reset();
    b.reset();
    let mut again = p.mux_a.open().await.unwrap();
    again.write_all(b"still alive").await.unwrap();
    again.close().await.unwrap();
    let mut again_b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut again_b).await, b"still alive");
}

/// The case the TOBEDECIDED item names: the client half-closed after its
/// request, then the target failed. Dropping `b` here sends a FIN, and the
/// client reads a truncated response as a complete one.
#[tokio::test]
async fn a_reset_after_the_peer_half_closed_reaches_the_peer() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut b).await, b"request");
    assert!(!b.is_reset());

    b.reset();
    // Not the empty reply a FIN would have meant.
    assert_eq!(read_reset(&mut a).await, b"");
    assert!(a.is_reset());
}

/// The other state registry `yamux` is silent in: after its own close, a
/// dropped stream sends nothing at all, so a peer that is blocked out of
/// credit never learns.
#[tokio::test]
async fn a_reset_after_our_own_close_unblocks_a_peer_waiting_for_credit() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;

    // `a` never reads, so `b` runs out of its 256 KiB of credit.
    let writer = tokio::spawn(async move {
        let result = b.write_all(&vec![7u8; 1 << 20]).await;
        (result, b)
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!writer.is_finished(), "the write must be blocked on credit");

    a.reset();
    let (result, b) = timeout(WAIT, writer)
        .await
        .expect("the RST must end the blocked write")
        .unwrap();
    assert_eq!(
        result.expect_err("the write cannot succeed").kind(),
        io::ErrorKind::ConnectionReset
    );
    assert!(b.is_reset());
}

/// Pins the limitation of plain dropping that `reset` exists for. If a later
/// `yamux` fixes it, this test fails and the patch is worth reconsidering.
#[tokio::test]
async fn dropping_a_stream_after_its_own_close_still_sends_nothing() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    let writer = tokio::spawn(async move { b.write_all(&vec![7u8; 1 << 20]).await });

    drop(a);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !writer.is_finished(),
        "a plain drop after close told the peer nothing before; if this fails, yamux changed"
    );
}

#[tokio::test]
async fn data_already_written_arrives_before_the_reset() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"hello").await.unwrap();
    a.reset();

    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_reset(&mut b).await, b"hello");
    assert!(b.is_reset());
}

#[tokio::test]
async fn writing_to_a_stream_the_peer_reset_fails_as_a_reset() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"hello").await.unwrap();
    a.reset();

    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_reset(&mut b).await, b"hello");
    // Still failing on a second read, and writes fail the same way.
    assert_eq!(
        b.read(&mut [0u8; 4]).await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(
        b.write_all(b"too late").await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    // An empty read is not the end of anything.
    assert_eq!(b.read(&mut []).await.unwrap(), 0);
}

#[tokio::test]
async fn resetting_a_stream_that_never_sent_anything_harms_nobody() {
    let mut p = pair();
    let unused = p.mux_a.open().await.unwrap();
    unused.reset();

    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"after").await.unwrap();
    a.close().await.unwrap();
    // The first stream never reached the peer, so the first one it sees is
    // the second.
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut b).await, b"after");
    assert!(!b.is_reset());
}

#[tokio::test]
async fn a_connection_that_ends_under_an_open_stream_reads_as_a_reset() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"partial").await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    let mut seen = [0u8; 7];
    timeout(WAIT, b.read_exact(&mut seen))
        .await
        .unwrap()
        .unwrap();
    assert!(!b.is_reset());

    p.cut_b();
    assert_eq!(read_reset(&mut b).await, b"");
    assert!(
        b.is_reset(),
        "the peer never closed its side: this is a cut, not an end"
    );
}

#[tokio::test]
async fn a_connection_that_ends_after_the_peer_closed_is_still_a_clean_end() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"complete").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut b).await, b"complete");

    p.cut_b();
    // The FIN arrived before the connection went: what `b` read was whole.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!b.is_reset());
    assert_eq!(b.read(&mut [0u8; 4]).await.unwrap(), 0);
}

/// The first yamux review's M2: dropping is an abort unless the stream was closed. The server here
/// reads a whole request (the client half-closed), writes half of its answer and goes away
/// without calling anything: a panic, an early return, a cancelled future. Stock `yamux`
/// answers the half close with a FIN, and the client reads 500 bytes as a whole reply.
#[tokio::test]
async fn dropping_a_stream_that_was_not_closed_aborts_it() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut b).await, b"request");
    b.write_all(&[5u8; 500]).await.unwrap();
    drop(b);

    assert_eq!(read_reset(&mut a).await, vec![5u8; 500]);
    assert!(a.is_reset());
}

#[tokio::test]
async fn dropping_a_stream_that_was_closed_is_a_clean_end() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut b).await, b"request");
    b.write_all(&[5u8; 500]).await.unwrap();
    b.close().await.unwrap();
    drop(b);

    assert_eq!(read_clean(&mut a).await, vec![5u8; 500]);
    assert!(!a.is_reset());
}

/// A task that owns a stream and is aborted (a node shutting down, a `select!` branch that lost,
/// a timeout) drops it mid-use: the peer must see a reset.
#[tokio::test]
async fn aborting_a_task_that_owns_a_stream_resets_it() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    let task = tokio::spawn(async move {
        let mut request = Vec::new();
        b.read_to_end(&mut request).await.unwrap();
        // Working on the answer, forever.
        std::future::pending::<()>().await;
        drop(b);
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    task.abort();
    let _ = task.await;

    assert_eq!(read_reset(&mut a).await, b"");
}

/// The first yamux review's L1: after a reset, flushing and closing fail like reading and writing do.
#[tokio::test]
async fn flushing_and_closing_a_reset_stream_fail_as_a_reset() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"hello").await.unwrap();
    a.reset();
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_reset(&mut b).await, b"hello");

    assert_eq!(
        b.flush().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert_eq!(
        b.close().await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
}

/// A write after this side's own close is the caller's mistake, not a reset, and keeps its kind.
#[tokio::test]
async fn a_write_after_our_own_close_is_not_reported_as_a_reset() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let _b = accept(&mut p.inbound_b).await;

    let error = a.write_all(b"more").await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WriteZero);
    assert!(!a.is_reset());
}

/// The connection lost under a stream the peer had half-closed: reading is a clean end (the
/// peer's FIN was received), but this side can no longer write, and says so as a reset.
#[tokio::test]
async fn writing_after_the_connection_was_lost_is_reported_as_a_reset() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    assert_eq!(read_clean(&mut b).await, b"request");

    p.cut_b();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!b.is_reset(), "everything the peer sent was whole");
    assert_eq!(
        b.write_all(b"answer").await.unwrap_err().kind(),
        io::ErrorKind::ConnectionReset
    );
}

/// Resetting a stream that is closed in both directions sends nothing: there is nothing left to
/// abort, and an RST for a stream the peer has forgotten is noise.
#[tokio::test]
async fn resetting_a_stream_that_is_closed_both_ways_sends_nothing() {
    const SYN: u16 = 1;
    const FIN: u16 = 4;
    const RST: u16 = 8;
    let mut frame = vec![0, 0];
    frame.extend_from_slice(&(SYN | FIN).to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&3u32.to_be_bytes());
    frame.extend_from_slice(b"abc");

    let (mux, mut inbound, mut outbound, driver) = menzil_stream::new(Mode::Server, 65_535);
    tokio::spawn(driver);
    let sent = tokio::spawn(async move {
        let mut frames = Vec::new();
        while let Some(frame) = outbound.next_frame().await {
            frames.push(frame);
        }
        frames
    });
    mux.feed_inbound(frame).unwrap();
    let mut stream = accept(&mut inbound).await;
    assert_eq!(read_clean(&mut stream).await, b"abc");
    // Our side closes: the stream is closed in both directions.
    stream.close().await.unwrap();
    stream.reset();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop((mux, inbound));
    let frames = timeout(WAIT, sent).await.unwrap().unwrap();
    assert!(!frames.is_empty(), "the close itself went out");
    for frame in &frames {
        let flags = u16::from_be_bytes([frame[2], frame[3]]);
        assert_eq!(
            flags & RST,
            0,
            "nothing may reset a closed stream: {frame:?}"
        );
    }
}

/// A stream that ended cleanly stays clean when an RST for it arrives late
/// (the peer's `reset` crossed our FIN on the wire): everything it delivered
/// before its FIN was whole.
#[tokio::test]
async fn a_late_rst_does_not_taint_a_stream_that_already_ended_cleanly() {
    const SYN: u16 = 1;
    const FIN: u16 = 4;
    const RST: u16 = 8;
    fn data(flags: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0, 0];
        f.extend_from_slice(&flags.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&(body.len() as u32).to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    let (mux, mut inbound, mut outbound, driver) = menzil_stream::new(Mode::Server, 65_535);
    tokio::spawn(driver);
    tokio::spawn(async move { while outbound.next_frame().await.is_some() {} });
    mux.feed_inbound(data(SYN | FIN, b"abc")).unwrap();
    let mut stream = accept(&mut inbound).await;
    // The peer's FIN came with the SYN and ours goes out now: both directions are
    // finished before the RST below is fed.
    stream.close().await.unwrap();

    mux.feed_inbound(data(RST, b"")).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(read_clean(&mut stream).await, b"abc");
    assert!(!stream.is_reset());
}

/// A window update can carry the RST flag too (the yamux spec allows it, this
/// `yamux` never sends it), so a peer that does is reported the same way.
#[tokio::test]
async fn an_rst_on_a_window_update_frame_is_a_reset_too() {
    const SYN: u16 = 1;
    const RST: u16 = 8;
    fn frame(tag: u8, flags: u16, len: u32, body: &[u8]) -> Vec<u8> {
        let mut f = vec![0, tag];
        f.extend_from_slice(&flags.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.extend_from_slice(&len.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    let (mux, mut inbound, mut outbound, driver) = menzil_stream::new(Mode::Server, 65_535);
    tokio::spawn(driver);
    tokio::spawn(async move { while outbound.next_frame().await.is_some() {} });
    mux.feed_inbound(frame(0, SYN, 3, b"abc")).unwrap();
    let mut stream = accept(&mut inbound).await;
    mux.feed_inbound(frame(1, RST, 0, b"")).unwrap();

    assert_eq!(read_reset(&mut stream).await, b"abc");
    assert!(stream.is_reset());
}
