//! `Stream::torn_down` (`vendor/yamux/PATCHES.md`, patch 4): a stream's owner that is not
//! polling the stream still learns that the peer reset it or that the connection went away.
//!
//! Reading and writing register a waker only while they are pending. A node that serves a
//! stream to a local target stops polling the stream after the peer's FIN (the target is
//! silent), and while a write to the target is blocked; nothing woke it for an RST or a lost
//! session, and the target's socket stayed open (the second L4i review, M1). The tests below
//! never poll the stream they watch.

use std::time::Duration;

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_stream::{Inbound, Mode, OutboundFrames, Stream, StreamMux};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);
/// How long a watcher that must stay pending is given to complete wrongly.
const QUIET: Duration = Duration::from_millis(300);

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
    /// Ends `b`'s connection the way a vanished peer does: nothing will ever be fed to it
    /// again, and its driver ends. The streams `b` handed out stay with their owners.
    fn cut_b(self) {
        self.pump_to_b.abort();
        drop(self.mux_b);
        drop(self.inbound_b);
    }
}

async fn accept(inbound: &mut Inbound) -> Stream {
    timeout(WAIT, inbound.accept())
        .await
        .expect("a stream must arrive")
        .expect("the connection must be alive")
}

/// Polls the stream's watcher on a task of its own, as a pipe does, so that only a wake-up can
/// complete it: nothing polls it again by chance.
fn watch(stream: &Stream) -> JoinHandle<()> {
    tokio::spawn(stream.torn_down())
}

/// The watcher must stay pending for a while.
async fn assert_pending(watcher: &JoinHandle<()>, what: &str) {
    tokio::time::sleep(QUIET).await;
    assert!(!watcher.is_finished(), "the watcher completed {what}");
}

/// The watcher must complete soon.
async fn assert_completes(watcher: &mut JoinHandle<()>, what: &str) {
    timeout(WAIT, watcher)
        .await
        .unwrap_or_else(|_| panic!("the watcher did not complete {what}"))
        .unwrap();
}

/// Sends the request, its FIN, and reads it on `b` up to the end of file: from then on nobody
/// polls `b`'s stream, as in a pipe whose target is silent.
async fn half_closed_by_the_peer(p: &mut Pair) -> (Stream, Stream) {
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"request").await.unwrap();
    a.close().await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    let mut got = Vec::new();
    timeout(WAIT, b.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"request");
    (a, b)
}

#[tokio::test]
async fn an_open_stream_is_not_torn_down() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    let b = accept(&mut p.inbound_b).await;
    let watcher = watch(&b);
    assert_pending(&watcher, "for a healthy stream").await;
    // Traffic does not disturb it either.
    a.write_all(b"more").await.unwrap();
    a.flush().await.unwrap();
    assert_pending(&watcher, "for a healthy stream with traffic").await;
}

#[tokio::test]
async fn the_peers_reset_tears_a_stream_down_that_nobody_polls() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    let b = accept(&mut p.inbound_b).await;
    let mut watcher = watch(&b);
    assert_pending(&watcher, "before the reset").await;

    a.reset();
    assert_completes(&mut watcher, "after the peer's reset").await;
    assert!(b.is_reset());
}

/// The state of a served pipe whose target is silent: the peer's FIN was read, so nothing
/// polls the stream any more. The peer then aborts.
#[tokio::test]
async fn a_reset_after_the_peers_half_close_tears_the_stream_down() {
    let mut p = pair();
    let (a, b) = half_closed_by_the_peer(&mut p).await;
    let mut watcher = watch(&b);
    assert_pending(&watcher, "for a stream that was only half-closed").await;

    a.reset();
    assert_completes(
        &mut watcher,
        "after the peer's reset of a half-closed stream",
    )
    .await;
    // The peer's data was whole, but the reset is still a reset.
    assert!(b.is_reset());
}

/// The same, with the connection lost instead of an RST. The peer's data was whole, so the
/// stream does not read as reset (`is_reset` stays false, patch 2), but its owner can no
/// longer finish it and has to be told.
#[tokio::test]
async fn a_lost_connection_tears_down_a_stream_the_peer_had_half_closed() {
    let mut p = pair();
    let (_a, b) = half_closed_by_the_peer(&mut p).await;
    let mut watcher = watch(&b);
    assert_pending(&watcher, "for a stream that was only half-closed").await;

    p.cut_b();
    assert_completes(&mut watcher, "after the connection was lost").await;
    assert!(
        !b.is_reset(),
        "everything the peer sent before its FIN was whole"
    );
}

#[tokio::test]
async fn a_lost_connection_tears_down_an_open_stream() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    let b = accept(&mut p.inbound_b).await;
    let mut watcher = watch(&b);
    assert_pending(&watcher, "before the connection was lost").await;

    p.cut_b();
    assert_completes(&mut watcher, "after the connection was lost").await;
    assert!(b.is_reset());
}

/// A stream that we closed ourselves and the peer then reset (its reset crossed our FIN or came
/// after it) is torn down as well: the peer did not finish it.
#[tokio::test]
async fn a_reset_after_our_own_close_tears_the_stream_down() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    let mut b = accept(&mut p.inbound_b).await;
    let mut watcher = watch(&b);
    b.close().await.unwrap();
    assert_pending(&watcher, "after only our own close").await;

    a.reset();
    assert_completes(&mut watcher, "after the peer's reset").await;
}

/// A stream that ended cleanly in both directions is never torn down, not by a late RST (the
/// peer's `reset` crossing our FIN) and not by the connection ending afterwards.
#[tokio::test]
async fn a_stream_that_ended_cleanly_is_never_torn_down() {
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
    let watcher = watch(&stream);
    // The peer's FIN came with the SYN and ours goes out now: finished both ways.
    stream.close().await.unwrap();
    assert_pending(&watcher, "after a clean end").await;

    mux.feed_inbound(data(RST, b"")).unwrap();
    assert_pending(&watcher, "for a late RST after a clean end").await;

    drop(mux);
    drop(inbound);
    assert_pending(&watcher, "for the connection ending after a clean end").await;
}

/// An RST can come on a window update frame (the yamux spec allows it, this `yamux` never sends
/// it).
#[tokio::test]
async fn an_rst_on_a_window_update_frame_tears_the_stream_down() {
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
    let stream = accept(&mut inbound).await;
    let mut watcher = watch(&stream);
    assert_pending(&watcher, "before the RST").await;

    mux.feed_inbound(frame(1, RST, 0, b"")).unwrap();
    assert_completes(&mut watcher, "after an RST on a window update frame").await;
}

#[tokio::test]
async fn a_watcher_made_after_the_teardown_completes_at_once() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    let b = accept(&mut p.inbound_b).await;
    let mut first = watch(&b);
    a.reset();
    assert_completes(&mut first, "after the peer's reset").await;

    let mut late = watch(&b);
    assert_completes(&mut late, "for a stream torn down before it was made").await;
}

/// The waker is the one of the task that polled the watcher last, wherever that is: a watcher
/// polled once and then moved to another task is still woken.
#[tokio::test]
async fn a_watcher_polled_by_two_tasks_in_turn_wakes_the_last() {
    let mut p = pair();
    let mut a = p.mux_a.open().await.unwrap();
    a.write_all(b"x").await.unwrap();
    let b = accept(&mut p.inbound_b).await;
    let mut watcher = Box::pin(b.torn_down());
    assert!(
        timeout(QUIET, watcher.as_mut()).await.is_err(),
        "pending before the reset"
    );
    // A different task polls it from now on.
    let mut task = tokio::spawn(async move {
        watcher.await;
    });
    tokio::time::sleep(QUIET).await;
    assert!(!task.is_finished());
    a.reset();
    assert_completes(&mut task, "on the task that polled it last").await;
}
