//! A connection stays clear of `yamux`'s 512-stream cap (TODO.md L4h5's stream-count note, the
//! L4i review's finding M1).
//!
//! Stock `yamux` ends a session when a local open meets its cap, and answers a peer's stream
//! past the cap with a GoAway, which ends the session for the peer. This crate stops at
//! `MAX_LIVE_STREAMS` counted the way `yamux` counts: its table, which also holds a stream that
//! was dropped until its last frames are written. An `open` past the limit fails on its own, a
//! stream the peer opens past it is reset, and the vendored `yamux` refuses a stream at 512 with
//! an RST instead of ending the connection.
//!
//! The first version of this crate counted live handles instead, and a stalled uplink defeated
//! it: streams dropped with data queued stayed in `yamux`'s table, the handle count read zero,
//! and the 213th open ended the session. `lingering_streams_count_against_the_limit` is that
//! scenario.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_stream::{
    Inbound, MAX_LIVE_STREAMS, Mode, OutboundFrames, Stream, StreamMux, StreamMuxError,
};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(10);

/// Forwards frames while `open` is set; while it is not, the frames wait, which is an uplink
/// that is stalled (the relay is slow, the peer's credit has run out).
async fn gated_pump(mut from: OutboundFrames, to: StreamMux, open: Arc<AtomicBool>) {
    while let Some(frame) = from.next_frame().await {
        while !open.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

struct Side {
    mux: StreamMux,
    inbound: Inbound,
    driver: JoinHandle<Result<(), StreamMuxError>>,
    /// Whether this side's frames reach the other side.
    uplink: Arc<AtomicBool>,
}

fn connected_pair() -> (Side, Side) {
    let (mux_a, inbound_a, outbound_a, driver_a) = menzil_stream::new(Mode::Client, 65_535);
    let (mux_b, inbound_b, outbound_b, driver_b) = menzil_stream::new(Mode::Server, 65_535);
    let (driver_a, driver_b) = (tokio::spawn(driver_a), tokio::spawn(driver_b));
    let (uplink_a, uplink_b) = (
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(true)),
    );
    tokio::spawn(gated_pump(outbound_a, mux_b.clone(), uplink_a.clone()));
    tokio::spawn(gated_pump(outbound_b, mux_a.clone(), uplink_b.clone()));
    (
        Side {
            mux: mux_a,
            inbound: inbound_a,
            driver: driver_a,
            uplink: uplink_a,
        },
        Side {
            mux: mux_b,
            inbound: inbound_b,
            driver: driver_b,
            uplink: uplink_b,
        },
    )
}

/// Opens one stream from `from`, has `to` accept it and answers on it, so that the
/// stream is acknowledged and `yamux` does not hold the next open back.
async fn open_pair(from: &StreamMux, to: &mut Inbound) -> (Stream, Stream) {
    let mut opened = from.open().await.expect("the open must succeed");
    opened.write_all(b"1").await.unwrap();
    let mut accepted = timeout(WAIT, to.accept())
        .await
        .expect("the stream must arrive")
        .expect("the connection is alive");
    accepted.write_all(b"2").await.unwrap();
    // Read both bytes, so that nothing is left in either buffer.
    let mut byte = [0u8; 1];
    timeout(WAIT, accepted.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&byte, b"1");
    timeout(WAIT, opened.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&byte, b"2");
    (opened, accepted)
}

/// Opens until it works, for after streams were dropped: a slot comes back at once but
/// `yamux` removes the stream from its table only when it processes the drop.
async fn open_when_there_is_room(mux: &StreamMux) -> Stream {
    for _ in 0..500 {
        match mux.open().await {
            Ok(stream) => return stream,
            Err(StreamMuxError::StreamLimit(_)) => {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
            Err(other) => panic!("the connection died: {other:?}"),
        }
    }
    panic!("the table never made room");
}

#[tokio::test]
async fn an_open_at_the_limit_fails_alone_and_works_again_after_a_drop() {
    let (a, mut b) = connected_pair();
    let mut held = Vec::new();
    for _ in 0..MAX_LIVE_STREAMS {
        held.push(open_pair(&a.mux, &mut b.inbound).await);
    }
    assert_eq!(a.mux.live_streams(), MAX_LIVE_STREAMS);
    assert_eq!(b.mux.live_streams(), MAX_LIVE_STREAMS);

    // Both directions are full: neither side can open another, and neither failure is fatal.
    for mux in [&a.mux, &b.mux] {
        match mux.open().await {
            Err(StreamMuxError::StreamLimit(limit)) => assert_eq!(limit, MAX_LIVE_STREAMS),
            other => panic!("expected the stream limit, got {other:?}"),
        }
    }
    // Every held stream still works.
    let (opened, accepted) = held.last_mut().unwrap();
    opened.write_all(b"alive").await.unwrap();
    let mut got = [0u8; 5];
    timeout(WAIT, accepted.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"alive");

    // A handle's slot comes back when the stream is dropped, and room in the table a moment later.
    let (opened, accepted) = held.pop().unwrap();
    drop(opened);
    assert_eq!(a.mux.live_streams(), MAX_LIVE_STREAMS - 1);
    drop(accepted);
    let mut again = open_when_there_is_room(&a.mux).await;
    again.write_all(b"again").await.unwrap();
    let mut accepted = timeout(WAIT, b.inbound.accept()).await.unwrap().unwrap();
    let mut got = [0u8; 5];
    timeout(WAIT, accepted.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"again");
    assert_eq!(a.mux.refused_inbound_streams(), 0);
    assert_eq!(b.mux.refused_inbound_streams(), 0);
    assert!(!a.driver.is_finished() && !b.driver.is_finished());
}

/// The L4i review's M1, local half. B's uplink stalls, B writes a response on 300 streams and
/// drops them: no handle is alive, but `yamux` keeps all 300 until it can write their frames.
/// Opening more must hit the limit, not `yamux`'s cap.
#[tokio::test]
async fn lingering_streams_count_against_the_limit() {
    let (mut a, b) = connected_pair();
    let mut held = Vec::new();
    for _ in 0..300 {
        held.push(open_pair(&b.mux, &mut a.inbound).await);
    }
    b.uplink.store(false, Ordering::SeqCst);
    let mut a_side = Vec::new();
    for (mut b_stream, a_stream) in held {
        timeout(WAIT, b_stream.write_all(&[9u8; 64 * 1024]))
            .await
            .expect("the write must not hang")
            .unwrap();
        drop(b_stream);
        a_side.push(a_stream);
    }
    assert_eq!(b.mux.live_streams(), 0, "no handle is alive any more");

    // The 300 are still in the table, so the limit is met after 148 more.
    let mut opened = Vec::new();
    loop {
        match timeout(WAIT, b.mux.open())
            .await
            .expect("open must not hang")
        {
            Ok(stream) => opened.push(stream),
            Err(StreamMuxError::StreamLimit(limit)) => {
                assert_eq!(limit, MAX_LIVE_STREAMS);
                break;
            }
            Err(other) => panic!("the connection died instead of refusing: {other:?}"),
        }
        assert!(opened.len() <= MAX_LIVE_STREAMS, "the limit never came");
    }
    assert_eq!(opened.len(), MAX_LIVE_STREAMS - 300);
    assert!(!b.driver.is_finished(), "the connection must survive");

    // The uplink recovers: the table empties and the streams A holds are told they were reset.
    b.uplink.store(true, Ordering::SeqCst);
    let mut buf = Vec::new();
    let first = timeout(WAIT, a_side[0].read_to_end(&mut buf))
        .await
        .unwrap();
    assert_eq!(
        buf.len(),
        64 * 1024,
        "the response arrived before the reset"
    );
    assert!(
        first.is_err(),
        "a stream dropped with data pending is aborted"
    );
    let _fresh = open_when_there_is_room(&b.mux).await;
    assert!(!a.driver.is_finished() && !b.driver.is_finished());
}

/// The L4i review's M1, peer half: A (an honest peer) has 300 streams to B, B answers on each
/// while its uplink is stalled and drops them, A gives up and opens 250 more. B's table cannot
/// take them all; what it cannot take is refused with an RST and the session survives, where
/// stock `yamux` answered with a GoAway that ended it.
#[tokio::test]
async fn a_burst_of_streams_into_a_full_table_is_refused_not_fatal() {
    let (a, mut b) = connected_pair();
    let mut held = Vec::new();
    for _ in 0..300 {
        held.push(open_pair(&a.mux, &mut b.inbound).await);
    }
    b.uplink.store(false, Ordering::SeqCst);
    let mut a_old = Vec::new();
    for (a_stream, mut b_stream) in held {
        timeout(WAIT, b_stream.write_all(&[9u8; 64 * 1024]))
            .await
            .expect("the write must not hang")
            .unwrap();
        drop(b_stream);
        a_old.push(a_stream);
    }
    // A's application gives up on the slow responses.
    drop(std::mem::take(&mut a_old));
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut a_new = Vec::new();
    for _ in 0..250 {
        let mut stream = timeout(WAIT, a.mux.open())
            .await
            .expect("open must not hang")
            .expect("A's own table is small");
        stream.write_all(b"x").await.unwrap();
        a_new.push(stream);
    }
    let mut b_new = Vec::new();
    while let Ok(Some(stream)) = timeout(Duration::from_millis(500), b.inbound.accept()).await {
        b_new.push(stream);
    }
    assert!(
        b_new.len() <= MAX_LIVE_STREAMS - 300,
        "B's table was nearly full: it took {}",
        b_new.len()
    );
    assert!(
        b.mux.refused_inbound_streams() > 0,
        "some had to be refused"
    );

    // B's uplink recovers. Neither connection ended, and a fresh stream works.
    b.uplink.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(!b.driver.is_finished(), "B's connection must survive");
    assert!(!a.driver.is_finished(), "so must A's");
    drop((a_new, b_new));
    let (mut fresh_a, mut fresh_b) = {
        let mut opened = open_when_there_is_room(&a.mux).await;
        opened.write_all(b"fresh").await.unwrap();
        let accepted = loop {
            let stream = timeout(WAIT, b.inbound.accept()).await.unwrap().unwrap();
            // Leftovers of the burst may still be queued; the fresh one carries "fresh".
            let mut stream = stream;
            let mut probe = [0u8; 5];
            if timeout(Duration::from_millis(300), stream.read_exact(&mut probe))
                .await
                .is_ok_and(|r| r.is_ok())
                && &probe == b"fresh"
            {
                break stream;
            }
        };
        (opened, accepted)
    };
    fresh_b.write_all(b"ok").await.unwrap();
    let mut two = [0u8; 2];
    timeout(WAIT, fresh_a.read_exact(&mut two))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&two, b"ok");
}

/// Raw frames, so that one side can be pushed past the limit without its own `open` getting
/// in the way: the peer here does not honor our limit.
#[tokio::test]
async fn a_stream_the_peer_opens_past_the_limit_is_reset_and_the_connection_survives() {
    const SYN: u16 = 1;
    const FIN: u16 = 4;
    fn syn_frame(stream: u32, flags: u16) -> Vec<u8> {
        let mut f = vec![0, 0];
        f.extend_from_slice(&(SYN | flags).to_be_bytes());
        f.extend_from_slice(&stream.to_be_bytes());
        f.extend_from_slice(&1u32.to_be_bytes());
        f.push(b'x');
        f
    }

    let (mux, mut inbound, mut outbound, driver) = menzil_stream::new(Mode::Server, 65_535);
    let driver = tokio::spawn(driver);
    // Everything the server sends is collected: RST frames show up here.
    let sent = tokio::spawn(async move {
        let mut frames = Vec::new();
        while let Some(frame) = outbound.next_frame().await {
            frames.push(frame);
        }
        frames
    });

    let total = MAX_LIVE_STREAMS + 40;
    let mut held = Vec::new();
    for i in 0..total {
        // The refused streams arrive with a FIN as well: dropping such a stream would answer
        // with a FIN, which reads as a clean end, so only a reset tells the peer.
        let flags = if i >= MAX_LIVE_STREAMS { FIN } else { 0 };
        mux.feed_inbound(syn_frame(1 + 2 * i as u32, flags))
            .unwrap();
        // One at a time, so the driver settles each stream before the next arrives.
        if i < MAX_LIVE_STREAMS {
            held.push(timeout(WAIT, inbound.accept()).await.unwrap().unwrap());
        } else {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
    assert_eq!(mux.live_streams(), MAX_LIVE_STREAMS);
    assert_eq!(mux.refused_inbound_streams(), 40);
    assert!(!driver.is_finished(), "the connection must survive");
    // The refused streams were never handed up.
    assert!(
        timeout(Duration::from_millis(100), inbound.accept())
            .await
            .is_err()
    );

    // Each refused stream got an RST (flag 8) addressed to its id.
    drop(mux);
    drop(inbound);
    drop(held);
    let frames = timeout(WAIT, sent).await.unwrap().unwrap();
    let rst_for = |id: u32| {
        frames.iter().any(|f| {
            f.len() >= 12
                && f[1] == 0
                && u16::from_be_bytes([f[2], f[3]]) & 8 != 0
                && u32::from_be_bytes([f[4], f[5], f[6], f[7]]) == id
        })
    };
    for i in MAX_LIVE_STREAMS..total {
        assert!(rst_for(1 + 2 * i as u32), "no RST for refused stream {i}");
    }
}

/// The vendored `yamux` refuses a stream at its own cap with an RST and goes on: no GoAway, the
/// connection stays up. The Driver's own limit is out of the way here (it refuses first), so
/// this feeds a bare `yamux` connection through the adapter's frame boundary directly.
#[tokio::test]
async fn yamux_refuses_a_stream_at_its_cap_instead_of_ending_the_connection() {
    const SYN: u16 = 1;
    /// A stream is opened by its first frame: a data frame with a body, or a window update
    /// (what a stream that reads before it writes sends); both must be refused at the cap.
    fn syn_frame(stream: u32) -> Vec<u8> {
        let mut f = vec![0, if stream % 4 == 1 { 0 } else { 1 }];
        f.extend_from_slice(&SYN.to_be_bytes());
        f.extend_from_slice(&stream.to_be_bytes());
        if stream % 4 == 1 {
            f.extend_from_slice(&1u32.to_be_bytes());
            f.push(b'x');
        } else {
            f.extend_from_slice(&0u32.to_be_bytes());
        }
        f
    }

    // A server whose uplink is stalled: the refusals pile up as lingering streams and the table
    // really reaches 512. 600 streams arrive; 88 find the table at its cap.
    let (mux, inbound, mut outbound, driver) = menzil_stream::new(Mode::Server, 65_535);
    let driver = tokio::spawn(driver);
    let uplink = Arc::new(AtomicBool::new(false));
    let gate = uplink.clone();
    let sent = tokio::spawn(async move {
        let mut frames = Vec::new();
        while let Some(frame) = outbound.next_frame().await {
            while !gate.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            frames.push(frame);
        }
        frames
    });
    for i in 0..600u32 {
        mux.feed_inbound(syn_frame(1 + 2 * i)).unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !driver.is_finished(),
        "a stream past the cap must not end the connection"
    );
    uplink.store(true, Ordering::SeqCst);
    // Still serving: a stream that arrives now is either accepted or refused, and the
    // connection answers it.
    mux.feed_inbound(syn_frame(1 + 2 * 600)).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!driver.is_finished());
    drop((mux, inbound));
    let frames = timeout(WAIT, sent).await.unwrap().unwrap();
    assert!(
        frames.iter().all(|f| f.len() < 2 || f[1] != 3),
        "no GoAway may have been sent"
    );
}
