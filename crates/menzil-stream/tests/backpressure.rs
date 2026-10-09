//! Outbound backpressure end to end (TODO.md L4h5): a full outbound
//! frame channel must pause `yamux`, never end the connection.
//!
//! Every test here reproduces a way the earlier hard-failure budget
//! (`OUTBOUND_FRAME_BUDGET` as a fatal `poll_write` error, DONE.md's L4f
//! entry) ended a perfectly healthy connection: a consumer that stops
//! draining for a while (TODO.md L4h3's own second line), a peer-driven
//! flood of replies `yamux` itself generates (the L4f review's Ping
//! example, now bounded by `yamux`'s single pending-reply slot rather
//! than by failing), a burst of refused OPENs (TODO.md L4g's 129-OPEN
//! line), and ordinary bulk transfer over many streams behind a paced
//! consumer (the L4h3 round-2 review's 23-streams-and-up repro). Each one
//! was confirmed to fail against the pre-L4h5 `record_io.rs` before the
//! fix existed, so none of these can pass vacuously.

use std::time::Duration;

use futures_util::FutureExt;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_proto::{ErrorCode, NetworkId, NodeId, OpenBody, OpenMeta, ServiceId, ServiceKind};
use menzil_stream::{
    Authorizer, Inbound, Mode, OpenDecision, OpenRefusal, OpenRequest, OutboundFrames,
    ServiceHandler, StreamMux, StreamMuxError, initiate_open, respond_to_open,
};
use tokio::task::JoinHandle;

type DriverHandle = JoinHandle<Result<(), StreamMuxError>>;

/// How the test pumps ferry frames from one connection into the other.
#[derive(Clone, Copy)]
enum Pump {
    /// Forward every frame as soon as it is available, never yielding in
    /// between: the drain side is as fast as it can be (the shape that
    /// reproduced TODO.md's refused-OPEN-burst line, where one `Driver`
    /// poll emits a burst before anything downstream runs at all).
    Instant,
    /// Yield to the scheduler after every frame, so the consumer is always
    /// the slower side and the `Driver` (and every stream writer feeding
    /// it) gets to run repeatedly between two frames being drained.
    Paced,
}

async fn pump(mut from: OutboundFrames, to: StreamMux, how: Pump) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
        if matches!(how, Pump::Paced) {
            tokio::task::yield_now().await;
        }
    }
}

struct Pair {
    mux_a: StreamMux,
    inbound_a: Inbound,
    mux_b: StreamMux,
    inbound_b: Inbound,
    driver_a: DriverHandle,
    driver_b: DriverHandle,
}

fn connected_pair(max_record: u32, how: Pump) -> Pair {
    let (mux_a, inbound_a, outbound_a, driver_a) = menzil_stream::new(Mode::Client, max_record);
    let (mux_b, inbound_b, outbound_b, driver_b) = menzil_stream::new(Mode::Server, max_record);
    let driver_a = tokio::spawn(driver_a);
    let driver_b = tokio::spawn(driver_b);
    tokio::spawn(pump(outbound_a, mux_b.clone(), how));
    tokio::spawn(pump(outbound_b, mux_a.clone(), how));
    Pair {
        mux_a,
        inbound_a,
        mux_b,
        inbound_b,
        driver_a,
        driver_b,
    }
}

/// One yamux data frame's worth of window: yamux's own initial per-stream
/// receive window is 256 KiB (`DEFAULT_CREDIT`, protocol.md 5.3), so a
/// writer with no peer to send window updates can push exactly this many
/// bytes per stream, and no more.
const INITIAL_WINDOW: usize = 256 * 1024;

#[tokio::test]
async fn a_consumer_that_stops_draining_pauses_the_driver_instead_of_ending_it() {
    let (mux, _inbound, mut outbound, driver) = menzil_stream::new(Mode::Client, 65_535);
    let driver: DriverHandle = tokio::spawn(driver);

    // Each stream has its own independent 256 KiB window (16 full frames),
    // so 40 concurrent writers can produce 640 frames with no peer window
    // update arriving at all — well past the outbound channel's
    // capacity (64 frames), with no consumer draining it.
    const STREAMS: usize = 40;
    let mut writers = Vec::new();
    for i in 0..STREAMS {
        let mut stream = mux.open().await.unwrap();
        writers.push(tokio::spawn(async move {
            stream.write_all(&vec![i as u8; INITIAL_WINDOW]).await?;
            stream.flush().await
        }));
    }

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !driver.is_finished(),
        "a full outbound channel must pause the driver, not end the connection"
    );
    assert!(
        writers.iter().any(|w| !w.is_finished()),
        "with nothing draining, at least some writers must be held back by backpressure"
    );

    // Now something drains: every held-back writer must make progress and
    // finish, with no frame lost along the way.
    let drain = tokio::spawn(async move {
        let mut frames = 0usize;
        while let Some(_frame) = outbound.next_frame().await {
            frames += 1;
        }
        frames
    });
    for writer in writers {
        tokio::time::timeout(Duration::from_secs(10), writer)
            .await
            .expect("a writer held back by backpressure must resume once draining starts")
            .unwrap()
            .expect("a resumed write must succeed");
    }
    assert!(!driver.is_finished());

    drop(mux);
    let frames = tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .expect("the drain task must end once the connection does")
        .unwrap();
    // 40 streams x 16 full frames each, at the least.
    assert!(frames >= STREAMS * 16, "only {frames} frames were produced");
}

fn ping(nonce: u32) -> Vec<u8> {
    // A SYN-flagged Ping on the connection-level stream id 0: `yamux`
    // answers with an ACK-flagged Ping echoing the nonce.
    let mut frame = vec![0u8, 2, 0, 1, 0, 0, 0, 0];
    frame.extend_from_slice(&nonce.to_be_bytes());
    frame
}

#[tokio::test]
async fn a_ping_flood_with_nothing_draining_stays_bounded_and_loses_no_reply() {
    // The L4f review's own example: a peer flooding bare Pings makes
    // `yamux` generate a Pong per Ping, synchronously, whether or not
    // anything drains them. `yamux` 0.14.1 holds at most one pending reply
    // and stops reading further input until it is written, so with a
    // bounded channel that pauses the writer, the queue cannot grow past
    // the channel's capacity however many Pings are fed.
    let (mux, _inbound, mut outbound, driver) = menzil_stream::new(Mode::Server, 65_535);
    let driver: DriverHandle = tokio::spawn(driver);

    const PINGS: u32 = 50_000;
    for nonce in 0..PINGS {
        mux.feed_inbound(ping(nonce)).unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !driver.is_finished(),
        "a Ping flood with nothing draining must pause the driver, not end it"
    );

    // Snapshot of what is queued right now: `now_or_never` never yields to
    // the driver, so this counts exactly what had accumulated at the stall.
    // Not every frame is a reply to one of our Pings: `yamux` also sends
    // its own RTT Ping (SYN-flagged, not ACK) as soon as a connection
    // exists, so only ACK-flagged Pings count as Pongs below.
    let mut queued = 0usize;
    let mut pongs: Vec<u32> = Vec::new();
    let note = |frame: &[u8], pongs: &mut Vec<u32>| {
        assert_eq!(frame.len(), 12, "every frame here is a bare header");
        let is_ack_ping = frame[1] == 2 && u16::from_be_bytes([frame[2], frame[3]]) & 0x2 != 0;
        if is_ack_ping {
            pongs.push(u32::from_be_bytes([
                frame[8], frame[9], frame[10], frame[11],
            ]));
        }
    };
    while let Some(Some(frame)) = outbound.next_frame().now_or_never() {
        queued += 1;
        note(&frame, &mut pongs);
    }
    assert!(
        queued <= 300,
        "{queued} frames were queued with nothing draining: the queue is not bounded"
    );
    assert!(queued > 0, "the stall must have queued something");

    // Draining for real: every remaining reply arrives, in order, none
    // lost.
    while pongs.len() < PINGS as usize {
        let frame = tokio::time::timeout(Duration::from_secs(5), outbound.next_frame())
            .await
            .expect("the driver must resume and keep answering once draining starts")
            .expect("the connection must still be alive");
        note(&frame, &mut pongs);
    }
    // Compared by hand rather than with `assert_eq!` on two 50,000-element
    // vectors, whose failure message would be unreadable.
    let first_wrong = pongs
        .iter()
        .enumerate()
        .find(|&(position, &nonce)| nonce != position as u32);
    assert_eq!(first_wrong, None, "replies must be complete and in order");
    assert!(!driver.is_finished());
}

struct DenyAll;
impl Authorizer for DenyAll {
    fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
        OpenDecision::Deny(OpenRefusal {
            code: ErrorCode::NoGrant,
            msg: "no grant".to_string(),
        })
    }
}

struct NeverHandles;
impl<S> ServiceHandler<S> for NeverHandles {
    type Handling = std::future::Ready<()>;

    fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Ok(())
    }

    fn handle(&self, _stream: S, _request: OpenRequest) -> Self::Handling {
        panic!("every OPEN in this test is denied before handle() could run")
    }
}

#[tokio::test]
async fn a_burst_of_refused_opens_past_the_old_budget_does_not_end_the_responder() {
    // TODO.md's L4g line: each refused OPEN costs the responder two
    // outbound frames (OPEN_ACK, then the FIN after it); 129 at once is
    // 258 frames, past the 256-plus-one-slot channel, and ended the
    // responder's whole `Driver` in 10 of 10 runs on a current-thread
    // runtime. 200 here is well past that, and still under yamux's own
    // 256-unacknowledged-stream cap on the initiator.
    const OPENS: usize = 200;
    let Pair {
        mux_a,
        inbound_a: _inbound_a,
        mux_b: _mux_b,
        mut inbound_b,
        driver_a,
        driver_b,
    } = connected_pair(65_535, Pump::Instant);

    let network = NetworkId::from([1u8; 32]);
    let initiator = NodeId::from([2u8; 32]);
    let responder = tokio::spawn(async move {
        let mut handlers = Vec::new();
        while let Some(stream) = inbound_b.accept().await {
            handlers.push(tokio::spawn(async move {
                let _ = respond_to_open(stream, network, initiator, &DenyAll, &NeverHandles).await;
            }));
        }
        for handler in handlers {
            let _ = handler.await;
        }
    });

    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service: ServiceId::new(ServiceKind::Tcp, "ssh"),
        target: None,
        meta: OpenMeta::default(),
    };
    let mut initiators = Vec::new();
    for _ in 0..OPENS {
        let mux = mux_a.clone();
        let open = open.clone();
        initiators.push(tokio::spawn(async move {
            let mut stream = mux.open().await.expect("open must succeed");
            initiate_open(&mut stream, &open).await
        }));
    }
    for initiator in initiators {
        let ack = tokio::time::timeout(Duration::from_secs(10), initiator)
            .await
            .expect("every refusal must come back, not hang")
            .unwrap()
            .expect("a refused OPEN must surface as a refusal ack, not a dead connection");
        assert!(!ack.ok);
        assert_eq!(ack.code, ErrorCode::NoGrant);
    }
    assert!(
        !driver_a.is_finished(),
        "the initiator's driver must survive"
    );
    assert!(
        !driver_b.is_finished(),
        "the responder's driver must survive a burst of refusals"
    );
    drop(mux_a);
    responder.abort();
}

#[tokio::test]
async fn bulk_transfer_over_many_streams_behind_a_paced_consumer_completes_intact() {
    // The L4h3 round-2 review's repro shape: 23 streams and up reliably
    // exhausted the old budget on ordinary load, no hostility needed.
    // 32 streams, each moving 512 KiB (two initial windows, so window
    // updates must flow back the whole time).
    const STREAMS: usize = 32;
    const PER_STREAM: usize = 2 * INITIAL_WINDOW;
    let Pair {
        mux_a,
        inbound_a: _inbound_a,
        mux_b: _mux_b,
        mut inbound_b,
        driver_a,
        driver_b,
    } = connected_pair(65_535, Pump::Paced);

    let mut writers = Vec::new();
    for i in 0..STREAMS {
        let mut stream = mux_a.open().await.unwrap();
        writers.push(tokio::spawn(async move {
            // The first byte tags the stream; the rest is derived from the
            // stream's index and position, so misrouting or reordering
            // shows up as a content mismatch, not only a length one.
            let mut payload = vec![0u8; PER_STREAM];
            for (pos, byte) in payload.iter_mut().enumerate() {
                *byte = ((pos + i) % 251) as u8;
            }
            payload[0] = i as u8;
            stream.write_all(&payload).await?;
            stream.close().await
        }));
    }

    let mut readers = Vec::new();
    for _ in 0..STREAMS {
        let mut stream = inbound_b.accept().await.expect("every stream must be seen");
        readers.push(tokio::spawn(async move {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.map(|_| buf)
        }));
    }

    for writer in writers {
        tokio::time::timeout(Duration::from_secs(60), writer)
            .await
            .expect("bulk transfer must finish")
            .unwrap()
            .expect("no write may fail");
    }
    let mut seen = [false; STREAMS];
    for reader in readers {
        let buf = tokio::time::timeout(Duration::from_secs(60), reader)
            .await
            .expect("bulk transfer must finish")
            .unwrap()
            .expect("no read may fail");
        assert_eq!(buf.len(), PER_STREAM);
        let i = buf[0] as usize;
        assert!(!seen[i], "stream {i} arrived twice");
        seen[i] = true;
        for (pos, &byte) in buf.iter().enumerate().skip(1) {
            assert_eq!(byte, ((pos + i) % 251) as u8, "stream {i}, byte {pos}");
        }
    }
    assert!(seen.iter().all(|&s| s));
    assert!(!driver_a.is_finished());
    assert!(!driver_b.is_finished());
}
