//! The buffer meter (patch 5 of the vendored `yamux`, `menzil_stream::new_metered`) sees every
//! change of the bytes a connection's streams hold received but not yet read, and the frame body
//! cap ends a connection whose peer claims a larger body (`MAX_FRAME_BODY`).
//!
//! One `#[tokio::test]` for the binary: the phases share nothing but are sequential on purpose.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_stream::{
    BufferMeter, Inbound, MAX_FRAME_BODY, Mode, MuxLimits, OutboundFrames, Stream, StreamMux,
    StreamMuxError,
};
use tokio::task::JoinHandle;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(10);
const KIB: usize = 1024;

/// Counts what is buffered; `consumed` past what was buffered is recorded, never silently wrapped.
#[derive(Debug, Default)]
struct Counting {
    held: AtomicUsize,
    underflow: AtomicBool,
}

impl BufferMeter for Counting {
    fn buffered(&self, n: usize) {
        self.held.fetch_add(n, Ordering::SeqCst);
    }
    fn consumed(&self, n: usize) {
        let before = self.held.fetch_sub(n, Ordering::SeqCst);
        if before < n {
            self.underflow.store(true, Ordering::SeqCst);
        }
    }
}

impl Counting {
    fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }
    /// Waits for the meter to read `want`: yamux updates it when it processes a frame or a drop.
    async fn settles_at(&self, want: usize) {
        for _ in 0..1000 {
            if self.held() == want {
                assert!(
                    !self.underflow.load(Ordering::SeqCst),
                    "consumed past buffered"
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("meter is {} and never reached {want}", self.held());
    }
}

async fn pump(mut from: OutboundFrames, to: StreamMux) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

struct Pair {
    a: StreamMux,
    inbound_b: Inbound,
    driver_b: JoinHandle<Result<(), StreamMuxError>>,
    mux_b: StreamMux,
}

/// `a` is an ordinary client; `b` is the server and the metered side.
fn metered_pair(meter: Arc<Counting>) -> Pair {
    let (a, _inbound_a, out_a, driver_a) = menzil_stream::new(Mode::Client, 65_535);
    let (mux_b, inbound_b, out_b, driver_b) =
        menzil_stream::new_metered(Mode::Server, 65_535, MuxLimits::default(), meter);
    tokio::spawn(driver_a);
    let driver_b = tokio::spawn(driver_b);
    tokio::spawn(pump(out_a, mux_b.clone()));
    tokio::spawn(pump(out_b, a.clone()));
    Pair {
        a,
        inbound_b,
        driver_b,
        mux_b,
    }
}

/// Opens a stream on `a`, writes `len` bytes, and returns both ends.
async fn fill(p: &mut Pair, len: usize) -> (Stream, Stream) {
    let mut opened = p.a.open().await.expect("open");
    opened.write_all(&vec![7u8; len]).await.unwrap();
    let accepted = timeout(WAIT, p.inbound_b.accept())
        .await
        .expect("the stream must arrive")
        .expect("alive");
    (opened, accepted)
}

#[tokio::test]
async fn the_meter_follows_unread_bytes_and_the_frame_cap_ends_the_connection() {
    let meter = Arc::new(Counting::default());
    let mut p = metered_pair(meter.clone());

    // 3 unread streams x 200 KiB.
    let (a1, mut b1) = fill(&mut p, 200 * KIB).await;
    let (a2, b2) = fill(&mut p, 200 * KIB).await;
    let (a3, b3) = fill(&mut p, 200 * KIB).await;
    meter.settles_at(600 * KIB).await;

    // Reading 100 KiB drops it by 100 KiB.
    let mut buf = vec![0u8; 100 * KIB];
    timeout(WAIT, b1.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    meter.settles_at(500 * KIB).await;

    // Dropping a stream with unread data takes its share out.
    drop(b2);
    meter.settles_at(300 * KIB).await;

    // A peer RST with unread data, then the drop.
    a3.reset();
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(b3);
    meter.settles_at(100 * KIB).await;
    drop(a2);

    // Dropping the whole connection returns everything.
    p.driver_b.abort();
    drop(p.mux_b);
    drop(p.inbound_b);
    drop(b1);
    drop(a1);
    meter.settles_at(0).await;
    assert!(!meter.underflow.load(Ordering::SeqCst));

    // A frame header claiming more than MAX_FRAME_BODY ends the connection with an error.
    let meter = Arc::new(Counting::default());
    let p = metered_pair(meter.clone());
    let claimed = 70_000usize;
    assert!(claimed > MAX_FRAME_BODY);
    let mut frame = Vec::with_capacity(12 + claimed);
    frame.extend_from_slice(&[0, 0]); // version 0, type Data
    frame.extend_from_slice(&1u16.to_be_bytes()); // flags: SYN
    frame.extend_from_slice(&1u32.to_be_bytes()); // stream id 1
    frame.extend_from_slice(&(claimed as u32).to_be_bytes());
    frame.resize(12 + claimed, 1);
    p.mux_b.feed_inbound(frame).expect("one well formed frame");
    let result = timeout(WAIT, p.driver_b)
        .await
        .expect("the driver must end")
        .expect("no panic");
    assert!(result.is_err(), "an oversized body must end the connection");
    meter.settles_at(0).await;
}
