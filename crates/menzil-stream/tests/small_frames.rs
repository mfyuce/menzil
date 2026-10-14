//! A peer that cuts its data into tiny frames must not make a stream cost more
//! memory than its receive window says (`vendor/yamux/PATCHES.md`, patch 1).
//!
//! `yamux` counts a stream's receive window in payload bytes, but kept every
//! data frame's body as a `Vec` of its own in a queue of its own: a one-byte
//! frame cost about 65 bytes of heap against one byte of window, and a peer
//! entitled to 256 KiB of window per stream (144 MiB per session, see
//! `RECEIVE_WINDOW_GRANT`) could pin gigabytes by never being read from. The
//! vendored `yamux` appends short bodies to the previous chunk instead.
//!
//! Three more cases run in the same test: a reader that keeps pace must not make a chunk grow
//! without bound (the first yamux review found that a comparison of the unread length with the cap
//! survived every test, because nothing read while frames arrived), and frames alternating a
//! 1 KiB body with a one byte body, the pattern that costs most (about twice the payload: the
//! one byte append doubles the capacity of the exact-fit 1 KiB body), must stay within 2.5
//! times, which is the factor `vendor/yamux/PATCHES.md` states.
//!
//! This binary holds one test on purpose: it counts every live heap byte of
//! the process through a global allocator, so nothing else may run beside it.
//! It fails against the registry `yamux`, which holds 65 bytes of counted heap
//! per one-byte frame (16.3 MB for the 249,000 frames below, measured when this
//! test was written); the vendored one holds about one byte per frame.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::io::AsyncReadExt;
use menzil_stream::{Mode, StreamMux};

/// Counts the heap the way glibc's `malloc` reserves it: an 8 byte header,
/// 16 byte granularity and a 32 byte minimum, so that a one-byte `Vec` counts
/// as the 32 bytes it really occupies.
struct CountingAlloc;

static LIVE: AtomicUsize = AtomicUsize::new(0);

fn footprint(size: usize) -> usize {
    (size + 8).next_multiple_of(16).max(32)
}

// SAFETY: every method forwards to `System` unchanged and only adds to or
// subtracts from a counter.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(footprint(layout.size()), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(footprint(layout.size()), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE.fetch_add(footprint(new_size), Ordering::Relaxed);
            LIVE.fetch_sub(footprint(layout.size()), Ordering::Relaxed);
        }
        new
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

const SYN: u16 = 1;
const FIN: u16 = 4;

/// One yamux data frame (spec version 0): `u8 version | u8 type | u16 flags |
/// u32 stream id | u32 length | body`, big endian.
fn data_frame(stream: u32, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(12 + body.len());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&flags.to_be_bytes());
    frame.extend_from_slice(&stream.to_be_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(body);
    frame
}

/// Counts the records `yamux` has read, which is when their guards drop.
struct Read(Arc<AtomicUsize>);

impl Drop for Read {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Feeds frames to a server side connection and waits until `yamux` has
/// consumed every one, so that nothing but the stream's own buffer is left.
struct Feeder {
    mux: StreamMux,
    read: Arc<AtomicUsize>,
    sent: usize,
}

impl Feeder {
    async fn feed(&mut self, frames: impl IntoIterator<Item = Vec<u8>>) {
        for frame in frames {
            self.mux
                .feed_inbound_guarded(frame, Box::new(Read(self.read.clone())))
                .unwrap();
            self.sent += 1;
        }
        tokio::time::timeout(Duration::from_secs(60), async {
            while self.read.load(Ordering::SeqCst) < self.sent {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("yamux must read every record that was fed");
    }
}

/// A server side connection whose outbound frames are thrown away.
fn server() -> (Feeder, menzil_stream::Inbound) {
    let (mux, inbound, mut outbound, driver) = menzil_stream::new(Mode::Server, 65_535);
    tokio::spawn(driver);
    tokio::spawn(async move { while outbound.next_frame().await.is_some() {} });
    let feeder = Feeder {
        mux,
        read: Arc::new(AtomicUsize::new(0)),
        sent: 0,
    };
    (feeder, inbound)
}

#[tokio::test(flavor = "current_thread")]
async fn tiny_frames_cost_memory_in_proportion_to_their_payload() {
    // Under a stream's initial 256 KiB window, one byte each.
    const FRAMES: usize = 250_000;
    const WARM_UP: usize = 1_000;
    let byte = |i: usize| (i % 251) as u8;

    let (mut feeder, mut inbound) = server();
    feeder.feed([data_frame(1, SYN, &[byte(0)])]).await;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), inbound.accept())
        .await
        .unwrap()
        .expect("the SYN frame opens a stream");
    // One-time costs (the stream, the first chunk, the queues) come before the
    // snapshot.
    feeder
        .feed((1..WARM_UP).map(|i| data_frame(1, 0, &[byte(i)])))
        .await;
    let before = LIVE.load(Ordering::SeqCst);

    for start in (WARM_UP..FRAMES).step_by(5_000) {
        let end = (start + 5_000).min(FRAMES);
        feeder
            .feed((start..end).map(|i| data_frame(1, 0, &[byte(i)])))
            .await;
    }
    let held = LIVE.load(Ordering::SeqCst) - before;
    let payload = FRAMES - WARM_UP;
    assert!(
        held <= 4 * payload,
        "{payload} one-byte frames left {held} bytes of heap held ({} per frame): the receive \
         window charged {payload} bytes",
        held / payload
    );

    // Nothing was lost or reordered on the way.
    feeder.feed([data_frame(1, FIN, &[])]).await;
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();
    assert_eq!(got.len(), FRAMES);
    assert!(got.iter().enumerate().all(|(i, b)| *b == byte(i)));

    // Bodies of every size in between keep their bytes and their order too.
    let (mut feeder, mut inbound) = server();
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut expected = Vec::new();
    let mut frames = Vec::new();
    while expected.len() < 250_000 {
        let len = [1, 7, 90, 1_000, 1_023, 1_024, 1_025, 3_000][next() as usize % 8];
        let body: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        let flags = if frames.is_empty() { SYN } else { 0 };
        frames.push(data_frame(1, flags, &body));
        expected.extend_from_slice(&body);
    }
    frames.push(data_frame(1, FIN, &[]));
    feeder.feed(frames).await;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), inbound.accept())
        .await
        .unwrap()
        .unwrap();
    let mut got = Vec::new();
    stream.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, expected);

    // A reader that keeps pace holds nothing. Each round feeds a batch of one byte frames, well
    // under the 8 KiB a chunk may reach, and reads it all before the next; what is held at the
    // end is what was held after the first dozen rounds, not a chunk that grew with every round.
    let (mut feeder, mut inbound) = server();
    feeder.feed([data_frame(1, SYN, &[byte(0)])]).await;
    let mut stream = tokio::time::timeout(Duration::from_secs(5), inbound.accept())
        .await
        .unwrap()
        .unwrap();
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await.unwrap();
    const BATCH: usize = 1_000;
    const ROUNDS: usize = 220;
    let mut before = 0;
    for round in 0..ROUNDS {
        feeder
            .feed((0..BATCH).map(|i| data_frame(1, 0, &[byte(i)])))
            .await;
        let mut got = vec![0u8; BATCH];
        tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert!(got.iter().enumerate().all(|(i, b)| *b == byte(i)));
        drop(got);
        if round == 12 {
            before = LIVE.load(Ordering::SeqCst);
        }
    }
    let growth = LIVE.load(Ordering::SeqCst).saturating_sub(before);
    assert!(
        growth <= 64 * 1024,
        "a reader that keeps pace left {growth} more bytes held after {} more rounds",
        ROUNDS - 13
    );
    drop(stream);

    // The worst pattern for patch 1: a 1 KiB body (kept as a chunk of its own, exact fit), then
    // one byte appended to it (doubling it), over and over, on a stream nobody reads.
    let (mut feeder, mut inbound) = server();
    let pair = |first: bool| {
        let flags = if first { SYN } else { 0 };
        [data_frame(1, flags, &[7u8; 1024]), data_frame(1, 0, &[8u8])]
    };
    feeder.feed(pair(true)).await;
    let _stream = tokio::time::timeout(Duration::from_secs(5), inbound.accept())
        .await
        .unwrap()
        .unwrap();
    const WARM_PAIRS: usize = 10;
    const PAIRS: usize = 240;
    for _ in 1..WARM_PAIRS {
        feeder.feed(pair(false)).await;
    }
    let before = LIVE.load(Ordering::SeqCst);
    for _ in WARM_PAIRS..PAIRS {
        feeder.feed(pair(false)).await;
    }
    let held = LIVE.load(Ordering::SeqCst) - before;
    let payload = (PAIRS - WARM_PAIRS) * 1025;
    assert!(
        held * 2 <= payload * 5,
        "{payload} bytes of 1 KiB and one byte frames held {held} bytes of heap ({:.2} per byte)",
        held as f64 / payload as f64
    );
}
