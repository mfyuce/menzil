//! The L4 datagram class (protocol.md 5.2, 5.4; egress slice 2b1) over a real relay: two nodes,
//! each a real [`menzil_node::run_session`] against an in-process `menzil_relay::Relay`, each
//! with a real [`menzil_node::new_router`], doing the L4 handshake through the relay. B accepts
//! with a test [`ServiceHandler`] that implements `open_channel` (it allocates a channel from
//! its session's table) and echoes every datagram back; A opens UDP channels with
//! [`menzil_node::open_udp_stream`]. Nothing here is served by production code yet (the exit's
//! UDP channel is slice 2b2): this exercises the layer itself.
//!
//! Checks, in order:
//!
//! 1. 1,000 datagrams of mixed sizes up to the maximum payload (65,452 bytes at the default
//!    record size) go A to B and come back: each arrives at most once, intact, and is one that
//!    was sent (loss and reordering are allowed; duplicates and forgeries are not); one byte
//!    over the maximum is refused at the sender.
//! 2. Datagram loss never ends the session. B's handler stops reading its channels while five
//!    channels are sent far more than a session may hold (the session's datagram budget is 1 MiB,
//!    a channel's sink 256 KiB): what does not fit is dropped silently at B, the budget is never
//!    exceeded, the session lives, datagrams flow again once the handler reads, and an ordinary
//!    stream still works. (The relay's own pair bucket is not driven here: the nodes' buckets
//!    are set at the relay's figures, so a node cannot send past it, and the relay's drop is
//!    covered in `menzil-relay::forward`'s tests.)
//! 3. A stream reset ends delivery: the responder's channel goes with the stream, datagrams
//!    sent afterwards are dropped (counted, never delivered, never answered), and a channel
//!    opened later gets a different id (the 60 s quarantine).
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE`
//! is process-global (see that file's own doc comment). Every wait is bounded.

#![cfg(target_os = "linux")]

mod common;

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use common::{
    Identity, PATIENCE, TestRelay, echo_round_trip, identity, node_cert, policy, seed_roster,
    service, session_config, start_relay, trust_test_certificate,
};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_node::channels::{Channel, ChannelTable, DGRAM_BUDGET_PER_SESSION, SendDrop};
use menzil_node::{
    L4SessionHandle, LocalIdentity, PolicyStore, RefuseAll, RosterStore, RouterConfig,
    RouterHandle, RouterParts, SendBudgets, SessionEvent, SessionReady, accept_loop, new_router,
    open_stream, open_udp_stream, run_session,
};
use menzil_proto::{ErrorCode, NetworkId, OpenTarget, OpenTransport};
use menzil_stream::{Authorizer, OpenDecision, OpenRefusal, OpenRequest, ServiceHandler, Stream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

/// The most a datagram carries at the default record size (protocol.md 5.4).
const MAX_PAYLOAD: usize = 65_452;
/// How many datagrams the first phase sends.
const MIXED: u32 = 1_000;

/// The size of datagram `idx`: the first thousand are mixed up to the maximum, those from
/// 100,000 on (the overload phase) are 1,200 bytes, every other later one is four bytes, just
/// the index.
fn size_of(idx: u32) -> usize {
    if idx >= 100_000 {
        1_200
    } else if idx >= MIXED {
        4
    } else if idx.is_multiple_of(50) {
        MAX_PAYLOAD
    } else if idx % 10 == 5 {
        20_000
    } else {
        [4, 17, 200, 1_200, 1_400][(idx % 5) as usize]
    }
}

/// `idx` as four big endian bytes, then a pattern that depends on both the position and the
/// index, so a datagram that was altered, truncated or put together from two is caught.
fn payload(idx: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size_of(idx));
    bytes.extend_from_slice(&idx.to_be_bytes());
    while bytes.len() < size_of(idx) {
        bytes.push((idx as usize * 31 + bytes.len()) as u8);
    }
    bytes
}

/// The index of a datagram that arrived, after checking that it is exactly one that was sent.
fn checked_index(bytes: &[u8]) -> u32 {
    assert!(
        bytes.len() >= 4,
        "a datagram of {} bytes was never sent",
        bytes.len()
    );
    let idx = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    assert!(
        bytes == payload(idx).as_slice(),
        "datagram {idx} arrived altered or truncated ({} bytes)",
        bytes.len()
    );
    idx
}

/// Accepts every OPEN (the grant rules are not what is under test).
struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
        OpenDecision::Allow
    }
}

/// What the echo handler holds for one accepted stream.
struct Opened {
    channel: Option<Channel>,
}

/// B's handler: an `egress:*` UDP OPEN gets a channel from `table`, kept until the stream ends;
/// every datagram on it is counted and echoed back (dropped, not retried, when the sender's
/// bucket is empty). Any other OPEN is an echo stream.
#[derive(Clone)]
struct Echo {
    table: ChannelTable,
    /// Datagrams that reached a handler's channel at B.
    received: Arc<AtomicU64>,
    /// While set, handlers read no datagram (the channels' sinks fill up).
    stall: Arc<AtomicBool>,
}

impl ServiceHandler<Stream> for Echo {
    type Opened = Opened;
    type Handling = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    async fn open(&self, _request: &OpenRequest) -> Result<Opened, OpenRefusal> {
        Ok(Opened { channel: None })
    }

    fn open_channel(
        &self,
        request: &OpenRequest,
        opened: &mut Opened,
    ) -> Result<Option<u16>, OpenRefusal> {
        let asks_for_udp = request
            .target
            .as_ref()
            .is_some_and(|t| t.transport == Some(OpenTransport::Udp));
        if !asks_for_udp {
            return Ok(None);
        }
        let channel = self.table.allocate().map_err(|e| OpenRefusal {
            code: ErrorCode::RateLimited,
            msg: e.to_string(),
        })?;
        let id = channel.id();
        opened.channel = Some(channel);
        Ok(Some(id))
    }

    fn handle(
        &self,
        mut stream: Stream,
        _request: OpenRequest,
        mut opened: Opened,
    ) -> Self::Handling {
        let received = Arc::clone(&self.received);
        let stall = Arc::clone(&self.stall);
        Box::pin(async move {
            let mut buf = [0u8; 4096];
            loop {
                enum Event {
                    Stream(std::io::Result<usize>),
                    Datagram(Option<Vec<u8>>),
                    Idle,
                }
                let event = {
                    let datagram = async {
                        if stall.load(Ordering::Relaxed) {
                            sleep(Duration::from_millis(20)).await;
                            return Event::Idle;
                        }
                        match opened.channel.as_mut() {
                            Some(channel) => Event::Datagram(channel.recv().await),
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        read = stream.read(&mut buf) => Event::Stream(read),
                        event = datagram => event,
                    }
                };
                match event {
                    Event::Stream(Ok(n)) if n > 0 && opened.channel.is_none() => {
                        if stream.write_all(&buf[..n]).await.is_err()
                            || stream.flush().await.is_err()
                        {
                            break;
                        }
                    }
                    // An end, a reset, or a byte on a UDP stream: the channel goes with the stream.
                    Event::Stream(_) => break,
                    Event::Datagram(Some(bytes)) => {
                        received.fetch_add(1, Ordering::Relaxed);
                        if let Some(channel) = opened.channel.as_ref() {
                            let _ = channel.send(&bytes);
                        }
                    }
                    Event::Datagram(None) => break,
                    Event::Idle => {}
                }
            }
            // `opened` (and the channel in it) is dropped with the stream's task.
            drop(opened);
        })
    }
}

struct LiveNode {
    id: Identity,
    handle: RouterHandle,
    ready: mpsc::UnboundedReceiver<SessionReady>,
    passthrough: mpsc::Receiver<SessionEvent>,
    task: tokio::task::JoinHandle<()>,
}

fn live_node(
    relay: &TestRelay,
    id: Identity,
    network_id: NetworkId,
    policies: &Arc<PolicyStore>,
    rosters: &Arc<RosterStore>,
) -> LiveNode {
    let (events_tx, events_rx) = mpsc::channel(256);
    let (outbound_tx, outbound_rx) = mpsc::channel(256);
    let task = tokio::spawn(run_session(
        session_config(relay, &id, network_id),
        HashMap::new(),
        events_tx,
        outbound_rx,
        rosters.clone(),
    ));
    let config = RouterConfig::new(
        LocalIdentity {
            node_cert: node_cert(&id),
            x25519_private: id.x25519_private,
        },
        relay.id.node_id,
        policies.clone(),
        rosters.clone(),
        SendBudgets::new(),
    )
    .unwrap();
    let RouterParts {
        handle,
        ready,
        passthrough,
        task: router,
        ..
    } = new_router(config, outbound_tx, events_rx);
    tokio::spawn(router);
    LiveNode {
        id,
        handle,
        ready,
        passthrough,
        task,
    }
}

async fn next_attached(node: &mut LiveNode) {
    timeout(PATIENCE, async {
        loop {
            match node.passthrough.recv().await {
                Some(SessionEvent::Attached { .. }) => return,
                Some(_) => {}
                None => panic!("the router ended"),
            }
        }
    })
    .await
    .expect("the node never attached");
}

fn target() -> OpenTarget {
    OpenTarget {
        host: "example.com".to_string(),
        port: 53,
        transport: None,
    }
}

fn egress_star() -> menzil_proto::ServiceId {
    service("egress:*")
}

/// Everything that arrived on `channel` so far, checked, into `seen`; returns how many.
fn drain(channel: &mut Channel, seen: &mut HashSet<u32>) -> usize {
    let mut n = 0;
    while let Some(bytes) = channel.try_recv() {
        let idx = checked_index(&bytes);
        assert!(seen.insert(idx), "datagram {idx} arrived twice");
        n += 1;
    }
    n
}

/// Waits (bounded) until `want` holds; panics with `what` otherwise.
async fn eventually(what: &str, within: Duration, mut want: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !want() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        sleep(Duration::from_millis(20)).await;
    }
}

/// How the datagrams of one session are sent: paced just under the buckets' rate so that
/// nothing is dropped for being too fast, except where a phase wants exactly that.
async fn pace(n: usize) {
    if n >= 1_000 {
        sleep(Duration::from_secs_f64((n + 32) as f64 / 1_500_000.0)).await;
    }
}

#[tokio::test]
async fn datagrams_over_a_real_relay() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster) = seed_roster(&relay, &[&a, &b]);
    let policy = policy(&owner, network_id, &a, &b, vec![]);
    let stores = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster).unwrap();
        (policies, rosters)
    };
    let (a_policies, a_rosters) = stores();
    let (b_policies, b_rosters) = stores();
    let mut na = live_node(&relay, a, network_id, &a_policies, &a_rosters);
    let mut nb = live_node(&relay, b, network_id, &b_policies, &b_rosters);
    next_attached(&mut na).await;
    next_attached(&mut nb).await;

    let a_session: L4SessionHandle = timeout(
        PATIENCE,
        na.handle.ensure_session(nb.id.node_id, network_id),
    )
    .await
    .expect("the handshake must finish")
    .expect("and succeed");
    let ready_a = timeout(PATIENCE, na.ready.recv()).await.unwrap().unwrap();
    let ready_b = timeout(PATIENCE, nb.ready.recv()).await.unwrap().unwrap();
    let SessionReady {
        handle: b_session,
        acceptor: mut b_acceptor,
        ..
    } = ready_b;
    let SessionReady {
        acceptor: mut a_acceptor,
        ..
    } = ready_a;
    let b_table = b_session
        .channels()
        .expect("a member session has channels")
        .clone();
    let a_table = a_session
        .channels()
        .expect("a member session has channels")
        .clone();
    assert_eq!(a_table.max_payload(), MAX_PAYLOAD);

    let received = Arc::new(AtomicU64::new(0));
    let stall = Arc::new(AtomicBool::new(false));
    let handler = Echo {
        table: b_table.clone(),
        received: Arc::clone(&received),
        stall: Arc::clone(&stall),
    };
    let b_serving = tokio::spawn(async move {
        accept_loop(&mut b_acceptor, AllowAll, handler).await;
    });
    let a_serving = tokio::spawn(async move {
        accept_loop(&mut a_acceptor, AllowAll, RefuseAll).await;
    });

    let (stream1, mut ch1) = timeout(
        PATIENCE,
        open_udp_stream(&a_session, egress_star(), target()),
    )
    .await
    .expect("the OPEN must be answered")
    .expect("a UDP OPEN is acked with a channel");
    assert_eq!(ch1.id() % 2, 1, "B is the session responder: odd ids");
    assert!(b_table.is_live(ch1.id()));

    // ---- 1. a thousand mixed datagrams: at most once, intact, only ones that were sent ----
    assert_eq!(
        ch1.send(&vec![0u8; MAX_PAYLOAD + 1]),
        Err(SendDrop::TooLarge),
        "one byte over the maximum is refused at the sender"
    );
    let mut seen: HashSet<u32> = HashSet::new();
    let started = Instant::now();
    let mut next = 0u32;
    let mut quiet_since = Instant::now();
    loop {
        if drain(&mut ch1, &mut seen) > 0 {
            quiet_since = Instant::now();
        }
        if next < MIXED {
            match ch1.send(&payload(next)) {
                Ok(()) => {
                    pace(size_of(next)).await;
                    next += 1;
                    quiet_since = Instant::now();
                }
                Err(SendDrop::ChannelRate | SendDrop::PeerRate) => {
                    sleep(Duration::from_millis(2)).await
                }
                Err(SendDrop::QueueFull) => sleep(Duration::from_millis(1)).await,
                Err(other) => panic!("a datagram was refused: {other:?}"),
            }
            tokio::task::yield_now().await;
        } else {
            if quiet_since.elapsed() > Duration::from_millis(2_500)
                || started.elapsed() > Duration::from_secs(60)
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
    let delivered = seen.len();
    let at_max = seen.iter().filter(|&&i| size_of(i) == MAX_PAYLOAD).count();
    assert!(
        delivered >= 100,
        "only {delivered} of {MIXED} datagrams came back"
    );
    assert!(at_max >= 1, "no datagram of the maximum size came back");
    assert!(
        seen.iter().all(|&i| i < MIXED),
        "a datagram that was never sent came back"
    );
    eprintln!("phase 1: {delivered} of {MIXED} echoed ({at_max} of maximum size)");

    // ---- 2. datagram loss never ends the session ----
    // Five channels whose handlers do not read: sent more than the session may hold, the excess
    // is dropped at B (sinks full, then the session's 1 MiB datagram budget) and nothing else.
    stall.store(true, Ordering::Relaxed);
    let mut extra: Vec<(Stream, Channel)> = Vec::new();
    for _ in 0..4 {
        extra.push(
            timeout(
                PATIENCE,
                open_udp_stream(&a_session, egress_star(), target()),
            )
            .await
            .expect("the OPEN must be answered")
            .expect("an extra channel"),
        );
    }
    let mut ids = HashSet::from([ch1.id()]);
    ids.extend(extra.iter().map(|(_, c)| c.id()));
    assert_eq!(ids.len(), 5);
    let before = received.load(Ordering::Relaxed);
    let per_channel = 260u32;
    let sent_total = 5 * per_channel as u64;
    let overload_started = Instant::now();
    for k in 0..per_channel * 5 {
        let datagram = payload(100_000 + k);
        loop {
            let channel = match k % 5 {
                0 => &ch1,
                n => &extra[n as usize - 1].1,
            };
            match channel.send(&datagram) {
                Ok(()) => break,
                Err(SendDrop::ChannelRate | SendDrop::PeerRate | SendDrop::QueueFull) => {
                    assert!(
                        overload_started.elapsed() < Duration::from_secs(60),
                        "the overload never got sent"
                    );
                    sleep(Duration::from_millis(2)).await;
                }
                Err(other) => panic!("a datagram was refused: {other:?}"),
            }
        }
        if k % 16 == 0 {
            tokio::task::yield_now().await;
        }
    }
    // Let what is in flight land (the handlers hold still, so B's table only fills up).
    let mut in_use = 0;
    let mut still_since = Instant::now();
    let settle = Instant::now();
    while still_since.elapsed() < Duration::from_millis(1_500)
        && settle.elapsed() < Duration::from_secs(30)
    {
        sleep(Duration::from_millis(50)).await;
        let now = b_session.dgram_in_use();
        if now != in_use {
            in_use = now;
            still_since = Instant::now();
        }
    }
    eprintln!(
        "phase 2: {sent_total} datagrams sent, B holds {in_use} bytes, dropped {:?}",
        b_table.dropped()
    );
    assert!(
        in_use >= 512 * 1024,
        "B held only {in_use} bytes: the overload did not arrive"
    );
    assert!(
        in_use <= DGRAM_BUDGET_PER_SESSION,
        "B holds {in_use} bytes, over its {DGRAM_BUDGET_PER_SESSION} byte datagram budget"
    );
    // Each handler may have been waiting inside `recv` when the stall began: one each at most.
    assert!(
        received.load(Ordering::Relaxed) <= before + 5,
        "stalled handlers kept reading datagrams"
    );
    // The handlers read again: what B held is delivered, the rest is gone.
    stall.store(false, Ordering::Relaxed);
    let mut last = received.load(Ordering::Relaxed);
    let mut still_since = Instant::now();
    let settle = Instant::now();
    while (still_since.elapsed() < Duration::from_millis(1_500)
        || b_session.dgram_in_use() > 64 * 1024)
        && settle.elapsed() < Duration::from_secs(40)
    {
        sleep(Duration::from_millis(50)).await;
        let now = received.load(Ordering::Relaxed);
        if now != last {
            last = now;
            still_since = Instant::now();
        }
    }
    let reached_b = received.load(Ordering::Relaxed) - before;
    eprintln!("phase 2: {reached_b} of {sent_total} datagrams reached B's handlers");
    assert!(
        reached_b >= 100,
        "almost nothing was delivered once the handlers read"
    );
    assert!(
        reached_b + 100 <= sent_total,
        "nothing was dropped: {sent_total} sent, {reached_b} arrived"
    );
    assert!(
        b_session.dgram_in_use() <= 64 * 1024,
        "B still holds {} bytes",
        b_session.dgram_in_use()
    );
    // The extra channels and their echoes go; ch1 keeps its own.
    drop(extra);
    drain(&mut ch1, &mut seen);

    // The session lives: datagrams flow again ...
    sleep(Duration::from_millis(1_500)).await;
    let post: Vec<u32> = (50_000..50_020).collect();
    for idx in &post {
        ch1.send(&payload(*idx))
            .expect("a refilled bucket takes a datagram");
        sleep(Duration::from_millis(20)).await;
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        drain(&mut ch1, &mut seen);
        let back = post.iter().filter(|i| seen.contains(i)).count();
        if back == post.len() {
            break;
        }
        if Instant::now() > deadline {
            assert!(
                back >= 15,
                "only {back} of 20 datagrams came back after the burst"
            );
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    // ... and an ordinary stream works on the same session.
    let mut echo = timeout(PATIENCE, open_stream(&a_session, service("tcp:app"), None))
        .await
        .expect("the OPEN must be answered")
        .expect("an ordinary stream opens after the burst");
    timeout(PATIENCE, echo_round_trip(&mut echo, b"after the burst"))
        .await
        .expect("the stream must echo");
    drop(echo);

    // ---- 3. a stream reset ends delivery ----
    let (stream2, mut ch2) = timeout(
        PATIENCE,
        open_udp_stream(&a_session, egress_star(), target()),
    )
    .await
    .expect("the OPEN must be answered")
    .expect("a second channel");
    let id2 = ch2.id();
    assert_ne!(id2, ch1.id());
    let mut seen2: HashSet<u32> = HashSet::new();
    ch2.send(&payload(60_000)).unwrap();
    eventually(
        "the echo on the second channel",
        Duration::from_secs(15),
        || {
            drain(&mut ch2, &mut seen2);
            seen2.contains(&60_000)
        },
    )
    .await;

    drop(stream2); // A resets the stream.
    eventually(
        "B ends the reset stream's channel",
        Duration::from_secs(15),
        || !b_table.is_live(id2),
    )
    .await;
    let handled_before = received.load(Ordering::Relaxed);
    let unknown_before = b_table.dropped().unknown_channel;
    for idx in 60_001..60_006 {
        ch2.send(&payload(idx))
            .expect("A's own end still takes the datagram");
    }
    eventually(
        "B counts the datagrams for the ended channel as dropped",
        Duration::from_secs(15),
        || b_table.dropped().unknown_channel >= unknown_before + 5,
    )
    .await;
    sleep(Duration::from_millis(1_000)).await;
    assert_eq!(
        drain(&mut ch2, &mut seen2),
        0,
        "a datagram was answered after the stream was reset"
    );
    assert!(
        !seen2.iter().any(|i| *i > 60_000),
        "a datagram sent after the reset was delivered"
    );
    assert_eq!(
        received.load(Ordering::Relaxed),
        handled_before,
        "a handler at B saw a datagram after its stream was reset"
    );

    // The id is not handed out again within the quarantine: new channels get other ids.
    ids.insert(id2);
    let mut keep = Vec::new();
    for _ in 0..4 {
        let (stream, channel) = timeout(
            PATIENCE,
            open_udp_stream(&a_session, egress_star(), target()),
        )
        .await
        .expect("the OPEN must be answered")
        .expect("a later channel");
        assert!(
            ids.insert(channel.id()),
            "channel id {} was handed out again",
            channel.id()
        );
        assert_eq!(channel.id() % 2, 1);
        keep.push((stream, channel));
    }
    let (_, last) = keep.last_mut().unwrap();
    let mut seen3: HashSet<u32> = HashSet::new();
    last.send(&payload(70_000)).unwrap();
    eventually(
        "the echo on a later channel",
        Duration::from_secs(15),
        || {
            drain(last, &mut seen3);
            seen3.contains(&70_000)
        },
    )
    .await;
    assert!(
        b_table.is_live(ch1.id()),
        "the first channel's stream was never reset and must still be live"
    );

    drop(keep);
    drop(stream1);
    drop(ch1);
    drop(ch2);
    b_serving.abort();
    a_serving.abort();
    na.task.abort();
    nb.task.abort();
}
