//! Datagram channels of one L4 session (protocol.md 5.4, egress slice 2b1 step 2).
//!
//! A channel is opened by a yamux stream: the OPEN responder allocates the id, with the
//! parity of its own L4 session role (the session initiator even ids, the responder odd), and
//! the OPEN_ACK carries it. The initiator registers the id when it reads the ack, after
//! checking that it has the other side's parity and is not live. A channel lives exactly as
//! long as its stream: whoever holds the [`Channel`] drops it when the stream ends (the
//! handler's task on the responder, the opener on the initiator), and the session's end
//! closes every channel ([`ChannelTable::close_all`]).
//!
//! **What this module is not**: it opens no socket and serves nothing. Nothing in production
//! allocates a channel yet (the exit's UDP channel is slice 2b2), so a datagram arriving for
//! a channel id is dropped as unknown. The machinery is exercised by tests and by a
//! `ServiceHandler` that overrides `open_channel`.
//!
//! **Every drop is silent.** An unknown or removed channel, an over-rate datagram, a full
//! sink: the datagram is counted ([`ChannelTable::dropped`]) and dropped, with no CLOSE, no
//! error record and no end of the session. The record was authentic (the replay window of
//! `menzil-e2e` already recorded it), so nothing about it may be answered: no path answers a
//! datagram with a datagram.
//!
//! **Memory.** The datagrams a session holds, in the actor's queue and in the sinks of its
//! channels together, are charged to one budget ([`DGRAM_BUDGET_PER_SESSION`]) through the
//! permit that travels with each datagram, and a datagram past it is dropped on arrival.
//! A sink holds at most [`SINK_CAPACITY_BYTES`] of payload. At most
//! [`MAX_CHANNELS_PER_SESSION`] channels are live at once.
//!
//! **Time** is read through the table's clock, which a test replaces
//! ([`ChannelTable::with_clock`]); the production clock is tokio's, so a paused runtime moves
//! it too.
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::l4_session::InboundPermit;

/// At most this many channels are live in one session (below yamux's 512 live streams).
pub const MAX_CHANNELS_PER_SESSION: usize = 64;

/// A channel id is not handed out again for this long after it was freed (protocol.md 5.4):
/// a datagram of the old channel that arrives late then cannot land on a new destination.
pub const CHANNEL_QUARANTINE: Duration = Duration::from_secs(60);

/// How much payload one channel's sink holds before it drops what arrives.
pub const SINK_CAPACITY_BYTES: usize = 256 * 1024;

/// What one session may hold of datagrams that no channel has read yet: the actor's queue and
/// the sinks together.
pub const DGRAM_BUDGET_PER_SESSION: usize = 1024 * 1024;

/// How many datagrams the actor's command queue holds for sending; a datagram that finds it
/// full is dropped.
pub const DGRAM_SEND_QUEUE: usize = 64;

/// What a datagram of `n` payload bytes costs on the wire and in every bucket: the 13 byte
/// frame prefix, the 3 byte DGRAM header and the 16 byte tag.
pub const DGRAM_WIRE_OVERHEAD: usize = 32;

/// A bucket's sustained rate, 20 Mbit/s (the relay's figure for one pair, protocol.md 5.4).
pub const BUCKET_RATE_BYTES_PER_SEC: u64 = 2_500_000;

/// A bucket's burst.
pub const BUCKET_BURST_BYTES: usize = 256 * 1024;

/// One datagram on its way to the actor: the channel and the payload.
pub(crate) type DgramOut = (u16, Vec<u8>);

/// What a sink holds: the payload and the charge that counts it against the session budget.
type Held = (Vec<u8>, InboundPermit);

/// A token bucket, refilled from the caller's clock.
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn full(now: Instant) -> Self {
        Self {
            tokens: BUCKET_BURST_BYTES as f64,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        if now > self.last {
            let elapsed = now.duration_since(self.last).as_secs_f64();
            self.tokens = (self.tokens + elapsed * BUCKET_RATE_BYTES_PER_SEC as f64)
                .min(BUCKET_BURST_BYTES as f64);
            self.last = now;
        }
    }

    /// Takes `cost` bytes if the bucket has them.
    fn try_take(&mut self, cost: usize, now: Instant) -> bool {
        self.refill(now);
        if cost as f64 <= self.tokens {
            self.tokens -= cost as f64;
            true
        } else {
            false
        }
    }

    fn give_back(&mut self, cost: usize) {
        self.tokens = (self.tokens + cost as f64).min(BUCKET_BURST_BYTES as f64);
    }
}

/// Why a channel could not be allocated or registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
    /// [`MAX_CHANNELS_PER_SESSION`] channels are live.
    #[error("the session already has {MAX_CHANNELS_PER_SESSION} live channels")]
    TooMany,
    /// Every id of this side's parity is live or was freed less than [`CHANNEL_QUARANTINE`] ago.
    #[error("no channel id is free")]
    NoFreeId,
    /// An id the peer named has this side's own parity, which only this side hands out.
    #[error("the channel id has the wrong parity for the peer's role")]
    WrongParity,
    /// An id the peer named is already live in this session.
    #[error("the channel id is already live")]
    Live,
    /// The session has ended.
    #[error("the session has ended")]
    Closed,
}

/// Why [`Channel::send`] dropped a datagram. None of them ends anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SendDrop {
    /// The payload is over what one record carries (datagrams are never split).
    #[error("the datagram is larger than one record can carry")]
    TooLarge,
    /// The channel's own bucket is empty.
    #[error("the channel's rate limit is reached")]
    ChannelRate,
    /// The bucket shared by all channels to this peer is empty.
    #[error("the peer's aggregate rate limit is reached")]
    PeerRate,
    /// The session's send queue is full, or the session is gone.
    #[error("the session's send queue is full or gone")]
    QueueFull,
    /// This channel is no longer live.
    #[error("the channel is closed")]
    Closed,
}

/// What [`ChannelTable::deliver`] did with a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    Delivered,
    /// No live channel has that id (never opened, or removed).
    Unknown,
    /// The channel's receive bucket was empty.
    RateLimited,
    /// The channel's sink holds [`SINK_CAPACITY_BYTES`] already.
    SinkFull,
}

/// How many datagrams a table dropped, by reason.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dropped {
    /// For a channel id that is not live.
    pub unknown_channel: u64,
    /// Over a channel's receive bucket.
    pub rate_limited: u64,
    /// Into a full sink.
    pub sink_full: u64,
    /// By the sending side ([`SendDrop`]), any reason.
    pub send: u64,
}

struct Sink {
    tx: mpsc::UnboundedSender<Held>,
    queued: Arc<AtomicUsize>,
    recv_bucket: TokenBucket,
    send_bucket: TokenBucket,
}

struct Inner {
    /// This side was the L4 session initiator: it allocates even ids and the peer's are odd.
    initiator: bool,
    /// Where the next allocation starts looking; always of this side's parity.
    cursor: u16,
    live: HashMap<u16, Sink>,
    /// Ids of this side's parity and when they were freed, for the quarantine.
    freed: HashMap<u16, Instant>,
    /// The bucket shared by every channel's sends to this peer.
    send_aggregate: TokenBucket,
    dropped: Dropped,
    closed: bool,
}

/// The channels of one L4 session. Cheap to clone; every clone is the same table.
#[derive(Clone)]
pub struct ChannelTable {
    inner: Arc<Mutex<Inner>>,
    /// To the session actor, which encrypts and sends.
    out: mpsc::Sender<DgramOut>,
    max_payload: usize,
    clock: Arc<dyn Fn() -> Instant + Send + Sync>,
}

impl std::fmt::Debug for ChannelTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelTable")
            .field("live", &self.len())
            .finish()
    }
}

fn tokio_now() -> Instant {
    tokio::time::Instant::now().into_std()
}

impl ChannelTable {
    /// A table for a session this node is the initiator of (`initiator`) or the responder of,
    /// sending through `out`, whose datagrams carry at most `max_payload` bytes.
    pub(crate) fn new(initiator: bool, out: mpsc::Sender<DgramOut>, max_payload: usize) -> Self {
        Self::with_clock(initiator, out, max_payload, Arc::new(tokio_now))
    }

    /// [`Self::new`] reading time from `clock`.
    pub(crate) fn with_clock(
        initiator: bool,
        out: mpsc::Sender<DgramOut>,
        max_payload: usize,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        let now = clock();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                initiator,
                cursor: if initiator { 0 } else { 1 },
                live: HashMap::new(),
                freed: HashMap::new(),
                send_aggregate: TokenBucket::full(now),
                dropped: Dropped::default(),
                closed: false,
            })),
            out,
            max_payload,
            clock,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// How many channels are live.
    pub fn len(&self) -> usize {
        self.lock().live.len()
    }

    /// Whether no channel is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `id` is live.
    pub fn is_live(&self, id: u16) -> bool {
        self.lock().live.contains_key(&id)
    }

    /// How many datagrams this table dropped so far, by reason.
    pub fn dropped(&self) -> Dropped {
        self.lock().dropped
    }

    /// The largest payload [`Channel::send`] accepts.
    pub fn max_payload(&self) -> usize {
        self.max_payload
    }

    /// Allocates a channel as the OPEN responder: the next free id of this side's parity
    /// (cyclic, skipping live ids and ids freed less than [`CHANNEL_QUARANTINE`] ago), the
    /// channel registered before its OPEN_ACK is written.
    pub fn allocate(&self) -> Result<Channel, ChannelError> {
        let now = self.now();
        let mut inner = self.lock();
        if inner.closed {
            return Err(ChannelError::Closed);
        }
        if inner.live.len() >= MAX_CHANNELS_PER_SESSION {
            return Err(ChannelError::TooMany);
        }
        inner
            .freed
            .retain(|_, at| now.saturating_duration_since(*at) < CHANNEL_QUARANTINE);
        // 32,768 ids of one parity.
        let mut found = None;
        for _ in 0..=u16::MAX / 2 {
            let id = inner.cursor;
            inner.cursor = inner.cursor.wrapping_add(2);
            if inner.live.contains_key(&id) || inner.freed.contains_key(&id) {
                continue;
            }
            found = Some(id);
            break;
        }
        let id = found.ok_or(ChannelError::NoFreeId)?;
        Ok(self.insert(&mut inner, id, now))
    }

    /// Registers the channel the peer's OPEN_ACK named, as the OPEN initiator. Refused (and the
    /// caller resets the stream) when `id` has this side's own parity, is live already, or the
    /// session is at [`MAX_CHANNELS_PER_SESSION`].
    pub fn register_remote(&self, id: u16) -> Result<Channel, ChannelError> {
        let now = self.now();
        let mut inner = self.lock();
        if inner.closed {
            return Err(ChannelError::Closed);
        }
        let peer_parity_is_odd = inner.initiator;
        if (id % 2 == 1) != peer_parity_is_odd {
            return Err(ChannelError::WrongParity);
        }
        if inner.live.contains_key(&id) {
            return Err(ChannelError::Live);
        }
        if inner.live.len() >= MAX_CHANNELS_PER_SESSION {
            return Err(ChannelError::TooMany);
        }
        Ok(self.insert(&mut inner, id, now))
    }

    fn insert(&self, inner: &mut Inner, id: u16, now: Instant) -> Channel {
        let (tx, rx) = mpsc::unbounded_channel();
        let queued = Arc::new(AtomicUsize::new(0));
        inner.live.insert(
            id,
            Sink {
                tx,
                queued: Arc::clone(&queued),
                recv_bucket: TokenBucket::full(now),
                send_bucket: TokenBucket::full(now),
            },
        );
        Channel {
            id,
            table: self.clone(),
            rx,
            queued,
        }
    }

    /// Removes `id`; one of this side's own parity starts its quarantine.
    fn release(&self, id: u16) {
        let now = self.now();
        let mut inner = self.lock();
        if inner.live.remove(&id).is_none() {
            return;
        }
        let own_parity_is_odd = !inner.initiator;
        if (id % 2 == 1) == own_parity_is_odd {
            inner.freed.insert(id, now);
        }
    }

    /// Ends every channel (the session ended): each [`Channel::recv`] returns `None` once it has
    /// read what was queued, each send is dropped, and nothing more can be allocated.
    pub(crate) fn close_all(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.live.clear();
    }

    /// Hands a decrypted datagram to its channel. Never fails the session: a datagram this
    /// cannot deliver is counted and dropped, and `permit` (its charge against the session
    /// budget) goes back with it.
    pub(crate) fn deliver(&self, channel: u16, bytes: Vec<u8>, permit: InboundPermit) -> Delivery {
        let now = self.now();
        let mut inner = self.lock();
        let Some(sink) = inner.live.get_mut(&channel) else {
            inner.dropped.unknown_channel += 1;
            return Delivery::Unknown;
        };
        if !sink
            .recv_bucket
            .try_take(bytes.len() + DGRAM_WIRE_OVERHEAD, now)
        {
            inner.dropped.rate_limited += 1;
            return Delivery::RateLimited;
        }
        if sink.queued.load(Ordering::Acquire) + bytes.len() > SINK_CAPACITY_BYTES {
            inner.dropped.sink_full += 1;
            return Delivery::SinkFull;
        }
        sink.queued.fetch_add(bytes.len(), Ordering::AcqRel);
        if sink.tx.send((bytes, permit)).is_err() {
            // The receiving half is gone: the channel is as good as removed.
            inner.dropped.unknown_channel += 1;
            return Delivery::Unknown;
        }
        Delivery::Delivered
    }
}

/// One live channel: its end of the datagrams that arrive for it, and the way to send. Dropping
/// it removes the channel (and starts the quarantine of an id this side allocated), so the
/// holder keeps it exactly as long as the stream the channel belongs to.
pub struct Channel {
    id: u16,
    table: ChannelTable,
    rx: mpsc::UnboundedReceiver<Held>,
    queued: Arc<AtomicUsize>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel").field("id", &self.id).finish()
    }
}

impl Channel {
    /// The channel id of the OPEN_ACK.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// The next datagram, or `None` once the channel was ended (the session ended).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        let (bytes, _charge) = self.rx.recv().await?;
        self.queued.fetch_sub(bytes.len(), Ordering::AcqRel);
        Some(bytes)
    }

    /// The next datagram if one is waiting.
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        let (bytes, _charge) = self.rx.try_recv().ok()?;
        self.queued.fetch_sub(bytes.len(), Ordering::AcqRel);
        Some(bytes)
    }

    /// Sends `bytes` as one datagram, or drops it (see [`SendDrop`]). Never waits and never ends
    /// the session. The datagram is charged `bytes.len() + 32` to this channel's bucket and to
    /// the one all channels to this peer share, before anything is encrypted: a datagram over
    /// either leaves no counter behind.
    pub fn send(&self, bytes: &[u8]) -> Result<(), SendDrop> {
        let outcome = self.try_send(bytes);
        if outcome.is_err() {
            self.table.lock().dropped.send += 1;
        }
        outcome
    }

    fn try_send(&self, bytes: &[u8]) -> Result<(), SendDrop> {
        if bytes.len() > self.table.max_payload {
            return Err(SendDrop::TooLarge);
        }
        let cost = bytes.len() + DGRAM_WIRE_OVERHEAD;
        let now = self.table.now();
        {
            let mut inner = self.table.lock();
            if inner.closed {
                return Err(SendDrop::Closed);
            }
            let Inner {
                live,
                send_aggregate,
                ..
            } = &mut *inner;
            let Some(sink) = live.get_mut(&self.id) else {
                return Err(SendDrop::Closed);
            };
            if !sink.send_bucket.try_take(cost, now) {
                return Err(SendDrop::ChannelRate);
            }
            if !send_aggregate.try_take(cost, now) {
                sink.send_bucket.give_back(cost);
                return Err(SendDrop::PeerRate);
            }
        }
        // A full queue or an actor that is gone drops the datagram: a gap is harmless here.
        self.table
            .out
            .try_send((self.id, bytes.to_vec()))
            .map_err(|_| SendDrop::QueueFull)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.table.release(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l4_session::InboundBudget;

    /// A clock the test moves by hand.
    #[derive(Clone)]
    struct Manual(Arc<Mutex<Instant>>);

    impl Manual {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }
        fn advance(&self, by: Duration) {
            *self.0.lock().unwrap() += by;
        }
        fn clock(&self) -> Arc<dyn Fn() -> Instant + Send + Sync> {
            let inner = Arc::clone(&self.0);
            Arc::new(move || *inner.lock().unwrap())
        }
    }

    fn table(initiator: bool, clock: &Manual) -> (ChannelTable, mpsc::Receiver<DgramOut>) {
        let (tx, rx) = mpsc::channel(DGRAM_SEND_QUEUE);
        (
            ChannelTable::with_clock(initiator, tx, 65_452, clock.clock()),
            rx,
        )
    }

    fn permit(budget: &InboundBudget) -> InboundPermit {
        budget.try_reserve(1).expect("budget has room")
    }

    #[test]
    fn channel_ids_follow_the_responders_session_role_parity() {
        let clock = Manual::new();
        // The session initiator hands out even ids, the responder odd ones, each its own
        // sequence, so the two sets never meet.
        let (initiator, _rx) = table(true, &clock);
        let (responder, _rx2) = table(false, &clock);
        let mut ids = Vec::new();
        let held: Vec<Channel> = (0..4).map(|_| initiator.allocate().unwrap()).collect();
        ids.extend(held.iter().map(Channel::id));
        assert!(ids.iter().all(|id| id % 2 == 0), "{ids:?}");
        let held2: Vec<Channel> = (0..4).map(|_| responder.allocate().unwrap()).collect();
        assert!(held2.iter().all(|c| c.id() % 2 == 1));
        // And each side registers only what the peer's parity allows.
        assert_eq!(
            initiator.register_remote(4).unwrap_err(),
            ChannelError::WrongParity,
            "an even id is the initiator's own"
        );
        assert_eq!(
            responder.register_remote(5).unwrap_err(),
            ChannelError::WrongParity,
            "an odd id is the responder's own"
        );
        initiator
            .register_remote(5)
            .expect("an odd id is the peer's");
        responder
            .register_remote(4)
            .expect("an even id is the peer's");
    }

    #[test]
    fn a_remote_id_that_is_live_is_refused() {
        let clock = Manual::new();
        let (initiator, _rx) = table(true, &clock);
        let first = initiator.register_remote(7).unwrap();
        assert_eq!(
            initiator.register_remote(7).unwrap_err(),
            ChannelError::Live
        );
        drop(first);
        initiator
            .register_remote(7)
            .expect("free again once the channel is gone");
    }

    #[test]
    fn a_freed_channel_id_is_not_reused_within_60_s() {
        let clock = Manual::new();
        let (responder, _rx) = table(false, &clock);
        let mut first = None;
        // Every id of this side's parity is used once and freed at the same instant.
        for n in 0..32_768u32 {
            let channel = responder.allocate().expect("an unused id is free");
            if n == 0 {
                first = Some(channel.id());
            }
        }
        assert_eq!(
            responder.allocate().unwrap_err(),
            ChannelError::NoFreeId,
            "every id was freed less than 60 s ago"
        );
        clock.advance(CHANNEL_QUARANTINE - Duration::from_secs(1));
        assert_eq!(responder.allocate().unwrap_err(), ChannelError::NoFreeId);
        clock.advance(Duration::from_secs(1));
        let again = responder.allocate().expect("60 s have passed");
        assert_eq!(Some(again.id()), first, "the oldest freed id comes back");
    }

    #[test]
    fn at_most_64_channels_are_live() {
        let clock = Manual::new();
        let (responder, _rx) = table(false, &clock);
        let held: Vec<Channel> = (0..MAX_CHANNELS_PER_SESSION)
            .map(|_| responder.allocate().unwrap())
            .collect();
        assert_eq!(responder.allocate().unwrap_err(), ChannelError::TooMany);
        assert_eq!(
            responder.register_remote(2).unwrap_err(),
            ChannelError::TooMany
        );
        drop(held);
        assert!(responder.is_empty());
    }

    #[test]
    fn the_receivers_channel_bucket_drops_the_excess() {
        let clock = Manual::new();
        let (responder, _rx) = table(false, &clock);
        let budget = InboundBudget::new(DGRAM_BUDGET_PER_SESSION * 8);
        let mut channel = responder.allocate().unwrap();
        let id = channel.id();
        let cost = 1000 + DGRAM_WIRE_OVERHEAD;
        let fits = BUCKET_BURST_BYTES / cost;
        // The sink takes more than the bucket does here, so the bucket is what stops it.
        for n in 0..fits {
            assert_eq!(
                responder.deliver(id, vec![0; 1000], permit(&budget)),
                Delivery::Delivered,
                "datagram {n} is within the burst"
            );
            // Reading keeps the sink empty.
            assert!(channel.try_recv().is_some());
        }
        assert_eq!(
            responder.deliver(id, vec![0; 1000], permit(&budget)),
            Delivery::RateLimited,
            "the burst is spent"
        );
        assert!(channel.try_recv().is_none(), "nothing was queued for it");
        assert_eq!(responder.dropped().rate_limited, 1);
        // The bucket refills with time.
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            responder.deliver(id, vec![0; 1000], permit(&budget)),
            Delivery::Delivered
        );
        // Another channel has a bucket of its own.
        let other = responder.allocate().unwrap();
        assert_eq!(
            responder.deliver(other.id(), vec![0; 1000], permit(&budget)),
            Delivery::Delivered
        );
        assert_eq!(budget.in_use_for_tests(), 2, "two datagrams are held");
    }

    #[test]
    fn a_full_sink_drops_and_what_a_read_frees_is_given_back() {
        let clock = Manual::new();
        let (responder, _rx) = table(false, &clock);
        let budget = InboundBudget::new(DGRAM_BUDGET_PER_SESSION);
        let mut channel = responder.allocate().unwrap();
        let id = channel.id();
        // 4 x 64 KiB fill the 256 KiB sink; the buckets are not what stops this (burst 256 KiB
        // of wire bytes is just below, so move the clock between datagrams).
        for _ in 0..4 {
            assert_eq!(
                responder.deliver(id, vec![0; 64 * 1024], permit(&budget)),
                Delivery::Delivered
            );
            clock.advance(Duration::from_secs(1));
        }
        assert_eq!(
            responder.deliver(id, vec![0; 1], permit(&budget)),
            Delivery::SinkFull
        );
        assert_eq!(responder.dropped().sink_full, 1);
        assert_eq!(
            budget.in_use_for_tests(),
            4,
            "the refused one gave its charge back"
        );
        assert!(channel.try_recv().is_some());
        assert_eq!(budget.in_use_for_tests(), 3, "a read gives its charge back");
        assert_eq!(
            responder.deliver(id, vec![0; 1], permit(&budget)),
            Delivery::Delivered
        );
    }

    #[test]
    fn an_unknown_channel_is_dropped_and_counted() {
        let clock = Manual::new();
        let (responder, _rx) = table(false, &clock);
        let budget = InboundBudget::new(DGRAM_BUDGET_PER_SESSION);
        assert_eq!(
            responder.deliver(9, vec![1, 2, 3], permit(&budget)),
            Delivery::Unknown
        );
        assert_eq!(responder.dropped().unknown_channel, 1);
        assert_eq!(budget.in_use_for_tests(), 0);
    }

    #[test]
    fn the_senders_buckets_drop_the_excess_before_the_queue() {
        let clock = Manual::new();
        let (responder, mut rx) = table(false, &clock);
        let channel = responder.allocate().unwrap();
        let cost = 1000 + DGRAM_WIRE_OVERHEAD;
        let fits = BUCKET_BURST_BYTES / cost;
        for _ in 0..fits {
            channel.send(&[0; 1000]).unwrap();
            rx.try_recv().expect("queued for the actor");
        }
        assert_eq!(channel.send(&[0; 1000]), Err(SendDrop::ChannelRate));
        assert!(
            rx.try_recv().is_err(),
            "a datagram over the bucket is not queued"
        );
        clock.advance(Duration::from_secs(1));
        channel.send(&[0; 1000]).expect("refilled");
        // A datagram larger than one record is refused at once.
        assert_eq!(channel.send(&vec![0; 65_453]), Err(SendDrop::TooLarge));
        assert_eq!(responder.dropped().send, 2);
    }

    #[test]
    fn a_full_send_queue_drops_the_datagram() {
        let clock = Manual::new();
        let (responder, mut rx) = table(false, &clock);
        let channel = responder.allocate().unwrap();
        for _ in 0..DGRAM_SEND_QUEUE {
            channel.send(&[0; 10]).unwrap();
        }
        assert_eq!(channel.send(&[0; 10]), Err(SendDrop::QueueFull));
        drop(rx.try_recv());
        channel.send(&[0; 10]).expect("room again");
        // An actor that is gone drops too.
        drop(rx);
        assert_eq!(channel.send(&[0; 10]), Err(SendDrop::QueueFull));
    }

    #[test]
    fn the_peer_aggregate_bucket_is_shared_by_all_channels() {
        let clock = Manual::new();
        let (responder, _rx) = table(false, &clock);
        let a = responder.allocate().unwrap();
        let b = responder.allocate().unwrap();
        let payload = vec![0u8; 60_000];
        let cost = payload.len() + DGRAM_WIRE_OVERHEAD;
        let fits = BUCKET_BURST_BYTES / cost;
        // Each channel alone could send `fits` of these; together they share one bucket.
        for _ in 0..fits {
            a.send(&payload).unwrap();
        }
        assert_eq!(b.send(&payload), Err(SendDrop::PeerRate));
        // The refused datagram gave its channel tokens back: `b` can still send a small one.
        b.send(&[0; 100]).expect("b's own bucket is intact");
    }

    #[test]
    fn closing_the_table_ends_every_channel() {
        let clock = Manual::new();
        let (responder, _rx) = table(false, &clock);
        let mut channel = responder.allocate().unwrap();
        responder.close_all();
        assert_eq!(channel.send(&[1]), Err(SendDrop::Closed));
        assert_eq!(responder.allocate().unwrap_err(), ChannelError::Closed);
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        assert_eq!(rt.block_on(channel.recv()), None);
    }
}
