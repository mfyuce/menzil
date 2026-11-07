//! A tenant's bandwidth bucket, volume counter and delayed CREDIT (multi tenant design 2.3 and
//! 2.4, slice MT8; threat A8).
//!
//! The relay never drops a tenant's reliable data to enforce bandwidth, and it never refuses
//! it: it makes the sender wait. A reliable SEND is paid for with the sender's credit
//! (protocol.md 4.2), and the credit comes back as a CREDIT record once the relay has handed the
//! RECV to the destination's connection (`crate::forward::ForwardTable::drained`). A tenant that
//! is over its bandwidth gets that CREDIT *later*: [`Shaper::charge`] takes the bytes out of the
//! tenant's bucket (which may go into debt), and while the bucket is in debt the CREDIT of the
//! tenant's senders is held back and handed out by one timer task per tenant (`flush`) as time
//! pays the debt off. So the sender's rate converges on the bucket's rate, nothing is lost
//! (every byte charged is granted back, once) and a sender never sees anything but a slower
//! transfer.
//!
//! Held CREDIT is released fairly (round T4, M3): each sending NodeId has its own FIFO of
//! (pair, bytes), and the bytes the bucket pays off per second are shared equally among the
//! senders that have CREDIT held (max-min fair, like processor sharing). A record therefore waits
//! for the bytes charged before it *by its own sender* plus an equal share with the others, never
//! for the whole tenant's debt: one member that spent all its windows delays an honest member by
//! about one share of the rate, not by the sum of everyone's in-flight bytes. Nothing is lost:
//! the CREDIT granted equals the CREDIT consumed.
//!
//! Droppable traffic is paid at admission, never on credit (round T4, M1): a droppable SEND takes
//! its bytes from the bucket when it is admitted ([`Shaper::try_take`]) and is dropped when the
//! bucket does not hold them (empty, or in debt from reliable traffic). So droppable traffic
//! never drives the bucket below zero and never delays the CREDIT of reliable senders. Bytes taken
//! for a droppable record that the destination later discards unsent are not given back (accepted:
//! droppable is lossy by definition and the figure is a ceiling).
//!
//! One bucket per tenant. A tenant's debt delays only that tenant's CREDIT, so a second
//! tenant's throughput does not depend on the first one's stall (the tasks and the buckets are
//! separate; the pair table's lock is held for a few instructions only).
//!
//! The volume counter is the bytes charged in the current period (30 days by default). Once it
//! reaches the tenant's volume figure the bucket's rate falls to the floor rate (5 Mbit/s by
//! default) until the period ends (decision D3, option A), and its burst falls to one second of
//! the floor rate: a full 256 MiB burst would otherwise make the floor meaningless for the first
//! minutes. At 5 Mbit/s a 1 MiB credit window takes about 1.7 s to come back, far below the 35
//! s a node's staged frame waits (L4h5), so throttling never ends a session.
//!
//! Time is `tokio::time::Instant`, so tests can pause the clock. Nothing here is persisted: a
//! relay restart starts the period afresh (accepted in the design).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use menzil_proto::NodeId;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::forward::ForwardItem;
use crate::registry::SessionRegistry;
use crate::tenant::Figures;

/// Whose CREDIT is being held: the sender, the destination the credit is for, and the sender's
/// session at the time the bytes were charged (a sender that reconnected since is owed nothing:
/// its new session starts with a fresh ledger).
type CreditKey = (NodeId, NodeId, u32);

/// A tenant's figures in the units the bucket uses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ShapeFigures {
    /// Sustained rate, bytes per second.
    rate: f64,
    /// Bucket size, bytes.
    burst: f64,
    /// Bytes per period before the floor applies.
    volume: u64,
    /// Length of the period.
    period: Duration,
    /// Rate once the volume is used up, bytes per second.
    floor: f64,
}

impl ShapeFigures {
    pub(crate) fn from_figures(figures: &Figures) -> Self {
        Self {
            rate: figures.bandwidth_mbit as f64 * 125_000.0,
            burst: figures.burst_mib as f64 * 1_048_576.0,
            volume: figures.volume_gib.saturating_mul(1 << 30),
            period: Duration::from_secs(figures.volume_days.saturating_mul(86_400)),
            floor: figures.floor_mbit as f64 * 125_000.0,
        }
    }
}

struct Inner {
    figures: ShapeFigures,
    /// Bytes the tenant may move now; negative is debt.
    tokens: f64,
    last: Instant,
    period_start: Instant,
    period_bytes: u64,
    /// The rate the last refill used (bytes per second), for the timer's wait.
    rate: f64,
    /// CREDIT owed and not yet released, one FIFO per sending NodeId.
    held: HashMap<NodeId, VecDeque<Held>>,
    /// Bytes of debt that time has paid off since they were last shared out among `held`.
    pool: f64,
    /// Whether a timer task is running for `held`.
    flusher: bool,
}

/// The longest a sender's queue may grow before records of one pair are merged (bounds memory
/// when a hostile sender alternates pairs).
const MAX_HELD_PER_SENDER: usize = 1024;

/// The shortest wait of the timer: records are released in batches of at least this much time.
const MIN_TICK: Duration = Duration::from_millis(10);

/// The longest wait of the timer while anything is held: a big held record (a pair's merged
/// window) is released in parts at this pace, so a sender's CREDIT comes back smoothly at the
/// bucket's rate instead of in one lump when the whole record has been paid.
const MAX_TICK: Duration = Duration::from_millis(250);

/// A partly paid record releases what is paid once it is this many bytes.
const PARTIAL_GRANT_BYTES: f64 = 16_384.0;

/// CREDIT of one pair, waiting for the bucket.
#[derive(Debug)]
struct Held {
    key: CreditKey,
    /// Bytes of CREDIT not yet released.
    bytes: u32,
    /// Bytes of `bytes` the bucket has paid off so far.
    paid: f64,
}

impl Inner {
    /// Brings `tokens` and the volume period up to `now`.
    fn refill(&mut self, now: Instant) {
        let f = self.figures;
        let since_period = now.saturating_duration_since(self.period_start);
        if !f.period.is_zero() && since_period >= f.period {
            let whole = since_period.as_secs() / f.period.as_secs().max(1);
            self.period_start += f.period * u32::try_from(whole).unwrap_or(u32::MAX);
            self.period_bytes = 0;
        }
        let at_floor = self.period_bytes >= f.volume;
        let (rate, cap) = if at_floor {
            (f.floor, f.floor.min(f.burst))
        } else {
            (f.rate, f.burst)
        };
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        let before = self.tokens;
        let added = elapsed * rate;
        self.tokens = (before + added).min(cap);
        // Only the part of the refill that pays off a debt is shared out among the held CREDIT;
        // what fills the burst is not, and nothing is stored while nothing is held.
        if before < 0.0 && !self.held.is_empty() {
            self.pool += added.min(-before);
        }
        self.last = now;
        self.rate = rate;
    }

    /// Adds `bytes` of CREDIT for `key` to its sender's queue (merging into the tail when it is
    /// the same pair, or anywhere in the queue when the queue is too long).
    fn push(&mut self, key: CreditKey, bytes: u32) {
        let queue = self.held.entry(key.0).or_default();
        let same = |h: &Held| h.key == key;
        let slot = if queue.back().is_some_and(same) {
            queue.back_mut()
        } else if queue.len() >= MAX_HELD_PER_SENDER {
            queue.iter_mut().rev().find(|h| h.key == key)
        } else {
            None
        };
        match slot {
            Some(held) if held.bytes.checked_add(bytes).is_some() => held.bytes += bytes,
            _ => queue.push_back(Held {
                key,
                bytes,
                paid: 0.0,
            }),
        }
    }

    /// Shares the paid off debt in `pool` equally among the senders that have CREDIT held, each
    /// sender's share going to its oldest records first, and returns the records now fully paid.
    /// A bucket that is out of debt releases everything (delay is never loss).
    fn distribute(&mut self) -> Vec<(CreditKey, u32)> {
        let mut due = Vec::new();
        if self.tokens >= 0.0 {
            for (_, queue) in self.held.drain() {
                due.extend(queue.into_iter().map(|h| (h.key, h.bytes)));
            }
            self.pool = 0.0;
            return due;
        }
        let mut left = std::mem::take(&mut self.pool);
        while left > 0.0 && !self.held.is_empty() {
            let share = left / self.held.len() as f64;
            let mut used = 0.0;
            for queue in self.held.values_mut() {
                let mut budget = share;
                while budget > 0.0 {
                    let Some(head) = queue.front_mut() else { break };
                    let need = f64::from(head.bytes) - head.paid;
                    if budget >= need - 1e-6 {
                        budget -= need;
                        used += need;
                        if let Some(done) = queue.pop_front() {
                            due.push((done.key, done.bytes));
                        }
                    } else {
                        head.paid += budget;
                        used += budget;
                        budget = 0.0;
                        // What is paid of a big record goes out now, in whole bytes.
                        if head.paid >= PARTIAL_GRANT_BYTES {
                            let part = head.paid.floor();
                            let whole = part as u32;
                            head.bytes -= whole;
                            head.paid -= part;
                            due.push((head.key, whole));
                        }
                    }
                }
            }
            self.held.retain(|_, queue| !queue.is_empty());
            left -= used;
            if used <= 0.0 {
                break;
            }
        }
        due
    }

    /// How long until the first held record is paid off at today's rate and sharing (at most
    /// [`MAX_TICK`]), if any is held.
    fn wait(&self) -> Option<Duration> {
        let senders = self.held.len();
        let neediest = self
            .held
            .values()
            .filter_map(|queue| queue.front())
            .map(|head| f64::from(head.bytes) - head.paid)
            .fold(f64::INFINITY, f64::min);
        if senders == 0 || !neediest.is_finite() {
            return None;
        }
        let seconds = neediest * senders as f64 / self.rate.max(1.0);
        Some(Duration::from_secs_f64(seconds.clamp(0.0, 86_400.0)).clamp(MIN_TICK, MAX_TICK))
    }
}

/// One tenant's bucket and counter. Cheap to clone: the timer task holds a clone.
#[derive(Clone)]
pub(crate) struct Shaper {
    inner: Arc<Mutex<Inner>>,
    /// Wakes the timer when a record joins a queue it is not waiting for.
    wake: Arc<Notify>,
}

/// What [`Shaper::charge`] decided about the CREDIT it was given.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Credit {
    /// The bucket is not in debt: grant it now.
    Now,
    /// Held; the timer task releases it.
    Held {
        /// Nobody is running the timer yet: the caller must start it ([`Shaper::flush`]).
        start_timer: bool,
    },
    /// Nothing was owed (an unreliable record).
    None,
}

impl Shaper {
    /// A bucket full to its burst, no volume used.
    pub(crate) fn new(figures: &Figures, now: Instant) -> Self {
        let figures = ShapeFigures::from_figures(figures);
        Self {
            inner: Arc::new(Mutex::new(Inner {
                figures,
                tokens: figures.burst,
                last: now,
                period_start: now,
                period_bytes: 0,
                rate: figures.rate,
                held: HashMap::new(),
                pool: 0.0,
                flusher: false,
            })),
            wake: Arc::new(Notify::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes `bytes` that went out to a destination from the bucket and the volume counter, with
    /// the tenant's current `figures` (a reload may have changed them). `credit` is the CREDIT
    /// this charge owes its sender, if it was reliable: it is granted now when the bucket is not
    /// in debt, else held for the timer.
    pub(crate) fn charge(
        &self,
        figures: &Figures,
        bytes: u32,
        credit: Option<CreditKey>,
        now: Instant,
    ) -> Credit {
        let mut inner = self.lock();
        inner.figures = ShapeFigures::from_figures(figures);
        inner.refill(now);
        inner.tokens -= f64::from(bytes);
        inner.period_bytes = inner.period_bytes.saturating_add(u64::from(bytes));
        let Some(key) = credit else {
            return Credit::None;
        };
        if inner.tokens >= 0.0 && inner.held.is_empty() {
            return Credit::Now;
        }
        inner.push(key, bytes);
        let start_timer = !inner.flusher;
        inner.flusher = true;
        drop(inner);
        if !start_timer {
            // The record may be due sooner than the timer's next wake.
            self.wake.notify_one();
        }
        Credit::Held { start_timer }
    }

    /// Takes `bytes` of a droppable record from the bucket if it holds them, and counts them in
    /// the volume. A bucket that is empty or in debt refuses: the record is dropped. The bucket
    /// is never taken below zero by this (round T4, M1).
    pub(crate) fn try_take(&self, figures: &Figures, bytes: u32, now: Instant) -> bool {
        let mut inner = self.lock();
        inner.figures = ShapeFigures::from_figures(figures);
        inner.refill(now);
        if inner.tokens < f64::from(bytes) {
            return false;
        }
        inner.tokens -= f64::from(bytes);
        inner.period_bytes = inner.period_bytes.saturating_add(u64::from(bytes));
        true
    }

    /// Whether the bucket is in debt now (reliable traffic took more than it held). The relay's
    /// own sender (the expose principal) is not held back by delayed CREDIT as a member is, so it
    /// asks this before a reliable frame and waits while it is true.
    pub(crate) fn in_debt(&self, figures: &Figures, now: Instant) -> bool {
        let mut inner = self.lock();
        inner.figures = ShapeFigures::from_figures(figures);
        inner.refill(now);
        inner.tokens < 0.0
    }

    /// Runs until nothing is held: shares out what time has paid off among the senders, hands
    /// the paid records to the senders that are still the same session, and sleeps until the
    /// next record is due (or a new record joins). Spawned once per burst of debt by whoever got
    /// `start_timer`.
    pub(crate) async fn flush(self, registry: SessionRegistry) {
        loop {
            let (due, wait) = {
                let mut inner = self.lock();
                inner.refill(Instant::now());
                let due = inner.distribute();
                let wait = inner.wait();
                if wait.is_none() {
                    inner.flusher = false;
                }
                (due, wait)
            };
            grant(&registry, due);
            let Some(wait) = wait else { return };
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.wake.notified() => {}
            }
        }
    }

    /// Hands out everything held now, whatever the bucket says (no timer can run: the caller is
    /// not inside a runtime). Delay never becomes loss.
    pub(crate) fn release_all(&self, registry: &SessionRegistry) {
        let due: Vec<(CreditKey, u32)> = {
            let mut inner = self.lock();
            inner.flusher = false;
            inner.pool = 0.0;
            inner
                .held
                .drain()
                .flat_map(|(_, queue)| queue.into_iter().map(|h| (h.key, h.bytes)))
                .collect()
        };
        grant(registry, due);
    }

    /// The bytes charged in the current volume period and how long that period still runs, as of
    /// `now`, changing nothing: a period that has ended since the last charge is shown as the
    /// new one the next charge would start (zero bytes), as [`Inner::refill`] would roll it.
    pub(crate) fn volume_status(&self, now: Instant) -> (u64, Duration) {
        let inner = self.lock();
        let period = inner.figures.period;
        if period.is_zero() {
            return (inner.period_bytes, Duration::ZERO);
        }
        let since = now.saturating_duration_since(inner.period_start);
        let (bytes, start) = if since >= period {
            let whole = since.as_secs() / period.as_secs().max(1);
            (
                0,
                inner.period_start + period * u32::try_from(whole).unwrap_or(u32::MAX),
            )
        } else {
            (inner.period_bytes, inner.period_start)
        };
        (bytes, (start + period).saturating_duration_since(now))
    }

    /// The bytes charged in the current volume period (tests).
    #[cfg(test)]
    pub(crate) fn volume_used(&self) -> u64 {
        self.lock().period_bytes
    }

    /// Counts `bytes` as used this period without moving any (tests: reaching the floor).
    #[cfg(test)]
    pub(crate) fn add_volume(&self, bytes: u64) {
        let mut inner = self.lock();
        inner.period_bytes = inner.period_bytes.saturating_add(bytes);
    }

    /// Credit held back at this moment (tests).
    #[cfg(test)]
    pub(crate) fn held(&self) -> u64 {
        self.lock()
            .held
            .values()
            .flatten()
            .map(|h| u64::from(h.bytes))
            .sum()
    }
}

/// Sends the CREDIT records in `due`, except to a sender that has reconnected since (its new
/// session has a ledger of its own and is owed nothing for the old one).
fn grant(registry: &SessionRegistry, due: Vec<(CreditKey, u32)>) {
    // Records of one pair that are due together go out as one CREDIT (several, if the sum does
    // not fit a CREDIT record: never a byte lost).
    let mut by_key: HashMap<CreditKey, u64> = HashMap::new();
    for (key, bytes) in due {
        *by_key.entry(key).or_default() += u64::from(bytes);
    }
    for ((src, dst, session_id), mut bytes) in by_key {
        if !registry.is_current(&src, session_id) {
            continue;
        }
        while bytes > 0 {
            let part = u32::try_from(bytes).unwrap_or(u32::MAX);
            registry.deliver(
                &src,
                ForwardItem::Credit {
                    peer: dst,
                    bytes: part,
                },
            );
            bytes -= u64::from(part);
        }
    }
}

/// The map of tenants' buckets (one per tenant that has figures and has moved data).
#[derive(Default)]
pub(crate) struct Shapers {
    by_tenant: Mutex<HashMap<crate::tenant::TenantId, Shaper>>,
}

impl Shapers {
    /// The bucket of `tenant`, made on first use from `figures`.
    pub(crate) fn of(&self, tenant: &crate::tenant::TenantId, figures: &Figures) -> Shaper {
        let mut map = self
            .by_tenant
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(shaper) = map.get(tenant) {
            return shaper.clone();
        }
        let shaper = Shaper::new(figures, Instant::now());
        map.insert(tenant.clone(), shaper.clone());
        shaper
    }

    /// The volume used and the time left of `tenant`'s period ([`Shaper::volume_status`]), if it
    /// has a bucket (it has moved data).
    pub(crate) fn volume_status(
        &self,
        tenant: &crate::tenant::TenantId,
        now: Instant,
    ) -> Option<(u64, Duration)> {
        let shaper = self
            .by_tenant
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(tenant)
            .cloned()?;
        Some(shaper.volume_status(now))
    }

    /// The bucket of `tenant`, if it has one (tests).
    #[cfg(test)]
    pub(crate) fn get(&self, tenant: &crate::tenant::TenantId) -> Option<Shaper> {
        self.by_tenant
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(tenant)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::SessionRegistry;

    fn node(n: u8) -> NodeId {
        NodeId::from([n; 32])
    }

    /// 1 Mbit/s sustained (125,000 bytes/s), 1 MiB burst, floor 1 Mbit/s.
    fn slow() -> Figures {
        Figures {
            bandwidth_mbit: 1,
            burst_mib: 1,
            floor_mbit: 1,
            volume_gib: 1,
            volume_days: 30,
            ..Figures::friend()
        }
    }

    /// The status export reads the volume of the period and when it ends without touching the
    /// bucket, and shows a period that has ended since the last charge as the next one.
    #[tokio::test(start_paused = true)]
    async fn the_volume_status_reports_the_period_and_rolls_it_without_a_charge() {
        let day = Duration::from_secs(86_400);
        let start = Instant::now();
        let shaper = Shaper::new(&slow(), start);
        assert_eq!(shaper.volume_status(start), (0, 30 * day));
        shaper.charge(&slow(), 1_000, None, start);
        tokio::time::advance(10 * day).await;
        assert_eq!(shaper.volume_status(Instant::now()), (1_000, 20 * day));
        // Read only: asking again changes nothing.
        assert_eq!(shaper.volume_status(Instant::now()), (1_000, 20 * day));
        assert_eq!(shaper.volume_used(), 1_000);
        // After the period (35 days in): nothing used, the next period has 25 days to run.
        tokio::time::advance(25 * day).await;
        assert_eq!(shaper.volume_status(Instant::now()), (0, 25 * day));
        assert_eq!(
            shaper.volume_used(),
            1_000,
            "the status does not roll the real counter"
        );
        // 65 days in: two periods are gone, the third ends at day 90.
        tokio::time::advance(30 * day).await;
        assert_eq!(shaper.volume_status(Instant::now()), (0, 25 * day));
    }

    #[tokio::test(start_paused = true)]
    async fn within_the_burst_credit_is_granted_at_once() {
        let shaper = Shaper::new(&slow(), Instant::now());
        let key = (node(1), node(2), 1);
        assert_eq!(
            shaper.charge(&slow(), 1_000_000, Some(key), Instant::now()),
            Credit::Now
        );
        assert_eq!(shaper.volume_used(), 1_000_000);
        assert_eq!(shaper.held(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn past_the_burst_credit_is_held_until_the_debt_is_paid() {
        let shaper = Shaper::new(&slow(), Instant::now());
        let key = (node(1), node(2), 1);
        // 1 MiB burst; charging 1 MiB + 125,000 leaves a debt of 125,000 bytes = 1 s.
        assert_eq!(
            shaper.charge(&slow(), 1_048_576, Some(key), Instant::now()),
            Credit::Now
        );
        assert_eq!(
            shaper.charge(&slow(), 125_000, Some(key), Instant::now()),
            Credit::Held { start_timer: true }
        );
        assert_eq!(shaper.held(), 125_000);
        assert_eq!(
            shaper.lock().tokens,
            -125_000.0,
            "a debt of one second of the rate"
        );
        assert_eq!(
            shaper.lock().wait(),
            Some(MAX_TICK),
            "the timer looks again after at most a tick"
        );
        // Another charge while held joins the timer that is running.
        assert_eq!(
            shaper.charge(&slow(), 10, Some(key), Instant::now()),
            Credit::Held { start_timer: false }
        );
    }

    /// Round T4, M1: a droppable record is paid from the bucket at admission; it is refused when
    /// the bucket does not hold its bytes (empty, or in debt) and never takes the bucket below
    /// zero.
    #[tokio::test(start_paused = true)]
    async fn a_droppable_take_never_goes_below_zero_and_is_refused_in_debt() {
        let shaper = Shaper::new(&slow(), Instant::now());
        // The 1 MiB burst: 16 records of 64 KiB fit exactly, the 17th does not.
        for _ in 0..16 {
            assert!(shaper.try_take(&slow(), 65_536, Instant::now()));
        }
        assert!(!shaper.try_take(&slow(), 65_536, Instant::now()));
        assert!(shaper.lock().tokens >= 0.0);
        assert_eq!(
            shaper.volume_used(),
            16 * 65_536,
            "the refused one is not counted"
        );
        // A reliable charge puts the bucket in debt: every droppable record is refused.
        let key = (node(1), node(2), 1);
        assert_eq!(
            shaper.charge(&slow(), 100_000, Some(key), Instant::now()),
            Credit::Held { start_timer: true }
        );
        assert!(shaper.lock().tokens < 0.0);
        assert!(!shaper.try_take(&slow(), 1, Instant::now()));
        let debt = shaper.lock().tokens;
        assert_eq!(debt, shaper.lock().tokens, "a refused take changes nothing");
        // Time pays the debt and fills the bucket again.
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(shaper.try_take(&slow(), 65_536, Instant::now()));
    }

    /// A registry with a session for each of `nodes`, and their CREDIT receivers.
    fn senders(
        nodes: &[u8],
    ) -> (
        SessionRegistry,
        HashMap<u8, tokio::sync::mpsc::UnboundedReceiver<ForwardItem>>,
    ) {
        let registry = SessionRegistry::new();
        let receivers = nodes
            .iter()
            .map(|&n| (n, registry.attach(node(n), 1, Vec::new()).2))
            .collect();
        (registry, receivers)
    }

    fn credit_of(rx: &mut tokio::sync::mpsc::UnboundedReceiver<ForwardItem>) -> u64 {
        let mut total = 0;
        while let Ok(item) = rx.try_recv() {
            if let ForwardItem::Credit { bytes, .. } = item {
                total += u64::from(bytes);
            }
        }
        total
    }

    /// Round T4, M3: the bytes the bucket pays off are shared equally among the senders that
    /// have CREDIT held, each sender's FIFO served in its own order. A small record of one sender
    /// does not wait for the large debt of another, only for its own bytes at its share.
    #[tokio::test(start_paused = true)]
    async fn held_credit_is_shared_among_senders_and_never_lost() {
        let (registry, mut rx) = senders(&[1, 2]);
        let shaper = Shaper::new(&slow(), Instant::now());
        // Sender 1 spends 4 MiB in 1 MiB windows (a debt of about 25 s beyond the burst), then
        // sender 2 charges one 64 KiB record.
        let big = (node(1), node(9), 1);
        for _ in 0..4 {
            shaper.charge(&slow(), 1_048_576, Some(big), Instant::now());
        }
        let small = (node(2), node(9), 1);
        let held = shaper.charge(&slow(), 65_536, Some(small), Instant::now());
        assert_eq!(held, Credit::Held { start_timer: false });
        tokio::spawn(shaper.clone().flush(registry.clone()));
        // Two senders share 125,000 B/s: the small record needs 65,536 at 62,500 B/s, about 1 s.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(credit_of(rx.get_mut(&2).unwrap()), 65_536);
        // Sender 1 was served in parts meanwhile, never beyond what was paid.
        let first = credit_of(rx.get_mut(&1).unwrap());
        assert!(first > 0 && first < 4 * 1_048_576 - 1_048_576, "{first}");
        // Everything held comes back, once: 3 MiB at 125,000 B/s is about 25 s.
        tokio::time::sleep(Duration::from_secs(60)).await;
        let rest = credit_of(rx.get_mut(&1).unwrap());
        // The first MiB was inside the burst (granted by the caller at once, not held).
        assert_eq!(first + rest, 3 * 1_048_576);
        assert_eq!(shaper.held(), 0);
    }

    /// Round T4, M3: one sender's records leave in the order they were charged, and nothing
    /// charged is lost or granted twice.
    #[tokio::test(start_paused = true)]
    async fn one_senders_credit_is_released_in_charge_order_and_sums_to_the_charge() {
        let (registry, mut rx) = senders(&[1]);
        let shaper = Shaper::new(&slow(), Instant::now());
        shaper.charge(&slow(), 1_048_576, None, Instant::now());
        let (first, second) = ((node(1), node(5), 1), (node(1), node(6), 1));
        // 100,000 bytes for pair 5, then 200,000 for pair 6: debts of 0.8 s and 2.4 s.
        shaper.charge(&slow(), 100_000, Some(first), Instant::now());
        shaper.charge(&slow(), 200_000, Some(second), Instant::now());
        tokio::spawn(shaper.clone().flush(registry.clone()));
        tokio::time::sleep(Duration::from_millis(900)).await;
        let mut by_peer = HashMap::new();
        while let Ok(item) = rx.get_mut(&1).unwrap().try_recv() {
            if let ForwardItem::Credit { peer, bytes } = item {
                *by_peer.entry(peer).or_insert(0u64) += u64::from(bytes);
            }
        }
        assert_eq!(
            by_peer.get(&node(5)),
            Some(&100_000),
            "the older record first"
        );
        assert!(
            by_peer.get(&node(6)).copied().unwrap_or(0) < 50_000,
            "the later record has not been paid yet: {by_peer:?}"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        let rest = credit_of(rx.get_mut(&1).unwrap());
        let got = by_peer.get(&node(6)).copied().unwrap_or(0) + rest;
        assert_eq!(got, 200_000, "the later record in full, once");
        assert_eq!(shaper.held(), 0);
    }

    /// Round T4, M3: the paid off bytes are shared equally among the senders that have CREDIT
    /// held, whatever order they are visited in, and a sender with less to pay hands its surplus
    /// to the others (max-min fairness).
    #[tokio::test(start_paused = true)]
    async fn the_paid_off_debt_is_split_equally_among_the_senders_with_credit_held() {
        let shaper = Shaper::new(&slow(), Instant::now());
        let mut inner = shaper.lock();
        for n in 1..=3 {
            inner.push((node(n), node(9), 1), 1_000_000);
        }
        inner.tokens = -1.0;
        inner.pool = 90_000.0;
        let mut by_sender: HashMap<NodeId, u64> = HashMap::new();
        for ((src, _, _), bytes) in inner.distribute() {
            *by_sender.entry(src).or_default() += u64::from(bytes);
        }
        for n in 1..=3 {
            // 30,000 each, less than a whole record: granted in whole bytes, a little may stay
            // unreleased as a fraction.
            let got = by_sender.get(&node(n)).copied().unwrap_or(0);
            assert!((29_999..=30_000).contains(&got), "sender {n} got {got}");
        }
        // A sender needing less than its share gives the rest to the others.
        drop(inner);
        let other = Shaper::new(&slow(), Instant::now());
        let mut guard = other.lock();
        guard.push((node(1), node(9), 1), 10_000);
        guard.push((node(2), node(9), 1), 1_000_000);
        guard.tokens = -1.0;
        guard.pool = 100_000.0;
        let mut by_sender: HashMap<NodeId, u64> = HashMap::new();
        for ((src, _, _), bytes) in guard.distribute() {
            *by_sender.entry(src).or_default() += u64::from(bytes);
        }
        assert_eq!(by_sender.get(&node(1)), Some(&10_000));
        let second = by_sender.get(&node(2)).copied().unwrap_or(0);
        assert!((89_999..=90_000).contains(&second), "{second}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_floor_applies_once_the_volume_is_used_up_and_ends_with_the_period() {
        let shaper = Shaper::new(&slow(), Instant::now());
        shaper.add_volume(1 << 30);
        // At the floor the burst is one second of the floor rate.
        shaper.charge(&slow(), 125_000, None, Instant::now());
        assert!(shaper.lock().tokens < 1.0);
        let mut inner = shaper.lock();
        inner.refill(Instant::now() + Duration::from_secs(100));
        assert!(
            inner.tokens <= 125_000.0,
            "the floor's burst is one second of the floor rate, not the tenant's 1 MiB"
        );
        // The period ends: the volume counter starts again and the burst is back.
        inner.refill(Instant::now() + Duration::from_secs(30 * 86_400 + 1));
        assert_eq!(inner.period_bytes, 0);
        inner.refill(Instant::now() + Duration::from_secs(30 * 86_400 + 100));
        assert!(inner.tokens > 125_000.0 && inner.tokens <= 1_048_576.0);
    }
}
