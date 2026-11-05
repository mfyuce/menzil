//! A tenant's bandwidth bucket, volume counter and delayed CREDIT (multi tenant design 2.3 and
//! 2.4, slice MT8; threat A8).
//!
//! The relay never drops a tenant's reliable data to enforce bandwidth, and it never refuses
//! it: it makes the sender wait. A reliable SEND is paid for with the sender's credit
//! (protocol.md 4.2), and the credit comes back as a CREDIT record once the relay has handed the
//! RECV to the destination's connection (`crate::forward::ForwardTable::drained`). A tenant that
//! is over its bandwidth gets that CREDIT *later*: [`Shaper::charge`] takes the bytes out of the
//! tenant's bucket (which may go into debt), and while the bucket is in debt the CREDIT of the
//! tenant's senders is held back and handed out by one timer task per tenant
//! (`flush`), when the debt has been paid off by time. So the sender's rate converges on the
//! bucket's rate, nothing is lost (every byte charged is granted back, once, in the order it was
//! consumed), and a sender never sees anything but a slower transfer.
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

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use menzil_proto::NodeId;
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
    /// CREDIT owed and not yet released.
    pending: HashMap<CreditKey, u32>,
    /// Whether a timer task is running for `pending`.
    flusher: bool,
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
        self.tokens = (self.tokens + elapsed * rate).min(cap);
        self.last = now;
        self.rate = rate;
    }

    /// How long until the debt is paid, if there is one.
    fn wait(&self) -> Option<Duration> {
        if self.tokens >= 0.0 {
            return None;
        }
        let seconds = -self.tokens / self.rate.max(1.0);
        // A millisecond at least, so the timer never spins on a debt of a few bytes.
        Some(Duration::from_secs_f64(seconds.min(86_400.0)).max(Duration::from_millis(1)))
    }
}

/// One tenant's bucket and counter. Cheap to clone: the timer task holds a clone.
#[derive(Clone)]
pub(crate) struct Shaper {
    inner: Arc<Mutex<Inner>>,
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
                pending: HashMap::new(),
                flusher: false,
            })),
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
        if inner.tokens >= 0.0 && inner.pending.is_empty() {
            return Credit::Now;
        }
        let owed = inner.pending.entry(key).or_insert(0);
        *owed = owed.saturating_add(bytes);
        let start_timer = !inner.flusher;
        inner.flusher = true;
        Credit::Held { start_timer }
    }

    /// Runs until nothing is held: waits for the debt to be paid, then hands out everything held
    /// (to the senders that are still the same session) and looks again. Spawned once per burst
    /// of debt by whoever got `start_timer`.
    pub(crate) async fn flush(self, registry: SessionRegistry) {
        loop {
            let wait = {
                let mut inner = self.lock();
                inner.refill(Instant::now());
                match inner.wait() {
                    Some(wait) => Some(wait),
                    None if inner.pending.is_empty() => {
                        inner.flusher = false;
                        return;
                    }
                    None => None,
                }
            };
            if let Some(wait) = wait {
                tokio::time::sleep(wait).await;
                continue;
            }
            let due = std::mem::take(&mut self.lock().pending);
            grant(&registry, due);
        }
    }

    /// Hands out everything held now, whatever the bucket says (no timer can run: the caller is
    /// not inside a runtime). Delay never becomes loss.
    pub(crate) fn release_all(&self, registry: &SessionRegistry) {
        let due = {
            let mut inner = self.lock();
            inner.flusher = false;
            std::mem::take(&mut inner.pending)
        };
        grant(registry, due);
    }

    /// The bytes charged in the current volume period (tests, and the operator's status).
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
        self.lock().pending.values().map(|&b| u64::from(b)).sum()
    }
}

/// Sends the CREDIT records in `due`, except to a sender that has reconnected since (its new
/// session has a ledger of its own and is owed nothing for the old one).
fn grant(registry: &SessionRegistry, due: HashMap<CreditKey, u32>) {
    for ((src, dst, session_id), bytes) in due {
        if registry.is_current(&src, session_id) {
            registry.deliver(&src, ForwardItem::Credit { peer: dst, bytes });
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
            shaper.lock().wait(),
            Some(Duration::from_secs(1)),
            "a debt of one second of the rate"
        );
        // Another charge while held joins the timer that is running.
        assert_eq!(
            shaper.charge(&slow(), 10, Some(key), Instant::now()),
            Credit::Held { start_timer: false }
        );
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
