//! Per session rate limits for the records a node can repeat cheaply but the relay answers
//! expensively (multi tenant slice MT5; threat A13 of `multitenant-design.md`): ADVERTISE
//! (takes the relay wide label lock) and completed DOC transfers (a 1 MiB reassembly and, for
//! a Roster, signature checks).
//!
//! The figures are the design's global safety limits table:
//!
//! | Item | Figure |
//! |---|---|
//! | ADVERTISE per session | 10 per minute, burst 3 |
//! | Completed DOC transfers per session | 6 per minute, burst 3 |
//! | Transfers not adopted (stale, invalid, unclaimed, over the rate) | the 3rd within a minute ends the session |
//!
//! They are [`SessionRates`], settable once per relay (`Relay::with_session_rates`) so a test
//! or an operator can change them without touching the code. The state lives in the session's
//! own task ([`SessionBudget`]), so nothing here takes a lock and a session can only exhaust
//! its own allowance.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

/// ADVERTISE records one session may send per minute, once its burst is spent.
pub const ADVERTISE_PER_MINUTE: u32 = 10;
/// ADVERTISE records a fresh session may send back to back.
pub const ADVERTISE_BURST: u32 = 3;
/// Completed DOC transfers one session may send per minute, once its burst is spent.
pub const DOC_TRANSFERS_PER_MINUTE: u32 = 6;
/// Completed DOC transfers a fresh session may send back to back.
pub const DOC_BURST: u32 = 3;
/// Transfers not adopted within [`UNADOPTED_WINDOW`] that end the session (the last one does).
pub const UNADOPTED_DOCS_TO_END: u32 = 3;
/// The window over which [`SessionRates::unadopted_docs_to_end`] counts.
pub const UNADOPTED_WINDOW: Duration = Duration::from_secs(60);

/// The per session limits a relay applies. [`Default`] is the figures above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRates {
    /// ADVERTISE records per minute once the burst is spent; the next one is answered
    /// ERROR `rate_limited` and otherwise ignored (the node's claims stay as they were).
    pub advertise_per_minute: u32,
    /// ADVERTISE records a session may send back to back.
    pub advertise_burst: u32,
    /// Completed DOC transfers per minute once the burst is spent; a transfer over it is
    /// dropped without being decoded or verified, and counts as not adopted.
    pub doc_transfers_per_minute: u32,
    /// Completed DOC transfers a session may send back to back.
    pub doc_burst: u32,
    /// How many transfers that are not adopted (stale, invalid, for a network the session did
    /// not claim, over the rate) within a minute end the session with ERROR and GOAWAY
    /// `rate_limited`. Zero never ends one.
    pub unadopted_docs_to_end: u32,
}

impl Default for SessionRates {
    fn default() -> Self {
        Self {
            advertise_per_minute: ADVERTISE_PER_MINUTE,
            advertise_burst: ADVERTISE_BURST,
            doc_transfers_per_minute: DOC_TRANSFERS_PER_MINUTE,
            doc_burst: DOC_BURST,
            unadopted_docs_to_end: UNADOPTED_DOCS_TO_END,
        }
    }
}

/// Microseconds in a minute: one token costs this many "token microseconds per minute", so a
/// bucket refilling `per_minute` tokens a minute gains exactly `per_minute` units per elapsed
/// microsecond and no remainder is ever lost to rounding.
const UNITS_PER_TOKEN: u128 = 60_000_000;

/// A token bucket in integer units, on tokio's clock (so tests under `start_paused` are
/// exact). Starts full.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    units: u128,
    cap: u128,
    per_minute: u128,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket of `burst` tokens that refills `per_minute` tokens a minute.
    pub(crate) fn new(per_minute: u32, burst: u32) -> Self {
        let cap = u128::from(burst) * UNITS_PER_TOKEN;
        Self {
            units: cap,
            cap,
            per_minute: u128::from(per_minute),
            last: Instant::now(),
        }
    }

    /// Takes one token if there is one.
    pub(crate) fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_micros();
        self.last = now;
        self.units = (self.units + elapsed * self.per_minute).min(self.cap);
        if self.units >= UNITS_PER_TOKEN {
            self.units -= UNITS_PER_TOKEN;
            true
        } else {
            false
        }
    }
}

/// What one session may still do: owned by the session task, so no lock and no sharing.
#[derive(Debug)]
pub(crate) struct SessionBudget {
    pub(crate) advertise: TokenBucket,
    pub(crate) docs: TokenBucket,
    unadopted: VecDeque<Instant>,
    to_end: u32,
}

impl SessionBudget {
    pub(crate) fn new(rates: &SessionRates) -> Self {
        Self {
            advertise: TokenBucket::new(rates.advertise_per_minute, rates.advertise_burst),
            docs: TokenBucket::new(rates.doc_transfers_per_minute, rates.doc_burst),
            unadopted: VecDeque::new(),
            to_end: rates.unadopted_docs_to_end,
        }
    }

    /// Records one transfer that was not adopted; true when the session has now sent
    /// [`SessionRates::unadopted_docs_to_end`] of them within [`UNADOPTED_WINDOW`] and is to be
    /// ended.
    pub(crate) fn note_unadopted(&mut self) -> bool {
        if self.to_end == 0 {
            return false;
        }
        let now = Instant::now();
        while self
            .unadopted
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= UNADOPTED_WINDOW)
        {
            self.unadopted.pop_front();
        }
        self.unadopted.push_back(now);
        self.unadopted.len() >= self.to_end as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_bucket_gives_its_burst_then_one_token_per_refill_interval() {
        let mut bucket = TokenBucket::new(10, 3);
        assert!(bucket.try_take() && bucket.try_take() && bucket.try_take());
        assert!(
            !bucket.try_take(),
            "the fourth back to back is over the burst"
        );
        tokio::time::advance(Duration::from_millis(5_900)).await;
        assert!(!bucket.try_take(), "10 a minute is one token per 6 s");
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
    }

    #[tokio::test(start_paused = true)]
    async fn polling_often_does_not_lose_the_fraction_of_a_token() {
        let mut bucket = TokenBucket::new(10, 1);
        assert!(bucket.try_take());
        for _ in 0..59 {
            tokio::time::advance(Duration::from_millis(100)).await;
            assert!(!bucket.try_take());
        }
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(
            bucket.try_take(),
            "60 polls of 100 ms add up to the 6 s a token takes"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_long_wait_refills_to_the_burst_and_no_further() {
        let mut bucket = TokenBucket::new(10, 3);
        for _ in 0..3 {
            assert!(bucket.try_take());
        }
        tokio::time::advance(Duration::from_secs(3_600)).await;
        assert!(bucket.try_take() && bucket.try_take() && bucket.try_take());
        assert!(!bucket.try_take());
    }

    #[tokio::test(start_paused = true)]
    async fn the_third_unadopted_transfer_within_a_minute_ends_the_session() {
        let mut budget = SessionBudget::new(&SessionRates::default());
        assert!(!budget.note_unadopted());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!budget.note_unadopted());
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(budget.note_unadopted(), "three within 59 s");
    }

    #[tokio::test(start_paused = true)]
    async fn unadopted_transfers_spread_over_more_than_a_minute_never_end_it() {
        let mut budget = SessionBudget::new(&SessionRates::default());
        for _ in 0..20 {
            assert!(!budget.note_unadopted());
            tokio::time::advance(Duration::from_secs(31)).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn zero_unadopted_to_end_never_ends_a_session() {
        let rates = SessionRates {
            unadopted_docs_to_end: 0,
            ..SessionRates::default()
        };
        let mut budget = SessionBudget::new(&rates);
        for _ in 0..10 {
            assert!(!budget.note_unadopted());
        }
    }
}
