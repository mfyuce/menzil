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
//! | Completed DOC transfers per session | 6 per minute, burst 3 or the number of networks the session claimed, whichever is more (at most 32) |
//! | Base Rosters per session | the same, in a bucket of their own |
//! | Transfers the relay cannot use (invalid, forged, undecodable, for an unclaimed or unserved network, over the rate and not a claimed network's) | the 3rd within a minute ends the session |
//! | Transfers over the rate for a claimed, served network | the 30th within a minute ends the session |
//!
//! They are [`SessionRates`], settable once per relay (`Relay::with_session_rates`) so a test
//! or an operator can change them without touching the code. The state lives in the session's
//! own task ([`SessionBudget`]), so nothing here takes a lock and a session can only exhaust
//! its own allowance.
//!
//! An honest node pushes a base Roster and then the Roster for every claimed network it holds
//! newer than the relay (steward signed ones travel as a pair), once, right after ATTACH. That
//! is up to two transfers per claimed network at once, so the burst follows the number of
//! claimed networks (round T3, M1) and a base is charged to a bucket of its own, never to the
//! one a Roster needs. A transfer that is stale, or that is over the rate but is a genuine
//! Roster of a claimed network, is the node's honest doing (an old copy, a busy minute) and
//! does not count towards the ending rule above, only towards a larger one that keeps the
//! decoding it costs bounded.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

/// ADVERTISE records one session may send per minute, once its burst is spent.
pub const ADVERTISE_PER_MINUTE: u32 = 10;
/// ADVERTISE records a fresh session may send back to back.
pub const ADVERTISE_BURST: u32 = 3;
/// Completed DOC transfers one session may send per minute, once its burst is spent.
pub const DOC_TRANSFERS_PER_MINUTE: u32 = 6;
/// Completed DOC transfers a fresh session may send back to back, at least; a session that
/// claimed more networks gets one per claimed network, up to [`MAX_DOC_BURST`].
pub const DOC_BURST: u32 = 3;
/// The most a session's DOC burst grows to with the networks it claimed (a HELLO claims at most
/// 32).
pub const MAX_DOC_BURST: u32 = 32;
/// Transfers the relay could not use within [`UNADOPTED_WINDOW`] that end the session (the last
/// one does).
pub const UNADOPTED_DOCS_TO_END: u32 = 3;
/// Transfers over the rate, for a claimed and served network, within [`UNADOPTED_WINDOW`] that
/// end the session (the last one does).
pub const OVER_RATE_DOCS_TO_END: u32 = 30;
/// The window over which [`SessionRates::unadopted_docs_to_end`] and
/// [`SessionRates::over_rate_docs_to_end`] count.
pub const UNADOPTED_WINDOW: Duration = Duration::from_secs(60);

/// The per session limits a relay applies. [`Default`] is the figures above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRates {
    /// ADVERTISE records per minute once the burst is spent; the next one is answered
    /// ERROR `rate_limited` and otherwise ignored (the node's claims stay as they were).
    pub advertise_per_minute: u32,
    /// ADVERTISE records a session may send back to back.
    pub advertise_burst: u32,
    /// Completed DOC transfers per minute once the burst is spent (Rosters and base Rosters
    /// each have a bucket of this rate); a transfer over it is not verified and not adopted.
    pub doc_transfers_per_minute: u32,
    /// Completed DOC transfers a session may send back to back, at least: a session that claimed
    /// more networks than this gets one per claimed network (at most [`MAX_DOC_BURST`]).
    pub doc_burst: u32,
    /// How many transfers the relay could not use (invalid, undecodable, for a network the
    /// session did not claim or the relay does not serve, or over the rate and not a genuine
    /// Roster of a claimed network) within a minute end the session with ERROR and GOAWAY
    /// `rate_limited`. Zero never ends one. A stale transfer of a claimed network is not one.
    pub unadopted_docs_to_end: u32,
    /// How many transfers over the rate that are Rosters of a claimed, served network within a
    /// minute end the session the same way. They are the honest node's excess, so the figure is
    /// far above [`Self::unadopted_docs_to_end`]; it exists because deciding that a transfer is
    /// such a Roster costs a decode, which must stay bounded. Zero never ends one.
    pub over_rate_docs_to_end: u32,
}

impl Default for SessionRates {
    fn default() -> Self {
        Self {
            advertise_per_minute: ADVERTISE_PER_MINUTE,
            advertise_burst: ADVERTISE_BURST,
            doc_transfers_per_minute: DOC_TRANSFERS_PER_MINUTE,
            doc_burst: DOC_BURST,
            unadopted_docs_to_end: UNADOPTED_DOCS_TO_END,
            over_rate_docs_to_end: OVER_RATE_DOCS_TO_END,
        }
    }
}

/// Microseconds in a minute: one token costs this many "token microseconds per minute", so a
/// bucket refilling `per_minute` tokens a minute gains exactly `per_minute` units per elapsed
/// microsecond and no remainder is ever lost to rounding.
const UNITS_PER_TOKEN: u128 = 60_000_000;

/// The same for a bucket that refills a number of tokens an hour.
const UNITS_PER_TOKEN_HOURLY: u128 = 3_600_000_000;

/// A token bucket in integer units, on tokio's clock (so tests under `start_paused` are
/// exact). Starts full.
#[derive(Debug)]
pub(crate) struct TokenBucket {
    units: u128,
    cap: u128,
    /// Tokens gained per period (a minute, or an hour for [`Self::per_hour`]).
    per_period: u128,
    /// Units one token costs: the period in microseconds.
    token: u128,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket of `burst` tokens that refills `per_minute` tokens a minute.
    pub(crate) fn new(per_minute: u32, burst: u32) -> Self {
        Self::with_token(per_minute, burst, UNITS_PER_TOKEN)
    }

    /// A full bucket of `burst` tokens that refills `per_hour` tokens an hour (a rate below one
    /// a minute, like a tenant's Roster adoptions).
    pub(crate) fn per_hour(per_hour: u32, burst: u32) -> Self {
        Self::with_token(per_hour, burst, UNITS_PER_TOKEN_HOURLY)
    }

    fn with_token(per_period: u32, burst: u32, token: u128) -> Self {
        let cap = u128::from(burst) * token;
        Self {
            units: cap,
            cap,
            per_period: u128::from(per_period),
            token,
            last: Instant::now(),
        }
    }

    /// Takes one token if there is one.
    pub(crate) fn try_take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_micros();
        self.last = now;
        self.units = (self.units + elapsed * self.per_period).min(self.cap);
        if self.units >= self.token {
            self.units -= self.token;
            true
        } else {
            false
        }
    }
}

/// The allowances for completed DOC transfers: one bucket for Rosters, one for the base Rosters
/// that travel ahead of a steward signed one, so that a pair costs one token of each and a base
/// never uses up the token its Roster needs (round T3, M1).
#[derive(Debug)]
pub(crate) struct DocBuckets {
    pub(crate) rosters: TokenBucket,
    pub(crate) bases: TokenBucket,
}

impl DocBuckets {
    /// The buckets of a session that claimed `claimed` networks: a burst of
    /// [`SessionRates::doc_burst`], or one per claimed network if that is more, never above
    /// [`MAX_DOC_BURST`] (nor below the configured burst).
    pub(crate) fn new(rates: &SessionRates, claimed: usize) -> Self {
        let from_claims = u32::try_from(claimed.min(MAX_DOC_BURST as usize)).unwrap_or(0);
        let burst = rates.doc_burst.max(from_claims);
        Self {
            rosters: TokenBucket::new(rates.doc_transfers_per_minute, burst),
            bases: TokenBucket::new(rates.doc_transfers_per_minute, burst),
        }
    }

    /// Allowances these tests never run out of; `crate::rate` has its own.
    #[cfg(test)]
    pub(crate) fn unlimited() -> Self {
        Self {
            rosters: TokenBucket::new(60_000, 1_000),
            bases: TokenBucket::new(60_000, 1_000),
        }
    }
}

/// Events within [`UNADOPTED_WINDOW`], counted to a limit.
#[derive(Debug)]
struct Window {
    times: VecDeque<Instant>,
    to_end: u32,
}

impl Window {
    fn new(to_end: u32) -> Self {
        Self {
            times: VecDeque::new(),
            to_end,
        }
    }

    /// Records one event; true when `to_end` of them are now within the window. Zero never.
    fn note(&mut self) -> bool {
        if self.to_end == 0 {
            return false;
        }
        let now = Instant::now();
        while self
            .times
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= UNADOPTED_WINDOW)
        {
            self.times.pop_front();
        }
        self.times.push_back(now);
        self.times.len() >= self.to_end as usize
    }
}

/// What one session may still do: owned by the session task, so no lock and no sharing.
#[derive(Debug)]
pub(crate) struct SessionBudget {
    pub(crate) advertise: TokenBucket,
    pub(crate) docs: DocBuckets,
    unadopted: Window,
    over_rate: Window,
}

impl SessionBudget {
    /// The allowances of a session that claimed `claimed` networks.
    pub(crate) fn new(rates: &SessionRates, claimed: usize) -> Self {
        Self {
            advertise: TokenBucket::new(rates.advertise_per_minute, rates.advertise_burst),
            docs: DocBuckets::new(rates, claimed),
            unadopted: Window::new(rates.unadopted_docs_to_end),
            over_rate: Window::new(rates.over_rate_docs_to_end),
        }
    }

    /// Records one transfer the relay could not use; true when the session has now sent
    /// [`SessionRates::unadopted_docs_to_end`] of them within [`UNADOPTED_WINDOW`] and is to be
    /// ended.
    pub(crate) fn note_unadopted(&mut self) -> bool {
        self.unadopted.note()
    }

    /// Records one transfer over the rate that is a Roster of a claimed, served network; true
    /// when the session has now sent [`SessionRates::over_rate_docs_to_end`] of them within
    /// [`UNADOPTED_WINDOW`] and is to be ended.
    pub(crate) fn note_over_rate(&mut self) -> bool {
        self.over_rate.note()
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
    async fn an_hourly_bucket_gives_its_burst_then_one_token_per_hour_share() {
        let mut bucket = TokenBucket::per_hour(20, 5);
        for _ in 0..5 {
            assert!(bucket.try_take());
        }
        assert!(
            !bucket.try_take(),
            "the sixth back to back is over the burst"
        );
        // 20 an hour is one token per 180 s.
        tokio::time::advance(Duration::from_secs(179)).await;
        assert!(!bucket.try_take());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(bucket.try_take());
        assert!(!bucket.try_take());
        tokio::time::advance(Duration::from_secs(10 * 3_600)).await;
        for _ in 0..5 {
            assert!(bucket.try_take());
        }
        assert!(
            !bucket.try_take(),
            "a long wait refills to the burst, no further"
        );
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
        let mut budget = SessionBudget::new(&SessionRates::default(), 1);
        assert!(!budget.note_unadopted());
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(!budget.note_unadopted());
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(budget.note_unadopted(), "three within 59 s");
    }

    #[tokio::test(start_paused = true)]
    async fn unadopted_transfers_spread_over_more_than_a_minute_never_end_it() {
        let mut budget = SessionBudget::new(&SessionRates::default(), 1);
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
        let mut budget = SessionBudget::new(&rates, 1);
        for _ in 0..10 {
            assert!(!budget.note_unadopted());
        }
    }

    /// Round T3, M1: the DOC burst is the configured one or the number of claimed networks, if
    /// that is more, but never more than [`MAX_DOC_BURST`]; Rosters and bases have a bucket each.
    #[tokio::test(start_paused = true)]
    async fn the_doc_burst_follows_the_claimed_networks_up_to_a_cap() {
        fn takes(bucket: &mut TokenBucket) -> u32 {
            let mut n = 0;
            while bucket.try_take() {
                n += 1;
                assert!(n < 1_000);
            }
            n
        }
        let rates = SessionRates::default();
        assert_eq!(takes(&mut DocBuckets::new(&rates, 0).rosters), 3);
        assert_eq!(takes(&mut DocBuckets::new(&rates, 1).rosters), 3);
        assert_eq!(takes(&mut DocBuckets::new(&rates, 3).rosters), 3);
        assert_eq!(takes(&mut DocBuckets::new(&rates, 4).rosters), 4);
        assert_eq!(takes(&mut DocBuckets::new(&rates, 20).rosters), 20);
        assert_eq!(
            takes(&mut DocBuckets::new(&rates, 100).rosters),
            MAX_DOC_BURST
        );
        let mut buckets = DocBuckets::new(&rates, 5);
        assert_eq!(takes(&mut buckets.rosters), 5);
        assert_eq!(takes(&mut buckets.bases), 5, "a bucket of their own");
        // A configured burst above the cap is the operator's choice and is kept.
        let big = SessionRates {
            doc_burst: 50,
            ..SessionRates::default()
        };
        assert_eq!(takes(&mut DocBuckets::new(&big, 2).rosters), 50);
    }

    #[tokio::test(start_paused = true)]
    async fn over_rate_transfers_are_counted_apart_from_unusable_ones() {
        let rates = SessionRates {
            over_rate_docs_to_end: 4,
            ..SessionRates::default()
        };
        let mut budget = SessionBudget::new(&rates, 1);
        for _ in 0..3 {
            assert!(!budget.note_over_rate());
        }
        assert!(
            !budget.note_unadopted(),
            "the unusable count is separate: this is its first"
        );
        assert!(budget.note_over_rate(), "the fourth within a minute");
        let mut never = SessionBudget::new(
            &SessionRates {
                over_rate_docs_to_end: 0,
                ..SessionRates::default()
            },
            1,
        );
        for _ in 0..50 {
            assert!(!never.note_over_rate());
        }
    }
}
