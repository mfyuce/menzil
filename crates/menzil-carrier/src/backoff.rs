//! Reconnect backoff (protocol.md 3.3): exponential 1 s to 60 s with full
//! jitter, reset to the floor after a connection has stayed up over 60 s;
//! a `retry_after_ms` hint (e.g. a future GOAWAY record) overrides the
//! schedule for one delay, spread the same way.
//!
//! Pure delay computation, no sleeping: callers drive their own timer
//! (e.g. `tokio::time::sleep`) with the returned [`std::time::Duration`].

use std::time::Duration;

const FLOOR: Duration = Duration::from_secs(1);
const CEILING: Duration = Duration::from_secs(60);
const RESET_AFTER_UPTIME: Duration = Duration::from_secs(60);

/// The reconnect backoff schedule's state: just an attempt counter and a
/// jitter source.
#[derive(Debug, Clone)]
pub struct Backoff {
    attempt: u32,
    rng: fastrand::Rng,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            attempt: 0,
            rng: fastrand::Rng::new(),
        }
    }
}

impl Backoff {
    /// A fresh schedule, starting at the floor.
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets the schedule to the floor once a connection has stayed up
    /// at least [`RESET_AFTER_UPTIME`]; shorter uptimes leave the current
    /// attempt count (and thus the growing delay) untouched.
    pub fn note_connection_uptime(&mut self, uptime: Duration) {
        if uptime >= RESET_AFTER_UPTIME {
            self.attempt = 0;
        }
    }

    /// The delay before the next reconnect attempt: `2^attempt` seconds
    /// capped at 60 s, with full jitter (uniform in `[0, delay]`), and
    /// advances the schedule.
    pub fn next_delay(&mut self) -> Duration {
        let factor = 1u32.checked_shl(self.attempt).unwrap_or(u32::MAX);
        let exponential = FLOOR.saturating_mul(factor).min(CEILING);
        self.attempt = self.attempt.saturating_add(1);
        self.jitter(exponential)
    }

    /// Overrides the schedule for one delay with an explicit
    /// `retry_after_ms` hint (protocol.md 3.3: "`retry_after_ms` from
    /// GOAWAY is honored and spread"), applying the same full jitter.
    /// Does not itself consume or otherwise interpret a GOAWAY record;
    /// that belongs to the L3 layer, which has one.
    pub fn next_delay_with_hint(&mut self, retry_after_ms: u32) -> Duration {
        self.jitter(Duration::from_millis(u64::from(retry_after_ms)))
    }

    fn jitter(&mut self, max: Duration) -> Duration {
        if max.is_zero() {
            return max;
        }
        let millis = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(self.rng.u64(0..=millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_delay_is_bounded_by_the_floor() {
        for _ in 0..200 {
            let mut b = Backoff::new();
            assert!(b.next_delay() <= FLOOR);
        }
    }

    #[test]
    fn delay_grows_and_caps_at_the_ceiling() {
        let mut b = Backoff::new();
        let mut max_seen = Duration::ZERO;
        for _ in 0..20 {
            let d = b.next_delay();
            assert!(d <= CEILING);
            max_seen = max_seen.max(d);
        }
        // With 20 attempts the exponential schedule must have reached the
        // ceiling's neighborhood at least once (allow jitter to land low).
        assert!(max_seen > Duration::from_secs(30));
    }

    #[test]
    fn uptime_under_threshold_does_not_reset() {
        let mut b = Backoff::new();
        for _ in 0..10 {
            b.next_delay();
        }
        let attempt_before = b.attempt;
        b.note_connection_uptime(Duration::from_secs(59));
        assert_eq!(b.attempt, attempt_before);
    }

    #[test]
    fn uptime_at_threshold_resets_to_floor() {
        let mut b = Backoff::new();
        for _ in 0..10 {
            b.next_delay();
        }
        b.note_connection_uptime(Duration::from_secs(60));
        assert_eq!(b.attempt, 0);
        assert!(b.next_delay() <= FLOOR);
    }

    #[test]
    fn hint_overrides_with_jitter_up_to_the_hint() {
        let mut b = Backoff::new();
        for _ in 0..200 {
            let d = b.next_delay_with_hint(5_000);
            assert!(d <= Duration::from_millis(5_000));
        }
    }

    #[test]
    fn zero_hint_yields_zero_delay() {
        let mut b = Backoff::new();
        assert_eq!(b.next_delay_with_hint(0), Duration::ZERO);
    }
}
