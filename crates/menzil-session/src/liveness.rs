//! PING/PONG liveness (protocol.md 3.3): "a link is dead when no
//! authenticated record has arrived for two ping intervals (interval
//! 25 s, so 50 s)."
//!
//! Pure, timer-free: callers drive their own clock (e.g.
//! `tokio::time::interval`) and pass in `now`, matching
//! `menzil_carrier::Backoff`'s style.

use std::time::{Duration, Instant};

const PING_INTERVAL: Duration = Duration::from_secs(25);
const DEAD_AFTER: Duration = Duration::from_secs(50);

/// Tracks time since the last authenticated record arrived. protocol.md
/// 3.3 measures inbound activity only ("no authenticated record has
/// arrived"), not traffic in either direction, so [`Liveness::note_activity`]
/// should be called on every successful decrypt, never on send.
#[derive(Debug, Clone)]
pub struct Liveness {
    last_activity: Instant,
}

impl Liveness {
    /// Starts counting from `now`.
    pub fn new(now: Instant) -> Self {
        Self { last_activity: now }
    }

    /// Call whenever any record is successfully authenticated and
    /// decrypted — not just PONG; protocol.md 3.3 says "no authenticated
    /// record", not "no PONG", so every successful
    /// [`crate::Transport::decrypt_record`] should drive this, and
    /// nothing else needs to.
    pub fn note_activity(&mut self, now: Instant) {
        self.last_activity = now;
    }

    /// Whether at least one ping interval (25 s) has passed since the
    /// last authenticated record: time to send a PING.
    pub fn should_ping(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= PING_INTERVAL
    }

    /// Whether at least two ping intervals (50 s) have passed: the link
    /// is dead.
    pub fn is_dead(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_activity) >= DEAD_AFTER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_liveness_neither_pings_nor_is_dead() {
        let now = Instant::now();
        let liveness = Liveness::new(now);
        assert!(!liveness.should_ping(now));
        assert!(!liveness.is_dead(now));
    }

    #[test]
    fn should_ping_after_one_interval_but_not_dead_yet() {
        let start = Instant::now();
        let liveness = Liveness::new(start);
        let at_25s = start + PING_INTERVAL;
        assert!(liveness.should_ping(at_25s));
        assert!(!liveness.is_dead(at_25s));
    }

    #[test]
    fn dead_after_two_intervals() {
        let start = Instant::now();
        let liveness = Liveness::new(start);
        let at_50s = start + DEAD_AFTER;
        assert!(liveness.is_dead(at_50s));
    }

    #[test]
    fn activity_resets_the_clock() {
        let start = Instant::now();
        let mut liveness = Liveness::new(start);
        let at_40s = start + Duration::from_secs(40);
        liveness.note_activity(at_40s);
        // 45s absolute = only 5s since the reset at 40s: not due yet.
        let at_45s = start + Duration::from_secs(45);
        assert!(!liveness.should_ping(at_45s));
    }
}
