//! Hourly REKEY timing (protocol.md 4.1: "Noise `Rekey()` runs in both
//! directions on REKEY every hour"; 4.2: "the sender rekeys its sending
//! state after this record, the receiver rekeys its receiving state on
//! receipt").
//!
//! Pure, timer-free, matching [`crate::Liveness`] and
//! `menzil_carrier::Backoff`'s style: this only tracks *when to send*
//! the next REKEY record and rekey this side's own sending cipher
//! (`[Transport::rekey_outgoing`](crate::Transport::rekey_outgoing)).
//! Rekeying the receiving cipher
//! (`[Transport::rekey_incoming`](crate::Transport::rekey_incoming)) has
//! no schedule of its own — it happens whenever a REKEY record arrives,
//! which this type has no opinion about.

use std::time::{Duration, Instant};

const REKEY_INTERVAL: Duration = Duration::from_secs(3600);

/// Tracks when this side last rekeyed its own sending state.
#[derive(Debug, Clone)]
pub struct RekeySchedule {
    last_rekeyed: Instant,
}

impl RekeySchedule {
    /// Starts counting from `now`.
    pub fn new(now: Instant) -> Self {
        Self { last_rekeyed: now }
    }

    /// Whether an hour has passed since this side last rekeyed its
    /// sending state: time to send a REKEY record and call
    /// [`crate::Transport::rekey_outgoing`].
    pub fn due(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_rekeyed) >= REKEY_INTERVAL
    }

    /// Call after sending a REKEY record and rekeying the sending
    /// cipher, to restart the hourly countdown.
    pub fn note_rekeyed(&mut self, now: Instant) {
        self.last_rekeyed = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_due_immediately() {
        let now = Instant::now();
        assert!(!RekeySchedule::new(now).due(now));
    }

    #[test]
    fn due_after_an_hour() {
        let start = Instant::now();
        let schedule = RekeySchedule::new(start);
        assert!(schedule.due(start + REKEY_INTERVAL));
    }

    #[test]
    fn note_rekeyed_restarts_the_countdown() {
        let start = Instant::now();
        let mut schedule = RekeySchedule::new(start);
        let at_one_hour = start + REKEY_INTERVAL;
        schedule.note_rekeyed(at_one_hour);
        let just_after = at_one_hour + Duration::from_secs(1);
        assert!(!schedule.due(just_after));
    }
}
