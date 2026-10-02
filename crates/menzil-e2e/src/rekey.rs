//! REKEY timing (protocol.md 5.2: "every 2^20 records or every hour a
//! sender emits REKEY (class 0) and applies Noise `Rekey()` to its
//! sending state; the receiver applies it on receipt").
//!
//! Pure, timer-free, matching `menzil_session::RekeySchedule`'s style —
//! extended with a record-count trigger L3's own hourly-only schedule
//! never needed. This only tracks *when to send* the next REKEY record
//! and rekey this side's own sending cipher
//! ([`crate::E2eTransport::rekey_outgoing`]). Rekeying the receiving
//! cipher ([`crate::E2eTransport::rekey_incoming`]) has no schedule of
//! its own — it happens whenever a REKEY record arrives, which this type
//! has no opinion about.
//!
//! protocol.md does not say whether the 2^20-record counter counts one
//! class or both; this counts every data record this side sends through
//! [`crate::E2eTransport::encrypt_data`] regardless of class, since
//! REKEY's `Rekey()` call rekeys the one sending cipher both classes
//! share (protocol.md 5.2's counter split selects a nonce, not a
//! separate cipher) — there is one sending state to exhaust, not two.

use std::time::{Duration, Instant};

const REKEY_INTERVAL: Duration = Duration::from_secs(3600);
const REKEY_RECORD_LIMIT: u64 = 1 << 20;

/// Tracks when this side last rekeyed its own sending state, by both
/// elapsed time and records sent since.
#[derive(Debug, Clone)]
pub struct RekeySchedule {
    last_rekeyed: Instant,
    records_sent: u64,
}

impl RekeySchedule {
    /// Starts counting from `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            last_rekeyed: now,
            records_sent: 0,
        }
    }

    /// Call after successfully sending any data record (any kind, any
    /// class) through the transport this schedule watches.
    pub fn note_sent(&mut self) {
        self.records_sent = self.records_sent.saturating_add(1);
    }

    /// Whether an hour has passed, or 2^20 records have been sent, since
    /// this side last rekeyed: time to send a REKEY record and call
    /// [`crate::E2eTransport::rekey_outgoing`].
    pub fn due(&self, now: Instant) -> bool {
        self.records_sent >= REKEY_RECORD_LIMIT
            || now.saturating_duration_since(self.last_rekeyed) >= REKEY_INTERVAL
    }

    /// Call after sending a REKEY record and rekeying the sending
    /// cipher, to restart both countdowns.
    pub fn note_rekeyed(&mut self, now: Instant) {
        self.last_rekeyed = now;
        self.records_sent = 0;
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
    fn due_after_the_record_limit_regardless_of_time() {
        let start = Instant::now();
        let mut schedule = RekeySchedule::new(start);
        for _ in 0..REKEY_RECORD_LIMIT {
            assert!(!schedule.due(start));
            schedule.note_sent();
        }
        assert!(schedule.due(start));
    }

    #[test]
    fn note_rekeyed_restarts_both_countdowns() {
        let start = Instant::now();
        let mut schedule = RekeySchedule::new(start);
        for _ in 0..REKEY_RECORD_LIMIT {
            schedule.note_sent();
        }
        let at_one_hour = start + REKEY_INTERVAL;
        schedule.note_rekeyed(at_one_hour);
        assert!(!schedule.due(at_one_hour));
        let just_after = at_one_hour + Duration::from_secs(1);
        assert!(!schedule.due(just_after));
    }
}
