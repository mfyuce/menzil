//! When an L4 session is replaced by a fresh full handshake (protocol.md 5.2, slice R1 of the
//! re-handshake design `docs/private/rehandshake-design.md` section 3, "Who starts, and when").
//!
//! Sans-IO, like [`crate::RekeySchedule`]: a [`ReplaceSchedule`] owns no timer and no clock.
//! The caller passes a monotonic `Instant` to every method, so a test drives it with a fake
//! clock. It belongs to the *initiator* of a session (the side that sent the `init` of the
//! current session), measured from that side's own handshake completion (`start`).
//!
//! The figures, all overridable through [`ReplaceDurations`] for tests:
//!
//! - **due** at `24 h - jitter`, the jitter drawn once per session by the caller from
//!   `U(0, 30 min)` and passed in (so tests are deterministic and a node's many sessions
//!   spread out). A jitter above the maximum is clamped to it.
//! - one attempt waits for its `resp` at most the **pending timeout** (10 s);
//! - after a failed attempt, retry after **30 s, 60 s, 120 s, 240 s, then every 5 min**. The
//!   delay counts from the failure: for a timeout, from the moment the timeout ran out, not
//!   from when the caller happened to poll;
//! - **hard cap** `24 h + 30 min` from `start`: from that instant (inclusive) [`Poll::Expired`]
//!   is the answer, whatever an attempt in flight is doing. The caller ends the session with
//!   CLOSE `session_expired` (29). A session ends at the cap on both sides, so the initiator
//!   has between 30 and 60 minutes of retries.
//!
//! The schedule is about the initiator's replacement only. The responder has no schedule; it
//! only needs [`ReplaceSchedule::hard_cap_at`]-style bookkeeping of its own (the same cap), for
//! which it can build a schedule with jitter zero and read [`ReplaceSchedule::hard_cap_at`].

use std::time::{Duration, Instant};

/// The figures of a [`ReplaceSchedule`]. [`Default`] is the protocol's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceDurations {
    /// Age at which a replacement is due, before jitter. Default 24 h.
    pub lifetime: Duration,
    /// The largest jitter; a larger one passed in is clamped to it. Default 30 min.
    pub max_jitter: Duration,
    /// How long one `init` waits for its `resp`. Default 10 s.
    pub pending_timeout: Duration,
    /// Delays after the first, second, ... failed attempt. Default 30 s, 60 s, 120 s, 240 s.
    pub retry_delays: Vec<Duration>,
    /// Every delay after the list is used up. Default 5 min.
    pub steady_delay: Duration,
    /// Age at which the session must end whatever happens. Default 24 h 30 min.
    pub hard_cap: Duration,
}

impl Default for ReplaceDurations {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(24 * 3600),
            max_jitter: Duration::from_secs(30 * 60),
            pending_timeout: Duration::from_secs(10),
            retry_delays: [30, 60, 120, 240]
                .into_iter()
                .map(Duration::from_secs)
                .collect(),
            steady_delay: Duration::from_secs(5 * 60),
            hard_cap: Duration::from_secs(24 * 3600 + 30 * 60),
        }
    }
}

/// What [`ReplaceSchedule::poll`] says the caller should do now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// Nothing yet; look again at (or after) this instant. While an attempt is in flight this
    /// is its timeout.
    WaitUntil(Instant),
    /// Send an `init` now, then call [`ReplaceSchedule::begin_attempt`].
    Start,
    /// The hard cap is reached: end the session with `session_expired`.
    Expired,
    /// [`ReplaceSchedule::succeeded`] was called: nothing more to schedule.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// No attempt in flight; the next one may start at `.0`.
    Idle(Instant),
    /// An `init` is out since `.0`.
    InFlight(Instant),
    Done,
}

/// See the module docs.
#[derive(Debug, Clone)]
pub struct ReplaceSchedule {
    durations: ReplaceDurations,
    due_at: Instant,
    hard_cap_at: Instant,
    failures: usize,
    state: State,
}

impl ReplaceSchedule {
    /// A schedule for a session whose handshake completed at `start`, with the protocol's
    /// figures and the caller's `jitter` (drawn once per session from `U(0, 30 min)`).
    pub fn new(start: Instant, jitter: Duration) -> Self {
        Self::with_durations(start, jitter, ReplaceDurations::default())
    }

    /// As [`Self::new`] with other figures (tests).
    pub fn with_durations(start: Instant, jitter: Duration, durations: ReplaceDurations) -> Self {
        let jitter = jitter.min(durations.max_jitter);
        let due_at = start + durations.lifetime.saturating_sub(jitter);
        let hard_cap_at = start + durations.hard_cap;
        Self {
            durations,
            due_at,
            hard_cap_at,
            failures: 0,
            state: State::Idle(due_at),
        }
    }

    /// The instant the first attempt is due.
    pub fn due_at(&self) -> Instant {
        self.due_at
    }

    /// The instant the session must end.
    pub fn hard_cap_at(&self) -> Instant {
        self.hard_cap_at
    }

    /// How many attempts have failed so far.
    pub fn failures(&self) -> usize {
        self.failures
    }

    /// What to do at `now`. An attempt in flight whose timeout has run out is turned into a
    /// failure here (and its retry scheduled from the timeout instant), so a caller needs no
    /// separate timer for it beyond the instant [`Poll::WaitUntil`] names.
    pub fn poll(&mut self, now: Instant) -> Poll {
        if matches!(self.state, State::Done) {
            return Poll::Done;
        }
        if now >= self.hard_cap_at {
            return Poll::Expired;
        }
        if let State::InFlight(since) = self.state {
            let deadline = since + self.durations.pending_timeout;
            if now < deadline {
                return Poll::WaitUntil(deadline.min(self.hard_cap_at));
            }
            self.fail_at(deadline);
        }
        match self.state {
            State::Idle(at) if now >= at => Poll::Start,
            State::Idle(at) => Poll::WaitUntil(at.min(self.hard_cap_at)),
            State::InFlight(_) | State::Done => unreachable!("handled above"),
        }
    }

    /// The caller sent an `init` at `now`. Ignored when the schedule is done or an attempt is
    /// already in flight.
    pub fn begin_attempt(&mut self, now: Instant) {
        if matches!(self.state, State::Idle(_)) {
            self.state = State::InFlight(now);
        }
    }

    /// The attempt in flight failed at `now` (a refusal, a closed epoch): retry by the delay
    /// list. Does nothing when no attempt is in flight.
    pub fn attempt_failed(&mut self, now: Instant) {
        if matches!(self.state, State::InFlight(_)) {
            self.fail_at(now);
        }
    }

    /// The replacement took over (the new session has its own schedule).
    pub fn succeeded(&mut self) {
        self.state = State::Done;
    }

    fn fail_at(&mut self, at: Instant) {
        let delay = self
            .durations
            .retry_delays
            .get(self.failures)
            .copied()
            .unwrap_or(self.durations.steady_delay);
        self.failures += 1;
        self.state = State::Idle(at + delay);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn s(n: u64) -> Duration {
        Duration::from_secs(n)
    }
    const H24: Duration = s(24 * 3600);
    const MIN30: Duration = s(30 * 60);

    fn start() -> Instant {
        Instant::now()
    }

    #[test]
    fn due_window_is_24h_minus_jitter_inside_the_last_30_minutes() {
        let t0 = start();
        // No jitter: due at exactly 24 h.
        assert_eq!(ReplaceSchedule::new(t0, s(0)).due_at(), t0 + H24);
        // Full jitter: 23 h 30 min.
        assert_eq!(ReplaceSchedule::new(t0, MIN30).due_at(), t0 + H24 - MIN30);
        // Any value in between lands in the window.
        assert_eq!(ReplaceSchedule::new(t0, s(777)).due_at(), t0 + H24 - s(777));
        // More than the maximum is clamped to it: never earlier than 23 h 30 min.
        assert_eq!(
            ReplaceSchedule::new(t0, MIN30 + s(1)).due_at(),
            t0 + H24 - MIN30
        );
        assert_eq!(
            ReplaceSchedule::new(t0, Duration::MAX).due_at(),
            t0 + H24 - MIN30
        );
    }

    #[test]
    fn nothing_starts_before_due_and_start_is_offered_at_due() {
        let t0 = start();
        let mut sch = ReplaceSchedule::new(t0, s(600));
        let due = t0 + H24 - s(600);
        assert_eq!(sch.poll(t0), Poll::WaitUntil(due));
        assert_eq!(sch.poll(due - s(1)), Poll::WaitUntil(due));
        assert_eq!(sch.poll(due), Poll::Start);
        assert_eq!(sch.poll(due + s(5)), Poll::Start);
    }

    #[test]
    fn a_timeout_turns_into_the_retry_sequence_30_60_120_240_then_300() {
        let t0 = start();
        let mut sch = ReplaceSchedule::new(t0, s(0));
        let mut now = t0 + H24;
        let expected_delays = [30u64, 60, 120, 240, 300, 300, 300];
        for (n, delay) in expected_delays.into_iter().enumerate() {
            assert_eq!(sch.poll(now), Poll::Start, "attempt {n}");
            sch.begin_attempt(now);
            // In flight: wait for the timeout instant.
            let timeout = now + s(10);
            assert_eq!(sch.poll(now + s(9)), Poll::WaitUntil(timeout));
            // Poll late: the retry still counts from the timeout instant, not from the poll.
            let retry_at = timeout + s(delay);
            assert_eq!(
                sch.poll(timeout + s(1)),
                Poll::WaitUntil(retry_at),
                "attempt {n}"
            );
            assert_eq!(sch.poll(retry_at - s(1)), Poll::WaitUntil(retry_at));
            assert_eq!(sch.failures(), n + 1);
            now = retry_at;
        }
    }

    #[test]
    fn an_explicit_failure_counts_the_delay_from_the_failure() {
        let t0 = start();
        let mut sch = ReplaceSchedule::new(t0, s(0));
        let now = t0 + H24;
        assert_eq!(sch.poll(now), Poll::Start);
        sch.begin_attempt(now);
        sch.attempt_failed(now + s(2));
        assert_eq!(sch.poll(now + s(3)), Poll::WaitUntil(now + s(2) + s(30)));
        // A failure with nothing in flight changes nothing.
        let before = sch.failures();
        sch.attempt_failed(now + s(4));
        assert_eq!(sch.failures(), before);
    }

    #[test]
    fn success_ends_the_schedule_even_past_the_cap() {
        let t0 = start();
        let mut sch = ReplaceSchedule::new(t0, s(0));
        let now = t0 + H24;
        sch.begin_attempt(now);
        sch.succeeded();
        assert_eq!(sch.poll(now + s(1)), Poll::Done);
        assert_eq!(sch.poll(t0 + H24 + MIN30 + s(10)), Poll::Done);
        // begin_attempt after done does not revive it.
        sch.begin_attempt(now);
        assert_eq!(sch.poll(now + s(1)), Poll::Done);
    }

    #[test]
    fn the_hard_cap_is_exactly_24h30m_inclusive_and_one_tick_before_is_not() {
        let t0 = start();
        let cap = t0 + H24 + MIN30;
        let mut sch = ReplaceSchedule::new(t0, s(0));
        assert_eq!(sch.hard_cap_at(), cap);
        let one_tick = Duration::from_nanos(1);
        assert_ne!(sch.poll(cap - one_tick), Poll::Expired);
        assert_eq!(sch.poll(cap), Poll::Expired);
        assert_eq!(sch.poll(cap + s(60)), Poll::Expired);
        // Also with an attempt in flight and with a retry pending.
        let mut sch = ReplaceSchedule::new(t0, s(0));
        sch.begin_attempt(cap - s(5));
        assert_ne!(sch.poll(cap - one_tick), Poll::Expired);
        assert_eq!(sch.poll(cap), Poll::Expired);
    }

    #[test]
    fn a_wait_never_runs_past_the_hard_cap() {
        let t0 = start();
        let cap = t0 + H24 + MIN30;
        let mut sch = ReplaceSchedule::new(t0, s(0));
        let now = cap - s(100);
        assert_eq!(sch.poll(now), Poll::Start);
        sch.begin_attempt(now);
        // The timeout would be at cap - 90 s: fine. Fail it, then the 30 s retry is fine too;
        // a long delay would be clamped to the cap.
        assert_eq!(sch.poll(now + s(1)), Poll::WaitUntil(now + s(10)));
        let mut late = ReplaceSchedule::with_durations(
            t0,
            s(0),
            ReplaceDurations {
                retry_delays: vec![s(10_000)],
                ..ReplaceDurations::default()
            },
        );
        let n = cap - s(50);
        late.begin_attempt(n);
        assert_eq!(late.poll(n + s(11)), Poll::WaitUntil(cap));
    }

    #[test]
    fn test_overrides_shorten_every_figure() {
        let t0 = start();
        let d = ReplaceDurations {
            lifetime: s(2),
            max_jitter: s(1),
            pending_timeout: s(1),
            retry_delays: vec![s(1)],
            steady_delay: s(2),
            hard_cap: s(6),
        };
        let mut sch = ReplaceSchedule::with_durations(t0, s(5), d);
        assert_eq!(sch.due_at(), t0 + s(1));
        assert_eq!(sch.hard_cap_at(), t0 + s(6));
        assert_eq!(sch.poll(t0 + s(1)), Poll::Start);
        sch.begin_attempt(t0 + s(1));
        assert_eq!(sch.poll(t0 + s(2)), Poll::WaitUntil(t0 + s(3)));
        assert_eq!(sch.poll(t0 + s(3)), Poll::Start);
        sch.begin_attempt(t0 + s(3));
        // Second failure uses the steady delay.
        assert_eq!(sch.poll(t0 + s(4)), Poll::WaitUntil(t0 + s(6)));
        assert_eq!(sch.poll(t0 + s(6)), Poll::Expired);
    }
}
