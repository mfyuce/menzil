//! The adaptive in-flight window of one destination (throughput design note
//! `docs/private/adaptive-inflight-design.md`, section A, slice 2): pure logic, no I/O and no clock
//! of its own (every call is given `now`), so it is tested against a small link simulator.
//!
//! What it does. The relay's per pair credit is a fixed 1 MiB; on a slow line that much unacked data
//! stands in queues for seconds, and every small record waits behind it. The controller keeps the
//! bytes in flight (sent and not yet credited back) near `max_rate * (min_rtt + D)`: enough to fill
//! the path plus a short standing queue of about `D` (the target queueing delay), whatever the line.
//! The ack clock is the relay's CREDIT, one per record, returned when the record has been handed to
//! the destination's socket, in send order.
//!
//! Measured per record: its round trip time (credit time minus send time) and the delivery rate (the
//! bytes credited between its send and its credit, over that time, as BBR measures it, which a burst
//! of credit cannot inflate). Control law, once per round (a round ends when the record sent at its
//! start is credited): the window moves toward `T = max_rate * (min_rtt + D)` by at most 0.7x down
//! and 2x up, within `[floor, ceiling]`; a round whose every RTT sample is above `min_rtt + 2 D`
//! shrinks it (a line that just got slower is seen within a round); a path not seen empty for 10 s
//! (its smallest RTT is that old) is probed with the floor for one round or 200 ms.
//!
//! Wired into the node's send queue by slice 3; until then only the tests use it.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// How long a round trip minimum stays valid.
const MIN_RTT_WINDOW: Duration = Duration::from_secs(10);
/// How many finished rounds the delivery rate maximum looks back over.
const RATE_ROUNDS: usize = 6;
/// The longest the window shrinks in one round, and the most it grows.
const STEP_DOWN: f64 = 0.7;
const STEP_UP: f64 = 2.0;
/// A path is "seen empty" when a round's smallest RTT is within this factor of the minimum.
const CONFIRM_FACTOR: f64 = 1.25;
/// How long the window is held at the floor to see the empty path again.
const PROBE_HOLD: Duration = Duration::from_millis(200);

/// The settings of one controller.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WindowConfig {
    /// The smallest window: two maximum records, so a record always fits.
    pub floor: usize,
    /// The largest: never above the relay's credit.
    pub ceiling: usize,
    /// The window of a new pair: today's behaviour, so nothing is slower than before.
    pub start: usize,
    /// The standing queue the window aims for (`D`).
    pub target_delay: Duration,
}

/// One reliable record sent and not yet credited back.
#[derive(Debug, Clone, Copy)]
struct Sent {
    /// The credit offset at which this record is fully credited.
    end: u64,
    t_sent: Instant,
    credited_at_send: u64,
    t_credited_at_send: Instant,
}

/// What one round has seen so far.
#[derive(Debug, Clone, Copy)]
struct Round {
    /// The credit offset that ends the round.
    end: u64,
    min_rtt: Option<Duration>,
    max_rate: f64,
    /// Something waited on the window at one of this round's sends.
    window_limited: bool,
}

/// The window of one destination.
#[derive(Debug)]
pub(crate) struct WindowController {
    cfg: WindowConfig,
    window: usize,
    sent: u64,
    credited: u64,
    last_credit_at: Instant,
    in_order: VecDeque<Sent>,
    round: Option<Round>,
    /// The smallest round trip time and when the empty path was last seen (a round whose smallest
    /// RTT was within [`CONFIRM_FACTOR`] of it).
    min_rtt: Option<(Instant, Duration)>,
    /// The smallest RTT of the rounds while the window is held at the floor.
    probe_min: Option<Duration>,
    /// The largest delivery rate (bytes a second) of each of the last [`RATE_ROUNDS`] rounds.
    rates: VecDeque<f64>,
    probe_until: Option<Instant>,
}

impl WindowController {
    pub(crate) fn new(cfg: WindowConfig, now: Instant) -> Self {
        let floor = cfg.floor.max(1);
        let ceiling = cfg.ceiling.max(floor);
        let cfg = WindowConfig {
            floor,
            ceiling,
            start: cfg.start.clamp(floor, ceiling),
            ..cfg
        };
        Self {
            window: cfg.start,
            cfg,
            sent: 0,
            credited: 0,
            last_credit_at: now,
            in_order: VecDeque::new(),
            round: None,
            min_rtt: None,
            probe_min: None,
            rates: VecDeque::new(),
            probe_until: None,
        }
    }

    /// The bytes that may be in flight now.
    pub(crate) fn window(&self) -> usize {
        self.window
    }

    /// Bytes sent and not yet credited back.
    pub(crate) fn in_flight(&self) -> u64 {
        self.sent - self.credited
    }

    /// A reliable record of `charge` bytes was handed to the carrier at `now`. `window_limited`:
    /// something else was ready and waited on the window when this was sent.
    pub(crate) fn on_sent(&mut self, now: Instant, charge: u32, window_limited: bool) {
        self.sent += u64::from(charge);
        self.in_order.push_back(Sent {
            end: self.sent,
            t_sent: now,
            credited_at_send: self.credited,
            t_credited_at_send: self.last_credit_at,
        });
        match &mut self.round {
            Some(round) => round.window_limited |= window_limited,
            None => {
                self.round = Some(Round {
                    end: self.sent,
                    min_rtt: None,
                    max_rate: 0.0,
                    window_limited,
                });
            }
        }
    }

    /// The relay credited `bytes` back at `now`. More than was sent and not yet credited is cut to
    /// that (a relay that over-credits cannot make the clock run ahead of the data).
    pub(crate) fn on_credit(&mut self, now: Instant, bytes: u32) {
        let add = u64::from(bytes).min(self.sent - self.credited);
        self.credited += add;
        self.last_credit_at = now;
        while let Some(front) = self.in_order.front().copied() {
            if front.end > self.credited {
                break;
            }
            self.in_order.pop_front();
            let rtt = now.saturating_duration_since(front.t_sent);
            let elapsed = now.saturating_duration_since(front.t_credited_at_send);
            let delivered = front.end - front.credited_at_send;
            if let Some(round) = &mut self.round {
                round.min_rtt = Some(round.min_rtt.map_or(rtt, |m| m.min(rtt)));
                if !elapsed.is_zero() {
                    round.max_rate = round.max_rate.max(delivered as f64 / elapsed.as_secs_f64());
                }
                if self.credited >= round.end {
                    self.finish_round(now);
                }
            }
        }
    }

    fn finish_round(&mut self, now: Instant) {
        let Some(round) = self.round.take() else {
            return;
        };
        let Some(round_min) = round.min_rtt else {
            return;
        };
        // The minimum is never replaced by a larger sample just because it is old: a path with a
        // standing queue would then take the queue for the empty path. It is probed instead.
        let (seen_at, min_rtt) = match self.min_rtt {
            Some((at, rtt)) if round_min > rtt => (at, rtt),
            _ => (now, round_min),
        };
        self.min_rtt = Some((seen_at, min_rtt));
        if round_min.as_secs_f64() <= min_rtt.as_secs_f64() * CONFIRM_FACTOR {
            self.min_rtt = Some((now, min_rtt));
        }
        let seen_at = self.min_rtt.map_or(now, |(at, _)| at);

        // (An idle or application limited round samples a low rate and is kept like any other: the
        // maximum over the last rounds forgets the path's capacity after a long idle spell, and the
        // first busy round measures it again before the window is computed. The window itself is
        // never shrunk on the evidence of a round in which nothing waited on it: see below.)
        if round.max_rate > 0.0 {
            self.rates.push_back(round.max_rate);
            while self.rates.len() > RATE_ROUNDS {
                self.rates.pop_front();
            }
        }

        if let Some(until) = self.probe_until {
            self.probe_min = Some(self.probe_min.map_or(round_min, |m| m.min(round_min)));
            if now < until {
                self.window = self.cfg.floor;
                return;
            }
            // The window sat at the floor: the smallest RTT it saw is the empty path now.
            self.probe_until = None;
            let seen = self.probe_min.take().unwrap_or(round_min);
            self.min_rtt = Some((now, seen));
        } else if now.saturating_duration_since(seen_at) >= MIN_RTT_WINDOW {
            self.probe_until = Some(now + PROBE_HOLD);
            self.probe_min = None;
            self.window = self.cfg.floor;
            return;
        }
        let min_rtt = self.min_rtt.map_or(min_rtt, |(_, rtt)| rtt);

        // Every sample of a full round far above the empty path: the line got slower or another
        // flow arrived. Seen within a round, not when the rate filter forgets.
        if round_min > min_rtt + self.cfg.target_delay * 2 {
            self.window = self.step(self.window as f64 * STEP_DOWN);
            return;
        }

        let max_rate = self.rates.iter().copied().fold(0.0, f64::max);
        if max_rate > 0.0 {
            let target = max_rate * (min_rtt + self.cfg.target_delay).as_secs_f64();
            let lo = self.window as f64 * STEP_DOWN;
            let hi = self.window as f64 * STEP_UP;
            let next = self.step(target.clamp(lo, hi));
            // A round in which nothing waited on the window says the window is not what limits the
            // sender (idle, or application limited): it may grow, never shrink, on that evidence.
            self.window = if round.window_limited {
                next
            } else {
                next.max(self.window)
            };
        }
    }

    /// `value` as a window within `[floor, ceiling]`.
    fn step(&self, value: f64) -> usize {
        if !value.is_finite() {
            return self.cfg.ceiling;
        }
        (value.clamp(self.cfg.floor as f64, self.cfg.ceiling as f64)) as usize
    }
}

#[cfg(test)]
mod tests;
