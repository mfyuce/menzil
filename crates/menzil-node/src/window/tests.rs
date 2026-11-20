//! The controller against a small discrete link: a sender that obeys the window, a bottleneck that
//! serves a FIFO at a rate, and a CREDIT that returns `back` after a record leaves the bottleneck
//! (so the empty path RTT is `back` plus the record's own service time). One step is 1 ms.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::*;

const REC: u32 = 16 * 1024;
const MIB: usize = 1024 * 1024;

fn cfg() -> WindowConfig {
    WindowConfig {
        floor: 128 * 1024,
        ceiling: 3 * MIB,
        start: MIB,
        target_delay: Duration::from_millis(100),
    }
}

struct Sim {
    t0: Instant,
    ms: u64,
    ctl: WindowController,
    /// Bottleneck rate, bytes a second.
    rate: f64,
    /// Path delay added after the bottleneck, ms.
    back_ms: u64,
    queue: VecDeque<f64>,
    budget: f64,
    credits: VecDeque<(u64, u32)>,
    /// Bytes a second the application offers; `None` is a bulk sender with always more to send.
    app: Option<f64>,
    tokens: f64,
}

impl Sim {
    fn new(rate: f64, back_ms: u64) -> Self {
        let t0 = Instant::now();
        Self {
            t0,
            ms: 0,
            ctl: WindowController::new(cfg(), t0),
            rate,
            back_ms,
            queue: VecDeque::new(),
            budget: 0.0,
            credits: VecDeque::new(),
            app: None,
            tokens: 0.0,
        }
    }

    fn now(&self) -> Instant {
        self.t0 + Duration::from_millis(self.ms)
    }

    fn step(&mut self) {
        self.ms += 1;
        let now = self.now();
        while let Some(&(due, bytes)) = self.credits.front() {
            if due > self.ms {
                break;
            }
            self.credits.pop_front();
            self.ctl.on_credit(now, bytes);
        }
        if let Some(app) = self.app {
            self.tokens = (self.tokens + app / 1000.0).min(f64::from(REC) * 4.0);
        }
        loop {
            let fits = self.ctl.in_flight() + u64::from(REC) <= self.ctl.window() as u64;
            let wanted = self.app.is_none() || self.tokens >= f64::from(REC);
            if !(fits && wanted) {
                break;
            }
            if self.app.is_some() {
                self.tokens -= f64::from(REC);
            }
            let limited = self.app.is_none()
                && self.ctl.in_flight() + 2 * u64::from(REC) > self.ctl.window() as u64;
            self.ctl.on_sent(now, REC, limited);
            self.queue.push_back(f64::from(REC));
        }
        self.budget += self.rate / 1000.0;
        while let Some(front) = self.queue.front_mut() {
            if self.budget >= *front {
                self.budget -= *front;
                self.queue.pop_front();
                self.credits.push_back((self.ms + self.back_ms, REC));
            } else {
                *front -= self.budget;
                self.budget = 0.0;
                break;
            }
        }
        if self.queue.is_empty() {
            self.budget = 0.0;
        }
    }

    fn run(&mut self, secs: u64) {
        for _ in 0..secs * 1000 {
            self.step();
        }
    }

    /// The standing queue at the bottleneck, as time.
    fn queue_delay(&self) -> Duration {
        Duration::from_secs_f64(self.queue.iter().sum::<f64>() / self.rate)
    }
}

const MBIT15: f64 = 15.0e6 / 8.0;

#[test]
fn on_a_15_mbit_line_the_window_settles_at_rate_times_rtt_plus_d_and_the_queue_stays_near_d() {
    let mut sim = Sim::new(MBIT15, 115);
    sim.run(3);
    let target = MBIT15 * 0.215;
    let mut worst_queue = Duration::ZERO;
    for _ in 0..(6 * 10) {
        sim.run_ms(100);
        let w = sim.ctl.window() as f64;
        assert!(
            (w - target).abs() <= target * 0.15,
            "window {w} not within 15% of {target} at {} ms",
            sim.ms
        );
        worst_queue = worst_queue.max(sim.queue_delay());
    }
    assert!(
        worst_queue <= Duration::from_millis(130),
        "standing queue {worst_queue:?}"
    );
}

impl Sim {
    fn run_ms(&mut self, ms: u64) {
        for _ in 0..ms {
            self.step();
        }
    }
}

#[test]
fn on_a_gigabit_line_the_window_reaches_the_ceiling() {
    let mut sim = Sim::new(125.0e6, 115);
    sim.run(5);
    assert_eq!(sim.ctl.window(), 3 * MIB);
}

#[test]
fn a_line_that_gets_ten_times_slower_has_its_queue_back_under_two_d_within_seconds() {
    let mut sim = Sim::new(12.5e6, 115);
    sim.run(8);
    assert!(sim.ctl.window() > MIB, "the 100 Mbit/s window is large");
    sim.rate = 1.25e6;
    let mut back_under = None;
    for ms in 0..20_000u64 {
        sim.step();
        if ms > 500 && sim.queue_delay() <= Duration::from_millis(200) {
            back_under = Some(ms);
            break;
        }
    }
    let ms = back_under.expect("the queue never came back under 2 D");
    assert!(ms <= 6_000, "took {ms} ms");
}

#[test]
fn an_application_limited_sender_keeps_its_window() {
    let mut sim = Sim::new(12.5e6, 115);
    sim.app = Some(100.0 * 1024.0);
    sim.run(30);
    assert!(
        sim.ctl.window() >= MIB,
        "an idle sender's window fell to {}",
        sim.ctl.window()
    );
}

#[test]
fn in_steady_state_the_window_varies_by_at_most_15_percent() {
    let mut sim = Sim::new(MBIT15, 115);
    sim.run(3);
    let (mut lo, mut hi) = (usize::MAX, 0);
    for _ in 0..65 {
        sim.run_ms(100);
        lo = lo.min(sim.ctl.window());
        hi = hi.max(sim.ctl.window());
    }
    assert!(
        hi as f64 <= lo as f64 * 1.15,
        "window between {lo} and {hi}"
    );
}

#[test]
fn a_path_not_seen_empty_for_ten_seconds_is_probed_with_the_floor_for_a_moment() {
    let mut sim = Sim::new(MBIT15, 115);
    let mut floor_seen_after = None;
    for ms in 0..16_000u64 {
        sim.step();
        if ms > 5_000 && sim.ctl.window() == cfg().floor {
            floor_seen_after = Some(ms);
            break;
        }
    }
    assert!(
        floor_seen_after.is_some(),
        "the window never went to the floor to see the empty path"
    );
}

#[test]
fn credit_beyond_what_was_sent_zero_time_and_huge_numbers_never_leave_the_bounds() {
    let t0 = Instant::now();
    let mut ctl = WindowController::new(cfg(), t0);
    ctl.on_credit(t0, u32::MAX);
    assert_eq!(ctl.in_flight(), 0);
    ctl.on_sent(t0, u32::MAX, true);
    ctl.on_credit(t0, 1);
    ctl.on_credit(t0, u32::MAX);
    ctl.on_credit(t0 - Duration::from_secs(5).min(Duration::ZERO), u32::MAX);
    for i in 0..1000u32 {
        let at = t0 + Duration::from_micros(u64::from(i % 7));
        ctl.on_sent(at, REC, i % 3 == 0);
        ctl.on_credit(at, if i % 5 == 0 { u32::MAX } else { REC });
        let w = ctl.window();
        assert!((cfg().floor..=cfg().ceiling).contains(&w), "window {w}");
    }
}

#[test]
fn a_new_controller_starts_at_the_start_window_inside_the_bounds() {
    let t0 = Instant::now();
    let c = WindowController::new(
        WindowConfig {
            floor: 10,
            ceiling: 5,
            start: 1_000,
            target_delay: Duration::from_millis(100),
        },
        t0,
    );
    assert_eq!(c.window(), 10, "a ceiling below the floor is lifted to it");
    assert_eq!(WindowController::new(cfg(), t0).window(), MIB);
}

#[test]
fn a_very_slow_line_holds_the_window_at_the_floor_not_below_it() {
    // 1 Mbit/s: rate x (RTT + D) is about 27 KiB, far under the floor (two maximum records). The
    // first round starts with 1 MiB in flight, 8 s of queue at this rate, and every round shrinks
    // the window by 0.7 at most: it takes about 15 s to reach the floor. At the floor the window is
    // itself a second of queue; the probe then sees that as the path's round trip, so the window
    // settles a little above the floor (self consistent: nothing smaller is allowed).
    let mut sim = Sim::new(1.0e6 / 8.0, 115);
    let mut lowest = usize::MAX;
    for _ in 0..(120 * 10) {
        sim.run_ms(100);
        lowest = lowest.min(sim.ctl.window());
    }
    assert_eq!(
        lowest,
        cfg().floor,
        "the window went below the floor, or never reached it"
    );
    assert!(sim.ctl.window() as f64 <= cfg().floor as f64 * 1.2);
}

#[test]
fn an_idle_spell_does_not_make_the_controller_forget_what_the_path_carried() {
    let mut sim = Sim::new(MBIT15, 115);
    sim.run(5);
    sim.app = Some(100.0 * 1024.0);
    sim.run(20);
    sim.app = None;
    sim.run_ms(1_000);
    let target = MBIT15 * 0.215;
    assert!(
        sim.ctl.window() as f64 >= target * 0.85,
        "after the idle spell the window is {}, the path wants {target}",
        sim.ctl.window()
    );
}

#[test]
fn a_window_value_outside_the_bounds_or_not_a_number_is_cut_to_them() {
    let ctl = WindowController::new(cfg(), Instant::now());
    assert_eq!(ctl.step(1.0), cfg().floor);
    assert_eq!(ctl.step(1.0e18), cfg().ceiling);
    assert_eq!(ctl.step(f64::INFINITY), cfg().ceiling);
    assert_eq!(ctl.step(f64::NAN), cfg().ceiling);
    assert_eq!(ctl.step(200_000.0), 200_000);
}
