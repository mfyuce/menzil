//! Per-peer handshake rate limiting (protocol.md 5.1: "Handshakes are rate
//! limited per peer (10 per minute) because each costs four Diffie Hellman
//! operations and two signature checks"; TODO.md L4e1).
//!
//! Sans-IO like the rest of this crate: the caller passes `now`, so tests
//! need no clock and a caller owns the one real one.
//!
//! **What it counts**: every inbound `init` a peer sends, by the NodeId the
//! relay attests as the RECV `src`. It is applied *before* the responder's
//! handshake work (the Diffie Hellmans and signature checks it exists to
//! ration), so a refused `init` costs a hash lookup.
//!
//! **A sliding log, not a token bucket, and only accepted attempts are
//! logged**: a peer is allowed `max` attempts in any `window`. Refused
//! attempts are not recorded, so a flood does not extend its own block
//! beyond the one `window` its earliest accepted attempts take to age out,
//! and each peer's log never grows past `max` entries.
//!
//! **Memory is bounded two ways**: an expired log is dropped, and no more
//! than `max_tracked_peers` peers are tracked at once. When that many
//! distinct peers have each been accepted within the last `window`, a peer
//! not yet tracked is *refused* rather than evicting someone: failing
//! closed keeps the work it rations bounded, and reaching the cap at all
//! means thousands of distinct members all handshaking inside one minute,
//! which no personal network produces. The peers it sees are authenticated
//! by the relay (a member cannot claim another's `src`), so the cap is not
//! reachable by an outsider. A malicious *relay* could fabricate sources,
//! and then this limiter bounds less than it seems to: each fabricated
//! source gets its ten `init`s a minute, each of which costs the responder
//! the Diffie Hellmans in `E2eResponderHandshake::start` before the Policy
//! can refuse it, and 4096 such sources keep the table full, so a genuine
//! peer not yet tracked is refused until their logs expire. A relay can
//! deny service by dropping traffic anyway, so this is no worse than that;
//! it is only not free. A full table is swept at most once a second, so
//! refusing the 4097th source and every one after it stays a lookup.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use menzil_proto::NodeId;

/// The least time between two sweeps of a full table (see [`HandshakeLimiter::allow`]).
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// protocol.md 5.1 / 10: ten handshakes per peer per minute.
pub const DEFAULT_HANDSHAKES_PER_WINDOW: usize = 10;
/// The window [`DEFAULT_HANDSHAKES_PER_WINDOW`] is counted over.
pub const DEFAULT_HANDSHAKE_WINDOW: Duration = Duration::from_secs(60);
/// Distinct peers tracked at once before untracked ones are refused.
pub const DEFAULT_MAX_TRACKED_PEERS: usize = 4096;

/// A sliding-log limiter keyed by peer. See the module docs.
#[derive(Debug)]
pub struct HandshakeLimiter {
    max: usize,
    window: Duration,
    max_tracked_peers: usize,
    accepted: HashMap<NodeId, VecDeque<Instant>>,
    last_sweep: Option<Instant>,
}

impl HandshakeLimiter {
    /// A limiter allowing `max` attempts per peer in any `window`, tracking
    /// at most `max_tracked_peers` peers.
    pub fn new(max: usize, window: Duration, max_tracked_peers: usize) -> Self {
        Self {
            max,
            window,
            max_tracked_peers,
            accepted: HashMap::new(),
            last_sweep: None,
        }
    }

    /// protocol.md's numbers: 10 per minute, 4096 peers tracked.
    pub fn with_defaults() -> Self {
        Self::new(
            DEFAULT_HANDSHAKES_PER_WINDOW,
            DEFAULT_HANDSHAKE_WINDOW,
            DEFAULT_MAX_TRACKED_PEERS,
        )
    }

    /// Whether `peer` may start one more handshake at `now`; records it if
    /// so. A refusal records nothing.
    pub fn allow(&mut self, peer: &NodeId, now: Instant) -> bool {
        if self.max == 0 {
            return false;
        }
        if !self.accepted.contains_key(peer) && self.accepted.len() >= self.max_tracked_peers {
            // Make room only from peers whose whole log has expired, and
            // look for them at most once a second: sweeping on every
            // attempt would make each refusal cost a pass over the table.
            if self
                .last_sweep
                .is_none_or(|last| now.saturating_duration_since(last) >= SWEEP_INTERVAL)
            {
                self.sweep(now);
            }
            if self.accepted.len() >= self.max_tracked_peers {
                return false;
            }
        }
        let log = self.accepted.entry(*peer).or_default();
        while let Some(&oldest) = log.front() {
            if now.saturating_duration_since(oldest) >= self.window {
                log.pop_front();
            } else {
                break;
            }
        }
        if log.len() >= self.max {
            return false;
        }
        log.push_back(now);
        true
    }

    /// Drops every peer whose log has fully expired by `now`. [`Self::allow`]
    /// does this itself when the table is full; a caller may also run it on
    /// a timer to give the memory back sooner.
    pub fn sweep(&mut self, now: Instant) {
        self.last_sweep = Some(now);
        let window = self.window;
        self.accepted.retain(|_, log| {
            log.back()
                .is_some_and(|&newest| now.saturating_duration_since(newest) < window)
        });
    }

    /// How many peers are currently tracked.
    pub fn tracked_peers(&self) -> usize {
        self.accepted.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> NodeId {
        NodeId::from([seed; 32])
    }

    const WINDOW: Duration = Duration::from_secs(60);

    fn limiter() -> HandshakeLimiter {
        HandshakeLimiter::new(10, WINDOW, 4096)
    }

    #[test]
    fn the_defaults_are_the_spec_numbers() {
        // protocol.md 5.1 and section 10: 10 per minute per peer.
        assert_eq!(DEFAULT_HANDSHAKES_PER_WINDOW, 10);
        assert_eq!(DEFAULT_HANDSHAKE_WINDOW, Duration::from_secs(60));
        let mut l = HandshakeLimiter::with_defaults();
        let t0 = Instant::now();
        assert_eq!((0..11).filter(|_| l.allow(&peer(1), t0)).count(), 10);
    }

    #[test]
    fn the_eleventh_attempt_inside_the_window_is_refused() {
        let mut l = limiter();
        let t0 = Instant::now();
        for i in 0..10 {
            assert!(
                l.allow(&peer(1), t0 + Duration::from_secs(i)),
                "attempt {i}"
            );
        }
        assert!(!l.allow(&peer(1), t0 + Duration::from_secs(10)));
        assert!(!l.allow(&peer(1), t0 + Duration::from_secs(59)));
    }

    #[test]
    fn the_window_slides_so_attempts_return_as_the_oldest_age_out() {
        let mut l = limiter();
        let t0 = Instant::now();
        for i in 0..10 {
            assert!(l.allow(&peer(1), t0 + Duration::from_secs(i)));
        }
        // The first attempt (t0) ages out at t0 + 60 s, the second at 61 s.
        assert!(!l.allow(&peer(1), t0 + Duration::from_secs(59)));
        assert!(l.allow(&peer(1), t0 + Duration::from_secs(60)));
        assert!(
            !l.allow(&peer(1), t0 + Duration::from_secs(60)),
            "10 in window again"
        );
        assert!(l.allow(&peer(1), t0 + Duration::from_secs(61)));
    }

    #[test]
    fn a_refused_attempt_is_not_recorded_so_a_flood_does_not_extend_its_own_block() {
        let mut l = limiter();
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(l.allow(&peer(1), t0));
        }
        // A thousand refused attempts during the window...
        for i in 1..=1000 {
            assert!(!l.allow(&peer(1), t0 + Duration::from_millis(i * 50)));
        }
        // ...cost nothing: the block still ends exactly when the accepted
        // ones age out.
        assert!(l.allow(&peer(1), t0 + WINDOW));
    }

    #[test]
    fn peers_are_limited_independently() {
        let mut l = limiter();
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(l.allow(&peer(1), t0));
        }
        assert!(!l.allow(&peer(1), t0));
        assert!(l.allow(&peer(2), t0), "another peer is unaffected");
    }

    #[test]
    fn a_zero_limit_refuses_everything() {
        let mut l = HandshakeLimiter::new(0, WINDOW, 4096);
        assert!(!l.allow(&peer(1), Instant::now()));
    }

    #[test]
    fn untracked_peers_are_refused_when_the_table_is_full_of_live_ones() {
        let mut l = HandshakeLimiter::new(10, WINDOW, 3);
        let t0 = Instant::now();
        for seed in 1..=3 {
            assert!(l.allow(&peer(seed), t0));
        }
        assert_eq!(l.tracked_peers(), 3);
        assert!(
            !l.allow(&peer(4), t0),
            "fail closed rather than evict a live peer"
        );
        assert!(l.allow(&peer(1), t0), "a tracked peer is still served");
        assert_eq!(l.tracked_peers(), 3);
    }

    #[test]
    fn a_full_table_makes_room_from_expired_peers_only() {
        let mut l = HandshakeLimiter::new(10, WINDOW, 3);
        let t0 = Instant::now();
        assert!(l.allow(&peer(1), t0));
        assert!(l.allow(&peer(2), t0 + Duration::from_secs(30)));
        assert!(l.allow(&peer(3), t0 + Duration::from_secs(30)));
        // Peer 1's only attempt has expired by t0 + 61 s; the other two have not.
        let later = t0 + Duration::from_secs(61);
        assert!(l.allow(&peer(4), later));
        assert_eq!(l.tracked_peers(), 3, "peer 1 made room");
        assert!(!l.allow(&peer(5), later), "but nothing else did");
    }

    #[test]
    fn a_full_table_is_swept_at_most_once_a_second() {
        let mut l = HandshakeLimiter::new(10, WINDOW, 2);
        let t0 = Instant::now();
        assert!(l.allow(&peer(1), t0));
        assert!(l.allow(&peer(2), t0 + Duration::from_secs(10)));
        // Full. This refusal sweeps (nothing has expired yet).
        assert!(!l.allow(&peer(3), t0 + Duration::from_millis(59_900)));
        // Peer 1's log expired at 60 s, but a sweep ran 0.3 s ago.
        assert!(!l.allow(&peer(3), t0 + Duration::from_millis(60_200)));
        // A second after that sweep the table is swept again, and room is made.
        assert!(l.allow(&peer(3), t0 + Duration::from_millis(60_950)));
        assert_eq!(l.tracked_peers(), 2);
    }

    #[test]
    fn sweep_drops_fully_expired_peers() {
        let mut l = limiter();
        let t0 = Instant::now();
        for seed in 1..=5 {
            assert!(l.allow(&peer(seed), t0));
        }
        l.sweep(t0 + Duration::from_secs(10));
        assert_eq!(l.tracked_peers(), 5);
        l.sweep(t0 + WINDOW);
        assert_eq!(l.tracked_peers(), 0);
    }

    #[test]
    fn a_clock_that_runs_backwards_does_not_panic_or_unblock() {
        // `Instant` is monotonic in practice, but a caller could pass an
        // older `now` than an earlier call's: saturating arithmetic keeps
        // that from panicking, and the attempts still count.
        let mut l = limiter();
        let t0 = Instant::now() + Duration::from_secs(100);
        for _ in 0..10 {
            assert!(l.allow(&peer(1), t0));
        }
        assert!(!l.allow(&peer(1), t0 - Duration::from_secs(50)));
    }
}
