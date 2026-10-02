//! KEEP liveness (protocol.md 5.2: KEEP is "empty, every 20 s when
//! idle").
//!
//! **A design bug this crate shipped and then caught on its own, via its
//! own red-team review**: an earlier version of this module copied
//! `menzil_session::Liveness`'s inbound-only model wholesale — track
//! time since the last *received* record, send a keepalive once that
//! has gone quiet long enough. That works for L3's PING because PING
//! gets a PONG reply, which resets the *sender's own* inbound clock too,
//! so the rule is self-correcting in both directions. KEEP has no reply
//! (protocol.md 5.2's plaintext-kind table: no `KEEP_ACK`). Live-tested
//! consequence: once one side's receive clock had gone quiet for 20 s
//! and it sent a KEEP, the *other* side's clock reset on receiving it —
//! but the *sender's own* clock, having only ever been driven by
//! receives, never recorded that it had just sent anything, so
//! `should_send_keep` stayed true on every subsequent check and the
//! sender entered a tight KEEP-sending loop instead of going quiet for
//! another 20 s. Fixed by switching to the model WireGuard itself uses
//! for exactly this kind of one-way keepalive ("passive keepalive"):
//! track *send*-idleness for when to emit a KEEP, independently of
//! *receive*-idleness for [`Liveness::is_dead`]. Real traffic counts the
//! same as a KEEP on the send side — sending *anything* is proof of
//! life, not just an explicit keepalive — so [`Liveness::note_sent`]
//! should be called after every record this side successfully sends via
//! `menzil_e2e::E2eTransport::encrypt_data`, not only after a KEEP.
//!
//! **A judgment call worth flagging explicitly** (this crate's own
//! scoping pass listed "a missing dead-peer timeout" as an open item:
//! unlike L3's section 3.3, protocol.md 5.2 states KEEP's send interval
//! but never states a threshold for when a silent L4 peer should be
//! considered dead). [`DEAD_AFTER`] picks one rather than leaving it
//! unimplemented: twice the send interval, the same ratio
//! `menzil_session::Liveness` already uses for L3 (25 s ping / 50 s
//! dead), applied to L4's own 20 s KEEP interval. This is a local
//! liveness policy, not a wire format, so it needs no protocol.md edit
//! or TOBEDECIDED entry the way TOBEDECIDED item 6 did; it can be
//! revisited by whichever of L4e/L4h first wires real teardown behavior
//! to [`Liveness::is_dead`] if 40 s proves too tight or too loose in
//! practice. Unlike the send/receive split above, this number was
//! already a documented judgment call before the red-team review and
//! stays one; the review found no fault with it specifically (it found
//! fault with the *mechanism* feeding `is_dead`'s sibling,
//! `should_send_keep`).

use std::time::{Duration, Instant};

const KEEP_INTERVAL: Duration = Duration::from_secs(20);
const DEAD_AFTER: Duration = Duration::from_secs(40);

/// Tracks time since this side last sent and last received, separately
/// — see this module's doc comment on why KEEP specifically needs both,
/// unlike L3's PING/PONG.
#[derive(Debug, Clone)]
pub struct Liveness {
    last_sent: Instant,
    last_received: Instant,
}

impl Liveness {
    /// Starts counting both clocks from `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            last_sent: now,
            last_received: now,
        }
    }

    /// Call after this side successfully sends *any* data record — not
    /// just KEEP; see this module's doc comment on why real traffic
    /// counts the same as an explicit keepalive.
    pub fn note_sent(&mut self, now: Instant) {
        self.last_sent = now;
    }

    /// Call whenever any data record is successfully decrypted
    /// (`menzil_e2e::E2eTransport::decrypt_data`) — not just KEEP.
    pub fn note_received(&mut self, now: Instant) {
        self.last_received = now;
    }

    /// Whether at least 20 s have passed since this side last *sent*
    /// anything: time to send a KEEP. Calling this and then actually
    /// sending something (a KEEP or otherwise) should always be
    /// followed by [`Self::note_sent`], or this will report true again
    /// on the very next check.
    pub fn should_send_keep(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_sent) >= KEEP_INTERVAL
    }

    /// Whether this side should consider its peer dead: at least 40 s
    /// since anything was last *received* (this module's own documented
    /// judgment call — see its doc comment).
    pub fn is_dead(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_received) >= DEAD_AFTER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_liveness_neither_keeps_nor_is_dead() {
        let now = Instant::now();
        let liveness = Liveness::new(now);
        assert!(!liveness.should_send_keep(now));
        assert!(!liveness.is_dead(now));
    }

    #[test]
    fn should_send_keep_after_one_interval_but_not_dead_yet() {
        let start = Instant::now();
        let liveness = Liveness::new(start);
        let at_20s = start + KEEP_INTERVAL;
        assert!(liveness.should_send_keep(at_20s));
        assert!(!liveness.is_dead(at_20s));
    }

    #[test]
    fn dead_after_two_intervals_of_silence() {
        let start = Instant::now();
        let liveness = Liveness::new(start);
        let at_40s = start + DEAD_AFTER;
        assert!(liveness.is_dead(at_40s));
    }

    #[test]
    fn note_sent_resets_only_the_send_clock() {
        let start = Instant::now();
        let mut liveness = Liveness::new(start);
        let at_30s = start + Duration::from_secs(30);
        liveness.note_sent(at_30s);
        let at_35s = start + Duration::from_secs(35);
        // Send clock was just reset at 30s: not due at 35s.
        assert!(!liveness.should_send_keep(at_35s));
        // Receive clock was never touched, so is_dead still measures
        // from `start`, not from `note_sent`'s timestamp.
        assert!(liveness.is_dead(start + DEAD_AFTER));
    }

    #[test]
    fn note_received_resets_only_the_receive_clock() {
        let start = Instant::now();
        let mut liveness = Liveness::new(start);
        let at_30s = start + Duration::from_secs(30);
        liveness.note_received(at_30s);
        // Receive clock was just reset: not dead shortly after.
        assert!(!liveness.is_dead(at_30s + Duration::from_secs(5)));
        // Send clock was never touched, so should_send_keep still
        // measures from `start`: already well past 20s by t=30s.
        assert!(liveness.should_send_keep(at_30s));
    }

    /// The regression test for the bug this module's own doc comment
    /// describes: two sides, driven only by the documented rule ("note
    /// sent on send, note received on receive, send a KEEP when
    /// send-idle for 20s, call `note_sent` after"), must both stay
    /// alive indefinitely through nothing but KEEPs, regardless of how
    /// their initial activity is offset from each other. The old,
    /// receive-only model failed this at exactly t=40s for every
    /// nonzero offset tried.
    #[test]
    fn two_sides_driven_by_keep_alone_never_go_dead_despite_an_offset_start() {
        for offset_ms in [0u64, 1, 50, 150, 3_000, 19_000] {
            let start = Instant::now();
            let mut a = Liveness::new(start);
            let mut b = Liveness::new(start + Duration::from_millis(offset_ms));

            let mut now = start;
            let end = start + Duration::from_secs(300);
            let tick = Duration::from_millis(100);
            let latency = Duration::from_millis(10);
            while now < end {
                if a.should_send_keep(now) {
                    a.note_sent(now);
                    b.note_received(now + latency);
                }
                if b.should_send_keep(now) {
                    b.note_sent(now);
                    a.note_received(now + latency);
                }
                assert!(!a.is_dead(now), "a died at {now:?}, offset {offset_ms}ms");
                assert!(!b.is_dead(now), "b died at {now:?}, offset {offset_ms}ms");
                now += tick;
            }
        }
    }
}
