//! The receive side replay window of the L4 datagram class (protocol.md
//! 5.2): 2048 positions, a 256 byte bitmap, RFC 6479 style.
//!
//! The window is two steps on purpose, so a caller can run the AEAD
//! between them: [`ReplayWindow::check`] never mutates and says whether a
//! sequence could still be accepted, [`ReplayWindow::commit`] records one
//! that has authenticated and decoded. Only `commit` moves the window, so
//! a forged frame (which never reaches it) cannot slide it.
//!
//! The accepted range is `top - 2047 ..= top` (each position once) plus
//! anything above `top`. Before the first commit the window is empty and
//! sequence 0 is accepted like any other.

use crate::error::E2eError;

/// Number of sequence positions the window remembers.
pub const REPLAY_WINDOW_SIZE: u64 = 2048;

const WORDS: usize = (REPLAY_WINDOW_SIZE / 64) as usize;
const INDEX_MASK: u64 = REPLAY_WINDOW_SIZE - 1;

/// A 2048 position replay window over datagram sequence numbers.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// The highest committed sequence; meaningful only when `any`.
    top: u64,
    /// Whether anything was committed yet.
    any: bool,
    /// Bit `seq & 2047` is set when that sequence was committed and is
    /// still inside the window.
    bits: [u64; WORDS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    /// An empty window: every sequence is acceptable.
    pub fn new() -> Self {
        Self {
            top: 0,
            any: false,
            bits: [0; WORDS],
        }
    }

    fn bit(seq: u64) -> (usize, u64) {
        let index = seq & INDEX_MASK;
        ((index / 64) as usize, 1u64 << (index % 64))
    }

    fn is_set(&self, seq: u64) -> bool {
        let (word, mask) = Self::bit(seq);
        self.bits[word] & mask != 0
    }

    fn set(&mut self, seq: u64) {
        let (word, mask) = Self::bit(seq);
        self.bits[word] |= mask;
    }

    fn clear(&mut self, seq: u64) {
        let (word, mask) = Self::bit(seq);
        self.bits[word] &= !mask;
    }

    /// Whether `seq` could still be accepted, without changing anything:
    /// [`E2eError::DatagramTooOld`] when it is 2048 or more behind the
    /// highest committed sequence, [`E2eError::DatagramReplayed`] when it
    /// was committed already.
    pub fn check(&self, seq: u64) -> Result<(), E2eError> {
        if !self.any || seq > self.top {
            return Ok(());
        }
        if self.top - seq >= REPLAY_WINDOW_SIZE {
            return Err(E2eError::DatagramTooOld);
        }
        if self.is_set(seq) {
            return Err(E2eError::DatagramReplayed);
        }
        Ok(())
    }

    /// Records `seq` as received, sliding the window when it is above the
    /// highest committed sequence (a jump of 2048 or more clears it). Call
    /// only for a datagram that authenticated and decoded, and only after
    /// [`Self::check`] passed for the same `seq`.
    pub fn commit(&mut self, seq: u64) {
        if !self.any {
            self.bits = [0; WORDS];
            self.any = true;
            self.top = seq;
        } else if seq > self.top {
            let jump = seq - self.top;
            if jump >= REPLAY_WINDOW_SIZE {
                self.bits = [0; WORDS];
            } else {
                for s in self.top + 1..=seq {
                    self.clear(s);
                }
            }
            self.top = seq;
        } else if self.top - seq >= REPLAY_WINDOW_SIZE {
            // Too old to record; `check` refuses these.
            return;
        }
        self.set(seq);
    }

    /// The highest committed sequence, if any.
    pub fn top(&self) -> Option<u64> {
        self.any.then_some(self.top)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(w: &mut ReplayWindow, seq: u64) {
        w.check(seq).unwrap();
        w.commit(seq);
    }

    #[test]
    fn replay_window_accepts_sequence_zero_first() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.top(), None);
        w.check(0).unwrap();
        w.commit(0);
        assert_eq!(w.top(), Some(0));
        assert!(matches!(w.check(0), Err(E2eError::DatagramReplayed)));
    }

    #[test]
    fn the_first_datagram_may_be_any_sequence() {
        let mut w = ReplayWindow::new();
        accept(&mut w, 5000);
        assert!(matches!(w.check(5000), Err(E2eError::DatagramReplayed)));
        w.check(5000 - 2047).unwrap();
        assert!(matches!(
            w.check(5000 - 2048),
            Err(E2eError::DatagramTooOld)
        ));
    }

    #[test]
    fn check_never_mutates() {
        let w = ReplayWindow::new();
        w.check(10).unwrap();
        w.check(10).unwrap();
        assert_eq!(w.top(), None);
    }

    #[test]
    fn sliding_clears_the_stale_bits_of_the_positions_it_passes() {
        let mut w = ReplayWindow::new();
        accept(&mut w, 5);
        accept(&mut w, 2000);
        // 2060 passes the ring positions of 2001..=2060, among them index 5.
        accept(&mut w, 2060);
        // 2053 shares index 5 with the long gone 5 and was never seen.
        w.check(2053).unwrap();
        assert!(matches!(w.check(2000), Err(E2eError::DatagramReplayed)));
        assert!(matches!(w.check(2060), Err(E2eError::DatagramReplayed)));
    }

    #[test]
    fn the_ring_wraps_without_losing_recent_entries() {
        let mut w = ReplayWindow::new();
        for s in 4000u64..4100 {
            accept(&mut w, s);
        }
        for s in 4000u64..4100 {
            assert!(matches!(w.check(s), Err(E2eError::DatagramReplayed)), "{s}");
        }
        w.check(4100).unwrap();
        w.check(3999).unwrap();
    }
}
