use std::{cmp, sync::Arc};

use parking_lot::Mutex;
use web_time::Instant;

use crate::{connection::rtt::Rtt, Config, ConnectionError, DEFAULT_CREDIT};

#[derive(Debug)]
pub(crate) struct FlowController {
    config: Arc<Config>,
    last_window_update: Instant,
    /// See [`Connection::rtt`].
    rtt: Rtt,
    /// See [`Connection::accumulated_max_stream_windows`].
    accumulated_max_stream_windows: Arc<Mutex<usize>>,
    receive_window: u32,
    max_receive_window: u32,
    send_window: u32,
}

impl FlowController {
    pub(crate) fn new(
        receive_window: u32,
        send_window: u32,
        accumulated_max_stream_windows: Arc<Mutex<usize>>,
        rtt: Rtt,
        config: Arc<Config>,
    ) -> Self {
        Self {
            receive_window,
            send_window,
            config,
            rtt,
            accumulated_max_stream_windows,
            max_receive_window: DEFAULT_CREDIT,
            last_window_update: Instant::now(),
        }
    }

    /// Calculate the number of additional window bytes the receiving side (local) should grant the
    /// sending side (remote) via a window update message.
    ///
    /// Returns `None` if too small to justify a window update message.
    pub(crate) fn next_window_update(&mut self, buffer_len: usize) -> Option<u32> {
        self.assert_invariants(buffer_len);

        let bytes_received = self.max_receive_window - self.receive_window;
        let mut next_window_update =
            bytes_received.saturating_sub(buffer_len.try_into().unwrap_or(u32::MAX));

        // Don't send an update in case half or more of the window is still available to the sender.
        if next_window_update < self.max_receive_window / 2 {
            return None;
        }

        // Patch 6 (menzil): give grown window back. The time since the previous shrink or grant
        // (`last_window_update`) is at least max(1 s, 4 x RTT) and half a window is due, so the stream is not using its grown maximum: the credit
        // that would be granted now is not granted, and the maximum falls by that much, down to
        // `DEFAULT_CREDIT`. The bytes the sender already holds credit for stay valid (the maximum
        // never drops below credit outstanding plus data buffered), so an honest peer is never
        // cut off; the growth budget gets the difference back for other streams.
        if self.max_receive_window > DEFAULT_CREDIT {
            let idle_after = cmp::max(
                std::time::Duration::from_secs(1),
                self.rtt.get().unwrap_or_default() * 4,
            );
            if self.last_window_update.elapsed() >= idle_after {
                let reduce = cmp::min(next_window_update, self.max_receive_window - DEFAULT_CREDIT);
                *self.accumulated_max_stream_windows.lock() -= reduce as usize;
                self.max_receive_window -= reduce;
                next_window_update -= reduce;
                log::debug!(
                    "idle, window_max down by {} bytes to {}",
                    reduce,
                    self.max_receive_window
                );
                // The shrink is the answer to this interval: the next one is measured from now
                // (opus round S-C2, M1), or one idle gap would walk the window down to
                // `DEFAULT_CREDIT` on every later due update, however fast the stream runs.
                self.last_window_update = Instant::now();
                if next_window_update == 0 {
                    self.assert_invariants(buffer_len);
                    return None;
                }
                self.receive_window += next_window_update;
                self.assert_invariants(buffer_len);
                return Some(next_window_update);
            }
        }

        log::trace!(
            "received {} mb in {} seconds ({} mbit/s)",
            next_window_update as f64 / crate::MIB as f64,
            self.last_window_update.elapsed().as_secs_f64(),
            next_window_update as f64 / crate::MIB as f64 * 8.0
                / self.last_window_update.elapsed().as_secs_f64()
        );

        // Auto-tuning `max_receive_window`
        //
        // The ideal `max_receive_window` is equal to the bandwidth-delay-product (BDP), thus
        // allowing the remote sender to exhaust the entire available bandwidth on a single stream.
        // Choosing `max_receive_window` too small prevents the remote sender from exhausting the
        // available bandwidth. Choosing `max_receive_window` to large is wasteful and delays
        // backpressure from the receiver to the sender on the stream.
        //
        // In case the remote sender has exhausted half or more of its credit in less than 2
        // round-trips, try to double `max_receive_window`.
        //
        // For simplicity `max_receive_window` is never decreased.
        //
        // This implementation is heavily influenced by QUIC. See document below for rational on the
        // above strategy.
        //
        // https://docs.google.com/document/d/1F2YfdDXKpy20WVKJueEf4abn_LVZHhMUMS5gX6Pgjl4/edit?usp=sharing
        if self
            .rtt
            .get()
            .map(|rtt| self.last_window_update.elapsed() < rtt * 2)
            .unwrap_or(false)
        {
            let mut accumulated_max_stream_windows = self.accumulated_max_stream_windows.lock();

            // Ideally one can just double it:
            let new_max = self.max_receive_window.saturating_mul(2);

            // But one has to consider the configured connection limit:
            let new_max = {
                let connection_limit: usize = self.max_receive_window as usize +
                    // the overall configured conneciton limit
                    (self.config.max_connection_receive_window.unwrap_or(usize::MAX)
                    // minus the minimum amount of window guaranteed to each stream
                    - self.config.max_num_streams * DEFAULT_CREDIT as usize
                    // minus the amount of bytes beyond the minimum amount (`DEFAULT_CREDIT`)
                    // already allocated by this and other streams on the connection.
                    - *accumulated_max_stream_windows);

                cmp::min(new_max, connection_limit.try_into().unwrap_or(u32::MAX))
            };

            // Account for the additional credit on the accumulated connection counter.
            *accumulated_max_stream_windows += (new_max - self.max_receive_window) as usize;
            drop(accumulated_max_stream_windows);

            log::debug!(
                "old window_max: {} mb, new window_max: {} mb",
                self.max_receive_window as f64 / crate::MIB as f64,
                new_max as f64 / crate::MIB as f64
            );

            self.max_receive_window = new_max;

            // Recalculate `next_window_update` with the new `max_receive_window`.
            let bytes_received = self.max_receive_window - self.receive_window;
            next_window_update =
                bytes_received.saturating_sub(buffer_len.try_into().unwrap_or(u32::MAX));
        }

        self.last_window_update = Instant::now();
        self.receive_window += next_window_update;

        self.assert_invariants(buffer_len);

        Some(next_window_update)
    }

    fn assert_invariants(&self, buffer_len: usize) {
        if !cfg!(debug_assertions) {
            return;
        }

        let config = &self.config;
        let rtt = self.rtt.get();
        let accumulated_max_stream_windows = *self.accumulated_max_stream_windows.lock();

        assert!(
            buffer_len <= self.max_receive_window as usize,
            "The current buffer size never exceeds the maximum stream receive window."
        );
        assert!(
            self.receive_window <= self.max_receive_window,
            "The current window never exceeds the maximum."
        );
        assert!(
            (self.max_receive_window - DEFAULT_CREDIT) as usize
                <= config.max_connection_receive_window.unwrap_or(usize::MAX)
                    - config.max_num_streams * DEFAULT_CREDIT as usize,
            "The maximum never exceeds its maximum portion of the configured connection limit."
        );
        assert!(
            (self.max_receive_window - DEFAULT_CREDIT) as usize
                <= accumulated_max_stream_windows,
            "The amount by which the stream maximum exceeds DEFAULT_CREDIT is tracked in accumulated_max_stream_windows."
        );
        if rtt.is_none() {
            assert_eq!(
                self.max_receive_window, DEFAULT_CREDIT,
                "The maximum is only increased iff an rtt measurement is available."
            );
        }
    }

    pub(crate) fn send_window(&self) -> u32 {
        self.send_window
    }

    pub(crate) fn consume_send_window(&mut self, i: u32) -> Result<(), ConnectionError> {
        self.send_window = self
            .send_window
            .checked_sub(i)
            .ok_or(ConnectionError::InvalidWindowUpdate)?;
        Ok(())
    }

    pub(crate) fn increase_send_window_by(&mut self, i: u32) -> Result<(), ConnectionError> {
        self.send_window = self
            .send_window
            .checked_add(i)
            .ok_or(ConnectionError::InvalidWindowUpdate)?;
        Ok(())
    }

    pub(crate) fn consume_receive_window(&mut self, i: u32) -> Result<(), ConnectionError> {
        self.receive_window = self
            .receive_window
            .checked_sub(i)
            .ok_or(ConnectionError::InvalidWindowUpdate)?;
        Ok(())
    }
}

impl Drop for FlowController {
    fn drop(&mut self) {
        let mut accumulated_max_stream_windows = self.accumulated_max_stream_windows.lock();

        debug_assert!(
            *accumulated_max_stream_windows >= (self.max_receive_window - DEFAULT_CREDIT) as usize,
            "{accumulated_max_stream_windows} {}",
            self.max_receive_window
        );

        *accumulated_max_stream_windows -= (self.max_receive_window - DEFAULT_CREDIT) as usize;
    }
}

#[cfg(all(test, upstream_quickcheck))]
mod tests {
    use super::*;
    use quickcheck::{GenRange, QuickCheck};
    use web_time::Duration;

    #[derive(Debug)]
    struct Input {
        controller: FlowController,
        buffer_len: usize,
    }

    #[cfg(test)]
    impl Clone for Input {
        fn clone(&self) -> Self {
            Self {
                controller: FlowController {
                    config: self.controller.config.clone(),
                    accumulated_max_stream_windows: Arc::new(Mutex::new(
                        *self.controller.accumulated_max_stream_windows.lock(),
                    )),
                    rtt: self.controller.rtt.clone(),
                    last_window_update: self.controller.last_window_update,
                    receive_window: self.controller.receive_window,
                    max_receive_window: self.controller.max_receive_window,
                    send_window: self.controller.send_window,
                },
                buffer_len: self.buffer_len,
            }
        }
    }

    impl quickcheck::Arbitrary for Input {
        fn arbitrary(g: &mut quickcheck::Gen) -> Self {
            let config = Arc::new(Config::arbitrary(g));
            let rtt = Rtt::arbitrary(g);

            let max_connection_minus_default =
                config.max_connection_receive_window.unwrap_or(usize::MAX)
                    - (config.max_num_streams * (DEFAULT_CREDIT as usize));

            let max_receive_window = if rtt.get().is_none() {
                DEFAULT_CREDIT
            } else {
                g.gen_range(
                    DEFAULT_CREDIT
                        ..(DEFAULT_CREDIT as usize)
                            .saturating_add(max_connection_minus_default)
                            .try_into()
                            .unwrap_or(u32::MAX)
                            .saturating_add(1),
                )
            };
            let receive_window = g.gen_range(0..max_receive_window);
            let buffer_len = g.gen_range(0..max_receive_window as usize);
            let accumulated_max_stream_windows = Arc::new(Mutex::new(g.gen_range(
                (max_receive_window - DEFAULT_CREDIT) as usize
                    ..max_connection_minus_default.saturating_add(1),
            )));
            let last_window_update =
                Instant::now() - Duration::from_secs(g.gen_range(0..(60 * 60 * 24)));
            let send_window = g.gen_range(0..u32::MAX);

            Self {
                controller: FlowController {
                    accumulated_max_stream_windows,
                    rtt,
                    last_window_update,
                    config,
                    receive_window,
                    max_receive_window,
                    send_window,
                },
                buffer_len,
            }
        }
    }

    #[test]
    fn next_window_update() {
        fn property(
            Input {
                mut controller,
                buffer_len,
            }: Input,
        ) {
            controller.next_window_update(buffer_len);
        }

        QuickCheck::new().quickcheck(property as fn(_))
    }
}

/// Patch 6 tests (menzil).
#[cfg(test)]
mod shrink_tests {
    use super::*;
    use std::time::Duration;

    fn controller(acc: &Arc<Mutex<usize>>, rtt_ms: u64, grown: u32) -> FlowController {
        let mut config = Config::default();
        config.set_max_num_streams(512);
        config.set_max_connection_receive_window(Some(
            512 * DEFAULT_CREDIT as usize + 16 * 1024 * 1024,
        ));
        let mut c = FlowController::new(
            DEFAULT_CREDIT,
            DEFAULT_CREDIT,
            acc.clone(),
            Rtt::with_sample(Duration::from_millis(rtt_ms)),
            Arc::new(config),
        );
        // A stream that grew to `grown` and whose sender has used all of its credit.
        *acc.lock() += (grown - DEFAULT_CREDIT) as usize;
        c.max_receive_window = grown;
        c.receive_window = 0;
        c
    }

    #[test]
    fn an_idle_grown_window_gives_its_growth_back_as_credit_is_spent() {
        let acc = Arc::new(Mutex::new(0usize));
        let mib = 1024 * 1024u32;
        let mut c = controller(&acc, 200, 8 * mib);
        c.last_window_update = Instant::now() - Duration::from_secs(5);
        // The reader has consumed everything the sender spent: 8 MiB due, nothing buffered.
        let upd = c.next_window_update(0);
        assert_eq!(c.max_receive_window, DEFAULT_CREDIT);
        assert_eq!(*acc.lock(), 0, "the whole growth is back in the budget");
        // Only the guaranteed window is granted again, never more than the new maximum.
        assert_eq!(upd, Some(DEFAULT_CREDIT));
        assert_eq!(c.receive_window, DEFAULT_CREDIT);
        drop(c);
        assert_eq!(*acc.lock(), 0);
    }

    #[test]
    fn a_shrink_never_drops_below_credit_outstanding_plus_buffered_data() {
        let acc = Arc::new(Mutex::new(0usize));
        let mib = 1024 * 1024u32;
        let mut c = controller(&acc, 200, 8 * mib);
        c.last_window_update = Instant::now() - Duration::from_secs(5);
        c.receive_window = 3 * mib; // the sender still holds 3 MiB of credit
                                    // 5 MiB received, 1 MiB of it still unread: 4 MiB read and due.
        c.next_window_update(mib as usize);
        assert!(c.max_receive_window >= c.receive_window + mib);
        assert_eq!(
            *acc.lock(),
            (c.max_receive_window - DEFAULT_CREDIT) as usize
        );
    }

    #[test]
    fn a_fast_stream_keeps_its_window() {
        let acc = Arc::new(Mutex::new(0usize));
        let mib = 1024 * 1024u32;
        let mut c = controller(&acc, 200, 8 * mib);
        c.last_window_update = Instant::now() - Duration::from_millis(300);
        c.next_window_update(0);
        assert!(
            c.max_receive_window >= 8 * mib,
            "300 ms is not idle at RTT 200 ms"
        );
    }

    #[test]
    fn the_idle_threshold_scales_with_the_rtt_and_has_a_floor_of_one_second() {
        let acc = Arc::new(Mutex::new(0usize));
        let mib = 1024 * 1024u32;
        // RTT 2 s: 5 s is below 4 x RTT = 8 s, so no shrink (kills rtt * 1, a dropped RTT term, min for max).
        let mut c = controller(&acc, 2000, 8 * mib);
        c.last_window_update = Instant::now() - Duration::from_secs(5);
        c.next_window_update(0);
        assert!(c.max_receive_window >= 8 * mib);
        // RTT 10 ms: 1.5 s is above the 1 s floor, so it shrinks (kills a raised floor).
        let acc2 = Arc::new(Mutex::new(0usize));
        let mut c = controller(&acc2, 10, 8 * mib);
        c.last_window_update = Instant::now() - Duration::from_millis(1500);
        c.next_window_update(0);
        assert_eq!(c.max_receive_window, DEFAULT_CREDIT);
        // RTT 10 ms: 0.5 s is below the floor, no shrink.
        let acc3 = Arc::new(Mutex::new(0usize));
        let mut c = controller(&acc3, 10, 8 * mib);
        c.last_window_update = Instant::now() - Duration::from_millis(500);
        c.next_window_update(0);
        assert!(c.max_receive_window >= 8 * mib);
    }

    #[test]
    fn one_idle_gap_shrinks_once_and_a_fast_stream_then_keeps_its_window() {
        let acc = Arc::new(Mutex::new(0usize));
        let mib = 1024 * 1024u32;
        let mut c = controller(&acc, 200, 8 * mib);
        c.last_window_update = Instant::now() - Duration::from_secs(5);
        c.receive_window = 4 * mib; // 4 MiB received and read, 4 MiB credit outstanding
        assert_eq!(
            c.next_window_update(0),
            None,
            "the whole due credit went to the shrink"
        );
        let after = c.max_receive_window;
        assert_eq!(after, 4 * mib);
        // The sender spends half of it at once; the update is due again right away.
        c.receive_window = 2 * mib;
        c.next_window_update(0);
        assert!(
            c.max_receive_window >= after,
            "a fast interval must not shrink again"
        );
    }

    #[test]
    fn the_counter_matches_the_growth_over_a_random_sequence() {
        let mib = 1024 * 1024u32;
        let acc = Arc::new(Mutex::new(0usize));
        let mut c = controller(&acc, 200, 8 * mib);
        let mut x: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..400 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let idle = x % 3 == 0;
            c.last_window_update =
                Instant::now() - Duration::from_millis(if idle { 3000 } else { 50 });
            let buffered = (x >> 8) as u32 % (c.max_receive_window / 2);
            c.receive_window = (x >> 20) as u32 % (c.max_receive_window - buffered);
            c.next_window_update(buffered as usize);
            assert_eq!(
                *acc.lock(),
                (c.max_receive_window - DEFAULT_CREDIT) as usize
            );
            assert!(c.receive_window + buffered <= c.max_receive_window);
        }
        drop(c);
        assert_eq!(*acc.lock(), 0);
    }
}
