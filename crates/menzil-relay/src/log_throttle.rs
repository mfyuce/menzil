//! A small per key throttle for the warn lines a peer's traffic can cause (multi tenant slice
//! MT5, isolation rule I7): a hostile peer must not flood the operator's log, nor hide another
//! peer's warnings behind its own.
//!
//! [`LogThrottle::admit`] says whether a line of some kind about some subject may be written
//! now: the first one is, then at most one per [`INTERVAL`] for the same (kind, subject). The
//! answer carries how many were held back since the last written line, for the line to say so
//! ("and 4000 more"). The subject is a NodeId or an address; once a tenant exists it is the
//! tenant. Memory is bounded: past [`MAX_KEYS`] live keys, the expired ones are swept, and if
//! the map is still full, new subjects of a kind share one overflow key per kind (so a flood
//! of fresh subjects is throttled as one, never grows the map).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use menzil_proto::NodeId;
use tokio::time::Instant;

/// At most one line per key in this time.
pub(crate) const INTERVAL: Duration = Duration::from_secs(60);

/// Live keys the map keeps before it sweeps and, if need be, falls back to the overflow key.
pub(crate) const MAX_KEYS: usize = 4096;

type Key = (&'static str, [u8; 32]);

struct Entry {
    last: Instant,
    held_back: u64,
}

/// The relay's log throttle, shared by every session.
#[derive(Default)]
pub(crate) struct LogThrottle {
    entries: Mutex<HashMap<Key, Entry>>,
}

impl LogThrottle {
    /// `Some(n)` when a line of `kind` about `subject` may be written now, with `n` the number
    /// of such lines held back since the last one that was; `None` when this one is held back.
    pub(crate) fn admit(&self, kind: &'static str, subject: [u8; 32]) -> Option<u64> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap();
        let mut key = (kind, subject);
        if !entries.contains_key(&key) && entries.len() >= MAX_KEYS {
            entries.retain(|_, e| now.saturating_duration_since(e.last) < INTERVAL);
            if entries.len() >= MAX_KEYS {
                key = (kind, [0xff; 32]);
            }
        }
        match entries.get_mut(&key) {
            None => {
                entries.insert(
                    key,
                    Entry {
                        last: now,
                        held_back: 0,
                    },
                );
                Some(0)
            }
            Some(entry) if now.saturating_duration_since(entry.last) >= INTERVAL => {
                let held_back = entry.held_back;
                entry.last = now;
                entry.held_back = 0;
                Some(held_back)
            }
            Some(entry) => {
                entry.held_back += 1;
                None
            }
        }
    }

    /// [`Self::admit`] for a NodeId.
    pub(crate) fn admit_node(&self, kind: &'static str, node_id: &NodeId) -> Option<u64> {
        self.admit(kind, <[u8; 32]>::from(*node_id))
    }

    /// This throttle, for lines about `node_id`.
    pub(crate) fn about<'a>(&'a self, node_id: &NodeId) -> NodeLog<'a> {
        NodeLog {
            throttle: self,
            node_id: *node_id,
        }
    }

    /// Lines of `kind` about `node_id` held back since the last one written (tests).
    #[cfg(test)]
    pub(crate) fn held_back(&self, kind: &'static str, node_id: &NodeId) -> u64 {
        self.held_back_for(kind, <[u8; 32]>::from(*node_id))
    }

    /// [`Self::held_back`] for any subject key (tests).
    #[cfg(test)]
    pub(crate) fn held_back_for(&self, kind: &'static str, subject: [u8; 32]) -> u64 {
        self.entries
            .lock()
            .unwrap()
            .get(&(kind, subject))
            .map_or(0, |entry| entry.held_back)
    }

    /// Live keys (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

/// A [`LogThrottle`] bound to one NodeId, for code that logs about the peer it is serving
/// (`crate::doc`) without knowing the relay.
#[derive(Clone, Copy)]
pub(crate) struct NodeLog<'a> {
    throttle: &'a LogThrottle,
    node_id: NodeId,
}

impl NodeLog<'_> {
    /// See [`LogThrottle::admit_node`].
    pub(crate) fn admit(&self, kind: &'static str) -> Option<u64> {
        self.throttle.admit_node(kind, &self.node_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[tokio::test(start_paused = true)]
    async fn one_line_a_minute_per_key_with_the_count_held_back() {
        let throttle = LogThrottle::default();
        assert_eq!(throttle.admit("doc", subject(1)), Some(0));
        for _ in 0..500 {
            assert_eq!(throttle.admit("doc", subject(1)), None);
        }
        tokio::time::advance(INTERVAL - Duration::from_millis(1)).await;
        assert_eq!(throttle.admit("doc", subject(1)), None);
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            throttle.admit("doc", subject(1)),
            Some(501),
            "the line says how many were held back"
        );
        assert_eq!(throttle.admit("doc", subject(1)), None);
    }

    #[tokio::test(start_paused = true)]
    async fn another_subject_or_kind_is_not_held_back_by_a_noisy_one() {
        let throttle = LogThrottle::default();
        assert_eq!(throttle.admit("doc", subject(1)), Some(0));
        for _ in 0..50 {
            assert_eq!(throttle.admit("doc", subject(1)), None);
        }
        assert_eq!(throttle.admit("doc", subject(2)), Some(0));
        assert_eq!(throttle.admit("advertise", subject(1)), Some(0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_of_fresh_subjects_cannot_grow_the_map_or_write_unbounded_lines() {
        let throttle = LogThrottle::default();
        let mut written = 0usize;
        for i in 0..(MAX_KEYS * 3) {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&(i as u64).to_le_bytes());
            if throttle.admit("doc", s).is_some() {
                written += 1;
            }
        }
        assert_eq!(
            written,
            MAX_KEYS + 1,
            "one line per live key, then one more for the shared overflow key"
        );
        assert!(throttle.len() <= MAX_KEYS + 1);
        // Once the entries are old, the sweep makes room again.
        tokio::time::advance(INTERVAL).await;
        assert_eq!(throttle.admit("doc", subject(9)), Some(0));
        assert!(throttle.len() <= 2);
    }
}
