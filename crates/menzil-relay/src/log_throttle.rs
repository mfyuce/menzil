//! A small per key throttle for the warn lines a peer's traffic can cause (multi tenant slice
//! MT5, isolation rule I7): a hostile peer must not flood the operator's log, nor hide another
//! peer's warnings behind its own.
//!
//! [`LogThrottle::admit`] says whether a line of some kind about some subject may be written
//! now: the first one is, then at most one per [`INTERVAL`] for the same (kind, subject). The
//! answer carries how many were held back since the last written line, for the line to say so
//! ("and 4000 more"). The subject is a NodeId or an address; once a tenant exists it is the
//! tenant.
//!
//! Memory is bounded per kind (round T3, L2): each kind has a budget of [`MAX_KEYS`] live keys,
//! so a flood of one kind (failed handshakes from fresh IPv6 prefixes, which needs no key at
//! all) can never use up another kind's keys. Past its budget a kind's expired keys are swept
//! (at most once a [`SWEEP_EVERY`]), and if it is still full, new subjects of an address keyed
//! kind ([`LogThrottle::admit`]) share one overflow key of that kind, so a flood of fresh
//! addresses is throttled as one and never grows the map. A kind keyed by NodeId
//! ([`LogThrottle::admit_node`]) has no overflow key: a NodeId reaches these lines only after
//! its HELLO passed, so the NodeIds are bounded by the Rosters the relay holds, and one peer
//! cannot hide another's first warning behind a shared line.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use menzil_proto::NodeId;
use tokio::time::Instant;

/// At most one line per key in this time.
pub(crate) const INTERVAL: Duration = Duration::from_secs(60);

/// Live keys one kind keeps before it sweeps and, if need be, falls back to its overflow key.
pub(crate) const MAX_KEYS: usize = 4096;

/// The shortest time between two sweeps of one kind that found it still full: sweeping on every
/// new subject would make a flood cost a pass over the map each.
pub(crate) const SWEEP_EVERY: Duration = Duration::from_secs(1);

type Key = (&'static str, [u8; 32]);

struct Entry {
    last: Instant,
    held_back: u64,
}

#[derive(Default)]
struct Kind {
    /// Live keys of this kind, the overflow key included.
    live: usize,
    swept: Option<Instant>,
}

#[derive(Default)]
struct State {
    entries: HashMap<Key, Entry>,
    kinds: HashMap<&'static str, Kind>,
}

/// The relay's log throttle, shared by every session.
#[derive(Default)]
pub(crate) struct LogThrottle {
    state: Mutex<State>,
}

impl LogThrottle {
    /// `Some(n)` when a line of `kind` about `subject` (an address key) may be written now, with
    /// `n` the number of such lines held back since the last one that was; `None` when this one
    /// is held back. Past the kind's key budget, new subjects share one overflow key.
    pub(crate) fn admit(&self, kind: &'static str, subject: [u8; 32]) -> Option<u64> {
        self.admit_with(kind, subject, true)
    }

    fn admit_with(&self, kind: &'static str, subject: [u8; 32], overflow: bool) -> Option<u64> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let State { entries, kinds } = &mut *state;
        let mut key = (kind, subject);
        if !entries.contains_key(&key) {
            let info = kinds.entry(kind).or_default();
            if info.live >= MAX_KEYS
                && info
                    .swept
                    .is_none_or(|at| now.saturating_duration_since(at) >= SWEEP_EVERY)
            {
                info.swept = Some(now);
                entries.retain(|(k, _), e| {
                    *k != kind || now.saturating_duration_since(e.last) < INTERVAL
                });
                info.live = entries.keys().filter(|(k, _)| *k == kind).count();
            }
            if info.live >= MAX_KEYS && overflow {
                key = (kind, [0xff; 32]);
            }
            if !entries.contains_key(&key) {
                info.live += 1;
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

    /// [`Self::admit`] for a NodeId: the kind has no overflow key (see the module comment).
    pub(crate) fn admit_node(&self, kind: &'static str, node_id: &NodeId) -> Option<u64> {
        self.admit_with(kind, <[u8; 32]>::from(*node_id), false)
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
        self.state
            .lock()
            .unwrap()
            .entries
            .get(&(kind, subject))
            .map_or(0, |entry| entry.held_back)
    }

    /// Live keys (tests).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.state.lock().unwrap().entries.len()
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

    fn fresh_subject(i: usize) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = 6;
        s[1..9].copy_from_slice(&(i as u64).to_le_bytes());
        s
    }

    /// Round T3, L2: a kind that has used up its keys (failed handshakes from fresh /64s need no
    /// key at all) cannot take another kind's lines: the budget is per kind.
    #[tokio::test(start_paused = true)]
    async fn a_full_kind_does_not_hide_another_kinds_first_line() {
        let throttle = LogThrottle::default();
        for i in 0..MAX_KEYS + 10 {
            throttle.admit("failed_before_attach", fresh_subject(i));
        }
        let attacker = NodeId::from([0xA1; 32]);
        let victim = NodeId::from([0xB2; 32]);
        assert_eq!(throttle.admit_node("doc_refused", &attacker), Some(0));
        assert_eq!(
            throttle.admit_node("doc_refused", &victim),
            Some(0),
            "the victim's first line was held back"
        );
        // An address keyed kind has a budget of its own too, not the full kind's overflow.
        assert_eq!(throttle.admit("other_addr_kind", fresh_subject(1)), Some(0));
        assert_eq!(throttle.admit("other_addr_kind", fresh_subject(2)), Some(0));
    }

    /// Round T3, L2: a kind keyed by NodeId has no shared overflow key: every NodeId gets its
    /// own first line however many are live, and the kind is swept once its lines have expired.
    #[tokio::test(start_paused = true)]
    async fn node_keyed_kinds_never_share_an_overflow_key() {
        let throttle = LogThrottle::default();
        for i in 0..3 * MAX_KEYS {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert_eq!(
                throttle.admit_node("doc_refused", &NodeId::from(id)),
                Some(0),
                "NodeId {i} shared a line"
            );
        }
        assert_eq!(throttle.len(), 3 * MAX_KEYS);
        // Expired, the next new NodeId sweeps them.
        tokio::time::advance(INTERVAL).await;
        assert_eq!(
            throttle.admit_node("doc_refused", &NodeId::from([0xEE; 32])),
            Some(0)
        );
        assert_eq!(throttle.len(), 1);
    }

    /// An address keyed kind past its budget still shares an overflow key of its own kind, and
    /// does not sweep on every new subject (once a second at most).
    #[tokio::test(start_paused = true)]
    async fn an_address_keyed_kind_overflows_within_its_own_kind_only() {
        let throttle = LogThrottle::default();
        for i in 0..MAX_KEYS {
            assert_eq!(
                throttle.admit("failed_before_attach", fresh_subject(i)),
                Some(0)
            );
        }
        assert_eq!(
            throttle.admit("failed_before_attach", fresh_subject(MAX_KEYS)),
            Some(0),
            "the first of the overflow"
        );
        assert_eq!(
            throttle.admit("failed_before_attach", fresh_subject(MAX_KEYS + 1)),
            None,
            "the rest share it"
        );
        assert_eq!(throttle.admit("other_kind", fresh_subject(0)), Some(0));
        assert!(throttle.len() <= MAX_KEYS + 2);
    }
}
