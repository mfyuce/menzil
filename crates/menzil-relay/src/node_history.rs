//! Per-NodeId replay-defense state the relay must remember across
//! reconnects for as long as it keeps running (protocol.md 4.1: "rejects
//! a serial lower than the highest it has seen", "rejects a `timestamp`
//! not greater than the last accepted for that NodeId").
//!
//! In-memory only, lost on restart: no persistent identity/state store
//! exists yet — the same gap `menzil-node` flags for its own side of
//! HELLO's `timestamp`. A restarted relay accepts the first serial and
//! timestamp it sees from a NodeId again, exactly as if that NodeId were
//! new to it.

use std::collections::HashMap;
use std::sync::RwLock;

use menzil_proto::{NodeId, Tai64N};

/// Which check failed, from [`NodeHistory::check_and_record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryViolation {
    /// The serial was lower than the highest previously accepted for
    /// this NodeId.
    StaleSerial,
    /// The timestamp was not strictly greater than the last accepted
    /// for this NodeId.
    StaleTimestamp,
}

/// How many NodeIds the history remembers before it starts evicting (MT4, threat A9). Only a
/// NodeId listed in a held Roster reaches the history (HELLO's standing check runs first), but
/// Rosters come from tenants and members leave, so the table needs a bound of its own.
pub const MAX_HISTORY_ENTRIES: usize = 65_536;

#[derive(Clone, Copy)]
struct Entry {
    serial: u32,
    timestamp: [u8; 12],
    /// The write counter value of the last time this entry was written: the age used to pick
    /// what to evict first.
    touched: u64,
}

#[derive(Default)]
struct State {
    seen: HashMap<NodeId, Entry>,
    clock: u64,
    /// While a sweep could not bring the table down to its target because of vouched-for
    /// entries, the size at which the next sweep is worth running (so a table full of members is
    /// not swept on every insert). Zero when the last sweep reached its target.
    sweep_at: usize,
}

/// The relay's per-NodeId high-water marks.
///
/// Bounded at `capacity` entries (default [`MAX_HISTORY_ENTRIES`]). When a new NodeId would
/// push the table over its bound, the oldest entries of NodeIds that the caller no longer
/// vouches for (see [`NodeHistory::check_and_record_retaining`]) are dropped until the table is
/// at seven eighths of the bound, so the cost of the sweep is spread over many inserts. Entries
/// the caller vouches for (NodeIds listed in a Roster the relay holds) are never evicted; if
/// they alone fill the table it grows past the bound, as the Rosters themselves bound it. An
/// evicted NodeId loses its replay marks: its next HELLO is accepted as a first one, which is
/// no worse than after a relay restart (this table is in memory only, see the module comment),
/// and it can only happen to a NodeId that no held Roster lists, which cannot attach anyway.
pub struct NodeHistory {
    state: RwLock<State>,
    capacity: usize,
}

impl Default for NodeHistory {
    fn default() -> Self {
        Self::with_capacity(MAX_HISTORY_ENTRIES)
    }
}

impl NodeHistory {
    /// No history for any NodeId yet, bounded at [`MAX_HISTORY_ENTRIES`].
    pub fn new() -> Self {
        Self::default()
    }

    /// No history yet, bounded at `capacity` entries (at least 8).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            state: RwLock::new(State::default()),
            capacity: capacity.max(8),
        }
    }

    /// How many NodeIds have marks right now.
    pub fn len(&self) -> usize {
        self.state.read().unwrap().seen.len()
    }

    /// Whether no NodeId has marks.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// [`Self::check_and_record_retaining`] that vouches for nobody: when the table is full the
    /// oldest entries go first, whoever they belong to.
    pub fn check_and_record(
        &self,
        node_id: NodeId,
        serial: u32,
        timestamp: Tai64N,
    ) -> Result<(), HistoryViolation> {
        self.check_and_record_retaining(node_id, serial, timestamp, |_| false)
    }

    /// Checks `serial` and `timestamp` against this NodeId's high-water
    /// marks, atomically recording both as the new marks only if *both*
    /// checks pass. A HELLO that fails here for either reason leaves the
    /// recorded marks untouched: "last accepted", not "last attempted"
    /// (protocol.md 4.1's own wording for the timestamp check; applied
    /// the same way to the serial mark here for one simple, consistent
    /// rule, since a HELLO that is ultimately rejected — for this or any
    /// other reason — never actually gets a session, so there is nothing
    /// for a future comparison to need to have "seen" from it).
    ///
    /// `retain` says which NodeIds must survive an eviction (the ones a held Roster lists); it
    /// is called only when the table is over its bound, with the history locked, so it must be
    /// quick and must not call back into this history.
    pub fn check_and_record_retaining(
        &self,
        node_id: NodeId,
        serial: u32,
        timestamp: Tai64N,
        retain: impl Fn(&NodeId) -> bool,
    ) -> Result<(), HistoryViolation> {
        let timestamp_bytes = <[u8; 12]>::from(timestamp);
        let mut guard = self.state.write().unwrap();
        if let Some(entry) = guard.seen.get(&node_id) {
            if serial < entry.serial {
                return Err(HistoryViolation::StaleSerial);
            }
            if timestamp_bytes <= entry.timestamp {
                return Err(HistoryViolation::StaleTimestamp);
            }
        } else if guard.seen.len() >= self.capacity.max(guard.sweep_at) {
            Self::evict(&mut guard, self.capacity, &retain);
        }
        guard.clock += 1;
        let touched = guard.clock;
        guard.seen.insert(
            node_id,
            Entry {
                serial,
                timestamp: timestamp_bytes,
                touched,
            },
        );
        Ok(())
    }

    /// Drops the oldest entries `retain` does not vouch for, down to seven eighths of
    /// `capacity` (or as far as the unvouched entries go).
    fn evict(state: &mut State, capacity: usize, retain: &impl Fn(&NodeId) -> bool) {
        let target = capacity - capacity / 8;
        let mut evictable: Vec<(u64, NodeId)> = state
            .seen
            .iter()
            .filter(|(id, _)| !retain(id))
            .map(|(id, entry)| (entry.touched, *id))
            .collect();
        evictable.sort_unstable_by_key(|(touched, _)| *touched);
        let excess = state.seen.len().saturating_sub(target);
        for (_, id) in evictable.into_iter().take(excess) {
            state.seen.remove(&id);
        }
        // A sweep that did not reach its target (the rest is vouched for) waits for the table to
        // grow by an eighth of the bound before the next one, wherever the table stands: just
        // below the bound as much as at or above it (round T3, L1), or every fresh insert would
        // scan the whole table under the write lock.
        state.sweep_at = if state.seen.len() > target {
            state.seen.len() + capacity / 8
        } else {
            0
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(seconds_byte: u8) -> Tai64N {
        let mut bytes = [0u8; 12];
        bytes[7] = seconds_byte;
        Tai64N::from(bytes)
    }

    #[test]
    fn first_hello_from_a_node_always_succeeds() {
        let history = NodeHistory::new();
        assert!(
            history
                .check_and_record(NodeId::from([1u8; 32]), 1, ts(10))
                .is_ok()
        );
    }

    #[test]
    fn equal_serial_with_a_later_timestamp_succeeds() {
        let history = NodeHistory::new();
        let node_id = NodeId::from([1u8; 32]);
        history.check_and_record(node_id, 5, ts(10)).unwrap();
        assert!(history.check_and_record(node_id, 5, ts(11)).is_ok());
    }

    #[test]
    fn a_lower_serial_is_rejected() {
        let history = NodeHistory::new();
        let node_id = NodeId::from([1u8; 32]);
        history.check_and_record(node_id, 5, ts(10)).unwrap();
        assert_eq!(
            history.check_and_record(node_id, 4, ts(20)),
            Err(HistoryViolation::StaleSerial)
        );
    }

    #[test]
    fn a_non_increasing_timestamp_is_rejected() {
        let history = NodeHistory::new();
        let node_id = NodeId::from([1u8; 32]);
        history.check_and_record(node_id, 5, ts(10)).unwrap();
        assert_eq!(
            history.check_and_record(node_id, 5, ts(10)),
            Err(HistoryViolation::StaleTimestamp)
        );
        assert_eq!(
            history.check_and_record(node_id, 5, ts(9)),
            Err(HistoryViolation::StaleTimestamp)
        );
    }

    #[test]
    fn a_rejected_attempt_does_not_move_the_high_water_marks() {
        let history = NodeHistory::new();
        let node_id = NodeId::from([1u8; 32]);
        history.check_and_record(node_id, 5, ts(10)).unwrap();
        // This attempt has a higher serial but a stale timestamp: it
        // must be rejected, and must not raise the recorded serial
        // either, so a later, well-formed HELLO with serial 5 (still
        // above the *original* mark) is unaffected either way — the
        // real assertion is that the timestamp comparison below still
        // uses `ts(10)`, not the failed attempt's `ts(5)`.
        assert_eq!(
            history.check_and_record(node_id, 9, ts(5)),
            Err(HistoryViolation::StaleTimestamp)
        );
        assert!(history.check_and_record(node_id, 5, ts(11)).is_ok());
    }

    #[test]
    fn different_nodes_have_independent_history() {
        let history = NodeHistory::new();
        history
            .check_and_record(NodeId::from([1u8; 32]), 9, ts(10))
            .unwrap();
        assert!(
            history
                .check_and_record(NodeId::from([2u8; 32]), 1, ts(1))
                .is_ok()
        );
    }

    fn key(n: u32) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        bytes[31] = 0xEE;
        NodeId::from(bytes)
    }

    /// MT4, threat A9: 100,000 fresh keys leave the table at its bound, and the entries the
    /// caller vouches for (the first, and so the oldest, ones) survive every eviction: their
    /// replay marks still refuse a stale serial.
    #[test]
    fn history_stays_at_its_bound_under_100_000_fresh_keys_while_members_survive() {
        let history = NodeHistory::new();
        let members: Vec<NodeId> = (0..3).map(|n| key(1_000_000 + n)).collect();
        let is_member = |id: &NodeId| members.contains(id);
        for member in &members {
            history
                .check_and_record_retaining(*member, 7, ts(10), is_member)
                .unwrap();
        }
        let mut peak = 0;
        for n in 0..100_000u32 {
            history
                .check_and_record_retaining(key(n), 1, ts(10), is_member)
                .unwrap();
            peak = peak.max(history.len());
        }
        assert!(
            peak <= MAX_HISTORY_ENTRIES,
            "the table reached {peak} entries, bound {MAX_HISTORY_ENTRIES}"
        );
        assert!(
            history.len() > MAX_HISTORY_ENTRIES / 2,
            "not emptied wholesale"
        );
        for member in &members {
            assert_eq!(
                history.check_and_record_retaining(*member, 6, ts(11), is_member),
                Err(HistoryViolation::StaleSerial),
                "a member's replay mark must survive eviction"
            );
        }
        // The oldest fresh keys were evicted first (they are not members): their marks are
        // gone, so the same HELLO is accepted as a first one. The newest are still held.
        assert!(
            history
                .check_and_record_retaining(key(0), 1, ts(10), is_member)
                .is_ok()
        );
        assert_eq!(
            history.check_and_record_retaining(key(99_999), 1, ts(10), is_member),
            Err(HistoryViolation::StaleTimestamp)
        );
    }

    #[test]
    fn eviction_goes_oldest_first_and_a_touched_entry_counts_as_young() {
        let history = NodeHistory::with_capacity(16);
        let nobody = |_: &NodeId| false;
        for n in 0..16 {
            history
                .check_and_record_retaining(key(n), 1, ts(10), nobody)
                .unwrap();
        }
        // Key 0 reconnects: it is now the youngest.
        history
            .check_and_record_retaining(key(0), 1, ts(11), nobody)
            .unwrap();
        // A new key pushes the table over: down to 14 (7/8 of 16), then the new one is added.
        history
            .check_and_record_retaining(key(100), 1, ts(10), nobody)
            .unwrap();
        assert_eq!(history.len(), 15);
        assert_eq!(
            history.check_and_record_retaining(key(0), 1, ts(11), nobody),
            Err(HistoryViolation::StaleTimestamp),
            "the touched entry survived"
        );
        assert!(
            history
                .check_and_record_retaining(key(1), 1, ts(10), nobody)
                .is_ok(),
            "an old untouched entry was evicted"
        );
    }

    #[test]
    fn a_table_full_of_vouched_entries_grows_and_is_not_swept_on_every_insert() {
        let history = NodeHistory::with_capacity(64);
        let everyone = |_: &NodeId| true;
        let swept = std::cell::Cell::new(0u32);
        let counting = |_: &NodeId| {
            swept.set(swept.get() + 1);
            true
        };
        for n in 0..64 {
            history
                .check_and_record_retaining(key(n), 1, ts(10), everyone)
                .unwrap();
        }
        for n in 64..164 {
            history
                .check_and_record_retaining(key(n), 1, ts(10), counting)
                .unwrap();
        }
        assert_eq!(history.len(), 164, "vouched entries are never evicted");
        // A sweep on every one of the 100 inserts would make about 11,400 retain calls (the sum
        // of the table sizes); one per 8 entries of growth makes about a tenth of that.
        assert!(swept.get() < 3_000, "{} retain calls", swept.get());
    }

    /// Round T3, L1: vouched entries just below the bound used to make every fresh insert a full
    /// sweep (`sweep_at` was reset to zero whenever the sweep left the table under the bound).
    #[test]
    fn vouched_entries_just_below_the_bound_do_not_make_every_insert_a_sweep() {
        let cap = 128usize;
        let history = NodeHistory::with_capacity(cap);
        let vouched: std::collections::HashSet<NodeId> = (0..cap as u32 - 1).map(key).collect();
        for id in &vouched {
            history
                .check_and_record_retaining(*id, 1, ts(10), |_| true)
                .unwrap();
        }
        let calls = std::cell::Cell::new(0u64);
        let counting = |id: &NodeId| {
            calls.set(calls.get() + 1);
            vouched.contains(id)
        };
        for n in 0..400u32 {
            history
                .check_and_record_retaining(key(5_000_000 + n), 1, ts(10), counting)
                .unwrap();
            assert!(history.len() <= cap + cap / 8, "len {}", history.len());
        }
        // A sweep on every insert is about 400 * 128 = 51,000 calls; one per eighth of the
        // bound of growth is about 400 / 16 * 143 = 3,600.
        assert!(
            calls.get() < 10_000,
            "{} retain calls for 400 inserts",
            calls.get()
        );
        for id in &vouched {
            assert_eq!(
                history.check_and_record_retaining(*id, 0, ts(11), |_| true),
                Err(HistoryViolation::StaleSerial),
                "a vouched entry was evicted"
            );
        }
    }
}
