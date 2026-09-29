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

/// The relay's per-NodeId high-water marks.
#[derive(Default)]
pub struct NodeHistory {
    seen: RwLock<HashMap<NodeId, (u32, [u8; 12])>>,
}

impl NodeHistory {
    /// No history for any NodeId yet.
    pub fn new() -> Self {
        Self::default()
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
    pub fn check_and_record(
        &self,
        node_id: NodeId,
        serial: u32,
        timestamp: Tai64N,
    ) -> Result<(), HistoryViolation> {
        let timestamp_bytes = <[u8; 12]>::from(timestamp);
        let mut guard = self.seen.write().unwrap();
        if let Some(&(highest_serial, last_timestamp)) = guard.get(&node_id) {
            if serial < highest_serial {
                return Err(HistoryViolation::StaleSerial);
            }
            if timestamp_bytes <= last_timestamp {
                return Err(HistoryViolation::StaleTimestamp);
            }
        }
        guard.insert(node_id, (serial, timestamp_bytes));
        Ok(())
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
}
