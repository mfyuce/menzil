//! Per-peer credit accounting (protocol.md 4.2's flow-control
//! paragraph): a reliable SEND consumes credit, CREDIT records grant
//! more. Just the counter — how a relay computes what to grant and
//! when, and any per-(source,destination) queue or token-bucket
//! machinery around it, is a session-registry concern (TODO.md L3e), not
//! this crate's.

use crate::error::SessionError;

/// A per-peer credit balance in bytes (protocol.md 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditLedger {
    remaining: u32,
}

impl CreditLedger {
    /// Starts a ledger with `initial` bytes of credit (protocol.md 4.2:
    /// WELCOME's `limits.credit`, default 1 MiB).
    pub fn new(initial: u32) -> Self {
        Self { remaining: initial }
    }

    /// The current balance.
    pub fn remaining(&self) -> u32 {
        self.remaining
    }

    /// Consumes `amount` for an outgoing reliable SEND. Fails, rather
    /// than underflowing, if `amount` exceeds the remaining balance
    /// (protocol.md 4.2: "a reliable SEND beyond credit is a protocol
    /// violation and closes the session" — this type only reports the
    /// violation; closing the session is the caller's job).
    pub fn consume(&mut self, amount: u32) -> Result<(), SessionError> {
        match self.remaining.checked_sub(amount) {
            Some(rest) => {
                self.remaining = rest;
                Ok(())
            }
            None => Err(SessionError::CreditExceeded {
                requested: amount,
                remaining: self.remaining,
            }),
        }
    }

    /// Grants `amount` more credit (protocol.md 4.2: "replenished as
    /// bytes are written to the destination socket"), saturating rather
    /// than overflowing at `u32::MAX`.
    pub fn grant(&mut self, amount: u32) {
        self.remaining = self.remaining.saturating_add(amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_within_balance_succeeds() {
        let mut ledger = CreditLedger::new(100);
        ledger.consume(60).unwrap();
        assert_eq!(ledger.remaining(), 40);
    }

    #[test]
    fn consume_beyond_balance_fails_without_underflowing() {
        let mut ledger = CreditLedger::new(100);
        let err = ledger.consume(101).unwrap_err();
        assert!(matches!(
            err,
            SessionError::CreditExceeded {
                requested: 101,
                remaining: 100
            }
        ));
        // The failed attempt must not have touched the balance.
        assert_eq!(ledger.remaining(), 100);
    }

    #[test]
    fn grant_saturates_instead_of_overflowing() {
        let mut ledger = CreditLedger::new(u32::MAX - 1);
        ledger.grant(10);
        assert_eq!(ledger.remaining(), u32::MAX);
    }

    #[test]
    fn grant_then_consume_round_trips() {
        let mut ledger = CreditLedger::new(0);
        ledger.grant(1_048_576);
        ledger.consume(1_048_576).unwrap();
        assert_eq!(ledger.remaining(), 0);
    }
}
