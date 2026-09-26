//! Outer transport carrier for menzil.
//!
//! Carries bytes for the relay, node, and client roles over TLS on port
//! 443, through corporate HTTP CONNECT proxies when present, on top of
//! WebSocket today and an HTTP/2 upgrade later. Handles keepalive and
//! reconnection, and exposes a single Stream abstraction so upper layers
//! do not need to know which underlying transport is in use.

#![forbid(unsafe_code)]

/// Placeholder for the carrier entry point. Construction will grow
/// configuration, such as the proxy address, TLS settings, and the
/// keepalive interval, once the transport implementation lands.
#[derive(Debug, Default)]
pub struct Carrier;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_can_be_constructed() {
        let carrier = Carrier;
        assert_eq!(format!("{carrier:?}"), "Carrier");
    }
}
