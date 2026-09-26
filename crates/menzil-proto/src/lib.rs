//! Wire types, framing, and versioning for the menzil protocol.
//!
//! This crate defines the (node, service) addressing scheme and the
//! policy input types shared by the relay, node, and client roles. It
//! has no transport or async runtime dependencies: it only describes
//! bytes on the wire and the identifiers used to route them.

#![forbid(unsafe_code)]

/// Current wire protocol version, bumped whenever the framing format
/// changes in a way that is not backward compatible.
pub const PROTOCOL_VERSION: u16 = 1;

/// Address of a service published by a node, used by the relay to route
/// streams and by clients to name a reach or expose target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// Identity of the node hosting the service.
    pub node: String,
    /// Name of the service on that node.
    pub service: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_round_trips_its_fields() {
        let addr = Address {
            node: "node-a".to_string(),
            service: "ssh".to_string(),
        };
        assert_eq!(addr.node, "node-a");
        assert_eq!(addr.service, "ssh");
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
