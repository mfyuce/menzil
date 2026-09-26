//! Node and client roles for menzil.
//!
//! Maintains the local service registry, dials out to the relay to
//! publish or reach services, and hosts the SOCKS executor and the SSH
//! stdio mode used by the client side commands.

#![forbid(unsafe_code)]

/// Placeholder node handle. Will grow the service registry and dial out
/// logic once the carrier and proto crates are wired in.
#[derive(Debug, Default)]
pub struct Node;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_can_be_constructed() {
        let node = Node;
        assert_eq!(format!("{node:?}"), "Node");
    }
}
