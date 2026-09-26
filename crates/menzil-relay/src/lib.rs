//! Blind relay role for menzil.
//!
//! Keeps a session registry keyed by node identity, routes streams
//! between nodes and clients without inspecting their contents, and
//! passes SNI through untouched for public shares so the relay never
//! terminates TLS on behalf of a service. Also hosts the ACME hooks used
//! to obtain certificates for relay controlled names.

#![forbid(unsafe_code)]

/// Placeholder session registry. Will map node identities to their
/// active sessions once the transport and protocol crates are wired in.
#[derive(Debug, Default)]
pub struct Relay;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_can_be_constructed() {
        let relay = Relay;
        assert_eq!(format!("{relay:?}"), "Relay");
    }
}
