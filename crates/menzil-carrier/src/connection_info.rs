//! Connection information (protocol.md 3.2):
//! `menzil://relay.example:443/_menzil/v1?id=<relay NodeId hex>[&key=<relay x25519 hex>]`.
//!
//! Exchanged out of band (typed, pasted, QR) and never fetched through the
//! path it protects; this module only parses the string form.

use menzil_proto::{NodeId, X25519PublicKey};
use url::Url;

use crate::error::CarrierError;

/// The default WebSocket path (protocol.md 3.1 step 4), used when a parsed
/// URL carries an empty path.
pub const DEFAULT_PATH: &str = "/_menzil/v1";

/// A parsed `menzil://` connection string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// The relay's host name or IP address.
    pub host: String,
    /// The relay's port.
    pub port: u16,
    /// The WebSocket upgrade path, operator configurable.
    pub path: String,
    /// The anchor: the relay's NodeId, verified at the L3 handshake
    /// (protocol.md 4.1).
    pub relay_node_id: NodeId,
    /// A cached X25519 static key enabling the one round trip IK
    /// handshake; `None` (or stale) falls back to XX (protocol.md 3.2,
    /// 4.1). Only the L3 layer, not built yet, acts on staleness.
    pub relay_x25519: Option<X25519PublicKey>,
}

impl ConnectionInfo {
    /// Parses a `menzil://...` connection string.
    pub fn parse(raw: &str) -> Result<Self, CarrierError> {
        let url = Url::parse(raw).map_err(|e| CarrierError::ConnectionInfo(e.to_string()))?;
        if url.scheme() != "menzil" {
            return Err(CarrierError::ConnectionInfo(format!(
                "unexpected scheme {:?}, want \"menzil\"",
                url.scheme()
            )));
        }
        let host = url
            .host_str()
            .ok_or_else(|| CarrierError::ConnectionInfo("missing host".to_string()))?
            .to_string();
        let port = url.port().unwrap_or(443);
        let path = match url.path() {
            "" => DEFAULT_PATH.to_string(),
            p => p.to_string(),
        };

        let mut relay_node_id = None;
        let mut relay_x25519 = None;
        for (key, value) in url.query_pairs() {
            match &*key {
                "id" => {
                    let bytes = parse_hex32(&value)
                        .map_err(|e| CarrierError::ConnectionInfo(format!("bad id: {e}")))?;
                    relay_node_id = Some(NodeId::from(bytes));
                }
                "key" => {
                    let bytes = parse_hex32(&value)
                        .map_err(|e| CarrierError::ConnectionInfo(format!("bad key: {e}")))?;
                    relay_x25519 = Some(X25519PublicKey::from(bytes));
                }
                _ => {}
            }
        }
        let relay_node_id = relay_node_id.ok_or_else(|| {
            CarrierError::ConnectionInfo("missing required \"id\" query parameter".to_string())
        })?;

        Ok(Self {
            host,
            port,
            path,
            relay_node_id,
            relay_x25519,
        })
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| format!("invalid hex at byte {i}"))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(byte: u8) -> String {
        (0..32).map(|_| format!("{byte:02x}")).collect()
    }

    #[test]
    fn parses_full_connection_info() {
        let id = hex32(0x11);
        let key = hex32(0x22);
        let raw = format!("menzil://relay.example:443/_menzil/v1?id={id}&key={key}");
        let info = ConnectionInfo::parse(&raw).unwrap();
        assert_eq!(info.host, "relay.example");
        assert_eq!(info.port, 443);
        assert_eq!(info.path, "/_menzil/v1");
        assert_eq!(info.relay_node_id, NodeId::from([0x11u8; 32]));
        assert_eq!(info.relay_x25519, Some(X25519PublicKey::from([0x22u8; 32])));
    }

    #[test]
    fn key_is_optional() {
        let id = hex32(0x33);
        let raw = format!("menzil://relay.example:443/_menzil/v1?id={id}");
        let info = ConnectionInfo::parse(&raw).unwrap();
        assert_eq!(info.relay_x25519, None);
    }

    #[test]
    fn defaults_path_and_port_when_absent() {
        let id = hex32(0x44);
        let raw = format!("menzil://relay.example?id={id}");
        let info = ConnectionInfo::parse(&raw).unwrap();
        assert_eq!(info.port, 443);
        assert_eq!(info.path, DEFAULT_PATH);
    }

    #[test]
    fn missing_id_is_rejected() {
        let raw = "menzil://relay.example:443/_menzil/v1";
        assert!(ConnectionInfo::parse(raw).is_err());
    }

    #[test]
    fn malformed_hex_is_rejected() {
        let raw = "menzil://relay.example:443/_menzil/v1?id=not-hex";
        assert!(ConnectionInfo::parse(raw).is_err());
    }

    #[test]
    fn wrong_scheme_is_rejected() {
        let id = hex32(0x55);
        let raw = format!("https://relay.example:443/_menzil/v1?id={id}");
        assert!(ConnectionInfo::parse(&raw).is_err());
    }
}
