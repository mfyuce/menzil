//! `ServiceId = kind ":" label` (protocol.md 2.4): every example the spec
//! gives (`tcp:ssh`, `udp:wg`, `egress:*`, ...) is a single colon-joined
//! string, so that is the wire form here too, not a CBOR map.

use std::fmt;
use std::str::FromStr;

use serde::de::{Deserialize, Deserializer, Error as DeError};
use serde::ser::{Serialize, Serializer};
use thiserror::Error;

/// `kind = "tcp" | "udp" | "http" | "tls" | "egress" | "acme-http" | "menzil"`
/// (protocol.md 2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceKind {
    /// Raw TCP.
    Tcp,
    /// Raw UDP.
    Udp,
    /// HTTP, unterminated by the relay.
    Http,
    /// TLS, terminated by the node.
    Tls,
    /// The egress (S3) exit service.
    Egress,
    /// The HTTP-01 ACME challenge responder.
    AcmeHttp,
    /// Reserved for menzil's own services (for example `menzil:docs`,
    /// protocol.md 5.5).
    Menzil,
}

/// A `kind` token that isn't one of protocol.md 2.4's seven literals.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown service kind {0:?}")]
pub struct UnknownServiceKind(pub String);

impl ServiceKind {
    /// The literal wire token, e.g. `"tcp"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Egress => "egress",
            Self::AcmeHttp => "acme-http",
            Self::Menzil => "menzil",
        }
    }
}

impl FromStr for ServiceKind {
    type Err = UnknownServiceKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "http" => Ok(Self::Http),
            "tls" => Ok(Self::Tls),
            "egress" => Ok(Self::Egress),
            "acme-http" => Ok(Self::AcmeHttp),
            "menzil" => Ok(Self::Menzil),
            other => Err(UnknownServiceKind(other.to_string())),
        }
    }
}

impl fmt::Display for ServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parse failure for a `kind:label` [`ServiceId`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServiceIdParseError {
    /// There was no `:` separating a kind from a label.
    #[error("service id {0:?} has no ':' separating kind from label")]
    MissingSeparator(String),
    /// The kind before the `:` was not recognized.
    #[error(transparent)]
    UnknownKind(#[from] UnknownServiceKind),
}

/// `tcp:ssh`, `udp:wg`, `http:app`, `egress:*`, ... (protocol.md 2.4). The
/// label is kept as an opaque string: whether `*` is meaningful, and the
/// LDH-label rule for advertised public names, are policy the relay and
/// node apply (protocol.md 4.4), not a constraint this wire type enforces.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceId {
    /// The service's kind.
    pub kind: ServiceKind,
    /// The service's label, opaque to this type (may be `"*"` in a
    /// pattern context).
    pub label: String,
}

/// Wire-identical to [`ServiceId`]; kept as a separate name only for
/// where it appears (protocol.md 2.4's `ServicePattern`, e.g. inside a
/// [`crate::network::Grant`]), since the label there is contextually a
/// pattern that may be `"*"`.
pub type ServicePattern = ServiceId;

impl ServiceId {
    /// Builds a service id from its parts.
    pub fn new(kind: ServiceKind, label: impl Into<String>) -> Self {
        Self {
            kind,
            label: label.into(),
        }
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.label)
    }
}

impl FromStr for ServiceId {
    type Err = ServiceIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (kind, label) = s
            .split_once(':')
            .ok_or_else(|| ServiceIdParseError::MissingSeparator(s.to_string()))?;
        Ok(Self {
            kind: kind.parse()?,
            label: label.to_string(),
        })
    }
}

impl Serialize for ServiceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ServiceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(DeError::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_display_and_from_str() {
        for s in [
            "tcp:ssh",
            "udp:wg",
            "http:app",
            "tls:app",
            "egress:*",
            "acme-http:app",
            "menzil:docs",
        ] {
            let id: ServiceId = s.parse().unwrap();
            assert_eq!(id.to_string(), s);
        }
    }

    #[test]
    fn rejects_unknown_kind() {
        assert!("ftp:app".parse::<ServiceId>().is_err());
    }

    #[test]
    fn rejects_missing_separator() {
        assert!("tcpssh".parse::<ServiceId>().is_err());
    }

    #[test]
    fn round_trips_through_cbor_as_a_single_text_string() {
        let id = ServiceId::new(ServiceKind::Egress, "*");
        let mut buf = Vec::new();
        ciborium::into_writer(&id, &mut buf).unwrap();
        let mut expected = Vec::new();
        ciborium::into_writer(&"egress:*", &mut expected).unwrap();
        assert_eq!(buf, expected);
        let decoded: ServiceId = ciborium::from_reader(&buf[..]).unwrap();
        assert_eq!(decoded, id);
    }
}
