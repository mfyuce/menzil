//! Networks, rosters, and policies (protocol.md 2.3): the owner-signed
//! documents that describe who belongs to a network and what they may do.

use std::fmt;

use serde::de::{Deserializer, Error as DeError, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};

use crate::bytes::{NetworkId, NodeId, StewardKey};
use crate::identity::NodeCert;
use crate::service::ServicePattern;
use crate::signed::{Signed, SignedBody, TAG_POLICY, TAG_ROSTER, TAG_STEWARD};

/// One entry of a [`RosterBody`]'s `members` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterMember {
    /// The member's node identity.
    pub node_id: NodeId,
    /// The lowest [`crate::identity::NodeCertBody::serial`] still
    /// accepted for this member; used to kill stale certificates ahead
    /// of full revocation (protocol.md 7.3).
    pub min_serial: u32,
}

/// One entry of a [`RosterBody`]'s `revoked` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokedMember {
    /// The revoked node identity.
    pub node_id: NodeId,
    /// When the revocation took effect, Unix seconds.
    pub since: u64,
}

/// One entry of a [`RosterBody`]'s `labels` list: a claimed public name
/// (protocol.md 4.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    /// The claimed name.
    pub name: String,
    /// The node it resolves to.
    pub node_id: NodeId,
}

/// ```text
/// Steward = Signed("steward"){ v: 1, network_id, steward_pub: bytes32,
///     may: ["admit", "renew"], not_after: u64 }
/// ```
/// (protocol.md 2.3)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StewardBody {
    /// Document schema version.
    pub v: u16,
    /// The network this steward acts for.
    pub network_id: NetworkId,
    /// The steward's public key. The spec gives `bytes32` with no stated
    /// key type, kept as its own type rather than assumed to be an
    /// X25519 or Ed25519 key.
    pub steward_pub: StewardKey,
    /// What the steward may do: `"admit"`, `"renew"`.
    pub may: Vec<String>,
    /// When this delegation expires, Unix seconds.
    pub not_after: u64,
}

impl SignedBody for StewardBody {
    const TAG: &'static str = TAG_STEWARD;
}

/// A signed steward delegation.
pub type Steward = Signed<StewardBody>;

/// ```text
/// Roster = Signed("roster"){ v: 1, network_id, seq: u64, issued: u64, expires: u64,
///     members: [ { node_id, min_serial: u32 } ],
///     revoked: [ { node_id, since: u64 } ],
///     stewards: [ Steward ],
///     labels:  [ { name: str, node_id } ] }
/// ```
/// (protocol.md 2.3). What a relay needs and may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterBody {
    /// Document schema version.
    pub v: u16,
    /// The network this roster describes.
    pub network_id: NetworkId,
    /// Monotonic sequence number; a verifier never accepts a lower `seq`
    /// than the newest it has already verified for this network.
    pub seq: u64,
    /// When this roster was issued, Unix seconds.
    pub issued: u64,
    /// When this roster expires, Unix seconds. At most 14 days after
    /// `issued` (protocol.md 2.3); a policy check for the issuer, not
    /// enforced by this type.
    pub expires: u64,
    /// Current members and their minimum accepted certificate serial.
    pub members: Vec<RosterMember>,
    /// Members revoked from this network.
    pub revoked: Vec<RevokedMember>,
    /// Delegated stewards; protocol.md 2.3 says there is exactly one
    /// active steward, a policy invariant this type does not enforce.
    pub stewards: Vec<Steward>,
    /// Claimed public names.
    pub labels: Vec<Label>,
}

impl SignedBody for RosterBody {
    const TAG: &'static str = TAG_ROSTER;
}

/// A signed, verifiable network roster.
pub type Roster = Signed<RosterBody>;

/// One entry of a [`PolicyBody`]'s `members` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMember {
    /// The member's node identity.
    pub node_id: NodeId,
    /// A human-readable name for this member.
    pub name: String,
    /// Roles this member holds within the network.
    pub roles: Vec<String>,
}

/// `to_node: node_id | "*"` (protocol.md 2.3's [`Grant`]): a specific
/// node, or every node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeOrWildcard {
    /// A specific node.
    Node(NodeId),
    /// Every node (the literal string `"*"` on the wire).
    Any,
}

impl Serialize for NodeOrWildcard {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Node(node_id) => node_id.serialize(serializer),
            Self::Any => serializer.serialize_str("*"),
        }
    }
}

struct NodeOrWildcardVisitor;

impl<'de> Visitor<'de> for NodeOrWildcardVisitor {
    type Value = NodeOrWildcard;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a 32-byte node id or the string \"*\"")
    }

    fn visit_bytes<E: DeError>(self, v: &[u8]) -> Result<Self::Value, E> {
        let array: [u8; 32] = v
            .try_into()
            .map_err(|_| E::invalid_length(v.len(), &self))?;
        Ok(NodeOrWildcard::Node(NodeId::from(array)))
    }

    fn visit_borrowed_bytes<E: DeError>(self, v: &'de [u8]) -> Result<Self::Value, E> {
        self.visit_bytes(v)
    }

    fn visit_byte_buf<E: DeError>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        self.visit_bytes(&v)
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        if v == "*" {
            Ok(NodeOrWildcard::Any)
        } else {
            Err(E::invalid_value(serde::de::Unexpected::Str(v), &self))
        }
    }
}

impl<'de> Deserialize<'de> for NodeOrWildcard {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(NodeOrWildcardVisitor)
    }
}

/// `Principal` is `{ network_id, node_id }` or `{ network_id, role }`
/// (protocol.md 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The network this principal is scoped to; roles and grants exist
    /// only inside one network.
    pub network_id: NetworkId,
    /// Which principal within that network.
    pub target: PrincipalTarget,
}

/// The `node_id` or `role` half of a [`Principal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalTarget {
    /// A specific node.
    Node(NodeId),
    /// Every node holding a role.
    Role(String),
}

impl Serialize for Principal {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("network_id", &self.network_id)?;
        match &self.target {
            PrincipalTarget::Node(node_id) => map.serialize_entry("node_id", node_id)?,
            PrincipalTarget::Role(role) => map.serialize_entry("role", role)?,
        }
        map.end()
    }
}

struct PrincipalVisitor;

impl<'de> Visitor<'de> for PrincipalVisitor {
    type Value = Principal;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a map with \"network_id\" and exactly one of \"node_id\" or \"role\"")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut network_id: Option<NetworkId> = None;
        let mut node_id: Option<NodeId> = None;
        let mut role: Option<String> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "network_id" if network_id.is_none() => network_id = Some(map.next_value()?),
                "node_id" if node_id.is_none() && role.is_none() => {
                    node_id = Some(map.next_value()?)
                }
                "role" if role.is_none() && node_id.is_none() => role = Some(map.next_value()?),
                other => {
                    return Err(DeError::custom(format!(
                        "Principal: unexpected or duplicate key {other:?}"
                    )));
                }
            }
        }

        let network_id = network_id.ok_or_else(|| DeError::missing_field("network_id"))?;
        let target = match (node_id, role) {
            (Some(node_id), None) => PrincipalTarget::Node(node_id),
            (None, Some(role)) => PrincipalTarget::Role(role),
            (None, None) => {
                return Err(DeError::custom(
                    "Principal: exactly one of \"node_id\" or \"role\" is required",
                ));
            }
            (Some(_), Some(_)) => unreachable!("the loop above never sets both"),
        };
        Ok(Principal { network_id, target })
    }
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(PrincipalVisitor)
    }
}

/// An opaque host/port matching pattern, as it appears in a
/// [`Policy`](crate::network::Policy)'s default egress deny list
/// (protocol.md 8), e.g. `"10.0.0.0/8"`. This crate only carries the
/// pattern text; canonicalizing an address and matching it against a
/// list of these is the future egress implementation's job (protocol.md
/// 8), not this wire type's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPortPattern(pub String);

/// One entry of a [`PolicyBody`]'s `grants` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// Who is granted access.
    pub from: Principal,
    /// Which node the grant applies to.
    pub to_node: NodeOrWildcard,
    /// Which services on `to_node` are reachable.
    pub services: Vec<ServicePattern>,
    /// When the grant expires, Unix seconds; `None` for no expiry.
    pub expires: Option<u64>,
}

/// One entry of a [`PolicyBody`]'s `egress` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    /// The node this rule applies to.
    pub node_id: NodeId,
    /// Patterns explicitly allowed.
    pub allow: Vec<HostPortPattern>,
    /// Patterns explicitly denied; checked before `allow` (protocol.md 8).
    pub deny: Vec<HostPortPattern>,
}

/// One entry of a [`PolicyBody`]'s `accept` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptEntry {
    /// The node this entry applies to.
    pub node_id: NodeId,
    /// Whether that node accepts peer (non-relay) traffic.
    pub peers: bool,
}

/// ```text
/// Policy = Signed("policy"){ v: 1, network_id, seq: u64, issued: u64, expires: u64,
///     members: [ { node_id, name: str, roles: [str] } ],
///     certs:   [ NodeCert ],
///     grants:  [ { from: Principal, to_node: node_id | "*", services: [ServicePattern], expires: u64 | null } ],
///     egress:  [ { node_id, allow: [HostPortPattern], deny: [HostPortPattern] } ],
///     accept:  [ { node_id, peers: bool } ] }
/// ```
/// (protocol.md 2.3). Delivered end to end between members; never to a
/// relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyBody {
    /// Document schema version.
    pub v: u16,
    /// The network this policy describes.
    pub network_id: NetworkId,
    /// Monotonic sequence number, issued together with the Roster of the
    /// same `seq`.
    pub seq: u64,
    /// When this policy was issued, Unix seconds.
    pub issued: u64,
    /// When this policy expires, Unix seconds.
    pub expires: u64,
    /// Members, their display name, and their roles.
    pub members: Vec<PolicyMember>,
    /// Current certificates for members named in `grants`.
    pub certs: Vec<NodeCert>,
    /// Access grants between principals and services.
    pub grants: Vec<Grant>,
    /// Egress allow/deny rules per node.
    pub egress: Vec<EgressRule>,
    /// Whether each node accepts peer traffic.
    pub accept: Vec<AcceptEntry>,
}

impl SignedBody for PolicyBody {
    const TAG: &'static str = TAG_POLICY;
}

/// A signed, verifiable network policy.
pub type Policy = Signed<PolicyBody>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeCertBody;
    use ed25519_dalek::SigningKey;

    fn network_id() -> NetworkId {
        NetworkId::from([9u8; 32])
    }

    #[test]
    fn roster_with_nested_steward_and_label_round_trips() {
        let owner = SigningKey::generate(&mut rand::rng());
        let steward_key = SigningKey::generate(&mut rand::rng());
        let steward_body = StewardBody {
            v: crate::PROTOCOL_VERSION,
            network_id: network_id(),
            steward_pub: StewardKey::from([3u8; 32]),
            may: vec!["admit".to_string(), "renew".to_string()],
            not_after: 2_000_000_000,
        };
        let steward = Steward::sign(&steward_key, &steward_body).unwrap();

        let roster_body = RosterBody {
            v: crate::PROTOCOL_VERSION,
            network_id: network_id(),
            seq: 1,
            issued: 1_700_000_000,
            expires: 1_700_000_000 + 14 * 86_400,
            members: vec![RosterMember {
                node_id: NodeId::from([1u8; 32]),
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![steward],
            labels: vec![Label {
                name: "example".to_string(),
                node_id: NodeId::from([1u8; 32]),
            }],
        };
        let roster = Roster::sign(&owner, &roster_body).unwrap();
        roster.verify(&owner.verifying_key()).unwrap();
        let decoded = roster.decode().unwrap();
        assert_eq!(decoded, roster_body);
        decoded.stewards[0]
            .verify(&steward_key.verifying_key())
            .unwrap();
    }

    #[test]
    fn policy_with_nested_cert_and_both_principal_and_wildcard_forms_round_trips() {
        let owner = SigningKey::generate(&mut rand::rng());
        let node_key = SigningKey::generate(&mut rand::rng());
        let node_id = NodeId::from([4u8; 32]);
        let cert_body = NodeCertBody {
            v: crate::PROTOCOL_VERSION,
            node_id,
            x25519_pub: crate::bytes::X25519PublicKey::from([5u8; 32]),
            serial: 1,
            not_before: 1_700_000_000,
            not_after: 1_700_000_000 + 400 * 86_400,
        };
        let cert = NodeCert::sign(&node_key, &cert_body).unwrap();

        let policy_body = PolicyBody {
            v: crate::PROTOCOL_VERSION,
            network_id: network_id(),
            seq: 1,
            issued: 1_700_000_000,
            expires: 1_700_000_000 + 14 * 86_400,
            members: vec![PolicyMember {
                node_id,
                name: "node-a".to_string(),
                roles: vec!["steward".to_string()],
            }],
            certs: vec![cert],
            grants: vec![
                Grant {
                    from: Principal {
                        network_id: network_id(),
                        target: PrincipalTarget::Node(node_id),
                    },
                    to_node: NodeOrWildcard::Node(node_id),
                    services: vec!["tcp:ssh".parse().unwrap()],
                    expires: Some(1_800_000_000),
                },
                Grant {
                    from: Principal {
                        network_id: network_id(),
                        target: PrincipalTarget::Role("steward".to_string()),
                    },
                    to_node: NodeOrWildcard::Any,
                    services: vec!["egress:*".parse().unwrap()],
                    expires: None,
                },
            ],
            egress: vec![EgressRule {
                node_id,
                allow: vec![],
                deny: vec![HostPortPattern("10.0.0.0/8".to_string())],
            }],
            accept: vec![AcceptEntry {
                node_id,
                peers: true,
            }],
        };
        let policy = Policy::sign(&owner, &policy_body).unwrap();
        policy.verify(&owner.verifying_key()).unwrap();
        let decoded = policy.decode().unwrap();
        assert_eq!(decoded, policy_body);
        decoded.certs[0].verify(&node_key.verifying_key()).unwrap();
    }

    #[test]
    fn principal_rejects_both_node_id_and_role() {
        // {"network_id": <32 bytes>, "node_id": <32 bytes>, "role": "x"}
        let mut buf = Vec::new();
        {
            use ciborium::value::Value;
            let network_id = vec![0u8; 32];
            let node_id = vec![1u8; 32];
            let value = Value::Map(vec![
                (
                    Value::Text("network_id".to_string()),
                    Value::Bytes(network_id),
                ),
                (Value::Text("node_id".to_string()), Value::Bytes(node_id)),
                (
                    Value::Text("role".to_string()),
                    Value::Text("steward".to_string()),
                ),
            ]);
            ciborium::into_writer(&value, &mut buf).unwrap();
        }
        let result: Result<Principal, _> = ciborium::from_reader(&buf[..]);
        assert!(result.is_err());
    }

    #[test]
    fn node_or_wildcard_rejects_non_star_string() {
        let mut buf = Vec::new();
        ciborium::into_writer(&"not-a-star", &mut buf).unwrap();
        let result: Result<NodeOrWildcard, _> = ciborium::from_reader(&buf[..]);
        assert!(result.is_err());
    }
}
