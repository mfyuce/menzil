//! HELLO validation against a held Roster (protocol.md 4.1): "The relay
//! verifies the NodeCert and rejects a serial lower than the highest it
//! has seen or lower than any Roster's `min_serial` for that node,
//! rejects a `timestamp` not greater than the last accepted for that
//! NodeId, and checks each claimed network against its Rosters: unknown
//! network, unlisted node or revoked node fails with ERROR. A node may
//! claim no network; it may then only redeem an invite."
//!
//! Deliberately not checked here: a claimed network's Roster having
//! passed its own `expires` (`ErrorCode::RosterExpired` exists in the
//! registry, but this specific paragraph doesn't name it). protocol.md
//! 2.3 places that consequence at forwarding ("relays stop forwarding
//! for that network"), which is the separate, later flow-control item's
//! job, not a reason to refuse the session itself here.
//!
//! Pure: takes the already-decrypted HELLO, the Noise-negotiated
//! initiator static key, and read-only access to the roster/history
//! stores; returns the verified NodeId on success or the ErrorCode and
//! message to report on failure. No I/O beyond what `RosterStore`/
//! `NodeHistory` already do internally (a brief, non-blocking lock).

use ed25519_dalek::VerifyingKey;
use menzil_proto::{ErrorCode, HelloBody, NodeCertBody, NodeId, X25519PublicKey};

use crate::node_history::{HistoryViolation, NodeHistory};
use crate::roster_store::RosterStore;

/// One HELLO check failed: the code and message a relay sends back in
/// an ERROR record (protocol.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloRejection {
    /// The registry code.
    pub code: ErrorCode,
    /// Free-text detail.
    pub message: String,
}

fn reject(code: ErrorCode, message: impl Into<String>) -> HelloRejection {
    HelloRejection {
        code,
        message: message.into(),
    }
}

/// Verifies HELLO's `node_cert`: a valid self-signature (protocol.md
/// 2.2: the cert's own claimed `node_id` is the key that must have
/// signed it), a validity window that covers `now`, and that its
/// `x25519_pub` matches the key the Noise handshake actually negotiated
/// for the initiator — the same check protocol.md 4.1 has the *node*
/// perform on the relay's own cert, mirrored here for the relay's side
/// of the same handshake. Returns the verified body.
fn verify_node_cert(
    hello: &HelloBody,
    node_static: &X25519PublicKey,
    now: u64,
) -> Result<NodeCertBody, HelloRejection> {
    let body = hello
        .node_cert
        .decode()
        .map_err(|e| reject(ErrorCode::BadCert, e.to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id))
        .map_err(|e| reject(ErrorCode::BadCert, e.to_string()))?;
    hello
        .node_cert
        .verify(&verifying_key)
        .map_err(|e| reject(ErrorCode::BadCert, e.to_string()))?;
    if !body.is_valid_at(now) {
        return Err(reject(
            ErrorCode::BadCert,
            format!(
                "node_cert is outside its validity window ({}..={}) at {now}",
                body.not_before, body.not_after
            ),
        ));
    }
    if &body.x25519_pub != node_static {
        return Err(reject(
            ErrorCode::BadCert,
            "node_cert.x25519_pub does not match the negotiated Noise static key",
        ));
    }
    Ok(body)
}

/// Serial, timestamp, and per-claimed-network checks against `node_id`
/// (already proven to own `cert_serial`'s NodeCert by
/// [`verify_node_cert`]).
///
/// [`NodeHistory::check_and_record`] runs last, deliberately: it is the
/// only side-effecting check here (every other one is a read-only
/// lookup), and [`NodeHistory`]'s own "last accepted, not last
/// attempted" invariant only holds crate-wide if nothing after it can
/// still cause the overall HELLO to be rejected. Running it first would
/// let a HELLO that fails a *later*, unrelated check (e.g. an unknown
/// claimed network) still permanently advance the replay-defense
/// high-water marks — technically fine for security (no check is
/// weakened), but it would quietly break that documented guarantee and
/// needlessly cost a legitimate node's immediate retry a `stale_timestamp`
/// rejection it did nothing to deserve.
fn validate_against_rosters(
    hello: &HelloBody,
    node_id: NodeId,
    cert_serial: u32,
    rosters: &RosterStore,
    history: &NodeHistory,
) -> Result<(), HelloRejection> {
    if let Some(min_serial) = rosters.min_serial_for(&node_id)
        && cert_serial < min_serial
    {
        return Err(reject(
            ErrorCode::StaleSerial,
            format!("serial {cert_serial} is below this node's Roster min_serial {min_serial}"),
        ));
    }

    for network_id in &hello.networks {
        let Some(roster) = rosters.get(network_id) else {
            return Err(reject(
                ErrorCode::UnknownNetwork,
                format!("no Roster held for network {network_id}"),
            ));
        };
        // Checked before membership, and independently of it: a Roster
        // may or may not still carry a revoked node in `members`
        // alongside `revoked` (protocol.md 2.3 doesn't say which), and
        // a revoked node should get the more specific `Revoked` either
        // way, not `NotMember`.
        if roster
            .revoked
            .iter()
            .any(|revoked| revoked.node_id == node_id)
        {
            return Err(reject(
                ErrorCode::Revoked,
                format!("node is revoked from network {network_id}"),
            ));
        }
        if !roster
            .members
            .iter()
            .any(|member| member.node_id == node_id)
        {
            return Err(reject(
                ErrorCode::NotMember,
                format!("node is not a member of network {network_id}"),
            ));
        }
    }

    history
        .check_and_record(node_id, cert_serial, hello.timestamp)
        .map_err(|violation| match violation {
            HistoryViolation::StaleSerial => reject(
                ErrorCode::StaleSerial,
                "serial is not higher than the last one accepted from this node",
            ),
            HistoryViolation::StaleTimestamp => reject(
                ErrorCode::StaleTimestamp,
                "timestamp does not advance past the last one accepted from this node",
            ),
        })?;

    Ok(())
}

/// The single entry point: verifies `hello`'s NodeCert, then checks
/// serial/timestamp history and each claimed network against `rosters`.
/// On success, returns the verified NodeId and records this HELLO's
/// serial/timestamp into `history` as the new high-water marks.
pub fn check_hello(
    hello: &HelloBody,
    node_static: &X25519PublicKey,
    rosters: &RosterStore,
    history: &NodeHistory,
    now: u64,
) -> Result<NodeId, HelloRejection> {
    let cert_body = verify_node_cert(hello, node_static, now)?;
    validate_against_rosters(hello, cert_body.node_id, cert_body.serial, rosters, history)?;
    Ok(cert_body.node_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{NetworkId, Roster};
    use menzil_proto::{NodeCert, RevokedMember, RosterBody, RosterMember, Tai64N};
    use std::collections::HashMap;

    struct Fixture {
        signing_key: SigningKey,
        node_id: NodeId,
        x25519_static: X25519PublicKey,
    }

    fn fixture() -> Fixture {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let node_id = NodeId::from(signing_key.verifying_key().to_bytes());
        Fixture {
            signing_key,
            node_id,
            x25519_static: X25519PublicKey::from([7u8; 32]),
        }
    }

    fn hello_with(
        fixture: &Fixture,
        networks: Vec<NetworkId>,
        serial: u32,
        ts_byte: u8,
    ) -> HelloBody {
        let cert_body = menzil_proto::NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: fixture.node_id,
            x25519_pub: fixture.x25519_static,
            serial,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        let node_cert = NodeCert::sign(&fixture.signing_key, &cert_body).unwrap();
        let mut timestamp_bytes = [0u8; 12];
        timestamp_bytes[7] = ts_byte;
        HelloBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_cert,
            networks,
            timestamp: Tai64N::from(timestamp_bytes),
            roster_seq: HashMap::new(),
            caps: vec![],
            e2e_protos: vec![0x01],
        }
    }

    fn roster_for(
        owner: &SigningKey,
        network_id: NetworkId,
        member: NodeId,
        revoked: bool,
    ) -> Roster {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: if revoked {
                vec![]
            } else {
                vec![RosterMember {
                    node_id: member,
                    min_serial: 1,
                }]
            },
            revoked: if revoked {
                vec![RevokedMember {
                    node_id: member,
                    since: 0,
                }]
            } else {
                vec![]
            },
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    #[test]
    fn no_claimed_networks_succeeds_with_a_valid_cert() {
        let fixture = fixture();
        let hello = hello_with(&fixture, vec![], 1, 10);
        let rosters = RosterStore::new();
        let history = NodeHistory::new();
        let node_id = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap();
        assert_eq!(node_id, fixture.node_id);
    }

    #[test]
    fn a_membership_in_a_held_roster_succeeds() {
        let fixture = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters
            .set(&roster_for(&owner, network_id, fixture.node_id, false))
            .unwrap();
        let history = NodeHistory::new();

        let hello = hello_with(&fixture, vec![network_id], 1, 10);
        assert!(check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).is_ok());
    }

    #[test]
    fn an_unknown_claimed_network_is_rejected() {
        let fixture = fixture();
        let hello = hello_with(&fixture, vec![NetworkId::from([1u8; 32])], 1, 10);
        let rosters = RosterStore::new();
        let history = NodeHistory::new();
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnknownNetwork);
    }

    #[test]
    fn an_unlisted_node_is_rejected() {
        let fixture = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        // Roster exists, but lists some other node, not this one.
        rosters
            .set(&roster_for(
                &owner,
                network_id,
                NodeId::from([9u8; 32]),
                false,
            ))
            .unwrap();
        let history = NodeHistory::new();

        let hello = hello_with(&fixture, vec![network_id], 1, 10);
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotMember);
    }

    #[test]
    fn a_revoked_node_is_rejected() {
        let fixture = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters
            .set(&roster_for(&owner, network_id, fixture.node_id, true))
            .unwrap();
        let history = NodeHistory::new();

        let hello = hello_with(&fixture, vec![network_id], 1, 10);
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::Revoked);
    }

    #[test]
    fn a_serial_below_a_rosters_min_serial_is_rejected() {
        let fixture = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id: fixture.node_id,
                min_serial: 5,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        let rosters = RosterStore::new();
        rosters.set(&Roster::sign(&owner, &body).unwrap()).unwrap();
        let history = NodeHistory::new();

        // Claims no network at all: min_serial_for scans every held
        // Roster regardless of what's claimed (see this module's docs).
        let hello = hello_with(&fixture, vec![], 4, 10);
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::StaleSerial);
    }

    #[test]
    fn a_hello_rejected_for_an_unrelated_reason_does_not_advance_history() {
        let fixture = fixture();
        let rosters = RosterStore::new();
        let history = NodeHistory::new();

        // Valid cert, serial, and timestamp, but an unknown claimed
        // network: rejected, and must not move the timestamp
        // high-water mark (see `validate_against_rosters`'s docs).
        let unknown_network = NetworkId::from([0x99; 32]);
        let rejected = hello_with(&fixture, vec![unknown_network], 1, 10);
        let err =
            check_hello(&rejected, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnknownNetwork);

        // Retried with the exact same timestamp and no unknown network
        // this time: must still succeed. If the first attempt had
        // recorded its timestamp, this would fail as `StaleTimestamp`.
        let retry = hello_with(&fixture, vec![], 1, 10);
        assert!(check_hello(&retry, &fixture.x25519_static, &rosters, &history, 500).is_ok());
    }

    #[test]
    fn a_wrong_negotiated_static_key_is_rejected_as_bad_cert() {
        let fixture = fixture();
        let hello = hello_with(&fixture, vec![], 1, 10);
        let rosters = RosterStore::new();
        let history = NodeHistory::new();
        let wrong_static = X25519PublicKey::from([0xAB; 32]);
        let err = check_hello(&hello, &wrong_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadCert);
    }

    #[test]
    fn an_expired_cert_is_rejected_as_bad_cert() {
        let fixture = fixture();
        let hello = hello_with(&fixture, vec![], 1, 10);
        let rosters = RosterStore::new();
        let history = NodeHistory::new();
        let far_future = 2_000_000_000;
        let err = check_hello(
            &hello,
            &fixture.x25519_static,
            &rosters,
            &history,
            far_future,
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadCert);
    }

    #[test]
    fn a_stale_timestamp_on_reconnect_is_rejected() {
        let fixture = fixture();
        let rosters = RosterStore::new();
        let history = NodeHistory::new();
        let first = hello_with(&fixture, vec![], 1, 10);
        check_hello(&first, &fixture.x25519_static, &rosters, &history, 500).unwrap();

        let replay = hello_with(&fixture, vec![], 1, 10);
        let err =
            check_hello(&replay, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::StaleTimestamp);
    }
}
