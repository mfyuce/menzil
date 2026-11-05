//! HELLO validation against a held Roster (protocol.md 4.1): "The relay
//! verifies the NodeCert and rejects a serial lower than the highest it
//! has seen or lower than the `min_serial` for that node in a Roster of a
//! claimed network,
//! rejects a `timestamp` not greater than the last accepted for that
//! NodeId, and checks each claimed network against its Rosters: an unlisted
//! node (an unserved network counts as listing nobody, so it answers
//! `not_member` exactly like a served network that does not list the
//! node) or a revoked node fails with ERROR. A node may
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

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use menzil_proto::{ErrorCode, HelloBody, NetworkId, NodeCertBody, NodeId, X25519PublicKey};

use crate::node_history::{HistoryViolation, NodeHistory};
use crate::roster_store::RosterStore;

/// The most distinct networks one HELLO may claim. A HELLO is read before the sender has proven
/// anything, so what it makes the relay do must be bounded by something other than the size of
/// the message (a Noise message 1 of 65,535 bytes holds about 1,800 NetworkIds). The owner design
/// (D7) gives a friend 3 networks; 32 leaves room for an operator's own. The repeats of one
/// NetworkId are dropped first and do not count; a HELLO with more distinct ones is refused with
/// `too_large` and no `network` before the RosterStore is touched, an answer that does not
/// depend on which networks the relay serves. protocol.md 4.1 states no limit of its own.
pub const MAX_HELLO_NETWORKS: usize = 32;

/// `networks` without its repeats, in the order of first appearance.
pub(crate) fn dedup_networks(networks: &[NetworkId]) -> Vec<NetworkId> {
    let mut seen = HashSet::with_capacity(networks.len());
    networks
        .iter()
        .copied()
        .filter(|id| seen.insert(*id))
        .collect()
}

/// One HELLO check failed: the code and message a relay sends back in
/// an ERROR record (protocol.md 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloRejection {
    /// The registry code.
    pub code: ErrorCode,
    /// Free-text detail.
    pub message: String,
    /// The claimed network whose Roster caused this rejection (revoked, not a member, or the
    /// `min_serial` that is too high), when one did: the Roster a relay sends an evicted node
    /// before the ERROR (protocol.md 4.2).
    pub network: Option<NetworkId>,
}

fn reject(code: ErrorCode, message: impl Into<String>) -> HelloRejection {
    HelloRejection {
        code,
        message: message.into(),
        network: None,
    }
}

fn reject_in(code: ErrorCode, message: impl Into<String>, network: NetworkId) -> HelloRejection {
    HelloRejection {
        network: Some(network),
        ..reject(code, message)
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

/// The Roster side of HELLO validation, for `node_id` holding a NodeCert of `cert_serial` and
/// claiming `networks`: a serial below the `min_serial` for the node in a Roster of a claimed
/// network (one network's owner has no say over the node's standing in another's, the twelfth
/// red-team round, M1), then for each claimed network: revoked there (checked before membership, and independently of
/// it: a Roster may or may not still carry a revoked node in `members` alongside `revoked`
/// (protocol.md 2.3 doesn't say which), and a revoked node should get the more specific
/// `Revoked` either way, not `NotMember`), or not listed there. A network this relay does not
/// serve counts as one that lists nobody and gets the same `NotMember` (isolation rule I2).
///
/// Pure and read only. The one rule both of its callers apply: [`check_hello`] when a session
/// starts, and `crate::session` again whenever a Roster of a network the session claimed is
/// adopted (protocol.md 7.3, "relays end the session of a node that a Roster they adopt
/// revokes"), so that a session is ended exactly when the same HELLO would now be refused.
pub(crate) fn roster_standing(
    node_id: &NodeId,
    cert_serial: u32,
    networks: &[NetworkId],
    rosters: &RosterStore,
) -> Result<(), HelloRejection> {
    if let Some((network_id, min_serial)) = rosters.min_serial_in(node_id, networks)
        && cert_serial < min_serial
    {
        return Err(reject_in(
            ErrorCode::StaleSerial,
            format!("serial {cert_serial} is below this node's Roster min_serial {min_serial}"),
            network_id,
        ));
    }

    for network_id in networks {
        // A network this relay does not serve is judged as a served one that lists nobody
        // (isolation rule I2, decision D5): the same code, message and `network` as "not a
        // member", so no peer can test which networks a relay serves. The node explains the
        // likely cause itself from its own Roster. Nothing before this point in the check
        // order depends on whether the network is served: `min_serial_in` looks only at
        // Rosters that list this very node, so a stranger's key never reaches a different
        // answer through it. `standing_of` is one hash lookup that clones nothing and answers
        // an unserved network with the standing of an unlisted node, so the work does not tell
        // them apart either (the first multi tenant red-team round, M1 and M2).
        let standing = rosters.standing_of(node_id, network_id);
        if standing.revoked {
            return Err(reject_in(
                ErrorCode::Revoked,
                format!("node is revoked from network {network_id}"),
                *network_id,
            ));
        }
        if !standing.listed {
            return Err(reject_in(
                ErrorCode::NotMember,
                format!("node is not a member of network {network_id}"),
                *network_id,
            ));
        }
    }
    Ok(())
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
fn validate_against_rosters<T>(
    hello: &HelloBody,
    node_id: NodeId,
    cert_serial: u32,
    rosters: &RosterStore,
    history: &NodeHistory,
    admit: impl FnOnce(&NodeId, &[NetworkId]) -> Result<T, HelloRejection>,
) -> Result<T, HelloRejection> {
    // Repeats dropped and the count capped before the first look at the store: the work below
    // is then at most MAX_HELLO_NETWORKS lookups however the HELLO was padded.
    let claimed = dedup_networks(&hello.networks);
    // Decision D6 (MT4): a HELLO that claims no network is refused. Its only legitimate use
    // is redeeming an invitation, which is not built (phase 2), and until then it would give
    // any key a session that lives as long as it answers PING. The code is `not_member`: the
    // node is a member of none of the networks it named, and the answer says nothing about
    // which networks this relay serves.
    if claimed.is_empty() {
        return Err(reject(
            ErrorCode::NotMember,
            "a HELLO must claim at least one network",
        ));
    }
    if claimed.len() > MAX_HELLO_NETWORKS {
        return Err(reject(
            ErrorCode::TooLarge,
            format!("a HELLO may claim at most {MAX_HELLO_NETWORKS} networks"),
        ));
    }
    roster_standing(&node_id, cert_serial, &claimed, rosters)?;

    // The caller's admission caps (`crate::admission`) apply to a NodeId that is proven and in
    // standing, and before the history is written: a refused HELLO leaves no mark, so the same
    // node can retry at once.
    let admitted = admit(&node_id, &claimed)?;

    history
        .check_and_record_retaining(node_id, cert_serial, hello.timestamp, |id| {
            rosters.lists_node(id)
        })
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

    Ok(admitted)
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
    check_hello_admitting(hello, node_static, rosters, history, now, |_, _| Ok(()))
        .map(|(node_id, ())| node_id)
}

/// [`check_hello`] with one more step: `admit` runs once the NodeId is proven and in standing
/// (and before the history is written), and what it returns comes back with the NodeId. The
/// session driver passes the per NodeId admission cap here, so that a HELLO refused for being
/// over it leaves no replay mark.
pub(crate) fn check_hello_admitting<T>(
    hello: &HelloBody,
    node_static: &X25519PublicKey,
    rosters: &RosterStore,
    history: &NodeHistory,
    now: u64,
    admit: impl FnOnce(&NodeId, &[NetworkId]) -> Result<T, HelloRejection>,
) -> Result<(NodeId, T), HelloRejection> {
    let cert_body = verify_node_cert(hello, node_static, now)?;
    let admitted = validate_against_rosters(
        hello,
        cert_body.node_id,
        cert_body.serial,
        rosters,
        history,
        admit,
    )?;
    Ok((cert_body.node_id, admitted))
}

/// The refusal for a session that would take its tenant over a figure (`over_quota`, design
/// 2.3). Only a proven NodeId in standing in the networks it claimed is ever told this (the
/// admission step runs after the Roster checks), so it says nothing a stranger could use.
pub(crate) fn over_quota(refused: &crate::tenant::OverQuota) -> HelloRejection {
    reject(ErrorCode::OverQuota, refused.message())
}

/// The refusal for a NodeId that has too many sessions waiting to ATTACH, or a relay with too
/// many attached: `rate_limited` ("a limit in protocol.md section 10 was exceeded").
pub(crate) fn over_limit(message: &str) -> HelloRejection {
    reject(ErrorCode::RateLimited, message)
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

    /// Decision D6 (MT4): a HELLO that claims no network is refused, whatever the cert, and
    /// leaves no replay mark (the same timestamp can be used by the retry that does claim one).
    #[test]
    fn a_hello_that_claims_no_network_is_refused_and_leaves_no_replay_mark() {
        let fixture = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters
            .set(&roster_for(&owner, network_id, fixture.node_id, false))
            .unwrap();
        let history = NodeHistory::new();

        let empty = hello_with(&fixture, vec![], 1, 10);
        let err = check_hello(&empty, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotMember);
        assert_eq!(err.network, None);
        assert!(history.is_empty(), "a refused HELLO must not be recorded");

        let retry = hello_with(&fixture, vec![network_id], 1, 10);
        let node_id = check_hello(&retry, &fixture.x25519_static, &rosters, &history, 500).unwrap();
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
    fn an_unknown_claimed_network_is_rejected_as_not_a_member() {
        let fixture = fixture();
        let hello = hello_with(&fixture, vec![NetworkId::from([1u8; 32])], 1, 10);
        let rosters = RosterStore::new();
        let history = NodeHistory::new();
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotMember);
    }

    /// Isolation rule I2: the same HELLO, to a relay that does not serve the network and to one
    /// that serves it without listing the node, is refused with the identical rejection (code,
    /// message and `network`), so nobody can test which networks a relay serves.
    #[test]
    fn an_unserved_network_is_refused_exactly_like_a_served_one_that_does_not_list_the_node() {
        let fixture = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let stranger = NodeId::from([0x55; 32]);

        let serving = RosterStore::new();
        serving
            .set(&roster_for(&owner, network_id, stranger, false))
            .unwrap();
        let not_serving = RosterStore::new();

        let hello = hello_with(&fixture, vec![network_id], 1, 10);
        let served_answer = check_hello(
            &hello,
            &fixture.x25519_static,
            &serving,
            &NodeHistory::new(),
            500,
        )
        .unwrap_err();
        let unserved_answer = check_hello(
            &hello,
            &fixture.x25519_static,
            &not_serving,
            &NodeHistory::new(),
            500,
        )
        .unwrap_err();
        assert_eq!(served_answer.code, ErrorCode::NotMember);
        assert_eq!(unserved_answer, served_answer);
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

        // Claims the network that set the floor: refused, naming that network.
        let hello = hello_with(&fixture, vec![network_id], 4, 10);
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::StaleSerial);
        assert_eq!(err.network, Some(network_id));

        // Claims another network that lists the node with a low floor: the first network's
        // floor does not apply (round 12, M1: the floor is judged per claimed network).
        let owner_b = SigningKey::generate(&mut rand::rng());
        let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
        rosters
            .set(&roster_for(&owner_b, network_b, fixture.node_id, false))
            .unwrap();
        let hello = hello_with(&fixture, vec![network_b], 4, 11);
        assert!(check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).is_ok());
    }

    /// Round 12, M1: another network's Roster listing the node with a huge `min_serial` does
    /// not refuse a HELLO that claims only the node's own network.
    #[test]
    fn another_networks_min_serial_does_not_refuse_a_hello_that_does_not_claim_it() {
        let fixture = fixture();
        let (owner_a, owner_b) = (
            SigningKey::generate(&mut rand::rng()),
            SigningKey::generate(&mut rand::rng()),
        );
        let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
        let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
        let roster = |owner: &SigningKey, network_id, min_serial| {
            let body = RosterBody {
                v: menzil_proto::PROTOCOL_VERSION,
                network_id,
                seq: 1,
                issued: 0,
                expires: 1_000_000_000,
                members: vec![RosterMember {
                    node_id: fixture.node_id,
                    min_serial,
                }],
                revoked: vec![],
                stewards: vec![],
                labels: vec![],
            };
            Roster::sign(owner, &body).unwrap()
        };
        let rosters = RosterStore::new();
        rosters.set(&roster(&owner_a, network_a, u32::MAX)).unwrap();
        rosters.set(&roster(&owner_b, network_b, 1)).unwrap();
        let history = NodeHistory::new();
        let hello = hello_with(&fixture, vec![network_b], 1, 10);
        assert!(check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).is_ok());
        // Claiming A as well is the node's own choice and A's floor applies.
        let hello = hello_with(&fixture, vec![network_a, network_b], 1, 11);
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::StaleSerial);
        assert_eq!(err.network, Some(network_a));
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
        assert_eq!(err.code, ErrorCode::NotMember);

        // Retried with the exact same timestamp and no unknown network
        // this time: must still succeed. If the first attempt had
        // recorded its timestamp, this would fail as `StaleTimestamp`.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        rosters
            .set(&roster_for(&owner, network_id, fixture.node_id, false))
            .unwrap();
        let retry = hello_with(&fixture, vec![network_id], 1, 10);
        assert!(check_hello(&retry, &fixture.x25519_static, &rosters, &history, 500).is_ok());
    }

    /// MT4: the admission step runs only for a proven NodeId in standing, and a HELLO it
    /// refuses leaves no replay mark (the retry with the same timestamp is accepted).
    #[test]
    fn a_refused_admission_leaves_no_replay_mark_and_is_not_asked_of_a_node_out_of_standing() {
        let fixture = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters
            .set(&roster_for(&owner, network_id, fixture.node_id, false))
            .unwrap();
        let history = NodeHistory::new();
        let hello = hello_with(&fixture, vec![network_id], 1, 10);

        let refused: Result<(NodeId, ()), _> = check_hello_admitting(
            &hello,
            &fixture.x25519_static,
            &rosters,
            &history,
            500,
            |_, _| Err(over_limit("full")),
        );
        assert_eq!(refused.unwrap_err().code, ErrorCode::RateLimited);
        assert!(history.is_empty());
        assert!(
            check_hello_admitting(
                &hello,
                &fixture.x25519_static,
                &rosters,
                &history,
                500,
                |_, _| { Ok(()) }
            )
            .is_ok(),
            "the same HELLO is accepted once there is room"
        );

        // A node that claims a network that does not list it never reaches the admission step.
        let stranger = self::fixture();
        let hello = hello_with(&stranger, vec![network_id], 1, 10);
        let mut asked = false;
        let err = check_hello_admitting(
            &hello,
            &stranger.x25519_static,
            &rosters,
            &history,
            500,
            |_, _| {
                asked = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::NotMember);
        assert!(!asked);
    }

    /// MT4: the history's eviction keeps the marks of NodeIds a held Roster lists. A tiny
    /// history, a member recorded first (the oldest entry), then other nodes that leave their
    /// Roster; further HELLOs push the table over its bound and the member's mark survives.
    #[test]
    fn eviction_keeps_the_replay_marks_of_nodes_a_held_roster_lists() {
        let member = fixture();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let leavers: Vec<Fixture> = (0..20).map(|_| fixture()).collect();
        let rosters = RosterStore::new();
        let listing = |seq: u64, nodes: Vec<NodeId>| {
            let body = RosterBody {
                v: menzil_proto::PROTOCOL_VERSION,
                network_id,
                seq,
                issued: 0,
                expires: 1_000_000_000,
                members: nodes
                    .into_iter()
                    .map(|node_id| RosterMember {
                        node_id,
                        min_serial: 1,
                    })
                    .collect(),
                revoked: vec![],
                stewards: vec![],
                labels: vec![],
            };
            Roster::sign(&owner, &body).unwrap()
        };
        let mut everyone: Vec<NodeId> = leavers.iter().map(|f| f.node_id).collect();
        everyone.push(member.node_id);
        rosters.set(&listing(1, everyone)).unwrap();
        let history = NodeHistory::with_capacity(8);
        let hello = hello_with(&member, vec![network_id], 5, 10);
        check_hello(&hello, &member.x25519_static, &rosters, &history, 500).unwrap();
        for (n, leaver) in leavers.iter().enumerate() {
            let hello = hello_with(leaver, vec![network_id], 1, 10 + n as u8);
            check_hello(&hello, &leaver.x25519_static, &rosters, &history, 500).unwrap();
        }
        // Everyone was listed, so everyone is vouched for: the table grew past its bound of 8.
        assert_eq!(history.len(), 21);
        // The leavers leave the Roster; more HELLOs from the member's own network mates.
        rosters.set(&listing(2, vec![member.node_id])).unwrap();
        let late: Vec<Fixture> = (0..20).map(|_| fixture()).collect();
        let mut with_late = vec![member.node_id];
        with_late.extend(late.iter().map(|f| f.node_id));
        rosters.set(&listing(3, with_late)).unwrap();
        for (n, node) in late.iter().enumerate() {
            let hello = hello_with(node, vec![network_id], 1, 10 + n as u8);
            check_hello(&hello, &node.x25519_static, &rosters, &history, 500).unwrap();
        }
        let replay = hello_with(&member, vec![network_id], 4, 11);
        let err = check_hello(&replay, &member.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(
            err.code,
            ErrorCode::StaleSerial,
            "the member's mark was evicted"
        );
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
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters
            .set(&roster_for(&owner, network_id, fixture.node_id, false))
            .unwrap();
        let history = NodeHistory::new();
        let first = hello_with(&fixture, vec![network_id], 1, 10);
        check_hello(&first, &fixture.x25519_static, &rosters, &history, 500).unwrap();

        let replay = hello_with(&fixture, vec![network_id], 1, 10);
        let err =
            check_hello(&replay, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::StaleTimestamp);
    }
    /// A relay holding one Roster per owner key that lists `member`; returns the store and the
    /// networks in order.
    fn rosters_listing(member: NodeId, count: usize) -> (RosterStore, Vec<NetworkId>) {
        let rosters = RosterStore::new();
        let networks = (0..count)
            .map(|_| {
                let owner = SigningKey::generate(&mut rand::rng());
                let network_id = NetworkId::from(owner.verifying_key().to_bytes());
                rosters
                    .set(&roster_for(&owner, network_id, member, false))
                    .unwrap();
                network_id
            })
            .collect();
        (rosters, networks)
    }

    fn unserved_networks(count: usize) -> Vec<NetworkId> {
        (0..count)
            .map(|i| NetworkId::from([(i as u8).wrapping_add(1); 32]))
            .collect()
    }

    /// First multi tenant round, M1 and M2: a HELLO that repeats one NetworkId a couple of
    /// thousand times costs the same few lookups as one that names it once, for a served and
    /// for an unserved network alike.
    #[test]
    fn a_hello_repeating_one_network_is_judged_in_bounded_work() {
        let fixture = fixture();
        let history = NodeHistory::new();
        let (rosters, networks) = rosters_listing(fixture.node_id, 1);
        let unserved = unserved_networks(1)[0];

        let hello = hello_with(&fixture, vec![networks[0]; 2000], 1, 10);
        assert!(check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).is_ok());
        let served_work = rosters.lookup_count();
        assert!(served_work <= 2, "{served_work} lookups for one network");

        let hello = hello_with(&fixture, vec![unserved; 2000], 1, 11);
        let before = rosters.lookup_count();
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotMember);
        assert_eq!(err.network, Some(unserved));
        let unserved_work = rosters.lookup_count() - before;
        assert_eq!(
            unserved_work, served_work,
            "an unserved network costs what a served one does"
        );
    }

    #[test]
    fn dropping_repeats_keeps_a_legitimate_multi_network_claim_working() {
        let fixture = fixture();
        let history = NodeHistory::new();
        let (rosters, networks) = rosters_listing(fixture.node_id, 3);
        let (a, b, c) = (networks[0], networks[1], networks[2]);
        let hello = hello_with(&fixture, vec![a, b, a, c, b, c, a], 1, 10);
        assert_eq!(
            check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap(),
            fixture.node_id
        );
        assert_eq!(dedup_networks(&[a, b, a, c, b, c, a]), vec![a, b, c]);

        // A refusal still names the first claimed network that fails, in order of first
        // appearance, not the repeat.
        let stranger = unserved_networks(2);
        let hello = hello_with(&fixture, vec![a, stranger[0], a, stranger[1]], 1, 11);
        let err = check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotMember);
        assert_eq!(err.network, Some(stranger[0]));
    }

    #[test]
    fn more_than_the_cap_of_distinct_networks_is_refused_before_the_store_is_touched() {
        let fixture = fixture();
        let history = NodeHistory::new();
        let (rosters, networks) = rosters_listing(fixture.node_id, MAX_HELLO_NETWORKS + 1);

        // Exactly the cap passes, repeats beside it notwithstanding.
        let mut at_cap = networks[..MAX_HELLO_NETWORKS].to_vec();
        at_cap.extend_from_slice(&networks[..5]);
        let hello = hello_with(&fixture, at_cap, 1, 10);
        assert!(check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).is_ok());

        let before = rosters.lookup_count();
        let hello = hello_with(&fixture, networks.clone(), 1, 11);
        let served =
            check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(
            rosters.lookup_count(),
            before,
            "no lookup for an over cap HELLO"
        );
        assert_eq!(served.code, ErrorCode::TooLarge);
        assert_eq!(served.network, None);

        // The same number of networks the relay does not serve is refused identically, so the
        // refusal says nothing about what is served.
        let hello = hello_with(&fixture, unserved_networks(MAX_HELLO_NETWORKS + 1), 1, 12);
        let unserved =
            check_hello(&hello, &fixture.x25519_static, &rosters, &history, 500).unwrap_err();
        assert_eq!(unserved, served);
        assert_eq!(rosters.lookup_count(), before);
    }
}
