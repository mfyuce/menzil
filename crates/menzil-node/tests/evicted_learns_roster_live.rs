//! A node that a relay evicts is first sent the Roster of the network concerned, adopts it, and
//! so leaves that network out of its next HELLO and stays attached with its other networks
//! (protocol.md 4.2, 7.3; the twelfth red-team round, N1 and L1).
//!
//! The Roster reaches the relay's store directly (no DOC fan-out), so the relay's own eviction
//! path is the only way the node can learn it. For each of the three reasons (revoked, dropped,
//! `min_serial` raised above the node's serial) the node is told, adopts the newer Roster, and
//! the reconnect with the same Roster store is not refused. Without the Roster in the eviction
//! the node would claim the network again and be refused as a whole.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{identity, session_config, start_relay, trust_test_certificate, unix_now};
use ed25519_dalek::SigningKey;
use menzil_node::{NodeError, RosterStore, Session};
use menzil_proto::trust::Signer;
use menzil_proto::{
    ErrorCode, NetworkId, NodeId, PROTOCOL_VERSION, Record, RevokedMember, Roster, RosterBody,
    RosterMember, Steward, StewardBody, StewardKey,
};
use tokio::time::timeout;

fn roster(
    owner: &SigningKey,
    seq: u64,
    members: &[(NodeId, u32)],
    revoked: &[NodeId],
) -> (NetworkId, Roster) {
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq,
        issued: unix_now() - 60,
        expires: unix_now() + 7 * 86_400,
        members: members
            .iter()
            .map(|&(node_id, min_serial)| RosterMember {
                node_id,
                min_serial,
            })
            .collect(),
        revoked: revoked
            .iter()
            .map(|&node_id| RevokedMember { node_id, since: 1 })
            .collect(),
        stewards: vec![],
        labels: vec![],
    };
    (network_id, Roster::sign(owner, &body).unwrap())
}

/// A steward network: the owner signs bases that carry one `Steward` entry, the steward renews
/// them (same members and revocations, `seq` + 1).
struct StewardNet {
    owner: SigningKey,
    steward: SigningKey,
    network_id: NetworkId,
}

impl StewardNet {
    fn new() -> Self {
        let owner = SigningKey::generate(&mut rand::rng());
        let steward = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        Self {
            owner,
            steward,
            network_id,
        }
    }

    /// The owner signed base at `base_seq` (expired when `expired`) and the steward's renewal at
    /// `base_seq + 1`, fresh.
    fn pair(
        &self,
        base_seq: u64,
        expired: bool,
        members: &[(NodeId, u32)],
        revoked: &[NodeId],
    ) -> (Roster, Roster) {
        let now = unix_now();
        let day = 86_400;
        let entry = Steward::sign(
            &self.owner,
            &StewardBody {
                v: PROTOCOL_VERSION,
                network_id: self.network_id,
                steward_pub: StewardKey::from(self.steward.verifying_key().to_bytes()),
                may: vec!["renew".to_string()],
                not_after: now + 30 * day,
            },
        )
        .unwrap();
        let mut body = RosterBody {
            v: PROTOCOL_VERSION,
            network_id: self.network_id,
            seq: base_seq,
            issued: if expired { now - 10 * day } else { now - 60 },
            expires: if expired { now - day } else { now + 5 * day },
            members: members
                .iter()
                .map(|&(node_id, min_serial)| RosterMember {
                    node_id,
                    min_serial,
                })
                .collect(),
            revoked: revoked
                .iter()
                .map(|&node_id| RevokedMember { node_id, since: 1 })
                .collect(),
            stewards: vec![entry],
            labels: vec![],
        };
        let base = Roster::sign(&self.owner, &body).unwrap();
        body.seq = base_seq + 1;
        body.issued = now - 30;
        body.expires = now + 7 * day;
        (base, Roster::sign(&self.steward, &body).unwrap())
    }
}

fn assert_steward_held(held: &RosterStore, network: &NetworkId, seq: u64, what: &str) {
    assert_eq!(
        held.body(network).unwrap().seq,
        seq,
        "{what}: the node adopted the steward Roster"
    );
    assert!(
        matches!(held.signer(network), Some(Signer::Steward { .. })),
        "{what}: held signer is the steward"
    );
}

#[tokio::test]
async fn an_evicted_node_adopts_the_roster_it_is_sent_and_keeps_its_other_networks() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1_048_576).await;
    let env = HashMap::new();
    let other = identity().node_id;

    // (expected ERROR, what the next Roster of network A says about the node)
    type Next = fn(NodeId, NodeId) -> (Vec<(NodeId, u32)>, Vec<NodeId>);
    let cases: [(ErrorCode, Next); 3] = [
        (ErrorCode::Revoked, |node, other| {
            (vec![(other, 1)], vec![node])
        }),
        (ErrorCode::NotMember, |_node, other| {
            (vec![(other, 1)], vec![])
        }),
        (ErrorCode::StaleSerial, |node, other| {
            (vec![(node, 2), (other, 1)], vec![])
        }),
    ];
    for (expected, next) in cases {
        let node = identity();
        let owner_a = SigningKey::generate(&mut rand::rng());
        let owner_b = SigningKey::generate(&mut rand::rng());
        let (network_a, a1) = roster(&owner_a, 1, &[(node.node_id, 1), (other, 1)], &[]);
        let (network_b, b1) = roster(&owner_b, 1, &[(node.node_id, 1)], &[]);
        relay.relay.rosters().set(&a1).unwrap();
        relay.relay.rosters().set(&b1).unwrap();

        let mut config = session_config(&relay, &node, network_a);
        config.networks = vec![network_a, network_b];
        let held = Arc::new(RosterStore::new());
        held.set(&a1).unwrap();
        held.set(&b1).unwrap();
        let mut session = Session::connect(&config, &env, Arc::clone(&held))
            .await
            .unwrap();

        // The Roster only the relay's store hears of: the node learns it from the eviction.
        let (members, revoked) = next(node.node_id, other);
        let (_, a2) = roster(&owner_a, 2, &members, &revoked);
        relay.relay.rosters().set(&a2).unwrap();

        let told = timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("the relay evicts the node");
        assert!(
            matches!(&told, Ok(Record::Error(body)) if body.code == expected),
            "{expected:?}: got {told:?}"
        );
        let goaway = timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("the relay ends the session");
        assert!(
            matches!(&goaway, Err(NodeError::Goaway { reason, .. }) if reason == "revoked"),
            "{expected:?}: got {goaway:?}"
        );
        assert_eq!(
            held.body(&network_a).unwrap().seq,
            2,
            "{expected:?}: the node adopted the Roster it was sent before the ERROR"
        );

        // The reconnect leaves A out and stays attached with B.
        let mut again = Session::connect(&config, &env, Arc::clone(&held))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_secs(2), again.recv()).await.is_err(),
            "{expected:?}: nothing ends the reconnect, it claims only B"
        );
        again.close().await;
    }

    // A HELLO refused for standing: the node holds a stale Roster (seq 1) that still lists it,
    // the relay holds seq 2. The refusal sends that Roster before the ERROR, so the node learns
    // it; `not_member` sends none (isolation rule I2).
    let refused: [(ErrorCode, Next, bool); 3] = [
        (
            ErrorCode::Revoked,
            |node, other| (vec![(other, 1)], vec![node]),
            true,
        ),
        (
            ErrorCode::StaleSerial,
            |node, other| (vec![(node, 2), (other, 1)], vec![]),
            true,
        ),
        (
            ErrorCode::NotMember,
            |_node, other| (vec![(other, 1)], vec![]),
            false,
        ),
    ];
    for (expected, next, learns) in refused {
        let node = identity();
        let owner_a = SigningKey::generate(&mut rand::rng());
        let (network_a, a1) = roster(&owner_a, 1, &[(node.node_id, 1), (other, 1)], &[]);
        let (members, revoked) = next(node.node_id, other);
        let (_, a2) = roster(&owner_a, 2, &members, &revoked);
        relay.relay.rosters().set(&a1).unwrap();
        relay.relay.rosters().set(&a2).unwrap();

        let config = session_config(&relay, &node, network_a);
        let held = Arc::new(RosterStore::new());
        held.set(&a1).unwrap();
        let mut session = Session::connect(&config, &env, Arc::clone(&held))
            .await
            .unwrap();
        let told = timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("the relay refuses the HELLO");
        assert!(
            matches!(&told, Ok(Record::Error(body)) if body.code == expected),
            "refused {expected:?}: got {told:?}"
        );
        assert_eq!(
            held.body(&network_a).unwrap().seq,
            if learns { 2 } else { 1 },
            "refused {expected:?}: the Roster is sent before the ERROR only for standing"
        );
    }

    // STEWARD network. The relay holds an owner signed base and the steward's renewal on it; the
    // node learns the pair (base first) from the eviction or the refused HELLO.
    let now = unix_now();
    // (expected ERROR, base expired, base members and min_serial, base revoked)
    type Steward = fn(NodeId, NodeId) -> (Vec<(NodeId, u32)>, Vec<NodeId>);
    let evictions: [(&str, ErrorCode, bool, Steward); 3] = [
        (
            "steward revoked",
            ErrorCode::Revoked,
            true,
            |node, other| (vec![(other, 1)], vec![node]),
        ),
        (
            "steward min_serial",
            ErrorCode::StaleSerial,
            false,
            |node, other| (vec![(node, 2), (other, 1)], vec![]),
        ),
        (
            "steward dropped",
            ErrorCode::NotMember,
            false,
            |_node, other| (vec![(other, 1)], vec![]),
        ),
    ];
    for (what, expected, expired, next) in evictions {
        let node = identity();
        let net = StewardNet::new();
        let network_a = net.network_id;
        let owner_b = SigningKey::generate(&mut rand::rng());
        let (network_b, b1) = roster(&owner_b, 1, &[(node.node_id, 1)], &[]);
        relay.relay.rosters().set(&b1).unwrap();
        let held = Arc::new(RosterStore::new());
        held.set(&b1).unwrap();
        if expected == ErrorCode::NotMember {
            // The node holds a steward Roster that lists it.
            let (b0, r0) = net.pair(5, false, &[(node.node_id, 1), (other, 1)], &[]);
            held.adopt_roster(&r0, Some(&b0), now).unwrap();
            relay.relay.rosters().adopt(&r0, Some(&b0), now).unwrap();
        } else {
            let (_, a1) = roster(&net.owner, 1, &[(node.node_id, 1), (other, 1)], &[]);
            held.set(&a1).unwrap();
            relay.relay.rosters().set(&a1).unwrap();
        }

        let mut config = session_config(&relay, &node, network_a);
        config.networks = vec![network_a, network_b];
        let mut session = Session::connect(&config, &env, Arc::clone(&held))
            .await
            .unwrap();

        let (members, revoked) = next(node.node_id, other);
        let (base, renewal) = net.pair(10, expired, &members, &revoked);
        relay
            .relay
            .rosters()
            .adopt(&renewal, Some(&base), now)
            .unwrap();

        let told = timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("the relay evicts the node");
        assert!(
            matches!(&told, Ok(Record::Error(body)) if body.code == expected),
            "{what}: got {told:?}"
        );
        let goaway = timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("the relay ends the session");
        assert!(
            matches!(&goaway, Err(NodeError::Goaway { reason, .. }) if reason == "revoked"),
            "{what}: got {goaway:?}"
        );
        assert_steward_held(&held, &network_a, 11, what);

        let mut again = Session::connect(&config, &env, Arc::clone(&held))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_secs(2), again.recv()).await.is_err(),
            "{what}: nothing ends the reconnect, it claims only B"
        );
        again.close().await;
    }

    // Refused HELLO against a steward pair: Revoked and StaleSerial learn it, NotMember nothing.
    let refused_steward: [(&str, ErrorCode, Steward, bool); 3] = [
        (
            "refused steward revoked",
            ErrorCode::Revoked,
            |node, other| (vec![(other, 1)], vec![node]),
            true,
        ),
        (
            "refused steward min_serial",
            ErrorCode::StaleSerial,
            |node, other| (vec![(node, 2), (other, 1)], vec![]),
            true,
        ),
        (
            "refused steward dropped",
            ErrorCode::NotMember,
            |_node, other| (vec![(other, 1)], vec![]),
            false,
        ),
    ];
    for (what, expected, next, learns) in refused_steward {
        let node = identity();
        let net = StewardNet::new();
        let network_a = net.network_id;
        let (_, a1) = roster(&net.owner, 1, &[(node.node_id, 1), (other, 1)], &[]);
        let (members, revoked) = next(node.node_id, other);
        let (base, renewal) = net.pair(10, false, &members, &revoked);
        relay.relay.rosters().set(&a1).unwrap();
        relay
            .relay
            .rosters()
            .adopt(&renewal, Some(&base), now)
            .unwrap();

        let config = session_config(&relay, &node, network_a);
        let held = Arc::new(RosterStore::new());
        held.set(&a1).unwrap();
        let mut session = Session::connect(&config, &env, Arc::clone(&held))
            .await
            .unwrap();
        let told = timeout(Duration::from_secs(10), session.recv())
            .await
            .expect("the relay refuses the HELLO");
        assert!(
            matches!(&told, Ok(Record::Error(body)) if body.code == expected),
            "{what}: got {told:?}"
        );
        if learns {
            assert_steward_held(&held, &network_a, 11, what);
        } else {
            assert_eq!(
                held.body(&network_a).unwrap().seq,
                1,
                "{what}: nothing learned"
            );
            assert!(
                matches!(held.signer(&network_a), Some(Signer::Owner)),
                "{what}"
            );
        }
    }
}
