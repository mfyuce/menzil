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
use menzil_proto::{
    ErrorCode, NetworkId, NodeId, PROTOCOL_VERSION, Record, RevokedMember, Roster, RosterBody,
    RosterMember,
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
}
