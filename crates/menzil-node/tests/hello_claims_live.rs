//! A node leaves out of its HELLO a network whose Roster it holds revokes it (protocol.md 4.1;
//! TODO.md L4k K5), over a real relay: `Session::connect` dials, handshakes and sends HELLO with
//! the claims it decided on.
//!
//! The relay refuses a HELLO that claims a network revoking the node as a whole (ERROR `revoked`,
//! then the connection ends). So the node of this test, revoked in network A and a member of B,
//! stays attached only if it did not claim A. The control run holds no Roster for A and is
//! refused, which shows the relay would have refused the claim.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{identity, session_config, start_relay, trust_test_certificate};
use ed25519_dalek::SigningKey;
use menzil_node::{RosterStore, Session};
use menzil_proto::{
    ErrorCode, NetworkId, NodeId, PROTOCOL_VERSION, Record, RevokedMember, Roster, RosterBody,
    RosterMember,
};
use tokio::time::timeout;

fn roster(owner: &SigningKey, members: &[NodeId], revoked: &[NodeId]) -> (NetworkId, Roster) {
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: members
            .iter()
            .map(|&node_id| RosterMember {
                node_id,
                min_serial: 1,
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
async fn a_revoked_node_claims_only_the_networks_that_do_not_revoke_it() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1_048_576).await;
    let node = identity();
    let owner_a = SigningKey::generate(&mut rand::rng());
    let owner_b = SigningKey::generate(&mut rand::rng());
    let (network_a, roster_a) = roster(&owner_a, &[], &[node.node_id]);
    let (network_b, roster_b) = roster(&owner_b, &[node.node_id], &[]);
    relay.relay.rosters().set(&roster_a).unwrap();
    relay.relay.rosters().set(&roster_b).unwrap();

    let mut config = session_config(&relay, &node, network_a);
    config.networks = vec![network_a, network_b];
    let env = HashMap::new();

    // Control: a node that does not hold A's Roster claims A, and the relay refuses it.
    let blind = Arc::new(RosterStore::new());
    blind.set(&roster_b).unwrap();
    let mut refused = Session::connect(&config, &env, blind).await.unwrap();
    let ended = timeout(Duration::from_secs(10), refused.recv())
        .await
        .expect("the relay answers a HELLO that claims a revoking network");
    assert!(
        matches!(&ended, Ok(Record::Error(body)) if body.code == ErrorCode::Revoked),
        "the control run is refused with ERROR revoked, got {ended:?}"
    );

    // The node that holds A's Roster leaves A out and stays attached with B.
    let informed = Arc::new(RosterStore::new());
    informed.set(&roster_a).unwrap();
    informed.set(&roster_b).unwrap();
    let mut attached = Session::connect(&config, &env, informed).await.unwrap();
    assert!(
        timeout(Duration::from_secs(2), attached.recv())
            .await
            .is_err(),
        "nothing ends this session: it did not claim the network that revokes it"
    );
    attached.close().await;
}
