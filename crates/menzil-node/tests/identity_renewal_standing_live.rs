//! A running node that renews its certificate is judged by the new serial everywhere (cert
//! rotation S4), over a real relay. A and B serve each other. B renews to serial 2
//! (`Node::renew_identity`), then receives a Policy that lists the serial 2 certificate and a
//! Roster that raises B's `min_serial` to 2. B's revalidator and the authorizers of its sessions
//! read the serial from the identity cell, so the session B has had since before the renewal
//! stays open and keeps serving. With the serial B started with (1) the same Roster would end
//! every session of B within two seconds (`own_revocation_live.rs` shows how fast a lost
//! standing ends them).
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE`
//! is process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{
    PATIENCE, echo_round_trip, echo_server, grant, identity, policy, seed_roster, service,
    session_config, start_relay, trust_test_certificate,
};
use menzil_node::{LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RosterStore};
use menzil_proto::{NodeCert, NodeCertBody, PROTOCOL_VERSION, Policy, Roster};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn a_node_that_renewed_is_judged_by_its_new_serial_in_open_sessions() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    let policy1 = policy(
        &owner,
        network_id,
        &a,
        &b,
        vec![
            grant(network_id, a.node_id, b.node_id, &["tcp:app"], None),
            grant(network_id, b.node_id, a.node_id, &["tcp:app"], None),
        ],
    );
    let stores = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy1).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster1).unwrap();
        (policies, rosters)
    };
    let (a_policies, a_rosters) = stores();
    let (b_policies, b_rosters) = stores();

    let mut start = Vec::new();
    for (id, policies, rosters) in [
        (&a, a_policies, a_rosters),
        (&b, b_policies.clone(), b_rosters.clone()),
    ] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (ended_tx, _ended) = mpsc::unbounded_channel();
        tokio::spawn(echo_server(target, ended_tx));
        let services = LocalServices::new()
            .serve(service("tcp:app"), LocalTarget::new("127.0.0.1", port))
            .unwrap();
        start.push(
            Node::start(
                NodeConfig {
                    session: session_config(&relay, id, network_id),
                    env: HashMap::new(),
                    policies,
                    rosters,
                },
                services,
            )
            .unwrap(),
        );
    }
    let nb = start.pop().unwrap();
    let na = start.pop().unwrap();
    nb.wait_attached(PATIENCE).await.expect("B must attach");
    na.wait_attached(PATIENCE).await.expect("A must attach");

    let mut a_to_b = timeout(
        PATIENCE,
        na.open_stream(b.node_id, network_id, service("tcp:app"), None),
    )
    .await
    .unwrap()
    .expect("A may use B's service");
    echo_round_trip(&mut a_to_b, b"before").await;

    // B renews: serial 2, valid at the real clock.
    let renewed = NodeCert::sign(
        &b.signing,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: b.node_id,
            x25519_pub: b.x25519_public,
            serial: 2,
            not_before: 1_000_000_000,
            not_after: 4_000_000_000,
        },
    )
    .unwrap();
    nb.renew_identity(renewed.clone()).unwrap();

    // B's Policy lists the serial 2 certificate first, then its Roster raises the floor to 2: in
    // that order B is never, even for a moment, below the floor by the documents it holds.
    let mut policy2 = policy1.decode().unwrap();
    policy2.seq = 2;
    policy2.certs.push(renewed);
    assert!(
        b_policies
            .set(&Policy::sign(&owner, &policy2).unwrap())
            .unwrap()
    );
    let mut roster2 = roster1.decode().unwrap();
    roster2.seq = 2;
    for member in &mut roster2.members {
        if member.node_id == b.node_id {
            member.min_serial = 2;
        }
    }
    assert!(
        b_rosters
            .set(&Roster::sign(&owner, &roster2).unwrap())
            .unwrap()
    );

    // Longer than the two seconds a lost standing takes to end the sessions.
    tokio::time::sleep(Duration::from_millis(3500)).await;
    echo_round_trip(&mut a_to_b, b"after").await;
    // And B still dials: its own standing holds by the new serial.
    let mut b_to_a = timeout(
        PATIENCE,
        nb.open_stream(a.node_id, network_id, service("tcp:app"), None),
    )
    .await
    .unwrap()
    .expect("B may still use A's service");
    echo_round_trip(&mut b_to_a, b"b to a").await;

    na.shutdown().await;
    nb.shutdown().await;
}
