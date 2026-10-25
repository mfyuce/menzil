//! L4k K4 over a real relay: this node is revoked. A and B serve each other; B holds a Roster
//! that revokes B (the Roster alone, as the relay delivers it). Every session of B closes, so
//! the stream A opened to B and the stream B opened to A are both reset within two seconds, and
//! B serves and dials nothing from then on.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE`
//! is process-global (see that file's own doc comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use common::{
    PATIENCE, echo_round_trip, echo_server, grant, identity, policy, seed_roster, service,
    session_config, start_relay, trust_test_certificate, unix_now,
};
use futures_util::io::AsyncReadExt;
use menzil_node::{
    EnsureError, LocalServices, LocalTarget, Node, NodeConfig, NodeOpenError, PolicyStore,
    RosterStore,
};
use menzil_proto::{RevokedMember, Roster};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn a_node_that_is_revoked_closes_every_session_and_serves_and_dials_nothing() {
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

    // Each node serves `tcp:app` from its own echo target.
    let mut start = Vec::new();
    let mut ended_by_target = Vec::new();
    for (id, policies, rosters) in [
        (&a, a_policies, a_rosters),
        (&b, b_policies, b_rosters.clone()),
    ] {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let (ended_tx, ended) = mpsc::unbounded_channel();
        tokio::spawn(echo_server(target, ended_tx));
        ended_by_target.push(ended);
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
    echo_round_trip(&mut a_to_b, b"a to b").await;
    let mut b_to_a = timeout(
        PATIENCE,
        nb.open_stream(a.node_id, network_id, service("tcp:app"), None),
    )
    .await
    .unwrap()
    .expect("B may use A's service");
    echo_round_trip(&mut b_to_a, b"b to a").await;

    let mut roster2 = roster1.decode().unwrap();
    roster2.seq = 2;
    roster2.members.retain(|member| member.node_id != b.node_id);
    roster2.revoked.push(RevokedMember {
        node_id: b.node_id,
        since: unix_now(),
    });
    b_rosters
        .set(&Roster::sign(&owner, &roster2).unwrap())
        .unwrap();

    let mut byte = [0u8; 1];
    for (what, stream) in [
        ("A's stream to B", &mut a_to_b),
        ("B's stream to A", &mut b_to_a),
    ] {
        let error = timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap_or_else(|_| panic!("{what} must be reset within two seconds"))
            .expect_err("a reset, not an end of file");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{what}");
    }
    // Both targets saw the streams end by RST.
    for (what, ended) in ["A's target", "B's target"]
        .into_iter()
        .zip(ended_by_target.iter_mut())
    {
        let outcome = timeout(PATIENCE, ended.recv()).await.unwrap().unwrap();
        assert!(
            matches!(
                outcome,
                Err(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
            ),
            "{what} must see an RST, got {outcome:?}"
        );
    }
    // B is out: it dials nothing.
    match timeout(
        PATIENCE,
        nb.open_stream(a.node_id, network_id, service("tcp:app"), None),
    )
    .await
    .unwrap()
    {
        Err(NodeOpenError::Session(EnsureError::NotAMember)) => {}
        other => panic!("a revoked node must not dial, got {:?}", other.map(|_| ())),
    }

    na.shutdown().await;
    nb.shutdown().await;
}
