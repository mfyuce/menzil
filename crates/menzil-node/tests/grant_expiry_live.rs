//! L4k K4 over a real relay: a grant that expires. B serves `tcp:app` to A; B adopts a pair
//! whose grant for A ends three seconds from now. The revalidator wakes at that second by its
//! own deadline (no document changes then): A's stream is reset within a second of it, the
//! session stays, and the next OPEN is `no_grant`.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE`
//! is process-global (see that file's own doc comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{
    PATIENCE, echo_round_trip, echo_server, grant, identity, policy, reissue, seed_roster, service,
    session_config, start_relay, trust_test_certificate, unix_now,
};
use futures_util::io::AsyncReadExt;
use menzil_node::{
    DocStore, LocalServices, LocalTarget, Node, NodeConfig, NodeOpenError, OpenStreamError,
    PolicyStore, RefuseAll, RosterStore,
};
use menzil_proto::ErrorCode;
use menzil_proto::trust::Bundle;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Wall clock, as seconds with a fraction.
fn wall() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[tokio::test]
async fn a_stream_is_reset_within_a_second_of_the_expiry_of_its_grant() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    let policy1 = policy(
        &owner,
        network_id,
        &a,
        &b,
        vec![grant(network_id, a.node_id, b.node_id, &["tcp:app"], None)],
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

    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_port = app.local_addr().unwrap().port();
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(app, ended_tx));
    let services = LocalServices::new()
        .serve(service("tcp:app"), LocalTarget::new("127.0.0.1", app_port))
        .unwrap();
    let nb = Node::start(
        NodeConfig {
            session: session_config(&relay, &b, network_id),
            env: HashMap::new(),
            policies: b_policies.clone(),
            rosters: b_rosters.clone(),
        },
        services,
    )
    .unwrap();
    let na = Node::start(
        NodeConfig {
            session: session_config(&relay, &a, network_id),
            env: HashMap::new(),
            policies: a_policies,
            rosters: a_rosters,
        },
        RefuseAll,
    )
    .unwrap();
    nb.wait_attached(PATIENCE).await.expect("B must attach");
    na.wait_attached(PATIENCE).await.expect("A must attach");

    let mut stream = timeout(
        PATIENCE,
        na.open_stream(b.node_id, network_id, service("tcp:app"), None),
    )
    .await
    .unwrap()
    .expect("granted");
    echo_round_trip(&mut stream, b"before").await;

    // B adopts the same pair with the grant now ending at `expires`.
    let expires = unix_now() + 4;
    let (roster2, policy2) = reissue(
        &owner,
        &roster1,
        &policy1,
        2,
        |_| {},
        |body| {
            body.grants = vec![grant(
                network_id,
                a.node_id,
                b.node_id,
                &["tcp:app"],
                Some(expires),
            )];
        },
    );
    DocStore::new(&b_rosters, &b_policies)
        .adopt(
            &Bundle {
                roster: Some(roster2),
                policy: Some(policy2),
                ..Bundle::default()
            },
            unix_now(),
        )
        .unwrap();
    echo_round_trip(&mut stream, b"still granted").await;
    assert!(
        wall() < expires as f64,
        "the machine is too slow for this test: the grant ended before the stream was checked"
    );

    let mut byte = [0u8; 1];
    let error = timeout(Duration::from_secs(10), stream.read(&mut byte))
        .await
        .expect("the stream must be reset when its grant expires")
        .expect_err("a reset, not an end of file");
    let reset_at = wall();
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert!(
        reset_at >= expires as f64,
        "reset {:.3}s before the grant ended",
        expires as f64 - reset_at
    );
    assert!(
        reset_at < expires as f64 + 1.0,
        "reset {:.3}s after the grant ended",
        reset_at - expires as f64
    );
    let target = timeout(PATIENCE, ended.recv()).await.unwrap().unwrap();
    assert!(
        matches!(
            target,
            Err(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        ),
        "B's target must see an RST, got {target:?}"
    );

    // The session stays; the grant is gone.
    match timeout(
        PATIENCE,
        na.open_stream(b.node_id, network_id, service("tcp:app"), None),
    )
    .await
    .unwrap()
    {
        Err(NodeOpenError::Open(OpenStreamError::Refused { code, .. })) => {
            assert_eq!(code, ErrorCode::NoGrant)
        }
        other => panic!("expected no_grant, got {:?}", other.map(|_| ())),
    }

    na.shutdown().await;
    nb.shutdown().await;
}
