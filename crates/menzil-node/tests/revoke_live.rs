//! L4k K4 over a real relay: the revalidator at the node that serves. A opens streams to B's
//! `tcp:` services; B's documents change and nothing is restarted.
//!
//! 1. B adopts a pair whose Policy no longer has A's grant for `tcp:app`: A's stream to it is
//!    reset (A reads `ConnectionReset`, B's target an RST) within two seconds, A's stream to
//!    `tcp:keep` goes on, the session stays: a new `tcp:app` OPEN is answered `no_grant` and A
//!    still fetches documents over it.
//! 2. B then holds a Roster (alone, as the relay delivers it) that revokes A: the session ends,
//!    A's remaining stream is reset, and A's next request gets no session (B, which refuses
//!    silently, answers no handshake).
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
    PATIENCE, echo_round_trip, echo_server, grant, identity, policy, reissue, seed_roster, service,
    session_config, start_relay, trust_test_certificate, unix_now,
};
use futures_util::io::AsyncReadExt;
use menzil_node::docs::{DocsParams, STREAM_DEADLINE, StoreDocs};
use menzil_node::{
    DocStore, LocalServices, LocalTarget, Node, NodeConfig, NodeOpenError, OpenStreamError,
    PolicyStore, RefuseAll, RosterStore, docs_service,
};
use menzil_proto::trust::Bundle;
use menzil_proto::{ErrorCode, RevokedMember, Roster};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[tokio::test]
async fn b_resets_the_stream_whose_grant_went_then_ends_the_session_of_a_revoked_peer() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    let policy1 = policy(
        &owner,
        network_id,
        &a,
        &b,
        vec![grant(
            network_id,
            a.node_id,
            b.node_id,
            &["tcp:app", "tcp:keep"],
            None,
        )],
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

    // B's two targets, each reporting how a connection to it ended.
    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_port = app.local_addr().unwrap().port();
    let (app_ended_tx, mut app_ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(app, app_ended_tx));
    let keep = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let keep_port = keep.local_addr().unwrap().port();
    let (keep_ended_tx, mut keep_ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(keep, keep_ended_tx));
    let services = LocalServices::new()
        .serve(service("tcp:app"), LocalTarget::new("127.0.0.1", app_port))
        .unwrap()
        .serve(
            service("tcp:keep"),
            LocalTarget::new("127.0.0.1", keep_port),
        )
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
            policies: a_policies.clone(),
            rosters: a_rosters.clone(),
        },
        RefuseAll,
    )
    .unwrap();
    nb.wait_attached(PATIENCE).await.expect("B must attach");
    na.wait_attached(PATIENCE).await.expect("A must attach");
    let open = |name: &'static str| {
        let na = &na;
        async move {
            timeout(
                PATIENCE,
                na.open_stream(b.node_id, network_id, service(name), None),
            )
            .await
            .expect("the OPEN must be answered")
        }
    };

    let mut app_stream = open("tcp:app").await.expect("granted");
    echo_round_trip(&mut app_stream, b"app").await;
    let mut keep_stream = open("tcp:keep").await.expect("granted");
    echo_round_trip(&mut keep_stream, b"keep").await;

    // --- 1. a pair without the `tcp:app` grant reaches B ---------------------------------
    let (roster2, policy2) = reissue(
        &owner,
        &roster1,
        &policy1,
        2,
        |_| {},
        |body| {
            body.grants = vec![grant(network_id, a.node_id, b.node_id, &["tcp:keep"], None)];
        },
    );
    DocStore::new(&b_rosters, &b_policies)
        .adopt(
            &Bundle {
                roster: Some(roster2.clone()),
                policy: Some(policy2.clone()),
                ..Bundle::default()
            },
            unix_now(),
        )
        .unwrap();

    let mut byte = [0u8; 1];
    let error = timeout(Duration::from_secs(2), app_stream.read(&mut byte))
        .await
        .expect("the stream whose grant went must be reset within two seconds")
        .expect_err("a reset, not an end of file");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    let target = timeout(PATIENCE, app_ended.recv()).await.unwrap().unwrap();
    assert!(
        matches!(
            target,
            Err(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        ),
        "B's target must see an RST, got {target:?}"
    );
    // The other service is untouched, and so is the session.
    echo_round_trip(&mut keep_stream, b"still granted").await;
    let refused = open("tcp:app").await.expect_err("the grant is gone");
    match refused {
        NodeOpenError::Open(OpenStreamError::Refused { code, .. }) => {
            assert_eq!(code, ErrorCode::NoGrant)
        }
        other => panic!("expected no_grant on the same session, got {other:?}"),
    }
    // menzil:docs needs no grant: A still fetches over the session.
    // The node's own document sync may be using the one docs stream a peer is allowed at a
    // time (right after the session came up, on a loaded machine): ask again.
    let mut docs = None;
    for _ in 0..50 {
        match timeout(
            PATIENCE,
            na.open_stream(b.node_id, network_id, docs_service(), None),
        )
        .await
        .unwrap()
        {
            Ok(stream) => {
                docs = Some(stream);
                break;
            }
            Err(NodeOpenError::Open(OpenStreamError::Refused {
                code: ErrorCode::RateLimited,
                ..
            })) => tokio::time::sleep(Duration::from_millis(200)).await,
            Err(other) => panic!("a member fetches documents: {other:?}"),
        }
    }
    let mut docs = docs.expect("a member fetches documents");
    let report = menzil_node::docs::fetch(
        &mut docs,
        StoreDocs::new(&a_rosters, &a_policies, network_id),
        &DocsParams {
            network_id,
            now: unix_now(),
            deadline: STREAM_DEADLINE,
        },
    )
    .await
    .expect("the fetch works on a session whose grant went");
    assert_eq!(report.peer_policy_seq, Some(2));
    assert_eq!(a_policies.seq(&network_id), Some(2), "and A took the pair");

    // --- 2. a Roster that revokes A reaches B alone -------------------------------------
    let mut roster3 = roster2.decode().unwrap();
    roster3.seq = 3;
    roster3.members.retain(|member| member.node_id != a.node_id);
    roster3.revoked.push(RevokedMember {
        node_id: a.node_id,
        since: unix_now(),
    });
    b_rosters
        .set(&Roster::sign(&owner, &roster3).unwrap())
        .unwrap();

    let error = timeout(Duration::from_secs(2), keep_stream.read(&mut byte))
        .await
        .expect("the session ends: A's remaining stream is reset within two seconds")
        .expect_err("a reset, not an end of file");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    let target = timeout(PATIENCE, keep_ended.recv()).await.unwrap().unwrap();
    assert!(
        matches!(
            target,
            Err(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        ),
        "B's target must see an RST, got {target:?}"
    );
    // A new request is not answered the way a live session would answer (with a refusal in a
    // few milliseconds): the session is gone. A has the Roster from the relay by now and does
    // not dial (`NotAMember`); had it not, B would answer no handshake of a revoked node.
    let again = timeout(
        Duration::from_secs(6),
        na.open_stream(b.node_id, network_id, service("tcp:keep"), None),
    )
    .await;
    assert!(
        !matches!(again, Ok(Ok(_))),
        "a revoked node must not get a stream"
    );
    assert!(
        !matches!(
            again,
            Ok(Err(NodeOpenError::Open(OpenStreamError::Refused { .. })))
        ),
        "the session must be gone, not merely refusing"
    );

    na.shutdown().await;
    nb.shutdown().await;
}
