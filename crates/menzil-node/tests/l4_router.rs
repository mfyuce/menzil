//! The L4 router (TODO.md L4h6) over a real relay: two nodes, each a real
//! [`menzil_node::run_session`] against a real in-process
//! `menzil_relay::Relay` (real TLS, WebSocket and Noise), each with a real
//! [`menzil_node::new_router`] on top, doing the whole L4 handshake with
//! each other through the relay's SEND/RECV forwarding: the signed
//! documents, the admission checks, the session actors, `yamux` and bytes
//! both ways. Then the relay supersedes one node's attachment, which is the
//! L3 reconnect that has to end its sessions and make the next request start
//! over. `src/l4_router/tests.rs` covers every branch of the same code over
//! an in-memory stand-in for the relay; this is the same code with nothing
//! stood in.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly
//! one: `SSL_CERT_FILE` is process-global (see that file's own doc
//! comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::{
    Identity, PATIENCE, TestRelay, identity, node_cert, policy, seed_roster, session_config,
    start_relay, trust_test_certificate,
};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_node::{
    EndReason, L4SessionAcceptor, L4SessionHandle, LocalIdentity, PolicyStore, RosterStore,
    RouterConfig, RouterHandle, RouterParts, SendBudgets, Session, SessionEvent, SessionReady,
    new_router, run_session,
};
use menzil_proto::{Grant, NetworkId, NodeOrWildcard, Principal, PrincipalTarget};
use tokio::sync::mpsc;
use tokio::time::timeout;

struct LiveNode {
    id: Identity,
    handle: RouterHandle,
    ready: mpsc::UnboundedReceiver<SessionReady>,
    passthrough: mpsc::Receiver<SessionEvent>,
    task: tokio::task::JoinHandle<()>,
}

/// A node attached to `relay` with a router on top, holding the network's
/// documents.
fn live_node(
    relay: &TestRelay,
    id: Identity,
    network_id: NetworkId,
    policies: &Arc<PolicyStore>,
    rosters: &Arc<RosterStore>,
) -> LiveNode {
    let (events_tx, events_rx) = mpsc::channel(256);
    let (outbound_tx, outbound_rx) = mpsc::channel(256);
    let task = tokio::spawn(run_session(
        session_config(relay, &id, network_id),
        HashMap::new(),
        events_tx,
        outbound_rx,
        rosters.clone(),
    ));
    let config = RouterConfig::new(
        LocalIdentity {
            node_cert: node_cert(&id),
            x25519_private: id.x25519_private,
        },
        relay.id.node_id,
        policies.clone(),
        rosters.clone(),
        SendBudgets::new(),
    )
    .unwrap();
    let RouterParts {
        handle,
        ready,
        passthrough,
        task: router,
        ..
    } = new_router(config, outbound_tx, events_rx);
    // The router task is detached; it ends when `run_session`'s events do.
    tokio::spawn(router);
    LiveNode {
        id,
        handle,
        ready,
        passthrough,
        task,
    }
}

/// Waits for the router's echo of the next `Attached` and returns its epoch.
async fn next_attached(node: &mut LiveNode) -> menzil_node::Epoch {
    timeout(PATIENCE, async {
        loop {
            match node.passthrough.recv().await {
                Some(SessionEvent::Attached { epoch, .. }) => return epoch,
                Some(_) => {}
                None => panic!("the router ended"),
            }
        }
    })
    .await
    .expect("the node never attached")
}

async fn next_detached(node: &mut LiveNode) {
    timeout(PATIENCE, async {
        loop {
            match node.passthrough.recv().await {
                Some(SessionEvent::Detached { .. }) => return,
                Some(_) => {}
                None => panic!("the router ended"),
            }
        }
    })
    .await
    .expect("the node never detached");
}

/// A stream opened on `from`, accepted on `to`, and bytes both ways.
async fn exchange_bytes(from: &L4SessionHandle, to_acceptor: &mut L4SessionAcceptor) {
    let mut opened = from.open_stream().await.unwrap();
    opened.write_all(b"ping").await.unwrap();
    let mut accepted = timeout(PATIENCE, to_acceptor.accept())
        .await
        .expect("the peer must see the stream")
        .expect("the session is alive");
    let mut buf = [0u8; 4];
    accepted.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    accepted.write_all(b"pong").await.unwrap();
    opened.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
}

#[tokio::test]
async fn l4_router_over_a_real_relay() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster) = seed_roster(&relay, &[&a, &b]);
    let grant = Grant {
        from: Principal {
            network_id,
            target: PrincipalTarget::Node(a.node_id),
        },
        to_node: NodeOrWildcard::Node(b.node_id),
        services: vec!["tcp:ssh".parse().unwrap()],
        expires: None,
    };
    let policy = policy(&owner, network_id, &a, &b, vec![grant]);
    let stores = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster).unwrap();
        (policies, rosters)
    };
    let (a_policies, a_rosters) = stores();
    let (b_policies, b_rosters) = stores();
    let a_session_config = session_config(&relay, &a, network_id);
    let mut na = live_node(&relay, a, network_id, &a_policies, &a_rosters);
    let mut nb = live_node(&relay, b, network_id, &b_policies, &b_rosters);
    let epoch1 = next_attached(&mut na).await;
    next_attached(&mut nb).await;

    // --- a session over the real relay ---------------------------------
    let handle = timeout(
        PATIENCE,
        na.handle.ensure_session(nb.id.node_id, network_id),
    )
    .await
    .expect("the handshake must finish")
    .expect("and succeed");
    let mut ready_a = timeout(PATIENCE, na.ready.recv()).await.unwrap().unwrap();
    let mut ready_b = timeout(PATIENCE, nb.ready.recv()).await.unwrap().unwrap();
    assert_eq!(ready_a.peer, nb.id.node_id);
    assert_eq!(ready_b.peer, na.id.node_id);
    assert_eq!(ready_a.epoch, epoch1);
    assert_eq!(ready_a.peer_policy_seq, Some(1));
    exchange_bytes(&handle, &mut ready_b.acceptor).await;
    exchange_bytes(&ready_b.handle, &mut ready_a.acceptor).await;

    // --- the relay supersedes A's attachment ----------------------------
    let usurper = Session::connect(&a_session_config, &HashMap::new(), a_rosters.clone())
        .await
        .unwrap();
    drop(usurper);
    next_detached(&mut na).await;
    let reason = timeout(PATIENCE, ready_a.acceptor.closed())
        .await
        .expect("A's session must end with its attachment");
    assert!(
        matches!(reason.as_ref(), EndReason::EpochEnded),
        "{reason:?}"
    );
    let epoch2 = next_attached(&mut na).await;
    assert!(epoch2 > epoch1);

    // The next request starts over, and B (which still holds the old
    // session) takes the new handshake as a replacement.
    let handle2 = timeout(
        PATIENCE,
        na.handle.ensure_session(nb.id.node_id, network_id),
    )
    .await
    .expect("the second handshake must finish")
    .expect("and succeed");
    let mut ready_a2 = timeout(PATIENCE, na.ready.recv()).await.unwrap().unwrap();
    let mut ready_b2 = timeout(PATIENCE, nb.ready.recv()).await.unwrap().unwrap();
    assert_eq!(ready_a2.epoch, epoch2);
    exchange_bytes(&handle2, &mut ready_b2.acceptor).await;
    exchange_bytes(&ready_b2.handle, &mut ready_a2.acceptor).await;
    let old_at_b = timeout(PATIENCE, ready_b.acceptor.closed())
        .await
        .expect("B's replaced session must end");
    assert!(
        matches!(old_at_b.as_ref(), EndReason::ClosedLocally(None)),
        "{old_at_b:?}"
    );

    na.task.abort();
    nb.task.abort();
}
