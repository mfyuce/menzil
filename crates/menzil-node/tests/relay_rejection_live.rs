//! A node remembers why the relay turned it away or put it out, and forgets it once an
//! attachment has lasted without being turned away (`run_session_observed`, `RelayNotes`;
//! protocol.md 4.2, 7.3).
//!
//! Four things against a real relay, in one run:
//! 1. a HELLO claiming a network whose Roster does not list the node is answered ERROR
//!    `not_member`, and the notes hold that code with the time;
//! 2. the relay then holds a Roster that lists the node: the reconnect is not turned away, and
//!    once it has settled the notes are empty again;
//! 3. a Roster that drops the node, on a settled session: the relay evicts it with ERROR
//!    `not_member` and GOAWAY `revoked`, and the notes hold both, also after the node has
//!    reconnected without that network (it is not a good attach for it);
//! 4. a whole `Node` reports the same through `last_relay_error()`.
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
use menzil_node::{
    Node, NodeConfig, PolicyStore, RefuseAll, RelayError, RelayNotes, RosterStore, SessionEvent,
    run_session_observed,
};
use menzil_proto::{
    ErrorCode, NetworkId, NodeId, PROTOCOL_VERSION, Roster, RosterBody, RosterMember,
};
use tokio::sync::{mpsc, watch};

fn roster(owner: &SigningKey, seq: u64, members: &[NodeId]) -> (NetworkId, Roster) {
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq,
        issued: unix_now() - 60,
        expires: unix_now() + 7 * 86_400,
        members: members
            .iter()
            .map(|&node_id| RosterMember {
                node_id,
                min_serial: 1,
            })
            .collect(),
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    (network_id, Roster::sign(owner, &body).unwrap())
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..4_000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("gave up waiting for {what}");
}

#[tokio::test]
async fn the_relays_rejection_is_remembered_and_forgotten_after_a_good_attachment() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1_048_576).await;
    let node = identity();
    let other = identity().node_id;
    let owner = SigningKey::generate(&mut rand::rng());
    // The node is not listed in network A.
    let (network, a1) = roster(&owner, 1, &[other]);
    relay.relay.rosters().set(&a1).unwrap();

    let config = session_config(&relay, &node, network);
    let notes = RelayNotes::with_settle(Duration::from_secs(1));
    let (events_tx, mut events_rx) = mpsc::channel::<SessionEvent>(16);
    let (_outbound_tx, outbound_rx) = mpsc::channel(16);
    let (stop_tx, stop_rx) = watch::channel(false);
    let started = unix_now();
    let task = tokio::spawn(run_session_observed(
        config,
        HashMap::new(),
        events_tx,
        outbound_rx,
        Arc::new(RosterStore::new()),
        stop_rx,
        notes.clone(),
    ));
    tokio::spawn(async move { while events_rx.recv().await.is_some() {} });

    // 1. Turned away at HELLO.
    until("the rejection", || notes.last_error().is_some()).await;
    let first = notes.last_error().unwrap();
    assert_eq!(first.code, Some(ErrorCode::NotMember), "{first:?}");
    assert!(!first.message.is_empty(), "the relay's own words are kept");
    assert_eq!(first.goaway, None, "a refused HELLO has no GOAWAY");
    assert!(
        first.at >= started && first.at <= unix_now(),
        "the time it came: {first:?}"
    );

    // 2. A Roster that lists the node: the next attachment is good, and settles.
    let (_, a2) = roster(&owner, 2, &[other, node.node_id]);
    relay.relay.rosters().set(&a2).unwrap();
    until("the rejection to be forgotten", || {
        notes.last_error().is_none()
    })
    .await;

    // 3. Dropped on a settled session: ERROR and GOAWAY, both kept.
    let (_, a3) = roster(&owner, 3, &[other]);
    relay.relay.rosters().set(&a3).unwrap();
    until("the eviction", || notes.last_error().is_some()).await;
    let evicted: RelayError = notes.last_error().unwrap();
    assert_eq!(evicted.code, Some(ErrorCode::NotMember), "{evicted:?}");
    assert_eq!(evicted.goaway.as_deref(), Some("revoked"), "{evicted:?}");
    assert!(evicted.at >= first.at);
    // The node adopted the Roster it was sent, so it reconnects without claiming network A: that
    // attachment settles (a second, and then some), but it is not a good attach for A, and the
    // reason stays.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(notes.last_error(), Some(evicted.clone()));

    stop_tx.send(true).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), task).await;

    // 4. A whole node that network A's Roster (now #3) does not list says why it is not attached.
    let stranger = identity();
    let node = Node::start(
        NodeConfig {
            session: session_config(&relay, &stranger, network),
            env: HashMap::new(),
            policies: Arc::new(PolicyStore::new()),
            rosters: Arc::new(RosterStore::new()),
        },
        RefuseAll,
    )
    .unwrap();
    assert_eq!(node.last_relay_error(), None, "nothing yet");
    assert!(!node.is_attached(), "not before it has dialed");
    until("the node to be turned away", || {
        node.last_relay_error().is_some()
    })
    .await;
    let told = node.last_relay_error().unwrap();
    assert_eq!(told.code, Some(ErrorCode::NotMember), "{told:?}");
    node.shutdown().await;

    // A node the Roster lists attaches, is attached, and has nothing held against it.
    let member = identity();
    let (_, a4) = roster(&owner, 4, &[other, member.node_id]);
    relay.relay.rosters().set(&a4).unwrap();
    let node = Node::start(
        NodeConfig {
            session: session_config(&relay, &member, network),
            env: HashMap::new(),
            policies: Arc::new(PolicyStore::new()),
            rosters: Arc::new(RosterStore::new()),
        },
        RefuseAll,
    )
    .unwrap();
    assert!(node.wait_attached(Duration::from_secs(20)).await.is_some());
    assert!(node.is_attached());
    assert_eq!(node.last_relay_error(), None);
    node.shutdown().await;
}
