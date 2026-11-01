//! A renewed certificate reaches the relay (cert rotation S4), over a real relay.
//!
//! `Session::connect` reads the identity cell at each connect, so the HELLO of a reconnect
//! carries the certificate the cell holds then. The relay keeps a high water mark of the serial
//! it accepted per NodeId and answers a lower one with ERROR `stale_serial`, which makes the
//! serial in a HELLO observable: after the reconnect with the renewed cell, a HELLO with the
//! old serial is refused. Without the renewal in the HELLO it would be accepted.
//!
//! The second half renews a running `Node` through `Node::renew_identity`, with the real clock.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{Identity, identity, node_cert, session_config, start_relay, trust_test_certificate};
use menzil_node::{IdentityError, Node, NodeConfig, PolicyStore, RefuseAll, RosterStore, Session};
use menzil_proto::{ErrorCode, NodeCert, NodeCertBody, PROTOCOL_VERSION, Record};
use tokio::time::timeout;

fn cert_with(id: &Identity, serial: u32, not_before: u64, not_after: u64) -> NodeCert {
    NodeCert::sign(
        &id.signing,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: id.node_id,
            x25519_pub: id.x25519_public,
            serial,
            not_before,
            not_after,
        },
    )
    .unwrap()
}

/// The first thing a relay says to a connection it turns away, if it does so within a moment.
async fn refusal(session: &mut Session) -> Option<ErrorCode> {
    match timeout(Duration::from_secs(2), session.recv()).await {
        Ok(Ok(Record::Error(body))) => Some(body.code),
        _ => None,
    }
}

#[tokio::test]
async fn a_renewed_certificate_is_presented_by_the_next_hello_and_the_running_node_switches() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1_048_576).await;
    let env = HashMap::new();
    let rosters = Arc::new(RosterStore::new());

    // ---- Session::connect reads the cell at each connect -------------------------------
    let me = identity();
    let (_owner, network, _roster) = common::seed_roster(&relay, &[&me]);
    let config = session_config(&relay, &me, network);
    let cell = config.identity.clone();
    assert_eq!(cell.serial(), 1);

    let mut first = Session::connect(&config, &env, rosters.clone())
        .await
        .unwrap();
    assert_eq!(refusal(&mut first).await, None, "serial 1 is accepted");
    first.close().await;

    // Renew: the cell now holds serial 2, and the next connect presents it.
    cell.set(cert_with(&me, 2, 0, 4_000_000_000), 1_000)
        .unwrap();
    let mut second = Session::connect(&config, &env, rosters.clone())
        .await
        .unwrap();
    assert_eq!(refusal(&mut second).await, None, "serial 2 is accepted");
    second.close().await;

    // The relay's high water mark is now 2: a node still presenting serial 1 is turned away.
    let old_config = session_config(&relay, &me, network);
    assert_eq!(old_config.identity.serial(), 1);
    let mut old = Session::connect(&old_config, &env, rosters.clone())
        .await
        .unwrap();
    assert_eq!(
        refusal(&mut old).await,
        Some(ErrorCode::StaleSerial),
        "the reconnect after the renewal presented serial 2, so the relay now refuses serial 1"
    );

    // ---- Node::renew_identity ------------------------------------------------------------
    let node_id = identity();
    let node_config = session_config(&relay, &node_id, network);
    let node_cell = node_config.identity.clone();
    let node = Node::start(
        NodeConfig {
            session: node_config,
            env: HashMap::new(),
            policies: Arc::new(PolicyStore::new()),
            rosters: Arc::new(RosterStore::new()),
        },
        RefuseAll,
    )
    .unwrap();

    // Not newer, another key, not valid now: refused, nothing changes.
    assert_eq!(
        node.renew_identity(node_cert(&node_id)),
        Err(IdentityError::NotNewer {
            current: 1,
            offered: 1
        })
    );
    let other = identity();
    assert_eq!(
        node.renew_identity(cert_with(&other, 2, 0, 4_000_000_000)),
        Err(IdentityError::OtherNode)
    );
    assert_eq!(
        node.renew_identity(cert_with(&node_id, 2, 0, 1_000_000_000)),
        Err(IdentityError::NotValidNow)
    );
    assert_eq!(node_cell.serial(), 1);

    // Valid at the real clock but not at time 0: pins that the node judges against now.
    let renewed = cert_with(&node_id, 2, 1_000_000_000, 4_000_000_000);
    node.renew_identity(renewed.clone()).unwrap();
    assert_eq!(node_cell.serial(), 2);
    assert_eq!(node_cell.get().node_cert, renewed);
    node.shutdown().await;
}
