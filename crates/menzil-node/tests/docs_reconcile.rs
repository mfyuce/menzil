//! The session initiator's comparison of seqs (TODO.md L4j S6) over a real relay: as in
//! `docs_triggers.rs` the owner issues a pair on one node while both are attached and the relay
//! hands the other node the Roster, but here the Policy fetch that follows a newer Roster waits
//! up to a day, so it cannot be what brings the Policy. The node that is behind opens a session
//! to the other (a stream request does it); the responder's handshake payload shows it is ahead
//! and the initiator fetches, without a restart and with no ordinary stream involved.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE`
//! is process-global (see that file's own doc comment).
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE`
//! is process-global (see that file's own doc comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{
    PATIENCE, identity, policy, seed_roster, session_config, start_relay, trust_test_certificate,
};
use menzil_node::{DocStore, Node, NodeConfig, PolicyStore, RefuseAll, RosterStore, SyncConfig};
use menzil_proto::trust::Bundle;
use menzil_proto::{Policy, Roster};
use tokio::time::{sleep, timeout};

/// Waits until `check` holds, up to [`PATIENCE`].
async fn until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let waited = timeout(PATIENCE, async {
        while !check().await {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "gave up waiting for {what}");
}

#[tokio::test]
async fn a_node_behind_fetches_at_the_handshake_what_its_peer_holds() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    let policy1 = policy(&owner, network_id, &a, &b, vec![]);

    let held = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy1).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster1).unwrap();
        (policies, rosters)
    };
    let (a_policies, a_rosters) = held();
    let (b_policies, b_rosters) = held();
    // The Policy fetch after a newer Roster would wait up to a day: the test is over long before.
    let no_jitter = SyncConfig {
        policy_jitter_max: Duration::from_secs(86_400),
    };
    let start = |id: &common::Identity, policies: &Arc<PolicyStore>, rosters: &Arc<RosterStore>| {
        Node::start_with_sync(
            NodeConfig {
                session: session_config(&relay, id, network_id),
                env: HashMap::new(),
                policies: policies.clone(),
                rosters: rosters.clone(),
            },
            RefuseAll,
            no_jitter,
        )
        .unwrap()
    };
    let na = start(&a, &a_policies, &a_rosters);
    let nb = start(&b, &b_policies, &b_rosters);
    na.wait_attached(PATIENCE).await.expect("A attaches");
    nb.wait_attached(PATIENCE).await.expect("B attaches");
    assert_eq!(relay.relay.rosters().seqs().get(&network_id), Some(&1));

    // The owner issues seq 2 and it is installed on A alone, as `menzil admit` would.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut roster = roster1.decode().unwrap();
    roster.seq = 2;
    roster.issued = now - 100;
    roster.expires = now + 10 * 86_400;
    let mut pol = policy1.decode().unwrap();
    pol.seq = 2;
    pol.issued = now - 100;
    pol.expires = now + 10 * 86_400;
    let bundle = Bundle {
        roster: Some(Roster::sign(&owner, &roster).unwrap()),
        policy: Some(Policy::sign(&owner, &pol).unwrap()),
        ..Bundle::default()
    };
    DocStore::new(&a_rosters, &a_policies)
        .adopt(&bundle, now)
        .unwrap();

    // A gives the relay the Roster on its live session ...
    until("the relay to hold Roster 2", || async {
        relay.relay.rosters().seqs().get(&network_id) == Some(&2)
    })
    .await;
    // ... the relay hands it to B ...
    until("B to hold Roster 2", || async {
        b_rosters.seq(&network_id) == Some(2)
    })
    .await;
    // ... B's Policy is behind its Roster, and its own fetch is a day away. It opens a session to
    // A (the stream itself is refused, A grants B nothing); the handshake tells B that A is ahead.
    assert_eq!(b_policies.seq(&network_id), Some(1));
    let opened = nb
        .open_stream(a.node_id, network_id, "tcp:none".parse().unwrap(), None)
        .await;
    assert!(opened.is_err(), "A serves nothing");
    until("B to hold Policy 2", || async {
        b_policies.seq(&network_id) == Some(2)
    })
    .await;
    assert_eq!(b_rosters.get(&network_id), a_rosters.get(&network_id));
    assert_eq!(b_policies.get(&network_id), a_policies.get(&network_id));

    na.shutdown().await;
    nb.shutdown().await;
}
