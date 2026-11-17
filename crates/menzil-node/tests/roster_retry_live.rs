//! A node whose Roster push the relay refused as `over_quota` sends its Rosters again after
//! `ROSTER_RETRY_AFTER` (review R-3), through the `roster_retry` arm of the attached loop.
//!
//! A real relay whose tenant has a burst of one Roster adoption and a refill of one a second:
//! the first newer Roster the node pushes is adopted, the second is refused, and only the retry
//! timer (short here, through [`ShareBook::set_roster_retry_after`]) gets it there. One
//! `#[tokio::test]`: `SSL_CERT_FILE` is process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use common::{identity, session_config, start_relay, trust_test_certificate, unix_now};
use ed25519_dalek::SigningKey;
use menzil_node::{
    Observers, RelayNotes, RosterStore, SessionEvent, ShareBook, run_session_observed,
};
use menzil_proto::{NetworkId, NodeId, PROTOCOL_VERSION, Roster, RosterBody, RosterMember};
use menzil_relay::{Class, Slug, TenantBook, TenantSpec};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

fn roster(owner: &SigningKey, node: NodeId, seq: u64) -> (NetworkId, Roster) {
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq,
        issued: unix_now() - 60,
        expires: unix_now() + 7 * 86_400,
        members: vec![RosterMember {
            node_id: node,
            min_serial: 1,
        }],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    (network_id, Roster::sign(owner, &body).unwrap())
}

#[tokio::test]
async fn a_roster_push_refused_as_over_quota_is_sent_again_after_the_retry_delay() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let node = identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let (network_id, roster1) = roster(&owner, node.node_id, 1);
    relay.relay.rosters().set(&roster1).unwrap();
    relay.relay.set_tenants(TenantBook::build(
        vec![TenantSpec {
            slug: Slug::parse("ali").unwrap(),
            networks: vec![network_id],
            class: Class::Friend,
            overrides: BTreeMap::from([
                ("roster_adoption_burst".to_string(), 1),
                ("roster_adoptions_per_hour".to_string(), 3_600),
            ]),
            terminated: false,
            extra_names: Vec::new(),
            added: 1,
        }],
        vec![],
        &HashSet::new(),
        &HashSet::new(),
    ));
    let own = Arc::new(RosterStore::new());
    own.set(&roster1).unwrap();

    let book = ShareBook::new();
    book.set_roster_retry_after(Duration::from_secs(2));
    let (events_tx, mut events_rx) = mpsc::channel::<SessionEvent>(64);
    let (_outbound_tx, outbound_rx) = mpsc::channel(16);
    let (stop, stop_rx) = watch::channel(false);
    tokio::spawn(async move { while events_rx.recv().await.is_some() {} });
    tokio::spawn(run_session_observed(
        session_config(&relay, &node, network_id),
        HashMap::new(),
        events_tx,
        outbound_rx,
        own.clone(),
        stop_rx,
        Observers {
            notes: RelayNotes::new(),
            shares: book,
        },
    ));
    let until = |want: u64| {
        let relay = &relay;
        async move {
            timeout(Duration::from_secs(20), async {
                while relay.relay.rosters().seq_of(&network_id) != Some(want) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
        }
    };
    // Let the attachment settle, then push 2 (the burst's one token) ...
    tokio::time::sleep(Duration::from_millis(500)).await;
    own.set(&roster(&owner, node.node_id, 2).1).unwrap();
    until(2).await.expect("seq 2 must be adopted");
    // ... and 3 at once: refused (bucket empty), and adopted only by the retry.
    own.set(&roster(&owner, node.node_id, 3).1).unwrap();
    until(3)
        .await
        .expect("the refused Roster must be pushed again after the retry delay");
    let _ = stop.send(true);
}
