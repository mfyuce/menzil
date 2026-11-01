//! A node with two networks on a relay serving three: WELCOME lists only the two the node
//! claimed and passed (MT1, isolation rule I1), and everything that depended on WELCOME's
//! `rosters` still works. The node that holds a newer Roster of one network pushes it and the
//! relay adopts it; the other networks are untouched; two nodes of the networks forward to each
//! other. A first contact (no relay static key known, Noise `Xx`) gets an empty list, pushes its
//! Roster all the same and attaches.
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
use menzil_node::{Epoch, OutboundSend, RosterStore, Session, SessionEvent, run_session};
use menzil_proto::{NetworkId, NodeId, PROTOCOL_VERSION, Record, Roster, RosterBody, RosterMember};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(30);

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

fn send_to(dst: NodeId, payload: Vec<u8>) -> OutboundSend {
    let (outcome, _rx) = oneshot::channel();
    OutboundSend {
        dst,
        e2e_proto: 0x01,
        flags: 0x00,
        payload,
        epoch: Epoch::first(),
        outcome,
        permit: None,
    }
}

async fn relay_seq(relay: &common::TestRelay, network: &NetworkId) -> Option<u64> {
    relay.relay.rosters().seqs().get(network).copied()
}

async fn until_relay_seq(relay: &common::TestRelay, network: &NetworkId, seq: u64) {
    let reached = timeout(PATIENCE, async {
        while relay_seq(relay, network).await != Some(seq) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "the relay never held seq {seq}, it holds {:?}",
        relay_seq(relay, network).await
    );
}

#[tokio::test]
async fn a_node_of_two_networks_on_a_relay_of_three_attaches_catches_up_and_forwards() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1_048_576).await;
    let (a, b, outsider) = (identity(), identity(), identity());
    let owners: Vec<SigningKey> = (0..3)
        .map(|_| SigningKey::generate(&mut rand::rng()))
        .collect();
    let (net_x, x1) = roster(&owners[0], 1, &[a.node_id, b.node_id]);
    let (net_y, y1) = roster(&owners[1], 1, &[a.node_id, b.node_id]);
    let (net_z, z1) = roster(&owners[2], 1, &[outsider.node_id]);
    for held in [&x1, &y1, &z1] {
        relay.relay.rosters().set(held).unwrap();
    }
    // The node holds a newer Roster of X than the relay does.
    let (_, x2) = roster(&owners[0], 2, &[a.node_id, b.node_id]);
    let env = HashMap::new();

    let mut config = session_config(&relay, &a, net_x);
    config.networks = vec![net_x, net_y];

    // Noise Ik (the relay's static key is known): WELCOME lists X and Y, not Z.
    let held = Arc::new(RosterStore::new());
    held.set(&x1).unwrap();
    held.set(&y1).unwrap();
    let mut session = Session::connect(&config, &env, held).await.unwrap();
    let listed: HashMap<NetworkId, u64> = session.welcome().rosters.clone();
    assert_eq!(listed, HashMap::from([(net_x, 1), (net_y, 1)]));
    session.close().await;

    // Noise Xx (first contact): nothing is listed, and the node still attaches.
    let mut first_contact = config.clone();
    first_contact.dial.connection_info.relay_x25519 = None;
    let held = Arc::new(RosterStore::new());
    held.set(&x1).unwrap();
    held.set(&y1).unwrap();
    let mut session = Session::connect(&first_contact, &env, held).await.unwrap();
    assert!(
        session.welcome().rosters.is_empty(),
        "got {:?}",
        session.welcome().rosters
    );
    assert!(
        timeout(Duration::from_secs(2), session.recv())
            .await
            .is_err(),
        "an Xx first contact is not refused"
    );
    session.close().await;
    assert_eq!(relay_seq(&relay, &net_x).await, Some(1));

    // Catch up and forwarding, through the real session loop, node A holding X at seq 2.
    let held_a = Arc::new(RosterStore::new());
    held_a.set(&x2).unwrap();
    held_a.set(&y1).unwrap();
    let (a_events_tx, mut a_events) = mpsc::channel(64);
    let (a_outbound, a_outbound_rx) = mpsc::channel(64);
    let a_task = tokio::spawn(run_session(
        config.clone(),
        HashMap::new(),
        a_events_tx,
        a_outbound_rx,
        held_a,
    ));
    let held_b = Arc::new(RosterStore::new());
    held_b.set(&x1).unwrap();
    held_b.set(&y1).unwrap();
    let mut config_b = session_config(&relay, &b, net_x);
    config_b.networks = vec![net_x, net_y];
    let (b_events_tx, mut b_events) = mpsc::channel(64);
    let (b_outbound, b_outbound_rx) = mpsc::channel(64);
    let b_task = tokio::spawn(run_session(
        config_b,
        HashMap::new(),
        b_events_tx,
        b_outbound_rx,
        held_b,
    ));

    until_relay_seq(&relay, &net_x, 2).await;
    assert_eq!(relay_seq(&relay, &net_y).await, Some(1));
    assert_eq!(relay_seq(&relay, &net_z).await, Some(1));

    // Both ways, retried until both ends are attached (a send before that is refused).
    for (from, to, to_events, from_id, payload) in [
        (
            &a_outbound,
            b.node_id,
            &mut b_events,
            a.node_id,
            b"a to b".to_vec(),
        ),
        (
            &b_outbound,
            a.node_id,
            &mut a_events,
            b.node_id,
            b"b to a".to_vec(),
        ),
    ] {
        let arrived = timeout(PATIENCE, async {
            loop {
                from.send(send_to(to, payload.clone())).await.unwrap();
                if let Ok(Some(SessionEvent::Record { record, .. })) =
                    timeout(Duration::from_millis(200), to_events.recv()).await
                    && let Record::Recv {
                        src, payload: got, ..
                    } = *record
                    && src == from_id
                    && got == payload
                {
                    return;
                }
            }
        })
        .await;
        assert!(arrived.is_ok(), "no payload arrived");
    }
    a_task.abort();
    b_task.abort();
}
