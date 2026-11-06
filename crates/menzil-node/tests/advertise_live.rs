//! A node advertises its configured shares to a real relay (protocol.md 4.4; expose design slice
//! S-E1): after ATTACH, again after a reconnect (the relay's claims end with the session), when
//! the owner changes the set (an empty set too), and once more when a newer Roster that the node
//! pushes is what a rejected name was waiting for. The relay's ADVERTISE_ACK lands in the node's
//! [`ShareBook`] and is forgotten when the attachment ends.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global (see that file's own doc comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{PATIENCE, identity, session_config, start_relay, trust_test_certificate, unix_now};
use ed25519_dalek::SigningKey;
use menzil_node::{
    Node, NodeConfig, PolicyStore, RefuseAll, RosterStore, Session, SessionEvent, ShareSnapshot,
};
use menzil_proto::{
    Label, NetworkId, NodeId, PROTOCOL_VERSION, Roster, RosterBody, RosterMember, Share, ShareMode,
};
use tokio::time::timeout;

fn roster(owner: &SigningKey, seq: u64, node: NodeId, labels: &[&str]) -> (NetworkId, Roster) {
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq,
        // A relay adopts a Roster over DOC by the acceptance predicate (protocol.md 2.3): fresh
        // and valid for at most 14 days. (The seeded first one is not judged that way.)
        issued: unix_now() - 60,
        expires: unix_now() + 7 * 86_400,
        members: vec![RosterMember {
            node_id: node,
            min_serial: 1,
        }],
        revoked: vec![],
        stewards: vec![],
        labels: labels
            .iter()
            .map(|name| Label {
                name: name.to_string(),
                node_id: node,
            })
            .collect(),
    };
    (network_id, Roster::sign(owner, &body).unwrap())
}

fn share(name: &str, mode: ShareMode, service: &str, alpn: &[&str]) -> Share {
    Share {
        name: name.to_string(),
        mode,
        service: service.parse().unwrap(),
        alpn: alpn.iter().map(|a| a.to_string()).collect(),
    }
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    timeout(PATIENCE, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("gave up waiting for {what}"));
}

fn names_of(shares: &[Share]) -> Vec<String> {
    let mut names: Vec<String> = shares.iter().map(|s| s.name.clone()).collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_node_advertises_after_every_attach_and_when_its_shares_change() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let node = identity();
    let owner = SigningKey::generate(&mut rand::rng());
    // The owner granted this node `app` and `web`, not `ghost` (yet).
    let (network_id, roster1) = roster(&owner, 1, node.node_id, &["app", "web"]);
    relay.relay.rosters().set(&roster1).unwrap();
    let own = Arc::new(RosterStore::new());
    own.set(&roster1).unwrap();

    let session_config = session_config(&relay, &node, network_id);
    let mut started = Node::start(
        NodeConfig {
            session: session_config.clone(),
            env: HashMap::new(),
            policies: Arc::new(PolicyStore::new()),
            rosters: own.clone(),
        },
        RefuseAll,
    )
    .unwrap();
    let book = started.shares().clone();
    // What the book held at the moment each attachment ended (the event is delivered after the
    // session cleared it, and before the next attachment begins).
    let at_detach: Arc<Mutex<Vec<ShareSnapshot>>> = Arc::default();
    let mut events = started.take_events().unwrap();
    tokio::spawn({
        let (book, at_detach) = (book.clone(), at_detach.clone());
        async move {
            while let Some(event) = events.recv().await {
                if matches!(event, SessionEvent::Detached { .. }) {
                    at_detach.lock().unwrap().push(book.snapshot());
                }
            }
        }
    });
    let app = share("app", ShareMode::Blind, "tls:app", &["h2"]);
    let web = share("web", ShareMode::Terminated, "http:web", &[]);
    let ghost = share("ghost", ShareMode::Blind, "tls:ghost", &[]);
    book.set_shares(vec![app.clone(), web.clone(), ghost.clone()])
        .unwrap();

    // 1. The first attach: the relay accepts what the Roster grants and says why not the rest.
    until("the first ADVERTISE_ACK", || book.snapshot().acked).await;
    let snapshot = book.snapshot();
    assert_eq!(names_of(&snapshot.accepted), ["app", "web"], "{snapshot:?}");
    assert_eq!(snapshot.rejected.len(), 1, "{snapshot:?}");
    assert_eq!(snapshot.rejected[0].name, "ghost");
    assert_eq!(snapshot.rejected[0].reason, "label_unclaimed");
    let mut full = snapshot.names.clone();
    full.sort();
    assert_eq!(full, ["app", "web"], "the full names of the default tenant");
    assert!(book.accepted_service(&app.service));
    assert!(!book.accepted_service(&ghost.service));
    // The relay holds the claims: the same shares, by what it keeps for the node.
    assert_eq!(
        names_of(&relay.relay.labels().shares_for(&node.node_id)),
        ["app", "web"]
    );
    // What the node sent is what the relay kept (ALPN included).
    assert!(
        relay
            .relay
            .labels()
            .shares_for(&node.node_id)
            .contains(&app)
    );

    // 2. A newer Roster that grants `ghost`, which the node holds and pushes: the rejected name is
    // asked for again and accepted.
    let (_, roster2) = roster(&owner, 2, node.node_id, &["app", "web", "ghost"]);
    own.set(&roster2).unwrap();
    until("ghost to be accepted after the Roster push", || {
        book.accepted_service(&ghost.service)
    })
    .await;
    assert_eq!(
        names_of(&relay.relay.labels().shares_for(&node.node_id)),
        ["app", "ghost", "web"]
    );
    assert!(book.snapshot().rejected.is_empty());

    // 3. A reconnect: the relay's claims end with the session, and so does the node's record of
    // them; the new attachment advertises again.
    let epoch1 = started
        .wait_attached(Duration::from_secs(5))
        .await
        .expect("attached");
    let usurper = Session::connect(&session_config, &HashMap::new(), own.clone())
        .await
        .unwrap();
    drop(usurper);
    // Only once the node is attached under a later epoch is the book free of the old ACK: the
    // old attachment's end clears it before the new one begins.
    timeout(PATIENCE, async {
        loop {
            match started.wait_attached(Duration::from_millis(200)).await {
                Some(epoch) if epoch > epoch1 => break,
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("the node must attach again");
    until("the end of the first attachment to be seen", || {
        !at_detach.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(
        *at_detach.lock().unwrap(),
        vec![ShareSnapshot::default()],
        "the ended attachment's claims and answer are forgotten with it"
    );
    until("the ACK of the new attachment", || book.snapshot().acked).await;
    assert_eq!(
        names_of(&book.snapshot().accepted),
        ["app", "ghost", "web"],
        "advertised again after the reconnect"
    );
    assert_eq!(
        names_of(&relay.relay.labels().shares_for(&node.node_id)),
        ["app", "ghost", "web"],
        "and the relay holds them again"
    );

    // 4. The owner changes the set while attached: the relay's claims follow, and an empty set
    // drops them all (the relay keeps the last complete set it was given).
    book.set_shares(vec![app.clone()]).unwrap();
    until("the relay to hold only app", || {
        names_of(&relay.relay.labels().shares_for(&node.node_id)) == ["app"]
    })
    .await;
    until("the ACK of the smaller set", || {
        names_of(&book.snapshot().accepted) == ["app"]
    })
    .await;
    book.set_shares(vec![]).unwrap();
    until("the relay to hold nothing", || {
        relay.relay.labels().shares_for(&node.node_id).is_empty()
    })
    .await;
    until("the ACK of the empty set", || {
        book.snapshot().accepted.is_empty() && book.snapshot().sent.is_empty()
    })
    .await;

    started.shutdown().await;
}
