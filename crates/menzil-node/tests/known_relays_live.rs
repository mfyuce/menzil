//! The node's memory of its relay's certificate over a real relay (design note
//! `relay-key-and-invites-design.md` A3, slice A1): a stale configured key falls back from IK to
//! XX and returns to IK on the stored key; a relay that presents a lower serial under the same
//! NodeId is refused `RelayRollback` by a node that remembers the higher one, and accepted by a
//! node that does not (so the memory is what protects).
//!
//! One `#[tokio::test]`: `SSL_CERT_FILE` is process-global (see `live_session.rs`).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use common::{Identity, TestRelay, TestTrust, identity, session_config, trust_test_certificate};
use menzil_node::{KnownRelays, NodeError, RosterStore, Session};
use menzil_proto::{Limits, NodeCert, NodeCertBody, PROTOCOL_VERSION, X25519PublicKey};
use menzil_relay::{Listener, Relay, RelayIdentity, server_config};
use rustls::pki_types::PrivateKeyDer;

/// A relay for `id` presenting `serial`.
async fn relay_at_serial(trust: &TestTrust, id: Identity, serial: u32) -> TestRelay {
    let body = NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id: id.node_id,
        x25519_pub: id.x25519_public,
        serial,
        not_before: 0,
        not_after: 4_000_000_000,
    };
    let node_cert = NodeCert::sign(&id.signing, &body).unwrap();
    let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
    let tls = server_config(trust.chain.clone(), key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls, "/_menzil/v1")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = Relay::new(
        RelayIdentity {
            node_cert,
            x25519_private: id.x25519_private,
        },
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: 1_048_576,
        },
    );
    let serving = relay.clone();
    tokio::spawn(async move { serving.serve(&listener).await });
    TestRelay { addr, id, relay }
}

fn copy_of(id: &Identity) -> Identity {
    Identity {
        signing: id.signing.clone(),
        node_id: id.node_id,
        x25519_private: id.x25519_private,
        x25519_public: id.x25519_public,
    }
}

async fn connect(config: &menzil_node::SessionConfig) -> Result<Session, NodeError> {
    Session::connect(config, &HashMap::new(), Arc::new(RosterStore::new())).await
}

#[tokio::test]
async fn the_node_remembers_its_relay_and_falls_back_from_a_stale_key() {
    let trust = trust_test_certificate();
    let relay_id = identity();
    let new_relay = relay_at_serial(&trust, copy_of(&relay_id), 2).await;
    let old_relay = relay_at_serial(&trust, copy_of(&relay_id), 1).await;
    let node = identity();
    let network = menzil_proto::NetworkId::from([9; 32]);

    // A node whose configured key is stale: IK fails, the next attempt is XX and attaches, and
    // from then on the node dials IK with the key it remembers, ignoring the configured one.
    let stale = X25519PublicKey::from([0x42; 32]);
    let known = Arc::new(KnownRelays::in_memory());
    let mut config = session_config(&new_relay, &node, network);
    config.networks = vec![];
    config.known_relays = known.clone();
    config.dial.connection_info.relay_x25519 = Some(stale);
    let first = connect(&config).await;
    assert!(first.is_err(), "IK with a stale key fails");
    assert_eq!(
        known.dial_key(&relay_id.node_id, Some(stale)),
        None,
        "the next attempt is XX"
    );
    let mut second = connect(&config).await.expect("XX attaches");
    second.close().await;
    assert_eq!(known.stored(&relay_id.node_id).unwrap().0, 2);
    assert_eq!(
        known.dial_key(&relay_id.node_id, Some(stale)),
        Some(relay_id.x25519_public),
        "back to IK with the stored key, over the configured one"
    );
    let mut third = connect(&config)
        .await
        .expect("IK on the stored key attaches");
    third.close().await;

    // The same relay NodeId on another address, presenting serial 1 (an old backup, or a stolen
    // older key): refused by the node that remembers serial 2 ...
    let mut rolled_back = session_config(&old_relay, &node, network);
    rolled_back.networks = vec![];
    rolled_back.known_relays = known.clone();
    match connect(&rolled_back).await {
        Err(NodeError::RelayRollback {
            stored: 2,
            presented: 1,
        }) => {}
        other => panic!(
            "expected RelayRollback, got {:?}",
            other.map(|_| "a session")
        ),
    }
    // ... and accepted by a node with no memory, which shows the memory is what protects.
    rolled_back.known_relays = Arc::new(KnownRelays::in_memory());
    let mut naive = connect(&rolled_back).await.expect("no memory, no refusal");
    naive.close().await;
}
