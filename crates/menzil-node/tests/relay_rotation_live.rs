//! A relay rotates its static key over a real relay (design note
//! `relay-key-and-invites-design.md` A8, slice A3; threat model item 14): the previous key
//! answers IK for its window and hands out `relay_next`, the node stores the higher serial and
//! dials the new key from then on (also after a restart from the same file), a relay with the
//! old identity is refused `RelayRollback` by a node that remembers serial 2 and accepted by one
//! that does not, a retired previous key no longer answers and a node that still has the old key
//! falls back to XX.
//!
//! One `#[tokio::test]`: `SSL_CERT_FILE` is process-global (see `live_session.rs`).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use common::{Identity, TestRelay, TestTrust, identity, session_config, trust_test_certificate};
use menzil_node::{KnownRelays, NodeError, RelayFile, RosterStore, Session};
use menzil_proto::{Limits, NetworkId, NodeCert, NodeCertBody, PROTOCOL_VERSION, X25519PublicKey};
use menzil_relay::{Listener, PreviousKey, Relay, RelayIdentity, server_config};
use rustls::pki_types::PrivateKeyDer;

/// The known-relays file of one node home, shared by the "restarts" of that node.
#[derive(Debug, Clone, Default)]
struct MemFile(Arc<Mutex<Option<Vec<u8>>>>);

impl RelayFile for MemFile {
    fn lock(&self) -> io::Result<Box<dyn Send>> {
        Ok(Box::new(()))
    }
    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().clone())
    }
    fn write(&self, bytes: &[u8]) -> io::Result<()> {
        *self.0.lock().unwrap() = Some(bytes.to_vec());
        Ok(())
    }
    fn set_aside(&self, _unix: u64) -> io::Result<()> {
        *self.0.lock().unwrap() = None;
        Ok(())
    }
}

/// One static key of the relay: the keypair and its certificate at `serial`.
struct Key {
    private: [u8; 32],
    public: X25519PublicKey,
    cert: NodeCert,
}

fn key_at(base: &Identity, serial: u32) -> Key {
    let fresh = identity();
    let body = NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id: base.node_id,
        x25519_pub: fresh.x25519_public,
        serial,
        not_before: 0,
        not_after: 4_000_000_000,
    };
    Key {
        private: fresh.x25519_private,
        public: fresh.x25519_public,
        cert: NodeCert::sign(&base.signing, &body).unwrap(),
    }
}

fn copy_of(id: &Identity, key: &Key) -> Identity {
    Identity {
        signing: id.signing.clone(),
        node_id: id.node_id,
        x25519_private: key.private,
        x25519_public: key.public,
    }
}

/// A relay for `id` answering `current`, and `previous` until `retire_at`.
async fn relay_on(
    trust: &TestTrust,
    id: &Identity,
    current: &Key,
    previous: Option<(&Key, u64)>,
) -> TestRelay {
    let tls = server_config(
        trust.chain.clone(),
        PrivateKeyDer::Pkcs8(trust.key_der.clone().into()),
    )
    .unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls, "/_menzil/v1")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let relay = Relay::new(
        RelayIdentity {
            node_cert: current.cert.clone(),
            x25519_private: current.private,
        },
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: 1_048_576,
        },
    );
    if let Some((old, retire_at)) = previous {
        relay.set_previous(Some(PreviousKey {
            node_cert: old.cert.clone(),
            x25519_private: old.private,
            retire_at,
        }));
    }
    let serving = relay.clone();
    tokio::spawn(async move { serving.serve(&listener).await });
    TestRelay {
        addr,
        id: copy_of(id, current),
        relay,
    }
}

async fn connect(config: &menzil_node::SessionConfig) -> Result<Session, NodeError> {
    Session::connect(config, &HashMap::new(), Arc::new(RosterStore::new())).await
}

/// A node config toward `relay` with `known` as its memory and `config_key` as `relay =` key.
fn node_config(
    relay: &TestRelay,
    node: &Identity,
    known: KnownRelays,
    config_key: X25519PublicKey,
) -> menzil_node::SessionConfig {
    let mut config = session_config(relay, node, NetworkId::from([9; 32]));
    config.networks = vec![];
    config.known_relays = Arc::new(known);
    config.dial.connection_info.relay_x25519 = Some(config_key);
    config
}

#[tokio::test]
async fn a_rotated_relay_key_is_followed_by_the_node_and_the_old_one_is_refused() {
    let trust = trust_test_certificate();
    let base = identity();
    let k1 = key_at(&base, 1);
    let k2 = key_at(&base, 2);
    let node = identity();
    let file = MemFile::default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // The relay on K1: the node attaches by IK on the configured key and remembers serial 1.
    let before = relay_on(&trust, &base, &k1, None).await;
    let config = node_config(
        &before,
        &node,
        KnownRelays::open(Box::new(file.clone()), now),
        k1.public,
    );
    connect(&config).await.expect("IK on K1").close().await;
    assert_eq!(config.known_relays.stored(&base.node_id).unwrap().0, 1);

    // Rotation and restart: K2 at serial 2 with K1 as the previous key (window open). The node
    // still dials IK on K1, which the previous key answers; `relay_next` makes it store serial 2.
    let during = relay_on(&trust, &base, &k2, Some((&k1, now + 3600))).await;
    let config = node_config(
        &during,
        &node,
        KnownRelays::open(Box::new(file.clone()), now),
        k1.public,
    );
    assert_eq!(
        config.known_relays.dial_key(&base.node_id, Some(k1.public)),
        Some(k1.public)
    );
    connect(&config)
        .await
        .expect("IK on the previous key, first try")
        .close()
        .await;
    assert_eq!(
        config.known_relays.stored(&base.node_id),
        Some((2, k2.public)),
        "relay_next became the record"
    );

    // The node restarted from the same file dials IK on K2 (the configured K1 is ignored), and
    // attaches on the first try: no fallback was needed.
    let config = node_config(
        &during,
        &node,
        KnownRelays::open(Box::new(file.clone()), now),
        k1.public,
    );
    assert_eq!(
        config.known_relays.dial_key(&base.node_id, Some(k1.public)),
        Some(k2.public)
    );
    connect(&config).await.expect("IK on K2").close().await;

    // A relay process with the old K1 identity at serial 1: refused by the node that remembers
    // serial 2 (its IK on K2 fails first, the next attempt is XX and meets the serial rule) ...
    let old = relay_on(&trust, &base, &k1, None).await;
    let config = node_config(
        &old,
        &node,
        KnownRelays::open(Box::new(file.clone()), now),
        k1.public,
    );
    let mut refused = None;
    for _ in 0..2 {
        match connect(&config).await {
            Err(error @ NodeError::RelayRollback { .. }) => {
                refused = Some(error);
                break;
            }
            Err(_) => {}
            Ok(_) => panic!("a rolled back relay was accepted by a node that remembers serial 2"),
        }
    }
    assert!(
        matches!(
            refused,
            Some(NodeError::RelayRollback {
                stored: 2,
                presented: 1
            })
        ),
        "expected RelayRollback, got {refused:?}"
    );
    // ... and accepted by a node with no file, which shows the file is what protects.
    let naive = node_config(&old, &node, KnownRelays::in_memory(), k1.public);
    connect(&naive)
        .await
        .expect("no memory, no refusal")
        .close()
        .await;

    // Retired window: K2 with K1 retired (retire_at in the past). IK on K1 gets no answer, the
    // node falls back to XX and attaches, with and without a record of K1, and learns serial 2.
    let retired = relay_on(&trust, &base, &k2, Some((&k1, 1))).await;
    let blank = node_config(&retired, &node, KnownRelays::in_memory(), k1.public);
    assert!(
        connect(&blank).await.is_err(),
        "the retired key answers nothing"
    );
    connect(&blank).await.expect("XX attaches").close().await;
    assert_eq!(blank.known_relays.stored(&base.node_id).unwrap().0, 2);
    assert_eq!(
        blank.known_relays.dial_key(&base.node_id, Some(k1.public)),
        Some(k2.public),
        "back to IK, on the new key"
    );
    connect(&blank).await.expect("IK on K2").close().await;

    let other_home = MemFile::default();
    {
        let seeded = KnownRelays::open(Box::new(other_home.clone()), now);
        let first = relay_on(&trust, &base, &k1, None).await;
        let c = node_config(&first, &node, seeded, k1.public);
        connect(&c).await.expect("K1 at serial 1").close().await;
    }
    let remembering = node_config(
        &retired,
        &node,
        KnownRelays::open(Box::new(other_home), now),
        k1.public,
    );
    assert!(connect(&remembering).await.is_err());
    connect(&remembering)
        .await
        .expect("XX attaches with K1 on record")
        .close()
        .await;
    assert_eq!(remembering.known_relays.stored(&base.node_id).unwrap().0, 2);
}
