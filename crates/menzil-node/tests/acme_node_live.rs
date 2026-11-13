//! The node's certificates end to end over real sockets (protocol.md 6.2, expose design S-E8):
//! a real relay with a front door and a share domain, a real node whose shares are blind and one
//! of them lists `acme-tls/1`, the node's renewal supervisor fed by the relay's ADVERTISE_ACK,
//! and a fake in process CA whose TLS-ALPN-01 validation connects over TCP to the relay's own
//! front door.
//!
//! 1. The ACK carries the share domain and the accepted full names. The supervisor orders
//!    `app.share.test` (label `app` of the default tenant, composed from the ACK, not from any
//!    setting): the CA's validation goes through the front door and the relay's blind path to
//!    the node's `AcmeHandler`, which answers it; the certificate is stored under
//!    `<home>/acme/certs/app.share.test/` (key 0600, directory 0700). A share the relay did not
//!    accept (`other`, no Roster label) is never ordered.
//! 2. The owner withdraws the share: the task stops (the CA is asked nothing more) and the
//!    status is forgotten. Putting it back and the relay's next ACK start it again: with the
//!    stored certificate removed in between, a new order is made and the certificate is stored
//!    again.
//!
//! One `#[tokio::test]` because `SSL_CERT_FILE` is process-global (see `live_session.rs`). Every
//! wait is bounded.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{
    PATIENCE, echo_server, identity, node_cert, service, session_config, trust_test_certificate,
    unix_now,
};
use ed25519_dalek::SigningKey;
use menzil_acme::testing::{FakeCa, Flags};
use menzil_node::acme::{
    AcmeHandler, AcmeSetup, AcmeStatus, CertState, CertStore, ChallengeBook, spawn_renewals,
};
use menzil_node::{LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RosterStore};
use menzil_proto::{
    Label, Limits, NetworkId, NodeId, PROTOCOL_VERSION, Policy, PolicyBody, PolicyMember, Roster,
    RosterBody, RosterMember, Share, ShareMode,
};
use menzil_relay::{
    AcceptConfig, AdmissionLimits, FrontDoorConfig, Listener, PrincipalConfig, Relay,
    RelayIdentity, server_config,
};
use rustls::pki_types::PrivateKeyDer;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// The share domain.
const H: &str = "share.test";
const NAME: &str = "myapp.share.test";

fn roster(owner: &SigningKey, node: NodeId, other: NodeId, labels: &[&str]) -> (NetworkId, Roster) {
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: unix_now() - 60,
        expires: unix_now() + 7 * 86_400,
        members: [node, other]
            .iter()
            .map(|&node_id| RosterMember {
                node_id,
                min_serial: 1,
            })
            .collect(),
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

fn policy_for(
    owner: &SigningKey,
    network_id: NetworkId,
    node: &common::Identity,
    other: &common::Identity,
) -> Policy {
    let body = PolicyBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: unix_now() - 60,
        expires: unix_now() + 7 * 86_400,
        members: [node, other]
            .iter()
            .map(|id| PolicyMember {
                node_id: id.node_id,
                name: "node".to_string(),
                roles: vec![],
            })
            .collect(),
        certs: vec![node_cert(node), node_cert(other)],
        grants: vec![],
        egress: vec![],
        accept: vec![],
    };
    Policy::sign(owner, &body).unwrap()
}

fn blind(name: &str, alpn: &[&str]) -> Share {
    Share {
        name: name.to_string(),
        mode: ShareMode::Blind,
        service: format!("tls:{name}").parse().unwrap(),
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

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("menzil-acme-node-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn orders(ca: &Arc<FakeCa>) -> usize {
    ca.state()
        .log
        .iter()
        .filter(|r| *r == "Post /order")
        .count()
}

#[tokio::test]
async fn the_node_orders_for_the_name_of_the_relays_ack_and_stops_and_starts_with_its_shares() {
    let trust = trust_test_certificate();
    let scratch = Scratch::new();

    // --- the relay: a front door under `share.test` ----------------------------------------
    let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
    let tls_config = server_config(trust.chain.clone(), key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls_config, "/_menzil/v1")
        .await
        .unwrap();
    let front_addr = listener.local_addr().unwrap();
    let relay_id = identity();
    let relay = Relay::new(
        RelayIdentity {
            node_cert: node_cert(&relay_id),
            x25519_private: relay_id.x25519_private,
        },
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: 256 * 1024,
        },
    )
    .with_admission_limits(AdmissionLimits {
        connections_per_ip_per_minute: 1_000_000,
        max_unattached_per_ip: 1_000_000,
        max_handshakes_per_ip: 1_000_000,
        max_handshakes_per_v6_48: 1_000_000,
        ..AdmissionLimits::default()
    })
    .with_principal_config(
        PrincipalConfig::default()
            .with_tick(Duration::from_millis(50))
            .with_handshake_timeout(Duration::from_secs(3)),
    )
    .with_front_door(
        FrontDoorConfig::new("localhost", H)
            .unwrap()
            .with_failure_delay(Duration::from_millis(50)),
    );
    let serving = relay.clone();
    tokio::spawn(async move {
        serving
            .serve_with_http(&listener, None, AcceptConfig::default())
            .await
    });
    let test_relay = common::TestRelay {
        addr: front_addr,
        id: relay_id,
        relay: relay.clone(),
    };

    // --- the documents: the node holds the label `app`, not `other` -------------------------
    let node_id = identity();
    let peer = identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let (network_id, roster1) = roster(&owner, node_id.node_id, peer.node_id, &["myapp"]);
    let policy1 = policy_for(&owner, network_id, &node_id, &peer);
    relay.rosters().set(&roster1).unwrap();
    let rosters = Arc::new(RosterStore::new());
    rosters.set(&roster1).unwrap();
    let policies = Arc::new(PolicyStore::new());
    policies.set(&policy1).unwrap();

    // --- the node: the handler that answers validations, around a local echo target ---------
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let (ended, _keep) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(echo, ended));
    let challenges = ChallengeBook::new();
    let services = LocalServices::new()
        .serve(
            service("tls:myapp"),
            LocalTarget::new("127.0.0.1", echo_port),
        )
        .unwrap()
        .serve(
            service("tls:other"),
            LocalTarget::new("127.0.0.1", echo_port),
        )
        .unwrap();
    let node = Node::start(
        NodeConfig {
            session: session_config(&test_relay, &node_id, network_id),
            env: HashMap::new(),
            policies,
            rosters,
        },
        AcmeHandler::new(services, challenges.clone()),
    )
    .unwrap();
    node.wait_attached(Duration::from_secs(20))
        .await
        .expect("the node must attach through the front door");
    until("the relay to hold the node", || {
        relay.attached_node(&node_id.node_id).is_some()
    })
    .await;

    // --- the supervisor, with a CA that validates through the front door --------------------
    let ca = FakeCa::new(
        &challenges,
        Flags {
            validate_via: Some(front_addr),
            ..Flags::default()
        },
    );
    let store = CertStore::new(&scratch.0);
    let status = AcmeStatus::new();
    let book = node.shares().clone();
    let supervisor = spawn_renewals(
        AcmeSetup {
            transport: ca.clone(),
            directory_url: format!("{}/dir", menzil_acme::testing::CA),
            contact: Some("mailto:ops@example.org".to_string()),
            account_key_path: CertStore::account_key_path(&scratch.0),
            store: store.clone(),
            timing: menzil_acme::testing::fast(),
        },
        book.clone(),
        challenges.clone(),
        status.clone(),
        || None,
    );

    // --- 1. the ACK names the domain and the name; the order, the validation, the files -----
    let myapp = blind("myapp", &["acme-tls/1"]);
    let other = blind("other", &["acme-tls/1"]);
    book.set_shares(vec![myapp.clone(), other.clone()]).unwrap();
    until("the certificate", || store.validity(NAME).is_some()).await;
    assert_eq!(book.share_domain().as_deref(), Some(H), "the ACK's domain");
    assert_eq!(book.names(), vec!["myapp".to_string()]);
    assert!(book.accepted_service(&myapp.service));
    assert!(
        !book.accepted_service(&other.service),
        "the relay holds no label `other` for this node"
    );
    {
        let state = ca.state();
        assert_eq!(state.domain, NAME, "the CA was asked for exactly this name");
        assert_eq!(
            state.validated,
            Some(true),
            "the node answered the CA's validation, which came through the relay's front door"
        );
        assert!(state.finalized);
    }
    assert_eq!(orders(&ca), 1, "only `myapp` was ordered, `other` never");
    let (chain, key) = store.paths(NAME).unwrap();
    assert!(chain.exists() && key.exists());
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key), 0o600);
        assert_eq!(mode(chain.parent().unwrap()), 0o700);
        assert_eq!(
            mode(&CertStore::account_key_path(&scratch.0)),
            0o600,
            "the account key was made on first use, private"
        );
    }
    assert!(matches!(
        status.state(&store, NAME, unix_now()),
        CertState::Valid { not_after } if not_after > unix_now()
    ));
    assert_eq!(
        status.state(&store, "other.share.test", unix_now()),
        CertState::None
    );

    // --- 2. withdrawn: the task stops; put back: it starts again ---------------------------
    book.set_shares(vec![other.clone()]).unwrap();
    until("the withdrawal to reach the relay", || {
        !book.accepted_service(&myapp.service)
    })
    .await;
    std::fs::remove_dir_all(chain.parent().unwrap()).unwrap();
    let before = orders(&ca);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(orders(&ca), before, "a withdrawn share is not ordered for");
    assert!(store.validity(NAME).is_none());
    book.set_shares(vec![myapp.clone(), other.clone()]).unwrap();
    until("the certificate again", || store.validity(NAME).is_some()).await;
    assert!(
        orders(&ca) > before,
        "after the next ACK the node orders again"
    );

    supervisor.abort();
    node.close_gracefully(Duration::from_secs(2)).await;
}
