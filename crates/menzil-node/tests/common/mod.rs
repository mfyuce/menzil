//! Shared setup for the live tests in this directory that run a real relay:
//! a throwaway TLS certificate trusted through `SSL_CERT_FILE`, node and
//! relay identities, a seeded Roster and Policy, and a node's session
//! configuration. Each test binary that includes this module is its own
//! process, so the process-global `SSL_CERT_FILE` it sets is per test
//! binary (see `live_session.rs`'s doc comment for why that must happen
//! before any dial).

#![allow(dead_code)] // each test binary uses a different subset

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use menzil_carrier::{ConnectionInfo, DialConfig, ProxyOverride};
use menzil_node::{LocalIdentity, SessionConfig};
use menzil_proto::{
    Grant, Limits, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, Policy, PolicyBody,
    PolicyMember, Roster, RosterBody, RosterMember, X25519PublicKey,
};
use menzil_relay::{Listener, Relay, RelayIdentity, server_config};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub const PATIENCE: Duration = Duration::from_secs(60);

pub struct TestTrust {
    pub chain: Vec<CertificateDer<'static>>,
    pub key_der: Vec<u8>,
    pub pem_path: std::path::PathBuf,
}

pub fn trust_test_certificate() -> TestTrust {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let pem_path =
        std::env::temp_dir().join(format!("menzil-node-live-{}.pem", std::process::id()));
    std::fs::write(&pem_path, cert.pem()).unwrap();
    // SAFETY: the first thing the only test in this binary does, on a
    // current-thread runtime, before any dial (and so before any
    // blocking-pool thread) exists. See `live_session.rs`'s doc comment.
    unsafe { std::env::set_var("SSL_CERT_FILE", &pem_path) };
    TestTrust {
        chain: vec![cert.der().clone()],
        key_der: signing_key.serialize_der(),
        pem_path,
    }
}

impl Drop for TestTrust {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.pem_path);
    }
}

pub struct Identity {
    pub signing: SigningKey,
    pub node_id: NodeId,
    pub x25519_private: [u8; 32],
    pub x25519_public: X25519PublicKey,
}

pub fn identity() -> Identity {
    let signing = SigningKey::generate(&mut rand::rng());
    let node_id = NodeId::from(signing.verifying_key().to_bytes());
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    Identity {
        signing,
        node_id,
        x25519_private: <[u8; 32]>::try_from(keypair.private).unwrap(),
        x25519_public: X25519PublicKey::from(<[u8; 32]>::try_from(keypair.public).unwrap()),
    }
}

pub fn node_cert(id: &Identity) -> NodeCert {
    let body = NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id: id.node_id,
        x25519_pub: id.x25519_public,
        serial: 1,
        not_before: 0,
        not_after: 4_000_000_000,
    };
    NodeCert::sign(&id.signing, &body).unwrap()
}

pub struct TestRelay {
    pub addr: SocketAddr,
    pub id: Identity,
    pub relay: Relay,
}

pub async fn start_relay(trust: &TestTrust, credit: u32) -> TestRelay {
    let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
    let tls = server_config(trust.chain.clone(), key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls, "/_menzil/v1")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let id = identity();
    let relay = Relay::new(
        RelayIdentity {
            node_cert: node_cert(&id),
            x25519_private: id.x25519_private,
        },
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit,
        },
    );
    let serving = relay.clone();
    tokio::spawn(async move { serving.serve(&listener).await });
    TestRelay { addr, id, relay }
}

/// Seeds the relay's Roster and returns what a node needs to hold the same
/// documents: the owner's key, the network, and the signed Roster.
pub fn seed_roster(relay: &TestRelay, members: &[&Identity]) -> (SigningKey, NetworkId, Roster) {
    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: members
            .iter()
            .map(|member| RosterMember {
                node_id: member.node_id,
                min_serial: 1,
            })
            .collect(),
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    let roster = Roster::sign(&owner, &body).unwrap();
    relay.relay.rosters().set(&roster).unwrap();
    (owner, network_id, roster)
}

/// The Policy every node holds: both members, both certs, and `grants`.
pub fn policy(
    owner: &SigningKey,
    network_id: NetworkId,
    a: &Identity,
    b: &Identity,
    grants: Vec<Grant>,
) -> Policy {
    let body = PolicyBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: [a, b]
            .iter()
            .map(|p| PolicyMember {
                node_id: p.node_id,
                name: "node".to_string(),
                roles: vec![],
            })
            .collect(),
        certs: vec![node_cert(a), node_cert(b)],
        grants,
        egress: vec![],
        accept: vec![],
    };
    Policy::sign(owner, &body).unwrap()
}

pub fn session_config(relay: &TestRelay, id: &Identity, network_id: NetworkId) -> SessionConfig {
    SessionConfig {
        dial: DialConfig {
            connection_info: ConnectionInfo {
                host: "localhost".to_string(),
                port: relay.addr.port(),
                path: "/_menzil/v1".to_string(),
                relay_node_id: relay.id.node_id,
                relay_x25519: Some(relay.id.x25519_public),
            },
            proxy_override: Some(ProxyOverride::Direct),
        },
        identity: LocalIdentity {
            node_cert: node_cert(id),
            x25519_private: id.x25519_private,
        },
        networks: vec![network_id],
        caps: vec![],
        e2e_protos: vec![0x01],
    }
}
