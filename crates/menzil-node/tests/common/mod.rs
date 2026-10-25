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

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::watch;

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

/// What a [`ControlledProxy`] does with the bytes a node sends.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// Forward them as fast as they come.
    Flowing,
    /// Read nothing, so the node's writes block once the kernel's small buffers fill.
    Paused,
}

/// A TCP proxy between a node and the relay whose node-to-relay direction can be paused (the
/// other direction is never touched). The receive buffer is set tiny on the listener, which the
/// accepted sockets inherit, and the carrier sets `TCP_NOTSENT_LOWAT` to 16 KiB, so a paused
/// proxy blocks the node's writes after about a hundred kilobytes whatever the machine's socket
/// buffers are (the same arrangement as `live_session.rs`'s own proxy, which also throttles).
pub struct ControlledProxy {
    pub port: u16,
    pub wire: watch::Sender<Wire>,
}

pub async fn controlled_proxy(relay: SocketAddr) -> ControlledProxy {
    let socket = TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4 * 1024).unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let listener = socket.listen(16).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (wire, wire_rx) = watch::channel(Wire::Flowing);
    tokio::spawn(async move {
        while let Ok((down, _)) = listener.accept().await {
            let up = TcpStream::connect(relay).await.unwrap();
            let (mut down_read, mut down_write) = down.into_split();
            let (mut up_read, mut up_write) = up.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut up_read, &mut down_write).await;
            });
            let mut wire_rx = wire_rx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    if *wire_rx.borrow() == Wire::Paused {
                        if wire_rx.changed().await.is_err() {
                            return;
                        }
                        continue;
                    }
                    let n = match down_read.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if up_write.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    ControlledProxy { port, wire }
}

// ---- served targets and re issued documents (the L4k revocation tests) -----------------

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use menzil_proto::{NodeOrWildcard, Principal, PrincipalTarget, ServiceId};
use menzil_stream::Stream;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

pub fn service(s: &str) -> ServiceId {
    s.parse().unwrap()
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `from` may use `services` on `to`, until `expires`.
pub fn grant(
    network_id: NetworkId,
    from: NodeId,
    to: NodeId,
    services: &[&str],
    expires: Option<u64>,
) -> Grant {
    Grant {
        from: Principal {
            network_id,
            target: PrincipalTarget::Node(from),
        },
        to_node: NodeOrWildcard::Node(to),
        services: services.iter().map(|s| service(s)).collect(),
        expires,
    }
}

/// `policy` and `roster` re issued as `seq` (fresh dates), with `edit` applied to the bodies.
pub fn reissue(
    owner: &SigningKey,
    roster: &Roster,
    policy: &Policy,
    seq: u64,
    edit_roster: impl FnOnce(&mut RosterBody),
    edit_policy: impl FnOnce(&mut PolicyBody),
) -> (Roster, Policy) {
    let now = unix_now();
    let mut roster = roster.decode().unwrap();
    roster.seq = seq;
    roster.issued = now - 100;
    roster.expires = now + 10 * 86_400;
    edit_roster(&mut roster);
    let mut policy = policy.decode().unwrap();
    policy.seq = seq;
    policy.issued = now - 100;
    policy.expires = now + 10 * 86_400;
    edit_policy(&mut policy);
    (
        Roster::sign(owner, &roster).unwrap(),
        Policy::sign(owner, &policy).unwrap(),
    )
}

/// How a connection to an echo server ended, as the server saw it.
pub type Ended = Result<(), io::ErrorKind>;

/// Echoes every byte until the peer's end of file. Each connection reports how it ended.
pub async fn echo_server(listener: TcpListener, ended: mpsc::UnboundedSender<Ended>) {
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let ended = ended.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let outcome = loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        if let Err(e) = socket.write_all(&buf[..n]).await {
                            break Err(e.kind());
                        }
                    }
                    Err(e) => break Err(e.kind()),
                }
            };
            let _ = socket.shutdown().await;
            let _ = ended.send(outcome);
        });
    }
}

pub async fn echo_round_trip(stream: &mut Stream, data: &[u8]) {
    let mut back = vec![0u8; data.len()];
    let (mut reader, mut writer) = stream.split();
    let (_, read) = tokio::join!(
        async {
            writer.write_all(data).await.unwrap();
            writer.flush().await.unwrap();
        },
        async { reader.read_exact(&mut back).await },
    );
    read.unwrap();
    assert_eq!(back, data);
}
