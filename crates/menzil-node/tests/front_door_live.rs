//! The blind front door of the relay's TLS port end to end over real sockets (protocol.md 6.2 to
//! 6.4, expose design slice S-E6): a real relay with a share domain, a real node serving
//! `[[share]]`s to local echo servers, and public clients that are plain TCP sockets writing a
//! real ClientHello (made by rustls) and whatever follows.
//!
//! 1. The relay's own host name still takes the TLS and WebSocket path: the node attaches
//!    through the front door (every later step depends on it).
//! 2. `app.share.test` (`tls:`), `raw.share.test` (`tcp:`, decision E5) and the ACME challenge
//!    name that listed `acme-tls/1`: the ClientHello and the bytes after it echo through the
//!    relay principal to the node's local echo server, byte for byte, and the node's handler
//!    sees `meta.sni` (lowercased) and `meta.client_ip`.
//! 3. A refused connection gets the same seven bytes whatever the cause, and not sooner than the
//!    failure delay: an unknown name, the apex, a name outside the share domain, no SNI, bytes
//!    that are not TLS, a name nobody holds, a quarantined name, a terminated share, an
//!    `acme-tls/1` hello for a share that did not list it, a node that refuses the stream, a name
//!    over its figure, a tenant over its figure, a node that is gone.
//! 4. The per name (2) and per tenant (3) figures hold, a place is given back when a connection
//!    ends, and a refusal on any path (here a principal refusal) leaves no place taken.
//! 5. The peek cap drops a connection quietly (no byte) and so does the peek deadline.
//! 6. An idle connection is ended and gives its place back.
//! 7. Port 80: a request for any name under the share domain is redirected to https (known or
//!    not, the same), a challenge for a held name is opened as `acme-http:<label>` on the node
//!    (which refuses it until it can serve it) and answered with the one fixed 404, as is a
//!    challenge for an unknown name.
//!
//! One `#[tokio::test]` because `SSL_CERT_FILE` is process-global (see `live_session.rs`). Every
//! wait is bounded, so a regression fails the test instead of hanging it.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    PATIENCE, TestRelay, TestTrust, echo_server, identity, node_cert, service, session_config,
    trust_test_certificate, unix_now,
};
use ed25519_dalek::SigningKey;
use menzil_node::{LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RosterStore};
use menzil_proto::{
    Label, Limits, NetworkId, NodeId, PROTOCOL_VERSION, Policy, PolicyBody, PolicyMember, Roster,
    RosterBody, RosterMember, Share, ShareMode,
};
use menzil_relay::{
    AcceptConfig, AdmissionLimits, FrontDoorConfig, Listener, NameState, PrincipalConfig,
    Quarantine, QuarantineKind, Relay, RelayIdentity, server_config,
};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use rustls::pki_types::{PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// The share domain.
const H: &str = "share.test";
/// What every refused connection on the TLS port gets: a fatal `unrecognized_name` alert record.
const REFUSAL: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];
/// What a refused request on port 80 gets.
const HTTP_REFUSAL: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
const FAILURE_DELAY: Duration = Duration::from_millis(300);
const PER_NAME: usize = 2;
const PER_TENANT: usize = 3;
const IDLE: Duration = Duration::from_secs(6);
const PEEK_DEADLINE: Duration = Duration::from_secs(2);
const MAX_PEEKS: usize = 3;
/// How long one client exchange may take before the test calls it hung.
const BOUND: Duration = Duration::from_secs(25);

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

fn share(name: &str, mode: ShareMode, svc: &str, alpn: &[&str]) -> Share {
    Share {
        name: name.to_string(),
        mode,
        service: svc.parse().unwrap(),
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

/// The node's handler: `inner`, after recording every OPEN that reached it.
struct Recording<H> {
    inner: H,
    opens: Arc<Mutex<Vec<OpenRequest>>>,
}

impl<H> ServiceHandler<Stream> for Recording<H>
where
    H: ServiceHandler<Stream> + Send + Sync,
{
    type Opened = H::Opened;
    type Handling = H::Handling;

    async fn open(&self, request: &OpenRequest) -> Result<Self::Opened, OpenRefusal> {
        self.opens.lock().unwrap().push(request.clone());
        self.inner.open(request).await
    }

    fn handle(&self, stream: Stream, request: OpenRequest, opened: Self::Opened) -> Self::Handling {
        self.inner.handle(stream, request, opened)
    }
}

/// A relay with a front door on `127.0.0.1:0` (TLS port) and a port 80 listener.
async fn start_front_door_relay(
    trust: &TestTrust,
    front: FrontDoorConfig,
) -> (TestRelay, SocketAddr) {
    let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
    let tls = server_config(trust.chain.clone(), key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls, "/_menzil/v1")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http.local_addr().unwrap();
    let id = identity();
    let relay = Relay::new(
        RelayIdentity {
            node_cert: node_cert(&id),
            x25519_private: id.x25519_private,
        },
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: 256 * 1024,
        },
    )
    // Every client here is 127.0.0.1: the per address figures are tested on their own.
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
    .with_front_door(front);
    let serving = relay.clone();
    tokio::spawn(async move {
        serving
            .serve_with_http(&listener, Some(http), AcceptConfig::default())
            .await
    });
    (TestRelay { addr, id, relay }, http_addr)
}

/// The bytes of a ClientHello for `sni` (none for `None`) offering `alpn`, as rustls writes them.
fn client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(["unused.test".to_string()]).unwrap();
    roots.add(cert.der().clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    let name = match sni {
        Some(name) => ServerName::try_from(name.to_string()).unwrap(),
        // An address is sent without an SNI extension.
        None => ServerName::try_from("192.0.2.1").unwrap(),
    };
    let mut client = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes
}

/// The ClientHello record `hello` (one record) as two records, the handshake message cut at `at`.
fn fragmented(hello: &[u8], at: usize) -> Vec<u8> {
    let (header, payload) = hello.split_at(5);
    assert_eq!(
        usize::from(u16::from_be_bytes([header[3], header[4]])),
        payload.len(),
        "one record"
    );
    let mut out = Vec::new();
    for part in [&payload[..at], &payload[at..]] {
        out.extend_from_slice(&[header[0], header[1], header[2]]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Connects, writes `bytes`, and reads until the relay closes: what came back and how long it
/// took (from the write).
async fn answer_to(addr: SocketAddr, bytes: &[u8]) -> (Vec<u8>, Duration) {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(bytes).await.unwrap();
    let began = Instant::now();
    let mut got = Vec::new();
    let mut chunk = [0u8; 1024];
    timeout(BOUND, async {
        loop {
            match tcp.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
            }
        }
    })
    .await
    .expect("the relay never closed the connection");
    (got, began.elapsed())
}

/// A connection through the front door that echoed `hello` and `tail`, held open.
async fn echoing(addr: SocketAddr, hello: &[u8], tail: &[u8]) -> TcpStream {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(hello).await.unwrap();
    tcp.write_all(tail).await.unwrap();
    let mut back = vec![0u8; hello.len() + tail.len()];
    timeout(BOUND, tcp.read_exact(&mut back))
        .await
        .expect("the echo did not come back in time")
        .expect("the relay closed the connection instead of piping it");
    assert_eq!(
        &back[..hello.len()],
        hello,
        "the ClientHello is piped unchanged"
    );
    assert_eq!(&back[hello.len()..], tail);
    tcp
}

/// Whether `tcp` is closed by the relay, with no byte, within `within`.
async fn closed_quietly(tcp: &mut TcpStream, within: Duration) -> bool {
    let mut byte = [0u8; 1];
    match timeout(within, tcp.read(&mut byte)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

/// A refusal is `REFUSAL` and not before the failure delay.
fn assert_refused(cause: &str, got: &[u8], took: Duration, quick: bool) {
    assert_eq!(got, REFUSAL, "{cause}: every cause gets the same bytes");
    assert!(
        took >= FAILURE_DELAY - Duration::from_millis(30),
        "{cause}: refused after {took:?}, sooner than the failure delay"
    );
    if quick {
        assert!(
            took < Duration::from_secs(5),
            "{cause}: a refusal that needs no round trip took {took:?}"
        );
    }
}

/// `GET {target}` with `host` (none for no Host header), over plain HTTP.
fn http_get(target: &str, host: Option<&str>) -> Vec<u8> {
    match host {
        Some(host) => format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
        None => format!("GET {target} HTTP/1.1\r\n\r\n").into_bytes(),
    }
}

fn redirect(host: &str, path: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn the_front_door_pipes_blind_shares_and_refuses_everything_else_the_same_way() {
    let trust = trust_test_certificate();
    let front = FrontDoorConfig::new("localhost", H)
        .unwrap()
        .with_failure_delay(FAILURE_DELAY)
        .with_share_connections(PER_NAME, PER_TENANT)
        .with_idle_timeout(IDLE)
        .with_peek_deadline(PEEK_DEADLINE)
        .with_max_peeks(MAX_PEEKS);
    let (relay, http) = start_front_door_relay(&trust, front).await;
    // The relay holds a quarantine for a name nobody holds.
    let mut state = NameState::default();
    state.quarantine.insert(
        "quar".to_string(),
        Quarantine {
            kind: QuarantineKind::Flat,
            since: unix_now(),
            tenant: None,
            network: Some(NetworkId::from([7u8; 32])),
        },
    );
    relay.relay.labels().load_state(&state);

    let node = identity();
    let other = identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let (network_id, roster1) = roster(
        &owner,
        node.node_id,
        other.node_id,
        &["app", "raw", "acme", "web", "gone", "ghost"],
    );
    let policy1 = policy_for(&owner, network_id, &node, &other);
    relay.relay.rosters().set(&roster1).unwrap();
    let rosters = Arc::new(RosterStore::new());
    rosters.set(&roster1).unwrap();
    let policies = Arc::new(PolicyStore::new());
    policies.set(&policy1).unwrap();

    // The node's local targets: three echo servers (app, raw, web); `acme` shares app's.
    let mut ports = HashMap::new();
    for name in ["app", "raw", "web"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        ports.insert(name, listener.local_addr().unwrap().port());
        let (ended, _keep) = mpsc::unbounded_channel();
        tokio::spawn(echo_server(listener, ended));
    }
    let services = LocalServices::new()
        .serve(
            service("tls:app"),
            LocalTarget::new("127.0.0.1", ports["app"]),
        )
        .unwrap()
        .serve(
            service("tls:acme"),
            LocalTarget::new("127.0.0.1", ports["app"]),
        )
        .unwrap()
        .serve(
            service("tcp:raw"),
            LocalTarget::new("127.0.0.1", ports["raw"]),
        )
        .unwrap()
        .serve(
            service("http:web"),
            LocalTarget::new("127.0.0.1", ports["web"]),
        )
        .unwrap();
    let opens: Arc<Mutex<Vec<OpenRequest>>> = Arc::default();
    let session_config = session_config(&relay, &node, network_id);

    // --- 1. the relay's own host name takes the WebSocket path through the front door -----
    let started = Node::start(
        NodeConfig {
            session: session_config,
            env: HashMap::new(),
            policies,
            rosters,
        },
        Recording {
            inner: services,
            opens: opens.clone(),
        },
    )
    .unwrap();
    let book = started.shares().clone();
    started
        .wait_attached(Duration::from_secs(20))
        .await
        .expect("the node must attach through the front door (SNI is the relay's own host)");
    until("the relay to hold the node", || {
        relay.relay.attached_node(&node.node_id).is_some()
    })
    .await;
    let shares = vec![
        share("app", ShareMode::Blind, "tls:app", &["h2", "http/1.1"]),
        share("raw", ShareMode::Blind, "tcp:raw", &[]),
        share("acme", ShareMode::Blind, "tls:acme", &["acme-tls/1"]),
        share("web", ShareMode::Terminated, "http:web", &[]),
        share("gone", ShareMode::Blind, "tls:gone", &[]),
    ];
    book.set_shares(shares.clone()).unwrap();
    until("the shares to be accepted", || {
        shares.iter().all(|s| book.accepted_service(&s.service))
    })
    .await;
    until("the relay to hold the claims", || {
        relay.relay.labels().shares_for(&node.node_id).len() == shares.len()
    })
    .await;
    let tls = relay.addr;

    // --- 2. blind shares: the bytes echo, the node sees the meta ------------------------------
    let hello = client_hello(Some("App.Share.Test"), &["h2", "http/1.1"]);
    let tail = b"application bytes after the hello".to_vec();
    drop(echoing(tls, &hello, &tail).await);
    let raw_hello = client_hello(Some("raw.share.test"), &[]);
    drop(echoing(tls, &raw_hello, b"raw bytes").await);
    let acme_hello = client_hello(Some("acme.share.test"), &["acme-tls/1"]);
    drop(echoing(tls, &acme_hello, b"challenge").await);
    // A ClientHello spread over two TLS records is routed the same.
    let split_hello = fragmented(&client_hello(Some("app.share.test"), &["h2"]), 30);
    drop(echoing(tls, &split_hello, b"fragmented").await);
    {
        let seen = opens.lock().unwrap();
        assert_eq!(seen.len(), 4, "{seen:?}");
        for request in seen.iter() {
            assert_eq!(request.initiator, relay.id.node_id, "the relay principal");
            assert_eq!(request.network_id, network_id);
            assert!(request.target.is_none());
            assert_eq!(request.meta.client_ip.as_deref(), Some("127.0.0.1"));
        }
        assert_eq!(seen[0].service, service("tls:app"));
        assert_eq!(
            seen[0].meta.sni.as_deref(),
            Some("app.share.test"),
            "lowercased"
        );
        assert_eq!(seen[1].service, service("tcp:raw"));
        assert_eq!(seen[1].meta.sni.as_deref(), Some("raw.share.test"));
        assert_eq!(seen[2].service, service("tls:acme"));
        assert_eq!(seen[3].service, service("tls:app"));
        assert_eq!(seen[3].meta.sni.as_deref(), Some("app.share.test"));
    }

    // --- 3. one refusal for every cause ---------------------------------------------------
    let ok_hello = client_hello(Some("app.share.test"), &["h2"]);
    let cases: Vec<(&str, Vec<u8>, bool)> = vec![
        (
            "an unknown name",
            client_hello(Some("nosuch.share.test"), &[]),
            true,
        ),
        ("the apex", client_hello(Some("share.test"), &[]), true),
        (
            "a name outside the share domain",
            client_hello(Some("app.other.test"), &[]),
            true,
        ),
        (
            "a name too deep",
            client_hello(Some("x.app.share.test"), &[]),
            true,
        ),
        (
            "a ClientHello over 16 KiB",
            [
                vec![22, 3, 1, 0x40, 0x00, 1, 0, 0xff, 0xff],
                vec![0u8; 16_380],
            ]
            .concat(),
            true,
        ),
        ("no SNI", client_hello(None, &[]), true),
        (
            "bytes that are not TLS",
            b"GET / HTTP/1.1\r\nHost: app.share.test\r\n\r\n".to_vec(),
            true,
        ),
        (
            "a name nobody holds",
            client_hello(Some("ghost.share.test"), &[]),
            true,
        ),
        (
            "a quarantined name",
            client_hello(Some("quar.share.test"), &[]),
            true,
        ),
        (
            "a terminated share",
            client_hello(Some("web.share.test"), &[]),
            true,
        ),
        (
            "acme-tls/1 for a share that did not list it",
            client_hello(Some("app.share.test"), &["acme-tls/1"]),
            true,
        ),
        (
            "acme-tls/1 among others for a share that did not list it",
            client_hello(Some("raw.share.test"), &["h2", "acme-tls/1"]),
            true,
        ),
        // The node accepted the share and refuses the stream (no such local service): one
        // round trip to the node, not a lookup.
        (
            "a node that refuses the stream",
            client_hello(Some("gone.share.test"), &[]),
            false,
        ),
    ];
    for (cause, bytes, quick) in &cases {
        let (got, took) = answer_to(tls, bytes).await;
        assert_refused(cause, &got, took, *quick);
    }
    // None of those reached the node's handler but the refused stream.
    assert_eq!(
        opens.lock().unwrap().len(),
        5,
        "only the refused `gone` stream was opened besides the four echoes: {:?}",
        opens.lock().unwrap()
    );
    // A refusal on the principal path (above) left no place taken: the tenant's three places
    // are all still there, so four connections of which three succeed prove it below.

    // --- 4. figures: 2 per name, 3 per tenant, released when a connection ends -------------
    let a1 = echoing(tls, &ok_hello, b"1").await;
    let a2 = echoing(tls, &ok_hello, b"2").await;
    let (got, took) = answer_to(tls, &ok_hello).await;
    assert_refused("a name over its figure", &got, took, true);
    let r1 = echoing(tls, &raw_hello, b"3").await;
    // The tenant has three connections: app, app, raw. Another name is over the tenant figure.
    let (got, took) = answer_to(tls, &acme_hello).await;
    assert_refused("a tenant over its figure", &got, took, true);
    let (got, took) = answer_to(tls, &raw_hello).await;
    assert_refused(
        "a tenant over its figure (a name under its own)",
        &got,
        took,
        true,
    );
    // A connection that ends gives its place back.
    drop(a1);
    let mut again = None;
    for _ in 0..100 {
        let mut tcp = TcpStream::connect(tls).await.unwrap();
        tcp.write_all(&ok_hello).await.unwrap();
        let mut back = vec![0u8; ok_hello.len()];
        if timeout(BOUND, tcp.read_exact(&mut back))
            .await
            .is_ok_and(|r| r.is_ok())
        {
            assert_eq!(back, ok_hello);
            again = Some(tcp);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let a3 = again.expect("the place of a closed connection was never given back");
    drop((a2, a3, r1));
    // All released: three fresh ones fit again (app, app, raw), a fourth does not.
    let mut held = Vec::new();
    for hello in [&ok_hello, &ok_hello, &raw_hello] {
        let mut placed = None;
        for _ in 0..100 {
            let mut tcp = TcpStream::connect(tls).await.unwrap();
            tcp.write_all(hello).await.unwrap();
            let mut back = vec![0u8; hello.len()];
            if timeout(BOUND, tcp.read_exact(&mut back))
                .await
                .is_ok_and(|r| r.is_ok())
            {
                placed = Some(tcp);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        held.push(placed.expect("a released place was not usable again"));
    }
    let (got, took) = answer_to(tls, &acme_hello).await;
    assert_refused("a tenant over its figure again", &got, took, true);
    drop(held);

    // --- 5. the peek cap and the peek deadline drop quietly -------------------------------
    // Wait for the places above to go: the next steps need the tenant empty.
    let mut silent = Vec::new();
    for _ in 0..MAX_PEEKS {
        silent.push(TcpStream::connect(tls).await.unwrap());
    }
    // Give the relay time to have accepted all of them into peeks.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut over = TcpStream::connect(tls).await.unwrap();
    assert!(
        closed_quietly(&mut over, Duration::from_millis(1500)).await,
        "a connection over the peek cap is dropped at once, without a byte"
    );
    // The silent ones are dropped at the deadline, without a byte.
    let began = Instant::now();
    for tcp in &mut silent {
        assert!(
            closed_quietly(tcp, PEEK_DEADLINE + Duration::from_secs(8)).await,
            "a peer that never sends its hello is dropped without a byte"
        );
    }
    assert!(
        began.elapsed() >= PEEK_DEADLINE - Duration::from_millis(600),
        "they were held until the deadline, {:?}",
        began.elapsed()
    );
    drop(silent);
    // A peek that is over frees its place.
    drop(echoing(tls, &ok_hello, b"after the peeks").await);

    // --- 6. an idle connection is ended and gives its place back ---------------------------
    let mut idle = echoing(tls, &ok_hello, b"then silence").await;
    let began = Instant::now();
    assert!(
        closed_quietly(&mut idle, IDLE * 3).await,
        "an idle connection must be ended by the relay"
    );
    assert!(
        began.elapsed() >= IDLE - Duration::from_secs(1),
        "ended after {:?}, before the idle timeout",
        began.elapsed()
    );

    // --- 7. port 80 --------------------------------------------------------------------------
    let (got, _) = answer_to(http, &http_get("/a/b?c=d", Some("app.share.test"))).await;
    assert_eq!(got, redirect("app.share.test", "/a/b?c=d"));
    let (got, _) = answer_to(http, &http_get("/", Some("Nosuch.Share.Test:80"))).await;
    assert_eq!(
        got,
        redirect("nosuch.share.test", "/"),
        "the redirect does not tell a held name from an unknown one"
    );
    let (got, _) = answer_to(http, &http_get("/", Some("localhost"))).await;
    assert_eq!(got, redirect("localhost", "/"));
    let before = opens.lock().unwrap().len();
    let challenge = "/.well-known/acme-challenge/token123";
    let (got, took) = answer_to(http, &http_get(challenge, Some("app.share.test"))).await;
    assert_eq!(got, HTTP_REFUSAL, "a challenge the node cannot serve yet");
    assert!(
        took >= FAILURE_DELAY - Duration::from_millis(30),
        "{took:?}"
    );
    {
        let seen = opens.lock().unwrap();
        assert_eq!(seen.len(), before + 1, "the challenge reached the node");
        let last = seen.last().unwrap();
        assert_eq!(last.service, service("acme-http:app"));
        assert_eq!(last.meta.sni.as_deref(), Some("app.share.test"));
        assert_eq!(last.meta.client_ip.as_deref(), Some("127.0.0.1"));
    }
    for (what, request) in [
        (
            "an unknown name",
            http_get(challenge, Some("nosuch.share.test")),
        ),
        (
            "a name outside the domain",
            http_get(challenge, Some("app.other.test")),
        ),
        ("no Host", http_get(challenge, None)),
        (
            "a terminated share",
            http_get(challenge, Some("web.share.test")),
        ),
        (
            "a host outside the share domain, not a challenge",
            http_get("/", Some("app.other.test")),
        ),
    ] {
        let (got, took) = answer_to(http, &request).await;
        assert_eq!(got, HTTP_REFUSAL, "{what}");
        assert!(
            took >= FAILURE_DELAY - Duration::from_millis(30),
            "{what}: {took:?}"
        );
    }
    assert_eq!(
        opens.lock().unwrap().len(),
        before + 1,
        "only the held blind name's challenge reached the node: {:?}",
        opens.lock().unwrap()
    );

    // --- 8. a node that is gone -------------------------------------------------------------
    started.shutdown().await;
    until("the relay to drop the node", || {
        relay.relay.attached_node(&node.node_id).is_none()
    })
    .await;
    let (got, took) = answer_to(tls, &ok_hello).await;
    assert_refused("a node that is not attached", &got, took, true);
}
