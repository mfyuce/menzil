//! WebSocket through a terminated share end to end over real sockets (protocol.md 6.3): a real
//! relay with a front door and a share domain, a real node with a `[[share]]` in mode terminated
//! (`http:web`) behind a local target that speaks HTTP/1.1 and WebSocket (hand written: the RFC
//! 6455 example key and accept, frames are opaque bytes that the target echoes), and a real TLS
//! client that trusts only the certificate installed for the name.
//!
//! 1. A handshake through TLS, the terminator, the principal stream and the node's `http:`
//!    service: the target sees one canonical `Connection: Upgrade` and `Upgrade: websocket`, the
//!    key, version, subprotocol and origin unchanged, one `X-Forwarded-For` (the client), and none
//!    of the spoofed address headers. The client gets the `101` with the subprotocol, and the
//!    first frame the target wrote right behind its head. Frames of several sizes (up to 100,000
//!    bytes) go there and back unchanged, in order.
//! 2. The bytes are charged to the tenant (`usage_snapshot` grows by at least what went up).
//! 3. The open WebSocket keeps the connection's place: with `share_connections_per_name = 1` a
//!    second connection to the name is refused with the alert while it is open, and served again
//!    once it has ended (a clean close from the client).
//! 4. A final answer (`401`) to a handshake is an ordinary response and the connection stays
//!    HTTP; a handshake with a wrong version is `400` and an `h2c` upgrade `501`, neither reaches
//!    the target.
//! 5. The node withdraws the share while a WebSocket is open: the relay cuts the connection,
//!    abruptly (at its next 30 second check at the latest; the unit tests in the relay pin the
//!    check itself), and a new connection gets the alert.
//!
//! One `#[tokio::test]` because `SSL_CERT_FILE` is process-global (see `live_session.rs`). Every
//! wait is bounded, so a regression fails the test instead of hanging it.

#![cfg(target_os = "linux")]

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    PATIENCE, identity, node_cert, service, session_config, trust_test_certificate, unix_now,
};
use ed25519_dalek::SigningKey;
use menzil_node::{LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RosterStore};
use menzil_proto::{
    Label, Limits, NetworkId, NodeId, PROTOCOL_VERSION, Policy, PolicyBody, PolicyMember, Roster,
    RosterBody, RosterMember, Share, ShareMode,
};
use menzil_relay::{
    AcceptConfig, AcmeConfig, AdmissionLimits, Class, FrontDoorConfig, Listener, PrincipalConfig,
    Relay, RelayAcme, RelayIdentity, Slug, TenantBook, TenantSpec, server_config,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// The share domain.
const H: &str = "share.test";
/// The terminated name under test: label `web` of the tenant `ali`, in the `t` zone.
const T_HOST: &str = "web.ali.t.share.test";
const FAILURE_DELAY: Duration = Duration::from_millis(300);
/// How long one client exchange may take before the test calls it hung.
const BOUND: Duration = Duration::from_secs(25);
/// The RFC 6455 example key and the accept it earns.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
/// What the target writes right behind its `101` head.
const FIRST_FRAME: &[u8] = b"\x81\x0bfirst frame";

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

fn share(name: &str, mode: ShareMode, svc: &str) -> Share {
    Share {
        name: name.to_string(),
        mode,
        service: svc.parse().unwrap(),
        alpn: vec![],
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

/// The node's local target: records each request head; `/chat` with an upgrade is answered `101`
/// with a frame right behind the head and then echoes every byte; `/denied` is answered `401`;
/// anything else `200`. Connections are kept alive.
#[derive(Clone, Default)]
struct Target {
    heads: Arc<Mutex<Vec<String>>>,
}

impl Target {
    async fn serve(self, listener: TcpListener) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let heads = self.heads.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let end = loop {
                        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break at + 4;
                        }
                        let mut chunk = [0u8; 4096];
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    buf.drain(..end);
                    heads.lock().unwrap().push(head.clone());
                    if head.starts_with("GET /chat ") && !header_values(&head, "upgrade").is_empty()
                    {
                        let mut reply = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\nSec-WebSocket-Protocol: chat\r\n\r\n"
                        )
                        .into_bytes();
                        reply.extend_from_slice(FIRST_FRAME);
                        if socket.write_all(&reply).await.is_err() {
                            return;
                        }
                        let mut chunk = vec![0u8; 16 * 1024];
                        loop {
                            match socket.read(&mut chunk).await {
                                Ok(0) | Err(_) => return,
                                Ok(n) => {
                                    if socket.write_all(&chunk[..n]).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    let reply = if head.starts_with("GET /denied ") {
                        "HTTP/1.1 401 Unauthorized\r\nContent-Length: 2\r\n\r\nno"
                    } else {
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                    };
                    if socket.write_all(reply.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    }

    fn count(&self) -> usize {
        self.heads.lock().unwrap().len()
    }
}

/// The header lines of `head` named `name` (case-insensitive), values trimmed.
fn header_values(head: &str, name: &str) -> Vec<String> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
        .collect()
}

/// A relay with a front door on `127.0.0.1:0` (the TLS port), ACME run by the caller, and the
/// listener's address (the front door's, which the fake CA validates against).
async fn start_relay(listener: Listener, acme: RelayAcme) -> (common::TestRelay, Relay) {
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
    .with_front_door(
        FrontDoorConfig::new("localhost", H)
            .unwrap()
            .with_failure_delay(FAILURE_DELAY),
    )
    .with_acme(acme);
    let serving = relay.clone();
    tokio::spawn(async move {
        serving
            .serve_with_http(&listener, None, AcceptConfig::default())
            .await
    });
    (
        common::TestRelay {
            addr,
            id,
            relay: relay.clone(),
        },
        relay,
    )
}

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

fn client_config(root: &CertificateDer<'static>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// A TLS connection to the front door for `sni`, verifying the certificate against `root` only;
/// `None` if the handshake fails (the front door's refusal alert, a full figure).
async fn tls_try(addr: SocketAddr, root: &CertificateDer<'static>, sni: &str) -> Option<Tls> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(sni.to_string()).unwrap();
    timeout(
        BOUND,
        TlsConnector::from(client_config(root)).connect(name, tcp),
    )
    .await
    .expect("the TLS handshake hung")
    .ok()
}

async fn tls_connect(addr: SocketAddr, root: &CertificateDer<'static>, sni: &str) -> Tls {
    tls_try(addr, root, sni)
        .await
        .expect("the connection must be served")
}

/// A connection for `sni` once the place of an ended one is free again.
async fn connect_when_free(addr: SocketAddr, root: &CertificateDer<'static>, sni: &str) -> Tls {
    let deadline = Instant::now() + PATIENCE;
    loop {
        if let Some(tls) = tls_try(addr, root, sni).await {
            return tls;
        }
        assert!(Instant::now() < deadline, "the place was never given back");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// One response head (up to its blank line) and the bytes that came behind it in the same reads.
async fn read_head(rd: &mut (impl AsyncReadExt + Unpin)) -> (String, Vec<u8>) {
    timeout(BOUND, async {
        let mut buf = Vec::new();
        loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8(buf[..at + 4].to_vec()).unwrap();
                return (head, buf[at + 4..].to_vec());
            }
            let mut chunk = [0u8; 4096];
            let n = rd.read(&mut chunk).await.expect("the response head");
            assert!(n > 0, "closed before a full response head: {buf:?}");
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("no response head in time")
}

/// `n` bytes: `extra` first, then the stream.
async fn read_n(rd: &mut (impl AsyncReadExt + Unpin), extra: &mut Vec<u8>, n: usize) -> Vec<u8> {
    timeout(BOUND, async {
        while extra.len() < n {
            let mut chunk = vec![0u8; 16 * 1024];
            let got = rd.read(&mut chunk).await.expect("a read of the pipe");
            assert!(got > 0, "the pipe ended with {} of {n} bytes", extra.len());
            extra.extend_from_slice(&chunk[..got]);
        }
        extra.drain(..n).collect()
    })
    .await
    .expect("the bytes did not arrive in time")
}

/// The handshake of the example in RFC 6455, with the headers a browser sends and some spoofed
/// address headers.
fn handshake(path: &str, version: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {T_HOST}\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\
         Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: {version}\r\nSec-WebSocket-Protocol: chat\r\n\
         Origin: https://app.example\r\nX-Forwarded-For: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\n\
         X_Real_IP: 6.6.6.6\r\n\r\n"
    )
}

fn ali_bytes(relay: &Relay) -> u64 {
    relay
        .usage_snapshot()
        .iter()
        .find(|(id, _)| id.slug() == Some("ali"))
        .map_or(0, |(_, usage)| usage.bytes_period)
}

#[tokio::test]
async fn a_websocket_goes_through_a_terminated_share_and_follows_its_name() {
    let trust = trust_test_certificate();

    // --- the relay: front door, tenant `ali` (terminated, one connection per name) ----------
    let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
    let tls_config = server_config(trust.chain.clone(), key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls_config, "/_menzil/v1")
        .await
        .unwrap();
    let acme =
        RelayAcme::new(AcmeConfig::new("https://ca.example.test/dir", "/nonexistent").unwrap());
    // The certificate of the name, installed by hand (the ordering is S-E9c's test): the client
    // trusts exactly this one.
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed([T_HOST.to_string()]).unwrap();
    acme.certs()
        .install_pem(T_HOST, &cert.pem(), &signing_key.serialize_pem())
        .unwrap();
    let root = cert.der().clone();
    let (relay, relay_handle) = start_relay(listener, acme).await;

    let node = identity();
    let other = identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let (network_id, roster1) = roster(&owner, node.node_id, other.node_id, &["web"]);
    let policy1 = policy_for(&owner, network_id, &node, &other);
    relay.relay.rosters().set(&roster1).unwrap();
    relay.relay.set_tenants(TenantBook::build(
        vec![TenantSpec {
            slug: Slug::parse("ali").unwrap(),
            networks: vec![network_id],
            class: Class::Friend,
            overrides: BTreeMap::from([("share_connections_per_name".to_string(), 1)]),
            terminated: true,
            extra_names: Vec::new(),
            added: 1,
        }],
        vec![],
        &HashSet::new(),
        &HashSet::new(),
    ));
    let rosters = Arc::new(RosterStore::new());
    rosters.set(&roster1).unwrap();
    let policies = Arc::new(PolicyStore::new());
    policies.set(&policy1).unwrap();

    // --- the node: `http:web` terminated behind the local target ---------------------------
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    let target = Target::default();
    tokio::spawn(target.clone().serve(http));
    let services = LocalServices::new()
        .serve(
            service("http:web"),
            LocalTarget::new("127.0.0.1", http_port),
        )
        .unwrap();
    let started = Node::start(
        NodeConfig {
            session: session_config(&relay, &node, network_id),
            env: HashMap::new(),
            policies,
            rosters,
        },
        services,
    )
    .unwrap();
    let book = started.shares().clone();
    started
        .wait_attached(Duration::from_secs(20))
        .await
        .expect("the node must attach through the front door");
    until("the relay to hold the node", || {
        relay_handle.attached_node(&node.node_id).is_some()
    })
    .await;
    let web = share("web", ShareMode::Terminated, "http:web");
    book.set_shares(vec![web.clone()]).unwrap();
    until("the share to be accepted", || {
        book.accepted_service(&web.service)
    })
    .await;
    until("the relay to hold the claim", || {
        relay_handle.labels().shares_for(&node.node_id).len() == 1
    })
    .await;
    let tls_addr = relay.addr;

    // --- 1. a WebSocket through TLS, the terminator, the principal stream and the node ------
    let volume_before = ali_bytes(&relay_handle);
    let (mut rd, mut wr) = tokio::io::split(tls_connect(tls_addr, &root, T_HOST).await);
    wr.write_all(handshake("/chat", "13").as_bytes())
        .await
        .unwrap();
    let (head, mut extra) = read_head(&mut rd).await;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    assert!(
        head.contains(&format!("Sec-WebSocket-Accept: {ACCEPT}\r\n")),
        "{head}"
    );
    assert!(head.contains("Sec-WebSocket-Protocol: chat\r\n"), "{head}");
    {
        let heads = target.heads.lock().unwrap();
        assert_eq!(heads.len(), 1);
        let seen = &heads[0];
        assert_eq!(
            header_values(seen, "upgrade"),
            vec!["websocket".to_string()]
        );
        assert_eq!(
            header_values(seen, "connection"),
            vec!["Upgrade".to_string()]
        );
        assert_eq!(
            header_values(seen, "sec-websocket-key"),
            vec![KEY.to_string()]
        );
        assert_eq!(
            header_values(seen, "sec-websocket-version"),
            vec!["13".to_string()]
        );
        assert_eq!(
            header_values(seen, "sec-websocket-protocol"),
            vec!["chat".to_string()]
        );
        assert_eq!(
            header_values(seen, "origin"),
            vec!["https://app.example".to_string()]
        );
        assert_eq!(
            header_values(seen, "x-forwarded-for"),
            vec!["127.0.0.1".to_string()],
            "{seen}"
        );
        assert!(!seen.contains("6.6.6.6"), "{seen}");
        assert!(header_values(seen, "forwarded").is_empty(), "{seen}");
        assert_eq!(header_values(seen, "host"), vec![T_HOST.to_string()]);
    }
    // The frame the target wrote right behind its head arrives first.
    assert_eq!(
        read_n(&mut rd, &mut extra, FIRST_FRAME.len()).await,
        FIRST_FRAME
    );
    // Frames of several sizes there and back, byte for byte.
    let mut up_total = 0u64;
    for (i, size) in [1usize, 2, 125, 126, 1_000, 16_384, 65_535, 100_000]
        .into_iter()
        .enumerate()
    {
        let frame: Vec<u8> = (0..size).map(|n| (n * 7 + i) as u8).collect();
        let (written, back) = tokio::join!(
            wr.write_all(&frame),
            read_n(&mut rd, &mut extra, frame.len())
        );
        written.unwrap();
        assert!(back == frame, "the frame of {size} bytes came back changed");
        up_total += size as u64;
    }
    assert!(extra.is_empty());
    // --- 2. what went through is charged to the tenant -------------------------------------
    let charged = ali_bytes(&relay_handle) - volume_before;
    assert!(
        charged >= up_total,
        "{charged} bytes charged for {up_total} bytes sent"
    );

    // --- 3. the open WebSocket keeps its place ---------------------------------------------
    assert!(
        tls_try(tls_addr, &root, T_HOST).await.is_none(),
        "a second connection while the WebSocket is open exceeds the figure of one per name"
    );
    // A clean close from the client ends the pipe both ways and gives the place back.
    wr.shutdown().await.unwrap();
    let mut rest = Vec::new();
    let ended = timeout(BOUND, rd.read_to_end(&mut rest)).await;
    assert!(
        matches!(ended, Ok(Ok(_))),
        "a clean close of both sides ends with a close_notify, not an error: {ended:?}"
    );
    drop((rd, wr));

    // --- 4. other answers and refusals: HTTP stays HTTP, nothing reaches the target ---------
    let mut tls = connect_when_free(tls_addr, &root, T_HOST).await;
    tls.write_all(handshake("/denied", "13").as_bytes())
        .await
        .unwrap();
    let (head, mut extra) = read_head(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 401 "), "{head}");
    assert_eq!(read_n(&mut tls, &mut extra, 2).await, b"no");
    tls.write_all(format!("GET /plain HTTP/1.1\r\nHost: {T_HOST}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let (head, mut extra) = read_head(&mut tls).await;
    assert!(
        head.starts_with("HTTP/1.1 200 "),
        "the connection stayed HTTP: {head}"
    );
    assert_eq!(read_n(&mut tls, &mut extra, 2).await, b"ok");
    let seen_by_target = target.count();
    assert_eq!(
        seen_by_target, 3,
        "the websocket, the 401 and the plain request"
    );
    // A wrong version is 400, and the connection is closed.
    tls.write_all(handshake("/chat", "12").as_bytes())
        .await
        .unwrap();
    let (head, _) = read_head(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
    drop(tls);
    // An upgrade to h2c is 501.
    let mut tls = connect_when_free(tls_addr, &root, T_HOST).await;
    tls.write_all(
        format!(
            "GET /chat HTTP/1.1\r\nHost: {T_HOST}\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let (head, _) = read_head(&mut tls).await;
    assert!(head.starts_with("HTTP/1.1 501 "), "{head}");
    drop(tls);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        target.count(),
        seen_by_target,
        "neither refusal reached the target"
    );

    // --- 5. the node withdraws the share while a WebSocket is open --------------------------
    let (mut rd, mut wr) = tokio::io::split(connect_when_free(tls_addr, &root, T_HOST).await);
    wr.write_all(handshake("/chat", "13").as_bytes())
        .await
        .unwrap();
    let (head, mut extra) = read_head(&mut rd).await;
    assert!(head.starts_with("HTTP/1.1 101 "), "{head}");
    read_n(&mut rd, &mut extra, FIRST_FRAME.len()).await;
    book.set_shares(vec![]).unwrap();
    until("the relay to drop the claim", || {
        relay_handle.labels().shares_for(&node.node_id).is_empty()
    })
    .await;
    // The relay asks again every 30 s: within a little more than that the connection is cut,
    // abruptly (an error on the client's side, not a clean close).
    let cut = timeout(Duration::from_secs(45), async {
        let mut chunk = [0u8; 1024];
        loop {
            match rd.read(&mut chunk).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .expect("the WebSocket of a withdrawn share was never cut");
    assert!(cut.is_err(), "a cut is no clean close: {cut:?}");
    drop((rd, wr));
    assert!(
        tls_try(tls_addr, &root, T_HOST).await.is_none(),
        "a new connection to a withdrawn share gets the alert"
    );

    started.shutdown().await;
}
