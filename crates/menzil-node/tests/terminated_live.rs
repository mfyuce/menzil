//! A terminated share end to end over real sockets (protocol.md 6.3, expose design slice S-E9c):
//! a real relay with a front door, a share domain and ACME, a real node with a `[[share]]` in
//! mode terminated (`http:web`) behind a local HTTP target, a fake in process ACME CA whose
//! TLS-ALPN-01 validation connects over TCP to the relay's own front door, and a real TLS client
//! that trusts only the root the fake CA made.
//!
//! 1. The relay orders `web.ali.t.share.test` through `RelayAcme` (the tenant `ali` has the
//!    `terminated` flag and the node holds the grant); the CA's validation is answered by the
//!    front door, the certificate is issued, stored and installed by the relay, not by hand. A
//!    blind share of the same tenant is never ordered.
//! 2. The two zones do not mix: the blind name echoes bytes, the blind name under `t` and the
//!    terminated name under the blind zone get the 7 byte alert.
//! 3. A GET over TLS (SNI `web.ali.t.share.test`, certificate verified against the CA root)
//!    returns the local target's body through the relay terminator, the principal stream and the
//!    node's `http:` service, twice on one kept alive connection. The target saw exactly one
//!    `X-Forwarded-For` (the client's loopback address), `X-Forwarded-Proto: https`, and none of
//!    the `Forwarded`, `X-Real-IP` or `X-Forwarded-*` values the client supplied.
//! 4. `Host` other than the SNI is `421`, and both `Content-Length` and `Transfer-Encoding` is
//!    `400`; the target never sees either.
//! 5. After the node withdraws the share, the kept alive connection is closed before its next
//!    request reaches the target, and a new connection gets the alert.
//!
//! One `#[tokio::test]` because `SSL_CERT_FILE` is process-global (see `live_session.rs`). Every
//! wait is bounded, so a regression fails the test instead of hanging it.

#![cfg(target_os = "linux")]

mod common;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    PATIENCE, echo_server, identity, node_cert, service, session_config, trust_test_certificate,
    unix_now,
};
use ed25519_dalek::SigningKey;
use menzil_acme::testing::{CA, FakeCa, Flags, fast};
use menzil_node::{LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RosterStore};
use menzil_proto::{
    Label, Limits, NetworkId, NodeId, PROTOCOL_VERSION, Policy, PolicyBody, PolicyMember, Roster,
    RosterBody, RosterMember, Share, ShareMode,
};
use menzil_relay::{
    AcceptConfig, AcmeConfig, AdmissionLimits, Class, FrontDoorConfig, Listener, PrincipalConfig,
    Relay, RelayAcme, RelayIdentity, Slug, TenantBook, TenantSpec, run_acme, server_config,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// The share domain.
const H: &str = "share.test";
/// The terminated name under test: label `web` of the tenant `ali`, in the `t` zone.
const T_HOST: &str = "web.ali.t.share.test";
/// What every refused connection on the TLS port gets: a fatal `unrecognized_name` alert record.
const REFUSAL: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];
const FAILURE_DELAY: Duration = Duration::from_millis(300);
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

/// A scratch directory for the relay's ACME account key and certificates.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("menzil-terminated-live-{}", std::process::id()));
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

/// The node's local HTTP target: keeps connections alive, records each request head (and body
/// length), answers `GET` with a fixed body.
#[derive(Clone, Default)]
struct Target {
    heads: Arc<Mutex<Vec<String>>>,
}

const BODY: &str = "hello from the local target";

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
                    heads.lock().unwrap().push(head);
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{BODY}",
                        BODY.len()
                    );
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

/// The bytes of a ClientHello for `sni`, as rustls writes them.
fn client_hello(sni: &str) -> Vec<u8> {
    let mut roots = rustls::RootCertStore::empty();
    let rcgen::CertifiedKey { cert, .. } =
        rcgen::generate_simple_self_signed(["unused.test".to_string()]).unwrap();
    roots.add(cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(sni.to_string()).unwrap();
    let mut client = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let mut bytes = Vec::new();
    client.write_tls(&mut bytes).unwrap();
    bytes
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

async fn assert_refused(cause: &str, addr: SocketAddr, sni: &str) {
    let (got, took) = answer_to(addr, &client_hello(sni)).await;
    assert_eq!(got, REFUSAL, "{cause}: the one refusal");
    assert!(
        took >= FAILURE_DELAY - Duration::from_millis(30),
        "{cause}: refused after {took:?}, sooner than the failure delay"
    );
}

/// A blind client: the ClientHello and `tail` echo back through the relay to the node's echo
/// server, byte for byte.
async fn echoes(addr: SocketAddr, sni: &str, tail: &[u8]) {
    let hello = client_hello(sni);
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(&hello).await.unwrap();
    tcp.write_all(tail).await.unwrap();
    let mut back = vec![0u8; hello.len() + tail.len()];
    timeout(BOUND, tcp.read_exact(&mut back))
        .await
        .expect("the echo did not come back in time")
        .expect("the relay closed the connection instead of piping it");
    assert_eq!(&back[..hello.len()], &hello[..]);
    assert_eq!(&back[hello.len()..], tail);
}

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

/// A TLS connection to the front door for `sni`, verifying the certificate against `root` only.
async fn tls_connect(addr: SocketAddr, root: &CertificateDer<'static>, sni: &str) -> Tls {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(root.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = ServerName::try_from(sni.to_string()).unwrap();
    timeout(
        BOUND,
        TlsConnector::from(Arc::new(config)).connect(name, tcp),
    )
    .await
    .expect("the TLS handshake hung")
    .expect("the certificate the CA issued must verify against the CA's root")
}

/// One response: its head and its body (framed by `Content-Length`).
async fn read_response(tls: &mut Tls) -> (String, Vec<u8>) {
    timeout(BOUND, async {
        let mut buf = Vec::new();
        let end = loop {
            if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
            let mut chunk = [0u8; 4096];
            let n = tls.read(&mut chunk).await.expect("the response head");
            assert!(n > 0, "closed before a full response head: {buf:?}");
            buf.extend_from_slice(&chunk[..n]);
        };
        let head = String::from_utf8(buf[..end].to_vec()).unwrap();
        let length: usize = header_values(&head, "content-length")
            .first()
            .map_or(0, |v| v.parse().unwrap());
        let mut body = buf[end..].to_vec();
        while body.len() < length {
            let mut chunk = [0u8; 4096];
            let n = tls.read(&mut chunk).await.expect("the response body");
            assert!(n > 0, "closed inside the body");
            body.extend_from_slice(&chunk[..n]);
        }
        (head, body)
    })
    .await
    .expect("no response in time")
}

/// Whether `tls` is closed with no byte of an answer within `within`.
async fn closed_without_answer(tls: &mut Tls, within: Duration) -> bool {
    let mut chunk = [0u8; 1024];
    match timeout(within, tls.read(&mut chunk)).await {
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(_)) | Err(_) => false,
    }
}

#[tokio::test]
async fn a_terminated_share_is_served_through_a_certificate_the_relay_ordered_itself() {
    let trust = trust_test_certificate();
    let scratch = Scratch::new();

    // --- the relay: front door, tenant `ali` (terminated), ACME against the fake CA ---------
    let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
    let tls_config = server_config(trust.chain.clone(), key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls_config, "/_menzil/v1")
        .await
        .unwrap();
    let front_addr = listener.local_addr().unwrap();
    let acme_config = AcmeConfig::new(&format!("{CA}/dir"), &scratch.0)
        .unwrap()
        .with_contact("mailto:ops@example.org")
        .with_tick(Duration::from_millis(20));
    let acme = RelayAcme::new(acme_config)
        .with_timing(fast())
        .with_external_runner();
    let ca = FakeCa::new(
        acme.challenges(),
        Flags {
            // The CA's validation connection goes to the relay's real front door.
            validate_via: Some(front_addr),
            ..Flags::default()
        },
    );
    let (relay, relay_handle) = start_relay(listener, acme.clone()).await;
    let acme_task = tokio::spawn(run_acme(relay_handle, acme.clone(), ca.clone()));

    let node = identity();
    let other = identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let (network_id, roster1) = roster(&owner, node.node_id, other.node_id, &["web", "app"]);
    let policy1 = policy_for(&owner, network_id, &node, &other);
    relay.relay.rosters().set(&roster1).unwrap();
    relay.relay.set_tenants(TenantBook::build(
        vec![TenantSpec {
            slug: Slug::parse("ali").unwrap(),
            networks: vec![network_id],
            class: Class::Friend,
            overrides: Default::default(),
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

    // --- the node: `http:web` terminated behind a local HTTP target, `tls:app` blind --------
    let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http.local_addr().unwrap().port();
    let target = Target::default();
    tokio::spawn(target.clone().serve(http));
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let (ended, _keep) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(echo, ended));
    let services = LocalServices::new()
        .serve(
            service("http:web"),
            LocalTarget::new("127.0.0.1", http_port),
        )
        .unwrap()
        .serve(service("tls:app"), LocalTarget::new("127.0.0.1", echo_port))
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
        relay.relay.attached_node(&node.node_id).is_some()
    })
    .await;
    let web = share("web", ShareMode::Terminated, "http:web");
    let app = share("app", ShareMode::Blind, "tls:app");
    book.set_shares(vec![web.clone(), app.clone()]).unwrap();
    until("the shares to be accepted", || {
        book.accepted_service(&web.service) && book.accepted_service(&app.service)
    })
    .await;
    until("the relay to hold the claims", || {
        relay.relay.labels().shares_for(&node.node_id).len() == 2
    })
    .await;
    let tls_addr = relay.addr;

    // --- 1. the relay orders the certificate itself, through the CA and its own front door ---
    until("the relay's certificate for the terminated name", || {
        acme.certs().get(T_HOST).is_some()
    })
    .await;
    let certified = acme.certs().get(T_HOST).unwrap();
    assert!(
        certified.cert.len() >= 2,
        "the CA's chain: the leaf and its root"
    );
    let root = certified.cert.last().unwrap().clone().into_owned();
    {
        let state = ca.state();
        assert_eq!(
            state.domain, T_HOST,
            "the CA was asked for exactly this name"
        );
        assert_eq!(
            state.validated,
            Some(true),
            "the CA validated through the front door's challenge certificate"
        );
        assert!(state.finalized);
        assert_eq!(state.challenge_posts, 1);
        assert_eq!(
            state.log.iter().filter(|r| *r == "Post /order").count(),
            1,
            "{:?}",
            state.log
        );
    }
    assert!(
        acme.challenges().is_empty() || !acme.challenges().is_pending(T_HOST),
        "the order ended"
    );
    // The same assertion from the other side: nothing but the terminated name was ever ordered.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(acme.certs().names(), vec![T_HOST.to_string()]);
    assert_eq!(
        ca.state()
            .log
            .iter()
            .filter(|r| *r == "Post /order")
            .count(),
        1,
        "the blind share of the same tenant is never ordered"
    );

    // --- 2. zone separation ----------------------------------------------------------------
    echoes(tls_addr, "app.ali.share.test", b"blind bytes").await;
    assert_refused(
        "a terminated share under the blind zone",
        tls_addr,
        "web.ali.share.test",
    )
    .await;
    assert_refused(
        "a blind share under the terminated zone",
        tls_addr,
        "app.ali.t.share.test",
    )
    .await;
    assert_eq!(target.count(), 0, "nothing reached the HTTP target yet");

    // --- 3. a GET through TLS, the terminator, the principal stream and the node -------------
    let mut kept = tls_connect(tls_addr, &root, T_HOST).await;
    let get = format!(
        "GET /hello HTTP/1.1\r\nHost: {T_HOST}\r\nX-Forwarded-For: 6.6.6.6\r\nForwarded: for=6.6.6.6\r\nX-Real-IP: 6.6.6.6\r\nX-Forwarded-Proto: http\r\n\r\n"
    );
    kept.write_all(get.as_bytes()).await.unwrap();
    let (head, body) = read_response(&mut kept).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, BODY.as_bytes());
    {
        let heads = target.heads.lock().unwrap();
        assert_eq!(heads.len(), 1);
        let seen = &heads[0];
        assert!(seen.starts_with("GET /hello HTTP/1.1\r\n"), "{seen}");
        assert_eq!(
            header_values(seen, "x-forwarded-for"),
            vec!["127.0.0.1".to_string()],
            "one X-Forwarded-For, the real client, none of the client's own: {seen}"
        );
        assert_eq!(
            header_values(seen, "x-forwarded-proto"),
            vec!["https".to_string()],
            "{seen}"
        );
        assert!(header_values(seen, "forwarded").is_empty(), "{seen}");
        assert!(header_values(seen, "x-real-ip").is_empty(), "{seen}");
        assert!(!seen.contains("6.6.6.6"), "{seen}");
        assert_eq!(header_values(seen, "host"), vec![T_HOST.to_string()]);
    }
    // The connection is kept alive: a second request goes through the same node stream.
    kept.write_all(get.as_bytes()).await.unwrap();
    let (head, body) = read_response(&mut kept).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, BODY.as_bytes());
    assert_eq!(target.count(), 2);

    // --- 4. a Host that is not the SNI, and ambiguous framing, never reach the target --------
    let mut wrong_host = tls_connect(tls_addr, &root, T_HOST).await;
    wrong_host
        .write_all(b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n")
        .await
        .unwrap();
    let (head, _) = read_response(&mut wrong_host).await;
    assert!(head.starts_with("HTTP/1.1 421"), "{head}");
    let mut smuggle = tls_connect(tls_addr, &root, T_HOST).await;
    smuggle
        .write_all(
            format!(
                "POST / HTTP/1.1\r\nHost: {T_HOST}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (head, _) = read_response(&mut smuggle).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(target.count(), 2, "neither request reached the target");

    // --- 5. the share is withdrawn: the kept alive connection is closed, new ones refused ----
    book.set_shares(vec![app.clone()]).unwrap();
    until("the node to hold only the blind share", || {
        !book.accepted_service(&web.service)
    })
    .await;
    until("the relay to drop the claim", || {
        relay.relay.labels().shares_for(&node.node_id).len() == 1
    })
    .await;
    kept.write_all(get.as_bytes()).await.unwrap();
    assert!(
        closed_without_answer(&mut kept, Duration::from_secs(10)).await,
        "a withdrawn share's kept alive connection is closed, not answered"
    );
    assert_eq!(
        target.count(),
        2,
        "the third request never reached the target"
    );
    assert_refused("a withdrawn terminated share", tls_addr, T_HOST).await;
    // The blind share of the same tenant is not touched by it.
    echoes(tls_addr, "app.ali.share.test", b"still blind").await;

    acme_task.abort();
    started.shutdown().await;
}
