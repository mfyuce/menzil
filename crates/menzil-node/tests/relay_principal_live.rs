//! The relay principal end to end over real sockets (protocol.md 6.1, expose design slice S-E5):
//! a real relay, a real node serving `[[share]]`s to local TCP echo servers, and the relay's
//! `Principal` opening streams to them. What the unit tests of each side check against a scripted
//! peer is checked here against the other real side.
//!
//! 1. A node that advertised no share is silent to the principal's `init`
//!    ([`PrincipalError::HandshakeTimeout`]) and starts no session.
//! 2. Once its shares are accepted the principal opens `tls:app` and `tcp:raw`: bytes echo both
//!    ways, one megabyte through a small relay credit window too. The node's handler sees the
//!    relay as initiator, `network_id` as the session's, no target and `meta` validated (a good
//!    `client_ip` and `sni` kept, bad ones dropped).
//! 3. A service the node serves to members but did not share is refused `no_grant`, and nothing
//!    reaches its local target.
//! 4. Withdrawing a share resets that share's live stream and leaves the other share's stream and
//!    the session alone; a new OPEN of the withdrawn service is `no_grant`.
//! 5. An L3 reconnect of the node ends the principal session and its streams; after the node
//!    advertised again a fresh `open` works.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global (see that file's own doc comment). Every wait is bounded, so a regression
//! fails the test instead of hanging it.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::{
    Ended, PATIENCE, echo_round_trip, echo_server, identity, node_cert, service, session_config,
    start_relay, trust_test_certificate, unix_now,
};
use ed25519_dalek::SigningKey;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_node::{
    LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RosterStore, Session,
};
use menzil_proto::{
    ErrorCode, Label, NetworkId, NodeId, OpenMeta, PROTOCOL_VERSION, Policy, PolicyBody,
    PolicyMember, Roster, RosterBody, RosterMember, Share, ShareMode,
};
use menzil_relay::{Principal, PrincipalConfig, PrincipalError, TenantId};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// How long one principal call may take before the test calls it hung.
const BOUND: Duration = Duration::from_secs(20);
/// The principal's wait for the node's `resp`: short, because step 1 waits all of it.
const HANDSHAKE: Duration = Duration::from_secs(3);
/// The relay's credit window towards the node: far below the megabyte of step 2, so the transfer
/// only completes if credit is returned all along.
const CREDIT: u32 = 128 * 1024;

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

fn share(name: &str, svc: &str) -> Share {
    Share {
        name: name.to_string(),
        mode: ShareMode::Blind,
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

/// The node's handler: `inner`, after recording every OPEN that reached it (that is, passed the
/// authorizer, and for the relay principal's session had its `meta` validated).
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

/// A target that only counts the connections made to it.
async fn counting_server(listener: TcpListener, accepted: Arc<AtomicUsize>) {
    loop {
        let Ok((socket, _)) = listener.accept().await else {
            return;
        };
        accepted.fetch_add(1, Ordering::SeqCst);
        drop(socket);
    }
}

fn meta(client_ip: &str, sni: &str) -> OpenMeta {
    OpenMeta {
        client_ip: Some(client_ip.to_string()),
        sni: Some(sni.to_string()),
    }
}

async fn open(
    principal: &Principal,
    node: NodeId,
    network_id: NetworkId,
    svc: &str,
    meta: OpenMeta,
) -> Result<Stream, PrincipalError> {
    timeout(
        BOUND,
        principal.open(&TenantId::Default, node, network_id, service(svc), meta),
    )
    .await
    .unwrap_or_else(|_| panic!("principal.open({svc}) hung"))
}

/// The one read of a stream that was reset: bounded, and an error rather than an end of file.
async fn expect_reset(stream: &mut Stream, within: Duration, what: &str) {
    let mut byte = [0u8; 1];
    let error = timeout(within, stream.read(&mut byte))
        .await
        .unwrap_or_else(|_| panic!("{what}: the stream was not reset in time"))
        .expect_err("a reset, not an end of file");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{what}");
}

async fn local_target_ended(ended: &mut mpsc::UnboundedReceiver<Ended>, what: &str) -> Ended {
    timeout(PATIENCE, ended.recv())
        .await
        .unwrap_or_else(|_| panic!("{what}: the local target never saw the connection end"))
        .expect("the echo server is alive")
}

#[tokio::test]
async fn the_relay_principal_opens_shared_services_of_a_live_node_and_only_those() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, CREDIT).await;
    let node = identity();
    let other = identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let (network_id, roster1) = roster(&owner, node.node_id, other.node_id, &["myapp", "raw"]);
    let policy1 = policy_for(&owner, network_id, &node, &other);
    relay.relay.rosters().set(&roster1).unwrap();
    let rosters = Arc::new(RosterStore::new());
    rosters.set(&roster1).unwrap();
    let policies = Arc::new(PolicyStore::new());
    policies.set(&policy1).unwrap();

    // The node's three local targets: two it shares, one it serves to members only.
    let myapp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_port = myapp.local_addr().unwrap().port();
    let (app_ended_tx, mut app_ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(myapp, app_ended_tx));
    let raw = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let raw_port = raw.local_addr().unwrap().port();
    let (raw_ended_tx, mut raw_ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(raw, raw_ended_tx));
    let secret = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let secret_port = secret.local_addr().unwrap().port();
    let secret_connections = Arc::new(AtomicUsize::new(0));
    tokio::spawn(counting_server(secret, secret_connections.clone()));
    let services = LocalServices::new()
        .serve(
            service("tls:myapp"),
            LocalTarget::new("127.0.0.1", app_port),
        )
        .unwrap()
        .serve(service("tcp:raw"), LocalTarget::new("127.0.0.1", raw_port))
        .unwrap()
        .serve(
            service("tcp:secret"),
            LocalTarget::new("127.0.0.1", secret_port),
        )
        .unwrap();
    let opens: Arc<Mutex<Vec<OpenRequest>>> = Arc::default();

    let session_config = session_config(&relay, &node, network_id);
    let started = Node::start(
        NodeConfig {
            session: session_config.clone(),
            env: HashMap::new(),
            policies,
            rosters: rosters.clone(),
        },
        Recording {
            inner: services,
            opens: opens.clone(),
        },
    )
    .unwrap();
    let book = started.shares().clone();
    started
        .wait_attached(PATIENCE)
        .await
        .expect("the node must attach");
    // The node counts itself attached when it has sent ATTACH; the relay has it when it has read it.
    until("the relay to hold the node", || {
        relay.relay.attached_node(&node.node_id).is_some()
    })
    .await;

    let principal = Principal::with_config(
        &relay.relay,
        PrincipalConfig::default()
            .with_tick(Duration::from_millis(50))
            .with_handshake_timeout(HANDSHAKE),
    );
    let app_share = share("myapp", "tls:myapp");
    let raw_share = share("raw", "tcp:raw");

    // --- 1. nothing shared yet: the node is silent ---------------------------------------
    let began = Instant::now();
    let error = open(
        &principal,
        node.node_id,
        network_id,
        "tls:myapp",
        OpenMeta::default(),
    )
    .await
    .expect_err("a node with no accepted share answers no init");
    assert_eq!(error, PrincipalError::HandshakeTimeout);
    assert!(
        began.elapsed() >= HANDSHAKE,
        "the silence is waited out, not guessed: {:?}",
        began.elapsed()
    );
    assert_eq!(
        principal.session_count(),
        0,
        "a failed handshake leaves no session"
    );
    assert!(opens.lock().unwrap().is_empty());

    // --- 2. shared: bytes both ways, with the meta the node validated --------------------
    book.set_shares(vec![app_share.clone(), raw_share.clone()])
        .unwrap();
    until("both shares to be accepted", || {
        book.accepted_service(&app_share.service) && book.accepted_service(&raw_share.service)
    })
    .await;
    let good = meta("203.0.113.9", "myapp.menzil.test");
    let mut app_stream = open(&principal, node.node_id, network_id, "tls:myapp", good)
        .await
        .expect("a shared service opens");
    echo_round_trip(&mut app_stream, b"hello through the relay principal").await;
    // A megabyte, through a credit window an eighth of that.
    let big: Vec<u8> = (0..1usize << 20).map(|i| (i % 251) as u8).collect();
    timeout(PATIENCE, echo_round_trip(&mut app_stream, &big))
        .await
        .expect("one megabyte must cross a small credit window");
    let mut raw_stream = open(
        &principal,
        node.node_id,
        network_id,
        "tcp:raw",
        meta("not an address", "evil.example"),
    )
    .await
    .expect("a tcp: share opens on the same session");
    echo_round_trip(&mut raw_stream, b"raw bytes").await;
    assert_eq!(
        principal.session_count(),
        1,
        "one session per (node, network)"
    );
    {
        let seen = opens.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        for request in seen.iter() {
            assert_eq!(request.initiator, relay.id.node_id, "the relay principal");
            assert_eq!(request.network_id, network_id);
            assert!(request.target.is_none());
        }
        assert_eq!(seen[0].service, service("tls:myapp"));
        assert_eq!(seen[0].meta.client_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(seen[0].meta.sni.as_deref(), Some("myapp.menzil.test"));
        assert_eq!(seen[1].service, service("tcp:raw"));
        assert_eq!(seen[1].meta, OpenMeta::default(), "bad fields are dropped");
    }

    // --- 3. a service that was not shared is refused, and never connected to -------------
    match open(
        &principal,
        node.node_id,
        network_id,
        "tcp:secret",
        OpenMeta::default(),
    )
    .await
    {
        Err(PrincipalError::Refused { code, .. }) => assert_eq!(code, ErrorCode::NoGrant),
        other => panic!("an unshared service must be refused no_grant, got {other:?}"),
    }
    // Neither the handler nor the target saw it (give a wrongly connected target time to show).
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(secret_connections.load(Ordering::SeqCst), 0);
    assert_eq!(opens.lock().unwrap().len(), 2, "the handler never saw it");
    // The refusal costs the session nothing.
    echo_round_trip(&mut app_stream, b"still open").await;

    // --- 4. withdrawing a share resets its stream, not the other share's -----------------
    book.set_shares(vec![raw_share.clone()]).unwrap();
    expect_reset(
        &mut app_stream,
        Duration::from_secs(15),
        "the withdrawn share's stream",
    )
    .await;
    assert!(
        matches!(
            local_target_ended(&mut app_ended, "the withdrawn share").await,
            Err(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        ),
        "the target sees the reset"
    );
    until("the node to hold only raw", || {
        !book.accepted_service(&app_share.service)
    })
    .await;
    echo_round_trip(&mut raw_stream, b"the other share is untouched").await;
    match open(
        &principal,
        node.node_id,
        network_id,
        "tls:myapp",
        OpenMeta::default(),
    )
    .await
    {
        Err(PrincipalError::Refused { code, .. }) => assert_eq!(code, ErrorCode::NoGrant),
        other => panic!("a withdrawn share must be refused no_grant, got {other:?}"),
    }
    assert_eq!(
        principal.session_count(),
        1,
        "the session stays for the share left"
    );
    // Share it again for the rest.
    book.set_shares(vec![app_share.clone(), raw_share.clone()])
        .unwrap();
    until("myapp to be accepted again", || {
        book.accepted_service(&app_share.service)
    })
    .await;

    // --- 5. an L3 reconnect ends the session; the next open starts a fresh one -----------
    let epoch1 = started
        .wait_attached(Duration::from_secs(5))
        .await
        .expect("attached");
    let usurper = Session::connect(&session_config, &HashMap::new(), rosters.clone())
        .await
        .unwrap();
    drop(usurper);
    // The principal looks at the node's attachment every 50 ms tick: a few seconds is generous.
    expect_reset(
        &mut raw_stream,
        Duration::from_secs(5),
        "the stream of the ended L3 attachment",
    )
    .await;
    assert!(
        matches!(
            local_target_ended(&mut raw_ended, "the ended attachment").await,
            Err(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        ),
        "the target sees the reset"
    );
    until(
        "the principal to drop the session of the old attachment",
        || principal.session_count() == 0,
    )
    .await;
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
    // Gated on what the relay holds, as the front door will be (it routes a name only to the holder
    // of its claim), not on the node's own ACK: the relay writes ADVERTISE_ACK before it serves
    // the next frame of that attachment, so an `init` sent after the claims exist reaches a node
    // that already knows its shares are accepted.
    until("the relay to hold the claims again", || {
        relay.relay.labels().shares_for(&node.node_id).len() == 2
    })
    .await;
    let mut again = open(
        &principal,
        node.node_id,
        network_id,
        "tcp:raw",
        meta("2001:db8::1", "raw.menzil.test"),
    )
    .await
    .expect("a fresh session after the reconnect");
    echo_round_trip(&mut again, b"after the reconnect").await;
    assert_eq!(principal.session_count(), 1);
    {
        let seen = opens.lock().unwrap();
        let last = seen.last().unwrap();
        assert_eq!(last.service, service("tcp:raw"));
        assert_eq!(last.meta.client_ip.as_deref(), Some("2001:db8::1"));
    }
    again.close().await.unwrap();
    assert_eq!(
        local_target_ended(&mut raw_ended, "a closed stream").await,
        Ok(()),
        "a clean close reaches the target as an end of file"
    );

    started.shutdown().await;
}
