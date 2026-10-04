//! Regression tests for the two bugs an opus red-team review's second
//! round found in TODO.md L4h1's own first-round fix (its first round
//! found the original deadlock this item's own `run_session` doc
//! comment now describes): neither is distinguishable from the
//! original, buggy code by `live_session.rs`'s own existing scenarios,
//! which this file's own [`Proxy`] exists to close.
//!
//! 1. A detach-triggered deadlock: `run_session`'s post-detach drain ran
//!    `events.reserve().await` with nothing else running concurrently;
//!    if `events`'s buffer already held an unread item, that blocked
//!    forever, and with nothing left draining `outbound` either, a
//!    caller blocked writing a full `outbound` never completed either.
//! 2. An `OutboundSend`'s `outcome` left unresolved for the whole
//!    reconnect gap rather than resolved promptly *during* it: neither
//!    `Session::connect` nor the backoff sleep between failed attempts
//!    serviced `outbound` at all.
//!
//! `live_session.rs`'s own reconnect test forces a detach via a second,
//! raw `Session::connect` under the same identity, which `menzil-relay`
//! supersedes with `retry_after_ms: 0` while the relay itself stays up —
//! too fast and too forgiving a gap to tell either bug apart from its
//! fix. [`Proxy`] forces a hard, proxy-killed disconnect (no GOAWAY, no
//! graceful anything) and, separately, a chosen number of outright
//! refused dial attempts, each one a real `Backoff`-driven sleep to
//! flood stale sends into.
//!
//! A second, separate `#[tokio::test]` binary, not folded into
//! `live_session.rs`: that file's own `SSL_CERT_FILE` mutation is sound
//! only with exactly one test per *process* (see its own doc comment),
//! and `cargo test` already runs each `tests/*.rs` file as its own
//! process, so this file needs no coordination with it — only the same
//! single-test discipline, applied again on its own.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use menzil_carrier::{ConnectionInfo, DialConfig, ProxyOverride};
use menzil_node::{
    EnqueueOutcome, Epoch, LocalIdentity, OutboundSend, RosterStore, SessionConfig, SessionEvent,
    run_session,
};
use menzil_proto::{
    Limits, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, Roster, RosterBody,
    RosterMember, X25519PublicKey,
};
use menzil_relay::{Listener, Relay, RelayIdentity, server_config};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(20);

struct TestTrust {
    chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
    pem_path: std::path::PathBuf,
}

fn trust_test_certificate() -> TestTrust {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let pem_path = std::env::temp_dir().join(format!(
        "menzil-node-epoch-resilience-{}.pem",
        std::process::id()
    ));
    std::fs::write(&pem_path, cert.pem()).unwrap();
    // SAFETY: see live_session.rs's own identical doc comment — this
    // file is a separate test binary (its own process), so it carries
    // no race with that file's own `set_var` call.
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

struct Identity {
    signing: SigningKey,
    node_id: NodeId,
    x25519_private: [u8; 32],
    x25519_public: X25519PublicKey,
}

fn identity() -> Identity {
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

fn node_cert(id: &Identity) -> NodeCert {
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

struct TestRelay {
    relay: Relay,
    addr: SocketAddr,
    id: Identity,
}

async fn start_relay(trust: &TestTrust, credit: u32) -> TestRelay {
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
    TestRelay { relay, addr, id }
}

fn seed_roster(relay: &TestRelay, members: &[&Identity]) -> NetworkId {
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
    relay
        .relay
        .rosters()
        .set(&Roster::sign(&owner, &body).unwrap())
        .unwrap();
    network_id
}

fn session_config_port(
    relay: &TestRelay,
    id: &Identity,
    network_id: NetworkId,
    port: u16,
) -> SessionConfig {
    SessionConfig {
        dial: DialConfig {
            connection_info: ConnectionInfo {
                host: "localhost".to_string(),
                port,
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

fn spawn_node_port(
    relay: &TestRelay,
    id: &Identity,
    network_id: NetworkId,
    port: u16,
    events: mpsc::Sender<SessionEvent>,
    outbound: mpsc::Receiver<OutboundSend>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_session(
        session_config_port(relay, id, network_id, port),
        HashMap::new(),
        events,
        outbound,
        Arc::new(RosterStore::new()),
    ))
}

fn with_outcome(
    dst: NodeId,
    epoch: Epoch,
    payload: Vec<u8>,
) -> (OutboundSend, oneshot::Receiver<EnqueueOutcome>) {
    let (outcome, rx) = oneshot::channel();
    (
        OutboundSend {
            dst,
            e2e_proto: 0x01,
            flags: 0x00,
            payload,
            epoch,
            outcome,
        },
        rx,
    )
}

async fn wait_attached(events: &mut mpsc::Receiver<SessionEvent>) -> Epoch {
    timeout(PATIENCE, async {
        loop {
            match events.recv().await {
                Some(SessionEvent::Attached { epoch, .. }) => return epoch,
                Some(_) => {}
                None => panic!("events closed while waiting for Attached"),
            }
        }
    })
    .await
    .expect("timed out waiting for Attached")
}

/// A controllable TCP proxy in front of the relay: refuses the first
/// `refuse_first` connections outright (accept, then close at once — a
/// real, fast-failing dial, forcing a real `Backoff` sleep), forwards
/// every connection after that, and [`Proxy::kill_all`] drops every
/// currently-forwarding connection at once (a hard disconnect, not a
/// graceful GOAWAY).
struct Proxy {
    port: u16,
    kill: Arc<Notify>,
}

impl Proxy {
    async fn start(upstream: SocketAddr, refuse_first: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let refuse_first = Arc::new(AtomicUsize::new(refuse_first));
        let kill = Arc::new(Notify::new());
        let kill_for_task = Arc::clone(&kill);
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let refuse_now = refuse_first
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok();
                let kill_for_conn = Arc::clone(&kill_for_task);
                tokio::spawn(async move {
                    if refuse_now {
                        drop(client);
                        return;
                    }
                    let Ok(mut up) = TcpStream::connect(upstream).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut up) => {}
                        _ = kill_for_conn.notified() => {}
                    }
                });
            }
        });
        Proxy { port, kill }
    }

    fn kill_all(&self) {
        self.kill.notify_waiters();
    }
}

#[tokio::test]
async fn epoch_resilience() {
    let trust = trust_test_certificate();
    a_detach_with_a_caller_blocked_on_outbound_does_not_deadlock(&trust).await;
    stale_sends_are_refused_promptly_through_a_real_backoff_wait(&trust).await;
}

/// Round one's own finding 1, reproduced at the exact shape it was
/// found in: `events` and `outbound` both capacity 1, one event already
/// sitting unread in `events` when the attachment ends (`proxy.kill_all`
/// — a hard disconnect, not GOAWAY, which leaves no real gap to get
/// stuck in), and the caller's own task writing several sends into
/// `outbound` before it ever reads `events` again.
async fn a_detach_with_a_caller_blocked_on_outbound_does_not_deadlock(trust: &TestTrust) {
    let relay = start_relay(trust, 1_048_576).await;
    let (node, peer) = (identity(), identity());
    let network_id = seed_roster(&relay, &[&node, &peer]);
    let proxy = Proxy::start(relay.addr, 0).await;

    let (node_events_tx, mut node_events) = mpsc::channel(1);
    let (node_outbound, node_outbound_rx) = mpsc::channel(1);
    let node_task = spawn_node_port(
        &relay,
        &node,
        network_id,
        proxy.port,
        node_events_tx,
        node_outbound_rx,
    );
    let (peer_events_tx, mut peer_events) = mpsc::channel(64);
    let (peer_outbound, peer_outbound_rx) = mpsc::channel(64);
    let peer_task = spawn_node_port(
        &relay,
        &peer,
        network_id,
        relay.addr.port(),
        peer_events_tx,
        peer_outbound_rx,
    );

    let epoch1 = wait_attached(&mut node_events).await;
    let peer_epoch = wait_attached(&mut peer_events).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // One record from `peer`, deliberately left unread: fills
    // `node_events`'s one slot and stays there.
    let (hello, _hello_outcome) = with_outcome(node.node_id, peer_epoch, b"hello".to_vec());
    peer_outbound.send(hello).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    proxy.kill_all();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let peer_id = peer.node_id;
    let caller_loop = async move {
        let mut outcomes = Vec::new();
        for i in 0..4u8 {
            let (req, rx) = with_outcome(peer_id, epoch1, vec![0xA0 + i]);
            node_outbound.send(req).await.unwrap();
            outcomes.push(rx);
        }
        let (mut saw_detached, mut saw_attached) = (false, false);
        while !(saw_detached && saw_attached) {
            match node_events.recv().await {
                Some(SessionEvent::Detached { .. }) => saw_detached = true,
                Some(SessionEvent::Attached { .. }) => saw_attached = true,
                Some(_) => {}
                None => break,
            }
        }
        outcomes
    };
    let outcomes = timeout(PATIENCE, caller_loop)
        .await
        .expect("a detach must not deadlock a caller blocked writing outbound against events");
    for rx in outcomes {
        let outcome = timeout(Duration::from_secs(2), rx)
            .await
            .expect("every queued send's outcome must eventually resolve too")
            .unwrap();
        assert_eq!(outcome, EnqueueOutcome::WrongEpoch);
    }

    node_task.abort();
    peer_task.abort();
}

/// Round one's own finding 2: an `OutboundSend`'s `outcome` must resolve
/// promptly *during* an actual reconnect gap — including a real backoff
/// wait between failed dial attempts — not only once this node finally
/// reattaches. `Proxy::start`'s `refuse_first: 2` forces two real failed
/// connect attempts, hence two real `Backoff` sleeps, before the third
/// succeeds.
async fn stale_sends_are_refused_promptly_through_a_real_backoff_wait(trust: &TestTrust) {
    let relay = start_relay(trust, 1_048_576).await;
    let (node, peer) = (identity(), identity());
    let network_id = seed_roster(&relay, &[&node, &peer]);
    let proxy = Proxy::start(relay.addr, 2).await;

    let (node_events_tx, mut node_events) = mpsc::channel(64);
    let (node_outbound, node_outbound_rx) = mpsc::channel(4);
    let node_task = spawn_node_port(
        &relay,
        &node,
        network_id,
        proxy.port,
        node_events_tx,
        node_outbound_rx,
    );

    let epoch1 = wait_attached(&mut node_events).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    proxy.kill_all();
    // Let the detach actually land inside `run_session` (epoch bumped)
    // before flooding: a send genuinely tagged `epoch1` while `epoch1`
    // is still current is legitimately `Accepted`, not a bug.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
    let peer_id = peer.node_id;
    let flood = tokio::spawn(async move {
        let mut max_latency = Duration::ZERO;
        let mut all_wrong_epoch = true;
        loop {
            let (req, rx) = with_outcome(peer_id, epoch1, b"stale".to_vec());
            let sent = Instant::now();
            if node_outbound.send(req).await.is_err() {
                break;
            }
            match timeout(Duration::from_secs(5), rx).await {
                Ok(Ok(outcome)) => {
                    max_latency = max_latency.max(sent.elapsed());
                    if outcome != EnqueueOutcome::WrongEpoch {
                        all_wrong_epoch = false;
                    }
                }
                _ => all_wrong_epoch = false,
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(5)) => {}
                _ = &mut stop_rx => break,
            }
        }
        (max_latency, all_wrong_epoch)
    });

    let epoch2 = wait_attached(&mut node_events).await;
    assert!(epoch2 > epoch1, "must reattach under a new epoch");
    let _ = stop_tx.send(());
    let (max_latency, all_wrong_epoch) = flood.await.unwrap();

    assert!(
        all_wrong_epoch,
        "every send tagged for the epoch that just ended must be refused with WrongEpoch throughout the whole reconnect gap"
    );
    assert!(
        max_latency < Duration::from_millis(500),
        "a stale send's outcome must resolve promptly even during a real backoff wait between failed dial attempts, took {max_latency:?}"
    );

    node_task.abort();
}
