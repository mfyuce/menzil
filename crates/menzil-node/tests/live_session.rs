//! Live end-to-end tests of [`menzil_node::run_session`] (TODO.md L4b): a
//! real in-process `menzil_relay::Relay` over real TLS, WebSocket, and
//! Noise, dialed through the real, unmodified `menzil_carrier::Carrier::dial`
//! — the platform certificate verifier included, not a test connector.
//!
//! How a test certificate gets trusted: `rustls-platform-verifier` on
//! Linux loads its roots through `rustls-native-certs`, which documents
//! that it reads the PEM file named by `SSL_CERT_FILE` *instead of* the
//! system bundle when that variable is set. [`trust_test_certificate`]
//! writes a freshly generated self-signed certificate to a temp file and
//! points `SSL_CERT_FILE` at it for this test process only. That is
//! Linux-specific (the macOS and Windows verifiers ignore the variable),
//! hence the `cfg` below; CI runs tests on Linux only.
//!
//! Why this file holds exactly one `#[tokio::test]`, running each scenario
//! in turn: `std::env::set_var` is only sound while no other thread can be
//! reading the environment. libtest runs separate tests on separate
//! threads concurrently, so a second test in this binary could race the
//! first one's `set_var`. With one test on a current-thread runtime, the
//! variable is set before any other thread (runtime worker, blocking pool,
//! or another test) exists. Add a new scenario as another `async fn`
//! called from [`run_session_over_a_live_relay`], not as a new test.
//!
//! What is covered, and why here rather than in `outbound`'s own unit
//! tests: `run_session`'s select loop itself (finding 5 of TODO.md L4b's
//! review) has no other test at all, and the wire order a peer actually
//! observes (finding 1) is not pinned by `outbound`'s own regression test
//! for it either: as written, that test's credit covers the earlier item,
//! so it still passes with the per-destination ordering fix reverted.
//! Readiness is detected by probing through the relay (a record only
//! arrives once both ends are attached), never by reading logs.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use menzil_carrier::{ConnectionInfo, DialConfig, ProxyOverride};
use menzil_node::{LocalIdentity, OutboundSend, RosterStore, SessionConfig, run_session};
use menzil_proto::{
    Limits, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, Record, Roster,
    RosterBody, RosterMember, X25519PublicKey,
};
use menzil_relay::{Listener, Relay, RelayIdentity, server_config};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Generous: nothing here is expected to take more than a second or two,
/// but CI machines can be slow and a false failure is worse than a slow
/// true one.
const PATIENCE: Duration = Duration::from_secs(15);

/// A self-signed certificate for `localhost`, trusted by this process's
/// platform verifier through `SSL_CERT_FILE` (see this file's own doc
/// comment for why that is sound only in a single-test binary).
struct TestTrust {
    chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
    pem_path: std::path::PathBuf,
}

fn trust_test_certificate() -> TestTrust {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let pem_path = std::env::temp_dir().join(format!(
        "menzil-node-live-session-{}.pem",
        std::process::id()
    ));
    std::fs::write(&pem_path, cert.pem()).unwrap();
    // SAFETY: this is the first thing the only test in this binary does,
    // on a current-thread runtime, before any dial (and so before any
    // blocking-pool thread) exists: nothing else can be reading the
    // environment concurrently. See this file's own doc comment.
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

/// A served relay, plus what a node needs to dial it.
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

/// Seeds one Roster listing every member of `members`, so any two of them
/// may forward to each other through `relay`.
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

/// Runs [`run_session`] for `id` against `relay`, with the caller's ends
/// of its `events` and `outbound` channels handed in and out explicitly so
/// a test can size them, or pre-fill `outbound` before the node dials.
fn spawn_node(
    relay: &TestRelay,
    id: &Identity,
    network_id: NetworkId,
    events: mpsc::Sender<Record>,
    outbound: mpsc::Receiver<OutboundSend>,
) -> tokio::task::JoinHandle<()> {
    let config = SessionConfig {
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
    };
    tokio::spawn(run_session(
        config,
        HashMap::new(),
        events,
        outbound,
        Arc::new(RosterStore::new()),
    ))
}

fn reliable(dst: NodeId, payload: Vec<u8>) -> OutboundSend {
    OutboundSend {
        dst,
        e2e_proto: 0x01,
        flags: 0x00,
        payload,
    }
}

/// The next RECV on `events` from `src`, skipping anything else (a probe
/// from someone else, an ERROR); `None` if none arrives within [`PATIENCE`].
async fn next_recv_from(events: &mut mpsc::Receiver<Record>, src: NodeId) -> Option<Vec<u8>> {
    timeout(PATIENCE, async {
        loop {
            match events.recv().await? {
                Record::Recv {
                    src: from, payload, ..
                } if from == src => return Some(payload),
                _ => {}
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Waits until a record from `from` actually reaches `to` through the
/// relay — proof both are attached and routable — by sending a small
/// probe every 100 ms (one sent before `to` attaches is refused, not
/// queued) until one arrives, then discards anything else already queued.
async fn wait_until_routable(
    from_outbound: &mpsc::Sender<OutboundSend>,
    from: NodeId,
    to_events: &mut mpsc::Receiver<Record>,
    to: NodeId,
) {
    let probed = timeout(PATIENCE, async {
        loop {
            from_outbound
                .send(reliable(to, b"probe".to_vec()))
                .await
                .unwrap();
            if let Ok(Some(Record::Recv { src, .. })) =
                timeout(Duration::from_millis(100), to_events.recv()).await
                && src == from
            {
                return;
            }
        }
    })
    .await;
    assert!(probed.is_ok(), "the two nodes never became routable");
    tokio::time::sleep(Duration::from_millis(200)).await;
    while to_events.try_recv().is_ok() {}
}

#[tokio::test]
async fn run_session_over_a_live_relay() {
    let trust = trust_test_certificate();
    reliable_sends_to_one_peer_arrive_in_the_order_they_were_queued(&trust).await;
    a_caller_that_both_reads_events_and_writes_outbound_cannot_deadlock(&trust).await;
}

/// Regression test for TODO.md L4b's review, finding 1, at the wire: with
/// credit (100_000) that covers a later, smaller item (100 bytes) but not
/// an earlier, larger one (50_000, once 60_000 is already in flight), the
/// peer must still receive the three in the order they were queued — not
/// the smaller one first. Pre-filling `outbound` before the sender even
/// dials makes all three reach its queue before any CREDIT can return.
async fn reliable_sends_to_one_peer_arrive_in_the_order_they_were_queued(trust: &TestTrust) {
    let relay = start_relay(trust, 100_000).await;
    let (sender, receiver, prober) = (identity(), identity(), identity());
    let network_id = seed_roster(&relay, &[&sender, &receiver, &prober]);

    let (receiver_events_tx, mut receiver_events) = mpsc::channel(64);
    let (_receiver_outbound, receiver_outbound_rx) = mpsc::channel(64);
    let receiver_task = spawn_node(
        &relay,
        &receiver,
        network_id,
        receiver_events_tx,
        receiver_outbound_rx,
    );
    let (prober_events_tx, _prober_events) = mpsc::channel(64);
    let (prober_outbound, prober_outbound_rx) = mpsc::channel(64);
    let prober_task = spawn_node(
        &relay,
        &prober,
        network_id,
        prober_events_tx,
        prober_outbound_rx,
    );
    wait_until_routable(
        &prober_outbound,
        prober.node_id,
        &mut receiver_events,
        receiver.node_id,
    )
    .await;

    let (sender_events_tx, _sender_events) = mpsc::channel(64);
    let (sender_outbound, sender_outbound_rx) = mpsc::channel(64);
    for (tag, len) in [(0u8, 60_000), (1, 50_000), (2, 100)] {
        sender_outbound
            .send(reliable(receiver.node_id, vec![tag; len]))
            .await
            .unwrap();
    }
    let sender_task = spawn_node(
        &relay,
        &sender,
        network_id,
        sender_events_tx,
        sender_outbound_rx,
    );

    let mut order = Vec::new();
    for _ in 0..3 {
        let payload = next_recv_from(&mut receiver_events, sender.node_id)
            .await
            .expect("all three reliable sends must arrive");
        order.push(payload[0]);
    }
    assert_eq!(
        order,
        vec![0, 1, 2],
        "reliable sends to one peer were reordered"
    );

    for task in [sender_task, receiver_task, prober_task] {
        task.abort();
    }
}

/// Regression test for TODO.md L4b's review, finding 5: a caller whose one
/// task both reads `events` and writes `outbound` (the natural shape for
/// anything that replies to what it receives), with both channels at
/// capacity 1. Records for it are already waiting when it starts, and it
/// writes several outbound sends before reading any of them. A
/// `run_session` that awaited `events.send()` inside its select would stop
/// draining `outbound` while that send is stuck, and the caller's second
/// `outbound` write would then never complete: a permanent hang.
async fn a_caller_that_both_reads_events_and_writes_outbound_cannot_deadlock(trust: &TestTrust) {
    let relay = start_relay(trust, 1_048_576).await;
    let (caller, peer) = (identity(), identity());
    let network_id = seed_roster(&relay, &[&caller, &peer]);

    let (caller_events_tx, mut caller_events) = mpsc::channel(1);
    let (caller_outbound, caller_outbound_rx) = mpsc::channel(1);
    let caller_task = spawn_node(
        &relay,
        &caller,
        network_id,
        caller_events_tx,
        caller_outbound_rx,
    );
    let (peer_events_tx, mut peer_events) = mpsc::channel(64);
    let (peer_outbound, peer_outbound_rx) = mpsc::channel(64);
    let peer_task = spawn_node(&relay, &peer, network_id, peer_events_tx, peer_outbound_rx);
    wait_until_routable(
        &peer_outbound,
        peer.node_id,
        &mut caller_events,
        caller.node_id,
    )
    .await;

    for i in 0..4u8 {
        peer_outbound
            .send(reliable(caller.node_id, vec![0xB0 + i; 1_000]))
            .await
            .unwrap();
    }
    // Let those arrive and back up against `caller_events`' capacity of 1.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let peer_id = peer.node_id;
    let caller_loop = async move {
        for i in 0..4u8 {
            caller_outbound
                .send(reliable(peer_id, vec![0xA0 + i; 1_000]))
                .await
                .unwrap();
        }
        let mut received = Vec::new();
        while received.len() < 4 {
            match caller_events.recv().await {
                Some(Record::Recv { src, payload, .. }) if src == peer_id => {
                    received.push(payload[0])
                }
                Some(_) => {}
                None => break,
            }
        }
        received
    };
    let received = timeout(PATIENCE, caller_loop)
        .await
        .expect("run_session stopped draining `outbound` while a delivery was stuck: deadlock");
    assert_eq!(received, vec![0xB0, 0xB1, 0xB2, 0xB3]);

    let mut delivered = Vec::new();
    for _ in 0..4 {
        let payload = next_recv_from(&mut peer_events, caller.node_id)
            .await
            .expect("the caller's own sends must also get through");
        delivered.push(payload[0]);
    }
    assert_eq!(delivered, vec![0xA0, 0xA1, 0xA2, 0xA3]);

    caller_task.abort();
    peer_task.abort();
}
