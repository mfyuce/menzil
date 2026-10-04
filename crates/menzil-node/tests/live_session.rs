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
use menzil_node::{
    EnqueueOutcome, Epoch, LocalIdentity, OutboundSend, RosterStore, Session, SessionConfig,
    SessionEvent, run_session,
};
use menzil_proto::{
    Limits, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, Record, Roster,
    RosterBody, RosterMember, X25519PublicKey,
};
use menzil_relay::{Listener, Relay, RelayIdentity, server_config};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{mpsc, oneshot};
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

/// Everything [`Session::connect`] or [`spawn_node`] needs to dial
/// `relay` as `id`, claiming `network_id`; split out of [`spawn_node`]
/// so a test can also drive a raw, second [`Session::connect`] under the
/// same identity (to force a supersede-triggered reconnect) without
/// duplicating this.
fn session_config(relay: &TestRelay, id: &Identity, network_id: NetworkId) -> SessionConfig {
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

/// Runs [`run_session`] for `id` against `relay`, with the caller's ends
/// of its `events` and `outbound` channels handed in and out explicitly so
/// a test can size them, or pre-fill `outbound` before the node dials.
fn spawn_node(
    relay: &TestRelay,
    id: &Identity,
    network_id: NetworkId,
    events: mpsc::Sender<SessionEvent>,
    outbound: mpsc::Receiver<OutboundSend>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_session(
        session_config(relay, id, network_id),
        HashMap::new(),
        events,
        outbound,
        Arc::new(RosterStore::new()),
    ))
}

/// `epoch` is [`Epoch::first`] for a send queued before `dst`'s very
/// first attachment, or whatever epoch a prior [`SessionEvent::Attached`]
/// reported. The admission outcome is resolved to nobody — see
/// [`reliable_with_outcome`] for a test that wants to inspect it.
fn reliable(dst: NodeId, epoch: Epoch, payload: Vec<u8>) -> OutboundSend {
    let (outcome, _rx) = oneshot::channel();
    OutboundSend {
        dst,
        e2e_proto: 0x01,
        flags: 0x00,
        payload,
        epoch,
        outcome,
    }
}

/// Like [`reliable`], but also hands back the receiving half of this
/// send's admission outcome.
fn reliable_with_outcome(
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

/// The next RECV on `events` from `src`, skipping anything else (a probe
/// from someone else, an ERROR) *and* a literal `b"probe"` payload from
/// `src` itself — `wait_until_routable`'s own probes share `src` with
/// whatever real payload a test sends right after it, and its cleanup
/// drain can only ever clear what is already sitting in `events`' own
/// buffer, not whatever is still upstream in the prober's `outbound`
/// queue or in flight; those trickle in later, well after cleanup, and
/// would otherwise read back as real data here. `None` if nothing
/// besides probes arrives within [`PATIENCE`].
async fn next_recv_from(events: &mut mpsc::Receiver<SessionEvent>, src: NodeId) -> Option<Vec<u8>> {
    timeout(PATIENCE, async {
        loop {
            if let SessionEvent::Record { record, .. } = events.recv().await?
                && let Record::Recv {
                    src: from, payload, ..
                } = *record
                && from == src
                && payload != b"probe"
            {
                return Some(payload);
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
    to_events: &mut mpsc::Receiver<SessionEvent>,
    to: NodeId,
) {
    let probed = timeout(PATIENCE, async {
        loop {
            from_outbound
                .send(reliable(to, Epoch::first(), b"probe".to_vec()))
                .await
                .unwrap();
            if let Ok(Some(SessionEvent::Record { record, .. })) =
                timeout(Duration::from_millis(100), to_events.recv()).await
                && let Record::Recv { src, .. } = *record
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
    a_reconnect_gets_a_fresh_epoch_and_refuses_a_stale_tagged_send(&trust).await;
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
            .send(reliable(receiver.node_id, Epoch::first(), vec![tag; len]))
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
///
/// Also where TODO.md's own long-flaky `live_session.rs` entry traced
/// its root cause: `wait_until_routable` must probe *from* `peer` here
/// (not a dedicated third identity, unlike the order test above) to
/// prove `peer` itself, not just `caller`, is attached before the real
/// payload below is queued. `caller_events`' own capacity of 1 means its
/// cleanup drain can only ever clear the single probe already sitting in
/// that one slot; every earlier probe `wait_until_routable`'s loop also
/// sent is still upstream at that point — queued in `peer`'s own
/// `outbound`, mid-network, or mid-decrypt on `caller`'s side — and
/// trickles in one at a time well *after* cleanup has already returned,
/// landing in this very loop with the same `src` as the real payload,
/// read back as `[112, ...]` (`b'p'`) instead of `0xB0..`. Fixed by
/// filtering the literal probe payload out of `received` below, the fix
/// this item's own TODO line named as the alternative to a separate
/// prober identity; live A/B verified under artificial load (opus
/// red-team review of this item, 2026-10-04): an unfiltered copy of this
/// test failed 19 of 24 runs with exactly this shape, the shipped,
/// filtered version 15 of 15.
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
            .send(reliable(
                caller.node_id,
                Epoch::first(),
                vec![0xB0 + i; 1_000],
            ))
            .await
            .unwrap();
    }
    // Let those arrive and back up against `caller_events`' capacity of 1.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let peer_id = peer.node_id;
    let caller_loop = async move {
        for i in 0..4u8 {
            caller_outbound
                .send(reliable(peer_id, Epoch::first(), vec![0xA0 + i; 1_000]))
                .await
                .unwrap();
        }
        let mut received = Vec::new();
        while received.len() < 4 {
            match caller_events.recv().await {
                Some(SessionEvent::Record { record, .. }) => {
                    if let Record::Recv { src, payload, .. } = *record
                        && src == peer_id
                        && payload != b"probe"
                    {
                        received.push(payload[0]);
                    }
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

/// Regression test for TODO.md L4h1: a fresh attachment's epoch is
/// surfaced to the caller, in order, strictly before any record from it;
/// a reconnect gets the next epoch, never a repeat of the last one; and
/// an `OutboundSend` tagged for an epoch that is no longer current is
/// refused with `EnqueueOutcome::WrongEpoch`, promptly, *during* the
/// reconnect gap itself (not only once reattached) — the exact gap this
/// item closes ("a send queued during a reconnect goes out on the next
/// L3 session"). A send tagged for the new epoch is then shown to
/// actually go through, as the positive control: were the refusal above
/// not real (a stale send silently reaching `peer` anyway), it was
/// queued first and would arrive first, so this would observe it instead
/// of the fresh payload. The reconnect itself is forced the same way
/// `menzil-relay`'s own `session_tests.rs` already proves reliable: a
/// second, raw `Session::connect` under the identical identity
/// supersedes the first, which the relay ends with GOAWAY.
async fn a_reconnect_gets_a_fresh_epoch_and_refuses_a_stale_tagged_send(trust: &TestTrust) {
    let relay = start_relay(trust, 100_000).await;
    let (node, peer) = (identity(), identity());
    let network_id = seed_roster(&relay, &[&node, &peer]);

    let (node_events_tx, mut node_events) = mpsc::channel(64);
    let (node_outbound, node_outbound_rx) = mpsc::channel(64);
    let node_task = spawn_node(&relay, &node, network_id, node_events_tx, node_outbound_rx);
    let (peer_events_tx, mut peer_events) = mpsc::channel(64);
    let (_peer_outbound, peer_outbound_rx) = mpsc::channel(64);
    let peer_task = spawn_node(&relay, &peer, network_id, peer_events_tx, peer_outbound_rx);

    let (epoch1, limits) = match timeout(PATIENCE, node_events.recv()).await {
        Ok(Some(SessionEvent::Attached { epoch, limits })) => (epoch, limits),
        other => panic!("expected Attached as the very first event, got {other:?}"),
    };
    assert_eq!(epoch1, Epoch::first());
    assert!(
        limits.max_record > 0,
        "WELCOME's own limits must actually reach the caller"
    );
    wait_until_routable(&node_outbound, node.node_id, &mut peer_events, peer.node_id).await;

    let usurper = Session::connect(
        &session_config(&relay, &node, network_id),
        &HashMap::new(),
        Arc::new(RosterStore::new()),
    )
    .await
    .unwrap();
    drop(usurper);

    loop {
        match timeout(PATIENCE, node_events.recv()).await {
            Ok(Some(SessionEvent::Detached { epoch })) => {
                assert_eq!(
                    epoch, epoch1,
                    "must detach from the epoch it was attached to"
                );
                break;
            }
            Ok(Some(_)) => continue,
            other => panic!("expected Detached after being superseded, got {other:?}"),
        }
    }

    // Queued right in the reconnect gap, strictly before the new epoch's
    // own `Attached` is even observed.
    let (stale, stale_outcome) = reliable_with_outcome(peer.node_id, epoch1, b"stale".to_vec());
    node_outbound.send(stale).await.unwrap();
    assert_eq!(
        stale_outcome.await.unwrap(),
        EnqueueOutcome::WrongEpoch,
        "a send tagged for a past epoch must be refused during the reconnect gap itself"
    );

    let epoch2 = match timeout(PATIENCE, node_events.recv()).await {
        Ok(Some(SessionEvent::Attached { epoch, .. })) => epoch,
        other => panic!("expected a fresh Attached after reconnecting, got {other:?}"),
    };
    assert!(
        epoch2 > epoch1,
        "a reconnect must get a new epoch, never repeat the last one"
    );

    let fresh = reliable(peer.node_id, epoch2, b"fresh".to_vec());
    node_outbound.send(fresh).await.unwrap();
    let delivered = next_recv_from(&mut peer_events, node.node_id)
        .await
        .expect("a send tagged for the current epoch must actually be delivered");
    assert_eq!(delivered, b"fresh");

    node_task.abort();
    peer_task.abort();
}
