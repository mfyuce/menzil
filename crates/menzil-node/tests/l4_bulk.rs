//! Bulk transfer through two real L4 session actors, each attached to a
//! real in-process `menzil_relay::Relay` through the real
//! [`menzil_node::run_session`] (TODO.md L4h5): the whole send path at
//! once — `yamux`, `menzil-stream`'s outbound channel, the L4 actor,
//! `run_session`'s node-side `OutboundQueue`, the relay's credit — which
//! no single crate's own tests exercise together. This is the live
//! measurement L4h5's own TODO line asks for ("against both a
//! deliberately credit-starved relay and plain ordinary-load bulk
//! transfer"), kept as a regression test.
//!
//! What it pins: with 16 concurrent streams, the receive windows `yamux`
//! grants add up to 4 MiB, more than the node's send queue holds (3 MiB
//! per destination). Before the send budget (`SendBudget`), this ended
//! the sending session with `SendRefused(QueueFull)` and the receiver
//! with a counter-gap `Decrypt` error — measured live against a *healthy*
//! relay, not only a starved one: 0 of 32 streams arrived, sessions dead,
//! at 32 streams x 512 KiB. Both sessions must now survive, every byte
//! intact, whether the relay returns credit promptly or barely at all.
//!
//! The L4 Noise handshake itself is done directly in-process (the same
//! way `l5_stream.rs`'s own tests do); only the L4 *data* travels through
//! the relay, as epoch-tagged reliable SENDs, exactly as a running node
//! would send them.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly
//! one: `SSL_CERT_FILE` is process-global (see that file's own doc
//! comment). Scenarios are `async fn`s called from [`l4_bulk`].
//!
//! Runs in a debug build at roughly 0.5 MiB/s (unoptimized crypto, six
//! passes of it per byte across the two L4 and four L3 hops), so the
//! sizes are the smallest that still overflow the old queue; the same
//! transfer takes about half a second in a release build.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use futures_util::FutureExt;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_carrier::{ConnectionInfo, DialConfig, ProxyOverride};
use menzil_e2e::{E2eInitiatorHandshake, E2eResponderHandshake};
use menzil_node::{
    EndReason, Epoch, L4SessionAcceptor, L4SessionConfig, L4SessionHandle, LocalIdentity,
    OutboundSend, RosterStore, SendBudgets, SessionConfig, SessionEvent, new_l4_session,
    run_session,
};
use menzil_proto::{
    E2eFrame, Limits, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, Record, Roster,
    RosterBody, RosterMember, X25519PublicKey,
};
use menzil_relay::{Listener, Relay, RelayIdentity, server_config};
use menzil_stream::Mode;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(30);

struct TestTrust {
    chain: Vec<CertificateDer<'static>>,
    key_der: Vec<u8>,
    pem_path: std::path::PathBuf,
}

fn trust_test_certificate() -> TestTrust {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["localhost".to_string()]).unwrap();
    let pem_path =
        std::env::temp_dir().join(format!("menzil-node-l4-bulk-{}.pem", std::process::id()));
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
    addr: SocketAddr,
    id: Identity,
    relay: Relay,
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
    TestRelay { addr, id, relay }
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

/// One node: its identity, the channel its L4 actor will send through,
/// and its not-yet-consumed event stream.
struct Node {
    id: Identity,
    outbound: mpsc::Sender<OutboundSend>,
    events: mpsc::Receiver<SessionEvent>,
}

fn start_node(relay: &TestRelay, id: Identity, network_id: NetworkId) -> Node {
    let (events_tx, events) = mpsc::channel(1024);
    let (outbound, outbound_rx) = mpsc::channel(64);
    tokio::spawn(run_session(
        session_config(relay, &id, network_id),
        HashMap::new(),
        events_tx,
        outbound_rx,
        Arc::new(RosterStore::new()),
    ));
    Node {
        id,
        outbound,
        events,
    }
}

async fn wait_attached(events: &mut mpsc::Receiver<SessionEvent>) -> (Epoch, Limits) {
    timeout(PATIENCE, async {
        loop {
            match events.recv().await {
                Some(SessionEvent::Attached { epoch, limits }) => return (epoch, limits),
                Some(_) => {}
                None => panic!("events closed while waiting for Attached"),
            }
        }
    })
    .await
    .expect("timed out waiting for Attached")
}

/// A record from `from` actually reaching `to` through the relay proves
/// both are attached and routable (see `live_session.rs`).
async fn wait_until_routable(from: &Node, to: &mut Node) {
    let epoch = Epoch::first();
    let probed = timeout(PATIENCE, async {
        loop {
            let (outcome, _rx) = oneshot::channel();
            from.outbound
                .send(OutboundSend {
                    dst: to.id.node_id,
                    e2e_proto: 0x01,
                    flags: 0x00,
                    payload: b"probe".to_vec(),
                    epoch,
                    outcome,
                    permit: None,
                })
                .await
                .unwrap();
            if let Ok(Some(SessionEvent::Record { record, .. })) =
                timeout(Duration::from_millis(100), to.events.recv()).await
                && let Record::Recv { src, .. } = *record
                && src == from.id.node_id
            {
                return;
            }
        }
    })
    .await;
    assert!(probed.is_ok(), "the two nodes never became routable");
    tokio::time::sleep(Duration::from_millis(200)).await;
    while to.events.try_recv().is_ok() {}
}

/// Feeds every RECV from `peer` into `handle` (the in-process stand-in for
/// L4h6's demux) and fires `epoch_ended` on the first `Detached`.
fn spawn_demux(
    mut events: mpsc::Receiver<SessionEvent>,
    handle: L4SessionHandle,
    peer: NodeId,
    epoch_ended: oneshot::Sender<()>,
) {
    tokio::spawn(async move {
        let mut epoch_ended = Some(epoch_ended);
        while let Some(event) = events.recv().await {
            match event {
                SessionEvent::Record { record, .. } => {
                    if let Record::Recv { src, payload, .. } = *record
                        && src == peer
                        && let Ok(E2eFrame::Data {
                            counter,
                            ciphertext,
                            ..
                        }) = E2eFrame::decode(&payload)
                    {
                        handle.feed_inbound(counter, ciphertext);
                    }
                }
                SessionEvent::Detached { .. } => {
                    if let Some(tx) = epoch_ended.take() {
                        let _ = tx.send(());
                    }
                }
                SessionEvent::Attached { .. } => {}
            }
        }
    });
}

/// Two nodes attached to one relay with a live L4 session between them.
struct Pair {
    a: L4SessionHandle,
    a_acceptor: L4SessionAcceptor,
    b_acceptor: L4SessionAcceptor,
    _outbound: [mpsc::Sender<OutboundSend>; 2],
}

async fn live_pair(relay: &TestRelay) -> Pair {
    let a_id = identity();
    let b_id = identity();
    let network_id = seed_roster(relay, &[&a_id, &b_id]);
    let mut a = start_node(relay, a_id, network_id);
    let mut b = start_node(relay, b_id, network_id);

    let (a_epoch, a_limits) = wait_attached(&mut a.events).await;
    let (b_epoch, b_limits) = wait_attached(&mut b.events).await;
    wait_until_routable(&a, &mut b).await;

    let max_record = a_limits.max_record.min(b_limits.max_record);
    let (a_hs, init) = E2eInitiatorHandshake::start(
        &a.id.x25519_private,
        &b.id.x25519_public,
        network_id,
        a.id.node_id,
        b.id.node_id,
        1,
    )
    .unwrap();
    let b_hs =
        E2eResponderHandshake::start(&b.id.x25519_private, a.id.node_id, b.id.node_id, &init)
            .unwrap();
    let (b_transport, resp) = b_hs
        .finish(node_cert(&b.id), 0, 0, vec![], 2, max_record)
        .unwrap();
    let (a_transport, _payload, _b_static) = a_hs.finish(&resp, max_record).unwrap();

    let (a_end_tx, a_end_rx) = oneshot::channel();
    let (a_handle, a_acceptor, a_task) = new_l4_session(
        L4SessionConfig {
            transport: a_transport,
            peer: b.id.node_id,
            network_id,
            mode: Mode::Client,
            max_record,
            epoch: a_epoch,
            send_budget: SendBudgets::new().for_peer(b.id.node_id),
            observer: None,
        },
        a.outbound.clone(),
        a_end_rx,
    );
    let (b_end_tx, b_end_rx) = oneshot::channel();
    let (b_handle, b_acceptor, b_task) = new_l4_session(
        L4SessionConfig {
            transport: b_transport,
            peer: a.id.node_id,
            network_id,
            mode: Mode::Server,
            max_record,
            epoch: b_epoch,
            send_budget: SendBudgets::new().for_peer(a.id.node_id),
            observer: None,
        },
        b.outbound.clone(),
        b_end_rx,
    );
    tokio::spawn(a_task);
    tokio::spawn(b_task);
    spawn_demux(a.events, a_handle.clone(), b.id.node_id, a_end_tx);
    spawn_demux(b.events, b_handle, a.id.node_id, b_end_tx);

    Pair {
        a: a_handle,
        a_acceptor,
        b_acceptor,
        // `run_session` ends once every sender of its `outbound` channel
        // is gone; the L4 actors hold clones, but keeping these makes
        // that independent of the actors' own lifetimes.
        _outbound: [a.outbound, b.outbound],
    }
}

/// What one bulk-transfer run observed.
#[derive(Debug)]
struct Report {
    elapsed: Duration,
    /// Streams whose bytes arrived complete and correct.
    intact: usize,
    streams: usize,
    a_ended: Option<String>,
    b_ended: Option<String>,
}

fn payload(index: usize, len: usize) -> Vec<u8> {
    let mut data: Vec<u8> = (0..len).map(|pos| ((pos + index) % 251) as u8).collect();
    data[0] = index as u8;
    data
}

/// `streams` concurrent one-way transfers of `per_stream` bytes each, A to
/// B, over one live L4 session.
async fn bulk(relay: &TestRelay, streams: usize, per_stream: usize) -> Report {
    let Pair {
        a,
        mut a_acceptor,
        mut b_acceptor,
        _outbound,
    } = live_pair(relay).await;
    let started = Instant::now();

    let mut writers = Vec::new();
    for index in 0..streams {
        let Ok(mut stream) = a.open_stream().await else {
            break;
        };
        writers.push(tokio::spawn(async move {
            stream.write_all(&payload(index, per_stream)).await?;
            stream.close().await
        }));
    }

    let mut readers = Vec::new();
    for _ in 0..streams {
        match timeout(Duration::from_secs(5), b_acceptor.accept()).await {
            Ok(Some(mut stream)) => readers.push(tokio::spawn(async move {
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await.map(|_| buf)
            })),
            _ => break,
        }
    }

    let mut intact = 0;
    for reader in readers {
        if let Ok(Ok(Ok(buf))) = timeout(PATIENCE, reader).await
            && buf.len() == per_stream
            && buf == payload(buf[0] as usize, per_stream)
        {
            intact += 1;
        }
    }
    for writer in writers {
        let _ = timeout(Duration::from_secs(1), writer).await;
    }
    let elapsed = started.elapsed();

    let ended = |reason: Option<Arc<EndReason>>| reason.map(|r| format!("{r:?}"));
    Report {
        elapsed,
        intact,
        streams,
        a_ended: ended(a_acceptor.closed().now_or_never()),
        b_ended: ended(b_acceptor.closed().now_or_never()),
    }
}

/// 16 streams, each moving exactly one initial `yamux` window (256 KiB):
/// 4 MiB that all become eligible to send at once, against a 3 MiB
/// per-destination queue.
const STREAMS: usize = 16;
const PER_STREAM: usize = 256 * 1024;

fn assert_survived(scenario: &str, report: &Report) {
    assert_eq!(
        report.intact, report.streams,
        "{scenario}: every stream must arrive complete and correct: {report:#?}"
    );
    assert!(
        report.a_ended.is_none() && report.b_ended.is_none(),
        "{scenario}: neither session may end under ordinary bulk transfer: {report:#?}"
    );
}

#[tokio::test]
async fn l4_bulk() {
    let trust = trust_test_certificate();

    // Plain ordinary-load bulk transfer over a healthy relay (WELCOME's
    // default 1 MiB credit, protocol.md 4.1).
    let relay = start_relay(&trust, 1 << 20).await;
    let report = bulk(&relay, STREAMS, PER_STREAM).await;
    eprintln!(
        "healthy relay, {STREAMS} x {PER_STREAM} B: {:?}",
        report.elapsed
    );
    assert_survived("healthy relay", &report);

    // A deliberately credit-starved relay: 64 KiB of credit, so the node's
    // queue stays full and the transfer proceeds one small credit window
    // at a time.
    let relay = start_relay(&trust, 64 * 1024).await;
    let report = bulk(&relay, STREAMS, PER_STREAM).await;
    eprintln!(
        "credit-starved relay, {STREAMS} x {PER_STREAM} B: {:?}",
        report.elapsed
    );
    assert_survived("credit-starved relay", &report);
}
