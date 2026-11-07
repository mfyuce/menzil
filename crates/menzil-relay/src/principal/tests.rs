//! Tests of the relay principal against a scripted responder: a node that is attached to the
//! relay's registry and answers the L4 handshake and OPENs with `menzil-e2e` and `menzil-stream`
//! used from their responder side, with no `menzil-node` involved. Frames from the node reach the
//! relay through the endpoint exactly as a session's SEND to the relay's NodeId does
//! (`RelayEndpoint::accept`), and everything the relay sends is drained from the registration's
//! forward channel as a real session would drain it.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_e2e::{E2eResponderHandshake, E2eTransport};
use menzil_proto::{
    E2eDataBody, E2eFrame, ErrorCode, Limits, NetworkId, NodeCert, NodeCertBody, NodeId, OpenMeta,
    PROTOCOL_VERSION, Record, ServiceId, ServiceKind, X25519PublicKey,
};
use menzil_stream::{
    Authorizer, Mode, OpenDecision, OpenRefusal, OpenRequest, Responded, ServiceHandler, Stream,
    respond_to_open,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use super::*;
use crate::endpoint::EndpointCredit;
use crate::forward::ForwardItem;
use crate::identity::RelayIdentity;
use crate::tenant::Slug;

/// A test that hangs (a mutant that stops a session from ending, say) fails after this instead.
const BOUND: Duration = Duration::from_secs(20);

async fn bounded<T>(what: &str, future: impl Future<Output = T>) -> T {
    match tokio::time::timeout(BOUND, future).await {
        Ok(value) => value,
        Err(_) => panic!("timed out: {what}"),
    }
}

/// Waits (in the runtime's clock, which tests may have paused) until `condition` holds.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    bounded(what, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
}

/// Lets the dispatcher and the sessions run for a while (real or paused time alike).
async fn settle() {
    tokio::time::sleep(Duration::from_millis(300)).await;
}

fn ik_params() -> snow::params::NoiseParams {
    "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
}

#[derive(Clone)]
struct TestNode {
    signing_key: SigningKey,
    node_id: NodeId,
    x25519_private: [u8; 32],
    x25519_public: X25519PublicKey,
}

impl TestNode {
    fn new() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rng());
        let kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        Self {
            node_id: NodeId::from(signing_key.verifying_key().to_bytes()),
            x25519_private: <[u8; 32]>::try_from(kp.private).unwrap(),
            x25519_public: X25519PublicKey::from(<[u8; 32]>::try_from(kp.public).unwrap()),
            signing_key,
        }
    }

    fn cert(&self) -> NodeCert {
        let body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: self.node_id,
            x25519_pub: self.x25519_public,
            serial: 1,
            not_before: 0,
            not_after: 4_000_000_000,
        };
        NodeCert::sign(&self.signing_key, &body).unwrap()
    }
}

fn network(seed: u8) -> NetworkId {
    NetworkId::from([seed; 32])
}

fn limits() -> Limits {
    Limits {
        max_record: 65_535,
        max_peers: 10,
        credit: 1_048_576,
    }
}

fn relay_with(limits: Limits) -> Relay {
    let raw = TestNode::new();
    Relay::new(
        RelayIdentity {
            node_cert: raw.cert(),
            x25519_private: raw.x25519_private,
        },
        limits,
    )
}

fn service(label: &str) -> ServiceId {
    ServiceId::new(ServiceKind::Tls, label)
}

fn meta() -> OpenMeta {
    OpenMeta {
        client_ip: Some("203.0.113.9".to_string()),
        sni: Some("demo.example.org".to_string()),
    }
}

/// A short, quick configuration (real time): ticks every 20 ms.
fn quick() -> PrincipalConfig {
    PrincipalConfig::default()
        .with_tick(Duration::from_millis(20))
        .with_handshake_timeout(Duration::from_secs(5))
}

/// How the scripted node behaves.
#[derive(Clone)]
struct Behaviour {
    /// It answers `init` for these networks and stays silent for any other.
    networks: Vec<NetworkId>,
    /// It answers with the certificate of another node.
    wrong_cert: bool,
    /// It refuses every OPEN with this code.
    refuse: Option<ErrorCode>,
    /// What the service behind an accepted OPEN does.
    service: Scripted,
}

/// What the scripted node's service does with a stream.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scripted {
    /// Reads and writes the bytes back.
    Echo,
    /// Never reads and never writes (the relay's writes stop at the window the node granted).
    Silent,
    /// Writes as fast as it may and never reads (the node's writes stop at the window the relay
    /// granted, which is what the relay holds when nobody reads its end).
    Flood,
}

impl Behaviour {
    fn serving(networks: &[NetworkId]) -> Self {
        Self {
            networks: networks.to_vec(),
            wrong_cert: false,
            refuse: None,
            service: Scripted::Echo,
        }
    }
}

/// What the scripted node saw and holds, shared with the test.
#[derive(Default)]
struct Seen {
    inits: Mutex<Vec<NetworkId>>,
    opens: Mutex<Vec<OpenRequest>>,
    closes: Mutex<Vec<(ErrorCode, String)>>,
    keeps: AtomicUsize,
    transport: Mutex<Option<E2eTransport>>,
}

impl Seen {
    fn init_count(&self) -> usize {
        self.inits.lock().unwrap().len()
    }

    /// A valid CLOSE record of the established session, as this node would send it (the next
    /// counter of its sending direction is consumed), encoded for a SEND to the relay.
    fn forge_close(&self) -> Vec<u8> {
        let mut guard = self.transport.lock().unwrap();
        let transport = guard.as_mut().expect("the session is established");
        transport
            .encrypt_data(&E2eDataBody::Close {
                code: ErrorCode::NoGrant,
                msg: "forged by the test".to_string(),
            })
            .unwrap()
            .encode()
    }
}

struct Auth {
    seen: Arc<Seen>,
    refuse: Option<ErrorCode>,
}

impl Authorizer for Auth {
    fn authorize(&self, request: &OpenRequest) -> OpenDecision {
        self.seen.opens.lock().unwrap().push(request.clone());
        match self.refuse {
            Some(code) => OpenDecision::Deny(OpenRefusal {
                code,
                msg: "refused by the scripted node".to_string(),
            }),
            None => OpenDecision::Allow,
        }
    }
}

/// The scripted node's service (see [`Scripted`]).
struct Service(Scripted);

impl ServiceHandler<Stream> for Service {
    type Opened = ();
    type Handling = Pin<Box<dyn Future<Output = ()> + Send>>;

    async fn open(&self, _request: &OpenRequest) -> Result<Self::Opened, OpenRefusal> {
        Ok(())
    }

    fn handle(&self, mut stream: Stream, _request: OpenRequest, _opened: ()) -> Self::Handling {
        let mode = self.0;
        Box::pin(async move {
            match mode {
                Scripted::Echo => {}
                Scripted::Silent => {
                    let _stream = stream;
                    std::future::pending::<()>().await;
                    return;
                }
                Scripted::Flood => {
                    let chunk = vec![0xa5u8; 16 * 1024];
                    while stream.write_all(&chunk).await.is_ok() {}
                    return;
                }
            }
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        let _ = stream.close().await;
                        return;
                    }
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        })
    }
}

/// One L3 attachment of a scripted node and the task that answers for it.
struct Attached {
    node: TestNode,
    seen: Arc<Seen>,
    credit: Arc<EndpointCredit>,
    /// While `false`, the node reads nothing from the relay (so the relay's pair fills up).
    gate: watch::Sender<bool>,
    task: JoinHandle<()>,
    // The registration's other ends, kept so the registry does not see them closed.
    _supersede: oneshot::Receiver<()>,
    _outbound: mpsc::Receiver<Record>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Attached {
    /// `payload` as a SEND of this node to the relay, with L3 session id `session_id` (which
    /// need not be the current one: that is how a stale frame is made).
    fn inject_as(&self, relay: &Relay, session_id: u32, payload: Vec<u8>) {
        inject(relay, &self.credit, self.node.node_id, session_id, payload);
    }
}

fn inject(relay: &Relay, credit: &EndpointCredit, src: NodeId, session_id: u32, payload: Vec<u8>) {
    relay.endpoint.accept(
        &relay.registry,
        relay.relay_id().unwrap(),
        credit,
        src,
        session_id,
        E2E_PROTO_TAG,
        0,
        payload,
    );
}

fn attach(relay: &Relay, node: &TestNode, session_id: u32, behaviour: Behaviour) -> Attached {
    let (supersede, outbound, forward_rx) = relay.registry.attach_counted(
        node.node_id,
        session_id,
        node.x25519_public,
        vec![],
        None,
        None,
    );
    let seen = Arc::new(Seen::default());
    let credit = Arc::new(EndpointCredit::new(&relay.limits));
    let (gate, gate_rx) = watch::channel(true);
    let task = tokio::spawn(responder(
        relay.clone(),
        node.clone(),
        session_id,
        forward_rx,
        behaviour,
        Arc::clone(&seen),
        Arc::clone(&credit),
        gate_rx,
    ));
    Attached {
        node: node.clone(),
        seen,
        credit,
        gate,
        task,
        _supersede: supersede,
        _outbound: outbound,
    }
}

#[allow(clippy::too_many_arguments)]
async fn responder(
    relay: Relay,
    node: TestNode,
    session_id: u32,
    mut forward_rx: mpsc::UnboundedReceiver<ForwardItem>,
    behaviour: Behaviour,
    seen: Arc<Seen>,
    credit: Arc<EndpointCredit>,
    mut gate: watch::Receiver<bool>,
) {
    let relay_id = relay.relay_id().unwrap();
    let max_record = relay.limits.max_record;
    let mut mux: Option<menzil_stream::StreamMux> = None;
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    while let Some(item) = forward_rx.recv().await {
        if gate.wait_for(|open| *open).await.is_err() {
            break;
        }
        let ForwardItem::Recv {
            record,
            src,
            charge,
            reliable,
            generation,
            src_session_id,
            shared,
        } = item
        else {
            continue;
        };
        // As the session of this node would, once it has written the record.
        relay.forwarding.drained(
            &relay.registry,
            &src,
            &node.node_id,
            charge,
            reliable,
            generation,
            src_session_id,
            &shared,
        );
        let Record::Recv { payload, .. } = *record else {
            continue;
        };
        let Ok(frame) = E2eFrame::decode(&payload) else {
            continue;
        };
        match frame {
            E2eFrame::Init { network_id, .. } => {
                seen.inits.lock().unwrap().push(network_id);
                if !behaviour.networks.contains(&network_id) {
                    continue;
                }
                let Ok(handshake) = E2eResponderHandshake::start(
                    &node.x25519_private,
                    relay_id,
                    node.node_id,
                    &frame,
                ) else {
                    continue;
                };
                let cert = if behaviour.wrong_cert {
                    TestNode::new().cert()
                } else {
                    node.cert()
                };
                let (transport, resp) = handshake
                    .finish(
                        cert,
                        1,
                        1,
                        vec![E2E_PROTO_TAG],
                        0x7700 + session_id,
                        max_record,
                    )
                    .unwrap();
                *seen.transport.lock().unwrap() = Some(transport);
                let (new_mux, mut inbound, mut outbound, driver) =
                    menzil_stream::new(Mode::Server, max_record);
                mux = Some(new_mux);
                tasks.push(tokio::spawn(async move {
                    let _ = driver.await;
                }));
                // Frames of the node's yamux, encrypted with the session's transport.
                let pump = {
                    let relay = relay.clone();
                    let seen = Arc::clone(&seen);
                    let credit = Arc::clone(&credit);
                    tokio::spawn(async move {
                        while let Some(bytes) = outbound.next_frame().await {
                            let frame = {
                                let mut guard = seen.transport.lock().unwrap();
                                let Some(transport) = guard.as_mut() else {
                                    continue;
                                };
                                transport.encrypt_data(&E2eDataBody::Mux(bytes)).unwrap()
                            };
                            inject(&relay, &credit, node.node_id, session_id, frame.encode());
                        }
                    })
                };
                tasks.push(pump);
                let acceptor = {
                    let seen = Arc::clone(&seen);
                    let refuse = behaviour.refuse;
                    let service = behaviour.service;
                    tokio::spawn(async move {
                        while let Some(stream) = inbound.accept().await {
                            let seen = Arc::clone(&seen);
                            tokio::spawn(async move {
                                let auth = Auth {
                                    seen: Arc::clone(&seen),
                                    refuse,
                                };
                                if let Ok(Responded::Accepted(handling)) = respond_to_open(
                                    stream,
                                    network_id,
                                    relay_id,
                                    &auth,
                                    &Service(service),
                                )
                                .await
                                {
                                    handling.await;
                                }
                            });
                        }
                    })
                };
                tasks.push(acceptor);
                inject(&relay, &credit, node.node_id, session_id, resp.encode());
            }
            E2eFrame::Data {
                counter,
                ciphertext,
                ..
            } => {
                let body = seen
                    .transport
                    .lock()
                    .unwrap()
                    .as_mut()
                    .and_then(|transport| transport.decrypt_data(counter, &ciphertext).ok());
                match body {
                    Some(E2eDataBody::Mux(bytes)) => {
                        if let Some(mux) = &mux {
                            let _ = mux.feed_inbound(bytes);
                        }
                    }
                    Some(E2eDataBody::Close { code, msg }) => {
                        seen.closes.lock().unwrap().push((code, msg));
                    }
                    Some(E2eDataBody::Keep) => {
                        seen.keeps.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {}
                }
            }
            E2eFrame::Resp { .. } => {}
        }
    }
    for task in tasks {
        task.abort();
    }
}

/// A relay with a principal and one attached scripted node serving `networks`.
struct Rig {
    relay: Relay,
    principal: Principal,
    node: TestNode,
    attached: Attached,
}

fn rig(config: PrincipalConfig, networks: &[NetworkId]) -> Rig {
    rig_with(relay_with(limits()), config, networks)
}

fn rig_with(relay: Relay, config: PrincipalConfig, networks: &[NetworkId]) -> Rig {
    let principal = Principal::with_config(&relay, config);
    let node = TestNode::new();
    let attached = attach(&relay, &node, 7, Behaviour::serving(networks));
    Rig {
        relay,
        principal,
        node,
        attached,
    }
}

impl Rig {
    async fn open(&self, network: NetworkId, label: &str) -> Result<Stream, PrincipalError> {
        bounded(
            "open",
            self.principal.open(
                &TenantId::Default,
                self.node.node_id,
                network,
                service(label),
                meta(),
            ),
        )
        .await
    }
}

// ---- open ----

#[tokio::test]
async fn an_open_succeeds_and_bytes_make_the_round_trip() {
    let n = network(1);
    let rig = rig(quick(), &[n]);
    let stream = rig.open(n, "demo").await.expect("the stream opens");

    // What the node was told: this network, the relay as the initiator, the relay's meta and
    // a null target.
    assert_eq!(*rig.attached.seen.inits.lock().unwrap(), vec![n]);
    {
        let opens = rig.attached.seen.opens.lock().unwrap();
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].network_id, n);
        assert_eq!(opens[0].initiator, rig.relay.relay_id().unwrap());
        assert_eq!(opens[0].service, service("demo"));
        assert_eq!(opens[0].target, None, "the relay never names a target");
        assert_eq!(opens[0].meta, meta());
    }
    assert_eq!(rig.principal.session_count(), 1);
    assert_eq!(rig.principal.tenant_session_count(&TenantId::Default), 1);

    // A byte round trip, both directions, more than one yamux window's worth of records.
    let (mut reader, mut writer) = stream.split();
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let to_send = payload.clone();
    let write = tokio::spawn(async move {
        writer.write_all(&to_send).await.unwrap();
        writer.flush().await.unwrap();
        writer
    });
    let mut echoed = vec![0u8; payload.len()];
    bounded("echo", reader.read_exact(&mut echoed))
        .await
        .unwrap();
    assert_eq!(echoed, payload);
    let _writer = write.await.unwrap();

    // A second stream rides the same session: no second handshake.
    let second = rig.open(n, "other").await.expect("a second stream");
    assert_eq!(rig.attached.seen.init_count(), 1);
    assert_eq!(rig.principal.session_count(), 1);
    drop(second);
}

#[tokio::test]
async fn a_service_other_than_a_share_kind_is_not_opened() {
    let n = network(1);
    let rig = rig(quick(), &[n]);
    for kind in [ServiceKind::Menzil, ServiceKind::Egress, ServiceKind::Udp] {
        let error = bounded(
            "open",
            rig.principal.open(
                &TenantId::Default,
                rig.node.node_id,
                n,
                ServiceId::new(kind, "docs"),
                meta(),
            ),
        )
        .await
        .expect_err("not a share kind");
        assert_eq!(error, PrincipalError::ServiceNotAllowed);
    }
    assert_eq!(rig.attached.seen.init_count(), 0, "no session was started");
}

#[tokio::test]
async fn a_node_that_is_not_attached_is_reported_without_a_session() {
    let n = network(1);
    let relay = relay_with(limits());
    let principal = Principal::with_config(&relay, quick());
    let stranger = TestNode::new();
    let error = bounded(
        "open",
        principal.open(
            &TenantId::Default,
            stranger.node_id,
            n,
            service("demo"),
            meta(),
        ),
    )
    .await
    .expect_err("nobody is attached");
    assert_eq!(error, PrincipalError::NotAttached);
    assert_eq!(principal.session_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_node_that_does_not_know_the_network_stays_silent_and_the_open_times_out() {
    let known = network(1);
    let unknown = network(2);
    let config = quick().with_handshake_timeout(Duration::from_secs(3));
    let rig = rig(config, &[known]);
    let error = rig.open(unknown, "demo").await.expect_err("silence");
    assert_eq!(error, PrincipalError::HandshakeTimeout);
    assert_eq!(rig.attached.seen.init_count(), 1, "the init did go out");
    // The place was given back.
    assert_eq!(rig.principal.session_count(), 0);
    assert_eq!(rig.principal.tenant_session_count(&TenantId::Default), 0);
    // And the same node answers for the network it knows.
    rig.open(known, "demo")
        .await
        .expect("the known network works");
}

#[tokio::test]
async fn a_resp_with_another_nodes_certificate_is_refused() {
    let n = network(1);
    let relay = relay_with(limits());
    let principal = Principal::with_config(&relay, quick());
    let node = TestNode::new();
    let behaviour = Behaviour {
        wrong_cert: true,
        ..Behaviour::serving(&[n])
    };
    let _attached = attach(&relay, &node, 7, behaviour);
    let error = bounded(
        "open",
        principal.open(&TenantId::Default, node.node_id, n, service("demo"), meta()),
    )
    .await
    .expect_err("a certificate for another node");
    assert!(
        matches!(error, PrincipalError::HandshakeFailed(_)),
        "{error:?}"
    );
    assert_eq!(principal.session_count(), 0);
}

#[tokio::test]
async fn a_refused_open_is_reported_with_the_nodes_code_and_leaves_the_session() {
    let n = network(1);
    let relay = relay_with(limits());
    let principal = Principal::with_config(&relay, quick());
    let node = TestNode::new();
    let behaviour = Behaviour {
        refuse: Some(ErrorCode::UnknownService),
        ..Behaviour::serving(&[n])
    };
    let _attached = attach(&relay, &node, 7, behaviour);
    let error = bounded(
        "open",
        principal.open(&TenantId::Default, node.node_id, n, service("demo"), meta()),
    )
    .await
    .expect_err("refused");
    match error {
        PrincipalError::Refused { code, .. } => assert_eq!(code, ErrorCode::UnknownService),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert_eq!(principal.session_count(), 1, "the session is fine");
}

// ---- path pin ----

#[tokio::test]
async fn a_session_ends_when_the_node_reattaches_and_the_next_open_starts_a_fresh_one() {
    let n = network(1);
    let rig = rig(quick(), &[n]);
    let mut stream = rig.open(n, "demo").await.unwrap();
    assert_eq!(rig.principal.session_count(), 1);

    // The node attaches again over a new L3 session.
    let second = attach(&rig.relay, &rig.node, 8, Behaviour::serving(&[n]));
    eventually("the pinned session ends", || {
        rig.principal.session_count() == 0
    })
    .await;
    // The stream on it is over: a read ends (in an error or at the end), it does not hang.
    let mut buf = [0u8; 8];
    let read = bounded("read", stream.read(&mut buf)).await;
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

    // Nothing of the old path was used for the new one: the new attachment saw one init only
    // when the next open came.
    assert_eq!(second.seen.init_count(), 0);
    let _again = rig.open(n, "demo").await.expect("a fresh session");
    assert_eq!(second.seen.init_count(), 1);
    assert_eq!(rig.principal.session_count(), 1);
}

#[tokio::test]
async fn a_session_ends_when_the_node_detaches() {
    let n = network(1);
    let rig = rig(quick(), &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    assert!(rig.relay.registry.detach(&rig.node.node_id, 7));
    eventually("the session ends", || rig.principal.session_count() == 0).await;
    let error = rig.open(n, "demo").await.expect_err("detached");
    assert_eq!(error, PrincipalError::NotAttached);
}

#[tokio::test]
async fn an_open_after_a_reattach_replaces_a_session_that_has_not_noticed_yet() {
    let n = network(1);
    // A tick so long that only the open can notice the change.
    let rig = rig(quick().with_tick(Duration::from_secs(3600)), &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    let second = attach(&rig.relay, &rig.node, 8, Behaviour::serving(&[n]));
    let _again = rig.open(n, "demo").await.expect("a fresh session");
    assert_eq!(second.seen.init_count(), 1);
    assert_eq!(rig.principal.session_count(), 1);
}

#[tokio::test]
async fn a_frame_of_another_l3_session_never_feeds_the_session() {
    let n = network(1);
    let rig = rig(quick().with_tick(Duration::from_secs(3600)), &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    let close = rig.attached.seen.forge_close();

    // A genuine CLOSE of the node's session, but claimed by an L3 session that is not the one
    // the node is attached by: dropped, the session lives.
    rig.attached.inject_as(&rig.relay, 6, close.clone());
    settle().await;
    assert_eq!(rig.principal.session_count(), 1, "a stale frame is ignored");

    // The very same record by the right L3 session ends it: the frame was good, only its path
    // was not.
    rig.attached.inject_as(&rig.relay, 7, close);
    eventually("the CLOSE ends the session", || {
        rig.principal.session_count() == 0
    })
    .await;
}

#[tokio::test]
async fn a_frame_of_the_old_l3_session_after_a_reattach_does_not_reach_the_old_session() {
    let n = network(1);
    let rig = rig(quick().with_tick(Duration::from_secs(3600)), &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    let close = rig.attached.seen.forge_close();

    // The node attaches again; the old L4 session has not noticed yet (the tick is an hour).
    let _second = attach(&rig.relay, &rig.node, 8, Behaviour::serving(&[n]));
    // A frame still carrying the old L3 session id: the node is not attached by it any more.
    rig.attached.inject_as(&rig.relay, 7, close);
    settle().await;
    assert_eq!(
        rig.principal.session_count(),
        1,
        "the stale frame was dropped, not processed"
    );
}

#[tokio::test]
async fn frames_from_a_member_that_is_not_the_node_never_feed_the_session() {
    let n = network(1);
    let rig = rig(quick().with_tick(Duration::from_secs(3600)), &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    let close = rig.attached.seen.forge_close();

    // Another attached member sends the node's genuine record (it learned the index, say).
    // Its L3 session number is the node's (the numbers of two sessions may coincide): only
    // the sender tells them apart.
    let member = TestNode::new();
    let member_attached = attach(&rig.relay, &member, 7, Behaviour::serving(&[]));
    inject(
        &rig.relay,
        &member_attached.credit,
        member.node_id,
        7,
        close.clone(),
    );
    settle().await;
    assert_eq!(
        rig.principal.session_count(),
        1,
        "a member's frame is ignored"
    );

    // From the node itself the same bytes end the session.
    rig.attached.inject_as(&rig.relay, 7, close);
    eventually("the node's own CLOSE ends it", || {
        rig.principal.session_count() == 0
    })
    .await;
}

#[tokio::test]
async fn an_init_or_junk_from_the_node_is_not_a_resp_or_data() {
    let n = network(1);
    let rig = rig(quick().with_tick(Duration::from_secs(3600)), &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    // An `init`, an unknown tag, a truncated data frame and a data frame to an unknown index.
    let init = E2eFrame::Init {
        sender_index: 1,
        network_id: n,
        noise_msg1: vec![0; 48],
    }
    .encode();
    for payload in [
        init,
        vec![0x09, 1, 2, 3],
        vec![0x03, 0, 0],
        E2eFrame::Data {
            receiver_index: 0xdead_beef,
            counter: 0,
            ciphertext: vec![0; 40],
        }
        .encode(),
    ] {
        rig.attached.inject_as(&rig.relay, 7, payload);
    }
    settle().await;
    assert_eq!(rig.principal.session_count(), 1);
}

// ---- idle, age, keep ----

#[tokio::test(start_paused = true)]
async fn a_session_with_no_stream_is_closed_after_the_idle_time() {
    let n = network(1);
    let config = quick()
        .with_tick(Duration::from_secs(1))
        .with_idle_timeout(Duration::from_secs(30));
    let rig = rig(config, &[n]);
    let mut stream = rig.open(n, "demo").await.unwrap();

    // A held stream keeps it open for far longer than the idle time.
    tokio::time::sleep(Duration::from_secs(35)).await;
    assert_eq!(rig.principal.session_count(), 1, "a stream is in use");

    // Closed cleanly, then the clock starts.
    stream.close().await.unwrap();
    drop(stream);
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(
        rig.principal.session_count(),
        1,
        "not yet idle for long enough"
    );
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(rig.principal.session_count(), 0, "idle for the whole time");
    let closes = rig.attached.seen.closes.lock().unwrap().clone();
    assert_eq!(closes.len(), 1, "the node was told");
    assert_eq!(closes[0].0, ErrorCode::ShuttingDown);
}

#[tokio::test(start_paused = true)]
async fn a_session_is_ended_at_its_age_and_the_next_open_handshakes_anew() {
    let n = network(1);
    let config = quick()
        .with_tick(Duration::from_secs(1))
        .with_max_session_age(Duration::from_secs(15));
    let rig = rig(config, &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    assert_eq!(rig.attached.seen.init_count(), 1);
    tokio::time::sleep(Duration::from_secs(17)).await;
    assert_eq!(rig.principal.session_count(), 0, "aged out");
    let _again = rig.open(n, "demo").await.unwrap();
    assert_eq!(rig.attached.seen.init_count(), 2, "a new handshake");
}

#[tokio::test(start_paused = true)]
async fn the_relay_keeps_a_quiet_session_alive_with_keep_and_gives_up_on_a_silent_node() {
    let n = network(1);
    let config = quick().with_tick(Duration::from_secs(1));
    let rig = rig(config, &[n]);
    let _stream = rig.open(n, "demo").await.unwrap();
    tokio::time::sleep(Duration::from_secs(22)).await;
    assert!(
        rig.attached.seen.keeps.load(Ordering::SeqCst) >= 1,
        "a KEEP went out after 20 seconds of silence"
    );
    // The scripted node never answers: after 40 seconds without a record the peer is dead.
    tokio::time::sleep(Duration::from_secs(25)).await;
    assert_eq!(rig.principal.session_count(), 0);
}

// ---- caps ----

#[tokio::test]
async fn sessions_are_capped_per_tenant_and_in_all() {
    let n = network(1);
    let config = quick().with_max_per_tenant(2).with_max_total(3);
    let relay = relay_with(limits());
    let principal = Principal::with_config(&relay, config);
    let nodes: Vec<TestNode> = (0..5).map(|_| TestNode::new()).collect();
    let _attached: Vec<Attached> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| attach(&relay, node, 10 + i as u32, Behaviour::serving(&[n])))
        .collect();
    let ali = TenantId::Named(Slug::parse("friends").unwrap());
    let default = TenantId::Default;
    let open = |tenant: &TenantId, node: &TestNode| {
        let tenant = tenant.clone();
        let principal = principal.clone();
        let node = node.node_id;
        async move {
            bounded(
                "open",
                principal.open(&tenant, node, n, service("demo"), meta()),
            )
            .await
        }
    };

    let _a1 = open(&default, &nodes[0]).await.expect("first");
    let _a2 = open(&default, &nodes[1]).await.expect("second");
    // The tenant is at its figure: no third, and no handshake was started for it.
    let error = open(&default, &nodes[2])
        .await
        .expect_err("over the tenant cap");
    assert_eq!(error, PrincipalError::TenantCap { limit: 2 });
    assert_eq!(_attached[2].seen.init_count(), 0);
    assert_eq!(principal.tenant_session_count(&default), 2);

    // Another tenant is not held back by it, up to the relay wide figure.
    let _b1 = open(&ali, &nodes[2]).await.expect("another tenant");
    let error = open(&ali, &nodes[3]).await.expect_err("over the relay cap");
    assert_eq!(error, PrincipalError::RelayCap { limit: 3 });
    assert_eq!(_attached[3].seen.init_count(), 0);
    assert_eq!(principal.session_count(), 3);
    assert_eq!(principal.tenant_session_count(&ali), 1);

    // A stream on a session that exists is not a new session.
    open(&default, &nodes[0]).await.expect("same session");
    assert_eq!(principal.session_count(), 3);
}

/// Opens until it works or the wait is over: a dropped stream's place comes back once `yamux`
/// has written its reset, not at the drop.
async fn open_when_a_place_frees(rig: &Rig, network: NetworkId) -> Stream {
    bounded("a place to come back", async {
        loop {
            match rig.open(network, "demo").await {
                Ok(stream) => return stream,
                Err(PrincipalError::StreamLimit | PrincipalError::TenantStreamCap { .. }) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(other) => panic!("unexpected: {other:?}"),
            }
        }
    })
    .await
}

/// Expose round 1, M2: a session holds at most `max_streams_per_session` streams, at that
/// figure and not at `menzil-stream`'s 448, and a place comes back when a stream is dropped.
#[tokio::test]
async fn a_session_holds_at_most_its_stream_cap_and_a_dropped_stream_gives_its_place_back() {
    let n = network(1);
    let rig = rig(quick().with_max_streams_per_session(3), &[n]);
    let a = rig.open(n, "demo").await.expect("first");
    let _b = rig.open(n, "demo").await.expect("second");
    let _c = rig.open(n, "demo").await.expect("third");
    assert_eq!(
        rig.open(n, "demo").await.expect_err("over the session cap"),
        PrincipalError::StreamLimit
    );
    assert_eq!(rig.principal.session_count(), 1, "the session goes on");
    drop(a);
    let _again = open_when_a_place_frees(&rig, n).await;
    assert_eq!(
        rig.open(n, "demo").await.expect_err("full again"),
        PrincipalError::StreamLimit
    );
}

/// A principal session's connection has the session's stream cap as its table and receive
/// windows that never grow (the figures those mean are `menzil-stream`'s own test).
#[test]
fn a_principal_session_is_built_with_the_stream_cap_and_without_window_growth() {
    let limits = PrincipalConfig::default()
        .with_max_streams_per_session(7)
        .mux_limits();
    assert_eq!(limits.max_live_streams, 7);
    assert!(!limits.window_growth);
    assert_eq!(
        PrincipalConfig::default().mux_limits().max_live_streams,
        DEFAULT_MAX_STREAMS_PER_SESSION
    );
}

#[tokio::test]
async fn the_tenants_streams_are_capped_across_sessions_and_given_back() {
    let (n1, n2) = (network(1), network(2));
    let relay = relay_with(limits());
    let principal = Principal::with_config(
        &relay,
        quick()
            .with_max_streams_per_session(8)
            .with_max_streams_per_tenant(3),
    );
    let node = TestNode::new();
    let attached = attach(&relay, &node, 7, Behaviour::serving(&[n1, n2]));
    let rig = Rig {
        relay,
        principal,
        node,
        attached,
    };
    let _a = rig.open(n1, "demo").await.expect("first");
    let b = rig.open(n1, "demo").await.expect("second");
    let _c = rig
        .open(n2, "demo")
        .await
        .expect("third, on another session of the tenant");
    assert_eq!(rig.principal.session_count(), 2);
    assert_eq!(
        rig.open(n2, "demo").await.expect_err("over the tenant cap"),
        PrincipalError::TenantStreamCap { limit: 3 }
    );
    assert_eq!(
        rig.open(n1, "demo").await.expect_err("either session"),
        PrincipalError::TenantStreamCap { limit: 3 }
    );
    // Another tenant has streams of its own (another node: a network's session has one tenant).
    let other = TestNode::new();
    let _other_attached = attach(&rig.relay, &other, 11, Behaviour::serving(&[n1]));
    let ali = TenantId::Named(Slug::parse("friends").unwrap());
    let _x = bounded(
        "open",
        rig.principal
            .open(&ali, other.node_id, n1, service("demo"), meta()),
    )
    .await
    .expect("another tenant is not held back");
    // A dropped stream gives its place back.
    drop(b);
    let _d = open_when_a_place_frees(&rig, n2).await;
    assert_eq!(
        rig.open(n2, "demo").await.expect_err("full again"),
        PrincipalError::TenantStreamCap { limit: 3 }
    );
    // A session that ends gives back every place it held: the node reattaches, and the tenant
    // opens on a fresh session while the dead streams are still held here.
    assert!(rig.relay.registry.detach(&rig.node.node_id, 7));
    eventually("the sessions end", || {
        rig.principal.tenant_session_count(&TenantId::Default) == 0
    })
    .await;
    let _reattached = attach(&rig.relay, &rig.node, 8, Behaviour::serving(&[n1, n2]));
    let _fresh = rig
        .open(n1, "demo")
        .await
        .expect("a place on a fresh session");
}

/// Several opens at once cannot overshoot the tenant's cap: a place is taken before the stream
/// exists.
#[tokio::test]
async fn opens_made_at_once_do_not_overshoot_the_tenants_cap() {
    let n = network(1);
    let rig = rig(
        quick()
            .with_max_streams_per_session(16)
            .with_max_streams_per_tenant(3),
        &[n],
    );
    // The session first, so that the opens below race for places and not for the handshake.
    let first = rig.open(n, "demo").await.expect("first");
    let results = futures_util::future::join_all((0..8).map(|_| rig.open(n, "demo"))).await;
    let opened = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(opened, 2, "3 places, one already taken: {results:?}");
    assert!(
        results
            .iter()
            .filter_map(|r| r.as_ref().err())
            .all(|e| *e == PrincipalError::TenantStreamCap { limit: 3 })
    );
    drop(first);
}

#[tokio::test(start_paused = true)]
async fn a_session_that_ends_gives_its_place_back_to_the_caps() {
    let n = network(1);
    let config = quick()
        .with_tick(Duration::from_secs(1))
        .with_idle_timeout(Duration::from_secs(5))
        .with_max_total(1)
        .with_max_per_tenant(1);
    let rig = rig(config, &[n]);
    let other = TestNode::new();
    let _other_attached = attach(&rig.relay, &other, 11, Behaviour::serving(&[n]));
    let first = rig.open(n, "demo").await.unwrap();
    let error = bounded(
        "open",
        rig.principal.open(
            &TenantId::Default,
            other.node_id,
            n,
            service("demo"),
            meta(),
        ),
    )
    .await
    .expect_err("full");
    assert_eq!(error, PrincipalError::RelayCap { limit: 1 });
    drop(first);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(rig.principal.session_count(), 0);
    bounded(
        "open",
        rig.principal.open(
            &TenantId::Default,
            other.node_id,
            n,
            service("demo"),
            meta(),
        ),
    )
    .await
    .expect("the place is free again");
}

#[tokio::test]
async fn the_relays_own_figures_are_the_designs() {
    let config = Relay::new(
        {
            let raw = TestNode::new();
            RelayIdentity {
                node_cert: raw.cert(),
                x25519_private: raw.x25519_private,
            }
        },
        limits(),
    )
    .principal_config();
    assert_eq!(config.max_per_tenant, 256);
    assert_eq!(config.max_total, 2_048);
    assert_eq!(config.idle_timeout, Duration::from_secs(300));
    assert_eq!(config.max_session_age, Duration::from_secs(24 * 3600));
    assert_eq!(config.max_streams_per_session, 64);
    assert_eq!(config.max_streams_per_tenant, 1_024);
}

#[tokio::test]
async fn the_caps_can_be_set_on_the_relay() {
    let raw = TestNode::new();
    let relay = Relay::new(
        RelayIdentity {
            node_cert: raw.cert(),
            x25519_private: raw.x25519_private,
        },
        limits(),
    )
    .with_principal_config(
        PrincipalConfig::default()
            .with_max_per_tenant(7)
            .with_max_total(9),
    );
    let principal = Principal::new(&relay);
    assert_eq!(principal.config().max_per_tenant, 7);
    assert_eq!(principal.config().max_total, 9);
}

// ---- sending ----

#[tokio::test]
async fn a_full_pair_holds_reliable_data_back_and_loses_none() {
    let n = network(1);
    // 40 KB of credit toward the node: a few yamux frames fill the pair.
    let small = Limits {
        credit: 40_000,
        ..limits()
    };
    let rig = rig_with(relay_with(small), quick(), &[n]);
    let stream = rig.open(n, "demo").await.unwrap();

    // The node stops reading: the pair fills and the principal has to wait.
    let _ = rig.attached.gate.send(false);
    let (mut reader, mut writer) = stream.split();
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 239) as u8).collect();
    let to_send = payload.clone();
    let write = tokio::spawn(async move {
        writer.write_all(&to_send).await.unwrap();
        writer.flush().await.unwrap();
        writer
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The pair toward the node really is full: its credit is spent and bytes are queued.
    let relay_id = rig.relay.relay_id().unwrap();
    let (credit_left, queued, _) = rig
        .relay
        .forwarding
        .pair_figures(&relay_id, &rig.node.node_id)
        .expect("the relay's pair toward the node");
    assert!(queued > 0 && credit_left < 16_384, "{credit_left} {queued}");
    assert_eq!(rig.principal.session_count(), 1, "waiting is not failing");

    // The node reads again: everything arrives, in order, and comes back.
    let _ = rig.attached.gate.send(true);
    let mut echoed = vec![0u8; payload.len()];
    bounded("echo", reader.read_exact(&mut echoed))
        .await
        .unwrap();
    assert_eq!(echoed, payload);
    let _writer = write.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_pair_that_stays_full_for_the_whole_send_wait_ends_the_session() {
    let n = network(1);
    let small = Limits {
        credit: 40_000,
        ..limits()
    };
    let config = quick()
        .with_tick(Duration::from_secs(1))
        .with_send_wait(Duration::from_secs(5));
    let rig = rig_with(relay_with(small), config, &[n]);
    let stream = rig.open(n, "demo").await.unwrap();
    let _ = rig.attached.gate.send(false);
    let (_reader, mut writer) = stream.split();
    let writing = tokio::spawn(async move {
        let _ = writer.write_all(&vec![7u8; 400_000]).await;
    });
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(rig.principal.session_count(), 0, "gave up after the wait");
    writing.abort();
}

// ---- the principal going away ----

#[tokio::test]
async fn dropping_the_principal_ends_its_sessions() {
    let n = network(1);
    let rig = rig(quick(), &[n]);
    let mut stream = rig.open(n, "demo").await.unwrap();
    let Rig {
        principal,
        relay,
        attached,
        node: _,
    } = rig;
    drop(principal);
    let mut buf = [0u8; 4];
    let read = bounded("read", stream.read(&mut buf)).await;
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    drop(attached);
    drop(relay);
}

// ---- what a session buffers (expose round 1, M2) ----

mod heap {
    //! The resident set of the test process, from `/proc/self/statm` (the relay crate forbids
    //! `unsafe`, so no counting allocator here; `menzil-stream/tests/small_frames.rs` has one).
    //! It counts every page of the process, so the measurement runs alone
    //! (`--ignored --test-threads=1`), and only growth is read from it: freed memory the
    //! allocator keeps is not subtracted, so a figure is at most what was held at once.
    pub fn live() -> usize {
        let statm = std::fs::read_to_string("/proc/self/statm").expect("Linux /proc");
        let resident_pages: usize = statm
            .split_whitespace()
            .nth(1)
            .and_then(|field| field.parse().ok())
            .expect("statm has a resident field");
        resident_pages * 4096
    }
}

/// Waits until the resident set has not changed for a second.
async fn quiet_heap() -> usize {
    let mut last = heap::live();
    let mut still = 0;
    for _ in 0..400 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let now = heap::live();
        if now.abs_diff(last) < 4096 {
            still += 1;
            if still >= 10 {
                return now;
            }
        } else {
            still = 0;
        }
        last = now;
    }
    last
}

/// Opens `streams` streams through one principal session to a scripted node whose service is
/// `service`, lets every stream fill its window (the relay writes into each in `Silent` mode and
/// reads nothing; the node writes into each in `Flood` mode and the relay reads nothing), and
/// returns the resident memory the whole process grew by beyond what it held with the session
/// up and one stream.
///
/// The relay's ends and the scripted node's ends live in one process, so the figure is both ends
/// of the connection: an upper bound of what the relay holds.
async fn heap_with_full_streams(service: Scripted, relay_writes: bool, streams: usize) -> usize {
    let n = network(1);
    let relay = relay_with(limits());
    let principal =
        Principal::with_config(&relay, quick().with_idle_timeout(Duration::from_secs(3600)));
    let node = TestNode::new();
    let behaviour = Behaviour {
        service,
        ..Behaviour::serving(&[n])
    };
    let _attached = attach(&relay, &node, 7, behaviour);
    let open = |label: String| {
        principal.open(
            &TenantId::Default,
            node.node_id,
            n,
            service_named(&label),
            meta(),
        )
    };
    // One stream to bring the session up, then the baseline.
    let first = bounded("first open", open("probe0".to_string()))
        .await
        .expect("the first stream");
    let (first_reader, mut first_writer) = first.split();
    let chunk = vec![0x5au8; 16 * 1024];
    let mut held = Vec::new();
    let mut writers = Vec::new();
    if relay_writes {
        writers.push(tokio::spawn(async move {
            while first_writer.write_all(&chunk).await.is_ok() {}
        }));
    }
    held.push(first_reader);
    let base = quiet_heap().await;
    for i in 1..streams {
        let stream = bounded("open", open(format!("probe{i}")))
            .await
            .expect("a stream");
        let (reader, mut writer) = stream.split();
        if relay_writes {
            let chunk = vec![0x5au8; 16 * 1024];
            writers.push(tokio::spawn(async move {
                while writer.write_all(&chunk).await.is_ok() {}
            }));
        } else {
            held.push(reader);
            continue;
        }
        held.push(reader);
    }
    let full = quiet_heap().await;
    for writer in &writers {
        writer.abort();
    }
    drop(held);
    full.saturating_sub(base)
}

fn service_named(label: &str) -> ServiceId {
    service(label)
}

/// The measurement behind the principal's stream caps, one configuration a process (a resident
/// set only grows, so a second run in the same process would reuse what the first freed):
/// `MEASURE_SERVICE=silent|flood|both MEASURE_STREAMS=64 cargo test -p menzil-relay --lib --
/// --ignored --nocapture --test-threads=1 measure_what_a_session_buffers`
#[tokio::test]
#[ignore = "a measurement: reads the whole process's resident set, run it alone"]
async fn measure_what_a_session_buffers() {
    let mode = std::env::var("MEASURE_SERVICE").unwrap_or_default();
    let service = match mode.as_str() {
        "flood" | "both" => Scripted::Flood,
        _ => Scripted::Silent,
    };
    let streams: usize = std::env::var("MEASURE_STREAMS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16);
    let baseline = heap::live();
    let grown = heap_with_full_streams(service, mode != "flood", streams).await;
    println!(
        "MEASURE {} streams={streams} grew_bytes={grown} per_stream={} process_rss_before={baseline}",
        if mode.is_empty() { "silent" } else { &mode },
        grown / streams.saturating_sub(1).max(1)
    );
}
