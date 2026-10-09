//! The router's tests: [`Engine`] and the task around it, driven through an
//! in-memory stand-in for the L3 layer (no relay, no sockets), so every
//! branch of the handshake orchestration can be reached deterministically
//! and, under a paused clock, instantly. `tests/l4_router.rs` runs the same
//! thing over a real relay.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_e2e::{E2eInitiatorHandshake, E2eResponderHandshake, E2eTransport};
use menzil_proto::{
    E2eDataBody, Grant, NodeCert, NodeCertBody, NodeOrWildcard, PROTOCOL_VERSION, Policy,
    PolicyBody, PolicyMember, Principal, PrincipalTarget, Roster, RosterBody, RosterMember,
    X25519PublicKey,
};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::*;
use crate::l4_session::EndReason;
use crate::outbound::EnqueueOutcome;

// ----------------------------------------------------------------------
// Identities and documents
// ----------------------------------------------------------------------

struct Party {
    signing: SigningKey,
    id: NodeId,
    x25519_private: [u8; 32],
    x25519_public: X25519PublicKey,
    cert: NodeCert,
}

fn party() -> Party {
    let signing = SigningKey::generate(&mut rand::rng());
    let id = NodeId::from(signing.verifying_key().to_bytes());
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    let x25519_private = <[u8; 32]>::try_from(keypair.private).unwrap();
    let x25519_public = X25519PublicKey::from(<[u8; 32]>::try_from(keypair.public).unwrap());
    let cert = NodeCert::sign(
        &signing,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: id,
            x25519_pub: x25519_public,
            serial: 1,
            not_before: 0,
            not_after: 4_000_000_000,
        },
    )
    .unwrap();
    Party {
        signing,
        id,
        x25519_private,
        x25519_public,
        cert,
    }
}

impl Party {
    /// A second owner of the same identity, for a test that hands one to a
    /// [`Manual`] and keeps using the other.
    fn clone_for_test(&self) -> Party {
        Party {
            signing: self.signing.clone(),
            id: self.id,
            x25519_private: self.x25519_private,
            x25519_public: self.x25519_public,
            cert: self.cert.clone(),
        }
    }

    fn identity(&self) -> LocalIdentity {
        LocalIdentity {
            node_cert: self.cert.clone(),
            x25519_private: self.x25519_private,
        }
    }
}

struct World {
    owner: SigningKey,
    network: NetworkId,
}

fn world() -> World {
    let owner = SigningKey::generate(&mut rand::rng());
    let network = NetworkId::from(owner.verifying_key().to_bytes());
    World { owner, network }
}

impl World {
    fn roster(&self, members: &[&Party]) -> Roster {
        let body = RosterBody {
            v: PROTOCOL_VERSION,
            network_id: self.network,
            seq: 1,
            issued: 0,
            expires: 4_000_000_000,
            members: members
                .iter()
                .map(|p| RosterMember {
                    node_id: p.id,
                    min_serial: 1,
                })
                .collect(),
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(&self.owner, &body).unwrap()
    }

    fn policy(&self, members: &[&Party], certs_of: &[&Party], grants: Vec<Grant>) -> Policy {
        let body = PolicyBody {
            v: PROTOCOL_VERSION,
            network_id: self.network,
            seq: 1,
            issued: 0,
            expires: 4_000_000_000,
            members: members
                .iter()
                .map(|p| PolicyMember {
                    node_id: p.id,
                    name: "node".to_string(),
                    roles: vec![],
                })
                .collect(),
            certs: certs_of.iter().map(|p| p.cert.clone()).collect(),
            grants,
            egress: vec![],
            accept: vec![],
        };
        Policy::sign(&self.owner, &body).unwrap()
    }

    /// `from` may use `tcp:ssh` on `to`.
    fn grant(&self, from: &Party, to: &Party) -> Grant {
        Grant {
            from: Principal {
                network_id: self.network,
                target: PrincipalTarget::Node(from.id),
            },
            to_node: NodeOrWildcard::Node(to.id),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        }
    }

    /// Stores holding the whole network: everyone a member with a valid
    /// cert, and `grants`.
    fn stores(&self, parties: &[&Party], grants: Vec<Grant>) -> Stores {
        let rosters = RosterStore::new();
        rosters.set(&self.roster(parties)).unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&self.policy(parties, parties, grants))
            .unwrap();
        Stores {
            policies: Arc::new(policies),
            rosters: Arc::new(rosters),
        }
    }
}

#[derive(Clone)]
struct Stores {
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
}

// ----------------------------------------------------------------------
// An in-memory stand-in for the L3 layer
// ----------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Logged {
    src: NodeId,
    dst: NodeId,
    kind: &'static str,
    payload: Vec<u8>,
}

struct Link {
    events: mpsc::Sender<SessionEvent>,
    epoch: Epoch,
    up: bool,
}

#[derive(Default)]
struct NetInner {
    links: HashMap<NodeId, Link>,
    log: Vec<Logged>,
    /// While set, frames are queued instead of delivered.
    holding: bool,
    held: Vec<(NodeId, NodeId, u8, u8, Vec<u8>)>,
}

#[derive(Clone)]
struct Net {
    inner: Arc<Mutex<NetInner>>,
    relay: NodeId,
}

const LIMITS: Limits = Limits {
    max_record: 65_535,
    max_peers: 10,
    credit: 1 << 20,
};

impl Net {
    fn new() -> Self {
        Self::with_relay(NodeId::from([0xAA; 32]))
    }

    /// A network whose relay has this NodeId (the one `init`s are refused
    /// from).
    fn with_relay(relay: NodeId) -> Self {
        Self {
            inner: Arc::default(),
            relay,
        }
    }

    /// Every frame of `kind` logged so far, oldest first.
    fn frames(&self, kind: &str) -> Vec<Logged> {
        self.inner
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| l.kind == kind)
            .cloned()
            .collect()
    }

    fn deliver(&self, src: NodeId, dst: NodeId, e2e_proto: u8, flags: u8, payload: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.holding {
            inner.held.push((src, dst, e2e_proto, flags, payload));
            return;
        }
        let Some(link) = inner.links.get(&dst) else {
            return;
        };
        if !link.up {
            return;
        }
        let event = SessionEvent::Record {
            epoch: link.epoch,
            record: Box::new(Record::Recv {
                src,
                e2e_proto,
                flags,
                payload,
            }),
        };
        let _ = link.events.try_send(event);
    }

    /// Holds every frame from now until [`Self::release`].
    fn hold(&self) {
        self.inner.lock().unwrap().holding = true;
    }

    fn release(&self) {
        let held = {
            let mut inner = self.inner.lock().unwrap();
            inner.holding = false;
            std::mem::take(&mut inner.held)
        };
        for (src, dst, proto, flags, payload) in held {
            self.deliver(src, dst, proto, flags, payload);
        }
    }

    /// Whether `dst` is currently reachable (a stand-in for the relay
    /// having it attached).
    fn set_up(&self, node: &NodeId, up: bool) {
        if let Some(link) = self.inner.lock().unwrap().links.get_mut(node) {
            link.up = up;
        }
    }

    fn count(&self, kind: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| l.kind == kind)
            .count()
    }

    fn count_from(&self, src: &NodeId, kind: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .log
            .iter()
            .filter(|l| &l.src == src && l.kind == kind)
            .count()
    }

    /// A mailbox for a party that is not a router: whatever is sent to it
    /// arrives on the returned receiver as an L3 event.
    fn mailbox(&self, id: NodeId) -> mpsc::Receiver<SessionEvent> {
        let (tx, rx) = mpsc::channel(256);
        self.inner.lock().unwrap().links.insert(
            id,
            Link {
                events: tx,
                epoch: Epoch::first(),
                up: true,
            },
        );
        rx
    }

    /// Delivers a frame to `dst` as if `src` had sent it, bypassing the log.
    fn inject(&self, src: NodeId, dst: NodeId, frame: &E2eFrame) {
        self.deliver(src, dst, E2E_PROTO_TAG, 0, frame.encode());
    }
}

struct TestNode {
    net: Net,
    party_id: NodeId,
    handle: RouterHandle,
    ready: mpsc::UnboundedReceiver<SessionReady>,
    passthrough: mpsc::Receiver<SessionEvent>,
    attachment: tokio::sync::watch::Receiver<Option<Epoch>>,
    events: mpsc::Sender<SessionEvent>,
    task: JoinHandle<()>,
    wire: JoinHandle<()>,
}

impl TestNode {
    async fn next_ready(&mut self) -> SessionReady {
        timeout(Duration::from_secs(5), self.ready.recv())
            .await
            .expect("a session should have come up")
            .expect("the router is running")
    }

    /// Tells the router it is attached at `epoch` and waits until it has
    /// processed that: it echoes every `Attached` and `Detached` on
    /// `passthrough` after handling it, which makes a deterministic
    /// barrier.
    async fn attach(&mut self, epoch: Epoch) {
        if let Some(link) = self.net.inner.lock().unwrap().links.get_mut(&self.party_id) {
            link.epoch = epoch;
        }
        self.events
            .send(SessionEvent::Attached {
                epoch,
                limits: LIMITS,
            })
            .await
            .unwrap();
        self.barrier().await;
    }

    async fn detach(&mut self, epoch: Epoch) {
        self.events
            .send(SessionEvent::Detached { epoch })
            .await
            .unwrap();
        self.barrier().await;
    }

    async fn barrier(&mut self) {
        let echoed = timeout(Duration::from_secs(5), self.passthrough.recv())
            .await
            .expect("the router echoes attach and detach events")
            .unwrap();
        assert!(matches!(
            echoed,
            SessionEvent::Attached { .. } | SessionEvent::Detached { .. }
        ));
    }
}

/// A router for `party` over `stores`, attached to `net` at the first
/// epoch.
async fn node(net: &Net, party: &Party, stores: &Stores) -> TestNode {
    let (events_tx, events_rx) = mpsc::channel(1024);
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<OutboundSend>(1024);
    net.inner.lock().unwrap().links.insert(
        party.id,
        Link {
            events: events_tx.clone(),
            epoch: Epoch::first(),
            up: true,
        },
    );
    let config = RouterConfig::new(
        party.identity(),
        net.relay,
        stores.policies.clone(),
        stores.rosters.clone(),
        SendBudgets::new(),
    )
    .unwrap();
    let parts = new_router(config, outbound_tx, events_rx);
    let task = tokio::spawn(parts.task);

    let wire_net = net.clone();
    let src = party.id;
    let wire = tokio::spawn(async move {
        while let Some(request) = outbound_rx.recv().await {
            let kind = match E2eFrame::decode(&request.payload) {
                Ok(E2eFrame::Init { .. }) => "init",
                Ok(E2eFrame::Resp { .. }) => "resp",
                Ok(E2eFrame::Data { .. }) => "data",
                Err(_) => "other",
            };
            wire_net.inner.lock().unwrap().log.push(Logged {
                src,
                dst: request.dst,
                kind,
                payload: request.payload.clone(),
            });
            let _ = request.outcome.send(EnqueueOutcome::Accepted);
            wire_net.deliver(
                src,
                request.dst,
                request.e2e_proto,
                request.flags,
                request.payload,
            );
        }
    });

    let mut node = TestNode {
        net: net.clone(),
        party_id: party.id,
        handle: parts.handle,
        ready: parts.ready,
        passthrough: parts.passthrough,
        attachment: parts.attachment,
        events: events_tx,
        task,
        wire,
    };
    node.attach(Epoch::first()).await;
    node
}

async fn ensure(
    node: &TestNode,
    peer: NodeId,
    network: NetworkId,
) -> Result<L4SessionHandle, EnsureError> {
    timeout(
        Duration::from_secs(120),
        node.handle.ensure_session(peer, network),
    )
    .await
    .expect("ensure_session must finish")
}

/// Opens a stream on `from` and accepts it on `to`'s acceptor, then moves
/// bytes both ways: the proof that a session really carries data end to
/// end, through the table's routing, in both directions.
async fn exchange_bytes(
    from: &L4SessionHandle,
    from_acceptor: &mut L4SessionAcceptor,
    to_acceptor: &mut L4SessionAcceptor,
) {
    let mut opened = from.open_stream().await.unwrap();
    opened.write_all(b"ping").await.unwrap();
    let mut accepted = timeout(Duration::from_secs(5), to_acceptor.accept())
        .await
        .expect("the peer must see the stream")
        .expect("the session is alive");
    let mut buf = [0u8; 4];
    accepted.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    accepted.write_all(b"pong").await.unwrap();
    opened.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    let _ = from_acceptor; // kept in the signature for symmetry with the callers
}

// ----------------------------------------------------------------------
// A remote peer played by hand
// ----------------------------------------------------------------------

/// A party that is not a router: the test sends its frames itself and
/// reads what the routers send it, to put a handshake in any state it
/// likes (an `init` with nothing after it, a `resp` that lies about the
/// protocols it speaks, ...).
struct Manual {
    party: Party,
    mailbox: mpsc::Receiver<SessionEvent>,
}

impl Manual {
    fn new(net: &Net, party: Party) -> Self {
        let mailbox = net.mailbox(party.id);
        Self { party, mailbox }
    }

    /// The next L4 frame a router sent this party, and from whom.
    async fn next_frame(&mut self) -> (NodeId, E2eFrame) {
        loop {
            let event = timeout(Duration::from_secs(5), self.mailbox.recv())
                .await
                .expect("a router should have sent this party a frame")
                .expect("the mailbox is open");
            if let SessionEvent::Record { record, .. } = event
                && let Record::Recv { src, payload, .. } = *record
                && let Ok(frame) = E2eFrame::decode(&payload)
            {
                return (src, frame);
            }
        }
    }

    /// An `init` to `responder` in `network`, under `index`.
    fn init(
        &self,
        responder: &Party,
        network: NetworkId,
        index: u32,
    ) -> (E2eInitiatorHandshake, E2eFrame) {
        E2eInitiatorHandshake::start(
            &self.party.x25519_private,
            &responder.x25519_public,
            network,
            self.party.id,
            responder.id,
            index,
        )
        .unwrap()
    }

    /// Completes `hs` with `resp` and returns the transport and the
    /// responder's index (the `receiver_index` of every frame sent to it).
    fn finish(hs: E2eInitiatorHandshake, resp: &E2eFrame) -> (E2eTransport, u32) {
        let E2eFrame::Resp { sender_index, .. } = resp else {
            panic!("not a resp: {resp:?}");
        };
        let (transport, _payload, _static) = hs.finish(resp, 65_535).unwrap();
        (transport, *sender_index)
    }
}

fn data_frame(transport: &mut E2eTransport, receiver_index: u32, body: &E2eDataBody) -> E2eFrame {
    match transport.encrypt_data(body).unwrap() {
        E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } => E2eFrame::Data {
            receiver_index,
            counter,
            ciphertext,
        },
        other => panic!("encrypt_data produced {other:?}"),
    }
}

// ----------------------------------------------------------------------
// Scenarios
// ----------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_session_comes_up_between_two_nodes_and_carries_bytes_both_ways() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    let mut nb = node(&net, &b, &stores).await;

    let handle = ensure(&na, b.id, w.network)
        .await
        .expect("the handshake succeeds");
    assert_eq!(handle.peer(), b.id);

    let mut ready_a = na.next_ready().await;
    let mut ready_b = nb.next_ready().await;
    assert_eq!(ready_a.role, Role::Initiator);
    assert_eq!(ready_a.peer, b.id);
    assert_eq!(ready_a.network_id, w.network);
    assert_eq!(ready_b.role, Role::Responder);
    assert_eq!(ready_b.peer, a.id);
    // Only the initiator learns the peer's document sequence numbers.
    assert_eq!(ready_a.peer_roster_seq, Some(1));
    assert_eq!(ready_a.peer_policy_seq, Some(1));
    assert_eq!(ready_b.peer_roster_seq, None);

    exchange_bytes(
        &ready_a.handle,
        &mut ready_a.acceptor,
        &mut ready_b.acceptor,
    )
    .await;
    // And the other way: B opens a stream on its responder-side session,
    // which only works once the first record promoted it.
    exchange_bytes(
        &ready_b.handle,
        &mut ready_b.acceptor,
        &mut ready_a.acceptor,
    )
    .await;

    assert_eq!(net.count_from(&a.id, "init"), 1);
    assert_eq!(net.count_from(&b.id, "resp"), 1);
}

#[tokio::test(start_paused = true)]
async fn the_responder_reuses_the_session_instead_of_starting_a_second_one() {
    let w = world();
    let (a, b) = (party(), party());
    // Both directions are granted, so B could dial A if it wanted to.
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b), w.grant(&b, &a)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let nb = node(&net, &b, &stores).await;

    ensure(&na, b.id, w.network).await.unwrap();
    // A's first record has reached B by now (yamux sends one at once), so
    // B's responder-side session was promoted.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let from_b = ensure(&nb, a.id, w.network).await.unwrap();
    assert_eq!(from_b.peer(), a.id);
    assert_eq!(net.count_from(&b.id, "init"), 0, "B must not have dialed A");
    assert_eq!(net.count("init"), 1);
}

#[tokio::test(start_paused = true)]
async fn concurrent_callers_share_one_handshake() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let _nb = node(&net, &b, &stores).await;

    let (first, second, third) = tokio::join!(
        ensure(&na, b.id, w.network),
        ensure(&na, b.id, w.network),
        ensure(&na, b.id, w.network)
    );
    first.unwrap();
    second.unwrap();
    third.unwrap();
    assert_eq!(
        net.count_from(&a.id, "init"),
        1,
        "one init for three callers"
    );
}

#[tokio::test(start_paused = true)]
async fn a_peer_with_no_cert_in_our_policy_cannot_be_dialed() {
    let w = world();
    let (a, b, stranger) = (party(), party(), party());
    let stores = w.stores(&[&a, &b], vec![]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    assert_eq!(
        ensure(&na, stranger.id, w.network).await.err(),
        Some(EnsureError::UnknownPeer)
    );
    assert_eq!(
        ensure(&na, a.id, w.network).await.err(),
        Some(EnsureError::SelfPeer)
    );
    assert_eq!(net.count("init"), 0, "nothing goes on the wire");
}

#[tokio::test(start_paused = true)]
async fn a_member_with_no_grant_gets_the_handshake_and_then_close_no_grant() {
    let w = world();
    let (a, b) = (party(), party());
    // Both are members; nobody has a grant.
    let stores = w.stores(&[&a, &b], vec![]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    let mut nb = node(&net, &b, &stores).await;

    ensure(&na, b.id, w.network)
        .await
        .expect("the handshake itself succeeds");
    let mut ready_a = na.next_ready().await;
    let reason = timeout(Duration::from_secs(5), ready_a.acceptor.closed())
        .await
        .expect("the session must end");
    assert!(
        matches!(
            reason.as_ref(),
            EndReason::PeerClosed {
                code: ErrorCode::NoGrant,
                ..
            }
        ),
        "{reason:?}"
    );
    // B reports no session to serve.
    assert!(
        timeout(Duration::from_millis(200), nb.ready.recv())
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn when_both_sides_initiate_at_once_the_lower_node_ids_session_is_the_one_kept() {
    let w = world();
    let (p, q) = (party(), party());
    let (low, high) = if p.id.as_ref() < q.id.as_ref() {
        (p, q)
    } else {
        (q, p)
    };
    let stores = w.stores(
        &[&low, &high],
        vec![w.grant(&low, &high), w.grant(&high, &low)],
    );
    let net = Net::new();
    let mut n_low = node(&net, &low, &stores).await;
    let mut n_high = node(&net, &high, &stores).await;

    // Both `init`s are out before either arrives.
    net.hold();
    let from_low = {
        let handle = n_low.handle.clone();
        let (peer, network) = (high.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    let from_high = {
        let handle = n_high.handle.clone();
        let (peer, network) = (low.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    while net.count("init") < 2 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    net.release();

    let low_handle = timeout(Duration::from_secs(60), from_low)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let high_handle = timeout(Duration::from_secs(60), from_high)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(low_handle.peer(), high.id);
    assert_eq!(high_handle.peer(), low.id);

    // One session each, the lower node's: it initiated, the higher answered.
    let mut ready_low = n_low.next_ready().await;
    let mut ready_high = n_high.next_ready().await;
    assert_eq!(ready_low.role, Role::Initiator);
    assert_eq!(ready_high.role, Role::Responder);
    assert!(
        timeout(Duration::from_millis(300), n_low.ready.recv())
            .await
            .is_err()
    );
    assert!(
        timeout(Duration::from_millis(300), n_high.ready.recv())
            .await
            .is_err()
    );
    assert_eq!(
        net.count_from(&low.id, "resp"),
        0,
        "the lower node never answered"
    );
    assert_eq!(net.count_from(&high.id, "resp"), 1);

    // And the session both callers got is the one that works.
    exchange_bytes(
        &low_handle,
        &mut ready_low.acceptor,
        &mut ready_high.acceptor,
    )
    .await;
    exchange_bytes(
        &high_handle,
        &mut ready_high.acceptor,
        &mut ready_low.acceptor,
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_restarted_peer_replaces_the_session_once_its_first_record_arrives() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b), w.grant(&b, &a)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let mut nb = node(&net, &b, &stores).await;

    ensure(&na, b.id, w.network).await.unwrap();
    let mut old_at_b = nb.next_ready().await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // A "restarts": its router and everything it held are gone, and a fresh
    // one with the same identity starts from nothing.
    na.task.abort();
    na.wire.abort();
    drop(na);
    let mut na2 = node(&net, &a, &stores).await;
    let handle = ensure(&na2, b.id, w.network).await.unwrap();
    let mut new_at_a = na2.next_ready().await;
    let mut new_at_b = nb.next_ready().await;
    assert_eq!(new_at_b.role, Role::Responder);

    // B kept the old session until the new one's first record decrypted,
    // then ended it.
    let reason = timeout(Duration::from_secs(5), old_at_b.acceptor.closed())
        .await
        .expect("the replaced session must end");
    assert!(
        matches!(reason.as_ref(), EndReason::ClosedLocally(None)),
        "{reason:?}"
    );

    // B's own `ensure_session` now returns the new session, and it works.
    let from_b = ensure(&nb, a.id, w.network).await.unwrap();
    exchange_bytes(&from_b, &mut new_at_b.acceptor, &mut new_at_a.acceptor).await;
    exchange_bytes(&handle, &mut new_at_a.acceptor, &mut new_at_b.acceptor).await;
    assert_eq!(net.count_from(&b.id, "init"), 0, "B never dialed A");
}

#[tokio::test(start_paused = true)]
async fn an_eleventh_init_in_a_minute_from_one_peer_gets_no_answer() {
    let w = world();
    let (b, m) = (party(), party());
    let stores = w.stores(&[&b, &m], vec![w.grant(&m, &b)]);
    let net = Net::new();
    let _nb = node(&net, &b, &stores).await;
    let mut manual = Manual::new(&net, m);

    for index in 1..=11u32 {
        let (_hs, init) = manual.init(&b, w.network, index);
        net.inject(manual.party.id, b.id, &init);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        net.count_from(&b.id, "resp"),
        10,
        "the limit is ten a minute"
    );

    tokio::time::advance(Duration::from_secs(61)).await;
    let (_hs, init) = manual.init(&b, w.network, 12);
    net.inject(manual.party.id, b.id, &init);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(net.count_from(&b.id, "resp"), 11, "and it recovers");
    let _ = manual.next_frame().await;
}

#[tokio::test(start_paused = true)]
async fn an_init_from_the_attached_relays_own_node_id_is_refused() {
    let w = world();
    let (b, relay_party) = (party(), party());
    // The relay's NodeId is a perfectly valid member with a grant: only
    // the rule about the relay refuses it.
    let stores = w.stores(&[&b, &relay_party], vec![w.grant(&relay_party, &b)]);
    let net = Net::with_relay(relay_party.id);
    let _nb = node(&net, &b, &stores).await;
    let manual = Manual::new(&net, relay_party);

    let (_hs, init) = manual.init(&b, w.network, 1);
    net.inject(manual.party.id, b.id, &init);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&b.id, "resp"), 0);
}

#[tokio::test(start_paused = true)]
async fn an_init_from_a_non_member_or_for_an_unknown_network_gets_no_answer() {
    let w = world();
    let (b, outsider, member) = (party(), party(), party());
    let stores = w.stores(&[&b, &member], vec![w.grant(&member, &b)]);
    let net = Net::new();
    let mut nb = node(&net, &b, &stores).await;
    let outsider = Manual::new(&net, outsider);
    let member = Manual::new(&net, member);

    // Not in Policy or Roster: no cert, so nothing to admit it on.
    let (_hs, init) = outsider.init(&b, w.network, 1);
    net.inject(outsider.party.id, b.id, &init);
    // A member, but naming a network we hold no documents for.
    let (_hs, init) = member.init(&b, NetworkId::from([0x42; 32]), 2);
    net.inject(member.party.id, b.id, &init);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&b.id, "resp"), 0);
    assert!(nb.ready.try_recv().is_err());

    // The member in the right network is answered, so it was not the
    // setup that silenced the others.
    let (_hs, init) = member.init(&b, w.network, 3);
    net.inject(member.party.id, b.id, &init);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&b.id, "resp"), 1);
}

#[tokio::test(start_paused = true)]
async fn data_is_delivered_only_from_the_sessions_own_peer() {
    let w = world();
    let (a, b, c) = (party(), party(), party());
    let stores = w.stores(&[&a, &b, &c], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let mut nb = node(&net, &b, &stores).await;
    let _mailbox_c = Manual::new(&net, c.clone_for_test());

    ensure(&na, b.id, w.network).await.unwrap();
    let mut at_b = nb.next_ready().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let first_data = net
        .frames("data")
        .into_iter()
        .find(|f| f.src == a.id && f.dst == b.id)
        .expect("A sent B a data record");
    let replay = E2eFrame::decode(&first_data.payload).unwrap();

    // The same bytes from a third party are not a session's traffic and
    // change nothing...
    net.inject(c.id, b.id, &replay);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        timeout(Duration::from_millis(200), at_b.acceptor.closed())
            .await
            .is_err(),
        "still alive"
    );

    // The datagram class is not served in phase 1: even the right bytes
    // from the right peer, flagged droppable, are dropped, not delivered.
    net.deliver(a.id, b.id, E2E_PROTO_TAG, 0x01, replay.encode());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        timeout(Duration::from_millis(200), at_b.acceptor.closed())
            .await
            .is_err(),
        "a droppable-flagged replay must not reach the session"
    );

    // ...while the same record unflagged from its peer is a counter
    // violation and ends the session, which also shows the right source
    // was routed.
    net.inject(a.id, b.id, &replay);
    let reason = timeout(Duration::from_secs(5), at_b.acceptor.closed())
        .await
        .expect("a replay from the peer ends the session");
    assert!(
        matches!(reason.as_ref(), EndReason::Decrypt(_)),
        "{reason:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn records_that_are_not_ours_pass_through_and_the_rest_are_dropped() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![]);
    let net = Net::new();
    let mut nb = node(&net, &b, &stores).await;

    // Another protocol's RECV, and a non-RECV record: handed on.
    net.deliver(a.id, b.id, 0x02, 0, vec![1, 2, 3]);
    let passed = timeout(Duration::from_secs(1), nb.passthrough.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        passed,
        SessionEvent::Record { record, .. } if matches!(*record, Record::Recv { e2e_proto: 0x02, .. })
    ));

    // Ours but droppable (the datagram class, phase 2), undecodable, or
    // for a session that does not exist: dropped without a trace.
    let init = E2eFrame::Data {
        receiver_index: 99,
        counter: 0,
        ciphertext: vec![0; 32],
    };
    net.deliver(a.id, b.id, E2E_PROTO_TAG, 0x01, init.encode());
    net.deliver(a.id, b.id, E2E_PROTO_TAG, 0, vec![0xFF; 7]);
    net.inject(a.id, b.id, &init);
    assert!(
        timeout(Duration::from_millis(300), nb.passthrough.recv())
            .await
            .is_err()
    );
    assert!(nb.ready.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn detaching_ends_the_sessions_fails_the_waiters_and_the_next_attachment_starts_over() {
    let w = world();
    let (a, b, c) = (party(), party(), party());
    let stores = w.stores(&[&a, &b, &c], vec![w.grant(&a, &b), w.grant(&a, &c)]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    let mut nb = node(&net, &b, &stores).await;
    let _c = Manual::new(&net, c.clone_for_test());

    ensure(&na, b.id, w.network).await.unwrap();
    let mut at_a = na.next_ready().await;
    let _at_b_old = nb.next_ready().await;

    // A request that cannot be answered (C never replies) is waiting when
    // the attachment ends.
    let waiting = {
        let handle = na.handle.clone();
        let (peer, network) = (c.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    na.detach(Epoch::first()).await;
    assert_eq!(
        timeout(Duration::from_secs(5), waiting)
            .await
            .unwrap()
            .unwrap()
            .err(),
        Some(EnsureError::Detached)
    );
    let reason = timeout(Duration::from_secs(5), at_a.acceptor.closed())
        .await
        .expect("the session ends with its attachment");
    assert!(
        matches!(reason.as_ref(), EndReason::EpochEnded),
        "{reason:?}"
    );
    assert_eq!(
        ensure(&na, b.id, w.network).await.err(),
        Some(EnsureError::NotAttached)
    );

    // The next attachment gets a fresh handshake (which B, still holding
    // the old session, takes as a replacement) and a working session.
    na.attach(Epoch::first().next()).await;
    let handle = ensure(&na, b.id, w.network).await.unwrap();
    let mut new_at_a = na.next_ready().await;
    let mut new_at_b = nb.next_ready().await;
    exchange_bytes(&handle, &mut new_at_a.acceptor, &mut new_at_b.acceptor).await;
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_init_is_retried_twice_and_then_the_caller_is_told() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let _nb = node(&net, &b, &stores).await;
    net.set_up(&b.id, false);

    let started = tokio::time::Instant::now();
    assert_eq!(
        ensure(&na, b.id, w.network).await.err(),
        Some(EnsureError::Timeout)
    );
    let took = started.elapsed();
    assert_eq!(net.count_from(&a.id, "init"), HANDSHAKE_ATTEMPTS as usize);
    assert!(
        (Duration::from_secs(29)..Duration::from_secs(35)).contains(&took),
        "three attempts of the table's 10 s pending timeout: {took:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_candidate_that_never_sees_a_record_expires_and_fails_whoever_waited_for_it() {
    let w = world();
    let (b, m) = (party(), party());
    let stores = w.stores(&[&b, &m], vec![w.grant(&m, &b), w.grant(&b, &m)]);
    let net = Net::new();
    let mut nb = node(&net, &b, &stores).await;
    let mut manual = Manual::new(&net, m);

    let (_hs, init) = manual.init(&b, w.network, 1);
    net.inject(manual.party.id, b.id, &init);
    let _resp = manual.next_frame().await;
    let mut at_b = nb.next_ready().await;

    // B wants a session to M: M's own `init` already created a candidate,
    // so it waits for that instead of dialing.
    let waiting = {
        let handle = nb.handle.clone();
        let (peer, network) = (manual.party.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&b.id, "init"), 0);

    // M never sends a record.
    let outcome = timeout(Duration::from_secs(120), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.err(), Some(EnsureError::SessionEnded));
    let reason = timeout(Duration::from_secs(5), at_b.acceptor.closed())
        .await
        .unwrap();
    assert!(
        matches!(reason.as_ref(), EndReason::ClosedLocally(None)),
        "{reason:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_waiter_on_a_candidate_gets_its_handle_when_the_first_record_arrives() {
    let w = world();
    let (b, m) = (party(), party());
    let stores = w.stores(&[&b, &m], vec![w.grant(&m, &b), w.grant(&b, &m)]);
    let net = Net::new();
    let mut nb = node(&net, &b, &stores).await;
    let mut manual = Manual::new(&net, m);

    let (hs, init) = manual.init(&b, w.network, 1);
    net.inject(manual.party.id, b.id, &init);
    let (_, resp) = manual.next_frame().await;
    let _at_b = nb.next_ready().await;
    let (mut transport, b_index) = Manual::finish(hs, &resp);

    let waiting = {
        let handle = nb.handle.clone();
        let (peer, network) = (manual.party.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !waiting.is_finished(),
        "nothing to hand out before the first record"
    );

    let first = data_frame(&mut transport, b_index, &E2eDataBody::Keep);
    net.inject(manual.party.id, b.id, &first);
    let handle = timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(handle.peer(), manual.party.id);
    assert_eq!(net.count_from(&b.id, "init"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_resp_that_does_not_offer_our_protocol_is_refused_as_a_downgrade() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let mut manual_b = Manual::new(&net, b.clone_for_test());

    let asking = {
        let handle = na.handle.clone();
        let (peer, network) = (b.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    let (src, init) = manual_b.next_frame().await;
    assert_eq!(src, a.id);
    // B answers honestly in every respect except the one that matters.
    let hs = E2eResponderHandshake::start(&b.x25519_private, a.id, b.id, &init).unwrap();
    let (_transport, resp) = hs
        .finish(b.cert.clone(), 1, 1, vec![0x02], 4242, 65_535)
        .unwrap();
    net.inject(b.id, a.id, &resp);
    let outcome = timeout(Duration::from_secs(5), asking)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.err(), Some(EnsureError::Refused));
}

#[tokio::test(start_paused = true)]
async fn a_resp_from_the_wrong_source_is_ignored_and_the_real_one_still_completes() {
    let w = world();
    let (a, b, c) = (party(), party(), party());
    let stores = w.stores(&[&a, &b, &c], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let mut manual_b = Manual::new(&net, b.clone_for_test());
    let _c = Manual::new(&net, c.clone_for_test());

    let asking = {
        let handle = na.handle.clone();
        let (peer, network) = (b.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    let (_, init) = manual_b.next_frame().await;
    let hs = E2eResponderHandshake::start(&b.x25519_private, a.id, b.id, &init).unwrap();
    let (_transport, resp) = hs
        .finish(b.cert.clone(), 1, 1, vec![E2E_PROTO_TAG], 4242, 65_535)
        .unwrap();

    // The right bytes from the wrong sender: not B's answer.
    net.inject(c.id, a.id, &resp);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!asking.is_finished());
    // From B itself it completes.
    net.inject(b.id, a.id, &resp);
    let handle = timeout(Duration::from_secs(5), asking)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(handle.peer(), b.id);
}

#[tokio::test(start_paused = true)]
async fn a_record_tagged_with_an_attachment_that_has_ended_is_dropped() {
    let w = world();
    let (b, m) = (party(), party());
    let stores = w.stores(&[&b, &m], vec![w.grant(&m, &b)]);
    let net = Net::new();
    let mut nb = node(&net, &b, &stores).await;
    let manual = Manual::new(&net, m);

    nb.detach(Epoch::first()).await;
    let second = Epoch::first().next();
    nb.attach(second).await;

    // A perfectly good `init`, but tagged with the epoch that ended.
    let (_hs, init) = manual.init(&b, w.network, 1);
    let stale = SessionEvent::Record {
        epoch: Epoch::first(),
        record: Box::new(Record::Recv {
            src: manual.party.id,
            e2e_proto: E2E_PROTO_TAG,
            flags: 0,
            payload: init.encode(),
        }),
    };
    nb.events.send(stale).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&b.id, "resp"), 0);

    // The same `init` under the current epoch is answered.
    net.inject(manual.party.id, b.id, &init);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&b.id, "resp"), 1);
}

#[tokio::test(start_paused = true)]
async fn a_resp_whose_cert_is_not_the_dialed_nodes_is_refused() {
    let w = world();
    let (a, b, c) = (party(), party(), party());
    let stores = w.stores(&[&a, &b, &c], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let mut manual_b = Manual::new(&net, b.clone_for_test());

    let asking = {
        let handle = na.handle.clone();
        let (peer, network) = (b.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    let (_, init) = manual_b.next_frame().await;
    // B answers with C's (valid, member) certificate: the wire-consistency
    // check on what the responder claims about itself fails.
    let hs = E2eResponderHandshake::start(&b.x25519_private, a.id, b.id, &init).unwrap();
    let (_transport, resp) = hs
        .finish(c.cert.clone(), 1, 1, vec![E2E_PROTO_TAG], 4242, 65_535)
        .unwrap();
    net.inject(b.id, a.id, &resp);
    let outcome = timeout(Duration::from_secs(5), asking)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome.err(), Some(EnsureError::Refused));
}

/// An [`Engine`] driven by hand, with its three outputs.
struct Driven {
    engine: Engine,
    outbound: mpsc::Receiver<OutboundSend>,
    _ready: mpsc::UnboundedReceiver<SessionReady>,
    _notices: mpsc::UnboundedReceiver<(u64, SessionNotice)>,
}

fn driven(party: &Party, stores: &Stores, relay: NodeId, index: u32) -> Driven {
    // Every session this engine allocates gets the same index, so that the
    // second one reuses the first one's.
    driven_with(party, stores, relay, 1024, move || index)
}

/// [`driven`], with an outbound channel of `capacity` and its own source of
/// session indices.
fn driven_with(
    party: &Party,
    stores: &Stores,
    relay: NodeId,
    capacity: usize,
    index_source: impl FnMut() -> u32 + Send + 'static,
) -> Driven {
    let (outbound_tx, outbound) = mpsc::channel(capacity);
    let (ready_tx, ready) = mpsc::unbounded_channel();
    let (notices_tx, notices) = mpsc::unbounded_channel();
    let config = RouterConfig::new(
        party.identity(),
        relay,
        stores.policies.clone(),
        stores.rosters.clone(),
        SendBudgets::new(),
    )
    .unwrap();
    let (attachment_tx, _) = tokio::sync::watch::channel(None);
    let engine = Engine::new(
        config,
        outbound_tx,
        ready_tx,
        notices_tx,
        attachment_tx,
        index_source,
    );
    Driven {
        engine,
        outbound,
        _ready: ready,
        _notices: notices,
    }
}

#[tokio::test]
async fn a_late_notice_from_an_ended_session_cannot_touch_the_one_that_reused_its_index() {
    let w = world();
    let (b, m) = (party(), party());
    let stores = w.stores(&[&b, &m], vec![w.grant(&m, &b)]);
    let mut d = driven(&b, &stores, NodeId::from([0xAA; 32]), 7);
    let manual = Manual::new(&Net::new(), m);
    d.engine.on_attached(Epoch::first(), LIMITS);
    let recv = |frame: &E2eFrame| Record::Recv {
        src: manual.party.id,
        e2e_proto: E2E_PROTO_TAG,
        flags: 0,
        payload: frame.encode(),
    };

    // The first session gets index 7 and, a moment later, ends.
    let (_hs, init) = manual.init(&b, w.network, 1);
    assert!(
        d.engine
            .on_record(Epoch::first(), recv(&init), Now::capture())
            .is_none()
    );
    let first = d
        .engine
        .table
        .get(7)
        .expect("a session at index 7")
        .generation;
    d.engine.on_notice(tag_of(first, 7), SessionNotice::Ended);
    assert!(d.engine.table.get(7).is_none(), "its own notice removes it");

    // The next one reuses index 7 under a new generation.
    let (_hs, init) = manual.init(&b, w.network, 2);
    assert!(
        d.engine
            .on_record(Epoch::first(), recv(&init), Now::capture())
            .is_none()
    );
    let second = d
        .engine
        .table
        .get(7)
        .expect("a session at index 7 again")
        .generation;
    assert_ne!(first, second);

    // The first one's `Ended`, arriving late (or twice), is not about it.
    d.engine.on_notice(tag_of(first, 7), SessionNotice::Ended);
    assert!(
        d.engine.table.get(7).is_some(),
        "a notice for generation {first} removed the session of generation {second}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_attachment_watch_follows_attached_and_detached() {
    let w = world();
    let a = party();
    let stores = w.stores(&[&a], vec![]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    assert_eq!(*na.attachment.borrow(), Some(Epoch::first()));

    na.detach(Epoch::first()).await;
    assert_eq!(*na.attachment.borrow(), None);

    let second = Epoch::first().next();
    na.attach(second).await;
    assert_eq!(*na.attachment.borrow(), Some(second));

    // A `Detached` for an attachment that is no longer the current one
    // changes nothing.
    na.detach(Epoch::first()).await;
    assert_eq!(*na.attachment.borrow(), Some(second));
}

// ----------------------------------------------------------------------
// The opus review of L4h6 and L4h7 (2026-10-09)
// ----------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_caller_waiting_on_candidates_that_keep_being_replaced_is_told_to_give_up() {
    // A peer that sends a fresh `init` every 25 s and never a record keeps
    // a fresh candidate in the slot (each replaces the last and restarts
    // its 30 s timer), so a caller waiting on that slot would wait for as
    // long as they keep coming. The caller's own deadline bounds it.
    let w = world();
    let (b, m) = (party(), party());
    let stores = w.stores(&[&b, &m], vec![w.grant(&m, &b), w.grant(&b, &m)]);
    let net = Net::new();
    let nb = node(&net, &b, &stores).await;
    let mut manual = Manual::new(&net, m);

    let (_hs, init) = manual.init(&b, w.network, 1);
    net.inject(manual.party.id, b.id, &init);
    let _ = manual.next_frame().await;

    let waiting = {
        let handle = nb.handle.clone();
        let (peer, network) = (manual.party.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    for index in 2..=5 {
        tokio::time::sleep(Duration::from_secs(25)).await;
        let (_hs, init) = manual.init(&b, w.network, index);
        net.inject(manual.party.id, b.id, &init);
        let _ = manual.next_frame().await;
    }
    let outcome = timeout(Duration::from_secs(1), waiting)
        .await
        .expect("the caller must have been answered long ago")
        .unwrap();
    assert_eq!(outcome.err(), Some(EnsureError::Timeout));
    assert_eq!(net.count_from(&b.id, "init"), 0, "B never dialed M itself");
}

#[tokio::test(start_paused = true)]
async fn a_caller_that_stopped_listening_does_not_keep_an_initiation_alive() {
    let w = world();
    let (a, c) = (party(), party());
    let stores = w.stores(&[&a, &c], vec![w.grant(&a, &c)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;
    let _silent = Manual::new(&net, c.clone_for_test());

    let asking = {
        let handle = na.handle.clone();
        let (peer, network) = (c.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&a.id, "init"), 1);
    asking.abort();
    let _ = asking.await;

    // The first `init` times out at 10 s; with nobody left to want it, no
    // second one is sent.
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(net.count_from(&a.id, "init"), 1, "no retry for nobody");
}

#[tokio::test(start_paused = true)]
async fn an_init_the_relay_delivers_twice_is_answered_once() {
    // Answering the copy would bring up a second candidate that supersedes
    // the first, while the initiator completes with the first `resp` and
    // is left holding a session the responder no longer routes.
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    let mut nb = node(&net, &b, &stores).await;

    net.hold();
    let asking = {
        let handle = na.handle.clone();
        let (peer, network) = (b.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    while net.count("init") < 1 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let init = E2eFrame::decode(&net.frames("init")[0].payload).unwrap();
    net.inject(a.id, b.id, &init); // right behind the original
    net.release();

    let handle = timeout(Duration::from_secs(5), asking)
        .await
        .unwrap()
        .unwrap()
        .expect("the handshake succeeds");
    let mut at_a = na.next_ready().await;
    let mut at_b = nb.next_ready().await;
    assert_eq!(net.count_from(&b.id, "resp"), 1, "the copy got no answer");
    exchange_bytes(&handle, &mut at_a.acceptor, &mut at_b.acceptor).await;
    assert!(nb.ready.try_recv().is_err(), "and no second session");
}

#[tokio::test(start_paused = true)]
async fn replaying_the_init_of_a_live_session_brings_up_nothing() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    let mut nb = node(&net, &b, &stores).await;

    let handle = ensure(&na, b.id, w.network).await.unwrap();
    let mut at_a = na.next_ready().await;
    let mut at_b = nb.next_ready().await;
    exchange_bytes(&handle, &mut at_a.acceptor, &mut at_b.acceptor).await;
    let init = E2eFrame::decode(&net.frames("init")[0].payload).unwrap();

    // The session is current by now; the recording is replayed anyway.
    net.inject(a.id, b.id, &init);
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(net.count_from(&b.id, "resp"), 1, "the replay got no answer");
    assert!(nb.ready.try_recv().is_err());
    exchange_bytes(&handle, &mut at_a.acceptor, &mut at_b.acceptor).await;
}

#[tokio::test(start_paused = true)]
async fn a_no_grant_init_does_not_abandon_our_own_valid_initiation() {
    // Both dial at once and only the higher node has a grant (on the
    // lower). The lower node's `init` wins the tie-break at the higher
    // one, which answers it no-grant. That answer must not cost the higher
    // node its own initiation: its grant was never the problem.
    let w = world();
    let (p, q) = (party(), party());
    let (low, high) = if p.id.as_ref() < q.id.as_ref() {
        (p, q)
    } else {
        (q, p)
    };
    let stores = w.stores(&[&low, &high], vec![w.grant(&high, &low)]);
    let net = Net::new();
    let mut n_low = node(&net, &low, &stores).await;
    let mut n_high = node(&net, &high, &stores).await;

    net.hold();
    let from_low = {
        let handle = n_low.handle.clone();
        let (peer, network) = (high.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    let from_high = {
        let handle = n_high.handle.clone();
        let (peer, network) = (low.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    while net.count("init") < 2 {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    net.release();

    // The lower node's own call completes (it won the tie-break, got the
    // handshake) and its session is then closed `no_grant`.
    let low_outcome = timeout(Duration::from_secs(60), from_low)
        .await
        .unwrap()
        .unwrap();
    assert!(low_outcome.is_ok(), "{:?}", low_outcome.err());
    let mut ready_low = n_low.next_ready().await;
    let reason = timeout(Duration::from_secs(5), ready_low.acceptor.closed())
        .await
        .unwrap();
    assert!(
        matches!(
            reason.as_ref(),
            EndReason::PeerClosed {
                code: ErrorCode::NoGrant,
                ..
            }
        ),
        "{reason:?}"
    );

    // The higher node's call is not told its session ended: its `init` was
    // ignored by the lower node (which kept its own), so it is retried, and
    // the retry is answered.
    let high_outcome = timeout(Duration::from_secs(120), from_high)
        .await
        .unwrap()
        .unwrap();
    assert!(high_outcome.is_ok(), "{:?}", high_outcome.err());
    let mut at_high = n_high.next_ready().await;
    let mut at_low = n_low.next_ready().await;
    exchange_bytes(
        &high_outcome.unwrap(),
        &mut at_high.acceptor,
        &mut at_low.acceptor,
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_detach_of_an_attachment_that_already_ended_leaves_the_current_one_alone() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    let mut manual_b = Manual::new(&net, b.clone_for_test());

    na.detach(Epoch::first()).await;
    let second = Epoch::first().next();
    na.attach(second).await;

    let asking = {
        let handle = na.handle.clone();
        let (peer, network) = (b.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    let (_, init) = manual_b.next_frame().await;
    na.detach(Epoch::first()).await; // stale: the second epoch is the one attached
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        !asking.is_finished(),
        "a caller of the current attachment must not be told it ended"
    );
    assert_eq!(*na.attachment.borrow(), Some(second));

    // The peer answers, and the initiation, which lives under the current
    // attachment, completes.
    let hs = E2eResponderHandshake::start(&b.x25519_private, a.id, b.id, &init).unwrap();
    let (_transport, resp) = hs
        .finish(b.cert.clone(), 1, 1, vec![E2E_PROTO_TAG], 4242, 65_535)
        .unwrap();
    net.inject(b.id, a.id, &resp);
    let outcome = timeout(Duration::from_secs(5), asking)
        .await
        .unwrap()
        .unwrap();
    assert!(outcome.is_ok(), "{:?}", outcome.err());
    assert_eq!(na.next_ready().await.peer, b.id);
}

#[tokio::test(start_paused = true)]
async fn a_detach_abandons_pending_initiations_so_the_next_request_starts_fresh() {
    // Without this, a request made after the reconnect would wait on the
    // dead attachment's `init`, whose `resp` can no longer arrive, instead
    // of sending its own.
    let w = world();
    let (a, c) = (party(), party());
    let stores = w.stores(&[&a, &c], vec![w.grant(&a, &c)]);
    let net = Net::new();
    let mut na = node(&net, &a, &stores).await;
    let _silent = Manual::new(&net, c.clone_for_test());

    let first = {
        let handle = na.handle.clone();
        let (peer, network) = (c.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(net.count_from(&a.id, "init"), 1);
    na.detach(Epoch::first()).await;
    assert_eq!(first.await.unwrap().err(), Some(EnsureError::Detached));

    na.attach(Epoch::first().next()).await;
    let _second = {
        let handle = na.handle.clone();
        let (peer, network) = (c.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        net.count_from(&a.id, "init"),
        2,
        "a fresh init under the new attachment"
    );
}

#[tokio::test(start_paused = true)]
async fn a_node_that_is_not_a_member_itself_does_not_dial() {
    // The responder side already refuses when this node's own standing is
    // bad; the initiator side must not dial out from the same position.
    let w = world();
    let (me, peer) = (party(), party());
    // The documents list the peer, and not this node.
    let stores = w.stores(&[&peer], vec![w.grant(&me, &peer)]);
    let net = Net::new();
    let na = node(&net, &me, &stores).await;
    let _peer = Manual::new(&net, peer.clone_for_test());

    let outcome = ensure(&na, peer.id, w.network).await;
    assert_eq!(outcome.err(), Some(EnsureError::NotAMember));
    assert_eq!(net.count_from(&me.id, "init"), 0, "and sends nothing");
}

#[tokio::test(start_paused = true)]
async fn the_attached_relay_is_not_dialed_even_when_a_policy_lists_it() {
    let w = world();
    let (a, relay) = (party(), party());
    // The documents wrongly list the relay as a member with a cert.
    let stores = w.stores(&[&a, &relay], vec![w.grant(&a, &relay)]);
    let net = Net::with_relay(relay.id);
    let na = node(&net, &a, &stores).await;

    let outcome = ensure(&na, relay.id, w.network).await;
    assert_eq!(outcome.err(), Some(EnsureError::UnknownPeer));
    assert_eq!(net.count_from(&a.id, "init"), 0, "and sends nothing");
}

#[test]
fn a_log_throttle_lets_one_line_through_a_second_and_counts_the_rest() {
    let mut throttle = LogThrottle::new();
    let t0 = Instant::now();
    assert_eq!(throttle.allow(t0), Some(0));
    for i in 1..=3 {
        assert_eq!(throttle.allow(t0 + Duration::from_millis(100 * i)), None);
    }
    // A second after the last line written, the next one gets through and
    // says how many were held back.
    assert_eq!(throttle.allow(t0 + Duration::from_secs(1)), Some(3));
    assert_eq!(throttle.allow(t0 + Duration::from_millis(1500)), None);
    assert_eq!(throttle.allow(t0 + Duration::from_secs(2)), Some(1));
}

#[tokio::test(start_paused = true)]
async fn a_handshake_frame_the_full_outbound_channel_could_not_take_goes_out_on_a_later_tick() {
    // The session actors share the outbound channel, so with bulk
    // transfers running over a slow link it is full for stretches; a
    // `resp` or `init` lost to it would cost the peer a 10 s retry.
    let w = world();
    let (b, m, n) = (party(), party(), party());
    let stores = w.stores(&[&b, &m, &n], vec![w.grant(&m, &b), w.grant(&n, &b)]);
    let mut next = 100;
    let mut d = driven_with(&b, &stores, NodeId::from([0xAA; 32]), 1, move || {
        next += 1;
        next
    });
    let net = Net::new();
    let (manual_m, manual_n) = (Manual::new(&net, m), Manual::new(&net, n));
    d.engine.on_attached(Epoch::first(), LIMITS);
    let recv = |manual: &Manual, frame: &E2eFrame| Record::Recv {
        src: manual.party.id,
        e2e_proto: E2E_PROTO_TAG,
        flags: 0,
        payload: frame.encode(),
    };

    // M's `resp` takes the channel's only slot; N's has no room.
    let (_hs, init) = manual_m.init(&b, w.network, 1);
    assert!(
        d.engine
            .on_record(Epoch::first(), recv(&manual_m, &init), Now::capture())
            .is_none()
    );
    let (_hs, init) = manual_n.init(&b, w.network, 1);
    assert!(
        d.engine
            .on_record(Epoch::first(), recv(&manual_n, &init), Now::capture())
            .is_none()
    );
    assert_eq!(d.engine.unsent.len(), 1, "N's resp is held back, not lost");

    // Nothing happens until there is room, and a tick with the channel still
    // full keeps the frame.
    d.engine.on_tick(Now::capture());
    assert_eq!(d.engine.unsent.len(), 1);
    assert_eq!(d.outbound.try_recv().unwrap().dst, manual_m.party.id);
    d.engine.on_tick(Now::capture());
    assert!(d.engine.unsent.is_empty());
    assert_eq!(d.outbound.try_recv().unwrap().dst, manual_n.party.id);
}

#[tokio::test(start_paused = true)]
async fn held_back_frames_keep_their_order_are_bounded_and_die_with_their_attachment() {
    let w = world();
    let b = party();
    let stores = w.stores(&[&b], vec![]);
    let mut d = driven_with(&b, &stores, NodeId::from([0xAA; 32]), 1, || 7);
    d.engine.on_attached(Epoch::first(), LIMITS);
    let dst = NodeId::from([0x42; 32]);

    // One fits the channel; the rest wait, and past MAX_UNSENT the oldest go.
    let total = MAX_UNSENT + 10;
    for i in 0..=total {
        d.engine.send(dst, Epoch::first(), vec![i as u8]);
    }
    assert_eq!(d.engine.unsent.len(), MAX_UNSENT);
    let oldest_kept = d.engine.unsent.front().unwrap().payload[0];
    assert_eq!(oldest_kept as usize, total + 1 - MAX_UNSENT);

    // Draining the channel and ticking releases them in order.
    let mut seen = vec![d.outbound.try_recv().unwrap().payload[0]];
    for _ in 0..=MAX_UNSENT {
        d.engine.on_tick(Now::capture());
        while let Ok(request) = d.outbound.try_recv() {
            seen.push(request.payload[0]);
        }
    }
    assert!(d.engine.unsent.is_empty(), "each tick moves a frame on");
    assert_eq!(seen[0], 0);
    assert!(
        seen[1..].windows(2).all(|pair| pair[0] < pair[1]),
        "{seen:?}"
    );
    assert_eq!(*seen.last().unwrap() as usize, total);

    // What is still waiting when its attachment ends is of no use any more.
    d.engine.send(dst, Epoch::first(), vec![1]);
    d.engine.send(dst, Epoch::first(), vec![2]);
    assert!(!d.engine.unsent.is_empty());
    d.engine.on_detached(Epoch::first());
    assert!(d.engine.unsent.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_session_whose_peer_goes_silent_ends_and_the_next_request_starts_over() {
    // The session actor reads time through tokio's clock, so this runs on
    // the paused one: B's side must give up on a peer that has said nothing
    // for the dead-peer window, the router must forget the session, and the
    // next request must dial afresh instead of being handed a dead handle.
    let w = world();
    let (b, m) = (party(), party());
    let stores = w.stores(&[&b, &m], vec![w.grant(&m, &b), w.grant(&b, &m)]);
    let net = Net::new();
    let mut nb = node(&net, &b, &stores).await;
    let mut manual = Manual::new(&net, m);

    // M handshakes with B and sends one record, which makes the session
    // B's current one; then M says nothing more.
    let (hs, init) = manual.init(&b, w.network, 1);
    net.inject(manual.party.id, b.id, &init);
    let (_, resp) = manual.next_frame().await;
    let (mut transport, b_index) = Manual::finish(hs, &resp);
    net.inject(
        manual.party.id,
        b.id,
        &data_frame(&mut transport, b_index, &E2eDataBody::Keep),
    );
    let mut ready = nb.next_ready().await;
    // The record promoted the candidate: a request for M now finds it.
    let handle = ensure(&nb, manual.party.id, w.network).await.unwrap();
    assert_eq!(handle.peer(), manual.party.id);
    assert_eq!(net.count_from(&b.id, "init"), 0);

    let reason = timeout(Duration::from_secs(300), ready.acceptor.closed())
        .await
        .expect("a silent peer must be given up on");
    assert!(matches!(reason.as_ref(), EndReason::PeerDead), "{reason:?}");

    // Let the router handle the actor's `Ended`, then ask again.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let asking = {
        let handle = nb.handle.clone();
        let (peer, network) = (manual.party.id, w.network);
        tokio::spawn(async move { handle.ensure_session(peer, network).await })
    };
    loop {
        let (_, frame) = manual.next_frame().await;
        if matches!(frame, E2eFrame::Init { .. }) {
            break;
        }
    }
    asking.abort();
}

#[tokio::test(start_paused = true)]
async fn a_network_we_hold_no_documents_for_is_unknown_not_a_standing_problem() {
    let w = world();
    let (a, b) = (party(), party());
    let stores = w.stores(&[&a, &b], vec![w.grant(&a, &b)]);
    let net = Net::new();
    let na = node(&net, &a, &stores).await;

    let outcome = ensure(&na, b.id, NetworkId::from([0xEE; 32])).await;
    assert_eq!(outcome.err(), Some(EnsureError::UnknownPeer));
    assert_eq!(net.count_from(&a.id, "init"), 0);
}
