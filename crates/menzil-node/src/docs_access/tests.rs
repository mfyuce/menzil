//! The limits on `menzil:docs` streams and the per session handler (protocol.md 5.5), over real
//! streams: the OPEN exchange of `menzil_stream::respond_to_open` with the node's own
//! [`PolicyAuthorizer`] and [`SessionHandler`], and `docs::fetch` and `docs::push` as the opener.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use menzil_proto::{
    NetworkId, OpenBody, OpenMeta, PROTOCOL_VERSION, Policy, PolicyBody, PolicyMember, Roster,
    RosterBody, RosterMember,
};
use menzil_stream::{
    Authorizer, Mode, OpenDecision, OutboundFrames, Responded, StreamMux, initiate_open,
    respond_to_open,
};
use tokio::task::JoinHandle;

use super::*;
use crate::admission::{PolicyAuthorizer, docs_service};
use crate::docs::{bundle_to_push, fetch, push};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// ---------------------------------------------------------------- the gate

fn peer(n: u8) -> NodeId {
    NodeId::from([n; 32])
}

#[tokio::test(start_paused = true)]
async fn a_peer_has_one_docs_stream_at_a_time() {
    let gate = DocsGate::new(DocsLimits::default());
    let first = gate.try_acquire(peer(1)).expect("the first");
    assert!(gate.try_acquire(peer(1)).is_none(), "one at a time");
    assert!(
        gate.try_acquire(peer(2)).is_some(),
        "another peer is not held up"
    );
    drop(first);
    assert!(gate.try_acquire(peer(1)).is_some(), "the place came back");
}

#[tokio::test(start_paused = true)]
async fn a_docs_only_sessions_place_is_its_own_and_takes_none_of_the_peers() {
    let gate = DocsGate::new(DocsLimits::default());
    // Every place of the peer and of the node is taken by ordinary sessions...
    let taken: Vec<_> = (1..=4)
        .map(|n| gate.try_acquire(peer(n)).unwrap())
        .collect();
    assert!(gate.try_acquire(peer(5)).is_none(), "in all is full");
    // ...and docs only sessions still have theirs, one each.
    let (one, two) = (gate.new_session_key(), gate.new_session_key());
    let first = gate.try_acquire_session(one).expect("its own place");
    assert!(gate.try_acquire_session(two).is_some(), "another session");
    assert!(
        gate.try_acquire_session(one).is_none(),
        "one stream a session"
    );
    drop(first);
    assert!(
        gate.try_acquire_session(one).is_some(),
        "the place came back"
    );
    // And they took nothing from the others: when an ordinary place goes, it is the next
    // ordinary stream that gets it, and the per peer count of a forged `src` is untouched.
    drop(taken);
    assert!(gate.try_acquire(peer(1)).is_some());
    assert_eq!(
        gate.started_by(&peer(1)),
        2,
        "the minute count is the ordinary one only"
    );
}

#[tokio::test(start_paused = true)]
async fn four_docs_streams_in_all() {
    let gate = DocsGate::new(DocsLimits::default());
    let held: Vec<_> = (1..=4)
        .map(|n| gate.try_acquire(peer(n)).expect("within the four"))
        .collect();
    assert!(
        gate.try_acquire(peer(5)).is_none(),
        "the fifth is over the limit"
    );
    drop(held);
    assert!(gate.try_acquire(peer(5)).is_some());
}

#[tokio::test(start_paused = true)]
async fn six_docs_streams_per_peer_per_minute() {
    let gate = DocsGate::new(DocsLimits::default());
    for _ in 0..6 {
        drop(gate.try_acquire(peer(1)).expect("within the six"));
    }
    assert!(
        gate.try_acquire(peer(1)).is_none(),
        "the seventh in a minute"
    );
    assert!(gate.try_acquire(peer(2)).is_some(), "the count is per peer");
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert!(
        gate.try_acquire(peer(1)).is_none(),
        "still inside the minute"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(
        gate.try_acquire(peer(1)).is_some(),
        "a minute on, it is allowed again"
    );
}

#[tokio::test(start_paused = true)]
async fn a_refused_try_does_not_use_up_the_peers_minute() {
    let gate = DocsGate::new(DocsLimits::default());
    let held = gate.try_acquire(peer(1)).unwrap();
    for _ in 0..20 {
        assert!(gate.try_acquire(peer(1)).is_none());
    }
    drop(held);
    // One was started; five more fit in the minute, the twenty refusals cost nothing.
    for _ in 0..5 {
        drop(gate.try_acquire(peer(1)).expect("refusals are not counted"));
    }
    assert!(gate.try_acquire(peer(1)).is_none());
}

#[tokio::test(start_paused = true)]
async fn the_gate_forgets_peers_that_were_quiet_for_a_minute() {
    let gate = DocsGate::new(DocsLimits::default());
    for n in 1..=50 {
        drop(gate.try_acquire(peer(n)).unwrap());
    }
    tokio::time::sleep(Duration::from_secs(61)).await;
    drop(gate.try_acquire(peer(99)).unwrap());
    let state = gate.state.lock().unwrap();
    assert_eq!(
        state.started.len(),
        1,
        "only the peer that just came is kept"
    );
    assert!(state.active_by_peer.is_empty());
    assert_eq!(state.active, 0);
}

// ---------------------------------------------------------------- the handler over streams

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
    fn roster(&self, seq: u64, members: &[NodeId], revoked: &[NodeId]) -> Roster {
        let now = unix_now();
        Roster::sign(
            &self.owner,
            &RosterBody {
                v: PROTOCOL_VERSION,
                network_id: self.network,
                seq,
                issued: now - 1_000,
                expires: now + 10 * 86_400,
                members: members
                    .iter()
                    .map(|&node_id| RosterMember {
                        node_id,
                        min_serial: 1,
                    })
                    .collect(),
                revoked: revoked
                    .iter()
                    .map(|&node_id| menzil_proto::RevokedMember { node_id, since: 0 })
                    .collect(),
                stewards: vec![],
                labels: vec![],
            },
        )
        .unwrap()
    }

    fn policy(&self, seq: u64, members: &[NodeId]) -> Policy {
        let now = unix_now();
        Policy::sign(
            &self.owner,
            &PolicyBody {
                v: PROTOCOL_VERSION,
                network_id: self.network,
                seq,
                issued: now - 1_000,
                expires: now + 10 * 86_400,
                members: members
                    .iter()
                    .map(|&node_id| PolicyMember {
                        node_id,
                        name: "node".to_string(),
                        roles: vec![],
                    })
                    .collect(),
                certs: vec![],
                grants: vec![],
                egress: vec![],
                accept: vec![],
            },
        )
        .unwrap()
    }

    /// Stores holding the pair at `seq`.
    fn stores(&self, seq: u64, members: &[NodeId]) -> (Arc<PolicyStore>, Arc<RosterStore>) {
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&self.roster(seq, members, &[])).unwrap();
        let policies = Arc::new(PolicyStore::new());
        policies.set(&self.policy(seq, members)).unwrap();
        (policies, rosters)
    }
}

/// The inner handler of the node, counting what reaches it.
#[derive(Default)]
struct Inner {
    opened: AtomicUsize,
}

impl ServiceHandler<Stream> for Inner {
    type Opened = ();
    type Handling = std::future::Ready<()>;

    async fn open(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        self.opened.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn handle(&self, _stream: Stream, _request: OpenRequest, _opened: ()) -> Self::Handling {
        std::future::ready(())
    }
}

/// Lets everything through, to test a handler without the authorizer's help.
struct AllowAll;

impl Authorizer for AllowAll {
    fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
        OpenDecision::Allow
    }
}

async fn pump(mut from: OutboundFrames, to: StreamMux) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

/// What the server side of a test has: the node's stores, one gate for all, the inner handler.
struct Server {
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    gate: Arc<DocsGate>,
    inner: Arc<Inner>,
    network: NetworkId,
    me: NodeId,
}

impl Server {
    fn new(world: &World, policies: Arc<PolicyStore>, rosters: Arc<RosterStore>) -> Self {
        Self {
            policies,
            rosters,
            gate: DocsGate::new(DocsLimits::default()),
            inner: Arc::new(Inner::default()),
            network: world.network,
            me: peer(0xEE),
        }
    }

    fn authorizer(&self) -> PolicyAuthorizer {
        PolicyAuthorizer::new(
            self.policies.clone(),
            self.rosters.clone(),
            self.network,
            self.me,
        )
    }

    fn full_handler(&self) -> SessionHandler<Inner> {
        SessionHandler::full(
            self.inner.clone(),
            self.gate.clone(),
            self.policies.clone(),
            self.rosters.clone(),
        )
    }

    fn docs_only_handler(&self, ended: Arc<AtomicUsize>) -> SessionHandler<Inner> {
        SessionHandler::docs_only(
            self.inner.clone(),
            self.gate.clone(),
            self.policies.clone(),
            self.rosters.clone(),
            move || {
                ended.fetch_add(1, Ordering::SeqCst);
            },
        )
    }

    /// A connection from `peer` that this server answers with `authorizer` and `handler`.
    fn connect<A, H>(&self, from: NodeId, authorizer: A, handler: H) -> Client
    where
        A: Authorizer + Send + Sync + 'static,
        H: ServiceHandler<Stream> + Send + Sync + 'static,
        H::Handling: Send + 'static,
    {
        let (client, _client_inbound, client_out, client_driver) =
            menzil_stream::new(Mode::Client, 65_535);
        let (server, mut server_inbound, server_out, server_driver) =
            menzil_stream::new(Mode::Server, 65_535);
        tokio::spawn(client_driver);
        tokio::spawn(server_driver);
        tokio::spawn(pump(client_out, server.clone()));
        tokio::spawn(pump(server_out, client.clone()));
        let network = self.network;
        let task = tokio::spawn(async move {
            let _keep = server;
            let authorizer = Arc::new(authorizer);
            let handler = Arc::new(handler);
            while let Some(stream) = server_inbound.accept().await {
                let (authorizer, handler) = (authorizer.clone(), handler.clone());
                tokio::spawn(async move {
                    if let Ok(Responded::Accepted(handling)) =
                        respond_to_open(stream, network, from, &*authorizer, &*handler).await
                    {
                        handling.await;
                    }
                });
            }
        });
        Client {
            mux: client,
            network,
            _server: task,
        }
    }

    /// A connection from `from` answered the way an ordinary session is.
    fn ordinary(&self, from: NodeId) -> Client {
        self.connect(from, self.authorizer(), self.full_handler())
    }
}

struct Client {
    mux: StreamMux,
    network: NetworkId,
    _server: JoinHandle<()>,
}

fn open_body(service: menzil_proto::ServiceId) -> OpenBody {
    OpenBody {
        v: PROTOCOL_VERSION,
        service,
        target: None,
        meta: OpenMeta::default(),
    }
}

impl Client {
    /// Opens a stream for `service`; the server's answer comes with it.
    async fn open(&self, service: menzil_proto::ServiceId) -> (Stream, menzil_proto::OpenAckBody) {
        let mut stream = self.mux.open().await.unwrap();
        let ack = initiate_open(&mut stream, &open_body(service))
            .await
            .unwrap();
        (stream, ack)
    }

    fn params(&self) -> DocsParams {
        DocsParams {
            network_id: self.network,
            now: unix_now(),
            deadline: STREAM_DEADLINE,
        }
    }
}

#[tokio::test]
async fn a_member_with_no_grant_fetches_documents_and_is_refused_everything_else() {
    let w = world();
    let (server_id, member) = (peer(0xEE), peer(1));
    let (policies, rosters) = w.stores(2, &[server_id, member]);
    let server = Server::new(&w, policies, rosters);
    let client = server.ordinary(member);

    // The member holds the pair at seq 1 and gets seq 2 over menzil:docs, with no grant anywhere.
    let (client_policies, client_rosters) = w.stores(1, &[server_id, member]);
    let sink = StoreDocs::new(&client_rosters, &client_policies, w.network);
    let (mut stream, ack) = client.open(docs_service()).await;
    assert!(ack.ok, "{ack:?}");
    let report = fetch(&mut stream, sink, &client.params()).await.unwrap();
    assert!(report.adopted.roster && report.adopted.policy);
    assert_eq!(client_rosters.seq(&w.network), Some(2));

    // Everything else is decided by the grant, and there is none.
    let (_stream, ack) = client.open("tcp:ssh".parse().unwrap()).await;
    assert!(!ack.ok);
    assert_eq!(ack.code, ErrorCode::NoGrant);
    assert_eq!(
        server.inner.opened.load(Ordering::SeqCst),
        0,
        "the inner handler is never asked"
    );
}

#[tokio::test]
async fn the_docs_service_never_reaches_the_inner_handler_and_other_services_do() {
    let w = world();
    let (server_id, member) = (peer(0xEE), peer(1));
    let (policies, rosters) = w.stores(2, &[server_id, member]);
    let server = Server::new(&w, policies, rosters);
    // Everything is authorized here: what is under test is the dispatch.
    let client = server.connect(member, AllowAll, server.full_handler());

    let (_docs, ack) = client.open(docs_service()).await;
    assert!(ack.ok);
    assert_eq!(server.inner.opened.load(Ordering::SeqCst), 0);
    let (_other, ack) = client.open("tcp:ssh".parse().unwrap()).await;
    assert!(ack.ok);
    assert_eq!(server.inner.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_peer_revoked_mid_session_is_refused_the_next_docs_open() {
    let w = world();
    let (server_id, member) = (peer(0xEE), peer(1));
    let (policies, rosters) = w.stores(2, &[server_id, member]);
    let server = Server::new(&w, policies, rosters.clone());
    let client = server.ordinary(member);

    let (_stream, ack) = client.open(docs_service()).await;
    assert!(ack.ok, "a member is served");
    drop(_stream);

    // A Roster that revokes the member arrives while the session is up.
    rosters
        .set(&w.roster(3, &[server_id, member], &[member]))
        .unwrap();
    let (_stream, ack) = client.open(docs_service()).await;
    assert!(!ack.ok);
    assert_eq!(ack.code, ErrorCode::NoGrant);
}

#[tokio::test]
async fn a_peer_the_roster_does_not_list_is_refused_docs() {
    let w = world();
    let (server_id, member, stranger) = (peer(0xEE), peer(1), peer(9));
    let (policies, rosters) = w.stores(2, &[server_id, member]);
    let server = Server::new(&w, policies, rosters);
    let client = server.ordinary(stranger);
    let (_stream, ack) = client.open(docs_service()).await;
    assert!(!ack.ok);
    assert_eq!(ack.code, ErrorCode::NoGrant);
}

#[tokio::test]
async fn a_second_docs_stream_of_a_peer_is_rate_limited_until_the_first_is_over() {
    let w = world();
    let (server_id, member) = (peer(0xEE), peer(1));
    let (policies, rosters) = w.stores(2, &[server_id, member]);
    let server = Server::new(&w, policies, rosters);
    let client = server.ordinary(member);

    // The first is opened and left idle: it holds its place.
    let (first, ack) = client.open(docs_service()).await;
    assert!(ack.ok);
    let (_second, ack) = client.open(docs_service()).await;
    assert!(!ack.ok);
    assert_eq!(ack.code, ErrorCode::RateLimited);

    first.reset();
    let mut answered = None;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (_stream, ack) = client.open(docs_service()).await;
        if ack.ok {
            answered = Some(ack);
            break;
        }
        assert_eq!(ack.code, ErrorCode::RateLimited);
    }
    assert!(
        answered.is_some(),
        "the place came back when the stream ended"
    );
}

#[tokio::test]
async fn four_docs_streams_in_all_over_every_session() {
    let w = world();
    let server_id = peer(0xEE);
    let members: Vec<NodeId> = (1..=5).map(peer).collect();
    let mut all = vec![server_id];
    all.extend(members.iter().copied());
    let (policies, rosters) = w.stores(2, &all);
    let server = Server::new(&w, policies, rosters);

    // Five members, one session each, one idle docs stream each.
    let clients: Vec<Client> = members.iter().map(|&m| server.ordinary(m)).collect();
    let mut streams = Vec::new();
    for client in clients.iter().take(4) {
        let (stream, ack) = client.open(docs_service()).await;
        assert!(ack.ok, "{ack:?}");
        streams.push(stream);
    }
    let (_fifth, ack) = clients[4].open(docs_service()).await;
    assert!(!ack.ok);
    assert_eq!(ack.code, ErrorCode::RateLimited);
}

#[tokio::test(start_paused = true)]
async fn six_docs_streams_per_peer_per_minute_over_the_wire() {
    let w = world();
    let (server_id, member) = (peer(0xEE), peer(1));
    let (policies, rosters) = w.stores(2, &[server_id, member]);
    let server = Server::new(&w, policies, rosters);
    let client = server.ordinary(member);

    for round in 0..6 {
        let (client_policies, client_rosters) = w.stores(1, &[server_id, member]);
        let sink = StoreDocs::new(&client_rosters, &client_policies, w.network);
        let (mut stream, ack) = client.open(docs_service()).await;
        assert!(ack.ok, "stream {round}: {ack:?}");
        fetch(&mut stream, sink, &client.params()).await.unwrap();
        stream.close().await.unwrap();
        // Let the server's side finish and give its place back.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (_stream, ack) = client.open(docs_service()).await;
    assert!(!ack.ok);
    assert_eq!(ack.code, ErrorCode::RateLimited, "the seventh in a minute");

    tokio::time::sleep(Duration::from_secs(61)).await;
    let (_stream, ack) = client.open(docs_service()).await;
    assert!(ack.ok, "a minute later it is served again");
}

#[tokio::test]
async fn a_docs_only_session_takes_one_push_then_ends_the_session() {
    let w = world();
    let (server_id, member) = (peer(0xEE), peer(1));
    // The server is behind (seq 1); the member comes with seq 2.
    let (policies, rosters) = w.stores(1, &[server_id, member]);
    let server = Server::new(&w, policies, rosters.clone());
    let ended = Arc::new(AtomicUsize::new(0));
    let client = server.connect(
        member,
        server.authorizer().docs_only(),
        server.docs_only_handler(ended.clone()),
    );

    let (member_policies, member_rosters) = w.stores(2, &[server_id, member]);
    let source = StoreDocs::new(&member_rosters, &member_policies, w.network);
    let bundle = bundle_to_push(&source, unix_now());
    let (mut stream, ack) = client.open(docs_service()).await;
    assert!(ack.ok, "{ack:?}");
    let result = push(&mut stream, &bundle, &client.params()).await.unwrap();
    assert_eq!(result.roster, menzil_proto::docs::Outcome::Adopted);
    assert_eq!(rosters.seq(&w.network), Some(2), "the push was adopted");
    assert_eq!(
        ended.load(Ordering::SeqCst),
        0,
        "the session is not ended while the opener may still be reading the result"
    );
    stream.close().await.unwrap();
    for _ in 0..100 {
        if ended.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(ended.load(Ordering::SeqCst), 1, "the session is ended once");
}

#[tokio::test]
async fn a_docs_only_session_refuses_a_fetch_and_every_other_open() {
    let w = world();
    let (server_id, member) = (peer(0xEE), peer(1));
    let (policies, rosters) = w.stores(2, &[server_id, member]);
    let server = Server::new(&w, policies, rosters);
    let ended = Arc::new(AtomicUsize::new(0));
    // The authorizer lets everything through: the handler is what is under test here.
    let client = server.connect(member, AllowAll, server.docs_only_handler(ended.clone()));

    // Not tcp:ssh, not anything the inner handler could take.
    let (_stream, ack) = client.open("tcp:ssh".parse().unwrap()).await;
    assert!(!ack.ok);
    assert_eq!(ack.code, ErrorCode::NoGrant);
    assert_eq!(server.inner.opened.load(Ordering::SeqCst), 0);

    // A fetch is a violation: nothing is sent, the stream is reset, the session is ended.
    let (client_policies, client_rosters) = w.stores(1, &[server_id, member]);
    let sink = StoreDocs::new(&client_rosters, &client_policies, w.network);
    let (mut stream, ack) = client.open(docs_service()).await;
    assert!(ack.ok);
    let fetched = fetch(&mut stream, sink, &client.params()).await;
    assert!(fetched.is_err(), "no documents come back: {fetched:?}");
    assert_eq!(client_rosters.seq(&w.network), Some(1));
    for _ in 0..100 {
        if ended.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(ended.load(Ordering::SeqCst), 1);
}
