//! Live end-to-end tests of the session lifecycle (`relay.rs`,
//! `session.rs`, `hello.rs`, `registry.rs`, `doc.rs` together): a real
//! self-signed certificate, a real TLS+WebSocket connection, and a real
//! Noise handshake driven directly against `menzil-session`'s public API,
//! bypassing `menzil-carrier::Carrier::dial` entirely (it hardcodes the
//! platform TLS verifier with no way to trust a test-only certificate;
//! this is the workaround, not a limitation of this test — see
//! `menzil-node`'s own notes on the same constraint from the other
//! side). `#[cfg(test)]` on this module's declaration in `lib.rs` already
//! gates the whole thing out of non-test builds.

use std::collections::HashMap;
use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use menzil_proto::{
    AdvertiseBody, DocReassembler, DocType, ErrorCode, HelloBody, Label, Limits, NetworkId,
    NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, Record, Roster, RosterBody, RosterMember,
    Share, ShareMode, Tai64N, WelcomeBody, X25519PublicKey,
};
use menzil_session::{HandshakePattern, NodeHandshake, Transport, prologue};
use rustls::pki_types::CertificateDer;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::identity::RelayIdentity;
use crate::listener::Listener;
use crate::relay::Relay;
use crate::tests_support::{DAY, StewardNet, real_now, self_signed_cert, test_client};

fn ik_params() -> snow::params::NoiseParams {
    "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
}

struct TestIdentity {
    signing_key: SigningKey,
    node_id: NodeId,
    x25519_private: [u8; 32],
    x25519_public: X25519PublicKey,
}

fn generate_identity() -> TestIdentity {
    let signing_key = SigningKey::generate(&mut rand::rng());
    let node_id = NodeId::from(signing_key.verifying_key().to_bytes());
    let kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
    let x25519_private = <[u8; 32]>::try_from(kp.private).unwrap();
    let x25519_public = X25519PublicKey::from(<[u8; 32]>::try_from(kp.public).unwrap());
    TestIdentity {
        signing_key,
        node_id,
        x25519_private,
        x25519_public,
    }
}

fn node_cert_for(identity: &TestIdentity, serial: u32) -> NodeCert {
    let body = NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id: identity.node_id,
        x25519_pub: identity.x25519_public,
        serial,
        not_before: 0,
        not_after: 4_000_000_000,
    };
    NodeCert::sign(&identity.signing_key, &body).unwrap()
}

fn test_limits() -> Limits {
    Limits {
        max_record: 65_535,
        max_peers: 10,
        credit: 1_048_576,
    }
}

/// Binds a real `Listener` on a self-signed cert and a `Relay` with
/// `limits`, and returns the relay's own X25519 public key (needed by
/// [`TestClient::connect`]'s `Ik` handshake) alongside everything a
/// caller needs to spawn `relay.serve(&listener)`.
async fn bind_test_relay_with_limits(
    limits: Limits,
) -> (Relay, Listener, CertificateDer<'static>, X25519PublicKey) {
    let (chain, key) = self_signed_cert("localhost");
    let cert = chain[0].clone();
    let tls_config = crate::tls::server_config(chain, key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls_config, "/_menzil/v1")
        .await
        .unwrap();
    let raw = generate_identity();
    let node_cert = node_cert_for(&raw, 1);
    let relay_x25519 = raw.x25519_public;
    // Every test connects from 127.0.0.1, many of them a lot: the per address figures are
    // lifted here and tested on their own (the MT4 section below).
    let relay = Relay::new(
        RelayIdentity {
            node_cert,
            x25519_private: raw.x25519_private,
        },
        limits,
    )
    .with_admission_limits(crate::admission::AdmissionLimits {
        connections_per_ip_per_minute: 1_000_000,
        max_unattached_per_ip: 1_000_000,
        ..crate::admission::AdmissionLimits::default()
    });
    (relay, listener, cert, relay_x25519)
}

/// [`bind_test_relay_with_limits`] with this file's own default
/// [`test_limits`].
async fn bind_test_relay() -> (Relay, Listener, CertificateDer<'static>, X25519PublicKey) {
    bind_test_relay_with_limits(test_limits()).await
}

/// One end of a live, real Noise `Ik` session with the relay under test:
/// a real WebSocket connection plus the client-side `Transport` that
/// resulted from actually completing the handshake against it.
struct TestClient {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    transport: Transport,
}

impl TestClient {
    #[allow(clippy::too_many_arguments)]
    async fn connect(
        addr: SocketAddr,
        cert: CertificateDer<'static>,
        client_identity: &TestIdentity,
        relay_x25519: X25519PublicKey,
        networks: Vec<NetworkId>,
        roster_seq: HashMap<NetworkId, u64>,
        serial: u32,
        timestamp_byte: u8,
    ) -> (Self, WelcomeBody) {
        let mut ws = test_client(addr, cert, "/_menzil/v1").await;
        let pattern = HandshakePattern::Ik;
        let prologue_bytes = prologue("menzil.v1", "menzil.v1", pattern);
        let mut timestamp = [0u8; 12];
        timestamp[7] = timestamp_byte;
        let hello = HelloBody {
            v: PROTOCOL_VERSION,
            node_cert: node_cert_for(client_identity, serial),
            networks,
            timestamp: Tai64N::from(timestamp),
            roster_seq,
            caps: vec![],
            e2e_protos: vec![0x01],
        };
        let (node_handshake, message1) = NodeHandshake::start(
            pattern,
            &client_identity.x25519_private,
            Some(&relay_x25519),
            &prologue_bytes,
            &hello,
        )
        .unwrap();
        ws.send(Message::Binary(message1.into())).await.unwrap();
        let message2 = match ws.next().await.unwrap().unwrap() {
            Message::Binary(bytes) => bytes.to_vec(),
            other => panic!("expected a binary message 2, got {other:?}"),
        };
        let (transport, welcome, _relay_static, outgoing) =
            node_handshake.finish(&message2).unwrap();
        assert!(outgoing.is_none(), "Ik never has a message 3");
        (Self { ws, transport }, welcome)
    }

    /// The first contact shape: a real Noise `Xx` handshake (the node does not know the
    /// relay's static key), HELLO riding message 3. Returns the client and the WELCOME that
    /// message 2 carried.
    async fn connect_xx(
        addr: SocketAddr,
        cert: CertificateDer<'static>,
        client_identity: &TestIdentity,
        networks: Vec<NetworkId>,
        timestamp_byte: u8,
    ) -> (Self, WelcomeBody) {
        let mut ws = test_client(addr, cert, "/_menzil/v1").await;
        let pattern = HandshakePattern::Xx;
        let prologue_bytes = prologue("menzil.v1", "menzil.v1", pattern);
        let mut timestamp = [0u8; 12];
        timestamp[7] = timestamp_byte;
        let hello = HelloBody {
            v: PROTOCOL_VERSION,
            node_cert: node_cert_for(client_identity, 1),
            networks,
            timestamp: Tai64N::from(timestamp),
            roster_seq: HashMap::new(),
            caps: vec![],
            e2e_protos: vec![0x01],
        };
        let (node_handshake, message1) = NodeHandshake::start(
            pattern,
            &client_identity.x25519_private,
            None,
            &prologue_bytes,
            &hello,
        )
        .unwrap();
        ws.send(Message::Binary(message1.into())).await.unwrap();
        let message2 = match ws.next().await.unwrap().unwrap() {
            Message::Binary(bytes) => bytes.to_vec(),
            other => panic!("expected a binary message 2, got {other:?}"),
        };
        let (transport, welcome, _relay_static, outgoing) =
            node_handshake.finish(&message2).unwrap();
        let message3 = outgoing.expect("Xx always has a message 3");
        ws.send(Message::Binary(message3.into())).await.unwrap();
        (Self { ws, transport }, welcome)
    }

    async fn send(&mut self, record: Record) {
        let bytes = self.transport.encrypt_record(&record).unwrap();
        self.ws.send(Message::Binary(bytes.into())).await.unwrap();
    }

    /// The next decrypted record, or `None` once the connection has
    /// ended — whether cleanly (a close frame, or a plain EOF) or
    /// abnormally (a WebSocket-level error, which this treats the same
    /// as a close rather than panicking, since the relay's own side
    /// simply drops its connection on rejection rather than performing
    /// a clean WebSocket close handshake).
    async fn recv(&mut self) -> Option<Record> {
        match self.ws.next().await {
            Some(Ok(Message::Binary(bytes))) => {
                Some(self.transport.decrypt_record(&bytes).unwrap())
            }
            Some(Ok(Message::Close(_))) | None => None,
            Some(Ok(other)) => panic!("expected a binary or close message, got {other:?}"),
            Some(Err(_)) => None,
        }
    }

    /// Reads records until one complete DOC transfer reassembles, whatever its
    /// `doc_type`.
    async fn recv_doc_transfer(&mut self) -> (DocType, Vec<u8>) {
        let mut reassembler = DocReassembler::new();
        loop {
            match self.recv().await {
                Some(Record::Doc(body)) => {
                    if let Some(done) = reassembler.accept(&body).unwrap() {
                        return done;
                    }
                }
                other => panic!("expected a DOC chunk, got {other:?}"),
            }
        }
    }

    /// Reads records until a complete DOC transfer reassembles, decoding
    /// it as a Roster (protocol.md 4.3: at L3 this is the only doc_type a
    /// relay ever sends). Panics if the connection ends, or a
    /// non-`Doc` record arrives, before one completes — every test that
    /// calls this already knows a DOC push is exactly what should be
    /// happening next.
    async fn recv_roster_doc(&mut self) -> Roster {
        let mut reassembler = DocReassembler::new();
        loop {
            match self.recv().await {
                Some(Record::Doc(body)) => {
                    if let Some((doc_type, bytes)) = reassembler.accept(&body).unwrap() {
                        assert_eq!(doc_type, DocType::Roster);
                        return Roster::decode_strict(&bytes).unwrap();
                    }
                }
                other => panic!("expected a DOC(roster) chunk, got {other:?}"),
            }
        }
    }
}

/// Seeds `relay` with a fresh network listing `members`, and returns what a HELLO of one of them
/// claims: the network, and a `roster_seq` that says the node already holds the Roster, so no
/// DOC catch-up push follows its ATTACH. A HELLO that claims no network is refused (D6), so a
/// test that only needs a session to exist claims one of these.
fn seed_network(
    relay: &Relay,
    members: &[&TestIdentity],
) -> (Vec<NetworkId>, HashMap<NetworkId, u64>) {
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
            .map(|identity| RosterMember {
                node_id: identity.node_id,
                min_serial: 1,
            })
            .collect(),
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    relay
        .rosters()
        .set(&Roster::sign(&owner, &body).unwrap())
        .unwrap();
    (vec![network_id], HashMap::from([(network_id, 1)]))
}

async fn ping_pong(client: &mut TestClient, nonce: [u8; 8]) {
    client.send(Record::Ping { nonce }).await;
    assert_eq!(client.recv().await, Some(Record::Pong { nonce }));
}

#[tokio::test]
async fn attach_registers_the_session() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let client_identity = generate_identity();
    let (networks, seq) = seed_network(&relay, &[&client_identity]);
    let (mut client, welcome) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        networks,
        seq,
        1,
        10,
    )
    .await;
    assert_eq!(welcome.v, PROTOCOL_VERSION);
    assert_eq!(
        relay.registry.attached_session_id(&client_identity.node_id),
        None
    );

    client.send(Record::Attach).await;
    // A PING/PONG round trip over the same connection is a
    // deterministic synchronization point: ATTACH is processed strictly
    // before this PING is, since both travel over one ordered stream
    // into the relay's single per-connection recv loop.
    ping_pong(&mut client, [1; 8]).await;

    assert_eq!(
        relay.registry.attached_session_id(&client_identity.node_id),
        Some(welcome.session)
    );
}

#[tokio::test]
async fn a_second_attach_supersedes_the_first() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let client_identity = generate_identity();
    let (networks, seq) = seed_network(&relay, &[&client_identity]);
    let (mut client1, _) = TestClient::connect(
        addr,
        cert.clone(),
        &client_identity,
        relay_x25519,
        networks.clone(),
        seq.clone(),
        1,
        10,
    )
    .await;
    client1.send(Record::Attach).await;
    ping_pong(&mut client1, [1; 8]).await;

    // Same identity, a second connection: serial stays the same
    // (allowed — only a *lower* serial is rejected) but the timestamp
    // must still strictly advance (protocol.md 4.1).
    let (mut client2, _) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        networks,
        seq,
        1,
        20,
    )
    .await;
    client2.send(Record::Attach).await;
    ping_pong(&mut client2, [2; 8]).await;

    match client1.recv().await {
        Some(Record::Goaway(body)) => assert_eq!(body.reason, "superseded"),
        other => panic!("expected GOAWAY on the superseded connection, got {other:?}"),
    }
}

#[tokio::test]
async fn an_unserved_claimed_network_gets_not_member_then_the_connection_ends() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { relay.serve(&listener).await });

    let client_identity = generate_identity();
    let unknown_network = NetworkId::from([0x42; 32]);
    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        vec![unknown_network],
        HashMap::new(),
        1,
        10,
    )
    .await;

    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR, got {other:?}"),
    }
    assert_eq!(
        client.recv().await,
        None,
        "the relay closes the connection after a HELLO rejection"
    );
}

#[tokio::test]
async fn a_member_of_a_held_roster_attaches_successfully() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();

    let client_identity = generate_identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let roster_body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![RosterMember {
            node_id: client_identity.node_id,
            min_serial: 1,
        }],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    // Seeding a Roster this way, directly through `RosterStore`, is
    // still how an operator gives a relay its very first Roster for a
    // network (protocol.md 4.3 covers propagation once one exists, not
    // how the first one arrives).
    relay
        .rosters()
        .set(&Roster::sign(&owner, &roster_body).unwrap())
        .unwrap();

    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client, welcome) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client.send(Record::Attach).await;
    // This client's HELLO claimed no roster_seq at all for `network_id`,
    // and the relay already holds seq 1: the attach-time catch-up
    // (protocol.md 4.3, see `crate::doc`) pushes it right away, ahead of
    // any other traffic.
    let caught_up = client.recv_roster_doc().await;
    assert_eq!(caught_up.decode().unwrap(), roster_body);

    ping_pong(&mut client, [3; 8]).await;
    assert_eq!(
        relay.registry.attached_session_id(&client_identity.node_id),
        Some(welcome.session)
    );
}

#[tokio::test]
async fn an_already_caught_up_node_gets_no_unsolicited_doc_push() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();

    let client_identity = generate_identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let roster_body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![RosterMember {
            node_id: client_identity.node_id,
            min_serial: 1,
        }],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    relay
        .rosters()
        .set(&Roster::sign(&owner, &roster_body).unwrap())
        .unwrap();

    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let mut roster_seq = HashMap::new();
    roster_seq.insert(network_id, 1);
    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        vec![network_id],
        roster_seq,
        1,
        10,
    )
    .await;
    client.send(Record::Attach).await;
    // Already at seq 1, matching what the relay holds: no catch-up push
    // is owed, so the very next thing on the wire is the PONG, not a
    // DOC.
    ping_pong(&mut client, [4; 8]).await;
}

#[tokio::test]
async fn a_newer_roster_from_one_member_propagates_to_another_attached_member() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();

    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity_a = generate_identity();
    let identity_b = generate_identity();
    let roster_v1 = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![
            RosterMember {
                node_id: identity_a.node_id,
                min_serial: 1,
            },
            RosterMember {
                node_id: identity_b.node_id,
                min_serial: 1,
            },
        ],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    relay
        .rosters()
        .set(&Roster::sign(&owner, &roster_v1).unwrap())
        .unwrap();

    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_a,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_a.send(Record::Attach).await;
    assert_eq!(client_a.recv_roster_doc().await.decode().unwrap().seq, 1);

    let (mut client_b, _) = TestClient::connect(
        addr,
        cert,
        &identity_b,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_b.send(Record::Attach).await;
    assert_eq!(client_b.recv_roster_doc().await.decode().unwrap().seq, 1);

    // client_a now pushes a newer Roster to the relay over DOC.
    let roster_v2 = RosterBody {
        seq: 2,
        issued: real_now(),
        expires: real_now() + 7 * DAY,
        ..roster_v1.clone()
    };
    let signed_v2 = Roster::sign(&owner, &roster_v2).unwrap();
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &signed_v2.encode()) {
        client_a.send(record).await;
    }

    // client_b, still attached and a claimed member of this network,
    // receives the fan-out.
    let propagated = client_b.recv_roster_doc().await;
    assert_eq!(propagated.decode().unwrap(), roster_v2);

    // client_a, the sender, is excluded from its own fan-out: the next
    // thing it sees is an ordinary PONG, not a stray DOC echoed back.
    ping_pong(&mut client_a, [9; 8]).await;
}

/// A relay serving `net` with its owner signed base, and one member identity listed in it.
async fn steward_relay(
    net_member: &TestIdentity,
) -> (
    Relay,
    Listener,
    CertificateDer<'static>,
    X25519PublicKey,
    StewardNet,
) {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let net = StewardNet::new(10, real_now(), net_member.node_id);
    relay.rosters().set(&net.base).unwrap();
    (relay, listener, cert, relay_x25519, net)
}

fn doc_records_of(doc_type: DocType, roster: &Roster) -> Vec<Record> {
    menzil_proto::split_into_doc_records(doc_type, &roster.encode())
}

#[tokio::test]
async fn catch_up_sends_the_base_of_a_steward_roster_before_the_roster() {
    let identity = generate_identity();
    let (relay, listener, cert, relay_x25519, net) = steward_relay(&identity).await;
    let renewal = net.renewal(&net.steward, 11);
    assert!(
        relay
            .rosters()
            .adopt(&renewal, Some(&net.base), real_now())
            .unwrap()
    );
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &identity,
        relay_x25519,
        vec![net.network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client.send(Record::Attach).await;

    let (first_type, first) = client.recv_doc_transfer().await;
    assert_eq!(first_type, DocType::BaseRoster);
    assert_eq!(Roster::decode_strict(&first).unwrap(), net.base);
    let (second_type, second) = client.recv_doc_transfer().await;
    assert_eq!(second_type, DocType::Roster);
    assert_eq!(Roster::decode_strict(&second).unwrap(), renewal);
}

#[tokio::test]
async fn a_steward_roster_sent_with_its_base_is_adopted_and_fanned_out_base_first() {
    let identity_a = generate_identity();
    let identity_b = generate_identity();
    // Both identities are members, so both can attach and claim the network.
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let net = StewardNet::new(10, real_now(), identity_a.node_id).with_member(identity_b.node_id);
    relay.rosters().set(&net.base).unwrap();
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_a,
        relay_x25519,
        vec![net.network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_a.send(Record::Attach).await;
    assert_eq!(client_a.recv_roster_doc().await, net.base);
    let (mut client_b, _) = TestClient::connect(
        addr,
        cert,
        &identity_b,
        relay_x25519,
        vec![net.network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_b.send(Record::Attach).await;
    assert_eq!(client_b.recv_roster_doc().await, net.base);

    let renewal = net.renewal(&net.steward, 11);
    for record in doc_records_of(DocType::BaseRoster, &net.base) {
        client_a.send(record).await;
    }
    for record in doc_records_of(DocType::Roster, &renewal) {
        client_a.send(record).await;
    }

    let (first_type, first) = client_b.recv_doc_transfer().await;
    assert_eq!(first_type, DocType::BaseRoster);
    assert_eq!(Roster::decode_strict(&first).unwrap(), net.base);
    let (second_type, second) = client_b.recv_doc_transfer().await;
    assert_eq!(second_type, DocType::Roster);
    assert_eq!(Roster::decode_strict(&second).unwrap(), renewal);
    assert_eq!(relay.rosters().base(&net.network_id).unwrap(), net.base);
}

#[tokio::test]
async fn a_pending_base_does_not_outlive_its_session() {
    let identity = generate_identity();
    let (relay, listener, cert, relay_x25519, net) = steward_relay(&identity).await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    // The first session sends the base and goes away.
    let (mut first, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity,
        relay_x25519,
        vec![net.network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    first.send(Record::Attach).await;
    assert_eq!(first.recv_roster_doc().await, net.base);
    for record in doc_records_of(DocType::BaseRoster, &net.base) {
        first.send(record).await;
    }
    ping_pong(&mut first, [1; 8]).await;
    drop(first);

    // The second session sends the steward Roster alone: it has no base to stand on.
    let (mut second, _) = TestClient::connect(
        addr,
        cert,
        &identity,
        relay_x25519,
        vec![net.network_id],
        HashMap::new(),
        1,
        11,
    )
    .await;
    second.send(Record::Attach).await;
    assert_eq!(second.recv_roster_doc().await, net.base);
    for record in doc_records_of(DocType::Roster, &net.renewal(&net.steward, 11)) {
        second.send(record).await;
    }
    ping_pong(&mut second, [2; 8]).await;
    assert_eq!(relay.rosters().get(&net.network_id).unwrap().seq, 10);
}

#[tokio::test]
async fn rekey_from_the_client_is_applied_before_the_next_record() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let client_identity = generate_identity();
    let (networks, seq) = seed_network(&relay, &[&client_identity]);
    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        networks,
        seq,
        1,
        10,
    )
    .await;
    client.send(Record::Attach).await;
    ping_pong(&mut client, [1; 8]).await;

    client.send(Record::Rekey).await;
    client.transport.rekey_outgoing();
    // If the relay had not rekeyed its own receiving state in response,
    // this PING would fail to decrypt on the relay's side and no PONG
    // would come back.
    ping_pong(&mut client, [2; 8]).await;
}

fn roster_with_label(
    owner: &SigningKey,
    network_id: NetworkId,
    node_id: NodeId,
    name: &str,
) -> Roster {
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![RosterMember {
            node_id,
            min_serial: 1,
        }],
        revoked: vec![],
        stewards: vec![],
        labels: vec![Label {
            name: name.to_string(),
            node_id,
        }],
    };
    Roster::sign(owner, &body).unwrap()
}

fn advertise_one(name: &str) -> Record {
    Record::Advertise(AdvertiseBody {
        v: PROTOCOL_VERSION,
        shares: vec![Share {
            name: name.to_string(),
            mode: ShareMode::Terminated,
            service: "tcp:ssh".parse().unwrap(),
            alpn: vec![],
        }],
        accept_peers: true,
    })
}

#[tokio::test]
async fn advertise_before_attach_is_ignored() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();

    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity = generate_identity();
    relay
        .rosters()
        .set(&roster_with_label(
            &owner,
            network_id,
            identity.node_id,
            "example",
        ))
        .unwrap();

    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &identity,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    // Deliberately no ATTACH here: this is exactly the gap a red team
    // review found — a pre-attach ADVERTISE being processed anyway, with
    // no attached session ever registered for `SessionRegistry::detach`
    // to later release it through.
    client.send(advertise_one("example")).await;
    // A PING/PONG round trip is a deterministic synchronization point,
    // as elsewhere in this file: both travel over one ordered stream
    // into the relay's single per-connection recv loop, so if the
    // ADVERTISE had produced an ADVERTISE_ACK, it would have arrived
    // before this PONG.
    client.send(Record::Ping { nonce: [9; 8] }).await;
    assert_eq!(client.recv().await, Some(Record::Pong { nonce: [9; 8] }));

    assert!(
        relay.labels.shares_for(&identity.node_id).is_empty(),
        "a pre-attach ADVERTISE must never be processed at all"
    );
}

#[tokio::test]
async fn advertise_after_attach_is_accepted_and_acknowledged() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();

    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity = generate_identity();
    relay
        .rosters()
        .set(&roster_with_label(
            &owner,
            network_id,
            identity.node_id,
            "example",
        ))
        .unwrap();

    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &identity,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client.send(Record::Attach).await;
    // This client's HELLO claimed no roster_seq at all for `network_id`,
    // so the attach-time catch-up (protocol.md 4.3, `crate::doc`) pushes
    // the just-seeded Roster right away, ahead of anything else —
    // consume it before expecting the ADVERTISE_ACK.
    let _ = client.recv_roster_doc().await;
    client.send(advertise_one("example")).await;

    match client.recv().await {
        Some(Record::AdvertiseAck(ack)) => {
            assert_eq!(ack.accepted, vec!["example"]);
            assert!(ack.rejected.is_empty());
        }
        other => panic!("expected an ADVERTISE_ACK, got {other:?}"),
    }
    assert_eq!(relay.labels.shares_for(&identity.node_id).len(), 1);
}

#[tokio::test]
async fn a_reconnecting_session_does_not_inherit_the_previous_sessions_claims() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();

    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity = generate_identity();
    relay
        .rosters()
        .set(&roster_with_label(
            &owner,
            network_id,
            identity.node_id,
            "example",
        ))
        .unwrap();

    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client1, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client1.send(Record::Attach).await;
    // Same attach-time catch-up as `advertise_after_attach_is_accepted_and_acknowledged`.
    let _ = client1.recv_roster_doc().await;
    client1.send(advertise_one("example")).await;
    match client1.recv().await {
        Some(Record::AdvertiseAck(ack)) => assert_eq!(ack.accepted, vec!["example"]),
        other => panic!("expected an ADVERTISE_ACK, got {other:?}"),
    }
    assert_eq!(relay.labels.shares_for(&identity.node_id).len(), 1);

    // Same identity reconnects (the serial may stay the same; only the
    // timestamp must still strictly advance, protocol.md 4.1) and
    // attaches, superseding the first session — but never re-sends its
    // own ADVERTISE this time.
    let (mut client2, _) = TestClient::connect(
        addr,
        cert,
        &identity,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        20,
    )
    .await;
    client2.send(Record::Attach).await;
    let _ = client2.recv_roster_doc().await;
    ping_pong(&mut client2, [1; 8]).await;

    assert!(
        relay.labels.shares_for(&identity.node_id).is_empty(),
        "a freshly attached session must not silently inherit a prior session's claims"
    );
}

fn send_record(dst: NodeId, payload: Vec<u8>) -> Record {
    Record::Send {
        dst,
        e2e_proto: 0x01,
        flags: 0,
        payload,
    }
}

/// Two identities, both members of one freshly seeded Roster, both
/// already attached to `relay` and past their attach-time DOC catch-up —
/// ready for a SEND/RECV/CREDIT test (TODO.md L3h) to act on directly.
async fn two_attached_members(
    relay: &Relay,
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    relay_x25519: X25519PublicKey,
) -> (TestClient, NodeId, TestClient, NodeId) {
    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity_a = generate_identity();
    let identity_b = generate_identity();
    let roster = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![
            RosterMember {
                node_id: identity_a.node_id,
                min_serial: 1,
            },
            RosterMember {
                node_id: identity_b.node_id,
                min_serial: 1,
            },
        ],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    relay
        .rosters()
        .set(&Roster::sign(&owner, &roster).unwrap())
        .unwrap();

    let (mut client_a, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_a,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_a.send(Record::Attach).await;
    let _ = client_a.recv_roster_doc().await;

    let (mut client_b, _) = TestClient::connect(
        addr,
        cert,
        &identity_b,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_b.send(Record::Attach).await;
    let _ = client_b.recv_roster_doc().await;

    (client_a, identity_a.node_id, client_b, identity_b.node_id)
}

#[tokio::test]
async fn a_send_between_attached_common_members_is_forwarded_and_credited() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, node_a, mut client_b, node_b) =
        two_attached_members(&relay, addr, cert, relay_x25519).await;

    let payload = vec![9u8; 100];
    client_a.send(send_record(node_b, payload.clone())).await;

    match client_b.recv().await {
        Some(Record::Recv {
            src,
            e2e_proto,
            flags,
            payload: got,
        }) => {
            assert_eq!(src, node_a);
            assert_eq!(e2e_proto, 0x01);
            assert_eq!(flags, 0);
            assert_eq!(got, payload);
        }
        other => panic!("expected RECV, got {other:?}"),
    }

    // Once the RECV above was actually handed to client_b's own
    // connection to send, the relay grants the consumed credit back to
    // client_a and reports it (protocol.md 4.2).
    match client_a.recv().await {
        Some(Record::Credit(body)) => {
            assert_eq!(body.peer, node_b);
            assert_eq!(body.bytes, payload.len() as u32);
        }
        other => panic!("expected CREDIT, got {other:?}"),
    }

    // Also assert the relay's own ledger, not just the wire record's
    // shape: an opus red team review found (finding L2) that a mutation
    // deleting the actual credit-granting call still left every test in
    // this suite passing, because nothing checked the ledger itself was
    // restored — only that *a* CREDIT record with the right numbers
    // arrived, which the record's own construction guarantees regardless
    // of whether the ledger agrees.
    assert_eq!(
        relay.forwarding.remaining_credit(&node_a, &node_b),
        Some(test_limits().credit),
        "the relay's own ledger, not just the CREDIT record sent, must reflect the grant"
    );
}

#[tokio::test]
async fn credit_granted_back_is_genuinely_usable_for_a_further_send() {
    // A stronger regression test for the same finding (L2): prove
    // replenished credit can actually be *spent* again, which the
    // mutation described above would still fail even if the previous
    // test's ledger assertion were removed — a session that treats
    // `drained` as a no-op would let this second SEND exceed the small
    // credit configured here and get its session closed instead of a
    // second, successful RECV.
    // Comfortably above MIN_FORWARD_CHARGE_BYTES (64) so the numbers below
    // reflect the payload size chosen, not that floor.
    let payload_len = 200usize;
    let small_credit = Limits {
        max_record: 65_535,
        max_peers: 10,
        credit: 300,
    };
    let (relay, listener, cert, relay_x25519) = bind_test_relay_with_limits(small_credit).await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, _node_a, mut client_b, node_b) =
        two_attached_members(&relay, addr, cert, relay_x25519).await;

    client_a
        .send(send_record(node_b, vec![0u8; payload_len]))
        .await;
    match client_b.recv().await {
        Some(Record::Recv { .. }) => {}
        other => panic!("expected the first RECV, got {other:?}"),
    }
    match client_a.recv().await {
        Some(Record::Credit(body)) => assert_eq!(body.bytes, payload_len as u32),
        other => panic!("expected the first CREDIT, got {other:?}"),
    }

    // Credit is back to the full 300; a second 200-byte send would exceed
    // the original 300 - 200 = 100 remaining if replenishment were a
    // no-op, but must succeed now that it has genuinely been granted
    // back.
    client_a
        .send(send_record(node_b, vec![1u8; payload_len]))
        .await;
    match client_b.recv().await {
        Some(Record::Recv { payload, .. }) => assert_eq!(payload, vec![1u8; payload_len]),
        other => panic!("expected the second RECV — credit was not really replenished: {other:?}"),
    }
}

#[tokio::test]
async fn a_reconnecting_destination_gets_a_fresh_credit_ledger_not_its_previous_sessions_leftovers()
{
    // Regression test for finding H2: `ForwardTable`'s pairs used to be
    // keyed only by NodeId, so a destination's fresh WELCOME credit could
    // land on top of, or be shrunk by, whatever a *previous* session for
    // the same NodeId had left consumed and never (or not yet) granted
    // back. `forward.rs`'s own unit tests already prove
    // `ForwardTable::clear_for` is correct in isolation; this proves the
    // real attach flow in `crate::session` actually calls it, over a
    // genuine reconnect, the same way
    // `a_reconnecting_session_does_not_inherit_the_previous_sessions_claims`
    // already does for label claims via the identical, adjacent call.
    let small_credit = Limits {
        max_record: 65_535,
        max_peers: 10,
        credit: 100,
    };
    let (relay, listener, cert, relay_x25519) = bind_test_relay_with_limits(small_credit).await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity_a = generate_identity();
    let identity_b = generate_identity();
    let roster = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![
            RosterMember {
                node_id: identity_a.node_id,
                min_serial: 1,
            },
            RosterMember {
                node_id: identity_b.node_id,
                min_serial: 1,
            },
        ],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    relay
        .rosters()
        .set(&Roster::sign(&owner, &roster).unwrap())
        .unwrap();

    let (mut client_a, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_a,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_a.send(Record::Attach).await;
    let _ = client_a.recv_roster_doc().await;

    let (mut client_b1, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_b,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_b1.send(Record::Attach).await;
    let _ = client_b1.recv_roster_doc().await;

    // Send once and fully drain it (read both the RECV and the CREDIT)
    // so the (identity_a, identity_b) pair genuinely exists in
    // `ForwardTable` — not a race-prone attempt to catch it mid-flight,
    // which `forward.rs`'s own unit tests already cover deterministically
    // by calling `ForwardTable::clear_for` directly; this test only needs
    // to prove the real attach flow *calls* it.
    client_a
        .send(send_record(identity_b.node_id, vec![0u8; 90]))
        .await;
    match client_b1.recv().await {
        Some(Record::Recv { .. }) => {}
        other => panic!("expected the RECV, got {other:?}"),
    }
    match client_a.recv().await {
        Some(Record::Credit(_)) => {}
        other => panic!("expected the CREDIT, got {other:?}"),
    }
    assert!(
        relay
            .forwarding
            .remaining_credit(&identity_a.node_id, &identity_b.node_id)
            .is_some(),
        "the pair must exist in ForwardTable after a completed send, for this test to mean anything"
    );

    // client_b reconnects (same identity — protocol.md 4.1 only requires
    // the timestamp to strictly advance, not the serial to change).
    drop(client_b1);
    let (mut client_b2, _) = TestClient::connect(
        addr,
        cert,
        &identity_b,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        20,
    )
    .await;
    client_b2.send(Record::Attach).await;
    let _ = client_b2.recv_roster_doc().await;

    // Without H2's fix, this pair's now-stale entry (from client_b1's
    // ended session) would still be sitting in `ForwardTable`,
    // unaffected by client_b2's fresh attach.
    assert!(
        relay
            .forwarding
            .remaining_credit(&identity_a.node_id, &identity_b.node_id)
            .is_none(),
        "a fresh attach for identity_b must reset (remove) every pair it appears in, \
         not leave its previous session's ledger entry behind"
    );

    // And a send against the fresh session succeeds using the fresh,
    // full WELCOME credit, not whatever the old session's ledger held.
    client_a
        .send(send_record(identity_b.node_id, vec![7u8; 100]))
        .await;
    match client_b2.recv().await {
        Some(Record::Recv { payload, .. }) => assert_eq!(payload, vec![7u8; 100]),
        other => panic!(
            "expected the post-reconnect RECV to succeed on a fresh credit ledger, got {other:?}"
        ),
    }
}

/// Polls until `node_id` is no longer registered (its session's teardown
/// has passed `detach`); the forwarding cleanup runs under the same lock,
/// so nothing further is pending once this returns.
async fn wait_until_detached(relay: &Relay, node_id: &NodeId) {
    for _ in 0..200 {
        if !relay.registry.is_attached(node_id) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("the session never detached");
}

#[tokio::test]
async fn a_disconnecting_node_releases_its_forwarding_pairs() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, node_a, mut client_b, node_b) =
        two_attached_members(&relay, addr, cert, relay_x25519).await;

    client_a.send(send_record(node_b, vec![1u8; 50])).await;
    match client_b.recv().await {
        Some(Record::Recv { .. }) => {}
        other => panic!("expected RECV, got {other:?}"),
    }
    match client_a.recv().await {
        Some(Record::Credit(_)) => {}
        other => panic!("expected CREDIT, got {other:?}"),
    }
    assert_eq!(
        relay.forwarding.pair_count_for(&node_a),
        1,
        "the pair must exist before the disconnect, for this test to mean anything"
    );

    drop(client_a);
    wait_until_detached(&relay, &node_a).await;

    assert_eq!(
        relay.forwarding.pair_count_for(&node_a),
        0,
        "a node that left and never returns must not keep forwarding state"
    );
    assert!(
        relay
            .forwarding
            .remaining_credit(&node_a, &node_b)
            .is_none(),
        "the (a, b) ledger must be gone"
    );
    assert!(
        relay.registry.is_attached(&node_b),
        "an unrelated node stays attached"
    );
}

#[tokio::test]
async fn a_superseded_sessions_teardown_keeps_the_new_sessions_forwarding_pairs() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity_a = generate_identity();
    let identity_b = generate_identity();
    let (node_a, node_b) = (identity_a.node_id, identity_b.node_id);
    let roster = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![
            RosterMember {
                node_id: node_a,
                min_serial: 1,
            },
            RosterMember {
                node_id: node_b,
                min_serial: 1,
            },
        ],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    relay
        .rosters()
        .set(&Roster::sign(&owner, &roster).unwrap())
        .unwrap();

    let (mut client_a1, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_a,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_a1.send(Record::Attach).await;
    let _ = client_a1.recv_roster_doc().await;

    let (mut client_b, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_b,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client_b.send(Record::Attach).await;
    let _ = client_b.recv_roster_doc().await;

    // The same identity attaches again, superseding the first session.
    let (mut client_a2, _) = TestClient::connect(
        addr,
        cert,
        &identity_a,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        20,
    )
    .await;
    client_a2.send(Record::Attach).await;
    let _ = client_a2.recv_roster_doc().await;

    // The new session builds forwarding state of its own.
    client_a2.send(send_record(node_b, vec![3u8; 40])).await;
    match client_b.recv().await {
        Some(Record::Recv { .. }) => {}
        other => panic!("expected RECV, got {other:?}"),
    }
    match client_a2.recv().await {
        Some(Record::Credit(_)) => {}
        other => panic!("expected CREDIT, got {other:?}"),
    }

    // Let the old session finish its teardown completely: it is told it
    // was superseded, then its connection ends.
    match client_a1.recv().await {
        Some(Record::Goaway(body)) => assert_eq!(body.reason, "superseded"),
        other => panic!("expected GOAWAY on the superseded connection, got {other:?}"),
    }
    drop(client_a1);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert_eq!(
        relay.forwarding.pair_count_for(&node_a),
        1,
        "the superseded session's teardown must not wipe the new session's pair"
    );
    assert!(
        relay
            .forwarding
            .remaining_credit(&node_a, &node_b)
            .is_some(),
        "the new session's (a, b) ledger must survive"
    );

    // And the surviving session's own departure does release it.
    drop(client_a2);
    wait_until_detached(&relay, &node_a).await;
    assert_eq!(relay.forwarding.pair_count_for(&node_a), 0);
}

#[tokio::test]
async fn a_send_to_an_authorized_but_unattached_node_gets_peer_offline() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    // `offline_member` is a legitimate Roster member (unlike an
    // unrelated stranger, who gets Forbidden instead — see
    // `a_send_to_an_unauthorized_stranger_gets_forbidden_not_peer_offline`,
    // finding M2) that simply never attaches.
    let owner = SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let identity = generate_identity();
    let offline_member = generate_identity();
    let roster = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: vec![
            RosterMember {
                node_id: identity.node_id,
                min_serial: 1,
            },
            RosterMember {
                node_id: offline_member.node_id,
                min_serial: 1,
            },
        ],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    relay
        .rosters()
        .set(&Roster::sign(&owner, &roster).unwrap())
        .unwrap();

    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &identity,
        relay_x25519,
        vec![network_id],
        HashMap::new(),
        1,
        10,
    )
    .await;
    client.send(Record::Attach).await;
    let _ = client.recv_roster_doc().await;

    client
        .send(send_record(offline_member.node_id, vec![1, 2, 3]))
        .await;

    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::PeerOffline),
        other => panic!("expected ERROR(PeerOffline), got {other:?}"),
    }
}

#[tokio::test]
async fn a_send_to_an_unauthorized_stranger_gets_forbidden_not_peer_offline() {
    // Regression test for finding M2: a sender with no legitimate
    // standing gets the same Forbidden answer whether the target NodeId
    // is real, attached, or offline — never a PeerOffline that would
    // leak the target's online status to someone unauthorized to ask.
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let identity = generate_identity();
    let (networks, seq) = seed_network(&relay, &[&identity]);
    let (mut client, _) =
        TestClient::connect(addr, cert, &identity, relay_x25519, networks, seq, 1, 10).await;
    client.send(Record::Attach).await;

    let stranger = NodeId::from([0x77; 32]);
    client.send(send_record(stranger, vec![1, 2, 3])).await;

    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::Forbidden),
        other => panic!("expected ERROR(Forbidden), got {other:?}"),
    }
}

#[tokio::test]
async fn a_send_with_no_common_roster_membership_is_forbidden() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    // Two independently attached nodes, each member of a network of its own: no
    // Roster lists the two of them together.
    let identity_a = generate_identity();
    let identity_b = generate_identity();
    let (networks_a, seq_a) = seed_network(&relay, &[&identity_a]);
    let (networks_b, seq_b) = seed_network(&relay, &[&identity_b]);
    let (mut client_a, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_a,
        relay_x25519,
        networks_a,
        seq_a,
        1,
        10,
    )
    .await;
    client_a.send(Record::Attach).await;
    let (mut client_b, _) = TestClient::connect(
        addr,
        cert,
        &identity_b,
        relay_x25519,
        networks_b,
        seq_b,
        1,
        10,
    )
    .await;
    client_b.send(Record::Attach).await;

    client_a
        .send(send_record(identity_b.node_id, vec![1]))
        .await;
    match client_a.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::Forbidden),
        other => panic!("expected ERROR(Forbidden), got {other:?}"),
    }
}

#[tokio::test]
async fn a_send_to_a_destination_that_opted_out_of_peer_traffic_is_peer_offline() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, _node_a, mut client_b, node_b) =
        two_attached_members(&relay, addr, cert, relay_x25519).await;

    client_b
        .send(Record::Advertise(AdvertiseBody {
            v: PROTOCOL_VERSION,
            shares: vec![],
            accept_peers: false,
        }))
        .await;
    match client_b.recv().await {
        Some(Record::AdvertiseAck(_)) => {}
        other => panic!("expected an ADVERTISE_ACK, got {other:?}"),
    }

    client_a.send(send_record(node_b, vec![1, 2, 3])).await;
    match client_a.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::PeerOffline),
        other => panic!("expected ERROR(PeerOffline), got {other:?}"),
    }
}

/// Two tenants on one relay (isolation rule I4, attack A4): the owner of network X lists the
/// sender `s` and also `d`, a node that really belongs to the other tenant's network Y and
/// never joined X.
struct ForeignListing {
    relay: Relay,
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    relay_x25519: X25519PublicKey,
    network_x: NetworkId,
    network_y: NetworkId,
    s: TestIdentity,
    d: TestIdentity,
}

async fn foreign_listing() -> ForeignListing {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let owner_x = SigningKey::generate(&mut rand::rng());
    let owner_y = SigningKey::generate(&mut rand::rng());
    let network_x = NetworkId::from(owner_x.verifying_key().to_bytes());
    let network_y = NetworkId::from(owner_y.verifying_key().to_bytes());
    let (s, d) = (generate_identity(), generate_identity());
    relay
        .rosters()
        .set(&evict_roster(
            &owner_x,
            network_x,
            1,
            &[(s.node_id, 1), (d.node_id, 1)],
            &[],
        ))
        .unwrap();
    relay
        .rosters()
        .set(&evict_roster(
            &owner_y,
            network_y,
            1,
            &[(d.node_id, 1)],
            &[],
        ))
        .unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    ForeignListing {
        relay,
        addr,
        cert,
        relay_x25519,
        network_x,
        network_y,
        s,
        d,
    }
}

impl ForeignListing {
    /// Connects `who` claiming `networks`, attaches, and reads the catch-up Roster pushes.
    async fn attach(
        &self,
        who: &TestIdentity,
        networks: Vec<NetworkId>,
        timestamp_byte: u8,
    ) -> TestClient {
        let (mut client, _) = TestClient::connect(
            self.addr,
            self.cert.clone(),
            who,
            self.relay_x25519,
            networks.clone(),
            HashMap::new(),
            1,
            timestamp_byte,
        )
        .await;
        client.send(Record::Attach).await;
        for _ in &networks {
            let _ = client.recv_roster_doc().await;
        }
        client
    }

    /// `s` sends 100 reliable bytes to `d`; returns the ERROR it got, after checking that the
    /// credit came back too (the refusal reimbursed it).
    async fn refused_send(&self, s: &mut TestClient) -> menzil_proto::ErrorBody {
        s.send(send_record(self.d.node_id, vec![7u8; 100])).await;
        let (mut error, mut credit) = (None, None);
        for _ in 0..2 {
            match s.recv().await {
                Some(Record::Error(body)) => error = Some(body),
                Some(Record::Credit(body)) => credit = Some(body),
                other => panic!("expected ERROR and CREDIT, got {other:?}"),
            }
        }
        let credit = credit.expect("a refused reliable SEND must be reimbursed");
        assert_eq!(credit.peer, self.d.node_id);
        assert_eq!(credit.bytes, 100);
        error.expect("an ERROR")
    }
}

#[tokio::test]
async fn a_foreign_owner_listing_a_node_gets_byte_identical_peer_offline_and_the_node_hears_nothing()
 {
    let f = foreign_listing().await;
    let mut s = f.attach(&f.s, vec![f.network_x], 10).await;

    // 1. d is offline.
    let offline = f.refused_send(&mut s).await;
    assert_eq!(offline.code, ErrorCode::PeerOffline);

    // 2. d is online, but claims only Y.
    let mut d = f.attach(&f.d, vec![f.network_y], 10).await;
    assert!(f.relay.registry.is_attached(&f.d.node_id));
    let online = f.refused_send(&mut s).await;

    // 3. d is online, claims only Y, and takes no peer traffic.
    d.send(Record::Advertise(AdvertiseBody {
        v: PROTOCOL_VERSION,
        shares: vec![],
        accept_peers: false,
    }))
    .await;
    match d.recv().await {
        Some(Record::AdvertiseAck(_)) => {}
        other => panic!("expected an ADVERTISE_ACK, got {other:?}"),
    }
    let closed = f.refused_send(&mut s).await;

    assert_eq!(online, offline, "online must read exactly like offline");
    assert_eq!(
        closed, offline,
        "closed to peers must read exactly like offline"
    );
    // Nothing reached d: its next record is the answer to its own PING.
    ping_pong(&mut d, [3; 8]).await;
    assert_eq!(
        f.relay
            .forwarding
            .remaining_credit(&f.s.node_id, &f.d.node_id),
        None,
        "refusals reserve no pair credit"
    );
}

#[tokio::test]
async fn a_destination_that_reattaches_with_other_claims_is_judged_by_its_new_claims() {
    let f = foreign_listing().await;
    let mut s = f.attach(&f.s, vec![f.network_x], 10).await;

    // d claims X (really joined it): forwarded.
    let mut d1 = f.attach(&f.d, vec![f.network_x], 10).await;
    s.send(send_record(f.d.node_id, vec![1u8; 100])).await;
    match d1.recv().await {
        Some(Record::Recv { src, payload, .. }) => {
            assert_eq!(src, f.s.node_id);
            assert_eq!(payload, vec![1u8; 100]);
        }
        other => panic!("expected RECV, got {other:?}"),
    }
    match s.recv().await {
        Some(Record::Credit(_)) => {}
        other => panic!("expected CREDIT, got {other:?}"),
    }

    // d re-attaches claiming only Y: the very next SEND is refused like an offline node.
    let mut d2 = f.attach(&f.d, vec![f.network_y], 11).await;
    let refused = f.refused_send(&mut s).await;
    assert_eq!(refused.code, ErrorCode::PeerOffline);
    ping_pong(&mut d2, [4; 8]).await;

    // And claiming both again: forwarded again, both ways.
    let mut d3 = f.attach(&f.d, vec![f.network_x, f.network_y], 12).await;
    s.send(send_record(f.d.node_id, vec![2u8; 100])).await;
    match d3.recv().await {
        Some(Record::Recv { payload, .. }) => assert_eq!(payload, vec![2u8; 100]),
        other => panic!("expected RECV, got {other:?}"),
    }
    match s.recv().await {
        Some(Record::Credit(_)) => {}
        other => panic!("expected CREDIT, got {other:?}"),
    }
    d3.send(send_record(f.s.node_id, vec![3u8; 100])).await;
    match s.recv().await {
        Some(Record::Recv { src, payload, .. }) => {
            assert_eq!(src, f.d.node_id);
            assert_eq!(payload, vec![3u8; 100]);
        }
        other => panic!("expected RECV, got {other:?}"),
    }
}

#[tokio::test]
async fn members_of_a_common_claimed_network_forward_both_ways() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, node_a, mut client_b, node_b) =
        two_attached_members(&relay, addr, cert, relay_x25519).await;

    client_a.send(send_record(node_b, vec![1u8; 100])).await;
    match client_b.recv().await {
        Some(Record::Recv { src, .. }) => assert_eq!(src, node_a),
        other => panic!("expected RECV, got {other:?}"),
    }
    client_b.send(send_record(node_a, vec![2u8; 100])).await;
    // client_a first gets the CREDIT for its own SEND, then the RECV.
    let mut got_recv = false;
    for _ in 0..2 {
        match client_a.recv().await {
            Some(Record::Recv { src, payload, .. }) => {
                assert_eq!(src, node_b);
                assert_eq!(payload, vec![2u8; 100]);
                got_recv = true;
            }
            Some(Record::Credit(_)) => {}
            other => panic!("expected CREDIT or RECV, got {other:?}"),
        }
    }
    assert!(got_recv);
}

#[tokio::test]
async fn a_reliable_send_beyond_credit_closes_the_session() {
    let small_credit = Limits {
        max_record: 65_535,
        max_peers: 10,
        credit: 50,
    };
    let (relay, listener, cert, relay_x25519) = bind_test_relay_with_limits(small_credit).await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let (mut client_a, _node_a, _client_b, node_b) =
        two_attached_members(&relay, addr, cert, relay_x25519).await;

    // Credit is only 50 bytes; this single SEND already exceeds it
    // (protocol.md 4.2: "a reliable SEND beyond credit is a protocol
    // violation and closes the session").
    client_a.send(send_record(node_b, vec![0u8; 51])).await;

    match client_a.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::CreditExceeded),
        other => panic!("expected ERROR(CreditExceeded), got {other:?}"),
    }
    assert_eq!(
        client_a.recv().await,
        None,
        "the relay closes the connection after a credit violation"
    );
}

#[tokio::test]
async fn max_peers_has_no_spec_default_and_is_always_the_caller_choice() {
    // Not a behavioral test: a standing regression guard for a
    // deliberate design decision (see `Relay::new`'s docs) — protocol.md
    // 10's limits table has no `max_peers` row, unlike `max_record` and
    // `credit`, so this field must never grow a silently invented
    // default the way those two safely could.
    let limits = test_limits();
    assert_eq!(limits.max_peers, 10);
}

// --- Eviction when an adopted Roster takes a node out of standing (protocol.md 7.3; L4k K5) ---

use crate::session::StandingWatch;
use menzil_proto::RevokedMember;

/// A Roster of `network_id` signed by `owner` that the relay will adopt now: `members` as
/// `(node, min_serial)` and `revoked` nodes.
fn evict_roster(
    owner: &SigningKey,
    network_id: NetworkId,
    seq: u64,
    members: &[(NodeId, u32)],
    revoked: &[NodeId],
) -> Roster {
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq,
        issued: real_now(),
        expires: real_now() + 7 * DAY,
        members: members
            .iter()
            .map(|&(node_id, min_serial)| RosterMember {
                node_id,
                min_serial,
            })
            .collect(),
        revoked: revoked
            .iter()
            .map(|&node_id| RevokedMember {
                node_id,
                since: real_now(),
            })
            .collect(),
        stewards: vec![],
        labels: vec![],
    };
    Roster::sign(owner, &body).unwrap()
}

/// What a node out of standing was sent, the relay's state afterwards, and that others were
/// left alone.
struct Eviction {
    /// Everything `x` received from the Roster push on, until its connection ended.
    x_records: Vec<Record>,
    relay: Relay,
}

/// Network A has `x` (serial 1) and `y`; network B, another owner's, has `z`. Everyone connects
/// (`x` attaches only when `attach_x`), then `y` pushes the Roster `next` builds (seq 2, from the
/// owner of A, with `x` and `y` as arguments) over DOC. Reads `x` to the end of its connection,
/// then checks that `y` and `z` are still attached and answer, and that `x` is not attached.
async fn eviction_scenario(
    attach_x: bool,
    next: impl FnOnce(&SigningKey, NetworkId, NodeId, NodeId) -> Roster,
) -> Eviction {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let (x, y, z) = (
        generate_identity(),
        generate_identity(),
        generate_identity(),
    );
    let owner_a = SigningKey::generate(&mut rand::rng());
    let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
    let owner_b = SigningKey::generate(&mut rand::rng());
    let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
    relay
        .rosters()
        .set(&evict_roster(
            &owner_a,
            network_a,
            1,
            &[(x.node_id, 1), (y.node_id, 1)],
            &[],
        ))
        .unwrap();
    relay
        .rosters()
        .set(&evict_roster(
            &owner_b,
            network_b,
            1,
            &[(z.node_id, 1)],
            &[],
        ))
        .unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let seen = |network_id| HashMap::from([(network_id, 1u64)]);
    let (mut client_x, _) = TestClient::connect(
        addr,
        cert.clone(),
        &x,
        relay_x25519,
        vec![network_a],
        seen(network_a),
        1,
        10,
    )
    .await;
    let (mut client_y, _) = TestClient::connect(
        addr,
        cert.clone(),
        &y,
        relay_x25519,
        vec![network_a],
        seen(network_a),
        1,
        10,
    )
    .await;
    let (mut client_z, _) = TestClient::connect(
        addr,
        cert,
        &z,
        relay_x25519,
        vec![network_b],
        seen(network_b),
        1,
        10,
    )
    .await;
    if attach_x {
        client_x.send(Record::Attach).await;
    }
    client_y.send(Record::Attach).await;
    client_z.send(Record::Attach).await;
    ping_pong(&mut client_x, [1; 8]).await;
    ping_pong(&mut client_y, [2; 8]).await;
    ping_pong(&mut client_z, [3; 8]).await;
    assert_eq!(relay.registry.is_attached(&x.node_id), attach_x);
    assert!(relay.registry.is_attached(&y.node_id));
    assert!(relay.registry.is_attached(&z.node_id));

    let next_roster = next(&owner_a, network_a, x.node_id, y.node_id);
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &next_roster.encode()) {
        client_y.send(record).await;
    }

    let mut x_records = Vec::new();
    while let Some(record) =
        tokio::time::timeout(std::time::Duration::from_secs(10), client_x.recv())
            .await
            .expect("x's connection must end")
    {
        x_records.push(record);
    }

    assert!(
        !relay.registry.is_attached(&x.node_id),
        "the evicted node is detached once its connection has ended"
    );
    ping_pong(&mut client_y, [4; 8]).await;
    ping_pong(&mut client_z, [5; 8]).await;
    assert!(relay.registry.is_attached(&y.node_id));
    assert!(
        relay.registry.is_attached(&z.node_id),
        "a node of another network is not touched"
    );
    Eviction { x_records, relay }
}

/// The ERROR code and GOAWAY of an eviction: the ERROR first, the GOAWAY last, `revoked`.
fn assert_told_out(eviction: &Eviction, code: ErrorCode) {
    let records = &eviction.x_records;
    let error_at = records
        .iter()
        .position(|record| matches!(record, Record::Error(body) if body.code == code))
        .unwrap_or_else(|| panic!("expected ERROR {code:?} among {records:?}"));
    match records.last() {
        Some(Record::Goaway(body)) => {
            assert_eq!(body.reason, "revoked");
            assert_eq!(body.retry_after_ms, 0);
        }
        other => panic!("expected GOAWAY as the last record, got {other:?}"),
    }
    assert_eq!(
        records
            .iter()
            .filter(|r| matches!(r, Record::Goaway(_)))
            .count(),
        1
    );
    assert!(
        error_at < records.len() - 1,
        "the ERROR comes before the GOAWAY"
    );
}

#[tokio::test]
async fn an_attached_node_that_an_adopted_roster_revokes_is_told_and_detached() {
    let eviction = eviction_scenario(true, |owner, network, x, y| {
        evict_roster(owner, network, 2, &[(y, 1)], &[x])
    })
    .await;
    assert_told_out(&eviction, ErrorCode::Revoked);
    // The relay now holds the revoking Roster, and refuses the node's HELLO.
    assert_eq!(eviction.relay.rosters().seqs().values().max(), Some(&2));
}

#[tokio::test]
async fn a_node_the_adopted_roster_no_longer_lists_is_told_not_member() {
    let eviction = eviction_scenario(true, |owner, network, _x, y| {
        evict_roster(owner, network, 2, &[(y, 1)], &[])
    })
    .await;
    assert_told_out(&eviction, ErrorCode::NotMember);
}

#[tokio::test]
async fn a_min_serial_raised_above_the_hello_serial_evicts_a_still_listed_node() {
    let eviction = eviction_scenario(true, |owner, network, x, y| {
        evict_roster(owner, network, 2, &[(x, 2), (y, 1)], &[])
    })
    .await;
    assert_told_out(&eviction, ErrorCode::StaleSerial);
}

#[tokio::test]
async fn a_session_that_has_not_attached_yet_is_evicted_too() {
    let eviction = eviction_scenario(false, |owner, network, x, y| {
        evict_roster(owner, network, 2, &[(y, 1)], &[x])
    })
    .await;
    assert_told_out(&eviction, ErrorCode::Revoked);
}

#[tokio::test]
async fn a_roster_that_leaves_a_node_in_standing_ends_nothing() {
    // `min_serial` raised to exactly the serial the node presented is no eviction.
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let (x, y) = (generate_identity(), generate_identity());
    let owner = SigningKey::generate(&mut rand::rng());
    let network = NetworkId::from(owner.verifying_key().to_bytes());
    relay
        .rosters()
        .set(&evict_roster(
            &owner,
            network,
            1,
            &[(x.node_id, 1), (y.node_id, 1)],
            &[],
        ))
        .unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    let seen = HashMap::from([(network, 1u64)]);
    let (mut client_x, _) = TestClient::connect(
        addr,
        cert.clone(),
        &x,
        relay_x25519,
        vec![network],
        seen.clone(),
        3,
        10,
    )
    .await;
    let (mut client_y, _) =
        TestClient::connect(addr, cert, &y, relay_x25519, vec![network], seen, 1, 10).await;
    client_x.send(Record::Attach).await;
    client_y.send(Record::Attach).await;
    ping_pong(&mut client_x, [1; 8]).await;
    ping_pong(&mut client_y, [2; 8]).await;

    let next = evict_roster(&owner, network, 2, &[(x.node_id, 3), (y.node_id, 1)], &[]);
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &next.encode()) {
        client_y.send(record).await;
    }
    // x hears the fan-out of the new Roster, and nothing else.
    assert_eq!(client_x.recv_roster_doc().await.decode().unwrap().seq, 2);
    ping_pong(&mut client_x, [3; 8]).await;
    assert!(relay.registry.is_attached(&x.node_id));
}

#[tokio::test]
async fn a_standing_watch_wakes_only_for_a_claimed_network_or_missed_notices() {
    let (relay, _listener, _cert, _x25519) = bind_test_relay().await;
    let owner_a = SigningKey::generate(&mut rand::rng());
    let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
    let owner_b = SigningKey::generate(&mut rand::rng());
    let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
    let node = NodeId::from([5u8; 32]);
    for (owner, network) in [(&owner_a, network_a), (&owner_b, network_b)] {
        relay
            .rosters()
            .set(&evict_roster(owner, network, 1, &[(node, 1)], &[]))
            .unwrap();
    }
    let short = std::time::Duration::from_millis(200);
    let long = std::time::Duration::from_secs(5);
    let mut watch = StandingWatch::new(&relay);

    // A newer Roster of a network not claimed wakes nobody.
    relay
        .rosters()
        .set(&evict_roster(&owner_b, network_b, 2, &[(node, 1)], &[]))
        .unwrap();
    assert!(
        tokio::time::timeout(short, watch.changed(&[network_a]))
            .await
            .is_err(),
        "another network's Roster is none of this session's business"
    );
    // One of the claimed network does.
    relay
        .rosters()
        .set(&evict_roster(&owner_a, network_a, 2, &[(node, 1)], &[]))
        .unwrap();
    assert!(
        tokio::time::timeout(long, watch.changed(&[network_a]))
            .await
            .is_ok()
    );

    // Missed notices (more than the backlog) wake it whatever the networks were.
    for seq in 3..120 {
        relay
            .rosters()
            .set(&evict_roster(&owner_b, network_b, seq, &[(node, 1)], &[]))
            .unwrap();
    }
    assert!(
        tokio::time::timeout(long, watch.changed(&[network_a]))
            .await
            .is_ok(),
        "a lagged watch looks at every claimed network"
    );
}

// --- Round 12: standing is judged per claimed network, and an evicted node hears the Roster ---

/// Reads `client` until its connection ends, giving up after ten seconds.
async fn read_to_end(client: &mut TestClient) -> Vec<Record> {
    let mut records = Vec::new();
    while let Some(record) = tokio::time::timeout(std::time::Duration::from_secs(10), client.recv())
        .await
        .expect("the connection must end")
    {
        records.push(record);
    }
    records
}

/// Round 12, N1: a node evicted by a Roster that only the store hears of (no DOC fan-out, so the
/// eviction path is the only way the node can learn it) gets that Roster first, then the ERROR,
/// then the GOAWAY.
async fn evicted_node_hears_the_roster(
    expected: ErrorCode,
    next: impl FnOnce(&SigningKey, NetworkId, NodeId, NodeId) -> Roster,
) {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let (x, y) = (generate_identity(), generate_identity());
    let owner = SigningKey::generate(&mut rand::rng());
    let network = NetworkId::from(owner.verifying_key().to_bytes());
    relay
        .rosters()
        .set(&evict_roster(
            &owner,
            network,
            1,
            &[(x.node_id, 1), (y.node_id, 1)],
            &[],
        ))
        .unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    let (mut client_x, _) = TestClient::connect(
        addr,
        cert,
        &x,
        relay_x25519,
        vec![network],
        HashMap::from([(network, 1u64)]),
        1,
        10,
    )
    .await;
    client_x.send(Record::Attach).await;
    ping_pong(&mut client_x, [1; 8]).await;

    let next = next(&owner, network, x.node_id, y.node_id);
    relay.rosters().set(&next).unwrap();

    let mut reassembler = DocReassembler::new();
    let mut heard = None;
    let mut kinds = Vec::new();
    for record in read_to_end(&mut client_x).await {
        match record {
            Record::Doc(body) => {
                assert!(
                    kinds.is_empty(),
                    "the DOC comes before the ERROR and the GOAWAY: {kinds:?}"
                );
                if let Some((doc_type, bytes)) = reassembler.accept(&body).unwrap() {
                    assert_eq!(doc_type, DocType::Roster);
                    heard = Some(Roster::decode_strict(&bytes).unwrap());
                }
            }
            Record::Error(body) => kinds.push(format!("ERROR {:?}", body.code)),
            Record::Goaway(_) => kinds.push("GOAWAY".to_string()),
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(
        kinds,
        vec![format!("ERROR {expected:?}"), "GOAWAY".to_string()]
    );
    assert_eq!(heard.expect("the Roster was sent").decode().unwrap().seq, 2);
}

#[tokio::test]
async fn a_revoked_node_is_sent_the_revoking_roster_before_the_error() {
    evicted_node_hears_the_roster(ErrorCode::Revoked, |owner, network, x, y| {
        evict_roster(owner, network, 2, &[(y, 1)], &[x])
    })
    .await;
}

#[tokio::test]
async fn a_dropped_node_is_sent_the_dropping_roster_before_the_error() {
    evicted_node_hears_the_roster(ErrorCode::NotMember, |owner, network, _x, y| {
        evict_roster(owner, network, 2, &[(y, 1)], &[])
    })
    .await;
}

#[tokio::test]
async fn a_node_below_a_raised_min_serial_is_sent_that_roster_before_the_error() {
    evicted_node_hears_the_roster(ErrorCode::StaleSerial, |owner, network, x, y| {
        evict_roster(owner, network, 2, &[(x, 2), (y, 1)], &[])
    })
    .await;
}

/// Round 12, M1 setup: network A (the attacker's) and B (the victim `z`'s, with `w`). The
/// attacker is a member of A only and claims nothing.
struct SharedRelay {
    relay: Relay,
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    relay_x25519: X25519PublicKey,
    owner_a: SigningKey,
    network_a: NetworkId,
    owner_b: SigningKey,
    network_b: NetworkId,
    attacker: TestIdentity,
    z: TestIdentity,
    w: TestIdentity,
}

async fn shared_relay() -> SharedRelay {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let (attacker, z, w) = (
        generate_identity(),
        generate_identity(),
        generate_identity(),
    );
    let owner_a = SigningKey::generate(&mut rand::rng());
    let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
    let owner_b = SigningKey::generate(&mut rand::rng());
    let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
    relay
        .rosters()
        .set(&evict_roster(
            &owner_a,
            network_a,
            1,
            &[(attacker.node_id, 1)],
            &[],
        ))
        .unwrap();
    relay
        .rosters()
        .set(&evict_roster(
            &owner_b,
            network_b,
            1,
            &[(z.node_id, 1), (w.node_id, 1)],
            &[],
        ))
        .unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    SharedRelay {
        relay,
        addr,
        cert,
        relay_x25519,
        owner_a,
        network_a,
        owner_b,
        network_b,
        attacker,
        z,
        w,
    }
}

impl SharedRelay {
    async fn connect(
        &self,
        who: &TestIdentity,
        networks: Vec<NetworkId>,
        seq: u64,
        ts: u8,
    ) -> TestClient {
        let seen = networks.iter().map(|n| (*n, seq)).collect();
        TestClient::connect(
            self.addr,
            self.cert.clone(),
            who,
            self.relay_x25519,
            networks,
            seen,
            1,
            ts,
        )
        .await
        .0
    }

    /// The attacker pushes a Roster of A that lists `z` with `min_serial` u32::MAX.
    fn poison(&self, seq: u64) -> Vec<Record> {
        let roster = evict_roster(
            &self.owner_a,
            self.network_a,
            seq,
            &[(self.attacker.node_id, 1), (self.z.node_id, u32::MAX)],
            &[],
        );
        menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode())
    }
}

/// Round 12, M1: the owner of network A lists a node of network B (never admitted to A) with a
/// huge `min_serial`. The node, which claims only B, is neither refused at HELLO nor evicted when
/// B's own Roster is renewed.
#[tokio::test]
async fn another_networks_min_serial_neither_evicts_nor_locks_out_a_node() {
    let shared = shared_relay().await;
    let mut client_z = shared
        .connect(&shared.z, vec![shared.network_b], 1, 10)
        .await;
    let mut client_w = shared
        .connect(&shared.w, vec![shared.network_b], 1, 10)
        .await;
    client_z.send(Record::Attach).await;
    client_w.send(Record::Attach).await;
    ping_pong(&mut client_z, [1; 8]).await;
    ping_pong(&mut client_w, [2; 8]).await;

    // The attacker is a real member of A and claims it: since MT2 a DOC for a network the
    // session did not claim is dropped, so this is the case that still reaches the store.
    let mut attacker = shared
        .connect(&shared.attacker, vec![shared.network_a], 1, 10)
        .await;
    for record in shared.poison(2) {
        attacker.send(record).await;
    }
    ping_pong(&mut attacker, [3; 8]).await;
    assert_eq!(
        shared.relay.rosters().seqs().get(&shared.network_a),
        Some(&2)
    );

    // B's owner renews, nothing about z changes: the eviction judge looks at B only.
    let renewal = evict_roster(
        &shared.owner_b,
        shared.network_b,
        2,
        &[(shared.z.node_id, 1), (shared.w.node_id, 1)],
        &[],
    );
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &renewal.encode()) {
        client_w.send(record).await;
    }
    assert_eq!(client_z.recv_roster_doc().await.decode().unwrap().seq, 2);
    ping_pong(&mut client_z, [4; 8]).await;
    assert!(shared.relay.registry.is_attached(&shared.z.node_id));

    // A fresh HELLO claiming B is accepted too.
    let mut again = shared
        .connect(&shared.z, vec![shared.network_b], 2, 20)
        .await;
    again.send(Record::Attach).await;
    ping_pong(&mut again, [5; 8]).await;
}

/// Round 12, M1 and the lagged watch: a burst of the attacker's Rosters makes the victim's
/// watch miss notices, which re-judges it; it is in standing in the one network it claimed and
/// stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_of_other_networks_rosters_does_not_evict_an_honest_node() {
    let shared = shared_relay().await;
    let mut client_z = shared
        .connect(&shared.z, vec![shared.network_b], 1, 10)
        .await;
    client_z.send(Record::Attach).await;
    ping_pong(&mut client_z, [1; 8]).await;
    // The attacker is a real member of A and claims it: since MT2 a DOC for a network the
    // session did not claim is dropped, so this is the case that still reaches the store.
    let mut attacker = shared
        .connect(&shared.attacker, vec![shared.network_a], 1, 10)
        .await;
    let mut all = Vec::new();
    for seq in 2..200u64 {
        all.extend(shared.poison(seq));
    }
    for record in all {
        attacker.send(record).await;
    }
    ping_pong(&mut attacker, [3; 8]).await;
    assert_eq!(
        shared.relay.rosters().seqs().get(&shared.network_a),
        Some(&199)
    );
    // Give z's task the time to wake on the lag and judge itself.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    ping_pong(&mut client_z, [2; 8]).await;
    assert!(shared.relay.registry.is_attached(&shared.z.node_id));
}

/// Round 12, M1: a node that does claim the network whose Roster holds the high `min_serial` is
/// still judged by it (the owner of A decides about A).
#[tokio::test]
async fn a_claimed_networks_own_min_serial_still_evicts() {
    let shared = shared_relay().await;
    // z is a member of A now, at serial 1; it claims A and B.
    let admit = evict_roster(
        &shared.owner_a,
        shared.network_a,
        2,
        &[(shared.attacker.node_id, 1), (shared.z.node_id, 1)],
        &[],
    );
    shared.relay.rosters().set(&admit).unwrap();
    let mut client_z = shared
        .connect(&shared.z, vec![shared.network_a, shared.network_b], 2, 10)
        .await;
    client_z.send(Record::Attach).await;
    ping_pong(&mut client_z, [1; 8]).await;
    let poison = evict_roster(
        &shared.owner_a,
        shared.network_a,
        3,
        &[(shared.attacker.node_id, 1), (shared.z.node_id, 5)],
        &[],
    );
    shared.relay.rosters().set(&poison).unwrap();
    let records = read_to_end(&mut client_z).await;
    assert!(
        records
            .iter()
            .any(|r| matches!(r, Record::Error(body) if body.code == ErrorCode::StaleSerial))
    );
}

// The accept loop's handling of peers that never finish their handshake
// (`Relay::serve_with`): the TCP accept is never blocked by one, a stalled
// handshake is closed after the timeout, and the number of handshakes in
// flight is bounded.

use crate::relay::AcceptConfig;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Waits up to `within` for the relay to close `sock` (EOF or reset).
/// Returns false if the socket was still open when the time ran out.
async fn closed_by_relay(sock: &mut TcpStream, within: Duration) -> bool {
    let mut buf = [0u8; 16];
    match tokio::time::timeout(within, sock.read(&mut buf)).await {
        Err(_elapsed) => false,
        Ok(Ok(0)) | Ok(Err(_)) => true,
        Ok(Ok(n)) => panic!("the relay sent {n} unexpected bytes to a silent peer"),
    }
}

/// A full session setup (TLS, WebSocket, Noise, WELCOME) plus a PING/PONG
/// with a fresh identity: proof the relay really serves this client.
async fn assert_served(
    relay: &Relay,
    addr: SocketAddr,
    cert: &CertificateDer<'static>,
    relay_x25519: X25519PublicKey,
) -> TestClient {
    let identity = generate_identity();
    let (networks, seq) = seed_network(relay, &[&identity]);
    let (mut client, _welcome) = tokio::time::timeout(
        Duration::from_secs(5),
        TestClient::connect(
            addr,
            cert.clone(),
            &identity,
            relay_x25519,
            networks,
            seq,
            1,
            10,
        ),
    )
    .await
    .expect("the relay did not serve a real client in time");
    ping_pong(&mut client, [7; 8]).await;
    client
}

#[tokio::test]
async fn an_idle_socket_does_not_block_other_clients() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    // Connects and never says a word; kept open for the whole test.
    let _idle = TcpStream::connect(addr).await.unwrap();
    // Let the accept loop take it before the real client arrives.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let _served = assert_served(&relay, addr, &cert, relay_x25519).await;
}

#[tokio::test]
async fn a_stalled_handshake_is_closed_after_the_timeout() {
    let (relay, listener, _cert, _x) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let config = AcceptConfig {
        handshake_timeout: Duration::from_millis(300),
        max_inflight_handshakes: 256,
    };
    tokio::spawn(async move { relay.serve_with(&listener, config).await });

    let mut stalled = TcpStream::connect(addr).await.unwrap();
    let started = std::time::Instant::now();
    assert!(
        !closed_by_relay(&mut stalled, Duration::from_millis(100)).await,
        "the relay closed a young handshake early"
    );
    assert!(
        closed_by_relay(&mut stalled, Duration::from_secs(5)).await,
        "the relay never closed a stalled handshake"
    );
    assert!(started.elapsed() >= Duration::from_millis(250));
}

#[tokio::test]
async fn handshakes_in_flight_are_limited_and_the_slot_is_freed_afterwards() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let config = AcceptConfig {
        handshake_timeout: Duration::from_millis(1000),
        max_inflight_handshakes: 1,
    };
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve_with(&listener, config).await });

    // The only slot is taken by a peer that never speaks.
    let mut stalled = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // A second socket is dropped at once, long before the stalled
    // handshake's timeout, and while that one is still open.
    let mut second = TcpStream::connect(addr).await.unwrap();
    assert!(
        closed_by_relay(&mut second, Duration::from_millis(700)).await,
        "a connection over the in-flight limit was not dropped at once"
    );
    assert!(
        !closed_by_relay(&mut stalled, Duration::from_millis(20)).await,
        "the stalled handshake ended before its timeout"
    );

    // Once the stalled handshake times out, its slot is free again.
    assert!(closed_by_relay(&mut stalled, Duration::from_secs(5)).await);
    let _third = assert_served(&relay, addr, &cert, relay_x25519).await;
    // The slot is for the handshake only, not for the session: with the
    // third session still running, a fourth client is served too.
    let _fourth = assert_served(&relay, addr, &cert, relay_x25519).await;
}

// ---- WELCOME lists only what the peer proved (MT1, isolation rule I1) -----------------------

/// A relay serving three unrelated networks, each listing the NodeIds given for it.
struct ThreeNetworks {
    relay: Relay,
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    relay_x25519: X25519PublicKey,
    owners: [SigningKey; 3],
    networks: [NetworkId; 3],
}

async fn three_networks(listed: [&[NodeId]; 3]) -> ThreeNetworks {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let owners = [
        SigningKey::generate(&mut rand::rng()),
        SigningKey::generate(&mut rand::rng()),
        SigningKey::generate(&mut rand::rng()),
    ];
    let networks = owners
        .each_ref()
        .map(|owner| NetworkId::from(owner.verifying_key().to_bytes()));
    for index in 0..3 {
        let members: Vec<(NodeId, u32)> = listed[index].iter().map(|&node| (node, 1)).collect();
        relay
            .rosters()
            .set(&evict_roster(
                &owners[index],
                networks[index],
                1 + index as u64,
                &members,
                &[],
            ))
            .unwrap();
    }
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    ThreeNetworks {
        relay,
        addr,
        cert,
        relay_x25519,
        owners,
        networks,
    }
}

impl ThreeNetworks {
    /// The `seq` each network was seeded with (`1 + index`, so a leak of the wrong network or
    /// the wrong number shows).
    fn seeded(&self, indexes: &[usize]) -> HashMap<NetworkId, u64> {
        indexes
            .iter()
            .map(|&index| (self.networks[index], 1 + index as u64))
            .collect()
    }

    async fn connect_ik(
        &self,
        who: &TestIdentity,
        claims: Vec<NetworkId>,
        timestamp_byte: u8,
    ) -> (TestClient, WelcomeBody) {
        TestClient::connect(
            self.addr,
            self.cert.clone(),
            who,
            self.relay_x25519,
            claims,
            HashMap::new(),
            1,
            timestamp_byte,
        )
        .await
    }
}

#[tokio::test]
async fn a_stranger_with_a_fresh_key_sees_no_networks_in_welcome() {
    let member = generate_identity();
    let three = three_networks([&[member.node_id], &[member.node_id], &[]]).await;
    let stranger = generate_identity();

    // Claims nothing: refused (D6), and nothing listed.
    let (mut client, welcome) = three.connect_ik(&stranger, vec![], 10).await;
    assert!(
        welcome.rosters.is_empty(),
        "a stranger enumerated {:?}",
        welcome.rosters
    );
    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR(not_member), got {other:?}"),
    }

    // Claims a network that exists: refused, still nothing listed.
    let (mut client, welcome) = three
        .connect_ik(&stranger, three.networks.to_vec(), 20)
        .await;
    assert!(welcome.rosters.is_empty());
    assert!(matches!(client.recv().await, Some(Record::Error(_))));
}

#[tokio::test]
async fn an_ik_member_of_one_of_three_networks_sees_only_that_one() {
    let member = generate_identity();
    let three = three_networks([&[member.node_id], &[], &[]]).await;

    let (mut client, welcome) = three.connect_ik(&member, vec![three.networks[0]], 10).await;
    assert_eq!(welcome.rosters, three.seeded(&[0]));
    client.send(Record::Attach).await;
    // No `roster_seq` was claimed, so the relay's attach time catch up arrives first.
    client.recv_roster_doc().await;
    ping_pong(&mut client, [2; 8]).await;
}

#[tokio::test]
async fn an_ik_welcome_lists_the_claimed_networks_not_every_network_the_node_is_listed_in() {
    let member = generate_identity();
    let three = three_networks([&[member.node_id], &[member.node_id], &[member.node_id]]).await;

    let (_, welcome) = three.connect_ik(&member, vec![three.networks[1]], 10).await;
    assert_eq!(welcome.rosters, three.seeded(&[1]));

    let (_, welcome) = three
        .connect_ik(&member, vec![three.networks[0], three.networks[2]], 20)
        .await;
    assert_eq!(welcome.rosters, three.seeded(&[0, 2]));

    let (_, welcome) = three.connect_ik(&member, vec![], 30).await;
    assert!(
        welcome.rosters.is_empty(),
        "listed but claiming nothing (refused, D6)"
    );
}

#[tokio::test]
async fn an_xx_member_sees_no_networks_and_its_roster_push_is_handled_as_before() {
    let member = generate_identity();
    let three = three_networks([&[member.node_id], &[], &[]]).await;
    let network = three.networks[0];

    let (mut client, welcome) =
        TestClient::connect_xx(three.addr, three.cert.clone(), &member, vec![network], 10).await;
    assert!(
        welcome.rosters.is_empty(),
        "message 2 is written before HELLO exists: {:?}",
        welcome.rosters
    );
    client.send(Record::Attach).await;
    // This HELLO claimed no `roster_seq`, so the attach time catch up still pushes the
    // relay's Roster at once, as for IK.
    let held = client.recv_roster_doc().await;
    assert_eq!(held.decode().unwrap().seq, 1);

    // The node pushes its Roster for the claimed network: an equal `seq` is dropped...
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &held.encode()) {
        client.send(record).await;
    }
    ping_pong(&mut client, [3; 8]).await;
    assert_eq!(three.relay.rosters().seqs().get(&network), Some(&1));

    // ...and a newer one is adopted.
    let newer = evict_roster(&three.owners[0], network, 2, &[(member.node_id, 1)], &[]);
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &newer.encode()) {
        client.send(record).await;
    }
    ping_pong(&mut client, [4; 8]).await;
    assert_eq!(three.relay.rosters().seqs().get(&network), Some(&2));
}

#[tokio::test]
async fn a_rejected_ik_hello_sees_empty_rosters_then_the_error() {
    let member = generate_identity();
    let three = three_networks([&[member.node_id], &[], &[]]).await;

    // One claim passes, one does not: the whole HELLO is refused and nothing is listed.
    let (mut client, welcome) = three
        .connect_ik(&member, vec![three.networks[0], three.networks[1]], 10)
        .await;
    assert!(
        welcome.rosters.is_empty(),
        "a refused HELLO was told {:?}",
        welcome.rosters
    );
    // A node writes ATTACH and more right after WELCOME, before it reads anything: the relay
    // keeps the socket open for it, so those writes land and the ERROR is still read.
    for _ in 0..3 {
        client.send(Record::Attach).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR not_member, got {other:?}"),
    }
    assert_eq!(client.recv().await, None);

    // A claim of a network that is not served at all.
    let (mut client, welcome) = three
        .connect_ik(&member, vec![NetworkId::from([0x42; 32])], 20)
        .await;
    assert!(welcome.rosters.is_empty());
    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR not_member, got {other:?}"),
    }
    assert_eq!(client.recv().await, None);
}

// --- MT2: no oracle for which networks a relay serves (isolation rules I2 and I3) ---

/// The ERROR a relay answers to an IK HELLO of `who` claiming `network`, as encoded bytes, and
/// what WELCOME listed. `serving` seeds the relay with a Roster of `network` that lists only
/// `listed`.
async fn hello_refusal(
    who: &TestIdentity,
    network: NetworkId,
    serving: Option<(&SigningKey, NodeId)>,
) -> (Vec<u8>, usize) {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    if let Some((owner, listed)) = serving {
        relay
            .rosters()
            .set(&evict_roster(owner, network, 1, &[(listed, 1)], &[]))
            .unwrap();
    }
    tokio::spawn(async move { relay.serve(&listener).await });
    let (mut client, welcome) = TestClient::connect(
        addr,
        cert,
        who,
        relay_x25519,
        vec![network],
        HashMap::new(),
        1,
        10,
    )
    .await;
    let error = match client.recv().await {
        Some(record @ Record::Error(_)) => record.encode(),
        other => panic!("expected ERROR, got {other:?}"),
    };
    assert_eq!(client.recv().await, None);
    (error, welcome.rosters.len())
}

#[tokio::test]
async fn a_hello_for_an_unserved_network_is_refused_byte_for_byte_like_an_unlisted_one() {
    let who = generate_identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let network = NetworkId::from(owner.verifying_key().to_bytes());
    let other_member = NodeId::from([0x77; 32]);

    let (served_unlisted, served_rosters) =
        hello_refusal(&who, network, Some((&owner, other_member))).await;
    let (unserved, unserved_rosters) = hello_refusal(&who, network, None).await;

    assert_eq!(served_rosters, 0);
    assert_eq!(unserved_rosters, 0);
    assert_eq!(
        unserved, served_unlisted,
        "the refusal must not tell whether the relay serves the network"
    );
    // And it is the `not_member` answer, not some other code that happens to match.
    match Record::decode(&unserved).unwrap() {
        Record::Error(body) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR, got {other:?}"),
    }
}

/// What a session does not get back from DOC pushes: a Roster for an unserved network, for a
/// served network the session did not claim, and a forged one for a claimed network. The
/// relay answers none of them (the next record is the PONG for the PING sent after) and
/// stores none.
#[tokio::test]
async fn a_doc_for_an_unserved_unclaimed_or_forged_roster_gets_no_record_back() {
    let member = generate_identity();
    let three = three_networks([&[member.node_id], &[member.node_id], &[]]).await;
    let claimed = three.networks[0];

    let (mut client, welcome) = three.connect_ik(&member, vec![claimed], 10).await;
    assert_eq!(welcome.rosters, three.seeded(&[0]));
    client.send(Record::Attach).await;
    client.recv_roster_doc().await;
    ping_pong(&mut client, [1; 8]).await;

    // A valid Roster of a network this relay does not serve.
    let stranger_owner = SigningKey::generate(&mut rand::rng());
    let stranger_net = NetworkId::from(stranger_owner.verifying_key().to_bytes());
    let unserved = evict_roster(
        &stranger_owner,
        stranger_net,
        5,
        &[(member.node_id, 1)],
        &[],
    );
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &unserved.encode()) {
        client.send(record).await;
    }
    ping_pong(&mut client, [2; 8]).await;
    assert!(!three.relay.rosters().seqs().contains_key(&stranger_net));

    // A valid, newer Roster of a served network the session did not claim.
    let unclaimed = evict_roster(
        &three.owners[1],
        three.networks[1],
        9,
        &[(member.node_id, 1)],
        &[],
    );
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &unclaimed.encode()) {
        client.send(record).await;
    }
    ping_pong(&mut client, [3; 8]).await;
    assert_eq!(
        three.relay.rosters().seqs().get(&three.networks[1]),
        Some(&2)
    );

    // A newer Roster of the claimed network with a signature that is not the owner's.
    let impostor = SigningKey::generate(&mut rand::rng());
    let forged = evict_roster(&impostor, claimed, 9, &[(member.node_id, 1)], &[]);
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &forged.encode()) {
        client.send(record).await;
    }
    ping_pong(&mut client, [4; 8]).await;
    assert_eq!(three.relay.rosters().seqs().get(&claimed), Some(&1));

    // The same session still adopts a legitimate newer Roster of the claimed network.
    let genuine = evict_roster(&three.owners[0], claimed, 7, &[(member.node_id, 1)], &[]);
    for record in menzil_proto::split_into_doc_records(DocType::Roster, &genuine.encode()) {
        client.send(record).await;
    }
    ping_pong(&mut client, [5; 8]).await;
    assert_eq!(three.relay.rosters().seqs().get(&claimed), Some(&7));
}

/// First multi tenant round, L1: what a stranger reads as WELCOME `session` does not move with
/// the connections other people open in between (bare TCP connects count too).
#[tokio::test]
async fn welcome_session_numbers_do_not_count_other_connections() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { relay.serve(&listener).await });

    let mut seen: Vec<(u32, u32)> = Vec::new();
    let mut parked = Vec::new();
    for round in 0..50u32 {
        // 0 to 4 other connections before each stranger.
        let others = round % 5;
        for _ in 0..others {
            parked.push(tokio::net::TcpStream::connect(addr).await.unwrap());
        }
        let stranger = generate_identity();
        let (_client, welcome) = TestClient::connect(
            addr,
            cert.clone(),
            &stranger,
            relay_x25519,
            vec![],
            HashMap::new(),
            1,
            10,
        )
        .await;
        seen.push((welcome.session, others));
    }
    for pair in seen.windows(2) {
        let step = pair[1].0.wrapping_sub(pair[0].0);
        assert_ne!(
            step,
            pair[1].1 + 1,
            "the step between two strangers must not equal the connections between them: {seen:?}"
        );
    }
    assert!(
        seen.windows(2).any(|pair| pair[1].0 < pair[0].0),
        "the numbers must not rise with the connections: {seen:?}"
    );
    let distinct: std::collections::HashSet<_> = seen.iter().map(|(id, _)| id).collect();
    assert_eq!(distinct.len(), seen.len());
}

/// First multi tenant round, M1 and M2: a HELLO naming more distinct networks than
/// MAX_HELLO_NETWORKS is refused with the same ERROR whether or not the relay serves any of
/// them, and a HELLO repeating one network 1800 times (about the most message 1 can hold) gets the ordinary `not_member`.
#[tokio::test]
async fn a_hello_over_the_network_cap_is_refused_alike_for_served_and_unserved_networks() {
    let who = generate_identity();
    let owner = SigningKey::generate(&mut rand::rng());
    let served = NetworkId::from(owner.verifying_key().to_bytes());
    let other_member = NodeId::from([0x77; 32]);
    let over_cap = |first: NetworkId| -> Vec<NetworkId> {
        std::iter::once(first)
            .chain((1..=crate::hello::MAX_HELLO_NETWORKS as u8).map(|i| NetworkId::from([i; 32])))
            .collect()
    };

    let mut errors = Vec::new();
    for serving in [true, false] {
        let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
        let addr = listener.local_addr().unwrap();
        if serving {
            relay
                .rosters()
                .set(&evict_roster(&owner, served, 1, &[(other_member, 1)], &[]))
                .unwrap();
        }
        let rosters = relay.rosters().lookup_count();
        let relay_for_count = relay.clone();
        tokio::spawn(async move { relay.serve(&listener).await });
        let (mut client, welcome) = TestClient::connect(
            addr,
            cert,
            &who,
            relay_x25519,
            over_cap(served),
            HashMap::new(),
            1,
            10,
        )
        .await;
        assert!(welcome.rosters.is_empty());
        let error = match client.recv().await {
            Some(record @ Record::Error(_)) => record,
            other => panic!("expected ERROR, got {other:?}"),
        };
        assert_eq!(relay_for_count.rosters().lookup_count(), rosters);
        match &error {
            Record::Error(body) => assert_eq!(body.code, ErrorCode::TooLarge),
            _ => unreachable!(),
        }
        errors.push(error.encode());
    }
    assert_eq!(
        errors[0], errors[1],
        "the refusal must not tell what is served"
    );

    // The same repeat, 1800 times: the ordinary answer of a one network claim.
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { relay.serve(&listener).await });
    let (mut client, _welcome) = TestClient::connect(
        addr,
        cert,
        &who,
        relay_x25519,
        vec![served; 1800],
        HashMap::new(),
        1,
        10,
    )
    .await;
    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR, got {other:?}"),
    }
}

// --- MT4: session hygiene (threats A9 and A14) ------------------------------------------------

use crate::admission::AdmissionLimits;
use crate::session::{ATTACH_DEADLINE, NOISE_DEADLINE};

const LOOPBACK: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

/// [`bind_test_relay`] with `admission` as the relay's caps (the default test relay lifts the
/// per address ones).
async fn bind_test_relay_admitting(
    admission: AdmissionLimits,
) -> (Relay, Listener, CertificateDer<'static>, X25519PublicKey) {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    (
        relay.with_admission_limits(admission),
        listener,
        cert,
        relay_x25519,
    )
}

/// Waits (real time, up to 3 s) until `condition` holds.
async fn eventually(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..300 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("never became true: {what}");
}

/// Decision D6: a HELLO that claims no network is refused, for a listed member as for a
/// stranger, in IK as in XX, with the ordinary ERROR after the linger, and no session exists.
#[tokio::test]
async fn a_hello_that_claims_no_network_is_refused_ik_and_xx() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    let member = generate_identity();
    let (_networks, _seq) = seed_network(&relay, &[&member]);

    // IK, writing ATTACH right after WELCOME as a node does: the ERROR is still readable.
    let (mut client, welcome) = TestClient::connect(
        addr,
        cert.clone(),
        &member,
        relay_x25519,
        vec![],
        HashMap::new(),
        1,
        10,
    )
    .await;
    assert!(welcome.rosters.is_empty());
    client.send(Record::Attach).await;
    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR not_member, got {other:?}"),
    }
    assert_eq!(client.recv().await, None);

    // XX (first contact), the same.
    let (mut client, _welcome) = TestClient::connect_xx(addr, cert, &member, vec![], 20).await;
    client.send(Record::Attach).await;
    match client.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::NotMember),
        other => panic!("expected ERROR not_member, got {other:?}"),
    }
    assert_eq!(client.recv().await, None);
    assert_eq!(relay.registry.attached_session_id(&member.node_id), None);
}

/// A9: a session that passed HELLO and never sends ATTACH is closed 10 s after the handshake,
/// not before; PINGs in between do not move the deadline.
#[tokio::test]
async fn a_session_that_never_attaches_is_closed_after_10_seconds() {
    assert_eq!(ATTACH_DEADLINE, Duration::from_secs(10));
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    let member = generate_identity();
    let (networks, seq) = seed_network(&relay, &[&member]);

    let (mut client, _welcome) =
        TestClient::connect(addr, cert, &member, relay_x25519, networks, seq, 1, 10).await;
    // The relay is in its pre ATTACH loop once it has answered this (real time).
    ping_pong(&mut client, [1; 8]).await;
    assert_eq!(relay.admission.unattached_of_node(&member.node_id), 1);

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_eq!(
        relay.admission.unattached_of_node(&member.node_id),
        1,
        "closed before the deadline"
    );
    assert_eq!(relay.admission.unattached_of_peer(LOOPBACK), 1);

    tokio::time::advance(Duration::from_millis(1_500)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        relay.admission.unattached_of_node(&member.node_id),
        0,
        "still open past the deadline"
    );
    assert_eq!(relay.admission.unattached_of_peer(LOOPBACK), 0);
    let closed = tokio::time::timeout(Duration::from_secs(30), client.recv()).await;
    assert_eq!(closed.expect("the connection was never closed"), None);
    assert_eq!(relay.registry.attached_session_id(&member.node_id), None);
}

/// A9: a connection that finishes the WebSocket upgrade and then never completes the Noise
/// handshake is dropped after the Noise deadline (the TLS and upgrade steps have their own).
#[tokio::test]
async fn a_noise_handshake_that_never_completes_is_dropped_after_10_seconds() {
    assert_eq!(NOISE_DEADLINE, Duration::from_secs(10));
    let (relay, listener, cert, _relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let mut ws = test_client(addr, cert, "/_menzil/v1").await;
    // The upgrade is done; give the relay's task a moment (real time) to enter its Noise phase.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(relay.admission.unattached_of_peer(LOOPBACK), 1);

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_eq!(
        relay.admission.unattached_of_peer(LOOPBACK),
        1,
        "dropped before the deadline"
    );
    tokio::time::advance(Duration::from_millis(1_500)).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        relay.admission.unattached_of_peer(LOOPBACK),
        0,
        "a silent peer still holds its slot past the deadline"
    );
    let ended = tokio::time::timeout(Duration::from_secs(30), ws.next())
        .await
        .expect("the connection was never closed");
    assert!(
        !matches!(ended, Some(Ok(Message::Binary(_)))),
        "the relay sent something to a silent peer: {ended:?}"
    );
}

/// A9: a NodeId may have two handshaken sessions waiting to ATTACH; the third is refused with
/// `rate_limited` before its WELCOME lists anything, leaves no replay mark (the same HELLO is
/// accepted once a slot is free), and an ATTACH gives its slot back.
#[tokio::test]
async fn a_third_unattached_session_of_a_node_is_refused() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    let member = generate_identity();
    let (networks, seq) = seed_network(&relay, &[&member]);
    let connect = |timestamp: u8| {
        TestClient::connect(
            addr,
            cert.clone(),
            &member,
            relay_x25519,
            networks.clone(),
            seq.clone(),
            1,
            timestamp,
        )
    };

    let (first, w1) = connect(10).await;
    let (_second, w2) = connect(11).await;
    assert!(!w1.rosters.is_empty() && !w2.rosters.is_empty());
    assert_eq!(relay.admission.unattached_of_node(&member.node_id), 2);

    let (mut third, w3) = connect(12).await;
    assert!(w3.rosters.is_empty(), "a refused HELLO is told nothing");
    match third.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::RateLimited),
        other => panic!("expected ERROR rate_limited, got {other:?}"),
    }
    assert_eq!(third.recv().await, None);
    assert_eq!(relay.admission.unattached_of_node(&member.node_id), 2);

    // One of the two goes away; the refused HELLO (same timestamp 12) now passes.
    drop(first);
    eventually("the dropped session gives its slot back", || {
        relay.admission.unattached_of_node(&member.node_id) == 1
    })
    .await;
    let (mut fourth, w4) = connect(12).await;
    assert!(!w4.rosters.is_empty());
    fourth.send(Record::Attach).await;
    ping_pong(&mut fourth, [4; 8]).await;
    assert_eq!(
        relay.admission.unattached_of_node(&member.node_id),
        1,
        "the attached session no longer counts as waiting to attach"
    );
    assert_eq!(relay.admission.attached(), 1);
}

/// A14: one peer address may hold only so many unattached sessions; a connection over it is
/// closed at once, and the slot comes back when one of its connections ends.
#[tokio::test]
async fn a_peer_address_over_its_unattached_share_is_dropped_at_once() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay_admitting(AdmissionLimits {
        max_unattached_per_ip: 3,
        connections_per_ip_per_minute: 1_000,
        ..AdmissionLimits::default()
    })
    .await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    // Three peers that connect and say nothing hold the three slots.
    let idle: Vec<TcpStream> = futures_util::future::join_all(
        (0..3).map(|_| async { TcpStream::connect(addr).await.unwrap() }),
    )
    .await;
    eventually("three slots taken", || {
        relay.admission.unattached_of_peer(LOOPBACK) == 3
    })
    .await;

    let mut fourth = TcpStream::connect(addr).await.unwrap();
    assert!(
        closed_by_relay(&mut fourth, Duration::from_millis(1500)).await,
        "a connection over the per address share was not dropped at once"
    );
    // Another handshake in flight does not make the relay forget the share.
    assert_eq!(relay.admission.unattached_of_peer(LOOPBACK), 3);

    // One idle peer leaves: its slot is free, a real client is served.
    let mut idle = idle;
    drop(idle.pop());
    eventually("a slot freed", || {
        relay.admission.unattached_of_peer(LOOPBACK) == 2
    })
    .await;
    let _served = assert_served(&relay, addr, &cert, relay_x25519).await;
}

/// A14: the 61st connection within a minute from one address gets HTTP 429 at the WebSocket
/// upgrade (the first 60 upgrade); the window itself is exercised under paused time in
/// `admission.rs`.
#[tokio::test]
async fn the_61st_connection_in_a_minute_gets_429_at_the_upgrade() {
    let (relay, listener, cert, _relay_x25519) = bind_test_relay_admitting(AdmissionLimits {
        max_unattached_per_ip: 10_000,
        ..AdmissionLimits::default()
    })
    .await;
    assert_eq!(AdmissionLimits::default().connections_per_ip_per_minute, 60);
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });

    let mut held = Vec::new();
    for n in 1..=60 {
        match crate::tests_support::try_test_client(addr, cert.clone(), "/_menzil/v1").await {
            Ok(ws) => held.push(ws),
            Err(err) => panic!("connection {n} should upgrade: {err:?}"),
        }
    }
    for n in [61, 62] {
        match crate::tests_support::try_test_client(addr, cert.clone(), "/_menzil/v1").await {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status().as_u16(), 429, "connection {n}");
            }
            other => panic!("connection {n} should get 429, got {:?}", other.map(|_| ())),
        }
    }
}

/// Attached sessions are capped in all: an ATTACH over the cap is refused with `rate_limited`
/// and does not disturb the attached one; a NodeId that is attached already may replace its
/// own session at the cap.
#[tokio::test]
async fn an_attach_over_the_attached_cap_is_refused_but_a_replacement_is_not() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay_admitting(AdmissionLimits {
        max_attached: 1,
        max_unattached_per_ip: 10_000,
        connections_per_ip_per_minute: 10_000,
        ..AdmissionLimits::default()
    })
    .await;
    let addr = listener.local_addr().unwrap();
    let serve_relay = relay.clone();
    tokio::spawn(async move { serve_relay.serve(&listener).await });
    let (a, b) = (generate_identity(), generate_identity());
    let (networks, seq) = seed_network(&relay, &[&a, &b]);

    let (mut client_a, _) = TestClient::connect(
        addr,
        cert.clone(),
        &a,
        relay_x25519,
        networks.clone(),
        seq.clone(),
        1,
        10,
    )
    .await;
    client_a.send(Record::Attach).await;
    ping_pong(&mut client_a, [1; 8]).await;
    assert_eq!(relay.admission.attached(), 1);
    assert_eq!(
        relay.admission.unattached_of_peer(LOOPBACK),
        0,
        "an attached session no longer holds a per address slot"
    );

    let (mut client_b, _) = TestClient::connect(
        addr,
        cert.clone(),
        &b,
        relay_x25519,
        networks.clone(),
        seq.clone(),
        1,
        10,
    )
    .await;
    client_b.send(Record::Attach).await;
    match client_b.recv().await {
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::RateLimited),
        other => panic!("expected ERROR rate_limited, got {other:?}"),
    }
    assert_eq!(client_b.recv().await, None);
    assert_eq!(relay.registry.attached_session_id(&b.node_id), None);
    ping_pong(&mut client_a, [2; 8]).await;

    // A re-attaches from a second connection at the cap: let in, the first is superseded.
    let (mut client_a2, _) =
        TestClient::connect(addr, cert, &a, relay_x25519, networks, seq, 1, 20).await;
    client_a2.send(Record::Attach).await;
    ping_pong(&mut client_a2, [3; 8]).await;
    match client_a.recv().await {
        Some(Record::Goaway(body)) => assert_eq!(body.reason, "superseded"),
        other => panic!("expected GOAWAY superseded, got {other:?}"),
    }
}
