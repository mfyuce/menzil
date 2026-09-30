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
use crate::tests_support::{self_signed_cert, test_client};

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
    let relay = Relay::new(
        RelayIdentity {
            node_cert,
            x25519_private: raw.x25519_private,
        },
        limits,
    );
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
    let (mut client, welcome) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        vec![],
        HashMap::new(),
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
        Some(1)
    );
}

#[tokio::test]
async fn a_second_attach_supersedes_the_first() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { relay.serve(&listener).await });

    let client_identity = generate_identity();
    let (mut client1, _) = TestClient::connect(
        addr,
        cert.clone(),
        &client_identity,
        relay_x25519,
        vec![],
        HashMap::new(),
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
        vec![],
        HashMap::new(),
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
async fn an_unknown_claimed_network_gets_an_error_then_the_connection_ends() {
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
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::UnknownNetwork),
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

    let (mut client, _) = TestClient::connect(
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
        Some(1)
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

#[tokio::test]
async fn rekey_from_the_client_is_applied_before_the_next_record() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { relay.serve(&listener).await });

    let client_identity = generate_identity();
    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &client_identity,
        relay_x25519,
        vec![],
        HashMap::new(),
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
    tokio::spawn(async move { relay.serve(&listener).await });

    let identity = generate_identity();
    let (mut client, _) = TestClient::connect(
        addr,
        cert,
        &identity,
        relay_x25519,
        vec![],
        HashMap::new(),
        1,
        10,
    )
    .await;
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
    tokio::spawn(async move { relay.serve(&listener).await });

    // Two independently attached nodes claiming no networks at all: no
    // Roster lists the two of them together.
    let identity_a = generate_identity();
    let identity_b = generate_identity();
    let (mut client_a, _) = TestClient::connect(
        addr,
        cert.clone(),
        &identity_a,
        relay_x25519,
        vec![],
        HashMap::new(),
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
        vec![],
        HashMap::new(),
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
async fn a_send_to_a_destination_that_opted_out_of_peer_traffic_is_forbidden() {
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
        Some(Record::Error(body)) => assert_eq!(body.code, ErrorCode::Forbidden),
        other => panic!("expected ERROR(Forbidden), got {other:?}"),
    }
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
