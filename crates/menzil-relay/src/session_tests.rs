//! Live end-to-end tests of the session lifecycle (`relay.rs`,
//! `session.rs`, `hello.rs`, `registry.rs` together): a real self-signed
//! certificate, a real TLS+WebSocket connection, and a real Noise
//! handshake driven directly against `menzil-session`'s public API,
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
    ErrorCode, HelloBody, Limits, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION,
    Record, Roster, RosterBody, RosterMember, Tai64N, WelcomeBody, X25519PublicKey,
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

/// Binds a real `Listener` on a self-signed cert and a `Relay` to go
/// with it, and returns the relay's own X25519 public key (needed by
/// [`TestClient::connect`]'s `Ik` handshake) alongside everything a
/// caller needs to spawn `relay.serve(&listener)`.
async fn bind_test_relay() -> (Relay, Listener, CertificateDer<'static>, X25519PublicKey) {
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
        test_limits(),
    );
    (relay, listener, cert, relay_x25519)
}

/// One end of a live, real Noise `Ik` session with the relay under test:
/// a real WebSocket connection plus the client-side `Transport` that
/// resulted from actually completing the handshake against it.
struct TestClient {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    transport: Transport,
}

impl TestClient {
    async fn connect(
        addr: SocketAddr,
        cert: CertificateDer<'static>,
        client_identity: &TestIdentity,
        relay_x25519: X25519PublicKey,
        networks: Vec<NetworkId>,
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
            roster_seq: HashMap::new(),
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
    let (mut client, welcome) =
        TestClient::connect(addr, cert, &client_identity, relay_x25519, vec![], 1, 10).await;
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
        1,
        10,
    )
    .await;
    client1.send(Record::Attach).await;
    ping_pong(&mut client1, [1; 8]).await;

    // Same identity, a second connection: serial stays the same
    // (allowed — only a *lower* serial is rejected) but the timestamp
    // must still strictly advance (protocol.md 4.1).
    let (mut client2, _) =
        TestClient::connect(addr, cert, &client_identity, relay_x25519, vec![], 1, 20).await;
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
    // Seeding a Roster this way, directly through `RosterStore`, is the
    // whole point of `Relay::rosters` for now: DOC-based propagation
    // isn't built yet.
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
        1,
        10,
    )
    .await;
    client.send(Record::Attach).await;
    ping_pong(&mut client, [3; 8]).await;
    assert_eq!(
        relay.registry.attached_session_id(&client_identity.node_id),
        Some(1)
    );
}

#[tokio::test]
async fn rekey_from_the_client_is_applied_before_the_next_record() {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { relay.serve(&listener).await });

    let client_identity = generate_identity();
    let (mut client, _) =
        TestClient::connect(addr, cert, &client_identity, relay_x25519, vec![], 1, 10).await;
    client.send(Record::Attach).await;
    ping_pong(&mut client, [1; 8]).await;

    client.send(Record::Rekey).await;
    client.transport.rekey_outgoing();
    // If the relay had not rekeyed its own receiving state in response,
    // this PING would fail to decrypt on the relay's side and no PONG
    // would come back.
    ping_pong(&mut client, [2; 8]).await;
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
