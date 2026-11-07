//! Tests of the ACME module: the challenge book and certificate, the validation answer over a
//! real TLS handshake, the stream handler in front of a real local target, the RFC 8555 client
//! against an in process CA that checks every JWS, the HTTP transport against a local TLS
//! server, and the store and renewal rules.

use std::sync::Arc;
use std::time::Duration;

use futures_util::io::AsyncReadExt as _;
use futures_util::io::AsyncWriteExt as _;
use menzil_proto::{AdvertiseAckBody, NetworkId, NodeId, OpenMeta, Share, ShareMode};
use menzil_stream::{Mode, OpenRequest, OutboundFrames, ServiceHandler, Stream, StreamMux};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

use super::*;
use crate::serve::{LocalServices, LocalTarget};
use crate::shares::{ShareBook, lists_acme_alpn};
use menzil_acme::{is_validation_of, peek_client_hello};

#[cfg(feature = "aws-lc-rs")]
fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

const PEEK_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT: Duration = Duration::from_secs(10);
const DOMAIN: &str = "app.relay.example";

fn sha256(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

// ---- the client side of a validation: what a CA sees ----

#[derive(Debug)]
struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(alpn: &[&str]) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Arc::new(config)
}

/// The `id-pe-acmeIdentifier` extension of `der`: whether it is critical and its value.
fn acme_identifier(der: &[u8]) -> Option<(bool, Vec<u8>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    cert.extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .map(|ext| (ext.critical, ext.value.to_vec()))
}

/// The bytes a client sends first (its ClientHello) for `sni` and `alpn`.
async fn capture_hello(sni: &str, alpn: &[&str]) -> (Vec<u8>, ()) {
    let (mut server_io, client_io) = tokio::io::duplex(64 * 1024);
    let connector = TlsConnector::from(client_config(alpn));
    let name = ServerName::try_from(sni.to_string()).unwrap();
    let client = tokio::spawn(async move {
        let _ = connector.connect(name, client_io).await;
    });
    let mut buf = vec![0u8; 8192];
    let n = server_io.read(&mut buf).await.unwrap();
    buf.truncate(n);
    drop(server_io);
    let _ = client.await;
    (buf, ())
}

// ---- the handler in front of a real local target ----

async fn pump(mut from: OutboundFrames, to: StreamMux) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

/// A connected pair of streams, (the client's, the server's), over in memory pumps that live as
/// long as the runtime. The opening byte is consumed.
async fn stream_pair() -> (Stream, Stream) {
    let (client, client_inbound, client_out, client_driver) =
        menzil_stream::new(Mode::Client, 65_535);
    let (server, mut server_inbound, server_out, server_driver) =
        menzil_stream::new(Mode::Server, 65_535);
    tokio::spawn(client_driver);
    tokio::spawn(server_driver);
    tokio::spawn(pump(client_out, server.clone()));
    tokio::spawn(pump(server_out, client.clone()));
    let mut opened = client.open().await.unwrap();
    opened.write_all(b"x").await.unwrap();
    let mut remote = tokio::time::timeout(WAIT, server_inbound.accept())
        .await
        .unwrap()
        .unwrap();
    let mut first = [0u8; 1];
    remote.read_exact(&mut first).await.unwrap();
    tokio::spawn(async move {
        let _keep = (client, client_inbound, server, server_inbound);
        std::future::pending::<()>().await;
    });
    (opened, remote)
}

struct Fixture {
    target: TcpListener,
    handler: AcmeHandler,
    book: ChallengeBook,
}

impl Fixture {
    async fn new() -> Self {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let services = LocalServices::new()
            .serve(
                "tls:app".parse().unwrap(),
                LocalTarget::new("127.0.0.1", port),
            )
            .unwrap()
            .serve(
                "http:app".parse().unwrap(),
                LocalTarget::new("127.0.0.1", port),
            )
            .unwrap();
        let book = ChallengeBook::new();
        Self {
            target,
            handler: AcmeHandler::new(services, book.clone()),
            book,
        }
    }

    /// Opens `service` with `sni` in the meta the way the relay principal does, serves it with
    /// the handler and returns the client end and the target's accepted connection.
    async fn open(&self, service: &str, sni: Option<&str>) -> (Stream, tokio::net::TcpStream) {
        let request = OpenRequest {
            network_id: NetworkId::from([1u8; 32]),
            initiator: NodeId::from([2u8; 32]),
            service: service.parse().unwrap(),
            target: None,
            meta: OpenMeta {
                client_ip: Some("192.0.2.1".to_string()),
                sni: sni.map(str::to_string),
            },
        };
        let opened = self.handler.open_with_own_limits(&request).await.unwrap();
        let (client, server) = stream_pair().await;
        tokio::spawn(self.handler.handle(server, request, opened));
        let (socket, _) = tokio::time::timeout(WAIT, self.target.accept())
            .await
            .unwrap()
            .unwrap();
        (client, socket)
    }
}

/// Reads from the target until `want` bytes arrived (or an end).
async fn read_target(socket: &mut tokio::net::TcpStream, want: usize) -> Vec<u8> {
    let mut got = Vec::new();
    let mut chunk = [0u8; 4096];
    while got.len() < want {
        match tokio::time::timeout(WAIT, socket.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => got.extend_from_slice(&chunk[..n]),
        }
    }
    got
}

/// Starts a TLS client over `stream` (a validation or an ordinary connection), whose handshake
/// the caller does not wait for.
fn start_client(stream: Stream, sni: &str, alpn: &[&str]) -> tokio::task::JoinHandle<bool> {
    let connector = TlsConnector::from(client_config(alpn));
    let name = ServerName::try_from(sni.to_string()).unwrap();
    tokio::spawn(async move {
        connector
            .connect(name, crate::serve::TokioStream(stream))
            .await
            .is_ok()
    })
}

#[tokio::test]
async fn a_stream_without_a_pending_order_is_piped_untouched_and_unread() {
    let fixture = Fixture::new().await;
    let (mut client, mut target) = fixture.open("tls:app", Some(DOMAIN)).await;
    client
        .write_all(b"\x16\x03\x01 not looked at")
        .await
        .unwrap();
    // At once: a stream that was being peeked at would hold these bytes back until its hello
    // was whole or the peek timed out.
    let mut got = [0u8; 17];
    tokio::time::timeout(Duration::from_secs(2), target.read_exact(&mut got))
        .await
        .expect("the bytes reached the target without delay")
        .unwrap();
    assert_eq!(&got, b"\x16\x03\x01 not looked at");
    target.write_all(b"back").await.unwrap();
    let mut answer = [0u8; 4];
    tokio::time::timeout(WAIT, client.read_exact(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&answer, b"back");
}

#[tokio::test]
async fn through_the_handler_a_validation_is_answered_and_never_reaches_the_target() {
    let fixture = Fixture::new().await;
    let _order = fixture.book.begin(DOMAIN, "tok.thumb").unwrap();
    let (client, mut target) = fixture.open("tls:app", Some(DOMAIN)).await;
    let connector = TlsConnector::from(client_config(&["acme-tls/1"]));
    let name = ServerName::try_from(DOMAIN.to_string()).unwrap();
    let tls = tokio::time::timeout(
        WAIT,
        connector.connect(name, crate::serve::TokioStream(client)),
    )
    .await
    .unwrap()
    .expect("the handshake completes");
    let leaf = tls.get_ref().1.peer_certificates().unwrap()[0]
        .as_ref()
        .to_vec();
    assert_eq!(
        &acme_identifier(&leaf).unwrap().1[2..],
        sha256(b"tok.thumb").as_slice()
    );
    // The target never saw a byte of it: its connection was dropped unused.
    let seen = read_target(&mut target, 1).await;
    assert!(seen.is_empty(), "the target got {} bytes", seen.len());
}

#[tokio::test]
async fn an_ordinary_hello_in_the_window_reaches_the_target_whole() {
    let fixture = Fixture::new().await;
    let _order = fixture.book.begin(DOMAIN, "tok.thumb").unwrap();
    let (client, mut target) = fixture.open("tls:app", Some(DOMAIN)).await;
    let (hello, ()) = capture_hello(DOMAIN, &["h2"]).await;
    let client_task = start_client(client, DOMAIN, &["h2"]);
    let got = read_target(&mut target, hello.len()).await;
    let mut parsed = got.as_slice();
    let peeked = peek_client_hello(&mut parsed).await.unwrap();
    let hello_seen = peeked
        .hello
        .expect("a whole ClientHello reached the target");
    let view = hello_seen.client_hello();
    assert_eq!(view.server_name(), Some(DOMAIN));
    assert_eq!(
        view.alpn().unwrap().collect::<Vec<_>>(),
        vec![b"h2".as_slice()]
    );
    assert!(!is_validation_of(&hello_seen, DOMAIN));
    client_task.abort();
}

#[tokio::test]
async fn a_validation_for_another_name_or_a_lapsed_order_reaches_the_target() {
    let fixture = Fixture::new().await;
    // The stream's name has an order, but the hello is for something else.
    let _order = fixture.book.begin(DOMAIN, "tok.thumb").unwrap();
    let (client, mut target) = fixture.open("tls:app", Some(DOMAIN)).await;
    let client_task = start_client(client, "elsewhere.relay.example", &["acme-tls/1"]);
    let got = read_target(&mut target, 100).await;
    assert_eq!(got.first(), Some(&0x16), "the hello was passed on");
    client_task.abort();
    // An order that was dropped: not pending, the stream is not read at all.
    let book = fixture.book.clone();
    drop(_order);
    assert!(!book.is_pending(DOMAIN));
    let (client, mut target) = fixture.open("tls:app", Some(DOMAIN)).await;
    let client_task = start_client(client, DOMAIN, &["acme-tls/1"]);
    let got = read_target(&mut target, 100).await;
    assert_eq!(got.first(), Some(&0x16));
    client_task.abort();
}

#[tokio::test]
async fn non_tls_bytes_in_the_window_reach_the_target_and_so_does_what_follows() {
    let fixture = Fixture::new().await;
    let _order = fixture.book.begin(DOMAIN, "tok.thumb").unwrap();
    let (mut client, mut target) = fixture.open("tls:app", Some(DOMAIN)).await;
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    assert_eq!(
        read_target(&mut target, 18).await,
        b"GET / HTTP/1.1\r\n\r\n"
    );
    client.write_all(b"and later bytes").await.unwrap();
    assert_eq!(read_target(&mut target, 15).await, b"and later bytes");
}

#[tokio::test]
async fn only_the_relay_principals_sni_and_only_tls_and_tcp_services_are_looked_at() {
    let fixture = Fixture::new().await;
    let _order = fixture.book.begin(DOMAIN, "tok.thumb").unwrap();
    // A member's stream has no sni (the node scrubs it): the pending name does not matter.
    let (mut client, mut target) = fixture.open("tls:app", None).await;
    let (hello, ()) = capture_hello(DOMAIN, &["acme-tls/1"]).await;
    client.write_all(&hello).await.unwrap();
    assert_eq!(read_target(&mut target, hello.len()).await, hello);
    // An http: service is not a blind share.
    let (client, mut target) = fixture.open("http:app", Some(DOMAIN)).await;
    let client_task = start_client(client, DOMAIN, &["acme-tls/1"]);
    let got = read_target(&mut target, 100).await;
    assert_eq!(got.first(), Some(&0x16));
    client_task.abort();
}

#[tokio::test(start_paused = true)]
async fn a_stream_that_never_sends_a_hello_is_reset_after_the_peek_timeout() {
    let fixture = Fixture::new().await;
    let _order = fixture.book.begin(DOMAIN, "tok.thumb").unwrap();
    let (mut client, _target) = fixture.open("tls:app", Some(DOMAIN)).await;
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(PEEK_TIMEOUT * 3, client.read(&mut byte))
        .await
        .expect("the handler gave up inside the timeout");
    assert!(read.is_err() || read.unwrap() == 0, "closed, not served");
}

// ---- which shares are wanted ----

fn share(name: &str, mode: ShareMode, service: &str, alpn: &[&str]) -> Share {
    Share {
        name: name.to_string(),
        mode,
        service: service.parse().unwrap(),
        alpn: alpn.iter().map(|a| a.to_string()).collect(),
    }
}

fn ack(accepted: &[&str]) -> AdvertiseAckBody {
    AdvertiseAckBody {
        accepted: accepted.iter().map(|s| s.to_string()).collect(),
        rejected: Vec::new(),
        names: Vec::new(),
        share_domain: None,
    }
}

#[test]
fn a_share_is_wanted_only_when_accepted_blind_and_listing_acme_tls_1() {
    let with = share("app", ShareMode::Blind, "tls:app", &["h2", "acme-tls/1"]);
    let without = share("plain", ShareMode::Blind, "tls:plain", &["h2"]);
    let any_alpn = share("any", ShareMode::Blind, "tls:any", &[]);
    assert!(lists_acme_alpn(&with));
    assert!(!lists_acme_alpn(&without));
    assert!(
        !lists_acme_alpn(&any_alpn),
        "an empty list is not a request for it"
    );
    assert!(!lists_acme_alpn(&share(
        "t",
        ShareMode::Terminated,
        "http:t",
        &["acme-tls/1"]
    )));

    let book = ShareBook::new();
    let all = [with.clone(), without.clone(), any_alpn.clone()];
    assert!(!wanted(&book, "app"), "nothing sent");
    book.note_sent(&all);
    assert!(!wanted(&book, "app"), "sent, not answered yet");
    book.note_ack(&ack(&["app", "plain", "any"]));
    assert!(wanted(&book, "app"));
    assert!(!wanted(&book, "plain"));
    assert!(!wanted(&book, "any"));
    assert!(!wanted(&book, "unknown"));
    book.note_detached();
    assert!(
        !wanted(&book, "app"),
        "the claims ended with the attachment"
    );
    book.note_sent(&all);
    book.note_ack(&ack(&["plain"]));
    assert!(!wanted(&book, "app"), "rejected by the relay");
}

// ---- the renewal wrapper ----

#[tokio::test(start_paused = true)]
async fn the_renewal_loop_orders_only_while_the_share_is_wanted_and_stores_the_result() {
    use menzil_acme::testing::{FakeCa, Flags, client_for};

    let scratch = std::env::temp_dir().join(format!(
        "menzil-node-acme-test-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    std::fs::create_dir_all(&scratch).unwrap();
    let store = CertStore::new(&scratch);
    let book = ChallengeBook::new();
    let shares = ShareBook::new();
    let job = AcmeJob {
        share: "app".to_string(),
        domain: DOMAIN.to_string(),
    };
    let ca = FakeCa::new(&book, Flags::default());
    let task = tokio::spawn(run_renewals(
        client_for(&ca),
        store.clone(),
        shares.clone(),
        book.clone(),
        job,
    ));
    // Not accepted: minutes pass and the CA is not asked anything.
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert!(ca.state().log.is_empty());
    assert!(store.validity(DOMAIN).is_none());
    // Accepted and listing acme-tls/1: an order is made and kept.
    let share = share("app", ShareMode::Blind, "tls:app", &["acme-tls/1"]);
    shares.note_sent(std::slice::from_ref(&share));
    shares.note_ack(&ack(&["app"]));
    for _ in 0..200 {
        if store.validity(DOMAIN).is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert!(
        store.validity(DOMAIN).is_some(),
        "the certificate was stored"
    );
    task.abort();
    let _ = std::fs::remove_dir_all(&scratch);
}
