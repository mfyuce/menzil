//! Tests of the ACME module: the challenge book and certificate, the validation answer over a
//! real TLS handshake, the stream handler in front of a real local target, the RFC 8555 client
//! against an in process CA that checks every JWS, the HTTP transport against a local TLS
//! server, and the store and renewal rules.

use std::sync::Arc;
use std::time::Duration;

use ring_crate::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;

use super::client::der_to_raw_p256;
use super::http::{MAX_HEAD_BYTES, MAX_RESPONSE_BYTES, parse_response};
use super::renew::{check_issued, write_private};
use super::*;

use crate::testing::*;

/// A scratch directory that goes away with the value.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "menzil-acme-test-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---- names, the book, the certificate ----

#[test]
fn only_plain_lowercase_ldh_names_may_be_ordered() {
    for ok in [
        "a",
        "app.relay.example",
        "a-b.c1.d",
        "xn--bcher-kva.example",
    ] {
        assert!(check_domain(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "*.example",
        "App.example",
        "a..b",
        ".a",
        "a.",
        "-a.example",
        "a-.example",
        "a b",
        "../x",
        "a/b",
        "a_b.example",
        &"a".repeat(64),
        &format!("{}.example", "a".repeat(250)),
    ] {
        assert!(
            matches!(check_domain(bad), Err(AcmeError::BadDomain(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn the_challenge_certificate_names_the_domain_and_carries_the_digest_as_a_critical_extension() {
    let digest = key_authorization_digest("token.thumbprint");
    assert_eq!(digest.to_vec(), sha256(b"token.thumbprint"));
    let (cert, _key) = challenge_certificate(DOMAIN, &digest).unwrap();
    assert_eq!(dns_names(cert.as_ref()), vec![DOMAIN.to_string()]);
    let (critical, value) = acme_identifier(cert.as_ref()).expect("the extension");
    assert!(critical, "RFC 8737 requires the extension to be critical");
    // An OCTET STRING of 32 bytes.
    assert_eq!(&value[..2], &[0x04, 0x20]);
    assert_eq!(&value[2..], &digest);
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).unwrap();
    assert!(
        parsed.subject().iter().next().is_none(),
        "no subject: the name is in the SAN only"
    );
}

#[tokio::test]
async fn a_name_is_pending_between_begin_and_the_drop_of_its_order() {
    let book = ChallengeBook::new();
    assert!(book.is_empty() && !book.is_pending(DOMAIN));
    let order = book.begin(DOMAIN, "k.a").unwrap();
    assert!(book.is_pending(DOMAIN));
    assert!(!book.is_pending("other.relay.example"), "exact names only");
    assert!(
        !book.is_pending("APP.relay.example"),
        "lookups are lowercase"
    );
    assert_eq!(book.len(), 1);
    drop(order);
    assert!(!book.is_pending(DOMAIN));
    assert!(book.is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_order_is_pending_for_five_minutes_and_no_longer() {
    let book = ChallengeBook::new();
    let _order = book.begin(DOMAIN, "k.a").unwrap();
    assert_eq!(PENDING_TTL, Duration::from_secs(300));
    tokio::time::advance(PENDING_TTL - Duration::from_secs(1)).await;
    assert!(book.is_pending(DOMAIN));
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(!book.is_pending(DOMAIN), "expired");
    assert!(book.is_empty());
    assert!(book.config_for(DOMAIN).is_none());
}

#[tokio::test]
async fn at_most_sixteen_orders_wait_and_a_bad_name_is_refused() {
    let book = ChallengeBook::new();
    let orders: Vec<_> = (0..MAX_PENDING)
        .map(|i| book.begin(&format!("n{i}.example"), "k.a").unwrap())
        .collect();
    assert!(matches!(
        book.begin("one-more.example", "k.a"),
        Err(AcmeError::TooManyPending)
    ));
    // The same name again replaces its order, it does not need a place.
    let _again = book.begin("n0.example", "k2.a").unwrap();
    assert_eq!(book.len(), MAX_PENDING);
    drop(orders);
    assert!(matches!(
        book.begin("*.example", "k.a"),
        Err(AcmeError::BadDomain(_))
    ));
    assert!(matches!(
        book.begin("Upper.example", "k.a"),
        Err(AcmeError::BadDomain(_))
    ));
}

#[tokio::test]
async fn an_older_order_that_ends_does_not_remove_the_newer_one_for_the_same_name() {
    let book = ChallengeBook::new();
    let first = book.begin(DOMAIN, "k1.a").unwrap();
    let second = book.begin(DOMAIN, "k2.a").unwrap();
    drop(first);
    assert!(book.is_pending(DOMAIN), "the second order still waits");
    drop(second);
    assert!(!book.is_pending(DOMAIN));
}

// ---- the validation answer over a real TLS handshake ----

#[tokio::test]
async fn a_validation_connection_gets_the_challenge_certificate_with_the_digest_of_its_order() {
    let book = ChallengeBook::new();
    let key_authorization = "tok123.thumb456";
    let _order = book.begin(DOMAIN, key_authorization).unwrap();
    let (served, seen) = validate(&book, DOMAIN, &["acme-tls/1"]).await;
    assert_eq!(served, Served::Answered);
    let seen = seen.expect("the handshake completes");
    assert_eq!(seen.alpn.as_deref(), Some(b"acme-tls/1".as_slice()));
    assert_eq!(dns_names(&seen.leaf), vec![DOMAIN.to_string()]);
    let (critical, value) = acme_identifier(&seen.leaf).unwrap();
    assert!(critical);
    assert_eq!(&value[2..], sha256(key_authorization.as_bytes()).as_slice());
}

#[tokio::test]
async fn without_a_pending_order_a_validation_connection_is_not_answered() {
    let book = ChallengeBook::new();
    let (served, seen) = validate(&book, DOMAIN, &["acme-tls/1"]).await;
    // (The handler does not even read such a stream; a name whose order ended while the hello
    // arrived is closed, never answered.)
    assert_eq!(served, Served::Failed);
    assert!(seen.is_none(), "no certificate was presented");
}

#[tokio::test]
async fn the_alpn_must_be_exactly_acme_tls_1() {
    let book = ChallengeBook::new();
    let _order = book.begin(DOMAIN, "k.a").unwrap();
    for alpn in [
        vec!["h2"],
        vec!["http/1.1"],
        vec!["acme-tls/1", "h2"],
        vec!["h2", "acme-tls/1"],
        vec![],
    ] {
        let (served, seen) = validate(&book, DOMAIN, &alpn).await;
        assert!(matches!(served, Served::PassOn(_)), "{alpn:?}: {served:?}");
        assert!(seen.is_none(), "{alpn:?}: no certificate");
    }
}

#[tokio::test]
async fn a_validation_for_a_name_without_an_order_is_not_answered_by_another_names_order() {
    let book = ChallengeBook::new();
    let _order = book.begin("other.relay.example", "k.a").unwrap();
    // The handler is asked for the stream's own SNI; its order is the only one that counts.
    let (served, seen) = validate(&book, DOMAIN, &["acme-tls/1"]).await;
    assert_eq!(
        served,
        Served::Failed,
        "no order for this name: never answered"
    );
    assert!(seen.is_none());
    // And a hello whose SNI differs from the stream's name is not a validation of it.
    let (mut server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = {
        let book = book.clone();
        tokio::spawn(
            async move { answer_or_pass(&mut server_io, "other.relay.example", &book).await },
        )
    };
    let connector = TlsConnector::from(client_config(&["acme-tls/1"]));
    let name = ServerName::try_from(DOMAIN.to_string()).unwrap();
    let attempt = tokio::time::timeout(WAIT, connector.connect(name, client_io)).await;
    assert!(matches!(attempt, Ok(Err(_))), "no handshake");
    assert!(matches!(server.await.unwrap(), Served::PassOn(_)));
}

#[tokio::test]
async fn garbage_and_a_short_stream_are_passed_on_whole_and_never_answered() {
    let book = ChallengeBook::new();
    let _order = book.begin(DOMAIN, "k.a").unwrap();
    for garbage in [
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
        &[0x16, 0x03, 0x01, 0xff, 0xff, 1, 2, 3],
        &[0u8; 64],
    ] {
        let mut input = garbage;
        let served = answer_or_pass(&mut ReadOnly(&mut input), DOMAIN, &book).await;
        assert_eq!(served, Served::PassOn(garbage.to_vec()));
    }
    // An end of stream in the middle of a hello: what came is passed on.
    let (hello, _) = capture_hello(DOMAIN, &["acme-tls/1"]).await;
    let part = &hello[..hello.len() / 2];
    let mut input = part;
    let served = answer_or_pass(&mut ReadOnly(&mut input), DOMAIN, &book).await;
    assert_eq!(served, Served::PassOn(part.to_vec()));
}

#[tokio::test]
async fn a_hello_over_sixteen_kib_is_passed_on_and_not_buffered_further() {
    let book = ChallengeBook::new();
    let _order = book.begin(DOMAIN, "k.a").unwrap();
    // A handshake record header that claims 20 KiB and then enough bytes to pass the cap.
    let mut bytes = vec![0x16, 0x03, 0x01, 0x50, 0x00, 0x01, 0x00, 0x4f, 0xf0];
    bytes.resize(MAX_HELLO_BYTES + 100, 0x41);
    let mut input = bytes.as_slice();
    let served = answer_or_pass(&mut ReadOnly(&mut input), DOMAIN, &book).await;
    match served {
        Served::PassOn(read) => assert!(read.len() <= MAX_HELLO_BYTES, "{}", read.len()),
        other => panic!("{other:?}"),
    }
}

/// A reader with nothing to write to (the garbage tests never get as far as an answer).
struct ReadOnly<'a, R>(&'a mut R);

impl<R: AsyncRead + Unpin> AsyncRead for ReadOnly<'_, R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}

impl<R> AsyncWrite for ReadOnly<'_, R> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
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

// ---- ES256, DER and renewal arithmetic ----

#[test]
fn der_signatures_become_fixed_width_r_and_s() {
    // r short, s with a leading zero byte for the sign bit (33 bytes).
    let r = [0x11u8; 31];
    let mut s = vec![0x00];
    s.extend([0xf0u8; 32]);
    let mut der = vec![0x30, (2 + r.len() + 2 + s.len()) as u8, 0x02, r.len() as u8];
    der.extend(r);
    der.extend([0x02, s.len() as u8]);
    der.extend(&s);
    let raw = der_to_raw_p256(&der).unwrap();
    assert_eq!(&raw[..32], &[&[0u8][..], &r[..]].concat()[..]);
    assert_eq!(&raw[32..], &[0xf0u8; 32]);
    // Tiny values.
    let der = [0x30, 6, 0x02, 1, 0x00, 0x02, 1, 0x05];
    let raw = der_to_raw_p256(&der).unwrap();
    assert_eq!(raw[..32], [0u8; 32]);
    assert_eq!(raw[63], 5);
    // Malformed: wrong tag, trailing byte, a 33 byte value without a zero pad, wrong length.
    assert!(der_to_raw_p256(&[0x31, 6, 0x02, 1, 1, 0x02, 1, 5]).is_none());
    assert!(der_to_raw_p256(&[0x30, 7, 0x02, 1, 1, 0x02, 1, 5, 9]).is_none());
    let mut big = vec![0x30, 2 + 33 + 3, 0x02, 33, 0x01];
    big.extend([0xffu8; 32]);
    big.extend([0x02, 1, 5]);
    assert!(der_to_raw_p256(&big).is_none());
    assert!(der_to_raw_p256(&[0x30, 9, 0x02, 1, 1, 0x02, 1, 5]).is_none());
    assert!(der_to_raw_p256(&[]).is_none());
}

#[test]
fn the_account_key_signs_es256_and_has_an_rfc_7638_thumbprint() {
    let key = AccountKey::generate().unwrap();
    let (x, y) = key.coordinates().unwrap();
    let mut point = vec![4u8];
    point.extend(unb64(&x));
    point.extend(unb64(&y));
    let signature = key.sign(b"message").unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(b"message", &signature)
        .expect("a valid fixed width ES256 signature");
    assert!(
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(b"other", &signature)
            .is_err()
    );
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    assert_eq!(key.thumbprint().unwrap(), b64(sha256(canonical.as_bytes())));
}

#[test]
fn renewal_is_at_two_thirds_less_a_jitter_of_at_most_a_twelfth() {
    let (nb, na) = (1_000_000u64, 1_000_000 + 90 * 86_400);
    let life = na - nb;
    assert_eq!(
        renewal_time(nb, na, 0.0),
        nb + life / 3 * 2,
        "no jitter: exactly 2/3"
    );
    let earliest = renewal_time(nb, na, 1.0);
    assert!(earliest < renewal_time(nb, na, 0.0));
    assert!(earliest >= nb + life / 3 * 2 - life / 12);
    for jitter in [0.0, 0.1, 0.5, 0.99, 1.0, 7.0, -3.0, f64::NAN, f64::INFINITY] {
        let at = renewal_time(nb, na, jitter);
        assert!(at <= nb + life / 3 * 2, "never later than 2/3 ({jitter})");
        assert!(at >= nb + life / 3 * 2 - life / 12, "({jitter})");
    }
    // A degenerate lifetime does not underflow.
    assert_eq!(renewal_time(10, 10, 1.0), 10);
    assert_eq!(renewal_time(10, 5, 1.0), 10);
}

// ---- the store ----

#[test]
fn an_issued_certificate_must_name_the_domain_carry_the_key_and_be_valid() {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let pem = issue_leaf(DOMAIN, key.public_key_raw());
    let (nb, na) = check_issued(&pem, DOMAIN, key.public_key_raw()).unwrap();
    assert!(nb < na);
    let wrong_name = check_issued(
        &issue_leaf("evil.example", key.public_key_raw()),
        DOMAIN,
        key.public_key_raw(),
    );
    assert!(matches!(wrong_name, Err(AcmeError::Protocol(m)) if m.contains("name the domain")));
    let other = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let wrong_key = check_issued(&pem, DOMAIN, other.public_key_raw());
    assert!(matches!(wrong_key, Err(AcmeError::Protocol(m)) if m.contains("key of the request")));
    assert!(check_issued("not pem", DOMAIN, key.public_key_raw()).is_err());
    assert!(check_issued("", DOMAIN, key.public_key_raw()).is_err());
}

#[test]
fn the_store_keeps_the_key_private_replaces_atomically_and_refuses_odd_names() {
    let scratch = Scratch::new();
    let store = CertStore::new(&scratch.0);
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let issued = Issued {
        chain_pem: issue_leaf(DOMAIN, key.public_key_raw()),
        key_pem: key.serialize_pem(),
        not_before: 0,
        not_after: 0,
    };
    assert!(store.validity(DOMAIN).is_none());
    store.save(DOMAIN, &issued).unwrap();
    store.save(DOMAIN, &issued).unwrap();
    let (chain, key_path) = store.paths(DOMAIN).unwrap();
    assert_eq!(std::fs::read_to_string(&chain).unwrap(), issued.chain_pem);
    assert_eq!(std::fs::read_to_string(&key_path).unwrap(), issued.key_pem);
    let (nb, na) = store.validity(DOMAIN).unwrap();
    assert!(nb < na);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key_path), 0o600);
        assert_eq!(mode(&chain), 0o600);
        assert_eq!(mode(chain.parent().unwrap()), 0o700);
    }
    let leftovers: Vec<_> = std::fs::read_dir(chain.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(leftovers.len(), 2, "no temporary files: {leftovers:?}");
    for bad in ["../x", "a/b", "*.example", ""] {
        assert!(store.paths(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_account_key_is_created_once_read_back_and_never_replaced_when_odd() {
    let scratch = Scratch::new();
    let path = CertStore::account_key_path(&scratch.0);
    let first = AccountKey::load_or_create(&path).unwrap();
    let again = AccountKey::load_or_create(&path).unwrap();
    assert_eq!(first.thumbprint().unwrap(), again.thumbprint().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(AccountKey::load_or_create(&path), Err(AcmeError::Store(m)) if m.contains("readable by others"))
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Something that is not a key is an error and is left alone.
    let junk = scratch.0.join("junk.key");
    write_private(&junk, b"not a key").unwrap();
    assert!(AccountKey::load_or_create(&junk).is_err());
    assert_eq!(std::fs::read(&junk).unwrap(), b"not a key");
}

// ---- the HTTP transport ----

#[test]
fn http_responses_are_parsed_by_length_by_chunks_or_by_close() {
    let parse = |raw: &[u8], eof: bool, head: bool| parse_response(raw, eof, head);
    let ok = parse(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nReplay-Nonce: abc\r\n\r\nhello",
        false,
        false,
    )
    .unwrap()
    .unwrap();
    assert_eq!((ok.status, ok.body.as_slice()), (200, b"hello".as_slice()));
    assert_eq!(
        ok.header("replay-nonce"),
        Some("abc"),
        "names are lowercased"
    );
    // Incomplete: head, length body.
    assert!(
        parse(b"HTTP/1.1 200 OK\r\nContent-Le", false, false)
            .unwrap()
            .is_none()
    );
    assert!(
        parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel",
            false,
            false
        )
        .unwrap()
        .is_none()
    );
    assert!(
        parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel",
            true,
            false
        )
        .is_err()
    );
    // Chunked, with an extension and trailers.
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nTrailer: t\r\n\r\n";
    let done = parse(chunked, false, false).unwrap().unwrap();
    assert_eq!(done.body, b"abcde");
    for cut in [chunked.len() - 1, chunked.len() - 5, 50, 60] {
        assert!(
            parse(&chunked[..cut], false, false).unwrap().is_none(),
            "{cut}"
        );
        assert!(parse(&chunked[..cut], true, false).is_err(), "{cut}");
    }
    assert!(
        parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            false,
            false
        )
        .is_err()
    );
    assert!(
        parse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nabXX",
            false,
            false
        )
        .is_err()
    );
    // Read to close.
    assert!(
        parse(b"HTTP/1.1 200 OK\r\n\r\nbody", false, false)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        parse(b"HTTP/1.1 200 OK\r\n\r\nbody", true, false)
            .unwrap()
            .unwrap()
            .body,
        b"body"
    );
    // HEAD has no body whatever the headers say; 204 neither.
    let head = parse(
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nReplay-Nonce: n\r\n\r\n",
        false,
        true,
    )
    .unwrap()
    .unwrap();
    assert!(head.body.is_empty());
    assert!(
        parse(b"HTTP/1.1 204 No Content\r\n\r\n", false, false)
            .unwrap()
            .unwrap()
            .body
            .is_empty()
    );
}

#[test]
fn http_responses_that_are_too_big_or_odd_are_refused() {
    assert!(parse_response(b"HTTP/1.1 100 Continue\r\n\r\n", false, false).is_err());
    assert!(parse_response(b"garbage garbage\r\n\r\n", false, false).is_err());
    let long_length = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        MAX_RESPONSE_BYTES + 1
    );
    assert!(parse_response(long_length.as_bytes(), false, false).is_err());
    assert!(
        parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            false,
            false
        )
        .is_err()
    );
    let mut huge_head = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    huge_head.resize(MAX_HEAD_BYTES + 10, b'a');
    assert!(parse_response(&huge_head, false, false).is_err());
    let mut chunk_flood = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    chunk_flood.extend(format!("{:x}\r\n", MAX_RESPONSE_BYTES + 1).as_bytes());
    assert!(parse_response(&chunk_flood, false, false).is_err());
}

/// A TLS server on localhost that answers one connection with `reply` (in two writes) and
/// returns the request it saw.
async fn tls_server(
    reply: Vec<u8>,
) -> (
    u16,
    Arc<rustls::ClientConfig>,
    tokio::task::JoinHandle<String>,
) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let server_config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap(),
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let client_config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(server_config)
            .accept(tcp)
            .await
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = tls.read(&mut chunk).await.unwrap();
            request.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&request).into_owned();
            if let Some(split) = text.find("\r\n\r\n") {
                let length = text
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= split + 4 + length {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        let half = reply.len() / 2;
        tls.write_all(&reply[..half]).await.unwrap();
        tls.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        tls.write_all(&reply[half..]).await.unwrap();
        let _ = tls.shutdown().await;
        String::from_utf8_lossy(&request).into_owned()
    });
    (port, client_config, task)
}

#[tokio::test]
async fn the_https_transport_sends_a_post_and_reads_a_chunked_answer_in_pieces() {
    let reply = b"HTTP/1.1 201 Created\r\nReplay-Nonce: n1\r\nLocation: https://ca/acct/1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n2\r\n1}\r\n0\r\n\r\n".to_vec();
    let (port, config, server) = tls_server(reply).await;
    let transport = HttpsTransport::with_config(config);
    let response = transport
        .send(HttpRequest {
            method: Method::Post,
            url: format!("https://localhost:{port}/new-acct?x=1"),
            headers: vec![("Content-Type", "application/jose+json".to_string())],
            body: b"{\"payload\":1}".to_vec(),
        })
        .await
        .unwrap();
    assert_eq!(response.status, 201);
    assert_eq!(response.body, b"{\"a\":1}");
    assert_eq!(response.header("replay-nonce"), Some("n1"));
    assert_eq!(response.header("location"), Some("https://ca/acct/1"));
    let request = server.await.unwrap();
    assert!(
        request.starts_with("POST /new-acct?x=1 HTTP/1.1\r\n"),
        "{request}"
    );
    assert!(request.contains(&format!("Host: localhost:{port}\r\n")));
    assert!(request.contains("Connection: close\r\n"));
    assert!(request.contains("Content-Type: application/jose+json\r\n"));
    assert!(request.contains("Content-Length: 13\r\n"));
    assert!(request.ends_with("\r\n\r\n{\"payload\":1}"));
}

#[tokio::test]
async fn the_https_transport_reads_a_head_answer_without_a_body() {
    let reply = b"HTTP/1.1 200 OK\r\nReplay-Nonce: fresh\r\nContent-Length: 4\r\n\r\n".to_vec();
    let (port, config, server) = tls_server(reply).await;
    let response = HttpsTransport::with_config(config)
        .send(HttpRequest {
            method: Method::Head,
            url: format!("https://localhost:{port}/nonce"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await
        .unwrap();
    assert_eq!(response.header("replay-nonce"), Some("fresh"));
    assert!(response.body.is_empty());
    assert!(
        server
            .await
            .unwrap()
            .starts_with("HEAD /nonce HTTP/1.1\r\n")
    );
}

#[tokio::test]
async fn the_https_transport_refuses_plain_http_credentials_and_untrusted_servers() {
    let transport = HttpsTransport::with_config(client_config(&[]));
    for url in [
        "http://localhost:1/dir",
        "https://user:pw@localhost:1/dir",
        "ftp://localhost/dir",
        "not a url",
    ] {
        let result = transport
            .send(HttpRequest {
                method: Method::Get,
                url: url.to_string(),
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await;
        assert!(matches!(result, Err(AcmeError::Http(_))), "{url}");
    }
    // A server whose certificate the client does not trust.
    let (port, _trusting, server) =
        tls_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
    let (_, other_config, _other) = tls_server(Vec::new()).await;
    let result = HttpsTransport::with_config(other_config)
        .send(HttpRequest {
            method: Method::Get,
            url: format!("https://localhost:{port}/dir"),
            headers: Vec::new(),
            body: Vec::new(),
        })
        .await;
    assert!(matches!(result, Err(AcmeError::Http(_))), "{result:?}");
    server.abort();
}

async fn obtain(
    flags: Flags,
    wanted: bool,
) -> (Result<Issued, AcmeError>, Arc<FakeCa>, ChallengeBook) {
    let book = ChallengeBook::new();
    let ca = FakeCa::new(&book, flags);
    let mut client = client_for(&ca);
    let result = client.obtain(DOMAIN, &book, &move || wanted).await;
    (result, ca, book)
}

#[tokio::test]
async fn the_client_obtains_a_certificate_through_the_whole_exchange() {
    let (result, ca, book) = obtain(
        Flags {
            pending_polls: 2,
            finalize_processing: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    let issued = result.unwrap();
    let state = ca.state();
    // The CA verified every JWS (check_jws asserts); no nonce was reused or missing.
    assert_eq!(state.bad_nonce_answers, 0);
    // The name was pending when the CA was told to validate, and the CA's validation connection
    // saw the digest of the key authorization it computed from the account key it was shown.
    assert_eq!(state.pending_at_challenge, Some(true));
    assert_eq!(state.challenge_posts, 1);
    assert_eq!(state.digest_seen, state.expected_digest);
    assert!(state.digest_seen.is_some());
    assert!(state.accept_header_ok);
    // The order of the exchange.
    let routes: Vec<&str> = state.log.iter().map(String::as_str).collect();
    let position = |needle: &str| routes.iter().position(|r| *r == needle).unwrap();
    assert!(position("Get /dir") < position("Post /acct"));
    assert!(position("Post /acct") < position("Post /order"));
    assert!(position("Post /order") < position("Post /authz/1"));
    assert!(position("Post /authz/1") < position("Post /chal/1"));
    assert!(position("Post /chal/1") < position("Post /finalize/1"));
    assert!(position("Post /finalize/1") < position("Post /cert/1"));
    assert_eq!(routes.iter().filter(|r| **r == "Post /acct").count(), 1);
    // The name is no longer pending, and the result is what the store would keep.
    assert!(book.is_empty());
    assert!(issued.chain_pem.matches("BEGIN CERTIFICATE").count() == 2);
    assert!(issued.key_pem.contains("PRIVATE KEY"));
    assert!(issued.not_before < issued.not_after);
}

#[tokio::test]
async fn a_second_obtain_reuses_the_account_and_the_nonce() {
    let book = ChallengeBook::new();
    let ca = FakeCa::new(&book, Flags::default());
    let mut client = client_for(&ca);
    client.obtain(DOMAIN, &book, &|| true).await.unwrap();
    {
        let mut state = ca.state();
        state.validated = None;
        state.finalized = false;
        state.polls_after_validation = 0;
    }
    client.obtain(DOMAIN, &book, &|| true).await.unwrap();
    let state = ca.state();
    assert_eq!(state.log.iter().filter(|r| *r == "Post /acct").count(), 1);
    assert_eq!(state.log.iter().filter(|r| *r == "Get /dir").count(), 1);
    assert_eq!(state.bad_nonce_answers, 0);
}

#[tokio::test]
async fn a_bad_nonce_is_retried_with_the_fresh_nonce_and_not_forever() {
    let (result, ca, _book) = obtain(
        Flags {
            bad_nonce_once: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    result.unwrap();
    assert_eq!(ca.state().bad_nonce_answers, 1);

    let (result, ca, _book) = obtain(
        Flags {
            bad_nonce_always: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    assert!(
        matches!(&result, Err(AcmeError::Problem { status: 400, kind, .. }) if kind.ends_with("badNonce")),
        "{result:?}"
    );
    // The nonce comes from the answers; the retries are bounded.
    assert!(ca.state().bad_nonce_answers <= 3);
}

#[tokio::test]
async fn a_share_that_is_no_longer_wanted_ends_the_attempt_before_the_ca_is_told_to_validate() {
    let (result, ca, book) = obtain(Flags::default(), false).await;
    assert!(matches!(result, Err(AcmeError::NotWanted)), "{result:?}");
    assert_eq!(ca.state().challenge_posts, 0);
    assert!(book.is_empty());
}

#[tokio::test]
async fn authorizations_that_are_not_for_the_ordered_name_are_refused() {
    for flags in [
        Flags {
            wildcard: true,
            ..Flags::default()
        },
        Flags {
            other_identifier: true,
            ..Flags::default()
        },
        Flags {
            order_other_identifier: true,
            ..Flags::default()
        },
    ] {
        let (result, ca, book) = obtain(flags.clone(), true).await;
        assert!(matches!(result, Err(AcmeError::Protocol(_))), "{result:?}");
        assert_eq!(
            ca.state().challenge_posts,
            0,
            "the CA was never told to validate"
        );
        assert!(book.is_empty());
    }
}

#[tokio::test]
async fn a_challenge_the_client_cannot_answer_or_a_token_that_is_not_base64url_is_refused() {
    let (result, ca, _book) = obtain(
        Flags {
            no_alpn_challenge: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    assert!(
        matches!(&result, Err(AcmeError::Failed(m)) if m.contains("tls-alpn-01")),
        "{result:?}"
    );
    assert_eq!(ca.state().challenge_posts, 0);
    let (result, ca, book) = obtain(
        Flags {
            bad_token: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    assert!(matches!(result, Err(AcmeError::Protocol(_))), "{result:?}");
    assert_eq!(ca.state().challenge_posts, 0);
    assert!(book.is_empty());
}

#[tokio::test]
async fn a_failed_validation_ends_the_order_with_the_cas_reason_and_clears_the_name() {
    let (result, ca, book) = obtain(
        Flags {
            validation_fails: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    assert!(
        matches!(&result, Err(AcmeError::Failed(m)) if m.contains("the validation connection failed")),
        "{result:?}"
    );
    assert_eq!(ca.state().challenge_posts, 1);
    assert!(book.is_empty(), "the name stops being answered");
    assert!(!ca.state().log.iter().any(|r| r == "Post /finalize/1"));
}

#[tokio::test]
async fn an_authorization_that_never_completes_times_out_and_clears_the_name() {
    let book = ChallengeBook::new();
    let ca = FakeCa::new(
        &book,
        Flags {
            never_validates: true,
            ..Flags::default()
        },
    );
    let mut client = client_for(&ca).with_timing(Timing {
        poll_interval: Duration::from_millis(5),
        poll_max_interval: Duration::from_millis(5),
        poll_deadline: Duration::from_millis(60),
    });
    let result = client.obtain(DOMAIN, &book, &|| true).await;
    assert!(matches!(result, Err(AcmeError::Timeout(_))), "{result:?}");
    assert!(book.is_empty());
}

#[tokio::test]
async fn a_certificate_for_another_name_or_another_key_is_not_accepted() {
    let (result, _, _) = obtain(
        Flags {
            cert_for_other_domain: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    assert!(
        matches!(&result, Err(AcmeError::Protocol(m)) if m.contains("name the domain")),
        "{result:?}"
    );
    let (result, _, _) = obtain(
        Flags {
            cert_with_other_key: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    assert!(
        matches!(&result, Err(AcmeError::Protocol(m)) if m.contains("key of the request")),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_refused_account_is_the_cas_problem_and_a_bad_domain_never_leaves_the_node() {
    let (result, ca, _) = obtain(
        Flags {
            refuse_account: true,
            ..Flags::default()
        },
        true,
    )
    .await;
    assert!(
        matches!(&result, Err(AcmeError::Problem { status: 403, kind, .. }) if kind.ends_with(":unauthorized")),
        "{result:?}"
    );
    assert!(!ca.state().log.iter().any(|r| r == "Post /order"));
    let book = ChallengeBook::new();
    let ca = FakeCa::new(&book, Flags::default());
    let result = client_for(&ca)
        .obtain("*.relay.example", &book, &|| true)
        .await;
    assert!(matches!(result, Err(AcmeError::BadDomain(_))));
    assert!(ca.state().log.is_empty(), "nothing was sent");
}

#[tokio::test(start_paused = true)]
async fn the_renewal_loop_orders_for_a_wanted_name_stores_the_result_and_stays_quiet_for_an_unwanted_one()
 {
    let scratch = Scratch::new();
    let store = CertStore::new(&scratch.0);
    let book = ChallengeBook::new();
    let allowed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let job = AcmeJob {
        share: "app".to_string(),
        domain: DOMAIN.to_string(),
    };
    let ca = FakeCa::new(&book, Flags::default());
    let task = tokio::spawn(run_renewals(
        client_for(&ca),
        store.clone(),
        {
            let allowed = allowed.clone();
            move || allowed.load(std::sync::atomic::Ordering::SeqCst)
        },
        book.clone(),
        job,
    ));
    // Not wanted: minutes pass and the CA is not asked anything.
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert!(ca.state().log.is_empty());
    assert!(store.validity(DOMAIN).is_none());
    // Wanted: an order is made and kept.
    allowed.store(true, std::sync::atomic::Ordering::SeqCst);
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
    let (chain, key) = store.paths(DOMAIN).unwrap();
    assert!(chain.exists() && key.exists());
    // Valid until 2090: no new order while it lasts.
    let orders = ca
        .state()
        .log
        .iter()
        .filter(|r| *r == "Post /order")
        .count();
    tokio::time::sleep(Duration::from_secs(24 * 3600)).await;
    assert_eq!(
        ca.state()
            .log
            .iter()
            .filter(|r| *r == "Post /order")
            .count(),
        orders
    );
    task.abort();
}
