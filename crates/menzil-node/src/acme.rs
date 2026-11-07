//! Node side ACME TLS-ALPN-01 through the relay (protocol.md 6.2, expose design S-E8).
//!
//! A node that holds a blind share (`tls:<label>`, or `tcp:`) terminates TLS for the share's name
//! itself, so it also obtains and renews that name's certificate itself. The CA's validation
//! connection reaches the relay's front door like any client, with ALPN `acme-tls/1` and the
//! share name as SNI, and the relay (which routes it only to a node whose share lists
//! `acme-tls/1`) opens a blind `tls:` stream with the bytes, ClientHello included. This module is
//! the node's half:
//!
//! * [`ChallengeBook`]: the orders that wait for a validation connection now. An entry exists
//!   only between [`ChallengeBook::begin`] and the drop of its [`PendingOrder`] (or five
//!   minutes, [`PENDING_TTL`], whichever comes first), at most [`MAX_PENDING`] at a time, and it
//!   holds the challenge certificate ready (self signed, SAN the exact name, the critical
//!   `id-pe-acmeIdentifier` extension with the SHA-256 of the key authorization, RFC 8737).
//! * [`AcmeHandler`]: wraps [`LocalServices`] and, for a relay stream whose SNI has a pending
//!   order, reads the ClientHello (16 KiB, 5 s) and answers it with the challenge certificate
//!   if, and only if, its ALPN list is exactly `acme-tls/1` and its SNI is the pending name. A
//!   stream without a pending order is not read at all; any other stream with one is handed to
//!   the local target with the bytes already read written first. Every failure on the way
//!   (garbage, a slow client, no certificate for the name) is a closed stream, never a
//!   certificate.
//! * [`client`]: a small RFC 8555 client (ES256 JWS, one account key, `tls-alpn-01` only) over a
//!   transport trait; [`http`]: that transport over HTTPS with the platform verifier;
//!   [`renew`]: the certificate store (atomic, key 0600) and the loop that renews at two
//!   thirds of the lifetime less a jitter.
//!
//! What this module does not do: decide the share's full name (the share domain is the relay's,
//! open decision 53, so the caller passes the domain), wire the handler into the CLI, or hand the
//! issued certificate to the service behind the share (it is written to
//! `<home>/acme/certs/<domain>/{fullchain,privkey}.pem`).

pub mod client;
pub mod http;
pub mod renew;

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use menzil_proto::ServiceKind;
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{Accepted, Acceptor};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::serve::{LocalServices, OpenedTarget, TokioStream};
pub use crate::shares::ACME_ALPN;

pub use client::{AccountKey, AcmeClient, Issued, Timing};
pub use http::{AcmeTransport, HttpRequest, HttpResponse, HttpsTransport, Method};
pub use renew::{AcmeJob, CertStore, renewal_time, run_renewals};

/// How long an order waits for its validation connection (and so how long its challenge
/// certificate can be served).
pub const PENDING_TTL: Duration = Duration::from_secs(300);

/// How many orders may wait at once.
pub const MAX_PENDING: usize = 16;

/// How much of a stream is read to find the ClientHello (the relay's own peek has the same cap).
const MAX_HELLO_BYTES: usize = 16 * 1024;

/// How long the ClientHello of a stream may take to arrive.
const PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the whole answer to a validation connection may take.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an ACME step failed.
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// Not a name an order may be for (one or more lowercase LDH labels, no wildcard).
    #[error("{0:?} is not a name an ACME order may be for")]
    BadDomain(String),
    /// [`MAX_PENDING`] orders are already waiting.
    #[error("too many orders are waiting for a validation connection")]
    TooManyPending,
    /// A certificate or key could not be made.
    #[error("certificate: {0}")]
    Cert(String),
    /// The TLS setup of the responder or the client.
    #[error("tls: {0}")]
    Tls(String),
    /// The HTTP exchange with the CA failed.
    #[error("http: {0}")]
    Http(String),
    /// The CA answered with a problem document or an error status.
    #[error("the CA answered {status} {kind}: {detail}")]
    Problem {
        /// The HTTP status.
        status: u16,
        /// The problem `type`, or empty.
        kind: String,
        /// The problem `detail`, or empty.
        detail: String,
    },
    /// The CA's answer is not what RFC 8555 says.
    #[error("the CA's answer is not valid: {0}")]
    Protocol(String),
    /// The order or its authorization ended `invalid`.
    #[error("the order failed: {0}")]
    Failed(String),
    /// The share is not accepted by the relay, or does not list `acme-tls/1`.
    #[error("the share is not accepted or does not list acme-tls/1")]
    NotWanted,
    /// A wait ran out.
    #[error("timed out: {0}")]
    Timeout(&'static str),
    /// The certificate store or the account key file.
    #[error("store: {0}")]
    Store(String),
}

/// Whether `domain` is a name an order may be for: 1 to 253 bytes, dot separated labels of 1 to
/// 63 lowercase letters, digits and hyphens (not at either end), no wildcard, no trailing dot.
/// The names a stream's SNI is compared with are in this form too.
pub fn check_domain(domain: &str) -> Result<(), AcmeError> {
    let ok = !domain.is_empty()
        && domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if ok {
        Ok(())
    } else {
        Err(AcmeError::BadDomain(domain.to_string()))
    }
}

#[cfg(feature = "aws-lc-rs")]
pub(crate) fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
pub(crate) fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!(
    "menzil-node requires either the \"aws-lc-rs\" (default) or \"ring\" feature to select a TLS crypto provider"
);

/// The challenge certificate of RFC 8737 for `domain` and the SHA-256 of the key authorization
/// `digest`: self signed, no subject, SAN `domain`, the critical `id-pe-acmeIdentifier`
/// extension holding `digest`; with its key.
pub(crate) fn challenge_certificate(
    domain: &str,
    digest: &[u8; 32],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), AcmeError> {
    let cert_error = |e: rcgen::Error| AcmeError::Cert(e.to_string());
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
    let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(cert_error)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(digest));
    let cert = params.self_signed(&key).map_err(cert_error)?;
    let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der()));
    Ok((cert.der().clone(), key_der))
}

/// Presents one certificate whatever the ClientHello says.
#[derive(Debug)]
struct FixedCertificate(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for FixedCertificate {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// [`challenge_certificate`] as a rustls server configuration that offers `acme-tls/1` and
/// nothing else.
pub(crate) fn challenge_config(
    domain: &str,
    digest: &[u8; 32],
) -> Result<Arc<rustls::ServerConfig>, AcmeError> {
    let (cert, key_der) = challenge_certificate(domain, digest)?;
    let provider = Arc::new(default_provider());
    let signing_key = provider
        .key_provider
        .load_private_key(key_der)
        .map_err(|e| AcmeError::Tls(e.to_string()))?;
    // `CertifiedKey::new`, not `with_single_cert`: that one parses the certificate as an end
    // entity certificate and refuses the critical acmeIdentifier extension rustls does not know.
    let certified = Arc::new(rustls::sign::CertifiedKey::new(vec![cert], signing_key));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| AcmeError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCertificate(certified)));
    config.alpn_protocols = vec![ACME_ALPN.as_bytes().to_vec()];
    Ok(Arc::new(config))
}

/// The SHA-256 of a key authorization (RFC 8737 section 3).
pub(crate) fn key_authorization_digest(key_authorization: &str) -> [u8; 32] {
    Sha256::digest(key_authorization.as_bytes()).into()
}

struct Pending {
    config: Arc<rustls::ServerConfig>,
    deadline: Instant,
    id: u64,
}

#[derive(Default)]
struct BookInner {
    pending: Mutex<HashMap<String, Pending>>,
    next_id: AtomicU64,
}

/// The orders that wait for a validation connection. One handle, cloned freely; the client side
/// ([`AcmeClient::obtain`]) fills it and [`AcmeHandler`] reads it. See the module docs.
#[derive(Clone, Default)]
pub struct ChallengeBook {
    inner: Arc<BookInner>,
}

impl std::fmt::Debug for ChallengeBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChallengeBook")
            .field("pending", &self.len())
            .finish()
    }
}

impl ChallengeBook {
    /// A book with no pending order: no stream is answered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes `domain` pending for [`PENDING_TTL`] with the challenge for `key_authorization`, a
    /// second order for the same name replacing the first. Refused for a bad name and past
    /// [`MAX_PENDING`] orders.
    pub fn begin(&self, domain: &str, key_authorization: &str) -> Result<PendingOrder, AcmeError> {
        check_domain(domain)?;
        let config = challenge_config(domain, &key_authorization_digest(key_authorization))?;
        let now = Instant::now();
        let mut pending = self.lock();
        pending.retain(|_, order| order.deadline > now);
        if pending.len() >= MAX_PENDING && !pending.contains_key(domain) {
            return Err(AcmeError::TooManyPending);
        }
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        pending.insert(
            domain.to_string(),
            Pending {
                config,
                deadline: now + PENDING_TTL,
                id,
            },
        );
        Ok(PendingOrder {
            book: self.clone(),
            domain: domain.to_string(),
            id,
        })
    }

    /// Whether an order for exactly `name` (lowercase) waits now.
    pub fn is_pending(&self, name: &str) -> bool {
        self.config_for(name).is_some()
    }

    /// How many orders wait now.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.lock().values().filter(|o| o.deadline > now).count()
    }

    /// Whether no order waits now.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn config_for(&self, name: &str) -> Option<Arc<rustls::ServerConfig>> {
        let now = Instant::now();
        self.lock()
            .get(name)
            .filter(|order| order.deadline > now)
            .map(|order| order.config.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pending>> {
        // Plain data replaced whole: a panic elsewhere leaves it consistent.
        self.inner
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// An order waiting for its validation connection; the name stops being answered when this is
/// dropped (the order is valid, invalid or given up).
#[derive(Debug)]
pub struct PendingOrder {
    book: ChallengeBook,
    domain: String,
    id: u64,
}

impl Drop for PendingOrder {
    fn drop(&mut self) {
        let mut pending = self.book.lock();
        // A newer order for the same name is not ours to remove.
        if pending.get(&self.domain).is_some_and(|o| o.id == self.id) {
            pending.remove(&self.domain);
        }
    }
}

/// What reading the start of a stream found.
struct Peeked {
    /// Every byte read so far.
    buf: Vec<u8>,
    /// The parsed ClientHello, if one arrived whole.
    hello: Option<Accepted>,
}

/// Reads from `io` until rustls has a whole ClientHello, at most [`MAX_HELLO_BYTES`]. Garbage,
/// too long a hello and an early end of stream give `hello: None` with what was read, so that
/// the caller can pass it on; only an I/O error is an `Err`.
async fn peek_client_hello<S>(io: &mut S) -> io::Result<Peeked>
where
    S: AsyncRead + Unpin,
{
    let mut acceptor = Acceptor::default();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = io.read(&mut chunk).await?;
        if n == 0 || buf.len() + n > MAX_HELLO_BYTES {
            return Ok(Peeked { buf, hello: None });
        }
        buf.extend_from_slice(&chunk[..n]);
        let mut fed = &chunk[..n];
        while !fed.is_empty() {
            match acceptor.read_tls(&mut fed) {
                Ok(0) | Err(_) => return Ok(Peeked { buf, hello: None }),
                Ok(_) => {}
            }
        }
        match acceptor.accept() {
            Ok(None) => {}
            Ok(Some(hello)) => {
                return Ok(Peeked {
                    buf,
                    hello: Some(hello),
                });
            }
            Err(_) => return Ok(Peeked { buf, hello: None }),
        }
    }
}

/// Whether `hello` is a TLS-ALPN-01 validation of `name`: its SNI is `name` and its ALPN list is
/// exactly `acme-tls/1`.
fn is_validation_of(hello: &Accepted, name: &str) -> bool {
    let hello = hello.client_hello();
    let sni_matches = hello
        .server_name()
        .is_some_and(|sni| sni.eq_ignore_ascii_case(name));
    let alpn_matches = hello
        .alpn()
        .is_some_and(|mut alpn| alpn.next() == Some(ACME_ALPN.as_bytes()) && alpn.next().is_none());
    sni_matches && alpn_matches
}

/// Completes the TLS handshake of `hello` with `config` over `io` (the challenge certificate goes
/// out; the CA checks it and closes), then closes.
async fn answer_challenge<S>(
    io: &mut S,
    hello: Accepted,
    config: Arc<rustls::ServerConfig>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut conn = hello
        .into_connection(config)
        .map_err(|(error, _alert)| io::Error::other(error))?;
    let mut chunk = [0u8; 4096];
    loop {
        while conn.wants_write() {
            let mut out = Vec::new();
            conn.write_tls(&mut out)?;
            io.write_all(&out).await?;
        }
        io.flush().await?;
        if !conn.is_handshaking() {
            break;
        }
        let n = io.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let mut fed = &chunk[..n];
        while !fed.is_empty() {
            conn.read_tls(&mut fed)?;
            conn.process_new_packets().map_err(io::Error::other)?;
        }
    }
    // The certificate went out and the handshake is complete: the CA has what it came for and may
    // already have gone, so closing is best effort.
    conn.send_close_notify();
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).is_err() {
            break;
        }
    }
    let _ = io.write_all(&out).await;
    let _ = io.flush().await;
    let _ = io.shutdown().await;
    Ok(())
}

/// [`LocalServices`] that also answers TLS-ALPN-01 validation connections for the names of a
/// [`ChallengeBook`]. See the module docs; hand it to the node in place of the plain
/// [`LocalServices`].
///
/// Only the relay principal sets `meta.sni` (the node scrubs it from every member's OPEN), so a
/// member can never reach the responder; without a pending order for the stream's SNI the stream
/// is not read.
#[derive(Debug, Clone)]
pub struct AcmeHandler {
    services: LocalServices,
    book: ChallengeBook,
}

impl AcmeHandler {
    /// `services` with the validation answers of `book`.
    pub fn new(services: LocalServices, book: ChallengeBook) -> Self {
        Self { services, book }
    }
}

impl ServiceHandler<Stream> for AcmeHandler {
    type Opened = OpenedTarget;
    type Handling = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<OpenedTarget, OpenRefusal> {
        self.services.open(request).await
    }

    async fn open_with_own_limits(
        &self,
        request: &OpenRequest,
    ) -> Result<OpenedTarget, OpenRefusal> {
        self.services.open_with_own_limits(request).await
    }

    fn handle(&self, stream: Stream, request: OpenRequest, opened: OpenedTarget) -> Self::Handling {
        let sni = request
            .meta
            .sni
            .as_deref()
            .map(str::to_ascii_lowercase)
            .filter(|_| matches!(request.service.kind, ServiceKind::Tls | ServiceKind::Tcp))
            .filter(|sni| self.book.is_pending(sni));
        let Some(sni) = sni else {
            return self
                .services
                .handle_with_prefix(stream, request, opened, Vec::new());
        };
        let services = self.services.clone();
        let book = self.book.clone();
        Box::pin(async move {
            let mut remote = TokioStream(stream);
            match answer_or_pass(&mut remote, &sni, &book).await {
                Served::Answered => {
                    // The connection the open made is of no use for a validation; dropping it
                    // resets it.
                    drop(opened);
                }
                Served::PassOn(read) => {
                    services
                        .handle_with_prefix(remote.0, request, opened, read)
                        .await;
                }
                // A slow or broken stream: nothing was served, nothing is passed on.
                Served::Failed => remote.0.reset(),
            }
        })
    }
}

/// What [`answer_or_pass`] did with a stream.
#[derive(Debug, PartialEq, Eq)]
enum Served {
    /// A validation connection: the challenge certificate was presented and the stream closed.
    Answered,
    /// Not one: the bytes read so far, to be passed on to the local target before the rest.
    PassOn(Vec<u8>),
    /// Nothing can be said of it (a timeout, an I/O error, the order ended while the hello
    /// arrived, a handshake that did not complete): close it.
    Failed,
}

/// Reads the start of `io`, a stream of the share whose SNI is `sni`, and answers it with the
/// challenge certificate of `book` if it is a validation of exactly that name, else hands back
/// what was read. See [`AcmeHandler`].
async fn answer_or_pass<S>(io: &mut S, sni: &str, book: &ChallengeBook) -> Served
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(Ok(Peeked { buf, hello })) =
        tokio::time::timeout(PEEK_TIMEOUT, peek_client_hello(io)).await
    else {
        return Served::Failed;
    };
    let Some(hello) = hello else {
        return Served::PassOn(buf);
    };
    if !is_validation_of(&hello, sni) {
        return Served::PassOn(buf);
    }
    // The order may have ended while the hello arrived.
    let Some(config) = book.config_for(sni) else {
        return Served::Failed;
    };
    match tokio::time::timeout(ANSWER_TIMEOUT, answer_challenge(io, hello, config)).await {
        Ok(Ok(())) => Served::Answered,
        _ => Served::Failed,
    }
}

#[cfg(test)]
mod tests;
