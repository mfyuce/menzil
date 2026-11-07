//! The relay's own ACME (TLS-ALPN-01, expose design S-E9a): certificates for the relay's own host
//! name(s) and for the names the relay terminates itself.
//!
//! The relay is the TLS endpoint of its own front door, so it answers `acme-tls/1` itself, for
//! the names of its own orders only; a blind share's validation is the node's (`menzil-node`,
//! S-E8) and reaches this module never. What lives here:
//!
//! * [`RelayCertBook`]: name to current certificate, a rustls `ResolvesServerCert` (no
//!   certificate for a name is a failed handshake, never another name's certificate; only an
//!   operator supplied fallback, the relay's static certificate, answers every other name).
//! * [`AcmeConfig`] and [`RelayAcme`]: the settings (the directory URL and the contact are
//!   operator keys with no default, so a relay never talks to a CA nobody named), the book and
//!   the pending challenges, handed to the relay with `Relay::with_acme`.
//! * The names that are ordered: the configured host names, and for each accepted terminated
//!   (`http:`) share of a tenant that has the `terminated` flag, whose holder is attached and
//!   whose label the Roster still grants, `<name>.t.<share domain>` (the `t` zone,
//!   multitenant design 2: `<label>.t.H`, `<label>.<slug>.t.H`). A name that is not in that set
//!   is never ordered: nothing a client sends (an SNI, a Host) starts an order, and the set is
//!   asked again before the CA is told to validate.
//! * [`OrderLimiter`]: one order per name per minute (a failure doubles the wait up to an hour)
//!   and at most [`MAX_PENDING_ORDERS`] orders in flight at once.
//! * The front door's half ([`answer_validation`]): a ClientHello with ALPN exactly
//!   `acme-tls/1` and an SNI that has a pending order is answered with the challenge
//!   certificate; any other connection is unchanged.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use menzil_acme::client::Timing;
use menzil_acme::{
    ACME_ALPN, ANSWER_TIMEOUT, AcmeClient, AcmeError, AcmeJob, AcmeTransport, CertStore,
    ChallengeBook, MAX_PENDING, Peeked, answer_challenge, certified_key_from_pem, check_domain,
    is_validation_of, peek_client_hello, renewal_time,
};
use menzil_proto::{ServiceKind, ShareMode};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpStream;
use tokio::time::Instant;

use crate::relay::Relay;

/// One order per name per this long, whatever happened to the last one.
pub const ORDER_MIN_INTERVAL: Duration = Duration::from_secs(60);

/// The longest wait after repeated failures of one name.
pub const ORDER_BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// Orders in flight at once (the challenge book's own cap).
pub const MAX_PENDING_ORDERS: usize = MAX_PENDING;

// ---------------------------------------------------------------------------------------------
// The certificate book
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct BookInner {
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    fallback: RwLock<Option<Arc<CertifiedKey>>>,
}

/// The current certificate of each name the relay serves TLS for. Cloning shares it.
#[derive(Clone, Default)]
pub struct RelayCertBook {
    inner: Arc<BookInner>,
}

impl std::fmt::Debug for RelayCertBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayCertBook")
            .field("names", &self.names())
            .finish()
    }
}

impl RelayCertBook {
    /// An empty book with no fallback: every name fails its handshake until it has a certificate.
    pub fn new() -> Self {
        Self::default()
    }

    /// The certificate answered for every name that has none of its own (the operator's static
    /// certificate for the relay's own host name), from PEM files' contents.
    pub fn set_fallback_pem(&self, chain_pem: &str, key_pem: &str) -> Result<(), AcmeError> {
        let key = certified_key_from_pem(chain_pem, key_pem)?;
        *self
            .inner
            .fallback
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(key);
        Ok(())
    }

    /// Keeps `chain_pem` and `key_pem` as the certificate of `name` (lowercase), replacing the
    /// one it had.
    pub fn install_pem(&self, name: &str, chain_pem: &str, key_pem: &str) -> Result<(), AcmeError> {
        check_domain(name)?;
        let key = certified_key_from_pem(chain_pem, key_pem)?;
        self.inner
            .certs
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(name.to_string(), key);
        Ok(())
    }

    /// The certificate of exactly `name`, if it has one.
    pub fn get(&self, name: &str) -> Option<Arc<CertifiedKey>> {
        self.inner
            .certs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(name)
            .cloned()
    }

    /// The names that have a certificate now, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .inner
            .certs
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    }

    /// Forgets every certificate whose name `keep` refuses (a name that is no longer served).
    pub fn retain(&self, keep: impl Fn(&str) -> bool) {
        self.inner
            .certs
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|name, _| keep(name));
    }

    /// A rustls server configuration for the relay's own host name that resolves from this book
    /// (ALPN `http/1.1`, as [`crate::server_config`]).
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, AcmeError> {
        crate::tls::ensure_crypto_provider();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(self.clone()));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

impl std::fmt::Debug for BookInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BookInner")
    }
}

impl ResolvesServerCert for RelayCertBook {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name().map(str::to_ascii_lowercase);
        if let Some(found) = sni.as_deref().and_then(|name| self.get(name)) {
            return Some(found);
        }
        self.inner
            .fallback
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

// ---------------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------------

/// The relay's ACME settings. Nothing here has a default that names a CA.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    directory_url: String,
    contact: Option<String>,
    dir: PathBuf,
    hosts: Vec<String>,
    tick: Duration,
}

impl AcmeConfig {
    /// Settings for the CA whose RFC 8555 directory is at `directory_url` (an `https://` URL;
    /// the operator names it, for a trial the CA's staging directory), keeping the account key
    /// and the certificates under `dir` (`acme/account.key`, `acme/certs/<name>/`).
    pub fn new(directory_url: &str, dir: impl Into<PathBuf>) -> Result<Self, AcmeError> {
        if !directory_url.starts_with("https://") {
            return Err(AcmeError::Protocol(format!(
                "the ACME directory {directory_url:?} is not an https:// URL"
            )));
        }
        Ok(Self {
            directory_url: directory_url.to_string(),
            contact: None,
            dir: dir.into(),
            hosts: Vec::new(),
            tick: Duration::from_secs(60),
        })
    }

    /// With the contact the CA may write to (`mailto:ops@example.org`).
    #[must_use]
    pub fn with_contact(mut self, contact: &str) -> Self {
        self.contact = Some(contact.to_string());
        self
    }

    /// With the relay's own host name(s) to keep a certificate for.
    pub fn with_hosts(mut self, hosts: &[&str]) -> Result<Self, AcmeError> {
        let mut out = Vec::new();
        for host in hosts {
            let host = host.to_ascii_lowercase();
            check_domain(&host)?;
            if !out.contains(&host) {
                out.push(host);
            }
        }
        self.hosts = out;
        Ok(self)
    }

    /// With `tick` as the time between looks at the names (tests).
    #[must_use]
    pub fn with_tick(mut self, tick: Duration) -> Self {
        self.tick = tick;
        self
    }

    /// The directory URL.
    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    /// The configured host names.
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }
}

/// What a relay with ACME holds: the settings, the certificates, the orders waiting for their
/// validation connection and the limiter.
#[derive(Clone)]
pub struct RelayAcme {
    config: Arc<AcmeConfig>,
    certs: RelayCertBook,
    challenges: ChallengeBook,
    limiter: Arc<OrderLimiter>,
    timing: Timing,
    external_runner: bool,
}

impl std::fmt::Debug for RelayAcme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayAcme")
            .field("config", &self.config)
            .field("certs", &self.certs)
            .finish()
    }
}

impl RelayAcme {
    /// ACME with `config` and an empty certificate book.
    pub fn new(config: AcmeConfig) -> Self {
        Self::with_book(config, RelayCertBook::new())
    }

    /// ACME with `config` filling `certs` (which the relay's own TLS configuration resolves
    /// from, [`RelayCertBook::server_config`]).
    pub fn with_book(config: AcmeConfig, certs: RelayCertBook) -> Self {
        Self {
            config: Arc::new(config),
            certs,
            challenges: ChallengeBook::new(),
            limiter: Arc::default(),
            timing: Timing::default(),
            external_runner: false,
        }
    }

    /// The caller runs [`run`] itself (with its own transport; tests): the relay's serve loop
    /// still answers validations of the pending orders but starts no renewal task of its own.
    #[must_use]
    pub fn with_external_runner(mut self) -> Self {
        self.external_runner = true;
        self
    }

    /// Whether the caller runs [`run`] itself ([`Self::with_external_runner`]).
    pub fn has_external_runner(&self) -> bool {
        self.external_runner
    }

    /// With other waits in the client (tests).
    #[must_use]
    pub fn with_timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    /// The certificates.
    pub fn certs(&self) -> &RelayCertBook {
        &self.certs
    }

    /// The orders waiting for a validation connection.
    pub fn challenges(&self) -> &ChallengeBook {
        &self.challenges
    }

    /// The settings.
    pub fn config(&self) -> &AcmeConfig {
        &self.config
    }

    /// The order limiter.
    pub fn limiter(&self) -> &OrderLimiter {
        &self.limiter
    }
}

// ---------------------------------------------------------------------------------------------
// The limiter
// ---------------------------------------------------------------------------------------------

struct NameState {
    next_allowed: Instant,
    backoff: Duration,
}

#[derive(Default)]
struct LimiterInner {
    names: HashMap<String, NameState>,
    in_flight: HashSet<String>,
}

/// One order per name per [`ORDER_MIN_INTERVAL`] (a failure doubles the wait, up to
/// [`ORDER_BACKOFF_MAX`]; a success resets it), one order per name at a time, and at most
/// [`MAX_PENDING_ORDERS`] in flight.
#[derive(Default)]
pub struct OrderLimiter {
    inner: Mutex<LimiterInner>,
}

/// An order the limiter let start; it counts as in flight until this is dropped.
pub struct OrderPermit {
    limiter: Arc<OrderLimiter>,
    name: String,
}

impl OrderLimiter {
    fn lock(&self) -> std::sync::MutexGuard<'_, LimiterInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts an order for `name` if it may: none in flight for it, the least interval since
    /// its last start is over and fewer than [`MAX_PENDING_ORDERS`] orders are in flight.
    pub fn try_start(self: &Arc<Self>, name: &str) -> Option<OrderPermit> {
        let now = Instant::now();
        let mut inner = self.lock();
        if inner.in_flight.len() >= MAX_PENDING_ORDERS || inner.in_flight.contains(name) {
            return None;
        }
        let state = inner.names.entry(name.to_string()).or_insert(NameState {
            next_allowed: now,
            backoff: ORDER_MIN_INTERVAL,
        });
        if state.next_allowed > now {
            return None;
        }
        state.next_allowed = now + ORDER_MIN_INTERVAL;
        inner.in_flight.insert(name.to_string());
        Some(OrderPermit {
            limiter: Arc::clone(self),
            name: name.to_string(),
        })
    }

    /// How many orders are in flight.
    pub fn in_flight(&self) -> usize {
        self.lock().in_flight.len()
    }

    /// Forgets the names `keep` refuses (they are not served any more).
    pub fn retain(&self, keep: impl Fn(&str) -> bool) {
        self.lock().names.retain(|name, _| keep(name));
    }
}

impl OrderPermit {
    /// The order failed: the next one for this name waits twice as long as the last wait.
    pub fn failed(&self) {
        let now = Instant::now();
        let mut inner = self.limiter.lock();
        if let Some(state) = inner.names.get_mut(&self.name) {
            state.backoff = (state.backoff * 2).min(ORDER_BACKOFF_MAX);
            state.next_allowed = now + state.backoff;
        }
    }

    /// The order succeeded: the wait is back to the least interval.
    pub fn succeeded(&self) {
        let now = Instant::now();
        let mut inner = self.limiter.lock();
        if let Some(state) = inner.names.get_mut(&self.name) {
            state.backoff = ORDER_MIN_INTERVAL;
            state.next_allowed = now + ORDER_MIN_INTERVAL;
        }
    }
}

impl Drop for OrderPermit {
    fn drop(&mut self) {
        self.limiter.lock().in_flight.remove(&self.name);
    }
}

// ---------------------------------------------------------------------------------------------
// The names
// ---------------------------------------------------------------------------------------------

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The names a certificate is kept for now: the configured hosts, and the terminated names of
/// the relay's tenants (see the module docs), sorted, without duplicates. The terminated names
/// need a share domain (`zone`); without one only the hosts are wanted.
pub(crate) fn wanted_names(
    relay: &Relay,
    config: &AcmeConfig,
    zone: Option<&str>,
    now: u64,
) -> Vec<String> {
    let mut names: Vec<String> = config.hosts.clone();
    if let Some(zone) = zone {
        names.extend(terminated_names(relay, zone, now));
    }
    names.sort();
    names.dedup();
    names
}

/// `<name>.t.<zone>` for every accepted terminated share that may be served now.
fn terminated_names(relay: &Relay, zone: &str, now: u64) -> Vec<String> {
    let book = relay.tenants();
    relay
        .labels()
        .held_names(now)
        .into_iter()
        .filter_map(|(full, held)| {
            if held.share.mode != ShareMode::Terminated
                || held.share.service.kind != ServiceKind::Http
            {
                return None;
            }
            let label = full.split('.').next().unwrap_or(&full);
            // The same judgement as the front door's, made now: a grant the owner withdrew, a
            // holder that is gone or a network held back orders nothing.
            if !relay
                .rosters()
                .label_granted(&held.network, &held.node, label)
                || relay.attached_node(&held.node).is_none()
                || book.is_held_back(&held.network)
            {
                return None;
            }
            let tenant = book.tenant_of(&held.network);
            if !tenant.terminated || tenant.id.slug() != held.tenant.as_deref() {
                return None;
            }
            let name = format!("{full}.t.{zone}");
            check_domain(&name).ok()?;
            Some(name)
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// The renewal task
// ---------------------------------------------------------------------------------------------

/// Keeps a certificate for every wanted name, forever (the caller aborts the task): once per
/// `tick` it asks for the wanted names, loads what the store holds, forgets the certificates
/// of names no longer wanted and starts an order for each name that has none or is due, as far
/// as the limiter lets it. Orders run as tasks of this one; dropping it ends them.
pub async fn run<T>(relay: Relay, acme: RelayAcme, transport: T)
where
    T: AcmeTransport + Clone + 'static,
{
    let zone = relay
        .front_door_config()
        .map(|front| front.share_domain().to_string());
    let store = CertStore::new(&acme.config.dir);
    let account = match menzil_acme::AccountKey::load_or_create(&CertStore::account_key_path(
        &acme.config.dir,
    )) {
        Ok(account) => account.to_pem(),
        Err(error) => {
            tracing::warn!(%error, "ACME: the account key is unusable; the relay will not order certificates");
            return;
        }
    };
    let mut orders = tokio::task::JoinSet::new();
    loop {
        while orders.try_join_next().is_some() {}
        let names = wanted_names(&relay, &acme.config, zone.as_deref(), unix_now());
        acme.certs.retain(|name| names.iter().any(|n| n == name));
        acme.limiter.retain(|name| names.iter().any(|n| n == name));
        for name in &names {
            let validity = store.validity(name);
            if acme.certs.get(name).is_none() && validity.is_some() {
                load_stored(&store, &acme.certs, name);
            }
            let due = match validity {
                Some((not_before, not_after)) if unix_now() < not_after => {
                    unix_now() >= renewal_time(not_before, not_after, jitter_of(name))
                }
                _ => true,
            };
            if !due {
                continue;
            }
            // The permit goes with the order's task and is given back when that ends.
            let Some(permit) = acme.limiter.try_start(name) else {
                continue;
            };
            orders.spawn(order(
                relay.clone(),
                acme.clone(),
                transport.clone(),
                account.clone(),
                zone.clone(),
                name.clone(),
                permit,
            ));
        }
        tokio::time::sleep(acme.config.tick).await;
    }
}

/// A fixed fraction in `[0, 1)` of `name`, so that a name's renewal time does not move between
/// looks.
fn jitter_of(name: &str) -> f64 {
    let sum = name.bytes().fold(0u32, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(u32::from(b))
    });
    f64::from(sum % 1000) / 1000.0
}

fn load_stored(store: &CertStore, certs: &RelayCertBook, name: &str) {
    let Ok((chain, key)) = store.paths(name) else {
        return;
    };
    let (Ok(chain), Ok(key)) = (std::fs::read_to_string(chain), std::fs::read_to_string(key))
    else {
        return;
    };
    if let Err(error) = certs.install_pem(name, &chain, &key) {
        tracing::warn!(%name, %error, "ACME: the stored certificate is unusable");
    }
}

/// Asked again just before the CA is told to validate: whether `name` is still one the relay
/// wants a certificate for (an order whose share was withdrawn, or whose grant was, meanwhile
/// ends with [`AcmeError::NotWanted`] and nothing is made pending).
pub(crate) fn still_wanted(
    relay: &Relay,
    config: &Arc<AcmeConfig>,
    zone: Option<&str>,
    name: &str,
) -> impl Fn() -> bool + Send + Sync + 'static {
    let (relay, config, zone, name) = (
        relay.clone(),
        Arc::clone(config),
        zone.map(str::to_string),
        name.to_string(),
    );
    move || wanted_names(&relay, &config, zone.as_deref(), unix_now()).contains(&name)
}

/// One order for `name`.
async fn order<T>(
    relay: Relay,
    acme: RelayAcme,
    transport: T,
    account: String,
    zone: Option<String>,
    name: String,
    permit: OrderPermit,
) where
    T: AcmeTransport + Clone + 'static,
{
    let job = AcmeJob {
        share: name.clone(),
        domain: name.clone(),
    };
    let Ok(account) = menzil_acme::AccountKey::from_pem(&account) else {
        return;
    };
    let mut client = AcmeClient::new(
        transport,
        acme.config.directory_url.clone(),
        account,
        acme.config.contact.clone(),
    )
    .with_timing(acme.timing);
    let still_wanted = still_wanted(&relay, &acme.config, zone.as_deref(), &name);
    let outcome = client
        .obtain(&job.domain, &acme.challenges, &still_wanted)
        .await;
    let store = CertStore::new(&acme.config.dir);
    let saved = outcome.and_then(|issued| {
        store.save(&job.domain, &issued)?;
        acme.certs
            .install_pem(&job.domain, &issued.chain_pem, &issued.key_pem)?;
        Ok(issued)
    });
    match saved {
        Ok(issued) => {
            tracing::info!(domain = %job.domain, not_after = issued.not_after, "ACME: a certificate was issued");
            permit.succeeded();
        }
        Err(AcmeError::NotWanted) => {}
        Err(error) => {
            tracing::warn!(domain = %job.domain, %error, "ACME: no certificate was issued; retrying later");
            permit.failed();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The front door's half
// ---------------------------------------------------------------------------------------------

/// What [`answer_validation`] did with a connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Answered {
    /// Not a validation of a pending order: nothing was written, route it as usual.
    NotOurs,
    /// A validation: the challenge certificate was presented (or the attempt failed) and the
    /// connection is finished.
    Done,
}

/// Answers `tcp`, whose first `bytes` (a whole ClientHello for `sni`) were read already, if it
/// is a TLS-ALPN-01 validation of an order that is pending now: ALPN exactly `acme-tls/1` and
/// SNI exactly the pending name.
pub(crate) async fn answer_validation(
    acme: &RelayAcme,
    tcp: &mut TcpStream,
    bytes: &[u8],
    sni: &str,
) -> Answered {
    let mut replay = bytes;
    let Ok(Peeked {
        hello: Some(hello), ..
    }) = peek_client_hello(&mut replay).await
    else {
        return Answered::NotOurs;
    };
    if !is_validation_of(&hello, sni) {
        return Answered::NotOurs;
    }
    let Some(config) = acme.challenges.config_for(sni) else {
        return Answered::NotOurs;
    };
    let result = tokio::time::timeout(ANSWER_TIMEOUT, answer_challenge(tcp, hello, config)).await;
    if !matches!(result, Ok(Ok(()))) {
        tracing::debug!("a validation connection was not completed");
    }
    Answered::Done
}

/// Whether a ClientHello offering exactly `alpn` for `sni` may be a validation of a pending
/// order of `acme`: ALPN exactly `acme-tls/1`, and the SNI has an order pending now.
pub(crate) fn is_pending_validation(acme: &RelayAcme, sni: Option<&str>, alpn: &[Vec<u8>]) -> bool {
    matches!(alpn, [only] if only.as_slice() == ACME_ALPN.as_bytes())
        && sni.is_some_and(|sni| acme.challenges.is_pending(sni))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use menzil_acme::testing::{CA, FakeCa, Flags, acme_identifier, client_config, fast, sha256};
    use menzil_proto::ShareMode;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::front_door::tests::{H, OWN, World, ali, share, tests_unix_now, world};
    use crate::front_door::{FrontDoor, FrontDoorConfig, REFUSAL};
    use crate::relay::Accepting;
    use crate::tenant::TenantSpec;

    // ---- the certificate book ----

    fn pem_for(name: &str) -> (String, String) {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed([name.to_string()]).unwrap();
        (cert.pem(), signing_key.serialize_pem())
    }

    /// The leaf the server of `config` presents for `sni`, or `None` if the handshake fails.
    async fn presented(config: Arc<rustls::ServerConfig>, sni: &str) -> Option<Vec<u8>> {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let server = tokio::spawn(async move { acceptor.accept(server_io).await.is_ok() });
        let connector = TlsConnector::from(client_config(&[]));
        let name = ServerName::try_from(sni.to_string()).unwrap();
        let leaf = connector
            .connect(name, client_io)
            .await
            .ok()
            .map(|tls| tls.get_ref().1.peer_certificates().unwrap()[0].to_vec());
        let _ = server.await;
        leaf
    }

    #[tokio::test]
    async fn the_book_answers_a_name_with_its_own_certificate_and_no_other_name_with_it() {
        let book = RelayCertBook::new();
        let (chain, key) = pem_for("web.t.s.example.test");
        book.install_pem("web.t.s.example.test", &chain, &key)
            .unwrap();
        let config = book.server_config().unwrap();
        let own = book.get("web.t.s.example.test").unwrap().cert[0].to_vec();
        assert_eq!(
            presented(config.clone(), "web.t.s.example.test").await,
            Some(own.clone())
        );
        // No fallback: another name fails its handshake, it never gets this certificate.
        assert_eq!(
            presented(config.clone(), "other.t.s.example.test").await,
            None
        );
        // The operator's static certificate answers the names that have none of their own.
        let (fallback_chain, fallback_key) = pem_for(OWN);
        book.set_fallback_pem(&fallback_chain, &fallback_key)
            .unwrap();
        let fallback = presented(config.clone(), OWN).await.expect("fallback");
        assert_ne!(fallback, own);
        assert_eq!(
            presented(config.clone(), "web.t.s.example.test").await,
            Some(own)
        );
        // A name that is no longer served loses its own certificate.
        book.retain(|name| name != "web.t.s.example.test");
        assert_eq!(
            presented(config, "web.t.s.example.test").await,
            Some(fallback)
        );
    }

    #[test]
    fn a_bad_name_or_a_bad_pair_is_not_installed() {
        let book = RelayCertBook::new();
        let (chain, key) = pem_for("a.example.test");
        assert!(book.install_pem("A.Example.Test", &chain, &key).is_err());
        assert!(book.install_pem("*.example.test", &chain, &key).is_err());
        assert!(book.install_pem("a.example.test", "", &key).is_err());
        assert!(
            book.install_pem("a.example.test", &chain, "not a key")
                .is_err()
        );
        assert!(book.names().is_empty());
        book.install_pem("a.example.test", &chain, &key).unwrap();
        assert_eq!(book.names(), vec!["a.example.test".to_string()]);
    }

    #[test]
    fn a_directory_that_is_not_https_and_a_bad_host_are_refused() {
        assert!(AcmeConfig::new("http://ca.test/dir", "/tmp/x").is_err());
        assert!(AcmeConfig::new("ca.test/dir", "/tmp/x").is_err());
        let config = AcmeConfig::new("https://ca.test/dir", "/tmp/x").unwrap();
        assert!(config.clone().with_hosts(&["*.example.test"]).is_err());
        assert!(config.clone().with_hosts(&["a b"]).is_err());
        let ok = config
            .with_hosts(&["Relay.Example.Test", "relay.example.test"])
            .unwrap();
        assert_eq!(ok.hosts(), ["relay.example.test".to_string()]);
    }

    // ---- the limiter ----

    #[tokio::test(start_paused = true)]
    async fn one_order_per_name_per_minute() {
        let limiter = Arc::new(OrderLimiter::default());
        let permit = limiter.try_start("a.example.test").expect("first");
        permit.succeeded();
        // In flight: not twice.
        assert!(limiter.try_start("a.example.test").is_none());
        drop(permit);
        // Over, but within the minute.
        assert!(limiter.try_start("a.example.test").is_none());
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(limiter.try_start("a.example.test").is_none());
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(limiter.try_start("a.example.test").is_some());
        // Another name has its own clock.
        assert!(limiter.try_start("b.example.test").is_some());
        // An order that ended without a verdict (its name was no longer wanted) is spaced too.
        let permit = limiter.try_start("c.example.test").expect("first");
        drop(permit);
        assert!(limiter.try_start("c.example.test").is_none());
        tokio::time::advance(ORDER_MIN_INTERVAL + Duration::from_secs(1)).await;
        assert!(limiter.try_start("c.example.test").is_some());
    }

    #[tokio::test]
    async fn only_an_exact_acme_alpn_for_a_pending_name_is_a_validation() {
        let acme = acme_for(std::path::Path::new("/nonexistent"), &[OWN]);
        let name = format!("web.ali.t.{H}");
        let exact = vec![b"acme-tls/1".to_vec()];
        assert!(
            !is_pending_validation(&acme, Some(&name), &exact),
            "no order"
        );
        let _order = acme.challenges().begin(&name, "tok.thumb").unwrap();
        assert!(is_pending_validation(&acme, Some(&name), &exact));
        assert!(
            !is_pending_validation(&acme, Some(OWN), &exact),
            "another name"
        );
        assert!(!is_pending_validation(&acme, None, &exact), "no SNI");
        assert!(!is_pending_validation(&acme, Some(&name), &[]));
        assert!(!is_pending_validation(
            &acme,
            Some(&name),
            &[b"h2".to_vec()]
        ));
        let both = vec![b"h2".to_vec(), b"acme-tls/1".to_vec()];
        assert!(!is_pending_validation(&acme, Some(&name), &both));
        let twice = vec![b"acme-tls/1".to_vec(), b"acme-tls/1".to_vec()];
        assert!(!is_pending_validation(&acme, Some(&name), &twice));
    }

    #[tokio::test(start_paused = true)]
    async fn failures_double_the_wait_up_to_an_hour_and_a_success_resets_it() {
        let limiter = Arc::new(OrderLimiter::default());
        let name = "a.example.test";
        let mut wait = ORDER_MIN_INTERVAL;
        for _ in 0..10 {
            let permit = limiter.try_start(name).expect("due");
            permit.failed();
            drop(permit);
            wait = (wait * 2).min(ORDER_BACKOFF_MAX);
            tokio::time::advance(wait - Duration::from_secs(1)).await;
            assert!(limiter.try_start(name).is_none(), "not before {wait:?}");
            tokio::time::advance(Duration::from_secs(2)).await;
        }
        assert_eq!(wait, ORDER_BACKOFF_MAX);
        // A success: the next one is a minute away, not an hour.
        let permit = limiter.try_start(name).expect("due");
        permit.succeeded();
        drop(permit);
        tokio::time::advance(ORDER_MIN_INTERVAL + Duration::from_secs(1)).await;
        assert!(limiter.try_start(name).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_sixteen_orders_are_in_flight_and_a_finished_one_gives_its_place_back() {
        let limiter = Arc::new(OrderLimiter::default());
        let mut permits = Vec::new();
        for i in 0..MAX_PENDING_ORDERS {
            permits.push(
                limiter
                    .try_start(&format!("n{i}.example.test"))
                    .expect("room"),
            );
        }
        assert_eq!(MAX_PENDING_ORDERS, 16);
        assert_eq!(limiter.in_flight(), 16);
        assert!(limiter.try_start("one-more.example.test").is_none());
        permits.pop();
        assert_eq!(limiter.in_flight(), 15);
        assert!(limiter.try_start("one-more.example.test").is_some());
    }

    // ---- which names are ordered ----

    fn terminated_ali() -> TenantSpec {
        let mut spec = ali(&[]);
        spec.terminated = true;
        spec
    }

    fn acme_for(dir: &std::path::Path, hosts: &[&str]) -> RelayAcme {
        let config = AcmeConfig::new(&format!("{CA}/dir"), dir)
            .unwrap()
            .with_contact("mailto:ops@example.org")
            .with_hosts(hosts)
            .unwrap()
            .with_tick(Duration::from_millis(20));
        RelayAcme::new(config).with_timing(fast())
    }

    fn relay_with(w: &World, acme: &RelayAcme) -> Relay {
        w.relay
            .clone()
            .with_front_door(FrontDoorConfig::new(OWN, H).unwrap())
            .with_acme(acme.clone())
    }

    fn names(w: &World, hosts: &[&str]) -> Vec<String> {
        let acme = acme_for(std::path::Path::new("/nonexistent"), hosts);
        wanted_names(&w.relay, &acme.config, Some(H), tests_unix_now())
    }

    #[tokio::test]
    async fn the_hosts_and_the_accepted_terminated_shares_of_a_flagged_tenant_are_wanted() {
        let w = world(&["web", "app", "plain"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![
            share("web", ShareMode::Terminated, "http:web", &[]),
            share("app", ShareMode::Blind, "tls:app", &["acme-tls/1"]),
            share("plain", ShareMode::Blind, "tcp:plain", &[]),
        ]);
        assert_eq!(
            names(&w, &[OWN]),
            vec![OWN.to_string(), format!("web.ali.t.{H}")]
        );
        assert_eq!(names(&w, &[]), vec![format!("web.ali.t.{H}")]);
        // Without a share domain only the hosts are wanted.
        let acme = acme_for(std::path::Path::new("/nonexistent"), &[OWN]);
        assert_eq!(
            wanted_names(&w.relay, &acme.config, None, tests_unix_now()),
            vec![OWN.to_string()]
        );
    }

    #[tokio::test]
    async fn a_terminated_share_of_an_unflagged_tenant_or_the_default_tenant_is_not_wanted() {
        let unflagged = world(&["web"], Some(ali(&[])));
        unflagged.attach();
        unflagged.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        assert!(names(&unflagged, &[]).is_empty());
        let default = world(&["web"], None);
        default.attach();
        default.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        assert!(names(&default, &[]).is_empty());
    }

    #[tokio::test]
    async fn a_terminated_name_is_wanted_only_while_it_is_held_granted_and_its_node_attached() {
        let w = world(&["web"], Some(terminated_ali()));
        let wanted = format!("web.ali.t.{H}");
        // Nothing advertised, nobody attached.
        assert!(names(&w, &[]).is_empty());
        w.attach();
        w.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        assert_eq!(names(&w, &[]), vec![wanted.clone()]);
        // The grant withdrawn by the owner's next Roster.
        w.roster(2, &[w.node], &[]);
        assert!(names(&w, &[]).is_empty(), "no grant");
        w.roster(3, &[w.node], &[("web", w.node)]);
        assert_eq!(names(&w, &[]), vec![wanted.clone()]);
        // The claim gone, then the share withdrawn.
        w.relay.labels().clear_for(&w.node, tests_unix_now());
        assert!(names(&w, &[]).is_empty(), "unheld");
        w.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        assert_eq!(names(&w, &[]), vec![wanted]);
        w.advertise(vec![]);
        assert!(names(&w, &[]).is_empty(), "withdrawn");
        w.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        // Detached.
        assert!(w.relay.registry.detach(&w.node, 1));
        assert!(names(&w, &[]).is_empty(), "detached");
    }

    #[tokio::test]
    async fn an_order_is_asked_again_whether_its_name_is_still_wanted() {
        let w = world(&["web"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        let acme = acme_for(std::path::Path::new("/nonexistent"), &[]);
        let wanted = format!("web.ali.t.{H}");
        let check = still_wanted(&w.relay, &acme.config, Some(H), &wanted);
        let other = still_wanted(&w.relay, &acme.config, Some(H), &format!("other.t.{H}"));
        assert!(check());
        assert!(!other(), "a name nobody holds is never wanted");
        w.advertise(vec![]);
        assert!(!check(), "withdrawn since the order began");
    }

    // ---- the renewal task against an in process CA ----

    async fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
        for _ in 0..500 {
            if ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for {what}");
    }

    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "menzil-relay-acme-test-{}-{}",
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

    #[tokio::test]
    async fn the_relay_obtains_and_stores_a_certificate_for_its_own_host() {
        let scratch = Scratch::new();
        let w = world(&["app"], None);
        let acme = acme_for(&scratch.0, &[OWN]);
        let relay = relay_with(&w, &acme);
        let ca = FakeCa::new(acme.challenges(), Flags::default());
        let task = tokio::spawn(run(relay, acme.clone(), ca.clone()));
        wait_for("the certificate of the host", || {
            acme.certs().get(OWN).is_some()
        })
        .await;
        assert_eq!(ca.state().domain, OWN);
        let (chain, key) = CertStore::new(&scratch.0).paths(OWN).unwrap();
        assert!(chain.exists() && key.exists(), "kept on disk");
        assert!(
            scratch.0.join("acme").join("account.key").exists(),
            "the account key is kept"
        );
        // The order ended: the name is not answered any more.
        wait_for("the order to end", || acme.challenges().is_empty()).await;
        task.abort();
    }

    #[tokio::test]
    async fn a_terminated_name_is_ordered_and_a_blind_share_is_never() {
        let scratch = Scratch::new();
        let w = world(&["web", "app"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![
            share("web", ShareMode::Terminated, "http:web", &[]),
            share("app", ShareMode::Blind, "tls:app", &["acme-tls/1"]),
        ]);
        let acme = acme_for(&scratch.0, &[]);
        let relay = relay_with(&w, &acme);
        let ca = FakeCa::new(acme.challenges(), Flags::default());
        let task = tokio::spawn(run(relay, acme.clone(), ca.clone()));
        let wanted = format!("web.ali.t.{H}");
        wait_for("the certificate of the terminated name", || {
            acme.certs().get(&wanted).is_some()
        })
        .await;
        assert_eq!(ca.state().domain, wanted);
        // Let several more ticks pass: nothing else is ordered.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(acme.certs().names(), vec![wanted.clone()]);
        assert_eq!(
            ca.state()
                .log
                .iter()
                .filter(|r| *r == "Post /order")
                .count(),
            1
        );
        // The share withdrawn: the certificate goes out of the book.
        w.advertise(vec![]);
        wait_for("the certificate to go", || acme.certs().names().is_empty()).await;
        task.abort();
    }

    #[tokio::test]
    async fn nothing_is_ordered_for_a_name_no_share_accepted() {
        let scratch = Scratch::new();
        // A blind share, an unflagged tenant's terminated share, an unattached holder: no host
        // configured, so no name is wanted and the CA is never spoken to.
        let w = world(&["web", "app"], Some(ali(&[])));
        w.advertise(vec![]);
        w.attach();
        w.advertise(vec![
            share("web", ShareMode::Terminated, "http:web", &[]),
            share("app", ShareMode::Blind, "tls:app", &["acme-tls/1"]),
        ]);
        let acme = acme_for(&scratch.0, &[]);
        let relay = relay_with(&w, &acme);
        let ca = FakeCa::new(acme.challenges(), Flags::default());
        let task = tokio::spawn(run(relay, acme.clone(), ca.clone()));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(ca.state().log.is_empty(), "{:?}", ca.state().log);
        assert!(acme.certs().names().is_empty());
        assert!(acme.challenges().is_empty());
        task.abort();
    }

    #[tokio::test]
    async fn a_failing_ca_is_asked_once_a_minute_at_most() {
        let scratch = Scratch::new();
        let w = world(&["app"], None);
        let acme = acme_for(&scratch.0, &[OWN]);
        let relay = relay_with(&w, &acme);
        let ca = FakeCa::new(
            acme.challenges(),
            Flags {
                refuse_account: true,
                ..Flags::default()
            },
        );
        let task = tokio::spawn(run(relay, acme.clone(), ca.clone()));
        tokio::time::sleep(Duration::from_millis(500)).await;
        let accounts = ca.state().log.iter().filter(|r| *r == "Post /acct").count();
        assert_eq!(accounts, 1, "{:?}", ca.state().log);
        assert!(acme.certs().get(OWN).is_none());
        task.abort();
    }

    // ---- the front door answers validations of its own orders ----

    /// The bytes of a ClientHello for `sni` offering `alpn`.
    fn hello_bytes(sni: &str, alpn: &[&str]) -> Vec<u8> {
        let name = ServerName::try_from(sni.to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(client_config(alpn), name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    struct Door {
        relay: Relay,
        acme: RelayAcme,
        door: Arc<FrontDoor>,
        listener: TcpListener,
        accepting: Arc<Accepting>,
    }

    async fn door(with_acme: bool) -> Door {
        let w = world(&["app"], None);
        let acme = acme_for(std::path::Path::new("/nonexistent"), &[OWN]);
        let relay = if with_acme {
            relay_with(&w, &acme)
        } else {
            w.relay
                .clone()
                .with_front_door(FrontDoorConfig::new(OWN, H).unwrap())
        };
        let door = FrontDoor::new(&relay, FrontDoorConfig::new(OWN, H).unwrap());
        let (chain, key) = crate::tests_support::self_signed_cert("localhost");
        let own = crate::listener::Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            crate::server_config(chain, key).unwrap(),
            "/",
        )
        .await
        .unwrap();
        let accepting = Arc::new(Accepting {
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
            upgrader: own.upgrader(),
            timeout: Duration::from_secs(5),
        });
        Door {
            relay,
            acme,
            door,
            listener: TcpListener::bind("127.0.0.1:0").await.unwrap(),
            accepting,
        }
    }

    impl Door {
        /// Connects, sends `hello` raw and lets the front door handle the connection; returns
        /// everything the client got back until the connection closed.
        async fn exchange(&self, hello: &[u8]) -> Vec<u8> {
            let addr = self.listener.local_addr().unwrap();
            let mut client = TcpStream::connect(addr).await.unwrap();
            let (tcp, peer) = self.listener.accept().await.unwrap();
            let slot = self.relay.admission.admit_connection(peer.ip()).unwrap();
            let peek = self.door.try_peek().unwrap();
            let handled = tokio::spawn(Arc::clone(&self.door).handle_tls(
                self.relay.clone(),
                Arc::clone(&self.accepting),
                tcp,
                peer,
                slot,
                peek,
            ));
            client.write_all(hello).await.unwrap();
            let mut got = Vec::new();
            let mut chunk = [0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    match client.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&chunk[..n]),
                    }
                }
            })
            .await;
            drop(client);
            let _ = tokio::time::timeout(Duration::from_secs(5), handled).await;
            got
        }

        /// A full TLS-ALPN-01 style validation of `sni`: the leaf the front door presents.
        async fn validate(&self, sni: &str, alpn: &[&str]) -> Option<Vec<u8>> {
            let addr = self.listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            let (tcp, peer) = self.listener.accept().await.unwrap();
            let slot = self.relay.admission.admit_connection(peer.ip()).unwrap();
            let peek = self.door.try_peek().unwrap();
            let handled = tokio::spawn(Arc::clone(&self.door).handle_tls(
                self.relay.clone(),
                Arc::clone(&self.accepting),
                tcp,
                peer,
                slot,
                peek,
            ));
            let connector = TlsConnector::from(client_config(alpn));
            let name = ServerName::try_from(sni.to_string()).unwrap();
            let leaf =
                tokio::time::timeout(Duration::from_secs(5), connector.connect(name, client))
                    .await
                    .ok()?
                    .ok()
                    .map(|tls| tls.get_ref().1.peer_certificates().unwrap()[0].to_vec());
            let _ = tokio::time::timeout(Duration::from_secs(5), handled).await;
            leaf
        }
    }

    #[tokio::test]
    async fn a_validation_of_a_pending_order_gets_the_challenge_certificate() {
        let d = door(true).await;
        for name in [OWN.to_string(), format!("web.ali.t.{H}")] {
            let order = d.acme.challenges().begin(&name, "tok.thumb").unwrap();
            let leaf = d
                .validate(&name, &["acme-tls/1"])
                .await
                .expect("the challenge certificate");
            let (critical, value) = acme_identifier(&leaf).expect("acmeIdentifier");
            assert!(critical);
            assert_eq!(&value[2..], sha256(b"tok.thumb").as_slice());
            drop(order);
        }
    }

    #[tokio::test]
    async fn every_other_hello_gets_the_same_seven_bytes_as_before() {
        let d = door(true).await;
        let name = format!("web.ali.t.{H}");
        // No order: the name routes to nothing.
        assert_eq!(
            d.exchange(&hello_bytes(&name, &["acme-tls/1"])).await,
            REFUSAL
        );
        // An order for another name does not answer this one.
        let _other = d
            .acme
            .challenges()
            .begin(&format!("other.t.{H}"), "t.t")
            .unwrap();
        assert_eq!(
            d.exchange(&hello_bytes(&name, &["acme-tls/1"])).await,
            REFUSAL
        );
        // An order for this name, but the ALPN list is not exactly acme-tls/1.
        let order = d.acme.challenges().begin(&name, "tok.thumb").unwrap();
        assert_eq!(
            d.exchange(&hello_bytes(&name, &["h2", "acme-tls/1"])).await,
            REFUSAL
        );
        assert_eq!(d.exchange(&hello_bytes(&name, &["h2"])).await, REFUSAL);
        assert_eq!(d.exchange(&hello_bytes(&name, &[])).await, REFUSAL);
        // The order ended: refused again.
        drop(order);
        assert_eq!(
            d.exchange(&hello_bytes(&name, &["acme-tls/1"])).await,
            REFUSAL
        );
        // Not a ClientHello at all.
        assert_eq!(d.exchange(b"GET / HTTP/1.1\r\n\r\n").await, REFUSAL);
    }

    #[tokio::test]
    async fn a_relay_without_acme_answers_no_validation() {
        let d = door(false).await;
        assert!(d.relay.acme().is_none());
        let name = format!("web.ali.t.{H}");
        // The book of a relay that has no ACME is not the front door's: a pending order in
        // another relay's book changes nothing here.
        let _order = d.acme.challenges().begin(&name, "tok.thumb").unwrap();
        assert_eq!(
            d.exchange(&hello_bytes(&name, &["acme-tls/1"])).await,
            REFUSAL
        );
    }
}
