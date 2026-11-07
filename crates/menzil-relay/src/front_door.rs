//! The blind front door of the relay's TLS port (protocol.md 6.2 to 6.4, expose design slice
//! S-E6): public connections for share names, routed to the node that holds the name without
//! terminating their TLS.
//!
//! # What it does
//!
//! With a share domain `H` configured ([`FrontDoorConfig`], `Relay::with_front_door`), every
//! connection on the TLS port first has its ClientHello read (`crate::sni`: up to 16 KiB, 10 s,
//! at most 1,024 at once; over the cap or past the deadline the connection is dropped without an
//! answer) and is then handled by what the SNI says:
//!
//! * SNI equal to the relay's own host name: the existing TLS and WebSocket path, with the bytes
//!   read replayed (`crate::prefixed`), unchanged otherwise.
//! * `<label>.H` or `<label>.<slug>.H` that a node holds now, whose share is blind with a `tls:`
//!   or `tcp:` service (decision E5: `tcp:` shares are reached by SNI too), and whose ClientHello
//!   does not offer ALPN `acme-tls/1` unless the share listed it: the relay principal
//!   (`crate::principal`) opens the share's service on that node with `meta{client_ip, sni}` and
//!   the raw bytes, ClientHello included, are piped both ways.
//! * `<label>.t.H` or `<label>.<slug>.t.H` (the terminated zone, never mixed with the blind one)
//!   of an accepted `http:` share of a tenant with the `terminated` flag, held by an attached
//!   node under a grant the Roster still gives, whose network is not held back, and for which the
//!   relay's ACME holds a certificate for exactly that name (`crate::acme`; the book's fallback
//!   never answers a share name): the relay terminates TLS and `crate::http_term` serves the
//!   HTTP, one `http:<label>` stream per client connection. A precondition that is missing is
//!   the one refusal below, like any other failure.
//! * anything else: the one static refusal below.
//!
//! A hello with ALPN exactly `acme-tls/1` and an SNI that has an order pending in the relay's own
//! ACME (`crate::acme`) is answered with the challenge certificate before any of the above; the
//! refusals below are unchanged.
//!
//! Without a share domain the relay does none of this: no byte is read before TLS, and every
//! connection takes the existing path as before.
//!
//! # One refusal for every failure
//!
//! An unknown name, a name nobody holds, a quarantined name, a holder that is not attached, no
//! SNI, an SNI that is not a hostname, bytes that are not a ClientHello, a share that is not
//! blind or not `tls:`/`tcp:`, an `acme-tls/1` hello for a share that did not list it, a
//! connection over a name's or a tenant's share figure, over the relay-wide share cap, and every
//! error of the principal (its own caps, a handshake the node did not answer, a refused OPEN)
//! get the same bytes, [`REFUSAL`]: one fatal TLS alert record, `unrecognized_name`, and then the
//! connection is closed. No condition changes a byte of it, and which one applied is not logged
//! above debug level.
//!
//! The protocol says "the operator's static site". A static site needs a certificate valid for
//! the name asked, and this relay has none for share names (terminated shares and ACME are later
//! slices; a relay never holds a certificate that covers a blind name, 6.2). The relay's own
//! certificate would present a name mismatch, so a client could read no page anyway, and serving
//! one costs a full TLS handshake per probe. A fixed alert is the answer a TLS server gives for
//! a name it does not serve (RFC 6066 4), it is seven bytes, it costs nothing to send, and it is
//! the same for every cause. The static site is the later slice's.
//!
//! Timing: a failure is answered no sooner than [`FrontDoorConfig::failure_delay`] after the
//! relay decided it (250 ms), so that the quick refusals (a lookup in memory) do not stand out
//! from one another or from a refusal that took one network round trip to the node. What it does
//! not hide is a refusal that took long: a principal handshake the node never answers takes up
//! to its 10 s timeout, and that is visible to a prober as "this name is held and the node is
//! attached but silent". The delay is bounded to a count of connections
//! ([`FrontDoorConfig::max_answers`]); over it a failing connection is closed at once.
//!
//! # Counters
//!
//! A public connection to a share counts against its name, its tenant and the relay in all, from
//! the decision to route it until both ends are gone, on every path (a guard releases on drop).
//! Defaults are protocol.md 10's: 64 per name and 256 per tenant, the tenant figures
//! `share_connections_per_name` and `share_connections` where the tenant has figures, the
//! front door's own defaults where it has none (the default tenant, the `personal` class), and
//! [`FRONT_DOOR_MAX_TOTAL`] in all. Beneath them the principal's own bounds apply (64 streams per
//! session, 1,024 per tenant, 256 sessions per tenant): an error there is a refusal like any
//! other.
//!
//! # Port 80
//!
//! `Relay::serve_with_http` also serves plain HTTP on a listener the operator gives it (off
//! unless given): `GET /.well-known/acme-challenge/...` for a name that routes as above is
//! opened as `acme-http:<label>` on the holder; every other request whose `Host` is under `H` (or
//! is the relay's own host) is answered `301` to `https://<host><path>`, whether or not the name
//! exists. A challenge that cannot be served (no such name, a node that refuses `acme-http:`, as
//! every node does until it can serve it) and a request for a host outside `H` get one fixed
//! `404` ([`HTTP_REFUSAL`]) after the same delay.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use menzil_proto::{OpenMeta, ServiceId, ServiceKind, ShareMode};
use menzil_stream::Stream;
use rustls::server::{ClientHello as TlsClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional_with_sizes,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::acme::{self, RelayCertBook};
use crate::admission::{IpSlot, PeerKey};
use crate::advertise::HeldName;
use crate::http_term::{self, HttpLimits};
use crate::prefixed::PrefixedTcp;
use crate::principal::Principal;
use crate::relay::{Accepting, Relay};
use crate::sni::{self, ClientHello, MAX_PEEKS, PEEK_DEADLINE, Peeked, normalize_host};
use crate::tenant::TenantId;

/// The bytes every refused connection on the TLS port gets: a TLS record (type 21 alert, legacy
/// version 3.3, two bytes long) holding a fatal (2) `unrecognized_name` (112) alert.
pub(crate) const REFUSAL: [u8; 7] = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70];

/// The bytes every refused request on port 80 that is not redirected gets.
pub(crate) const HTTP_REFUSAL: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// The ALPN protocol id of TLS-ALPN-01 (RFC 8737), the one the relay decides on.
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";

/// The path prefix of HTTP-01 challenges (RFC 8555 8.3).
const ACME_PATH: &str = "/.well-known/acme-challenge/";

/// How long a refusal waits, from the decision, before it is sent.
pub const FRONT_DOOR_FAILURE_DELAY: Duration = Duration::from_millis(250);
/// Refusals that may be waiting or being sent at once.
pub const FRONT_DOOR_MAX_ANSWERS: usize = 1_024;
/// A piped connection with no byte moved in either direction this long is ended.
pub const FRONT_DOOR_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// Public connections to one name at once, for a tenant without figures (protocol.md 10).
pub const FRONT_DOOR_PER_NAME: usize = 64;
/// Public connections to one tenant's shares at once, for a tenant without figures.
pub const FRONT_DOOR_PER_TENANT: usize = 256;
/// Public share connections at once in all. About 290 KiB of buffers on the relay for each when
/// nobody reads (the principal's measurement), so the default is about 1.2 GiB at the worst.
pub const FRONT_DOOR_MAX_TOTAL: usize = 4_096;

/// Public connections one client (an IPv4 address or an IPv6 /64) may hold to one name at once.
pub const FRONT_DOOR_PER_CLIENT_PER_NAME: usize = 8;
/// Public share connections one client may hold at once in all, whatever the names.
pub const FRONT_DOOR_PER_CLIENT: usize = 32;
/// How many clients' worth of [`FRONT_DOOR_PER_CLIENT`] one IPv6 /48 may hold at once (a /48
/// holds 65,536 /64s, each a client of its own above, so a /48 needs a figure of its own).
pub const FRONT_DOOR_V6_48_FACTOR: usize = 4;
/// A piped connection that has not had a byte from the node is ended after this long, as a whole
/// and as silence (the node answers a ClientHello at once; a connection nothing answers is held
/// for nothing).
pub const FRONT_DOOR_FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the refusal's bytes may take to be accepted by the peer's socket.
const REFUSAL_WRITE: Duration = Duration::from_secs(1);
/// How long a refused peer's remaining bytes are read and discarded after the refusal, so that
/// closing does not reset the connection before the peer has read the alert.
const REFUSAL_DRAIN: Duration = Duration::from_millis(500);
/// The size of each direction's copy buffer.
const PIPE_BUFFER: usize = 16 * 1024;
/// The most bytes of an HTTP request head read on port 80.
const HTTP_HEAD_LIMIT: usize = 8 * 1024;

/// The front door's settings. [`FrontDoorConfig::new`] gives the protocol's figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontDoorConfig {
    own_host: String,
    share_domain: String,
    /// How long a peer has to deliver its whole ClientHello.
    pub peek_deadline: Duration,
    /// How many connections may be reading a ClientHello at once.
    pub max_peeks: usize,
    /// The least time between deciding a refusal and sending it.
    pub failure_delay: Duration,
    /// How many refusals may wait or be sent at once.
    pub max_answers: usize,
    /// How long a piped connection may be silent.
    pub idle_timeout: Duration,
    /// Connections to one name at once for a tenant without share figures.
    pub per_name: usize,
    /// Connections to one tenant's shares at once for a tenant without share figures.
    pub per_tenant: usize,
    /// Connections to shares at once in all.
    pub max_total: usize,
    /// Connections one client (an IPv4 address, an IPv6 /64) may hold to one name at once.
    pub per_client_per_name: usize,
    /// Connections one client may hold to shares at once in all.
    pub per_client: usize,
    /// Connections one IPv6 /48 may hold to shares at once in all.
    pub per_v6_48: usize,
    /// The longest a piped connection may live, or be silent, before the node sent a byte.
    pub first_byte_timeout: Duration,
    /// The terminated shares' HTTP terminator's time limits.
    http: HttpLimits,
}

/// A host name or share domain that is not a plain ASCII DNS name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "{what} {name:?} is not a plain ASCII DNS name (letters, digits and hyphens in dot separated labels, no trailing dot)"
)]
pub struct FrontDoorConfigError {
    what: &'static str,
    name: String,
}

impl FrontDoorConfig {
    /// A front door for the relay whose own host name is `own_host` (the name its nodes dial
    /// and its certificate covers) serving the share domain `share_domain` (`H`). Both are
    /// lowercased. The two may not be equal, and the host name may not lie under `H`.
    pub fn new(own_host: &str, share_domain: &str) -> Result<Self, FrontDoorConfigError> {
        let own = normalize_host(own_host.as_bytes()).ok_or_else(|| FrontDoorConfigError {
            what: "the relay's host name",
            name: own_host.to_string(),
        })?;
        let share =
            normalize_host(share_domain.as_bytes()).ok_or_else(|| FrontDoorConfigError {
                what: "the share domain",
                name: share_domain.to_string(),
            })?;
        if own == share {
            return Err(FrontDoorConfigError {
                what: "the share domain, equal to the relay's host name,",
                name: share_domain.to_string(),
            });
        }
        if own.ends_with(&format!(".{share}")) {
            // The relay's own name inside the share domain could be claimed as a share label by a
            // member (and its port 80 challenges would go to that member): not a setup to start
            // (expose round 2, L1).
            return Err(FrontDoorConfigError {
                what: "the relay's host name, under the share domain,",
                name: own_host.to_string(),
            });
        }
        Ok(Self {
            own_host: own,
            share_domain: share,
            peek_deadline: PEEK_DEADLINE,
            max_peeks: MAX_PEEKS,
            failure_delay: FRONT_DOOR_FAILURE_DELAY,
            max_answers: FRONT_DOOR_MAX_ANSWERS,
            idle_timeout: FRONT_DOOR_IDLE_TIMEOUT,
            per_name: FRONT_DOOR_PER_NAME,
            per_tenant: FRONT_DOOR_PER_TENANT,
            max_total: FRONT_DOOR_MAX_TOTAL,
            per_client_per_name: FRONT_DOOR_PER_CLIENT_PER_NAME,
            per_client: FRONT_DOOR_PER_CLIENT,
            per_v6_48: FRONT_DOOR_PER_CLIENT * FRONT_DOOR_V6_48_FACTOR,
            first_byte_timeout: FRONT_DOOR_FIRST_BYTE_TIMEOUT,
            http: HttpLimits::default(),
        })
    }

    /// The most file descriptors the front door's unauthenticated and piped work can hold at
    /// once: connections reading a ClientHello (`max_peeks`), the same on port 80 if it is
    /// served (`http`), refusals in flight (`max_answers`) and piped share connections
    /// (`max_total`). A relay whose `RLIMIT_NOFILE` is below this accepts nothing further when
    /// the figures are reached (`accept` fails with `EMFILE`), members' reconnects included.
    pub fn fd_budget(&self, http: bool) -> usize {
        let peeks = self.max_peeks.saturating_mul(if http { 2 } else { 1 });
        peeks
            .saturating_add(self.max_answers)
            .saturating_add(self.max_total)
    }

    /// The relay's own host name, lowercase.
    pub fn own_host(&self) -> &str {
        &self.own_host
    }

    /// The share domain `H`, lowercase.
    pub fn share_domain(&self) -> &str {
        &self.share_domain
    }

    /// With `deadline` for the ClientHello.
    #[must_use]
    pub fn with_peek_deadline(mut self, deadline: Duration) -> Self {
        self.peek_deadline = deadline;
        self
    }

    /// With `max` concurrent ClientHello reads.
    #[must_use]
    pub fn with_max_peeks(mut self, max: usize) -> Self {
        self.max_peeks = max;
        self
    }

    /// With `delay` as the least time before a refusal is sent.
    #[must_use]
    pub fn with_failure_delay(mut self, delay: Duration) -> Self {
        self.failure_delay = delay;
        self
    }

    /// With `max` refusals in flight.
    #[must_use]
    pub fn with_max_answers(mut self, max: usize) -> Self {
        self.max_answers = max;
        self
    }

    /// With `idle` as the longest a piped connection may be silent.
    #[must_use]
    pub fn with_idle_timeout(mut self, idle: Duration) -> Self {
        self.idle_timeout = idle;
        self
    }

    /// With `per_name` and `per_tenant` as the share connection figures of a tenant that has no
    /// figures of its own.
    #[must_use]
    pub fn with_share_connections(mut self, per_name: usize, per_tenant: usize) -> Self {
        self.per_name = per_name;
        self.per_tenant = per_tenant;
        self
    }

    /// With `max` share connections in all.
    #[must_use]
    pub fn with_max_total(mut self, max: usize) -> Self {
        self.max_total = max;
        self
    }

    /// With `per_name` connections of one client to one name, `per_client` of one client in all
    /// and `per_v6_48` of one IPv6 /48 in all (a client is an IPv4 address or an IPv6 /64).
    #[must_use]
    pub fn with_client_figures(
        mut self,
        per_name: usize,
        per_client: usize,
        per_v6_48: usize,
    ) -> Self {
        self.per_client_per_name = per_name;
        self.per_client = per_client;
        self.per_v6_48 = per_v6_48;
        self
    }

    /// With `timeout` as the longest a piped connection may live, or be silent, until the node
    /// has sent a byte.
    #[must_use]
    pub fn with_first_byte_timeout(mut self, timeout: Duration) -> Self {
        self.first_byte_timeout = timeout;
        self
    }

    /// With `limits` as the time limits of the terminated shares' HTTP terminator (tests).
    #[must_use]
    #[cfg(test)]
    pub(crate) fn with_http_limits(mut self, limits: HttpLimits) -> Self {
        self.http = limits;
        self
    }
}

// ---------------------------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Counts {
    per_name: HashMap<String, usize>,
    per_tenant: HashMap<TenantId, usize>,
    total: usize,
    /// Per client and name, per client, and per IPv6 /48 (expose round 2, M2).
    per_client_name: HashMap<(PeerKey, String), usize>,
    per_client: HashMap<PeerKey, usize>,
    per_v6_48: HashMap<[u8; 6], usize>,
}

/// One more of `key` in `map`.
fn bump<K: std::hash::Hash + Eq>(map: &mut HashMap<K, usize>, key: K) {
    *map.entry(key).or_insert(0) += 1;
}

/// One less of `key` in `map`; the entry goes with its last.
fn lower<K: std::hash::Hash + Eq>(map: &mut HashMap<K, usize>, key: &K) {
    if let Some(n) = map.get_mut(key) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            map.remove(key);
        }
    }
}

/// The live public share connections per name, per tenant and in all.
#[derive(Default)]
pub(crate) struct ShareCounters {
    counts: Mutex<Counts>,
}

/// One share connection counted by [`ShareCounters::try_acquire`]; dropping it gives the place
/// back, whichever way the connection ended.
pub(crate) struct ShareSlot {
    counters: Arc<ShareCounters>,
    name: String,
    tenant: TenantId,
    client: PeerKey,
}

/// The figures one acquisition is held to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShareLimits {
    pub(crate) per_name: usize,
    pub(crate) per_tenant: usize,
    pub(crate) total: usize,
    /// One client (see [`PeerKey`]) to one name, and to all names.
    pub(crate) per_client_name: usize,
    pub(crate) per_client: usize,
    /// One IPv6 /48 to all names.
    pub(crate) per_v6_48: usize,
}

impl ShareCounters {
    fn lock(&self) -> MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes a place for a connection to `name` of `tenant` from `client`, unless the name, the
    /// tenant, the relay, the client (to this name or in all) or the client's IPv6 /48 is at its
    /// figure.
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
        name: &str,
        tenant: &TenantId,
        client: PeerKey,
        limits: ShareLimits,
    ) -> Option<ShareSlot> {
        let mut counts = self.lock();
        let of_client_name = counts
            .per_client_name
            .get(&(client, name.to_string()))
            .copied()
            .unwrap_or(0);
        let of_v6_48 = client.prefix48().map_or(0, |prefix| {
            counts.per_v6_48.get(&prefix).copied().unwrap_or(0)
        });
        if counts.total >= limits.total
            || counts.per_name.get(name).copied().unwrap_or(0) >= limits.per_name
            || counts.per_tenant.get(tenant).copied().unwrap_or(0) >= limits.per_tenant
            || of_client_name >= limits.per_client_name
            || counts.per_client.get(&client).copied().unwrap_or(0) >= limits.per_client
            || (client.prefix48().is_some() && of_v6_48 >= limits.per_v6_48)
        {
            return None;
        }
        counts.total += 1;
        bump(&mut counts.per_name, name.to_string());
        bump(&mut counts.per_tenant, tenant.clone());
        bump(&mut counts.per_client_name, (client, name.to_string()));
        bump(&mut counts.per_client, client);
        if let Some(prefix) = client.prefix48() {
            bump(&mut counts.per_v6_48, prefix);
        }
        drop(counts);
        Some(ShareSlot {
            counters: Arc::clone(self),
            name: name.to_string(),
            tenant: tenant.clone(),
            client,
        })
    }

    /// Connections counted for `name` now.
    #[cfg(test)]
    pub(crate) fn of_name(&self, name: &str) -> usize {
        self.lock().per_name.get(name).copied().unwrap_or(0)
    }

    /// Connections counted for `tenant` now.
    #[cfg(test)]
    pub(crate) fn of_tenant(&self, tenant: &TenantId) -> usize {
        self.lock().per_tenant.get(tenant).copied().unwrap_or(0)
    }

    /// Connections counted in all.
    #[cfg(test)]
    pub(crate) fn total(&self) -> usize {
        self.lock().total
    }
}

impl Drop for ShareSlot {
    fn drop(&mut self) {
        let mut counts = self.counters.lock();
        counts.total = counts.total.saturating_sub(1);
        lower(&mut counts.per_name, &self.name);
        lower(&mut counts.per_tenant, &self.tenant);
        lower(
            &mut counts.per_client_name,
            &(self.client, self.name.clone()),
        );
        lower(&mut counts.per_client, &self.client);
        if let Some(prefix) = self.client.prefix48() {
            lower(&mut counts.per_v6_48, &prefix);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------------

/// What a connection is routed to.
enum Route {
    /// The relay's own host name: the TLS and WebSocket path.
    Own,
    /// A share that a node holds.
    Share(Box<Resolved>),
    /// A terminated share: the name, and the certificate the relay holds for exactly it.
    Terminated(Box<Resolved>, String, Arc<CertifiedKey>),
    /// The static refusal.
    Refuse,
}

/// A share name that resolved to a node.
struct Resolved {
    /// The full name relative to the share domain (`app`, `app.ali`).
    name: String,
    tenant: TenantId,
    held: HeldName,
    limits: ShareLimits,
}

impl Resolved {
    /// The node, the network and the service to open, and the `meta` for OPEN.
    fn service(&self) -> ServiceId {
        self.held.share.service.clone()
    }
}

/// Whether a blind share is one the front door routes by SNI: a `tls:` or `tcp:` service of a
/// blind share (decision E5). A terminated share (`http:`) is not served here.
fn routable(mode: ShareMode, kind: ServiceKind) -> bool {
    matches!(
        (mode, kind),
        (ShareMode::Blind, ServiceKind::Tls | ServiceKind::Tcp)
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The front door of one running relay: its settings, its principal and its counters.
pub(crate) struct FrontDoor {
    config: FrontDoorConfig,
    /// `.` and the share domain.
    suffix: String,
    /// `.t.` and the share domain: the terminated zone.
    terminated_suffix: String,
    /// The TLS configuration of terminated names, made on first use.
    terminated_tls: OnceLock<Arc<rustls::ServerConfig>>,
    principal: Principal,
    counters: Arc<ShareCounters>,
    peeks: Arc<Semaphore>,
    answers: Arc<Semaphore>,
    http_peeks: Arc<Semaphore>,
}

impl FrontDoor {
    /// A front door for `relay`; spawns the relay's principal, so it must be called inside a
    /// tokio runtime.
    pub(crate) fn new(relay: &Relay, config: FrontDoorConfig) -> Arc<Self> {
        Arc::new(Self {
            suffix: format!(".{}", config.share_domain),
            terminated_suffix: format!(".t.{}", config.share_domain),
            terminated_tls: OnceLock::new(),
            principal: Principal::new(relay),
            counters: Arc::default(),
            peeks: Arc::new(Semaphore::new(config.max_peeks)),
            answers: Arc::new(Semaphore::new(config.max_answers)),
            http_peeks: Arc::new(Semaphore::new(config.max_peeks)),
            config,
        })
    }

    /// A permit to read one ClientHello, or `None` when the relay is reading as many as it may.
    pub(crate) fn try_peek(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.peeks).try_acquire_owned().ok()
    }

    /// Resolves `host` (lowercase) as a full name of a share: held now by an attached node
    /// that has accepted a blind `tls:`/`tcp:` share for it, in the zone of the tenant of the
    /// network that granted it. `alpn` is what the client offered. Names of the terminated zone
    /// (`t.H`) never resolve here.
    fn resolve(&self, relay: &Relay, host: &str, alpn: &[Vec<u8>]) -> Option<Resolved> {
        let name = host.strip_suffix(self.suffix.as_str())?;
        // A label `t` is the terminated zone's (no slug may be `t`): a blind name never has one.
        if name.split('.').any(|label| label == "t") {
            return None;
        }
        let resolved = self.resolve_name(relay, name)?;
        if !routable(resolved.held.share.mode, resolved.held.share.service.kind) {
            return None;
        }
        if alpn.iter().any(|offered| offered == ACME_TLS_ALPN)
            && !resolved
                .held
                .share
                .alpn
                .iter()
                .any(|a| a.as_bytes() == ACME_TLS_ALPN)
        {
            return None;
        }
        Some(resolved)
    }

    /// Resolves `host` (lowercase) as the full name of a terminated share (`<label>.t.H`,
    /// `<label>.<slug>.t.H`): an accepted `http:` share of a tenant with the `terminated` flag,
    /// held by an attached node under a grant the Roster still gives, whose network is not held
    /// back, and for which the relay holds a certificate for exactly `host`. Also gives that
    /// certificate. A hello offering `acme-tls/1` is not a terminated name's business (the
    /// relay's own pending validations are answered before routing).
    fn resolve_terminated(
        &self,
        relay: &Relay,
        host: &str,
        alpn: &[Vec<u8>],
    ) -> Option<(Resolved, Arc<CertifiedKey>)> {
        let name = host.strip_suffix(self.terminated_suffix.as_str())?;
        if name.split('.').any(|label| label == "t") {
            return None;
        }
        if alpn.iter().any(|offered| offered == ACME_TLS_ALPN) {
            return None;
        }
        let resolved = self.resolve_name(relay, name)?;
        if resolved.held.share.mode != ShareMode::Terminated
            || resolved.held.share.service.kind != ServiceKind::Http
            || !relay.tenants().tenant_of(&resolved.held.network).terminated
        {
            return None;
        }
        let cert = relay.acme()?.certs().get(host)?;
        Some((resolved, cert))
    }

    /// What blind and terminated names share: `name` (relative to the zone, `app` or `app.ali`)
    /// is accepted for a node, granted now, held by an attached node, its network not held back,
    /// and in the zone of its tenant. The mode of the share is the caller's to judge.
    fn resolve_name(&self, relay: &Relay, name: &str) -> Option<Resolved> {
        if name.is_empty() || name.split('.').count() > 2 {
            return None;
        }
        let held = relay.labels().held_name(name, unix_now())?;
        // The grant is judged now, not when the name was accepted: a label the owner moved to
        // another node or dropped, or a holder the Roster no longer lists, routes nothing even
        // while the old holder stays attached (expose round 2, M1).
        let label = name.split('.').next().unwrap_or(name);
        if !relay
            .rosters()
            .label_granted(&held.network, &held.node, label)
        {
            return None;
        }
        // The gate: the holder is attached now (the principal checks again at `open`).
        relay.attached_node(&held.node)?;
        let book = relay.tenants();
        if book.is_held_back(&held.network) {
            return None;
        }
        let tenant = book.id_of(&held.network).clone();
        // The name is in the zone of the tenant of its network: the record's tenant, the zone
        // label of the name and the book must all say the same.
        if tenant.slug() != held.tenant.as_deref() {
            return None;
        }
        if let Some((_, zone)) = name.split_once('.')
            && Some(zone) != tenant.slug()
        {
            return None;
        }
        let figures = book.figures_of(&tenant);
        let limits = ShareLimits {
            per_name: figures.map_or(self.config.per_name, |f| {
                usize::try_from(f.share_connections_per_name).unwrap_or(usize::MAX)
            }),
            per_tenant: figures.map_or(self.config.per_tenant, |f| {
                usize::try_from(f.share_connections).unwrap_or(usize::MAX)
            }),
            total: self.config.max_total,
            per_client_name: self.config.per_client_per_name,
            per_client: self.config.per_client,
            per_v6_48: self.config.per_v6_48,
        };
        Some(Resolved {
            name: name.to_string(),
            tenant,
            held,
            limits,
        })
    }

    fn route(&self, relay: &Relay, hello: &ClientHello) -> Route {
        let Some(sni) = hello.sni.as_deref() else {
            return Route::Refuse;
        };
        if sni == self.config.own_host {
            return Route::Own;
        }
        // The two zones never mix: a name under `t.H` is judged as a terminated name only, any
        // other as a blind one only (which refuses every label `t`).
        if sni.ends_with(self.terminated_suffix.as_str()) {
            return match self.resolve_terminated(relay, sni, &hello.alpn) {
                Some((resolved, cert)) => {
                    Route::Terminated(Box::new(resolved), sni.to_string(), cert)
                }
                None => Route::Refuse,
            };
        }
        match self.resolve(relay, sni, &hello.alpn) {
            Some(resolved) => Route::Share(Box::new(resolved)),
            None => Route::Refuse,
        }
    }

    // -----------------------------------------------------------------------------------------
    // The TLS port
    // -----------------------------------------------------------------------------------------

    /// Handles one accepted connection on the TLS port: reads the ClientHello, then routes it.
    /// `peek` is held for the reading only.
    pub(crate) async fn handle_tls(
        self: Arc<Self>,
        relay: Relay,
        accepting: Arc<Accepting>,
        mut tcp: TcpStream,
        peer: SocketAddr,
        mut ip_slot: IpSlot,
        peek: tokio::sync::OwnedSemaphorePermit,
    ) {
        let peeked = sni::read_client_hello(&mut tcp, self.config.peek_deadline).await;
        let decided = Instant::now();
        let (bytes, hello) = match peeked {
            Peeked::Dropped => return,
            Peeked::Invalid(why) => {
                drop(peek);
                tracing::debug!(?why, "not a routable ClientHello");
                drop(ip_slot);
                self.refuse(tcp, decided, &REFUSAL).await;
                return;
            }
            Peeked::Hello { bytes, hello } => (bytes, hello),
        };
        // A TLS-ALPN-01 validation of one of the relay's own pending orders (ALPN exactly
        // `acme-tls/1`, an SNI with an order pending now) is answered here, before routing; it
        // keeps the peek permit and the address's share while it is, so it is bounded like a
        // ClientHello read. Anything else, a failed parse included, goes on as before.
        if let Some(acme) = relay.acme()
            && let Some(sni) = hello.sni.as_deref()
            && acme::is_pending_validation(acme, Some(sni), &hello.alpn)
            && acme::answer_validation(acme, &mut tcp, &bytes, sni).await == acme::Answered::Done
        {
            drop(peek);
            drop(ip_slot);
            return;
        }
        drop(peek);
        match self.route(&relay, &hello) {
            Route::Own => {
                relay
                    .serve_own_host(&accepting, PrefixedTcp::with_prefix(bytes, tcp), ip_slot)
                    .await;
            }
            Route::Refuse => {
                drop(ip_slot);
                self.refuse(tcp, decided, &REFUSAL).await;
            }
            Route::Share(resolved) => {
                // A public connection is not a session: it holds no unattached share of the
                // peer's address (its rate was counted at accept).
                ip_slot.end_handshake();
                drop(ip_slot);
                let sni = hello.sni.unwrap_or_default();
                self.serve_share(tcp, peer, *resolved, sni, bytes, None, decided)
                    .await;
            }
            Route::Terminated(resolved, host, cert) => {
                ip_slot.end_handshake();
                drop(ip_slot);
                self.serve_terminated(relay, tcp, peer, *resolved, host, cert, bytes, decided)
                    .await;
            }
        }
    }

    /// Terminates TLS for a terminated share with `cert` and serves its HTTP (`crate::http_term`):
    /// the share counts against its figures like a blind one, a refusal before the handshake is
    /// the same alert as everywhere, and the node stream is opened only when the first valid
    /// request is in hand.
    #[allow(clippy::too_many_arguments)]
    async fn serve_terminated(
        self: &Arc<Self>,
        relay: Relay,
        tcp: TcpStream,
        peer: SocketAddr,
        resolved: Resolved,
        host: String,
        _cert: Arc<CertifiedKey>,
        hello_bytes: Vec<u8>,
        decided: Instant,
    ) {
        let Some(slot) = self.counters.try_acquire(
            &resolved.name,
            &resolved.tenant,
            PeerKey::of(peer.ip()),
            resolved.limits,
        ) else {
            tracing::debug!(name = %resolved.name, "share connection figure reached");
            self.refuse(tcp, decided, &REFUSAL).await;
            return;
        };
        let Some(config) = self.terminated_config(&relay) else {
            self.refuse(tcp, decided, &REFUSAL).await;
            return;
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let limits = self.config.http;
        let accepted = tokio::time::timeout(
            limits.head_timeout,
            acceptor.accept(PrefixedTcp::with_prefix(hello_bytes, tcp)),
        )
        .await;
        let Ok(Ok(tls)) = accepted else {
            tracing::debug!(name = %resolved.name, "the TLS handshake of a terminated name failed");
            return;
        };
        let client_ip = peer.ip();
        let door = Arc::clone(self);
        let still = {
            let (relay, host) = (relay.clone(), host.clone());
            let door = Arc::clone(self);
            move || door.resolve_terminated(&relay, &host, &[]).is_some()
        };
        let opening = {
            let host = host.clone();
            let resolved = &resolved;
            move || async move {
                let meta = OpenMeta {
                    client_ip: Some(client_ip.to_canonical().to_string()),
                    sni: Some(host),
                };
                match door
                    .principal
                    .open(
                        &resolved.tenant,
                        resolved.held.node,
                        resolved.held.network,
                        resolved.service(),
                        meta,
                    )
                    .await
                {
                    Ok(stream) => Some(TokioStream(stream)),
                    Err(error) => {
                        tracing::debug!(name = %resolved.name, %error, "the share could not be opened");
                        None
                    }
                }
            }
        };
        http_term::serve(tls, &host, client_ip, limits, still, opening).await;
        drop(slot);
    }

    /// The TLS configuration of terminated names: the certificate of exactly the name asked
    /// (the book's own fallback for the relay's host is never offered), ALPN `http/1.1`.
    fn terminated_config(&self, relay: &Relay) -> Option<Arc<rustls::ServerConfig>> {
        if let Some(config) = self.terminated_tls.get() {
            return Some(Arc::clone(config));
        }
        let certs = relay.acme()?.certs().clone();
        crate::tls::ensure_crypto_provider();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(ExactCerts(certs)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some(Arc::clone(
            self.terminated_tls.get_or_init(|| Arc::new(config)),
        ))
    }

    /// Opens the share and pipes `first` (the bytes already read from the client) and then the
    /// connection through it; refuses on any failure to get that far. `service` overrides the
    /// share's own service (`acme-http:<label>` on port 80).
    #[allow(clippy::too_many_arguments)]
    async fn serve_share(
        &self,
        tcp: TcpStream,
        peer: SocketAddr,
        resolved: Resolved,
        sni: String,
        first: Vec<u8>,
        service: Option<ServiceId>,
        decided: Instant,
    ) {
        let refusal: &'static [u8] = if service.is_some() {
            HTTP_REFUSAL
        } else {
            &REFUSAL
        };
        let Some(slot) = self.counters.try_acquire(
            &resolved.name,
            &resolved.tenant,
            PeerKey::of(peer.ip()),
            resolved.limits,
        ) else {
            tracing::debug!(name = %resolved.name, "share connection figure reached");
            self.refuse(tcp, decided, refusal).await;
            return;
        };
        let meta = OpenMeta {
            client_ip: Some(peer.ip().to_canonical().to_string()),
            sni: Some(sni),
        };
        let service = service.unwrap_or_else(|| resolved.service());
        let opened = self
            .principal
            .open(
                &resolved.tenant,
                resolved.held.node,
                resolved.held.network,
                service,
                meta,
            )
            .await;
        let stream = match opened {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(name = %resolved.name, %error, "the share could not be opened");
                self.refuse(tcp, decided, refusal).await;
                return;
            }
        };
        self.pipe(tcp, stream, first).await;
        drop(slot);
    }

    /// Sends `refusal` no sooner than the failure delay after `decided`, closes, and waits a
    /// moment for the peer to take it. A connection that finds [`FrontDoorConfig::max_answers`]
    /// refusals in flight is closed at once, without one.
    async fn refuse(&self, mut tcp: TcpStream, decided: Instant, refusal: &[u8]) {
        let Ok(_permit) = Arc::clone(&self.answers).try_acquire_owned() else {
            return;
        };
        tokio::time::sleep_until(decided + self.config.failure_delay).await;
        let _ = tokio::time::timeout(REFUSAL_WRITE, tcp.write_all(refusal)).await;
        let _ = tokio::time::timeout(REFUSAL_WRITE, tcp.shutdown()).await;
        let _ = tokio::time::timeout(REFUSAL_DRAIN, async {
            let mut sink = [0u8; 1024];
            while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
        })
        .await;
    }

    /// Writes `first` to the share and copies both ways until both directions have ended, the
    /// stream is torn down, or nothing moved for the idle timeout.
    async fn pipe(&self, tcp: TcpStream, stream: Stream, first: Vec<u8>) {
        let activity = Activity::new();
        let torn_down = stream.torn_down();
        let mut remote = Watched::new(TokioStream(stream), Arc::clone(&activity), true);
        let mut local = Watched::new(tcp, Arc::clone(&activity), false);
        let idle = self.config.idle_timeout;
        let first_byte = self.config.first_byte_timeout;
        let copy = async {
            remote.write_all(&first).await?;
            remote.flush().await?;
            copy_bidirectional_with_sizes(&mut remote, &mut local, PIPE_BUFFER, PIPE_BUFFER).await
        };
        let outcome = tokio::select! {
            biased;
            result = copy => result.map(|_| ()),
            () = torn_down => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "the stream was torn down under the pipe",
            )),
            () = went_idle(&activity, idle, first_byte) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no byte moved for the idle timeout (or none came from the node in time)",
            )),
        };
        if let Err(error) = outcome {
            tracing::debug!(%error, "share connection ended abnormally");
            // Dropping an unfinished stream resets it; the socket is closed by the drop too.
        }
    }

    // -----------------------------------------------------------------------------------------
    // Port 80
    // -----------------------------------------------------------------------------------------

    /// Serves plain HTTP on `listener` until the task is aborted (see the module docs).
    pub(crate) async fn serve_http(self: Arc<Self>, relay: Relay, listener: TcpListener) {
        loop {
            let (tcp, peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(%error, "relay failed to accept a port 80 connection");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Some(ip_slot) = relay.admission.admit_connection(peer.ip()) else {
                continue;
            };
            let Ok(peek) = Arc::clone(&self.http_peeks).try_acquire_owned() else {
                continue;
            };
            let this = Arc::clone(&self);
            let relay = relay.clone();
            tokio::spawn(async move {
                this.handle_http(relay, tcp, peer, ip_slot, peek).await;
            });
        }
    }

    async fn handle_http(
        self: Arc<Self>,
        relay: Relay,
        mut tcp: TcpStream,
        peer: SocketAddr,
        ip_slot: IpSlot,
        peek: tokio::sync::OwnedSemaphorePermit,
    ) {
        let read = read_http_head(&mut tcp, self.config.peek_deadline).await;
        drop(ip_slot);
        let decided = Instant::now();
        let Some((bytes, head)) = read else {
            return;
        };
        let Some(host) = head.host.as_deref() else {
            drop(peek);
            self.refuse(tcp, decided, HTTP_REFUSAL).await;
            return;
        };
        let path = head.target.split('?').next().unwrap_or("");
        // The relay's own host is never a share: it is looked at before the challenge branch.
        if host != self.config.own_host && path.starts_with(ACME_PATH) {
            // A challenge: opened on the holder if it is a blind share's name, refused alike
            // otherwise.
            drop(peek);
            let resolved = (head.method == "GET")
                .then(|| self.resolve(&relay, host, &[]))
                .flatten();
            let Some(resolved) = resolved else {
                self.refuse(tcp, decided, HTTP_REFUSAL).await;
                return;
            };
            let service = ServiceId {
                kind: ServiceKind::AcmeHttp,
                label: resolved
                    .name
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            };
            self.serve_share(
                tcp,
                peer,
                resolved,
                host.to_string(),
                bytes,
                Some(service),
                decided,
            )
            .await;
            return;
        }
        if host == self.config.own_host || host.ends_with(self.suffix.as_str()) {
            // The redirect holds the connection's place among the readers until it is sent.
            let response = redirect_to(host, &head.target).into_bytes();
            let _ = tokio::time::timeout(REFUSAL_WRITE, tcp.write_all(&response)).await;
            let _ = tokio::time::timeout(REFUSAL_WRITE, tcp.shutdown()).await;
            let _ = tokio::time::timeout(REFUSAL_DRAIN, async {
                let mut sink = [0u8; 1024];
                while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
            })
            .await;
            drop(peek);
            return;
        }
        drop(peek);
        self.refuse(tcp, decided, HTTP_REFUSAL).await;
    }
}

/// The `301` to the https URL of the same host and path. `target` is the request target as
/// sent: kept if it is an origin form path of visible ASCII only, `/` otherwise.
fn redirect_to(host: &str, target: &str) -> String {
    let path = if target.starts_with('/')
        && target.len() <= 2048
        && target.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        target
    } else {
        "/"
    };
    format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

// ---------------------------------------------------------------------------------------------
// The request head of port 80
// ---------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct HttpHead {
    method: String,
    target: String,
    /// The `Host` header, lowercased, without a port.
    host: Option<String>,
}

/// Reads up to the end of an HTTP request head (at most [`HTTP_HEAD_LIMIT`] bytes, `deadline`
/// in all); the bytes read and what they say, or `None` for anything that is not a head the
/// relay can read.
async fn read_http_head(tcp: &mut TcpStream, deadline: Duration) -> Option<(Vec<u8>, HttpHead)> {
    let read = async {
        let mut head = HeadBuffer::default();
        let mut chunk = [0u8; 2048];
        loop {
            let room = (HTTP_HEAD_LIMIT - head.bytes.len()).min(chunk.len());
            if room == 0 {
                return None;
            }
            match tcp.read(&mut chunk[..room]).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => {
                    if let Some(end) = head.push(&chunk[..n]) {
                        let parsed = parse_head(&head.bytes[..end])?;
                        return Some((head.bytes, parsed));
                    }
                }
            }
        }
    };
    tokio::time::timeout(deadline, read).await.ok().flatten()
}

/// The bytes of a request head read so far, and the search for its blank line, which looks at
/// each byte once (expose round 2, L2): a blank line cut by the edge of two reads begins at most
/// three bytes before the new data, so only those three and the new bytes are scanned.
#[derive(Default)]
struct HeadBuffer {
    bytes: Vec<u8>,
    /// Positions scanned in all, over every push (tests measure the work with it).
    #[cfg(test)]
    scanned: usize,
}

impl HeadBuffer {
    /// Adds `chunk`; the length of the head including its blank line, if the bytes hold one.
    fn push(&mut self, chunk: &[u8]) -> Option<usize> {
        let from = self.bytes.len().saturating_sub(3);
        self.bytes.extend_from_slice(chunk);
        #[cfg(test)]
        {
            self.scanned += self.bytes.len() - from;
        }
        find_head_end_from(&self.bytes, from)
    }
}

/// The length of the head including its blank line, if `bytes` holds one at or after `from`.
fn find_head_end_from(bytes: &[u8], from: usize) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| from + at + 4)
}

fn parse_head(head: &[u8]) -> Option<HttpHead> {
    let text = std::str::from_utf8(head).ok()?;
    let text = text.strip_suffix("\r\n\r\n")?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || target.is_empty()
        || !version.starts_with("HTTP/1.")
    {
        return None;
    }
    let mut host: Option<String> = None;
    let mut seen_host = false;
    for line in lines {
        if line.is_empty()
            || line.starts_with([' ', '\t'])
            || line.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0))
        {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_whitespace()) {
            return None;
        }
        if name.eq_ignore_ascii_case("host") {
            if std::mem::replace(&mut seen_host, true) {
                return None;
            }
            host = host_without_port(value.trim());
        }
    }
    Some(HttpHead {
        method: method.to_string(),
        target: target.to_string(),
        host,
    })
}

/// A `Host` value as a lowercase hostname without its port, `None` if it is not a plain DNS
/// name (an address in brackets, userinfo and the like).
fn host_without_port(value: &str) -> Option<String> {
    let name = match value.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        Some(_) => return None,
        None => value,
    };
    normalize_host(name.as_bytes())
}

// ---------------------------------------------------------------------------------------------
// The pipe
// ---------------------------------------------------------------------------------------------

/// When something last moved through a pipe, as milliseconds since the pipe began, and whether
/// the node has sent a byte yet.
struct Activity {
    began: Instant,
    last_ms: AtomicU64,
    node_spoke: AtomicBool,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            began: Instant::now(),
            last_ms: AtomicU64::new(0),
            node_spoke: AtomicBool::new(false),
        })
    }

    fn touch(&self) {
        let ms = u64::try_from(self.began.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }

    /// A byte came from the node (before the touch, so a waiter that sees the touch sees this).
    fn node_sent(&self) {
        self.node_spoke.store(true, Ordering::Relaxed);
    }
}

/// Completes when the pipe is to end for want of bytes. Once the node has sent a byte: nothing
/// moved for `idle`. Before: nothing moved for `idle` or for `first_byte`, whichever is less, or
/// `first_byte` have passed in all, however busy the client kept it (a client sending to a node
/// that never answers costs the client nothing, so only the node's first byte makes a pipe
/// worth the long idle time).
async fn went_idle(activity: &Activity, idle: Duration, first_byte: Duration) {
    loop {
        let spoke = activity.node_spoke.load(Ordering::Relaxed);
        let last = activity.last_ms.load(Ordering::Relaxed);
        let since_last = Duration::from_millis(last);
        let deadline = if spoke {
            activity.began + since_last + idle
        } else {
            (activity.began + since_last + idle.min(first_byte)).min(activity.began + first_byte)
        };
        tokio::time::sleep_until(deadline).await;
        let spoke_now = activity.node_spoke.load(Ordering::Relaxed);
        if !spoke_now && Instant::now() >= activity.began + first_byte {
            return;
        }
        if spoke_now == spoke && activity.last_ms.load(Ordering::Relaxed) == last {
            return;
        }
    }
}

/// An I/O object that records every read and write that moved something.
struct Watched<T> {
    inner: T,
    activity: Arc<Activity>,
    /// Whether the bytes this reads come from the node.
    from_node: bool,
}

impl<T> Watched<T> {
    fn new(inner: T, activity: Arc<Activity>, from_node: bool) -> Self {
        Self {
            inner,
            activity,
            from_node,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) {
            if self.from_node && buf.filled().len() > before {
                self.activity.node_sent();
            }
            self.activity.touch();
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(poll, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `menzil_stream::Stream` speaks `futures` I/O; tokio's `copy_bidirectional` wants its own
/// traits (the same adapter `menzil-node`'s serving pipe uses).
struct TokioStream(Stream);

/// Certificates by exact SNI name, with no fallback.
#[derive(Debug)]
struct ExactCerts(RelayCertBook);

impl ResolvesServerCert for ExactCerts {
    fn resolve(&self, client_hello: TlsClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0
            .get(&client_hello.server_name()?.to_ascii_lowercase())
    }
}

impl AsyncRead for TokioStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match futures_util::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TokioStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        futures_util::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        futures_util::io::AsyncWrite::poll_close(Pin::new(&mut self.0), cx)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::IpAddr;

    use super::*;

    fn tenant(slug: &str) -> TenantId {
        TenantId::Named(crate::tenant::Slug::parse(slug).unwrap())
    }

    fn limits(per_name: usize, per_tenant: usize, total: usize) -> ShareLimits {
        ShareLimits {
            per_name,
            per_tenant,
            total,
            per_client_name: usize::MAX,
            per_client: usize::MAX,
            per_v6_48: usize::MAX,
        }
    }

    /// The client at `10.0.0.n`.
    fn client(n: u8) -> PeerKey {
        PeerKey::of(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, n)))
    }

    /// The client in the /64 `2001:db8:<hi>:<lo>::/64` (so the /48 is `<hi>`'s).
    fn v6(hi: u16, lo: u16) -> PeerKey {
        PeerKey::of(IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, hi, lo, 0, 0, 0, 1,
        )))
    }

    #[test]
    fn the_counters_hold_each_figure_and_give_every_place_back() {
        let counters = Arc::new(ShareCounters::default());
        let ali = tenant("ali");
        let veli = tenant("veli");
        let l = limits(2, 3, 100);
        let a1 = counters.try_acquire("app.ali", &ali, client(1), l).unwrap();
        let a2 = counters.try_acquire("app.ali", &ali, client(1), l).unwrap();
        assert!(
            counters
                .try_acquire("app.ali", &ali, client(1), l)
                .is_none(),
            "the third connection to one name is over its figure"
        );
        let b1 = counters
            .try_acquire("blog.ali", &ali, client(1), l)
            .unwrap();
        assert!(
            counters
                .try_acquire("wiki.ali", &ali, client(1), l)
                .is_none(),
            "the fourth connection of one tenant is over its figure"
        );
        let other = counters
            .try_acquire("app.veli", &veli, client(1), l)
            .unwrap();
        assert_eq!(counters.of_name("app.ali"), 2);
        assert_eq!(counters.of_tenant(&ali), 3);
        assert_eq!(counters.total(), 4);
        drop(a1);
        let again = counters
            .try_acquire("wiki.ali", &ali, client(1), l)
            .expect("a released place is usable at once");
        drop((a2, b1, other, again));
        assert_eq!(counters.total(), 0);
        assert_eq!(counters.of_name("app.ali"), 0);
        assert_eq!(counters.of_tenant(&ali), 0);
        assert!(
            counters.lock().per_name.is_empty(),
            "no entry is left behind"
        );
        assert!(counters.lock().per_tenant.is_empty());
    }

    #[test]
    fn the_relay_wide_figure_holds_across_tenants() {
        let counters = Arc::new(ShareCounters::default());
        let l = limits(10, 10, 2);
        let _a = counters
            .try_acquire("a.ali", &tenant("ali"), client(1), l)
            .unwrap();
        let _b = counters
            .try_acquire("b.veli", &tenant("veli"), client(1), l)
            .unwrap();
        assert!(
            counters
                .try_acquire("c.deli", &tenant("deli"), client(1), l)
                .is_none()
        );
    }

    #[test]
    fn the_refusals_are_fixed_bytes() {
        assert_eq!(REFUSAL, [21, 3, 3, 0, 2, 2, 112]);
        assert!(HTTP_REFUSAL.starts_with(b"HTTP/1.1 404 "));
    }

    #[test]
    fn only_a_blind_tls_or_tcp_share_is_routable() {
        use ServiceKind::*;
        assert!(routable(ShareMode::Blind, Tls));
        assert!(routable(ShareMode::Blind, Tcp));
        assert!(!routable(ShareMode::Blind, Http));
        assert!(!routable(ShareMode::Blind, AcmeHttp));
        assert!(!routable(ShareMode::Terminated, Http));
        assert!(!routable(ShareMode::Terminated, Tls));
        assert!(!routable(ShareMode::Terminated, Tcp));
    }

    #[test]
    fn config_names_are_validated_and_lowercased() {
        let config = FrontDoorConfig::new("Relay.Example.Test", "S.Example.Test").unwrap();
        assert_eq!(config.own_host(), "relay.example.test");
        assert_eq!(config.share_domain(), "s.example.test");
        assert!(FrontDoorConfig::new("relay.example.test", "relay.example.test").is_err());
        assert!(FrontDoorConfig::new("relay.example.test", "").is_err());
        assert!(FrontDoorConfig::new("relay.example.test", "s.example.test.").is_err());
        assert!(FrontDoorConfig::new("bad host", "s.example.test").is_err());
    }

    #[test]
    fn a_request_head_is_read_strictly() {
        let ok = parse_head(
            b"GET /.well-known/acme-challenge/tok?x=1 HTTP/1.1\r\nHost: App.Example.Test:80\r\nUser-Agent: t\r\n\r\n",
        )
        .unwrap();
        assert_eq!(ok.method, "GET");
        assert_eq!(ok.target, "/.well-known/acme-challenge/tok?x=1");
        assert_eq!(ok.host.as_deref(), Some("app.example.test"));
        assert_eq!(
            parse_head(b"GET / HTTP/1.0\r\n\r\n").unwrap().host,
            None,
            "no Host header"
        );
        for bad in [
            &b"GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\n Host: a.test\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a.test\r\nX: a\nb\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : a.test\r\n\r\n",
            b"get / HTTP/1.1\r\nHost: a.test\r\n\r\n",
            b"GET / HTTP/2\r\nHost: a.test\r\n\r\n",
            b"GET /\r\nHost: a.test\r\n\r\n",
            b"GET / HTTP/1.1 x\r\nHost: a.test\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a.test\0\r\n\r\n",
            b"GET / HTTP/1.1\r\nnocolon\r\n\r\n",
        ] {
            assert_eq!(parse_head(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
        // A Host that is not a plain name parses as "no host".
        for host in ["[::1]:80", "a.test:x", "u@a.test", "a.test:", "a b"] {
            let head = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            assert_eq!(parse_head(head.as_bytes()).unwrap().host, None, "{host}");
        }
    }

    #[test]
    fn the_redirect_keeps_a_visible_ascii_path_and_nothing_else() {
        assert_eq!(
            redirect_to("app.s.test", "/a/b?c=d"),
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://app.s.test/a/b?c=d\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        for target in ["*", "http://evil.test/", "/a b", "/a\u{e9}", "/a\u{7f}"] {
            assert!(
                redirect_to("app.s.test", target).contains("Location: https://app.s.test/\r\n"),
                "{target:?}"
            );
        }
        let long = format!("/{}", "a".repeat(3000));
        assert!(redirect_to("app.s.test", &long).contains("https://app.s.test/\r\n"));
    }

    // -----------------------------------------------------------------------------------------
    // Resolution against a relay's own state
    // -----------------------------------------------------------------------------------------

    use std::collections::{BTreeMap, HashSet};

    use ed25519_dalek::SigningKey;
    use menzil_proto::{
        AdvertiseBody, Label, Limits, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION,
        Roster, RosterBody, RosterMember, Share, X25519PublicKey,
    };

    use crate::identity::RelayIdentity;
    use crate::names::{Quarantine, QuarantineKind};
    use crate::tenant::{Class, Slug, TenantBook, TenantSpec};

    pub(crate) const OWN: &str = "relay.example.test";
    pub(crate) fn tests_unix_now() -> u64 {
        super::unix_now()
    }

    pub(crate) const H: &str = "s.example.test";

    pub(crate) struct World {
        pub(crate) relay: Relay,
        pub(crate) door: Arc<FrontDoor>,
        pub(crate) node: NodeId,
        pub(crate) network: NetworkId,
        pub(crate) owner: SigningKey,
    }

    pub(crate) fn relay() -> Relay {
        let key = SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: NodeId::from(key.verifying_key().to_bytes()),
            x25519_pub: X25519PublicKey::from([5u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 4_000_000_000,
        };
        Relay::new(
            RelayIdentity {
                node_cert: NodeCert::sign(&key, &body).unwrap(),
                x25519_private: [5u8; 32],
            },
            Limits {
                max_record: 65_535,
                max_peers: 10,
                credit: 1 << 20,
            },
        )
    }

    pub(crate) fn share(name: &str, mode: ShareMode, service: &str, alpn: &[&str]) -> Share {
        Share {
            name: name.to_string(),
            mode,
            service: service.parse().unwrap(),
            alpn: alpn.iter().map(|a| a.to_string()).collect(),
        }
    }

    pub(crate) fn world(labels: &[&str], tenants: Option<TenantSpec>) -> World {
        // The caller's tenant spec gets this network patched in.
        let owner = SigningKey::generate(&mut rand::rng());
        let network = NetworkId::from(owner.verifying_key().to_bytes());
        let node = NodeId::from([9u8; 32]);
        let relay = relay();
        let body = RosterBody {
            v: PROTOCOL_VERSION,
            network_id: network,
            seq: 1,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id: node,
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: labels
                .iter()
                .map(|name| Label {
                    name: name.to_string(),
                    node_id: node,
                })
                .collect(),
        };
        relay
            .rosters()
            .set(&Roster::sign(&owner, &body).unwrap())
            .unwrap();
        if let Some(mut spec) = tenants {
            spec.networks = vec![network];
            relay.set_tenants(TenantBook::build(
                vec![spec],
                Vec::new(),
                &HashSet::new(),
                &HashSet::new(),
            ));
        }
        let door = FrontDoor::new(&relay, FrontDoorConfig::new(OWN, H).unwrap());
        World {
            relay,
            door,
            node,
            network,
            owner,
        }
    }

    impl World {
        pub(crate) fn attach(&self) {
            // Kept alive by leaking the receivers: the registration is what is looked at.
            let held = self.relay.registry.attach(self.node, 1, vec![self.network]);
            std::mem::forget(held);
        }

        pub(crate) fn advertise(&self, shares: Vec<Share>) -> menzil_proto::AdvertiseAckBody {
            self.relay.labels().advertise(
                self.relay.rosters(),
                &self.relay.tenants(),
                &[self.network],
                &self.node,
                &AdvertiseBody {
                    v: PROTOCOL_VERSION,
                    shares,
                    accept_peers: true,
                },
                unix_now(),
            )
        }

        /// The owner's Roster `seq` listing `members` and granting each `(label, node)`.
        pub(crate) fn roster(&self, seq: u64, members: &[NodeId], labels: &[(&str, NodeId)]) {
            let body = RosterBody {
                v: PROTOCOL_VERSION,
                network_id: self.network,
                seq,
                issued: 0,
                expires: 1_000_000_000,
                members: members
                    .iter()
                    .map(|node_id| RosterMember {
                        node_id: *node_id,
                        min_serial: 1,
                    })
                    .collect(),
                revoked: vec![],
                stewards: vec![],
                labels: labels
                    .iter()
                    .map(|(name, node_id)| Label {
                        name: name.to_string(),
                        node_id: *node_id,
                    })
                    .collect(),
            };
            assert!(
                self.relay
                    .rosters()
                    .set(&Roster::sign(&self.owner, &body).unwrap())
                    .unwrap()
            );
        }

        pub(crate) fn attach_node(&self, node: NodeId) {
            std::mem::forget(self.relay.registry.attach(node, 1, vec![self.network]));
        }

        pub(crate) fn advertise_as(
            &self,
            node: NodeId,
            shares: Vec<Share>,
        ) -> menzil_proto::AdvertiseAckBody {
            self.relay.labels().advertise(
                self.relay.rosters(),
                &self.relay.tenants(),
                &[self.network],
                &node,
                &AdvertiseBody {
                    v: PROTOCOL_VERSION,
                    shares,
                    accept_peers: true,
                },
                unix_now(),
            )
        }

        fn resolve(&self, host: &str, alpn: &[&[u8]]) -> Option<Resolved> {
            let alpn: Vec<Vec<u8>> = alpn.iter().map(|a| a.to_vec()).collect();
            self.door.resolve(&self.relay, host, &alpn)
        }
    }

    pub(crate) fn ali(overrides: &[(&str, u64)]) -> TenantSpec {
        TenantSpec {
            slug: Slug::parse("ali").unwrap(),
            networks: Vec::new(),
            class: Class::Friend,
            overrides: overrides
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect::<BTreeMap<_, _>>(),
            terminated: false,
            extra_names: Vec::new(),
            added: 1,
        }
    }

    fn hello(sni: Option<&str>, alpn: &[&[u8]]) -> ClientHello {
        ClientHello {
            sni: sni.map(str::to_string),
            alpn: alpn.iter().map(|a| a.to_vec()).collect(),
        }
    }

    fn is_refuse(route: &Route) -> bool {
        matches!(route, Route::Refuse)
    }

    #[tokio::test]
    async fn a_held_blind_name_resolves_to_its_node_network_and_service() {
        let w = world(&["app", "raw"], None);
        w.attach();
        w.advertise(vec![
            share("app", ShareMode::Blind, "tls:app", &[]),
            share("raw", ShareMode::Blind, "tcp:raw", &[]),
        ]);
        let app = w.resolve("app.s.example.test", &[b"h2"]).expect("app");
        assert_eq!(app.name, "app");
        assert_eq!(app.tenant, TenantId::Default);
        assert_eq!(app.held.node, w.node);
        assert_eq!(app.held.network, w.network);
        assert_eq!(app.service(), "tls:app".parse().unwrap());
        assert_eq!(app.limits.per_name, FRONT_DOOR_PER_NAME);
        assert_eq!(app.limits.per_tenant, FRONT_DOOR_PER_TENANT);
        assert_eq!(app.limits.total, FRONT_DOOR_MAX_TOTAL);
        let raw = w.resolve("raw.s.example.test", &[]).expect("tcp: by SNI");
        assert_eq!(raw.service(), "tcp:raw".parse().unwrap());
    }

    #[tokio::test]
    async fn every_other_name_resolves_to_nothing() {
        let w = world(&["app"], None);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        for host in [
            "nosuch.s.example.test",
            "s.example.test",
            ".s.example.test",
            "app.example.test",
            "app.s.example.test.evil.test",
            "x.app.s.example.test",
            "app.ali.s.example.test",
            "app.t.example.test",
            "relay.example.test",
        ] {
            assert!(w.resolve(host, &[]).is_none(), "{host}");
        }
        assert!(w.resolve("app.s.example.test", &[]).is_some());
    }

    #[tokio::test]
    async fn a_name_is_served_only_while_its_node_is_attached_and_holds_the_claim() {
        let w = world(&["app"], None);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert!(w.resolve("app.s.example.test", &[]).is_some());
        // The claim is gone (a new session before its ADVERTISE, or a withdrawal).
        w.relay.labels().clear_for(&w.node, unix_now());
        assert!(w.resolve("app.s.example.test", &[]).is_none(), "unheld");
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert!(w.resolve("app.s.example.test", &[]).is_some());
        // The share withdrawn by a later ADVERTISE.
        w.advertise(vec![]);
        assert!(w.resolve("app.s.example.test", &[]).is_none(), "withdrawn");
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        // The node detached while the claim is still on the books.
        assert!(w.relay.registry.detach(&w.node, 1));
        assert!(w.resolve("app.s.example.test", &[]).is_none(), "detached");
    }

    #[tokio::test]
    async fn a_terminated_share_and_a_share_of_another_kind_are_not_routed() {
        let w = world(&["web", "app"], None);
        w.attach();
        w.advertise(vec![
            share("web", ShareMode::Terminated, "http:web", &[]),
            share("app", ShareMode::Blind, "tls:app", &[]),
        ]);
        assert!(w.resolve("web.s.example.test", &[]).is_none());
        assert!(w.resolve("app.s.example.test", &[]).is_some());
    }

    #[tokio::test]
    async fn acme_tls_is_routed_only_to_a_share_that_listed_it() {
        let w = world(&["plain", "acme", "mixed"], None);
        w.attach();
        w.advertise(vec![
            share("plain", ShareMode::Blind, "tls:plain", &["h2"]),
            share("acme", ShareMode::Blind, "tls:acme", &["acme-tls/1"]),
            share(
                "mixed",
                ShareMode::Blind,
                "tls:mixed",
                &["h2", "acme-tls/1"],
            ),
        ]);
        let challenge: &[&[u8]] = &[b"acme-tls/1"];
        let both: &[&[u8]] = &[b"h2", b"acme-tls/1"];
        assert!(w.resolve("plain.s.example.test", challenge).is_none());
        assert!(w.resolve("plain.s.example.test", both).is_none());
        assert!(w.resolve("plain.s.example.test", &[b"h2"]).is_some());
        assert!(w.resolve("acme.s.example.test", challenge).is_some());
        assert!(w.resolve("mixed.s.example.test", challenge).is_some());
        assert!(
            w.resolve("acme.s.example.test", &[]).is_some(),
            "an ordinary hello for a share that listed the challenge protocol is routed too"
        );
    }

    #[tokio::test]
    async fn a_name_in_quarantine_resolves_to_nothing() {
        let w = world(&["app"], None);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert!(w.resolve("app.s.example.test", &[]).is_some());
        let mut state = w.relay.labels().state();
        state.quarantine.insert(
            "app".to_string(),
            Quarantine {
                kind: QuarantineKind::Flat,
                since: unix_now(),
                tenant: None,
                network: Some(w.network),
            },
        );
        w.relay.labels().load_state(&state);
        assert!(w.resolve("app.s.example.test", &[]).is_none());
        // An ended quarantine is none.
        state.quarantine.get_mut("app").unwrap().since = 1;
        w.relay.labels().load_state(&state);
        assert!(w.resolve("app.s.example.test", &[]).is_some());
    }

    #[tokio::test]
    async fn a_tenants_names_live_in_its_zone_and_use_its_share_figures() {
        let w = world(
            &["app"],
            Some(ali(&[
                ("share_connections_per_name", 2),
                ("share_connections", 5),
            ])),
        );
        w.attach();
        let ack = w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert_eq!(ack.names, vec!["app.ali".to_string()]);
        assert!(
            w.resolve("app.s.example.test", &[]).is_none(),
            "the flat name is not this tenant's"
        );
        let resolved = w.resolve("app.ali.s.example.test", &[]).expect("zone name");
        assert_eq!(resolved.name, "app.ali");
        assert_eq!(resolved.tenant.slug(), Some("ali"));
        assert_eq!(resolved.limits.per_name, 2, "the tenant's figure");
        assert_eq!(resolved.limits.per_tenant, 5);
        assert!(
            w.resolve("app.veli.s.example.test", &[]).is_none(),
            "another tenant's zone"
        );
    }

    #[tokio::test]
    async fn a_name_whose_network_changed_tenant_since_it_was_accepted_is_refused() {
        let w = world(&["app"], None);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert!(w.resolve("app.s.example.test", &[]).is_some());
        // The operator moved the network into a tenant: the accepted name (a flat one, the
        // default tenant's) is no longer the zone of the network's tenant.
        let mut spec = ali(&[]);
        spec.networks = vec![w.network];
        w.relay.set_tenants(TenantBook::build(
            vec![spec],
            Vec::new(),
            &HashSet::new(),
            &HashSet::new(),
        ));
        assert!(w.resolve("app.s.example.test", &[]).is_none());
        // A network the tenant file of which was refused is held back and not served either.
        let book = TenantBook::build(
            vec![],
            vec![crate::tenant::Refusal {
                name: "veli".to_string(),
                reason: "test".to_string(),
                networks: vec![w.network],
            }],
            &HashSet::new(),
            &HashSet::new(),
        );
        w.relay.set_tenants(book);
        assert!(w.resolve("app.s.example.test", &[]).is_none());
    }

    #[tokio::test]
    async fn the_relays_own_host_name_is_routed_to_the_websocket_path_before_anything_else() {
        let w = world(&["app"], None);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        let route = |sni: Option<&str>, alpn: &[&[u8]]| w.door.route(&w.relay, &hello(sni, alpn));
        assert!(matches!(route(Some(OWN), &[b"http/1.1"]), Route::Own));
        assert!(matches!(route(Some(OWN), &[b"acme-tls/1"]), Route::Own));
        assert!(matches!(
            route(Some("app.s.example.test"), &[]),
            Route::Share(_)
        ));
        assert!(is_refuse(&route(None, &[])));
        assert!(is_refuse(&route(Some("other.example.test"), &[])));
        assert!(is_refuse(&route(Some("nosuch.s.example.test"), &[])));
        assert!(is_refuse(&route(
            Some("app.s.example.test"),
            &[b"acme-tls/1"]
        )));
    }
    /// Expose round 2, M1: a label the owner moved or dropped stops routing to the old holder
    /// at once, and the new grantee's claim stops being refused once the stale holder is gone.
    #[tokio::test]
    async fn a_label_the_owner_moved_or_dropped_stops_routing_to_the_old_holder() {
        let w = world(&["app"], None);
        let x = w.node;
        let y = NodeId::from([8u8; 32]);
        w.attach();
        w.attach_node(y);
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert_eq!(w.resolve("app.s.example.test", &[]).unwrap().held.node, x);
        // The owner moves the label to Y. X stays attached and never advertises again.
        w.roster(2, &[x, y], &[("app", y)]);
        assert!(
            w.resolve("app.s.example.test", &[]).is_none(),
            "the old holder is not routed to once the Roster grants the label to another node"
        );
        // The stale holder entry still stands until the registry looks at the Rosters.
        let stale = w.advertise_as(y, vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert_eq!(
            stale.rejected.len(),
            1,
            "label_taken while X is still listed"
        );
        assert_eq!(
            w.relay
                .labels()
                .release_ungranted(w.relay.rosters(), unix_now()),
            1
        );
        let ack = w.advertise_as(y, vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        assert_eq!(ack.accepted, vec!["app".to_string()], "{ack:?}");
        assert_eq!(w.resolve("app.s.example.test", &[]).unwrap().held.node, y);
        // The owner drops the label: nobody is routed to, and the next pass releases Y's entry.
        w.roster(3, &[x, y], &[]);
        assert!(w.resolve("app.s.example.test", &[]).is_none());
        assert_eq!(
            w.relay
                .labels()
                .release_ungranted(w.relay.rosters(), unix_now()),
            1
        );
        assert_eq!(
            w.relay
                .labels()
                .release_ungranted(w.relay.rosters(), unix_now()),
            0
        );
    }

    /// A holder the Roster no longer lists (or revokes) is not routed to either.
    #[tokio::test]
    async fn a_holder_the_roster_no_longer_lists_is_not_routed_to() {
        let w = world(&["app"], None);
        let other = NodeId::from([8u8; 32]);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        w.roster(2, &[other], &[("app", w.node)]);
        assert!(w.resolve("app.s.example.test", &[]).is_none());
        w.roster(3, &[w.node, other], &[("app", w.node)]);
        assert!(w.resolve("app.s.example.test", &[]).is_some());
    }

    /// The relay's own watcher runs the pass on every Roster change.
    #[tokio::test]
    async fn the_relays_roster_watcher_drops_the_holders_of_a_moved_label() {
        let w = world(&["app"], None);
        let y = NodeId::from([8u8; 32]);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        let watcher = w.relay.watch_grants();
        w.roster(2, &[w.node, y], &[("app", y)]);
        let mut freed = false;
        for _ in 0..200 {
            if w.relay.labels().held_name("app", unix_now()).is_none() {
                freed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        watcher.abort();
        assert!(freed, "the watcher released the old holder's entry");
    }
    // -----------------------------------------------------------------------------------------
    // Expose round 2: per client figures (M2)
    // -----------------------------------------------------------------------------------------

    /// The figures of a front door made with the defaults.
    fn default_limits() -> ShareLimits {
        let config = FrontDoorConfig::new(OWN, H).unwrap();
        ShareLimits {
            per_name: config.per_name,
            per_tenant: config.max_total,
            total: config.max_total,
            per_client_name: config.per_client_per_name,
            per_client: config.per_client,
            per_v6_48: config.per_v6_48,
        }
    }

    #[test]
    fn the_defaults_are_the_named_constants() {
        let config = FrontDoorConfig::new(OWN, H).unwrap();
        assert_eq!(config.per_client_per_name, FRONT_DOOR_PER_CLIENT_PER_NAME);
        assert_eq!(config.per_client, FRONT_DOOR_PER_CLIENT);
        assert_eq!(
            config.per_v6_48,
            FRONT_DOOR_PER_CLIENT * FRONT_DOOR_V6_48_FACTOR
        );
        assert_eq!(config.first_byte_timeout, FRONT_DOOR_FIRST_BYTE_TIMEOUT);
        let tuned = config
            .with_client_figures(1, 2, 3)
            .with_first_byte_timeout(Duration::from_secs(1));
        assert_eq!(
            (tuned.per_client_per_name, tuned.per_client, tuned.per_v6_48),
            (1, 2, 3)
        );
        assert_eq!(tuned.first_byte_timeout, Duration::from_secs(1));
    }

    #[test]
    fn one_client_is_held_to_its_figures_to_a_name_and_in_all() {
        let counters = Arc::new(ShareCounters::default());
        let ali = tenant("ali");
        let l = ShareLimits {
            per_client_name: 2,
            per_client: 3,
            ..limits(100, 100, 100)
        };
        let a1 = counters.try_acquire("a.ali", &ali, client(1), l).unwrap();
        let _a2 = counters.try_acquire("a.ali", &ali, client(1), l).unwrap();
        assert!(
            counters.try_acquire("a.ali", &ali, client(1), l).is_none(),
            "a third connection of one client to one name"
        );
        let _b = counters.try_acquire("b.ali", &ali, client(1), l).unwrap();
        assert!(
            counters.try_acquire("c.ali", &ali, client(1), l).is_none(),
            "a fourth connection of one client in all"
        );
        let _other = counters
            .try_acquire("a.ali", &ali, client(2), l)
            .expect("another client is not affected");
        drop(a1);
        assert!(counters.try_acquire("c.ali", &ali, client(1), l).is_some());
    }

    #[test]
    fn two_clients_cannot_lock_a_name_out_of_sixty_four() {
        let counters = Arc::new(ShareCounters::default());
        let ali = tenant("ali");
        let l = default_limits();
        let mut held = Vec::new();
        for who in [1u8, 2] {
            for _ in 0..FRONT_DOOR_PER_CLIENT_PER_NAME {
                held.push(
                    counters
                        .try_acquire("app.ali", &ali, client(who), l)
                        .unwrap(),
                );
            }
            assert!(
                counters
                    .try_acquire("app.ali", &ali, client(who), l)
                    .is_none(),
                "client {who} is at its figure for the name"
            );
        }
        assert!(l.per_name > 2 * FRONT_DOOR_PER_CLIENT_PER_NAME);
        assert!(
            counters
                .try_acquire("app.ali", &ali, client(3), l)
                .is_some(),
            "a third client still gets in"
        );
    }

    #[test]
    fn one_ipv6_48_cannot_fill_the_relay_wide_figure() {
        let counters = Arc::new(ShareCounters::default());
        let l = default_limits();
        let mut admitted = Vec::new();
        // One /48 (many /64s) trying many names, as the round's probe did.
        for lo in 0..2_000u16 {
            for name in 0..4 {
                for _ in 0..FRONT_DOOR_PER_CLIENT_PER_NAME {
                    let full = format!("n{name}.ali");
                    if let Some(slot) = counters.try_acquire(&full, &tenant("ali"), v6(1, lo), l) {
                        admitted.push(slot);
                    }
                }
            }
        }
        assert_eq!(admitted.len(), l.per_v6_48, "stopped at the /48 aggregate");
        assert!(
            l.per_v6_48 * 8 <= l.total,
            "far below the relay wide figure"
        );
        assert!(
            counters
                .try_acquire("n0.ali", &tenant("ali"), v6(2, 0), l)
                .is_some(),
            "another /48 is not locked out"
        );
        // Addresses of one /64 are one client.
        let same64 = PeerKey::of(IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 3, 3, 1, 2, 3, 4,
        )));
        assert_eq!(same64, v6(3, 3));
        // An IPv4 client has no /48.
        assert!(client(1).prefix48().is_none());
    }

    #[test]
    fn every_client_count_is_given_back_whichever_way_the_connection_ends() {
        let counters = Arc::new(ShareCounters::default());
        let l = default_limits();
        let slots: Vec<ShareSlot> = (0..6u16)
            .map(|i| {
                let who = if i % 2 == 0 { client(1) } else { v6(1, i) };
                counters
                    .try_acquire(&format!("n{}.ali", i % 3), &tenant("ali"), who, l)
                    .unwrap()
            })
            .collect();
        assert_eq!(counters.total(), 6);
        // Dropped out of order, as connections end.
        let mut slots = slots;
        drop(slots.remove(3));
        drop(slots.remove(0));
        drop(slots);
        let counts = counters.lock();
        assert_eq!(counts.total, 0);
        assert!(counts.per_name.is_empty());
        assert!(counts.per_tenant.is_empty());
        assert!(counts.per_client_name.is_empty());
        assert!(counts.per_client.is_empty());
        assert!(counts.per_v6_48.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_pipe_the_node_never_answers_ends_at_the_first_byte_timeout_however_busy_the_client()
    {
        let activity = Activity::new();
        let busy = async {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                activity.touch();
            }
        };
        let began = Instant::now();
        tokio::select! {
            () = went_idle(&activity, Duration::from_secs(600), Duration::from_secs(30)) => {}
            () = busy => unreachable!(),
        }
        let took = began.elapsed();
        assert!(
            took >= Duration::from_secs(30) && took < Duration::from_secs(31),
            "{took:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn once_the_node_has_spoken_the_long_idle_time_applies() {
        let activity = Activity::new();
        let speaker = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            activity.node_sent();
            activity.touch();
            std::future::pending::<()>().await;
        };
        let began = Instant::now();
        tokio::select! {
            () = went_idle(&activity, Duration::from_secs(100), Duration::from_secs(30)) => {}
            () = speaker => unreachable!(),
        }
        let took = began.elapsed();
        assert!(
            took >= Duration::from_secs(105) && took < Duration::from_secs(106),
            "{took:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_time_shorter_than_the_first_byte_time_applies_before_the_node_speaks() {
        let activity = Activity::new();
        let began = Instant::now();
        went_idle(&activity, Duration::from_secs(5), Duration::from_secs(30)).await;
        assert_eq!(began.elapsed(), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn only_bytes_read_from_the_node_count_as_its_first() {
        use tokio::io::duplex;
        for from_node in [false, true] {
            let activity = Activity::new();
            let (mut far, near) = duplex(64);
            let mut watched = Watched::new(near, Arc::clone(&activity), from_node);
            let mut buf = [0u8; 8];
            // An empty read (the far end closes) is not a byte.
            far.write_all(b"x").await.unwrap();
            drop(far);
            assert_eq!(watched.read(&mut buf).await.unwrap(), 1);
            assert_eq!(watched.read(&mut buf).await.unwrap(), 0);
            assert_eq!(
                activity.node_spoke.load(Ordering::Relaxed),
                from_node,
                "from_node {from_node}"
            );
        }
        // And a read of nothing from the node is not one.
        let activity = Activity::new();
        let (far, near) = duplex(64);
        drop(far);
        let mut watched = Watched::new(near, Arc::clone(&activity), true);
        assert_eq!(watched.read(&mut [0u8; 8]).await.unwrap(), 0);
        assert!(!activity.node_spoke.load(Ordering::Relaxed));
    }

    // -----------------------------------------------------------------------------------------
    // Expose round 2: the relay's own host (L1)
    // -----------------------------------------------------------------------------------------

    #[test]
    fn a_relay_host_under_the_share_domain_is_refused_at_startup() {
        assert!(FrontDoorConfig::new("edge.s.example.test", "s.example.test").is_err());
        assert!(FrontDoorConfig::new("Deep.Edge.S.Example.Test", "s.example.test").is_err());
        // Not under it: a sibling, the parent, a look alike suffix.
        for own in [
            "relay.example.test",
            "example.test",
            "edge.xs.example.test",
            "s.example.test.evil.test",
        ] {
            assert!(FrontDoorConfig::new(own, "s.example.test").is_ok(), "{own}");
        }
    }

    /// One request on port 80 against a door of `w`; what came back.
    async fn http_exchange(w: &World, request: &[u8]) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let slot = w.relay.admission.admit_connection(peer.ip()).unwrap();
        let peek = Arc::clone(&w.door.http_peeks).try_acquire_owned().unwrap();
        let handler = tokio::spawn(Arc::clone(&w.door).handle_http(
            w.relay.clone(),
            server,
            peer,
            slot,
            peek,
        ));
        client.write_all(request).await.unwrap();
        let mut response = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response)).await;
        let _ = handler.await;
        response
    }

    #[tokio::test]
    async fn a_challenge_for_the_relays_own_host_is_redirected_not_given_to_a_member() {
        let w = world(&["app"], None);
        w.attach();
        w.advertise(vec![share("app", ShareMode::Blind, "tls:app", &[])]);
        let own = http_exchange(
            &w,
            format!("GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: {OWN}\r\n\r\n")
                .as_bytes(),
        )
        .await;
        assert_eq!(
            own,
            redirect(OWN, "/.well-known/acme-challenge/tok").into_bytes(),
            "{}",
            String::from_utf8_lossy(&own)
        );
        // A challenge for a name nobody holds is still the fixed refusal.
        let unheld = http_exchange(
            &w,
            b"GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: nosuch.s.example.test\r\n\r\n",
        )
        .await;
        assert_eq!(unheld, HTTP_REFUSAL);
    }

    fn redirect(host: &str, path: &str) -> String {
        redirect_to(host, path)
    }

    // -----------------------------------------------------------------------------------------
    // Expose round 2: the head reader's work (L2)
    // -----------------------------------------------------------------------------------------

    #[test]
    fn the_incremental_head_scan_finds_what_a_whole_scan_finds_at_every_chunk_size() {
        let inputs: [&[u8]; 6] = [
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\r\n\r\n",
            b"A\r\n\r\r\n\r\nB\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: a\r\n",
            b"\r\n\r\n\r\n\r\n",
        ];
        for input in inputs {
            for chunk in 1..=7usize {
                let mut head = HeadBuffer::default();
                let mut found = None;
                let mut fed = 0usize;
                for piece in input.chunks(chunk) {
                    fed += piece.len();
                    let got = head.push(piece);
                    let whole = find_head_end_from(&input[..fed], 0);
                    assert_eq!(got, whole, "chunk {chunk}, {fed} bytes of {input:?}");
                    if got.is_some() {
                        found = got;
                        break;
                    }
                }
                assert_eq!(found, find_head_end_from(input, 0), "chunk {chunk}");
            }
        }
    }

    #[test]
    fn a_dribbled_head_costs_a_few_scans_per_byte_not_a_rescan_of_everything() {
        let mut head = HeadBuffer::default();
        for _ in 0..HTTP_HEAD_LIMIT {
            assert!(head.push(b"a").is_none());
        }
        assert!(
            head.scanned <= 4 * HTTP_HEAD_LIMIT,
            "{} positions scanned for {HTTP_HEAD_LIMIT} bytes",
            head.scanned
        );
    }
    #[test]
    fn the_descriptor_budget_is_the_sum_of_the_figures() {
        let config = FrontDoorConfig::new(OWN, H).unwrap();
        assert_eq!(config.fd_budget(true), 1_024 * 2 + 1_024 + 4_096);
        assert_eq!(config.fd_budget(false), 1_024 + 1_024 + 4_096);
        let small = config
            .with_max_peeks(3)
            .with_max_answers(5)
            .with_max_total(7);
        assert_eq!(small.fd_budget(true), 6 + 5 + 7);
        assert_eq!(small.fd_budget(false), 3 + 5 + 7);
    }

    // -----------------------------------------------------------------------------------------
    // Terminated names (S-E9b)
    // -----------------------------------------------------------------------------------------

    const T_HOST: &str = "web.ali.t.s.example.test";

    fn terminated_ali() -> TenantSpec {
        let mut spec = ali(&[]);
        spec.terminated = true;
        spec
    }

    /// A relay with ACME and a certificate for each of `hosts`, and the PEMs of the first.
    fn with_certs(w: &World, hosts: &[&str]) -> Relay {
        let config =
            crate::acme::AcmeConfig::new("https://ca.example.test/dir", "/nonexistent").unwrap();
        let relay = w
            .relay
            .clone()
            .with_acme(crate::acme::RelayAcme::new(config));
        for host in hosts {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed([host.to_string()]).unwrap();
            relay
                .acme()
                .unwrap()
                .certs()
                .install_pem(host, &cert.pem(), &signing_key.serialize_pem())
                .unwrap();
        }
        relay
    }

    /// Everything a terminated name needs: a flagged tenant, `web` advertised as `http:web`
    /// and accepted, the holder attached, the grant in the Roster, a certificate.
    fn terminated_world() -> (World, Relay) {
        let w = world(&["web", "app"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![
            share("web", ShareMode::Terminated, "http:web", &[]),
            share("app", ShareMode::Blind, "tls:app", &[]),
        ]);
        let relay = with_certs(&w, &[T_HOST, "app.ali.t.s.example.test"]);
        (w, relay)
    }

    fn t_resolve(w: &World, relay: &Relay, host: &str) -> Option<(Resolved, Arc<CertifiedKey>)> {
        w.door.resolve_terminated(relay, host, &[])
    }

    fn t_route(w: &World, relay: &Relay, host: &str, alpn: &[&[u8]]) -> Route {
        w.door.route(relay, &hello(Some(host), alpn))
    }

    #[tokio::test]
    async fn a_terminated_name_with_every_precondition_routes() {
        let (w, relay) = terminated_world();
        let (resolved, _cert) = t_resolve(&w, &relay, T_HOST).expect("resolves");
        assert_eq!(resolved.name, "web.ali");
        assert_eq!(resolved.service().to_string(), "http:web");
        assert!(matches!(
            t_route(&w, &relay, T_HOST, &[]),
            Route::Terminated(_, ref host, _) if host == T_HOST
        ));
    }

    #[tokio::test]
    async fn each_missing_precondition_of_a_terminated_name_is_the_one_refusal() {
        // (the refusal is `Route::Refuse`: `handle_tls` sends the 7 byte alert for it, like
        // for every other failure)
        let refused = |w: &World, relay: &Relay, what: &str| {
            assert!(
                matches!(t_route(w, relay, T_HOST, &[]), Route::Refuse),
                "{what}"
            );
        };
        // the tenant's `terminated` flag
        let w = world(&["web"], Some(ali(&[])));
        w.attach();
        w.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        let relay = with_certs(&w, &[T_HOST]);
        refused(&w, &relay, "tenant without the flag");
        // the default tenant never has it
        let w = world(&["web"], None);
        w.attach();
        w.advertise(vec![share("web", ShareMode::Terminated, "http:web", &[])]);
        let relay = with_certs(&w, &["web.t.s.example.test"]);
        assert!(matches!(
            t_route(&w, &relay, "web.t.s.example.test", &[]),
            Route::Refuse
        ));
        // a certificate for exactly that name
        let (w, _relay) = terminated_world();
        let no_cert = with_certs(&w, &["other.ali.t.s.example.test"]);
        refused(&w, &no_cert, "no certificate for the name");
        let no_acme = w.relay.clone();
        refused(&w, &no_acme, "no ACME at all");
        // the fallback certificate of the relay's own host is no certificate for a share name
        let fallback = with_certs(&w, &[]);
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed([OWN.to_string()]).unwrap();
        fallback
            .acme()
            .unwrap()
            .certs()
            .set_fallback_pem(&cert.pem(), &signing_key.serialize_pem())
            .unwrap();
        refused(&w, &fallback, "only a fallback certificate");
        // the Roster still granting the label
        let (w, relay) = terminated_world();
        w.roster(2, &[w.node], &[]);
        refused(&w, &relay, "grant withdrawn");
        // the holder attached
        let (w, relay) = terminated_world();
        assert!(w.relay.registry.detach(&w.node, 1));
        refused(&w, &relay, "holder detached");
        // the share accepted as `http:` (a blind share under the same label is no terminated one)
        let w = world(&["web"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![share("web", ShareMode::Blind, "tls:web", &[])]);
        let relay = with_certs(&w, &[T_HOST]);
        refused(&w, &relay, "blind share");
        // a blind share that names an `http:` service is no terminated one either
        let w = world(&["web"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![share("web", ShareMode::Blind, "http:web", &[])]);
        let relay = with_certs(&w, &[T_HOST]);
        refused(&w, &relay, "blind share with an http service");
        // a certificate for another name serves nothing here
        let w = world(&["web", "app"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![
            share("web", ShareMode::Terminated, "http:web", &[]),
            share("app", ShareMode::Terminated, "http:app", &[]),
        ]);
        let relay = with_certs(&w, &[T_HOST]);
        assert!(matches!(
            t_route(&w, &relay, T_HOST, &[]),
            Route::Terminated(..)
        ));
        assert!(matches!(
            t_route(&w, &relay, "app.ali.t.s.example.test", &[]),
            Route::Refuse
        ));
        let w = world(&["web"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![share("web", ShareMode::Terminated, "tcp:web", &[])]);
        let relay = with_certs(&w, &[T_HOST]);
        refused(&w, &relay, "terminated share of another service kind");
        let w = world(&["web"], Some(terminated_ali()));
        w.attach();
        let relay = with_certs(&w, &[T_HOST]);
        refused(&w, &relay, "nothing advertised");
        // the network not held back
        let (w, relay) = terminated_world();
        let mut spec = terminated_ali();
        spec.networks = vec![w.network];
        relay.set_tenants(TenantBook::build(
            vec![spec],
            Vec::new(),
            &HashSet::new(),
            &HashSet::from(["ali".to_string()]),
        ));
        assert!(relay.tenants().is_held_back(&w.network));
        refused(&w, &relay, "network held back");
        // ALPN `acme-tls/1` offered
        let (w, relay) = terminated_world();
        assert!(matches!(
            t_route(&w, &relay, T_HOST, &[b"acme-tls/1"]),
            Route::Refuse
        ));
    }

    #[tokio::test]
    async fn the_blind_and_the_terminated_zone_never_resolve_each_others_names() {
        let (w, relay) = terminated_world();
        // a terminated share is not blind-routable, and a blind share is not terminated
        assert!(
            w.door
                .resolve(&relay, "web.ali.s.example.test", &[])
                .is_none()
        );
        assert!(
            t_resolve(&w, &relay, "app.ali.t.s.example.test").is_none(),
            "a blind share under the terminated zone, with a certificate"
        );
        assert!(
            w.door
                .resolve(&relay, "app.ali.s.example.test", &[])
                .is_some()
        );
        assert!(matches!(
            t_route(&w, &relay, "app.ali.t.s.example.test", &[]),
            Route::Refuse
        ));
        assert!(matches!(
            t_route(&w, &relay, "web.ali.s.example.test", &[]),
            Route::Refuse
        ));
        // the zone label `t` is nobody's blind name
        for host in [
            "t.s.example.test",
            "app.t.s.example.test",
            "app.ali.t.s.example.test.evil",
            "ali.t.s.example.test",
            "x.web.ali.t.s.example.test",
            "web.t.ali.s.example.test",
        ] {
            assert!(w.door.resolve(&relay, host, &[]).is_none(), "{host} blind");
            assert!(t_resolve(&w, &relay, host).is_none(), "{host} terminated");
        }
        // another tenant's zone, and the flat name of the default tenant
        assert!(t_resolve(&w, &relay, "web.bob.t.s.example.test").is_none());
        assert!(t_resolve(&w, &relay, "web.t.s.example.test").is_none());
        // a blind share named like a terminated label of the same tenant is still blind only
        let w = world(&["web"], Some(terminated_ali()));
        w.attach();
        w.advertise(vec![share("web", ShareMode::Blind, "tls:web", &[])]);
        let relay = with_certs(&w, &[T_HOST]);
        assert!(
            w.door
                .resolve(&relay, "web.ali.s.example.test", &[])
                .is_some()
        );
        assert!(t_resolve(&w, &relay, T_HOST).is_none());
    }

    #[tokio::test]
    async fn the_terminated_tls_configuration_serves_exactly_the_name_asked() {
        use rustls::pki_types::ServerName;
        let (w, relay) = terminated_world();
        // the book's fallback (the relay's own host) must never answer a share name
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed([OWN.to_string()]).unwrap();
        relay
            .acme()
            .unwrap()
            .certs()
            .set_fallback_pem(&cert.pem(), &signing_key.serialize_pem())
            .unwrap();
        let config = w.door.terminated_config(&relay).expect("config");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let (_, held) = t_resolve(&w, &relay, T_HOST).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(held.cert[0].clone()).unwrap();
        roots.add(cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let handshake = |name: &'static str| {
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&config));
            let connector = connector.clone();
            async move {
                let (c, s) = tokio::io::duplex(1 << 16);
                let (server, client) = tokio::join!(
                    acceptor.accept(s),
                    connector.connect(ServerName::try_from(name).unwrap(), c)
                );
                (server.is_ok(), client.is_ok())
            }
        };
        assert_eq!(handshake("web.ali.t.s.example.test").await, (true, true));
        // a name with no certificate of its own gets no handshake, not the fallback
        assert_eq!(
            handshake("nobody.ali.t.s.example.test").await,
            (false, false)
        );
        assert_eq!(handshake("relay.example.test").await, (false, false));
    }

    #[test]
    fn the_http_limits_are_the_terminators_defaults_unless_set() {
        let config = FrontDoorConfig::new(OWN, H).unwrap();
        assert_eq!(config.http, HttpLimits::default());
        let set = HttpLimits {
            head_timeout: Duration::from_secs(1),
            keepalive_idle: Duration::from_secs(2),
            body_idle: Duration::from_secs(3),
        };
        assert_eq!(config.with_http_limits(set).http, set);
    }
}
