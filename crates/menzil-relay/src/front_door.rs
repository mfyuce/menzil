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
//!   the raw bytes, ClientHello included, are piped both ways. Terminated (`http:`) shares are
//!   not served here.
//! * anything else: the one static refusal below.
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use menzil_proto::{OpenMeta, ServiceId, ServiceKind, ShareMode};
use menzil_stream::Stream;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional_with_sizes,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::admission::IpSlot;
use crate::advertise::HeldName;
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
    /// lowercased. The two may not be equal.
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
        })
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
}

// ---------------------------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Counts {
    per_name: HashMap<String, usize>,
    per_tenant: HashMap<TenantId, usize>,
    total: usize,
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
}

/// The figures one acquisition is held to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ShareLimits {
    pub(crate) per_name: usize,
    pub(crate) per_tenant: usize,
    pub(crate) total: usize,
}

impl ShareCounters {
    fn lock(&self) -> MutexGuard<'_, Counts> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes a place for a connection to `name` of `tenant`, unless the name, the tenant or the
    /// relay is at its figure.
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
        name: &str,
        tenant: &TenantId,
        limits: ShareLimits,
    ) -> Option<ShareSlot> {
        let mut counts = self.lock();
        if counts.total >= limits.total
            || counts.per_name.get(name).copied().unwrap_or(0) >= limits.per_name
            || counts.per_tenant.get(tenant).copied().unwrap_or(0) >= limits.per_tenant
        {
            return None;
        }
        counts.total += 1;
        *counts.per_name.entry(name.to_string()).or_insert(0) += 1;
        *counts.per_tenant.entry(tenant.clone()).or_insert(0) += 1;
        drop(counts);
        Some(ShareSlot {
            counters: Arc::clone(self),
            name: name.to_string(),
            tenant: tenant.clone(),
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
        if let Some(n) = counts.per_name.get_mut(&self.name) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.per_name.remove(&self.name);
            }
        }
        if let Some(n) = counts.per_tenant.get_mut(&self.tenant) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.per_tenant.remove(&self.tenant);
            }
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
    /// network that granted it. `alpn` is what the client offered.
    fn resolve(&self, relay: &Relay, host: &str, alpn: &[Vec<u8>]) -> Option<Resolved> {
        let name = host.strip_suffix(self.suffix.as_str())?;
        if name.is_empty() || name.split('.').count() > 2 {
            return None;
        }
        let held = relay.labels().held_name(name, unix_now())?;
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
        if !routable(held.share.mode, held.share.service.kind) {
            return None;
        }
        if alpn.iter().any(|offered| offered == ACME_TLS_ALPN)
            && !held
                .share
                .alpn
                .iter()
                .any(|a| a.as_bytes() == ACME_TLS_ALPN)
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
        drop(peek);
        let decided = Instant::now();
        let (bytes, hello) = match peeked {
            Peeked::Dropped => return,
            Peeked::Invalid(why) => {
                tracing::debug!(?why, "not a routable ClientHello");
                drop(ip_slot);
                self.refuse(tcp, decided, &REFUSAL).await;
                return;
            }
            Peeked::Hello { bytes, hello } => (bytes, hello),
        };
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
        }
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
        let Some(slot) =
            self.counters
                .try_acquire(&resolved.name, &resolved.tenant, resolved.limits)
        else {
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
        let mut remote = Watched::new(TokioStream(stream), Arc::clone(&activity));
        let mut local = Watched::new(tcp, Arc::clone(&activity));
        let idle = self.config.idle_timeout;
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
            () = went_idle(&activity, idle) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no byte moved for the idle timeout",
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
        if path.starts_with(ACME_PATH) {
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
        let mut bytes: Vec<u8> = Vec::with_capacity(1024);
        let mut chunk = [0u8; 2048];
        loop {
            if let Some(end) = find_head_end(&bytes) {
                let head = parse_head(&bytes[..end])?;
                return Some((bytes, head));
            }
            let room = (HTTP_HEAD_LIMIT - bytes.len()).min(chunk.len());
            if room == 0 {
                return None;
            }
            match tcp.read(&mut chunk[..room]).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            }
        }
    };
    tokio::time::timeout(deadline, read).await.ok().flatten()
}

/// The length of the head including its blank line, if `bytes` holds one.
fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
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

/// When something last moved through a pipe, as milliseconds since the pipe began.
struct Activity {
    began: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            began: Instant::now(),
            last_ms: AtomicU64::new(0),
        })
    }

    fn touch(&self) {
        let ms = u64::try_from(self.began.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(ms, Ordering::Relaxed);
    }
}

/// Completes when nothing has moved for `idle`.
async fn went_idle(activity: &Activity, idle: Duration) {
    loop {
        let last = activity.last_ms.load(Ordering::Relaxed);
        tokio::time::sleep_until(activity.began + Duration::from_millis(last) + idle).await;
        if activity.last_ms.load(Ordering::Relaxed) == last {
            return;
        }
    }
}

/// An I/O object that records every read and write that moved something.
struct Watched<T> {
    inner: T,
    activity: Arc<Activity>,
}

impl<T> Watched<T> {
    fn new(inner: T, activity: Arc<Activity>) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) {
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
mod tests {
    use super::*;

    fn tenant(slug: &str) -> TenantId {
        TenantId::Named(crate::tenant::Slug::parse(slug).unwrap())
    }

    fn limits(per_name: usize, per_tenant: usize, total: usize) -> ShareLimits {
        ShareLimits {
            per_name,
            per_tenant,
            total,
        }
    }

    #[test]
    fn the_counters_hold_each_figure_and_give_every_place_back() {
        let counters = Arc::new(ShareCounters::default());
        let ali = tenant("ali");
        let veli = tenant("veli");
        let l = limits(2, 3, 100);
        let a1 = counters.try_acquire("app.ali", &ali, l).unwrap();
        let a2 = counters.try_acquire("app.ali", &ali, l).unwrap();
        assert!(
            counters.try_acquire("app.ali", &ali, l).is_none(),
            "the third connection to one name is over its figure"
        );
        let b1 = counters.try_acquire("blog.ali", &ali, l).unwrap();
        assert!(
            counters.try_acquire("wiki.ali", &ali, l).is_none(),
            "the fourth connection of one tenant is over its figure"
        );
        let other = counters.try_acquire("app.veli", &veli, l).unwrap();
        assert_eq!(counters.of_name("app.ali"), 2);
        assert_eq!(counters.of_tenant(&ali), 3);
        assert_eq!(counters.total(), 4);
        drop(a1);
        let again = counters
            .try_acquire("wiki.ali", &ali, l)
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
        let _a = counters.try_acquire("a.ali", &tenant("ali"), l).unwrap();
        let _b = counters.try_acquire("b.veli", &tenant("veli"), l).unwrap();
        assert!(counters.try_acquire("c.deli", &tenant("deli"), l).is_none());
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

    const OWN: &str = "relay.example.test";
    const H: &str = "s.example.test";

    struct World {
        relay: Relay,
        door: Arc<FrontDoor>,
        node: NodeId,
        network: NetworkId,
    }

    fn relay() -> Relay {
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

    fn share(name: &str, mode: ShareMode, service: &str, alpn: &[&str]) -> Share {
        Share {
            name: name.to_string(),
            mode,
            service: service.parse().unwrap(),
            alpn: alpn.iter().map(|a| a.to_string()).collect(),
        }
    }

    fn world(labels: &[&str], tenants: Option<TenantSpec>) -> World {
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
        }
    }

    impl World {
        fn attach(&self) {
            // Kept alive by leaking the receivers: the registration is what is looked at.
            let held = self.relay.registry.attach(self.node, 1, vec![self.network]);
            std::mem::forget(held);
        }

        fn advertise(&self, shares: Vec<Share>) -> menzil_proto::AdvertiseAckBody {
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

        fn resolve(&self, host: &str, alpn: &[&[u8]]) -> Option<Resolved> {
            let alpn: Vec<Vec<u8>> = alpn.iter().map(|a| a.to_vec()).collect();
            self.door.resolve(&self.relay, host, &alpn)
        }
    }

    fn ali(overrides: &[(&str, u64)]) -> TenantSpec {
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
}
