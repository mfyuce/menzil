//! Serving accepted streams (TODO.md L4i): [`LocalServices`] maps the
//! services a node offers to local targets and pipes a granted stream to
//! the target.
//!
//! It is the [`ServiceHandler`] a node is started with (`Node::start`) when it should serve
//! something. The grant check has already run when it is asked
//! ([`crate::PolicyAuthorizer`]), so a peer learns nothing about what is
//! configured beyond the services it holds a grant for.
//!
//! * **What is served.** `tcp:`, `http:` and `tls:` services, each backed
//!   by one explicitly configured `host:port` (protocol.md 2.4: a label
//!   never maps implicitly to a port on localhost). All three are a byte
//!   pipe to a TCP socket here; what the bytes mean (HTTP, a TLS the target
//!   itself speaks) is between the peer and the target. Terminating TLS for
//!   public shares, `udp:`, `egress:`, `acme-http:` and `menzil:docs` are
//!   other items' work; configuring one of them is refused, and an OPEN for
//!   one is answered `unknown_service`. `egress:*` is the exception that is not a table
//!   entry: with an [`EgressExecutor`] ([`LocalServices::with_egress`]) a counted peer OPEN
//!   for it is dialled by the executor's own rules (protocol.md 8, `crate::egress`), with
//!   the same slots and pipe; the relay principal's path, and a node without an enabled
//!   executor, answer it `unknown_service`.
//! * **The local connect comes before the OPEN_ACK.** [`Self::open`]
//!   (`ServiceHandler::open`) connects to the target inside the caller's 10
//!   second OPEN timeout, with its own, shorter limit
//!   ([`DEFAULT_CONNECT_TIMEOUT`], never more than [`MAX_CONNECT_TIMEOUT`]). A target that
//!   refuses or does not answer is an OPEN_ACK `ok: false` with `target_unreachable`, never an
//!   accepted stream that ends at once, and the peer's `msg` says nothing of
//!   the local address or error (the log does). Only after the ack does the
//!   pipe start.
//! * **A clean end and an abnormal end.** The pipe is two directions with
//!   half-close: a FIN from the peer shuts down the target socket's write
//!   side and a FIN from the target closes the stream's, and the pipe is
//!   over when both directions are (protocol.md 5.3). Anything else is
//!   abnormal and resets both ends, so that truncation is visible
//!   (protocol.md 5.2, 5.3): an error on the target socket resets the
//!   stream, a reset stream (the peer's RST, or the L4 session lost under
//!   it) resets the target socket (`SO_LINGER` of zero, an RST on the wire),
//!   and so does the pipe being dropped before it finished (the node shutting down), and a
//!   connection that was made but never piped (the ack could not be written, the OPEN
//!   timed out after the connect, the handler future was dropped before it ran).
//!   A copy that waits on the target does not poll the stream, so the stream's teardown
//!   is watched separately (`menzil_stream::Stream::torn_down`): without it a peer's RST
//!   after its FIN, or the loss of the session, would reach a silent target never.
//! * **What a peer can make the node hold** ([`ServeLimits`]). Every served connection takes
//!   a slot of a node-wide count and of its peer's own count (by initiating node), taken
//!   before the target is connected to; an OPEN past either is refused with `rate_limited`
//!   and costs nothing but the refusal. The target sockets get fixed, small kernel buffers
//!   (set before the connect, which also stops the kernel autotuning them: a target that
//!   does not read otherwise lets a peer pile up megabytes per stream in the kernel, measured
//!   4.66 MiB). A hostname target is resolved on a blocking thread, at most four lookups at a
//!   time, and a lookup the OPEN timeout gave up on keeps its place until it returns. The
//!   log lines a peer can repeat as fast as it can send OPENs are throttled to one per
//!   interval with a count of the ones left out.
//! * **Not bounded here.** A pipe has no idle timeout and a service no limit of its own (the
//!   TODO.md line); the streams a session may hold are bounded by `menzil-stream`'s live
//!   stream limit and the OPEN admission control of [`crate::accept_loop`]. A target that
//!   stalls forever holds its stream and its slot until the peer ends it.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::io::{AsyncRead, AsyncWrite};
use menzil_proto::{ErrorCode, NodeId, ServiceId, ServiceKind};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use thiserror::Error;
use tokio::io::{ReadBuf, copy_bidirectional_with_sizes};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::egress::EgressExecutor;
use crate::l5_stream::OPEN_TIMEOUT;

/// How long [`LocalServices`] waits for the local connect by default. Well
/// inside the 10 second OPEN timeout the peer runs (protocol.md 5.3), so a
/// dead target is answered with a refusal rather than a timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest connect timeout [`LocalServices::with_connect_timeout`] accepts: a second short
/// of the OPEN timeout the peer runs, so that a refusal can still be written and read in time.
pub const MAX_CONNECT_TIMEOUT: Duration = OPEN_TIMEOUT.saturating_sub(Duration::from_secs(1));

/// How many connections [`LocalServices`] serves at once, all peers together, by default. A
/// descriptor each, and with the usual soft limit of 1,024 per process a node has to keep well
/// below it.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// How many connections one peer (an initiating node) may hold at once by default. Low enough
/// that one member cannot fill a target's own connection limit (sshd's `MaxStartups`, a
/// database's `max_connections`) or the node-wide count.
pub const DEFAULT_MAX_CONNECTIONS_PER_PEER: usize = 64;

/// The size asked for the send and receive buffer of each target socket, by default. The kernel
/// doubles it, so each socket can hold about twice this in each direction.
pub const DEFAULT_SOCKET_BUFFER: u32 = 128 * 1024;

/// How many hostname lookups may run on blocking threads at once.
const MAX_CONCURRENT_LOOKUPS: usize = 4;

/// The least time between two log lines for the same kind of refusal.
pub(crate) const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// The size of each direction's copy buffer: one `yamux` data frame
/// (`menzil-stream` keeps its 16 KiB default).
const PIPE_BUFFER: usize = 16 * 1024;

/// A local `host:port` a service is served from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTarget {
    host: String,
    port: u16,
}

impl LocalTarget {
    /// A target at `host` (a name or an address) and `port`.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    /// The host, as configured.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Display for LocalTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why a service could not be configured.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServeConfigError {
    /// Only `tcp:`, `http:` and `tls:` services are served from a local
    /// target in this version.
    #[error("services of kind {0} cannot be served from a local target")]
    UnsupportedKind(ServiceKind),
    /// A service is one exact label; `*` only means something in a grant.
    #[error("a served service needs an exact label, not {0:?}")]
    WildcardLabel(String),
    /// The label was empty.
    #[error("a served service needs a label")]
    EmptyLabel,
}

/// What a node serving local targets holds for its peers at most. See the module documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeLimits {
    /// Connections served at once, all peers together. At least 1.
    pub max_connections: usize,
    /// Connections served at once for one peer. At least 1.
    pub max_connections_per_peer: usize,
    /// `SO_SNDBUF` and `SO_RCVBUF` asked for each target socket, in bytes (the kernel doubles
    /// the value and has a floor of its own).
    pub socket_buffer: u32,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_connections_per_peer: DEFAULT_MAX_CONNECTIONS_PER_PEER,
            socket_buffer: DEFAULT_SOCKET_BUFFER,
        }
    }
}

/// The services a node offers and the local targets behind them. See the
/// module documentation.
///
/// A clone shares the connection counts, the lookup limit and the log throttles with the
/// original (they belong to the node), so run one set per node. It shares the table of services
/// too: [`Self::set_target`] and [`Self::remove_target`] on one handle take effect for every
/// clone, including the one a running node serves from (`menzil expose` adds and removes a
/// service while the node runs).
#[derive(Debug, Clone)]
pub struct LocalServices {
    targets: Arc<RwLock<HashMap<ServiceId, LocalTarget>>>,
    connect_timeout: Duration,
    limits: ServeLimits,
    slots: Arc<Slots>,
    lookups: Arc<Semaphore>,
    /// For the refusals past a limit, and for the connects that failed; apart, so that a flood
    /// of one does not hide the other.
    full_log: Arc<LogThrottle>,
    connect_log: Arc<LogThrottle>,
    resolve: Resolve,
    /// The exit side of `egress:*` ([`Self::with_egress`]); none serves no egress.
    egress: Option<Arc<EgressExecutor>>,
}

/// Resolves a host name to addresses. Blocking, so it runs on a blocking thread.
type Resolve = fn(&str, u16) -> io::Result<Vec<SocketAddr>>;

pub(crate) fn system_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok((host, port).to_socket_addrs()?.collect())
}

impl Default for LocalServices {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalServices {
    /// A node that serves nothing yet.
    pub fn new() -> Self {
        let limits = ServeLimits::default();
        Self {
            targets: Arc::new(RwLock::new(HashMap::new())),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            slots: Slots::new(&limits),
            limits,
            lookups: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
            full_log: Arc::new(LogThrottle::new(LOG_INTERVAL)),
            connect_log: Arc::new(LogThrottle::new(LOG_INTERVAL)),
            resolve: system_resolve,
            egress: None,
        }
    }

    /// Serves `service` from `target`, replacing what it was served from
    /// before. Refused for a kind other than `tcp`, `http` and `tls`, and
    /// for a label that is empty or `*`.
    pub fn serve(self, service: ServiceId, target: LocalTarget) -> Result<Self, ServeConfigError> {
        self.set_target(service, target)?;
        Ok(self)
    }

    /// [`Self::serve`] on a handle that is already in use: the change is seen by every clone, so
    /// by a running node, from the next OPEN on. A connection already piped is not touched.
    pub fn set_target(
        &self,
        service: ServiceId,
        target: LocalTarget,
    ) -> Result<(), ServeConfigError> {
        if !matches!(
            service.kind,
            ServiceKind::Tcp | ServiceKind::Http | ServiceKind::Tls
        ) {
            return Err(ServeConfigError::UnsupportedKind(service.kind));
        }
        if service.label.is_empty() {
            return Err(ServeConfigError::EmptyLabel);
        }
        if service.label == "*" {
            return Err(ServeConfigError::WildcardLabel(service.label));
        }
        self.targets_mut().insert(service, target);
        Ok(())
    }

    /// Stops serving `service`: the next OPEN for it is refused `unknown_service`. Whether it was
    /// served. A connection already piped is not touched (a share's streams are reset by the
    /// node when the share is withdrawn, not here).
    pub fn remove_target(&self, service: &ServiceId) -> bool {
        self.targets_mut().remove(service).is_some()
    }

    fn targets_ref(&self) -> std::sync::RwLockReadGuard<'_, HashMap<ServiceId, LocalTarget>> {
        // The table is plain data replaced entry by entry: a panic elsewhere leaves it usable.
        self.targets.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn targets_mut(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<ServiceId, LocalTarget>> {
        self.targets.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Gives up on the local connect after `timeout` instead of
    /// [`DEFAULT_CONNECT_TIMEOUT`], but never after more than [`MAX_CONNECT_TIMEOUT`]: a peer
    /// gives up on its OPEN after 10 seconds, and a refusal that arrives later is lost.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout.min(MAX_CONNECT_TIMEOUT);
        self
    }

    /// Serves `egress:*` through `executor` (protocol.md 8), for counted peer OPENs only: the
    /// relay principal's path refuses it. An executor that is not [`EgressExecutor::enabled`]
    /// serves nothing, like none. It takes its places from the same [`ServeLimits`] as the
    /// local services. A local service table never maps egress ([`Self::set_target`] refuses it).
    pub fn with_egress(mut self, executor: EgressExecutor) -> Self {
        self.egress = Some(Arc::new(executor));
        self
    }

    /// Replaces the default [`ServeLimits`]. Values of zero count as 1, and a total past
    /// what a semaphore can hold (about 2^61, far more than any process has descriptors for)
    /// is cut to that: it used to panic. Starts the counts afresh, so call it while
    /// configuring, before the node runs.
    pub fn with_limits(mut self, limits: ServeLimits) -> Self {
        let limits = ServeLimits {
            max_connections: limits.max_connections.clamp(1, Semaphore::MAX_PERMITS),
            max_connections_per_peer: limits.max_connections_per_peer.max(1),
            socket_buffer: limits.socket_buffer,
        };
        self.slots = Slots::new(&limits);
        self.limits = limits;
        self
    }

    /// The target `service` is served from, if it is.
    pub fn target(&self, service: &ServiceId) -> Option<LocalTarget> {
        self.targets_ref().get(service).cloned()
    }

    /// How many services are configured.
    pub fn len(&self) -> usize {
        self.targets_ref().len()
    }

    /// Whether nothing is configured.
    pub fn is_empty(&self) -> bool {
        self.targets_ref().is_empty()
    }

    /// The connect timeout in force.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// The limits in force.
    pub fn limits(&self) -> ServeLimits {
        self.limits
    }

    /// How many connections are being served now.
    pub fn connections(&self) -> usize {
        self.slots.in_use()
    }

    /// Connects to `target`: resolves the host if it is a name, then tries each address in
    /// turn, as `TcpStream::connect` does, with the socket's buffers fixed before the connect.
    async fn connect(&self, target: &LocalTarget) -> io::Result<TcpStream> {
        let mut last = None;
        for addr in self.resolve(target).await? {
            match connect_addr(addr, self.limits.socket_buffer).await {
                Ok(socket) => return Ok(socket),
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "the target name has no address")
        }))
    }

    /// The addresses of `target`. An address needs no lookup. A name is looked up on a blocking
    /// thread that owns its place among [`MAX_CONCURRENT_LOOKUPS`] until it returns, however
    /// long that takes and whether or not the OPEN is still waiting for it.
    async fn resolve(&self, target: &LocalTarget) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = target.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, target.port)]);
        }
        let permit = self
            .lookups
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("the lookup limit was closed"))?;
        let (host, port, resolve) = (target.host.clone(), target.port, self.resolve);
        tokio::task::spawn_blocking(move || {
            let result = resolve(&host, port);
            drop(permit);
            result
        })
        .await
        .map_err(io::Error::other)?
    }
}

/// A socket connected to `addr`, with fixed `buffer` sizes. The sizes are set before the
/// connect: that is what stops the kernel from tuning them upward, and it fixes the window the
/// connection starts with.
pub(crate) async fn connect_addr(addr: SocketAddr, buffer: u32) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    socket.set_send_buffer_size(buffer)?;
    socket.set_recv_buffer_size(buffer)?;
    let stream = socket.connect(addr).await?;
    // Interactive services (a shell) must not wait for Nagle.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

fn refusal(code: ErrorCode, msg: &str) -> OpenRefusal {
    OpenRefusal {
        code,
        msg: msg.to_string(),
    }
}

impl LocalServices {
    /// Takes the place a counted open holds, before anything is connected to or looked up: a
    /// peer past a limit costs the refusal. An open that is counted elsewhere (the relay
    /// principal's) takes no place here.
    fn take_slot(&self, request: &OpenRequest, counted: bool) -> Result<Option<Slot>, OpenRefusal> {
        if !counted {
            return Ok(None);
        }
        match self.slots.take(request.initiator) {
            Ok(slot) => Ok(Some(slot)),
            Err(full) => {
                if let Some(left_out) = self.full_log.permit(Instant::now()) {
                    tracing::warn!(
                        service = %request.service,
                        peer = %request.initiator,
                        ?full,
                        left_out,
                        "refused an OPEN: a limit on served connections is reached"
                    );
                }
                Err(refusal(ErrorCode::RateLimited, "too many connections"))
            }
        }
    }

    /// An `egress:*` OPEN (protocol.md 8). Only a counted peer open reaches the executor; the
    /// relay principal's, and every open while egress is off, is `unknown_service`, the answer
    /// for a service this node does not serve.
    async fn open_egress(
        &self,
        request: &OpenRequest,
        counted: bool,
    ) -> Result<OpenedTarget, OpenRefusal> {
        let Some(executor) = self
            .egress
            .as_ref()
            .filter(|executor| counted && executor.enabled())
        else {
            return Err(refusal(ErrorCode::UnknownService, "no such service"));
        };
        if request.service.label != "*" {
            return Err(refusal(ErrorCode::UnknownService, "no such service"));
        }
        let slot = self.take_slot(request, counted)?;
        let socket = executor
            .dial(request, self.limits.socket_buffer, self.connect_timeout)
            .await?;
        Ok(OpenedTarget {
            socket: Some(socket),
            slot,
        })
    }

    async fn open_target(
        &self,
        request: &OpenRequest,
        counted: bool,
    ) -> Result<OpenedTarget, OpenRefusal> {
        if request.service.kind == ServiceKind::Egress {
            return self.open_egress(request, counted).await;
        }
        // Looked up once, before any await: a service removed meanwhile does not hold the table.
        let Some(target) = self.target(&request.service) else {
            return Err(refusal(ErrorCode::UnknownService, "no such service"));
        };
        let target = &target;
        let slot = self.take_slot(request, counted)?;
        let connect = self.connect(target);
        match tokio::time::timeout(self.connect_timeout, connect).await {
            Ok(Ok(socket)) => Ok(OpenedTarget {
                socket: Some(socket),
                slot,
            }),
            Ok(Err(error)) => {
                if let Some(left_out) = self.connect_log.permit(Instant::now()) {
                    tracing::info!(
                        service = %request.service,
                        target = %target,
                        %error,
                        left_out,
                        "the local target refused a connection for a granted OPEN"
                    );
                }
                Err(refusal(
                    ErrorCode::TargetUnreachable,
                    "could not connect to the local target",
                ))
            }
            Err(_) => {
                if let Some(left_out) = self.connect_log.permit(Instant::now()) {
                    tracing::info!(
                        service = %request.service,
                        target = %target,
                        left_out,
                        "the local target did not answer in time for a granted OPEN"
                    );
                }
                Err(refusal(
                    ErrorCode::TargetUnreachable,
                    "the local target did not answer in time",
                ))
            }
        }
    }
}

impl ServiceHandler<Stream> for LocalServices {
    type Opened = OpenedTarget;
    type Handling = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<OpenedTarget, OpenRefusal> {
        self.open_target(request, true).await
    }

    /// Without a place in this node's [`ServeLimits`]: the caller (the relay principal's
    /// handler) bounds what it holds by figures of its own.
    async fn open_with_own_limits(
        &self,
        request: &OpenRequest,
    ) -> Result<OpenedTarget, OpenRefusal> {
        self.open_target(request, false).await
    }

    fn handle(&self, stream: Stream, request: OpenRequest, opened: OpenedTarget) -> Self::Handling {
        self.handle_with_prefix(stream, request, opened, Vec::new())
    }
}

impl LocalServices {
    /// [`ServiceHandler::handle`] for a stream of which the first bytes were already read (the
    /// ClientHello the ACME responder looked at, `crate::acme`): `prefix` is written to the
    /// target before the pipe starts, so the target sees the stream whole.
    pub(crate) fn handle_with_prefix(
        &self,
        stream: Stream,
        request: OpenRequest,
        opened: OpenedTarget,
        prefix: Vec<u8>,
    ) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        let connect_timeout = self.connect_timeout;
        // A future dropped before it ran drops `stream` and `opened`, which reset themselves.
        Box::pin(async move {
            let mut pipe = Pipe::new(stream, opened);
            pipe.run_with_prefix(&request.service, &prefix, connect_timeout)
                .await
        })
    }
}

/// The connection to a local target that [`LocalServices`] made for an accepted OPEN, with the
/// slot it holds. Dropping it before the pipe was started (the OPEN_ACK could not be written,
/// the OPEN timed out after the connect, the handler future was dropped unpolled) resets the
/// connection, so the target sees a connection that failed and not an empty one that ended well.
#[derive(Debug)]
pub struct OpenedTarget {
    socket: Option<TcpStream>,
    slot: Option<Slot>,
}

impl OpenedTarget {
    /// The socket and the slot (none for an open counted elsewhere), for the pipe, which takes over the duty to reset.
    fn into_parts(mut self) -> (TcpStream, Option<Slot>) {
        (
            self.socket
                .take()
                .expect("an opened target holds its socket"),
            self.slot.take(),
        )
    }

    /// The target socket, for tests.
    #[cfg(test)]
    fn socket(&self) -> &TcpStream {
        self.socket
            .as_ref()
            .expect("an opened target holds its socket")
    }
}

impl Drop for OpenedTarget {
    fn drop(&mut self) {
        if let Some(socket) = self.socket.take() {
            reset_socket(&socket);
        }
    }
}

/// Counts the connections being served: all together, and per peer.
#[derive(Debug)]
struct Slots {
    total: Arc<Semaphore>,
    max_total: usize,
    per_peer: Mutex<HashMap<NodeId, usize>>,
    max_per_peer: usize,
}

/// Which limit refused a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Full {
    /// All peers together.
    Everyone,
    /// This peer's own.
    Peer,
}

impl Slots {
    fn new(limits: &ServeLimits) -> Arc<Self> {
        Arc::new(Self {
            total: Arc::new(Semaphore::new(limits.max_connections)),
            max_total: limits.max_connections,
            per_peer: Mutex::new(HashMap::new()),
            max_per_peer: limits.max_connections_per_peer,
        })
    }

    fn take(self: &Arc<Self>, peer: NodeId) -> Result<Slot, Full> {
        let permit = self
            .total
            .clone()
            .try_acquire_owned()
            .map_err(|_| Full::Everyone)?;
        let mut held = self.per_peer.lock().unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(peer).or_insert(0);
        if *count >= self.max_per_peer {
            if *count == 0 {
                held.remove(&peer);
            }
            return Err(Full::Peer);
        }
        *count += 1;
        Ok(Slot {
            _permit: permit,
            peer,
            slots: self.clone(),
        })
    }

    fn in_use(&self) -> usize {
        self.max_total - self.total.available_permits()
    }

    /// How many peers have an entry in the count, for tests: an entry must not outlive the
    /// last connection of its peer.
    #[cfg(test)]
    fn tracked_peers(&self) -> usize {
        self.per_peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// One served connection's share of the counts; gives it back on drop.
#[derive(Debug)]
struct Slot {
    _permit: OwnedSemaphorePermit,
    peer: NodeId,
    slots: Arc<Slots>,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self
            .slots
            .per_peer
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.peer) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.peer);
            }
        }
    }
}

/// Lets one log line through per interval, and says how many it held back since the last.
#[derive(Debug)]
pub(crate) struct LogThrottle {
    interval: Duration,
    state: Mutex<ThrottleState>,
}

#[derive(Debug, Default)]
struct ThrottleState {
    last: Option<Instant>,
    left_out: u64,
}

impl LogThrottle {
    pub(crate) fn new(interval: Duration) -> Self {
        Self {
            interval,
            state: Mutex::new(ThrottleState::default()),
        }
    }

    /// `Some(n)` when a line may be written at `now`, `n` being the ones left out since the
    /// last; `None` when it may not.
    pub(crate) fn permit(&self, now: Instant) -> Option<u64> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match state.last {
            Some(last) if now.duration_since(last) < self.interval => {
                state.left_out += 1;
                None
            }
            _ => {
                state.last = Some(now);
                Some(std::mem::take(&mut state.left_out))
            }
        }
    }
}

/// The two ends of one served stream and the slot they hold. Dropping it before [`Pipe::run`]
/// has seen both directions finish (the task was aborted, the node is shutting down, the
/// future never ran) resets both ends.
struct Pipe {
    remote: Option<TokioStream>,
    local: Option<TcpStream>,
    _slot: Option<Slot>,
}

impl Pipe {
    fn new(stream: Stream, opened: OpenedTarget) -> Self {
        let (socket, slot) = opened.into_parts();
        Self {
            remote: Some(TokioStream(stream)),
            local: Some(socket),
            _slot: slot,
        }
    }

    async fn run_with_prefix(&mut self, service: &ServiceId, prefix: &[u8], limit: Duration) {
        if !prefix.is_empty() {
            let Some(local) = self.local.as_mut() else {
                return;
            };
            use tokio::io::AsyncWriteExt as _;
            // The target gets the bytes already read before anything else; one that does not
            // take them in time is as good as unreachable.
            if !matches!(
                tokio::time::timeout(limit, local.write_all(prefix)).await,
                Ok(Ok(()))
            ) {
                tracing::debug!(%service, "the local target did not take the first bytes of a stream");
                self.abort();
                return;
            }
        }
        self.run(service).await;
    }

    async fn run(&mut self, service: &ServiceId) {
        let (Some(remote), Some(local)) = (self.remote.as_mut(), self.local.as_mut()) else {
            return;
        };
        // The copy polls the stream only while a direction is waiting on it. After the peer's
        // FIN with a silent target, and while a write to a target that does not read is
        // blocked, nothing does, so no waker is registered and the peer's RST or the loss of
        // the session would wake nobody. The watcher has a waker of its own.
        let torn_down = remote.0.torn_down();
        let copy = copy_bidirectional_with_sizes(remote, local, PIPE_BUFFER, PIPE_BUFFER);
        let outcome = tokio::select! {
            // A copy that finished wins over a teardown that came with it: it moved every
            // byte and shut both directions down.
            biased;
            result = copy => result,
            () = torn_down => Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "the stream was torn down under the pipe",
            )),
        };
        match outcome {
            Ok((to_target, from_target)) => {
                tracing::debug!(%service, to_target, from_target, "served stream ended cleanly");
                // Both directions are finished and shut down: nothing to reset.
                self.remote = None;
                self.local = None;
            }
            Err(error) => {
                tracing::debug!(%service, %error, "served stream ended abnormally");
                self.abort();
            }
        }
    }

    /// Resets whatever is still held: an RST to the target, an RST to the peer.
    fn abort(&mut self) {
        if let Some(local) = self.local.take() {
            reset_socket(&local);
        }
        if let Some(remote) = self.remote.take() {
            remote.0.reset();
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Makes closing `socket` send an RST instead of a FIN, so that the target
/// sees an error and not a clean end of file. Linger zero does not block on close.
fn reset_socket(socket: &TcpStream) {
    let _ = socket2::SockRef::from(socket).set_linger(Some(Duration::ZERO));
}

/// `menzil_stream::Stream` speaks `futures` I/O; tokio's `copy_bidirectional`
/// wants its own traits.
pub(crate) struct TokioStream(pub(crate) Stream);

impl tokio::io::AsyncRead for TokioStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match AsyncRead::poll_read(Pin::new(&mut self.0), cx, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for TokioStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(Pin::new(&mut self.0), cx)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use menzil_proto::{ErrorCode, NetworkId, NodeId, OpenBody, OpenMeta, PROTOCOL_VERSION};
    use menzil_stream::{
        Authorizer, Mode, OpenDecision, OpenRefusal, OpenRequest, OutboundFrames, Responded,
        Stream, StreamMux, initiate_open, respond_to_open,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;
    use tokio::time::timeout;

    use super::*;

    const WAIT: Duration = Duration::from_secs(10);

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

    /// A client that opens streams and a server that serves them with
    /// `services`, joined by in-memory pumps.
    struct Rig {
        client: StreamMux,
        /// Ends the server's connection when aborted and dropped, like a lost session.
        cut_server: Option<(JoinHandle<()>, StreamMux)>,
    }

    impl Rig {
        fn new(services: LocalServices) -> Self {
            let (client, _client_inbound, client_out, client_driver) =
                menzil_stream::new(Mode::Client, 65_535);
            let (server, mut server_inbound, server_out, server_driver) =
                menzil_stream::new(Mode::Server, 65_535);
            tokio::spawn(client_driver);
            tokio::spawn(server_driver);
            let into_server = tokio::spawn(pump(client_out, server.clone()));
            tokio::spawn(pump(server_out, client.clone()));
            let services = Arc::new(services);
            tokio::spawn(async move {
                while let Some(stream) = server_inbound.accept().await {
                    let services = services.clone();
                    tokio::spawn(async move {
                        let responded = respond_to_open(
                            stream,
                            NetworkId::from([1u8; 32]),
                            NodeId::from([2u8; 32]),
                            &AllowAll,
                            &*services,
                        )
                        .await;
                        if let Ok(Responded::Accepted(handling)) = responded {
                            handling.await;
                        }
                    });
                }
            });
            Rig {
                client,
                cut_server: Some((into_server, server)),
            }
        }

        /// Opens a stream for `service` and runs the OPEN exchange.
        async fn open(&self, service: &str) -> (Stream, menzil_proto::OpenAckBody) {
            let mut stream = self.client.open().await.unwrap();
            let ack = initiate_open(&mut stream, &open_body(service))
                .await
                .unwrap();
            (stream, ack)
        }

        fn cut_server(&mut self) {
            let (pump, server) = self.cut_server.take().unwrap();
            pump.abort();
            drop(server);
        }
    }

    fn open_body(service: &str) -> OpenBody {
        OpenBody {
            v: PROTOCOL_VERSION,
            service: service.parse().unwrap(),
            target: None,
            meta: OpenMeta::default(),
        }
    }

    fn services_for(listener: &TcpListener) -> LocalServices {
        let port = listener.local_addr().unwrap().port();
        LocalServices::new()
            .serve(
                "tcp:app".parse().unwrap(),
                LocalTarget::new("127.0.0.1", port),
            )
            .unwrap()
    }

    async fn listener() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    /// Makes the socket close with an RST.
    fn rst_on_close(socket: &TcpStream) {
        socket2::SockRef::from(socket)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
    }

    /// The request a peer `initiator` (any byte) makes for `service`.
    fn request(service: &str, initiator: u8) -> OpenRequest {
        OpenRequest {
            network_id: NetworkId::from([1u8; 32]),
            initiator: NodeId::from([initiator; 32]),
            service: service.parse().unwrap(),
            target: None,
            meta: OpenMeta::default(),
        }
    }

    /// A connected pair of streams, (the client's, the server's), over in-memory pumps that
    /// live as long as the runtime.
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
        let remote = timeout(WAIT, server_inbound.accept())
            .await
            .unwrap()
            .unwrap();
        tokio::spawn(async move {
            let _keep = (client, client_inbound, server, server_inbound);
            std::future::pending::<()>().await;
        });
        (opened, remote)
    }

    /// An opened target for a socket, holding a slot of a node with the default limits.
    fn opened_target(socket: TcpStream) -> OpenedTarget {
        let slots = Slots::new(&ServeLimits::default());
        OpenedTarget {
            socket: Some(socket),
            slot: Some(slots.take(NodeId::from([9u8; 32])).unwrap()),
        }
    }

    fn is_reset(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
        )
    }

    /// Waits for the socket to report an error without using it: a silent target has nothing to
    /// write, and a read after the pipe's FIN is a clean end of file whatever follows, so the
    /// socket's own error (`SO_ERROR`, what an RST sets) is the only place its reset shows.
    async fn socket_error(socket: &TcpStream, limit: Duration) -> Option<io::Error> {
        let started = std::time::Instant::now();
        loop {
            if let Some(error) = socket.take_error().unwrap() {
                return Some(error);
            }
            if started.elapsed() > limit {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn is_reset_or_broken_pipe(error: &io::Error) -> bool {
        is_reset(error) || error.kind() == io::ErrorKind::BrokenPipe
    }

    #[test]
    fn only_tcp_http_and_tls_services_with_an_exact_label_can_be_configured() {
        let target = || LocalTarget::new("127.0.0.1", 1);
        for ok in ["tcp:ssh", "http:app", "tls:app"] {
            assert!(
                LocalServices::new()
                    .serve(ok.parse().unwrap(), target())
                    .is_ok()
            );
        }
        for (service, expected) in [
            (
                "udp:wg",
                ServeConfigError::UnsupportedKind(ServiceKind::Udp),
            ),
            (
                "egress:*",
                ServeConfigError::UnsupportedKind(ServiceKind::Egress),
            ),
            (
                "acme-http:app",
                ServeConfigError::UnsupportedKind(ServiceKind::AcmeHttp),
            ),
            (
                "menzil:docs",
                ServeConfigError::UnsupportedKind(ServiceKind::Menzil),
            ),
            ("tcp:*", ServeConfigError::WildcardLabel("*".to_string())),
            ("tcp:", ServeConfigError::EmptyLabel),
        ] {
            let error = LocalServices::new()
                .serve(service.parse().unwrap(), target())
                .unwrap_err();
            assert_eq!(error, expected, "{service}");
        }
        let services = LocalServices::new()
            .serve("tcp:ssh".parse().unwrap(), LocalTarget::new("host", 22))
            .unwrap();
        assert_eq!(services.len(), 1);
        assert!(!services.is_empty());
        assert_eq!(
            services
                .target(&"tcp:ssh".parse().unwrap())
                .unwrap()
                .to_string(),
            "host:22"
        );
        assert!(services.target(&"tcp:other".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn a_stream_is_piped_both_ways_and_ends_cleanly() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            // Echo until the peer's FIN, then close our side.
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                socket.write_all(&buf[..n]).await.unwrap();
            }
            socket.shutdown().await.unwrap();
            got
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok, "{ack:?}");
        stream.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        timeout(WAIT, stream.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&back, b"hello");
        stream.close().await.unwrap();
        let mut rest = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .expect("the target closed cleanly: a clean end, not a reset");
        assert!(rest.is_empty());
        assert_eq!(timeout(WAIT, target).await.unwrap().unwrap(), b"hello");
    }

    #[tokio::test]
    async fn a_half_closed_request_still_gets_its_whole_response() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            // The request ended with the client's FIN; the response follows it.
            socket.write_all(&vec![9u8; 100_000]).await.unwrap();
            request
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"request").await.unwrap();
        stream.close().await.unwrap();
        let mut response = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut response))
            .await
            .unwrap()
            .expect("a response that ended with the target's FIN is complete");
        assert_eq!(response, vec![9u8; 100_000]);
        assert_eq!(timeout(WAIT, target).await.unwrap().unwrap(), b"request");
    }

    #[tokio::test]
    async fn bytes_sent_behind_the_open_header_reach_the_target() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut early = [0u8; 5];
            socket.read_exact(&mut early).await.unwrap();
            early
        });

        // The OPEN header and the first bytes of the service go out together,
        // before the OPEN_ACK has come back.
        let mut stream = rig.client.open().await.unwrap();
        let mut bytes = open_body("tcp:app").encode().unwrap();
        bytes.extend_from_slice(b"early");
        stream.write_all(&bytes).await.unwrap();
        stream.flush().await.unwrap();
        let mut prefix = [0u8; 2];
        timeout(WAIT, stream.read_exact(&mut prefix))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(timeout(WAIT, target).await.unwrap().unwrap(), *b"early");
    }

    #[tokio::test]
    async fn a_target_that_refuses_is_refused_in_the_ack_not_accepted_and_ended() {
        let listener = listener().await;
        let services = services_for(&listener);
        drop(listener); // nothing listens on that port any more
        let rig = Rig::new(services);

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(!ack.ok);
        assert_eq!(ack.code, ErrorCode::TargetUnreachable);
        assert!(
            !ack.msg.contains("127.0.0.1"),
            "the local address is the node's business: {ack:?}"
        );
        let mut rest = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert!(
            rest.is_empty(),
            "a refused stream carries nothing after its ack"
        );
    }

    #[tokio::test]
    async fn a_service_that_is_not_configured_is_unknown() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        for service in ["tcp:other", "http:app", "udp:app"] {
            let (_stream, ack) = rig.open(service).await;
            assert!(!ack.ok, "{service}");
            assert_eq!(ack.code, ErrorCode::UnknownService, "{service}");
        }
        // And the target was never even connected to.
        assert!(
            timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_target_that_resets_resets_the_stream() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut one = [0u8; 1];
            socket.read_exact(&mut one).await.unwrap();
            rst_on_close(&socket);
            drop(socket);
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"x").await.unwrap();
        let mut got = Vec::new();
        let error = timeout(WAIT, stream.read_to_end(&mut got))
            .await
            .unwrap()
            .expect_err("a reset target is not a clean end of file");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        target.await.unwrap();
    }

    #[tokio::test]
    async fn a_reset_stream_resets_the_target_socket() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut one = [0u8; 1];
            socket.read_exact(&mut one).await.unwrap();
            // Not a clean end of file.
            socket.read(&mut one).await
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"x").await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stream.reset();
        let result = timeout(WAIT, target).await.unwrap().unwrap();
        assert!(
            matches!(&result, Err(e) if is_reset(e)),
            "the target must see a reset, got {result:?}"
        );
    }

    /// A clean end must not turn into a reset: the target here closes its own
    /// side at once and reads the whole upload only afterwards, so a spurious
    /// RST at the end of the pipe would show as an error where its final read
    /// should be a clean end of file.
    #[tokio::test]
    async fn a_clean_end_is_not_a_reset_even_for_a_target_that_is_still_reading() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.shutdown().await.unwrap();
            tokio::time::sleep(Duration::from_millis(400)).await;
            let mut got = Vec::new();
            socket.read_to_end(&mut got).await.map(|_| got)
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        let upload = vec![5u8; 512 * 1024];
        stream.write_all(&upload).await.unwrap();
        stream.close().await.unwrap();
        let mut rest = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .expect("the target closed cleanly");
        let got = timeout(WAIT, target).await.unwrap().unwrap();
        assert_eq!(
            got.expect("a clean end reads as end of file, not an error"),
            upload
        );
    }

    /// A clean end must not throw away what the target has not received yet. The target here
    /// closes its own side at once and reads nothing for a second; the upload is more than its
    /// receive buffer takes but fits our send buffer, so the pipe finishes (both directions
    /// done) while part of the upload is still queued in our kernel. A reset at that point
    /// (a linger of zero on a socket whose data and FIN are not delivered) would discard that
    /// part and send an RST; a plain close delivers it, then the end of file.
    #[tokio::test]
    async fn a_clean_end_does_not_discard_what_the_target_has_not_received_yet() {
        const SIZE: usize = 240 * 1024;
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.shutdown().await.unwrap();
            tokio::time::sleep(Duration::from_millis(1000)).await;
            let mut got = Vec::new();
            socket.read_to_end(&mut got).await.map(|_| got)
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        let upload = vec![8u8; SIZE];
        stream.write_all(&upload).await.unwrap();
        stream.close().await.unwrap();
        let mut rest = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .expect("the target closed cleanly");
        // The pipe is over by now: both directions are done.
        let got = timeout(WAIT, target).await.unwrap().unwrap();
        assert_eq!(
            got.expect("a clean end reads as end of file, after all the data"),
            upload
        );
    }

    /// The state stock `yamux` cannot reset (TOBEDECIDED item 11): the client
    /// sent its request and its FIN, and then the target fails. The stream
    /// must end in a reset, not in the clean end of file a plain drop would
    /// give, or the client reads a truncated response as a whole one.
    #[tokio::test]
    async fn a_target_that_fails_after_the_client_half_closed_resets_the_stream() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            socket.write_all(b"partial").await.unwrap();
            // Let the partial response reach the stream before the failure.
            tokio::time::sleep(Duration::from_millis(150)).await;
            rst_on_close(&socket);
            drop(socket);
            request
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"request").await.unwrap();
        stream.close().await.unwrap();
        let mut response = Vec::new();
        let error = timeout(WAIT, stream.read_to_end(&mut response))
            .await
            .unwrap()
            .expect_err("a response cut off by a failure must not read as complete");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(
            response, b"partial",
            "what arrived before the failure is delivered"
        );
        assert_eq!(timeout(WAIT, target).await.unwrap().unwrap(), b"request");
    }

    /// The same state seen from the other side: the client half-closed and
    /// then aborts. The target, which saw the half-close as an end of file,
    /// must find the connection reset when it next uses it.
    #[tokio::test]
    async fn a_client_reset_after_its_half_close_resets_the_target() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel::<()>();
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            reset_rx.await.unwrap();
            // The pipe resets the socket once the stream was reset; writes then fail.
            let mut outcome = Ok(());
            for _ in 0..50 {
                if let Err(e) = socket.write_all(&[7u8; 16 * 1024]).await {
                    outcome = Err(e);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            (request, outcome)
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"request").await.unwrap();
        stream.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        stream.reset();
        tokio::time::sleep(Duration::from_millis(200)).await;
        reset_tx.send(()).unwrap();
        let (request, outcome) = timeout(WAIT, target).await.unwrap().unwrap();
        assert_eq!(request, b"request");
        assert!(
            matches!(&outcome, Err(e) if is_reset(e) || e.kind() == io::ErrorKind::BrokenPipe),
            "the target must find its socket reset, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn a_session_lost_under_a_stream_resets_the_target_socket() {
        let listener = listener().await;
        let mut rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut one = [0u8; 1];
            socket.read_exact(&mut one).await.unwrap();
            socket.read(&mut one).await
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"x").await.unwrap();
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        rig.cut_server();
        let result = timeout(WAIT, target).await.unwrap().unwrap();
        assert!(
            matches!(&result, Err(e) if is_reset(e)),
            "a lost session is an abnormal end: the target must see a reset, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_pipe_dropped_before_it_finished_resets_the_target_socket() {
        let listener = listener().await;
        let port = listener.local_addr().unwrap().port();
        let local = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut accepted, _) = listener.accept().await.unwrap();

        // A stream pair to give the pipe its remote end.
        let (client, mut client_inbound, client_out, client_driver) =
            menzil_stream::new(Mode::Client, 65_535);
        let (server, mut server_inbound, server_out, server_driver) =
            menzil_stream::new(Mode::Server, 65_535);
        tokio::spawn(client_driver);
        tokio::spawn(server_driver);
        tokio::spawn(pump(client_out, server.clone()));
        tokio::spawn(pump(server_out, client.clone()));
        let mut opened = client.open().await.unwrap();
        opened.write_all(b"x").await.unwrap();
        let remote = timeout(WAIT, server_inbound.accept())
            .await
            .unwrap()
            .unwrap();
        let _ = &mut client_inbound;

        let mut pipe = Pipe::new(remote, opened_target(local));
        let task = tokio::spawn(async move { pipe.run(&"tcp:app".parse().unwrap()).await });
        let mut one = [0u8; 1];
        accepted.read_exact(&mut one).await.unwrap();
        // The node shuts down: the task is aborted mid-pipe.
        task.abort();
        let _ = task.await;
        let result = timeout(WAIT, accepted.read(&mut one)).await.unwrap();
        assert!(
            matches!(&result, Err(e) if is_reset(e)),
            "an aborted pipe is abnormal: reset, not a clean end, got {result:?}"
        );
        // And the peer's stream was reset too.
        let mut rest = Vec::new();
        let error = timeout(WAIT, opened.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    /// The second L4i review, M1. After the client's FIN the pipe has nothing to read from the
    /// stream and waits on the silent target; nothing polls the stream, so nothing told the pipe
    /// that the session was gone, and the target's socket stayed open (a descriptor, a task and
    /// kernel buffers on both ends, for ever).
    #[tokio::test]
    async fn a_silent_target_is_reset_when_the_session_is_lost_after_the_clients_half_close() {
        let listener = listener().await;
        let mut rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            // Silent from here on: no write, no read.
            (request, socket_error(&socket, WAIT).await)
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"request").await.unwrap();
        stream.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        rig.cut_server();
        let (request, error) = timeout(WAIT * 2, target).await.unwrap().unwrap();
        assert_eq!(request, b"request");
        let error = error.expect("a lost session must reset a target that stays silent");
        assert!(is_reset_or_broken_pipe(&error), "{error:?}");
    }

    /// The same with the client's RST instead of a lost session.
    #[tokio::test]
    async fn a_silent_target_is_reset_when_the_client_resets_after_its_half_close() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            socket.read_to_end(&mut request).await.unwrap();
            (request, socket_error(&socket, WAIT).await)
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        stream.write_all(b"request").await.unwrap();
        stream.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        stream.reset();
        let (request, error) = timeout(WAIT * 2, target).await.unwrap().unwrap();
        assert_eq!(request, b"request");
        let error = error.expect("a reset must reach a target that stays silent");
        assert!(is_reset_or_broken_pipe(&error), "{error:?}");
    }

    /// A target that does not read blocks the pipe's write to it; the pipe then polls neither
    /// side of the stream, and the client's RST woke nobody.
    #[tokio::test]
    async fn a_target_that_does_not_read_is_reset_when_the_client_resets() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            // Never reads.
            socket_error(&socket, WAIT).await
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel::<()>();
        let uploader = tokio::spawn(async move {
            let big = vec![1u8; 16 * 1024 * 1024];
            tokio::select! {
                _ = stream.write_all(&big) => panic!("the target reads nothing: the upload cannot finish"),
                _ = reset_rx => {}
            }
            stream.reset();
        });
        // Long enough for the pipe to fill the socket buffers and block on its write.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!uploader.is_finished());
        reset_tx.send(()).unwrap();
        uploader.await.unwrap();
        let error = timeout(WAIT * 2, target).await.unwrap().unwrap();
        let error = error.expect("a reset must reach a target that does not read");
        assert!(is_reset_or_broken_pipe(&error), "{error:?}");
    }

    /// `Pipe::abort` must reset the stream, not just drop it. Once the target has sent its FIN the
    /// pipe has closed the stream (a clean end for that direction), and a plain drop of a
    /// closed stream sends nothing: a peer that is still uploading, blocked on credit, would
    /// wait for ever for a pipe whose target then failed.
    #[tokio::test]
    async fn a_target_that_fails_after_its_own_fin_resets_a_peer_that_is_still_uploading() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Its own end first, then it stops reading, and some time later it fails.
            socket.shutdown().await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            rst_on_close(&socket);
            drop(socket);
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        let big = vec![1u8; 16 * 1024 * 1024];
        let error = timeout(WAIT, stream.write_all(&big))
            .await
            .expect("the upload must fail when the target fails, not hang")
            .expect_err("a target that failed cannot have taken 16 MiB");
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        target.await.unwrap();
    }

    #[tokio::test]
    async fn a_large_transfer_arrives_intact_in_both_directions() {
        const SIZE: usize = 4 * 1024 * 1024;
        let pattern = |i: usize| (i % 251) as u8;
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = socket.into_split();
            let up = tokio::spawn(async move {
                let mut got = Vec::with_capacity(SIZE);
                read.read_to_end(&mut got).await.unwrap();
                got
            });
            let down: Vec<u8> = (0..SIZE).map(|i| pattern(i + 1)).collect();
            write.write_all(&down).await.unwrap();
            write.shutdown().await.unwrap();
            up.await.unwrap()
        });

        let (stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        let (mut reader, mut writer) = stream.split();
        let sent: Vec<u8> = (0..SIZE).map(pattern).collect();
        let (written, received) = timeout(
            Duration::from_secs(60),
            futures_util::future::join(
                async {
                    writer.write_all(&sent).await.unwrap();
                    writer.close().await.unwrap();
                },
                async {
                    let mut got = Vec::with_capacity(SIZE);
                    reader.read_to_end(&mut got).await.unwrap();
                    got
                },
            ),
        )
        .await
        .unwrap();
        let () = written;
        assert_eq!(received.len(), SIZE);
        assert!(
            received
                .iter()
                .enumerate()
                .all(|(i, b)| *b == pattern(i + 1))
        );
        let at_target = timeout(WAIT, target).await.unwrap().unwrap();
        assert_eq!(at_target, sent);
    }

    #[tokio::test]
    async fn a_target_that_never_answers_is_refused_when_the_connect_times_out() {
        // A listening socket whose accept queue is full drops further SYNs, so a
        // connect to it hangs. Fill the queue (backlog 0 holds one connection),
        // then ask for a service on that port.
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        socket
            .bind(
                &"127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .unwrap();
        socket.listen(0).unwrap();
        let addr = socket.local_addr().unwrap().as_socket().unwrap();
        let mut fillers = Vec::new();
        for _ in 0..4 {
            let filler =
                socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
            let _ = filler.set_nonblocking(true);
            let _ = filler.connect(&addr.into());
            fillers.push(filler);
        }
        let services = LocalServices::new()
            .serve(
                "tcp:app".parse().unwrap(),
                LocalTarget::new("127.0.0.1", addr.port()),
            )
            .unwrap()
            .with_connect_timeout(Duration::from_millis(300));
        let rig = Rig::new(services);

        let started = std::time::Instant::now();
        let (_stream, ack) = rig.open("tcp:app").await;
        assert!(!ack.ok);
        assert_eq!(ack.code, ErrorCode::TargetUnreachable);
        assert_eq!(ack.msg, "the local target did not answer in time");
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(fillers);
    }
    /// The second L4i review, L1: a connection made for an OPEN that is then not piped (the ack
    /// could not be written, the OPEN timed out after the connect) closed with a FIN, so the
    /// target saw an empty connection that ended well.
    #[tokio::test]
    async fn an_opened_target_dropped_before_the_pipe_starts_resets_the_connection() {
        let listener = listener().await;
        let services = services_for(&listener);
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut one = [0u8; 1];
            socket.read(&mut one).await
        });

        let opened = services.open(&request("tcp:app", 1)).await.unwrap();
        drop(opened);
        let result = timeout(WAIT, target).await.unwrap().unwrap();
        assert!(
            matches!(&result, Err(e) if is_reset(e)),
            "a connection nobody piped is a failed one, not an empty clean one: {result:?}"
        );
    }

    /// `menzil expose` adds and removes a service while the node runs: the handle the node
    /// serves from is a clone, and a change through another clone is seen by it at once.
    #[tokio::test]
    async fn a_service_added_or_removed_on_one_clone_is_seen_by_the_clone_that_serves() {
        let listener = listener().await;
        let port = listener.local_addr().unwrap().port();
        let running = LocalServices::new();
        let handle = running.clone();
        let service: ServiceId = "tls:late".parse().unwrap();
        assert!(matches!(
            running.open(&request("tls:late", 1)).await,
            Err(OpenRefusal {
                code: ErrorCode::UnknownService,
                ..
            })
        ));
        handle
            .set_target(service.clone(), LocalTarget::new("127.0.0.1", port))
            .unwrap();
        assert_eq!(running.len(), 1);
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let opened = running.open(&request("tls:late", 1)).await.unwrap();
        timeout(WAIT, accept).await.unwrap().unwrap().unwrap();
        drop(opened);
        // A kind or label that cannot be served is refused on a live handle as on a new one.
        assert_eq!(
            handle
                .set_target("udp:x".parse().unwrap(), LocalTarget::new("h", 1))
                .unwrap_err(),
            ServeConfigError::UnsupportedKind(ServiceKind::Udp)
        );
        assert!(handle.remove_target(&service));
        assert!(!handle.remove_target(&service), "already gone");
        assert!(running.is_empty());
        assert!(matches!(
            running.open(&request("tls:late", 1)).await,
            Err(OpenRefusal {
                code: ErrorCode::UnknownService,
                ..
            })
        ));
    }

    /// The same for a handler future that is dropped without ever running: the stream and the
    /// connection it holds reset themselves.
    #[tokio::test]
    async fn a_handler_future_dropped_before_it_runs_resets_both_ends() {
        let listener = listener().await;
        let services = services_for(&listener);
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut one = [0u8; 1];
            socket.read(&mut one).await
        });
        let (mut client_side, server_side) = stream_pair().await;

        let request = request("tcp:app", 1);
        let opened = services.open(&request).await.unwrap();
        let handling = services.handle(server_side, request, opened);
        drop(handling);

        let result = timeout(WAIT, target).await.unwrap().unwrap();
        assert!(
            matches!(&result, Err(e) if is_reset(e)),
            "the target must see a reset, got {result:?}"
        );
        let mut rest = Vec::new();
        let error = timeout(WAIT, client_side.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        assert_eq!(services.connections(), 0, "the slot is given back");
    }

    /// Interactive services must not wait for Nagle.
    #[tokio::test]
    async fn the_target_socket_has_nodelay() {
        let listener = listener().await;
        let services = services_for(&listener);
        let opened = services.open(&request("tcp:app", 1)).await.unwrap();
        assert!(opened.socket().nodelay().unwrap());
        drop(listener);
    }

    /// The second L4i review, M2: the kernel buffers of a target socket were autotuned, and a
    /// target that does not read let a peer pile up megabytes per stream in them.
    #[tokio::test]
    async fn target_sockets_get_the_fixed_buffers_that_were_asked_for() {
        let listener = listener().await;
        let services = services_for(&listener).with_limits(ServeLimits {
            socket_buffer: 16 * 1024,
            ..ServeLimits::default()
        });
        let opened = services.open(&request("tcp:app", 1)).await.unwrap();
        let socket = socket2::SockRef::from(opened.socket());
        // The kernel doubles what is asked for. Autotuned, the send buffer of a connected
        // loopback socket is megabytes and the receive buffer 128 KiB.
        let (send, receive) = (
            socket.send_buffer_size().unwrap(),
            socket.recv_buffer_size().unwrap(),
        );
        assert!((16 * 1024..=64 * 1024).contains(&send), "send {send}");
        assert!(
            (16 * 1024..=64 * 1024).contains(&receive),
            "receive {receive}"
        );
    }

    /// The same, as a peer sees it: how much a stream takes before the target's socket pushes
    /// back. Measured 4.66 MiB per stream before the buffers were fixed.
    #[tokio::test]
    async fn a_target_that_does_not_read_takes_only_a_bounded_amount() {
        let listener = listener().await;
        let rig = Rig::new(services_for(&listener));
        let target = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            // Holds the connection and never reads.
            tokio::time::sleep(Duration::from_secs(3)).await;
            drop(socket);
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        let written = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = written.clone();
        let uploader = tokio::spawn(async move {
            let chunk = vec![3u8; 64 * 1024];
            loop {
                if stream.write_all(&chunk).await.is_err() {
                    return;
                }
                counter.fetch_add(chunk.len(), std::sync::atomic::Ordering::Relaxed);
            }
        });
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let taken = written.load(std::sync::atomic::Ordering::Relaxed);
        uploader.abort();
        target.abort();
        assert!(
            taken > 64 * 1024,
            "something must have gone through: {taken}"
        );
        assert!(
            taken < 2 * 1024 * 1024,
            "a target that reads nothing must push back early, took {taken} bytes"
        );
    }

    fn limits(max_connections: usize, max_connections_per_peer: usize) -> ServeLimits {
        ServeLimits {
            max_connections,
            max_connections_per_peer,
            ..ServeLimits::default()
        }
    }

    fn assert_rate_limited(refusal: Result<OpenedTarget, OpenRefusal>, what: &str) {
        match refusal {
            Err(refusal) => {
                assert_eq!(refusal.code, ErrorCode::RateLimited, "{what}");
                assert_eq!(refusal.msg, "too many connections", "{what}");
            }
            Ok(_) => panic!("{what}: expected a refusal"),
        }
    }

    #[tokio::test]
    async fn the_node_wide_limit_refuses_the_next_open_and_a_slot_comes_back_when_it_ends() {
        let listener = listener().await;
        let services = services_for(&listener).with_limits(limits(2, 2));
        let first = services.open(&request("tcp:app", 1)).await.unwrap();
        let _second = services.open(&request("tcp:app", 2)).await.unwrap();
        assert_eq!(services.connections(), 2);

        // A third peer, well within its own limit, finds the node full.
        assert_rate_limited(
            services.open(&request("tcp:app", 3)).await,
            "the node is full",
        );
        // The refused OPEN never connected to the target.
        let mut accepted = 0;
        while timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_ok()
        {
            accepted += 1;
        }
        assert_eq!(accepted, 2);

        drop(first);
        assert_eq!(services.connections(), 1);
        let _third = services.open(&request("tcp:app", 3)).await.unwrap();
        assert_eq!(services.connections(), 2);
    }

    #[tokio::test]
    async fn the_per_peer_limit_counts_each_initiator_apart() {
        let listener = listener().await;
        let services = services_for(&listener).with_limits(limits(10, 1));
        let first = services.open(&request("tcp:app", 1)).await.unwrap();
        assert_rate_limited(
            services.open(&request("tcp:app", 1)).await,
            "peer 1 holds its one",
        );
        // Another peer is not affected, and a refusal took nothing from the count.
        let other = services.open(&request("tcp:app", 2)).await.unwrap();
        assert_eq!(services.connections(), 2);
        assert_eq!(services.slots.tracked_peers(), 2);

        drop(first);
        let again = services.open(&request("tcp:app", 1)).await.unwrap();
        assert_eq!(services.connections(), 2);

        // A peer's entry goes with its last connection.
        drop(other);
        drop(again);
        assert_eq!(services.connections(), 0);
        assert_eq!(services.slots.tracked_peers(), 0);
    }

    /// Through the whole OPEN exchange: the refusal reaches the peer as `rate_limited`, and
    /// the slot comes back when the pipe ends cleanly.
    #[tokio::test]
    async fn a_served_connection_holds_its_slot_until_its_pipe_ends() {
        let listener = listener().await;
        let services = services_for(&listener).with_limits(limits(1, 1));
        let rig = Rig::new(services.clone());
        let target = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut sink = Vec::new();
            socket.read_to_end(&mut sink).await.unwrap();
            socket.shutdown().await.unwrap();
        });

        let (mut stream, ack) = rig.open("tcp:app").await;
        assert!(ack.ok);
        assert_eq!(services.connections(), 1);
        let (_refused_stream, refused) = rig.open("tcp:app").await;
        assert!(!refused.ok);
        assert_eq!(refused.code, ErrorCode::RateLimited);

        stream.close().await.unwrap();
        let mut rest = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        timeout(WAIT, target).await.unwrap().unwrap();
        timeout(WAIT, async {
            while services.connections() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the slot must come back when the pipe ended");
    }

    #[tokio::test]
    async fn a_connect_that_fails_or_is_given_up_on_gives_its_slot_back() {
        let listener = listener().await;
        let services = services_for(&listener).with_limits(limits(1, 1));
        drop(listener); // nothing listens any more
        match services.open(&request("tcp:app", 1)).await {
            Err(refusal) => assert_eq!(refusal.code, ErrorCode::TargetUnreachable),
            Ok(_) => panic!("nothing listens"),
        }
        assert_eq!(services.connections(), 0);

        // An open that is dropped while it waits (the caller's OPEN timeout) too: the
        // address is one a connect never completes to.
        let slow = LocalServices::new()
            .serve(
                "tcp:app".parse().unwrap(),
                LocalTarget::new("203.0.113.1", 9),
            )
            .unwrap()
            .with_limits(limits(1, 1));
        let _ = timeout(
            Duration::from_millis(100),
            slow.open(&request("tcp:app", 1)),
        )
        .await;
        assert_eq!(slow.connections(), 0);
    }

    #[test]
    fn limits_and_the_connect_timeout_are_kept_in_range() {
        let services = LocalServices::new().with_limits(ServeLimits {
            max_connections: 0,
            max_connections_per_peer: 0,
            socket_buffer: 4096,
        });
        assert_eq!(services.limits().max_connections, 1);
        assert_eq!(services.limits().max_connections_per_peer, 1);
        assert_eq!(services.limits().socket_buffer, 4096);
        // The fifth red-team round, N1: a total past what a semaphore holds panicked at start.
        let huge = LocalServices::new().with_limits(ServeLimits {
            max_connections: usize::MAX,
            max_connections_per_peer: usize::MAX,
            socket_buffer: 4096,
        });
        assert_eq!(huge.limits().max_connections, Semaphore::MAX_PERMITS);
        assert_eq!(huge.limits().max_connections_per_peer, usize::MAX);
        assert_eq!(
            LocalServices::new().limits(),
            ServeLimits {
                max_connections: DEFAULT_MAX_CONNECTIONS,
                max_connections_per_peer: DEFAULT_MAX_CONNECTIONS_PER_PEER,
                socket_buffer: DEFAULT_SOCKET_BUFFER,
            }
        );

        assert_eq!(
            LocalServices::new().connect_timeout(),
            DEFAULT_CONNECT_TIMEOUT
        );
        // Half the OPEN timeout, as documented: a refusal has time to be written and read.
        assert_eq!(DEFAULT_CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(DEFAULT_CONNECT_TIMEOUT * 2, OPEN_TIMEOUT);
        let one = Duration::from_secs(1);
        assert_eq!(
            LocalServices::new()
                .with_connect_timeout(one)
                .connect_timeout(),
            one
        );
        // Never more than the peer waits for the ack, less a second.
        assert_eq!(MAX_CONNECT_TIMEOUT, Duration::from_secs(9));
        assert_eq!(
            LocalServices::new()
                .with_connect_timeout(Duration::from_secs(3600))
                .connect_timeout(),
            MAX_CONNECT_TIMEOUT
        );
    }

    #[test]
    fn the_log_throttle_lets_one_line_through_per_interval_and_counts_the_rest() {
        let throttle = LogThrottle::new(Duration::from_secs(10));
        let t0 = Instant::now();
        let at = |secs: u64| t0 + Duration::from_secs(secs);
        assert_eq!(throttle.permit(at(0)), Some(0));
        assert_eq!(throttle.permit(at(1)), None);
        assert_eq!(throttle.permit(at(9)), None);
        // Exactly one interval later it may.
        assert_eq!(throttle.permit(at(10)), Some(2));
        assert_eq!(throttle.permit(at(15)), None);
        assert_eq!(throttle.permit(at(21)), Some(1));
        assert_eq!(throttle.permit(at(40)), Some(0));
    }

    mod lookups {
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        use super::*;

        static RUNNING: AtomicUsize = AtomicUsize::new(0);
        static PEAK: AtomicUsize = AtomicUsize::new(0);
        static STARTED: AtomicUsize = AtomicUsize::new(0);
        /// While set, a lookup does not return.
        static HOLD: AtomicBool = AtomicBool::new(false);

        fn slow_resolve(_host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            STARTED.fetch_add(1, Ordering::SeqCst);
            let now = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
            PEAK.fetch_max(now, Ordering::SeqCst);
            while HOLD.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(100));
            RUNNING.fetch_sub(1, Ordering::SeqCst);
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])
        }

        fn named_services(port: u16) -> LocalServices {
            let mut services = LocalServices::new()
                .serve(
                    "tcp:app".parse().unwrap(),
                    LocalTarget::new("target.invalid", port),
                )
                .unwrap();
            services.resolve = slow_resolve;
            services
        }

        /// One test for both properties, since the counters are process-wide statics.
        #[tokio::test]
        async fn hostname_lookups_run_four_at_a_time_and_an_abandoned_one_keeps_its_place() {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let mut held = Vec::new();
                while let Ok((socket, _)) = listener.accept().await {
                    held.push(socket);
                }
            });

            // Twelve OPENs at once from twelve peers: all served, never more than four
            // lookups at a time.
            let services = Arc::new(named_services(port));
            let mut opens = Vec::new();
            for peer in 1..=12u8 {
                let services = services.clone();
                opens.push(tokio::spawn(async move {
                    services.open(&request("tcp:app", peer)).await.map(drop)
                }));
            }
            for open in opens {
                open.await.unwrap().expect("a lookup that waited its turn");
            }
            assert_eq!(STARTED.load(Ordering::SeqCst), 12);
            let peak = PEAK.load(Ordering::SeqCst);
            assert!((2..=4).contains(&peak), "peak {peak}");

            // Eight OPENs, one after the other, each giving up after 50 ms on a lookup that does
            // not return: the lookups are abandoned, not stopped, and the abandoned ones still
            // hold their places, so the fifth and the rest never start.
            STARTED.store(0, Ordering::SeqCst);
            PEAK.store(0, Ordering::SeqCst);
            HOLD.store(true, Ordering::SeqCst);
            let impatient = named_services(port).with_connect_timeout(Duration::from_millis(50));
            for peer in 1..=8u8 {
                match impatient.open(&request("tcp:app", peer)).await {
                    Err(refusal) => assert_eq!(refusal.code, ErrorCode::TargetUnreachable),
                    Ok(_) => panic!("the lookup does not return"),
                }
            }
            timeout(WAIT, async {
                while STARTED.load(Ordering::SeqCst) < 4 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the four lookups that got a place must start");
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                STARTED.load(Ordering::SeqCst),
                4,
                "a lookup abandoned by its OPEN must keep its place until it returns"
            );
            assert_eq!(PEAK.load(Ordering::SeqCst), 4);

            // Nothing is leaked: once they have returned, lookups run again.
            HOLD.store(false, Ordering::SeqCst);
            let patient = named_services(port);
            timeout(WAIT, patient.open(&request("tcp:app", 1)))
                .await
                .expect("a lookup once the abandoned ones are done")
                .map(drop)
                .unwrap();
        }

        #[tokio::test]
        async fn an_address_needs_no_lookup() {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            let mut services = LocalServices::new()
                .serve(
                    "tcp:app".parse().unwrap(),
                    LocalTarget::new("127.0.0.1", port),
                )
                .unwrap();
            services.resolve = |_, _| panic!("an address is not looked up");
            services
                .open(&request("tcp:app", 1))
                .await
                .map(drop)
                .unwrap();
        }
    }

    /// `egress:*` through [`LocalServices::with_egress`] (protocol.md 8, the dial itself is
    /// `crate::egress`'s): what reaches the executor, the slots and the pipe.
    mod egress {
        use menzil_proto::{EgressRule, HostPortPattern, OpenTarget};
        use tokio::sync::Notify;

        use super::*;

        /// An executor with the test only floor (127.0.0.0/8 may be dialled) whose rule allows
        /// `allow`, no resolver needed and no own addresses.
        fn executor(allow: &[&str], enabled: bool) -> EgressExecutor {
            let rule = EgressRule {
                node_id: NodeId::from([7u8; 32]),
                allow: allow.iter().map(|t| HostPortPattern((*t).into())).collect(),
                deny: vec![],
            };
            EgressExecutor::new(enabled, Arc::new(move |_: &NetworkId| Some(rule.clone())))
                .with_own_addresses(|| Ok(Vec::new()))
                .narrowed_floor_for_tests()
        }

        fn egress_request(port: u16) -> OpenRequest {
            OpenRequest {
                target: Some(OpenTarget {
                    host: "127.0.0.1".to_owned(),
                    port,
                }),
                ..request("egress:*", 1)
            }
        }

        async fn nothing_accepted(listener: &TcpListener) {
            assert!(
                timeout(Duration::from_millis(150), listener.accept())
                    .await
                    .is_err(),
                "the target was connected to"
            );
        }

        impl Rig {
            async fn open_egress(
                &self,
                service: &str,
                host: &str,
                port: u16,
            ) -> (Stream, menzil_proto::OpenAckBody) {
                let mut stream = self.client.open().await.unwrap();
                let body = OpenBody {
                    target: Some(OpenTarget {
                        host: host.to_owned(),
                        port,
                    }),
                    ..open_body(service)
                };
                let ack = initiate_open(&mut stream, &body).await.unwrap();
                (stream, ack)
            }
        }

        #[tokio::test]
        async fn an_egress_open_on_the_relay_principals_path_is_refused_even_when_egress_is_on() {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            // The rules would let this dial through (loopback is open to the test floor), so the
            // refusal below is the path's own.
            let services = LocalServices::new().with_egress(executor(&["127.0.0.0/8"], true));
            let refused = services
                .open_with_own_limits(&egress_request(port))
                .await
                .map(drop)
                .unwrap_err();
            assert_eq!(refused.code, ErrorCode::UnknownService);
            nothing_accepted(&listener).await;
            assert_eq!(services.connections(), 0);
            // The same executor serves a counted peer open.
            services
                .open(&egress_request(port))
                .await
                .map(drop)
                .expect("a counted peer OPEN is dialled");
            timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        }

        #[tokio::test]
        async fn without_an_enabled_executor_an_egress_open_is_unknown_service() {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            let none = LocalServices::new();
            let disabled = LocalServices::new().with_egress(executor(&["127.0.0.0/8"], false));
            for (what, services) in [("none", none), ("disabled", disabled)] {
                let refused = services
                    .open(&egress_request(port))
                    .await
                    .map(drop)
                    .unwrap_err();
                assert_eq!(refused.code, ErrorCode::UnknownService, "{what}");
            }
            // Over the wire too, with the OPEN exchange on a stream.
            let rig = Rig::new(LocalServices::new());
            let (_stream, ack) = rig.open_egress("egress:*", "127.0.0.1", port).await;
            assert!(!ack.ok);
            assert_eq!(ack.code, ErrorCode::UnknownService);
            nothing_accepted(&listener).await;
        }

        #[tokio::test]
        async fn only_the_literal_egress_star_is_served() {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            let services = LocalServices::new().with_egress(executor(&["127.0.0.0/8"], true));
            let mut other = egress_request(port);
            other.service = "egress:other".parse().unwrap();
            let refused = services.open(&other).await.map(drop).unwrap_err();
            assert_eq!(refused.code, ErrorCode::UnknownService);
            nothing_accepted(&listener).await;
        }

        #[tokio::test]
        async fn the_local_service_table_never_maps_egress() {
            let services = LocalServices::new().with_egress(executor(&["127.0.0.0/8"], true));
            assert_eq!(
                services
                    .set_target(
                        "egress:*".parse().unwrap(),
                        LocalTarget::new("127.0.0.1", 1)
                    )
                    .unwrap_err(),
                ServeConfigError::UnsupportedKind(ServiceKind::Egress)
            );
            assert!(services.is_empty());
        }

        #[tokio::test]
        async fn an_egress_open_is_ok_only_after_the_connect_and_the_pipe_carries_bytes_both_ways()
        {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            let gate = Arc::new(Notify::new());
            let connector_gate = gate.clone();
            let services = LocalServices::new().with_egress(
                executor(&["127.0.0.0/8"], true).with_connector(move |addr, buffer| {
                    let gate = connector_gate.clone();
                    async move {
                        gate.notified().await;
                        connect_addr(addr, buffer).await
                    }
                }),
            );
            let counted = services.clone();
            let rig = Rig::new(services);
            let target = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 64];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    socket.write_all(&buf[..n]).await.unwrap();
                }
                socket.shutdown().await.unwrap();
            });

            let opening = rig.open_egress("egress:*", "127.0.0.1", port);
            tokio::pin!(opening);
            // While the connect is held there is no answer, ok or otherwise.
            assert!(
                timeout(Duration::from_millis(200), &mut opening)
                    .await
                    .is_err(),
                "the OPEN was answered before the connect finished"
            );
            gate.notify_one();
            let (mut stream, ack) = timeout(WAIT, &mut opening).await.unwrap();
            assert!(ack.ok, "{ack:?}");
            // It holds a slot of the node like any served connection.
            assert_eq!(counted.connections(), 1);

            stream.write_all(b"hello egress").await.unwrap();
            let mut back = [0u8; 12];
            timeout(WAIT, stream.read_exact(&mut back))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&back, b"hello egress");
            stream.close().await.unwrap();
            let mut rest = Vec::new();
            timeout(WAIT, stream.read_to_end(&mut rest))
                .await
                .unwrap()
                .expect("a clean end");
            assert!(rest.is_empty());
            timeout(WAIT, target).await.unwrap().unwrap();
            // The slot comes back with the pipe.
            for _ in 0..50 {
                if counted.connections() == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(counted.connections(), 0);
        }

        #[tokio::test]
        async fn a_refused_egress_target_is_answered_in_the_ack_and_costs_no_slot() {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            // The production floor: loopback is refused.
            let rule = EgressRule {
                node_id: NodeId::from([7u8; 32]),
                allow: vec![HostPortPattern("0.0.0.0/0".into())],
                deny: vec![],
            };
            let production =
                EgressExecutor::new(true, Arc::new(move |_: &NetworkId| Some(rule.clone())))
                    .with_own_addresses(|| Ok(Vec::new()));
            let services = LocalServices::new().with_egress(production);
            let counted = services.clone();
            let rig = Rig::new(services);
            let (_stream, ack) = rig.open_egress("egress:*", "127.0.0.1", port).await;
            assert!(!ack.ok);
            assert_eq!(ack.code, ErrorCode::Forbidden);
            let (_stream, ack) = rig.open_egress("egress:*", "127.1", port).await;
            assert_eq!(ack.code, ErrorCode::InvalidTarget);
            nothing_accepted(&listener).await;
            assert_eq!(counted.connections(), 0);
        }

        #[tokio::test]
        async fn egress_opens_share_the_slots_of_the_node_and_are_refused_past_them() {
            let listener = listener().await;
            let port = listener.local_addr().unwrap().port();
            let services = LocalServices::new()
                .with_limits(limits(1, 1))
                .with_egress(executor(&["127.0.0.0/8"], true));
            let first = services.open(&egress_request(port)).await.unwrap();
            assert_eq!(services.connections(), 1);
            assert_rate_limited(services.open(&egress_request(port)).await, "egress");
            drop(first);
            services
                .open(&egress_request(port))
                .await
                .map(drop)
                .expect("a slot is free again");
        }
    }
}
