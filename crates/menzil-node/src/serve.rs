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
//!   one is answered `unknown_service`.
//! * **The local connect comes before the OPEN_ACK.** [`Self::open`]
//!   (`ServiceHandler::open`) connects to the target inside the caller's 10
//!   second OPEN timeout, with its own, shorter limit
//!   ([`DEFAULT_CONNECT_TIMEOUT`]). A target that refuses or does not answer
//!   is an OPEN_ACK `ok: false` with `target_unreachable`, never an
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
//!   and so does the pipe being dropped before it finished (the node shutting down).
//! * **Not bounded here.** A pipe has no idle timeout; the streams a
//!   session may hold are bounded by `menzil-stream`'s live stream limit and
//!   the OPEN admission control of [`crate::accept_loop`]. A target that
//!   stalls forever holds its stream until the peer ends it.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::io::{AsyncRead, AsyncWrite};
use menzil_proto::{ErrorCode, ServiceId, ServiceKind};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use thiserror::Error;
use tokio::io::{ReadBuf, copy_bidirectional_with_sizes};
use tokio::net::TcpStream;

/// How long [`LocalServices`] waits for the local connect by default. Well
/// inside the 10 second OPEN timeout the peer runs (protocol.md 5.3), so a
/// dead target is answered with a refusal rather than a timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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

/// The services a node offers and the local targets behind them. See the
/// module documentation.
#[derive(Debug, Clone)]
pub struct LocalServices {
    targets: HashMap<ServiceId, LocalTarget>,
    connect_timeout: Duration,
}

impl Default for LocalServices {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalServices {
    /// A node that serves nothing yet.
    pub fn new() -> Self {
        Self {
            targets: HashMap::new(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Serves `service` from `target`, replacing what it was served from
    /// before. Refused for a kind other than `tcp`, `http` and `tls`, and
    /// for a label that is empty or `*`.
    pub fn serve(
        mut self,
        service: ServiceId,
        target: LocalTarget,
    ) -> Result<Self, ServeConfigError> {
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
        self.targets.insert(service, target);
        Ok(self)
    }

    /// Gives up on the local connect after `timeout` instead of
    /// [`DEFAULT_CONNECT_TIMEOUT`]. Keep it under the 10 seconds a peer waits
    /// for the OPEN_ACK.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// The target `service` is served from, if it is.
    pub fn target(&self, service: &ServiceId) -> Option<&LocalTarget> {
        self.targets.get(service)
    }

    /// How many services are configured.
    pub fn len(&self) -> usize {
        self.targets.len()
    }

    /// Whether nothing is configured.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

fn refusal(code: ErrorCode, msg: &str) -> OpenRefusal {
    OpenRefusal {
        code,
        msg: msg.to_string(),
    }
}

impl ServiceHandler<Stream> for LocalServices {
    type Opened = TcpStream;
    type Handling = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<TcpStream, OpenRefusal> {
        let Some(target) = self.targets.get(&request.service) else {
            return Err(refusal(ErrorCode::UnknownService, "no such service"));
        };
        let connect = TcpStream::connect((target.host.as_str(), target.port));
        match tokio::time::timeout(self.connect_timeout, connect).await {
            Ok(Ok(socket)) => {
                // Interactive services (a shell) must not wait for Nagle.
                let _ = socket.set_nodelay(true);
                Ok(socket)
            }
            Ok(Err(error)) => {
                tracing::info!(
                    service = %request.service,
                    target = %target,
                    %error,
                    "the local target refused a connection for a granted OPEN"
                );
                Err(refusal(
                    ErrorCode::TargetUnreachable,
                    "could not connect to the local target",
                ))
            }
            Err(_) => {
                tracing::info!(
                    service = %request.service,
                    target = %target,
                    "the local target did not answer in time for a granted OPEN"
                );
                Err(refusal(
                    ErrorCode::TargetUnreachable,
                    "the local target did not answer in time",
                ))
            }
        }
    }

    fn handle(&self, stream: Stream, request: OpenRequest, socket: TcpStream) -> Self::Handling {
        Box::pin(pipe(stream, socket, request.service))
    }
}

/// Pipes `stream` to `socket` until both directions have ended, and resets
/// both when the pipe ends any other way. See the module documentation.
async fn pipe(stream: Stream, socket: TcpStream, service: ServiceId) {
    let mut pipe = Pipe {
        remote: Some(TokioStream(stream)),
        local: Some(socket),
    };
    pipe.run(&service).await;
}

/// The two ends of one served stream. Dropping it before [`Pipe::run`] has
/// seen both directions finish (the task was aborted, the node is shutting
/// down) resets both ends.
struct Pipe {
    remote: Option<TokioStream>,
    local: Option<TcpStream>,
}

impl Pipe {
    async fn run(&mut self, service: &ServiceId) {
        let (Some(remote), Some(local)) = (self.remote.as_mut(), self.local.as_mut()) else {
            return;
        };
        match copy_bidirectional_with_sizes(remote, local, PIPE_BUFFER, PIPE_BUFFER).await {
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
struct TokioStream(Stream);

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
        Authorizer, Mode, OpenDecision, OpenRequest, OutboundFrames, Responded, Stream, StreamMux,
        initiate_open, respond_to_open,
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

    fn is_reset(error: &io::Error) -> bool {
        matches!(
            error.kind(),
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
        )
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

        let task = tokio::spawn(pipe(remote, local, "tcp:app".parse().unwrap()));
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
}
