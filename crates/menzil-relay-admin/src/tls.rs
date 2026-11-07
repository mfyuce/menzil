//! Mutual TLS, and nothing else: there is no plaintext listener in this crate.
//!
//! The server speaks TLS 1.3 only, asks every client for a certificate and verifies it against the
//! client CA file alone (never the system roots). A connection whose handshake fails is dropped in
//! the accept task and never reaches tonic, so no handler sees it.

use std::fs;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::transport::server::Connected;

use crate::service::Admin;

/// How long a client has to finish the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How many connections (handshaking or open) are served at once.
pub const MAX_CONNECTIONS: usize = 64;

/// The three files the server needs.
#[derive(Debug, Clone)]
pub struct TlsFiles {
    /// The server certificate chain (PEM).
    pub cert: PathBuf,
    /// The server's private key (PEM); refused when group or other can read it.
    pub key: PathBuf,
    /// The CA that signs the clients' certificates (PEM). The only trust anchor.
    pub client_ca: PathBuf,
}

/// Why the server cannot start. The text names files: it goes to the operator's terminal, never
/// into an RPC status.
#[derive(Debug)]
pub struct TlsError(pub String);

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TlsError {}

/// Refuses a key file that group or other can read or write, or that is not a plain file.
pub fn check_key_mode(path: &Path) -> Result<(), TlsError> {
    let meta = fs::metadata(path)
        .map_err(|e| TlsError(format!("cannot read the key file {}: {e}", path.display())))?;
    if !meta.is_file() {
        return Err(TlsError(format!("{} is not a file", path.display())));
    }
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(TlsError(format!(
            "the key file {} has mode {mode:03o}: group and other must have no access (chmod 600)",
            path.display()
        )));
    }
    Ok(())
}

/// The server's TLS configuration: TLS 1.3 only, client certificate required, verified against
/// the client CA only, ALPN `h2`.
pub fn server_config(files: &TlsFiles) -> Result<rustls::ServerConfig, TlsError> {
    check_key_mode(&files.key)?;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certs = CertificateDer::pem_file_iter(&files.cert)
        .map_err(|e| TlsError(format!("cannot read {}: {e}", files.cert.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError(format!("bad certificate in {}: {e}", files.cert.display())))?;
    if certs.is_empty() {
        return Err(TlsError(format!(
            "no certificate in {}",
            files.cert.display()
        )));
    }
    let key = PrivateKeyDer::from_pem_file(&files.key).map_err(|e| {
        TlsError(format!(
            "cannot read the key in {}: {e}",
            files.key.display()
        ))
    })?;
    let mut roots = RootCertStore::empty();
    let cas = CertificateDer::pem_file_iter(&files.client_ca)
        .map_err(|e| TlsError(format!("cannot read {}: {e}", files.client_ca.display())))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            TlsError(format!(
                "bad certificate in {}: {e}",
                files.client_ca.display()
            ))
        })?;
    if cas.is_empty() {
        return Err(TlsError(format!(
            "no certificate in {}",
            files.client_ca.display()
        )));
    }
    for ca in cas {
        roots.add(ca).map_err(|e| {
            TlsError(format!(
                "bad client CA in {}: {e}",
                files.client_ca.display()
            ))
        })?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| TlsError(format!("client verifier: {e}")))?;
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| TlsError(format!("TLS versions: {e}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| TlsError(format!("the server certificate and key do not fit: {e}")))?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// A TLS connection with a verified client, as tonic wants it.
struct Conn {
    inner: TlsStream<TcpStream>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Connected for Conn {
    type ConnectInfo = ();
    fn connect_info(&self) {}
}

impl AsyncRead for Conn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Conn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The agent, bound but not yet serving.
pub struct AdminServer {
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    admin: Admin,
}

impl AdminServer {
    /// Binds `addr` (port 0 picks one). Nothing is served until [`Self::serve`].
    pub async fn bind(
        addr: SocketAddr,
        config: rustls::ServerConfig,
        admin: Admin,
    ) -> io::Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(addr).await?,
            config: Arc::new(config),
            admin,
        })
    }

    /// The address bound.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves until `shutdown` completes, then stops accepting and lets open requests finish.
    pub async fn serve(
        self,
        shutdown: impl Future<Output = ()>,
    ) -> Result<(), tonic::transport::Error> {
        let (tx, rx) = mpsc::channel::<io::Result<Conn>>(16);
        let acceptor = TlsAcceptor::from(self.config);
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let listener = self.listener;
        let accepting = tokio::spawn(async move {
            loop {
                // A free slot first: beyond the limit a connection waits in the backlog.
                let Ok(permit) = slots.clone().acquire_owned().await else {
                    return;
                };
                let (tcp, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    // A failed handshake (no certificate, a certificate of another CA, plaintext,
                    // TLS 1.2) ends here: tonic never sees the connection.
                    if let Ok(Ok(inner)) =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                    {
                        let _ = tx
                            .send(Ok(Conn {
                                inner,
                                _permit: permit,
                            }))
                            .await;
                    }
                });
            }
        });
        // The transport's own deadline is a backstop that always fires after the agent's, so the
        // agent's (which cancels a queued change) is the one a client sees.
        let backstop = self.admin.request_timeout() + Duration::from_secs(2);
        let result = Server::builder()
            .timeout(backstop)
            .max_concurrent_streams(crate::service::MAX_CONCURRENT as u32)
            .add_service(self.admin.into_server())
            .serve_with_incoming_shutdown(ReceiverStream::new(rx), shutdown)
            .await;
        accepting.abort();
        result
    }
}
