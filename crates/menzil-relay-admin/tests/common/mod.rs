#![allow(dead_code)]
//! A real agent over loopback with a real mTLS client, on a temporary relay home.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hyper_util::rt::TokioIo;
use menzil_cli::home::Home;
use menzil_cli::local::{init, network_create, token_for_relay};
use menzil_proto::NetworkId;
use menzil_relay_admin::certs::{Generated, generate};
use menzil_relay_admin::pb::tenant_admin_client::TenantAdminClient;
use menzil_relay_admin::{Admin, AdminServer, TlsFiles, server_config};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tonic::transport::{Channel, Endpoint};

pub fn clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An owner's home with one network, and the token a relay is given for it.
pub struct Owner {
    pub _dir: tempfile::TempDir,
    pub home: Home,
    pub id: NetworkId,
}

impl Owner {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path().join("menzil"));
        init(&home, clock()).unwrap();
        let id = network_create(&home, "laptop", clock()).unwrap();
        Self {
            _dir: dir,
            home,
            id,
        }
    }
    pub fn token(&self) -> String {
        token_for_relay(&self.home, None).unwrap()
    }
}

pub fn files_of(g: &Generated) -> TlsFiles {
    TlsFiles {
        cert: g.server_cert.clone(),
        key: g.server_key.clone(),
        client_ca: g.ca_cert.clone(),
    }
}

pub struct Fixture {
    pub _dir: tempfile::TempDir,
    pub relay_home: PathBuf,
    pub certs: Generated,
    pub addr: SocketAddr,
    pub admin: Admin,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    pub task: Option<tokio::task::JoinHandle<()>>,
}

impl Fixture {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let relay_home = dir.path().join("relay-home");
        let certs = generate(&dir.path().join("certs"), "localhost", "menzil-ui").unwrap();
        let config = server_config(&files_of(&certs)).unwrap();
        let admin = Admin::new(Home::new(&relay_home));
        let server = AdminServer::bind("127.0.0.1:0".parse().unwrap(), config, admin.clone())
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = server
                .serve(async {
                    let _ = stop_rx.await;
                })
                .await;
        });
        Self {
            _dir: dir,
            relay_home,
            certs,
            addr,
            admin,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub fn home(&self) -> Home {
        Home::new(&self.relay_home)
    }

    pub fn tenant_file(&self, slug: &str) -> PathBuf {
        self.relay_home
            .join("relay")
            .join("tenants")
            .join(format!("{slug}.toml"))
    }

    /// A client with the certificate and the CA of this fixture.
    pub async fn client(&self) -> TenantAdminClient<Channel> {
        connect(
            self.addr,
            &self.certs.ca_cert,
            Some((&self.certs.client_cert, &self.certs.client_key)),
        )
        .await
        .expect("connect")
    }

    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10), task).await;
        }
    }
}

pub fn client_config(trust: &Path, identity: Option<(&Path, &Path)>) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(trust).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
    let mut config = match identity {
        Some((cert, key)) => {
            let chain = CertificateDer::pem_file_iter(cert)
                .unwrap()
                .map(Result::unwrap)
                .collect();
            builder
                .with_client_auth_cert(chain, PrivateKeyDer::from_pem_file(key).unwrap())
                .unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    config
}

/// A TLS channel to `addr` verifying the server as `localhost`.
pub async fn connect(
    addr: SocketAddr,
    trust: &Path,
    identity: Option<(&Path, &Path)>,
) -> Result<TenantAdminClient<Channel>, tonic::transport::Error> {
    connect_with(addr, client_config(trust, identity)).await
}

/// A TLS channel with a client configuration of the caller's.
pub async fn connect_with(
    addr: SocketAddr,
    config: rustls::ClientConfig,
) -> Result<TenantAdminClient<Channel>, tonic::transport::Error> {
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let channel = Endpoint::from_static("http://localhost")
        .connect_with_connector(tower::service_fn(move |_| {
            let connector = connector.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                let tls = connector
                    .connect(ServerName::try_from("localhost").unwrap(), tcp)
                    .await?;
                Ok::<_, std::io::Error>(TokioIo::new(tls))
            }
        }))
        .await?;
    Ok(TenantAdminClient::new(channel))
}
