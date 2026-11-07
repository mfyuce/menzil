//! `menzil-relay-admin`: see the library and `README.md`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use menzil_cli::home::Home;
use menzil_relay_admin::certs::generate;
use menzil_relay_admin::{Admin, AdminServer, TlsFiles, server_config};
use tokio::signal::unix::{SignalKind, signal};

/// How long open requests get to finish after SIGTERM or SIGINT.
const GRACE: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(
    name = "menzil-relay-admin",
    version,
    about = "mTLS gRPC admin agent for a menzil relay's tenant files",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,
    /// The relay's menzil home (the directory that holds `relay/`); default: the usual home.
    #[arg(long)]
    home: Option<PathBuf>,
    /// Address to listen on. A non loopback address is allowed and warned about.
    #[arg(long, default_value = "127.0.0.1:7443")]
    listen: SocketAddr,
    /// The server certificate chain (PEM).
    #[arg(long)]
    cert: Option<PathBuf>,
    /// The server private key (PEM, mode 0600).
    #[arg(long)]
    key: Option<PathBuf>,
    /// The CA that signs client certificates (PEM): the only trust anchor.
    #[arg(long)]
    client_ca: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Make a private CA, a server certificate and a client certificate in a directory.
    GenCerts {
        /// The directory to write into (made 0700 if missing; nothing is overwritten).
        #[arg(long)]
        out: PathBuf,
        /// The server's name (a DNS name or an IP); 127.0.0.1 is always added.
        #[arg(long)]
        server_name: String,
        /// The client certificate's name.
        #[arg(long, default_value = "menzil-ui")]
        client_name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();
    if let Some(Cmd::GenCerts {
        out,
        server_name,
        client_name,
    }) = cli.command
    {
        let files = generate(&out, &server_name, &client_name).map_err(anyhow::Error::msg)?;
        println!(
            "server side: {} {} {}",
            files.server_cert.display(),
            files.server_key.display(),
            files.ca_cert.display()
        );
        println!(
            "menzil-ui side: {} {} {}",
            files.client_cert.display(),
            files.client_key.display(),
            files.ca_cert.display()
        );
        println!(
            "move {} offline: it signs new certificates and the agent never needs it",
            files.ca_key.display()
        );
        return Ok(());
    }
    let (Some(cert), Some(key), Some(client_ca)) = (cli.cert, cli.key, cli.client_ca) else {
        bail!("--cert, --key and --client-ca are required");
    };
    let home = match cli.home {
        Some(root) => Home::new(root),
        None => Home::locate()?,
    };
    let config = server_config(&TlsFiles {
        cert,
        key,
        client_ca,
    })?;
    if !cli.listen.ip().is_loopback() {
        tracing::warn!(
            "listening on a non loopback address; only clients with a certificate of the client CA are served"
        );
    }
    let server = AdminServer::bind(cli.listen, config, Admin::new(home))
        .await
        .context("cannot listen")?;
    tracing::info!(listen = %server.local_addr()?, "serving (mutual TLS 1.3)");
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let serving = server.serve(async {
        let _ = stop_rx.await;
    });
    tokio::pin!(serving);
    tokio::select! {
        result = &mut serving => result?,
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    let _ = stop_tx.send(());
    if tokio::time::timeout(GRACE, serving).await.is_err() {
        tracing::warn!("open requests did not finish in time; stopping");
    }
    Ok(())
}
