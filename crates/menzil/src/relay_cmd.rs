//! `menzil relay`: running a relay and telling it which networks it serves.
//!
//! A relay machine is initialised like any device (`menzil init`: its identity is the anchor
//! nodes pin) but it is never a member of a network (protocol.md 6.1). It learns the networks it
//! serves from their owners: `menzil relay add-network <token>` takes the Roster token the
//! owner printed with `menzil token --for-relay` and keeps it as `<home>/relay/<network>.roster`.
//! The Policy travels only between members (protocol.md 2.3), so the token a relay is given does
//! not carry it, and a full membership token is refused. Members push newer
//! Rosters to the relay when they attach (protocol.md 4.3), so the file only has to be good
//! enough to start from.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::VerifyingKey;
use menzil_proto::{Limits, NetworkId, Roster};
use menzil_relay::{Listener, Relay, RelayIdentity};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinHandle;

use crate::home::{Home, parse_hex32};
use crate::local::load_identity;
use crate::token::decode_roster;

/// The WebSocket path nodes ask for unless the operator picks another (protocol.md 3.1).
pub const DEFAULT_PATH: &str = "/_menzil/v1";

/// The per session figures a relay announces in WELCOME: the largest record the protocol has,
/// the credit protocol.md 10 names, and a ceiling on peers nobody reads yet.
const LIMITS: Limits = Limits {
    max_record: 65_535,
    max_peers: 1024,
    credit: 1 << 20,
};

fn relay_dir(home: &Home) -> PathBuf {
    home.root().join("relay")
}

fn roster_path(home: &Home, network_id: &NetworkId) -> PathBuf {
    relay_dir(home).join(format!("{}.roster", network_id.to_hex()))
}

/// Keeps the Roster in a relay token as a network this relay serves. The signature is checked
/// against the network's own key, an expired Roster is refused, and a Roster no newer than the
/// one kept is left alone. Returns the network and the sequence number now kept.
pub fn add_network(home: &Home, token: &str, now: u64) -> Result<(NetworkId, u64)> {
    let roster = decode_roster(token)?;
    let body = roster.decode()?;
    let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.network_id))
        .map_err(|_| anyhow!("{} is not a valid network id", body.network_id))?;
    roster
        .verify(&key)
        .context("this Roster was not signed by the network's owner")?;
    if body.expires <= now {
        bail!("this Roster has expired: ask the owner for a current token");
    }
    // From the look at what is held to the write: two runs at once could each see the older
    // Roster and the slower write would put it over the newer.
    let _lock = home.lock_relay()?;
    let path = roster_path(home, &body.network_id);
    if let Ok(held) = fs::read(&path)
        && let Ok(held) = Roster::decode_strict(&held)
        && let Ok(held) = held.decode()
        && held.seq >= body.seq
    {
        return Ok((body.network_id, held.seq));
    }
    home.write_public(&path, &roster.encode())?;
    Ok((body.network_id, body.seq))
}

/// The Rosters this relay serves. A file that cannot be read is an error, not a network that
/// quietly goes unserved.
pub fn load_rosters(home: &Home) -> Result<Vec<Roster>> {
    let (rosters, mut failures) = load_rosters_each(home)?;
    if failures.is_empty() {
        Ok(rosters)
    } else {
        Err(failures.swap_remove(0))
    }
}

/// Every Roster in the relay's directory that can be read, and an error for each file that
/// cannot: one damaged file is not allowed to hide the others (the fourth red-team round, L3: a
/// running relay that read them as a whole picked up no newer Roster, a revocation among them,
/// for any network while one file was damaged).
pub fn load_rosters_each(home: &Home) -> Result<(Vec<Roster>, Vec<anyhow::Error>)> {
    let dir = relay_dir(home);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((vec![], vec![])),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let (mut rosters, mut failures) = (Vec::new(), Vec::new());
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("roster") {
            continue;
        }
        let name_ok = path
            .file_stem()
            .and_then(|s| s.to_str())
            .is_some_and(|s| parse_hex32(s).is_some());
        if !name_ok {
            continue;
        }
        let read = fs::read(&path)
            .with_context(|| format!("reading {}", path.display()))
            .and_then(|bytes| {
                Roster::decode_strict(&bytes)
                    .with_context(|| format!("{} is damaged", path.display()))
            });
        match read {
            Ok(roster) => rosters.push(roster),
            Err(error) => failures.push(error),
        }
    }
    Ok((rosters, failures))
}

/// This machine's identity as a relay's: the certificate nodes verify and the key behind it.
pub fn relay_identity(home: &Home) -> Result<RelayIdentity> {
    let (keys, cert) = load_identity(home)?;
    Ok(RelayIdentity {
        node_cert: cert,
        x25519_private: keys.x25519_private(),
    })
}

/// The connection information nodes put in their `config.toml` (protocol.md 3.2): the anchor
/// (this relay's NodeId) and its static key, which saves nodes a round trip.
pub fn connection_info(
    host: &str,
    port: u16,
    path: &str,
    identity: &RelayIdentity,
) -> Result<String> {
    let cert = identity.node_cert.decode()?;
    Ok(format!(
        "menzil://{host}:{port}{path}?id={}&key={}",
        cert.node_id.to_hex(),
        cert.x25519_pub.to_hex()
    ))
}

/// A `rustls` server configuration from PEM files: a certificate chain and a private key, such
/// as the `fullchain.pem` and `privkey.pem` certbot writes.
pub fn tls_from_pem(cert: &Path, key: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let chain = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading {}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{} holds no valid certificate", cert.display()))?;
    if chain.is_empty() {
        bail!("{} holds no certificate", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .with_context(|| format!("{} holds no private key", key.display()))?;
    Ok(menzil_relay::server_config(chain, key)?)
}

/// How to run the relay.
#[derive(Debug, Clone)]
pub struct RunOptions {
    /// Where to listen.
    pub listen: SocketAddr,
    /// The TLS certificate chain, PEM.
    pub tls_cert: PathBuf,
    /// The TLS private key, PEM.
    pub tls_key: PathBuf,
    /// The WebSocket path to answer on.
    pub path: String,
    /// The public name of this relay, for the connection information that is printed.
    pub host: Option<String>,
    /// How often the relay looks for newer Rosters on disk (what `add-network` writes while the
    /// relay runs).
    pub reload_every: std::time::Duration,
}

/// How often a relay reloads its Rosters unless told otherwise.
pub const DEFAULT_RELOAD_EVERY: std::time::Duration = std::time::Duration::from_secs(15);

/// A relay that is listening.
pub struct RunningRelay {
    /// The address it listens on.
    pub addr: SocketAddr,
    /// The connection information for nodes, with the host name the operator gave (or
    /// `RELAY-HOST`).
    pub connection_info: String,
    /// The networks it serves.
    pub networks: Vec<NetworkId>,
    relay: Relay,
    task: JoinHandle<()>,
    reload: JoinHandle<()>,
}

impl RunningRelay {
    /// Waits for the relay's task, which only ends if it is aborted.
    pub async fn wait(&mut self) {
        let _ = (&mut self.task).await;
    }

    /// The sequence number of the Roster the relay holds for `network_id` now.
    pub fn roster_seq(&self, network_id: &NetworkId) -> Option<u64> {
        self.relay.rosters().get(network_id).map(|body| body.seq)
    }

    /// Stops the relay.
    pub fn stop(&self) {
        self.task.abort();
        self.reload.abort();
    }
}

impl Drop for RunningRelay {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The system clock in Unix seconds, for the time rules of protocol.md 2.3.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Binds, loads the Rosters and starts serving.
pub async fn start(home: &Home, options: &RunOptions) -> Result<RunningRelay> {
    let identity = relay_identity(home)?;
    let rosters = load_rosters(home)?;
    if rosters.is_empty() {
        bail!("this relay serves no network: run `menzil relay add-network <token>` first");
    }
    let tls = tls_from_pem(&options.tls_cert, &options.tls_key)?;
    let listener = Listener::bind(options.listen, tls, options.path.clone()).await?;
    let addr = listener.local_addr()?;
    let info = connection_info(
        options.host.as_deref().unwrap_or("RELAY-HOST"),
        addr.port(),
        &options.path,
        &identity,
    )?;
    let relay = Relay::new(identity, LIMITS);
    let mut networks = Vec::new();
    for roster in &rosters {
        relay.rosters().adopt(roster, None, unix_now())?;
        networks.push(roster.decode()?.network_id);
    }
    let serving = relay.clone();
    let task = tokio::spawn(async move { serving.serve(&listener).await });
    // `add-network` with a newer token while the relay runs is picked up here; the store keeps
    // the newer of what it holds and what is read (protocol.md 2.3: never a lower `seq`), and
    // members push newer Rosters themselves whenever they attach.
    let reload = {
        let (relay, home, every) = (relay.clone(), home.clone(), options.reload_every);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                match load_rosters_each(&home) {
                    Ok((rosters, failures)) => {
                        for failure in &failures {
                            tracing::warn!(error = %format!("{failure:#}"), "a Roster file cannot be read");
                        }
                        for roster in &rosters {
                            if let Err(error) = relay.rosters().adopt(roster, None, unix_now()) {
                                tracing::warn!(%error, "a Roster on disk was refused");
                            }
                        }
                    }
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "reading the Rosters failed");
                    }
                }
            }
        })
    };
    Ok(RunningRelay {
        addr,
        connection_info: info,
        networks,
        relay,
        task,
        reload,
    })
}

#[cfg(test)]
mod tests;
