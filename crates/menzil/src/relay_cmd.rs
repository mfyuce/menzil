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
use menzil_proto::trust::{DOC_MAX_LIFETIME, HeldRoster, HeldView, Reason, Verdict, check_bundle};
use menzil_proto::{Limits, NetworkId, Roster};
use menzil_relay::{Listener, Relay, RelayError, RelayIdentity};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinHandle;

use crate::home::{Home, parse_hex32};
use crate::local::load_identity;
use crate::persist::Worker;
use crate::token::{decode_roster, roster_from_bytes, roster_to_bytes};

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

/// A Roster this relay serves, as it is kept on disk: with the owner signed Roster it was made
/// from when a steward signed it (protocol.md 2.3).
#[derive(Debug, Clone)]
pub struct StoredRoster {
    /// The Roster.
    pub roster: Roster,
    /// Its base, for a Roster a steward signed.
    pub base: Option<Roster>,
}

/// Keeps the Roster in a relay token as a network this relay serves. It must pass the
/// acceptance predicate of protocol.md 2.3 (`menzil_proto::trust`: signed by the network's own
/// key, or by the steward its base lists, and not expired), and a Roster no newer than the one
/// kept is left alone. Returns the network and the sequence number now kept.
pub fn add_network(home: &Home, token: &str, now: u64) -> Result<(NetworkId, u64)> {
    let (roster, base) = decode_roster(token)?;
    keep_roster(home, &roster, base.as_ref(), now, Keep::Create)?
        .ok_or_else(|| anyhow!("the Roster was not kept"))
}

/// Whether [`keep_roster`] may bring a network into the relay's directory.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    /// `add-network`: the operator asks for the network, so a missing file is made.
    Create,
    /// The relay keeping a Roster it adopted over DOC: only a file that is there is updated, and
    /// one that cannot be read is not written over. A network the operator removed by hand
    /// stays removed (the tenant's next Roster must not bring it back at the next start).
    UpdateOnly,
}

/// Keeps `roster` (with its `base`, for a Roster a steward signed) as the Roster this relay
/// starts from for its network, if the acceptance predicate of protocol.md 2.3 takes it against
/// what is kept: [`add_network`] after decoding a token, and the relay itself for a Roster it
/// adopted over DOC. A Roster no newer than the one kept is left alone, so an older one never
/// replaces a newer one on disk, whoever hands it over and in whatever order. Returns the
/// network and the sequence number now kept; `None` for [`Keep::UpdateOnly`] when nothing is
/// held for the network.
fn keep_roster(
    home: &Home,
    roster: &Roster,
    base: Option<&Roster>,
    now: u64,
    keep: Keep,
) -> Result<Option<(NetworkId, u64)>> {
    let body = roster.decode()?;
    let bundle = menzil_proto::trust::Bundle {
        base_roster: base.cloned(),
        roster: Some(roster.clone()),
        ..Default::default()
    };
    // From the look at what is held to the write: two runs at once could each see the older
    // Roster and the slower write would put it over the newer, so the judgement is made under
    // the lock.
    let _lock = match keep {
        Keep::Create => home.lock_relay()?,
        Keep::UpdateOnly => match home.lock_relay_if_held()? {
            Some(lock) => lock,
            None => return Ok(None),
        },
    };
    let path = roster_path(home, &body.network_id);
    // Judge the token again against what is kept (protocol.md 2.3): a newer `seq` alone is not
    // enough, a steward's Roster on a base older than the kept Roster's base would undo what
    // the owner changed since. For `add-network` a file that cannot be read counts as nothing
    // held (the operator is replacing it); the keeper of an adopted Roster neither creates a
    // missing file nor writes over a damaged one.
    let bytes = match (fs::read(&path), keep) {
        (Ok(bytes), _) => Some(bytes),
        (Err(error), Keep::UpdateOnly) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        (Err(error), Keep::UpdateOnly) => {
            return Err(error).with_context(|| {
                format!(
                    "the Roster file {} cannot be read; not written over",
                    path.display()
                )
            });
        }
        (Err(_), Keep::Create) => None,
    };
    let held = bytes
        .and_then(|bytes| roster_from_bytes(&bytes).ok())
        .and_then(|(roster, base)| HeldRoster::new(&roster, base.as_ref()).ok());
    if held.is_none() && keep == Keep::UpdateOnly {
        bail!(
            "the Roster file {} cannot be read; not written over",
            path.display()
        );
    }
    let held_seq = held.as_ref().map(HeldRoster::seq);
    let view = HeldView {
        network_id: body.network_id,
        roster: held,
        policy_seq: None,
    };
    let adoption = match check_bundle(&view, &bundle, now) {
        Verdict::Adopt(adoption) => adoption,
        Verdict::Held => return Ok(Some((body.network_id, held_seq.unwrap_or(body.seq)))),
        Verdict::Reject(Reason::Expired) => {
            bail!("this Roster has expired: ask the owner for a current token")
        }
        Verdict::Reject(reason) => {
            bail!(
                "this Roster is not acceptable: {}",
                crate::local::refusal(reason)
            )
        }
    };
    // The owner's own signature makes a base pointless: it is not kept.
    let base = match adoption.signer {
        menzil_proto::trust::Signer::Owner => None,
        menzil_proto::trust::Signer::Steward { .. } => base,
    };
    home.write_public(&path, &roster_to_bytes(roster, base))?;
    Ok(Some((body.network_id, body.seq)))
}

/// The Rosters this relay serves. A file that cannot be read is an error, not a network that
/// quietly goes unserved.
pub fn load_rosters(home: &Home) -> Result<Vec<StoredRoster>> {
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
pub fn load_rosters_each(home: &Home) -> Result<(Vec<StoredRoster>, Vec<anyhow::Error>)> {
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
                roster_from_bytes(&bytes)
                    .map(|(roster, base)| StoredRoster { roster, base })
                    .map_err(|e| anyhow!("{} is damaged: {e}", path.display()))
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

/// How long a clean stop waits for the keeper to write the last Roster adopted over DOC.
pub const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

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
    keeper: Arc<Worker<(NetworkId, Roster, Option<Roster>)>>,
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

    /// Waits until every Roster the relay adopted over DOC so far has been written to (or
    /// refused by) the relay directory, at most `timeout`; whether it got there.
    pub fn flush_rosters(&self, timeout: std::time::Duration) -> bool {
        self.keeper.flush(timeout)
    }

    /// [`Self::flush_rosters`] off the async threads (it blocks on the keeper, which may wait
    /// for a lock another command holds): for a clean stop of `menzil relay run`, so that the
    /// last Roster adopted over DOC is on disk before the process goes.
    pub async fn flush_rosters_blocking(&self, timeout: std::time::Duration) -> bool {
        let keeper = Arc::clone(&self.keeper);
        tokio::task::spawn_blocking(move || keeper.flush(timeout))
            .await
            .unwrap_or(false)
    }

    /// Stops the relay.
    pub fn stop(&self) {
        self.task.abort();
        self.reload.abort();
    }
}

/// What `menzil relay run` does after it has started: waits until `stop` is ready (a signal) or
/// the relay's task ends, then flushes the keeper, so that the last Roster adopted over DOC is
/// on disk before the process goes (TOBEDECIDED 28b; bounded by [`STOP_GRACE`], the lock another
/// command holds is not waited for forever). `Some` with what `stop` gave if it was the signal.
pub async fn run_until<F: std::future::Future>(
    relay: &mut RunningRelay,
    stop: F,
) -> Option<F::Output> {
    let stopped = tokio::select! {
        _ = relay.wait() => None,
        out = stop => Some(out),
    };
    if !relay.flush_rosters_blocking(STOP_GRACE).await {
        eprintln!("menzil: the Rosters adopted last may not have reached the disk");
    }
    stopped
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
    for stored in &rosters {
        let network_id = stored.roster.decode()?.network_id;
        match relay
            .rosters()
            .adopt(&stored.roster, stored.base.as_ref(), unix_now())
        {
            Ok(_) => networks.push(network_id),
            // A Roster that ran out on disk (the relay does not write the ones it takes over
            // DOC, so the file is as old as the last `add-network`) or is not valid yet is
            // still held, judged at its own `issued` (every other rule of protocol.md 2.3
            // still applies), so that a member's newer Roster over DOC can replace it
            // (`accept_roster_chunk` refuses a network the store does not hold). Holding it
            // does not serve traffic: forwarding checks `expires` itself
            // (`RosterStore::grants_forwarding`). One that cannot be held that way holds back
            // its own network, not the others (the sixth red-team round, M1; the ninth, M2).
            Err(RelayError::DocumentRejected(reason @ (Reason::Expired | Reason::NotYetValid))) => {
                let issued = stored.roster.decode()?.issued;
                let held = issued <= unix_now().saturating_add(DOC_MAX_LIFETIME)
                    && relay
                        .rosters()
                        .adopt(&stored.roster, stored.base.as_ref(), issued)
                        .is_ok();
                if held {
                    networks.push(network_id);
                    tracing::warn!(
                        network = %network_id,
                        ?reason,
                        "the Roster on disk for this network is not valid now: held, but nothing is forwarded until a valid one arrives (a member's push, or `menzil relay add-network` with a newer token)"
                    );
                    eprintln!(
                        "warning: network {network_id}: the Roster on disk is not valid now ({reason:?}); held, not forwarding until a valid one arrives"
                    );
                } else {
                    tracing::warn!(
                        network = %network_id,
                        ?reason,
                        "the Roster on disk for this network is not valid now and cannot be held: the network is not served until a valid one arrives (`menzil relay add-network` with a newer token)"
                    );
                    eprintln!(
                        "warning: network {network_id}: the Roster on disk is not valid now ({reason:?}); not served until a valid one arrives"
                    );
                }
            }
            Err(error) => {
                return Err(anyhow::Error::new(error)
                    .context(format!("the Roster of network {network_id} was refused")));
            }
        }
    }
    // A Roster adopted from here on (a member's push over DOC, or a newer file `add-network`
    // wrote) is kept in the relay directory too, through the same judgement `add-network`
    // makes, so that a restart starts from it and not from the file the operator last wrote
    // (TOBEDECIDED 19d). A thread does the writing: it takes a file lock, and it must not hold
    // up the session that handed the Roster over. A write that fails is a warning; the Roster
    // stays held in memory.
    let keeper = {
        let home = home.clone();
        Worker::spawn(
            "menzil-relay-keep",
            |job: &(NetworkId, Roster, Option<Roster>)| job.0,
            move |(_, roster, base): (NetworkId, Roster, Option<Roster>)| {
                let Ok(body) = roster.decode() else { return };
                let network = Some(body.network_id);
                // Judged at the Roster's own `issued` time, like the held-but-expired start: the
                // time rules were checked when the store took it, and what is left to ask here is
                // its signatures and `seq` against the file.
                if let Err(error) =
                    keep_roster(&home, &roster, base.as_ref(), body.issued, Keep::UpdateOnly)
                {
                    tracing::warn!(?network, error = %format!("{error:#}"), "the Roster adopted over DOC could not be kept on disk: a restart will start from the older file");
                }
            },
        )?
    };
    {
        let keeper = Arc::clone(&keeper);
        relay.rosters().set_on_adopted(move |roster, base| {
            if let Ok(body) = roster.decode() {
                keeper.submit((body.network_id, roster.clone(), base.cloned()));
            }
        });
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
                        for stored in &rosters {
                            if let Err(error) = relay.rosters().adopt(
                                &stored.roster,
                                stored.base.as_ref(),
                                unix_now(),
                            ) {
                                let network =
                                    stored.roster.decode().map(|body| body.network_id).ok();
                                tracing::warn!(?network, %error, "a Roster on disk was refused");
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
        keeper,
    })
}

#[cfg(test)]
mod tests;
