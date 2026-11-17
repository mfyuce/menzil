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

use std::collections::HashSet;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use menzil_proto::trust::{DOC_MAX_LIFETIME, HeldRoster, HeldView, Reason, Verdict, check_bundle};
use menzil_proto::{Limits, NetworkId, Roster};
use menzil_relay::{
    AcceptConfig, FrontDoorConfig, Listener, NameState, Relay, RelayError, RelayIdentity,
    TenantBook,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinHandle;

use crate::home::{Home, parse_hex32};
use crate::local::load_identity;
use crate::persist::{Attempt, FlushReport, Outcome, Worker};
use crate::token::{roster_from_bytes, roster_to_bytes};

pub mod names_state;
pub mod status;
pub mod tenants;

/// The WebSocket path nodes ask for unless the operator picks another (protocol.md 3.1).
pub const DEFAULT_PATH: &str = "/_menzil/v1";

/// The per session figures a relay announces in WELCOME: the largest record the protocol has,
/// the credit protocol.md 10 names, and the most destinations one sending node may have.
///
/// `max_peers` is enforced since the data plane quotas (MT8): the relay refuses a node's NEW
/// pair beyond this many destinations with ERROR `over_quota` (pairs that exist keep working).
/// 1024 is far above any personal use, so a relay without tenant files behaves as before; a
/// tenant with figures is told, and held to, its own lower `destinations_per_node` (32 for the
/// `friend` class) in the WELCOME of a session that proved its networks.
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
///
/// A network the relay already serves for a tenant stays with it; a new one goes to the default
/// tenant. [`tenants::add_network_to`] is the same with a tenant to put it in.
pub fn add_network(home: &Home, token: &str, now: u64) -> Result<(NetworkId, u64)> {
    let added = tenants::add_network_to(home, token, now, None)?;
    Ok((added.network_id, added.seq))
}

/// Whether [`keep_roster_locked`] may bring a network into the relay's directory.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keep {
    /// `add-network`: the operator asks for the network, so a missing file is made.
    Create,
    /// The relay keeping a Roster it adopted over DOC: only a file that is there is updated, and
    /// one that cannot be read is not written over. A network the operator removed by hand
    /// stays removed (the tenant's next Roster must not bring it back at the next start).
    UpdateOnly,
}

/// A Roster file that is there and cannot be understood: the keeper never writes over it.
#[derive(Debug)]
struct DamagedRosterFile(String);

impl std::fmt::Display for DamagedRosterFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DamagedRosterFile {}

/// Why the keeper could not keep a Roster, by what the keeper does about it.
#[derive(Debug)]
enum KeepError {
    /// The relay lock stayed held by another process: retry.
    Busy(anyhow::Error),
    /// Reading or writing failed (ENOSPC, EIO, a path in the way): retry.
    Io(anyhow::Error),
    /// The file is damaged: the operator's, never retried, never written over.
    Damaged(anyhow::Error),
    /// The acceptance predicate refuses the Roster against what is kept: retrying changes
    /// nothing.
    Refused(anyhow::Error),
}

impl KeepError {
    /// By the typed errors at the bottom, never by their wording.
    fn classify(error: anyhow::Error) -> Self {
        if error.downcast_ref::<crate::home::LockBusy>().is_some() {
            Self::Busy(error)
        } else if error.downcast_ref::<DamagedRosterFile>().is_some() {
            Self::Damaged(error)
        } else if error.downcast_ref::<tenants::CommandError>().is_some() {
            Self::Refused(error)
        } else {
            Self::Io(error)
        }
    }

    fn error(&self) -> &anyhow::Error {
        match self {
            Self::Busy(e) | Self::Io(e) | Self::Damaged(e) | Self::Refused(e) => e,
        }
    }
}

/// [`keep_roster_locked`] with [`Keep::UpdateOnly`] for the keeper thread: the lock is waited for at
/// most `wait`, and a failure says what kind it is.
fn keep_roster_for_keeper(
    home: &Home,
    roster: &Roster,
    base: Option<&Roster>,
    now: u64,
    wait: std::time::Duration,
) -> Result<Option<(NetworkId, u64)>, KeepError> {
    let Some(_lock) = home
        .lock_relay_if_held_within(wait)
        .map_err(KeepError::classify)?
    else {
        return Ok(None);
    };
    keep_roster_locked(home, roster, base, now, Keep::UpdateOnly).map_err(KeepError::classify)
}

/// How long the keeper threads wait for the relay lock in one attempt (the commands wait ten
/// seconds): a failed attempt is retried with a backoff, and a long wait would hold up the
/// other networks' jobs.
pub const KEEPER_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Keeps `roster` (with its `base`, for a Roster a steward signed) as the Roster this relay
/// starts from for its network, if the acceptance predicate of protocol.md 2.3 takes it against
/// what is kept: [`add_network`] after decoding a token, and the relay itself for a Roster it
/// adopted over DOC. A Roster no newer than the one kept is left alone, so an older one never
/// replaces a newer one on disk, whoever hands it over and in whatever order. Returns the
/// network and the sequence number now kept; `None` for [`Keep::UpdateOnly`] when nothing is
/// held for the network.
/// The caller holds the relay lock (`home.lock_relay()`, or the keeper's wait).
fn keep_roster_locked(
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
        return Err(DamagedRosterFile(format!(
            "the Roster file {} cannot be read; not written over",
            path.display()
        ))
        .into());
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
            return Err(tenants::CommandError::TokenExpired.into());
        }
        Verdict::Reject(reason) => {
            return Err(tenants::CommandError::TokenNotAcceptable {
                reason: crate::local::refusal(reason),
            }
            .into());
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
        x25519_private: *keys.x25519_private(),
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
    /// A static HTML file (at most 64 KiB, read once at start) to answer a plain HTTP request to
    /// the relay's own host name with, such as a browser opening `https://<host>/`. Without it
    /// such a request gets no answer. A WebSocket upgrade is not affected.
    pub fallback_page: Option<PathBuf>,
    /// The per address admission figures to run with, or `None` for the defaults
    /// (`menzil_relay::AdmissionLimits`). A relay behind a reverse proxy or serving many users
    /// behind one address raises them.
    pub admission: Option<menzil_relay::AdmissionLimits>,
    /// The audit file to append to (`docs/spec/audit-format.md`), or `None` for none.
    pub audit_file: Option<PathBuf>,
}

/// The admission limits the `--connections-per-ip-per-minute`, `--handshakes-per-ip` and
/// `--unattached-per-ip` flags ask for on top of the defaults; `None` when none was given.
pub fn admission_limits(
    connections_per_minute: Option<u32>,
    handshakes: Option<u32>,
    unattached: Option<u32>,
) -> Option<menzil_relay::AdmissionLimits> {
    if connections_per_minute.is_none() && handshakes.is_none() && unattached.is_none() {
        return None;
    }
    let mut limits = menzil_relay::AdmissionLimits::default();
    if let Some(n) = connections_per_minute {
        limits.connections_per_ip_per_minute = n as usize;
    }
    if let Some(n) = handshakes {
        limits.max_handshakes_per_ip = n as usize;
    }
    if let Some(n) = unattached {
        limits.max_unattached_per_ip = n as usize;
    }
    Some(limits)
}

/// The blind front door of `menzil relay run` (protocol.md 6.2): off unless a share domain is
/// given. The relay's own host name (`RunOptions::host`) is then required: the SNI that keeps
/// its WebSocket path.
#[derive(Debug, Clone)]
pub struct FrontDoorOptions {
    /// The share domain `H`: names are `<label>.H` and `<label>.<tenant>.H`.
    pub share_domain: String,
    /// Where to serve plain HTTP for ACME HTTP-01 and the redirect to https (port 80); not
    /// served when `None`.
    pub http_listen: Option<SocketAddr>,
    /// The relay's own ACME (TLS-ALPN-01): certificates for `--host` and for the names of
    /// terminated shares; off when `None`.
    pub acme: Option<AcmeOptions>,
}

/// The relay's ACME settings (`menzil relay run --acme-directory`). There is no default CA:
/// the operator names the directory (for a trial, the CA's staging directory).
#[derive(Debug, Clone)]
pub struct AcmeOptions {
    /// The RFC 8555 directory URL (https).
    pub directory_url: String,
    /// The contact for the CA's notices (`mailto:...`), if any.
    pub contact: Option<String>,
}

/// The soft `RLIMIT_NOFILE` is never raised above this (Linux refuses a limit over
/// `fs.nr_open`, 1,048,576 by default, and a hard limit of "unlimited" is no figure to set).
const NOFILE_CEILING: u64 = 1_048_576;

/// What to do about `RLIMIT_NOFILE` for a front door that may hold `need` descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofilePlan {
    /// The soft limit to set, or `None` to leave it (it is at the hard limit or the ceiling).
    pub raise_to: Option<u64>,
    /// Whether the limit, after the raise, is still below `need`.
    pub short: bool,
}

/// Decides from the soft and hard limits (`u64::MAX` for none) and the `need`: raise the soft
/// limit to the hard one (at most [`NOFILE_CEILING`]), and flag a limit that stays below `need`.
pub fn nofile_plan(soft: u64, hard: u64, need: u64) -> NofilePlan {
    let target = hard.min(NOFILE_CEILING);
    let raise_to = (target > soft).then_some(target);
    let after = raise_to.unwrap_or(soft);
    NofilePlan {
        raise_to,
        short: after < need,
    }
}

/// The soft and hard `RLIMIT_NOFILE` of this process; `u64::MAX` for none. `None` where it
/// cannot be read.
#[cfg(unix)]
fn read_nofile() -> Option<(u64, u64)> {
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile);
    Some((
        limit.current.unwrap_or(u64::MAX),
        limit.maximum.unwrap_or(u64::MAX),
    ))
}

#[cfg(not(unix))]
fn read_nofile() -> Option<(u64, u64)> {
    None
}

/// Sets the soft limit to `soft`, keeping the hard one.
#[cfg(unix)]
fn write_nofile(soft: u64, hard: u64) -> bool {
    let maximum = (hard != u64::MAX).then_some(hard);
    rustix::process::setrlimit(
        rustix::process::Resource::Nofile,
        rustix::process::Rlimit {
            current: Some(soft),
            maximum,
        },
    )
    .is_ok()
}

#[cfg(not(unix))]
fn write_nofile(_soft: u64, _hard: u64) -> bool {
    false
}

/// With a front door the relay can hold thousands of descriptors for the public (see
/// [`FrontDoorConfig::fd_budget`]); a soft limit of 1,024 (the usual default) would make
/// `accept` fail at the figures. Raises the soft limit to the hard one and warns if the result
/// is still below the budget (expose round 2, L3).
fn raise_nofile_for(config: &FrontDoorConfig, http: bool) {
    let need = u64::try_from(config.fd_budget(http)).unwrap_or(u64::MAX);
    let Some((soft, hard)) = read_nofile() else {
        return;
    };
    let plan = nofile_plan(soft, hard, need);
    let mut now = soft;
    if let Some(target) = plan.raise_to {
        if write_nofile(target, hard) {
            now = target;
        } else {
            tracing::warn!(
                soft,
                target,
                "could not raise the soft file descriptor limit"
            );
        }
    }
    if now < need {
        tracing::warn!(
            limit = now,
            need,
            "the file descriptor limit is below what the front door may hold; at its figures the relay stops accepting connections, its nodes' included (raise LimitNOFILE or `ulimit -n`)"
        );
        eprintln!(
            "warning: the file descriptor limit ({now}) is below the {need} the front door may hold; raise LimitNOFILE (systemd) or `ulimit -n`"
        );
    }
}

/// How long a clean stop waits for the keeper to write the last Roster adopted over DOC.
pub const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

/// How often a relay reloads its Rosters unless told otherwise.
pub const DEFAULT_RELOAD_EVERY: std::time::Duration = std::time::Duration::from_secs(15);

/// Both keepers' reports as (rosters reached, names reached, what is not on disk).
fn flush_summary(rosters: FlushReport, names: FlushReport) -> (bool, bool, Vec<String>) {
    let mut unwritten = rosters.unwritten;
    unwritten.extend(names.unwritten);
    // A flush that was not reached may not know which job it was (a panic): say so.
    if (!rosters.reached || !names.reached) && unwritten.is_empty() {
        unwritten.push("(unknown)".to_string());
    }
    (rosters.reached, names.reached, unwritten)
}

/// Flushes the Roster keeper and then the names keeper under one deadline: both together take
/// at most `timeout`, not twice that.
fn flush_both(
    keeper: &Worker<(NetworkId, Roster, Option<Roster>)>,
    names_keeper: &Worker<NameState>,
    timeout: std::time::Duration,
) -> (bool, bool, Vec<String>) {
    let deadline = std::time::Instant::now() + timeout;
    let rosters = keeper.flush(timeout);
    let names = names_keeper.flush(deadline.saturating_duration_since(std::time::Instant::now()));
    flush_summary(rosters, names)
}

/// A relay that is listening.
pub struct RunningRelay {
    /// The address it listens on.
    pub addr: SocketAddr,
    /// The connection information for nodes, with the host name the operator gave (or
    /// `RELAY-HOST`).
    pub connection_info: String,
    /// The networks it serves.
    pub networks: Vec<NetworkId>,
    /// The address its plain HTTP listener is bound to, if it has one.
    pub http_addr: Option<SocketAddr>,
    relay: Relay,
    task: JoinHandle<()>,
    reload: JoinHandle<()>,
    /// Writes `relay/status.json` every few seconds ([`status`]).
    status: JoinHandle<()>,
    keeper: Arc<Worker<(NetworkId, Roster, Option<Roster>)>>,
    /// Writes `relay/names.state` after every change of the name state (MT9).
    names_keeper: Arc<Worker<NameState>>,
}

impl RunningRelay {
    /// Waits for the relay's task, which serves until it is aborted; what the join gave. A
    /// task that returns by itself is `Ok(())`, one that panicked or was aborted is the error.
    pub async fn wait(&mut self) -> Result<(), tokio::task::JoinError> {
        (&mut self.task).await
    }

    /// The tenants the relay knows now (the tenant files as of the last reload).
    pub fn tenants(&self) -> Arc<TenantBook> {
        self.relay.tenants()
    }

    /// The sequence number of the Roster the relay holds for `network_id` now.
    pub fn roster_seq(&self, network_id: &NetworkId) -> Option<u64> {
        self.relay.rosters().get(network_id).map(|body| body.seq)
    }

    /// Waits until every Roster the relay adopted over DOC so far has been written to (or
    /// refused by) the relay directory, and the name state as it was has been written to
    /// `names.state`, at most `timeout` for each; whether it got there. A write that keeps
    /// failing is run once more and then left to the retry backoff: see
    /// [`Self::flush_report`] for what is still not on disk.
    pub fn flush_rosters(&self, timeout: std::time::Duration) -> bool {
        let report = self.flush_report(timeout);
        report.0 && report.1
    }

    /// Flushes both keepers: what each reached, and the names of what is not on disk (networks
    /// by id, `names.state`).
    fn flush_report(&self, timeout: std::time::Duration) -> (bool, bool, Vec<String>) {
        flush_both(&self.keeper, &self.names_keeper, timeout)
    }

    /// [`Self::flush_rosters`] off the async threads (it blocks on the keeper, which may wait
    /// for a lock another command holds): for a clean stop of `menzil relay run`, so that the
    /// last Roster adopted over DOC is on disk before the process goes. The names of what is
    /// still not on disk (networks by id, `names.state`); empty when all is written.
    pub async fn flush_rosters_blocking(&self, timeout: std::time::Duration) -> Vec<String> {
        let keeper = Arc::clone(&self.keeper);
        let names_keeper = Arc::clone(&self.names_keeper);
        tokio::task::spawn_blocking(move || flush_both(&keeper, &names_keeper, timeout).2)
            .await
            .unwrap_or_else(|_| vec!["(the flush did not finish)".to_string()])
    }

    /// Stops the relay.
    pub fn stop(&self) {
        self.task.abort();
        self.reload.abort();
        self.status.abort();
    }
}

/// The line for the operator when `unwritten` (networks by id, `names.state`) did not reach the
/// disk at the stop; `None` when all did.
fn stop_notice(unwritten: &[String]) -> Option<String> {
    if unwritten.is_empty() {
        return None;
    }
    Some(format!(
        "menzil: not on disk at the stop: {} (a restart starts from the older file; add the network again with a current token if its Roster changed)",
        unwritten.join(", ")
    ))
}

/// What `menzil relay run` does after it has started: waits until `stop` is ready (a signal) or
/// the relay's task ends, then flushes the keeper, so that the last Roster adopted over DOC is
/// on disk before the process goes (TOBEDECIDED 28b; bounded by [`STOP_GRACE`], the lock another
/// command holds is not waited for forever). `Ok(Some)` with what `stop` gave if it was the
/// signal. If the relay's task ends first (it panicked, was aborted, or returned, none of which
/// is a stop anyone asked for) the keeper is flushed all the same and the result is an error, so
/// that the process exits non-zero.
pub async fn run_until<F: std::future::Future>(
    relay: &mut RunningRelay,
    stop: F,
) -> Result<Option<F::Output>> {
    let ended = tokio::select! {
        joined = relay.wait() => Err(joined),
        out = stop => Ok(out),
    };
    // Stop serving first: a Roster adopted while the keeper flushes would be neither written
    // nor named.
    relay.stop();
    let unwritten = relay.flush_rosters_blocking(STOP_GRACE).await;
    if let Some(line) = stop_notice(&unwritten) {
        tracing::warn!(unwritten = %unwritten.join(", "), "not on disk at the stop");
        eprintln!("{line}");
    }
    match ended {
        Ok(out) => Ok(Some(out)),
        Err(Ok(())) => bail!("relay task ended unexpectedly"),
        Err(Err(error)) if error.is_panic() => bail!("relay task panicked: {error}"),
        Err(Err(error)) => bail!("relay task ended unexpectedly: {error}"),
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
    start_with(home, options, None).await
}

/// [`start`], with the blind front door of `front` on the TLS port if it is given.
pub async fn start_with(
    home: &Home,
    options: &RunOptions,
    front: Option<&FrontDoorOptions>,
) -> Result<RunningRelay> {
    start_with_status_every(home, options, front, status::EXPORT_EVERY).await
}

/// [`start_with`] with the interval of the status export (`relay/status.json`) given.
pub(crate) async fn start_with_status_every(
    home: &Home,
    options: &RunOptions,
    front: Option<&FrontDoorOptions>,
    status_every: std::time::Duration,
) -> Result<RunningRelay> {
    start_tuned(home, options, front, status_every, KEEPER_LOCK_WAIT).await
}

/// [`start_with_status_every`] with the keepers' lock wait given (tests make it short).
pub(crate) async fn start_tuned(
    home: &Home,
    options: &RunOptions,
    front: Option<&FrontDoorOptions>,
    status_every: std::time::Duration,
    keeper_lock_wait: std::time::Duration,
) -> Result<RunningRelay> {
    // The front door needs the relay's own host name to tell its nodes from the public, before
    // anything is bound or read.
    let front_door = match front {
        None => None,
        Some(front) => {
            let host = options.host.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "--share-domain needs --host: the relay's own host name is the SNI its nodes dial"
                )
            })?;
            Some(FrontDoorConfig::new(host, &front.share_domain)?)
        }
    };
    let identity = relay_identity(home)?;
    let all_rosters = load_rosters(home)?;
    // The tenant files, before anything is served: a network a tenant file refuses is held
    // back, and one that cannot be told apart from the operator's intent stops the start (its
    // networks would otherwise be served as the default tenant's).
    let book = tenants::load_book(home, &all_rosters)?;
    for note in tenants::book_notes(&book, &all_rosters) {
        tracing::warn!("{note}");
        eprintln!("warning: {note}");
    }
    // The durable name state (MT9): a damaged file stops the start, because the relay would
    // otherwise hand out names it holds back, and then write over the file.
    let name_state = names_state::load_for_start(home)?;
    let rosters: Vec<StoredRoster> = all_rosters
        .into_iter()
        .filter(|stored| {
            stored
                .roster
                .decode()
                .is_ok_and(|body| !book.is_held_back(&body.network_id))
        })
        .collect();
    if rosters.is_empty() {
        bail!("this relay serves no network: run `menzil relay add-network <token>` first");
    }
    // With ACME the relay's own TLS configuration resolves from the certificate book: the
    // operator's certificate files answer until (and whenever) the book has nothing better.
    let acme = match (
        front.and_then(|front| front.acme.as_ref()),
        options.host.as_deref(),
    ) {
        (Some(acme), Some(host)) => {
            let mut config = menzil_relay::AcmeConfig::new(&acme.directory_url, home.root())?
                .with_hosts(&[host])?;
            if let Some(contact) = &acme.contact {
                config = config.with_contact(contact);
            }
            let book = menzil_relay::RelayCertBook::new();
            let chain = std::fs::read_to_string(&options.tls_cert)
                .with_context(|| format!("reading {}", options.tls_cert.display()))?;
            let key = std::fs::read_to_string(&options.tls_key)
                .with_context(|| format!("reading {}", options.tls_key.display()))?;
            book.set_fallback_pem(&chain, &key)?;
            Some(menzil_relay::RelayAcme::with_book(config, book))
        }
        _ => None,
    };
    let tls = match &acme {
        Some(acme) => acme.certs().server_config()?,
        None => tls_from_pem(&options.tls_cert, &options.tls_key)?,
    };
    let mut listener = Listener::bind(options.listen, tls, options.path.clone()).await?;
    if let Some(path) = &options.fallback_page {
        use std::io::Read as _;
        let mut html = Vec::new();
        std::fs::File::open(path)
            .and_then(|f| {
                f.take(menzil_relay::FALLBACK_PAGE_MAX_BYTES as u64 + 1)
                    .read_to_end(&mut html)
            })
            .with_context(|| format!("reading the fallback page {}", path.display()))?;
        let page = menzil_relay::FallbackPage::new(html)
            .with_context(|| format!("the fallback page {}", path.display()))?;
        listener = listener.with_fallback_page(page);
    }
    let addr = listener.local_addr()?;
    let info = connection_info(
        options.host.as_deref().unwrap_or("RELAY-HOST"),
        addr.port(),
        &options.path,
        &identity,
    )?;
    let http = match front.and_then(|front| front.http_listen) {
        Some(addr) => Some(
            tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("listening on {addr} for plain HTTP"))?,
        ),
        None => None,
    };
    let http_addr = http
        .as_ref()
        .map(tokio::net::TcpListener::local_addr)
        .transpose()?;
    let mut relay = Relay::new(identity, LIMITS);
    if let Some(limits) = options.admission {
        relay = relay.with_admission_limits(limits);
    }
    if let Some(path) = &options.audit_file {
        let audit = menzil_audit::AuditLog::open(path, menzil_audit::Source::Relay, false)
            .with_context(|| format!("opening the audit file {}", path.display()))?;
        relay = relay.with_audit(audit);
    }
    if let Some(config) = front_door {
        raise_nofile_for(&config, http.is_some());
        relay = relay.with_front_door(config);
    }
    if let Some(acme) = acme {
        relay = relay.with_acme(acme);
    }
    relay.set_tenants(book);
    relay.labels().load_state(&name_state);
    let mut networks = Vec::new();
    for stored in &rosters {
        let network_id = stored.roster.decode()?.network_id;
        match relay
            .rosters()
            .adopt(&stored.roster, stored.base.as_ref(), unix_now())
        {
            Ok(_) => networks.push(network_id),
            // A Roster that ran out on disk (the keeper writes the ones it takes over DOC, but
            // a write that failed or has not run yet leaves the file as old as the last `add-network`) or is not valid yet is
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
            |job: &(NetworkId, Roster, Option<Roster>)| job.0.to_string(),
            move |(_, roster, base): &(NetworkId, Roster, Option<Roster>), attempt: &Attempt| {
                let Ok(body) = roster.decode() else {
                    return Outcome::Done;
                };
                let network = Some(body.network_id);
                // Judged at the Roster's own `issued` time, like the held-but-expired start: the
                // time rules were checked when the store took it, and what is left to ask here is
                // its signatures and `seq` against the file. A retry of an older Roster against a
                // newer file is `Held` (never a lower `seq` on disk).
                match keep_roster_for_keeper(
                    &home,
                    roster,
                    base.as_ref(),
                    body.issued,
                    attempt.lock_wait(keeper_lock_wait),
                ) {
                    Ok(_) => Outcome::Done,
                    Err(error @ (KeepError::Busy(_) | KeepError::Io(_))) => Outcome::Retry {
                        class: if matches!(error, KeepError::Busy(_)) {
                            "busy"
                        } else {
                            "io"
                        },
                        error: format!("network {}: {:#}", body.network_id, error.error()),
                    },
                    Err(error) => {
                        tracing::warn!(?network, error = %format!("{:#}", error.error()), "the Roster adopted over DOC could not be kept on disk: a restart will start from the older file");
                        Outcome::Done
                    }
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
    // The name state reaches the disk through its own keeper thread, which coalesces: the latest
    // snapshot wins, and the registry's callback only queues it.
    let names_keeper = {
        let home = home.clone();
        Worker::spawn(
            "menzil-relay-names",
            |_: &NameState| "names.state".to_string(),
            move |snapshot: &NameState, attempt: &Attempt| {
                match names_state::write_relay_part_within(
                    &home,
                    snapshot,
                    attempt.lock_wait(keeper_lock_wait),
                ) {
                    Ok(()) => Outcome::Done,
                    Err(error) => Outcome::Retry {
                        class: if error.downcast_ref::<crate::home::LockBusy>().is_some() {
                            "busy"
                        } else {
                            "io"
                        },
                        error: format!("{error:#}"),
                    },
                }
            },
        )?
    };
    {
        let names_keeper = Arc::clone(&names_keeper);
        relay
            .labels()
            .set_on_change(move |state| names_keeper.submit(state.clone()));
    }
    let serving = relay.clone();
    let task = tokio::spawn(async move {
        serving
            .serve_with_http(&listener, http, AcceptConfig::default())
            .await
    });
    // `add-network` with a newer token while the relay runs is picked up here; the store keeps
    // the newer of what it holds and what is read (protocol.md 2.3: never a lower `seq`), and
    // members push newer Rosters themselves whenever they attach.
    let reload = {
        let (relay, home, every) = (relay.clone(), home.clone(), options.reload_every);
        tokio::spawn(async move {
            let mut announced = Vec::new();
            loop {
                tokio::time::sleep(every).await;
                reload_once(&relay, &home, &mut announced);
            }
        })
    };
    let status = status::spawn_exporter(relay.clone(), home.clone(), status_every);
    Ok(RunningRelay {
        addr,
        connection_info: info,
        networks,
        http_addr,
        relay,
        task,
        reload,
        status,
        keeper,
        names_keeper,
    })
}

/// The ids of the Roster files in the relay directory, readable or not: a damaged file is
/// still the operator's file for its network. A directory that is not there is an error here,
/// not "no files": a relay must not drop every network because its directory cannot be seen.
fn roster_file_ids(home: &Home) -> Result<HashSet<NetworkId>> {
    let dir = relay_dir(home);
    let mut ids = HashSet::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("roster") {
            continue;
        }
        if let Some(id) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(parse_hex32)
        {
            ids.insert(NetworkId::from(id));
        }
    }
    Ok(ids)
}

/// One pass of the reload: the tenant files, the Rosters on disk that are newer than the ones
/// held, and the networks the operator removed. A network the relay holds that has no Roster
/// file any more (`relay remove-network`, `remove-tenant`), or that a tenant file the book
/// refuses now lists, is dropped from the store, which ends the sessions that claimed it. A
/// directory that cannot be read, or tenant files that cannot be read, change nothing: the relay
/// keeps serving what it has. `announced` holds the notes printed last time, so that a standing
/// problem is said once and not at every pass.
fn reload_once(relay: &Relay, home: &Home, announced: &mut Vec<String>) {
    reload_once_with(relay, home, announced, &mut || {});
}

/// [`reload_once`] with a function called once, between dropping the networks that are no
/// longer served and swapping in the new tenant book (tests look at the relay there).
///
/// The order matters (round T5, L5): the networks of a removed or held back tenant leave the
/// store, ending their sessions, BEFORE the new book is set. With the book swapped first, those
/// networks would for a moment belong to the default tenant, and a node of theirs that
/// advertised in that moment could take a flat name of the default tenant's and lock its owner
/// out for 180 days through the quarantine of the removal.
fn reload_once_with(
    relay: &Relay,
    home: &Home,
    announced: &mut Vec<String>,
    before_swap: &mut dyn FnMut(),
) {
    let (rosters, failures) = match load_rosters_each(home) {
        Ok(read) => read,
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "reading the Rosters failed");
            return;
        }
    };
    for failure in &failures {
        tracing::warn!(error = %format!("{failure:#}"), "a Roster file cannot be read");
    }
    let mut notes = Vec::new();
    let loaded = match tenants::load_book(home, &rosters) {
        Ok(book) => {
            notes = tenants::book_notes(&book, &rosters);
            Some(book)
        }
        Err(error) => {
            notes.push(format!(
                "the tenant files cannot be read ({error:#}): the relay keeps the tenants it had"
            ));
            None
        }
    };
    if *announced != notes {
        for note in &notes {
            tracing::warn!("{note}");
        }
        *announced = notes;
    }
    // Which networks are no longer served is judged with the book that is about to be set (or
    // the one the relay has, when the tenant files cannot be read).
    let current = relay.tenants();
    {
        let book: &TenantBook = loaded.as_ref().unwrap_or(&current);
        match roster_file_ids(home) {
            Ok(present) => {
                for network in relay.rosters().networks() {
                    let held_back = book.is_held_back(&network);
                    let file_gone = !present.contains(&network);
                    if (held_back || file_gone) && relay.rosters().remove(&network) {
                        // The Roster file is gone: its names are released, a flat one waits 180
                        // days for the network to come back (design 2.2, rule 9). A suspended
                        // tenant's network keeps its names, as the tenant book says: resume
                        // brings the network back with them, not as new names against the
                        // weekly quota (review medium R-2).
                        if file_gone {
                            relay.labels().network_removed(
                                relay.rosters(),
                                book,
                                &network,
                                unix_now(),
                            );
                        }
                        tracing::warn!(
                            %network,
                            held_back,
                            "the network is no longer served (its Roster file is gone, or its tenant file is not used): the sessions that claimed it end"
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "the Roster files cannot be listed; no network is dropped");
            }
        }
    }
    before_swap();
    if let Some(book) = loaded {
        relay.set_tenants(book);
    }
    let book = relay.tenants();
    for stored in &rosters {
        let Ok(body) = stored.roster.decode() else {
            continue;
        };
        if book.is_held_back(&body.network_id) {
            continue;
        }
        if let Err(error) = relay
            .rosters()
            .adopt(&stored.roster, stored.base.as_ref(), unix_now())
        {
            tracing::warn!(network = ?body.network_id, %error, "a Roster on disk was refused");
        }
    }
    // The periodic name pass (MT9): names held are stamped, names unadvertised for 90 days or
    // dropped from their Roster are released.
    relay.labels().sweep(relay.rosters(), &book, unix_now());
}

#[cfg(test)]
mod tests;
