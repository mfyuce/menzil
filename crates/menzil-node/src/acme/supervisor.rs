//! The node's ACME renewal tasks, started and stopped from what the relay answered (expose design
//! S-E8; protocol.md 6.2, 11, 12).
//!
//! The name to order comes from the relay: its ADVERTISE_ACK carries the share domain `H`
//! (`share_domain`, TBD 53) and the full names it accepted, relative to `H` (`names`: `app` for
//! `app.H`, `app.ali` for `app.ali.H`). [`candidate_jobs`] turns one [`ShareSnapshot`] into the
//! jobs that could be run: one per share that is [`wanted`] (accepted, blind, lists `acme-tls/1`)
//! and per name of the ACK that belongs to it, ordered for `<name>.<H>`. Nothing else is ever
//! ordered: not a name the ACK did not list, not a share the relay did not accept, not any name
//! when the ACK had no plausible `H`.
//!
//! `share_domain` in config.toml is only a cross check ([`plan`]): when it is set and differs
//! from the relay's `H`, nothing is ordered and one plain warning is logged for that pair.
//!
//! [`spawn_renewals`] is the supervisor: a task that follows the [`ShareBook`]'s change
//! notification (an ACK stored, a share withdrawn, the attachment ended) and a slow tick, makes
//! the [`plan`] again and keeps exactly one [`run_renewals_observed`] task per planned job. A
//! share that stops being wanted, a name the new ACK no longer lists and the end of the
//! attachment stop the task at once; the next attachment's ACK starts it again (a certificate
//! on disk that is not due is not ordered again). The account key is made (0600, atomically) the
//! first time a job needs it.
//!
//! What this does not do: pass the certificate on. It is on disk under
//! `<home>/acme/certs/<name>/{fullchain,privkey}.pem` and the service behind the share reads
//! it from there; the node signals nobody and runs no command.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use menzil_acme::{
    AccountKey, AcmeClient, AcmeJob, AcmeTransport, CertStore, ChallengeBook, FailureKind,
    Progress, Timing, check_domain, run_renewals_observed,
};
use tokio::task::JoinHandle;

use super::wanted;
use crate::shares::{MAX_SHARES, ShareBook, ShareSnapshot, lists_acme_alpn};

/// The most jobs one node runs at once (one per share and name; a label two tenants grant gives
/// two names).
pub const MAX_JOBS: usize = MAX_SHARES;

/// How often the supervisor looks again without a notification: the share domain in config.toml
/// may have been edited, and a key that could not be made is tried again.
const RECONCILE_EVERY: Duration = Duration::from_secs(30);

/// Where the share domain of config.toml and the relay's differ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMismatch {
    /// The relay's, from its ACK.
    pub relay: String,
    /// The one in config.toml.
    pub configured: String,
}

/// What [`plan`] decided.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    /// The jobs to run now.
    pub jobs: BTreeSet<AcmeJob>,
    /// The jobs that would run but for a [`DomainMismatch`] (empty without one).
    pub blocked: BTreeSet<AcmeJob>,
    /// Set when the configured share domain differs from the relay's.
    pub mismatch: Option<DomainMismatch>,
}

/// The jobs the relay's latest answer in `snapshot` allows, whatever config.toml says: see the
/// module docs. At most [`MAX_JOBS`].
pub fn candidate_jobs(snapshot: &ShareSnapshot) -> BTreeSet<AcmeJob> {
    let mut jobs = BTreeSet::new();
    if !snapshot.acked {
        return jobs;
    }
    let Some(domain) = snapshot.share_domain.as_deref() else {
        return jobs;
    };
    for name in &snapshot.names {
        // `label` or `label.<tenant slug>`: anything longer is not a name this relay composes.
        let mut labels = name.split('.');
        let (Some(label), tenant, None) = (labels.next(), labels.next(), labels.next()) else {
            continue;
        };
        if tenant.is_some_and(str::is_empty) {
            continue;
        }
        let is_wanted = snapshot
            .accepted
            .iter()
            .any(|share| share.name == label && lists_acme_alpn(share));
        if !is_wanted {
            continue;
        }
        let full = format!("{name}.{domain}");
        if check_domain(&full).is_err() {
            continue;
        }
        if jobs.len() >= MAX_JOBS {
            break;
        }
        jobs.insert(AcmeJob {
            share: label.to_string(),
            domain: full,
        });
    }
    jobs
}

/// The jobs to run for `snapshot`, given the `share_domain` of config.toml (a cross check only:
/// `None` checks nothing).
pub fn plan(snapshot: &ShareSnapshot, configured_domain: Option<&str>) -> Plan {
    let candidates = candidate_jobs(snapshot);
    let mismatch = match (snapshot.share_domain.as_deref(), configured_domain) {
        (Some(relay), Some(configured)) if !relay.eq_ignore_ascii_case(configured) => {
            Some(DomainMismatch {
                relay: relay.to_string(),
                configured: configured.to_string(),
            })
        }
        _ => None,
    };
    if mismatch.is_some() {
        Plan {
            jobs: BTreeSet::new(),
            blocked: candidates,
            mismatch,
        }
    } else {
        Plan {
            jobs: candidates,
            blocked: BTreeSet::new(),
            mismatch: None,
        }
    }
}

/// What a certificate of one name stands at, for a status display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertState {
    /// None is stored and no order is running or has failed.
    None,
    /// One is stored and not expired; it ends at `not_after` (Unix seconds).
    Valid {
        /// The end of the certificate.
        not_after: u64,
    },
    /// An order is running.
    Renewing,
    /// The latest attempt failed (or none is made, for a [`FailureKind::DomainMismatch`]).
    Failed(FailureKind),
}

/// What the renewal tasks are doing, per full name. Cloned freely; the tasks write it and a
/// status display reads it.
#[derive(Debug, Clone, Default)]
pub struct AcmeStatus {
    inner: Arc<Mutex<HashMap<String, Progress>>>,
}

impl AcmeStatus {
    /// An empty status.
    pub fn new() -> Self {
        Self::default()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Progress>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Notes what the task of `domain` is doing (the renewal tasks do; tests may).
    pub fn record(&self, domain: &str, progress: Progress) {
        let mut map = self.map();
        match progress {
            Progress::Issued | Progress::Idle => {
                map.remove(domain);
            }
            other => {
                map.insert(domain.to_string(), other);
            }
        }
    }

    /// Forgets what was noted for `domain`.
    pub fn forget(&self, domain: &str) {
        self.map().remove(domain);
    }

    /// Where `domain` stands at `now` (Unix seconds): what the tasks say, else what `store` holds.
    pub fn state(&self, store: &CertStore, domain: &str, now: u64) -> CertState {
        match self.map().get(domain) {
            Some(Progress::Renewing) => return CertState::Renewing,
            Some(Progress::Failed(kind)) => return CertState::Failed(*kind),
            _ => {}
        }
        match store.validity(domain) {
            Some((_, not_after)) if not_after > now => CertState::Valid { not_after },
            _ => CertState::None,
        }
    }
}

/// What the supervisor needs to talk to the CA.
pub struct AcmeSetup<T> {
    /// How to reach the CA.
    pub transport: T,
    /// The CA's RFC 8555 directory (https).
    pub directory_url: String,
    /// The contact for the CA's notices, if any.
    pub contact: Option<String>,
    /// The account key file (made on first use).
    pub account_key_path: PathBuf,
    /// Where certificates are kept.
    pub store: CertStore,
    /// How the client waits.
    pub timing: Timing,
}

/// The jobs that run: aborted when dropped, so that aborting the supervisor takes them with it.
#[derive(Default)]
struct Running(HashMap<AcmeJob, JoinHandle<()>>);

impl Drop for Running {
    fn drop(&mut self) {
        for handle in self.0.values() {
            handle.abort();
        }
    }
}

/// Starts the supervisor (see the module docs). `configured_domain` is asked at every look and
/// answers the `share_domain` of config.toml, lowercase (the caller keeps its last good value
/// when the file cannot be read). The returned task keeps its jobs only while it lives: abort it
/// and they stop too.
pub fn spawn_renewals<T>(
    setup: AcmeSetup<T>,
    shares: ShareBook,
    book: ChallengeBook,
    status: AcmeStatus,
    mut configured_domain: impl FnMut() -> Option<String> + Send + 'static,
) -> JoinHandle<()>
where
    T: AcmeTransport + Clone + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut changes = shares.subscribe_accepted();
        let mut running = Running::default();
        let mut key_pem: Option<String> = None;
        let mut warned: Option<(String, String)> = None;
        let mut key_failed = false;
        let mut no_domain_warned = false;
        let mut blocked_now: BTreeSet<String> = BTreeSet::new();
        loop {
            let snapshot = shares.snapshot();
            let configured = configured_domain();
            let plan = plan(&snapshot, configured.as_deref());

            match &plan.mismatch {
                Some(mismatch) => {
                    let pair = (mismatch.relay.clone(), mismatch.configured.clone());
                    if warned.as_ref() != Some(&pair) {
                        tracing::warn!(
                            relay = %mismatch.relay,
                            configured = %mismatch.configured,
                            "share_domain in config.toml differs from the relay's share domain: no certificate is ordered until they agree"
                        );
                        warned = Some(pair);
                    }
                }
                None => warned = None,
            }
            let wanted_without_domain = snapshot.acked
                && snapshot.share_domain.is_none()
                && snapshot.accepted.iter().any(lists_acme_alpn);
            if wanted_without_domain {
                if !no_domain_warned {
                    tracing::warn!(
                        "the relay did not send its share domain, so no certificate is ordered for the shares that list acme-tls/1"
                    );
                    no_domain_warned = true;
                }
            } else {
                no_domain_warned = false;
            }

            // Stop what is no longer planned.
            running.0.retain(|job, handle| {
                if plan.jobs.contains(job) {
                    true
                } else {
                    handle.abort();
                    status.forget(&job.domain);
                    false
                }
            });
            // A name that cannot be ordered because of the mismatch says so; one that no longer
            // is blocked forgets it.
            let blocked: BTreeSet<String> =
                plan.blocked.iter().map(|job| job.domain.clone()).collect();
            for domain in blocked_now.difference(&blocked) {
                status.forget(domain);
            }
            for domain in &blocked {
                status.record(domain, Progress::Failed(FailureKind::DomainMismatch));
            }
            blocked_now = blocked;

            // Start what is planned and not running.
            for job in &plan.jobs {
                if running.0.contains_key(job) {
                    continue;
                }
                if key_pem.is_none() {
                    match AccountKey::load_or_create(&setup.account_key_path) {
                        Ok(key) => {
                            key_pem = Some(key.to_pem());
                            key_failed = false;
                        }
                        Err(error) => {
                            if !key_failed {
                                tracing::warn!(%error, "the ACME account key is not usable, no certificate is ordered until it is");
                                key_failed = true;
                            }
                            status.record(&job.domain, Progress::Failed(FailureKind::Local));
                            continue;
                        }
                    }
                }
                let Some(pem) = key_pem.as_deref() else {
                    continue;
                };
                let client = match AccountKey::from_pem(pem) {
                    Ok(key) => AcmeClient::new(
                        setup.transport.clone(),
                        setup.directory_url.clone(),
                        key,
                        setup.contact.clone(),
                    )
                    .with_timing(setup.timing),
                    Err(error) => {
                        tracing::warn!(%error, "the ACME account key cannot be read back");
                        status.record(&job.domain, Progress::Failed(FailureKind::Local));
                        continue;
                    }
                };
                status.forget(&job.domain);
                let (task_shares, share) = (shares.clone(), job.share.clone());
                let (task_status, domain) = (status.clone(), job.domain.clone());
                let handle = tokio::spawn(run_renewals_observed(
                    client,
                    setup.store.clone(),
                    move || wanted(&task_shares, &share),
                    book.clone(),
                    job.clone(),
                    move |progress| task_status.record(&domain, progress),
                ));
                running.0.insert(job.clone(), handle);
            }

            tokio::select! {
                changed = changes.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
                () = tokio::time::sleep(RECONCILE_EVERY) => {}
            }
        }
    })
}
