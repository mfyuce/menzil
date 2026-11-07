//! What the node does with an issued certificate: the checks it makes before keeping one, the
//! store (`<home>/acme/certs/<domain>/{fullchain,privkey}.pem`, each file replaced atomically,
//! the key readable by the owner only), the renewal time (two thirds of the lifetime less a
//! jitter) and the loop that renews.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time::Instant;

use x509_parser::extensions::GeneralName;

use super::client::{AcmeClient, Issued};
use super::http::AcmeTransport;
use super::{AcmeError, ChallengeBook, FailureKind, check_domain};

/// The longest the loop sleeps in one piece, so that a clock that jumped is noticed.
const MAX_SLEEP: Duration = Duration::from_secs(6 * 3600);

/// How long the loop waits before it looks again when the share is not wanted (for the node: not accepted
/// yet, or no longer listing `acme-tls/1`; for the relay: no longer a configured name).
const UNWANTED_WAIT: Duration = Duration::from_secs(60);

/// The first and the longest wait after a failed attempt.
const BACKOFF_START: Duration = Duration::from_secs(60);
/// The longest wait after failed attempts. A [`RenewPace`] that nobody wants for this long has
/// nothing left to remember.
pub const BACKOFF_MAX: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct PaceState {
    /// No order for this name before this time.
    next_allowed: Instant,
    /// The wait the next failure sets (doubles up to [`BACKOFF_MAX`]).
    backoff: Duration,
}

/// When the next order for one name may start, and how long the wait after the next failure is.
/// It belongs to the name, not to the task that renews it: the caller keeps it while a task
/// ends and a new one starts (an attachment that goes and comes back, a name the relay drops
/// and lists again), so that starting a task is not a way past the backoff (expose round 4, M2).
/// Cloned freely; the clones are one state.
#[derive(Debug, Clone)]
pub struct RenewPace {
    inner: Arc<Mutex<PaceState>>,
}

impl Default for RenewPace {
    fn default() -> Self {
        Self::new()
    }
}

impl RenewPace {
    /// A fresh state: an order may start at once, a failure waits [`BACKOFF_START`].
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(PaceState {
                next_allowed: Instant::now(),
                backoff: BACKOFF_START,
            })),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, PaceState> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// When the next order may start.
    pub fn next_allowed(&self) -> Instant {
        self.state().next_allowed
    }

    /// Whether `other` is this very state (a clone of it).
    pub fn is_same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// The wait (before jitter) the next failure sets.
    pub fn backoff(&self) -> Duration {
        self.state().backoff
    }

    /// An order starts now: the next one is at least [`BACKOFF_START`] away, however it ends.
    fn started(&self) {
        let mut state = self.state();
        state.next_allowed = state.next_allowed.max(Instant::now() + BACKOFF_START);
    }

    /// The order failed: the next waits the backoff (with jitter), which then doubles.
    fn failed(&self) -> Duration {
        let mut state = self.state();
        let wait = state.backoff.mul_f64(0.75 + fastrand::f64() / 2.0);
        state.backoff = (state.backoff * 2).min(BACKOFF_MAX);
        state.next_allowed = Instant::now() + wait;
        wait
    }

    /// The order succeeded: the backoff is back at the start.
    fn succeeded(&self) {
        let mut state = self.state();
        state.backoff = BACKOFF_START;
        state.next_allowed = Instant::now() + BACKOFF_START;
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// When to renew a certificate valid from `not_before` to `not_after`: two thirds of the way,
/// less up to a twelfth of the lifetime (`jitter` in `[0, 1)`), so that nodes that got their
/// certificates together do not ask together, and never later than two thirds.
pub fn renewal_time(not_before: u64, not_after: u64, jitter: f64) -> u64 {
    let life = not_after.saturating_sub(not_before);
    let jitter = if jitter.is_finite() {
        jitter.clamp(0.0, 1.0)
    } else {
        0.0
    };
    let earlier = (life as f64 / 12.0 * jitter) as u64;
    not_before + life / 3 * 2 - earlier.min(life / 3 * 2)
}

/// Writes `bytes` to `path` as a file only the owner can read, atomically (a temporary file in
/// the same directory, renamed over). The directory is made (0700) if it is missing.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AcmeError> {
    let store = |e: &dyn std::fmt::Display| AcmeError::Store(format!("{}: {e}", path.display()));
    let dir = path
        .parent()
        .ok_or_else(|| AcmeError::Store(format!("{}: no directory", path.display())))?;
    create_private_dir(dir).map_err(|e| store(&e))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temp = dir.join(format!(".{name}.{}.tmp", fastrand::u64(..)));
    let written = (|| {
        use std::io::Write as _;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()
    })();
    if let Err(e) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(store(&e));
    }
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        store(&e)
    })
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// What a leaf certificate is checked for before it is kept: the first PEM block parses, names
/// `domain` in its subject alternative names, carries `public_key` (the key of the CSR, as the
/// raw point) and is valid now. Returns its `notBefore` and `notAfter` in Unix seconds.
pub(crate) fn check_issued(
    chain_pem: &str,
    domain: &str,
    public_key: &[u8],
) -> Result<(u64, u64), AcmeError> {
    let bad = |why: &str| AcmeError::Protocol(format!("the certificate: {why}"));
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(chain_pem.as_bytes()).map_err(|_| bad("no PEM block"))?;
    let cert = pem.parse_x509().map_err(|_| bad("it does not parse"))?;
    let names_domain = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .is_some_and(|san| {
            san.value.general_names.iter().any(
                |name| matches!(name, GeneralName::DNSName(dns) if dns.eq_ignore_ascii_case(domain)),
            )
        });
    if !names_domain {
        return Err(bad("it does not name the domain"));
    }
    if cert.public_key().subject_public_key.data.as_ref() != public_key {
        return Err(bad("it does not carry the key of the request"));
    }
    let validity = cert.validity();
    let (not_before, not_after) = (
        u64::try_from(validity.not_before.timestamp()).map_err(|_| bad("a bad notBefore"))?,
        u64::try_from(validity.not_after.timestamp()).map_err(|_| bad("a bad notAfter"))?,
    );
    let now = unix_now();
    if not_after <= now || not_before > now + 3600 || not_after <= not_before {
        return Err(bad("it is not valid now"));
    }
    Ok((not_before, not_after))
}

/// Where the node keeps what ACME issued: `<home>/acme/certs/<domain>/`.
#[derive(Debug, Clone)]
pub struct CertStore {
    root: PathBuf,
}

impl CertStore {
    /// The store of the node home `home`.
    pub fn new(home: &Path) -> Self {
        Self {
            root: home.join("acme").join("certs"),
        }
    }

    /// The account key file of the node home `home`.
    pub fn account_key_path(home: &Path) -> PathBuf {
        home.join("acme").join("account.key")
    }

    /// The certificate chain file and the key file of `domain`.
    pub fn paths(&self, domain: &str) -> Result<(PathBuf, PathBuf), AcmeError> {
        check_domain(domain)?;
        let dir = self.root.join(domain);
        Ok((dir.join("fullchain.pem"), dir.join("privkey.pem")))
    }

    /// Keeps `issued` for `domain`: the key (0600) and the chain, each replaced atomically.
    pub fn save(&self, domain: &str, issued: &Issued) -> Result<(), AcmeError> {
        let (chain, key) = self.paths(domain)?;
        write_private(&key, issued.key_pem.as_bytes())?;
        write_private(&chain, issued.chain_pem.as_bytes())
    }

    /// The validity of the chain kept for `domain`, if there is one that parses.
    pub fn validity(&self, domain: &str) -> Option<(u64, u64)> {
        let (chain, _) = self.paths(domain).ok()?;
        let pem = std::fs::read_to_string(chain).ok()?;
        let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
        let cert = block.parse_x509().ok()?;
        let validity = cert.validity();
        Some((
            u64::try_from(validity.not_before.timestamp()).ok()?,
            u64::try_from(validity.not_after.timestamp()).ok()?,
        ))
    }
}

/// One name to keep a certificate for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AcmeJob {
    /// The share's name (its label), as in `[[share]]`.
    pub share: String,
    /// The full name the certificate is for (the share name under the relay's share domain).
    pub domain: String,
}

/// What a renewal loop is doing, as [`run_renewals_observed`] reports it (for a status display;
/// nothing is decided from it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// An order is being made now.
    Renewing,
    /// An order ended with a certificate that is stored.
    Issued,
    /// An attempt failed; another follows after a wait.
    Failed(FailureKind),
    /// The attempt ended because the name is not wanted any more (nothing failed).
    Idle,
}

/// Keeps a certificate for `job.domain` fresh, forever (the caller aborts the task): when none is
/// stored, or the stored one is past its renewal time, and `wanted()` says so, an
/// [`AcmeClient::obtain`] is run and its result stored; a failure is logged and retried after
/// a wait that doubles from one minute to one hour, with jitter. (The wait lives in a state of
/// this call only; a caller that restarts the task keeps one [`RenewPace`] per name and uses
/// [`run_renewals_observed`].)
pub async fn run_renewals<T: AcmeTransport>(
    client: AcmeClient<T>,
    store: CertStore,
    wanted: impl Fn() -> bool + Send + Sync,
    book: ChallengeBook,
    job: AcmeJob,
) {
    run_renewals_observed(client, store, wanted, book, job, RenewPace::new(), |_| {}).await
}

/// [`run_renewals`] that also tells `observe` what it is doing: [`Progress::Renewing`] before
/// each order, and how the order ended. `pace` is the name's order timing: no order starts
/// before [`RenewPace::next_allowed`], every order start sets it a minute ahead, a failure
/// sets it by the doubling backoff and a success resets the backoff.
pub async fn run_renewals_observed<T: AcmeTransport>(
    mut client: AcmeClient<T>,
    store: CertStore,
    wanted: impl Fn() -> bool + Send + Sync,
    book: ChallengeBook,
    job: AcmeJob,
    pace: RenewPace,
    observe: impl Fn(Progress) + Send + Sync,
) {
    loop {
        let now = unix_now();
        let due = match store.validity(&job.domain) {
            Some((not_before, not_after)) if now < not_after => {
                renewal_time(not_before, not_after, fastrand::f64())
            }
            _ => 0,
        };
        if now < due {
            tokio::time::sleep(Duration::from_secs(due - now).min(MAX_SLEEP)).await;
            continue;
        }
        if !wanted() {
            tokio::time::sleep(UNWANTED_WAIT).await;
            continue;
        }
        // The wait of an earlier task for this name, or of an earlier failure, is not over.
        let allowed = pace.next_allowed();
        if allowed > Instant::now() {
            tokio::time::sleep_until(allowed).await;
            continue;
        }
        pace.started();
        observe(Progress::Renewing);
        let outcome = client.obtain(&job.domain, &book, &wanted).await;
        let wait = match outcome
            .and_then(|issued| store.save(&job.domain, &issued).map(|()| issued))
        {
            Ok(issued) => {
                tracing::info!(domain = %job.domain, not_after = issued.not_after, "a certificate was issued and stored");
                pace.succeeded();
                observe(Progress::Issued);
                // However short a lifetime the CA chose, one order a minute at most.
                BACKOFF_START
            }
            Err(AcmeError::NotWanted) => {
                observe(Progress::Idle);
                UNWANTED_WAIT
            }
            Err(error) => {
                tracing::warn!(domain = %job.domain, %error, "ACME did not issue a certificate; retrying later");
                observe(Progress::Failed(error.failure_kind()));
                pace.failed()
            }
        };
        tokio::time::sleep(wait).await;
    }
}
