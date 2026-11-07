//! Tests of the renewal supervisor: which jobs a relay answer allows (pure), and the tasks it
//! starts and stops (with an in process CA, under paused time).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use menzil_acme::testing::{FakeCa, Flags, fast, unb64};
use menzil_proto::{AdvertiseAckBody, Share, ShareMode};

use super::*;

const H: &str = "share.test";

fn share(name: &str, mode: ShareMode, service: &str, alpn: &[&str]) -> Share {
    Share {
        name: name.to_string(),
        mode,
        service: service.parse().unwrap(),
        alpn: alpn.iter().map(|a| a.to_string()).collect(),
    }
}

fn blind(name: &str, alpn: &[&str]) -> Share {
    share(name, ShareMode::Blind, &format!("tls:{name}"), alpn)
}

fn ack(accepted: &[&str], names: &[&str], domain: Option<&str>) -> AdvertiseAckBody {
    AdvertiseAckBody {
        accepted: accepted.iter().map(|s| s.to_string()).collect(),
        rejected: Vec::new(),
        names: names.iter().map(|s| s.to_string()).collect(),
        share_domain: domain.map(str::to_string),
    }
}

/// The book after `shares` were sent and `ack` came back.
fn answered(shares: &[Share], ack: &AdvertiseAckBody) -> ShareBook {
    let book = ShareBook::new();
    book.note_sent(shares);
    book.note_ack(ack);
    book
}

fn domains(jobs: &BTreeSet<AcmeJob>) -> Vec<String> {
    jobs.iter().map(|job| job.domain.clone()).collect()
}

// ---- which jobs a relay answer allows ----

#[test]
fn only_a_wanted_share_and_only_a_name_of_the_ack_is_a_job_under_the_acks_domain() {
    let shares = [
        blind("app", &["h2", "acme-tls/1"]),
        blind("plain", &["h2"]),
        blind("any", &[]),
        share("web", ShareMode::Terminated, "http:web", &[]),
        blind("unlisted", &["acme-tls/1"]),
        blind("refused", &["acme-tls/1"]),
    ];
    let names = [
        "app",
        "app.ali",
        "plain",
        "any",
        "web",
        // `unlisted` is accepted but the ACK names no full name for it; `refused` is not
        // accepted at all, and a name nobody asked for is not ours.
        "stranger",
        "stranger.ali",
    ];
    let book = answered(
        &shares,
        &ack(&["app", "plain", "any", "web", "unlisted"], &names, Some(H)),
    );
    let jobs = candidate_jobs(&book.snapshot());
    assert_eq!(domains(&jobs), ["app.ali.share.test", "app.share.test"]);
    assert!(jobs.iter().all(|job| job.share == "app"));
}

#[test]
fn no_job_without_an_ack_without_a_domain_or_for_an_odd_name() {
    let shares = [blind("app", &["acme-tls/1"])];
    // Nothing answered yet.
    let book = ShareBook::new();
    book.note_sent(&shares);
    assert!(candidate_jobs(&book.snapshot()).is_empty());
    // An ACK without the share domain (an older relay): the node cannot name anything.
    let book = answered(&shares, &ack(&["app"], &["app"], None));
    assert!(candidate_jobs(&book.snapshot()).is_empty());
    // An ACK whose domain is not plausible is stored as none.
    let book = answered(&shares, &ack(&["app"], &["app"], Some("Not A Domain")));
    assert!(candidate_jobs(&book.snapshot()).is_empty());
    // A name that is not `label` or `label.slug`, or that builds an unusable full name.
    let book = answered(
        &shares,
        &ack(
            &["app"],
            &["app.a.b", "app.", ".app", "app..x", "app.Ali", ""],
            Some(H),
        ),
    );
    assert!(candidate_jobs(&book.snapshot()).is_empty());
    // The end of the attachment ends every job.
    let book = answered(&shares, &ack(&["app"], &["app"], Some(H)));
    assert_eq!(candidate_jobs(&book.snapshot()).len(), 1);
    book.note_detached();
    assert!(candidate_jobs(&book.snapshot()).is_empty());
}

#[test]
fn a_flood_of_names_is_cut_at_the_job_limit() {
    let shares = [blind("app", &["acme-tls/1"])];
    let many: Vec<String> = (0..200).map(|n| format!("app.t{n}")).collect();
    let names: Vec<&str> = many.iter().map(String::as_str).collect();
    let book = answered(&shares, &ack(&["app"], &names, Some(H)));
    assert_eq!(candidate_jobs(&book.snapshot()).len(), MAX_JOBS);
}

#[test]
fn a_configured_share_domain_is_only_a_cross_check() {
    let shares = [blind("app", &["acme-tls/1"])];
    let book = answered(&shares, &ack(&["app"], &["app"], Some(H)));
    let snapshot = book.snapshot();
    // Not set, or the same (in any case): the jobs run.
    for configured in [None, Some("share.test"), Some("SHARE.test")] {
        let decided = plan(&snapshot, configured);
        assert_eq!(domains(&decided.jobs), ["app.share.test"], "{configured:?}");
        assert!(decided.blocked.is_empty() && decided.mismatch.is_none());
    }
    // Different: nothing runs, what would have is named, and the pair is reported.
    let decided = plan(&snapshot, Some("other.test"));
    assert!(decided.jobs.is_empty());
    assert_eq!(domains(&decided.blocked), ["app.share.test"]);
    assert_eq!(
        decided.mismatch,
        Some(DomainMismatch {
            relay: H.to_string(),
            configured: "other.test".to_string()
        })
    );
    // The configured domain is never used to build a name: with none from the relay there is
    // nothing, however it is set.
    let book = answered(&shares, &ack(&["app"], &["app"], None));
    let decided = plan(&book.snapshot(), Some("other.test"));
    assert!(decided.jobs.is_empty() && decided.blocked.is_empty() && decided.mismatch.is_none());
}

// ---- the tasks ----

/// A scratch node home.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "menzil-node-acme-sup-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// An in process CA that records the name of every order (the first place a name reaches it)
/// and never validates, so that each attempt fails the same way, quickly.
#[derive(Clone)]
struct Recording {
    ca: Arc<FakeCa>,
    orders: Arc<Mutex<Vec<String>>>,
}

impl Recording {
    fn new(flags: Flags) -> Self {
        let book = ChallengeBook::new();
        Self {
            ca: FakeCa::new(&book, flags),
            orders: Arc::default(),
        }
    }

    /// How many orders each name got.
    fn counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for name in self.orders.lock().unwrap().iter() {
            *counts.entry(name.clone()).or_insert(0) += 1;
        }
        counts
    }
}

impl AcmeTransport for Recording {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, AcmeError> {
        if request.method == Method::Post && request.url.ends_with("/order") {
            let body = String::from_utf8_lossy(&request.body).into_owned();
            let payload = body
                .split("\"payload\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default();
            let text = String::from_utf8(unb64(payload)).unwrap();
            let name = text
                .split("\"value\":\"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_default();
            self.orders.lock().unwrap().push(name.to_string());
        }
        self.ca.send(request).await
    }
}

fn setup(home: &std::path::Path, transport: Recording) -> AcmeSetup<Recording> {
    AcmeSetup {
        transport,
        directory_url: format!("{}/dir", menzil_acme::testing::CA),
        contact: None,
        account_key_path: CertStore::account_key_path(home),
        store: CertStore::new(home),
        timing: fast(),
    }
}

fn never_validates() -> Flags {
    Flags {
        validation_fails: true,
        ..Flags::default()
    }
}

async fn minutes(n: u64) {
    tokio::time::sleep(Duration::from_secs(60 * n)).await;
}

fn state_of(status: &AcmeStatus, home: &std::path::Path, domain: &str) -> CertState {
    status.state(&CertStore::new(home), domain, 0)
}

#[tokio::test(start_paused = true)]
async fn tasks_follow_the_relays_answer_start_stop_and_start_again() {
    let scratch = Scratch::new();
    let ca = Recording::new(never_validates());
    let shares = ShareBook::new();
    let status = AcmeStatus::new();
    let supervisor = spawn_renewals(
        setup(&scratch.0, ca.clone()),
        shares.clone(),
        ChallengeBook::new(),
        status.clone(),
        || None,
    );
    let key_file = CertStore::account_key_path(&scratch.0);

    // Nothing answered: minutes pass, the CA is not asked and no account key is made.
    minutes(10).await;
    assert!(ca.counts().is_empty());
    assert!(!key_file.exists(), "the account key is made on first use");

    // The ACK: only the wanted share and only the names it lists are ordered.
    let all = [
        blind("app", &["acme-tls/1"]),
        blind("plain", &["h2"]),
        blind("unlisted", &["acme-tls/1"]),
        share("web", ShareMode::Terminated, "http:web", &[]),
    ];
    let first = ack(
        &["app", "plain", "unlisted", "web"],
        &["app", "app.ali", "plain", "web"],
        Some(H),
    );
    shares.note_sent(&all);
    shares.note_ack(&first);
    minutes(10).await;
    let counts = ca.counts();
    assert_eq!(
        counts.keys().cloned().collect::<Vec<_>>(),
        ["app.ali.share.test", "app.share.test"],
        "{counts:?}"
    );
    assert_eq!(
        state_of(&status, &scratch.0, "app.share.test"),
        CertState::Failed(FailureKind::Validation)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the account key is private");
    }

    // A new ACK that no longer lists `app.ali`: its task stops, `app`'s goes on.
    shares.note_sent(&all);
    shares.note_ack(&ack(
        &["app", "plain", "unlisted", "web"],
        &["app", "plain", "web"],
        Some(H),
    ));
    minutes(2).await;
    assert_eq!(
        state_of(&status, &scratch.0, "app.ali.share.test"),
        CertState::None
    );
    let before = ca.counts();
    minutes(180).await;
    let after = ca.counts();
    assert_eq!(
        after["app.ali.share.test"], before["app.ali.share.test"],
        "no order for a name the ACK dropped"
    );
    assert!(
        after["app.share.test"] > before["app.share.test"],
        "the other name goes on: {before:?} then {after:?}"
    );

    // The attachment ends: everything stops and the status is forgotten.
    shares.note_detached();
    minutes(2).await;
    assert_eq!(
        state_of(&status, &scratch.0, "app.share.test"),
        CertState::None
    );
    let before = ca.counts();
    minutes(180).await;
    assert_eq!(ca.counts(), before, "nothing is ordered while detached");

    // Attached again and ACKed: it starts again.
    shares.note_sent(&all);
    shares.note_ack(&first);
    minutes(10).await;
    let after = ca.counts();
    assert!(
        after["app.share.test"] > before["app.share.test"]
            && after["app.ali.share.test"] > before["app.ali.share.test"],
        "{before:?} then {after:?}"
    );

    // The owner takes `app` away: its tasks stop (the relay's answer need not come).
    shares.note_sent(&[blind("plain", &["h2"])]);
    minutes(2).await;
    let before = ca.counts();
    minutes(180).await;
    assert_eq!(ca.counts(), before, "a withdrawn share is not ordered for");

    // Stopping the supervisor stops its tasks too.
    shares.note_sent(&all);
    shares.note_ack(&first);
    minutes(10).await;
    let running = ca.counts();
    assert!(running["app.share.test"] > before["app.share.test"]);
    supervisor.abort();
    let _ = supervisor.await;
    minutes(1).await;
    let stopped = ca.counts();
    minutes(180).await;
    assert_eq!(
        ca.counts(),
        stopped,
        "aborting the supervisor took its tasks"
    );
}

#[tokio::test(start_paused = true)]
async fn a_share_domain_that_differs_from_the_relays_orders_nothing_until_they_agree() {
    let scratch = Scratch::new();
    let ca = Recording::new(never_validates());
    let shares = ShareBook::new();
    let status = AcmeStatus::new();
    let configured = Arc::new(Mutex::new(Some("other.test".to_string())));
    let supervisor = spawn_renewals(
        setup(&scratch.0, ca.clone()),
        shares.clone(),
        ChallengeBook::new(),
        status.clone(),
        {
            let configured = configured.clone();
            move || configured.lock().unwrap().clone()
        },
    );
    shares.note_sent(&[blind("app", &["acme-tls/1"])]);
    shares.note_ack(&ack(&["app"], &["app"], Some(H)));
    minutes(10).await;
    assert!(ca.counts().is_empty(), "no order on a mismatch");
    assert!(
        !CertStore::account_key_path(&scratch.0).exists(),
        "not even an account key"
    );
    assert_eq!(
        state_of(&status, &scratch.0, "app.share.test"),
        CertState::Failed(FailureKind::DomainMismatch)
    );
    // The configuration is corrected (the 30 second look finds it): the order is made.
    *configured.lock().unwrap() = Some(H.to_string());
    minutes(10).await;
    assert!(ca.counts().contains_key("app.share.test"));
    assert_eq!(
        state_of(&status, &scratch.0, "app.share.test"),
        CertState::Failed(FailureKind::Validation)
    );
    // And an edit that makes them differ again stops it.
    *configured.lock().unwrap() = Some("again.test".to_string());
    minutes(2).await;
    let before = ca.counts();
    minutes(180).await;
    assert_eq!(ca.counts(), before);
    assert_eq!(
        state_of(&status, &scratch.0, "app.share.test"),
        CertState::Failed(FailureKind::DomainMismatch)
    );
    supervisor.abort();
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn an_account_key_others_can_read_is_not_used_and_nothing_is_ordered() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let key_file = CertStore::account_key_path(&scratch.0);
    // A usable key, but with a mode others can read.
    std::fs::create_dir_all(key_file.parent().unwrap()).unwrap();
    std::fs::write(&key_file, AccountKey::generate().unwrap().to_pem()).unwrap();
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let ca = Recording::new(never_validates());
    let shares = ShareBook::new();
    let status = AcmeStatus::new();
    let supervisor = spawn_renewals(
        setup(&scratch.0, ca.clone()),
        shares.clone(),
        ChallengeBook::new(),
        status.clone(),
        || None,
    );
    shares.note_sent(&[blind("app", &["acme-tls/1"])]);
    shares.note_ack(&ack(&["app"], &["app"], Some(H)));
    minutes(5).await;
    assert!(ca.counts().is_empty());
    assert_eq!(
        state_of(&status, &scratch.0, "app.share.test"),
        CertState::Failed(FailureKind::Local)
    );
    assert_eq!(
        std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777,
        0o644,
        "the file is left as it is"
    );
    // The owner fixes the mode: the next look orders.
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    minutes(2).await;
    assert!(ca.counts().contains_key("app.share.test"));
    supervisor.abort();
}

#[tokio::test(start_paused = true)]
async fn a_certificate_is_obtained_stored_and_reported_valid() {
    let scratch = Scratch::new();
    let book = ChallengeBook::new();
    let recording = Recording {
        ca: FakeCa::new(&book, Flags::default()),
        orders: Arc::default(),
    };
    let shares = ShareBook::new();
    let status = AcmeStatus::new();
    let supervisor = spawn_renewals(
        setup(&scratch.0, recording.clone()),
        shares.clone(),
        book,
        status.clone(),
        || Some(H.to_string()),
    );
    shares.note_sent(&[blind("app", &["acme-tls/1"])]);
    shares.note_ack(&ack(&["app"], &["app"], Some(H)));
    let store = CertStore::new(&scratch.0);
    for _ in 0..200 {
        if store.validity("app.share.test").is_some() {
            break;
        }
        minutes(1).await;
    }
    assert!(store.validity("app.share.test").is_some());
    let (chain, key) = store.paths("app.share.test").unwrap();
    assert!(chain.exists() && key.exists());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(matches!(
        status.state(&store, "app.share.test", now),
        CertState::Valid { not_after } if not_after > now
    ));
    // A name that was never ordered has nothing.
    assert_eq!(
        status.state(&store, "other.share.test", now),
        CertState::None
    );
    supervisor.abort();
}
