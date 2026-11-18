//! The awaiting tail end to end (slice D3 L4 S3, design note invite-roster-only-policy-design.md):
//! the issuer's push ladder is shortened to 1 s a rung and its tail to 2 s, so a device that
//! starts its node long after the ladder ended still gets the Policy, and so does one whose
//! issuer node was restarted between the admission and the device's start (the tail is seeded
//! from the invite book, in memory only otherwise).
//!
//! One `#[tokio::test]`: `SSL_CERT_FILE` and the test knobs are process-global.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::time::{Duration, Instant};

use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::invite::{self, CreateSpec};
use menzil_cli::join::{JoinError, JoinOptions, Joined, redeem};
use menzil_cli::local::{
    admit, init, join as join_documents, network_create, steward_add, steward_request,
    token_for_relay,
};
use menzil_cli::node_cmd::{self, RunningNode};
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};

const WAIT: Duration = Duration::from_secs(60);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn until(what: &str, mut check: impl FnMut() -> bool) {
    let started = Instant::now();
    while !check() {
        assert!(started.elapsed() < WAIT, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn options(name: &str) -> JoinOptions {
    JoinOptions {
        name: Some(name.to_string()),
        wait: Duration::from_secs(40),
        retry_first: Duration::from_secs(1),
        retry_max: Duration::from_secs(2),
    }
}

/// A device home with an identity and a config that dials directly.
fn device(root: &Path, label: &str, real: u64) -> (Home, String) {
    let home = Home::new(root.join(label));
    init(&home, real).unwrap();
    std::fs::write(home.config_path(), "proxy = \"direct\"\n").unwrap();
    (home, label.to_string())
}

/// Redeems `token` from each `(home, name)` at once; the results in the same order.
async fn race(token: &str, devices: &[(Home, String)]) -> Vec<Result<Joined, JoinError>> {
    let handles: Vec<_> = devices
        .iter()
        .map(|(home, name)| {
            let (home, name, token) = (home.clone(), name.clone(), token.to_string());
            tokio::spawn(async move { redeem(&home, &token, &options(&name), &mut |_| {}).await })
        })
        .collect();
    let mut results = Vec::new();
    for handle in handles {
        results.push(tokio::time::timeout(WAIT, handle).await.unwrap().unwrap());
    }
    results
}

async fn start_node(home: &Home, socket: &Path) -> RunningNode {
    let node = node_cmd::start(home, &Config::load(home).unwrap(), socket)
        .await
        .unwrap();
    node.node.wait_attached(WAIT).await.expect("node attaches");
    node
}

#[tokio::test]
async fn a_device_that_starts_after_the_ladder_still_gets_the_policy_from_the_tail() {
    // SAFETY: first thing in the only test of this binary, before any other thread reads it.
    unsafe {
        std::env::set_var("MENZIL_TEST_PUSH_RETRY", "1");
        std::env::set_var("MENZIL_TEST_AWAIT_TAIL", "2");
    }
    let real = unix_now();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = root.join("fullchain.pem");
    let key_pem = root.join("privkey.pem");
    std::fs::write(&cert_pem, certified.cert.pem()).unwrap();
    std::fs::write(&key_pem, certified.signing_key.serialize_pem()).unwrap();
    // SAFETY: the first thing the only test in this binary does, before any dial or other thread
    // that could read the environment.
    unsafe { std::env::set_var("SSL_CERT_FILE", &cert_pem) };

    // ---- the network: an owner, a steward that may admit, a relay ---------------------------
    let relay_home = Home::new(root.join("relay"));
    let owner_home = Home::new(root.join("owner"));
    let steward_home = Home::new(root.join("steward"));
    init(&relay_home, real).unwrap();
    init(&owner_home, real).unwrap();
    let network_id = network_create(&owner_home, "owner", real).unwrap();
    let steward_join = init(&steward_home, real).unwrap().join_request;
    let admitted = admit(&owner_home, None, &steward_join, "steward", &[], real).unwrap();
    join_documents(&steward_home, &admitted.token, real).unwrap();
    let asked = steward_request(&steward_home, None).unwrap();
    let may = ["admit".to_string()];
    let listed = steward_add(&owner_home, None, &asked.token, &may, 30, real).unwrap();
    join_documents(&steward_home, &listed.issued.token, real).unwrap();
    relay_cmd::add_network(
        &relay_home,
        &token_for_relay(&owner_home, None).unwrap(),
        real,
    )
    .unwrap();
    let relay = relay_cmd::start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert_pem.clone(),
            tls_key: key_pem.clone(),
            path: DEFAULT_PATH.to_string(),
            host: Some("localhost".to_string()),
            reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
            fallback_page: None,
            admission: None,
            audit_file: None,
        },
    )
    .await
    .unwrap();
    let relay_line = relay.connection_info.to_string();
    std::fs::write(
        steward_home.config_path(),
        format!("relay = \"{relay_line}\"\nproxy = \"direct\"\n"),
    )
    .unwrap();
    let mut steward = start_node(&steward_home, &root.join("steward.sock")).await;

    let make =
        |spec: &CreateSpec| invite::create(&steward_home, spec, &relay_line, unix_now()).unwrap();

    // ---- (1) the device starts 12 s after its admission (a plain delivery check: the ladder
    // may still be running, a dial that finds nobody attached waits a while per rung) ---------
    let first = make(&CreateSpec::default());
    let alpha = device(root, "alpha", real);
    let results = race(&first.token, std::slice::from_ref(&alpha)).await;
    assert!(results[0].is_ok(), "{results:?}");
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert!(alpha.0.roster_only_path(&network_id).is_file());
    let alpha_node = start_node(&alpha.0, &root.join("alpha.sock")).await;
    until("the tail to give alpha the Policy", || {
        alpha_node.node.policies().seq(&network_id).is_some()
    })
    .await;
    until("documents.bin to replace roster-only.bin", || {
        alpha.0.documents_path(&network_id).is_file()
            && !alpha.0.roster_only_path(&network_id).exists()
    })
    .await;

    // ---- (2) the issuer node restarts after the admission, so no ladder runs for bravo: only
    // the tail, seeded from the invite book at start, can deliver (mutants: no seed, no tail) ---
    let second = make(&CreateSpec::default());
    let bravo = device(root, "bravo", real);
    let results = race(&second.token, std::slice::from_ref(&bravo)).await;
    assert!(results[0].is_ok(), "{results:?}");
    assert!(steward.node.close_gracefully(Duration::from_secs(10)).await);
    drop(steward);
    steward = start_node(&steward_home, &root.join("steward2.sock")).await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert!(bravo.0.roster_only_path(&network_id).is_file());
    let bravo_node = start_node(&bravo.0, &root.join("bravo.sock")).await;
    until("the seeded tail to give bravo the Policy", || {
        bravo_node.node.policies().seq(&network_id).is_some()
    })
    .await;
    until("bravo's documents.bin", || {
        bravo.0.documents_path(&network_id).is_file()
            && !bravo.0.roster_only_path(&network_id).exists()
    })
    .await;

    drop(alpha_node);
    drop(bravo_node);
    drop(steward);
    relay.stop();
}
