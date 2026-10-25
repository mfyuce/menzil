//! A steward node renews the network's documents by itself and a member adopts them without a
//! restart (protocol.md 7.3, L4j S7), over a real relay with real TLS; then the steward admits
//! a device from the command line while its node runs, and the node pushes that to the member
//! too (the reload path).
//!
//! One `#[tokio::test]` for the same reason `menzil-node`'s live tests have exactly one:
//! `SSL_CERT_FILE` is process-global, and it must be set before anything dials.

#![cfg(target_os = "linux")]

use std::time::Duration;

use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::local::{
    admit, init, join, load_documents, network_create, steward_add, steward_request,
    token_for_relay,
};
use menzil_cli::node_cmd;
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use menzil_node::PolicyStore;
use menzil_proto::NetworkId;
use menzil_proto::trust::Signer;

const DAY: u64 = 24 * 60 * 60;
const WAIT: Duration = Duration::from_secs(60);

/// Polls until `check` holds, up to `WAIT`.
async fn until(what: &str, mut check: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !check() {
        assert!(started.elapsed() < WAIT, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn holds_member(policies: &PolicyStore, network_id: &NetworkId, name: &str) -> bool {
    policies
        .body(network_id)
        .is_some_and(|body| body.members.iter().any(|member| member.name == name))
}

#[tokio::test]
async fn a_steward_node_renews_by_itself_and_a_member_adopts_without_a_restart() {
    let real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // The network was made eight days ago: its documents run out in six, inside the seven
    // days after which a steward renews. Certificates are valid from then on.
    let issued = real - 8 * DAY;
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

    let relay_home = Home::new(root.join("relay"));
    let owner_home = Home::new(root.join("owner"));
    let steward_home = Home::new(root.join("steward"));
    let phone_home = Home::new(root.join("phone"));
    let tablet_home = Home::new(root.join("tablet"));
    init(&relay_home, issued).unwrap();
    init(&owner_home, issued).unwrap();
    let network_id = network_create(&owner_home, "owner", issued).unwrap();
    let steward_join = init(&steward_home, issued).unwrap().join_request;
    let phone_join = init(&phone_home, issued).unwrap().join_request;
    let tablet_join = init(&tablet_home, real).unwrap().join_request;
    let admitted = admit(&owner_home, None, &steward_join, "steward", &[], issued).unwrap();
    join(&steward_home, &admitted.token, issued).unwrap();
    admit(&owner_home, None, &phone_join, "phone", &[], issued).unwrap();
    let asked = steward_request(&steward_home, None).unwrap();
    let may = ["admit".to_string(), "renew".to_string()];
    let listed = steward_add(&owner_home, None, &asked.token, &may, 30, issued).unwrap();
    join(&steward_home, &listed.issued.token, issued).unwrap();
    join(&phone_home, &listed.issued.token, issued).unwrap();
    let start_seq = listed.issued.seq;
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
        },
    )
    .await
    .unwrap();
    for home in [&steward_home, &phone_home] {
        std::fs::create_dir_all(home.root()).unwrap();
        std::fs::write(
            home.config_path(),
            format!(
                "relay = \"{}\"\nproxy = \"direct\"\n",
                relay.connection_info
            ),
        )
        .unwrap();
    }

    // The member first, so that it is on the relay when the steward starts and renews.
    let phone = node_cmd::start(
        &phone_home,
        &Config::load(&phone_home).unwrap(),
        &root.join("phone.sock"),
    )
    .await
    .unwrap();
    phone
        .node
        .wait_attached(WAIT)
        .await
        .expect("phone attaches");
    assert_eq!(phone.node.rosters().seq(&network_id), Some(start_seq));

    let steward = node_cmd::start(
        &steward_home,
        &Config::load(&steward_home).unwrap(),
        &root.join("steward.sock"),
    )
    .await
    .unwrap();
    steward
        .node
        .wait_attached(WAIT)
        .await
        .expect("steward attaches");

    // The steward renews at its start; the phone, which never restarts, ends up with it.
    let renewed = start_seq + 1;
    until("the steward to renew", || {
        steward.node.rosters().seq(&network_id) == Some(renewed)
    })
    .await;
    let disk = load_documents(&steward_home, &network_id).unwrap();
    assert_eq!(disk.seq(), renewed);
    assert!(disk.roster_body().expires > real + 13 * DAY);
    until("the phone to adopt the renewed pair", || {
        phone.node.rosters().seq(&network_id) == Some(renewed)
            && phone.node.policies().seq(&network_id) == Some(renewed)
    })
    .await;
    assert!(matches!(
        phone.node.rosters().signer(&network_id),
        Some(Signer::Steward { .. })
    ));
    // The relay has it too: a restarted phone would hear it in WELCOME (not checked here).

    // Then the steward admits a device from the command line while its node runs: the node
    // picks the file up on its reload, and, being the issuer, pushes it to the phone.
    let admitted = admit(&steward_home, None, &tablet_join, "tablet", &[], real).unwrap();
    assert_eq!(admitted.seq, renewed + 1);
    until("the phone to hold the tablet", || {
        holds_member(phone.node.policies(), &network_id, "tablet")
    })
    .await;
    assert_eq!(phone.node.rosters().seq(&network_id), Some(renewed + 1));

    drop(steward);
    drop(phone);
    relay.stop();
}
