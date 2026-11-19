//! Does a bare drop of a `RunningNode` (no `close_gracefully`) end its relay session? The relay
//! writes `relay/status.json` every 10 s with `attached_sessions` per tenant; after the drop the
//! sum must reach zero. One `#[tokio::test]`: `SSL_CERT_FILE` is process-global.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::time::{Duration, Instant};

use menzil_cli::config::Config;
use menzil_cli::home::Home;
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

async fn start_node(home: &Home, socket: &Path) -> RunningNode {
    let node = node_cmd::start(home, &Config::load(home).unwrap(), socket)
        .await
        .unwrap();
    node.node.wait_attached(WAIT).await.expect("node attaches");
    node
}

#[tokio::test]
async fn a_bare_drop_of_a_running_node_ends_its_relay_session() {
    // SAFETY: first thing in the only test of this binary, before any other thread reads it.
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
    let _network_id = network_create(&owner_home, "owner", real).unwrap();
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
            redeem: None,
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
    let steward = start_node(&steward_home, &root.join("steward.sock")).await;

    let attached = || -> u64 {
        let text = std::fs::read_to_string(relay_home.root().join("relay").join("status.json"))
            .unwrap_or_default();
        text.split("\"attached_sessions\":")
            .skip(1)
            .filter_map(|rest| {
                rest.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse::<u64>()
                    .ok()
            })
            .sum()
    };
    until("the status file to show the steward attached", || {
        attached() == 1
    })
    .await;
    drop(steward);
    until("the relay to see the dropped node gone", || attached() == 0).await;
    relay.stop();
}
