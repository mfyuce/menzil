//! `menzil relay run` as a process: SIGTERM is a clean stop that first flushes the keeper, so the
//! Roster the relay adopted last over DOC is on disk when the process is gone (`run_until`,
//! TOBEDECIDED 28b). The in-process tests call `run_until` with a stand-in for the signal; this
//! runs the real binary, so the wiring of `main.rs` (`signals::shutdown()` into `run_until`, the
//! exit status, the "stopping" line) is what is under test.
//!
//! The relay is the child. A steward node in this process renews the network's Roster at its
//! start and pushes it to the relay over DOC while this test holds the relay's file lock, so the
//! keeper cannot write it; only the flush at the stop, which waits for the lock (up to 3 s) and
//! gets it when the test lets go just after the signal, puts it on disk. A process that ignored
//! the flush (or the signal) leaves the old Roster behind.
//!
//! One `#[tokio::test]`: `SSL_CERT_FILE` is process-global and must be set before anything dials.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::local::{
    admit, init, join, network_create, steward_add, steward_request, token_for_relay,
};
use menzil_cli::node_cmd;
use menzil_cli::relay_cmd;
use menzil_proto::NetworkId;

const DAY: u64 = 24 * 60 * 60;
const WAIT: Duration = Duration::from_secs(60);
/// The relay's own flush bound is 3 s; a stop takes less than this on an idle machine and not
/// much more under load.
const EXIT_BOUND: Duration = Duration::from_secs(12);

struct Guard(Option<Child>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn stored_seq(relay_home: &Home, network_id: &NetworkId) -> Option<u64> {
    relay_cmd::load_rosters(relay_home).ok().and_then(|kept| {
        kept.iter()
            .filter_map(|stored| stored.roster.decode().ok())
            .find(|body| &body.network_id == network_id)
            .map(|body| body.seq)
    })
}

#[tokio::test]
async fn sigterm_flushes_the_roster_adopted_last_and_exits_zero() {
    let real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // As in steward_renew_live: made eight days ago, so the steward renews when its node starts.
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
    init(&relay_home, issued).unwrap();
    init(&owner_home, issued).unwrap();
    let network_id = network_create(&owner_home, "owner", issued).unwrap();
    let steward_join = init(&steward_home, issued).unwrap().join_request;
    let admitted = admit(&owner_home, None, &steward_join, "steward", &[], issued).unwrap();
    join(&steward_home, &admitted.token, issued).unwrap();
    let asked = steward_request(&steward_home, None).unwrap();
    let may = ["admit".to_string(), "renew".to_string()];
    let listed = steward_add(&owner_home, None, &asked.token, &may, 30, issued).unwrap();
    join(&steward_home, &listed.issued.token, issued).unwrap();
    let start_seq = listed.issued.seq;
    relay_cmd::add_network(
        &relay_home,
        &token_for_relay(&owner_home, None).unwrap(),
        real,
    )
    .unwrap();
    assert_eq!(stored_seq(&relay_home, &network_id), Some(start_seq));

    // The relay: the real binary.
    let mut child = Command::new(env!("CARGO_BIN_EXE_menzil"))
        .arg("--home")
        .arg(relay_home.root())
        .args([
            "relay",
            "run",
            "--listen",
            "127.0.0.1:0",
            "--host",
            "localhost",
        ])
        .arg("--tls-cert")
        .arg(&cert_pem)
        .arg("--tls-key")
        .arg(&key_pem)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let mut relay = Guard(Some(child));
    // The connection information is the only line on standard output.
    let (info_tx, info_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = info_tx.send(line);
        }
    });
    let (err_tx, err_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        let _ = err_tx.send(text);
    });
    let connection_info = info_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the relay prints its connection information");

    std::fs::create_dir_all(steward_home.root()).unwrap();
    std::fs::write(
        steward_home.config_path(),
        format!("relay = \"{connection_info}\"\nproxy = \"direct\"\n"),
    )
    .unwrap();

    // From here the keeper cannot write.
    let busy = relay_home.lock_relay().unwrap();
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
    let renewed = start_seq + 1;
    let started = Instant::now();
    while steward.node.rosters().seq(&network_id) != Some(renewed) {
        assert!(started.elapsed() < WAIT, "the steward did not renew");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The push to the relay is not observable from here except on the disk, which the lock keeps
    // untouched; give it time.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        stored_seq(&relay_home, &network_id),
        Some(start_seq),
        "the lock was supposed to keep the keeper from writing"
    );

    let pid = relay.0.as_ref().unwrap().id();
    let signalled = Instant::now();
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .unwrap();
    assert!(status.success());
    // Let go a moment after the signal: the flush at the stop is waiting for the lock.
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(busy);

    let mut child = relay.0.take().unwrap();
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        if signalled.elapsed() > EXIT_BOUND {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the relay did not exit within {EXIT_BOUND:?} of SIGTERM");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(exit.success(), "exit status {exit:?} after SIGTERM");
    let errors = err_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(errors.contains("stopping ("), "{errors}");
    assert!(
        !errors.contains("may not have reached the disk"),
        "{errors}"
    );
    assert!(!errors.contains("panicked"), "{errors}");

    assert_eq!(
        stored_seq(&relay_home, &network_id),
        Some(renewed),
        "the Roster adopted last was not on disk after the stop"
    );
    drop(steward);
}
