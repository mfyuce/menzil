//! A reader of standard error that goes away early (`menzil status 2>&1 | grep -q`, a log
//! collector that died) must not make a command panic or end a running role: the standard print
//! macro does, so the crate has its own (`stderr.rs`), and the log writer must not use it either.

#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use menzil_cli::home::Home;
use menzil_cli::local::{init, network_create, token_for_relay};
use menzil_cli::relay_cmd;

const WAIT: Duration = Duration::from_secs(30);

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The writing end of a pipe nobody reads: every write to it fails with a broken pipe.
fn nobody_reads() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_menzil"));
    command
        .arg("--home")
        .arg(home)
        .args(args)
        .env("XDG_RUNTIME_DIR", home)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null());
    command
}

fn menzil(home: &Path, args: &[&str]) -> Output {
    command(home, args)
        .stdout(Stdio::piped())
        .stderr(nobody_reads())
        .output()
        .unwrap()
}

#[test]
fn commands_keep_their_exit_status_when_standard_error_has_no_reader() {
    let dir = tempfile::tempdir().unwrap();
    // A failure is still a failure, not a panic: there is no identity yet.
    let out = menzil(dir.path(), &["join-request"]);
    assert_eq!(out.status.code(), Some(1), "{:?}", out.status);
    assert!(menzil(dir.path(), &["init"]).status.success());
    // No node answers, which `status` notes on standard error.
    let out = menzil(dir.path(), &["status"]);
    assert!(out.status.success(), "{:?}", out.status);
}

/// A running role writes both its own lines and log lines; both meet the closed pipe.
#[test]
fn a_relay_runs_and_stops_cleanly_when_standard_error_has_no_reader() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("relay");
    // A relay does not start without a network to serve.
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let relay_home = Home::new(&home);
    let owner_home = Home::new(dir.path().join("owner"));
    // Its certificate (400 days) ends soon, so the start logs a warning on the main task, where a
    // panic of the log writer ends the process.
    init(&relay_home, now - 380 * 24 * 60 * 60).unwrap();
    init(&owner_home, now).unwrap();
    network_create(&owner_home, "owner", now).unwrap();
    let network = token_for_relay(&owner_home, None).unwrap();
    relay_cmd::add_network(&relay_home, &network, now).unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = dir.path().join("fullchain.pem");
    let key_pem = dir.path().join("privkey.pem");
    std::fs::write(&cert_pem, certified.cert.pem()).unwrap();
    std::fs::write(&key_pem, certified.signing_key.serialize_pem()).unwrap();

    let mut child = command(
        &home,
        &[
            "relay",
            "run",
            "--listen",
            "127.0.0.1:0",
            "--host",
            "localhost",
        ],
    )
    .arg("--tls-cert")
    .arg(&cert_pem)
    .arg("--tls-key")
    .arg(&key_pem)
    .stdout(Stdio::piped())
    .stderr(nobody_reads())
    .spawn()
    .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut relay = Guard(child);
    let (info_tx, info_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = info_tx.send(line);
        }
    });
    // Log lines go to standard error, so the first line here is the connection information.
    info_rx
        .recv_timeout(WAIT)
        .expect("the relay prints its connection information");
    // Long enough for the signal handlers, which are installed after that line.
    std::thread::sleep(Duration::from_millis(500));
    assert!(relay.0.try_wait().unwrap().is_none(), "the relay ended");

    let sent = Command::new("kill")
        .arg("-TERM")
        .arg(relay.0.id().to_string())
        .status()
        .unwrap();
    assert!(sent.success());
    let started = Instant::now();
    let exit = loop {
        if let Some(exit) = relay.0.try_wait().unwrap() {
            break exit;
        }
        assert!(started.elapsed() < WAIT, "the relay did not stop");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(exit.success(), "exit status {exit:?} after SIGTERM");
}
