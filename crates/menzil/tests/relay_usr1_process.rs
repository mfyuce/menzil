//! `menzil relay run --audit-file` as a process: SIGUSR1 makes the relay open the audit file
//! again, so a rotation (move the file away, signal) leaves a fresh file at the path and the
//! moved one untouched. Opening creates the file, so its reappearance is the observable.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn menzil(home: &std::path::Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_menzil"));
    command.arg("--home").arg(home).args(args);
    command
}

#[test]
fn sigusr1_reopens_the_audit_file() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("relay");
    assert!(menzil(&home, &["init"]).output().unwrap().status.success());
    // A relay serves at least one network.
    let owner = dir.path().join("owner");
    assert!(menzil(&owner, &["init"]).output().unwrap().status.success());
    assert!(
        menzil(&owner, &["network", "create"])
            .output()
            .unwrap()
            .status
            .success()
    );
    let token = menzil(&owner, &["token", "--for-relay"])
        .output()
        .unwrap()
        .stdout;
    let token = String::from_utf8(token).unwrap();
    assert!(
        menzil(&home, &["relay", "add-network", token.trim()])
            .output()
            .unwrap()
            .status
            .success()
    );
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert = dir.path().join("fullchain.pem");
    let key = dir.path().join("privkey.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    let audit = dir.path().join("audit.jsonl");

    let mut child = menzil(
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
    .arg(&cert)
    .arg("--tls-key")
    .arg(&key)
    .arg("--audit-file")
    .arg(&audit)
    .stdout(Stdio::piped())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
    let stdout = child.stdout.take().unwrap();
    let relay = Guard(child);
    // The connection information line says the relay is up (and the audit file is open).
    let mut lines = BufReader::new(stdout).lines();
    lines.next().expect("connection information").unwrap();
    assert!(audit.exists());

    let rotated = dir.path().join("audit.jsonl.1");
    std::fs::rename(&audit, &rotated).unwrap();
    assert!(!audit.exists());
    let status = Command::new("kill")
        .arg("-USR1")
        .arg(relay.0.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    let started = Instant::now();
    while !audit.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "no new audit file after SIGUSR1"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(rotated.exists());
    // The process is still up: the signal is not a stop.
    std::thread::sleep(Duration::from_millis(300));
    let mut relay = relay;
    assert!(relay.0.try_wait().unwrap().is_none());
}
