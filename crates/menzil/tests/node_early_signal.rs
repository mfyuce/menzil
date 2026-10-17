//! A stopping signal while `menzil node` is still attaching to its relay (the fourth red-team
//! round, N3). The node waits up to 60 s for the relay; its signal handlers used to be installed
//! only after that wait, so a SIGTERM in the meantime took the default action: the process died
//! on the spot and left the agent socket file behind. It has to stop the way it stops later:
//! status 0, socket file removed.

#![cfg(target_os = "linux")]

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use menzil_cli::local::{init, network_create};

const WAIT: Duration = Duration::from_secs(20);

/// Kills the child when the test ends one way or another.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn a_signal_while_the_node_is_still_attaching_stops_it_the_graceful_way() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // A short path: Unix socket paths are limited to about 100 bytes.
    let dir = tempfile::Builder::new()
        .prefix("ne")
        .tempdir_in("/tmp")
        .unwrap();
    let home = menzil_cli::home::Home::new(dir.path().join("h"));
    init(&home, now).unwrap();
    network_create(&home, "laptop", now).unwrap();
    let socket = dir.path().join("a.sock");
    // A relay that is not there (nothing listens on port 1): the node starts, tries and tries,
    // and is not attached for the whole of the 60 s it waits.
    let (id, key) = ("aa".repeat(32), "bb".repeat(32));
    std::fs::write(
        home.config_path(),
        format!(
            "relay = \"menzil://127.0.0.1:1/_menzil/v1?id={id}&key={key}\"\nproxy = \"direct\"\nagent_socket = \"{}\"\n",
            socket.display()
        ),
    )
    .unwrap();

    let mut node = Guard(
        Command::new(env!("CARGO_BIN_EXE_menzil"))
            .arg("node")
            .env("MENZIL_HOME", home.root())
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    // The agent socket is bound before the wait for the relay begins.
    let started = Instant::now();
    while !socket.exists() {
        assert!(started.elapsed() < WAIT, "the node never bound its socket");
        assert!(
            node.0.try_wait().unwrap().is_none(),
            "the node ended before it bound its socket"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // Let it get as far as the wait for the relay.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        node.0.try_wait().unwrap().is_none(),
        "the node must still be attaching"
    );

    let status = Command::new("kill")
        .arg("-TERM")
        .arg(node.0.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = node.0.try_wait().unwrap() {
            break status;
        }
        assert!(started.elapsed() < WAIT, "the node did not stop");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "a node stopped by a signal exits normally (a bare SIGTERM would have ended it as {status:?})"
    );
    assert!(
        !socket.exists(),
        "the agent socket file must be removed on the way out"
    );
}
