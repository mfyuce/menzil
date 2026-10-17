//! `menzil reach --unix` as a process, against a fake agent: the option reaches the listener, the
//! socket it makes is private, bytes go through, and a stopping signal ends it the graceful way
//! (status 0, socket file removed). The unit tests in `reach::tests` cover the carrying itself;
//! this covers `main.rs`'s wiring (TOBEDECIDED 15).

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A fake agent on `socket`: answers one request with `ok`, `bytes` and an end, then reads the
/// client's frames to their end.
fn fake_agent(socket: &Path, bytes: &'static [u8]) {
    let listener = UnixListener::bind(socket).unwrap();
    thread::spawn(move || {
        let (connection, _) = listener.accept().unwrap();
        let mut writer = connection.try_clone().unwrap();
        let mut reader = BufReader::new(connection);
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        assert_eq!(request, "open laptop/ssh\n");
        writer.write_all(b"ok\n").unwrap();
        writer.write_all(&frame(0, bytes)).unwrap();
        writer.write_all(&frame(1, b"")).unwrap();
        let mut rest = Vec::new();
        let _ = reader.read_to_end(&mut rest);
    });
}

/// Kills the process when the test ends one way or another.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn reach_on_a_unix_socket_carries_bytes_is_private_and_stops_cleanly() {
    // A short path: Unix socket paths are limited to about 100 bytes.
    let dir = tempfile::Builder::new()
        .prefix("rp")
        .tempdir_in("/tmp")
        .unwrap();
    let agent = dir.path().join("a.sock");
    fake_agent(&agent, b"from the service");
    std::fs::write(
        dir.path().join("config.toml"),
        format!("agent_socket = \"{}\"\n", agent.display()),
    )
    .unwrap();
    // The directory is made by `reach`, private; the socket file is for its owner alone.
    let reach_socket = dir.path().join("made-by-reach").join("r.sock");

    let mut reach = Guard(
        Command::new(env!("CARGO_BIN_EXE_menzil"))
            .args(["reach", "laptop/ssh", "--unix"])
            .arg(&reach_socket)
            .env("MENZIL_HOME", dir.path())
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let started = Instant::now();
    while !reach_socket.exists() {
        assert!(started.elapsed() < WAIT, "reach never made its socket");
        assert!(
            reach.0.try_wait().unwrap().is_none(),
            "reach ended before it made its socket"
        );
        thread::sleep(Duration::from_millis(20));
    }
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&reach_socket), 0o600);
    assert_eq!(mode(reach_socket.parent().unwrap()), 0o700);
    // A lock next to the socket says that a reach is running there; a second one is told so
    // without connecting to the first (the fifth red-team round, N2).
    let lock = dir.path().join("made-by-reach").join("r.sock.lock");
    assert!(lock.exists());
    let second = Command::new(env!("CARGO_BIN_EXE_menzil"))
        .args(["reach", "laptop/ssh", "--unix"])
        .arg(&reach_socket)
        .env("MENZIL_HOME", dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(1), "{second:?}");
    let message = String::from_utf8_lossy(&second.stderr);
    assert!(message.contains("already listening"), "{message}");
    assert!(
        reach_socket.exists() && lock.exists(),
        "the second one disturbed the first"
    );

    // A connection gets what the service sent, then end of file.
    let mut client = UnixStream::connect(&reach_socket).unwrap();
    client.set_read_timeout(Some(WAIT)).unwrap();
    client.write_all(b"request").unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut got = Vec::new();
    client.read_to_end(&mut got).unwrap();
    assert_eq!(got, b"from the service");

    // A stopping signal ends reach with status 0 and takes its socket file with it.
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(reach.0.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = reach.0.try_wait().unwrap() {
            break status;
        }
        assert!(started.elapsed() < WAIT, "reach did not stop");
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
    assert!(
        !reach_socket.exists(),
        "the socket file must be removed on the way out"
    );
    assert!(
        !lock.exists(),
        "the lock file must be removed on the way out"
    );
}

#[test]
fn a_tcp_address_and_a_unix_socket_together_are_refused() {
    let dir = tempfile::Builder::new()
        .prefix("rp")
        .tempdir_in("/tmp")
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_menzil"))
        .args(["reach", "laptop/ssh", "--unix"])
        .arg(dir.path().join("r.sock"))
        .args(["--listen", "127.0.0.1:2222"])
        .env("MENZIL_HOME", dir.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let message = String::from_utf8_lossy(&output.stderr);
    assert!(message.contains("cannot be used with"), "{message}");
    assert!(!dir.path().join("r.sock").exists());
}
