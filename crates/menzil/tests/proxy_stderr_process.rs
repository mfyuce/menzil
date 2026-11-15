//! `menzil proxy` as a process: whatever a client sends in a `Proxy-Authorization` header must
//! never reach the proxy's standard error. The proxy's log lines are `eprintln!` calls, which a
//! tracing capture cannot see, so this runs the real binary against a fake agent and reads its
//! whole standard error. The cases: an accepted CONNECT, a CONNECT the exit refuses, a malformed
//! head and a plain GET, each carrying the header.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);
const SECRET: &str = "hunter2-s3cr3t-Zk9qLp";
const END: u8 = 1;

/// A fake agent: a `connect` for a host starting with `ok.` is answered `ok` (and the stream is
/// ended at once), any other is answered with an exit's refusal.
fn fake_agent(socket: &Path) {
    let listener = UnixListener::bind(socket).unwrap();
    thread::spawn(move || {
        for connection in listener.incoming() {
            let Ok(connection) = connection else { return };
            thread::spawn(move || {
                let mut writer = connection.try_clone().unwrap();
                let mut reader = BufReader::new(connection);
                let mut request = String::new();
                if reader.read_line(&mut request).is_err() {
                    return;
                }
                let host = request.split(' ').nth(2).unwrap_or("");
                if host.starts_with("ok.") {
                    let _ = writer.write_all(b"ok\n");
                    let _ = writer.write_all(&[END, 0, 0, 0, 0]);
                    let mut rest = Vec::new();
                    let _ = reader.read_to_end(&mut rest);
                } else {
                    let _ = writer.write_all(b"error refused by the other end: forbidden\n");
                }
            });
        }
    });
}

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Sends `request`, then reads the reply until the proxy closes or `limit` bytes or a pause.
fn exchange(address: &str, request: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut got = Vec::new();
    let mut buffer = [0u8; 1024];
    while let Ok(n) = stream.read(&mut buffer) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buffer[..n]);
        if got.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    got
}

#[test]
fn the_proxy_never_writes_a_proxy_authorization_value_to_standard_error() {
    use base64::Engine as _;
    let dir = tempfile::Builder::new()
        .prefix("mz")
        .tempdir_in("/tmp")
        .unwrap();
    let socket = dir.path().join("a.sock");
    std::fs::write(
        dir.path().join("config.toml"),
        format!("agent_socket = \"{}\"\n", socket.display()),
    )
    .unwrap();
    fake_agent(&socket);

    let mut child = Guard(
        Command::new(env!("CARGO_BIN_EXE_menzil"))
            .args(["proxy", "peer/x", "--listen", "127.0.0.1:0"])
            .env("MENZIL_HOME", dir.path())
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = child.0.stderr.take().unwrap();
    let log = Arc::new(Mutex::new(String::new()));
    let (first_tx, first_rx) = std::sync::mpsc::channel();
    let reader = {
        let log = log.clone();
        thread::spawn(move || {
            let mut lines = BufReader::new(stderr);
            let mut line = String::new();
            let mut first = Some(first_tx);
            while let Ok(n) = lines.read_line(&mut line) {
                if n == 0 {
                    break;
                }
                if let Some(tx) = first.take() {
                    let _ = tx.send(line.clone());
                }
                log.lock().unwrap().push_str(&line);
                line.clear();
            }
        })
    };
    let banner = first_rx
        .recv_timeout(WAIT)
        .expect("the proxy says where it listens");
    let address = banner
        .split(" on ")
        .nth(1)
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_else(|| panic!("no address in {banner:?}"))
        .to_string();

    let basic = base64::engine::general_purpose::STANDARD.encode(format!("user:{SECRET}"));
    let header = format!("Proxy-Authorization: Basic {basic}\r\n");

    // (a) accepted: the agent says ok.
    let reply = exchange(
        &address,
        format!("CONNECT ok.example:443 HTTP/1.1\r\nHost: ok.example:443\r\n{header}\r\n")
            .as_bytes(),
    );
    assert!(
        String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200"),
        "{reply:?}"
    );
    // (b) refused by the exit.
    let reply = exchange(
        &address,
        format!("CONNECT denied.example:443 HTTP/1.1\r\nHost: denied.example:443\r\n{header}\r\n")
            .as_bytes(),
    );
    assert!(
        !String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 200"),
        "{reply:?}"
    );
    // (c) a malformed head that contains the header.
    let _ = exchange(
        &address,
        format!("CONNECT denied.example:443 HTTP/1.1\r\n{header}no colon on this line\r\n\r\n")
            .as_bytes(),
    );
    let _ = exchange(
        &address,
        format!("CONNECT :::bad target HTTP/9\r\n{header}\r\n").as_bytes(),
    );
    // (d) a plain GET.
    let reply = exchange(
        &address,
        format!("GET http://denied.example/ HTTP/1.1\r\nHost: denied.example\r\n{header}\r\n")
            .as_bytes(),
    );
    assert!(String::from_utf8_lossy(&reply).contains("405"), "{reply:?}");

    // Wait until the refusals have been logged, then end the process and read all of it.
    let started = Instant::now();
    while !log.lock().unwrap().contains("refused a connection") {
        assert!(
            started.elapsed() < WAIT,
            "no refusal line was logged: {:?}",
            log.lock().unwrap()
        );
        thread::sleep(Duration::from_millis(50));
    }
    thread::sleep(Duration::from_millis(300));
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    reader.join().unwrap();

    let all = log.lock().unwrap().clone();
    assert!(
        all.contains("menzil proxy:"),
        "stderr was not captured: {all:?}"
    );
    assert!(
        all.contains("failed"),
        "the exit's refusal was not logged: {all:?}"
    );
    assert!(!all.contains(SECRET), "the secret reached stderr: {all}");
    assert!(
        !all.contains(&basic),
        "the base64 value reached stderr: {all}"
    );
    assert!(
        !all.to_ascii_lowercase().contains("proxy-authorization"),
        "the header reached stderr: {all}"
    );
}
