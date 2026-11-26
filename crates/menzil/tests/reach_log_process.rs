//! What `menzil reach` writes to standard error: a connection that failed is named with its peer
//! and its target, and a local program that simply left (closed or reset its connection while
//! data was still under way) is no failure and gets no line.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reads to the end of what `reach` sends, which comes when it is done with the connection.
fn wait_for_the_end(mut reader: BufReader<UnixStream>) {
    let mut rest = Vec::new();
    let _ = reader.read_to_end(&mut rest);
}

/// A fake agent whose connections, in the order they come, are: one that is sent data for as long
/// as it takes it, one that is held open, one that is refused and one whose stream is reset. It
/// says when a connection is over.
fn fake_agent(socket: &Path, over: mpsc::Sender<()>) {
    let listener = UnixListener::bind(socket).unwrap();
    thread::spawn(move || {
        for (index, connection) in listener.incoming().enumerate() {
            let connection = connection.unwrap();
            let mut writer = connection.try_clone().unwrap();
            let mut reader = BufReader::new(connection);
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            match index {
                0 => {
                    writer.write_all(b"ok\n").unwrap();
                    let data = frame(0, &[7u8; 16 * 1024]);
                    while writer.write_all(&data).is_ok() {}
                }
                1 => {
                    writer.write_all(b"ok\n").unwrap();
                    wait_for_the_end(reader);
                }
                2 => {
                    writer.write_all(b"error no OPEN_ACK within 10s\n").unwrap();
                }
                _ => {
                    writer.write_all(b"ok\n").unwrap();
                    writer.write_all(&frame(2, b"boom")).unwrap();
                    wait_for_the_end(reader);
                }
            }
            let _ = over.send(());
        }
    });
}

#[test]
fn failures_are_named_and_a_local_program_that_left_is_not_one() {
    // A short path: Unix socket paths are limited to about 100 bytes.
    let dir = tempfile::Builder::new()
        .prefix("rl")
        .tempdir_in("/tmp")
        .unwrap();
    let agent = dir.path().join("a.sock");
    let (over_tx, over) = mpsc::channel();
    fake_agent(&agent, over_tx);
    std::fs::write(
        dir.path().join("config.toml"),
        format!("agent_socket = \"{}\"\n", agent.display()),
    )
    .unwrap();
    let mut reach = Guard(
        Command::new(env!("CARGO_BIN_EXE_menzil"))
            .args(["reach", "laptop/ssh", "--listen", "127.0.0.1:0"])
            .env("MENZIL_HOME", dir.path())
            .env("RUST_LOG", "error")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut errors = BufReader::new(reach.0.stderr.take().unwrap());
    let mut first = String::new();
    errors.read_line(&mut first).unwrap();
    let address = first
        .strip_prefix("carrying connections to ")
        .and_then(|rest| rest.split(' ').next())
        .unwrap_or_else(|| panic!("{first}"))
        .to_string();
    let connect = || {
        let client = TcpStream::connect(&address).unwrap();
        client.set_read_timeout(Some(WAIT)).unwrap();
        client
    };

    // Leaves in the middle of an answer.
    let mut client = connect();
    client.read_exact(&mut [0u8; 1024]).unwrap();
    drop(client);
    over.recv_timeout(WAIT).expect("the first connection ends");

    // Resets while nothing is under way.
    let client = connect();
    thread::sleep(Duration::from_millis(300));
    socket2::SockRef::from(&client)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(client);
    over.recv_timeout(WAIT).expect("the second connection ends");

    // Two that fail on the far side.
    let mut ports = Vec::new();
    for _ in 0..2 {
        let mut client = connect();
        ports.push(client.local_addr().unwrap());
        let _ = client.read_to_end(&mut Vec::new());
        over.recv_timeout(WAIT).expect("a failed connection ends");
    }

    // Time for a line about the first two, had there been one.
    thread::sleep(Duration::from_millis(500));
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(reach.0.id().to_string())
        .status()
        .unwrap();
    assert!(status.success());
    let started = Instant::now();
    while reach.0.try_wait().unwrap().is_none() {
        assert!(started.elapsed() < WAIT, "reach did not stop");
        thread::sleep(Duration::from_millis(20));
    }
    let mut rest = String::new();
    errors.read_to_string(&mut rest).unwrap();
    let lines: Vec<&str> = rest
        .lines()
        .filter(|line| !line.starts_with("stopping ("))
        .collect();
    assert_eq!(lines.len(), 2, "{rest}");
    for (line, (peer, why)) in lines
        .iter()
        .zip(ports.iter().zip(["no OPEN_ACK within 10s", "boom"]))
    {
        assert!(
            line.contains(&format!("from {peer} to laptop/ssh")),
            "{line}"
        );
        assert!(line.contains(why), "{line}");
    }
}
