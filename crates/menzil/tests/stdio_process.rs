//! `menzil stdio` as a process, against a fake agent: what a ProxyCommand's parent sees on the
//! pipes. The third red-team round, M7 and L7: the stream's end has to be end of file on
//! standard output *while the process goes on carrying standard input* (a peer that finished
//! first may still be reading), a reset has to end the process at once whatever standard input
//! is doing, and a clean end of both has to end it at once too.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const WAIT: Duration = Duration::from_secs(20);
const DATA: u8 = 0;
const END: u8 = 1;
const RESET: u8 = 2;

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// What the fake agent sends after `ok`.
enum Script {
    /// Data, then an end; then it reads the client's frames and reports them.
    DataThenEnd(&'static [u8]),
    /// Data, then a reset.
    DataThenReset(&'static [u8]),
}

/// A fake agent on `socket`; the receiver gets the bytes the client sent, once its end came.
fn fake_agent(socket: &Path, send: Script) -> mpsc::Receiver<Vec<u8>> {
    let listener = UnixListener::bind(socket).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let (connection, _) = listener.accept().unwrap();
        let mut writer = connection.try_clone().unwrap();
        let mut reader = BufReader::new(connection);
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        assert!(request.starts_with("open "), "{request}");
        writer.write_all(b"ok\n").unwrap();
        match send {
            Script::DataThenEnd(bytes) => {
                writer.write_all(&frame(DATA, bytes)).unwrap();
                writer.write_all(&frame(END, b"")).unwrap();
            }
            Script::DataThenReset(bytes) => {
                writer.write_all(&frame(DATA, bytes)).unwrap();
                writer.write_all(&frame(RESET, b"boom \x1b[2J")).unwrap();
                // Hold the connection until the client has gone.
                let mut rest = Vec::new();
                let _ = reader.read_to_end(&mut rest);
                return;
            }
        }
        let mut all = Vec::new();
        loop {
            let mut header = [0u8; 5];
            if reader.read_exact(&mut header).is_err() {
                return;
            }
            let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
            let mut payload = vec![0u8; length as usize];
            if reader.read_exact(&mut payload).is_err() {
                return;
            }
            match header[0] {
                DATA => all.extend_from_slice(&payload),
                END => {
                    let _ = tx.send(all);
                    return;
                }
                _ => return,
            }
        }
    });
    rx
}

/// A `menzil stdio` process with the agent socket at `socket`.
fn spawn_stdio(home: &Path, socket: &Path) -> Child {
    std::fs::write(
        home.join("config.toml"),
        format!("agent_socket = \"{}\"\n", socket.display()),
    )
    .unwrap();
    Command::new(env!("CARGO_BIN_EXE_menzil"))
        .arg("stdio")
        .arg("peer/x")
        .env("MENZIL_HOME", home)
        .env("RUST_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Kills the process when the test ends one way or another.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reads `source` to its end on a thread, so that a missing end of file fails the test with a
/// timeout instead of hanging it.
fn read_to_end_on_a_thread(mut source: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut all = Vec::new();
        let _ = source.read_to_end(&mut all);
        let _ = tx.send(all);
    });
    rx
}

fn short_dir() -> tempfile::TempDir {
    // A Unix socket path is limited to about 100 bytes.
    tempfile::Builder::new()
        .prefix("mz")
        .tempdir_in("/tmp")
        .unwrap()
}

#[test]
fn a_service_that_ended_first_closes_standard_output_while_standard_input_is_carried_on() {
    let dir = short_dir();
    let socket = dir.path().join("a.sock");
    let from_client = fake_agent(&socket, Script::DataThenEnd(b"greet"));
    let mut child = Guard(spawn_stdio(dir.path(), &socket));
    let mut stdin = child.0.stdin.take().unwrap();
    let output = read_to_end_on_a_thread(child.0.stdout.take().unwrap());

    // The end reaches the program reading standard output, while the process is still alive.
    let got = output
        .recv_timeout(WAIT)
        .expect("standard output must reach end of file when the service ends");
    assert_eq!(got, b"greet");
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the process carries standard input on until it ends"
    );

    // Standard input still works, and its end ends the process, cleanly and at once.
    stdin.write_all(b"the rest of the upload").unwrap();
    drop(stdin);
    let sent = from_client
        .recv_timeout(WAIT)
        .expect("the agent gets the upload and its end");
    assert_eq!(sent, b"the rest of the upload");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(started.elapsed() < WAIT, "the process did not exit");
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
}

#[test]
fn a_reset_ends_the_process_at_once_with_status_1_whatever_standard_input_is_doing() {
    let dir = short_dir();
    let socket = dir.path().join("b.sock");
    let _from_client = fake_agent(&socket, Script::DataThenReset(b"partial"));
    let mut child = Guard(spawn_stdio(dir.path(), &socket));
    // Standard input stays open and silent: the process must not wait for it.
    let _stdin = child.0.stdin.take().unwrap();
    let output = read_to_end_on_a_thread(child.0.stdout.take().unwrap());
    let errors = read_to_end_on_a_thread(child.0.stderr.take().unwrap());

    let got = output
        .recv_timeout(WAIT)
        .expect("standard output ends when the process exits");
    assert_eq!(got, b"partial");
    let status = child.0.wait().unwrap();
    assert_eq!(status.code(), Some(1));
    let message = String::from_utf8_lossy(&errors.recv_timeout(WAIT).unwrap()).into_owned();
    assert!(
        message.contains("reset") && message.contains("boom"),
        "{message}"
    );
    assert!(
        !message.contains('\u{1b}'),
        "what the agent sent must not reach the terminal as an escape: {message:?}"
    );
}

/// The fourth red-team round, L4: with one socket for standard input and output (inetd,
/// systemd's `Accept=yes`, socat's EXEC), pointing descriptor 1 at `/dev/null` releases nothing
/// while descriptor 0 holds the socket, so the program on the other end never saw the service's
/// end (and a program that reads to end of file before it closes waits for ever). Pipes, which
/// ssh's ProxyCommand uses, were never affected.
#[test]
fn with_one_socket_for_input_and_output_the_services_end_reaches_the_program_on_it() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let dir = short_dir();
    let socket = dir.path().join("c.sock");
    let from_client = fake_agent(&socket, Script::DataThenEnd(b"answer"));
    std::fs::write(
        dir.path().join("config.toml"),
        format!("agent_socket = \"{}\"\n", socket.display()),
    )
    .unwrap();
    // Both descriptors are the same socket; the test keeps the other end.
    let (mine, theirs) = UnixStream::pair().unwrap();
    let for_stdin: OwnedFd = theirs.try_clone().unwrap().into();
    let for_stdout: OwnedFd = theirs.into();
    let mut child = Guard(
        Command::new(env!("CARGO_BIN_EXE_menzil"))
            .arg("stdio")
            .arg("peer/x")
            .env("MENZIL_HOME", dir.path())
            .env("RUST_LOG", "error")
            .stdin(Stdio::from(for_stdin))
            .stdout(Stdio::from(for_stdout))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut writer = mine.try_clone().unwrap();
    let output = read_to_end_on_a_thread(mine);

    let got = output
        .recv_timeout(WAIT)
        .expect("the service's end must reach the program that holds the other end of the socket");
    assert_eq!(got, b"answer");
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "the process carries standard input on until it ends"
    );

    // The program finishes sending; the process ends cleanly.
    writer.write_all(b"upload").unwrap();
    writer.shutdown(std::net::Shutdown::Write).unwrap();
    let sent = from_client
        .recv_timeout(WAIT)
        .expect("the agent gets the upload and its end");
    assert_eq!(sent, b"upload");
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(started.elapsed() < WAIT, "the process did not exit");
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
}
