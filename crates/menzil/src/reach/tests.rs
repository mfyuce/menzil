//! `menzil reach` against a fake agent that says what a real one could: what a connection sees
//! at its end is the point (the third red-team round, M3: a reset used to arrive as a clean end
//! of file because the write half's drop sent a FIN first).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::*;

const WAIT: Duration = Duration::from_secs(10);
const DATA: u8 = 0;
const END: u8 = 1;
const RESET: u8 = 2;

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// What the fake agent does with a connection once it has read the request line.
#[derive(Clone, Copy)]
enum Script {
    /// `error <message>`.
    Refuse(&'static str),
    /// `ok`, the bytes, then a reset.
    DataThenReset(&'static [u8]),
    /// `ok`, the bytes, an end; then the client's frames to their end.
    DataThenEnd(&'static [u8]),
    /// `ok`, this many bytes, an end; then the client's frames to their end.
    ManyBytesThenEnd(usize),
    /// `ok`, an end at once; then the client's frames to their end.
    EndThenRead,
    /// `ok`, then nothing: the stream stays open.
    Hold,
    /// `ok`, the bytes, then nothing: the stream stays open.
    DataThenHold(&'static [u8]),
}

struct Fake {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    /// What the client sent, once its end frame came.
    got: mpsc::UnboundedReceiver<Vec<u8>>,
}

async fn fake_agent(script: Script) -> Fake {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (got_tx, got) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((connection, _)) = listener.accept().await else {
                return;
            };
            let got_tx = got_tx.clone();
            tokio::spawn(async move {
                let (read, mut write) = connection.into_split();
                let mut read = BufReader::new(read);
                let mut request = String::new();
                if read.read_line(&mut request).await.is_err() {
                    return;
                }
                match script {
                    Script::Refuse(message) => {
                        let _ = write
                            .write_all(format!("error {message}\n").as_bytes())
                            .await;
                        return;
                    }
                    Script::DataThenReset(bytes) => {
                        let _ = write.write_all(b"ok\n").await;
                        let _ = write.write_all(&frame(DATA, bytes)).await;
                        let _ = write.write_all(&frame(RESET, b"boom")).await;
                        let _ = write.flush().await;
                        // Stay until the client has gone: a closed connection is not the point.
                        let mut sink = Vec::new();
                        let _ = read.read_to_end(&mut sink).await;
                        return;
                    }
                    Script::DataThenEnd(bytes) => {
                        let _ = write.write_all(b"ok\n").await;
                        let _ = write.write_all(&frame(DATA, bytes)).await;
                        let _ = write.write_all(&frame(END, b"")).await;
                    }
                    Script::ManyBytesThenEnd(length) => {
                        let _ = write.write_all(b"ok\n").await;
                        let chunk = vec![5u8; 16 * 1024];
                        let mut left = length;
                        while left > 0 {
                            let n = left.min(chunk.len());
                            let _ = write.write_all(&frame(DATA, &chunk[..n])).await;
                            left -= n;
                        }
                        let _ = write.write_all(&frame(END, b"")).await;
                    }
                    Script::EndThenRead => {
                        let _ = write.write_all(b"ok\n").await;
                        let _ = write.write_all(&frame(END, b"")).await;
                    }
                    Script::Hold => {
                        let _ = write.write_all(b"ok\n").await;
                        let mut sink = Vec::new();
                        let _ = read.read_to_end(&mut sink).await;
                        return;
                    }
                    Script::DataThenHold(bytes) => {
                        let _ = write.write_all(b"ok\n").await;
                        let _ = write.write_all(&frame(DATA, bytes)).await;
                        let _ = write.flush().await;
                        let mut sink = Vec::new();
                        let _ = read.read_to_end(&mut sink).await;
                        return;
                    }
                }
                // The client's frames to their end.
                let mut all = Vec::new();
                loop {
                    let mut header = [0u8; 5];
                    if read.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
                    let mut payload = vec![0u8; length as usize];
                    if read.read_exact(&mut payload).await.is_err() {
                        return;
                    }
                    match header[0] {
                        DATA => all.extend_from_slice(&payload),
                        END => {
                            let _ = got_tx.send(all);
                            return;
                        }
                        _ => return,
                    }
                }
            });
        }
    });
    Fake {
        _dir: dir,
        socket,
        got,
    }
}

/// `menzil reach` on an ephemeral port, to `socket`; the sender stops it.
async fn start(
    socket: &std::path::Path,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    JoinHandle<Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    let socket = socket.to_path_buf();
    let task = tokio::spawn(async move {
        run(&socket, "peer/x", listener, async {
            let _ = stop_rx.await;
        })
        .await
    });
    (addr, stop_tx, task)
}

/// Reads the connection to its end: what came, and how it ended.
async fn read_to_the_end(client: &mut TcpStream) -> (Vec<u8>, io::Result<usize>) {
    let mut got = Vec::new();
    let ended = timeout(WAIT, client.read_to_end(&mut got))
        .await
        .expect("the connection must end");
    (got, ended)
}

#[tokio::test]
async fn a_reset_stream_resets_the_connection_after_the_data_that_came() {
    let fake = fake_agent(Script::DataThenReset(b"partial-response")).await;
    let (addr, _stop, _task) = start(&fake.socket).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (got, ended) = read_to_the_end(&mut client).await;
    let error = ended.expect_err("a reset stream must not end as a clean end of file");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(got, b"partial-response");
}

#[tokio::test]
async fn a_refusal_resets_the_connection() {
    let fake = fake_agent(Script::Refuse("no_grant")).await;
    let (addr, _stop, _task) = start(&fake.socket).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (got, ended) = read_to_the_end(&mut client).await;
    assert!(got.is_empty());
    let error = ended.expect_err("a refused connection is not an empty clean one");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn no_agent_resets_the_connection() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("none.sock");
    let (addr, _stop, _task) = start(&missing).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let (got, ended) = read_to_the_end(&mut client).await;
    assert!(got.is_empty());
    let error = ended.expect_err("no agent is not an empty clean connection");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn a_stream_that_ended_cleanly_both_ways_closes_the_connection_cleanly() {
    let mut fake = fake_agent(Script::DataThenEnd(b"hello")).await;
    let (addr, _stop, _task) = start(&fake.socket).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    let (got, ended) = read_to_the_end(&mut client).await;
    ended.expect("a clean end reads as end of file");
    assert_eq!(got, b"hello");
    let sent = timeout(WAIT, fake.got.recv()).await.unwrap().unwrap();
    assert_eq!(sent, b"request");
}

/// The third red-team round, M7: the service finished first; the connection's program may still
/// be sending, and all of it must arrive.
#[tokio::test]
async fn a_service_that_ended_first_does_not_cut_off_what_the_client_still_sends() {
    let mut fake = fake_agent(Script::EndThenRead).await;
    let (addr, _stop, _task) = start(&fake.socket).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    // Its end reaches the program as end of file while it can still write.
    let (got, ended) = read_to_the_end(&mut client).await;
    ended.expect("the service ended cleanly");
    assert!(got.is_empty());
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.write_all(&[7u8; 1000]).await.unwrap();
    client.shutdown().await.unwrap();
    let sent = timeout(WAIT, fake.got.recv()).await.unwrap().unwrap();
    assert_eq!(sent, vec![7u8; 1000]);
}

/// A stop (SIGINT, SIGTERM, SIGHUP all end up here) must not close what is open as if it had
/// finished.
#[tokio::test]
async fn stopping_resets_the_connections_that_are_open() {
    let fake = fake_agent(Script::Hold).await;
    let (addr, stop, task) = start(&fake.socket).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    // Let the connection get as far as an open stream.
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop.send(()).unwrap();
    let (_, ended) = read_to_the_end(&mut client).await;
    let error = ended.expect_err("an interrupted connection is not a finished one");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
}

/// A clean end must not throw away what the client has not read yet. The client here has a small
/// receive buffer, finishes sending at once and reads nothing for a while; the service sends more
/// than that buffer takes, so part of it is still queued in the kernel when the bridge is over. A
/// reset at that point (a linger of zero on a socket that still holds unsent data and a FIN)
/// would discard that part and send an RST; a plain close delivers it, then the end of file.
#[tokio::test]
async fn a_clean_end_does_not_discard_what_the_client_has_not_read_yet() {
    const SIZE: usize = 512 * 1024;
    let fake = fake_agent(Script::ManyBytesThenEnd(SIZE)).await;
    let (addr, _stop, _task) = start(&fake.socket).await;
    // The buffer is set before the connect, so that the window it opens with stays small.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(16 * 1024).unwrap();
    let mut client = socket.connect(addr).await.unwrap();
    client.shutdown().await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    let (got, ended) = read_to_the_end(&mut client).await;
    ended.expect("a clean end reads as end of file, after all the data");
    assert_eq!(got.len(), SIZE);
    assert!(got.iter().all(|&b| b == 5));
}

/// A listener whose `accept` fails on chosen calls, as the real one does when the process is out
/// of descriptors.
struct Flaky {
    inner: TcpListener,
    calls: AtomicUsize,
    /// The calls, counted from 1, that fail.
    failing: &'static [usize],
}

impl Accept for Flaky {
    type Connection = TcpStream;

    async fn accept(&self) -> io::Result<(TcpStream, String)> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.failing.contains(&call) {
            // EMFILE on Linux and macOS alike.
            return Err(io::Error::from_raw_os_error(24));
        }
        Accept::accept(&self.inner).await
    }
}

/// The fourth red-team round, M1: an `accept` that failed ended `run`, and the connections in
/// flight were dropped without their reset, so each read a clean end of file after a truncated
/// answer. A failed `accept` is now reported and tried again; what is open is not touched.
#[tokio::test]
async fn a_failed_accept_neither_ends_reach_nor_cuts_the_connections_in_flight() {
    let fake = fake_agent(Script::DataThenHold(b"partial-answer")).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // The second call to accept fails, right after the first connection was taken.
    let flaky = Flaky {
        inner: listener,
        calls: AtomicUsize::new(0),
        failing: &[2],
    };
    let (stop_tx, stop_rx) = oneshot::channel();
    let socket = fake.socket.clone();
    let task = tokio::spawn(async move {
        run_on(&socket, "peer/x", flaky, async {
            let _ = stop_rx.await;
        })
        .await
    });
    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut got = [0u8; 14];
    timeout(WAIT, first.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"partial-answer");
    // The connection stays open while accept recovers: not a byte, and not an end of file.
    let mut byte = [0u8; 1];
    assert!(
        timeout(Duration::from_millis(600), first.read(&mut byte))
            .await
            .is_err(),
        "the connection in flight was ended by the failed accept"
    );
    assert!(!task.is_finished(), "a failed accept ended run");
    // A connection made after the failure is served.
    let mut second = TcpStream::connect(addr).await.unwrap();
    timeout(WAIT, second.read_exact(&mut got))
        .await
        .expect("the second connection must be carried")
        .unwrap();
    assert_eq!(&got, b"partial-answer");
    // A stop still resets what is open.
    stop_tx.send(()).unwrap();
    let (_, ended) = read_to_the_end(&mut first).await;
    let error = ended.expect_err("a stopped connection is not a finished one");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
}

/// Whatever ends `run` without going through its stop (here a task aborted; a panic or the
/// process being killed close the sockets the same way), a connection in flight is reset, never
/// closed as if it had finished: the reset is the state it is accepted in.
#[tokio::test]
async fn an_aborted_reach_resets_the_connections_that_are_open() {
    let fake = fake_agent(Script::DataThenHold(b"partial-answer")).await;
    let (addr, _stop, task) = start(&fake.socket).await;
    let mut client = TcpStream::connect(addr).await.unwrap();
    let mut got = [0u8; 14];
    timeout(WAIT, client.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    task.abort();
    let (_, ended) = read_to_the_end(&mut client).await;
    let error = ended.expect_err("an aborted reach must not leave a clean end of file");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
}

/// `menzil reach --unix` on a socket in a fresh private directory, to `socket`; the sender stops
/// it. The directory is kept alive by the first element.
async fn start_unix(
    socket: &std::path::Path,
) -> (
    tempfile::TempDir,
    PathBuf,
    oneshot::Sender<()>,
    JoinHandle<Result<()>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reach.sock");
    let bound = bind_unix(&path).await.unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    let socket = socket.to_path_buf();
    let task = tokio::spawn(async move {
        run_unix(&socket, "peer/x", bound, async {
            let _ = stop_rx.await;
        })
        .await
    });
    (dir, path, stop_tx, task)
}

/// Reads a Unix connection to its end: what came, and how it ended.
async fn read_unix_to_the_end(client: &mut UnixStream) -> (Vec<u8>, io::Result<usize>) {
    let mut got = Vec::new();
    let ended = timeout(WAIT, client.read_to_end(&mut got))
        .await
        .expect("the connection must end");
    (got, ended)
}

#[tokio::test]
async fn a_unix_socket_carries_the_bytes_both_ways_and_ends_cleanly() {
    let mut fake = fake_agent(Script::DataThenEnd(b"hello")).await;
    let (_dir, path, _stop, _task) = start_unix(&fake.socket).await;
    let mut client = UnixStream::connect(&path).await.unwrap();
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();
    let (got, ended) = read_unix_to_the_end(&mut client).await;
    ended.expect("a clean end reads as end of file");
    assert_eq!(got, b"hello");
    let sent = timeout(WAIT, fake.got.recv()).await.unwrap().unwrap();
    assert_eq!(sent, b"request");
}

/// A service that finishes first does not cut off what the program on the socket still sends
/// (the third round's M7, on a Unix socket).
#[tokio::test]
async fn a_unix_connection_still_sends_after_the_service_ended() {
    let mut fake = fake_agent(Script::EndThenRead).await;
    let (_dir, path, _stop, _task) = start_unix(&fake.socket).await;
    let mut client = UnixStream::connect(&path).await.unwrap();
    let (got, ended) = read_unix_to_the_end(&mut client).await;
    ended.expect("the service ended cleanly");
    assert!(got.is_empty());
    tokio::time::sleep(Duration::from_millis(200)).await;
    client.write_all(&[7u8; 1000]).await.unwrap();
    client.shutdown().await.unwrap();
    let sent = timeout(WAIT, fake.got.recv()).await.unwrap().unwrap();
    assert_eq!(sent, vec![7u8; 1000]);
}

/// What the documentation says a Unix socket cannot be relied on to do: show a reset. The data
/// that came is delivered and then a program that sent nothing the end of this connection left
/// unread reads end of file, as for a clean end. If this ever fails because the program is told
/// something, the documentation (`--help`, the module documentation, protocol.md 12, TOBEDECIDED
/// 15) has to change with it.
#[tokio::test]
async fn a_reset_stream_ends_a_unix_connection_as_end_of_file() {
    let fake = fake_agent(Script::DataThenReset(b"partial-response")).await;
    let (_dir, path, _stop, _task) = start_unix(&fake.socket).await;
    let mut client = UnixStream::connect(&path).await.unwrap();
    let (got, ended) = read_unix_to_the_end(&mut client).await;
    ended.expect("a Unix socket has no reset to show");
    assert_eq!(got, b"partial-response");
}

#[tokio::test]
async fn a_refusal_ends_a_unix_connection_and_reach_goes_on() {
    let fake = fake_agent(Script::Refuse("no_grant")).await;
    let (_dir, path, _stop, task) = start_unix(&fake.socket).await;
    for _ in 0..2 {
        let mut client = UnixStream::connect(&path).await.unwrap();
        let (got, ended) = read_unix_to_the_end(&mut client).await;
        assert!(got.is_empty());
        ended.expect("end of file");
    }
    assert!(!task.is_finished());
}

#[cfg(unix)]
#[tokio::test]
async fn the_reach_socket_is_private_and_goes_away_when_reach_stops() {
    use std::os::unix::fs::PermissionsExt;
    let fake = fake_agent(Script::Hold).await;
    let base = tempfile::tempdir().unwrap();
    // A directory this creates is private; the socket is for its owner alone.
    let path = base.path().join("made-for-reach").join("reach.sock");
    let bound = bind_unix(&path).await.unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
    let lock = lock_path(&path);
    assert!(
        lock.exists(),
        "the lock file is next to the socket while it runs"
    );
    let (stop_tx, stop_rx) = oneshot::channel();
    let socket = fake.socket.clone();
    let task = tokio::spawn(async move {
        run_unix(&socket, "peer/x", bound, async {
            let _ = stop_rx.await;
        })
        .await
    });
    let mut client = UnixStream::connect(&path).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop_tx.send(()).unwrap();
    let (_, ended) = read_unix_to_the_end(&mut client).await;
    ended.expect("a stop ends the connection");
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    assert!(!path.exists(), "the socket file stays behind after a stop");
    assert!(!lock.exists(), "the lock file stays behind after a stop");
}

#[tokio::test]
async fn a_live_reach_socket_is_neither_taken_over_nor_asked_and_a_stale_one_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reach.sock");
    let mut first = bind_unix(&path).await.unwrap();
    let error = format!("{:#}", bind_unix(&path).await.err().unwrap());
    assert!(
        error.contains("another `menzil reach` is already listening"),
        "{error}"
    );
    // The fifth red-team round, N2: finding that out must not have connected to the live one
    // (it would carry the connection to its service).
    let listener = first.listener.take().unwrap();
    assert!(
        timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "the second reach connected to the first to see whether it was alive"
    );
    // Ending the first removes the socket and its lock.
    drop(first);
    drop(listener);
    assert!(!path.exists() && !lock_path(&path).exists());
    // What a reach that was killed leaves behind: a socket file nobody listens on, no lock held.
    drop(UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    let second = bind_unix(&path).await.unwrap();
    assert!(second.path().exists());
}

#[tokio::test]
async fn a_reach_socket_path_too_long_for_unix_names_the_option() {
    let long = PathBuf::from(format!("/tmp/{}/reach.sock", "d".repeat(120)));
    let error = format!("{:#}", bind_unix(&long).await.err().unwrap());
    assert!(
        error.contains("the reach socket path is") && error.contains("`--unix`"),
        "{error}"
    );
    assert!(!error.contains("agent_socket"), "{error}");
}

/// The uid of whoever connects is checked again on accept (the socket's mode and directory are
/// the first guard): a process of another user is closed without being carried or answered.
#[tokio::test]
async fn a_unix_connection_of_another_user_is_closed_unanswered() {
    let me = agent::current_uid().await.unwrap();
    for (uid, carried) in [(me, true), (me.wrapping_add(1), false)] {
        let fake = fake_agent(Script::Hold).await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reach.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (stop_tx, stop_rx) = oneshot::channel();
        let socket = fake.socket.clone();
        let task = tokio::spawn(async move {
            run_on(&socket, "peer/x", UserSocket { listener, uid }, async {
                let _ = stop_rx.await;
            })
            .await
        });
        let mut client = UnixStream::connect(&path).await.unwrap();
        let mut byte = [0u8; 1];
        let read = timeout(Duration::from_millis(800), client.read(&mut byte)).await;
        if carried {
            assert!(read.is_err(), "a connection of this user must stay open");
        } else {
            assert_eq!(
                read.expect("a connection of another user must be closed")
                    .unwrap(),
                0
            );
        }
        stop_tx.send(()).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    }
}

/// The fifth red-team round, M1, at the end of a run: when `reach` stops, the path to its socket
/// leads somewhere else (a link in it was pointed elsewhere, where a program of its own has a
/// socket and a lock of the same names). Removing by name deleted those; `reach` now removes only
/// the files it made.
#[cfg(unix)]
#[tokio::test]
async fn a_reach_that_stops_leaves_alone_what_its_path_names_by_then() {
    let fake = fake_agent(Script::Hold).await;
    let base = tempfile::tempdir().unwrap();
    let (real, other) = (base.path().join("real"), base.path().join("other"));
    fs::create_dir(&real).unwrap();
    fs::create_dir(&other).unwrap();
    let via = base.path().join("via");
    std::os::unix::fs::symlink("real", &via).unwrap();
    let path = via.join("reach.sock");
    let bound = bind_unix(&path).await.unwrap();
    let (stop_tx, stop_rx) = oneshot::channel();
    let socket = fake.socket.clone();
    let task = tokio::spawn(async move {
        run_unix(&socket, "peer/x", bound, async {
            let _ = stop_rx.await;
        })
        .await
    });
    // The path now leads to a directory with a socket and a lock of the same names.
    fs::remove_file(&via).unwrap();
    std::os::unix::fs::symlink("other", &via).unwrap();
    let theirs = UnixListener::bind(other.join("reach.sock")).unwrap();
    fs::write(other.join("reach.sock.lock"), b"theirs").unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop_tx.send(()).unwrap();
    timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    assert!(
        other.join("reach.sock").exists(),
        "reach removed a socket it did not make"
    );
    assert_eq!(fs::read(other.join("reach.sock.lock")).unwrap(), b"theirs");
    drop(theirs);
}

/// The same checks as the agent's reach `--unix` too: a path through a directory that others can
/// write to is refused, and nothing is made in it.
#[cfg(unix)]
#[tokio::test]
async fn a_reach_socket_below_a_directory_others_can_write_to_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let open = base.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
    let path = open.join("below").join("reach.sock");
    let error = format!("{:#}", bind_unix(&path).await.err().unwrap());
    assert!(error.contains("can be written by other users"), "{error}");
    assert!(!open.join("below").exists());
}
