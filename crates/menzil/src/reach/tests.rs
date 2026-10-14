//! `menzil reach` against a fake agent that says what a real one could: what a connection sees
//! at its end is the point (the third red-team round, M3: a reset used to arrive as a clean end
//! of file because the write half's drop sent a FIN first).

use std::io;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};
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
