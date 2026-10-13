use std::io;
use std::sync::Mutex;

use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use menzil_stream::{Inbound, Mode, OutboundFrames, StreamMux};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::sync::mpsc;

use super::*;

const WAIT: Duration = Duration::from_secs(10);

async fn pump(mut from: OutboundFrames, to: StreamMux) {
    while let Some(frame) = from.next_frame().await {
        if to.feed_inbound(frame).is_err() {
            return;
        }
    }
}

/// How a remote stream handler saw its stream end.
type Seen = Result<usize, io::ErrorKind>;

/// The remote end of the streams the agent opens: the first byte of a stream says how it
/// behaves.
///
/// * `e` echoes until the end of file and closes;
/// * `r` reads one byte, writes `partial` and resets the stream;
/// * `h` reads to the end of file, writes `got N` and closes;
/// * `w` reads to the end and reports how that ended, so a test can see a reset.
async fn remote(mut inbound: Inbound, seen: mpsc::UnboundedSender<Seen>) {
    while let Some(mut stream) = inbound.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut behavior = [0u8; 1];
            if stream.read_exact(&mut behavior).await.is_err() {
                return;
            }
            match behavior[0] {
                b'e' => {
                    let mut buffer = [0u8; 4096];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buffer[..n]).await.is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let _ = stream.close().await;
                }
                b'r' => {
                    let mut one = [0u8; 1];
                    let _ = stream.read_exact(&mut one).await;
                    let _ = stream.write_all(b"partial").await;
                    let _ = stream.flush().await;
                    stream.reset();
                }
                b'h' => {
                    let mut all = Vec::new();
                    if stream.read_to_end(&mut all).await.is_ok() {
                        let _ = stream
                            .write_all(format!("got {}", all.len()).as_bytes())
                            .await;
                        let _ = stream.close().await;
                    }
                }
                b's' => {
                    // Reads to the end of the client's side, then keeps sending until a write
                    // fails: it learns the client is gone only if the agent resets the stream.
                    let mut all = Vec::new();
                    if stream.read_to_end(&mut all).await.is_err() {
                        return;
                    }
                    let outcome = loop {
                        if let Err(error) = stream.write_all(&[1u8; 8 * 1024]).await {
                            break Err(error.kind());
                        }
                        if let Err(error) = stream.flush().await {
                            break Err(error.kind());
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    };
                    let _ = seen.send(outcome.map(|()| 0));
                }
                b'w' => {
                    let mut all = Vec::new();
                    let ended = stream.read_to_end(&mut all).await;
                    let _ = seen.send(ended.map_err(|e| e.kind()));
                }
                _ => {}
            }
        });
    }
}

/// Opens streams on the client side of an in-memory connection; `who` picks the behavior.
struct TestOpener {
    mux: StreamMux,
}

impl Opener for TestOpener {
    async fn open(&self, target: &str) -> Result<Stream, String> {
        let (who, behavior) = target.split_once('/').ok_or("not who/service")?;
        match who {
            "refuse" => return Err("no member called refuse".to_string()),
            "garbled" => return Err("bad\nname \u{1b}[31mred".to_string()),
            _ => {}
        }
        let mut stream = self.mux.open().await.map_err(|e| e.to_string())?;
        stream
            .write_all(behavior.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        Ok(stream)
    }
}

struct Rig {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    seen: mpsc::UnboundedReceiver<Seen>,
    agent: tokio::task::JoinHandle<()>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.agent.abort();
    }
}

fn rig() -> Rig {
    let (client_mux, _client_inbound, client_out, client_driver) =
        menzil_stream::new(Mode::Client, 65_535);
    let (server_mux, server_inbound, server_out, server_driver) =
        menzil_stream::new(Mode::Server, 65_535);
    tokio::spawn(client_driver);
    tokio::spawn(server_driver);
    tokio::spawn(pump(client_out, server_mux.clone()));
    tokio::spawn(pump(server_out, client_mux.clone()));
    let (seen_tx, seen) = mpsc::unbounded_channel();
    tokio::spawn(remote(server_inbound, seen_tx));

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let agent = tokio::spawn(serve(listener, Arc::new(TestOpener { mux: client_mux })));
    Rig {
        _dir: dir,
        socket,
        seen,
        agent,
    }
}

/// Runs the client with `input` as stdin and returns what came out and how it ended.
async fn run_client(rig: &Rig, target: &str, input: &[u8]) -> Result<(Vec<u8>, End)> {
    let (mut feed, stdin) = duplex(64 * 1024);
    let (stdout, mut collect) = duplex(1 << 20);
    let input = input.to_vec();
    tokio::spawn(async move {
        let _ = feed.write_all(&input).await;
        let _ = feed.shutdown().await;
    });
    let end = timeout(WAIT, connect_and_bridge(&rig.socket, target, stdin, stdout))
        .await
        .expect("the client must finish")?;
    let mut output = Vec::new();
    collect.read_to_end(&mut output).await.unwrap();
    Ok((output, end))
}

#[test]
fn a_request_is_one_open_line_of_printable_characters() {
    assert_eq!(parse_request("open laptop/ssh\n"), Ok("laptop/ssh"));
    assert_eq!(
        parse_request("open laptop/tcp:ssh\r\n"),
        Ok("laptop/tcp:ssh")
    );
    assert_eq!(parse_request("open a/b"), Ok("a/b"));
    let long = format!("open {}\n", "a".repeat(257));
    for bad in [
        "",
        "\n",
        "hello\n",
        "open\n",
        "open \n",
        "open a b\n",
        "open a\tb\n",
        "open a\u{1b}[31m\n",
        "OPEN a/b\n",
        " open a/b\n",
        long.as_str(),
    ] {
        assert!(parse_request(bad).is_err(), "{bad:?}");
    }
    assert!(parse_request(&format!("open {}\n", "a".repeat(256))).is_ok());
}

#[tokio::test]
async fn bytes_flow_both_ways_and_a_clean_close_is_a_clean_end() {
    let rig = rig();
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let (output, end) = run_client(&rig, "peer/e", &data).await.unwrap();
    assert_eq!(end, End::Clean);
    assert_eq!(output, data);
}

#[tokio::test]
async fn a_half_closed_request_still_gets_its_whole_response() {
    let rig = rig();
    let (output, end) = run_client(&rig, "peer/h", b"abcdef").await.unwrap();
    assert_eq!(output, b"got 6");
    assert_eq!(end, End::Clean);
}

#[tokio::test]
async fn a_reset_stream_reaches_the_client_as_a_reset_after_what_arrived() {
    let rig = rig();
    let (output, end) = run_client(&rig, "peer/r", b"x").await.unwrap();
    assert_eq!(output, b"partial");
    match end {
        End::Reset(message) => assert!(message.contains("reset"), "{message}"),
        End::Clean => panic!("a reset stream must not read as a clean end"),
    }
}

#[tokio::test]
async fn what_the_opener_says_is_one_clean_line() {
    let rig = rig();
    let error = run_client(&rig, "refuse/e", b"").await.unwrap_err();
    assert_eq!(error.to_string(), "no member called refuse");
    let error = run_client(&rig, "garbled/e", b"")
        .await
        .unwrap_err()
        .to_string();
    assert!(
        !error.contains('\n') && !error.contains('\u{1b}'),
        "{error:?}"
    );
    assert!(error.starts_with("bad name"), "{error:?}");
}

#[tokio::test]
async fn a_bad_request_is_answered_and_a_silent_client_is_not_waited_for_forever() {
    let rig = rig();
    for line in ["hello\n", "open a b\n", "open \n"] {
        let mut connection = UnixStream::connect(&rig.socket).await.unwrap();
        connection.write_all(line.as_bytes()).await.unwrap();
        let mut reply = String::new();
        BufReader::new(&mut connection)
            .read_line(&mut reply)
            .await
            .unwrap();
        assert!(reply.starts_with("error "), "{line:?}: {reply:?}");
    }
    // An over-long line gets no answer, only a closed connection.
    let mut connection = UnixStream::connect(&rig.socket).await.unwrap();
    connection.write_all(&vec![b'a'; 2000]).await.unwrap();
    let mut rest = Vec::new();
    timeout(WAIT, connection.read_to_end(&mut rest))
        .await
        .unwrap()
        .ok();
    assert!(rest.is_empty());
}

/// Asks for a stream behaving as `behavior` and returns the raw connection, past the `ok`.
async fn raw_client(rig: &Rig, behavior: &str) -> UnixStream {
    let mut connection = UnixStream::connect(&rig.socket).await.unwrap();
    connection
        .write_all(format!("open peer/{behavior}\n").as_bytes())
        .await
        .unwrap();
    let mut reply = [0u8; 3];
    connection.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok\n");
    connection
}

async fn send_frame(connection: &mut UnixStream, kind: u8, payload: &[u8]) {
    write_frame(connection, kind, payload).await.unwrap();
}

/// The distinction the framing exists for: the same silence on the socket, a closed connection,
/// is a clean end after an end frame and a reset without one.
#[tokio::test]
async fn a_client_that_vanishes_resets_the_stream_and_one_that_says_it_is_done_does_not() {
    let mut rig = rig();

    // Sent its bytes, then closed with no end frame: the program died.
    let mut connection = raw_client(&rig, "w").await;
    send_frame(&mut connection, FRAME_DATA, b"some bytes").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(connection);
    let seen = timeout(WAIT, rig.seen.recv()).await.unwrap().unwrap();
    assert_eq!(
        seen,
        Err(io::ErrorKind::ConnectionReset),
        "a vanished client is a reset"
    );

    // The same bytes and then an end frame: finished, and the remote reads a clean end.
    let mut connection = raw_client(&rig, "w").await;
    send_frame(&mut connection, FRAME_DATA, b"some bytes").await;
    send_frame(&mut connection, FRAME_END, &[]).await;
    drop(connection);
    let seen = timeout(WAIT, rig.seen.recv()).await.unwrap().unwrap();
    assert_eq!(seen, Ok(10), "an end frame is a clean end of file");

    // An explicit reset is a reset.
    let mut connection = raw_client(&rig, "w").await;
    send_frame(&mut connection, FRAME_DATA, b"abc").await;
    send_frame(&mut connection, FRAME_RESET, b"changed my mind").await;
    let seen = timeout(WAIT, rig.seen.recv()).await.unwrap().unwrap();
    assert_eq!(seen, Err(io::ErrorKind::ConnectionReset));
}

#[tokio::test]
async fn a_client_whose_connection_breaks_while_data_flows_resets_the_stream_and_the_agent_goes_on()
{
    let mut rig = rig();
    let mut connection = raw_client(&rig, "e").await;
    // Plenty to echo, never read, then gone.
    for _ in 0..8 {
        send_frame(&mut connection, FRAME_DATA, &[7u8; 16 * 1024]).await;
    }
    drop(connection);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (output, end) = run_client(&rig, "peer/e", b"still working").await.unwrap();
    assert_eq!(
        (output.as_slice(), end),
        (&b"still working"[..], End::Clean)
    );
    let _ = rig.seen.try_recv();
}

/// The client said it was done sending (an end frame) and then died. The stream's write side is
/// closed by then, so only an explicit reset tells the remote, which is still sending.
#[tokio::test]
async fn a_client_that_finished_sending_and_then_vanished_still_resets_the_stream() {
    let mut rig = rig();
    let mut connection = raw_client(&rig, "s").await;
    send_frame(&mut connection, FRAME_DATA, b"request").await;
    send_frame(&mut connection, FRAME_END, &[]).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(connection);
    let seen = timeout(WAIT, rig.seen.recv()).await.unwrap().unwrap();
    assert_eq!(seen, Err(io::ErrorKind::ConnectionReset));
}

#[tokio::test]
async fn nonsense_from_the_client_after_ok_resets_the_stream() {
    let mut rig = rig();
    for garbage in [&[9u8, 0, 0, 0, 0][..], &[0u8, 0xff, 0xff, 0xff, 0xff][..]] {
        let mut connection = raw_client(&rig, "w").await;
        send_frame(&mut connection, FRAME_DATA, b"x").await;
        connection.write_all(garbage).await.unwrap();
        let seen = timeout(WAIT, rig.seen.recv()).await.unwrap().unwrap();
        assert_eq!(seen, Err(io::ErrorKind::ConnectionReset), "{garbage:?}");
    }
}

#[tokio::test]
async fn many_clients_at_once_do_not_disturb_each_other() {
    let rig = Arc::new(rig());
    let mut tasks = Vec::new();
    for i in 0..24u8 {
        let rig = rig.clone();
        tasks.push(tokio::spawn(async move {
            let data = vec![i; 60_000 + usize::from(i) * 1000];
            let (output, end) = run_client(&rig, "peer/e", &data).await.unwrap();
            assert_eq!(end, End::Clean);
            assert_eq!(output, data);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn without_an_agent_the_client_says_how_to_start_one() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("none.sock");
    let (_feed, stdin) = duplex(16);
    let (stdout, _collect) = duplex(16);
    let error = connect_and_bridge(&missing, "a/b", stdin, stdout)
        .await
        .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("menzil node") && text.contains("none.sock"),
        "{text}"
    );
}

#[tokio::test]
async fn the_client_returns_when_the_stream_ends_even_if_its_input_stays_open() {
    let rig = rig();
    // `r` ends the stream by itself; the input is never closed.
    let (_keep_open, stdin) = duplex(64);
    let (stdout, mut collect) = duplex(1024);
    let mut input = _keep_open;
    input.write_all(b"x").await.unwrap();
    let end = timeout(
        WAIT,
        connect_and_bridge(&rig.socket, "peer/r", stdin, stdout),
    )
    .await
    .expect("must not wait for the input")
    .unwrap();
    assert!(matches!(end, End::Reset(_)));
    let mut got = Vec::new();
    collect.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"partial");
}

#[tokio::test]
async fn frames_that_lie_are_a_reset_not_a_crash() {
    // A fake agent that answers ok and then sends garbage frames.
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let frames: Vec<Vec<u8>> = vec![
        vec![9, 0, 0, 0, 0],              // unknown kind
        vec![0, 0xff, 0xff, 0xff, 0xff],  // length too long
        vec![0, 0, 0, 0, 10, b'a', b'b'], // cut off in the payload
        vec![0, 0, 0],                    // cut off in the header
    ];
    let served = Mutex::new(frames.into_iter());
    let server = tokio::spawn(async move {
        loop {
            let (mut connection, _) = listener.accept().await.unwrap();
            let frame = served.lock().unwrap().next();
            let mut request = [0u8; 64];
            let _ = connection.read(&mut request).await;
            connection.write_all(b"ok\n").await.unwrap();
            if let Some(frame) = frame {
                connection.write_all(&frame).await.unwrap();
            }
            drop(connection);
        }
    });
    for _ in 0..4 {
        let (_feed, stdin) = duplex(16);
        let (stdout, _collect) = duplex(1024);
        let end = timeout(WAIT, connect_and_bridge(&socket, "a/b", stdin, stdout))
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(end, End::Reset(_)), "{end:?}");
    }
    server.abort();
}
