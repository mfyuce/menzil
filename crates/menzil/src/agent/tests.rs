use std::io;
use std::sync::Mutex;

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
/// * `w` reads to the end and reports how that ended, so a test can see a reset;
/// * `f` finishes first: writes `greet`, closes, then reads to the end and reports how many
///   bytes it got (a peer that half-closes and still listens).
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
                b'f' => {
                    let _ = stream.write_all(b"greet").await;
                    let _ = stream.close().await;
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
            // `long/<n>`: an explanation of n four byte characters.
            "long" => return Err("\u{1F600}".repeat(behavior.parse().unwrap())),
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
    let (mut feed, mut stdin) = duplex(64 * 1024);
    let (mut stdout, mut collect) = duplex(1 << 20);
    let input = input.to_vec();
    tokio::spawn(async move {
        let _ = feed.write_all(&input).await;
        let _ = feed.shutdown().await;
    });
    let end = timeout(
        WAIT,
        connect_and_bridge(&rig.socket, target, &mut stdin, &mut stdout),
    )
    .await
    .expect("the client must finish")?;
    drop(stdout);
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

/// Round 13 N1: an explanation that reaches the person is not cut at 300 characters (the advice
/// at its end was lost), and one far over the limit is cut to the limit and still arrives as the
/// error, not as a client that gave up on a long line.
#[tokio::test]
async fn a_long_explanation_reaches_the_client_up_to_the_error_limit() {
    let rig = rig();
    let whole = run_client(&rig, "long/900", b"")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        whole.chars().count(),
        900,
        "{} chars",
        whole.chars().count()
    );
    let cut = run_client(&rig, "long/5000", b"")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(cut.chars().count(), ERROR_LINE_CHARS);
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
    let (_feed, mut stdin) = duplex(16);
    let (mut stdout, _collect) = duplex(16);
    let error = connect_and_bridge(&missing, "a/b", &mut stdin, &mut stdout)
        .await
        .unwrap_err();
    let text = format!("{error:#}");
    assert!(
        text.contains("menzil node") && text.contains("none.sock"),
        "{text}"
    );
}

/// A reset is the end of everything: the client does not wait for a program that keeps its
/// input open.
#[tokio::test]
async fn a_reset_ends_the_client_at_once_even_if_its_input_stays_open() {
    let rig = rig();
    // `r` ends the stream by itself; the input is never closed.
    let (mut keep_open, mut stdin) = duplex(64);
    let (mut stdout, mut collect) = duplex(1024);
    keep_open.write_all(b"x").await.unwrap();
    let end = timeout(
        WAIT,
        connect_and_bridge(&rig.socket, "peer/r", &mut stdin, &mut stdout),
    )
    .await
    .expect("must not wait for the input")
    .unwrap();
    assert!(matches!(end, End::Reset(_)));
    drop(stdout);
    let mut got = Vec::new();
    collect.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"partial");
}

/// The third red-team round, M7: the peer finished first and still reads. Its end closes the
/// client's output at once (the program reading it sees end of file), and the client goes on
/// carrying the input to the end; it used to stop the input, the agent reset the stream, and the
/// peer got a reset where it expected the rest of the upload.
#[tokio::test]
async fn after_the_peers_end_the_client_carries_its_input_on_until_it_ends() {
    let mut rig = rig();
    let (mut feed, mut stdin) = duplex(64 * 1024);
    let (mut stdout, mut collect) = duplex(1 << 20);
    let socket = rig.socket.clone();
    let client = tokio::spawn(async move {
        connect_and_bridge(&socket, "peer/f", &mut stdin, &mut stdout).await
    });
    feed.write_all(b"a").await.unwrap();

    // The peer's end reaches the program while the input is still open.
    let mut output = Vec::new();
    timeout(WAIT, collect.read_to_end(&mut output))
        .await
        .expect("the output must be closed when the peer ends")
        .unwrap();
    assert_eq!(output, b"greet");
    assert!(!client.is_finished(), "the input is not finished yet");

    tokio::time::sleep(Duration::from_millis(300)).await;
    feed.write_all(&[b'b'; 1000]).await.unwrap();
    feed.shutdown().await.unwrap();
    let end = timeout(WAIT, client).await.unwrap().unwrap().unwrap();
    assert_eq!(end, End::Clean);
    let remote = timeout(WAIT, rig.seen.recv()).await.unwrap().unwrap();
    assert_eq!(
        remote,
        Ok(1001),
        "the whole upload reaches a peer that ended first"
    );
}

/// A client whose own input fails resets the stream, and says so.
#[tokio::test]
async fn an_input_that_fails_resets_the_stream_and_ends_the_client() {
    struct FailingInput;
    impl AsyncRead for FailingInput {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Err(io::Error::other("the disk went away")))
        }
    }
    let mut rig = rig();
    let (mut stdout, _collect) = duplex(1024);
    let end = timeout(
        WAIT,
        connect_and_bridge(&rig.socket, "peer/w", &mut FailingInput, &mut stdout),
    )
    .await
    .unwrap()
    .unwrap();
    match end {
        End::Reset(why) => assert!(why.contains("disk went away"), "{why}"),
        End::Clean => panic!("a failing input is not a clean end"),
    }
    let remote = timeout(WAIT, rig.seen.recv()).await.unwrap().unwrap();
    assert_eq!(remote, Err(io::ErrorKind::ConnectionReset));
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
        let (_feed, mut stdin) = duplex(16);
        let (mut stdout, _collect) = duplex(1024);
        let end = timeout(
            WAIT,
            connect_and_bridge(&socket, "a/b", &mut stdin, &mut stdout),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(matches!(end, End::Reset(_)), "{end:?}");
    }
    server.abort();
}

#[tokio::test]
async fn current_uid_is_the_user_of_this_process() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let owner = std::fs::metadata(dir.path()).unwrap().uid();
    assert_eq!(current_uid().await.unwrap(), owner);
}

/// The third red-team round, M2: a socket that another user serves gets nothing from this
/// client, not even the name of the service asked for.
#[tokio::test]
async fn a_socket_another_user_serves_gets_nothing_from_the_client() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let received = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut got = Vec::new();
        let _ = timeout(Duration::from_millis(500), connection.read_to_end(&mut got)).await;
        got
    });
    let uid = current_uid().await.unwrap();
    let (_feed, mut stdin) = duplex(16);
    let (mut stdout, _collect) = duplex(16);
    // The server is this user; the client was told to expect somebody else.
    let error = bridge_as(&socket, "peer/e", &mut stdin, &mut stdout, uid + 1)
        .await
        .unwrap_err();
    let text = format!("{error:#}");
    assert!(text.contains("another user"), "{text}");
    assert_eq!(received.await.unwrap(), b"", "nothing was sent to it");
}

/// And the agent does not serve a connection from another user: nothing reaches the opener. (The
/// opener records the call instead of panicking: a panic in the connection's task would be
/// swallowed there, and the client would see a closed connection all the same.)
#[tokio::test]
async fn the_agent_closes_a_connection_from_another_user_unanswered() {
    struct Records(Arc<std::sync::atomic::AtomicUsize>);
    impl Opener for Records {
        async fn open(&self, _target: &str) -> Result<Stream, String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("a connection from another user reached the opener".to_string())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = current_uid().await.unwrap();
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // The agent expects somebody else; this process connects.
    let agent = tokio::spawn(serve_user(
        listener,
        Arc::new(Records(opened.clone())),
        uid + 1,
    ));
    let (_feed, mut stdin) = duplex(16);
    let (mut stdout, _collect) = duplex(16);
    let error = timeout(
        WAIT,
        connect_and_bridge(&socket, "peer/e", &mut stdin, &mut stdout),
    )
    .await
    .unwrap()
    .unwrap_err();
    // Closed unanswered, with the request still unread: the client sees either the end of the
    // connection or the reset the kernel sends for unread data. Not an answer of the opener's.
    let text = format!("{error:#}");
    assert!(
        text.contains("without answering") || text.contains("reset by peer"),
        "{text}"
    );
    assert_eq!(
        opened.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the opener was reached"
    );
    assert!(!agent.is_finished(), "the agent goes on serving");

    // The same agent for this user does serve the connection (it reaches the opener).
    let own = dir.path().join("own.sock");
    let listener = UnixListener::bind(&own).unwrap();
    let served = tokio::spawn(serve_user(listener, Arc::new(Records(opened.clone())), uid));
    let (_feed, mut stdin) = duplex(16);
    let (mut stdout, _collect) = duplex(16);
    let error = connect_and_bridge(&own, "peer/e", &mut stdin, &mut stdout)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("reached the opener"),
        "{error:#}"
    );
    assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 1);
    served.abort();
    agent.abort();
}

/// An agent that cannot take what the client sends is a broken stream, not a finished one: the
/// client's data went nowhere, and the answer it may still get must not read as a clean end.
#[tokio::test]
async fn an_agent_that_stops_reading_ends_the_client_as_a_reset_not_a_clean_end() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (connection, _) = listener.accept().await.unwrap();
        let (read, write) = connection.into_split();
        let mut read = BufReader::new(read);
        let mut request = String::new();
        read.read_line(&mut request).await.unwrap();
        let mut connection = read.into_inner().reunite(write).unwrap();
        // Stops taking input (the client's writes fail from now on) before it says ok, but then
        // answers as if all were well.
        socket2::SockRef::from(&connection)
            .shutdown(std::net::Shutdown::Read)
            .unwrap();
        connection.write_all(b"ok\n").await.unwrap();
        write_frame(&mut connection, FRAME_DATA, b"an answer")
            .await
            .unwrap();
        write_frame(&mut connection, FRAME_END, &[]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
    });
    let (mut feed, mut stdin) = duplex(64 * 1024);
    let (mut stdout, _collect) = duplex(1024);
    feed.write_all(&[1u8; 4096]).await.unwrap();
    let end = timeout(
        WAIT,
        connect_and_bridge(&socket, "peer/e", &mut stdin, &mut stdout),
    )
    .await
    .unwrap()
    .unwrap();
    match end {
        End::Reset(why) => assert!(why.contains("agent went away"), "{why}"),
        End::Clean => panic!("the agent took none of the input, and the end was reported clean"),
    }
    server.abort();
}

/// The third red-team round, M2: whoever answers on the socket can write what it likes, and the
/// client must not pass terminal escapes on to the user's terminal.
#[tokio::test]
async fn what_an_agent_sends_never_reaches_the_terminal_unescaped() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("fake.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let evil = "\u{1b}]0;PWNED\u{7}\u{1b}[2Jboom \u{202e}gpj";
    let replies: Vec<Vec<u8>> = vec![format!("error {evil}\n").into_bytes(), {
        let mut r = b"ok\n".to_vec();
        r.push(FRAME_RESET);
        r.extend_from_slice(&(evil.len() as u32).to_be_bytes());
        r.extend_from_slice(evil.as_bytes());
        r
    }];
    let served = Mutex::new(replies.into_iter());
    let server = tokio::spawn(async move {
        loop {
            let (mut connection, _) = listener.accept().await.unwrap();
            let reply = served.lock().unwrap().next();
            let mut request = [0u8; 64];
            let _ = connection.read(&mut request).await;
            if let Some(reply) = reply {
                connection.write_all(&reply).await.unwrap();
            }
            drop(connection);
        }
    });
    for round in 0..2 {
        let (_feed, mut stdin) = duplex(16);
        let (mut stdout, _collect) = duplex(1024);
        let shown = match connect_and_bridge(&socket, "a/b", &mut stdin, &mut stdout).await {
            Err(error) => format!("{error:#}"),
            Ok(End::Reset(why)) => why,
            Ok(End::Clean) => panic!("round {round}: not a clean end"),
        };
        assert!(shown.contains("PWNED"), "the words stay: {shown}");
        assert!(
            !shown.chars().any(text::is_unsafe),
            "round {round}: an escape reached the terminal text: {shown:?}"
        );
    }
    server.abort();
}

// ---- the `status` request (the relay's last rejection reaches `menzil status`) ----

struct Reports(RelayStatus);

impl Opener for Reports {
    async fn open(&self, _target: &str) -> Result<Stream, String> {
        Err("no streams here".to_string())
    }
    async fn status(&self) -> RelayStatus {
        self.0.clone()
    }
}

fn rejected(code: &str) -> Rejected {
    Rejected {
        at: 1_700_000_000,
        code: Some(code.to_string()),
        message: "node is revoked in network x".to_string(),
        goaway: Some("revoked".to_string()),
        listed_in_own_roster: false,
    }
}

async fn ask(status: RelayStatus) -> Result<RelayStatus> {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = current_uid().await.unwrap();
    let agent = tokio::spawn(serve_user(listener, Arc::new(Reports(status)), uid));
    let got = timeout(WAIT, query_status_as(&socket, uid)).await.unwrap();
    agent.abort();
    got
}

#[tokio::test]
async fn the_status_request_carries_the_rejection_and_whether_the_node_is_attached() {
    let sent = RelayStatus {
        attached: Some(false),
        rejected: Some(rejected("revoked")),
    };
    assert_eq!(ask(sent.clone()).await.unwrap(), sent);
    // Every part is optional: attached with nothing held against it, an ERROR without text, a
    // GOAWAY alone.
    let attached = RelayStatus {
        attached: Some(true),
        rejected: None,
    };
    assert_eq!(ask(attached.clone()).await.unwrap(), attached);
    let bare = RelayStatus {
        attached: None,
        rejected: Some(Rejected {
            at: 5,
            code: Some("not_member".to_string()),
            message: String::new(),
            goaway: None,
            listed_in_own_roster: false,
        }),
    };
    assert_eq!(ask(bare.clone()).await.unwrap(), bare);
    // A not_member that the node's own Roster contradicts keeps that on the way.
    let listed = RelayStatus {
        attached: None,
        rejected: Some(Rejected {
            at: 5,
            code: Some("not_member".to_string()),
            message: String::new(),
            goaway: None,
            listed_in_own_roster: true,
        }),
    };
    assert_eq!(ask(listed.clone()).await.unwrap(), listed);
    let goaway_only = RelayStatus {
        attached: Some(true),
        rejected: Some(Rejected {
            at: 6,
            code: None,
            message: String::new(),
            goaway: Some("superseded".to_string()),
            listed_in_own_roster: false,
        }),
    };
    assert_eq!(ask(goaway_only.clone()).await.unwrap(), goaway_only);
    // An opener that knows nothing says nothing.
    assert_eq!(
        ask(RelayStatus::default()).await.unwrap(),
        RelayStatus::default()
    );
}

#[tokio::test]
async fn the_default_opener_answers_status_with_nothing() {
    struct Plain;
    impl Opener for Plain {
        async fn open(&self, _target: &str) -> Result<Stream, String> {
            Err("no".to_string())
        }
    }
    assert_eq!(Plain.status().await, RelayStatus::default());
}

#[tokio::test]
async fn what_the_agent_says_in_a_status_reply_never_reaches_the_terminal_unescaped() {
    let sent = RelayStatus {
        attached: Some(false),
        rejected: Some(Rejected {
            at: 1,
            code: Some("revoked\u{1b}[2J".to_string()),
            message: "line one\nrejected_code forged\u{202e}".to_string(),
            goaway: Some("a\u{7}b".to_string()),
            listed_in_own_roster: false,
        }),
    };
    let got = ask(sent).await.unwrap();
    let rejected = got.rejected.unwrap();
    let all = format!(
        "{:?} {} {:?}",
        rejected.code, rejected.message, rejected.goaway
    );
    assert!(
        !all.contains('\u{1b}') && !all.contains('\u{202e}') && !all.contains('\u{7}'),
        "{all:?}"
    );
    assert_eq!(rejected.code.as_deref(), Some("revoked [2J"));
    // The newline in the text did not start a line of its own that forges a key.
    assert_eq!(rejected.message, "line one rejected_code forged ");
}

#[test]
fn a_client_skips_keys_it_does_not_know_and_ignores_a_reply_with_no_rejection() {
    let lines: Vec<String> = [
        "attached no",
        "future_field something new",
        "rejected_at 42",
        "rejected_code stale_serial",
        "rejected_extra x",
    ]
    .iter()
    .map(|l| l.to_string())
    .collect();
    let status = RelayStatus::from_lines(&lines);
    assert_eq!(status.attached, Some(false));
    let rejected = status.rejected.unwrap();
    assert_eq!(
        (rejected.at, rejected.code.as_deref()),
        (42, Some("stale_serial"))
    );
    // A time with nothing it is the time of is not a rejection.
    let only_time = RelayStatus::from_lines(&["rejected_at 42".to_string()]);
    assert_eq!(only_time.rejected, None);
    // A time that does not parse is 0 ("unknown").
    let odd = RelayStatus::from_lines(&[
        "rejected_at soon".to_string(),
        "rejected_code revoked".to_string(),
    ]);
    assert_eq!(odd.rejected.unwrap().at, 0);
}

/// An agent from before the request answers `error ...`: the client reports that, and does not
/// make a status of it.
#[tokio::test]
async fn an_agent_that_does_not_know_the_request_gives_no_status() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("old.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = current_uid().await.unwrap();
    let old = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 64];
        let _ = connection.read(&mut request).await;
        connection
            .write_all(b"error the request must be `open <who>/<service>`\n")
            .await
            .unwrap();
    });
    let error = timeout(WAIT, query_status_as(&socket, uid))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("does not report its status"),
        "{error:#}"
    );
    old.await.unwrap();
    // And with no agent at all, it says how to start one.
    let error = query_status_as(&dir.path().join("none.sock"), uid)
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("no agent is listening"),
        "{error:#}"
    );
}

#[tokio::test]
async fn the_status_client_refuses_a_socket_that_another_user_serves() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = current_uid().await.unwrap();
    let agent = tokio::spawn(serve_user(
        listener,
        Arc::new(Reports(RelayStatus::default())),
        uid,
    ));
    let error = query_status_as(&socket, uid + 1).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("served by another user"),
        "{error:#}"
    );
    agent.abort();
}

#[test]
fn status_is_rendered_with_the_reason_in_words() {
    let now = 1_700_000_000 + 7 * 60;
    let text = RelayStatus {
        attached: Some(false),
        rejected: Some(rejected("revoked")),
    }
    .render(now);
    assert!(text.starts_with("relay: not attached\n"), "{text}");
    assert!(
        text.contains("the relay turned this device away")
            && text.contains("revoked")
            && text.contains("7 minutes ago")
            && text.contains("node is revoked in network x")
            && text.contains("GOAWAY revoked"),
        "{text}"
    );
    assert_eq!(text.lines().count(), 2, "{text}");
    let text = RelayStatus {
        attached: Some(true),
        rejected: None,
    }
    .render(now);
    assert_eq!(text, "relay: attached\n");
    assert_eq!(RelayStatus::default().render(now), "");
}

/// Each side makes the text printable on its own: the agent before it sends, the client when it
/// reads, whatever the other side did.
#[test]
fn the_agent_and_the_client_each_make_the_status_text_printable() {
    let dirty = RelayStatus {
        attached: Some(false),
        rejected: Some(Rejected {
            at: 1,
            code: Some("re\u{1b}[2Jvoked\nattached yes".to_string()),
            message: "a\nb\u{202e}".to_string(),
            goaway: Some("g\u{7}".to_string()),
            listed_in_own_roster: false,
        }),
    };
    // What the agent writes has one line per key and nothing that acts.
    let sent = dirty.to_lines();
    assert_eq!(sent.lines().count(), 5, "{sent:?}");
    assert!(
        !sent.contains('\u{1b}') && !sent.contains('\u{202e}') && !sent.contains('\u{7}'),
        "{sent:?}"
    );
    // What the client reads is cleaned even when the agent did not.
    let lines: Vec<String> = [
        "rejected_at 1",
        "rejected_code re\u{1b}[2Jvoked",
        "rejected_message a\u{202e}b",
        "rejected_goaway g\u{7}",
    ]
    .iter()
    .map(|l| l.to_string())
    .collect();
    let rejected = RelayStatus::from_lines(&lines).rejected.unwrap();
    assert_eq!(rejected.code.as_deref(), Some("re [2Jvoked"));
    assert_eq!(rejected.message, "a b");
    assert_eq!(rejected.goaway.as_deref(), Some("g "));
}

// ---- round 13 ----

/// A reply whose lines the test writes itself, then closes.
async fn ask_raw(reply: Vec<u8>) -> Result<RelayStatus> {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("raw.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = current_uid().await.unwrap();
    let agent = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 64];
        let _ = connection.read(&mut request).await;
        // The client may have stopped reading by now.
        let _ = connection.write_all(&reply).await;
    });
    let got = timeout(WAIT, query_status_as(&socket, uid)).await.unwrap();
    agent.await.unwrap();
    got
}

/// L1: what a relay can make the node keep (256 bytes, here four byte characters) goes through
/// the agent and the client as it is, and the whole status is read.
#[tokio::test]
async fn four_byte_relay_text_does_not_hide_the_status() {
    let notes = menzil_node::RelayNotes::new();
    notes.begin_attachment();
    let emoji = "\u{1F600}".repeat(5_000);
    notes.note_error(
        &menzil_proto::ErrorBody {
            code: menzil_proto::ErrorCode::Revoked,
            msg: emoji.clone(),
        },
        1_700_000_000,
    );
    notes.note_goaway(&emoji, 1_700_000_001);
    let kept = notes.last_error().unwrap();
    let sent = RelayStatus {
        attached: Some(false),
        rejected: Some(Rejected {
            at: kept.at,
            code: Some("revoked".to_string()),
            message: kept.message.clone(),
            goaway: kept.goaway.clone(),
            listed_in_own_roster: false,
        }),
    };
    let got = ask(sent).await.unwrap();
    assert_eq!(got.attached, Some(false));
    let rejected = got.rejected.unwrap();
    assert_eq!(rejected.code.as_deref(), Some("revoked"));
    assert_eq!(rejected.message, kept.message);
    assert_eq!(rejected.goaway, kept.goaway);
}

/// L1: a line the client cannot take (over long, or not text) is left out; the lines around it
/// still make the status.
#[tokio::test]
async fn an_over_long_or_garbled_line_is_skipped_and_the_rest_of_the_reply_is_read() {
    let mut reply = b"attached no\nrejected_at 5\nrejected_code revoked\n".to_vec();
    reply.extend_from_slice(b"rejected_message ");
    reply.extend_from_slice(&vec![b'x'; 3 * MAX_REPLY_BYTES]);
    reply.extend_from_slice(b"\nsomething \xff\xfe not text\nrejected_goaway superseded\n");
    let got = ask_raw(reply).await.unwrap();
    assert_eq!(got.attached, Some(false));
    let rejected = got.rejected.unwrap();
    assert_eq!(rejected.code.as_deref(), Some("revoked"));
    assert_eq!(rejected.message, "", "the long line is gone");
    assert_eq!(rejected.goaway.as_deref(), Some("superseded"));
    // The reply ends in the middle of an over long line: what came before is still a status.
    let mut reply = b"attached yes\n".to_vec();
    reply.extend_from_slice(&vec![b'y'; 2 * MAX_REPLY_BYTES]);
    let got = ask_raw(reply).await.unwrap();
    assert_eq!(got.attached, Some(true));
    // Skipped lines count toward the most lines read: nothing after them is waited for.
    let mut reply = Vec::new();
    for _ in 0..MAX_STATUS_LINES {
        reply.extend_from_slice(&vec![b'z'; MAX_REPLY_BYTES + 1]);
        reply.push(b'\n');
    }
    reply.extend_from_slice(b"attached yes\n");
    let got = ask_raw(reply).await.unwrap();
    assert_eq!(got.attached, None, "past the limit of lines");
}

/// The reader of lines: an over long line is dropped to its newline, whatever the size of the
/// chunks it arrives in, and the next line is intact.
#[tokio::test]
async fn the_lenient_line_reader_drops_a_long_line_and_keeps_the_next() {
    for capacity in [1, 3, 8, 64] {
        let data = b"ab\nabcdefghijklmnop\nok\n\xff\nlast";
        let mut reader = BufReader::with_capacity(capacity, &data[..]);
        assert_eq!(
            read_line_lenient(&mut reader, 6).await.unwrap(),
            Some(Line::Text("ab\n".to_string()))
        );
        assert_eq!(
            read_line_lenient(&mut reader, 6).await.unwrap(),
            Some(Line::TooLong)
        );
        assert_eq!(
            read_line_lenient(&mut reader, 6).await.unwrap(),
            Some(Line::Text("ok\n".to_string()))
        );
        assert_eq!(
            read_line_lenient(&mut reader, 6).await.unwrap(),
            Some(Line::NotUtf8)
        );
        // A connection that ends in the middle of an ordinary line is an error.
        assert!(read_line_lenient(&mut reader, 6).await.is_err());
        // A connection that ends in the middle of an over long line: that line, then the end.
        let mut cut = BufReader::with_capacity(capacity, &b"abcdefghij"[..]);
        assert_eq!(
            read_line_lenient(&mut cut, 6).await.unwrap(),
            Some(Line::TooLong)
        );
        assert_eq!(read_line_lenient(&mut cut, 6).await.unwrap(), None);
        // The strict reader still refuses an over long line.
        let mut strict = BufReader::with_capacity(capacity, &b"abcdefghij\n"[..]);
        assert!(read_line(&mut strict, 6).await.is_err());
    }
}

/// N2: a time near the end of the range does not overflow (a debug build panicked).
#[test]
fn a_rejection_with_a_huge_time_renders_without_overflow() {
    let status = RelayStatus::from_lines(&[
        "attached no".to_string(),
        "rejected_at 18446744073709551615".to_string(),
        "rejected_code revoked".to_string(),
    ]);
    let text = status.render(1_700_000_000);
    assert!(text.contains("just now"), "{text}");
}

// ---- the certificate (cert rotation S6): `cert renew`, and the certificate in `status` ----

fn a_cert(serial: u32) -> menzil_proto::NodeCert {
    menzil_admin::NodeKeys::generate()
        .issue_cert(serial, 1_700_000_000, 1_700_000_000 + 1000)
        .unwrap()
}

/// An opener that renews to a prepared answer and reports a prepared certificate status.
struct Certs {
    renewal: Result<RenewedCert, String>,
    status: Option<CertStatus>,
    asked: std::sync::atomic::AtomicUsize,
}

impl Opener for Certs {
    async fn open(&self, _target: &str) -> Result<Stream, String> {
        Err("no streams here".to_string())
    }
    async fn cert_status(&self) -> Option<CertStatus> {
        self.status.clone()
    }
    async fn renew_cert(&self) -> Result<RenewedCert, String> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.renewal.clone()
    }
}

fn certs(renewal: Result<RenewedCert, String>, status: Option<CertStatus>) -> Arc<Certs> {
    Arc::new(Certs {
        renewal,
        status,
        asked: std::sync::atomic::AtomicUsize::new(0),
    })
}

async fn with_agent<O: Opener, T>(opener: Arc<O>, client: impl AsyncFnOnce(&Path, u32) -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = current_uid().await.unwrap();
    let agent = tokio::spawn(serve_user(listener, opener, uid));
    let got = timeout(WAIT, client(&socket, uid)).await.unwrap();
    agent.abort();
    got
}

fn renewed_of(cert: &menzil_proto::NodeCert) -> RenewedCert {
    let body = cert.decode().unwrap();
    RenewedCert {
        serial: body.serial,
        not_after: body.not_after,
        token: crate::token::encode_cert_request(cert),
    }
}

#[tokio::test]
async fn a_cert_renew_request_gets_the_serial_and_the_token_the_node_made() {
    let cert = a_cert(7);
    let opener = certs(Ok(renewed_of(&cert)), None);
    let got = with_agent(opener.clone(), async |socket, uid| {
        renew_cert_as(socket, uid).await
    })
    .await
    .unwrap();
    assert_eq!(got, renewed_of(&cert));
    assert_eq!(crate::token::decode_cert_request(&got.token).unwrap(), cert);
    assert_eq!(opener.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_node_that_refuses_to_renew_says_why_and_is_not_bypassed() {
    let opener = certs(
        Err("the node did not take it\nsecond line".to_string()),
        None,
    );
    let error = with_agent(opener, async |socket, uid| renew_cert_as(socket, uid).await)
        .await
        .unwrap_err();
    match error {
        RenewError::Failed(error) => {
            let shown = format!("{error:#}");
            assert!(shown.contains("the node did not take it"), "{shown}");
            assert!(!shown.contains('\n'), "{shown:?}");
        }
        RenewError::NoAgent => panic!("an agent answered; that is not 'no agent'"),
    }
    // An agent that predates the request, or has no renewer, refuses in words.
    struct Plain;
    impl Opener for Plain {
        async fn open(&self, _target: &str) -> Result<Stream, String> {
            Err("no".to_string())
        }
    }
    let error = with_agent(Arc::new(Plain), async |socket, uid| {
        renew_cert_as(socket, uid).await
    })
    .await
    .unwrap_err();
    assert!(
        matches!(error, RenewError::Failed(ref e) if format!("{e:#}").contains("does not renew")),
        "{error}"
    );
}

#[tokio::test]
async fn nothing_listening_is_no_agent_and_anything_else_is_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let uid = current_uid().await.unwrap();
    // No socket file at all, and a stale one nobody listens at.
    let missing = dir.path().join("none.sock");
    assert!(matches!(
        renew_cert_as(&missing, uid).await,
        Err(RenewError::NoAgent)
    ));
    let stale = dir.path().join("stale.sock");
    drop(UnixListener::bind(&stale).unwrap());
    assert!(matches!(
        renew_cert_as(&stale, uid).await,
        Err(RenewError::NoAgent)
    ));
}

#[tokio::test]
async fn the_token_in_a_cert_renew_answer_is_checked_before_it_is_shown() {
    // A token for serial 7 under a reported serial of 8.
    let cert = a_cert(7);
    let mut lie = renewed_of(&cert);
    lie.serial = 8;
    let error = with_agent(certs(Ok(lie), None), async |socket, uid| {
        renew_cert_as(socket, uid).await
    })
    .await
    .unwrap_err();
    assert!(
        matches!(error, RenewError::Failed(ref e) if format!("{e:#}").contains("does not match")),
        "{error}"
    );
    // A token that is not a certificate token (a join request has the wrong prefix).
    let mut wrong = renewed_of(&cert);
    wrong.token = crate::token::encode_join_request(&cert);
    let error = with_agent(certs(Ok(wrong), None), async |socket, uid| {
        renew_cert_as(socket, uid).await
    })
    .await
    .unwrap_err();
    assert!(matches!(error, RenewError::Failed(_)), "{error}");
}

#[tokio::test]
async fn the_status_reply_carries_the_certificate_and_the_networks_that_do_not_list_it() {
    let sent = CertStatus {
        serial: 3,
        not_after: 1_800_000_000,
        unlisted: vec![
            UnlistedCert {
                network: menzil_proto::NetworkId::from([7u8; 32]),
                days: 12,
            },
            UnlistedCert {
                network: menzil_proto::NetworkId::from([8u8; 32]),
                days: 0,
            },
        ],
    };
    let opener = certs(Err("unused".into()), Some(sent.clone()));
    let got = with_agent(opener, async |socket, uid| {
        query_node_status_as(socket, uid).await
    })
    .await
    .unwrap();
    assert_eq!(got.cert, Some(sent.clone()));
    // The relay part is untouched by the certificate lines, and an agent without a certificate
    // says none.
    assert_eq!(got.relay, RelayStatus::default());
    let none = with_agent(certs(Err("unused".into()), None), async |socket, uid| {
        query_node_status_as(socket, uid).await
    })
    .await
    .unwrap();
    assert_eq!(none.cert, None);
    // The older call still works against such an agent.
    let relay = with_agent(
        certs(Err("unused".into()), Some(sent.clone())),
        async |socket, uid| query_status_as(socket, uid).await,
    )
    .await
    .unwrap();
    assert_eq!(relay, RelayStatus::default());

    let text = sent.render(1_800_000_000 - 3 * 24 * 60 * 60);
    assert!(
        text.contains("serial 3") && text.contains("expires in 3 days"),
        "{text}"
    );
    assert!(
        text.contains(&"07".repeat(32)) && text.contains("12 day(s)"),
        "{text}"
    );
    assert!(text.contains("menzil cert request"), "{text}");
}

#[test]
fn a_certificate_status_line_that_is_off_is_skipped_not_believed() {
    let lines: Vec<String> = [
        "cert_serial 4",
        "cert_not_after 99",
        "cert_unlisted nothex 5",
        "cert_unlisted",
        &format!("cert_unlisted {} notanumber", "ab".repeat(32)),
        &format!("cert_unlisted {} 6", "ab".repeat(32)),
        "cert_future x",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let status = CertStatus::from_lines(&lines).unwrap();
    assert_eq!(
        status.unlisted,
        vec![UnlistedCert {
            network: menzil_proto::NetworkId::from([0xab; 32]),
            days: 6
        }]
    );
    // Without a serial and an end there is no certificate part.
    assert_eq!(CertStatus::from_lines(&["cert_serial 4".to_string()]), None);
    assert_eq!(CertStatus::from_lines(&[]), None);
}

// ---- shares (S-E7): `expose`, `unexpose`, and the share lines of `status` ----

use crate::expose::{ExposeMode, ShareState};

fn a_spec(label: &str) -> ExposeSpec {
    ExposeSpec {
        label: label.to_string(),
        mode: ExposeMode::Tcp,
        host: "::1".to_string(),
        port: 8443,
        alpn: vec!["h2".to_string()],
        replace: true,
    }
}

fn a_view(label: &str) -> ShareView {
    ShareView {
        label: label.to_string(),
        mode: "tcp".to_string(),
        service: format!("tcp:{label}"),
        target: Some("[::1]:8443".to_string()),
        alpn: vec!["h2".to_string()],
        state: ShareState::Accepted,
        names: vec![label.to_string(), format!("{label}.ali")],
        reason: None,
    }
}

/// An opener that records what it is asked to expose and answers as prepared.
struct Sharer {
    views: Vec<ShareView>,
    exposed: Mutex<Vec<ExposeSpec>>,
    removed: Mutex<Vec<String>>,
    refuse: Option<String>,
}

fn sharer(views: Vec<ShareView>, refuse: Option<&str>) -> Arc<Sharer> {
    Arc::new(Sharer {
        views,
        exposed: Mutex::new(Vec::new()),
        removed: Mutex::new(Vec::new()),
        refuse: refuse.map(str::to_string),
    })
}

impl Opener for Sharer {
    async fn open(&self, _target: &str) -> Result<Stream, String> {
        Err("no streams here".to_string())
    }
    async fn shares(&self) -> Vec<ShareView> {
        self.views.clone()
    }
    async fn expose(&self, spec: ExposeSpec) -> Result<ExposeReply, String> {
        self.exposed.lock().unwrap().push(spec.clone());
        match &self.refuse {
            Some(why) => Err(why.clone()),
            None => Ok(ExposeReply {
                changed: true,
                share: a_view(&spec.label),
                notes: vec!["one note".to_string()],
            }),
        }
    }
    async fn unexpose(&self, label: String) -> Result<UnexposeReply, String> {
        self.removed.lock().unwrap().push(label);
        match &self.refuse {
            Some(why) => Err(why.clone()),
            None => Ok(UnexposeReply {
                notes: vec!["kept tcp:ssh".to_string()],
                service_removed: true,
            }),
        }
    }
}

#[tokio::test]
async fn an_expose_request_reaches_the_node_whole_and_its_answer_comes_back() {
    let opener = sharer(vec![], None);
    let spec = a_spec("app");
    let reply = with_agent(opener.clone(), async |socket, uid| {
        request_expose_as(socket, &spec, uid).await
    })
    .await
    .unwrap();
    assert_eq!(opener.exposed.lock().unwrap().as_slice(), [spec]);
    assert!(reply.changed);
    assert_eq!(reply.share, a_view("app"));
    assert_eq!(reply.notes, ["one note"]);

    let gone = with_agent(opener.clone(), async |socket, uid| {
        request_unexpose_as(socket, "app", uid).await
    })
    .await
    .unwrap();
    assert_eq!(opener.removed.lock().unwrap().as_slice(), ["app"]);
    assert!(gone.service_removed);
    assert_eq!(gone.notes, ["kept tcp:ssh"]);
}

#[tokio::test]
async fn a_refusal_of_the_node_comes_back_as_one_line_and_a_bad_request_never_reaches_it() {
    let opener = sharer(vec![], Some("it said no\nsecond line"));
    let error = with_agent(opener.clone(), async |socket, uid| {
        request_expose_as(socket, &a_spec("app"), uid).await
    })
    .await
    .unwrap_err();
    match error {
        AskError::Failed(e) => {
            let shown = format!("{e:#}");
            assert!(
                shown.contains("it said no") && !shown.contains('\n'),
                "{shown:?}"
            );
        }
        AskError::NoAgent => panic!("an agent answered"),
    }
    let error = with_agent(opener.clone(), async |socket, uid| {
        request_unexpose_as(socket, "app", uid).await
    })
    .await
    .unwrap_err();
    assert!(matches!(error, AskError::Failed(ref e) if format!("{e:#}").contains("it said no")));

    // A request line the agent cannot parse is answered by the agent itself.
    let untouched = sharer(vec![], None);
    for (line, wanted) in [
        ("expose name=a bogus", "key=value"),
        (
            "expose name=a mode=blind host=h port=1 replace=0 evil=1",
            "unknown field",
        ),
        (
            "expose name=a mode=blind host=h port=99999 replace=0",
            "port",
        ),
    ] {
        let reply = with_agent(untouched.clone(), async |socket, _uid| {
            let mut connection = UnixStream::connect(socket).await.unwrap();
            connection
                .write_all(format!("{line}\n").as_bytes())
                .await
                .unwrap();
            let mut reply = String::new();
            connection.read_to_string(&mut reply).await.unwrap();
            reply
        })
        .await;
        assert!(
            reply.starts_with("error ") && reply.contains(wanted),
            "{line}: {reply}"
        );
    }
    assert!(untouched.exposed.lock().unwrap().is_empty());

    // An agent that does not manage shares says so; a request too long for the agent is not sent.
    struct Plain;
    impl Opener for Plain {
        async fn open(&self, _target: &str) -> Result<Stream, String> {
            Err("no".to_string())
        }
    }
    let error = with_agent(Arc::new(Plain), async |socket, uid| {
        request_expose_as(socket, &a_spec("app"), uid).await
    })
    .await
    .unwrap_err();
    assert!(
        matches!(error, AskError::Failed(ref e) if format!("{e:#}").contains("does not manage shares"))
    );
    let mut long = a_spec("app");
    long.alpn = (0..60).map(|n| format!("protocol-{n:04}")).collect();
    let dir = tempfile::tempdir().unwrap();
    let uid = current_uid().await.unwrap();
    let error = request_expose_as(&dir.path().join("none.sock"), &long, uid)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AskError::Failed(ref e) if format!("{e:#}").contains("longer than the agent takes"))
    );
    // A label with a space or a newline does not become two requests.
    let error = request_unexpose_as(&dir.path().join("none.sock"), "a\nstatus", uid)
        .await
        .unwrap_err();
    assert!(matches!(error, AskError::Failed(_)), "{error}");
}

#[tokio::test]
async fn nothing_listening_is_no_agent_for_the_share_requests_too() {
    let dir = tempfile::tempdir().unwrap();
    let uid = current_uid().await.unwrap();
    let missing = dir.path().join("none.sock");
    assert!(matches!(
        request_expose_as(&missing, &a_spec("a"), uid).await,
        Err(AskError::NoAgent)
    ));
    assert!(matches!(
        request_unexpose_as(&missing, "a", uid).await,
        Err(AskError::NoAgent)
    ));
    let stale = dir.path().join("stale.sock");
    drop(UnixListener::bind(&stale).unwrap());
    assert!(matches!(
        request_expose_as(&stale, &a_spec("a"), uid).await,
        Err(AskError::NoAgent)
    ));
}

#[tokio::test]
async fn the_status_reply_carries_the_shares_and_at_most_sixty_four() {
    let views: Vec<ShareView> = (0..70).map(|n| a_view(&format!("s{n}"))).collect();
    let opener = sharer(views.clone(), None);
    let got = with_agent(opener, async |socket, uid| {
        query_node_status_as(socket, uid).await
    })
    .await
    .unwrap();
    assert_eq!(got.shares.len(), MAX_SHARE_LINES);
    assert_eq!(got.shares[0], views[0]);
    assert_eq!(got.shares[63], views[63]);
    // An opener with no shares says none, and the relay part is as before.
    let got = with_agent(certs(Err("x".into()), None), async |socket, uid| {
        query_node_status_as(socket, uid).await
    })
    .await
    .unwrap();
    assert!(got.shares.is_empty());
}

/// An agent that lies: lines that are not shares, a share with a hostile reason, a line past the
/// limit. The client keeps what is well formed and shows nothing unprintable.
#[tokio::test]
async fn a_status_with_hostile_share_lines_yields_only_the_well_formed_ones() {
    let mut reply = b"attached yes\nshare label=ok mode=blind service=tls:ok state=rejected reason=bad\x1b[31m red\n".to_vec();
    reply.extend_from_slice(b"share label=Bad mode=blind service=tls:x state=accepted\n");
    reply.extend_from_slice(b"share \xff\xfe\n");
    reply.extend_from_slice(
        b"share label=two mode=tcp service=tcp:two state=pending names=a.b,evil\x1b\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("raw.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let uid = current_uid().await.unwrap();
    let agent = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 64];
        let _ = connection.read(&mut request).await;
        let _ = connection.write_all(&reply).await;
    });
    let got = timeout(WAIT, query_node_status_as(&socket, uid))
        .await
        .unwrap()
        .unwrap();
    agent.await.unwrap();
    assert_eq!(got.shares.len(), 2, "{:?}", got.shares);
    assert_eq!(got.shares[0].label, "ok");
    assert_eq!(got.shares[0].state, ShareState::Rejected);
    let reason = got.shares[0].reason.as_deref().unwrap();
    assert!(
        !reason.contains('\u{1b}') && reason.contains("red"),
        "{reason:?}"
    );
    assert_eq!(got.shares[1].names, ["a.b"]);
}
