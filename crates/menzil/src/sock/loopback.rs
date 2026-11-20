//! The Unix socket API over loopback TCP plus a token (D11 W2, docs/private/windows-agent-
//! transport-design.md). A "socket path" is a small file holding the port and a 256 bit token;
//! `bind` makes it, `connect` reads it. Compiled on every platform so the tests run on Linux; used
//! (through `crate::sock`) where there are no Unix sockets.
#![cfg_attr(unix, allow(dead_code))]

use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf as TcpRead, OwnedWriteHalf as TcpWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;

pub type OwnedReadHalf = TcpRead;
pub type OwnedWriteHalf = TcpWrite;

const TOKEN_BYTES: usize = 32;
const NONCE: usize = 32;
/// The whole mutual proof, per connection.
const AUTH_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_UNAUTHENTICATED: usize = 256;
/// A parked authenticated stream waits this long for `accept` to take it.
const QUEUE_TIMEOUT: Duration = Duration::from_secs(5);
/// What a socket file can be at most: `65535 <64 hex>\n`.
const FILE_MAX: u64 = 80;

/// Who is on the other end: nobody to tell apart, the token already did. Invariant: a
/// [`UnixStream`] outside `pair()` exists only after the mutual proof, and its field is private,
/// so `admit` and `serve_user` passing every uid here is safe (review W2-6).
#[derive(Debug, Clone, Copy)]
pub struct UCred(());

impl UCred {
    pub fn uid(&self) -> u32 {
        0
    }
    pub fn pid(&self) -> Option<i32> {
        None
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The proof of one side: a hash over the token and both nonces, the label telling the sides
/// apart so that one cannot be replayed as the other. The token itself never travels.
fn proof(label: u8, token: &[u8], server: &[u8], client: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update([label]);
    hash.update(token);
    hash.update(server);
    hash.update(client);
    hash.finalize().into()
}

/// What a socket file holds, parsed: the port and the token text. Exactly `<port> <64 hex>\n`.
fn parse(text: &str) -> Option<(u16, &str)> {
    let (port, token) = text.strip_suffix('\n')?.split_once(' ')?;
    let ok = token.len() == TOKEN_BYTES * 2
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    (ok && port.bytes().all(|b| b.is_ascii_digit()))
        .then(|| port.parse().ok().map(|port| (port, token)))
        .flatten()
}

/// Whether `path` is a file this module wrote: a small regular file of exactly that form. What
/// is not is never touched (review W2-4).
pub fn is_socket_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    meta.is_file()
        && meta.len() <= FILE_MAX
        && std::fs::read_to_string(path).is_ok_and(|text| parse(&text).is_some())
}

/// A fingerprint of the file's contents, so that shutdown removes the file it made and not one
/// another instance put in its place (review W2-5).
pub fn file_digest(path: &Path) -> io::Result<[u8; 32]> {
    Ok(Sha256::digest(std::fs::read(path)?).into())
}

#[derive(Debug)]
pub struct UnixStream(TcpStream);

impl UnixStream {
    /// Reads the file at `path`, dials the port in it and runs the mutual proof: the server must
    /// show it knows the token too, or the connection is dropped (`InvalidData`), so a process
    /// that took over the port of a dead agent gets nothing (review W2-1).
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<UnixStream> {
        let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_string());
        let path = path.as_ref();
        if std::fs::metadata(path)?.len() > FILE_MAX {
            return Err(bad("not a menzil socket file"));
        }
        let text = std::fs::read_to_string(path)?;
        let (port, token) = parse(&text).ok_or_else(|| bad("not a menzil socket file"))?;
        let mut stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
        let proven = tokio::time::timeout(AUTH_TIMEOUT, async {
            let mut server = [0u8; NONCE];
            stream.read_exact(&mut server).await?;
            let mut client = [0u8; NONCE];
            rand::rng().fill_bytes(&mut client);
            let mine = proof(b'c', token.as_bytes(), &server, &client);
            stream.write_all(&client).await?;
            stream.write_all(&mine).await?;
            let mut theirs = [0u8; 32];
            stream.read_exact(&mut theirs).await?;
            let want = proof(b's', token.as_bytes(), &server, &client);
            Ok::<bool, io::Error>(equal(&theirs, &want))
        })
        .await;
        match proven {
            Ok(Ok(true)) => Ok(UnixStream(stream)),
            Ok(Ok(false)) | Ok(Err(_)) | Err(_) => Err(bad("the server did not prove the token")),
        }
    }

    /// Two connected streams of this process (no proof needed: nobody else holds them).
    pub fn pair() -> io::Result<(UnixStream, UnixStream)> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = listener.local_addr()?;
        let near = std::net::TcpStream::connect(addr)?;
        let (far, _) = listener.accept()?;
        for s in [&near, &far] {
            s.set_nonblocking(true)?;
        }
        Ok((
            UnixStream(TcpStream::from_std(near)?),
            UnixStream(TcpStream::from_std(far)?),
        ))
    }

    pub fn peer_cred(&self) -> io::Result<UCred> {
        Ok(UCred(()))
    }

    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        self.0.into_split()
    }
}

impl tokio::io::AsyncRead for UnixStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for UnixStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Debug)]
pub struct UnixListener {
    accepted: tokio::sync::Mutex<mpsc::Receiver<UnixStream>>,
    task: JoinHandle<()>,
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl UnixListener {
    /// Listens on a random loopback port and writes the socket file at `path` (new, owner only
    /// where the platform has modes); an existing file is an error (`AddrInUse`).
    pub fn bind(path: impl AsRef<Path>) -> io::Result<UnixListener> {
        let std_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        std_listener.set_nonblocking(true)?;
        let port = std_listener.local_addr()?.port();
        let mut raw = [0u8; TOKEN_BYTES];
        rand::rng().fill_bytes(&mut raw);
        let token = hex(&raw);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(path.as_ref()).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                io::Error::new(io::ErrorKind::AddrInUse, error)
            } else {
                error
            }
        })?;
        file.write_all(format!("{port} {token}\n").as_bytes())?;
        drop(file);
        let listener = TcpListener::from_std(std_listener)?;
        let (sender, receiver) = mpsc::channel(16);
        let task = tokio::spawn(accept_loop(listener, token.into_bytes().into(), sender));
        Ok(UnixListener {
            accepted: tokio::sync::Mutex::new(receiver),
            task,
        })
    }

    pub async fn accept(&self) -> io::Result<(UnixStream, ())> {
        match self.accepted.lock().await.recv().await {
            Some(stream) => Ok((stream, ())),
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "listener closed")),
        }
    }
}

async fn accept_loop(listener: TcpListener, token: Arc<[u8]>, out: mpsc::Sender<UnixStream>) {
    let slots = Arc::new(Semaphore::new(MAX_UNAUTHENTICATED));
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue; // over the cap: dropped
        };
        let (token, out) = (token.clone(), out.clone());
        tokio::spawn(async move {
            let proven = tokio::time::timeout(AUTH_TIMEOUT, serve_proof(stream, &token)).await;
            drop(permit);
            if let Ok(Ok(stream)) = proven {
                let _ = out.send_timeout(UnixStream(stream), QUEUE_TIMEOUT).await;
            }
        });
    }
}

/// The server half of the mutual proof: its nonce first (so a client can tell a live server from
/// a refusing one), then the client's nonce and proof, then its own proof.
async fn serve_proof(mut stream: TcpStream, token: &[u8]) -> io::Result<TcpStream> {
    let mut server = [0u8; NONCE];
    rand::rng().fill_bytes(&mut server);
    stream.write_all(&server).await?;
    let mut client = [0u8; NONCE];
    stream.read_exact(&mut client).await?;
    let mut theirs = [0u8; 32];
    stream.read_exact(&mut theirs).await?;
    if !equal(&theirs, &proof(b'c', token, &server, &client)) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    stream
        .write_all(&proof(b's', token, &server, &client))
        .await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[tokio::test]
    async fn a_client_with_the_file_gets_a_working_stream() {
        let d = dir();
        let path = d.path().join("a.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut client = UnixStream::connect(&path).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        let (mut read, mut write) = server.into_split();
        write.write_all(b"pong").await.unwrap();
        client.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");
        drop(read.read(&mut [0u8; 1]));
    }

    #[tokio::test]
    async fn a_connection_with_a_wrong_proof_or_none_never_reaches_accept() {
        let d = dir();
        let path = d.path().join("a.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let port: u16 = text.split(' ').next().unwrap().parse().unwrap();
        let mut wrong = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut nonce = [0u8; NONCE];
        wrong.read_exact(&mut nonce).await.unwrap(); // the server speaks first
        wrong.write_all(&[b'0'; NONCE + 32]).await.unwrap();
        let mut sink = [0u8; 1];
        assert_eq!(
            wrong.read(&mut sink).await.unwrap_or(0),
            0,
            "closed, no proof given"
        );
        let mut silent = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let _good = UnixStream::connect(&path).await.unwrap();
        let (_server, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("the good client is accepted")
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err(),
            "nobody else was let in"
        );
        drop(silent.shutdown().await);
    }

    #[tokio::test]
    async fn a_process_that_took_over_the_port_is_not_given_the_token_or_the_session() {
        let d = dir();
        let path = d.path().join("a.sock");
        let squatter = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = squatter.local_addr().unwrap().port();
        std::fs::write(&path, format!("{port} {}\n", "ab".repeat(32))).unwrap();
        let seen = tokio::spawn(async move {
            let (mut s, _) = squatter.accept().await.unwrap();
            s.write_all(&[7u8; NONCE]).await.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 256];
            // reads what the client sends before giving up; a fake proof back
            let _ = tokio::time::timeout(Duration::from_millis(300), async {
                loop {
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    if got.len() >= NONCE + 32 {
                        let _ = s.write_all(&[9u8; 32]).await;
                    }
                }
            })
            .await;
            got
        });
        let error = UnixStream::connect(&path).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let got = seen.await.unwrap();
        assert!(
            !got.windows(64).any(|w| w == "ab".repeat(32).as_bytes()),
            "the token itself never travels"
        );
    }

    #[tokio::test]
    async fn only_a_small_file_of_exactly_our_form_counts_as_a_socket_file() {
        let d = dir();
        let good = d.path().join("good");
        std::fs::write(&good, format!("4000 {}\n", "0f".repeat(32))).unwrap();
        assert!(is_socket_file(&good));
        for (name, text) in [
            ("junk", "nonsense".to_string()),
            ("upper", format!("4000 {}\n", "0F".repeat(32))),
            ("nonl", format!("4000 {}", "0f".repeat(32))),
            (
                "big",
                format!("4000 {}\n{}", "0f".repeat(32), "x".repeat(100)),
            ),
            ("port", format!("40x0 {}\n", "0f".repeat(32))),
        ] {
            let p = d.path().join(name);
            std::fs::write(&p, text).unwrap();
            assert!(!is_socket_file(&p), "{name}");
        }
        assert!(!is_socket_file(d.path()), "a directory");
        assert!(!is_socket_file(&d.path().join("missing")));
        let first = file_digest(&good).unwrap();
        std::fs::write(&good, format!("4001 {}\n", "0f".repeat(32))).unwrap();
        assert_ne!(first, file_digest(&good).unwrap());
    }

    #[tokio::test]
    async fn the_socket_file_is_new_private_and_a_second_bind_is_refused() {
        let d = dir();
        let path = d.path().join("a.sock");
        let _first = UnixListener::bind(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let (port, token) = text.trim().split_once(' ').unwrap();
        assert!(port.parse::<u16>().is_ok());
        assert_eq!(token.len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let again = UnixListener::bind(&path).unwrap_err();
        assert_eq!(again.kind(), io::ErrorKind::AddrInUse);
    }

    #[tokio::test]
    async fn a_stale_file_and_a_pair_behave() {
        let d = dir();
        let path = d.path().join("a.sock");
        drop(UnixListener::bind(&path).unwrap());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            UnixStream::connect(&path).await.is_err(),
            "nobody listens any more"
        );
        std::fs::write(d.path().join("junk"), "nonsense").unwrap();
        let junk = UnixStream::connect(d.path().join("junk"))
            .await
            .unwrap_err();
        assert_eq!(junk.kind(), io::ErrorKind::InvalidData);
        let (a, b) = UnixStream::pair().unwrap();
        assert_eq!(a.peer_cred().unwrap().uid(), b.peer_cred().unwrap().uid());
    }

    #[test]
    fn the_comparison_looks_at_every_byte_and_the_length() {
        assert!(equal(b"abc", b"abc"));
        assert!(!equal(b"abc", b"abd"));
        assert!(!equal(b"abc", b"ab"));
    }
}
