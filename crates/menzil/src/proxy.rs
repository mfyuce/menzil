//! `menzil proxy <exit>`: a local SOCKS5 proxy whose every `CONNECT` leaves through the egress
//! exit of another member (protocol.md 8), by way of the agent's `connect` request
//! ([`crate::agent`]).
//!
//! # What it is and is not
//!
//! The SOCKS5 server is written by hand and strict (RFC 1928): it speaks one method, no
//! authentication (0x00), and one command, `CONNECT`. `BIND` and `UDP ASSOCIATE` are answered
//! "command not supported" (0x07), SOCKS4 is closed without a word, and nothing the protocol does
//! not call for is read: the greeting and the request are read by exact counts, so bytes a client
//! pipelines behind its request stay where they are until the success reply has been sent and the
//! bridge starts (they are the first bytes it carries).
//!
//! # Names are never resolved here
//!
//! A destination that is a domain name is sent to the exit as a name, and the exit resolves it
//! (protocol.md 8: "names are sent as names and resolved at the exit, never locally"). Nothing in
//! this file looks a name up, and a test fails if a call that would is added. That is why an
//! application must be told to use `socks5h://` (resolve at the proxy): with `socks5://` the
//! application resolves the name itself, first, and sends an address, which both leaks the lookup
//! to the local resolver and takes the choice of what a name means from the exit. An address the
//! client sends (IPv4 or IPv6) goes to the exit as canonical text and nothing more is done to it:
//! the exit's own canonicalization and rules decide. The one thing done to a name is to fold its
//! ASCII letters to lower case, which the exit expects of the initiator (it refuses an upper
//! case name rather than fold it).
//!
//! # Replies
//!
//! The success reply (`05 00 00 01 00 00 00 00 00 00`, bound address 0.0.0.0:0) is sent only after
//! the agent has said `ok`, that is after the exit has dialled the destination and the stream is
//! open; before that the client has been told nothing. A refusal is mapped from the exit's code
//! name, which the agent's error line carries ([`reply_code`]):
//!
//! | what the exit said | SOCKS reply |
//! |---|---|
//! | `no_grant`, `forbidden` | 0x02 not allowed by ruleset |
//! | `target_unreachable` | 0x04 host unreachable |
//! | `invalid_target` | 0x08 address type not supported |
//! | `rate_limited`, `unknown_service`, anything else (no agent, no such member, a lost session) | 0x01 general failure |
//!
//! `unknown_service` is deliberately the general failure: it is what an exit that has egress
//! turned off, or no egress entry, says, and the proxy has no reason to tell the application more
//! than "failed". After a failure reply the connection is closed in an orderly way (a FIN after
//! the reply, so that it is read); a connection that goes wrong after the success reply is reset
//! like `reach` does it, so the program cannot take a truncated answer for a whole one.
//!
//! # The listener
//!
//! Loopback only ([`parse_listen`]): the proxy has no authentication, so whoever can reach the
//! port gets this user's `egress:*` grant. A TCP port on 127.0.0.1 is open to every user of the
//! machine (as with `menzil reach`); a hostname other than the exact `localhost` is refused, and
//! `localhost` is taken to be 127.0.0.1 without asking a resolver. At most [`MAX_CONNECTIONS`]
//! connections at once; the next is closed at once.
//!
//! # Time
//!
//! The greeting and the request together must arrive within [`HANDSHAKE_TIMEOUT`] of the
//! connection being accepted, else it is dropped. The wait for the exit is bounded by the agent:
//! it gives up on an open after 60 seconds and says so, and [`crate::agent::open_connect`] gives
//! up on the agent after 70, so a connection that waits for a hanging exit holds its place for
//! 70 seconds at most (and a stop ends it at once).

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::agent::{self, End};
use crate::text;

/// How many connections are carried at once.
pub const MAX_CONNECTIONS: usize = 128;
/// How long the greeting and the request have, together, from the connection being accepted.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a stop waits for the connections to be reset.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long, and how much, a refused connection's remaining input is read and thrown away before
/// it is closed (see [`close_after_reply`]).
const DRAIN_TIME: Duration = Duration::from_secs(1);
const DRAIN_BYTES: usize = 64 * 1024;
/// How long `run` waits after a failed `accept` before it tries again.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);
/// How often a failing `accept` is reported.
const ACCEPT_REPORT_INTERVAL: Duration = Duration::from_secs(10);
/// The longest host the log line shows.
const LOG_HOST_BYTES: usize = 255;

const SOCKS_VERSION: u8 = 5;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// The SOCKS reply codes this proxy sends.
mod code {
    pub const SUCCEEDED: u8 = 0x00;
    pub const GENERAL_FAILURE: u8 = 0x01;
    pub const NOT_ALLOWED: u8 = 0x02;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// A SOCKS5 reply: version, code, reserved, address type IPv4 and the bound address 0.0.0.0:0.
fn reply_bytes(code: u8) -> [u8; 10] {
    [SOCKS_VERSION, code, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0]
}

/// The SOCKS reply code for a refusal the agent reported, by the exit's code name. The agent's
/// text for a refusal by the exit is `refused by the other end: <code> (<the exit's words>)`; the
/// code is read only from there, never from the words after it (the exit's text is not ours), and
/// anything that does not have that shape is a general failure. See the module documentation for
/// the table.
pub fn reply_code(message: &str) -> u8 {
    let Some(rest) = message.strip_prefix("refused by the other end: ") else {
        return code::GENERAL_FAILURE;
    };
    match rest.split(' ').next().unwrap_or("") {
        "no_grant" | "forbidden" => code::NOT_ALLOWED,
        "target_unreachable" => code::HOST_UNREACHABLE,
        "invalid_target" => code::ADDRESS_TYPE_NOT_SUPPORTED,
        _ => code::GENERAL_FAILURE,
    }
}

/// Where a destination is opened: the agent, or (in the tests) something that says what a real
/// one could.
pub trait Exit: Send + Sync + 'static {
    /// What an opened destination is.
    type Open: Open;

    /// Asks the exit to dial `host`:`port` (a name or an address as text; `host` and `port` have
    /// passed [`agent::validate_target`]). Returns when the destination is open or when it is
    /// not, with the words for the log; the text of a refusal by the exit has the shape
    /// [`reply_code`] reads.
    fn connect(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Self::Open, String>> + Send;
}

/// An open destination.
pub trait Open: Send + 'static {
    /// Carries `input` to it and its bytes to `output`, both directions to their end
    /// ([`agent::Opened::bridge`]).
    fn bridge<R, W>(
        self,
        input: &mut R,
        output: &mut W,
    ) -> impl Future<Output = Result<End>> + Send
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send;
}

/// The exit `who` through the agent at `socket`.
pub struct AgentExit {
    socket: PathBuf,
    who: String,
}

impl AgentExit {
    /// The exit `who` (a member as `menzil open` takes it) through the agent at `socket`.
    pub fn new(socket: &Path, who: &str) -> Self {
        Self {
            socket: socket.to_path_buf(),
            who: who.to_string(),
        }
    }
}

impl Exit for AgentExit {
    type Open = agent::Opened;

    async fn connect(&self, host: &str, port: u16) -> Result<agent::Opened, String> {
        agent::open_connect(&self.socket, &self.who, host, port)
            .await
            .map_err(|error| format!("{error:#}"))
    }
}

impl Open for agent::Opened {
    async fn bridge<R, W>(self, input: &mut R, output: &mut W) -> Result<End>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        agent::Opened::bridge(self, input, output).await
    }
}

/// What is asked for: a destination, as the text the exit is sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// An address in the canonical text of `std::net` (IPv6 without brackets), or a name as it
    /// came, never resolved.
    pub host: String,
    /// The port, 1 to 65535.
    pub port: u16,
}

/// Why a handshake did not end in a request.
#[derive(Debug, PartialEq, Eq)]
enum Fault {
    /// Closed without a word: not a SOCKS5 client at all, or a client that went away.
    Silent(&'static str),
    /// The client was told why (a SOCKS reply was sent) and is closed.
    Replied(&'static str),
    /// The connection failed or ended in the middle of the handshake.
    Gone,
}

async fn send_reply<W: AsyncWrite + Unpin>(write: &mut W, code: u8) -> io::Result<()> {
    write.write_all(&reply_bytes(code)).await?;
    write.flush().await
}

/// A failure reply, then the fault.
async fn refuse<W: AsyncWrite + Unpin>(
    write: &mut W,
    code: u8,
    why: &'static str,
) -> Result<Request, Fault> {
    match send_reply(write, code).await {
        Ok(()) => Err(Fault::Replied(why)),
        Err(_) => Err(Fault::Gone),
    }
}

/// Reads exactly `buffer.len()` bytes and not one more.
async fn take<R: AsyncRead + Unpin>(read: &mut R, buffer: &mut [u8]) -> Result<(), Fault> {
    read.read_exact(buffer)
        .await
        .map(|_| ())
        .map_err(|_| Fault::Gone)
}

/// The greeting and the request, by exact counts. Writes the replies (the method selection, and
/// a failure reply for a request that is refused) itself.
async fn handshake<R, W>(read: &mut R, write: &mut W) -> Result<Request, Fault>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Greeting: VER NMETHODS METHODS...
    let mut head = [0u8; 2];
    take(read, &mut head[..1]).await?;
    if head[0] != SOCKS_VERSION {
        // SOCKS4 (0x04) or anything that is not SOCKS5: not answered.
        return Err(Fault::Silent("the client did not speak SOCKS5"));
    }
    take(read, &mut head[1..]).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    take(read, &mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        let sent = write
            .write_all(&[SOCKS_VERSION, METHOD_NONE_ACCEPTABLE])
            .await;
        let _ = write.flush().await;
        return match sent {
            Ok(()) => Err(Fault::Replied(
                "the client offered no method this proxy takes",
            )),
            Err(_) => Err(Fault::Gone),
        };
    }
    write
        .write_all(&[SOCKS_VERSION, METHOD_NO_AUTH])
        .await
        .map_err(|_| Fault::Gone)?;
    write.flush().await.map_err(|_| Fault::Gone)?;

    // Request: VER CMD RSV ATYP, then the address and the port.
    let mut header = [0u8; 4];
    take(read, &mut header).await?;
    let [version, command, reserved, address_type] = header;
    if version != SOCKS_VERSION {
        return Err(Fault::Silent("the request was not SOCKS5"));
    }
    if reserved != 0 {
        return refuse(write, code::GENERAL_FAILURE, "the reserved byte was not 0").await;
    }
    if command != CMD_CONNECT {
        // BIND, UDP ASSOCIATE and anything else.
        return refuse(
            write,
            code::COMMAND_NOT_SUPPORTED,
            "only CONNECT is supported",
        )
        .await;
    }
    let host = match address_type {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            take(read, &mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            take(read, &mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            take(read, &mut length).await?;
            if length[0] == 0 {
                return refuse(write, code::GENERAL_FAILURE, "a domain of length 0").await;
            }
            let mut name = vec![0u8; usize::from(length[0])];
            take(read, &mut name).await?;
            let Ok(name) = String::from_utf8(name) else {
                return refuse(
                    write,
                    code::ADDRESS_TYPE_NOT_SUPPORTED,
                    "a domain that is not UTF-8",
                )
                .await;
            };
            // Names are case insensitive and an application sends them as typed; the exit
            // refuses an upper case name rather than fold it ("the initiator side is expected
            // to lowercase a name", `menzil_node::egress`), so this is the folding. ASCII only:
            // nothing else of the name is touched.
            name.to_ascii_lowercase()
        }
        _ => {
            return refuse(
                write,
                code::ADDRESS_TYPE_NOT_SUPPORTED,
                "an address type that is not supported",
            )
            .await;
        }
    };
    let mut port = [0u8; 2];
    take(read, &mut port).await?;
    let port = u16::from_be_bytes(port);
    if port == 0 {
        return refuse(write, code::GENERAL_FAILURE, "port 0").await;
    }
    // The same local check the agent makes, before anything is sent (it does not canonicalize:
    // the exit decides what a valid name is).
    if agent::validate_target(&host, port).is_err() {
        return refuse(
            write,
            code::ADDRESS_TYPE_NOT_SUPPORTED,
            "a destination that cannot be one",
        )
        .await;
    }
    Ok(Request { host, port })
}

/// How a connection ended, for the listener: whether closing it is orderly or a reset.
#[derive(Debug, PartialEq, Eq)]
enum Done {
    /// Carried to a clean end in both directions: close with a FIN.
    Clean,
    /// A failure reply was sent (and flushed, the output shut down, the input drained): close
    /// with a FIN after it, so that it is read.
    Replied,
    /// Anything else (the client went away, did not speak SOCKS5, took too long, the stream was
    /// reset): close with a reset.
    Dropped,
}

/// `host` as the log shows it: unsafe characters written out and at most 255 bytes.
fn log_host(host: &str) -> String {
    let mut shown = text::escaped(host);
    if shown.len() > LOG_HOST_BYTES {
        let mut end = LOG_HOST_BYTES;
        while !shown.is_char_boundary(end) {
            end -= 1;
        }
        shown.truncate(end);
    }
    shown
}

/// Ends a connection that was sent a failure reply, in order: the reply is flushed, the output is
/// shut down (a FIN, which the client reads after the reply), and what the client had already
/// sent behind its request (an application pipelines its first bytes) is read and thrown away,
/// for a second and 64 KiB at most. Without that the close finds unread input and TCP answers it
/// with an RST, which can reach the client before it has read the reply and cost it the reply.
/// Nothing that is thrown away goes anywhere.
async fn close_after_reply<R, W>(read: &mut R, write: &mut W) -> Done
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let _ = write.shutdown().await;
    let _ = timeout(DRAIN_TIME, async {
        let mut buffer = [0u8; 4096];
        let mut left = DRAIN_BYTES;
        while left > 0 {
            let at_most = buffer.len().min(left);
            match read.read(&mut buffer[..at_most]).await {
                Ok(0) | Err(_) => break,
                Ok(n) => left -= n,
            }
        }
    })
    .await;
    Done::Replied
}

/// One connection, from the greeting to the end of the bridge. `deadline` bounds the greeting and
/// the request together. Nothing of the payload is ever logged.
async fn serve_socks<R, W, E>(
    read: &mut R,
    write: &mut W,
    exit: &E,
    peer: &str,
    deadline: Duration,
) -> Done
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
    E: Exit,
{
    let request = match timeout(deadline, handshake(read, write)).await {
        Err(_) => {
            eprintln!("menzil proxy: closed a connection from {peer}: no complete request in time");
            return Done::Dropped;
        }
        Ok(Ok(request)) => request,
        Ok(Err(Fault::Replied(why))) => {
            eprintln!("menzil proxy: refused a connection from {peer}: {why}");
            return close_after_reply(read, write).await;
        }
        Ok(Err(Fault::Silent(why))) => {
            eprintln!("menzil proxy: closed a connection from {peer}: {why}");
            return Done::Dropped;
        }
        Ok(Err(Fault::Gone)) => return Done::Dropped,
    };
    let Request { host, port } = request;
    let open = match exit.connect(&host, port).await {
        Ok(open) => open,
        Err(message) => {
            eprintln!(
                "menzil proxy: {peer} to {}:{port} failed: {}",
                log_host(&host),
                text::one_line(&message, 300)
            );
            return match send_reply(write, reply_code(&message)).await {
                Ok(()) => close_after_reply(read, write).await,
                Err(_) => Done::Dropped,
            };
        }
    };
    // Only now, with the destination open, does the client hear that it is.
    if send_reply(write, code::SUCCEEDED).await.is_err() {
        // Dropping `open` has the agent reset the stream.
        return Done::Dropped;
    }
    match open.bridge(read, write).await {
        Ok(End::Clean) => Done::Clean,
        Ok(End::Reset(why)) => {
            eprintln!(
                "menzil proxy: {peer} to {}:{port} was reset: {}",
                log_host(&host),
                text::one_line(&why, 300)
            );
            Done::Dropped
        }
        Err(error) => {
            eprintln!(
                "menzil proxy: {peer} to {}:{port} failed: {}",
                log_host(&host),
                text::one_line(&format!("{error:#}"), 300)
            );
            Done::Dropped
        }
    }
}

/// The address `menzil proxy` may listen on, from `--listen`: loopback only. `127.0.0.1:1080`
/// style (any 127.0.0.0/8 address) and `[::1]:1080`; the one hostname taken is exactly
/// `localhost`, which is 127.0.0.1 here (no lookup: this file resolves nothing). Anything else,
/// `0.0.0.0` and `::` and a LAN address and every other name included, is refused with the
/// reason, and nothing is bound.
pub fn parse_listen(listen: &str) -> Result<SocketAddr> {
    let (host, port) = listen.rsplit_once(':').with_context(|| {
        format!("--listen {listen:?} is not ADDR:PORT, for example 127.0.0.1:1080")
    })?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("--listen {listen:?}: {port:?} is not a port (0 to 65535)"))?;
    let ip = if host == "localhost" {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        let bare = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match bare.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => bail!(
                "--listen {listen:?}: {host:?} is neither a loopback address nor `localhost`; the proxy listens on loopback only"
            ),
        }
    };
    if !ip.is_loopback() {
        bail!(
            "--listen {listen:?}: {ip} is not a loopback address; the proxy has no authentication, so it listens on 127.0.0.1 or ::1 only"
        );
    }
    Ok(SocketAddr::new(ip, port))
}

/// Binds the listener for `--listen` (see [`parse_listen`]); nothing is bound when it is refused.
pub async fn bind(listen: &str) -> Result<TcpListener> {
    let address = parse_listen(listen)?;
    TcpListener::bind(address)
        .await
        .with_context(|| format!("listening on {address}"))
}

/// Carries every connection `listener` accepts through the exit `who` of the agent at `socket`
/// until `stop` completes, then resets whatever is still open.
pub async fn run(
    socket: &Path,
    who: &str,
    listener: TcpListener,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    run_with(Arc::new(AgentExit::new(socket, who)), listener, stop).await
}

/// [`run`] for any [`Exit`]. A failed `accept` is reported and tried again, never the end of the
/// loop; a connection is made to reset when it is closed from the moment it is accepted and is
/// closed in order only when it ended cleanly or was told why (the reasons are in `reach`).
pub async fn run_with<E: Exit>(
    exit: Arc<E>,
    listener: TcpListener,
    stop: impl Future<Output = ()>,
) -> Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let (stop_tx, stop_rx) = watch::channel(false);
    let mut connections = JoinSet::new();
    let mut last_report: Option<Instant> = None;
    tokio::pin!(stop);
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            () = &mut stop => break,
        };
        let (connection, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                if last_report.is_none_or(|at| at.elapsed() >= ACCEPT_REPORT_INTERVAL) {
                    eprintln!(
                        "menzil proxy: accepting a connection failed, trying again: {}",
                        text::one_line(&error.to_string(), 300)
                    );
                    last_report = Some(Instant::now());
                }
                tokio::select! {
                    () = tokio::time::sleep(ACCEPT_RETRY) => {}
                    () = &mut stop => break,
                }
                continue;
            }
        };
        let _ = connection.set_nodelay(true);
        reset_on_close(&connection, true);
        // Finished connections out of the set, so that it does not grow with every one served.
        while connections.try_join_next().is_some() {}
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            eprintln!("menzil proxy: too many connections, refusing one from {peer}");
            continue;
        };
        let (exit, mut stop) = (exit.clone(), stop_rx.clone());
        connections.spawn(async move {
            carry(connection, peer.to_string(), &*exit, &mut stop).await;
            drop(permit);
        });
    }
    let _ = stop_tx.send(true);
    let _ = tokio::time::timeout(STOP_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    Ok(())
}

/// Makes closing `connection` send an RST (`true`) or the usual orderly end (`false`).
fn reset_on_close(connection: &TcpStream, reset: bool) {
    let linger = reset.then_some(Duration::ZERO);
    let _ = socket2::SockRef::from(connection).set_linger(linger);
}

/// One accepted connection, to its end.
async fn carry<E: Exit>(
    mut connection: TcpStream,
    peer: String,
    exit: &E,
    stop: &mut watch::Receiver<bool>,
) {
    let done = {
        // Borrowed halves: dropping an owned write half would shut it down (a FIN).
        let (mut read, mut write) = tokio::io::split(&mut connection);
        tokio::select! {
            done = serve_socks(&mut read, &mut write, exit, &peer, HANDSHAKE_TIMEOUT) => Some(done),
            _ = stop.wait_for(|stopped| *stopped) => None,
        }
    };
    if let Some(Done::Clean | Done::Replied) = done {
        reset_on_close(&connection, false);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncBufReadExt, BufReader, duplex};
    use tokio::net::UnixListener;
    use tokio::sync::mpsc;

    use super::*;

    const WAIT: Duration = Duration::from_secs(10);
    /// What a test gives the greeting and the request where it is not the point.
    const SHORT: Duration = Duration::from_millis(200);

    // ---- a fake exit -------------------------------------------------------------------------

    /// What the fake exit does when asked.
    #[derive(Clone)]
    enum Say {
        /// Open, and the bridge echoes.
        Open,
        /// Refuse with this text.
        Refuse(&'static str),
    }

    struct FakeExit {
        say: Say,
        /// The destinations asked for, in order.
        asked: Mutex<Vec<(String, u16)>>,
        /// Held back until a permit is added, if set.
        gate: Option<Arc<Semaphore>>,
        /// What the bridges got, and whether any ran.
        bridged: Arc<Mutex<Vec<u8>>>,
        bridges: Arc<AtomicUsize>,
    }

    impl FakeExit {
        fn new(say: Say) -> Arc<Self> {
            Arc::new(Self {
                say,
                asked: Mutex::new(Vec::new()),
                gate: None,
                bridged: Arc::new(Mutex::new(Vec::new())),
                bridges: Arc::new(AtomicUsize::new(0)),
            })
        }

        fn gated(say: Say) -> (Arc<Self>, Arc<Semaphore>) {
            let gate = Arc::new(Semaphore::new(0));
            let exit = Arc::new(Self {
                say,
                asked: Mutex::new(Vec::new()),
                gate: Some(gate.clone()),
                bridged: Arc::new(Mutex::new(Vec::new())),
                bridges: Arc::new(AtomicUsize::new(0)),
            });
            (exit, gate)
        }

        fn asked(&self) -> Vec<(String, u16)> {
            self.asked.lock().unwrap().clone()
        }
    }

    struct FakeOpen {
        bridged: Arc<Mutex<Vec<u8>>>,
        bridges: Arc<AtomicUsize>,
    }

    impl Exit for FakeExit {
        type Open = FakeOpen;

        async fn connect(&self, host: &str, port: u16) -> Result<FakeOpen, String> {
            self.asked.lock().unwrap().push((host.to_string(), port));
            if let Some(gate) = &self.gate {
                gate.acquire().await.unwrap().forget();
            }
            match &self.say {
                Say::Refuse(text) => Err((*text).to_string()),
                Say::Open => Ok(FakeOpen {
                    bridged: self.bridged.clone(),
                    bridges: self.bridges.clone(),
                }),
            }
        }
    }

    impl Open for FakeOpen {
        async fn bridge<R, W>(self, input: &mut R, output: &mut W) -> Result<End>
        where
            R: AsyncRead + Unpin + Send,
            W: AsyncWrite + Unpin + Send,
        {
            self.bridges.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0u8; 1024];
            loop {
                let n = input.read(&mut buffer).await?;
                if n == 0 {
                    output.shutdown().await?;
                    return Ok(End::Clean);
                }
                self.bridged.lock().unwrap().extend_from_slice(&buffer[..n]);
                output.write_all(&buffer[..n]).await?;
            }
        }
    }

    impl FakeExit {
        /// Whether any bridge has run (the success reply was sent and the bytes carried).
        fn bridge_started(&self) -> bool {
            self.bridges.load(Ordering::SeqCst) > 0
        }
    }

    // ---- driving serve_socks over memory -----------------------------------------------------

    /// Runs one connection over memory: `input` is what the client sends (then it closes its
    /// side), and what comes back is what the server wrote.
    async fn drive(exit: &FakeExit, input: &[u8], deadline: Duration) -> (Done, Vec<u8>) {
        let (mut client, server) = duplex(1 << 16);
        let (mut read, mut write) = tokio::io::split(server);
        let input = input.to_vec();
        let feeder = tokio::spawn(async move {
            let _ = client.write_all(&input).await;
            let _ = client.shutdown().await;
            let mut out = Vec::new();
            let _ = client.read_to_end(&mut out).await;
            out
        });
        let done = serve_socks(&mut read, &mut write, exit, "test", deadline).await;
        drop((read, write));
        let out = timeout(WAIT, feeder).await.unwrap().unwrap();
        (done, out)
    }

    fn greeting(methods: &[u8]) -> Vec<u8> {
        let mut out = vec![5, methods.len() as u8];
        out.extend_from_slice(methods);
        out
    }

    fn request(command: u8, address: &[u8], port: u16) -> Vec<u8> {
        let mut out = vec![5, command, 0];
        out.extend_from_slice(address);
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    fn domain(name: &[u8]) -> Vec<u8> {
        let mut out = vec![ATYP_DOMAIN, name.len() as u8];
        out.extend_from_slice(name);
        out
    }

    fn ipv4(octets: [u8; 4]) -> Vec<u8> {
        let mut out = vec![ATYP_IPV4];
        out.extend_from_slice(&octets);
        out
    }

    fn ipv6(octets: [u8; 16]) -> Vec<u8> {
        let mut out = vec![ATYP_IPV6];
        out.extend_from_slice(&octets);
        out
    }

    const METHOD_OK: [u8; 2] = [5, 0];
    const OK_REPLY: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

    fn failure(code: u8) -> [u8; 10] {
        [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
    }

    /// `[METHOD_OK]` then a failure reply.
    fn greeted_then(code: u8) -> Vec<u8> {
        let mut out = METHOD_OK.to_vec();
        out.extend_from_slice(&failure(code));
        out
    }

    fn all(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    // ---- the parser, as a table --------------------------------------------------------------

    #[tokio::test]
    async fn valid_requests_reach_the_exit_as_text_and_get_the_success_reply_after_it_opened() {
        let v6: [u8; 16] = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let mapped: [u8; 16] = "::ffff:127.0.0.1".parse::<Ipv6Addr>().unwrap().octets();
        let longest = "x".repeat(253);
        let long_name = "a".repeat(63) + "." + &"b".repeat(63) + "." + &"c".repeat(63);
        let cases: Vec<(Vec<u8>, &str, u16)> = vec![
            (
                request(1, &ipv4([93, 184, 216, 34]), 443),
                "93.184.216.34",
                443,
            ),
            (request(1, &ipv4([0, 0, 0, 0]), 1), "0.0.0.0", 1),
            (request(1, &ipv4([127, 0, 0, 1]), 65535), "127.0.0.1", 65535),
            (request(1, &ipv6(v6), 80), "2001:db8::1", 80),
            // Handed to the exit as it is written; the exit's canonicalization is the authority.
            (request(1, &ipv6(mapped), 22), "::ffff:127.0.0.1", 22),
            (request(1, &domain(b"example.org"), 443), "example.org", 443),
            // An upper case name is lowercased (the exit refuses it otherwise), nothing else is.
            (request(1, &domain(b"Example.ORG"), 443), "example.org", 443),
            (request(1, &domain(b"a"), 7), "a", 7),
            (
                request(1, &domain(long_name.as_bytes()), 80),
                &long_name,
                80,
            ),
            (request(1, &domain(&[b'x'; 253]), 80), &longest, 80),
            (
                request(1, &domain("MÜNCHEN.Example".as_bytes()), 80),
                "mÜnchen.example",
                80,
            ),
        ];
        for (request, host, port) in cases {
            let exit = FakeExit::new(Say::Open);
            let input = all(&[&greeting(&[0]), &request]);
            let (done, out) = drive(&exit, &input, WAIT).await;
            assert_eq!(done, Done::Clean, "{host}");
            assert_eq!(exit.asked(), vec![(host.to_string(), port)], "{host}");
            assert_eq!(out, all(&[&METHOD_OK, &OK_REPLY]), "{host}");
        }
    }

    #[tokio::test]
    async fn the_greeting_is_checked_exactly() {
        let req = request(1, &domain(b"example.org"), 443);
        // Offered among others, anywhere in the list, 255 methods included.
        let mut many: Vec<u8> = (1..=254).collect();
        many.push(0);
        assert_eq!(many.len(), 255);
        for methods in [vec![0], vec![2, 0], vec![0, 2], vec![1, 2, 0, 3], many] {
            let exit = FakeExit::new(Say::Open);
            let (done, out) = drive(&exit, &all(&[&greeting(&methods), &req]), WAIT).await;
            assert_eq!(done, Done::Clean, "{methods:?}");
            assert_eq!(out, all(&[&METHOD_OK, &OK_REPLY]));
        }
        // 0x00 not offered (nothing, only username/password, 255 methods that exclude it): 05 FF,
        // and the request that follows is never read or acted on.
        let without: Vec<u8> = (1..=255).collect();
        assert_eq!(without.len(), 255);
        for methods in [vec![], vec![2], vec![1, 2, 3], vec![0xFF], without] {
            let exit = FakeExit::new(Say::Open);
            let (done, out) = drive(&exit, &all(&[&greeting(&methods), &req]), WAIT).await;
            assert_eq!(done, Done::Replied, "{methods:?}");
            assert_eq!(out, vec![5, 0xFF], "{methods:?}");
            assert!(exit.asked().is_empty());
        }
    }

    #[tokio::test]
    async fn a_client_that_is_not_socks5_is_closed_without_a_reply() {
        for first in [
            vec![4, 1, 0x01, 0xBB, 93, 184, 216, 34, 0],
            vec![0],
            vec![6, 1, 0],
            vec![0xFF, 1, 0],
            b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            b"CONNECT example.org:443 HTTP/1.1\r\n\r\n".to_vec(),
        ] {
            let exit = FakeExit::new(Say::Open);
            let (done, out) = drive(&exit, &first, WAIT).await;
            assert_eq!(done, Done::Dropped, "{first:?}");
            assert!(out.is_empty(), "{first:?}: {out:?}");
            assert!(exit.asked().is_empty());
        }
    }

    #[tokio::test]
    async fn a_request_that_is_not_allowed_is_answered_with_its_code_and_never_reaches_the_exit() {
        let greet = greeting(&[0]);
        let dom = domain(b"example.org");
        let bad_utf8 = domain(&[0xFF, 0xFE, b'a']);
        let with_nul = domain(b"exa\0mple.org");
        let with_space = domain(b"exa mple.org");
        let with_tab = domain(b"exa\tmple.org");
        let with_newline = domain(b"exa\nmple.org");
        let too_long = domain(&[b'a'; 254]);
        let longest_byte = domain(&[b'a'; 255]);
        let cases: Vec<(&str, Vec<u8>, u8)> = vec![
            ("BIND", request(2, &dom, 80), 0x07),
            ("UDP ASSOCIATE", request(3, &dom, 80), 0x07),
            ("unknown command 0", request(0, &dom, 80), 0x07),
            ("unknown command 4", request(4, &dom, 80), 0x07),
            ("unknown command 255", request(255, &dom, 80), 0x07),
            ("reserved byte 1", all(&[&[5, 1, 1], &dom, &[0, 80]]), 0x01),
            (
                "reserved byte 255",
                all(&[&[5, 1, 255], &dom, &[0, 80]]),
                0x01,
            ),
            // The reserved byte is judged before the command.
            (
                "reserved byte 1 with BIND",
                all(&[&[5, 2, 1], &dom, &[0, 80]]),
                0x01,
            ),
            (
                "domain of length 0",
                all(&[&[5, 1, 0, 3, 0], &[0, 80]]),
                0x01,
            ),
            ("domain that is not UTF-8", request(1, &bad_utf8, 80), 0x08),
            ("domain with NUL", request(1, &with_nul, 80), 0x08),
            ("domain with a space", request(1, &with_space, 80), 0x08),
            ("domain with a tab", request(1, &with_tab, 80), 0x08),
            ("domain with a newline", request(1, &with_newline, 80), 0x08),
            ("domain of 254 bytes", request(1, &too_long, 80), 0x08),
            ("domain of 255 bytes", request(1, &longest_byte, 80), 0x08),
            (
                "address type 0",
                all(&[&[5, 1, 0, 0], &[1, 2, 3, 4, 0, 80]]),
                0x08,
            ),
            (
                "address type 2",
                all(&[&[5, 1, 0, 2], &[1, 2, 3, 4, 0, 80]]),
                0x08,
            ),
            (
                "address type 5",
                all(&[&[5, 1, 0, 5], &[1, 2, 3, 4, 0, 80]]),
                0x08,
            ),
            (
                "address type 255",
                all(&[&[5, 1, 0, 255], &[1, 2, 3, 4, 0, 80]]),
                0x08,
            ),
            ("port 0 on a name", request(1, &dom, 0), 0x01),
            ("port 0 on IPv4", request(1, &ipv4([1, 2, 3, 4]), 0), 0x01),
            ("port 0 on IPv6", request(1, &ipv6([0; 16]), 0), 0x01),
        ];
        for (what, request, wanted) in cases {
            let exit = FakeExit::new(Say::Open);
            let (done, out) = drive(&exit, &all(&[&greet, &request]), WAIT).await;
            assert_eq!(done, Done::Replied, "{what}");
            assert_eq!(out, greeted_then(wanted), "{what}");
            assert!(exit.asked().is_empty(), "{what}");
        }
        // A request whose VER is not 5 is not a SOCKS5 conversation: closed, not answered.
        for version in [0u8, 4, 6, 255] {
            let exit = FakeExit::new(Say::Open);
            let bad = all(&[&[version, 1, 0], &dom, &[0, 80]]);
            let (done, out) = drive(&exit, &all(&[&greet, &bad]), WAIT).await;
            assert_eq!(done, Done::Dropped, "version {version}");
            assert_eq!(out, METHOD_OK.to_vec(), "version {version}");
            assert!(exit.asked().is_empty());
        }
    }

    #[tokio::test]
    async fn input_that_stops_anywhere_is_dropped_without_a_request_for_the_exit() {
        let full = all(&[&greeting(&[0]), &request(1, &domain(b"example.org"), 443)]);
        let greeting_len = greeting(&[0]).len();
        for cut in 0..full.len() {
            let exit = FakeExit::new(Say::Open);
            let (done, out) = drive(&exit, &full[..cut], WAIT).await;
            assert_eq!(done, Done::Dropped, "cut at {cut}");
            let wanted: Vec<u8> = if cut >= greeting_len {
                METHOD_OK.to_vec()
            } else {
                vec![]
            };
            assert_eq!(out, wanted, "cut at {cut}");
            assert!(exit.asked().is_empty(), "cut at {cut}");
        }
        // The same for the other address types.
        for address in [ipv4([1, 2, 3, 4]), ipv6([1; 16])] {
            let full = all(&[&greeting(&[0]), &request(1, &address, 80)]);
            for cut in 0..full.len() {
                let exit = FakeExit::new(Say::Open);
                let (done, _) = drive(&exit, &full[..cut], WAIT).await;
                assert_eq!(done, Done::Dropped, "cut at {cut}");
                assert!(exit.asked().is_empty());
            }
        }
        // And in the middle of a greeting that promises more methods than arrive.
        let exit = FakeExit::new(Say::Open);
        let (done, out) = drive(&exit, &[5, 10, 0, 1], WAIT).await;
        assert_eq!((done, out.as_slice()), (Done::Dropped, &[][..]));
    }

    #[tokio::test]
    async fn a_greeting_that_never_finishes_is_dropped_at_the_deadline() {
        // The deadline is the constant below; the tests give the same code a shorter one, since
        // this crate's tokio has no paused time.
        assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(10));
        for sent in [
            vec![],
            vec![5],
            vec![5, 3, 0],
            all(&[&greeting(&[0]), &[5, 1, 0]]),
        ] {
            let exit = FakeExit::new(Say::Open);
            let (mut client, server) = duplex(1 << 16);
            client.write_all(&sent).await.unwrap();
            let (mut read, mut write) = tokio::io::split(server);
            let began = Instant::now();
            // The client stays connected and silent: only the deadline ends it.
            let done = serve_socks(&mut read, &mut write, &*exit, "test", SHORT).await;
            assert_eq!(done, Done::Dropped, "{sent:?}");
            assert!(began.elapsed() >= SHORT && began.elapsed() < WAIT);
            assert!(exit.asked().is_empty());
            drop(client);
        }
    }

    #[tokio::test]
    async fn the_deadline_covers_the_request_too_but_not_the_wait_for_the_exit() {
        // A request that arrived in time is not cut off while the exit takes its time.
        let (exit, gate) = FakeExit::gated(Say::Open);
        let (mut client, server) = duplex(1 << 16);
        let (mut read, mut write) = tokio::io::split(server);
        let input = all(&[&greeting(&[0]), &request(1, &domain(b"example.org"), 443)]);
        client.write_all(&input).await.unwrap();
        let serving = {
            let exit = exit.clone();
            tokio::spawn(async move {
                let done = serve_socks(&mut read, &mut write, &*exit, "test", SHORT).await;
                (done, read, write)
            })
        };
        tokio::time::sleep(SHORT * 3).await;
        assert!(!serving.is_finished(), "dropped while the exit was working");
        gate.add_permits(1);
        client.shutdown().await.unwrap();
        let (done, _, _) = timeout(WAIT, serving).await.unwrap().unwrap();
        assert_eq!(done, Done::Clean);
    }

    // ---- ordering: success only after the exit, pipelined bytes ------------------------------

    #[tokio::test]
    async fn the_success_reply_waits_for_the_exit_and_pipelined_bytes_wait_with_it() {
        let (exit, gate) = FakeExit::gated(Say::Open);
        let (mut client, server) = duplex(1 << 16);
        let (mut read, mut write) = tokio::io::split(server);
        // The request and, right behind it, the first bytes of the application's own protocol.
        let input = all(&[
            &greeting(&[0]),
            &request(1, &domain(b"example.org"), 443),
            b"PIPELINED-DATA",
        ]);
        client.write_all(&input).await.unwrap();
        let serving = {
            let exit = exit.clone();
            tokio::spawn(
                async move { serve_socks(&mut read, &mut write, &*exit, "test", WAIT).await },
            )
        };
        // The method selection arrives; the success reply must not, while the exit is asked.
        let mut method = [0u8; 2];
        timeout(WAIT, client.read_exact(&mut method))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, METHOD_OK);
        while exit.asked().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut early = [0u8; 1];
        let early = timeout(Duration::from_millis(300), client.read(&mut early)).await;
        assert!(
            early.is_err(),
            "a reply came before the exit answered: {early:?}"
        );
        assert!(
            !exit.bridge_started(),
            "bytes were carried before the success reply"
        );
        assert!(exit.bridged.lock().unwrap().is_empty());

        gate.add_permits(1);
        let mut reply = [0u8; 10];
        timeout(WAIT, client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, OK_REPLY);
        // The pipelined bytes were not eaten by the parser: they are the first the bridge got,
        // whole, and they come back echoed after the reply.
        let mut echoed = [0u8; 14];
        timeout(WAIT, client.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"PIPELINED-DATA");
        client.shutdown().await.unwrap();
        assert_eq!(timeout(WAIT, serving).await.unwrap().unwrap(), Done::Clean);
        assert_eq!(exit.bridged.lock().unwrap().as_slice(), b"PIPELINED-DATA");
    }

    #[tokio::test]
    async fn bytes_pipelined_behind_every_address_type_reach_the_bridge_whole() {
        for address in [domain(b"example.org"), ipv4([10, 1, 2, 3]), ipv6([7; 16])] {
            let exit = FakeExit::new(Say::Open);
            let input = all(&[
                &greeting(&[0]),
                &request(1, &address, 8080),
                &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            ]);
            let (done, out) = drive(&exit, &input, WAIT).await;
            assert_eq!(done, Done::Clean);
            assert_eq!(
                exit.bridged.lock().unwrap().as_slice(),
                &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]
            );
            assert_eq!(&out[..12], &all(&[&METHOD_OK, &OK_REPLY])[..12]);
            assert_eq!(&out[12..], &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        }
    }

    // ---- refusals: the table -----------------------------------------------------------------

    #[test]
    fn a_refusal_maps_to_its_code_by_the_exits_code_name_and_only_by_that() {
        for (message, wanted) in [
            (
                "refused by the other end: no_grant (nope): this device holds no grant",
                0x02,
            ),
            (
                "refused by the other end: forbidden (target not allowed)",
                0x02,
            ),
            (
                "refused by the other end: target_unreachable (could not connect)",
                0x04,
            ),
            ("refused by the other end: invalid_target (bad host)", 0x08),
            ("refused by the other end: rate_limited (busy)", 0x01),
            (
                "refused by the other end: unknown_service (nothing here)",
                0x01,
            ),
            ("refused by the other end: shutting_down ()", 0x01),
            ("refused by the other end: something_new (x)", 0x01),
            ("refused by the other end: ", 0x01),
            ("no member called \"laptop\" (members: phone)", 0x01),
            ("this node is not connected to the relay (yet): check", 0x01),
            (
                "no agent is listening at /x: start it with `menzil node`",
                0x01,
            ),
            ("the stream could not be opened in time", 0x01),
            ("egress is not available", 0x01),
            ("", 0x01),
            // The exit's own words cannot choose the code: only the name right after the prefix.
            (
                "refused by the other end: unknown_service (forbidden)",
                0x01,
            ),
            ("refused by the other end: rate_limited (no_grant)", 0x01),
            ("refused by the other end: unknown_service forbidden", 0x01),
            ("refused by the other end: forbidden_x (a)", 0x01),
            ("refused by the other end:  forbidden (a)", 0x01),
            (
                "the agent said: refused by the other end: forbidden (a)",
                0x01,
            ),
            (
                "no member called \"refused by the other end: forbidden\"",
                0x01,
            ),
            ("Refused by the other end: forbidden (a)", 0x01),
        ] {
            assert_eq!(reply_code(message), wanted, "{message:?}");
        }
    }

    #[tokio::test]
    async fn each_refusal_text_gets_its_reply_code_and_the_connection_is_closed_after_it() {
        for (text, wanted) in [
            ("refused by the other end: no_grant (x)", 0x02),
            ("refused by the other end: forbidden (x)", 0x02),
            ("refused by the other end: invalid_target (x)", 0x08),
            ("refused by the other end: target_unreachable (x)", 0x04),
            ("refused by the other end: rate_limited (x)", 0x01),
            ("refused by the other end: unknown_service (x)", 0x01),
            ("anything else", 0x01),
        ] {
            let exit = FakeExit::new(Say::Refuse(text));
            let input = all(&[
                &greeting(&[0]),
                &request(1, &domain(b"no-such-host.invalid"), 443),
                b"PAYLOAD-THAT-MUST-NOT-GO-ANYWHERE",
            ]);
            let (done, out) = drive(&exit, &input, WAIT).await;
            assert_eq!(done, Done::Replied, "{text}");
            assert_eq!(out, greeted_then(wanted), "{text}");
            // The name went to the exit as a name, once.
            assert_eq!(
                exit.asked(),
                vec![("no-such-host.invalid".to_string(), 443)]
            );
            // No bridge ran, so not a byte of the payload was read by anything.
            assert!(!exit.bridge_started());
        }
    }

    // ---- no local DNS ------------------------------------------------------------------------

    #[tokio::test]
    async fn a_name_that_cannot_resolve_reaches_the_exit_as_that_name_and_its_refusal_is_the_answer()
     {
        // If a local lookup came first, this name would fail there (it ends in `.invalid`, which
        // never resolves) and the reply would be the lookup's, not the exit's `forbidden`.
        // `socks5h` semantics: the proxy resolves nothing.
        let exit = FakeExit::new(Say::Refuse("refused by the other end: forbidden (x)"));
        let input = all(&[
            &greeting(&[0]),
            &request(1, &domain(b"nothing.resolves.invalid"), 80),
        ]);
        let (_, out) = drive(&exit, &input, WAIT).await;
        assert_eq!(out, greeted_then(0x02));
        assert_eq!(
            exit.asked(),
            vec![("nothing.resolves.invalid".to_string(), 80)]
        );
    }

    #[test]
    fn nothing_in_this_file_looks_a_name_up() {
        // Structural: the production half of this file (before its tests) names no call that
        // resolves a name. The needles are built so that this test does not match itself.
        let source = include_str!("proxy.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        for needle in [
            ["lookup", "_host"].concat(),
            ["to_socket", "_addrs"].concat(),
            ["get", "addrinfo"].concat(),
            ["Resolver", "::"].concat(),
            ["resolve", "("].concat(),
            ["Tcp", "Stream::connect"].concat(),
        ] {
            assert!(
                !production.contains(&needle),
                "proxy.rs must resolve nothing and dial nothing itself: found `{needle}`"
            );
        }
    }

    // ---- --listen ----------------------------------------------------------------------------

    #[tokio::test]
    async fn only_loopback_may_be_listened_on() {
        for bad in [
            "0.0.0.0:1080",
            "[::]:1080",
            "192.168.1.5:1080",
            "10.0.0.1:1080",
            "8.8.8.8:1080",
            "example.com:1080",
            "localhost.example.com:1080",
            "LOCALHOST:1080",
            "Localhost:1080",
            "localhost.:1080",
            " localhost:1080",
            "127.0.0.1.example.com:1080",
            "[::ffff:127.0.0.1]:1080",
            "[::ffff:192.168.1.5]:1080",
            "[fe80::1]:1080",
            "128.0.0.1:1080",
            "1080",
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:99999",
            "127.0.0.1:-1",
            ":1080",
            "",
            "::1:1080x",
        ] {
            let error = parse_listen(bad).unwrap_err();
            assert!(
                format!("{error:#}").contains("--listen"),
                "{bad:?} was not refused in words: {error:#}"
            );
        }
        for (good, wanted) in [
            ("127.0.0.1:0", "127.0.0.1:0"),
            ("127.0.0.1:1080", "127.0.0.1:1080"),
            ("127.1.2.3:8080", "127.1.2.3:8080"),
            ("[::1]:0", "[::1]:0"),
            ("[::1]:1080", "[::1]:1080"),
            ("localhost:0", "127.0.0.1:0"),
            ("localhost:1080", "127.0.0.1:1080"),
        ] {
            assert_eq!(parse_listen(good).unwrap().to_string(), wanted, "{good}");
        }
        // Binding goes through the same check, and a refused address is not bound.
        let free = {
            let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap().port()
        };
        for bad in [
            format!("0.0.0.0:{free}"),
            format!("[::]:{free}"),
            format!("example.com:{free}"),
        ] {
            assert!(bind(&bad).await.is_err(), "{bad}");
        }
        // Nothing listens there, so the port is still free to take.
        let again = TcpListener::bind(("0.0.0.0", free)).await;
        assert!(again.is_ok(), "a refused --listen bound the port");
        for good in ["127.0.0.1:0", "[::1]:0", "localhost:0"] {
            let listener = bind(good).await.unwrap();
            assert!(listener.local_addr().unwrap().ip().is_loopback());
        }
    }

    // ---- the listener ------------------------------------------------------------------------

    async fn start_proxy<E: Exit>(
        exit: Arc<E>,
    ) -> (
        SocketAddr,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let listener = bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let task = tokio::spawn(run_with(exit, listener, async move {
            let _ = stop_rx.wait_for(|stopped| *stopped).await;
        }));
        (address, stop_tx, task)
    }

    async fn socks_connect(address: SocketAddr, host: &[u8], port: u16) -> (TcpStream, [u8; 10]) {
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&all(&[&greeting(&[0]), &request(1, &domain(host), port)]))
            .await
            .unwrap();
        let mut method = [0u8; 2];
        timeout(WAIT, client.read_exact(&mut method))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, METHOD_OK);
        let mut reply = [0u8; 10];
        timeout(WAIT, client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        (client, reply)
    }

    #[tokio::test]
    async fn a_connection_over_tcp_is_carried_both_ways_and_ends_cleanly() {
        let exit = FakeExit::new(Say::Open);
        let (address, stop, task) = start_proxy(exit.clone()).await;
        let (mut client, reply) = socks_connect(address, b"example.org", 443).await;
        assert_eq!(reply, OK_REPLY);
        client.write_all(b"hello through the proxy").await.unwrap();
        let mut echoed = vec![0u8; 23];
        timeout(WAIT, client.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(echoed, b"hello through the proxy");
        client.shutdown().await.unwrap();
        // The destination finished too: a clean end, not a reset.
        let mut rest = Vec::new();
        let ended = timeout(WAIT, client.read_to_end(&mut rest)).await.unwrap();
        assert!(ended.is_ok() && rest.is_empty(), "{ended:?} {rest:?}");
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_refused_connection_reads_its_reply_and_then_the_end() {
        let exit = FakeExit::new(Say::Refuse("refused by the other end: forbidden (x)"));
        let (address, stop, task) = start_proxy(exit).await;
        let (mut client, reply) = socks_connect(address, b"internal.example", 80).await;
        assert_eq!(reply, failure(0x02));
        let mut rest = Vec::new();
        let ended = timeout(WAIT, client.read_to_end(&mut rest)).await.unwrap();
        // An orderly close after the reply, not a reset that could eat it.
        assert!(ended.is_ok() && rest.is_empty(), "{ended:?}");
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_client_that_sent_data_behind_a_refused_request_still_reads_the_reply_and_the_end() {
        // The application pipelined its first bytes; closing a socket that holds unread input
        // makes TCP send an RST, and an RST that lands before the client has read the reply can
        // cost it the reply. The proxy reads that input away before it closes. The client here
        // reads late, when anything that was going to arrive has.
        for refuse in [
            "refused by the other end: forbidden (x)",
            "refused by the other end: unknown_service (x)",
        ] {
            let exit = FakeExit::new(Say::Refuse(refuse));
            let (address, stop, task) = start_proxy(exit).await;
            let mut client = TcpStream::connect(address).await.unwrap();
            let payload = vec![0x16u8; 20_000];
            client
                .write_all(&all(&[
                    &greeting(&[0]),
                    &request(1, &domain(b"example.org"), 443),
                    &payload,
                ]))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
            let mut reply = [0u8; 12];
            timeout(WAIT, client.read_exact(&mut reply))
                .await
                .unwrap()
                .expect("the reply must still be readable");
            assert_eq!(&reply[..2], &METHOD_OK);
            assert_eq!(reply[3], reply_code(refuse));
            let mut rest = Vec::new();
            let ended = timeout(WAIT, client.read_to_end(&mut rest)).await.unwrap();
            assert!(ended.is_ok() && rest.is_empty(), "{ended:?} {rest:?}");
            stop.send(true).unwrap();
            timeout(WAIT, task).await.unwrap().unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn a_refused_connection_has_its_pending_input_read_away_up_to_a_bound() {
        // Over a small pipe, so that a writer is held up by every byte nobody has read: what the
        // drain reads is what the writer gets to send.
        async fn drained(total: usize) -> (usize, Duration) {
            let (mut client, server) = duplex(1024);
            let (mut read, mut write) = tokio::io::split(server);
            let written = Arc::new(AtomicUsize::new(0));
            let writer = {
                let written = written.clone();
                tokio::spawn(async move {
                    let chunk = [7u8; 512];
                    while written.load(Ordering::SeqCst) < total {
                        if client.write_all(&chunk).await.is_err() {
                            return;
                        }
                        written.fetch_add(chunk.len(), Ordering::SeqCst);
                    }
                    // Done sending: the client closes.
                })
            };
            let began = Instant::now();
            let done = close_after_reply(&mut read, &mut write).await;
            let took = began.elapsed();
            assert_eq!(done, Done::Replied);
            tokio::time::sleep(Duration::from_millis(50)).await;
            writer.abort();
            (written.load(Ordering::SeqCst), took)
        }
        // What a client had pipelined (20 KB) is read away, up to its end, without waiting.
        let (written, took) = drained(20_000).await;
        assert!(
            written >= 20_000,
            "the pending input was not read: {written}"
        );
        assert!(
            took < DRAIN_TIME,
            "waited for a client that was done: {took:?}"
        );
        // A client that goes on sending is read only up to the bound, and then closed on.
        let (written, took) = drained(10 * DRAIN_BYTES).await;
        assert!(
            written <= DRAIN_BYTES + 2 * 1024,
            "read past the bound: {written}"
        );
        assert!(written >= DRAIN_BYTES, "stopped early: {written}");
        assert!(took < DRAIN_TIME, "{took:?}");
    }

    #[tokio::test]
    async fn the_hundred_and_twenty_ninth_connection_is_closed_at_once() {
        let exit = FakeExit::new(Say::Open);
        let (address, stop, task) = start_proxy(exit.clone()).await;
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            held.push(TcpStream::connect(address).await.unwrap());
        }
        // Let the listener take them all.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut extra = TcpStream::connect(address).await.unwrap();
        let _ = extra.write_all(&greeting(&[0])).await;
        let mut seen = [0u8; 2];
        let got = timeout(WAIT, extra.read(&mut seen)).await.unwrap();
        // Closed (end of file or a reset), never a method selection.
        assert!(
            !matches!(got, Ok(n) if n > 0),
            "the 129th was served: {got:?}"
        );
        // The held ones are still served: one that speaks gets its answer.
        let mut first = held.remove(0);
        first.write_all(&greeting(&[0])).await.unwrap();
        let mut method = [0u8; 2];
        timeout(WAIT, first.read_exact(&mut method))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, METHOD_OK);
        // A place freed is a place that can be used again.
        drop(first);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut again = TcpStream::connect(address).await.unwrap();
        again.write_all(&greeting(&[0])).await.unwrap();
        timeout(WAIT, again.read_exact(&mut method))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(method, METHOD_OK);
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
        drop(held);
    }

    #[tokio::test]
    async fn stopping_ends_a_connection_that_waits_for_the_exit() {
        let (exit, _gate) = FakeExit::gated(Say::Open);
        let (address, stop, task) = start_proxy(exit.clone()).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&all(&[
                &greeting(&[0]),
                &request(1, &domain(b"example.org"), 80),
            ]))
            .await
            .unwrap();
        let mut method = [0u8; 2];
        timeout(WAIT, client.read_exact(&mut method))
            .await
            .unwrap()
            .unwrap();
        while exit.asked().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
        // It was never told that the destination was open.
        let mut rest = Vec::new();
        let _ = timeout(WAIT, client.read_to_end(&mut rest)).await.unwrap();
        assert!(rest.is_empty(), "{rest:?}");
    }

    #[tokio::test]
    async fn a_socks4_greeting_over_tcp_is_closed_without_an_answer() {
        let exit = FakeExit::new(Say::Open);
        let (address, stop, task) = start_proxy(exit.clone()).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&[4, 1, 0x01, 0xBB, 93, 184, 216, 34, 0])
            .await
            .unwrap();
        let mut rest = Vec::new();
        let _ = timeout(WAIT, client.read_to_end(&mut rest)).await.unwrap();
        assert!(rest.is_empty(), "answered a SOCKS4 client: {rest:?}");
        assert!(exit.asked().is_empty());
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    }

    // ---- through a fake agent: what reaches it and what does not -----------------------------

    /// A fake agent socket that answers every request with `reply` and reports the request line
    /// and every byte that came after it.
    struct FakeAgent {
        _dir: tempfile::TempDir,
        socket: PathBuf,
        lines: mpsc::UnboundedReceiver<String>,
        rest: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    async fn fake_agent(reply: &'static str) -> FakeAgent {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("fake.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (lines_tx, lines) = mpsc::unbounded_channel();
        let (rest_tx, rest) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((connection, _)) = listener.accept().await else {
                    return;
                };
                let (lines_tx, rest_tx) = (lines_tx.clone(), rest_tx.clone());
                tokio::spawn(async move {
                    let (read, mut write) = connection.into_split();
                    let mut read = BufReader::new(read);
                    let mut line = String::new();
                    if read.read_line(&mut line).await.is_err() {
                        return;
                    }
                    let _ = lines_tx.send(line);
                    let _ = write.write_all(reply.as_bytes()).await;
                    let _ = write.flush().await;
                    // Whatever the client sends after the request, to its end.
                    let mut rest = Vec::new();
                    let _ = read.read_to_end(&mut rest).await;
                    let _ = rest_tx.send(rest);
                });
            }
        });
        FakeAgent {
            _dir: dir,
            socket,
            lines,
            rest,
        }
    }

    #[tokio::test]
    async fn through_an_agent_each_refusal_gets_its_code_and_no_payload_reaches_it() {
        for (reply, wanted) in [
            (
                "error refused by the other end: no_grant (x): this device holds no grant\n",
                0x02,
            ),
            ("error refused by the other end: forbidden (x)\n", 0x02),
            ("error refused by the other end: invalid_target (x)\n", 0x08),
            (
                "error refused by the other end: target_unreachable (x)\n",
                0x04,
            ),
            ("error refused by the other end: rate_limited (x)\n", 0x01),
            (
                "error refused by the other end: unknown_service (x)\n",
                0x01,
            ),
            ("error no member called \"exit\" (members: a, b)\n", 0x01),
            (
                "error this node is not connected to the relay (yet)\n",
                0x01,
            ),
            ("error the stream could not be opened in time\n", 0x01),
        ] {
            let mut agent = fake_agent(reply).await;
            let exit = Arc::new(AgentExit::new(&agent.socket, "exit"));
            let (address, stop, task) = start_proxy(exit).await;
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(&all(&[
                    &greeting(&[0]),
                    &request(1, &domain(b"example.org"), 8443),
                    b"PAYLOAD-THAT-MUST-NOT-REACH-THE-AGENT",
                ]))
                .await
                .unwrap();
            let mut got = Vec::new();
            timeout(WAIT, client.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, greeted_then(wanted), "{reply}");
            // The agent was asked once, for exactly this, and was sent nothing after the line.
            assert_eq!(
                timeout(WAIT, agent.lines.recv()).await.unwrap().unwrap(),
                "connect exit example.org 8443\n"
            );
            drop(client);
            stop.send(true).unwrap();
            timeout(WAIT, task).await.unwrap().unwrap().unwrap();
            let rest = timeout(WAIT, agent.rest.recv()).await.unwrap().unwrap();
            assert!(
                rest.is_empty(),
                "{reply}: the agent got {rest:?} after the request"
            );
        }
    }

    #[tokio::test]
    async fn no_agent_is_a_general_failure_and_the_proxy_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let exit = Arc::new(AgentExit::new(
            &dir.path().join("nobody-listens.sock"),
            "exit",
        ));
        let (address, stop, task) = start_proxy(exit).await;
        for _ in 0..2 {
            let (mut client, reply) = socks_connect(address, b"example.org", 80).await;
            assert_eq!(reply, failure(0x01));
            let mut rest = Vec::new();
            let _ = timeout(WAIT, client.read_to_end(&mut rest)).await.unwrap();
        }
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_address_the_client_sends_goes_to_the_agent_as_canonical_text_never_resolved() {
        let mut agent = fake_agent("error refused by the other end: forbidden (x)\n").await;
        let exit = Arc::new(AgentExit::new(&agent.socket, "exit"));
        let (address, stop, task) = start_proxy(exit).await;
        for (address_bytes, wanted) in [
            (ipv4([127, 0, 0, 1]), "connect exit 127.0.0.1 80\n"),
            (
                ipv6("::1".parse::<Ipv6Addr>().unwrap().octets()),
                "connect exit ::1 80\n",
            ),
            (
                ipv6("2001:db8::7".parse::<Ipv6Addr>().unwrap().octets()),
                "connect exit 2001:db8::7 80\n",
            ),
        ] {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(&all(&[&greeting(&[0]), &request(1, &address_bytes, 80)]))
                .await
                .unwrap();
            let mut got = Vec::new();
            timeout(WAIT, client.read_to_end(&mut got))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, greeted_then(0x02));
            assert_eq!(
                timeout(WAIT, agent.lines.recv()).await.unwrap().unwrap(),
                wanted
            );
        }
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_successful_open_through_an_agent_is_followed_by_the_bridge() {
        // `ok`, one data frame, an end frame: the destination answered and closed.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("ok.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (got_tx, mut got) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (connection, _) = listener.accept().await.unwrap();
            let (read, mut write) = connection.into_split();
            let mut read = BufReader::new(read);
            let mut line = String::new();
            read.read_line(&mut line).await.unwrap();
            write.write_all(b"ok\n").await.unwrap();
            let frame = |kind: u8, payload: &[u8]| {
                let mut out = vec![kind];
                out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                out.extend_from_slice(payload);
                out
            };
            write
                .write_all(&frame(0, b"from the destination"))
                .await
                .unwrap();
            write.write_all(&frame(1, b"")).await.unwrap();
            let mut rest = Vec::new();
            let _ = read.read_to_end(&mut rest).await;
            let _ = got_tx.send((line, rest));
        });
        let exit = Arc::new(AgentExit::new(&socket, "exit"));
        let (address, stop, task) = start_proxy(exit).await;
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&all(&[
                &greeting(&[0]),
                &request(1, &domain(b"example.org"), 443),
                b"early bytes",
            ]))
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut all_back = Vec::new();
        timeout(WAIT, client.read_to_end(&mut all_back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            all_back,
            all(&[&METHOD_OK, &OK_REPLY, b"from the destination"])
        );
        let (line, rest) = timeout(WAIT, got.recv()).await.unwrap().unwrap();
        assert_eq!(line, "connect exit example.org 443\n");
        // The pipelined bytes reached the agent as a data frame, after the success, then the end.
        let mut wanted = vec![0u8];
        wanted.extend_from_slice(&11u32.to_be_bytes());
        wanted.extend_from_slice(b"early bytes");
        wanted.extend_from_slice(&[1, 0, 0, 0, 0]);
        assert_eq!(rest, wanted);
        stop.send(true).unwrap();
        timeout(WAIT, task).await.unwrap().unwrap().unwrap();
    }

    #[test]
    fn the_log_shows_a_host_escaped_and_cut() {
        assert_eq!(log_host("example.org"), "example.org");
        assert!(!log_host("a\u{1b}[31mb").contains('\u{1b}'));
        assert!(log_host(&"x".repeat(1000)).len() <= LOG_HOST_BYTES);
        let multibyte = "é".repeat(300);
        let shown = log_host(&multibyte);
        assert!(shown.len() <= LOG_HOST_BYTES && shown.chars().all(|c| c == 'é'));
    }
}
