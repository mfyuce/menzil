//! The agent's local socket: how `menzil stdio` and `menzil reach` get a stream through the node
//! that holds the sessions (protocol.md 12). One Unix domain socket, mode 0600 in a directory
//! only the user can enter, so any process of the same user may use it and nobody else.
//!
//! The protocol is one request and then frames:
//!
//! ```text
//! client -> agent   open <who>/<service>\n          (one line, at most 512 bytes)
//! agent  -> client  ok\n   or   error <message>\n    (one line)
//! after ok, in both directions, frames:   u8 kind | u32 big endian length | payload
//!                   kind 0 data
//!                   kind 1 end: the sender will send no more, and the stream is still fine
//!                   kind 2 reset: the sender aborts, payload is a reason
//! ```
//!
//! Both directions are framed because a clean end and an abnormal one must stay apart all the
//! way to the program that uses the stream (protocol.md 5.2, "never with a clean end of
//! file"), and a Unix socket cannot say it: closing it looks the same whether the program
//! finished or died. A direction that ends without an end or reset frame is a program that
//! died, and the agent resets the stream. What the stream's peer sends is delivered to the
//! client in order, and its FIN becomes an end frame, its RST a reset frame.

use std::future::Future;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use menzil_stream::Stream;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// The longest request line, newline included.
pub const MAX_REQUEST_BYTES: usize = 512;
/// The longest reply line the client reads.
const MAX_REPLY_BYTES: usize = 1024;
/// The largest payload of one frame. The agent sends at most one yamux frame's worth.
const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
const COPY_BUFFER: usize = 16 * 1024;

const FRAME_DATA: u8 = 0;
const FRAME_END: u8 = 1;
const FRAME_RESET: u8 = 2;

/// How long a client has to send its request line.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the agent spends getting a stream open (the session handshake and the OPEN).
const OPEN_TIMEOUT: Duration = Duration::from_secs(60);
/// How many connections the agent serves at once.
const MAX_CONNECTIONS: usize = 256;

/// What the agent needs of a node: a way to open a stream to `<who>/<service>`. An error is a
/// message for the person at the other end of the socket, so it must not carry anything
/// secret.
pub trait Opener: Send + Sync + 'static {
    /// Opens a stream to `target`, which is `<who>/<service>` as the user typed it.
    fn open(&self, target: &str) -> impl Future<Output = Result<Stream, String>> + Send;
}

/// How a stream ended, as the client learns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The peer closed its side after sending everything.
    Clean,
    /// The stream was reset, or the connection under it was lost; nothing it carried may be
    /// taken as complete. The text says why.
    Reset(String),
}

/// A request line that is allowed: one `open` and a target of printable characters.
pub fn parse_request(line: &str) -> Result<&str, String> {
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let target = line
        .strip_prefix("open ")
        .ok_or_else(|| "the request must be `open <who>/<service>`".to_string())?;
    if target.is_empty()
        || target.len() > 256
        || target.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("the target must be 1 to 256 printable characters without spaces".to_string());
    }
    Ok(target)
}

/// Single line, printable: what goes back to a client after `error `.
fn one_line(message: &str) -> String {
    message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect()
}

async fn write_frame<W: AsyncWrite + Unpin>(
    out: &mut W,
    kind: u8,
    payload: &[u8],
) -> io::Result<()> {
    debug_assert!(payload.len() <= MAX_FRAME_PAYLOAD);
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(kind);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    out.write_all(&frame).await
}

/// One frame: its kind and its payload (in `payload`, which is reused). A direction that ends
/// before a frame does is `UnexpectedEof`: the sender died.
async fn read_frame<R: AsyncRead + Unpin>(read: &mut R, payload: &mut Vec<u8>) -> io::Result<u8> {
    let mut header = [0u8; 5];
    read.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a frame is too long",
        ));
    }
    payload.resize(length, 0);
    read.read_exact(payload).await?;
    Ok(header[0])
}

/// Reads one line of at most `limit` bytes (the newline included); `None` at end of file before
/// any byte.
async fn read_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<String>> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            bail!("the line ended without a newline");
        }
        let take = match available.iter().position(|&b| b == b'\n') {
            Some(i) => i + 1,
            None => available.len(),
        };
        if line.len() + take > limit {
            bail!("the line is longer than {limit} bytes");
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.ends_with(b"\n") {
            return String::from_utf8(line)
                .map(Some)
                .map_err(|_| anyhow!("the line is not UTF-8"));
        }
    }
}

/// Serves the agent socket until the task is dropped.
pub async fn serve<O: Opener>(listener: UnixListener, opener: Arc<O>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (connection, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "the agent failed to accept a connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            tracing::warn!("the agent has {MAX_CONNECTIONS} connections already, refusing one");
            drop(connection);
            continue;
        };
        let opener = opener.clone();
        tokio::spawn(async move {
            if let Err(error) = handle(connection, &*opener).await {
                tracing::debug!(error = %format!("{error:#}"), "an agent connection ended");
            }
            drop(permit);
        });
    }
}

async fn handle<O: Opener>(connection: UnixStream, opener: &O) -> Result<()> {
    let (read, mut write) = connection.into_split();
    let mut read = BufReader::new(read);
    let line = timeout(REQUEST_TIMEOUT, read_line(&mut read, MAX_REQUEST_BYTES))
        .await
        .context("the request did not arrive in time")??
        .ok_or_else(|| anyhow!("the client sent nothing"))?;
    let target = match parse_request(&line) {
        Ok(target) => target,
        Err(message) => {
            write
                .write_all(format!("error {message}\n").as_bytes())
                .await?;
            return Ok(());
        }
    };
    let opened = match timeout(OPEN_TIMEOUT, opener.open(target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(message)) => {
            write
                .write_all(format!("error {}\n", one_line(&message)).as_bytes())
                .await?;
            return Ok(());
        }
        Err(_) => {
            write
                .write_all(b"error the stream could not be opened in time\n")
                .await?;
            return Ok(());
        }
    };
    write.write_all(b"ok\n").await?;
    write.flush().await?;
    bridge(opened, read, write).await;
    Ok(())
}

/// Pipes a stream and a client connection to the end. The client's bytes are written to the
/// stream; a clean end of file from the client closes the stream's write side, anything else
/// wrong with the client (it vanished, a write to it failed) drops the stream unclosed, which
/// aborts it. What the stream delivers is framed to the client, with its end as a frame.
async fn bridge<R, W>(stream: Stream, mut from_client: BufReader<R>, mut to_client: W)
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let (mut stream_read, mut stream_write) = stream.split();
    let up = async {
        let mut payload = Vec::new();
        loop {
            match read_frame(&mut from_client, &mut payload).await? {
                FRAME_DATA => stream_write.write_all(&payload).await?,
                FRAME_END => {
                    stream_write.close().await?;
                    return io::Result::Ok(());
                }
                FRAME_RESET => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the client reset the stream",
                    ));
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unknown frame kind",
                    ));
                }
            }
        }
    };
    let down = async {
        let mut buffer = vec![0u8; COPY_BUFFER];
        loop {
            match stream_read.read(&mut buffer).await {
                Ok(0) => {
                    write_frame(&mut to_client, FRAME_END, &[]).await?;
                    return io::Result::Ok(());
                }
                Ok(n) => write_frame(&mut to_client, FRAME_DATA, &buffer[..n]).await?,
                Err(error) => {
                    let message = one_line(&error.to_string());
                    write_frame(&mut to_client, FRAME_RESET, message.as_bytes()).await?;
                    return Ok(());
                }
            }
        }
    };
    // Both directions to their end. The first failure (a client that vanished, a stream that
    // cannot be written) stops the other, and the stream is then reset: the client's end of
    // file looked like a half close, and only a failed write shows that it was a vanished
    // client, by which time the stream's write side is closed and a plain drop would send
    // nothing.
    let result = tokio::try_join!(up, down);
    if let Err(error) = result {
        tracing::debug!(%error, "an agent stream was aborted");
        if let Ok(stream) = stream_read.reunite(stream_write) {
            stream.reset();
        }
    }
}

/// How the client asks.
fn request_line(target: &str) -> String {
    format!("open {target}\n")
}

/// The client side: asks the agent at `socket` for a stream to `target`, then carries `input`
/// to it and its bytes to `output` until it ends. `input` reaching end of file half-closes the
/// stream; the call returns when the stream ends, whether or not `input` is still open.
pub async fn connect_and_bridge<R, W>(
    socket: &Path,
    target: &str,
    mut input: R,
    mut output: W,
) -> Result<End>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send,
{
    crate::node_cmd::check_socket_path_length(socket)?;
    let connection = UnixStream::connect(socket).await.with_context(|| {
        format!(
            "no agent is listening at {}: start it with `menzil node`",
            socket.display()
        )
    })?;
    let (read, mut write) = connection.into_split();
    let mut read = BufReader::new(read);
    write.write_all(request_line(target).as_bytes()).await?;
    let reply = timeout(
        OPEN_TIMEOUT + Duration::from_secs(10),
        read_line(&mut read, MAX_REPLY_BYTES),
    )
    .await
    .context("the agent did not answer in time")??
    .ok_or_else(|| anyhow!("the agent closed the connection without answering"))?;
    match reply.trim_end() {
        "ok" => {}
        other => match other.strip_prefix("error ") {
            Some(message) => bail!("{message}"),
            None => bail!("the agent answered something this client does not understand"),
        },
    }

    // The input runs on its own task: when the stream ends the call returns at once, even if
    // the program feeding `input` has not closed it.
    let up = tokio::spawn(async move {
        let mut buffer = vec![0u8; COPY_BUFFER];
        loop {
            match input.read(&mut buffer).await {
                Ok(0) => {
                    let _ = write_frame(&mut write, FRAME_END, &[]).await;
                    return;
                }
                Ok(n) => {
                    if write_frame(&mut write, FRAME_DATA, &buffer[..n])
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    let message = one_line(&error.to_string());
                    let _ = write_frame(&mut write, FRAME_RESET, message.as_bytes()).await;
                    return;
                }
            }
        }
    });
    let end = read_frames(&mut read, &mut output).await;
    up.abort();
    end
}

async fn read_frames<R, W>(read: &mut R, output: &mut W) -> Result<End>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    loop {
        let kind = match read_frame(read, &mut payload).await {
            Ok(kind) => kind,
            Err(error) => return Ok(End::Reset(format!("the agent went away: {error}"))),
        };
        match kind {
            FRAME_DATA => {
                output.write_all(&payload).await?;
                output.flush().await?;
            }
            FRAME_END => {
                output.flush().await?;
                return Ok(End::Clean);
            }
            FRAME_RESET => {
                output.flush().await?;
                return Ok(End::Reset(String::from_utf8_lossy(&payload).into_owned()));
            }
            _ => {
                return Ok(End::Reset(
                    "the agent sent a frame of an unknown kind".to_string(),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests;
