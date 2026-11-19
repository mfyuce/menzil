//! Stand-ins for the Unix socket types, used where there are none (Windows, D11 W1). They have
//! the surface the agent, reach and proxy code uses, and every operation that would need a
//! socket fails with `Unsupported` and a message that says what is missing, so the code
//! compiles everywhere and a Windows user gets an answer instead of a build error. The real
//! thing for Windows (named pipes or a loopback agent) is slice W2. Compiled on every platform
//! so that the tests can run on Linux; only used where `cfg(not(unix))`.
#![cfg_attr(unix, allow(dead_code))]

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const WHY: &str = "Unix domain sockets are not available on this platform yet (the agent, `menzil reach` and `menzil proxy --unix` need them; Windows support is slice W2)";

fn unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::Unsupported, WHY))
}

/// Who is on the other end of a socket.
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

#[derive(Debug)]
pub struct UnixStream(());

impl UnixStream {
    pub async fn connect(_path: impl AsRef<Path>) -> io::Result<UnixStream> {
        unsupported()
    }
    pub fn pair() -> io::Result<(UnixStream, UnixStream)> {
        unsupported()
    }
    pub fn peer_cred(&self) -> io::Result<UCred> {
        unsupported()
    }
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        (OwnedReadHalf(()), OwnedWriteHalf(()))
    }
}

#[derive(Debug)]
pub struct OwnedReadHalf(());
#[derive(Debug)]
pub struct OwnedWriteHalf(());

fn not_here() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, WHY)
}

impl AsyncRead for UnixStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(not_here()))
    }
}
impl AsyncWrite for UnixStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(not_here()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(not_here()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(not_here()))
    }
}
impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(not_here()))
    }
}
impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(not_here()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(not_here()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(not_here()))
    }
}

#[derive(Debug)]
pub struct UnixListener(());

impl UnixListener {
    pub fn bind(_path: impl AsRef<Path>) -> io::Result<UnixListener> {
        unsupported()
    }
    pub async fn accept(&self) -> io::Result<(UnixStream, ())> {
        unsupported()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_socket_operation_says_what_is_missing() {
        let bind = UnixListener::bind("x.sock").unwrap_err();
        assert_eq!(bind.kind(), io::ErrorKind::Unsupported);
        assert!(bind.to_string().contains("Windows"), "{bind}");
        let connect = UnixStream::connect("x.sock").await.unwrap_err();
        assert_eq!(connect.kind(), io::ErrorKind::Unsupported);
        assert_eq!(
            UnixStream::pair().unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}
