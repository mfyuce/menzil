//! A TCP socket with bytes already read from it put back in front (the ClientHello the front door
//! read to find the SNI, `crate::front_door`): whichever path takes the connection reads the
//! same bytes the client sent, then the rest of the socket.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// `prefix`, then `tcp`. Writes go straight to the socket.
pub(crate) struct PrefixedTcp {
    prefix: Vec<u8>,
    taken: usize,
    tcp: TcpStream,
}

impl PrefixedTcp {
    /// A socket nothing was read from.
    pub(crate) fn plain(tcp: TcpStream) -> Self {
        Self::with_prefix(Vec::new(), tcp)
    }

    /// `tcp` with `prefix` read first.
    pub(crate) fn with_prefix(prefix: Vec<u8>, tcp: TcpStream) -> Self {
        Self {
            prefix,
            taken: 0,
            tcp,
        }
    }

    /// Whether the socket has Nagle's algorithm turned off.
    #[cfg(test)]
    pub(crate) fn nodelay(&self) -> io::Result<bool> {
        self.tcp.nodelay()
    }
}

impl AsyncRead for PrefixedTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.taken < this.prefix.len() {
            let rest = &this.prefix[this.taken..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            this.taken += n;
            if this.taken == this.prefix.len() {
                this.prefix = Vec::new();
                this.taken = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

/// `prefix`, then `inner`: bytes already read from a stream (the head of an HTTP request read
/// to see whether it is a WebSocket upgrade, `crate::listener`) put back in front of it. Writes
/// go straight to `inner`. With an empty prefix this is `inner`.
pub(crate) struct Replay<S> {
    prefix: Vec<u8>,
    taken: usize,
    inner: S,
}

impl<S> Replay<S> {
    /// `inner` with `prefix` read first.
    pub(crate) fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            taken: 0,
            inner,
        }
    }

    /// The stream underneath.
    #[cfg(test)]
    pub(crate) fn get_ref(&self) -> &S {
        &self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Replay<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.taken < this.prefix.len() {
            let rest = &this.prefix[this.taken..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            this.taken += n;
            if this.taken == this.prefix.len() {
                this.prefix = Vec::new();
                this.taken = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Replay<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
