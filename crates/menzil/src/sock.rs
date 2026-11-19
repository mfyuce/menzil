//! The Unix socket types the agent, reach and proxy code use, from one place: tokio's on Unix,
//! the stand-ins of [`unsupported`] elsewhere (D11 W1).

mod unsupported;

#[cfg(unix)]
pub use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
#[cfg(unix)]
pub use tokio::net::{UnixListener, UnixStream};

#[cfg(not(unix))]
pub use unsupported::{OwnedReadHalf, OwnedWriteHalf, UnixListener, UnixStream};
