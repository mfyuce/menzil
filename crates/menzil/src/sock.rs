//! The Unix socket types the agent, reach and proxy code use, from one place: tokio's on Unix,
//! the loopback plus token stand-ins of [`loopback`] elsewhere (D11 W2).

pub(crate) mod loopback;

#[cfg(unix)]
pub use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
#[cfg(unix)]
pub use tokio::net::{UnixListener, UnixStream};

#[cfg(not(unix))]
pub use loopback::{OwnedReadHalf, OwnedWriteHalf, UnixListener, UnixStream};
