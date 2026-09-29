//! Outer transport carrier for menzil.
//!
//! Carries bytes for the relay, node, and client roles over TLS on port
//! 443, through corporate HTTP CONNECT proxies when present, on top of
//! WebSocket today and an HTTP/2 upgrade later. Handles reconnection, and
//! exposes a single [`Carrier`] abstraction so upper layers do not need to
//! know which underlying transport is in use.
//!
//! This crate stops at L2 (protocol.md 1, 3): the Noise handshake,
//! HELLO/WELCOME, records, and credit flow of L3 belong to the
//! relay-session crate once it exists. Phase 1 scope (protocol.md 13):
//! environment-variable proxy discovery and Basic auth only; OS proxy
//! settings, PAC/WPAD, NTLM, and Negotiate are phase 2.

#![forbid(unsafe_code)]

mod backoff;
mod carrier;
mod connect;
mod connection_info;
mod error;
mod proxy;
mod socket_tuning;
mod tls;
mod websocket;

pub use backoff::Backoff;
pub use carrier::{Carrier, DialConfig, MAX_MESSAGE_BYTES, dial_with_backoff};
pub use connection_info::{ConnectionInfo, DEFAULT_PATH};
pub use error::CarrierError;
pub use proxy::{ProxyCredentials, ProxyOverride, ProxyResolution, ProxyTarget};
pub use tls::client_config;
pub use websocket::{HandshakeOutcome, SUBPROTOCOL};
