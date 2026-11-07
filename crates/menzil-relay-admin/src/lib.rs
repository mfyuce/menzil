//! `menzil-relay-admin`: a thin mTLS gRPC agent (`TenantAdmin`, `proto/menzil_admin.proto`) that
//! changes a relay's tenant files through the library functions of `menzil_cli::relay_cmd::tenants`
//! and does nothing else: it never touches keys, Rosters of its own, or the relay process. An RPC
//! reply means "the file is written"; the running relay applies it within 15 seconds.
//!
//! * [`service`]: the RPCs and the mapping of library errors to gRPC codes.
//! * [`tls`]: the server (mutual TLS 1.3 only, client certificate required, one CA) and the check
//!   of the key file's mode.
//! * [`certs`]: `gen-certs`, a private CA with one server and one client certificate.

#![forbid(unsafe_code)]

/// The generated protobuf and tonic code of `proto/menzil_admin.proto`.
#[allow(clippy::all, clippy::pedantic, missing_docs)]
pub mod pb {
    tonic::include_proto!("menzil.admin.v3");
}

pub mod certs;
pub mod service;
pub mod tls;

pub use service::Admin;
pub use tls::{AdminServer, ConnLimits, TlsFiles, server_config};
