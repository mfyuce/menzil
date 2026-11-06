//! Relay-side inbound transport for menzil (protocol.md 1, 3, 6.2's own
//! hostname case).
//!
//! Accepts TLS+WebSocket connections to the relay's own hostname and
//! completes the L3 upgrade, mirroring `menzil-carrier`'s client-side
//! shape so a session layer can treat either uniformly. Deliberately not
//! here:
//!
//! - SNI-based routing to advertised blind share names (protocol.md 6.2;
//!   phase 2 per protocol.md 13).
//! - ACME certificate provisioning (protocol.md 11); certificate and key
//!   material is supplied to this crate already loaded.
//! - Relay-terminated HTTP serving for terminated shares (its own
//!   TODO.md line, protocol.md 6.3).

#![forbid(unsafe_code)]

mod admission;
mod advertise;
mod connection;
mod doc;
mod endpoint;
mod error;
mod forward;
mod hello;
mod identity;
mod listener;
mod log_throttle;
mod names;
mod node_history;
mod rate;
mod registry;
mod relay;
mod roster_store;
mod session;
#[cfg(test)]
mod session_tests;
mod shaping;
mod tenant;
#[cfg(test)]
mod tests_support;
mod tls;

pub use admission::{
    AdmissionLimits, CONNECTIONS_PER_IP_PER_MINUTE, MAX_ATTACHED, MAX_HANDSHAKES_PER_IP,
    MAX_HANDSHAKES_PER_V6_48, MAX_TRACKED_PEERS, MAX_UNATTACHED_PER_IP, MAX_UNATTACHED_PER_NODE,
    RATE_WINDOW,
};
pub use advertise::{DEFAULT_RESERVED_LABELS, LabelRegistry};
pub use connection::InboundConnection;
pub use endpoint::{InboundFrame, RelayEndpoint};
pub use error::RelayError;
pub use forward::RelaySendOutcome;
pub use hello::{HelloRejection, check_hello};
pub use identity::RelayIdentity;
pub use listener::Listener;
pub use names::{
    Claim, NEW_NAMES_WINDOW_DAYS, NameFigures, NameRecord, NameRefusal, NameState, NamesStateError,
    Quarantine, QuarantineKind, RELEASE_DAYS, TOUCH_SECS,
};
pub use node_history::{HistoryViolation, MAX_HISTORY_ENTRIES, NodeHistory};
pub use rate::{
    ADVERTISE_BURST, ADVERTISE_PER_MINUTE, DOC_BURST, DOC_TRANSFERS_PER_MINUTE, MAX_DOC_BURST,
    OVER_RATE_DOCS_TO_END, SessionRates, UNADOPTED_DOCS_TO_END, UNADOPTED_WINDOW,
};
pub use registry::SessionRegistry;
pub use relay::{AcceptConfig, AttachedNode, HANDSHAKE_TIMEOUT, MAX_INFLIGHT_HANDSHAKES, Relay};
pub use roster_store::RosterStore;
pub use tenant::{
    Class, Figures, LABEL_MAX_LEN, QUARANTINE_DAYS, Refusal, SLUG_MAX_LEN, SLUG_MIN_LEN, Slug,
    SlugError, Tenant, TenantBook, TenantId, TenantSpec, check_flat_name,
};
pub use tls::server_config;
