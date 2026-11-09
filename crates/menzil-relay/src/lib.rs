//! Relay-side inbound transport for menzil (protocol.md 1, 3, 6.2's own
//! hostname case).
//!
//! Accepts TLS+WebSocket connections to the relay's own hostname and
//! completes the L3 upgrade, mirroring `menzil-carrier`'s client-side
//! shape so a session layer can treat either uniformly. Deliberately not
//! here:
//!
//! - Anything but the blind front door of the TLS port (`front_door`: protocol.md 6.2 to 6.4,
//!   SNI routing of blind `tls:` and `tcp:` shares through the relay principal, and the TLS of
//!   terminated shares); the static site is a later slice.
//! - The relay's own ACME is `acme` (TLS-ALPN-01 for the relay's host name and the names of
//!   terminated shares, needs the front door); the certificate and key of the relay's own host
//!   are otherwise supplied to this crate already loaded.
//! - `http_term` is the HTTP/1.1 terminator of terminated shares (protocol.md 6.3); WebSocket
//!   upgrade through it is not built.

#![forbid(unsafe_code)]

mod acme;
mod admission;
mod advertise;
mod connection;
mod doc;
mod endpoint;
mod error;
mod forward;
mod front_door;
mod hello;
mod http_term;
mod identity;
mod listener;
mod log_throttle;
mod names;
mod node_history;
mod prefixed;
mod principal;
mod rate;
mod registry;
mod relay;
mod roster_store;
mod session;
#[cfg(test)]
mod session_tests;
mod shaping;
mod sni;
mod tenant;
#[cfg(test)]
mod tests_support;
mod tls;
mod usage_snapshot;

pub use acme::{
    AcmeConfig, MAX_PENDING_ORDERS, ORDER_BACKOFF_MAX, ORDER_MIN_INTERVAL, OrderLimiter,
    OrderPermit, RelayAcme, RelayCertBook, run as run_acme,
};
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
pub use front_door::{
    FRONT_DOOR_FAILURE_DELAY, FRONT_DOOR_FIRST_BYTE_TIMEOUT, FRONT_DOOR_IDLE_TIMEOUT,
    FRONT_DOOR_MAX_ANSWERS, FRONT_DOOR_MAX_TOTAL, FRONT_DOOR_PER_CLIENT,
    FRONT_DOOR_PER_CLIENT_PER_NAME, FRONT_DOOR_PER_NAME, FRONT_DOOR_PER_TENANT,
    FRONT_DOOR_V6_48_FACTOR, FrontDoorConfig, FrontDoorConfigError,
};
pub use hello::{HelloRejection, check_hello};
pub use identity::RelayIdentity;
pub use listener::{FALLBACK_PAGE_MAX_BYTES, FallbackPage, Listener};
pub use names::{
    Claim, NEW_NAMES_WINDOW_DAYS, NameFigures, NameRecord, NameRefusal, NameState, NamesStateError,
    Quarantine, QuarantineKind, RELEASE_DAYS, TOUCH_SECS,
};
pub use node_history::{HistoryViolation, MAX_HISTORY_ENTRIES, NodeHistory};
pub use principal::{
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_PER_TENANT,
    DEFAULT_MAX_SESSION_AGE, DEFAULT_MAX_STREAMS_PER_SESSION, DEFAULT_MAX_STREAMS_PER_TENANT,
    DEFAULT_MAX_TOTAL, DEFAULT_OPEN_TIMEOUT, DEFAULT_SEND_WAIT, DEFAULT_TICK, Principal,
    PrincipalConfig, PrincipalError, SEND_RETRY,
};
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
pub use usage_snapshot::TenantUsageNow;
