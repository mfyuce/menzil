//! The relay's top-level runtime state and accept loop (protocol.md 3,
//! 4.1): bundles the shared state every accepted connection needs (this
//! relay's own identity, its held Rosters, per-NodeId replay-defense
//! history, and the attached-session registry) and runs
//! [`Listener::accept`] in a loop, spawning one task per connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use menzil_proto::Limits;

use crate::advertise::LabelRegistry;
use crate::identity::RelayIdentity;
use crate::listener::Listener;
use crate::node_history::NodeHistory;
use crate::registry::SessionRegistry;
use crate::roster_store::RosterStore;
use crate::session;

/// A relay's shared runtime state: cheap to clone (every field is an
/// `Arc`, or `Copy`), so each accepted connection's spawned task gets
/// its own handle without contending on anything but the state itself.
#[derive(Clone)]
pub struct Relay {
    pub(crate) identity: Arc<RelayIdentity>,
    pub(crate) rosters: Arc<RosterStore>,
    pub(crate) history: Arc<NodeHistory>,
    pub(crate) registry: Arc<SessionRegistry>,
    pub(crate) labels: Arc<LabelRegistry>,
    pub(crate) limits: Limits,
    next_session_id: Arc<AtomicU32>,
}

impl Relay {
    /// A relay with `identity` and `limits`, serving no networks yet:
    /// seed Rosters through [`Relay::rosters`] before or while calling
    /// [`Relay::serve`]. protocol.md 10 gives no stated default for
    /// `Limits.max_peers` (only `max_record` and `credit` have one), so
    /// `limits` is always the caller's explicit choice, never invented
    /// here.
    pub fn new(identity: RelayIdentity, limits: Limits) -> Self {
        Self {
            identity: Arc::new(identity),
            rosters: Arc::new(RosterStore::new()),
            history: Arc::new(NodeHistory::new()),
            registry: Arc::new(SessionRegistry::new()),
            labels: Arc::new(LabelRegistry::new()),
            limits,
            next_session_id: Arc::new(AtomicU32::new(1)),
        }
    }

    /// This relay's held Rosters. An operator or test harness seeds the
    /// very first Roster for a network directly through this handle
    /// (`crate::doc`'s DOC handling, protocol.md 4.3, only ever *updates*
    /// a network already held this way — see `crate::doc::accept_roster_chunk`'s
    /// docs for why introducing a brand new network is deliberately not
    /// possible over the wire).
    pub fn rosters(&self) -> &RosterStore {
        &self.rosters
    }

    /// Accepts connections from `listener` forever, spawning one task
    /// per connection to run its handshake, HELLO validation
    /// (protocol.md 4.1), and its attached liveness/REKEY loop
    /// (protocol.md 3.3, 4.2). A single connection's own accept or
    /// handshake failure is logged and does not stop this loop — only
    /// ending the process does.
    pub async fn serve(&self, listener: &Listener) {
        loop {
            let conn = match listener.accept().await {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(error = %err, "relay failed to accept a connection");
                    continue;
                }
            };
            let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            let relay = self.clone();
            tokio::spawn(async move {
                session::handle_connection(conn, relay, session_id).await;
            });
        }
    }
}
