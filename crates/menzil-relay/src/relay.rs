//! The relay's top-level runtime state and accept loop (protocol.md 3,
//! 4.1): bundles the shared state every accepted connection needs (this
//! relay's own identity, its held Rosters, per-NodeId replay-defense
//! history, and the attached-session registry) and runs
//! [`Listener::accept`] in a loop, spawning one task per connection.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use menzil_proto::Limits;

use crate::advertise::LabelRegistry;
use crate::forward::ForwardTable;
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
    pub(crate) forwarding: Arc<ForwardTable>,
    pub(crate) limits: Limits,
    next_session_id: Arc<AtomicU32>,
}

impl Relay {
    /// A relay with `identity` and `limits`, serving no networks yet:
    /// seed Rosters through [`Relay::rosters`] before or while calling
    /// [`Relay::serve`]. protocol.md 10 gives no stated default for
    /// `Limits.max_peers` (only `max_record` and `credit` have one), so
    /// `limits.max_peers` is always the caller's explicit choice, never
    /// invented here.
    ///
    /// `limits.credit` and `limits.max_record` are the two exceptions,
    /// each clamped (never raised, only ever lowered) before being
    /// stored — not inventing a value where the caller gave none, but
    /// correcting an internally-inconsistent one.
    ///
    /// `credit` is clamped to [`crate::forward::MAX_QUEUE_BYTES`]: an
    /// opus red team review (finding M1) caught that WELCOME advertised
    /// whatever `credit` the caller passed, unclamped, while
    /// `crate::forward::ForwardTable` separately clamped its own ledger
    /// to the same figure — so a caller configuring `credit` above the
    /// queue's own byte cap got a relay that told a node it had more
    /// credit than the relay would actually honor, killing an entirely
    /// compliant node's session the first time it believed WELCOME.
    /// Clamping once, here, is what keeps WELCOME and the ledger unable
    /// to disagree by construction.
    ///
    /// `max_record` is clamped to `menzil_carrier::MAX_MESSAGE_BYTES`
    /// (65,535 — the same figure protocol.md 10 states as `max_record`'s
    /// own default), a gap TODO.md L4b's own second review round found
    /// live: nothing stopped an operator from configuring `max_record`
    /// *above* what `Carrier::send` will actually transmit in one L2
    /// message, and WELCOME would then advertise a size a node could
    /// believe, try, and have fail to even encrypt — tearing down an
    /// otherwise healthy session the same way an unclamped `credit`
    /// once did (finding M1). Unlike `credit`, this is not a caller
    /// choice with a legitimate reason to exceed the clamp — 65,535 is
    /// the wire's own hard ceiling (`menzil-carrier::carrier::MAX_MESSAGE_BYTES`),
    /// not merely this crate's own policy, so clamping here can only
    /// ever correct a misconfiguration, never narrow a legitimate one.
    pub fn new(identity: RelayIdentity, mut limits: Limits) -> Self {
        limits.credit = limits.credit.min(crate::forward::MAX_QUEUE_BYTES as u32);
        limits.max_record = limits
            .max_record
            .min(menzil_carrier::MAX_MESSAGE_BYTES as u32);
        Self {
            identity: Arc::new(identity),
            rosters: Arc::new(RosterStore::new()),
            history: Arc::new(NodeHistory::new()),
            registry: Arc::new(SessionRegistry::new()),
            labels: Arc::new(LabelRegistry::new()),
            forwarding: Arc::new(ForwardTable::new()),
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
