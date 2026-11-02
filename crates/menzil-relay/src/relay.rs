//! The relay's top-level runtime state and accept loop (protocol.md 3,
//! 4.1): bundles the shared state every accepted connection needs (this
//! relay's own identity, its held Rosters, per-NodeId replay-defense
//! history, and the attached-session registry) and runs
//! [`Listener::accept_tcp`] in a loop, spawning one task per connection
//! that runs the handshake under a timeout and an in-flight limit.

use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

use menzil_proto::Limits;

use crate::advertise::LabelRegistry;
use crate::forward::ForwardTable;
use crate::identity::RelayIdentity;
use crate::listener::Listener;
use crate::node_history::NodeHistory;
use crate::registry::SessionRegistry;
use crate::roster_store::RosterStore;
use crate::session;

/// The session numbers a relay hands out: WELCOME's `session` and the key of the registry's
/// supersede and teardown rules (equality is all they use).
///
/// The number a stranger reads in WELCOME must not be a relay wide connection counter, which
/// would show it how many connections every tenant opened in between (the first multi tenant
/// red-team round, L1). The relay counts internally, one step per accepted socket, and sends
/// that count through a keyed permutation of the 32 bit space: a four round Feistel network over
/// two 16 bit halves whose round function is SipHash keyed from the process's random state (a
/// pseudo random permutation by Luby and Rackoff). A permutation never repeats a value, so two
/// live sessions cannot share a number (before 2^32 connections, as with the plain counter), and
/// no collision handling or table of live ids is needed. The key is drawn at start and never
/// leaves the process; logs and the registry carry the sent number, the counter is not kept.
struct SessionIds {
    counter: AtomicU32,
    keys: RandomState,
}

impl SessionIds {
    fn new() -> Self {
        Self {
            counter: AtomicU32::new(1),
            keys: RandomState::new(),
        }
    }

    /// The number for the next accepted socket.
    fn next(&self) -> u32 {
        self.permute(self.counter.fetch_add(1, Ordering::Relaxed))
    }

    fn permute(&self, value: u32) -> u32 {
        let (mut left, mut right) = ((value >> 16) as u16, value as u16);
        for round in 0u8..4 {
            let mixed = self.keys.hash_one((round, right)) as u16;
            (left, right) = (right, left ^ mixed);
        }
        (u32::from(left) << 16) | u32::from(right)
    }
}

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
    next_session_id: Arc<SessionIds>,
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
            next_session_id: Arc::new(SessionIds::new()),
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

    /// [`Relay::serve_with`] with [`AcceptConfig::default`].
    pub async fn serve(&self, listener: &Listener) {
        self.serve_with(listener, AcceptConfig::default()).await
    }

    /// Accepts connections from `listener` forever. The loop only does
    /// the TCP accept ([`Listener::accept_tcp`]); each socket then gets
    /// its own task, which runs the TLS and WebSocket handshake under
    /// `config.handshake_timeout`, then HELLO validation (protocol.md
    /// 4.1) and the attached liveness/REKEY loop (protocol.md 3.3, 4.2).
    ///
    /// At most `config.max_inflight_handshakes` handshakes run at once.
    /// A socket that arrives when none is free is dropped at once, so
    /// the loop never waits on a peer and memory stays bounded; a
    /// handshake slot is freed when the handshake ends (done, failed or
    /// timed out), not when the session does. A single connection's own
    /// accept or handshake failure is logged and does not stop this
    /// loop; only ending the process does.
    pub async fn serve_with(&self, listener: &Listener, config: AcceptConfig) {
        let slots = Arc::new(Semaphore::new(config.max_inflight_handshakes));
        let upgrader = listener.upgrader();
        loop {
            let tcp = match listener.accept_tcp().await {
                Ok(tcp) => tcp,
                Err(err) => {
                    tracing::warn!(error = %err, "relay failed to accept a connection");
                    // A persistent error (no file descriptors left) must not spin the loop.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                tracing::debug!(
                    limit = config.max_inflight_handshakes,
                    "too many handshakes in flight; dropping a new connection"
                );
                continue;
            };
            let session_id = self.next_session_id.next();
            let relay = self.clone();
            let upgrader = Arc::clone(&upgrader);
            let timeout = config.handshake_timeout;
            tokio::spawn(async move {
                let handshake = tokio::time::timeout(timeout, upgrader.handshake(tcp)).await;
                // The slot is for the handshake only: free it before the
                // session starts, not when the session ends.
                drop(permit);
                let conn = match handshake {
                    Ok(Ok(conn)) => conn,
                    Ok(Err(err)) => {
                        tracing::debug!(error = %err, "inbound handshake failed");
                        return;
                    }
                    Err(_elapsed) => {
                        tracing::debug!(?timeout, "inbound handshake timed out");
                        return;
                    }
                };
                session::handle_connection(conn, relay, session_id).await;
            });
        }
    }
}

/// How long one inbound TLS plus WebSocket handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many inbound handshakes may be in flight at once; further new
/// sockets are dropped until one finishes.
pub const MAX_INFLIGHT_HANDSHAKES: usize = 256;

/// The limits [`Relay::serve_with`] puts on connections that have not yet
/// finished their handshake. [`Default`] is [`HANDSHAKE_TIMEOUT`] and
/// [`MAX_INFLIGHT_HANDSHAKES`].
#[derive(Debug, Clone, Copy)]
pub struct AcceptConfig {
    /// A handshake not finished after this long is abandoned and its
    /// socket closed.
    pub handshake_timeout: Duration,
    /// The most handshakes in flight at once.
    pub max_inflight_handshakes: usize,
}

impl Default for AcceptConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: HANDSHAKE_TIMEOUT,
            max_inflight_handshakes: MAX_INFLIGHT_HANDSHAKES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// First multi tenant round, L1: the numbers sent out are distinct, are not the plain
    /// counter, never step by one, and do not rise with the connections.
    #[test]
    fn session_numbers_do_not_reveal_how_many_connections_came_between() {
        let ids = SessionIds::new();
        let drawn: Vec<u32> = (0..50).map(|_| ids.next()).collect();
        let distinct: std::collections::HashSet<_> = drawn.iter().collect();
        assert_eq!(distinct.len(), drawn.len(), "a number is never reused");
        assert!(
            drawn.windows(2).all(|w| w[1] != w[0].wrapping_add(1)),
            "consecutive connections must not get consecutive numbers: {drawn:?}"
        );
        assert!(
            drawn.windows(2).any(|w| w[1] < w[0]),
            "the numbers must not rise with the connection count: {drawn:?}"
        );
        assert_ne!(drawn[0], 1, "the first number is not the bare counter");
    }

    #[test]
    fn the_session_number_mapping_is_a_permutation_keyed_per_process() {
        let a = SessionIds::new();
        let b = SessionIds::new();
        // Distinct inputs, distinct outputs (a sample; the Feistel shape guarantees it).
        let outputs: std::collections::HashSet<u32> =
            (0..20_000u32).map(|n| a.permute(n)).collect();
        assert_eq!(outputs.len(), 20_000);
        // Another key gives another mapping.
        assert!((0..16u32).any(|n| a.permute(n) != b.permute(n)));
    }
}
