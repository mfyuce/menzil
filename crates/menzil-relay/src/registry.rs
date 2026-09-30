//! Tracks which NodeId currently has an attached, routable session
//! (protocol.md 4.1: "the new session is not routable and does not
//! supersede an existing one until the node's first transport record,
//! ATTACH, is decrypted. Then the previous session for that NodeId
//! receives GOAWAY `superseded`"; protocol.md 10: "Sessions per NodeId: 1
//! attached"), and lets another connection's task hand a record to an
//! attached session's own connection for it to actually send
//! (`crate::doc`'s DOC propagation, protocol.md 4.3, is the first user of
//! this; TODO.md L3h's SEND->RECV forwarding will be a later one).
//!
//! Forwarding a SEND to whatever session is registered here, with credit
//! enforcement and bounded per-(source,destination) queues, is a
//! separate, later item's job (TODO.md L3h, the flow-control paragraph of
//! protocol.md 4.2): [`SessionRegistry::send_to`] is deliberately a
//! simple, best-effort, non-credited channel, correctly scoped to DOC's
//! own low-volume, best-effort-is-fine control traffic — not a
//! foundation L3h's higher-stakes SEND/RECV data plane should build on
//! without its own credit/backpressure design.

use std::collections::HashMap;
use std::sync::RwLock;

use menzil_proto::{NetworkId, NodeId, Record};
use tokio::sync::{mpsc, oneshot};

/// How many records [`SessionRegistry::send_to`] will queue for one
/// attached session before further sends start being dropped. A full 1
/// MiB roster chunked at `menzil_proto::MAX_DOC_CHUNK_BYTES` is at most
/// ~18 records; this leaves generous headroom for a few concurrent
/// per-network propagations without needing real backpressure, which
/// (per this module's doc comment) is deliberately not built here.
const OUTBOUND_CAPACITY: usize = 128;

struct Registration {
    session_id: u32,
    /// Networks this session claimed in its own HELLO (protocol.md 4.1),
    /// used to target DOC propagation (protocol.md 4.3) at sessions that
    /// actually asked to hear about a given network, not merely at every
    /// attached session that happens to be listed in its Roster.
    claimed_networks: Vec<NetworkId>,
    supersede: oneshot::Sender<()>,
    outbound: mpsc::Sender<Record>,
}

/// The relay's currently-attached sessions, at most one per NodeId.
#[derive(Default)]
pub struct SessionRegistry {
    by_node: RwLock<HashMap<NodeId, Registration>>,
}

impl SessionRegistry {
    /// No sessions attached yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `session_id` as the attached session for `node_id`,
    /// claiming `claimed_networks` (its HELLO's own `networks` list).
    /// Returns a receiver that fires once — with no payload, since the
    /// only thing to communicate is that it happened — when *this*
    /// registration is later superseded (it is simply dropped, and never
    /// fires, if that never happens), and a receiver of records handed to
    /// [`SessionRegistry::send_to`] for this NodeId, which the caller
    /// must keep polling and actually send over its own connection for
    /// as long as it stays attached.
    ///
    /// If another session was already registered for this NodeId, its
    /// own supersede receiver fires immediately and it is replaced right
    /// away, dropping its outbound sender too (so its receiver simply
    /// ends); callers do not wait for the old session to actually finish
    /// leaving before this returns.
    pub fn attach(
        &self,
        node_id: NodeId,
        session_id: u32,
        claimed_networks: Vec<NetworkId>,
    ) -> (oneshot::Receiver<()>, mpsc::Receiver<Record>) {
        let (supersede_tx, supersede_rx) = oneshot::channel();
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let mut guard = self.by_node.write().unwrap();
        if let Some(previous) = guard.insert(
            node_id,
            Registration {
                session_id,
                claimed_networks,
                supersede: supersede_tx,
                outbound: outbound_tx,
            },
        ) {
            let _ = previous.supersede.send(());
        }
        (supersede_rx, outbound_rx)
    }

    /// Removes `node_id`'s registration, but only if it still belongs to
    /// `session_id`: a session that already lost a supersede race must
    /// not delete the newer registration that replaced it on its own way
    /// out. Returns whether it actually removed anything: `crate::session`
    /// uses this to decide whether releasing this NodeId's advertised
    /// labels (`crate::advertise::LabelRegistry::clear_for`) is safe — a
    /// stale detach call from a session that already lost that race must
    /// not clear labels the newer, still-attached session has since
    /// re-claimed.
    pub fn detach(&self, node_id: &NodeId, session_id: u32) -> bool {
        let mut guard = self.by_node.write().unwrap();
        if guard
            .get(node_id)
            .is_some_and(|registration| registration.session_id == session_id)
        {
            guard.remove(node_id);
            true
        } else {
            false
        }
    }

    /// Hands `record` to `node_id`'s attached connection to send, if any
    /// is currently attached and its outbound queue is not full
    /// (best-effort — see this module's doc comment). Returns whether it
    /// was actually queued.
    pub fn send_to(&self, node_id: &NodeId, record: Record) -> bool {
        self.by_node
            .read()
            .unwrap()
            .get(node_id)
            .is_some_and(|registration| registration.outbound.try_send(record).is_ok())
    }

    /// Whether `session_id` is still `node_id`'s currently registered
    /// session — `false` before it has ever attached, and `false` again
    /// once a newer session for the same NodeId has superseded it.
    /// `crate::session` checks this before acting on a record whose
    /// effect reaches beyond this one connection (ADVERTISE, TODO.md
    /// L3g): a connection that is not, or is no longer, the current one
    /// for its NodeId must not still be able to mutate state a newer
    /// session owns — a stale connection can otherwise keep processing
    /// buffered input for a little while after being superseded (see
    /// this module's own doc comment on [`SessionRegistry::attach`]),
    /// and a record decrypted during that window is still genuinely
    /// authentic, just no longer current.
    pub fn is_current(&self, node_id: &NodeId, session_id: u32) -> bool {
        self.by_node
            .read()
            .unwrap()
            .get(node_id)
            .is_some_and(|registration| registration.session_id == session_id)
    }

    /// Every currently attached NodeId that claimed `network_id` in its
    /// own HELLO, excluding `exclude` — the fan-out target list for DOC
    /// propagation (protocol.md 4.3: "a relay sends DOC(roster) to
    /// attached members of that network").
    pub fn attached_members_of(&self, network_id: &NetworkId, exclude: &NodeId) -> Vec<NodeId> {
        self.by_node
            .read()
            .unwrap()
            .iter()
            .filter(|(node_id, registration)| {
                *node_id != exclude && registration.claimed_networks.contains(network_id)
            })
            .map(|(node_id, _)| *node_id)
            .collect()
    }

    /// Whether `node_id` currently has an attached session, and if so,
    /// its session id. Exposed mainly for tests (crate-visible so the
    /// live end-to-end suite can use it too); nothing in this item's own
    /// scope needs to query it beyond attach/detach.
    #[cfg(test)]
    pub(crate) fn attached_session_id(&self, node_id: &NodeId) -> Option<u32> {
        self.by_node
            .read()
            .unwrap()
            .get(node_id)
            .map(|registration| registration.session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_then_detach_clears_the_registration() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let _handles = registry.attach(node_id, 1, vec![]);
        assert_eq!(registry.attached_session_id(&node_id), Some(1));
        assert!(registry.detach(&node_id, 1));
        assert_eq!(registry.attached_session_id(&node_id), None);
    }

    #[test]
    fn attaching_again_supersedes_the_previous_registration() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let (mut old_rx, _old_outbound) = registry.attach(node_id, 1, vec![]);
        assert!(old_rx.try_recv().is_err(), "not superseded yet");

        let _new_handles = registry.attach(node_id, 2, vec![]);
        assert_eq!(registry.attached_session_id(&node_id), Some(2));
        assert!(
            old_rx.try_recv().is_ok(),
            "the old registration's receiver must fire once superseded"
        );
    }

    #[test]
    fn a_superseded_session_detaching_does_not_remove_the_new_one() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let _old_handles = registry.attach(node_id, 1, vec![]);
        let _new_handles = registry.attach(node_id, 2, vec![]);

        // Session 1's own cleanup runs after it was already superseded.
        assert!(
            !registry.detach(&node_id, 1),
            "a stale detach must report it removed nothing"
        );
        assert_eq!(
            registry.attached_session_id(&node_id),
            Some(2),
            "detaching a stale session id must not evict the current one"
        );
    }

    #[test]
    fn independent_nodes_do_not_affect_each_other() {
        let registry = SessionRegistry::new();
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        let _rx_a = registry.attach(a, 1, vec![]);
        let _rx_b = registry.attach(b, 2, vec![]);
        registry.detach(&a, 1);
        assert_eq!(registry.attached_session_id(&a), None);
        assert_eq!(registry.attached_session_id(&b), Some(2));
    }

    #[test]
    fn send_to_delivers_to_an_attached_sessions_outbound_receiver() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let (_supersede_rx, mut outbound_rx) = registry.attach(node_id, 1, vec![]);
        assert!(registry.send_to(&node_id, Record::Rekey));
        assert_eq!(outbound_rx.try_recv().unwrap(), Record::Rekey);
    }

    #[test]
    fn send_to_a_node_with_no_attached_session_is_a_no_op() {
        let registry = SessionRegistry::new();
        assert!(!registry.send_to(&NodeId::from([9u8; 32]), Record::Rekey));
    }

    #[test]
    fn is_current_is_false_before_any_attach() {
        let registry = SessionRegistry::new();
        assert!(!registry.is_current(&NodeId::from([1u8; 32]), 1));
    }

    #[test]
    fn is_current_is_true_for_the_attached_session_and_false_for_any_other_id() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let _handles = registry.attach(node_id, 1, vec![]);
        assert!(registry.is_current(&node_id, 1));
        assert!(!registry.is_current(&node_id, 2));
    }

    #[test]
    fn is_current_is_false_for_a_session_that_has_been_superseded() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let _old = registry.attach(node_id, 1, vec![]);
        let _new = registry.attach(node_id, 2, vec![]);
        assert!(!registry.is_current(&node_id, 1));
        assert!(registry.is_current(&node_id, 2));
    }

    #[test]
    fn attached_members_of_filters_by_claimed_network_and_excludes_the_given_node() {
        let registry = SessionRegistry::new();
        let network_a = NetworkId::from([1u8; 32]);
        let network_b = NetworkId::from([2u8; 32]);
        let a = NodeId::from([10u8; 32]);
        let b = NodeId::from([11u8; 32]);
        let c = NodeId::from([12u8; 32]);
        let _a = registry.attach(a, 1, vec![network_a]);
        let _b = registry.attach(b, 2, vec![network_a, network_b]);
        let _c = registry.attach(c, 3, vec![network_b]);

        let members = registry.attached_members_of(&network_a, &a);
        assert_eq!(members, vec![b]);

        let mut members = registry.attached_members_of(&network_b, &NodeId::from([99u8; 32]));
        members.sort_by_key(|n| n.as_ref().to_vec());
        let mut expected = vec![b, c];
        expected.sort_by_key(|n| n.as_ref().to_vec());
        assert_eq!(members, expected);
    }
}
