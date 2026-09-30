//! Tracks which NodeId currently has an attached, routable session
//! (protocol.md 4.1: "the new session is not routable and does not
//! supersede an existing one until the node's first transport record,
//! ATTACH, is decrypted. Then the previous session for that NodeId
//! receives GOAWAY `superseded`"; protocol.md 10: "Sessions per NodeId: 1
//! attached"), and lets another connection's task hand a record to an
//! attached session's own connection for it to actually send.
//!
//! Two separate channels do this, deliberately kept apart rather than
//! shared:
//!
//! - [`SessionRegistry::send_to`] is a simple, best-effort, non-credited,
//!   bounded-by-item-count channel: correctly scoped to DOC propagation
//!   (protocol.md 4.3, TODO.md L3f) and ADVERTISE_ACK/control traffic,
//!   where dropping an occasional message under backpressure is
//!   acceptable and a resend or the next state sync recovers it.
//! - [`SessionRegistry::deliver`] is the SEND->RECV data-plane path
//!   (protocol.md 4.2's flow-control paragraph, TODO.md L3h,
//!   `crate::forward`): unbounded, because `crate::forward::ForwardTable`
//!   already performs its own credit/queue-budget/token-bucket admission
//!   control before ever calling it, and a second, independent,
//!   item-count-based bound on top would risk rejecting traffic that
//!   admission control already approved, for reasons unrelated to actual
//!   memory pressure (e.g. many small reliable records, none of which
//!   individually matter, arriving in a burst).

use std::collections::HashMap;
use std::sync::RwLock;

use menzil_proto::{NetworkId, NodeId, Record};
use tokio::sync::{mpsc, oneshot};

use crate::forward::ForwardItem;

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
    /// The SEND->RECV data-plane delivery path (TODO.md L3h,
    /// `crate::forward`), deliberately separate from `outbound` above —
    /// see this module's own doc comment.
    forward: mpsc::UnboundedSender<ForwardItem>,
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
    /// fires, if that never happens); a receiver of records handed to
    /// [`SessionRegistry::send_to`] for this NodeId; and a receiver of
    /// items handed to [`SessionRegistry::deliver`] for this NodeId
    /// (TODO.md L3h) — the caller must keep polling both for as long as
    /// it stays attached, and actually send what they yield over its own
    /// connection.
    ///
    /// If another session was already registered for this NodeId, its
    /// own supersede receiver fires immediately and it is replaced right
    /// away, dropping its outbound senders too (so its receivers simply
    /// end); callers do not wait for the old session to actually finish
    /// leaving before this returns.
    ///
    /// Crate-visible only, not `pub`: unlike this type's other methods,
    /// its return type now carries [`ForwardItem`] (TODO.md L3h), which
    /// is itself crate-internal plumbing (`crate::forward`'s own drain
    /// bookkeeping) with no reason to ever be nameable outside this
    /// crate — nothing external can reach a `SessionRegistry` to call
    /// this anyway, since `Relay::registry` is itself crate-visible only.
    pub(crate) fn attach(
        &self,
        node_id: NodeId,
        session_id: u32,
        claimed_networks: Vec<NetworkId>,
    ) -> (
        oneshot::Receiver<()>,
        mpsc::Receiver<Record>,
        mpsc::UnboundedReceiver<ForwardItem>,
    ) {
        let (supersede_tx, supersede_rx) = oneshot::channel();
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let (forward_tx, forward_rx) = mpsc::unbounded_channel();
        let mut guard = self.by_node.write().unwrap();
        if let Some(previous) = guard.insert(
            node_id,
            Registration {
                session_id,
                claimed_networks,
                supersede: supersede_tx,
                outbound: outbound_tx,
                forward: forward_tx,
            },
        ) {
            let _ = previous.supersede.send(());
        }
        (supersede_rx, outbound_rx, forward_rx)
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

    /// Hands `item` to `node_id`'s attached connection to send as a RECV
    /// record (TODO.md L3h's SEND->RECV data plane, `crate::forward`) —
    /// see this module's own doc comment for why this is a separate
    /// channel from [`SessionRegistry::send_to`], not the same one.
    /// Returns whether `node_id` was actually attached to receive it.
    pub(crate) fn deliver(&self, node_id: &NodeId, item: ForwardItem) -> bool {
        self.by_node
            .read()
            .unwrap()
            .get(node_id)
            .is_some_and(|registration| registration.forward.send(item).is_ok())
    }

    /// Whether `node_id` currently has an attached session (protocol.md
    /// 4.2's forwarding rule: "dst is online and attached").
    /// `crate::forward::ForwardTable::forward` checks this only *after*
    /// confirming `src` is authorized to reach `dst` at all — never
    /// before — so that an unauthorized sender can never use this to
    /// learn whether an arbitrary NodeId is currently online (an opus red
    /// team review's finding M2, fixed by reordering the checks; see
    /// `crate::forward`'s module doc comment).
    pub(crate) fn is_attached(&self, node_id: &NodeId) -> bool {
        self.by_node.read().unwrap().contains_key(node_id)
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
        let (mut old_rx, _old_outbound, _old_forward) = registry.attach(node_id, 1, vec![]);
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
        let (_supersede_rx, mut outbound_rx, _forward_rx) = registry.attach(node_id, 1, vec![]);
        assert!(registry.send_to(&node_id, Record::Rekey));
        assert_eq!(outbound_rx.try_recv().unwrap(), Record::Rekey);
    }

    #[test]
    fn send_to_a_node_with_no_attached_session_is_a_no_op() {
        let registry = SessionRegistry::new();
        assert!(!registry.send_to(&NodeId::from([9u8; 32]), Record::Rekey));
    }

    fn forward_item(charge: u32) -> ForwardItem {
        ForwardItem::Recv {
            record: Box::new(Record::Recv {
                src: NodeId::from([7u8; 32]),
                e2e_proto: 0x01,
                flags: 0,
                payload: vec![0u8; charge as usize],
            }),
            src: NodeId::from([7u8; 32]),
            charge,
            reliable: true,
        }
    }

    #[test]
    fn deliver_hands_off_to_an_attached_sessions_forward_receiver() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let (_supersede_rx, _outbound_rx, mut forward_rx) = registry.attach(node_id, 1, vec![]);
        assert!(registry.deliver(&node_id, forward_item(3)));
        match forward_rx.try_recv() {
            Ok(ForwardItem::Recv { charge, .. }) => assert_eq!(charge, 3),
            _ => panic!("expected a Recv item"),
        }
    }

    #[test]
    fn deliver_to_a_node_with_no_attached_session_is_a_no_op() {
        let registry = SessionRegistry::new();
        assert!(!registry.deliver(&NodeId::from([9u8; 32]), forward_item(3)));
    }

    #[test]
    fn is_attached_reflects_whether_a_session_is_currently_registered() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        assert!(!registry.is_attached(&node_id));
        let _handles = registry.attach(node_id, 1, vec![]);
        assert!(registry.is_attached(&node_id));
        registry.detach(&node_id, 1);
        assert!(!registry.is_attached(&node_id));
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
