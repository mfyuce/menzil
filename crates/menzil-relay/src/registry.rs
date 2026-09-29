//! Tracks which NodeId currently has an attached, routable session
//! (protocol.md 4.1: "the new session is not routable and does not
//! supersede an existing one until the node's first transport record,
//! ATTACH, is decrypted. Then the previous session for that NodeId
//! receives GOAWAY `superseded`"; protocol.md 10: "Sessions per NodeId: 1
//! attached").
//!
//! Forwarding a SEND to whatever session is registered here is a
//! separate, later item's job (the flow-control paragraph of protocol.md
//! 4.2): this only tracks *which* session, if any, currently owns a
//! NodeId, and how to tell a superseded one to leave.

use std::collections::HashMap;
use std::sync::RwLock;

use menzil_proto::NodeId;
use tokio::sync::oneshot;

struct Registration {
    session_id: u32,
    supersede: oneshot::Sender<()>,
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
    /// returning a receiver that fires once — with no payload, since the
    /// only thing to communicate is that it happened — when *this*
    /// registration is later superseded (it is simply dropped, and never
    /// fires, if that never happens). If another session was already
    /// registered for this NodeId, its own receiver fires immediately
    /// and it is replaced right away; callers do not wait for the old
    /// session to actually finish leaving before this returns.
    pub fn attach(&self, node_id: NodeId, session_id: u32) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        let mut guard = self.by_node.write().unwrap();
        if let Some(previous) = guard.insert(
            node_id,
            Registration {
                session_id,
                supersede: tx,
            },
        ) {
            let _ = previous.supersede.send(());
        }
        rx
    }

    /// Removes `node_id`'s registration, but only if it still belongs to
    /// `session_id`: a session that already lost a supersede race must
    /// not delete the newer registration that replaced it on its own way
    /// out.
    pub fn detach(&self, node_id: &NodeId, session_id: u32) {
        let mut guard = self.by_node.write().unwrap();
        if guard
            .get(node_id)
            .is_some_and(|registration| registration.session_id == session_id)
        {
            guard.remove(node_id);
        }
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
        let _rx = registry.attach(node_id, 1);
        assert_eq!(registry.attached_session_id(&node_id), Some(1));
        registry.detach(&node_id, 1);
        assert_eq!(registry.attached_session_id(&node_id), None);
    }

    #[test]
    fn attaching_again_supersedes_the_previous_registration() {
        let registry = SessionRegistry::new();
        let node_id = NodeId::from([1u8; 32]);
        let mut old_rx = registry.attach(node_id, 1);
        assert!(old_rx.try_recv().is_err(), "not superseded yet");

        let _new_rx = registry.attach(node_id, 2);
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
        let _old_rx = registry.attach(node_id, 1);
        let _new_rx = registry.attach(node_id, 2);

        // Session 1's own cleanup runs after it was already superseded.
        registry.detach(&node_id, 1);
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
        let _rx_a = registry.attach(a, 1);
        let _rx_b = registry.attach(b, 2);
        registry.detach(&a, 1);
        assert_eq!(registry.attached_session_id(&a), None);
        assert_eq!(registry.attached_session_id(&b), Some(2));
    }
}
