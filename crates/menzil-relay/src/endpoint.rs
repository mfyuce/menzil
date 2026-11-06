//! The relay as an L3 endpoint (expose design 3, slice S-E2): a SEND whose `dst` is the relay's
//! own NodeId is not forwarded to anyone and is not refused. It is handed to a consumer inside
//! the relay (later the expose principal, which speaks L4 to the node), and the sender is
//! credited exactly like a pair: the session starts with `limits.credit`, a reliable frame
//! spends its charge, and the charge comes back as a CREDIT record `{peer: relay_id}` once the
//! consumer is done with the frame ([`InboundFrame`] is dropped). A reliable frame beyond the
//! credit is the same protocol violation as for a pair: ERROR `credit_exceeded` and the session
//! ends.
//!
//! Who may send: any session that is currently attached (the caller checks `is_current`). No
//! Roster or claim is consulted here, because nothing is forwarded: whether a frame means
//! anything is the consumer's business, and it is a Noise handshake, not this module, that
//! authenticates it. Every frame costs at least [`MIN_FORWARD_CHARGE_BYTES`] against the credit,
//! as for a pair, so the number of frames in flight is bounded too.
//!
//! Bounds. Reliable frames in flight are bounded by the credit (at most
//! [`MAX_QUEUE_BYTES`], clamped in `Relay::new`) per session. Droppable frames are not credited;
//! their bytes in flight are held under the headroom the credit leaves in the 4 MiB queue
//! (`MAX_QUEUE_BYTES - credit`), and a droppable frame over it is dropped silently, as for a
//! pair. There is no token bucket and no tenant charge on this direction: the node's tenant is
//! not known to the relay here (a node may be in several), the consumer knows the name and
//! charges its own traffic when it answers ([`crate::forward::ForwardTable::forward_from_relay`]).
//!
//! With no consumer subscribed a frame is dropped at once and its credit returns at once, so a
//! node can neither learn that the relay has no expose principal nor park memory in it.
//!
//! Frames leave through an unbounded channel: its size is bounded by the credit above, not by
//! the channel, for the same reason the data plane's `SessionRegistry::deliver` is unbounded.

use std::sync::{Arc, Mutex, PoisonError};

use menzil_proto::{ErrorBody, ErrorCode, Limits, NodeId};
use menzil_session::CreditLedger;
use tokio::sync::mpsc;

use crate::forward::{ForwardItem, MAX_QUEUE_BYTES};
use crate::registry::SessionRegistry;

/// The minimum a frame is charged, the same floor a pair uses.
const MIN_FORWARD_CHARGE_BYTES: u32 = menzil_proto::MIN_SEND_CHARGE_BYTES;

/// What a session may still send to the relay: the reliable credit ledger and the droppable bytes
/// in flight. One per attached session; a new session starts afresh (protocol.md 4.2 scopes
/// credit to the session).
pub(crate) struct EndpointCredit {
    ledgers: Arc<Mutex<Ledgers>>,
    /// The credit the session started with, which also sets the droppable headroom.
    initial_credit: u32,
}

struct Ledgers {
    credit: CreditLedger,
    droppable_in_flight: usize,
}

impl EndpointCredit {
    /// A session's allowance: `limits.credit` (as WELCOME announced it) clamped to the queue.
    pub(crate) fn new(limits: &Limits) -> Self {
        let initial_credit = limits.credit.min(MAX_QUEUE_BYTES as u32);
        Self {
            ledgers: Arc::new(Mutex::new(Ledgers {
                credit: CreditLedger::new(initial_credit),
                droppable_in_flight: 0,
            })),
            initial_credit,
        }
    }

    fn lock(ledgers: &Mutex<Ledgers>) -> std::sync::MutexGuard<'_, Ledgers> {
        ledgers.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The reliable credit left (tests).
    #[cfg(test)]
    pub(crate) fn remaining(&self) -> u32 {
        Self::lock(&self.ledgers).credit.remaining()
    }

    /// The droppable bytes in flight (tests).
    #[cfg(test)]
    pub(crate) fn droppable_in_flight(&self) -> usize {
        Self::lock(&self.ledgers).droppable_in_flight
    }
}

/// Gives the charge of one frame back when the frame is dropped: to the ledger, and for a
/// reliable frame as a CREDIT record to the session it came from. Dropping is the whole
/// interface, so a consumer that forgets a frame, or a channel that is closed, cannot leak
/// credit.
struct CreditTicket {
    ledgers: Arc<Mutex<Ledgers>>,
    registry: Arc<SessionRegistry>,
    node: NodeId,
    session_id: u32,
    relay_id: NodeId,
    charge: u32,
    reliable: bool,
}

impl Drop for CreditTicket {
    fn drop(&mut self) {
        {
            let mut ledgers = EndpointCredit::lock(&self.ledgers);
            if self.reliable {
                ledgers.credit.grant(self.charge);
            } else {
                ledgers.droppable_in_flight = ledgers
                    .droppable_in_flight
                    .saturating_sub(self.charge as usize);
            }
        }
        if self.reliable {
            // Only to the session that spent it: a node that re-attached has a fresh ledger.
            self.registry.deliver_to_session(
                &self.node,
                self.session_id,
                ForwardItem::Credit {
                    peer: self.relay_id,
                    bytes: self.charge,
                },
            );
        }
    }
}

/// One SEND a node addressed to the relay, as the consumer sees it. Drop it when it has been
/// dealt with: that is what returns the sender's credit.
pub struct InboundFrame {
    /// The attached node that sent it (the relay knows it from the L3 session, not from the
    /// frame).
    pub src: NodeId,
    /// The L3 session id of the sender at the time: a frame of an older session is stale when
    /// the node has re-attached since (compare with [`crate::Relay::attached_node`]).
    pub session_id: u32,
    /// `e2e_proto` of the SEND (0x01 or 0x02).
    pub e2e_proto: u8,
    /// The SEND flags: bit 0 set means droppable.
    pub flags: u8,
    /// The payload, uninterpreted.
    pub payload: Vec<u8>,
    _ticket: CreditTicket,
}

impl std::fmt::Debug for InboundFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InboundFrame")
            .field("src", &self.src)
            .field("session_id", &self.session_id)
            .field("e2e_proto", &self.e2e_proto)
            .field("flags", &self.flags)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// What [`RelayEndpoint::accept`] decided; the session driver acts on it.
#[derive(Debug)]
pub(crate) enum EndpointOutcome {
    /// Handed to the consumer, or dropped for want of one or of room: the sender hears nothing.
    Taken,
    /// Refused; send the error and keep the session.
    Refused(ErrorBody),
    /// A reliable frame beyond the credit: send the error and end the session.
    CreditViolation(ErrorBody),
}

/// The relay's end of the frames nodes send to its NodeId: at most one consumer at a time.
#[derive(Default)]
pub struct RelayEndpoint {
    consumer: Mutex<Option<mpsc::UnboundedSender<InboundFrame>>>,
}

impl RelayEndpoint {
    /// Becomes the consumer of every frame sent to the relay from now on. A consumer that was
    /// subscribed before stops receiving (its channel ends).
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<InboundFrame> {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.consumer.lock().unwrap_or_else(PoisonError::into_inner) = Some(tx);
        rx
    }

    /// Takes one SEND addressed to the relay from the attached session `session_id` of `src`,
    /// whose allowance is `credit`. `registry` is where the CREDIT record goes.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn accept(
        &self,
        registry: &Arc<SessionRegistry>,
        relay_id: NodeId,
        credit: &EndpointCredit,
        src: NodeId,
        session_id: u32,
        e2e_proto: u8,
        flags: u8,
        payload: Vec<u8>,
    ) -> EndpointOutcome {
        let reliable = flags & 0x01 == 0;
        let charge = (payload.len() as u32).max(MIN_FORWARD_CHARGE_BYTES);
        if e2e_proto != 0x01 && e2e_proto != 0x02 {
            // The sender spent the credit on its side; nothing was taken here, so put it back.
            if reliable {
                registry.deliver_to_session(
                    &src,
                    session_id,
                    ForwardItem::Credit {
                        peer: relay_id,
                        bytes: charge,
                    },
                );
            }
            return EndpointOutcome::Refused(ErrorBody {
                code: ErrorCode::UnknownE2e,
                msg: format!("unrecognized e2e_proto {e2e_proto:#04x}"),
            });
        }
        {
            let mut ledgers = EndpointCredit::lock(&credit.ledgers);
            if reliable {
                if let Err(err) = ledgers.credit.consume(charge) {
                    return EndpointOutcome::CreditViolation(ErrorBody {
                        code: ErrorCode::CreditExceeded,
                        msg: err.to_string(),
                    });
                }
            } else {
                let ceiling = MAX_QUEUE_BYTES.saturating_sub(credit.initial_credit as usize);
                if ledgers.droppable_in_flight + charge as usize > ceiling {
                    return EndpointOutcome::Taken;
                }
                ledgers.droppable_in_flight += charge as usize;
            }
        }
        // From here the ticket owns the charge: any path that drops the frame gives it back.
        let frame = InboundFrame {
            src,
            session_id,
            e2e_proto,
            flags,
            payload,
            _ticket: CreditTicket {
                ledgers: Arc::clone(&credit.ledgers),
                registry: Arc::clone(registry),
                node: src,
                session_id,
                relay_id,
                charge,
                reliable,
            },
        };
        let consumer = self
            .consumer
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(consumer) = consumer {
            // A closed channel hands the frame back inside the error; dropping it returns the
            // credit.
            let _ = consumer.send(frame);
        }
        EndpointOutcome::Taken
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(credit: u32) -> Limits {
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit,
        }
    }

    const RELAY: [u8; 32] = [0xee; 32];

    struct Fixture {
        endpoint: RelayEndpoint,
        registry: Arc<SessionRegistry>,
        credit: EndpointCredit,
        node: NodeId,
        forward_rx: tokio::sync::mpsc::UnboundedReceiver<ForwardItem>,
        // Keeps the registration's other channels alive.
        _handles: (
            tokio::sync::oneshot::Receiver<()>,
            tokio::sync::mpsc::Receiver<menzil_proto::Record>,
        ),
    }

    fn fixture(credit: u32) -> Fixture {
        let registry = Arc::new(SessionRegistry::new());
        let node = NodeId::from([1u8; 32]);
        let (supersede, outbound, forward_rx) = registry.attach(node, 7, vec![]);
        Fixture {
            endpoint: RelayEndpoint::default(),
            registry,
            credit: EndpointCredit::new(&limits(credit)),
            node,
            forward_rx,
            _handles: (supersede, outbound),
        }
    }

    impl Fixture {
        fn send(&self, flags: u8, len: usize) -> EndpointOutcome {
            self.send_proto(0x01, flags, len)
        }

        fn send_proto(&self, e2e_proto: u8, flags: u8, len: usize) -> EndpointOutcome {
            self.endpoint.accept(
                &self.registry,
                NodeId::from(RELAY),
                &self.credit,
                self.node,
                7,
                e2e_proto,
                flags,
                vec![0u8; len],
            )
        }

        fn credits(&mut self) -> Vec<(NodeId, u32)> {
            let mut out = Vec::new();
            while let Ok(item) = self.forward_rx.try_recv() {
                if let ForwardItem::Credit { peer, bytes } = item {
                    out.push((peer, bytes));
                }
            }
            out
        }
    }

    #[test]
    fn a_reliable_frame_spends_credit_and_dropping_it_returns_credit_and_a_credit_record() {
        let mut f = fixture(1000);
        let mut rx = f.endpoint.subscribe();
        assert!(matches!(f.send(0, 200), EndpointOutcome::Taken));
        assert_eq!(f.credit.remaining(), 800);
        assert!(
            f.credits().is_empty(),
            "nothing is granted back before it is consumed"
        );

        let frame = rx.try_recv().expect("the consumer got the frame");
        assert_eq!(frame.src, f.node);
        assert_eq!(frame.payload.len(), 200);
        drop(frame);
        assert_eq!(f.credit.remaining(), 1000);
        assert_eq!(f.credits(), vec![(NodeId::from(RELAY), 200)]);
    }

    #[test]
    fn a_reliable_frame_beyond_the_credit_is_a_credit_violation() {
        let f = fixture(300);
        let _rx = f.endpoint.subscribe();
        assert!(matches!(f.send(0, 200), EndpointOutcome::Taken));
        match f.send(0, 200) {
            EndpointOutcome::CreditViolation(error) => {
                assert_eq!(error.code, ErrorCode::CreditExceeded)
            }
            other => panic!("expected a credit violation, got {other:?}"),
        }
        assert_eq!(f.credit.remaining(), 100, "a refused frame spends nothing");
    }

    #[test]
    fn the_floor_applies_to_a_tiny_frame() {
        let f = fixture(1000);
        let _rx = f.endpoint.subscribe();
        assert!(matches!(f.send(0, 0), EndpointOutcome::Taken));
        assert_eq!(f.credit.remaining(), 1000 - MIN_FORWARD_CHARGE_BYTES);
    }

    #[test]
    fn without_a_consumer_a_frame_is_dropped_and_its_credit_comes_straight_back() {
        let mut f = fixture(1000);
        assert!(matches!(f.send(0, 200), EndpointOutcome::Taken));
        assert_eq!(f.credit.remaining(), 1000);
        assert_eq!(f.credits(), vec![(NodeId::from(RELAY), 200)]);
    }

    #[test]
    fn a_consumer_that_went_away_returns_the_credit_too() {
        let mut f = fixture(1000);
        drop(f.endpoint.subscribe());
        assert!(matches!(f.send(0, 200), EndpointOutcome::Taken));
        assert_eq!(f.credit.remaining(), 1000);
        assert_eq!(f.credits().len(), 1);
    }

    #[test]
    fn a_new_subscriber_replaces_the_old_one() {
        let f = fixture(1000);
        let mut old = f.endpoint.subscribe();
        let mut new = f.endpoint.subscribe();
        assert!(matches!(f.send(0, 100), EndpointOutcome::Taken));
        assert!(new.try_recv().is_ok());
        assert!(old.try_recv().is_err());
    }

    #[test]
    fn an_unknown_e2e_proto_is_refused_and_the_credit_reimbursed_without_touching_the_ledger() {
        let mut f = fixture(1000);
        let _rx = f.endpoint.subscribe();
        match f.send_proto(0x7f, 0, 200) {
            EndpointOutcome::Refused(error) => assert_eq!(error.code, ErrorCode::UnknownE2e),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert_eq!(f.credit.remaining(), 1000);
        assert_eq!(f.credits(), vec![(NodeId::from(RELAY), 200)]);
    }

    #[test]
    fn droppable_frames_are_bounded_by_the_headroom_and_never_credited() {
        // Credit 1 MiB leaves 3 MiB of headroom in the 4 MiB queue.
        let mut f = fixture(1 << 20);
        let mut rx = f.endpoint.subscribe();
        let ceiling = MAX_QUEUE_BYTES - (1 << 20);
        let mut held = Vec::new();
        let mut taken = 0;
        while taken + 65_000 <= ceiling {
            assert!(matches!(f.send(1, 65_000), EndpointOutcome::Taken));
            held.push(rx.try_recv().expect("within the headroom"));
            taken += 65_000;
        }
        assert_eq!(f.credit.droppable_in_flight(), taken);
        // The next one does not fit: dropped silently, nothing reaches the consumer.
        assert!(matches!(f.send(1, 65_000), EndpointOutcome::Taken));
        assert!(rx.try_recv().is_err(), "over the headroom is dropped");
        assert_eq!(f.credit.droppable_in_flight(), taken);
        assert_eq!(
            f.credit.remaining(),
            1 << 20,
            "droppable never spends credit"
        );

        held.clear();
        assert_eq!(f.credit.droppable_in_flight(), 0);
        assert!(
            f.credits().is_empty(),
            "droppable is never granted back as CREDIT"
        );
    }

    #[test]
    fn a_frame_returns_credit_only_to_the_session_that_spent_it() {
        let f = fixture(1000);
        let mut rx = f.endpoint.subscribe();
        assert!(matches!(f.send(0, 100), EndpointOutcome::Taken));
        let frame = rx.try_recv().unwrap();
        // The node re-attaches (session 8) before the consumer is done.
        let (_s, _o, mut new_forward) = f.registry.attach(f.node, 8, vec![]);
        drop(frame);
        assert!(
            new_forward.try_recv().is_err(),
            "the new session has a ledger of its own and is owed nothing"
        );
    }
}
