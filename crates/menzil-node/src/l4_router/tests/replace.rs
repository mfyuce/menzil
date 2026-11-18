//! D1 R3: the 24 hour replacement of full sessions and the continuation of the streams across
//! it, at the router (protocol.md 5.2, `docs/private/rehandshake-design.md` section 3). One
//! test per row of the decision table, an [`Engine`] driven by hand against a peer played by
//! the test (so every frame, index and counter is the test's to choose); the live test with a
//! real relay is `tests/rehandshake_live.rs`.
//!
//! Time is virtual (`start_paused`): a test advances the clock and calls `on_tick` itself.

use menzil_e2e::ReplaceDurations;
use menzil_proto::{ContinueAckBody, E2eHandshakePayload};

use super::*;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// Figures a test can step through: due at `lifetime` (no jitter), the cap at `cap`, retries
/// every 5 s.
fn cfg(lifetime: u64, cap: u64) -> ReplaceConfig {
    ReplaceConfig {
        durations: ReplaceDurations {
            lifetime: secs(lifetime),
            max_jitter: Duration::ZERO,
            pending_timeout: secs(10),
            retry_delays: vec![secs(5)],
            steady_delay: secs(5),
            hard_cap: secs(cap),
        },
        continuation: true,
        held_timeout: secs(30),
    }
}

/// An engine with its three outputs.
struct Eng {
    engine: Engine,
    /// What the wire task saw leave, oldest first.
    log: Arc<Mutex<Vec<(NodeId, E2eFrame)>>>,
    ready: mpsc::UnboundedReceiver<SessionReady>,
    notices: mpsc::UnboundedReceiver<(u64, SessionNotice)>,
}

fn eng(local: &Party, stores: &Stores, replace: ReplaceConfig) -> Eng {
    let (outbound_tx, mut outbound) = mpsc::channel::<OutboundSend>(1024);
    let (ready_tx, ready) = mpsc::unbounded_channel();
    let (notices_tx, notices) = mpsc::unbounded_channel();
    let config = RouterConfig::new(
        local.identity(),
        NodeId::from([0xAA; 32]),
        stores.policies.clone(),
        stores.rosters.clone(),
        SendBudgets::new(),
    )
    .unwrap()
    .with_replace(replace);
    let (attachment_tx, _) = tokio::sync::watch::channel(None);
    // The engine's own indices: 101, 102, ...
    let mut next = 100u32;
    let mut engine = Engine::new(
        config,
        outbound_tx,
        ready_tx,
        notices_tx,
        attachment_tx,
        move || {
            next += 1;
            next
        },
    );
    engine.on_attached(Epoch::first(), LIMITS, relay_static());
    // The L3 session's stand-in: takes every request, notes the frame, accepts it.
    let log: Arc<Mutex<Vec<(NodeId, E2eFrame)>>> = Arc::default();
    let seen = Arc::clone(&log);
    tokio::spawn(async move {
        while let Some(request) = outbound.recv().await {
            seen.lock()
                .unwrap()
                .push((request.dst, E2eFrame::decode(&request.payload).unwrap()));
            let _ = request.outcome.send(EnqueueOutcome::Accepted);
        }
    });
    Eng {
        engine,
        log,
        ready,
        notices,
    }
}

impl Eng {
    fn recv(&mut self, src: NodeId, frame: &E2eFrame) {
        let record = Record::Recv {
            src,
            e2e_proto: E2E_PROTO_TAG,
            flags: 0,
            payload: frame.encode(),
        };
        assert!(
            self.engine
                .on_record(Epoch::first(), record, Now::capture())
                .is_none()
        );
    }

    /// Every L4 frame the engine (and its actors) sent since the last call, with its
    /// destination.
    async fn frames(&mut self) -> Vec<(NodeId, E2eFrame)> {
        tokio::time::sleep(Duration::from_millis(1)).await;
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    /// Lets the actors run, then hands their notices to the engine, as the router task would.
    async fn pump(&mut self) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        while let Ok((tag, notice)) = self.notices.try_recv() {
            self.engine.on_notice(tag, notice);
        }
    }

    /// Moves the clock by `by` and runs the router's tick.
    async fn advance(&mut self, by: Duration) {
        tokio::time::advance(by).await;
        self.engine.on_tick(Now::capture());
        self.pump().await;
    }

    fn slot(&self, peer: &Party, w: &World) -> SlotState {
        self.engine.table.slot(&peer.id, &w.network)
    }

    fn tag_at(&self, index: u32) -> u64 {
        self.engine.table.get(index).unwrap().tag
    }
}

/// The peer's side of one handshake it started towards the engine.
struct Hs {
    transport: E2eTransport,
    payload: E2eHandshakePayload,
    /// The engine's own index for the session (the `receiver_index` the peer stamps on frames).
    index: u32,
}

impl Eng {
    /// `from` sends the engine an `init` under `wire` and completes the handshake with the
    /// engine's `resp`.
    async fn handshake(&mut self, from: &Party, local: &Party, w: &World, wire: u32) -> Hs {
        let (mut hs, init) = E2eInitiatorHandshake::start(
            &from.x25519_private,
            &local.x25519_public,
            w.network,
            from.id,
            local.id,
            wire,
        )
        .unwrap();
        self.recv(from.id, &init);
        let mut frames = self.frames().await;
        let position = frames
            .iter()
            .position(|(_, f)| matches!(f, E2eFrame::Resp { .. }))
            .expect("the engine answers with a resp");
        let (_, resp) = frames.remove(position);
        // What else the actors sent stays for the test to read.
        self.log.lock().unwrap().extend(frames);
        let E2eFrame::Resp { sender_index, .. } = &resp else {
            unreachable!()
        };
        let index = *sender_index;
        let (transport, payload, _) = hs.finish(&resp, 65_535).unwrap();
        Hs {
            transport,
            payload,
            index,
        }
    }

    /// A full session with `from` as the chain initiator: handshake, first record noted.
    async fn establish(
        &mut self,
        from: &Party,
        local: &Party,
        w: &World,
        wire: u32,
    ) -> (Hs, SessionReady) {
        let hs = self.handshake(from, local, w, wire).await;
        let ready = self.ready.try_recv().expect("a session came up");
        let tag = self.tag_at(hs.index);
        self.engine.on_notice(tag, SessionNotice::FirstRecord);
        assert_eq!(self.slot(from, w).current, Some(hs.index));
        (hs, ready)
    }
}

/// CONTINUE as the peer would send it: the first record of the replacement transport `new`.
fn continue_record(new: &mut E2eTransport, prior: u32, sent: u64, old: &E2eTransport) -> E2eFrame {
    new.encrypt_raw(
        &ContinueBody {
            prior,
            sent,
            binding: continue_binding(old.handshake_hash()),
        }
        .encode(),
    )
    .unwrap()
}

fn world_of(a: &Party, b: &Party) -> (World, Stores) {
    let w = world();
    let stores = w.stores(&[a, b], vec![w.grant(a, b), w.grant(b, a)]);
    (w, stores)
}

/// The first record of `frames` that is a data frame for `receiver_index`, decrypted raw with
/// `transport`.
fn first_raw(
    frames: &[(NodeId, E2eFrame)],
    receiver_index: u32,
    transport: &mut E2eTransport,
) -> Option<Vec<u8>> {
    frames.iter().find_map(|(_, frame)| match frame {
        E2eFrame::Data {
            receiver_index: r,
            counter,
            ciphertext,
        } if *r == receiver_index && RecordClass::of_counter(*counter) == RecordClass::Reliable => {
            Some(transport.decrypt_raw(*counter, ciphertext).unwrap())
        }
        _ => None,
    })
}

// ----------------------------------------------------------------------
// Responder: the decision table of design section 3
// ----------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_second_init_from_the_chain_initiator_is_answered_with_held_and_held_by_the_router() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, _ready) = e.establish(&m, &b, &w, 1).await;
    assert_eq!(first.payload.held, None, "no session yet: nothing to offer");

    let second = e.handshake(&m, &b, &w, 2).await;
    assert_eq!(
        second.payload.held,
        Some(first.index),
        "the current session is offered"
    );
    // The candidate has no actor and no table entry of its own beyond the reserved index; the
    // current session carries on and nobody is told of a new session.
    assert!(e.engine.held.contains_key(&second.index));
    assert!(e.ready.try_recv().is_err());
    let slot = e.slot(&m, &w);
    assert_eq!((slot.current, slot.candidate), (Some(first.index), None));
}

#[tokio::test(start_paused = true)]
async fn no_held_is_offered_when_the_continuation_is_off_or_the_session_is_not_the_peers_to_replace()
 {
    // Off: an old build behaviour.
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut off = cfg(100, 200);
    off.continuation = false;
    let mut e = eng(&b, &stores, off);
    let (first, _ready) = e.establish(&m, &b, &w, 1).await;
    let second = e.handshake(&m, &b, &w, 2).await;
    assert_eq!(second.payload.held, None);
    assert!(e.engine.held.is_empty());
    assert!(
        e.slot(&m, &w).candidate == Some(second.index),
        "an ordinary candidate"
    );
    let _ = first;

    // A session this node started is never offered: the roles never swap, so only the
    // initiator's own replacements can continue it.
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (reply, _answer) = oneshot::channel();
    e.engine
        .ensure(m.id, w.network, false, reply, Now::capture());
    let init = e
        .frames()
        .await
        .into_iter()
        .find_map(|(_, f)| matches!(f, E2eFrame::Init { .. }).then_some(f))
        .unwrap();
    let (_t, resp) = respond(&m, &b, &init, 7_001, None);
    e.recv(m.id, &resp);
    let _ready = e.ready.try_recv().expect("our own session came up");
    assert!(e.slot(&m, &w).current.is_some());
    let again = e.handshake(&m, &b, &w, 2).await;
    assert_eq!(
        again.payload.held, None,
        "a session we started is not the peer's to continue"
    );
}

/// The peer's answer to an `init` of the engine's.
fn respond(
    m: &Party,
    b: &Party,
    init: &E2eFrame,
    own_index: u32,
    held: Option<u32>,
) -> (E2eTransport, E2eFrame) {
    let hs = E2eResponderHandshake::start(&m.x25519_private, b.id, m.id, init).unwrap();
    match held {
        Some(held) => {
            hs.finish_offering_held(m.cert.clone(), 1, 1, vec![0x01], held, own_index, 65_535)
        }
        None => hs.finish(m.cert.clone(), 1, 1, vec![0x01], own_index, 65_535),
    }
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_valid_continue_hands_the_transport_to_the_current_actor_and_the_new_index_takes_over() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, mut ready) = e.establish(&m, &b, &w, 1).await;
    let tag = e.tag_at(first.index);
    let mut second = e.handshake(&m, &b, &w, 2).await;

    // What the actor wrote on the old session so far (reliable, to the peer's index 1).
    e.pump().await;
    let sent_before = e
        .frames()
        .await
        .iter()
        .filter(|(_, f)| {
            matches!(f, E2eFrame::Data { receiver_index: 1, counter, .. }
                if RecordClass::of_counter(*counter) == RecordClass::Reliable)
        })
        .count() as u64;
    let continue_frame = continue_record(&mut second.transport, first.index, 0, &first.transport);
    e.recv(m.id, &continue_frame);

    // The candidate's index is the session's entry now, the old one routes nothing, and the
    // same actor serves it (no new session was announced).
    let slot = e.slot(&m, &w);
    assert_eq!(
        (slot.current, slot.alias, slot.candidate),
        (Some(second.index), None, None)
    );
    assert!(e.engine.table.get(first.index).is_none());
    assert!(e.engine.held.is_empty());
    assert_eq!(e.engine.ages[&tag].index, second.index);
    assert!(e.ready.try_recv().is_err());
    let entry = e.engine.table.get(second.index).unwrap();
    assert!(!entry.is_label());
    assert_eq!(entry.transport_gen, 1);

    // The actor answers CONTINUE_ACK as the first record on the new transport.
    e.pump().await;
    let frames = e.frames().await;
    let plain = first_raw(&frames, 2, &mut second.transport).expect("CONTINUE_ACK");
    // Its `sent` counts the reliable records the actor wrote on the old session (to the
    // peer's first wire index, 1).
    let on_old = frames
        .iter()
        .filter(|(_, f)| {
            matches!(f, E2eFrame::Data { receiver_index: 1, counter, .. }
                if RecordClass::of_counter(*counter) == RecordClass::Reliable)
        })
        .count() as u64
        + sent_before;
    assert_eq!(ContinueAckBody::decode(&plain).unwrap().sent, on_old);

    // And frames of the new index reach it: the peer's CLOSE on the new transport ends the
    // session the first `ready` announced.
    let close = data_frame(
        &mut second.transport,
        second.index,
        &E2eDataBody::Close {
            code: ErrorCode::GrantRemoved,
            msg: String::new(),
        },
    );
    e.recv(m.id, &close);
    let reason = ended(&mut ready.acceptor).await;
    assert!(
        matches!(reason.as_ref(), EndReason::PeerClosed { code, .. } if *code == ErrorCode::GrantRemoved),
        "{reason:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_continue_with_the_wrong_binding_ends_the_session_it_named_and_closes_the_candidate() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, mut ready) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;

    // The binding of some other session's handshake hash.
    let other = [0x42u8; 32];
    let frame = second
        .transport
        .encrypt_raw(
            &ContinueBody {
                prior: first.index,
                sent: 0,
                binding: continue_binding(&other),
            }
            .encode(),
        )
        .unwrap();
    e.recv(m.id, &frame);
    e.pump().await;

    // CLOSE handover_failed on the candidate, the named session ended, nothing installed.
    let frames = e.frames().await;
    let close = frames.iter().find_map(|(_, f)| match f {
        E2eFrame::Data {
            receiver_index: 2,
            counter,
            ciphertext,
        } if *counter == 0 => Some(second.transport.decrypt_data(*counter, ciphertext).unwrap()),
        _ => None,
    });
    assert!(
        matches!(close, Some(E2eDataBody::Close { code, .. }) if code == ErrorCode::HandoverFailed),
        "{close:?}"
    );
    let reason = ended(&mut ready.acceptor).await;
    assert!(
        matches!(reason.as_ref(), EndReason::ClosedLocally(Some(c)) if c.code == ErrorCode::HandoverFailed),
        "{reason:?}"
    );
    assert_eq!(e.slot(&m, &w), SlotState::default());
    assert!(e.engine.held.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_continue_that_names_no_current_session_closes_only_the_candidate() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, mut ready) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;

    let frame = continue_record(
        &mut second.transport,
        first.index + 1000,
        0,
        &first.transport,
    );
    e.recv(m.id, &frame);
    e.pump().await;

    let frames = e.frames().await;
    let close = frames.iter().find_map(|(_, f)| match f {
        E2eFrame::Data {
            receiver_index: 2,
            counter,
            ciphertext,
        } if *counter == 0 => Some(second.transport.decrypt_data(*counter, ciphertext).unwrap()),
        _ => None,
    });
    assert!(
        matches!(close, Some(E2eDataBody::Close { code, .. }) if code == ErrorCode::HandoverFailed)
    );
    // `prior` did not name this slot's current session: it carries on.
    assert!(
        timeout(secs(1), ready.acceptor.closed()).await.is_err(),
        "the current session must not end"
    );
    assert_eq!(e.slot(&m, &w).current, Some(first.index));
    assert!(e.engine.held.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_continue_naming_another_peers_session_touches_neither_session() {
    let (m, n, b) = (party(), party(), party());
    let w = world();
    let stores = w.stores(&[&m, &n, &b], vec![w.grant(&m, &b), w.grant(&n, &b)]);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (m1, mut m_ready) = e.establish(&m, &b, &w, 1).await;
    let (n1, mut n_ready) = e.establish(&n, &b, &w, 1).await;
    let mut m2 = e.handshake(&m, &b, &w, 2).await;

    // M's CONTINUE carries N's index and N's session binding: a member naming someone else's
    // session.
    let frame = continue_record(&mut m2.transport, n1.index, 0, &n1.transport);
    e.recv(m.id, &frame);
    e.pump().await;

    assert!(
        timeout(secs(1), m_ready.acceptor.closed()).await.is_err(),
        "M's own session must not end: `prior` did not name it"
    );
    assert!(
        timeout(secs(1), n_ready.acceptor.closed()).await.is_err(),
        "N's session must not end"
    );
    assert_eq!(e.slot(&n, &w).current, Some(n1.index));
    // M's own current session did not end either: `prior` did not name it.
    assert_eq!(e.slot(&m, &w).current, Some(m1.index));
    assert!(e.engine.held.is_empty());
}

#[tokio::test(start_paused = true)]
async fn another_first_record_replaces_the_session_as_before() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, mut old) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;
    assert!(e.engine.held.contains_key(&second.index));

    // A peer that predates the continuation, or restarted: its first record is MUX.
    let frame = data_frame(&mut second.transport, second.index, &E2eDataBody::Keep);
    e.recv(m.id, &frame);
    assert!(e.engine.held.is_empty());
    let new = e.ready.try_recv().expect("a new session is announced");
    assert_eq!(new.role, Role::Responder);
    e.pump().await;

    // The new actor read the record, which proved it: the old session is retired.
    assert_eq!(e.slot(&m, &w).current, Some(second.index));
    assert!(e.engine.table.get(first.index).is_none());
    let reason = ended(&mut old.acceptor).await;
    assert!(
        matches!(reason.as_ref(), EndReason::ClosedLocally(None)),
        "{reason:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn junk_of_any_length_leaves_the_held_candidate_waiting() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, _old) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;

    for len in [17, 61, 100, 400] {
        e.recv(m.id, &junk_data(second.index, 0, len));
        e.pump().await;
        assert!(e.engine.held.contains_key(&second.index), "len {len}");
        assert!(e.ready.try_recv().is_err(), "len {len}");
        assert_eq!(e.slot(&m, &w).current, Some(first.index), "len {len}");
    }
    // The genuine CONTINUE still lands on the held candidate.
    let frame = continue_record(&mut second.transport, first.index, 0, &first.transport);
    e.recv(m.id, &frame);
    assert_eq!(e.slot(&m, &w).current, Some(second.index));
}

#[tokio::test(start_paused = true)]
async fn a_candidate_without_a_first_record_is_dropped_after_thirty_seconds_and_the_current_stays()
{
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, _old) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;
    let len = e.engine.table.len();

    e.advance(secs(29)).await;
    assert!(e.engine.held.contains_key(&second.index));
    e.advance(secs(2)).await;
    assert!(e.engine.held.is_empty());
    assert_eq!(
        e.engine.table.len(),
        len - 1,
        "its index is back in the table"
    );
    assert_eq!(e.slot(&m, &w).current, Some(first.index));

    // A CONTINUE after that gets no answer and changes nothing.
    let frame = continue_record(&mut second.transport, first.index, 0, &first.transport);
    e.recv(m.id, &frame);
    e.pump().await;
    assert!(e.frames().await.iter().all(|(_, f)| !matches!(
        f,
        E2eFrame::Data {
            receiver_index: 2,
            ..
        }
    )));
    assert_eq!(e.slot(&m, &w).current, Some(first.index));
}

#[tokio::test(start_paused = true)]
async fn a_datagram_or_junk_before_the_first_reliable_record_proves_nothing() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, _old) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;

    // A datagram first: dropped.
    let dgram = second.transport.encrypt_dgram(1, b"hello").unwrap();
    let E2eFrame::Data { counter, .. } = &dgram else {
        unreachable!()
    };
    assert_eq!(RecordClass::of_counter(*counter), RecordClass::Datagram);
    e.recv(m.id, &dgram);
    // Junk of a CONTINUE's length that does not authenticate: dropped, the candidate waits.
    e.recv(m.id, &junk_data(second.index, 0, 61));
    assert!(e.engine.held.contains_key(&second.index));
    assert_eq!(e.slot(&m, &w).current, Some(first.index));

    // The real CONTINUE still works afterwards.
    let frame = continue_record(&mut second.transport, first.index, 0, &first.transport);
    e.recv(m.id, &frame);
    assert_eq!(e.slot(&m, &w).current, Some(second.index));
}

#[tokio::test(start_paused = true)]
async fn a_continue_for_a_peer_that_no_longer_stands_is_refused_synchronously() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, mut old) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;

    // The Roster alone revokes M between the `init` and the CONTINUE; no Revalidator pass ran.
    edit_roster_of(&w, &stores, |body| {
        body.revoked.push(menzil_proto::RevokedMember {
            node_id: m.id,
            since: 0,
        });
    });
    let frame = continue_record(&mut second.transport, first.index, 0, &first.transport);
    e.recv(m.id, &frame);
    e.pump().await;

    assert_eq!(e.slot(&m, &w), SlotState::default(), "nothing carries on");
    let reason = ended(&mut old.acceptor).await;
    assert!(
        matches!(reason.as_ref(), EndReason::ClosedLocally(Some(c)) if c.code == ErrorCode::GrantRemoved),
        "{reason:?}"
    );
    assert!(e.engine.held.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_detach_drops_the_held_candidate_and_gives_its_index_back() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (_first, _old) = e.establish(&m, &b, &w, 1).await;
    let _second = e.handshake(&m, &b, &w, 2).await;
    assert_eq!(e.engine.held.len(), 1);
    e.engine.on_detached(Epoch::first());
    assert!(e.engine.held.is_empty());
    assert!(e.engine.held_slot.is_empty());
    assert!(
        e.engine.table.is_empty(),
        "the reserved index is released too"
    );
}

#[tokio::test(start_paused = true)]
async fn a_repeat_of_the_init_that_made_a_held_candidate_is_ignored() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (_first, _old) = e.establish(&m, &b, &w, 1).await;
    let (_hs, init) = E2eInitiatorHandshake::start(
        &m.x25519_private,
        &b.x25519_public,
        w.network,
        m.id,
        b.id,
        2,
    )
    .unwrap();
    e.recv(m.id, &init);
    assert_eq!(e.engine.held.len(), 1);
    let before = e.frames().await.len();
    assert!(before >= 1);
    e.recv(m.id, &init);
    assert!(e.frames().await.is_empty(), "the copy gets no answer");
    assert_eq!(e.engine.held.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_session_ends_at_the_hard_cap_on_the_responder_side_too() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(20, 30));
    let (_first, mut ready) = e.establish(&m, &b, &w, 1).await;
    e.advance(secs(29)).await;
    assert!(timeout(secs(0), ready.acceptor.closed()).await.is_err());
    e.advance(secs(2)).await;
    let reason = ended(&mut ready.acceptor).await;
    assert!(
        matches!(reason.as_ref(), EndReason::ClosedLocally(Some(c)) if c.code == ErrorCode::SessionExpired),
        "{reason:?}"
    );
    assert_eq!(e.slot(&m, &w), SlotState::default());
    assert!(e.engine.ages.is_empty());
}

// ----------------------------------------------------------------------
// Initiator
// ----------------------------------------------------------------------

/// The engine dials `m`; `m` answers (no `held`: it holds nothing yet). The first session.
async fn dial(
    e: &mut Eng,
    m: &Party,
    b: &Party,
    w: &World,
    m_index: u32,
) -> (E2eTransport, SessionReady) {
    let (reply, _answer) = oneshot::channel();
    e.engine
        .ensure(m.id, w.network, false, reply, Now::capture());
    let init = e
        .frames()
        .await
        .into_iter()
        .find_map(|(_, f)| matches!(f, E2eFrame::Init { .. }).then_some(f))
        .expect("an init");
    let (t, resp) = respond(m, b, &init, m_index, None);
    e.recv(m.id, &resp);
    let ready = e.ready.try_recv().expect("the session came up");
    (t, ready)
}

/// The next `init` the engine sent.
async fn next_init(e: &mut Eng) -> Option<E2eFrame> {
    e.frames()
        .await
        .into_iter()
        .find_map(|(_, f)| matches!(f, E2eFrame::Init { .. }).then_some(f))
}

#[tokio::test(start_paused = true)]
async fn the_chain_initiator_sends_its_replacement_init_when_the_session_is_due() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(20, 40));
    let (_t1, _ready) = dial(&mut e, &m, &b, &w, 7_001).await;
    let _ = e.frames().await;

    e.advance(secs(19)).await;
    assert!(next_init(&mut e).await.is_none(), "not due yet");
    e.advance(secs(2)).await;
    let init = next_init(&mut e).await.expect("the replacement init");
    let E2eFrame::Init { .. } = init else {
        unreachable!()
    };
    let slot = e.slot(&m, &w);
    assert!(
        slot.current.is_some() && slot.pending.is_some(),
        "a pending next to the current"
    );
    // Nobody waits for it.
    assert!(e.engine.waiters.is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_replacement_init_is_retried_by_the_schedule() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(20, 100));
    let (_t1, _ready) = dial(&mut e, &m, &b, &w, 7_001).await;
    e.advance(secs(21)).await;
    assert!(next_init(&mut e).await.is_some());
    // 10 s without a resp, then 5 s of delay, then again.
    e.advance(secs(11)).await;
    assert!(next_init(&mut e).await.is_none());
    e.advance(secs(5)).await;
    assert!(next_init(&mut e).await.is_some(), "the retry");
}

/// Drives the replacement up to the peer's `resp`: returns the engine's own old index, the
/// peer's transports and what the engine sent.
struct Replacing {
    old_index: u32,
    t1: E2eTransport,
    ready: SessionReady,
}

async fn start_replacement(
    e: &mut Eng,
    m: &Party,
    b: &Party,
    w: &World,
    lifetime: u64,
) -> (Replacing, E2eFrame) {
    let (t1, ready) = dial(e, m, b, w, 7_001).await;
    let old_index = e.slot(m, w).current.unwrap();
    let _ = e.frames().await;
    e.advance(secs(lifetime + 1)).await;
    let init = next_init(e).await.expect("the replacement init");
    (
        Replacing {
            old_index,
            t1,
            ready,
        },
        init,
    )
}

#[tokio::test(start_paused = true)]
async fn a_resp_with_the_matching_held_continues_the_session_and_the_cutover_commits_on_the_ack() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(20, 100));
    let (r, init) = start_replacement(&mut e, &m, &b, &w, 20).await;
    let tag = e.tag_at(r.old_index);

    let (mut t2, resp) = respond(&m, &b, &init, 7_002, Some(7_001));
    e.recv(m.id, &resp);
    // Not a new session: an alias routes the replacement's frames to the old actor.
    assert!(e.ready.try_recv().is_err());
    let slot = e.slot(&m, &w);
    assert_eq!(slot.current, Some(r.old_index));
    let alias = slot.alias.expect("an alias");
    assert!(e.engine.table.get(alias).unwrap().is_label());
    assert!(e.engine.ages[&tag].cutover.is_some());

    // The actor sends CONTINUE first on the new transport.
    e.pump().await;
    let frames = e.frames().await;
    let plain = first_raw(&frames, 7_002, &mut t2).expect("CONTINUE");
    let body = ContinueBody::decode(&plain).unwrap();
    assert_eq!(body.prior, 7_001);
    assert_eq!(body.binding, continue_binding(r.t1.handshake_hash()));

    // Before the ACK nothing commits.
    e.advance(secs(1)).await;
    assert_eq!(e.slot(&m, &w).alias, Some(alias));
    // The peer's CONTINUE_ACK, as its first record on the new transport.
    let ack = t2
        .encrypt_raw(
            &ContinueAckBody {
                sent: r.t1.reliable_sent(),
            }
            .encode(),
        )
        .unwrap();
    e.recv(m.id, &ack);
    e.advance(secs(1)).await;

    let slot = e.slot(&m, &w);
    assert_eq!((slot.current, slot.alias), (Some(alias), None));
    assert!(e.engine.table.get(r.old_index).is_none());
    assert!(!e.engine.table.get(alias).unwrap().is_label());
    assert_eq!(e.engine.ages[&tag].index, alias);
    assert!(e.engine.ages[&tag].cutover.is_none());
    assert!(
        e.engine.ages[&tag].schedule.is_some(),
        "a new schedule for the new keys"
    );
    assert!(e.ready.try_recv().is_err(), "the same session throughout");
    // The old actor is the session: it did not end.
    let mut ready = r.ready;
    assert!(timeout(secs(1), ready.acceptor.closed()).await.is_err());
}

#[tokio::test(start_paused = true)]
async fn a_resp_without_a_matching_held_starts_the_replacement_afresh() {
    for held in [None, Some(9_999)] {
        let (m, b) = (party(), party());
        let (w, stores) = world_of(&m, &b);
        let mut e = eng(&b, &stores, cfg(20, 100));
        let (mut r, init) = start_replacement(&mut e, &m, &b, &w, 20).await;

        let (_t2, resp) = respond(&m, &b, &init, 7_002, held);
        e.recv(m.id, &resp);
        // Today's replacement: a new session, the old one closed at once.
        let new = e.ready.try_recv().expect("a new session");
        assert_eq!(new.role, Role::Initiator);
        let slot = e.slot(&m, &w);
        assert_ne!(slot.current, Some(r.old_index));
        assert_eq!(slot.alias, None);
        let reason = ended(&mut r.ready.acceptor).await;
        assert!(
            matches!(reason.as_ref(), EndReason::ClosedLocally(None)),
            "{reason:?}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_docs_only_resp_to_a_replacement_leaves_the_old_session_and_the_schedule_retries() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(20, 100));
    let (mut r, init) = start_replacement(&mut e, &m, &b, &w, 20).await;

    let hs = E2eResponderHandshake::start(&m.x25519_private, b.id, m.id, &init).unwrap();
    let (_t2, resp) = hs
        .finish_docs_only(m.cert.clone(), 1, 1, vec![0x01], 7_002, 65_535)
        .unwrap();
    e.recv(m.id, &resp);
    // The documents push gets its docs only session; the old full session carries on.
    let aside = e.ready.try_recv().expect("the docs only session");
    assert!(aside.docs_only);
    assert_eq!(e.slot(&m, &w).current, Some(r.old_index));
    assert!(timeout(secs(1), r.ready.acceptor.closed()).await.is_err());
    // The schedule retries after its delay.
    e.advance(secs(5)).await;
    assert!(next_init(&mut e).await.is_some(), "retried");
}

#[tokio::test(start_paused = true)]
async fn the_initiator_ends_a_session_at_the_hard_cap_when_every_replacement_fails() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(10, 25));
    let (_t1, mut ready) = dial(&mut e, &m, &b, &w, 7_001).await;
    // Nobody answers any replacement init; the session lives until the cap.
    for _ in 0..5 {
        e.advance(secs(6)).await;
    }
    let reason = ended(&mut ready.acceptor).await;
    assert!(
        matches!(reason.as_ref(), EndReason::ClosedLocally(Some(c)) if c.code == ErrorCode::SessionExpired),
        "{reason:?}"
    );
    assert_eq!(e.slot(&m, &w), SlotState::default());
}

#[tokio::test(start_paused = true)]
async fn a_replacement_in_flight_is_abandoned_with_its_attachment() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(20, 100));
    let (_r, _init) = start_replacement(&mut e, &m, &b, &w, 20).await;
    assert!(e.slot(&m, &w).pending.is_some());
    e.engine.on_detached(Epoch::first());
    assert!(e.engine.table.is_empty());
    assert!(e.engine.ages.is_empty() || e.engine.ages.values().all(|a| a.cutover.is_none()));
}

#[tokio::test(start_paused = true)]
async fn a_revoked_peer_ends_both_the_old_session_and_the_continuation_in_progress() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, cfg(20, 100));
    let (r, init) = start_replacement(&mut e, &m, &b, &w, 20).await;
    let (_t2, resp) = respond(&m, &b, &init, 7_002, Some(7_001));
    e.recv(m.id, &resp);
    assert!(e.slot(&m, &w).alias.is_some());

    // The old actor ends (the Revalidator's `grant_removed`): the table forgets the session
    // and its alias together.
    r.ready.handle.close(Some(grant_removed_close()));
    e.pump().await;
    assert_eq!(e.slot(&m, &w), SlotState::default());
    assert!(e.engine.ages.is_empty() || e.engine.ages.values().all(|a| a.cutover.is_none()));
}

#[tokio::test(start_paused = true)]
async fn a_record_for_a_held_candidate_from_another_source_is_not_read() {
    let (m, n, b) = (party(), party(), party());
    let w = world();
    let stores = w.stores(&[&m, &n, &b], vec![w.grant(&m, &b), w.grant(&n, &b)]);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (first, _old) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;

    // A valid CONTINUE, but the relay stamps another member's NodeId on it.
    let frame = continue_record(&mut second.transport, first.index, 0, &first.transport);
    e.recv(n.id, &frame);
    e.pump().await;
    assert!(e.engine.held.contains_key(&second.index), "still waiting");
    assert_eq!(e.slot(&m, &w).current, Some(first.index));
    // From the real source it is still accepted.
    e.recv(m.id, &frame);
    assert_eq!(e.slot(&m, &w).current, Some(second.index));
}

#[tokio::test(start_paused = true)]
async fn a_replacement_candidate_of_a_peer_that_no_longer_stands_gets_no_session() {
    let (m, b) = (party(), party());
    let (w, stores) = world_of(&m, &b);
    let mut e = eng(&b, &stores, ReplaceConfig::default());
    let (_first, _old) = e.establish(&m, &b, &w, 1).await;
    let mut second = e.handshake(&m, &b, &w, 2).await;
    edit_roster_of(&w, &stores, |body| {
        body.revoked.push(menzil_proto::RevokedMember {
            node_id: m.id,
            since: 0,
        });
    });
    // Not a CONTINUE: a peer that restarted.
    let frame = data_frame(&mut second.transport, second.index, &E2eDataBody::Keep);
    e.recv(m.id, &frame);
    e.pump().await;
    assert!(
        e.ready.try_recv().is_err(),
        "no new session for a peer that was revoked"
    );
    assert!(e.engine.held.is_empty());
    let close = e.frames().await.into_iter().find_map(|(_, f)| match f {
        E2eFrame::Data {
            receiver_index: 2,
            counter,
            ciphertext,
        } if counter == 0 => Some(second.transport.decrypt_data(counter, &ciphertext).unwrap()),
        _ => None,
    });
    assert!(
        matches!(close, Some(E2eDataBody::Close { code, .. }) if code == ErrorCode::GrantRemoved)
    );
}
