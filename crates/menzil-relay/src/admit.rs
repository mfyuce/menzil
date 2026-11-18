//! Invite redemption, the relay's side (protocol.md 7.2, design note
//! `relay-key-and-invites-design.md` B4, slice D3 B2).
//!
//! A HELLO that claims no network opens a *redeem session*: the relay judges only the NodeCert,
//! and the session may do one thing, send ADMIT_REQUEST as its first transport record (control
//! records, PING and REKEY, are answered as in any session). It is never attached and never
//! routable, and no ATTACH, SEND or ADVERTISE is acted on: any other record ends it with ERROR
//! `not_member`. It counts against the unattached figures of its address and its NodeId (the
//! `IpSlot` and `NodeSlot` the session holds), and it lives at most
//! [`RedeemLimits::max_wait`] (10 minutes) once its request is held.
//!
//! What the relay checks on a request (`check_request`): it decodes, `roles` is empty, `expires`
//! is ahead, the request's `node_cert` names the session's own NodeId, the network is served and
//! its Roster names the invite's signer as the owner (the network id is the owner's key) or as a
//! steward with `admit` and a `not_after` ahead, and the signature verifies. The invite carries
//! no signer field, so the relay tries the owner key and every eligible steward key. Every
//! failure, an unserved network included, gets the same ERROR `bad_invite` with the same message
//! (isolation rule I2): the signature work is the same whatever the Roster holds (the owner key
//! and one steward slot are always verified, a dummy key filling the slot when the network has
//! no eligible steward or is not served), and the verdict "served" is combined only after all of
//! it. The relay cannot check the tag (it needs the secret); the issuer does.
//!
//! A request that passes is *held*, in memory only (a relay restart loses it, the device retries;
//! this is documented behaviour, nothing is persisted): at most [`RedeemLimits::per_network`]
//! per network (100), [`RedeemLimits::per_invite`] per invite id (8, counted per network),
//! [`HOLD_PER_NODE`] per NodeId (1, by construction: the book is keyed by NodeId) and
//! [`RedeemLimits::per_address`] per source address
//! (4, an IPv6 address by its /64); over a figure the answer is ERROR `rate_limited`.
//!
//! Issuers register with ADMIT_LISTEN on an *attached* session of the network: the proof must
//! verify over (this relay's NodeId, the session's NodeId, the session's HELLO timestamp) by the
//! owner key or a steward with `admit` (`on_listen`). The newest registration of a network
//! receives its ADMIT_PENDING records, the held ones at registration and each new one as it is
//! held; a registration whose signer has since lost its right (the Roster no longer names it) is
//! dropped at the next delivery. With no registration the device is answered
//! ADMIT_RESULT `{ pending: true }` and its request stays held. ADMIT_REFUSED from the
//! registered session becomes ADMIT_RESULT `{ refused: code }` for the matching request (from
//! any other session it is ignored). Success needs no record: the redeem session listens to
//! Roster changes (`RosterStore::subscribe`, whichever path stored the Roster) and, when the held
//! Roster lists its NodeId unrevoked, sends ADMIT_RESULT `{ roster, base_roster? }` and ends.
//!
//! Delivery of ADMIT_PENDING goes through `SessionRegistry::send_to`, which is best effort (a
//! full outbound queue drops it); a device whose request was dropped that way waits for the
//! relay's cap on its session and retries.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use menzil_proto::{
    AdmitListenBody, AdmitRefusedBody, AdmitRequestBody, AdmitResultBody, ErrorBody, ErrorCode,
    InviteId, NetworkId, NodeId, Record, Tai64N,
};
use menzil_session::{Liveness, RekeySchedule, Transport};
use tokio::sync::mpsc;

use crate::admission::{IpSlot, PeerKey};
use crate::connection::InboundConnection;
use crate::rate::SessionBudget;
use crate::relay::Relay;
use crate::session::{
    PreAttach, REJECTION_LINGER, StandingWatch, TICK, TickOutcome, on_tick, send_record, unix_now,
};

/// Requests held per network (protocol.md section 10).
pub const HOLD_PER_NETWORK: usize = 100;
/// Requests held per invite id of a network.
pub const HOLD_PER_INVITE: usize = 8;
/// Requests held per NodeId (fixed: the book holds one entry per NodeId).
pub const HOLD_PER_NODE: usize = 1;
/// Requests held per source address (an IPv6 address by its /64).
pub const HOLD_PER_ADDRESS: usize = 4;
/// The longest a redeem session lives once its request is held.
pub const REDEEM_MAX_WAIT: Duration = Duration::from_secs(600);

/// The figures of redeem sessions. [`Default`] is the constants above; set once per relay
/// (`Relay::with_redeem_limits`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedeemLimits {
    /// Held requests per network; the next is answered ERROR `rate_limited`.
    pub per_network: usize,
    /// Held requests per invite id (within a network).
    pub per_invite: usize,
    /// Held requests per source address.
    pub per_address: usize,
    /// How long a redeem session whose request is held may live.
    pub max_wait: Duration,
}

impl Default for RedeemLimits {
    fn default() -> Self {
        Self {
            per_network: HOLD_PER_NETWORK,
            per_invite: HOLD_PER_INVITE,
            per_address: HOLD_PER_ADDRESS,
            max_wait: REDEEM_MAX_WAIT,
        }
    }
}

/// One held request.
struct Entry {
    id: u64,
    network: NetworkId,
    invite_id: InviteId,
    peer: PeerKey,
    request: Arc<AdmitRequestBody>,
    answer: mpsc::Sender<u16>,
}

/// The registered issuer session of a network.
#[derive(Clone, Copy)]
struct Listener {
    node_id: NodeId,
    session_id: u32,
    signer: [u8; 32],
}

#[derive(Default)]
struct Inner {
    next_id: u64,
    by_node: HashMap<NodeId, Entry>,
    per_network: HashMap<NetworkId, usize>,
    per_invite: HashMap<(NetworkId, InviteId), usize>,
    per_peer: HashMap<PeerKey, usize>,
    listeners: HashMap<NetworkId, Listener>,
}

/// The relay's held requests and issuer registrations (memory only).
pub(crate) struct AdmitBook {
    limits: RedeemLimits,
    inner: Mutex<Inner>,
    /// Signature verifications `check_request` did (tests: the work must not depend on whether
    /// the network is served).
    #[cfg(test)]
    verifies: std::sync::atomic::AtomicUsize,
}

fn decrement<K: std::hash::Hash + Eq>(map: &mut HashMap<K, usize>, key: &K) {
    if let Some(count) = map.get_mut(key) {
        *count -= 1;
        if *count == 0 {
            map.remove(key);
        }
    }
}

impl AdmitBook {
    pub(crate) fn new(limits: RedeemLimits) -> Self {
        Self {
            limits,
            inner: Mutex::new(Inner::default()),
            #[cfg(test)]
            verifies: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(crate) fn limits(&self) -> RedeemLimits {
        self.limits
    }

    /// Holds `request` for `node_id` unless a figure is reached. The returned guard releases
    /// the place when dropped; the receiver gets a refusal code from the registered issuer.
    fn hold(
        self: &Arc<Self>,
        network: NetworkId,
        invite_id: InviteId,
        node_id: NodeId,
        peer: PeerKey,
        request: Arc<AdmitRequestBody>,
    ) -> Result<(Held, mpsc::Receiver<u16>), ()> {
        let mut inner = self.inner.lock().unwrap();
        let limits = &self.limits;
        if inner.by_node.contains_key(&node_id) {
            return Err(());
        }
        if inner.per_peer.get(&peer).copied().unwrap_or(0) >= limits.per_address {
            return Err(());
        }
        if inner
            .per_invite
            .get(&(network, invite_id))
            .copied()
            .unwrap_or(0)
            >= limits.per_invite
        {
            return Err(());
        }
        if inner.per_network.get(&network).copied().unwrap_or(0) >= limits.per_network {
            return Err(());
        }
        let id = inner.next_id;
        inner.next_id += 1;
        let (answer, answers) = mpsc::channel(2);
        *inner.per_network.entry(network).or_insert(0) += 1;
        *inner.per_invite.entry((network, invite_id)).or_insert(0) += 1;
        *inner.per_peer.entry(peer).or_insert(0) += 1;
        inner.by_node.insert(
            node_id,
            Entry {
                id,
                network,
                invite_id,
                peer,
                request,
                answer,
            },
        );
        drop(inner);
        Ok((
            Held {
                book: Arc::clone(self),
                node_id,
                id,
            },
            answers,
        ))
    }

    fn release(&self, node_id: &NodeId, id: u64) {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .by_node
            .get(node_id)
            .is_none_or(|entry| entry.id != id)
        {
            return;
        }
        if let Some(entry) = inner.by_node.remove(node_id) {
            decrement(&mut inner.per_network, &entry.network);
            decrement(&mut inner.per_invite, &(entry.network, entry.invite_id));
            decrement(&mut inner.per_peer, &entry.peer);
        }
    }

    /// Registers `node_id`'s session as the issuer of `network` (the newest wins).
    fn register(&self, network: NetworkId, node_id: NodeId, session_id: u32, signer: [u8; 32]) {
        self.inner.lock().unwrap().listeners.insert(
            network,
            Listener {
                node_id,
                session_id,
                signer,
            },
        );
    }

    /// Drops every registration of this session (it is ending).
    pub(crate) fn unlisten(&self, node_id: &NodeId, session_id: u32) {
        self.inner
            .lock()
            .unwrap()
            .listeners
            .retain(|_, l| !(l.node_id == *node_id && l.session_id == session_id));
    }

    fn listener_of(&self, network: &NetworkId) -> Option<Listener> {
        self.inner.lock().unwrap().listeners.get(network).copied()
    }

    fn drop_listener(&self, network: &NetworkId, gone: &Listener) {
        let mut inner = self.inner.lock().unwrap();
        if inner.listeners.get(network).is_some_and(|l| {
            l.node_id == gone.node_id && l.session_id == gone.session_id && l.signer == gone.signer
        }) {
            inner.listeners.remove(network);
        }
    }

    /// The requests held for `network`.
    fn pending_of(&self, network: &NetworkId) -> Vec<Arc<AdmitRequestBody>> {
        self.inner
            .lock()
            .unwrap()
            .by_node
            .values()
            .filter(|entry| entry.network == *network)
            .map(|entry| Arc::clone(&entry.request))
            .collect()
    }

    /// An ADMIT_REFUSED from session (`node_id`, `session_id`): forwarded to the matching held
    /// request only when that session is the registered issuer of the request's network.
    fn refuse(&self, node_id: &NodeId, session_id: u32, body: &AdmitRefusedBody) -> bool {
        let inner = self.inner.lock().unwrap();
        let Some(entry) = inner.by_node.get(&body.node_id) else {
            return false;
        };
        if entry.invite_id != body.invite_id {
            return false;
        }
        let registered = inner
            .listeners
            .get(&entry.network)
            .is_some_and(|l| l.node_id == *node_id && l.session_id == session_id);
        registered && entry.answer.try_send(u16::from(body.code)).is_ok()
    }

    /// How many requests are held in all (tests).
    #[cfg(test)]
    pub(crate) fn held(&self) -> usize {
        self.inner.lock().unwrap().by_node.len()
    }

    /// Whether `network` has a registered issuer (tests).
    #[cfg(test)]
    pub(crate) fn has_listener(&self, network: &NetworkId) -> bool {
        self.inner.lock().unwrap().listeners.contains_key(network)
    }

    #[cfg(test)]
    pub(crate) fn verify_count(&self) -> usize {
        self.verifies.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// A held request; dropping it frees its place under every figure.
struct Held {
    book: Arc<AdmitBook>,
    node_id: NodeId,
    id: u64,
}

impl Drop for Held {
    fn drop(&mut self) {
        self.book.release(&self.node_id, self.id);
    }
}

/// The one ERROR every failed check of an invite gets, whatever failed (rule I2).
fn bad_invite() -> ErrorBody {
    ErrorBody {
        code: ErrorCode::BadInvite,
        msg: "the invite cannot be redeemed here".to_string(),
    }
}

fn error(code: ErrorCode, msg: &str) -> ErrorBody {
    ErrorBody {
        code,
        msg: msg.to_string(),
    }
}

/// The key of a placeholder verification (the Ed25519 base point): used to do the same
/// signature work for a network that has no eligible steward or is not served.
const DUMMY_KEY: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// The network `body` may be redeemed in, or `None` (the caller answers [`bad_invite`] for every
/// `None`). See the module comment for the checks and why their order and cost are what they
/// are.
fn check_request(
    relay: &Relay,
    node_id: &NodeId,
    body: &AdmitRequestBody,
    now: u64,
) -> Option<(NetworkId, InviteId)> {
    let invite = body.invite.decode().ok()?;
    invite.check_roles_empty().ok()?;
    if invite.expires <= now {
        return None;
    }
    // The request is for this session's own device: the Roster that answers it must list the
    // NodeId the relay can hold the request for.
    let cert = body.node_cert.decode().ok()?;
    if cert.node_id != *node_id {
        return None;
    }
    let network = invite.network_id;
    let verify = |key: &[u8; 32]| -> bool {
        #[cfg(test)]
        relay
            .admit
            .verifies
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        VerifyingKey::from_bytes(key).is_ok_and(|key| body.invite.verify(&key).is_ok())
    };
    // The owner key and at least one steward slot are always verified: a served network with
    // no eligible steward and an unserved one do the same work.
    let owner_ok = verify(&<[u8; 32]>::from(network));
    let stewards = relay.rosters.admit_stewards(&network, now);
    let served = stewards.is_some();
    let mut steward_ok = false;
    let mut done = 0usize;
    for key in stewards.iter().flatten() {
        steward_ok |= verify(key);
        done += 1;
    }
    while done < 1 {
        steward_ok |= verify(&DUMMY_KEY);
        done += 1;
    }
    (served & (owner_ok | steward_ok)).then_some((network, invite.invite_id))
}

/// Whether `signer` may speak for `network` now: its owner key, or a steward with `admit`.
fn signer_current(relay: &Relay, network: &NetworkId, signer: &[u8; 32], now: u64) -> bool {
    if *signer == <[u8; 32]>::from(*network) {
        return relay.rosters.serves(network);
    }
    relay
        .rosters
        .admit_stewards(network, now)
        .is_some_and(|keys| keys.contains(signer))
}

/// Sends `request` to the registered issuer of `network`, if there is one that may still speak
/// for it. True when it was handed to the issuer's session.
fn deliver_pending(relay: &Relay, network: &NetworkId, request: &Arc<AdmitRequestBody>) -> bool {
    let Some(listener) = relay.admit.listener_of(network) else {
        return false;
    };
    if !signer_current(relay, network, &listener.signer, unix_now()) {
        relay.admit.drop_listener(network, &listener);
        return false;
    }
    relay
        .registry
        .is_current(&listener.node_id, listener.session_id)
        && relay.registry.send_to(
            &listener.node_id,
            Record::AdmitPending(request.as_ref().clone()),
        )
}

/// ADMIT_LISTEN from the attached session (`node_id`, `session_id`) that claimed
/// `claimed_networks`. Silent on every failure (a forged proof learns nothing); true when the
/// session has sent too many that failed and is to be ended.
pub(crate) fn on_listen(
    relay: &Relay,
    node_id: &NodeId,
    session_id: u32,
    claimed_networks: &[NetworkId],
    hello_timestamp: Tai64N,
    budget: &mut SessionBudget,
    body: &AdmitListenBody,
) -> bool {
    let ok = listen_accepted(
        relay,
        node_id,
        session_id,
        claimed_networks,
        hello_timestamp,
        budget,
        body,
    );
    if ok {
        for request in relay.admit.pending_of(&body.network_id) {
            deliver_pending(relay, &body.network_id, &request);
        }
        return false;
    }
    budget.note_unadopted()
}

fn listen_accepted(
    relay: &Relay,
    node_id: &NodeId,
    session_id: u32,
    claimed_networks: &[NetworkId],
    hello_timestamp: Tai64N,
    budget: &mut SessionBudget,
    body: &AdmitListenBody,
) -> bool {
    if !relay.registry.is_current(node_id, session_id)
        || !claimed_networks.contains(&body.network_id)
        || !budget.listen.try_take()
    {
        return false;
    }
    let Some(relay_id) = relay.relay_id() else {
        return false;
    };
    let signer = <[u8; 32]>::from(body.signer);
    if !signer_current(relay, &body.network_id, &signer, unix_now()) {
        return false;
    }
    if body.verify(relay_id, *node_id, hello_timestamp).is_err() {
        return false;
    }
    relay
        .admit
        .register(body.network_id, *node_id, session_id, signer);
    true
}

/// ADMIT_REFUSED from the attached session (`node_id`, `session_id`). Ignored unless that
/// session is the registered issuer of the request's network.
pub(crate) fn on_refused(
    relay: &Relay,
    node_id: &NodeId,
    session_id: u32,
    body: &AdmitRefusedBody,
) {
    if relay.registry.is_current(node_id, session_id) {
        relay.admit.refuse(node_id, session_id, body);
    }
}

/// ADMIT_RESULT `{ roster, base_roster? }` when the held Roster of `network` lists `node_id`
/// and does not revoke it.
fn admitted_result(
    relay: &Relay,
    network: &NetworkId,
    node_id: &NodeId,
) -> Option<AdmitResultBody> {
    let standing = relay.rosters.standing_of(node_id, network);
    if !standing.listed || standing.revoked {
        return None;
    }
    let (roster, base_roster) = relay.rosters.signed_with_base(network)?;
    Some(AdmitResultBody::Admitted {
        roster,
        base_roster,
    })
}

/// How a redeem session ends.
enum Finish {
    /// The result or error is sent; read and discard for a moment, then close.
    Linger,
    /// Close now (the peer is gone or dead).
    Close,
}

async fn linger(conn: &mut InboundConnection) {
    let _ = tokio::time::timeout(REJECTION_LINGER, async {
        while conn.recv().await.is_ok() {}
    })
    .await;
}

/// Drives one redeem session (a HELLO that claimed no network and passed the NodeCert checks)
/// to its end. `pre_attach` and `ip_slot` are held for the whole life of the session, so it
/// counts against the unattached figures of its NodeId and address until it ends.
pub(crate) async fn run_redeem_session(
    mut conn: InboundConnection,
    mut transport: Transport,
    node_id: NodeId,
    session_id: u32,
    relay: &Relay,
    pre_attach: PreAttach,
    ip_slot: IpSlot,
) {
    let peer = ip_slot.peer_key();
    let now_instant = std::time::Instant::now;
    let mut liveness = Liveness::new(now_instant());
    let mut rekey = RekeySchedule::new(now_instant());
    let mut tick = tokio::time::interval(TICK);
    let deadline = tokio::time::sleep(relay.timeouts.attach);
    tokio::pin!(deadline);
    let mut requested = false;
    // What a held request keeps: its place, the issuer's answers, the network and the Roster
    // watch (all `None` until the request passed).
    let mut guard: Option<Held> = None;
    let mut answers: Option<mpsc::Receiver<u16>> = None;
    let mut waiting_in: Option<NetworkId> = None;
    let mut watch: Option<StandingWatch> = None;

    let finish = loop {
        if conn.is_broken() {
            break Finish::Close;
        }
        let answer = async {
            match answers.as_mut() {
                Some(answers) => answers.recv().await,
                None => std::future::pending().await,
            }
        };
        let roster_changed = async {
            match (watch.as_mut(), waiting_in) {
                (Some(watch), Some(network)) => watch.changed(&[network]).await,
                _ => std::future::pending().await,
            }
        };
        tokio::select! {
            () = &mut deadline => {
                tracing::debug!(session_id, node_id = %node_id, "redeem session timed out, closing");
                break Finish::Close;
            }
            _ = tick.tick() => {
                if on_tick(&mut conn, &mut transport, &liveness, &mut rekey).await == TickOutcome::Dead {
                    break Finish::Close;
                }
            }
            code = answer => {
                if let Some(code) = code {
                    let _ = send_record(
                        &mut conn,
                        &mut transport,
                        Record::AdmitResult(AdmitResultBody::Refused(code)),
                    )
                    .await;
                    break Finish::Linger;
                }
            }
            () = roster_changed => {
                if let Some(network) = waiting_in.as_ref()
                    && let Some(result) = admitted_result(relay, network, &node_id)
                {
                    let _ = send_record(&mut conn, &mut transport, Record::AdmitResult(result)).await;
                    break Finish::Linger;
                }
            }
            incoming = conn.recv() => {
                let Ok(bytes) = incoming else {
                    break Finish::Close;
                };
                let Ok(record) = transport.decrypt_record(&bytes) else {
                    break Finish::Close;
                };
                liveness.note_activity(now_instant());
                match record {
                    Record::Ping { nonce } => {
                        let _ = send_record(&mut conn, &mut transport, Record::Pong { nonce }).await;
                    }
                    Record::Pong { .. } => {}
                    Record::Rekey => transport.rekey_incoming(),
                    Record::AdmitRequest(body) if !requested => {
                        requested = true;
                        match accept_request(relay, &node_id, peer, body) {
                            Err(refusal) => {
                                let _ = send_record(&mut conn, &mut transport, Record::Error(refusal)).await;
                                break Finish::Linger;
                            }
                            Ok(accepted) => {
                                deadline
                                    .as_mut()
                                    .reset(tokio::time::Instant::now() + relay.admit.limits().max_wait);
                                let (held, rx, network, changes, request) = accepted;
                                // The Roster may already list the device (a retry after an
                                // admission whose answer was lost): answer at once.
                                if let Some(result) = admitted_result(relay, &network, &node_id) {
                                    let _ = send_record(&mut conn, &mut transport, Record::AdmitResult(result)).await;
                                    drop(held);
                                    break Finish::Linger;
                                }
                                if !deliver_pending(relay, &network, &request) {
                                    let _ = send_record(
                                        &mut conn,
                                        &mut transport,
                                        Record::AdmitResult(AdmitResultBody::Pending),
                                    )
                                    .await;
                                }
                                guard = Some(held);
                                answers = Some(rx);
                                waiting_in = Some(network);
                                watch = Some(changes);
                            }
                        }
                    }
                    _ => {
                        // ATTACH, SEND, ADVERTISE, a second request, anything else: this session
                        // is not a member's.
                        let refusal = error(
                            ErrorCode::NotMember,
                            "a session that claims no network may only redeem an invite",
                        );
                        let _ = send_record(&mut conn, &mut transport, Record::Error(refusal)).await;
                        break Finish::Linger;
                    }
                }
            }
        }
    };
    drop(guard);
    if matches!(finish, Finish::Linger) {
        linger(&mut conn).await;
    }
    drop(pre_attach);
    drop(ip_slot);
}

/// The checks and the hold of one ADMIT_REQUEST: the held place, its answer channel, the
/// network, a Roster watch started before the caller looks at the Roster, and the request.
#[allow(clippy::type_complexity)]
fn accept_request(
    relay: &Relay,
    node_id: &NodeId,
    peer: PeerKey,
    body: AdmitRequestBody,
) -> Result<
    (
        Held,
        mpsc::Receiver<u16>,
        NetworkId,
        StandingWatch,
        Arc<AdmitRequestBody>,
    ),
    ErrorBody,
> {
    let Some((network, invite_id)) = check_request(relay, node_id, &body, unix_now()) else {
        return Err(bad_invite());
    };
    let request = Arc::new(body);
    // Listening starts before the caller's own look at the Roster, so an adoption between the
    // two is not missed.
    let watch = StandingWatch::new(relay);
    match relay
        .admit
        .hold(network, invite_id, *node_id, peer, Arc::clone(&request))
    {
        Ok((guard, answers)) => Ok((guard, answers, network, watch, request)),
        Err(()) => Err(error(
            ErrorCode::RateLimited,
            "too many invite requests are waiting; try again later",
        )),
    }
}
