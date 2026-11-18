//! The issuer's side of invite redemption (protocol.md 7.2, design note
//! `relay-key-and-invites-design.md` B3, slice D3 B3).
//!
//! A relay delivers ADMIT_PENDING (a device's [`AdmitRequestBody`]) to the session that
//! registered with ADMIT_LISTEN. This module judges each request and says what to do: refuse it
//! with ADMIT_REFUSED, or admit the device. It holds no keys and no files: everything that
//! touches either (the invite book, the signing key, the saved documents, the network lock)
//! is behind [`AdmitIssuer`] and [`AdmitTxn`], which the command line implements.
//!
//! # The checks, first failure wins
//!
//! In [`process_batch`], for each request of one network:
//!
//! 1. the invite is signed by this device's key for the network ([`AdmitTxn::signed_here`]) and
//!    its `invite_id` is in the book: otherwise *silence* (another issuer's answer stands);
//! 2. the invite is not revoked, has no roles and `now < expires`: `bad_invite`;
//! 3. `BLAKE2s(secret) == secret_hash` (book integrity): `bad_invite`;
//! 4. the tag, in constant time ([`verify_admit_tag`]): `bad_tag`;
//! 5. the `node_cert` verifies against its own NodeId, is valid now and is valid for at most
//!    400 days: `bad_cert`;
//! 6. the node is not revoked in the held Roster: `revoked`;
//! 7. the name passes `check_name`, equals the invite's fixed name when it has one, and is not
//!    another member's, letter case aside: `name_taken` (the code for every name refusal);
//! 8. the counting rule below: `bad_invite` when the invite is used up.
//!
//! # The counting rule (idempotence per NodeId)
//!
//! `redeemed` lists the NodeIds an invite admitted; its length is the number of uses spent.
//! A NodeId already in it costs nothing again: if it is a member the request succeeds again (the
//! held Roster is sent to the relay once more), if it is not (a crash between the book write
//! and the save, or an owner fold that dropped it) it is admitted again without counting.
//! Otherwise `len(redeemed) < uses` is needed, the NodeId is appended and **the book is written
//! first, then the documents are issued and saved**, all under the network lock the
//! transaction holds: a crash after the book write loses nothing (the retry takes the first
//! rule), a failed book write admits nobody. Success needs no record: the relay answers the
//! device when it adopts the Roster that lists it.
//!
//! # Batching
//!
//! Requests that arrive within [`BATCH_WINDOW`] of the first are judged together and admitted in
//! one pair, so an invite with fifty uses costs the relay one Roster adoption, not fifty. A
//! NodeId that appears twice in a batch (the same request through two relays) is admitted once.
//! Refusals wait for the window like the rest.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use menzil_proto::{
    AdmitListenBody, AdmitRefusedBody, AdmitRequestBody, ErrorCode, Invite, InviteId, NetworkId,
    NodeCert, NodeId, Tai64N, check_name, hash_invite_secret, verify_admit_tag,
};
use tokio::sync::Notify;
use zeroize::Zeroizing;

/// How long after the first request the handler waits for others before it issues the pair.
pub const BATCH_WINDOW: Duration = Duration::from_secs(2);
/// How many times a batch that found its network busy is tried again.
pub const MAX_DEFERS: u8 = 3;
/// The most requests held for the next batch; the newest over it is dropped (the device's
/// relay retry brings it back).
pub const MAX_QUEUED: usize = 256;
/// The most answers held for the session loop.
const MAX_OUTBOX: usize = 1024;
/// A node certificate lasts at most 400 days (protocol.md 2.2).
const MAX_CERT_LIFETIME_SECS: u64 = 400 * 24 * 60 * 60;

/// What the book holds for one invite.
#[derive(Clone)]
pub struct InviteRecord {
    /// The signed invite as `invite create` made it.
    pub invite: Invite,
    /// The invite secret (never leaves this device but in the token).
    pub secret: Zeroizing<Vec<u8>>,
    /// Revoked with `menzil invite revoke`.
    pub revoked: bool,
    /// The NodeIds this invite admitted; its length is the uses spent.
    pub redeemed: Vec<NodeId>,
}

impl std::fmt::Debug for InviteRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteRecord")
            .field("revoked", &self.revoked)
            .field("redeemed", &self.redeemed.len())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// What the held Roster says of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Not listed.
    Absent,
    /// Listed and not revoked.
    Member,
    /// On the revoked list.
    Revoked,
}

/// A failure of a write the transaction does; the text is for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueFault(pub String);

impl std::fmt::Display for IssueFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why no transaction was opened: this device cannot issue for the network (no key, a steward
/// that lost its right: `retry` false) or the network is busy (`retry` true). The handler is
/// silent for the whole batch; a busy one is tried again, at most [`MAX_DEFERS`] times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotIssuer {
    /// For the log.
    pub why: String,
    /// Whether a later try may open the transaction.
    pub retry: bool,
}

/// One network's book and documents, held under the network lock from [`AdmitIssuer::begin`] to
/// the drop of the transaction.
pub trait AdmitTxn: Send {
    /// The book's record of `id`.
    fn invite(&self, id: &InviteId) -> Option<InviteRecord>;
    /// Whether `invite` is signed by this device's key for the network (the owner key, or the
    /// steward key it holds).
    fn signed_here(&self, invite: &Invite) -> bool;
    /// The held Roster's word on `node`.
    fn standing(&self, node: &NodeId) -> Standing;
    /// The members' names in the held Policy.
    fn names(&self) -> Vec<(NodeId, String)>;
    /// Writes the redeemed lists of the invites that changed (one atomic write of the book).
    fn record_redeemed(&mut self, changes: &[(InviteId, Vec<NodeId>)]) -> Result<(), IssueFault>;
    /// Issues one pair that admits `devices` (certificate and name each, no roles) and saves it.
    /// Called after [`Self::record_redeemed`].
    fn admit(&mut self, devices: &[(NodeCert, String)]) -> Result<(), IssueFault>;
}

/// What the command line gives the handler.
pub trait AdmitIssuer: Send + Sync + 'static {
    /// The ADMIT_LISTEN proof for `network` on this session, when this device holds an issuer
    /// key for it (the owner key, or a steward key the held documents list with `admit` and a
    /// `not_after` ahead); `None` otherwise. Blocking.
    fn listen_proof(
        &self,
        network: &NetworkId,
        relay: NodeId,
        session: NodeId,
        hello_timestamp: Tai64N,
        now: u64,
    ) -> Option<AdmitListenBody>;

    /// Opens a transaction on `network`: takes its lock, reads the book and the held documents.
    /// Blocking.
    fn begin(&self, network: &NetworkId, now: u64) -> Result<Box<dyn AdmitTxn>, NotIssuer>;
}

/// What a batch came to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BatchOutcome {
    /// The refusals to send to the relay.
    pub refused: Vec<AdmitRefusedBody>,
    /// How many devices were issued in the one pair.
    pub admitted: usize,
    /// Devices that were members already and asked again: the Roster goes to the relay again.
    pub resend: bool,
    /// The requests of a batch whose network was busy, to be tried again.
    pub deferred: Vec<AdmitRequestBody>,
}

fn refuse(
    refused: &mut Vec<AdmitRefusedBody>,
    invite_id: InviteId,
    node_id: NodeId,
    code: ErrorCode,
) {
    refused.push(AdmitRefusedBody {
        invite_id,
        node_id,
        code,
    });
}

/// Judges `requests` for `network` and issues one pair for the ones that pass (see the module
/// comment). `requests` whose invite names another network are dropped. Blocking: it takes the
/// network lock through [`AdmitIssuer::begin`].
pub fn process_batch(
    issuer: &dyn AdmitIssuer,
    network: &NetworkId,
    requests: Vec<AdmitRequestBody>,
    now: u64,
) -> BatchOutcome {
    let mut outcome = BatchOutcome::default();
    let mut txn = match issuer.begin(network, now) {
        Ok(txn) => txn,
        Err(NotIssuer { why, retry }) => {
            tracing::debug!(%network, why, retry, "no invite admission for this network on this device");
            if retry {
                outcome.deferred = requests;
            }
            return outcome;
        }
    };
    // Working copies of the redeemed lists, and what changed.
    let mut redeemed: HashMap<InviteId, Vec<NodeId>> = HashMap::new();
    let mut changed: Vec<InviteId> = Vec::new();
    let mut to_admit: Vec<(NodeCert, String)> = Vec::new();
    let mut batch_nodes: HashSet<NodeId> = HashSet::new();
    // The names taken so far, lowercase, with the node that holds each.
    let mut names: Vec<(NodeId, String)> = txn
        .names()
        .into_iter()
        .map(|(node, name)| (node, name.to_lowercase()))
        .collect();
    for request in requests {
        let Ok(invite) = request.invite.decode() else {
            continue;
        };
        if invite.network_id != *network {
            continue;
        }
        // 1. Ours and in the book, else silence.
        if !txn.signed_here(&request.invite) {
            continue;
        }
        let Some(record) = txn.invite(&invite.invite_id) else {
            continue;
        };
        let Ok(cert) = request.node_cert.decode() else {
            // Not a request from a device that could be named in a refusal.
            continue;
        };
        let (invite_id, node_id) = (invite.invite_id, cert.node_id);
        // 2. Live.
        if record.revoked || invite.check_roles_empty().is_err() || now >= invite.expires {
            refuse(
                &mut outcome.refused,
                invite_id,
                node_id,
                ErrorCode::BadInvite,
            );
            continue;
        }
        // 3. Book integrity.
        if hash_invite_secret(&record.secret) != invite.secret_hash {
            refuse(
                &mut outcome.refused,
                invite_id,
                node_id,
                ErrorCode::BadInvite,
            );
            continue;
        }
        // 4. The tag.
        if !verify_admit_tag(
            &record.secret,
            invite_id,
            &request.node_cert,
            &request.name,
            &request.tag,
        ) {
            refuse(&mut outcome.refused, invite_id, node_id, ErrorCode::BadTag);
            continue;
        }
        // 5. The certificate.
        let cert_ok = VerifyingKey::from_bytes(&<[u8; 32]>::from(cert.node_id))
            .is_ok_and(|key| request.node_cert.verify(&key).is_ok())
            && cert.is_valid_at(now)
            && cert.not_after.saturating_sub(cert.not_before) <= MAX_CERT_LIFETIME_SECS;
        if !cert_ok {
            refuse(&mut outcome.refused, invite_id, node_id, ErrorCode::BadCert);
            continue;
        }
        // 6. Not revoked.
        let standing = txn.standing(&node_id);
        if standing == Standing::Revoked {
            refuse(&mut outcome.refused, invite_id, node_id, ErrorCode::Revoked);
            continue;
        }
        // 7. The name.
        let lowered = request.name.to_lowercase();
        let name_ok = check_name(&request.name).is_ok()
            && invite.check_request_name(&request.name).is_ok()
            && !names
                .iter()
                .any(|(holder, taken)| *holder != node_id && *taken == lowered);
        if !name_ok {
            refuse(
                &mut outcome.refused,
                invite_id,
                node_id,
                ErrorCode::NameTaken,
            );
            continue;
        }
        // A device already in this batch (the same request through two relays, or with two
        // invites) is admitted once and counted once.
        if batch_nodes.contains(&node_id) {
            continue;
        }
        // 8. The counting rule.
        let list = redeemed
            .entry(invite_id)
            .or_insert_with(|| record.redeemed.clone());
        if list.contains(&node_id) {
            if standing == Standing::Member {
                outcome.resend = true;
            } else {
                batch_nodes.insert(node_id);
                names.push((node_id, lowered));
                to_admit.push((request.node_cert.clone(), request.name.clone()));
            }
            continue;
        }
        if list.len() < usize::from(invite.uses) {
            list.push(node_id);
            if !changed.contains(&invite_id) {
                changed.push(invite_id);
            }
            batch_nodes.insert(node_id);
            names.push((node_id, lowered));
            to_admit.push((request.node_cert.clone(), request.name.clone()));
        } else {
            refuse(
                &mut outcome.refused,
                invite_id,
                node_id,
                ErrorCode::BadInvite,
            );
        }
    }
    // The book first, then the documents.
    if !changed.is_empty() {
        let changes: Vec<(InviteId, Vec<NodeId>)> = changed
            .iter()
            .map(|id| (*id, redeemed[id].clone()))
            .collect();
        if let Err(fault) = txn.record_redeemed(&changes) {
            tracing::warn!(%network, %fault, "the invite book could not be written, nobody was admitted");
            return BatchOutcome {
                refused: outcome.refused,
                ..BatchOutcome::default()
            };
        }
    }
    if !to_admit.is_empty() {
        match txn.admit(&to_admit) {
            Ok(()) => outcome.admitted = to_admit.len(),
            Err(fault) => {
                // The uses are spent and written; the devices' retry admits them without
                // counting again.
                tracing::warn!(%network, %fault, "the admission could not be issued, the devices will retry");
            }
        }
    }
    outcome
}

/// What the handler asks the session loop to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitOut {
    /// Send ADMIT_REFUSED.
    Refused(AdmitRefusedBody),
    /// Send the held Roster of the network to the relay again.
    ResendRoster(NetworkId),
}

/// Receives ADMIT_PENDING requests from the session, judges them in batches on a blocking
/// thread and hands the answers back. One per node.
pub struct AdmitHandler {
    issuer: Arc<dyn AdmitIssuer>,
    queue: Mutex<Vec<(AdmitRequestBody, u8)>>,
    wake: Notify,
    outbox: Mutex<VecDeque<AdmitOut>>,
    out_wake: Notify,
    window: Duration,
}

impl std::fmt::Debug for AdmitHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmitHandler").finish_non_exhaustive()
    }
}

impl AdmitHandler {
    /// A handler with the batch window of [`BATCH_WINDOW`]. Spawns its worker; call inside a
    /// Tokio runtime. The worker ends when the last handle is dropped.
    pub fn spawn(issuer: Arc<dyn AdmitIssuer>) -> Arc<Self> {
        Self::spawn_with_window(issuer, BATCH_WINDOW)
    }

    /// [`Self::spawn`] with another batch window (tests).
    pub fn spawn_with_window(issuer: Arc<dyn AdmitIssuer>, window: Duration) -> Arc<Self> {
        let handler = Arc::new(Self {
            issuer,
            queue: Mutex::new(Vec::new()),
            wake: Notify::new(),
            outbox: Mutex::new(VecDeque::new()),
            out_wake: Notify::new(),
            window,
        });
        tokio::spawn(worker(Arc::downgrade(&handler)));
        handler
    }

    /// Hands one ADMIT_PENDING request to the next batch.
    pub fn submit(&self, request: AdmitRequestBody) {
        {
            let mut queue = self.queue.lock().unwrap();
            if queue.len() >= MAX_QUEUED {
                return;
            }
            queue.push((request, 0));
        }
        self.wake.notify_one();
    }

    /// The next thing to tell the relay; waits for one.
    pub async fn next_out(&self) -> AdmitOut {
        loop {
            if let Some(out) = self.outbox.lock().unwrap().pop_front() {
                return out;
            }
            self.out_wake.notified().await;
        }
    }

    fn push_out(&self, out: AdmitOut) {
        {
            let mut outbox = self.outbox.lock().unwrap();
            if outbox.len() >= MAX_OUTBOX {
                outbox.pop_front();
            }
            outbox.push_back(out);
        }
        self.out_wake.notify_one();
    }

    /// The ADMIT_LISTEN bodies for the networks of `networks` this device may issue for.
    pub async fn listen_bodies(
        &self,
        networks: Vec<NetworkId>,
        relay: NodeId,
        session: NodeId,
        hello_timestamp: Tai64N,
        now: u64,
    ) -> Vec<AdmitListenBody> {
        let issuer = Arc::clone(&self.issuer);
        tokio::task::spawn_blocking(move || {
            networks
                .iter()
                .filter_map(|network| {
                    issuer.listen_proof(network, relay, session, hello_timestamp, now)
                })
                .collect()
        })
        .await
        .unwrap_or_default()
    }

    fn take_queue(&self) -> Vec<(AdmitRequestBody, u8)> {
        std::mem::take(&mut *self.queue.lock().unwrap())
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn worker(handler: Weak<AdmitHandler>) {
    loop {
        let Some(this) = handler.upgrade() else {
            return;
        };
        let window = this.window;
        let wake = async {
            // Do not hold the handler across the wait: a dropped node must end the worker.
            this.wake.notified().await;
        };
        // Wake at most every second to notice that the handler is gone.
        if tokio::time::timeout(Duration::from_secs(1), wake)
            .await
            .is_err()
        {
            continue;
        }
        tokio::time::sleep(window).await;
        let requests = this.take_queue();
        if requests.is_empty() {
            continue;
        }
        let mut by_network: HashMap<NetworkId, Vec<(AdmitRequestBody, u8)>> = HashMap::new();
        for (request, tries) in requests {
            if let Ok(invite) = request.invite.decode() {
                by_network
                    .entry(invite.network_id)
                    .or_default()
                    .push((request, tries));
            }
        }
        for (network, requests) in by_network {
            let issuer = Arc::clone(&this.issuer);
            let tries: Vec<u8> = requests.iter().map(|(_, tries)| *tries).collect();
            let requests: Vec<AdmitRequestBody> =
                requests.into_iter().map(|(request, _)| request).collect();
            let done = tokio::task::spawn_blocking(move || {
                process_batch(&*issuer, &network, requests, unix_now())
            })
            .await;
            let Ok(outcome) = done else {
                tracing::warn!("an invite admission batch panicked");
                continue;
            };
            if !outcome.deferred.is_empty() {
                // Deferred requests keep their order, so the counts line up with `tries`.
                let mut queue = this.queue.lock().unwrap();
                for (request, tried) in outcome.deferred.into_iter().zip(tries) {
                    if tried + 1 < MAX_DEFERS && queue.len() < MAX_QUEUED {
                        queue.push((request, tried + 1));
                    }
                }
                drop(queue);
                this.wake.notify_one();
            }
            for refused in outcome.refused {
                this.push_out(AdmitOut::Refused(refused));
            }
            if outcome.resend {
                this.push_out(AdmitOut::ResendRoster(network));
            }
        }
    }
}

#[cfg(test)]
mod tests;
