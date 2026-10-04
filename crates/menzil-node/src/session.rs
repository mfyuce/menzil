//! The node-side L3 relay session (protocol.md 3, 4.1, 4.2; TODO.md
//! L3d): dial via `menzil-carrier`, run the Noise handshake via
//! `menzil-session`, verify the relay's identity, send ATTACH, and stay
//! attached.
//!
//! DOC(roster) propagation both directions (protocol.md 4.3; TODO.md
//! L3f) is handled transparently here too, the same way PING/REKEY/
//! GOAWAY already were: an inbound DOC is reassembled and, once complete,
//! verified and stored into this session's [`RosterStore`]
//! (`Engine::accept_doc`); right after ATTACH, [`Session::connect`] pushes
//! DOC(roster) for every network where this node's own store already
//! holds something newer than WELCOME's `rosters` reported (protocol.md
//! 4.3's literal node-to-relay rule, via `push_records_for_newer_rosters`).
//! `RosterStore` is owned by the caller and threaded through, not rebuilt
//! per reconnect, so a node does not forget what it holds just because
//! the link dropped.
//!
//! The node side of protocol.md 4.2's SEND/RECV/CREDIT data plane
//! (TODO.md L4b) lives here too, in [`run_session`]'s own attached loop:
//! before this, nothing let a caller send anything into a running L3
//! session at all, only receive (this module's own former doc comment
//! said as much). [`crate::outbound::OutboundQueue`] does the actual
//! per-peer credit and queueing logic, kept separate and I/O-free the
//! same way [`Engine`] is; `run_session` only drains it and feeds it
//! inbound CREDIT records.
//!
//! Protocol.md 5.1's path pinning (TODO.md L4h1) — an L4 session belongs
//! to exactly the L3 attachment it was opened under, never silently
//! surviving into whichever one attaches next — makes `run_session`
//! surface each attachment to its own epoch, via [`SessionEvent`]: every
//! [`Record`] delivery is now wrapped with the [`Epoch`] it arrived
//! under, framed by `Attached`/`Detached` around it, and an
//! [`OutboundSend`] carries the epoch it was produced for, refused with
//! [`EnqueueOutcome::WrongEpoch`] rather than silently sent once that
//! epoch is no longer current — closing the gap this module's own prior
//! doc comment did not yet have a name for ("a send queued during a
//! reconnect goes out on the next L3 session").
//!
//! Split in two: [`Engine`] is the pure protocol logic (decrypt, classify
//! a record, track the liveness/rekey clocks) with no `Carrier` and no
//! I/O, so it can be driven and tested with any source of ciphertext —
//! not just a real dial. [`Session`] is the thin async wrapper that
//! actually owns a [`Carrier`] and plumbs bytes through it. This split
//! exists because `menzil_carrier::Carrier::dial` hardcodes the platform
//! TLS verifier with no injection point for a test root of trust (see
//! `menzil-carrier/src/tls.rs`), the same way `menzil-relay`'s ACME
//! provisioning couldn't be exercised live either: a real end-to-end dial
//! through [`Session::connect`] is not something this crate's own test
//! suite can drive, so the logic worth automated coverage lives in
//! [`Engine`] instead, and [`Session`]'s I/O glue was read by hand
//! against protocol.md 4.1's exact message sequence rather than run.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;

use menzil_carrier::{Backoff, Carrier, ConnectionInfo, DialConfig};
use menzil_proto::{
    Capability, DocBody, DocReassembler, DocType, GoawayBody, HelloBody, Limits,
    MIN_SEND_CHARGE_BYTES, NetworkId, PROTOCOL_VERSION, Record, Roster, Tai64N, WelcomeBody,
    X25519PublicKey,
};
use menzil_session::{
    HandshakePattern, Liveness, NodeHandshake, RekeySchedule, Transport, prologue,
};

use crate::error::NodeError;
use crate::identity::LocalIdentity;
use crate::outbound::{EnqueueOutcome, Epoch, MAX_QUEUED_BYTES, OutboundQueue, OutboundSend};
use crate::roster_store::RosterStore;

/// Everything [`Session::connect`] needs beyond what
/// [`Carrier::dial`] itself takes.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// The relay to reach and how (protocol.md 3).
    pub dial: DialConfig,
    /// This node's own identity.
    pub identity: LocalIdentity,
    /// Networks this node claims membership in; empty to redeem an
    /// invite only (protocol.md 4.1).
    pub networks: Vec<NetworkId>,
    /// Capabilities this node offers (protocol.md 4.1).
    pub caps: Vec<Capability>,
    /// `e2e_proto` tags this node supports (protocol.md 4.2, 9).
    pub e2e_protos: Vec<u8>,
}

/// The pure L3 session logic, independent of how bytes travel: decrypts
/// inbound messages, classifies what to do with each record, and drives
/// the liveness/rekey clocks (`menzil_session`'s own primitives are
/// timer-free and expect "whoever owns the session" to drive them — this
/// is that caller).
struct Engine {
    transport: Transport,
    liveness: Liveness,
    rekey: RekeySchedule,
    roster_store: Arc<RosterStore>,
    doc_reassembler: DocReassembler,
    /// This node's own claimed networks (`SessionConfig::networks`),
    /// checked before an inbound DOC(roster) is stored — see
    /// `Engine::accept_doc` for why.
    claimed_networks: Vec<NetworkId>,
}

/// What [`Engine::on_message`] learned from one inbound ciphertext.
#[derive(Debug)]
enum EngineEvent {
    /// Handled internally (an incoming REKEY, a DOC chunk — whether it
    /// completed a transfer or not, see `Engine::accept_doc` — or a bare
    /// PONG; liveness activity is already recorded for every decrypted
    /// record, so a PONG needs nothing further); nothing to do.
    None,
    /// Send this record straight back (a PONG for a PING).
    Reply(Record),
    /// Not something `Engine` itself interprets (SEND/RECV/ADVERTISE*/
    /// PEER_STATE/CREDIT/ADMIT_*/ERROR — protocol.md 4.2, 4.4, 7.2).
    /// DOC never reaches here (protocol.md 4.3; TODO.md L3f) — see
    /// `Engine::accept_doc`. Everything else this variant carries is
    /// handed to [`run_session`]'s own caller as-is, except `Credit`:
    /// `run_session` intercepts that one itself (TODO.md L4b) to update
    /// its [`OutboundQueue`] rather than forwarding a raw CREDIT record
    /// onward, since by L4b the caller has no direct use for one.
    Deliver(Record),
    /// The relay ended the session (protocol.md 4.2).
    Goaway(GoawayBody),
}

/// What the liveness/rekey clocks want done, from [`Engine::on_tick`].
#[derive(Debug)]
enum TickEvent {
    /// Nothing due yet.
    None,
    /// No authenticated record has arrived for two ping intervals: the
    /// caller should give up on this connection (protocol.md 3.3).
    Dead,
    /// Send this record; no further action.
    Send(Record),
    /// Send this record (always [`Record::Rekey`]), then call
    /// [`Engine::rekey_outgoing`] once the send actually completes.
    /// Split in two because the REKEY record itself must still be
    /// encrypted under the *old* sending key (protocol.md 4.2: "the
    /// sender rekeys its sending state after this record").
    SendThenRekey(Record),
}

impl Engine {
    fn new(
        transport: Transport,
        now: Instant,
        roster_store: Arc<RosterStore>,
        claimed_networks: Vec<NetworkId>,
    ) -> Self {
        Self {
            transport,
            liveness: Liveness::new(now),
            rekey: RekeySchedule::new(now),
            roster_store,
            doc_reassembler: DocReassembler::new(),
            claimed_networks,
        }
    }

    /// Decrypts one inbound message and classifies it, recording
    /// liveness activity for any record that decrypts successfully
    /// (protocol.md 3.3: "no *authenticated* record", not "no PONG").
    fn on_message(&mut self, ciphertext: &[u8], now: Instant) -> Result<EngineEvent, NodeError> {
        let record = self.transport.decrypt_record(ciphertext)?;
        self.liveness.note_activity(now);
        Ok(match record {
            Record::Ping { nonce } => EngineEvent::Reply(Record::Pong { nonce }),
            Record::Pong { .. } => EngineEvent::None,
            Record::Rekey => {
                self.transport.rekey_incoming();
                EngineEvent::None
            }
            Record::Goaway(body) => EngineEvent::Goaway(body),
            Record::Doc(body) => {
                self.accept_doc(&body);
                EngineEvent::None
            }
            other => EngineEvent::Deliver(other),
        })
    }

    /// Feeds one DOC chunk (protocol.md 4.2, 4.3) into this session's
    /// reassembler; once a transfer completes, decodes and verifies it
    /// as a Roster for a network this node itself claims, and stores it
    /// via `roster_store`. Any other `doc_type` is logged and ignored
    /// without attempting to decode it as one (at L3, a relay only ever
    /// sends Roster; Policy is end to end only). A malformed chunk, or a
    /// reassembled payload that fails to decode or verify, is likewise
    /// logged and ignored rather than ending the session.
    ///
    /// The relay is already cryptographically authenticated by this
    /// point (WELCOME's `relay_cert` check, `verify_relay_identity`), but
    /// that only proves *which* relay this is, not that it will only ever
    /// send well-behaved DOC traffic — a relay this node dialed is still
    /// a much less trusted party than this node's own key material, and
    /// nothing about DOC's own framing bounds how many distinct networks
    /// a relay could claim to be pushing Rosters for. Restricting storage
    /// to `claimed_networks` (mirroring the equivalent restriction
    /// `crate::doc` enforces on the relay's own side, for the same
    /// reason) keeps a relay from growing this node's roster store
    /// without bound, and keeps `roster_store`'s content meaningful: it
    /// should only ever answer for networks this node actually claims.
    fn accept_doc(&mut self, body: &DocBody) {
        let (doc_type, bytes) = match self.doc_reassembler.accept(body) {
            Ok(Some(done)) => done,
            Ok(None) => return,
            Err(err) => {
                tracing::debug!(error = %err, "DOC chunk rejected");
                return;
            }
        };
        if doc_type != DocType::Roster {
            tracing::debug!(?doc_type, "ignoring a non-Roster DOC transfer at L3");
            return;
        }
        let roster = match Roster::decode_strict(&bytes) {
            Ok(roster) => roster,
            Err(err) => {
                tracing::warn!(error = %err, "reassembled DOC did not decode as a Roster");
                return;
            }
        };
        let decoded = match roster.decode() {
            Ok(decoded) => decoded,
            Err(err) => {
                tracing::warn!(error = %err, "reassembled DOC's Roster body did not decode");
                return;
            }
        };
        if !self.claimed_networks.contains(&decoded.network_id) {
            tracing::warn!(
                network_id = %decoded.network_id,
                "ignoring a DOC(roster) for a network this node does not claim"
            );
            return;
        }
        if let Err(err) = self.roster_store.set(&roster) {
            tracing::warn!(error = %err, "reassembled DOC did not verify as a Roster");
        }
    }

    /// Checks the liveness and rekey clocks against `now`; a dead link
    /// takes priority over trying to ping or rekey it.
    fn on_tick(&mut self, now: Instant) -> TickEvent {
        if self.liveness.is_dead(now) {
            return TickEvent::Dead;
        }
        if self.rekey.due(now) {
            self.rekey.note_rekeyed(now);
            return TickEvent::SendThenRekey(Record::Rekey);
        }
        if self.liveness.should_ping(now) {
            let mut nonce = [0u8; 8];
            fastrand::fill(&mut nonce);
            return TickEvent::Send(Record::Ping { nonce });
        }
        TickEvent::None
    }

    /// Completes a [`TickEvent::SendThenRekey`] once its REKEY record has
    /// actually been sent.
    fn rekey_outgoing(&mut self) {
        self.transport.rekey_outgoing();
    }

    fn encrypt(&mut self, record: &Record) -> Result<Vec<u8>, NodeError> {
        Ok(self.transport.encrypt_record(record)?)
    }
}

/// How often [`Session::recv`] checks the liveness/rekey clocks when
/// nothing has arrived. Both clocks operate on scales of seconds to an
/// hour (protocol.md 3.3, 4.1), so this granularity costs nothing
/// observable; a fixed schedule (`tokio::time::Interval`, not a plain
/// `sleep` re-armed each loop pass) matters here so sustained sub-second
/// inbound traffic can never keep resetting the check away indefinitely,
/// which would otherwise starve the hourly REKEY.
const TICK: Duration = Duration::from_secs(1);

/// How long [`run_session`]'s drain loop waits for one queued outbound
/// send to actually complete before giving up on this attachment and
/// reconnecting (TODO.md L4b's own review, finding 7, live-reproduced
/// against a real relay under two-way saturated traffic with a slow
/// reader): the drain loop does not read the carrier at all while it is
/// draining, so a write that blocks because the *relay* has stopped
/// reading from this node — itself possible if the relay is meanwhile
/// stuck writing to this same node, `menzil-relay`'s own pre-existing,
/// documented no-write-timeout gap — would otherwise hang forever with
/// nothing left to interrupt it: this loop runs outside [`Session::recv`],
/// so the liveness clock that would normally notice a dead link never
/// gets to run either. Ending the attachment on a stall, rather than
/// waiting indefinitely, is a partial mitigation, not the complete fix
/// (a true fix needs the relay side timed out too, and ideally a
/// priority split between control and data sends on both ends — a
/// bigger change than this item's scope, mirroring
/// `menzil-relay::forward`'s own module doc comment's identical
/// judgment call about its matching gap). No protocol.md default exists
/// for this; chosen well under the 60s idle-session default (protocol.md
/// 10) so a genuine stall is noticed and reconnected well before the
/// liveness mechanism would otherwise have had a chance to.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

/// One attached L3 relay session: dial, handshake, verify, ATTACH
/// (protocol.md 3, 4.1, 4.2). Owns the live [`Carrier`] plus the pure
/// [`Engine`] logic that runs on top of it.
pub struct Session {
    carrier: Carrier,
    engine: Engine,
    welcome: WelcomeBody,
    tick: tokio::time::Interval,
}

impl Session {
    /// One connection attempt: dial via `menzil-carrier`, run the L3
    /// handshake via `menzil-session`, verify the relay's identity
    /// (protocol.md 4.1), send ATTACH ("the new session is not
    /// routable... until the node's first transport record, ATTACH, is
    /// decrypted"), then push DOC(roster) for any network where
    /// `roster_store` already holds something newer than WELCOME
    /// reported (protocol.md 4.3). Does not retry; see [`run_session`]
    /// for the reconnect loop.
    pub async fn connect(
        config: &SessionConfig,
        env: &HashMap<String, String>,
        roster_store: Arc<RosterStore>,
    ) -> Result<Self, NodeError> {
        let mut carrier = Carrier::dial(&config.dial, env).await?;
        let (transport, welcome) = run_handshake(&mut carrier, config, &roster_store).await?;
        let mut session = Self {
            carrier,
            engine: Engine::new(
                transport,
                Instant::now(),
                Arc::clone(&roster_store),
                config.networks.clone(),
            ),
            welcome,
            tick: tokio::time::interval(TICK),
        };
        session.send(Record::Attach).await?;
        let catch_up = push_records_for_newer_rosters(
            &config.networks,
            &roster_store,
            &session.welcome.rosters,
        );
        for record in catch_up {
            session.send(record).await?;
        }
        Ok(session)
    }

    /// WELCOME as the relay sent it: session id, limits, and each claimed
    /// network's current Roster `seq`.
    pub fn welcome(&self) -> &WelcomeBody {
        &self.welcome
    }

    /// Encrypts and sends one L3 record.
    pub async fn send(&mut self, record: Record) -> Result<(), NodeError> {
        let bytes = self.engine.encrypt(&record)?;
        self.carrier.send(bytes).await?;
        Ok(())
    }

    /// Encrypts and sends `record` (always [`Record::Rekey`]), then
    /// rekeys this session's own sending state — but, unlike
    /// [`Self::send`] followed by a separate [`Engine::rekey_outgoing`]
    /// call, with *no `.await` between encrypting and rekeying*.
    ///
    /// TODO.md L4b's own review (finding 6, live-reproduced against a
    /// real relay): once [`Self::recv`] is driven from inside an outer
    /// `tokio::select!` that can also complete a *different* branch
    /// (`run_session`'s own `outbound` channel), any `.await` inside
    /// `recv` becomes a point where the whole call can be cancelled —
    /// dropped mid-future, never resumed. The record's ciphertext is
    /// still delivered regardless (`tokio-tungstenite` commits it to its
    /// own write buffer at the very first poll of the send), but a
    /// cancellation *between* that send completing and a separate
    /// `rekey_outgoing()` call afterward would leave this session still
    /// encrypting with the *old* key for whatever it sends next, while
    /// the relay — which rekeys its receiving side the instant it reads
    /// this REKEY record — expects the new one; every following record
    /// then fails to decrypt on the relay's side, and this session's own
    /// connection is dropped and has to reconnect from a genuine
    /// protocol desync, not merely a lost race. Rust's async model can
    /// only ever suspend (and so only ever let a caller cancel) at an
    /// actual `.await` point: putting the rekey *before* the one
    /// `.await` this method has, immediately after the synchronous
    /// encrypt, makes it unconditionally happen before the record can
    /// ever be observed as sent, no matter what cancels the send itself.
    async fn send_rekey(&mut self, record: Record) -> Result<(), NodeError> {
        let bytes = self.engine.encrypt(&record)?;
        self.engine.rekey_outgoing();
        self.carrier.send(bytes).await?;
        Ok(())
    }

    /// Waits for the next record meant for the caller, transparently
    /// answering PING with PONG, applying an incoming REKEY, ingesting an
    /// incoming DOC (protocol.md 4.3), and sending this side's own PING
    /// or REKEY as their clocks come due. Returns an error — ending this
    /// connection — on GOAWAY, a dead link, or a carrier failure;
    /// [`run_session`] is what turns that into a reconnect.
    pub async fn recv(&mut self) -> Result<Record, NodeError> {
        loop {
            tokio::select! {
                incoming = self.carrier.recv() => {
                    let bytes = incoming?;
                    match self.engine.on_message(&bytes, Instant::now())? {
                        EngineEvent::None => {}
                        EngineEvent::Reply(record) => self.send(record).await?,
                        EngineEvent::Deliver(record) => return Ok(record),
                        EngineEvent::Goaway(body) => {
                            return Err(NodeError::Goaway {
                                reason: body.reason,
                                retry_after_ms: body.retry_after_ms,
                            });
                        }
                    }
                }

                _ = self.tick.tick() => {
                    match self.engine.on_tick(Instant::now()) {
                        TickEvent::None => {}
                        TickEvent::Dead => return Err(NodeError::LinkDead),
                        TickEvent::Send(record) => self.send(record).await?,
                        TickEvent::SendThenRekey(record) => self.send_rekey(record).await?,
                    }
                }
            }
        }
    }
}

/// DOC(roster) chunk records to send for every network in `networks`
/// where `roster_store` holds something newer than `welcome_rosters`
/// reports the relay already has (protocol.md 4.3: "A node sends
/// DOC(roster) to a relay when it holds a newer Roster than the relay's
/// WELCOME `rosters` shows"). A network this node claims but holds no
/// Roster for at all (nothing to push yet — e.g. before ever being
/// admitted) is silently skipped, not an error.
///
/// Compares `welcome_rosters`'s entry as an `Option`, not
/// `seq > welcome_rosters.get(..).unwrap_or(0)`: a legitimate Roster can
/// have `seq: 0` (protocol.md never forbids it), and folding "the relay
/// has nothing at all for this network" into the same value as "the relay
/// explicitly holds seq 0" would silently swallow exactly that push.
fn push_records_for_newer_rosters(
    networks: &[NetworkId],
    roster_store: &RosterStore,
    welcome_rosters: &HashMap<NetworkId, u64>,
) -> Vec<Record> {
    let mut records = Vec::new();
    for network_id in networks {
        let Some(seq) = roster_store.seq(network_id) else {
            continue;
        };
        let relay_is_current = welcome_rosters
            .get(network_id)
            .is_some_and(|&relay_seq| relay_seq >= seq);
        if relay_is_current {
            continue;
        }
        // `seq` and `get` are independent reads of `roster_store`; a
        // concurrent update between them could in principle make this
        // `None` even though `seq` just succeeded. Skipping it here (not
        // panicking) is correct either way: the update that raced this
        // one is itself newer still, and gets its own chance to be
        // noticed and pushed the next time this runs.
        let Some(roster) = roster_store.get(network_id) else {
            continue;
        };
        records.extend(menzil_proto::split_into_doc_records(
            DocType::Roster,
            &roster.encode(),
        ));
    }
    records
}

/// Runs [`NodeHandshake`] to completion over `carrier` and verifies the
/// result (protocol.md 4.1).
async fn run_handshake(
    carrier: &mut Carrier,
    config: &SessionConfig,
    roster_store: &RosterStore,
) -> Result<(Transport, WelcomeBody), NodeError> {
    let info = &config.dial.connection_info;
    // "`key` is a cache that enables the one round trip IK handshake;
    // when it is absent or stale the node uses XX" (protocol.md 3.2).
    // Detecting staleness (as opposed to absence) would need a record of
    // past failed attempts that no store exists yet to hold; see this
    // module's doc comment.
    let pattern = if info.relay_x25519.is_some() {
        HandshakePattern::Ik
    } else {
        HandshakePattern::Xx
    };

    let selected =
        carrier
            .selected_subprotocol
            .clone()
            .ok_or_else(|| NodeError::SubprotocolNotSelected {
                subprotocol: carrier.offered_subprotocol.clone(),
            })?;
    let prologue_bytes = prologue(&carrier.offered_subprotocol, &selected, pattern);

    let roster_seq = config
        .networks
        .iter()
        .filter_map(|network_id| roster_store.seq(network_id).map(|seq| (*network_id, seq)))
        .collect();
    let hello = HelloBody {
        v: PROTOCOL_VERSION,
        node_cert: config.identity.node_cert.clone(),
        networks: config.networks.clone(),
        timestamp: tai64n_now(),
        roster_seq,
        caps: config.caps.clone(),
        e2e_protos: config.e2e_protos.clone(),
    };

    let (node_handshake, message1) = NodeHandshake::start(
        pattern,
        &config.identity.x25519_private,
        info.relay_x25519.as_ref(),
        &prologue_bytes,
        &hello,
    )?;
    carrier.send(message1).await?;
    let message2 = carrier.recv().await?;
    let (transport, welcome, relay_static, message3) = node_handshake.finish(&message2)?;
    if let Some(message3) = message3 {
        carrier.send(message3).await?;
    }

    verify_relay_identity(info, &welcome, &relay_static)?;
    Ok((transport, welcome))
}

/// protocol.md 4.1: "the node verifies `relay_cert.node_id` equals the
/// `id` of its connection information and `relay_cert.x25519_pub` equals
/// the relay static key of the handshake". `menzil_session` surfaces both
/// sides of this comparison without performing it; this is where it
/// actually happens.
///
/// Not done here: "remembers the highest relay serial" (protocol.md
/// 4.1) needs state kept across reconnects, which needs a persistent
/// identity/state store that does not exist yet (the same gap
/// `tai64n_now`'s docs flag for HELLO's timestamp).
fn verify_relay_identity(
    info: &ConnectionInfo,
    welcome: &WelcomeBody,
    relay_static: &X25519PublicKey,
) -> Result<(), NodeError> {
    let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(info.relay_node_id))?;
    welcome.relay_cert.verify(&verifying_key)?;
    let cert_body = welcome.relay_cert.decode()?;
    if cert_body.node_id != info.relay_node_id {
        return Err(NodeError::RelayIdentityMismatch(
            "relay_cert.node_id does not match the dialed connection information's id",
        ));
    }
    if cert_body.x25519_pub != *relay_static {
        return Err(NodeError::RelayIdentityMismatch(
            "relay_cert.x25519_pub does not match the relay's negotiated Noise static key",
        ));
    }
    Ok(())
}

/// The TAI64 label offset (2^62), added to a Unix-epoch second count to
/// form the label half of TAI64N.
const TAI64_UNIX_EPOCH_OFFSET: u64 = 0x4000000000000000;

/// Approximates TAI64N (HELLO's `timestamp`, protocol.md 4.1) from the
/// system's UTC clock rather than true TAI, which would need a
/// leap-second table this crate does not have. protocol.md 4.1 only
/// relies on this value being strictly greater than the last one a relay
/// accepted for this node id, never on exact TAI accuracy (see
/// [`Tai64N`]'s own docs), so the UTC approximation does not by itself
/// break correctness.
///
/// What is not handled: this does not persist the last timestamp it
/// produced across a process restart, and does not guard against a
/// system clock that jumps backward. Either could make a relay reject
/// the next HELLO with `stale_timestamp`; both need a persistent
/// identity/state store that does not exist yet.
fn tai64n_now() -> Tai64N {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let label = TAI64_UNIX_EPOCH_OFFSET.wrapping_add(since_epoch.as_secs());
    let mut bytes = [0u8; 12];
    bytes[0..8].copy_from_slice(&label.to_be_bytes());
    bytes[8..12].copy_from_slice(&since_epoch.subsec_nanos().to_be_bytes());
    Tai64N::from(bytes)
}

/// One event [`run_session`] delivers through `events`, in order:
/// records interleaved with this L3 session's own attachment lifecycle
/// (protocol.md 5.1's path pinning, TODO.md L4h1) — an L4 layer built on
/// top needs this to know which attachment a given record arrived under,
/// and when one it holds open has ended.
#[derive(Debug)]
pub enum SessionEvent {
    /// This attachment's L3 handshake and ATTACH completed; always the
    /// first event of `epoch`. `limits` is WELCOME's own (protocol.md
    /// 4.1) — `limits.max_record` is what an `E2eTransport` or
    /// `menzil_stream::new` built for this epoch must be sized with.
    /// Every [`Record`] delivered until the matching `Detached` belongs
    /// to this same epoch. Not a routability guarantee: the relay sends
    /// WELCOME unconditionally, before HELLO is even checked, so a HELLO
    /// this relay goes on to reject (an unknown network, a revoked or
    /// stale-serial NodeCert) still produces `Attached`, immediately
    /// followed by a `Record` carrying that rejection as an ERROR, then
    /// `Detached` — a real but short-lived "phantom" epoch, not a bug in
    /// this type.
    Attached {
        /// This attachment's epoch.
        epoch: Epoch,
        /// WELCOME's own limits (protocol.md 4.1).
        limits: Limits,
    },
    /// This attachment ended; always the last event of `epoch`. Any
    /// [`OutboundSend`] still tagged with it is now refused with
    /// [`EnqueueOutcome::WrongEpoch`], never sent under whatever
    /// attachment comes next — but a send already resolved
    /// [`EnqueueOutcome::Accepted`] and still sitting in this epoch's own
    /// `OutboundQueue`, never yet handed to the wire, is simply discarded
    /// with it, the same already-accepted scope of loss
    /// `OutboundQueue::next_ready_to_send`'s own doc comment describes
    /// for a connection that just ends: `Accepted` means "admitted to
    /// the local send queue," never "reached the wire or the peer."
    Detached {
        /// The attachment that just ended.
        epoch: Epoch,
    },
    /// One L3 record delivered while `epoch` was attached. Boxed: a bare
    /// `Record` makes this the largest variant by far (clippy's
    /// `large_enum_variant`, the same lint `menzil-relay::forward`'s own
    /// `ForwardItem::Recv` already hit and fixed the identical way).
    Record {
        /// Which attachment this arrived under.
        epoch: Epoch,
        /// The record itself.
        record: Box<Record>,
    },
}

/// Logs and resolves `req`'s `outcome` to [`EnqueueOutcome::WrongEpoch`]
/// unconditionally — for a caller that already knows, by construction,
/// that no epoch `req` could legitimately be tagged with is current
/// right now (the detach-to-reconnect gap below, once the new epoch has
/// already been decided but before any caller could possibly have been
/// told it, since `Attached` for it has not been delivered yet).
fn refuse_stale(req: OutboundSend) {
    tracing::warn!(dst = %req.dst, "outbound send tagged for a past epoch, refused");
    let _ = req.outcome.send(EnqueueOutcome::WrongEpoch);
}

/// Like [`refuse_stale`], but for the bootstrap window before this
/// node's *own* next attachment: a send tagged with the epoch about to
/// attach (`epoch`, not yet current) — most commonly [`Epoch::first`],
/// queued before this node's very first attachment, exactly the pattern
/// several live tests rely on — is held in `waiting` rather than refused,
/// to be admitted once that attachment actually completes; anything else
/// is refused immediately rather than left to wait out the rest of the
/// outage unanswered (TODO.md L4h1's own review, finding 2). `waiting`
/// has no `OutboundQueue` of its own yet to bound it, so `waiting_bytes`
/// is charged and checked against the same [`MAX_QUEUED_BYTES`] total
/// `OutboundQueue` itself enforces once one exists — a dial or
/// handshake that never completes (nothing here has a timeout; a
/// pre-existing, separate gap) must not let `waiting` grow without
/// bound in the meantime (found red-teaming this item's own round-one
/// fix, round two).
fn hold_or_refuse(
    req: OutboundSend,
    epoch: Epoch,
    waiting: &mut Vec<OutboundSend>,
    waiting_bytes: &mut usize,
) {
    if req.epoch != epoch {
        refuse_stale(req);
        return;
    }
    let charge = req.payload.len().max(MIN_SEND_CHARGE_BYTES as usize);
    if *waiting_bytes + charge > MAX_QUEUED_BYTES {
        tracing::warn!(dst = %req.dst, "outbound queue full while dialing, reliable send refused");
        let _ = req.outcome.send(EnqueueOutcome::QueueFull);
        return;
    }
    *waiting_bytes += charge;
    waiting.push(req);
}

/// Admits `req` into `outbound_queue` and resolves its `outcome`
/// — the one place this happens, shared by the attached loop's own
/// drain and by replaying whatever [`hold_or_refuse`] held in `waiting`
/// once a fresh `outbound_queue` exists for it to be admitted into.
fn admit(req: OutboundSend, epoch: Epoch, outbound_queue: &mut OutboundQueue) {
    if req.epoch != epoch {
        refuse_stale(req);
        return;
    }
    let dst = req.dst;
    let payload_len = req.payload.len();
    let outcome = outbound_queue.enqueue(req.dst, req.e2e_proto, req.flags, req.payload);
    match outcome {
        EnqueueOutcome::QueueFull => {
            tracing::warn!(dst = %dst, "node outbound queue full, reliable send refused");
        }
        EnqueueOutcome::TooLarge => {
            tracing::warn!(
                dst = %dst,
                payload_len,
                "outbound send exceeds the max L3 SEND payload, refused"
            );
        }
        EnqueueOutcome::Accepted | EnqueueOutcome::Dropped => {}
        EnqueueOutcome::WrongEpoch => {
            unreachable!("OutboundQueue::enqueue never produces WrongEpoch; checked above")
        }
    }
    let _ = req.outcome.send(outcome);
}

/// Dials with [`Backoff`] retry, servicing `outbound` throughout —
/// TODO.md L4h1's own review, finding 2: a send is tagged with an epoch
/// the instant it is produced, so one tagged for the epoch *about to*
/// attach must not sit unanswered for the entire outage (`Session::connect`
/// plus however many failed-attempt backoff sleeps) only to finally be
/// resolved, however it resolves, once this finally returns; one tagged
/// for any other, already-stale epoch must not either, even though the
/// answer for that case is always the same `WrongEpoch` refusal.
/// `connect`'s own future, and each backoff sleep's, is polled in place
/// (pinned, not reconstructed) across however many times the other
/// `select!` branch fires first — reconstructing either on every such
/// poll would silently restart it from zero every time, the same bug
/// class L3d's own liveness/rekey ticker already hit once. Returns
/// `None` once `events`'s receiver is dropped, the same signal
/// `run_session` already ends on once attached — without this, nothing
/// here would ever notice a vanished caller and this would retry
/// forever against a relay nobody is listening for the result of
/// (found red-teaming this item's own round-one fix, round two).
async fn connect_with_retry(
    config: &SessionConfig,
    env: &HashMap<String, String>,
    roster_store: Arc<RosterStore>,
    outbound: &mut mpsc::Receiver<OutboundSend>,
    events: &mpsc::Sender<SessionEvent>,
    backoff: &mut Backoff,
    epoch: Epoch,
) -> Option<(Session, Vec<OutboundSend>)> {
    let mut waiting: Vec<OutboundSend> = Vec::new();
    let mut waiting_bytes: usize = 0;
    loop {
        let dial = Session::connect(config, env, Arc::clone(&roster_store));
        tokio::pin!(dial);
        let result = loop {
            tokio::select! {
                result = &mut dial => break result,
                Some(req) = outbound.recv() => hold_or_refuse(req, epoch, &mut waiting, &mut waiting_bytes),
                () = events.closed() => return None,
            }
        };
        match result {
            Ok(session) => return Some((session, waiting)),
            Err(err) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %err, delay_ms = delay.as_millis(), ?epoch, "node session connect failed, retrying");
                let sleep = tokio::time::sleep(delay);
                tokio::pin!(sleep);
                loop {
                    tokio::select! {
                        _ = &mut sleep => break,
                        Some(req) = outbound.recv() => hold_or_refuse(req, epoch, &mut waiting, &mut waiting_bytes),
                        () = events.closed() => return None,
                    }
                }
            }
        }
    }
}

/// Dials, attaches, and stays attached indefinitely: reconnects through
/// [`connect_with_retry`] on any error, honoring GOAWAY's
/// `retry_after_ms` hint when that was the reason (protocol.md 3.3,
/// 4.1). `roster_store` is shared across every reconnect attempt
/// (protocol.md 4.3; TODO.md L3f), not rebuilt per attempt; a fresh
/// [`OutboundQueue`] is *not* shared the same way — it is rebuilt on
/// every attach, deliberately, mirroring
/// `menzil-relay::forward::ForwardTable::clear_for`'s own per-attach
/// reset (L3h's finding H2: stale credit must not silently outlive a
/// reconnect). Inbound records this crate does not interpret itself
/// (everything but ATTACH/PING/PONG/REKEY/GOAWAY/DOC/CREDIT) are sent to
/// `events` as [`SessionEvent::Record`]; CREDIT is intercepted here
/// instead, to update the `OutboundQueue` (TODO.md L4b). Outbound SEND
/// requests arrive through `outbound`; once its sender end is dropped,
/// that side simply goes quiet (no more sends can be queued) without
/// ending the function — only `events`'s receiver being dropped does
/// that, unchanged from before L4b. Returns once `events`'s receiver is
/// dropped; any `OutboundSend` still sitting in `outbound`'s buffer at
/// that point is simply dropped along with it, which a caller watching
/// its own `outcome` oneshot observes as a disconnect, not a hang.
///
/// Each attachment gets the next [`Epoch`] (TODO.md L4h1; protocol.md
/// 5.1's path pinning), starting at [`Epoch::first`]: `Attached` is
/// pushed the moment [`connect_with_retry`] returns, before
/// `session.recv()` is polled even once, so a caller can never see a
/// record from an epoch before its own `Attached`; `Detached` is pushed
/// the moment the attached loop below ends, for any reason, and `epoch`
/// is advanced immediately after, before the reconnect gap even starts
/// — not after it, so that gap's own `outbound` servicing (below, and
/// inside `connect_with_retry`) already refuses against the *next*
/// epoch, not the one that just ended. An [`OutboundSend`] drained from
/// `outbound` whose own `epoch` no longer matches the current one is
/// refused with [`EnqueueOutcome::WrongEpoch`] — resolved on its
/// `outcome` oneshot like any other admission outcome — rather than
/// silently enqueued to go out, as it used to, whenever this node next
/// happens to attach.
///
/// At most one delivered event is ever held outstanding at a time, in
/// `pending`, waiting for room in `events` via [`mpsc::Sender::reserve`]
/// rather than `events.send(...).await` directly inside the same
/// `tokio::select!` that also has to keep servicing `outbound` (TODO.md
/// L4b's own review, finding 5, live-reproduced against a real relay: a
/// caller that both reads `events` and writes `outbound` from the same
/// task — the natural shape for something that replies to what it
/// receives — can leave `events.send(...).await` permanently blocked on
/// a full channel while that same caller is itself blocked trying to
/// write a now-full `outbound`, with nothing left to break the cycle;
/// `reserve` lets this loop keep draining `outbound` and running the
/// send loop below while a delivery is stalled, instead of stopping
/// dead). While a delivery is pending, `session.recv()` is not polled
/// again either — new inbound records simply wait in the carrier's own
/// buffer, ordinary TCP-level backpressure, not a loss — which also
/// means the liveness/rekey clocks `session.recv()` drives internally
/// pause for that same stretch; sustained backpressure long enough to
/// blow past the liveness window once resumed reconnects this
/// attachment, a real but accepted trade far short of finding 5's
/// original permanent hang. `pending` can hold a second event only in
/// the narrow case the attached loop ends while a `Record` is still
/// waiting in it: `Detached` is pushed behind it, not instead of it,
/// which also closes a smaller pre-existing gap (found while
/// implementing TODO.md L4h1, not itself L4h1's own concern) where that
/// still-pending record would otherwise simply be dropped, along with
/// `pending_deliver` itself, the instant the attached loop ended. That
/// drain, below, keeps servicing `outbound` throughout (refusing
/// everything, unconditionally — nothing could legitimately be tagged
/// for the new epoch yet, since its own `Attached` has not reached the
/// caller) rather than running outside any `select!` at all, the same
/// finding-5 deadlock this function already avoids elsewhere: an
/// `events` of capacity 1 with one record already waiting in it, and a
/// caller blocked writing a full `outbound` before it ever reads that
/// record, reproduces the identical cycle here too if nothing drains
/// `outbound` concurrently (found red-teaming this item, not merely
/// theorized — live-reproduced as a genuine, permanent hang before this
/// fix).
pub async fn run_session(
    config: SessionConfig,
    env: HashMap<String, String>,
    events: mpsc::Sender<SessionEvent>,
    mut outbound: mpsc::Receiver<OutboundSend>,
    roster_store: Arc<RosterStore>,
) {
    let mut backoff = Backoff::new();
    let mut epoch = Epoch::first();
    loop {
        let Some((mut session, waiting)) = connect_with_retry(
            &config,
            &env,
            Arc::clone(&roster_store),
            &mut outbound,
            &events,
            &mut backoff,
            epoch,
        )
        .await
        else {
            return;
        };
        tracing::info!(?epoch, "node session attached");
        let attached_at = Instant::now();
        let limits = session.welcome().limits;
        let mut outbound_queue = OutboundQueue::new(limits.credit, limits.max_record);
        for req in waiting {
            admit(req, epoch, &mut outbound_queue);
        }
        let mut pending: VecDeque<SessionEvent> = VecDeque::new();
        pending.push_back(SessionEvent::Attached { epoch, limits });

        // `retry_after_ms`: `Some(hint)` only for a GOAWAY-caused break,
        // matching the two different backoff calls the loop used to make
        // inline before L4b added a second way to leave it (a send
        // failure, or a send timeout, while draining `outbound_queue`).
        let retry_after_ms = 'attached: loop {
            tokio::select! {
                recv_result = session.recv(), if pending.is_empty() => {
                    match recv_result {
                        Ok(Record::Credit(body)) => {
                            outbound_queue.note_credit(body.peer, body.bytes);
                        }
                        Ok(record) => {
                            pending.push_back(SessionEvent::Record {
                                epoch,
                                record: Box::new(record),
                            });
                        }
                        Err(NodeError::Goaway { reason, retry_after_ms }) => {
                            tracing::info!(reason, retry_after_ms, "relay sent GOAWAY, reconnecting");
                            break 'attached Some(retry_after_ms);
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "node session ended, reconnecting");
                            break 'attached None;
                        }
                    }
                }
                permit = events.reserve(), if !pending.is_empty() => {
                    match permit {
                        Ok(permit) => {
                            let event = pending.pop_front().expect(
                                "this branch only runs while pending is non-empty",
                            );
                            permit.send(event);
                        }
                        Err(_) => return,
                    }
                }
                Some(req) = outbound.recv() => {
                    admit(req, epoch, &mut outbound_queue);
                }
            }

            while let Some(record) = outbound_queue.next_ready_to_send() {
                match tokio::time::timeout(SEND_TIMEOUT, session.send(record)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        tracing::warn!(error = %err, "node session ended while draining outbound sends, reconnecting");
                        break 'attached None;
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            "node session outbound send stalled past the write timeout, reconnecting"
                        );
                        break 'attached None;
                    }
                }
            }
        };
        // Captured here, not after the drain below: that drain's own
        // duration depends on how fast the caller reads `events`, which
        // has nothing to do with how long this attachment actually
        // lasted — using `attached_at.elapsed()` after it would let a
        // slow reader inflate a short-lived connection's own uptime and
        // wrongly reset `backoff` (found red-teaming this item's own
        // round-one fix, round two).
        let uptime = attached_at.elapsed();

        pending.push_back(SessionEvent::Detached { epoch });
        drop(outbound_queue);
        drop(session);
        epoch = epoch.next();
        while !pending.is_empty() {
            tokio::select! {
                permit = events.reserve() => {
                    match permit {
                        Ok(permit) => {
                            let event = pending.pop_front().expect(
                                "loop guarded by !pending.is_empty()",
                            );
                            permit.send(event);
                        }
                        Err(_) => return,
                    }
                }
                Some(req) = outbound.recv() => refuse_stale(req),
            }
        }

        backoff.note_connection_uptime(uptime);
        let delay = match retry_after_ms {
            Some(hint) => backoff.next_delay_with_hint(hint),
            None => backoff.next_delay(),
        };
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => break,
                Some(req) = outbound.recv() => refuse_stale(req),
                () = events.closed() => return,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{Limits, NodeCert, NodeCertBody, NodeId, RosterBody, RosterMember};

    fn node_cert(seed: u8) -> NodeCert {
        let key = SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: NodeId::from([seed; 32]),
            x25519_pub: X25519PublicKey::from([seed; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }

    fn test_roster_store() -> Arc<RosterStore> {
        Arc::new(RosterStore::new())
    }

    fn signed_roster(owner: &SigningKey, network_id: NetworkId, seq: u64) -> Roster {
        let body = RosterBody {
            v: PROTOCOL_VERSION,
            network_id,
            seq,
            issued: 0,
            expires: 1_000_000_000,
            members: vec![RosterMember {
                node_id: NodeId::from([1u8; 32]),
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    /// A real, live `Ik` handshake producing two interoperable
    /// [`Transport`]s, purely to exercise [`Engine`] against genuine
    /// ciphertext. This is not a re-test of the handshake itself
    /// (`menzil-session` already covers that thoroughly) — just a way to
    /// get two transports that can talk to each other without a network.
    fn ik_params() -> snow::params::NoiseParams {
        "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
    }

    fn two_live_transports() -> (Transport, Transport) {
        use menzil_session::{RelayHandshake, RelayHandshakeStep};

        let pattern = HandshakePattern::Ik;
        let node_kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        let relay_kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        let node_priv = <[u8; 32]>::try_from(node_kp.private).unwrap();
        // Move `.public` out before `.private`: both are partial moves of
        // distinct fields of the same local, so order doesn't matter, but
        // this keeps the borrow shape obviously simple either way.
        let relay_pub = X25519PublicKey::from(<[u8; 32]>::try_from(relay_kp.public).unwrap());
        let relay_priv = <[u8; 32]>::try_from(relay_kp.private).unwrap();

        let prologue_bytes = prologue("menzil.v1", "menzil.v1", pattern);
        let hello = HelloBody {
            v: PROTOCOL_VERSION,
            node_cert: node_cert(1),
            networks: vec![],
            timestamp: Tai64N::from([0u8; 12]),
            roster_seq: HashMap::new(),
            caps: vec![],
            e2e_protos: vec![0x01],
        };
        let welcome = sample_welcome(node_cert(2));

        let (node_handshake, message1) = NodeHandshake::start(
            pattern,
            &node_priv,
            Some(&relay_pub),
            &prologue_bytes,
            &hello,
        )
        .unwrap();
        let relay_handshake =
            RelayHandshake::start(pattern, &relay_priv, &prologue_bytes, &message1).unwrap();
        let (step, _node_static, message2) = relay_handshake.write_welcome(&welcome).unwrap();
        let RelayHandshakeStep::Finished {
            transport: relay_transport,
            ..
        } = step
        else {
            unreachable!("Ik always finishes at write_welcome")
        };
        let (node_transport, _welcome, _relay_static, outgoing) =
            node_handshake.finish(&message2).unwrap();
        assert!(outgoing.is_none(), "Ik never has a message 3");
        (node_transport, relay_transport)
    }

    fn sample_welcome(relay_cert: NodeCert) -> WelcomeBody {
        WelcomeBody {
            v: PROTOCOL_VERSION,
            relay_cert,
            session: 1,
            time: 0,
            limits: Limits {
                max_record: 65_535,
                max_peers: 1,
                credit: 1_048_576,
            },
            rosters: HashMap::new(),
        }
    }

    #[test]
    fn on_message_replies_to_ping_and_updates_liveness() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now, test_roster_store(), vec![]);

        let ciphertext = relay_transport
            .encrypt_record(&Record::Ping { nonce: [7; 8] })
            .unwrap();
        let later = now + Duration::from_secs(10);
        let event = engine.on_message(&ciphertext, later).unwrap();
        assert!(matches!(event, EngineEvent::Reply(Record::Pong { nonce }) if nonce == [7; 8]));
        assert!(!engine.liveness.is_dead(later));
        assert!(!engine.liveness.should_ping(later));
    }

    #[test]
    fn on_message_treats_a_bare_pong_as_activity_only() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now, test_roster_store(), vec![]);
        let ciphertext = relay_transport
            .encrypt_record(&Record::Pong { nonce: [1; 8] })
            .unwrap();
        let event = engine.on_message(&ciphertext, now).unwrap();
        assert!(matches!(event, EngineEvent::None));
    }

    #[test]
    fn on_message_rekeys_incoming_on_rekey_record() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now, test_roster_store(), vec![]);

        let ciphertext = relay_transport.encrypt_record(&Record::Rekey).unwrap();
        assert!(matches!(
            engine.on_message(&ciphertext, now).unwrap(),
            EngineEvent::None
        ));

        // The peer rekeys its own sending state to match; a message
        // encrypted under the new key must decrypt correctly only
        // because the engine actually rekeyed its receiving state above.
        relay_transport.rekey_outgoing();
        let ciphertext = relay_transport
            .encrypt_record(&Record::Ping { nonce: [1; 8] })
            .unwrap();
        let event = engine.on_message(&ciphertext, now).unwrap();
        assert!(matches!(event, EngineEvent::Reply(Record::Pong { nonce }) if nonce == [1; 8]));
    }

    #[test]
    fn on_message_surfaces_goaway() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let mut engine = Engine::new(node_transport, Instant::now(), test_roster_store(), vec![]);
        let goaway = GoawayBody {
            reason: "superseded".to_string(),
            retry_after_ms: 250,
        };
        let ciphertext = relay_transport
            .encrypt_record(&Record::Goaway(goaway.clone()))
            .unwrap();
        let event = engine.on_message(&ciphertext, Instant::now()).unwrap();
        match event {
            EngineEvent::Goaway(body) => assert_eq!(body, goaway),
            other => panic!("expected Goaway, got {other:?}"),
        }
    }

    #[test]
    fn on_message_delivers_everything_else() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let mut engine = Engine::new(node_transport, Instant::now(), test_roster_store(), vec![]);
        let record = Record::Credit(menzil_proto::CreditBody {
            peer: NodeId::from([9u8; 32]),
            bytes: 1024,
        });
        let ciphertext = relay_transport.encrypt_record(&record).unwrap();
        let event = engine.on_message(&ciphertext, Instant::now()).unwrap();
        match event {
            EngineEvent::Deliver(delivered) => assert_eq!(delivered, record),
            other => panic!("expected Deliver, got {other:?}"),
        }
    }

    #[test]
    fn on_message_stores_a_roster_completed_over_doc_and_returns_none() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let roster_store = test_roster_store();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let mut engine = Engine::new(
            node_transport,
            Instant::now(),
            Arc::clone(&roster_store),
            vec![network_id],
        );

        let roster = signed_roster(&owner, network_id, 1);
        let records = menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode());

        let mut last_event = None;
        for record in records {
            let ciphertext = relay_transport.encrypt_record(&record).unwrap();
            last_event = Some(engine.on_message(&ciphertext, Instant::now()).unwrap());
        }
        assert!(matches!(last_event, Some(EngineEvent::None)));
        assert_eq!(roster_store.seq(&network_id), Some(1));
    }

    #[test]
    fn on_message_ignores_a_stale_roster_over_doc() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let roster_store = test_roster_store();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        roster_store
            .set(&signed_roster(&owner, network_id, 5))
            .unwrap();
        let mut engine = Engine::new(
            node_transport,
            Instant::now(),
            Arc::clone(&roster_store),
            vec![network_id],
        );

        let stale = signed_roster(&owner, network_id, 3);
        for record in menzil_proto::split_into_doc_records(DocType::Roster, &stale.encode()) {
            let ciphertext = relay_transport.encrypt_record(&record).unwrap();
            engine.on_message(&ciphertext, Instant::now()).unwrap();
        }
        assert_eq!(roster_store.seq(&network_id), Some(5));
    }

    #[test]
    fn on_message_ignores_a_roster_over_doc_for_a_network_this_node_does_not_claim() {
        // Regression test: a relay this node dialed is authenticated
        // (WELCOME's `relay_cert` check), but that alone must not let it
        // grow this node's roster store with networks the node never
        // asked to claim (see `Engine::accept_doc`'s docs).
        let (node_transport, mut relay_transport) = two_live_transports();
        let roster_store = test_roster_store();
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        // `claimed_networks` is empty: this node never claimed
        // `network_id` at all.
        let mut engine = Engine::new(
            node_transport,
            Instant::now(),
            Arc::clone(&roster_store),
            vec![],
        );

        let roster = signed_roster(&owner, network_id, 1);
        for record in menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode()) {
            let ciphertext = relay_transport.encrypt_record(&record).unwrap();
            engine.on_message(&ciphertext, Instant::now()).unwrap();
        }
        assert_eq!(roster_store.seq(&network_id), None);
    }

    #[test]
    fn on_message_ignores_a_policy_doc_type_at_l3() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let roster_store = test_roster_store();
        let mut engine = Engine::new(
            node_transport,
            Instant::now(),
            Arc::clone(&roster_store),
            vec![],
        );

        let record = Record::Doc(menzil_proto::DocBody {
            doc_type: DocType::Policy,
            doc_id: menzil_proto::DocId::from([1u8; 16]),
            index: 0,
            count: 1,
            chunk: vec![1, 2, 3],
        });
        let ciphertext = relay_transport.encrypt_record(&record).unwrap();
        let event = engine.on_message(&ciphertext, Instant::now()).unwrap();
        assert!(matches!(event, EngineEvent::None));
    }

    #[test]
    fn on_tick_is_none_when_fresh() {
        let (node_transport, _relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now, test_roster_store(), vec![]);
        assert!(matches!(engine.on_tick(now), TickEvent::None));
    }

    #[test]
    fn on_tick_sends_ping_after_one_interval() {
        let (node_transport, _relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now, test_roster_store(), vec![]);
        let event = engine.on_tick(now + Duration::from_secs(25));
        assert!(matches!(event, TickEvent::Send(Record::Ping { .. })));
    }

    #[test]
    fn on_tick_reports_dead_after_two_intervals() {
        let (node_transport, _relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now, test_roster_store(), vec![]);
        assert!(matches!(
            engine.on_tick(now + Duration::from_secs(50)),
            TickEvent::Dead
        ));
    }

    #[test]
    fn on_tick_rekeys_after_an_hour_of_sustained_activity() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now, test_roster_store(), vec![]);

        // Keep the link alive right up to the hour mark so `is_dead`
        // doesn't preempt the rekey check.
        let almost_an_hour = now + Duration::from_secs(3599);
        let ciphertext = relay_transport
            .encrypt_record(&Record::Ping { nonce: [3; 8] })
            .unwrap();
        engine.on_message(&ciphertext, almost_an_hour).unwrap();

        let an_hour = now + Duration::from_secs(3600);
        assert!(matches!(
            engine.on_tick(an_hour),
            TickEvent::SendThenRekey(Record::Rekey)
        ));
        // The schedule must not fire again immediately.
        assert!(matches!(engine.on_tick(an_hour), TickEvent::None));
    }

    #[test]
    fn encrypt_round_trips_with_the_peer() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let mut engine = Engine::new(node_transport, Instant::now(), test_roster_store(), vec![]);
        let bytes = engine.encrypt(&Record::Attach).unwrap();
        assert_eq!(
            relay_transport.decrypt_record(&bytes).unwrap(),
            Record::Attach
        );
    }

    fn sample_info(relay_node_id: NodeId, relay_x25519: X25519PublicKey) -> ConnectionInfo {
        ConnectionInfo {
            host: "relay.example".to_string(),
            port: 443,
            path: "/_menzil/v1".to_string(),
            relay_node_id,
            relay_x25519: Some(relay_x25519),
        }
    }

    #[test]
    fn verify_relay_identity_accepts_a_matching_cert() {
        let key = SigningKey::generate(&mut rand::rng());
        let node_id = NodeId::from(key.verifying_key().to_bytes());
        let relay_static = X25519PublicKey::from([5u8; 32]);
        let cert_body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id,
            x25519_pub: relay_static,
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        let relay_cert = NodeCert::sign(&key, &cert_body).unwrap();
        let welcome = sample_welcome(relay_cert);
        let info = sample_info(node_id, relay_static);
        verify_relay_identity(&info, &welcome, &relay_static).unwrap();
    }

    #[test]
    fn verify_relay_identity_rejects_a_node_id_field_mismatch() {
        let key = SigningKey::generate(&mut rand::rng());
        // What we dialed, and what actually signed the certificate.
        let dialed_id = NodeId::from(key.verifying_key().to_bytes());
        // The certificate's own body claims a different node id.
        let claimed_id = NodeId::from([0x77; 32]);
        let relay_static = X25519PublicKey::from([5u8; 32]);
        let cert_body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: claimed_id,
            x25519_pub: relay_static,
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        let relay_cert = NodeCert::sign(&key, &cert_body).unwrap();
        let welcome = sample_welcome(relay_cert);
        let info = sample_info(dialed_id, relay_static);
        let err = verify_relay_identity(&info, &welcome, &relay_static).unwrap_err();
        assert!(matches!(err, NodeError::RelayIdentityMismatch(_)));
    }

    #[test]
    fn verify_relay_identity_rejects_an_x25519_mismatch() {
        let key = SigningKey::generate(&mut rand::rng());
        let node_id = NodeId::from(key.verifying_key().to_bytes());
        let cert_x25519 = X25519PublicKey::from([5u8; 32]);
        let negotiated_x25519 = X25519PublicKey::from([6u8; 32]);
        let cert_body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id,
            x25519_pub: cert_x25519,
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        let relay_cert = NodeCert::sign(&key, &cert_body).unwrap();
        let welcome = sample_welcome(relay_cert);
        let info = sample_info(node_id, cert_x25519);
        let err = verify_relay_identity(&info, &welcome, &negotiated_x25519).unwrap_err();
        assert!(matches!(err, NodeError::RelayIdentityMismatch(_)));
    }

    #[test]
    fn tai64n_now_label_is_near_the_current_unix_time() {
        let bytes = <[u8; 12]>::from(tai64n_now());
        let label = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let seconds = label - TAI64_UNIX_EPOCH_OFFSET;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(seconds.abs_diff(now) < 5);
    }

    #[test]
    fn tai64n_now_is_monotonic_across_calls() {
        let a = <[u8; 12]>::from(tai64n_now());
        std::thread::sleep(Duration::from_millis(2));
        let b = <[u8; 12]>::from(tai64n_now());
        assert!(b > a);
    }

    #[test]
    fn push_records_for_newer_rosters_pushes_only_when_this_node_is_ahead() {
        let owner_a = SigningKey::generate(&mut rand::rng());
        let owner_b = SigningKey::generate(&mut rand::rng());
        let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
        let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
        let unheld = NetworkId::from([0x33; 32]);

        let store = test_roster_store();
        store.set(&signed_roster(&owner_a, network_a, 3)).unwrap();
        store.set(&signed_roster(&owner_b, network_b, 2)).unwrap();

        let mut welcome_rosters = HashMap::new();
        welcome_rosters.insert(network_a, 1); // we're ahead: push
        welcome_rosters.insert(network_b, 2); // even: nothing to push

        let records = push_records_for_newer_rosters(
            &[network_a, network_b, unheld],
            &store,
            &welcome_rosters,
        );
        assert!(!records.is_empty());
        let mut reassembler = DocReassembler::new();
        let mut pushed_networks = Vec::new();
        for record in records {
            let Record::Doc(body) = record else {
                unreachable!()
            };
            if let Some((doc_type, bytes)) = reassembler.accept(&body).unwrap() {
                assert_eq!(doc_type, DocType::Roster);
                let roster = Roster::decode_strict(&bytes).unwrap();
                pushed_networks.push(roster.decode().unwrap().network_id);
            }
        }
        assert_eq!(pushed_networks, vec![network_a]);
    }

    #[test]
    fn push_records_for_newer_rosters_is_empty_when_relay_is_ahead_or_equal() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = test_roster_store();
        store.set(&signed_roster(&owner, network_id, 2)).unwrap();

        let mut welcome_rosters = HashMap::new();
        welcome_rosters.insert(network_id, 5);
        assert!(push_records_for_newer_rosters(&[network_id], &store, &welcome_rosters).is_empty());

        welcome_rosters.insert(network_id, 2);
        assert!(push_records_for_newer_rosters(&[network_id], &store, &welcome_rosters).is_empty());
    }

    #[test]
    fn push_records_for_newer_rosters_is_empty_for_a_claimed_but_unheld_network() {
        let network_id = NetworkId::from([1u8; 32]);
        let store = test_roster_store();
        assert!(push_records_for_newer_rosters(&[network_id], &store, &HashMap::new()).is_empty());
    }

    #[test]
    fn push_records_for_newer_rosters_pushes_a_seq_zero_roster_when_welcome_has_no_entry() {
        // Regression test: comparing against `.unwrap_or(0)` would make
        // this indistinguishable from "the relay already holds seq 0",
        // silently skipping a push the relay genuinely needs.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let store = test_roster_store();
        store.set(&signed_roster(&owner, network_id, 0)).unwrap();

        let records = push_records_for_newer_rosters(&[network_id], &store, &HashMap::new());
        assert!(!records.is_empty());
    }
}
