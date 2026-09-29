//! The node-side L3 relay session (protocol.md 3, 4.1, 4.2; TODO.md
//! L3d): dial via `menzil-carrier`, run the Noise handshake via
//! `menzil-session`, verify the relay's identity, send ATTACH, and stay
//! attached.
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

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use tokio::sync::mpsc;

use menzil_carrier::{Backoff, Carrier, ConnectionInfo, DialConfig};
use menzil_proto::{
    Capability, GoawayBody, HelloBody, NetworkId, PROTOCOL_VERSION, Record, Tai64N, WelcomeBody,
    X25519PublicKey,
};
use menzil_session::{
    HandshakePattern, Liveness, NodeHandshake, RekeySchedule, Transport, prologue,
};

use crate::error::NodeError;
use crate::identity::LocalIdentity;

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
    /// The newest Roster `seq` this node already holds, per network
    /// (protocol.md 4.1, 4.3).
    pub roster_seq: HashMap<NetworkId, u64>,
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
}

/// What [`Engine::on_message`] learned from one inbound ciphertext.
#[derive(Debug)]
enum EngineEvent {
    /// Handled internally (an incoming REKEY, or a bare PONG — liveness
    /// activity is already recorded for every decrypted record, so a
    /// PONG needs nothing further); nothing to do.
    None,
    /// Send this record straight back (a PONG for a PING).
    Reply(Record),
    /// Not something this crate interprets itself (SEND/RECV/ADVERTISE*/
    /// DOC/PEER_STATE/CREDIT/ADMIT_*/ERROR — protocol.md 4.3, 4.4, 7.2;
    /// TODO.md L3f, L3g, L4's job); hand it to the caller.
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
    fn new(transport: Transport, now: Instant) -> Self {
        Self {
            transport,
            liveness: Liveness::new(now),
            rekey: RekeySchedule::new(now),
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
            other => EngineEvent::Deliver(other),
        })
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
    /// (protocol.md 4.1), then send ATTACH ("the new session is not
    /// routable... until the node's first transport record, ATTACH, is
    /// decrypted"). Does not retry; see [`run_session`] for the reconnect
    /// loop.
    pub async fn connect(
        config: &SessionConfig,
        env: &HashMap<String, String>,
    ) -> Result<Self, NodeError> {
        let mut carrier = Carrier::dial(&config.dial, env).await?;
        let (transport, welcome) = run_handshake(&mut carrier, config).await?;
        let mut session = Self {
            carrier,
            engine: Engine::new(transport, Instant::now()),
            welcome,
            tick: tokio::time::interval(TICK),
        };
        session.send(Record::Attach).await?;
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

    /// Waits for the next record meant for the caller, transparently
    /// answering PING with PONG, applying an incoming REKEY, and sending
    /// this side's own PING or REKEY as their clocks come due. Returns
    /// an error — ending this connection — on GOAWAY, a dead link, or a
    /// carrier failure; [`run_session`] is what turns that into a
    /// reconnect.
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
                        TickEvent::SendThenRekey(record) => {
                            self.send(record).await?;
                            self.engine.rekey_outgoing();
                        }
                    }
                }
            }
        }
    }
}

/// Runs [`NodeHandshake`] to completion over `carrier` and verifies the
/// result (protocol.md 4.1).
async fn run_handshake(
    carrier: &mut Carrier,
    config: &SessionConfig,
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

    let hello = HelloBody {
        v: PROTOCOL_VERSION,
        node_cert: config.identity.node_cert.clone(),
        networks: config.networks.clone(),
        timestamp: tai64n_now(),
        roster_seq: config.roster_seq.clone(),
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

/// Dials, attaches, and stays attached indefinitely: reconnects through
/// [`Backoff`] on any error, honoring GOAWAY's `retry_after_ms` hint when
/// that was the reason (protocol.md 3.3, 4.1). Records this crate does
/// not interpret itself (everything but ATTACH/PING/PONG/REKEY/GOAWAY)
/// are sent to `events`; interpreting them is a later item's job
/// (TODO.md L3f, L3g, L4). Returns once `events`'s receiver is dropped.
pub async fn run_session(
    config: SessionConfig,
    env: HashMap<String, String>,
    events: mpsc::Sender<Record>,
) {
    let mut backoff = Backoff::new();
    loop {
        let mut session = match Session::connect(&config, &env).await {
            Ok(session) => session,
            Err(err) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %err, delay_ms = delay.as_millis(), "node session connect failed, retrying");
                tokio::time::sleep(delay).await;
                continue;
            }
        };
        tracing::info!("node session attached");
        let attached_at = Instant::now();

        loop {
            match session.recv().await {
                Ok(record) => {
                    if events.send(record).await.is_err() {
                        return;
                    }
                }
                Err(NodeError::Goaway {
                    reason,
                    retry_after_ms,
                }) => {
                    tracing::info!(reason, retry_after_ms, "relay sent GOAWAY, reconnecting");
                    backoff.note_connection_uptime(attached_at.elapsed());
                    tokio::time::sleep(backoff.next_delay_with_hint(retry_after_ms)).await;
                    break;
                }
                Err(err) => {
                    tracing::warn!(error = %err, "node session ended, reconnecting");
                    backoff.note_connection_uptime(attached_at.elapsed());
                    tokio::time::sleep(backoff.next_delay()).await;
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{Limits, NodeCert, NodeCertBody, NodeId};

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
        let mut engine = Engine::new(node_transport, now);

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
        let mut engine = Engine::new(node_transport, now);
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
        let mut engine = Engine::new(node_transport, now);

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
        let mut engine = Engine::new(node_transport, Instant::now());
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
        let mut engine = Engine::new(node_transport, Instant::now());
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
    fn on_tick_is_none_when_fresh() {
        let (node_transport, _relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now);
        assert!(matches!(engine.on_tick(now), TickEvent::None));
    }

    #[test]
    fn on_tick_sends_ping_after_one_interval() {
        let (node_transport, _relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now);
        let event = engine.on_tick(now + Duration::from_secs(25));
        assert!(matches!(event, TickEvent::Send(Record::Ping { .. })));
    }

    #[test]
    fn on_tick_reports_dead_after_two_intervals() {
        let (node_transport, _relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now);
        assert!(matches!(
            engine.on_tick(now + Duration::from_secs(50)),
            TickEvent::Dead
        ));
    }

    #[test]
    fn on_tick_rekeys_after_an_hour_of_sustained_activity() {
        let (node_transport, mut relay_transport) = two_live_transports();
        let now = Instant::now();
        let mut engine = Engine::new(node_transport, now);

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
        let mut engine = Engine::new(node_transport, Instant::now());
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
}
