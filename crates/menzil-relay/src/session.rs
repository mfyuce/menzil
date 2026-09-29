//! The relay's per-connection session driver (protocol.md 3, 4.1, 4.2):
//! completes the inbound handshake, validates HELLO against a held
//! Roster, answers WELCOME, then drives the session's liveness and
//! REKEY schedule until it is attached, superseded, idle, or closed.
//!
//! Deliberately not here — a separate, later item's job (protocol.md
//! 4.2's flow-control paragraph): SEND -> RECV forwarding, credit
//! enforcement, and the per-(source,destination) queues. SEND and CREDIT
//! (and everything else this build doesn't yet act on: DOC, ADVERTISE,
//! ADVERTISE_ACK, PEER_STATE, ADMIT_*, and a GOAWAY received from a node,
//! which is a protocol violation since that record is relay-to-node only
//! — not specially detected as such yet, just as unhandled as the rest)
//! are decrypted, logged, and otherwise ignored.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use menzil_proto::{ErrorBody, GoawayBody, NodeId, Record, WelcomeBody};
use menzil_session::{
    HandshakePattern, Liveness, RekeySchedule, RelayHandshake, RelayHandshakeStep, Transport,
    prologue,
};

use crate::connection::InboundConnection;
use crate::error::RelayError;
use crate::hello::check_hello;
use crate::relay::Relay;

/// The exact byte length of a Noise `Xx` pattern's message 1: just the
/// initiator's ephemeral public key (32 bytes for X25519, `DHLEN`), sent
/// unencrypted since no key exists yet — protocol.md 4.1 carries no
/// payload in `Xx`'s message 1 either ("There is no application data in
/// message 1"), so this figure never varies. Confirmed empirically
/// against this workspace's own `menzil-session`/`snow` versions (32
/// bytes for `Xx`; 369 bytes for a representative `Ik` message 1, which
/// additionally carries an encrypted static key — 32 + 16-byte tag — and
/// an encrypted HELLO payload on top of the same 32-byte ephemeral key)
/// rather than assumed from the Noise spec alone.
const XX_MESSAGE1_LEN: usize = 32;

/// Resolves the open question `menzil-session` itself left to this crate
/// ("nothing in the spec says how a relay would know in advance which
/// pattern an inbound connection is about to speak"): `Ik`'s message 1
/// additionally carries the initiator's encrypted static key (48 bytes)
/// and an encrypted HELLO payload (at least its own 16-byte tag) on top
/// of the same 32-byte ephemeral key `Xx` sends alone, so it can never be
/// as short as `Xx`'s fixed, exact 32 bytes. Any message 1 of exactly
/// [`XX_MESSAGE1_LEN`] bytes is therefore `Xx`; anything else (always
/// structurally larger, never shorter) is `Ik`. A malformed message 1
/// that happens to land on the wrong side of this check simply fails to
/// parse as whichever pattern this guesses, the same as it would fail
/// under any other guess — this never turns a malformed handshake into a
/// successful one under the wrong pattern.
fn detect_pattern(message1: &[u8]) -> HandshakePattern {
    if message1.len() == XX_MESSAGE1_LEN {
        HandshakePattern::Xx
    } else {
        HandshakePattern::Ik
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_welcome(relay: &Relay, session_id: u32) -> WelcomeBody {
    WelcomeBody {
        v: menzil_proto::PROTOCOL_VERSION,
        relay_cert: relay.identity.node_cert.clone(),
        session: session_id,
        time: unix_now(),
        limits: relay.limits,
        rosters: relay.rosters.seqs(),
    }
}

/// Runs the Noise handshake to completion (protocol.md 4.1), then checks
/// HELLO. On a HELLO rejection, best-effort sends an ERROR record over
/// the now-established transport before returning the error — WELCOME
/// itself is unconditional (its contents never depend on HELLO, and
/// `Xx`'s wire order sends it before HELLO is even readable), so there is
/// no way to avoid completing the handshake before learning whether the
/// node passes these checks.
async fn run_handshake_and_validate(
    mut conn: InboundConnection,
    relay: &Relay,
    session_id: u32,
) -> Result<(InboundConnection, Transport, NodeId), RelayError> {
    let message1 = conn.recv().await?;
    let pattern = detect_pattern(&message1);
    let prologue_bytes = prologue(
        &conn.offered_subprotocol,
        &conn.selected_subprotocol,
        pattern,
    );

    let relay_handshake = RelayHandshake::start(
        pattern,
        &relay.identity.x25519_private,
        &prologue_bytes,
        &message1,
    )?;
    let welcome = build_welcome(relay, session_id);
    let (step, node_static_ik, message2) = relay_handshake.write_welcome(&welcome)?;
    conn.send(message2).await?;

    let (mut transport, hello, node_static) = match step {
        RelayHandshakeStep::Finished { transport, hello } => {
            let node_static =
                node_static_ik.expect("Ik always learns the initiator's static key by message 1");
            (transport, *hello, node_static)
        }
        RelayHandshakeStep::AwaitingHello(awaiting) => {
            let message3 = conn.recv().await?;
            awaiting.finish(&message3)?
        }
    };

    match check_hello(
        &hello,
        &node_static,
        &relay.rosters,
        &relay.history,
        unix_now(),
    ) {
        Ok(node_id) => Ok((conn, transport, node_id)),
        Err(rejection) => {
            let error_record = Record::Error(ErrorBody {
                code: rejection.code,
                msg: rejection.message.clone(),
            });
            if let Ok(bytes) = transport.encrypt_record(&error_record) {
                let _ = conn.send(bytes).await;
            }
            Err(RelayError::HelloRejected {
                code: rejection.code,
                message: rejection.message,
            })
        }
    }
}

async fn send_record(
    conn: &mut InboundConnection,
    transport: &mut Transport,
    record: Record,
) -> Result<(), RelayError> {
    let bytes = transport.encrypt_record(&record)?;
    conn.send(bytes).await?;
    Ok(())
}

/// What [`dispatch`] learned from one inbound record.
#[derive(Debug, PartialEq, Eq)]
enum Dispatch {
    /// Handled; keep going.
    Continue,
    /// ATTACH was decrypted (protocol.md 4.1).
    Attach,
    /// The connection closed, or a record failed to decrypt.
    End,
}

/// Decrypts and reacts to one inbound message, shared by both the
/// pre-attach and post-attach phases of [`run_attached_loop`]: PING gets
/// a PONG, REKEY rekeys the receiving cipher, ATTACH is reported to the
/// caller (idempotent either side of it — see this module's doc
/// comment), and everything else is logged and otherwise ignored.
async fn dispatch(
    conn: &mut InboundConnection,
    transport: &mut Transport,
    liveness: &mut Liveness,
    incoming: Result<Vec<u8>, RelayError>,
) -> Dispatch {
    let bytes = match incoming {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::debug!(error = %err, "relay inbound connection ended");
            return Dispatch::End;
        }
    };
    let record = match transport.decrypt_record(&bytes) {
        Ok(record) => record,
        Err(err) => {
            tracing::debug!(error = %err, "relay failed to decrypt a record, closing");
            return Dispatch::End;
        }
    };
    liveness.note_activity(Instant::now());
    match record {
        Record::Ping { nonce } => {
            let _ = send_record(conn, transport, Record::Pong { nonce }).await;
            Dispatch::Continue
        }
        Record::Pong { .. } => Dispatch::Continue,
        Record::Rekey => {
            transport.rekey_incoming();
            Dispatch::Continue
        }
        Record::Attach => Dispatch::Attach,
        other => {
            tracing::debug!(
                ?other,
                "record type not forwarded or acted on by this relay build yet"
            );
            Dispatch::Continue
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum TickOutcome {
    Continue,
    Dead,
}

/// Sends this side's own PING or REKEY as [`Liveness`]/[`RekeySchedule`]
/// come due; a dead link (protocol.md 3.3) is reported for the caller to
/// end the session over.
async fn on_tick(
    conn: &mut InboundConnection,
    transport: &mut Transport,
    liveness: &Liveness,
    rekey: &mut RekeySchedule,
) -> TickOutcome {
    let now = Instant::now();
    if liveness.is_dead(now) {
        return TickOutcome::Dead;
    }
    if rekey.due(now) {
        if send_record(conn, transport, Record::Rekey).await.is_ok() {
            transport.rekey_outgoing();
        }
        rekey.note_rekeyed(now);
    } else if liveness.should_ping(now) {
        let mut nonce = [0u8; 8];
        fastrand::fill(&mut nonce);
        let _ = send_record(conn, transport, Record::Ping { nonce }).await;
    }
    TickOutcome::Continue
}

/// How often the liveness/REKEY clocks are checked when nothing has
/// arrived; see `menzil-node`'s identical constant for why a fixed
/// `tokio::time::Interval` (not a plain `sleep` re-armed each loop pass)
/// matters here.
const TICK: Duration = Duration::from_secs(1);

/// Drives one handshaken connection from "not yet routable" through
/// attachment (protocol.md 4.1) to however it ends: idle, closed, or
/// superseded by a newer session for the same NodeId (protocol.md 10:
/// "Sessions per NodeId: 1 attached").
async fn run_attached_loop(
    mut conn: InboundConnection,
    mut transport: Transport,
    node_id: NodeId,
    session_id: u32,
    relay: &Relay,
) {
    let mut liveness = Liveness::new(Instant::now());
    let mut rekey = RekeySchedule::new(Instant::now());
    let mut tick = tokio::time::interval(TICK);

    // Phase 1: not yet routable, waiting for ATTACH as the node's first
    // transport record. Liveness and REKEY are already driven here too,
    // so a node that never attaches at all still gets evicted rather
    // than leaving this pre-attach window open forever.
    loop {
        tokio::select! {
            incoming = conn.recv() => {
                match dispatch(&mut conn, &mut transport, &mut liveness, incoming).await {
                    Dispatch::Attach => break,
                    Dispatch::Continue => {}
                    Dispatch::End => return,
                }
            }
            _ = tick.tick() => {
                if on_tick(&mut conn, &mut transport, &liveness, &mut rekey).await == TickOutcome::Dead {
                    return;
                }
            }
        }
    }

    tracing::info!(session_id, node_id = %node_id, "relay session attached");
    let mut supersede_rx = relay.registry.attach(node_id, session_id);

    // Phase 2: attached and routable; stay alive until idle, closed, or
    // superseded.
    loop {
        tokio::select! {
            incoming = conn.recv() => {
                match dispatch(&mut conn, &mut transport, &mut liveness, incoming).await {
                    Dispatch::Attach | Dispatch::Continue => {}
                    Dispatch::End => break,
                }
            }
            _ = tick.tick() => {
                if on_tick(&mut conn, &mut transport, &liveness, &mut rekey).await == TickOutcome::Dead {
                    tracing::debug!(session_id, "relay session idle, evicting");
                    break;
                }
            }
            _ = &mut supersede_rx => {
                let goaway = Record::Goaway(GoawayBody {
                    reason: "superseded".to_string(),
                    retry_after_ms: 0,
                });
                let _ = send_record(&mut conn, &mut transport, goaway).await;
                tracing::info!(session_id, node_id = %node_id, "relay session superseded");
                break;
            }
        }
    }

    relay.registry.detach(&node_id, session_id);
}

/// The whole life of one accepted connection: handshake, HELLO
/// validation, then the attached loop. Never propagates an error or
/// panics — [`Relay::serve`] fires this off with `tokio::spawn` and has
/// no result to collect.
pub(crate) async fn handle_connection(conn: InboundConnection, relay: Relay, session_id: u32) {
    match run_handshake_and_validate(conn, &relay, session_id).await {
        Ok((conn, transport, node_id)) => {
            run_attached_loop(conn, transport, node_id, session_id, &relay).await;
        }
        Err(err) => {
            tracing::warn!(error = %err, session_id, "relay inbound session failed before attaching");
        }
    }
}
