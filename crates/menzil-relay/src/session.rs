//! The relay's per-connection session driver (protocol.md 3, 4.1, 4.2):
//! completes the inbound handshake, validates HELLO against a held
//! Roster, answers WELCOME, then drives the session's liveness and
//! REKEY schedule until it is attached, superseded, idle, or closed.
//! Also drives DOC(roster) propagation (protocol.md 4.3; TODO.md L3f, see
//! `crate::doc`) both on receipt and as an attach-time catch-up, and
//! delivers anything `crate::doc`'s fan-out hands this session through
//! `SessionRegistry::send_to`.
//!
//! Also handles ADVERTISE / ADVERTISE_ACK label claiming against a held
//! Roster (protocol.md 4.4; TODO.md L3g, see `crate::advertise`) — only
//! for a connection `SessionRegistry::is_current` confirms is still
//! `node_id`'s current session, checked fresh on every ADVERTISE, not
//! just at attach time — and resets a node's advertised labels both
//! right after a fresh attach (so they never silently carry over from a
//! prior, possibly-superseded session) and on a genuine detach (not
//! merely superseded — see `SessionRegistry::detach`'s own return
//! value), so a node that goes fully idle eventually frees its names.
//!
//! Also handles SEND -> RECV forwarding, credit enforcement, and the
//! bounded per-(source,destination) queues (protocol.md 4.2's flow
//! control paragraph; TODO.md L3h, see `crate::forward`) — the same
//! `is_current` guard as ADVERTISE gates a SEND from ever being processed
//! before ATTACH or after this session has been superseded, and
//! `crate::forward::ForwardTable`'s own drain (once a queued RECV record
//! is actually handed to its destination's connection to send) is what
//! grants credit back and sends the resulting CREDIT record, over
//! [`crate::registry::SessionRegistry::deliver`], a channel kept
//! separate from DOC/ADVERTISE_ACK's own for the reasons `crate::registry`'s
//! module doc comment gives.
//!
//! Everything else this build doesn't yet act on (PEER_STATE, ADMIT_*,
//! and an ADVERTISE_ACK, CREDIT, or GOAWAY received from a node, all
//! protocol violations since those records are relay-to-node only — not
//! specially detected as such yet, just as unhandled as the rest) is
//! decrypted, logged, and otherwise ignored.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use menzil_proto::{
    CreditBody, DocReassembler, ErrorBody, ErrorCode, GoawayBody, HelloBody, NetworkId, NodeId,
    Record, WelcomeBody,
};
use menzil_session::{
    HandshakePattern, Liveness, RekeySchedule, RelayHandshake, RelayHandshakeStep, Transport,
    prologue,
};

use crate::connection::InboundConnection;
use crate::doc::{self, AcceptOutcome};
use crate::error::RelayError;
use crate::forward::{ForwardItem, ForwardOutcome};
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
) -> Result<(InboundConnection, Transport, NodeId, HelloBody), RelayError> {
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
        Ok(node_id) => Ok((conn, transport, node_id, hello)),
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

/// Encrypts and sends every record in `records`, best effort (matching
/// this module's existing `let _ =` treatment of PING/REKEY/GOAWAY sends:
/// a send failure here means the connection is on its way out regardless,
/// and the next `conn.recv()` will surface that through the normal
/// `Dispatch::End` path rather than needing a second error path here).
async fn send_all(conn: &mut InboundConnection, transport: &mut Transport, records: Vec<Record>) {
    for record in records {
        let _ = send_record(conn, transport, record).await;
    }
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
/// comment), DOC(roster) is fed to `crate::doc` and, if it completed with
/// something newer, fanned out to this network's other attached members,
/// ADVERTISE is validated and acknowledged via `crate::advertise` but
/// only while `session_id` is still current (see this function's own
/// call site below), and everything else is logged and otherwise
/// ignored.
#[allow(clippy::too_many_arguments)]
async fn dispatch(
    conn: &mut InboundConnection,
    transport: &mut Transport,
    liveness: &mut Liveness,
    doc_reassembler: &mut DocReassembler,
    relay: &Relay,
    node_id: &NodeId,
    session_id: u32,
    claimed_networks: &[NetworkId],
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
        Record::Doc(body) => {
            match doc::accept_roster_chunk(doc_reassembler, &body, &relay.rosters) {
                AcceptOutcome::NewRoster(network_id) => {
                    if let Some(records) = doc::roster_doc_records(&relay.rosters, &network_id) {
                        doc::fan_out(&relay.registry, &network_id, node_id, &records);
                    }
                }
                AcceptOutcome::TooLarge => {
                    let error = Record::Error(ErrorBody {
                        code: ErrorCode::TooLarge,
                        msg: "DOC transfer exceeded the size limit".to_string(),
                    });
                    let _ = send_record(conn, transport, error).await;
                }
                AcceptOutcome::NetworkNotServed(_) => {
                    let error = Record::Error(ErrorBody {
                        code: ErrorCode::UnknownNetwork,
                        msg: "this relay does not serve that network".to_string(),
                    });
                    let _ = send_record(conn, transport, error).await;
                }
                AcceptOutcome::Nothing
                | AcceptOutcome::IgnoredDocType(_)
                | AcceptOutcome::Invalid => {}
            }
            Dispatch::Continue
        }
        Record::Advertise(body) => {
            // Only for a connection that is still `node_id`'s current
            // session (protocol.md 4.1: not routable, and — by this
            // build's own choice, see `crate::advertise`'s doc comment —
            // not yet eligible to claim anything, until ATTACH; and no
            // longer eligible at all once a newer session has superseded
            // this one, even if this connection has not yet noticed and
            // stops on its own). A red team review found that skipping
            // this check let a pre-attach ADVERTISE both leak a claim
            // forever if that connection then simply disappeared, and
            // let an already-superseded connection's late-arriving
            // ADVERTISE overwrite a newer session's own claims.
            if relay.registry.is_current(node_id, session_id) {
                let ack = relay
                    .labels
                    .advertise(&relay.rosters, claimed_networks, node_id, &body);
                let _ = send_record(conn, transport, Record::AdvertiseAck(ack)).await;
            } else {
                tracing::debug!(
                    session_id,
                    node_id = %node_id,
                    "ignoring ADVERTISE from a session that is not (or no longer) current"
                );
            }
            Dispatch::Continue
        }
        Record::Send {
            dst,
            e2e_proto,
            flags,
            payload,
        } => {
            // Same guard, same reasoning as ADVERTISE just above: a
            // session that is not yet, or no longer, current for
            // `node_id` must not be able to move data through the relay
            // on its behalf.
            if relay.registry.is_current(node_id, session_id) {
                let outcome = relay.forwarding.forward(
                    &relay.rosters,
                    &relay.registry,
                    &relay.labels,
                    &relay.limits,
                    node_id,
                    claimed_networks,
                    &dst,
                    e2e_proto,
                    flags,
                    payload,
                    unix_now(),
                );
                match outcome {
                    ForwardOutcome::Queued | ForwardOutcome::Dropped => Dispatch::Continue,
                    ForwardOutcome::Refused(error) => {
                        let _ = send_record(conn, transport, Record::Error(error)).await;
                        Dispatch::Continue
                    }
                    ForwardOutcome::CreditViolation(error) => {
                        let _ = send_record(conn, transport, Record::Error(error)).await;
                        Dispatch::End
                    }
                }
            } else {
                tracing::debug!(
                    session_id,
                    node_id = %node_id,
                    "ignoring SEND from a session that is not (or no longer) current"
                );
                Dispatch::Continue
            }
        }
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
/// "Sessions per NodeId: 1 attached"). `claimed_networks` and
/// `their_roster_seq` are this node's own HELLO `networks`/`roster_seq`
/// (protocol.md 4.1), used for DOC propagation targeting and the
/// attach-time catch-up (protocol.md 4.3; `crate::doc`).
async fn run_attached_loop(
    mut conn: InboundConnection,
    mut transport: Transport,
    node_id: NodeId,
    session_id: u32,
    relay: &Relay,
    claimed_networks: Vec<NetworkId>,
    their_roster_seq: HashMap<NetworkId, u64>,
) {
    let mut liveness = Liveness::new(Instant::now());
    let mut rekey = RekeySchedule::new(Instant::now());
    let mut tick = tokio::time::interval(TICK);
    let mut doc_reassembler = DocReassembler::new();

    // Phase 1: not yet routable, waiting for ATTACH as the node's first
    // transport record. Liveness and REKEY are already driven here too,
    // so a node that never attaches at all still gets evicted rather
    // than leaving this pre-attach window open forever.
    loop {
        tokio::select! {
            incoming = conn.recv() => {
                let outcome = dispatch(
                    &mut conn, &mut transport, &mut liveness, &mut doc_reassembler, relay,
                    &node_id, session_id, &claimed_networks, incoming,
                ).await;
                match outcome {
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
    let (mut supersede_rx, mut outbound_rx, mut forward_rx) =
        relay
            .registry
            .attach(node_id, session_id, claimed_networks.clone());
    // A freshly attached session starts with no inherited label claims
    // — see `crate::advertise::LabelRegistry::clear_for`'s doc comment
    // for why this runs here, before this session gets a chance to send
    // its own ADVERTISE, rather than relying only on the old session's
    // own eventual detach. Likewise for SEND/RECV credit and queue state
    // (protocol.md 4.2 scopes both to "(source session, destination
    // session)", not to the NodeId across reconnects — an opus red team
    // review's finding H2): `node_id` needs clearing in both its possible
    // roles, see `ForwardTable::clear_for`'s own doc comment for why.
    relay.labels.clear_for(&node_id);
    relay.forwarding.clear_for(&node_id);

    // Attach-time catch-up (protocol.md 4.3, extended — see `crate::doc`'s
    // module doc comment for why): this node may be attaching already
    // behind what this relay holds for a network it just claimed.
    for network_id in doc::catch_up_targets(&relay.rosters, &claimed_networks, &their_roster_seq) {
        if let Some(records) = doc::roster_doc_records(&relay.rosters, &network_id) {
            send_all(&mut conn, &mut transport, records).await;
        }
    }

    // Phase 2: attached and routable; stay alive until idle, closed, or
    // superseded.
    loop {
        tokio::select! {
            incoming = conn.recv() => {
                let outcome = dispatch(
                    &mut conn, &mut transport, &mut liveness, &mut doc_reassembler, relay,
                    &node_id, session_id, &claimed_networks, incoming,
                ).await;
                match outcome {
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
            Some(record) = outbound_rx.recv() => {
                let _ = send_record(&mut conn, &mut transport, record).await;
            }
            Some(item) = forward_rx.recv() => {
                match item {
                    ForwardItem::Recv { record, src, charge, reliable, generation, src_session_id } => {
                        // Only now — once this RECV record has actually
                        // been handed to this (destination) connection to
                        // send, not merely admitted into `ForwardTable`
                        // — does the sending side's credit get granted
                        // back (protocol.md 4.2: "replenished as bytes
                        // are written to the destination socket") and a
                        // CREDIT record queued for it (see `drained`'s
                        // own doc comment for why that record travels
                        // this same reliable channel, not `send_to`'s
                        // lossy one).
                        let _ = send_record(&mut conn, &mut transport, *record).await;
                        relay.forwarding.drained(&relay.registry, &src, &node_id, charge, reliable, generation, src_session_id);
                    }
                    ForwardItem::Credit { peer, bytes } => {
                        let _ = send_record(
                            &mut conn, &mut transport, Record::Credit(CreditBody { peer, bytes }),
                        ).await;
                    }
                }
            }
        }
    }

    // Anything still sitting in `forward_rx` at this point will never be
    // handed to this connection to send — it is ending regardless of
    // whether `detach` below actually finds it still current. Draining it
    // here (rather than letting `forward_rx` simply drop, discarding
    // whatever it still held) is the fix for an opus red team review's
    // finding H1: undrained items silently leaked their share of the
    // sender's credit and the pair's queue budget forever, surviving even
    // the destination's next reconnect (until `clear_for` closed that
    // specific gap for the *reconnect* case above; this closes it for the
    // *in-flight-at-teardown* case, which is not the same window — a
    // session can end this way without anyone ever reconnecting again for
    // a while, or at all). Only `Recv` items carry anything to release; a
    // stranded `Credit` item is simply dropped (no ledger state to
    // reconcile, and `node_id`, its intended recipient, is the one whose
    // credit that item was reporting — not `src`'s of any `Recv` also
    // found here — so there is nothing further to do for it here either
    // way).
    forward_rx.close();
    while let Ok(item) = forward_rx.try_recv() {
        if let ForwardItem::Recv {
            src,
            charge,
            reliable,
            generation,
            src_session_id,
            ..
        } = item
        {
            relay.forwarding.drained(
                &relay.registry,
                &src,
                &node_id,
                charge,
                reliable,
                generation,
                src_session_id,
            );
        }
    }

    if relay.registry.detach(&node_id, session_id) {
        relay.labels.clear_for(&node_id);
    }
}

/// Deduplicates HELLO's `networks` before it becomes this session's
/// `claimed_networks`. `check_hello` validates each claim independently
/// and never rejects a repeated one, but every entry here later drives
/// its own catch-up lookup and, if triggered, its own full DOC resend
/// (`crate::doc::catch_up_targets`); without this, one real NetworkId
/// repeated many times in a single HELLO would get that network's whole
/// Roster pushed once per repetition instead of once.
fn dedup_networks(networks: Vec<NetworkId>) -> Vec<NetworkId> {
    let mut seen = HashSet::with_capacity(networks.len());
    networks.into_iter().filter(|id| seen.insert(*id)).collect()
}

/// The whole life of one accepted connection: handshake, HELLO
/// validation, then the attached loop. Never propagates an error or
/// panics — [`Relay::serve`] fires this off with `tokio::spawn` and has
/// no result to collect.
pub(crate) async fn handle_connection(conn: InboundConnection, relay: Relay, session_id: u32) {
    match run_handshake_and_validate(conn, &relay, session_id).await {
        Ok((conn, transport, node_id, hello)) => {
            run_attached_loop(
                conn,
                transport,
                node_id,
                session_id,
                &relay,
                dedup_networks(hello.networks),
                hello.roster_seq,
            )
            .await;
        }
        Err(err) => {
            tracing::warn!(error = %err, session_id, "relay inbound session failed before attaching");
        }
    }
}
