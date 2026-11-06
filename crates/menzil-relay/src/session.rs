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
//! A session also ends when a Roster the relay adopts later puts its node out of standing in a
//! network it claimed (protocol.md 7.3; TODO.md L4k K5): revoked, no longer listed, or a
//! `min_serial` raised above the serial of the NodeCert it presented in HELLO. The node gets
//! the Roster of that network (DOC), then ERROR (`revoked`, `not_member` or `stale_serial`) and
//! GOAWAY `revoked`, and the session detaches. Every session judges itself (it listens to `RosterStore::subscribe`), attached or
//! not yet, by the rule HELLO applied (`crate::hello::roster_standing`), so a node of another
//! network is never looked at.
//!
//! Everything else this build doesn't yet act on (PEER_STATE, ADMIT_*,
//! and an ADVERTISE_ACK, CREDIT, or GOAWAY received from a node, all
//! protocol violations since those records are relay-to-node only — not
//! specially detected as such yet, just as unhandled as the rest) is
//! decrypted, logged, and otherwise ignored.

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use menzil_proto::{
    CreditBody, DocReassembler, ErrorBody, ErrorCode, GoawayBody, HelloBody, NetworkId, NodeId,
    Record, WelcomeBody, X25519PublicKey,
};
use menzil_session::{
    HandshakePattern, Liveness, RekeySchedule, RelayHandshake, RelayHandshakeStep, Transport,
    prologue,
};
use tokio::sync::broadcast;

use crate::admission::{IpSlot, NodeSlot};
use crate::connection::InboundConnection;
use crate::doc::{self, AcceptOutcome, PendingBases};
use crate::endpoint::{EndpointCredit, EndpointOutcome};
use crate::error::RelayError;
use crate::forward::{ForwardItem, ForwardOutcome};
use crate::hello::{
    HelloRejection, check_hello_admitting, dedup_networks, over_limit, over_quota, roster_standing,
};
use crate::rate::SessionBudget;
use crate::relay::Relay;
use crate::tenant::{OverQuota, TenantUnattached};

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

/// How long a refused peer's connection stays open, read and discarded, after its ERROR was
/// sent (see `run_handshake_and_validate`).
const REJECTION_LINGER: Duration = Duration::from_secs(1);

/// How long a connection that finished its WebSocket upgrade has to complete the Noise
/// handshake and have its HELLO accepted, from the first message to the end of the rejection
/// linger. The TLS and upgrade steps have `AcceptConfig::handshake_timeout` of their own; this
/// is the step after them, which a peer could otherwise stall for ever by upgrading and then
/// saying nothing (MT4, threat A9).
pub(crate) const NOISE_DEADLINE: Duration = Duration::from_secs(10);

/// How long a session that passed HELLO has to send ATTACH, counted from the end of the
/// handshake; then it is closed (MT4, threat A9; protocol.md 4.1).
pub(crate) const ATTACH_DEADLINE: Duration = Duration::from_secs(10);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// WELCOME for one session. `rosters` is what this session may learn about the relay's
/// networks (isolation rule I1): never the relay's whole list, only networks the peer's own
/// HELLO claimed and passed.
///
/// `limits.max_peers` is the relay's figure, lowered to the `destinations_per_node` figure of
/// every tenant with figures among the networks listed (MT8, design 2.3): the node is told the
/// number the relay will enforce for it. An `Xx` session lists none and hears the relay's figure.
///
/// Accepted limit (round T4, N3): an `Xx` session's WELCOME is written before its HELLO exists,
/// so it carries the relay's `max_peers` while the tenant's `destinations_per_node` is what is
/// enforced once the session attaches. Nodes ignore `max_peers` today; if one starts to rely on
/// it, an `Xx` node learns the lower figure only by a refused first SEND (ERROR `over_quota`).
fn build_welcome(relay: &Relay, session_id: u32, rosters: HashMap<NetworkId, u64>) -> WelcomeBody {
    let mut limits = relay.limits;
    if !rosters.is_empty() {
        let book = relay.tenants();
        let claimed: Vec<NetworkId> = rosters.keys().copied().collect();
        for tenant in book.session_tenants(&claimed) {
            if let Some(figures) = book.figures_of(tenant) {
                let own = u32::try_from(figures.destinations_per_node).unwrap_or(u32::MAX);
                limits.max_peers = limits.max_peers.min(own);
            }
        }
    }
    WelcomeBody {
        v: menzil_proto::PROTOCOL_VERSION,
        relay_cert: relay.identity.node_cert.clone(),
        session: session_id,
        time: unix_now(),
        limits,
        rosters,
    }
}

/// What a session that passed HELLO holds until it attaches or ends: its place in the per NodeId
/// admission cap and in the unattached counts of its tenants. Dropping it gives both back.
pub(crate) struct PreAttach {
    _node: NodeSlot,
    _tenants: TenantUnattached,
}

/// The admission steps of a HELLO that is proven and in standing (see `check_hello_admitting`):
/// the per NodeId cap, then the figures of the tenants of the networks it claimed (MT7, design
/// 2.3). A tenant at its figure refuses the session before WELCOME in `Ik` (the check runs before
/// message 2) with `over_quota`, which only a node in standing in that tenant's network ever
/// hears. The slots live until the session attaches or ends.
fn admit_session(
    relay: &Relay,
    node_id: &NodeId,
    claimed: &[NetworkId],
) -> Result<PreAttach, HelloRejection> {
    let node = relay.admission.admit_node(*node_id).ok_or_else(|| {
        over_limit("too many sessions of this node are waiting to attach; try again shortly")
    })?;
    let attached_before = relay
        .registry
        .attachment_of(node_id)
        .map(|attachment| attachment.claimed_networks)
        .unwrap_or_default();
    let tenants = relay
        .usage
        .admit_unattached(&relay.tenants(), claimed, &attached_before)
        .map_err(|refused| {
            note_over_quota(relay, node_id, &refused, "handshake");
            over_quota(&refused)
        })?;
    Ok(PreAttach {
        _node: node,
        _tenants: tenants,
    })
}

/// The operator's line about a tenant that refused a session; one a minute per node.
fn note_over_quota(relay: &Relay, node_id: &NodeId, refused: &OverQuota, at: &'static str) {
    if let Some(held_back) = relay.log.admit_node("tenant_over_quota", node_id) {
        tracing::warn!(
            node_id = %node_id,
            tenant = %refused.tenant,
            quota = ?refused.quota,
            at,
            held_back,
            "a tenant is at its limit, refusing a session"
        );
    }
}

/// Runs the Noise handshake to completion (protocol.md 4.1), then checks
/// HELLO. On a HELLO rejection, best-effort sends an ERROR record over
/// the now-established transport before returning the error.
///
/// What WELCOME's `rosters` may say depends on what is known when message 2 is written
/// (isolation rule I1). `Ik`: HELLO rides message 1, so it is checked before message 2 is
/// written and WELCOME lists exactly the networks it claimed, if it passed; a HELLO that
/// fails gets an empty list, then the ERROR. `Xx`: message 2 is written before HELLO exists
/// (it rides message 3), so nothing about the peer is proven yet and the list is empty; the
/// node pushes its Roster for any claimed network missing from it (protocol.md 4.3), which
/// the relay drops as equal when it already holds it. The wire format and message order are
/// unchanged either way.
async fn run_handshake_and_validate(
    mut conn: InboundConnection,
    relay: &Relay,
    session_id: u32,
) -> Result<(InboundConnection, Transport, NodeId, HelloBody, PreAttach), RelayError> {
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
    // `Ik` only: HELLO and the node's static key are both known after message 1. The check
    // runs exactly once per session (it records the HELLO's serial and timestamp).
    let early = match (relay_handshake.hello(), relay_handshake.remote_static()) {
        (Some(hello), Some(node_static)) => Some(check_hello_admitting(
            hello,
            &node_static,
            &relay.rosters,
            &relay.history,
            unix_now(),
            |node_id, claimed| admit_session(relay, node_id, claimed),
        )),
        _ => None,
    };
    let proven_rosters = match (&early, relay_handshake.hello()) {
        (Some(Ok(_)), Some(hello)) => relay.rosters.seqs_for(&dedup_networks(&hello.networks)),
        _ => HashMap::new(),
    };
    let welcome = build_welcome(relay, session_id, proven_rosters);
    let (step, _node_static_ik, message2) = relay_handshake.write_welcome(&welcome)?;
    conn.send(message2).await?;

    let (mut transport, hello, checked) = match step {
        RelayHandshakeStep::Finished { transport, hello } => (
            transport,
            *hello,
            early.expect("Ik always has its HELLO checked before WELCOME"),
        ),
        RelayHandshakeStep::AwaitingHello(awaiting) => {
            let message3 = conn.recv().await?;
            let (transport, hello, node_static) = awaiting.finish(&message3)?;
            let checked = check_hello_admitting(
                &hello,
                &node_static,
                &relay.rosters,
                &relay.history,
                unix_now(),
                |node_id, claimed| admit_session(relay, node_id, claimed),
            );
            (transport, hello, checked)
        }
    };

    match checked {
        Ok((node_id, pre_attach)) => Ok((conn, transport, node_id, hello, pre_attach)),
        Err(rejection) => {
            let error_record = Record::Error(ErrorBody {
                code: rejection.code,
                msg: rejection.message.clone(),
            });
            if let Ok(bytes) = transport.encrypt_record(&error_record) {
                let _ = conn.send(bytes).await;
            }
            if rejection.code == ErrorCode::OverQuota {
                // A tenant's figure, not a verdict on the node: it is told to wait.
                let goaway = Record::Goaway(over_quota_goaway());
                if let Ok(bytes) = transport.encrypt_record(&goaway) {
                    let _ = conn.send(bytes).await;
                }
            }
            // An `Ik` HELLO is now checked before WELCOME is written, so the ERROR follows
            // WELCOME at once. The node writes ATTACH right after WELCOME; closing this
            // socket under it would reset the connection before the node reads the ERROR
            // (its write fails with a broken pipe and the reason is lost). Read and discard
            // for a moment, until the node closes or the linger ends.
            let _ = tokio::time::timeout(REJECTION_LINGER, async {
                while conn.recv().await.is_ok() {}
            })
            .await;
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

/// How long a session ended for sending too much is asked to wait before it reconnects.
const RATE_LIMITED_RETRY_MS: u32 = 60_000;

/// How long a device a tenant's figure turned away is asked to wait before it reconnects.
const OVER_QUOTA_RETRY_MS: u32 = 60_000;

/// The GOAWAY that follows ERROR `over_quota` (design 2.3).
fn over_quota_goaway() -> GoawayBody {
    GoawayBody {
        reason: "over_quota".to_string(),
        retry_after_ms: OVER_QUOTA_RETRY_MS,
    }
}

/// Tells a session its tenant is at a figure: ERROR `over_quota`, then GOAWAY `over_quota` with
/// a retry delay, both best effort. The caller ends the session.
async fn end_over_quota(conn: &mut InboundConnection, transport: &mut Transport, message: &str) {
    let error = Record::Error(ErrorBody {
        code: ErrorCode::OverQuota,
        msg: message.to_string(),
    });
    let _ = send_record(conn, transport, error).await;
    let _ = send_record(conn, transport, Record::Goaway(over_quota_goaway())).await;
}

/// Tells a session it is ending for sending too much: ERROR `rate_limited`, then GOAWAY
/// `rate_limited` with a retry delay, both best effort. The caller ends the session.
async fn end_rate_limited(conn: &mut InboundConnection, transport: &mut Transport, what: &str) {
    let error = Record::Error(ErrorBody {
        code: ErrorCode::RateLimited,
        msg: format!("{what}; the session is closed, try again in a minute"),
    });
    let _ = send_record(conn, transport, error).await;
    let goaway = Record::Goaway(GoawayBody {
        reason: "rate_limited".to_string(),
        retry_after_ms: RATE_LIMITED_RETRY_MS,
    });
    let _ = send_record(conn, transport, goaway).await;
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
    pending_bases: &mut PendingBases,
    budget: &mut SessionBudget,
    relay: &Relay,
    node_id: &NodeId,
    session_id: u32,
    claimed_networks: &[NetworkId],
    endpoint_credit: &EndpointCredit,
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
            let outcome = doc::accept_roster_chunk(
                doc_reassembler,
                pending_bases,
                &body,
                &relay.rosters,
                claimed_networks,
                unix_now(),
                &mut budget.docs,
                &relay.roster_quota(*node_id),
                relay.log.about(node_id),
            );
            // A transfer the relay could not use (invalid, forged, for a network the session did
            // not claim or the relay does not serve, over the rate and not a claimed network's)
            // is counted, and a session that keeps sending them is ended (MT5, threat A13),
            // however it is answered, or not, one by one. A stale one is not counted: the node
            // claimed the network and held an old copy, which is no misbehaviour (round T3, M1;
            // TBD 44). A genuine Roster of a claimed network over the rate is the honest node's
            // excess; it counts only towards a larger figure that bounds the decoding it costs.
            let ends_session = match &outcome {
                AcceptOutcome::Invalid | AcceptOutcome::Dropped(_) | AcceptOutcome::OverRate => {
                    budget.note_unadopted()
                }
                AcceptOutcome::OverRateClaimed(_) | AcceptOutcome::OverQuota(_) => {
                    budget.note_over_rate()
                }
                _ => false,
            };
            match outcome {
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
                // The tenant's Roster adoptions of this network are used up (design 2.3): the
                // node is told, and tries again on its next attach or push. Only a claimed,
                // served network of the session gets here, so it tells a stranger nothing.
                AcceptOutcome::OverQuota(_) => {
                    let error = Record::Error(ErrorBody {
                        code: ErrorCode::OverQuota,
                        msg: "this relay's limit on Roster updates for your network is reached; try again later".to_string(),
                    });
                    let _ = send_record(conn, transport, error).await;
                }
                // Silent on purpose (isolation rule I3): a DOC for a network that was not
                // claimed, that is not served, or that does not verify gets no answer; nor does
                // one over the rate, which would only hand the peer a free oracle on the bucket.
                AcceptOutcome::Nothing
                | AcceptOutcome::IgnoredDocType(_)
                | AcceptOutcome::Stale(_)
                | AcceptOutcome::OverRate
                | AcceptOutcome::OverRateClaimed(_)
                | AcceptOutcome::Dropped(_)
                | AcceptOutcome::Invalid => {}
            }
            if ends_session {
                if let Some(held_back) = relay.log.admit_node("doc_session_ended", node_id) {
                    tracing::warn!(
                        session_id,
                        node_id = %node_id,
                        held_back,
                        "ending a session that keeps sending DOC transfers the relay cannot use"
                    );
                }
                end_rate_limited(conn, transport, "sending too many DOC transfers").await;
                return Dispatch::End;
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
            if !budget.advertise.try_take() {
                // Over the rate: the node's claims stay as they were, and it is told, so a
                // misbehaving client can see why nothing changed. The line is throttled.
                if let Some(held_back) = relay.log.admit_node("advertise_over_rate", node_id) {
                    tracing::warn!(
                        session_id,
                        node_id = %node_id,
                        held_back,
                        "a session sends ADVERTISE faster than allowed; refusing the excess"
                    );
                }
                let error = Record::Error(ErrorBody {
                    code: ErrorCode::RateLimited,
                    msg: "too many ADVERTISE records; try again later".to_string(),
                });
                let _ = send_record(conn, transport, error).await;
            } else if relay.registry.is_current(node_id, session_id) {
                let ack = relay.labels.advertise(
                    &relay.rosters,
                    &relay.tenants(),
                    claimed_networks,
                    node_id,
                    &body,
                    unix_now(),
                );
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
            if relay.registry.is_current(node_id, session_id) && relay.is_relay(&dst) {
                // Addressed to the relay itself: taken here, never forwarded and never refused
                // `forbidden` (`crate::endpoint`). `src` is the session's own NodeId; the SEND
                // carries none, so nothing a member sends can name another source.
                let Some(relay_id) = relay.relay_id() else {
                    return Dispatch::Continue;
                };
                match relay.endpoint.accept(
                    &relay.registry,
                    relay_id,
                    endpoint_credit,
                    *node_id,
                    session_id,
                    e2e_proto,
                    flags,
                    payload,
                ) {
                    EndpointOutcome::Taken => Dispatch::Continue,
                    EndpointOutcome::Refused(error) => {
                        let _ = send_record(conn, transport, Record::Error(error)).await;
                        Dispatch::Continue
                    }
                    EndpointOutcome::CreditViolation(error) => {
                        let _ = send_record(conn, transport, Record::Error(error)).await;
                        Dispatch::End
                    }
                }
            } else if relay.registry.is_current(node_id, session_id) {
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
                    ForwardOutcome::OverQuota {
                        error,
                        tenant,
                        quota,
                    } => {
                        // The operator hears, once a minute per node; the sender is told
                        // `over_quota` without a tenant or a number.
                        if let Some(held_back) =
                            relay.log.admit_node("tenant_over_quota_pairs", node_id)
                        {
                            tracing::warn!(node_id = %node_id, tenant = %tenant, ?quota, held_back, "a tenant is at its limit, refusing a new pair");
                        }
                        let _ = send_record(conn, transport, Record::Error(error)).await;
                        Dispatch::Continue
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

/// What a session hears of Roster changes (`RosterStore::subscribe`), to judge itself again when
/// a network it claimed has a newer Roster.
pub(crate) struct StandingWatch {
    changes: broadcast::Receiver<NetworkId>,
    /// False once the store is gone, which cannot happen while the `Relay` is held; then nothing
    /// more is heard (and the arm must not spin on an always ready `Closed`).
    open: bool,
}

impl StandingWatch {
    /// Listening starts now, so a Roster adopted from here on is not missed; a check right after
    /// closes the gap since HELLO was judged.
    pub(crate) fn new(relay: &Relay) -> Self {
        Self {
            changes: relay.rosters.subscribe(),
            open: true,
        }
    }

    /// Resolves when a Roster of one of `claimed` was stored, or when notices were missed (then
    /// any network may have changed). A Roster of any other network is none of this session's
    /// business and is skipped.
    pub(crate) async fn changed(&mut self, claimed: &[NetworkId]) {
        loop {
            if !self.open {
                std::future::pending::<()>().await;
            }
            match self.changes.recv().await {
                Ok(network_id) if claimed.contains(&network_id) => return,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => return,
                Err(broadcast::error::RecvError::Closed) => self.open = false,
            }
        }
    }
}

/// Why `node_id` must no longer be served in the networks it claimed, if the Rosters held now say
/// so: the rule HELLO applied, against what is held at this moment.
fn out_of_standing(
    relay: &Relay,
    node_id: &NodeId,
    cert_serial: u32,
    claimed_networks: &[NetworkId],
) -> Option<HelloRejection> {
    roster_standing(node_id, cert_serial, claimed_networks, &relay.rosters).err()
}

/// Tells a node it is out: first the Roster of the network concerned (DOC records, base first
/// for a steward signed one), so that the node learns why even when the fan-out of that Roster
/// lost the race to this eviction and can leave the network out of its next HELLO (protocol.md
/// 4.2, the twelfth red-team round, N1); then ERROR with the reason, then GOAWAY `revoked`
/// (protocol.md 4.2, 7.3), all best effort. The caller ends the session.
async fn send_eviction(
    conn: &mut InboundConnection,
    transport: &mut Transport,
    relay: &Relay,
    rejection: HelloRejection,
    session_id: u32,
    node_id: &NodeId,
) {
    tracing::info!(
        session_id,
        node_id = %node_id,
        code = ?rejection.code,
        reason = %rejection.message,
        "relay session ended, the node is out of standing in a claimed network"
    );

    if let Some(network_id) = rejection.network
        && let Some(records) = doc::roster_doc_records(&relay.rosters, &network_id)
    {
        send_all(conn, transport, records).await;
    }
    let error = Record::Error(ErrorBody {
        code: rejection.code,
        msg: rejection.message,
    });
    let _ = send_record(conn, transport, error).await;
    let goaway = Record::Goaway(GoawayBody {
        reason: "revoked".to_string(),
        retry_after_ms: 0,
    });
    let _ = send_record(conn, transport, goaway).await;
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
#[allow(clippy::too_many_arguments)]
async fn run_attached_loop(
    mut conn: InboundConnection,
    mut transport: Transport,
    node_id: NodeId,
    cert_serial: u32,
    cert_x25519: X25519PublicKey,
    session_id: u32,
    relay: &Relay,
    claimed_networks: Vec<NetworkId>,
    their_roster_seq: HashMap<NetworkId, u64>,
    pre_attach: PreAttach,
    ip_slot: IpSlot,
) {
    // Listening before judging, so a Roster adopted between the two is heard; HELLO was judged
    // against whatever was held then.
    let mut watch = StandingWatch::new(relay);
    if let Some(rejection) = out_of_standing(relay, &node_id, cert_serial, &claimed_networks) {
        send_eviction(
            &mut conn,
            &mut transport,
            relay,
            rejection,
            session_id,
            &node_id,
        )
        .await;
        return;
    }
    let mut liveness = Liveness::new(Instant::now());
    let mut rekey = RekeySchedule::new(Instant::now());
    let mut tick = tokio::time::interval(TICK);
    let mut doc_reassembler = DocReassembler::new();
    // Bases sent ahead of a steward signed Roster; they live and die with this session.
    let mut pending_bases = PendingBases::new();
    // What this session may still send: ADVERTISE and DOC allowances (`crate::rate`).
    let mut budget = SessionBudget::new(&relay.rates, claimed_networks.len());
    // What this session may send to the relay's own NodeId (`crate::endpoint`).
    let endpoint_credit = EndpointCredit::new(&relay.limits);

    // Phase 1: not yet routable, waiting for ATTACH as the node's first
    // transport record. Liveness and REKEY are already driven here too,
    // but a node that keeps answering PING must not hold this window open
    // for ever: ATTACH has a hard deadline (MT4, threat A9), whatever else
    // arrives meanwhile.
    let attach_at = tokio::time::Instant::now() + relay.timeouts.attach;
    let attach_deadline = tokio::time::sleep_until(attach_at);
    tokio::pin!(attach_deadline);
    // A peer that never reads must not be able to park this task in a write past the deadline
    // (round T3, M2): every send is bounded by it until ATTACH.
    conn.limit_sends_until(Some(attach_at));
    loop {
        if conn.is_broken() {
            tracing::debug!(session_id, node_id = %node_id, "relay session closed, a send timed out");
            return;
        }
        tokio::select! {
            () = &mut attach_deadline => {
                tracing::debug!(session_id, node_id = %node_id, "relay session did not ATTACH in time, closing");
                return;
            }
            incoming = conn.recv() => {
                let outcome = dispatch(
                    &mut conn, &mut transport, &mut liveness, &mut doc_reassembler, &mut pending_bases, &mut budget, relay,
                    &node_id, session_id, &claimed_networks, &endpoint_credit, incoming,
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
            () = watch.changed(&claimed_networks) => {
                if let Some(rejection) = out_of_standing(relay, &node_id, cert_serial, &claimed_networks) {
                    send_eviction(&mut conn, &mut transport, relay, rejection, session_id, &node_id).await;
                    return;
                }
            }
        }
    }

    conn.limit_sends_until(None);
    // Attached sessions are capped in all, and per tenant (MT7). A NodeId that is attached
    // already replaces its old session and is let in (the old one is told to leave right
    // below); the registry takes the place over, so the count is the number of registrations,
    // not of session tasks. The tenant count is taken here, the moment it can be exact; the
    // HELLO only kept a full tenant from handshaking.
    let previous = relay.registry.attachment_of(&node_id);
    let Some(attached_slot) = relay.admission.admit_attached(previous.is_some()) else {
        if let Some(held_back) = relay.log.admit_node("attach_cap", &node_id) {
            tracing::warn!(session_id, node_id = %node_id, held_back, "relay is at its attached session cap, refusing ATTACH");
        }
        let error = Record::Error(ErrorBody {
            code: ErrorCode::RateLimited,
            msg: "the relay has too many attached sessions; try again later".to_string(),
        });
        let _ = send_record(&mut conn, &mut transport, error).await;
        return;
    };
    let replacing = previous.map(|a| a.claimed_networks).unwrap_or_default();
    let tenant_slot =
        match relay
            .usage
            .admit_attached(&relay.tenants(), &claimed_networks, &replacing)
        {
            Ok(slot) => slot,
            Err(refused) => {
                note_over_quota(relay, &node_id, &refused, "attach");
                end_over_quota(&mut conn, &mut transport, refused.message()).await;
                return;
            }
        };
    // From here on the session counts as attached, no longer as waiting to.
    drop(pre_attach);
    drop(ip_slot);

    tracing::info!(session_id, node_id = %node_id, "relay session attached");
    let (mut supersede_rx, mut outbound_rx, mut forward_rx) = relay.registry.attach_counted(
        node_id,
        session_id,
        cert_x25519,
        claimed_networks.clone(),
        Some(attached_slot),
        Some(tenant_slot),
    );
    // A freshly attached session starts with no inherited label claims
    // — see `crate::advertise::LabelRegistry::clear_for`'s doc comment
    // for why this runs here, before this session gets a chance to send
    // its own ADVERTISE, rather than relying only on the old session's
    // own eventual detach. Likewise for SEND/RECV credit and queue state
    // (protocol.md 4.2 scopes both to "(source session, destination
    // session)", not to the NodeId across reconnects — an opus red team
    // review's finding H2): `node_id` needs clearing in both its possible
    // roles, see `ForwardTable::clear_for`'s own doc comment for why.
    relay.labels.clear_for(&node_id, unix_now());
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
        if conn.is_broken() {
            tracing::debug!(session_id, node_id = %node_id, "relay session closed, a send timed out");
            break;
        }
        tokio::select! {
            incoming = conn.recv() => {
                let outcome = dispatch(
                    &mut conn, &mut transport, &mut liveness, &mut doc_reassembler, &mut pending_bases, &mut budget, relay,
                    &node_id, session_id, &claimed_networks, &endpoint_credit, incoming,
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
            () = watch.changed(&claimed_networks) => {
                if let Some(rejection) = out_of_standing(relay, &node_id, cert_serial, &claimed_networks) {
                    // What this attached session already queued toward other nodes is not
                    // delivered (round T2, N2): the destinations' drain loops drop it. Only an
                    // attached session has pairs; a session still attaching must not mark the
                    // pairs of an older session of the same NodeId.
                    relay.forwarding.revoke_sender(&node_id, session_id);
                    send_eviction(&mut conn, &mut transport, relay, rejection, session_id, &node_id).await;
                    break;
                }
            }
            Some(record) = outbound_rx.recv() => {
                let _ = send_record(&mut conn, &mut transport, record).await;
            }
            Some(item) = forward_rx.recv() => {
                match item {
                    ForwardItem::Recv { record, src, charge, reliable, generation, src_session_id, shared } => {
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
                        if shared.is_revoked() {
                            // `src` was evicted from a network while this was queued: it is
                            // not delivered, and nothing is charged for it.
                            tracing::debug!(session_id, "dropping a queued RECV of an evicted sender");
                            relay.forwarding.released(&relay.registry, &src, &node_id, charge, reliable, generation, src_session_id, &shared);
                        } else {
                            let _ = send_record(&mut conn, &mut transport, *record).await;
                            relay.forwarding.drained(&relay.registry, &src, &node_id, charge, reliable, generation, src_session_id, &shared);
                        }
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
            shared,
            ..
        } = item
        {
            relay.forwarding.released(
                &relay.registry,
                &src,
                &node_id,
                charge,
                reliable,
                generation,
                src_session_id,
                &shared,
            );
        }
    }

    // Only the session that actually removed the registration releases
    // this NodeId's per-pair forwarding state (credit ledgers, queue
    // budgets, token buckets), and does so under the registry lock (see
    // `SessionRegistry::detach_then`): a superseded session's late
    // teardown must not wipe the pairs its newer replacement has already
    // started using. Without this, a NodeId that never attaches again
    // would keep its pairs for the life of the relay. The drain loop
    // above has already settled this session's in-flight items; a
    // `drained` call from another session's queue that arrives after the
    // pair is gone finds no pair and is a no-op.
    if relay.registry.detach_then(&node_id, session_id, || {
        relay.forwarding.clear_for(&node_id)
    }) {
        relay.labels.clear_for(&node_id, unix_now());
    }
}

/// The whole life of one accepted connection: handshake, HELLO
/// validation, then the attached loop. Never propagates an error or
/// panics — [`Relay::serve`] fires this off with `tokio::spawn` and has
/// no result to collect.
pub(crate) async fn handle_connection(
    mut conn: InboundConnection,
    relay: Relay,
    session_id: u32,
    ip_slot: IpSlot,
) {
    conn.set_write_timeout(relay.timeouts.write);
    let ip_key = ip_slot.log_key();
    let handshake = tokio::time::timeout(
        NOISE_DEADLINE,
        run_handshake_and_validate(conn, &relay, session_id),
    )
    .await;
    let handshake = match handshake {
        Ok(result) => result,
        Err(_elapsed) => {
            tracing::debug!(
                session_id,
                "relay inbound handshake did not complete in time"
            );
            return;
        }
    };
    match handshake {
        Ok((conn, transport, node_id, hello, pre_attach)) => {
            // The NodeCert was verified by `check_hello`; this reads the serial it judged.
            let Ok(cert) = hello.node_cert.decode() else {
                tracing::warn!(
                    session_id,
                    "relay session dropped, its verified NodeCert did not decode"
                );
                return;
            };
            run_attached_loop(
                conn,
                transport,
                node_id,
                cert.serial,
                cert.x25519_pub,
                session_id,
                &relay,
                dedup_networks(&hello.networks),
                hello.roster_seq,
                pre_attach,
                ip_slot,
            )
            .await;
        }
        Err(err) => {
            // Anyone who can open a TCP connection can cause this line, so it is throttled per
            // peer address.
            if let Some(held_back) = relay.log.admit("failed_before_attach", ip_key) {
                tracing::warn!(error = %err, session_id, held_back, "relay inbound session failed before attaching");
            }
        }
    }
}
