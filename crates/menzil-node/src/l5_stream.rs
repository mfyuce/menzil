//! The L5 stream layer on one established L4 session (protocol.md 5.3) —
//! TODO.md L4h4. [`open`] runs the initiator side of one OPEN/OPEN_ACK
//! exchange on a freshly opened [`L4SessionHandle::open_stream`] result;
//! [`accept_loop`] runs the responder side on every stream the peer
//! opens, through a caller-supplied [`Authorizer`]/[`ServiceHandler`]
//! pair, spawning an accepted stream's [`ServiceHandler::handle`] future
//! (fire-and-forget, matching that trait's own contract). Both enforce
//! protocol.md 5.3's 10 second OPEN timeout, which neither
//! `menzil_stream::initiate_open` nor `respond_to_open` bounds on its
//! own. [`accept_loop`] takes the [`L4SessionAcceptor`] half of a
//! session, not the cloneable [`L4SessionHandle`] — so a caller can run
//! it on its own task while a different task opens, feeds inbound data,
//! or closes through the other half at the same time; an earlier version
//! of this module took the single, unsplit handle `&mut`, which made
//! that impossible (a round-2 red-team review's own finding, fixed by
//! splitting the handle one layer down in `l4_session`, not here).
//!
//! **Not this module's job**: deciding grants ([`Authorizer`], TODO.md
//! L4h2's [`crate::PolicyAuthorizer`]) or dispatching an accepted stream
//! to a configured local target ([`ServiceHandler`], TODO.md L4i) —
//! both are a caller's concern; [`accept_loop`] only wires the exchange
//! and the admission control around them.
//!
//! **Why `accept_loop` always scrubs `meta` to its default before either
//! gate sees it**: `menzil_stream::OpenRequest::meta` is peer-chosen and
//! "honored only when the sender is the relay principal" (that type's
//! own doc comment), but neither `menzil_stream::open` nor
//! `respond_to_open` strips it for an ordinary member session — by
//! design, since that crate has no session context to know which case it
//! is in. This module's caller is always a member session (nothing here
//! runs the relay-principal path TODO.md's `expose` line and
//! TOBEDECIDED item 8 still need to define), so [`accept_loop`] wraps
//! whatever `Authorizer`/`ServiceHandler` it is given in a private
//! adapter that rebuilds the request with `meta: OpenMeta::default()`
//! before delegating — the only point where this can actually be
//! enforced, since `respond_to_open` builds the real `OpenRequest`
//! internally and never hands it to its caller first.
//!
//! **Why a timed-out exchange is simply dropped, on both sides**: for
//! [`open`], protocol.md 5.3's own OPEN/OPEN_ACK exchange rides
//! `menzil_stream::initiate_open`, whose doc comment states directly that
//! it "is not cancel-safe" — a cancelled read or write can leave the
//! stream positioned mid-header, so it must never be used again.
//! `respond_to_open` carries no equivalent warning in its own doc
//! comment, but the same reasoning applies by construction: it is built
//! from the same `read_len_prefixed`/`write_all` primitives, and
//! cancelling it mid-call leaves no way to know how many bytes of
//! someone's header were actually consumed or delivered. [`accept_loop`]
//! therefore treats a timed-out inbound exchange the same way: the
//! `respond_to_open` future (which owns the stream by value) is simply
//! left to drop when `tokio::time::timeout` gives up on it, never
//! retried or inspected further.
//!
//! **Per-session OPEN admission** ([`MAX_CONCURRENT_OPENS`]): bounds how
//! many inbound exchanges [`accept_loop`] runs at once; a stream that
//! arrives with no slot free is shed outright — a bare drop, denied even
//! the chance to be read — rather than parked the way a bare
//! `respond_to_open` loop with no bound at all would park every one of
//! them (`menzil_stream::respond_to_open`'s own doc comment: up to
//! yamux's 512-stream cap, after which this side's own next
//! `StreamMux::open` ends the whole `Driver`). The initiator sees a shed
//! stream as a plain I/O error on its own exchange, indistinguishable
//! from a session that simply died — a real, known limitation, not
//! solved here (see the next paragraph for why).
//!
//! **A round-2 red-team review found a smarter-looking fix for that
//! limitation was actually worse, live, and this module was reverted
//! back to the shape above because of it.** The tried fix raised
//! [`MAX_CONCURRENT_OPENS`] from 32 to 128 (reasoning that taking the
//! admission permit synchronously, before the exchange it guards has
//! even run, can shed a burst of already-queued streams a session could
//! have handled fine) and, on shedding, wrote an explicit
//! `OPEN_ACK{ok: false, RateLimited}` refusal instead of this bare drop
//! (so the initiator could tell "shed" apart from "session died").
//! Measured live, it traded a lower-severity problem for a higher-
//! severity one: a refused exchange costs *two* outbound frames (the
//! OPEN_ACK, then a separate FIN from closing the stream), not "at most
//! one" as that version's own doc comment claimed, so 128 slots
//! resolving inside one `Driver` poll is the *entire* 256-frame budget,
//! not half of it — and this killed sessions the original 32-slot,
//! bare-drop shape never did across the same tests, including through
//! the plain, non-hostile [`open`] API at a realistic concurrency
//! (n=200-256 against a refusing handler: zero deaths at the original
//! bound, real deaths at the raised one). An occasional false shed is
//! strictly better than an occasional dead session, so this module keeps
//! the smaller problem rather than the larger one. This is the same
//! structural gap TODO.md's own L4h3/L4h5 lines named — a single
//! `Driver` poll can emit more frames than `menzil-stream`'s outbound
//! channel holds before anything downstream, including this module's own
//! admission control, ever gets a chance to run — and said to escalate
//! to `menzil-stream`'s budget pausing instead of failing outright
//! rather than retune a number here, since no bound or shedding strategy
//! chosen at this layer could close it, only trade which load pattern
//! triggers it.
//!
//! **That escalation has since happened (TODO.md L4h5), and the gap is
//! closed one layer down**: `menzil-stream`'s outbound channel now pauses
//! `yamux` when full instead of ending the connection, so a burst of
//! refusals, of any size, only queues. A second symptom that first looked
//! like a separate, unknown `yamux` bug ("unknown frame type N") was the
//! same exhaustion misreported by a retry bug in `RecordIo::poll_write`,
//! which is gone with the failure path it lived in. The 32-slot bare-drop
//! shape above is deliberately left as measured rather than re-tuned:
//! the 128-slot variant that killed sessions then no longer would, but
//! nothing here re-measured it, and a shed stream still reads as a dead
//! session to its initiator either way. This module's own
//! `#[ignore]`d `tests::a_hostile_unpaced_open_burst_does_not_end_the_session`
//! is the end-to-end probe of a hostile burst; the tests that fail
//! without the pause semantics are in `menzil-stream`'s
//! `tests/backpressure.rs`.
use std::sync::Arc;
use std::time::Duration;

use menzil_proto::{ErrorCode, OpenBody, OpenMeta, OpenTarget, ServiceId, ServiceKind};
use menzil_stream::{
    Authorizer, OpenDecision, OpenError, OpenRefusal, OpenRequest, Responded, ServiceHandler,
    Stream, StreamMuxError, initiate_open, respond_to_open,
};
use tokio::sync::Semaphore;

use crate::l4_session::{L4SessionAcceptor, L4SessionHandle};

/// protocol.md 5.3: "OPEN times out after 10 seconds" — applied to both
/// [`open`]'s own exchange and each one [`accept_loop`] runs. `pub`
/// rather than private so the rustdoc links to it above (and this
/// module's own tests) resolve.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// How many inbound OPEN exchanges [`accept_loop`] runs at once, per
/// session, before shedding the rest — see this module's own doc
/// comment for why a fixed bound, not retuned against a burst, and why
/// a round-2 red-team review reverted an attempt to raise this past its
/// original value. `pub` for the same reason as [`OPEN_TIMEOUT`].
pub const MAX_CONCURRENT_OPENS: usize = 32;

/// `msg` with every control character, bidi-formatting character, and
/// zero-width character removed, then capped at a sane display length.
/// [`menzil_proto::OpenAckBody::msg`], once decoded off the wire, is
/// peer-controlled text with no length or content guarantee beyond the
/// registry's own `u16` frame-size ceiling — `menzil_stream::
/// OpenRequest`'s own doc comment already warns the *responder* side of
/// this exchange about the identical hazard on `OpenRequest::msg`, but
/// nothing sanitized the *initiator* side's own [`OpenStreamError::Refused`]
/// before this existed, and that value is exactly the kind of thing a
/// caller logs. Stripping only `char::is_control()` was not enough on
/// its own — a round-2 red-team review confirmed live that a bidi
/// override (U+202E) or a zero-width space (U+200B) both pass through
/// that filter unchanged, which is exactly the kind of character used to
/// make logged or displayed text read as something other than what it
/// is. Cut at a `char` boundary (not a byte one) since the characters
/// stripped here are first filtered out rather than counted against the
/// cap, so no byte-boundary walk is needed the way `menzil_stream::open`'s
/// own `clamp_refusal_msg` needs for its raw byte cap.
fn sanitize_peer_msg(msg: &str) -> String {
    const MAX_CHARS: usize = 256;
    fn is_hazardous(c: char) -> bool {
        c.is_control()
            // Explicit bidi formatting (LRE/RLE/PDF/LRO/RLO through
            // LRI/RLI/FSI/PDI) — can reorder how surrounding text
            // displays without changing its content.
            || ('\u{202A}'..='\u{202E}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
            // Zero-width characters (ZWSP/ZWNJ/ZWJ/LRM/RLM) — invisible,
            // can split or hide tokens in logged or displayed text.
            || ('\u{200B}'..='\u{200F}').contains(&c)
            // Byte-order mark, also used as a zero-width no-break space.
            || c == '\u{FEFF}'
    }
    let cleaned: String = msg.chars().filter(|c| !is_hazardous(*c)).collect();
    if cleaned.chars().count() <= MAX_CHARS {
        cleaned
    } else {
        let truncated: String = cleaned.chars().take(MAX_CHARS).collect();
        format!("{truncated}\u{2026}")
    }
}

/// Errors from [`open`]: driving one outbound OPEN/OPEN_ACK exchange to
/// completion. A peer's explicit refusal ([`Self::Refused`]) is a
/// successful exchange with a negative answer, kept distinct from the
/// exchange itself failing.
#[derive(Debug, thiserror::Error)]
pub enum OpenStreamError {
    /// `target` was given for a `service` other than the literal
    /// `egress:*` — protocol.md 5.3: "`target` must be null unless
    /// `service` is `egress:*`". Checked locally, before this call ever
    /// opens a raw stream: a 2026-10-06 red-team review noted the
    /// original version instead let a guaranteed-invalid OPEN reach the
    /// wire and burn a stream only to have the peer reject it.
    #[error("target is only valid for the egress:* service")]
    InvalidTarget,
    /// Opening the raw L5 stream itself failed — in practice, this
    /// session has already ended.
    #[error("opening the raw stream: {0}")]
    Stream(#[from] StreamMuxError),
    /// Writing this side's OPEN header, or reading and decoding the
    /// peer's OPEN_ACK, failed.
    #[error("open/open_ack exchange: {0}")]
    Exchange(#[from] OpenError),
    /// No OPEN_ACK arrived within [`OPEN_TIMEOUT`]. The stream this call
    /// opened is already gone — see this module's own doc comment on why
    /// a timed-out exchange is never retried on the same stream.
    #[error("no OPEN_ACK within {0:?}")]
    Timeout(Duration),
    /// The peer's OPEN_ACK carried `ok: false`.
    #[error("peer refused ({code:?}): {msg}")]
    Refused {
        /// The refusal's reason code.
        code: ErrorCode,
        /// The refusal's human-readable detail, sanitized by
        /// [`sanitize_peer_msg`] — this is peer-controlled text.
        msg: String,
    },
}

/// Runs the initiator side of one OPEN/OPEN_ACK exchange (protocol.md
/// 5.3) for `service` (and, only for the literal `egress:*` service,
/// `target`) on `session`: opens a fresh raw stream, then drives
/// `menzil_stream::initiate_open` on it. On success, returns the stream
/// ready for `service`'s own byte traffic. The whole call — opening the
/// raw stream included, not only the OPEN/OPEN_ACK exchange once it
/// exists — is bounded by one [`OPEN_TIMEOUT`] deadline: a round-2
/// red-team review found live that `session.open_stream()` itself can
/// wait well past 10s, on yamux's own unacknowledged-outbound backlog
/// rather than anything this function's timeout was, at the time, even
/// watching.
pub async fn open(
    session: &L4SessionHandle,
    service: ServiceId,
    target: Option<OpenTarget>,
) -> Result<Stream, OpenStreamError> {
    if target.is_some() && service != ServiceId::new(ServiceKind::Egress, "*") {
        return Err(OpenStreamError::InvalidTarget);
    }
    match tokio::time::timeout(OPEN_TIMEOUT, open_inner(session, service, target)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(OpenStreamError::Timeout(OPEN_TIMEOUT)),
    }
}

/// [`open`]'s own body, run under its single [`OPEN_TIMEOUT`] deadline —
/// split out only so that deadline can wrap `session.open_stream()` too,
/// not just the exchange that follows it.
async fn open_inner(
    session: &L4SessionHandle,
    service: ServiceId,
    target: Option<OpenTarget>,
) -> Result<Stream, OpenStreamError> {
    let mut stream = session.open_stream().await?;
    let open = OpenBody {
        v: menzil_proto::PROTOCOL_VERSION,
        service,
        target,
        meta: OpenMeta::default(),
    };
    let ack = initiate_open(&mut stream, &open).await?;
    if ack.ok {
        Ok(stream)
    } else {
        Err(OpenStreamError::Refused {
            code: ack.code,
            msg: sanitize_peer_msg(&ack.msg),
        })
    }
}

/// `request`, rebuilt with `meta` forced to its default — see this
/// module's own doc comment for why [`accept_loop`] always does this for
/// a member session.
fn as_member_request(request: &OpenRequest) -> OpenRequest {
    OpenRequest {
        meta: OpenMeta::default(),
        ..request.clone()
    }
}

/// Wraps an [`Authorizer`] so every request it actually sees has already
/// had its `meta` scrubbed — see this module's own doc comment.
struct MemberAuthorizer<A>(A);

impl<A: Authorizer> Authorizer for MemberAuthorizer<A> {
    fn authorize(&self, request: &OpenRequest) -> OpenDecision {
        self.0.authorize(&as_member_request(request))
    }
}

/// Wraps a [`ServiceHandler`] the same way [`MemberAuthorizer`] wraps an
/// [`Authorizer`].
struct MemberServiceHandler<H>(H);

impl<S, H: ServiceHandler<S>> ServiceHandler<S> for MemberServiceHandler<H> {
    type Handling = H::Handling;

    fn accepts(&self, request: &OpenRequest) -> Result<(), OpenRefusal> {
        self.0.accepts(&as_member_request(request))
    }

    fn handle(&self, stream: S, request: OpenRequest) -> Self::Handling {
        self.0.handle(stream, as_member_request(&request))
    }
}

/// Runs the responder side of every OPEN a peer sends on `acceptor`,
/// until its session ends (`acceptor.accept()` returns `None`). Each
/// inbound stream runs `menzil_stream::respond_to_open` against
/// `authorizer` and `handler` (both scrubbed of peer-sent `meta` first —
/// see this module's own doc comment) under [`OPEN_TIMEOUT`], bounded by
/// [`MAX_CONCURRENT_OPENS`] concurrent exchanges; a stream arriving with
/// no slot free is shed — a bare drop, see this module's own doc
/// comment for why — rather than queued. An accepted exchange's own
/// [`ServiceHandler::handle`] future is spawned (fire-and-forget) once
/// its OPEN_ACK has gone out — this function's own admission slot is
/// released as soon as the exchange itself ends (accepted, refused,
/// timed out, or errored), not held for that future's own lifetime,
/// since an accepted stream's own resource pressure (yamux's stream cap,
/// `menzil-stream`'s outbound budget) is a separate, not-yet-built
/// concern (TODO.md's L4h5 line, amended 2026-10-06: nothing today
/// bounds how many already-accepted streams stay alive at once) rather
/// than something this function's own admission slot could cover.
///
/// Takes the unique [`L4SessionAcceptor`] half of a session, not the
/// cloneable [`L4SessionHandle`] — see this module's own doc comment.
pub async fn accept_loop<A, H>(acceptor: &mut L4SessionAcceptor, authorizer: A, handler: H)
where
    A: Authorizer + Send + Sync + 'static,
    H: ServiceHandler<Stream> + Send + Sync + 'static,
    H::Handling: Send + 'static,
{
    let network_id = acceptor.network_id();
    let peer = acceptor.peer();
    let authorizer = Arc::new(MemberAuthorizer(authorizer));
    let handler = Arc::new(MemberServiceHandler(handler));
    let admission = Arc::new(Semaphore::new(MAX_CONCURRENT_OPENS));

    while let Some(stream) = acceptor.accept().await {
        let Ok(permit) = Arc::clone(&admission).try_acquire_owned() else {
            tracing::debug!(
                peer = %peer,
                network_id = %network_id,
                "inbound OPEN shed: no admission slot free"
            );
            // Bare drop, not an explicit refusal — see this module's own
            // doc comment for why: a round-2 red-team review found that
            // writing one costs an extra outbound frame per shed stream,
            // and that extra cost alone was enough to tip a hostile
            // burst into ending the session, which a dropped stream's
            // own single RST does not.
            drop(stream);
            continue;
        };
        let authorizer = Arc::clone(&authorizer);
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _permit = permit;
            let outcome = tokio::time::timeout(
                OPEN_TIMEOUT,
                respond_to_open(stream, network_id, peer, &*authorizer, &*handler),
            )
            .await;
            match outcome {
                Ok(Ok(Responded::Accepted(handling))) => {
                    tokio::spawn(handling);
                }
                Ok(Ok(Responded::Refused(refusal))) => {
                    tracing::debug!(peer = %peer, code = ?refusal.code, "inbound OPEN refused");
                }
                Ok(Err(err)) => {
                    tracing::debug!(peer = %peer, error = %err, "inbound OPEN exchange failed");
                }
                Err(_elapsed) => {
                    tracing::debug!(peer = %peer, "inbound OPEN timed out waiting for its header");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use menzil_e2e::{E2eInitiatorHandshake, E2eResponderHandshake};
    use menzil_proto::{NetworkId, NodeCert, NodeCertBody, NodeId, ServiceKind, X25519PublicKey};
    use menzil_stream::Mode;
    use tokio::sync::{mpsc, oneshot};

    use crate::l4_session::{L4SessionConfig, new as new_l4_session};
    use crate::outbound::{EnqueueOutcome, Epoch, OutboundSend};

    fn ik_params() -> snow::params::NoiseParams {
        "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
    }

    fn fresh_keypair() -> ([u8; 32], X25519PublicKey) {
        let kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        let private = <[u8; 32]>::try_from(kp.private).unwrap();
        let public = X25519PublicKey::from(<[u8; 32]>::try_from(kp.public).unwrap());
        (private, public)
    }

    fn sample_cert(node_id: NodeId) -> NodeCert {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id,
            x25519_pub: X25519PublicKey::from([9u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 4_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }

    /// Mirrors `l4_session::tests::two_sessions` (not reused directly —
    /// that module keeps its own test helpers private): a live
    /// `menzil_e2e` handshake, one [`L4SessionHandle`]/[`L4SessionAcceptor`]/
    /// task triple per side, each fed by the other side's own outbound
    /// frames directly, no L3 session or relay involved. `a`/`b_handle`
    /// and `b`/`a_acceptor` are kept alive even though most tests never
    /// touch them directly. **Dropping every field this struct exposes
    /// does not end either session** — a round-2 red-team review
    /// confirmed live that neither ends within 3s, correcting this
    /// comment's own previous, opposite claim: each side's [`pump`] task
    /// holds its own clone of the *other* side's handle (see `pump`'s
    /// own doc comment), so the two sides keep each other alive in a
    /// cycle no matter what a test does with the fields below. Only
    /// ending a session some other way (`close()`, or its pump's own
    /// source session ending) breaks that cycle on that side.
    struct TwoSessions {
        a: L4SessionHandle,
        a_acceptor: L4SessionAcceptor,
        b: L4SessionAcceptor,
        b_handle: L4SessionHandle,
        _pump_a_to_b: tokio::task::JoinHandle<()>,
        _pump_b_to_a: tokio::task::JoinHandle<()>,
        _task_a: tokio::task::JoinHandle<()>,
        _task_b: tokio::task::JoinHandle<()>,
        _a_epoch_ended_tx: oneshot::Sender<()>,
        _b_epoch_ended_tx: oneshot::Sender<()>,
    }

    /// [`one_session`]'s own return shape, named so it reads as one thing
    /// rather than tripping clippy's `type_complexity` lint.
    type OneSession = (
        L4SessionHandle,
        L4SessionAcceptor,
        mpsc::Receiver<OutboundSend>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    );

    fn one_session(
        transport: menzil_e2e::E2eTransport,
        peer: NodeId,
        network_id: NetworkId,
        mode: Mode,
        max_record: u32,
    ) -> OneSession {
        let (outbound_tx, outbound_rx) = mpsc::channel(64);
        let (epoch_ended_tx, epoch_ended_rx) = oneshot::channel();
        let (handle, acceptor, task) = new_l4_session(
            L4SessionConfig {
                transport,
                peer,
                network_id,
                mode,
                max_record,
                epoch: Epoch::first(),
                send_budget: crate::outbound::SendBudgets::new().for_peer(peer),
                observer: None,
            },
            outbound_tx,
            epoch_ended_rx,
        );
        (
            handle,
            acceptor,
            outbound_rx,
            epoch_ended_tx,
            tokio::spawn(task),
        )
    }

    /// Spawns a task that drains `rx` (one side's own `OutboundSend`
    /// stream), decodes each one's `E2eFrame::Data`, and feeds it
    /// straight into `dst`'s inbound side — the in-process stand-in for
    /// "the L3 relay delivered this SEND as a RECV," skipping L3
    /// entirely. Always resolves the admission outcome `Accepted`.
    /// Takes `dst` by value (a cloned [`L4SessionHandle`]) rather than
    /// borrowing it for the pump task's whole lifetime.
    fn pump(
        mut rx: mpsc::Receiver<OutboundSend>,
        dst: L4SessionHandle,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                let frame = menzil_proto::E2eFrame::decode(&req.payload)
                    .expect("this crate's own encoding");
                if let menzil_proto::E2eFrame::Data {
                    counter,
                    ciphertext,
                    ..
                } = frame
                {
                    dst.feed_inbound(counter, ciphertext);
                }
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        })
    }

    fn two_sessions_with_max_record(max_record: u32) -> TwoSessions {
        let (a_priv, _a_pub) = fresh_keypair();
        let (b_priv, b_pub) = fresh_keypair();
        let network_id = NetworkId::from([1u8; 32]);
        let a_node = NodeId::from([0x11; 32]);
        let b_node = NodeId::from([0x21; 32]);

        let (a_hs, init) =
            E2eInitiatorHandshake::start(&a_priv, &b_pub, network_id, a_node, b_node, 1).unwrap();
        let b_hs = E2eResponderHandshake::start(&b_priv, a_node, b_node, &init).unwrap();
        let (b_transport, resp) = b_hs
            .finish(sample_cert(b_node), 0, 0, vec![], 2, max_record)
            .unwrap();
        let (a_transport, _payload, _b_static) = a_hs.finish(&resp, max_record).unwrap();

        let (a_handle, a_acceptor, a_outbound_rx, a_epoch_ended_tx, task_a) =
            one_session(a_transport, b_node, network_id, Mode::Client, max_record);
        let (b_handle, b_acceptor, b_outbound_rx, b_epoch_ended_tx, task_b) =
            one_session(b_transport, a_node, network_id, Mode::Server, max_record);

        let pump_a_to_b = pump(a_outbound_rx, b_handle.clone());
        let pump_b_to_a = pump(b_outbound_rx, a_handle.clone());

        TwoSessions {
            a: a_handle,
            a_acceptor,
            b: b_acceptor,
            b_handle,
            _pump_a_to_b: pump_a_to_b,
            _pump_b_to_a: pump_b_to_a,
            _task_a: task_a,
            _task_b: task_b,
            _a_epoch_ended_tx: a_epoch_ended_tx,
            _b_epoch_ended_tx: b_epoch_ended_tx,
        }
    }

    fn two_sessions() -> TwoSessions {
        two_sessions_with_max_record(65_535)
    }

    /// Reads one `u16 len | CBOR` OPEN_ACK header directly off `stream` —
    /// the same shape `menzil_stream::open`'s own private
    /// `read_len_prefixed` reads, duplicated here (that helper is not
    /// exported) for tests that bypass [`open`] to send a hand-built
    /// OPEN.
    async fn read_ack(stream: &mut Stream) -> menzil_proto::OpenAckBody {
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let len = u16::from_be_bytes(prefix) as usize;
        let mut buf = prefix.to_vec();
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.unwrap();
        buf.extend_from_slice(&body);
        menzil_proto::OpenAckBody::decode(&buf).unwrap()
    }

    /// An [`Authorizer`] that allows everything — [`accept_loop`]'s own
    /// admission control, not grant evaluation, is what most of these
    /// tests exercise.
    struct AllowAll;
    impl Authorizer for AllowAll {
        fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
            OpenDecision::Allow
        }
    }

    /// A [`ServiceHandler`] that accepts everything and counts how many
    /// streams it actually ran, so a test can tell "accepted" apart from
    /// "shed" or "refused" by the final count rather than by racing
    /// individual stream outcomes.
    #[derive(Clone, Default)]
    struct CountingHandler {
        accepted: Arc<AtomicUsize>,
    }

    impl ServiceHandler<Stream> for CountingHandler {
        type Handling = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

        fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
            Ok(())
        }

        fn handle(&self, mut stream: Stream, _request: OpenRequest) -> Self::Handling {
            let accepted = Arc::clone(&self.accepted);
            Box::pin(async move {
                let mut buf = [0u8; 1];
                let _ = stream.read_exact(&mut buf).await;
                accepted.fetch_add(1, Ordering::SeqCst);
            })
        }
    }

    /// A [`ServiceHandler`] that always refuses — the "refuse-all until
    /// L4i" stub TODO.md's own L4h4 line names, kept test-only here: the
    /// right wire [`ErrorCode`] for a production "nothing is configured"
    /// stub is not named by protocol.md's own registry, and picking one
    /// for real use is not this item's call to make silently.
    struct RefuseAll;
    impl ServiceHandler<Stream> for RefuseAll {
        type Handling = std::future::Ready<()>;

        fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
            Err(OpenRefusal {
                code: ErrorCode::Unknown(0),
                msg: "test stub refuses everything".to_string(),
            })
        }

        fn handle(&self, _stream: Stream, _request: OpenRequest) -> Self::Handling {
            unreachable!("accepts always refuses, so handle is never called")
        }
    }

    /// An [`Authorizer`] *and* [`ServiceHandler`] that both assert `meta`
    /// has already been scrubbed to its default before they see a
    /// request — combined into one type so one test exercises both
    /// gates, after a 2026-10-06 red-team review found the previous
    /// version of this test asserted only the `Authorizer` side, leaving
    /// the identical scrub on the `ServiceHandler` side unverified.
    struct MetaAssertingGate;
    impl Authorizer for MetaAssertingGate {
        fn authorize(&self, request: &OpenRequest) -> OpenDecision {
            assert_eq!(
                request.meta,
                OpenMeta::default(),
                "accept_loop must scrub a member-sent meta before the Authorizer sees it"
            );
            OpenDecision::Allow
        }
    }
    impl ServiceHandler<Stream> for MetaAssertingGate {
        type Handling = std::future::Ready<()>;

        fn accepts(&self, request: &OpenRequest) -> Result<(), OpenRefusal> {
            assert_eq!(
                request.meta,
                OpenMeta::default(),
                "accept_loop must scrub a member-sent meta before ServiceHandler::accepts sees it"
            );
            Ok(())
        }

        fn handle(&self, _stream: Stream, request: OpenRequest) -> Self::Handling {
            assert_eq!(
                request.meta,
                OpenMeta::default(),
                "accept_loop must scrub a member-sent meta before ServiceHandler::handle sees it"
            );
            std::future::ready(())
        }
    }

    fn ssh() -> ServiceId {
        ServiceId::new(ServiceKind::Tcp, "ssh")
    }

    fn open_header(service: ServiceId) -> Vec<u8> {
        OpenBody {
            v: menzil_proto::PROTOCOL_VERSION,
            service,
            target: None,
            meta: OpenMeta::default(),
        }
        .encode()
        .unwrap()
    }

    #[tokio::test]
    async fn open_against_an_accepting_handler_returns_a_usable_stream() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let handler = CountingHandler::default();
        let accepted = Arc::clone(&handler.accepted);
        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b, AllowAll, handler).await;
        });

        let mut stream = tokio::time::timeout(Duration::from_secs(5), open(&a, ssh(), None))
            .await
            .expect("open did not time out")
            .expect("open was not refused");
        stream.write_all(b"x").await.unwrap();
        stream.flush().await.unwrap();

        for _ in 0..200 {
            if accepted.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        accept_task.abort();
    }

    #[tokio::test]
    async fn open_against_a_refusing_handler_is_refused() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b, AllowAll, RefuseAll).await;
        });

        let result = tokio::time::timeout(Duration::from_secs(5), open(&a, ssh(), None))
            .await
            .expect("open did not time out");
        match result {
            Err(OpenStreamError::Refused { code, .. }) => {
                assert_eq!(code, ErrorCode::Unknown(0));
            }
            other => panic!("expected a Refused error, got {other:?}"),
        }
        accept_task.abort();
    }

    #[tokio::test]
    async fn open_rejects_a_target_for_a_non_egress_service_locally() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            b: _b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let target = Some(OpenTarget {
            host: "example.com".to_string(),
            port: 443,
        });
        let result = open(&a, ssh(), target).await;
        assert!(
            matches!(result, Err(OpenStreamError::InvalidTarget)),
            "expected a local InvalidTarget error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_refused_opens_message_is_sanitized_before_display() {
        struct ControlCharRefusal;
        impl ServiceHandler<Stream> for ControlCharRefusal {
            type Handling = std::future::Ready<()>;

            fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
                Err(OpenRefusal {
                    code: ErrorCode::Unknown(0),
                    msg: "line one\u{1b}[31mred\u{1b}[0m\nline two".to_string(),
                })
            }

            fn handle(&self, _stream: Stream, _request: OpenRequest) -> Self::Handling {
                unreachable!("accepts always refuses, so handle is never called")
            }
        }

        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b, AllowAll, ControlCharRefusal).await;
        });

        let result = tokio::time::timeout(Duration::from_secs(5), open(&a, ssh(), None))
            .await
            .expect("open did not time out");
        let Err(err) = result else {
            panic!("expected a Refused error, got {result:?}")
        };
        let rendered = err.to_string();
        assert!(
            !rendered.contains('\u{1b}') && !rendered.contains('\n'),
            "a peer-controlled control character or newline must not reach Display: {rendered:?}"
        );
        accept_task.abort();
    }

    #[tokio::test]
    async fn a_refused_opens_message_strips_bidi_and_zero_width_characters() {
        struct BidiRefusal;
        impl ServiceHandler<Stream> for BidiRefusal {
            type Handling = std::future::Ready<()>;

            fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
                Err(OpenRefusal {
                    code: ErrorCode::Unknown(0),
                    // A bidi override followed by a zero-width space —
                    // round 2 confirmed both pass through a filter that
                    // only strips `char::is_control()`.
                    msg: "safe\u{202e}evil\u{200b}text".to_string(),
                })
            }

            fn handle(&self, _stream: Stream, _request: OpenRequest) -> Self::Handling {
                unreachable!("accepts always refuses, so handle is never called")
            }
        }

        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b, AllowAll, BidiRefusal).await;
        });

        let result = tokio::time::timeout(Duration::from_secs(5), open(&a, ssh(), None))
            .await
            .expect("open did not time out");
        let Err(err) = result else {
            panic!("expected a Refused error, got {result:?}")
        };
        let rendered = err.to_string();
        assert!(
            !rendered.contains('\u{202e}') && !rendered.contains('\u{200b}'),
            "a peer-controlled bidi override or zero-width character must not reach Display: \
             {rendered:?}"
        );
        accept_task.abort();
    }

    #[tokio::test]
    async fn a_malformed_ack_surfaces_as_exchange_not_refused() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let responder = tokio::spawn(async move {
            let mut stream = b.accept().await.unwrap();
            let header = read_ack_header_len(&mut stream).await;
            let mut discard = vec![0u8; header];
            stream.read_exact(&mut discard).await.unwrap();
            // A well-formed length prefix (1 byte of body) whose body is
            // not a valid `OpenAckBody` CBOR map at all — `0xff` alone
            // decodes as nothing this type's `Deserialize` can use.
            stream.write_all(&[0x00, 0x01, 0xff]).await.unwrap();
            stream.flush().await.unwrap();
        });

        let result = tokio::time::timeout(Duration::from_secs(5), open(&a, ssh(), None))
            .await
            .expect("open did not time out");
        assert!(
            matches!(result, Err(OpenStreamError::Exchange(_))),
            "a malformed ack must surface as Exchange, not Refused or Timeout: {result:?}"
        );
        responder.await.unwrap();
    }

    /// Reads just the `u16` length prefix of one `u16 len | CBOR` header
    /// and returns the body length it declares, leaving the body itself
    /// unread — a smaller duplicate of [`read_ack`] for a test that
    /// wants to discard the body rather than decode it.
    async fn read_ack_header_len(stream: &mut Stream) -> usize {
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        u16::from_be_bytes(prefix) as usize
    }

    #[tokio::test]
    async fn accept_loop_scrubs_member_sent_meta_before_either_gate_sees_it() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b, MetaAssertingGate, MetaAssertingGate).await;
        });

        let mut stream = a.open_stream().await.unwrap();
        let crafted = OpenBody {
            v: menzil_proto::PROTOCOL_VERSION,
            service: ssh(),
            target: None,
            meta: OpenMeta {
                client_ip: Some("203.0.113.9".to_string()),
                sni: Some("evil.example".to_string()),
            },
        };
        stream.write_all(&crafted.encode().unwrap()).await.unwrap();
        stream.flush().await.unwrap();

        let ack = tokio::time::timeout(Duration::from_secs(5), read_ack(&mut stream))
            .await
            .expect("no OPEN_ACK arrived");
        // If `MetaAssertingGate::authorize`/`accepts`/`handle` had seen
        // the crafted, non-default `meta` above, it would have panicked
        // inside the spawned `accept_task` instead of ever reaching this
        // ack.
        assert!(ack.ok);
        accept_task.abort();
    }

    #[tokio::test]
    async fn excess_inbound_opens_are_shed_not_parked() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b, AllowAll, CountingHandler::default()).await;
        });

        // Fills every admission slot with a stream `respond_to_open` can
        // never finish reading a header from: one byte is enough for
        // yamux to notify the peer a stream exists at all (confirmed by
        // `l4_session`'s own `open_stream_on_one_side_is_accepted_on_the_
        // other` test, which relies on the identical fact), but leaves
        // `read_len_prefixed`'s first `read_exact` of 2 bytes permanently
        // short by one, so the responding task parks on it (holding its
        // admission permit) for this whole test.
        let mut probes = Vec::new();
        for _ in 0..MAX_CONCURRENT_OPENS {
            let mut stream = a.open_stream().await.unwrap();
            stream.write_all(&[0u8]).await.unwrap();
            stream.flush().await.unwrap();
            probes.push(stream);
        }

        // Every admission slot is now held. One more, fully-formed OPEN
        // must be shed outright — denied even the chance to be read —
        // which this side observes as a fast failure, not a 10s wait
        // for `open`'s own timeout: a shed stream is dropped by
        // `accept_loop` without ever being FIN'd, so yamux sends an RST
        // this side's read surfaces as an error almost immediately (see
        // this module's own doc comment for why shedding is a bare drop
        // rather than an explicit refusal).
        match tokio::time::timeout(Duration::from_secs(2), open(&a, ssh(), None)).await {
            Ok(Err(OpenStreamError::Timeout(_))) => {
                panic!("a shed stream should fail fast via RST, not via open's own 10s timeout")
            }
            Ok(Err(_)) => {} // expected: the RST surfaces as an I/O error on the exchange
            Ok(Ok(_)) => panic!("expected the stream beyond the admission bound to be shed"),
            Err(_) => panic!("a shed stream should fail well within 2s, not hang"),
        }

        drop(probes);
        accept_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "slow (about 5s of fixed waiting) end-to-end probe of a hostile OPEN burst; \
                the tests that fail without `menzil-stream`'s pause-on-full outbound channel \
                are in that crate's tests/backpressure.rs"]
    async fn a_hostile_unpaced_open_burst_does_not_end_the_session() {
        // A 2026-10-06 red-team review found that `open()`-paced bursts
        // (this test's own predecessor) cannot actually exercise this
        // bound's worst case at all: yamux's own initiator-side pacing
        // (at most 256 unacknowledged SYNs in flight) and this actor's
        // own one-record-per-`select!`-iteration processing mean the
        // responder never sees more than a small fraction of a burst at
        // once, however large. This version bypasses that pacing
        // entirely — encrypting raw yamux SYN frames with `a`'s own
        // transport and handing them straight to `b`'s inbound feed,
        // bypassing `L4SessionHandle::open_stream`.
        //
        // **What this test is, and is not, evidence of**: it was written
        // as the live reproduction of TODO.md's L4h3/L4h5 structural gap
        // (a single `Driver` poll emitting more outbound frames than
        // `menzil-stream`'s channel held, which then ended the session).
        // That gap is closed in `menzil-stream` (the channel now pauses
        // `yamux` instead of failing), and this test passes reliably (10
        // of 10 runs at the time) — but it never reliably *failed*
        // against this module's reverted 32-slot shape either (a
        // round-2 review measured 30/30 survivals before the fix), so it
        // is not proof that the fix works; `menzil-stream`'s
        // `tests/backpressure.rs` is, each of its tests having been
        // confirmed to fail against the pre-fix code. Kept as a real,
        // working harness for a hostile burst at the whole-session
        // level, and `#[ignore]`d only because it spends about five
        // seconds waiting (asserting the session is *still* alive after
        // them cannot be made faster).
        //
        // Deliberately not `two_sessions()`: this test needs `a`'s own
        // raw `E2eTransport` left unconsumed (to encrypt hostile frames
        // with directly) while `b`'s matching transport runs inside a
        // real session actor — `two_sessions()` feeds both transports
        // into real sessions and keeps neither raw, so it cannot supply
        // this shape. The two sides must still be one real handshake
        // pair: feeding frames encrypted with an *unrelated* transport
        // into `b`'s actor would simply fail to authenticate and be
        // silently dropped (see `l4_session::run`'s own pre-
        // authentication-failure arm), making this test pass for the
        // wrong reason — nothing would ever actually reach `b`'s
        // `Inbound` queue at all.
        let (a_priv, _a_pub) = fresh_keypair();
        let (b_priv, b_pub) = fresh_keypair();
        let network_id = NetworkId::from([3u8; 32]);
        let a_node = NodeId::from([0x13; 32]);
        let b_node = NodeId::from([0x23; 32]);
        let (a_hs, init) =
            E2eInitiatorHandshake::start(&a_priv, &b_pub, network_id, a_node, b_node, 1).unwrap();
        let b_hs = E2eResponderHandshake::start(&b_priv, a_node, b_node, &init).unwrap();
        let (b_transport, resp) = b_hs
            .finish(sample_cert(b_node), 0, 0, vec![], 2, 65_535)
            .unwrap();
        let (mut a_transport, _payload, _b_static) = a_hs.finish(&resp, 65_535).unwrap();

        let (b_handle, mut b_acceptor, mut b_outbound_rx, _b_epoch_ended_tx, _task_b) =
            one_session(b_transport, a_node, network_id, Mode::Server, 65_535);
        // Drains `b`'s own outbound sends (yamux's own initial frame,
        // every OPEN_ACK this burst provokes, any REKEY/KEEP) so none of
        // it ever blocks on `l4_session`'s own send-outcome timeout and
        // ends the session for a reason unrelated to this test.
        let _drain = tokio::spawn(async move {
            while let Some(req) = b_outbound_rx.recv().await {
                let _ = req.outcome.send(EnqueueOutcome::Accepted);
            }
        });

        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b_acceptor, AllowAll, RefuseAll).await;
            b_acceptor.closed().await
        });

        let header = open_header(ssh());
        const BURST: usize = 1000;
        for i in 0..BURST {
            let stream_id = 1 + 2 * i as u32;
            let mut raw = vec![0u8, 0u8]; // yamux Data frame, version 0
            raw.extend_from_slice(&1u16.to_be_bytes()); // flags: SYN
            raw.extend_from_slice(&stream_id.to_be_bytes());
            raw.extend_from_slice(&(header.len() as u32).to_be_bytes());
            raw.extend_from_slice(&header);
            let frame = a_transport
                .encrypt_data(&menzil_proto::E2eDataBody::Mux(raw))
                .unwrap();
            let menzil_proto::E2eFrame::Data {
                counter,
                ciphertext,
                ..
            } = frame
            else {
                unreachable!("encrypt_data always produces a Data frame for Mux")
            };
            // Bypasses `L4SessionHandle::open_stream`'s own yamux
            // pacing entirely — the point of this test.
            b_handle.feed_inbound(counter, ciphertext);
        }

        match tokio::time::timeout(Duration::from_secs(5), accept_task).await {
            Err(_still_running) => {}
            Ok(Ok(reason)) => panic!(
                "b's session ended under a hostile {BURST}-SYN burst, every one carrying a \
                 real OPEN header and refused outright by the handler — exactly what the \
                 admission bound exists to prevent. reason={reason:?}"
            ),
            Ok(Err(join_err)) => panic!("accept_loop task panicked: {join_err}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn responder_open_timeout_frees_its_admission_slot() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            mut b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        let accept_task = tokio::spawn(async move {
            accept_loop(&mut b, AllowAll, CountingHandler::default()).await;
        });

        let mut probes = Vec::new();
        for _ in 0..MAX_CONCURRENT_OPENS {
            let mut stream = a.open_stream().await.unwrap();
            stream.write_all(&[0u8]).await.unwrap();
            stream.flush().await.unwrap();
            probes.push(stream);
        }

        // Hardcoded, not derived from `OPEN_TIMEOUT`: this test exists to
        // catch a regression that silently changes that constant's own
        // value, so its own deadline cannot be defined in terms of it.
        tokio::time::sleep(Duration::from_secs(11)).await;

        let fresh = tokio::time::timeout(Duration::from_secs(5), open(&a, ssh(), None))
            .await
            .expect(
                "a fresh open must not hang once every slot has been freed by the \
                 responder's own OPEN timeout",
            );
        assert!(
            fresh.is_ok(),
            "expected a freed admission slot after the responder's own OPEN timeout fired: \
             {fresh:?}"
        );

        drop(probes);
        accept_task.abort();
    }

    #[tokio::test(start_paused = true)]
    async fn open_times_out_when_the_peer_never_acks() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            b: _b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        // `_b`'s own `accept_loop` is deliberately never started, so
        // nothing ever reads the OPEN header this call writes, let alone
        // acks it.
        let open_task = tokio::spawn(async move { open(&a, ssh(), None).await });

        // Hardcoded for the same reason as this module's own responder-
        // side timeout test above.
        tokio::time::sleep(Duration::from_secs(11)).await;

        let result = tokio::time::timeout(Duration::from_secs(5), open_task)
            .await
            .expect("must not hang")
            .unwrap();
        assert!(
            matches!(result, Err(OpenStreamError::Timeout(_))),
            "expected a Timeout once the peer never acks within the initiator's own bound, \
             got {result:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn open_s_timeout_covers_the_raw_stream_open_too() {
        let TwoSessions {
            a,
            a_acceptor: _a_acceptor,
            b: _b,
            b_handle: _b_handle,
            _pump_a_to_b,
            _pump_b_to_a,
            _task_a,
            _task_b,
            _a_epoch_ended_tx,
            _b_epoch_ended_tx,
        } = two_sessions();
        // Holds every slot of yamux's own unacknowledged-outbound
        // backlog (`_b`'s own `accept_loop` is deliberately never
        // started, so nothing ever acks any of these) — a round-2
        // red-team review confirmed live that a 257th raw
        // `open_stream()` call then waits on that backlog itself, not
        // on anything `open()`'s own `OPEN_TIMEOUT` was, at the time,
        // even watching.
        const BACKLOG: usize = 256;
        let mut held = Vec::with_capacity(BACKLOG);
        for _ in 0..BACKLOG {
            held.push(a.open_stream().await.unwrap());
        }

        let open_task = tokio::spawn(async move { open(&a, ssh(), None).await });

        // Hardcoded for the same reason as this module's own other two
        // timeout tests above.
        tokio::time::sleep(Duration::from_secs(11)).await;

        let result = tokio::time::timeout(Duration::from_secs(5), open_task)
            .await
            .expect("must not hang")
            .unwrap();
        assert!(
            matches!(result, Err(OpenStreamError::Timeout(_))),
            "expected a Timeout once the raw stream open itself cannot complete within \
             open()'s own bound, got {result:?}"
        );
        drop(held);
    }
}
