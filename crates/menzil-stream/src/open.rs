//! The L5 OPEN/OPEN_ACK exchange (protocol.md 5.3) run directly on an
//! already-open stream, plus the `Authorizer`/`ServiceHandler` interface
//! a caller plugs grant evaluation and local-target dispatch into
//! (TODO.md L4g). Concrete implementations of both traits — grant
//! evaluation against `menzil_node::PolicyStore` (TODO.md L4c), and
//! dispatch to a configured `tcp:`/`http:`/`tls:` target (TODO.md L4i) —
//! are deliberately not this module's job; this crate exposes only the
//! contract, exactly what decision 0001 asks for ("the L5 OPEN and
//! OPEN_ACK headers and the service model are defined independently of
//! the mux so that the QUIC change stays below them").
//!
//! **Generic over any `S: AsyncRead + AsyncWrite + Unpin`, not tied to
//! [`crate::Stream`] specifically**: the functions here never name
//! `yamux` or any other mux. A future QUIC-based L4 (decision 0001's
//! `e2e_proto 0x02`) reuses this layer unchanged by supplying its own
//! stream type. That genericity is also why every header written here is
//! explicitly flushed (and a refused stream explicitly closed) rather
//! than trusting `write_all` alone: `AsyncWrite` only promises delivery
//! after a flush, and an `S` that buffers (`futures::io::BufWriter`, say)
//! otherwise loses a refusal or deadlocks an exchange outright — both
//! confirmed live by a 2026-10-02 red team review, on `yamux::Stream`
//! wrapped in exactly that `BufWriter`.
//!
//! **No timeout of its own**: protocol.md 5.3's "OPEN times out after 10
//! seconds" is left to the caller to enforce (e.g. wrapping
//! [`initiate_open`]/[`respond_to_open`] in `tokio::time::timeout`), the
//! same way every other time-sensitive rule in this crate's sibling
//! crates (rekey intervals, idle liveness) is a value the caller checks
//! against its own clock rather than something driven by an internal
//! sleep — consistent with this crate staying `futures`-native rather
//! than tied to one executor's timer (see [`crate`]'s own doc comment).
//! See [`respond_to_open`]'s own doc comment for what, concretely, a
//! caller that forgets this exposes itself to.
//!
//! **Why `ServiceHandler` is split into [`ServiceHandler::accepts`] and
//! [`ServiceHandler::handle`] rather than one fallible call**: OPEN_ACK
//! must go out on `stream` itself regardless of the outcome, so whatever
//! decides "would this actually work" must run *before* `stream`'s
//! ownership ever passes to the handler — once [`ServiceHandler::handle`]
//! takes it, this module has no way to get it back to send a refusal
//! on. `accepts` is therefore a cheap, synchronous, pre-ack check (e.g.
//! "is a local target even configured for this service") against
//! `&OpenRequest` alone; `handle` only ever runs after OPEN_ACK `ok:
//! true` has actually been written, takes `stream` by value, and is
//! fire-and-forget from this module's perspective — a later failure
//! inside it (a local dial refused, say) is that implementation's own
//! problem to turn into a stream reset, not something OPEN_ACK can still
//! speak to by then.
//!
//! **What that split cannot express, found by the same 2026-10-02 review
//! building a realistic tokio-based handler against it** (a config-map
//! lookup in `accepts`, a real `TcpStream` dial plus
//! `copy_bidirectional` in `handle`, the whole thing spawned on a
//! multi-thread runtime — it binds and runs without friction for phase
//! 1's `tcp:`/`http:`/`tls:` dispatch): `ok: true` always precedes any
//! dial, so a configured-but-dead local target reads back to the
//! initiator as an accepted stream that immediately ends, never as a
//! refusal (protocol.md 5.3's "on `ok` the stream is a byte pipe to the
//! configured local target" reads at least as naturally as "the dial
//! already succeeded"); nothing `accepts` decides can be handed to
//! `handle` (a second lookup, racing any config reload in between, and no
//! way to release something `accepts` reserved if the ack write then
//! fails); and neither gate can put a `channel` into OPEN_ACK (protocol.md
//! 5.4) or run section 8's resolve-once-then-vet egress rules, which need
//! async DNS, before the ack. Nothing before phase 2's datagram channels
//! and egress strictly needs more — TODO.md tracks deciding the shape
//! before either builds on this one.

use std::future::Future;

use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use menzil_proto::{
    ErrorCode, NetworkId, NodeId, OpenAckBody, OpenBody, OpenMeta, OpenTarget, ProtoError,
    ServiceId, ServiceKind,
};

/// The longest [`OpenRefusal::msg`] [`respond_to_open`] ever puts on the
/// wire, in bytes, cut at a UTF-8 boundary and marked with a trailing
/// ellipsis. An implementation that echoes peer-chosen text into its
/// refusal (the service label it found no grant for, say) could otherwise
/// push OPEN_ACK past its own `u16` length prefix — confirmed live by a
/// 2026-10-02 red team review: a ~65 KB label and an echoing `Authorizer`
/// made `respond_to_open` send no OPEN_ACK at all and fail instead,
/// breaking its own "exactly one OPEN_ACK either way" contract. The same
/// failure mode, and the same fix, as `menzil-relay`'s own
/// `MAX_ECHOED_NAME_BYTES` for ADVERTISE_ACK. Generous for any real
/// human-readable reason, and small enough that a refusal also stays one
/// yamux frame at yamux's own default 16 KiB split size, rather than
/// several.
const MAX_REFUSAL_MSG_BYTES: usize = 1024;

/// Errors from driving one OPEN/OPEN_ACK exchange over a stream.
/// Deliberately has nothing to say about *authorization* outcomes — an
/// `Authorizer`/`ServiceHandler` refusal is a successful exchange with a
/// negative answer, not a failure of this type (see [`Responded`] and
/// [`initiate_open`]'s return value).
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// Reading or writing the stream itself failed — including the peer
    /// ending the stream partway through a header (`UnexpectedEof`).
    #[error("i/o error on the stream: {0}")]
    Io(#[source] std::io::Error),
    /// The peer's header did not decode as a well-formed OPEN/OPEN_ACK.
    #[error("malformed open header: {0}")]
    Malformed(#[source] ProtoError),
    /// This side's *own* header could not be encoded — in practice an
    /// [`OpenBody`] whose fields (a target host name, say) are too long
    /// for its `u16` length prefix. A local error, not the peer's, and
    /// nothing was written to the stream; kept apart from
    /// [`Self::Malformed`], which a caller may reasonably treat as peer
    /// misbehavior, after a 2026-10-02 red team review found exactly this
    /// case reported as `Malformed`.
    #[error("could not encode this side's own open header: {0}")]
    Encode(#[source] ProtoError),
}

/// Everything the responder side of an OPEN needs to decide whether to
/// accept it: the header's own fields, plus the session identity context
/// this crate has no way to know on its own (protocol.md 5.3's grant
/// check is "for `(network, initiator)` on `(this node, service)`" —
/// which node is "this node" is for whichever [`Authorizer`]/
/// [`ServiceHandler`] is plugged in to already know, not a field here;
/// `network_id`/`initiator` are the caller's session state, in practice
/// `menzil-node`'s L4 session wiring, TODO.md L4h).
///
/// `service`, `target`, and `meta` are peer-chosen and otherwise
/// unvalidated beyond their wire types: a label or host name can be tens
/// of kilobytes long and carry control characters (confirmed live by a
/// 2026-10-02 red team review — a NUL and a newline inside a label both
/// reach the gates), so log or echo them with that in mind.
#[derive(Debug, Clone)]
pub struct OpenRequest {
    /// The network this L4 session is on.
    pub network_id: NetworkId,
    /// The peer that sent this OPEN.
    pub initiator: NodeId,
    /// The service it named.
    pub service: ServiceId,
    /// Present only when `service` is the literal `egress:*` (protocol.md
    /// 5.3) — not any `egress`-kind service: [`respond_to_open`] itself
    /// rejects every other combination with [`ErrorCode::InvalidTarget`]
    /// before either gate runs, rather than leaving every
    /// [`Authorizer`]/[`ServiceHandler`] to each remember this rule on its
    /// own.
    pub target: Option<OpenTarget>,
    /// Relay-principal-only metadata (see [`OpenMeta`]'s own doc
    /// comment), passed through verbatim: whether `initiator` actually
    /// *is* the relay principal, and so whether this is trustworthy, is
    /// session context only the caller has, not something this crate can
    /// check on its own. Nothing strips a member-sent `meta` before
    /// either gate sees it — see TODO.md.
    pub meta: OpenMeta,
}

/// Why an OPEN was refused — the peer-visible reason an OPEN_ACK with
/// `ok: false` carries, shared by both gates ([`Authorizer`] denying a
/// grant, or [`ServiceHandler::accepts`] declining an otherwise-
/// authorized request).
///
/// **Both fields reach the peer** (`msg` capped at 1,024 bytes, see
/// below), so choose them with the care `menzil_node::PolicyStore::
/// check_membership`'s own doc comment asks of its error codes: a refusal
/// that tells fine-grained internal reasons apart for a peer without real
/// standing recreates the oracle `menzil-relay/src/forward.rs`'s finding
/// M2 closed off. Keep that detail in local logs instead — the caller
/// still gets the full, untruncated value back through
/// [`Responded::Refused`].
#[derive(Debug, Clone)]
pub struct OpenRefusal {
    /// A reason code, reusing the shared L3/L4 [`ErrorCode`] registry
    /// rather than inventing a parallel one — the same call
    /// `OpenAckBody::code` and `menzil_node::PolicyStore` already make.
    pub code: ErrorCode,
    /// A human-readable detail. [`respond_to_open`] sends at most its
    /// first 1,024 bytes (cut at a UTF-8 boundary, marked with an
    /// ellipsis) — see that function's own doc comment.
    pub msg: String,
}

/// Whether an OPEN is authorized, from [`Authorizer::authorize`].
#[derive(Debug, Clone)]
pub enum OpenDecision {
    /// The grant check passed; [`ServiceHandler::accepts`] gets the next
    /// say.
    Allow,
    /// No grant covers this request.
    Deny(OpenRefusal),
}

/// Decides whether an OPEN is authorized. Implemented by the caller
/// (`menzil-node`, TODO.md L4h) against its own `menzil_node::PolicyStore`
/// (TODO.md L4c) and roster store; this crate defines only the contract.
///
/// Pure and synchronous, mirroring `menzil_node::PolicyStore::has_grant`'s
/// own shape directly — a Policy/Roster grant check is already in
/// memory and needs no I/O. **Must not block**: [`respond_to_open`]
/// calls this inline, from inside its own future, so in every realistic
/// caller it runs on an async executor's worker thread. (This doc comment
/// previously suggested an implementation needing to await something
/// could block on its own runtime handle instead; a 2026-10-02 red team
/// review confirmed live that `tokio::runtime::Handle::block_on` there
/// panics — "Cannot start a runtime from within a runtime" — and that
/// `futures::executor::block_on` on a current-thread runtime hangs
/// forever.) Anything that genuinely needs I/O belongs before
/// [`respond_to_open`] is ever called — state kept fresh in memory by a
/// separate task, say — not inside this method.
pub trait Authorizer {
    /// Decides `request`.
    fn authorize(&self, request: &OpenRequest) -> OpenDecision;
}

/// Takes over an OPEN that both gates have already approved, and does
/// whatever `request.service` means — dispatching to a configured local
/// `tcp:`/`http:`/`tls:` target (TODO.md L4i) is the only implementation
/// this project ships, but nothing here assumes that.
///
/// See this module's own doc comment for why this is split from
/// [`Self::accepts`] the way it is, and what that split cannot express.
pub trait ServiceHandler<S> {
    /// The future [`Self::handle`] hands back, actually running `stream`
    /// to completion. `Send + 'static` because the only realistic caller
    /// (`menzil-node`, already tokio-based) needs to spawn it; this
    /// trait does not spawn it itself, matching the rest of this crate
    /// (nothing here ever calls `tokio::spawn`) — the caller of
    /// [`respond_to_open`] does that with the [`Responded::Accepted`]
    /// value it gets back. Stable Rust cannot name an `async` block's
    /// type here, so a real implementation will in practice box it
    /// (`Pin<Box<dyn Future<Output = ()> + Send>>`).
    type Handling: Future<Output = ()> + Send + 'static;

    /// Cheap, synchronous, pre-OPEN_ACK check: would this handler even
    /// take `request` at all (e.g. is a local target actually configured
    /// for its service)? Only ever called once `request.target` has
    /// already passed protocol.md 5.3's own structural rule and an
    /// [`Authorizer`] has already allowed `request` — neither an invalid
    /// target nor a grant denial ever reaches this method, mirroring
    /// protocol.md 5.3's own ordering ("the target node evaluates the
    /// grant ... On `ok` the stream is a byte pipe to ..."). That ordering
    /// is also what keeps a peer from probing which services this node
    /// has configured beyond the ones it is actually granted. Must not
    /// touch the stream, and must not block (the same constraint, for the
    /// same reason, as [`Authorizer::authorize`]): see this module's own
    /// doc comment for why `respond_to_open` still needs the stream
    /// available to send OPEN_ACK regardless of the answer.
    fn accepts(&self, request: &OpenRequest) -> Result<(), OpenRefusal>;

    /// Takes ownership of `stream`, whose OPEN_ACK `ok: true` has already
    /// been written and flushed for this exact `request` (the same one
    /// [`Self::accepts`] just approved). Any bytes the initiator sent
    /// right behind its OPEN header are still unread on `stream`. By the
    /// time this returns, `stream`'s fate is this handler's
    /// responsibility alone — `respond_to_open` has nothing further to do
    /// with it.
    fn handle(&self, stream: S, request: OpenRequest) -> Self::Handling;
}

/// What came of one `respond_to_open` call once its OPEN_ACK has
/// actually been written.
#[derive(Debug)]
pub enum Responded<F> {
    /// OPEN_ACK `ok: true` went out; `F` is [`ServiceHandler::handle`]'s
    /// own future, not yet run — the caller must drive it (in practice
    /// `tokio::spawn`) for the stream to do anything at all.
    Accepted(F),
    /// OPEN_ACK `ok: false` went out for this reason (its `msg` possibly
    /// truncated on the wire; this is the full value); `stream` has
    /// already been closed and dropped by [`respond_to_open`].
    Refused(OpenRefusal),
}

/// Reads one `u16 len | body` header some stream delivers, returning the
/// complete buffer (length prefix included) ready for
/// [`OpenBody::decode`]/[`OpenAckBody::decode`], which both expect that
/// full shape rather than only the CBOR part. Never reads past the end of
/// that one header: whatever the peer sent behind it stays on `stream`.
///
/// Grows its buffer only as body bytes actually arrive (`len` itself is
/// bounded by its own `u16` wire width, so at most 65,535 of them),
/// rather than sizing it from the claimed length up front: a 2026-10-02
/// red team review measured that earlier shape at ~64 KiB held per stream
/// for a peer that sent nothing but `ff ff` — ~33 MiB per connection at
/// yamux's own 512-stream cap, held for as long as nothing times the call
/// out — against ~0.8 MiB for streams that sent nothing at all.
async fn read_len_prefixed<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, OpenError> {
    let mut prefix = [0u8; 2];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(OpenError::Io)?;
    let len = u16::from_be_bytes(prefix);
    let mut buf = prefix.to_vec();
    let read = (&mut *stream)
        .take(u64::from(len))
        .read_to_end(&mut buf)
        .await
        .map_err(OpenError::Io)?;
    if read != usize::from(len) {
        return Err(OpenError::Io(std::io::ErrorKind::UnexpectedEof.into()));
    }
    Ok(buf)
}

/// [`OpenRefusal::msg`] cut to `MAX_REFUSAL_MSG_BYTES` at a valid UTF-8
/// boundary (walking backward from the byte limit, which always
/// terminates: 0 is always a boundary), marking that it was cut — the
/// same shape as `menzil-relay`'s own `truncate_for_echo`.
fn clamp_refusal_msg(msg: &str) -> String {
    if msg.len() <= MAX_REFUSAL_MSG_BYTES {
        return msg.to_string();
    }
    let mut end = MAX_REFUSAL_MSG_BYTES;
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\u{2026}", &msg[..end])
}

/// Runs the *initiator* side of one OPEN/OPEN_ACK exchange (protocol.md
/// 5.3) on a freshly opened stream: writes and flushes `open`, then reads
/// back and decodes the peer's OPEN_ACK. Returns the ack whether `ok` is
/// true or false — an explicit refusal is a successful exchange with a
/// negative answer, not an [`OpenError`]; the caller decides what to do
/// with `stream` either way (in practice, nothing further on a refusal,
/// since nothing else will ever arrive on it). On `ok: true`, any bytes
/// the responder sent right behind its OPEN_ACK are still unread on
/// `stream`.
///
/// Carries no timeout of its own — see this module's own doc comment.
/// **Not cancel-safe**: a caller's timeout (or any other cancellation)
/// firing partway through the OPEN_ACK leaves `stream` positioned in the
/// middle of that header — confirmed live by a 2026-10-02 red team
/// review, whose next read returned the ack's own CBOR tail as though it
/// were service data. After cancellation, or after any `Err` from this
/// function, `stream` must be dropped, never used further.
pub async fn initiate_open<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    open: &OpenBody,
) -> Result<OpenAckBody, OpenError> {
    let encoded = open.encode().map_err(OpenError::Encode)?;
    stream.write_all(&encoded).await.map_err(OpenError::Io)?;
    stream.flush().await.map_err(OpenError::Io)?;
    let raw = read_len_prefixed(stream).await?;
    OpenAckBody::decode(&raw).map_err(OpenError::Malformed)
}

/// Runs the *responder* side of one OPEN/OPEN_ACK exchange on a stream
/// the peer just opened (one [`crate::Inbound::accept`] result, in
/// practice): reads the OPEN header, asks `authorizer` then `handler`,
/// and sends exactly one OPEN_ACK either way before returning — see
/// [`Responded`]. An accepting OPEN_ACK is flushed before `stream` is
/// handed to [`ServiceHandler::handle`]; a refusing one is followed by
/// closing `stream` (on `yamux::Stream`, a FIN after the ack rather than
/// the RST a bare drop would send) rather than merely dropping it, so it
/// is actually delivered whatever `S` is — see this module's own doc
/// comment. A refusal's `msg` is cut to its first 1,024 bytes on the wire
/// (`MAX_REFUSAL_MSG_BYTES`).
///
/// Takes `stream` by value, unlike [`initiate_open`]'s `&mut`: once this
/// function sends an accepting OPEN_ACK, further use of `stream` is
/// entirely [`ServiceHandler::handle`]'s business, not something this
/// function or its caller still needs a handle on afterward.
///
/// Carries no timeout of its own — see this module's own doc comment. A
/// caller wanting to bound how long an opened-but-silent stream may sit
/// here waiting for its OPEN header should wrap this call in its own
/// timeout, and in practice must: nothing else bounds that wait except
/// the end of the whole connection. Confirmed live by a 2026-10-02 red
/// team review: a peer can park one of these calls per stream, forever,
/// up to yamux's own 512-streams-per-connection cap (yamux answers a
/// 513th with a GoAway but keeps this side's connection, and every parked
/// call, running) — and a stream table that full also makes this side's
/// own next [`crate::StreamMux::open`] on that connection end the whole
/// [`crate::Driver`] (`TooManyStreams`, see [`crate::Driver`]'s own doc
/// comment), taking every stream on it down.
pub async fn respond_to_open<S, A, H>(
    mut stream: S,
    network_id: NetworkId,
    initiator: NodeId,
    authorizer: &A,
    handler: &H,
) -> Result<Responded<H::Handling>, OpenError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: Authorizer,
    H: ServiceHandler<S>,
{
    let raw = read_len_prefixed(&mut stream).await?;
    let open = OpenBody::decode(&raw).map_err(OpenError::Malformed)?;
    let request = OpenRequest {
        network_id,
        initiator,
        service: open.service,
        target: open.target,
        meta: open.meta,
    };

    // protocol.md 5.3: "`target` must be null unless `service` is
    // `egress:*`." menzil-proto's own `OpenBody` doc comment leaves this
    // check to this module rather than enforcing it itself; checked here,
    // ahead of both gates, so no `Authorizer`/`ServiceHandler` has to
    // remember it on its own. `egress:*` is the literal `ServiceId`
    // (protocol.md 2.4 lists it as one, and it is the only `egress`
    // service the spec ever names), not "any `egress`-kind service" — an
    // earlier draft compared `kind` alone, letting `egress:<anything>`
    // through with a target, confirmed live by a 2026-10-02 red team
    // review; and since a Policy grant's `egress:*` *pattern* matches
    // every `egress` label (`ServiceId::matches_pattern`), nothing
    // downstream would have caught it either.
    let target_allowed =
        request.service.kind == ServiceKind::Egress && request.service.label == "*";
    let refusal = if request.target.is_some() && !target_allowed {
        Some(OpenRefusal {
            code: ErrorCode::InvalidTarget,
            msg: "target is only valid for the egress:* service (protocol.md 5.3)".to_string(),
        })
    } else {
        match authorizer.authorize(&request) {
            OpenDecision::Allow => handler.accepts(&request).err(),
            OpenDecision::Deny(refusal) => Some(refusal),
        }
    };

    let ack = match &refusal {
        None => OpenAckBody {
            ok: true,
            code: ErrorCode::Unknown(0),
            msg: String::new(),
            channel: None,
        },
        Some(r) => OpenAckBody {
            ok: false,
            code: r.code,
            msg: clamp_refusal_msg(&r.msg),
            channel: None,
        },
    };
    let encoded = ack.encode().map_err(OpenError::Encode)?;
    stream.write_all(&encoded).await.map_err(OpenError::Io)?;

    match refusal {
        None => {
            stream.flush().await.map_err(OpenError::Io)?;
            Ok(Responded::Accepted(handler.handle(stream, request)))
        }
        Some(r) => {
            stream.close().await.map_err(OpenError::Io)?;
            Ok(Responded::Refused(r))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    /// A minimal `AsyncRead + AsyncWrite` test double: reads come from a
    /// pre-loaded buffer, writes land in another — enough to exercise
    /// [`initiate_open`]/[`respond_to_open`] against hand-built byte
    /// sequences without needing a real two-way connection (the
    /// `tests/open_exchange.rs` integration test covers that instead,
    /// over real `yamux::Stream`s). Models `AsyncWrite`'s own delivery
    /// contract: only what was written before the most recent flush or
    /// close counts as `delivered`, so a test can tell "written" from
    /// "actually sent" the way a buffering stream would.
    struct MockStream {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
        delivered: usize,
        closed: bool,
    }

    impl MockStream {
        fn preloaded(bytes: Vec<u8>) -> Self {
            Self {
                to_read: std::io::Cursor::new(bytes),
                written: Vec::new(),
                delivered: 0,
                closed: false,
            }
        }

        fn delivered(&self) -> &[u8] {
            &self.written[..self.delivered]
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            Poll::Ready(std::io::Read::read(&mut this.to_read, buf))
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            this.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.delivered = this.written.len();
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let this = self.get_mut();
            this.delivered = this.written.len();
            this.closed = true;
            Poll::Ready(Ok(()))
        }
    }

    /// Lends a [`MockStream`] to [`respond_to_open`] (which takes its
    /// stream by value) while the test keeps ownership, so the test can
    /// inspect what was written, delivered, and closed afterward.
    struct Lent<'a>(&'a mut MockStream);

    impl AsyncRead for Lent<'_> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut *self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Lent<'_> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut *self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut *self.get_mut().0).poll_flush(cx)
        }
        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut *self.get_mut().0).poll_close(cx)
        }
    }

    fn sample_request() -> OpenRequest {
        OpenRequest {
            network_id: NetworkId::from([1u8; 32]),
            initiator: NodeId::from([2u8; 32]),
            service: ServiceId::new(menzil_proto::ServiceKind::Tcp, "ssh"),
            target: None,
            meta: OpenMeta::default(),
        }
    }

    fn sample_open() -> OpenBody {
        let request = sample_request();
        OpenBody {
            v: menzil_proto::PROTOCOL_VERSION,
            service: request.service,
            target: request.target,
            meta: request.meta,
        }
    }

    /// Allows everything, counting how often it was asked — so a test
    /// can pin that a rule checked "before either gate" really never
    /// reaches this one.
    #[derive(Default)]
    struct AllowAll {
        asked: Cell<usize>,
    }
    impl Authorizer for AllowAll {
        fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
            self.asked.set(self.asked.get() + 1);
            OpenDecision::Allow
        }
    }

    struct DenyAll(ErrorCode, &'static str);
    impl Authorizer for DenyAll {
        fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
            OpenDecision::Deny(OpenRefusal {
                code: self.0,
                msg: self.1.to_string(),
            })
        }
    }

    /// Answers `accepts` with a fixed result, counting how often it was
    /// asked, and hands back a future from `handle` that just records it
    /// ran, via the oneshot it closes over.
    struct RecordingHandler {
        accepts_result: Result<(), OpenRefusal>,
        accepts_asked: Cell<usize>,
        ran_tx: std::sync::Mutex<Option<futures_channel::oneshot::Sender<OpenRequest>>>,
    }

    impl RecordingHandler {
        fn allow() -> (Self, futures_channel::oneshot::Receiver<OpenRequest>) {
            let (tx, rx) = futures_channel::oneshot::channel();
            (
                Self {
                    accepts_result: Ok(()),
                    accepts_asked: Cell::new(0),
                    ran_tx: std::sync::Mutex::new(Some(tx)),
                },
                rx,
            )
        }

        fn decline(refusal: OpenRefusal) -> Self {
            Self {
                accepts_result: Err(refusal),
                accepts_asked: Cell::new(0),
                ran_tx: std::sync::Mutex::new(None),
            }
        }
    }

    impl<S> ServiceHandler<S> for RecordingHandler {
        type Handling = std::future::Ready<()>;

        fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
            self.accepts_asked.set(self.accepts_asked.get() + 1);
            self.accepts_result.clone()
        }

        fn handle(&self, _stream: S, request: OpenRequest) -> Self::Handling {
            if let Some(tx) = self.ran_tx.lock().unwrap().take() {
                let _ = tx.send(request);
            }
            std::future::ready(())
        }
    }

    #[tokio::test]
    async fn initiate_open_writes_the_header_and_decodes_an_accepting_ack() {
        let ack = OpenAckBody {
            ok: true,
            code: ErrorCode::Unknown(0),
            msg: String::new(),
            channel: None,
        };
        let mut stream = MockStream::preloaded(ack.encode().unwrap());

        let open = sample_open();
        let decoded = initiate_open(&mut stream, &open).await.unwrap();
        assert_eq!(decoded, ack);
        assert_eq!(stream.written, open.encode().unwrap());
    }

    #[tokio::test]
    async fn initiate_open_flushes_its_header_before_waiting_for_the_ack() {
        let ack = OpenAckBody {
            ok: true,
            code: ErrorCode::Unknown(0),
            msg: String::new(),
            channel: None,
        };
        let mut stream = MockStream::preloaded(ack.encode().unwrap());

        let open = sample_open();
        initiate_open(&mut stream, &open).await.unwrap();
        assert_eq!(
            stream.delivered(),
            open.encode().unwrap(),
            "an unflushed OPEN may never leave a buffering stream, deadlocking the exchange"
        );
    }

    #[tokio::test]
    async fn initiate_open_returns_a_refusal_ack_without_erroring() {
        let ack = OpenAckBody {
            ok: false,
            code: ErrorCode::NoGrant,
            msg: "no grant".to_string(),
            channel: None,
        };
        let mut stream = MockStream::preloaded(ack.encode().unwrap());

        let decoded = initiate_open(&mut stream, &sample_open()).await.unwrap();
        assert_eq!(decoded, ack);
    }

    #[tokio::test]
    async fn initiate_open_reports_a_truncated_ack_as_io_error() {
        let mut stream = MockStream::preloaded(vec![0x00, 0x05, 0x01]); // declares 5, has 1
        let err = initiate_open(&mut stream, &sample_open())
            .await
            .unwrap_err();
        assert!(matches!(err, OpenError::Io(_)));
    }

    #[tokio::test]
    async fn initiate_open_reports_an_unencodable_open_as_a_local_error_and_writes_nothing() {
        let mut open = sample_open();
        open.service = ServiceId::new(ServiceKind::Egress, "*");
        open.target = Some(OpenTarget {
            host: "a".repeat(70_000),
            port: 443,
        });
        let mut stream = MockStream::preloaded(Vec::new());

        let err = initiate_open(&mut stream, &open).await.unwrap_err();
        assert!(
            matches!(err, OpenError::Encode(_)),
            "this side's own oversized header is not the peer's malformed one: {err:?}"
        );
        assert!(stream.written.is_empty());
    }

    #[tokio::test]
    async fn respond_to_open_denies_before_ever_asking_the_handler() {
        let mut stream = MockStream::preloaded(sample_open().encode().unwrap());

        let (handler, mut ran_rx) = RecordingHandler::allow();
        let network_id = NetworkId::from([9u8; 32]);
        let initiator = NodeId::from([8u8; 32]);
        let result = respond_to_open(
            Lent(&mut stream),
            network_id,
            initiator,
            &DenyAll(ErrorCode::NoGrant, "no grant"),
            &handler,
        )
        .await
        .unwrap();

        match result {
            Responded::Refused(refusal) => {
                assert_eq!(refusal.code, ErrorCode::NoGrant);
                assert_eq!(refusal.msg, "no grant");
            }
            Responded::Accepted(_) => panic!("a denied Authorizer must never reach the handler"),
        }
        assert_eq!(
            handler.accepts_asked.get(),
            0,
            "a peer without a grant must not learn, even indirectly, what the handler would say"
        );
        assert!(
            ran_rx.try_recv().unwrap().is_none(),
            "the handler must not have run"
        );
    }

    #[tokio::test]
    async fn respond_to_open_closes_the_stream_after_delivering_a_refusal() {
        let mut stream = MockStream::preloaded(sample_open().encode().unwrap());
        let (handler, _ran_rx) = RecordingHandler::allow();

        respond_to_open(
            Lent(&mut stream),
            NetworkId::from([0u8; 32]),
            NodeId::from([0u8; 32]),
            &DenyAll(ErrorCode::NoGrant, "no grant"),
            &handler,
        )
        .await
        .unwrap();

        let ack = OpenAckBody::decode(stream.delivered())
            .expect("the refusal must be flushed out, not left in a buffer the drop discards");
        assert!(!ack.ok);
        assert!(stream.closed);
    }

    #[tokio::test]
    async fn respond_to_open_flushes_an_accepting_ack_before_handing_off_the_stream() {
        let mut stream = MockStream::preloaded(sample_open().encode().unwrap());
        let (handler, _ran_rx) = RecordingHandler::allow();

        let result = respond_to_open(
            Lent(&mut stream),
            NetworkId::from([0u8; 32]),
            NodeId::from([0u8; 32]),
            &AllowAll::default(),
            &handler,
        )
        .await
        .unwrap();
        assert!(matches!(result, Responded::Accepted(_)));
        drop(result);

        let ack = OpenAckBody::decode(stream.delivered()).expect(
            "an unflushed ok:true can deadlock a handler waiting for the client to speak first",
        );
        assert!(ack.ok);
        assert!(!stream.closed, "an accepted stream belongs to the handler");
    }

    #[tokio::test]
    async fn respond_to_open_rejects_a_non_null_target_on_a_non_egress_service_before_either_gate()
    {
        let mut open = sample_open();
        open.service = ServiceId::new(ServiceKind::Tcp, "ssh");
        open.target = Some(OpenTarget {
            host: "example.com".to_string(),
            port: 443,
        });
        let stream = MockStream::preloaded(open.encode().unwrap());

        let authorizer = AllowAll::default();
        let (handler, mut ran_rx) = RecordingHandler::allow();
        let result = respond_to_open(
            stream,
            NetworkId::from([0u8; 32]),
            NodeId::from([0u8; 32]),
            &authorizer,
            &handler,
        )
        .await
        .unwrap();

        match result {
            Responded::Refused(refusal) => assert_eq!(refusal.code, ErrorCode::InvalidTarget),
            Responded::Accepted(_) => {
                panic!("a non-null target on a non-egress service must never be Accepted")
            }
        }
        assert_eq!(
            authorizer.asked.get(),
            0,
            "the Authorizer must not be asked"
        );
        assert_eq!(handler.accepts_asked.get(), 0, "nor the handler");
        assert!(
            ran_rx.try_recv().unwrap().is_none(),
            "neither gate should have run: this is rejected before either is asked"
        );
    }

    #[tokio::test]
    async fn respond_to_open_rejects_a_target_on_any_egress_service_but_the_literal_wildcard() {
        let mut open = sample_open();
        open.service = ServiceId::new(ServiceKind::Egress, "office");
        open.target = Some(OpenTarget {
            host: "example.com".to_string(),
            port: 443,
        });
        let stream = MockStream::preloaded(open.encode().unwrap());

        let authorizer = AllowAll::default();
        let (handler, _ran_rx) = RecordingHandler::allow();
        let result = respond_to_open(
            stream,
            NetworkId::from([0u8; 32]),
            NodeId::from([0u8; 32]),
            &authorizer,
            &handler,
        )
        .await
        .unwrap();

        match result {
            Responded::Refused(refusal) => assert_eq!(refusal.code, ErrorCode::InvalidTarget),
            Responded::Accepted(_) => panic!("only `egress:*` itself may carry a target"),
        }
        assert_eq!(authorizer.asked.get(), 0);
    }

    #[tokio::test]
    async fn respond_to_open_lets_an_egress_wildcard_open_without_a_target_reach_the_gates() {
        // protocol.md 5.3 constrains only one direction ("`target` must be
        // null unless `service` is `egress:*`"); a null target on
        // `egress:*` itself is the gates' business, not a structural
        // refusal.
        let mut open = sample_open();
        open.service = ServiceId::new(ServiceKind::Egress, "*");
        open.target = None;
        let stream = MockStream::preloaded(open.encode().unwrap());

        let authorizer = AllowAll::default();
        let (handler, _ran_rx) = RecordingHandler::allow();
        let result = respond_to_open(
            stream,
            NetworkId::from([0u8; 32]),
            NodeId::from([0u8; 32]),
            &authorizer,
            &handler,
        )
        .await
        .unwrap();

        assert!(matches!(result, Responded::Accepted(_)));
        assert_eq!(authorizer.asked.get(), 1);
        assert_eq!(handler.accepts_asked.get(), 1);
    }

    #[tokio::test]
    async fn respond_to_open_lets_the_handler_decline_an_authorized_request() {
        let stream = MockStream::preloaded(sample_open().encode().unwrap());
        let handler = RecordingHandler::decline(OpenRefusal {
            code: ErrorCode::Forbidden,
            msg: "no local target configured".to_string(),
        });

        let result = respond_to_open(
            stream,
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            &AllowAll::default(),
            &handler,
        )
        .await
        .unwrap();

        match result {
            Responded::Refused(refusal) => {
                assert_eq!(refusal.code, ErrorCode::Forbidden);
                assert_eq!(refusal.msg, "no local target configured");
            }
            Responded::Accepted(_) => panic!("the handler declined; this must be a refusal"),
        }
    }

    #[tokio::test]
    async fn respond_to_open_still_sends_a_refusal_whose_msg_is_too_long_for_the_wire() {
        // A label near OPEN's own size limit, echoed into the refusal by a
        // plausible Authorizer, used to push OPEN_ACK past its u16 length
        // prefix: no ack at all went out (see `MAX_REFUSAL_MSG_BYTES`).
        struct EchoingDeny;
        impl Authorizer for EchoingDeny {
            fn authorize(&self, request: &OpenRequest) -> OpenDecision {
                OpenDecision::Deny(OpenRefusal {
                    code: ErrorCode::NoGrant,
                    msg: format!(
                        "no grant for {} (network {}, initiator {})",
                        request.service, request.network_id, request.initiator
                    ),
                })
            }
        }
        let mut open = sample_open();
        open.service = ServiceId::new(ServiceKind::Tcp, "é".repeat(32_700));
        let mut stream = MockStream::preloaded(open.encode().unwrap());
        let (handler, _ran_rx) = RecordingHandler::allow();

        let result = respond_to_open(
            Lent(&mut stream),
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            &EchoingDeny,
            &handler,
        )
        .await
        .unwrap();

        let Responded::Refused(refusal) = result else {
            panic!("a denial must be Refused");
        };
        assert!(
            refusal.msg.len() > u16::MAX as usize,
            "the caller gets the full, untruncated refusal back for its own logs"
        );
        let ack = OpenAckBody::decode(stream.delivered())
            .expect("exactly one OPEN_ACK must still go out");
        assert!(!ack.ok);
        assert_eq!(ack.code, ErrorCode::NoGrant);
        assert!(ack.msg.len() <= MAX_REFUSAL_MSG_BYTES + '\u{2026}'.len_utf8());
        assert!(ack.msg.ends_with('\u{2026}'));
    }

    #[tokio::test]
    async fn respond_to_open_accepts_and_hands_the_request_to_the_handler() {
        let stream = MockStream::preloaded(sample_open().encode().unwrap());
        let (handler, ran_rx) = RecordingHandler::allow();
        let network_id = NetworkId::from([3u8; 32]);
        let initiator = NodeId::from([4u8; 32]);

        let result = respond_to_open(
            stream,
            network_id,
            initiator,
            &AllowAll::default(),
            &handler,
        )
        .await
        .unwrap();

        let Responded::Accepted(handling) = result else {
            panic!("an allowed request with an accepting handler must be Accepted");
        };
        handling.await;
        let request = ran_rx
            .await
            .expect("the handler's `handle` must have run with the request");
        assert_eq!(request.network_id, network_id);
        assert_eq!(request.initiator, initiator);
    }

    #[tokio::test]
    async fn respond_to_open_rejects_a_malformed_header() {
        let stream = MockStream::preloaded(vec![0x00, 0x02, 0xbf, 0xff]); // indefinite-length CBOR
        let (handler, _ran_rx) = RecordingHandler::allow();
        let err = respond_to_open(
            stream,
            NetworkId::from([0u8; 32]),
            NodeId::from([0u8; 32]),
            &AllowAll::default(),
            &handler,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, OpenError::Malformed(_)));
    }

    #[tokio::test]
    async fn read_len_prefixed_reads_exactly_one_header_and_nothing_behind_it() {
        let mut bytes = sample_open().encode().unwrap();
        let header_len = bytes.len();
        bytes.extend_from_slice(b"early data");
        let mut stream = MockStream::preloaded(bytes);

        let header = read_len_prefixed(&mut stream).await.unwrap();
        assert_eq!(header.len(), header_len);
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"early data");
    }

    #[tokio::test]
    async fn read_len_prefixed_reports_a_body_cut_short_as_unexpected_eof() {
        for cut in 0..sample_open().encode().unwrap().len() {
            let mut bytes = sample_open().encode().unwrap();
            bytes.truncate(cut);
            let err = read_len_prefixed(&mut MockStream::preloaded(bytes))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, OpenError::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
                "cut at {cut}: {err:?}"
            );
        }
    }
}
