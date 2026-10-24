//! The `menzil:docs` protocol over one stream (protocol.md 5.5), as a library: [`serve`] answers
//! a `fetch` or accepts a `push`, [`fetch`] and [`push`] are the opener's side. Nothing here
//! opens a stream, checks who may open one or counts streams per peer (the rate limits of 5.5
//! belong to the accept loop that will call this): every function takes a stream that is already
//! open and past OPEN_ACK, and any `AsyncRead + AsyncWrite` will do.
//!
//! What a stream may cost is bounded in this order, and nothing is allocated for a frame before
//! its length has passed: the message count (the seventh is refused before its header is
//! read), the frame length (checked on the four prefix bytes, before a buffer exists), strict
//! decoding, the size of a document, the network of the session, and only then the signature
//! checks, which belong to the [`DocsSink`] (the [`StoreDocs`] sink runs
//! [`menzil_proto::trust::check_bundle`] through [`DocStore::adopt`]). The whole operation has
//! one deadline ([`menzil_proto::docs::STREAM_DEADLINE`] unless the caller says otherwise).
//!
//! A protocol violation (a frame or document over its limit, a seventh message, a message that
//! does not decode, out of turn or out of order) is an `Err`: the caller resets the stream. A
//! document that is wrong in itself (does not decode as a Roster or Policy, belongs to another
//! network, fails the acceptance predicate) is answered with a `result` carrying `bad_document`
//! or `roster_expired`, the push is not adopted, and `serve` returns `Ok`.

use std::time::Duration;

use futures_util::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use menzil_proto::docs::{
    DocKind, DocsError, FRAME_HEADER_LEN, Message, MessageCounter, Outcome, check_frame_len,
    decode_message, encode_frame,
};
use menzil_proto::trust::{Bundle, Reason, Signer};
use menzil_proto::{ErrorCode, MAX_DOC_BYTES, NetworkId, Policy, Roster};
use thiserror::Error;

use crate::docs_store::{Adopted, DocStore};
use crate::error::NodeError;
use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;

pub use menzil_proto::docs::STREAM_DEADLINE;

/// Why a `menzil:docs` operation failed. Everything except [`Self::Rejected`] means the stream
/// is to be reset.
#[derive(Debug, Error)]
pub enum DocsStreamError {
    /// The stream failed or ended early.
    #[error("stream error: {0}")]
    Io(#[from] std::io::Error),
    /// A frame over its limit, a seventh message, or a message that does not decode.
    #[error("framing: {0}")]
    Frame(#[from] DocsError),
    /// The operation did not finish within its deadline.
    #[error("deadline passed")]
    Timeout,
    /// A message that does not belong here (out of turn, out of order, repeated, not allowed on
    /// this stream).
    #[error("protocol violation: {0}")]
    Unexpected(&'static str),
    /// A document over [`MAX_DOC_BYTES`].
    #[error("document of {len} bytes exceeds the {max} byte limit")]
    DocTooLarge {
        /// The size offered.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// What a fetch brought was refused (the reason is for the local log).
    #[error("documents refused: {0:?}")]
    Rejected(Reason),
    /// The sink failed in a way that is not a verdict on the documents.
    #[error("sink: {0}")]
    Sink(NodeError),
}

/// What the local stores hold, as `fetch` and `result` report it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeldDocs {
    /// The seq of the held Roster.
    pub roster_seq: Option<u64>,
    /// The seq of the held Policy.
    pub policy_seq: Option<u64>,
    /// The seq of the base of the held Roster, when it is steward signed.
    pub base_seq: Option<u64>,
    /// The seq of the base of the held Policy, when it is steward signed (an owner signed Policy
    /// has none, whatever the Roster stands on).
    pub policy_base_seq: Option<u64>,
}

/// The owner signed bases a node holds beside its steward signed documents.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeldBases {
    /// The base of the held Roster.
    pub roster: Option<Roster>,
    /// The base of the held Policy.
    pub policy: Option<Policy>,
}

/// Where documents to give away come from.
pub trait DocsSource {
    /// The held Roster with its base (steward signed Rosters only).
    fn roster(&self) -> Option<(Roster, Option<Roster>)>;
    /// The held Policy with its base (steward signed Policies only).
    fn policy(&self) -> Option<(Policy, Option<Policy>)>;
}

/// Where documents that arrive go. S5 and S6 plug their own in; [`StoreDocs`] is the one backed
/// by the node's stores.
pub trait DocsSink {
    /// Judges `bundle` at `now` (Unix seconds) and adopts what it may. [`NodeError::
    /// DocumentRejected`] is a verdict on the documents, answered with a code; any other error is
    /// a failure of the sink and resets the stream.
    fn adopt(&self, bundle: &Bundle, now: u64) -> Result<Adopted, NodeError>;
    /// What is held now.
    fn held(&self) -> HeldDocs;
    /// The bases held now. A fetch answer leaves out a base the opener announced (plan_fetch),
    /// so the opener puts its own back before judging. The default holds none.
    fn held_bases(&self) -> HeldBases {
        HeldBases::default()
    }
}

impl<T: DocsSource + ?Sized> DocsSource for &T {
    fn roster(&self) -> Option<(Roster, Option<Roster>)> {
        (**self).roster()
    }
    fn policy(&self) -> Option<(Policy, Option<Policy>)> {
        (**self).policy()
    }
}

impl<T: DocsSink + ?Sized> DocsSink for &T {
    fn adopt(&self, bundle: &Bundle, now: u64) -> Result<Adopted, NodeError> {
        (**self).adopt(bundle, now)
    }
    fn held(&self) -> HeldDocs {
        (**self).held()
    }
    fn held_bases(&self) -> HeldBases {
        (**self).held_bases()
    }
}

/// What a caller says about one operation.
#[derive(Debug, Clone, Copy)]
pub struct DocsParams {
    /// The network of the session; a document of another network is refused.
    pub network_id: NetworkId,
    /// The time, Unix seconds, for expiry and for the acceptance predicate.
    pub now: u64,
    /// The whole operation must be over by then.
    pub deadline: Duration,
}

/// Whether [`serve`] answers a `fetch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeMode {
    /// A `fetch` or a `push`.
    Full,
    /// A `push` only (a docs only session, protocol.md 5.1): a `fetch` is a violation and no
    /// document is ever sent.
    PushOnly,
}

/// What [`serve`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Served {
    /// A `fetch` was answered.
    Fetch,
    /// A `push` was answered with this `result`.
    Push(PushResult),
}

/// The `result` of a push, as the receiver sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushResult {
    /// What became of the Roster.
    pub roster: Outcome,
    /// What became of the Policy.
    pub policy: Outcome,
    /// Why, when something was rejected.
    pub code: Option<ErrorCode>,
    /// The seq of the Roster the receiver holds afterwards.
    pub roster_seq: Option<u64>,
    /// The seq of the Policy the receiver holds afterwards.
    pub policy_seq: Option<u64>,
}

/// What [`fetch`] brought.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FetchReport {
    /// What the sink adopted.
    pub adopted: Adopted,
    /// The seq of the other side's Roster, from its `end`.
    pub peer_roster_seq: Option<u64>,
    /// The seq of the other side's Policy, from its `end`.
    pub peer_policy_seq: Option<u64>,
}

/// A [`DocsSource`] and [`DocsSink`] over the node's two stores, for one network.
#[derive(Clone, Copy)]
pub struct StoreDocs<'a> {
    rosters: &'a RosterStore,
    policies: &'a PolicyStore,
    network_id: NetworkId,
}

impl<'a> StoreDocs<'a> {
    /// The stores of `network_id`.
    pub fn new(rosters: &'a RosterStore, policies: &'a PolicyStore, network_id: NetworkId) -> Self {
        Self {
            rosters,
            policies,
            network_id,
        }
    }
}

impl DocsSource for StoreDocs<'_> {
    fn roster(&self) -> Option<(Roster, Option<Roster>)> {
        self.rosters.get_with_base(&self.network_id)
    }

    fn policy(&self) -> Option<(Policy, Option<Policy>)> {
        self.policies.get_with_base(&self.network_id)
    }
}

impl DocsSink for StoreDocs<'_> {
    fn adopt(&self, bundle: &Bundle, now: u64) -> Result<Adopted, NodeError> {
        if !bundle_is_of(bundle, &self.network_id) {
            return Err(NodeError::DocumentRejected(Reason::WrongNetwork));
        }
        DocStore::new(self.rosters, self.policies).adopt(bundle, now)
    }

    fn held_bases(&self) -> HeldBases {
        HeldBases {
            roster: self.rosters.base(&self.network_id),
            policy: self.policies.base(&self.network_id),
        }
    }

    fn held(&self) -> HeldDocs {
        let base_seq = match self.rosters.signer(&self.network_id) {
            Some(Signer::Steward { base_seq, .. }) => Some(base_seq),
            _ => None,
        };
        let policy_base_seq = match self.policies.signer(&self.network_id) {
            Some(Signer::Steward { base_seq, .. }) => Some(base_seq),
            _ => None,
        };
        HeldDocs {
            roster_seq: self.rosters.seq(&self.network_id),
            policy_seq: self.policies.seq(&self.network_id),
            base_seq,
            policy_base_seq,
        }
    }
}

/// Whether every document of `bundle` belongs to `network_id`. A document that does not decode
/// does not.
fn bundle_is_of(bundle: &Bundle, network_id: &NetworkId) -> bool {
    let roster_ok = |doc: &Option<Roster>| {
        doc.as_ref()
            .is_none_or(|d| d.decode().is_ok_and(|b| b.network_id == *network_id))
    };
    let policy_ok = |doc: &Option<Policy>| {
        doc.as_ref()
            .is_none_or(|d| d.decode().is_ok_and(|b| b.network_id == *network_id))
    };
    roster_ok(&bundle.roster)
        && roster_ok(&bundle.base_roster)
        && policy_ok(&bundle.policy)
        && policy_ok(&bundle.base_policy)
}

/// Puts back the bases a fetch answer left out because the opener announced them: a missing
/// base is filled from the one held when its `seq` is the one announced for that document (the
/// Roster's and the Policy's bases are announced separately).
fn fill_bases(
    bundle: &mut Bundle,
    announced_roster: Option<u64>,
    announced_policy: Option<u64>,
    bases: HeldBases,
) {
    if bundle.roster.is_some()
        && bundle.base_roster.is_none()
        && let Some(announced) = announced_roster
        && let Some(base) = bases.roster
        && roster_seq_of(&base) == Some(announced)
    {
        bundle.base_roster = Some(base);
    }
    if bundle.policy.is_some()
        && bundle.base_policy.is_none()
        && let Some(announced) = announced_policy
        && let Some(base) = bases.policy
        && policy_seq_of(&base) == Some(announced)
    {
        bundle.base_policy = Some(base);
    }
}

/// The `seq` and `expires` of a held document, read from its signed body.
fn seq_expires<T: menzil_proto::SignedBody>(
    doc: &menzil_proto::Signed<T>,
    f: impl Fn(&T) -> (u64, u64),
) -> Option<(u64, u64)> {
    doc.decode().ok().map(|body| f(&body))
}

fn roster_seq_expires(doc: &Roster) -> Option<(u64, u64)> {
    seq_expires(doc, |b| (b.seq, b.expires))
}

fn policy_seq_expires(doc: &Policy) -> Option<(u64, u64)> {
    seq_expires(doc, |b| (b.seq, b.expires))
}

/// Whether a document of `seq` is newer than what the other side holds.
fn newer(seq: u64, held: Option<u64>) -> bool {
    held.is_none_or(|held| seq > held)
}

/// What to send in answer to a `fetch` with these seqs, at `now`: each unexpired document that
/// is newer; the Policy only when the Roster held has its `seq` and (it is sent, or the
/// opener's Roster has that `seq`); a base only when the opener does not hold it (the Roster's
/// base against `request_base_seq`, the Policy's base against `request_policy_base_seq`);
/// bases first; then `end`. Pure, so that the rules can be tested one by
/// one.
pub fn plan_fetch<S: DocsSource>(
    source: &S,
    request_roster_seq: Option<u64>,
    request_policy_seq: Option<u64>,
    request_base_seq: Option<u64>,
    request_policy_base_seq: Option<u64>,
    now: u64,
) -> Vec<Message> {
    let roster = source.roster();
    let policy = source.policy();
    let roster_info = roster.as_ref().and_then(|(r, _)| roster_seq_expires(r));
    let policy_info = policy.as_ref().and_then(|(p, _)| policy_seq_expires(p));

    let send_roster = match roster_info {
        Some((seq, expires)) => expires > now && newer(seq, request_roster_seq),
        None => false,
    };
    let send_policy = match (policy_info, roster_info) {
        (Some((pseq, pexpires)), Some((rseq, _))) => {
            pexpires > now
                && pseq == rseq
                && newer(pseq, request_policy_seq)
                && (send_roster || request_roster_seq == Some(pseq))
        }
        _ => false,
    };

    let mut out = Vec::new();
    if send_roster
        && let Some((_, Some(base))) = &roster
        && base_wanted(roster_seq_of(base), request_base_seq)
    {
        out.push(Message::Doc {
            kind: DocKind::BaseRoster,
            doc: base.encode(),
        });
    }
    if send_policy
        && let Some((_, Some(base))) = &policy
        && base_wanted(policy_seq_of(base), request_policy_base_seq)
    {
        out.push(Message::Doc {
            kind: DocKind::BasePolicy,
            doc: base.encode(),
        });
    }
    if send_roster && let Some((doc, _)) = &roster {
        out.push(Message::Doc {
            kind: DocKind::Roster,
            doc: doc.encode(),
        });
    }
    if send_policy && let Some((doc, _)) = &policy {
        out.push(Message::Doc {
            kind: DocKind::Policy,
            doc: doc.encode(),
        });
    }
    out.push(Message::End {
        roster_seq: roster_info.map(|(seq, _)| seq),
        policy_seq: policy_info.map(|(seq, _)| seq),
    });
    out
}

fn roster_seq_of(doc: &Roster) -> Option<u64> {
    roster_seq_expires(doc).map(|(seq, _)| seq)
}

fn policy_seq_of(doc: &Policy) -> Option<u64> {
    policy_seq_expires(doc).map(|(seq, _)| seq)
}

/// A base is sent unless the opener already holds one of the same `seq`.
fn base_wanted(base_seq: Option<u64>, request_base_seq: Option<u64>) -> bool {
    base_seq.is_none() || base_seq != request_base_seq
}

/// The documents a push of everything held would carry: the unexpired Roster with its base, and
/// the Policy with its base when it pairs with that Roster (the same `seq`).
pub fn bundle_to_push<S: DocsSource>(source: &S, now: u64) -> Bundle {
    let mut bundle = Bundle::default();
    let Some((roster, base_roster)) = source.roster() else {
        return bundle;
    };
    let Some((rseq, rexpires)) = roster_seq_expires(&roster) else {
        return bundle;
    };
    if rexpires <= now {
        return bundle;
    }
    bundle.roster = Some(roster);
    bundle.base_roster = base_roster;
    if let Some((policy, base_policy)) = source.policy()
        && let Some((pseq, pexpires)) = policy_seq_expires(&policy)
        && pseq == rseq
        && pexpires > now
    {
        bundle.policy = Some(policy);
        bundle.base_policy = base_policy;
    }
    bundle
}

/// The messages that push `bundle`: `push`, the documents bases first, `end` with the seqs of
/// the bundle's own Roster and Policy.
fn push_messages(bundle: &Bundle) -> Vec<Message> {
    let mut out = vec![Message::Push];
    let docs = [
        (
            DocKind::BaseRoster,
            bundle.base_roster.as_ref().map(Roster::encode),
        ),
        (
            DocKind::BasePolicy,
            bundle.base_policy.as_ref().map(Policy::encode),
        ),
        (DocKind::Roster, bundle.roster.as_ref().map(Roster::encode)),
        (DocKind::Policy, bundle.policy.as_ref().map(Policy::encode)),
    ];
    for (kind, doc) in docs {
        if let Some(doc) = doc {
            out.push(Message::Doc { kind, doc });
        }
    }
    out.push(Message::End {
        roster_seq: bundle.roster.as_ref().and_then(roster_seq_of),
        policy_seq: bundle.policy.as_ref().and_then(policy_seq_of),
    });
    out
}

async fn write_message<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &Message,
) -> Result<(), DocsStreamError> {
    stream.write_all(&encode_frame(message)?).await?;
    stream.flush().await?;
    Ok(())
}

/// Reads one message. The count is admitted before anything is read, and the length prefix is
/// checked before the buffer for the body is allocated.
async fn read_message<S: AsyncRead + Unpin>(
    stream: &mut S,
    counter: &mut MessageCounter,
) -> Result<Message, DocsStreamError> {
    counter.admit()?;
    let mut prefix = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut prefix).await?;
    let len = check_frame_len(u32::from_be_bytes(prefix))?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(decode_message(&body)?)
}

/// What a run of `doc` messages up to `end` came to.
struct Collected {
    bundle: Bundle,
    /// A `roster` / `policy` document was sent (whether or not it decoded).
    sent_roster: bool,
    sent_policy: bool,
    /// The first thing wrong with a document itself, if any; the bundle is then not to be used.
    defect: Option<Reason>,
    end_roster_seq: Option<u64>,
    end_policy_seq: Option<u64>,
}

/// Reads `doc` messages until `end`. Documents come once each and bases first (strictly
/// increasing kind). A document over [`MAX_DOC_BYTES`] is a violation; one that does not decode
/// or belongs to another network is a defect, remembered while the stream is read to its end.
async fn collect<S: AsyncRead + Unpin>(
    stream: &mut S,
    counter: &mut MessageCounter,
    network_id: &NetworkId,
) -> Result<Collected, DocsStreamError> {
    let mut bundle = Bundle::default();
    let mut defect = None;
    let mut last: Option<DocKind> = None;
    let (mut sent_roster, mut sent_policy) = (false, false);
    loop {
        match read_message(stream, counter).await? {
            Message::Doc { kind, doc } => {
                if last.is_some_and(|last| kind <= last) {
                    return Err(DocsStreamError::Unexpected("document out of order"));
                }
                last = Some(kind);
                sent_roster |= kind == DocKind::Roster;
                sent_policy |= kind == DocKind::Policy;
                if doc.len() > MAX_DOC_BYTES {
                    return Err(DocsStreamError::DocTooLarge {
                        len: doc.len(),
                        max: MAX_DOC_BYTES,
                    });
                }
                if defect.is_some() {
                    continue;
                }
                match store_doc(&mut bundle, kind, &doc, network_id) {
                    Ok(()) => {}
                    Err(reason) => defect = Some(reason),
                }
            }
            Message::End {
                roster_seq,
                policy_seq,
            } => {
                return Ok(Collected {
                    bundle,
                    sent_roster,
                    sent_policy,
                    defect,
                    end_roster_seq: roster_seq,
                    end_policy_seq: policy_seq,
                });
            }
            _ => return Err(DocsStreamError::Unexpected("expected doc or end")),
        }
    }
}

/// Decodes one document into its slot of `bundle`, refusing one of another network.
fn store_doc(
    bundle: &mut Bundle,
    kind: DocKind,
    bytes: &[u8],
    network_id: &NetworkId,
) -> Result<(), Reason> {
    match kind {
        DocKind::BaseRoster | DocKind::Roster => {
            let doc = Roster::decode_strict(bytes).map_err(|_| Reason::Malformed)?;
            let body = doc.decode().map_err(|_| Reason::Malformed)?;
            if body.network_id != *network_id {
                return Err(Reason::WrongNetwork);
            }
            if kind == DocKind::Roster {
                bundle.roster = Some(doc);
            } else {
                bundle.base_roster = Some(doc);
            }
        }
        DocKind::BasePolicy | DocKind::Policy => {
            let doc = Policy::decode_strict(bytes).map_err(|_| Reason::Malformed)?;
            let body = doc.decode().map_err(|_| Reason::Malformed)?;
            if body.network_id != *network_id {
                return Err(Reason::WrongNetwork);
            }
            if kind == DocKind::Policy {
                bundle.policy = Some(doc);
            } else {
                bundle.base_policy = Some(doc);
            }
        }
    }
    Ok(())
}

/// The code a peer is told for a refused document.
fn code_for(error: &NodeError) -> Option<ErrorCode> {
    match error {
        NodeError::DocumentRejected(reason) => Some(reason.code()),
        NodeError::Proto(_) => Some(ErrorCode::BadDocument),
        _ => None,
    }
}

/// Judges what a push brought and builds the `result` for it.
fn judge_push<K: DocsSink>(
    sink: &K,
    collected: Collected,
    now: u64,
) -> Result<Message, DocsStreamError> {
    let bundle = collected.bundle;
    let (sent_roster, sent_policy) = (collected.sent_roster, collected.sent_policy);
    let verdict: Result<Adopted, ErrorCode> = if let Some(reason) = collected.defect {
        Err(reason.code())
    } else if !sent_roster && !sent_policy {
        Ok(Adopted::default())
    } else {
        match sink.adopt(&bundle, now) {
            Ok(adopted) => Ok(adopted),
            Err(NodeError::DocumentTooLarge { len, max }) => {
                return Err(DocsStreamError::DocTooLarge { len, max });
            }
            Err(error) => match code_for(&error) {
                Some(code) => Err(code),
                None => return Err(DocsStreamError::Sink(error)),
            },
        }
    };
    let outcome = |sent: bool, adopted: bool| match (&verdict, sent) {
        (_, false) => Outcome::NotSent,
        (Err(_), true) => Outcome::Rejected,
        (Ok(_), true) if adopted => Outcome::Adopted,
        (Ok(_), true) => Outcome::Held,
    };
    let adopted = verdict.as_ref().copied().unwrap_or_default();
    let held = sink.held();
    Ok(Message::Result {
        roster: outcome(sent_roster, adopted.roster),
        policy: outcome(sent_policy, adopted.policy),
        code: verdict.err(),
        roster_seq: held.roster_seq,
        policy_seq: held.policy_seq,
    })
}

/// Answers the first message of an incoming `menzil:docs` stream: a `fetch` from `source`, or a
/// `push` into `sink`. The stream is left open for the caller to close.
pub async fn serve<S, Src, Snk>(
    stream: &mut S,
    source: Src,
    sink: Snk,
    params: &DocsParams,
    mode: ServeMode,
) -> Result<Served, DocsStreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Src: DocsSource,
    Snk: DocsSink,
{
    tokio::time::timeout(
        params.deadline,
        serve_inner(stream, source, sink, params, mode),
    )
    .await
    .map_err(|_| DocsStreamError::Timeout)?
}

async fn serve_inner<S, Src, Snk>(
    stream: &mut S,
    source: Src,
    sink: Snk,
    params: &DocsParams,
    mode: ServeMode,
) -> Result<Served, DocsStreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Src: DocsSource,
    Snk: DocsSink,
{
    let mut counter = MessageCounter::new();
    match read_message(stream, &mut counter).await? {
        Message::Fetch {
            roster_seq,
            policy_seq,
            base_seq,
            policy_base_seq,
        } => {
            if mode == ServeMode::PushOnly {
                return Err(DocsStreamError::Unexpected("fetch on a docs only session"));
            }
            for message in plan_fetch(
                &source,
                roster_seq,
                policy_seq,
                base_seq,
                policy_base_seq,
                params.now,
            ) {
                write_message(stream, &message).await?;
            }
            Ok(Served::Fetch)
        }
        Message::Push => {
            let collected = collect(stream, &mut counter, &params.network_id).await?;
            let result = judge_push(&sink, collected, params.now)?;
            write_message(stream, &result).await?;
            let Message::Result {
                roster,
                policy,
                code,
                roster_seq,
                policy_seq,
            } = result
            else {
                unreachable!("judge_push builds a result")
            };
            Ok(Served::Push(PushResult {
                roster,
                policy,
                code,
                roster_seq,
                policy_seq,
            }))
        }
        _ => Err(DocsStreamError::Unexpected("expected fetch or push")),
    }
}

/// Opens a fetch: sends what `sink` holds, reads what comes back and hands it to the sink.
pub async fn fetch<S, Snk>(
    stream: &mut S,
    sink: Snk,
    params: &DocsParams,
) -> Result<FetchReport, DocsStreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    Snk: DocsSink,
{
    tokio::time::timeout(params.deadline, async {
        let held = sink.held();
        write_message(
            stream,
            &Message::Fetch {
                roster_seq: held.roster_seq,
                policy_seq: held.policy_seq,
                base_seq: held.base_seq,
                policy_base_seq: held.policy_base_seq,
            },
        )
        .await?;
        let mut counter = MessageCounter::new();
        let mut collected = collect(stream, &mut counter, &params.network_id).await?;
        if let Some(reason) = collected.defect {
            return Err(DocsStreamError::Rejected(reason));
        }
        fill_bases(
            &mut collected.bundle,
            held.base_seq,
            held.policy_base_seq,
            sink.held_bases(),
        );
        let mut report = FetchReport {
            adopted: Adopted::default(),
            peer_roster_seq: collected.end_roster_seq,
            peer_policy_seq: collected.end_policy_seq,
        };
        if collected.bundle.roster.is_some() || collected.bundle.policy.is_some() {
            report.adopted = match sink.adopt(&collected.bundle, params.now) {
                Ok(adopted) => adopted,
                Err(NodeError::DocumentRejected(reason)) => {
                    return Err(DocsStreamError::Rejected(reason));
                }
                Err(NodeError::DocumentTooLarge { len, max }) => {
                    return Err(DocsStreamError::DocTooLarge { len, max });
                }
                Err(error) => return Err(DocsStreamError::Sink(error)),
            };
        }
        Ok(report)
    })
    .await
    .map_err(|_| DocsStreamError::Timeout)?
}

/// Opens a push of `bundle` and returns the receiver's `result`.
pub async fn push<S>(
    stream: &mut S,
    bundle: &Bundle,
    params: &DocsParams,
) -> Result<PushResult, DocsStreamError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(params.deadline, async {
        for message in push_messages(bundle) {
            write_message(stream, &message).await?;
        }
        let mut counter = MessageCounter::new();
        match read_message(stream, &mut counter).await? {
            Message::Result {
                roster,
                policy,
                code,
                roster_seq,
                policy_seq,
            } => Ok(PushResult {
                roster,
                policy,
                code,
                roster_seq,
                policy_seq,
            }),
            _ => Err(DocsStreamError::Unexpected("expected result")),
        }
    })
    .await
    .map_err(|_| DocsStreamError::Timeout)?
}

#[cfg(test)]
mod tests;
