//! The public shares a node asks its relay to route to it (protocol.md 4.4, 6.1; expose design
//! slice S-E1): what the owner configured, what the relay answered, and the rule that sends the
//! first after the second.
//!
//! [`ShareBook`] is one handle, cloned freely, shared between the node's owner side (which sets
//! the configured shares: [`ShareBook::set_shares`]) and the relay session (which sends them and
//! stores the answer). The session sends an ADVERTISE after every ATTACH and whenever the set
//! changes, and states the complete set each time (the relay drops claims an ADVERTISE leaves
//! out). The relay's ADVERTISE_ACK is stored here and forgotten when the attachment ends: the
//! relay's claims end with the session, so a name is only usable while an ACK of the current
//! attachment accepted it.
//!
//! Not here: who may use an accepted share. This module only records what the relay accepted and
//! answers [`ShareBook::accepted_service`]; the relay principal's router branch and authorizer
//! (`l4_router`, `relay_serve`, expose design S-E4) ask it.
//!
//! The ACK names no network (the relay judges a name against every network the session claimed),
//! so the book is per relay attachment, not per network. A caller that needs the network of a
//! share (the relay principal's session of one network, expose design S-E4) asks the Roster of
//! that network, which lists the label for this node: `relay_serve::accepted_shares`.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use menzil_proto::{
    AdvertiseAckBody, AdvertiseBody, RejectedShare, ServiceId, ServiceKind, Share, ShareMode,
};
use tokio::sync::watch;
use tokio::time::Instant;

/// How many shares one ADVERTISE may carry (protocol.md 4.4: a longer one is refused whole).
pub const MAX_SHARES: usize = 64;

/// The longest a share name may be: one LDH label (protocol.md 4.4).
pub const MAX_NAME_BYTES: usize = 63;

/// Why a set of shares is not acceptable. Every message names the share, so that a person can find
/// it in the file it came from.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShareError {
    /// More shares than one ADVERTISE may carry.
    #[error("{0} shares are configured, at most {MAX_SHARES} can be advertised")]
    TooMany(usize),
    /// The name is not one LDH label in lowercase.
    #[error("share name {name:?}: {why}")]
    BadName {
        /// The name as written.
        name: String,
        /// What is wrong with it.
        why: &'static str,
    },
    /// Two shares with one name.
    #[error("share name {0:?} is used twice")]
    Duplicate(String),
    /// The service is not one a share of this mode may point at.
    #[error("share {name:?}: {why}")]
    BadService {
        /// The share.
        name: String,
        /// What is wrong with it.
        why: String,
    },
    /// An ALPN identifier that cannot be one.
    #[error("share {name:?}: {why}")]
    BadAlpn {
        /// The share.
        name: String,
        /// What is wrong with it.
        why: &'static str,
    },
}

/// Whether `name` is one lowercase LDH label of 1 to 63 characters that neither starts nor ends
/// with a hyphen (protocol.md 4.4). A dot makes it a custom domain, which a relay does not accept
/// yet, so it is refused here with its own reason rather than "not LDH".
pub fn check_name(name: &str) -> Result<(), ShareError> {
    let bad = |why| {
        Err(ShareError::BadName {
            name: name.to_string(),
            why,
        })
    };
    if name.is_empty() {
        return bad("it is empty");
    }
    if name.len() > MAX_NAME_BYTES {
        return bad("it is longer than 63 characters");
    }
    if name.contains('.') {
        return bad("it contains a dot (a custom domain is not supported yet; use one label)");
    }
    if name.bytes().any(|b| b.is_ascii_uppercase()) {
        return bad("it has uppercase letters (names are lowercase)");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return bad("it may only hold letters, digits and hyphens");
    }
    if name.starts_with('-') || name.ends_with('-') {
        return bad("it starts or ends with a hyphen");
    }
    Ok(())
}

/// Checks a whole set of shares before it is advertised: names, duplicates, the count, the
/// service of each (a blind share points at `tls:` or `tcp:`, a terminated one at `http:`, the
/// label non empty and not `*`) and the ALPN list (none for a terminated share, where the relay
/// ignores it, so that an entry is a mistake and not a no-op).
pub fn validate_shares(shares: &[Share]) -> Result<(), ShareError> {
    if shares.len() > MAX_SHARES {
        return Err(ShareError::TooMany(shares.len()));
    }
    let mut seen = HashSet::new();
    for share in shares {
        check_name(&share.name)?;
        if !seen.insert(share.name.as_str()) {
            return Err(ShareError::Duplicate(share.name.clone()));
        }
        let allowed: &[ServiceKind] = match share.mode {
            ShareMode::Blind => &[ServiceKind::Tls, ServiceKind::Tcp],
            ShareMode::Terminated => &[ServiceKind::Http],
        };
        if !allowed.contains(&share.service.kind) {
            let want = allowed
                .iter()
                .map(|k| format!("{k}:"))
                .collect::<Vec<_>>()
                .join(" or ");
            let mode = match share.mode {
                ShareMode::Blind => "blind",
                ShareMode::Terminated => "terminated",
            };
            return Err(ShareError::BadService {
                name: share.name.clone(),
                why: format!(
                    "a {mode} share points at a {want} service, not {}",
                    share.service
                ),
            });
        }
        if share.service.label.is_empty() || share.service.label == "*" {
            return Err(ShareError::BadService {
                name: share.name.clone(),
                why: format!("the service {} needs a specific label", share.service),
            });
        }
        if share.mode == ShareMode::Terminated && !share.alpn.is_empty() {
            return Err(ShareError::BadAlpn {
                name: share.name.clone(),
                why: "alpn applies to blind shares only (a terminated share has none)",
            });
        }
        for alpn in &share.alpn {
            if alpn.is_empty() || alpn.len() > 255 || !alpn.is_ascii() {
                return Err(ShareError::BadAlpn {
                    name: share.name.clone(),
                    why: "an alpn identifier is 1 to 255 ASCII characters",
                });
            }
        }
    }
    Ok(())
}

/// What the relay answered to the node's latest ADVERTISE of this attachment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareSnapshot {
    /// The shares of the latest ADVERTISE sent in this attachment (empty before one is sent and
    /// after the attachment ended).
    pub sent: Vec<Share>,
    /// Whether an ADVERTISE_ACK has come in this attachment.
    pub acked: bool,
    /// The shares the relay accepted: those of `sent` whose name its ACK lists as accepted.
    pub accepted: Vec<Share>,
    /// The names it rejected, with its reason each.
    pub rejected: Vec<RejectedShare>,
    /// The full names it accepted, relative to its share domain (`names` of the ACK; empty from a
    /// relay that does not send it).
    pub names: Vec<String>,
}

#[derive(Default)]
struct State {
    snapshot: ShareSnapshot,
}

struct Inner {
    /// What the owner configured; the session follows it.
    configured: watch::Sender<Arc<Vec<Share>>>,
    state: Mutex<State>,
    /// Counts the changes of what the relay accepted (an ACK came in, the attachment ended), for
    /// whoever must act when a share is withdrawn (the revalidator of the relay principal's
    /// sessions).
    accepted_changes: watch::Sender<u64>,
    /// How long the relay has to answer an ADVERTISE and how long a refusal is waited out; the
    /// two figures of [`AdvertiseWatch`], settable for tests.
    timing: Mutex<(Duration, Duration)>,
}

/// The configured shares and the relay's answer. See the module docs.
#[derive(Clone)]
pub struct ShareBook {
    inner: Arc<Inner>,
}

impl Default for ShareBook {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ShareBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareBook")
            .field("configured", &*self.inner.configured.borrow())
            .field("relay_answer", &self.snapshot())
            .finish()
    }
}

impl ShareBook {
    /// A book with no shares: the node advertises nothing.
    pub fn new() -> Self {
        let (configured, _) = watch::channel(Arc::new(Vec::new()));
        let (accepted_changes, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                configured,
                state: Mutex::new(State::default()),
                accepted_changes,
                timing: Mutex::new((ADVERTISE_ACK_TIMEOUT, ADVERTISE_RETRY_DELAY)),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // The state is plain data replaced whole: a panic elsewhere leaves it consistent.
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the configured shares, after [`validate_shares`]; the relay session advertises
    /// the new set on its live attachment, or at its next one. An invalid set changes nothing and
    /// is returned as an error.
    pub fn set_shares(&self, shares: Vec<Share>) -> Result<(), ShareError> {
        validate_shares(&shares)?;
        self.inner.configured.send_if_modified(|current| {
            if **current == shares {
                false
            } else {
                *current = Arc::new(shares);
                true
            }
        });
        Ok(())
    }

    /// Other figures than [`ADVERTISE_ACK_TIMEOUT`] and [`ADVERTISE_RETRY_DELAY`], for tests that
    /// cannot wait that long; takes effect at the next attachment.
    #[doc(hidden)]
    pub fn set_advertise_timing(&self, ack_timeout: Duration, retry_delay: Duration) {
        *self
            .inner
            .timing
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = (ack_timeout, retry_delay);
    }

    /// The bookkeeping of the answers to the ADVERTISE records of one attachment, with this
    /// book's figures.
    pub(crate) fn advertise_watch(&self) -> AdvertiseWatch {
        let (ack_timeout, retry_delay) = *self
            .inner
            .timing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        AdvertiseWatch::with_timing(ack_timeout, retry_delay)
    }

    /// The shares the owner configured.
    pub fn configured(&self) -> Vec<Share> {
        self.inner.configured.borrow().as_ref().clone()
    }

    /// What the relay answered in this attachment (see [`ShareSnapshot`]).
    pub fn snapshot(&self) -> ShareSnapshot {
        self.state().snapshot.clone()
    }

    /// The full names the relay accepted in this attachment, relative to its share domain.
    pub fn names(&self) -> Vec<String> {
        self.state().snapshot.names.clone()
    }

    /// Whether the relay accepted a share that points at `service`, in this attachment. This is
    /// the question a later slice's authorizer asks before it lets the relay open that service.
    pub fn accepted_service(&self, service: &ServiceId) -> bool {
        self.state()
            .snapshot
            .accepted
            .iter()
            .any(|share| &share.service == service)
    }

    /// Whether some share of the latest ADVERTISE is not accepted (no answer yet counts). A
    /// newer Roster at the relay can change that, so the session asks again after it sent one.
    pub(crate) fn has_unaccepted(&self) -> bool {
        let state = self.state();
        state.snapshot.sent.len() != state.snapshot.accepted.len()
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<Arc<Vec<Share>>> {
        self.inner.configured.subscribe()
    }

    /// A receiver that sees a change each time the relay's answer is stored or forgotten (an
    /// ADVERTISE_ACK, the end of the attachment): the moment a share can have been withdrawn.
    pub(crate) fn subscribe_accepted(&self) -> watch::Receiver<u64> {
        self.inner.accepted_changes.subscribe()
    }

    fn accepted_changed(&self) {
        self.inner.accepted_changes.send_modify(|count| *count += 1);
    }

    /// The shares the relay accepted in this attachment, whole (see [`ShareSnapshot::accepted`]).
    pub fn accepted(&self) -> Vec<Share> {
        self.state().snapshot.accepted.clone()
    }

    /// An ADVERTISE with `shares` is about to be sent.
    ///
    /// A share the new set no longer holds (same name and an equal [`Share`], so a changed service,
    /// mode or ALPN counts as withdrawn too) stops being accepted at once, not when the relay's
    /// answer comes: the owner took it away, and a relay that never answers (or refuses the
    /// ADVERTISE as over its rate) must not keep it served. The watcher of the accepted set is
    /// told, so that the streams of the withdrawn share are reset now. A share the new set still
    /// holds stays accepted until the answer, because the relay's claims do too.
    pub(crate) fn note_sent(&self, shares: &[Share]) {
        let mut state = self.state();
        state.snapshot.sent = shares.to_vec();
        let before = state.snapshot.accepted.len();
        state
            .snapshot
            .accepted
            .retain(|accepted| shares.iter().any(|share| share == accepted));
        let withdrawn = state.snapshot.accepted.len() != before;
        drop(state);
        if withdrawn {
            self.accepted_changed();
        }
    }

    /// The relay's ADVERTISE_ACK arrived.
    pub(crate) fn note_ack(&self, ack: &AdvertiseAckBody) {
        let mut state = self.state();
        let snapshot = &mut state.snapshot;
        snapshot.acked = true;
        snapshot.accepted = snapshot
            .sent
            .iter()
            .filter(|share| ack.accepted.iter().any(|name| name == &share.name))
            .cloned()
            .collect();
        snapshot.rejected = ack.rejected.clone();
        snapshot.names = ack.names.clone();
        drop(state);
        self.accepted_changed();
    }

    /// The attachment ended: the relay's claims ended with it.
    pub(crate) fn note_detached(&self) {
        self.state().snapshot = ShareSnapshot::default();
        self.accepted_changed();
    }
}

/// How long the relay has to answer an ADVERTISE (with its ACK, or an ERROR) before the node
/// takes the attachment for dead and re-attaches: a relay that never answers must not leave the
/// node unable to tell what the relay holds for it.
pub const ADVERTISE_ACK_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the node waits before it states its shares again after the relay answered an
/// ADVERTISE with an ERROR (typically `rate_limited`, which a relay says after ten a minute, so
/// that the next try finds a token again).
pub const ADVERTISE_RETRY_DELAY: Duration = Duration::from_secs(10);

/// What became due on an [`AdvertiseWatch`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Due {
    /// An ADVERTISE got no answer within [`ADVERTISE_ACK_TIMEOUT`]: end the attachment.
    AckMissing,
    /// The wait after a refused ADVERTISE is over: state the shares again.
    Retry,
}

/// The node's bookkeeping of the answers to its ADVERTISE records in one attachment: how many are
/// unanswered, when the oldest must be answered by, and when to try again after a refusal. Plain
/// state with the clock passed in, driven by the relay session loop (`session.rs`).
#[derive(Debug)]
pub(crate) struct AdvertiseWatch {
    unanswered: u32,
    deadline: Option<Instant>,
    retry_at: Option<Instant>,
    ack_timeout: Duration,
    retry_delay: Duration,
}

impl AdvertiseWatch {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_timing(ADVERTISE_ACK_TIMEOUT, ADVERTISE_RETRY_DELAY)
    }

    pub(crate) fn with_timing(ack_timeout: Duration, retry_delay: Duration) -> Self {
        Self {
            unanswered: 0,
            deadline: None,
            retry_at: None,
            ack_timeout,
            retry_delay,
        }
    }

    /// An ADVERTISE was written. It supersedes a retry that was waiting.
    pub(crate) fn sent(&mut self, now: Instant) {
        self.unanswered += 1;
        self.retry_at = None;
        if self.deadline.is_none() {
            self.deadline = Some(now + self.ack_timeout);
        }
    }

    fn answered(&mut self, now: Instant) -> bool {
        if self.unanswered == 0 {
            return false;
        }
        self.unanswered -= 1;
        self.deadline = (self.unanswered > 0).then(|| now + self.ack_timeout);
        true
    }

    /// An ADVERTISE_ACK came in.
    pub(crate) fn acked(&mut self, now: Instant) {
        self.answered(now);
    }

    /// An ERROR came in. While an ADVERTISE is unanswered it is that one's answer: the relay did
    /// not take the set (its claims stay as they were), so the node asks again after a while.
    /// Returns whether the ERROR counted as such an answer.
    pub(crate) fn refused(&mut self, now: Instant) -> bool {
        if !self.answered(now) {
            return false;
        }
        self.retry_at = Some(now + self.retry_delay);
        true
    }

    /// Whether some ADVERTISE is unanswered.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> bool {
        self.unanswered > 0
    }

    /// Resolves when something is due; never resolves while nothing is. The retry is spent by
    /// being reported, the missing answer is not (the caller ends the attachment).
    pub(crate) async fn due(&mut self) -> Due {
        let next = match (self.deadline, self.retry_at) {
            (None, None) => return std::future::pending().await,
            (Some(deadline), None) => (deadline, Due::AckMissing),
            (None, Some(retry)) => (retry, Due::Retry),
            (Some(deadline), Some(retry)) => {
                if retry < deadline {
                    (retry, Due::Retry)
                } else {
                    (deadline, Due::AckMissing)
                }
            }
        };
        tokio::time::sleep_until(next.0).await;
        if next.1 == Due::Retry {
            self.retry_at = None;
        }
        next.1
    }
}

/// The ADVERTISE that states `shares` as this node's complete set. A node accepts peers: it has
/// no setting that says otherwise yet.
pub(crate) fn advertise_body(shares: &[Share]) -> AdvertiseBody {
    AdvertiseBody {
        v: 1,
        shares: shares.to_vec(),
        accept_peers: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(name: &str, mode: ShareMode, service: &str) -> Share {
        Share {
            name: name.to_string(),
            mode,
            service: service.parse().unwrap(),
            alpn: vec![],
        }
    }

    fn blind(name: &str) -> Share {
        share(name, ShareMode::Blind, &format!("tls:{name}"))
    }

    #[test]
    fn names_are_one_lowercase_ldh_label() {
        for good in ["app", "a", "my-app-2", "0day", &"a".repeat(63)] {
            assert_eq!(check_name(good), Ok(()), "{good}");
        }
        for (bad, word) in [
            ("", "empty"),
            ("App", "uppercase"),
            ("my_app", "letters, digits and hyphens"),
            ("-app", "hyphen"),
            ("app-", "hyphen"),
            ("a.b", "dot"),
            ("caf\u{e9}", "letters, digits and hyphens"),
            (&"a".repeat(64), "63"),
        ] {
            let error = check_name(bad).unwrap_err().to_string();
            assert!(error.contains(word), "{bad:?}: {error}");
        }
    }

    #[test]
    fn a_set_is_refused_whole_for_a_duplicate_a_wrong_service_or_too_many() {
        assert_eq!(validate_shares(&[blind("a"), blind("b")]), Ok(()));
        assert_eq!(
            validate_shares(&[blind("a"), blind("a")]),
            Err(ShareError::Duplicate("a".to_string()))
        );
        // A blind share is tls or tcp, a terminated one http.
        let error = validate_shares(&[share("a", ShareMode::Blind, "http:a")]).unwrap_err();
        assert!(error.to_string().contains("tls: or tcp:"), "{error}");
        let error = validate_shares(&[share("a", ShareMode::Terminated, "tls:a")]).unwrap_err();
        assert!(error.to_string().contains("http:"), "{error}");
        assert_eq!(
            validate_shares(&[share("a", ShareMode::Terminated, "http:a")]),
            Ok(())
        );
        assert_eq!(
            validate_shares(&[share("a", ShareMode::Blind, "tcp:ssh")]),
            Ok(())
        );
        assert!(validate_shares(&[share("a", ShareMode::Blind, "tls:*")]).is_err());
        assert!(validate_shares(&[share("a", ShareMode::Blind, "tls:")]).is_err());
        let many: Vec<Share> = (0..=MAX_SHARES).map(|i| blind(&format!("n{i}"))).collect();
        assert_eq!(
            validate_shares(&many),
            Err(ShareError::TooMany(MAX_SHARES + 1))
        );
        assert_eq!(validate_shares(&many[..MAX_SHARES]), Ok(()));
    }

    #[test]
    fn alpn_belongs_to_blind_shares_only() {
        let mut blind_with = blind("a");
        blind_with.alpn = vec!["h2".to_string(), "acme-tls/1".to_string()];
        assert_eq!(validate_shares(std::slice::from_ref(&blind_with)), Ok(()));
        let mut terminated = share("a", ShareMode::Terminated, "http:a");
        terminated.alpn = vec!["h2".to_string()];
        assert!(matches!(
            validate_shares(&[terminated]),
            Err(ShareError::BadAlpn { .. })
        ));
        blind_with.alpn = vec![String::new()];
        assert!(matches!(
            validate_shares(&[blind_with]),
            Err(ShareError::BadAlpn { .. })
        ));
    }

    #[test]
    fn an_invalid_set_changes_nothing() {
        let book = ShareBook::new();
        book.set_shares(vec![blind("a")]).unwrap();
        assert!(book.set_shares(vec![blind("A")]).is_err());
        assert_eq!(book.configured(), vec![blind("a")]);
    }

    #[test]
    fn setting_the_same_shares_again_does_not_notify_the_session() {
        let book = ShareBook::new();
        let mut watcher = book.subscribe();
        book.set_shares(vec![blind("a")]).unwrap();
        assert!(watcher.has_changed().unwrap());
        watcher.borrow_and_update();
        book.set_shares(vec![blind("a")]).unwrap();
        assert!(!watcher.has_changed().unwrap(), "no change, no ADVERTISE");
        book.set_shares(vec![]).unwrap();
        assert!(watcher.has_changed().unwrap());
    }

    fn ack(accepted: &[&str], rejected: &[(&str, &str)], names: &[&str]) -> AdvertiseAckBody {
        AdvertiseAckBody {
            accepted: accepted.iter().map(|s| s.to_string()).collect(),
            rejected: rejected
                .iter()
                .map(|(name, reason)| RejectedShare {
                    name: name.to_string(),
                    reason: reason.to_string(),
                })
                .collect(),
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn the_ack_is_kept_against_the_shares_it_answered_and_forgotten_on_detach() {
        let book = ShareBook::new();
        let (a, b) = (blind("a"), blind("b"));
        book.note_sent(&[a.clone(), b.clone()]);
        assert!(book.has_unaccepted(), "no answer yet");
        assert!(!book.accepted_service(&a.service));

        book.note_ack(&ack(&["a"], &[("b", "label_unclaimed")], &["a.ali"]));
        let snapshot = book.snapshot();
        assert!(snapshot.acked);
        assert_eq!(snapshot.accepted, vec![a.clone()]);
        assert_eq!(snapshot.rejected.len(), 1);
        assert_eq!(snapshot.rejected[0].reason, "label_unclaimed");
        assert_eq!(book.names(), vec!["a.ali".to_string()]);
        assert!(book.accepted_service(&a.service));
        assert!(!book.accepted_service(&b.service), "b was rejected");
        assert!(book.has_unaccepted());

        book.note_detached();
        assert_eq!(book.snapshot(), ShareSnapshot::default());
        assert!(
            !book.accepted_service(&a.service),
            "the claims ended with the session"
        );
    }

    #[test]
    fn an_ack_naming_a_share_that_was_not_sent_accepts_nothing() {
        let book = ShareBook::new();
        book.note_sent(&[blind("a")]);
        book.note_ack(&ack(&["zzz"], &[], &[]));
        assert!(book.snapshot().accepted.is_empty());
    }

    #[test]
    fn a_share_taken_out_of_the_set_stops_being_accepted_before_any_answer() {
        let book = ShareBook::new();
        let (a, b) = (blind("a"), blind("b"));
        book.note_sent(&[a.clone(), b.clone()]);
        book.note_ack(&ack(&["a", "b"], &[], &[]));
        let mut watcher = book.subscribe_accepted();
        watcher.borrow_and_update();

        // `a` leaves the set, and the relay has not answered (or never will).
        book.note_sent(std::slice::from_ref(&b));
        assert!(!book.accepted_service(&a.service), "withdrawn means gone");
        assert!(
            book.accepted_service(&b.service),
            "b stays until the answer"
        );
        assert!(
            watcher.has_changed().unwrap(),
            "the watcher is told at once"
        );
        watcher.borrow_and_update();

        // The same set again changes nothing and tells nobody.
        book.note_sent(std::slice::from_ref(&b));
        assert!(book.accepted_service(&b.service));
        assert!(!watcher.has_changed().unwrap());
    }

    #[test]
    fn a_share_whose_value_changed_is_not_accepted_under_its_old_value() {
        let book = ShareBook::new();
        let old = blind("a");
        book.note_sent(std::slice::from_ref(&old));
        book.note_ack(&ack(&["a"], &[], &[]));
        // Same name, another service behind it: the relay accepted the old one only.
        let changed = share("a", ShareMode::Blind, "tls:elsewhere");
        book.note_sent(std::slice::from_ref(&changed));
        assert!(!book.accepted_service(&old.service));
        assert!(!book.accepted_service(&changed.service));
        assert!(book.accepted().is_empty());
        assert!(book.has_unaccepted());
    }

    // ---- the answers to ADVERTISE ----------------------------------------------

    use tokio::time::timeout;

    #[tokio::test(start_paused = true)]
    async fn an_advertise_with_no_answer_is_reported_after_the_ack_timeout() {
        let mut watch = AdvertiseWatch::new();
        assert!(
            timeout(Duration::from_secs(3600), watch.due())
                .await
                .is_err(),
            "nothing is due while nothing is waiting"
        );
        watch.sent(Instant::now());
        assert!(watch.waiting());
        assert!(
            timeout(ADVERTISE_ACK_TIMEOUT - Duration::from_secs(1), watch.due())
                .await
                .is_err(),
            "not before the deadline"
        );
        let started = Instant::now();
        assert_eq!(
            timeout(Duration::from_secs(5), watch.due()).await,
            Ok(Due::AckMissing)
        );
        assert!(Instant::now() - started <= Duration::from_secs(2));
        assert_eq!(ADVERTISE_ACK_TIMEOUT, Duration::from_secs(30));
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_clears_the_deadline_and_a_second_unanswered_one_keeps_it() {
        let mut watch = AdvertiseWatch::new();
        watch.sent(Instant::now());
        tokio::time::sleep(Duration::from_secs(20)).await;
        watch.acked(Instant::now());
        assert!(!watch.waiting());
        assert!(
            timeout(Duration::from_secs(3600), watch.due())
                .await
                .is_err(),
            "answered in time: nothing is due"
        );

        // Two out, one answered: the other still has its own deadline, counted from the answer.
        watch.sent(Instant::now());
        watch.sent(Instant::now());
        tokio::time::sleep(Duration::from_secs(20)).await;
        watch.acked(Instant::now());
        assert!(watch.waiting());
        assert!(
            timeout(ADVERTISE_ACK_TIMEOUT - Duration::from_secs(1), watch.due())
                .await
                .is_err()
        );
        assert_eq!(
            timeout(Duration::from_secs(5), watch.due()).await,
            Ok(Due::AckMissing)
        );
        // An ACK nobody asked for is no answer to anything.
        let mut idle = AdvertiseWatch::new();
        idle.acked(Instant::now());
        assert!(!idle.waiting());
    }

    #[tokio::test(start_paused = true)]
    async fn an_error_while_waiting_is_a_refusal_that_is_retried_once_after_the_delay() {
        let mut watch = AdvertiseWatch::new();
        // An ERROR with nothing in flight is not about ADVERTISE.
        assert!(!watch.refused(Instant::now()));
        assert!(
            timeout(Duration::from_secs(3600), watch.due())
                .await
                .is_err(),
            "no retry for an unrelated ERROR"
        );

        watch.sent(Instant::now());
        assert!(watch.refused(Instant::now()));
        assert!(
            !watch.waiting(),
            "the refusal is the answer: no ack deadline"
        );
        assert!(
            timeout(ADVERTISE_RETRY_DELAY - Duration::from_secs(1), watch.due())
                .await
                .is_err()
        );
        assert_eq!(
            timeout(Duration::from_secs(5), watch.due()).await,
            Ok(Due::Retry)
        );
        assert!(
            timeout(Duration::from_secs(3600), watch.due())
                .await
                .is_err(),
            "a retry is reported once"
        );

        // Stating the shares again before the retry came supersedes it.
        watch.sent(Instant::now());
        assert!(watch.refused(Instant::now()));
        watch.sent(Instant::now());
        assert_eq!(
            timeout(Duration::from_secs(3600), watch.due()).await,
            Ok(Due::AckMissing),
            "only the new ADVERTISE's deadline is left"
        );
    }
}
