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
//! Not here: who may use an accepted share (the relay principal's authorizer is a later slice).
//! This module only records what the relay accepted and answers [`ShareBook::accepted_service`].
//!
//! The ACK names no network (the relay judges a name against every network the session claimed),
//! so the book is per relay attachment, not per network.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use menzil_proto::{
    AdvertiseAckBody, AdvertiseBody, RejectedShare, ServiceId, ServiceKind, Share, ShareMode,
};
use tokio::sync::watch;

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
        Self {
            inner: Arc::new(Inner {
                configured,
                state: Mutex::new(State::default()),
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

    /// An ADVERTISE with `shares` is about to be sent.
    pub(crate) fn note_sent(&self, shares: &[Share]) {
        let mut state = self.state();
        state.snapshot.sent = shares.to_vec();
        // The relay's answer to the one before no longer describes what was just asked; the
        // accepted set stays until the new answer, because the relay's claims do too.
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
    }

    /// The attachment ended: the relay's claims ended with it.
    pub(crate) fn note_detached(&self) {
        self.state().snapshot = ShareSnapshot::default();
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
}
