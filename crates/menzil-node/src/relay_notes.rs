//! What the relay last said about turning this node away (protocol.md 4.2, 7.3).
//!
//! A relay that refuses a HELLO, or ends a session because the node lost its standing in a
//! claimed network (revoked, no longer listed, certificate below the floor), answers with an
//! ERROR record (`revoked`, `not_member`, `stale_serial`, ...) and, for an eviction, a GOAWAY.
//! The session loop reconnects at once and the reason reached only the info log. A
//! [`RelayNotes`] keeps the last such answer, with the time it came, so that whoever runs the
//! node (the CLI's `status`, a refused `stdio`) can tell the person why instead of listing the
//! possible causes.
//!
//! **When it is cleared**: the relay sends WELCOME before it looks at HELLO, so an attach is
//! not known to be good the moment it is made (a "phantom" epoch is followed within a round trip
//! by the ERROR). An attachment that has lasted [`ATTACH_SETTLED`] without being turned away
//! settles, and settling drops what an earlier attachment recorded, provided the attachment
//! claimed every network the node is configured for ([`RelayNotes::settle`]): a node that
//! leaves a network out of HELLO because its own Roster revokes it attaches without it, and that
//! is not a good attach for the network it was turned away from. What the current attachment
//! recorded stays until the next complete one settles.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use menzil_proto::{ErrorBody, ErrorCode};

/// How long an attachment must last, with no ERROR that turns it away, to count as good.
pub const ATTACH_SETTLED: Duration = Duration::from_secs(2);

/// The longest relay message kept, in bytes (cut on a character boundary). The text is the
/// relay's and is shown to a person: whoever shows it makes it printable
/// ([`menzil_cli`'s `text::one_line`]). Bytes, not characters: the text travels over the agent
/// socket in lines of bounded length, and four byte characters would make 256 of them a line of
/// 1024 bytes (round 13 L1).
const MAX_MESSAGE_BYTES: usize = 256;

/// `text` cut to at most `max` bytes, not inside a character.
fn cut_bytes(text: &str, max: usize) -> String {
    let mut end = max.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// One answer of the relay that turned this node away, or ended its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayError {
    /// The code of the ERROR record (`revoked`, `not_member`, `stale_serial`, ...); `None` when
    /// only a GOAWAY came.
    pub code: Option<ErrorCode>,
    /// The ERROR record's free text (empty when only a GOAWAY came).
    pub message: String,
    /// The reason of the GOAWAY that followed in the same attachment, if one did
    /// (`revoked`, `superseded`, ...).
    pub goaway: Option<String>,
    /// When it came, Unix seconds.
    pub at: u64,
}

#[derive(Debug)]
struct Held {
    error: RelayError,
    /// The attachment that recorded it.
    attachment: u64,
}

#[derive(Debug, Default)]
struct Inner {
    last: Option<Held>,
    /// Counts attachments; the current one is the last begun.
    attachment: u64,
    settled: bool,
}

/// The last rejection by the relay, shared between the session loop that notes it and the
/// node that reports it. Cheap to clone; every clone is the same record.
#[derive(Debug, Clone)]
pub struct RelayNotes {
    inner: Arc<Mutex<Inner>>,
    settle_after: Duration,
}

impl Default for RelayNotes {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether `code` says the relay turned this node away (or out), as opposed to refusing one
/// record. `UnknownNetwork` counts only before the attachment settled: later it is the answer to
/// a document sent for a network the relay does not serve, and the session goes on.
/// `UnknownE2e` never counts: protocol.md 4.2 makes it the refusal of one SEND, after which the
/// session goes on (round 13 N3).
fn turns_away(code: ErrorCode, settled: bool) -> bool {
    match code {
        ErrorCode::BadCert
        | ErrorCode::StaleSerial
        | ErrorCode::StaleTimestamp
        | ErrorCode::NotMember
        | ErrorCode::Revoked
        | ErrorCode::RosterExpired => true,
        ErrorCode::UnknownNetwork => !settled,
        _ => false,
    }
}

impl RelayNotes {
    /// An empty record that settles an attachment after [`ATTACH_SETTLED`].
    pub fn new() -> Self {
        Self::with_settle(ATTACH_SETTLED)
    }

    /// [`Self::new`] with another settling time (tests shorten it).
    pub fn with_settle(settle_after: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
            settle_after,
        }
    }

    /// How long an attachment must last to settle.
    pub fn settle_after(&self) -> Duration {
        self.settle_after
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The last answer that turned this node away or ended its session, if it has not been
    /// cleared by a good attachment since.
    pub fn last_error(&self) -> Option<RelayError> {
        self.inner().last.as_ref().map(|held| held.error.clone())
    }

    /// A new attachment begins (its WELCOME came): not yet known to be good.
    pub fn begin_attachment(&self) {
        let mut inner = self.inner();
        inner.attachment += 1;
        inner.settled = false;
    }

    /// The current attachment lasted [`Self::settle_after`] without being turned away. What an
    /// earlier attachment recorded is dropped if `complete` (it claimed every network the node
    /// is configured for); an attachment that left one out keeps it. What this one recorded
    /// stays either way.
    pub fn settle(&self, complete: bool) {
        let mut inner = self.inner();
        inner.settled = true;
        let current = inner.attachment;
        if complete
            && inner
                .last
                .as_ref()
                .is_some_and(|held| held.attachment < current)
        {
            inner.last = None;
        }
    }

    /// An ERROR record arrived at `now` (Unix seconds). Kept when its code says the node was
    /// turned away; a refusal of one record (`forbidden`, `peer_offline`, ...) is not.
    pub fn note_error(&self, body: &ErrorBody, now: u64) {
        let mut inner = self.inner();
        if !turns_away(body.code, inner.settled) {
            return;
        }
        let attachment = inner.attachment;
        inner.last = Some(Held {
            error: RelayError {
                code: Some(body.code),
                message: cut_bytes(&body.msg, MAX_MESSAGE_BYTES),
                goaway: None,
                at: now,
            },
            attachment,
        });
    }

    /// A GOAWAY arrived at `now`. It joins the ERROR of the same attachment (a relay that evicts
    /// sends ERROR `revoked` and then GOAWAY `revoked`); alone it is recorded as it is.
    pub fn note_goaway(&self, reason: &str, now: u64) {
        let mut inner = self.inner();
        let attachment = inner.attachment;
        let reason = cut_bytes(reason, MAX_MESSAGE_BYTES);
        if let Some(held) = inner.last.as_mut()
            && held.attachment == attachment
            && held.error.goaway.is_none()
        {
            held.error.goaway = Some(reason);
            return;
        }
        inner.last = Some(Held {
            error: RelayError {
                code: None,
                message: String::new(),
                goaway: Some(reason),
                at: now,
            },
            attachment,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn error(code: ErrorCode, msg: &str) -> ErrorBody {
        ErrorBody {
            code,
            msg: msg.to_string(),
        }
    }

    #[test]
    fn a_rejection_is_kept_with_its_code_message_and_time() {
        let notes = RelayNotes::new();
        assert_eq!(notes.last_error(), None);
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::Revoked, "node is revoked"), 1_000);
        assert_eq!(
            notes.last_error(),
            Some(RelayError {
                code: Some(ErrorCode::Revoked),
                message: "node is revoked".to_string(),
                goaway: None,
                at: 1_000,
            })
        );
    }

    #[test]
    fn only_answers_that_turn_the_node_away_are_kept() {
        for code in [
            ErrorCode::BadCert,
            ErrorCode::StaleSerial,
            ErrorCode::StaleTimestamp,
            ErrorCode::NotMember,
            ErrorCode::Revoked,
            ErrorCode::RosterExpired,
            ErrorCode::UnknownNetwork,
        ] {
            let notes = RelayNotes::new();
            notes.begin_attachment();
            notes.note_error(&error(code, "x"), 5);
            assert_eq!(notes.last_error().map(|e| e.code), Some(Some(code)));
        }
        for code in [
            ErrorCode::Forbidden,
            ErrorCode::PeerOffline,
            ErrorCode::CreditExceeded,
            ErrorCode::TooLarge,
            ErrorCode::RateLimited,
            ErrorCode::LabelTaken,
            ErrorCode::UnknownType,
            ErrorCode::BadDocument,
            ErrorCode::UnknownE2e,
            ErrorCode::Unknown(999),
        ] {
            let notes = RelayNotes::new();
            notes.begin_attachment();
            notes.note_error(&error(code, "x"), 5);
            assert_eq!(notes.last_error(), None, "{code:?}");
        }
    }

    #[test]
    fn unknown_network_after_the_attachment_settled_is_the_answer_to_a_document() {
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.settle(true);
        notes.note_error(&error(ErrorCode::UnknownNetwork, "not served"), 7);
        assert_eq!(notes.last_error(), None);
        // A new attachment is unsettled again: there it is the HELLO that was refused.
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::UnknownNetwork, "not served"), 8);
        assert!(notes.last_error().is_some());
        // The other codes count at any time (an eviction comes on a settled session).
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.settle(true);
        notes.note_error(&error(ErrorCode::Revoked, "evicted"), 9);
        assert!(notes.last_error().is_some());
    }

    #[test]
    fn a_goaway_joins_the_error_of_the_same_attachment_and_stands_alone_otherwise() {
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::Revoked, "evicted"), 10);
        notes.note_goaway("revoked", 11);
        assert_eq!(
            notes.last_error(),
            Some(RelayError {
                code: Some(ErrorCode::Revoked),
                message: "evicted".to_string(),
                goaway: Some("revoked".to_string()),
                at: 10,
            })
        );
        // A GOAWAY with nothing before it in this attachment.
        notes.begin_attachment();
        notes.note_goaway("superseded", 20);
        assert_eq!(
            notes.last_error(),
            Some(RelayError {
                code: None,
                message: String::new(),
                goaway: Some("superseded".to_string()),
                at: 20,
            })
        );
        // The ERROR of an earlier attachment is not joined by a later GOAWAY.
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::NotMember, "gone"), 30);
        notes.begin_attachment();
        notes.note_goaway("superseded", 31);
        let last = notes.last_error().unwrap();
        assert_eq!(
            (last.code, last.goaway.as_deref()),
            (None, Some("superseded"))
        );
    }

    #[test]
    fn a_newer_answer_replaces_the_older_one() {
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::StaleSerial, "old"), 1);
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::Revoked, "new"), 2);
        let last = notes.last_error().unwrap();
        assert_eq!((last.code, last.at), (Some(ErrorCode::Revoked), 2));
    }

    #[test]
    fn settling_clears_an_earlier_attachments_answer_but_not_the_current_ones() {
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::Revoked, "x"), 1);
        // The same attachment settles after the answer (it was kept up): the answer stays.
        notes.settle(true);
        assert!(notes.last_error().is_some());
        // The next attachment lasts: the earlier answer goes.
        notes.begin_attachment();
        assert!(notes.last_error().is_some(), "not before it settles");
        notes.settle(true);
        assert_eq!(notes.last_error(), None);
    }

    #[test]
    fn an_attachment_that_left_a_network_out_does_not_clear_the_answer() {
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::Revoked, "x"), 1);
        notes.begin_attachment();
        notes.settle(false);
        assert!(notes.last_error().is_some(), "kept");
        // It counts as settled all the same: UnknownNetwork is then a reply to a document.
        notes.note_error(&error(ErrorCode::UnknownNetwork, "not served"), 3);
        assert_eq!(notes.last_error().unwrap().code, Some(ErrorCode::Revoked));
        // The next attachment that claims everything clears it.
        notes.begin_attachment();
        notes.settle(true);
        assert_eq!(notes.last_error(), None);
    }

    /// Round 13 N3: `unknown_e2e` refuses one SEND (protocol.md 4.2); the session goes on, so it
    /// is not a turning away, on a settled attachment or before.
    #[test]
    fn unknown_e2e_is_the_refusal_of_one_send_and_is_not_recorded() {
        for settle in [false, true] {
            let notes = RelayNotes::new();
            notes.begin_attachment();
            if settle {
                notes.settle(true);
            }
            notes.note_error(&error(ErrorCode::UnknownE2e, "unrecognized e2e_proto"), 5);
            assert_eq!(notes.last_error(), None, "settled: {settle}");
        }
        // And it does not push out what the relay said before.
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::Revoked, "evicted"), 1);
        notes.note_error(&error(ErrorCode::UnknownE2e, "x"), 2);
        assert_eq!(notes.last_error().unwrap().at, 1);
    }

    /// Round 13 L1: the cut is by bytes, on a character boundary, never inside a character.
    #[test]
    fn a_long_message_is_cut_by_bytes_on_a_character_boundary() {
        assert_eq!(cut_bytes("abc", 10), "abc");
        assert_eq!(cut_bytes("abc", 3), "abc");
        assert_eq!(cut_bytes("abcd", 3), "abc");
        assert_eq!(cut_bytes("", 3), "");
        // 'é' is two bytes: a cut at 3 keeps one of them whole.
        assert_eq!(cut_bytes("éé", 3), "é");
        assert_eq!(cut_bytes("éé", 4), "éé");
        // A four byte character does not fit in 3 bytes.
        assert_eq!(cut_bytes("\u{1F600}", 3), "");
        let notes = RelayNotes::new();
        notes.begin_attachment();
        let emoji = "\u{1F600}".repeat(5_000);
        notes.note_error(&error(ErrorCode::Revoked, &emoji), 1);
        notes.note_goaway(&emoji, 2);
        let last = notes.last_error().unwrap();
        assert_eq!(last.message.len(), MAX_MESSAGE_BYTES);
        assert_eq!(last.goaway.unwrap().len(), MAX_MESSAGE_BYTES);
        // A goaway alone is cut the same.
        let notes = RelayNotes::new();
        notes.begin_attachment();
        notes.note_goaway(&"é".repeat(1_000), 3);
        assert_eq!(
            notes.last_error().unwrap().goaway.unwrap().len(),
            MAX_MESSAGE_BYTES
        );
    }

    #[test]
    fn a_long_message_is_cut_and_clones_share_the_record() {
        let notes = RelayNotes::new();
        let other = notes.clone();
        notes.begin_attachment();
        notes.note_error(&error(ErrorCode::Revoked, &"é".repeat(1_000)), 1);
        let last = other.last_error().unwrap();
        assert_eq!(last.message.len(), MAX_MESSAGE_BYTES);
        other.note_goaway(&"g".repeat(1_000), 2);
        assert_eq!(
            notes.last_error().unwrap().goaway.unwrap().len(),
            MAX_MESSAGE_BYTES
        );
    }
}
