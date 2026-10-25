//! Text that came from somewhere else and is about to reach a terminal or a log: a peer's
//! refusal message, what a socket's owner answers, the names and roles an owner signed.
//!
//! A terminal treats some characters as commands (escape sequences that set the title, clear the
//! screen or write to the clipboard) and some as disguise (a right to left override that makes a
//! file name read backwards, a zero width space that makes two names look alike). Nothing that is
//! not ours is printed without passing through here.

/// What a person is told when a stream or a session ended and the reason is not on the wire. The
/// other device ends a session with one uniform CLOSE `grant_removed` whatever the cause (protocol
/// 5.3: the peer was revoked, left the Policy, lost its certificate, or the grant is gone), and a
/// relay turns a revoked device away with ERROR and GOAWAY `revoked` (protocol 7.3); neither says
/// more, so the words name the causes and where to look.
pub const CUT_OFF: &str = "a member that was revoked, or whose grant was taken back, is cut off at once (the other device ends the session with CLOSE grant_removed, and a relay turns a revoked device away with ERROR and GOAWAY revoked); `menzil status` shows what this device still holds";

/// When the relay turned the device away, in words: "just now" under a minute, else "3 minutes
/// ago" and so on. A time in the future (the clocks differ) reads as "just now".
fn ago(at: u64, now: u64) -> String {
    if now.saturating_sub(at) < 60 {
        "just now".to_string()
    } else {
        crate::local::relative(at, now)
    }
}

/// What the relay's ERROR code means for this device, in plain words, and what to do about it.
fn code_meaning(code: &str) -> (&'static str, &'static str) {
    match code {
        "revoked" => (
            "this device is revoked in a network it claimed",
            "the owner of that network revoked it; ask the owner whether that was meant",
        ),
        "not_member" => (
            "this device is not listed as a member of a network it claimed",
            "it was removed, or never admitted; ask the owner to admit it, then `menzil join` the new token",
        ),
        "stale_serial" => (
            "the certificate of this device is older than the owner allows",
            "a newer one was issued; `menzil join` a current token",
        ),
        "stale_timestamp" => (
            "the relay did not accept the time of this device's HELLO",
            "check that the clock of this device is right",
        ),
        "bad_cert" => (
            "the relay could not verify the certificate of this device",
            "`menzil join` a current token",
        ),
        "unknown_network" => (
            "the relay does not serve a network this device claimed",
            "check `relay` in config.toml and that the owner added the network to this relay",
        ),
        "roster_expired" => (
            "the documents of a network this device claimed have expired at the relay",
            "the owner or the steward has to issue new ones",
        ),
        _ => ("the relay refused this device", "see the relay's own words"),
    }
}

/// The relay's last rejection in words for a person: what it said, what that means, when, and
/// what to do. The relay's own text is cut to one printable line. One line, no newline.
pub fn turned_away(rejected: &crate::agent::Rejected, now: u64) -> String {
    let when = if rejected.at == 0 {
        String::new()
    } else {
        format!(", {}", ago(rejected.at, now))
    };
    let told = if rejected.message.is_empty() {
        String::new()
    } else {
        format!("; the relay said \"{}\"", one_line(&rejected.message, 200))
    };
    let goaway = rejected.goaway.as_deref().map(|g| one_line(g, 100));
    match (&rejected.code, goaway) {
        (Some(code), goaway) => {
            let (meaning, advice) = code_meaning(code);
            let then = goaway.map_or_else(String::new, |g| {
                format!("; it then ended the session (GOAWAY {g})")
            });
            format!(
                "the relay turned this device away: {meaning} ({}{when}{told}){then}. {advice}",
                one_line(code, 40)
            )
        }
        (None, Some(goaway)) => {
            format!("the relay ended the session of this device (GOAWAY {goaway}{when})")
        }
        (None, None) => format!("the relay turned this device away{when}"),
    }
}

/// Whether `c` must not reach a terminal as it is: a control character (C0, DEL, C1), a line or
/// paragraph separator, or an invisible one (the format characters such as the bidirectional
/// controls, zero width characters, the soft hyphen, the annotation marks and the tag
/// characters, and the other default-ignorable code points such as the Hangul fillers and the
/// variation selectors). The rule is the admin crate's, which holds names to it too.
pub fn is_unsafe(c: char) -> bool {
    menzil_admin::is_unsafe(c)
}

/// `text` with every unsafe character written out as an escape such as `\u{1b}`: nothing is
/// lost silently, and nothing acts. For text that stays what it is (a name in a listing).
pub fn escaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_unsafe(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// `message` as one line of at most `limit` characters, each unsafe character (a newline
/// included) turned into a space: what goes after `menzil: ` or `error ` on one line.
pub fn one_line(message: &str, limit: usize) -> String {
    message
        .chars()
        .map(|c| if is_unsafe(c) { ' ' } else { c })
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_invisible_format_characters_are_unsafe() {
        for c in [
            '\u{0}',
            '\u{7}',
            '\u{8}',
            '\n',
            '\r',
            '\u{1b}',
            '\u{7f}',
            '\u{85}',
            '\u{9b}',
            '\u{ad}',
            '\u{61c}',
            '\u{200b}',
            '\u{200d}',
            '\u{200e}',
            '\u{200f}',
            '\u{2028}',
            '\u{2029}',
            '\u{202a}',
            '\u{202e}',
            '\u{2060}',
            '\u{2066}',
            '\u{2069}',
            '\u{206f}',
            '\u{feff}',
            '\u{fff9}',
            '\u{fffb}',
            // The fourth red-team round, N1: letters that print as nothing, and the tag block.
            '\u{3164}',
            '\u{115f}',
            '\u{1160}',
            '\u{ffa0}',
            '\u{34f}',
            '\u{fe0f}',
            '\u{600}',
            '\u{e0001}',
            '\u{e0041}',
            '\u{e007f}',
        ] {
            assert!(is_unsafe(c), "{c:?}");
        }
        for c in [
            'a',
            'Z',
            '0',
            ' ',
            '-',
            '_',
            '.',
            '/',
            'ü',
            'ğ',
            'あ',
            '\u{1f600}',
            '\u{200a}',
        ] {
            assert!(!is_unsafe(c), "{c:?}");
        }
    }

    #[test]
    fn escaping_keeps_everything_visible_and_changes_only_what_acts() {
        assert_eq!(escaped("laptop"), "laptop");
        assert_eq!(escaped("ünlü ağ"), "ünlü ağ");
        assert_eq!(escaped("a\u{1b}]52;c;x\u{7}b"), "a\\u{1b}]52;c;x\\u{7}b");
        assert_eq!(escaped("x\u{202e}gpj"), "x\\u{202e}gpj");
        assert_eq!(escaped("new\nline"), "new\\u{a}line");
    }

    #[test]
    fn one_line_is_one_short_printable_line() {
        assert_eq!(one_line("a\nb\u{1b}[2Jc\u{202e}d", 100), "a b [2Jc d");
        assert_eq!(one_line("abcdef", 3), "abc");
        assert_eq!(one_line("", 3), "");
        // The limit counts characters, not bytes.
        assert_eq!(one_line("ğğğğ", 2), "ğğ");
    }

    #[test]
    fn ago_does_not_overflow_near_the_end_of_the_range() {
        assert_eq!(ago(u64::MAX, 1_700_000_000), "just now");
        assert_eq!(ago(u64::MAX - 59, u64::MAX), "just now");
        assert_eq!(ago(u64::MAX, u64::MAX), "just now");
        assert_eq!(ago(1_000, 1_000 + 180), "3 minutes ago");
        assert_eq!(ago(1_000 + 60, 1_000 + 60 + 59), "just now");
    }

    fn rejected(code: Option<&str>, goaway: Option<&str>, message: &str) -> crate::agent::Rejected {
        crate::agent::Rejected {
            at: 1_000,
            code: code.map(str::to_string),
            message: message.to_string(),
            goaway: goaway.map(str::to_string),
        }
    }

    #[test]
    fn a_rejection_is_told_with_its_meaning_when_and_what_to_do() {
        for (code, meaning, advice) in [
            ("revoked", "is revoked", "ask the owner"),
            (
                "not_member",
                "not listed as a member",
                "ask the owner to admit",
            ),
            (
                "stale_serial",
                "older than the owner allows",
                "`menzil join`",
            ),
            ("stale_timestamp", "HELLO", "clock"),
            ("bad_cert", "could not verify", "`menzil join`"),
            (
                "unknown_network",
                "does not serve",
                "`relay` in config.toml",
            ),
            ("roster_expired", "have expired", "steward"),
            ("something_new", "refused this device", "relay's own words"),
        ] {
            let text = turned_away(&rejected(Some(code), None, ""), 1_000 + 180);
            assert!(
                text.starts_with("the relay turned this device away: ")
                    && text.contains(meaning)
                    && text.contains(advice)
                    && text.contains(&format!("({code}, 3 minutes ago)")),
                "{code}: {text}"
            );
        }
    }

    #[test]
    fn the_relays_own_words_and_the_goaway_are_added_and_stay_on_one_line() {
        let text = turned_away(
            &rejected(
                Some("revoked"),
                Some("revoked"),
                "node\nis\u{1b}[2J revoked",
            ),
            1_010,
        );
        assert!(
            text.contains("just now")
                && text.contains("the relay said \"node is [2J revoked\"")
                && text.contains("it then ended the session (GOAWAY revoked)"),
            "{text}"
        );
        assert!(!text.contains('\n') && !text.contains('\u{1b}'), "{text:?}");
        let alone = turned_away(&rejected(None, Some("superseded"), ""), 1_000 + 7_200);
        assert_eq!(
            alone,
            "the relay ended the session of this device (GOAWAY superseded, 2 hours ago)"
        );
        // No time known, no clause for it.
        let mut unknown = rejected(Some("revoked"), None, "");
        unknown.at = 0;
        assert!(turned_away(&unknown, 5_000).contains("(revoked)"));
    }
}
