//! Hygiene for the member names and roles that reach terminals, logs and addresses.
//!
//! Names and roles are chosen by whoever issues a Policy, and they are printed, typed in
//! `name/service` addresses and compared. The issuer (`menzil-admin`) and every verifier that
//! adopts a member somebody else added (`trust`) hold them to the same rule, so it lives here.

use thiserror::Error;

/// The longest member name: a name is the first part of a `name/service` address, one DNS
/// label's worth.
const MAX_NAME_BYTES: usize = 63;

/// Why a name or a role was refused. The text it carries is escaped (see [`shown`]).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameError {
    /// A name that is not letters, digits, '-', '_' and '.' in the allowed length.
    #[error(
        "member name {0:?} must be 1 to 63 bytes of letters, digits, '-', '_' and '.', starting with a letter or a digit"
    )]
    BadName(String),
    /// A name of eight or more hexadecimal digits, which an address could take for the start
    /// of a node id (`menzil stdio 1a2b3c4d/ssh`).
    #[error(
        "member name {0:?} is eight or more hexadecimal digits only, which could be taken for the start of a node id"
    )]
    NameLooksLikeNodeId(String),
    /// A role that is not letters, digits, '-', '_' and '.'.
    #[error(
        "role {0:?} must be 1 to 63 bytes of letters, digits, '-', '_' and '.', starting with a letter or a digit"
    )]
    BadRole(String),
}

/// A member name heads an address (`name/service`) and shows up in logs and on a terminal, so it
/// is letters, digits, `-`, `_` and `.` only, and starts with a letter or a digit (so it is
/// never `.` or `..`): no `/`, no whitespace, nothing a terminal treats as a control, and none
/// of the invisible characters (a right to left override, a zero width space, the Hangul fillers
/// that are letters printing as nothing: see [`is_invisible`]) that make two names look alike.
/// Letters are not limited to ASCII.
///
/// Public because a device that is handed documents it did not issue has to hold them to the
/// same rule (`menzil join`, and every adoption of a steward's admission): names reach terminals
/// and addresses whoever chose them.
pub fn check_name(name: &str) -> Result<(), NameError> {
    if !usable_word(name) {
        return Err(NameError::BadName(shown(name)));
    }
    // `1a2b3c4d` is a name or the start of a node id, and an address cannot tell which.
    if name.len() >= 8 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NameError::NameLooksLikeNodeId(shown(name)));
    }
    Ok(())
}

/// A role is held to the same characters as a name (it is typed in `role:<role>` and printed),
/// without the rule about node ids.
pub fn check_role(role: &str) -> Result<(), NameError> {
    if usable_word(role) {
        Ok(())
    } else {
        Err(NameError::BadRole(shown(role)))
    }
}

fn usable_word(word: &str) -> bool {
    let letter = |c: char| c.is_alphanumeric() && !is_invisible(c);
    !word.is_empty()
        && word.len() <= MAX_NAME_BYTES
        && word.chars().next().is_some_and(letter)
        && word
            .chars()
            .all(|c| letter(c) || matches!(c, '-' | '_' | '.'))
}

/// Whether `c` is invisible, or acts on the text around it without being a letter: the Unicode
/// format characters (the bidirectional controls, the zero width characters, the soft hyphen,
/// the tag characters) and the other default-ignorable code points (the Hangul fillers, which
/// are letters that print as nothing, the variation selectors, the combining grapheme joiner,
/// the Khmer inherent vowels, the Mongolian selectors). A name made of them can look like
/// another name, and text that holds them prints as less than it says. One table for names and
/// for the text that reaches a terminal, so that the two cannot drift apart (the fourth
/// red-team round, N1: the Hangul fillers passed both).
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// Whether `c` must not reach a terminal or a log as it is: a control character (C0, DEL, C1), a
/// line or paragraph separator, or an invisible one ([`is_invisible`]).
pub fn is_unsafe(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') || is_invisible(c)
}

/// `text` with every unsafe character written out as an escape such as `\u{3164}`: what an error
/// quotes of a name or a role it refused, so that it does not carry the very characters the
/// name was refused for (`{:?}` leaves the Hangul fillers alone: they are letters).
pub fn shown(text: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_roles_follow_the_hygiene_rule() {
        check_name("laptop-2").unwrap();
        check_name("ünlü").unwrap();
        check_role("1a2b3c4d").unwrap();
        for bad in [
            "",
            "-x",
            "a b",
            "a/b",
            "a\u{202e}b",
            "a\u{3164}",
            &"n".repeat(64),
        ] {
            assert!(
                matches!(check_name(bad), Err(NameError::BadName(_))),
                "{bad:?}"
            );
            assert!(
                matches!(check_role(bad), Err(NameError::BadRole(_))),
                "{bad:?}"
            );
        }
        assert!(matches!(
            check_name("1a2b3c4d"),
            Err(NameError::NameLooksLikeNodeId(_))
        ));
    }

    #[test]
    fn a_refused_name_is_quoted_with_its_invisible_characters_escaped() {
        let Err(NameError::BadName(shown)) = check_name("a\u{3164}b c") else {
            panic!("expected BadName");
        };
        assert!(shown.contains("\\u{3164}"), "{shown}");
        assert!(!shown.contains('\u{3164}'));
    }
}
