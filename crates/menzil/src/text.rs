//! Text that came from somewhere else and is about to reach a terminal or a log: a peer's
//! refusal message, what a socket's owner answers, the names and roles an owner signed.
//!
//! A terminal treats some characters as commands (escape sequences that set the title, clear the
//! screen or write to the clipboard) and some as disguise (a right to left override that makes a
//! file name read backwards, a zero width space that makes two names look alike). Nothing that is
//! not ours is printed without passing through here.

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
}
