// Included by both crate roots (`lib.rs` and `main.rs`) ahead of every other module.

/// Shadows the standard macro, which panics when standard error cannot be written: a reader that
/// has gone (`menzil status 2>&1 | grep -q`) must neither change a command's exit status nor end
/// a running role. There is nowhere left to report the failure, so it is dropped.
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        // One write for the whole line, so that lines of concurrent tasks do not interleave.
        let line = format!("{}\n", format_args!($($arg)*));
        let _ = std::io::stderr().write_all(line.as_bytes());
    }};
}
