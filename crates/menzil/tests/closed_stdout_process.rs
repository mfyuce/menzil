//! A reader that goes away early (`menzil status | grep -q`, `| head -1`) must not make a command
//! panic: the standard print macros do, so `main.rs` has its own.

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn menzil(home: &Path, args: &[&str], stdout: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_menzil"))
        .arg("--home")
        .arg(home)
        .args(args)
        .env("XDG_RUNTIME_DIR", home)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

/// The writing end of a pipe nobody reads: every write to it fails with a broken pipe.
fn nobody_reads() -> Stdio {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    writer.into()
}

#[test]
fn commands_end_normally_when_their_reader_has_gone() {
    let dir = tempfile::tempdir().unwrap();
    for args in [&["init"][..], &["join-request"], &["status"]] {
        let out = menzil(dir.path(), args, nobody_reads());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{args:?}: {:?}\n{stderr}", out.status);
        assert!(!stderr.contains("panicked"), "{args:?}: {stderr}");
    }
    // The commands did their work all the same, and still print to a reader that is there.
    let out = menzil(dir.path(), &["join-request"], Stdio::piped());
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("menzil1-join:"));
}
