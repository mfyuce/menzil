//! `menzil steward request|add|remove` and `admit`/`renew` with a steward key, as processes: the
//! wiring of `main.rs` (TODO L4j S3). The unit tests in `local::tests` cover what the commands do.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

/// Runs `menzil --home <home> <args>`, with `stdin` given to it when there is any.
fn menzil(home: &Path, args: &[&str], stdin: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_menzil"))
        .arg("--home")
        .arg(home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    Output {
        ok: out.status.success(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

/// The line of `text` that starts with `prefix`.
fn token(text: &str, prefix: &str) -> String {
    text.lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix} line in {text}"))
        .to_string()
}

fn ok(output: Output) -> Output {
    assert!(
        output.ok,
        "stdout: {}\nstderr: {}",
        output.stdout, output.stderr
    );
    output
}

#[test]
fn a_steward_is_requested_listed_used_and_removed_from_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, steward, phone) = (
        dir.path().join("owner"),
        dir.path().join("steward"),
        dir.path().join("phone"),
    );
    ok(menzil(&owner, &["init"], None));
    ok(menzil(&owner, &["network", "create"], None));
    let steward_join = token(
        &ok(menzil(&steward, &["init"], None)).stdout,
        "menzil1-join:",
    );
    let phone_join = token(&ok(menzil(&phone, &["init"], None)).stdout, "menzil1-join:");

    // The steward device is a member, then asks to be the steward.
    let admitted = ok(menzil(
        &owner,
        &["admit", "-", "--name", "steward"],
        Some(&steward_join),
    ));
    ok(menzil(
        &steward,
        &["join", "-"],
        Some(&token(&admitted.stdout, "menzil1-docs:")),
    ));
    let asked = ok(menzil(&steward, &["steward", "request"], None));
    let request = token(&asked.stdout, "menzil1-steward:");
    // Asking again prints the same request.
    let again = ok(menzil(&steward, &["steward", "request"], None));
    assert_eq!(token(&again.stdout, "menzil1-steward:"), request);
    assert!(again.stdout.contains("already"), "{}", again.stdout);

    // The owner lists it: defaults are both rights and a month.
    let added = ok(menzil(&owner, &["steward", "add", "-"], Some(&request)));
    assert!(added.stdout.contains("listed steward"), "{}", added.stdout);
    ok(menzil(
        &steward,
        &["join", "-"],
        Some(&token(&added.stdout, "menzil1-docs:")),
    ));
    let status = ok(menzil(&steward, &["status"], None)).stdout;
    assert!(
        status.contains("steward") && status.contains("(this device)"),
        "{status}"
    );

    // Days out of range and rights that do not exist are refused with a message.
    let bad_days = menzil(
        &owner,
        &["steward", "add", "-", "--days", "91"],
        Some(&request),
    );
    assert!(
        !bad_days.ok && bad_days.stderr.contains("1 to 90 days"),
        "{}",
        bad_days.stderr
    );
    let bad_right = menzil(
        &owner,
        &["steward", "add", "-", "--may", "grant"],
        Some(&request),
    );
    assert!(
        !bad_right.ok && bad_right.stderr.contains("admit"),
        "{}",
        bad_right.stderr
    );

    // With the defaults it may renew as it stands (a renewal that appends nobody needs `renew`).
    let first = ok(menzil(&steward, &["renew"], None));
    assert!(first.stdout.contains("renewed"), "{}", first.stdout);

    // The steward admits the phone (no roles) and renews; the phone joins on the token alone.
    let refused = menzil(
        &steward,
        &["admit", "-", "--name", "phone", "--role", "admin"],
        Some(&phone_join),
    );
    assert!(
        !refused.ok && refused.stderr.contains("without roles"),
        "{}",
        refused.stderr
    );
    let by_steward = ok(menzil(
        &steward,
        &["admit", "-", "--name", "phone"],
        Some(&phone_join),
    ));
    let joined = ok(menzil(
        &phone,
        &["join", "-"],
        Some(&token(&by_steward.stdout, "menzil1-docs:")),
    ));
    assert!(
        joined.stdout.contains("joined network"),
        "{}",
        joined.stdout
    );
    let renewed = ok(menzil(&steward, &["renew"], None));
    assert!(renewed.stdout.contains("renewed"), "{}", renewed.stdout);
    // The relay token of the steward's documents carries the base.
    let relay = ok(menzil(&steward, &["token", "--for-relay"], None)).stdout;
    assert!(relay.trim().starts_with("menzil1-roster:"));

    // The phone is no steward and no owner.
    let denied = menzil(&phone, &["renew"], None);
    assert!(
        !denied.ok && denied.stderr.contains("does not own"),
        "{}",
        denied.stderr
    );

    // The owner takes the steward's documents, removes the steward; the steward cannot renew.
    ok(menzil(
        &owner,
        &["join", "-"],
        Some(&token(&by_steward.stdout, "menzil1-docs:")),
    ));
    let removed = ok(menzil(&owner, &["steward", "remove"], None));
    assert!(
        removed.stdout.contains("removed the steward"),
        "{}",
        removed.stdout
    );
    ok(menzil(
        &steward,
        &["join", "-"],
        Some(&token(&removed.stdout, "menzil1-docs:")),
    ));
    let stuck = menzil(&steward, &["renew"], None);
    assert!(
        !stuck.ok && stuck.stderr.contains("lists no steward"),
        "{}",
        stuck.stderr
    );
    let again = menzil(&owner, &["steward", "remove"], None);
    assert!(
        !again.ok && again.stderr.contains("lists no steward"),
        "{}",
        again.stderr
    );
}
