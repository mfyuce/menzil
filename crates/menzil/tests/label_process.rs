//! `menzil label add|remove|list` as processes: the wiring of `main.rs` and the words it prints
//! (what a relay needs before it accepts a public name). The unit tests in `local::tests` cover
//! what the commands do.

use std::path::Path;
use std::process::{Command, Stdio};

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn menzil(home: &Path, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_menzil"))
        .arg("--home")
        .arg(home)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Output {
        ok: out.status.success(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
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
fn a_label_is_given_listed_moved_and_taken_back_from_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, phone) = (dir.path().join("owner"), dir.path().join("phone"));
    ok(menzil(&owner, &["init"]));
    ok(menzil(&owner, &["network", "create", "--name", "laptop"]));
    let joined = ok(menzil(&phone, &["init"])).stdout;
    let join_request = joined
        .lines()
        .find(|l| l.starts_with("menzil1-join:"))
        .unwrap()
        .to_string();
    ok(menzil(&owner, &["admit", &join_request, "--name", "phone"]));

    // Nothing yet.
    assert!(
        ok(menzil(&owner, &["label", "list"]))
            .stdout
            .contains("no labels")
    );

    // Add: the words say what happened and what the relay and the members need.
    let added = ok(menzil(&owner, &["label", "add", "myapp", "phone"])).stdout;
    assert!(
        added.contains("label myapp now belongs to phone")
            && added.contains("documents are now #3")
            && added.contains("menzil token --for-relay")
            && added.contains("within 15 seconds")
            && added.lines().any(|l| l.starts_with("menzil1-docs:")),
        "{added}"
    );
    let listed = ok(menzil(&owner, &["label", "list"])).stdout;
    assert_eq!(listed.trim(), "myapp  phone", "{listed}");

    // Refusals are plain, exit non zero, and print no token.
    for (args, words) in [
        (&["label", "add", "Myapp", "phone"][..], "lowercase"),
        (&["label", "add", "www", "phone"], "reserved"),
        (&["label", "add", "web", "tablet"], "no member called"),
        (
            &["label", "add", "myapp", "laptop"],
            "belongs to another member",
        ),
        (&["label", "remove", "nope"], "no label matches"),
    ] {
        let refused = menzil(&owner, args);
        assert!(
            !refused.ok && refused.stderr.contains(words) && !refused.stdout.contains("menzil1-"),
            "{args:?}: {}",
            refused.stderr
        );
    }

    // The explicit move, then the name goes back.
    let moved = ok(menzil(
        &owner,
        &["label", "add", "myapp", "laptop", "--replace"],
    ))
    .stdout;
    assert!(
        moved.contains("label myapp now belongs to laptop") && moved.contains("moved from phone"),
        "{moved}"
    );
    assert_eq!(
        ok(menzil(&owner, &["label", "list"])).stdout.trim(),
        "myapp  laptop"
    );
    let removed = ok(menzil(&owner, &["label", "remove", "myapp", "laptop"])).stdout;
    assert!(
        removed.contains("took label myapp back") && removed.contains("documents are now #5"),
        "{removed}"
    );
    assert!(
        ok(menzil(&owner, &["label", "list"]))
            .stdout
            .contains("no labels")
    );

    // The phone holds no owner key: refused, in words about the owner.
    let phone_docs = ok(menzil(&owner, &["token"])).stdout;
    let token = phone_docs
        .lines()
        .find(|l| l.starts_with("menzil1-docs:"))
        .unwrap();
    ok(menzil(&phone, &["join", token]));
    let refused = menzil(&phone, &["label", "add", "web", "phone"]);
    assert!(
        !refused.ok && refused.stderr.contains("does not own"),
        "{}",
        refused.stderr
    );
    // `--help` names the command and its subcommands.
    let help = ok(menzil(&owner, &["label", "--help"])).stdout;
    for word in ["add", "remove", "list", "Roster"] {
        assert!(help.contains(word), "{word}: {help}");
    }
}
