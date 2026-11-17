//! `menzil relay add-network --tenant`, `tenants`, `remove-network` and `remove-tenant` as
//! processes: the wiring of `main.rs` (multi tenant slice MT6). The unit tests in
//! `relay_cmd::tests` cover what the commands do.

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
    menzil_env(home, args, stdin, None)
}

/// [`menzil`] with `MENZIL_RELAY_AUDIT_FILE` set to `audit` when given.
fn menzil_env(home: &Path, args: &[&str], stdin: Option<&str>, audit: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_menzil"));
    if let Some(audit) = audit {
        command.env("MENZIL_RELAY_AUDIT_FILE", audit);
    }
    let mut child = command
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

fn ok(output: Output) -> Output {
    assert!(
        output.ok,
        "stdout: {}\nstderr: {}",
        output.stdout, output.stderr
    );
    output
}

/// An owner's home with a network; the relay token it gives an operator, and the network id.
fn network(dir: &Path, name: &str) -> (String, String) {
    let owner = dir.join(name);
    ok(menzil(&owner, &["init"], None));
    let created = ok(menzil(&owner, &["network", "create"], None)).stdout;
    let id = created
        .strip_prefix("created network ")
        .and_then(|rest| rest.split_whitespace().next())
        .unwrap_or_else(|| panic!("no network id in {created}"))
        .to_string();
    let token = ok(menzil(&owner, &["token", "--for-relay"], None))
        .stdout
        .trim()
        .to_string();
    (token, id)
}

#[test]
fn tenants_are_added_listed_and_removed_from_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let relay = dir.path().join("relay");
    ok(menzil(&relay, &["init"], None));
    let (token_a, id_a) = network(dir.path(), "owner-a");
    let (token_b, id_b) = network(dir.path(), "owner-b");

    let added = ok(menzil(
        &relay,
        &["relay", "add-network", "-", "--tenant", "ali"],
        Some(&token_a),
    ));
    assert!(
        added.stdout.contains(&format!("network {id_a}")) && added.stdout.contains("tenant ali"),
        "{}",
        added.stdout
    );
    // Without --tenant the network is the default tenant's, and that is the old behaviour.
    let plain = ok(menzil(&relay, &["relay", "add-network", &token_b], None));
    assert!(!plain.stdout.contains("tenant"), "{}", plain.stdout);

    let listing = ok(menzil(&relay, &["relay", "tenants"], None)).stdout;
    assert!(
        listing.contains("tenant ali  class friend  networks 1/3"),
        "{listing}"
    );
    assert!(
        listing.contains("tenant (default)  class personal  networks 1"),
        "{listing}"
    );

    // A bad name and a network moved by --tenant are errors with a message.
    let bad = menzil(
        &relay,
        &["relay", "add-network", "-", "--tenant", "Www"],
        Some(&token_a),
    );
    assert!(!bad.ok && !bad.stderr.is_empty());
    let moved = menzil(
        &relay,
        &["relay", "add-network", "-", "--tenant", "veli"],
        Some(&token_a),
    );
    assert!(
        !moved.ok && moved.stderr.contains("already in tenant ali"),
        "{}",
        moved.stderr
    );

    ok(menzil(&relay, &["relay", "remove-network", &id_b], None));
    let after = ok(menzil(&relay, &["relay", "tenants"], None)).stdout;
    assert!(
        after.contains("tenant (default)  class personal  networks 0"),
        "{after}"
    );
    assert!(!menzil(&relay, &["relay", "remove-network", &id_b], None).ok);

    let removed = ok(menzil(&relay, &["relay", "remove-tenant", "ali"], None));
    assert!(removed.stdout.contains("1 network"), "{}", removed.stdout);
    let gone = ok(menzil(&relay, &["relay", "tenants"], None)).stdout;
    assert!(
        !gone.contains("tenant ali") && gone.contains("quarantine: ali"),
        "{gone}"
    );
    assert!(!menzil(&relay, &["relay", "remove-tenant", "ali"], None).ok);
}

/// With `MENZIL_RELAY_AUDIT_FILE` the tenant commands append their events to that file.
#[test]
fn tenant_commands_write_audit_events() {
    let dir = tempfile::tempdir().unwrap();
    let relay = dir.path().join("relay");
    let audit = dir.path().join("audit.jsonl");
    ok(menzil(&relay, &["init"], None));
    let (token, id) = network(dir.path(), "owner-a");
    let run = |args: &[&str], stdin: Option<&str>| {
        ok(menzil_env(&relay, args, stdin, Some(&audit)));
    };
    run(
        &["relay", "add-network", "-", "--tenant", "ali"],
        Some(&token),
    );
    run(&["relay", "suspend-tenant", "ali"], None);
    run(&["relay", "suspend-tenant", "ali"], None);
    run(&["relay", "resume-tenant", "ali"], None);
    run(&["relay", "remove-tenant", "ali"], None);
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let evs: Vec<&str> = lines.iter().map(|l| l["ev"].as_str().unwrap()).collect();
    // The second suspend changed nothing and writes nothing.
    assert_eq!(
        evs,
        [
            "network_added",
            "tenant_suspended",
            "tenant_resumed",
            "tenant_removed"
        ]
    );
    assert_eq!(lines[0]["network"], id);
    assert_eq!(lines[0]["tenant"], "ali");
    assert_eq!(lines[0]["by"], "relay");
    assert_eq!(lines[3]["networks"], serde_json::json!([id]));
}
