//! `menzil cert [show|renew|request|accept]` as processes: the wiring of `main.rs` (cert
//! rotation S6). The unit tests in `local::tests`, `cert_node::tests` and `agent::tests` cover
//! what the commands do; here, that the command line reaches them. A renewal with no node
//! running writes the file under the node lock and leaves the key file as it was.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

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
fn a_certificate_is_shown_renewed_without_a_node_and_listed_by_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, phone) = (dir.path().join("owner"), dir.path().join("phone"));
    ok(menzil(&owner, &["init"], None));
    ok(menzil(&owner, &["network", "create"], None));
    let phone_join = token(&ok(menzil(&phone, &["init"], None)).stdout, "menzil1-join:");
    let admitted = ok(menzil(
        &owner,
        &["admit", "-", "--name", "phone"],
        Some(&phone_join),
    ));
    ok(menzil(
        &phone,
        &["join", "-"],
        Some(&token(&admitted.stdout, "menzil1-docs:")),
    ));

    // `menzil cert` alone shows; `request` prints the token for the current certificate.
    let shown = ok(menzil(&phone, &["cert"], None)).stdout;
    assert!(shown.contains("certificate serial 1"), "{shown}");
    assert!(
        shown.contains("the current certificate is listed"),
        "{shown}"
    );
    let explicit = ok(menzil(&phone, &["cert", "show"], None)).stdout;
    assert_eq!(explicit, shown);
    let current = token(
        &ok(menzil(&phone, &["cert", "request"], None)).stdout,
        "menzil1-cert:",
    );
    // Accepting the certificate that is listed already is refused, nothing changes.
    let refused = menzil(&owner, &["cert", "accept", &current], None);
    assert!(!refused.ok, "{}", refused.stdout);
    assert!(refused.stderr.contains("serial"), "{}", refused.stderr);

    // Renewal with no node: the file is written, the key file is byte for byte as it was.
    let key = std::fs::read(phone.join("identity.key")).unwrap();
    let renewed = ok(menzil(&phone, &["cert", "renew"], None));
    assert!(
        renewed.stdout.contains("no node is running"),
        "{}",
        renewed.stdout
    );
    assert!(renewed.stdout.contains("serial 2"), "{}", renewed.stdout);
    let renewed_token = token(&renewed.stdout, "menzil1-cert:");
    assert_ne!(renewed_token, current);
    assert_eq!(std::fs::read(phone.join("identity.key")).unwrap(), key);
    let shown = ok(menzil(&phone, &["cert"], None)).stdout;
    assert!(shown.contains("certificate serial 2"), "{shown}");
    assert!(shown.contains("NOT listed"), "{shown}");
    assert_eq!(
        token(
            &ok(menzil(&phone, &["cert", "request"], None)).stdout,
            "menzil1-cert:"
        ),
        renewed_token
    );

    // A join request is the wrong kind of token for `cert accept`.
    let wrong = menzil(&owner, &["cert", "accept", &phone_join], None);
    assert!(!wrong.ok);
    assert!(wrong.stderr.contains("menzil1-cert:"), "{}", wrong.stderr);

    // The owner lists it (from standard input), the phone takes the documents.
    let accepted = ok(menzil(
        &owner,
        &["cert", "accept", "-"],
        Some(&renewed_token),
    ));
    assert!(
        accepted.stdout.contains("listed the renewed certificate"),
        "{}",
        accepted.stdout
    );
    ok(menzil(
        &phone,
        &["join", "-"],
        Some(&token(&accepted.stdout, "menzil1-docs:")),
    ));
    let shown = ok(menzil(&phone, &["cert"], None)).stdout;
    assert!(shown.contains("lists serial 2"), "{shown}");
    assert!(
        shown.contains("the current certificate is listed"),
        "{shown}"
    );
}

#[test]
fn a_new_identity_prints_the_replace_line_and_the_owner_runs_it() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, phone) = (dir.path().join("owner"), dir.path().join("phone"));
    ok(menzil(&owner, &["init"], None));
    ok(menzil(&owner, &["network", "create"], None));
    let phone_join = token(&ok(menzil(&phone, &["init"], None)).stdout, "menzil1-join:");
    let admitted = ok(menzil(
        &owner,
        &["admit", "-", "--name", "phone"],
        Some(&phone_join),
    ));
    ok(menzil(
        &phone,
        &["join", "-"],
        Some(&token(&admitted.stdout, "menzil1-docs:")),
    ));

    // Plain `init` still refuses, and its message names the flag.
    let refused = menzil(&phone, &["init"], None);
    assert!(!refused.ok);
    assert!(
        refused.stderr.contains("--new-identity"),
        "{}",
        refused.stderr
    );

    let key = std::fs::read(phone.join("identity.key")).unwrap();
    let done = ok(menzil(&phone, &["init", "--new-identity"], None));
    let new_join = token(&done.stdout, "menzil1-join:");
    assert_ne!(new_join, phone_join);
    assert_eq!(std::fs::read_dir(phone.join("retired")).unwrap().count(), 2);
    assert!(
        std::fs::read_dir(phone.join("retired"))
            .unwrap()
            .any(|entry| std::fs::read(entry.unwrap().path()).unwrap() == key),
        "the old key is in retired/"
    );
    // The line for the owner names the network, the old name and the new join request.
    let line = done
        .stdout
        .lines()
        .find(|line| line.contains("menzil admit --network"))
        .unwrap_or_else(|| panic!("no replace line in {}", done.stdout))
        .trim()
        .to_string();
    assert!(line.contains("--replace phone"), "{line}");
    assert!(line.ends_with(&new_join), "{line}");

    // `--replace` takes no `--name`, and `admit` needs one or the other.
    let both = menzil(
        &owner,
        &["admit", "-", "--name", "x", "--replace", "phone"],
        Some(&new_join),
    );
    assert!(!both.ok);
    let neither = menzil(&owner, &["admit", "-"], Some(&new_join));
    assert!(!neither.ok);

    // The owner runs what the line says (with the join request from standard input).
    let replaced = ok(menzil(
        &owner,
        &["admit", "--replace", "phone", "-"],
        Some(&new_join),
    ));
    assert!(
        replaced.stdout.contains("which is revoked"),
        "{}",
        replaced.stdout
    );
    ok(menzil(
        &phone,
        &["join", "-"],
        Some(&token(&replaced.stdout, "menzil1-docs:")),
    ));
    let shown = ok(menzil(&phone, &["status"], None)).stdout;
    assert!(shown.contains("phone"), "{shown}");
}
