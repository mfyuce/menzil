//! `menzil relay status [--json]` as a process: the wiring of `main.rs` and what it says when the
//! relay's status file is missing or old. What the file holds is tested in `relay_cmd::status`.

use std::path::Path;
use std::process::Command;

use menzil_cli::home::Home;
use menzil_cli::relay_cmd::status::{self, DEFAULT_KEY, StatusDoc, TenantEntry};

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
        .output()
        .unwrap();
    Output {
        ok: out.status.success(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn doc(generated_unix: u64) -> StatusDoc {
    let entry = |n: u32| TenantEntry {
        attached_sessions: n,
        live_pairs: n + 1,
        bytes_period: 1_000 * u64::from(n),
        names: n + 2,
        period_end_unix: 1_900_000_000,
    };
    StatusDoc {
        version: status::VERSION,
        generated_unix,
        tenants: [("alpha", entry(3)), (DEFAULT_KEY, entry(1))]
            .into_iter()
            .map(|(key, entry)| (key.to_string(), entry))
            .collect(),
    }
}

#[test]
fn relay_status_prints_the_exported_document_and_refuses_a_missing_or_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("relay");
    let missing = menzil(&home, &["relay", "status"]);
    assert!(!missing.ok);
    assert!(
        missing.stderr.contains("has not exported its status"),
        "{}",
        missing.stderr
    );

    let current = doc(now());
    status::write(&Home::new(&home), &current).unwrap();
    let json = menzil(&home, &["relay", "status", "--json"]);
    assert!(json.ok, "{}", json.stderr);
    assert_eq!(json.stdout, current.render());
    assert_eq!(StatusDoc::parse(json.stdout.as_bytes()).unwrap(), current);

    let human = menzil(&home, &["relay", "status"]);
    assert!(human.ok, "{}", human.stderr);
    assert!(human.stdout.contains("(default)"), "{}", human.stdout);
    assert!(human.stdout.contains("alpha"), "{}", human.stdout);
    assert!(!human.stdout.contains("_default"), "{}", human.stdout);

    status::write(&Home::new(&home), &doc(now() - 120)).unwrap();
    for args in [&["relay", "status"][..], &["relay", "status", "--json"][..]] {
        let old = menzil(&home, args);
        assert!(!old.ok);
        assert!(old.stdout.is_empty(), "nothing is printed for an old file");
        assert!(old.stderr.contains("out of date"), "{}", old.stderr);
    }
}
