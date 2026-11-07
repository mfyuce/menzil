use std::path::Path;
use std::sync::{Arc, Barrier};
use std::time::Duration;

use menzil_node::ShareSnapshot;
use menzil_proto::RejectedShare;

use super::*;
use crate::local::{init, network_create};
use crate::node_cmd::{RunningNode, start};

fn spec(label: &str, port: u16) -> ExposeSpec {
    ExposeSpec {
        label: label.to_string(),
        mode: ExposeMode::Blind,
        host: "127.0.0.1".to_string(),
        port,
        alpn: vec![],
        replace: false,
    }
}

const BASE: &str = r#"# my menzil config
relay = "menzil://relay.example.org:443/_menzil/v1?id=abababababababababababababababababababababababababababababababab"

[services]
# ssh for friends
"tcp:ssh" = "127.0.0.1:22"   # keep me

# tuning
[serve]
max_connections = 10
"#;

fn err(result: Result<Plan>) -> String {
    format!("{:#}", result.unwrap_err())
}

// ---- the request ------------------------------------------------------------------------

#[test]
fn a_request_line_round_trips_and_every_field_is_checked() {
    let mut full = spec("app", 8443);
    full.mode = ExposeMode::Tcp;
    full.host = "::1".to_string();
    full.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    full.replace = true;
    let line = full.to_request_line();
    assert_eq!(
        line,
        "expose name=app mode=tcp host=::1 port=8443 replace=1 alpn=h2,http/1.1"
    );
    assert_eq!(ExposeSpec::parse_request_line(&line).unwrap(), full);
    assert_eq!(full.target(), "[::1]:8443");
    assert_eq!(full.service().unwrap().to_string(), "tcp:app");
    assert_eq!(spec("app", 80).target(), "127.0.0.1:80");
    assert_eq!(spec("app", 80).service().unwrap().to_string(), "tls:app");

    for (line, wanted) in [
        ("expose name=a mode=blind host=h port=1", "no replace"),
        ("expose name=a mode=blind host=h replace=0", "no port"),
        ("expose mode=blind host=h port=1 replace=0", "no name"),
        ("expose name=a mode=blind port=1 replace=0", "no host"),
        ("expose name=a host=h port=1 replace=0", "no mode"),
        ("expose name=a mode=blind host=h port=1 replace=2", "0 or 1"),
        (
            "expose name=a mode=blind host=h port=70000 replace=0",
            "port",
        ),
        ("expose name=a mode=blind host=h port=x replace=0", "port"),
        (
            "expose name=a name=b mode=blind host=h port=1 replace=0",
            "twice",
        ),
        (
            "expose name=a mode=blind host=h port=1 replace=0 x=1",
            "unknown field",
        ),
        ("expose name=a mode=weird host=h port=1 replace=0", "weird"),
        ("expose nonsense", "key=value"),
    ] {
        let error = ExposeSpec::parse_request_line(line).unwrap_err();
        assert!(error.contains(wanted), "{line:?}: {error}");
    }
}

#[test]
fn what_cannot_be_exposed_is_refused_with_its_reason() {
    let mut terminated = spec("app", 80);
    terminated.mode = ExposeMode::Terminated;
    let error = terminated.validate().unwrap_err().to_string();
    assert!(
        error.contains("terminated mode is not built yet")
            && error.contains("S-E9a")
            && error.contains("S-E9b"),
        "{error}"
    );
    // The refusal comes before the file is looked at.
    assert!(err(plan_expose("", &terminated)).contains("not built yet"));

    for (change, wanted) in [
        (
            (|s: &mut ExposeSpec| s.label = "App".into()) as fn(&mut ExposeSpec),
            "uppercase",
        ),
        (|s| s.label = "a.b".into(), "dot"),
        (|s| s.label = String::new(), "empty"),
        (|s| s.label = "-a".into(), "hyphen"),
        (|s| s.port = 0, "port 0"),
        (|s| s.host = String::new(), "host"),
        (|s| s.host = "a b".into(), "host"),
        (|s| s.host = "[::1]".into(), "without brackets"),
        (|s| s.host = "h\nx".into(), "host"),
        (|s| s.alpn = vec![String::new()], "alpn"),
        (|s| s.alpn = vec!["a b".into()], "alpn"),
        (|s| s.alpn = vec!["a\"b".into()], "alpn"),
        (|s| s.alpn = vec!["x".repeat(256)], "alpn"),
    ] {
        let mut bad = spec("app", 80);
        change(&mut bad);
        let error = format!("{:#}", bad.validate().unwrap_err());
        assert!(error.contains(wanted), "{bad:?}: {error}");
    }
    // Good ones.
    for host in [
        "127.0.0.1",
        "::1",
        "localhost",
        "nas.lan",
        "10.0.0.5",
        "my_host",
    ] {
        let mut good = spec("app", 80);
        good.host = host.to_string();
        good.validate().unwrap();
    }
    let mut alpn = spec("app", 80);
    alpn.alpn = vec!["h2".into(), "http/1.1".into(), "acme-tls/1".into()];
    alpn.validate().unwrap();
}

#[test]
fn only_the_machines_own_loopback_is_not_a_warning() {
    for host in ["127.0.0.1", "127.9.9.9", "::1", "localhost", "LOCALHOST"] {
        assert!(is_loopback(host), "{host}");
    }
    for host in ["10.0.0.5", "0.0.0.0", "nas.lan", "169.254.169.254"] {
        assert!(!is_loopback(host), "{host}");
    }
}

// ---- the edit of the file ---------------------------------------------------------------

#[test]
fn an_exposed_port_is_added_to_services_and_shares_and_everything_else_stays_as_written() {
    let plan = plan_expose(BASE, &spec("app", 8443)).unwrap();
    assert!(plan.changed);
    assert_eq!(
        plan.new_text,
        r#"# my menzil config
relay = "menzil://relay.example.org:443/_menzil/v1?id=abababababababababababababababababababababababababababababababab"

[services]
# ssh for friends
"tcp:ssh" = "127.0.0.1:22"   # keep me
"tls:app" = "127.0.0.1:8443"  # menzil expose

# tuning
[serve]
max_connections = 10

[[share]]
name = "app"
mode = "blind"
service = "tls:app"
"#
    );
    assert_eq!(plan.config.shares().unwrap().len(), 1);
    assert_eq!(plan.target, "127.0.0.1:8443");
    // A second one lands after the first share, ALPN written as a list, the tcp mode on a tcp
    // service.
    let mut second = spec("box", 22);
    second.mode = ExposeMode::Tcp;
    second.alpn = vec!["h2".into(), "http/1.1".into()];
    let plan = plan_expose(&plan.new_text, &second).unwrap();
    assert!(plan.new_text.ends_with(
        "[[share]]\nname = \"app\"\nmode = \"blind\"\nservice = \"tls:app\"\n\n[[share]]\nname = \"box\"\nmode = \"tcp\"\nservice = \"tcp:box\"\nalpn = [\"h2\", \"http/1.1\"]\n"
    ), "{}", plan.new_text);
    assert_eq!(plan.config.services["tcp:box"], "127.0.0.1:22");
    // Comments and the order of the rest are untouched.
    assert!(plan.new_text.starts_with("# my menzil config\nrelay = "));
    assert!(
        plan.new_text
            .contains("\"tcp:ssh\" = \"127.0.0.1:22\"   # keep me\n")
    );
    assert!(
        plan.new_text
            .contains("\n# tuning\n[serve]\nmax_connections = 10\n")
    );
}

#[test]
fn a_file_with_no_services_table_or_no_final_newline_or_crlf_gets_a_well_formed_edit() {
    for text in [
        "",
        "relay = \"menzil://h:1/_menzil/v1?id=ab\"",
        "# only a comment\n",
    ] {
        let plan = plan_expose(text, &spec("app", 8443)).unwrap();
        assert!(
            plan.new_text
                .contains("[services]\n\"tls:app\" = \"127.0.0.1:8443\"  # menzil expose\n"),
            "{}",
            plan.new_text
        );
        assert!(
            plan.new_text.ends_with("service = \"tls:app\"\n"),
            "{}",
            plan.new_text
        );
        assert!(
            plan.new_text.starts_with(text),
            "the old text is a prefix: {}",
            plan.new_text
        );
        assert_eq!(plan.config.share.len(), 1);
    }
    // A last line that has no newline, inside the services table.
    let plan = plan_expose(
        "[services]\n\"tcp:ssh\" = \"127.0.0.1:22\"",
        &spec("app", 1),
    )
    .unwrap();
    assert!(plan
        .new_text
        .starts_with("[services]\n\"tcp:ssh\" = \"127.0.0.1:22\"\n\"tls:app\" = \"127.0.0.1:1\"  # menzil expose\n"));
    // Windows line endings are kept.
    let crlf = "[services]\r\n\"tcp:ssh\" = \"127.0.0.1:22\"\r\n";
    let plan = plan_expose(crlf, &spec("app", 1)).unwrap();
    assert!(
        !plan.new_text.replace("\r\n", "").contains('\n'),
        "{:?}",
        plan.new_text
    );
    assert_eq!(plan.config.share.len(), 1);
}

#[test]
fn exposing_the_same_thing_again_changes_nothing() {
    let first = plan_expose(BASE, &spec("app", 8443)).unwrap();
    let again = plan_expose(&first.new_text, &spec("app", 8443)).unwrap();
    assert!(!again.changed);
    assert_eq!(again.new_text, first.new_text);
}

#[test]
fn a_name_used_with_another_port_is_refused_unless_replace_is_given() {
    let first = plan_expose(BASE, &spec("app", 8443)).unwrap();
    let error = err(plan_expose(&first.new_text, &spec("app", 9000)));
    assert!(
        error.contains("exists already")
            && error.contains("--replace")
            && error.contains("127.0.0.1:8443"),
        "{error}"
    );
    // A different ALPN list is a different share too.
    let mut other = spec("app", 8443);
    other.alpn = vec!["h2".into()];
    assert!(err(plan_expose(&first.new_text, &other)).contains("exists already"));

    let mut replace = spec("app", 9000);
    replace.replace = true;
    let plan = plan_expose(&first.new_text, &replace).unwrap();
    assert!(plan.changed);
    assert_eq!(plan.config.services["tls:app"], "127.0.0.1:9000");
    assert_eq!(plan.config.share.len(), 1, "replaced, not added");
    // The marker stays on the line it was on: `expose remove` still takes the service out.
    assert!(
        plan.new_text
            .contains("\"tls:app\" = \"127.0.0.1:9000\"  # menzil expose\n"),
        "{}",
        plan.new_text
    );
    // Replacing in place keeps the share where it was in the file.
    let two = plan_expose(&first.new_text, &spec("web", 1)).unwrap();
    let mut replace_first = spec("app", 7);
    replace_first.replace = true;
    let plan = plan_expose(&two.new_text, &replace_first).unwrap();
    let names: Vec<&str> = plan.config.share.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["app", "web"]);
    assert!(
        plan.new_text.find("name = \"app\"").unwrap()
            < plan.new_text.find("name = \"web\"").unwrap()
    );
}

#[test]
fn a_service_that_is_already_there_is_not_taken_over_quietly() {
    // `tcp:ssh` is served from port 22 for the members: exposing another port under that
    // service is refused, with the same port it is just a share.
    let mut ssh = spec("ssh", 2222);
    ssh.mode = ExposeMode::Tcp;
    let error = err(plan_expose(BASE, &ssh));
    assert!(
        error.contains("tcp:ssh is served from 127.0.0.1:22") && error.contains("--replace"),
        "{error}"
    );
    ssh.port = 22;
    let plan = plan_expose(BASE, &ssh).unwrap();
    assert_eq!(plan.config.share.len(), 1);
    assert!(
        !plan.new_text.contains("# menzil expose"),
        "no service was made: {}",
        plan.new_text
    );
    // Removing that share leaves the service the members use.
    let removed = plan_unexpose(&plan.new_text, "ssh").unwrap();
    assert_eq!(removed.config.services["tcp:ssh"], "127.0.0.1:22");
    assert!(removed.removed_service.is_none());
    assert!(
        removed.notes.iter().any(|n| n.contains("tcp:ssh stays")),
        "{:?}",
        removed.notes
    );
    assert_eq!(removed.new_text, BASE, "the file is as it was");
    // With --replace the target is changed (and the line's own comment is kept).
    ssh.port = 2222;
    ssh.replace = true;
    let plan = plan_expose(BASE, &ssh).unwrap();
    assert!(
        plan.new_text
            .contains("\"tcp:ssh\" = \"127.0.0.1:2222\"   # keep me\n"),
        "{}",
        plan.new_text
    );
}

#[test]
fn another_share_on_the_same_service_is_not_changed_behind_its_back() {
    let text = "[services]\n\"tls:app\" = \"127.0.0.1:1\"\n\n[[share]]\nname = \"other\"\nmode = \"blind\"\nservice = \"tls:app\"\n";
    let mut app = spec("app", 2);
    app.replace = true;
    let error = err(plan_expose(text, &app));
    assert!(error.contains("another share uses tls:app"), "{error}");
}

#[test]
fn a_changed_mode_moves_the_share_and_takes_the_service_it_made_along() {
    let first = plan_expose(BASE, &spec("app", 8443)).unwrap();
    let mut tcp = spec("app", 8443);
    tcp.mode = ExposeMode::Tcp;
    tcp.replace = true;
    let plan = plan_expose(&first.new_text, &tcp).unwrap();
    assert_eq!(
        plan.removed_service.as_ref().unwrap().to_string(),
        "tls:app"
    );
    assert!(plan.config.services.contains_key("tcp:app"));
    assert!(
        !plan.config.services.contains_key("tls:app"),
        "{}",
        plan.new_text
    );
    assert_eq!(plan.config.share[0].service, "tcp:app");
    // A service the person wrote stays, with a note.
    let text = "[services]\n\"tls:app\" = \"127.0.0.1:8443\"\n\n[[share]]\nname = \"app\"\nmode = \"blind\"\nservice = \"tls:app\"\n";
    let plan = plan_expose(text, &tcp).unwrap();
    assert!(plan.removed_service.is_none());
    assert!(plan.config.services.contains_key("tls:app"));
    assert!(
        plan.notes
            .iter()
            .any(|n| n.contains("tls:app is still in [services]")),
        "{:?}",
        plan.notes
    );
}

#[test]
fn removing_a_share_takes_the_service_expose_made_and_nothing_else() {
    let first = plan_expose(BASE, &spec("app", 8443)).unwrap();
    let removed = plan_unexpose(&first.new_text, "app").unwrap();
    assert_eq!(
        removed.removed_service.as_ref().unwrap().to_string(),
        "tls:app"
    );
    assert_eq!(removed.new_text, BASE, "back to exactly what it was");
    assert_eq!(removed.share.name, "app");
    // A file that had nothing is empty again, not left with an empty table.
    let from_nothing = plan_expose("", &spec("app", 1)).unwrap();
    assert_eq!(
        plan_unexpose(&from_nothing.new_text, "app")
            .unwrap()
            .new_text,
        ""
    );
    // Two shares: only the named one goes.
    let two = plan_expose(&first.new_text, &spec("web", 1)).unwrap();
    let removed = plan_unexpose(&two.new_text, "app").unwrap();
    assert_eq!(removed.config.share.len(), 1);
    assert_eq!(removed.config.share[0].name, "web");
    assert!(removed.config.services.contains_key("tls:web"));
    // A name nobody has.
    let error = err(plan_unexpose(&two.new_text, "nope"));
    assert!(
        error.contains("no share named \"nope\"") && error.contains("app, web"),
        "{error}"
    );
    assert!(err(plan_unexpose(BASE, "nope")).contains("there are none"));
}

#[test]
fn a_file_in_a_form_the_editor_does_not_read_is_refused_and_not_mangled() {
    // Shares as an inline array, services as dotted keys: not edited by text.
    let inline = "share = [{ name = \"a\", mode = \"blind\", service = \"tls:a\" }]\n\n[services]\n\"tls:a\" = \"127.0.0.1:1\"\n";
    let mut replace = spec("a", 2);
    replace.replace = true;
    assert!(err(plan_expose(inline, &replace)).contains("cannot edit safely"));
    assert!(err(plan_expose(inline, &spec("b", 3))).contains("cannot edit safely"));
    assert!(err(plan_unexpose(inline, "a")).contains("cannot edit safely"));
    let dotted = "services.\"tcp:ssh\" = \"127.0.0.1:22\"\n";
    assert!(err(plan_expose(dotted, &spec("b", 3))).contains("cannot edit safely"));
    // A file that is already wrong is not edited on top of its mistake.
    assert!(err(plan_expose("raley = 1\n", &spec("b", 3))).contains("not valid"));
    assert!(
        err(plan_expose(
            "[services]\n\"tcp:ssh\" = \"x\"\n",
            &spec("b", 3)
        ))
        .contains("host:port")
    );
    assert!(err(plan_expose("share_domain = \"nodot\"\n", &spec("b", 3))).contains("share_domain"));
}

#[test]
fn what_the_node_cannot_hold_is_refused_before_the_file_is_written() {
    // 64 shares is the most one ADVERTISE carries.
    let mut text = String::new();
    for n in 0..64 {
        text = plan_expose(&text, &spec(&format!("s{n}"), 1000 + n))
            .unwrap()
            .new_text;
    }
    let error = err(plan_expose(&text, &spec("one-more", 1)));
    assert!(error.contains("64"), "{error}");
}

// ---- writing and applying ----------------------------------------------------------------

/// A config for a home with no identity (nothing starts from it).
fn plain_config(home: &Home, dir: &Path, extra: &str) -> Config {
    config_with(
        home,
        dir,
        extra,
        format!(
            "menzil://relay.example.org:443/_menzil/v1?id={}",
            "ab".repeat(32)
        ),
    )
}

/// A config a node can start from: the relay is a refused address, no relay answers.
fn live_config(home: &Home, dir: &Path, extra: &str) -> Config {
    let info = crate::relay_cmd::connection_info(
        "127.0.0.1",
        9,
        crate::relay_cmd::DEFAULT_PATH,
        &crate::relay_cmd::relay_identity(home).unwrap(),
    )
    .unwrap();
    config_with(home, dir, extra, info)
}

fn config_with(home: &Home, dir: &Path, extra: &str, info: String) -> Config {
    let text = format!(
        "# written by hand\nrelay = \"{info}\"\nproxy = \"direct\"\nagent_socket = \"{}\"\nshare_domain = \"tunnel.example.org\"\n\n[services]\n\"tcp:ssh\" = \"127.0.0.1:22\"\n{extra}",
        dir.join("a.sock").display()
    );
    std::fs::create_dir_all(home.root()).unwrap();
    std::fs::write(home.config_path(), text).unwrap();
    Config::load(home).unwrap()
}

fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A device with an identity and a network, a config, and a node running on it (no relay
/// answers; none is needed).
async fn running(dir: &Path, extra: &str) -> (Home, RunningNode) {
    let home = Home::new(dir.join("home"));
    init(&home, real_now()).unwrap();
    network_create(&home, "laptop", real_now()).unwrap();
    let config = live_config(&home, dir, extra);
    let node = start(&home, &config, &dir.join("a.sock")).await.unwrap();
    (home, node)
}

fn config_text(home: &Home) -> String {
    std::fs::read_to_string(home.config_path()).unwrap()
}

/// The whole path: the CLI asks the agent over its socket, the node's services and shares change
/// at once, `config.toml` keeps the change, `list` and `status` say what the node holds.
#[tokio::test]
async fn a_running_node_serves_and_advertises_a_new_share_at_once_and_a_restart_keeps_it() {
    let dir = tempfile::tempdir().unwrap();
    let (home, node) = running(dir.path(), "").await;
    let app: ServiceId = "tls:app".parse().unwrap();
    assert!(node.services.target(&app).is_none());
    assert!(node.node.shares().configured().is_empty());

    let out = run_expose(&home, spec("app", 8443)).await.unwrap();
    assert!(
        out.contains("exposed app (blind): tls:app -> 127.0.0.1:8443"),
        "{out}"
    );
    assert!(out.contains("the running node advertises it now"), "{out}");
    assert!(out.contains("target must speak TLS itself"), "{out}");
    // No relay is attached: the share is configured, not advertised, and says so; the address is
    // built from the share domain of config.toml.
    assert!(
        out.contains("not advertised: this node is not attached"),
        "{out}"
    );
    assert!(
        out.contains("https://app.tunnel.example.org once the relay accepts it"),
        "{out}"
    );
    assert!(!out.contains("no node is running"), "{out}");

    // The node: the service is served from the new target, the share is configured.
    assert_eq!(
        node.services.target(&app).unwrap().to_string(),
        "127.0.0.1:8443"
    );
    assert_eq!(node.node.shares().configured().len(), 1);
    // The file: written, comments kept, the other service untouched.
    let text = config_text(&home);
    assert!(text.starts_with("# written by hand\n"), "{text}");
    assert!(
        text.contains("\"tls:app\" = \"127.0.0.1:8443\"  # menzil expose"),
        "{text}"
    );
    assert!(text.contains("[[share]]\nname = \"app\""), "{text}");
    // A restart reads the same thing from the file.
    let reread = Config::load(&home).unwrap();
    assert_eq!(reread.shares().unwrap(), node.node.shares().configured());

    // `expose list` and `status` carry the relay's side.
    let list = run_list(&home).await.unwrap();
    assert!(list.contains("relay: not attached"), "{list}");
    assert!(
        list.contains("app: blind tls:app -> 127.0.0.1:8443"),
        "{list}"
    );
    let socket = crate::node_cmd::agent_socket_path(&home, &reread);
    let status = crate::agent::query_node_status(&socket).await.unwrap();
    assert_eq!(status.shares.len(), 1);
    assert_eq!(status.shares[0].label, "app");
    assert_eq!(status.shares[0].state, ShareState::Offline);
    assert_eq!(status.shares[0].target.as_deref(), Some("127.0.0.1:8443"));

    // The same again changes nothing; another port is refused, then replaced.
    let again = run_expose(&home, spec("app", 8443)).await.unwrap();
    assert!(again.contains("is exposed as asked already"), "{again}");
    let error = format!(
        "{:#}",
        run_expose(&home, spec("app", 9000)).await.unwrap_err()
    );
    assert!(
        error.contains("exists already") && error.contains("--replace"),
        "{error}"
    );
    assert_eq!(
        node.services.target(&app).unwrap().to_string(),
        "127.0.0.1:8443"
    );
    let mut replace = spec("app", 9000);
    replace.replace = true;
    run_expose(&home, replace).await.unwrap();
    assert_eq!(
        node.services.target(&app).unwrap().to_string(),
        "127.0.0.1:9000"
    );
    assert_eq!(node.node.shares().configured().len(), 1);

    // A refusal from the node comes back as its words and changes nothing.
    let before = config_text(&home);
    let mut bad = spec("Bad", 1);
    bad.mode = ExposeMode::Blind;
    let error = format!("{:#}", run_expose(&home, bad).await.unwrap_err());
    assert!(error.contains("uppercase"), "{error}");
    assert_eq!(config_text(&home), before);

    // Removing: the share and the service made for it go, the file is back to what it was.
    let out = run_unexpose(&home, "app").await.unwrap();
    assert!(
        out.contains("removed the share app") && out.contains("stopped advertising"),
        "{out}"
    );
    assert!(node.services.target(&app).is_none());
    assert!(node.node.shares().configured().is_empty());
    let text = config_text(&home);
    assert!(
        !text.contains("tls:app") && !text.contains("[[share]]"),
        "{text}"
    );
    assert!(text.contains("\"tcp:ssh\" = \"127.0.0.1:22\""), "{text}");
    let error = format!("{:#}", run_unexpose(&home, "app").await.unwrap_err());
    assert!(error.contains("no share named \"app\""), "{error}");
    // The config lock is not left behind by any of it.
    drop(home.lock_config().unwrap());
}

#[tokio::test]
async fn with_no_node_expose_edits_the_file_alone_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    plain_config(&home, dir.path(), "");
    let out = run_expose(&home, spec("app", 8443)).await.unwrap();
    assert!(
        out.contains("no node is running: only config.toml was changed"),
        "{out}"
    );
    assert!(out.contains("exposed app (blind)"), "{out}");
    assert!(
        out.contains("https://app.tunnel.example.org once the relay accepts it"),
        "{out}"
    );
    let config = Config::load(&home).unwrap();
    assert_eq!(config.shares().unwrap().len(), 1);
    let list = run_list(&home).await.unwrap();
    assert!(
        list.contains("app: blind tls:app -> 127.0.0.1:8443"),
        "{list}"
    );
    assert!(list.contains("no node is running"), "{list}");
    assert!(!list.contains("relay:"), "{list}");
    // The same error texts as with a node.
    let error = format!("{:#}", run_expose(&home, spec("app", 9)).await.unwrap_err());
    assert!(error.contains("exists already"), "{error}");
    let out = run_unexpose(&home, "app").await.unwrap();
    assert!(
        out.contains("no node is running: only config.toml was changed"),
        "{out}"
    );
    assert!(Config::load(&home).unwrap().share.is_empty());
    assert!(
        run_list(&home)
            .await
            .unwrap()
            .contains("nothing is exposed")
    );
    // A file that is not valid stops the command with the reason, whoever is asked.
    std::fs::write(home.config_path(), "raley = 1\n").unwrap();
    assert!(run_expose(&home, spec("app", 1)).await.is_err());
    assert_eq!(config_text(&home), "raley = 1\n");
}

#[tokio::test]
async fn a_hand_edit_of_services_and_shares_is_picked_up_by_the_reload_without_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (home, node) = running(dir.path(), "").await;
    let mut text = config_text(&home);
    text.push_str("\n[[share]]\nname = \"hand\"\nmode = \"blind\"\nservice = \"tls:hand\"\n");
    text = text.replace(
        "\"tcp:ssh\" = \"127.0.0.1:22\"\n",
        "\"tcp:ssh\" = \"127.0.0.1:22\"\n\"tls:hand\" = \"127.0.0.1:7777\"\n",
    );
    std::fs::write(home.config_path(), text).unwrap();
    // Before: a share for a service the node did not start with waited for a restart.
    crate::node_cmd::reload_shares(&home, &node.node, &node.services);
    let hand: ServiceId = "tls:hand".parse().unwrap();
    assert_eq!(
        node.services.target(&hand).unwrap().to_string(),
        "127.0.0.1:7777"
    );
    let shares = node.node.shares().configured();
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].name, "hand");
    // A changed port is followed too.
    let text = config_text(&home).replace("127.0.0.1:7777", "127.0.0.1:7778");
    std::fs::write(home.config_path(), text).unwrap();
    crate::node_cmd::reload_shares(&home, &node.node, &node.services);
    assert_eq!(
        node.services.target(&hand).unwrap().to_string(),
        "127.0.0.1:7778"
    );
    // A file that is wrong changes nothing.
    std::fs::write(home.config_path(), "raley = 1\n").unwrap();
    crate::node_cmd::reload_shares(&home, &node.node, &node.services);
    assert_eq!(node.node.shares().configured().len(), 1);
    assert_eq!(
        node.services.target(&hand).unwrap().to_string(),
        "127.0.0.1:7778"
    );
}

/// The reload reads the file and applies it as one step under the config lock: without it a
/// reload that read the file before an `expose` could apply the old shares after it.
#[tokio::test]
async fn the_reload_waits_for_a_change_to_the_file_that_is_in_progress() {
    let dir = tempfile::tempdir().unwrap();
    let (home, node) = running(dir.path(), "").await;
    let held = home.lock_config().unwrap();
    let (h, n, s) = (home.clone(), node.node.clone(), node.services.clone());
    let reloading = std::thread::spawn(move || crate::node_cmd::reload_shares(&h, &n, &s));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !reloading.is_finished(),
        "the reload went on without the lock"
    );
    drop(held);
    tokio::task::spawn_blocking(move || reloading.join().unwrap())
        .await
        .unwrap();
}

#[test]
fn concurrent_changes_to_the_file_are_all_kept() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    plain_config(&home, dir.path(), "");
    let threads = 12;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|n| {
            let (home, barrier) = (home.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                expose(&home, &spec(&format!("s{n}"), 2000 + n as u16), None).unwrap()
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let config = Config::load(&home).unwrap();
    assert_eq!(
        config.shares().unwrap().len(),
        threads,
        "{}",
        config_text(&home)
    );
    assert_eq!(config.services.len(), threads + 1, "{}", config_text(&home));
    // Taking them away concurrently as well.
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|n| {
            let (home, barrier) = (home.clone(), barrier.clone());
            std::thread::spawn(move || {
                barrier.wait();
                unexpose(&home, &format!("s{n}"), None).unwrap()
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let config = Config::load(&home).unwrap();
    assert!(config.share.is_empty(), "{}", config_text(&home));
    assert_eq!(config.services.len(), 1);
}

#[test]
fn the_file_is_written_atomically_readable_by_its_owner_only_and_a_link_stays_a_link() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    plain_config(&home, dir.path(), "");
    expose(&home, &spec("app", 1), None).unwrap();
    let mode = std::fs::metadata(home.config_path()).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let leftovers: Vec<_> = std::fs::read_dir(home.root())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
    // config.toml kept in a dotfiles repository: the change goes to the file, the link stays.
    let real = dir.path().join("dotfiles.toml");
    std::fs::rename(home.config_path(), &real).unwrap();
    symlink(&real, home.config_path()).unwrap();
    expose(&home, &spec("web", 2), None).unwrap();
    assert!(
        std::fs::symlink_metadata(home.config_path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        std::fs::read_to_string(&real)
            .unwrap()
            .contains("name = \"web\"")
    );
}

#[test]
fn a_failed_edit_leaves_the_file_as_it_was() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    plain_config(&home, dir.path(), "");
    let before = config_text(&home);
    let mut terminated = spec("app", 1);
    terminated.mode = ExposeMode::Terminated;
    assert!(expose(&home, &terminated, None).is_err());
    assert!(unexpose(&home, "nothing", None).is_err());
    assert_eq!(config_text(&home), before);
}

// ---- what the relay said ------------------------------------------------------------------

fn share_of(name: &str, service: &str) -> Share {
    Share {
        name: name.to_string(),
        mode: ShareMode::Blind,
        service: service.parse().unwrap(),
        alpn: vec![],
    }
}

#[test]
fn each_share_shows_what_the_relay_answered_and_why() {
    let services = LocalServices::new();
    services
        .set_target(
            "tls:app".parse().unwrap(),
            menzil_node::LocalTarget::new("127.0.0.1", 8443),
        )
        .unwrap();
    let (app, web, db, ssh) = (
        share_of("app", "tls:app"),
        share_of("web", "tls:web"),
        share_of("db", "tls:db"),
        share_of("ssh", "tcp:ssh"),
    );
    let snapshot = ShareSnapshot {
        sent: vec![app.clone(), web.clone(), ssh.clone()],
        acked: true,
        accepted: vec![app.clone()],
        rejected: vec![RejectedShare {
            name: "web".into(),
            reason: "label_taken".into(),
        }],
        names: vec![
            "app".into(),
            "app.ali".into(),
            "apple".into(),
            "other.zed".into(),
        ],
    };
    let configured = [app.clone(), web, db, ssh];
    let views = views_from(&configured, &snapshot, &services, true);
    assert_eq!(views[0].state, ShareState::Accepted);
    // The names of this label only: not `apple`, not another share's.
    assert_eq!(views[0].names, ["app", "app.ali"]);
    assert_eq!(views[0].target.as_deref(), Some("127.0.0.1:8443"));
    assert_eq!(views[1].state, ShareState::Rejected);
    assert_eq!(views[1].reason.as_deref(), Some("label_taken"));
    assert_eq!(views[1].target, None);
    // Configured after the last ADVERTISE: not answered yet.
    assert_eq!(views[2].state, ShareState::Pending);
    // Sent, and the relay named it in neither list.
    assert_eq!(views[3].state, ShareState::Pending);
    assert_eq!(views[3].mode, "tcp", "a tcp: service is the tcp mode");
    // A tcp: service is the tcp mode.
    let mut tcp = share_of("box", "tcp:box");
    tcp.mode = ShareMode::Blind;
    assert_eq!(
        views_from(&[tcp], &ShareSnapshot::default(), &services, true)[0].mode,
        "tcp"
    );
    // Not attached: nothing is advertised, whatever the last answer was.
    let offline = views_from(&configured, &snapshot, &services, false);
    assert!(
        offline
            .iter()
            .all(|v| v.state == ShareState::Offline && v.names.is_empty())
    );
    // A changed share (another ALPN) is not the one the relay accepted.
    let mut changed = app;
    changed.alpn = vec!["h2".into()];
    assert_eq!(
        views_from(&[changed], &snapshot, &services, true)[0].state,
        ShareState::Pending
    );
}

fn view(label: &str, state: ShareState) -> ShareView {
    ShareView {
        label: label.into(),
        mode: "blind".into(),
        service: format!("tls:{label}"),
        target: Some("127.0.0.1:8443".into()),
        alpn: vec![],
        state,
        names: vec![],
        reason: None,
    }
}

#[test]
fn a_share_line_round_trips_and_text_from_the_relay_cannot_break_it() {
    let mut full = view("app", ShareState::Accepted);
    full.alpn = vec!["h2".into(), "http/1.1".into()];
    full.names = vec!["app".into(), "app.ali".into()];
    assert_eq!(ShareView::from_line(&full.to_line()).unwrap(), full);
    let mut rejected = view("web", ShareState::Rejected);
    rejected.reason = Some("reserved name: it is the relay's".into());
    assert_eq!(ShareView::from_line(&rejected.to_line()).unwrap(), rejected);
    // Hostile content: a reason with a newline and an escape sequence is one printable line, a
    // name with anything but letters, digits, hyphens and dots is dropped, and names are few.
    let mut hostile = view("web", ShareState::Rejected);
    hostile.reason = Some("bad\nshare label=x\u{1b}[31m".into());
    hostile.names = vec![
        "ok.name".into(),
        "evil name".into(),
        "x\u{1b}y".into(),
        "UP".into(),
    ];
    let line = hostile.to_line();
    assert!(!line.contains('\n') && !line.contains('\u{1b}'), "{line:?}");
    let back = ShareView::from_line(&line).unwrap();
    assert_eq!(back.names, ["ok.name"]);
    assert_eq!(back.label, "web");
    // A line from an agent that lies about its fields is not a share.
    for line in [
        "share label=App mode=blind service=tls:a state=accepted",
        "share label=a mode=blind service=nonsense state=accepted",
        "share label=a mode=other service=tls:a state=accepted",
        "share label=a mode=blind service=tls:a state=maybe",
        "share label=a mode=blind service=tls:a",
        "share mode=blind service=tls:a state=accepted",
        "status ok",
    ] {
        assert!(ShareView::from_line(line).is_none(), "{line}");
    }
    // A key this client does not know is skipped.
    let line = "share label=a mode=blind service=tls:a state=accepted future=1";
    assert_eq!(ShareView::from_line(line).unwrap().label, "a");
}

#[test]
fn the_reply_to_expose_and_unexpose_round_trips() {
    let reply = ExposeReply {
        changed: true,
        share: view("app", ShareState::Pending),
        notes: vec!["tls:old is still in [services]".into()],
    };
    let lines: Vec<String> = reply.to_lines().lines().map(str::to_string).collect();
    assert_eq!(ExposeReply::from_lines(&lines).unwrap(), reply);
    assert!(ExposeReply::from_lines(&["changed yes".to_string()]).is_err());
    let gone = UnexposeReply {
        notes: vec!["tcp:ssh stays".into()],
        service_removed: true,
    };
    let lines: Vec<String> = gone.to_lines().lines().map(str::to_string).collect();
    assert_eq!(UnexposeReply::from_lines(&lines), gone);
}

// ---- the text ------------------------------------------------------------------------------

#[test]
fn the_public_address_is_built_from_what_the_relay_accepted_and_the_share_domain() {
    let mut accepted = view("app", ShareState::Accepted);
    accepted.names = vec!["app".into(), "app.ali".into()];
    assert_eq!(
        public_address(&accepted, Some("tunnel.example.org")),
        "https://app.tunnel.example.org, https://app.ali.tunnel.example.org"
    );
    // Without the domain: the relay's names and a way to get whole addresses.
    let text = public_address(&accepted, None);
    assert!(
        text.contains("app.<share domain>, app.ali.<share domain>")
            && text.contains("share_domain"),
        "{text}"
    );
    // Not accepted yet: what it will be, and the tenant form.
    let pending = view("app", ShareState::Pending);
    let text = public_address(&pending, Some("tunnel.example.org"));
    assert!(
        text.contains("https://app.tunnel.example.org once the relay accepts it")
            && text.contains("app.<tenant>.tunnel.example.org"),
        "{text}"
    );
    let text = public_address(&pending, None);
    assert!(
        text.contains("app.<the relay's share domain>") && text.contains("share_domain"),
        "{text}"
    );
    // A tcp share is reached with TLS and a name, not as https.
    let mut tcp = view("box", ShareState::Accepted);
    tcp.mode = "tcp".into();
    tcp.names = vec!["box".into()];
    let text = public_address(&tcp, Some("d.org"));
    assert!(
        text.starts_with("box.d.org:443 (TLS with that name as SNI"),
        "{text}"
    );
}

#[test]
fn the_list_and_the_status_lines_say_accepted_or_rejected_with_the_relays_reason() {
    let mut accepted = view("app", ShareState::Accepted);
    accepted.names = vec!["app.ali".into()];
    accepted.alpn = vec!["h2".into()];
    let mut rejected = view("web", ShareState::Rejected);
    rejected.reason = Some("label_taken".into());
    let views = [
        accepted,
        rejected,
        view("db", ShareState::Pending),
        view("x", ShareState::Offline),
    ];
    let list = render_list(&views, Some("t.example.org"));
    assert!(
        list.contains("app: blind tls:app -> 127.0.0.1:8443, alpn h2\n  accepted by the relay; https://app.ali.t.example.org\n"),
        "{list}"
    );
    assert!(
        list.contains(
            "web: blind tls:web -> 127.0.0.1:8443\n  REJECTED by the relay: label_taken;"
        ),
        "{list}"
    );
    assert!(list.contains("the relay has not answered yet"), "{list}");
    assert!(
        list.contains("not advertised: this node is not attached to the relay"),
        "{list}"
    );
    let status = render_status(&views, Some("t.example.org"));
    assert!(status.contains("share app: blind tls:app -> 127.0.0.1:8443; accepted by the relay; https://app.ali.t.example.org\n"), "{status}");
    assert!(
        status.contains(
            "share web: blind tls:web -> 127.0.0.1:8443; REJECTED by the relay: label_taken;"
        ),
        "{status}"
    );
    assert_eq!(status.lines().count(), 4);
    assert_eq!(render_status(&[], None), "");
    // What the relay wrote is shown printable.
    let mut sly = view("web", ShareState::Rejected);
    sly.reason = Some("a\u{1b}[2Jb".into());
    assert!(!render_list(&[sly], None).contains('\u{1b}'));
    // A share with no served target.
    let mut lost = view("gone", ShareState::Pending);
    lost.target = None;
    assert!(render_list(&[lost], None).contains("-> (not served)"));
}

#[test]
fn a_target_that_is_not_loopback_gets_a_warning() {
    let mut open = spec("app", 80);
    open.host = "10.0.0.5".into();
    let out = render_exposed(
        &open,
        true,
        &view("app", ShareState::Pending),
        &[],
        true,
        None,
    );
    assert!(
        out.contains("warning: 10.0.0.5 is not this machine's loopback"),
        "{out}"
    );
    let out = render_exposed(
        &spec("app", 80),
        true,
        &view("app", ShareState::Pending),
        &[],
        true,
        None,
    );
    assert!(!out.contains("warning"), "{out}");
}

#[test]
fn a_share_domain_in_config_is_checked_before_it_is_printed() {
    let domain = |text: &str| {
        Config::parse(&format!("share_domain = \"{text}\""))
            .unwrap()
            .share_domain()
    };
    assert_eq!(
        domain("Tunnel.Example.ORG").unwrap().as_deref(),
        Some("tunnel.example.org")
    );
    assert_eq!(Config::parse("").unwrap().share_domain().unwrap(), None);
    for bad in [
        "",
        "nodot",
        "https://t.example.org",
        "t.example.org:443",
        "t.example.org/",
        "t.example.org.",
        "-a.example.org",
        "a..org",
        "a b.org",
        "t.exam_ple.org",
    ] {
        let error = format!("{:#}", domain(bad).unwrap_err());
        assert!(error.contains("share_domain"), "{bad:?}: {error}");
    }
}

/// The check after an edit: a text that parses but is not the old configuration with exactly the
/// intended change is refused (no form of file this repository's tests could construct gets that
/// far through the editor, so the check is tried on its own).
#[test]
fn an_edit_that_parses_but_is_not_the_change_asked_for_is_refused() {
    let doc = Doc::new("relay = \"menzil://a:1/_menzil/v1?id=ab\"\n");
    let expected = Config::parse("relay = \"menzil://b:1/_menzil/v1?id=ab\"\n").unwrap();
    let error = format!("{:#}", verify(&doc, &expected).unwrap_err());
    assert!(
        error.contains("cannot edit safely") && error.contains("exactly the change"),
        "{error}"
    );
    let same = Config::parse(&doc.text()).unwrap();
    assert_eq!(verify(&doc, &same).unwrap(), same);
}
