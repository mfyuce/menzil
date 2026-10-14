use menzil_admin::NodeKeys;

use super::*;
use crate::local::{admit, init, join, network_create, renew};

const NOW: u64 = 1_800_000_000;

fn entry(network: u8, name: &str, node: u8) -> Entry {
    Entry {
        network_id: NetworkId::from([network; 32]),
        name: name.to_string(),
        node_id: NodeId::from([node; 32]),
    }
}

#[test]
fn a_target_is_a_member_and_a_service_with_tcp_as_the_default_kind() {
    let (who, service) = split_target("laptop/ssh").unwrap();
    assert_eq!((who, service), ("laptop", "tcp:ssh".parse().unwrap()));
    let (who, service) = split_target("nas.lan/http:photos").unwrap();
    assert_eq!((who, service), ("nas.lan", "http:photos".parse().unwrap()));
    let (_, service) = split_target("a/tcp:b:c").unwrap();
    assert_eq!(service.label, "b:c");
    for bad in [
        "",
        "laptop",
        "/ssh",
        "laptop/",
        "laptop/*",
        "laptop/tcp:*",
        "laptop/udp9:x",
        "laptop/tcp:",
    ] {
        assert!(split_target(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn names_resolve_uniquely_or_not_at_all() {
    let directory = Directory::from_entries(vec![
        entry(1, "laptop", 0xaa),
        entry(1, "phone", 0xbb),
        entry(2, "phone", 0xcc),
        entry(2, "nas", 0xdd),
    ]);
    assert_eq!(
        directory.resolve("laptop").unwrap().node_id,
        NodeId::from([0xaa; 32])
    );
    assert_eq!(
        directory.resolve("nas").unwrap().network_id,
        NetworkId::from([2; 32])
    );

    // The same name in two networks is not guessed at.
    let error = directory.resolve("phone").unwrap_err();
    assert!(
        error.contains("ambiguous") && error.contains("bbbbbbbb") && error.contains("cccccccc"),
        "{error}"
    );
    // But a node id prefix says which.
    assert_eq!(directory.resolve("cccccccc").unwrap().name, "phone");
    assert_eq!(
        directory.resolve("BBBBBBBB").unwrap().node_id,
        NodeId::from([0xbb; 32])
    );

    // Unknown names list the members; too short a prefix is not a prefix.
    let error = directory.resolve("tablet").unwrap_err();
    assert!(error.contains("laptop, nas, phone"), "{error}");
    assert!(directory.resolve("bbbbbbb").is_err());
    assert!(directory.resolve("").is_err());
    assert!(
        Directory::default()
            .resolve("x")
            .unwrap_err()
            .contains("no network documents")
    );
}

#[test]
fn the_directory_follows_the_documents_on_disk() {
    let owner_dir = tempfile::tempdir().unwrap();
    let owner = Home::new(owner_dir.path());
    init(&owner, NOW).unwrap();
    let id = network_create(&owner, "laptop", NOW).unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let member = Home::new(member_dir.path());
    let request = init(&member, NOW).unwrap().join_request;

    let directory = Directory::load(&owner).unwrap();
    assert_eq!(directory.resolve("laptop").unwrap().network_id, id);
    assert!(directory.resolve("phone").is_err());

    let admitted = admit(&owner, None, &request, "phone", &[], NOW).unwrap();
    let directory = Directory::load(&owner).unwrap();
    assert_eq!(
        directory.resolve("phone").unwrap().node_id,
        admitted.member.unwrap()
    );

    // A node's stores take what is on disk, and a reload picks up a newer pair.
    join(&member, &admitted.token, NOW).unwrap();
    let (policies, rosters, networks) = load_stores(&member).unwrap();
    assert_eq!(networks, vec![id]);
    assert_eq!(policies.seq(&id), Some(2));
    let renewed = renew(&owner, None, NOW + 86_400).unwrap();
    join(&member, &renewed.token, NOW + 86_400).unwrap();
    let directory = RwLock::new(Directory::default());
    let mut last = HashMap::new();
    reload(&member, &policies, &rosters, &directory, &mut last).unwrap();
    assert_eq!(policies.seq(&id), Some(3));
    assert_eq!(rosters.seq(&id), Some(3));
    assert_eq!(
        directory
            .read()
            .unwrap()
            .resolve("laptop")
            .unwrap()
            .network_id,
        id
    );
    assert_eq!(last.get(&id), Some(&3));
}

#[test]
fn a_node_with_no_network_or_no_identity_refuses_to_start_with_a_reason() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path());
    assert!(format!("{:#}", load_stores(&home).err().unwrap()).contains("no network"));
    init(&home, NOW).unwrap();
    assert!(format!("{:#}", load_stores(&home).err().unwrap()).contains("menzil network create"));
    // Damaged documents stop it instead of leaving a network that rejects everybody.
    let id = network_create(&home, "me", NOW).unwrap();
    fs::write(home.documents_path(&id), b"junk").unwrap();
    assert!(format!("{:#}", load_stores(&home).err().unwrap()).contains("damaged"));
}

#[test]
fn the_agent_socket_is_where_the_configuration_or_the_runtime_directory_says() {
    let home = Home::new("/h");
    let config = Config {
        agent_socket: Some("/run/x.sock".into()),
        ..Config::default()
    };
    assert_eq!(
        agent_socket_path(&home, &config),
        PathBuf::from("/run/x.sock")
    );
    // Without a setting it depends on the environment; either way it ends in agent.sock.
    let path = agent_socket_path(&home, &Config::default());
    assert!(path.ends_with("agent.sock"), "{path:?}");
}

#[tokio::test]
async fn a_stale_socket_is_replaced_and_a_live_one_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("run").join("agent.sock");
    let first = bind_agent_socket(&socket).await.unwrap();
    // Somebody is listening: a second node must not take it over.
    let error = format!("{:#}", bind_agent_socket(&socket).await.err().unwrap());
    assert!(error.contains("already listening"), "{error}");
    // The listener is gone (the node died) but its file is left behind.
    drop(first);
    assert!(socket.exists());
    let second = bind_agent_socket(&socket).await.unwrap();
    drop(second);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _live = bind_agent_socket(&socket).await.unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&socket), 0o600);
        assert_eq!(
            mode(socket.parent().unwrap()),
            0o700,
            "a directory this creates is private"
        );
    }
}

#[test]
fn what_a_person_is_told_about_a_failed_open_is_plain() {
    let text = explain(&NodeOpenError::Session(EnsureError::NotAttached));
    assert!(text.contains("not connected to the relay"), "{text}");
    let text = explain(&NodeOpenError::Session(EnsureError::Timeout));
    assert!(text.contains("did not answer"), "{text}");
    // Anything else keeps the library's own words.
    assert_eq!(
        explain(&NodeOpenError::Session(EnsureError::SelfPeer)),
        "no session to the peer: cannot open a session to ourselves"
    );
    let refused = NodeOpenError::Open(OpenStreamError::Refused {
        code: menzil_proto::ErrorCode::NoGrant,
        msg: "no grant".to_string(),
    });
    assert_eq!(
        explain(&refused),
        "refused by the other end: no_grant (no grant)"
    );
    let _ = NodeKeys::generate;
}

#[tokio::test]
async fn a_socket_path_too_long_for_unix_says_what_to_do() {
    let long = PathBuf::from(format!("/tmp/{}/agent.sock", "d".repeat(120)));
    let error = format!("{:#}", bind_agent_socket(&long).await.err().unwrap());
    assert!(
        error.contains("agent_socket") && error.contains("config.toml"),
        "{error}"
    );
    // The third red-team round, M2: it used to suggest `/tmp/menzil.sock`, where any other user
    // can put a socket of their own first.
    assert!(
        !error.contains("/tmp/menzil.sock") && error.contains("XDG_RUNTIME_DIR"),
        "{error}"
    );
    assert!(check_socket_path_length(Path::new("/run/user/1000/menzil/agent.sock")).is_ok());
    assert!(check_socket_path_length(&long).is_err());
}

/// The third red-team round, M1: a member of another network named like the start of this
/// device's node id took the address of that node, because names were tried first and the node
/// id only when no name matched.
#[test]
fn a_name_never_takes_the_address_of_a_node_id_prefix() {
    let mine = Entry {
        network_id: NetworkId::from([1u8; 32]),
        name: "laptop".to_string(),
        node_id: NodeId::from([0x1a; 32]),
    };
    let theirs = Entry {
        network_id: NetworkId::from([2u8; 32]),
        name: "1a1a1a1a".to_string(),
        node_id: NodeId::from([0x99; 32]),
    };
    let directory = Directory::from_entries(vec![mine.clone(), theirs.clone()]);
    let error = directory.resolve("1a1a1a1a").unwrap_err();
    assert!(
        error.contains("ambiguous") && error.contains("laptop") && error.contains("1a1a1a1a"),
        "{error}"
    );
    // The full id of the device is ambiguous too, if some name is that id.
    let full_name = Entry {
        name: mine.node_id.to_hex(),
        ..theirs.clone()
    };
    let directory = Directory::from_entries(vec![mine.clone(), full_name]);
    assert!(directory.resolve(&mine.node_id.to_hex()).is_err());
    // A name that is the start of the *same* node's id names one member, not two.
    let same = Entry {
        name: "1a1a1a1a".to_string(),
        ..mine.clone()
    };
    let directory = Directory::from_entries(vec![same.clone()]);
    assert_eq!(directory.resolve("1a1a1a1a").unwrap(), &same);
    // And what is asked for by another name still finds its member.
    let directory = Directory::from_entries(vec![mine.clone(), theirs.clone()]);
    assert_eq!(directory.resolve("laptop").unwrap(), &mine);
}

#[test]
fn names_in_an_error_message_are_escaped() {
    let directory = Directory::from_entries(vec![entry(1, "laptop", 0xaa)]);
    let error = directory.resolve("x\u{1b}[2J").unwrap_err();
    assert!(!error.chars().any(text::is_unsafe), "{error:?}");
    let evil = Directory::from_entries(vec![entry(1, "a\u{1b}]0;x\u{7}", 0xaa)]);
    let error = evil.resolve("nobody").unwrap_err();
    assert!(!error.chars().any(text::is_unsafe), "{error:?}");
}

/// M8: a file at `agent_socket` that is not a socket (the configuration pointing at the wrong
/// file) was deleted and replaced by a socket.
#[tokio::test]
async fn a_file_that_is_not_a_socket_is_never_removed() {
    let dir = tempfile::tempdir().unwrap();
    let precious = dir.path().join("precious.txt");
    fs::write(&precious, b"do not lose this").unwrap();
    let error = format!("{:#}", bind_agent_socket(&precious).await.err().unwrap());
    assert!(error.contains("not a socket"), "{error}");
    assert_eq!(fs::read(&precious).unwrap(), b"do not lose this");

    // A symbolic link is not a socket either, and is not followed to remove its target.
    #[cfg(unix)]
    {
        let link = dir.path().join("link.sock");
        std::os::unix::fs::symlink(&precious, &link).unwrap();
        let error = format!("{:#}", bind_agent_socket(&link).await.err().unwrap());
        assert!(error.contains("not a socket"), "{error}");
        assert_eq!(fs::read(&precious).unwrap(), b"do not lose this");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    // A directory neither.
    let directory = dir.path().join("a-directory");
    fs::create_dir(&directory).unwrap();
    assert!(bind_agent_socket(&directory).await.is_err());
    assert!(directory.is_dir());
}

#[test]
fn a_bare_file_name_is_in_the_current_directory() {
    assert_eq!(socket_directory(Path::new("n1.sock")), Path::new("."));
    assert_eq!(socket_directory(Path::new("./n1.sock")), Path::new("."));
    assert_eq!(
        socket_directory(Path::new("/run/menzil/a.sock")),
        Path::new("/run/menzil")
    );
    assert_eq!(socket_directory(Path::new("sub/a.sock")), Path::new("sub"));
}

/// L8: `env::vars` panics when a variable is not UTF-8, and a node must not die of what its
/// environment happens to hold.
#[cfg(unix)]
#[test]
fn an_environment_variable_that_is_not_text_is_left_out() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let vars = vec![
        (
            OsString::from("HTTPS_PROXY"),
            OsString::from("http://proxy:3128"),
        ),
        (
            OsString::from("BAD_VALUE"),
            OsString::from_vec(vec![b'x', 0xff]),
        ),
        (
            OsString::from_vec(vec![b'B', 0xfe]),
            OsString::from("value"),
        ),
    ];
    let env = text_environment(vars.into_iter());
    assert_eq!(env.len(), 1);
    assert_eq!(env["HTTPS_PROXY"], "http://proxy:3128");
}

/// L2: two nodes with one identity displace each other at the relay; the socket path alone did
/// not stop it (it depends on the environment).
#[test]
fn only_one_node_runs_per_home() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path());
    let first = home.lock_node().unwrap();
    let started = std::time::Instant::now();
    let error = format!("{:#}", home.lock_node().unwrap_err());
    assert!(
        error.contains("another `menzil node` is running"),
        "{error}"
    );
    // At once: a node does not wait ten seconds for another one to go away.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
    // Another home is another node.
    let other_dir = tempfile::tempdir().unwrap();
    let _other = Home::new(other_dir.path()).lock_node().unwrap();
    // The lock goes with the node.
    drop(first);
    let _again = home.lock_node().unwrap();
}

/// L1: a network whose documents cannot be read must not keep the others from being reloaded
/// (a revocation installed with `menzil join` would never be applied), and the name directory
/// must still follow the readable ones.
#[test]
fn one_unreadable_network_does_not_stop_the_reload_of_the_others() {
    let owner_dir = tempfile::tempdir().unwrap();
    let owner = Home::new(owner_dir.path());
    init(&owner, NOW).unwrap();
    let id = network_create(&owner, "laptop", NOW).unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let member = Home::new(member_dir.path());
    let request = init(&member, NOW).unwrap().join_request;
    let admitted = admit(&owner, None, &request, "phone", &[], NOW).unwrap();
    join(&member, &admitted.token, NOW).unwrap();
    let (policies, rosters, _) = load_stores(&member).unwrap();
    // A network that sorts before the good one and whose documents are damaged.
    let broken = member.root().join("networks").join("00".repeat(32));
    fs::create_dir_all(&broken).unwrap();
    fs::write(broken.join("documents.bin"), b"junk").unwrap();
    let renewed = renew(&owner, None, NOW + 86_400).unwrap();
    join(&member, &renewed.token, NOW + 86_400).unwrap();

    let directory = RwLock::new(Directory::default());
    let mut last = HashMap::new();
    let result = reload(&member, &policies, &rosters, &directory, &mut last);
    // The damage is reported ...
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("damaged"), "{error}");
    // ... and the good network was reloaded all the same, names included.
    assert_eq!(policies.seq(&id), Some(3));
    assert_eq!(last.get(&id), Some(&3));
    assert!(directory.read().unwrap().resolve("laptop").is_ok());
}

/// A directory that holds no documents (a failed write, a lock taken before the first save) is
/// not a network, and does not stop a node from starting or reloading.
#[test]
fn a_directory_without_documents_is_not_a_network() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path());
    init(&home, NOW).unwrap();
    let id = network_create(&home, "laptop", NOW).unwrap();
    fs::create_dir_all(home.root().join("networks").join("00".repeat(32))).unwrap();
    assert_eq!(home.networks().unwrap(), vec![id]);
    assert!(load_stores(&home).is_ok());
}

/// L2 through `start`: a second node on one home is refused before it touches the socket or the
/// relay, whatever `XDG_RUNTIME_DIR` says about where its socket would be.
#[tokio::test]
async fn a_second_node_on_one_home_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    init(&home, NOW).unwrap();
    network_create(&home, "laptop", NOW).unwrap();
    let info = crate::relay_cmd::connection_info(
        "relay.example.org",
        443,
        crate::relay_cmd::DEFAULT_PATH,
        &crate::relay_cmd::relay_identity(&home).unwrap(),
    )
    .unwrap();
    let config = Config::parse(&format!("relay = \"{info}\"\nproxy = \"direct\"\n")).unwrap();
    let first = start(&home, &config, &dir.path().join("a.sock"))
        .await
        .unwrap();
    // A different socket path: the old guard would not have noticed.
    let error = start(&home, &config, &dir.path().join("b.sock"))
        .await
        .err()
        .expect("a second node on the same home");
    assert!(
        format!("{error:#}").contains("another `menzil node` is running"),
        "{error:#}"
    );
    assert!(
        !dir.path().join("b.sock").exists(),
        "it never got as far as a socket"
    );
    drop(first);
    // Once the first node is gone the home is free again.
    let again = start(&home, &config, &dir.path().join("c.sock")).await;
    assert!(again.is_ok(), "{:#}", again.err().unwrap());
}
