use menzil_admin::NodeKeys;

use super::*;
use crate::local::{admit, init, join, network_create, renew};

/// A fixed moment near the real clock: what the stores adopt is judged against the real clock
/// (protocol.md 2.3), so a fixture issued years away from it would be refused.
fn clock() -> u64 {
    static BASE: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    *BASE
}

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
    init(&owner, clock()).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let member = Home::new(member_dir.path());
    let request = init(&member, clock()).unwrap().join_request;

    let directory = Directory::load(&owner).unwrap();
    assert_eq!(directory.resolve("laptop").unwrap().network_id, id);
    assert!(directory.resolve("phone").is_err());

    let admitted = admit(&owner, None, &request, "phone", &[], clock()).unwrap();
    let directory = Directory::load(&owner).unwrap();
    assert_eq!(
        directory.resolve("phone").unwrap().node_id,
        admitted.member.unwrap()
    );

    // A node's stores take what is on disk, and a reload picks up a newer pair.
    join(&member, &admitted.token, clock()).unwrap();
    let (policies, rosters, networks) = load_stores(&member).unwrap();
    assert_eq!(networks, vec![id]);
    assert_eq!(policies.seq(&id), Some(2));
    let renewed = renew(&owner, None, clock() + 60).unwrap();
    join(&member, &renewed.token, clock() + 60).unwrap();
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
    init(&home, clock()).unwrap();
    assert!(format!("{:#}", load_stores(&home).err().unwrap()).contains("menzil network create"));
    // Damaged documents stop it instead of leaving a network that rejects everybody.
    let id = network_create(&home, "me", clock()).unwrap();
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
    let text = explain(&NodeOpenError::Session(EnsureError::DocsOnly));
    assert!(
        text.contains("only took them") && text.contains("try again"),
        "{text}"
    );
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

/// The fourth red-team round, M2: OpenSSH lowercases the host name before it expands `%h`, so
/// `ssh Laptop` asks for `laptop`. A member `Laptop` has to be found that way, and a member of
/// another network that merely differs in letter case must not take the connection.
#[test]
fn names_compare_without_regard_to_letter_case_and_every_hit_counts() {
    // What ssh sends for `ssh Laptop` finds the member with the capital.
    let directory =
        Directory::from_entries(vec![entry(1, "Laptop", 0xaa), entry(1, "phone", 0xbb)]);
    for who in ["laptop", "Laptop", "LAPTOP"] {
        assert_eq!(
            directory.resolve(who).unwrap().node_id,
            NodeId::from([0xaa; 32]),
            "{who}"
        );
    }
    // The owner of another network names a member "laptop": that is no silent winner.
    let directory =
        Directory::from_entries(vec![entry(1, "Laptop", 0xaa), entry(2, "laptop", 0xcc)]);
    for who in ["laptop", "Laptop", "LAPTOP"] {
        let error = directory.resolve(who).unwrap_err();
        assert!(
            error.contains("ambiguous") && error.contains("aaaaaaaa") && error.contains("cccccccc"),
            "{who}: {error}"
        );
    }
    // A node id prefix still says which.
    assert_eq!(
        directory.resolve("cccccccc").unwrap().network_id,
        NetworkId::from([2; 32])
    );
    // Letters beyond ASCII fold the way the issuing tool folds them.
    let directory = Directory::from_entries(vec![entry(1, "Ünlü", 0xaa)]);
    assert!(directory.resolve("ünlü").is_ok());
    // Different names stay different.
    assert!(directory.resolve("unlu").is_err());
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

/// The fourth red-team round, N4: the socket's directory was used whoever could write to it,
/// and the chmods that follow the bind follow links. A directory others can write to is refused
/// (the sticky bit, as on /tmp, is the exception), and so is one that belongs to somebody else.
#[cfg(unix)]
#[tokio::test]
async fn a_socket_directory_that_others_can_write_to_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let set =
        |mode: u32| fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
    let socket = dir.path().join("a.sock");
    for mode in [0o777, 0o707, 0o702, 0o772, 0o757] {
        set(mode);
        let error = format!("{:#}", bind_agent_socket(&socket).await.err().unwrap());
        assert!(
            error.contains("can be written by other users"),
            "{mode:o}: {error}"
        );
        assert!(!socket.exists(), "{mode:o}: nothing was bound");
    }
    // Private, group writable (the usual private group: every directory is 0775 under umask
    // 0002), or world writable with the sticky bit (as /tmp is), is fine.
    for mode in [0o700, 0o755, 0o750, 0o770, 0o775, 0o1777] {
        set(mode);
        let listener = bind_agent_socket(&socket)
            .await
            .unwrap_or_else(|e| panic!("{mode:o}: {e:#}"));
        drop(listener);
        let _ = fs::remove_file(&socket);
    }
    // A directory of somebody else (not root) is refused whatever its mode; checked with a
    // user id that is not the owner's.
    set(0o700);
    let me = agent::current_uid().await.unwrap();
    assert!(check_private_directory(dir.path(), me).is_ok());
    let error = format!(
        "{:#}",
        check_private_directory(dir.path(), me + 1).unwrap_err()
    );
    assert!(error.contains("belongs to another user"), "{error}");
    // A file is not a directory.
    let file = dir.path().join("f");
    fs::write(&file, b"x").unwrap();
    assert!(check_private_directory(&file, me).is_err());
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
    init(&owner, clock()).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let member = Home::new(member_dir.path());
    let request = init(&member, clock()).unwrap().join_request;
    let admitted = admit(&owner, None, &request, "phone", &[], clock()).unwrap();
    join(&member, &admitted.token, clock()).unwrap();
    let (policies, rosters, _) = load_stores(&member).unwrap();
    // A network that sorts before the good one and whose documents are damaged.
    let broken = member.root().join("networks").join("00".repeat(32));
    fs::create_dir_all(&broken).unwrap();
    fs::write(broken.join("documents.bin"), b"junk").unwrap();
    let renewed = renew(&owner, None, clock() + 60).unwrap();
    join(&member, &renewed.token, clock() + 60).unwrap();

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

/// The fourth red-team round, L1: a network whose documents become unreadable between two
/// reloads keeps its names in the directory. Left out, a name that two networks share (refused
/// as ambiguous until then) would silently mean the other network's member, while the stores
/// went on holding the damaged network's documents.
#[test]
fn a_network_that_becomes_unreadable_keeps_its_names() {
    // One device in two networks, each owned by a device that calls itself "laptop".
    let member_dir = tempfile::tempdir().unwrap();
    let member = Home::new(member_dir.path());
    let request = init(&member, clock()).unwrap().join_request;
    let (mut ids, mut keep_alive) = (Vec::new(), Vec::new());
    for _ in 0..2 {
        let dir = tempfile::tempdir().unwrap();
        let owner = Home::new(dir.path());
        init(&owner, clock()).unwrap();
        ids.push(network_create(&owner, "laptop", clock()).unwrap());
        let admitted = admit(&owner, None, &request, "phone", &[], clock()).unwrap();
        join(&member, &admitted.token, clock()).unwrap();
        keep_alive.push(dir);
    }
    let (policies, rosters, _) = load_stores(&member).unwrap();
    let directory = RwLock::new(Directory::load(&member).unwrap());
    let mut last = HashMap::new();
    reload(&member, &policies, &rosters, &directory, &mut last).unwrap();
    let error = directory.read().unwrap().resolve("laptop").unwrap_err();
    assert!(error.contains("ambiguous"), "{error}");

    // The first network's documents are damaged between two reloads.
    fs::write(member.documents_path(&ids[0]), b"junk").unwrap();
    let result = reload(&member, &policies, &rosters, &directory, &mut last);
    assert!(result.is_err(), "the damage is reported");
    let error = directory
        .read()
        .unwrap()
        .resolve("laptop")
        .expect_err("the damaged network's names are kept, so the name is still ambiguous");
    assert!(error.contains("ambiguous"), "{error}");
}

/// A directory that holds no documents (a failed write, a lock taken before the first save) is
/// not a network, and does not stop a node from starting or reloading.
#[test]
fn a_directory_without_documents_is_not_a_network() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path());
    init(&home, clock()).unwrap();
    let id = network_create(&home, "laptop", clock()).unwrap();
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
    init(&home, clock()).unwrap();
    network_create(&home, "laptop", clock()).unwrap();
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

// ----------------------------------------------------------------------------------------
// The fifth red-team round, M1: the path to a socket must not be changeable by anybody else.
// One user id is all a test has, so "made by another user" is a link-owner function that says
// so, and "somebody else can write here" is the directory mode.
// ----------------------------------------------------------------------------------------

#[cfg(unix)]
fn owner_of(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).unwrap().uid()
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// `prepare_chain` with the real owner of a link.
#[cfg(unix)]
fn chain(dir: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    prepare_chain(dir, uid, &|link| link.uid())
}

#[cfg(unix)]
#[test]
fn a_link_in_the_path_made_by_another_user_is_refused() {
    let base = tempfile::tempdir().unwrap();
    let me = owner_of(base.path());
    fs::create_dir(base.path().join("real")).unwrap();
    std::os::unix::fs::symlink("real", base.path().join("via")).unwrap();
    let through = base.path().join("via");
    // A link of this user is fine...
    chain(&through, me).unwrap();
    // ...the same link made by somebody else is not, however private what it leads to is.
    let error = format!(
        "{:#}",
        prepare_chain(&through, me, &|_| me + 1).unwrap_err()
    );
    assert!(error.contains("a link made by another user"), "{error}");
    // Root's links are the system's own (`/tmp` is one on macOS).
    prepare_chain(&through, me, &|_| 0).unwrap();
}

/// The shape of the report: a link in a sticky directory, pointing at a private one.
#[cfg(unix)]
#[test]
fn a_link_that_others_can_replace_is_refused_even_when_this_user_made_it() {
    let base = tempfile::tempdir().unwrap();
    let me = owner_of(base.path());
    let shared = base.path().join("shared");
    fs::create_dir(&shared).unwrap();
    fs::create_dir(base.path().join("real")).unwrap();
    std::os::unix::fs::symlink("../real", shared.join("via")).unwrap();
    let through = shared.join("via");
    // A directory only this user can change: fine.
    chain(&through, me).unwrap();
    // Others can write to it (without the sticky bit): they can replace the link.
    set_mode(&shared, 0o777);
    let error = format!("{:#}", chain(&through, me).unwrap_err());
    assert!(error.contains("can be written by other users"), "{error}");
    // With the sticky bit (as `/tmp` has) they cannot.
    set_mode(&shared, 0o1777);
    chain(&through, me).unwrap();
}

/// The fix covers what the link leads through, not only what the path says: a link to a
/// directory whose own parent others can write to.
#[cfg(unix)]
#[test]
fn a_directory_behind_a_link_is_checked_as_it_really_is() {
    let base = tempfile::tempdir().unwrap();
    let me = owner_of(base.path());
    let open = base.path().join("open");
    fs::create_dir(&open).unwrap();
    fs::create_dir(open.join("inner")).unwrap();
    set_mode(&open.join("inner"), 0o700);
    std::os::unix::fs::symlink("open/inner", base.path().join("via")).unwrap();
    let through = base.path().join("via");
    chain(&through, me).unwrap();
    // `open` is not on the path as written (`via` is), but the kernel goes through it.
    set_mode(&open, 0o777);
    let error = format!("{:#}", chain(&through, me).unwrap_err());
    assert!(error.contains("can be written by other users"), "{error}");
    assert!(error.contains("open"), "{error}");
}

/// Nothing is made below a step that failed (so nothing is made through a link someone else
/// made, or in a directory others can write to), and what is made is private.
#[cfg(unix)]
#[test]
fn missing_directories_are_made_private_and_only_below_steps_that_passed() {
    use std::os::unix::fs::PermissionsExt;
    let base = tempfile::tempdir().unwrap();
    let me = owner_of(base.path());
    let deep = base.path().join("a").join("b").join("c");
    chain(&deep, me).unwrap();
    for dir in ["a", "a/b", "a/b/c"] {
        let mode = fs::metadata(base.path().join(dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{dir}");
    }
    // Below a directory others can write to: refused, and not made.
    let open = base.path().join("open");
    fs::create_dir(&open).unwrap();
    set_mode(&open, 0o777);
    let below = open.join("new").join("deeper");
    assert!(chain(&below, me).is_err());
    assert!(!open.join("new").exists(), "made below a step that failed");
    // Below a link made by another user: refused, and not made in what it leads to.
    let real = base.path().join("real");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink("real", base.path().join("via")).unwrap();
    let error = format!(
        "{:#}",
        prepare_chain(&base.path().join("via").join("new"), me, &|_| me + 1).unwrap_err()
    );
    assert!(error.contains("a link made by another user"), "{error}");
    assert!(
        !real.join("new").exists(),
        "made through a link of another user"
    );
}

/// Ownership is checked on every step, not only on the last directory.
#[cfg(unix)]
#[test]
fn a_directory_that_belongs_to_another_user_is_refused_on_the_way_too() {
    let base = tempfile::tempdir().unwrap();
    let me = owner_of(base.path());
    let inner = base.path().join("inner");
    fs::create_dir(&inner).unwrap();
    // With a user id that is not the owner's, the first directory that is not root's fails.
    let error = format!("{:#}", chain(&inner, me + 1).unwrap_err());
    assert!(error.contains("belongs to another user"), "{error}");
}

#[cfg(unix)]
#[tokio::test]
async fn a_socket_in_a_directory_behind_a_link_of_this_user_binds_and_is_found_again() {
    let base = tempfile::tempdir().unwrap();
    fs::create_dir(base.path().join("real")).unwrap();
    std::os::unix::fs::symlink("real", base.path().join("via")).unwrap();
    let path = base.path().join("via").join("a.sock");
    let listener = bind_private_socket(&path, &AGENT_SOCKET).await.unwrap();
    assert!(path.exists());
    let identity = file_identity(&path).unwrap();
    assert_eq!(
        identity,
        file_identity(&base.path().join("real").join("a.sock")).unwrap()
    );
    drop(listener);
}

#[cfg(unix)]
#[tokio::test]
async fn a_socket_is_removed_only_while_the_path_still_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.sock");
    // The socket this run made: removed.
    let first = bind_private_socket(&path, &AGENT_SOCKET).await.unwrap();
    let identity = file_identity(&path).unwrap();
    assert!(remove_if_unchanged(&path, identity));
    assert!(!path.exists());
    // Already gone: nothing to do.
    assert!(!remove_if_unchanged(&path, identity));
    drop(first);

    // Another socket put at the path (by another run, or by somebody else): left alone.
    let mine = bind_private_socket(&path, &AGENT_SOCKET).await.unwrap();
    let identity = file_identity(&path).unwrap();
    fs::remove_file(&path).unwrap();
    let theirs = UnixListener::bind(&path).unwrap();
    assert!(!remove_if_unchanged(&path, identity));
    assert!(
        path.exists(),
        "removed a socket that is not the one that was made"
    );
    drop((mine, theirs));
    fs::remove_file(&path).unwrap();

    // A file, a link or a directory at the path: left alone.
    let mine = bind_private_socket(&path, &AGENT_SOCKET).await.unwrap();
    let identity = file_identity(&path).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"precious").unwrap();
    assert!(!remove_if_unchanged(&path, identity));
    assert_eq!(fs::read(&path).unwrap(), b"precious");
    drop(mine);
}

/// A trailing slash is not a file name (`Path` ignores it, which would take `dir/` for the file
/// `dir`); the agent socket and the reach socket share the check.
#[cfg(unix)]
#[tokio::test]
async fn a_socket_path_must_name_a_file() {
    let base = tempfile::tempdir().unwrap();
    for bad in [
        format!("{}/", base.path().join("dirx").display()),
        format!("{}/.", base.path().display()),
        format!("{}/..", base.path().display()),
        "/".to_string(),
    ] {
        let error = format!(
            "{:#}",
            bind_private_socket(Path::new(&bad), &AGENT_SOCKET)
                .await
                .err()
                .unwrap()
        );
        assert!(
            error.contains("does not name a socket file"),
            "{bad}: {error}"
        );
        assert!(error.contains("agent_socket"), "{bad}: {error}");
    }
    assert!(!base.path().join("dirx").exists());
}

/// Round 6, M2: documents on disk that ran out hold back their own network, not the node: the
/// stores load without it, and the other networks are held.
#[test]
fn expired_documents_on_disk_do_not_stop_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("menzil"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let then = now - 15 * 24 * 3600;
    crate::local::init(&home, then).unwrap();
    let old = crate::local::network_create(&home, "laptop", then).unwrap();
    let fresh = crate::local::network_create(&home, "laptop", now).unwrap();
    let (policies, rosters, networks) =
        load_stores(&home).expect("expired documents of one network must not stop the node");
    assert!(networks.contains(&old) && networks.contains(&fresh));
    assert_eq!(rosters.seq(&old), None);
    assert_eq!(policies.seq(&old), None);
    assert!(rosters.seq(&fresh).is_some());
    assert!(policies.seq(&fresh).is_some());
}

/// Round 6, L1: a Roster that reached the node over L3 ahead of the docs token on disk is not a
/// failure of the reload; the node waits, and takes the pair when a newer token is installed.
#[test]
fn a_roster_from_the_relay_ahead_of_the_disk_pair_makes_the_reload_wait() {
    let owner_dir = tempfile::tempdir().unwrap();
    let owner = Home::new(owner_dir.path());
    init(&owner, clock()).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let member_dir = tempfile::tempdir().unwrap();
    let member = Home::new(member_dir.path());
    let request = init(&member, clock()).unwrap().join_request;
    let admitted = admit(&owner, None, &request, "phone", &[], clock()).unwrap();
    join(&member, &admitted.token, clock()).unwrap();
    let (policies, rosters, _) = load_stores(&member).unwrap();
    let start = policies.seq(&id).unwrap();
    let third = renew(&owner, None, clock() + 60).unwrap();
    let fourth = renew(&owner, None, clock() + 120).unwrap();
    let roster4 = crate::local::load_documents(&owner, &id)
        .unwrap()
        .roster()
        .clone();
    assert!(rosters.adopt_owner(&roster4, clock() + 120).unwrap());
    let held = rosters.seq(&id).unwrap();
    join(&member, &third.token, clock() + 60).unwrap();
    let directory = RwLock::new(Directory::default());
    let mut last = HashMap::new();
    reload(&member, &policies, &rosters, &directory, &mut last)
        .expect("a disk pair older than the held Roster is waited for, not an error");
    assert_eq!(rosters.seq(&id), Some(held));
    assert_eq!(policies.seq(&id), Some(start));
    // The matching token is installed: the pair is taken.
    join(&member, &fourth.token, clock() + 120).unwrap();
    reload(&member, &policies, &rosters, &directory, &mut last).unwrap();
    assert_eq!(policies.seq(&id), Some(held));
}

/// Protocol.md 2.3 (TODO L4j S3): a node that holds documents a steward signed loads them
/// through the acceptance predicate with their base, and picks up the steward's next ones when
/// they are written to disk, without a restart.
#[test]
fn a_node_loads_and_reloads_documents_a_steward_signed() {
    use menzil_proto::trust::Signer;
    let owner_dir = tempfile::tempdir().unwrap();
    let owner = Home::new(owner_dir.path());
    init(&owner, clock()).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let steward_dir = tempfile::tempdir().unwrap();
    let steward = Home::new(steward_dir.path());
    let request = init(&steward, clock()).unwrap().join_request;
    let admitted = admit(&owner, None, &request, "steward", &[], clock()).unwrap();
    join(&steward, &admitted.token, clock()).unwrap();
    let asked = crate::local::steward_request(&steward, None).unwrap();
    let listed = crate::local::steward_add(
        &owner,
        None,
        &asked.token,
        &["admit".to_string(), "renew".to_string()],
        30,
        clock(),
    )
    .unwrap();
    join(&steward, &listed.issued.token, clock()).unwrap();
    renew(&steward, None, clock() + 60).unwrap();

    let (policies, rosters, networks) = load_stores(&steward).unwrap();
    assert_eq!(networks, vec![id]);
    assert_eq!((rosters.seq(&id), policies.seq(&id)), (Some(4), Some(4)));
    assert!(matches!(
        rosters.signer(&id),
        Some(Signer::Steward { base_seq: 3, .. })
    ));
    assert_eq!(rosters.base(&id).unwrap().decode().unwrap().seq, 3);
    assert_eq!(policies.base(&id).unwrap().decode().unwrap().seq, 3);

    // The steward admits a device while the node runs; the reload takes it, base and all.
    let phone_dir = tempfile::tempdir().unwrap();
    let phone = Home::new(phone_dir.path());
    let phone_request = init(&phone, clock()).unwrap().join_request;
    let directory = RwLock::new(Directory::load(&steward).unwrap());
    admit(&steward, None, &phone_request, "phone", &[], clock() + 120).unwrap();
    let mut last = HashMap::new();
    reload(&steward, &policies, &rosters, &directory, &mut last).unwrap();
    assert_eq!((rosters.seq(&id), policies.seq(&id)), (Some(5), Some(5)));
    assert_eq!(rosters.base(&id).unwrap().decode().unwrap().seq, 3);
    assert!(directory.read().unwrap().resolve("phone").is_ok());

    // A member that holds the owner's pair loads the steward's from the token like any other.
    let (policies2, rosters2, _) = load_stores(&owner).unwrap();
    assert_eq!(rosters2.seq(&id), Some(3));
    assert!(rosters2.base(&id).is_none());
    let docs = crate::local::load_documents(&steward, &id).unwrap();
    join(
        &owner,
        &crate::token::encode_documents(&docs),
        clock() + 120,
    )
    .unwrap();
    let directory2 = RwLock::new(Directory::default());
    reload(
        &owner,
        &policies2,
        &rosters2,
        &directory2,
        &mut HashMap::new(),
    )
    .unwrap();
    assert_eq!((rosters2.seq(&id), policies2.seq(&id)), (Some(5), Some(5)));
    assert!(matches!(rosters2.signer(&id), Some(Signer::Steward { .. })));

    // The file with its base cut off is not trusted: the node does not start on it.
    let docs_path = steward.documents_path(&id);
    let bare = crate::token::documents_to_bytes(
        &menzil_admin::Documents::from_signed(docs.roster().clone(), docs.policy().clone())
            .unwrap(),
    );
    std::fs::write(&docs_path, bare).unwrap();
    assert!(load_stores(&steward).is_err());
}
