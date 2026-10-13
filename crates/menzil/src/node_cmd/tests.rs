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
    assert!(check_socket_path_length(Path::new("/run/user/1000/menzil/agent.sock")).is_ok());
    assert!(check_socket_path_length(&long).is_err());
}
