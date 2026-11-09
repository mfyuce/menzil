use std::time::Duration;

use menzil_admin::{NodeKeys, OwnerKey, create_network};
use menzil_carrier::ConnectionInfo;
use menzil_proto::Policy;

use super::*;
use crate::local::{init, join, network_create};
use crate::token::{encode_documents, encode_roster};

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
const DAY: u64 = 24 * 60 * 60;

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("menzil"));
    (dir, home)
}

/// An owner's token for a network, and the owner's home.
fn token_of_a_network() -> (tempfile::TempDir, Home, NetworkId, String) {
    let (dir, owner) = home();
    init(&owner, clock()).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let token = crate::local::token(&owner, None).unwrap();
    (dir, owner, id, token)
}

/// The token an owner gives a relay's operator: the Roster alone.
fn relay_token(owner: &Home) -> String {
    crate::local::token_for_relay(owner, None).unwrap()
}

fn pem_files(dir: &Path) -> (PathBuf, PathBuf) {
    let certified = rcgen::generate_simple_self_signed(vec!["relay.example".to_string()]).unwrap();
    let cert = dir.join("fullchain.pem");
    let key = dir.join("privkey.pem");
    fs::write(&cert, certified.cert.pem()).unwrap();
    fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
    (cert, key)
}

#[test]
fn a_relay_keeps_the_roster_of_a_network_and_not_its_policy() {
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let (_d, relay) = home();
    let (network, seq) = add_network(&relay, &relay_token(&owner), clock() + 1).unwrap();
    assert_eq!((network, seq), (id, 1));

    let rosters = load_rosters(&relay).unwrap();
    assert_eq!(rosters.len(), 1);
    assert_eq!(rosters[0].roster.decode().unwrap().network_id, id);
    // Nothing of the Policy is on disk: members' names and grants are none of a relay's business.
    let bytes = fs::read(roster_path(&relay, &id)).unwrap();
    assert_eq!(bytes, rosters[0].roster.encode());
    assert!(
        !bytes.windows(6).any(|w| w == b"laptop"),
        "a member's name is in the Policy, not in what a relay keeps"
    );
    assert!(Policy::decode_strict(&bytes).unwrap().decode().is_err());
    assert!(!relay.documents_path(&id).exists());
}

/// The fourth red-team round, N5: two `add-network` runs at the same moment each looked at what
/// was held, then wrote; the slower write could put the older Roster over the newer one.
#[test]
fn add_network_runs_at_the_same_moment_leave_the_newest_roster() {
    const TOKENS: usize = 6;
    const ROUNDS: usize = 10;
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let mut tokens = vec![relay_token(&owner)];
    for step in 1..TOKENS as u64 {
        crate::local::renew(&owner, None, clock() + step * DAY).unwrap();
        tokens.push(relay_token(&owner));
    }
    for round in 0..ROUNDS {
        let (_d, relay) = home();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(TOKENS));
        // Every Roster is still valid on the day all of them are added.
        let now = clock() + TOKENS as u64 * DAY;
        let threads: Vec<_> = tokens
            .iter()
            .map(|token| {
                let (token, relay, barrier) = (token.clone(), relay.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    add_network(&relay, &token, now)
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        let kept = load_rosters(&relay).unwrap();
        assert_eq!(kept.len(), 1, "round {round}");
        assert_eq!(
            kept[0].roster.decode().unwrap().seq,
            TOKENS as u64,
            "round {round}: the relay must end up with the newest Roster of {id}"
        );
    }
}

#[test]
fn an_older_or_equal_roster_does_not_replace_a_newer_one() {
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let first = relay_token(&owner);
    let (_d, relay) = home();
    add_network(&relay, &first, clock()).unwrap();
    crate::local::renew(&owner, None, clock() + DAY).unwrap();
    assert_eq!(
        add_network(&relay, &relay_token(&owner), clock() + DAY).unwrap(),
        (id, 2)
    );
    // The first token again: the relay keeps what is newer and says so.
    assert_eq!(add_network(&relay, &first, clock() + DAY).unwrap(), (id, 2));
    assert_eq!(
        load_rosters(&relay).unwrap()[0]
            .roster
            .decode()
            .unwrap()
            .seq,
        2
    );
}

#[test]
fn add_network_refuses_forged_expired_and_wrong_tokens() {
    let (_o, owner, _id, docs_token) = token_of_a_network();
    let token = relay_token(&owner);
    let (_d, relay) = home();
    let message =
        |token: &str, at: u64| format!("{:#}", add_network(&relay, token, at).unwrap_err());

    assert!(message(&token, clock() + 15 * DAY).contains("expired"));
    assert!(
        message("menzil1-join:AAAA", clock()).contains("other kind")
            || message("menzil1-join:AAAA", clock()).contains("expected")
    );
    assert!(message("garbage", clock()).contains("expected"));

    // Documents of the owner's network, signed by somebody else.
    let owner = OwnerKey::generate();
    let keys = NodeKeys::generate();
    let cert = keys.issue_cert(1, clock() - 10, clock() + 1000).unwrap();
    let docs = create_network(&owner, &cert, "x", clock()).unwrap();
    let thief = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let forged = encode_roster(&Roster::sign(&thief, docs.roster_body()).unwrap(), None);
    assert!(message(&forged, clock()).contains("not signed by the network's owner"));

    // The full membership token carries the Policy, and a relay is not given that.
    let refused = message(&docs_token, clock());
    assert!(
        refused.contains("Policy") && refused.contains("--for-relay"),
        "{refused}"
    );
    let forged_docs = encode_documents(
        &menzil_admin::Documents::from_signed(
            Roster::sign(&thief, docs.roster_body()).unwrap(),
            Policy::sign(&thief, docs.policy_body()).unwrap(),
        )
        .unwrap(),
    );
    assert!(message(&forged_docs, clock()).contains("--for-relay"));
    assert!(load_rosters(&relay).unwrap().is_empty());
}

/// The third red-team round, M6: the token for a relay carries the Roster and nothing of the
/// Policy, so that what the Policy keeps from relays (who may use what, the members' device
/// names) is not on the relay operator's command line, in their shell history or in `ps`.
#[test]
fn the_token_for_a_relay_holds_the_roster_and_none_of_the_policy() {
    let (_o, owner, _id, docs_token) = token_of_a_network();
    let relay_token = relay_token(&owner);
    assert!(relay_token.starts_with(crate::token::ROSTER_PREFIX));
    assert!(
        relay_token.len() < docs_token.len(),
        "the Policy is not in it"
    );
    // It decodes as a Roster, and as nothing else.
    let (roster, base) = crate::token::decode_roster(&relay_token).unwrap();
    assert!(base.is_none());
    assert_eq!(roster.decode().unwrap().members.len(), 1);
    assert!(crate::token::decode_documents(&relay_token).is_err());
    assert!(crate::local::join(&home().1, &relay_token, clock()).is_err());
    // And the name of the device, which only the Policy holds, is nowhere in the text's bytes.
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&relay_token[crate::token::ROSTER_PREFIX.len()..])
        .unwrap();
    assert!(!bytes.windows(6).any(|w| w == b"laptop"));
}

#[test]
fn a_damaged_roster_file_is_an_error_and_strangers_are_ignored() {
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let (_d, relay) = home();
    add_network(&relay, &relay_token(&owner), clock()).unwrap();
    fs::write(relay_dir(&relay).join("notes.txt"), b"x").unwrap();
    fs::write(relay_dir(&relay).join("readme.roster"), b"x").unwrap();
    assert_eq!(load_rosters(&relay).unwrap().len(), 1);

    fs::write(roster_path(&relay, &id), b"junk").unwrap();
    let error = format!("{:#}", load_rosters(&relay).unwrap_err());
    assert!(error.contains("damaged"), "{error}");
}

#[test]
fn the_connection_information_names_the_relay_and_parses_back() {
    let (_d, relay) = home();
    init(&relay, clock()).unwrap();
    let identity = relay_identity(&relay).unwrap();
    let text = connection_info("relay.example.org", 443, DEFAULT_PATH, &identity).unwrap();
    let info = ConnectionInfo::parse(&text).unwrap();
    let cert = identity.node_cert.decode().unwrap();
    assert_eq!((info.host.as_str(), info.port), ("relay.example.org", 443));
    assert_eq!(info.path, DEFAULT_PATH);
    assert_eq!(info.relay_node_id, cert.node_id);
    assert_eq!(info.relay_x25519, Some(cert.x25519_pub));
}

#[test]
fn tls_comes_from_pem_files_and_bad_files_are_named() {
    let dir = tempfile::tempdir().unwrap();
    let (cert, key) = pem_files(dir.path());
    let config = tls_from_pem(&cert, &key).unwrap();
    assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);

    let message = |cert: &Path, key: &Path| format!("{:#}", tls_from_pem(cert, key).unwrap_err());
    let missing = dir.path().join("missing.pem");
    assert!(message(&missing, &key).contains("missing.pem"));
    assert!(message(&cert, &missing).contains("missing.pem"));
    // A key where the certificate belongs, and the reverse.
    assert!(message(&key, &key).contains("no"));
    assert!(message(&cert, &cert).contains("no private key"));
    let empty = dir.path().join("empty.pem");
    fs::write(&empty, "").unwrap();
    assert!(message(&empty, &key).contains("no certificate"));
}

#[tokio::test]
async fn a_relay_starts_with_its_networks_and_says_how_to_reach_it() {
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    let (cert, key) = pem_files(dir.path());
    let options = RunOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_cert: cert,
        tls_key: key,
        path: DEFAULT_PATH.to_string(),
        host: Some("localhost".to_string()),
        reload_every: Duration::from_millis(100),
        fallback_page: None,
    };

    // No network yet: a relay that would refuse everyone does not start.
    let error = start(&relay_home, &options).await.err().unwrap();
    assert!(format!("{error:#}").contains("add-network"));

    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &options).await.unwrap();
    assert_eq!(running.networks, vec![id]);
    assert_ne!(running.addr.port(), 0);
    let info = ConnectionInfo::parse(&running.connection_info).unwrap();
    assert_eq!(
        (info.host.as_str(), info.port),
        ("localhost", running.addr.port())
    );
    assert_eq!(
        info.relay_node_id,
        relay_identity(&relay_home)
            .unwrap()
            .node_cert
            .decode()
            .unwrap()
            .node_id
    );
    running.stop();
}

#[test]
fn a_member_device_is_not_a_relay_and_cannot_join_as_one() {
    // The relay machine never `join`s: it is not a member, and `join` says so.
    let (_o, _owner, _id, token) = token_of_a_network();
    let (_d, relay) = home();
    init(&relay, clock()).unwrap();
    let error = format!("{:#}", join(&relay, &token, clock()).unwrap_err());
    assert!(error.contains("not a member"), "{error}");
}

/// `menzil renew` on the owner and `add-network` with the new token on the relay's machine, while
/// the relay runs: the relay holds the newer Roster a moment later, without a restart.
/// The fourth red-team round, L3: one unreadable Roster file stopped every update, so a newer
/// Roster (a revocation, say) added for another network was not picked up while the file stayed
/// damaged. Each file is read on its own.
#[tokio::test]
async fn one_damaged_roster_file_does_not_stop_the_reload_of_the_others() {
    let (_oa, owner_a, id_a, _) = token_of_a_network();
    let (_ob, owner_b, id_b, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner_a), clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner_b), clock()).unwrap();
    let (cert, key) = pem_files(dir.path());
    let running = start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert,
            tls_key: key,
            path: DEFAULT_PATH.to_string(),
            host: None,
            reload_every: Duration::from_millis(50),
            fallback_page: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(running.roster_seq(&id_a), Some(1));
    assert_eq!(running.roster_seq(&id_b), Some(1));

    // Network A's file is damaged; network B gets a newer Roster.
    fs::write(roster_path(&relay_home, &id_a), b"junk").unwrap();
    crate::local::renew(&owner_b, None, clock() + 60).unwrap();
    add_network(&relay_home, &relay_token(&owner_b), clock() + 60).unwrap();
    let mut seq = 0;
    for _ in 0..100 {
        seq = running.roster_seq(&id_b).unwrap();
        if seq == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        seq, 2,
        "the damaged file of another network kept the relay from taking the newer Roster"
    );
    assert_eq!(
        running.roster_seq(&id_a),
        Some(1),
        "the damaged network keeps what the relay held"
    );
}

#[tokio::test]
async fn a_running_relay_picks_up_a_newer_roster_added_to_its_directory() {
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let (cert, key) = pem_files(dir.path());
    let running = start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert,
            tls_key: key,
            path: DEFAULT_PATH.to_string(),
            host: None,
            reload_every: Duration::from_millis(50),
            fallback_page: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(running.roster_seq(&id), Some(1));

    crate::local::renew(&owner, None, clock() + 60).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock() + 60).unwrap();
    let mut seq = 0;
    for _ in 0..100 {
        seq = running.roster_seq(&id).unwrap();
        if seq == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(seq, 2, "the relay never took the newer Roster");

    // A broken file does not stop the relay or change what it holds.
    fs::write(roster_path(&relay_home, &id), b"junk").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(running.roster_seq(&id), Some(2));
}

/// Round 6, M1 and round 9, M2: one network whose Roster on disk has expired (renewals travel by
/// DOC, which the relay does not write back) does not stop the relay and does not hold back the
/// others. The expired Roster is held, so a member's newer Roster can replace it, but it
/// forwards nothing; one issued more than 14 days ahead of the clock is not held.
#[tokio::test]
async fn an_expired_roster_on_disk_is_held_but_forwards_nothing() {
    let (_oa, owner_a) = home();
    init(&owner_a, clock() - 15 * DAY).unwrap();
    let id_a = network_create(&owner_a, "laptop", clock() - 15 * DAY).unwrap();
    let (_ob, owner_b, id_b, _) = token_of_a_network();
    let (_oc, owner_c) = home();
    init(&owner_c, clock() + 20 * DAY).unwrap();
    let id_c = network_create(&owner_c, "laptop", clock() + 20 * DAY).unwrap();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner_a), clock() - 15 * DAY + 60).unwrap();
    add_network(&relay_home, &relay_token(&owner_b), clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner_c), clock() + 20 * DAY).unwrap();
    let (cert, key) = pem_files(dir.path());
    let options = RunOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_cert: cert,
        tls_key: key,
        path: DEFAULT_PATH.to_string(),
        host: Some("localhost".to_string()),
        reload_every: Duration::from_millis(100),
        fallback_page: None,
    };
    let running = start(&relay_home, &options)
        .await
        .expect("an expired Roster of one network must not stop the relay");
    assert!(running.networks.contains(&id_a) && running.networks.contains(&id_b));
    assert!(!running.networks.contains(&id_c));
    assert!(running.roster_seq(&id_b).is_some());
    assert!(running.roster_seq(&id_a).is_some(), "held");
    assert_eq!(running.roster_seq(&id_c), None);
    // Held, not used: the owner is a member of its own network, and nothing is forwarded.
    let owner_node = crate::local::load_documents(&owner_a, &id_a)
        .unwrap()
        .roster_body()
        .members[0]
        .node_id;
    let rosters = running.relay.rosters();
    assert!(
        rosters
            .grants_forwarding(&owner_node, &[id_a], &owner_node, clock())
            .is_empty()
    );
    // A newer Roster (what a member pushes over DOC) replaces it, and then forwards.
    let renewed = crate::local::renew(&owner_a, None, clock()).unwrap();
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    assert!(rosters.adopt(pair.roster(), None, clock()).unwrap());
    assert_eq!(running.roster_seq(&id_a), Some(renewed.seq));
    assert_eq!(
        rosters.grants_forwarding(&owner_node, &[id_a], &owner_node, clock()),
        vec![id_a]
    );
    running.stop();
}

/// A network whose steward renewed: the owner's home, the steward device's home and the network.
fn steward_renewed_network() -> (tempfile::TempDir, Home, tempfile::TempDir, Home, NetworkId) {
    let (od, owner) = home();
    init(&owner, clock()).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let (sd, steward) = home();
    let request = init(&steward, clock()).unwrap().join_request;
    let admitted = crate::local::admit(&owner, None, &request, "steward", &[], clock()).unwrap();
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
    crate::local::renew(&steward, None, clock() + 60).unwrap();
    (od, owner, sd, steward, id)
}

/// Protocol.md 2.3, 4.3: a Roster a steward signed is kept by a relay together with the owner
/// signed Roster it was made from, and is refused without it.
#[test]
fn a_relay_keeps_a_steward_signed_roster_with_its_base() {
    let (_o, owner, _s, steward, id) = steward_renewed_network();
    let (_d, relay) = home();
    let token = relay_token(&steward);
    assert_eq!(add_network(&relay, &token, clock() + 61).unwrap(), (id, 4));
    let stored = load_rosters(&relay).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].roster.decode().unwrap().seq, 4);
    assert_eq!(stored[0].base.as_ref().unwrap().decode().unwrap().seq, 3);
    assert_eq!(fs::read(roster_path(&relay, &id)).unwrap()[0], 2);
    // What was kept is what the relay's store takes.
    let store = menzil_relay::RosterStore::new();
    assert!(
        store
            .adopt(&stored[0].roster, stored[0].base.as_ref(), clock() + 61)
            .unwrap()
    );

    // Without the base the same Roster is refused, and nothing is written.
    let (_d2, bare_relay) = home();
    let (roster, _) = crate::token::decode_roster(&token).unwrap();
    let message = format!(
        "{:#}",
        add_network(&bare_relay, &encode_roster(&roster, None), clock() + 61).unwrap_err()
    );
    assert!(
        message.contains("not signed by the network's owner"),
        "{message}"
    );
    assert!(load_rosters(&bare_relay).unwrap().is_empty());

    // The owner's older Roster does not replace it...
    let owner_token = relay_token(&owner);
    assert_eq!(
        add_network(&relay, &owner_token, clock() + 61).unwrap(),
        (id, 4)
    );
    // ...and the owner's newer one does, with no base kept.
    let renewed = crate::local::renew(&owner, None, clock() + 120).unwrap();
    assert_eq!(
        add_network(&relay, &relay_token(&owner), clock() + 120).unwrap(),
        (id, renewed.seq)
    );
    assert!(load_rosters(&relay).unwrap()[0].base.is_none());
    assert_eq!(fs::read(roster_path(&relay, &id)).unwrap()[0] & 0xf0, 0x80);
}

/// Protocol.md 2.3: a newer `seq` is not enough. A steward's Roster made from a base older than
/// the base of the Roster the relay keeps would undo what the owner changed since. (The owner
/// normally jumps past the steward's span; this is an owner who did not.)
#[test]
fn a_steward_roster_on_an_older_base_does_not_replace_a_newer_owner_roster() {
    use ed25519_dalek::SigningKey;
    use menzil_proto::{
        NodeId, PROTOCOL_VERSION, RosterBody, RosterMember, Steward, StewardBody, StewardKey,
    };
    let owner = SigningKey::generate(&mut rand::rng());
    let steward = SigningKey::generate(&mut rand::rng());
    let id = NetworkId::from(owner.verifying_key().to_bytes());
    let entry = Steward::sign(
        &owner,
        &StewardBody {
            v: PROTOCOL_VERSION,
            network_id: id,
            steward_pub: StewardKey::from(steward.verifying_key().to_bytes()),
            may: vec!["renew".to_string()],
            not_after: clock() + 30 * DAY,
        },
    )
    .unwrap();
    let roster = |seq: u64, members: u8| RosterBody {
        v: PROTOCOL_VERSION,
        network_id: id,
        seq,
        issued: clock(),
        expires: clock() + 7 * DAY,
        members: (1..=members)
            .map(|n| RosterMember {
                node_id: NodeId::from([n; 32]),
                min_serial: 1,
            })
            .collect(),
        revoked: vec![],
        stewards: vec![entry.clone()],
        labels: vec![],
    };
    let base5 = Roster::sign(&owner, &roster(5, 1)).unwrap();
    let owner8 = Roster::sign(&owner, &roster(8, 1)).unwrap();
    let stale = Roster::sign(&steward, &roster(10, 1)).unwrap();

    let (_d, relay) = home();
    assert_eq!(
        add_network(&relay, &encode_roster(&owner8, None), clock() + 1).unwrap(),
        (id, 8)
    );
    // Seq 10 is above 8, but its base (5) is older than the kept Roster's base (8).
    let message = format!(
        "{:#}",
        add_network(&relay, &encode_roster(&stale, Some(&base5)), clock() + 1).unwrap_err()
    );
    assert!(message.contains("not acceptable"), "{message}");
    let kept = load_rosters(&relay).unwrap();
    assert_eq!(kept[0].roster.decode().unwrap().seq, 8);
    assert!(kept[0].base.is_none());

    // A steward Roster made from the owner's seq 8 is still taken.
    let fresh = Roster::sign(&steward, &roster(11, 1)).unwrap();
    assert_eq!(
        add_network(&relay, &encode_roster(&fresh, Some(&owner8)), clock() + 1).unwrap(),
        (id, 11)
    );
    let kept = load_rosters(&relay).unwrap();
    assert_eq!(kept[0].roster.decode().unwrap().seq, 11);
    assert_eq!(kept[0].base.as_ref().unwrap().decode().unwrap().seq, 8);
}

#[tokio::test]
async fn a_relay_starts_and_reloads_with_a_steward_signed_roster() {
    let (_o, owner, _s, steward, id) = steward_renewed_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    let (cert, key) = pem_files(dir.path());
    let options = RunOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_cert: cert,
        tls_key: key,
        path: DEFAULT_PATH.to_string(),
        host: Some("localhost".to_string()),
        reload_every: Duration::from_millis(100),
        fallback_page: None,
    };
    // The relay got the owner's Roster first; the steward's, made from it, is added later.
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &options).await.unwrap();
    assert_eq!(running.roster_seq(&id), Some(3));
    add_network(&relay_home, &relay_token(&steward), clock() + 61).unwrap();
    let mut seq = running.roster_seq(&id);
    for _ in 0..50 {
        if seq == Some(4) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        seq = running.roster_seq(&id);
    }
    assert_eq!(
        seq,
        Some(4),
        "the reload takes the steward's Roster with its base"
    );
    running.stop();
    // And a start from a file that holds one.
    let running = start(&relay_home, &options).await.unwrap();
    assert_eq!(running.roster_seq(&id), Some(4));
    running.stop();
}

// ---- Rosters adopted over DOC are kept (TOBEDECIDED 19d) ----

fn run_options(dir: &Path) -> RunOptions {
    let (cert, key) = pem_files(dir);
    RunOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_cert: cert,
        tls_key: key,
        path: DEFAULT_PATH.to_string(),
        host: None,
        reload_every: Duration::from_secs(3600),
        fallback_page: None,
    }
}

const FLUSH: Duration = Duration::from_secs(10);

/// A Roster a member pushed over DOC is on disk once the keeper is done, and a relay started
/// after a restart holds it instead of the file the operator last wrote.
#[tokio::test]
async fn a_roster_adopted_over_doc_is_on_disk_and_the_next_start_holds_it() {
    let (_o, owner, id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let options = run_options(dir.path());
    let running = start(&relay_home, &options).await.unwrap();
    assert_eq!(running.roster_seq(&id), Some(1));

    let renewed = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 60)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    let stored = load_rosters(&relay_home).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].roster.decode().unwrap().seq, renewed.seq);
    running.stop();

    let restarted = start(&relay_home, &options).await.unwrap();
    assert_eq!(restarted.roster_seq(&id), Some(renewed.seq));
    restarted.stop();
}

/// A steward signed Roster adopted over DOC is kept with its base, in the file layout the
/// loader reads.
#[tokio::test]
async fn a_steward_signed_roster_adopted_over_doc_is_kept_with_its_base() {
    let (_o, owner, _s, steward, id) = steward_renewed_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock() + 61).unwrap();
    let options = run_options(dir.path());
    let running = start(&relay_home, &options).await.unwrap();
    let seeded = running.roster_seq(&id).unwrap();

    let (roster, base) = crate::token::decode_roster(&relay_token(&steward)).unwrap();
    assert!(base.is_some());
    assert!(
        running
            .relay
            .rosters()
            .adopt(&roster, base.as_ref(), clock() + 61)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    let stored = load_rosters(&relay_home).unwrap();
    assert_eq!(stored.len(), 1);
    let seq = roster.decode().unwrap().seq;
    assert!(seq > seeded);
    assert_eq!(stored[0].roster.decode().unwrap().seq, seq);
    assert_eq!(
        stored[0].base.as_ref().unwrap().decode().unwrap().seq,
        base.unwrap().decode().unwrap().seq
    );
    running.stop();
}

/// A Roster that cannot be written stays adopted in memory (the relay keeps serving it), the
/// damaged path is not replaced, and the next Roster is kept once the path is fine again.
#[tokio::test]
async fn a_roster_that_cannot_be_written_stays_adopted_and_the_keeper_goes_on() {
    let (_o, owner, id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &run_options(dir.path())).await.unwrap();
    let path = roster_path(&relay_home, &id);
    let good = fs::read(&path).unwrap();
    // A directory where the file goes: the atomic rename onto it fails.
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();

    let second = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&second.token).unwrap();
    let rosters = running.relay.rosters();
    assert!(rosters.adopt(pair.roster(), None, clock() + 60).unwrap());
    assert!(running.flush_rosters(FLUSH));
    assert_eq!(running.roster_seq(&id), Some(second.seq));
    assert!(path.is_dir());

    fs::remove_dir(&path).unwrap();
    fs::write(&path, good).unwrap();
    let third = crate::local::renew(&owner, None, clock() + 120).unwrap();
    let pair = crate::token::decode_documents(&third.token).unwrap();
    assert!(rosters.adopt(pair.roster(), None, clock() + 120).unwrap());
    assert!(running.flush_rosters(FLUSH));
    let stored = load_rosters(&relay_home).unwrap();
    assert_eq!(stored[0].roster.decode().unwrap().seq, third.seq);
    running.stop();
}

/// Never a lower `seq` on disk: a newer file the operator wrote while the relay ran is not
/// replaced by an older Roster that arrives over DOC afterwards.
#[tokio::test]
async fn a_roster_adopted_over_doc_does_not_replace_a_newer_file() {
    let (_o, owner, id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &run_options(dir.path())).await.unwrap();
    let second = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let third = crate::local::renew(&owner, None, clock() + 120).unwrap();
    // The operator installs the third while the relay holds the first (the reload is an hour
    // away); the second then arrives over DOC.
    add_network(&relay_home, &relay_token(&owner), clock() + 120).unwrap();
    let pair = crate::token::decode_documents(&second.token).unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 120)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    assert_eq!(
        load_rosters(&relay_home).unwrap()[0]
            .roster
            .decode()
            .unwrap()
            .seq,
        third.seq
    );
    assert_eq!(running.roster_seq(&id), Some(second.seq));
    running.stop();
}

// ---- round 10: the keeper updates and never creates; a clean stop flushes ----

/// Round 10, L2: a Roster file the operator deleted by hand while the relay ran (the running relay
/// holds the network until its next reload; `relay remove-network` is the supported way, and is
/// tested below) is not written back by the next Roster adopted over DOC.
#[tokio::test]
async fn a_removed_roster_file_is_not_brought_back_by_an_adopted_roster() {
    let (_o, owner, id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &run_options(dir.path())).await.unwrap();
    let path = roster_path(&relay_home, &id);
    fs::remove_file(&path).unwrap();
    let renewed = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 60)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    assert_eq!(
        running.roster_seq(&id),
        Some(renewed.seq),
        "still held in memory"
    );
    assert!(!path.exists(), "the deleted file stays deleted");
    running.stop();
    assert!(
        load_rosters(&relay_home).unwrap().is_empty(),
        "a restart would not serve the removed network"
    );
}

/// Round 10, L2: not even the relay's directory (and its lock file) is made for the keeper.
#[tokio::test]
async fn the_keeper_does_not_make_the_relay_directory() {
    let (_o, owner, id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &run_options(dir.path())).await.unwrap();
    let relay_dir = roster_path(&relay_home, &id)
        .parent()
        .unwrap()
        .to_path_buf();
    fs::remove_dir_all(&relay_dir).unwrap();
    let renewed = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 60)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    assert!(
        !relay_dir.exists(),
        "the keeper made {}",
        relay_dir.display()
    );
    running.stop();
}

/// Round 10, N1: the keeper never writes over a Roster file that cannot be read (TOBEDECIDED
/// 28e), and goes on with the next once it is readable again. `add-network` still replaces it.
#[tokio::test]
async fn the_keeper_does_not_write_over_a_damaged_roster_file() {
    let (_o, owner, id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &run_options(dir.path())).await.unwrap();
    let path = roster_path(&relay_home, &id);
    let good = fs::read(&path).unwrap();
    fs::write(&path, b"damaged").unwrap();
    let second = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&second.token).unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 60)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    assert_eq!(fs::read(&path).unwrap(), b"damaged");
    assert_eq!(running.roster_seq(&id), Some(second.seq));
    fs::write(&path, good).unwrap();
    let third = crate::local::renew(&owner, None, clock() + 120).unwrap();
    let pair = crate::token::decode_documents(&third.token).unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 120)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    assert_eq!(
        load_rosters(&relay_home).unwrap()[0]
            .roster
            .decode()
            .unwrap()
            .seq,
        third.seq
    );
    // The operator's own command still repairs a damaged file.
    fs::write(&path, b"damaged").unwrap();
    add_network(&relay_home, &relay_token(&owner), clock() + 120).unwrap();
    assert_eq!(
        load_rosters(&relay_home).unwrap()[0]
            .roster
            .decode()
            .unwrap()
            .seq,
        third.seq
    );
    running.stop();
}

/// Round 10, L1: what `menzil relay run` does at a stop writes the Roster adopted last, even
/// when the relay lock was busy (an `add-network` in progress) when it was adopted.
#[tokio::test]
async fn a_clean_stop_flushes_the_roster_adopted_last() {
    let (_o, owner, id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let mut running = start(&relay_home, &run_options(dir.path())).await.unwrap();
    let renewed = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    let busy = relay_home.lock_relay().unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 60)
            .unwrap()
    );
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(busy);
    });
    // The signal is already here.
    assert_eq!(run_until(&mut running, async { 7 }).await.unwrap(), Some(7));
    assert_eq!(
        load_rosters(&relay_home).unwrap()[0]
            .roster
            .decode()
            .unwrap()
            .seq,
        renewed.seq,
        "the stop returned before the Roster was on disk"
    );
    assert_eq!(running.roster_seq(&id), Some(renewed.seq));
}

/// Shared setup for the `run_until` task-end tests: a relay that has adopted a newer Roster over
/// DOC while the relay lock was busy, so that only a flush at the stop gets it onto the disk.
/// Returns the pieces and the sequence number the disk must show afterwards.
async fn relay_with_a_roster_waiting_for_the_flush() -> (tempfile::TempDir, Home, RunningRelay, u64)
{
    let (_o, owner, _id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let running = start(&relay_home, &run_options(dir.path())).await.unwrap();
    let renewed = crate::local::renew(&owner, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    let busy = relay_home.lock_relay().unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 60)
            .unwrap()
    );
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(busy);
    });
    (dir, relay_home, running, renewed.seq)
}

/// A relay task that panics is not a stop: `run_until` is an error naming the panic (so that
/// `menzil relay run` exits non-zero), and it still flushes the Roster adopted last first.
#[tokio::test]
async fn a_panicking_relay_task_is_an_error_and_still_flushes() {
    let (_dir, relay_home, mut running, seq) = relay_with_a_roster_waiting_for_the_flush().await;
    running.task.abort();
    running.task = tokio::spawn(async { panic!("relay boom") });
    let error = run_until(&mut running, std::future::pending::<u8>())
        .await
        .unwrap_err();
    let text = format!("{error:#}");
    assert!(text.contains("relay task panicked"), "{text}");
    assert!(text.contains("relay boom"), "{text}");
    assert_eq!(
        load_rosters(&relay_home).unwrap()[0]
            .roster
            .decode()
            .unwrap()
            .seq,
        seq,
        "the error path returned before the Roster was on disk"
    );
}

/// A relay task that returns by itself (or is aborted) is not a stop either.
#[tokio::test]
async fn a_relay_task_that_ends_by_itself_is_an_error() {
    let (_dir, _relay_home, mut running, _seq) = relay_with_a_roster_waiting_for_the_flush().await;
    running.task.abort();
    running.task = tokio::spawn(async {});
    let error = run_until(&mut running, std::future::pending::<u8>())
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("relay task ended unexpectedly"),
        "{error:#}"
    );
    running.task = tokio::spawn(std::future::pending::<()>());
    running.task.abort();
    let error = run_until(&mut running, std::future::pending::<u8>())
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("relay task ended unexpectedly"),
        "{error:#}"
    );
}

/// The stop firing while the relay task lives is `Ok(Some(what the stop gave))`, and the flush
/// has happened.
#[tokio::test]
async fn a_stop_with_a_live_relay_task_is_ok_some_and_flushes() {
    let (_dir, relay_home, mut running, seq) = relay_with_a_roster_waiting_for_the_flush().await;
    let out = run_until(&mut running, async {
        tokio::time::sleep(Duration::from_millis(20)).await;
        "signal"
    })
    .await
    .unwrap();
    assert_eq!(out, Some("signal"));
    assert_eq!(
        load_rosters(&relay_home).unwrap()[0]
            .roster
            .decode()
            .unwrap()
            .seq,
        seq
    );
}

// ---- MT6: tenants (multi tenant design 2.1) ----

use super::tenants::{
    add_network_to, load_book, read_specs, remove_network, remove_tenant, render_tenants,
    tenants_dir,
};
use menzil_relay::TenantId;

/// A relay machine's home, initialised.
fn relay_machine() -> (tempfile::TempDir, Home) {
    let (dir, relay) = home();
    init(&relay, clock()).unwrap();
    (dir, relay)
}

/// A new network with its own owner: the owner's home (to renew from), the network and a relay
/// token.
fn another_network() -> (tempfile::TempDir, Home, NetworkId, String) {
    let (dir, owner, id, _) = token_of_a_network();
    let token = relay_token(&owner);
    (dir, owner, id, token)
}

fn tenant_file(relay: &Home, slug: &str) -> PathBuf {
    tenants_dir(relay).join(format!("{slug}.toml"))
}

fn read_tenant_file(relay: &Home, slug: &str) -> String {
    fs::read_to_string(tenant_file(relay, slug)).unwrap()
}

/// A relay running on `relay`'s directory, with the reload driven by hand (`reload_once`).
async fn running_on(dir: &Path, relay: &Home) -> RunningRelay {
    start(relay, &run_options(dir)).await.unwrap()
}

#[test]
fn a_directory_without_tenant_files_is_one_default_tenant_with_flat_names() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_d, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    add_network(&relay, &token_b, clock()).unwrap();
    assert!(
        !tenants_dir(&relay).exists(),
        "an add without a tenant makes no tenant file"
    );
    let (specs, refused) = read_specs(&relay).unwrap();
    assert!(specs.is_empty() && refused.is_empty());

    let rosters = load_rosters(&relay).unwrap();
    let book = load_book(&relay, &rosters).unwrap();
    assert_eq!(book.named_count(), 0);
    assert_eq!(book.tenants().count(), 1);
    for id in [id_a, id_b] {
        assert_eq!(book.id_of(&id), &TenantId::Default);
        assert!(!book.is_held_back(&id));
    }
    assert_eq!(book.default_tenant().class, menzil_relay::Class::Personal);
    assert_eq!(book.default_tenant().figures, None);

    let listing = render_tenants(&relay, clock()).unwrap();
    assert!(
        listing.contains("tenant (default)  class personal  networks 2"),
        "{listing}"
    );
    assert_eq!(listing.matches("tenant ").count(), 1, "{listing}");
    assert!(listing.contains(&format!("network {id_a}  Roster #1")));
}

#[tokio::test]
async fn a_relay_without_tenant_files_starts_with_the_default_tenant_only() {
    let (_a, _oa, id, token) = another_network();
    let (dir, relay) = relay_machine();
    add_network(&relay, &token, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    assert_eq!(running.networks, vec![id]);
    assert_eq!(running.tenants().named_count(), 0);
    assert_eq!(running.tenants().id_of(&id), &TenantId::Default);
    running.stop();
}

#[test]
fn add_network_with_a_tenant_writes_its_file_and_the_book_follows() {
    let (_a, owner_a, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_c, _oc, id_c, token_c) = another_network();
    let (_d, relay) = relay_machine();

    let added = add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    assert_eq!(
        (added.network_id, added.seq, added.tenant.as_deref()),
        (id_a, 1, Some("ali"))
    );
    assert!(
        added.warnings.is_empty(),
        "the first tenant of an empty relay needs no warning"
    );
    let text = read_tenant_file(&relay, "ali");
    assert!(text.contains(&id_a.to_hex()) && text.contains("class = \"friend\""));
    assert_eq!(
        add_network_to(&relay, &token_b, clock(), Some("ali"))
            .unwrap()
            .seq,
        1
    );
    // The default tenant's network stays outside.
    let default = add_network_to(&relay, &token_c, clock(), None).unwrap();
    assert_eq!(default.tenant, None);
    let two_networks = read_tenant_file(&relay, "ali");

    let rosters = load_rosters(&relay).unwrap();
    let book = load_book(&relay, &rosters).unwrap();
    assert_eq!(book.id_of(&id_a).slug(), Some("ali"));
    assert_eq!(book.id_of(&id_b).slug(), Some("ali"));
    assert_eq!(book.id_of(&id_c), &TenantId::Default);
    assert_eq!(
        book.named("ali").unwrap().figures,
        Some(menzil_relay::Figures::friend())
    );

    // A newer token without --tenant renews the Roster and leaves the network where it is.
    crate::local::renew(&owner_a, None, clock() + DAY).unwrap();
    let renewed = add_network_to(&relay, &relay_token(&owner_a), clock() + DAY, None).unwrap();
    assert_eq!((renewed.seq, renewed.tenant.as_deref()), (2, Some("ali")));
    assert_eq!(
        read_tenant_file(&relay, "ali"),
        two_networks,
        "a renewal rewrites no tenant file"
    );

    // It cannot be moved by naming another tenant.
    let error = add_network_to(&relay, &relay_token(&owner_a), clock() + DAY, Some("veli"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("already in tenant ali"), "{error}");
    assert!(!tenant_file(&relay, "veli").exists());

    let listing = render_tenants(&relay, clock()).unwrap();
    assert!(
        listing.contains("tenant ali  class friend  networks 2/3"),
        "{listing}"
    );
    assert!(
        listing.contains("tenant (default)  class personal  networks 1"),
        "{listing}"
    );
}

#[test]
fn the_second_tenant_is_warned_about_once() {
    let (_a, _oa, _ia, token_a) = another_network();
    let (_b, _ob, _ib, token_b) = another_network();
    let (_c, _oc, _ic, token_c) = another_network();
    let (_d, relay) = relay_machine();
    // A default tenant network plus a first tenant: two tenants.
    add_network(&relay, &token_a, clock()).unwrap();
    let first = add_network_to(&relay, &token_b, clock(), Some("ali")).unwrap();
    assert_eq!(first.warnings.len(), 1, "{:?}", first.warnings);
    assert!(first.warnings[0].contains("Public Suffix List"));
    // The same tenant again: nothing new to say.
    let again = add_network_to(&relay, &token_c, clock(), Some("ali")).unwrap();
    assert!(again.warnings.is_empty());
}

#[test]
fn a_fourth_network_for_a_friend_is_refused_and_nothing_is_written() {
    let nets: Vec<_> = (0..4).map(|_| another_network()).collect();
    let (_d, relay) = relay_machine();
    for (_, _, _, token) in &nets[..3] {
        add_network_to(&relay, token, clock(), Some("ali")).unwrap();
    }
    let before = read_tenant_file(&relay, "ali");
    let (_, _, id4, token4) = &nets[3];
    let error = add_network_to(&relay, token4, clock(), Some("ali"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("may have 3 network"), "{error}");
    assert_eq!(read_tenant_file(&relay, "ali"), before);
    assert!(
        !roster_path(&relay, id4).exists(),
        "the Roster was not kept either"
    );

    // The operator raises the figure in the file; then it fits.
    fs::write(
        tenant_file(&relay, "ali"),
        format!("{before}max_networks = 4\n"),
    )
    .unwrap();
    add_network_to(&relay, token4, clock(), Some("ali")).unwrap();
    assert!(roster_path(&relay, id4).exists());
}

#[test]
fn bad_tenant_names_are_refused_before_anything_is_written() {
    let (_a, _oa, id, token) = another_network();
    let (_d, relay) = relay_machine();
    for bad in [
        "Ab",
        "ab",
        "www",
        "a_b",
        "-abc",
        "abc-",
        "a.b",
        &"x".repeat(33),
        "t",
    ] {
        let error = add_network_to(&relay, &token, clock(), Some(bad)).unwrap_err();
        assert!(!format!("{error:#}").is_empty());
        assert!(!tenants_dir(&relay).exists(), "{bad}");
        assert!(!roster_path(&relay, &id).exists(), "{bad}");
    }
}

#[test]
fn a_token_the_relay_refuses_leaves_no_tenant_behind() {
    let (_a, _oa, _ia, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_d, relay) = relay_machine();
    // A new tenant whose first token is refused (expired at that time): no tenant file.
    let way_later = clock() + 400 * DAY;
    assert!(add_network_to(&relay, &token_b, way_later, Some("veli")).is_err());
    assert!(!tenant_file(&relay, "veli").exists());
    // An existing tenant whose second network is refused: the file is as it was.
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    let before = read_tenant_file(&relay, "ali");
    assert!(add_network_to(&relay, &token_b, way_later, Some("ali")).is_err());
    assert_eq!(read_tenant_file(&relay, "ali"), before);
    assert!(!before.contains(&id_b.to_hex()));
}

#[test]
fn an_extra_name_two_tenants_share_refuses_the_newer_file_and_holds_its_networks_back() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_c, _oc, id_c, token_c) = another_network();
    let (_d, relay) = relay_machine();
    for token in [&token_a, &token_b, &token_c] {
        add_network(&relay, token, clock()).unwrap();
    }
    fs::create_dir_all(tenants_dir(&relay)).unwrap();
    let file = |network: NetworkId, added: u64| {
        format!(
            "networks = [\"{}\"]\nextra_names = [\"blog\"]\nadded = {added}\n",
            network.to_hex()
        )
    };
    fs::write(tenant_file(&relay, "ali"), file(id_a, 10)).unwrap();
    fs::write(tenant_file(&relay, "veli"), file(id_b, 20)).unwrap();

    let rosters = load_rosters(&relay).unwrap();
    let book = load_book(&relay, &rosters).unwrap();
    assert!(book.named("ali").is_some());
    assert!(book.named("veli").is_none(), "the newer file is refused");
    assert!(book.is_held_back(&id_b));
    assert_eq!(book.id_of(&id_a).slug(), Some("ali"));
    assert_eq!(book.id_of(&id_c), &TenantId::Default);

    let listing = render_tenants(&relay, clock()).unwrap();
    assert!(listing.contains("not used: veli.toml"), "{listing}");
    assert!(listing.contains("blog"), "{listing}");
}

#[tokio::test]
async fn a_network_in_a_refused_tenant_file_is_not_served_and_serves_again_once_fixed() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (dir, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    add_network(&relay, &token_b, clock()).unwrap();
    // A typo in the class: the file is wrong, its network must not fall to the default tenant.
    fs::create_dir_all(tenants_dir(&relay)).unwrap();
    let wrong = format!("networks = [\"{}\"]\nclass = \"gold\"\n", id_b.to_hex());
    fs::write(tenant_file(&relay, "veli"), &wrong).unwrap();

    let running = running_on(dir.path(), &relay).await;
    assert_eq!(running.networks, vec![id_a], "{:?}", running.networks);
    assert_eq!(running.roster_seq(&id_b), None);
    assert!(running.tenants().is_held_back(&id_b));

    // Fixed: the next reload serves it, in its tenant.
    fs::write(
        tenant_file(&relay, "veli"),
        format!("networks = [\"{}\"]\n", id_b.to_hex()),
    )
    .unwrap();
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_b), Some(1));
    assert_eq!(running.tenants().id_of(&id_b).slug(), Some("veli"));

    // Broken again: the network goes out of service at the next reload.
    fs::write(tenant_file(&relay, "veli"), &wrong).unwrap();
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_b), None);
    assert_eq!(running.roster_seq(&id_a), Some(1));
    running.stop();
}

#[tokio::test]
async fn tenant_files_that_are_not_toml_stop_a_start_and_a_reload_keeps_the_tenants_it_had() {
    let (_a, _oa, id, token) = another_network();
    let (dir, relay) = relay_machine();
    add_network_to(&relay, &token, clock(), Some("ali")).unwrap();
    let good = read_tenant_file(&relay, "ali");

    fs::write(tenant_file(&relay, "ali"), "networks = [[[ nonsense").unwrap();
    let error = start(&relay, &run_options(dir.path())).await.err().unwrap();
    assert!(format!("{error:#}").contains("ali.toml"), "{error:#}");

    fs::write(tenant_file(&relay, "ali"), &good).unwrap();
    let running = running_on(dir.path(), &relay).await;
    assert_eq!(running.tenants().id_of(&id).slug(), Some("ali"));
    fs::write(tenant_file(&relay, "ali"), "networks = [[[ nonsense").unwrap();
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(
        running.tenants().id_of(&id).slug(),
        Some("ali"),
        "the reload keeps the tenants it had"
    );
    assert_eq!(running.roster_seq(&id), Some(1), "and keeps serving");
    running.stop();
}

#[test]
fn remove_network_deletes_the_roster_and_the_listing_and_nothing_else() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_c, _oc, id_c, token_c) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    add_network_to(&relay, &token_b, clock(), Some("ali")).unwrap();
    add_network(&relay, &token_c, clock()).unwrap();

    let removed = remove_network(&relay, &id_a.to_hex().to_uppercase()).unwrap();
    assert_eq!(
        (removed.network_id, removed.tenant.as_deref()),
        (id_a, Some("ali"))
    );
    assert!(!roster_path(&relay, &id_a).exists());
    assert!(roster_path(&relay, &id_b).exists() && roster_path(&relay, &id_c).exists());
    let text = read_tenant_file(&relay, "ali");
    assert!(!text.contains(&id_a.to_hex()) && text.contains(&id_b.to_hex()));

    // The default tenant's network has no listing to edit.
    let removed = remove_network(&relay, &id_c.to_hex()).unwrap();
    assert_eq!(removed.tenant, None);
    assert!(!roster_path(&relay, &id_c).exists());

    // Not served, not a network id, nothing there at all.
    assert!(remove_network(&relay, &id_a.to_hex()).is_err());
    assert!(remove_network(&relay, "nonsense").is_err());
    let (_e, empty) = home();
    assert!(remove_network(&empty, &id_a.to_hex()).is_err());

    // The last network of a tenant leaves the tenant in place, empty.
    remove_network(&relay, &id_b.to_hex()).unwrap();
    assert!(tenant_file(&relay, "ali").exists());
    let listing = render_tenants(&relay, clock()).unwrap();
    assert!(
        listing.contains("tenant ali  class friend  networks 0/3"),
        "{listing}"
    );
}

#[tokio::test]
async fn a_running_relay_drops_a_removed_network_and_the_keeper_does_not_write_it_back() {
    let (_a, owner_a, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (dir, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    add_network(&relay, &token_b, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    assert_eq!(running.roster_seq(&id_a), Some(1));
    let mut notices = running.relay.rosters().subscribe();

    remove_network(&relay, &id_a.to_hex()).unwrap();
    // Until the reload the relay holds it (the CLI is another process).
    assert_eq!(running.roster_seq(&id_a), Some(1));
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_a), None, "dropped at the reload");
    assert_eq!(
        running.roster_seq(&id_b),
        Some(1),
        "the other network stays"
    );
    // The sessions of the network hear of it as they hear of a new Roster (they end `not_member`).
    assert_eq!(notices.try_recv().unwrap(), id_a);

    // A Roster for the removed network that was already on its way (a member's push that won
    // the race with the reload) is held for a moment, never written to disk, and the next reload
    // drops it again.
    let renewed = crate::local::renew(&owner_a, None, clock() + 60).unwrap();
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    assert!(
        running
            .relay
            .rosters()
            .adopt(pair.roster(), None, clock() + 60)
            .unwrap()
    );
    assert!(running.flush_rosters(FLUSH));
    assert!(
        !roster_path(&relay, &id_a).exists(),
        "the keeper must not make the file"
    );
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_a), None);
    assert!(!roster_path(&relay, &id_a).exists());
    running.stop();
    assert_eq!(
        load_rosters(&relay).unwrap().len(),
        1,
        "a restart serves the other only"
    );
}

#[tokio::test]
async fn a_relay_whose_directory_cannot_be_seen_keeps_serving_its_networks() {
    let (_a, _oa, id, token) = another_network();
    let (dir, relay) = relay_machine();
    add_network(&relay, &token, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    fs::remove_dir_all(relay_dir(&relay)).unwrap();
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(
        running.roster_seq(&id),
        Some(1),
        "a directory that is not there is no removal order"
    );
    running.stop();
}

#[tokio::test]
async fn a_damaged_roster_file_is_not_a_removal() {
    let (_a, _oa, id, token) = another_network();
    let (dir, relay) = relay_machine();
    add_network(&relay, &token, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    fs::write(roster_path(&relay, &id), b"damaged").unwrap();
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id), Some(1));
    running.stop();
}

#[tokio::test]
async fn remove_tenant_removes_its_networks_and_keeps_its_name_back() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_c, _oc, id_c, token_c) = another_network();
    let (dir, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    add_network_to(&relay, &token_b, clock(), Some("ali")).unwrap();
    add_network(&relay, &token_c, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;

    let mut removed = remove_tenant(&relay, "ali", clock()).unwrap();
    removed.sort_by_key(NetworkId::to_hex);
    let mut expected = vec![id_a, id_b];
    expected.sort_by_key(NetworkId::to_hex);
    assert_eq!(removed, expected);
    assert!(!tenant_file(&relay, "ali").exists());
    assert!(!roster_path(&relay, &id_a).exists() && !roster_path(&relay, &id_b).exists());
    assert!(
        roster_path(&relay, &id_c).exists(),
        "the default tenant is untouched"
    );

    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_a), None);
    assert_eq!(running.roster_seq(&id_b), None);
    assert_eq!(running.roster_seq(&id_c), Some(1));
    running.stop();

    // The name is not given to anyone for 180 days.
    let (_e, _oe, _ie, token_e) = another_network();
    let error = add_network_to(&relay, &token_e, clock() + DAY, Some("ali"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("removed"), "{error}");
    assert!(!tenant_file(&relay, "ali").exists());
    let listing = render_tenants(&relay, clock() + DAY).unwrap();
    assert!(listing.contains("quarantine: ali"), "{listing}");
    let later = render_tenants(&relay, clock() + 181 * DAY).unwrap();
    assert!(!later.contains("quarantine"), "{later}");
    let still = render_tenants(&relay, clock() + 179 * DAY).unwrap();
    assert!(still.contains("quarantine: ali"), "{still}");

    // No such tenant, a name that is not a tenant name.
    assert!(remove_tenant(&relay, "ali", clock()).is_err());
    assert!(remove_tenant(&relay, "nobody", clock()).is_err());
    assert!(remove_tenant(&relay, "Not A Name", clock()).is_err());
}

// --- Round T4 -------------------------------------------------------------------------------

/// L1: a tenant file whose `networks` cannot be read at all must never send its networks to the
/// default tenant: every way to read the book fails, `remove-tenant` refuses and keeps the file
/// and the Rosters (the file stays quarantined by the error until the operator repairs it).
#[test]
fn a_tenant_file_whose_networks_cannot_be_read_is_an_error_not_the_default_tenant() {
    let (_a, _oa, id, token) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token, clock(), Some("ali")).unwrap();
    let rosters = load_rosters(&relay).unwrap();
    let ali = TenantId::Named(menzil_relay::Slug::parse("ali").unwrap());
    assert_eq!(load_book(&relay, &rosters).unwrap().id_of(&id), &ali);

    // A hand edit: the id written as a string instead of a list; a list with an entry that is
    // not an id; a list nested in a table; text that is not TOML.
    for broken in [
        format!("networks = \"{}\"\nclass = \"friend\"\n", id.to_hex()),
        format!("networks = [\"{}\", 7]\n", id.to_hex()),
        format!("networks = [\"{}x\"]\n", id.to_hex()),
        "networks = [\n".to_string(),
    ] {
        fs::write(tenant_file(&relay, "ali"), &broken).unwrap();
        assert!(
            load_book(&relay, &rosters).is_err(),
            "the book is not built from {broken:?}"
        );
        assert!(read_specs(&relay).is_err());
        assert!(render_tenants(&relay, clock()).is_err());
        // remove-tenant refuses and deletes nothing.
        let error = remove_tenant(&relay, "ali", clock()).unwrap_err();
        assert!(format!("{error:#}").contains("not removed"), "{error:#}");
        assert!(tenant_file(&relay, "ali").exists());
        assert!(roster_path(&relay, &id).exists());
        assert!(
            !tenants_dir(&relay).join(".quarantine").exists(),
            "a refused removal quarantines nothing"
        );
    }

    // A file that is fine apart from another field is still held back with its networks.
    fs::write(
        tenant_file(&relay, "ali"),
        format!("networks = [\"{}\"]\nclass = \"nonsense\"\n", id.to_hex()),
    )
    .unwrap();
    let book = load_book(&relay, &rosters).unwrap();
    assert!(book.is_held_back(&id));
    assert_eq!(book.refused()[0].networks, vec![id]);

    // Repaired, the file is removed as usual.
    fs::write(
        tenant_file(&relay, "ali"),
        format!("networks = [\"{}\"]\n", id.to_hex()),
    )
    .unwrap();
    assert_eq!(remove_tenant(&relay, "ali", clock()).unwrap(), vec![id]);
    assert!(!tenant_file(&relay, "ali").exists() && !roster_path(&relay, &id).exists());
}

/// N5 (design 2.2, rule 1): a hand written file whose slug is in quarantine is refused by the
/// book the relay loads, and its networks are held back.
#[test]
fn a_hand_written_file_with_a_quarantined_slug_is_refused_by_the_relays_book() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    remove_tenant(&relay, "ali", clock()).unwrap();
    // The operator keeps a second network, then writes a file bringing the name back by hand.
    add_network_to(&relay, &token_b, clock(), Some("veli")).unwrap();
    fs::write(
        tenant_file(&relay, "ali"),
        format!("networks = [\"{}\"]\n", id_b.to_hex()),
    )
    .unwrap();
    let rosters = load_rosters(&relay).unwrap();
    let book = load_book(&relay, &rosters).unwrap();
    assert!(book.named("ali").is_none());
    assert!(book.is_held_back(&id_b), "the listed network is not served");
    let refusal = book.refused().iter().find(|r| r.name == "ali").unwrap();
    assert!(refusal.reason.contains("quarantine"), "{}", refusal.reason);
    assert!(!roster_path(&relay, &id_a).exists());
}

// ---- MT9: names per tenant, the durable name state ----

use menzil_proto::NodeId;

/// A network (hand made: the CLI has no command that grants labels) whose Roster grants
/// `labels` (name, node) to the nodes it lists; its relay token.
fn labeled_network(labels: &[(&str, u8)]) -> (NetworkId, String) {
    let owner = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let mut members: Vec<NodeId> = labels.iter().map(|&(_, n)| NodeId::from([n; 32])).collect();
    members.dedup();
    let body = menzil_proto::RosterBody {
        v: menzil_proto::PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: clock(),
        expires: clock() + 10 * DAY,
        members: members
            .iter()
            .map(|&node_id| menzil_proto::RosterMember {
                node_id,
                min_serial: 1,
            })
            .collect(),
        revoked: vec![],
        stewards: vec![],
        labels: labels
            .iter()
            .map(|&(name, n)| menzil_proto::Label {
                name: name.to_string(),
                node_id: NodeId::from([n; 32]),
            })
            .collect(),
    };
    let roster = Roster::sign(&owner, &body).unwrap();
    (network_id, crate::token::encode_roster(&roster, None))
}

fn advertise_now(
    running: &RunningRelay,
    network: &NetworkId,
    node: u8,
    names: &[&str],
    now: u64,
) -> menzil_proto::AdvertiseAckBody {
    let body = menzil_proto::AdvertiseBody {
        v: menzil_proto::PROTOCOL_VERSION,
        shares: names
            .iter()
            .map(|name| menzil_proto::Share {
                name: name.to_string(),
                mode: menzil_proto::ShareMode::Blind,
                service: "tcp:ssh".parse().unwrap(),
                alpn: vec![],
            })
            .collect(),
        accept_peers: true,
    };
    running.relay.labels().advertise(
        running.relay.rosters(),
        &running.relay.tenants(),
        &[*network],
        &NodeId::from([node; 32]),
        &body,
        now,
    )
}

fn names_file(relay: &Home) -> String {
    fs::read_to_string(names_state::state_path(relay)).unwrap()
}

/// A name accepted is on disk once the keeper is done; a release and its quarantine are too; and
/// after a restart the quarantine still holds: another network cannot take the released flat
/// name, the one that held it can (design 2.2, rules 8 and 9).
#[tokio::test]
async fn the_quarantine_of_a_released_name_survives_a_restart() {
    let (net_a, token_a) = labeled_network(&[("app", 1)]);
    let (net_b, token_b) = labeled_network(&[("app", 2)]);
    let (dir, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    add_network(&relay, &token_b, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    assert!(
        !names_state::state_path(&relay).exists(),
        "nothing kept before a name exists"
    );

    let t0 = clock();
    let ack = advertise_now(&running, &net_a, 1, &["app"], t0);
    assert_eq!(ack.names, vec!["app"]);
    assert!(running.flush_rosters(FLUSH));
    let text = names_file(&relay);
    assert!(text.starts_with("menzil-names-state 1\n"), "{text}");
    assert!(
        text.contains(&format!("name app - {} {t0} {t0}", net_a.to_hex())),
        "{text}"
    );

    // The holder leaves; 90 days later the periodic pass releases the name into quarantine.
    running
        .relay
        .labels()
        .clear_for(&NodeId::from([1u8; 32]), t0);
    running.relay.labels().sweep(
        running.relay.rosters(),
        &running.relay.tenants(),
        t0 + 90 * DAY,
    );
    assert!(running.flush_rosters(FLUSH));
    let text = names_file(&relay);
    assert!(!text.contains("\nname app"), "{text}");
    assert!(
        text.contains(&format!(
            "quarantine flat app {} - {}",
            t0 + 90 * DAY,
            net_a.to_hex()
        )),
        "{text}"
    );
    running.stop();

    // Restart: the file is the relay's memory.
    let restarted = running_on(dir.path(), &relay).await;
    let later = t0 + 100 * DAY;
    let theirs = advertise_now(&restarted, &net_b, 2, &["app"], later);
    assert!(theirs.names.is_empty());
    assert_eq!(theirs.rejected[0].reason, "quarantined");
    let hers = advertise_now(&restarted, &net_a, 1, &["app"], later);
    assert_eq!(hers.names, vec!["app"]);
    restarted.stop();
}

/// Rule 4: a flat name the default tenant was accepted for (here: its network was removed since,
/// so only the name state remembers it, in quarantine) cannot be a tenant's name.
#[tokio::test]
async fn a_name_the_default_tenant_was_accepted_for_cannot_become_a_tenant_name() {
    let (net_a, token_a) = labeled_network(&[("shop", 1)]);
    let (_c, _oc, _id_c, token_c) = another_network();
    let (_b, _ob, _id_b, token_b) = another_network();
    let (dir, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    add_network(&relay, &token_c, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    advertise_now(&running, &net_a, 1, &["shop"], clock());
    // The removal ends the session that held the name.
    running
        .relay
        .labels()
        .clear_for(&NodeId::from([1u8; 32]), clock());
    remove_network(&relay, &net_a.to_hex()).unwrap();
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert!(running.flush_rosters(FLUSH));
    running.stop();
    assert!(names_file(&relay).contains("quarantine flat shop "));
    // No Roster grants `shop` any more: only the name state keeps it from becoming a tenant.
    let error = add_network_to(&relay, &token_b, clock(), Some("shop"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("flat name"), "{error}");
    assert!(!tenant_file(&relay, "shop").exists());
    // And a hand written file is refused by the book the relay loads.
    fs::create_dir_all(tenants_dir(&relay)).unwrap();
    fs::write(tenant_file(&relay, "shop"), "networks = []\n").unwrap();
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    assert!(book.named("shop").is_none());
    assert_eq!(book.refused().len(), 1);
}

/// A damaged name state stops a start with an error that names the file and the line, and is
/// never written over by the keeper or used by a command.
#[tokio::test]
async fn a_damaged_name_state_fails_closed_with_a_clear_error() {
    let (_a, _oa, _id, token) = another_network();
    let (dir, relay) = relay_machine();
    add_network(&relay, &token, clock()).unwrap();
    let path = names_state::state_path(&relay);
    for bad in [
        "garbage\n".to_string(),
        String::new(),
        "menzil-names-state 1\nname app - nothex 1 2\n".to_string(),
    ] {
        fs::write(&path, &bad).unwrap();
        let error = match start(&relay, &run_options(dir.path())).await {
            Ok(_) => panic!("a relay started with a damaged name state: {bad:?}"),
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.contains("names.state") && error.contains("damaged"),
            "{error}"
        );
        assert!(error.contains("line"), "{error}");
        // Nothing wrote over it, and the commands that read it say so.
        let snapshot = menzil_relay::NameState::default();
        assert!(names_state::write_relay_part(&relay, &snapshot).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), bad);
        assert!(render_tenants(&relay, clock()).is_err());
        assert!(add_network_to(&relay, &token, clock(), Some("ali")).is_err());
        assert!(remove_tenant(&relay, "ali", clock()).is_err());
    }
    fs::remove_file(&path).unwrap();
    start(&relay, &run_options(dir.path()))
        .await
        .unwrap()
        .stop();
}

/// The state file is replaced atomically: while writers rewrite it as fast as they can, a reader
/// never finds a torn file, and no temporary file is left behind.
#[test]
fn the_name_state_is_written_atomically() {
    let (_d, relay) = relay_machine();
    fs::create_dir_all(relay_dir(&relay)).unwrap();
    let mut state = menzil_relay::NameState::default();
    for i in 0..200 {
        state.names.insert(
            format!("name{i}"),
            menzil_relay::NameRecord {
                tenant: None,
                network: NetworkId::from([1u8; 32]),
                first: 1,
                last: 2,
            },
        );
    }
    names_state::write_relay_part(&relay, &state).unwrap();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let torn = std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            let mut torn = 0;
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                match fs::read_to_string(names_state::state_path(&relay)) {
                    Ok(text) => {
                        if menzil_relay::NameState::parse(&text).is_err() {
                            torn += 1;
                        }
                    }
                    Err(_) => torn += 1,
                }
            }
            torn
        });
        for round in 0..150 {
            state.names.get_mut("name0").unwrap().last = 3 + round;
            names_state::write_relay_part(&relay, &state).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        reader.join().unwrap()
    });
    assert_eq!(torn, 0, "a reader saw a torn or missing name state");
    let leftovers: Vec<_> = fs::read_dir(relay_dir(&relay))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// The first slice's `.quarantine` file is read as slug entries and moved into `names.state` the
/// first time the relay starts; `remove-tenant` writes the slug there; and the running relay,
/// writing its own part, keeps the operator's slug entries.
#[tokio::test]
async fn the_legacy_quarantine_moves_into_the_name_state_and_the_relay_keeps_the_slugs() {
    let (net_a, token_a) = labeled_network(&[("app", 1)]);
    let (_b, _ob, _id_b, token_b) = another_network();
    let (dir, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    // A slug the first slice left behind.
    fs::create_dir_all(tenants_dir(&relay)).unwrap();
    let legacy = tenants_dir(&relay).join(".quarantine");
    fs::write(&legacy, format!("oldone {}\n", clock())).unwrap();
    // Read in place before the migration...
    let error = add_network_to(&relay, &token_b, clock() + DAY, Some("oldone"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("removed"), "{error}");

    let running = running_on(dir.path(), &relay).await;
    assert!(!legacy.exists(), "moved, not copied");
    assert!(names_file(&relay).contains(&format!("quarantine slug oldone {} - -", clock())));
    // ...and after it.
    assert!(add_network_to(&relay, &token_b, clock() + DAY, Some("oldone")).is_err());

    // A removal while the relay runs, then the relay writes its own part: both slugs stay.
    add_network_to(&relay, &token_b, clock(), Some("ali")).unwrap();
    remove_tenant(&relay, "ali", clock() + 5).unwrap();
    assert!(!legacy.exists());
    advertise_now(&running, &net_a, 1, &["app"], clock());
    assert!(running.flush_rosters(FLUSH));
    let text = names_file(&relay);
    assert!(text.contains("quarantine slug oldone"), "{text}");
    assert!(text.contains("quarantine slug ali"), "{text}");
    assert!(text.contains("name app - "), "{text}");
    let listing = render_tenants(&relay, clock() + DAY).unwrap();
    assert!(
        listing.contains("quarantine: ali") && listing.contains("quarantine: oldone"),
        "{listing}"
    );
    running.stop();
}

/// An operator removing a network: the running relay releases its names at the next reload, a
/// flat one into quarantine bound to that network.
#[tokio::test]
async fn removing_a_network_releases_its_names_at_the_next_reload() {
    let (net_a, token_a) = labeled_network(&[("app", 1)]);
    let (_b, token_b) = labeled_network(&[("other", 2)]);
    let (dir, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    add_network(&relay, &token_b, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    advertise_now(&running, &net_a, 1, &["app"], clock());
    remove_network(&relay, &net_a.to_hex()).unwrap();
    reload_once(&running.relay, &relay, &mut Vec::new());
    // A session still holds the name when the network goes (it ends a moment later): the
    // reload leaves it, as the sweep leaves a held name (round T5, L4)...
    assert!(running.flush_rosters(FLUSH));
    assert!(names_file(&relay).contains("\nname app "));
    // ...and releases it at the pass after the session has gone.
    running
        .relay
        .labels()
        .clear_for(&NodeId::from([1u8; 32]), clock());
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert!(running.flush_rosters(FLUSH));
    let text = names_file(&relay);
    assert!(!text.contains("\nname app"), "{text}");
    assert!(text.contains("quarantine flat app"), "{text}");
    running.stop();
}

/// The reload runs the periodic pass: a name nobody has advertised for 90 days is released at
/// the next reload, a flat one into quarantine (the real clock decides here).
#[tokio::test]
async fn the_reload_releases_a_name_unadvertised_for_ninety_days() {
    let (net_a, token_a) = labeled_network(&[("old", 1), ("fresh", 1)]);
    let (dir, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    // `old` last advertised 100 days ago, `fresh` 50 days ago (nothing advertises since, so the
    // release can only come from the reload's pass).
    let long_ago = clock() - 100 * DAY;
    let node = NodeId::from([1u8; 32]);
    advertise_now(&running, &net_a, 1, &["old"], long_ago);
    running.relay.labels().clear_for(&node, long_ago);
    advertise_now(&running, &net_a, 1, &["fresh"], long_ago + 50 * DAY);
    running.relay.labels().clear_for(&node, long_ago + 50 * DAY);
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert!(running.flush_rosters(FLUSH));
    let text = names_file(&relay);
    assert!(!text.contains("\nname old "), "{text}");
    assert!(text.contains("quarantine flat old "), "{text}");
    assert!(text.contains("\nname fresh "), "{text}");
    running.stop();
}

// ---- round T5 ----

/// A signed Roster of a network `owner` controls, with `labels` (name, node) and a `seq`.
fn owned_roster(
    owner: &ed25519_dalek::SigningKey,
    seq: u64,
    labels: &[(&str, u8)],
) -> menzil_proto::Roster {
    let members: Vec<NodeId> = (1..=9u8).map(|n| NodeId::from([n; 32])).collect();
    let body = menzil_proto::RosterBody {
        v: menzil_proto::PROTOCOL_VERSION,
        network_id: NetworkId::from(owner.verifying_key().to_bytes()),
        seq,
        issued: clock() - 60,
        expires: clock() + 10 * DAY,
        members: members
            .iter()
            .map(|&node_id| menzil_proto::RosterMember {
                node_id,
                min_serial: 1,
            })
            .collect(),
        revoked: vec![],
        stewards: vec![],
        labels: labels
            .iter()
            .map(|&(name, n)| menzil_proto::Label {
                name: name.to_string(),
                node_id: NodeId::from([n; 32]),
            })
            .collect(),
    };
    Roster::sign(owner, &body).unwrap()
}

/// Round T5, M1: an owner of a default tenant network who lists a label equal to an older
/// tenant's slug in its Roster does not take that tenant offline; advertising the label stays
/// refused.
#[tokio::test]
async fn t5_a_default_roster_label_equal_to_a_slug_does_not_take_the_tenant_down() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (dir, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    let owner = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let id_d = NetworkId::from(owner.verifying_key().to_bytes());
    let first = owned_roster(&owner, 1, &[]);
    add_network(&relay, &encode_roster(&first, None), clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    assert_eq!(running.tenants().id_of(&id_a).slug(), Some("ali"));

    // The label reaches the relay by `add-network` with a newer token...
    let with_label = owned_roster(&owner, 2, &[("ALI", 5)]);
    add_network(&relay, &encode_roster(&with_label, None), clock()).unwrap();
    let rosters = load_rosters(&relay).unwrap();
    let book = load_book(&relay, &rosters).unwrap();
    assert!(book.named("ali").is_some(), "{:?}", book.refused());
    assert!(!book.is_held_back(&id_a));

    // ...or as a member's push over DOC, which the keeper writes to the file.
    let pushed = owned_roster(&owner, 3, &[("ali", 5)]);
    running
        .relay
        .rosters()
        .adopt(&pushed, None, unix_now())
        .unwrap();
    assert!(running.flush_rosters(FLUSH));
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.tenants().id_of(&id_a).slug(), Some("ali"));
    assert!(!running.tenants().is_held_back(&id_a));
    assert!(
        running.roster_seq(&id_a).is_some(),
        "ali's network is still served"
    );

    // The default tenant cannot advertise the label, which is the slug.
    let ack = advertise_now(&running, &id_d, 5, &["ali"], clock());
    assert!(ack.names.is_empty());
    assert_eq!(ack.rejected[0].reason, "reserved name");
    running.stop();
}

/// Round T5, M1: a slug equal to a label a default Roster merely lists (nobody was accepted for
/// it) is allowed; one the relay accepted the default tenant for still is not.
#[test]
fn t5_a_tenant_name_is_judged_against_accepted_names_not_listed_labels() {
    let (_net, token_d) = labeled_network(&[("shop", 1)]);
    let (_b, _ob, _id_b, token_b) = another_network();
    let (_dir, relay) = relay_machine();
    add_network(&relay, &token_d, clock()).unwrap();
    let added = add_network_to(&relay, &token_b, clock(), Some("shop")).unwrap();
    assert_eq!(added.tenant.as_deref(), Some("shop"));
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    assert!(book.named("shop").is_some());
    assert!(
        book.reserves_flat_name("shop"),
        "so the label stays refused for the default tenant"
    );
}

/// Round T5, M3: `add-network --tenant <slug>` where the slug equals an older tenant's grant is
/// refused by the command, and the older tenant stays.
#[test]
fn t5_a_new_slug_equal_to_an_older_grant_is_refused_by_the_command() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_d, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    fs::create_dir_all(tenants_dir(&relay)).unwrap();
    fs::write(
        tenant_file(&relay, "ali"),
        format!(
            "networks = [\"{}\"]\nextra_names = [\"blog\"]\nadded = 10\n",
            id_a.to_hex()
        ),
    )
    .unwrap();
    let error = add_network_to(&relay, &token_b, clock(), Some("blog"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("blog") && error.contains("ali"), "{error}");
    assert!(!tenant_file(&relay, "blog").exists());
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    assert!(book.named("ali").is_some() && !book.is_held_back(&id_a));
    assert!(!book.is_held_back(&id_b));

    // Hand written, the newer file is the one the relay refuses.
    fs::write(
        tenant_file(&relay, "blog"),
        format!("networks = [\"{}\"]\nadded = 20\n", id_b.to_hex()),
    )
    .unwrap();
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    assert!(book.named("ali").is_some() && book.named("blog").is_none());
    assert!(book.is_held_back(&id_b) && !book.is_held_back(&id_a));
}

/// Round T5, M3: a command that would leave another tenant refused by the book stops, even when
/// the other file is not the one the command writes (here ali's `added` lies in the future, so
/// the new file would count as the older one and ali's grant would lose).
#[test]
fn t5_add_network_refuses_what_would_take_another_tenant_offline() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, _id_b, token_b) = another_network();
    let (_d, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    fs::create_dir_all(tenants_dir(&relay)).unwrap();
    fs::write(
        tenant_file(&relay, "ali"),
        format!(
            "networks = [\"{}\"]\nextra_names = [\"blog\"]\nadded = {}\n",
            id_a.to_hex(),
            clock() + 400 * DAY
        ),
    )
    .unwrap();
    let error = add_network_to(&relay, &token_b, clock(), Some("blog"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("take tenant ali offline"), "{error}");
    assert!(!tenant_file(&relay, "blog").exists());
}

/// Round T5, L1 and L2: a grant equal to a removed tenant's quarantined slug, and a slug equal
/// to a flat name a tenant was accepted for (here in quarantine), are refused.
#[test]
fn t5_slugs_and_grants_are_judged_against_quarantined_and_tenant_names() {
    let (_b, _ob, _id_b, token_b) = another_network();
    let (_c, _oc, id_c, token_c) = another_network();
    let (_d, relay) = relay_machine();
    // A flat name "blog" of tenant ali in quarantine.
    fs::create_dir_all(super::relay_dir(&relay)).unwrap();
    let mut state = menzil_relay::NameState::default();
    let claim = menzil_relay::Claim {
        full: "blog",
        tenant: Some("ali"),
        network: NetworkId::from([7u8; 32]),
    };
    let _ = state.accept(&claim, None, clock() - 10);
    assert!(state.release("blog", clock() - 5));
    state.quarantine_slug("gone", clock() - 5);
    fs::write(names_state::state_path(&relay), state.render()).unwrap();

    let error = add_network_to(&relay, &token_b, clock(), Some("blog"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("flat name") && error.contains("ali"),
        "{error}"
    );
    assert!(!tenant_file(&relay, "blog").exists());

    // A hand written tenant file whose grant is the quarantined slug is not used.
    add_network_to(&relay, &token_c, clock(), Some("veli")).unwrap();
    fs::write(
        tenant_file(&relay, "veli"),
        format!(
            "networks = [\"{}\"]\nextra_names = [\"gone\"]\nadded = 20\n",
            id_c.to_hex()
        ),
    )
    .unwrap();
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    assert!(book.named("veli").is_none());
    assert!(book.is_held_back(&id_c));
}

/// Round T5, L5: the networks of a removed tenant leave the store before the new tenant book is
/// set, so that in between they are not the default tenant's.
#[tokio::test]
async fn t5_a_reload_drops_a_removed_tenants_networks_before_it_swaps_the_book() {
    let (net_a, token_a) = labeled_network(&[("app", 1)]);
    let (net_d, token_d) = labeled_network(&[("app", 2)]);
    let (dir, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    add_network(&relay, &token_d, clock()).unwrap();
    let running = running_on(dir.path(), &relay).await;
    // The default tenant's node holds `app`, and is offline for a moment.
    assert_eq!(
        advertise_now(&running, &net_d, 2, &["app"], clock()).names,
        ["app"]
    );
    running
        .relay
        .labels()
        .clear_for(&NodeId::from([2u8; 32]), clock());
    assert_eq!(
        advertise_now(&running, &net_a, 1, &["app"], clock()).names,
        ["app.ali"]
    );
    running
        .relay
        .labels()
        .clear_for(&NodeId::from([1u8; 32]), clock());

    remove_tenant(&relay, "ali", clock()).unwrap();
    let mut looked = false;
    reload_once_with(&running.relay, &relay, &mut Vec::new(), &mut || {
        looked = true;
        assert!(
            !running.relay.rosters().serves(&net_a),
            "the removed tenant's network was still in the store when the book was swapped"
        );
        assert_eq!(
            running.relay.tenants().id_of(&net_a).slug(),
            Some("ali"),
            "the old book still stands at this point"
        );
        let ack = advertise_now(&running, &net_a, 1, &["app"], clock());
        assert!(ack.names.is_empty(), "{ack:?}");
    });
    assert!(looked);
    // The default tenant's name is where it was, and its node can take it again.
    let state = running.relay.labels().state();
    assert_eq!(state.names["app"].network, net_d);
    assert!(!state.quarantine.contains_key("app"));
    assert_eq!(
        advertise_now(&running, &net_d, 2, &["app"], clock()).names,
        ["app"]
    );
    running.stop();
}

/// Round T5, N2: a bad line of the old slug quarantine file is skipped (with a warning), the
/// good ones are moved, and the name state stays readable; slug entries whose quarantine has
/// ended are not carried on by a write.
#[tokio::test]
async fn t5_the_old_quarantine_file_is_validated_and_ended_slugs_are_pruned() {
    let (net_a, token_a) = labeled_network(&[("app", 1)]);
    let (dir, relay) = relay_machine();
    add_network(&relay, &token_a, clock()).unwrap();
    fs::create_dir_all(tenants_dir(&relay)).unwrap();
    let legacy = tenants_dir(&relay).join(".quarantine");
    fs::write(
        &legacy,
        format!(
            "oldone {}\nBad_Slug 5\nnot a line\nab {}\nx\n",
            clock(),
            clock()
        ),
    )
    .unwrap();
    // A slug entry written by a state file long ago, and one still running.
    let mut state = menzil_relay::NameState::default();
    state.quarantine_slug("expired", clock() - 200 * DAY);
    state.quarantine_slug("current", clock() - DAY);
    fs::create_dir_all(super::relay_dir(&relay)).unwrap();
    fs::write(names_state::state_path(&relay), state.render()).unwrap();

    let running = running_on(dir.path(), &relay).await;
    assert!(!legacy.exists(), "migrated");
    let text = names_file(&relay);
    assert!(text.contains("quarantine slug oldone "), "{text}");
    assert!(
        !text.contains("Bad_Slug") && !text.contains("quarantine slug ab "),
        "{text}"
    );
    assert!(menzil_relay::NameState::parse(&text).is_ok());
    // The relay's own write drops the slug whose quarantine ended and keeps the others.
    advertise_now(&running, &net_a, 1, &["app"], clock());
    assert!(running.flush_rosters(FLUSH));
    let text = names_file(&relay);
    assert!(!text.contains("quarantine slug expired "), "{text}");
    assert!(text.contains("quarantine slug current "), "{text}");
    assert!(text.contains("quarantine slug oldone "), "{text}");
    // And so does `remove-tenant`'s.
    let mut state = menzil_relay::NameState::parse(&text).unwrap();
    state.quarantine_slug("stale", clock() - 300 * DAY);
    fs::write(names_state::state_path(&relay), state.render()).unwrap();
    let (_b, _ob, _id_b, token_b) = another_network();
    add_network_to(&relay, &token_b, clock(), Some("ali")).unwrap();
    remove_tenant(&relay, "ali", clock()).unwrap();
    let text = names_file(&relay);
    assert!(!text.contains("quarantine slug stale "), "{text}");
    assert!(text.contains("quarantine slug ali "), "{text}");
    running.stop();
}

// ---- The blind front door (expose slice S-E6) ----

/// The share domain needs the relay's own host name, and both must be plain DNS names: nothing
/// is bound or read before that is judged.
#[tokio::test]
async fn the_front_door_needs_a_host_and_plain_names() {
    let (_o, owner, _id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let mut options = run_options(dir.path());
    let front = FrontDoorOptions {
        share_domain: "s.example".to_string(),
        http_listen: None,
        acme: None,
    };
    let error = start_with(&relay_home, &options, Some(&front))
        .await
        .err()
        .expect("no host");
    assert!(format!("{error:#}").contains("--host"), "{error:#}");
    options.host = Some("relay.example".to_string());
    for bad in ["", "s.example.", "bad domain", "relay.example"] {
        let front = FrontDoorOptions {
            share_domain: bad.to_string(),
            http_listen: None,
            acme: None,
        };
        assert!(
            start_with(&relay_home, &options, Some(&front))
                .await
                .is_err(),
            "{bad:?}"
        );
    }
}

/// The relay's ACME names no CA by itself: a directory that is not an https URL stops the
/// start, before anything is bound (no network is touched either way).
#[tokio::test]
async fn the_relays_acme_directory_must_be_an_https_url() {
    let (_o, owner, _id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let mut options = run_options(dir.path());
    options.host = Some("relay.example".to_string());
    for bad in [
        "",
        "http://ca.example/dir",
        "ca.example/dir",
        "ftp://ca.example",
    ] {
        let front = FrontDoorOptions {
            share_domain: "s.example".to_string(),
            http_listen: None,
            acme: Some(AcmeOptions {
                directory_url: bad.to_string(),
                contact: None,
            }),
        };
        let error = start_with(&relay_home, &options, Some(&front))
            .await
            .err()
            .unwrap_or_else(|| panic!("{bad:?} started"));
        assert!(format!("{error:#}").contains("https"), "{bad:?}: {error:#}");
    }
}

/// With a share domain the relay answers an unknown share name with the one fixed refusal and
/// serves port 80 only when asked; without one it reads nothing before TLS.
#[tokio::test]
async fn a_relay_with_a_share_domain_refuses_unknown_names_and_serves_port_80_only_when_asked() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (_o, owner, _id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let mut options = run_options(dir.path());
    options.host = Some("relay.example".to_string());

    let front = FrontDoorOptions {
        share_domain: "s.example".to_string(),
        http_listen: None,
        acme: None,
    };
    let running = start_with(&relay_home, &options, Some(&front))
        .await
        .unwrap();
    assert!(
        running.http_addr.is_none(),
        "port 80 is off unless asked for"
    );
    running.stop();

    let front = FrontDoorOptions {
        share_domain: "s.example".to_string(),
        http_listen: Some("127.0.0.1:0".parse().unwrap()),
        acme: None,
    };
    let running = start_with(&relay_home, &options, Some(&front))
        .await
        .unwrap();
    let http = running.http_addr.expect("asked for");
    let mut tcp = tokio::net::TcpStream::connect(http).await.unwrap();
    tcp.write_all(b"GET /x HTTP/1.1\r\nHost: app.s.example\r\n\r\n")
        .await
        .unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), tcp.read_to_end(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        String::from_utf8(got).unwrap(),
        "HTTP/1.1 301 Moved Permanently\r\nLocation: https://app.s.example/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    running.stop();
}

/// Expose round 2, L3: the soft file descriptor limit goes to the hard one (never past the
/// ceiling), and a limit that stays below the front door's budget is flagged.
#[test]
fn the_file_descriptor_plan_raises_to_the_hard_limit_and_flags_a_shortfall() {
    let need = 7_168;
    // The systemd default soft limit, a roomy hard one: raised, enough.
    assert_eq!(
        nofile_plan(1_024, 524_288, need),
        NofilePlan {
            raise_to: Some(524_288),
            short: false
        }
    );
    // A hard limit that is itself too low: raised to it, still short.
    assert_eq!(
        nofile_plan(1_024, 4_096, need),
        NofilePlan {
            raise_to: Some(4_096),
            short: true
        }
    );
    // Already at the hard limit: nothing to set; short or not by its own figure.
    assert_eq!(
        nofile_plan(4_096, 4_096, need),
        NofilePlan {
            raise_to: None,
            short: true
        }
    );
    assert_eq!(
        nofile_plan(65_536, 65_536, need),
        NofilePlan {
            raise_to: None,
            short: false
        }
    );
    // Soft above the need already, hard higher: still raised (to the hard one), not short.
    assert_eq!(nofile_plan(8_192, 16_384, need).raise_to, Some(16_384));
    // An unlimited hard limit is not set as such; the ceiling is.
    assert_eq!(
        nofile_plan(1_024, u64::MAX, need).raise_to,
        Some(NOFILE_CEILING)
    );
    // The exact budget is enough, one less is not.
    assert!(!nofile_plan(need, need, need).short);
    assert!(nofile_plan(need - 1, need - 1, need).short);
}

// ---- UI-A: `suspended` and the typed tenant operations ----

use super::tenants::{
    TenantError, UpdateTenant, get_tenant, list_tenants, set_suspended, update_tenant,
};
use menzil_relay::Class;
use std::collections::BTreeMap;

fn overrides(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
    pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
}

fn with_overrides(map: BTreeMap<String, u64>) -> UpdateTenant {
    UpdateTenant {
        quota_overrides: Some(map),
        ..UpdateTenant::default()
    }
}

#[tokio::test]
async fn a_suspended_tenants_networks_are_dropped_at_reload_and_resume_restores_them() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (dir, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    add_network_to(&relay, &token_b, clock(), Some("veli")).unwrap();
    // `terminated` is on, and suspending leaves it so.
    update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            terminated: Some(true),
            ..UpdateTenant::default()
        },
    )
    .unwrap();
    let running = running_on(dir.path(), &relay).await;
    assert_eq!(running.roster_seq(&id_a), Some(1));

    let info = set_suspended(&relay, "ali", true).unwrap();
    assert!(info.suspended && info.terminated);
    assert!(read_tenant_file(&relay, "ali").contains("suspended = true"));
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_a), None, "not served");
    assert_eq!(running.roster_seq(&id_b), Some(1), "another tenant is");
    assert!(roster_path(&relay, &id_a).exists(), "the Roster file stays");
    // Not the default tenant's: it is held back and still ali's.
    let book = running.relay.tenants();
    assert!(book.is_held_back(&id_a) && !book.is_held_back(&id_b));
    assert_eq!(
        book.id_of(&id_a),
        &TenantId::Named(menzil_relay::Slug::parse("ali").unwrap())
    );
    assert!(
        book.named("ali").unwrap().terminated,
        "terminated is untouched"
    );
    // And again after another reload: it does not creep back in.
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_a), None);

    let info = set_suspended(&relay, "ali", false).unwrap();
    assert!(!info.suspended && info.terminated);
    assert!(!read_tenant_file(&relay, "ali").contains("suspended"));
    reload_once(&running.relay, &relay, &mut Vec::new());
    assert_eq!(running.roster_seq(&id_a), Some(1), "resume restores");
    assert!(!running.relay.tenants().is_held_back(&id_a));
    running.stop();
}

#[test]
fn a_suspended_tenant_keeps_its_networks_out_of_the_default_tenant_and_takes_no_new_one() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, _id_b, token_b) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    set_suspended(&relay, "ali", true).unwrap();

    // A renewal without `--tenant` leaves the network in ali, held back.
    let renewed = add_network_to(&relay, &token_a, clock() + 1, None).unwrap();
    assert_eq!(renewed.tenant.as_deref(), Some("ali"));
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    assert!(book.is_held_back(&id_a));
    assert_eq!(
        book.id_of(&id_a),
        &TenantId::Named(menzil_relay::Slug::parse("ali").unwrap())
    );
    assert!(read_tenant_file(&relay, "ali").contains("suspended = true"));

    // A new network cannot go into the suspended tenant, and a listed one cannot move away.
    let error = add_network_to(&relay, &token_b, clock(), Some("ali"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("suspended"), "{error}");
    let error = add_network_to(&relay, &token_a, clock(), Some("veli"))
        .unwrap_err()
        .to_string();
    assert!(error.contains("already in tenant ali"), "{error}");

    // `remove-network` keeps the key.
    remove_network(&relay, &id_a.to_hex()).unwrap();
    assert!(read_tenant_file(&relay, "ali").contains("suspended = true"));

    // The listing says so.
    let listing = render_tenants(&relay, clock()).unwrap();
    assert!(listing.contains("suspended"), "{listing}");
}

#[test]
fn suspend_and_resume_are_idempotent_and_name_their_errors() {
    let (_a, _oa, _id, token_a) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    assert!(!set_suspended(&relay, "ali", false).unwrap().suspended);
    assert!(set_suspended(&relay, "ali", true).unwrap().suspended);
    assert!(set_suspended(&relay, "ali", true).unwrap().suspended);
    assert_eq!(
        set_suspended(&relay, "nobody", true).unwrap_err(),
        TenantError::NotFound
    );
    assert!(matches!(
        set_suspended(&relay, "Not A Name", true).unwrap_err(),
        TenantError::Invalid(_)
    ));
}

#[test]
fn an_update_or_a_renewal_never_lifts_a_suspension() {
    let (_a, _oa, _id, token_a) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    set_suspended(&relay, "ali", true).unwrap();

    // Every writer that rewrites the tenant file keeps the flag.
    let info = update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            terminated: Some(true),
            quota_overrides: Some(overrides(&[("names", 7)])),
            ..UpdateTenant::default()
        },
    )
    .unwrap();
    assert!(info.suspended && info.terminated, "{info:?}");
    assert!(get_tenant(&relay, "ali").unwrap().suspended);
    // A renewal of the same network without `--tenant` leaves the tenant suspended too.
    add_network_to(&relay, &token_a, clock() + 10, None).unwrap();
    assert!(get_tenant(&relay, "ali").unwrap().suspended);
    // Resume lifts it, and only resume.
    assert!(!set_suspended(&relay, "ali", false).unwrap().suspended);
}

#[test]
fn get_and_list_tenants_report_what_the_file_says() {
    let (_a, _oa, id_a, token_a) = another_network();
    let (_b, _ob, id_b, token_b) = another_network();
    let (_d, relay) = relay_machine();
    assert_eq!(list_tenants(&relay).unwrap(), vec![]);
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    add_network_to(&relay, &token_b, clock() + 5, Some("veli")).unwrap();
    update_tenant(&relay, "veli", with_overrides(overrides(&[("names", 9)]))).unwrap();
    set_suspended(&relay, "veli", true).unwrap();

    let ali = get_tenant(&relay, "ali").unwrap();
    assert_eq!(ali.slug, "ali");
    assert_eq!(ali.network_ids, vec![id_a]);
    assert_eq!(ali.class, Class::Friend);
    assert!(!ali.terminated && !ali.suspended);
    assert_eq!(ali.added_unix, clock());
    assert!(ali.quota_overrides.is_empty());
    let veli = get_tenant(&relay, "veli").unwrap();
    assert_eq!(veli.network_ids, vec![id_b]);
    assert!(veli.suspended);
    assert_eq!(veli.added_unix, clock() + 5);
    assert_eq!(veli.quota_overrides, overrides(&[("names", 9)]));
    let all = list_tenants(&relay).unwrap();
    assert_eq!(all, vec![ali, veli]);
    assert_eq!(
        get_tenant(&relay, "nobody").unwrap_err(),
        TenantError::NotFound
    );
    assert!(matches!(
        get_tenant(&relay, "x").unwrap_err(),
        TenantError::Invalid(_)
    ));
    // A file the relay refuses is not NotFound.
    fs::write(tenant_file(&relay, "bad"), "class = \"gold\"\n").unwrap();
    assert!(matches!(
        get_tenant(&relay, "bad").unwrap_err(),
        TenantError::Precondition(_)
    ));
    assert_eq!(list_tenants(&relay).unwrap().len(), 2);
}

#[test]
fn update_tenant_round_trips_through_the_file_and_replaces_the_override_set() {
    let (_a, _oa, _id, token_a) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    let info = update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            terminated: Some(true),
            quota_overrides: Some(overrides(&[("names", 9), ("bandwidth_mbit", 50)])),
            class: None,
        },
    )
    .unwrap();
    assert!(info.terminated);
    assert_eq!(
        info.quota_overrides,
        overrides(&[("names", 9), ("bandwidth_mbit", 50)])
    );
    // The file says it and the book reads it the same.
    let text = read_tenant_file(&relay, "ali");
    assert!(
        text.contains("names = 9") && text.contains("terminated = true"),
        "{text}"
    );
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    let figures = book.named("ali").unwrap().figures.unwrap();
    assert_eq!((figures.names, figures.bandwidth_mbit), (9, 50));
    assert!(book.refused().is_empty());

    // `Some` REPLACES: only `roster_kib` is left, `names` is back to the default.
    update_tenant(
        &relay,
        "ali",
        with_overrides(overrides(&[("roster_kib", 4)])),
    )
    .unwrap();
    let info = get_tenant(&relay, "ali").unwrap();
    assert_eq!(info.quota_overrides, overrides(&[("roster_kib", 4)]));
    assert!(info.terminated, "a field left None is kept");
    // None keeps the set; an empty set goes back to the class defaults.
    update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            terminated: Some(false),
            ..UpdateTenant::default()
        },
    )
    .unwrap();
    assert_eq!(
        get_tenant(&relay, "ali").unwrap().quota_overrides,
        overrides(&[("roster_kib", 4)])
    );
    update_tenant(&relay, "ali", with_overrides(BTreeMap::new())).unwrap();
    let info = get_tenant(&relay, "ali").unwrap();
    assert!(info.quota_overrides.is_empty() && !info.terminated);
    // The class changes both ways.
    let personal = UpdateTenant {
        class: Some(Class::Personal),
        ..UpdateTenant::default()
    };
    assert_eq!(
        update_tenant(&relay, "ali", personal).unwrap().class,
        Class::Personal
    );
    assert_eq!(
        get_tenant(&relay, "ali").unwrap().class,
        Class::Personal,
        "{}",
        read_tenant_file(&relay, "ali")
    );
    let friend = UpdateTenant {
        class: Some(Class::Friend),
        ..UpdateTenant::default()
    };
    assert_eq!(
        update_tenant(&relay, "ali", friend).unwrap().class,
        Class::Friend
    );
}

#[test]
fn update_tenant_refuses_a_personal_tenant_with_overrides_in_either_order() {
    let (_a, _oa, _id, token_a) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    // Overrides on a personal tenant.
    update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            class: Some(Class::Personal),
            ..UpdateTenant::default()
        },
    )
    .unwrap();
    let before = read_tenant_file(&relay, "ali");
    let error =
        update_tenant(&relay, "ali", with_overrides(overrides(&[("names", 9)]))).unwrap_err();
    assert!(matches!(error, TenantError::Invalid(_)), "{error:?}");
    // Class and overrides together.
    let both = UpdateTenant {
        class: Some(Class::Personal),
        quota_overrides: Some(overrides(&[("names", 9)])),
        ..UpdateTenant::default()
    };
    assert!(matches!(
        update_tenant(&relay, "ali", both).unwrap_err(),
        TenantError::Invalid(_)
    ));
    // An empty set on a personal tenant is fine.
    update_tenant(&relay, "ali", with_overrides(BTreeMap::new())).unwrap();
    assert_eq!(
        before.lines().count(),
        read_tenant_file(&relay, "ali").lines().count()
    );

    // The other order: a friend with overrides cannot become personal.
    update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            class: Some(Class::Friend),
            quota_overrides: Some(overrides(&[("names", 9)])),
            ..UpdateTenant::default()
        },
    )
    .unwrap();
    let before = read_tenant_file(&relay, "ali");
    let error = update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            class: Some(Class::Personal),
            ..UpdateTenant::default()
        },
    )
    .unwrap_err();
    assert!(matches!(error, TenantError::Invalid(_)), "{error:?}");
    assert_eq!(
        read_tenant_file(&relay, "ali"),
        before,
        "nothing was written"
    );
    assert_eq!(get_tenant(&relay, "ali").unwrap().class, Class::Friend);
}

#[test]
fn update_tenant_judges_every_figure_with_the_relays_rules() {
    let (_a, _oa, _id, token_a) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    let before = read_tenant_file(&relay, "ali");
    let invalid = |map: BTreeMap<String, u64>| {
        let error = update_tenant(&relay, "ali", with_overrides(map)).unwrap_err();
        assert!(matches!(error, TenantError::Invalid(_)), "{error:?}");
    };
    invalid(overrides(&[("no_such_figure", 3)]));
    invalid(overrides(&[("names", 0)]));
    let (name, max) = menzil_relay::Figures::KEYS[3];
    invalid(overrides(&[(name, max + 1)]));
    // The floor above the bandwidth, set together or against the default bandwidth of 100.
    invalid(overrides(&[("bandwidth_mbit", 10), ("floor_mbit", 11)]));
    invalid(overrides(&[("floor_mbit", 101)]));
    assert_eq!(
        read_tenant_file(&relay, "ali"),
        before,
        "nothing was written"
    );
    // Every key the relay knows, at its maximum, is accepted (and `max_networks` at the
    // maximum is no problem).
    let all: BTreeMap<String, u64> = menzil_relay::Figures::KEYS
        .iter()
        .map(|(k, max)| (k.to_string(), *max))
        .collect();
    // Floor at the maximum equals the bandwidth at the maximum, which is allowed.
    update_tenant(&relay, "ali", with_overrides(all.clone())).unwrap();
    assert_eq!(get_tenant(&relay, "ali").unwrap().quota_overrides, all);
    // A lowered bandwidth alone is judged as the relay does: the default floor follows it down.
    update_tenant(
        &relay,
        "ali",
        with_overrides(overrides(&[("bandwidth_mbit", 1)])),
    )
    .unwrap();
    let book = load_book(&relay, &load_rosters(&relay).unwrap()).unwrap();
    assert!(book.refused().is_empty(), "{:?}", book.refused());
    // Unknown slug and bad slug.
    assert_eq!(
        update_tenant(&relay, "nobody", UpdateTenant::default()).unwrap_err(),
        TenantError::NotFound
    );
    assert!(matches!(
        update_tenant(&relay, "Not A Name", UpdateTenant::default()).unwrap_err(),
        TenantError::Invalid(_)
    ));
}

#[test]
fn update_tenant_refuses_max_networks_below_the_networks_it_has() {
    let (_a, _oa, _ia, token_a) = another_network();
    let (_b, _ob, _ib, token_b) = another_network();
    let (_d, relay) = relay_machine();
    add_network_to(&relay, &token_a, clock(), Some("ali")).unwrap();
    add_network_to(&relay, &token_b, clock(), Some("ali")).unwrap();
    let before = read_tenant_file(&relay, "ali");
    let error = update_tenant(
        &relay,
        "ali",
        with_overrides(overrides(&[("max_networks", 1)])),
    )
    .unwrap_err();
    assert!(matches!(error, TenantError::Precondition(_)), "{error:?}");
    assert_eq!(read_tenant_file(&relay, "ali"), before);
    // Equal to the count is fine.
    update_tenant(
        &relay,
        "ali",
        with_overrides(overrides(&[("max_networks", 2)])),
    )
    .unwrap();
    // A change that does not touch the figures is not held up by one that already exceeds.
    let file = read_tenant_file(&relay, "ali").replace("max_networks = 2", "max_networks = 1");
    fs::write(tenant_file(&relay, "ali"), file).unwrap();
    update_tenant(
        &relay,
        "ali",
        UpdateTenant {
            terminated: Some(true),
            ..UpdateTenant::default()
        },
    )
    .unwrap();
}

// ---- The status export (`relay/status.json`) ----

/// Waits (real time, up to 10 s) for `read` of the relay's status file to satisfy `ok`.
async fn status_when(home: &Home, ok: impl Fn(&status::StatusDoc) -> bool) -> status::StatusDoc {
    let mut last = None;
    for _ in 0..200 {
        match status::read(home, unix_now()) {
            Ok(doc) if ok(&doc) => return doc,
            other => last = Some(other),
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the status file never showed it: {last:?}");
}

/// A running relay writes its tenants' counters to `status.json` (the default tenant under its
/// reserved key), keeps it current, and stops writing when it stops.
#[tokio::test]
async fn a_running_relay_exports_its_counters_and_stops_with_the_relay() {
    let (_oa, owner_a, _ida, _) = token_of_a_network();
    let (_ob, owner_b, idb, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network_to(&relay_home, &relay_token(&owner_a), clock(), None).unwrap();
    add_network_to(&relay_home, &relay_token(&owner_b), clock(), Some("ali")).unwrap();
    let options = run_options(dir.path());
    let running = start_with_status_every(&relay_home, &options, None, Duration::from_millis(100))
        .await
        .unwrap();
    let first = status_when(&relay_home, |_| true).await;
    assert_eq!(first.version, status::VERSION);
    let keys: std::collections::BTreeSet<&str> = first.tenants.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([status::DEFAULT_KEY, "ali"]),
        "the default tenant and the named one, nothing else"
    );
    assert_eq!(first.entry("ali"), status::TenantEntry::default());
    // A counter that changes later shows up in a later export.
    let mut names = NameState::default();
    for full in ["a.ali", "b.ali"] {
        names.names.insert(
            full.to_string(),
            menzil_relay::NameRecord {
                tenant: Some("ali".to_string()),
                network: idb,
                first: 1,
                last: 1,
            },
        );
    }
    running.relay.labels().load_state(&names);
    let later = status_when(&relay_home, |doc| doc.entry("ali").names == 2).await;
    assert_eq!(later.entry(status::DEFAULT_KEY).names, 0);
    // The text on disk is what `relay status --json` prints.
    let on_disk = std::fs::read_to_string(status::status_path(&relay_home)).unwrap();
    assert!(on_disk.contains("\"_default\""));
    for secret in [idb.to_hex().as_str(), "menzil1-"] {
        assert!(
            !on_disk.contains(secret),
            "the file names no network or token"
        );
    }
    // Stopping the relay stops the export: nothing is written after the last pass.
    running.stop();
    tokio::time::sleep(Duration::from_millis(400)).await;
    let stopped = status::read(&relay_home, unix_now())
        .unwrap()
        .generated_unix;
    tokio::time::sleep(Duration::from_millis(2_200)).await;
    assert_eq!(
        status::read(&relay_home, unix_now())
            .unwrap()
            .generated_unix,
        stopped,
        "the status export went on after the relay stopped"
    );
}

/// `--fallback-page`: the file is read at start, so a missing, empty or oversize one is a start
/// error that names it, and a good one starts the relay.
#[tokio::test]
async fn a_relay_reads_its_fallback_page_at_start_and_refuses_a_bad_one() {
    let (_o, owner, _id, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner), clock()).unwrap();
    let mut options = run_options(dir.path());

    options.fallback_page = Some(dir.path().join("missing.html"));
    let error = start(&relay_home, &options).await.err().unwrap();
    assert!(format!("{error:#}").contains("fallback page"), "{error:#}");

    let page = dir.path().join("index.html");
    options.fallback_page = Some(page.clone());
    fs::write(&page, b"").unwrap();
    let error = start(&relay_home, &options).await.err().unwrap();
    assert!(format!("{error:#}").contains("fallback page"), "{error:#}");

    fs::write(&page, vec![b'x'; menzil_relay::FALLBACK_PAGE_MAX_BYTES + 1]).unwrap();
    let error = start(&relay_home, &options).await.err().unwrap();
    assert!(format!("{error:#}").contains("fallback page"), "{error:#}");

    fs::write(&page, b"<h1>hi</h1>").unwrap();
    let running = start(&relay_home, &options).await.unwrap();
    running.stop();
}
