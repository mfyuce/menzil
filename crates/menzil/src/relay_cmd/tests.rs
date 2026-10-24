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

/// Round 6, M1: one network whose Roster on disk has expired (renewals travel by DOC, which the
/// relay does not write back) holds back that network only; the relay starts and serves the
/// others.
#[tokio::test]
async fn an_expired_roster_on_disk_holds_back_its_network_only() {
    let (_oa, owner_a) = home();
    init(&owner_a, clock() - 15 * DAY).unwrap();
    let id_a = network_create(&owner_a, "laptop", clock() - 15 * DAY).unwrap();
    let (_ob, owner_b, id_b, _) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, clock()).unwrap();
    add_network(&relay_home, &relay_token(&owner_a), clock() - 15 * DAY + 60).unwrap();
    add_network(&relay_home, &relay_token(&owner_b), clock()).unwrap();
    let (cert, key) = pem_files(dir.path());
    let options = RunOptions {
        listen: "127.0.0.1:0".parse().unwrap(),
        tls_cert: cert,
        tls_key: key,
        path: DEFAULT_PATH.to_string(),
        host: Some("localhost".to_string()),
        reload_every: Duration::from_millis(100),
    };
    let running = start(&relay_home, &options)
        .await
        .expect("an expired Roster of one network must not stop the relay");
    assert_eq!(running.networks, vec![id_b]);
    assert!(running.roster_seq(&id_b).is_some());
    assert_eq!(running.roster_seq(&id_a), None);
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
