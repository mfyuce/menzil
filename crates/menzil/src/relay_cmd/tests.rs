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
    assert_eq!(rosters[0].decode().unwrap().network_id, id);
    // Nothing of the Policy is on disk: members' names and grants are none of a relay's business.
    let bytes = fs::read(roster_path(&relay, &id)).unwrap();
    assert_eq!(bytes, rosters[0].encode());
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
            kept[0].decode().unwrap().seq,
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
    assert_eq!(load_rosters(&relay).unwrap()[0].decode().unwrap().seq, 2);
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
    let forged = encode_roster(&Roster::sign(&thief, docs.roster_body()).unwrap());
    assert!(message(&forged, clock()).contains("not signed by the network's owner"));

    // The full membership token carries the Policy, and a relay is not given that.
    let refused = message(&docs_token, clock());
    assert!(
        refused.contains("Policy") && refused.contains("--for-relay"),
        "{refused}"
    );
    let forged_docs = encode_documents(
        &Roster::sign(&thief, docs.roster_body()).unwrap(),
        &Policy::sign(&thief, docs.policy_body()).unwrap(),
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
    let roster = crate::token::decode_roster(&relay_token).unwrap();
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
