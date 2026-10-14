use std::time::Duration;

use menzil_admin::{NodeKeys, OwnerKey, create_network};
use menzil_carrier::ConnectionInfo;
use menzil_proto::Policy;

use super::*;
use crate::local::{init, join, network_create};
use crate::token::{encode_documents, encode_roster};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 24 * 60 * 60;

fn home() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("menzil"));
    (dir, home)
}

/// An owner's token for a network, and the owner's home.
fn token_of_a_network() -> (tempfile::TempDir, Home, NetworkId, String) {
    let (dir, owner) = home();
    init(&owner, NOW).unwrap();
    let id = network_create(&owner, "laptop", NOW).unwrap();
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
    let (network, seq) = add_network(&relay, &relay_token(&owner), NOW + 1).unwrap();
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

#[test]
fn an_older_or_equal_roster_does_not_replace_a_newer_one() {
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let first = relay_token(&owner);
    let (_d, relay) = home();
    add_network(&relay, &first, NOW).unwrap();
    crate::local::renew(&owner, None, NOW + DAY).unwrap();
    assert_eq!(
        add_network(&relay, &relay_token(&owner), NOW + DAY).unwrap(),
        (id, 2)
    );
    // The first token again: the relay keeps what is newer and says so.
    assert_eq!(add_network(&relay, &first, NOW + DAY).unwrap(), (id, 2));
    assert_eq!(load_rosters(&relay).unwrap()[0].decode().unwrap().seq, 2);
}

#[test]
fn add_network_refuses_forged_expired_and_wrong_tokens() {
    let (_o, owner, _id, docs_token) = token_of_a_network();
    let token = relay_token(&owner);
    let (_d, relay) = home();
    let message =
        |token: &str, at: u64| format!("{:#}", add_network(&relay, token, at).unwrap_err());

    assert!(message(&token, NOW + 15 * DAY).contains("expired"));
    assert!(
        message("menzil1-join:AAAA", NOW).contains("other kind")
            || message("menzil1-join:AAAA", NOW).contains("expected")
    );
    assert!(message("garbage", NOW).contains("expected"));

    // Documents of the owner's network, signed by somebody else.
    let owner = OwnerKey::generate();
    let keys = NodeKeys::generate();
    let cert = keys.issue_cert(1, NOW - 10, NOW + 1000).unwrap();
    let docs = create_network(&owner, &cert, "x", NOW).unwrap();
    let thief = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let forged = encode_roster(&Roster::sign(&thief, docs.roster_body()).unwrap());
    assert!(message(&forged, NOW).contains("not signed by the network's owner"));

    // The full membership token carries the Policy, and a relay is not given that.
    let refused = message(&docs_token, NOW);
    assert!(
        refused.contains("Policy") && refused.contains("--for-relay"),
        "{refused}"
    );
    let forged_docs = encode_documents(
        &Roster::sign(&thief, docs.roster_body()).unwrap(),
        &Policy::sign(&thief, docs.policy_body()).unwrap(),
    );
    assert!(message(&forged_docs, NOW).contains("--for-relay"));
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
    assert!(crate::local::join(&home().1, &relay_token, NOW).is_err());
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
    add_network(&relay, &relay_token(&owner), NOW).unwrap();
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
    init(&relay, NOW).unwrap();
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
    init(&relay_home, NOW).unwrap();
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

    add_network(&relay_home, &relay_token(&owner), NOW).unwrap();
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
    init(&relay, NOW).unwrap();
    let error = format!("{:#}", join(&relay, &token, NOW).unwrap_err());
    assert!(error.contains("not a member"), "{error}");
}

/// `menzil renew` on the owner and `add-network` with the new token on the relay's machine, while
/// the relay runs: the relay holds the newer Roster a moment later, without a restart.
#[tokio::test]
async fn a_running_relay_picks_up_a_newer_roster_added_to_its_directory() {
    let (_o, owner, id, _docs_token) = token_of_a_network();
    let (dir, relay_home) = home();
    init(&relay_home, NOW).unwrap();
    add_network(&relay_home, &relay_token(&owner), NOW).unwrap();
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

    crate::local::renew(&owner, None, NOW + DAY).unwrap();
    add_network(&relay_home, &relay_token(&owner), NOW + DAY).unwrap();
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
