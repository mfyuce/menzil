//! `menzil join <invite>` against a real relay and a running issuer node (slice D3 B4): the happy
//! path writes the Roster only state, the config line and the relay record, and the device's own
//! node then receives the Policy by the issuer's push and removes the Roster only file; the
//! refusals of the relay and the issuer reach the person as refusals; a request that finds no
//! issuer waits and is answered when the issuer attaches.
//!
//! One `#[tokio::test]`: `SSL_CERT_FILE` is process-global and must be set before anything dials.
//! (The full end to end test, a stream over the admitted device, is slice B5.)

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::invite::{self, CreateSpec};
use menzil_cli::join::{JoinError, JoinOptions, RelayConfig, redeem};
use menzil_cli::local::{init, load_documents, network_create, token_for_relay};
use menzil_cli::node_cmd;
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use menzil_cli::token::{InviteToken, decode_invite, encode_invite};
use menzil_proto::{ErrorCode, Invite};

const WAIT: Duration = Duration::from_secs(60);

async fn until(what: &str, mut check: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !check() {
        assert!(started.elapsed() < WAIT, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn options(name: &str) -> JoinOptions {
    JoinOptions {
        name: Some(name.to_string()),
        wait: Duration::from_secs(60),
        retry_first: Duration::from_secs(1),
        retry_max: Duration::from_secs(2),
    }
}

fn refused(result: Result<menzil_cli::join::Joined, JoinError>) -> ErrorCode {
    match result {
        Err(JoinError::Refused { code, message }) => {
            assert!(!message.is_empty());
            code
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A device home with an identity and a config that dials directly.
fn device(root: &std::path::Path, label: &str, real: u64) -> Home {
    let home = Home::new(root.join(label));
    init(&home, real).unwrap();
    std::fs::write(home.config_path(), "proxy = \"direct\"\n").unwrap();
    home
}

#[tokio::test]
async fn a_device_joins_with_an_invite_and_its_node_then_gets_the_policy() {
    let real = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = root.join("fullchain.pem");
    let key_pem = root.join("privkey.pem");
    std::fs::write(&cert_pem, certified.cert.pem()).unwrap();
    std::fs::write(&key_pem, certified.signing_key.serialize_pem()).unwrap();
    // SAFETY: the first thing the only test in this binary does, before any dial or other thread
    // that could read the environment.
    unsafe { std::env::set_var("SSL_CERT_FILE", &cert_pem) };

    let relay_home = Home::new(root.join("relay"));
    let owner_home = Home::new(root.join("owner"));
    init(&relay_home, real).unwrap();
    init(&owner_home, real).unwrap();
    let network_id = network_create(&owner_home, "owner", real).unwrap();
    relay_cmd::add_network(
        &relay_home,
        &token_for_relay(&owner_home, None).unwrap(),
        real,
    )
    .unwrap();
    let relay = relay_cmd::start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert_pem.clone(),
            tls_key: key_pem.clone(),
            path: DEFAULT_PATH.to_string(),
            host: Some("localhost".to_string()),
            reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
            fallback_page: None,
            admission: None,
            audit_file: None,
        },
    )
    .await
    .unwrap();
    let relay_line = relay.connection_info.to_string();
    std::fs::write(
        owner_home.config_path(),
        format!("relay = \"{relay_line}\"\nproxy = \"direct\"\n"),
    )
    .unwrap();

    let start_owner = || async {
        let owner = node_cmd::start(
            &owner_home,
            &Config::load(&owner_home).unwrap(),
            &root.join("owner.sock"),
        )
        .await
        .unwrap();
        owner
            .node
            .wait_attached(WAIT)
            .await
            .expect("owner attaches");
        owner
    };
    // ---- pending, then admitted --------------------------------------------------------------
    // No issuer attached yet: the relay holds the request and says `pending`; the device waits and
    // is answered when the issuer attaches.
    let invite_for = |spec: &CreateSpec| {
        invite::create(&owner_home, spec, &relay_line, real)
            .unwrap()
            .token
    };
    let late_home = device(root, "late", real);
    let late = invite_for(&CreateSpec::default());
    let said = Arc::new(Mutex::new(Vec::<String>::new()));
    let waiting = {
        let (home, said) = (late_home.clone(), said.clone());
        tokio::spawn(async move {
            redeem(&home, &late, &options("late"), &mut |l| {
                said.lock().unwrap().push(l.to_string())
            })
            .await
        })
    };
    until("the device to be told it is pending", || {
        !said.lock().unwrap().is_empty()
    })
    .await;
    assert!(said.lock().unwrap()[0].contains("issuer is not reachable"));
    assert!(!waiting.is_finished());
    let owner = start_owner().await;
    let joined = tokio::time::timeout(WAIT, waiting)
        .await
        .expect("the device is answered once the issuer attaches")
        .unwrap()
        .unwrap();
    assert_eq!(joined.name, "late");
    assert!(late_home.roster_only_path(&network_id).is_file());
    assert_eq!(joined.roster_seq, 2);

    // ---- the happy path ------------------------------------------------------------------
    let phone_home = device(root, "phone", real);
    let token = invite_for(&CreateSpec::default());
    let mut lines = Vec::new();
    let joined = redeem(&phone_home, &token, &options("phone"), &mut |l| {
        lines.push(l.to_string())
    })
    .await
    .unwrap();
    assert_eq!(joined.network_id, network_id);
    assert_eq!(joined.name, "phone");
    assert_eq!(
        joined.roster_seq, 3,
        "one new Roster after the late device's"
    );
    assert_eq!(joined.relay_config, RelayConfig::Written);
    let only = phone_home.roster_only_path(&network_id);
    assert_eq!(
        std::fs::metadata(&only).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!phone_home.documents_path(&network_id).exists());
    let config = Config::load(&phone_home).unwrap();
    assert_eq!(config.relay.as_deref(), Some(relay_line.as_str()));
    assert_eq!(config.proxy.as_deref(), Some("direct"));
    // The relay record is in known-relays.cbor (the handshake stored it).
    let known = std::fs::read(phone_home.known_relays_path()).unwrap();
    let relay_id: [u8; 32] = menzil_carrier::ConnectionInfo::parse(&relay_line)
        .unwrap()
        .relay_node_id
        .into();
    assert!(
        known.windows(32).any(|w| w == relay_id),
        "the relay's record is stored"
    );
    assert!(
        lines.is_empty(),
        "nothing to say on the way when the issuer answers at once"
    );
    // The same device again: its home is in the network now (the Roster only file does not
    // count as documents, so the request goes out again and the issuer answers it as a repeat).
    let again = redeem(&phone_home, &token, &options("phone"), &mut |_| {})
        .await
        .unwrap();
    assert_eq!(
        again.roster_seq, 3,
        "the retry of a lost answer changes nothing"
    );

    // The device's node claims the network on the Roster only file and the issuer's push gives
    // it the Policy; the file is then gone and documents.bin is there.
    let phone = node_cmd::start(
        &phone_home,
        &Config::load(&phone_home).unwrap(),
        &root.join("phone.sock"),
    )
    .await
    .unwrap();
    assert_eq!(phone.node.rosters().seq(&network_id), Some(3));
    assert_eq!(phone.node.policies().seq(&network_id), None);
    phone
        .node
        .wait_attached(WAIT)
        .await
        .expect("phone attaches");
    until("the Policy to reach the phone", || {
        phone.node.policies().seq(&network_id) == Some(3)
    })
    .await;
    until("documents.bin to replace roster-only.bin", || {
        phone_home.documents_path(&network_id).is_file() && !only.exists()
    })
    .await;
    assert_eq!(load_documents(&phone_home, &network_id).unwrap().seq(), 3);
    drop(phone);

    // ---- refusals --------------------------------------------------------------------------
    // The invite had one use: another device is refused by the issuer.
    let tablet_home = device(root, "tablet", real);
    let code = refused(redeem(&tablet_home, &token, &options("tablet"), &mut |_| {}).await);
    assert_eq!(code, ErrorCode::BadInvite);
    assert!(tablet_home.roster_only_networks().unwrap().is_empty());
    assert_eq!(
        std::fs::read_to_string(tablet_home.config_path()).unwrap(),
        "proxy = \"direct\"\n",
        "a refusal changes nothing on the device"
    );

    // A name that is taken.
    let two = invite_for(&CreateSpec {
        uses: 2,
        ..CreateSpec::default()
    });
    let code = refused(redeem(&tablet_home, &two, &options("phone"), &mut |_| {}).await);
    assert_eq!(code, ErrorCode::NameTaken);
    // And the same invite still has its uses: a free name goes through.
    let joined = redeem(&tablet_home, &two, &options("tablet"), &mut |_| {})
        .await
        .unwrap();
    assert_eq!(joined.name, "tablet");

    // An invite signed by somebody who is neither the owner nor a steward: the device cannot tell
    // (a steward's looks the same), the relay refuses it.
    let stray_home = device(root, "stray", real);
    let genuine = decode_invite(&invite_for(&CreateSpec::default())).unwrap();
    let body = genuine.invite.decode().unwrap();
    let forged = encode_invite(&InviteToken {
        invite: Invite::sign(&SigningKey::generate(&mut rand::rng()), &body).unwrap(),
        secret: genuine.secret,
        relay: genuine.relay.clone(),
    });
    let code = refused(redeem(&stray_home, &forged, &options("stray"), &mut |_| {}).await);
    assert_eq!(code, ErrorCode::BadInvite);

    // An invite that fixes the name: another --name is refused before any network use, none
    // takes the fixed one. The config of this device already names a relay: it is not changed.
    let fixed_home = device(root, "fixed", real);
    let other_relay = format!(
        "menzil://other.example.org:443/_menzil/v1?id={}",
        "cd".repeat(32)
    );
    std::fs::write(
        fixed_home.config_path(),
        format!("relay = \"{other_relay}\"\nproxy = \"direct\"\n"),
    )
    .unwrap();
    let fixed = invite_for(&CreateSpec {
        name: Some("watch".into()),
        ..CreateSpec::default()
    });
    assert!(matches!(
        redeem(&fixed_home, &fixed, &options("pager"), &mut |_| {}).await,
        Err(JoinError::Invalid(_))
    ));
    let joined = redeem(
        &fixed_home,
        &fixed,
        &JoinOptions {
            name: None,
            ..options("")
        },
        &mut |_| {},
    )
    .await
    .unwrap();
    assert_eq!(joined.name, "watch");
    assert_eq!(
        joined.relay_config,
        RelayConfig::Differs {
            configured: other_relay.clone()
        }
    );
    assert_eq!(
        Config::load(&fixed_home).unwrap().relay.as_deref(),
        Some(other_relay.as_str())
    );

    drop(owner);
    relay.stop();
}
