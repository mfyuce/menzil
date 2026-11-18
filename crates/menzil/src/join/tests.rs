use std::os::unix::fs::PermissionsExt;

use menzil_proto::{Invite, InviteId, NodeId, PROTOCOL_VERSION, RevokedMember, verify_admit_tag};

use menzil_admin::create_network;

use super::*;
use crate::invite::{CreateSpec, create};
use crate::local::{
    admit, init, join as join_documents, load_documents, load_owner, network_create,
};
use crate::token::encode_invite;

const DAY: u64 = 86_400;

fn now() -> u64 {
    unix_now()
}

fn relay() -> String {
    format!(
        "menzil://relay.example.org:443/_menzil/v1?id={}",
        "ab".repeat(32)
    )
}

struct Fx {
    _dir: tempfile::TempDir,
    owner: Home,
    device: Home,
    network: NetworkId,
}

fn fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let owner = Home::new(dir.path().join("owner"));
    let device = Home::new(dir.path().join("device"));
    init(&owner, now()).unwrap();
    init(&device, now()).unwrap();
    let network = network_create(&owner, "owner", now()).unwrap();
    Fx {
        _dir: dir,
        owner,
        device,
        network,
    }
}

fn token_of(fx: &Fx, spec: &CreateSpec) -> String {
    create(&fx.owner, spec, &relay(), now()).unwrap().token
}

/// A token whose invite body is `edit`ed and signed by `key` (the owner's, unless told).
fn crafted(
    fx: &Fx,
    key: Option<&ed25519_dalek::SigningKey>,
    secret: [u8; 32],
    edit: impl FnOnce(&mut InviteBody),
) -> String {
    let owner = load_owner(&fx.owner, &fx.network).unwrap();
    let mut body = InviteBody {
        v: PROTOCOL_VERSION,
        network_id: fx.network,
        invite_id: InviteId::from([5u8; 16]),
        secret_hash: hash_invite_secret(&secret),
        roles: vec![],
        expires: now() + DAY,
        uses: 1,
        name: None,
    };
    edit(&mut body);
    let invite = Invite::sign(key.unwrap_or(owner.signing_key()), &body).unwrap();
    encode_invite(&InviteToken {
        invite,
        secret: menzil_proto::ByteArray::from(secret),
        relay: relay(),
    })
}

fn invalid(result: Result<Prepared, JoinError>) -> String {
    match result {
        Err(JoinError::Invalid(message)) => message,
        other => panic!("expected an Invalid refusal, got {other:?}"),
    }
}

#[test]
fn a_good_owner_signed_token_makes_a_request_whose_tag_verifies() {
    let fx = fx();
    let token = token_of(&fx, &CreateSpec::default());
    let prepared = prepare(&fx.device, &token, Some("phone"), now()).unwrap();
    assert_eq!(prepared.name, "phone");
    assert_eq!(prepared.signature, Signature::Owner);
    assert_eq!(prepared.request.name, "phone");
    assert_eq!(prepared.request.node_cert, prepared.cert);
    assert!(verify_admit_tag(
        prepared.token.secret.as_ref(),
        prepared.body.invite_id,
        &prepared.cert,
        "phone",
        &prepared.request.tag
    ));
}

#[test]
fn an_expired_invite_is_refused_before_any_network_use() {
    let fx = fx();
    let token = token_of(&fx, &CreateSpec::default());
    let message = invalid(prepare(&fx.device, &token, Some("phone"), now() + 8 * DAY));
    assert!(message.contains("expired"), "{message}");
}

#[test]
fn an_invite_with_roles_is_refused() {
    let fx = fx();
    let token = crafted(&fx, None, [3; 32], |body| {
        body.roles = vec!["admin".to_string()];
    });
    let message = invalid(prepare(&fx.device, &token, Some("phone"), now()));
    assert!(message.contains("roles"), "{message}");
    // The control: the same invite without roles is fine.
    let token = crafted(&fx, None, [3; 32], |_| {});
    assert!(prepare(&fx.device, &token, Some("phone"), now()).is_ok());
}

#[test]
fn a_token_whose_secret_does_not_match_its_invite_is_damaged() {
    let fx = fx();
    let token = crafted(&fx, None, [3; 32], |body| {
        body.secret_hash = hash_invite_secret(&[4; 32]);
    });
    let message = invalid(prepare(&fx.device, &token, Some("phone"), now()));
    assert!(message.contains("damaged"), "{message}");
}

#[test]
fn an_invite_the_owner_key_does_not_verify_may_be_a_stewards_and_goes_on() {
    let fx = fx();
    let stranger = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let token = crafted(&fx, Some(&stranger), [3; 32], |_| {});
    let prepared = prepare(&fx.device, &token, Some("phone"), now()).unwrap();
    assert_eq!(prepared.signature, Signature::NotOwner);
}

#[test]
fn a_network_id_that_is_not_a_key_is_refused() {
    let fx = fx();
    // The first y coordinate (little endian, high bytes zero) that is not on the curve.
    let bytes = (2u8..=255)
        .map(|y| {
            let mut bytes = [0u8; 32];
            bytes[0] = y;
            bytes
        })
        .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
        .expect("some small y is not a point");
    let token = crafted(&fx, None, [3; 32], |body| {
        body.network_id = NetworkId::from(bytes);
    });
    let message = invalid(prepare(&fx.device, &token, Some("phone"), now()));
    assert!(message.contains("not a key"), "{message}");
}

#[test]
fn the_name_is_the_fixed_one_or_the_given_one_and_passes_check_name() {
    let fx = fx();
    let fixed = token_of(
        &fx,
        &CreateSpec {
            name: Some("tablet".into()),
            ..CreateSpec::default()
        },
    );
    assert_eq!(
        prepare(&fx.device, &fixed, None, now()).unwrap().name,
        "tablet"
    );
    assert_eq!(
        prepare(&fx.device, &fixed, Some("tablet"), now())
            .unwrap()
            .name,
        "tablet"
    );
    let message = invalid(prepare(&fx.device, &fixed, Some("phone"), now()));
    assert!(message.contains("fixes the device name"), "{message}");

    let free = token_of(&fx, &CreateSpec::default());
    assert_eq!(
        prepare(&fx.device, &free, Some("Pixel"), now())
            .unwrap()
            .name,
        "Pixel"
    );
    let message = invalid(prepare(&fx.device, &free, Some("bad name!"), now()));
    assert!(message.contains("device name"), "{message}");
    // No name at all: the host name when it is usable, else a message asking for --name.
    match (default_name(), prepare(&fx.device, &free, None, now())) {
        (Some(host), Ok(prepared)) => assert_eq!(prepared.name, host),
        (None, Err(JoinError::Invalid(message))) => assert!(message.contains("--name")),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_device_already_in_the_network_or_without_identity_is_refused() {
    let fx = fx();
    let token = token_of(&fx, &CreateSpec::default());
    let bare = Home::new(fx._dir.path().join("bare"));
    assert!(prepare(&bare, &token, Some("phone"), now()).is_err());

    let request = crate::local::join_request(&fx.device).unwrap();
    let admitted = admit(&fx.owner, None, &request, "phone", &[], now()).unwrap();
    join_documents(&fx.device, &admitted.token, now()).unwrap();
    let message = invalid(prepare(&fx.device, &token, Some("phone"), now()));
    assert!(message.contains("already"), "{message}");
}

// ---- judging the Roster ---------------------------------------------------------------------

/// The owner of `fx` admits the device; the Roster it then holds, the owner's key and the
/// device's certificate.
fn admitted(fx: &Fx) -> (Roster, menzil_admin::OwnerKey, NodeCert) {
    let request = crate::local::join_request(&fx.device).unwrap();
    admit(&fx.owner, None, &request, "phone", &[], now()).unwrap();
    let docs = load_documents(&fx.owner, &fx.network).unwrap();
    let owner = load_owner(&fx.owner, &fx.network).unwrap();
    let cert = crate::local::load_identity(&fx.device).unwrap().1;
    (docs.roster().clone(), owner, cert)
}

fn answer(roster: Roster) -> RosterOnly {
    RosterOnly {
        roster,
        base_roster: None,
    }
}

fn resign(
    roster: &Roster,
    owner: &menzil_admin::OwnerKey,
    edit: impl FnOnce(&mut RosterBody),
) -> Roster {
    let mut body = roster.decode().unwrap();
    edit(&mut body);
    Roster::sign(owner.signing_key(), &body).unwrap()
}

fn bad_roster(result: Result<RosterOnly, JoinError>) -> String {
    match result {
        Err(JoinError::BadRoster(message)) => message,
        other => panic!("expected a refused Roster, got {other:?}"),
    }
}

#[test]
fn a_roster_that_lists_the_device_is_accepted() {
    let fx = fx();
    let (roster, _, cert) = admitted(&fx);
    assert!(judge(fx.network, &cert, answer(roster), now()).is_ok());
}

#[test]
fn a_roster_of_another_network_is_refused() {
    let fx = fx();
    let (_, _, cert) = admitted(&fx);
    // A network of somebody else that lists the device (it is the founder there).
    let other_owner = menzil_admin::OwnerKey::generate();
    let other = create_network(&other_owner, &cert, "dev", now()).unwrap();
    let message = bad_roster(judge(
        fx.network,
        &cert,
        answer(other.roster().clone()),
        now(),
    ));
    assert!(message.contains("WrongNetwork"), "{message}");
}

#[test]
fn a_roster_that_does_not_list_the_device_is_refused() {
    let fx = fx();
    // The owner alone: the device was never admitted.
    let roster = load_documents(&fx.owner, &fx.network)
        .unwrap()
        .roster()
        .clone();
    let cert = crate::local::load_identity(&fx.device).unwrap().1;
    let message = bad_roster(judge(fx.network, &cert, answer(roster), now()));
    assert!(message.contains("does not list"), "{message}");
}

#[test]
fn a_roster_that_lists_the_device_as_revoked_is_refused() {
    let fx = fx();
    let (roster, owner, cert) = admitted(&fx);
    let id = cert.decode().unwrap().node_id;
    let roster = resign(&roster, &owner, |body| {
        body.revoked.push(RevokedMember {
            node_id: id,
            since: 0,
        });
    });
    let message = bad_roster(judge(fx.network, &cert, answer(roster), now()));
    assert!(message.contains("revoked"), "{message}");
}

#[test]
fn a_roster_whose_min_serial_is_above_the_certificate_is_refused() {
    let fx = fx();
    let (roster, owner, cert) = admitted(&fx);
    let id = cert.decode().unwrap().node_id;
    let roster = resign(&roster, &owner, |body| {
        for member in &mut body.members {
            if member.node_id == id {
                member.min_serial = 2;
            }
        }
    });
    let message = bad_roster(judge(fx.network, &cert, answer(roster), now()));
    assert!(message.contains("serial"), "{message}");
}

#[test]
fn a_roster_signed_by_somebody_else_is_refused() {
    let fx = fx();
    let (roster, _, cert) = admitted(&fx);
    let impostor = menzil_admin::OwnerKey::generate();
    let forged = resign(&roster, &impostor, |_| {});
    assert!(judge(fx.network, &cert, answer(forged), now()).is_err());
}

#[test]
fn every_refusal_code_has_its_own_message() {
    let messages: Vec<String> = [
        ErrorCode::BadInvite,
        ErrorCode::BadTag,
        ErrorCode::BadCert,
        ErrorCode::Revoked,
        ErrorCode::NameTaken,
        ErrorCode::RateLimited,
    ]
    .into_iter()
    .map(|code| refusal_message(code, "phone"))
    .collect();
    for (i, a) in messages.iter().enumerate() {
        for b in &messages[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert!(refusal_message(ErrorCode::NameTaken, "phone").contains("`phone`"));
    assert!(refusal_message(ErrorCode::BadInvite, "x").contains("invite"));
    assert!(refusal_message(ErrorCode::BadTag, "x").contains("secret"));
    assert!(refusal_message(ErrorCode::BadCert, "x").contains("certificate"));
    assert!(refusal_message(ErrorCode::Revoked, "x").contains("revoked"));
    assert!(refusal_message(ErrorCode::RateLimited, "x").contains("too many"));
    // A code without a text of its own still says what it was.
    assert!(refusal_message(ErrorCode::NotMember, "x").contains("not_member"));
}

// ---- the Roster only file -------------------------------------------------------------------

#[test]
fn the_roster_only_file_is_private_whole_and_leaves_nothing_behind() {
    let fx = fx();
    let (roster, _, _) = admitted(&fx);
    write_roster_only(&fx.device, &fx.network, &answer(roster)).unwrap();
    let path = fx.device.roster_only_path(&fx.network);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let dir = fx.device.network_dir(&fx.network);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [".lock", "roster-only.bin"],
        "no temporary file is left"
    );
    assert_eq!(fx.device.roster_only_networks().unwrap(), vec![fx.network]);
}

fn load_for(fx: &Fx) -> Vec<(NetworkId, RosterOnly)> {
    let (keys, cert) = crate::local::load_identity(&fx.device).unwrap();
    let serial = cert.decode().unwrap().serial;
    load_roster_only(&fx.device, &keys.node_id(), serial, now()).unwrap()
}

#[test]
fn a_good_roster_only_file_is_loaded_and_a_bad_one_never_grants() {
    let fx = fx();
    let (roster, owner, cert) = admitted(&fx);
    let me = cert.decode().unwrap().node_id;
    write_roster_only(&fx.device, &fx.network, &answer(roster.clone())).unwrap();
    assert_eq!(load_for(&fx).len(), 1);

    let path = fx.device.roster_only_path(&fx.network);
    // Garbage.
    std::fs::write(&path, b"not cbor at all").unwrap();
    assert!(load_for(&fx).is_empty(), "a corrupt file is ignored");
    // Truncated.
    write_roster_only(&fx.device, &fx.network, &answer(roster.clone())).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    assert!(load_for(&fx).is_empty());
    // One byte of the signed body changed: the signature no longer verifies.
    let mut tampered = bytes.clone();
    let at = tampered.len() / 3;
    tampered[at] ^= 0x01;
    std::fs::write(&path, &tampered).unwrap();
    assert!(load_for(&fx).is_empty(), "a tampered file is ignored");
    // A Roster of another network under this network's directory.
    let other_owner = menzil_admin::OwnerKey::generate();
    let other = create_network(&other_owner, &cert, "dev", now()).unwrap();
    write_roster_only(&fx.device, &fx.network, &answer(other.roster().clone())).unwrap();
    assert!(
        load_for(&fx).is_empty(),
        "a stale file of another network is ignored"
    );
    // A Roster that no longer lists this device in good standing.
    for edit in [
        Box::new(move |b: &mut RosterBody| {
            b.revoked.push(RevokedMember {
                node_id: me,
                since: 0,
            })
        }) as Box<dyn FnOnce(&mut RosterBody)>,
        Box::new(move |b: &mut RosterBody| b.members.retain(|m| m.node_id != me)),
        Box::new(move |b: &mut RosterBody| {
            for m in &mut b.members {
                if m.node_id == me {
                    m.min_serial = 9;
                }
            }
        }),
    ] {
        let changed = resign(&roster, &owner, edit);
        write_roster_only(&fx.device, &fx.network, &answer(changed)).unwrap();
        assert!(load_for(&fx).is_empty());
    }
    // An expired Roster.
    let expired = resign(&roster, &owner, |b| {
        b.issued = now() - 20 * DAY;
        b.expires = now() - 6 * DAY;
    });
    write_roster_only(&fx.device, &fx.network, &answer(expired)).unwrap();
    assert!(load_for(&fx).is_empty());
}

#[test]
fn documents_beside_the_file_win_and_the_file_is_no_network() {
    let fx = fx();
    let (roster, _, _) = admitted(&fx);
    write_roster_only(&fx.device, &fx.network, &answer(roster)).unwrap();
    let docs = load_documents(&fx.owner, &fx.network).unwrap();
    crate::local::save_documents(&fx.device, &docs).unwrap();
    assert!(
        !fx.device.roster_only_path(&fx.network).exists(),
        "writing the documents removes the Roster only file"
    );
    // A leftover next to documents.bin is not a Roster only network.
    std::fs::write(fx.device.roster_only_path(&fx.network), b"x").unwrap();
    assert!(fx.device.roster_only_networks().unwrap().is_empty());
}

#[test]
fn the_keeper_writes_the_first_documents_of_a_roster_only_network_and_removes_the_file() {
    let fx = fx();
    let (roster, _, _) = admitted(&fx);
    write_roster_only(&fx.device, &fx.network, &answer(roster)).unwrap();
    let docs = load_documents(&fx.owner, &fx.network).unwrap();
    // The node's keeper calls this with `create = false`: without the Roster only file it would
    // not bring a network into being.
    let kept = crate::local::keep_documents(&fx.device, &docs, now(), false).unwrap();
    assert!(kept.is_some());
    assert!(fx.device.documents_path(&fx.network).is_file());
    assert!(!fx.device.roster_only_path(&fx.network).exists());
    // Without the file the same call keeps nothing.
    let other = Home::new(fx._dir.path().join("other"));
    init(&other, now()).unwrap();
    assert!(
        crate::local::keep_documents(&other, &docs, now(), false)
            .unwrap()
            .is_none()
    );
}

#[test]
fn the_node_starts_from_a_roster_only_file_and_a_corrupt_one_is_no_network() {
    let fx = fx();
    let (roster, _, _) = admitted(&fx);
    write_roster_only(&fx.device, &fx.network, &answer(roster)).unwrap();
    let (policies, rosters, networks) = crate::node_cmd::load_stores(&fx.device).unwrap();
    assert_eq!(networks, vec![fx.network]);
    assert!(rosters.seq(&fx.network).is_some());
    assert!(
        policies.seq(&fx.network).is_none(),
        "the Policy has not come"
    );

    std::fs::write(fx.device.roster_only_path(&fx.network), b"junk").unwrap();
    let Err(error) = crate::node_cmd::load_stores(&fx.device) else {
        panic!("a corrupt Roster only file is no network");
    };
    assert!(format!("{error:#}").contains("no network"), "{error:#}");
}

#[test]
fn status_says_admitted_waiting_for_the_policy() {
    let fx = fx();
    let (roster, _, _) = admitted(&fx);
    write_roster_only(&fx.device, &fx.network, &answer(roster)).unwrap();
    let text = crate::local::status(&fx.device).unwrap().render(now());
    assert!(text.contains("admitted, waiting for the Policy"), "{text}");
    assert!(text.contains(&fx.network.to_string()), "{text}");
    assert!(!text.contains("no networks"), "{text}");
}

// ---- config.toml ------------------------------------------------------------------------------

#[test]
fn relay_goes_into_a_config_without_one_and_into_none_that_has_one() {
    let fx = fx();
    let home = &fx.device;
    // No file at all.
    assert_eq!(ensure_relay(home, &relay()).unwrap(), RelayConfig::Written);
    let text = std::fs::read_to_string(home.config_path()).unwrap();
    assert_eq!(
        Config::parse(&text).unwrap().relay.as_deref(),
        Some(relay().as_str())
    );
    assert_eq!(
        std::fs::metadata(home.config_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    // The same relay again: nothing to do.
    assert_eq!(ensure_relay(home, &relay()).unwrap(), RelayConfig::Already);
    // Another relay: the file is not touched.
    let other = format!(
        "menzil://other.example.org:443/_menzil/v1?id={}",
        "cd".repeat(32)
    );
    let before = std::fs::read_to_string(home.config_path()).unwrap();
    assert_eq!(
        ensure_relay(home, &other).unwrap(),
        RelayConfig::Differs {
            configured: relay()
        }
    );
    assert_eq!(std::fs::read_to_string(home.config_path()).unwrap(), before);
}

#[test]
fn the_relay_line_goes_before_the_tables_of_an_existing_config() {
    let fx = fx();
    std::fs::create_dir_all(fx.device.root()).unwrap();
    std::fs::write(
        fx.device.config_path(),
        "# mine\nproxy = \"direct\"\n\n[services]\nssh = \"127.0.0.1:22\"\n",
    )
    .unwrap();
    assert_eq!(
        ensure_relay(&fx.device, &relay()).unwrap(),
        RelayConfig::Written
    );
    let text = std::fs::read_to_string(fx.device.config_path()).unwrap();
    let config = Config::parse(&text).unwrap();
    assert_eq!(config.relay.as_deref(), Some(relay().as_str()));
    assert!(text.contains("# mine") && text.contains("ssh = "), "{text}");
    assert_eq!(config.proxy.as_deref(), Some("direct"));
}

#[test]
fn a_config_that_does_not_parse_is_not_written_over() {
    let fx = fx();
    std::fs::create_dir_all(fx.device.root()).unwrap();
    std::fs::write(fx.device.config_path(), "relay = [").unwrap();
    assert!(ensure_relay(&fx.device, &relay()).is_err());
    assert_eq!(
        std::fs::read_to_string(fx.device.config_path()).unwrap(),
        "relay = ["
    );
}

// ---- refusals before any network use ----------------------------------------------------------

#[tokio::test]
async fn a_node_running_on_the_home_refuses_the_join_and_nothing_is_written() {
    let fx = fx();
    let token = token_of(&fx, &CreateSpec::default());
    let _node = fx.device.lock_node().unwrap();
    let options = JoinOptions {
        name: Some("phone".into()),
        ..JoinOptions::default()
    };
    let error = redeem(&fx.device, &token, &options, &mut |_| {})
        .await
        .unwrap_err();
    assert!(matches!(error, JoinError::Invalid(_)), "{error:?}");
    assert!(error.to_string().contains("stop the node"), "{error}");
    assert!(fx.device.roster_only_networks().unwrap().is_empty());
    assert!(!fx.device.config_path().exists());
    let _ = NodeId::from([0u8; 32]);
}

#[tokio::test]
async fn an_unusable_token_never_reaches_the_network() {
    let fx = fx();
    let options = JoinOptions {
        name: Some("phone".into()),
        ..JoinOptions::default()
    };
    for token in ["menzil1-invite:%%%", "menzil1-docs:abc", "", "nonsense"] {
        let error = redeem(&fx.device, token, &options, &mut |_| {})
            .await
            .unwrap_err();
        assert!(matches!(error, JoinError::Invalid(_)), "{token}: {error:?}");
    }
}
