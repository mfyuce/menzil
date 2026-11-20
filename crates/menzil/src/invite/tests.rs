#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use menzil_admin::NodeKeys;
use menzil_node::admit_handler::{BatchOutcome, process_batch};
use menzil_proto::{AdmitRequestBody, ErrorCode, compute_admit_tag};

use super::*;
use crate::local::{admit, init, join, network_create, steward_add, steward_request};
use crate::token::decode_invite;

const NOW: u64 = 1_800_000_000;

fn relay() -> String {
    format!(
        "menzil://relay.example.org:443/_menzil/v1?id={}",
        "ab".repeat(32)
    )
}

struct Fixture {
    _dir: tempfile::TempDir,
    owner: Home,
    network: NetworkId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let owner = Home::new(dir.path().join("owner"));
    init(&owner, NOW).unwrap();
    let network = network_create(&owner, "owner", NOW).unwrap();
    Fixture {
        _dir: dir,
        owner,
        network,
    }
}

/// A steward device of the fixture's network, listed for `days` with `may`.
fn steward(fx: &Fixture, days: u64, may: &[&str]) -> Home {
    let label = format!("steward{days}x{}", may.join("-"));
    let home = Home::new(fx._dir.path().join(&label));
    let join_request = init(&home, NOW).unwrap().join_request;
    let admitted = admit(&fx.owner, None, &join_request, &label, &[], NOW).unwrap();
    join(&home, &admitted.token, NOW).unwrap();
    let asked = steward_request(&home, None).unwrap();
    let may: Vec<String> = may.iter().map(|s| s.to_string()).collect();
    let listed = steward_add(&fx.owner, None, &asked.token, &may, days, NOW).unwrap();
    join(&home, &listed.issued.token, NOW).unwrap();
    home
}

struct Device {
    cert: NodeCert,
    id: NodeId,
}

fn device() -> Device {
    let keys = NodeKeys::generate();
    let cert = keys.issue_cert(1, NOW - 10, NOW + 100 * DAY).unwrap();
    Device {
        id: keys.node_id(),
        cert,
    }
}

/// The request a device makes with the token.
fn request(token: &str, dev: &Device, name: &str) -> AdmitRequestBody {
    let parsed = decode_invite(token).unwrap();
    let id = parsed.invite.decode().unwrap().invite_id;
    AdmitRequestBody {
        invite: parsed.invite,
        node_cert: dev.cert.clone(),
        name: name.to_string(),
        tag: compute_admit_tag(&parsed.secret.0, id, &dev.cert, name),
    }
}

fn make(home: &Home, spec: &CreateSpec) -> Created {
    create(home, spec, &relay(), NOW).unwrap()
}

fn issuer(home: &Home) -> CliIssuer {
    CliIssuer::new(home.clone(), None)
}

fn run(home: &Home, network: &NetworkId, requests: Vec<AdmitRequestBody>) -> BatchOutcome {
    process_batch(&issuer(home), network, requests, NOW)
}

#[test]
fn a_token_round_trips_and_carries_what_the_device_needs() {
    let fx = fixture();
    let made = make(&fx.owner, &CreateSpec::default());
    assert!(made.token.starts_with("menzil1-invite:"));
    assert!(made.warnings.is_empty());
    assert_eq!(made.uses, 1);
    assert_eq!(made.expires, NOW + 7 * DAY);
    let parsed = decode_invite(&made.token).unwrap();
    assert_eq!(parsed.relay, relay());
    let body = parsed.invite.decode().unwrap();
    assert_eq!(body.network_id, fx.network);
    assert_eq!(body.invite_id, made.invite_id);
    assert_eq!(body.expires, made.expires);
    assert!(body.roles.is_empty() && body.name.is_none());
    assert_eq!(body.secret_hash, hash_invite_secret(&parsed.secret.0));
    // Signed by the owner key, which is the network id.
    let owner_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(fx.network)).unwrap();
    parsed.invite.verify(&owner_key).unwrap();
    // The text form survives whitespace around it and refuses other kinds.
    assert_eq!(
        decode_invite(&format!("  {}\n", made.token)).unwrap(),
        parsed
    );
    assert!(decode_invite("menzil1-join:abcd").is_err());
    assert!(decode_invite("menzil1-invite:%%%").is_err());
    assert!(decode_invite("menzil1-invite:AAAA").is_err());
}

#[test]
fn two_invites_differ_in_id_and_secret() {
    let fx = fixture();
    let (a, b) = (
        make(&fx.owner, &CreateSpec::default()),
        make(&fx.owner, &CreateSpec::default()),
    );
    assert_ne!(a.invite_id, b.invite_id);
    let (ta, tb) = (
        decode_invite(&a.token).unwrap(),
        decode_invite(&b.token).unwrap(),
    );
    assert_ne!(ta.secret.0, tb.secret.0);
}

#[cfg(unix)]
#[test]
fn the_book_is_private_whole_and_leaves_nothing_behind() {
    let fx = fixture();
    make(&fx.owner, &CreateSpec::default());
    let path = fx.owner.invites_path(&fx.network);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the book holds secrets");
    make(&fx.owner, &CreateSpec::default());
    let book = load_book(&fx.owner, &fx.network).unwrap();
    assert_eq!(book.invites.len(), 2);
    // Written atomically: no temporary file is left in the network directory.
    let mut names: Vec<String> = std::fs::read_dir(fx.owner.network_dir(&fx.network))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, [".lock", "documents.bin", "invites.cbor"]);
    // A damaged book is an error, never a fresh one that forgets the counters.
    std::fs::write(&path, b"not cbor").unwrap();
    assert!(load_book(&fx.owner, &fx.network).is_err());
    assert!(create(&fx.owner, &CreateSpec::default(), &relay(), NOW).is_err());
}

#[test]
fn the_limits_of_create_are_enforced() {
    let fx = fixture();
    let spec = |uses, life| CreateSpec {
        uses,
        life_secs: life,
        ..CreateSpec::default()
    };
    assert!(create(&fx.owner, &spec(0, DAY), &relay(), NOW).is_err());
    assert!(create(&fx.owner, &spec(1, 0), &relay(), NOW).is_err());
    assert!(create(&fx.owner, &spec(1, 30 * DAY + 1), &relay(), NOW).is_err());
    let thirty = create(&fx.owner, &spec(255, 30 * DAY), &relay(), NOW).unwrap();
    assert_eq!(thirty.expires, NOW + 30 * DAY);
    let bad_name = CreateSpec {
        name: Some("not a name".to_string()),
        ..CreateSpec::default()
    };
    assert!(create(&fx.owner, &bad_name, &relay(), NOW).is_err());
    assert!(create(&fx.owner, &CreateSpec::default(), "not a relay", NOW).is_err());
    // No relay in config.toml: the token could not say where to redeem.
    let error = execute(&fx.owner, &InviteOp::Create(CreateSpec::default()), NOW).unwrap_err();
    assert!(format!("{error:#}").contains("no relay is configured"));
    // A fixed name travels in the invite.
    let named = CreateSpec {
        name: Some("kiosk".to_string()),
        ..CreateSpec::default()
    };
    let made = make(&fx.owner, &named);
    let body = decode_invite(&made.token).unwrap().invite.decode().unwrap();
    assert_eq!(body.name.as_deref(), Some("kiosk"));
}

/// Round R-B N2: a fixed name with more than one use would refuse every later device.
#[test]
fn a_fixed_name_with_more_than_one_use_is_refused() {
    let fx = fixture();
    let spec = |uses| CreateSpec {
        uses,
        name: Some("kiosk".to_string()),
        ..CreateSpec::default()
    };
    let error = create(&fx.owner, &spec(2), &relay(), NOW).unwrap_err();
    assert!(
        format!("{error:#}").contains("one device only"),
        "{error:#}"
    );
    assert!(create(&fx.owner, &spec(1), &relay(), NOW).is_ok());
    // No name, several uses: fine.
    let many = CreateSpec {
        uses: 3,
        ..CreateSpec::default()
    };
    assert!(create(&fx.owner, &many, &relay(), NOW).is_ok());
}

/// Round R-B L1: a member presenting another invite spends no use of it, does not void the
/// batch, and is answered with the Roster it has.
#[test]
fn a_member_with_a_second_invite_spends_nothing_and_does_not_poison_the_batch() {
    let fx = fixture();
    let a = make(&fx.owner, &CreateSpec::default());
    let b = make(
        &fx.owner,
        &CreateSpec {
            uses: 2,
            ..CreateSpec::default()
        },
    );
    let member = device();
    let out = run(
        &fx.owner,
        &fx.network,
        vec![request(&a.token, &member, "member")],
    );
    assert_eq!(out.admitted, 1);
    let fresh = device();
    let out = run(
        &fx.owner,
        &fx.network,
        vec![
            request(&b.token, &member, "member"),
            request(&b.token, &fresh, "fresh"),
        ],
    );
    assert_eq!(out.admitted, 1, "{out:?}");
    assert!(out.refused.is_empty(), "{out:?}");
    assert!(out.resend, "{out:?}");
    let docs = local::load_documents(&fx.owner, &fx.network).unwrap();
    assert!(docs.is_member(&fresh.id));
    let book = load_book(&fx.owner, &fx.network).unwrap();
    let redeemed = &book.get(&b.invite_id).unwrap().redeemed;
    assert_eq!(
        redeemed.len(),
        1,
        "the member spent a use of the second invite"
    );
    assert!(!redeemed.contains(&member.id));
}

#[test]
fn a_device_that_is_no_issuer_cannot_create() {
    let fx = fixture();
    // A plain member: documents, no key.
    let home = Home::new(fx._dir.path().join("member"));
    let jr = init(&home, NOW).unwrap().join_request;
    let admitted = admit(&fx.owner, None, &jr, "member", &[], NOW).unwrap();
    join(&home, &admitted.token, NOW).unwrap();
    assert!(create(&home, &CreateSpec::default(), &relay(), NOW).is_err());
    assert!(!CliIssuer::is_needed(&home));
    assert!(CliIssuer::is_needed(&fx.owner));
    // A steward without `admit` cannot either.
    let renew_only = steward(&fx, 30, &["renew"]);
    let error = create(&renew_only, &CreateSpec::default(), &relay(), NOW).unwrap_err();
    assert!(format!("{error:#}").contains("admit"), "{error:#}");
}

#[test]
fn a_steward_invite_is_signed_by_the_steward_and_never_outlives_it() {
    let fx = fixture();
    let home = steward(&fx, 3, &["admit", "renew"]);
    let made = make(&home, &CreateSpec::default());
    // Seven days asked, the delegation ends in three: cut, and said so.
    assert_eq!(made.expires, NOW + 3 * DAY);
    assert_eq!(made.warnings.len(), 1, "{:?}", made.warnings);
    assert!(made.warnings[0].contains("steward"));
    let parsed = decode_invite(&made.token).unwrap();
    let steward_key = local::load_steward(&home, &fx.network).unwrap();
    parsed
        .invite
        .verify(&steward_key.signing_key().verifying_key())
        .unwrap();
    let owner_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(fx.network)).unwrap();
    assert!(parsed.invite.verify(&owner_key).is_err());
    // A shorter invite inside the delegation has no warning.
    let short = create(
        &home,
        &CreateSpec {
            life_secs: DAY,
            ..CreateSpec::default()
        },
        &relay(),
        NOW,
    )
    .unwrap();
    assert!(short.warnings.is_empty());
    // After the delegation, nothing.
    assert!(create(&home, &CreateSpec::default(), &relay(), NOW + 3 * DAY).is_err());
}

#[test]
fn list_and_revoke_work_on_the_book() {
    let fx = fixture();
    let a = make(&fx.owner, &CreateSpec::default());
    let b = make(
        &fx.owner,
        &CreateSpec {
            uses: 3,
            ..CreateSpec::default()
        },
    );
    let (network, listed) = list(&fx.owner, None).unwrap();
    assert_eq!(network, fx.network);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, b.invite_id, "newest first");
    assert_eq!((listed[0].used, listed[0].total), (0, 3));
    // Redeemed by one device: the list shows it by name.
    let dev = device();
    let out = run(
        &fx.owner,
        &fx.network,
        vec![request(&b.token, &dev, "desk")],
    );
    assert_eq!(out.admitted, 1);
    let (_, listed) = list(&fx.owner, None).unwrap();
    assert_eq!(listed[0].used, 1);
    assert_eq!(listed[0].names, ["desk"]);
    // Revoke by prefix; short or unknown prefixes are refused.
    assert!(revoke(&fx.owner, None, "ab", NOW).is_err());
    assert!(revoke(&fx.owner, None, "zzzz", NOW).is_err());
    let prefix = &a.invite_id.to_hex()[..8];
    assert_eq!(revoke(&fx.owner, None, prefix, NOW).unwrap(), a.invite_id);
    let (_, listed) = list(&fx.owner, None).unwrap();
    assert!(listed.iter().find(|l| l.id == a.invite_id).unwrap().revoked);
    // A revoked invite admits nobody.
    let late = device();
    let out = run(
        &fx.owner,
        &fx.network,
        vec![request(&a.token, &late, "late")],
    );
    assert_eq!(out.admitted, 0);
    assert_eq!(out.refused[0].code, ErrorCode::BadInvite);
    // The rendering says it all in text.
    let lines = execute(&fx.owner, &InviteOp::List { network: None }, NOW).unwrap();
    let text = render(&InviteOp::List { network: None }, &lines, NOW);
    assert!(
        text.contains("1/3") && text.contains("desk") && text.contains("yes"),
        "{text}"
    );
}

#[test]
fn entries_are_dropped_thirty_days_after_they_expire() {
    let fx = fixture();
    let made = make(&fx.owner, &CreateSpec::default());
    let mut book = load_book(&fx.owner, &fx.network).unwrap();
    book.prune(made.expires + KEEP_AFTER_EXPIRY_SECS - 1);
    assert_eq!(book.invites.len(), 1);
    book.prune(made.expires + KEEP_AFTER_EXPIRY_SECS);
    assert!(book.invites.is_empty());
}

#[test]
fn a_request_admits_the_device_in_the_saved_documents_and_counts_once_after_a_reload() {
    let fx = fixture();
    let made = make(&fx.owner, &CreateSpec::default());
    let dev = device();
    let req = request(&made.token, &dev, "phone");
    let seq_before = local::load_documents(&fx.owner, &fx.network).unwrap().seq();
    let out = run(&fx.owner, &fx.network, vec![req.clone()]);
    assert_eq!(out.admitted, 1);
    let docs = local::load_documents(&fx.owner, &fx.network).unwrap();
    assert!(docs.is_member(&dev.id));
    assert_eq!(docs.seq(), seq_before + 1);
    assert!(docs.policy_body().members.iter().any(|m| m.name == "phone"));
    assert_eq!(
        load_book(&fx.owner, &fx.network).unwrap().invites[0].redeemed,
        [dev.id]
    );
    // Fed again as from a second relay, through a fresh issuer that reads the book from disk:
    // success again, nothing issued, nothing counted.
    let again = run(&fx.owner, &fx.network, vec![req]);
    assert!(again.resend);
    assert_eq!((again.admitted, again.refused.len()), (0, 0));
    assert_eq!(
        local::load_documents(&fx.owner, &fx.network).unwrap().seq(),
        seq_before + 1
    );
    assert_eq!(
        load_book(&fx.owner, &fx.network).unwrap().invites[0]
            .redeemed
            .len(),
        1
    );
}

#[test]
fn uses_is_exact_with_the_real_book_and_a_batch_is_one_pair() {
    let fx = fixture();
    let made = make(
        &fx.owner,
        &CreateSpec {
            uses: 2,
            ..CreateSpec::default()
        },
    );
    let devices: Vec<Device> = (0..5).map(|_| device()).collect();
    let seq_before = local::load_documents(&fx.owner, &fx.network).unwrap().seq();
    let requests: Vec<_> = devices
        .iter()
        .enumerate()
        .map(|(i, d)| request(&made.token, d, &format!("d{i}")))
        .collect();
    let out = run(&fx.owner, &fx.network, requests);
    assert_eq!(out.admitted, 2);
    assert_eq!(out.refused.len(), 3);
    assert!(out.refused.iter().all(|r| r.code == ErrorCode::BadInvite));
    let docs = local::load_documents(&fx.owner, &fx.network).unwrap();
    assert_eq!(docs.seq(), seq_before + 1, "two devices, one pair");
    assert!(docs.is_member(&devices[0].id) && docs.is_member(&devices[1].id));
    assert!(!docs.is_member(&devices[2].id));
}

#[test]
fn a_steward_issuer_admits_with_documents_the_network_accepts() {
    let fx = fixture();
    let home = steward(&fx, 30, &["admit", "renew"]);
    let made = make(&home, &CreateSpec::default());
    let dev = device();
    let out = run(
        &home,
        &fx.network,
        vec![request(&made.token, &dev, "kiosk")],
    );
    assert_eq!(out.admitted, 1, "{out:?}");
    // `load_documents` judges them with the acceptance predicate: signed by the listed steward.
    let docs = local::load_documents(&home, &fx.network).unwrap();
    assert!(docs.is_member(&dev.id));
    // An invite the owner signed is not this device's (another issuer answers).
    let owners = make(&fx.owner, &CreateSpec::default());
    let other = device();
    let out = run(
        &home,
        &fx.network,
        vec![request(&owners.token, &other, "x")],
    );
    assert_eq!(out, BatchOutcome::default());
}

#[test]
fn a_fault_after_the_book_write_costs_no_use_with_the_real_files() {
    let fx = fixture();
    let made = make(&fx.owner, &CreateSpec::default());
    let dev = device();
    let req = request(&made.token, &dev, "phone");
    // The book is written and the documents are not (a crash in between): done by hand with the
    // transaction the handler uses.
    {
        let mut txn = issuer(&fx.owner).begin(&fx.network, NOW).ok().unwrap();
        txn.record_redeemed(&[(made.invite_id, vec![dev.id])])
            .unwrap();
    }
    let docs = local::load_documents(&fx.owner, &fx.network).unwrap();
    assert!(!docs.is_member(&dev.id));
    // The retry admits the device and does not count it again.
    let out = run(&fx.owner, &fx.network, vec![req]);
    assert_eq!(out.admitted, 1);
    assert_eq!(
        load_book(&fx.owner, &fx.network).unwrap().invites[0]
            .redeemed
            .len(),
        1
    );
    // And the single use is gone for the next device.
    let next = device();
    let out = run(
        &fx.owner,
        &fx.network,
        vec![request(&made.token, &next, "next")],
    );
    assert_eq!(out.refused[0].code, ErrorCode::BadInvite);
}

#[test]
fn a_dropped_member_in_the_book_is_admitted_again() {
    // A pair that does not list the device though the book says it redeemed (an owner fold):
    // the book is edited here to say so.
    let fx = fixture();
    let made = make(&fx.owner, &CreateSpec::default());
    let dev = device();
    let mut book = load_book(&fx.owner, &fx.network).unwrap();
    book.invites[0].redeemed.push(dev.id);
    let _lock = fx.owner.lock_network(&fx.network).unwrap();
    save_book(&fx.owner, &fx.network, &mut book, NOW).unwrap();
    drop(_lock);
    let out = run(
        &fx.owner,
        &fx.network,
        vec![request(&made.token, &dev, "back")],
    );
    assert_eq!(out.admitted, 1);
    assert!(
        local::load_documents(&fx.owner, &fx.network)
            .unwrap()
            .is_member(&dev.id)
    );
}

#[test]
fn the_listen_proof_is_made_for_an_issuer_and_bound_to_the_session() {
    let fx = fixture();
    let relay_id = NodeId::from([1u8; 32]);
    let session = NodeId::from([2u8; 32]);
    let ts = Tai64N::from([3u8; 12]);
    let body = issuer(&fx.owner)
        .listen_proof(&fx.network, relay_id, session, ts, NOW)
        .expect("the owner may issue");
    assert_eq!(body.network_id, fx.network);
    assert_eq!(body.signer.0, <[u8; 32]>::from(fx.network));
    body.verify(relay_id, session, ts).unwrap();
    // Useless on another relay, another session or another HELLO.
    assert!(body.verify(NodeId::from([9u8; 32]), session, ts).is_err());
    assert!(body.verify(relay_id, NodeId::from([9u8; 32]), ts).is_err());
    assert!(
        body.verify(relay_id, session, Tai64N::from([9u8; 12]))
            .is_err()
    );
    // A steward with `admit` proves with its own key; one without, or past `not_after`, does not.
    let admit_steward = steward(&fx, 30, &["admit", "renew"]);
    let proof = issuer(&admit_steward)
        .listen_proof(&fx.network, relay_id, session, ts, NOW)
        .expect("a steward with admit may");
    let key = local::load_steward(&admit_steward, &fx.network).unwrap();
    assert_eq!(proof.signer.0, <[u8; 32]>::from(key.public()));
    assert!(
        issuer(&admit_steward)
            .listen_proof(&fx.network, relay_id, session, ts, NOW + 31 * DAY)
            .is_none()
    );
    let renew_only = steward(&fx, 30, &["renew"]);
    assert!(
        issuer(&renew_only)
            .listen_proof(&fx.network, relay_id, session, ts, NOW)
            .is_none()
    );
}

#[test]
fn the_request_lines_round_trip_and_are_read_strictly() {
    let ops = [
        InviteOp::Create(CreateSpec {
            network: Some("ab".repeat(32)),
            uses: 5,
            life_secs: 3600,
            name: Some("kiosk".to_string()),
        }),
        InviteOp::Create(CreateSpec::default()),
        InviteOp::List { network: None },
        InviteOp::Revoke {
            network: None,
            id: "abcd1234".to_string(),
        },
    ];
    for op in ops {
        let line = op.to_request_line();
        assert_eq!(InviteOp::parse_request_line(&line).unwrap(), op, "{line}");
    }
    for bad in [
        "invite-create",
        "invite-create network=- uses=1 expires=5",
        "invite-create network=- uses=x expires=5 name=-",
        "invite-create uses=1 network=- expires=5 name=-",
        "invite-create network=- uses=1 expires=5 name=- extra=1",
        "invite-list",
        "invite-list network=",
        "invite-revoke network=- id=a b",
        "invite-delete network=-",
    ] {
        assert!(InviteOp::parse_request_line(bad).is_err(), "{bad}");
    }
}

#[test]
fn expires_is_seconds_or_a_number_with_a_unit() {
    assert_eq!(parse_life("90"), Ok(90));
    assert_eq!(parse_life("30s"), Ok(30));
    assert_eq!(parse_life("10m"), Ok(600));
    assert_eq!(parse_life("12h"), Ok(12 * 3600));
    assert_eq!(parse_life("7d"), Ok(7 * DAY));
    assert_eq!(parse_life("30d"), Ok(30 * DAY));
    for bad in [
        "",
        "0",
        "0d",
        "31d",
        "d",
        "-1",
        "1w",
        "1.5d",
        "99999999999999999999d",
    ] {
        assert!(parse_life(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn creating_through_execute_prints_the_token_and_what_to_know() {
    let fx = fixture();
    std::fs::write(fx.owner.config_path(), format!("relay = \"{}\"\n", relay())).unwrap();
    let op = InviteOp::Create(CreateSpec::default());
    let lines = execute(&fx.owner, &op, NOW).unwrap();
    let token = lines.iter().find_map(|l| l.strip_prefix("token ")).unwrap();
    assert_eq!(decode_invite(token).unwrap().relay, relay());
    let text = render(&op, &lines, NOW);
    assert!(
        text.contains(token) && text.contains("bearer secret"),
        "{text}"
    );
    assert!(
        !text.contains("not built"),
        "the device side exists: {text}"
    );
    assert!(text.contains("menzil join <token>"), "{text}");
    // Every line fits the agent's answer limit.
    assert!(lines.iter().all(|l| l.chars().count() < 1200));
    // Revoke through the same path.
    let id = lines
        .iter()
        .find_map(|l| l.strip_prefix("invite_id "))
        .unwrap();
    let revoked = execute(
        &fx.owner,
        &InviteOp::Revoke {
            network: None,
            id: id[..8].to_string(),
        },
        NOW,
    )
    .unwrap();
    assert_eq!(revoked, [format!("revoked {id}")]);
}

#[test]
fn the_awaiting_seed_is_the_redeemed_devices_until_expiry_plus_the_longest_roster_life() {
    let fx = fixture();
    let made = make(&fx.owner, &CreateSpec::default());
    let dev = device();
    let out = run(
        &fx.owner,
        &fx.network,
        vec![request(&made.token, &dev, "d0")],
    );
    assert_eq!(out.admitted, 1);
    let deadline = made.expires + DOC_MAX_LIFETIME;
    // A new process reads the same book: the seed is found again.
    assert_eq!(
        awaiting_from_book(&fx.owner, &fx.network, NOW),
        vec![(dev.id, deadline)]
    );
    assert_eq!(
        awaiting_from_book(&fx.owner, &fx.network, deadline - 1),
        vec![(dev.id, deadline)]
    );
    assert!(awaiting_from_book(&fx.owner, &fx.network, deadline).is_empty());
}

#[test]
fn a_revoked_invite_still_seeds_the_devices_it_admitted_and_an_unused_one_seeds_nothing() {
    let fx = fixture();
    let unused = make(&fx.owner, &CreateSpec::default());
    assert!(awaiting_from_book(&fx.owner, &fx.network, NOW).is_empty());
    let dev = device();
    let used = make(&fx.owner, &CreateSpec::default());
    run(
        &fx.owner,
        &fx.network,
        vec![request(&used.token, &dev, "d0")],
    );
    let _ = unused;
    revoke(&fx.owner, None, &hex_prefix(&used.token), NOW).unwrap();
    let seed = awaiting_from_book(&fx.owner, &fx.network, NOW);
    assert_eq!(seed.len(), 1);
    assert_eq!(seed[0].0, dev.id);
}

fn hex_prefix(token: &str) -> String {
    let id = decode_invite(token)
        .unwrap()
        .invite
        .decode()
        .unwrap()
        .invite_id;
    id.to_hex()
}

#[test]
fn a_home_without_a_book_seeds_nothing() {
    let fx = fixture();
    assert!(awaiting_from_book(&fx.owner, &fx.network, NOW).is_empty());
}
