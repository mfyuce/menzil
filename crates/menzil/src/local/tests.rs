use menzil_node::{PolicyStore, RosterStore};
use menzil_proto::{Policy, Roster};

use super::*;
use crate::token::{DOCS_PREFIX, encode_documents};

const NOW: u64 = 1_800_000_000;

fn device() -> (tempfile::TempDir, Home) {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("menzil"));
    (dir, home)
}

fn service(s: &str) -> ServiceId {
    s.parse().unwrap()
}

/// An owner device with a network, and a second device with an identity.
struct Two {
    _dirs: (tempfile::TempDir, tempfile::TempDir),
    owner: Home,
    member: Home,
    network_id: NetworkId,
    join_request: String,
}

fn two_devices() -> Two {
    let (owner_dir, owner) = device();
    let (member_dir, member) = device();
    init(&owner, NOW).unwrap();
    let network_id = network_create(&owner, "laptop", NOW).unwrap();
    let join_request = init(&member, NOW).unwrap().join_request;
    Two {
        _dirs: (owner_dir, member_dir),
        owner,
        member,
        network_id,
        join_request,
    }
}

#[test]
fn init_makes_an_identity_once() {
    let (_dir, home) = device();
    let first = init(&home, NOW).unwrap();
    let (keys, cert) = load_identity(&home).unwrap();
    assert_eq!(keys.node_id(), first.node_id);
    assert_eq!(decode_join_request(&first.join_request).unwrap(), cert);
    assert_eq!(join_request(&home).unwrap(), first.join_request);

    // The certificate is valid from just before now to a bit over a year after.
    let body = cert.decode().unwrap();
    assert_eq!(body.serial, 1);
    assert!(body.is_valid_at(NOW) && body.is_valid_at(NOW + 399 * DAY));
    assert!(!body.is_valid_at(NOW + 401 * DAY));

    // A second init changes nothing.
    let key_before = fs::read(home.identity_key_path()).unwrap();
    let error = init(&home, NOW + 1).unwrap_err().to_string();
    assert!(error.contains("already has an identity"), "{error}");
    assert_eq!(fs::read(home.identity_key_path()).unwrap(), key_before);
    assert_eq!(load_identity(&home).unwrap().0.node_id(), first.node_id);
}

#[cfg(unix)]
#[test]
fn secrets_are_private_and_documents_are_not() {
    use std::os::unix::fs::PermissionsExt;
    let two = two_devices();
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&two.owner.identity_key_path()), 0o600);
    assert_eq!(mode(&two.owner.owner_key_path(&two.network_id)), 0o600);
    assert_eq!(
        mode(&two.owner.documents_path(&two.network_id)) & 0o077,
        0o044 & 0o077
    );
}

#[test]
fn an_identity_whose_files_do_not_belong_together_is_refused() {
    let (_a, one) = device();
    let (_b, other) = device();
    init(&one, NOW).unwrap();
    init(&other, NOW).unwrap();
    fs::copy(other.identity_cert_path(), one.identity_cert_path()).unwrap();
    let error = format!("{:#}", load_identity(&one).unwrap_err());
    assert!(error.contains("do not belong together"), "{error}");
    // And with no identity at all the message says what to do.
    let (_c, none) = device();
    assert!(format!("{:#}", load_identity(&none).unwrap_err()).contains("menzil init"));
}

#[test]
fn a_member_is_admitted_granted_and_updated_by_pasted_tokens() {
    let two = two_devices();

    // Admit: the owner learns the member's node id from its join request.
    let admitted = admit(
        &two.owner,
        None,
        &two.join_request,
        "phone",
        &["family".to_string()],
        NOW + 10,
    )
    .unwrap();
    assert_eq!((admitted.seq, admitted.network_id), (2, two.network_id));
    let phone = admitted.member.unwrap();
    assert_eq!(phone, load_identity(&two.member).unwrap().0.node_id());

    // The member joins with the token.
    assert_eq!(
        join(&two.member, &admitted.token, NOW + 11).unwrap(),
        Joined::New {
            network_id: two.network_id,
            seq: 2
        }
    );
    assert_eq!(
        join(&two.member, &admitted.token, NOW + 12).unwrap(),
        Joined::AlreadyCurrent {
            network_id: two.network_id,
            held_seq: 2
        }
    );

    // A grant, by names, reaches it as a newer pair.
    let granted = grant(
        &two.owner,
        None,
        "phone",
        "laptop",
        &[service("tcp:ssh")],
        None,
        NOW + 20,
    )
    .unwrap();
    assert_eq!(granted.seq, 3);
    assert_eq!(
        join(&two.member, &granted.token, NOW + 21).unwrap(),
        Joined::Updated {
            network_id: two.network_id,
            from_seq: 2,
            seq: 3
        }
    );
    // The older token cannot take it back.
    assert_eq!(
        join(&two.member, &admitted.token, NOW + 22).unwrap(),
        Joined::AlreadyCurrent {
            network_id: two.network_id,
            held_seq: 3
        }
    );

    // Both devices now hold documents the node's own stores accept and agree on.
    let laptop = load_identity(&two.owner).unwrap().0.node_id();
    for home in [&two.owner, &two.member] {
        let docs = load_documents(home, &two.network_id).unwrap();
        let (rosters, policies) = (RosterStore::new(), PolicyStore::new());
        assert!(rosters.set(docs.roster()).unwrap());
        assert!(policies.set(docs.policy()).unwrap());
        assert_eq!(docs.seq(), 3);
        for node in [laptop, phone] {
            assert_eq!(
                policies.check_membership(&rosters, &two.network_id, &node, 1, NOW + 30),
                Ok(())
            );
        }
        assert!(policies.has_grant(
            &rosters,
            &two.network_id,
            &phone,
            &laptop,
            Some(&service("tcp:ssh")),
            NOW + 30
        ));
        assert!(!policies.has_grant(
            &rosters,
            &two.network_id,
            &laptop,
            &phone,
            Some(&service("tcp:ssh")),
            NOW + 30
        ));
    }
    // Reprinting gives the token of what is held.
    assert_eq!(token(&two.member, None).unwrap(), granted.token);
}

#[test]
fn only_the_owner_can_admit_grant_or_renew() {
    let two = two_devices();
    let admitted = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    join(&two.member, &admitted.token, NOW).unwrap();

    let (_d, third) = device();
    let third_request = init(&third, NOW).unwrap().join_request;
    let message = |r: Result<Issued>| format!("{:#}", r.unwrap_err());
    assert!(
        message(admit(&two.member, None, &third_request, "tablet", &[], NOW))
            .contains("does not own")
    );
    assert!(
        message(grant(
            &two.member,
            None,
            "phone",
            "laptop",
            &[service("tcp:ssh")],
            None,
            NOW
        ))
        .contains("does not own")
    );
    assert!(message(renew(&two.member, None, NOW)).contains("does not own"));
}

#[test]
fn join_refuses_what_is_not_for_this_device_or_not_genuine() {
    let two = two_devices();
    let admitted = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    let error =
        |home: &Home, token: &str, at: u64| format!("{:#}", join(home, token, at).unwrap_err());

    // A device that is not a member.
    let (_d, stranger) = device();
    init(&stranger, NOW).unwrap();
    assert!(error(&stranger, &admitted.token, NOW).contains("not a member"));
    // A device with no identity.
    let (_e, blank) = device();
    assert!(error(&blank, &admitted.token, NOW).contains("menzil init"));
    // Expired documents.
    assert!(error(&two.member, &admitted.token, NOW + 15 * DAY).contains("expired"));
    // Another kind of token, and nonsense.
    assert!(error(&two.member, &two.join_request, NOW).contains("other kind"));
    assert!(error(&two.member, "menzil1-docs:not-base64!", NOW).contains("base64"));
    // Nothing was written by any of that.
    assert!(!two.member.documents_path(&two.network_id).exists());

    // Documents signed by somebody else but claiming this network are refused.
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    let thief = ed25519_dalek::SigningKey::generate(&mut rand::rng());
    let forged_roster = Roster::sign(&thief, docs.roster_body()).unwrap();
    let forged_policy = Policy::sign(&thief, docs.policy_body()).unwrap();
    let forged = encode_documents(&forged_roster, &forged_policy);
    assert!(error(&two.member, &forged, NOW).contains("not signed by the network's owner"));

    // A byte changed anywhere in a genuine token is refused, never half accepted.
    let text = admitted
        .token
        .strip_prefix(DOCS_PREFIX)
        .unwrap()
        .to_string();
    let mut refused = 0;
    for position in (0..text.len()).step_by(37) {
        let mut bytes = text.clone().into_bytes();
        bytes[position] = if bytes[position] == b'A' { b'B' } else { b'A' };
        let damaged = format!("{DOCS_PREFIX}{}", String::from_utf8(bytes).unwrap());
        if join(&two.member, &damaged, NOW).is_err() {
            refused += 1;
        } else {
            // A change in padding-free base64 can leave the same bytes; then it is the same pair.
            assert_eq!(token(&two.member, None).unwrap(), admitted.token);
            fs::remove_file(two.member.documents_path(&two.network_id)).unwrap();
        }
    }
    assert!(refused > 5, "only {refused} damaged tokens were refused");
}

#[test]
fn a_network_is_named_or_the_only_one() {
    let (_dir, home) = device();
    init(&home, NOW).unwrap();
    let none = format!("{:#}", resolve_network(&home, None).unwrap_err());
    assert!(none.contains("network create"), "{none}");

    let first = network_create(&home, "laptop", NOW).unwrap();
    assert_eq!(resolve_network(&home, None).unwrap(), first);
    let second = network_create(&home, "laptop", NOW).unwrap();
    assert_ne!(first, second, "every network has its own owner key");
    let several = format!("{:#}", resolve_network(&home, None).unwrap_err());
    assert!(several.contains(&first.to_hex()) && several.contains(&second.to_hex()));
    assert_eq!(
        resolve_network(&home, Some(&first.to_hex())).unwrap(),
        first
    );
    assert_eq!(
        resolve_network(
            &home,
            Some(&format!(" {} ", second.to_hex().to_uppercase()))
        )
        .unwrap(),
        second
    );
    for bad in ["", "abc", "laptop", &"g".repeat(64)] {
        assert!(resolve_network(&home, Some(bad)).is_err(), "{bad:?}");
    }
    // Commands act on the one named.
    let renewed = renew(&home, Some(&first.to_hex()), NOW + DAY).unwrap();
    assert_eq!((renewed.network_id, renewed.seq), (first, 2));
    assert_eq!(load_documents(&home, &second).unwrap().seq(), 1);
}

#[test]
fn members_are_found_by_name_or_by_a_unique_start_of_their_node_id() {
    let two = two_devices();
    let admitted = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    let phone = admitted.member.unwrap();
    let laptop = load_identity(&two.owner).unwrap().0.node_id();

    assert_eq!(resolve_member(&docs, "phone").unwrap(), phone);
    assert_eq!(resolve_member(&docs, "laptop").unwrap(), laptop);
    let hex = phone.to_hex();
    assert_eq!(resolve_member(&docs, &hex[..8]).unwrap(), phone);
    assert_eq!(resolve_member(&docs, &hex.to_uppercase()).unwrap(), phone);
    for bad in ["", "tablet", &hex[..7], "zzzzzzzz", "Phone"] {
        let error = format!("{:#}", resolve_member(&docs, bad).unwrap_err());
        assert!(error.contains("laptop, phone"), "{bad:?}: {error}");
    }
}

#[test]
fn grants_name_members_roles_and_everyone() {
    let two = two_devices();
    admit(
        &two.owner,
        None,
        &two.join_request,
        "phone",
        &["family".to_string()],
        NOW,
    )
    .unwrap();
    let ssh = [service("tcp:ssh")];
    grant(
        &two.owner,
        None,
        "role:family",
        "laptop",
        &ssh,
        Some(NOW + DAY),
        NOW,
    )
    .unwrap();
    let issued = grant(&two.owner, None, "laptop", "*", &ssh, None, NOW).unwrap();
    assert_eq!(issued.seq, 4);
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    let grants = &docs.policy_body().grants;
    assert_eq!(grants.len(), 2);
    assert_eq!(
        grants[0].from.target,
        PrincipalTarget::Role("family".to_string())
    );
    assert_eq!(grants[0].expires, Some(NOW + DAY));
    assert_eq!(grants[1].to_node, NodeOrWildcard::Any);

    // What the admin crate refuses comes back as a message, and nothing is saved.
    let error = |from: &str, to: &str, s: &[ServiceId]| {
        format!(
            "{:#}",
            grant(&two.owner, None, from, to, s, None, NOW).unwrap_err()
        )
    };
    assert!(error("tablet", "laptop", &ssh).contains("no member called"));
    assert!(error("phone", "laptop", &[]).contains("names no service"));
    assert_eq!(
        load_documents(&two.owner, &two.network_id).unwrap().seq(),
        4
    );
}

#[test]
fn renewing_extends_the_lifetime_and_changes_nothing_else() {
    let two = two_devices();
    admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    let before = load_documents(&two.owner, &two.network_id).unwrap();
    let renewed = renew(&two.owner, None, NOW + 10 * DAY).unwrap();
    let after = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(renewed.seq, before.seq() + 1);
    assert_eq!(after.roster_body().expires, NOW + 24 * DAY);
    assert_eq!(after.roster_body().members, before.roster_body().members);
    assert_eq!(after.policy_body().members, before.policy_body().members);
    // The member takes the renewed pair like any other.
    join(&two.member, &renewed.token, NOW + 10 * DAY).unwrap();
}

#[test]
fn documents_that_were_edited_on_disk_are_refused() {
    let two = two_devices();
    let path = two.owner.documents_path(&two.network_id);
    let mut bytes = fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&path, &bytes).unwrap();
    assert!(load_documents(&two.owner, &two.network_id).is_err());
    // Truncated, and emptied.
    fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    assert!(load_documents(&two.owner, &two.network_id).is_err());
    fs::write(&path, b"").unwrap();
    assert!(load_documents(&two.owner, &two.network_id).is_err());
    // Joining over damaged documents does not silently replace them.
    let (_d, other) = device();
    let _ = other;
    let admitted_request = two.join_request.clone();
    fs::write(&path, b"junk").unwrap();
    let error = format!(
        "{:#}",
        admit(&two.owner, None, &admitted_request, "phone", &[], NOW).unwrap_err()
    );
    assert!(error.contains("damaged"), "{error}");
}

#[test]
fn status_reports_networks_members_and_problems() {
    let two = two_devices();
    admit(
        &two.owner,
        None,
        &two.join_request,
        "phone",
        &["family".to_string()],
        NOW,
    )
    .unwrap();
    let report = status(&two.owner).unwrap();
    let text = report.render(NOW + 2 * DAY);
    assert!(text.contains("this device: "), "{text}");
    assert!(text.contains("(owned by this device)"), "{text}");
    assert!(
        text.contains("documents #2, expires in 12 days, 0 grants"),
        "{text}"
    );
    assert!(text.contains("laptop (this device)"), "{text}");
    assert!(
        text.contains("phone  ") && text.contains("roles: family"),
        "{text}"
    );
    assert!(report.render(NOW + 20 * DAY).contains("EXPIRED 6 days ago"));

    // A device with nothing says what to do, and a damaged file is a line, not a failure.
    let (_d, blank) = device();
    assert!(status(&blank).unwrap().render(NOW).contains("menzil init"));
    fs::write(two.owner.documents_path(&two.network_id), b"junk").unwrap();
    let text = status(&two.owner).unwrap().render(NOW);
    assert!(text.contains("cannot be read"), "{text}");
}

#[test]
fn relative_times_read_naturally() {
    let now = 1_000_000;
    assert_eq!(relative(now + DAY, now), "in 1 day");
    assert_eq!(relative(now + 14 * DAY, now), "in 14 days");
    assert_eq!(relative(now + 5 * 3600, now), "in 5 hours");
    assert_eq!(relative(now + 120, now), "in 2 minutes");
    assert_eq!(relative(now - 3 * DAY, now), "3 days ago");
    assert_eq!(relative(now, now), "in 0 minutes");
}

#[test]
fn an_owner_key_file_of_another_network_is_not_used() {
    let (_dir, home) = device();
    init(&home, NOW).unwrap();
    let first = network_create(&home, "laptop", NOW).unwrap();
    let second = network_create(&home, "laptop", NOW).unwrap();
    // A key file moved to the wrong name: signing with it would make documents that nobody
    // accepts, so it must be refused before anything is signed.
    fs::copy(home.owner_key_path(&second), home.owner_key_path(&first)).unwrap();
    let error = format!(
        "{:#}",
        renew(&home, Some(&first.to_hex()), NOW).unwrap_err()
    );
    assert!(error.contains("is the key of another network"), "{error}");
    assert_eq!(load_documents(&home, &first).unwrap().seq(), 1);
    // The other one is untouched.
    assert_eq!(renew(&home, Some(&second.to_hex()), NOW).unwrap().seq, 2);
}
