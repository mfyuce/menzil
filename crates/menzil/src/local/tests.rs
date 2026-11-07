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

/// The third red-team round, L4: the home and its directories were created with the umask's
/// 0775 or 0755 and `documents.bin` was 0644, so any other user of the machine could read the
/// Policy (who may use what, every device's name).
#[cfg(unix)]
#[test]
fn keys_and_documents_are_private_and_so_are_the_directories_they_are_in() {
    use std::os::unix::fs::PermissionsExt;
    let two = two_devices();
    // The member joins, so that it holds documents too.
    let issued = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    join(&two.member, &issued.token, NOW).unwrap();
    let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    for home in [&two.owner, &two.member] {
        assert_eq!(mode(&home.identity_key_path()), 0o600);
        assert_eq!(mode(&home.documents_path(&two.network_id)), 0o600);
        // The certificate is the one public file (what the umask leaves of 0644).
        assert_eq!(mode(&home.identity_cert_path()) & 0o022, 0);
        for dir in [
            home.root().to_path_buf(),
            home.root().join("networks"),
            home.network_dir(&two.network_id),
        ] {
            assert_eq!(mode(&dir) & 0o077, 0, "{} is open to others", dir.display());
        }
    }
    assert_eq!(mode(&two.owner.owner_key_path(&two.network_id)), 0o600);
    assert_eq!(
        mode(&two.owner.root().join("owner")) & 0o077,
        0,
        "the owner key's directory is open to others"
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
    let forged = encode_documents(&Documents::from_signed(forged_roster, forged_policy).unwrap());
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

/// The third red-team round, M5: two owner commands at the same moment each read the same
/// documents, issued the same `seq` with different contents and reported success; one change was
/// lost and the documents forked. Under the lock every command gets its own number and none is
/// lost.
#[test]
fn owner_commands_at_the_same_moment_each_get_their_own_number_and_none_is_lost() {
    const COMMANDS: usize = 8;
    const ROUNDS: usize = 5;
    let two = two_devices();
    let issued = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    join(&two.member, &issued.token, NOW).unwrap();
    let mut expected_grants = 0;
    let mut seq = issued.seq;
    for round in 0..ROUNDS {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(COMMANDS));
        let threads: Vec<_> = (0..COMMANDS)
            .map(|command| {
                let (home, barrier) = (two.owner.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let service = format!("tcp:r{round}c{command}").parse().unwrap();
                    grant(&home, None, "phone", "laptop", &[service], None, NOW)
                })
            })
            .collect();
        let mut numbers: Vec<u64> = threads
            .into_iter()
            .map(|t| {
                t.join()
                    .unwrap()
                    .expect("a command waits its turn, it does not fail")
                    .seq
            })
            .collect();
        numbers.sort_unstable();
        assert_eq!(
            numbers,
            (seq + 1..=seq + COMMANDS as u64).collect::<Vec<_>>(),
            "round {round}: every command got its own number"
        );
        seq += COMMANDS as u64;
        expected_grants += COMMANDS;
    }
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(docs.seq(), seq);
    assert_eq!(
        docs.policy_body().grants.len(),
        expected_grants,
        "no change was lost"
    );
}

/// The fourth red-team round, L2: two `init`s at the same moment both found no identity, both
/// made one and both reported success; the certificate of one was left next to the key of the
/// other in 6 of 20 rounds. Under the lock exactly one makes the identity, the others find it and
/// change nothing, and what is on disk belongs together.
#[test]
fn two_inits_at_the_same_moment_make_one_identity_and_it_is_whole() {
    const COMMANDS: usize = 4;
    const ROUNDS: usize = 25;
    for round in 0..ROUNDS {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path().join("home"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(COMMANDS));
        let threads: Vec<_> = (0..COMMANDS)
            .map(|_| {
                let (home, barrier) = (home.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    init(&home, NOW)
                })
            })
            .collect();
        let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let made: Vec<_> = outcomes.iter().filter_map(|o| o.as_ref().ok()).collect();
        assert_eq!(
            made.len(),
            1,
            "round {round}: exactly one init makes the identity"
        );
        for refused in outcomes.iter().filter_map(|o| o.as_ref().err()) {
            let message = format!("{refused:#}");
            assert!(
                message.contains("already has an identity"),
                "round {round}: {message}"
            );
        }
        // The key and the certificate on disk belong together, and are the ones that were printed.
        let (keys, _) = load_identity(&home).unwrap_or_else(|e| panic!("round {round}: {e:#}"));
        assert_eq!(keys.node_id(), made[0].node_id, "round {round}");
    }
}

/// A Policy signed by the owner's key but made by hand: the way a name or a role nobody's tool
/// would issue gets into a token.
fn hand_made_token(two: &Two, change: impl FnOnce(&mut menzil_proto::PolicyBody)) -> String {
    let owner = load_owner(&two.owner, &two.network_id).unwrap();
    let current = load_documents(&two.owner, &two.network_id).unwrap();
    let mut roster = current.roster_body().clone();
    let mut policy = current.policy_body().clone();
    roster.seq += 1;
    policy.seq += 1;
    change(&mut policy);
    encode_documents(
        &Documents::from_signed(
            Roster::sign(owner.signing_key(), &roster).unwrap(),
            Policy::sign(owner.signing_key(), &policy).unwrap(),
        )
        .unwrap(),
    )
}

/// The third red-team round, L3 and M1: `join` accepted whatever the owner's key had signed, so
/// a hand made Policy could put a terminal escape in a name, or name a member like the start
/// of another node's id.
#[test]
fn join_refuses_names_and_roles_the_issuing_tool_would_not_have_issued() {
    let two = two_devices();
    let issued = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    join(&two.member, &issued.token, NOW).unwrap();
    // Members: [laptop (owner), phone (this device)].
    let bad_names = [
        "laptop\u{1b}]52;c;cm0gLXJmIH4K\u{7}",
        "x\u{202e}gpj.exe",
        "new\nline",
        "with space",
        ".",
        "..",
        "1a2b3c4d",
        // The fourth round, N1: letters that print as nothing, a variation selector, a tag.
        "laptop\u{3164}",
        "\u{3164}",
        "lap\u{115f}top",
        "\u{ffa0}x",
        "vs\u{fe0f}x",
        "tag\u{e0041}",
    ];
    for name in bad_names {
        let token = hand_made_token(&two, |policy| policy.members[0].name = name.to_string());
        let error = format!("{:#}", join(&two.member, &token, NOW).unwrap_err());
        assert!(error.contains("would not have issued"), "{name:?}: {error}");
        assert!(
            !error.chars().any(crate::text::is_unsafe),
            "the refusal itself must not carry the escape: {error:?}"
        );
    }
    for role in ["\u{1b}[31mADMIN\u{1b}[0m", "a b", "x:y", ""] {
        let token = hand_made_token(&two, |policy| {
            policy.members[1].roles = vec![role.to_string()]
        });
        let error = format!("{:#}", join(&two.member, &token, NOW).unwrap_err());
        assert!(error.contains("role"), "{role:?}: {error}");
        assert!(!error.chars().any(crate::text::is_unsafe), "{error:?}");
    }
    // Nothing was installed by any of them, and a sound pair still joins.
    assert_eq!(
        load_documents(&two.member, &two.network_id).unwrap().seq(),
        2
    );
    let sound = hand_made_token(&two, |policy| {
        policy.members[0].name = "workstation".to_string();
        policy.members[1].roles = vec!["admin".to_string()];
    });
    assert!(matches!(
        join(&two.member, &sound, NOW).unwrap(),
        Joined::Updated { seq: 3, .. }
    ));
}

/// The fourth red-team round, M2: `admit` treats "Laptop" and "laptop" as one name; a device
/// handed documents by another route holds them to the same rule, or two members could answer
/// to what `ssh` sends for either.
#[test]
fn join_refuses_two_members_whose_names_differ_only_in_letter_case() {
    let two = two_devices();
    let issued = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    join(&two.member, &issued.token, NOW).unwrap();
    // Members: [laptop (owner), phone (this device)].
    let token = hand_made_token(&two, |policy| policy.members[1].name = "Laptop".to_string());
    let error = format!("{:#}", join(&two.member, &token, NOW).unwrap_err());
    assert!(error.contains("differ only in letter case"), "{error}");
    assert!(!error.chars().any(crate::text::is_unsafe), "{error:?}");
    // Nothing was installed, and names that really differ still join.
    assert_eq!(
        load_documents(&two.member, &two.network_id).unwrap().seq(),
        2
    );
    let sound = hand_made_token(&two, |policy| {
        policy.members[1].name = "Laptop2".to_string()
    });
    assert!(matches!(
        join(&two.member, &sound, NOW).unwrap(),
        Joined::Updated { seq: 3, .. }
    ));
}

/// Documents that are already on disk (an older version of this tool, or an edit) are shown
/// escaped, not raw.
#[test]
fn status_shows_what_a_hand_made_policy_holds_without_letting_it_act() {
    let two = two_devices();
    let issued = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    join(&two.member, &issued.token, NOW).unwrap();
    let token = hand_made_token(&two, |policy| {
        policy.members[0].name =
            "laptop\u{1b}]52;c;cm0gLXJmIH4K\u{7}\u{1b}[2J\u{202e}gpj".to_string();
        policy.members[1].roles = vec!["\u{1b}[31mADMIN\u{1b}[0m".to_string()];
    });
    // Put it on disk the way an older tool, or an editor, could have.
    save_documents(&two.member, &decode_documents(&token).unwrap()).unwrap();
    let text = status(&two.member).unwrap().render(NOW);
    // (The report itself is lines.)
    assert!(
        !text.chars().any(|c| c != '\n' && crate::text::is_unsafe(c)),
        "{text:?}"
    );
    assert!(
        text.contains("\\u{1b}]52"),
        "the words stay, escaped: {text}"
    );
}

#[test]
fn an_expired_certificate_is_marked_in_the_status() {
    let two = two_devices();
    let text = status(&two.owner).unwrap().render(NOW + 500 * DAY);
    assert!(text.contains("certificate EXPIRED"), "{text}");
    let text = status(&two.owner).unwrap().render(NOW + DAY);
    assert!(text.contains("certificate expires in"), "{text}");
}

/// An owner command, run on a thread against the owner's home.
type OwnerCommand = Box<dyn FnOnce(&Home) -> Result<Issued> + Send>;

/// `admit` and `renew` are owner commands too: two admissions at the same moment must both
/// take effect (each under its own number), and so must a renewal beside a grant.
#[test]
fn admissions_and_renewals_at_the_same_moment_are_not_lost_either() {
    let two = two_devices();
    let phone_request = two.join_request.clone();
    let tablet = device();
    let tablet_request = init(&tablet.1, NOW).unwrap().join_request;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let spawn = |work: OwnerCommand| {
        let (home, barrier) = (two.owner.clone(), barrier.clone());
        std::thread::spawn(move || {
            barrier.wait();
            work(&home)
        })
    };
    let threads = [
        spawn(Box::new(move |home| {
            admit(home, None, &phone_request, "phone", &[], NOW)
        })),
        spawn(Box::new(move |home| {
            admit(home, None, &tablet_request, "tablet", &[], NOW)
        })),
        spawn(Box::new(|home| renew(home, None, NOW + DAY))),
    ];
    let mut numbers: Vec<u64> = threads
        .into_iter()
        .map(|t| t.join().unwrap().expect("each waits its turn").seq)
        .collect();
    numbers.sort_unstable();
    assert_eq!(numbers, vec![2, 3, 4], "three commands, three numbers");
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    let names: Vec<&str> = docs
        .policy_body()
        .members
        .iter()
        .map(|m| m.name.as_str())
        .collect();
    assert!(
        names.contains(&"phone") && names.contains(&"tablet"),
        "{names:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Stewards (protocol.md 2.3, 7.3; TODO L4j S3)
// ---------------------------------------------------------------------------------------------

use menzil_proto::trust::{STEWARD_SEQ_SPAN, Signer};

use crate::token::decode_documents;

fn all_rights() -> Vec<String> {
    vec!["admit".to_string(), "renew".to_string()]
}

/// An owner device, a device that is the steward (a member that holds a steward key the owner
/// listed), and a new device waiting to be admitted.
struct Stewarded {
    two: Two,
    _phone_dir: tempfile::TempDir,
    phone: Home,
    phone_request: String,
}

fn stewarded() -> Stewarded {
    let two = two_devices();
    // The steward device is a member first, as a device that runs a node must be.
    let admitted = admit(&two.owner, None, &two.join_request, "steward", &[], NOW).unwrap();
    join(&two.member, &admitted.token, NOW).unwrap();
    let request = steward_request(&two.member, None).unwrap();
    assert!(request.created);
    let listing = steward_add(
        &two.owner,
        None,
        &request.token,
        &all_rights(),
        30,
        NOW + 10,
    )
    .unwrap();
    assert_eq!(
        join(&two.member, &listing.issued.token, NOW + 10).unwrap(),
        Joined::Updated {
            network_id: two.network_id,
            from_seq: 2,
            seq: 3
        }
    );
    let (phone_dir, phone) = device();
    let phone_request = init(&phone, NOW).unwrap().join_request;
    Stewarded {
        two,
        _phone_dir: phone_dir,
        phone,
        phone_request,
    }
}

#[test]
fn a_steward_request_is_made_once_and_only_its_public_half_leaves_the_device() {
    let two = two_devices();
    let first = steward_request(&two.owner, None).unwrap();
    assert!(first.created);
    let key_path = two.owner.steward_key_path(&two.network_id);
    let secret = fs::read(&key_path).unwrap();
    assert_eq!(secret.len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&key_path), 0o600);
        assert_eq!(mode(key_path.parent().unwrap()) & 0o077, 0);
    }
    // The request names the network and the public key, and not a byte of the secret.
    assert!(first.token.starts_with(crate::token::STEWARD_PREFIX));
    let (network, public) = decode_steward_request(&first.token).unwrap();
    assert_eq!((network, public), (two.network_id, first.public));
    assert_eq!(
        load_steward(&two.owner, &two.network_id).unwrap().public(),
        public
    );
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&first.token[crate::token::STEWARD_PREFIX.len()..])
        .unwrap();
    assert!(!raw.windows(32).any(|w| w == secret.as_slice()));
    // Asking again changes nothing: the owner may have listed this key already.
    let again = steward_request(&two.owner, None).unwrap();
    assert!(!again.created);
    assert_eq!(again.token, first.token);
    assert_eq!(fs::read(&key_path).unwrap(), secret);
    // A device that holds both keys signs as the owner: roles are allowed, and the pair stands
    // alone.
    let admitted = admit(
        &two.owner,
        None,
        &two.join_request,
        "phone",
        &["admin".to_string()],
        NOW,
    )
    .unwrap();
    assert!(decode_documents(&admitted.token).unwrap().base().is_none());
    assert_eq!(
        load_documents(&two.owner, &two.network_id)
            .unwrap()
            .verify()
            .unwrap(),
        Signer::Owner
    );
    // A damaged key file is an error, not a new key.
    fs::write(&key_path, b"short").unwrap();
    assert!(steward_request(&two.owner, None).is_err());
    assert_eq!(fs::read(&key_path).unwrap(), b"short");
}

#[test]
fn the_owner_lists_and_removes_a_steward_and_only_the_owner_can() {
    let two = two_devices();
    let (_d, steward_device) = device();
    init(&steward_device, NOW).unwrap();
    // The steward device needs to know the network to ask: it names it by id.
    let id = two.network_id.to_hex();
    let request = steward_request(&steward_device, Some(&id)).unwrap();

    let added = steward_add(&two.owner, None, &request.token, &all_rights(), 30, NOW).unwrap();
    assert_eq!(added.steward, request.public);
    assert_eq!(added.not_after, NOW + 30 * DAY);
    assert_eq!(added.issued.seq, 2);
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(docs.roster_body().stewards.len(), 1);
    assert!(status(&two.owner).unwrap().render(NOW).contains("steward"));

    // Asked for something else than a steward request, or for another network.
    let error = |r: Result<StewardAdded>| format!("{:#}", r.unwrap_err());
    assert!(
        error(steward_add(
            &two.owner,
            None,
            &two.join_request,
            &all_rights(),
            30,
            NOW
        ))
        .contains("other kind")
    );
    let other = network_create(&two.owner, "second", NOW).unwrap();
    assert!(
        error(steward_add(
            &two.owner,
            Some(&other.to_hex()),
            &request.token,
            &all_rights(),
            30,
            NOW
        ))
        .contains("not for the one named")
    );
    // Days: 1 to 90.
    for days in [0, 91, u64::MAX] {
        assert!(
            error(steward_add(
                &two.owner,
                None,
                &request.token,
                &all_rights(),
                days,
                NOW
            ))
            .contains("1 to 90 days"),
            "{days}"
        );
    }
    steward_add(
        &two.owner,
        Some(&id),
        &request.token,
        &all_rights(),
        90,
        NOW,
    )
    .unwrap();
    // Rights: only admit and renew.
    assert!(
        error(steward_add(
            &two.owner,
            Some(&id),
            &request.token,
            &["grant".to_string()],
            30,
            NOW
        ))
        .contains("admit")
    );
    // The member device cannot list one: it does not own the network.
    assert!(
        error(steward_add(
            &steward_device,
            Some(&id),
            &request.token,
            &all_rights(),
            30,
            NOW
        ))
        .contains("does not own")
    );
    assert!(steward_remove(&steward_device, Some(&id), NOW).is_err());

    // Removing: documents with no steward, and removing again is an error.
    let before = load_documents(&two.owner, &two.network_id).unwrap().seq();
    let removed = steward_remove(&two.owner, Some(&id), NOW + 1).unwrap();
    assert_eq!(removed.seq, before + STEWARD_SEQ_SPAN + 1);
    assert!(
        load_documents(&two.owner, &two.network_id)
            .unwrap()
            .roster_body()
            .stewards
            .is_empty()
    );
    assert!(
        format!(
            "{:#}",
            steward_remove(&two.owner, Some(&id), NOW + 2).unwrap_err()
        )
        .contains("lists no steward")
    );
}

/// The flow of the slice: the steward admits, the new device joins on the token alone, the owner
/// takes the steward's documents, and its own next ones jump past the steward's range.
#[test]
fn a_steward_admits_and_renews_and_everyone_follows_by_token() {
    let s = stewarded();
    let two = &s.two;
    // The steward device holds the owner's pair that lists it, and signs with its own key.
    let admitted = admit(&two.member, None, &s.phone_request, "phone", &[], NOW + DAY).unwrap();
    assert_eq!(admitted.seq, 4);
    let docs = load_documents(&two.member, &two.network_id).unwrap();
    let (base_roster, _) = docs.base().expect("a steward pair is kept with its base");
    assert_eq!(base_roster.decode().unwrap().seq, 3);
    // The file on disk is version 2 and carries the base.
    assert_eq!(
        fs::read(two.member.documents_path(&two.network_id)).unwrap()[0],
        2
    );

    // The token carries the base too, and the new device joins on it alone.
    let carried = decode_documents(&admitted.token).unwrap();
    assert!(carried.base().is_some());
    assert_eq!(
        join(&s.phone, &admitted.token, NOW + DAY).unwrap(),
        Joined::New {
            network_id: two.network_id,
            seq: 4
        }
    );
    assert_eq!(
        fs::read(s.phone.documents_path(&two.network_id)).unwrap()[0],
        2
    );
    let on_phone = load_documents(&s.phone, &two.network_id).unwrap();
    assert!(on_phone.is_member(&admitted.member.unwrap()));
    assert_eq!(on_phone.base().map(|(r, _)| r), Some(base_roster));

    // The owner receives the steward's documents like anyone's.
    assert_eq!(
        join(&two.owner, &admitted.token, NOW + DAY).unwrap(),
        Joined::Updated {
            network_id: two.network_id,
            from_seq: 3,
            seq: 4
        }
    );
    // A renewal by the steward, from its own documents, keeps the owner's base.
    let renewed = renew(&two.member, None, NOW + 2 * DAY).unwrap();
    assert_eq!(renewed.seq, 5);
    assert_eq!(
        join(&s.phone, &renewed.token, NOW + 2 * DAY).unwrap(),
        Joined::Updated {
            network_id: two.network_id,
            from_seq: 4,
            seq: 5
        }
    );
    // The same token again is nothing to do.
    assert_eq!(
        join(&s.phone, &renewed.token, NOW + 2 * DAY).unwrap(),
        Joined::AlreadyCurrent {
            network_id: two.network_id,
            held_seq: 5
        }
    );
    // And the status says whose documents these are.
    let report = status(&s.phone).unwrap().render(NOW + 2 * DAY);
    assert!(report.contains("the steward's"), "{report}");
    let report = status(&two.member).unwrap().render(NOW + 2 * DAY);
    assert!(
        report.contains("(this device)") && report.contains("steward"),
        "{report}"
    );

    // The owner, who holds the steward's documents, issues its next ones past the whole range
    // counted from the base (3), and they replace the steward's on every device.
    join(&two.owner, &renewed.token, NOW + 2 * DAY).unwrap();
    let by_owner = renew(&two.owner, None, NOW + 3 * DAY).unwrap();
    assert_eq!(by_owner.seq, 3 + STEWARD_SEQ_SPAN + 1);
    assert_eq!(
        join(&s.phone, &by_owner.token, NOW + 3 * DAY).unwrap(),
        Joined::Updated {
            network_id: two.network_id,
            from_seq: 5,
            seq: by_owner.seq
        }
    );
    assert!(
        load_documents(&s.phone, &two.network_id)
            .unwrap()
            .base()
            .is_none()
    );
    assert_eq!(
        fs::read(s.phone.documents_path(&two.network_id)).unwrap()[0],
        1
    );
}

#[test]
fn a_steward_device_admits_without_roles_and_other_devices_cannot_sign() {
    let s = stewarded();
    let error = format!(
        "{:#}",
        admit(
            &s.two.member,
            None,
            &s.phone_request,
            "phone",
            &["admin".to_string()],
            NOW + DAY
        )
        .unwrap_err()
    );
    assert!(error.contains("without roles"), "{error}");
    // Nothing was written: still the owner's pair that listed the steward.
    assert_eq!(
        load_documents(&s.two.member, &s.two.network_id)
            .unwrap()
            .seq(),
        3
    );
    // A steward cannot grant, and a device that holds no key at all cannot admit or renew.
    assert!(
        grant(
            &s.two.member,
            None,
            "owner",
            "steward",
            &["tcp:ssh".parse().unwrap()],
            None,
            NOW
        )
        .is_err()
    );
    let admitted = admit(
        &s.two.member,
        None,
        &s.phone_request,
        "phone",
        &[],
        NOW + DAY,
    )
    .unwrap();
    join(&s.phone, &admitted.token, NOW + DAY).unwrap();
    for result in [
        renew(&s.phone, None, NOW + 2 * DAY),
        admit(&s.phone, None, &s.two.join_request, "x", &[], NOW + 2 * DAY),
    ] {
        let message = format!("{:#}", result.unwrap_err());
        assert!(message.contains("does not own"), "{message}");
    }
}

#[test]
fn join_refuses_a_steward_token_without_its_base() {
    let s = stewarded();
    let admitted = admit(
        &s.two.member,
        None,
        &s.phone_request,
        "phone",
        &[],
        NOW + DAY,
    )
    .unwrap();
    let docs = decode_documents(&admitted.token).unwrap();
    let bare = encode_documents(
        &Documents::from_signed(docs.roster().clone(), docs.policy().clone()).unwrap(),
    );
    let message = format!("{:#}", join(&s.phone, &bare, NOW + DAY).unwrap_err());
    assert!(
        message.contains("without") || message.contains("come without"),
        "{message}"
    );
    assert!(
        message.contains("documents that documents from a steward are made from"),
        "{message}"
    );
    assert!(!s.phone.documents_path(&s.two.network_id).exists());
    // The same token with its base is taken.
    join(&s.phone, &admitted.token, NOW + DAY).unwrap();
    // Documents a steward signed, with the base of another network, are not even a pair.
    let docs = decode_documents(&admitted.token).unwrap();
    let foreign_dir = tempfile::tempdir().unwrap();
    let foreign = Home::new(foreign_dir.path());
    init(&foreign, NOW).unwrap();
    let foreign_id = network_create(&foreign, "x", NOW).unwrap();
    let foreign_docs = load_documents(&foreign, &foreign_id).unwrap();
    assert!(
        Documents::from_signed_with_base(
            docs.roster().clone(),
            docs.policy().clone(),
            foreign_docs.roster().clone(),
            foreign_docs.policy().clone(),
        )
        .is_err()
    );
    // A base that is another pair of this network than the one the steward's were made from.
    let owner_later =
        decode_documents(&renew(&s.two.owner, None, NOW + DAY).unwrap().token).unwrap();
    let wrong = encode_documents(
        &Documents::from_signed_with_base(
            docs.roster().clone(),
            docs.policy().clone(),
            owner_later.roster().clone(),
            owner_later.policy().clone(),
        )
        .unwrap(),
    );
    let (_d, third) = device();
    init(&third, NOW).unwrap();
    assert!(join(&third, &wrong, NOW + DAY).is_err());
}

#[test]
fn a_steward_file_without_its_base_or_with_another_is_refused_not_trusted() {
    let s = stewarded();
    admit(
        &s.two.member,
        None,
        &s.phone_request,
        "phone",
        &[],
        NOW + DAY,
    )
    .unwrap();
    let path = s.two.member.documents_path(&s.two.network_id);
    let good = fs::read(&path).unwrap();
    let docs = load_documents(&s.two.member, &s.two.network_id).unwrap();
    // Version 1 bytes of the steward's pair: the base is gone.
    let stripped = documents_to_bytes(
        &Documents::from_signed(docs.roster().clone(), docs.policy().clone()).unwrap(),
    );
    fs::write(&path, stripped).unwrap();
    let message = format!(
        "{:#}",
        load_documents(&s.two.member, &s.two.network_id).unwrap_err()
    );
    assert!(
        message.contains("not signed by the network's owner"),
        "{message}"
    );
    // The status of the network says so instead of failing.
    assert!(
        status(&s.two.member)
            .unwrap()
            .render(NOW)
            .contains("cannot be read")
    );
    fs::write(&path, good).unwrap();
    load_documents(&s.two.member, &s.two.network_id).unwrap();
}

/// "Removing a steward leaves a Roster no steward doc can follow", on devices.
#[test]
fn after_the_owner_removes_the_steward_nothing_it_signed_is_taken() {
    let s = stewarded();
    let two = &s.two;
    let stale = admit(&two.member, None, &s.phone_request, "phone", &[], NOW + DAY).unwrap();
    let removed = steward_remove(&two.owner, None, NOW + 2 * DAY).unwrap();
    assert_eq!(removed.seq, 3 + STEWARD_SEQ_SPAN + 1);
    // The steward device takes the removal over the pair it signed itself...
    assert_eq!(
        join(&two.member, &removed.token, NOW + 2 * DAY).unwrap(),
        Joined::Updated {
            network_id: two.network_id,
            from_seq: 4,
            seq: removed.seq
        }
    );
    // ...and then can neither sign nor have what it signed taken by those who hold the removal.
    let message = format!("{:#}", renew(&two.member, None, NOW + 3 * DAY).unwrap_err());
    assert!(message.contains("lists no steward"), "{message}");
    assert!(matches!(
        join(&two.owner, &stale.token, NOW + 3 * DAY).unwrap(),
        Joined::AlreadyCurrent { held_seq, .. } if held_seq == removed.seq
    ));
    assert_eq!(
        load_documents(&two.owner, &two.network_id).unwrap().seq(),
        removed.seq
    );
}

/// The owner lists the steward anew (a new base, a whole range above the old one): documents
/// the steward made from the old base are left alone by a device that holds the new ones.
#[test]
fn a_steward_token_from_before_a_new_listing_is_left_alone() {
    let s = stewarded();
    let two = &s.two;
    let old = admit(&two.member, None, &s.phone_request, "phone", &[], NOW + DAY).unwrap();
    join(&s.phone, &old.token, NOW + DAY).unwrap();
    // The owner takes the steward's pair first (or its own next one would drop the member).
    join(&two.owner, &old.token, NOW + DAY).unwrap();
    let request = steward_request(&two.member, None).unwrap();
    let again = steward_add(
        &two.owner,
        None,
        &request.token,
        &all_rights(),
        30,
        NOW + 2 * DAY,
    )
    .unwrap();
    // Counted from the base of the pair it holds (#3), not from the steward's #4.
    assert_eq!(again.issued.seq, 3 + STEWARD_SEQ_SPAN + 1);
    join(&two.member, &again.issued.token, NOW + 2 * DAY).unwrap();
    let fresh = renew(&two.member, None, NOW + 3 * DAY).unwrap();
    assert_eq!(fresh.seq, again.issued.seq + 1);
    join(&s.phone, &again.issued.token, NOW + 3 * DAY).unwrap();
    join(&s.phone, &fresh.token, NOW + 3 * DAY).unwrap();
    // The token made on the old base is nothing to a device holding the new one.
    assert!(matches!(
        join(&s.phone, &old.token, NOW + 3 * DAY).unwrap(),
        Joined::AlreadyCurrent { held_seq, .. } if held_seq == fresh.seq
    ));
}

#[test]
fn the_token_for_a_relay_carries_the_base_of_a_steward_roster_and_no_policy() {
    let s = stewarded();
    admit(
        &s.two.member,
        None,
        &s.phone_request,
        "phone",
        &[],
        NOW + DAY,
    )
    .unwrap();
    let for_relay = token_for_relay(&s.two.member, None).unwrap();
    let (roster, base) = crate::token::decode_roster(&for_relay).unwrap();
    assert_eq!(roster.decode().unwrap().seq, 4);
    assert_eq!(base.unwrap().decode().unwrap().seq, 3);
    // The owner's own Roster needs no base.
    let (roster, base) =
        crate::token::decode_roster(&token_for_relay(&s.two.owner, None).unwrap()).unwrap();
    assert_eq!(roster.decode().unwrap().seq, 3);
    assert!(base.is_none());
}

/// A steward that made documents from a base older than the one a device holds (the owner
/// issued an unrelated pair inside the old range, which an owner that follows the rule never
/// does): refused, with the reason, not merely left alone.
#[test]
fn a_steward_token_on_a_base_older_than_the_held_one_is_refused() {
    let s = stewarded();
    let two = &s.two;
    let steward_docs = {
        let admitted = admit(&two.member, None, &s.phone_request, "phone", &[], NOW + DAY).unwrap();
        decode_documents(&admitted.token).unwrap()
    };
    assert_eq!(steward_docs.seq(), 4);
    // The steward's pair re-made at seq 100, still from base 3, signed with its own key.
    let steward = load_steward(&two.member, &two.network_id).unwrap();
    let (mut roster, mut policy) = (
        steward_docs.roster_body().clone(),
        steward_docs.policy_body().clone(),
    );
    roster.seq = 100;
    policy.seq = 100;
    let (base_roster, base_policy) = steward_docs.base().unwrap();
    let far = Documents::from_signed_with_base(
        Roster::sign(steward.signing_key(), &roster).unwrap(),
        Policy::sign(steward.signing_key(), &policy).unwrap(),
        base_roster.clone(),
        base_policy.clone(),
    )
    .unwrap();
    far.verify().unwrap();
    // A device holds an owner pair #5, hand made by the owner key, that does not follow the
    // rule: its base is 5, above the steward's 3.
    let owner = load_owner(&two.owner, &two.network_id).unwrap();
    let held = load_documents(&two.owner, &two.network_id).unwrap();
    let (mut r5, mut p5) = (held.roster_body().clone(), held.policy_body().clone());
    r5.seq = 5;
    p5.seq = 5;
    r5.stewards.clear();
    let five = Documents::from_signed(
        Roster::sign(owner.signing_key(), &r5).unwrap(),
        Policy::sign(owner.signing_key(), &p5).unwrap(),
    )
    .unwrap();
    // The device is the steward's own (a member of all of these).
    save_documents(&two.member, &five).unwrap();
    let message = format!(
        "{:#}",
        join(&two.member, &encode_documents(&far), NOW + 2 * DAY).unwrap_err()
    );
    assert!(
        message.contains("older than ones this device holds"),
        "{message}"
    );
    assert_eq!(
        load_documents(&two.member, &two.network_id).unwrap().seq(),
        5
    );
}

// ---------------------------------------------------------------------------------------------
// `revoke` and `ungrant` (protocol.md 7.3; L4k K1)
// ---------------------------------------------------------------------------------------------

#[test]
fn status_counts_the_revoked_nodes_and_says_nothing_before_any() {
    let (two, _phone) = with_phone();
    let text = status(&two.owner).unwrap().render(NOW);
    assert!(!text.contains("revoked"), "{text}");
    revoke(&two.owner, None, "phone", false, NOW + 5).unwrap();
    let report = status(&two.owner).unwrap();
    assert_eq!(report.networks[0].revoked, 1);
    let text = report.render(NOW + 5);
    assert!(text.contains("0 grants, 1 revoked\n"), "{text}");
    // The revoked node is gone from the members the status lists.
    assert!(!text.contains("phone"), "{text}");
}

/// The owner device with `phone` admitted and joined, and some grants.
fn with_phone() -> (Two, NodeId) {
    let two = two_devices();
    let admitted = admit(
        &two.owner,
        None,
        &two.join_request,
        "phone",
        &["family".to_string()],
        NOW,
    )
    .unwrap();
    join(&two.member, &admitted.token, NOW).unwrap();
    (two, admitted.member.unwrap())
}

fn documents_bytes(home: &Home, network_id: &NetworkId) -> Vec<u8> {
    fs::read(home.documents_path(network_id)).unwrap()
}

#[test]
fn revoking_a_member_by_name_by_prefix_or_by_whole_id() {
    let (two, phone) = with_phone();
    let ssh = [service("tcp:ssh")];
    grant(&two.owner, None, "phone", "laptop", &ssh, None, NOW).unwrap();
    grant(&two.owner, None, "role:family", "laptop", &ssh, None, NOW).unwrap();

    // By name.
    let revoked = revoke(&two.owner, None, "phone", false, NOW + 5).unwrap();
    assert_eq!(revoked.name.as_deref(), Some("phone"));
    assert!(revoked.was_member);
    assert!(!revoked.steward_listed);
    assert_eq!(revoked.issued.member, Some(phone));
    assert_eq!(revoked.issued.seq, 5);
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(docs.seq(), 5);
    assert!(!docs.is_member(&phone));
    assert_eq!(docs.roster_body().revoked.len(), 1);
    assert_eq!(docs.roster_body().revoked[0].node_id, phone);
    assert_eq!(docs.roster_body().revoked[0].since, NOW + 5);
    assert_eq!(docs.policy_body().members.len(), 1);
    // The token carries the same pair.
    assert_eq!(decode_documents(&revoked.issued.token).unwrap().seq(), 5);
    assert_eq!(token(&two.owner, None).unwrap(), revoked.issued.token);

    // Twice is an error, and says so.
    let again = format!(
        "{:#}",
        revoke(&two.owner, None, &phone.to_hex(), false, NOW + 6).unwrap_err()
    );
    assert!(again.contains("revoked already"), "{again}");
    assert_eq!(
        load_documents(&two.owner, &two.network_id).unwrap().seq(),
        5
    );

    // By the start of the node id.
    let (two, phone) = with_phone();
    let hex = phone.to_hex();
    let revoked = revoke(&two.owner, None, &hex[..8], false, NOW + 5).unwrap();
    assert_eq!(revoked.issued.member, Some(phone));
    assert_eq!(revoked.name.as_deref(), Some("phone"));

    // By a whole node id that no document lists: only the revoked list grows.
    let two = two_devices();
    let (_d, stranger) = device();
    let stranger_id = {
        init(&stranger, NOW).unwrap();
        load_identity(&stranger).unwrap().0.node_id()
    };
    let before = load_documents(&two.owner, &two.network_id).unwrap();
    let revoked = revoke(
        &two.owner,
        None,
        &stranger_id.to_hex().to_uppercase(),
        false,
        NOW + 5,
    )
    .unwrap();
    assert_eq!(revoked.name, None);
    assert!(!revoked.was_member);
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(docs.roster_body().revoked[0].node_id, stranger_id);
    assert_eq!(docs.roster_body().members, before.roster_body().members);

    // Anything else is not a member, and the message lists the members.
    let error = format!(
        "{:#}",
        revoke(&two.owner, None, "tablet", false, NOW).unwrap_err()
    );
    assert!(
        error.contains("no member called") && error.contains("laptop"),
        "{error}"
    );
    let short = format!(
        "{:#}",
        revoke(&two.owner, None, &stranger_id.to_hex()[..63], false, NOW).unwrap_err()
    );
    assert!(short.contains("no member called"), "{short}");
    assert_eq!(
        load_documents(&two.owner, &two.network_id).unwrap().seq(),
        2
    );
}

#[test]
fn a_device_revokes_itself_only_when_told_to() {
    let (two, _) = with_phone();
    let laptop = load_identity(&two.owner).unwrap().0.node_id();
    let before = documents_bytes(&two.owner, &two.network_id);
    for who in [
        "laptop".to_string(),
        laptop.to_hex(),
        laptop.to_hex()[..8].to_string(),
    ] {
        let error = format!(
            "{:#}",
            revoke(&two.owner, None, &who, false, NOW + 1).unwrap_err()
        );
        assert!(error.contains("--self"), "{who}: {error}");
        assert_eq!(documents_bytes(&two.owner, &two.network_id), before);
    }
    // Someone else is not "self".
    revoke(&two.owner, None, "phone", false, NOW + 1).unwrap();
    // With the flag it goes through.
    let done = revoke(&two.owner, None, "laptop", true, NOW + 2).unwrap();
    assert_eq!(done.issued.member, Some(laptop));
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert!(docs.roster_body().members.is_empty());
    assert!(
        docs.roster_body()
            .revoked
            .iter()
            .any(|r| r.node_id == laptop)
    );
}

#[test]
fn only_the_owner_revokes_and_a_steward_device_is_told_so() {
    let s = stewarded();
    let before = documents_bytes(&s.two.member, &s.two.network_id);
    // The device that holds the steward key.
    let error = format!(
        "{:#}",
        revoke(&s.two.member, None, "laptop", false, NOW + 20).unwrap_err()
    );
    assert!(
        error.contains("only the owner revokes (protocol.md 7.3)"),
        "{error}"
    );
    assert_eq!(documents_bytes(&s.two.member, &s.two.network_id), before);
    // A plain member device: no owner key, so the plain refusal every owner command gives.
    let (two, _) = with_phone();
    let error = format!(
        "{:#}",
        revoke(&two.member, None, "laptop", false, NOW).unwrap_err()
    );
    assert!(error.contains("does not own"), "{error}");
    assert!(!error.contains("only the owner revokes"), "{error}");
}

#[test]
fn revoking_beside_a_steward_says_the_steward_key_stays() {
    let s = stewarded();
    // The owner device revokes the device that hosts the steward key: the steward stays listed,
    // and the outcome says so, so that the command line can tell the user.
    let revoked = revoke(&s.two.owner, None, "steward", false, NOW + 20).unwrap();
    assert!(revoked.steward_listed);
    assert_eq!(revoked.issued.seq, 3 + STEWARD_SEQ_SPAN + 1);
    let docs = load_documents(&s.two.owner, &s.two.network_id).unwrap();
    assert_eq!(docs.roster_body().stewards.len(), 1);
    // After `steward remove` it is not listed any more.
    steward_remove(&s.two.owner, None, NOW + 21).unwrap();
    let (_d, third) = device();
    let request = init(&third, NOW).unwrap().join_request;
    admit(&s.two.owner, None, &request, "tablet", &[], NOW + 22).unwrap();
    let revoked = revoke(&s.two.owner, None, "tablet", false, NOW + 23).unwrap();
    assert!(!revoked.steward_listed);
}

#[test]
fn ungranting_takes_back_services_or_every_grant_between_two_members() {
    let (two, _) = with_phone();
    let (ssh, web, db) = (service("tcp:ssh"), service("http:web"), service("tcp:db"));
    grant(
        &two.owner,
        None,
        "phone",
        "laptop",
        &[ssh.clone(), web.clone()],
        None,
        NOW,
    )
    .unwrap();
    grant(
        &two.owner,
        None,
        "phone",
        "laptop",
        std::slice::from_ref(&db),
        Some(NOW + DAY),
        NOW,
    )
    .unwrap();
    grant(
        &two.owner,
        None,
        "phone",
        "*",
        std::slice::from_ref(&ssh),
        None,
        NOW,
    )
    .unwrap();
    grant(
        &two.owner,
        None,
        "role:family",
        "laptop",
        std::slice::from_ref(&ssh),
        None,
        NOW,
    )
    .unwrap();
    let grants = || {
        load_documents(&two.owner, &two.network_id)
            .unwrap()
            .policy_body()
            .grants
            .clone()
    };
    assert_eq!(grants().len(), 4);

    // One service of two.
    let issued = ungrant(
        &two.owner,
        None,
        "phone",
        "laptop",
        std::slice::from_ref(&ssh),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(issued.seq, 7);
    assert_eq!(decode_documents(&issued.token).unwrap().seq(), 7);
    assert_eq!(grants()[0].services, vec![web.clone()]);
    assert_eq!(grants().len(), 4);

    // A role is read as `grant` reads it; `*` too.
    ungrant(&two.owner, None, "role:family", "laptop", &[], NOW + 2).unwrap();
    assert_eq!(grants().len(), 3);
    ungrant(&two.owner, None, "phone", "*", &[], NOW + 3).unwrap();
    assert_eq!(grants().len(), 2);

    // Nothing matched: an error, and the file is as it was.
    let before = documents_bytes(&two.owner, &two.network_id);
    for (from, to, list) in [
        ("phone", "laptop", vec![service("tcp:other")]),
        ("laptop", "phone", vec![]),
        ("phone", "*", vec![]),
        ("role:family", "laptop", vec![]),
    ] {
        let error = format!(
            "{:#}",
            ungrant(&two.owner, None, from, to, &list, NOW + 9).unwrap_err()
        );
        assert!(error.contains("no grant matches"), "{from} {to}: {error}");
        assert_eq!(documents_bytes(&two.owner, &two.network_id), before);
    }
    // An unknown member is the same message `grant` gives.
    let error = format!(
        "{:#}",
        ungrant(&two.owner, None, "tablet", "laptop", &[], NOW).unwrap_err()
    );
    assert!(error.contains("no member called"), "{error}");

    // No services named: every grant from the phone to the laptop.
    ungrant(&two.owner, None, "phone", "laptop", &[], NOW + 4).unwrap();
    assert!(grants().is_empty());
}

#[test]
fn only_the_owner_ungrants() {
    let (two, _) = with_phone();
    grant(
        &two.owner,
        None,
        "phone",
        "laptop",
        &[service("tcp:ssh")],
        None,
        NOW,
    )
    .unwrap();
    let error = format!(
        "{:#}",
        ungrant(&two.member, None, "phone", "laptop", &[], NOW + 1).unwrap_err()
    );
    assert!(error.contains("does not own"), "{error}");
}

// ---- certificate rotation (cert-rotation design S6) ----

/// The owner, and a member that has joined: the member's own files are what a renewal changes.
fn joined_member() -> Two {
    let two = two_devices();
    let admitted = admit(&two.owner, None, &two.join_request, "phone", &[], NOW).unwrap();
    join(&two.member, &admitted.token, NOW).unwrap();
    two
}

fn serial_of(home: &Home) -> u32 {
    load_identity(home).unwrap().1.decode().unwrap().serial
}

#[test]
fn a_renewal_without_a_node_writes_the_certificate_and_leaves_the_key_file_as_it_was() {
    let two = joined_member();
    let key_before = fs::read(two.member.identity_key_path()).unwrap();
    let (keys_before, cert_before) = load_identity(&two.member).unwrap();

    let renewed = cert_renew(&two.member, NOW + DAY).unwrap();
    assert_eq!(renewed.serial, 2);

    // The key file is byte for byte what it was; the certificate is the next one for the same
    // keys, valid from a day ago for 400 days, and the token carries it.
    assert_eq!(
        fs::read(two.member.identity_key_path()).unwrap(),
        key_before
    );
    let (keys_after, cert_after) = load_identity(&two.member).unwrap();
    assert_eq!(keys_after.node_id(), keys_before.node_id());
    assert_eq!(cert_after, renewed.cert);
    let (old, new) = (cert_before.decode().unwrap(), cert_after.decode().unwrap());
    assert_eq!((new.serial, new.node_id), (old.serial + 1, old.node_id));
    assert_eq!(new.x25519_pub, old.x25519_pub);
    assert_eq!(new.not_before, NOW);
    assert_eq!(new.not_after - new.not_before, 400 * DAY);
    assert_eq!(renewed.not_after, new.not_after);
    assert_eq!(decode_cert_request(&renewed.token).unwrap(), cert_after);
    assert_eq!(cert_request(&two.member).unwrap(), renewed.token);
    // And again: one more.
    assert_eq!(cert_renew(&two.member, NOW + 2 * DAY).unwrap().serial, 3);
}

#[test]
fn a_renewal_gets_above_every_serial_the_held_documents_list() {
    let two = joined_member();
    // The owner lists a serial 4 certificate of the member (a cert the member's file lost: a
    // restored backup is the usual way to get here).
    let (keys, cert) = load_identity(&two.member).unwrap();
    let four = keys.next_cert(&cert, Some(3), NOW).unwrap();
    assert_eq!(four.decode().unwrap().serial, 4);
    let listed = cert_accept(&two.owner, None, &encode_cert_request(&four), NOW + DAY).unwrap();
    join(&two.member, &listed.token, NOW + DAY).unwrap();
    assert_eq!(serial_of(&two.member), 1);

    let renewed = cert_renew(&two.member, NOW + 2 * DAY).unwrap();
    assert_eq!(
        renewed.serial, 5,
        "one above the highest serial any held Policy lists"
    );
}

#[test]
fn a_renewal_is_refused_while_a_node_runs_and_changes_nothing() {
    let two = joined_member();
    let _node = two.member.lock_node().unwrap();
    let key_before = fs::read(two.member.identity_key_path()).unwrap();
    let cert_before = fs::read(two.member.identity_cert_path()).unwrap();
    let error = format!("{:#}", cert_renew(&two.member, NOW + DAY).unwrap_err());
    assert!(error.contains("`menzil node` is running"), "{error}");
    assert_eq!(
        fs::read(two.member.identity_key_path()).unwrap(),
        key_before
    );
    assert_eq!(
        fs::read(two.member.identity_cert_path()).unwrap(),
        cert_before
    );
}

#[test]
fn the_token_for_the_current_certificate_changes_nothing() {
    let two = joined_member();
    let before = fs::read(two.member.identity_cert_path()).unwrap();
    let token = cert_request(&two.member).unwrap();
    assert!(token.starts_with(crate::token::CERT_PREFIX));
    assert_eq!(
        decode_cert_request(&token).unwrap(),
        load_identity(&two.member).unwrap().1
    );
    assert_eq!(fs::read(two.member.identity_cert_path()).unwrap(), before);
    // No identity: says what to do.
    let (_dir, none) = device();
    assert!(format!("{:#}", cert_request(&none).unwrap_err()).contains("menzil init"));
}

#[test]
fn the_owner_lists_a_members_renewed_certificate_from_its_token() {
    let two = joined_member();
    let renewed = cert_renew(&two.member, NOW + DAY).unwrap();
    let member_id = renewed.cert.decode().unwrap().node_id;

    let issued = cert_accept(&two.owner, None, &renewed.token, NOW + 2 * DAY).unwrap();
    assert_eq!(issued.member, Some(member_id));
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(docs.seq(), issued.seq);
    let serials: Vec<u32> = docs
        .policy_body()
        .certs
        .iter()
        .map(|cert| cert.decode().unwrap())
        .filter(|body| body.node_id == member_id)
        .map(|body| body.serial)
        .collect();
    assert_eq!(
        serials,
        vec![2],
        "the owner's operation replaces the older certificate"
    );

    // The member takes the token and sees its certificate listed.
    join(&two.member, &issued.token, NOW + 2 * DAY).unwrap();
    let report = cert_show(&two.member).unwrap();
    assert_eq!(report.serial, 2);
    assert_eq!(
        report.networks[0].listed.map(|listed| listed.serial),
        Some(2)
    );
    let text = report.render(NOW + 2 * DAY);
    assert!(text.contains("the current certificate is listed"), "{text}");
}

#[test]
fn a_steward_only_device_lists_a_renewal_as_a_rotation() {
    let s = stewarded();
    // The steward admits the phone; the phone joins and renews.
    let admitted = admit(
        &s.two.member,
        None,
        &s.phone_request,
        "phone",
        &[],
        NOW + 20,
    )
    .unwrap();
    join(&s.phone, &admitted.token, NOW + 20).unwrap();
    let renewed = cert_renew(&s.phone, NOW + DAY).unwrap();
    let phone_id = renewed.cert.decode().unwrap().node_id;
    assert!(!s.two.member.owner_key_path(&s.two.network_id).exists());

    let issued = cert_accept(&s.two.member, None, &renewed.token, NOW + 2 * DAY).unwrap();
    assert_eq!(issued.member, Some(phone_id));
    let docs = load_documents(&s.two.member, &s.two.network_id).unwrap();
    assert!(docs.base().is_some(), "a steward's pair carries its base");
    let serials: Vec<u32> = docs
        .policy_body()
        .certs
        .iter()
        .map(|cert| cert.decode().unwrap())
        .filter(|body| body.node_id == phone_id)
        .map(|body| body.serial)
        .collect();
    // The phone was admitted by this steward, so its first certificate is in the tail: the
    // rotation replaces it in place (one tail certificate per member).
    assert_eq!(serials, vec![2]);
    // The phone adopts it.
    join(&s.phone, &issued.token, NOW + 2 * DAY).unwrap();
    assert_eq!(
        cert_show(&s.phone).unwrap().networks[0]
            .listed
            .map(|listed| listed.serial),
        Some(2)
    );
}

#[test]
fn accepting_a_certificate_takes_only_its_own_kind_of_token() {
    let two = joined_member();
    let join_token = cert_request(&two.member)
        .map(|t| t.replace(crate::token::CERT_PREFIX, crate::token::JOIN_PREFIX));
    let error = format!(
        "{:#}",
        cert_accept(&two.owner, None, &join_token.unwrap(), NOW + DAY).unwrap_err()
    );
    assert!(
        error.contains("menzil1-cert:") && error.contains("join request"),
        "{error}"
    );
    // A membership token is no certificate either.
    let docs_token = token(&two.owner, None).unwrap();
    assert!(cert_accept(&two.owner, None, &docs_token, NOW + DAY).is_err());
    // Nothing was issued.
    assert_eq!(
        load_documents(&two.owner, &two.network_id).unwrap().seq(),
        2
    );
    // A certificate that is not newer is refused by the operation, not listed twice.
    let current = cert_request(&two.member).unwrap();
    let error = format!(
        "{:#}",
        cert_accept(&two.owner, None, &current, NOW + DAY).unwrap_err()
    );
    assert!(!error.is_empty());
    assert_eq!(
        load_documents(&two.owner, &two.network_id).unwrap().seq(),
        2
    );
}

#[test]
fn the_certificate_report_says_when_a_network_does_not_list_the_current_one() {
    let two = joined_member();
    cert_renew(&two.member, NOW + DAY).unwrap();
    let report = cert_show(&two.member).unwrap();
    assert_eq!(report.serial, 2);
    let text = report.render(NOW + DAY);
    assert!(text.contains("certificate serial 2"), "{text}");
    assert!(text.contains("lists serial 1"), "{text}");
    assert!(text.contains("NOT listed"), "{text}");
    // Far from expiry: not due for renewal yet.
    assert!(!text.contains("due for renewal"), "{text}");
    // Near expiry it says so.
    let late = report.render(report.not_after - 59 * DAY);
    assert!(late.contains("due for renewal"), "{late}");
    let expired = report.render(report.not_after + 1);
    assert!(expired.contains("EXPIRED"), "{expired}");
}

// ---- new identity and replace (cert-rotation design S7) ----

fn mode_of(path: &std::path::Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn a_new_identity_puts_the_old_one_aside_privately_and_says_where_it_had_a_place() {
    let two = joined_member();
    let (old_keys, old_cert) = load_identity(&two.member).unwrap();
    let old = old_keys.node_id();
    let key_bytes = fs::read(two.member.identity_key_path()).unwrap();
    let docs_before = documents_bytes(&two.member, &two.network_id);

    let done = new_identity(&two.member, NOW + 5).unwrap();

    assert_eq!(done.old, old);
    assert_eq!(done.networks, vec![(two.network_id, "phone".to_string())]);
    // The old files are in `retired/` under the old id and the time, byte for byte.
    let stem = format!("{}-{}", old.to_hex(), NOW + 5);
    assert_eq!(
        done.retired.key,
        two.member.retired_dir().join(format!("{stem}.key"))
    );
    assert_eq!(
        done.retired.cert,
        two.member.retired_dir().join(format!("{stem}.cert"))
    );
    assert_eq!(fs::read(&done.retired.key).unwrap(), key_bytes);
    assert_eq!(fs::read(&done.retired.cert).unwrap(), old_cert.encode());
    assert_eq!(mode_of(&two.member.retired_dir()), 0o700);
    assert_eq!(mode_of(&done.retired.key), 0o600);
    // The home has a whole new identity with a first certificate, that is not the old one.
    let (new_keys, new_cert) = load_identity(&two.member).unwrap();
    assert_ne!(new_keys.node_id(), old);
    assert_eq!(new_keys.node_id(), done.made.node_id);
    assert_eq!(new_cert.decode().unwrap().serial, 1);
    assert_eq!(
        decode_join_request(&done.made.join_request).unwrap(),
        new_cert
    );
    // The documents are not touched.
    assert_eq!(documents_bytes(&two.member, &two.network_id), docs_before);
}

#[test]
fn a_new_identity_is_refused_while_a_node_runs_and_without_an_identity_and_changes_nothing() {
    let two = joined_member();
    let key_before = fs::read(two.member.identity_key_path()).unwrap();
    let cert_before = fs::read(two.member.identity_cert_path()).unwrap();
    {
        let _node = two.member.lock_node().unwrap();
        let error = format!("{:#}", new_identity(&two.member, NOW + 5).unwrap_err());
        assert!(error.contains("`menzil node` is running"), "{error}");
    }
    assert_eq!(
        fs::read(two.member.identity_key_path()).unwrap(),
        key_before
    );
    assert_eq!(
        fs::read(two.member.identity_cert_path()).unwrap(),
        cert_before
    );
    assert!(!two.member.retired_dir().exists());

    let (_dir, empty) = device();
    let error = format!("{:#}", new_identity(&empty, NOW).unwrap_err());
    assert!(error.contains("no identity"), "{error}");
    assert!(!empty.retired_dir().exists());
}

#[test]
fn the_key_moves_last_so_a_failure_before_it_leaves_the_identity_whole() {
    let two = joined_member();
    let (keys, cert) = load_identity(&two.member).unwrap();
    let old = keys.node_id();
    let key_before = fs::read(two.member.identity_key_path()).unwrap();
    let stem = format!("{}-{}", old.to_hex(), NOW + 5);

    // The certificate cannot be put aside (its place is a directory with something in it): the
    // key has not moved, the identity is whole, and nothing new was made.
    let cert_to = two.member.retired_dir().join(format!("{stem}.cert"));
    fs::create_dir_all(cert_to.join("in the way")).unwrap();
    assert!(new_identity(&two.member, NOW + 5).is_err());
    assert_eq!(
        fs::read(two.member.identity_key_path()).unwrap(),
        key_before
    );
    assert_eq!(load_identity(&two.member).unwrap().1, cert);
    assert!(
        !two.member
            .retired_dir()
            .join(format!("{stem}.key"))
            .exists()
    );
    fs::remove_dir_all(&cert_to).unwrap();

    // A retired key of that name is never replaced: refused before anything moves.
    let key_to = two.member.retired_dir().join(format!("{stem}.key"));
    fs::write(&key_to, b"an earlier key").unwrap();
    assert!(new_identity(&two.member, NOW + 5).is_err());
    assert_eq!(fs::read(&key_to).unwrap(), b"an earlier key");
    assert_eq!(
        fs::read(two.member.identity_key_path()).unwrap(),
        key_before
    );
    assert!(!cert_to.exists(), "the certificate was not copied either");
    fs::remove_file(&key_to).unwrap();

    // Once nothing is in the way it goes through.
    assert_eq!(new_identity(&two.member, NOW + 5).unwrap().old, old);
}

#[test]
fn a_new_identity_leaves_the_owner_key_and_the_documents_of_an_owner_device_alone() {
    let two = two_devices();
    let owner_key = fs::read(two.owner.owner_key_path(&two.network_id)).unwrap();
    let docs = documents_bytes(&two.owner, &two.network_id);
    let done = new_identity(&two.owner, NOW + 1).unwrap();
    assert_eq!(done.networks, vec![(two.network_id, "laptop".to_string())]);
    assert_eq!(
        fs::read(two.owner.owner_key_path(&two.network_id)).unwrap(),
        owner_key
    );
    assert_eq!(documents_bytes(&two.owner, &two.network_id), docs);
    assert!(!two.owner.retired_dir().join("owner").exists());
}

/// `joined_member`, then the member makes a new identity: the owner is to move the place.
fn moved_member() -> (Two, NewIdentity, NodeId) {
    let two = joined_member();
    let old = load_identity(&two.member).unwrap().0.node_id();
    let done = new_identity(&two.member, NOW + 5).unwrap();
    (two, done, old)
}

#[test]
fn the_owner_moves_the_place_to_the_new_identity_and_the_old_one_is_revoked() {
    let (two, done, old) = moved_member();
    let granted = grant(
        &two.owner,
        None,
        "phone",
        "laptop",
        &[service("tcp:ssh")],
        None,
        NOW + 2,
    )
    .unwrap();
    assert_eq!(granted.seq, 3);
    let (_, name) = &done.networks[0];

    let mut token = String::new();
    for who in [name.clone(), old.to_hex()[..8].to_string(), old.to_hex()] {
        // The same replacement three ways to name the member: each on a copy of the state.
        let copy = tempfile::tempdir().unwrap();
        let home = Home::new(copy.path().join("owner"));
        copy_dir(two.owner.root(), home.root());
        let replaced = replace(&home, None, &who, &done.made.join_request, NOW + 10).unwrap();
        assert_eq!(replaced.old, old, "{who}");
        assert_eq!(replaced.name, "phone");
        assert_eq!(replaced.issued.member, Some(done.made.node_id));
        assert_eq!(replaced.issued.seq, 4);
        let docs = load_documents(&home, &two.network_id).unwrap();
        assert!(docs.is_member(&done.made.node_id));
        assert!(!docs.is_member(&old));
        assert_eq!(docs.roster_body().revoked.len(), 1);
        assert_eq!(docs.roster_body().revoked[0].node_id, old);
        // The grant moved: the new node is the `from` of it.
        let grants = &docs.policy_body().grants;
        assert_eq!(grants.len(), 1, "{who}");
        assert_eq!(
            grants[0].from.target,
            PrincipalTarget::Node(done.made.node_id)
        );
        token = replaced.issued.token;
    }
    // The new device installs the token and is a member with the old one's name.
    join(&two.member, &token, NOW + 11).unwrap();
    let report = status(&two.member).unwrap();
    assert_eq!(report.networks[0].members.len(), 2);
    assert!(
        report.networks[0]
            .members
            .iter()
            .any(|m| m.name == "phone" && m.node_id == done.made.node_id)
    );
}

/// Copies a home directory (files and directories only), so that one state can be used again.
fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[test]
fn replace_refuses_a_steward_only_device_this_devices_own_node_and_a_stranger() {
    let (two, done, old) = moved_member();
    let (_, name) = done.networks[0].clone();

    // A steward only device is told that the owner revokes, and nothing changes.
    let s = stewarded();
    let held = documents_bytes(&s.two.member, &s.two.network_id);
    let error = format!(
        "{:#}",
        replace(&s.two.member, None, "steward", &s.phone_request, NOW + 20).unwrap_err()
    );
    assert!(error.contains("only the owner revokes"), "{error}");
    assert_eq!(documents_bytes(&s.two.member, &s.two.network_id), held);

    // The owner's own node: refused as `revoke` does.
    let error = format!(
        "{:#}",
        replace(
            &two.owner,
            None,
            "laptop",
            &done.made.join_request,
            NOW + 20
        )
        .unwrap_err()
    );
    assert!(error.contains("--self"), "{error}");

    // Nobody of that name; and a join request that is not one.
    let docs = documents_bytes(&two.owner, &two.network_id);
    let error = format!(
        "{:#}",
        replace(
            &two.owner,
            None,
            "nobody",
            &done.made.join_request,
            NOW + 20
        )
        .unwrap_err()
    );
    assert!(error.contains("no member called"), "{error}");
    let error = replace(&two.owner, None, &name, "menzil1-join:garbage", NOW + 20);
    assert!(error.is_err());
    assert_eq!(documents_bytes(&two.owner, &two.network_id), docs);

    // Once replaced, replacing the revoked one again is refused as such.
    replace(&two.owner, None, &name, &done.made.join_request, NOW + 30).unwrap();
    let (_dir, third) = device();
    let third_request = init(&third, NOW).unwrap().join_request;
    let error = format!(
        "{:#}",
        replace(&two.owner, None, &old.to_hex(), &third_request, NOW + 40).unwrap_err()
    );
    assert!(error.contains("revoked already"), "{error}");
}

// ---- labels: `menzil label add`, `remove`, `list` ----

fn labels(home: &Home, network_id: &NetworkId) -> Vec<(String, NodeId)> {
    load_documents(home, network_id)
        .unwrap()
        .roster_body()
        .labels
        .iter()
        .map(|l| (l.name.clone(), l.node_id))
        .collect()
}

fn err<T>(result: Result<T>) -> String {
    format!("{:#}", result.err().expect("an error"))
}

/// What a relay does with an ADVERTISE of `names` from `node` after it holds `docs`' Roster.
fn relay_accepts(docs: &Documents, node: &NodeId, names: &[&str]) -> (Vec<String>, Vec<String>) {
    use menzil_proto::{AdvertiseBody, PROTOCOL_VERSION, Share, ShareMode};
    let rosters = menzil_relay::RosterStore::new();
    assert!(rosters.set(docs.roster()).unwrap());
    let body = AdvertiseBody {
        v: PROTOCOL_VERSION,
        shares: names
            .iter()
            .map(|name| Share {
                name: name.to_string(),
                mode: ShareMode::Blind,
                service: service("tcp:ssh"),
                alpn: vec![],
            })
            .collect(),
        accept_peers: true,
    };
    let ack = menzil_relay::LabelRegistry::new().advertise(
        &rosters,
        &menzil_relay::TenantBook::default(),
        &[docs.network_id()],
        node,
        &body,
        NOW,
    );
    (
        ack.accepted,
        ack.rejected.into_iter().map(|r| r.reason).collect(),
    )
}

#[test]
fn a_label_given_by_the_owner_is_what_a_relay_needs_to_accept_the_name() {
    let (two, phone) = with_phone();
    let laptop = load_identity(&two.owner).unwrap().0.node_id();
    let seq_before = load_documents(&two.owner, &two.network_id).unwrap().seq();

    // Before: the relay holds the Roster and turns the name away.
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    let (accepted, rejected) = relay_accepts(&docs, &phone, &["app"]);
    assert!(accepted.is_empty());
    assert_eq!(rejected.len(), 1);

    let added = label_add(&two.owner, None, "app", "phone", false, NOW + 1).unwrap();
    assert_eq!(added.issued.seq, seq_before + 1);
    assert_eq!(added.issued.member, Some(phone));
    assert_eq!(added.member_name, "phone");
    assert_eq!(added.moved_from, None);
    assert_eq!(
        labels(&two.owner, &two.network_id),
        vec![("app".into(), phone)]
    );

    // The token is the pair the owner now holds; the Roster for a relay says the same.
    assert_eq!(
        decode_documents(&added.issued.token).unwrap().seq(),
        added.issued.seq
    );
    let relay_token = token_for_relay(&two.owner, None).unwrap();
    assert!(relay_token.starts_with(crate::token::ROSTER_PREFIX));

    // After: the relay takes the name from the phone and not from the laptop, and still
    // turns away a name nobody was given.
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(relay_accepts(&docs, &phone, &["app"]).0, vec!["app"]);
    let (accepted, rejected) = relay_accepts(&docs, &laptop, &["app"]);
    assert!(accepted.is_empty() && rejected.len() == 1);
    assert!(relay_accepts(&docs, &phone, &["other"]).0.is_empty());

    // The member joins with the token and sees the same list; the name by a node id prefix
    // works too.
    assert!(matches!(
        join(&two.member, &added.issued.token, NOW + 2).unwrap(),
        Joined::Updated { .. }
    ));
    let (_, listed) = label_list(&two.member, None).unwrap();
    assert_eq!(
        listed,
        vec![LabelEntry {
            name: "app".into(),
            node_id: phone,
            member: Some("phone".into())
        }]
    );
    let by_prefix = label_add(
        &two.owner,
        None,
        "blog",
        &phone.to_hex()[..8],
        false,
        NOW + 3,
    )
    .unwrap();
    assert_eq!(by_prefix.member_name, "phone");
    assert_eq!(by_prefix.issued.seq, added.issued.seq + 1);
}

#[test]
fn a_label_moves_only_with_replace_and_removing_it_closes_the_door_again() {
    let (two, phone) = with_phone();
    let laptop = load_identity(&two.owner).unwrap().0.node_id();
    label_add(&two.owner, None, "app", "phone", false, NOW).unwrap();
    let held = documents_bytes(&two.owner, &two.network_id);

    // Another member, the same member, each refused with the documents untouched.
    assert!(
        err(label_add(&two.owner, None, "app", "laptop", false, NOW + 1))
            .contains("belongs to another member")
    );
    assert!(
        err(label_add(&two.owner, None, "app", "phone", false, NOW + 1))
            .contains("this member's already")
    );
    assert_eq!(documents_bytes(&two.owner, &two.network_id), held);

    let moved = label_add(&two.owner, None, "app", "laptop", true, NOW + 2).unwrap();
    assert_eq!(moved.moved_from.as_deref(), Some("phone"));
    assert_eq!(moved.member_name, "laptop");
    assert_eq!(
        labels(&two.owner, &two.network_id),
        vec![("app".into(), laptop)]
    );
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert_eq!(relay_accepts(&docs, &laptop, &["app"]).0, vec!["app"]);
    assert!(relay_accepts(&docs, &phone, &["app"]).0.is_empty());

    // Remove: nothing to remove, then by the wrong member, then the right one.
    assert!(
        err(label_remove(&two.owner, None, "nope", None, NOW + 3)).contains("no label matches")
    );
    assert!(
        err(label_remove(
            &two.owner,
            None,
            "app",
            Some("phone"),
            NOW + 3
        ))
        .contains("no label matches")
    );
    assert!(
        err(label_remove(
            &two.owner,
            None,
            "app",
            Some("tablet"),
            NOW + 3
        ))
        .contains("no member called")
    );
    let seq = load_documents(&two.owner, &two.network_id).unwrap().seq();
    let removed = label_remove(&two.owner, None, "app", Some("laptop"), NOW + 4).unwrap();
    assert_eq!(removed.seq, seq + 1);
    assert_eq!(decode_documents(&removed.token).unwrap().seq(), seq + 1);
    assert!(labels(&two.owner, &two.network_id).is_empty());
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert!(relay_accepts(&docs, &laptop, &["app"]).0.is_empty());

    // With no member named, whoever has it loses it.
    label_add(&two.owner, None, "web", "phone", false, NOW + 5).unwrap();
    label_remove(&two.owner, None, "web", None, NOW + 6).unwrap();
    assert!(labels(&two.owner, &two.network_id).is_empty());
    let (_, none) = label_list(&two.owner, None).unwrap();
    assert!(none.is_empty());
}

#[test]
fn a_label_that_is_not_a_plain_unreserved_name_or_names_no_member_is_refused_untouched() {
    let (two, _phone) = with_phone();
    let held = documents_bytes(&two.owner, &two.network_id);
    let long = "a".repeat(64);
    for bad in [
        "",
        "-a",
        "a-",
        "App",
        "a.b",
        "a b",
        "a_b",
        "caf\u{e9}",
        "a\u{202e}b",
        "a\nb",
        long.as_str(),
    ] {
        let error = err(label_add(&two.owner, None, bad, "phone", false, NOW + 1));
        assert!(
            error.contains("must be 1 to 63 lowercase"),
            "{bad:?}: {error}"
        );
        assert!(
            !error.contains('\u{202e}') && !error.contains('\n'),
            "{error:?}"
        );
    }
    // Every name the relay reserves for all claims is refused here too.
    for reserved in menzil_relay::DEFAULT_RESERVED_LABELS {
        let error = err(label_add(
            &two.owner,
            None,
            reserved,
            "phone",
            false,
            NOW + 1,
        ));
        assert!(error.contains("is reserved"), "{reserved}: {error}");
        // `--replace` does not get past it.
        assert!(
            err(label_add(
                &two.owner,
                None,
                reserved,
                "phone",
                true,
                NOW + 1
            ))
            .contains("is reserved")
        );
    }
    assert!(!menzil_relay::DEFAULT_RESERVED_LABELS.is_empty());
    // A member that is not there, a node id prefix too short to be one, a revoked member.
    let hex = load_documents(&two.owner, &two.network_id)
        .unwrap()
        .roster_body()
        .members[1]
        .node_id
        .to_hex();
    for who in ["tablet", "", "Phone", &hex[..7], "zzzzzzzz"] {
        let error = err(label_add(&two.owner, None, "app", who, false, NOW + 1));
        assert!(error.contains("no member called"), "{who:?}: {error}");
    }
    assert_eq!(documents_bytes(&two.owner, &two.network_id), held);
    revoke(&two.owner, None, "phone", false, NOW + 2).unwrap();
    let after_revoke = documents_bytes(&two.owner, &two.network_id);
    assert!(
        err(label_add(&two.owner, None, "app", "phone", false, NOW + 3))
            .contains("no member called")
    );
    assert_eq!(documents_bytes(&two.owner, &two.network_id), after_revoke);
}

#[test]
fn only_the_owner_changes_labels_and_a_steward_is_told_so_in_plain_words() {
    let s = stewarded();
    let (two, steward_device) = (&s.two, &s.two.member);
    label_add(&two.owner, None, "app", "steward", false, NOW + 20).unwrap();
    // The steward device holds the documents of the owner's new pair.
    let token = token(&two.owner, None).unwrap();
    join(steward_device, &token, NOW + 21).unwrap();
    let held = documents_bytes(steward_device, &two.network_id);

    let error = err(label_add(
        steward_device,
        None,
        "blog",
        "steward",
        false,
        NOW + 22,
    ));
    assert!(
        error.contains("only the owner lists or takes back labels"),
        "{error}"
    );
    let error = err(label_remove(steward_device, None, "app", None, NOW + 22));
    assert!(
        error.contains("only the owner lists or takes back labels"),
        "{error}"
    );
    assert_eq!(documents_bytes(steward_device, &two.network_id), held);
    // Reading is for everyone.
    assert_eq!(label_list(steward_device, None).unwrap().1.len(), 1);

    // A plain member (no key at all) is refused as for a grant.
    let (plain, _) = with_phone();
    assert!(
        err(label_add(&plain.member, None, "app", "laptop", false, NOW)).contains("does not own")
    );
    assert!(err(label_remove(&plain.member, None, "app", None, NOW)).contains("does not own"));

    // The owner's pair after a steward's pair goes past what the steward can sign, and the
    // steward's later re-issue keeps the label.
    let owner_seq = load_documents(&two.owner, &two.network_id).unwrap().seq();
    let renewed = renew(steward_device, None, NOW + 30).unwrap();
    assert!(renewed.seq > owner_seq);
    let docs = load_documents(steward_device, &two.network_id).unwrap();
    assert_eq!(docs.roster_body().labels.len(), 1);
    let added = label_add(&two.owner, None, "blog", "steward", false, NOW + 31).unwrap();
    assert!(added.issued.seq > renewed.seq);
}

#[test]
fn revoking_a_member_takes_its_labels_and_the_relay_stops_taking_its_names() {
    let (two, phone) = with_phone();
    label_add(&two.owner, None, "app", "phone", false, NOW).unwrap();
    label_add(&two.owner, None, "blog", "phone", false, NOW).unwrap();
    assert_eq!(labels(&two.owner, &two.network_id).len(), 2);
    revoke(&two.owner, None, "phone", false, NOW + 1).unwrap();
    assert!(labels(&two.owner, &two.network_id).is_empty());
    let docs = load_documents(&two.owner, &two.network_id).unwrap();
    assert!(relay_accepts(&docs, &phone, &["app"]).0.is_empty());
}
