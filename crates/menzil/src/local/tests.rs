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
