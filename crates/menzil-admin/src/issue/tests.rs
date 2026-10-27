use ed25519_dalek::SigningKey;
use menzil_node::{PolicyStore, RosterStore};
use menzil_proto::{
    ErrorCode, NodeCertBody, NodeOrWildcard, Principal, RevokedMember, ServiceId, X25519PublicKey,
};

use super::*;
use crate::NodeKeys;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 24 * 60 * 60;

fn node() -> (NodeKeys, NodeCert) {
    let keys = NodeKeys::generate();
    let cert = keys
        .issue_cert(1, NOW - 100, NOW - 100 + 400 * DAY)
        .unwrap();
    (keys, cert)
}

fn service(s: &str) -> ServiceId {
    s.parse().unwrap()
}

fn node_grant(network_id: NetworkId, from: NodeId, to: NodeId, services: &[&str]) -> Grant {
    Grant {
        from: Principal {
            network_id,
            target: PrincipalTarget::Node(from),
        },
        to_node: NodeOrWildcard::Node(to),
        services: services.iter().map(|s| service(s)).collect(),
        expires: None,
    }
}

/// A network with a founder named "laptop", plus the stores a node loads it into.
fn founded() -> (OwnerKey, NodeKeys, NodeCert, Documents) {
    let owner = OwnerKey::generate();
    let (keys, cert) = node();
    let docs = create_network(&owner, &cert, "laptop", NOW).unwrap();
    (owner, keys, cert, docs)
}

fn load(docs: &Documents) -> (RosterStore, PolicyStore) {
    let (rosters, policies) = (RosterStore::new(), PolicyStore::new());
    assert!(rosters.set(docs.roster()).unwrap());
    assert!(policies.set(docs.policy()).unwrap());
    (rosters, policies)
}

#[test]
fn a_new_network_is_a_pair_every_verifier_accepts() {
    let (owner, keys, cert, docs) = founded();
    let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(owner.network_id())).unwrap();
    docs.roster().verify(&key).unwrap();
    docs.policy().verify(&key).unwrap();

    assert_eq!(docs.seq(), 1);
    assert_eq!(docs.network_id(), owner.network_id());
    let (roster, policy) = (docs.roster_body(), docs.policy_body());
    assert_eq!((roster.issued, roster.expires), (NOW, NOW + 14 * DAY));
    assert_eq!((policy.issued, policy.expires), (NOW, NOW + 14 * DAY));
    assert_eq!(roster.members.len(), 1);
    assert_eq!(roster.members[0].node_id, keys.node_id());
    assert_eq!(roster.members[0].min_serial, 1);
    assert_eq!(policy.members[0].name, "laptop");
    assert_eq!(policy.certs, vec![cert]);
    assert!(policy.grants.is_empty() && roster.revoked.is_empty());

    // The stores a node and a relay keep accept them, and the founder is a
    // member in good standing until the documents expire.
    let (rosters, policies) = load(&docs);
    let ok = |at| policies.check_membership(&rosters, &docs.network_id(), &keys.node_id(), 1, at);
    assert_eq!(ok(NOW), Ok(()));
    assert_eq!(ok(NOW + 14 * DAY - 1), Ok(()));
    assert_eq!(ok(NOW + 14 * DAY), Err(ErrorCode::RosterExpired));
}

#[test]
fn admitting_adds_the_member_to_both_documents_and_leaves_the_old_pair_alone() {
    let (owner, keys, _cert, docs) = founded();
    let (phone, phone_cert) = node();
    let admitted = admit(
        &owner,
        &docs,
        &phone_cert,
        "phone",
        &["family".to_string()],
        NOW + 60,
    )
    .unwrap();

    assert_eq!(admitted.seq(), 2);
    assert_eq!(admitted.roster_body().members.len(), 2);
    let member = &admitted.roster_body().members[1];
    assert_eq!((member.node_id, member.min_serial), (phone.node_id(), 1));
    let named = &admitted.policy_body().members[1];
    assert_eq!(named.name, "phone");
    assert_eq!(named.roles, vec!["family".to_string()]);
    assert_eq!(admitted.policy_body().certs.len(), 2);
    assert_eq!(admitted.policy_body().certs[1], phone_cert);
    assert_eq!(admitted.roster_body().issued, NOW + 60);
    assert_eq!(admitted.roster_body().expires, NOW + 60 + 14 * DAY);
    // Nothing is shared with the previous pair.
    assert_eq!(docs.seq(), 1);
    assert_eq!(docs.roster_body().members.len(), 1);

    // A node holding the first pair takes the second as the newer one, and
    // both members then pass the membership check.
    let (rosters, policies) = load(&docs);
    assert!(rosters.set(admitted.roster()).unwrap());
    assert!(policies.set(admitted.policy()).unwrap());
    for id in [keys.node_id(), phone.node_id()] {
        assert_eq!(
            policies.check_membership(&rosters, &admitted.network_id(), &id, 1, NOW + 60),
            Ok(())
        );
    }
    // Admitted, but allowed to reach nothing yet.
    assert!(!policies.has_grant(
        &rosters,
        &admitted.network_id(),
        &phone.node_id(),
        &keys.node_id(),
        Some(&service("tcp:ssh")),
        NOW + 60
    ));
}

#[test]
fn a_grant_opens_exactly_the_service_it_names() {
    let (owner, laptop, _, docs) = founded();
    let (phone, phone_cert) = node();
    let docs = admit(&owner, &docs, &phone_cert, "phone", &[], NOW).unwrap();
    let docs = grant(
        &owner,
        &docs,
        node_grant(
            docs.network_id(),
            phone.node_id(),
            laptop.node_id(),
            &["tcp:ssh"],
        ),
        NOW,
    )
    .unwrap();
    assert_eq!(docs.seq(), 3);
    assert_eq!(docs.policy_body().grants.len(), 1);

    let (rosters, policies) = load(&docs);
    let can = |from: &NodeKeys, to: &NodeKeys, s: &str| {
        policies.has_grant(
            &rosters,
            &docs.network_id(),
            &from.node_id(),
            &to.node_id(),
            Some(&service(s)),
            NOW,
        )
    };
    assert!(can(&phone, &laptop, "tcp:ssh"));
    assert!(!can(&phone, &laptop, "tcp:other"));
    assert!(!can(&laptop, &phone, "tcp:ssh"), "grants are directional");
}

#[test]
fn a_grant_may_name_a_role_or_every_node() {
    let (owner, _laptop, _, docs) = founded();
    let network_id = docs.network_id();
    let role = Grant {
        from: Principal {
            network_id,
            target: PrincipalTarget::Role("family".to_string()),
        },
        to_node: NodeOrWildcard::Any,
        services: vec![service("tcp:ssh")],
        expires: Some(NOW + DAY),
    };
    let docs = grant(&owner, &docs, role.clone(), NOW).unwrap();
    assert_eq!(docs.policy_body().grants, vec![role]);
}

#[test]
fn renewing_keeps_the_content_and_moves_the_lifetime() {
    let (owner, laptop, _, docs) = founded();
    let (phone, phone_cert) = node();
    let docs = admit(&owner, &docs, &phone_cert, "phone", &[], NOW).unwrap();
    let docs = grant(
        &owner,
        &docs,
        node_grant(
            docs.network_id(),
            phone.node_id(),
            laptop.node_id(),
            &["tcp:ssh"],
        ),
        NOW,
    )
    .unwrap();

    let later = NOW + 10 * DAY;
    let renewed = renew(&owner, &docs, later).unwrap();
    assert_eq!(renewed.seq(), docs.seq() + 1);
    assert_eq!(renewed.roster_body().issued, later);
    assert_eq!(renewed.policy_body().issued, later);
    assert_eq!(renewed.roster_body().expires, later + 14 * DAY);
    assert_eq!(renewed.policy_body().expires, later + 14 * DAY);
    assert_eq!(renewed.roster_body().members, docs.roster_body().members);
    assert_eq!(renewed.policy_body().members, docs.policy_body().members);
    assert_eq!(renewed.policy_body().certs, docs.policy_body().certs);
    assert_eq!(renewed.policy_body().grants, docs.policy_body().grants);

    // The old pair has run out by then, the renewed one has not.
    let (rosters, policies) = load(&docs);
    let at = later + 5 * DAY;
    let standing = |p: &PolicyStore, r: &RosterStore| {
        p.check_membership(r, &docs.network_id(), &phone.node_id(), 1, at)
    };
    assert_eq!(standing(&policies, &rosters), Err(ErrorCode::RosterExpired));
    assert!(rosters.set(renewed.roster()).unwrap());
    assert!(policies.set(renewed.policy()).unwrap());
    assert_eq!(standing(&policies, &rosters), Ok(()));
}

#[test]
fn a_certificate_that_does_not_verify_against_its_own_node_id_is_refused() {
    let (owner, _laptop, _, docs) = founded();
    let (victim, _) = node();
    let thief = SigningKey::generate(&mut rand::rng());
    // Signed by a key that is not the NodeId it claims.
    let forged = NodeCert::sign(
        &thief,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: victim.node_id(),
            x25519_pub: X25519PublicKey::from([9u8; 32]),
            serial: 1,
            not_before: NOW - 1,
            not_after: NOW + DAY,
        },
    )
    .unwrap();
    assert!(matches!(
        admit(&owner, &docs, &forged, "victim", &[], NOW),
        Err(AdminError::CertDoesNotVerify)
    ));
    assert!(matches!(
        create_network(&OwnerKey::generate(), &forged, "x", NOW),
        Err(AdminError::CertDoesNotVerify)
    ));
}

#[test]
fn a_certificate_outside_its_validity_window_is_refused() {
    let (owner, _laptop, _, docs) = founded();
    let keys = NodeKeys::generate();
    let expired = keys.issue_cert(1, NOW - 2 * DAY, NOW - DAY).unwrap();
    let early = keys.issue_cert(1, NOW + DAY, NOW + 2 * DAY).unwrap();
    for cert in [&expired, &early] {
        assert!(matches!(
            admit(&owner, &docs, cert, "late", &[], NOW),
            Err(AdminError::CertNotValidNow)
        ));
    }
}

#[test]
fn a_member_cannot_be_admitted_twice_and_names_are_unique() {
    let (owner, _laptop, laptop_cert, docs) = founded();
    assert!(matches!(
        admit(&owner, &docs, &laptop_cert, "again", &[], NOW),
        Err(AdminError::AlreadyMember(_))
    ));
    let (_, other_cert) = node();
    assert!(matches!(
        admit(&owner, &docs, &other_cert, "laptop", &[], NOW),
        Err(AdminError::NameTaken(name)) if name == "laptop"
    ));
}

/// The one table of invisible characters, for names and for the text that reaches a terminal.
#[test]
fn invisible_characters_are_told_from_visible_ones() {
    for c in [
        '\u{ad}',
        '\u{34f}',
        '\u{600}',
        '\u{61c}',
        '\u{115f}',
        '\u{1160}',
        '\u{17b4}',
        '\u{180b}',
        '\u{180e}',
        '\u{200b}',
        '\u{200d}',
        '\u{200f}',
        '\u{202a}',
        '\u{202e}',
        '\u{2060}',
        '\u{2065}',
        '\u{2069}',
        '\u{206f}',
        '\u{3164}',
        '\u{fe00}',
        '\u{fe0f}',
        '\u{feff}',
        '\u{ffa0}',
        '\u{fff0}',
        '\u{fffb}',
        '\u{e0001}',
        '\u{e0041}',
        '\u{e007f}',
        '\u{e0100}',
    ] {
        assert!(crate::is_invisible(c), "{c:?}");
    }
    for c in [
        'a',
        'Z',
        '0',
        '-',
        '_',
        '.',
        ' ',
        'ü',
        'ğ',
        'ı',
        'あ',
        '字',
        '\u{200a}',
        '\u{2028}',
        '\u{fffc}',
        '\u{fffd}',
        '\u{1f600}',
        '\u{5b0}',
    ] {
        assert!(!crate::is_invisible(c), "{c:?}");
    }
}

#[test]
fn names_that_cannot_head_an_address_are_refused() {
    let (owner, _laptop, _, docs) = founded();
    let long = "a".repeat(64);
    for bad in [
        "",
        "a/b",
        "a b",
        "tab\t",
        "new\nline",
        "nul\0",
        "a:b",
        "a,b",
        "right\u{202e}left",
        "zero\u{200b}width",
        "emoji\u{1f600}",
        // The fourth round, N1: letters and marks that print as nothing.
        "hangul\u{3164}filler",
        "\u{3164}",
        "x\u{115f}y",
        "\u{ffa0}x",
        "selector\u{fe0f}",
        "joiner\u{34f}x",
        "tag\u{e0041}",
        // Not names a person could type into an address: dots only, or a leading mark.
        ".",
        "..",
        ".hidden",
        "-flag",
        "_private",
        long.as_str(),
    ] {
        let (_, cert) = node();
        assert!(
            matches!(
                admit(&owner, &docs, &cert, bad, &[], NOW),
                Err(AdminError::BadName(_))
            ),
            "{bad:?}"
        );
    }
    for good in [
        "a",
        "my-phone",
        "Phone_2",
        "ünlü",
        "host.lan",
        &"z".repeat(63),
    ] {
        let (_, cert) = node();
        admit(&owner, &docs, &cert, good, &[], NOW).unwrap_or_else(|e| panic!("{good:?}: {e}"));
    }
    let (_, cert) = node();
    assert!(matches!(
        create_network(&OwnerKey::generate(), &cert, "a/b", NOW),
        Err(AdminError::BadName(_))
    ));
}

#[test]
fn only_the_owner_can_extend_the_documents() {
    let (_owner, _laptop, _, docs) = founded();
    let (_, cert) = node();
    // Another owner key: the documents are not its network's.
    let stranger = OwnerKey::generate();
    assert!(matches!(
        admit(&stranger, &docs, &cert, "x", &[], NOW),
        Err(AdminError::NotThisOwner)
    ));
    assert!(matches!(
        renew(&stranger, &docs, NOW),
        Err(AdminError::NotThisOwner)
    ));

    // Documents that name the owner's network but carry someone else's
    // signature are refused, whoever asks.
    let owner = OwnerKey::generate();
    let thief = SigningKey::generate(&mut rand::rng());
    let body = docs.roster_body().clone();
    let forged_roster = Roster::sign(
        &thief,
        &RosterBody {
            network_id: owner.network_id(),
            ..body
        },
    )
    .unwrap();
    let forged_policy = Policy::sign(
        &thief,
        &PolicyBody {
            network_id: owner.network_id(),
            ..docs.policy_body().clone()
        },
    )
    .unwrap();
    let forged = Documents::from_signed(forged_roster, forged_policy).unwrap();
    assert!(matches!(
        renew(&owner, &forged, NOW),
        Err(AdminError::Proto(_))
    ));
}

#[test]
fn documents_that_are_not_a_pair_are_refused() {
    let (owner, _laptop, _, docs) = founded();
    let (_, cert) = node();
    let newer = admit(&owner, &docs, &cert, "phone", &[], NOW).unwrap();
    assert!(matches!(
        Documents::from_signed(docs.roster().clone(), newer.policy().clone()),
        Err(AdminError::MismatchedDocuments(_))
    ));
    let (other_owner, _, _, other) = founded();
    let _ = other_owner;
    assert!(matches!(
        Documents::from_signed(docs.roster().clone(), other.policy().clone()),
        Err(AdminError::MismatchedDocuments(_))
    ));
    // The pair is rebuilt from what a node's stores hold.
    let (rosters, policies) = load(&newer);
    let again = Documents::from_signed(
        rosters.get(&newer.network_id()).unwrap(),
        policies.get(&newer.network_id()).unwrap(),
    )
    .unwrap();
    let next = renew(&owner, &again, NOW + DAY).unwrap();
    assert_eq!(next.seq(), 3);
}

#[test]
fn a_grant_must_make_sense_for_this_network() {
    let (owner, laptop, _, docs) = founded();
    let network_id = docs.network_id();
    let stranger = NodeKeys::generate();

    let foreign = node_grant(
        OwnerKey::generate().network_id(),
        laptop.node_id(),
        laptop.node_id(),
        &["tcp:ssh"],
    );
    assert!(matches!(
        grant(&owner, &docs, foreign, NOW),
        Err(AdminError::ForeignGrant)
    ));
    assert!(matches!(
        grant(
            &owner,
            &docs,
            node_grant(network_id, laptop.node_id(), laptop.node_id(), &[]),
            NOW
        ),
        Err(AdminError::EmptyGrant)
    ));
    for (from, to) in [
        (stranger.node_id(), laptop.node_id()),
        (laptop.node_id(), stranger.node_id()),
    ] {
        assert!(matches!(
            grant(&owner, &docs, node_grant(network_id, from, to, &["tcp:ssh"]), NOW),
            Err(AdminError::NotAMember(id)) if id == stranger.node_id()
        ));
    }
}

#[test]
fn a_document_over_the_size_verifiers_accept_is_refused_not_issued() {
    let (owner, laptop, _, docs) = founded();
    // About 2 MB of service patterns, twice what verifiers accept.
    let services: Vec<String> = (0..100_000)
        .map(|i| format!("tcp:service-{i:06}"))
        .collect();
    let services: Vec<&str> = services.iter().map(String::as_str).collect();
    let huge = node_grant(
        docs.network_id(),
        laptop.node_id(),
        laptop.node_id(),
        &services,
    );
    match grant(&owner, &docs, huge, NOW) {
        Err(AdminError::TooLarge { what, len, max }) => {
            assert_eq!(what, "Policy");
            assert!(len > max && max == MAX_DOC_BYTES);
        }
        Err(other) => panic!("expected TooLarge, got {other}"),
        Ok(issued) => panic!(
            "a {} byte Policy was issued",
            issued.policy().encode().len()
        ),
    }
}

#[test]
fn a_sequence_number_at_its_maximum_cannot_be_extended() {
    let (owner, _laptop, _, docs) = founded();
    let mut roster = docs.roster_body().clone();
    let mut policy = docs.policy_body().clone();
    roster.seq = u64::MAX;
    policy.seq = u64::MAX;
    let top = Documents::signed(&owner, roster, policy).unwrap();
    assert!(matches!(
        renew(&owner, &top, NOW),
        Err(AdminError::SeqOverflow)
    ));
}

/// The issuer owes protocol.md 2.2's 400 days: no verifier checks it.
#[test]
fn a_certificate_valid_for_longer_than_400_days_is_not_accepted_to_join() {
    let (owner, _laptop, _, docs) = founded();
    let keys = NodeKeys::generate();
    // `issue_cert` refuses such a window, so the certificate is built by hand.
    let cert_with = |extra: u64| {
        let body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: keys.node_id(),
            x25519_pub: keys.x25519_public(),
            serial: 1,
            not_before: NOW - 100,
            not_after: NOW - 100 + 400 * DAY + extra,
        };
        NodeCert::sign(keys.signing_key(), &body).unwrap()
    };
    admit(&owner, &docs, &cert_with(0), "exactly", &[], NOW).unwrap();
    for extra in [1, 100 * DAY, u64::MAX / 2] {
        assert!(
            matches!(
                admit(&owner, &docs, &cert_with(extra), "long", &[], NOW),
                Err(AdminError::CertLifetimeTooLong)
            ),
            "{extra}"
        );
    }
    assert!(matches!(
        create_network(&OwnerKey::generate(), &cert_with(1), "net", NOW),
        Err(AdminError::CertLifetimeTooLong)
    ));
}

#[test]
fn a_revoked_node_is_not_admitted_again() {
    let (owner, _laptop, _, docs) = founded();
    let (keys, cert) = node();
    let mut roster = docs.roster_body().clone();
    roster.revoked.push(RevokedMember {
        node_id: keys.node_id(),
        since: NOW - DAY,
    });
    let revoked = Documents::signed(&owner, roster, docs.policy_body().clone()).unwrap();
    assert!(matches!(
        admit(&owner, &revoked, &cert, "back", &[], NOW),
        Err(AdminError::Revoked(id)) if id == keys.node_id()
    ));
    // Someone else is still welcome.
    let (_, other) = node();
    admit(&owner, &revoked, &other, "other", &[], NOW).unwrap();
}

#[test]
fn names_that_differ_in_letter_case_only_are_the_same_name() {
    let (owner, _laptop, _, docs) = founded();
    for same in ["Laptop", "LAPTOP", "lAPtop"] {
        let (_, cert) = node();
        assert!(
            matches!(
                admit(&owner, &docs, &cert, same, &[], NOW),
                Err(AdminError::NameTaken(name)) if name == same
            ),
            "{same}"
        );
    }
    // Beyond ASCII too.
    let (_, cert) = node();
    let docs = admit(&owner, &docs, &cert, "ünlü", &[], NOW).unwrap();
    let (_, cert) = node();
    assert!(matches!(
        admit(&owner, &docs, &cert, "ÜNLÜ", &[], NOW),
        Err(AdminError::NameTaken(_))
    ));
}

/// What a verifier will hold the member to is the serial of the certificate it was admitted
/// with: older ones of the same node are dead from the start.
#[test]
fn a_member_s_minimum_serial_is_the_serial_of_its_certificate() {
    let owner = OwnerKey::generate();
    let founder = NodeKeys::generate();
    let founder_cert = founder.issue_cert(3, NOW - 100, NOW + DAY).unwrap();
    let docs = create_network(&owner, &founder_cert, "laptop", NOW).unwrap();
    let phone = NodeKeys::generate();
    let phone_cert = phone.issue_cert(7, NOW - 100, NOW + DAY).unwrap();
    let docs = admit(&owner, &docs, &phone_cert, "phone", &[], NOW).unwrap();

    let min_serial = |id: NodeId| {
        docs.roster_body()
            .members
            .iter()
            .find(|member| member.node_id == id)
            .unwrap()
            .min_serial
    };
    assert_eq!(min_serial(founder.node_id()), 3);
    assert_eq!(min_serial(phone.node_id()), 7);

    let (rosters, policies) = load(&docs);
    let standing = |id: NodeId, serial| {
        policies.check_membership(&rosters, &docs.network_id(), &id, serial, NOW)
    };
    assert_eq!(standing(phone.node_id(), 7), Ok(()));
    assert_eq!(standing(phone.node_id(), 6), Err(ErrorCode::StaleSerial));
    assert_eq!(standing(founder.node_id(), 2), Err(ErrorCode::StaleSerial));
}

/// The owner signs a successor of what it is given, so it must have checked both signatures:
/// a Policy someone else signed next to a genuine Roster would otherwise be extended with the
/// owner's signature on the forger's grants. (The test above covers a pair forged as a whole,
/// where the Roster check fails first.)
#[test]
fn a_genuine_roster_next_to_a_forged_policy_is_not_extended_and_the_other_way_round() {
    let (owner, laptop, _, docs) = founded();
    let thief = SigningKey::generate(&mut rand::rng());
    let (_, cert) = node();
    let extra = || {
        node_grant(
            docs.network_id(),
            laptop.node_id(),
            laptop.node_id(),
            &["tcp:everything"],
        )
    };

    let mut evil_policy = docs.policy_body().clone();
    evil_policy.grants.push(extra());
    let forged_policy = Policy::sign(&thief, &evil_policy).unwrap();
    let forged_roster = Roster::sign(&thief, docs.roster_body()).unwrap();
    for (what, mixed) in [
        (
            "forged policy",
            Documents::from_signed(docs.roster().clone(), forged_policy).unwrap(),
        ),
        (
            "forged roster",
            Documents::from_signed(forged_roster, docs.policy().clone()).unwrap(),
        ),
    ] {
        assert!(
            matches!(renew(&owner, &mixed, NOW + DAY), Err(AdminError::Proto(_))),
            "renew, {what}"
        );
        assert!(
            matches!(
                admit(&owner, &mixed, &cert, "x", &[], NOW),
                Err(AdminError::Proto(_))
            ),
            "admit, {what}"
        );
        assert!(
            matches!(
                grant(&owner, &mixed, extra(), NOW),
                Err(AdminError::Proto(_))
            ),
            "grant, {what}"
        );
    }
}

#[test]
fn the_size_limit_is_inclusive() {
    check_size("Roster", MAX_DOC_BYTES).unwrap();
    check_size("Policy", 0).unwrap();
    assert!(matches!(
        check_size("Policy", MAX_DOC_BYTES + 1),
        Err(AdminError::TooLarge { what: "Policy", len, max })
            if len == MAX_DOC_BYTES + 1 && max == MAX_DOC_BYTES
    ));
}

/// The third red-team round, M1: a name that is eight or more hex digits can be taken for the
/// start of a node id, and an address cannot tell which it is.
#[test]
fn a_name_that_reads_as_the_start_of_a_node_id_is_refused() {
    let (owner, _laptop, _, docs) = founded();
    for bad in ["1a2b3c4d", "DEADBEEF", "0123456789abcdef", &"a".repeat(63)] {
        let (_, cert) = node();
        assert!(
            matches!(
                admit(&owner, &docs, &cert, bad, &[], NOW),
                Err(AdminError::NameLooksLikeNodeId(_))
            ),
            "{bad}"
        );
        assert!(matches!(
            check_name(bad),
            Err(AdminError::NameLooksLikeNodeId(_))
        ));
    }
    // Short hex-looking words and longer words with a non-hex letter are names.
    for good in ["abc", "1234567", "face", "1a2b3c4g", "deadbeef-2", "phone1"] {
        check_name(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
}

#[test]
fn roles_are_held_to_the_same_characters_as_names() {
    let (owner, _laptop, _, docs) = founded();
    for good in ["admin", "ops-team", "dev_2", "a.b", "1a2b3c4d", "ünlü"] {
        check_role(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "",
        "-x",
        ".",
        "a b",
        "a:b",
        "a/b",
        "esc\u{1b}[2J",
        "right\u{202e}left",
        &"r".repeat(64),
    ] {
        assert!(
            matches!(check_role(bad), Err(AdminError::BadRole(_))),
            "{bad:?}"
        );
        let (_, cert) = node();
        assert!(
            matches!(
                admit(&owner, &docs, &cert, "someone", &[bad.to_string()], NOW),
                Err(AdminError::BadRole(_))
            ),
            "{bad:?}"
        );
    }
    let (_, cert) = node();
    admit(
        &owner,
        &docs,
        &cert,
        "someone",
        &["admin".to_string(), "dev".to_string()],
        NOW,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Stewards (protocol.md 2.3, 7.3; TODO L4j S3)
// ---------------------------------------------------------------------------------------------

use menzil_proto::StewardKey;
use menzil_proto::trust::{Reason, STEWARD_SEQ_SPAN};

use crate::StewardSecret;

const ADMIT_RENEW: [&str; 2] = ["admit", "renew"];

fn rights(rights: &[&str]) -> Vec<String> {
    rights.iter().map(|r| r.to_string()).collect()
}

/// A network whose owner delegated `steward` (rights `admit` and `renew`) until NOW + 30 days.
struct Stewarded {
    owner: OwnerKey,
    steward: StewardSecret,
    /// The owner signed pair that lists the steward: the base of everything the steward signs.
    base: Documents,
}

fn stewarded() -> Stewarded {
    stewarded_with(&ADMIT_RENEW)
}

fn stewarded_with(may: &[&str]) -> Stewarded {
    let (owner, _, _, docs) = founded();
    let steward = StewardSecret::generate();
    let base = delegate_steward(
        &owner,
        &docs,
        steward.public(),
        &rights(may),
        NOW + 30 * DAY,
        NOW,
    )
    .unwrap();
    Stewarded {
        owner,
        steward,
        base,
    }
}

/// What a verifier that holds `held` (or nothing) says about `docs` at `now`.
fn judged(held: Option<&Documents>, docs: &Documents, now: u64) -> Verdict {
    let view = match held {
        Some(held) => held.held_view().unwrap(),
        None => HeldView {
            network_id: docs.network_id(),
            roster: None,
            policy_seq: None,
        },
    };
    check_bundle(&view, &docs.bundle(), now)
}

fn adopted_signer(verdict: Verdict) -> Signer {
    match verdict {
        Verdict::Adopt(adoption) => adoption.signer,
        other => panic!("expected an adoption, got {other:?}"),
    }
}

#[test]
fn delegating_lists_one_owner_signed_steward_entry() {
    let s = stewarded();
    let owner_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(s.owner.network_id())).unwrap();
    assert_eq!(s.base.seq(), 2);
    assert_eq!(s.base.verify().unwrap(), Signer::Owner);
    assert!(s.base.base().is_none());
    let [entry] = s.base.roster_body().stewards.as_slice() else {
        panic!("one steward");
    };
    entry.verify(&owner_key).unwrap();
    let body = entry.decode().unwrap();
    assert_eq!(body.network_id, s.owner.network_id());
    assert_eq!(body.steward_pub, s.steward.public());
    assert_eq!(body.may, rights(&ADMIT_RENEW));
    assert_eq!(body.not_after, NOW + 30 * DAY);
    // Delegating a second steward replaces the first: exactly one is listed.
    let other = StewardSecret::generate();
    let replaced = delegate_steward(
        &s.owner,
        &s.base,
        other.public(),
        &rights(&["renew"]),
        NOW + 10 * DAY,
        NOW,
    )
    .unwrap();
    let [entry] = replaced.roster_body().stewards.as_slice() else {
        panic!("one steward");
    };
    assert_eq!(entry.decode().unwrap().steward_pub, other.public());
    // The policy is untouched.
    assert_eq!(replaced.policy_body().members, s.base.policy_body().members);
}

#[test]
fn a_steward_entry_with_bad_rights_lifetime_or_key_is_not_issued() {
    let (owner, _, _, docs) = founded();
    let key = StewardSecret::generate().public();
    let delegate = |may: &[&str], not_after: u64, key: StewardKey| {
        delegate_steward(&owner, &docs, key, &rights(may), not_after, NOW)
    };
    for bad in [&[][..], &["grant"], &["admit", "revoke"], &["ADMIT"]] {
        assert!(
            matches!(
                delegate(bad, NOW + DAY, key),
                Err(AdminError::BadStewardRights)
            ),
            "{bad:?}"
        );
    }
    // Duplicates are listed once.
    let twice = delegate(&["renew", "renew", "admit"], NOW + DAY, key).unwrap();
    let [entry] = twice.roster_body().stewards.as_slice() else {
        panic!("one steward");
    };
    assert_eq!(entry.decode().unwrap().may, rights(&["renew", "admit"]));
    // Up to 90 days, and not in the past.
    let ninety = 90 * DAY;
    delegate(&["renew"], NOW + ninety, key).unwrap();
    for not_after in [NOW + ninety + 1, NOW, NOW - 1, 0, u64::MAX] {
        assert!(
            matches!(
                delegate(&["renew"], not_after, key),
                Err(AdminError::BadStewardLifetime)
            ),
            "{not_after}"
        );
    }
    // A key that is no Ed25519 point (this one is a small order point's compressed encoding of
    // a value off the curve).
    let mut off_curve = [0xffu8; 32];
    off_curve[31] = 0x7f;
    if VerifyingKey::from_bytes(&off_curve).is_err() {
        assert!(matches!(
            delegate(&["renew"], NOW + DAY, StewardKey::from(off_curve)),
            Err(AdminError::BadStewardKey)
        ));
    }
    // Another owner cannot delegate for these documents.
    let stranger = OwnerKey::generate();
    assert!(matches!(
        delegate_steward(&stranger, &docs, key, &rights(&["renew"]), NOW + DAY, NOW),
        Err(AdminError::NotThisOwner)
    ));
}

/// Protocol.md 2.3: while its last documents list a steward, the owner's next documents have
/// a `seq` above the base's plus 2^20. One more than the span, not the span itself: a steward
/// may sign exactly base + span.
#[test]
fn the_owner_jumps_past_the_steward_span_while_a_steward_is_listed() {
    let s = stewarded();
    let base_seq = s.base.seq();
    let (_, cert) = node();
    let admitted = admit(&s.owner, &s.base, &cert, "phone", &[], NOW).unwrap();
    assert_eq!(admitted.seq(), base_seq + STEWARD_SEQ_SPAN + 1);
    assert_eq!(
        s.base.next_owner_seq().unwrap(),
        base_seq + STEWARD_SEQ_SPAN + 1
    );
    // Every owner operation follows the rule.
    assert_eq!(
        renew(&s.owner, &s.base, NOW).unwrap().seq(),
        base_seq + STEWARD_SEQ_SPAN + 1
    );
    let g = node_grant(
        s.base.network_id(),
        s.base.policy_body().members[0].node_id,
        s.base.policy_body().members[0].node_id,
        &["tcp:ssh"],
    );
    assert_eq!(
        grant(&s.owner, &s.base, g, NOW).unwrap().seq(),
        base_seq + STEWARD_SEQ_SPAN + 1
    );
    // The steward is still listed, so the next one jumps again, from the new pair.
    assert_eq!(
        renew(&s.owner, &admitted, NOW).unwrap().seq(),
        admitted.seq() + STEWARD_SEQ_SPAN + 1
    );
}

#[test]
fn without_a_steward_the_owner_counts_one_at_a_time() {
    let (owner, _, _, docs) = founded();
    assert_eq!(docs.next_owner_seq().unwrap(), 2);
    let (_, cert) = node();
    let admitted = admit(&owner, &docs, &cert, "phone", &[], NOW).unwrap();
    assert_eq!(admitted.seq(), 2);
    assert_eq!(renew(&owner, &admitted, NOW).unwrap().seq(), 3);
    // The same after the steward was removed: the removal pair carried the jump, the pairs
    // after it do not.
    let s = stewarded();
    let removed = remove_steward(&s.owner, &s.base, NOW).unwrap();
    assert_eq!(removed.next_owner_seq().unwrap(), removed.seq() + 1);
    assert_eq!(
        renew(&s.owner, &removed, NOW).unwrap().seq(),
        removed.seq() + 1
    );
}

#[test]
fn the_owner_extends_a_pair_a_steward_signed_from_its_base() {
    let s = stewarded();
    let (_, cert) = node();
    let by_steward = steward_admit(&s.steward, &s.base, &cert, "phone", NOW + DAY).unwrap();
    let renewed = steward_renew(&s.steward, &by_steward, NOW + 2 * DAY).unwrap();
    assert_eq!(renewed.seq(), s.base.seq() + 2);
    let by_owner = renew(&s.owner, &renewed, NOW + 3 * DAY).unwrap();
    // Past the steward's whole range, counted from its base and not from where it had got to.
    assert_eq!(by_owner.seq(), s.base.seq() + STEWARD_SEQ_SPAN + 1);
    assert_eq!(by_owner.verify().unwrap(), Signer::Owner);
    assert!(by_owner.base().is_none());
    // The member the steward admitted is still there; the steward is still listed.
    assert!(by_owner.is_member(&cert.decode().unwrap().node_id));
    assert_eq!(by_owner.roster_body().stewards.len(), 1);
    // A verifier holding the steward's last pair adopts it.
    assert_eq!(
        adopted_signer(judged(Some(&renewed), &by_owner, NOW + 3 * DAY)),
        Signer::Owner
    );
}

#[test]
fn what_a_steward_renews_passes_the_acceptance_predicate() {
    let s = stewarded();
    let renewed = steward_renew(&s.steward, &s.base, NOW + 10 * DAY).unwrap();
    assert_eq!(renewed.seq(), s.base.seq() + 1);
    let (rb, pb) = (renewed.roster_body(), renewed.policy_body());
    assert_eq!((rb.issued, pb.issued), (NOW + 10 * DAY, NOW + 10 * DAY));
    assert_eq!((rb.expires, pb.expires), (NOW + 24 * DAY, NOW + 24 * DAY));
    assert_eq!(
        (rb.members.clone(), pb.grants.clone()),
        (
            s.base.roster_body().members.clone(),
            s.base.policy_body().grants.clone()
        )
    );
    // Held by someone who holds the base, and by someone who holds nothing.
    let signer = Signer::Steward {
        key: s.steward.public(),
        base_seq: s.base.seq(),
    };
    assert_eq!(
        adopted_signer(judged(Some(&s.base), &renewed, NOW + 10 * DAY)),
        signer
    );
    assert_eq!(
        adopted_signer(judged(None, &renewed, NOW + 10 * DAY)),
        signer
    );
    assert_eq!(renewed.verify().unwrap(), signer);
    assert_eq!(renewed.base().map(|(r, _)| r), Some(s.base.roster()));

    // A pair the steward made from its own pair keeps the owner's base, counts on from the
    // pair it holds, and is adopted by those who hold the first.
    let again = steward_renew(&s.steward, &renewed, NOW + 11 * DAY).unwrap();
    assert_eq!(again.seq(), s.base.seq() + 2);
    assert_eq!(again.base().map(|(r, _)| r), Some(s.base.roster()));
    assert_eq!(
        adopted_signer(judged(Some(&renewed), &again, NOW + 11 * DAY)),
        signer
    );
    // And it is a renewal in the verifier's eyes whatever the clock of the issuer: after an
    // outage of the steward the documents may have run out; a renewal still works.
    let late = steward_renew(&s.steward, &renewed, NOW + 25 * DAY).unwrap();
    assert_eq!(
        adopted_signer(judged(Some(&renewed), &late, NOW + 25 * DAY)),
        signer
    );
}

#[test]
fn a_steward_pair_never_outlives_the_delegation() {
    let s = stewarded();
    // 20 days in, 14 days would end after not_after (30 days): it ends at not_after.
    let renewed = steward_renew(&s.steward, &s.base, NOW + 20 * DAY).unwrap();
    assert_eq!(renewed.roster_body().expires, NOW + 30 * DAY);
    assert_eq!(renewed.policy_body().expires, NOW + 30 * DAY);
    assert!(matches!(
        judged(Some(&s.base), &renewed, NOW + 20 * DAY),
        Verdict::Adopt(_)
    ));
    // At or after not_after there is nothing to sign with.
    for at in [NOW + 30 * DAY, NOW + 31 * DAY] {
        assert!(matches!(
            steward_renew(&s.steward, &s.base, at),
            Err(AdminError::Rejected(Reason::StewardExpired))
        ));
    }
}

#[test]
fn a_steward_admits_a_member_without_roles_and_the_network_adopts_it() {
    let s = stewarded();
    let (keys, cert) = node();
    let next = steward_admit(&s.steward, &s.base, &cert, "phone", NOW + DAY).unwrap();
    assert_eq!(next.seq(), s.base.seq() + 1);
    let id = keys.node_id();
    assert!(next.is_member(&id));
    let (rb, pb) = (next.roster_body(), next.policy_body());
    // Appended at the end, with the certificate's own serial and no roles.
    assert_eq!(rb.members.last().unwrap().node_id, id);
    assert_eq!(rb.members.last().unwrap().min_serial, 1);
    assert_eq!(pb.members.last().unwrap().name, "phone");
    assert!(pb.members.last().unwrap().roles.is_empty());
    assert_eq!(pb.certs.last().unwrap(), &cert);
    assert_eq!(rb.members.len(), 2);
    assert_eq!(pb.certs.len(), 2);
    let signer = Signer::Steward {
        key: s.steward.public(),
        base_seq: s.base.seq(),
    };
    assert_eq!(
        adopted_signer(judged(Some(&s.base), &next, NOW + DAY)),
        signer
    );
    assert_eq!(adopted_signer(judged(None, &next, NOW + DAY)), signer);
    // The result is held through the stores a node keeps.
    let (rosters, policies) = (RosterStore::new(), PolicyStore::new());
    rosters.set(s.base.roster()).unwrap();
    policies.set(s.base.policy()).unwrap();
    let store = menzil_node::DocStore::new(&rosters, &policies);
    let adopted = store.adopt(&next.bundle(), NOW + DAY).unwrap();
    assert!(adopted.roster && adopted.policy);
    assert_eq!(policies.seq(&next.network_id()), Some(next.seq()));
}

#[test]
fn a_steward_admits_by_the_issuers_checks_and_its_own_right() {
    let s = stewarded();
    let (_, cert) = node();
    let at = NOW + DAY;
    // The issuer's checks of `admit`.
    let founder = s.base.roster_body().members[0].node_id;
    let founders_cert = s.base.policy_body().certs[0].clone();
    assert!(matches!(
        steward_admit(&s.steward, &s.base, &founders_cert, "other", at),
        Err(AdminError::AlreadyMember(id)) if id == founder
    ));
    assert!(matches!(
        steward_admit(&s.steward, &s.base, &cert, "LAPTOP", at),
        Err(AdminError::NameTaken(_))
    ));
    assert!(matches!(
        steward_admit(&s.steward, &s.base, &cert, "bad name", at),
        Err(AdminError::BadName(_))
    ));
    let expired = {
        let keys = NodeKeys::generate();
        keys.issue_cert(1, 1, 100).unwrap()
    };
    assert!(matches!(
        steward_admit(&s.steward, &s.base, &expired, "late", at),
        Err(AdminError::CertNotValidNow)
    ));
    // A revoked node is not admitted again, by a steward neither.
    let (revoked_keys, revoked_cert) = node();
    let mut roster = s.base.roster_body().clone();
    roster.seq += 1;
    roster.revoked.push(RevokedMember {
        node_id: revoked_keys.node_id(),
        since: NOW,
    });
    let mut policy = s.base.policy_body().clone();
    policy.seq += 1;
    let with_revoked = Documents::signed(&s.owner, roster, policy).unwrap();
    assert!(matches!(
        steward_admit(&s.steward, &with_revoked, &revoked_cert, "ghost", at),
        Err(AdminError::Revoked(id)) if id == revoked_keys.node_id()
    ));

    // Rights: a steward that may only renew cannot admit; one that may only admit cannot renew.
    let renew_only = stewarded_with(&["renew"]);
    assert!(matches!(
        steward_admit(&renew_only.steward, &renew_only.base, &cert, "phone", at),
        Err(AdminError::Rejected(Reason::RightMissing))
    ));
    steward_renew(&renew_only.steward, &renew_only.base, at).unwrap();
    let admit_only = stewarded_with(&["admit"]);
    assert!(matches!(
        steward_renew(&admit_only.steward, &admit_only.base, at),
        Err(AdminError::Rejected(Reason::RightMissing))
    ));
    steward_admit(&admit_only.steward, &admit_only.base, &cert, "phone", at).unwrap();
}

#[test]
fn only_the_listed_steward_can_sign_and_only_when_one_is_listed() {
    let s = stewarded();
    let stranger = StewardSecret::generate();
    assert!(matches!(
        steward_renew(&stranger, &s.base, NOW + DAY),
        Err(AdminError::StewardNotListed)
    ));
    let removed = remove_steward(&s.owner, &s.base, NOW + DAY).unwrap();
    assert!(matches!(
        steward_renew(&s.steward, &removed, NOW + 2 * DAY),
        Err(AdminError::NoSteward)
    ));
    // Documents with no owner signature and no steward base are no ground to stand on.
    let (_, _, _, docs) = founded();
    let thief = SigningKey::generate(&mut rand::rng());
    let forged = Documents::signed_with(
        &thief,
        docs.roster_body().clone(),
        docs.policy_body().clone(),
        None,
    )
    .unwrap();
    assert!(matches!(
        steward_renew(&s.steward, &forged, NOW),
        Err(AdminError::Proto(_))
    ));
    assert!(matches!(
        delegate_steward(
            &s.owner,
            &forged,
            s.steward.public(),
            &rights(&["renew"]),
            NOW + DAY,
            NOW
        ),
        Err(AdminError::NotThisOwner | AdminError::Proto(_))
    ));
}

/// A steward pair signed at the very end of its range: `base + span`.
fn at_the_end_of_the_range(s: &Stewarded) -> Documents {
    let mut roster = s.base.roster_body().clone();
    let mut policy = s.base.policy_body().clone();
    roster.seq = s.base.seq() + STEWARD_SEQ_SPAN;
    policy.seq = roster.seq;
    roster.issued = NOW + DAY;
    policy.issued = NOW + DAY;
    roster.expires = NOW + 8 * DAY;
    policy.expires = NOW + 8 * DAY;
    Documents::signed_with(
        s.steward.signing_key(),
        roster,
        policy,
        Some(Base {
            roster: s.base.roster().clone(),
            policy: s.base.policy().clone(),
            seq: s.base.seq(),
        }),
    )
    .unwrap()
}

#[test]
fn a_steward_with_no_sequence_numbers_left_from_its_base_stops() {
    let s = stewarded();
    let last = at_the_end_of_the_range(&s);
    // The last number of the range is a valid pair...
    assert!(matches!(
        judged(Some(&s.base), &last, NOW + DAY),
        Verdict::Adopt(_)
    ));
    assert_eq!(
        last.verify().unwrap(),
        Signer::Steward {
            key: s.steward.public(),
            base_seq: s.base.seq(),
        }
    );
    // ...and one more is the owner's to issue.
    assert!(matches!(
        steward_renew(&s.steward, &last, NOW + 2 * DAY),
        Err(AdminError::SeqSpanExhausted)
    ));
    // One before the end still works.
    let mut before = s.base.roster_body().clone();
    let mut policy = s.base.policy_body().clone();
    before.seq = s.base.seq() + STEWARD_SEQ_SPAN - 1;
    policy.seq = before.seq;
    before.issued = NOW + DAY;
    policy.issued = NOW + DAY;
    before.expires = NOW + 8 * DAY;
    policy.expires = NOW + 8 * DAY;
    let before = Documents::signed_with(
        s.steward.signing_key(),
        before,
        policy,
        Some(Base {
            roster: s.base.roster().clone(),
            policy: s.base.policy().clone(),
            seq: s.base.seq(),
        }),
    )
    .unwrap();
    assert_eq!(
        steward_renew(&s.steward, &before, NOW + 2 * DAY)
            .unwrap()
            .seq(),
        s.base.seq() + STEWARD_SEQ_SPAN
    );
}

/// "Removing a steward leaves a Roster no steward document can follow": whatever the steward
/// signed from its base is at or below base + span, and the removal is above that.
#[test]
fn removing_a_steward_leaves_a_pair_no_steward_document_can_follow() {
    let s = stewarded();
    let last = at_the_end_of_the_range(&s);
    let removed = remove_steward(&s.owner, &s.base, NOW + 2 * DAY).unwrap();
    assert!(removed.roster_body().stewards.is_empty());
    assert_eq!(removed.verify().unwrap(), Signer::Owner);
    assert_eq!(removed.seq(), s.base.seq() + STEWARD_SEQ_SPAN + 1);
    // The member of the network who holds the steward's very last pair takes the removal...
    assert_eq!(
        adopted_signer(judged(Some(&last), &removed, NOW + 2 * DAY)),
        Signer::Owner
    );
    // ...and once it holds the removal, nothing the steward made from that base is newer.
    assert!(matches!(
        judged(Some(&removed), &last, NOW + 2 * DAY),
        Verdict::Held
    ));
    let first = steward_renew(&s.steward, &s.base, NOW + DAY).unwrap();
    assert!(matches!(
        judged(Some(&removed), &first, NOW + 2 * DAY),
        Verdict::Held
    ));
    // A steward pair made from the removal itself has nothing to stand on: it lists nobody.
    assert!(matches!(
        steward_renew(&s.steward, &removed, NOW + 3 * DAY),
        Err(AdminError::NoSteward)
    ));
    // Removing when none is listed is an error, not a silent new pair.
    assert!(matches!(
        remove_steward(&s.owner, &removed, NOW + 3 * DAY),
        Err(AdminError::NoSteward)
    ));
}

#[test]
fn removing_a_steward_after_it_admitted_keeps_the_members() {
    let s = stewarded();
    let (_, cert) = node();
    let admitted = steward_admit(&s.steward, &s.base, &cert, "phone", NOW + DAY).unwrap();
    let removed = remove_steward(&s.owner, &admitted, NOW + 2 * DAY).unwrap();
    assert!(removed.is_member(&cert.decode().unwrap().node_id));
    assert_eq!(removed.policy_body().certs.len(), 2);
    assert!(removed.roster_body().stewards.is_empty());
    assert_eq!(removed.seq(), s.base.seq() + STEWARD_SEQ_SPAN + 1);
}

#[test]
fn documents_with_a_base_are_checked_as_a_whole() {
    let s = stewarded();
    let renewed = steward_renew(&s.steward, &s.base, NOW + DAY).unwrap();
    let (base_roster, base_policy) = renewed.base().unwrap();
    let rebuilt = Documents::from_signed_with_base(
        renewed.roster().clone(),
        renewed.policy().clone(),
        base_roster.clone(),
        base_policy.clone(),
    )
    .unwrap();
    assert_eq!(rebuilt.verify().unwrap(), renewed.verify().unwrap());

    // Without its base, a steward signed pair stands on nothing.
    let bare = Documents::from_signed(renewed.roster().clone(), renewed.policy().clone()).unwrap();
    assert!(matches!(bare.verify(), Err(AdminError::Proto(_))));
    // With the base of another network, or a base that is not a pair, it is not even paired.
    let other = stewarded();
    assert!(matches!(
        Documents::from_signed_with_base(
            renewed.roster().clone(),
            renewed.policy().clone(),
            other.base.roster().clone(),
            other.base.policy().clone(),
        ),
        Err(AdminError::MismatchedDocuments(_))
    ));
    let later = renew(&s.owner, &s.base, NOW).unwrap();
    assert!(matches!(
        Documents::from_signed_with_base(
            renewed.roster().clone(),
            renewed.policy().clone(),
            s.base.roster().clone(),
            later.policy().clone(),
        ),
        Err(AdminError::MismatchedDocuments(_))
    ));
    // A base that is not the one the pair was made from: the predicate refuses it.
    let wrong_base = Documents::from_signed_with_base(
        renewed.roster().clone(),
        renewed.policy().clone(),
        later.roster().clone(),
        later.policy().clone(),
    )
    .unwrap();
    assert!(wrong_base.verify().is_err());
    // Extra bases on an owner signed pair are dropped when it is verified.
    let owner_signed = Documents::from_signed_with_base(
        s.base.roster().clone(),
        s.base.policy().clone(),
        s.base.roster().clone(),
        s.base.policy().clone(),
    )
    .unwrap();
    assert_eq!(owner_signed.verify().unwrap(), Signer::Owner);
    assert!(owner_signed.into_verified().unwrap().base().is_none());
}

/// An expired pair is formed all the same (`verify` has no clock but the pair's own): the
/// owner can renew it, and so can the steward.
#[test]
fn expired_steward_documents_can_still_be_extended() {
    let s = stewarded();
    let renewed = steward_renew(&s.steward, &s.base, NOW + DAY).unwrap();
    assert_eq!(renewed.roster_body().expires, NOW + 15 * DAY);
    let long_after = NOW + 29 * DAY;
    assert!(renewed.verify().is_ok());
    let by_steward = steward_renew(&s.steward, &renewed, long_after).unwrap();
    assert_eq!(by_steward.roster_body().expires, NOW + 30 * DAY);
    let by_owner = renew(&s.owner, &renewed, NOW + 40 * DAY).unwrap();
    assert_eq!(by_owner.roster_body().expires, NOW + 54 * DAY);
}

#[test]
fn the_pair_of_a_steward_is_one_steward_pair_not_two_halves() {
    // The steward signs both; a pair with a Policy signed by someone else is not formed.
    let s = stewarded();
    let renewed = steward_renew(&s.steward, &s.base, NOW + DAY).unwrap();
    let thief = SigningKey::generate(&mut rand::rng());
    let policy = Policy::sign(&thief, renewed.policy_body()).unwrap();
    let mixed = Documents::from_signed_with_base(
        renewed.roster().clone(),
        policy,
        s.base.roster().clone(),
        s.base.policy().clone(),
    )
    .unwrap();
    assert!(mixed.verify().is_err());
}

/// Round 7 L1: a steward pair whose Policy was issued some hours after its Roster is adopted by
/// every verifier at the real clock, so `verify` (and with it join, renew, load) accepts it.
#[test]
fn a_steward_pair_with_a_policy_issued_after_its_roster_verifies() {
    let s = stewarded();
    let renewed = steward_renew(&s.steward, &s.base, NOW + DAY).unwrap();
    let (base_r, base_p) = renewed.base().unwrap();
    let mut rb = renewed.roster_body().clone();
    let mut pb = renewed.policy_body().clone();
    rb.issued = NOW + DAY;
    pb.issued = NOW + DAY + 3 * 3600;
    rb.expires = rb.issued + DAY;
    pb.expires = pb.issued + DAY;
    let pair = Documents::from_signed_with_base(
        Roster::sign(s.steward.signing_key(), &rb).unwrap(),
        Policy::sign(s.steward.signing_key(), &pb).unwrap(),
        base_r.clone(),
        base_p.clone(),
    )
    .unwrap();
    let clock = pb.issued;
    let signer = Signer::Steward {
        key: s.steward.public(),
        base_seq: s.base.seq(),
    };
    // Every verifier adopts it at the real clock, from nothing and holding the base.
    assert_eq!(adopted_signer(judged(None, &pair, clock)), signer);
    assert_eq!(adopted_signer(judged(Some(&s.base), &pair, clock)), signer);
    assert_eq!(pair.verify().unwrap(), signer);
    // The owner can still extend it.
    assert!(renew(&s.owner, &pair, clock).is_ok());
}

/// Round 7 L3: a steward that may only admit cannot renew indefinitely once it has admitted a
/// member; renewing what it holds appends nothing new and needs `renew`. An admission still
/// carries fresh dates and needs only `admit`.
#[test]
fn an_admit_only_steward_cannot_renew_what_it_admitted_but_can_admit_again() {
    let s = stewarded_with(&["admit"]);
    let (_, a) = node();
    let (_, b) = node();
    assert!(matches!(
        steward_renew(&s.steward, &s.base, NOW + DAY),
        Err(AdminError::Rejected(Reason::RightMissing))
    ));
    let admitted = steward_admit(&s.steward, &s.base, &a, "printer", NOW + DAY).unwrap();
    assert!(matches!(
        steward_renew(&s.steward, &admitted, NOW + 13 * DAY),
        Err(AdminError::Rejected(Reason::RightMissing))
    ));
    let again = steward_admit(&s.steward, &admitted, &b, "scanner", NOW + 13 * DAY).unwrap();
    assert_eq!(again.roster_body().expires, NOW + 27 * DAY);
    assert_eq!(
        adopted_signer(judged(Some(&admitted), &again, NOW + 13 * DAY)),
        Signer::Steward {
            key: s.steward.public(),
            base_seq: s.base.seq()
        }
    );
    // With both rights the renewal of a pair that keeps the admission is fine.
    let both = stewarded();
    let admitted = steward_admit(&both.steward, &both.base, &a, "printer", NOW + DAY).unwrap();
    let renewed = steward_renew(&both.steward, &admitted, NOW + 13 * DAY).unwrap();
    assert_eq!(renewed.roster_body().members.len(), 2);
    renewed.verify().unwrap();
}

/// Round 7 L2: a renewal a steward makes from the base (a device that does not hold its own
/// admissions) drops them; a verifier that holds the admission refuses it.
#[test]
fn a_steward_renewal_from_the_base_is_refused_by_a_verifier_holding_its_admissions() {
    let s = stewarded();
    let (_, a) = node();
    let admitted = steward_admit(&s.steward, &s.base, &a, "printer", NOW + DAY).unwrap();
    // The stale device renews twice, so that its pair outranks the admission's.
    let stale = steward_renew(&s.steward, &s.base, NOW + 2 * DAY).unwrap();
    let stale = steward_renew(&s.steward, &stale, NOW + 2 * DAY).unwrap();
    assert!(!stale.is_member(&a.decode().unwrap().node_id));
    assert!(matches!(
        judged(Some(&admitted), &stale, NOW + 2 * DAY),
        Verdict::Reject(Reason::AppendedDropped)
    ));
}

// ---------------------------------------------------------------------------------------------
// Revocation and grant removal (protocol.md 7.3; L4k K1)
// ---------------------------------------------------------------------------------------------

use menzil_proto::{AcceptEntry, EgressRule, HostPortPattern, Label};

fn role_grant(network_id: NetworkId, role: &str, to: NodeOrWildcard, services: &[&str]) -> Grant {
    Grant {
        from: Principal {
            network_id,
            target: PrincipalTarget::Role(role.to_string()),
        },
        to_node: to,
        services: services.iter().map(|s| service(s)).collect(),
        expires: None,
    }
}

/// laptop (the founder), phone and tablet, with every kind of entry that names the phone and
/// a few that must survive its revocation.
struct Busy {
    owner: OwnerKey,
    laptop: NodeId,
    phone: NodeId,
    phone_cert: NodeCert,
    tablet: NodeId,
    docs: Documents,
}

fn busy() -> Busy {
    let (owner, laptop_keys, _, docs) = founded();
    let (phone_keys, phone_cert) = node();
    let (tablet_keys, tablet_cert) = node();
    let (laptop, phone, tablet) = (
        laptop_keys.node_id(),
        phone_keys.node_id(),
        tablet_keys.node_id(),
    );
    let docs = admit(&owner, &docs, &phone_cert, "phone", &["family".into()], NOW).unwrap();
    let docs = admit(&owner, &docs, &tablet_cert, "tablet", &[], NOW).unwrap();
    let network_id = docs.network_id();
    let mut roster = docs.roster_body().clone();
    let mut policy = docs.policy_body().clone();
    roster.labels = vec![
        Label {
            name: "mine".into(),
            node_id: phone,
        },
        Label {
            name: "home".into(),
            node_id: laptop,
        },
    ];
    policy.grants = vec![
        node_grant(network_id, phone, laptop, &["tcp:ssh"]),
        node_grant(network_id, laptop, phone, &["http:app"]),
        Grant {
            to_node: NodeOrWildcard::Any,
            ..node_grant(network_id, phone, laptop, &["tcp:web"])
        },
        role_grant(
            network_id,
            "family",
            NodeOrWildcard::Node(laptop),
            &["tcp:ssh"],
        ),
        Grant {
            to_node: NodeOrWildcard::Any,
            ..node_grant(network_id, laptop, laptop, &["tcp:ssh"])
        },
        node_grant(network_id, tablet, laptop, &["tcp:ssh"]),
    ];
    policy.egress = [phone, laptop]
        .map(|node_id| EgressRule {
            node_id,
            allow: vec![HostPortPattern("example.org:443".into())],
            deny: vec![],
        })
        .to_vec();
    policy.accept = [phone, tablet]
        .map(|node_id| AcceptEntry {
            node_id,
            peers: true,
        })
        .to_vec();
    let docs = Documents::signed(&owner, roster, policy).unwrap();
    Busy {
        owner,
        laptop,
        phone,
        phone_cert,
        tablet,
        docs,
    }
}

#[test]
fn revoking_lists_the_node_and_removes_every_trace_of_it_and_nothing_else() {
    let b = busy();
    let next = revoke(&b.owner, &b.docs, b.phone, NOW + 60).unwrap();
    let (rb, pb) = (next.roster_body(), next.policy_body());

    assert_eq!(next.seq(), b.docs.seq() + 1);
    assert_eq!((rb.issued, rb.expires), (NOW + 60, NOW + 60 + 14 * DAY));
    assert_eq!(rb.revoked.len(), 1);
    assert_eq!(
        (rb.revoked[0].node_id, rb.revoked[0].since),
        (b.phone, NOW + 60)
    );
    // The Roster: no member entry, no label of it; the others are as they were.
    let ids = |list: &[RosterMember]| list.iter().map(|m| m.node_id).collect::<Vec<_>>();
    assert_eq!(ids(&rb.members), vec![b.laptop, b.tablet]);
    assert_eq!(rb.labels.len(), 1);
    assert_eq!(rb.labels[0].node_id, b.laptop);
    // The Policy: no member, certificate, egress or accept entry of it, and only the grants
    // that name it as `from` or `to_node` are gone: the role grant, the grants of others and
    // the wildcard grant of the laptop stay.
    assert_eq!(
        pb.members.iter().map(|m| m.node_id).collect::<Vec<_>>(),
        vec![b.laptop, b.tablet]
    );
    assert_eq!(pb.certs.len(), 2);
    assert!(
        pb.certs
            .iter()
            .all(|cert| cert.decode().unwrap().node_id != b.phone)
    );
    assert_eq!(pb.grants, {
        let network_id = next.network_id();
        vec![
            role_grant(
                network_id,
                "family",
                NodeOrWildcard::Node(b.laptop),
                &["tcp:ssh"],
            ),
            Grant {
                to_node: NodeOrWildcard::Any,
                ..node_grant(network_id, b.laptop, b.laptop, &["tcp:ssh"])
            },
            node_grant(network_id, b.tablet, b.laptop, &["tcp:ssh"]),
        ]
    });
    assert_eq!(
        pb.egress.iter().map(|e| e.node_id).collect::<Vec<_>>(),
        vec![b.laptop]
    );
    assert_eq!(
        pb.accept.iter().map(|a| a.node_id).collect::<Vec<_>>(),
        vec![b.tablet]
    );
    // Names of the survivors are untouched, and the old pair is as it was.
    assert_eq!(pb.members[1].name, "tablet");
    assert_eq!(b.docs.roster_body().revoked.len(), 0);
    assert_eq!(b.docs.policy_body().grants.len(), 6);

    // The owner signed it, and a verifier holding the previous pair adopts it as the owner's.
    assert_eq!(next.verify().unwrap(), Signer::Owner);
    assert_eq!(
        adopted_signer(judged(Some(&b.docs), &next, NOW + 60)),
        Signer::Owner
    );
    // The stores: the phone is refused from now on, the others are not.
    let (rosters, policies) = load(&b.docs);
    let store = menzil_node::DocStore::new(&rosters, &policies);
    store.adopt(&next.bundle(), NOW + 60).unwrap();
    let standing = |id| policies.check_membership(&rosters, &next.network_id(), &id, 1, NOW + 60);
    assert_eq!(standing(b.phone), Err(ErrorCode::Revoked));
    assert_eq!(standing(b.tablet), Ok(()));
    // A revoked node cannot be admitted again with the certificate it had.
    assert!(matches!(
        admit(&b.owner, &next, &b.phone_cert, "phone", &[], NOW + 61),
        Err(AdminError::Revoked(id)) if id == b.phone
    ));
}

#[test]
fn revoking_twice_is_refused_and_a_stranger_can_be_revoked_ahead_of_time() {
    let b = busy();
    let next = revoke(&b.owner, &b.docs, b.phone, NOW).unwrap();
    assert!(matches!(
        revoke(&b.owner, &next, b.phone, NOW + 1),
        Err(AdminError::AlreadyRevoked(id)) if id == b.phone
    ));

    // A node these documents do not list (admitted by a steward after them, or never): only
    // the revoked list changes, besides the numbers.
    let (stranger, _) = node();
    let ahead = revoke(&b.owner, &b.docs, stranger.node_id(), NOW + 5).unwrap();
    assert_eq!(ahead.seq(), b.docs.seq() + 1);
    assert_eq!(ahead.roster_body().revoked.len(), 1);
    assert_eq!(ahead.roster_body().revoked[0].node_id, stranger.node_id());
    assert_eq!(ahead.roster_body().members, b.docs.roster_body().members);
    assert_eq!(ahead.roster_body().labels, b.docs.roster_body().labels);
    let (before, after) = (b.docs.policy_body(), ahead.policy_body());
    assert_eq!(
        (
            &after.members,
            &after.certs,
            &after.grants,
            &after.egress,
            &after.accept
        ),
        (
            &before.members,
            &before.certs,
            &before.grants,
            &before.egress,
            &before.accept
        )
    );
    assert_eq!(
        adopted_signer(judged(Some(&b.docs), &ahead, NOW + 5)),
        Signer::Owner
    );
    // And the list grows: a second revocation keeps the first.
    let both = revoke(&b.owner, &ahead, b.tablet, NOW + 6).unwrap();
    assert_eq!(
        both.roster_body()
            .revoked
            .iter()
            .map(|r| r.node_id)
            .collect::<Vec<_>>(),
        vec![stranger.node_id(), b.tablet]
    );
}

#[test]
fn a_revocation_beside_a_steward_jumps_the_span_and_the_steward_cannot_put_the_node_back() {
    let s = stewarded();
    let (phone_keys, phone_cert) = node();
    // The steward admits the phone; the owner, holding that pair, revokes it.
    let admitted = steward_admit(&s.steward, &s.base, &phone_cert, "phone", NOW + DAY).unwrap();
    let revoked = revoke(&s.owner, &admitted, phone_keys.node_id(), NOW + 2 * DAY).unwrap();
    assert_eq!(revoked.seq(), s.base.seq() + STEWARD_SEQ_SPAN + 1);
    assert_eq!(revoked.verify().unwrap(), Signer::Owner);
    assert!(revoked.base().is_none());
    // The steward stays listed (a steward key is not a node), the phone is gone.
    assert_eq!(
        revoked.roster_body().stewards,
        s.base.roster_body().stewards
    );
    assert!(!revoked.is_member(&phone_keys.node_id()));
    assert_eq!(
        adopted_signer(judged(Some(&admitted), &revoked, NOW + 2 * DAY)),
        Signer::Owner
    );

    // The steward cannot admit it again through the tool ...
    assert!(matches!(
        steward_admit(&s.steward, &revoked, &phone_cert, "phone", NOW + 3 * DAY),
        Err(AdminError::Revoked(id)) if id == phone_keys.node_id()
    ));
    // ... nor by hand: a pair of its own that appends the node is refused by a verifier.
    let (mut roster, mut policy, base) = revoked
        .steward_successor(&s.steward, NOW + 3 * DAY)
        .unwrap();
    roster.members.push(RosterMember {
        node_id: phone_keys.node_id(),
        min_serial: 1,
    });
    policy.members.push(PolicyMember {
        node_id: phone_keys.node_id(),
        name: "phone".into(),
        roles: vec![],
    });
    policy.certs.push(phone_cert.clone());
    let forced =
        Documents::signed_with(s.steward.signing_key(), roster, policy, Some(base)).unwrap();
    assert!(matches!(
        judged(Some(&revoked), &forced, NOW + 3 * DAY),
        Verdict::Reject(Reason::BadAppend)
    ));

    // What the steward may still do from the revocation pair: renew it, keeping the revocation.
    let renewed = steward_renew(&s.steward, &revoked, NOW + 3 * DAY).unwrap();
    assert_eq!(renewed.seq(), revoked.seq() + 1);
    assert_eq!(renewed.roster_body().revoked, revoked.roster_body().revoked);
    assert_eq!(
        adopted_signer(judged(Some(&revoked), &renewed, NOW + 3 * DAY)),
        Signer::Steward {
            key: s.steward.public(),
            base_seq: revoked.seq()
        }
    );
    // A renewal that left the revocation out would be refused.
    let mut plain = renewed.roster_body().clone();
    plain.revoked.clear();
    let tampered = Documents::signed_with(
        s.steward.signing_key(),
        plain,
        renewed.policy_body().clone(),
        renewed.base().map(|(r, p)| Base {
            roster: r.clone(),
            policy: p.clone(),
            seq: revoked.seq(),
        }),
    )
    .unwrap();
    assert!(matches!(
        judged(Some(&revoked), &tampered, NOW + 3 * DAY),
        Verdict::Reject(Reason::FieldChanged)
    ));
}

#[test]
fn only_the_owner_of_these_documents_can_revoke() {
    let b = busy();
    assert!(matches!(
        revoke(&OwnerKey::generate(), &b.docs, b.phone, NOW),
        Err(AdminError::NotThisOwner)
    ));
}

#[test]
fn removing_grants_takes_exactly_the_matching_ones() {
    let b = busy();
    let network_id = b.docs.network_id();
    let (phone, laptop) = (
        PrincipalTarget::Node(b.phone),
        NodeOrWildcard::Node(b.laptop),
    );

    // No services named: the grant from the phone to the laptop goes whole. The phone's
    // grant to everyone (`*`) and everyone else's stay.
    let whole = remove_grants(&b.owner, &b.docs, &phone, &laptop, None, NOW + 1).unwrap();
    assert_eq!(whole.seq(), b.docs.seq() + 1);
    assert_eq!(whole.policy_body().grants.len(), 5);
    assert!(
        whole
            .policy_body()
            .grants
            .iter()
            .all(|g| !(g.from.target == phone && g.to_node == laptop))
    );
    assert!(whole.policy_body().grants.contains(&Grant {
        to_node: NodeOrWildcard::Any,
        ..node_grant(network_id, b.phone, b.laptop, &["tcp:web"])
    }));
    // Nothing but the grants changed.
    assert_eq!(whole.roster_body().members, b.docs.roster_body().members);
    assert_eq!(whole.policy_body().members, b.docs.policy_body().members);
    assert_eq!(whole.policy_body().certs, b.docs.policy_body().certs);
    assert_eq!(whole.verify().unwrap(), Signer::Owner);
    assert_eq!(
        adopted_signer(judged(Some(&b.docs), &whole, NOW + 1)),
        Signer::Owner
    );

    // `*` is its own target: the phone's grant to everyone goes and the one to the laptop stays.
    let any = remove_grants(
        &b.owner,
        &b.docs,
        &phone,
        &NodeOrWildcard::Any,
        None,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(any.policy_body().grants.len(), 5);
    assert!(any.policy_body().grants.contains(&node_grant(
        network_id,
        b.phone,
        b.laptop,
        &["tcp:ssh"]
    )));

    // A role is a target like a node.
    let role = remove_grants(
        &b.owner,
        &b.docs,
        &PrincipalTarget::Role("family".into()),
        &laptop,
        None,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(role.policy_body().grants.len(), 5);
    assert!(
        role.policy_body()
            .grants
            .iter()
            .all(|g| !matches!(g.from.target, PrincipalTarget::Role(_)))
    );
}

#[test]
fn removing_some_services_leaves_the_rest_and_a_grant_left_empty_goes() {
    let (owner, laptop, _, docs) = founded();
    let (phone, phone_cert) = node();
    let docs = admit(&owner, &docs, &phone_cert, "phone", &[], NOW).unwrap();
    let network_id = docs.network_id();
    let (from, to) = (phone.node_id(), laptop.node_id());
    let docs = grant(
        &owner,
        &docs,
        node_grant(network_id, from, to, &["tcp:ssh", "http:app"]),
        NOW,
    )
    .unwrap();
    let docs = grant(
        &owner,
        &docs,
        node_grant(network_id, from, to, &["tcp:db"]),
        NOW,
    )
    .unwrap();
    let (target, to_node) = (PrincipalTarget::Node(from), NodeOrWildcard::Node(to));

    // One service of two: the grant stays with the other.
    let partial = remove_grants(
        &owner,
        &docs,
        &target,
        &to_node,
        Some(&[service("tcp:ssh")]),
        NOW + 1,
    )
    .unwrap();
    assert_eq!(
        partial.policy_body().grants,
        vec![
            node_grant(network_id, from, to, &["http:app"]),
            node_grant(network_id, from, to, &["tcp:db"]),
        ]
    );
    assert_eq!(
        adopted_signer(judged(Some(&docs), &partial, NOW + 1)),
        Signer::Owner
    );

    // The last service of a grant takes the grant with it; services of several grants at once.
    let more = remove_grants(
        &owner,
        &partial,
        &target,
        &to_node,
        Some(&[service("http:app"), service("tcp:db")]),
        NOW + 2,
    )
    .unwrap();
    assert!(more.policy_body().grants.is_empty());
    assert_eq!(more.seq(), partial.seq() + 1);

    // Patterns match as written: `tcp:*` is not `tcp:ssh`, and a service no grant holds is
    // nothing to remove. No pair is made, so no number is spent.
    for list in [
        &[service("tcp:*")][..],
        &[service("http:ssh")][..],
        &[service("tcp:other")][..],
        &[][..],
    ] {
        assert!(matches!(
            remove_grants(&owner, &docs, &target, &to_node, Some(list), NOW + 1),
            Err(AdminError::NoSuchGrant)
        ));
    }
    // Nothing from this principal, nothing to this target.
    assert!(matches!(
        remove_grants(
            &owner,
            &docs,
            &PrincipalTarget::Node(to),
            &to_node,
            None,
            NOW
        ),
        Err(AdminError::NoSuchGrant)
    ));
    assert!(matches!(
        remove_grants(&owner, &docs, &target, &NodeOrWildcard::Any, None, NOW),
        Err(AdminError::NoSuchGrant)
    ));
    assert!(matches!(
        remove_grants(&owner, &more, &target, &to_node, None, NOW),
        Err(AdminError::NoSuchGrant)
    ));
}

#[test]
fn an_expired_grant_is_removed_like_any_other_and_a_wildcard_pattern_is_an_exact_string() {
    let (owner, laptop, _, docs) = founded();
    let (phone, phone_cert) = node();
    let docs = admit(&owner, &docs, &phone_cert, "phone", &[], NOW).unwrap();
    let network_id = docs.network_id();
    let (from, to) = (phone.node_id(), laptop.node_id());
    let mut old = node_grant(network_id, from, to, &["tcp:*", "tcp:ssh"]);
    old.expires = Some(NOW - DAY);
    let docs = grant(&owner, &docs, old, NOW).unwrap();
    let (target, to_node) = (PrincipalTarget::Node(from), NodeOrWildcard::Node(to));
    let next = remove_grants(
        &owner,
        &docs,
        &target,
        &to_node,
        Some(&[service("tcp:*")]),
        NOW + 1,
    )
    .unwrap();
    // Only the pattern written `tcp:*` went; `tcp:ssh` stays, and so does the expiry.
    assert_eq!(next.policy_body().grants.len(), 1);
    assert_eq!(
        next.policy_body().grants[0].services,
        vec![service("tcp:ssh")]
    );
    assert_eq!(next.policy_body().grants[0].expires, Some(NOW - DAY));
    let gone = remove_grants(&owner, &next, &target, &to_node, None, NOW + 2).unwrap();
    assert!(gone.policy_body().grants.is_empty());
}

#[test]
fn removing_grants_beside_a_steward_jumps_the_span() {
    let s = stewarded();
    let me = s.base.roster_body().members[0].node_id;
    let g = node_grant(s.base.network_id(), me, me, &["tcp:ssh"]);
    let with = grant(&s.owner, &s.base, g, NOW).unwrap();
    let next = remove_grants(
        &s.owner,
        &with,
        &PrincipalTarget::Node(me),
        &NodeOrWildcard::Node(me),
        None,
        NOW + 1,
    )
    .unwrap();
    assert_eq!(next.seq(), with.seq() + STEWARD_SEQ_SPAN + 1);
    assert_eq!(next.roster_body().stewards.len(), 1);
}

// ---- accept_cert and next_cert (cert rotation S2) ----

/// A network with a founder and a member "phone" (serial 1 listed), by the owner.
fn with_phone() -> (OwnerKey, NodeKeys, NodeCert, Documents) {
    let (owner, _, _, docs) = founded();
    let (phone, phone_cert) = node();
    let docs = admit(&owner, &docs, &phone_cert, "phone", &[], NOW).unwrap();
    (owner, phone, phone_cert, docs)
}

fn certs_of(docs: &Documents, id: NodeId) -> Vec<u32> {
    docs.policy_body()
        .certs
        .iter()
        .map(|c| c.decode().unwrap())
        .filter(|b| b.node_id == id)
        .map(|b| b.serial)
        .collect()
}

#[test]
fn an_accepted_renewal_replaces_the_old_certificate_and_keeps_min_serial() {
    let (owner, phone, _, docs) = with_phone();
    let renewed = phone
        .next_cert(
            &phone.issue_cert(1, NOW - 1000, NOW + DAY).unwrap(),
            None,
            NOW + DAY,
        )
        .unwrap();
    let next = accept_cert(&owner, &docs, &renewed, NOW + DAY).unwrap();
    assert_eq!(next.seq(), docs.seq() + 1);
    assert_eq!(certs_of(&next, phone.node_id()), vec![2]);
    assert!(next.policy_body().certs.contains(&renewed));
    // The founder's certificate is still listed.
    assert_eq!(
        next.policy_body().certs.len(),
        docs.policy_body().certs.len()
    );
    // The Roster keeps min_serial 1: the old certificate is not cut off by listing the new.
    assert_eq!(next.roster_body().members, docs.roster_body().members);
    assert_eq!(
        next.roster_body()
            .members
            .iter()
            .find(|m| m.node_id == phone.node_id())
            .unwrap()
            .min_serial,
        1
    );
    assert_eq!(next.verify().unwrap(), Signer::Owner);
    assert_eq!(
        adopted_signer(judged(Some(&docs), &next, NOW + DAY)),
        Signer::Owner
    );
    // A third rotation replaces the second, the list does not grow.
    let third = phone.next_cert(&renewed, Some(2), NOW + 2 * DAY).unwrap();
    let again = accept_cert(&owner, &next, &third, NOW + 2 * DAY).unwrap();
    assert_eq!(certs_of(&again, phone.node_id()), vec![3]);
    assert_eq!(
        again.policy_body().certs.len(),
        docs.policy_body().certs.len()
    );
}

#[test]
fn a_certificate_not_above_the_listed_serial_is_refused() {
    let (owner, phone, _, docs) = with_phone();
    for serial in [0u32, 1] {
        let cert = phone.issue_cert(serial, NOW - 1000, NOW + DAY).unwrap();
        assert!(matches!(
            accept_cert(&owner, &docs, &cert, NOW),
            Err(AdminError::StaleCert { listed: 1, offered }) if offered == serial
        ));
    }
    let two = phone.issue_cert(2, NOW - 1000, NOW + DAY).unwrap();
    let docs = accept_cert(&owner, &docs, &two, NOW).unwrap();
    // Lower than the new listed one, though above the first.
    let again = phone.issue_cert(2, NOW - 900, NOW + DAY).unwrap();
    assert!(matches!(
        accept_cert(&owner, &docs, &again, NOW),
        Err(AdminError::StaleCert {
            listed: 2,
            offered: 2
        })
    ));
}

#[test]
fn a_renewal_with_another_key_is_refused() {
    let (owner, phone, _, docs) = with_phone();
    let other = NodeKeys::generate();
    let body = NodeCertBody {
        v: menzil_proto::PROTOCOL_VERSION,
        node_id: phone.node_id(),
        x25519_pub: other.x25519_public(),
        serial: 2,
        not_before: NOW - 1000,
        not_after: NOW + DAY,
    };
    let cert = NodeCert::sign(phone.signing_key(), &body).unwrap();
    assert!(matches!(
        accept_cert(&owner, &docs, &cert, NOW),
        Err(AdminError::NewKey(id)) if id == phone.node_id()
    ));
}

#[test]
fn a_revoked_or_unknown_node_cannot_have_a_renewal_listed() {
    let (owner, phone, _, docs) = with_phone();
    let cert = phone.issue_cert(2, NOW - 1000, NOW + DAY).unwrap();
    let revoked = revoke(&owner, &docs, phone.node_id(), NOW + 1).unwrap();
    assert!(matches!(
        accept_cert(&owner, &revoked, &cert, NOW + 2),
        Err(AdminError::Revoked(id)) if id == phone.node_id()
    ));
    let stranger = NodeKeys::generate();
    let cert = stranger.issue_cert(2, NOW - 1000, NOW + DAY).unwrap();
    assert!(matches!(
        accept_cert(&owner, &docs, &cert, NOW),
        Err(AdminError::NotAMember(id)) if id == stranger.node_id()
    ));
}

#[test]
fn a_renewal_must_verify_be_valid_now_and_last_at_most_400_days() {
    let (owner, phone, _, docs) = with_phone();
    let long = NodeCertBody {
        v: menzil_proto::PROTOCOL_VERSION,
        node_id: phone.node_id(),
        x25519_pub: phone.x25519_public(),
        serial: 2,
        not_before: NOW - 1000,
        not_after: NOW - 1000 + 400 * DAY + 1,
    };
    let cert = NodeCert::sign(phone.signing_key(), &long).unwrap();
    assert!(matches!(
        accept_cert(&owner, &docs, &cert, NOW),
        Err(AdminError::CertLifetimeTooLong)
    ));
    let ok = phone
        .issue_cert(2, NOW - 1000, NOW - 1000 + 400 * DAY)
        .unwrap();
    accept_cert(&owner, &docs, &ok, NOW).unwrap();
    let future = phone.issue_cert(2, NOW + 10, NOW + DAY).unwrap();
    assert!(matches!(
        accept_cert(&owner, &docs, &future, NOW),
        Err(AdminError::CertNotValidNow)
    ));
    // Signed by another key than its node id.
    let forger = NodeKeys::generate();
    let forged = NodeCert::sign(
        forger.signing_key(),
        &NodeCertBody {
            not_after: NOW + DAY,
            ..long
        },
    )
    .unwrap();
    assert!(matches!(
        accept_cert(&owner, &docs, &forged, NOW),
        Err(AdminError::CertDoesNotVerify)
    ));
}

#[test]
fn accepting_a_renewal_beside_a_steward_jumps_the_span() {
    let s = stewarded();
    let (phone, phone_cert) = node();
    let admitted = steward_admit(&s.steward, &s.base, &phone_cert, "phone", NOW + DAY).unwrap();
    let renewed = phone.next_cert(&phone_cert, None, NOW + 2 * DAY).unwrap();
    let next = accept_cert(&s.owner, &admitted, &renewed, NOW + 2 * DAY).unwrap();
    assert_eq!(next.seq(), s.base.seq() + STEWARD_SEQ_SPAN + 1);
    assert!(next.base().is_none());
    assert_eq!(certs_of(&next, phone.node_id()), vec![2]);
    assert_eq!(
        adopted_signer(judged(Some(&admitted), &next, NOW + 2 * DAY)),
        Signer::Owner
    );
}

#[test]
fn the_next_certificate_is_above_the_file_and_the_listed_serial() {
    let keys = NodeKeys::generate();
    let file = keys.issue_cert(3, NOW - 1000, NOW + DAY).unwrap();
    let serial = |cert: NodeCert| cert.decode().unwrap().serial;
    assert_eq!(serial(keys.next_cert(&file, None, NOW).unwrap()), 4);
    assert_eq!(serial(keys.next_cert(&file, Some(2), NOW).unwrap()), 4);
    assert_eq!(serial(keys.next_cert(&file, Some(3), NOW).unwrap()), 4);
    assert_eq!(serial(keys.next_cert(&file, Some(9), NOW).unwrap()), 10);
    let next = keys.next_cert(&file, None, NOW).unwrap().decode().unwrap();
    assert_eq!(next.not_before, NOW - DAY);
    assert_eq!(next.not_after, NOW - DAY + 400 * DAY);
    assert_eq!(next.node_id, keys.node_id());
    assert_eq!(next.x25519_pub, keys.x25519_public());
    // Another node's certificate is not ours to renew.
    let (_, foreign) = node();
    assert!(matches!(
        keys.next_cert(&foreign, None, NOW),
        Err(AdminError::CertDoesNotVerify)
    ));
}

#[test]
fn the_serial_does_not_wrap_at_its_maximum() {
    let keys = NodeKeys::generate();
    let max = keys.issue_cert(u32::MAX, NOW - 1000, NOW + DAY).unwrap();
    assert!(matches!(
        keys.next_cert(&max, None, NOW),
        Err(AdminError::SerialExhausted)
    ));
    let low = keys.issue_cert(1, NOW - 1000, NOW + DAY).unwrap();
    assert!(matches!(
        keys.next_cert(&low, Some(u32::MAX), NOW),
        Err(AdminError::SerialExhausted)
    ));
    let below = keys
        .issue_cert(u32::MAX - 1, NOW - 1000, NOW + DAY)
        .unwrap();
    assert_eq!(
        keys.next_cert(&below, None, NOW)
            .unwrap()
            .decode()
            .unwrap()
            .serial,
        u32::MAX
    );
}

// ---- steward_rotate (cert rotation S3) ----

/// A network whose owner admitted "phone" and "tablet" (serial 1 each) and then delegated a
/// steward with the rights `may`.
struct Rotating {
    owner: OwnerKey,
    steward: StewardSecret,
    phone: NodeKeys,
    tablet: NodeKeys,
    base: Documents,
}

fn rotating_with(may: &[&str]) -> Rotating {
    let (owner, _, _, docs) = founded();
    let (phone, phone_cert) = node();
    let (tablet, tablet_cert) = node();
    let docs = admit(&owner, &docs, &phone_cert, "phone", &[], NOW).unwrap();
    let docs = admit(&owner, &docs, &tablet_cert, "tablet", &[], NOW).unwrap();
    let steward = StewardSecret::generate();
    let base = delegate_steward(
        &owner,
        &docs,
        steward.public(),
        &rights(may),
        NOW + 30 * DAY,
        NOW,
    )
    .unwrap();
    Rotating {
        owner,
        steward,
        phone,
        tablet,
        base,
    }
}

fn renewed(keys: &NodeKeys, serial: u32) -> NodeCert {
    keys.issue_cert(serial, NOW + DAY - 1000, NOW + DAY - 1000 + 400 * DAY)
        .unwrap()
}

#[test]
fn a_steward_rotation_lists_the_renewal_and_the_network_adopts_it() {
    let r = rotating_with(&ADMIT_RENEW);
    let at = NOW + DAY;
    let cert = renewed(&r.phone, 2);
    let next = steward_rotate(&r.steward, &r.base, std::slice::from_ref(&cert), at).unwrap();
    assert_eq!(next.seq(), r.base.seq() + 1);
    // Appended after the base's certificates; the base's own are all still there.
    let base_certs = &r.base.policy_body().certs;
    assert_eq!(
        &next.policy_body().certs[..base_certs.len()],
        &base_certs[..]
    );
    assert_eq!(next.policy_body().certs.last().unwrap(), &cert);
    assert_eq!(next.policy_body().certs.len(), base_certs.len() + 1);
    // The Roster keeps its members and every `min_serial`.
    assert_eq!(next.roster_body().members, r.base.roster_body().members);
    let signer = Signer::Steward {
        key: r.steward.public(),
        base_seq: r.base.seq(),
    };
    assert_eq!(adopted_signer(judged(Some(&r.base), &next, at)), signer);
    assert_eq!(adopted_signer(judged(None, &next, at)), signer);
    // The relay judges the Roster alone, with its base: that passes too.
    let roster_only = Bundle {
        base_roster: next.bundle().base_roster,
        roster: next.bundle().roster,
        ..Bundle::default()
    };
    let view = r.base.held_view().unwrap();
    assert!(matches!(
        check_bundle(&view, &roster_only, at),
        Verdict::Adopt(_)
    ));
    // A node adopts it through its stores.
    let (rosters, policies) = load(&r.base);
    let store = menzil_node::DocStore::new(&rosters, &policies);
    let adopted = store.adopt(&next.bundle(), at).unwrap();
    assert!(adopted.roster && adopted.policy);
}

#[test]
fn a_second_rotation_replaces_the_tail_certificate_in_place_and_batches_several() {
    let r = rotating_with(&ADMIT_RENEW);
    let at = NOW + DAY;
    let first = steward_rotate(&r.steward, &r.base, &[renewed(&r.phone, 2)], at).unwrap();
    let base_len = r.base.policy_body().certs.len();
    // Phone again (serial 3) and tablet (serial 2) in one pair.
    let batch = [renewed(&r.phone, 3), renewed(&r.tablet, 2)];
    let second = steward_rotate(&r.steward, &first, &batch, at + 60).unwrap();
    let tail = &second.policy_body().certs[base_len..];
    assert_eq!(tail.len(), 2, "one tail certificate per node");
    assert_eq!(tail[0], batch[0]);
    assert_eq!(tail[1], batch[1]);
    assert_eq!(
        adopted_signer(judged(Some(&first), &second, at + 60)),
        Signer::Steward {
            key: r.steward.public(),
            base_seq: r.base.seq(),
        }
    );
}

#[test]
fn a_rotation_needs_both_the_admit_and_the_renew_right() {
    let at = NOW + DAY;
    for may in [&["renew"][..], &["admit"][..]] {
        let r = rotating_with(may);
        assert!(
            matches!(
                steward_rotate(&r.steward, &r.base, &[renewed(&r.phone, 2)], at),
                Err(AdminError::Rejected(Reason::RightMissing))
            ),
            "{may:?}"
        );
    }
}

#[test]
fn a_rotation_refuses_what_the_owner_op_refuses() {
    let r = rotating_with(&ADMIT_RENEW);
    let at = NOW + DAY;
    // Not above the listed serial.
    assert!(matches!(
        steward_rotate(&r.steward, &r.base, &[renewed(&r.phone, 1)], at),
        Err(AdminError::StaleCert {
            listed: 1,
            offered: 1
        })
    ));
    // Another key.
    let other = NodeKeys::generate();
    let body = NodeCertBody {
        v: menzil_proto::PROTOCOL_VERSION,
        node_id: r.phone.node_id(),
        x25519_pub: other.x25519_public(),
        serial: 2,
        not_before: NOW,
        not_after: NOW + DAY,
    };
    let cert = NodeCert::sign(r.phone.signing_key(), &body).unwrap();
    assert!(matches!(
        steward_rotate(&r.steward, &r.base, &[cert], at),
        Err(AdminError::NewKey(id)) if id == r.phone.node_id()
    ));
    // A stranger.
    let stranger = NodeKeys::generate();
    assert!(matches!(
        steward_rotate(&r.steward, &r.base, &[renewed(&stranger, 2)], at),
        Err(AdminError::NotAMember(id)) if id == stranger.node_id()
    ));
    // A window over 400 days.
    let body = NodeCertBody {
        v: menzil_proto::PROTOCOL_VERSION,
        node_id: r.phone.node_id(),
        x25519_pub: r.phone.x25519_public(),
        serial: 2,
        not_before: NOW,
        not_after: NOW + 400 * DAY + 1,
    };
    let cert = NodeCert::sign(r.phone.signing_key(), &body).unwrap();
    assert!(matches!(
        steward_rotate(&r.steward, &r.base, &[cert], at),
        Err(AdminError::CertLifetimeTooLong)
    ));
    // A revoked node: the owner revokes after the delegation, the steward builds on that pair.
    let revoked = revoke(&r.owner, &r.base, r.phone.node_id(), NOW + 10).unwrap();
    assert!(matches!(
        steward_rotate(&r.steward, &revoked, &[renewed(&r.phone, 2)], at),
        Err(AdminError::Revoked(id)) if id == r.phone.node_id()
    ));
}

// ---- round A fixes (L3, L4) ----

fn count_certs(docs: &Documents, id: NodeId) -> usize {
    certs_of(docs, id).len()
}

#[test]
fn owner_operations_do_not_carry_superseded_certificates_forward() {
    let (owner, keys, cert, docs) = founded();
    let steward = StewardSecret::generate();
    let mut docs = delegate_steward(
        &owner,
        &docs,
        steward.public(),
        &rights(&ADMIT_RENEW),
        NOW + 30 * DAY,
        NOW,
    )
    .unwrap();
    let id = keys.node_id();
    let mut current = cert;
    for i in 1..=4u64 {
        let at = NOW + i * 3600;
        let listed = docs
            .policy_body()
            .certs
            .iter()
            .map(|c| c.decode().unwrap().serial)
            .max();
        let next = keys.next_cert(&current, listed, at).unwrap();
        let rotated = steward_rotate(&steward, &docs, std::slice::from_ref(&next), at).unwrap();
        // The steward pair keeps the base certificate beside the renewal (its prefix rule).
        assert_eq!(count_certs(&rotated, id), 2, "round {i}");
        docs = renew(&owner, &rotated, at + 1).unwrap();
        // The owner pair keeps the renewal only.
        assert_eq!(
            certs_of(&docs, id),
            vec![next.decode().unwrap().serial],
            "round {i}"
        );
        current = next;
    }
}

#[test]
fn pruning_keeps_the_older_certificate_while_the_higher_one_is_not_yet_established() {
    let (owner, keys, cert, docs) = founded();
    let id = keys.node_id();
    // Serial 2 starts 60 s ago: not yet past the margin, so serial 1 stays.
    let fresh = keys.issue_cert(2, NOW - 60, NOW + 100 * DAY).unwrap();
    let mut policy = docs.policy_body().clone();
    policy.certs.push(fresh.clone());
    let with_both = Documents::signed(&owner, docs.roster_body().clone(), policy).unwrap();
    let next = renew(&owner, &with_both, NOW).unwrap();
    assert_eq!(certs_of(&next, id), vec![1, 2]);
    // Once it is older than the margin, serial 1 goes.
    let later = renew(&owner, &next, NOW + CERT_ISSUE_MARGIN_SECS).unwrap();
    assert_eq!(certs_of(&later, id), vec![2]);
    let _ = cert;
}

#[test]
fn a_renewal_must_have_been_valid_for_the_issue_margin() {
    let (owner, phone, _, docs) = with_phone();
    let at = NOW + 1000;
    let too_fresh = phone
        .issue_cert(2, at - CERT_ISSUE_MARGIN_SECS + 1, at + DAY)
        .unwrap();
    assert!(matches!(
        accept_cert(&owner, &docs, &too_fresh, at),
        Err(AdminError::CertTooFresh)
    ));
    let exact = phone
        .issue_cert(2, at - CERT_ISSUE_MARGIN_SECS, at + DAY)
        .unwrap();
    let next = accept_cert(&owner, &docs, &exact, at).unwrap();
    // A verifier a margin behind still sees it valid.
    assert!(
        next.policy_body()
            .certs
            .iter()
            .any(|c| c.decode().unwrap().is_valid_at(at - CERT_ISSUE_MARGIN_SECS))
    );
}

#[test]
fn a_steward_rotation_must_have_been_valid_for_the_issue_margin() {
    let r = rotating_with(&ADMIT_RENEW);
    let at = NOW + DAY;
    let too_fresh = r
        .phone
        .issue_cert(2, at - CERT_ISSUE_MARGIN_SECS + 1, at + DAY)
        .unwrap();
    assert!(matches!(
        steward_rotate(&r.steward, &r.base, &[too_fresh], at),
        Err(AdminError::CertTooFresh)
    ));
    let exact = r
        .phone
        .issue_cert(2, at - CERT_ISSUE_MARGIN_SECS, at + DAY)
        .unwrap();
    steward_rotate(&r.steward, &r.base, &[exact], at).unwrap();
}
