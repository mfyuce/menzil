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
