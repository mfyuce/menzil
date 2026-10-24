use ed25519_dalek::SigningKey;

use super::*;
use crate::bytes::X25519PublicKey;
use crate::identity::{NodeCert, NodeCertBody};
use crate::network::{
    AcceptEntry, Grant, Label, NodeOrWildcard, Principal, PrincipalTarget, RevokedMember,
    RosterMember, StewardBody,
};

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

fn key() -> SigningKey {
    SigningKey::generate(&mut rand::rng())
}

fn node(n: u8) -> NodeId {
    NodeId::from([n; 32])
}

fn id_of(key: &SigningKey) -> NodeId {
    NodeId::from(key.verifying_key().to_bytes())
}

/// A network at base `seq`, owned by `owner`, with one steward `steward` and a base pair.
struct Fx {
    owner: SigningKey,
    steward: SigningKey,
    other: SigningKey,
    net: NetworkId,
    not_after: u64,
    rb: RosterBody,
    pb: PolicyBody,
    base_roster: Roster,
    base_policy: Policy,
}

struct FxOptions {
    base_seq: u64,
    not_after: u64,
    entry_signer_is_owner: bool,
    entries: usize,
}

impl Default for FxOptions {
    fn default() -> Self {
        Self {
            base_seq: 10,
            not_after: NOW + 30 * DAY,
            entry_signer_is_owner: true,
            entries: 1,
        }
    }
}

impl Fx {
    fn new() -> Self {
        Self::with(FxOptions::default())
    }

    fn at(base_seq: u64) -> Self {
        Self::with(FxOptions {
            base_seq,
            ..FxOptions::default()
        })
    }

    fn with(options: FxOptions) -> Self {
        let owner = key();
        let steward = key();
        let other = key();
        let net = NetworkId::from(owner.verifying_key().to_bytes());
        let entry_body = StewardBody {
            v: PROTOCOL_VERSION,
            network_id: net,
            steward_pub: StewardKey::from(steward.verifying_key().to_bytes()),
            may: vec!["admit".to_string(), "renew".to_string()],
            not_after: options.not_after,
        };
        let entry_key = if options.entry_signer_is_owner {
            &owner
        } else {
            &other
        };
        let entry = Steward::sign(entry_key, &entry_body).unwrap();
        let rb = RosterBody {
            v: PROTOCOL_VERSION,
            network_id: net,
            seq: options.base_seq,
            issued: NOW - DAY,
            expires: NOW + 5 * DAY,
            members: vec![
                RosterMember {
                    node_id: node(1),
                    min_serial: 1,
                },
                RosterMember {
                    node_id: node(2),
                    min_serial: 3,
                },
            ],
            revoked: vec![RevokedMember {
                node_id: node(9),
                since: NOW - 10 * DAY,
            }],
            stewards: vec![entry; options.entries],
            labels: vec![Label {
                name: "home".to_string(),
                node_id: node(1),
            }],
        };
        let pb = PolicyBody {
            v: PROTOCOL_VERSION,
            network_id: net,
            seq: options.base_seq,
            issued: NOW - DAY,
            expires: NOW + 5 * DAY,
            members: vec![
                PolicyMember {
                    node_id: node(1),
                    name: "laptop".to_string(),
                    roles: vec!["admin".to_string()],
                },
                PolicyMember {
                    node_id: node(2),
                    name: "server".to_string(),
                    roles: vec![],
                },
            ],
            certs: vec![],
            grants: vec![Grant {
                from: Principal {
                    network_id: net,
                    target: PrincipalTarget::Node(node(1)),
                },
                to_node: NodeOrWildcard::Node(node(2)),
                services: vec!["tcp:ssh".parse().unwrap()],
                expires: None,
            }],
            egress: vec![],
            accept: vec![AcceptEntry {
                node_id: node(2),
                peers: true,
            }],
        };
        let base_roster = Roster::sign(&owner, &rb).unwrap();
        let base_policy = Policy::sign(&owner, &pb).unwrap();
        Self {
            owner,
            steward,
            other,
            net,
            not_after: options.not_after,
            rb,
            pb,
            base_roster,
            base_policy,
        }
    }

    fn base_seq(&self) -> u64 {
        self.rb.seq
    }

    /// A pair at `seq` signed by `signer` from the base, carrying the base, after `edit`.
    fn pair(
        &self,
        signer: &SigningKey,
        seq: u64,
        edit: impl FnOnce(&mut RosterBody, &mut PolicyBody),
    ) -> Bundle {
        let mut r = self.rb.clone();
        let mut p = self.pb.clone();
        r.seq = seq;
        p.seq = seq;
        r.issued = NOW;
        p.issued = NOW;
        r.expires = (NOW + 7 * DAY).min(self.not_after);
        p.expires = r.expires;
        edit(&mut r, &mut p);
        Bundle {
            base_roster: Some(self.base_roster.clone()),
            base_policy: Some(self.base_policy.clone()),
            roster: Some(Roster::sign(signer, &r).unwrap()),
            policy: Some(Policy::sign(signer, &p).unwrap()),
        }
    }

    /// A steward pair one above the base after `edit`.
    fn steward_pair(&self, edit: impl FnOnce(&mut RosterBody, &mut PolicyBody)) -> Bundle {
        self.pair(&self.steward, self.base_seq() + 1, edit)
    }

    fn held_nothing(&self) -> HeldView {
        HeldView {
            network_id: self.net,
            roster: None,
            policy_seq: None,
        }
    }

    fn check(&self, bundle: &Bundle) -> Verdict {
        check_bundle(&self.held_nothing(), bundle, NOW)
    }
}

fn rejected(verdict: Verdict) -> Reason {
    match verdict {
        Verdict::Reject(reason) => reason,
        other => panic!("expected a rejection, got {other:?}"),
    }
}

fn adopted(verdict: Verdict) -> Adoption {
    match verdict {
        Verdict::Adopt(adoption) => *adoption,
        other => panic!("expected an adoption, got {other:?}"),
    }
}

/// Admits a new member with `new_key`'s identity named `name` into both documents.
fn admit(new_key: &SigningKey, name: &str, r: &mut RosterBody, p: &mut PolicyBody) {
    let node_id = id_of(new_key);
    r.members.push(RosterMember {
        node_id,
        min_serial: 1,
    });
    p.members.push(PolicyMember {
        node_id,
        name: name.to_string(),
        roles: vec!["ops".to_string()],
    });
    let cert = NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id,
        x25519_pub: X25519PublicKey::from([7u8; 32]),
        serial: 1,
        not_before: NOW - DAY,
        not_after: NOW + 100 * DAY,
    };
    p.certs.push(NodeCert::sign(new_key, &cert).unwrap());
}

#[test]
fn an_owner_signed_pair_passes_unchanged() {
    let fx = Fx::new();
    let bundle = fx.pair(&fx.owner, 11, |r, p| {
        // The owner may change anything.
        r.revoked.clear();
        p.grants.clear();
    });
    let adoption = adopted(fx.check(&bundle));
    assert_eq!(adoption.signer, Signer::Owner);
    assert_eq!(adoption.roster.unwrap().seq, 11);
    assert_eq!(adoption.policy.unwrap().seq, 11);
}

#[test]
fn a_steward_renewal_passes_and_names_its_signer() {
    let fx = Fx::new();
    let adoption = adopted(fx.check(&fx.steward_pair(|_, _| {})));
    assert_eq!(
        adoption.signer,
        Signer::Steward {
            key: StewardKey::from(fx.steward.verifying_key().to_bytes()),
            base_seq: 10,
        }
    );
}

#[test]
fn a_steward_admission_with_its_certificate_passes() {
    let fx = Fx::new();
    let new_key = key();
    let bundle = fx.steward_pair(|r, p| admit(&new_key, "phone", r, p));
    let adoption = adopted(fx.check(&bundle));
    assert_eq!(adoption.roster.unwrap().members.len(), 3);
    assert_eq!(adoption.policy.unwrap().certs.len(), 1);
}

#[test]
fn a_renewal_that_changes_grants_is_refused() {
    let fx = Fx::new();
    let bundle = fx.steward_pair(|_, p| p.grants.clear());
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
}

#[test]
fn a_renewal_that_changes_egress_or_accept_is_refused() {
    let fx = Fx::new();
    let bundle = fx.steward_pair(|_, p| p.accept.clear());
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
    let bundle = fx.steward_pair(|_, p| {
        p.egress.push(crate::network::EgressRule {
            node_id: node(1),
            allow: vec![],
            deny: vec![],
        })
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
}

#[test]
fn a_steward_cannot_unrevoke() {
    let fx = Fx::new();
    let bundle = fx.steward_pair(|r, _| r.revoked.clear());
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
}

#[test]
fn a_steward_cannot_change_stewards_or_labels_or_serials() {
    let fx = Fx::new();
    let bundle = fx.steward_pair(|r, _| r.stewards.clear());
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
    let bundle = fx.steward_pair(|r, _| r.labels.clear());
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
    let bundle = fx.steward_pair(|r, _| r.members[1].min_serial = 0);
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
    let bundle = fx.steward_pair(|r, _| {
        r.members.remove(0);
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
}

#[test]
fn admitting_a_revoked_or_known_or_repeated_node_is_refused() {
    let fx = Fx::new();
    let append = |id: NodeId, r: &mut RosterBody, p: &mut PolicyBody| {
        r.members.push(RosterMember {
            node_id: id,
            min_serial: 1,
        });
        p.members.push(PolicyMember {
            node_id: id,
            name: "again".to_string(),
            roles: vec![],
        });
    };
    // Revoked in the base.
    let bundle = fx.steward_pair(|r, p| append(node(9), r, p));
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadAppend);
    // Appended twice.
    let bundle = fx.steward_pair(|r, p| {
        append(node(5), r, p);
        append(node(5), r, p);
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadAppend);
}

#[test]
fn a_steward_without_the_admit_right_cannot_append() {
    let mut fx = Fx::new();
    // Rebuild the base with a renew-only entry.
    let entry_body = StewardBody {
        v: PROTOCOL_VERSION,
        network_id: fx.net,
        steward_pub: StewardKey::from(fx.steward.verifying_key().to_bytes()),
        may: vec!["renew".to_string()],
        not_after: fx.not_after,
    };
    fx.rb.stewards = vec![Steward::sign(&fx.owner, &entry_body).unwrap()];
    fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
    let new_key = key();
    let bundle = fx.steward_pair(|r, p| admit(&new_key, "phone", r, p));
    assert_eq!(rejected(fx.check(&bundle)), Reason::RightMissing);
    // Renewing is still allowed.
    adopted(fx.check(&fx.steward_pair(|_, _| {})));
}

#[test]
fn a_steward_without_the_renew_right_cannot_renew() {
    let mut fx = Fx::new();
    let entry_body = StewardBody {
        v: PROTOCOL_VERSION,
        network_id: fx.net,
        steward_pub: StewardKey::from(fx.steward.verifying_key().to_bytes()),
        may: vec!["admit".to_string()],
        not_after: fx.not_after,
    };
    fx.rb.stewards = vec![Steward::sign(&fx.owner, &entry_body).unwrap()];
    fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
    assert_eq!(
        rejected(fx.check(&fx.steward_pair(|_, _| {}))),
        Reason::RightMissing
    );
}

#[test]
fn the_roster_and_policy_must_append_the_same_members() {
    let fx = Fx::new();
    let a = key();
    let b = key();
    let bundle = fx.steward_pair(|r, p| {
        admit(&a, "phone", r, p);
        // The Policy names another node than the Roster.
        let last = p.members.last_mut().unwrap();
        last.node_id = id_of(&b);
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadAppend);
}

#[test]
fn appended_names_and_roles_are_held_to_the_hygiene_rule() {
    let fx = Fx::new();
    let new_key = key();
    let bundle = fx.steward_pair(|r, p| admit(&new_key, "bad name", r, p));
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadName);
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        p.members.last_mut().unwrap().roles = vec!["a\u{202e}b".to_string()];
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadName);
}

#[test]
fn an_appended_certificate_must_verify_and_name_an_appended_node() {
    let fx = Fx::new();
    let new_key = key();
    // Signed by another key than the node it names.
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        let body = p.certs[0].decode().unwrap();
        p.certs[0] = NodeCert::sign(&key(), &body).unwrap();
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    // A valid certificate for a node that was not appended.
    let stranger = key();
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        let body = NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: id_of(&stranger),
            x25519_pub: X25519PublicKey::from([7u8; 32]),
            serial: 1,
            not_before: NOW - DAY,
            not_after: NOW + DAY,
        };
        p.certs.push(NodeCert::sign(&stranger, &body).unwrap());
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
}

#[test]
fn the_seq_span_is_exclusive_below_and_inclusive_above() {
    let fx = Fx::new();
    let base = fx.base_seq();
    adopted(fx.check(&fx.pair(&fx.steward, base + 1, |_, _| {})));
    adopted(fx.check(&fx.pair(&fx.steward, base + STEWARD_SEQ_SPAN, |_, _| {})));
    assert_eq!(
        rejected(fx.check(&fx.pair(&fx.steward, base + STEWARD_SEQ_SPAN + 1, |_, _| {}))),
        Reason::SeqOutOfSpan
    );
    // Equal to the base: not above it. (Held view empty, so the cheap path does not answer.)
    assert_eq!(
        rejected(fx.check(&fx.pair(&fx.steward, base, |_, _| {}))),
        Reason::SeqOutOfSpan
    );
    assert_eq!(
        rejected(fx.check(&fx.pair(&fx.steward, base - 1, |_, _| {}))),
        Reason::SeqOutOfSpan
    );
}

#[test]
fn a_steward_document_cannot_outlive_its_delegation() {
    let fx = Fx::with(FxOptions {
        not_after: NOW + 5 * DAY,
        ..FxOptions::default()
    });
    // expires == not_after is fine, one second more is not.
    adopted(fx.check(&fx.steward_pair(|r, p| {
        r.expires = fx.not_after;
        p.expires = fx.not_after;
    })));
    let bundle = fx.steward_pair(|r, p| {
        r.expires = fx.not_after + 1;
        p.expires = fx.not_after + 1;
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::ExpiresAfterNotAfter);
    // The Policy alone beyond it is enough.
    let bundle = fx.steward_pair(|_, p| p.expires = fx.not_after + 1);
    assert_eq!(rejected(fx.check(&bundle)), Reason::ExpiresAfterNotAfter);
}

#[test]
fn a_steward_is_dead_at_not_after() {
    let fx = Fx::with(FxOptions {
        not_after: NOW + 5 * DAY,
        ..FxOptions::default()
    });
    // One second before: valid. At not_after: dead, whatever the document says.
    let before = fx.not_after - 1;
    adopted(check_bundle(
        &fx.held_nothing(),
        &fx.pair(&fx.steward, 11, |r, p| {
            r.expires = fx.not_after;
            p.expires = fx.not_after;
        }),
        before,
    ));
    let at = fx.not_after;
    let bundle = fx.steward_pair(|r, p| {
        r.expires = at + 100;
        p.expires = at + 100;
    });
    assert_eq!(
        rejected(check_bundle(&fx.held_nothing(), &bundle, at)),
        Reason::StewardExpired
    );
}

#[test]
fn a_base_older_than_the_held_base_is_refused() {
    // Held: a steward pair (seq 1000) made from the base at 900.
    let newer = Fx::at(900);
    let held_bundle = newer.pair(&newer.steward, 1000, |_, _| {});
    let held = HeldView {
        network_id: newer.net,
        roster: Some(
            HeldRoster::new(
                held_bundle.roster.as_ref().unwrap(),
                Some(&newer.base_roster),
            )
            .unwrap(),
        ),
        policy_seq: Some(1000),
    };
    // Offered: a steward pair at 1100 made from the older base at 10, same network and steward.
    let mut older = Fx::at(10);
    older.owner = newer.owner.clone();
    older.steward = newer.steward.clone();
    older.net = newer.net;
    older.not_after = newer.not_after;
    older.rb.network_id = newer.net;
    older.pb.network_id = newer.net;
    older.rb.stewards = newer.rb.stewards.clone();
    older.base_roster = Roster::sign(&older.owner, &older.rb).unwrap();
    older.base_policy = Policy::sign(&older.owner, &older.pb).unwrap();
    let offered = older.pair(&older.steward, 1100, |_, _| {});
    assert_eq!(
        rejected(check_bundle(&held, &offered, NOW)),
        Reason::BaseOlderThanHeld
    );
    // The same offer from a base as new as the held one is fine.
    let fine = newer.pair(&newer.steward, 1100, |_, _| {});
    adopted(check_bundle(&held, &fine, NOW));
}

#[test]
fn a_policy_signed_by_another_key_than_its_roster_is_refused() {
    let fx = Fx::new();
    // Roster by the owner, Policy by the steward (with its base).
    let owner_pair = fx.pair(&fx.owner, 11, |_, _| {});
    let steward_pair = fx.steward_pair(|_, _| {});
    let mixed = Bundle {
        roster: owner_pair.roster.clone(),
        policy: steward_pair.policy.clone(),
        base_policy: steward_pair.base_policy.clone(),
        base_roster: None,
    };
    assert_eq!(rejected(fx.check(&mixed)), Reason::PairSigner);
    // Roster by the steward, Policy by the owner.
    let mixed = Bundle {
        roster: steward_pair.roster.clone(),
        base_roster: steward_pair.base_roster.clone(),
        policy: owner_pair.policy.clone(),
        base_policy: None,
    };
    assert_eq!(rejected(fx.check(&mixed)), Reason::PairSigner);
    // A key that is nobody's.
    let stranger = fx.pair(&fx.other, 11, |_, _| {});
    assert_eq!(rejected(fx.check(&stranger)), Reason::BadSignature);
}

#[test]
fn a_roster_and_policy_from_different_bases_are_refused() {
    let fx = Fx::new();
    let a = fx.steward_pair(|_, _| {});
    // The Policy from a base at 11 (an owner Policy at 11 lists no more than the base pair).
    let mut base11 = fx.pb.clone();
    base11.seq = 11;
    let base11_signed = Policy::sign(&fx.owner, &base11).unwrap();
    let mut p = base11.clone();
    p.seq = 12;
    p.issued = NOW;
    p.expires = NOW + DAY;
    let mut r = fx.rb.clone();
    r.seq = 12;
    r.issued = NOW;
    r.expires = NOW + DAY;
    let bundle = Bundle {
        base_roster: a.base_roster.clone(),
        base_policy: Some(base11_signed),
        roster: Some(Roster::sign(&fx.steward, &r).unwrap()),
        policy: Some(Policy::sign(&fx.steward, &p).unwrap()),
    };
    assert_eq!(rejected(fx.check(&bundle)), Reason::PairSigner);
}

#[test]
fn a_steward_entry_the_owner_did_not_sign_is_refused() {
    let fx = Fx::with(FxOptions {
        entry_signer_is_owner: false,
        ..FxOptions::default()
    });
    assert_eq!(
        rejected(fx.check(&fx.steward_pair(|_, _| {}))),
        Reason::BadStewardEntry
    );
}

#[test]
fn a_base_the_owner_did_not_sign_is_refused() {
    let mut fx = Fx::new();
    fx.base_roster = Roster::sign(&fx.other, &fx.rb).unwrap();
    assert_eq!(
        rejected(fx.check(&fx.steward_pair(|_, _| {}))),
        Reason::BadSignature
    );
}

#[test]
fn a_steward_document_without_its_base_is_refused() {
    let fx = Fx::new();
    let mut bundle = fx.steward_pair(|_, _| {});
    bundle.base_roster = None;
    assert_eq!(rejected(fx.check(&bundle)), Reason::MissingBase);
    let mut bundle = fx.steward_pair(|_, _| {});
    bundle.base_policy = None;
    assert_eq!(rejected(fx.check(&bundle)), Reason::MissingBase);
}

#[test]
fn a_steward_document_from_a_base_without_a_steward_is_refused() {
    let mut fx = Fx::new();
    fx.rb.stewards.clear();
    fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
    assert_eq!(
        rejected(fx.check(&fx.steward_pair(|_, _| {}))),
        Reason::NoSteward
    );
}

#[test]
fn two_steward_entries_are_refused_whoever_signed() {
    let fx = Fx::with(FxOptions {
        entries: 2,
        ..FxOptions::default()
    });
    // Even the owner's own pair.
    let owner_pair = fx.pair(&fx.owner, 11, |_, _| {});
    assert_eq!(rejected(fx.check(&owner_pair)), Reason::TooManyStewards);
    // And a steward pair whose base has two.
    let steward_pair = fx.pair(&fx.steward, 11, |r, _| r.stewards.truncate(1));
    assert_eq!(rejected(fx.check(&steward_pair)), Reason::TooManyStewards);
}

#[test]
fn a_forged_older_or_equal_document_is_held_not_rejected() {
    let fx = Fx::new();
    let real = fx.pair(&fx.owner, 20, |_, _| {});
    let held = HeldView {
        network_id: fx.net,
        roster: Some(HeldRoster::new(real.roster.as_ref().unwrap(), None).unwrap()),
        policy_seq: Some(20),
    };
    for seq in [3, 19, 20] {
        // Signed by nobody who matters, and a steward pair without its base on top.
        let forged = fx.pair(&fx.other, seq, |_, _| {});
        let mut no_base = forged.clone();
        no_base.base_roster = None;
        no_base.base_policy = None;
        for bundle in [forged, no_base] {
            assert!(
                matches!(check_bundle(&held, &bundle, NOW), Verdict::Held),
                "seq {seq}"
            );
        }
    }
    // One above is judged, and refused for its signature.
    let mut forged = fx.pair(&fx.other, 21, |_, _| {});
    forged.base_roster = None;
    forged.base_policy = None;
    assert_eq!(
        rejected(check_bundle(&held, &forged, NOW)),
        Reason::MissingBase
    );
}

#[test]
fn an_equal_roster_is_not_trusted_to_place_a_newer_policy() {
    let fx = Fx::new();
    // Held: Roster 20 (owner), Policy 19. Offered: a forged Roster 20 (ignored) and the real Policy 20.
    let real = fx.pair(&fx.owner, 20, |_, _| {});
    let held = HeldView {
        network_id: fx.net,
        roster: Some(HeldRoster::new(real.roster.as_ref().unwrap(), None).unwrap()),
        policy_seq: Some(19),
    };
    let forged_roster = fx.pair(&fx.other, 20, |_, _| {});
    let bundle = Bundle {
        roster: forged_roster.roster.clone(),
        policy: real.policy.clone(),
        ..Bundle::default()
    };
    let adoption = adopted(check_bundle(&held, &bundle, NOW));
    assert!(adoption.roster.is_none());
    assert_eq!(adoption.policy.unwrap().seq, 20);
    assert_eq!(adoption.signer, Signer::Owner);
}

#[test]
fn a_roster_and_a_policy_of_different_seq_are_refused() {
    let fx = Fx::new();
    let mut bundle = fx.pair(&fx.owner, 11, |_, _| {});
    let other = fx.pair(&fx.owner, 12, |_, _| {});
    bundle.policy = other.policy;
    assert_eq!(rejected(fx.check(&bundle)), Reason::PairMismatch);
}

#[test]
fn a_policy_alone_needs_the_held_roster_of_its_seq() {
    let fx = Fx::new();
    let pair = fx.steward_pair(|_, _| {});
    let held_roster =
        HeldRoster::new(pair.roster.as_ref().unwrap(), Some(&fx.base_roster)).unwrap();
    let policy_only = Bundle {
        policy: pair.policy.clone(),
        base_policy: pair.base_policy.clone(),
        ..Bundle::default()
    };
    // Nothing held: no Roster to place it.
    assert_eq!(rejected(fx.check(&policy_only)), Reason::PairMismatch);
    // Held Roster of another seq.
    let other = fx.pair(&fx.owner, 30, |_, _| {});
    let held = HeldView {
        network_id: fx.net,
        roster: Some(HeldRoster::new(other.roster.as_ref().unwrap(), None).unwrap()),
        policy_seq: Some(5),
    };
    assert_eq!(
        rejected(check_bundle(&held, &policy_only, NOW)),
        Reason::PairMismatch
    );
    // Held Roster of the same seq from the same steward and base: adopted.
    let held = HeldView {
        network_id: fx.net,
        roster: Some(held_roster),
        policy_seq: Some(5),
    };
    let adoption = adopted(check_bundle(&held, &policy_only, NOW));
    assert!(adoption.roster.is_none());
    assert_eq!(adoption.policy.unwrap().seq, 11);
}

#[test]
fn a_steward_admission_policy_alone_is_checked_against_the_held_roster() {
    let fx = Fx::new();
    let new_key = key();
    let pair = fx.steward_pair(|r, p| admit(&new_key, "phone", r, p));
    let held = HeldView {
        network_id: fx.net,
        roster: Some(
            HeldRoster::new(pair.roster.as_ref().unwrap(), Some(&fx.base_roster)).unwrap(),
        ),
        policy_seq: None,
    };
    let policy_only = Bundle {
        policy: pair.policy.clone(),
        base_policy: pair.base_policy.clone(),
        ..Bundle::default()
    };
    adopted(check_bundle(&held, &policy_only, NOW));
    // The same Policy admitting somebody the held Roster did not.
    let other_key = key();
    let wrong = fx.steward_pair(|r, p| admit(&other_key, "phone", r, p));
    let wrong_only = Bundle {
        policy: wrong.policy.clone(),
        base_policy: wrong.base_policy.clone(),
        ..Bundle::default()
    };
    assert_eq!(
        rejected(check_bundle(&held, &wrong_only, NOW)),
        Reason::BadAppend
    );
}

#[test]
fn the_time_rules_hold_for_every_signer() {
    let fx = Fx::new();
    let both = |issued: u64, expires: u64| {
        fx.pair(&fx.owner, 11, |r, p| {
            r.issued = issued;
            p.issued = issued;
            r.expires = expires;
            p.expires = expires;
        })
    };
    // 14 days exactly is fine, one second more is not.
    adopted(fx.check(&both(NOW, NOW + 14 * DAY)));
    assert_eq!(
        rejected(fx.check(&both(NOW, NOW + 14 * DAY + 1))),
        Reason::LifetimeTooLong
    );
    // Expires before it is issued.
    assert_eq!(
        rejected(fx.check(&both(NOW - 10, NOW - 11))),
        Reason::LifetimeTooLong
    );
    // An hour ahead is fine, one second more is not.
    adopted(fx.check(&both(NOW + 3600, NOW + 3600 + DAY)));
    assert_eq!(
        rejected(fx.check(&both(NOW + 3601, NOW + 3601 + DAY))),
        Reason::NotYetValid
    );
    // Expired: at now is dead, a second later is alive.
    assert_eq!(rejected(fx.check(&both(NOW - DAY, NOW))), Reason::Expired);
    adopted(fx.check(&both(NOW - DAY, NOW + 1)));
    // The Policy alone is held to it too.
    let bundle = fx.pair(&fx.owner, 11, |_, p| p.expires = p.issued + 14 * DAY + 1);
    assert_eq!(rejected(fx.check(&bundle)), Reason::LifetimeTooLong);
    // And so is a steward's.
    let bundle = fx.steward_pair(|r, p| {
        r.expires = NOW + 14 * DAY + 1;
        p.expires = NOW + 14 * DAY + 1;
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::LifetimeTooLong);
}

#[test]
fn an_expired_candidate_is_told_roster_expired_and_the_rest_bad_document() {
    assert_eq!(Reason::Expired.code(), ErrorCode::RosterExpired);
    assert_eq!(Reason::FieldChanged.code(), ErrorCode::BadDocument);
    assert_eq!(Reason::BadSignature.code(), ErrorCode::BadDocument);
}

#[test]
fn another_networks_document_is_refused() {
    let fx = Fx::new();
    let other = Fx::new();
    let bundle = other.pair(&other.owner, 11, |_, _| {});
    assert_eq!(rejected(fx.check(&bundle)), Reason::WrongNetwork);
}

#[test]
fn an_empty_bundle_is_held() {
    let fx = Fx::new();
    assert!(matches!(fx.check(&Bundle::default()), Verdict::Held));
}

#[test]
fn a_roster_alone_is_adopted_by_a_verifier_that_holds_an_older_policy() {
    let fx = Fx::new();
    let mut bundle = fx.steward_pair(|_, _| {});
    bundle.policy = None;
    bundle.base_policy = None;
    let adoption = adopted(fx.check(&bundle));
    assert!(adoption.policy.is_none());
    assert_eq!(adoption.roster.unwrap().seq, 11);
}

#[test]
fn the_policy_side_of_a_steward_pair_is_verified_too() {
    let fx = Fx::new();
    // The Roster is the steward's, the Policy is signed by somebody else.
    let good = fx.steward_pair(|_, _| {});
    let other = fx.steward_pair(|_, _| {});
    let mut forged = good.clone();
    let mut body = other.policy.as_ref().unwrap().decode().unwrap();
    body.seq = 11;
    forged.policy = Some(Policy::sign(&fx.other, &body).unwrap());
    assert_eq!(rejected(fx.check(&forged)), Reason::BadSignature);
    // The base Policy is not the owner's.
    let mut bad_base = good.clone();
    bad_base.base_policy = Some(Policy::sign(&fx.other, &fx.pb).unwrap());
    assert_eq!(rejected(fx.check(&bad_base)), Reason::BadSignature);
    // The Policy's seq is not above its base's.
    let mut low = fx.steward_pair(|_, _| {});
    let mut body = low.policy.as_ref().unwrap().decode().unwrap();
    body.seq = fx.base_seq();
    let mut roster_body = low.roster.as_ref().unwrap().decode().unwrap();
    roster_body.seq = fx.base_seq();
    low.policy = Some(Policy::sign(&fx.steward, &body).unwrap());
    low.roster = Some(Roster::sign(&fx.steward, &roster_body).unwrap());
    assert_eq!(rejected(fx.check(&low)), Reason::SeqOutOfSpan);
}

#[test]
fn a_steward_entry_for_another_network_or_version_or_key_is_refused() {
    for tweak in 0..3 {
        let mut fx = Fx::new();
        let mut body = fx.rb.stewards[0].decode().unwrap();
        match tweak {
            0 => body.v = PROTOCOL_VERSION + 1,
            1 => body.network_id = NetworkId::from([5u8; 32]),
            // Not a point on the curve.
            _ => body.steward_pub = StewardKey::from([2u8; 32]),
        }
        fx.rb.stewards = vec![Steward::sign(&fx.owner, &body).unwrap()];
        fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
        assert_eq!(
            rejected(fx.check(&fx.steward_pair(|_, _| {}))),
            Reason::BadStewardEntry,
            "tweak {tweak}"
        );
    }
}

#[test]
fn a_steward_cannot_change_the_schema_version() {
    let fx = Fx::new();
    let bundle = fx.steward_pair(|r, _| r.v += 1);
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
    let bundle = fx.steward_pair(|_, p| p.v += 1);
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
}

#[test]
fn admitting_an_existing_member_again_is_refused() {
    let fx = Fx::new();
    let bundle = fx.steward_pair(|r, p| {
        r.members.push(RosterMember {
            node_id: node(1),
            min_serial: 9,
        });
        p.members.push(PolicyMember {
            node_id: node(1),
            name: "again".to_string(),
            roles: vec![],
        });
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadAppend);
    // The Roster alone (a relay sees nothing else) is refused on its own.
    let mut roster_only = bundle.clone();
    roster_only.policy = None;
    roster_only.base_policy = None;
    assert_eq!(rejected(fx.check(&roster_only)), Reason::BadAppend);
}

#[test]
fn the_rights_are_checked_on_each_side_of_the_pair() {
    let mut fx = Fx::new();
    let entry_body = StewardBody {
        v: PROTOCOL_VERSION,
        network_id: fx.net,
        steward_pub: StewardKey::from(fx.steward.verifying_key().to_bytes()),
        may: vec!["admit".to_string()],
        not_after: fx.not_after,
    };
    fx.rb.stewards = vec![Steward::sign(&fx.owner, &entry_body).unwrap()];
    fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
    // An admit-only steward admits.
    let new_key = key();
    let pair = fx.steward_pair(|r, p| admit(&new_key, "phone", r, p));
    adopted(fx.check(&pair));
    // And its Policy alone, against the held Roster of that admission, passes on the same right.
    let held = HeldView {
        network_id: fx.net,
        roster: Some(
            HeldRoster::new(pair.roster.as_ref().unwrap(), Some(&fx.base_roster)).unwrap(),
        ),
        policy_seq: None,
    };
    let policy_only = Bundle {
        policy: pair.policy.clone(),
        base_policy: pair.base_policy.clone(),
        ..Bundle::default()
    };
    adopted(check_bundle(&held, &policy_only, NOW));
}

#[test]
fn a_member_the_base_policy_already_names_is_not_admitted() {
    let mut fx = Fx::new();
    let new_key = key();
    // The base Policy already lists the node that the steward now admits into the Roster.
    fx.pb.members.push(PolicyMember {
        node_id: id_of(&new_key),
        name: "ghost".to_string(),
        roles: vec![],
    });
    fx.base_policy = Policy::sign(&fx.owner, &fx.pb).unwrap();
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadAppend);
}

#[test]
fn a_roster_the_steward_did_not_sign_is_refused_even_with_a_good_policy() {
    let fx = Fx::new();
    let good = fx.steward_pair(|_, _| {});
    let forged = fx.pair(&fx.other, 11, |_, _| {});
    let bundle = Bundle {
        roster: forged.roster.clone(),
        ..good
    };
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadSignature);
}
