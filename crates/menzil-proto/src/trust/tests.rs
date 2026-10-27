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
        roles: vec![],
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

/// Round 6, M3: a steward admits; it does not grant. An appended member has no role, and a name
/// that no other member of the network has, whatever the letter case.
#[test]
fn a_steward_cannot_admit_into_a_role_or_under_a_taken_name() {
    let fx = Fx::new();
    let new_key = key();
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        p.members.last_mut().unwrap().roles = vec!["admin".to_string()];
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadName);
    // The name of a member of the base, exactly and with other letter case.
    for name in ["laptop", "Laptop", "SERVER"] {
        let bundle = fx.steward_pair(|r, p| admit(&new_key, name, r, p));
        assert_eq!(rejected(fx.check(&bundle)), Reason::BadName, "{name}");
    }
    // Two members appended together under one name.
    let (a, b) = (key(), key());
    let bundle = fx.steward_pair(|r, p| {
        admit(&a, "phone", r, p);
        admit(&b, "PHONE", r, p);
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadName);
    // A fresh name with no role is still admitted.
    let bundle = fx.steward_pair(|r, p| admit(&new_key, "phone", r, p));
    adopted(fx.check(&bundle));
}

/// Round 6, M4: an appended member's `min_serial` may not exceed the serial of the certificate
/// appended with it, and every appended member comes with exactly one certificate.
#[test]
fn a_steward_cannot_append_a_min_serial_above_the_appended_certificate() {
    let fx = Fx::new();
    let new_key = key();
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        r.members.last_mut().unwrap().min_serial = u32::MAX;
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        r.members.last_mut().unwrap().min_serial = 2;
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    // The serial of the certificate itself is allowed (the certificate has serial 1).
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        r.members.last_mut().unwrap().min_serial = 1;
    });
    adopted(fx.check(&bundle));
    // A member appended with no certificate at all, or with two.
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        p.certs.clear();
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "phone", r, p);
        let again = p.certs[0].clone();
        p.certs.push(again);
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
}

/// `RosterOf::appended` slices the held members after the base's, so a held Roster whose members
/// do not start with the base's (shorter, or other) must not be built at all.
#[test]
fn a_held_roster_whose_members_do_not_extend_its_base_is_refused() {
    let fx = Fx::new();
    let shorter = fx.steward_pair(|r, _| {
        r.members.truncate(1);
    });
    assert!(matches!(
        HeldRoster::new(shorter.roster.as_ref().unwrap(), Some(&fx.base_roster)),
        Err(Reason::FieldChanged)
    ));
    let other = fx.steward_pair(|r, _| {
        r.members[0].min_serial += 1;
    });
    assert!(matches!(
        HeldRoster::new(other.roster.as_ref().unwrap(), Some(&fx.base_roster)),
        Err(Reason::FieldChanged)
    ));
    // The same members, or more, are fine.
    let longer = fx.steward_pair(|r, p| admit(&key(), "new", r, p));
    assert!(HeldRoster::new(longer.roster.as_ref().unwrap(), Some(&fx.base_roster)).is_ok());
    let same = fx.steward_pair(|_, _| {});
    assert!(HeldRoster::new(same.roster.as_ref().unwrap(), Some(&fx.base_roster)).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Round 7: what a held steward Roster appended stays (L2); renew and admit follow what is new (L3)
// ---------------------------------------------------------------------------------------------

/// A fixture whose steward entry carries exactly the rights `may`.
fn fx_with_may(may: &[&str]) -> Fx {
    let mut fx = Fx::new();
    let entry_body = StewardBody {
        v: PROTOCOL_VERSION,
        network_id: fx.net,
        steward_pub: StewardKey::from(fx.steward.verifying_key().to_bytes()),
        may: may.iter().map(|m| m.to_string()).collect(),
        not_after: fx.not_after,
    };
    fx.rb.stewards = vec![Steward::sign(&fx.owner, &entry_body).unwrap()];
    fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
    fx
}

/// What a verifier holds that adopted the steward pair `held` (made from `fx`'s base).
fn holding(fx: &Fx, held: &Bundle) -> HeldView {
    HeldView {
        network_id: fx.net,
        roster: Some(
            HeldRoster::new(held.roster.as_ref().unwrap(), Some(&fx.base_roster)).unwrap(),
        ),
        policy_seq: held.policy.as_ref().map(|p| p.decode().unwrap().seq),
    }
}

/// The pair `fx.steward_pair` makes at `seq` after `edit`, with the steward's admissions `kept`
/// first (the members `keep` names are appended in this order).
fn pair_at(fx: &Fx, seq: u64, edit: impl FnOnce(&mut RosterBody, &mut PolicyBody)) -> Bundle {
    fx.pair(&fx.steward, seq, edit)
}

#[test]
fn a_steward_cannot_drop_a_member_it_admitted_and_give_its_name_to_another_node() {
    let fx = Fx::new();
    let (a, b) = (key(), key());
    let held_pair = pair_at(&fx, 11, |r, p| admit(&a, "printer", r, p));
    let held = holding(&fx, &held_pair);
    // From the same base: A gone, B under A's name.
    let rebind = pair_at(&fx, 12, |r, p| admit(&b, "printer", r, p));
    assert_eq!(
        rejected(check_bundle(&held, &rebind, NOW)),
        Reason::AppendedDropped
    );
    // A renewal that forgets A is no better.
    let forgets = pair_at(&fx, 12, |_, _| {});
    assert_eq!(
        rejected(check_bundle(&held, &forgets, NOW)),
        Reason::AppendedDropped
    );
    // A reordering is a change of the held members as well.
    let reordered = pair_at(&fx, 12, |r, p| {
        admit(&b, "scanner", r, p);
        admit(&a, "printer", r, p);
    });
    assert_eq!(
        rejected(check_bundle(&held, &reordered, NOW)),
        Reason::AppendedDropped
    );
    // Keeping A and adding B is an admission.
    let keeps = pair_at(&fx, 12, |r, p| {
        admit(&a, "printer", r, p);
        admit(&b, "scanner", r, p);
    });
    assert_eq!(
        adopted(check_bundle(&held, &keeps, NOW))
            .roster
            .unwrap()
            .members
            .len(),
        4
    );
    // Nobody holding nothing, or only the base, has anything to compare with.
    adopted(fx.check(&rebind));
}

#[test]
fn what_a_held_steward_roster_appended_is_compared_on_the_same_base_only() {
    let fx = Fx::new();
    let a = key();
    let held_pair = pair_at(&fx, 11, |r, p| admit(&a, "printer", r, p));
    let held = holding(&fx, &held_pair);
    // A steward pair on a newer owner base is judged against that base alone.
    let mut r2 = fx.rb.clone();
    let mut p2 = fx.pb.clone();
    r2.seq = 10 + STEWARD_SEQ_SPAN + 1;
    p2.seq = r2.seq;
    let base2 = (
        Roster::sign(&fx.owner, &r2).unwrap(),
        Policy::sign(&fx.owner, &p2).unwrap(),
    );
    let mut r3 = r2.clone();
    let mut p3 = p2.clone();
    r3.seq += 1;
    p3.seq += 1;
    r3.issued = NOW;
    p3.issued = NOW;
    r3.expires = NOW + 7 * DAY;
    p3.expires = NOW + 7 * DAY;
    let bundle = Bundle {
        base_roster: Some(base2.0),
        base_policy: Some(base2.1),
        roster: Some(Roster::sign(&fx.steward, &r3).unwrap()),
        policy: Some(Policy::sign(&fx.steward, &p3).unwrap()),
    };
    adopted(check_bundle(&held, &bundle, NOW));
}

#[test]
fn a_steward_that_may_only_admit_cannot_renew_what_it_admitted() {
    let fx = fx_with_may(&["admit"]);
    let (a, b) = (key(), key());
    // Nothing held, nothing appended: a renewal of the base is refused.
    assert_eq!(
        rejected(fx.check(&fx.steward_pair(|_, _| {}))),
        Reason::RightMissing
    );
    let held_pair = pair_at(&fx, 11, |r, p| admit(&a, "printer", r, p));
    adopted(fx.check(&held_pair));
    let held = holding(&fx, &held_pair);
    // Appending nothing beyond the held pair is a renewal, whatever the base is.
    let renewal = pair_at(&fx, 12, |r, p| admit(&a, "printer", r, p));
    assert_eq!(
        rejected(check_bundle(&held, &renewal, NOW)),
        Reason::RightMissing
    );
    // The Roster alone (it travels alone in an L3 DOC) is judged by the same rule.
    let roster_only = Bundle {
        base_roster: renewal.base_roster.clone(),
        roster: renewal.roster.clone(),
        ..Bundle::default()
    };
    assert_eq!(
        rejected(check_bundle(&held, &roster_only, NOW)),
        Reason::RightMissing
    );
    // A new member beyond the held ones is an admission, and it carries fresh dates.
    let admission = pair_at(&fx, 12, |r, p| {
        admit(&a, "printer", r, p);
        admit(&b, "scanner", r, p);
    });
    adopted(check_bundle(&held, &admission, NOW));
}

#[test]
fn a_steward_that_may_renew_and_admit_renews_a_pair_with_its_admissions() {
    let fx = Fx::new();
    let a = key();
    let held_pair = pair_at(&fx, 11, |r, p| admit(&a, "printer", r, p));
    let held = holding(&fx, &held_pair);
    let renewal = pair_at(&fx, 12, |r, p| admit(&a, "printer", r, p));
    adopted(check_bundle(&held, &renewal, NOW));
    // A steward that may only renew can renew the base, and never has admissions to keep.
    let renew_only = fx_with_may(&["renew"]);
    adopted(renew_only.check(&renew_only.steward_pair(|_, _| {})));
}

#[test]
fn the_policy_follows_the_same_rule_for_what_is_new() {
    let fx = fx_with_may(&["admit"]);
    let (a, b) = (key(), key());
    let held_pair = pair_at(&fx, 11, |r, p| admit(&a, "printer", r, p));
    let held = holding(&fx, &held_pair);
    // The Roster admits B (an admission), the Policy appends nothing new beyond the held
    // member: by the same rule that is a renewal, which this steward may not do.
    let inconsistent = pair_at(&fx, 12, |r, p| {
        admit(&a, "printer", r, p);
        let mut scratch_r = r.clone();
        let mut scratch_p = p.clone();
        admit(&b, "scanner", &mut scratch_r, &mut scratch_p);
        r.members.push(scratch_r.members.pop().unwrap());
    });
    assert_eq!(
        rejected(check_bundle(&held, &inconsistent, NOW)),
        Reason::RightMissing
    );
}

// ---------------------------------------------------------------------------------------------
// Cert rotation S3: a steward lists a member's renewed certificate (protocol.md 2.3)
// ---------------------------------------------------------------------------------------------

const KEY_A: [u8; 32] = [7u8; 32];

fn cert_for(
    k: &SigningKey,
    x25519: [u8; 32],
    serial: u32,
    not_before: u64,
    not_after: u64,
) -> NodeCert {
    let body = NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id: id_of(k),
        x25519_pub: X25519PublicKey::from(x25519),
        serial,
        not_before,
        not_after,
    };
    NodeCert::sign(k, &body).unwrap()
}

/// A renewal of `k`'s certificate: same Noise key as the base's, `serial`, a 100 day window.
fn renewal(k: &SigningKey, serial: u32) -> NodeCert {
    cert_for(k, KEY_A, serial, NOW - DAY, NOW + 100 * DAY)
}

/// A fixture whose base also holds the member `m` (a real key) with its serial 1 certificate.
fn fx_with_member(may: &[&str]) -> (Fx, SigningKey) {
    let mut fx = fx_with_may(may);
    let m = key();
    fx.rb.members.push(RosterMember {
        node_id: id_of(&m),
        min_serial: 1,
    });
    fx.pb.members.push(PolicyMember {
        node_id: id_of(&m),
        name: "phone".to_string(),
        roles: vec![],
    });
    fx.pb
        .certs
        .push(cert_for(&m, KEY_A, 1, NOW - 10 * DAY, NOW + 90 * DAY));
    fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
    fx.base_policy = Policy::sign(&fx.owner, &fx.pb).unwrap();
    (fx, m)
}

/// What a verifier holds that adopted the steward pair `held`, Policy included.
fn holding_policy(fx: &Fx, held: &Bundle) -> HeldView {
    let roster = HeldRoster::new(held.roster.as_ref().unwrap(), Some(&fx.base_roster))
        .unwrap()
        .with_policy(held.policy.as_ref().unwrap(), Some(&fx.base_policy))
        .unwrap();
    HeldView {
        network_id: fx.net,
        roster: Some(roster),
        policy_seq: held.policy.as_ref().map(|p| p.decode().unwrap().seq),
    }
}

#[test]
fn a_renewal_of_a_base_member_is_accepted() {
    let (fx, m) = fx_with_member(&["admit", "renew"]);
    let bundle = fx.steward_pair(|_, p| p.certs.push(renewal(&m, 2)));
    let adoption = adopted(fx.check(&bundle));
    assert!(matches!(adoption.signer, Signer::Steward { .. }));
    assert_eq!(adoption.policy.unwrap().certs.len(), 2);
    // The Roster alone (what a relay judges) is the plain renewal and passes.
    let roster_only = Bundle {
        base_roster: bundle.base_roster.clone(),
        roster: bundle.roster.clone(),
        ..Bundle::default()
    };
    adopted(fx.check(&roster_only));
}

#[test]
fn a_renewal_with_another_noise_key_is_refused() {
    let (fx, m) = fx_with_member(&["admit", "renew"]);
    let other = cert_for(&m, [8u8; 32], 2, NOW - DAY, NOW + 100 * DAY);
    let bundle = fx.steward_pair(|_, p| p.certs.push(other));
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
}

#[test]
fn a_renewal_must_have_a_serial_above_every_base_certificate() {
    let (mut fx, m) = fx_with_member(&["admit", "renew"]);
    // The base lists serials 1 and 3 for the node (the highest is not the last).
    fx.pb
        .certs
        .push(cert_for(&m, KEY_A, 3, NOW - 10 * DAY, NOW + 90 * DAY));
    fx.pb
        .certs
        .push(cert_for(&m, KEY_A, 2, NOW - 10 * DAY, NOW + 90 * DAY));
    fx.base_policy = Policy::sign(&fx.owner, &fx.pb).unwrap();
    for serial in [1, 2, 3] {
        let bundle = fx.steward_pair(|_, p| p.certs.push(renewal(&m, serial)));
        assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert, "{serial}");
    }
    let bundle = fx.steward_pair(|_, p| p.certs.push(renewal(&m, 4)));
    adopted(fx.check(&bundle));
}

#[test]
fn a_renewal_must_be_self_signed_and_at_most_400_days() {
    let (fx, m) = fx_with_member(&["admit", "renew"]);
    let forged = {
        let body = renewal(&m, 2).decode().unwrap();
        NodeCert::sign(&key(), &body).unwrap()
    };
    let bundle = fx.steward_pair(|_, p| p.certs.push(forged));
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    let long = cert_for(&m, KEY_A, 2, NOW - DAY, NOW - DAY + 400 * DAY + 1);
    let bundle = fx.steward_pair(|_, p| p.certs.push(long));
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    let exact = cert_for(&m, KEY_A, 2, NOW - DAY, NOW - DAY + 400 * DAY);
    let bundle = fx.steward_pair(|_, p| p.certs.push(exact));
    adopted(fx.check(&bundle));
}

#[test]
fn two_tail_certificates_for_one_node_are_refused() {
    let (fx, m) = fx_with_member(&["admit", "renew"]);
    let bundle = fx.steward_pair(|_, p| {
        p.certs.push(renewal(&m, 2));
        p.certs.push(renewal(&m, 3));
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    // Also for an appended member: its admission certificate and a second one.
    let (fx, _) = fx_with_member(&["admit", "renew"]);
    let new_key = key();
    let bundle = fx.steward_pair(|r, p| {
        admit(&new_key, "tablet", r, p);
        p.certs
            .push(cert_for(&new_key, [7u8; 32], 2, NOW - DAY, NOW + DAY));
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
}

#[test]
fn a_held_tail_certificate_may_not_be_dropped() {
    let (fx, m) = fx_with_member(&["admit", "renew"]);
    let held_pair = fx.pair(&fx.steward, 11, |_, p| p.certs.push(renewal(&m, 2)));
    let held = holding_policy(&fx, &held_pair);
    // The next pair from the same base without the renewal: the steward took it back.
    let dropped = fx.pair(&fx.steward, 12, |_, _| {});
    assert_eq!(
        rejected(check_bundle(&held, &dropped, NOW)),
        Reason::AppendedDropped
    );
    // With it (a plain renewal of dates) the pair passes.
    let kept = fx.pair(&fx.steward, 12, |_, p| p.certs.push(renewal(&m, 2)));
    adopted(check_bundle(&held, &kept, NOW));
}

#[test]
fn a_held_tail_certificate_may_not_be_lowered_or_given_another_key() {
    let (fx, m) = fx_with_member(&["admit", "renew"]);
    let held_pair = fx.pair(&fx.steward, 11, |_, p| p.certs.push(renewal(&m, 3)));
    let held = holding_policy(&fx, &held_pair);
    // Lowered: still above the base's serial 1, but below the held 3.
    let lowered = fx.pair(&fx.steward, 12, |_, p| p.certs.push(renewal(&m, 2)));
    assert_eq!(
        rejected(check_bundle(&held, &lowered, NOW)),
        Reason::AppendedDropped
    );
    // Equal serial is not below: allowed (new dates).
    let same = fx.pair(&fx.steward, 12, |_, p| {
        p.certs
            .push(cert_for(&m, KEY_A, 3, NOW - DAY, NOW + 120 * DAY));
    });
    adopted(check_bundle(&held, &same, NOW));
    // Raised is allowed.
    let raised = fx.pair(&fx.steward, 12, |_, p| p.certs.push(renewal(&m, 4)));
    adopted(check_bundle(&held, &raised, NOW));
}

#[test]
fn a_held_tail_certificate_of_an_admitted_member_keeps_its_key() {
    let fx = fx_with_may(&["admit", "renew"]);
    let a = key();
    let held_pair = fx.pair(&fx.steward, 11, |r, p| admit(&a, "printer", r, p));
    let held = holding_policy(&fx, &held_pair);
    // The same admission with a certificate for another Noise key.
    let rekeyed = fx.pair(&fx.steward, 12, |r, p| {
        admit(&a, "printer", r, p);
        p.certs.pop();
        p.certs
            .push(cert_for(&a, [9u8; 32], 2, NOW - DAY, NOW + DAY));
    });
    assert_eq!(
        rejected(check_bundle(&held, &rekeyed, NOW)),
        Reason::AppendedDropped
    );
    // The same key with a higher serial is a rotation of the admitted member: allowed.
    let rotated = fx.pair(&fx.steward, 12, |r, p| {
        admit(&a, "printer", r, p);
        p.certs.pop();
        p.certs.push(cert_for(&a, KEY_A, 2, NOW - DAY, NOW + DAY));
    });
    adopted(check_bundle(&held, &rotated, NOW));
}

#[test]
fn a_rotation_needs_admit_on_the_policy_and_renew_on_the_roster() {
    for may in [&["renew"][..], &["admit"][..]] {
        let (fx, m) = fx_with_member(may);
        let bundle = fx.steward_pair(|_, p| p.certs.push(renewal(&m, 2)));
        assert_eq!(rejected(fx.check(&bundle)), Reason::RightMissing, "{may:?}");
    }
    // The Policy alone (it travels alone on `menzil:docs`) with a held Roster needs `admit`: a
    // renew only steward is refused on the Policy side, which is not the Roster's rule.
    let (fx, m) = fx_with_member(&["renew"]);
    let renewed = fx.steward_pair(|_, _| {});
    let held = holding_policy(&fx, &renewed);
    let policy_only = {
        let mut p = fx.pb.clone();
        p.seq = fx.base_seq() + 1;
        p.issued = NOW;
        p.expires = (NOW + 7 * DAY).min(fx.not_after);
        p.certs.push(renewal(&m, 2));
        Bundle {
            base_policy: Some(fx.base_policy.clone()),
            policy: Some(Policy::sign(&fx.steward, &p).unwrap()),
            ..Bundle::default()
        }
    };
    let held = HeldView {
        policy_seq: Some(fx.base_seq()),
        ..held
    };
    assert_eq!(
        rejected(check_bundle(&held, &policy_only, NOW)),
        Reason::RightMissing
    );
    let (fx, _) = fx_with_member(&["admit", "renew"]);
    adopted(fx.check(&fx.steward_pair(|_, _| {})));
}

#[test]
fn a_tail_certificate_for_a_non_member_is_refused() {
    let (fx, _) = fx_with_member(&["admit", "renew"]);
    let stranger = key();
    let bundle = fx.steward_pair(|_, p| p.certs.push(renewal(&stranger, 2)));
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
    // A revoked node is not a member either.
    let revoked = SigningKey::from_bytes(&[5u8; 32]);
    let mut fx2 = fx_with_may(&["admit", "renew"]);
    fx2.rb.revoked.push(RevokedMember {
        node_id: id_of(&revoked),
        since: NOW - DAY,
    });
    fx2.base_roster = Roster::sign(&fx2.owner, &fx2.rb).unwrap();
    let bundle = fx2.steward_pair(|_, p| p.certs.push(renewal(&revoked, 2)));
    assert_eq!(rejected(fx2.check(&bundle)), Reason::BadCert);
}

#[test]
fn a_rotation_cannot_change_the_roster_or_a_min_serial() {
    let (fx, m) = fx_with_member(&["admit", "renew"]);
    let bundle = fx.steward_pair(|r, p| {
        p.certs.push(renewal(&m, 2));
        r.members.last_mut().unwrap().min_serial = 2;
    });
    assert_eq!(rejected(fx.check(&bundle)), Reason::FieldChanged);
}

#[test]
fn a_base_member_without_a_base_certificate_cannot_be_renewed() {
    // The base members of the plain fixture list no certificate: there is no key to hold to.
    let fx = Fx::new();
    let k = key();
    let mut fx = fx;
    fx.rb.members.push(RosterMember {
        node_id: id_of(&k),
        min_serial: 1,
    });
    fx.pb.members.push(PolicyMember {
        node_id: id_of(&k),
        name: "bare".to_string(),
        roles: vec![],
    });
    fx.base_roster = Roster::sign(&fx.owner, &fx.rb).unwrap();
    fx.base_policy = Policy::sign(&fx.owner, &fx.pb).unwrap();
    let bundle = fx.steward_pair(|_, p| p.certs.push(renewal(&k, 2)));
    assert_eq!(rejected(fx.check(&bundle)), Reason::BadCert);
}
