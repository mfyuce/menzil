//! The one door through which a node adopts a Roster and Policy pair (protocol.md 2.3, 4.3):
//! [`DocStore::adopt`] judges a [`Bundle`] with the acceptance predicate
//! [`menzil_proto::trust::check_bundle`] against what [`RosterStore`] and [`PolicyStore`]
//! hold, and stores the outcome in both or in neither.
//!
//! The two write locks are taken in a fixed order, Roster store first and Policy store second,
//! and held until both documents are stored, so two concurrent adoptions cannot interleave.
//! The readers (`check_membership`, `has_grant`) take one read lock after the other and copy
//! the body out, so a reader can still see the new Roster beside the old Policy, or the
//! reverse, for the length of one adoption; each document alone is one that was verified, and
//! both are only ever replaced by newer ones. Everything fallible (decoding the entries to hold, the size limit, the
//! predicate itself) runs before the first insert, so a refused Policy leaves the Roster as it
//! was.
//!
//! A steward signed document is stored together with the owner signed base it was made from,
//! and never without it: the base is what a later bundle is compared with
//! ([`menzil_proto::trust::HeldView`]) and what a relay or a member needs to be sent first when
//! the document is passed on.

use menzil_proto::trust::{Bundle, HeldView, Signer, Verdict, check_bundle};
use menzil_proto::{MAX_DOC_BYTES, NetworkId};

use crate::error::NodeError;
use crate::policy_store::{self, PolicyStore};
use crate::roster_store::{self, RosterStore};

/// What [`DocStore::adopt`] stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Adopted {
    /// The offered Roster replaced the held one.
    pub roster: bool,
    /// The offered Policy replaced the held one.
    pub policy: bool,
}

/// The two document stores of a node, adopted into as one.
#[derive(Clone, Copy)]
pub struct DocStore<'a> {
    rosters: &'a RosterStore,
    policies: &'a PolicyStore,
}

impl<'a> DocStore<'a> {
    /// A view over `rosters` and `policies`; they stay the caller's, and are read through
    /// their own accessors.
    pub fn new(rosters: &'a RosterStore, policies: &'a PolicyStore) -> Self {
        Self { rosters, policies }
    }

    /// Adopts what `bundle` offers if the acceptance predicate says so at `now` (Unix
    /// seconds). A Roster and a Policy offered together are both stored or neither is. A
    /// bundle with nothing newer than what is held is `Ok` with nothing stored; a refused one
    /// is [`NodeError::DocumentRejected`]. A document over [`MAX_DOC_BYTES`] is refused before
    /// anything is judged.
    pub fn adopt(&self, bundle: &Bundle, now: u64) -> Result<Adopted, NodeError> {
        let Some(network_id) = network_of(bundle)? else {
            return Ok(Adopted::default());
        };
        check_sizes(bundle)?;

        // The fixed lock order: Roster store, then Policy store.
        let mut rosters = self.rosters.write();
        let mut policies = self.policies.write();
        let view = HeldView {
            network_id,
            roster: rosters.get(&network_id).map(|held| held.view().clone()),
            policy_seq: policies.get(&network_id).map(policy_store::Held::seq),
        };
        let adoption = match check_bundle(&view, bundle, now) {
            Verdict::Adopt(adoption) => adoption,
            Verdict::Held => return Ok(Adopted::default()),
            Verdict::Reject(reason) => return Err(NodeError::DocumentRejected(reason)),
        };

        // Build both entries before inserting either.
        let roster = match (&adoption.roster, &bundle.roster) {
            (Some(_), Some(signed)) => Some(roster_store::Held::new(
                signed,
                base_of(adoption.signer, bundle.base_roster.as_ref())?,
                adoption.signer,
            )?),
            _ => None,
        };
        let policy = match (&adoption.policy, &bundle.policy) {
            (Some(_), Some(signed)) => Some(policy_store::Held::new(
                signed,
                base_of(adoption.signer, bundle.base_policy.as_ref())?,
                adoption.signer,
            )?),
            _ => None,
        };
        let adopted = Adopted {
            roster: roster.is_some(),
            policy: policy.is_some(),
        };
        if let Some(held) = roster {
            rosters.insert(network_id, held);
        }
        if let Some(held) = policy {
            policies.insert(network_id, held);
        }
        Ok(adopted)
    }
}

/// The base to hold with a document: none for an owner signed one, and for a steward signed
/// one the base the predicate has just checked. A steward signed document without its base
/// would be a bug in the predicate; it is refused here all the same, never stored.
fn base_of<T>(signer: Signer, base: Option<&T>) -> Result<Option<&T>, NodeError> {
    match (signer, base) {
        (Signer::Owner, _) => Ok(None),
        (Signer::Steward { .. }, Some(base)) => Ok(Some(base)),
        (Signer::Steward { .. }, None) => Err(NodeError::DocumentRejected(
            menzil_proto::trust::Reason::MissingBase,
        )),
    }
}

/// The network the bundle is about: its Roster's, else its Policy's. `None` for a bundle with
/// neither (nothing to adopt, whatever else it carries).
fn network_of(bundle: &Bundle) -> Result<Option<NetworkId>, NodeError> {
    if let Some(roster) = &bundle.roster {
        return Ok(Some(roster.decode()?.network_id));
    }
    if let Some(policy) = &bundle.policy {
        return Ok(Some(policy.decode()?.network_id));
    }
    Ok(None)
}

/// Refuses a bundle with a document too large to be forwarded (see `RosterStore::set`).
fn check_sizes(bundle: &Bundle) -> Result<(), NodeError> {
    let lens = [
        bundle.roster.as_ref().map(|d| d.encode().len()),
        bundle.policy.as_ref().map(|d| d.encode().len()),
        bundle.base_roster.as_ref().map(|d| d.encode().len()),
        bundle.base_policy.as_ref().map(|d| d.encode().len()),
    ];
    for len in lens.into_iter().flatten() {
        if len > MAX_DOC_BYTES {
            return Err(NodeError::DocumentTooLarge {
                len,
                max: MAX_DOC_BYTES,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::trust::Reason;
    use menzil_proto::{
        NodeId, PROTOCOL_VERSION, Policy, PolicyBody, PolicyMember, Roster, RosterBody,
        RosterMember, Steward, StewardBody, StewardKey,
    };

    const NOW: u64 = 1_800_000_000;
    const DAY: u64 = 86_400;

    /// A network at base `seq` 10 with one steward, and the owner signed base pair.
    struct Net {
        owner: SigningKey,
        steward: SigningKey,
        network_id: NetworkId,
        roster: RosterBody,
        policy: PolicyBody,
        base_roster: Roster,
        base_policy: Policy,
    }

    impl Net {
        fn new() -> Self {
            let owner = SigningKey::generate(&mut rand::rng());
            let steward = SigningKey::generate(&mut rand::rng());
            let network_id = NetworkId::from(owner.verifying_key().to_bytes());
            let entry = Steward::sign(
                &owner,
                &StewardBody {
                    v: PROTOCOL_VERSION,
                    network_id,
                    steward_pub: StewardKey::from(steward.verifying_key().to_bytes()),
                    may: vec!["renew".to_string()],
                    not_after: NOW + 30 * DAY,
                },
            )
            .unwrap();
            let roster = RosterBody {
                v: PROTOCOL_VERSION,
                network_id,
                seq: 10,
                issued: NOW - DAY,
                expires: NOW + 5 * DAY,
                members: vec![RosterMember {
                    node_id: NodeId::from([1u8; 32]),
                    min_serial: 1,
                }],
                revoked: vec![],
                stewards: vec![entry],
                labels: vec![],
            };
            let policy = PolicyBody {
                v: PROTOCOL_VERSION,
                network_id,
                seq: 10,
                issued: NOW - DAY,
                expires: NOW + 5 * DAY,
                members: vec![PolicyMember {
                    node_id: NodeId::from([1u8; 32]),
                    name: "laptop".to_string(),
                    roles: vec![],
                }],
                certs: vec![],
                grants: vec![],
                egress: vec![],
                accept: vec![],
            };
            Self {
                base_roster: Roster::sign(&owner, &roster).unwrap(),
                base_policy: Policy::sign(&owner, &policy).unwrap(),
                owner,
                steward,
                network_id,
                roster,
                policy,
            }
        }

        /// The owner signed base pair alone.
        fn base_bundle(&self) -> Bundle {
            Bundle {
                roster: Some(self.base_roster.clone()),
                policy: Some(self.base_policy.clone()),
                ..Bundle::default()
            }
        }

        /// A renewal pair at `seq`, signed by `signer`, with the bases when `with_bases`.
        fn renewal(&self, signer: &SigningKey, seq: u64, with_bases: bool) -> Bundle {
            let mut roster = self.roster.clone();
            let mut policy = self.policy.clone();
            roster.seq = seq;
            policy.seq = seq;
            roster.issued = NOW;
            policy.issued = NOW;
            roster.expires = NOW + 7 * DAY;
            policy.expires = NOW + 7 * DAY;
            Bundle {
                base_roster: with_bases.then(|| self.base_roster.clone()),
                base_policy: with_bases.then(|| self.base_policy.clone()),
                roster: Some(Roster::sign(signer, &roster).unwrap()),
                policy: Some(Policy::sign(signer, &policy).unwrap()),
            }
        }
    }

    fn refused(result: Result<Adopted, NodeError>) -> Reason {
        match result {
            Err(NodeError::DocumentRejected(reason)) => reason,
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    fn stores_holding_base(net: &Net) -> (RosterStore, PolicyStore) {
        let (rosters, policies) = (RosterStore::new(), PolicyStore::new());
        let adopted = DocStore::new(&rosters, &policies)
            .adopt(&net.base_bundle(), NOW)
            .unwrap();
        assert_eq!(
            adopted,
            Adopted {
                roster: true,
                policy: true
            }
        );
        (rosters, policies)
    }

    #[test]
    fn an_owner_signed_pair_is_adopted_held_without_a_base_and_not_adopted_twice() {
        let net = Net::new();
        let (rosters, policies) = stores_holding_base(&net);
        assert_eq!(rosters.get(&net.network_id), Some(net.base_roster.clone()));
        assert_eq!(policies.get(&net.network_id), Some(net.base_policy.clone()));
        assert_eq!(rosters.signer(&net.network_id), Some(Signer::Owner));
        assert_eq!(policies.signer(&net.network_id), Some(Signer::Owner));
        assert!(rosters.base(&net.network_id).is_none());
        assert!(policies.base(&net.network_id).is_none());

        let docs = DocStore::new(&rosters, &policies);
        assert_eq!(
            docs.adopt(&net.base_bundle(), NOW).unwrap(),
            Adopted::default()
        );
        // Bases that come along with an owner signed pair are not kept.
        let next = net.renewal(&net.owner, 11, true);
        assert_eq!(
            docs.adopt(&next, NOW).unwrap(),
            Adopted {
                roster: true,
                policy: true
            }
        );
        assert_eq!(rosters.seq(&net.network_id), Some(11));
        assert_eq!(policies.seq(&net.network_id), Some(11));
        assert_eq!(rosters.signer(&net.network_id), Some(Signer::Owner));
        assert!(rosters.base(&net.network_id).is_none());
        assert!(policies.base(&net.network_id).is_none());
    }

    /// Round 6, L2: a node that pushes a steward signed Roster to a relay sends the base first,
    /// as a relay does; without it every relay refuses the Roster.
    #[test]
    fn a_held_steward_roster_is_pushed_to_a_relay_after_its_base() {
        use menzil_proto::{DocType, Record};
        let net = Net::new();
        let (rosters, policies) = stores_holding_base(&net);
        DocStore::new(&rosters, &policies)
            .adopt(&net.renewal(&net.steward, 11, true), NOW)
            .unwrap();
        let records = crate::session::push_records_for_newer_rosters(
            &[net.network_id],
            &rosters,
            &std::collections::HashMap::new(),
        );
        let mut reassembler = menzil_proto::DocReassembler::new();
        let mut sent = Vec::new();
        for record in records {
            let Record::Doc(body) = record else {
                panic!("only DOC records")
            };
            if let Some((doc_type, bytes)) = reassembler.accept(&body).unwrap() {
                sent.push((doc_type, bytes));
            }
        }
        let types: Vec<DocType> = sent.iter().map(|(t, _)| *t).collect();
        assert_eq!(types, vec![DocType::BaseRoster, DocType::Roster]);
        assert_eq!(sent[0].1, net.base_roster.encode());
        assert_eq!(sent[1].1, rosters.get(&net.network_id).unwrap().encode());
    }

    #[test]
    fn a_steward_pair_is_held_with_its_bases_and_the_steward_as_signer() {
        let net = Net::new();
        let (rosters, policies) = stores_holding_base(&net);
        let bundle = net.renewal(&net.steward, 11, true);
        DocStore::new(&rosters, &policies)
            .adopt(&bundle, NOW)
            .unwrap();
        let signer = Signer::Steward {
            key: StewardKey::from(net.steward.verifying_key().to_bytes()),
            base_seq: 10,
        };
        assert_eq!(rosters.signer(&net.network_id), Some(signer));
        assert_eq!(policies.signer(&net.network_id), Some(signer));
        assert_eq!(rosters.base(&net.network_id), Some(net.base_roster.clone()));
        assert_eq!(
            policies.base(&net.network_id),
            Some(net.base_policy.clone())
        );
    }

    #[test]
    fn a_steward_pair_without_its_base_is_refused_and_nothing_is_stored() {
        let net = Net::new();
        let (rosters, policies) = stores_holding_base(&net);
        let bundle = net.renewal(&net.steward, 11, false);
        assert_eq!(
            refused(DocStore::new(&rosters, &policies).adopt(&bundle, NOW)),
            Reason::MissingBase
        );
        assert_eq!(rosters.seq(&net.network_id), Some(10));
        assert_eq!(policies.seq(&net.network_id), Some(10));
    }

    #[test]
    fn a_pair_with_a_bad_policy_leaves_the_roster_as_it_was() {
        let net = Net::new();
        let (rosters, policies) = stores_holding_base(&net);
        let mut bundle = net.renewal(&net.steward, 11, true);
        // The Roster is sound; the Policy was signed by a stranger.
        let stranger = SigningKey::generate(&mut rand::rng());
        let mut forged = net.policy.clone();
        forged.seq = 11;
        forged.issued = NOW;
        forged.expires = NOW + 7 * DAY;
        bundle.policy = Some(Policy::sign(&stranger, &forged).unwrap());
        assert_eq!(
            refused(DocStore::new(&rosters, &policies).adopt(&bundle, NOW)),
            Reason::BadSignature
        );
        assert_eq!(rosters.seq(&net.network_id), Some(10));
        assert_eq!(rosters.get(&net.network_id), Some(net.base_roster.clone()));
        assert_eq!(policies.seq(&net.network_id), Some(10));
    }

    #[test]
    fn a_policy_whose_seq_differs_from_the_held_rosters_is_refused() {
        let net = Net::new();
        let (rosters, policies) = stores_holding_base(&net);
        // A Policy at seq 12 alone, while the held Roster is at seq 10.
        let mut bundle = net.renewal(&net.owner, 12, false);
        bundle.roster = None;
        assert_eq!(
            refused(DocStore::new(&rosters, &policies).adopt(&bundle, NOW)),
            Reason::PairMismatch
        );
        assert_eq!(policies.seq(&net.network_id), Some(10));
    }

    #[test]
    fn the_time_rules_apply_to_what_is_adopted() {
        let net = Net::new();
        let (rosters, policies) = (RosterStore::new(), PolicyStore::new());
        // The base pair was issued a day before NOW and expires five days after: a verifier a
        // month later refuses it, and one a day before its issue time refuses it as not yet valid.
        assert_eq!(
            refused(DocStore::new(&rosters, &policies).adopt(&net.base_bundle(), NOW + 30 * DAY)),
            Reason::Expired
        );
        assert_eq!(
            refused(DocStore::new(&rosters, &policies).adopt(&net.base_bundle(), NOW - 3 * DAY)),
            Reason::NotYetValid
        );
        assert!(rosters.get(&net.network_id).is_none());
    }

    #[test]
    fn adopt_owner_refuses_a_steward_signed_roster_and_the_time_rules() {
        let net = Net::new();
        let rosters = RosterStore::new();
        assert!(rosters.adopt_owner(&net.base_roster, NOW).unwrap());
        assert!(!rosters.adopt_owner(&net.base_roster, NOW).unwrap());
        let steward_roster = net.renewal(&net.steward, 11, true).roster.unwrap();
        assert!(matches!(
            rosters.adopt_owner(&steward_roster, NOW),
            Err(NodeError::DocumentRejected(Reason::MissingBase))
        ));
        let owner_roster = net.renewal(&net.owner, 11, false).roster.unwrap();
        assert!(matches!(
            rosters.adopt_owner(&owner_roster, NOW + 30 * DAY),
            Err(NodeError::DocumentRejected(Reason::Expired))
        ));
        assert_eq!(rosters.seq(&net.network_id), Some(10));
    }
}
