//! Which Roster and Policy a verifier adopts (protocol.md 2.3): the pure acceptance predicate
//! for owner signed documents and for documents a steward signed on the owner's behalf.
//!
//! A steward signed Roster or Policy is never judged alone. It travels with its base, the owner
//! signed document of the same kind it was made from, and the steward's authority is the
//! `Steward` entry in the base Roster (signed by the owner inside a Roster signed by the owner).
//! The steward's rights are enforced by comparing the document with its base field by field:
//! `renew` may change `seq`, `issued` and `expires`; `admit` may also append new, unrevoked
//! members at the end of the lists. Nothing else may differ. The owner's own next documents
//! jump [`STEWARD_SEQ_SPAN`] past the base, so nothing a steward signed from that base can
//! outrank them.
//!
//! Nothing here reads a clock, a store or a socket: the held state is passed in as a
//! [`HeldView`], the offered documents as a [`Bundle`], and `now` as a parameter. The answer is a
//! [`Verdict`]; a [`Reason`] is an enum, never text taken from the documents. Cheap checks come
//! first (a document that is not newer than what is held costs no signature check), then the
//! time and sequence rules, then the signatures, then the field rules. A bundle is judged as a
//! whole: one rejected document rejects the bundle.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;

use crate::PROTOCOL_VERSION;
use crate::bytes::{NetworkId, NodeId, StewardKey};
use crate::error::ErrorCode;
use crate::names::{check_name, check_role};
use crate::network::{Policy, PolicyBody, PolicyMember, Roster, RosterBody, RosterMember, Steward};

/// A steward pair derived from a base with sequence number `B` has a `seq` in `(B, B +
/// STEWARD_SEQ_SPAN]`; the owner issues its next pair above `B + STEWARD_SEQ_SPAN`.
pub const STEWARD_SEQ_SPAN: u64 = 1 << 20;
/// How far ahead of the verifier's clock `issued` may be, in seconds.
pub const MAX_CLOCK_SKEW: u64 = 3_600;
/// The longest `expires - issued` of a Roster or Policy, in seconds (14 days), checked by every
/// verifier and not only by the issuer.
pub const DOC_MAX_LIFETIME: u64 = 14 * 24 * 60 * 60;
/// The longest lifetime of a `Steward` entry, in seconds (90 days). Only the issuer can check
/// it, because the entry carries `not_after` and no `issued`.
pub const STEWARD_MAX_LIFETIME: u64 = 90 * 24 * 60 * 60;

/// Who signed the Roster and Policy that a [`Verdict::Adopt`] or a held pair stands on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    /// The network key.
    Owner,
    /// The steward `key`, from the base whose `seq` is `base_seq`.
    Steward {
        /// The steward's public key, from the `Steward` entry.
        key: StewardKey,
        /// The `seq` of the owner signed base the documents were made from.
        base_seq: u64,
    },
}

/// Why a bundle was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// A document does not decode.
    Malformed,
    /// A document belongs to another network than the session's, or the network id is not a key.
    WrongNetwork,
    /// More than one `Steward` entry in a Roster, whoever signed it.
    TooManyStewards,
    /// The Roster and the Policy differ in `seq`, or a Policy came with no Roster of its `seq`.
    PairMismatch,
    /// `issued` is more than [`MAX_CLOCK_SKEW`] ahead of the verifier's clock.
    NotYetValid,
    /// `expires` is before `issued` or more than [`DOC_MAX_LIFETIME`] after it.
    LifetimeTooLong,
    /// `expires` is not after the verifier's clock.
    Expired,
    /// A signature does not verify.
    BadSignature,
    /// A steward signed document came without its base.
    MissingBase,
    /// The base is not a base for this document: another network, or a base Roster and base
    /// Policy that are not a pair.
    BadBase,
    /// `seq` is not above the base's or is more than [`STEWARD_SEQ_SPAN`] above it.
    SeqOutOfSpan,
    /// The base is older than the base of the Roster the verifier holds.
    BaseOlderThanHeld,
    /// The base Roster lists no steward.
    NoSteward,
    /// The `Steward` entry does not decode, is not signed by the owner, or names another network,
    /// version or an invalid key.
    BadStewardEntry,
    /// The verifier's clock is at or past the entry's `not_after`.
    StewardExpired,
    /// The document's `expires` is after the entry's `not_after`.
    ExpiresAfterNotAfter,
    /// The entry's `may` lacks the right the change needs (`renew` or `admit`).
    RightMissing,
    /// The steward changed something it may not.
    FieldChanged,
    /// Appended members that are not new and unrevoked, or Roster and Policy that do not append
    /// the same members.
    BadAppend,
    /// An appended certificate that does not verify against its own node id, or names a node that
    /// was not appended.
    BadCert,
    /// An appended member's name or role fails the hygiene rule.
    BadName,
    /// The Roster and the Policy were not signed by the same key from the same base.
    PairSigner,
}

impl Reason {
    /// The code a peer is told: `roster_expired` for an expired candidate, `bad_document` for
    /// everything else.
    pub fn code(self) -> ErrorCode {
        match self {
            Self::Expired => ErrorCode::RosterExpired,
            _ => ErrorCode::BadDocument,
        }
    }
}

/// What the verifier holds of one Roster: enough to place a Policy that arrives without its
/// Roster, and to compare a base with the base of the held Roster. Built when a Roster is
/// adopted and trusted as verified.
#[derive(Debug, Clone)]
pub struct HeldRoster {
    body: RosterBody,
    base: Option<RosterBody>,
    signer: Signer,
}

impl HeldRoster {
    /// The held `roster`, with the owner signed `base` it was made from when a steward signed it
    /// (`None` for an owner signed one). Decodes only; the signatures were checked when the
    /// Roster was adopted.
    pub fn new(roster: &Roster, base: Option<&Roster>) -> Result<Self, Reason> {
        let body = roster.decode().map_err(|_| Reason::Malformed)?;
        let Some(base) = base else {
            return Ok(Self {
                body,
                base: None,
                signer: Signer::Owner,
            });
        };
        let base = base.decode().map_err(|_| Reason::Malformed)?;
        let entry = body.stewards.first().ok_or(Reason::NoSteward)?;
        let entry = entry.decode().map_err(|_| Reason::BadStewardEntry)?;
        let signer = Signer::Steward {
            key: entry.steward_pub,
            base_seq: base.seq,
        };
        Ok(Self {
            body,
            base: Some(base),
            signer,
        })
    }

    /// The held Roster's `seq`.
    pub fn seq(&self) -> u64 {
        self.body.seq
    }

    /// The `seq` of the document the held Roster stands on: its own when the owner signed it.
    fn base_seq(&self) -> u64 {
        self.base.as_ref().map_or(self.body.seq, |base| base.seq)
    }
}

/// What a verifier holds for one network.
#[derive(Debug, Clone)]
pub struct HeldView {
    /// The network of the session the documents arrive on. Every document must be this
    /// network's, and its key checks the owner's signatures.
    pub network_id: NetworkId,
    /// The held Roster, if any.
    pub roster: Option<HeldRoster>,
    /// The `seq` of the held Policy, if any.
    pub policy_seq: Option<u64>,
}

/// The documents offered together, verbatim as they arrived. Any of them may be absent.
#[derive(Debug, Clone, Default)]
pub struct Bundle {
    /// The owner signed Roster a steward signed `roster` was made from.
    pub base_roster: Option<Roster>,
    /// The owner signed Policy a steward signed `policy` was made from.
    pub base_policy: Option<Policy>,
    /// The offered Roster.
    pub roster: Option<Roster>,
    /// The offered Policy.
    pub policy: Option<Policy>,
}

/// What to adopt. A document the verifier already holds a newer or equal one of is left out
/// (`None`); the bundle is adopted whole or not at all.
#[derive(Debug, Clone)]
pub struct Adoption {
    /// The Roster to adopt, decoded, if it is newer than the held one.
    pub roster: Option<RosterBody>,
    /// The Policy to adopt, decoded, if it is newer than the held one.
    pub policy: Option<PolicyBody>,
    /// Who signed the Roster (and the Policy) that will be held afterwards.
    pub signer: Signer,
}

/// The answer of [`check_bundle`].
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Adopt these.
    Adopt(Box<Adoption>),
    /// Nothing offered is newer than what is held. No signature was checked.
    Held,
    /// The bundle is refused; the reason is for the local log, the peer gets [`Reason::code`].
    Reject(Reason),
}

/// Whether `bundle` is to be adopted by a verifier that holds `held`, at `now` (Unix seconds).
pub fn check_bundle(held: &HeldView, bundle: &Bundle, now: u64) -> Verdict {
    match check(held, bundle, now) {
        Ok(Some(adoption)) => Verdict::Adopt(Box::new(adoption)),
        Ok(None) => Verdict::Held,
        Err(reason) => Verdict::Reject(reason),
    }
}

struct Ctx {
    owner: VerifyingKey,
    network_id: NetworkId,
    now: u64,
}

fn check(held: &HeldView, bundle: &Bundle, now: u64) -> Result<Option<Adoption>, Reason> {
    let roster = decode_roster(bundle.roster.as_ref(), held.network_id)?;
    let policy = decode_policy(bundle.policy.as_ref(), held.network_id)?;

    // The cheap path: a document that is not newer than what is held costs no signature check
    // (and a forged one is answered with `Held`, not an error).
    let held_roster_seq = held.roster.as_ref().map(HeldRoster::seq);
    let roster = roster.filter(|(_, body)| newer(body.seq, held_roster_seq));
    let policy = policy.filter(|(_, body)| newer(body.seq, held.policy_seq));
    if roster.is_none() && policy.is_none() {
        return Ok(None);
    }

    // The rest of the bundle is only read when something in it is going to be judged.
    let base_roster = decode_roster(bundle.base_roster.as_ref(), held.network_id)?;
    let base_policy = decode_policy(bundle.base_policy.as_ref(), held.network_id)?;
    if let Some((_, body)) = &base_roster {
        check_stewards_len(body)?;
    }
    if let Some((_, body)) = &roster {
        check_stewards_len(body)?;
    }

    let ctx = Ctx {
        owner: VerifyingKey::from_bytes(&<[u8; 32]>::from(held.network_id))
            .map_err(|_| Reason::WrongNetwork)?,
        network_id: held.network_id,
        now,
    };

    if let (Some((_, r)), Some((_, p))) = (&roster, &policy)
        && r.seq != p.seq
    {
        return Err(Reason::PairMismatch);
    }
    if let Some((_, r)) = &roster {
        time_rules(r.issued, r.expires, now)?;
    }
    if let Some((_, p)) = &policy {
        time_rules(p.issued, p.expires, now)?;
    }

    let held_base_seq = held.roster.as_ref().map(HeldRoster::base_seq);

    // The Roster this bundle ends up with, and who signed it: the offered one, or (for a Policy
    // that came alone) the held one of the same `seq`.
    let (signer, roster_ctx) = match &roster {
        Some((signed, body)) => {
            let base = base_roster.as_ref().map(|(s, b)| (*s, b));
            let signer = roster_signer(&ctx, signed, body, base, held_base_seq)?;
            let appended = match (&signer, base) {
                (Signer::Steward { .. }, Some((_, base_body))) => {
                    Some(roster_rules(body, base_body, &steward_of(base_body)?)?)
                }
                _ => None,
            };
            (signer, RosterOf::Offered { body, appended })
        }
        None => {
            let (_, p) = policy.as_ref().expect("one of the two is present");
            let held_roster = held
                .roster
                .as_ref()
                .filter(|h| h.seq() == p.seq)
                .ok_or(Reason::PairMismatch)?;
            (held_roster.signer, RosterOf::Held(held_roster))
        }
    };

    if let Some((signed, body)) = &policy {
        let roster_body = roster_ctx.body();
        let base = base_policy.as_ref().map(|(s, b)| (*s, b));
        let policy_signer = policy_signer(&ctx, signed, body, roster_body, base, held_base_seq)?;
        if policy_signer != signer {
            return Err(Reason::PairSigner);
        }
        if let (Signer::Steward { .. }, Some((_, base_body))) = (&policy_signer, base) {
            let entry = steward_of_stewards(&roster_body.stewards)?;
            let appended = roster_ctx.appended()?;
            policy_rules(body, base_body, &entry, &appended)?;
        }
    }

    Ok(Some(Adoption {
        roster: roster.map(|(_, body)| body),
        policy: policy.map(|(_, body)| body),
        signer,
    }))
}

/// The Roster a Policy is judged against.
enum RosterOf<'a> {
    /// In the bundle, with the members it appended when a steward signed it.
    Offered {
        body: &'a RosterBody,
        appended: Option<Vec<NodeId>>,
    },
    /// The held one, of the same `seq`.
    Held(&'a HeldRoster),
}

impl RosterOf<'_> {
    fn body(&self) -> &RosterBody {
        match self {
            Self::Offered { body, .. } => body,
            Self::Held(held) => &held.body,
        }
    }

    /// The members appended to the base (steward signed Rosters only).
    fn appended(&self) -> Result<Vec<NodeId>, Reason> {
        match self {
            Self::Offered { appended, .. } => appended.clone().ok_or(Reason::PairSigner),
            Self::Held(held) => {
                let base = held.base.as_ref().ok_or(Reason::PairSigner)?;
                Ok(held.body.members[base.members.len()..]
                    .iter()
                    .map(|m| m.node_id)
                    .collect())
            }
        }
    }
}

fn newer(seq: u64, held: Option<u64>) -> bool {
    held.is_none_or(|held| seq > held)
}

type Decoded<'a, S, B> = Option<(&'a S, B)>;

fn decode_roster(
    roster: Option<&Roster>,
    network_id: NetworkId,
) -> Result<Decoded<'_, Roster, RosterBody>, Reason> {
    let Some(roster) = roster else {
        return Ok(None);
    };
    let body = roster.decode().map_err(|_| Reason::Malformed)?;
    if body.network_id != network_id {
        return Err(Reason::WrongNetwork);
    }
    Ok(Some((roster, body)))
}

fn decode_policy(
    policy: Option<&Policy>,
    network_id: NetworkId,
) -> Result<Decoded<'_, Policy, PolicyBody>, Reason> {
    let Some(policy) = policy else {
        return Ok(None);
    };
    let body = policy.decode().map_err(|_| Reason::Malformed)?;
    if body.network_id != network_id {
        return Err(Reason::WrongNetwork);
    }
    Ok(Some((policy, body)))
}

/// A Roster lists at most one steward, whoever signed it (protocol.md 2.3: one active steward).
fn check_stewards_len(body: &RosterBody) -> Result<(), Reason> {
    if body.stewards.len() > 1 {
        return Err(Reason::TooManyStewards);
    }
    Ok(())
}

/// The time rules of every Roster and Policy (protocol.md 2.3).
fn time_rules(issued: u64, expires: u64, now: u64) -> Result<(), Reason> {
    if issued > now.saturating_add(MAX_CLOCK_SKEW) {
        return Err(Reason::NotYetValid);
    }
    if expires < issued || expires - issued > DOC_MAX_LIFETIME {
        return Err(Reason::LifetimeTooLong);
    }
    if expires <= now {
        return Err(Reason::Expired);
    }
    Ok(())
}

/// The `Steward` entry of a Roster's list, if it has exactly one, not yet verified.
fn steward_of_stewards(stewards: &[Steward]) -> Result<Steward, Reason> {
    match stewards {
        [one] => Ok(one.clone()),
        _ => Err(Reason::NoSteward),
    }
}

fn steward_of(base: &RosterBody) -> Result<Steward, Reason> {
    steward_of_stewards(&base.stewards)
}

/// The owner path, else the steward path, for a Roster. Returns who signed it; the field rules
/// of the steward path are separate ([`roster_rules`]).
fn roster_signer(
    ctx: &Ctx,
    roster: &Roster,
    body: &RosterBody,
    base: Option<(&Roster, &RosterBody)>,
    held_base_seq: Option<u64>,
) -> Result<Signer, Reason> {
    if roster.verify(&ctx.owner).is_ok() {
        return Ok(Signer::Owner);
    }
    let (base_signed, base_body) = base.ok_or(Reason::MissingBase)?;
    let entry = steward_of(base_body)?;
    let (key, vk) = steward_grant(
        ctx,
        body.seq,
        body.expires,
        base_body.seq,
        held_base_seq,
        &entry,
    )?;
    base_signed
        .verify(&ctx.owner)
        .map_err(|_| Reason::BadSignature)?;
    verify_entry(ctx, &entry)?;
    roster.verify(&vk).map_err(|_| Reason::BadSignature)?;
    Ok(Signer::Steward {
        key,
        base_seq: base_body.seq,
    })
}

/// The owner path, else the steward path, for a Policy, whose steward is the one the Roster it
/// pairs with lists.
fn policy_signer(
    ctx: &Ctx,
    policy: &Policy,
    body: &PolicyBody,
    roster: &RosterBody,
    base: Option<(&Policy, &PolicyBody)>,
    held_base_seq: Option<u64>,
) -> Result<Signer, Reason> {
    if policy.verify(&ctx.owner).is_ok() {
        return Ok(Signer::Owner);
    }
    let (base_signed, base_body) = base.ok_or(Reason::MissingBase)?;
    let entry = steward_of_stewards(&roster.stewards)?;
    let (key, vk) = steward_grant(
        ctx,
        body.seq,
        body.expires,
        base_body.seq,
        held_base_seq,
        &entry,
    )?;
    base_signed
        .verify(&ctx.owner)
        .map_err(|_| Reason::BadSignature)?;
    verify_entry(ctx, &entry)?;
    policy.verify(&vk).map_err(|_| Reason::BadSignature)?;
    Ok(Signer::Steward {
        key,
        base_seq: base_body.seq,
    })
}

/// The cheap checks of the steward path, before any signature: the `seq` span, the base against
/// the held base, the entry's content and the clocks. Returns the steward's key.
fn steward_grant(
    ctx: &Ctx,
    seq: u64,
    expires: u64,
    base_seq: u64,
    held_base_seq: Option<u64>,
    entry: &Steward,
) -> Result<(StewardKey, VerifyingKey), Reason> {
    if seq <= base_seq || seq > base_seq.saturating_add(STEWARD_SEQ_SPAN) {
        return Err(Reason::SeqOutOfSpan);
    }
    if held_base_seq.is_some_and(|held| base_seq < held) {
        return Err(Reason::BaseOlderThanHeld);
    }
    let entry = entry.decode().map_err(|_| Reason::BadStewardEntry)?;
    if entry.network_id != ctx.network_id || entry.v != PROTOCOL_VERSION {
        return Err(Reason::BadStewardEntry);
    }
    if ctx.now >= entry.not_after {
        return Err(Reason::StewardExpired);
    }
    if expires > entry.not_after {
        return Err(Reason::ExpiresAfterNotAfter);
    }
    let vk = VerifyingKey::from_bytes(&<[u8; 32]>::from(entry.steward_pub))
        .map_err(|_| Reason::BadStewardEntry)?;
    Ok((entry.steward_pub, vk))
}

/// The entry is signed by the owner.
fn verify_entry(ctx: &Ctx, entry: &Steward) -> Result<(), Reason> {
    entry
        .verify(&ctx.owner)
        .map_err(|_| Reason::BadStewardEntry)
}

/// Whether `entry` lets the steward make the change that appended `appended_any` members.
fn right_for(entry: &Steward, appended_any: bool) -> Result<(), Reason> {
    let entry = entry.decode().map_err(|_| Reason::BadStewardEntry)?;
    let right = if appended_any { "admit" } else { "renew" };
    if entry.may.iter().any(|may| may == right) {
        Ok(())
    } else {
        Err(Reason::RightMissing)
    }
}

/// A steward signed Roster against its base: the same but for the dates, or for members appended
/// at the end. Returns the appended node ids.
fn roster_rules(
    roster: &RosterBody,
    base: &RosterBody,
    entry: &Steward,
) -> Result<Vec<NodeId>, Reason> {
    if roster.v != base.v
        || roster.revoked != base.revoked
        || roster.stewards != base.stewards
        || roster.labels != base.labels
    {
        return Err(Reason::FieldChanged);
    }
    let appended = appended_of(&roster.members, &base.members)?;
    right_for(entry, !appended.is_empty())?;
    let known: HashSet<NodeId> = base.members.iter().map(|m| m.node_id).collect();
    let revoked: HashSet<NodeId> = base.revoked.iter().map(|r| r.node_id).collect();
    let mut seen = HashSet::new();
    let ids: Vec<NodeId> = appended.iter().map(|m: &RosterMember| m.node_id).collect();
    for id in &ids {
        if known.contains(id) || revoked.contains(id) || !seen.insert(*id) {
            return Err(Reason::BadAppend);
        }
    }
    Ok(ids)
}

/// The entries of `list` after `base`, which must be a prefix of it.
fn appended_of<'a, T: PartialEq>(list: &'a [T], base: &[T]) -> Result<&'a [T], Reason> {
    if list.len() < base.len() || list[..base.len()] != *base {
        return Err(Reason::FieldChanged);
    }
    Ok(&list[base.len()..])
}

/// A steward signed Policy against its base: the same but for the dates, or for the members of
/// the Roster's admission appended at the end of `members`, with their self signed certificates
/// at the end of `certs`.
fn policy_rules(
    policy: &PolicyBody,
    base: &PolicyBody,
    entry: &Steward,
    roster_appended: &[NodeId],
) -> Result<(), Reason> {
    if policy.v != base.v
        || policy.grants != base.grants
        || policy.egress != base.egress
        || policy.accept != base.accept
    {
        return Err(Reason::FieldChanged);
    }
    let members = appended_of(&policy.members, &base.members)?;
    let certs = appended_of(&policy.certs, &base.certs)?;
    right_for(entry, !members.is_empty())?;
    let ids: Vec<NodeId> = members.iter().map(|m: &PolicyMember| m.node_id).collect();
    if ids != roster_appended {
        return Err(Reason::BadAppend);
    }
    let known: HashSet<NodeId> = base.members.iter().map(|m| m.node_id).collect();
    if ids.iter().any(|id| known.contains(id)) {
        return Err(Reason::BadAppend);
    }
    for member in members {
        check_name(&member.name).map_err(|_| Reason::BadName)?;
        for role in &member.roles {
            check_role(role).map_err(|_| Reason::BadName)?;
        }
    }
    // Only now, after the document's own signature has passed, the certificates: a genuine
    // steward admission costs one verification for each.
    let appended: HashSet<NodeId> = ids.into_iter().collect();
    for cert in certs {
        let body = cert.decode().map_err(|_| Reason::BadCert)?;
        if !appended.contains(&body.node_id) {
            return Err(Reason::BadCert);
        }
        let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id))
            .map_err(|_| Reason::BadCert)?;
        cert.verify(&key).map_err(|_| Reason::BadCert)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
