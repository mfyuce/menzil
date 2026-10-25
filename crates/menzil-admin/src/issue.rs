//! Issuing a network's Roster and Policy, and each successor of them.

use ed25519_dalek::{SigningKey, VerifyingKey};
use menzil_proto::trust::{
    Bundle, HeldRoster, HeldView, STEWARD_MAX_LIFETIME, STEWARD_SEQ_SPAN, Signer, Verdict,
    check_bundle,
};
use menzil_proto::{
    Grant, MAX_DOC_BYTES, NetworkId, NodeCert, NodeId, NodeOrWildcard, PROTOCOL_VERSION, Policy,
    PolicyBody, PolicyMember, PrincipalTarget, RevokedMember, Roster, RosterBody, RosterMember,
    ServiceId, Steward, StewardBody, StewardKey,
};
pub use menzil_proto::{is_invisible, is_unsafe};

use crate::{AdminError, MAX_CERT_LIFETIME_SECS, OwnerKey, StewardSecret};

/// The rights a steward entry can hold (protocol.md 2.3).
const STEWARD_RIGHTS: [&str; 2] = ["admit", "renew"];

/// How long a Roster or Policy lives: protocol.md 2.3 allows at most 14 days
/// after `issued`, and a network whose documents are not re-issued before
/// then fails closed (7.3), so the longest allowed is the useful one.
pub const DOCUMENT_LIFETIME_SECS: u64 = 14 * 24 * 60 * 60;

/// The owner signed pair a steward signed pair was made from (protocol.md 2.3).
#[derive(Debug, Clone)]
struct Base {
    roster: Roster,
    policy: Policy,
    seq: u64,
}

/// A Roster and the Policy issued together with it (protocol.md 2.3: the
/// same `seq`, the same network). The operations below take one and return
/// the next.
///
/// A pair the owner signed stands alone. A pair a steward signed travels with its base, the
/// owner signed pair it was made from ([`Self::base`]); it is never held, passed on or written
/// to disk without it.
#[derive(Debug, Clone)]
pub struct Documents {
    roster: Roster,
    policy: Policy,
    roster_body: RosterBody,
    policy_body: PolicyBody,
    base: Option<Base>,
}

impl Documents {
    /// Pairs a Roster and a Policy that were issued together, for example
    /// the ones a node holds. Checks that they decode and agree on network
    /// and `seq`; whether the signatures are the owner's is checked by the
    /// operation that extends them ([`Self::verify`]).
    pub fn from_signed(roster: Roster, policy: Policy) -> Result<Self, AdminError> {
        let roster_body = roster.decode()?;
        let policy_body = policy.decode()?;
        if roster_body.network_id != policy_body.network_id {
            return Err(AdminError::MismatchedDocuments("different networks"));
        }
        if roster_body.seq != policy_body.seq {
            return Err(AdminError::MismatchedDocuments(
                "different sequence numbers",
            ));
        }
        Ok(Self {
            roster,
            policy,
            roster_body,
            policy_body,
            base: None,
        })
    }

    /// Like [`Self::from_signed`], for a pair a steward signed, with the owner signed pair
    /// (`base_roster`, `base_policy`) it was made from. The bases must be a pair of the same
    /// network too; whether they make the documents acceptable is [`Self::verify`]'s answer.
    pub fn from_signed_with_base(
        roster: Roster,
        policy: Policy,
        base_roster: Roster,
        base_policy: Policy,
    ) -> Result<Self, AdminError> {
        let mut docs = Self::from_signed(roster, policy)?;
        let (base_roster_body, base_policy_body) = (base_roster.decode()?, base_policy.decode()?);
        if base_roster_body.network_id != docs.network_id()
            || base_policy_body.network_id != docs.network_id()
        {
            return Err(AdminError::MismatchedDocuments("a base of another network"));
        }
        if base_roster_body.seq != base_policy_body.seq {
            return Err(AdminError::MismatchedDocuments(
                "the bases have different sequence numbers",
            ));
        }
        docs.base = Some(Base {
            roster: base_roster,
            policy: base_policy,
            seq: base_roster_body.seq,
        });
        Ok(docs)
    }

    /// The signed Roster.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The signed Policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The owner signed Roster and Policy a steward signed pair was made from; `None` for a
    /// pair the owner signed.
    pub fn base(&self) -> Option<(&Roster, &Policy)> {
        self.base.as_ref().map(|base| (&base.roster, &base.policy))
    }

    /// The decoded Roster.
    pub fn roster_body(&self) -> &RosterBody {
        &self.roster_body
    }

    /// The decoded Policy.
    pub fn policy_body(&self) -> &PolicyBody {
        &self.policy_body
    }

    /// The network.
    pub fn network_id(&self) -> NetworkId {
        self.roster_body.network_id
    }

    /// The sequence number both documents carry.
    pub fn seq(&self) -> u64 {
        self.roster_body.seq
    }

    /// Whether `node_id` is a member (not merely named by a grant).
    pub fn is_member(&self, node_id: &NodeId) -> bool {
        self.roster_body
            .members
            .iter()
            .any(|member| member.node_id == *node_id)
    }

    /// The documents and their bases as the bundle the acceptance predicate judges.
    pub fn bundle(&self) -> Bundle {
        Bundle {
            base_roster: self.base.as_ref().map(|base| base.roster.clone()),
            base_policy: self.base.as_ref().map(|base| base.policy.clone()),
            roster: Some(self.roster.clone()),
            policy: Some(self.policy.clone()),
        }
    }

    /// What a verifier that holds these documents holds, for judging the next bundle with
    /// [`check_bundle`]. These documents are trusted as verified: [`Self::verify`] first.
    pub fn held_view(&self) -> Result<HeldView, AdminError> {
        let held = HeldRoster::new(&self.roster, self.base.as_ref().map(|base| &base.roster))
            .map_err(AdminError::Rejected)?;
        Ok(HeldView {
            network_id: self.network_id(),
            roster: Some(held),
            policy_seq: Some(self.seq()),
        })
    }

    /// Whether these documents stand on a valid signature, whatever the clock says: both
    /// signed by the network key (no base is looked at), or both signed by the steward the
    /// base lists, under every rule of the acceptance predicate
    /// ([`menzil_proto::trust::check_bundle`], protocol.md 2.3) as of the moment they were
    /// issued (the later of the two `issued` times: a pair whose Policy was issued after its
    /// Roster is one every verifier adopts, so it is not refused here). Documents that have expired since are still formed, and an owner can still
    /// renew them. Returns who signed.
    pub fn verify(&self) -> Result<Signer, AdminError> {
        let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(self.network_id()))
            .map_err(menzil_proto::ProtoError::from)?;
        let Some(_) = &self.base else {
            self.roster.verify(&key)?;
            self.policy.verify(&key)?;
            return Ok(Signer::Owner);
        };
        if self.roster.verify(&key).is_ok() && self.policy.verify(&key).is_ok() {
            return Ok(Signer::Owner);
        }
        let empty = HeldView {
            network_id: self.network_id(),
            roster: None,
            policy_seq: None,
        };
        let at = self.roster_body.issued.max(self.policy_body.issued);
        match check_bundle(&empty, &self.bundle(), at) {
            Verdict::Adopt(adoption) => Ok(adoption.signer),
            Verdict::Held => Err(AdminError::MismatchedDocuments("nothing to adopt")),
            Verdict::Reject(reason) => Err(AdminError::Rejected(reason)),
        }
    }

    /// These documents once [`Self::verify`] has passed, with a base that the owner's own
    /// signature makes pointless (a token can carry one) dropped: what a device may keep and
    /// pass on.
    pub fn into_verified(mut self) -> Result<Self, AdminError> {
        if self.verify()? == Signer::Owner {
            self.base = None;
        }
        Ok(self)
    }

    /// The `seq` of the next pair the owner issues (protocol.md 2.3): one above these, and,
    /// while these list a steward, above the base's plus [`STEWARD_SEQ_SPAN`], so that
    /// nothing a steward can still sign from its base outranks it. The base of an owner signed
    /// pair is the pair itself.
    pub fn next_owner_seq(&self) -> Result<u64, AdminError> {
        let plain = self.seq().checked_add(1).ok_or(AdminError::SeqOverflow)?;
        if self.roster_body.stewards.is_empty() {
            return Ok(plain);
        }
        let base_seq = self.base.as_ref().map_or(self.seq(), |base| base.seq);
        let past_span = base_seq
            .checked_add(STEWARD_SEQ_SPAN + 1)
            .ok_or(AdminError::SeqOverflow)?;
        Ok(plain.max(past_span))
    }

    /// Signs the pair for `owner`.
    fn signed(
        owner: &OwnerKey,
        roster_body: RosterBody,
        policy_body: PolicyBody,
    ) -> Result<Self, AdminError> {
        Self::signed_with(owner.signing_key(), roster_body, policy_body, None)
    }

    /// Signs the pair with `key`; `base` is the owner signed pair a steward's is made from.
    fn signed_with(
        key: &SigningKey,
        roster_body: RosterBody,
        policy_body: PolicyBody,
        base: Option<Base>,
    ) -> Result<Self, AdminError> {
        let roster = Roster::sign(key, &roster_body)?;
        let policy = Policy::sign(key, &policy_body)?;
        check_size("Roster", roster.encode().len())?;
        check_size("Policy", policy.encode().len())?;
        Ok(Self {
            roster,
            policy,
            roster_body,
            policy_body,
            base,
        })
    }

    /// Checks that `owner` is the one these documents were signed by (or, for a pair a steward
    /// signed, that it stands on the owner's base), then returns copies of both bodies with the
    /// next `seq` ([`Self::next_owner_seq`]) and a fresh lifetime, ready to be changed.
    fn successor(
        &self,
        owner: &OwnerKey,
        now: u64,
    ) -> Result<(RosterBody, PolicyBody), AdminError> {
        if owner.network_id() != self.network_id() {
            return Err(AdminError::NotThisOwner);
        }
        let this = self.clone().into_verified()?;
        let seq = this.next_owner_seq()?;
        let mut roster = self.roster_body.clone();
        let mut policy = self.policy_body.clone();
        roster.seq = seq;
        policy.seq = seq;
        roster.issued = now;
        policy.issued = now;
        roster.expires = now.saturating_add(DOCUMENT_LIFETIME_SECS);
        policy.expires = roster.expires;
        Ok((roster, policy))
    }

    /// The same for a steward, on documents that [`Self::into_verified`] has passed: the base to build on (these documents, when the owner signed
    /// them; their own base otherwise), the `Steward` entry that lists `steward`, and the
    /// bodies with `seq + 1`, `issued` now and `expires` 14 days ahead or at the entry's
    /// `not_after`, whichever comes first (protocol.md 7.3).
    fn steward_successor(
        &self,
        steward: &StewardSecret,
        now: u64,
    ) -> Result<(RosterBody, PolicyBody, Base), AdminError> {
        let this = self;
        let entry = match self.roster_body.stewards.as_slice() {
            [one] => one.decode()?,
            [] => return Err(AdminError::NoSteward),
            _ => {
                return Err(AdminError::Rejected(
                    menzil_proto::trust::Reason::TooManyStewards,
                ));
            }
        };
        if entry.steward_pub != steward.public() {
            return Err(AdminError::StewardNotListed);
        }
        if now >= entry.not_after {
            return Err(AdminError::Rejected(
                menzil_proto::trust::Reason::StewardExpired,
            ));
        }
        let base = this.base.clone().unwrap_or_else(|| Base {
            roster: this.roster.clone(),
            policy: this.policy.clone(),
            seq: this.seq(),
        });
        let seq = self.seq().checked_add(1).ok_or(AdminError::SeqOverflow)?;
        if seq > base.seq.saturating_add(STEWARD_SEQ_SPAN) {
            return Err(AdminError::SeqSpanExhausted);
        }
        let mut roster = self.roster_body.clone();
        let mut policy = self.policy_body.clone();
        roster.seq = seq;
        policy.seq = seq;
        roster.issued = now;
        policy.issued = now;
        roster.expires = now
            .saturating_add(DOCUMENT_LIFETIME_SECS)
            .min(entry.not_after);
        policy.expires = roster.expires;
        Ok((roster, policy, base))
    }

    /// Signs a steward's successor and judges it the way a verifier that holds these documents
    /// will: documents that pass here are documents the network adopts.
    fn steward_signed(
        &self,
        steward: &StewardSecret,
        roster_body: RosterBody,
        policy_body: PolicyBody,
        base: Base,
        now: u64,
    ) -> Result<Self, AdminError> {
        let next = Self::signed_with(steward.signing_key(), roster_body, policy_body, Some(base))?;
        match check_bundle(&self.held_view()?, &next.bundle(), now) {
            Verdict::Adopt(adoption) if adoption.roster.is_some() && adoption.policy.is_some() => {
                Ok(next)
            }
            Verdict::Adopt(_) | Verdict::Held => {
                Err(AdminError::MismatchedDocuments("nothing to adopt"))
            }
            Verdict::Reject(reason) => Err(AdminError::Rejected(reason)),
        }
    }
}

/// The `Steward` entry for `steward`, signed by the owner (protocol.md 2.3).
fn steward_entry(
    owner: &OwnerKey,
    steward: StewardKey,
    may: &[String],
    not_after: u64,
    now: u64,
) -> Result<Steward, AdminError> {
    VerifyingKey::from_bytes(&<[u8; 32]>::from(steward)).map_err(|_| AdminError::BadStewardKey)?;
    let mut rights: Vec<String> = Vec::new();
    for right in may {
        if !STEWARD_RIGHTS.contains(&right.as_str()) {
            return Err(AdminError::BadStewardRights);
        }
        if !rights.contains(right) {
            rights.push(right.clone());
        }
    }
    if rights.is_empty() {
        return Err(AdminError::BadStewardRights);
    }
    if not_after <= now || not_after - now > STEWARD_MAX_LIFETIME {
        return Err(AdminError::BadStewardLifetime);
    }
    Ok(Steward::sign(
        owner.signing_key(),
        &StewardBody {
            v: PROTOCOL_VERSION,
            network_id: owner.network_id(),
            steward_pub: steward,
            may: rights,
            not_after,
        },
    )?)
}

/// Lists `steward` as the network's one steward (protocol.md 2.3, 7.3), replacing any other,
/// with the rights in `may` (`admit`, `renew`) until `not_after` (at most 90 days from `now`).
/// The pair is the owner's; steward signed documents are made from it. The owner's `seq` rule
/// ([`Documents::next_owner_seq`]) holds for it like for every owner operation.
pub fn delegate_steward(
    owner: &OwnerKey,
    current: &Documents,
    steward: StewardKey,
    may: &[String],
    not_after: u64,
    now: u64,
) -> Result<Documents, AdminError> {
    let entry = steward_entry(owner, steward, may, not_after, now)?;
    let (mut roster, policy) = current.successor(owner, now)?;
    roster.stewards = vec![entry];
    Documents::signed(owner, roster, policy)
}

/// Removes the steward. The new pair outranks everything the steward can sign from any base
/// it was listed in: its `seq` is above that base's plus 2^20 (protocol.md 2.3, 7.3).
/// Members the steward admitted stay until the owner revokes them.
pub fn remove_steward(
    owner: &OwnerKey,
    current: &Documents,
    now: u64,
) -> Result<Documents, AdminError> {
    if current.roster_body().stewards.is_empty() {
        return Err(AdminError::NoSteward);
    }
    let (mut roster, policy) = current.successor(owner, now)?;
    roster.stewards.clear();
    Documents::signed(owner, roster, policy)
}

/// A steward re-issues the same documents with the next `seq` and a fresh lifetime, ending at
/// its own `not_after` at the latest (protocol.md 7.3). `current` is the pair the steward holds:
/// the owner's, which lists its key, or its own last one. The result is judged by the
/// acceptance predicate against `current` before it is returned.
pub fn steward_renew(
    steward: &StewardSecret,
    current: &Documents,
    now: u64,
) -> Result<Documents, AdminError> {
    let current = current.clone().into_verified()?;
    let (roster, policy, base) = current.steward_successor(steward, now)?;
    current.steward_signed(steward, roster, policy, base, now)
}

/// A steward admits a member (protocol.md 7.1): appended at the end of the Roster and the
/// Policy with its certificate, `min_serial` the certificate's own, and no roles (a steward
/// admits; granting is the owner's). The checks of [`admit`] apply, and the result is judged
/// by the acceptance predicate before it is returned.
pub fn steward_admit(
    steward: &StewardSecret,
    current: &Documents,
    member: &NodeCert,
    name: &str,
    now: u64,
) -> Result<Documents, AdminError> {
    let current = current.clone().into_verified()?;
    let cert = check_admission(&current, member, name, now)?;
    let (mut roster, mut policy, base) = current.steward_successor(steward, now)?;
    roster.members.push(RosterMember {
        node_id: cert.node_id,
        min_serial: cert.serial,
    });
    policy.members.push(PolicyMember {
        node_id: cert.node_id,
        name: name.to_string(),
        roles: vec![],
    });
    policy.certs.push(member.clone());
    current.steward_signed(steward, roster, policy, base, now)
}

/// A document of `len` encoded bytes must not be larger than every verifier accepts.
fn check_size(what: &'static str, len: usize) -> Result<(), AdminError> {
    if len > MAX_DOC_BYTES {
        return Err(AdminError::TooLarge {
            what,
            len,
            max: MAX_DOC_BYTES,
        });
    }
    Ok(())
}

/// A joining certificate checked the way an issuer must: it verifies against
/// the NodeId it names, is valid at `now`, and is not valid for longer than 400 days
/// (protocol.md 2.2; no verifier enforces that).
fn checked_cert(cert: &NodeCert, now: u64) -> Result<menzil_proto::NodeCertBody, AdminError> {
    let body = cert.decode()?;
    let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id))
        .map_err(|_| AdminError::CertDoesNotVerify)?;
    cert.verify(&key)
        .map_err(|_| AdminError::CertDoesNotVerify)?;
    if !body.is_valid_at(now) {
        return Err(AdminError::CertNotValidNow);
    }
    if body.not_after.saturating_sub(body.not_before) > MAX_CERT_LIFETIME_SECS {
        return Err(AdminError::CertLifetimeTooLong);
    }
    Ok(body)
}

/// A member name heads an address (`name/service`) and must be usable as one; the rule and its
/// reasons are [`menzil_proto::check_name`]'s.
///
/// Public because a device that is handed documents it did not issue has to hold them to the
/// same rule (`menzil join`): names reach terminals and addresses whoever chose them.
pub fn check_name(name: &str) -> Result<(), AdminError> {
    menzil_proto::check_name(name).map_err(AdminError::from)
}

/// A role is held to the same characters as a name ([`menzil_proto::check_role`]).
pub fn check_role(role: &str) -> Result<(), AdminError> {
    menzil_proto::check_role(role).map_err(AdminError::from)
}

/// Starts a network: seq 1, with `founder` (the owner's own device, in
/// practice) as its only member and no grants. `founder` is the certificate
/// `menzil init` made; `name` is what the network's members will call it.
pub fn create_network(
    owner: &OwnerKey,
    founder: &NodeCert,
    name: &str,
    now: u64,
) -> Result<Documents, AdminError> {
    let cert = checked_cert(founder, now)?;
    check_name(name)?;
    let network_id = owner.network_id();
    let expires = now.saturating_add(DOCUMENT_LIFETIME_SECS);
    let roster = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: now,
        expires,
        members: vec![RosterMember {
            node_id: cert.node_id,
            min_serial: cert.serial,
        }],
        revoked: vec![],
        stewards: vec![],
        labels: vec![],
    };
    let policy = PolicyBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: now,
        expires,
        members: vec![PolicyMember {
            node_id: cert.node_id,
            name: name.to_string(),
            roles: vec![],
        }],
        certs: vec![founder.clone()],
        grants: vec![],
        egress: vec![],
        accept: vec![],
    };
    Documents::signed(owner, roster, policy)
}

/// Adds a member (protocol.md 7.1): its certificate, a name for addressing
/// it, and its roles. The member's `min_serial` is the certificate's own, so
/// older certificates of the same node are dead from the start. Grants are a
/// separate step ([`grant`]), so a freshly admitted node can reach nothing
/// until it is told what.
pub fn admit(
    owner: &OwnerKey,
    current: &Documents,
    member: &NodeCert,
    name: &str,
    roles: &[String],
    now: u64,
) -> Result<Documents, AdminError> {
    let cert = check_admission(current, member, name, now)?;
    for role in roles {
        check_role(role)?;
    }
    let (mut roster, mut policy) = current.successor(owner, now)?;
    roster.members.push(RosterMember {
        node_id: cert.node_id,
        min_serial: cert.serial,
    });
    policy.members.push(PolicyMember {
        node_id: cert.node_id,
        name: name.to_string(),
        roles: roles.to_vec(),
    });
    policy.certs.push(member.clone());
    Documents::signed(owner, roster, policy)
}

/// What an issuer checks before admitting `member` as `name`: the certificate, the name, that
/// the node is not a member or revoked already and that no member has the name (letter case
/// aside).
fn check_admission(
    current: &Documents,
    member: &NodeCert,
    name: &str,
    now: u64,
) -> Result<menzil_proto::NodeCertBody, AdminError> {
    let cert = checked_cert(member, now)?;
    check_name(name)?;
    if current.is_member(&cert.node_id) {
        return Err(AdminError::AlreadyMember(cert.node_id));
    }
    if current
        .roster_body()
        .revoked
        .iter()
        .any(|revoked| revoked.node_id == cert.node_id)
    {
        return Err(AdminError::Revoked(cert.node_id));
    }
    // "Laptop" and "laptop" are two names to a computer and one to a person typing an address.
    let wanted = name.to_lowercase();
    if current
        .policy_body()
        .members
        .iter()
        .any(|existing| existing.name.to_lowercase() == wanted)
    {
        return Err(AdminError::NameTaken(menzil_proto::shown(name)));
    }
    Ok(cert)
}

/// Adds a grant (protocol.md 2.3). The principal and the node it applies to
/// must be members of this network (a role or a wildcard excepted), the
/// grant must be scoped to this network and must name a service.
pub fn grant(
    owner: &OwnerKey,
    current: &Documents,
    grant: Grant,
    now: u64,
) -> Result<Documents, AdminError> {
    if grant.from.network_id != current.network_id() {
        return Err(AdminError::ForeignGrant);
    }
    if grant.services.is_empty() {
        return Err(AdminError::EmptyGrant);
    }
    if let PrincipalTarget::Node(node_id) = &grant.from.target
        && !current.is_member(node_id)
    {
        return Err(AdminError::NotAMember(*node_id));
    }
    if let NodeOrWildcard::Node(node_id) = &grant.to_node
        && !current.is_member(node_id)
    {
        return Err(AdminError::NotAMember(*node_id));
    }
    let (roster, mut policy) = current.successor(owner, now)?;
    policy.grants.push(grant);
    Documents::signed(owner, roster, policy)
}

/// Revokes `node_id` (protocol.md 7.3), owner only. The Roster lists it in `revoked` with `since`
/// now and loses its `members` entry and the labels naming it; the Policy loses its `members`
/// entry, its certificates, the grants whose `from` or `to_node` is the node (role grants and
/// `*` grants stay) and its `egress` and `accept` entries. The `stewards` list is untouched.
/// Removal is always revocation: a steward may admit any node the Roster does not revoke, so a
/// node merely dropped from `members` could be put back by it. The node need not be a member of
/// `current` (it may have been admitted by a steward after these documents, or be revoked ahead
/// of time). Refused with [`AdminError::AlreadyRevoked`] when it is revoked already.
pub fn revoke(
    owner: &OwnerKey,
    current: &Documents,
    node_id: NodeId,
    now: u64,
) -> Result<Documents, AdminError> {
    if current
        .roster_body()
        .revoked
        .iter()
        .any(|revoked| revoked.node_id == node_id)
    {
        return Err(AdminError::AlreadyRevoked(node_id));
    }
    let (mut roster, mut policy) = current.successor(owner, now)?;
    roster.members.retain(|member| member.node_id != node_id);
    roster.revoked.push(RevokedMember {
        node_id,
        since: now,
    });
    roster.labels.retain(|label| label.node_id != node_id);
    policy.members.retain(|member| member.node_id != node_id);
    let mut certs = Vec::with_capacity(policy.certs.len());
    for cert in policy.certs.drain(..) {
        if cert.decode()?.node_id != node_id {
            certs.push(cert);
        }
    }
    policy.certs = certs;
    policy.grants.retain(|grant| {
        grant.from.target != PrincipalTarget::Node(node_id)
            && grant.to_node != NodeOrWildcard::Node(node_id)
    });
    policy.egress.retain(|rule| rule.node_id != node_id);
    policy.accept.retain(|entry| entry.node_id != node_id);
    Documents::signed(owner, roster, policy)
}

/// Takes grants out of the Policy (owner only): those with exactly this `from` and `to_node`.
/// With `services` `None` they go whole; with `Some(list)` the patterns in the list (exact
/// match, `tcp:*` is not `tcp:ssh`) are removed from each and a grant left with none goes too.
/// Expired grants are matched like any other. When nothing matched the answer is
/// [`AdminError::NoSuchGrant`] and no number is spent.
pub fn remove_grants(
    owner: &OwnerKey,
    current: &Documents,
    from: &PrincipalTarget,
    to_node: &NodeOrWildcard,
    services: Option<&[ServiceId]>,
    now: u64,
) -> Result<Documents, AdminError> {
    let (roster, mut policy) = current.successor(owner, now)?;
    let mut changed = false;
    let mut kept = Vec::with_capacity(policy.grants.len());
    for mut grant in policy.grants.drain(..) {
        if grant.from.target != *from || grant.to_node != *to_node {
            kept.push(grant);
            continue;
        }
        match services {
            None => changed = true,
            Some(list) => {
                let before = grant.services.len();
                grant.services.retain(|service| !list.contains(service));
                if grant.services.len() != before {
                    changed = true;
                }
                if !grant.services.is_empty() {
                    kept.push(grant);
                }
            }
        }
    }
    if !changed {
        return Err(AdminError::NoSuchGrant);
    }
    policy.grants = kept;
    Documents::signed(owner, roster, policy)
}

/// Re-issues the same documents with the next `seq` and a fresh lifetime:
/// what keeps a network from failing closed (protocol.md 7.3).
pub fn renew(owner: &OwnerKey, current: &Documents, now: u64) -> Result<Documents, AdminError> {
    let (roster, policy) = current.successor(owner, now)?;
    Documents::signed(owner, roster, policy)
}

#[cfg(test)]
mod tests;
