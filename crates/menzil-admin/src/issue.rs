//! Issuing a network's Roster and Policy, and each successor of them.

use ed25519_dalek::VerifyingKey;
use menzil_proto::{
    Grant, MAX_DOC_BYTES, NetworkId, NodeCert, NodeId, NodeOrWildcard, PROTOCOL_VERSION, Policy,
    PolicyBody, PolicyMember, PrincipalTarget, Roster, RosterBody, RosterMember,
};
pub use menzil_proto::{is_invisible, is_unsafe};

use crate::{AdminError, MAX_CERT_LIFETIME_SECS, OwnerKey};

/// How long a Roster or Policy lives: protocol.md 2.3 allows at most 14 days
/// after `issued`, and a network whose documents are not re-issued before
/// then fails closed (7.3), so the longest allowed is the useful one.
pub const DOCUMENT_LIFETIME_SECS: u64 = 14 * 24 * 60 * 60;

/// A Roster and the Policy issued together with it (protocol.md 2.3: the
/// same `seq`, the same network). The operations below take one and return
/// the next.
#[derive(Debug, Clone)]
pub struct Documents {
    roster: Roster,
    policy: Policy,
    roster_body: RosterBody,
    policy_body: PolicyBody,
}

impl Documents {
    /// Pairs a Roster and a Policy that were issued together, for example
    /// the ones a node holds. Checks that they decode and agree on network
    /// and `seq`; whether the signatures are the owner's is checked by the
    /// operation that extends them.
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
        })
    }

    /// The signed Roster.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The signed Policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
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

    /// Signs the pair for `owner`.
    fn signed(
        owner: &OwnerKey,
        roster_body: RosterBody,
        policy_body: PolicyBody,
    ) -> Result<Self, AdminError> {
        let roster = Roster::sign(owner.signing_key(), &roster_body)?;
        let policy = Policy::sign(owner.signing_key(), &policy_body)?;
        check_size("Roster", roster.encode().len())?;
        check_size("Policy", policy.encode().len())?;
        Ok(Self {
            roster,
            policy,
            roster_body,
            policy_body,
        })
    }

    /// Checks that `owner` is the one these documents were signed by, then
    /// returns copies of both bodies with the next `seq` and a fresh
    /// lifetime, ready to be changed.
    fn successor(
        &self,
        owner: &OwnerKey,
        now: u64,
    ) -> Result<(RosterBody, PolicyBody), AdminError> {
        if owner.network_id() != self.network_id() {
            return Err(AdminError::NotThisOwner);
        }
        let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(self.network_id()))
            .map_err(menzil_proto::ProtoError::from)?;
        self.roster.verify(&key)?;
        self.policy.verify(&key)?;
        let seq = self.seq().checked_add(1).ok_or(AdminError::SeqOverflow)?;
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
    let cert = checked_cert(member, now)?;
    check_name(name)?;
    for role in roles {
        check_role(role)?;
    }
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

/// Re-issues the same documents with the next `seq` and a fresh lifetime:
/// what keeps a network from failing closed (protocol.md 7.3).
pub fn renew(owner: &OwnerKey, current: &Documents, now: u64) -> Result<Documents, AdminError> {
    let (roster, policy) = current.successor(owner, now)?;
    Documents::signed(owner, roster, policy)
}

#[cfg(test)]
mod tests;
