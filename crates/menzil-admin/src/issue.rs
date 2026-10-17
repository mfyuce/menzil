//! Issuing a network's Roster and Policy, and each successor of them.

use ed25519_dalek::VerifyingKey;
use menzil_proto::{
    Grant, MAX_DOC_BYTES, NetworkId, NodeCert, NodeId, NodeOrWildcard, PROTOCOL_VERSION, Policy,
    PolicyBody, PolicyMember, PrincipalTarget, Roster, RosterBody, RosterMember,
};

use crate::{AdminError, MAX_CERT_LIFETIME_SECS, OwnerKey};

/// How long a Roster or Policy lives: protocol.md 2.3 allows at most 14 days
/// after `issued`, and a network whose documents are not re-issued before
/// then fails closed (7.3), so the longest allowed is the useful one.
pub const DOCUMENT_LIFETIME_SECS: u64 = 14 * 24 * 60 * 60;

/// The longest member name: a name is the first part of a `name/service`
/// address, one DNS label's worth.
const MAX_NAME_BYTES: usize = 63;

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

/// A member name heads an address (`name/service`) and shows up in logs and on a terminal, so it
/// is letters, digits, `-`, `_` and `.` only, and starts with a letter or a digit (so it is
/// never `.` or `..`): no `/`, no whitespace, nothing a terminal treats as a control, and none
/// of the invisible characters (a right to left override, a zero width space, the Hangul fillers
/// that are letters printing as nothing: see [`is_invisible`]) that make two names look alike.
/// Letters are not limited to ASCII.
///
/// Public because a device that is handed documents it did not issue has to hold them to the
/// same rule (`menzil join`): names reach terminals and addresses whoever chose them.
pub fn check_name(name: &str) -> Result<(), AdminError> {
    if !usable_word(name) {
        return Err(AdminError::BadName(shown(name)));
    }
    // `1a2b3c4d` is a name or the start of a node id, and an address cannot tell which.
    if name.len() >= 8 && name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AdminError::NameLooksLikeNodeId(shown(name)));
    }
    Ok(())
}

/// A role is held to the same characters as a name (it is typed in `role:<role>` and printed),
/// without the rule about node ids.
pub fn check_role(role: &str) -> Result<(), AdminError> {
    if usable_word(role) {
        Ok(())
    } else {
        Err(AdminError::BadRole(shown(role)))
    }
}

fn usable_word(word: &str) -> bool {
    let letter = |c: char| c.is_alphanumeric() && !is_invisible(c);
    !word.is_empty()
        && word.len() <= MAX_NAME_BYTES
        && word.chars().next().is_some_and(letter)
        && word
            .chars()
            .all(|c| letter(c) || matches!(c, '-' | '_' | '.'))
}

/// Whether `c` is invisible, or acts on the text around it without being a letter: the Unicode
/// format characters (the bidirectional controls, the zero width characters, the soft hyphen,
/// the tag characters) and the other default-ignorable code points (the Hangul fillers, which
/// are letters that print as nothing, the variation selectors, the combining grapheme joiner,
/// the Khmer inherent vowels, the Mongolian selectors). A name made of them can look like
/// another name, and text that holds them prints as less than it says. One table for names and
/// for the text that reaches a terminal, so that the two cannot drift apart (the fourth
/// red-team round, N1: the Hangul fillers passed both).
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{ad}'
            | '\u{34f}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// Whether `c` must not reach a terminal or a log as it is: a control character (C0, DEL, C1), a
/// line or paragraph separator, or an invisible one ([`is_invisible`]).
pub fn is_unsafe(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') || is_invisible(c)
}

/// `text` with every unsafe character written out as an escape such as `\u{3164}`: what an error
/// quotes of a name or a role it refused, so that it does not carry the very characters the
/// name was refused for (`{:?}` leaves the Hangul fillers alone: they are letters).
fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_unsafe(c) {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
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
        return Err(AdminError::NameTaken(shown(name)));
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
