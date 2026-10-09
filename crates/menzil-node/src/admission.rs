//! L4 admission glue over [`PolicyStore`]/[`RosterStore`] (protocol.md
//! 5.1's handshake "Checks" paragraph and grant gate, 5.3's per-OPEN
//! grant check) — TODO.md L4h2. Pure, synchronous, no I/O, in the same
//! spirit as [`PolicyStore`] itself: this module answers "is this
//! allowed, right now, given what I currently hold," nothing more.
//! Running the actual Noise handshake (`menzil-e2e`) and the frame demux
//! that calls into this module (TODO.md L4h6) are both still to come.
//!
//! **Both sides' standing, not only the initiator's**: protocol.md 5.1
//! says the responder verifies "that *both* are unrevoked members of
//! `network_id` in an unexpired Roster and Policy" — [`decide_responder_
//! admission`] checks the responder's own standing (its caller-supplied
//! `responder_cert_serial`) as well as the initiator's, not only the
//! latter. A first version of this function checked only the initiator;
//! an opus red-team review (2026-10-05) caught the omission directly, by
//! constructing a Roster that revokes the responder and confirming the
//! function still answered `Allow`: a node already revoked from a
//! network (say, the owner reacting to a detected compromise) kept
//! admitting and serving OPENs from stale peers who simply hadn't
//! noticed the revocation yet, even though 7.3 names exactly this as a
//! case peers "refuse new sessions" over. Fixed here.
//!
//! **Three judgment calls protocol.md 5.1 leaves open, decided here**
//! (TODO.md L4h2's own line names exactly these three and asks whoever
//! implements it to record the choice):
//!
//! 1. **What the responder answers when a check fails**: protocol.md 5.1
//!    states no wire answer for this (only the separate grant check,
//!    right after it, gets one: resp-then-CLOSE `no_grant`). Decided
//!    here: refuse silently, never writing `resp` at all —
//!    [`HandshakeAdmission::Refuse`]. Two reasons, both already
//!    established precedent in this codebase rather than invented fresh:
//!    [`PolicyStore::check_membership`]'s own doc comment already warns a
//!    wire-facing caller to "collapse this to one uniform outward answer"
//!    rather than hand an unauthenticated-standing peer the kind of
//!    oracle `menzil-relay/src/forward.rs`'s finding M2 closed off — and
//!    silence is the most uniform answer there is. Not, however, *the
//!    same observable event* as the relay's own `peer_offline` ERROR (an
//!    earlier version of this comment overclaimed that; a red-team
//!    review caught it): `peer_offline` fires synchronously at L3 when
//!    the destination isn't even attached, while this is wire silence one
//!    layer up, shaped like an L4 handshake that simply never completes
//!    for any other reason either — different events, even though
//!    neither leaks *why*. It is also the cheaper answer: protocol.md 5.1
//!    rate-limits handshakes specifically because each "costs four
//!    Diffie-Hellman operations and two signature checks," and
//!    `E2eResponderHandshake::start`'s own doc comment (in `menzil-e2e`,
//!    not a dependency here) already exposes the initiator's static key
//!    before `resp` is written precisely so a caller can refuse before
//!    paying to complete the handshake for a peer with no real standing.
//!    The already-mandated grant-check answer stays the one case that
//!    gets an explicit wire reply, reusing it rather than inventing a
//!    parallel "membership failed" code.
//! 2. **Whether the initiator also checks the responder's own standing**
//!    (5.1's "both... are unrevoked members" is stated as the
//!    responder's check on the initiator; nothing symmetric is stated for
//!    the initiator checking the responder): decided here as yes, in
//!    [`decide_initiator_admission`]. threat-model.md 5's own item 5 ("A
//!    NodeCert with a serial below `min_serial`... is rejected at L3 and
//!    L4") reads as a guarantee about the protocol as a whole, not one
//!    side only, and 7.3's "peers close its L4 sessions on receipt and
//!    refuse new ones" sits oddly next to an initiator that skips this
//!    entirely. **Which cert the serial comes from matters, and an
//!    earlier version of this function got it wrong**: it used `resp`'s
//!    own self-asserted payload cert directly for the check. A red-team
//!    review demonstrated live that this is a real hole, not a style
//!    choice: an adversary who has compromised a node's Ed25519 identity
//!    key (threat-model 2.5's own adversary class) can self-sign *any*
//!    `NodeCertBody` it likes — a serial far above the real current one,
//!    a validity window out to `u64::MAX` — and the Noise transcript
//!    cannot tell a forged payload from a genuine one once message 1
//!    completes against whatever key the initiator happened to dial (an
//!    old, already-compromised one its own Policy snapshot hadn't moved
//!    past yet). Trusting that self-asserted serial would let a revoked
//!    node's still-live old key keep passing the one check — serial-floor
//!    enforcement — that revocation depends on. Fixed: the check below
//!    resolves the responder's cert from *this node's own* held Policy
//!    (the same [`resolve_member_cert`] the responder side already uses,
//!    just run against the initiator's own documents), never from the
//!    payload. The payload's `node_cert` is still used, but only for
//!    protocol.md 5.1's own two named checks — `node_id`/`x25519_pub`
//!    matching what was actually dialed and negotiated, a
//!    wire-consistency check on what the responder claims about itself,
//!    not a trust anchor for anything serial-related. A legitimate
//!    rotation this node's own Policy snapshot has not caught up to yet
//!    is therefore *not* specially caught by this check (an earlier
//!    version of this comment claimed it was) — it fails exactly like any
//!    other staleness would, the same outcome a session simply never
//!    completing produces either way.
//! 3. **Whether a Policy's `accept` entries are evaluated**: decided here
//!    as no, in either check this module implements — but the premise is
//!    narrower than an earlier version of this comment stated. `accept`
//!    (protocol.md 2.3, [`menzil_proto::network::AcceptEntry`]) is a
//!    *different* field from `ADVERTISE`'s own `accept_peers: bool`
//!    (protocol.md 4.2's forwarding rule, 6.1's relay-principal rule) —
//!    the one that actually has stated wire semantics today, enforced by
//!    a relay that never sees Policy at all. Whether Policy's own
//!    `accept` is meant to be the owner-authoritative counterpart a
//!    node's self-reported `accept_peers` should agree with, and who
//!    would ever check that agreement, protocol.md does not say — flagged
//!    as TOBEDECIDED item 9 rather than left for "if a real use surfaces"
//!    (a red-team review's correction to this comment's own earlier
//!    framing: worth deciding now, not deferring indefinitely).
//!
//! **Also found by that same review, flagged rather than fixed here**
//! (both now their own TODO.md lines, since fixing either is out of this
//! module's own scope): [`PolicyStore::has_grant`] matches a direct
//! `Principal::Node` grant without checking the Policy's own `members`
//! list, so a node removed from `members` but still named by a leftover
//! direct grant gets `NotMember` at handshake time yet `Allow` for the
//! identical service through [`PolicyAuthorizer`] — an L4c question, not
//! this module's to silently patch over. And: nothing here yet gives a
//! *pre-dial* caller (TODO.md L4e1/L4h6, not yet built) a way to resolve
//! "the cert I should dial with" the way [`resolve_member_cert`] resolves
//! one after the fact from an already-known key — needed before
//! `E2eInitiatorHandshake::start` can actually be driven.
//!
//! **Deliberately not done here**: putting any of the above on the wire
//! with more detail than "allow" / "allow, no grant" / refuse outright —
//! see point 1. [`HandshakeAdmission::Refuse`] and
//! [`InitiatorAdmission::Refuse`] both carry an [`ErrorCode`] purely for
//! the caller's own local logs, mirroring `check_membership`'s identical
//! choice to return a detailed error for diagnostics while cautioning
//! against ever forwarding it; nothing in this module's own public API
//! encodes that reason onto a wire record. Also not done here: resolving
//! *which* NodeCert this node itself sends in its own outgoing handshake
//! payload — that is this node's own already-established
//! [`crate::LocalIdentity`], not a Policy lookup.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use menzil_proto::{
    E2eHandshakePayload, ErrorCode, NetworkId, NodeCert, NodeCertBody, NodeId, ProtoError,
    X25519PublicKey,
};
use menzil_stream::{Authorizer, OpenDecision, OpenRefusal, OpenRequest};

use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;

/// Verifies `cert`'s self-signature against its own claimed `node_id`
/// (protocol.md 2.2: a node's `NodeId` *is* its Ed25519 public key, the
/// same reading `PolicyStore::set`'s identical
/// `VerifyingKey::from_bytes(&<[u8; 32]>::from(body.network_id))` call
/// already makes for a network's own self-signed documents) and that it
/// is currently valid, returning its decoded body on success. Used
/// wherever this module must trust a NodeCert's fields before relying on
/// them — on the responder side a candidate pulled from the Policy's own
/// `certs` (never individually re-verified when the Policy itself was
/// stored: `PolicyStore::set` only checks the enclosing PolicyBody's own
/// signature, leaving each embedded NodeCert's self-signature to whoever
/// actually relies on it, exactly the caller `check_membership`'s own doc
/// comment already expects: "the NodeCert the caller already decoded and
/// verified — not this function's concern"); on the initiator side, the
/// cert freshly received in `resp`'s payload, for the two wire-consistency
/// checks only (see this module's doc comment, point 2).
fn verify_cert(cert: &NodeCert, now: u64) -> Result<NodeCertBody, ProtoError> {
    let body = cert.decode()?;
    let verifying_key =
        VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id)).map_err(ProtoError::from)?;
    cert.verify(&verifying_key)?;
    if !body.is_valid_at(now) {
        return Err(ProtoError::Decode(
            "NodeCert is not valid at this time".to_string(),
        ));
    }
    Ok(body)
}

/// Resolves the member cert that must back `node_id`'s Noise static key
/// `claimed_key`, from `network_id`'s currently held Policy (protocol.md
/// 5.1's responder check: "the initiator's `node_id` equals the RECV
/// `src` and its static key matches"). Only a cert that matches both
/// `node_id` and `claimed_key`, is self-signed, and is currently valid
/// counts; among any such (structurally possible, if unusual — Policy's
/// `certs` is a flat list, not keyed) duplicates, the highest `serial`
/// wins, the same defensive "don't trust whichever happens to come
/// first" discipline `PolicyStore`'s own `roster_standing` already
/// applies to `RosterMember` duplicates (that one picks the strictest
/// floor across duplicates; this one picks the most permissive still-
/// valid serial — opposite directions, same discipline of not trusting
/// list order).
///
/// The cheap, unauthenticated `node_id`/`claimed_key` comparison runs
/// before the expensive self-signature check, not after: a red-team
/// review measured the other order live at ~373 ms per call with 3,000
/// certs in the Policy (comfortably under `MAX_DOC_BYTES`), since every
/// single entry paid for a full `verify_strict` before ever being
/// compared against what was actually being looked up. Both orders give
/// the same answer; only the cost differs, and nothing about this
/// reordering creates a timing oracle — resolution answers [`Option`],
/// never anything that reaches the wire (see this module's doc comment,
/// point 1), so there is no outward response for a timing difference to
/// leak through to begin with.
fn resolve_member_cert(
    policies: &PolicyStore,
    network_id: &NetworkId,
    node_id: &NodeId,
    claimed_key: &X25519PublicKey,
    now: u64,
) -> Option<NodeCertBody> {
    let policy = policies.body(network_id)?;
    policy
        .certs
        .iter()
        .filter(|cert| {
            cert.decode()
                .is_ok_and(|body| &body.node_id == node_id && &body.x25519_pub == claimed_key)
        })
        .filter_map(|cert| verify_cert(cert, now).ok())
        .max_by_key(|body| body.serial)
}

/// Resolves the cert to *dial* `node_id` with in `network_id` (protocol.md
/// 5.1: "A knows B's current NodeCert from the Policy `certs`"): the
/// counterpart of `resolve_member_cert`, which starts from a Noise static
/// key already negotiated and goes looking for the cert behind it, where
/// this starts from nothing but the peer's identity and says which key to
/// hand `E2eInitiatorHandshake::start` as the responder's (TODO.md L4h6,
/// the "no pre-dial NodeCert resolution" line).
///
/// Only a cert for `node_id` that is self-signed, currently valid and
/// whose serial passes [`PolicyStore::check_membership`] against the held
/// Roster counts: a peer whose newest cert this node knows of sits below
/// the Roster's `min_serial` floor, is revoked, or is simply not a member
/// is not dialed at all, which saves the Diffie Hellmans and, more to the
/// point, never trusts a key this node's own documents have moved past.
/// The highest serial wins among several that pass, the same
/// not-trusting-list-order discipline as `resolve_member_cert`. `None`
/// when the network is not held or nothing qualifies; the caller decides
/// what that means for whoever wanted the session.
pub fn resolve_dial_cert(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    node_id: &NodeId,
    now: u64,
) -> Option<NodeCertBody> {
    let policy = policies.body(network_id)?;
    policy
        .certs
        .iter()
        .filter(|cert| {
            // The cheap comparison first, for the same reason as in
            // `resolve_member_cert`: do not pay a signature check per
            // entry just to compare it against the one being looked up.
            cert.decode().is_ok_and(|body| &body.node_id == node_id)
        })
        .filter_map(|cert| verify_cert(cert, now).ok())
        .filter(|body| {
            policies
                .check_membership(rosters, network_id, node_id, body.serial, now)
                .is_ok()
        })
        .max_by_key(|body| body.serial)
}

/// What protocol.md 5.1's responder-side checks, plus its handshake-time
/// grant gate (`PolicyStore::has_grant` with `service: None`), decide
/// about one just-read `init` — before `resp` is ever written. See this
/// module's own doc comment, point 1, for why a failed check answers
/// silently rather than on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeAdmission {
    /// Every check passed and a grant exists: complete the handshake
    /// (write `resp`) and proceed normally.
    Allow,
    /// Every check passed but no grant exists for this initiator on this
    /// node (protocol.md 5.1): complete the handshake, then immediately
    /// answer with a `data` record of kind CLOSE `no_grant` — the one
    /// case protocol.md gives an explicit wire answer for.
    AllowNoGrant,
    /// A cert, membership, or serial check failed, for either side — see
    /// this module's doc comment on checking "both" sides' standing.
    /// Never write `resp`. `reason` is for this caller's own local logs
    /// only — see this module's own doc comment, point 1; it must never
    /// reach the wire.
    Refuse {
        /// Why, for local diagnostics only.
        reason: ErrorCode,
    },
}

/// Decides [`HandshakeAdmission`] for an `init` whose Noise message 1 has
/// already been read (so `initiator_static` — `E2eResponderHandshake::
/// initiator_static` in `menzil-e2e` — is already known), before `resp`
/// is written. `initiator_node_id` is the peer's claimed identity from
/// outside the handshake itself (protocol.md 5.1: "the RECV `src`"; see
/// `menzil-e2e::handshake`'s own doc comment for why a wrong value here
/// simply makes the handshake fail rather than needing its own explicit
/// check — this function trusts its caller already supplied the right
/// one, the same way the handshake crate itself does). `responder_node_id`
/// and `responder_cert_serial` are this node's own identity and current
/// cert serial (from its own [`crate::LocalIdentity`]) — this module's
/// doc comment explains why the responder's own standing is checked here
/// too, not only the initiator's.
// 8 genuinely independent scalar inputs (shared context plus both sides' own
// identity) — a struct bundling two of them purely to dodge this count would be
// ceremony this crate otherwise avoids, not a real grouping.
#[allow(clippy::too_many_arguments)]
pub fn decide_responder_admission(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    initiator_node_id: &NodeId,
    initiator_static: &X25519PublicKey,
    responder_node_id: &NodeId,
    responder_cert_serial: u32,
    now: u64,
) -> HandshakeAdmission {
    let Some(cert) = resolve_member_cert(
        policies,
        network_id,
        initiator_node_id,
        initiator_static,
        now,
    ) else {
        return HandshakeAdmission::Refuse {
            reason: ErrorCode::BadCert,
        };
    };

    if let Err(reason) =
        policies.check_membership(rosters, network_id, initiator_node_id, cert.serial, now)
    {
        return HandshakeAdmission::Refuse { reason };
    }

    if let Err(reason) = policies.check_membership(
        rosters,
        network_id,
        responder_node_id,
        responder_cert_serial,
        now,
    ) {
        return HandshakeAdmission::Refuse { reason };
    }

    if policies.has_grant(
        rosters,
        network_id,
        initiator_node_id,
        responder_node_id,
        None,
        now,
    ) {
        HandshakeAdmission::Allow
    } else {
        HandshakeAdmission::AllowNoGrant
    }
}

/// What the initiator-side checks decide about a just-finished `resp`.
/// See this module's own doc comment, point 2, for why this includes a
/// standing check protocol.md 5.1 does not literally name, and for which
/// cert's serial it uses and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorAdmission {
    /// Every check passed: the session is good to use.
    Allow,
    /// A check failed. `reason` is for local logs only (see this
    /// module's own doc comment, point 1) — there is no wire answer to
    /// give here either way: the handshake has already completed by the
    /// time this runs, so the only lever left is to drop the resulting
    /// transport unused, never sending anything over it, the same
    /// outward silence [`HandshakeAdmission::Refuse`] produces from the
    /// other side.
    Refuse {
        /// Why, for local diagnostics only.
        reason: ErrorCode,
    },
}

/// Decides [`InitiatorAdmission`] after `E2eInitiatorHandshake::finish`
/// (in `menzil-e2e`) has returned. `dialed_node_id` is the NodeId this
/// node chose to dial (protocol.md 5.1's first initiator check);
/// `negotiated_responder_static` is `finish`'s own returned responder
/// static key (its second check). `payload` is `finish`'s returned
/// [`E2eHandshakePayload`] — used only for those two named wire-
/// consistency checks. The membership/serial check below resolves the
/// responder's cert from *this node's own* held Policy instead (the same
/// way the responder resolves the initiator's), never from `payload` —
/// see this module's doc comment, point 2, for why trusting the payload
/// directly there is a real hole, not a style choice.
pub fn decide_initiator_admission(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    dialed_node_id: &NodeId,
    negotiated_responder_static: &X25519PublicKey,
    payload: &E2eHandshakePayload,
    now: u64,
) -> InitiatorAdmission {
    let Ok(claimed) = verify_cert(&payload.node_cert, now) else {
        return InitiatorAdmission::Refuse {
            reason: ErrorCode::BadCert,
        };
    };

    if &claimed.node_id != dialed_node_id || &claimed.x25519_pub != negotiated_responder_static {
        return InitiatorAdmission::Refuse {
            reason: ErrorCode::BadCert,
        };
    }

    let Some(own_view) = resolve_member_cert(
        policies,
        network_id,
        dialed_node_id,
        negotiated_responder_static,
        now,
    ) else {
        return InitiatorAdmission::Refuse {
            reason: ErrorCode::BadCert,
        };
    };

    match policies.check_membership(rosters, network_id, dialed_node_id, own_view.serial, now) {
        Ok(()) => InitiatorAdmission::Allow,
        Err(reason) => InitiatorAdmission::Refuse { reason },
    }
}

/// Implements [`menzil_stream::Authorizer`] (protocol.md 5.3's per-OPEN
/// grant check) against this node's held [`PolicyStore`]/[`RosterStore`]
/// — the per-OPEN counterpart to [`decide_responder_admission`]'s
/// handshake-time gate, both reusing `PolicyStore::has_grant`, narrowed
/// here by the OPEN's own `service`. `network_id`/`to_node` are this L4
/// session's own fixed identity (the same two values
/// [`decide_responder_admission`] used to admit it), supplied once at
/// construction: an `Authorizer` is per-session, not global.
#[derive(Clone)]
pub struct PolicyAuthorizer {
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    network_id: NetworkId,
    to_node: NodeId,
}

impl PolicyAuthorizer {
    /// Builds an authorizer for one L4 session on `network_id`, where
    /// `to_node` (this node's own identity) is the grant's target.
    pub fn new(
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        network_id: NetworkId,
        to_node: NodeId,
    ) -> Self {
        Self {
            policies,
            rosters,
            network_id,
            to_node,
        }
    }
}

impl Authorizer for PolicyAuthorizer {
    fn authorize(&self, request: &OpenRequest) -> OpenDecision {
        // Defensive: an `OpenRequest` for a different network than this
        // authorizer's own is caller misuse (every real caller builds one
        // authorizer per session, scoped to that session's own
        // `network_id`), but evaluating grants for the wrong network
        // would be worse than refusing outright — a red-team review
        // found this was previously unchecked.
        if request.network_id != self.network_id {
            return OpenDecision::Deny(OpenRefusal {
                code: ErrorCode::NoGrant,
                msg: "no grant".to_string(),
            });
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.policies.has_grant(
            &self.rosters,
            &self.network_id,
            &request.initiator,
            &self.to_node,
            Some(&request.service),
            now,
        ) {
            OpenDecision::Allow
        } else {
            OpenDecision::Deny(OpenRefusal {
                code: ErrorCode::NoGrant,
                msg: "no grant".to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{
        Grant, NodeOrWildcard, Policy, PolicyMember, Principal, PrincipalTarget, Roster,
        RosterMember,
    };

    /// Freshly generated identities for one test: a network owner, an
    /// `initiator` (whose Ed25519 identity key doubles as its signing key
    /// for its own NodeCert) and a `responder` (this node, in these
    /// tests — a fixed NodeId is enough since nothing here signs on its
    /// behalf). Generated once per test rather than hard-coded so
    /// `initiator_node_id`'s matching NodeCert can always be signed
    /// correctly.
    struct Ids {
        owner: SigningKey,
        network_id: NetworkId,
        initiator_signing_key: SigningKey,
        initiator_node_id: NodeId,
        initiator_x25519: X25519PublicKey,
        initiator_cert_serial: u32,
        responder_node_id: NodeId,
        responder_cert_serial: u32,
    }

    fn fresh_ids() -> Ids {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let initiator_signing_key = SigningKey::generate(&mut rand::rng());
        let initiator_node_id = NodeId::from(initiator_signing_key.verifying_key().to_bytes());
        // Not a real X25519 key — these tests never run an actual Noise
        // handshake, only compare this value against itself, so any
        // distinct 32-byte value serves.
        let initiator_x25519 = X25519PublicKey::from([0x42u8; 32]);
        let responder_node_id = NodeId::from([0x99u8; 32]);
        Ids {
            owner,
            network_id,
            initiator_signing_key,
            initiator_node_id,
            initiator_x25519,
            initiator_cert_serial: 3,
            responder_node_id,
            // Deliberately different from `initiator_cert_serial`, so a
            // test that accidentally mixed the two up would be caught.
            responder_cert_serial: 5,
        }
    }

    fn signed_cert(
        ids: &Ids,
        x25519_pub: X25519PublicKey,
        not_before: u64,
        not_after: u64,
    ) -> NodeCert {
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: ids.initiator_node_id,
            x25519_pub,
            serial: ids.initiator_cert_serial,
            not_before,
            not_after,
        };
        NodeCert::sign(&ids.initiator_signing_key, &body).unwrap()
    }

    /// A Roster listing both `initiator` (at `initiator_min_serial`) and
    /// `responder` (fixed at `min_serial: 1`, comfortably below
    /// `ids.responder_cert_serial`) — both sides need Roster/Policy
    /// standing now that [`decide_responder_admission`] checks both
    /// (see this module's doc comment).
    fn signed_roster(ids: &Ids, initiator_min_serial: u32) -> Roster {
        let body = menzil_proto::RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id: ids.network_id,
            seq: 1,
            issued: 0,
            expires: 4_000_000_000,
            members: vec![
                RosterMember {
                    node_id: ids.initiator_node_id,
                    min_serial: initiator_min_serial,
                },
                RosterMember {
                    node_id: ids.responder_node_id,
                    min_serial: 1,
                },
            ],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(&ids.owner, &body).unwrap()
    }

    fn signed_policy(ids: &Ids, certs: Vec<NodeCert>, grants: Vec<Grant>) -> Policy {
        let body = menzil_proto::PolicyBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id: ids.network_id,
            seq: 1,
            issued: 0,
            expires: 4_000_000_000,
            members: vec![
                PolicyMember {
                    node_id: ids.initiator_node_id,
                    name: "initiator".to_string(),
                    roles: vec![],
                },
                PolicyMember {
                    node_id: ids.responder_node_id,
                    name: "responder".to_string(),
                    roles: vec![],
                },
            ],
            certs,
            grants,
            egress: vec![],
            accept: vec![],
        };
        Policy::sign(&ids.owner, &body).unwrap()
    }

    fn allowing_grant(ids: &Ids) -> Grant {
        Grant {
            from: Principal {
                network_id: ids.network_id,
                target: PrincipalTarget::Node(ids.initiator_node_id),
            },
            to_node: NodeOrWildcard::Node(ids.responder_node_id),
            services: vec!["tcp:ssh".parse().unwrap()],
            expires: None,
        }
    }

    /// A network with `initiator` and `responder` both as Roster/Policy
    /// members (`initiator`'s Roster `min_serial: 1`), and a Policy
    /// carrying one valid, self-signed NodeCert for `initiator` at
    /// `ids.initiator_cert_serial` — everything
    /// `decide_responder_admission` needs to reach its grant check.
    /// `grants` is whatever the Policy should additionally carry.
    struct Fixture {
        ids: Ids,
        policies: PolicyStore,
        rosters: RosterStore,
    }

    fn fixture(grants: Vec<Grant>) -> Fixture {
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&ids, 1)).unwrap();

        let cert = signed_cert(&ids, ids.initiator_x25519, 0, 4_000_000_000);
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(&ids, vec![cert], grants))
            .unwrap();

        Fixture {
            ids,
            policies,
            rosters,
        }
    }

    #[test]
    fn responder_allows_a_member_with_a_grant() {
        let f = fixture(vec![]);
        let grant = allowing_grant(&f.ids);
        // Re-store a Policy that now also carries the grant: `fixture`'s
        // own store already holds seq 1, so this needs a higher seq to
        // replace it (`PolicyStore::set`'s own "never a lower or equal
        // seq" rule).
        let cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, 4_000_000_000);
        let mut body = signed_policy(&f.ids, vec![cert], vec![grant])
            .decode()
            .unwrap();
        body.seq = 2;
        let policy = Policy::sign(&f.ids.owner, &body).unwrap();
        assert!(f.policies.set(&policy).unwrap());

        assert_eq!(
            decide_responder_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.initiator_x25519,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
                1_000,
            ),
            HandshakeAdmission::Allow
        );
    }

    #[test]
    fn responder_allows_but_closes_a_member_with_no_grant() {
        let f = fixture(vec![]);
        assert_eq!(
            decide_responder_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.initiator_x25519,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
                1_000,
            ),
            HandshakeAdmission::AllowNoGrant
        );
    }

    #[test]
    fn responder_refuses_silently_when_no_cert_matches_the_negotiated_key() {
        let f = fixture(vec![]);
        let wrong_key = X25519PublicKey::from([0x55u8; 32]);
        assert_eq!(
            decide_responder_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &wrong_key,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
                1_000,
            ),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn responder_refuses_silently_when_only_a_different_members_cert_matches_the_key() {
        // A cert exists for some *other* node (`mallory`) at the same
        // negotiated key as `initiator_static`, with a serial that would
        // satisfy `initiator`'s own `min_serial` if it were wrongly
        // resolved for `initiator_node_id` instead of `mallory_node_id` —
        // pins that resolution requires BOTH `node_id` and the key to
        // match, not the key alone (a red-team review found this
        // specific property untested).
        let f = fixture(vec![]);
        let mallory_signing_key = SigningKey::generate(&mut rand::rng());
        let mallory_node_id = NodeId::from(mallory_signing_key.verifying_key().to_bytes());
        let mallory_cert = NodeCert::sign(
            &mallory_signing_key,
            &NodeCertBody {
                v: menzil_proto::PROTOCOL_VERSION,
                node_id: mallory_node_id,
                x25519_pub: f.ids.initiator_x25519,
                serial: 1,
                not_before: 0,
                not_after: 4_000_000_000,
            },
        )
        .unwrap();
        let mut body = signed_policy(&f.ids, vec![mallory_cert], vec![])
            .decode()
            .unwrap();
        body.seq = 2;
        let policy = Policy::sign(&f.ids.owner, &body).unwrap();
        assert!(f.policies.set(&policy).unwrap());

        assert_eq!(
            decide_responder_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.initiator_x25519,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
                1_000,
            ),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::BadCert
            },
            "mallory's cert matches the key but not initiator_node_id; it must not be used"
        );
    }

    #[test]
    fn responder_refuses_silently_when_the_cert_self_signature_is_forged() {
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&ids, 1)).unwrap();

        // Signed by a different key than the one `node_id` actually
        // names — structurally matches `initiator_node_id`/`initiator_
        // x25519` but is not a real self-signature.
        let forger = SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: ids.initiator_node_id,
            x25519_pub: ids.initiator_x25519,
            serial: ids.initiator_cert_serial,
            not_before: 0,
            not_after: 4_000_000_000,
        };
        let forged_cert = NodeCert::sign(&forger, &body).unwrap();

        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(&ids, vec![forged_cert], vec![]))
            .unwrap();

        assert_eq!(
            decide_responder_admission(
                &policies,
                &rosters,
                &ids.network_id,
                &ids.initiator_node_id,
                &ids.initiator_x25519,
                &ids.responder_node_id,
                ids.responder_cert_serial,
                1_000,
            ),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn responder_refuses_silently_when_the_matching_cert_has_expired() {
        let f = fixture(vec![]);
        // Replace the fixture's far-future cert with one that already
        // expired, at a higher seq so it actually replaces it.
        let expired_cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, 500);
        let mut body = signed_policy(&f.ids, vec![expired_cert.clone()], vec![])
            .decode()
            .unwrap();
        body.seq = 2;
        body.certs = vec![expired_cert];
        let policy = Policy::sign(&f.ids.owner, &body).unwrap();
        assert!(f.policies.set(&policy).unwrap());

        assert_eq!(
            decide_responder_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.initiator_x25519,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
                1_000,
            ),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn responder_picks_the_highest_serial_among_duplicate_valid_certs() {
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        // min_serial 5: the low-serial duplicate (1) would fail
        // `check_membership` on its own — only picking the high-serial
        // one (7) lets this succeed, so the assertion below actually
        // pins that resolution doesn't stop at whichever duplicate
        // happens to come first (a red-team review found the previous
        // version of this test, at min_serial 1, could not tell the two
        // apart: both passed either way).
        rosters.set(&signed_roster(&ids, 5)).unwrap();

        let low = NodeCert::sign(
            &ids.initiator_signing_key,
            &NodeCertBody {
                v: menzil_proto::PROTOCOL_VERSION,
                node_id: ids.initiator_node_id,
                x25519_pub: ids.initiator_x25519,
                serial: 1,
                not_before: 0,
                not_after: 4_000_000_000,
            },
        )
        .unwrap();
        let high = NodeCert::sign(
            &ids.initiator_signing_key,
            &NodeCertBody {
                v: menzil_proto::PROTOCOL_VERSION,
                node_id: ids.initiator_node_id,
                x25519_pub: ids.initiator_x25519,
                serial: 7,
                not_before: 0,
                not_after: 4_000_000_000,
            },
        )
        .unwrap();

        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(&ids, vec![low, high], vec![]))
            .unwrap();

        assert_eq!(
            decide_responder_admission(
                &policies,
                &rosters,
                &ids.network_id,
                &ids.initiator_node_id,
                &ids.initiator_x25519,
                &ids.responder_node_id,
                ids.responder_cert_serial,
                1_000,
            ),
            HandshakeAdmission::AllowNoGrant,
            "only the serial-7 duplicate satisfies min_serial 5; picking the serial-1 one \
             instead would wrongly refuse"
        );
    }

    #[test]
    fn responder_refuses_silently_when_the_initiators_membership_fails() {
        let f = fixture(vec![]);
        // `initiator`'s cert serial is below this custom Roster's
        // min_serial for it — StaleSerial, a real `check_membership`
        // failure rather than a cert-resolution one.
        let rosters = RosterStore::new();
        let mut body = signed_roster(&f.ids, 10).decode().unwrap();
        body.seq = 1;
        rosters
            .set(&Roster::sign(&f.ids.owner, &body).unwrap())
            .unwrap();

        match decide_responder_admission(
            &f.policies,
            &rosters,
            &f.ids.network_id,
            &f.ids.initiator_node_id,
            &f.ids.initiator_x25519,
            &f.ids.responder_node_id,
            f.ids.responder_cert_serial,
            1_000,
        ) {
            HandshakeAdmission::Refuse {
                reason: ErrorCode::StaleSerial,
            } => {}
            other => panic!("expected a StaleSerial refusal, got {other:?}"),
        }
    }

    #[test]
    fn responder_refuses_silently_when_its_own_standing_fails() {
        // protocol.md 5.1: the responder verifies "that *both* are
        // unrevoked members" — not only the initiator's standing. A
        // red-team review found this was never checked at all in the
        // first version of this function.
        let f = fixture(vec![]);
        let mut body = signed_roster(&f.ids, 1).decode().unwrap();
        body.seq = 1;
        body.revoked = vec![menzil_proto::RevokedMember {
            node_id: f.ids.responder_node_id,
            since: 0,
        }];
        let rosters = RosterStore::new();
        rosters
            .set(&Roster::sign(&f.ids.owner, &body).unwrap())
            .unwrap();

        match decide_responder_admission(
            &f.policies,
            &rosters,
            &f.ids.network_id,
            &f.ids.initiator_node_id,
            &f.ids.initiator_x25519,
            &f.ids.responder_node_id,
            f.ids.responder_cert_serial,
            1_000,
        ) {
            HandshakeAdmission::Refuse {
                reason: ErrorCode::Revoked,
            } => {}
            other => {
                panic!("expected a Revoked refusal for the responder's own standing, got {other:?}")
            }
        }
    }

    fn sample_payload(ids: &Ids, x25519_pub: X25519PublicKey) -> E2eHandshakePayload {
        E2eHandshakePayload {
            v: menzil_proto::PROTOCOL_VERSION,
            node_cert: signed_cert(ids, x25519_pub, 0, 4_000_000_000),
            roster_seq: 1,
            policy_seq: 1,
            e2e_protos: vec![0x01],
        }
    }

    #[test]
    fn initiator_allows_a_matching_valid_payload() {
        let f = fixture(vec![]);
        let payload = sample_payload(&f.ids, f.ids.initiator_x25519);
        assert_eq!(
            decide_initiator_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.initiator_x25519,
                &payload,
                1_000,
            ),
            InitiatorAdmission::Allow
        );
    }

    #[test]
    fn initiator_refuses_when_the_payload_cert_names_a_different_node() {
        let f = fixture(vec![]);
        let payload = sample_payload(&f.ids, f.ids.initiator_x25519);
        let dialed_someone_else = NodeId::from([0x77u8; 32]);
        assert_eq!(
            decide_initiator_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &dialed_someone_else,
                &f.ids.initiator_x25519,
                &payload,
                1_000,
            ),
            InitiatorAdmission::Refuse {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn initiator_refuses_when_the_negotiated_key_does_not_match_the_payload_cert() {
        let f = fixture(vec![]);
        let payload = sample_payload(&f.ids, f.ids.initiator_x25519);
        let different_negotiated_key = X25519PublicKey::from([0x66u8; 32]);
        assert_eq!(
            decide_initiator_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &different_negotiated_key,
                &payload,
                1_000,
            ),
            InitiatorAdmission::Refuse {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn initiator_refuses_a_payload_cert_with_a_forged_self_signature() {
        let f = fixture(vec![]);
        let forger = SigningKey::generate(&mut rand::rng());
        let forged_cert = NodeCert::sign(
            &forger,
            &NodeCertBody {
                v: menzil_proto::PROTOCOL_VERSION,
                node_id: f.ids.initiator_node_id,
                x25519_pub: f.ids.initiator_x25519,
                serial: f.ids.initiator_cert_serial,
                not_before: 0,
                not_after: 4_000_000_000,
            },
        )
        .unwrap();
        let payload = E2eHandshakePayload {
            v: menzil_proto::PROTOCOL_VERSION,
            node_cert: forged_cert,
            roster_seq: 1,
            policy_seq: 1,
            e2e_protos: vec![],
        };
        assert_eq!(
            decide_initiator_admission(
                &f.policies,
                &f.rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.initiator_x25519,
                &payload,
                1_000,
            ),
            InitiatorAdmission::Refuse {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn initiator_refuses_when_its_own_membership_check_on_the_responder_fails() {
        // The payload cert's own validity window is set far beyond the
        // Roster/Policy's `expires`, so this specifically exercises
        // `check_membership`'s own expiry check, not `verify_cert`'s —
        // a red-team review found an earlier version of this test could
        // not tell those two apart (both the cert and the documents
        // were already expired at the chosen `now`, so deleting the
        // `check_membership` call entirely still passed it).
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&ids, 1)).unwrap();
        let far_future_cert = signed_cert(&ids, ids.initiator_x25519, 0, u64::MAX);
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(&ids, vec![far_future_cert.clone()], vec![]))
            .unwrap();
        let payload = E2eHandshakePayload {
            v: menzil_proto::PROTOCOL_VERSION,
            node_cert: far_future_cert,
            roster_seq: 1,
            policy_seq: 1,
            e2e_protos: vec![],
        };

        // Past the Roster/Policy's own `expires` (4_000_000_000, see
        // `signed_roster`/`signed_policy`) but comfortably inside the
        // cert's own validity window.
        let past_roster_policy_expiry = 5_000_000_000;
        match decide_initiator_admission(
            &policies,
            &rosters,
            &ids.network_id,
            &ids.initiator_node_id,
            &ids.initiator_x25519,
            &payload,
            past_roster_policy_expiry,
        ) {
            InitiatorAdmission::Refuse {
                reason: ErrorCode::RosterExpired,
            } => {}
            other => panic!(
                "expected a RosterExpired refusal from check_membership itself, got {other:?}"
            ),
        }
    }

    #[test]
    fn initiator_does_not_trust_a_self_asserted_serial_in_the_payload() {
        // The payload claims a far higher serial than this node's own
        // Policy actually holds for the dialed peer — exactly what a
        // peer whose Ed25519 identity key is compromised could forge
        // (threat-model 2.5). A red-team review demonstrated live that
        // an earlier version of this function trusted this value
        // directly, which would let a revoked peer's still-live old key
        // keep passing serial-floor enforcement indefinitely.
        let f = fixture(vec![]);
        let mut roster_body = signed_roster(&f.ids, 100).decode().unwrap();
        roster_body.seq = 1;
        let rosters = RosterStore::new();
        rosters
            .set(&Roster::sign(&f.ids.owner, &roster_body).unwrap())
            .unwrap();

        let forged_payload_cert = NodeCert::sign(
            &f.ids.initiator_signing_key,
            &NodeCertBody {
                v: menzil_proto::PROTOCOL_VERSION,
                node_id: f.ids.initiator_node_id,
                x25519_pub: f.ids.initiator_x25519,
                serial: 9_999,
                not_before: 0,
                not_after: 4_000_000_000,
            },
        )
        .unwrap();
        let payload = E2eHandshakePayload {
            v: menzil_proto::PROTOCOL_VERSION,
            node_cert: forged_payload_cert,
            roster_seq: 1,
            policy_seq: 1,
            e2e_protos: vec![],
        };

        match decide_initiator_admission(
            &f.policies,
            &rosters,
            &f.ids.network_id,
            &f.ids.initiator_node_id,
            &f.ids.initiator_x25519,
            &payload,
            1_000,
        ) {
            InitiatorAdmission::Refuse {
                reason: ErrorCode::StaleSerial,
            } => {}
            other => panic!(
                "a forged serial 9999 in the payload must not bypass the Roster's real \
                 min_serial (100) via this node's own resolved cert (serial {}): got {other:?}",
                f.ids.initiator_cert_serial
            ),
        }
    }

    fn open_request(ids: &Ids) -> OpenRequest {
        OpenRequest {
            network_id: ids.network_id,
            initiator: ids.initiator_node_id,
            service: "tcp:ssh".parse().unwrap(),
            target: None,
            meta: menzil_proto::OpenMeta::default(),
        }
    }

    #[test]
    fn policy_authorizer_allows_a_granted_service() {
        let f = fixture(vec![]);
        let grant = allowing_grant(&f.ids);
        let cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, 4_000_000_000);
        let mut body = signed_policy(&f.ids, vec![cert], vec![grant])
            .decode()
            .unwrap();
        body.seq = 2;
        let policy = Policy::sign(&f.ids.owner, &body).unwrap();
        assert!(f.policies.set(&policy).unwrap());

        let authorizer = PolicyAuthorizer::new(
            Arc::new(f.policies),
            Arc::new(f.rosters),
            f.ids.network_id,
            f.ids.responder_node_id,
        );
        assert!(matches!(
            authorizer.authorize(&open_request(&f.ids)),
            OpenDecision::Allow
        ));
    }

    #[test]
    fn policy_authorizer_denies_an_ungranted_service() {
        let f = fixture(vec![]);
        // A grant exists, but only for a different service — pins that
        // `authorize` actually narrows by `request.service` (passing
        // `None` instead of `Some(&request.service)` to `has_grant`
        // would wrongly allow this, since a grant for *some* service
        // exists). A red-team review found the previous version of this
        // test, with no grants at all, could not tell that mutation from
        // correct behavior.
        let mut grant = allowing_grant(&f.ids);
        grant.services = vec!["tcp:web".parse().unwrap()];
        let cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, 4_000_000_000);
        let mut body = signed_policy(&f.ids, vec![cert], vec![grant])
            .decode()
            .unwrap();
        body.seq = 2;
        let policy = Policy::sign(&f.ids.owner, &body).unwrap();
        assert!(f.policies.set(&policy).unwrap());

        let authorizer = PolicyAuthorizer::new(
            Arc::new(f.policies),
            Arc::new(f.rosters),
            f.ids.network_id,
            f.ids.responder_node_id,
        );
        match authorizer.authorize(&open_request(&f.ids)) {
            OpenDecision::Deny(refusal) => {
                assert_eq!(refusal.code, ErrorCode::NoGrant);
                assert!(!refusal.msg.is_empty());
            }
            OpenDecision::Allow => panic!("grant is for tcp:web, not tcp:ssh; must be a denial"),
        }
    }

    #[test]
    fn policy_authorizer_denies_a_request_for_a_different_network() {
        let f = fixture(vec![]);
        let authorizer = PolicyAuthorizer::new(
            Arc::new(f.policies),
            Arc::new(f.rosters),
            f.ids.network_id,
            f.ids.responder_node_id,
        );
        let mut request = open_request(&f.ids);
        request.network_id = NetworkId::from([0x11u8; 32]);
        match authorizer.authorize(&request) {
            OpenDecision::Deny(refusal) => assert_eq!(refusal.code, ErrorCode::NoGrant),
            OpenDecision::Allow => panic!("must not evaluate grants for a different network"),
        }
    }
    // --- resolve_dial_cert ---------------------------------------------

    fn cert_with(ids: &Ids, serial: u32, not_before: u64, not_after: u64) -> NodeCert {
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: ids.initiator_node_id,
            x25519_pub: X25519PublicKey::from([serial as u8; 32]),
            serial,
            not_before,
            not_after,
        };
        NodeCert::sign(&ids.initiator_signing_key, &body).unwrap()
    }

    #[test]
    fn dial_resolves_the_members_cert_and_so_the_key_to_dial_with() {
        let f = fixture(vec![]);
        let cert = resolve_dial_cert(
            &f.policies,
            &f.rosters,
            &f.ids.network_id,
            &f.ids.initiator_node_id,
            1_000,
        )
        .expect("a member with a valid cert is dialable");
        assert_eq!(cert.node_id, f.ids.initiator_node_id);
        assert_eq!(cert.x25519_pub, f.ids.initiator_x25519);
        assert_eq!(cert.serial, f.ids.initiator_cert_serial);
    }

    #[test]
    fn dial_prefers_the_highest_serial_among_valid_certs() {
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&ids, 1)).unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &ids,
                vec![
                    cert_with(&ids, 2, 0, 4_000_000_000),
                    cert_with(&ids, 9, 0, 4_000_000_000),
                    cert_with(&ids, 4, 0, 4_000_000_000),
                ],
                vec![],
            ))
            .unwrap();
        let cert = resolve_dial_cert(
            &policies,
            &rosters,
            &ids.network_id,
            &ids.initiator_node_id,
            1_000,
        )
        .unwrap();
        assert_eq!(cert.serial, 9);
    }

    #[test]
    fn dial_skips_certs_below_the_rosters_floor_and_falls_back_to_one_above_it() {
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&ids, 5)).unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &ids,
                vec![
                    cert_with(&ids, 3, 0, 4_000_000_000),
                    cert_with(&ids, 6, 0, 4_000_000_000),
                ],
                vec![],
            ))
            .unwrap();
        let cert = resolve_dial_cert(
            &policies,
            &rosters,
            &ids.network_id,
            &ids.initiator_node_id,
            1_000,
        )
        .expect("serial 6 clears the floor of 5");
        assert_eq!(cert.serial, 6);

        // Only a cert below the floor: nothing to dial.
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &ids,
                vec![cert_with(&ids, 3, 0, 4_000_000_000)],
                vec![],
            ))
            .unwrap();
        assert!(
            resolve_dial_cert(
                &policies,
                &rosters,
                &ids.network_id,
                &ids.initiator_node_id,
                1_000
            )
            .is_none()
        );
    }

    #[test]
    fn dial_skips_an_expired_cert_for_an_older_one_that_is_still_valid() {
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&ids, 1)).unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(
                &ids,
                vec![
                    cert_with(&ids, 2, 0, 4_000_000_000),
                    cert_with(&ids, 7, 0, 500), // expired by `now` = 1_000
                ],
                vec![],
            ))
            .unwrap();
        let cert = resolve_dial_cert(
            &policies,
            &rosters,
            &ids.network_id,
            &ids.initiator_node_id,
            1_000,
        )
        .unwrap();
        assert_eq!(cert.serial, 2);
    }

    #[test]
    fn dial_ignores_a_cert_whose_signature_is_not_the_nodes_own() {
        // A cert claiming the initiator's NodeId but signed by someone
        // else's key: not self-signed, so not that node's cert.
        let ids = fresh_ids();
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&ids, 1)).unwrap();
        let forger = SigningKey::generate(&mut rand::rng());
        let forged_body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: ids.initiator_node_id,
            x25519_pub: X25519PublicKey::from([0xEE; 32]),
            serial: 8,
            not_before: 0,
            not_after: 4_000_000_000,
        };
        let forged = NodeCert::sign(&forger, &forged_body).unwrap();
        let policies = PolicyStore::new();
        policies
            .set(&signed_policy(&ids, vec![forged], vec![]))
            .unwrap();
        assert!(
            resolve_dial_cert(
                &policies,
                &rosters,
                &ids.network_id,
                &ids.initiator_node_id,
                1_000
            )
            .is_none()
        );
    }

    #[test]
    fn dial_finds_nothing_for_a_node_with_no_cert_or_in_a_network_not_held() {
        let f = fixture(vec![]);
        let stranger = NodeId::from([0x77; 32]);
        assert!(
            resolve_dial_cert(&f.policies, &f.rosters, &f.ids.network_id, &stranger, 1_000)
                .is_none()
        );
        let other_network = NetworkId::from([0x11; 32]);
        assert!(
            resolve_dial_cert(
                &f.policies,
                &f.rosters,
                &other_network,
                &f.ids.initiator_node_id,
                1_000
            )
            .is_none()
        );
    }
}
