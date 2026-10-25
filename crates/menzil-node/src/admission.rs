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
//!    The one exception is the `docs_only: true` handshake (TODO.md L4j
//!    S5): a peer the Roster lists as an unrevoked member but the Policy
//!    cannot vouch for completes the handshake and may push documents on
//!    it ([`HandshakeAdmission::DocsOnly`]). The old handshake-time CLOSE
//!    `no_grant` is gone: a member with no grant gets a normal session and
//!    is refused per stream.
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
//! (both then their own TODO.md lines, since fixing either was out of this
//! module's own scope): [`PolicyStore::has_grant`] matched a direct
//! `Principal::Node` grant without checking the Policy's own `members`
//! list, so a node removed from `members` but still named by a leftover
//! direct grant got `NotMember` at handshake time yet `Allow` for the
//! identical service through [`PolicyAuthorizer`]; closed by L4k K2: a
//! direct grant now counts only for a node the Policy lists. And: a
//! *pre-dial* caller had no way to resolve "the cert I should dial with" the
//! way [`resolve_member_cert`] resolves one after the fact from an
//! already-known key; [`resolve_dial_cert`] is that (built with the router,
//! TODO.md L4h6).
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
    E2eHandshakePayload, ErrorCode, NetworkId, NodeCert, NodeCertBody, NodeId, PolicyBody,
    ProtoError, RosterBody, ServiceId, ServiceKind, X25519PublicKey,
};
use menzil_stream::{Authorizer, OpenDecision, OpenRefusal, OpenRequest};

use crate::cert_index::CertIndex;
use crate::policy_store::{PolicyStore, roster_standing};
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

/// This node's own certificate, as the held Policy lists it (protocol.md 5.3: a node ends its
/// sessions when it "no longer is" a member, which includes a certificate there for its own
/// static key): self signed, valid at `now` (so its `not_after` counts), and a serial not below
/// this node's `min_serial` in `roster`. The error is for the local logs.
pub(crate) fn own_cert_standing(
    roster: &RosterBody,
    certs: &CertIndex,
    local: &NodeId,
    local_static: &X25519PublicKey,
    now: u64,
) -> Result<(), ErrorCode> {
    let min_serial = roster_standing(roster, local)?;
    let cert = certs
        .resolve(local, local_static, now)
        .ok_or(ErrorCode::BadCert)?;
    if cert.serial < min_serial {
        return Err(ErrorCode::StaleSerial);
    }
    Ok(())
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
    let view = policies.view(network_id)?;
    view.certs.resolve(node_id, claimed_key, now)
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
    resolve_dial_cert_with(policies, rosters, network_id, node_id, now, true)
}

/// [`resolve_dial_cert`] for a dial whose purpose is `menzil:docs`: the held pair may be past
/// its `expires` (TOBEDECIDED 25), everything else is checked as usual.
pub fn resolve_dial_cert_for_docs(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    node_id: &NodeId,
    now: u64,
) -> Option<NodeCertBody> {
    resolve_dial_cert_with(policies, rosters, network_id, node_id, now, false)
}

fn resolve_dial_cert_with(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    node_id: &NodeId,
    now: u64,
    check_expiry: bool,
) -> Option<NodeCertBody> {
    let view = policies.view(network_id)?;
    view.certs
        .valid_for_node(node_id, now)
        .filter(|body| {
            membership(
                policies,
                rosters,
                network_id,
                node_id,
                body.serial,
                now,
                check_expiry,
            )
            .is_ok()
        })
        .max_by_key(|body| body.serial)
}

/// [`PolicyStore::check_membership`], or without its expiry part.
pub(crate) fn membership(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    node_id: &NodeId,
    cert_serial: u32,
    now: u64,
    check_expiry: bool,
) -> Result<(), ErrorCode> {
    if check_expiry {
        policies.check_membership(rosters, network_id, node_id, cert_serial, now)
    } else {
        policies.check_membership_ignoring_expiry(rosters, network_id, node_id, cert_serial, now)
    }
}

/// Whether an L4 session between this node (`local`, whose NodeCert serial is `local_serial`)
/// and `peer` (whose Noise static key for the session is `peer_static`) may go on in
/// `network_id` at `now`, by the documents held right now (protocol.md 5.3, L4k): the
/// question the live re evaluation asks of every session whenever the Roster or the Policy
/// changes, and that a caller about to reuse a session asks first. Pure and synchronous.
///
/// 1. This node: unrevoked and listed in the Roster, `local_serial` not below its
///    `min_serial`, listed in the Policy `members`, and a certificate for its own static key
///    `local_static` in the Policy `certs` (self signed, valid at `now`, serial not below
///    `min_serial`).
/// 2. The peer: unrevoked and listed in the Roster, listed in the Policy `members`, and a
///    certificate for `peer_static` still in the Policy `certs` (self signed, valid at `now`)
///    with a serial not below the peer's `min_serial`.
///
/// The expiry of the documents is deliberately not asked (TOBEDECIDED 30 T2): expired
/// documents end no session, `has_grant` stops every granted stream on its own, and
/// `menzil:docs` stays usable on the session to fetch the renewal. A network this node holds no
/// Roster and Policy for fails with `UnknownNetwork`. The Roster is read before the Policy, and
/// each only once, so a Roster that revokes the peer ends the session before the Policy that
/// goes with it has arrived (the relay DOC comes first).
///
/// The error is for the caller's logs. Like [`PolicyStore::check_membership`]'s it must not
/// reach the wire: the peer is told one uniform CLOSE `grant_removed` (T1).
// Independent scalars, like `decide_responder_admission`.
#[allow(clippy::too_many_arguments)]
pub fn session_standing(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    peer: &NodeId,
    peer_static: &X25519PublicKey,
    local: &NodeId,
    local_serial: u32,
    local_static: &X25519PublicKey,
    now: u64,
) -> Result<(), ErrorCode> {
    let roster = rosters.body(network_id).ok_or(ErrorCode::UnknownNetwork)?;
    let view = policies.view(network_id).ok_or(ErrorCode::UnknownNetwork)?;
    let policy = &view.body;
    own_standing(
        &roster,
        policy,
        &view.certs,
        local,
        local_serial,
        local_static,
        now,
    )?;

    let peer_min_serial = roster_standing(&roster, peer)?;
    if !policy.members.iter().any(|member| &member.node_id == peer) {
        return Err(ErrorCode::NotMember);
    }
    let cert = view
        .certs
        .resolve(peer, peer_static, now)
        .ok_or(ErrorCode::BadCert)?;
    if cert.serial < peer_min_serial {
        return Err(ErrorCode::StaleSerial);
    }
    Ok(())
}

/// [`session_standing`] for a docs only session (protocol.md 5.1), either role: the Roster
/// alone. Such a session exists because the Policy cannot vouch for one side yet (the peer has
/// no certificate or listing there, or this node's own listing is what the awaited push
/// brings), so asking the Policy would end it the moment it began. What the session must keep
/// is the Roster's word: neither node revoked or unlisted, and this node's cert serial not
/// below its `min_serial` (the peer's serial is not known without a cert: its floor is
/// enforced by the full handshake that follows the push). A network without a Roster is
/// `UnknownNetwork`.
pub fn docs_only_standing(
    rosters: &RosterStore,
    network_id: &NetworkId,
    peer: &NodeId,
    local: &NodeId,
    local_serial: u32,
) -> Result<(), ErrorCode> {
    let roster = rosters.body(network_id).ok_or(ErrorCode::UnknownNetwork)?;
    roster_own_standing(&roster, local, local_serial)?;
    roster_standing(&roster, peer)?;
    Ok(())
}

/// The Roster part of [`own_standing`].
fn roster_own_standing(
    roster: &RosterBody,
    local: &NodeId,
    local_serial: u32,
) -> Result<(), ErrorCode> {
    if local_serial < roster_standing(roster, local)? {
        return Err(ErrorCode::StaleSerial);
    }
    Ok(())
}

/// This node's own standing, the first half of [`session_standing`]: unrevoked and listed in
/// the Roster with `local_serial` not below its `min_serial`, listed in the Policy, and with a
/// certificate there for its own static key `local_static` that is valid at `now` and not below
/// the `min_serial` ([`own_cert_standing`], round 11 N1).
fn own_standing(
    roster: &RosterBody,
    policy: &PolicyBody,
    certs: &CertIndex,
    local: &NodeId,
    local_serial: u32,
    local_static: &X25519PublicKey,
    now: u64,
) -> Result<(), ErrorCode> {
    roster_own_standing(roster, local, local_serial)?;
    if !policy.members.iter().any(|member| &member.node_id == local) {
        return Err(ErrorCode::NotMember);
    }
    own_cert_standing(roster, certs, local, local_static, now)
}

/// What protocol.md 5.1's responder-side checks decide about one just-read
/// `init`, before `resp` is written. See this module's own doc comment, point
/// 1, for why a failed check answers silently rather than on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeAdmission {
    /// Every check passed and a grant exists: complete the handshake
    /// (write `resp`) and proceed normally.
    Allow,
    /// Every check passed but no grant exists for this initiator on this
    /// node (protocol.md 5.1): complete the handshake and install a normal
    /// session. What the peer may open is decided per stream (5.3): every
    /// OPEN but `menzil:docs` is refused `no_grant`.
    AllowNoGrant,
    /// The initiator is an unrevoked member in the held Roster but cannot be
    /// admitted: no certificate in the Policy matches the handshake key, it
    /// is not in the Policy, or the held documents have expired. Complete the
    /// handshake with `docs_only: true` and accept one `menzil:docs` push
    /// (protocol.md 5.1, 5.5). `reason` is for local logs only.
    DocsOnly {
        /// Why the initiator could not be admitted, for local diagnostics.
        reason: ErrorCode,
    },
    /// A revocation, a serial below the floor, or this node's own standing
    /// failed. Never write `resp`. `reason` is for this caller's own local
    /// logs only; it must never reach the wire.
    Refuse {
        /// Why, for local diagnostics only.
        reason: ErrorCode,
    },
}

/// Whether `node_id` is listed in the held Roster of `network_id` and not
/// revoked there, expired or not. This is the cheap check the responder makes
/// on the RECV `src` before any Diffie Hellman (protocol.md 5.1), and the one
/// `menzil:docs` repeats on every OPEN (5.5). Expiry is deliberately not part
/// of it: a member of an expired Roster is exactly who a docs only push is
/// for.
pub fn is_unrevoked_roster_member(
    rosters: &RosterStore,
    network_id: &NetworkId,
    node_id: &NodeId,
) -> bool {
    rosters
        .body(network_id)
        .is_some_and(|roster| roster_standing(&roster, node_id).is_ok())
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
///
/// The order, cheap and decisive first: the initiator's Roster standing (not
/// listed or revoked: refuse); this node's own standing (revoked, not listed
/// or a stale serial: refuse); a resolvable cert below `min_serial` (refuse);
/// then the cases that only cost the initiator a push: expired documents, no
/// cert for the negotiated key, either side missing from the Policy (docs only); then the grant
/// (allow, or allow with no grant).
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
    let (Some(roster), Some(policy)) = (rosters.body(network_id), policies.body(network_id)) else {
        return HandshakeAdmission::Refuse {
            reason: ErrorCode::UnknownNetwork,
        };
    };

    let initiator_min_serial = match roster_standing(&roster, initiator_node_id) {
        Ok(min_serial) => min_serial,
        Err(reason) => return HandshakeAdmission::Refuse { reason },
    };

    match roster_standing(&roster, responder_node_id) {
        Ok(min_serial) if responder_cert_serial >= min_serial => {}
        Ok(_) => {
            return HandshakeAdmission::Refuse {
                reason: ErrorCode::StaleSerial,
            };
        }
        Err(reason) => return HandshakeAdmission::Refuse { reason },
    }

    let cert = resolve_member_cert(
        policies,
        network_id,
        initiator_node_id,
        initiator_static,
        now,
    );
    if let Some(cert) = &cert
        && cert.serial < initiator_min_serial
    {
        return HandshakeAdmission::Refuse {
            reason: ErrorCode::StaleSerial,
        };
    }

    if roster.expires <= now || policy.expires <= now {
        return HandshakeAdmission::DocsOnly {
            reason: ErrorCode::RosterExpired,
        };
    }
    if cert.is_none() {
        return HandshakeAdmission::DocsOnly {
            reason: ErrorCode::BadCert,
        };
    }
    if !policy
        .members
        .iter()
        .any(|member| &member.node_id == initiator_node_id)
    {
        return HandshakeAdmission::DocsOnly {
            reason: ErrorCode::NotMember,
        };
    }
    // A node the Roster lists but its own (older) Policy does not yet: it is
    // the one that needs a push, so it takes one.
    if !policy
        .members
        .iter()
        .any(|member| &member.node_id == responder_node_id)
    {
        return HandshakeAdmission::DocsOnly {
            reason: ErrorCode::NotMember,
        };
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
    decide_initiator_admission_with(
        policies,
        rosters,
        network_id,
        dialed_node_id,
        negotiated_responder_static,
        payload,
        now,
        true,
    )
}

/// [`decide_initiator_admission`] for a dial whose purpose is `menzil:docs`: the held pair may
/// be past its `expires` (TOBEDECIDED 25), everything else is checked as usual.
pub fn decide_initiator_admission_for_docs(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    dialed_node_id: &NodeId,
    negotiated_responder_static: &X25519PublicKey,
    payload: &E2eHandshakePayload,
    now: u64,
) -> InitiatorAdmission {
    decide_initiator_admission_with(
        policies,
        rosters,
        network_id,
        dialed_node_id,
        negotiated_responder_static,
        payload,
        now,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
fn decide_initiator_admission_with(
    policies: &PolicyStore,
    rosters: &RosterStore,
    network_id: &NetworkId,
    dialed_node_id: &NodeId,
    negotiated_responder_static: &X25519PublicKey,
    payload: &E2eHandshakePayload,
    now: u64,
    check_expiry: bool,
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

    match membership(
        policies,
        rosters,
        network_id,
        dialed_node_id,
        own_view.serial,
        now,
        check_expiry,
    ) {
        Ok(()) => InitiatorAdmission::Allow,
        Err(reason) => InitiatorAdmission::Refuse { reason },
    }
}

/// The service id of the documents service (protocol.md 5.5): served by every
/// node, named in no grant.
pub fn docs_service() -> ServiceId {
    ServiceId::new(ServiceKind::Menzil, "docs")
}

/// Whether `service` is `menzil:docs`.
pub fn is_docs_service(service: &ServiceId) -> bool {
    service.kind == ServiceKind::Menzil && service.label == "docs"
}

/// Implements [`menzil_stream::Authorizer`] (protocol.md 5.3's per-OPEN
/// grant check) against this node's held [`PolicyStore`]/[`RosterStore`]
/// — the per-OPEN counterpart to [`decide_responder_admission`]'s
/// handshake-time gate, both reusing `PolicyStore::has_grant`, narrowed
/// here by the OPEN's own `service`. `network_id`/`to_node` are this L4
/// session's own fixed identity (the same two values
/// [`decide_responder_admission`] used to admit it), supplied once at
/// construction: an `Authorizer` is per-session, not global.
///
/// `menzil:docs` is the exception (protocol.md 5.5): it needs no grant, only
/// that the peer is an unrevoked member of the session's network in the held
/// Roster, looked up again on every OPEN so a revocation that arrives
/// mid session stops the next one. On a docs only session
/// ([`Self::docs_only`]) nothing else is allowed at all.
#[derive(Clone)]
pub struct PolicyAuthorizer {
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    network_id: NetworkId,
    to_node: NodeId,
    /// The serial of this node's own NodeCert, for the floor of its own standing.
    to_node_serial: u32,
    /// This node's own static key, for its certificate in the Policy (round 11 N1).
    to_node_static: X25519PublicKey,
    docs_only: bool,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl PolicyAuthorizer {
    /// Builds an authorizer for one L4 session on `network_id`, where
    /// `to_node` (this node's own identity, its NodeCert's serial being
    /// `to_node_serial`) is the grant's target. Every OPEN is refused while this
    /// node's own standing fails (see [`session_standing`], part 1): a node that is
    /// revoked, no longer listed or below its `min_serial` serves nothing, for it
    /// cannot vouch for the documents of a network that dropped it.
    pub fn new(
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        network_id: NetworkId,
        to_node: NodeId,
        to_node_serial: u32,
        to_node_static: X25519PublicKey,
    ) -> Self {
        Self {
            policies,
            rosters,
            network_id,
            to_node,
            to_node_serial,
            to_node_static,
            docs_only: false,
        }
    }

    /// Narrows this authorizer to a docs only session (protocol.md 5.1):
    /// `menzil:docs` for a Roster member, and every other service refused.
    pub fn docs_only(mut self) -> Self {
        self.docs_only = true;
        self
    }

    /// Whether this node is still a member in good standing by the documents held now. Reads
    /// the Roster and the Policy once each, like [`session_standing`].
    fn own_standing_holds(&self) -> bool {
        // A docs only session is for a node whose own Policy listing may be what the push
        // brings (TODO.md, K2 edge cases): its own standing is the Roster's.
        if self.docs_only {
            return self.rosters.body(&self.network_id).is_some_and(|roster| {
                roster_own_standing(&roster, &self.to_node, self.to_node_serial).is_ok()
            });
        }
        match (
            self.rosters.body(&self.network_id),
            self.policies.view(&self.network_id),
        ) {
            (Some(roster), Some(view)) => own_standing(
                &roster,
                &view.body,
                &view.certs,
                &self.to_node,
                self.to_node_serial,
                &self.to_node_static,
                unix_now(),
            )
            .is_ok(),
            _ => false,
        }
    }

    fn no_grant() -> OpenDecision {
        OpenDecision::Deny(OpenRefusal {
            code: ErrorCode::NoGrant,
            msg: "no grant".to_string(),
        })
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
            return Self::no_grant();
        }
        // This node's own standing, before any service (`menzil:docs` included): checked on
        // every OPEN, so a revocation of this node that arrives mid session stops the next one.
        if !self.own_standing_holds() {
            return Self::no_grant();
        }
        if is_docs_service(&request.service) {
            return if is_unrevoked_roster_member(
                &self.rosters,
                &self.network_id,
                &request.initiator,
            ) {
                OpenDecision::Allow
            } else {
                Self::no_grant()
            };
        }
        if self.docs_only {
            return Self::no_grant();
        }
        let now = unix_now();
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
            Self::no_grant()
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
        responder_signing_key: SigningKey,
        responder_node_id: NodeId,
        responder_x25519: X25519PublicKey,
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
        // A real identity: its certificate in the Policy is part of its own standing.
        let responder_signing_key = SigningKey::generate(&mut rand::rng());
        let responder_node_id = NodeId::from(responder_signing_key.verifying_key().to_bytes());
        let responder_x25519 = X25519PublicKey::from([0x43u8; 32]);
        Ids {
            owner,
            network_id,
            initiator_signing_key,
            initiator_node_id,
            initiator_x25519,
            initiator_cert_serial: 3,
            responder_signing_key,
            responder_node_id,
            responder_x25519,
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

    /// The responder's own certificate (serial `responder_cert_serial`).
    fn responder_cert(ids: &Ids) -> NodeCert {
        NodeCert::sign(
            &ids.responder_signing_key,
            &NodeCertBody {
                v: menzil_proto::PROTOCOL_VERSION,
                node_id: ids.responder_node_id,
                x25519_pub: ids.responder_x25519,
                serial: ids.responder_cert_serial,
                not_before: 0,
                not_after: 4_000_000_000,
            },
        )
        .unwrap()
    }

    /// A Policy listing both parties, with `certs` and, always, the responder's own
    /// certificate.
    fn signed_policy(ids: &Ids, mut certs: Vec<NodeCert>, grants: Vec<Grant>) -> Policy {
        certs.push(responder_cert(ids));
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
    fn responder_admits_a_member_with_no_grant_as_a_normal_session() {
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
    fn responder_answers_docs_only_when_no_cert_matches_the_negotiated_key() {
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
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn responder_answers_docs_only_when_only_a_different_members_cert_matches_the_key() {
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
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::BadCert
            },
            "mallory's cert matches the key but not initiator_node_id; it must not be used"
        );
    }

    #[test]
    fn responder_answers_docs_only_when_the_cert_self_signature_is_forged() {
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
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::BadCert
            }
        );
    }

    #[test]
    fn responder_answers_docs_only_when_the_matching_cert_has_expired() {
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
            HandshakeAdmission::DocsOnly {
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
            docs_only: false,
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
            docs_only: false,
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
            docs_only: false,
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
            docs_only: false,
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
            f.ids.responder_cert_serial,
            f.ids.responder_x25519,
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
            f.ids.responder_cert_serial,
            f.ids.responder_x25519,
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
            f.ids.responder_cert_serial,
            f.ids.responder_x25519,
        );
        let mut request = open_request(&f.ids);
        request.network_id = NetworkId::from([0x11u8; 32]);
        match authorizer.authorize(&request) {
            OpenDecision::Deny(refusal) => assert_eq!(refusal.code, ErrorCode::NoGrant),
            OpenDecision::Allow => panic!("must not evaluate grants for a different network"),
        }
    }
    // --- docs only admission, the docs exemption (protocol.md 5.1, 5.5) ----

    /// Replaces the fixture's Roster by `edit` of it at the next seq.
    fn edit_roster(f: &Fixture, edit: impl FnOnce(&mut menzil_proto::RosterBody)) {
        let mut body = f.rosters.body(&f.ids.network_id).unwrap().as_ref().clone();
        body.seq += 1;
        edit(&mut body);
        assert!(
            f.rosters
                .set(&Roster::sign(&f.ids.owner, &body).unwrap())
                .unwrap()
        );
    }

    /// Replaces the fixture's Policy by `edit` of it at the next seq.
    fn edit_policy(f: &Fixture, edit: impl FnOnce(&mut menzil_proto::PolicyBody)) {
        let mut body = f.policies.body(&f.ids.network_id).unwrap().as_ref().clone();
        body.seq += 1;
        edit(&mut body);
        assert!(
            f.policies
                .set(&Policy::sign(&f.ids.owner, &body).unwrap())
                .unwrap()
        );
    }

    fn admit(f: &Fixture, now: u64) -> HandshakeAdmission {
        decide_responder_admission(
            &f.policies,
            &f.rosters,
            &f.ids.network_id,
            &f.ids.initiator_node_id,
            &f.ids.initiator_x25519,
            &f.ids.responder_node_id,
            f.ids.responder_cert_serial,
            now,
        )
    }

    #[test]
    fn responder_refuses_a_revoked_initiator_even_with_a_cert_and_a_grant() {
        let f = fixture(vec![]);
        let grant = allowing_grant(&f.ids);
        edit_policy(&f, |body| body.grants = vec![grant]);
        edit_roster(&f, |body| {
            body.revoked = vec![menzil_proto::RevokedMember {
                node_id: f.ids.initiator_node_id,
                since: 0,
            }];
        });
        assert_eq!(
            admit(&f, 1_000),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::Revoked
            }
        );
    }

    #[test]
    fn responder_refuses_an_initiator_the_roster_does_not_list() {
        let f = fixture(vec![]);
        edit_roster(&f, |body| {
            body.members
                .retain(|member| member.node_id != f.ids.initiator_node_id);
        });
        assert_eq!(
            admit(&f, 1_000),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::NotMember
            }
        );
    }

    #[test]
    fn responder_answers_docs_only_when_the_policy_does_not_list_the_initiator() {
        let f = fixture(vec![]);
        edit_policy(&f, |body| {
            body.members
                .retain(|member| member.node_id != f.ids.initiator_node_id);
        });
        assert_eq!(
            admit(&f, 1_000),
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::NotMember
            }
        );
    }

    #[test]
    fn responder_answers_docs_only_when_the_policy_does_not_list_itself() {
        let f = fixture(vec![]);
        edit_policy(&f, |body| {
            body.members
                .retain(|member| member.node_id != f.ids.responder_node_id);
        });
        assert_eq!(
            admit(&f, 1_000),
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::NotMember
            }
        );
    }

    #[test]
    fn responder_answers_docs_only_once_its_documents_have_expired() {
        let f = fixture(vec![]);
        // A cert that outlives the documents, so that expiry is the only thing wrong.
        let cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, u64::MAX);
        edit_policy(&f, |body| body.certs = vec![cert]);
        assert_eq!(admit(&f, 3_999_999_999), HandshakeAdmission::AllowNoGrant);
        assert_eq!(
            admit(&f, 4_000_000_000),
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::RosterExpired
            }
        );
    }

    #[test]
    fn responder_answers_docs_only_when_only_the_roster_has_expired() {
        let f = fixture(vec![]);
        let cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, u64::MAX);
        edit_policy(&f, |body| {
            body.certs = vec![cert];
            body.expires = 9_000_000_000;
        });
        assert_eq!(
            admit(&f, 4_000_000_001),
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::RosterExpired
            }
        );
    }

    #[test]
    fn responder_answers_docs_only_when_only_the_policy_has_expired() {
        let f = fixture(vec![]);
        let cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, u64::MAX);
        edit_roster(&f, |body| body.expires = 9_000_000_000);
        edit_policy(&f, |body| body.certs = vec![cert]);
        assert_eq!(
            admit(&f, 4_000_000_001),
            HandshakeAdmission::DocsOnly {
                reason: ErrorCode::RosterExpired
            }
        );
    }

    #[test]
    fn responder_still_refuses_a_stale_serial_or_a_revoked_self_when_the_documents_expired() {
        let f = fixture(vec![]);
        let cert = signed_cert(&f.ids, f.ids.initiator_x25519, 0, u64::MAX);
        edit_policy(&f, |body| body.certs = vec![cert]);
        edit_roster(&f, |body| {
            for member in &mut body.members {
                if member.node_id == f.ids.initiator_node_id {
                    member.min_serial = 100;
                }
            }
        });
        assert_eq!(
            admit(&f, 5_000_000_000),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::StaleSerial
            },
            "a certificate below the floor is refused whether or not the documents expired"
        );
        edit_roster(&f, |body| {
            for member in &mut body.members {
                member.min_serial = 1;
            }
            body.revoked = vec![menzil_proto::RevokedMember {
                node_id: f.ids.responder_node_id,
                since: 0,
            }];
        });
        assert_eq!(
            admit(&f, 5_000_000_000),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::Revoked
            },
            "a node that was revoked itself serves nobody, expired documents or not"
        );
    }

    #[test]
    fn responder_refuses_when_its_own_cert_serial_is_below_the_floor() {
        let f = fixture(vec![]);
        edit_roster(&f, |body| {
            for member in &mut body.members {
                if member.node_id == f.ids.responder_node_id {
                    member.min_serial = f.ids.responder_cert_serial + 1;
                }
            }
        });
        assert_eq!(
            admit(&f, 1_000),
            HandshakeAdmission::Refuse {
                reason: ErrorCode::StaleSerial
            }
        );
    }

    #[test]
    fn the_roster_member_check_ignores_expiry_and_refuses_revoked_and_unlisted() {
        let f = fixture(vec![]);
        let network = f.ids.network_id;
        assert!(is_unrevoked_roster_member(
            &f.rosters,
            &network,
            &f.ids.initiator_node_id
        ));
        assert!(!is_unrevoked_roster_member(
            &f.rosters,
            &network,
            &NodeId::from([0x77; 32])
        ));
        assert!(!is_unrevoked_roster_member(
            &f.rosters,
            &NetworkId::from([0x11; 32]),
            &f.ids.initiator_node_id
        ));
        edit_roster(&f, |body| {
            body.expires = 1;
            body.revoked = vec![menzil_proto::RevokedMember {
                node_id: f.ids.responder_node_id,
                since: 0,
            }];
        });
        assert!(
            is_unrevoked_roster_member(&f.rosters, &network, &f.ids.initiator_node_id),
            "an expired Roster still lists its unrevoked members"
        );
        assert!(!is_unrevoked_roster_member(
            &f.rosters,
            &network,
            &f.ids.responder_node_id
        ));
    }

    fn docs_request(ids: &Ids) -> OpenRequest {
        OpenRequest {
            service: docs_service(),
            ..open_request(ids)
        }
    }

    fn authorizer_of(f: &Fixture) -> (PolicyAuthorizer, Arc<RosterStore>, Arc<PolicyStore>) {
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&signed_roster(&f.ids, 1)).unwrap();
        let policies = Arc::new(PolicyStore::new());
        policies
            .set(&f.policies.get(&f.ids.network_id).unwrap())
            .unwrap();
        (
            PolicyAuthorizer::new(
                policies.clone(),
                rosters.clone(),
                f.ids.network_id,
                f.ids.responder_node_id,
                f.ids.responder_cert_serial,
                f.ids.responder_x25519,
            ),
            rosters,
            policies,
        )
    }

    #[test]
    fn docs_needs_no_grant_only_an_unrevoked_roster_member() {
        let f = fixture(vec![]);
        let (authorizer, rosters, _) = authorizer_of(&f);
        // No grant at all, so tcp:ssh is refused and menzil:docs is not.
        assert!(matches!(
            authorizer.authorize(&open_request(&f.ids)),
            OpenDecision::Deny(_)
        ));
        assert!(matches!(
            authorizer.authorize(&docs_request(&f.ids)),
            OpenDecision::Allow
        ));
        // Revoked in a Roster that arrives mid session: the next OPEN is refused.
        let mut body = rosters.body(&f.ids.network_id).unwrap().as_ref().clone();
        body.seq += 1;
        body.revoked = vec![menzil_proto::RevokedMember {
            node_id: f.ids.initiator_node_id,
            since: 0,
        }];
        rosters
            .set(&Roster::sign(&f.ids.owner, &body).unwrap())
            .unwrap();
        match authorizer.authorize(&docs_request(&f.ids)) {
            OpenDecision::Deny(refusal) => assert_eq!(refusal.code, ErrorCode::NoGrant),
            OpenDecision::Allow => panic!("a peer revoked mid session must be refused"),
        }
    }

    #[test]
    fn docs_is_refused_to_a_peer_the_roster_does_not_list() {
        let f = fixture(vec![]);
        let (authorizer, _, _) = authorizer_of(&f);
        let mut request = docs_request(&f.ids);
        request.initiator = NodeId::from([0x77; 32]);
        assert!(matches!(
            authorizer.authorize(&request),
            OpenDecision::Deny(_)
        ));
    }

    #[test]
    fn docs_is_served_from_an_expired_roster_to_its_unrevoked_members() {
        // The check is about standing, not freshness: a docs only push into an expired node is
        // what revives a network.
        let f = fixture(vec![]);
        let (authorizer, rosters, _) = authorizer_of(&f);
        let mut body = rosters.body(&f.ids.network_id).unwrap().as_ref().clone();
        body.seq += 1;
        body.expires = 1;
        rosters
            .set(&Roster::sign(&f.ids.owner, &body).unwrap())
            .unwrap();
        assert!(matches!(
            authorizer.authorize(&docs_request(&f.ids)),
            OpenDecision::Allow
        ));
    }

    #[test]
    fn a_docs_only_authorizer_serves_docs_and_nothing_a_grant_would_allow() {
        let f = fixture(vec![]);
        let grant = allowing_grant(&f.ids);
        edit_policy(&f, |body| body.grants = vec![grant]);
        let (full, _, _) = authorizer_of(&f);
        assert!(matches!(
            full.authorize(&open_request(&f.ids)),
            OpenDecision::Allow
        ));
        let narrowed = full.docs_only();
        match narrowed.authorize(&open_request(&f.ids)) {
            OpenDecision::Deny(refusal) => assert_eq!(refusal.code, ErrorCode::NoGrant),
            OpenDecision::Allow => panic!("a docs only session serves nothing but menzil:docs"),
        }
        assert!(matches!(
            narrowed.authorize(&docs_request(&f.ids)),
            OpenDecision::Allow
        ));
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

    // --- L4k: session_standing and the authorizer's own standing -----------------------------

    /// `session_standing` for the fixture's pair: the initiator is the peer (its cert is in the
    /// Policy for `initiator_x25519`, serial 3), the responder is this node (serial 5).
    fn standing(f: &Fixture, now: u64) -> Result<(), ErrorCode> {
        session_standing(
            &f.policies,
            &f.rosters,
            &f.ids.network_id,
            &f.ids.initiator_node_id,
            &f.ids.initiator_x25519,
            &f.ids.responder_node_id,
            f.ids.responder_cert_serial,
            &f.ids.responder_x25519,
            now,
        )
    }

    fn revoked(who: NodeId) -> menzil_proto::RevokedMember {
        menzil_proto::RevokedMember {
            node_id: who,
            since: 0,
        }
    }

    /// The responder's certificate, changed by `edit` and signed again.
    fn own_cert_with(ids: &Ids, edit: impl FnOnce(&mut NodeCertBody)) -> NodeCert {
        let mut body = responder_cert(ids).decode().unwrap();
        edit(&mut body);
        NodeCert::sign(&ids.responder_signing_key, &body).unwrap()
    }

    /// Round 11 N1 (protocol.md 5.3): this node's own certificate in the Policy, for its own
    /// static key, valid at `now` and not below its `min_serial`, is part of its standing.
    #[test]
    fn session_standing_needs_this_nodes_own_certificate_in_the_policy() {
        type Case = (&'static str, fn(&Fixture), ErrorCode);
        let cases: [Case; 4] = [
            (
                "gone from the Policy",
                |f| {
                    edit_policy(f, |b| {
                        b.certs
                            .retain(|c| c.decode().unwrap().node_id != f.ids.responder_node_id);
                    })
                },
                ErrorCode::BadCert,
            ),
            (
                "for another static key",
                |f| {
                    edit_policy(f, |b| {
                        b.certs
                            .retain(|c| c.decode().unwrap().node_id != f.ids.responder_node_id);
                        b.certs.push(own_cert_with(&f.ids, |c| {
                            c.x25519_pub = X25519PublicKey::from([0x44u8; 32]);
                        }));
                    })
                },
                ErrorCode::BadCert,
            ),
            (
                "run out (the peer's is still valid)",
                |f| {
                    edit_policy(f, |b| {
                        b.certs
                            .retain(|c| c.decode().unwrap().node_id != f.ids.responder_node_id);
                        b.certs.push(own_cert_with(&f.ids, |c| c.not_after = 500));
                    })
                },
                ErrorCode::BadCert,
            ),
            (
                "below the min_serial although the node's own serial is not",
                |f| {
                    edit_policy(f, |b| {
                        b.certs
                            .retain(|c| c.decode().unwrap().node_id != f.ids.responder_node_id);
                        b.certs.push(own_cert_with(&f.ids, |c| c.serial = 2));
                    });
                    edit_roster(f, |b| {
                        for m in &mut b.members {
                            if m.node_id == f.ids.responder_node_id {
                                m.min_serial = 3;
                            }
                        }
                    });
                },
                ErrorCode::StaleSerial,
            ),
        ];
        for (label, change, expected) in cases {
            let f = fixture(vec![]);
            assert_eq!(standing(&f, 1_000), Ok(()), "{label}: before");
            change(&f);
            assert_eq!(standing(&f, 1_000), Err(expected), "{label}");
        }
        // Valid until `not_after` itself, gone the second after.
        let f = fixture(vec![]);
        edit_policy(&f, |b| {
            b.certs
                .retain(|c| c.decode().unwrap().node_id != f.ids.responder_node_id);
            b.certs.push(own_cert_with(&f.ids, |c| c.not_after = 1_000));
        });
        assert_eq!(standing(&f, 1_000), Ok(()));
        assert_eq!(standing(&f, 1_001), Err(ErrorCode::BadCert));
    }

    #[test]
    fn session_standing_holds_for_two_members_in_good_standing() {
        let f = fixture(vec![]);
        assert_eq!(standing(&f, 1_000), Ok(()));
    }

    #[test]
    fn session_standing_fails_for_the_peer_in_each_way_it_can_lose_it() {
        type Case = (&'static str, fn(&Fixture), ErrorCode);
        let cases: [Case; 6] = [
            // The Roster alone: the Policy still lists the peer, its cert and a grant (the
            // relay DOC with the revocation arrives before the Policy does).
            (
                "revoked in the Roster",
                |f| {
                    edit_roster(f, |b| {
                        let who = f.ids.initiator_node_id;
                        b.revoked.push(revoked(who));
                    })
                },
                ErrorCode::Revoked,
            ),
            (
                "dropped from the Roster",
                |f| {
                    edit_roster(f, |b| {
                        b.members.retain(|m| m.node_id != f.ids.initiator_node_id);
                    })
                },
                ErrorCode::NotMember,
            ),
            (
                "dropped from the Policy",
                |f| {
                    edit_policy(f, |b| {
                        b.members.retain(|m| m.node_id != f.ids.initiator_node_id);
                    })
                },
                ErrorCode::NotMember,
            ),
            (
                "its cert gone from the Policy",
                |f| edit_policy(f, |b| b.certs.clear()),
                ErrorCode::BadCert,
            ),
            (
                "min_serial raised above the session cert",
                |f| {
                    edit_roster(f, |b| {
                        for m in &mut b.members {
                            if m.node_id == f.ids.initiator_node_id {
                                m.min_serial = f.ids.initiator_cert_serial + 1;
                            }
                        }
                    })
                },
                ErrorCode::StaleSerial,
            ),
            (
                "the cert of the session key replaced by one for another key",
                |f| {
                    let other = signed_cert(
                        &f.ids,
                        X25519PublicKey::from([0x43u8; 32]),
                        0,
                        4_000_000_000,
                    );
                    edit_policy(f, |b| b.certs = vec![other])
                },
                ErrorCode::BadCert,
            ),
        ];
        for (label, change, expected) in cases {
            let f = fixture(vec![]);
            assert_eq!(standing(&f, 1_000), Ok(()), "{label}: before");
            change(&f);
            assert_eq!(standing(&f, 1_000), Err(expected), "{label}");
        }
    }

    #[test]
    fn session_standing_fails_when_the_peers_cert_has_expired_and_the_documents_have_not() {
        let f = fixture(vec![]);
        // The cert is valid until 4_000_000_000; the documents are made to outlive it.
        edit_roster(&f, |b| b.expires = 5_000_000_000);
        edit_policy(&f, |b| b.expires = 5_000_000_000);
        assert_eq!(standing(&f, 3_999_999_999), Ok(()));
        assert_eq!(standing(&f, 4_000_000_001), Err(ErrorCode::BadCert));
    }

    #[test]
    fn session_standing_equal_to_the_min_serial_passes() {
        let f = fixture(vec![]);
        edit_roster(&f, |b| {
            for m in &mut b.members {
                m.min_serial = if m.node_id == f.ids.initiator_node_id {
                    f.ids.initiator_cert_serial
                } else {
                    f.ids.responder_cert_serial
                };
            }
        });
        assert_eq!(standing(&f, 1_000), Ok(()));
    }

    #[test]
    fn session_standing_fails_for_this_node_in_each_way_it_can_lose_it() {
        type Case = (&'static str, fn(&Fixture), ErrorCode);
        let cases: [Case; 4] = [
            (
                "revoked in the Roster",
                |f| {
                    edit_roster(f, |b| {
                        let who = f.ids.responder_node_id;
                        b.revoked.push(revoked(who));
                    })
                },
                ErrorCode::Revoked,
            ),
            (
                "dropped from the Roster",
                |f| {
                    edit_roster(f, |b| {
                        b.members.retain(|m| m.node_id != f.ids.responder_node_id);
                    })
                },
                ErrorCode::NotMember,
            ),
            (
                "dropped from the Policy",
                |f| {
                    edit_policy(f, |b| {
                        b.members.retain(|m| m.node_id != f.ids.responder_node_id);
                    })
                },
                ErrorCode::NotMember,
            ),
            (
                "min_serial raised above its own cert",
                |f| {
                    edit_roster(f, |b| {
                        for m in &mut b.members {
                            if m.node_id == f.ids.responder_node_id {
                                m.min_serial = f.ids.responder_cert_serial + 1;
                            }
                        }
                    })
                },
                ErrorCode::StaleSerial,
            ),
        ];
        for (label, change, expected) in cases {
            let f = fixture(vec![]);
            assert_eq!(standing(&f, 1_000), Ok(()), "{label}: before");
            change(&f);
            assert_eq!(standing(&f, 1_000), Err(expected), "{label}");
        }
        // And exactly at its floor it still holds.
        let f = fixture(vec![]);
        edit_roster(&f, |b| {
            for m in &mut b.members {
                if m.node_id == f.ids.responder_node_id {
                    m.min_serial = f.ids.responder_cert_serial;
                }
            }
        });
        assert_eq!(standing(&f, 1_000), Ok(()));
    }

    /// TOBEDECIDED 30 T2: documents that expire end no session.
    #[test]
    fn session_standing_ignores_the_expiry_of_the_documents() {
        let f = fixture(vec![]);
        edit_roster(&f, |b| b.expires = 1_500);
        edit_policy(&f, |b| b.expires = 1_500);
        assert_eq!(standing(&f, 1_000), Ok(()));
        assert_eq!(standing(&f, 2_000), Ok(()), "both documents expired");
    }

    #[test]
    fn session_standing_of_a_network_not_held_or_half_held_is_unknown() {
        let f = fixture(vec![]);
        let call = |policies: &PolicyStore, rosters: &RosterStore, network: &NetworkId| {
            session_standing(
                policies,
                rosters,
                network,
                &f.ids.initiator_node_id,
                &f.ids.initiator_x25519,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
                &f.ids.responder_x25519,
                1_000,
            )
        };
        let other = NetworkId::from([0x11; 32]);
        assert_eq!(
            call(&f.policies, &f.rosters, &other),
            Err(ErrorCode::UnknownNetwork)
        );
        assert_eq!(
            call(&PolicyStore::new(), &f.rosters, &f.ids.network_id),
            Err(ErrorCode::UnknownNetwork)
        );
        assert_eq!(
            call(&f.policies, &RosterStore::new(), &f.ids.network_id),
            Err(ErrorCode::UnknownNetwork)
        );
    }

    fn edit_roster_in(ids: &Ids, rosters: &RosterStore, edit: impl FnOnce(&mut RosterBody)) {
        let mut body = rosters.body(&ids.network_id).unwrap().as_ref().clone();
        body.seq += 1;
        edit(&mut body);
        assert!(
            rosters
                .set(&Roster::sign(&ids.owner, &body).unwrap())
                .unwrap()
        );
    }

    fn edit_policy_in(ids: &Ids, policies: &PolicyStore, edit: impl FnOnce(&mut PolicyBody)) {
        let mut body = policies.body(&ids.network_id).unwrap().as_ref().clone();
        body.seq += 1;
        edit(&mut body);
        assert!(
            policies
                .set(&Policy::sign(&ids.owner, &body).unwrap())
                .unwrap()
        );
    }

    /// T13, TODO.md "A node's own standing is checked when it dials and when it answers, not per
    /// OPEN": the authorizer of a session refuses every OPEN, `menzil:docs` included, once this
    /// node itself is no longer a member in good standing, and it looks on every OPEN.
    #[test]
    fn the_authorizer_refuses_everything_once_this_node_has_lost_its_own_standing() {
        type Case = (&'static str, fn(&Ids, &RosterStore, &PolicyStore));
        let cases: [Case; 6] = [
            ("revoked", |ids, rosters, _| {
                edit_roster_in(ids, rosters, |b| {
                    b.revoked.push(revoked(ids.responder_node_id));
                })
            }),
            ("dropped from the Roster", |ids, rosters, _| {
                edit_roster_in(ids, rosters, |b| {
                    b.members.retain(|m| m.node_id != ids.responder_node_id);
                })
            }),
            ("min_serial above its cert", |ids, rosters, _| {
                edit_roster_in(ids, rosters, |b| {
                    for m in &mut b.members {
                        if m.node_id == ids.responder_node_id {
                            m.min_serial = ids.responder_cert_serial + 1;
                        }
                    }
                })
            }),
            ("dropped from the Policy", |ids, _, policies| {
                edit_policy_in(ids, policies, |b| {
                    b.members.retain(|m| m.node_id != ids.responder_node_id);
                })
            }),
            (
                "its certificate gone from the Policy",
                |ids, _, policies| {
                    edit_policy_in(ids, policies, |b| {
                        b.certs
                            .retain(|c| c.decode().unwrap().node_id != ids.responder_node_id);
                    })
                },
            ),
            (
                "its certificate in the Policy has run out",
                |ids, _, policies| {
                    edit_policy_in(ids, policies, |b| {
                        b.certs
                            .retain(|c| c.decode().unwrap().node_id != ids.responder_node_id);
                        b.certs.push(own_cert_with(ids, |c| c.not_after = 1_000));
                    })
                },
            ),
        ];
        for (label, change) in cases {
            let f = fixture(vec![]);
            let grant = allowing_grant(&f.ids);
            edit_policy(&f, |body| body.grants = vec![grant]);
            let (authorizer, rosters, policies) = authorizer_of(&f);
            let allowed = |request: &OpenRequest| {
                matches!(authorizer.authorize(request), OpenDecision::Allow)
            };
            assert!(allowed(&open_request(&f.ids)), "{label}: granted, before");
            assert!(allowed(&docs_request(&f.ids)), "{label}: docs, before");
            change(&f.ids, &rosters, &policies);
            for (what, request) in [
                ("a granted service", open_request(&f.ids)),
                ("menzil:docs", docs_request(&f.ids)),
            ] {
                match authorizer.authorize(&request) {
                    OpenDecision::Deny(refusal) => {
                        assert_eq!(refusal.code, ErrorCode::NoGrant, "{label}: {what}")
                    }
                    OpenDecision::Allow => panic!("{label}: {what} must be refused"),
                }
            }
        }
    }

    /// The same floor, exactly met: a node whose cert serial equals its `min_serial` serves.
    #[test]
    fn the_authorizer_serves_a_node_whose_serial_equals_its_floor() {
        let f = fixture(vec![]);
        let (authorizer, rosters, _) = authorizer_of(&f);
        edit_roster_in(&f.ids, &rosters, |b| {
            for m in &mut b.members {
                if m.node_id == f.ids.responder_node_id {
                    m.min_serial = f.ids.responder_cert_serial;
                }
            }
        });
        assert!(matches!(
            authorizer.authorize(&docs_request(&f.ids)),
            OpenDecision::Allow
        ));
    }

    // --- docs only standing (L4k K4) ------------------------------------

    /// A docs only session is judged by the Roster alone: neither the peer's missing cert or
    /// Policy listing nor this node's own missing Policy listing is a reason to end it.
    #[test]
    fn docs_only_standing_is_the_rosters_word_and_only_the_rosters() {
        let call = |f: &Fixture, rosters: &RosterStore| {
            docs_only_standing(
                rosters,
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
            )
        };
        let f = fixture(vec![]);
        assert_eq!(call(&f, &f.rosters), Ok(()));

        // Nothing the Policy says matters: no peer cert, nobody listed.
        edit_policy_in(&f.ids, &f.policies, |b| {
            b.certs.clear();
            b.members.clear();
        });
        assert_eq!(call(&f, &f.rosters), Ok(()));

        type Case = (&'static str, fn(&Ids, &RosterStore), ErrorCode);
        let cases: [Case; 5] = [
            (
                "the peer is revoked",
                |ids, rosters| {
                    edit_roster_in(ids, rosters, |b| {
                        b.revoked.push(revoked(ids.initiator_node_id));
                    })
                },
                ErrorCode::Revoked,
            ),
            (
                "the peer is no longer listed",
                |ids, rosters| {
                    edit_roster_in(ids, rosters, |b| {
                        b.members.retain(|m| m.node_id != ids.initiator_node_id);
                    })
                },
                ErrorCode::NotMember,
            ),
            (
                "this node is revoked",
                |ids, rosters| {
                    edit_roster_in(ids, rosters, |b| {
                        b.revoked.push(revoked(ids.responder_node_id));
                    })
                },
                ErrorCode::Revoked,
            ),
            (
                "this node is no longer listed",
                |ids, rosters| {
                    edit_roster_in(ids, rosters, |b| {
                        b.members.retain(|m| m.node_id != ids.responder_node_id);
                    })
                },
                ErrorCode::NotMember,
            ),
            (
                "this node's min_serial is above its cert",
                |ids, rosters| {
                    edit_roster_in(ids, rosters, |b| {
                        for m in &mut b.members {
                            if m.node_id == ids.responder_node_id {
                                m.min_serial = ids.responder_cert_serial + 1;
                            }
                        }
                    })
                },
                ErrorCode::StaleSerial,
            ),
        ];
        for (label, change, expected) in cases {
            let f = fixture(vec![]);
            change(&f.ids, &f.rosters);
            assert_eq!(call(&f, &f.rosters), Err(expected), "{label}");
        }
        assert_eq!(
            docs_only_standing(
                &RosterStore::new(),
                &f.ids.network_id,
                &f.ids.initiator_node_id,
                &f.ids.responder_node_id,
                f.ids.responder_cert_serial,
            ),
            Err(ErrorCode::UnknownNetwork)
        );
    }

    /// The window a docs only session is for: this node is in the Roster and not yet in its
    /// older Policy. The push that brings the Policy must be taken, so the docs only
    /// authorizer asks the Roster for this node's own standing; a revoked node still serves
    /// nothing.
    #[test]
    fn a_docs_only_authorizer_takes_a_push_before_this_node_is_in_its_policy() {
        let f = fixture(vec![]);
        let (full, rosters, policies) = authorizer_of(&f);
        let narrowed = full.clone().docs_only();
        edit_policy_in(&f.ids, &policies, |b| {
            b.members.retain(|m| m.node_id != f.ids.responder_node_id);
        });
        assert!(matches!(
            full.authorize(&docs_request(&f.ids)),
            OpenDecision::Deny(_)
        ));
        assert!(matches!(
            narrowed.authorize(&docs_request(&f.ids)),
            OpenDecision::Allow
        ));
        edit_roster_in(&f.ids, &rosters, |b| {
            b.revoked.push(revoked(f.ids.responder_node_id));
        });
        assert!(matches!(
            narrowed.authorize(&docs_request(&f.ids)),
            OpenDecision::Deny(_)
        ));
    }
}
