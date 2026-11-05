//! Roster DOC propagation (protocol.md 4.3; TODO.md L3f): "A node sends
//! DOC(roster) to a relay when it holds a newer Roster than the relay's
//! WELCOME `rosters` shows; a relay sends DOC(roster) to attached members
//! of that network when it receives a newer one."
//!
//! Beyond those two literal rules, this also closes a gap neither one
//! covers by itself: a node that attaches while already *behind* what
//! this relay holds (its HELLO `roster_seq` for a claimed network is
//! lower than this relay's own) would otherwise never catch up, since
//! rule one only fires when the *node* is ahead, and rule two only fires
//! when the relay just *received* something newer — neither ever fires
//! for a node that simply reconnects after missing an update nobody
//! happens to re-push while it's attached. [`catch_up_targets`] extends
//! rule two's intent ("attached members... need the current roster") to
//! also cover a member attaching already stale, which is a member of the
//! same "attached members of that network" set rule two names, not a
//! new mechanism.
//!
//! A Roster a steward signed travels with its base, the owner signed Roster it was made from
//! (protocol.md 2.3, 4.3): the base is sent first, as a DOC of [`DocType::BaseRoster`], and the
//! Roster after it. The receiving side keeps the base pending, per session and bounded
//! ([`PendingBases`]), until the Roster it belongs to arrives or the session ends; a Roster is
//! judged with the base that came before it, never with a guess.
//!
//! Pure logic only, matching `crate::hello`'s split: no I/O, so this is
//! unit-testable directly. `crate::session` is the I/O glue that calls
//! this from the dispatch loop and actually sends the resulting records.

use std::collections::HashMap;

use menzil_proto::{
    DocBody, DocReassembler, DocReassemblyError, DocType, NetworkId, NodeId, Record, Roster,
};

use crate::log_throttle::NodeLog;
use crate::rate::DocBuckets;
use crate::registry::SessionRegistry;
use crate::roster_store::RosterStore;
use crate::tenant::RosterQuota;

/// The most bases a session may have pending at once, one per network.
const MAX_PENDING_BASES: usize = 8;

/// The base Rosters a session has sent and that wait for the Roster they belong to (at most one
/// per network, [`MAX_PENDING_BASES`] in all). Owned by the session's dispatch loop, so a
/// session that ends takes its pending bases with it: nothing carries over to the next
/// connection of the same node.
#[derive(Debug, Default)]
pub(crate) struct PendingBases {
    by_network: HashMap<NetworkId, Roster>,
}

impl PendingBases {
    /// No base pending.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Keeps `base` for `network_id`, replacing a pending one of that network. Returns false,
    /// keeping nothing, when [`MAX_PENDING_BASES`] other networks are already pending.
    fn keep(&mut self, network_id: NetworkId, base: Roster) -> bool {
        if !self.by_network.contains_key(&network_id) && self.by_network.len() >= MAX_PENDING_BASES
        {
            return false;
        }
        self.by_network.insert(network_id, base);
        true
    }

    /// The pending base of `network_id`, removed: it serves the one Roster that follows it.
    fn take(&mut self, network_id: &NetworkId) -> Option<Roster> {
        self.by_network.remove(network_id)
    }

    /// How many bases are pending.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_network.len()
    }
}

/// What [`accept_roster_chunk`] learned from one inbound DOC chunk.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AcceptOutcome {
    /// The transfer is not complete yet, or was a base held for the Roster that follows it —
    /// nothing further to do.
    Nothing,
    /// A transfer completed, but the session is over its allowance of completed transfers
    /// (`crate::rate`), and it is not a Roster the session may send (it does not decode, or it
    /// is for a network the session did not claim or the relay does not serve): dropped,
    /// nothing verified, no answer.
    OverRate,
    /// A transfer completed, but the session is over its allowance, and it decodes as a Roster
    /// of a network the session claimed and the relay serves: the honest node's excess (a busy
    /// minute, many networks). Dropped, nothing verified, no answer; it does not count towards
    /// the unusable transfers that end a session, only towards the larger over-rate figure
    /// (`SessionRates::over_rate_docs_to_end`).
    OverRateClaimed(NetworkId),
    /// A transfer completed and decoded, for a claimed and served network, but the relay holds a
    /// Roster for it that is as new or newer (a stale or duplicate resend; no signature was
    /// checked). Nothing was stored.
    Stale(NetworkId),
    /// A transfer completed, decoded, was a Roster of a claimed, served network that is newer
    /// than the held one, and would have gone to the signature check, but the tenant's adoptions
    /// of that network are used up (`crate::tenant`, design 2.3). Dropped before any signature
    /// is checked; the session is answered ERROR `over_quota`. Never for a stale transfer, which
    /// costs no signature check and no token.
    OverQuota(NetworkId),
    /// A transfer completed as a doc_type this build doesn't act on at
    /// L3 (protocol.md 4.3: "Policies travel only end to end" — never a
    /// raw L3 DOC to or from a relay).
    IgnoredDocType(DocType),
    /// The transfer's reassembled size exceeded
    /// [`menzil_proto::MAX_DOC_BYTES`], or too many concurrent transfers
    /// were already in progress on this connection.
    TooLarge,
    /// A transfer completed and decoded as a Roster, but for a network
    /// this relay does not already hold, or one the sending session did
    /// not claim (and pass) in its HELLO: dropped without any answer
    /// (isolation rule I3; see `accept_roster_chunk`'s own docs for why
    /// this matters).
    Dropped(NetworkId),
    /// A transfer completed but its bytes did not decode, or did not
    /// verify, as a Roster (malformed or forged).
    Invalid,
    /// A transfer completed, decoded, verified, was for a network this
    /// relay already serves, and was newer than anything already held:
    /// propagate it.
    NewRoster(NetworkId),
}

/// Feeds one inbound DOC chunk into `reassembler`; once its transfer
/// completes, decodes and verifies it as a Roster (rejecting any other
/// `doc_type` without attempting to decode it as one) and stores it via
/// `rosters` — but only for a network `rosters` already holds something
/// for and the sending session `claimed` (isolation rule I3).
///
/// I3: the network named in the (still unverified) body is compared with `claimed` and with
/// what `rosters` serves before the signature is looked at, and a miss is dropped with no
/// answer at all ([`AcceptOutcome::Dropped`] is silent at the caller), so a peer cannot use
/// DOC to learn which networks a relay serves, and a forged Roster for a network the peer has
/// no claim on costs it nothing but the bytes. For a claimed network a forged or stale
/// Roster is silent as well ([`AcceptOutcome::Invalid`]); only the size limit is answered,
/// and that does not depend on the document.
///
/// That last restriction is not optional: `NetworkId` *is* a network
/// owner's own Ed25519 public key (protocol.md 2.3), so anyone can mint a
/// validly self-signed Roster for a `NetworkId` they just generated on
/// the spot, and `check_hello` lets a node attach while claiming *no*
/// network at all ("it may then only redeem an invite" — protocol.md
/// 4.1). Without this check, any node whatsoever — including one with no
/// real standing on this relay — could get an arbitrary number of
/// invented networks stored and served: directly violating protocol.md
/// 4.3 ("refuse Rosters of other networks"), and, via
/// the standing checks over held Rosters, turning into a cheap way to
/// plant a forged Roster to lock a chosen real NodeId out (WELCOME's
/// `rosters` field, `crate::session::build_welcome`, lists only the
/// networks a session claimed and passed, so its payload size is bounded
/// by the HELLO, not by how many networks the relay holds). protocol.md 4.3's "networks they are
/// configured to serve" is exactly this: the very first Roster for a
/// network only ever arrives out of band, through an operator/admin
/// action (`Relay::rosters()`), never introduced by an untrusted wire
/// record; DOC only ever *updates* a network already held.
///
/// `buckets` is the session's allowance of completed transfers (`crate::rate`): one token (of
/// the Roster bucket, or of the base bucket for a base Roster, so a base and its Roster are not
/// charged to one token pool) is taken the moment a transfer completes, before it is verified.
/// A session over its rate costs the relay the reassembly it already paid and one decode, to
/// tell the honest excess ([`AcceptOutcome::OverRateClaimed`]) from the rest
/// ([`AcceptOutcome::OverRate`]); no signature is checked.
/// `quota` is what the network's tenant allows (`crate::tenant`, design 2.3), asked only once the
/// network is known to be claimed and served: a transfer whose encoded size is over the tenant's
/// Roster size figure is [`AcceptOutcome::TooLarge`] (a base Roster too), and a Roster newer than
/// the held one takes a token of the network's adoption bucket before its signature is looked at,
/// or is [`AcceptOutcome::OverQuota`].
/// `log` throttles the warn lines a peer can cause (isolation rule I7); what a line would have
/// said is still available at `debug` level in full.
///
/// A malformed chunk (bad index/count, a mid-transfer doc_type/count
/// change — see [`DocReassemblyError`]) is logged and treated as
/// [`AcceptOutcome::Nothing`]: a protocol violation here costs this one
/// transfer, not the whole session, and there is no single registry code
/// that fits a malformed *chunk* specifically. An oversized transfer, an
/// unserved network, or an invalid document each get their own
/// [`AcceptOutcome`] instead, so `crate::session` can decide whether a
/// registry `ErrorCode` applies.
#[allow(clippy::too_many_arguments)]
pub(crate) fn accept_roster_chunk(
    reassembler: &mut DocReassembler,
    pending: &mut PendingBases,
    body: &DocBody,
    rosters: &RosterStore,
    claimed: &[NetworkId],
    now: u64,
    buckets: &mut DocBuckets,
    quota: &dyn RosterQuota,
    log: NodeLog<'_>,
) -> AcceptOutcome {
    let (doc_type, bytes) = match reassembler.accept(body) {
        Ok(Some(done)) => done,
        Ok(None) => return AcceptOutcome::Nothing,
        Err(DocReassemblyError::TooLarge | DocReassemblyError::TooManyConcurrentTransfers) => {
            return AcceptOutcome::TooLarge;
        }
        Err(err) => {
            tracing::debug!(error = %err, "DOC chunk rejected");
            return AcceptOutcome::Nothing;
        }
    };
    let bucket = match doc_type {
        DocType::BaseRoster => &mut buckets.bases,
        _ => &mut buckets.rosters,
    };
    if !bucket.try_take() {
        if let Some(held_back) = log.admit("doc_over_rate") {
            tracing::warn!(
                held_back,
                "a session sends DOC transfers faster than allowed; dropping the excess unverified"
            );
        }
        return match claimed_served_network(doc_type, &bytes, rosters, claimed) {
            Some(network_id) => AcceptOutcome::OverRateClaimed(network_id),
            None => AcceptOutcome::OverRate,
        };
    }
    if !matches!(doc_type, DocType::Roster | DocType::BaseRoster) {
        tracing::debug!(?doc_type, "ignoring a non-Roster DOC transfer at L3");
        return AcceptOutcome::IgnoredDocType(doc_type);
    }

    let roster = match Roster::decode_strict(&bytes) {
        Ok(roster) => roster,
        Err(err) => {
            tracing::debug!(error = %err, "reassembled DOC did not decode as a Roster");
            if let Some(held_back) = log.admit("doc_refused") {
                tracing::warn!(held_back, error = %err, "a session sent a DOC that did not decode as a Roster");
            }
            return AcceptOutcome::Invalid;
        }
    };
    let decoded = match roster.decode() {
        Ok(decoded) => decoded,
        Err(err) => {
            tracing::debug!(error = %err, "reassembled DOC's Roster body did not decode");
            if let Some(held_back) = log.admit("doc_refused") {
                tracing::warn!(held_back, error = %err, "a session sent a DOC whose Roster body did not decode");
            }
            return AcceptOutcome::Invalid;
        }
    };
    if !claimed.contains(&decoded.network_id) || !rosters.serves(&decoded.network_id) {
        tracing::debug!(
            network_id = %decoded.network_id,
            "dropping a DOC(roster) for a network this session did not claim or this relay does not serve"
        );
        return AcceptOutcome::Dropped(decoded.network_id);
    }
    let max_bytes = quota.max_roster_bytes(&decoded.network_id);
    if bytes.len() > max_bytes {
        if let Some(held_back) = log.admit("doc_too_large") {
            tracing::warn!(
                held_back,
                len = bytes.len(),
                max = max_bytes,
                "a session sent a Roster larger than its tenant allows"
            );
        }
        return AcceptOutcome::TooLarge;
    }
    if doc_type == DocType::BaseRoster {
        // Judged with the Roster it belongs to, which follows; not stored.
        if !pending.keep(decoded.network_id, roster)
            && let Some(held_back) = log.admit("doc_refused")
        {
            tracing::warn!(
                held_back,
                "too many pending base Rosters on this session, dropping one"
            );
        }
        return AcceptOutcome::Nothing;
    }
    let base = pending.take(&decoded.network_id);
    // A Roster that is not newer than the held one is dropped by the store before any signature
    // is checked and costs nothing; one that is newer will cost two Ed25519 checks over up to
    // the tenant's size figure, and that is what the network's bucket meters (threat A11).
    let newer = rosters
        .seq_of(&decoded.network_id)
        .is_none_or(|held| decoded.seq > held);
    if newer && !quota.try_adopt(&decoded.network_id) {
        if let Some(held_back) = log.admit("doc_over_quota") {
            tracing::warn!(
                held_back,
                network_id = %decoded.network_id,
                "a network's Roster adoptions are over its tenant's rate; refusing a transfer unverified"
            );
        }
        return AcceptOutcome::OverQuota(decoded.network_id);
    }
    match rosters.adopt(&roster, base.as_ref(), now) {
        Ok(true) => AcceptOutcome::NewRoster(decoded.network_id),
        Ok(false) => AcceptOutcome::Stale(decoded.network_id),
        Err(err) => {
            tracing::debug!(error = %err, "reassembled DOC was not adopted as a Roster");
            if let Some(held_back) = log.admit("doc_refused") {
                tracing::warn!(held_back, error = %err, "a session sent a DOC that was not adopted as a Roster");
            }
            AcceptOutcome::Invalid
        }
    }
}

/// The network of a transfer that decodes (no signature is looked at) as a Roster or base Roster
/// of a network `claimed` and `rosters` serves; `None` for anything else.
fn claimed_served_network(
    doc_type: DocType,
    bytes: &[u8],
    rosters: &RosterStore,
    claimed: &[NetworkId],
) -> Option<NetworkId> {
    if !matches!(doc_type, DocType::Roster | DocType::BaseRoster) {
        return None;
    }
    let network_id = Roster::decode_strict(bytes).ok()?.decode().ok()?.network_id;
    (claimed.contains(&network_id) && rosters.serves(&network_id)).then_some(network_id)
}

/// Builds the DOC chunk records for `network_id`'s currently held roster, or `None` if this
/// relay holds none: the base first when a steward signed the Roster
/// (`DocType::BaseRoster`), then the Roster itself.
pub(crate) fn roster_doc_records(
    rosters: &RosterStore,
    network_id: &NetworkId,
) -> Option<Vec<Record>> {
    let (roster, base) = rosters.signed_with_base(network_id)?;
    let mut records = match base {
        Some(base) => menzil_proto::split_into_doc_records(DocType::BaseRoster, &base.encode()),
        None => Vec::new(),
    };
    records.extend(menzil_proto::split_into_doc_records(
        DocType::Roster,
        &roster.encode(),
    ));
    Some(records)
}

/// Sends `records` to every attached member of `network_id` except
/// `exclude`, best effort (protocol.md 4.3, `SessionRegistry::send_to`).
pub(crate) fn fan_out(
    registry: &SessionRegistry,
    network_id: &NetworkId,
    exclude: &NodeId,
    records: &[Record],
) {
    for target in registry.attached_members_of(network_id, exclude) {
        for record in records {
            if !registry.send_to(&target, record.clone()) {
                tracing::debug!(node_id = %target, ?network_id, "DOC propagation dropped, outbound queue full or session gone");
                break;
            }
        }
    }
}

/// Networks from `claimed` where `rosters` holds something newer than
/// `their_seq` already claims for it — the attach-time catch-up half of
/// "both directions" (see this module's doc comment).
///
/// Compares `their_seq`'s entry as an `Option`, not `seq > their_seq.get(..).unwrap_or(0)`:
/// a legitimate Roster can have `seq: 0` (protocol.md never forbids it),
/// and folding "this side has nothing at all" into the same value as "this
/// side explicitly holds seq 0" would silently swallow exactly that
/// catch-up.
pub(crate) fn catch_up_targets(
    rosters: &RosterStore,
    claimed: &[NetworkId],
    their_seq: &HashMap<NetworkId, u64>,
) -> Vec<NetworkId> {
    claimed
        .iter()
        .filter(|network_id| {
            rosters
                .seq_of(network_id)
                .is_some_and(|seq| their_seq.get(network_id).is_none_or(|&held| seq > held))
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::{DocId, RosterBody, RosterMember};

    use crate::tests_support::{DAY, StewardNet};

    const NOW: u64 = 1_800_000_000;

    fn signed_roster(owner: &SigningKey, network_id: NetworkId, seq: u64) -> Roster {
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id,
            seq,
            issued: NOW - 60,
            expires: NOW + 7 * DAY,
            members: vec![RosterMember {
                node_id: NodeId::from([1u8; 32]),
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        Roster::sign(owner, &body).unwrap()
    }

    fn feed_all(
        reassembler: &mut DocReassembler,
        records: &[Record],
        rosters: &RosterStore,
    ) -> AcceptOutcome {
        feed_pending(reassembler, &mut PendingBases::new(), records, rosters)
    }

    /// A session that claimed every network `rosters` serves.
    fn feed_pending(
        reassembler: &mut DocReassembler,
        pending: &mut PendingBases,
        records: &[Record],
        rosters: &RosterStore,
    ) -> AcceptOutcome {
        let claimed: Vec<NetworkId> = rosters.seqs().keys().copied().collect();
        feed_claiming(reassembler, pending, records, rosters, &claimed)
    }

    fn feed_claiming(
        reassembler: &mut DocReassembler,
        pending: &mut PendingBases,
        records: &[Record],
        rosters: &RosterStore,
        claimed: &[NetworkId],
    ) -> AcceptOutcome {
        // An allowance that these tests never run out of; `crate::rate` has its own.
        feed_limited(
            reassembler,
            pending,
            records,
            rosters,
            claimed,
            &mut DocBuckets::unlimited(),
        )
    }

    fn feed_limited(
        reassembler: &mut DocReassembler,
        pending: &mut PendingBases,
        records: &[Record],
        rosters: &RosterStore,
        claimed: &[NetworkId],
        buckets: &mut DocBuckets,
    ) -> AcceptOutcome {
        let throttle = crate::log_throttle::LogThrottle::default();
        let log = throttle.about(&NodeId::from([7u8; 32]));
        let mut last = AcceptOutcome::Nothing;
        for record in records {
            let Record::Doc(body) = record else {
                unreachable!()
            };
            last = accept_roster_chunk(
                reassembler,
                pending,
                body,
                rosters,
                claimed,
                NOW,
                buckets,
                &crate::tenant::Unlimited,
                log,
            );
        }
        last
    }

    #[test]
    fn a_complete_valid_roster_transfer_for_an_already_served_network_is_stored_and_reported_as_new()
     {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        // A network only ever starts being served through an
        // operator/admin action; DOC alone never introduces a new one
        // (see `accept_roster_chunk`'s docs) — seed seq 0 here so the
        // seq-1 transfer below is unambiguously "newer".
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 0)).unwrap();

        let roster = signed_roster(&owner, network_id, 1);
        let records = menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode());
        let mut reassembler = DocReassembler::new();

        assert_eq!(
            feed_all(&mut reassembler, &records, &rosters),
            AcceptOutcome::NewRoster(network_id)
        );
        assert_eq!(rosters.get(&network_id).unwrap().seq, 1);
    }

    /// Round 9, M2: a Roster that ran out on disk is held by the relay at start (judged at its
    /// own `issued`), and then the current Roster a member pushes over DOC replaces it; a relay
    /// that did not hold it drops every such DOC silently.
    #[test]
    fn a_held_expired_roster_is_replaced_by_a_newer_one_over_doc() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let mut body = signed_roster(&owner, network_id, 5).decode().unwrap();
        body.issued = NOW - 20 * DAY;
        body.expires = NOW - 6 * DAY;
        let expired = Roster::sign(&owner, &body).unwrap();
        let fresh = signed_roster(&owner, network_id, 9);
        let records = menzil_proto::split_into_doc_records(DocType::Roster, &fresh.encode());

        // Not held: the network is not served and the newer Roster is refused.
        let rosters = RosterStore::new();
        assert!(rosters.adopt(&expired, None, NOW).is_err());
        assert_eq!(
            feed_all(&mut DocReassembler::new(), &records, &rosters),
            AcceptOutcome::Dropped(network_id)
        );

        // Held, judged at its own `issued`: the newer one replaces it.
        assert!(rosters.adopt(&expired, None, body.issued).unwrap());
        assert_eq!(
            feed_all(&mut DocReassembler::new(), &records, &rosters),
            AcceptOutcome::NewRoster(network_id)
        );
        assert_eq!(rosters.get(&network_id).unwrap().seq, 9);
    }

    #[test]
    fn a_roster_for_a_network_this_relay_does_not_already_serve_is_refused_not_inserted() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let roster = signed_roster(&owner, network_id, 1);
        let records = menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode());

        // Nothing seeded: this relay was never configured to serve
        // `network_id` at all.
        let rosters = RosterStore::new();
        let mut reassembler = DocReassembler::new();

        assert_eq!(
            feed_all(&mut reassembler, &records, &rosters),
            AcceptOutcome::Dropped(network_id)
        );
        assert!(
            rosters.get(&network_id).is_none(),
            "a network this relay wasn't already serving must never be inserted via DOC"
        );
    }

    /// Isolation rule I3: a valid Roster of a served network is dropped when the sending
    /// session did not claim that network, and adopted when it did.
    #[test]
    fn a_roster_for_a_served_network_the_session_did_not_claim_is_dropped() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 0)).unwrap();
        let records = menzil_proto::split_into_doc_records(
            DocType::Roster,
            &signed_roster(&owner, network_id, 1).encode(),
        );

        let other = NetworkId::from([0x33; 32]);
        for claimed in [&[][..], &[other][..]] {
            assert_eq!(
                feed_claiming(
                    &mut DocReassembler::new(),
                    &mut PendingBases::new(),
                    &records,
                    &rosters,
                    claimed,
                ),
                AcceptOutcome::Dropped(network_id)
            );
            assert_eq!(rosters.get(&network_id).unwrap().seq, 0);
        }
        assert_eq!(
            feed_claiming(
                &mut DocReassembler::new(),
                &mut PendingBases::new(),
                &records,
                &rosters,
                &[other, network_id],
            ),
            AcceptOutcome::NewRoster(network_id)
        );

        // Claimed but not served (the relay dropped the network after HELLO): still dropped.
        let empty = RosterStore::new();
        assert_eq!(
            feed_claiming(
                &mut DocReassembler::new(),
                &mut PendingBases::new(),
                &records,
                &empty,
                &[network_id],
            ),
            AcceptOutcome::Dropped(network_id)
        );
        assert!(empty.get(&network_id).is_none());
    }

    /// The drop comes before the signature check: a forged Roster of an unclaimed network is
    /// `Dropped`, the same outcome as a valid one, so nothing tells a forgery from a genuine
    /// document, or a served network from an unserved one.
    #[test]
    fn a_forged_roster_for_an_unclaimed_network_is_dropped_like_a_valid_one() {
        let owner = SigningKey::generate(&mut rand::rng());
        let impostor = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 0)).unwrap();
        let forged = menzil_proto::split_into_doc_records(
            DocType::Roster,
            &signed_roster(&impostor, network_id, 1).encode(),
        );
        assert_eq!(
            feed_claiming(
                &mut DocReassembler::new(),
                &mut PendingBases::new(),
                &forged,
                &rosters,
                &[],
            ),
            AcceptOutcome::Dropped(network_id)
        );
    }

    #[test]
    fn an_attacker_cannot_use_doc_to_seed_an_arbitrary_number_of_fake_networks() {
        // Regression test for the vulnerability `accept_roster_chunk`'s
        // docs describe: nothing stops a node from generating many
        // NetworkId keypairs and self-signing a Roster for each. This
        // asserts none of them ever get stored, no matter how many are
        // tried.
        let rosters = RosterStore::new();
        for _ in 0..50 {
            let owner = SigningKey::generate(&mut rand::rng());
            let network_id = NetworkId::from(owner.verifying_key().to_bytes());
            let roster = signed_roster(&owner, network_id, 1);
            let records = menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode());
            let mut reassembler = DocReassembler::new();
            feed_all(&mut reassembler, &records, &rosters);
            assert!(rosters.get(&network_id).is_none());
        }
        assert!(rosters.seqs().is_empty());
    }

    /// A bucket pair that allows one Roster and one base back to back and refills far slower
    /// than a test runs.
    fn one_each() -> DocBuckets {
        let rates = crate::rate::SessionRates {
            doc_transfers_per_minute: 1,
            doc_burst: 1,
            ..crate::rate::SessionRates::default()
        };
        DocBuckets::new(&rates, 1)
    }

    /// Round T3, M1: a base Roster is charged to a bucket of its own, so the base and the Roster
    /// of one pair both pass on a burst of one; the next pair is over the rate and is told
    /// apart from garbage by its network (claimed and served).
    #[test]
    fn a_base_and_its_roster_are_charged_to_buckets_of_their_own() {
        let member = NodeId::from([1u8; 32]);
        let net = StewardNet::new(10, NOW, member);
        let rosters = RosterStore::new();
        rosters.set(&net.base).unwrap();
        let claimed = [net.network_id];
        let mut buckets = one_each();
        let mut reassembler = DocReassembler::new();
        let mut pending = PendingBases::new();
        let base = menzil_proto::split_into_doc_records(DocType::BaseRoster, &net.base.encode());
        let renewal = net.renewal(&net.steward, 11);
        let renewal_records =
            menzil_proto::split_into_doc_records(DocType::Roster, &renewal.encode());
        assert_eq!(
            feed_limited(
                &mut reassembler,
                &mut pending,
                &base,
                &rosters,
                &claimed,
                &mut buckets
            ),
            AcceptOutcome::Nothing,
            "the base is kept for its Roster"
        );
        assert_eq!(
            feed_limited(
                &mut reassembler,
                &mut pending,
                &renewal_records,
                &rosters,
                &claimed,
                &mut buckets
            ),
            AcceptOutcome::NewRoster(net.network_id),
            "the Roster still has its own token after the base took one"
        );
        // The second pair is over the rate in both buckets.
        let renewal2 = net.renewal(&net.steward, 12);
        let renewal2_records =
            menzil_proto::split_into_doc_records(DocType::Roster, &renewal2.encode());
        assert_eq!(
            feed_limited(
                &mut reassembler,
                &mut pending,
                &base,
                &rosters,
                &claimed,
                &mut buckets
            ),
            AcceptOutcome::OverRateClaimed(net.network_id)
        );
        assert_eq!(
            feed_limited(
                &mut reassembler,
                &mut pending,
                &renewal2_records,
                &rosters,
                &claimed,
                &mut buckets
            ),
            AcceptOutcome::OverRateClaimed(net.network_id)
        );
        assert_eq!(rosters.seq_of(&net.network_id), Some(11));
    }

    /// Round T3, M1: over the rate, only a transfer that decodes as a Roster of a claimed, served
    /// network is the honest excess; garbage, and Rosters of other networks, stay `OverRate`
    /// (which counts towards ending the session).
    #[test]
    fn over_the_rate_only_a_claimed_served_roster_is_the_honest_excess() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 1)).unwrap();
        let other_owner = SigningKey::generate(&mut rand::rng());
        let other = NetworkId::from(other_owner.verifying_key().to_bytes());
        rosters.set(&signed_roster(&other_owner, other, 1)).unwrap();
        let mut buckets = one_each();
        // Spend the one Roster token on something.
        let first = signed_roster(&owner, network_id, 2);
        let records = menzil_proto::split_into_doc_records(DocType::Roster, &first.encode());
        let mut reassembler = DocReassembler::new();
        let claimed = [network_id];
        let mut pending = PendingBases::new();
        assert_eq!(
            feed_limited(
                &mut reassembler,
                &mut pending,
                &records,
                &rosters,
                &claimed,
                &mut buckets
            ),
            AcceptOutcome::NewRoster(network_id)
        );
        let mut over = |roster: &Roster| {
            let records = menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode());
            feed_limited(
                &mut reassembler,
                &mut pending,
                &records,
                &rosters,
                &claimed,
                &mut buckets,
            )
        };
        assert_eq!(
            over(&signed_roster(&owner, network_id, 3)),
            AcceptOutcome::OverRateClaimed(network_id)
        );
        assert_eq!(
            over(&signed_roster(&other_owner, other, 3)),
            AcceptOutcome::OverRate,
            "served but not claimed"
        );
        let unserved_owner = SigningKey::generate(&mut rand::rng());
        let unserved = NetworkId::from(unserved_owner.verifying_key().to_bytes());
        assert_eq!(
            over(&signed_roster(&unserved_owner, unserved, 3)),
            AcceptOutcome::OverRate
        );
        // Not a Roster at all.
        let junk = menzil_proto::split_into_doc_records(DocType::Roster, &[1, 2, 3]);
        assert_eq!(
            feed_limited(
                &mut reassembler,
                &mut pending,
                &junk,
                &rosters,
                &claimed,
                &mut buckets
            ),
            AcceptOutcome::OverRate
        );
    }

    #[test]
    fn a_stale_resend_is_reported_as_stale() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 5)).unwrap();

        let stale = signed_roster(&owner, network_id, 5);
        let records = menzil_proto::split_into_doc_records(DocType::Roster, &stale.encode());
        let mut reassembler = DocReassembler::new();
        assert_eq!(
            feed_all(&mut reassembler, &records, &rosters),
            AcceptOutcome::Stale(network_id)
        );
    }

    #[test]
    fn a_policy_doc_type_is_ignored_without_touching_the_roster_store() {
        let doc_id = DocId::from([7u8; 16]);
        let body = DocBody {
            doc_type: DocType::Policy,
            doc_id,
            index: 0,
            count: 1,
            chunk: vec![1, 2, 3],
        };
        let rosters = RosterStore::new();
        let mut reassembler = DocReassembler::new();
        let outcome = accept_roster_chunk(
            &mut reassembler,
            &mut PendingBases::new(),
            &body,
            &rosters,
            &[],
            NOW,
            &mut DocBuckets::unlimited(),
            &crate::tenant::Unlimited,
            crate::log_throttle::LogThrottle::default().about(&NodeId::from([7u8; 32])),
        );
        assert_eq!(outcome, AcceptOutcome::IgnoredDocType(DocType::Policy));
    }

    /// A tenant's quota as `accept_roster_chunk` sees it: a size figure and a number of adoptions.
    struct Quota {
        max_bytes: usize,
        adoptions: std::cell::Cell<u32>,
    }

    impl RosterQuota for Quota {
        fn max_roster_bytes(&self, _: &NetworkId) -> usize {
            self.max_bytes
        }

        fn try_adopt(&self, _: &NetworkId) -> bool {
            let left = self.adoptions.get();
            self.adoptions.set(left.saturating_sub(1));
            left > 0
        }
    }

    fn feed_quota(
        records: &[Record],
        rosters: &RosterStore,
        claimed: &[NetworkId],
        quota: &Quota,
    ) -> AcceptOutcome {
        let mut reassembler = DocReassembler::new();
        let mut last = AcceptOutcome::Nothing;
        for record in records {
            let Record::Doc(body) = record else {
                unreachable!()
            };
            last = accept_roster_chunk(
                &mut reassembler,
                &mut PendingBases::new(),
                body,
                rosters,
                claimed,
                NOW,
                &mut DocBuckets::unlimited(),
                quota,
                crate::log_throttle::LogThrottle::default().about(&NodeId::from([7u8; 32])),
            );
        }
        last
    }

    /// MT7: a transfer over the tenant's size figure is `TooLarge`, for a claimed network only; a
    /// newer Roster takes one adoption before its signature is checked and is `OverQuota` when
    /// there is none; a stale one takes none.
    #[test]
    fn the_tenants_size_and_adoption_figures_apply_before_the_signature_check() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 1)).unwrap();
        let claimed = [network_id];
        let records = |roster: &Roster| {
            menzil_proto::split_into_doc_records(DocType::Roster, &roster.encode())
        };
        let size = signed_roster(&owner, network_id, 2).encode().len();

        // Over the size figure: TooLarge, and no adoption was taken.
        let quota = Quota {
            max_bytes: size - 1,
            adoptions: std::cell::Cell::new(5),
        };
        let two = records(&signed_roster(&owner, network_id, 2));
        assert_eq!(
            feed_quota(&two, &rosters, &claimed, &quota),
            AcceptOutcome::TooLarge
        );
        assert_eq!(quota.adoptions.get(), 5);
        // The same size for a network the session did not claim is dropped silently instead.
        assert_eq!(
            feed_quota(&two, &rosters, &[], &quota),
            AcceptOutcome::Dropped(network_id)
        );

        // At the figure, with one adoption left: adopted; with none: OverQuota, nothing stored.
        let quota = Quota {
            max_bytes: size,
            adoptions: std::cell::Cell::new(1),
        };
        assert_eq!(
            feed_quota(&two, &rosters, &claimed, &quota),
            AcceptOutcome::NewRoster(network_id)
        );
        let three = records(&signed_roster(&owner, network_id, 3));
        assert_eq!(
            feed_quota(&three, &rosters, &claimed, &quota),
            AcceptOutcome::OverQuota(network_id)
        );
        assert_eq!(rosters.seq_of(&network_id), Some(2));
        // A stale resend takes no adoption even when there are none left.
        assert_eq!(
            feed_quota(&two, &rosters, &claimed, &quota),
            AcceptOutcome::Stale(network_id)
        );
    }

    #[test]
    fn a_roster_with_a_bad_signature_for_an_already_served_network_is_invalid_not_stored() {
        // Two different owners: the roster claims `network_id` from
        // `owner`, but is actually signed by `impostor`.
        let owner = SigningKey::generate(&mut rand::rng());
        let impostor = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let forged = signed_roster(&impostor, network_id, 1);
        let records = menzil_proto::split_into_doc_records(DocType::Roster, &forged.encode());

        // Seed the *real* network first, so this exercises the signature
        // check specifically, not the not-served check.
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 0)).unwrap();
        let mut reassembler = DocReassembler::new();

        assert_eq!(
            feed_all(&mut reassembler, &records, &rosters),
            AcceptOutcome::Invalid
        );
        assert_eq!(
            rosters.get(&network_id).unwrap().seq,
            0,
            "the forged roster must not have replaced the real one"
        );
    }

    #[test]
    fn an_oversized_transfer_is_reported_as_too_large() {
        let mut reassembler = DocReassembler::new();
        let rosters = RosterStore::new();
        let doc_id = DocId::from([1u8; 16]);
        let big_chunk = vec![0u8; menzil_proto::MAX_DOC_CHUNK_BYTES];
        let count = (menzil_proto::MAX_DOC_BYTES / menzil_proto::MAX_DOC_CHUNK_BYTES + 2) as u16;
        for index in 0..count {
            let body = DocBody {
                doc_type: DocType::Roster,
                doc_id,
                index,
                count,
                chunk: big_chunk.clone(),
            };
            let outcome = accept_roster_chunk(
                &mut reassembler,
                &mut PendingBases::new(),
                &body,
                &rosters,
                &[],
                NOW,
                &mut DocBuckets::unlimited(),
                &crate::tenant::Unlimited,
                crate::log_throttle::LogThrottle::default().about(&NodeId::from([7u8; 32])),
            );
            if outcome == AcceptOutcome::TooLarge {
                return;
            }
        }
        panic!("expected TooLarge before every chunk was accepted");
    }

    #[test]
    fn roster_doc_records_round_trips_through_split_and_reassembly() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let roster = signed_roster(&owner, network_id, 3);
        let rosters = RosterStore::new();
        rosters.set(&roster).unwrap();

        let records = roster_doc_records(&rosters, &network_id).unwrap();
        // A receiving side must already serve this network too, per the
        // same restriction `accept_roster_chunk` enforces (real fan-out
        // targets always do — they only ever received this network's DOC
        // because they claimed it in a HELLO the relay already validated
        // against a held Roster).
        let receiving_side = RosterStore::new();
        receiving_side
            .set(&signed_roster(&owner, network_id, 0))
            .unwrap();
        let mut reassembler = DocReassembler::new();
        assert_eq!(
            feed_all(&mut reassembler, &records, &receiving_side),
            AcceptOutcome::NewRoster(network_id)
        );
    }

    #[test]
    fn roster_doc_records_is_none_for_an_unheld_network() {
        let rosters = RosterStore::new();
        assert!(roster_doc_records(&rosters, &NetworkId::from([1u8; 32])).is_none());
    }

    #[test]
    fn fan_out_reaches_claimed_members_and_skips_the_excluded_node() {
        let network_id = NetworkId::from([1u8; 32]);
        let registry = SessionRegistry::new();
        let sender = NodeId::from([10u8; 32]);
        let member = NodeId::from([11u8; 32]);
        let stranger = NodeId::from([12u8; 32]);
        let (_s1, mut sender_rx, _s1_fwd) = registry.attach(sender, 1, vec![network_id]);
        let (_s2, mut member_rx, _s2_fwd) = registry.attach(member, 2, vec![network_id]);
        let (_s3, mut stranger_rx, _s3_fwd) = registry.attach(stranger, 3, vec![]);

        fan_out(
            &registry,
            &network_id,
            &sender,
            &[Record::Rekey, Record::Attach],
        );

        assert_eq!(member_rx.try_recv().unwrap(), Record::Rekey);
        assert_eq!(member_rx.try_recv().unwrap(), Record::Attach);
        assert!(sender_rx.try_recv().is_err(), "the sender is excluded");
        assert!(
            stranger_rx.try_recv().is_err(),
            "a session that never claimed this network is not a target"
        );
    }

    #[test]
    fn catch_up_targets_finds_only_networks_where_the_relay_is_ahead() {
        let owner_a = SigningKey::generate(&mut rand::rng());
        let owner_b = SigningKey::generate(&mut rand::rng());
        let network_a = NetworkId::from(owner_a.verifying_key().to_bytes());
        let network_b = NetworkId::from(owner_b.verifying_key().to_bytes());
        let unheld = NetworkId::from([0x55; 32]);

        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner_a, network_a, 5)).unwrap();
        rosters.set(&signed_roster(&owner_b, network_b, 2)).unwrap();

        let mut their_seq = HashMap::new();
        their_seq.insert(network_a, 3); // behind: a catch-up target
        their_seq.insert(network_b, 2); // equal: not a target

        let targets = catch_up_targets(&rosters, &[network_a, network_b, unheld], &their_seq);
        assert_eq!(targets, vec![network_a]);
    }

    #[test]
    fn catch_up_targets_is_empty_when_the_node_never_claimed_anything() {
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 5)).unwrap();

        let targets = catch_up_targets(&rosters, &[], &HashMap::new());
        assert!(targets.is_empty());
    }

    #[test]
    fn catch_up_targets_fires_for_a_seq_zero_roster_when_the_node_has_none_at_all() {
        // Regression test: comparing against `.unwrap_or(0)` would make
        // this indistinguishable from "the node already has seq 0",
        // silently skipping a member that genuinely holds nothing yet.
        let owner = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let rosters = RosterStore::new();
        rosters.set(&signed_roster(&owner, network_id, 0)).unwrap();

        let targets = catch_up_targets(&rosters, &[network_id], &HashMap::new());
        assert_eq!(targets, vec![network_id]);
    }

    fn doc_records(doc_type: DocType, roster: &Roster) -> Vec<Record> {
        menzil_proto::split_into_doc_records(doc_type, &roster.encode())
    }

    #[test]
    fn a_base_then_a_steward_roster_over_doc_is_adopted_and_the_base_is_used_up() {
        let net = StewardNet::new(10, NOW, NodeId::from([1u8; 32]));
        let rosters = RosterStore::new();
        rosters.set(&net.base).unwrap();
        let mut reassembler = DocReassembler::new();
        let mut pending = PendingBases::new();

        let base = doc_records(DocType::BaseRoster, &net.base);
        assert_eq!(
            feed_pending(&mut reassembler, &mut pending, &base, &rosters),
            AcceptOutcome::Nothing
        );
        assert_eq!(pending.len(), 1);
        let renewal = net.renewal(&net.steward, 11);
        let records = doc_records(DocType::Roster, &renewal);
        assert_eq!(
            feed_pending(&mut reassembler, &mut pending, &records, &rosters),
            AcceptOutcome::NewRoster(net.network_id)
        );
        assert_eq!(pending.len(), 0);
        assert_eq!(rosters.base(&net.network_id).unwrap(), net.base);

        // The base was spent on that Roster: the next one needs its own.
        let next = doc_records(DocType::Roster, &net.renewal(&net.steward, 12));
        assert_eq!(
            feed_pending(&mut reassembler, &mut pending, &next, &rosters),
            AcceptOutcome::Invalid
        );
        assert_eq!(rosters.get(&net.network_id).unwrap().seq, 11);
    }

    #[test]
    fn a_steward_roster_over_doc_without_a_base_is_invalid() {
        let net = StewardNet::new(10, NOW, NodeId::from([1u8; 32]));
        let rosters = RosterStore::new();
        rosters.set(&net.base).unwrap();
        let records = doc_records(DocType::Roster, &net.renewal(&net.steward, 11));
        assert_eq!(
            feed_all(&mut DocReassembler::new(), &records, &rosters),
            AcceptOutcome::Invalid
        );
        assert_eq!(rosters.get(&net.network_id).unwrap().seq, 10);
    }

    #[test]
    fn a_base_for_a_network_this_relay_does_not_serve_is_not_kept() {
        let net = StewardNet::new(10, NOW, NodeId::from([1u8; 32]));
        let rosters = RosterStore::new();
        let mut pending = PendingBases::new();
        let base = doc_records(DocType::BaseRoster, &net.base);
        assert_eq!(
            feed_pending(&mut DocReassembler::new(), &mut pending, &base, &rosters),
            AcceptOutcome::Dropped(net.network_id)
        );
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn pending_bases_are_bounded_per_session() {
        let rosters = RosterStore::new();
        let mut pending = PendingBases::new();
        let mut reassembler = DocReassembler::new();
        let mut nets = Vec::new();
        for _ in 0..=MAX_PENDING_BASES {
            let net = StewardNet::new(10, NOW, NodeId::from([1u8; 32]));
            rosters.set(&net.base).unwrap();
            let base = doc_records(DocType::BaseRoster, &net.base);
            feed_pending(&mut reassembler, &mut pending, &base, &rosters);
            nets.push(net);
        }
        assert_eq!(pending.len(), MAX_PENDING_BASES);
        // The ninth network's base was dropped, so its steward Roster has none.
        let last = nets.last().unwrap();
        let records = doc_records(DocType::Roster, &last.renewal(&last.steward, 11));
        assert_eq!(
            feed_pending(&mut reassembler, &mut pending, &records, &rosters),
            AcceptOutcome::Invalid
        );
    }

    #[test]
    fn the_records_of_a_held_steward_roster_carry_the_base_first() {
        let net = StewardNet::new(10, NOW, NodeId::from([1u8; 32]));
        let rosters = RosterStore::new();
        rosters.set(&net.base).unwrap();
        // An owner signed Roster is sent alone.
        let alone = roster_doc_records(&rosters, &net.network_id).unwrap();
        assert_eq!(doc_types_of(&alone), vec![DocType::Roster]);

        let renewal = net.renewal(&net.steward, 11);
        rosters.adopt(&renewal, Some(&net.base), NOW).unwrap();
        let records = roster_doc_records(&rosters, &net.network_id).unwrap();
        assert_eq!(
            doc_types_of(&records),
            vec![DocType::BaseRoster, DocType::Roster]
        );
        // And what a receiver reassembles in that order is adopted.
        let receiving = RosterStore::new();
        receiving.set(&net.base).unwrap();
        let mut reassembler = DocReassembler::new();
        let mut pending = PendingBases::new();
        assert_eq!(
            feed_pending(&mut reassembler, &mut pending, &records, &receiving),
            AcceptOutcome::NewRoster(net.network_id)
        );
    }

    /// The `doc_type` of each complete transfer in `records`, in order.
    fn doc_types_of(records: &[Record]) -> Vec<DocType> {
        let mut seen = Vec::new();
        for record in records {
            let Record::Doc(body) = record else {
                unreachable!()
            };
            if body.index == 0 {
                seen.push(body.doc_type);
            }
        }
        seen
    }

    #[test]
    fn a_base_alone_is_never_stored() {
        let net = StewardNet::new(10, NOW, NodeId::from([1u8; 32]));
        let older = net.rebase(5);
        let rosters = RosterStore::new();
        rosters.set(&older.base).unwrap();
        // A newer owner signed Roster arrives as a base only, with nothing after it.
        let base = doc_records(DocType::BaseRoster, &net.base);
        assert_eq!(
            feed_all(&mut DocReassembler::new(), &base, &rosters),
            AcceptOutcome::Nothing
        );
        assert_eq!(rosters.get(&net.network_id).unwrap().seq, 5);
        assert!(rosters.base(&net.network_id).is_none());
    }
}
