//! Renewed node certificates offered over `menzil:docs`, kept as candidates for a steward to
//! list later (cert rotation S5, design Q7 c).
//!
//! A node whose certificate was renewed pushes it, as a `node_cert` document, to its peers. A
//! pushed certificate is **never accepted on trust**: whoever receives it judges it here, and
//! only a node that holds a steward key for the network ([`Holder::Steward`], with the rights
//! `admit` and `renew` and a `not_after` still ahead) records it at all. Everyone else, and
//! every node that holds no such key, ignores it (the caller answers `result` 3/3).
//!
//! The checks, in this order, and the first failure refuses the certificate (it is logged at
//! `warn` with its reason and never stored):
//!
//! 1. the certificate decodes, and its `node_id` is the session's peer;
//! 2. that peer is an unrevoked member of the session's network in the held Roster;
//! 3. its `x25519_pub` is the static key of the session (so a relay that forges the `src` of
//!    a record cannot pass a member's certificate off as another's: the member signed it over
//!    its own key);
//! 4. its `x25519_pub` is the key of the highest certificate the held Policy lists for that
//!    node (a new key is a new identity, as for `accept_cert`); a Policy that lists none
//!    skips this check;
//! 5. the self signature verifies under the `node_id` key;
//! 6. it is valid now, and its window is at most [`NODE_CERT_MAX_LIFETIME`];
//! 7. its serial is strictly above the highest serial known for that node: the certificates
//!    the held Policy lists, the candidate already stored, and the Roster's `min_serial`. An
//!    equal serial is a replay and a lower one a rollback; both are refused.
//!
//! The store keeps at most one candidate per member and network, the one with the highest
//! serial. A candidate the held Policy lists (the same serial or higher) is dropped the next
//! time the store is looked at, and so is one whose member is no longer an unrevoked member of
//! the held Roster or whose serial is below the Roster's `min_serial` for it. Nothing is persisted: a candidate is idempotent, because the
//! node pushes its certificate again on every session until a Policy lists it.
//!
//! A node that holds the owner key ([`Holder::Owner`]) stores nothing: when no steward is listed
//! it writes one log line per member and network and answers [`Offer::Noted`] that once.
//!
//! What a steward does with a candidate (issuing the rotation pair) is not here.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};

use ed25519_dalek::VerifyingKey;
use menzil_proto::trust::NODE_CERT_MAX_LIFETIME;
use menzil_proto::{NetworkId, NodeCert, NodeCertBody, NodeId, X25519PublicKey};

use crate::policy_store::{PolicyStore, roster_standing};
use crate::roster_store::RosterStore;

/// What this node is, for the network, as far as candidates are concerned. Set by the embedder
/// from the keys it holds ([`CertCandidates::set_holder`]); the library cannot know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    /// The node holds a steward key listed for the network. It records candidates only when
    /// the entry has both rights `admit` and `renew` and its `not_after` is still ahead.
    Steward {
        /// The entry holds the right `admit`.
        admit: bool,
        /// The entry holds the right `renew`.
        renew: bool,
        /// The delegation ends here, Unix seconds.
        not_after: u64,
    },
    /// The node holds the owner key. It records nothing (no automatic owner signing); when the
    /// held Roster lists no steward it logs, once per member and network, that the member has
    /// a newer certificate for the owner to accept.
    Owner,
}

impl Holder {
    /// Whether a node of this kind keeps candidates at `now`: a steward entry with both rights
    /// and a `not_after` ahead. The owner keeps none.
    fn records(self, now: u64) -> bool {
        match self {
            Self::Steward {
                admit,
                renew,
                not_after,
            } => admit && renew && not_after > now,
            Self::Owner => false,
        }
    }
}

/// The session a `node_cert` arrived on, as this node knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offerer {
    /// The session's network.
    pub network_id: NetworkId,
    /// The session's peer: the NodeId that dialed or answered.
    pub peer: NodeId,
    /// The peer's Noise static key of the session.
    pub peer_static: X25519PublicKey,
}

/// Why a certificate was refused. The peer is told nothing of it (the `result` is the same
/// whatever happens here, or the answer would tell which peers hold a steward or owner key);
/// the log keeps this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The certificate does not decode.
    Undecodable,
    /// Its `node_id` is not the session's peer.
    NotThePeer,
    /// The peer is not an unrevoked member in the held Roster.
    NotAMember,
    /// Its `x25519_pub` is not the session's static key.
    WrongStaticKey,
    /// Its `x25519_pub` is not the key of the highest certificate the held Policy lists for the
    /// node: a new key is a new identity, not a renewal.
    NewKey,
    /// The self signature does not verify.
    BadSignature,
    /// Not valid now (expired or not yet valid).
    NotValidNow,
    /// The window is over 400 days (or ends before it starts).
    WindowTooLong,
    /// The serial equals the highest known: a replay.
    Replay,
    /// The serial is below the highest known: a rollback.
    Rollback,
}

impl Refusal {
    fn text(self) -> &'static str {
        match self {
            Self::Undecodable => "the certificate does not decode",
            Self::NotThePeer => "its node_id is not the session peer",
            Self::NotAMember => "the peer is not an unrevoked member of the network",
            Self::WrongStaticKey => "its x25519_pub is not the session's static key",
            Self::NewKey => {
                "its x25519_pub differs from the key the held Policy lists for the node"
            }
            Self::BadSignature => "its self signature does not verify",
            Self::NotValidNow => "it is not valid now",
            Self::WindowTooLong => "its validity window is over 400 days",
            Self::Replay => "its serial equals the highest known (replay)",
            Self::Rollback => "its serial is below the highest known (rollback)",
        }
    }
}

/// What [`CertCandidates::offer`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// This node holds no steward key that could use it (or the steward entry lacks a right or
    /// has ended): nothing was judged or stored.
    Ignored,
    /// Judged valid and stored as the candidate of this member (replacing a lower one).
    Recorded,
    /// Judged valid at a node that holds the owner key, no steward is listed and this member
    /// was not named yet: the log line "has a newer certificate" was written. Never stored.
    Noted,
    /// Refused, and not stored.
    Refused(Refusal),
}

#[derive(Default)]
struct State {
    holders: HashMap<NetworkId, Holder>,
    candidates: HashMap<(NetworkId, NodeId), NodeCert>,
    /// Networks whose steward entry made this node ignore candidates, already logged once.
    ignored_logged: HashSet<NetworkId>,
    /// Members already named in the owner's log line, with the serial the line named: one line
    /// per renewal (a higher serial is a new line), forgotten once the Policy lists it.
    owner_logged: HashMap<(NetworkId, NodeId), u32>,
}

/// The candidate store of a node: the checks above and the certificates that passed them.
pub struct CertCandidates {
    rosters: Arc<RosterStore>,
    policies: Arc<PolicyStore>,
    state: Mutex<State>,
}

impl CertCandidates {
    /// A store judging against these documents. It holds nothing and ignores everything until
    /// [`Self::set_holder`] says what the node is.
    pub fn new(rosters: Arc<RosterStore>, policies: Arc<PolicyStore>) -> Self {
        Self {
            rosters,
            policies,
            state: Mutex::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Says what this node is for `network_id` (`None`: nothing, ignore candidates) at `now`
    /// (Unix seconds). A node that stops being able to use candidates loses those it had for the
    /// network: `None`, the owner key (which stores nothing), a steward entry without `admit` or
    /// `renew`, or one whose `not_after` has passed.
    pub fn set_holder(&self, network_id: NetworkId, holder: Option<Holder>, now: u64) {
        let mut state = self.lock();
        match holder {
            Some(holder) => {
                if state.holders.insert(network_id, holder) != Some(holder) {
                    // A changed entry is worth a new log line.
                    state.ignored_logged.remove(&network_id);
                }
            }
            None => {
                state.holders.remove(&network_id);
            }
        }
        if !holder.is_some_and(|holder| holder.records(now)) {
            state
                .candidates
                .retain(|(network, _), _| *network != network_id);
        }
    }

    /// The candidates of `network_id`, one per member, those the held Policy does not list
    /// yet and whose member still stands in the held Roster. Any other is dropped here.
    pub fn candidates(&self, network_id: NetworkId) -> Vec<NodeCert> {
        let mut state = self.lock();
        self.prune(&mut state, &network_id);
        state
            .candidates
            .iter()
            .filter(|((network, _), _)| *network == network_id)
            .map(|(_, cert)| cert.clone())
            .collect()
    }

    /// Drops the candidates of `network_id` that cannot be used any more: the member is not an
    /// unrevoked member of the held Roster (revoked, removed, or no Roster), the serial is below
    /// the Roster's `min_serial` for it, or the held Policy lists the same serial or a higher one.
    fn prune(&self, state: &mut State, network_id: &NetworkId) {
        let roster = self.rosters.body(network_id);
        let policy = self.policies.body(network_id);
        // A serial the Policy lists needs no more reminders (round C, N1).
        state.owner_logged.retain(|(network, node), serial| {
            network != network_id
                || policy
                    .as_ref()
                    .is_none_or(|policy| listed_serial(&policy.certs, node) < Some(*serial))
        });
        state.candidates.retain(|(network, node), cert| {
            if network != network_id {
                return true;
            }
            let Some(min_serial) = roster
                .as_ref()
                .and_then(|roster| roster_standing(roster, node).ok())
            else {
                return false;
            };
            let Ok(body) = cert.decode() else {
                return false;
            };
            if body.serial < min_serial {
                return false;
            }
            policy
                .as_ref()
                .is_none_or(|policy| listed_serial(&policy.certs, node) < Some(body.serial))
        });
    }

    /// Judges a pushed certificate that arrived on the session `from` at `now` (Unix seconds)
    /// and, when this node is a steward that can use it and it passes every check, records it.
    /// Never fails open: a refusal is logged at `warn` and nothing is stored. The state is
    /// locked for the whole judgement, so two certificates of one member cannot both pass
    /// against the same stored serial.
    pub fn offer(&self, from: &Offerer, cert: &NodeCert, now: u64) -> Offer {
        let network_id = from.network_id;
        let mut state = self.lock();
        // Whether this node can use a candidate at all comes first and is cheap: a node that
        // holds no steward key spends nothing on a pushed certificate.
        let holder = match state.holders.get(&network_id).copied() {
            None => return Offer::Ignored,
            Some(Holder::Steward {
                admit,
                renew,
                not_after,
            }) if !(admit && renew && not_after > now) => {
                // Whatever was recorded while the entry was good is of no use now.
                state
                    .candidates
                    .retain(|(network, _), _| *network != network_id);
                if state.ignored_logged.insert(network_id) {
                    tracing::warn!(
                        network = %network_id,
                        "this steward key cannot list renewed certificates (it needs the \
                         rights admit and renew and a not_after ahead); candidates are ignored"
                    );
                }
                return Offer::Ignored;
            }
            Some(holder) => holder,
        };
        let body = match self.judge(&state, from, cert, now) {
            Ok(body) => body,
            Err(refusal) => {
                tracing::warn!(
                    network = %network_id,
                    peer = %from.peer,
                    reason = refusal.text(),
                    "refused a pushed node_cert"
                );
                return Offer::Refused(refusal);
            }
        };
        match holder {
            Holder::Steward { .. } => {
                // The serial is above the stored one (the last check), so this replaces it.
                state
                    .candidates
                    .insert((network_id, from.peer), cert.clone());
                Offer::Recorded
            }
            Holder::Owner => {
                let steward_listed = self
                    .rosters
                    .body(&network_id)
                    .is_some_and(|roster| !roster.stewards.is_empty());
                self.prune(&mut state, &network_id);
                let logged = state.owner_logged.get(&(network_id, from.peer)).copied();
                if steward_listed || logged.is_some_and(|logged| logged >= body.serial) {
                    return Offer::Ignored;
                }
                state
                    .owner_logged
                    .insert((network_id, from.peer), body.serial);
                tracing::info!(
                    network = %network_id,
                    member = %from.peer,
                    serial = body.serial,
                    "{} has a newer certificate (serial {}); run `menzil cert accept` with its token",
                    from.peer,
                    body.serial
                );
                Offer::Noted
            }
        }
    }

    /// The checks, in order. Returns the decoded body of a certificate that passed them all.
    fn judge(
        &self,
        state: &State,
        from: &Offerer,
        cert: &NodeCert,
        now: u64,
    ) -> Result<NodeCertBody, Refusal> {
        let body = cert.decode().map_err(|_| Refusal::Undecodable)?;
        if body.node_id != from.peer {
            return Err(Refusal::NotThePeer);
        }
        let min_serial = self
            .rosters
            .body(&from.network_id)
            .and_then(|roster| roster_standing(&roster, &from.peer).ok())
            .ok_or(Refusal::NotAMember)?;
        if body.x25519_pub != from.peer_static {
            return Err(Refusal::WrongStaticKey);
        }
        // A listed certificate of the node fixes its key: a renewal keeps it (as `accept_cert`
        // requires). The check is a comparison, so it comes before the signature.
        if let Some(listed) = self
            .policies
            .body(&from.network_id)
            .and_then(|policy| listed_highest(&policy.certs, &from.peer))
            && listed.x25519_pub != body.x25519_pub
        {
            return Err(Refusal::NewKey);
        }
        let key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id))
            .map_err(|_| Refusal::BadSignature)?;
        cert.verify(&key).map_err(|_| Refusal::BadSignature)?;
        if !body.is_valid_at(now) {
            return Err(Refusal::NotValidNow);
        }
        if body.not_after < body.not_before
            || body.not_after - body.not_before > NODE_CERT_MAX_LIFETIME
        {
            return Err(Refusal::WindowTooLong);
        }
        let known = self.known_serial(state, &from.network_id, &from.peer, min_serial);
        match body.serial.cmp(&known) {
            std::cmp::Ordering::Greater => Ok(body),
            std::cmp::Ordering::Equal => Err(Refusal::Replay),
            std::cmp::Ordering::Less => Err(Refusal::Rollback),
        }
    }

    /// The highest serial known for `node` in `network_id`: the held Policy's certificates,
    /// the stored candidate and the Roster's `min_serial` (`floor`).
    fn known_serial(
        &self,
        state: &State,
        network_id: &NetworkId,
        node: &NodeId,
        floor: u32,
    ) -> u32 {
        let from_policy = self
            .policies
            .body(network_id)
            .and_then(|policy| listed_serial(&policy.certs, node));
        let from_candidate = state
            .candidates
            .get(&(*network_id, *node))
            .and_then(|cert| cert.decode().ok())
            .map(|body| body.serial);
        [Some(floor), from_policy, from_candidate]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(floor)
    }
}

/// The highest serial among `certs` that are for `node` (signatures are not looked at: the
/// Policy is an adopted document).
pub(crate) fn listed_serial(certs: &[NodeCert], node: &NodeId) -> Option<u32> {
    listed_highest(certs, node).map(|body| body.serial)
}

/// The certificate of `node` among `certs` that wins by [`NodeCertBody::rank`] (the one rule of
/// which certificate of a node is the highest).
fn listed_highest(certs: &[NodeCert], node: &NodeId) -> Option<NodeCertBody> {
    certs
        .iter()
        .filter_map(|cert| cert.decode().ok())
        .filter(|body| &body.node_id == node)
        .max_by_key(NodeCertBody::rank)
}

#[cfg(test)]
mod tests;
