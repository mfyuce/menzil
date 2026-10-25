//! The steward's own renewal inside `menzil node` (protocol.md 7.3, L4j S7): a node on a device
//! that holds a steward key re-issues the network's documents before they run out, so that a
//! network stays alive without anyone pasting a token to every member.
//!
//! The rules are a pure core ([`decide`], [`tick_due`], [`warn_due`]) that takes the clock and
//! what the node holds ([`Facts`]) and answers; [`tick_network`] reads the held documents and
//! does the I/O (the same save path the CLI uses, under the network lock, then the stores);
//! [`run`] is the thin task that calls it and starts the push to the members.
//!
//! What the loop renews from is the newer of what the node holds in memory (documents that
//! came over the relay or from a peer are not written to disk) and what is on disk (the
//! documents `menzil admit` or `menzil join` wrote), so it never signs a lower `seq` than the
//! network already has.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use menzil_admin::{Documents, StewardSecret};
use menzil_node::{DocStore, Node, PolicyStore, RosterStore};
use menzil_proto::trust::DOC_MAX_LIFETIME;
use menzil_proto::{NetworkId, StewardKey};
use tokio::task::JoinHandle;

use crate::home::Home;
use crate::local::{load_documents, load_steward, save_documents};

/// A steward renews when its documents expire within this long (protocol.md 7.3), in seconds.
pub const RENEW_WITHIN: u64 = 7 * 24 * 60 * 60;
/// A steward warns from this long before its entry's `not_after`, in seconds.
pub const WARN_WITHIN: u64 = 14 * 24 * 60 * 60;
/// How often a network is looked at, and the longest a failed look waits for the next one,
/// in seconds.
pub const TICK_SECS: u64 = 60 * 60;
/// How often the same warning is repeated, in seconds.
pub const WARN_EVERY_SECS: u64 = 24 * 60 * 60;
/// How often the task looks at whether a network is due (a changed `seq` makes it due at
/// once, which is how a reload is noticed).
const POLL: Duration = Duration::from_secs(15);

/// What a steward node needs to know about the documents it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The `seq` of the held pair.
    pub seq: u64,
    /// When the held pair expires, Unix seconds.
    pub expires: u64,
    /// The `Steward` entry of the newest owner signed Roster behind the held pair, if it lists
    /// one.
    pub entry: Option<EntryFacts>,
}

/// The `Steward` entry of the owner signed Roster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFacts {
    /// The listed key.
    pub key: StewardKey,
    /// The entry holds the right `renew`.
    pub may_renew: bool,
    /// The delegation ends here, Unix seconds.
    pub not_after: u64,
}

impl Facts {
    /// The facts of `docs`: the entry is read from the owner signed Roster the pair stands on
    /// (its base when a steward signed it, itself otherwise).
    pub fn of(docs: &Documents) -> Result<Self> {
        let owner_roster = docs.base().map_or(docs.roster(), |(roster, _)| roster);
        let entry = match owner_roster.decode()?.stewards.first() {
            Some(entry) => {
                let body = entry.decode()?;
                Some(EntryFacts {
                    key: body.steward_pub,
                    may_renew: body.may.iter().any(|right| right == "renew"),
                    not_after: body.not_after,
                })
            }
            None => None,
        };
        Ok(Self {
            seq: docs.seq(),
            expires: docs.roster_body().expires,
            entry,
        })
    }
}

/// Something the person running the steward node should hear about, once a day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// The held documents list no steward, or another one: this key is not used.
    NotListed,
    /// The steward's `not_after` has passed.
    Ended,
    /// The entry does not hold `renew`: the documents are not renewed here.
    LacksRenew,
    /// The entry ends in this many whole days; the owner has to list a new one.
    EndsSoon {
        /// Whole days left.
        days: u64,
    },
}

impl Warning {
    /// The sentence for the log and the terminal.
    pub fn text(self, network_id: &NetworkId) -> String {
        match self {
            Self::NotListed => format!(
                "network {network_id}: this device has a steward key, but the network's documents do not list it; the documents are not renewed here"
            ),
            Self::Ended => format!(
                "network {network_id}: this steward's time has run out; the documents are not renewed here until the owner lists a new steward (`menzil steward add`)"
            ),
            Self::LacksRenew => format!(
                "network {network_id}: this steward may admit but not renew; the documents are not renewed here (the owner renews, or lists the right `renew`)"
            ),
            Self::EndsSoon { days } => format!(
                "network {network_id}: this steward's time runs out in {days} day(s); the owner has to list a new one (`menzil steward add`) before then"
            ),
        }
    }
}

/// What to do with one network now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Plan {
    /// Sign the next pair.
    pub renew: bool,
    /// Say something.
    pub warning: Option<Warning>,
}

/// The `expires` a renewal made at `now` gets: 14 days ahead or at `not_after`, whichever comes
/// first (protocol.md 7.3).
pub fn renewed_expires(now: u64, not_after: u64) -> u64 {
    now.saturating_add(DOC_MAX_LIFETIME).min(not_after)
}

/// The renewal rule (protocol.md 7.3). `own` is the public half of the steward key this device
/// has, `None` when it has none; `held` is what the node holds.
///
/// Renew when the pair expires within [`RENEW_WITHIN`], the entry lists this key with `renew`,
/// `now` is before its `not_after`, and a renewal would reach further than the pair already
/// does (a pair cut short by `not_after` is not signed again and again, burning `seq`).
pub fn decide(now: u64, own: Option<StewardKey>, held: Option<&Facts>) -> Plan {
    let (Some(own), Some(held)) = (own, held) else {
        return Plan::default();
    };
    let Some(entry) = held.entry.as_ref().filter(|entry| entry.key == own) else {
        return Plan {
            renew: false,
            warning: Some(Warning::NotListed),
        };
    };
    if now >= entry.not_after {
        return Plan {
            renew: false,
            warning: Some(Warning::Ended),
        };
    }
    if !entry.may_renew {
        return Plan {
            renew: false,
            warning: Some(Warning::LacksRenew),
        };
    }
    let warning = (entry.not_after - now <= WARN_WITHIN).then(|| Warning::EndsSoon {
        days: (entry.not_after - now) / (24 * 60 * 60),
    });
    let renew = held.expires.saturating_sub(now) <= RENEW_WITHIN
        && renewed_expires(now, entry.not_after) > held.expires;
    Plan { renew, warning }
}

/// When a network was last looked at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tick {
    /// When, Unix seconds.
    pub at: u64,
    /// The `seq` held then; `None` after a failure that never got to read it.
    pub seq: Option<u64>,
}

/// Whether a network is looked at now: never looked at, [`TICK_SECS`] since the last time, or a
/// `seq` other than the one seen last (documents arrived: a reload, a push). A failed look
/// waits for the hour like any other.
pub fn tick_due(last: Option<Tick>, now: u64, seq: u64) -> bool {
    match last {
        None => true,
        Some(last) => {
            now.saturating_sub(last.at) >= TICK_SECS || last.seq.is_some_and(|seen| seen != seq)
        }
    }
}

/// Whether a warning is said now: not said yet, or [`WARN_EVERY_SECS`] since it was.
pub fn warn_due(last: Option<u64>, now: u64) -> bool {
    last.is_none_or(|at| now.saturating_sub(at) >= WARN_EVERY_SECS)
}

/// What the loop remembers of one network.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetState {
    last: Option<Tick>,
    last_warning: Option<u64>,
}

/// What one look came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to do: no steward key here, not due, or no documents.
    Idle,
    /// Looked, and nothing needed renewing.
    Checked,
    /// Renewed: the new pair is on disk and in the stores.
    Renewed {
        /// Its `seq`.
        seq: u64,
    },
}

/// The pair this node holds for a network: the newer of the stores' and the disk's.
fn held_documents(
    home: &Home,
    rosters: &RosterStore,
    policies: &PolicyStore,
    network_id: &NetworkId,
) -> Result<Option<Documents>> {
    let from_stores = stored_documents(rosters, policies, network_id);
    let from_disk = load_documents(home, network_id);
    match (from_stores, from_disk) {
        (Some(stored), Ok(disk)) => Ok(Some(if stored.seq() > disk.seq() {
            stored
        } else {
            disk
        })),
        (Some(stored), Err(_)) => Ok(Some(stored)),
        (None, Ok(disk)) => Ok(Some(disk)),
        (None, Err(error)) => Err(error),
    }
}

/// The pair in the stores, with its bases; `None` when a half is missing or the halves do not
/// belong together (the other half is mid adoption: the disk is used then).
fn stored_documents(
    rosters: &RosterStore,
    policies: &PolicyStore,
    network_id: &NetworkId,
) -> Option<Documents> {
    let (roster, roster_base) = rosters.get_with_base(network_id)?;
    let (policy, policy_base) = policies.get_with_base(network_id)?;
    match (roster_base, policy_base) {
        (None, None) => Documents::from_signed(roster, policy).ok(),
        (Some(roster_base), Some(policy_base)) => {
            Documents::from_signed_with_base(roster, policy, roster_base, policy_base).ok()
        }
        _ => None,
    }
}

/// Looks at one network at `now`: reads the steward key (none, none to do), decides, warns, and
/// when the rule says so signs the next pair, writes it where the CLI writes it (under the
/// network lock) and adopts it into the stores, which tells the relay push. Blocks (file lock,
/// disk): run it where blocking is allowed. A failure is returned, and the next look is at the
/// next hour like after any other.
pub fn tick_network(
    home: &Home,
    rosters: &RosterStore,
    policies: &PolicyStore,
    network_id: &NetworkId,
    now: u64,
    state: &mut NetState,
) -> Result<Outcome> {
    if !home.steward_key_path(network_id).exists() {
        return Ok(Outcome::Idle);
    }
    // A look that failed before it knew the `seq` waits for the hour, like any other.
    if state.last.is_some_and(|last| last.seq.is_none()) && !tick_due(state.last, now, 0) {
        return Ok(Outcome::Idle);
    }
    let outcome = look(home, rosters, policies, network_id, now, state);
    if outcome.is_err() {
        let seen = state.last.and_then(|last| last.seq);
        state.last = Some(Tick { at: now, seq: seen });
    }
    outcome
}

fn look(
    home: &Home,
    rosters: &RosterStore,
    policies: &PolicyStore,
    network_id: &NetworkId,
    now: u64,
    state: &mut NetState,
) -> Result<Outcome> {
    // Cheap first: is it due at all, without the lock.
    let Some(early) = held_documents(home, rosters, policies, network_id)? else {
        return Ok(Outcome::Idle);
    };
    if !tick_due(state.last, now, early.seq()) {
        return Ok(Outcome::Idle);
    }
    state.last = Some(Tick {
        at: now,
        seq: Some(early.seq()),
    });
    let key = load_steward(home, network_id)?;
    // From reading the documents to writing the next ones, like every command that issues.
    let _lock = home.lock_network(network_id)?;
    let Some(held) = held_documents(home, rosters, policies, network_id)? else {
        return Ok(Outcome::Idle);
    };
    let facts = Facts::of(&held)?;
    let plan = decide(now, Some(key.public()), Some(&facts));
    if let Some(warning) = plan.warning
        && warn_due(state.last_warning, now)
    {
        state.last_warning = Some(now);
        let text = warning.text(network_id);
        tracing::warn!(network = %network_id, "{text}");
        eprintln!("warning: {text}");
    }
    if !plan.renew {
        return Ok(Outcome::Checked);
    }
    renew_and_adopt(home, rosters, policies, &key, &held, now, state)
}

fn renew_and_adopt(
    home: &Home,
    rosters: &RosterStore,
    policies: &PolicyStore,
    key: &StewardSecret,
    held: &Documents,
    now: u64,
    state: &mut NetState,
) -> Result<Outcome> {
    let next = menzil_admin::steward_renew(key, held, now)
        .context("signing the renewed documents as the steward")?;
    save_documents(home, &next).context("writing the renewed documents")?;
    state.last = Some(Tick {
        at: now,
        seq: Some(next.seq()),
    });
    DocStore::new(rosters, policies)
        .adopt(&next.bundle(), now)
        .context("adopting the renewed documents")?;
    Ok(Outcome::Renewed { seq: next.seq() })
}

/// Whether this device issues documents for the network (it holds the owner's or a steward's
/// key): only such a device pushes what it finds on disk to the members (protocol.md 5.5); a
/// member that merely took a newer token does not.
pub fn is_issuer(home: &Home, network_id: &NetworkId) -> bool {
    home.owner_key_path(network_id).exists() || home.steward_key_path(network_id).exists()
}

/// Pushes the held documents to the members in the background (the schedule takes hours) and
/// logs what came of it.
pub fn spawn_push(node: &Arc<Node>, network_id: NetworkId) -> JoinHandle<()> {
    let node = Arc::clone(node);
    tokio::spawn(async move {
        let report = node.push_to_members(network_id).await;
        tracing::info!(
            network = %network_id,
            done = report.done,
            rejected = report.rejected,
            gave_up = report.gave_up,
            "pushed the new documents to the members"
        );
    })
}

/// The current time, Unix seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The task: at start, then whenever a network is due, looks at every network this device
/// holds a steward key for and pushes what it renewed.
pub async fn run(
    home: Home,
    rosters: Arc<RosterStore>,
    policies: Arc<PolicyStore>,
    node: Arc<Node>,
) {
    let mut states: HashMap<NetworkId, NetState> = HashMap::new();
    loop {
        let networks = match home.networks() {
            Ok(networks) => networks,
            Err(error) => {
                tracing::warn!(error = %format!("{error:#}"), "the steward loop cannot list the networks");
                Vec::new()
            }
        };
        for network_id in networks {
            let mut state = states.remove(&network_id).unwrap_or_default();
            let (home, rosters, policies) = (home.clone(), rosters.clone(), policies.clone());
            let joined = tokio::task::spawn_blocking(move || {
                let result = tick_network(
                    &home,
                    &rosters,
                    &policies,
                    &network_id,
                    unix_now(),
                    &mut state,
                );
                (result, state)
            })
            .await;
            let Ok((result, state)) = joined else {
                tracing::warn!("the steward loop's check panicked");
                continue;
            };
            states.insert(network_id, state);
            match result {
                Ok(Outcome::Renewed { seq }) => {
                    tracing::info!(network = %network_id, seq, "renewed the network's documents as its steward");
                    eprintln!(
                        "menzil: renewed the documents of network {network_id} as its steward (#{seq})"
                    );
                    spawn_push(&node, network_id);
                }
                Ok(Outcome::Idle | Outcome::Checked) => {}
                Err(error) => {
                    tracing::warn!(network = %network_id, error = %format!("{error:#}"), "the steward renewal failed; trying again in an hour");
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests;
