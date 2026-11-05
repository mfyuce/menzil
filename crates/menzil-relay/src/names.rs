//! The durable name state of a relay (multi tenant design 2.2 and 2.3, slice MT9): which full
//! names are held, when each was first accepted and last advertised, and which names are in
//! quarantine. [`NameState`] is data and rules over an explicit clock (`now`, Unix seconds), with
//! a text form the relay binary keeps in `relay/names.state`; [`crate::LabelRegistry`] owns one
//! and decides ADVERTISE with it, `menzil::relay_cmd::names_state` reads and writes the file.
//!
//! # Names
//!
//! A full name is written relative to the relay's share domain `H`: the default tenant's label
//! `app` is `app` (`app.H`), tenant `ali`'s is `app.ali` (`app.ali.H`). A label never contains a
//! dot and neither does a slug, so a key is flat (no dot, the default tenant's, or a name the
//! operator granted a tenant through `extra_names`) or in one tenant's zone (one dot). The first
//! level of that namespace is one: a flat name and a slug are the same kind of label, which is
//! why rule 4 of the design keeps them apart.
//!
//! # Rules kept here
//!
//! - Quota per tenant: `names` held in all and `new_names_per_week` accepted for the first time
//!   in any 7 days (rule 7). An operator grant (`extra_names`) counts toward the first and is
//!   exempt from the second.
//! - Release: a name not advertised for [`RELEASE_DAYS`] days, and not held by a session now, is
//!   released (rule 8). A released flat name enters quarantine for [`QUARANTINE_DAYS`] days, bound
//!   to the network that held it: only that network may take it back meanwhile. A released name
//!   in a tenant's zone is simply free again (nobody else can ever get it).
//! - Quarantine of a removed tenant's slug is written by the operator's command (`remove-tenant`),
//!   not by the running relay, which keeps those entries when it writes the file.
//!
//! Nothing here reads a clock or a file.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use menzil_proto::NetworkId;

use crate::tenant::QUARANTINE_DAYS;

/// Days without an ADVERTISE after which a name is released (protocol.md 4.4, rule 8).
pub const RELEASE_DAYS: u64 = 90;
/// The window of "at most N names accepted for the first time" (rule 7), in days.
pub const NEW_NAMES_WINDOW_DAYS: u64 = 7;
/// A name that is advertised again is stamped again only after this long (seconds), so that a
/// node that re-advertises at every attach does not make the relay rewrite its file each time.
/// Far below [`RELEASE_DAYS`].
pub const TOUCH_SECS: u64 = DAY;

const DAY: u64 = 24 * 60 * 60;
const HEADER: &str = "menzil-names-state 1";

/// One full name the relay holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameRecord {
    /// The slug of the tenant the name belongs to; `None` is the default tenant.
    pub tenant: Option<String>,
    /// The network whose Roster granted the label when the name was last accepted.
    pub network: NetworkId,
    /// When the name was first accepted (Unix seconds).
    pub first: u64,
    /// When it was last advertised (Unix seconds, stamped at most once per [`TOUCH_SECS`]).
    pub last: u64,
}

/// What a quarantined first level label was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineKind {
    /// A flat name that was released or whose network was removed.
    Flat,
    /// The slug of a removed tenant.
    Slug,
}

/// A first level label nobody may take over for [`QUARANTINE_DAYS`] days (rule 9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantine {
    /// A flat name or a slug.
    pub kind: QuarantineKind,
    /// When the quarantine began (Unix seconds).
    pub since: u64,
    /// For a flat name: the tenant that held it (`None` is the default tenant).
    pub tenant: Option<String>,
    /// For a flat name: the network that held it, the one network that may take it back.
    pub network: Option<NetworkId>,
}

impl Quarantine {
    /// When the quarantine ends (Unix seconds).
    pub fn until(&self) -> u64 {
        self.since.saturating_add(QUARANTINE_DAYS * DAY)
    }
}

/// Why a name was not given to a claimant (see [`NameState::accept`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameRefusal {
    /// The name is held by another tenant (a flat name granted to a tenant, or the default
    /// tenant's).
    OtherTenant,
    /// The name is in quarantine for another network.
    Quarantined,
    /// The tenant is at its figure for names held, or for names new in a week.
    OverQuota,
}

/// A name a claimant wants, as [`NameState::accept`] judges it.
#[derive(Debug, Clone)]
pub struct Claim<'a> {
    /// The full name (see the module doc).
    pub full: &'a str,
    /// The tenant's slug; `None` is the default tenant.
    pub tenant: Option<&'a str>,
    /// The network whose Roster grants the label.
    pub network: NetworkId,
}

/// The figures [`NameState::accept`] holds a tenant to.
#[derive(Debug, Clone, Copy)]
pub struct NameFigures {
    /// Names held in all.
    pub names: u64,
    /// Names accepted for the first time in any 7 days.
    pub new_per_week: u64,
}

/// A file that is not a name state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {reason}")]
pub struct NamesStateError {
    /// The 1-based line.
    pub line: usize,
    /// What is wrong with it.
    pub reason: String,
}

/// The names the relay holds and the labels in quarantine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameState {
    /// Held names by full name.
    pub names: BTreeMap<String, NameRecord>,
    /// Quarantined first level labels (flat names and slugs).
    pub quarantine: BTreeMap<String, Quarantine>,
}

/// Whether a full name is flat (the default tenant's or an operator grant) and not in a zone.
fn is_flat(full: &str) -> bool {
    !full.contains('.')
}

impl NameState {
    /// This state without the slug quarantine entries: the part the running relay owns (the
    /// operator's `remove-tenant` owns the slug entries and the relay keeps them as it finds
    /// them on disk).
    #[must_use]
    pub fn relay_part(&self) -> Self {
        Self {
            names: self.names.clone(),
            quarantine: self
                .quarantine
                .iter()
                .filter(|(_, q)| q.kind == QuarantineKind::Flat)
                .map(|(name, q)| (name.clone(), q.clone()))
                .collect(),
        }
    }

    /// The flat names the default tenant has been accepted for or is quarantined for: a tenant
    /// name or an `extra_names` entry equal to one is refused (rule 4).
    pub fn default_flat_names(&self) -> HashSet<String> {
        let held = self
            .names
            .iter()
            .filter(|(full, record)| is_flat(full) && record.tenant.is_none())
            .map(|(full, _)| full.clone());
        let quarantined = self
            .quarantine
            .iter()
            .filter(|(_, q)| q.kind == QuarantineKind::Flat && q.tenant.is_none())
            .map(|(name, _)| name.clone());
        held.chain(quarantined).collect()
    }

    /// The slugs in quarantine at `now`, each with the moment it is free again.
    pub fn quarantined_slugs(&self, now: u64) -> BTreeMap<String, u64> {
        self.quarantine
            .iter()
            .filter(|(_, q)| q.kind == QuarantineKind::Slug && q.until() > now)
            .map(|(name, q)| (name.clone(), q.until()))
            .collect()
    }

    /// Puts a removed tenant's slug in quarantine from `now` (a later `since` for the same slug
    /// wins).
    pub fn quarantine_slug(&mut self, slug: &str, now: u64) {
        let since = self
            .quarantine
            .get(slug)
            .filter(|q| q.kind == QuarantineKind::Slug)
            .map_or(now, |q| q.since.max(now));
        self.quarantine.insert(
            slug.to_string(),
            Quarantine {
                kind: QuarantineKind::Slug,
                since,
                tenant: None,
                network: None,
            },
        );
    }

    /// Drops every quarantine entry whose time has passed. Whether anything changed.
    pub fn prune(&mut self, now: u64) -> bool {
        let before = self.quarantine.len();
        self.quarantine.retain(|_, q| q.until() > now);
        self.quarantine.len() != before
    }

    /// Judges a claim for `claim.full`, and records it if it is given. `figures` is `None` for a
    /// tenant without figures (the default tenant, the `personal` class): nothing is counted
    /// against it. A flat name of a named tenant is an operator grant (`extra_names`): it counts
    /// toward the names held but not toward the names new in a week. A name already held by the
    /// same tenant is
    /// always given again (its stamp moves at most once per [`TOUCH_SECS`]). The second field of
    /// the result is whether the state changed.
    pub fn accept(
        &mut self,
        claim: &Claim<'_>,
        figures: Option<NameFigures>,
        now: u64,
    ) -> (Result<(), NameRefusal>, bool) {
        let tenant = claim.tenant.map(str::to_string);
        let exempt_weekly = tenant.is_some() && is_flat(claim.full);
        if let Some(record) = self.names.get_mut(claim.full) {
            if record.tenant != tenant {
                return (Err(NameRefusal::OtherTenant), false);
            }
            let mut changed = false;
            if record.network != claim.network {
                record.network = claim.network;
                changed = true;
            }
            if now.saturating_sub(record.last) >= TOUCH_SECS {
                record.last = now;
                changed = true;
            }
            return (Ok(()), changed);
        }
        let mut cleared = false;
        if let Some(q) = self.quarantine.get(claim.full) {
            if q.until() <= now {
                self.quarantine.remove(claim.full);
                cleared = true;
            } else if q.kind == QuarantineKind::Slug || q.network != Some(claim.network) {
                return (Err(NameRefusal::Quarantined), false);
            } else {
                // The network that held it takes it back.
                self.quarantine.remove(claim.full);
                cleared = true;
            }
        }
        if let Some(figures) = figures {
            let mine = || self.names.values().filter(|r| r.tenant == tenant);
            let held = mine().count() as u64;
            let window = NEW_NAMES_WINDOW_DAYS * DAY;
            let new_this_week = self
                .names
                .iter()
                .filter(|(full, r)| {
                    r.tenant == tenant
                        && !(r.tenant.is_some() && is_flat(full))
                        && r.first.saturating_add(window) > now
                })
                .count() as u64;
            if held >= figures.names || (!exempt_weekly && new_this_week >= figures.new_per_week) {
                return (Err(NameRefusal::OverQuota), cleared);
            }
        }
        self.names.insert(
            claim.full.to_string(),
            NameRecord {
                tenant,
                network: claim.network,
                first: now,
                last: now,
            },
        );
        (Ok(()), true)
    }

    /// Stamps `full` as advertised at `now` (a session that held it has just left): at most once
    /// per [`TOUCH_SECS`]. Whether the state changed.
    pub fn touch(&mut self, full: &str, now: u64) -> bool {
        match self.names.get_mut(full) {
            Some(record) if now.saturating_sub(record.last) >= TOUCH_SECS => {
                record.last = now;
                true
            }
            _ => false,
        }
    }

    /// Releases `full` at `now`: it is removed, and a flat name enters quarantine bound to the
    /// network that held it.
    pub fn release(&mut self, full: &str, now: u64) -> bool {
        let Some(record) = self.names.remove(full) else {
            return false;
        };
        if is_flat(full) {
            self.quarantine.insert(
                full.to_string(),
                Quarantine {
                    kind: QuarantineKind::Flat,
                    since: now,
                    tenant: record.tenant,
                    network: Some(record.network),
                },
            );
        }
        true
    }

    /// Releases every name `keep` says no to; the held names it is asked about are the ones
    /// not for the session registry to keep. Whether anything changed.
    pub fn release_where(
        &mut self,
        now: u64,
        mut release: impl FnMut(&str, &NameRecord) -> bool,
    ) -> bool {
        let doomed: Vec<String> = self
            .names
            .iter()
            .filter(|(full, record)| release(full, record))
            .map(|(full, _)| full.clone())
            .collect();
        let changed = !doomed.is_empty();
        for full in doomed {
            self.release(&full, now);
        }
        changed
    }

    /// The periodic pass: names held by a session now are stamped (so a name held for months
    /// is not "unadvertised"), the others not advertised for [`RELEASE_DAYS`] days are released,
    /// and quarantines that ended are dropped. Whether anything changed.
    pub fn sweep(&mut self, now: u64, is_held: impl Fn(&str) -> bool) -> bool {
        let mut changed = false;
        let keys: Vec<String> = self.names.keys().cloned().collect();
        for full in keys {
            if is_held(&full) {
                changed |= self.touch(&full, now);
                continue;
            }
            let expired = self
                .names
                .get(&full)
                .is_some_and(|r| r.last.saturating_add(RELEASE_DAYS * DAY) <= now);
            if expired {
                changed |= self.release(&full, now);
            }
        }
        changed | self.prune(now)
    }

    /// The state as the text kept in `relay/names.state`.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "{HEADER}");
        for (full, r) in &self.names {
            let _ = writeln!(
                out,
                "name {full} {} {} {} {}",
                r.tenant.as_deref().unwrap_or("-"),
                r.network.to_hex(),
                r.first,
                r.last
            );
        }
        for (name, q) in &self.quarantine {
            let kind = match q.kind {
                QuarantineKind::Flat => "flat",
                QuarantineKind::Slug => "slug",
            };
            let _ = writeln!(
                out,
                "quarantine {kind} {name} {} {} {}",
                q.since,
                q.tenant.as_deref().unwrap_or("-"),
                q.network.map_or_else(|| "-".to_string(), |n| n.to_hex())
            );
        }
        out
    }

    /// The state from the text [`Self::render`] writes. Anything else is an error that names
    /// the line: a damaged state is never half used (an empty text is damaged, too).
    pub fn parse(text: &str) -> Result<Self, NamesStateError> {
        let mut lines = text.lines().enumerate();
        match lines.next() {
            Some((_, HEADER)) => {}
            _ => {
                return Err(NamesStateError {
                    line: 1,
                    reason: format!("the first line is not {HEADER:?}"),
                });
            }
        }
        let mut state = Self::default();
        for (index, line) in lines {
            let fail = |reason: &str| NamesStateError {
                line: index + 1,
                reason: reason.to_string(),
            };
            if line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split(' ').collect();
            match fields.as_slice() {
                ["name", full, tenant, network, first, last] => {
                    check_full_name(full, tenant).map_err(|r| fail(&r))?;
                    let record = NameRecord {
                        tenant: slug_or_none(tenant),
                        network: parse_network(network).ok_or_else(|| fail("not a network id"))?,
                        first: first.parse().map_err(|_| fail("not a number"))?,
                        last: last.parse().map_err(|_| fail("not a number"))?,
                    };
                    if state.names.insert((*full).to_string(), record).is_some() {
                        return Err(fail("a name is listed twice"));
                    }
                }
                ["quarantine", kind, name, since, tenant, network] => {
                    let kind = match *kind {
                        "flat" => QuarantineKind::Flat,
                        "slug" => QuarantineKind::Slug,
                        _ => return Err(fail("a quarantine is `flat` or `slug`")),
                    };
                    if !is_label(name) {
                        return Err(fail("not a label"));
                    }
                    if *tenant != "-" && !is_label(tenant) {
                        return Err(fail("not a tenant name"));
                    }
                    let network = match *network {
                        "-" => None,
                        hex => Some(parse_network(hex).ok_or_else(|| fail("not a network id"))?),
                    };
                    let quarantine = Quarantine {
                        kind,
                        since: since.parse().map_err(|_| fail("not a number"))?,
                        tenant: slug_or_none(tenant),
                        network,
                    };
                    if state
                        .quarantine
                        .insert((*name).to_string(), quarantine)
                        .is_some()
                    {
                        return Err(fail("a quarantined name is listed twice"));
                    }
                }
                _ => return Err(fail("not a `name` or `quarantine` line of the right shape")),
            }
        }
        Ok(state)
    }
}

fn slug_or_none(text: &str) -> Option<String> {
    (text != "-").then(|| text.to_string())
}

/// One lowercase LDH label of 1 to 63 characters.
fn is_label(text: &str) -> bool {
    (1..=63).contains(&text.len())
        && !text.starts_with('-')
        && !text.ends_with('-')
        && text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `full` is `label` (flat) or `label.slug`, and its zone is the tenant the line says.
fn check_full_name(full: &str, tenant: &str) -> Result<(), String> {
    match full.split_once('.') {
        None if is_label(full) => Ok(()),
        Some((label, slug)) if is_label(label) && is_label(slug) && !slug.contains('.') => {
            if tenant == slug {
                Ok(())
            } else {
                Err("a name in a tenant's zone names another tenant".to_string())
            }
        }
        _ => Err("not a name: `label` or `label.tenant`".to_string()),
    }
}

fn parse_network(hex: &str) -> Option<NetworkId> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
        let digit = |b: u8| (b as char).to_digit(16);
        out[i] = (digit(pair[0])? * 16 + digit(pair[1])?) as u8;
    }
    Some(NetworkId::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;
    const FIG: NameFigures = NameFigures {
        names: 20,
        new_per_week: 5,
    };

    fn net(n: u8) -> NetworkId {
        NetworkId::from([n; 32])
    }

    fn claim<'a>(full: &'a str, tenant: Option<&'a str>, n: u8) -> Claim<'a> {
        Claim {
            full,
            tenant,
            network: net(n),
        }
    }

    #[test]
    fn the_text_form_round_trips() {
        let mut state = NameState::default();
        assert!(state.accept(&claim("app", None, 1), None, NOW).0.is_ok());
        assert!(
            state
                .accept(&claim("blog.ali", Some("ali"), 2), Some(FIG), NOW + 5)
                .0
                .is_ok()
        );
        assert!(state.release("app", NOW + 9));
        state.quarantine_slug("gone", NOW + 11);
        let text = state.render();
        assert!(text.starts_with("menzil-names-state 1\n"));
        assert_eq!(NameState::parse(&text).unwrap(), state);
        assert_eq!(
            NameState::parse(&NameState::default().render()).unwrap(),
            NameState::default()
        );
    }

    #[test]
    fn a_damaged_text_is_an_error_naming_the_line() {
        let ok = format!("{HEADER}\nname app - {} 1 2\n", net(1).to_hex());
        assert!(NameState::parse(&ok).is_ok());
        for (text, line) in [
            (String::new(), 1),
            ("garbage\n".to_string(), 1),
            (format!("{HEADER}\nname app - nothex 1 2\n"), 2),
            (format!("{HEADER}\nname app - {} x 2\n", net(1).to_hex()), 2),
            (
                format!("{HEADER}\nname app.ali bob {} 1 2\n", net(1).to_hex()),
                2,
            ),
            (format!("{HEADER}\nname App - {} 1 2\n", net(1).to_hex()), 2),
            (format!("{HEADER}\nsomething else\n"), 2),
            (
                format!(
                    "{HEADER}\nname app - {n} 1 2\nname app - {n} 1 2\n",
                    n = net(1).to_hex()
                ),
                3,
            ),
            (format!("{HEADER}\nquarantine odd app 1 - -\n"), 2),
        ] {
            let error = NameState::parse(&text).unwrap_err();
            assert_eq!(error.line, line, "{text:?}: {error}");
        }
    }

    #[test]
    fn the_weekly_figure_counts_first_acceptances_in_any_seven_days() {
        let mut state = NameState::default();
        for i in 0..5 {
            let full = format!("n{i}.ali");
            assert!(
                state
                    .accept(&claim(&full, Some("ali"), 1), Some(FIG), NOW)
                    .0
                    .is_ok()
            );
        }
        let sixth = claim("n5.ali", Some("ali"), 1);
        assert_eq!(
            state.accept(&sixth, Some(FIG), NOW + 7 * DAY - 1).0,
            Err(NameRefusal::OverQuota)
        );
        // A name already held is always given again.
        assert!(
            state
                .accept(&claim("n0.ali", Some("ali"), 1), Some(FIG), NOW + 3 * DAY)
                .0
                .is_ok()
        );
        // Seven days after the first acceptances, the window has moved on.
        assert!(state.accept(&sixth, Some(FIG), NOW + 7 * DAY).0.is_ok());
    }

    #[test]
    fn the_figure_for_names_held_counts_every_name_and_not_another_tenants() {
        let figures = NameFigures {
            names: 3,
            new_per_week: 100,
        };
        let mut state = NameState::default();
        for i in 0..3 {
            let full = format!("n{i}.ali");
            assert!(
                state
                    .accept(&claim(&full, Some("ali"), 1), Some(figures), NOW)
                    .0
                    .is_ok()
            );
        }
        assert_eq!(
            state
                .accept(&claim("n3.ali", Some("ali"), 1), Some(figures), NOW)
                .0,
            Err(NameRefusal::OverQuota)
        );
        assert!(
            state
                .accept(&claim("n0.bob", Some("bob"), 2), Some(figures), NOW)
                .0
                .is_ok()
        );
    }

    #[test]
    fn a_grant_counts_toward_the_names_held_and_not_toward_the_week() {
        let figures = NameFigures {
            names: 4,
            new_per_week: 1,
        };
        let mut state = NameState::default();
        // The one ordinary name uses the weekly figure of 1 up; the grants after it are still
        // given, and the names held count all four.
        assert!(
            state
                .accept(&claim("a.ali", Some("ali"), 1), Some(figures), NOW)
                .0
                .is_ok()
        );
        assert_eq!(
            state
                .accept(&claim("b.ali", Some("ali"), 1), Some(figures), NOW)
                .0,
            Err(NameRefusal::OverQuota),
            "a second ordinary name is over the week"
        );
        for grant in ["blog", "shop", "docs"] {
            assert!(
                state
                    .accept(&claim(grant, Some("ali"), 1), Some(figures), NOW)
                    .0
                    .is_ok(),
                "{grant}"
            );
        }
        // The fifth name is over the figure for names held, grants included.
        assert_eq!(
            state
                .accept(&claim("wiki", Some("ali"), 1), Some(figures), NOW)
                .0,
            Err(NameRefusal::OverQuota)
        );
    }

    #[test]
    fn a_name_not_advertised_for_ninety_days_is_released_and_a_flat_one_is_quarantined() {
        let mut state = NameState::default();
        let _ = state.accept(&claim("app", None, 1), None, NOW);
        let _ = state.accept(&claim("app.ali", Some("ali"), 2), Some(FIG), NOW);
        assert!(!state.sweep(NOW + 90 * DAY - 1, |_| false));
        assert!(state.sweep(NOW + 90 * DAY, |_| false));
        assert!(state.names.is_empty());
        let q = &state.quarantine["app"];
        assert_eq!(
            (q.kind, q.network, q.since),
            (QuarantineKind::Flat, Some(net(1)), NOW + 90 * DAY)
        );
        assert!(
            !state.quarantine.contains_key("app.ali"),
            "a zone name is free at once, not quarantined"
        );
        // Quarantine ends after 180 days.
        assert!(!state.prune(NOW + 90 * DAY + 180 * DAY - 1));
        assert!(state.prune(NOW + 90 * DAY + 180 * DAY));
        assert!(state.quarantine.is_empty());
    }

    #[test]
    fn a_name_held_by_a_session_is_stamped_not_released() {
        let mut state = NameState::default();
        let _ = state.accept(&claim("app", None, 1), None, NOW);
        let later = NOW + 200 * DAY;
        assert!(state.sweep(later, |name| name == "app"));
        assert_eq!(state.names["app"].last, later);
        // Stamped at most once a day.
        assert!(!state.sweep(later + 60, |name| name == "app"));
    }

    #[test]
    fn a_quarantined_flat_name_goes_back_only_to_the_network_that_held_it() {
        let mut state = NameState::default();
        let _ = state.accept(&claim("app", None, 1), None, NOW);
        state.release("app", NOW + DAY);
        assert_eq!(
            state.accept(&claim("app", None, 2), None, NOW + 2 * DAY).0,
            Err(NameRefusal::Quarantined)
        );
        let (back, changed) = state.accept(&claim("app", None, 1), None, NOW + 2 * DAY);
        assert!(back.is_ok() && changed);
        assert!(state.quarantine.is_empty());
        // After the quarantine, anybody.
        state.release("app", NOW + 3 * DAY);
        assert!(
            state
                .accept(&claim("app", None, 2), None, NOW + 3 * DAY + 180 * DAY)
                .0
                .is_ok()
        );
    }

    #[test]
    fn a_name_of_another_tenant_or_a_quarantined_slug_is_not_given() {
        let mut state = NameState::default();
        let _ = state.accept(&claim("blog", Some("ali"), 1), None, NOW);
        assert_eq!(
            state.accept(&claim("blog", None, 2), None, NOW).0,
            Err(NameRefusal::OtherTenant)
        );
        state.quarantine_slug("gone", NOW);
        assert_eq!(
            state.accept(&claim("gone", None, 2), None, NOW + DAY).0,
            Err(NameRefusal::Quarantined)
        );
        assert_eq!(
            state.quarantined_slugs(NOW + DAY).get("gone"),
            Some(&(NOW + 180 * DAY))
        );
    }

    #[test]
    fn the_relay_part_keeps_no_slug_and_the_default_names_are_the_default_tenants() {
        let mut state = NameState::default();
        let _ = state.accept(&claim("app", None, 1), None, NOW);
        let _ = state.accept(&claim("blog", Some("ali"), 1), None, NOW);
        let _ = state.accept(&claim("x.ali", Some("ali"), 1), None, NOW);
        state.quarantine_slug("gone", NOW);
        assert_eq!(
            state.default_flat_names(),
            ["app".to_string()].into_iter().collect()
        );
        assert!(state.relay_part().quarantine.is_empty());
        state.release("app", NOW);
        assert!(
            state.default_flat_names().contains("app"),
            "quarantined still counts"
        );
    }
}
