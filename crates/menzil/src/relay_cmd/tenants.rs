//! Tenants on the relay machine (multi tenant design 2.1, slice MT6): the files
//! `<home>/relay/tenants/<slug>.toml`, and the operator commands that change them together with
//! the Roster files (`relay add-network --tenant`, `remove-network`, `remove-tenant`, and the
//! listing `relay tenants`).
//!
//! A tenant file is written by the CLI and may be edited by hand:
//!
//! ```toml
//! networks = ["<64 hex digits>", ...]
//! class = "friend"          # or "personal"; absent means friend
//! terminated = false
//! extra_names = []          # exact flat names the operator grants this tenant
//! added = 1790000000        # Unix seconds
//! names = 30                # optional: any figure of the class (menzil_relay::Figures::KEYS)
//! ```
//!
//! A network no tenant file lists belongs to the default tenant (flat names, `personal` class),
//! so a relay directory without tenant files is the relay it was before tenants. Nothing here
//! enforces a figure on a session; the CLI only refuses to give a tenant more networks than its
//! class allows.
//!
//! Every command that changes the directory holds `lock_relay`, the lock `add-network` always
//! took, and orders its writes so that a failure half way can only leave a network listed but
//! not served, never served by the default tenant by mistake: `add-network` writes the tenant
//! file before the Roster, `remove-network` and `remove-tenant` delete the Roster files before
//! the tenant file.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;

use anyhow::{Context, Result, anyhow, bail};
use menzil_proto::NetworkId;
use menzil_relay::{
    Class, Figures, QUARANTINE_DAYS, Refusal, Slug, Tenant, TenantBook, TenantId, TenantSpec,
};
use serde::Deserialize;

use super::{Keep, StoredRoster, keep_roster_locked, load_rosters_each, relay_dir, roster_path};
use crate::home::{Home, parse_hex32};
use crate::token::decode_roster;

const DAY: u64 = 24 * 60 * 60;

/// The directory of tenant files.
pub fn tenants_dir(home: &Home) -> std::path::PathBuf {
    relay_dir(home).join("tenants")
}

fn tenant_path(home: &Home, slug: &str) -> std::path::PathBuf {
    tenants_dir(home).join(format!("{slug}.toml"))
}

/// The removed slugs and when they were removed, one `<slug> <unix>` per line. A slug stays
/// here for [`QUARANTINE_DAYS`] and is refused for a new tenant meanwhile (design 2.2, rule 9).
/// MT9 moves this into `names.state` with the rest of the durable name state.
fn quarantine_path(home: &Home) -> std::path::PathBuf {
    tenants_dir(home).join(".quarantine")
}

/// What a tenant file holds. The figures are the keys that are none of the others
/// ([`Figures::KEYS`]); the book judges them.
#[derive(Debug, Deserialize)]
struct TenantFile {
    #[serde(default)]
    networks: Vec<String>,
    class: Option<String>,
    #[serde(default)]
    terminated: bool,
    #[serde(default)]
    extra_names: Vec<String>,
    #[serde(default)]
    added: u64,
    #[serde(flatten)]
    figures: BTreeMap<String, u64>,
}

impl TenantFile {
    fn networks(&self) -> Result<Vec<NetworkId>> {
        self.networks
            .iter()
            .map(|text| {
                parse_hex32(text)
                    .map(NetworkId::from)
                    .ok_or_else(|| anyhow!("{text:?} is not a network id (64 hex digits)"))
            })
            .collect()
    }

    fn class(&self) -> Result<Class> {
        match &self.class {
            None => Ok(Class::Friend),
            Some(text) => Class::parse(text)
                .ok_or_else(|| anyhow!("class {text:?} is not `friend` or `personal`")),
        }
    }

    fn spec(&self, slug: Slug) -> Result<TenantSpec> {
        Ok(TenantSpec {
            slug,
            networks: self.networks()?,
            class: self.class()?,
            overrides: self.figures.clone(),
            terminated: self.terminated,
            extra_names: self.extra_names.clone(),
            added: self.added,
        })
    }

    fn of_spec(spec: &TenantSpec) -> Self {
        Self {
            networks: spec.networks.iter().map(NetworkId::to_hex).collect(),
            class: Some(spec.class.as_str().to_string()),
            terminated: spec.terminated,
            extra_names: spec.extra_names.clone(),
            added: spec.added,
            figures: spec.overrides.clone(),
        }
    }

    /// The file as text: the fields, then the figure overrides.
    fn render(&self) -> String {
        let mut out = String::from(
            "# A tenant of this relay (menzil relay add-network --tenant). Edit by hand if you\n# like; `menzil relay tenants` shows what the relay makes of it. Comments are not kept\n# when a command rewrites the file.\n",
        );
        let quoted = |items: &[String]| {
            items
                .iter()
                .map(|item| format!("{item:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let _ = writeln!(out, "networks = [{}]", quoted(&self.networks));
        if let Some(class) = &self.class {
            let _ = writeln!(out, "class = {class:?}");
        }
        let _ = writeln!(out, "terminated = {}", self.terminated);
        let _ = writeln!(out, "extra_names = [{}]", quoted(&self.extra_names));
        let _ = writeln!(out, "added = {}", self.added);
        for (key, value) in &self.figures {
            let _ = writeln!(out, "{key} = {value}");
        }
        out
    }
}

/// The networks a tenant file lists, as far as they can be read from a file whose other fields
/// may be wrong: so that a file the book refuses still holds its networks back.
fn salvage_networks(text: &str) -> Vec<NetworkId> {
    let Ok(table) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    table
        .get("networks")
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .filter_map(parse_hex32)
                .map(NetworkId::from)
                .collect()
        })
        .unwrap_or_default()
}

/// The tenant files of the relay directory: the ones that make a [`TenantSpec`], and the ones
/// that cannot (a file name that is not a slug, a field that is wrong), each with the networks
/// it lists so that they are held back. A file that cannot be read, or is not TOML at all, is an
/// error for the whole call: its networks are unknown, and serving them as the default
/// tenant's would hand them the most generous class. No directory is no tenants.
pub fn read_specs(home: &Home) -> Result<(Vec<TenantSpec>, Vec<Refusal>)> {
    let dir = tenants_dir(home);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let (mut specs, mut refused) = (Vec::new(), Vec::new());
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Some(name) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        let _syntax: toml::Table = text
            .parse()
            .with_context(|| format!("{} is not a valid tenant file", path.display()))?;
        let judged = Slug::parse(&name)
            .map_err(|e| anyhow!("{e}"))
            .and_then(|slug| {
                let file: TenantFile = toml::from_str(&text).map_err(|e| anyhow!("{e}"))?;
                file.spec(slug)
            });
        match judged {
            Ok(spec) => specs.push(spec),
            Err(error) => refused.push(Refusal {
                name,
                reason: format!("{error:#}"),
                networks: salvage_networks(&text),
            }),
        }
    }
    specs.sort_by(|a, b| a.slug.cmp(&b.slug));
    refused.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((specs, refused))
}

/// The flat names the default tenant holds: the labels of the Rosters of the networks no
/// tenant file lists.
fn default_names(rosters: &[StoredRoster], listed: &HashSet<NetworkId>) -> HashSet<String> {
    rosters
        .iter()
        .filter_map(|stored| stored.roster.decode().ok())
        .filter(|body| !listed.contains(&body.network_id))
        .flat_map(|body| body.labels)
        .map(|label| label.name.to_ascii_lowercase())
        .collect()
}

fn listed_networks(specs: &[TenantSpec], refused: &[Refusal]) -> HashSet<NetworkId> {
    specs
        .iter()
        .flat_map(|spec| spec.networks.iter())
        .chain(refused.iter().flat_map(|r| r.networks.iter()))
        .copied()
        .collect()
}

/// The tenants the relay directory describes, judged with the Rosters it holds (`rosters`, as
/// [`load_rosters_each`] read them). An error means the tenant files cannot be told apart from
/// what the operator wrote (see [`read_specs`]): at start the relay does not run, at a reload
/// it keeps the book it has.
pub fn load_book(home: &Home, rosters: &[StoredRoster]) -> Result<TenantBook> {
    let (specs, refused) = read_specs(home)?;
    let names = default_names(rosters, &listed_networks(&specs, &refused));
    Ok(TenantBook::build(specs, refused, &names))
}

/// What the operator should hear about the book: refused files, conflicts, and tenants that list
/// a network this relay holds no Roster for.
pub fn book_notes(book: &TenantBook, rosters: &[StoredRoster]) -> Vec<String> {
    let held: HashSet<NetworkId> = rosters
        .iter()
        .filter_map(|stored| stored.roster.decode().ok())
        .map(|body| body.network_id)
        .collect();
    let mut notes = Vec::new();
    for refusal in book.refused() {
        notes.push(format!(
            "tenant file {}.toml is not used: {}; its {} network(s) are not served",
            refusal.name,
            refusal.reason,
            refusal.networks.len()
        ));
    }
    notes.extend(book.warnings().iter().cloned());
    for tenant in book.tenants() {
        for network in &tenant.networks {
            if !held.contains(network) {
                notes.push(format!(
                    "tenant {} lists network {network}, which has no Roster here: `menzil relay add-network` it",
                    tenant.id
                ));
            }
        }
    }
    notes
}

fn read_quarantine(home: &Home) -> Result<BTreeMap<String, u64>> {
    let path = quarantine_path(home);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut removed = BTreeMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let (slug, at) = line
            .split_once(' ')
            .and_then(|(slug, at)| Some((slug, at.trim().parse::<u64>().ok()?)))
            .ok_or_else(|| anyhow!("{} has a line that is not `<slug> <unix>`", path.display()))?;
        removed.insert(slug.to_string(), at);
    }
    Ok(removed)
}

/// Removed slugs still in quarantine at `now`, with the moment each is free again.
fn quarantined(home: &Home, now: u64) -> Result<BTreeMap<String, u64>> {
    Ok(read_quarantine(home)?
        .into_iter()
        .map(|(slug, at)| (slug, at.saturating_add(QUARANTINE_DAYS * DAY)))
        .filter(|(_, until)| *until > now)
        .collect())
}

fn write_quarantine(home: &Home, removed: &BTreeMap<String, u64>) -> Result<()> {
    let text: String = removed
        .iter()
        .map(|(slug, at)| format!("{slug} {at}\n"))
        .collect();
    home.write_public(&quarantine_path(home), text.as_bytes())
}

/// What `add-network` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Added {
    /// The network.
    pub network_id: NetworkId,
    /// The `seq` of the Roster now kept.
    pub seq: u64,
    /// The tenant it belongs to; `None` is the default tenant.
    pub tenant: Option<String>,
    /// Things the operator should read.
    pub warnings: Vec<String>,
}

/// The warning for a relay that gains a second tenant (design 2.2, rule 12).
const PSL_WARNING: &str = "this relay now has more than one tenant: until the relay's host name is on the Public Suffix List, a blind share of one tenant can set a cookie for the whole host that the browser sends to another tenant's shares; and one tenant's abuse can get the host blocklisted for all of them. `menzil relay remove-tenant` is the remedy";

/// `add-network`, optionally into a tenant. With `tenant` the network is assigned to it (the
/// tenant is made, with the `friend` class, if no file exists; a slug in quarantine, a name that
/// clashes with the default tenant's or a grant of another tenant, and more networks than the
/// class allows are refused, and nothing is written). A network already in a tenant stays in it
/// when `tenant` is `None` (a newer token renews it), and cannot be moved by `tenant`: remove
/// it first.
pub fn add_network_to(home: &Home, token: &str, now: u64, tenant: Option<&str>) -> Result<Added> {
    let (roster, base) = decode_roster(token)?;
    let network_id = roster.decode()?.network_id;
    let _lock = home.lock_relay()?;

    let mut warnings = Vec::new();
    let mut restore: Option<(std::path::PathBuf, Option<Vec<u8>>)> = None;
    let mut assigned: Option<String> = None;
    match tenant {
        None => {
            // Where the network is now, for the report; a broken tenant file does not stop a
            // renewal, which touches no tenant file.
            if let Ok((specs, _)) = read_specs(home) {
                assigned = specs
                    .iter()
                    .find(|spec| spec.networks.contains(&network_id))
                    .map(|spec| spec.slug.to_string());
            }
        }
        Some(text) => {
            let slug = Slug::parse(text).map_err(|e| anyhow!("{e}"))?;
            let (mut specs, refused) = read_specs(home)?;
            if let Some(other) = specs
                .iter()
                .find(|s| s.networks.contains(&network_id) && s.slug != slug)
            {
                bail!(
                    "network {network_id} is already in tenant {}: `menzil relay remove-network` it first",
                    other.slug
                );
            }
            if refused.iter().any(|r| r.networks.contains(&network_id)) {
                bail!(
                    "network {network_id} is listed by a tenant file that is not used (see `menzil relay tenants`): fix or remove that file first"
                );
            }
            let existing = specs.iter().position(|spec| spec.slug == slug);
            let created = existing.is_none();
            if created {
                if let Some(until) = quarantined(home, now)?.get(slug.as_str()) {
                    bail!(
                        "the name {slug} belonged to a tenant that was removed; it cannot be used again until {until} (Unix time, {QUARANTINE_DAYS} days after the removal)"
                    );
                }
                specs.push(TenantSpec {
                    slug: slug.clone(),
                    networks: Vec::new(),
                    class: Class::Friend,
                    overrides: BTreeMap::new(),
                    terminated: false,
                    extra_names: Vec::new(),
                    added: now,
                });
            }
            let at = specs
                .iter()
                .position(|spec| spec.slug == slug)
                .expect("the spec is there");
            if !specs[at].networks.contains(&network_id) {
                specs[at].networks.push(network_id);
            }
            // Judge the result as the relay would.
            let (rosters, _) = load_rosters_each(home)?;
            let names = default_names(&rosters, &listed_networks(&specs, &refused));
            let others_before = specs.len() - usize::from(created);
            let had_default_networks = rosters.iter().any(|stored| {
                stored
                    .roster
                    .decode()
                    .is_ok_and(|b| !listed_networks(&specs, &refused).contains(&b.network_id))
            });
            let trial = TenantBook::build(specs.clone(), refused, &names);
            if let Some(refusal) = trial.refused().iter().find(|r| r.name == slug.as_str()) {
                bail!("tenant {slug} cannot take it: {}", refusal.reason);
            }
            if let Some(figures) = trial.named(slug.as_str()).and_then(|t| t.figures)
                && specs[at].networks.len() as u64 > figures.max_networks
            {
                bail!(
                    "tenant {slug} may have {} network(s) (its class's figure); remove one first or raise `max_networks` in {}",
                    figures.max_networks,
                    tenant_path(home, slug.as_str()).display()
                );
            }
            if created && (others_before > 0 || had_default_networks) {
                warnings.push(PSL_WARNING.to_string());
            }
            let path = tenant_path(home, slug.as_str());
            let before = match fs::read(&path) {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == ErrorKind::NotFound => None,
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            };
            let text = TenantFile::of_spec(&specs[at]).render();
            home.write_public(&path, text.as_bytes())?;
            restore = Some((path, before));
            assigned = Some(slug.to_string());
        }
    }

    // The tenant file lists the network first (listed but not served is harmless); the Roster
    // follows, and a refusal of the token undoes the tenant file.
    let kept = keep_roster_locked(home, &roster, base.as_ref(), now, Keep::Create)
        .and_then(|kept| kept.ok_or_else(|| anyhow!("the Roster was not kept")));
    let (network_id, seq) = match kept {
        Ok(kept) => kept,
        Err(error) => {
            if let Some((path, before)) = restore {
                let _ = match before {
                    Some(bytes) => home.write_public(&path, &bytes),
                    None => fs::remove_file(&path).map_err(Into::into),
                };
            }
            return Err(error);
        }
    };
    Ok(Added {
        network_id,
        seq,
        tenant: assigned,
        warnings,
    })
}

/// What `remove-network` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    /// The network.
    pub network_id: NetworkId,
    /// The tenant that listed it, if one did.
    pub tenant: Option<String>,
    /// Things the operator should read.
    pub warnings: Vec<String>,
}

fn remove_if_there(path: &std::path::Path) -> Result<bool> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

/// `relay remove-network <network>`: the relay stops serving the network. Its Roster file is
/// deleted and any tenant file that lists it is rewritten without it; a running relay drops the
/// network at its next reload, ends the sessions that claimed it (`not_member`), and its keeper
/// never writes the file again (it only updates files that are there).
pub fn remove_network(home: &Home, network: &str) -> Result<Removed> {
    let id = parse_hex32(network.trim())
        .map(NetworkId::from)
        .ok_or_else(|| anyhow!("{network:?} is not a network id (64 hex digits)"))?;
    let Some(_lock) = home.lock_relay_if_held()? else {
        bail!("this relay serves no network");
    };
    let mut warnings = Vec::new();
    let mut tenant = None;
    let listed = match tenant_files_listing(home, &id) {
        Ok(listed) => listed,
        Err(error) => {
            warnings.push(format!(
                "the tenant files could not be read ({error:#}): the Roster is removed, a tenant file may still list the network"
            ));
            Vec::new()
        }
    };
    let had_file = remove_if_there(&roster_path(home, &id))?;
    if !had_file && listed.is_empty() {
        bail!("this relay does not serve network {id}");
    }
    for (slug, mut file) in listed {
        let id_text = id.to_hex();
        file.networks.retain(|n| !n.eq_ignore_ascii_case(&id_text));
        home.write_public(&tenant_path(home, &slug), file.render().as_bytes())?;
        tenant = Some(slug);
    }
    Ok(Removed {
        network_id: id,
        tenant,
        warnings,
    })
}

/// The tenant files that list `id`, with their content (files that do not parse are skipped:
/// [`read_specs`] reports them).
fn tenant_files_listing(home: &Home, id: &NetworkId) -> Result<Vec<(String, TenantFile)>> {
    let dir = tenants_dir(home);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut found = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        if !salvage_networks(&text).contains(id) {
            continue;
        }
        let file: TenantFile = toml::from_str(&text)
            .with_context(|| format!("{} cannot be rewritten", path.display()))?;
        found.push((name.to_string(), file));
    }
    Ok(found)
}

/// `relay remove-tenant <slug>`: deletes the tenant's Roster files and then its file, and puts
/// the slug in quarantine for [`QUARANTINE_DAYS`] days. Returns the networks it listed. A
/// running relay drops them at its next reload, like `remove-network`.
pub fn remove_tenant(home: &Home, slug: &str, now: u64) -> Result<Vec<NetworkId>> {
    let slug = Slug::parse(slug).map_err(|e| anyhow!("{e}"))?;
    let Some(_lock) = home.lock_relay_if_held()? else {
        bail!("this relay has no tenant {slug}");
    };
    let path = tenant_path(home, slug.as_str());
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => bail!("this relay has no tenant {slug}"),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let networks = salvage_networks(&text);
    for network in &networks {
        remove_if_there(&roster_path(home, network))?;
    }
    let mut removed = read_quarantine(home)?;
    removed.insert(slug.to_string(), now);
    write_quarantine(home, &removed)?;
    remove_if_there(&path)?;
    Ok(networks)
}

/// `relay tenants`: every tenant with its class, networks, grants and the state of each Roster,
/// then the tenant files the relay refuses and the slugs in quarantine.
pub fn render_tenants(home: &Home, now: u64) -> Result<String> {
    let (rosters, failures) = load_rosters_each(home)?;
    let book = load_book(home, &rosters)?;
    let seq_of = |network: &NetworkId| {
        rosters
            .iter()
            .filter_map(|stored| stored.roster.decode().ok())
            .find(|body| &body.network_id == network)
            .map(|body| body.seq)
    };
    let listed: HashSet<NetworkId> = book
        .tenants()
        .flat_map(|t| t.networks.iter())
        .chain(book.refused().iter().flat_map(|r| r.networks.iter()))
        .copied()
        .collect();
    let mut out = String::new();
    for tenant in book.tenants() {
        let networks: Vec<NetworkId> = match tenant.id {
            TenantId::Default => rosters
                .iter()
                .filter_map(|stored| stored.roster.decode().ok())
                .map(|body| body.network_id)
                .filter(|id| !listed.contains(id))
                .collect(),
            TenantId::Named(_) => tenant.networks.clone(),
        };
        out.push_str(&tenant_heading(tenant, networks.len()));
        for network in &networks {
            match seq_of(network) {
                Some(seq) => {
                    let _ = writeln!(out, "  network {network}  Roster #{seq}");
                }
                None => {
                    let _ = writeln!(out, "  network {network}  no Roster here");
                }
            }
        }
    }
    for refusal in book.refused() {
        let _ = writeln!(
            out,
            "not used: {}.toml: {} ({} network(s) not served)",
            refusal.name,
            refusal.reason,
            refusal.networks.len()
        );
        for network in &refusal.networks {
            let _ = writeln!(out, "  network {network}  held back");
        }
    }
    for note in book.warnings() {
        let _ = writeln!(out, "warning: {note}");
    }
    for failure in &failures {
        let _ = writeln!(out, "warning: {failure:#}");
    }
    for (slug, until) in quarantined(home, now)? {
        let _ = writeln!(out, "quarantine: {slug} cannot be used again until {until}");
    }
    Ok(out)
}

fn tenant_heading(tenant: &Tenant, count: usize) -> String {
    let mut line = format!("tenant {}  class {}", tenant.id, tenant.class.as_str());
    match tenant.figures {
        Some(Figures {
            max_networks: networks,
            ..
        }) => {
            let _ = write!(line, "  networks {count}/{networks}");
        }
        None => {
            let _ = write!(line, "  networks {count}");
        }
    }
    if tenant.terminated {
        line.push_str("  terminated");
    }
    if tenant.added > 0 {
        let _ = write!(line, "  added {}", tenant.added);
    }
    line.push('\n');
    if !tenant.extra_names.is_empty() {
        let _ = writeln!(line, "  grants: {}", tenant.extra_names.join(", "));
    }
    line
}
