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
//! suspended = false         # true: the relay does not serve the tenant's networks (see below)
//! extra_names = []          # exact flat names the operator grants this tenant
//! added = 1790000000        # Unix seconds
//! names = 30                # optional: any figure of the class (menzil_relay::Figures::KEYS)
//! ```
//!
//! `suspended = true` (`relay suspend-tenant`, `resume-tenant`) holds the tenant's networks back
//! like a refused file: not served, their sessions end at the relay's next reload, and they never
//! fall to the default tenant. The file, the slug, the figures and `terminated` stay as they are.
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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;

use anyhow::{Context, Result, anyhow, bail};
use menzil_proto::NetworkId;
use menzil_relay::{
    Class, Figures, QUARANTINE_DAYS, Refusal, Slug, Tenant, TenantBook, TenantId, TenantSpec,
};
use serde::Deserialize;

use super::{
    Keep, StoredRoster, keep_roster_locked, load_rosters_each, names_state, relay_dir, roster_path,
};
use crate::home::{Home, parse_hex32};
use crate::token::decode_roster;

/// The directory of tenant files.
pub fn tenants_dir(home: &Home) -> std::path::PathBuf {
    relay_dir(home).join("tenants")
}

fn tenant_path(home: &Home, slug: &str) -> std::path::PathBuf {
    tenants_dir(home).join(format!("{slug}.toml"))
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
    suspended: bool,
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
            // A spec says nothing of suspension: the callers that rewrite from a spec refuse a
            // suspended tenant first.
            suspended: false,
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
        if self.suspended {
            out.push_str("suspended = true\n");
        }
        let _ = writeln!(out, "extra_names = [{}]", quoted(&self.extra_names));
        let _ = writeln!(out, "added = {}", self.added);
        for (key, value) in &self.figures {
            let _ = writeln!(out, "{key} = {value}");
        }
        out
    }
}

/// The networks a tenant file lists, as far as they can be read from a file whose other fields
/// may be wrong: so that a file the book refuses still holds its networks back. A file whose
/// `networks` cannot be read at all (not TOML, `networks` not an array, an element that is not
/// 64 hex digits) is an error: its networks are unknown, and a caller that carried on would let
/// them fall to the default tenant, the most generous class (round T4, L1). No `networks` key is
/// no networks.
fn salvage_networks(text: &str) -> Result<Vec<NetworkId>> {
    let table: toml::Table = text.parse().context("not valid TOML")?;
    let Some(value) = table.get("networks") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| anyhow!("`networks` is not a list of network ids"))?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .and_then(parse_hex32)
                .map(NetworkId::from)
                .ok_or_else(|| anyhow!("`networks` has an entry that is not a network id: {item}"))
        })
        .collect()
}

/// The tenant files of the relay directory: the ones that make a [`TenantSpec`], and the ones
/// that cannot (a file name that is not a slug, a field that is wrong), each with the networks
/// it lists so that they are held back. A file that cannot be read, or is not TOML at all, is an
/// error for the whole call: its networks are unknown, and serving them as the default
/// tenant's would hand them the most generous class. No directory is no tenants.
pub fn read_specs(home: &Home) -> Result<(Vec<TenantSpec>, Vec<Refusal>)> {
    let (files, refused) = read_files(home)?;
    Ok((files.into_iter().map(|(spec, _)| spec).collect(), refused))
}

/// [`read_specs`] with, for each spec, whether its file says `suspended = true`.
/// A tenant file that made a spec, with whether it says `suspended = true`.
type SpecFile = (TenantSpec, bool);

fn read_files(home: &Home) -> Result<(Vec<SpecFile>, Vec<Refusal>)> {
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
                file.spec(slug).map(|spec| (spec, file.suspended))
            });
        match judged {
            Ok(pair) => specs.push(pair),
            Err(error) => refused.push(Refusal {
                name,
                reason: format!("{error:#}"),
                networks: salvage_networks(&text).with_context(|| {
                    format!(
                        "{} cannot be used and its networks cannot be told",
                        path.display()
                    )
                })?,
            }),
        }
    }
    specs.sort_by(|a, b| a.0.slug.cmp(&b.0.slug));
    refused.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((specs, refused))
}

fn listed_networks(specs: &[TenantSpec], refused: &[Refusal]) -> HashSet<NetworkId> {
    specs
        .iter()
        .flat_map(|spec| spec.networks.iter())
        .chain(refused.iter().flat_map(|r| r.networks.iter()))
        .copied()
        .collect()
}

/// The tenants the relay directory describes, judged with the name state (`names.state`). The
/// Rosters (`_rosters`, as [`load_rosters_each`] read them) no longer take part in the judgement
/// (round T5, M1); the parameter stays for the callers. An error means the tenant files cannot be told apart from
/// what the operator wrote (see [`read_specs`]): at start the relay does not run, at a reload
/// it keeps the book it has.
pub fn load_book(home: &Home, _rosters: &[StoredRoster]) -> Result<TenantBook> {
    let (files, refused) = read_files(home)?;
    let suspended: Vec<Slug> = files
        .iter()
        .filter(|(_, suspended)| *suspended)
        .map(|(spec, _)| spec.slug.clone())
        .collect();
    let specs = files.into_iter().map(|(spec, _)| spec).collect();
    let names = FlatNames::read(home)?;
    // Removed slugs still in quarantine: a file that brings one back is refused (design 2.2,
    // rule 1; round T4, N5).
    let removed: HashSet<String> = quarantined(home, super::unix_now())?.into_keys().collect();
    let mut book = names.build(specs, refused, &removed);
    // A suspended tenant stays in the book; its networks are held back (K1).
    for slug in &suspended {
        book.suspend(slug);
    }
    Ok(book)
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

/// Removed slugs still in quarantine at `now`, with the moment each is free again (they live in
/// `relay/names.state` with the rest of the durable name state, see `names_state`).
fn quarantined(home: &Home, now: u64) -> Result<BTreeMap<String, u64>> {
    names_state::quarantined_slugs(home, now)
}

/// The flat names the relay has accepted (or holds in quarantine) for the default tenant and for
/// named tenants, from `names.state`. Tenant names and grants are judged against these and not
/// against labels a default tenant's Roster merely lists: an owner can put any label in a Roster
/// that reaches the relay, and that must not take an older tenant offline (round T5, M1). A label
/// like that stays refused when it is advertised (`TenantBook::reserves_flat_name`).
struct FlatNames {
    default: HashSet<String>,
    tenants: HashMap<String, String>,
}

impl FlatNames {
    fn read(home: &Home) -> Result<Self> {
        Ok(Self {
            default: names_state::default_flat_names(home)?,
            tenants: names_state::tenant_flat_names(home)?,
        })
    }

    fn build(
        &self,
        specs: Vec<TenantSpec>,
        refused: Vec<Refusal>,
        quarantined: &HashSet<String>,
    ) -> TenantBook {
        TenantBook::build_with_tenant_names(
            specs,
            refused,
            &self.default,
            &self.tenants,
            quarantined,
        )
    }
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
            let (files, refused) = read_files(home)?;
            if files
                .iter()
                .any(|(spec, suspended)| *suspended && spec.slug == slug)
            {
                bail!(
                    "tenant {slug} is suspended: `menzil relay resume-tenant {slug}` first (a network added now would not be served)"
                );
            }
            let mut specs: Vec<TenantSpec> = files.into_iter().map(|(spec, _)| spec).collect();
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
            // The tenant files as they are now, to tell what this one changes (round T5, M3).
            let specs_before = specs.clone();
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
            let names = FlatNames::read(home)?;
            let removed: HashSet<String> = quarantined(home, now)?.into_keys().collect();
            let others_before = specs.len() - usize::from(created);
            let had_default_networks = rosters.iter().any(|stored| {
                stored
                    .roster
                    .decode()
                    .is_ok_and(|b| !listed_networks(&specs, &refused).contains(&b.network_id))
            });
            let before = names.build(specs_before, refused.clone(), &removed);
            let trial = names.build(specs.clone(), refused, &removed);
            if let Some(refusal) = trial.refused().iter().find(|r| r.name == slug.as_str()) {
                bail!("tenant {slug} cannot take it: {}", refusal.reason);
            }
            // The change must not take any other tenant offline: a file the book takes now and
            // would refuse after it (a slug equal to its grant, say) stops the command.
            if let Some(refusal) = trial.refused().iter().find(|r| {
                !before
                    .refused()
                    .iter()
                    .any(|earlier| earlier.name == r.name)
            }) {
                bail!(
                    "this would take tenant {} offline: {}",
                    refusal.name,
                    refusal.reason
                );
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
        let listed = salvage_networks(&text)
            .with_context(|| format!("{} cannot be read", path.display()))?;
        if !listed.contains(id) {
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
    // A file whose networks cannot be told is not deleted: its Rosters would stay and be served
    // by the default tenant at the next reload (round T4, L1). The operator repairs or moves it.
    let networks = salvage_networks(&text).with_context(|| {
        format!(
            "{} cannot be read, so tenant {slug} is not removed: repair the file (or delete it and the Roster files by hand)",
            path.display()
        )
    })?;
    for network in &networks {
        remove_if_there(&roster_path(home, network))?;
    }
    names_state::quarantine_slug_locked(home, slug.as_str(), now)?;
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
    for (name, entry) in names_state::read(home)?.quarantine {
        if entry.kind == menzil_relay::QuarantineKind::Flat && entry.until() > now {
            let _ = writeln!(
                out,
                "quarantine: flat name {name} can be taken again only by the network that held it until {}",
                entry.until()
            );
        }
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
    if tenant.suspended {
        line.push_str("  suspended (networks not served)");
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

// ---------------------------------------------------------------------------------------------
// Library operations for the admin agent (slice UI-A): typed errors, no text to parse.
// ---------------------------------------------------------------------------------------------

/// Why a tenant operation failed, for a caller that maps the kind (the admin agent: `NotFound`
/// to NOT_FOUND, `AlreadyExists` to ALREADY_EXISTS, `Invalid` to INVALID_ARGUMENT, `Precondition`
/// to FAILED_PRECONDITION, `Io` to INTERNAL). Used by the functions below only; the older
/// commands keep their `anyhow` errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    /// No tenant has this slug.
    NotFound,
    /// A tenant with this slug exists already.
    AlreadyExists,
    /// The request is wrong whatever the state (bad slug, class, figure, combination).
    Invalid(String),
    /// The request is fine but the state refuses it (more networks than the new figure, a tenant
    /// file the relay does not use).
    Precondition(String),
    /// The directory could not be read or written, or a file could not be understood.
    Io(String),
}

impl std::fmt::Display for TenantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such tenant"),
            Self::AlreadyExists => f.write_str("a tenant with this name exists already"),
            Self::Invalid(why) | Self::Precondition(why) | Self::Io(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for TenantError {}

impl TenantError {
    fn io(error: &anyhow::Error) -> Self {
        Self::Io(format!("{error:#}"))
    }
}

/// A tenant as the admin agent reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantInfo {
    /// The slug.
    pub slug: String,
    /// The networks its file lists.
    pub network_ids: Vec<NetworkId>,
    /// Its class.
    pub class: Class,
    /// Whether terminated shares are allowed for it.
    pub terminated: bool,
    /// Whether it is suspended.
    pub suspended: bool,
    /// When it was added (Unix seconds).
    pub added_unix: u64,
    /// The figure overrides in its file (empty: the class defaults).
    pub quota_overrides: BTreeMap<String, u64>,
}

impl TenantInfo {
    fn of(spec: &TenantSpec, suspended: bool) -> Self {
        Self {
            slug: spec.slug.to_string(),
            network_ids: spec.networks.clone(),
            class: spec.class,
            terminated: spec.terminated,
            suspended,
            added_unix: spec.added,
            quota_overrides: spec.overrides.clone(),
        }
    }
}

/// What `update_tenant` changes; `None` leaves a field as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateTenant {
    /// The new class (`personal` or `friend`).
    pub class: Option<Class>,
    /// Whether terminated shares are allowed.
    pub terminated: Option<bool>,
    /// `Some` REPLACES the whole set of figure overrides; `Some(empty)` goes back to the class
    /// defaults.
    pub quota_overrides: Option<BTreeMap<String, u64>>,
}

fn parse_slug(slug: &str) -> Result<Slug, TenantError> {
    Slug::parse(slug).map_err(|e| TenantError::Invalid(e.to_string()))
}

/// The tenant `slug`, as its file says. A file the relay does not use (see `relay tenants`) is a
/// `Precondition` error with the relay's reason.
pub fn get_tenant(home: &Home, slug: &str) -> Result<TenantInfo, TenantError> {
    let slug = parse_slug(slug)?;
    let (files, refused) = read_files(home).map_err(|e| TenantError::io(&e))?;
    if let Some((spec, suspended)) = files.iter().find(|(spec, _)| spec.slug == slug) {
        return Ok(TenantInfo::of(spec, *suspended));
    }
    match refused.iter().find(|r| r.name == slug.as_str()) {
        Some(refusal) => Err(TenantError::Precondition(format!(
            "tenant file {slug}.toml is not used: {}",
            refusal.reason
        ))),
        None => Err(TenantError::NotFound),
    }
}

/// Every tenant file the relay can read, by slug. Files the relay refuses are not listed (see
/// `relay tenants` for them).
pub fn list_tenants(home: &Home) -> Result<Vec<TenantInfo>, TenantError> {
    let (files, _) = read_files(home).map_err(|e| TenantError::io(&e))?;
    Ok(files
        .iter()
        .map(|(spec, suspended)| TenantInfo::of(spec, *suspended))
        .collect())
}

/// Reads the tenant file `slug` for a change (`NotFound` when there is none).
fn read_file_for_change(
    home: &Home,
    slug: &Slug,
) -> Result<(std::path::PathBuf, TenantFile), TenantError> {
    let path = tenant_path(home, slug.as_str());
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Err(TenantError::NotFound),
        Err(e) => return Err(TenantError::Io(format!("reading {}: {e}", path.display()))),
    };
    let file: TenantFile = toml::from_str(&text).map_err(|e| {
        TenantError::Precondition(format!(
            "{} cannot be changed, repair it first: {e}",
            path.display()
        ))
    })?;
    Ok((path, file))
}

/// `relay suspend-tenant` (`suspend = true`) and `relay resume-tenant` (`false`): sets the
/// `suspended` key of the tenant's file under `lock_relay`. Idempotent. A running relay applies
/// it at its next reload (within 15 seconds): suspended networks are not served and their
/// sessions end; resumed ones are adopted again from their Roster files, which are never touched.
/// The file is rewritten (its comments are not kept, as with every command).
pub fn set_suspended(home: &Home, slug: &str, suspend: bool) -> Result<TenantInfo, TenantError> {
    let slug = parse_slug(slug)?;
    let lock = home.lock_relay().map_err(|e| TenantError::io(&e))?;
    let (path, mut file) = read_file_for_change(home, &slug)?;
    if file.suspended != suspend {
        file.suspended = suspend;
        home.write_public(&path, file.render().as_bytes())
            .map_err(|e| TenantError::io(&e))?;
    }
    drop(lock);
    get_tenant(home, slug.as_str())
}

/// `update_tenant`: changes class, `terminated` and the figure overrides of a tenant under
/// `lock_relay`, writing the file atomically (its comments are not kept). Refused, writing
/// nothing: a class other than `personal` or `friend` cannot be expressed (the type); `personal`
/// with any override (also when the class changes to `personal` while overrides stay, or
/// overrides are set on a `personal` tenant) and a figure that is unknown, zero, above its
/// maximum or a floor above the bandwidth are `Invalid`; a `max_networks` below the number of
/// networks the tenant has, when the change touches the class or the overrides, is `Precondition`.
/// As the relay judges a file, a lowered `bandwidth_mbit` alone pulls the default floor down with
/// it and is accepted. Returns the tenant as it is now.
pub fn update_tenant(
    home: &Home,
    slug: &str,
    update: UpdateTenant,
) -> Result<TenantInfo, TenantError> {
    let slug = parse_slug(slug)?;
    let lock = home.lock_relay().map_err(|e| TenantError::io(&e))?;
    let (path, mut file) = read_file_for_change(home, &slug)?;
    let current_class = file
        .class()
        .map_err(|e| TenantError::Precondition(format!("{e:#}")))?;
    let class = update.class.unwrap_or(current_class);
    let touches_figures =
        update.class.is_some_and(|c| c != current_class) || update.quota_overrides.is_some();
    let overrides = update
        .quota_overrides
        .clone()
        .unwrap_or_else(|| file.figures.clone());
    match class {
        Class::Personal => {
            if !overrides.is_empty() {
                return Err(TenantError::Invalid(
                    "figures can be set only for the friend class".to_string(),
                ));
            }
        }
        Class::Friend => {
            let figures = Figures::friend()
                .with_overrides(&overrides)
                .map_err(TenantError::Invalid)?;
            let count = file.networks.len() as u64;
            if touches_figures && count > figures.max_networks {
                return Err(TenantError::Precondition(format!(
                    "max_networks {} is below the {count} network(s) the tenant has: remove some first",
                    figures.max_networks
                )));
            }
        }
    }
    // Nothing is written before every rule has passed.
    file.class = Some(class.as_str().to_string());
    file.figures = overrides;
    if let Some(terminated) = update.terminated {
        file.terminated = terminated;
    }
    home.write_public(&path, file.render().as_bytes())
        .map_err(|e| TenantError::io(&e))?;
    drop(lock);
    get_tenant(home, slug.as_str())
}
