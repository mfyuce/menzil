//! Tenants of a shared relay (multi tenant design, section 2.1 and 2.2; slice MT6).
//!
//! A tenant is an operator chosen name (the slug) and a set of NetworkIds; every served network
//! belongs to exactly one tenant. Membership is decided only by the operator (`relay add-network
//! --tenant <slug>`): the Roster proves the network, the operator's command assigns it. A network
//! that no tenant lists belongs to the default tenant, which has no slug, flat names and the
//! `personal` class (no tenant figures, only the relay's global safety limits), so a relay
//! without tenant files is today's relay.
//!
//! This module is data and rules, and (MT7) the counters that enforce the session and document
//! figures: slug syntax, the classes and their figures, the [`TenantBook`] that answers "which
//! tenant owns this network", the attribution helpers, and [`TenantUsage`], the relay wide
//! counters of attached and unattached sessions per tenant and of Roster adoptions per network.
//! The counters are RAII guards like `crate::admission`'s slots: a count given out is given back
//! when the guard is dropped, on every path and when a task is cancelled. A tenant of the
//! `personal` class has no figures and is never refused (it is still counted). The data plane
//! figures are enforced by `crate::forward` (MT8) and the name figures by `crate::advertise`
//! with `crate::names` (MT9); nothing here reads a file: the relay binary
//! loads the tenant files and hands the specs over (`menzil::relay_cmd`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use menzil_proto::{NetworkId, NodeId};

use crate::advertise::DEFAULT_RESERVED_LABELS;
use crate::rate::TokenBucket;

/// Fewest characters in a slug.
pub const SLUG_MIN_LEN: usize = 3;
/// Most characters in a slug.
pub const SLUG_MAX_LEN: usize = 32;
/// Longest label (a slug, an `extra_names` entry) a DNS name may have.
pub const LABEL_MAX_LEN: usize = 63;
/// How long a removed tenant's slug cannot be given to anybody else (design 2.2, rule 9).
pub const QUARANTINE_DAYS: u64 = 180;

/// Names no tenant may be called, besides [`DEFAULT_RESERVED_LABELS`] and whatever the operator
/// adds (design 2.2, rule 1). `_menzil` is not a legal label anyway; it is listed so that the
/// refusal says "reserved".
const EXTRA_RESERVED_SLUGS: &[&str] = &["_menzil"];

/// Why a text is not a slug.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlugError {
    /// Fewer than [`SLUG_MIN_LEN`] or more than [`SLUG_MAX_LEN`] characters.
    #[error("a tenant name has {SLUG_MIN_LEN} to {SLUG_MAX_LEN} characters")]
    Length,
    /// A character other than a lowercase ASCII letter, a digit or a hyphen.
    #[error("a tenant name uses lowercase ASCII letters, digits and hyphens only")]
    Charset,
    /// Starts or ends with a hyphen.
    #[error("a tenant name does not start or end with a hyphen")]
    Hyphen,
    /// On the reserved list.
    #[error("{0:?} is reserved and cannot be a tenant name")]
    Reserved(String),
}

/// A tenant's name: one LDH label, 3 to 32 characters, lowercase ASCII letters, digits and
/// hyphens, not starting or ending with a hyphen, and not reserved (design 2.2, rule 1). The
/// other slug rules (unique among tenants, not a flat name of the default tenant, not in
/// quarantine) need the rest of the relay and are checked where that is known
/// ([`TenantBook::build`], the CLI).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slug(String);

impl Slug {
    /// `text` as a slug, with the fixed reserved list.
    pub fn parse(text: &str) -> Result<Self, SlugError> {
        Self::parse_reserving(text, &[])
    }

    /// `text` as a slug, with the fixed reserved list and the operator's own `extra_reserved`
    /// (compared lowercase).
    pub fn parse_reserving(text: &str, extra_reserved: &[String]) -> Result<Self, SlugError> {
        if !(SLUG_MIN_LEN..=SLUG_MAX_LEN).contains(&text.len()) {
            return Err(SlugError::Length);
        }
        if !text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(SlugError::Charset);
        }
        if text.starts_with('-') || text.ends_with('-') {
            return Err(SlugError::Hyphen);
        }
        let reserved = DEFAULT_RESERVED_LABELS.contains(&text)
            || EXTRA_RESERVED_SLUGS.contains(&text)
            || extra_reserved.iter().any(|r| r.eq_ignore_ascii_case(text));
        if reserved {
            return Err(SlugError::Reserved(text.to_string()));
        }
        Ok(Self(text.to_string()))
    }

    /// The slug as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Slug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A flat name the operator grants a tenant (`extra_names`): one LDH label of 1 to 63 lowercase
/// ASCII letters, digits and hyphens, not starting or ending with a hyphen. A dotted name stays
/// refused until custom domains exist (design 2.2, rule 11).
pub fn check_flat_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > LABEL_MAX_LEN {
        return Err(format!(
            "{name:?} is not a name: 1 to {LABEL_MAX_LEN} characters"
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "{name:?} is not a flat name: lowercase ASCII letters, digits and hyphens only (no dots)"
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(format!("{name:?} starts or ends with a hyphen"));
    }
    Ok(())
}

/// Who a network belongs to: the default tenant (no slug, flat names) or a named one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TenantId {
    /// The tenant with no slug: every network no tenant file lists.
    Default,
    /// A tenant the operator named.
    Named(Slug),
}

impl TenantId {
    /// The slug of a named tenant.
    pub fn slug(&self) -> Option<&str> {
        match self {
            Self::Default => None,
            Self::Named(slug) => Some(slug.as_str()),
        }
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("(default)"),
            Self::Named(slug) => f.write_str(slug.as_str()),
        }
    }
}

/// A tenant's quota class (design 2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// No tenant figures, only the relay's global safety limits: the default tenant's class.
    Personal,
    /// The figures of [`Figures::friend`], each changeable in the tenant's file: the class of a
    /// tenant with a slug unless its file says otherwise.
    Friend,
}

impl Class {
    /// The class as written in a tenant file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Friend => "friend",
        }
    }

    /// The class a tenant file's `class` names.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "personal" => Some(Self::Personal),
            "friend" => Some(Self::Friend),
            _ => None,
        }
    }
}

/// Defines [`Figures`] with its `friend` defaults and the table of keys a tenant file may
/// override, each with its allowed range (1 up to the maximum: zero or out of range values are
/// errors, as for `[serve]`).
macro_rules! figures {
    ($($(#[$doc:meta])* $field:ident = $default:expr, max $max:expr;)*) => {
        /// The per tenant figures of a class (design 2.3), in the units the tenant file uses
        /// (the key names say which). Enforced so far: the session figures and the Roster figures
        /// (MT7) and the data plane figures (MT8: pairs, destinations, droppable bytes, bandwidth,
        /// burst, volume, floor) and the name figures (MT9: `names`, `new_names_per_week`).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct Figures {
            $($(#[$doc])* pub $field: u64,)*
        }

        impl Figures {
            /// The figures of the `friend` class.
            pub const fn friend() -> Self {
                Self { $($field: $default,)* }
            }

            /// The keys a tenant file may set, with the largest value each takes.
            pub const KEYS: &'static [(&'static str, u64)] = &[$((stringify!($field), $max),)*];

            /// These figures with `overrides` (key to value) applied. An unknown key, a zero
            /// or a value above the key's maximum is an error naming the key.
            pub fn with_overrides(mut self, overrides: &BTreeMap<String, u64>) -> Result<Self, String> {
                for (key, &value) in overrides {
                    let Some(&(_, max)) = Self::KEYS.iter().find(|(name, _)| name == key) else {
                        return Err(format!("{key:?} is not a known figure"));
                    };
                    if value == 0 || value > max {
                        return Err(format!("{key} must be 1 to {max}, not {value}"));
                    }
                    match key.as_str() {
                        $(stringify!($field) => self.$field = value,)*
                        _ => unreachable!("the key was found in KEYS"),
                    }
                }
                self.floor_within_bandwidth(overrides)
            }
        }
    };
}

impl Figures {
    /// The floor rate must not exceed the sustained rate (round T4, N4): above it, using up the
    /// volume would speed a tenant up. A floor the file sets above the bandwidth is an error; a
    /// default floor above a bandwidth the file lowered follows the bandwidth down.
    fn floor_within_bandwidth(mut self, overrides: &BTreeMap<String, u64>) -> Result<Self, String> {
        if self.floor_mbit > self.bandwidth_mbit {
            if overrides.contains_key("floor_mbit") {
                return Err(format!(
                    "floor_mbit ({}) cannot exceed bandwidth_mbit ({})",
                    self.floor_mbit, self.bandwidth_mbit
                ));
            }
            self.floor_mbit = self.bandwidth_mbit;
        }
        Ok(self)
    }
}

figures! {
    /// Networks the tenant may have.
    max_networks = 3, max 1_000;
    /// Largest encoded Roster, in KiB (the protocol maximum is 1024).
    roster_kib = 256, max 1_024;
    /// Roster adoptions per network per hour.
    roster_adoptions_per_hour = 20, max 100_000;
    /// Roster adoptions per network in a burst.
    roster_adoption_burst = 5, max 100_000;
    /// Attached sessions (distinct NodeIds).
    attached_sessions = 64, max 100_000;
    /// Handshaken sessions that have not attached.
    unattached_sessions = 16, max 100_000;
    /// Live forwarding pairs.
    forwarding_pairs = 64, max 1_000_000;
    /// Distinct destinations per sending NodeId.
    destinations_per_node = 32, max 100_000;
    /// Droppable bytes queued over all pairs, in MiB.
    droppable_mib = 16, max 65_536;
    /// Sustained bandwidth, in Mbit/s.
    bandwidth_mbit = 100, max 1_000_000;
    /// Bandwidth burst, in MiB.
    burst_mib = 256, max 1_048_576;
    /// Traffic per period before the floor rate applies, in GiB.
    volume_gib = 250, max 1_000_000;
    /// Length of the volume period, in days.
    volume_days = 30, max 3_650;
    /// Bandwidth once the volume is used up, in Mbit/s.
    floor_mbit = 5, max 1_000_000;
    /// Names the tenant may hold in all.
    names = 20, max 100_000;
    /// Names accepted for the first time in any 7 days.
    new_names_per_week = 5, max 100_000;
}

/// What a tenant file says about one tenant, before the book judges it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSpec {
    /// The tenant's slug.
    pub slug: Slug,
    /// The networks it owns.
    pub networks: Vec<NetworkId>,
    /// Its class.
    pub class: Class,
    /// Figures that replace the class's (key to value, see [`Figures::KEYS`]); only for
    /// [`Class::Friend`].
    pub overrides: BTreeMap<String, u64>,
    /// Whether the relay may terminate TLS for the tenant's shares (protocol.md 6.3).
    pub terminated: bool,
    /// Exact flat names the operator grants the tenant (design 2.2, rule 10).
    pub extra_names: Vec<String>,
    /// When the tenant was added (Unix seconds); orders overlapping files.
    pub added: u64,
}

/// One tenant as the book holds it, after the judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// Its id.
    pub id: TenantId,
    /// Its class.
    pub class: Class,
    /// Its figures: `None` for [`Class::Personal`] (only the global safety limits apply).
    pub figures: Option<Figures>,
    /// The networks its file lists, in file order; empty for the default tenant, which owns
    /// whatever no file lists (the book does not know that set).
    pub networks: Vec<NetworkId>,
    /// Whether terminated shares are allowed for it.
    pub terminated: bool,
    /// The flat names the operator granted it.
    pub extra_names: Vec<String>,
    /// When it was added (Unix seconds), 0 for the default tenant.
    pub added: u64,
}

impl Tenant {
    fn default_tenant() -> Self {
        Self {
            id: TenantId::Default,
            class: Class::Personal,
            figures: None,
            networks: Vec::new(),
            terminated: false,
            extra_names: Vec::new(),
            added: 0,
        }
    }
}

/// What [`TenantBook::judge`] holds a file against.
#[derive(Clone, Copy)]
struct JudgedNames<'a> {
    /// The slugs of the files judged before this one.
    earlier: &'a HashSet<Slug>,
    default_names: &'a HashSet<String>,
    tenant_flat: &'a HashMap<String, String>,
    quarantined: &'a HashSet<String>,
    /// The grants of the tenants taken so far.
    granted: &'a HashMap<String, Slug>,
}

/// A tenant file the book did not take, and the networks it listed: they are held back (not
/// served), never given to the default tenant, whose names and class are the more generous ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The file's name without `.toml`, which may not even be a slug.
    pub name: String,
    /// Why.
    pub reason: String,
    /// The networks the file listed, as far as they could be read.
    pub networks: Vec<NetworkId>,
}

/// The relay's tenants, an immutable snapshot (the relay swaps in a new one at each reload).
#[derive(Debug, Clone)]
pub struct TenantBook {
    default: Tenant,
    named: BTreeMap<Slug, Tenant>,
    by_network: HashMap<NetworkId, TenantId>,
    held_back: HashSet<NetworkId>,
    refused: Vec<Refusal>,
    warnings: Vec<String>,
    /// Slugs of removed tenants still in quarantine (given to [`Self::build`]).
    quarantined_slugs: HashSet<String>,
}

impl Default for TenantBook {
    /// No tenant files: every network is the default tenant's. This is today's relay.
    fn default() -> Self {
        Self {
            default: Tenant::default_tenant(),
            named: BTreeMap::new(),
            by_network: HashMap::new(),
            held_back: HashSet::new(),
            refused: Vec::new(),
            warnings: Vec::new(),
            quarantined_slugs: HashSet::new(),
        }
    }
}

impl TenantBook {
    /// Judges `specs` (tenant files that parsed) and `refused` (files that could not be taken
    /// before this point, their networks held back).
    ///
    /// `default_names` are the flat names the relay has accepted the default tenant for, or holds
    /// in quarantine for it (`names.state`; not merely labels a default Roster lists, which an
    /// owner can put there at will, round T5, M1): a slug or an `extra_names` entry equal to one
    /// is refused. Files are judged in the order they were `added`, then by slug, so that when two
    /// overlap the older keeps what is contested and the newer is refused; a file is refused for a
    /// figure out of range, an override on the `personal` class, a bad flat name, an `extra_names`
    /// entry equal to the slug of an older tenant or a slug in quarantine, to a default tenant
    /// name or to an earlier tenant's entry, and a slug equal to a default tenant name, to an
    /// earlier tenant's entry or to a flat name a tenant is accepted for. A network a tenant already owns is dropped from a later
    /// file with a warning. More networks than the class's `max_networks` figure is a warning only
    /// (the CLI refuses to add past it; the relay keeps serving what the operator wrote).
    ///
    /// `quarantined` are the slugs of removed tenants still in quarantine (design 2.2, rule 1):
    /// a file whose slug is one of them is refused and its networks are held back, so that a
    /// hand written file cannot bring a removed tenant's name back before the quarantine ends
    /// (round T4, N5).
    pub fn build(
        specs: Vec<TenantSpec>,
        refused: Vec<Refusal>,
        default_names: &HashSet<String>,
        quarantined: &HashSet<String>,
    ) -> Self {
        Self::build_with_tenant_names(specs, refused, default_names, &HashMap::new(), quarantined)
    }

    /// [`Self::build`] with the flat names the relay has accepted named tenants for or holds in
    /// quarantine for them (`tenant_flat`, flat name to the slug of that tenant): a slug equal
    /// to one is refused, and so is a grant equal to one of another tenant (round T5, L2).
    pub fn build_with_tenant_names(
        mut specs: Vec<TenantSpec>,
        refused: Vec<Refusal>,
        default_names: &HashSet<String>,
        tenant_flat: &HashMap<String, String>,
        quarantined: &HashSet<String>,
    ) -> Self {
        specs.sort_by(|a, b| (a.added, &a.slug).cmp(&(b.added, &b.slug)));
        // The slugs of the files judged before the one at hand: the older file keeps what is
        // contested, the newer is the one refused (round T5, M3).
        let mut earlier: HashSet<Slug> = HashSet::new();
        let mut book = Self {
            refused,
            quarantined_slugs: quarantined.clone(),
            ..Self::default()
        };
        let mut granted: HashMap<String, Slug> = HashMap::new();
        for spec in specs {
            let before = earlier.clone();
            earlier.insert(spec.slug.clone());
            if quarantined.contains(spec.slug.as_str()) {
                book.refuse(
                    &spec,
                    format!(
                        "the name {} belonged to a tenant that was removed and is in quarantine; it cannot be used again until the quarantine ends",
                        spec.slug
                    ),
                );
                continue;
            }
            let names = JudgedNames {
                earlier: &before,
                default_names,
                tenant_flat,
                quarantined,
                granted: &granted,
            };
            match book.judge(&spec, &names) {
                Err(reason) => book.refuse(&spec, reason),
                Ok(mut tenant) => {
                    for name in &tenant.extra_names {
                        granted.insert(name.clone(), spec.slug.clone());
                    }
                    for network in &spec.networks {
                        if let Some(owner) = book.by_network.get(network) {
                            book.warnings.push(format!(
                                "network {network} is listed by tenant {} as well as {owner}; it stays with {owner}",
                                spec.slug
                            ));
                        } else {
                            book.by_network.insert(*network, tenant.id.clone());
                            tenant.networks.push(*network);
                        }
                    }
                    if let Some(figures) = &tenant.figures
                        && tenant.networks.len() as u64 > figures.max_networks
                    {
                        book.warnings.push(format!(
                            "tenant {} has {} networks, more than its {} allowed; all are served",
                            spec.slug,
                            tenant.networks.len(),
                            figures.max_networks
                        ));
                    }
                    book.named.insert(spec.slug.clone(), tenant);
                }
            }
        }
        for refusal in &book.refused {
            book.held_back.extend(refusal.networks.iter().copied());
        }
        book
    }

    fn judge(&self, spec: &TenantSpec, names: &JudgedNames<'_>) -> Result<Tenant, String> {
        let JudgedNames {
            earlier,
            default_names,
            tenant_flat,
            quarantined,
            granted,
        } = *names;
        if self.named.contains_key(&spec.slug) {
            return Err(format!("the name {} is already a tenant", spec.slug));
        }
        if default_names.contains(spec.slug.as_str()) {
            return Err(format!(
                "{} is a flat name the default tenant holds; a tenant name cannot equal one",
                spec.slug
            ));
        }
        if let Some(owner) = tenant_flat.get(spec.slug.as_str()) {
            return Err(format!(
                "{} is a flat name granted to tenant {owner}, held or in quarantine; a tenant name cannot equal one",
                spec.slug
            ));
        }
        if let Some(owner) = granted.get(spec.slug.as_str()) {
            return Err(format!(
                "{} is a name granted to tenant {owner}; a tenant name cannot equal one",
                spec.slug
            ));
        }
        let figures = match spec.class {
            Class::Personal => {
                if !spec.overrides.is_empty() {
                    return Err("figures can be set only for the friend class".to_string());
                }
                None
            }
            Class::Friend => Some(Figures::friend().with_overrides(&spec.overrides)?),
        };
        let mut extra_names: Vec<String> = Vec::new();
        for name in &spec.extra_names {
            check_flat_name(name)?;
            if earlier.iter().any(|slug| slug.as_str() == name) {
                return Err(format!("extra name {name:?} is a tenant name"));
            }
            if quarantined.contains(name) {
                return Err(format!(
                    "extra name {name:?} is the name of a removed tenant, in quarantine"
                ));
            }
            if let Some(owner) = tenant_flat.get(name)
                && owner != spec.slug.as_str()
            {
                return Err(format!(
                    "extra name {name:?} is held by tenant {owner}, or in quarantine for it"
                ));
            }
            if default_names.contains(name) {
                return Err(format!(
                    "extra name {name:?} is a name the default tenant holds"
                ));
            }
            if let Some(other) = granted.get(name) {
                return Err(format!("extra name {name:?} is granted to tenant {other}"));
            }
            if !extra_names.contains(name) {
                extra_names.push(name.clone());
            }
        }
        Ok(Tenant {
            id: TenantId::Named(spec.slug.clone()),
            class: spec.class,
            figures,
            networks: Vec::new(),
            terminated: spec.terminated,
            extra_names,
            added: spec.added,
        })
    }

    fn refuse(&mut self, spec: &TenantSpec, reason: String) {
        self.refused.push(Refusal {
            name: spec.slug.to_string(),
            reason,
            networks: spec.networks.clone(),
        });
    }

    /// The tenant that owns `network_id`: the one whose file lists it, else the default tenant.
    pub fn id_of(&self, network_id: &NetworkId) -> &TenantId {
        self.by_network.get(network_id).unwrap_or(&self.default.id)
    }

    /// [`Self::id_of`] with the tenant's record.
    pub fn tenant_of(&self, network_id: &NetworkId) -> &Tenant {
        match self.by_network.get(network_id) {
            Some(TenantId::Named(slug)) => self.named.get(slug).unwrap_or(&self.default),
            _ => &self.default,
        }
    }

    /// The named tenant called `slug`.
    pub fn named(&self, slug: &str) -> Option<&Tenant> {
        self.named
            .iter()
            .find(|(s, _)| s.as_str() == slug)
            .map(|(_, t)| t)
    }

    /// The default tenant.
    pub fn default_tenant(&self) -> &Tenant {
        &self.default
    }

    /// Every tenant: the default one first, then the named ones by slug.
    pub fn tenants(&self) -> impl Iterator<Item = &Tenant> {
        std::iter::once(&self.default).chain(self.named.values())
    }

    /// How many named tenants there are.
    pub fn named_count(&self) -> usize {
        self.named.len()
    }

    /// Whether the default tenant may not have `label` as a flat name (design 2.2, rule 4 and
    /// 10): it is the slug of a tenant, of a removed tenant still in quarantine, or a flat name
    /// the operator granted a tenant.
    pub fn reserves_flat_name(&self, label: &str) -> bool {
        self.quarantined_slugs.contains(label)
            || self.named.keys().any(|slug| slug.as_str() == label)
            || self
                .named
                .values()
                .any(|tenant| tenant.extra_names.iter().any(|name| name == label))
    }

    /// Whether `network_id` is in a tenant file the book refused: such a network is not served.
    pub fn is_held_back(&self, network_id: &NetworkId) -> bool {
        self.held_back.contains(network_id)
    }

    /// The tenant files that were refused.
    pub fn refused(&self) -> &[Refusal] {
        &self.refused
    }

    /// What the operator should hear about when the book was built.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The figures that apply to `id`: `None` for the default tenant, for a `personal` one and for
    /// a tenant this book does not hold (only the global safety limits apply to those).
    pub fn figures_of(&self, id: &TenantId) -> Option<&Figures> {
        match id {
            TenantId::Default => None,
            TenantId::Named(slug) => self.named.get(slug).and_then(|t| t.figures.as_ref()),
        }
    }

    /// Attribution of a session (design 2.1): the distinct tenants of the networks it claimed
    /// and passed standing in, in the order of the claims. A NodeId can claim only networks
    /// whose Roster lists it, so no tenant can inflate another's count with these.
    pub fn session_tenants(&self, claimed: &[NetworkId]) -> Vec<&TenantId> {
        let mut tenants: Vec<&TenantId> = Vec::new();
        for network_id in claimed {
            let id = self.id_of(network_id);
            if !tenants.contains(&id) {
                tenants.push(id);
            }
        }
        tenants
    }

    /// Attribution of a forwarding pair (design 2.1): the tenant of the network that authorized
    /// it, which is the first network of the sender's HELLO list that both sides claimed.
    /// `authorizing` is that list already narrowed to the networks both sides claimed, in the
    /// sender's order; `None` when it is empty.
    pub fn pair_tenant(&self, authorizing: &[NetworkId]) -> Option<&TenantId> {
        authorizing.first().map(|network_id| self.id_of(network_id))
    }

    /// Attribution of a Roster adoption, and of a label the Roster grants: the tenant of its
    /// network.
    pub fn adoption_tenant(&self, network_id: &NetworkId) -> &TenantId {
        self.id_of(network_id)
    }
}

/// Which tenant figure a session was refused for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Quota {
    /// Too many devices attached (distinct NodeIds).
    AttachedSessions,
    /// Too many devices connected and waiting to ATTACH.
    UnattachedSessions,
}

/// A session refused because its tenant is at a figure (`over_quota`, design 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OverQuota {
    /// The tenant that is full.
    pub(crate) tenant: TenantId,
    /// The figure.
    pub(crate) quota: Quota,
}

impl OverQuota {
    /// The text the refused device is shown (ERROR `msg`). It names no tenant and no figure: the
    /// device knows its own networks, and the operator's slugs and numbers are the operator's.
    pub(crate) fn message(&self) -> &'static str {
        match self.quota {
            Quota::AttachedSessions => {
                "this relay's limit on devices online for your network is reached; try again later"
            }
            Quota::UnattachedSessions => {
                "this relay's limit on devices connecting for your network is reached; try again shortly"
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    attached: usize,
    unattached: usize,
}

/// A network's bucket of Roster adoptions, with the figures it was made from (a reload that
/// changes them makes a new one).
struct AdoptionBucket {
    figures: (u64, u64),
    bucket: TokenBucket,
}

/// The relay wide counters behind the tenant figures (multi tenant design 2.3, slice MT7):
/// attached and unattached sessions per tenant, and Roster adoptions per network. Shared
/// (`Arc`) by the session tasks and the registry. A count is taken with one lock, all the
/// tenants of a session together, so a session over one tenant's figure takes nothing from the
/// others.
#[derive(Default)]
pub(crate) struct TenantUsage {
    counts: Mutex<HashMap<TenantId, Counts>>,
    /// One bucket per served network; only a network the session claimed and the relay serves
    /// is ever charged ([`RosterQuota`]'s caller checks that first), so the table is bounded by
    /// the networks served.
    adoptions: Mutex<HashMap<NetworkId, AdoptionBucket>>,
    /// One bucket per NodeId that sent a Roster that failed verification (round T4, the
    /// adoption bucket drain): what a member may spend of the relay's signature checking on
    /// transfers that do not verify, across all its sessions. Bounded by [`MAX_FAILED_SUBMITTERS`].
    failed: Mutex<HashMap<NodeId, TokenBucket>>,
}

/// Roster transfers that fail verification one NodeId may send per hour, once its burst is spent.
pub(crate) const FAILED_VERIFICATIONS_PER_HOUR: u32 = 12;
/// Roster transfers that fail verification a NodeId may send back to back.
pub(crate) const FAILED_VERIFICATION_BURST: u32 = 3;
/// The most NodeIds the failed verification table remembers; when it is full of NodeIds that are
/// still being limited, a further one is refused verification until one has recovered.
const MAX_FAILED_SUBMITTERS: usize = 4_096;

impl TenantUsage {
    /// Counters all at zero.
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn counts(&self) -> MutexGuard<'_, HashMap<TenantId, Counts>> {
        self.counts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts a handshaken, not yet attached session that claimed `claimed`, against every
    /// tenant of those networks (one count each, design 2.1).
    ///
    /// Accepted limit (round T4, L2; TBD 47): a NodeId listed by two tenants' networks is refused
    /// entirely when ANY of its tenants is at a figure, so a hostile owner who invites a victim's
    /// device into its own network and fills its own tenant keeps that device from attaching
    /// (the victim's network included) for as long as it likes. The design counts a session
    /// against every tenant it claimed on purpose; the alternative (admit it with the networks
    /// whose tenants have room and tell the node through WELCOME) is open for the owner to decide.
    /// Refused when any of them has its
    /// `unattached_sessions`, or its `attached_sessions` already attached and this NodeId is not
    /// one of them. `attached_before` is the claims of the NodeId's current registration, if it
    /// has one: a NodeId that is attached in a tenant already replaces its own session there, so
    /// a tenant at the figure still lets its own devices reconnect (as `crate::admission` does
    /// for the relay wide count). The attached check here only keeps a full tenant from
    /// handshaking; the count itself is taken at ATTACH ([`Self::admit_attached`]).
    pub(crate) fn admit_unattached(
        self: &Arc<Self>,
        book: &TenantBook,
        claimed: &[NetworkId],
        attached_before: &[NetworkId],
    ) -> Result<TenantUnattached, OverQuota> {
        let tenants: Vec<TenantId> = book.session_tenants(claimed).into_iter().cloned().collect();
        let replacing = book.session_tenants(attached_before);
        let mut counts = self.counts();
        for id in &tenants {
            let Some(figures) = book.figures_of(id) else {
                continue;
            };
            let held = counts.get(id).copied().unwrap_or_default();
            if held.unattached as u64 >= figures.unattached_sessions {
                return Err(OverQuota {
                    tenant: id.clone(),
                    quota: Quota::UnattachedSessions,
                });
            }
            if held.attached as u64 >= figures.attached_sessions && !replacing.contains(&id) {
                return Err(OverQuota {
                    tenant: id.clone(),
                    quota: Quota::AttachedSessions,
                });
            }
        }
        for id in &tenants {
            counts.entry(id.clone()).or_default().unattached += 1;
        }
        drop(counts);
        Ok(TenantUnattached {
            usage: Arc::clone(self),
            tenants,
        })
    }

    /// Counts an attached session that claimed `claimed`, against every tenant of those
    /// networks. Refused when any of them has its `attached_sessions` attached already, unless
    /// this NodeId is attached in it now (`replacing` is the claims of its current registration:
    /// the new session takes the old one's place, and for the moment both exist). The guard
    /// belongs to the registration (`crate::registry`), so the count is the number of
    /// registrations, however long a superseded session takes to leave.
    pub(crate) fn admit_attached(
        self: &Arc<Self>,
        book: &TenantBook,
        claimed: &[NetworkId],
        replacing: &[NetworkId],
    ) -> Result<TenantAttached, OverQuota> {
        let tenants: Vec<TenantId> = book.session_tenants(claimed).into_iter().cloned().collect();
        let replacing = book.session_tenants(replacing);
        let mut counts = self.counts();
        for id in &tenants {
            let Some(figures) = book.figures_of(id) else {
                continue;
            };
            let held = counts.get(id).copied().unwrap_or_default();
            if held.attached as u64 >= figures.attached_sessions && !replacing.contains(&id) {
                return Err(OverQuota {
                    tenant: id.clone(),
                    quota: Quota::AttachedSessions,
                });
            }
        }
        for id in &tenants {
            counts.entry(id.clone()).or_default().attached += 1;
        }
        drop(counts);
        Ok(TenantAttached {
            usage: Arc::clone(self),
            tenants,
        })
    }

    fn release(&self, tenants: &[TenantId], change: impl Fn(&mut Counts)) {
        let mut counts = self.counts();
        for id in tenants {
            if let Some(held) = counts.get_mut(id) {
                change(held);
                if held.attached == 0 && held.unattached == 0 {
                    counts.remove(id);
                }
            }
        }
    }

    /// Takes one Roster adoption of `network_id` from its bucket, if its tenant has figures and
    /// the bucket has a token; a tenant without figures is never refused. A bucket made from
    /// other figures than the tenant has now (a reload) is replaced.
    fn try_adopt(&self, book: &TenantBook, network_id: &NetworkId) -> bool {
        let Some(figures) = book.tenant_of(network_id).figures else {
            return true;
        };
        let key = (
            figures.roster_adoptions_per_hour,
            figures.roster_adoption_burst,
        );
        let mut buckets = self
            .adoptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let slot = buckets
            .entry(*network_id)
            .or_insert_with(|| AdoptionBucket {
                figures: key,
                bucket: Self::adoption_bucket(key),
            });
        if slot.figures != key {
            *slot = AdoptionBucket {
                figures: key,
                bucket: Self::adoption_bucket(key),
            };
        }
        slot.bucket.try_take()
    }

    /// Whether the bucket of `network_id` holds an adoption now, taking none (a tenant without
    /// figures always has one). A transfer is let through to the signature check only when it
    /// does; the token is taken after the check succeeds ([`Self::try_adopt`]), so a transfer
    /// that does not verify costs the network nothing (round T4).
    fn adoption_available(&self, book: &TenantBook, network_id: &NetworkId) -> bool {
        let Some(figures) = book.tenant_of(network_id).figures else {
            return true;
        };
        let key = (
            figures.roster_adoptions_per_hour,
            figures.roster_adoption_burst,
        );
        let mut buckets = self
            .adoptions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let slot = buckets
            .entry(*network_id)
            .or_insert_with(|| AdoptionBucket {
                figures: key,
                bucket: Self::adoption_bucket(key),
            });
        if slot.figures != key {
            *slot = AdoptionBucket {
                figures: key,
                bucket: Self::adoption_bucket(key),
            };
        }
        slot.bucket.has_token()
    }

    /// Whether `node_id` may still send a Roster to the signature check: it has not used up its
    /// allowance of transfers that failed it.
    fn may_verify(&self, node_id: &NodeId) -> bool {
        let mut failed = self.failed.lock().unwrap_or_else(PoisonError::into_inner);
        failed
            .get_mut(node_id)
            .is_none_or(|bucket| bucket.has_token())
    }

    /// Charges `node_id` for a Roster that failed the signature check (or was otherwise refused
    /// by it) to its own bucket.
    fn note_failed_verification(&self, node_id: &NodeId) {
        let mut failed = self.failed.lock().unwrap_or_else(PoisonError::into_inner);
        if !failed.contains_key(node_id) && failed.len() >= MAX_FAILED_SUBMITTERS {
            // Forget the NodeIds that have recovered; if all are still limited, this one is not
            // remembered (and so not limited): the table's size is the bound, and each entry
            // took a failed verification by a member of a served network.
            failed.retain(|_, bucket| !bucket.is_full());
            if failed.len() >= MAX_FAILED_SUBMITTERS {
                return;
            }
        }
        failed
            .entry(*node_id)
            .or_insert_with(|| {
                TokenBucket::per_hour(FAILED_VERIFICATIONS_PER_HOUR, FAILED_VERIFICATION_BURST)
            })
            .try_take();
    }

    fn adoption_bucket((per_hour, burst): (u64, u64)) -> TokenBucket {
        // The figures' ranges (1 to 100,000) fit a u32.
        TokenBucket::per_hour(
            u32::try_from(per_hour).unwrap_or(u32::MAX),
            u32::try_from(burst).unwrap_or(u32::MAX),
        )
    }

    /// Sessions of `id` that are attached, by this count (tests).
    #[cfg(test)]
    pub(crate) fn attached_of(&self, id: &TenantId) -> usize {
        self.counts().get(id).map_or(0, |c| c.attached)
    }

    /// Sessions of `id` that are handshaken and not attached, by this count (tests).
    #[cfg(test)]
    pub(crate) fn unattached_of(&self, id: &TenantId) -> usize {
        self.counts().get(id).map_or(0, |c| c.unattached)
    }

    /// Tenants with any count left (tests: nothing leaks).
    #[cfg(test)]
    pub(crate) fn tenants_counted(&self) -> usize {
        self.counts().len()
    }
}

/// The place of a handshaken, not yet attached session in its tenants' counts
/// ([`TenantUsage::admit_unattached`]); given back when dropped.
pub(crate) struct TenantUnattached {
    usage: Arc<TenantUsage>,
    tenants: Vec<TenantId>,
}

impl Drop for TenantUnattached {
    fn drop(&mut self) {
        self.usage.release(&self.tenants, |c| {
            c.unattached = c.unattached.saturating_sub(1)
        });
    }
}

/// The place of an attached session in its tenants' counts ([`TenantUsage::admit_attached`]);
/// given back when dropped.
pub(crate) struct TenantAttached {
    usage: Arc<TenantUsage>,
    tenants: Vec<TenantId>,
}

impl Drop for TenantAttached {
    fn drop(&mut self) {
        self.usage
            .release(&self.tenants, |c| c.attached = c.attached.saturating_sub(1));
    }
}

/// What a tenant allows of a DOC(roster) transfer, asked by `crate::doc` after it has checked that
/// the session claimed the network and the relay serves it (so a stranger learns nothing from
/// the answer).
pub(crate) trait RosterQuota {
    /// The largest encoded Roster (or base Roster) of `network_id` its tenant lets through, in
    /// bytes.
    fn max_roster_bytes(&self, network_id: &NetworkId) -> usize;

    /// Whether the network's bucket holds an adoption. Asked only for a transfer that is newer
    /// than the held Roster and will reach a signature check, and before it; false means refuse
    /// it undecoded further. Takes nothing: the adoption is paid for by [`Self::adopted`] once
    /// the Roster has verified, so a transfer that does not verify cannot drain the owner's
    /// allowance (round T4).
    fn adoption_available(&self, network_id: &NetworkId) -> bool;

    /// A Roster of the network verified and was adopted: takes its adoption from the bucket.
    fn adopted(&self, network_id: &NetworkId);

    /// Whether the session's NodeId may still send a Roster to the signature check (it has not
    /// used up what its own bucket allows of transfers that failed it).
    fn may_verify(&self) -> bool;

    /// A Roster of this session's NodeId did not verify: charged to that NodeId's own bucket,
    /// not to the network's.
    fn failed_verification(&self);
}

/// The quota of a relay's tenants as of one moment: the book that was current when it was made.
pub(crate) struct RelayQuota<'a> {
    pub(crate) book: Arc<TenantBook>,
    pub(crate) usage: &'a TenantUsage,
    /// The NodeId of the session that sends the transfer.
    pub(crate) submitter: NodeId,
}

#[cfg(test)]
impl RelayQuota<'_> {
    /// Takes an adoption from the network's bucket whatever the verification says (tests).
    pub(crate) fn try_adopt(&self, network_id: &NetworkId) -> bool {
        self.usage.try_adopt(&self.book, network_id)
    }

    /// [`RosterQuota::adoption_available`] for tests of other modules.
    pub(crate) fn adoption_available_for_test(&self, network_id: &NetworkId) -> bool {
        self.adoption_available(network_id)
    }

    /// [`RosterQuota::may_verify`] for tests of other modules.
    pub(crate) fn may_verify_for_test(&self) -> bool {
        self.may_verify()
    }
}

impl RosterQuota for RelayQuota<'_> {
    fn max_roster_bytes(&self, network_id: &NetworkId) -> usize {
        self.book
            .tenant_of(network_id)
            .figures
            .map_or(menzil_proto::MAX_DOC_BYTES, |figures| {
                usize::try_from(figures.roster_kib.saturating_mul(1024))
                    .unwrap_or(usize::MAX)
                    .min(menzil_proto::MAX_DOC_BYTES)
            })
    }

    fn adoption_available(&self, network_id: &NetworkId) -> bool {
        self.usage.adoption_available(&self.book, network_id)
    }

    fn adopted(&self, network_id: &NetworkId) {
        let _ = self.usage.try_adopt(&self.book, network_id);
    }

    fn may_verify(&self) -> bool {
        self.usage.may_verify(&self.submitter)
    }

    fn failed_verification(&self) {
        self.usage.note_failed_verification(&self.submitter);
    }
}

/// No tenant limits: what `crate::doc`'s own tests use.
#[cfg(test)]
pub(crate) struct Unlimited;

#[cfg(test)]
impl RosterQuota for Unlimited {
    fn max_roster_bytes(&self, _: &NetworkId) -> usize {
        menzil_proto::MAX_DOC_BYTES
    }

    fn adoption_available(&self, _: &NetworkId) -> bool {
        true
    }

    fn adopted(&self, _: &NetworkId) {}

    fn may_verify(&self) -> bool {
        true
    }

    fn failed_verification(&self) {}
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn net(n: u8) -> NetworkId {
        NetworkId::from([n; 32])
    }

    fn slug(text: &str) -> Slug {
        Slug::parse(text).unwrap()
    }

    fn spec(name: &str, networks: &[u8]) -> TenantSpec {
        TenantSpec {
            slug: slug(name),
            networks: networks.iter().map(|n| net(*n)).collect(),
            class: Class::Friend,
            overrides: BTreeMap::new(),
            terminated: false,
            extra_names: Vec::new(),
            added: 100,
        }
    }

    fn no_names() -> HashSet<String> {
        HashSet::new()
    }

    fn build(specs: Vec<TenantSpec>) -> TenantBook {
        TenantBook::build(specs, Vec::new(), &no_names(), &HashSet::new())
    }

    #[test]
    fn a_slug_is_one_ldh_label_of_three_to_thirty_two_lowercase_characters() {
        for good in ["ali", "a-b", "abc", "friend-2", "x1y", &"a".repeat(32)] {
            assert!(Slug::parse(good).is_ok(), "{good} should be a slug");
        }
        assert_eq!(Slug::parse("ab"), Err(SlugError::Length));
        assert_eq!(Slug::parse(""), Err(SlugError::Length));
        assert_eq!(Slug::parse(&"a".repeat(33)), Err(SlugError::Length));
        for bad in ["Ali", "al_i", "a.b", "ali ", "alî", "ALI"] {
            assert_eq!(Slug::parse(bad), Err(SlugError::Charset), "{bad}");
        }
        assert_eq!(Slug::parse("-ab"), Err(SlugError::Hyphen));
        assert_eq!(Slug::parse("ab-"), Err(SlugError::Hyphen));
    }

    #[test]
    fn reserved_names_are_not_slugs_and_the_operator_can_reserve_more() {
        for reserved in ["www", "mail", "admin", "api", "relay"] {
            assert_eq!(
                Slug::parse(reserved),
                Err(SlugError::Reserved(reserved.to_string()))
            );
        }
        // `t` and `_menzil` fail on their own syntax before the list; the zone name `t` is
        // reserved by length, and still listed in the reserved labels.
        assert!(Slug::parse("t").is_err());
        assert!(Slug::parse("_menzil").is_err());
        assert!(Slug::parse("ali").is_ok());
        assert_eq!(
            Slug::parse_reserving("ali", &["Ali".to_string()]),
            Err(SlugError::Reserved("ali".to_string()))
        );
    }

    #[test]
    fn a_flat_name_is_one_label_without_dots() {
        assert!(check_flat_name("blog").is_ok());
        assert!(check_flat_name("a").is_ok());
        assert!(check_flat_name("blog.example").is_err());
        assert!(check_flat_name("Blog").is_err());
        assert!(check_flat_name("-blog").is_err());
        assert!(check_flat_name("").is_err());
        assert!(check_flat_name(&"a".repeat(64)).is_err());
    }

    #[test]
    fn no_tenant_files_give_one_default_tenant_with_the_personal_class() {
        let book = TenantBook::default();
        assert_eq!(book.named_count(), 0);
        assert_eq!(book.tenants().count(), 1);
        let default = book.default_tenant();
        assert_eq!(default.id, TenantId::Default);
        assert_eq!(default.class, Class::Personal);
        assert_eq!(default.figures, None, "personal has no tenant figures");
        assert!(!default.terminated);
        assert!(default.extra_names.is_empty());
        // Any network belongs to it.
        assert_eq!(book.id_of(&net(7)), &TenantId::Default);
        assert_eq!(book.tenant_of(&net(7)).class, Class::Personal);
        assert!(!book.is_held_back(&net(7)));
        assert!(book.refused().is_empty() && book.warnings().is_empty());
        // A build from nothing is the same.
        let built = build(vec![]);
        assert_eq!(built.tenants().count(), 1);
        assert_eq!(built.id_of(&net(7)), &TenantId::Default);
    }

    #[test]
    fn a_networks_tenant_is_the_one_that_lists_it_and_the_rest_are_default() {
        let book = build(vec![spec("ali", &[1, 2]), spec("veli", &[3])]);
        assert_eq!(book.id_of(&net(1)).slug(), Some("ali"));
        assert_eq!(book.id_of(&net(2)).slug(), Some("ali"));
        assert_eq!(book.id_of(&net(3)).slug(), Some("veli"));
        assert_eq!(book.id_of(&net(4)), &TenantId::Default);
        assert_eq!(book.named("ali").unwrap().networks, vec![net(1), net(2)]);
        assert_eq!(book.tenant_of(&net(3)).id.to_string(), "veli");
        assert_eq!(book.tenants().count(), 3);
        assert_eq!(
            book.tenants().next().unwrap().id,
            TenantId::Default,
            "the default tenant comes first"
        );
        assert_eq!(
            book.named("ali").unwrap().figures,
            Some(Figures::friend()),
            "a friend tenant has the friend figures"
        );
    }

    #[test]
    fn friend_figures_are_the_table_of_the_design_and_overrides_replace_single_figures() {
        let friend = Figures::friend();
        assert_eq!(
            [
                friend.max_networks,
                friend.roster_kib,
                friend.attached_sessions,
                friend.unattached_sessions,
                friend.forwarding_pairs,
                friend.destinations_per_node,
                friend.droppable_mib,
                friend.bandwidth_mbit,
                friend.burst_mib,
                friend.volume_gib,
                friend.volume_days,
                friend.floor_mbit,
                friend.names,
                friend.new_names_per_week,
                friend.roster_adoptions_per_hour,
                friend.roster_adoption_burst,
            ],
            [
                3, 256, 64, 16, 64, 32, 16, 100, 256, 250, 30, 5, 20, 5, 20, 5
            ]
        );
        let mut one = spec("ali", &[1]);
        one.overrides = BTreeMap::from([("attached_sessions".to_string(), 8)]);
        let figures = build(vec![one]).named("ali").unwrap().figures.unwrap();
        assert_eq!(figures.attached_sessions, 8);
        assert_eq!(figures.names, 20, "the others keep the class's figure");
    }

    #[test]
    fn a_zero_unknown_or_oversized_figure_refuses_the_tenant_and_holds_its_networks_back() {
        for (key, value) in [("names", 0u64), ("roster_kib", 1025), ("no_such_figure", 3)] {
            let mut bad = spec("ali", &[1]);
            bad.overrides = BTreeMap::from([(key.to_string(), value)]);
            let book = build(vec![bad, spec("veli", &[2])]);
            assert!(book.named("ali").is_none(), "{key}={value}");
            assert_eq!(book.refused().len(), 1, "{key}={value}");
            assert!(book.refused()[0].reason.contains(key), "{key}={value}");
            assert!(
                book.is_held_back(&net(1)),
                "a refused tenant's network is not given to the default tenant"
            );
            assert!(!book.is_held_back(&net(2)));
            assert!(book.named("veli").is_some(), "the others are served");
        }
    }

    #[test]
    fn overrides_on_the_personal_class_are_refused() {
        let mut personal = spec("ali", &[1]);
        personal.class = Class::Personal;
        assert_eq!(
            build(vec![personal.clone()]).named("ali").unwrap().figures,
            None
        );
        personal.overrides = BTreeMap::from([("names".to_string(), 3)]);
        let book = build(vec![personal]);
        assert!(book.named("ali").is_none());
        assert!(book.is_held_back(&net(1)));
    }

    #[test]
    fn extra_names_that_overlap_are_refused() {
        // An exact flat name given to two tenants: the older keeps it, the newer is refused.
        let mut older = spec("ali", &[1]);
        older.extra_names = vec!["blog".into()];
        older.added = 10;
        let mut newer = spec("veli", &[2]);
        newer.extra_names = vec!["blog".into()];
        newer.added = 20;
        let book = build(vec![newer.clone(), older.clone()]);
        assert!(book.named("ali").is_some());
        assert!(book.named("veli").is_none(), "the newer file is refused");
        assert!(book.refused()[0].reason.contains("blog"));
        assert!(book.is_held_back(&net(2)) && !book.is_held_back(&net(1)));

        // Reversing the dates reverses the outcome: the order is by `added`, not by the input.
        older.added = 30;
        let book = build(vec![older, newer]);
        assert!(book.named("veli").is_some() && book.named("ali").is_none());
    }

    #[test]
    fn an_extra_name_equal_to_any_slug_or_to_a_default_tenant_name_is_refused() {
        // Equal to another tenant's slug: the older file keeps it, the newer is refused
        // (round T5, M3: adding a tenant must not take an older one offline).
        let mut grant = spec("ali", &[1]);
        grant.extra_names = vec!["veli".into()];
        grant.added = 1;
        let mut other = spec("veli", &[2]);
        other.added = 2;
        let book = build(vec![grant.clone(), other.clone()]);
        assert!(book.named("ali").is_some(), "the older grant stays");
        assert!(
            book.named("veli").is_none(),
            "the newer slug equals ali's grant"
        );
        assert!(book.is_held_back(&net(2)) && !book.is_held_back(&net(1)));
        // A grant that is newer than the slug it equals is the one refused.
        grant.added = 3;
        let book = build(vec![grant, other]);
        assert!(
            book.named("ali").is_none(),
            "ali's grant equals the slug veli"
        );
        assert!(book.named("veli").is_some());

        // Equal to a flat name the default tenant holds.
        let mut grant = spec("ali", &[1]);
        grant.extra_names = vec!["blog".into()];
        let held: HashSet<String> = ["blog".to_string()].into();
        let book = TenantBook::build(vec![grant], vec![], &held, &HashSet::new());
        assert!(book.named("ali").is_none());
        assert!(book.is_held_back(&net(1)));

        // A bad flat name (dotted) is refused too.
        let mut dotted = spec("ali", &[1]);
        dotted.extra_names = vec!["a.b".into()];
        assert!(build(vec![dotted]).named("ali").is_none());
    }

    #[test]
    fn a_slug_equal_to_a_default_tenant_flat_name_is_refused() {
        let held: HashSet<String> = ["ali".to_string()].into();
        let book = TenantBook::build(vec![spec("ali", &[1])], vec![], &held, &HashSet::new());
        assert!(book.named("ali").is_none());
        assert!(book.is_held_back(&net(1)));
    }

    /// Round T5, L1: a grant equal to the slug of a removed tenant (in quarantine) is refused,
    /// whoever asks, and the tenant's networks are held back.
    #[test]
    fn an_extra_name_equal_to_a_quarantined_slug_is_refused() {
        let mut grant = spec("veli", &[3]);
        grant.extra_names = vec!["gone".into()];
        let quarantined: HashSet<String> = ["gone".to_string()].into();
        let book = TenantBook::build(vec![grant.clone()], vec![], &no_names(), &quarantined);
        assert!(book.named("veli").is_none());
        assert!(book.is_held_back(&net(3)));
        assert!(book.refused()[0].reason.contains("quarantine"));
        // Without the quarantine it is an ordinary grant.
        assert!(build(vec![grant]).named("veli").is_some());
    }

    /// Round T5, L2: a slug cannot equal a flat name a named tenant is accepted for or is
    /// quarantined for (the apex of that name is the first level of one namespace), and a grant
    /// cannot be one of another tenant's, though a tenant keeps its own.
    #[test]
    fn a_slug_or_grant_equal_to_a_flat_name_of_a_tenant_is_refused() {
        let flat: HashMap<String, String> = [("blog".to_string(), "ali".to_string())].into();
        let build_with = |specs| {
            TenantBook::build_with_tenant_names(specs, vec![], &no_names(), &flat, &HashSet::new())
        };
        let book = build_with(vec![spec("blog", &[1])]);
        assert!(book.named("blog").is_none());
        assert!(book.refused()[0].reason.contains("tenant ali"));

        let mut other = spec("veli", &[2]);
        other.extra_names = vec!["blog".into()];
        let book = build_with(vec![other]);
        assert!(book.named("veli").is_none(), "ali holds blog");

        let mut own = spec("ali", &[3]);
        own.extra_names = vec!["blog".into()];
        let book = build_with(vec![own]);
        assert!(book.named("ali").is_some(), "its own grant is not a clash");
    }

    #[test]
    fn a_duplicate_slug_is_refused_and_a_network_two_files_list_stays_with_the_older() {
        let mut first = spec("ali", &[1]);
        first.added = 1;
        let mut second = spec("ali", &[9]);
        second.added = 2;
        let book = build(vec![first, second]);
        assert_eq!(book.named_count(), 1);
        assert!(book.is_held_back(&net(9)));

        let mut older = spec("ali", &[1, 2]);
        older.added = 1;
        let mut newer = spec("veli", &[2, 3]);
        newer.added = 2;
        let book = build(vec![newer, older]);
        assert_eq!(book.id_of(&net(2)).slug(), Some("ali"));
        assert_eq!(book.id_of(&net(3)).slug(), Some("veli"));
        assert_eq!(book.named("veli").unwrap().networks, vec![net(3)]);
        assert_eq!(book.warnings().len(), 1);
    }

    #[test]
    fn more_networks_than_the_class_allows_is_a_warning_and_all_are_served() {
        let book = build(vec![spec("ali", &[1, 2, 3, 4])]);
        assert_eq!(book.named("ali").unwrap().networks.len(), 4);
        assert_eq!(book.warnings().len(), 1);
        assert!(book.warnings()[0].contains("4 networks"));
        let mut personal = spec("veli", &[5, 6, 7, 8]);
        personal.class = Class::Personal;
        assert!(build(vec![personal]).warnings().is_empty());
    }

    #[test]
    fn attribution_follows_the_networks_a_session_claimed_and_the_one_that_authorized_a_pair() {
        let book = build(vec![spec("ali", &[1, 2]), spec("veli", &[3])]);
        // Distinct tenants, in claim order, whatever the number of networks in each.
        let tenants = book.session_tenants(&[net(1), net(3), net(2), net(4)]);
        let names: Vec<_> = tenants.iter().map(|t| t.to_string()).collect();
        assert_eq!(names, ["ali", "veli", "(default)"]);
        assert!(book.session_tenants(&[]).is_empty());
        // A pair counts against the first authorizing network's tenant.
        assert_eq!(
            book.pair_tenant(&[net(3), net(1)]).unwrap().slug(),
            Some("veli")
        );
        assert_eq!(
            book.pair_tenant(&[net(1), net(3)]).unwrap().slug(),
            Some("ali")
        );
        assert!(book.pair_tenant(&[]).is_none());
        assert_eq!(book.adoption_tenant(&net(2)).slug(), Some("ali"));
        assert_eq!(book.adoption_tenant(&net(9)), &TenantId::Default);
    }
    // ---- MT7: the session and Roster figures -------------------------------------------------

    /// The 65th attached device of a tenant is refused while the first of another tenant, and
    /// any number of the default tenant's, are let in; the counts come back when the guards go.
    #[test]
    fn the_65th_attached_node_of_a_tenant_is_refused_while_another_tenants_first_is_accepted() {
        let book = build(vec![spec("ali", &[1]), spec("veli", &[2])]);
        let usage = TenantUsage::new();
        let mut held = Vec::new();
        for _ in 0..64 {
            held.push(usage.admit_attached(&book, &[net(1)], &[]).unwrap());
        }
        let ali = TenantId::Named(slug("ali"));
        assert_eq!(usage.attached_of(&ali), 64);
        let refused = usage.admit_attached(&book, &[net(1)], &[]).err().unwrap();
        assert_eq!(
            refused,
            OverQuota {
                tenant: ali.clone(),
                quota: Quota::AttachedSessions
            }
        );
        assert_eq!(usage.attached_of(&ali), 64, "a refusal takes nothing");
        // Another tenant is not touched, and neither is the default tenant (no figures).
        let _veli = usage.admit_attached(&book, &[net(2)], &[]).unwrap();
        for _ in 0..100 {
            held.push(usage.admit_attached(&book, &[net(9)], &[]).unwrap());
        }
        // A NodeId already attached in the tenant may replace its own session at the figure.
        let replacement = usage.admit_attached(&book, &[net(1)], &[net(1)]).unwrap();
        assert_eq!(usage.attached_of(&ali), 65, "both exist for the moment");
        drop(replacement);
        // One leaves: the next is let in.
        held.remove(0);
        assert_eq!(usage.attached_of(&ali), 63);
        usage.admit_attached(&book, &[net(1)], &[]).unwrap();
    }

    #[test]
    fn the_17th_unattached_session_of_a_tenant_is_refused_and_a_full_tenant_does_not_handshake() {
        let book = build(vec![spec("ali", &[1]), spec("veli", &[2])]);
        let usage = TenantUsage::new();
        let mut held = Vec::new();
        for _ in 0..16 {
            held.push(usage.admit_unattached(&book, &[net(1)], &[]).unwrap());
        }
        let ali = TenantId::Named(slug("ali"));
        let refused = usage.admit_unattached(&book, &[net(1)], &[]).err().unwrap();
        assert_eq!(refused.quota, Quota::UnattachedSessions);
        assert_eq!(refused.tenant, ali);
        assert_eq!(usage.unattached_of(&ali), 16);
        assert!(usage.admit_unattached(&book, &[net(2)], &[]).is_ok());
        // A tenant with 64 attached refuses a new device's HELLO, but not one that is attached.
        let usage = TenantUsage::new();
        let attached: Vec<_> = (0..64)
            .map(|_| usage.admit_attached(&book, &[net(1)], &[]).unwrap())
            .collect();
        let full = usage.admit_unattached(&book, &[net(1)], &[]).err().unwrap();
        assert_eq!(full.quota, Quota::AttachedSessions);
        assert!(usage.admit_unattached(&book, &[net(1)], &[net(1)]).is_ok());
        drop(attached);
    }

    /// A session of two tenants counts against both and is refused when either is full, taking
    /// nothing from the other; every guard gives its count back, and an emptied entry leaves.
    #[test]
    fn a_session_in_two_tenants_counts_against_both_and_every_count_is_given_back() {
        let figures = |attached: u64| {
            let mut overrides = BTreeMap::new();
            overrides.insert("attached_sessions".to_string(), attached);
            overrides
        };
        let mut ali = spec("ali", &[1]);
        ali.overrides = figures(1);
        let book = build(vec![ali, spec("veli", &[2])]);
        let usage = TenantUsage::new();
        let (ali_id, veli_id) = (TenantId::Named(slug("ali")), TenantId::Named(slug("veli")));
        let both = usage.admit_attached(&book, &[net(1), net(2)], &[]).unwrap();
        assert_eq!(
            (usage.attached_of(&ali_id), usage.attached_of(&veli_id)),
            (1, 1)
        );
        let refused = usage
            .admit_attached(&book, &[net(2), net(1)], &[])
            .err()
            .unwrap();
        assert_eq!(refused.tenant, ali_id);
        assert_eq!(usage.attached_of(&veli_id), 1, "veli was not charged");
        let pending = usage.admit_unattached(&book, &[net(2)], &[]).unwrap();
        assert_eq!(usage.unattached_of(&veli_id), 1);
        drop(both);
        drop(pending);
        assert_eq!(usage.tenants_counted(), 0, "nothing is left behind");
        // Dropping the guard of a session counts down by one, not to zero.
        let (a, b) = (
            usage.admit_attached(&book, &[net(2)], &[]).unwrap(),
            usage.admit_attached(&book, &[net(2)], &[]).unwrap(),
        );
        drop(a);
        assert_eq!(usage.attached_of(&veli_id), 1);
        drop(b);
        assert_eq!(usage.attached_of(&veli_id), 0);
    }

    #[test]
    fn a_personal_tenant_is_counted_and_never_refused() {
        let mut personal = spec("ali", &[1]);
        personal.class = Class::Personal;
        let book = build(vec![personal]);
        let usage = TenantUsage::new();
        let held: Vec<_> = (0..300)
            .map(|_| {
                (
                    usage.admit_unattached(&book, &[net(1)], &[]).unwrap(),
                    usage.admit_attached(&book, &[net(1)], &[]).unwrap(),
                )
            })
            .collect();
        assert_eq!(usage.attached_of(&TenantId::Named(slug("ali"))), 300);
        assert_eq!(usage.unattached_of(&TenantId::Default), 0);
        drop(held);
        assert_eq!(usage.tenants_counted(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn roster_adoptions_per_network_are_metered_by_the_tenants_bucket() {
        let mut ali = spec("ali", &[1, 2]);
        ali.overrides = BTreeMap::from([
            ("roster_adoptions_per_hour".to_string(), 20),
            ("roster_adoption_burst".to_string(), 5),
        ]);
        let book = Arc::new(build(vec![ali, spec("veli", &[3])]));
        let usage = TenantUsage::new();
        let quota = RelayQuota {
            book: Arc::clone(&book),
            usage: &usage,
            submitter: NodeId::from([0u8; 32]),
        };
        for _ in 0..5 {
            assert!(quota.try_adopt(&net(1)));
        }
        assert!(!quota.try_adopt(&net(1)), "the sixth is over the burst");
        // Another network of the same tenant has its own bucket; so does another tenant.
        assert!(quota.try_adopt(&net(2)));
        assert!(quota.try_adopt(&net(3)));
        // 20 an hour: one token every 180 s.
        tokio::time::advance(Duration::from_secs(179)).await;
        assert!(!quota.try_adopt(&net(1)));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(quota.try_adopt(&net(1)));
        assert!(!quota.try_adopt(&net(1)));
        // The default tenant has no figures: never refused, nothing kept.
        for _ in 0..50 {
            assert!(quota.try_adopt(&net(9)));
        }
        assert_eq!(usage.adoptions.lock().unwrap().len(), 3);
        // A reload that changes the figures makes a new bucket.
        let mut ali = spec("ali", &[1, 2]);
        ali.overrides = BTreeMap::from([("roster_adoption_burst".to_string(), 2)]);
        let reloaded = RelayQuota {
            book: Arc::new(build(vec![ali])),
            usage: &usage,
            submitter: NodeId::from([0u8; 32]),
        };
        assert!(reloaded.try_adopt(&net(1)) && reloaded.try_adopt(&net(1)));
        assert!(!reloaded.try_adopt(&net(1)));
    }

    /// Round T4: the failed verification bucket is per NodeId, across sessions, refills with time
    /// and has a bounded table.
    #[tokio::test(start_paused = true)]
    async fn a_node_that_keeps_failing_verification_is_limited_on_its_own_account() {
        let usage = TenantUsage::new();
        let (bad, good) = (NodeId::from([1u8; 32]), NodeId::from([2u8; 32]));
        for _ in 0..FAILED_VERIFICATION_BURST {
            assert!(usage.may_verify(&bad));
            usage.note_failed_verification(&bad);
        }
        assert!(!usage.may_verify(&bad), "the burst is used up");
        assert!(usage.may_verify(&good), "another node is unaffected");
        // 12 an hour: one more after five minutes.
        tokio::time::advance(std::time::Duration::from_secs(299)).await;
        assert!(!usage.may_verify(&bad));
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        assert!(usage.may_verify(&bad));
        // The table is bounded: it cannot be grown past its size by failing NodeIds.
        for n in 0..(MAX_FAILED_SUBMITTERS as u32 + 100) {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&(n + 10).to_be_bytes());
            usage.note_failed_verification(&NodeId::from(id));
        }
        assert!(usage.failed.lock().unwrap().len() <= MAX_FAILED_SUBMITTERS);
    }

    /// Round T4, N4: a floor above the bandwidth would speed a tenant up once it used its volume.
    #[test]
    fn a_floor_above_the_bandwidth_is_refused_and_a_default_floor_follows_a_lowered_bandwidth() {
        let mut bad = spec("ali", &[1]);
        bad.overrides = BTreeMap::from([
            ("bandwidth_mbit".to_string(), 2),
            ("floor_mbit".to_string(), 3),
        ]);
        let book = build(vec![bad]);
        assert!(book.named("ali").is_none());
        assert!(book.refused()[0].reason.contains("floor_mbit"));
        assert!(book.is_held_back(&net(1)));

        // Only the floor set, above the default bandwidth of 100: refused too.
        let figures =
            Figures::friend().with_overrides(&BTreeMap::from([("floor_mbit".to_string(), 101)]));
        assert!(figures.is_err());
        // The bandwidth lowered below the default floor of 5: the floor follows it down.
        let mut low = spec("veli", &[2]);
        low.overrides = BTreeMap::from([("bandwidth_mbit".to_string(), 1)]);
        let book = build(vec![low]);
        let figures = book.named("veli").unwrap().figures.unwrap();
        assert_eq!((figures.bandwidth_mbit, figures.floor_mbit), (1, 1));
        // Equal is fine.
        let equal = Figures::friend().with_overrides(&BTreeMap::from([
            ("bandwidth_mbit".to_string(), 7),
            ("floor_mbit".to_string(), 7),
        ]));
        assert!(equal.is_ok());
    }

    /// Round T4, N5 (design 2.2, rule 1): a tenant file whose slug is in quarantine is refused and
    /// its networks held back.
    #[test]
    fn a_file_with_a_quarantined_slug_is_refused_and_its_networks_held_back() {
        let removed: HashSet<String> = ["ali".to_string()].into();
        let book = TenantBook::build(
            vec![spec("ali", &[1]), spec("veli", &[2])],
            vec![],
            &no_names(),
            &removed,
        );
        assert!(book.named("ali").is_none());
        assert!(book.named("veli").is_some());
        assert!(book.is_held_back(&net(1)));
        assert!(!book.is_held_back(&net(2)));
        let refusal = &book.refused()[0];
        assert_eq!(refusal.name, "ali");
        assert!(refusal.reason.contains("quarantine"), "{}", refusal.reason);
        assert_eq!(refusal.networks, vec![net(1)]);
    }

    #[test]
    fn the_roster_size_figure_is_the_tenants_and_never_above_the_protocol_maximum() {
        let mut small = spec("ali", &[1]);
        small.overrides = BTreeMap::from([("roster_kib".to_string(), 4)]);
        let book = Arc::new(build(vec![small, spec("veli", &[2])]));
        let usage = TenantUsage::new();
        let quota = RelayQuota {
            book,
            usage: &usage,
            submitter: NodeId::from([0u8; 32]),
        };
        assert_eq!(quota.max_roster_bytes(&net(1)), 4 * 1024);
        assert_eq!(
            quota.max_roster_bytes(&net(2)),
            256 * 1024,
            "the friend default"
        );
        assert_eq!(
            quota.max_roster_bytes(&net(9)),
            menzil_proto::MAX_DOC_BYTES,
            "the default tenant has only the protocol maximum"
        );
        let mut big = spec("ali", &[1]);
        big.overrides = BTreeMap::from([("roster_kib".to_string(), 1_024)]);
        let quota = RelayQuota {
            book: Arc::new(build(vec![big])),
            usage: &usage,
            submitter: NodeId::from([0u8; 32]),
        };
        assert_eq!(quota.max_roster_bytes(&net(1)), menzil_proto::MAX_DOC_BYTES);
    }
}
