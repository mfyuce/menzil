//! Tenants of a shared relay (multi tenant design, section 2.1 and 2.2; slice MT6).
//!
//! A tenant is an operator chosen name (the slug) and a set of NetworkIds; every served network
//! belongs to exactly one tenant. Membership is decided only by the operator (`relay add-network
//! --tenant <slug>`): the Roster proves the network, the operator's command assigns it. A network
//! that no tenant lists belongs to the default tenant, which has no slug, flat names and the
//! `personal` class (no tenant figures, only the relay's global safety limits), so a relay
//! without tenant files is today's relay.
//!
//! This module is data and rules only: slug syntax, the classes and their figures, the
//! [`TenantBook`] that answers "which tenant owns this network" and the attribution helpers the
//! enforcing slices (MT7 to MT9) call. Nothing here refuses a session, a Roster or a name yet,
//! and nothing reads a file: the relay binary loads the tenant files and hands the specs over
//! (`menzil::relay_cmd`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use menzil_proto::NetworkId;

use crate::advertise::DEFAULT_RESERVED_LABELS;

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
        /// (the key names say which). Nothing enforces them yet (MT7, MT8, MT9).
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
                Ok(self)
            }
        }
    };
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
        }
    }
}

impl TenantBook {
    /// Judges `specs` (tenant files that parsed) and `refused` (files that could not be taken
    /// before this point, their networks held back).
    ///
    /// `default_names` are the flat names the default tenant holds now (the labels its Rosters
    /// grant): a slug or an `extra_names` entry equal to one is refused. Files are judged in the
    /// order they were `added`, then by slug, so that when two overlap the older keeps what is
    /// contested and the newer is refused; a file is refused for a figure out of range, an
    /// override on the `personal` class, a bad flat name, an `extra_names` entry equal to any
    /// tenant's slug, to a default tenant name or to an earlier tenant's entry, and a slug
    /// equal to a default tenant name. A network a tenant already owns is dropped from a later
    /// file with a warning. More networks than the class's `max_networks` figure is a warning only
    /// (the CLI refuses to add past it; the relay keeps serving what the operator wrote).
    pub fn build(
        mut specs: Vec<TenantSpec>,
        refused: Vec<Refusal>,
        default_names: &HashSet<String>,
    ) -> Self {
        specs.sort_by(|a, b| (a.added, &a.slug).cmp(&(b.added, &b.slug)));
        let slugs: HashSet<Slug> = specs.iter().map(|spec| spec.slug.clone()).collect();
        let mut book = Self {
            refused,
            ..Self::default()
        };
        let mut granted: HashMap<String, Slug> = HashMap::new();
        for spec in specs {
            match book.judge(&spec, &slugs, default_names, &granted) {
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

    fn judge(
        &self,
        spec: &TenantSpec,
        slugs: &HashSet<Slug>,
        default_names: &HashSet<String>,
        granted: &HashMap<String, Slug>,
    ) -> Result<Tenant, String> {
        if self.named.contains_key(&spec.slug) {
            return Err(format!("the name {} is already a tenant", spec.slug));
        }
        if default_names.contains(spec.slug.as_str()) {
            return Err(format!(
                "{} is a flat name the default tenant holds; a tenant name cannot equal one",
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
            if slugs.iter().any(|slug| slug.as_str() == name) {
                return Err(format!("extra name {name:?} is a tenant name"));
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

#[cfg(test)]
mod tests {
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
        TenantBook::build(specs, Vec::new(), &no_names())
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
        // Equal to another tenant's slug, whichever file is older.
        let mut grant = spec("ali", &[1]);
        grant.extra_names = vec!["veli".into()];
        grant.added = 1;
        let mut other = spec("veli", &[2]);
        other.added = 2;
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
        let book = TenantBook::build(vec![grant], vec![], &held);
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
        let book = TenantBook::build(vec![spec("ali", &[1])], vec![], &held);
        assert!(book.named("ali").is_none());
        assert!(book.is_held_back(&net(1)));
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
}
