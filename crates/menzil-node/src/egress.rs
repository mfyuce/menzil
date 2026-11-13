//! The exit side of `egress:*` streams (protocol.md section 8, slice 1a): [`EgressExecutor`]
//! decides whether a target a member asked for may be dialled and, if so, dials it.
//!
//! What this is not: no SOCKS listener, no agent request, no config file key and no owner
//! command; those are later slices. [`crate::LocalServices::with_egress`] is where the executor
//! is plugged in, and only a counted peer OPEN reaches it (the relay principal's path refuses an
//! `egress:*` open before the executor is asked).
//!
//! Order of an OPEN, as in section 8:
//!
//! 1. The target is canonicalized into a [`Target`], the only type the rest of this module takes
//!    (an invalid target cannot be built): an IPv4 mapped IPv6 address becomes IPv4; an address
//!    literal is parsed strictly (std's parsers: four decimal fields with no leading zeros or a
//!    plain IPv6 literal, no zone id); anything else must be a lowercase name of letters, digits,
//!    hyphens and dots (labels of 1 to 63, 253 bytes at most, no trailing dot) whose last label
//!    does not start with a digit (so `127.1`, `0x7f.1`, `2130706433` and `0177.0.0.1`, which a
//!    resolver would read as addresses, are refused). Port 0 is refused. The initiator side is
//!    expected to lowercase a name; this side refuses uppercase rather than fold it. Refusal:
//!    `invalid_target`.
//! 2. The node's own [`EgressRule`] is read for the OPEN's network ([`EgressRules`]). An empty
//!    `allow` (after dropping patterns that do not parse) allows nothing: `forbidden`, nothing
//!    resolved.
//! 3. A name is matched against the name patterns before it is resolved ([`decide`]); a deny
//!    there is `forbidden` and the name is not resolved.
//! 4. The exit's own addresses are enumerated ([`own_addresses`] in production). If that fails,
//!    every dial is refused (fail closed) and the log says why.
//! 5. A name is resolved once, through a bounded resolver (16 lookups at a time on blocking
//!    threads, a lookup the OPEN gave up on keeps its place until it returns). Every answer is
//!    canonicalized and checked, an address literal itself too ([`EgressExecutor::vet`]): the
//!    floor, `self`, then the rules. An address that fails is dropped; a name with none left is
//!    refused `target_unreachable`, byte for byte the answer for a name that does not exist (the
//!    log has the reason). An address literal that fails is `forbidden`.
//! 6. The connect goes to the vetted [`SocketAddr`]s only, one after the other, inside one
//!    connect timeout for the whole of steps 5 and 6. Nothing is resolved again.
//!
//! The floor ([`reserved_reason`]): the unspecified, loopback, link local, multicast and `self`
//! addresses, and the ranges protocol.md 8 says no `allow` lifts (100.64/10, 198.18/15,
//! 240/4, 192.0.0.0/24, 192.88.99.0/24, ::/96, fc00::/7, 64:ff9b::/96, 64:ff9b:1::/48,
//! 2001::/32, 2002::/16), is refused whatever the Policy says. Three IPv4 private ranges
//! (10/8, 172.16/12, 192.168/16) are denied by the exit itself as built in deny entries, in
//! addition to the signed list, so they stay denied when a Policy lacks the default deny list;
//! a signed `allow` with a longer prefix lifts part of one (an `allow` of the same prefix ties
//! with the deny, and a tie is a deny).
//!
//! Choices where protocol.md 8 leaves room (all of them the stricter reading):
//!
//! * A pattern that does not parse matches nothing; two `egress` entries for one node are
//!   ambiguous and the node has no rule ([`rule_of`]).
//! * A name `allow` (an exact name or `*.name`) lets the name be resolved and its addresses
//!   count as allowed when no address pattern matches them, but an address pattern that wins
//!   (a deny of equal or greater specificity than any allow, built in private deny entries
//!   included) still drops the address. Name allows therefore never reach a private range.
//! * Name specificity has three tiers (exact, `*.name`, `*`), and a pattern with a port beats
//!   the same tier without one. All `*.name` patterns share their tier whatever their depth.
//! * A bracketed IPv6 pattern is accepted only with a port (`[addr]:port`, `[addr]/len:port`);
//!   a CIDR with host bits set (`10.1.2.3/8`) does not parse.
//! * An `allow` of `*:25` against the default deny `*:25` is a tie, so the deny wins: it does
//!   not lift port 25. Only an `allow` with a longer prefix on that port does (for example
//!   `203.0.113.0/24:25`).

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU16;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use menzil_proto::{EgressRule, ErrorCode, HostPortPattern, NetworkId, NodeId, PolicyBody};
use menzil_stream::{OpenRefusal, OpenRequest};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::policy_store::PolicyStore;
use crate::serve::{LOG_INTERVAL, LogThrottle, connect_addr, system_resolve};

/// How many name lookups the exit runs at once, on blocking threads.
pub const MAX_CONCURRENT_EGRESS_LOOKUPS: usize = 16;

/// The longest name, in bytes (RFC 1035).
const MAX_NAME: usize = 253;

/// The longest label, in bytes.
const MAX_LABEL: usize = 63;

/// A target that is not a canonical name or address, or whose port is 0. Answered
/// `invalid_target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTarget;

impl std::fmt::Display for InvalidTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not a canonical host name or address")
    }
}

impl std::error::Error for InvalidTarget {}

/// A DNS name as the exit accepts it: 1 to 253 bytes of lowercase letters, digits, hyphens and
/// dots, labels of 1 to 63 bytes (so no empty label, no trailing dot), and a last label that does
/// not start with a digit (a resolver reads an all numeric last label as an address form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name(String);

impl Name {
    /// `text` as a name, or [`InvalidTarget`].
    pub fn parse(text: &str) -> Result<Self, InvalidTarget> {
        if text.is_empty() || text.len() > MAX_NAME {
            return Err(InvalidTarget);
        }
        let mut last = "";
        for label in text.split('.') {
            let good = !label.is_empty()
                && label.len() <= MAX_LABEL
                && label
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'));
            if !good {
                return Err(InvalidTarget);
            }
            last = label;
        }
        if last.as_bytes()[0].is_ascii_digit() {
            return Err(InvalidTarget);
        }
        Ok(Name(text.to_owned()))
    }

    /// The name, lowercase, without a trailing dot.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The host of a [`Target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// An address literal, canonical (an IPv4 mapped IPv6 address is the IPv4 one).
    Addr(IpAddr),
    /// A name to resolve at the exit.
    Name(Name),
}

/// A canonical egress target. Built only by [`Target::canonicalize`], so a value is always a
/// valid host with a port other than 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    host: Host,
    port: NonZeroU16,
}

impl Target {
    /// Canonicalizes the `host` and `port` of an OPEN's target (module documentation, step 1).
    pub fn canonicalize(host: &str, port: u16) -> Result<Self, InvalidTarget> {
        let port = NonZeroU16::new(port).ok_or(InvalidTarget)?;
        if host.is_empty() || host.len() > MAX_NAME {
            return Err(InvalidTarget);
        }
        let host = if let Ok(v4) = Ipv4Addr::from_str(host) {
            Host::Addr(IpAddr::V4(v4))
        } else if host.contains(':') {
            // A zone id, brackets and every other decoration fail the parse.
            let v6 = Ipv6Addr::from_str(host).map_err(|_| InvalidTarget)?;
            Host::Addr(IpAddr::V6(v6).to_canonical())
        } else {
            Host::Name(Name::parse(host)?)
        };
        Ok(Self { host, port })
    }

    /// The host.
    pub fn host(&self) -> &Host {
        &self.host
    }

    /// The port, never 0.
    pub fn port(&self) -> u16 {
        self.port.get()
    }
}

// ---------------------------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------------------------

/// An address prefix whose host bits are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    len: u8,
}

impl Net {
    fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let net = Self { addr, len };
        // The prefix must be exact: `10.1.2.3/8` does not parse.
        net.contains(addr).then_some(net)
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.len))
                };
                u32::from(ip) & mask == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.len))
                };
                u128::from(ip) & mask == u128::from(net)
            }
            _ => false,
        }
    }
}

/// A parsed [`HostPortPattern`] (protocol.md 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// `*`: any target.
    Any,
    /// `*:port`: any target on that port.
    AnyPort(NonZeroU16),
    /// `self`: every address of the exit itself.
    Own,
    /// `CIDR` or `CIDR:port` (an address is a prefix of full length).
    Net {
        /// The prefix.
        net: Net,
        /// The port, if the pattern has one.
        port: Option<NonZeroU16>,
    },
    /// `name`: exactly this name.
    Name(String),
    /// `*.name`: any name below `name`, not `name` itself.
    Below(String),
}

/// A port as a pattern spells it: decimal digits only, no sign and no leading zero, 1 to 65535.
fn parse_port(text: &str) -> Option<NonZeroU16> {
    if text.is_empty()
        || text.len() > 5
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse::<u16>().ok().and_then(NonZeroU16::new)
}

/// A prefix length: decimal digits only, no leading zero, at most `max`.
fn parse_len(text: &str, max: u8) -> Option<u8> {
    if text.is_empty()
        || text.len() > 3
        || !text.bytes().all(|b| b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse::<u8>().ok().filter(|len| *len <= max)
}

fn parse_v4_net(text: &str) -> Option<Net> {
    let (addr, len) = match text.split_once('/') {
        Some((addr, len)) => (addr, parse_len(len, 32)?),
        None => (text, 32),
    };
    Net::new(IpAddr::V4(Ipv4Addr::from_str(addr).ok()?), len)
}

fn parse_v6_net(text: &str) -> Option<Net> {
    let (addr, len) = match text.split_once('/') {
        Some((addr, len)) => (addr, parse_len(len, 128)?),
        None => (text, 128),
    };
    Net::new(IpAddr::V6(Ipv6Addr::from_str(addr).ok()?), len)
}

impl Pattern {
    /// Parses a pattern; `None` for text that is none of the forms of protocol.md 8 (such a
    /// pattern matches nothing).
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > MAX_NAME + 2 {
            return None;
        }
        match text {
            "*" => return Some(Self::Any),
            "self" => return Some(Self::Own),
            _ => {}
        }
        if let Some(port) = text.strip_prefix("*:") {
            return parse_port(port).map(Self::AnyPort);
        }
        if let Some(base) = text.strip_prefix("*.") {
            return Name::parse(base).ok().map(|name| Self::Below(name.0));
        }
        if text.starts_with('*') {
            return None;
        }
        if let Some(rest) = text.strip_prefix('[') {
            // `[addr]:port` and `[addr]/len:port`.
            let (inner, after) = rest.split_once(']')?;
            let addr = Ipv6Addr::from_str(inner).ok()?;
            let (len, port) = match after.strip_prefix('/') {
                Some(after) => {
                    let (len, port) = after.split_once(':')?;
                    (parse_len(len, 128)?, port)
                }
                None => (128, after.strip_prefix(':')?),
            };
            return Some(Self::Net {
                net: Net::new(IpAddr::V6(addr), len)?,
                port: Some(parse_port(port)?),
            });
        }
        if text.contains(':') {
            // An IPv6 CIDR without a port, else an IPv4 CIDR with one.
            if let Some(net) = parse_v6_net(text) {
                return Some(Self::Net { net, port: None });
            }
            let (cidr, port) = text.split_once(':')?;
            return Some(Self::Net {
                net: parse_v4_net(cidr)?,
                port: Some(parse_port(port)?),
            });
        }
        if let Some(net) = parse_v4_net(text) {
            return Some(Self::Net { net, port: None });
        }
        if text.contains('/') {
            return None;
        }
        Name::parse(text).ok().map(|name| Self::Name(name.0))
    }
}

/// `pattern` parsed, or `None` for one that matches nothing.
pub fn parse_pattern(pattern: &HostPortPattern) -> Option<Pattern> {
    Pattern::parse(&pattern.0)
}

fn parse_all(patterns: &[HostPortPattern]) -> Vec<Pattern> {
    patterns.iter().filter_map(parse_pattern).collect()
}

/// What a rule is matched against.
#[derive(Debug, Clone, Copy)]
pub enum Subject<'a> {
    /// A name, before it is resolved.
    Name(&'a Name),
    /// An address (the target literal, or one answer of the resolver), canonical.
    Addr(IpAddr),
}

/// How specific a matching pattern is: for addresses the prefix length, for names the tier
/// (exact 2, `*.name` 1, `*` 0), then whether it names a port. Compared in that order.
type Specificity = (u8, bool);

fn full_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

/// The specificity of `pattern` if it matches `subject` on `port`.
fn rank(pattern: &Pattern, subject: Subject<'_>, port: u16, own: &[IpAddr]) -> Option<Specificity> {
    match (pattern, subject) {
        (Pattern::Any, _) => Some((0, false)),
        (Pattern::AnyPort(p), _) => (p.get() == port).then_some((0, true)),
        (Pattern::Own, Subject::Addr(ip)) => own.contains(&ip).then(|| (full_len(ip), false)),
        (Pattern::Net { net, port: p }, Subject::Addr(ip)) => {
            if !net.contains(ip) || p.is_some_and(|p| p.get() != port) {
                return None;
            }
            Some((net.len, p.is_some()))
        }
        (Pattern::Name(exact), Subject::Name(name)) => {
            (exact == name.as_str()).then_some((2, false))
        }
        (Pattern::Below(base), Subject::Name(name)) => name
            .as_str()
            .strip_suffix(base.as_str())
            .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.'))
            .then_some((1, false)),
        _ => None,
    }
}

/// The verdict of the rules on one subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The most specific matching pattern is an `allow`.
    Allow,
    /// The most specific matching pattern is a `deny`, or a `deny` and an `allow` tie.
    Deny,
    /// No pattern matches.
    NoMatch,
}

/// The length of the IPv4 private range `ip` lies in, if it does: the exit's built in deny
/// entries, in force whether or not the signed Policy lists them.
fn private_range_len(ip: Ipv4Addr) -> Option<u8> {
    let [a, b, _, _] = ip.octets();
    match (a, b) {
        (10, _) => Some(8),
        (172, 16..=31) => Some(12),
        (192, 168) => Some(16),
        _ => None,
    }
}

/// Matches `subject` on `port` against both lists by specificity (protocol.md 8): the most
/// specific matching pattern of either list wins, and on equal specificity the `deny` does.
pub fn decide(
    allow: &[Pattern],
    deny: &[Pattern],
    subject: Subject<'_>,
    port: u16,
    own: &[IpAddr],
) -> Verdict {
    let best = |list: &[Pattern]| {
        list.iter()
            .filter_map(|p| rank(p, subject, port, own))
            .max()
    };
    let allow = best(allow);
    let mut deny = best(deny);
    if let Subject::Addr(IpAddr::V4(ip)) = subject
        && let Some(len) = private_range_len(ip)
    {
        deny = deny.max(Some((len, false)));
    }
    match (allow, deny) {
        (None, None) => Verdict::NoMatch,
        (Some(_), None) => Verdict::Allow,
        (None, Some(_)) => Verdict::Deny,
        (Some(allow), Some(deny)) => {
            if deny >= allow {
                Verdict::Deny
            } else {
                Verdict::Allow
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The floor
// ---------------------------------------------------------------------------------------------

fn v4_in(ip: Ipv4Addr, base: [u8; 4], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(base))
}

fn v6_in(ip: Ipv6Addr, base: [u16; 8], len: u32) -> bool {
    let mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(base))
}

/// Why no Policy may make the exit dial `ip` (canonical): the floor and the ranges protocol.md 8
/// says are not liftable. `self` is checked apart, it needs the exit's addresses.
pub fn reserved_reason(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(ip) => {
            let ranges: [([u8; 4], u32, &str); 9] = [
                ([0, 0, 0, 0], 8, "unspecified"),
                ([127, 0, 0, 0], 8, "loopback"),
                ([169, 254, 0, 0], 16, "link local"),
                ([224, 0, 0, 0], 4, "multicast"),
                (
                    [100, 64, 0, 0],
                    10,
                    "shared address space (CGNAT, cloud metadata)",
                ),
                ([198, 18, 0, 0], 15, "benchmarking"),
                ([240, 0, 0, 0], 4, "reserved (240/4)"),
                (
                    [192, 0, 0, 0],
                    24,
                    "IETF protocol assignments (192.0.0.0/24)",
                ),
                ([192, 88, 99, 0], 24, "6to4 relay anycast (192.88.99.0/24)"),
            ];
            ranges
                .iter()
                .find(|(base, len, _)| v4_in(ip, *base, *len))
                .map(|(_, _, why)| *why)
        }
        IpAddr::V6(ip) => {
            let ranges: [([u16; 8], u32, &str); 8] = [
                (
                    [0; 8],
                    96,
                    "unspecified, loopback or IPv4 compatible (::/96)",
                ),
                ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10, "link local"),
                ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8, "multicast"),
                ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7, "unique local (fc00::/7)"),
                ([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96, "NAT64 (64:ff9b::/96)"),
                (
                    [0x64, 0xff9b, 1, 0, 0, 0, 0, 0],
                    48,
                    "local use NAT64 (64:ff9b:1::/48)",
                ),
                ([0x2001, 0, 0, 0, 0, 0, 0, 0], 32, "Teredo (2001::/32)"),
                ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16, "6to4 (2002::/16)"),
            ];
            ranges
                .iter()
                .find(|(base, len, _)| v6_in(ip, *base, *len))
                .map(|(_, _, why)| *why)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The exit's own addresses
// ---------------------------------------------------------------------------------------------

/// The IPv4 addresses a `/proc/net/fib_trie` lists as local (`/32 host LOCAL` under an address
/// line).
pub fn parse_fib_trie(text: &str) -> Vec<IpAddr> {
    let mut found: Vec<IpAddr> = Vec::new();
    let mut last: Option<Ipv4Addr> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("|-- ") {
            last = Ipv4Addr::from_str(rest.trim()).ok();
        } else if line.starts_with("+--") {
            last = None;
        } else if line.starts_with("/32 host LOCAL")
            && let Some(ip) = last.take()
            && !found.contains(&IpAddr::V4(ip))
        {
            found.push(IpAddr::V4(ip));
        }
    }
    found
}

/// The addresses of a `/proc/net/if_inet6` (32 hex digits first on each line); a line that does
/// not parse is an error, so that a file this code does not understand fails closed.
pub fn parse_if_inet6(text: &str) -> io::Result<Vec<IpAddr>> {
    let mut found = Vec::new();
    for line in text.lines() {
        let Some(word) = line.split_whitespace().next() else {
            continue;
        };
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "unreadable /proc/net/if_inet6");
        if word.len() != 32 {
            return Err(bad());
        }
        let bits = u128::from_str_radix(word, 16).map_err(|_| bad())?;
        found.push(IpAddr::V6(Ipv6Addr::from(bits)));
    }
    Ok(found)
}

/// The exit's own interface addresses, from `/proc/net/fib_trie` and `/proc/net/if_inet6`
/// (Linux, std only). An error when they cannot be read or no IPv4 address is found (a host
/// always has its loopback): the executor then refuses every dial.
pub fn own_addresses() -> io::Result<Vec<IpAddr>> {
    let v4 = parse_fib_trie(&std::fs::read_to_string("/proc/net/fib_trie")?);
    if v4.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no local IPv4 address in /proc/net/fib_trie",
        ));
    }
    let v6 = match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(text) => parse_if_inet6(&text)?,
        // A kernel without IPv6 has no such file and no IPv6 address.
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error),
    };
    Ok(v4.into_iter().chain(v6).collect())
}

// ---------------------------------------------------------------------------------------------
// The rules of this node
// ---------------------------------------------------------------------------------------------

/// The `egress` entry of `policy` for `node`: `None` when there is none, and also when there are
/// two or more (ambiguous, so the node has no rule).
pub fn rule_of<'a>(policy: &'a PolicyBody, node: &NodeId) -> Option<&'a EgressRule> {
    let mut entries = policy.egress.iter().filter(|rule| rule.node_id == *node);
    let rule = entries.next()?;
    entries.next().is_none().then_some(rule)
}

/// Where the executor reads this node's [`EgressRule`] for a network, at each OPEN.
pub trait EgressRules: Send + Sync {
    /// The rule of this node in `network_id`, if its Policy has exactly one.
    fn rule(&self, network_id: &NetworkId) -> Option<EgressRule>;
}

impl<F> EgressRules for F
where
    F: Fn(&NetworkId) -> Option<EgressRule> + Send + Sync,
{
    fn rule(&self, network_id: &NetworkId) -> Option<EgressRule> {
        self(network_id)
    }
}

/// [`EgressRules`] from the node's [`PolicyStore`].
pub struct PolicyEgressRules {
    policies: Arc<PolicyStore>,
    node: NodeId,
}

impl PolicyEgressRules {
    /// The rules `node` (this node) has in the Policies of `policies`.
    pub fn new(policies: Arc<PolicyStore>, node: NodeId) -> Self {
        Self { policies, node }
    }
}

impl EgressRules for PolicyEgressRules {
    fn rule(&self, network_id: &NetworkId) -> Option<EgressRule> {
        let body = self.policies.body(network_id)?;
        rule_of(&body, &self.node).cloned()
    }
}

// ---------------------------------------------------------------------------------------------
// The executor
// ---------------------------------------------------------------------------------------------

type ResolveFn = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;
type OwnFn = Arc<dyn Fn() -> io::Result<Vec<IpAddr>> + Send + Sync>;
type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
type ConnectFn = Arc<dyn Fn(SocketAddr, u32) -> ConnectFuture + Send + Sync>;

/// Why an egress OPEN is refused, before it becomes an [`OpenRefusal`]. The reason text is for
/// the log only.
enum Fail {
    Invalid(&'static str),
    NoRule,
    Forbidden(String),
    Unreachable(String),
}

/// The exit side of `egress:*`. See the module documentation.
pub struct EgressExecutor {
    enabled: bool,
    rules: Arc<dyn EgressRules>,
    resolver: ResolveFn,
    own: OwnFn,
    connector: ConnectFn,
    lookups: Arc<Semaphore>,
    refuse_log: LogThrottle,
    own_log: LogThrottle,
    /// Set only by `narrowed_floor_for_tests`; always false in a build without tests.
    loopback_ok: bool,
    #[cfg(test)]
    log_lines: std::sync::Mutex<Vec<String>>,
}

impl std::fmt::Debug for EgressExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressExecutor")
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

impl EgressExecutor {
    /// An executor reading its rules from `rules`. With `enabled` false the node answers an
    /// egress OPEN `unknown_service` and never gets here ([`Self::enabled`]). The resolver is
    /// the system's, the own addresses [`own_addresses`], the connector the node's own socket
    /// setup.
    pub fn new(enabled: bool, rules: Arc<dyn EgressRules>) -> Self {
        Self {
            enabled,
            rules,
            resolver: Arc::new(system_resolve),
            own: Arc::new(own_addresses),
            connector: Arc::new(|addr, buffer| Box::pin(connect_addr(addr, buffer))),
            lookups: Arc::new(Semaphore::new(MAX_CONCURRENT_EGRESS_LOOKUPS)),
            refuse_log: LogThrottle::new(LOG_INTERVAL),
            own_log: LogThrottle::new(LOG_INTERVAL),
            loopback_ok: false,
            #[cfg(test)]
            log_lines: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Resolves names with `resolve` instead of the system's resolver. Blocking, run on a
    /// blocking thread.
    pub fn with_resolver(
        mut self,
        resolve: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.resolver = Arc::new(resolve);
        self
    }

    /// Takes the exit's own addresses from `own` instead of [`own_addresses`]. An `Err` makes
    /// every dial fail closed.
    pub fn with_own_addresses(
        mut self,
        own: impl Fn() -> io::Result<Vec<IpAddr>> + Send + Sync + 'static,
    ) -> Self {
        self.own = Arc::new(own);
        self
    }

    /// Connects with `connect` (given the vetted address and the socket buffer size) instead of
    /// the node's own socket setup.
    pub fn with_connector<F, Fut>(mut self, connect: F) -> Self
    where
        F: Fn(SocketAddr, u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = io::Result<TcpStream>> + Send + 'static,
    {
        self.connector = Arc::new(move |addr, buffer| Box::pin(connect(addr, buffer)));
        self
    }

    /// Lets the floor pass 127.0.0.0/8 so that a test can use a loopback echo server. Compiled
    /// only into test builds: no production code can narrow the floor.
    #[cfg(test)]
    pub(crate) fn narrowed_floor_for_tests(mut self) -> Self {
        self.loopback_ok = true;
        self
    }

    /// Whether this node's configuration enables egress.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// What the log said, for tests.
    #[cfg(test)]
    pub(crate) fn logged(&self) -> Vec<String> {
        self.log_lines.lock().unwrap().clone()
    }

    /// Whether the exit may dial `ip` (canonical) on `port`: not in the floor, not its own, and
    /// the rules allow it. `name_allowed`: the name it came from was allowed by a name pattern,
    /// which counts when no address pattern matches. The reason for a refusal is for the log.
    fn vet(
        &self,
        ip: IpAddr,
        port: u16,
        name_allowed: bool,
        lists: (&[Pattern], &[Pattern]),
        own: &[IpAddr],
    ) -> Result<(), &'static str> {
        if let Some(why) = reserved_reason(ip) {
            let narrowed = self.loopback_ok && matches!(ip, IpAddr::V4(v4) if v4.is_loopback());
            if !narrowed {
                return Err(why);
            }
        }
        if own.contains(&ip) {
            return Err("an address of the exit itself");
        }
        match decide(lists.0, lists.1, Subject::Addr(ip), port, own) {
            Verdict::Allow => Ok(()),
            Verdict::Deny => Err("denied by a rule"),
            Verdict::NoMatch if name_allowed => Ok(()),
            Verdict::NoMatch => Err("no allow rule matches"),
        }
    }

    /// Turns `fail` into the refusal a peer gets and logs the reason (throttled; the payload is
    /// never part of it and the host is escaped).
    fn refuse(&self, request: &OpenRequest, host: &str, port: u16, fail: Fail) -> OpenRefusal {
        let (code, msg, reason) = match fail {
            Fail::Invalid(reason) => (
                ErrorCode::InvalidTarget,
                "invalid target",
                reason.to_owned(),
            ),
            Fail::NoRule => (ErrorCode::NoGrant, "no grant", "no egress rule".to_owned()),
            Fail::Forbidden(reason) => (ErrorCode::Forbidden, "target not allowed", reason),
            // One text for a name that does not exist, one that resolved only to refused
            // addresses, a refused connection and a timeout.
            Fail::Unreachable(reason) => (
                ErrorCode::TargetUnreachable,
                "could not connect to the target",
                reason,
            ),
        };
        let host: String = host
            .chars()
            .take(255)
            .flat_map(char::escape_default)
            .collect();
        #[cfg(test)]
        self.log_lines
            .lock()
            .unwrap()
            .push(format!("{}: {host}:{port}: {reason}", code.name()));
        if let Some(left_out) = self.refuse_log.permit(Instant::now()) {
            tracing::info!(
                peer = %request.initiator,
                %host,
                port,
                code = code.name(),
                %reason,
                left_out,
                "refused an egress OPEN"
            );
        }
        OpenRefusal {
            code,
            msg: msg.to_owned(),
        }
    }

    /// A name looked up once on a blocking thread that owns its place among
    /// [`MAX_CONCURRENT_EGRESS_LOOKUPS`] until it returns, however long that takes.
    async fn lookup(&self, name: &Name, port: u16) -> io::Result<Vec<SocketAddr>> {
        let permit = self
            .lookups
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("the lookup limit was closed"))?;
        let (resolver, host) = (self.resolver.clone(), name.as_str().to_owned());
        tokio::task::spawn_blocking(move || {
            let result = resolver(&host, port);
            drop(permit);
            result
        })
        .await
        .map_err(io::Error::other)?
    }

    /// Runs the rules of the module documentation on `request`'s target and, if they allow it,
    /// connects to a vetted address inside `connect_timeout`. `Ok` is a connected socket; every
    /// refusal is an [`OpenRefusal`] with a fixed text.
    pub async fn dial(
        &self,
        request: &OpenRequest,
        socket_buffer: u32,
        connect_timeout: Duration,
    ) -> Result<TcpStream, OpenRefusal> {
        let Some(raw) = request.target.as_ref() else {
            return Err(self.refuse(request, "", 0, Fail::Invalid("no target")));
        };
        let (host, port) = (raw.host.as_str(), raw.port);
        let fail = |fail| self.refuse(request, host, port, fail);

        let target = Target::canonicalize(host, port)
            .map_err(|_| fail(Fail::Invalid("not a canonical host or port 0")))?;
        let port = target.port();
        let Some(rule) = self.rules.rule(&request.network_id) else {
            return Err(fail(Fail::NoRule));
        };
        let (allow, deny) = (parse_all(&rule.allow), parse_all(&rule.deny));
        if allow.is_empty() {
            return Err(fail(Fail::Forbidden("the allow list is empty".to_owned())));
        }
        // A name is judged by the name rules before anything is looked up.
        let name_allowed = match target.host() {
            Host::Addr(_) => false,
            Host::Name(name) => match decide(&allow, &deny, Subject::Name(name), port, &[]) {
                Verdict::Deny => {
                    return Err(fail(Fail::Forbidden("denied by a name rule".to_owned())));
                }
                Verdict::Allow => true,
                Verdict::NoMatch => false,
            },
        };
        let own: Vec<IpAddr> = match (self.own)() {
            Ok(own) => own.into_iter().map(|ip| ip.to_canonical()).collect(),
            Err(error) => {
                if let Some(left_out) = self.own_log.permit(Instant::now()) {
                    tracing::error!(
                        %error,
                        left_out,
                        "the exit's own addresses cannot be read: every egress dial is refused"
                    );
                }
                return Err(fail(Fail::Unreachable(format!(
                    "the exit's own addresses cannot be read: {error}"
                ))));
            }
        };
        let lists = (allow.as_slice(), deny.as_slice());

        let work = async {
            let vetted: Vec<IpAddr> = match target.host() {
                Host::Addr(ip) => {
                    if let Err(why) = self.vet(*ip, port, false, lists, &own) {
                        return Err(Fail::Forbidden(why.to_owned()));
                    }
                    vec![*ip]
                }
                Host::Name(name) => {
                    let resolved = self
                        .lookup(name, port)
                        .await
                        .map_err(|error| Fail::Unreachable(format!("did not resolve: {error}")))?;
                    let mut vetted: Vec<IpAddr> = Vec::new();
                    let mut dropped: Vec<String> = Vec::new();
                    for answer in resolved {
                        let ip = answer.ip().to_canonical();
                        if vetted.contains(&ip) {
                            continue;
                        }
                        match self.vet(ip, port, name_allowed, lists, &own) {
                            Ok(()) => vetted.push(ip),
                            Err(why) if dropped.len() < 4 => dropped.push(format!("{ip} ({why})")),
                            Err(_) => {}
                        }
                    }
                    if vetted.is_empty() {
                        return Err(Fail::Unreachable(if dropped.is_empty() {
                            "did not resolve: no address".to_owned()
                        } else {
                            format!("resolved only to refused addresses: {}", dropped.join(", "))
                        }));
                    }
                    vetted
                }
            };
            let mut last = None;
            for ip in vetted {
                match (self.connector)(SocketAddr::new(ip, port), socket_buffer).await {
                    Ok(socket) => return Ok(socket),
                    Err(error) => last = Some(error),
                }
            }
            Err(Fail::Unreachable(format!(
                "connect failed: {}",
                last.map_or_else(|| "no address".to_owned(), |error| error.to_string())
            )))
        };
        match tokio::time::timeout(connect_timeout, work).await {
            Ok(Ok(socket)) => Ok(socket),
            Ok(Err(why)) => Err(fail(why)),
            Err(_) => Err(fail(Fail::Unreachable("did not answer in time".to_owned()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use menzil_proto::{OpenMeta, OpenTarget};
    use tokio::net::TcpListener;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn name(text: &str) -> Name {
        Name::parse(text).unwrap()
    }

    // --- canonicalization ----------------------------------------------------------------

    #[test]
    fn canonicalization_accepts_names_and_strict_addresses() {
        let long_name = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61));
        assert_eq!(long_name.len(), 253);
        let name_cases = [
            "example.com",
            "a-b.c1.example",
            "localhost",
            "1.2.3.example",
            "xn--nxasmq6b.example",
            long_name.as_str(),
        ];
        for host in name_cases {
            let target = Target::canonicalize(host, 443).unwrap_or_else(|_| panic!("{host}"));
            assert_eq!(target.host(), &Host::Name(name(host)), "{host}");
            assert_eq!(target.port(), 443);
        }
        let addr_cases = [
            ("93.184.216.34", "93.184.216.34"),
            ("127.0.0.1", "127.0.0.1"),
            ("::1", "::1"),
            ("2001:db8::1", "2001:db8::1"),
            ("2001:DB8::1", "2001:db8::1"),
            // An IPv4 mapped IPv6 address is the IPv4 address, in either spelling.
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("::ffff:7f00:1", "127.0.0.1"),
            ("::ffff:10.1.2.3", "10.1.2.3"),
            // IPv4 compatible is not mapped: it stays IPv6 (and the floor refuses it).
            ("::127.0.0.1", "::7f00:1"),
        ];
        for (host, want) in addr_cases {
            let target = Target::canonicalize(host, 80).unwrap_or_else(|_| panic!("{host}"));
            assert_eq!(target.host(), &Host::Addr(ip(want)), "{host}");
        }
    }

    #[test]
    fn canonicalization_refuses_every_probe() {
        let probes: Vec<(String, u16)> = vec![
            ("0x7f.1".into(), 80),
            ("0x7f.0.0.1".into(), 80),
            ("2130706433".into(), 80),
            ("0177.0.0.1".into(), 80),
            ("127.1".into(), 80),
            ("127.0.1".into(), 80),
            ("1.2.3.4.5".into(), 80),
            ("01.2.3.4".into(), 80),
            ("256.1.1.1".into(), 80),
            ("localhost.".into(), 80),
            ("example.com.".into(), 80),
            ("LOCALHOST".into(), 80),
            ("Example.com".into(), 80),
            ("[::ffff:7f00:1]".into(), 80),
            ("[::1]".into(), 80),
            ("fe80::1%eth0".into(), 80),
            ("::1%lo".into(), 80),
            ("::ffff:127.0.0.01".into(), 80),
            ("".into(), 80),
            (".".into(), 80),
            (".example.com".into(), 80),
            ("a..b".into(), 80),
            ("a b.example".into(), 80),
            ("exa_mple.com".into(), 80),
            ("nul\0.example".into(), 80),
            ("\0".into(), 80),
            ("münchen.example".into(), 80),
            ("http://example.com".into(), 80),
            ("example.com:80".into(), 80),
            ("user@example.com".into(), 80),
            ("a".repeat(64), 80),
            (format!("{}.example.com", "a".repeat(64)), 80),
            // 254 bytes: one over.
            (
                format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(62)),
                80,
            ),
            ("a".repeat(64 * 1024), 80),
            ("example.com".into(), 0),
            ("93.184.216.34".into(), 0),
            ("::1".into(), 0),
        ];
        for (host, port) in probes {
            let shown: String = host.chars().take(40).collect();
            assert_eq!(
                Target::canonicalize(&host, port),
                Err(InvalidTarget),
                "{shown:?} port {port}"
            );
        }
        // The 253 byte name, and the same with one label shortened, are fine.
        assert!(
            Target::canonicalize(
                &format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61)),
                80
            )
            .is_ok()
        );
        assert!(Target::canonicalize(&"a".repeat(63), 80).is_ok());
    }

    // --- patterns --------------------------------------------------------------------------

    #[test]
    fn patterns_parse_in_the_forms_of_section_8_and_nothing_else() {
        let valid = [
            "10.0.0.0/8",
            "10.1.2.3",
            "10.0.0.0/8:443",
            "1.2.3.4:80",
            "0.0.0.0/0",
            "2001:db8::/32",
            "::/0",
            "::1",
            "[2001:db8::]/32:443",
            "[2001:db8::1]:443",
            "example.com",
            "*.example.com",
            "*:25",
            "*",
            "self",
            "localhost",
        ];
        for text in valid {
            assert!(Pattern::parse(text).is_some(), "{text}");
        }
        let invalid = [
            "",
            "10.0.0.1/33",
            "10.1.2.3/8",
            "10.0.0.0/08",
            "010.0.0.0/8",
            "10.0.0.0/8:0",
            "10.0.0.0/8:99999",
            "10.0.0.0/8:+80",
            "10.0.0.0/8:080",
            "10.0.0.0/8:443:1",
            "*.",
            "*.*",
            "*example.com",
            "*:",
            "*:0",
            "*:80x",
            "Example.com",
            "EXAMPLE.COM",
            "example.com.",
            "127.1",
            "[::1]",
            "[::1]/128",
            "[::1]:0",
            "[::1",
            "2001:db8::/129",
            "2001:db8::/",
            "*.1",
            "a b",
            "Self",
            "10.0.0.0/8/8",
            "fe80::1%eth0",
            "example.com:80",
        ];
        for text in invalid {
            assert_eq!(Pattern::parse(text), None, "{text}");
        }
    }

    fn pats(texts: &[&str]) -> Vec<Pattern> {
        texts
            .iter()
            .map(|t| Pattern::parse(t).unwrap_or_else(|| panic!("{t}")))
            .collect()
    }

    fn addr_verdict(allow: &[&str], deny: &[&str], addr: &str, port: u16) -> Verdict {
        decide(
            &pats(allow),
            &pats(deny),
            Subject::Addr(ip(addr)),
            port,
            &[],
        )
    }

    fn name_verdict(allow: &[&str], deny: &[&str], host: &str, port: u16) -> Verdict {
        decide(
            &pats(allow),
            &pats(deny),
            Subject::Name(&name(host)),
            port,
            &[],
        )
    }

    #[test]
    fn address_specificity_prefix_then_port_and_deny_wins_a_tie() {
        use Verdict::*;
        // A longer prefix beats a shorter one, either way round.
        assert_eq!(
            addr_verdict(&["203.0.113.0/24"], &["203.0.0.0/8"], "203.0.113.9", 80),
            Allow
        );
        assert_eq!(
            addr_verdict(&["203.0.0.0/8"], &["203.0.113.0/24"], "203.0.113.9", 80),
            Deny
        );
        // At the same length a port beats none, either way round.
        assert_eq!(
            addr_verdict(
                &["203.0.113.0/24:80"],
                &["203.0.113.0/24"],
                "203.0.113.9",
                80
            ),
            Allow
        );
        assert_eq!(
            addr_verdict(
                &["203.0.113.0/24"],
                &["203.0.113.0/24:80"],
                "203.0.113.9",
                80
            ),
            Deny
        );
        // A port that is not the target's does not match at all.
        assert_eq!(
            addr_verdict(
                &["203.0.113.0/24"],
                &["203.0.113.0/24:81"],
                "203.0.113.9",
                80
            ),
            Allow
        );
        // Equal specificity: the deny.
        assert_eq!(
            addr_verdict(&["203.0.113.0/24"], &["203.0.113.0/24"], "203.0.113.9", 80),
            Deny
        );
        assert_eq!(
            addr_verdict(
                &["203.0.113.0/24:80"],
                &["203.0.113.0/24:80"],
                "203.0.113.9",
                80
            ),
            Deny
        );
        assert_eq!(
            addr_verdict(&["0.0.0.0/0"], &["*"], "203.0.113.9", 80),
            Deny
        );
        // No match and the families do not mix.
        assert_eq!(
            addr_verdict(&["198.51.100.0/24"], &[], "203.0.113.9", 80),
            NoMatch
        );
        assert_eq!(
            addr_verdict(&["0.0.0.0/0"], &[], "2001:db8::1", 80),
            NoMatch
        );
        assert_eq!(addr_verdict(&["::/0"], &[], "203.0.113.9", 80), NoMatch);
        assert_eq!(addr_verdict(&["::/0"], &[], "2001:db8::1", 80), Allow);
        // `*` and `*:port` match addresses too.
        assert_eq!(addr_verdict(&["*"], &[], "203.0.113.9", 80), Allow);
        assert_eq!(addr_verdict(&["*:80"], &[], "2001:db8::1", 80), Allow);
        assert_eq!(addr_verdict(&["*:80"], &[], "2001:db8::1", 81), NoMatch);
        // A name pattern never matches an address.
        assert_eq!(
            addr_verdict(&["example.com", "*.example.com"], &[], "203.0.113.9", 80),
            NoMatch
        );
    }

    #[test]
    fn the_built_in_private_deny_entries_hold_without_a_signed_list() {
        use Verdict::*;
        assert_eq!(addr_verdict(&["0.0.0.0/0"], &[], "10.1.2.3", 80), Deny);
        assert_eq!(addr_verdict(&["0.0.0.0/0"], &[], "172.16.0.1", 80), Deny);
        assert_eq!(
            addr_verdict(&["0.0.0.0/0"], &[], "172.31.255.255", 80),
            Deny
        );
        assert_eq!(addr_verdict(&["0.0.0.0/0"], &[], "172.32.0.1", 80), Allow);
        assert_eq!(addr_verdict(&["0.0.0.0/0"], &[], "192.168.1.1", 80), Deny);
        assert_eq!(addr_verdict(&["0.0.0.0/0"], &[], "192.169.1.1", 80), Allow);
        // An allow of the very same prefix ties; a longer one lifts.
        assert_eq!(addr_verdict(&["10.0.0.0/8"], &[], "10.1.2.3", 80), Deny);
        assert_eq!(addr_verdict(&["10.1.0.0/16"], &[], "10.1.2.3", 80), Allow);
        assert_eq!(addr_verdict(&["10.1.0.0/16"], &[], "10.2.2.3", 80), Deny);
    }

    #[test]
    fn name_specificity_is_exact_then_wildcard_then_star_and_a_port_beats_none() {
        use Verdict::*;
        // exact > *.name
        assert_eq!(
            name_verdict(
                &["api.corp.example"],
                &["*.corp.example"],
                "api.corp.example",
                443
            ),
            Allow
        );
        assert_eq!(
            name_verdict(
                &["*.corp.example"],
                &["api.corp.example"],
                "api.corp.example",
                443
            ),
            Deny
        );
        assert_eq!(
            name_verdict(
                &["api.corp.example"],
                &["*.corp.example"],
                "db.corp.example",
                443
            ),
            Deny
        );
        // *.name > *
        assert_eq!(
            name_verdict(&["*.example"], &["*"], "a.example", 443),
            Allow
        );
        assert_eq!(name_verdict(&["*"], &["*.example"], "a.example", 443), Deny);
        // *.name is not name itself, nor a name that merely ends in the same letters.
        assert_eq!(name_verdict(&["*.example"], &[], "example", 443), NoMatch);
        assert_eq!(
            name_verdict(&["*.example"], &[], "badexample", 443),
            NoMatch
        );
        assert_eq!(name_verdict(&["*.example"], &[], "a.b.example", 443), Allow);
        // a port beats none at the same tier; a tie is a deny.
        assert_eq!(name_verdict(&["*:443"], &["*"], "a.example", 443), Allow);
        assert_eq!(name_verdict(&["*"], &["*:443"], "a.example", 443), Deny);
        assert_eq!(name_verdict(&["*"], &["*"], "a.example", 443), Deny);
        assert_eq!(name_verdict(&["*:443"], &["*:443"], "a.example", 443), Deny);
        // Address patterns do not apply to a name.
        assert_eq!(
            name_verdict(&["0.0.0.0/0", "::/0"], &[], "a.example", 443),
            NoMatch
        );
    }

    #[test]
    fn self_matches_the_exits_own_addresses_with_a_full_length_prefix() {
        let own = [ip("203.0.113.7"), ip("2001:db8::7")];
        let decide_own = |allow: &[&str], deny: &[&str], addr: &str| {
            decide(&pats(allow), &pats(deny), Subject::Addr(ip(addr)), 80, &own)
        };
        assert_eq!(
            decide_own(&["0.0.0.0/0"], &["self"], "203.0.113.7"),
            Verdict::Deny
        );
        assert_eq!(
            decide_own(&["0.0.0.0/0"], &["self"], "203.0.113.8"),
            Verdict::Allow
        );
        assert_eq!(
            decide_own(&["::/0"], &["self"], "2001:db8::7"),
            Verdict::Deny
        );
        // The same length ties with a /32 allow: the deny.
        assert_eq!(
            decide_own(&["203.0.113.7/32"], &["self"], "203.0.113.7"),
            Verdict::Deny
        );
    }

    // --- the executor ----------------------------------------------------------------------

    /// The default deny list of protocol.md 8.
    fn default_deny() -> Vec<&'static str> {
        vec![
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "198.18.0.0/15",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "192.0.0.0/24",
            "192.88.99.0/24",
            "::/96",
            "::/128",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
            "64:ff9b::/96",
            "64:ff9b:1::/48",
            "2001::/32",
            "2002::/16",
            "self",
            "*:25",
        ]
    }

    fn rule(allow: &[&str], deny: &[&str]) -> EgressRule {
        let list = |texts: &[&str]| texts.iter().map(|t| HostPortPattern((*t).into())).collect();
        EgressRule {
            node_id: NodeId::from([7u8; 32]),
            allow: list(allow),
            deny: list(deny),
        }
    }

    fn internet() -> Vec<&'static str> {
        vec!["0.0.0.0/0", "::/0"]
    }

    /// What a test executor was asked to resolve and to connect to.
    #[derive(Default)]
    struct Seen {
        resolved: Mutex<Vec<(String, u16)>>,
        connected: Mutex<Vec<SocketAddr>>,
    }

    impl Seen {
        fn resolved(&self) -> Vec<(String, u16)> {
            self.resolved.lock().unwrap().clone()
        }
        fn connected(&self) -> Vec<SocketAddr> {
            self.connected.lock().unwrap().clone()
        }
    }

    /// An executor with the production floor, no own addresses, a resolver that answers from
    /// `table` (a name that is not in it does not exist), and a connector that records the
    /// address it is given and then connects to `sink` instead (a loopback listener of the test,
    /// so that no other address is dialled).
    fn executor(
        rule: EgressRule,
        table: Vec<(&'static str, Vec<&'static str>)>,
        sink: SocketAddr,
    ) -> (EgressExecutor, Arc<Seen>) {
        let seen = Arc::new(Seen::default());
        let (resolver_seen, connector_seen) = (seen.clone(), seen.clone());
        let executor = EgressExecutor::new(true, Arc::new(move |_: &NetworkId| Some(rule.clone())))
            .with_own_addresses(|| Ok(Vec::new()))
            .with_resolver(move |host, port| {
                resolver_seen
                    .resolved
                    .lock()
                    .unwrap()
                    .push((host.to_owned(), port));
                table
                    .iter()
                    .find(|(name, _)| *name == host)
                    .map(|(_, answers)| {
                        answers
                            .iter()
                            .map(|a| SocketAddr::new(ip(a), port))
                            .collect()
                    })
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such host"))
            })
            .with_connector(move |addr, _buffer| {
                connector_seen.connected.lock().unwrap().push(addr);
                async move { TcpStream::connect(sink).await }
            });
        (executor, seen)
    }

    /// A loopback listener that counts what it accepts.
    struct Counter {
        addr: SocketAddr,
        accepts: Arc<AtomicUsize>,
    }

    async fn counter() -> Counter {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepts = Arc::new(AtomicUsize::new(0));
        let count = accepts.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                held.push(socket);
            }
        });
        Counter { addr, accepts }
    }

    impl Counter {
        /// How many connections the listener accepted, after giving a connect time to arrive.
        async fn accepted(&self) -> usize {
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.accepts.load(Ordering::SeqCst)
        }
    }

    fn request(host: &str, port: u16) -> OpenRequest {
        OpenRequest {
            network_id: NetworkId::from([1u8; 32]),
            initiator: NodeId::from([2u8; 32]),
            service: "egress:*".parse().unwrap(),
            target: Some(OpenTarget {
                host: host.to_owned(),
                port,
            }),
            meta: OpenMeta::default(),
        }
    }

    async fn dial(
        executor: &EgressExecutor,
        host: &str,
        port: u16,
    ) -> Result<TcpStream, OpenRefusal> {
        executor
            .dial(&request(host, port), 64 * 1024, TIMEOUT)
            .await
    }

    async fn refusal_of(executor: &EgressExecutor, host: &str, port: u16) -> OpenRefusal {
        match dial(executor, host, port).await {
            Ok(_) => panic!("{host}:{port} was dialled"),
            Err(refusal) => refusal,
        }
    }

    #[tokio::test]
    async fn an_invalid_target_is_invalid_target_and_nothing_is_resolved_or_dialled() {
        let sink = counter().await;
        let (executor, seen) = executor(rule(&internet(), &default_deny()), vec![], sink.addr);
        for (host, port) in [
            ("127.1", 80),
            ("0x7f.1", 80),
            ("LOCALHOST", 80),
            ("example.com", 0),
        ] {
            let refusal = refusal_of(&executor, host, port).await;
            assert_eq!(refusal.code, ErrorCode::InvalidTarget, "{host}");
        }
        // No target at all.
        let mut no_target = request("example.com", 80);
        no_target.target = None;
        let refusal = executor
            .dial(&no_target, 1024, TIMEOUT)
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(refusal.code, ErrorCode::InvalidTarget);
        assert!(seen.resolved().is_empty());
        assert!(seen.connected().is_empty());
        assert_eq!(sink.accepted().await, 0);
    }

    #[tokio::test]
    async fn the_floor_refuses_literals_whatever_the_rules_say_and_dials_nothing() {
        // The rules allow the whole internet and list no deny at all: only the floor and the
        // built in entries stand between these targets and a connect.
        let sink = counter().await;
        let (executor, seen) = executor(rule(&internet(), &[]), vec![], sink.addr);
        let refused = [
            "127.0.0.1",
            "127.255.255.254",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "0.0.0.0",
            "0.1.2.3",
            "::",
            "169.254.169.254",
            "fe80::1",
            "224.0.0.1",
            "239.255.255.250",
            "ff02::1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.0.192",
            "100.100.100.200",
            "100.64.0.1",
            "198.18.0.1",
            "198.19.255.255",
            "192.88.99.1",
            "::127.0.0.1",
            "::2",
            "fd00:ec2::254",
            "fc00::1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2002:7f00:1::",
            "2002:a00:1::",
        ];
        for host in refused {
            let refusal = refusal_of(&executor, host, 443).await;
            assert_eq!(refusal.code, ErrorCode::Forbidden, "{host}");
        }
        assert!(seen.connected().is_empty());
        assert_eq!(sink.accepts.load(Ordering::SeqCst), 0);
        // Neighbours of those ranges are public and pass (this also shows the table is not
        // simply refusing everything).
        for host in [
            "100.63.255.255",
            "100.128.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "239.0.0.0",
            "223.255.255.255",
            "192.0.1.1",
            "192.88.100.1",
            "2001:db8::1",
            "2003::1",
            "2606:4700::1111",
            "64:ff9a::1",
        ] {
            if host == "239.0.0.0" {
                // multicast ends at 239.255.255.255: this one is inside the floor.
                assert_eq!(
                    refusal_of(&executor, host, 443).await.code,
                    ErrorCode::Forbidden,
                    "{host}"
                );
                continue;
            }
            dial(&executor, host, 443)
                .await
                .unwrap_or_else(|r| panic!("{host}: {r:?}"));
        }
    }

    #[tokio::test]
    async fn the_production_floor_refuses_loopback_with_zero_accepts_and_the_narrowed_one_does_not()
    {
        let target = counter().await;
        let port = target.addr.port();
        let rules = rule(&["127.0.0.0/8"], &[]);
        // Production constructor, the real connector: a connect would show as an accept.
        let production = EgressExecutor::new(true, {
            let rules = rules.clone();
            Arc::new(move |_: &NetworkId| Some(rules.clone()))
        })
        .with_own_addresses(|| Ok(Vec::new()))
        .with_resolver(|_, port| Ok(vec![SocketAddr::new(ip("127.0.0.1"), port)]));
        for host in ["127.0.0.1", "::ffff:127.0.0.1", "localhost"] {
            let refusal = refusal_of(&production, host, port).await;
            let want = if host == "localhost" {
                ErrorCode::TargetUnreachable
            } else {
                ErrorCode::Forbidden
            };
            assert_eq!(refusal.code, want, "{host}");
        }
        assert_eq!(
            target.accepted().await,
            0,
            "the production floor dialled loopback"
        );

        // The test only floor lets the very same rules through, so the difference is exactly the
        // narrowing and a connect really would have been seen.
        let narrowed =
            EgressExecutor::new(true, Arc::new(move |_: &NetworkId| Some(rules.clone())))
                .with_own_addresses(|| Ok(Vec::new()))
                .narrowed_floor_for_tests();
        let socket = dial(&narrowed, "127.0.0.1", port).await.unwrap();
        assert_eq!(target.accepted().await, 1);
        drop(socket);
        // And the narrowing is for 127.0.0.0/8 only.
        let refusal = refusal_of(&narrowed, "::1", port).await;
        assert_eq!(refusal.code, ErrorCode::Forbidden);
        let refusal = refusal_of(&narrowed, "169.254.169.254", 80).await;
        assert_eq!(refusal.code, ErrorCode::Forbidden);
    }

    #[tokio::test]
    async fn names_that_resolve_into_refused_ranges_are_target_unreachable_like_a_missing_name() {
        let sink = counter().await;
        let table = vec![
            ("localhost", vec!["127.0.0.1", "::1"]),
            ("mapped.example", vec!["::ffff:127.0.0.1"]),
            ("private.example", vec!["10.0.0.1"]),
            ("metadata.example", vec!["169.254.169.254"]),
            ("oracle.example", vec!["192.0.0.192"]),
            ("alibaba.example", vec!["100.100.100.200"]),
            ("ula.example", vec!["fd00:ec2::254"]),
            (
                "mixed.example",
                vec!["127.0.0.1", "10.0.0.1", "169.254.169.254"],
            ),
        ];
        let (executor, seen) = executor(rule(&internet(), &default_deny()), table, sink.addr);
        let missing = refusal_of(&executor, "nothing.example", 443).await;
        assert_eq!(missing.code, ErrorCode::TargetUnreachable);
        for host in [
            "localhost",
            "mapped.example",
            "private.example",
            "metadata.example",
            "oracle.example",
            "alibaba.example",
            "ula.example",
            "mixed.example",
        ] {
            let refusal = refusal_of(&executor, host, 443).await;
            assert_eq!(refusal.code, missing.code, "{host}");
            assert_eq!(refusal.msg, missing.msg, "{host}");
        }
        assert!(seen.connected().is_empty());
        assert_eq!(sink.accepts.load(Ordering::SeqCst), 0);
        // The real reason is in the log, apart from what the peer was told.
        let log = executor.logged().join("\n");
        assert!(log.contains("127.0.0.1 (loopback)"), "{log}");
        assert!(
            log.contains("::1 (unspecified, loopback or IPv4 compatible"),
            "{log}"
        );
        assert!(log.contains("10.0.0.1 (denied by a rule)"), "{log}");
        assert!(log.contains("169.254.169.254 (link local)"), "{log}");
        assert!(log.contains("did not resolve"), "{log}");
        assert!(!missing.msg.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn an_empty_allow_allows_nothing_and_resolves_nothing() {
        let sink = counter().await;
        let table = vec![("example.com", vec!["203.0.113.9"])];
        let (executor, seen) = executor(rule(&[], &default_deny()), table, sink.addr);
        assert_eq!(
            refusal_of(&executor, "203.0.113.9", 443).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            refusal_of(&executor, "example.com", 443).await.code,
            ErrorCode::Forbidden
        );
        // Patterns that do not parse count as no allow at all.
        let (executor, seen2) =
            executor_for(rule(&["10.1.2.3/8", "Example.com", "junk"], &[]), sink.addr);
        assert_eq!(
            refusal_of(&executor, "203.0.113.9", 443).await.code,
            ErrorCode::Forbidden
        );
        assert!(seen.resolved().is_empty() && seen2.resolved().is_empty());
        assert!(seen.connected().is_empty() && seen2.connected().is_empty());
    }

    fn executor_for(rule: EgressRule, sink: SocketAddr) -> (EgressExecutor, Arc<Seen>) {
        executor(rule, vec![("example.com", vec!["203.0.113.9"])], sink)
    }

    #[tokio::test]
    async fn a_signed_allow_lifts_part_of_a_private_range_and_nothing_below_the_floor() {
        let sink = counter().await;
        // 172.16.18.0/24 against the default deny 172.16.0.0/12.
        let mut allow = internet();
        allow.push("172.16.18.0/24");
        let (executor, seen) = executor_for(rule(&allow, &default_deny()), sink.addr);
        dial(&executor, "172.16.18.6", 22).await.unwrap();
        assert_eq!(
            seen.connected(),
            vec![SocketAddr::new(ip("172.16.18.6"), 22)]
        );
        assert_eq!(
            refusal_of(&executor, "172.16.19.1", 22).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            refusal_of(&executor, "10.0.0.1", 22).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            refusal_of(&executor, "172.16.0.1", 22).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(seen.connected().len(), 1);

        // The same with no deny list signed at all: the built in entries are the same.
        let (executor, seen) = executor_for(rule(&allow, &[]), sink.addr);
        dial(&executor, "172.16.18.6", 22).await.unwrap();
        assert_eq!(
            refusal_of(&executor, "172.16.19.1", 22).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(seen.connected().len(), 1);

        // Allows inside the floor and inside the non liftable ranges are ignored.
        let allowed_floor = [
            "127.0.0.0/8",
            "127.0.0.1/32",
            "100.64.0.0/10",
            "100.100.100.0/24",
            "169.254.0.0/16",
            "169.254.169.254/32",
            "0.0.0.0/8",
            "224.0.0.0/4",
            "198.18.0.0/15",
            "240.0.0.0/4",
            "192.0.0.0/24",
            "192.88.99.0/24",
            "::1/128",
            "::/96",
            "fc00::/7",
            "fe80::/10",
            "ff00::/8",
            "64:ff9b::/96",
            "64:ff9b:1::/48",
            "2001::/32",
            "2002::/16",
        ];
        let (executor, seen) = executor_for(rule(&allowed_floor, &[]), sink.addr);
        for host in [
            "127.0.0.1",
            "100.64.0.1",
            "100.100.100.200",
            "169.254.169.254",
            "0.0.0.1",
            "224.0.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "192.0.0.192",
            "192.88.99.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "2001::1",
            "2002::1",
        ] {
            assert_eq!(
                refusal_of(&executor, host, 443).await.code,
                ErrorCode::Forbidden,
                "{host}"
            );
        }
        assert!(seen.connected().is_empty());
        // Only the two lifted dials reached the sink (above); the refused ones did not.
        assert_eq!(sink.accepted().await, 2);
        // An allow of a range does not lift the floor for the whole internet either.
        let (executor, seen) = executor_for(rule(&internet(), &[]), sink.addr);
        assert_eq!(
            refusal_of(&executor, "127.0.0.1", 443).await.code,
            ErrorCode::Forbidden
        );
        assert!(seen.connected().is_empty());
    }

    #[tokio::test]
    async fn the_whole_internet_is_an_explicit_allow_and_port_25_is_denied_by_default() {
        let sink = counter().await;
        let (executor, seen) = executor_for(rule(&internet(), &default_deny()), sink.addr);
        dial(&executor, "203.0.113.9", 443).await.unwrap();
        dial(&executor, "2001:db8::1", 443).await.unwrap();
        dial(&executor, "example.com", 443).await.unwrap();
        assert_eq!(seen.connected().len(), 3);
        // The default deny `*:25` beats `0.0.0.0/0` and `::/0` (a port beats none).
        assert_eq!(
            refusal_of(&executor, "203.0.113.9", 25).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            refusal_of(&executor, "2001:db8::1", 25).await.code,
            ErrorCode::Forbidden
        );
        let by_name = refusal_of(&executor, "example.com", 25).await;
        assert_eq!(by_name.code, ErrorCode::Forbidden);
        assert_eq!(seen.connected().len(), 3);

        // A signed `allow *:25` ties with the default deny `*:25`, and a tie is a deny (the
        // stricter reading of protocol.md 8; see the module documentation).
        let mut allow = internet();
        allow.push("*:25");
        let (executor, seen) = executor_for(rule(&allow, &default_deny()), sink.addr);
        assert_eq!(
            refusal_of(&executor, "203.0.113.9", 25).await.code,
            ErrorCode::Forbidden
        );
        // An allow with a longer prefix on the port lifts it for that prefix only, and only on
        // that port.
        let mut allow = internet();
        allow.push("203.0.113.0/24:25");
        let (executor, seen2) = executor_for(rule(&allow, &default_deny()), sink.addr);
        dial(&executor, "203.0.113.9", 25).await.unwrap();
        assert_eq!(
            refusal_of(&executor, "198.51.100.1", 25).await.code,
            ErrorCode::Forbidden
        );
        dial(&executor, "203.0.113.9", 587).await.unwrap();
        assert_eq!(
            seen2.connected(),
            vec![
                SocketAddr::new(ip("203.0.113.9"), 25),
                SocketAddr::new(ip("203.0.113.9"), 587)
            ]
        );
        assert!(seen.connected().is_empty());
    }

    #[tokio::test]
    async fn a_name_is_resolved_once_and_only_a_vetted_address_is_connected_to() {
        let sink = counter().await;
        let table = vec![
            ("public-first.example", vec!["203.0.113.9", "127.0.0.1"]),
            (
                "loopback-first.example",
                vec!["127.0.0.1", "10.0.0.1", "203.0.113.10", "203.0.113.9"],
            ),
            ("mapped.example", vec!["::ffff:127.0.0.1", "203.0.113.11"]),
        ];
        let (executor, seen) = executor(rule(&internet(), &default_deny()), table, sink.addr);
        dial(&executor, "public-first.example", 443).await.unwrap();
        assert_eq!(
            seen.resolved(),
            vec![("public-first.example".to_owned(), 443)]
        );
        assert_eq!(
            seen.connected(),
            vec![SocketAddr::new(ip("203.0.113.9"), 443)]
        );

        dial(&executor, "loopback-first.example", 8443)
            .await
            .unwrap();
        assert_eq!(seen.resolved().len(), 2, "one lookup per OPEN");
        // The first vetted answer is the one dialled, not the first answer.
        assert_eq!(
            seen.connected()[1],
            SocketAddr::new(ip("203.0.113.10"), 8443)
        );

        dial(&executor, "mapped.example", 443).await.unwrap();
        assert_eq!(seen.resolved().len(), 3);
        assert_eq!(
            seen.connected()[2],
            SocketAddr::new(ip("203.0.113.11"), 443)
        );
        assert_eq!(seen.connected().len(), 3);
    }

    #[tokio::test]
    async fn a_connect_that_fails_tries_the_next_vetted_address_and_never_a_dropped_one() {
        let sink = counter().await;
        let seen = Arc::new(Seen::default());
        let connector_seen = seen.clone();
        let executor = EgressExecutor::new(true, {
            let rules = rule(&internet(), &default_deny());
            Arc::new(move |_: &NetworkId| Some(rules.clone()))
        })
        .with_own_addresses(|| Ok(Vec::new()))
        .with_resolver(|_, port| {
            Ok(vec![
                SocketAddr::new(ip("127.0.0.1"), port),
                SocketAddr::new(ip("203.0.113.9"), port),
                SocketAddr::new(ip("203.0.113.9"), port),
                SocketAddr::new(ip("203.0.113.10"), port),
            ])
        })
        .with_connector(move |addr, _| {
            connector_seen.connected.lock().unwrap().push(addr);
            let sink = sink.addr;
            async move {
                if addr.ip() == ip("203.0.113.9") {
                    Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
                } else {
                    TcpStream::connect(sink).await
                }
            }
        });
        dial(&executor, "multi.example", 443).await.unwrap();
        // 127.0.0.1 dropped, the duplicate answer asked once, then the next vetted address.
        assert_eq!(
            seen.connected(),
            vec![
                SocketAddr::new(ip("203.0.113.9"), 443),
                SocketAddr::new(ip("203.0.113.10"), 443)
            ]
        );
    }

    #[tokio::test]
    async fn a_resolver_that_hangs_or_a_connect_that_hangs_is_given_up_on_alike() {
        let sink = counter().await;
        let rules = rule(&internet(), &default_deny());
        let slow_connect = EgressExecutor::new(true, {
            let rules = rules.clone();
            Arc::new(move |_: &NetworkId| Some(rules.clone()))
        })
        .with_own_addresses(|| Ok(Vec::new()))
        .with_connector(|_, _| std::future::pending::<io::Result<TcpStream>>());
        let refusal = slow_connect
            .dial(
                &request("203.0.113.9", 443),
                1024,
                Duration::from_millis(100),
            )
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(refusal.code, ErrorCode::TargetUnreachable);
        assert!(
            slow_connect
                .logged()
                .join("\n")
                .contains("did not answer in time")
        );

        let slow_resolve =
            EgressExecutor::new(true, Arc::new(move |_: &NetworkId| Some(rules.clone())))
                .with_own_addresses(|| Ok(Vec::new()))
                .with_resolver(|_, _| {
                    std::thread::sleep(Duration::from_millis(500));
                    Ok(vec![SocketAddr::new(ip("203.0.113.9"), 443)])
                })
                .with_connector(move |_, _| {
                    let sink = sink.addr;
                    async move { TcpStream::connect(sink).await }
                });
        let started = std::time::Instant::now();
        let refusal = slow_resolve
            .dial(
                &request("slow.example", 443),
                1024,
                Duration::from_millis(100),
            )
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(refusal.code, ErrorCode::TargetUnreachable);
        assert!(started.elapsed() < Duration::from_millis(400));
        assert_eq!(refusal.msg, "could not connect to the target");
    }

    #[tokio::test]
    async fn name_rules_run_before_resolution_and_a_denied_name_is_not_looked_up() {
        let sink = counter().await;
        let table = vec![
            ("api.internal.example", vec!["203.0.113.9"]),
            ("db.internal.example", vec!["203.0.113.10"]),
            ("www.example", vec!["203.0.113.11"]),
        ];
        let mut allow = internet();
        allow.push("api.internal.example");
        let mut deny = default_deny();
        deny.push("*.internal.example");
        let (executor, seen) = executor(rule(&allow, &deny), table, sink.addr);
        // Denied by name: forbidden, and the resolver was never asked.
        assert_eq!(
            refusal_of(&executor, "db.internal.example", 443).await.code,
            ErrorCode::Forbidden
        );
        assert!(seen.resolved().is_empty());
        // The exact name beats the wildcard deny.
        dial(&executor, "api.internal.example", 443).await.unwrap();
        dial(&executor, "www.example", 443).await.unwrap();
        assert_eq!(seen.resolved().len(), 2);
    }

    #[tokio::test]
    async fn a_name_allow_makes_its_addresses_count_but_never_reaches_a_private_range() {
        let sink = counter().await;
        let table = vec![
            ("only.example", vec!["203.0.113.9"]),
            ("inside.only.example", vec!["10.1.2.3"]),
            ("floor.only.example", vec!["169.254.169.254"]),
            ("other.example", vec!["203.0.113.9"]),
        ];
        let (executor, seen) = executor(
            rule(&["only.example", "*.only.example"], &default_deny()),
            table,
            sink.addr,
        );
        dial(&executor, "only.example", 443).await.unwrap();
        // The name allow carries no addresses of its own: the private range and the floor drop
        // them, and a name no allow covers is refused at once.
        assert_eq!(
            refusal_of(&executor, "inside.only.example", 443).await.code,
            ErrorCode::TargetUnreachable
        );
        assert_eq!(
            refusal_of(&executor, "floor.only.example", 443).await.code,
            ErrorCode::TargetUnreachable
        );
        // Not covered by any allow: no name pattern matches, no address pattern allows.
        assert_eq!(
            refusal_of(&executor, "other.example", 443).await.code,
            ErrorCode::TargetUnreachable
        );
        // A literal is judged by the address rules only: no address allow, refused.
        assert_eq!(
            refusal_of(&executor, "203.0.113.9", 443).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            seen.connected(),
            vec![SocketAddr::new(ip("203.0.113.9"), 443)]
        );
    }

    #[tokio::test]
    async fn the_exits_own_addresses_are_refused_through_self_and_a_failure_to_read_them_refuses_all()
     {
        let sink = counter().await;
        let table = vec![
            ("me.example", vec!["203.0.113.7"]),
            ("ok.example", vec!["203.0.113.9"]),
        ];
        let (executor, seen) =
            executor(rule(&internet(), &default_deny()), table.clone(), sink.addr);
        // The own address in a test is a public looking one: the floor does not know it.
        let executor = executor.with_own_addresses(|| {
            Ok(vec![
                ip("203.0.113.7"),
                ip("::ffff:203.0.113.8"),
                ip("2001:db8::7"),
            ])
        });
        assert_eq!(
            refusal_of(&executor, "203.0.113.7", 443).await.code,
            ErrorCode::Forbidden
        );
        // A mapped own address counts as the IPv4 one.
        assert_eq!(
            refusal_of(&executor, "203.0.113.8", 443).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            refusal_of(&executor, "2001:db8::7", 443).await.code,
            ErrorCode::Forbidden
        );
        assert_eq!(
            refusal_of(&executor, "me.example", 443).await.code,
            ErrorCode::TargetUnreachable
        );
        dial(&executor, "203.0.113.9", 443).await.unwrap();
        dial(&executor, "ok.example", 443).await.unwrap();
        assert_eq!(seen.connected().len(), 2);
        assert!(
            executor
                .logged()
                .join("\n")
                .contains("203.0.113.7 (an address of the exit itself)")
        );

        // The own addresses cannot be read: nothing is dialled, not even a public address.
        let (broken, seen) = executor_for(rule(&internet(), &default_deny()), sink.addr);
        let broken = broken.with_own_addresses(|| Err(io::Error::other("no /proc")));
        for host in ["203.0.113.9", "example.com"] {
            let refusal = refusal_of(&broken, host, 443).await;
            assert_eq!(refusal.code, ErrorCode::TargetUnreachable, "{host}");
        }
        assert!(seen.connected().is_empty());
        assert!(seen.resolved().is_empty());
        assert!(
            broken
                .logged()
                .join("\n")
                .contains("own addresses cannot be read: no /proc")
        );
        // Only the two dials before the failure reached the sink.
        assert_eq!(sink.accepted().await, 2);
    }

    #[test]
    fn the_own_address_files_parse() {
        let fib = "\
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.0.0.0/8 2 0 2
        |-- 10.1.2.3
           /32 host LOCAL
        |-- 10.1.2.255
           /32 link BROADCAST
     |-- 127.0.0.0
        /8 host LOCAL
Local:
  +-- 0.0.0.0/0 3 0 5
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.1
           /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     |-- 10.1.2.3
        /32 host LOCAL
";
        assert_eq!(parse_fib_trie(fib), vec![ip("10.1.2.3"), ip("127.0.0.1")]);
        assert_eq!(parse_fib_trie("garbage"), Vec::<IpAddr>::new());
        let inet6 = "\
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000026ffffffe123456 02 40 20 80     eth0
20010db8000000000000000000000007 02 40 00 80     eth0
";
        assert_eq!(
            parse_if_inet6(inet6).unwrap(),
            vec![ip("::1"), ip("fe80::26f:ffff:fe12:3456"), ip("2001:db8::7")]
        );
        assert!(parse_if_inet6("nonsense 01 80").is_err());
        assert!(parse_if_inet6("0000000000000000000000000000000z 01 80 10 80 lo").is_err());
        assert_eq!(parse_if_inet6("").unwrap(), Vec::<IpAddr>::new());
    }

    #[test]
    fn the_real_own_addresses_include_loopback_on_this_host() {
        // Reads this machine's /proc: loopback is always there on Linux.
        let own = own_addresses().expect("/proc/net/fib_trie is readable");
        assert!(own.contains(&ip("127.0.0.1")), "{own:?}");
    }

    #[test]
    fn a_node_with_two_egress_entries_has_no_rule() {
        let node = NodeId::from([7u8; 32]);
        let other = NodeId::from([8u8; 32]);
        let entry = |node_id| EgressRule {
            node_id,
            allow: vec![],
            deny: vec![],
        };
        let mut body = PolicyBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id: NetworkId::from([1u8; 32]),
            seq: 1,
            issued: 0,
            expires: 4_000_000_000,
            members: vec![],
            certs: vec![],
            grants: vec![],
            egress: vec![],
            accept: vec![],
        };
        assert!(rule_of(&body, &node).is_none());
        body.egress = vec![entry(other)];
        assert!(rule_of(&body, &node).is_none());
        body.egress = vec![entry(other), entry(node)];
        assert!(rule_of(&body, &node).is_some());
        body.egress = vec![entry(node), entry(other), entry(node)];
        assert!(rule_of(&body, &node).is_none());
    }
}
