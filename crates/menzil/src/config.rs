//! `config.toml`: the settings a person writes. Everything else this crate keeps is made by
//! commands; this file is the one thing edited by hand.
//!
//! ```toml
//! # Connection information of the relay (printed by `menzil relay run`).
//! relay = "menzil://relay.example.org:443/_menzil/v1?id=<hex>&key=<hex>"
//!
//! # Optional: a proxy URL, or "direct". Without it the usual environment variables apply.
//! # proxy = "http://proxy.corp.example:3128"
//!
//! # What this node serves: service = "host:port".
//! [services]
//! "tcp:ssh" = "127.0.0.1:22"
//!
//! # Optional: what this node holds for its peers at most (these are the defaults).
//! [serve]
//! max_connections = 256           # served at once, all peers together, at most 1000000
//! max_connections_per_peer = 64   # served at once for one peer, at most 1000000
//! connect_timeout_secs = 5        # giving up on a service's local target, at most 9
//!
//! # Optional: make this node an egress exit (protocol.md 8). Off by default; the Policy must also
//! # give it an `egress` entry and a member an `egress:*` grant. Read at start: a change needs a
//! # restart.
//! # [egress]
//! # enabled = true
//! # max_connections = 128           # egress streams at once, all initiators together (a pool of
//! #                                 # its own); at most 1000000
//! # max_connections_per_peer = 32   # egress streams at once for one initiator
//! # idle_secs = 300                 # reset a stream with no byte in either direction this long
//! #                                 # (10 to 86400)
//! # deny = ["10.9.0.0/16", "*.corp.example", "*:3389"]   # extra local denies; only narrows
//!
//! # Optional: the relay's share domain H (public names are `<name>.H`, or `<name>.<tenant>.H`).
//! # Only `menzil expose` and `menzil status` use it, to print `https://<name>.H`; the relay
//! # operator tells it to you (relay run --share-domain).
//! # share_domain = "tunnel.example.org"
//!
//! # Optional: have this node get and renew certificates for its blind shares that list
//! # "acme-tls/1" (TLS-ALPN-01, protocol.md 6.2). There is no default CA: name the directory (for a
//! # trial, the CA's staging directory). The name to order comes from the relay (its share domain
//! # in the ADVERTISE_ACK); `share_domain` above is only a cross check. Without this table the node
//! # orders nothing. A change needs a restart.
//! # [acme]
//! # directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
//! # contact = "mailto:ops@example.org"       # optional
//! # account_key = "acme/account.key"          # optional; relative to the home; this is the default
//!
//! # Optional: public names the relay routes to this node (protocol.md 4.4). The service must be
//! # one of [services]. mode is "blind" (service tls:..., the node terminates TLS), "terminated"
//! # (http:..., the relay terminates TLS) or "tcp" (tcp:..., reached by name like a blind share).
//! # alpn is for blind and tcp shares only; leave it out for any.
//! [[share]]
//! name = "myapp"
//! mode = "blind"
//! service = "tls:app"
//! # alpn = ["h2", "http/1.1"]
//! ```
//!
//! A file that does not exist is an empty configuration. Unknown keys are an error: a typo should
//! not silently leave a service unconfigured. A limit of zero or past its maximum, or a timeout
//! past its maximum, is an error too, not a value that is quietly changed.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use menzil_carrier::{ConnectionInfo, ProxyOverride, redact_userinfo};
use menzil_node::validate_shares;
use menzil_node::{
    EgressLimits, LocalServices, LocalTarget, MAX_CONNECT_TIMEOUT, MAX_EGRESS_IDLE,
    MIN_EGRESS_IDLE, ServeLimits,
};
use menzil_proto::{ServiceId, ServiceKind, Share, ShareMode};
use serde::Deserialize;

use crate::home::Home;

/// The settings file.
#[derive(Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Connection information of the relay.
    pub relay: Option<String>,
    /// A proxy URL, or `direct`.
    pub proxy: Option<String>,
    /// Services this node serves, as `service = "host:port"`.
    #[serde(default)]
    pub services: BTreeMap<String, String>,
    /// Where the agent listens; by default under the runtime directory or the home.
    pub agent_socket: Option<PathBuf>,
    /// The relay's share domain (`H` of protocol.md 4.4), for printing public URLs only: nothing
    /// is decided from it ([`Self::share_domain`] checks it).
    pub share_domain: Option<String>,
    /// Certificates this node gets for its blind shares: `[acme]`. Off without it.
    pub acme: Option<AcmeSettings>,
    /// What this node holds for its peers at most: `[serve]`.
    #[serde(default)]
    pub serve: ServeSettings,
    /// Whether this node is an egress exit: `[egress]` (protocol.md 8). Off without it.
    #[serde(default)]
    pub egress: EgressSettings,
    /// Public names to advertise to the relay: `[[share]]`.
    #[serde(default)]
    pub share: Vec<ShareSettings>,
}

/// The `[egress]` table (protocol.md 8, 11): whether this node dials destinations for members
/// that hold an `egress:*` grant and that an `egress` entry of the Policy lets it serve.
///
/// ```toml
/// [egress]
/// enabled = true
/// max_connections = 128
/// max_connections_per_peer = 32
/// idle_secs = 300
/// deny = ["10.9.0.0/16", "*.corp.example", "*:3389"]
/// ```
///
/// `enabled` is the node's own consent and it is off by default: with the table absent, or
/// `enabled = false`, an egress OPEN is answered `unknown_service` (after the grant check), no
/// matter what the Policy says. The other keys are optional and keep the library's defaults:
/// `max_connections` and `max_connections_per_peer` are the egress streams served at once (a
/// pool of their own, apart from `[serve]`; 1 to 1000000), `idle_secs` the time without a byte
/// in either direction after which a stream is reset (10 to 86400), and `deny` an extra list of
/// patterns (the grammar of protocol.md 8) that the exit refuses whatever the signed Policy
/// allows: it can only narrow. An entry that does not parse, or is an IPv4 mapped IPv6 pattern,
/// fails the load of the file. An unknown key is an error that stops `menzil node` at start,
/// like everywhere in this file. The table is read at start only: a change needs a restart of
/// `menzil node` (the periodic reload applies `[[share]]` entries, not this).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EgressSettings {
    /// Whether this node serves as an egress exit. Default false.
    #[serde(default)]
    pub enabled: bool,
    /// Egress streams served at once, all initiators together.
    pub max_connections: Option<usize>,
    /// Egress streams served at once for one initiator.
    pub max_connections_per_peer: Option<usize>,
    /// Seconds without a byte in either direction before a stream is reset.
    pub idle_secs: Option<u64>,
    /// The node's own extra deny list.
    #[serde(default)]
    pub deny: Vec<String>,
}

/// [`EgressSettings`] checked: the limits to serve under and the parsed local deny list.
#[derive(Clone, Debug)]
pub struct EgressChecked {
    /// The limits ([`EgressLimits`]), the defaults for a key that was left out.
    pub limits: EgressLimits,
    /// The local deny list, parsed.
    pub deny: Vec<menzil_node::egress::Pattern>,
}

impl EgressSettings {
    /// Checks every key: a count of 0 or above [`MAX_SERVE_CONNECTIONS`], an idle time outside
    /// 10 to 86400 seconds, and a `deny` entry that does not parse (or is IPv4 mapped IPv6) are
    /// errors that name the key, never corrected quietly.
    pub fn checked(&self) -> Result<EgressChecked> {
        let in_range = |key: &str, value: usize| {
            if value == 0 {
                bail!(
                    "{key} in [egress] of config.toml is 0: an exit that serves no stream serves nothing (leave the key out for the default)"
                );
            }
            if value > MAX_SERVE_CONNECTIONS {
                bail!(
                    "{key} in [egress] of config.toml is {value}: it must be at most {MAX_SERVE_CONNECTIONS} (each stream holds a file descriptor)"
                );
            }
            Ok(value)
        };
        let mut limits = EgressLimits::default();
        if let Some(value) = self.max_connections {
            limits.max_connections = in_range("max_connections", value)?;
        }
        if let Some(value) = self.max_connections_per_peer {
            limits.max_connections_per_peer = in_range("max_connections_per_peer", value)?;
        }
        // One initiator's count above the pool would let it take the whole pool. A key that was
        // left out counts with its default, so `max_connections = 10` alone is refused too.
        if limits.max_connections_per_peer > limits.max_connections {
            bail!(
                "max_connections_per_peer in [egress] of config.toml is {}: it must not exceed max_connections, which is {} (one initiator could take the whole pool; a key left out counts with its default)",
                limits.max_connections_per_peer,
                limits.max_connections
            );
        }
        if let Some(seconds) = self.idle_secs {
            let (least, most) = (MIN_EGRESS_IDLE.as_secs(), MAX_EGRESS_IDLE.as_secs());
            if seconds < least || seconds > most {
                bail!(
                    "idle_secs in [egress] of config.toml is {seconds}: it must be from {least} to {most}"
                );
            }
            limits.idle = Duration::from_secs(seconds);
        }
        let deny = menzil_node::egress::parse_local_deny(&self.deny)
            .map_err(|e| anyhow!("deny in [egress] of config.toml: {e}"))?;
        Ok(EgressChecked { limits, deny })
    }
}

/// The `[acme]` table as written; [`Config::acme`] checks it. There is no default CA.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcmeSettings {
    /// The CA's RFC 8555 directory (https).
    pub directory_url: String,
    /// The contact for the CA's notices (`mailto:...`), if any.
    pub contact: Option<String>,
    /// The account key file; by default `acme/account.key` in the home. A relative path is
    /// relative to the home, not to the directory the node was started in.
    pub account_key: Option<PathBuf>,
}

/// [`AcmeSettings`] checked, with the account key path made whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcmeChecked {
    /// The CA's directory URL.
    pub directory_url: String,
    /// The contact, if any.
    pub contact: Option<String>,
    /// The account key file.
    pub account_key_path: PathBuf,
}

/// One `[[share]]` entry as written; [`Config::shares`] checks it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShareSettings {
    /// The public label (one lowercase LDH label).
    pub name: String,
    /// `blind`, `terminated` or `tcp`.
    pub mode: String,
    /// The service the name routes to, as in `[services]`.
    pub service: String,
    /// ALPN identifiers the node terminates; none means any.
    pub alpn: Option<Vec<String>>,
}

impl ShareSettings {
    /// The wire share this entry stands for, or why it is not one. `tcp` is a blind share whose
    /// service is `tcp:` (the wire has two modes), so each mode names the one service kind it
    /// goes with and a mismatch is an error, not a correction.
    fn to_share(&self) -> Result<Share> {
        let name = &self.name;
        let (mode, kind) = match self.mode.as_str() {
            "blind" => (ShareMode::Blind, ServiceKind::Tls),
            "terminated" => (ShareMode::Terminated, ServiceKind::Http),
            "tcp" => (ShareMode::Blind, ServiceKind::Tcp),
            other => bail!(
                "share {name:?} in config.toml: mode {other:?} is not one of \"blind\", \"terminated\", \"tcp\""
            ),
        };
        let service: ServiceId = self.service.parse().map_err(|e| {
            anyhow!(
                "share {name:?} in config.toml: service {:?}: {e}",
                self.service
            )
        })?;
        if service.kind != kind {
            bail!(
                "share {name:?} in config.toml: mode {:?} goes with a {kind}: service, not {service}",
                self.mode
            );
        }
        Ok(Share {
            name: self.name.clone(),
            mode,
            service,
            alpn: self.alpn.clone().unwrap_or_default(),
        })
    }
}

/// The most connections a `[serve]` limit may name. Each served connection holds a descriptor
/// (two, with the stream's own side), and no process has a million of them by default; a value
/// beyond what a semaphore can count used to panic the node at start (the fifth red-team round,
/// N1).
pub const MAX_SERVE_CONNECTIONS: usize = 1_000_000;

/// The `[serve]` table: limits on the connections a node serves. A key that is left out keeps
/// the library's default (see [`ServeLimits`]).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServeSettings {
    /// Connections served at once, all peers together.
    pub max_connections: Option<usize>,
    /// Connections served at once for one peer (an initiating node).
    pub max_connections_per_peer: Option<usize>,
    /// Seconds to wait for the connect to a service's local target.
    pub connect_timeout_secs: Option<u64>,
}

impl ServeSettings {
    /// The limits these settings ask for, on top of the defaults.
    fn limits(&self) -> Result<ServeLimits> {
        let in_range = |key: &str, value: usize| {
            if value == 0 {
                bail!(
                    "{key} in [serve] of config.toml is 0: a node that serves no connection serves nothing (leave the key out for the default)"
                );
            }
            if value > MAX_SERVE_CONNECTIONS {
                bail!(
                    "{key} in [serve] of config.toml is {value}: it must be at most {MAX_SERVE_CONNECTIONS} (each connection holds a file descriptor)"
                );
            }
            Ok(value)
        };
        let mut limits = ServeLimits::default();
        if let Some(value) = self.max_connections {
            limits.max_connections = in_range("max_connections", value)?;
        }
        if let Some(value) = self.max_connections_per_peer {
            limits.max_connections_per_peer = in_range("max_connections_per_peer", value)?;
        }
        Ok(limits)
    }

    /// The connect timeout asked for, if any.
    fn connect_timeout(&self) -> Result<Option<Duration>> {
        let Some(seconds) = self.connect_timeout_secs else {
            return Ok(None);
        };
        let longest = MAX_CONNECT_TIMEOUT.as_secs();
        if seconds == 0 || seconds > longest {
            bail!(
                "connect_timeout_secs in [serve] of config.toml is {seconds}: it must be from 1 to {longest} (the node that opens the stream gives up after 10 seconds, and a refusal that comes later is lost)"
            );
        }
        Ok(Some(Duration::from_secs(seconds)))
    }
}

impl std::fmt::Debug for Config {
    /// The proxy URL without its user name and password: a `Debug` print of the settings (or of
    /// anything that holds them) must not carry them into a log or a panic message (the fourth
    /// red-team round, N2).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("relay", &self.relay)
            .field("proxy", &self.proxy.as_deref().map(redact_userinfo))
            .field("services", &self.services)
            .field("agent_socket", &self.agent_socket)
            .field("share_domain", &self.share_domain)
            .field("acme", &self.acme)
            .field("serve", &self.serve)
            .field("egress", &self.egress)
            .field("share", &self.share)
            .finish()
    }
}

impl Config {
    /// Reads `home`'s `config.toml`; a missing file is an empty configuration.
    pub fn load(home: &Home) -> Result<Self> {
        let path = home.config_path();
        match fs::read_to_string(&path) {
            Ok(text) => Self::parse(&text).with_context(|| format!("in {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Parses the text of a configuration file.
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).map_err(|e| {
            // The message and where it is, without the quoted line the full report adds (a
            // proxy URL in it can hold a password).
            match e.span() {
                Some(span) => {
                    let before = &text[..span.start.min(text.len())];
                    let line = before.matches('\n').count() + 1;
                    let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
                    anyhow!("line {line}, column {column}: {}", e.message())
                }
                None => anyhow!("{}", e.message()),
            }
        })?;
        // The `[egress]` table is checked with the rest of the file: a deny entry the exit
        // could not read must stop the load, not deny nothing in silence.
        config.egress.checked()?;
        Ok(config)
    }

    /// The relay to attach to; an error saying how to configure one if there is none.
    pub fn connection_info(&self) -> Result<ConnectionInfo> {
        let relay = self.relay.as_deref().ok_or_else(|| {
            anyhow!("no relay is configured: put `relay = \"menzil://...\"` in config.toml")
        })?;
        ConnectionInfo::parse(relay).map_err(|e| anyhow!("relay in config.toml: {e}"))
    }

    /// The proxy decision: none (the environment decides), `direct`, or a URL.
    pub fn proxy_override(&self) -> Option<ProxyOverride> {
        match self.proxy.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(text) if text.eq_ignore_ascii_case("direct") => Some(ProxyOverride::Direct),
            Some(url) => Some(ProxyOverride::Use(url.to_string())),
        }
    }

    /// The shares to advertise, validated: every mode, name, service and ALPN entry is checked
    /// and an error names the share (nothing is corrected quietly), and each service must be one
    /// this node serves (`[services]`), since an accepted name that leads nowhere is a mistake.
    pub fn shares(&self) -> Result<Vec<Share>> {
        let mut shares = Vec::with_capacity(self.share.len());
        for settings in &self.share {
            let share = settings.to_share()?;
            if !self.services.contains_key(&share.service.to_string()) {
                bail!(
                    "share {:?} in config.toml points at {}, which is not in [services]: add it there, or this node would advertise a name it cannot serve",
                    share.name,
                    share.service
                );
            }
            shares.push(share);
        }
        validate_shares(&shares).map_err(|e| anyhow!("config.toml: {e}"))?;
        Ok(shares)
    }

    /// The `[acme]` table, checked, or `None` without one (the node then orders nothing).
    /// `directory_url` must be an `https://` URL with a host and no user name or password (there
    /// is no default CA), `contact` a `mailto:` URI, `account_key` a path (relative to `home`).
    pub fn acme(&self, home: &Home) -> Result<Option<AcmeChecked>> {
        let Some(settings) = &self.acme else {
            return Ok(None);
        };
        let plain = |text: &str| !text.chars().any(|c| c.is_control() || c.is_whitespace());
        let url = settings.directory_url.as_str();
        let authority = url
            .strip_prefix("https://")
            .map(|rest| rest.split(['/', '?', '#']).next().unwrap_or_default());
        match authority {
            Some(authority) if !authority.is_empty() && !authority.contains('@') && plain(url) => {}
            _ => bail!(
                "directory_url {url:?} in [acme] of config.toml must be an https:// URL with a host and no user name or password (there is no default CA: name the directory, for a trial the CA's staging directory)"
            ),
        }
        if let Some(contact) = &settings.contact {
            let ok = contact
                .strip_prefix("mailto:")
                .is_some_and(|address| !address.is_empty())
                && contact.len() <= 255
                && plain(contact);
            if !ok {
                bail!(
                    "contact {contact:?} in [acme] of config.toml must be a mailto: address, such as mailto:ops@example.org"
                );
            }
        }
        let account_key_path = match &settings.account_key {
            None => menzil_node::acme::CertStore::account_key_path(home.root()),
            Some(path) if path.as_os_str().is_empty() => {
                bail!(
                    "account_key in [acme] of config.toml is empty (leave the key out for the default)"
                )
            }
            Some(path) => home.root().join(path),
        };
        Ok(Some(AcmeChecked {
            directory_url: url.to_string(),
            contact: settings.contact.clone(),
            account_key_path,
        }))
    }

    /// The services to serve with the local target of each, validated.
    pub fn service_targets(&self) -> Result<Vec<(ServiceId, LocalTarget)>> {
        let mut out = Vec::with_capacity(self.services.len());
        for (service, target) in &self.services {
            let id: ServiceId = service
                .parse()
                .map_err(|e| anyhow!("service {service:?} in config.toml: {e}"))?;
            let target = parse_target(target)
                .with_context(|| format!("target of service {service:?} in config.toml"))?;
            out.push((id, target));
        }
        Ok(out)
    }

    /// Whether `[egress] enabled = true` is set: this node is an egress exit ([`EgressSettings`]).
    pub fn egress_enabled(&self) -> bool {
        self.egress.enabled
    }

    /// The `[egress]` table, checked ([`EgressSettings::checked`]).
    pub fn egress_checked(&self) -> Result<EgressChecked> {
        self.egress.checked()
    }

    /// The services to serve, validated.
    pub fn local_services(&self) -> Result<LocalServices> {
        let mut services = LocalServices::new();
        for (id, target) in self.service_targets()? {
            services = services
                .serve(id.clone(), target)
                .map_err(|e| anyhow!("service {id} in config.toml: {e}"))?;
        }
        services = services.with_limits(self.serve.limits()?);
        services = services.with_egress_limits(self.egress.checked()?.limits);
        if let Some(timeout) = self.serve.connect_timeout()? {
            services = services.with_connect_timeout(timeout);
        }
        Ok(services)
    }

    /// The relay's share domain in lowercase, if one is configured: a host name of at least two
    /// labels (letters, digits and hyphens, no trailing dot, at most 253 characters). A value
    /// that is not one is an error here, since it would be printed as part of a URL.
    pub fn share_domain(&self) -> Result<Option<String>> {
        let Some(domain) = self.share_domain.as_deref() else {
            return Ok(None);
        };
        let domain = domain.trim().to_ascii_lowercase();
        let bad = |why: &str| {
            bail!("share_domain {domain:?} in config.toml: {why}");
        };
        if domain.is_empty() || domain.len() > 253 {
            return bad("it must be 1 to 253 characters");
        }
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            return bad(
                "it must be a domain name with at least two labels, such as tunnel.example.org",
            );
        }
        for label in labels {
            let ldh = !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-');
            if !ldh {
                return bad(
                    "each label is 1 to 63 letters, digits and hyphens, not starting or ending with a hyphen (no scheme, port, path or trailing dot)",
                );
            }
        }
        Ok(Some(domain))
    }
}

/// `host:port`, with an IPv6 address in brackets (`[::1]:22`).
pub fn parse_target(text: &str) -> Result<LocalTarget> {
    let text = text.trim();
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("{text:?} is not host:port"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        bail!("{text:?} has no host");
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("{port:?} in {text:?} is not a port number"))?;
    if port == 0 {
        bail!("{text:?} names port 0");
    }
    Ok(LocalTarget::new(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_url() -> String {
        format!(
            "menzil://relay.example.org:443/_menzil/v1?id={}",
            "ab".repeat(32)
        )
    }

    /// The fourth red-team round, N2: the derived `Debug` of the settings printed the proxy URL
    /// with its password, and so did the `Debug` of everything that holds them.
    #[test]
    fn the_debug_output_of_the_settings_never_shows_the_proxy_password() {
        let config = Config::parse(
            "proxy = \"http://alice:hunter2@proxy.corp:3128\"\n[services]\n\"tcp:ssh\" = \"127.0.0.1:22\"\n",
        )
        .unwrap();
        let shown = format!("{config:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("alice"),
            "{shown}"
        );
        assert!(
            shown.contains("proxy.corp:3128") && shown.contains("127.0.0.1:22"),
            "{shown}"
        );
        // What is built from them is held to the same rule.
        let over = config.proxy_override();
        assert!(!format!("{over:?}").contains("hunter2"));
        // A setting with nothing secret in it prints as it is.
        let plain = Config::parse("proxy = \"direct\"\n").unwrap();
        assert!(format!("{plain:?}").contains("direct"));
    }

    #[test]
    fn a_full_file_parses_into_a_relay_a_proxy_and_services() {
        let text = format!(
            r#"
            relay = "{}"
            proxy = "http://proxy.corp:3128"
            agent_socket = "/run/user/1000/menzil.sock"

            [services]
            "tcp:ssh" = "127.0.0.1:22"
            "http:myapp" = "[::1]:8080"
            "#,
            relay_url()
        );
        let config = Config::parse(&text).unwrap();
        let info = config.connection_info().unwrap();
        assert_eq!((info.host.as_str(), info.port), ("relay.example.org", 443));
        assert_eq!(
            config.proxy_override(),
            Some(ProxyOverride::Use("http://proxy.corp:3128".to_string()))
        );
        assert_eq!(
            config.agent_socket,
            Some("/run/user/1000/menzil.sock".into())
        );
        let services = config.local_services().unwrap();
        assert_eq!(services.len(), 2);
        let ssh = services.target(&"tcp:ssh".parse().unwrap()).unwrap();
        assert_eq!((ssh.host(), ssh.port()), ("127.0.0.1", 22));
        let myapp = services.target(&"http:myapp".parse().unwrap()).unwrap();
        assert_eq!((myapp.host(), myapp.port()), ("::1", 8080));
    }

    #[test]
    fn egress_is_off_unless_the_table_turns_it_on() {
        // Absent, empty, and `enabled = false` are all off.
        assert!(!Config::parse("").unwrap().egress_enabled());
        assert!(!Config::parse("[egress]").unwrap().egress_enabled());
        assert!(
            !Config::parse("[egress]\nenabled = false")
                .unwrap()
                .egress_enabled()
        );
        assert!(Config::default().egress == EgressSettings::default());
        let on = Config::parse("[egress]\nenabled = true").unwrap();
        assert!(on.egress_enabled());
        assert_eq!(
            on.egress,
            EgressSettings {
                enabled: true,
                ..EgressSettings::default()
            }
        );
        // It sits next to the other tables without disturbing them.
        let both =
            Config::parse("[services]\n\"tcp:ssh\" = \"127.0.0.1:22\"\n[egress]\nenabled = true")
                .unwrap();
        assert!(both.egress_enabled());
        assert_eq!(both.local_services().unwrap().len(), 1);
    }

    #[test]
    fn a_mistake_in_the_egress_table_is_an_error() {
        for (text, wanted) in [
            // A key that is not there, and a typo of one that is.
            ("[egress]\nenabled = true\nlimit = 5", "limit"),
            ("[egress]\nenable = true", "enable"),
            ("[egress]\nallow = [\"*\"]", "allow"),
            ("[egress]\nidle = 5", "idle"),
            // The wrong type.
            ("[egress]\nenabled = \"yes\"", "boolean"),
            ("[egress]\nenabled = 1", "boolean"),
            ("egress = true", "struct"),
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(
                format!("{error:#}").contains(wanted),
                "{text:?} gave {error:#}"
            );
        }
    }

    #[test]
    fn the_egress_table_sets_the_limits_the_idle_time_and_the_local_deny_list() {
        use menzil_node::{DEFAULT_EGRESS_IDLE, EgressLimits};
        let services = |text: &str| Config::parse(text).unwrap().local_services().unwrap();
        // Nothing written: the defaults, 128 in all, 32 for one initiator, 300 s.
        let plain = services("");
        assert_eq!(plain.egress_limits(), EgressLimits::default());
        assert_eq!(plain.egress_limits().max_connections, 128);
        assert_eq!(plain.egress_limits().max_connections_per_peer, 32);
        assert_eq!(plain.egress_limits().idle, DEFAULT_EGRESS_IDLE);
        // The egress pool is not the serve pool.
        let apart = services("[serve]\nmax_connections = 7\n[egress]\nmax_connections = 40\n");
        assert_eq!(apart.limits().max_connections, 7);
        assert_eq!(apart.egress_limits().max_connections, 40);
        assert_eq!(apart.egress_limits().max_connections_per_peer, 32);
        let all = services(
            "[egress]\nmax_connections = 20\nmax_connections_per_peer = 3\nidle_secs = 10\n",
        );
        assert_eq!(
            all.egress_limits(),
            EgressLimits {
                max_connections: 20,
                max_connections_per_peer: 3,
                idle: Duration::from_secs(10),
            }
        );
        let top = services(&format!(
            "[egress]\nmax_connections = {MAX_SERVE_CONNECTIONS}\nidle_secs = 86400\n"
        ));
        assert_eq!(top.egress_limits().max_connections, MAX_SERVE_CONNECTIONS);
        assert_eq!(top.egress_limits().idle, Duration::from_secs(86_400));
        // The deny list is parsed.
        let config = Config::parse(
            "[egress]\nenabled = true\ndeny = [\"10.9.0.0/16\", \"*.corp.example\", \"*:3389\", \"self\"]\n",
        )
        .unwrap();
        assert_eq!(config.egress_checked().unwrap().deny.len(), 4);
        assert!(
            Config::parse("")
                .unwrap()
                .egress_checked()
                .unwrap()
                .deny
                .is_empty()
        );
    }

    #[test]
    fn an_egress_value_that_would_be_changed_quietly_fails_the_load() {
        for (text, wanted) in [
            ("[egress]\nmax_connections = 0", "max_connections"),
            (
                "[egress]\nmax_connections_per_peer = 0",
                "max_connections_per_peer",
            ),
            ("[egress]\nmax_connections = 1000001", "1000000"),
            (
                "[egress]\nmax_connections = 18446744073709551615",
                "max_connections",
            ),
            ("[egress]\nmax_connections_per_peer = 1000001", "1000000"),
            // One initiator may not hold more than the pool: both set, or one against the
            // default of the other (128 in all, 32 for one initiator).
            (
                "[egress]\nmax_connections = 10\nmax_connections_per_peer = 11",
                "must not exceed max_connections",
            ),
            (
                "[egress]\nmax_connections_per_peer = 129",
                "must not exceed max_connections",
            ),
            ("[egress]\nmax_connections = 31", "must not exceed"),
            ("[egress]\nidle_secs = 0", "idle_secs"),
            ("[egress]\nidle_secs = 9", "10 to 86400"),
            ("[egress]\nidle_secs = 86401", "10 to 86400"),
            ("[egress]\nidle_secs = -1", "expected u64"),
            // A deny entry that does not parse fails the load, and so does an IPv4 mapped one.
            ("[egress]\ndeny = [\"10.0.0.0/33\"]", "10.0.0.0/33"),
            ("[egress]\ndeny = [\"Corp.Example\"]", "Corp.Example"),
            ("[egress]\ndeny = [\"::ffff:10.0.0.0/104\"]", "IPv4 mapped"),
            ("[egress]\ndeny = [\"::ffff:10.1.2.3\"]", "IPv4 mapped"),
            (
                "[egress]\ndeny = [\"ok.example\", \"\"]",
                "deny in [egress]",
            ),
            ("[egress]\ndeny = \"*\"", "sequence"),
            ("[egress]\ndeny = [1]", "string"),
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(
                format!("{error:#}").contains(wanted),
                "{text:?} gave {error:#}"
            );
        }
        // It fails the load of a file on disk too, not only the parse of a string.
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path());
        std::fs::write(
            home.config_path(),
            "[egress]\nenabled = true\ndeny = [\"::ffff:10.0.0.1\"]\n",
        )
        .unwrap();
        assert!(Config::load(&home).is_err());
    }

    #[test]
    fn an_empty_or_missing_file_is_an_empty_configuration() {
        assert_eq!(Config::parse("").unwrap(), Config::default());
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(&Home::new(dir.path())).unwrap();
        assert_eq!(config, Config::default());
        assert!(config.proxy_override().is_none());
        assert!(config.local_services().unwrap().is_empty());
        let error = config.connection_info().unwrap_err().to_string();
        assert!(error.contains("no relay is configured"), "{error}");
    }

    #[test]
    fn a_mistake_in_the_file_is_an_error_that_names_it() {
        for (text, wanted) in [
            ("raley = \"x\"", "raley"),
            ("relay = 5", "string"),
            ("[services]\n\"tcp:ssh\" = \"22\"", "host:port"),
            ("[services]\n\"tcp:ssh\" = \"host:99999\"", "port"),
            ("[services]\n\"tcp:ssh\" = \":22\"", "no host"),
            ("[services]\n\"tcp:ssh\" = \"h:0\"", "port 0"),
            ("[services]\n\"ssh\" = \"h:22\"", "ssh"),
            ("[services]\n\"udp:wg\" = \"h:22\"", "udp"),
            ("[services]\n\"tcp:*\" = \"h:22\"", "exact label"),
        ] {
            let result = Config::parse(text).and_then(|c| c.local_services().map(|_| ()));
            let error = match result {
                Ok(()) => panic!("{text:?} was accepted"),
                Err(e) => format!("{e:#}"),
            };
            assert!(error.contains(wanted), "{text:?}: {error}");
        }
        let config = Config::parse("relay = \"menzil://h?id=zz\"").unwrap();
        assert!(config.connection_info().is_err());
    }

    #[test]
    fn a_syntax_error_says_where_it_is_and_does_not_quote_the_line() {
        let error =
            Config::parse("relay = \"x\"\n\nproxy = \"http://user:hunter2@p:3128\"\n[services\n")
                .unwrap_err()
                .to_string();
        assert!(error.starts_with("line 4, column"), "{error}");
        assert!(!error.contains("hunter2"), "{error}");
        let error = Config::parse("raley = 1").unwrap_err().to_string();
        assert!(error.starts_with("line 1, column 1"), "{error}");
    }

    #[test]
    fn the_proxy_setting_has_three_meanings() {
        let proxy = |text: &str| Config::parse(text).unwrap().proxy_override();
        assert_eq!(proxy(""), None);
        assert_eq!(proxy("proxy = \"\""), None);
        assert_eq!(proxy("proxy = \"direct\""), Some(ProxyOverride::Direct));
        assert_eq!(proxy("proxy = \"DIRECT\""), Some(ProxyOverride::Direct));
        assert_eq!(
            proxy("proxy = \"http://p:1\""),
            Some(ProxyOverride::Use("http://p:1".to_string()))
        );
    }

    /// TODO.md: the limits a node serves under were code-only. The keys are optional, each keeps
    /// the default when it is left out, and the node ends up with exactly what was written.
    #[test]
    fn the_serve_table_sets_the_limits_and_the_connect_timeout() {
        let services = |text: &str| Config::parse(text).unwrap().local_services().unwrap();
        // Nothing written: the library's defaults.
        let plain = services("");
        assert_eq!(plain.limits(), ServeLimits::default());
        assert_eq!(
            plain.connect_timeout(),
            menzil_node::DEFAULT_CONNECT_TIMEOUT
        );
        // Each key alone leaves the others as they were.
        let one = services("[serve]\nmax_connections = 10\n");
        assert_eq!(one.limits().max_connections, 10);
        assert_eq!(
            one.limits().max_connections_per_peer,
            ServeLimits::default().max_connections_per_peer
        );
        assert_eq!(one.connect_timeout(), menzil_node::DEFAULT_CONNECT_TIMEOUT);
        let all = services(
            "[serve]\nmax_connections = 20\nmax_connections_per_peer = 3\nconnect_timeout_secs = 2\n",
        );
        assert_eq!(all.limits().max_connections, 20);
        assert_eq!(all.limits().max_connections_per_peer, 3);
        assert_eq!(all.connect_timeout(), Duration::from_secs(2));
        // The longest the library allows is accepted as it is.
        let longest = services(&format!(
            "[serve]\nconnect_timeout_secs = {}\n",
            MAX_CONNECT_TIMEOUT.as_secs()
        ));
        assert_eq!(longest.connect_timeout(), MAX_CONNECT_TIMEOUT);
        // The socket buffer is not a setting.
        assert_eq!(
            all.limits().socket_buffer,
            ServeLimits::default().socket_buffer
        );
        // The largest value is accepted as it is.
        let largest = services(&format!(
            "[serve]\nmax_connections = {MAX_SERVE_CONNECTIONS}\nmax_connections_per_peer = {MAX_SERVE_CONNECTIONS}\n"
        ));
        assert_eq!(largest.limits().max_connections, MAX_SERVE_CONNECTIONS);
        assert_eq!(
            largest.limits().max_connections_per_peer,
            MAX_SERVE_CONNECTIONS
        );
    }

    #[test]
    fn a_serve_value_that_would_be_changed_quietly_is_an_error_that_names_it() {
        let too_long = MAX_CONNECT_TIMEOUT.as_secs() + 1;
        let too_many = format!("[serve]\nmax_connections = {}", MAX_SERVE_CONNECTIONS + 1);
        let too_many_per_peer = format!(
            "[serve]\nmax_connections_per_peer = {}",
            MAX_SERVE_CONNECTIONS + 1
        );
        for (text, wanted) in [
            // The fifth red-team round, N1: these panicked the node at start.
            (too_many.as_str(), "at most 1000000"),
            (
                "[serve]\nmax_connections = 9223372036854775807",
                "at most 1000000",
            ),
            (too_many_per_peer.as_str(), "at most 1000000"),
            ("[serve]\nmax_connections = 0", "max_connections"),
            (
                "[serve]\nmax_connections_per_peer = 0",
                "max_connections_per_peer",
            ),
            ("[serve]\nconnect_timeout_secs = 0", "connect_timeout_secs"),
            (
                &format!("[serve]\nconnect_timeout_secs = {too_long}"),
                "from 1 to",
            ),
        ] {
            let result = Config::parse(text).and_then(|c| c.local_services().map(|_| ()));
            let error = match result {
                Ok(()) => panic!("{text:?} was accepted"),
                Err(e) => format!("{e:#}"),
            };
            assert!(error.contains(wanted), "{text:?}: {error}");
        }
        // A typo in the table, a negative number and a word are refused by the parser.
        for (text, wanted) in [
            ("[serve]\nmax_conections = 5", "max_conections"),
            ("[serve]\nmax_connections = -1", "expected usize"),
            ("[serve]\nmax_connections = \"many\"", "expected usize"),
        ] {
            let error = Config::parse(text).unwrap_err().to_string();
            assert!(error.contains(wanted), "{text:?}: {error}");
        }
    }

    const SERVICES: &str = r#"
        [services]
        "tls:myapp" = "127.0.0.1:8443"
        "http:web" = "127.0.0.1:8080"
        "tcp:ssh" = "127.0.0.1:22"
    "#;

    fn shares_of(share_tables: &str) -> Result<Vec<Share>> {
        Config::parse(&format!("{SERVICES}\n{share_tables}")).and_then(|c| c.shares())
    }

    #[test]
    fn share_entries_become_wire_shares_for_each_mode() {
        let shares = shares_of(
            r#"
            [[share]]
            name = "myapp"
            mode = "blind"
            service = "tls:myapp"
            alpn = ["h2", "acme-tls/1"]

            [[share]]
            name = "web"
            mode = "terminated"
            service = "http:web"

            [[share]]
            name = "ssh"
            mode = "tcp"
            service = "tcp:ssh"
            "#,
        )
        .unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].mode, ShareMode::Blind);
        assert_eq!(shares[0].alpn, vec!["h2", "acme-tls/1"]);
        assert_eq!(shares[0].service.to_string(), "tls:myapp");
        assert_eq!(shares[1].mode, ShareMode::Terminated);
        assert!(shares[1].alpn.is_empty());
        // `tcp` is a blind share on the wire, with a tcp: service.
        assert_eq!(shares[2].mode, ShareMode::Blind);
        assert_eq!(shares[2].service.to_string(), "tcp:ssh");
        assert!(shares_of("").unwrap().is_empty());
    }

    #[test]
    fn a_bad_share_is_an_error_that_names_it_and_nothing_is_changed_quietly() {
        for (table, wanted) in [
            (
                "name = \"myapp\"\nmode = \"public\"\nservice = \"tls:myapp\"",
                "mode \"public\"",
            ),
            (
                "name = \"Myapp\"\nmode = \"blind\"\nservice = \"tls:myapp\"",
                "uppercase",
            ),
            (
                "name = \"a.b\"\nmode = \"blind\"\nservice = \"tls:myapp\"",
                "dot",
            ),
            (
                "name = \"-a\"\nmode = \"blind\"\nservice = \"tls:myapp\"",
                "hyphen",
            ),
            (
                "name = \"myapp\"\nmode = \"blind\"\nservice = \"http:web\"",
                "goes with a tls:",
            ),
            (
                "name = \"web\"\nmode = \"terminated\"\nservice = \"tls:myapp\"",
                "goes with a http:",
            ),
            (
                "name = \"ssh\"\nmode = \"tcp\"\nservice = \"tls:myapp\"",
                "goes with a tcp:",
            ),
            (
                "name = \"myapp\"\nmode = \"blind\"\nservice = \"nonsense\"",
                "service \"nonsense\"",
            ),
            (
                "name = \"myapp\"\nmode = \"blind\"\nservice = \"tls:other\"",
                "not in [services]",
            ),
            (
                "name = \"web\"\nmode = \"terminated\"\nservice = \"http:web\"\nalpn = [\"h2\"]",
                "blind shares only",
            ),
            (
                "name = \"myapp\"\nmode = \"blind\"\nservice = \"tls:myapp\"\nport = 1",
                "unknown field",
            ),
            ("name = \"myapp\"\nmode = \"blind\"", "missing field"),
        ] {
            let error = match shares_of(&format!("[[share]]\n{table}")) {
                Ok(_) => panic!("{table:?} was accepted"),
                Err(e) => format!("{e:#}"),
            };
            assert!(error.contains(wanted), "{table:?}: {error}");
        }
        // The same name twice is refused as a whole.
        let error = shares_of(
            "[[share]]\nname = \"myapp\"\nmode = \"blind\"\nservice = \"tls:myapp\"\n[[share]]\nname = \"myapp\"\nmode = \"tcp\"\nservice = \"tcp:ssh\"",
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("used twice"), "{error:#}");
    }

    fn acme_of(text: &str) -> Result<Option<AcmeChecked>> {
        Config::parse(text).and_then(|c| c.acme(&Home::new("/h")))
    }

    /// Without `[acme]` the node orders nothing: the configuration is exactly what it was.
    #[test]
    fn no_acme_table_changes_nothing() {
        assert_eq!(acme_of("").unwrap(), None);
        let text = format!(
            "{SERVICES}\n[[share]]\nname = \"myapp\"\nmode = \"blind\"\nservice = \"tls:myapp\"\nalpn = [\"acme-tls/1\"]\n"
        );
        let config = Config::parse(&text).unwrap();
        assert_eq!(config.acme, None);
        assert_eq!(config.acme(&Home::new("/h")).unwrap(), None);
        // The shares and services are read as before.
        assert_eq!(config.shares().unwrap().len(), 1);
        assert_eq!(config.local_services().unwrap().len(), 3);
        // The debug print has the table (and it holds no secret).
        let with = Config::parse("[acme]\ndirectory_url = \"https://ca.test/dir\"").unwrap();
        assert!(format!("{with:?}").contains("https://ca.test/dir"));
    }

    #[test]
    fn a_valid_acme_table_is_read_with_the_account_key_under_the_home() {
        let checked = acme_of(
            "[acme]\ndirectory_url = \"https://acme-staging-v02.api.letsencrypt.org/directory\"\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            checked.directory_url,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(checked.contact, None);
        assert_eq!(
            checked.account_key_path,
            PathBuf::from("/h/acme/account.key")
        );
        let checked = acme_of(
            "[acme]\ndirectory_url = \"https://ca.test:14000/dir?x=1\"\ncontact = \"mailto:ops@example.org\"\naccount_key = \"keys/ca.pem\"\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(checked.contact.as_deref(), Some("mailto:ops@example.org"));
        // A relative key path is the home's, an absolute one is as written.
        assert_eq!(checked.account_key_path, PathBuf::from("/h/keys/ca.pem"));
        let checked = acme_of(
            "[acme]\ndirectory_url = \"https://ca.test/dir\"\naccount_key = \"/etc/menzil/acme.key\"\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            checked.account_key_path,
            PathBuf::from("/etc/menzil/acme.key")
        );
    }

    #[test]
    fn a_bad_acme_table_is_an_error_that_names_it() {
        // The parser: a typo, a missing url, a key of the wrong type.
        for (text, wanted) in [
            (
                "[acme]\ndirectory_url = \"https://ca.test/dir\"\ncontcat = \"x\"",
                "contcat",
            ),
            ("[acme]\ncontact = \"mailto:a@b.c\"", "directory_url"),
            ("[acme]", "directory_url"),
            ("[acme]\ndirectory_url = 5", "string"),
            (
                "[acme]\ndirectory_url = \"https://ca.test/dir\"\naccount_key = 5",
                "string",
            ),
        ] {
            let error = match Config::parse(text) {
                Ok(_) => panic!("{text:?} was accepted"),
                Err(e) => e.to_string(),
            };
            assert!(error.contains(wanted), "{text:?}: {error}");
        }
        // The checks after it: https only, a host, no credentials, a mailto contact.
        for (text, wanted) in [
            ("[acme]\ndirectory_url = \"http://ca.test/dir\"", "https://"),
            ("[acme]\ndirectory_url = \"ca.test/dir\"", "https://"),
            ("[acme]\ndirectory_url = \"\"", "https://"),
            ("[acme]\ndirectory_url = \"https://\"", "host"),
            ("[acme]\ndirectory_url = \"https:///dir\"", "host"),
            (
                "[acme]\ndirectory_url = \"https://user:pw@ca.test/dir\"",
                "no user name",
            ),
            (
                "[acme]\ndirectory_url = \"https://ca.test/d ir\"",
                "https://",
            ),
            (
                "[acme]\ndirectory_url = \"https://ca.test/dir\"\ncontact = \"ops@example.org\"",
                "mailto:",
            ),
            (
                "[acme]\ndirectory_url = \"https://ca.test/dir\"\ncontact = \"mailto:\"",
                "mailto:",
            ),
            (
                "[acme]\ndirectory_url = \"https://ca.test/dir\"\ncontact = \"mailto:a b@c.d\"",
                "mailto:",
            ),
            (
                "[acme]\ndirectory_url = \"https://ca.test/dir\"\naccount_key = \"\"",
                "account_key",
            ),
        ] {
            let error = match acme_of(text) {
                Ok(_) => panic!("{text:?} was accepted"),
                Err(e) => format!("{e:#}"),
            };
            assert!(error.contains(wanted), "{text:?}: {error}");
        }
    }

    #[test]
    fn targets_are_host_and_port() {
        for (text, host, port) in [
            ("127.0.0.1:22", "127.0.0.1", 22),
            ("localhost:8080", "localhost", 8080),
            ("[::1]:443", "::1", 443),
            (" nas.lan:5000 ", "nas.lan", 5000),
        ] {
            let target = parse_target(text).unwrap();
            assert_eq!((target.host(), target.port()), (host, port), "{text}");
        }
        for bad in [
            "",
            "host",
            "host:",
            ":22",
            "host:abc",
            "host:70000",
            "[::1]",
        ] {
            assert!(parse_target(bad).is_err(), "{bad:?}");
        }
    }
}
