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
use menzil_node::{LocalServices, LocalTarget, MAX_CONNECT_TIMEOUT, ServeLimits};
use menzil_proto::ServiceId;
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
    /// What this node holds for its peers at most: `[serve]`.
    #[serde(default)]
    pub serve: ServeSettings,
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
            .field("serve", &self.serve)
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
        toml::from_str(text).map_err(|e| {
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
        })
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

    /// The services to serve, validated.
    pub fn local_services(&self) -> Result<LocalServices> {
        let mut services = LocalServices::new();
        for (service, target) in &self.services {
            let id: ServiceId = service
                .parse()
                .map_err(|e| anyhow!("service {service:?} in config.toml: {e}"))?;
            let target = parse_target(target)
                .with_context(|| format!("target of service {service:?} in config.toml"))?;
            services = services
                .serve(id, target)
                .map_err(|e| anyhow!("service {service:?} in config.toml: {e}"))?;
        }
        services = services.with_limits(self.serve.limits()?);
        if let Some(timeout) = self.serve.connect_timeout()? {
            services = services.with_connect_timeout(timeout);
        }
        Ok(services)
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
            "http:app" = "[::1]:8080"
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
        let app = services.target(&"http:app".parse().unwrap()).unwrap();
        assert_eq!((app.host(), app.port()), ("::1", 8080));
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
