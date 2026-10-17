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
//! ```
//!
//! A file that does not exist is an empty configuration. Unknown keys are an error: a typo should
//! not silently leave a service unconfigured.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use menzil_carrier::{ConnectionInfo, ProxyOverride, redact_userinfo};
use menzil_node::{LocalServices, LocalTarget};
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
