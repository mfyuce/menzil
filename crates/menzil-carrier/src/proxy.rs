//! Proxy resolution (protocol.md 3.1 step 1), phase-1 slice: an explicit
//! override, then `HTTPS_PROXY`/`ALL_PROXY` (either case) respecting
//! `NO_PROXY`, else direct. OS proxy settings, PAC/WPAD, NTLM, and
//! Negotiate are phase 2 (protocol.md 13).

use std::collections::HashMap;

use url::Url;

/// A proxy's address and, if its URL carried userinfo, Basic credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    /// The proxy's host name or IP address.
    pub host: String,
    /// The proxy's port.
    pub port: u16,
    /// Basic auth credentials parsed from the proxy URL's userinfo, if
    /// present.
    pub credentials: Option<ProxyCredentials>,
}

/// Basic auth credentials for a proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCredentials {
    /// The username.
    pub username: String,
    /// The password.
    pub password: String,
}

/// An explicit caller decision that skips environment discovery: either a
/// specific proxy to use, or a forced direct connection (equivalent to
/// `--no-proxy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyOverride {
    /// Use exactly this proxy URL, ignoring the environment.
    Use(String),
    /// Skip discovery and connect directly.
    Direct,
}

/// The result of resolving how to reach a target host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyResolution {
    /// Connect directly.
    Direct,
    /// Connect through this proxy.
    Via(ProxyTarget),
}

/// Resolves how to reach `target_host`: `override_` when given, else
/// `NO_PROXY`, else `HTTPS_PROXY`/`ALL_PROXY`, else direct.
///
/// `env` is injected rather than read from the real process environment so
/// resolution stays hermetic and safe to run in parallel tests; callers
/// pass `std::env::vars().collect()` (or similar) in production.
pub fn resolve(
    target_host: &str,
    env: &HashMap<String, String>,
    override_: Option<&ProxyOverride>,
) -> Result<ProxyResolution, String> {
    if let Some(o) = override_ {
        return match o {
            ProxyOverride::Direct => Ok(ProxyResolution::Direct),
            ProxyOverride::Use(raw) => parse_proxy_url(raw).map(ProxyResolution::Via),
        };
    }

    if no_proxy_matches(target_host, env) {
        return Ok(ProxyResolution::Direct);
    }

    if let Some(raw) = lookup_ci(env, "HTTPS_PROXY").or_else(|| lookup_ci(env, "ALL_PROXY")) {
        return parse_proxy_url(&raw).map(ProxyResolution::Via);
    }

    Ok(ProxyResolution::Direct)
}

fn lookup_ci(env: &HashMap<String, String>, key: &str) -> Option<String> {
    env.get(key)
        .or_else(|| env.get(&key.to_ascii_lowercase()))
        .cloned()
}

fn no_proxy_matches(target_host: &str, env: &HashMap<String, String>) -> bool {
    let Some(raw) = lookup_ci(env, "NO_PROXY") else {
        return false;
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .any(|pattern| host_matches_no_proxy(target_host, pattern))
}

/// `NO_PROXY` convention: an exact host match, a `*` wildcard, or a
/// (optionally leading-dot) domain suffix match.
fn host_matches_no_proxy(host: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_start_matches('.').to_ascii_lowercase();
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

fn parse_proxy_url(raw: &str) -> Result<ProxyTarget, String> {
    let url = Url::parse(raw).map_err(|e| format!("invalid proxy URL: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "proxy URL missing host".to_string())?
        .to_string();
    let port = url
        .port_or_known_default()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let credentials = if url.username().is_empty() {
        None
    } else {
        Some(ProxyCredentials {
            username: percent_decode(url.username()),
            password: percent_decode(url.password().unwrap_or("")),
        })
    };
    Ok(ProxyTarget {
        host,
        port,
        credentials,
    })
}

/// A minimal `%XX` percent-decoder for proxy URL userinfo. Bytes are
/// decoded first and the result interpreted as UTF-8 (lossily, which only
/// matters for malformed input) rather than pulling in a dependency for
/// this one narrow use.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn no_env_is_direct() {
        let e = env(&[]);
        assert_eq!(
            resolve("relay.example", &e, None).unwrap(),
            ProxyResolution::Direct
        );
    }

    #[test]
    fn https_proxy_is_used() {
        let e = env(&[("HTTPS_PROXY", "http://proxy.example:3128")]);
        let resolved = resolve("relay.example", &e, None).unwrap();
        assert_eq!(
            resolved,
            ProxyResolution::Via(ProxyTarget {
                host: "proxy.example".to_string(),
                port: 3128,
                credentials: None,
            })
        );
    }

    #[test]
    fn lowercase_env_var_is_honored() {
        let e = env(&[("https_proxy", "http://proxy.example:3128")]);
        assert!(matches!(
            resolve("relay.example", &e, None).unwrap(),
            ProxyResolution::Via(_)
        ));
    }

    #[test]
    fn all_proxy_is_a_fallback() {
        let e = env(&[("ALL_PROXY", "http://proxy.example:3128")]);
        assert!(matches!(
            resolve("relay.example", &e, None).unwrap(),
            ProxyResolution::Via(_)
        ));
    }

    #[test]
    fn https_proxy_takes_precedence_over_all_proxy() {
        let e = env(&[
            ("HTTPS_PROXY", "http://a.example:1"),
            ("ALL_PROXY", "http://b.example:2"),
        ]);
        let ProxyResolution::Via(target) = resolve("relay.example", &e, None).unwrap() else {
            panic!("expected Via");
        };
        assert_eq!(target.host, "a.example");
    }

    #[test]
    fn no_proxy_exact_match_forces_direct() {
        let e = env(&[
            ("HTTPS_PROXY", "http://proxy.example:3128"),
            ("NO_PROXY", "relay.example"),
        ]);
        assert_eq!(
            resolve("relay.example", &e, None).unwrap(),
            ProxyResolution::Direct
        );
    }

    #[test]
    fn no_proxy_suffix_match_forces_direct() {
        let e = env(&[
            ("HTTPS_PROXY", "http://proxy.example:3128"),
            ("NO_PROXY", ".internal.example"),
        ]);
        assert_eq!(
            resolve("relay.internal.example", &e, None).unwrap(),
            ProxyResolution::Direct
        );
    }

    #[test]
    fn no_proxy_does_not_match_unrelated_suffix() {
        let e = env(&[
            ("HTTPS_PROXY", "http://proxy.example:3128"),
            ("NO_PROXY", "example.com"),
        ]);
        assert!(matches!(
            resolve("notexample.com", &e, None).unwrap(),
            ProxyResolution::Via(_)
        ));
    }

    #[test]
    fn override_use_ignores_environment() {
        let e = env(&[("NO_PROXY", "*")]);
        let over = ProxyOverride::Use("http://forced.example:8080".to_string());
        let ProxyResolution::Via(target) = resolve("relay.example", &e, Some(&over)).unwrap()
        else {
            panic!("expected Via");
        };
        assert_eq!(target.host, "forced.example");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn override_direct_ignores_environment() {
        let e = env(&[("HTTPS_PROXY", "http://proxy.example:3128")]);
        let over = ProxyOverride::Direct;
        assert_eq!(
            resolve("relay.example", &e, Some(&over)).unwrap(),
            ProxyResolution::Direct
        );
    }

    #[test]
    fn credentials_are_parsed_and_percent_decoded() {
        let e = env(&[("HTTPS_PROXY", "http://user:p%40ss@proxy.example:3128")]);
        let ProxyResolution::Via(target) = resolve("relay.example", &e, None).unwrap() else {
            panic!("expected Via");
        };
        let creds = target.credentials.unwrap();
        assert_eq!(creds.username, "user");
        assert_eq!(creds.password, "p@ss");
    }
}
