//! `menzil expose`: a local port made reachable under a public name (S1, blind mode).
//!
//! `menzil expose 8443 --name app` serves `tls:app` to `127.0.0.1:8443` and advertises the name
//! `app` to the relay, which routes `https://app.<share domain>` to this node by SNI without
//! reading the bytes (protocol.md 6.2). The local target speaks its own TLS.
//!
//! How a change reaches a running node. `config.toml` stays the one place that says what the
//! node serves and advertises (a restart keeps it), and a running node is told over the agent
//! socket (protocol.md 12, requests `expose` and `unexpose`) instead of being restarted:
//!
//! ```text
//! client -> agent   expose name=<label> mode=<blind|tcp|terminated> host=<host> port=<port> replace=<0|1> [alpn=<a,b>]\n
//! client -> agent   unexpose <label>\n
//! agent  -> client  error <message>\n      or
//!                   ok\n, then   changed yes|no, share <fields>, note <text> (repeated)
//! ```
//!
//! The agent takes the config lock ([`Home::lock_config`]), edits `config.toml` in text (so that
//! comments, order and everything else a person wrote stay as they are), writes it atomically,
//! and then applies what the file now says to the running node: the services are added to the
//! node's [`LocalServices`] (which every clone of the handle shares) and the node's shares are
//! replaced, which it advertises on its live session. The 15 second reload of a running node
//! does the same from the file, so a hand edit of `[services]` and `[[share]]` is picked up too,
//! under the same lock. With no node running, `menzil expose` edits the file alone.
//!
//! The text edit is checked after it is made: the result must parse, validate, and equal the
//! old configuration with exactly the intended change. A file written in a form the editor does
//! not understand (an inline `share = [...]`, dotted keys) is refused with that reason and left
//! untouched, never mangled.
//!
//! A service that `expose` made carries a trailing `# menzil expose` comment, which is how
//! `expose remove` knows it may take the service out with the share; a service that was already
//! in `[services]` (shared with peers, say) stays.

use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail};
use menzil_node::acme::{FailureKind, check_domain};
use menzil_node::{LocalServices, ShareBook, ShareSnapshot, check_name, validate_shares};
use menzil_proto::{ServiceId, ServiceKind, Share, ShareMode};

use crate::config::{Config, ShareSettings};
use crate::home::Home;
use crate::text;

/// Written after a `[services]` entry that `menzil expose` made.
pub const MARKER: &str = "# menzil expose";

/// The most `share` lines a status reply carries (a node advertises 64 shares at most).
pub const MAX_SHARE_LINES: usize = menzil_node::MAX_SHARES;

/// The longest ALPN identifier `expose` takes.
const MAX_ALPN_BYTES: usize = 255;

/// What the share carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExposeMode {
    /// `tls:<label>`: the relay forwards the encrypted bytes; the local target speaks TLS.
    Blind,
    /// `tcp:<label>`: reached by SNI like a blind share; any protocol inside the TLS.
    Tcp,
    /// `http:<label>`: the relay terminates TLS and speaks HTTP/1.1 to the local target, so it
    /// reads the share's traffic (protocol.md 6.3).
    Terminated,
}

impl ExposeMode {
    /// The word used on the command line and in `config.toml`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blind => "blind",
            Self::Tcp => "tcp",
            Self::Terminated => "terminated",
        }
    }

    /// From the word.
    pub fn parse(word: &str) -> Result<Self, String> {
        match word {
            "blind" => Ok(Self::Blind),
            "tcp" => Ok(Self::Tcp),
            "terminated" => Ok(Self::Terminated),
            other => Err(format!(
                "mode {other:?} is not one of \"blind\", \"tcp\", \"terminated\""
            )),
        }
    }

    fn kind(self) -> ServiceKind {
        match self {
            Self::Blind => ServiceKind::Tls,
            Self::Tcp => ServiceKind::Tcp,
            Self::Terminated => ServiceKind::Http,
        }
    }
}

/// What `menzil expose <port> --name <label>` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeSpec {
    /// The public label (one lowercase LDH label).
    pub label: String,
    /// Blind, tcp or terminated.
    pub mode: ExposeMode,
    /// The host of the local target.
    pub host: String,
    /// The port of the local target.
    pub port: u16,
    /// ALPN identifiers the target terminates; none routes every ALPN except `acme-tls/1`, which
    /// must be listed by name. Not allowed for a terminated share (the relay terminates TLS).
    pub alpn: Vec<String>,
    /// Change a share or a service that exists already.
    pub replace: bool,
}

impl ExposeSpec {
    /// The service the share routes to: `tls:<label>` for blind, `tcp:<label>` for tcp.
    pub fn service(&self) -> Result<ServiceId> {
        format!("{}:{}", self.mode.kind(), self.label)
            .parse()
            .map_err(|e| anyhow!("service for {:?}: {e}", self.label))
    }

    /// The local target as `host:port` (an IPv6 address in brackets), as `[services]` has it.
    pub fn target(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// The `[[share]]` entry this stands for.
    fn settings(&self) -> Result<ShareSettings> {
        Ok(ShareSettings {
            name: self.label.clone(),
            mode: self.mode.as_str().to_string(),
            service: self.service()?.to_string(),
            alpn: (!self.alpn.is_empty()).then(|| self.alpn.clone()),
        })
    }

    /// Checks everything that can be checked without the file: the mode, the label, the port,
    /// the host and the ALPN list. A terminated share takes no ALPN list: the relay, not the
    /// target, terminates its TLS.
    pub fn validate(&self) -> Result<()> {
        if self.mode == ExposeMode::Terminated && !self.alpn.is_empty() {
            bail!(
                "--alpn does not apply to a terminated share: the relay terminates TLS itself and sends the target plain HTTP/1.1"
            );
        }
        check_name(&self.label).map_err(|e| anyhow!("{e}"))?;
        if self.port == 0 {
            bail!("port 0 is not a port to expose");
        }
        check_host(&self.host)?;
        for alpn in &self.alpn {
            let ok = !alpn.is_empty()
                && alpn.len() <= MAX_ALPN_BYTES
                && alpn.bytes().all(|b| b.is_ascii_graphic())
                && !alpn.contains([',', '"', '\\']);
            if !ok {
                bail!(
                    "alpn {:?}: an identifier is 1 to {MAX_ALPN_BYTES} printable ASCII characters without spaces, commas, quotes or backslashes (for example h2, http/1.1)",
                    text::escaped(alpn)
                );
            }
        }
        let share = Share {
            name: self.label.clone(),
            mode: match self.mode {
                ExposeMode::Terminated => ShareMode::Terminated,
                ExposeMode::Blind | ExposeMode::Tcp => ShareMode::Blind,
            },
            service: self.service()?,
            alpn: self.alpn.clone(),
        };
        validate_shares(&[share]).map_err(|e| anyhow!("{e}"))?;
        Ok(())
    }

    /// The agent request line for this.
    pub fn to_request_line(&self) -> String {
        let mut line = format!(
            "expose name={} mode={} host={} port={} replace={}",
            self.label,
            self.mode.as_str(),
            self.host,
            self.port,
            u8::from(self.replace)
        );
        if !self.alpn.is_empty() {
            line.push_str(" alpn=");
            line.push_str(&self.alpn.join(","));
        }
        line
    }

    /// Reads a request line (without its newline) the agent received; every field is checked
    /// by [`Self::validate`] afterwards.
    pub fn parse_request_line(line: &str) -> Result<Self, String> {
        let rest = line
            .strip_prefix("expose ")
            .ok_or_else(|| "not an expose request".to_string())?;
        let (mut name, mut mode, mut host, mut port, mut replace, mut alpn) =
            (None, None, None, None, None, None);
        for token in rest.split(' ').filter(|t| !t.is_empty()) {
            let (key, value) = token
                .split_once('=')
                .ok_or_else(|| format!("{token:?} is not key=value"))?;
            let slot = match key {
                "name" => &mut name,
                "mode" => &mut mode,
                "host" => &mut host,
                "port" => &mut port,
                "replace" => &mut replace,
                "alpn" => &mut alpn,
                other => return Err(format!("unknown field {:?}", text::escaped(other))),
            };
            if slot.replace(value).is_some() {
                return Err(format!("{key} is given twice"));
            }
        }
        let missing = |field: &str| format!("the request has no {field}");
        let port: u16 = port
            .ok_or_else(|| missing("port"))?
            .parse()
            .map_err(|_| "port is not a number from 1 to 65535".to_string())?;
        let replace = match replace.ok_or_else(|| missing("replace"))? {
            "0" => false,
            "1" => true,
            _ => return Err("replace is 0 or 1".to_string()),
        };
        Ok(Self {
            label: name.ok_or_else(|| missing("name"))?.to_string(),
            mode: ExposeMode::parse(mode.ok_or_else(|| missing("mode"))?)?,
            host: host.ok_or_else(|| missing("host"))?.to_string(),
            port,
            alpn: alpn
                .map(|a| a.split(',').map(str::to_string).collect())
                .unwrap_or_default(),
            replace,
        })
    }
}

/// A host the target may be: an IP address, or a host name of letters, digits, hyphens,
/// underscores and dots.
fn check_host(host: &str) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    let name_like = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && !host.starts_with(['-', '.']);
    if !name_like {
        bail!(
            "host {:?} is neither an IP address nor a host name (letters, digits, '.', '-', '_'); give an IPv6 address without brackets",
            text::escaped(host)
        );
    }
    Ok(())
}

/// Whether `host` is this machine's loopback (where a target is not exposed to anyone else).
pub fn is_loopback(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

// ---------------------------------------------------------------------------------------------
// The text edit

/// The lines of `config.toml`, each with its line ending.
struct Doc {
    lines: Vec<String>,
    eol: &'static str,
}

/// A table header line: `[name]` or `[[name]]`.
struct Header {
    array: bool,
    name: String,
}

/// A table of the file: its header line and the lines up to its last line that is neither blank
/// nor a comment (comments before the next header belong to it).
struct Block {
    header: Header,
    start: usize,
    end: usize,
}

fn header_of(line: &str) -> Option<Header> {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix("[[") {
        let name = rest.split("]]").next()?.trim();
        return Some(Header {
            array: true,
            name: name.to_string(),
        });
    }
    let rest = t.strip_prefix('[')?;
    let name = rest.split(']').next()?.trim();
    Some(Header {
        array: false,
        name: name.to_string(),
    })
}

fn is_blank_or_comment(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with('#')
}

/// A `key = "value"` line with a plain string as its value: the key and the value unquoted, and
/// what follows the value (a comment, spaces, the line ending). `None` for anything else.
fn parse_kv(line: &str) -> Option<(String, String, &str)> {
    fn quoted(s: &str) -> Option<(String, &str)> {
        let mut chars = s.char_indices();
        let (_, open) = chars.next()?;
        if open != '"' && open != '\'' {
            return None;
        }
        let end = s[1..].find(open)? + 1;
        let inner = &s[1..end];
        if inner.contains('\\') && open == '"' {
            return None;
        }
        Some((inner.to_string(), &s[end + 1..]))
    }
    let t = line.trim_start();
    let (key, rest) = if t.starts_with(['"', '\'']) {
        quoted(t)?
    } else {
        let end = t
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .unwrap_or(t.len());
        if end == 0 {
            return None;
        }
        (t[..end].to_string(), &t[end..])
    };
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let (value, tail) = quoted(rest)?;
    Some((key, value, tail))
}

fn toml_string(value: &str) -> String {
    let mut out = String::from('"');
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Doc {
    fn new(text: &str) -> Self {
        Self {
            lines: text.split_inclusive('\n').map(str::to_string).collect(),
            eol: if text.contains("\r\n") { "\r\n" } else { "\n" },
        }
    }

    fn text(&self) -> String {
        self.lines.concat()
    }

    fn blocks(&self) -> Vec<Block> {
        let headers: Vec<(usize, Header)> = self
            .lines
            .iter()
            .enumerate()
            .filter_map(|(i, l)| header_of(l).map(|h| (i, h)))
            .collect();
        let mut blocks = Vec::new();
        for (n, (start, _)) in headers.iter().enumerate() {
            let raw_end = headers.get(n + 1).map_or(self.lines.len(), |(i, _)| *i);
            let mut end = raw_end;
            while end > start + 1 && is_blank_or_comment(&self.lines[end - 1]) {
                end -= 1;
            }
            blocks.push(Block {
                start: *start,
                end,
                header: Header {
                    array: headers[n].1.array,
                    name: headers[n].1.name.clone(),
                },
            });
        }
        blocks
    }

    /// Makes sure the last line ends with a line ending, so that a line can follow it.
    fn terminate(&mut self) {
        if let Some(last) = self.lines.last_mut()
            && !last.ends_with('\n')
        {
            last.push_str(self.eol);
        }
    }

    /// Appends lines at the end of the file, after a blank line when the file has content.
    fn append(&mut self, new: Vec<String>) {
        self.terminate();
        if self.lines.last().is_some_and(|l| !l.trim().is_empty()) {
            self.lines.push(self.eol.to_string());
        }
        self.lines.extend(new);
    }

    fn services_block(&self) -> Option<Block> {
        self.blocks()
            .into_iter()
            .find(|b| !b.header.array && b.header.name == "services")
    }

    /// The index of the line of `[services]` that says `key`.
    fn service_line(&self, key: &str) -> Option<usize> {
        let block = self.services_block()?;
        (block.start + 1..block.end)
            .find(|&i| parse_kv(&self.lines[i]).is_some_and(|(k, ..)| k == key))
    }

    /// Whether the `[services]` line for `key` was made by `expose`.
    fn service_is_ours(&self, key: &str) -> bool {
        self.service_line(key).is_some_and(|i| {
            parse_kv(&self.lines[i])
                .is_some_and(|(_, _, tail)| tail.trim_start().starts_with(MARKER))
        })
    }

    /// Sets `key = "target"` in `[services]`: the value of an existing line is replaced with
    /// whatever follows it kept; a new line is added at the end of the table (the table itself
    /// at the end of the file when there is none), marked as ours.
    fn set_service(&mut self, key: &str, target: &str) {
        let quoted_key = toml_string(key);
        if let Some(i) = self.service_line(key) {
            let line = &self.lines[i];
            let indent = &line[..line.len() - line.trim_start().len()];
            let (_, _, tail) = parse_kv(line).expect("found by parse_kv");
            self.lines[i] = format!("{indent}{quoted_key} = {}{tail}", toml_string(target));
            return;
        }
        let new = format!(
            "{quoted_key} = {}  {MARKER}{}",
            toml_string(target),
            self.eol
        );
        if let Some(block) = self.services_block() {
            self.terminate();
            self.lines.insert(block.end, new);
            // `terminate` may have changed the last line only; the insert keeps order.
        } else {
            let header = format!("[services]{}", self.eol);
            self.append(vec![header, new]);
        }
    }

    /// Removes the `[services]` line for `key`; whether there was one. A `[services]` table
    /// left with nothing in it goes too (it was made for this line, or the person emptied it).
    fn remove_service(&mut self, key: &str) -> bool {
        let Some(i) = self.service_line(key) else {
            return false;
        };
        self.lines.remove(i);
        if let Some(block) = self.services_block()
            && block.end == block.start + 1
            && self
                .lines
                .get(block.start + 1)
                .is_none_or(|l| l.trim().is_empty())
        {
            self.lines.remove(block.start);
            self.drop_blank_before(block.start);
        }
        true
    }

    /// Removes the blank line before line `at`, if there is one and what follows is the end of
    /// the file or another blank line: the separator that went with something removed.
    fn drop_blank_before(&mut self, at: usize) {
        if at > 0
            && self.lines[at - 1].trim().is_empty()
            && self.lines.get(at).is_none_or(|l| l.trim().is_empty())
        {
            self.lines.remove(at - 1);
        }
    }

    /// The `[[share]]` blocks, in file order.
    fn share_blocks(&self) -> Vec<Block> {
        self.blocks()
            .into_iter()
            .filter(|b| b.header.array && b.header.name == "share")
            .collect()
    }

    fn share_text(&self, settings: &ShareSettings) -> Vec<String> {
        let eol = self.eol;
        let mut lines = vec![
            format!("[[share]]{eol}"),
            format!("name = {}{eol}", toml_string(&settings.name)),
            format!("mode = {}{eol}", toml_string(&settings.mode)),
            format!("service = {}{eol}", toml_string(&settings.service)),
        ];
        if let Some(alpn) = &settings.alpn {
            let list: Vec<String> = alpn.iter().map(|a| toml_string(a)).collect();
            lines.push(format!("alpn = [{}]{eol}", list.join(", ")));
        }
        lines
    }

    /// Replaces the `index`th `[[share]]` block with `settings`, in place; false if there is no
    /// such block (the share is written in a form this editor does not read).
    fn replace_share(&mut self, index: usize, settings: &ShareSettings) -> bool {
        let Some(block) = self.share_blocks().into_iter().nth(index) else {
            return false;
        };
        self.terminate();
        let new = self.share_text(settings);
        self.lines.splice(block.start..block.end, new);
        true
    }

    fn append_share(&mut self, settings: &ShareSettings) {
        let new = self.share_text(settings);
        self.append(new);
    }

    /// Removes the `index`th `[[share]]` block; false if there is none.
    fn remove_share(&mut self, index: usize) -> bool {
        let Some(block) = self.share_blocks().into_iter().nth(index) else {
            return false;
        };
        self.lines.drain(block.start..block.end);
        self.drop_blank_before(block.start);
        true
    }
}

/// What a change to `config.toml` comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The new text of the file (the old one when nothing changed).
    pub new_text: String,
    /// The configuration the new text parses to.
    pub config: Config,
    /// Whether anything changes.
    pub changed: bool,
    /// The share written (for `expose`), or the share removed (for `expose remove`).
    pub share: ShareSettings,
    /// The local target of that share.
    pub target: String,
    /// A service taken out of `[services]` (it was made by `expose` and nothing else uses it).
    pub removed_service: Option<ServiceId>,
    /// Things worth telling the person.
    pub notes: Vec<String>,
}

/// The configuration of `text`, refused unless the whole of it is valid: an edit on top of a
/// file that is already wrong would hide where the mistake is.
fn parse_for_edit(text: &str) -> Result<Config> {
    let config = Config::parse(text).context("config.toml is not valid, fix it first")?;
    config
        .shares()
        .map_err(|e| anyhow!("{e:#}\nfix config.toml first"))?;
    config
        .local_services()
        .map_err(|e| anyhow!("{e:#}\nfix config.toml first"))?;
    config
        .share_domain()
        .map_err(|e| anyhow!("{e:#}\nfix config.toml first"))?;
    Ok(config)
}

/// The edit is right only if the file now reads as the old configuration with the change.
fn verify(doc: &Doc, expected: &Config) -> Result<Config> {
    let new = Config::parse(&doc.text()).map_err(|e| {
        anyhow!(
            "config.toml is written in a form `menzil expose` cannot edit safely ({e}); it was not changed: edit it by hand"
        )
    })?;
    if &new != expected {
        bail!(
            "config.toml is written in a form `menzil expose` cannot edit safely (the edit would not leave exactly the change asked for); it was not changed: edit it by hand"
        );
    }
    new.shares().map_err(|e| anyhow!("{e:#}"))?;
    new.local_services().map_err(|e| anyhow!("{e:#}"))?;
    Ok(new)
}

fn same_share(have: &ShareSettings, want: &ShareSettings) -> bool {
    have.name == want.name
        && have.mode == want.mode
        && have.service == want.service
        && have.alpn.clone().unwrap_or_default() == want.alpn.clone().unwrap_or_default()
}

fn describe(have: &ShareSettings, config: &Config) -> String {
    let target = config
        .services
        .get(&have.service)
        .map_or("a service that is not in [services]", String::as_str);
    format!("{} {} to {target}", have.mode, have.service)
}

/// Plans `expose` on the text of `config.toml` (an empty text for a missing file). Pure: the
/// caller writes the result.
pub fn plan_expose(text: &str, spec: &ExposeSpec) -> Result<Plan> {
    spec.validate()?;
    let old = parse_for_edit(text)?;
    let label = &spec.label;
    let service = spec.service()?;
    let key = service.to_string();
    let target = spec.target();
    let want = spec.settings()?;
    let existing = old.share.iter().position(|s| &s.name == label);
    let service_now = old.services.get(&key).cloned();
    let mut notes = Vec::new();
    match existing {
        Some(i) => {
            let have = &old.share[i];
            if same_share(have, &want) && service_now.as_deref() == Some(target.as_str()) {
                return Ok(Plan {
                    new_text: text.to_string(),
                    config: old,
                    changed: false,
                    share: want,
                    target,
                    removed_service: None,
                    notes,
                });
            }
            if !spec.replace {
                bail!(
                    "a share named {label:?} exists already ({}); `menzil expose ... --replace` changes it, `menzil expose remove {label}` takes it away",
                    describe(have, &old)
                );
            }
        }
        None => {
            if let Some(current) = &service_now
                && current != &target
                && !spec.replace
            {
                bail!(
                    "{key} is served from {current} in config.toml already; `--replace` points it at {target} instead (peers that hold a grant for it reach the new target too), or pick another --name"
                );
            }
        }
    }
    // Another share on the same service would change with it.
    let others_use = |service_key: &str| {
        old.share
            .iter()
            .enumerate()
            .any(|(i, s)| Some(i) != existing && s.service == service_key)
    };
    if service_now.as_deref().is_some_and(|c| c != target) && others_use(&key) {
        bail!(
            "another share uses {key} too, so its target is not changed here: give this share its own --name"
        );
    }

    let mut doc = Doc::new(text);
    let mut expected = old.clone();
    if service_now.as_deref() != Some(target.as_str()) {
        doc.set_service(&key, &target);
        expected.services.insert(key.clone(), target.clone());
    }
    let mut removed_service = None;
    match existing {
        Some(i) => {
            // A changed mode moves the share to another service: the old one goes if `expose`
            // made it and nothing else uses it, and stays (with a note) otherwise.
            let old_key = old.share[i].service.clone();
            if old_key != key {
                if doc.service_is_ours(&old_key) && !others_use(&old_key) {
                    doc.remove_service(&old_key);
                    expected.services.remove(&old_key);
                    removed_service = old_key.parse().ok();
                } else if old.services.contains_key(&old_key) {
                    notes.push(format!(
                        "{old_key} is still in [services] (it was not made by `menzil expose`, or another share uses it)"
                    ));
                }
            }
            if !doc.replace_share(i, &want) {
                bail!(
                    "the share {label:?} of config.toml is written in a form `menzil expose` cannot edit safely (not as a [[share]] table); it was not changed: edit it by hand"
                );
            }
            expected.share[i] = want.clone();
        }
        None => {
            doc.append_share(&want);
            expected.share.push(want.clone());
        }
    }
    let config = verify(&doc, &expected)?;
    Ok(Plan {
        new_text: doc.text(),
        config,
        changed: true,
        share: want,
        target,
        removed_service,
        notes,
    })
}

/// Plans `expose remove <label>` on the text of `config.toml`.
pub fn plan_unexpose(text: &str, label: &str) -> Result<Plan> {
    let old = parse_for_edit(text)?;
    let Some(index) = old.share.iter().position(|s| s.name == label) else {
        let names: Vec<String> = old.share.iter().map(|s| text::escaped(&s.name)).collect();
        bail!(
            "no share named {:?} in config.toml ({}); `menzil expose list` shows what is exposed",
            text::escaped(label),
            if names.is_empty() {
                "there are none".to_string()
            } else {
                format!("there are: {}", names.join(", "))
            }
        );
    };
    let share = old.share[index].clone();
    let key = share.service.clone();
    let target = old.services.get(&key).cloned().unwrap_or_default();
    let mut doc = Doc::new(text);
    let mut expected = old.clone();
    let mut notes = Vec::new();
    let mut removed_service = None;
    if !doc.remove_share(index) {
        bail!(
            "the share {label:?} of config.toml is written in a form `menzil expose` cannot edit safely (not as a [[share]] table); it was not changed: edit it by hand"
        );
    }
    expected.share.remove(index);
    let used_by_another = old
        .share
        .iter()
        .enumerate()
        .any(|(i, s)| i != index && s.service == key);
    if old.services.contains_key(&key) {
        if doc.service_is_ours(&key) && !used_by_another {
            doc.remove_service(&key);
            expected.services.remove(&key);
            removed_service = key.parse().ok();
        } else {
            notes.push(format!(
                "{key} stays in [services]: it was not made by `menzil expose`, or another share uses it"
            ));
        }
    }
    let config = verify(&doc, &expected)?;
    Ok(Plan {
        new_text: doc.text(),
        config,
        changed: true,
        share,
        target,
        removed_service,
        notes,
    })
}

// ---------------------------------------------------------------------------------------------
// Writing the file and applying it to a running node

/// The parts of a running node that a change is applied to.
pub struct Runtime<'a> {
    /// The services the node serves from (a clone of the handle shares them).
    pub services: &'a LocalServices,
    /// The shares the node advertises.
    pub shares: &'a ShareBook,
}

fn read_config_text(home: &Home) -> Result<String> {
    let path = home.config_path();
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Adds or changes services from `config` on `services`, as a running node reloads them: a
/// service the node serves from another target is pointed at the new one, one it does not serve
/// is added. A service that is not in `config` is not touched (take it out with
/// `menzil expose remove`, or restart). Returns the services that could not be set, with why.
pub fn sync_services(config: &Config, services: &LocalServices) -> Vec<(String, String)> {
    let targets = match config.service_targets() {
        Ok(targets) => targets,
        Err(error) => return vec![("[services]".to_string(), format!("{error:#}"))],
    };
    let mut failed = Vec::new();
    for (id, target) in targets {
        if services.target(&id).as_ref() == Some(&target) {
            continue;
        }
        let name = id.to_string();
        if let Err(error) = services.set_target(id, target) {
            failed.push((name, error.to_string()));
        }
    }
    failed
}

/// Applies `config` to a running node: the services first, then the shares (so that a name is
/// never advertised before what it leads to is served), then the services `removed` after the
/// shares that used them are gone.
fn apply_runtime(config: &Config, runtime: &Runtime<'_>, removed: &[ServiceId]) -> Result<()> {
    if let Some((service, why)) = sync_services(config, runtime.services).into_iter().next() {
        bail!("the node cannot serve {service}: {why}");
    }
    runtime
        .shares
        .set_shares(config.shares()?)
        .map_err(|e| anyhow!("{e}"))?;
    for service in removed {
        runtime.services.remove_target(service);
    }
    Ok(())
}

/// Makes `spec` so: under the config lock, edits and writes `config.toml` and, given a running
/// node's parts, applies it to them. Blocking (the lock waits up to ten seconds).
pub fn expose(home: &Home, spec: &ExposeSpec, runtime: Option<&Runtime<'_>>) -> Result<Plan> {
    let _lock = home.lock_config()?;
    let plan = plan_expose(&read_config_text(home)?, spec)?;
    if plan.changed {
        home.write_config(plan.new_text.as_bytes())?;
    }
    if let Some(runtime) = runtime {
        apply_runtime(&plan.config, runtime, &[])?;
    }
    Ok(plan)
}

/// [`expose`] for `expose remove`.
pub fn unexpose(home: &Home, label: &str, runtime: Option<&Runtime<'_>>) -> Result<Plan> {
    let _lock = home.lock_config()?;
    let plan = plan_unexpose(&read_config_text(home)?, label)?;
    home.write_config(plan.new_text.as_bytes())?;
    if let Some(runtime) = runtime {
        let removed: Vec<ServiceId> = plan.removed_service.iter().cloned().collect();
        apply_runtime(&plan.config, runtime, &removed)?;
    }
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------
// What the relay says about each share

/// Where a share stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareState {
    /// The relay accepted the name.
    Accepted,
    /// The relay rejected it, with a reason.
    Rejected,
    /// Attached, and the relay has not answered for this share yet.
    Pending,
    /// The node is not attached to the relay.
    Offline,
    /// No node is running: only the file is known.
    NoNode,
}

impl ShareState {
    fn word(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Pending => "pending",
            Self::Offline => "offline",
            Self::NoNode => "no_node",
        }
    }
}

/// How the certificate of one full name stands, as the agent reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertViewState {
    /// None is kept and no order is running or has failed.
    None,
    /// One is kept and ends at this Unix time.
    Valid(u64),
    /// An order is running.
    Renewing,
    /// The latest attempt failed, or nothing is ordered (a share domain that differs).
    Failed(FailureKind),
}

/// The certificate of one full name of a share (`menzil node` with `[acme]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertView {
    /// The full name, such as `app.relay.example.org`.
    pub name: String,
    /// How it stands.
    pub state: CertViewState,
}

impl CertView {
    /// `name=state` for the wire: `none`, `valid:<Unix seconds>`, `renewing` or
    /// `failed:<code>` (a fixed word, never the CA's text).
    fn token(&self) -> String {
        let state = match self.state {
            CertViewState::None => "none".to_string(),
            CertViewState::Valid(not_after) => format!("valid:{not_after}"),
            CertViewState::Renewing => "renewing".to_string(),
            CertViewState::Failed(kind) => format!("failed:{}", kind.code()),
        };
        format!("{}={state}", self.name)
    }

    /// Reads one `name=state`; `None` for a name that is not a domain name or a state this
    /// client does not know.
    fn from_token(token: &str) -> Option<Self> {
        let (name, state) = token.split_once('=')?;
        check_domain(name).ok()?;
        let state = match state {
            "none" => CertViewState::None,
            "renewing" => CertViewState::Renewing,
            other => {
                if let Some(not_after) = other.strip_prefix("valid:") {
                    CertViewState::Valid(not_after.parse().ok()?)
                } else {
                    CertViewState::Failed(FailureKind::from_code(other.strip_prefix("failed:")?)?)
                }
            }
        };
        Some(Self {
            name: name.to_string(),
            state,
        })
    }

    /// The state in words, for the person: `none`, `valid until 2027-02-01`, `renewing` or
    /// `failed: <fixed text>`.
    pub fn state_text(&self) -> String {
        match self.state {
            CertViewState::None => "none".to_string(),
            CertViewState::Valid(not_after) => {
                format!("valid until {}", text::date_utc(not_after))
            }
            CertViewState::Renewing => "renewing".to_string(),
            CertViewState::Failed(kind) => format!("failed: {}", kind.text()),
        }
    }
}

/// The most certificates one `share` line carries.
const MAX_CERTS_PER_SHARE: usize = 8;

/// One share as `expose list` and `menzil status` show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareView {
    /// The public label.
    pub label: String,
    /// `blind`, `tcp` or `terminated`.
    pub mode: String,
    /// The service the name routes to.
    pub service: String,
    /// The local target (`host:port`), if the node serves the service.
    pub target: Option<String>,
    /// ALPN identifiers.
    pub alpn: Vec<String>,
    /// What the relay said.
    pub state: ShareState,
    /// The full names the relay accepted, relative to its share domain (`app`, `app.ali`).
    pub names: Vec<String>,
    /// The relay's reason, for a rejected share.
    pub reason: Option<String>,
    /// The certificates the node gets for the names of this share (empty unless `[acme]` is set
    /// and the share lists `acme-tls/1`).
    pub certs: Vec<CertView>,
}

fn mode_word(share: &Share) -> &'static str {
    match (share.mode, share.service.kind) {
        (ShareMode::Terminated, _) => "terminated",
        (ShareMode::Blind, ServiceKind::Tcp) => "tcp",
        (ShareMode::Blind, _) => "blind",
    }
}

/// The views of the shares a running node has, from its book and services. `attached` is
/// whether the node is on the relay now.
pub fn share_views(book: &ShareBook, services: &LocalServices, attached: bool) -> Vec<ShareView> {
    views_from(&book.configured(), &book.snapshot(), services, attached)
}

/// [`share_views`] from the pieces: the shares configured, the relay's answer, the services.
pub fn views_from(
    configured: &[Share],
    snapshot: &ShareSnapshot,
    services: &LocalServices,
    attached: bool,
) -> Vec<ShareView> {
    configured
        .iter()
        .map(|share| {
            let sent = snapshot.sent.contains(share);
            let rejected = sent
                .then(|| snapshot.rejected.iter().find(|r| r.name == share.name))
                .flatten();
            let (state, reason) = if !attached {
                (ShareState::Offline, None)
            } else if snapshot.accepted.contains(share) {
                (ShareState::Accepted, None)
            } else if let Some(rejected) = rejected {
                (ShareState::Rejected, Some(rejected.reason.clone()))
            } else {
                (ShareState::Pending, None)
            };
            let names = if state == ShareState::Accepted {
                let prefix = format!("{}.", share.name);
                snapshot
                    .names
                    .iter()
                    .filter(|n| **n == share.name || n.starts_with(&prefix))
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
            ShareView {
                label: share.name.clone(),
                mode: mode_word(share).to_string(),
                service: share.service.to_string(),
                target: services.target(&share.service).map(|t| t.to_string()),
                alpn: share.alpn.clone(),
                state,
                names,
                reason,
                certs: Vec::new(),
            }
        })
        .collect()
}

/// The views of the shares `config` holds, for when no node is running.
pub fn config_views(config: &Config) -> Result<Vec<ShareView>> {
    Ok(config
        .shares()?
        .iter()
        .map(|share| ShareView {
            label: share.name.clone(),
            mode: mode_word(share).to_string(),
            service: share.service.to_string(),
            target: config.services.get(&share.service.to_string()).cloned(),
            alpn: share.alpn.clone(),
            state: ShareState::NoNode,
            names: Vec::new(),
            reason: None,
            certs: Vec::new(),
        })
        .collect())
}

/// Characters a name from the relay may have when it is shown (a name is letters, digits,
/// hyphens and dots; anything else in it is left out, not shown).
fn clean_names(names: impl IntoIterator<Item = String>) -> Vec<String> {
    names
        .into_iter()
        .filter(|n| {
            !n.is_empty()
                && n.len() <= 253
                && n.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        })
        .take(8)
        .collect()
}

impl ShareView {
    /// The wire form: `share label=.. mode=.. service=.. target=.. state=.. [alpn=a,b]
    /// [names=a,b] [certs=<name>=<state>,..] [reason=<rest of the line>]`. No value but the
    /// reason has a space.
    pub fn to_line(&self) -> String {
        let mut line = format!(
            "share label={} mode={} service={} state={}",
            self.label,
            self.mode,
            self.service,
            self.state.word()
        );
        if let Some(target) = &self.target {
            line.push_str(&format!(" target={target}"));
        }
        if !self.alpn.is_empty() {
            line.push_str(&format!(" alpn={}", self.alpn.join(",")));
        }
        let names = clean_names(self.names.iter().cloned());
        if !names.is_empty() {
            line.push_str(&format!(" names={}", names.join(",")));
        }
        let certs: Vec<String> = self
            .certs
            .iter()
            .filter(|cert| check_domain(&cert.name).is_ok())
            .take(MAX_CERTS_PER_SHARE)
            .map(CertView::token)
            .collect();
        if !certs.is_empty() {
            line.push_str(&format!(" certs={}", certs.join(",")));
        }
        if let Some(reason) = &self.reason {
            line.push_str(&format!(" reason={}", text::one_line(reason, 300)));
        }
        line
    }

    /// Reads a `share` line; `None` when it is not one or lacks a field this client needs. The
    /// text is the relay's and the agent's: it is made printable here too.
    pub fn from_line(line: &str) -> Option<Self> {
        let rest = line.strip_prefix("share ")?;
        let (head, reason) = match rest.split_once(" reason=") {
            Some((head, reason)) => (head, Some(text::one_line(reason, 300))),
            None => (rest, None),
        };
        let (mut label, mut mode, mut service, mut target, mut state) =
            (None, None, None, None, None);
        let (mut alpn, mut names) = (Vec::new(), Vec::new());
        let mut certs = Vec::new();
        for token in head.split(' ').filter(|t| !t.is_empty()) {
            let Some((key, value)) = token.split_once('=') else {
                continue;
            };
            match key {
                "label" => label = Some(value.to_string()),
                "mode" => mode = Some(value.to_string()),
                "service" => service = Some(value.to_string()),
                "target" => target = Some(value.to_string()),
                "state" => {
                    state = Some(match value {
                        "accepted" => ShareState::Accepted,
                        "rejected" => ShareState::Rejected,
                        "pending" => ShareState::Pending,
                        "offline" => ShareState::Offline,
                        _ => return None,
                    })
                }
                "alpn" => alpn = value.split(',').map(str::to_string).collect(),
                "names" => names = value.split(',').map(str::to_string).collect(),
                // A client skips an entry it does not understand, like a field.
                "certs" => {
                    certs = value
                        .split(',')
                        .filter_map(CertView::from_token)
                        .take(MAX_CERTS_PER_SHARE)
                        .collect();
                }
                _ => {}
            }
        }
        let label = label?;
        check_name(&label).ok()?;
        let service = service?;
        service.parse::<ServiceId>().ok()?;
        let mode = mode?;
        if !["blind", "tcp", "terminated"].contains(&mode.as_str()) {
            return None;
        }
        Some(Self {
            label,
            mode,
            service,
            target: target.map(|t| text::one_line(&t, 300)),
            alpn: alpn.into_iter().map(|a| text::one_line(&a, 255)).collect(),
            state: state?,
            names: clean_names(names),
            reason,
            certs,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Replies of the agent

/// What an `expose` request came to, as the agent answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposeReply {
    /// Whether `config.toml` changed.
    pub changed: bool,
    /// The share, as the node holds it now.
    pub share: ShareView,
    /// Things worth telling the person.
    pub notes: Vec<String>,
}

/// What an `unexpose` request came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexposeReply {
    /// Things worth telling the person.
    pub notes: Vec<String>,
    /// Whether the node's service was removed with the share.
    pub service_removed: bool,
}

impl ExposeReply {
    /// The lines after `ok`.
    pub fn to_lines(&self) -> String {
        let mut out = format!(
            "changed {}\n{}\n",
            if self.changed { "yes" } else { "no" },
            self.share.to_line()
        );
        for note in &self.notes {
            out.push_str(&format!("note {}\n", text::one_line(note, 300)));
        }
        out
    }

    /// Reads the lines after `ok`.
    pub fn from_lines(lines: &[String]) -> Result<Self> {
        let (mut changed, mut share, mut notes) = (None, None, Vec::new());
        for line in lines {
            if let Some(value) = line.strip_prefix("changed ") {
                changed = Some(value.trim() == "yes");
            } else if line.starts_with("share ") {
                share = ShareView::from_line(line);
            } else if let Some(note) = line.strip_prefix("note ") {
                notes.push(text::one_line(note, 300));
            }
        }
        match (changed, share) {
            (Some(changed), Some(share)) => Ok(Self {
                changed,
                share,
                notes,
            }),
            _ => bail!("the agent's answer to `expose` is incomplete"),
        }
    }
}

impl UnexposeReply {
    /// The lines after `ok`.
    pub fn to_lines(&self) -> String {
        let mut out = format!(
            "service_removed {}\n",
            if self.service_removed { "yes" } else { "no" }
        );
        for note in &self.notes {
            out.push_str(&format!("note {}\n", text::one_line(note, 300)));
        }
        out
    }

    /// Reads the lines after `ok`.
    pub fn from_lines(lines: &[String]) -> Self {
        let mut reply = Self {
            notes: Vec::new(),
            service_removed: false,
        };
        for line in lines {
            if let Some(value) = line.strip_prefix("service_removed ") {
                reply.service_removed = value.trim() == "yes";
            } else if let Some(note) = line.strip_prefix("note ") {
                reply.notes.push(text::one_line(note, 300));
            }
        }
        reply
    }
}

// ---------------------------------------------------------------------------------------------
// Text for the person

/// The public address of a share, in words, for what is known: the names the relay accepted,
/// the share domain `domain` if configured.
pub fn public_address(view: &ShareView, domain: Option<&str>) -> String {
    let scheme = |name: &str| {
        if view.mode == "tcp" {
            format!("{name}:443 (TLS with that name as SNI; any protocol inside)")
        } else {
            format!("https://{name}")
        }
    };
    match (view.names.is_empty(), domain) {
        (false, Some(domain)) => view
            .names
            .iter()
            .map(|n| scheme(&format!("{n}.{domain}")))
            .collect::<Vec<_>>()
            .join(", "),
        (false, None) => format!(
            "{} under the relay's share domain (put `share_domain = \"...\"` in config.toml to print whole addresses)",
            view.names
                .iter()
                .map(|n| format!("{n}.<share domain>"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        (true, Some(domain)) => format!(
            "{} once the relay accepts it ({}.<tenant>.{domain} if the relay puts your network in a tenant)",
            scheme(&format!("{}.{domain}", view.label)),
            view.label
        ),
        (true, None) => format!(
            "{}.<the relay's share domain> (the domain is the relay's; `share_domain` in config.toml makes this print whole addresses)",
            view.label
        ),
    }
}

/// What the relay said, in words.
fn state_text(view: &ShareView) -> String {
    match view.state {
        ShareState::Accepted => "accepted by the relay".to_string(),
        ShareState::Rejected => format!(
            "REJECTED by the relay: {}",
            text::escaped(view.reason.as_deref().unwrap_or("no reason given"))
        ),
        ShareState::Pending => "the relay has not answered yet".to_string(),
        ShareState::Offline => "not advertised: this node is not attached to the relay".to_string(),
        ShareState::NoNode => {
            "no node is running; it is advertised when `menzil node` starts".to_string()
        }
    }
}

/// One share in `expose list`: a line for what it is, a line for what the relay said and where
/// it is reached.
pub fn render_share(view: &ShareView, domain: Option<&str>) -> String {
    let alpn = if view.alpn.is_empty() {
        String::new()
    } else {
        format!(", alpn {}", text::escaped(&view.alpn.join(", ")))
    };
    let mut out = format!(
        "{}: {} {} -> {}{alpn}\n  {}; {}\n",
        text::escaped(&view.label),
        view.mode,
        text::escaped(&view.service),
        view.target
            .as_deref()
            .map_or_else(|| "(not served)".to_string(), text::escaped),
        state_text(view),
        public_address(view, domain)
    );
    for cert in &view.certs {
        out.push_str(&format!(
            "  cert {}: {}\n",
            text::escaped(&cert.name),
            cert.state_text()
        ));
    }
    out
}

/// `menzil expose list`.
pub fn render_list(views: &[ShareView], domain: Option<&str>) -> String {
    if views.is_empty() {
        return "nothing is exposed: `menzil expose <port> --name <label>` exposes a local port under a public name\n"
            .to_string();
    }
    views.iter().map(|v| render_share(v, domain)).collect()
}

/// The shares in `menzil status`: one line each.
pub fn render_status(views: &[ShareView], domain: Option<&str>) -> String {
    views
        .iter()
        .map(|view| {
            let mut line = format!(
                "share {}: {} {} -> {}; {}; {}",
                text::escaped(&view.label),
                view.mode,
                text::escaped(&view.service),
                view.target
                    .as_deref()
                    .map_or_else(|| "(not served)".to_string(), text::escaped),
                state_text(view),
                public_address(view, domain)
            );
            for cert in &view.certs {
                line.push_str(&format!(
                    "; cert {}: {}",
                    text::escaped(&cert.name),
                    cert.state_text()
                ));
            }
            line.push('\n');
            line
        })
        .collect()
}

/// What `menzil expose` prints after it made a share. `running` says whether a node was told.
pub fn render_exposed(
    spec: &ExposeSpec,
    changed: bool,
    view: &ShareView,
    notes: &[String],
    running: bool,
    domain: Option<&str>,
) -> String {
    let mut out = String::new();
    if changed {
        out.push_str(&format!(
            "exposed {} ({}): {} -> {}\n",
            text::escaped(&view.label),
            view.mode,
            text::escaped(&view.service),
            view.target.as_deref().unwrap_or(&spec.target())
        ));
    } else {
        out.push_str(&format!(
            "{} is exposed as asked already; nothing changed\n",
            text::escaped(&view.label)
        ));
    }
    if spec.mode == ExposeMode::Terminated {
        out.push_str(
            "warning: the relay terminates TLS for this share and READS all of its traffic (protocol.md 6.3); do not expose anything you would not show the relay operator\n",
        );
        out.push_str(
            "the target must speak plain HTTP/1.1 (no TLS): the relay sends it the decrypted requests\n",
        );
        out.push_str(
            "it is served only if the relay operator turned `terminated` on for your tenant (`relay` tenant file) and the relay holds a certificate for the name\n",
        );
    } else {
        out.push_str(&format!(
            "the target must speak TLS itself: the relay forwards the encrypted bytes of a {} share and cannot read or terminate them\n",
            view.mode
        ));
    }
    if !is_loopback(&spec.host) {
        out.push_str(&format!(
            "warning: {} is not this machine's loopback: whoever reaches the public name reaches {}\n",
            text::escaped(&spec.host),
            spec.target()
        ));
    }
    for note in notes {
        out.push_str(&format!("note: {}\n", text::escaped(note)));
    }
    if running {
        out.push_str(&format!(
            "the running node advertises it now: {}\n",
            state_text(view)
        ));
    } else {
        out.push_str(
            "no node is running: only config.toml was changed; `menzil node` advertises it when it starts\n",
        );
    }
    out.push_str(&format!(
        "public address: {}\n",
        public_address(view, domain)
    ));
    out.push_str("`menzil expose list` shows what the relay says about it\n");
    out
}

/// What `menzil expose remove` prints.
pub fn render_unexposed(label: &str, notes: &[String], running: bool) -> String {
    let mut out = format!("removed the share {}\n", text::escaped(label));
    for note in notes {
        out.push_str(&format!("note: {}\n", text::escaped(note)));
    }
    if running {
        out.push_str("the running node stopped advertising it and serving it\n");
    } else {
        out.push_str("no node is running: only config.toml was changed\n");
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The commands

/// The configuration of `home` and the agent socket it names.
fn setup(home: &Home) -> Result<(Config, std::path::PathBuf)> {
    let config = Config::load(home)?;
    let socket = crate::node_cmd::agent_socket_path(home, &config);
    Ok((config, socket))
}

/// `menzil expose <port> --name <label>`: asks a running node, or edits `config.toml` when none
/// answers. Returns what to print.
pub async fn run_expose(home: &Home, spec: ExposeSpec) -> Result<String> {
    spec.validate()?;
    let (config, socket) = setup(home)?;
    let domain = config.share_domain()?;
    match crate::agent::request_expose(&socket, &spec).await {
        Ok(reply) => Ok(render_exposed(
            &spec,
            reply.changed,
            &reply.share,
            &reply.notes,
            true,
            domain.as_deref(),
        )),
        Err(crate::agent::AskError::Failed(error)) => Err(error),
        Err(crate::agent::AskError::NoAgent) => {
            let home = home.clone();
            let offline = spec.clone();
            let plan = tokio::task::spawn_blocking(move || expose(&home, &offline, None))
                .await
                .context("the change did not finish")??;
            let view = config_views(&plan.config)?
                .into_iter()
                .find(|view| view.label == spec.label)
                .ok_or_else(|| anyhow!("the share is not in config.toml after it was written"))?;
            Ok(render_exposed(
                &spec,
                plan.changed,
                &view,
                &plan.notes,
                false,
                domain.as_deref(),
            ))
        }
    }
}

/// `menzil expose remove <label>`.
pub async fn run_unexpose(home: &Home, label: &str) -> Result<String> {
    let (_, socket) = setup(home)?;
    match crate::agent::request_unexpose(&socket, label).await {
        Ok(reply) => Ok(render_unexposed(label, &reply.notes, true)),
        Err(crate::agent::AskError::Failed(error)) => Err(error),
        Err(crate::agent::AskError::NoAgent) => {
            let (home, label_owned) = (home.clone(), label.to_string());
            let plan = tokio::task::spawn_blocking(move || unexpose(&home, &label_owned, None))
                .await
                .context("the change did not finish")??;
            Ok(render_unexposed(label, &plan.notes, false))
        }
    }
}

/// `menzil expose list`: what a running node holds and what the relay said, or what the file
/// says when no node answers.
pub async fn run_list(home: &Home) -> Result<String> {
    let (config, socket) = setup(home)?;
    let domain = config.share_domain()?;
    match crate::agent::query_node_status(&socket).await {
        Ok(status) => {
            let mut out = String::new();
            match status.relay.attached {
                Some(true) => out.push_str("relay: attached\n"),
                Some(false) => out.push_str("relay: not attached\n"),
                None => {}
            }
            out.push_str(&render_list(&status.shares, domain.as_deref()));
            Ok(out)
        }
        Err(_) => Ok(render_list(&config_views(&config)?, domain.as_deref())),
    }
}

#[cfg(test)]
mod tests;
