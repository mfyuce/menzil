//! The relay's status export: `<relay dir>/status.json`, what `menzil relay status` prints and
//! what the admin agent's `GetUsage` answers from.
//!
//! The relay process holds its per tenant counters in memory (`Relay::usage_snapshot`). Every
//! [`EXPORT_EVERY`] it writes them to this file (a temporary file in the same directory, synced,
//! renamed over the old one, so a reader sees the old document or the whole new one, and the same
//! mode as the tenant files, in a directory only its owner can enter). A reader judges the file
//! by `generated_unix`: older than [`STALE_AFTER_SECS`] means the relay is down or not exporting.
//!
//! The document, version 1:
//!
//! ```json
//! {"version":1,"generated_unix":N,"tenants":{"<slug>":{"attached_sessions":0,"live_pairs":0,
//!  "bytes_period":0,"names":0,"period_end_unix":0}}}
//! ```
//!
//! The default tenant (the networks no tenant file lists) is under [`DEFAULT_KEY`], `"_default"`,
//! which is never a valid slug. Nothing else is in the file: no token, key, NodeId, network id or
//! address. A suspended tenant's `attached_sessions` and `live_pairs` are zero; `period_end_unix`
//! is 0 while a tenant has moved no data (its period starts with its first byte).

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Result, bail};
use menzil_relay::{Relay, Slug, TenantId, TenantUsageNow};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use super::{relay_dir, unix_now};
use crate::home::Home;

/// The file's name in the relay directory.
pub const FILE: &str = "status.json";
/// The document version this code writes and reads.
pub const VERSION: u32 = 1;
/// The key of the default tenant. Not a valid slug (a slug has no underscore).
pub const DEFAULT_KEY: &str = "_default";
/// The largest file a reader takes.
pub const MAX_BYTES: u64 = 1 << 20;
/// A document generated longer ago than this (seconds) is not current.
pub const STALE_AFTER_SECS: u64 = 60;
/// How often the running relay writes the file.
pub const EXPORT_EVERY: Duration = Duration::from_secs(10);

/// Where the file is.
pub fn status_path(home: &Home) -> PathBuf {
    relay_dir(home).join(FILE)
}

/// One tenant's counters, as the file holds them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantEntry {
    /// Devices attached now.
    pub attached_sessions: u32,
    /// Live forwarding pairs.
    pub live_pairs: u32,
    /// Bytes charged in the current volume period.
    pub bytes_period: u64,
    /// Names held.
    pub names: u32,
    /// When the volume period ends (Unix seconds), 0 before the tenant moved data.
    pub period_end_unix: i64,
}

impl From<TenantUsageNow> for TenantEntry {
    fn from(now: TenantUsageNow) -> Self {
        Self {
            attached_sessions: now.attached_sessions,
            live_pairs: now.live_pairs,
            bytes_period: now.bytes_period,
            names: now.names,
            period_end_unix: now.period_end_unix,
        }
    }
}

/// The whole document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusDoc {
    /// [`VERSION`].
    pub version: u32,
    /// When the relay wrote it (Unix seconds).
    pub generated_unix: u64,
    /// The counters by slug, the default tenant under [`DEFAULT_KEY`].
    pub tenants: BTreeMap<String, TenantEntry>,
}

/// Why a status file cannot be used. The texts are fixed and name no path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusError {
    /// There is no file: the relay is not running, or does not export.
    Missing,
    /// The file is older than [`STALE_AFTER_SECS`] (or dated in the future).
    Stale,
    /// The file is larger than [`MAX_BYTES`].
    TooLarge,
    /// The file is not a version 1 status document.
    Malformed,
    /// The file could not be read.
    Io,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "the relay has not exported its status: it is not running here",
            Self::Stale => "the relay's status is out of date: it is down or has stopped exporting",
            Self::TooLarge => "the relay's status file is too large to use",
            Self::Malformed => "the relay's status file is not a valid status document",
            Self::Io => "the relay's status file could not be read",
        })
    }
}

impl std::error::Error for StatusError {}

impl StatusDoc {
    /// The document for `snapshot` at `generated_unix`.
    pub fn from_snapshot(
        snapshot: &BTreeMap<TenantId, TenantUsageNow>,
        generated_unix: u64,
    ) -> Self {
        let tenants = snapshot
            .iter()
            .map(|(id, now)| {
                let key = id.slug().unwrap_or(DEFAULT_KEY).to_string();
                (key, TenantEntry::from(*now))
            })
            .collect();
        Self {
            version: VERSION,
            generated_unix,
            tenants,
        }
    }

    /// The counters of the tenant under `key` (a slug, or [`DEFAULT_KEY`]); all zero for a tenant
    /// the file does not list (a tenant the relay has not picked up yet).
    pub fn entry(&self, key: &str) -> TenantEntry {
        self.tenants.get(key).copied().unwrap_or_default()
    }

    /// The compact JSON text of the document, ending in a newline.
    pub fn render(&self) -> String {
        let mut text = serde_json::to_string(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Reads a document from file bytes, strictly: version 1, no unknown field, no missing one,
    /// nothing after the document, and every key the default key or a valid slug.
    pub fn parse(bytes: &[u8]) -> Result<Self, StatusError> {
        let doc: Self = serde_json::from_slice(bytes).map_err(|_| StatusError::Malformed)?;
        if doc.version != VERSION {
            return Err(StatusError::Malformed);
        }
        if doc
            .tenants
            .keys()
            .any(|key| key != DEFAULT_KEY && Slug::parse(key).is_err())
        {
            return Err(StatusError::Malformed);
        }
        Ok(doc)
    }

    /// Whether the document is current at `now`: generated at most [`STALE_AFTER_SECS`] ago, and
    /// not dated further ahead than that (a clock that jumped).
    pub fn is_current(&self, now: u64) -> bool {
        self.generated_unix.saturating_add(STALE_AFTER_SECS) >= now
            && self.generated_unix <= now.saturating_add(STALE_AFTER_SECS)
    }

    /// A short table for a person.
    pub fn render_human(&self, now: u64) -> String {
        let mut out = format!(
            "relay status, exported {} s ago\n{:<34} {:>8} {:>6} {:>6} {:>14}  {}\n",
            now.saturating_sub(self.generated_unix),
            "TENANT",
            "SESSIONS",
            "PAIRS",
            "NAMES",
            "BYTES(PERIOD)",
            "PERIOD ENDS"
        );
        let mut keys: Vec<&String> = self.tenants.keys().collect();
        // The default tenant first, then the named ones by slug.
        keys.sort_by_key(|key| (key.as_str() != DEFAULT_KEY, key.as_str()));
        for key in keys {
            let entry = self.tenants[key];
            let label = if key == DEFAULT_KEY {
                "(default)"
            } else {
                key.as_str()
            };
            let ends = if entry.period_end_unix == 0 {
                "-".to_string()
            } else {
                format!("unix {}", entry.period_end_unix)
            };
            out.push_str(&format!(
                "{:<34} {:>8} {:>6} {:>6} {:>14}  {}\n",
                label,
                entry.attached_sessions,
                entry.live_pairs,
                entry.names,
                entry.bytes_period,
                ends
            ));
        }
        out
    }
}

/// Writes the document atomically. A document over [`MAX_BYTES`] is not written (no reader would
/// take it).
pub fn write(home: &Home, doc: &StatusDoc) -> Result<()> {
    let text = doc.render();
    if text.len() as u64 > MAX_BYTES {
        bail!("the status document is larger than {MAX_BYTES} bytes: not written");
    }
    home.write_public(&status_path(home), text.as_bytes())
}

/// The bytes of the file at `path`, at most [`MAX_BYTES`] of them.
fn read_bounded(path: &std::path::Path) -> Result<Vec<u8>, StatusError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(StatusError::Missing),
        Err(_) => return Err(StatusError::Io),
    };
    match file.metadata() {
        Ok(meta) if meta.is_file() => {}
        _ => return Err(StatusError::Io),
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StatusError::Io)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(StatusError::TooLarge);
    }
    Ok(bytes)
}

/// The current status document of the relay of `home`: the file, read within [`MAX_BYTES`],
/// strictly parsed, and fresh at `now`.
pub fn read(home: &Home, now: u64) -> Result<StatusDoc, StatusError> {
    let doc = StatusDoc::parse(&read_bounded(&status_path(home))?)?;
    if doc.is_current(now) {
        Ok(doc)
    } else {
        Err(StatusError::Stale)
    }
}

/// Starts the task that writes the file now and then every `every`, until it is aborted
/// ([`super::RunningRelay::stop`]). A write that fails is warned about once per run of failures.
pub(crate) fn spawn_exporter(relay: Relay, home: Home, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut failing = false;
        loop {
            let doc = StatusDoc::from_snapshot(&relay.usage_snapshot(), unix_now());
            let target = home.clone();
            let result = tokio::task::spawn_blocking(move || write(&target, &doc)).await;
            match result {
                Ok(Ok(())) => failing = false,
                Ok(Err(error)) => {
                    if !failing {
                        tracing::warn!(error = %format!("{error:#}"), "the status file could not be written: `menzil relay status` and GetUsage will see old figures");
                    }
                    failing = true;
                }
                Err(_) => failing = true,
            }
            tokio::time::sleep(every).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn entry(seed: u32) -> TenantEntry {
        TenantEntry {
            attached_sessions: seed,
            live_pairs: seed + 1,
            bytes_period: u64::from(seed) * 3_000_000_000,
            names: seed + 2,
            period_end_unix: 1_900_000_000 + i64::from(seed),
        }
    }

    fn doc(generated_unix: u64, tenants: &[(&str, TenantEntry)]) -> StatusDoc {
        StatusDoc {
            version: VERSION,
            generated_unix,
            tenants: tenants
                .iter()
                .map(|(key, entry)| ((*key).to_string(), *entry))
                .collect(),
        }
    }

    fn home() -> (tempfile::TempDir, Home) {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path().join("menzil"));
        (dir, home)
    }

    /// A document with `count` tenants, big enough to be written in more than one disk block.
    fn big_doc(generated_unix: u64, count: usize) -> StatusDoc {
        StatusDoc {
            version: VERSION,
            generated_unix,
            tenants: (0..count)
                .map(|n| (format!("t-{n:07}"), entry(1)))
                .collect(),
        }
    }

    #[test]
    fn a_document_survives_render_and_parse_and_names_the_default_tenant_apart() {
        let original = doc(
            1_800_000_000,
            &[("alpha", entry(1)), (DEFAULT_KEY, entry(2))],
        );
        let text = original.render();
        assert!(text.ends_with('\n'));
        assert_eq!(StatusDoc::parse(text.as_bytes()).unwrap(), original);
        assert_eq!(original.entry(DEFAULT_KEY), entry(2));
        assert_eq!(original.entry("alpha"), entry(1));
        assert_eq!(
            original.entry("beta"),
            TenantEntry::default(),
            "a tenant the file does not list has zeros"
        );
        // The reserved key can never be a slug, so no tenant can take the default's entry.
        assert!(Slug::parse(DEFAULT_KEY).is_err());
        // The text has the documented keys and nothing else.
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        let keys = |value: &serde_json::Value| -> Vec<String> {
            value.as_object().unwrap().keys().cloned().collect()
        };
        assert_eq!(keys(&json), ["generated_unix", "tenants", "version"]);
        assert_eq!(
            keys(&json["tenants"]["alpha"]),
            [
                "attached_sessions",
                "bytes_period",
                "live_pairs",
                "names",
                "period_end_unix"
            ]
        );
    }

    #[test]
    fn a_snapshot_is_exported_with_the_default_tenant_under_its_own_key() {
        let mut snapshot = BTreeMap::new();
        let now = TenantUsageNow {
            attached_sessions: 3,
            live_pairs: 2,
            bytes_period: 77,
            names: 5,
            period_end_unix: 99,
        };
        snapshot.insert(TenantId::Default, now);
        snapshot.insert(
            TenantId::Named(Slug::parse("alpha").unwrap()),
            TenantUsageNow::default(),
        );
        let exported = StatusDoc::from_snapshot(&snapshot, 12);
        assert_eq!(exported.generated_unix, 12);
        assert_eq!(exported.version, VERSION);
        assert_eq!(exported.tenants.len(), 2);
        assert_eq!(
            exported.entry(DEFAULT_KEY),
            TenantEntry {
                attached_sessions: 3,
                live_pairs: 2,
                bytes_period: 77,
                names: 5,
                period_end_unix: 99
            }
        );
        assert_eq!(exported.entry("alpha"), TenantEntry::default());
    }

    #[test]
    fn parsing_is_strict() {
        let good = doc(5, &[("alpha", entry(1))]).render();
        assert!(StatusDoc::parse(good.as_bytes()).is_ok());
        let bad = [
            String::new(),
            "{}".to_string(),
            good.replace("\"version\":1", "\"version\":2"),
            good.replace("\"version\":1", "\"version\":0"),
            good.replace("\"live_pairs\"", "\"pairs\""),
            good.replace("\"names\"", "\"client_ip\":\"1.2.3.4\",\"names\""),
            good.replace("\"alpha\"", "\"Alpha\""),
            good.replace("\"alpha\"", "\"_menzil\""),
            good.replace("\"alpha\"", "\"\""),
            good.replace("\"alpha\"", "\"a.b\""),
            format!("{good}{good}"),
            good.replace("\"generated_unix\":5", "\"generated_unix\":-5"),
        ];
        for text in &bad {
            assert_eq!(
                StatusDoc::parse(text.as_bytes()),
                Err(StatusError::Malformed),
                "{text}"
            );
        }
        // A reserved but well formed key is judged by the slug rules like any other.
        assert!(StatusDoc::parse(good.replace("\"alpha\"", "\"_default\"").as_bytes()).is_ok());
    }

    #[test]
    fn a_document_is_current_for_a_minute_either_way() {
        let now = 1_000_000;
        for (generated, current) in [
            (now, true),
            (now - STALE_AFTER_SECS, true),
            (now - STALE_AFTER_SECS - 1, false),
            (now + STALE_AFTER_SECS, true),
            (now + STALE_AFTER_SECS + 1, false),
            (0, false),
        ] {
            assert_eq!(
                doc(generated, &[]).is_current(now),
                current,
                "generated {generated}"
            );
        }
    }

    #[test]
    fn reading_tells_missing_stale_oversized_malformed_and_unreadable_apart() {
        let (_d, home) = home();
        let now = 1_800_000_000;
        assert_eq!(read(&home, now), Err(StatusError::Missing));
        write(&home, &doc(now - 5, &[("alpha", entry(1))])).unwrap();
        assert_eq!(read(&home, now).unwrap().entry("alpha"), entry(1));
        assert_eq!(
            read(&home, now + 55),
            Ok(doc(now - 5, &[("alpha", entry(1))]))
        );
        assert_eq!(read(&home, now + 56), Err(StatusError::Stale));
        let path = status_path(&home);
        let mut padded = doc(now, &[]).render().into_bytes();
        padded.resize(usize::try_from(MAX_BYTES).unwrap(), b' ');
        std::fs::write(&path, &padded).unwrap();
        assert!(read(&home, now).is_ok(), "exactly the cap is read");
        padded.push(b' ');
        std::fs::write(&path, &padded).unwrap();
        assert_eq!(read(&home, now), Err(StatusError::TooLarge));
        std::fs::write(&path, b"{\"version\":1").unwrap();
        assert_eq!(read(&home, now), Err(StatusError::Malformed));
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(read(&home, now), Err(StatusError::Io));
        // The texts hold no path.
        for error in [
            StatusError::Missing,
            StatusError::Stale,
            StatusError::TooLarge,
            StatusError::Malformed,
            StatusError::Io,
        ] {
            assert!(!error.to_string().contains('/'));
        }
    }

    #[test]
    fn a_document_over_the_cap_is_not_written_and_the_old_one_stays() {
        let (_d, home) = home();
        write(&home, &doc(7, &[("alpha", entry(1))])).unwrap();
        // About 1.3 MB: past the cap, short of twice it.
        let big = big_doc(8, 12_000);
        let size = big.render().len() as u64;
        assert!(size > MAX_BYTES && size < 2 * MAX_BYTES, "{size}");
        assert!(write(&home, &big).is_err());
        assert_eq!(
            StatusDoc::parse(&std::fs::read(status_path(&home)).unwrap())
                .unwrap()
                .generated_unix,
            7
        );
        // One that fits (about 100 KB) is written.
        write(&home, &big_doc(9, 1_000)).unwrap();
        assert_eq!(
            StatusDoc::parse(&std::fs::read(status_path(&home)).unwrap())
                .unwrap()
                .generated_unix,
            9
        );
    }

    #[test]
    fn the_file_is_written_with_the_tenant_files_mode_and_leaves_nothing_beside_it() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, home) = home();
        write(&home, &doc(1, &[])).unwrap();
        write(&home, &doc(2, &[])).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&status_path(&home)), 0o644);
        let dir = status_path(&home).parent().unwrap().to_path_buf();
        // The relay directory is the owner's alone.
        assert_eq!(mode(&dir), 0o700);
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, [FILE], "no temporary file is left behind");
    }

    /// A reader never sees a partial document: while a writer replaces the file again and again,
    /// alternating a large document and a small one (so a truncating write would show an empty or
    /// half written file), every read parses.
    #[test]
    fn a_reader_never_sees_a_partial_file_while_it_is_replaced() {
        let (_d, home) = home();
        write(&home, &big_doc(1, 4_000)).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let (home, stop) = (home.clone(), Arc::clone(&stop));
                std::thread::spawn(move || {
                    let mut reads = 0u32;
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        match std::fs::read(status_path(&home)) {
                            Ok(bytes) => {
                                assert!(
                                    StatusDoc::parse(&bytes).is_ok(),
                                    "a reader saw a partial file of {} bytes",
                                    bytes.len()
                                );
                                reads += 1;
                            }
                            Err(error) => panic!("the file vanished while replaced: {error}"),
                        }
                    }
                    reads
                })
            })
            .collect();
        for round in 0..60u64 {
            let count = if round % 2 == 0 { 4_000 } else { 3 };
            write(&home, &big_doc(round + 2, count)).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for reader in readers {
            assert!(reader.join().unwrap() > 0, "the reader made no read");
        }
    }

    #[test]
    fn the_human_form_lists_the_default_tenant_first() {
        let shown = doc(
            100,
            &[
                ("zed", entry(3)),
                (DEFAULT_KEY, entry(1)),
                ("alpha", TenantEntry::default()),
            ],
        )
        .render_human(130);
        let lines: Vec<&str> = shown.lines().collect();
        assert!(lines[0].contains("exported 30 s ago"), "{shown}");
        assert!(lines[2].starts_with("(default)"), "{shown}");
        assert!(lines[3].starts_with("alpha"), "{shown}");
        assert!(lines[4].starts_with("zed"), "{shown}");
        assert!(lines[3].trim_end().ends_with('-'), "no period yet: {shown}");
        assert!(lines[4].contains("unix 1900000003"), "{shown}");
        assert!(!shown.contains("_default"));
    }
}
