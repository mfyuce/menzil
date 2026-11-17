//! The append only audit file of menzil (TBD 67 b). The format is public and versioned:
//! `docs/spec/audit-format.md`. One JSON object per line with `v`, `ts`, `by`, `ev` and the
//! flat fields of the event. No payload is ever a field; a client address is only written when
//! the operator turned that on (the caller decides, see [`AuditLog::include_ips`]).
//!
//! [`AuditLog`] is cheap to clone. A disabled log (the default) writes nothing. A write error
//! is counted and logged at most once a minute and is never fatal.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

/// The format version written as `v`.
pub const FORMAT_VERSION: u64 = 1;

/// The longest string field, in characters.
pub const MAX_FIELD_CHARS: usize = 255;

/// Who writes: the `by` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// A relay.
    Relay,
    /// A node.
    Node,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Node => "node",
        }
    }
}

/// A field value: strings are cut to [`MAX_FIELD_CHARS`] characters.
#[derive(Clone, Debug, PartialEq)]
pub enum Field {
    /// Text.
    Str(String),
    /// An unsigned integer.
    U64(u64),
    /// A number with a fraction.
    F64(f64),
    /// A flag.
    Bool(bool),
}

impl From<&str> for Field {
    fn from(text: &str) -> Self {
        Self::Str(text.to_owned())
    }
}
impl From<String> for Field {
    fn from(text: String) -> Self {
        Self::Str(text)
    }
}
impl From<u64> for Field {
    fn from(n: u64) -> Self {
        Self::U64(n)
    }
}
impl From<u32> for Field {
    fn from(n: u32) -> Self {
        Self::U64(u64::from(n))
    }
}
impl From<f64> for Field {
    fn from(n: f64) -> Self {
        Self::F64(n)
    }
}
impl From<bool> for Field {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

struct Sink {
    file: Mutex<std::fs::File>,
    errors: AtomicU64,
    last_warned: Mutex<Option<Instant>>,
}

/// An audit log: disabled, or an open file.
#[derive(Clone)]
pub struct AuditLog {
    sink: Option<Arc<Sink>>,
    source: Source,
    include_ips: bool,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("enabled", &self.sink.is_some())
            .field("source", &self.source)
            .field("include_ips", &self.include_ips)
            .finish()
    }
}

impl AuditLog {
    /// A log that writes nothing.
    pub fn disabled(source: Source) -> Self {
        Self {
            sink: None,
            source,
            include_ips: false,
        }
    }

    /// Opens `path` for appending (created with mode 0600 if missing). `include_ips` is what
    /// the operator asked for: callers add an address field only when [`Self::include_ips`] is
    /// true.
    pub fn open(path: &Path, source: Source, include_ips: bool) -> std::io::Result<Self> {
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        Ok(Self {
            sink: Some(Arc::new(Sink {
                file: Mutex::new(file),
                errors: AtomicU64::new(0),
                last_warned: Mutex::new(None),
            })),
            source,
            include_ips,
        })
    }

    /// Whether this log writes anything.
    pub fn enabled(&self) -> bool {
        self.sink.is_some()
    }

    /// Whether the operator turned on addresses of clients and targets.
    pub fn include_ips(&self) -> bool {
        self.include_ips
    }

    /// How many lines could not be written.
    pub fn write_errors(&self) -> u64 {
        self.sink
            .as_ref()
            .map_or(0, |sink| sink.errors.load(Ordering::Relaxed))
    }

    /// The same sink under another `by` (a process that is both, never both today).
    pub fn with_source(&self, source: Source) -> Self {
        Self {
            source,
            ..self.clone()
        }
    }

    /// Appends one line for event `ev` with `fields`. The reserved keys `v`, `ts`, `by`, `ev`
    /// cannot be overridden by a field of the same name (such a field is left out).
    pub fn record(&self, ev: &str, fields: &[(&str, Field)]) {
        let Some(sink) = &self.sink else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let line = render(self.source, now, ev, fields);
        let result = {
            let mut file = sink.file.lock().unwrap_or_else(PoisonError::into_inner);
            file.write_all(line.as_bytes())
        };
        if let Err(error) = result {
            sink.errors.fetch_add(1, Ordering::Relaxed);
            let mut last = sink
                .last_warned
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if last.is_none_or(|at| at.elapsed().as_secs() >= 60) {
                *last = Some(Instant::now());
                tracing::warn!(%error, errors = sink.errors.load(Ordering::Relaxed), "the audit file could not be written");
            }
        }
    }
}

fn cut(text: &str) -> String {
    text.chars().take(MAX_FIELD_CHARS).collect()
}

fn render(source: Source, ts: u64, ev: &str, fields: &[(&str, Field)]) -> String {
    let mut map = Map::new();
    map.insert("v".into(), FORMAT_VERSION.into());
    map.insert("ts".into(), ts.into());
    map.insert("by".into(), source.as_str().into());
    map.insert("ev".into(), cut(ev).into());
    for (key, value) in fields {
        if matches!(*key, "v" | "ts" | "by" | "ev") {
            continue;
        }
        let value = match value {
            Field::Str(text) => Value::String(cut(text)),
            Field::U64(n) => (*n).into(),
            Field::F64(n) => serde_json::Number::from_f64(*n).map_or(Value::Null, Value::Number),
            Field::Bool(b) => Value::Bool(*b),
        };
        map.insert(cut(key), value);
    }
    let mut line = Value::Object(map).to_string();
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(path: &Path) -> Vec<Value> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn a_disabled_log_writes_nothing_and_never_fails() {
        let log = AuditLog::disabled(Source::Node);
        log.record("x", &[("a", 1u64.into())]);
        assert!(!log.enabled());
        assert_eq!(log.write_errors(), 0);
    }

    #[test]
    fn a_line_has_the_four_keys_the_fields_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, Source::Relay, false).unwrap();
        log.record(
            "session_attach",
            &[
                ("node_id", "ab".into()),
                ("session", 7u32.into()),
                ("ok", true.into()),
            ],
        );
        // A second handle on the same file appends after it, it does not truncate.
        let again = AuditLog::open(&path, Source::Node, true).unwrap();
        again.record("egress_stream", &[("secs", 1.5f64.into())]);
        let all = lines(&path);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0]["v"], 1);
        assert_eq!(all[0]["by"], "relay");
        assert_eq!(all[0]["ev"], "session_attach");
        assert_eq!(all[0]["node_id"], "ab");
        assert_eq!(all[0]["session"], 7);
        assert_eq!(all[0]["ok"], true);
        assert!(all[0]["ts"].as_u64().unwrap() > 1_700_000_000);
        assert_eq!(all[1]["by"], "node");
        assert_eq!(all[1]["secs"], 1.5);
        assert!(again.include_ips() && !log.include_ips());
    }

    #[test]
    fn text_is_escaped_cut_and_cannot_forge_a_line_or_a_reserved_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, Source::Node, false).unwrap();
        let long = "é".repeat(400);
        log.record(
            "e",
            &[
                ("host", "a\nb\"{\"v\":9}".into()),
                ("long", long.into()),
                ("by", "relay".into()),
                ("v", 9u64.into()),
                ("nan", f64::NAN.into()),
            ],
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            raw.lines().count(),
            1,
            "a newline in a field made a line: {raw}"
        );
        let line = &lines(&path)[0];
        assert_eq!(line["host"], "a\nb\"{\"v\":9}");
        assert_eq!(
            line["long"].as_str().unwrap().chars().count(),
            MAX_FIELD_CHARS
        );
        assert_eq!(
            (line["by"].as_str(), line["v"].as_u64()),
            (Some("node"), Some(1))
        );
        assert!(line["nan"].is_null());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        AuditLog::open(&path, Source::Relay, false).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_write_error_is_counted_and_not_fatal() {
        let log = AuditLog::open(Path::new("/dev/full"), Source::Relay, false).unwrap();
        log.record("x", &[]);
        log.record("x", &[]);
        assert_eq!(log.write_errors(), 2);
    }
}
