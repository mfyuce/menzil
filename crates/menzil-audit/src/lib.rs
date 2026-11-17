//! The append only audit file of menzil (TBD 67 b). The format is public and versioned:
//! `docs/spec/audit-format.md`. One JSON object per line with `v`, `ts`, `by`, `ev` and the
//! flat fields of the event. No payload is ever a field; a client address is only written when
//! the operator turned that on (the caller decides, see [`AuditLog::include_ips`]).
//!
//! [`AuditLog`] is cheap to clone. A disabled log (the default) writes nothing. Lines go through a
//! bounded queue to a writer thread, so a slow disk never stalls a caller (a full queue drops and
//! counts the line). A write error is counted and logged at most once a minute and is never fatal.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

/// The format version written as `v`.
pub const FORMAT_VERSION: u64 = 1;

/// The most items of a list field.
pub const MAX_LIST_ITEMS: usize = 64;

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
    /// A list of strings (each cut like a string field, at most [`MAX_LIST_ITEMS`] items).
    List(Vec<String>),
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
impl From<Vec<String>> for Field {
    fn from(items: Vec<String>) -> Self {
        Self::List(items)
    }
}
impl From<bool> for Field {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}

/// The most lines waiting for the writer thread. A line that finds the queue full is dropped and
/// counted (see [`AuditLog::dropped`]): a slow or stuck disk never stalls a session.
pub const QUEUE_LINES: usize = 4096;

enum Msg {
    Line(String),
    Reopen,
    Flush(SyncSender<()>),
}

struct Counters {
    errors: AtomicU64,
    dropped: AtomicU64,
    last_warned: Mutex<Option<Instant>>,
}

impl Counters {
    fn warn(&self, what: &str, error: &dyn std::fmt::Display) {
        let mut last = self
            .last_warned
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_none_or(|at| at.elapsed().as_secs() >= 60) {
            *last = Some(Instant::now());
            tracing::warn!(%error, errors = self.errors.load(Ordering::Relaxed), dropped = self.dropped.load(Ordering::Relaxed), "{what}");
        }
    }
}

struct Sink {
    tx: SyncSender<Msg>,
    counters: Arc<Counters>,
}

fn open_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            tracing::warn!(path = %path.display(), "the audit file is readable or writable by group or others (mode {:o}); a new file is created 0600", meta.permissions().mode() & 0o777);
        }
    }
    Ok(file)
}

/// The writer thread: owns the file; ends when every [`AuditLog`] handle is gone. `dirty` means
/// the last write failed and a fragment without a newline may end the file: the next line
/// starts on a fresh one.
fn writer<W: Write>(
    rx: Receiver<Msg>,
    mut file: W,
    reopen: Option<Box<dyn Fn() -> std::io::Result<W> + Send>>,
    counters: &Counters,
) {
    let mut dirty = false;
    while let Ok(msg) = rx.recv() {
        match msg {
            Msg::Line(line) => {
                let mut out = String::with_capacity(line.len() + 1);
                if dirty {
                    out.push('\n');
                }
                out.push_str(&line);
                let result = file.write_all(out.as_bytes());
                dirty = result.is_err();
                if let Err(error) = result {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    counters.warn("the audit file could not be written", &error);
                }
            }
            Msg::Reopen => {
                let Some(reopen) = &reopen else { continue };
                // The old file stays in use when the new one cannot be opened.
                match reopen() {
                    Ok(new) => {
                        file = new;
                        dirty = false;
                    }
                    Err(error) => {
                        counters.errors.fetch_add(1, Ordering::Relaxed);
                        counters.warn("the audit file could not be reopened", &error);
                    }
                }
            }
            Msg::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

fn spawn_writer<W: Write + Send + 'static>(
    rx: Receiver<Msg>,
    file: W,
    reopen: Option<Box<dyn Fn() -> std::io::Result<W> + Send>>,
    counters: Arc<Counters>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("menzil-audit".into())
        .spawn(move || writer(rx, file, reopen, &counters))
        .map(|_| ())
}

/// An audit log: disabled, or an open file written by a thread of its own.
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
    /// true. Lines are written by a thread that ends with the last handle; call
    /// [`Self::flush`] before reading the file back.
    pub fn open(path: &Path, source: Source, include_ips: bool) -> std::io::Result<Self> {
        let file = open_file(path)?;
        Self::with_file(file, Some(path.to_path_buf()), source, include_ips)
    }

    fn with_file(
        file: std::fs::File,
        path: Option<PathBuf>,
        source: Source,
        include_ips: bool,
    ) -> std::io::Result<Self> {
        let (tx, rx) = sync_channel(QUEUE_LINES);
        let counters = Arc::new(Counters {
            errors: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            last_warned: Mutex::new(None),
        });
        let reopen = path.map(|path| {
            Box::new(move || open_file(&path))
                as Box<dyn Fn() -> std::io::Result<std::fs::File> + Send>
        });
        spawn_writer(rx, file, reopen, Arc::clone(&counters))?;
        Ok(Self {
            sink: Some(Arc::new(Sink { tx, counters })),
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

    /// How many lines could not be written (disk errors, failed reopens).
    pub fn write_errors(&self) -> u64 {
        self.sink
            .as_ref()
            .map_or(0, |sink| sink.counters.errors.load(Ordering::Relaxed))
    }

    /// How many lines were dropped because the queue to the writer was full.
    pub fn dropped(&self) -> u64 {
        self.sink
            .as_ref()
            .map_or(0, |sink| sink.counters.dropped.load(Ordering::Relaxed))
    }

    /// Asks the writer to open the path again (after a rotation moved the file away: SIGHUP).
    /// Lines queued before are written to the old file. The old file stays in use if the path
    /// cannot be opened. Returns false when the queue was full and the request was not queued.
    pub fn reopen(&self) -> bool {
        self.sink
            .as_ref()
            .is_some_and(|sink| sink.tx.try_send(Msg::Reopen).is_ok())
    }

    /// Waits until every line queued so far is written (a test or a clean stop; waits as long
    /// as the disk takes).
    pub fn flush(&self) {
        let Some(sink) = &self.sink else { return };
        let (done_tx, done_rx) = sync_channel(1);
        if sink.tx.send(Msg::Flush(done_tx)).is_ok() {
            let _ = done_rx.recv();
        }
    }

    /// The same sink under another `by` (a process that is both, never both today).
    pub fn with_source(&self, source: Source) -> Self {
        Self {
            source,
            ..self.clone()
        }
    }

    /// Queues one line for event `ev` with `fields`; never blocks. The reserved keys `v`, `ts`,
    /// `by`, `ev` cannot be overridden by a field of the same name (such a field is left out).
    pub fn record(&self, ev: &str, fields: &[(&str, Field)]) {
        let Some(sink) = &self.sink else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let line = render(self.source, now, ev, fields);
        if let Err(error) = sink.tx.try_send(Msg::Line(line)) {
            sink.counters.dropped.fetch_add(1, Ordering::Relaxed);
            let why = match error {
                TrySendError::Full(_) => "the queue to the audit writer is full",
                TrySendError::Disconnected(_) => "the audit writer has stopped",
            };
            sink.counters
                .warn("an audit line was dropped", &format_args!("{why}"));
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
            Field::List(items) => Value::Array(
                items
                    .iter()
                    .take(MAX_LIST_ITEMS)
                    .map(|item| Value::String(cut(item)))
                    .collect(),
            ),
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
        log.flush();
        again.flush();
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
        log.flush();
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

    #[test]
    fn a_list_is_an_array_with_every_id_whole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, Source::Relay, false).unwrap();
        let ids: Vec<String> = (0..32).map(|i| format!("{i:02x}").repeat(32)).collect();
        log.record("e", &[("networks", ids.clone().into())]);
        log.flush();
        assert_eq!(lines(&path)[0]["networks"], serde_json::json!(ids));
    }

    /// Fails the first write after writing half of it, like a full disk.
    struct HalfThenOk {
        out: Arc<Mutex<Vec<u8>>>,
        failed: bool,
    }
    impl Write for HalfThenOk {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut out = self.out.lock().unwrap();
            if !self.failed {
                self.failed = true;
                out.extend_from_slice(&buf[..buf.len() / 2]);
                return Err(std::io::Error::other("disk full"));
            }
            out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_write_is_counted_and_the_next_line_starts_fresh() {
        let out = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = sync_channel(8);
        let counters = Arc::new(Counters {
            errors: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            last_warned: Mutex::new(None),
        });
        let (done_tx, done_rx) = sync_channel(1);
        tx.send(Msg::Line("{\"a\":1}\n".into())).unwrap();
        tx.send(Msg::Line("{\"b\":2}\n".into())).unwrap();
        tx.send(Msg::Flush(done_tx)).unwrap();
        drop(tx);
        let sink = HalfThenOk {
            out: Arc::clone(&out),
            failed: false,
        };
        writer(rx, sink, None, &counters);
        done_rx.recv().unwrap();
        assert_eq!(counters.errors.load(Ordering::Relaxed), 1);
        let text = String::from_utf8(out.lock().unwrap().clone()).unwrap();
        let rows: Vec<&str> = text.lines().collect();
        assert_eq!(rows.len(), 2, "{text:?}");
        assert!(serde_json::from_str::<Value>(rows[0]).is_err(), "{text:?}");
        assert!(serde_json::from_str::<Value>(rows[1]).is_ok(), "{text:?}");
    }

    #[test]
    fn a_full_queue_drops_and_counts_and_never_blocks() {
        let (tx, _rx) = sync_channel(2);
        let log = AuditLog {
            sink: Some(Arc::new(Sink {
                tx,
                counters: Arc::new(Counters {
                    errors: AtomicU64::new(0),
                    dropped: AtomicU64::new(0),
                    last_warned: Mutex::new(None),
                }),
            })),
            source: Source::Relay,
            include_ips: false,
        };
        for _ in 0..5 {
            log.record("x", &[]);
        }
        assert_eq!(log.dropped(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn reopen_follows_the_path_after_a_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path, Source::Relay, false).unwrap();
        log.record("before", &[]);
        log.flush();
        let rotated = dir.path().join("audit.jsonl.1");
        std::fs::rename(&path, &rotated).unwrap();
        log.record("still_old", &[]);
        assert!(log.reopen());
        log.record("after", &[]);
        log.flush();
        let old: Vec<String> = lines(&rotated)
            .iter()
            .map(|l| l["ev"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(old, ["before", "still_old"]);
        assert_eq!(lines(&path)[0]["ev"], "after");
        assert_eq!(log.write_errors(), 0);
        // A path that cannot be opened keeps the old file in use and is counted.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(log.reopen());
        log.record("kept", &[]);
        log.flush();
        assert_eq!(log.write_errors(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn a_path_that_is_not_a_regular_file_is_refused() {
        assert!(AuditLog::open(Path::new("/dev/null"), Source::Relay, false).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let _log = AuditLog::open(&path, Source::Relay, false).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
