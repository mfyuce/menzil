//! Where things live, and how they are written.
//!
//! ```text
//! <home>/identity.key              64 secret bytes: Ed25519 seed, X25519 private key (0600)
//! <home>/identity.cert             this node's NodeCert (public)
//! <home>/config.toml               settings (written by the user)
//! <home>/networks/<id>/documents.bin     the Roster and Policy this node holds (one file,
//!                                         so the pair is replaced atomically)
//! <home>/owner/<id>.key            32 secret bytes: the owner key of a network (0600)
//! <home>/node.lock                 held by a running `menzil node`: one per home
//! <home>/networks/<id>/.lock       held while a command changes that network's documents
//! ```
//!
//! Directories are created readable by their owner only (0700), and so is every file that holds
//! more than the world may see: the keys, and the documents (the Policy lists who may use what).
//! The one public file is the certificate.
//!
//! `<home>` is `$MENZIL_HOME`, else `$XDG_CONFIG_HOME/menzil`, else `~/.config/menzil`
//! (`%APPDATA%\menzil` on Windows). The owner key exists only on the owner's device.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use menzil_proto::NetworkId;

/// Makes the names of temporary files differ between two writes in one process.
static TEMPORARIES: AtomicU64 = AtomicU64::new(0);

/// How long a command waits for another one that is changing the same network.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// An exclusive advisory lock on a file, held until this is dropped (or the process ends).
#[derive(Debug)]
pub struct FileLock {
    _file: fs::File,
}

/// A user's menzil directory.
#[derive(Debug, Clone)]
pub struct Home {
    root: PathBuf,
}

impl Home {
    /// The directory at `root`, which need not exist yet.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory the environment names (see the module documentation).
    pub fn locate() -> Result<Self> {
        let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
        if let Some(path) = var("MENZIL_HOME") {
            return Ok(Self::new(path));
        }
        if let Some(base) = var("XDG_CONFIG_HOME") {
            return Ok(Self::new(PathBuf::from(base).join("menzil")));
        }
        if let Some(home) = var("HOME") {
            return Ok(Self::new(
                PathBuf::from(home).join(".config").join("menzil"),
            ));
        }
        if let Some(appdata) = var("APPDATA") {
            return Ok(Self::new(PathBuf::from(appdata).join("menzil")));
        }
        bail!("cannot tell where to keep menzil's files: set MENZIL_HOME");
    }

    /// The directory itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The secret keys of this node.
    pub fn identity_key_path(&self) -> PathBuf {
        self.root.join("identity.key")
    }

    /// This node's certificate.
    pub fn identity_cert_path(&self) -> PathBuf {
        self.root.join("identity.cert")
    }

    /// The settings file.
    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// The directory of one network's documents.
    pub fn network_dir(&self, network_id: &NetworkId) -> PathBuf {
        self.root.join("networks").join(network_id.to_hex())
    }

    /// The Roster and Policy this node holds for a network, as one file.
    pub fn documents_path(&self, network_id: &NetworkId) -> PathBuf {
        self.network_dir(network_id).join("documents.bin")
    }

    /// The owner key of a network this node owns.
    pub fn owner_key_path(&self, network_id: &NetworkId) -> PathBuf {
        self.root
            .join("owner")
            .join(format!("{}.key", network_id.to_hex()))
    }

    /// The networks this node holds documents for, in id order.
    pub fn networks(&self) -> Result<Vec<NetworkId>> {
        let dir = self.root.join("networks");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            // Anything that is not a 64 digit hex name is somebody else's file, and a directory
            // without documents (a write that failed, a lock taken before the first save) is
            // not a network yet.
            if let Some(id) = name.to_str().and_then(parse_hex32) {
                let id = NetworkId::from(id);
                if self.documents_path(&id).is_file() {
                    ids.push(id);
                }
            }
        }
        ids.sort_by_key(|id| id.to_hex());
        Ok(ids)
    }

    /// Takes the lock that serializes changes to one network's documents: two commands that
    /// read the documents, issue the next ones and write them at the same moment would issue the
    /// same `seq` twice with different contents, and report success both. Waits for the other
    /// command, up to ten seconds.
    pub fn lock_network(&self, network_id: &NetworkId) -> Result<FileLock> {
        let dir = self.network_dir(network_id);
        create_private_dirs(&dir)?;
        lock_file(&dir.join(".lock"), LOCK_WAIT).with_context(|| {
            format!(
                "another menzil command is changing network {network_id}; try again in a moment"
            )
        })
    }

    /// Takes the lock that serializes `menzil init`: two at once would each find no identity,
    /// each make one, and write the certificate of one next to the key of the other, both
    /// reporting success (the fourth red-team round, L2). Waits for the other, up to ten
    /// seconds; the one that waited then finds the identity and stops.
    pub fn lock_init(&self) -> Result<FileLock> {
        create_private_dirs(&self.root)?;
        lock_file(&self.root.join("init.lock"), LOCK_WAIT).with_context(|| {
            format!(
                "another `menzil init` is running with {}; try again in a moment",
                self.root.display()
            )
        })
    }

    /// Takes the lock that serializes changes to the Rosters a relay keeps (`relay add-network`
    /// reads what is held, compares and writes: two at once could leave the older Roster on disk;
    /// the fourth red-team round, N5). Waits for the other, up to ten seconds.
    pub fn lock_relay(&self) -> Result<FileLock> {
        let dir = self.root.join("relay");
        create_private_dirs(&dir)?;
        lock_file(&dir.join(".lock"), LOCK_WAIT).with_context(|| {
            format!(
                "another `menzil relay add-network` is changing {}; try again in a moment",
                dir.display()
            )
        })
    }

    /// Takes the lock a running `menzil node` holds: two nodes with one identity would displace
    /// each other at the relay. Fails at once if another node holds it.
    pub fn lock_node(&self) -> Result<FileLock> {
        create_private_dirs(&self.root)?;
        lock_file(&self.root.join("node.lock"), Duration::ZERO).with_context(|| {
            format!(
                "another `menzil node` is running with {} (one node per identity)",
                self.root.display()
            )
        })
    }

    /// Writes a file readable by its owner only, replacing any earlier one atomically.
    pub fn write_secret(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        write_atomically(path, bytes, true)
    }

    /// Writes a file anybody may read, replacing any earlier one atomically.
    pub fn write_public(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        write_atomically(path, bytes, false)
    }
}

/// Opens (creating it, 0600) and exclusively locks the file at `path`, waiting up to `wait`.
fn lock_file(path: &Path, wait: Duration) -> Result<FileLock> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let started = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(FileLock { _file: file }),
            Err(fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= wait {
                    bail!("{} is locked by another process", path.display());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(fs::TryLockError::Error(error)) => {
                return Err(error).with_context(|| format!("locking {}", path.display()));
            }
        }
    }
}

/// Creates `dir` and the directories above it that are missing, readable by their owner only
/// (0700, less what the umask takes away). Directories that exist are left as they are.
fn create_private_dirs(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// The 32 bytes a 64 digit hex string stands for, or `None` for anything else. Upper and lower
/// case are both accepted.
pub fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks(2).enumerate() {
        let digit = |b: u8| (b as char).to_digit(16);
        out[i] = (digit(pair[0])? * 16 + digit(pair[1])?) as u8;
    }
    Some(out)
}

/// Writes `bytes` to a temporary file in `path`'s directory and renames it over `path`, so that
/// a reader sees the old file or the whole new one, never half of it. A secret file is created
/// with mode 0600 before anything is written to it (on platforms that have modes).
fn write_atomically(path: &Path, bytes: &[u8], secret: bool) -> Result<()> {
    let dir = path
        .parent()
        .with_context(|| format!("{} has no directory", path.display()))?;
    create_private_dirs(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let temporary = dir.join(format!(
        ".{name}.{}.{}.tmp",
        std::process::id(),
        TEMPORARIES.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(if secret { 0o600 } else { 0o644 });
        }
        #[cfg(not(unix))]
        let _ = secret;
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("creating {}", temporary.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path).with_context(|| format!("replacing {}", path.display()))?;
        // The rename itself is only durable once the directory is: best effort, a file system
        // that cannot sync a directory has still done the rename.
        if let Ok(directory) = fs::File::open(dir) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids_parse_in_either_case_and_nothing_else_does() {
        let id = [0xab; 32];
        let lower = "ab".repeat(32);
        assert_eq!(parse_hex32(&lower), Some(id));
        assert_eq!(parse_hex32(&lower.to_uppercase()), Some(id));
        for bad in [
            "",
            "ab",
            &"ab".repeat(31),
            &"ab".repeat(33),
            &"zz".repeat(32),
            &format!("{}é", "a".repeat(62)),
            &format!("0x{}", "ab".repeat(31)),
        ] {
            assert_eq!(parse_hex32(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_written_file_replaces_the_old_one_whole_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path().join("home"));
        let path = home.identity_cert_path();
        home.write_public(&path, b"first").unwrap();
        home.write_public(&path, b"second, longer").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second, longer");
        let leftovers: Vec<_> = fs::read_dir(home.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("identity.cert")]);
    }

    #[cfg(unix)]
    #[test]
    fn secrets_are_created_readable_by_their_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path());
        let secret = home.identity_key_path();
        let public = home.identity_cert_path();
        home.write_secret(&secret, b"secret").unwrap();
        home.write_public(&public, b"public").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&secret), 0o600);
        assert_eq!(mode(&public) & 0o022, 0, "not writable by others");
        // Replacing a secret keeps it private.
        home.write_secret(&secret, b"another").unwrap();
        assert_eq!(mode(&secret), 0o600);
    }

    #[test]
    fn networks_are_listed_by_their_directories_and_strangers_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path());
        assert!(home.networks().unwrap().is_empty());
        let (a, b) = (NetworkId::from([2u8; 32]), NetworkId::from([1u8; 32]));
        for id in [&a, &b] {
            home.write_public(&home.documents_path(id), b"r").unwrap();
        }
        fs::create_dir_all(dir.path().join("networks").join("notes")).unwrap();
        fs::write(dir.path().join("networks").join("stray.txt"), b"x").unwrap();
        assert_eq!(home.networks().unwrap(), vec![b, a]);
    }

    #[test]
    fn paths_are_under_the_home_and_name_the_network_in_hex() {
        let home = Home::new("/h");
        let id = NetworkId::from([0x0a; 32]);
        let hex = "0a".repeat(32);
        assert_eq!(home.identity_key_path(), PathBuf::from("/h/identity.key"));
        assert_eq!(
            home.documents_path(&id),
            PathBuf::from(format!("/h/networks/{hex}/documents.bin"))
        );
        assert_eq!(
            home.owner_key_path(&id),
            PathBuf::from(format!("/h/owner/{hex}.key"))
        );
    }

    #[test]
    fn writes_racing_in_one_process_do_not_collide_on_a_temporary_name() {
        // The temporary name used to be the process id alone: two writes of one file from two
        // threads collided ("File exists"), and the loser's cleanup removed the winner's file.
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path());
        let path = home.identity_cert_path();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8u8)
            .map(|i| {
                let (home, path, barrier) = (home.clone(), path.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    for round in 0..25u8 {
                        home.write_public(&path, &[i, round]).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(fs::read(&path).unwrap().len(), 2, "one whole write won");
        let leftovers: Vec<_> = fs::read_dir(home.root())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("identity.cert")]);
    }

    #[test]
    fn a_lock_excludes_every_other_holder_until_it_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let first = lock_file(&path, Duration::ZERO).unwrap();
        let started = Instant::now();
        let error = lock_file(&path, Duration::from_millis(150)).unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(150), "it waited");
        assert!(format!("{error:#}").contains("locked by another process"));
        drop(first);
        lock_file(&path, Duration::ZERO).unwrap();
    }

    #[test]
    fn a_network_lock_waits_for_the_command_that_holds_it() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path());
        let id = NetworkId::from([7u8; 32]);
        let first = home.lock_network(&id).unwrap();
        let (home2, ready) = (home.clone(), std::sync::mpsc::channel());
        let waiter = std::thread::spawn(move || {
            let _second = home2.lock_network(&id).unwrap();
            ready.0.send(()).unwrap();
        });
        // Not yet: the first holder has it.
        assert!(ready.1.recv_timeout(Duration::from_millis(200)).is_err());
        drop(first);
        ready
            .1
            .recv_timeout(Duration::from_secs(5))
            .expect("the waiter gets the lock when the holder lets go");
        waiter.join().unwrap();
        // A lock does not make a network of an empty directory.
        assert!(home.networks().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn directories_are_created_for_their_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path().join("a").join("b").join("home"));
        let id = NetworkId::from([3u8; 32]);
        home.write_secret(&home.owner_key_path(&id), b"k").unwrap();
        home.write_secret(&home.documents_path(&id), b"d").unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        for path in [
            home.root().to_path_buf(),
            home.root().join("owner"),
            home.root().join("networks"),
            home.network_dir(&id),
        ] {
            assert_eq!(mode(&path) & 0o077, 0, "{}", path.display());
        }
        // The lock files are private too.
        let _lock = home.lock_node().unwrap();
        assert_eq!(mode(&home.root().join("node.lock")) & 0o077, 0);
    }

    #[test]
    fn a_directory_without_documents_is_not_a_network() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path());
        let (with, without) = (NetworkId::from([1u8; 32]), NetworkId::from([2u8; 32]));
        home.write_public(&home.documents_path(&with), b"r")
            .unwrap();
        fs::create_dir_all(home.network_dir(&without)).unwrap();
        // A directory in the place of the file does not count either.
        let odd = NetworkId::from([3u8; 32]);
        fs::create_dir_all(home.documents_path(&odd)).unwrap();
        assert_eq!(home.networks().unwrap(), vec![with]);
    }
}
