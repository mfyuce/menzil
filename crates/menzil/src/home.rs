//! Where things live, and how they are written.
//!
//! ```text
//! <home>/identity.key              64 secret bytes: Ed25519 seed, X25519 private key (0600)
//! <home>/identity.cert             this node's NodeCert (public)
//! <home>/config.toml               settings (written by the user)
//! <home>/networks/<id>/documents.bin     the Roster and Policy this node holds (one file,
//!                                         so the pair is replaced atomically)
//! <home>/owner/<id>.key            32 secret bytes: the owner key of a network (0600)
//! ```
//!
//! `<home>` is `$MENZIL_HOME`, else `$XDG_CONFIG_HOME/menzil`, else `~/.config/menzil`
//! (`%APPDATA%\menzil` on Windows). The owner key exists only on the owner's device.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use menzil_proto::NetworkId;

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
            // Anything that is not a 64 digit hex name is somebody else's file.
            if let Some(id) = name.to_str().and_then(parse_hex32) {
                ids.push(NetworkId::from(id));
            }
        }
        ids.sort_by_key(|id| id.to_hex());
        Ok(ids)
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
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let temporary = dir.join(format!(".{name}.{}.tmp", std::process::id()));
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
}
