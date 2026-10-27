//! `menzil node`: the process that holds this device's relay session, serves its services and
//! answers the local agent socket (protocol.md 12). One per user.
//!
//! It reads the identity, every network's documents and `config.toml`, attaches to the relay
//! from the configuration, serves the `[services]` table to peers that hold a grant, and lets
//! local programs (`menzil stdio`, `menzil reach`) open streams to other members by name.
//! Updated documents (`menzil join` of a newer token) are picked up while it runs; a network
//! joined for the first time needs a restart, because the networks a node claims are fixed when
//! it attaches.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use menzil_carrier::DialConfig;
use menzil_node::{
    Adopted, AdoptedDocs, DocStore, EnsureError, LocalIdentity, Node, NodeConfig, NodeError,
    NodeOpenError, OpenStreamError, PolicyStore, RelayError, RosterStore, SessionConfig,
};
use menzil_proto::trust::{DOC_MAX_LIFETIME, Reason};
use menzil_proto::{ErrorCode, NetworkId, NodeId, ServiceId, ServiceKind};
use menzil_stream::Stream;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use crate::agent::{self, Opener};
use crate::config::Config;
use crate::home::{FileLock, Home};
use crate::local::{keep_documents, load_documents, load_identity};
use crate::persist::Worker;
use crate::steward_loop::{self, is_issuer, spawn_push};
use crate::text;

/// How often a running node looks for newer documents on disk.
const RELOAD_EVERY: Duration = Duration::from_secs(15);

/// How long a stopping node spends telling its peers and the relay goodbye.
const STOP_GRACE: Duration = Duration::from_secs(3);

/// One member of one network, as a person names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The network.
    pub network_id: NetworkId,
    /// The name in the Policy.
    pub name: String,
    /// The node.
    pub node_id: NodeId,
}

/// Who can be named: every member of every network this device holds documents for.
#[derive(Debug, Clone, Default)]
pub struct Directory {
    entries: Vec<Entry>,
}

impl Directory {
    /// From the documents in `home`; every network's documents must be readable.
    pub fn load(home: &Home) -> Result<Self> {
        let mut entries = Vec::new();
        for network_id in home.networks()? {
            let docs = load_documents(home, &network_id)?;
            entries.extend(Self::members_of(&network_id, &docs));
        }
        Ok(Self { entries })
    }

    /// The members one network's documents name.
    fn members_of(
        network_id: &NetworkId,
        docs: &menzil_admin::Documents,
    ) -> impl Iterator<Item = Entry> {
        let network_id = *network_id;
        docs.policy_body().members.iter().map(move |member| Entry {
            network_id,
            name: member.name.clone(),
            node_id: member.node_id,
        })
    }

    /// What this directory holds for one network.
    fn entries_in<'a>(&'a self, network_id: &'a NetworkId) -> impl Iterator<Item = &'a Entry> {
        self.entries
            .iter()
            .filter(move |entry| &entry.network_id == network_id)
    }

    /// From entries already at hand.
    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// The member `who` names: by name, or by the start of its NodeId in hex (8 digits or more).
    /// A name used in several networks, a prefix several nodes share, or a name that is the
    /// start of another member's node id, is refused with a list rather than guessed: names win
    /// over nothing (the third red-team round, M1: a member named like the start of this
    /// device's own node id, in another network, used to take the address of that node).
    ///
    /// Names compare without regard to letter case, as the issuing tool's own rule for a name
    /// being taken does, and as `ssh` needs: OpenSSH lowercases the host name before it expands
    /// `%h`, so `ssh Laptop` runs `menzil stdio laptop/ssh` (the fourth red-team round, M2: with
    /// an exact comparison a member `Laptop` could not be reached that way, and the owner of any
    /// other network this device is in could name a member `laptop` and take the connection).
    /// Every hit counts toward ambiguity.
    pub fn resolve(&self, who: &str) -> Result<&Entry, String> {
        let wants_prefix = who.len() >= 8 && who.bytes().all(|b| b.is_ascii_hexdigit());
        let prefix = who.to_ascii_lowercase();
        let wanted = who.to_lowercase();
        let hits: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|e| {
                e.name.to_lowercase() == wanted
                    || (wants_prefix && e.node_id.to_hex().starts_with(&prefix))
            })
            .collect();
        match hits.as_slice() {
            [one] => Ok(one),
            [] => {
                let mut names: Vec<String> = self
                    .entries
                    .iter()
                    .map(|e| text::escaped(&e.name))
                    .collect();
                names.sort();
                names.dedup();
                Err(if names.is_empty() {
                    "this node holds no network documents".to_string()
                } else {
                    format!(
                        "no member called {:?} (members: {})",
                        text::escaped(who),
                        names.join(", ")
                    )
                })
            }
            several => Err(format!(
                "{:?} is ambiguous: {}",
                text::escaped(who),
                several
                    .iter()
                    .map(|e| format!(
                        "{} ({} in network {})",
                        text::escaped(&e.name),
                        &e.node_id.to_hex()[..8],
                        &e.network_id.to_hex()[..8]
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}

/// `<who>/<service>`: the member and the service, `ssh` standing for `tcp:ssh`.
pub fn split_target(target: &str) -> Result<(&str, ServiceId), String> {
    let (who, service) = target
        .split_once('/')
        .filter(|(who, service)| !who.is_empty() && !service.is_empty())
        .ok_or_else(|| format!("{target:?} is not <who>/<service>, for example laptop/ssh"))?;
    let id = if service.contains(':') {
        service
            .parse::<ServiceId>()
            .map_err(|e| format!("service {service:?}: {e}"))?
    } else {
        ServiceId::new(ServiceKind::Tcp, service)
    };
    if id.label.is_empty() || id.label == "*" {
        return Err(format!("service {service:?} needs an exact label"));
    }
    Ok((who, id))
}

/// Where the agent listens: `agent_socket` in the configuration, else a socket under the
/// runtime directory, else one in the home.
pub fn agent_socket_path(home: &Home, config: &Config) -> PathBuf {
    if let Some(path) = &config.agent_socket {
        return path.clone();
    }
    match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        Some(runtime) => PathBuf::from(runtime).join("menzil").join("agent.sock"),
        None => home.root().join("agent.sock"),
    }
}

/// A Unix socket this program serves, in the words of the errors about it: what it is, where the
/// person changes its path, and who else could be holding it.
#[derive(Debug, Clone, Copy)]
pub struct SocketKind {
    /// What the socket is: "the agent socket".
    pub what: &'static str,
    /// What the person sets to move it: "`agent_socket` in config.toml".
    pub setting: &'static str,
    /// Who is meant when a live socket is found at the path: "another menzil node".
    pub holder: &'static str,
}

/// The socket `menzil node` answers `stdio` and `reach` on.
pub const AGENT_SOCKET: SocketKind = SocketKind {
    what: "the agent socket",
    setting: "`agent_socket` in config.toml",
    holder: "another menzil node",
};

/// The longest path a Unix domain socket can have is about 108 bytes (`sun_path`, less on some
/// systems); beyond it binding or connecting fails with an error that does not say what to do.
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// Refuses a socket path too long to use, with the remedy.
pub fn check_path_length(path: &Path, kind: &SocketKind) -> Result<()> {
    let length = path.as_os_str().len();
    if length > MAX_SOCKET_PATH_BYTES {
        bail!(
            "{} path is {length} bytes, more than a Unix socket path can be (about {MAX_SOCKET_PATH_BYTES}): set {} to a shorter path in a directory that only you can use, such as one under $XDG_RUNTIME_DIR: {}",
            kind.what,
            kind.setting,
            path.display()
        );
    }
    Ok(())
}

/// [`check_path_length`] for the agent socket.
pub fn check_socket_path_length(path: &Path) -> Result<()> {
    check_path_length(path, &AGENT_SOCKET)
}

/// The directory a socket path is in: a bare file name has no directory part, and means the
/// current directory.
fn socket_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// The environment as the node's settings see it: variables that are text. `env::vars` panics
/// on one that is not, and one that is not cannot name a proxy or a certificate file.
pub fn text_environment(
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> HashMap<String, String> {
    vars.filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
        .collect()
}

/// The directory of a private socket must belong to this user (or to root) and must not be
/// writable by other users, unless it has the sticky bit (as `/tmp` does: others cannot remove
/// or rename what is not theirs). In a directory others can write to, a user could swap the
/// socket, or the directory, for a link between the bind and the chmod that follows, and have
/// this process change the mode of a file of its own that the link points at (the fourth
/// red-team round, N4). Write permission for the group is accepted: with the usual private
/// group (a user's own, as on Ubuntu, where the umask makes every new directory 0775) it means
/// the owner alone, and a shared group is a choice the user made.
#[cfg(unix)]
pub fn check_private_directory(dir: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let found = fs::metadata(dir).with_context(|| format!("looking at {}", dir.display()))?;
    if !found.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    if found.uid() != uid && found.uid() != 0 {
        bail!(
            "{} belongs to another user (uid {}): use a directory of your own",
            dir.display(),
            found.uid()
        );
    }
    let mode = found.mode();
    if mode & 0o002 != 0 && mode & 0o1000 == 0 {
        bail!(
            "{} can be written by other users (mode {:o}): what is in it, or the path through it, could be swapped for something else; use a directory only you can write to, such as one under $XDG_RUNTIME_DIR",
            dir.display(),
            mode & 0o7777
        );
    }
    Ok(())
}

/// Binds the agent socket (see [`bind_private_socket`]). Whoever connects is checked against this
/// user's uid when the agent accepts (see [`crate::agent`]).
pub async fn bind_agent_socket(path: &Path) -> Result<UnixListener> {
    bind_private_socket(path, &AGENT_SOCKET).await
}

/// A file's identity as the file system tells it: the device and the inode.
#[cfg(unix)]
pub type FileIdentity = (u64, u64);

/// The identity of the file at `path`; a link is not followed.
#[cfg(unix)]
pub fn file_identity(path: &Path) -> std::io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let found = fs::symlink_metadata(path)?;
    Ok((found.dev(), found.ino()))
}

/// Removes the file at `path` if it is still the file with `identity` (a socket this process
/// bound, the lock file next to it), and says whether it did. A path can come to name something
/// else while a socket is served (a file put in its place, a directory in it pointed
/// elsewhere), and removing by name would then delete somebody else's file and leave one's own
/// behind (the fifth red-team round, M1). A link or a directory is never removed: their
/// identity is not the file's.
#[cfg(unix)]
pub fn remove_if_unchanged(path: &Path, identity: FileIdentity) -> bool {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(now) if !now.is_dir() && (now.dev(), now.ino()) == identity => {
            fs::remove_file(path).is_ok()
        }
        _ => false,
    }
}

/// Makes the directory of a socket, and everything on the way to it, such that nobody but this
/// user and root can change where a socket in it is reached, now or later (the fifth red-team
/// round, M1). The directory itself being private is not enough: a link in the path made by
/// another user can be pointed somewhere else once the socket is bound, and whatever connects
/// to the path (a database client, `nc -U`, which check nobody) then reaches that user's
/// socket instead; a directory on the way that others can write to lets them replace a step
/// of the path the same way.
///
/// The path is walked twice. As written, from the root (or the current directory), one step at
/// a time: a step that is a link must be owned by this user or root ([`MetadataExt::uid`] of
/// the link itself, `link_owner` in tests), and the directory it is or leads to is checked as
/// [`check_private_directory`] checks the last one. A missing step is made (0700) only once
/// everything above it has passed, so nothing is created through a link someone else made.
/// Then as it really is, with the links resolved: every directory of the resolved path is
/// checked the same way, which covers the links inside links. Nothing in the chain can then be
/// changed by anybody else, so what was checked is what the kernel resolves when the socket is
/// bound and when a client connects.
///
/// Write permission for the group is accepted on every step, as for the last one (see
/// [`check_private_directory`]), and so is the sticky bit on a directory others can write to
/// (as `/tmp` has: others cannot remove or rename what is not theirs).
#[cfg(unix)]
fn prepare_chain(dir: &Path, uid: u32, link_owner: &dyn Fn(&fs::Metadata) -> u32) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let absolute = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()
            .context("finding the current directory")?
            .join(dir)
    };
    let mut walked = PathBuf::new();
    for component in absolute.components() {
        walked.push(component);
        match fs::symlink_metadata(&walked) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match fs::DirBuilder::new().mode(0o700).create(&walked) {
                    Ok(()) => {}
                    // Somebody else made it a moment ago: what it is gets checked below.
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("creating {}", walked.display()));
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| format!("looking at {}", walked.display()));
            }
        }
        check_step(&walked, uid, link_owner)?;
    }
    let real =
        fs::canonicalize(&absolute).with_context(|| format!("resolving {}", absolute.display()))?;
    let mut walked = PathBuf::new();
    for component in real.components() {
        walked.push(component);
        check_step(&walked, uid, link_owner)?;
    }
    Ok(())
}

/// One step of [`prepare_chain`]: a link must be made by this user or root, and what the step
/// is or leads to must be a directory this user could be trusted with.
#[cfg(unix)]
fn check_step(step: &Path, uid: u32, link_owner: &dyn Fn(&fs::Metadata) -> u32) -> Result<()> {
    let own =
        fs::symlink_metadata(step).with_context(|| format!("looking at {}", step.display()))?;
    if own.file_type().is_symlink() {
        let owner = link_owner(&own);
        if owner != uid && owner != 0 {
            bail!(
                "{} is a link made by another user (uid {owner}): its maker can point it somewhere else after the socket is made, and whatever connects to the path would reach that; use a path without it, or a directory of your own",
                step.display()
            );
        }
    }
    check_private_directory(step, uid)
}

/// Binds a socket only this user can use ([`prepare_socket_directory`], then
/// [`bind_in_prepared_directory`]).
pub async fn bind_private_socket(path: &Path, kind: &SocketKind) -> Result<UnixListener> {
    prepare_socket_directory(path, kind).await?;
    bind_in_prepared_directory(path, kind).await
}

/// The first half of binding a private socket: refuses a path too long to use, and makes the
/// directory (0700 for whatever this creates) and checks the whole path to it (see
/// [`prepare_chain`]). Split from the bind so that a caller can take a lock in the directory
/// once it is known to be safe.
pub async fn prepare_socket_directory(path: &Path, kind: &SocketKind) -> Result<()> {
    check_path_length(path, kind)?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        // `Path` ignores a trailing slash and a trailing `.`, so `dir/` and `dir/.` would
        // otherwise be taken for the file `dir` in the directory above, and the lock file of
        // a reach socket for `dir/.lock`.
        let last = path
            .as_os_str()
            .as_bytes()
            .rsplit(|&byte| byte == b'/')
            .next()
            .unwrap_or_default();
        if matches!(last, b"" | b"." | b"..") {
            bail!(
                "{} does not name a socket file (it ends in a slash, or in `.` or `..`): set {} to a path with a file name in it",
                path.display(),
                kind.setting
            );
        }
    }
    let dir = socket_directory(path);
    #[cfg(unix)]
    {
        let uid = agent::current_uid()
            .await
            .context("finding out which user this is")?;
        prepare_chain(dir, uid, &|link| {
            use std::os::unix::fs::MetadataExt;
            link.uid()
        })?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(())
}

/// The second half: a socket file left by a process that died is removed; one with a process
/// behind it is an error; anything that is not a socket (a file the configuration pointed at
/// by mistake, a link) is an error and is left alone. The socket is readable by its owner only.
/// The directory must have been through [`prepare_socket_directory`].
pub async fn bind_in_prepared_directory(path: &Path, kind: &SocketKind) -> Result<UnixListener> {
    match fs::symlink_metadata(path) {
        Ok(found) => {
            #[cfg(unix)]
            let is_socket = {
                use std::os::unix::fs::FileTypeExt;
                found.file_type().is_socket()
            };
            #[cfg(not(unix))]
            let is_socket = true;
            if !is_socket {
                bail!(
                    "{} exists and is not a socket: not touching it (is {} pointing at the wrong file?)",
                    path.display(),
                    kind.setting
                );
            }
            match UnixStream::connect(path).await {
                Ok(_) => bail!("{} is already listening on {}", kind.holder, path.display()),
                Err(_) => fs::remove_file(path)
                    .with_context(|| format!("removing the stale socket {}", path.display()))?,
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("looking at {}", path.display()));
        }
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}

/// Loads every network's documents into the stores a node verifies against. A network whose
/// documents cannot be read stops the node: running without it would look like a working
/// network that rejects everyone. Documents that are expired or not valid yet do not: the pair
/// is put into the stores anyway, judged at its own `issued` time (every other rule of
/// protocol.md 2.3 still applies: signatures, steward rules, pair rules), and the network is
/// warned about by name. Held that way it is not usable (admission already refuses a pair past
/// its `expires`), but the member can be admitted for documents only and can dial for them, so a
/// steward's push or the relay's catch-up revives it after a restart (protocol.md 7.3; the sixth
/// red-team round, M2, and the ninth, M1). Only this start-up path relaxes the time rules; the
/// reload while the node runs ([`reload_adopting`]) and every other adoption stay strict. A pair
/// that is also bad for another reason, or whose `issued` is more than [`DOC_MAX_LIFETIME`]
/// ahead of the clock, is warned about and left out of the stores like before.
pub fn load_stores(home: &Home) -> Result<(Arc<PolicyStore>, Arc<RosterStore>, Vec<NetworkId>)> {
    let policies = Arc::new(PolicyStore::new());
    let rosters = Arc::new(RosterStore::new());
    let networks = home.networks()?;
    if networks.is_empty() {
        bail!(
            "this device is in no network: `menzil network create` or `menzil join <token>` first"
        );
    }
    for network_id in &networks {
        let docs = load_documents(home, network_id)?;
        match adopt_documents(&rosters, &policies, &docs) {
            Ok(_) => {}
            Err(NodeError::DocumentRejected(reason @ (Reason::Expired | Reason::NotYetValid))) => {
                match adopt_documents_as_issued(&rosters, &policies, &docs) {
                    Ok(_) => {
                        tracing::warn!(
                            network = %network_id,
                            ?reason,
                            "the documents on disk for this network are not valid now: held for documents only, the network is unusable until valid ones arrive (`menzil join` with a newer token, or a push from a steward or the relay)"
                        );
                        eprintln!(
                            "warning: network {network_id}: the documents on disk are not valid now ({reason:?}); held for documents only until valid ones arrive"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            network = %network_id,
                            ?reason,
                            "the documents on disk for this network are not valid now and cannot be held: it stays unusable until valid ones arrive (`menzil join` with a newer token)"
                        );
                        eprintln!(
                            "warning: network {network_id}: the documents on disk are not valid now ({reason:?}); it stays unusable until valid ones arrive"
                        );
                    }
                }
            }
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!(
                    "the documents of network {network_id} were refused"
                )));
            }
        }
    }
    Ok((policies, rosters, networks))
}

/// What came of reading one network's pair from disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disk {
    /// The pair was judged; whatever was newer than the stores held is stored now (`Adopted`
    /// says what).
    Judged(Adopted),
    /// The stores hold a Roster above the pair's `seq` (one that came over L3 ahead of the docs
    /// token). The Policy of the pair cannot be adopted without a Roster of its `seq`, so
    /// nothing is stored until a pair at or above the held Roster arrives.
    Waiting { held_roster: u64 },
}

/// Adopts the pair read from disk (the owner's, or a steward's with its base) through the
/// acceptance predicate of protocol.md 2.3 at the real clock: both are stored or neither is, and
/// a pair that is expired, issued in the future or valid for more than 14 days is refused.
fn adopt_documents(
    rosters: &RosterStore,
    policies: &PolicyStore,
    docs: &menzil_admin::Documents,
) -> Result<Disk, NodeError> {
    let network_id = docs.roster().decode()?.network_id;
    if let Some(held_roster) = rosters.seq(&network_id)
        && held_roster > docs.seq()
    {
        return Ok(Disk::Waiting { held_roster });
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // A pair a steward signed goes in with its base, which is what the stores judge it by and
    // pass it on with.
    let adopted = DocStore::new(rosters, policies).adopt(&docs.bundle(), now)?;
    Ok(Disk::Judged(adopted))
}

/// The start-up path of a pair that failed only on time (see [`load_stores`]): the same
/// acceptance predicate, judged at the pair's own `issued` instead of the clock, so that its
/// signatures, steward rules, pair rules and `seq` still count and only "has it run out" and
/// "is it from the future" do not. `DocStore::adopt` already takes the time to judge at, so no
/// other entry point is needed. A pair issued more than [`DOC_MAX_LIFETIME`] ahead of the clock
/// is not held (that is a wrong clock on the signer's side, not a pair that ran out).
fn adopt_documents_as_issued(
    rosters: &RosterStore,
    policies: &PolicyStore,
    docs: &menzil_admin::Documents,
) -> Result<Adopted, NodeError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let issued = docs.roster_body().issued.max(docs.policy_body().issued);
    if issued > now.saturating_add(DOC_MAX_LIFETIME) {
        return Err(NodeError::DocumentRejected(Reason::NotYetValid));
    }
    DocStore::new(rosters, policies).adopt(&docs.bundle(), issued)
}

/// Opens streams for the agent: resolves the name, then asks the node.
pub struct NodeOpener {
    node: Arc<Node>,
    directory: Arc<RwLock<Directory>>,
}

impl NodeOpener {
    /// An opener over a running node and the directory it resolves names in.
    pub fn new(node: Arc<Node>, directory: Arc<RwLock<Directory>>) -> Self {
        Self { node, directory }
    }
}

/// The relay's last rejection as the agent socket carries it.
fn rejected_of(error: RelayError) -> agent::Rejected {
    agent::Rejected {
        at: error.at,
        code: error.code.map(|code| code.name().to_string()),
        message: error.message,
        goaway: error.goaway,
    }
}

/// What a person is told about a failed open.
#[cfg(test)]
fn explain(error: &NodeOpenError) -> String {
    explain_with(error, None, 0)
}

/// [`explain`] for a node that knows why its relay turned it away, if it does (`rejected`, judged
/// at `now`): then the reason is stated, not only listed among the possible causes.
fn explain_with(error: &NodeOpenError, rejected: Option<&agent::Rejected>, now: u64) -> String {
    match error {
        NodeOpenError::Session(EnsureError::NotAttached) if rejected.is_some() => {
            let rejected = rejected.expect("guarded by is_some");
            format!(
                "this node is not connected to the relay. {}",
                text::turned_away(rejected, now)
            )
        }
        NodeOpenError::Session(EnsureError::NotAttached) => {
            "this node is not connected to the relay (yet): check `relay` in config.toml and the network; a device that was revoked is turned away by the relay too, and `menzil status` on the owner's device shows the revoked"
                .to_string()
        }
        NodeOpenError::Session(EnsureError::Timeout) => {
            "the other device did not answer: is it running `menzil node` and connected to the same relay? (A device that was revoked gets no answer either.)"
                .to_string()
        }
        NodeOpenError::Session(EnsureError::Refused) => {
            "the other device refused the session: are both of you members of the network, with current documents? (Neither of you may be revoked.)"
                .to_string()
        }
        NodeOpenError::Session(EnsureError::NotAMember) => {
            let mut told = "this device is not a member in good standing of that network any more: its documents may have expired (`menzil renew`), or it was revoked or removed by the owner"
                .to_string();
            // The relay may have said which.
            if let Some(rejected) = rejected {
                told.push_str(". ");
                told.push_str(&text::turned_away(rejected, now));
            }
            told
        }
        NodeOpenError::Session(EnsureError::UnknownPeer) => {
            "this device holds no valid certificate for that member in that network: the member may have been revoked, or these documents are older than its admission (`menzil join` a current token)"
                .to_string()
        }
        NodeOpenError::Session(EnsureError::DocsOnly) => {
            "the other device does not have this device's current documents yet (or its own have expired), so it only took them and no session was made: this device sent its documents and waited a few seconds, but no session came up from them, so try again in a moment; if it keeps happening, the other device needs a newer token (`menzil join`)"
                .to_string()
        }
        NodeOpenError::Open(OpenStreamError::Refused { code, msg }) => {
            let meaning = match code {
                ErrorCode::NoGrant => {
                    ": this device holds no grant for that service (the owner never gave it, or took it back with `menzil ungrant`)"
                }
                _ => "",
            };
            format!("refused by the other end: {} ({msg}){meaning}", code.name())
        }
        other => other.to_string(),
    }
}

impl Opener for NodeOpener {
    async fn open(&self, target: &str) -> Result<Stream, String> {
        let (who, service) = split_target(target)?;
        let (network_id, peer) = {
            let directory = self
                .directory
                .read()
                .map_err(|_| "the directory is unavailable".to_string())?;
            let entry = directory.resolve(who)?;
            (entry.network_id, entry.node_id)
        };
        self.node
            .open_stream(peer, network_id, service, None)
            .await
            .map_err(|error| {
                let rejected = self.node.last_relay_error().map(rejected_of);
                explain_with(&error, rejected.as_ref(), unix_now())
            })
    }

    async fn status(&self) -> agent::RelayStatus {
        agent::RelayStatus {
            attached: Some(self.node.is_attached()),
            rejected: self.node.last_relay_error().map(rejected_of),
        }
    }
}

/// The clock in Unix seconds.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A node that is running.
pub struct RunningNode {
    /// The node itself.
    pub node: Arc<Node>,
    /// Where the agent listens.
    pub socket: PathBuf,
    /// Which file the socket is, so that stopping removes that file and not whatever the path
    /// names by then (the fifth red-team round, M1).
    socket_identity: FileIdentity,
    /// The names this node can resolve.
    pub directory: Arc<RwLock<Directory>>,
    tasks: Vec<JoinHandle<()>>,
    /// Writes the documents the node adopts over the network to disk (see
    /// [`keep_adopted_documents`]).
    keeper: Arc<Worker<AdoptedDocs>>,
    /// Held while this node runs: one node per identity.
    _instance: FileLock,
}

impl RunningNode {
    /// Waits until every pair adopted so far has been written to (or refused by) the home
    /// directory, at most `timeout`; whether it got there. A clean stop calls it, so that the
    /// last adoption before a signal is not lost.
    pub fn flush_documents(&self, timeout: Duration) -> bool {
        self.keeper.flush(timeout)
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Starts the node and the agent socket.
pub async fn start(home: &Home, config: &Config, socket: &Path) -> Result<RunningNode> {
    // First: two nodes with one identity would displace each other at the relay, and the socket
    // path alone does not stop that (it depends on the environment).
    let instance = home.lock_node()?;
    let (keys, cert) = load_identity(home)?;
    let (policies, rosters, networks) = load_stores(home)?;
    let keeper = keep_adopted_documents(home, &rosters)?;
    let session = SessionConfig {
        dial: DialConfig {
            connection_info: config.connection_info()?,
            proxy_override: config.proxy_override(),
        },
        identity: LocalIdentity {
            node_cert: cert,
            x25519_private: keys.x25519_private(),
        },
        networks,
        caps: vec![],
        e2e_protos: vec![0x01],
    };
    let services = config.local_services()?;
    let listener = bind_agent_socket(socket).await?;
    let socket_identity =
        file_identity(socket).with_context(|| format!("looking at {}", socket.display()))?;
    let node = Arc::new(
        Node::start(
            NodeConfig {
                session,
                env: text_environment(std::env::vars_os()),
                policies: policies.clone(),
                rosters: rosters.clone(),
            },
            services,
        )
        .map_err(|e| anyhow!("{e}"))?,
    );
    let directory = Arc::new(RwLock::new(Directory::load(home)?));

    let agent_task = tokio::spawn(agent::serve(
        listener,
        Arc::new(NodeOpener::new(node.clone(), directory.clone())),
    ));
    let reload_task = {
        let (home, directory, node) = (home.clone(), directory.clone(), node.clone());
        let (policies, rosters) = (policies.clone(), rosters.clone());
        tokio::spawn(async move {
            let mut last: HashMap<NetworkId, u64> = HashMap::new();
            loop {
                tokio::time::sleep(RELOAD_EVERY).await;
                let mut adopted = Vec::new();
                match reload_adopting(
                    &home,
                    &policies,
                    &rosters,
                    &directory,
                    &mut last,
                    &mut adopted,
                ) {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "reloading the documents failed")
                    }
                }
                // Documents this device's own commands wrote: it is their issuer, so it tells
                // the members (a plain member that took a newer token does not).
                for network_id in adopted {
                    if is_issuer(&home, &network_id) {
                        spawn_push(&node, network_id);
                    }
                }
            }
        })
    };
    let steward_task = tokio::spawn(steward_loop::run(
        home.clone(),
        rosters.clone(),
        policies.clone(),
        node.clone(),
    ));
    Ok(RunningNode {
        node,
        socket: socket.to_path_buf(),
        socket_identity,
        directory,
        tasks: vec![agent_task, reload_task, steward_task],
        keeper,
        _instance: instance,
    })
}

/// Reads the documents again; the stores keep the newer of what they hold and what is on disk
/// (protocol.md 2.3: never a lower `seq`), and the directory follows.
pub fn reload(
    home: &Home,
    policies: &PolicyStore,
    rosters: &RosterStore,
    directory: &RwLock<Directory>,
    last: &mut HashMap<NetworkId, u64>,
) -> Result<()> {
    reload_adopting(home, policies, rosters, directory, last, &mut Vec::new())
}

/// [`reload`], and says which networks got documents from disk that the stores did not hold
/// (`adopted`, appended to): the ones a device that issues them pushes to the members
/// (protocol.md 5.5; `menzil admit` or `renew` wrote them while this node ran).
pub fn reload_adopting(
    home: &Home,
    policies: &PolicyStore,
    rosters: &RosterStore,
    directory: &RwLock<Directory>,
    last: &mut HashMap<NetworkId, u64>,
    adopted: &mut Vec<NetworkId>,
) -> Result<()> {
    // One network that cannot be read (a write that failed, a damaged file) must not keep the
    // others from being reloaded: a revocation installed with `menzil join` would otherwise
    // never be applied. Each failure is reported, and the first is returned at the end.
    let mut first_failure = None;
    let before = directory
        .read()
        .map_err(|_| anyhow!("the directory is unavailable"))?
        .clone();
    let mut entries = Vec::new();
    for network_id in home.networks()? {
        let loaded = load_documents(home, &network_id).and_then(|docs| {
            let disk = adopt_documents(rosters, policies, &docs)?;
            Ok((docs, disk))
        });
        match loaded {
            Ok((docs, Disk::Judged(now_held))) => {
                if now_held.roster || now_held.policy {
                    adopted.push(network_id);
                }
                let seq = docs.seq();
                entries.extend(Directory::members_of(&network_id, &docs));
                if last.insert(network_id, seq) != Some(seq) {
                    tracing::info!(network = %network_id, seq, "holding newer documents");
                }
            }
            // Not a failure: the pair on disk is older than the Roster the relay sent. The
            // stores and the directory stay as they are until a pair at or above it is installed
            // (the sixth red-team round, L1).
            Ok((docs, Disk::Waiting { held_roster })) => {
                if last.insert(network_id, docs.seq()) != Some(docs.seq()) {
                    tracing::info!(
                        network = %network_id,
                        disk_seq = docs.seq(),
                        held_roster,
                        "the documents on disk are older than the Roster held from the relay: waiting for newer ones (`menzil join` with a newer token)"
                    );
                }
                entries.extend(before.entries_in(&network_id).cloned());
            }
            Err(error) => {
                tracing::warn!(network = %network_id, error = %format!("{error:#}"), "cannot reload this network's documents");
                // The stores keep this network's documents as they were, and so does the
                // directory keep its names. Leaving them out would let a name that two networks
                // share (and that is refused as ambiguous) mean the other network's member
                // (the fourth red-team round, L1).
                entries.extend(before.entries_in(&network_id).cloned());
                first_failure.get_or_insert(error);
            }
        }
    }
    *directory
        .write()
        .map_err(|_| anyhow!("the directory is unavailable"))? = Directory::from_entries(entries);
    match first_failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Makes `rosters` (and with it the policies beside them, see [`DocStore::adopt`]) keep every
/// pair the node adopts from now on in the home directory, as `menzil join` would: a restart
/// then starts from it, not from the older pair on disk (a removed steward would otherwise
/// renew from its stale disk pair again). Called after [`load_stores`], so that what was read
/// from disk is not written back. The writing runs on a thread of its own (it takes the network
/// lock, which the steward loop holds while it adopts what it has just signed); a pair that
/// cannot be written is a warning and stays adopted in memory. Only a Roster and a Policy of
/// one `seq` form a pair that can be kept: a Roster adopted alone waits for its Policy.
pub fn keep_adopted_documents(
    home: &Home,
    rosters: &RosterStore,
) -> Result<Arc<Worker<AdoptedDocs>>> {
    let keeper = {
        let home = home.clone();
        Worker::spawn(
            "menzil-docs-keep",
            |adopted: &AdoptedDocs| adopted.network_id,
            move |adopted: AdoptedDocs| {
                if let Err(error) = keep_adopted(&home, &adopted) {
                    tracing::warn!(network = %adopted.network_id, error = %format!("{error:#}"), "documents adopted over the network could not be kept on disk: a restart will start from the older pair");
                }
            },
        )?
    };
    let hook = Arc::clone(&keeper);
    rosters.set_on_adopted(move |adopted| hook.submit(adopted.clone()));
    Ok(keeper)
}

/// Writes what `adopted` holds as the pair on disk, if it is a pair and newer than the disk's.
/// The acceptance predicate has judged the documents once already (they are in the stores);
/// [`keep_documents`] judges them again against the disk (not the clock), and a pair that does not stand on
/// its signatures is never written.
fn keep_adopted(home: &Home, adopted: &AdoptedDocs) -> Result<()> {
    let (Some((roster, roster_base)), Some((policy, policy_base))) =
        (adopted.roster.clone(), adopted.policy.clone())
    else {
        return Ok(());
    };
    let docs = match (roster_base, policy_base) {
        (None, None) => menzil_admin::Documents::from_signed(roster, policy),
        (Some(roster_base), Some(policy_base)) => {
            menzil_admin::Documents::from_signed_with_base(roster, policy, roster_base, policy_base)
        }
        // A steward signed Roster beside an owner signed Policy (or the reverse): not a pair
        // that is kept as one.
        _ => return Ok(()),
    };
    // Documents of two `seq` are not a pair yet (the other half is on its way).
    let Ok(docs) = docs else { return Ok(()) };
    let docs = docs.into_verified().map_err(|e| anyhow!("{e}"))?;
    // Judged at the pair's own `issued` time: the stores took it under the clock of the moment
    // (the time rules were checked then), and a pair that ran out or was stamped ahead while
    // it waited in the queue is still the newest the node holds. Signatures, steward rules and
    // `seq` against the disk still count.
    let at = docs.roster_body().issued.max(docs.policy_body().issued);
    keep_documents(home, &docs, at, false)?;
    Ok(())
}

/// `menzil node`: starts everything and runs until interrupted.
pub async fn run(home: &Home) -> Result<()> {
    // Before anything that takes time (starting, then up to 60 s of waiting to attach): a signal
    // from here on takes the path below, not the default action, which would leave the agent
    // socket behind and close what the node carries with a FIN (the fourth red-team round, N3).
    let mut signals = crate::signals::Shutdown::catch().context("catching signals")?;
    let config = Config::load(home)?;
    let socket = agent_socket_path(home, &config);
    let running = start(home, &config, &socket).await?;
    eprintln!(
        "menzil node running; agent socket {}",
        running.socket.display()
    );
    let early = {
        let attach = async {
            match running.node.wait_attached(Duration::from_secs(60)).await {
                Some(_) => eprintln!("connected to the relay"),
                None => eprintln!(
                    "not connected to the relay after 60 s; still trying (RUST_LOG=menzil=debug shows why)"
                ),
            }
        };
        tokio::pin!(attach);
        tokio::select! {
            () = &mut attach => None,
            why = signals.wait() => Some(why),
        }
    };
    // Every signal that stops a process takes this path: dropping the node resets what it
    // carries (a target connection closed by the kernel after a SIGTERM would end with a FIN,
    // as if the peer had finished).
    let why = match early {
        Some(why) => why,
        None => signals.wait().await,
    }
    .context("waiting for a signal")?;
    eprintln!("stopping ({why})");
    // No new request from here on: the socket goes first, then each peer is told (CLOSE
    // `shutting_down`) and the relay connection is closed politely, so that they end the
    // streams now instead of after the dead peer timeout. Bounded: a stalled link is not waited
    // for.
    remove_if_unchanged(&running.socket, running.socket_identity);
    if !running.node.close_gracefully(STOP_GRACE).await {
        eprintln!(
            "menzil: could not say goodbye to every peer in time; they will notice by the dead peer timeout"
        );
    }
    // The last pair adopted over the network is on disk before the process goes (bounded: a
    // lock someone else holds is not waited for forever).
    let flushed = {
        let keeper = running.keeper.clone();
        tokio::task::spawn_blocking(move || keeper.flush(STOP_GRACE))
            .await
            .unwrap_or(false)
    };
    if !flushed {
        eprintln!("menzil: the documents adopted last may not have reached the disk");
    }
    drop(running);
    Ok(())
}

#[cfg(test)]
mod tests;
