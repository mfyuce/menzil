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
    EnsureError, LocalIdentity, Node, NodeConfig, NodeOpenError, OpenStreamError, PolicyStore,
    RosterStore, SessionConfig,
};
use menzil_proto::{NetworkId, NodeId, ServiceId, ServiceKind};
use menzil_stream::Stream;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;

use crate::agent::{self, Opener};
use crate::config::Config;
use crate::home::{FileLock, Home};
use crate::local::{load_documents, load_identity};
use crate::text;

/// How often a running node looks for newer documents on disk.
const RELOAD_EVERY: Duration = Duration::from_secs(15);

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

/// The longest path a Unix domain socket can have is about 108 bytes (`sun_path`, less on some
/// systems); beyond it binding or connecting fails with an error that does not say what to do.
const MAX_SOCKET_PATH_BYTES: usize = 100;

/// Refuses a socket path too long to use, with the remedy.
pub fn check_socket_path_length(path: &Path) -> Result<()> {
    let length = path.as_os_str().len();
    if length > MAX_SOCKET_PATH_BYTES {
        bail!(
            "the agent socket path is {length} bytes, more than a Unix socket path can be (about {MAX_SOCKET_PATH_BYTES}): set `agent_socket` in config.toml to a shorter path in a directory that only you can use, such as one under $XDG_RUNTIME_DIR: {}",
            path.display()
        );
    }
    Ok(())
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

/// The directory of the agent socket must belong to this user (or to root) and must not be
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
            "{} belongs to another user (uid {}): put `agent_socket` in a directory of your own",
            dir.display(),
            found.uid()
        );
    }
    let mode = found.mode();
    if mode & 0o002 != 0 && mode & 0o1000 == 0 {
        bail!(
            "{} can be written by other users (mode {:o}): a socket there could be swapped for a link; use a directory only you can write to, such as the default under $XDG_RUNTIME_DIR",
            dir.display(),
            mode & 0o7777
        );
    }
    Ok(())
}

/// Binds the agent socket. A socket file left by a node that died is removed; one with a node
/// behind it is an error; anything that is not a socket (a file the configuration pointed at by
/// mistake, a link) is an error and is left alone. The directory is made private (0700) when
/// this creates it, and the socket readable by its owner only. A directory that another user
/// can write to is refused (see [`check_private_directory`]). Whoever connects is checked
/// against this user's uid when the agent accepts (see [`crate::agent`]).
pub async fn bind_agent_socket(path: &Path) -> Result<UnixListener> {
    check_socket_path_length(path)?;
    let dir = socket_directory(path);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Created private in one step: a directory that appears with the default mode and is
        // chmodded afterwards can be swapped for a link in between.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let uid = agent::current_uid()
            .await
            .context("finding out which user this is")?;
        check_private_directory(dir, uid)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
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
                    "{} exists and is not a socket: not touching it (is `agent_socket` in config.toml pointing at the wrong file?)",
                    path.display()
                );
            }
            match UnixStream::connect(path).await {
                Ok(_) => bail!(
                    "another menzil node is already listening on {}",
                    path.display()
                ),
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
/// network that rejects everyone.
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
        rosters.set(docs.roster())?;
        policies.set(docs.policy())?;
    }
    Ok((policies, rosters, networks))
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

/// What a person is told about a failed open.
fn explain(error: &NodeOpenError) -> String {
    match error {
        NodeOpenError::Session(EnsureError::NotAttached) => {
            "this node is not connected to the relay (yet): check `relay` in config.toml and the network"
                .to_string()
        }
        NodeOpenError::Session(EnsureError::Timeout) => {
            "the other device did not answer: is it running `menzil node` and connected to the same relay?"
                .to_string()
        }
        NodeOpenError::Session(EnsureError::Refused) => {
            "the other device refused the session: are both of you members of the network, with current documents?"
                .to_string()
        }
        NodeOpenError::Open(OpenStreamError::Refused { code, msg }) => {
            format!("refused by the other end: {} ({msg})", code.name())
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
            .map_err(|error| explain(&error))
    }
}

/// A node that is running.
pub struct RunningNode {
    /// The node itself.
    pub node: Arc<Node>,
    /// Where the agent listens.
    pub socket: PathBuf,
    /// The names this node can resolve.
    pub directory: Arc<RwLock<Directory>>,
    tasks: Vec<JoinHandle<()>>,
    /// Held while this node runs: one node per identity.
    _instance: FileLock,
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
        let (home, directory) = (home.clone(), directory.clone());
        tokio::spawn(async move {
            let mut last: HashMap<NetworkId, u64> = HashMap::new();
            loop {
                tokio::time::sleep(RELOAD_EVERY).await;
                match reload(&home, &policies, &rosters, &directory, &mut last) {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(error = %format!("{error:#}"), "reloading the documents failed")
                    }
                }
            }
        })
    };
    Ok(RunningNode {
        node,
        socket: socket.to_path_buf(),
        directory,
        tasks: vec![agent_task, reload_task],
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
            rosters.set(docs.roster())?;
            policies.set(docs.policy())?;
            Ok(docs)
        });
        match loaded {
            Ok(docs) => {
                let seq = docs.seq();
                entries.extend(Directory::members_of(&network_id, &docs));
                if last.insert(network_id, seq) != Some(seq) {
                    tracing::info!(network = %network_id, seq, "holding newer documents");
                }
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
    let _ = fs::remove_file(&running.socket);
    drop(running);
    Ok(())
}

#[cfg(test)]
mod tests;
