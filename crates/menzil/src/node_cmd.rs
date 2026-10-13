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
use crate::home::Home;
use crate::local::{load_documents, load_identity};

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
    /// From the documents in `home`.
    pub fn load(home: &Home) -> Result<Self> {
        let mut entries = Vec::new();
        for network_id in home.networks()? {
            let docs = load_documents(home, &network_id)?;
            for member in &docs.policy_body().members {
                entries.push(Entry {
                    network_id,
                    name: member.name.clone(),
                    node_id: member.node_id,
                });
            }
        }
        Ok(Self { entries })
    }

    /// From entries already at hand.
    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// The member `who` names: by name, or by the start of its NodeId in hex (8 digits or more).
    /// A name used in several networks, or a prefix several nodes share, is refused with a list
    /// rather than guessed.
    pub fn resolve(&self, who: &str) -> Result<&Entry, String> {
        let by_name: Vec<&Entry> = self.entries.iter().filter(|e| e.name == who).collect();
        let hits =
            if by_name.is_empty() && who.len() >= 8 && who.bytes().all(|b| b.is_ascii_hexdigit()) {
                let prefix = who.to_ascii_lowercase();
                self.entries
                    .iter()
                    .filter(|e| e.node_id.to_hex().starts_with(&prefix))
                    .collect()
            } else {
                by_name
            };
        match hits.as_slice() {
            [one] => Ok(one),
            [] => {
                let mut names: Vec<&str> = self.entries.iter().map(|e| e.name.as_str()).collect();
                names.sort();
                names.dedup();
                Err(if names.is_empty() {
                    "this node holds no network documents".to_string()
                } else {
                    format!("no member called {who:?} (members: {})", names.join(", "))
                })
            }
            several => Err(format!(
                "{who:?} is ambiguous: {}",
                several
                    .iter()
                    .map(|e| format!(
                        "{} in network {}",
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
            "the agent socket path is {length} bytes, more than a Unix socket path can be (about {MAX_SOCKET_PATH_BYTES}): set `agent_socket = \"/tmp/menzil.sock\"` (or another short path) in config.toml: {}",
            path.display()
        );
    }
    Ok(())
}

/// Binds the agent socket. A socket file left by a node that died is removed; one with a node
/// behind it is an error. The directory is made private (0700) when this creates it, and the
/// socket readable by its owner only.
pub async fn bind_agent_socket(path: &Path) -> Result<UnixListener> {
    check_socket_path_length(path)?;
    if let Some(dir) = path.parent().filter(|dir| !dir.exists()) {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
    }
    if path.exists() {
        match UnixStream::connect(path).await {
            Ok(_) => bail!(
                "another menzil node is already listening on {}",
                path.display()
            ),
            Err(_) => fs::remove_file(path)
                .with_context(|| format!("removing the stale socket {}", path.display()))?,
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
                env: std::env::vars().collect::<HashMap<_, _>>(),
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
    for network_id in home.networks()? {
        let docs = load_documents(home, &network_id)?;
        let seq = docs.seq();
        rosters.set(docs.roster())?;
        policies.set(docs.policy())?;
        if last.insert(network_id, seq) != Some(seq) {
            tracing::info!(network = %network_id, seq, "holding newer documents");
        }
    }
    *directory
        .write()
        .map_err(|_| anyhow!("the directory is unavailable"))? = Directory::load(home)?;
    Ok(())
}

/// `menzil node`: starts everything and runs until interrupted.
pub async fn run(home: &Home) -> Result<()> {
    let config = Config::load(home)?;
    let socket = agent_socket_path(home, &config);
    let running = start(home, &config, &socket).await?;
    eprintln!(
        "menzil node running; agent socket {}",
        running.socket.display()
    );
    match running.node.wait_attached(Duration::from_secs(60)).await {
        Some(_) => eprintln!("connected to the relay"),
        None => eprintln!(
            "not connected to the relay after 60 s; still trying (RUST_LOG=menzil=debug shows why)"
        ),
    }
    tokio::signal::ctrl_c()
        .await
        .context("waiting for ctrl-c")?;
    eprintln!("stopping");
    let _ = fs::remove_file(&running.socket);
    Ok(())
}

#[cfg(test)]
mod tests;
