//! `menzil invite create | list | revoke`, the invite book and the issuer's side of the
//! ADMIT_PENDING handler (protocol.md 7.2, design note `relay-key-and-invites-design.md` B3,
//! slice D3 B3). The device side (`menzil join <invite>`) is in [`crate::join`] (slice B4).
//!
//! # The invite book
//!
//! `<home>/networks/<id>/invites.cbor`, mode 0600 (it holds the secrets of live tokens), written
//! atomically ([`Home::write_secret`]) and only under the network lock that `menzil admit` holds.
//! Per invite: the signed Invite, its `secret`, `revoked` and `redeemed` (the NodeIds it admitted;
//! its length is the uses spent: the counter lives here and nowhere else, never in a signed
//! document and never at a relay). An entry is dropped 30 days after its `expires`.
//!
//! # Commands
//!
//! `create` draws a 16 byte invite id and a 32 byte secret, signs the Invite with the owner key
//! or with the steward key (a steward needs `admit` and a `not_after` ahead; the invite then
//! never outlives the steward: `expires` is cut to `not_after`, with a warning), records it and
//! returns `menzil1-invite:<base64url CBOR { invite, secret, relay }>` ([`crate::token`]), `relay`
//! being this device's own `relay =` of `config.toml`. Roles are always empty. Defaults: one use,
//! seven days; at most 30 days and 255 uses. `list` and `revoke` read and change the book; a
//! revoked invite admits nobody more (devices already admitted stay: revoke them as any member).
//!
//! The same operations are served by the node's agent socket (`invite-create`, `invite-list`,
//! `invite-revoke`, protocol.md 12) when a node runs: [`execute`] is the one implementation behind
//! both, the file lock makes them safe against each other and the node's admission handler.
//!
//! # The admission handler
//!
//! [`CliIssuer`] implements `menzil_node::admit_handler::AdmitIssuer` over the home directory: a
//! transaction ([`FileTxn`]) holds the network lock from reading the book and the documents to the
//! last save, so the counting rule of the node crate (book first, then documents) is atomic
//! against `menzil admit` and the other commands. The node crate holds no keys; every signature
//! is made here.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::VerifyingKey;
use menzil_admin::{Documents, StewardSecret};
use menzil_node::admit_handler::{
    AdmitIssuer, AdmitTxn, InviteRecord, IssueFault, NotIssuer, Standing,
};
use menzil_proto::{
    AdmitListenBody, ByteArray, Invite, InviteBody, InviteId, NetworkId, NodeCert, NodeId,
    PROTOCOL_VERSION, Tai64N, hash_invite_secret,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use zeroize::Zeroizing;

use crate::home::{FileLock, Home};
use crate::local::{self, Signing};
use crate::token::{InviteToken, encode_invite};

const DAY: u64 = 24 * 60 * 60;
/// The default life of an invite.
pub const DEFAULT_LIFE_SECS: u64 = 7 * DAY;
/// The longest life an invite may have.
pub const MAX_LIFE_SECS: u64 = 30 * DAY;
/// How long after its expiry an invite stays in the book (for `list`).
pub const KEEP_AFTER_EXPIRY_SECS: u64 = 30 * DAY;
/// The most invites a book holds.
pub const MAX_INVITES: usize = 1000;
/// The largest book file read.
const MAX_BOOK_BYTES: u64 = 8 * 1024 * 1024;
/// The most `invite` lines an `invite-list` answer carries (the agent client reads 32 lines).
const MAX_LIST_LINES: usize = 28;

/// One invite in the book.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookEntry {
    /// The signed invite as made.
    pub invite: Invite,
    /// The secret of the token.
    pub secret: ByteArray<32>,
    /// Revoked by `menzil invite revoke`.
    pub revoked: bool,
    /// The devices this invite admitted, in order.
    pub redeemed: Vec<NodeId>,
}

/// The file's content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteBook {
    /// Format version, 1.
    pub v: u16,
    /// The invites, oldest first.
    pub invites: Vec<BookEntry>,
}

impl InviteBook {
    /// The entry for `id`.
    pub fn get(&self, id: &InviteId) -> Option<&BookEntry> {
        self.invites.iter().find(|entry| {
            entry
                .invite
                .decode()
                .is_ok_and(|body| body.invite_id == *id)
        })
    }

    fn get_mut(&mut self, id: &InviteId) -> Option<&mut BookEntry> {
        self.invites.iter_mut().find(|entry| {
            entry
                .invite
                .decode()
                .is_ok_and(|body| body.invite_id == *id)
        })
    }

    /// Drops what expired more than [`KEEP_AFTER_EXPIRY_SECS`] ago.
    pub fn prune(&mut self, now: u64) {
        self.invites.retain(|entry| {
            entry
                .invite
                .decode()
                .is_ok_and(|body| body.expires.saturating_add(KEEP_AFTER_EXPIRY_SECS) > now)
        });
    }
}

/// Reads the book of a network (an empty one when there is no file). A damaged file is an error,
/// never silently replaced: it holds the counters.
pub fn load_book(home: &Home, network: &NetworkId) -> Result<InviteBook> {
    use std::io::Read;
    let path = home.invites_path(network);
    let file = match std::fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InviteBook {
                v: 1,
                invites: vec![],
            });
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BOOK_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > MAX_BOOK_BYTES {
        bail!("{} is larger than an invite book can be", path.display());
    }
    let book: InviteBook = ciborium::from_reader(bytes.as_slice())
        .with_context(|| format!("{} is damaged", path.display()))?;
    if book.v != 1 {
        bail!("{} is of a newer format ({})", path.display(), book.v);
    }
    Ok(book)
}

/// Writes the book (pruned first), atomically, mode 0600. The caller holds the network lock.
pub fn save_book(home: &Home, network: &NetworkId, book: &mut InviteBook, now: u64) -> Result<()> {
    book.prune(now);
    book.v = 1;
    let mut bytes = Vec::new();
    ciborium::into_writer(&*book, &mut bytes).context("encoding the invite book")?;
    home.write_secret(&home.invites_path(network), &bytes)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What `invite create` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSpec {
    /// The network (a hex id), or the only one this device knows.
    pub network: Option<String>,
    /// How many devices may redeem it (1 to 255).
    pub uses: u8,
    /// How long it lives, in seconds (1 to [`MAX_LIFE_SECS`]).
    pub life_secs: u64,
    /// A device name the invite fixes.
    pub name: Option<String>,
}

impl Default for CreateSpec {
    fn default() -> Self {
        Self {
            network: None,
            uses: 1,
            life_secs: DEFAULT_LIFE_SECS,
            name: None,
        }
    }
}

/// What `invite create` made.
#[derive(Debug, Clone)]
pub struct Created {
    /// The network.
    pub network_id: NetworkId,
    /// The invite's id.
    pub invite_id: InviteId,
    /// When it expires, Unix seconds.
    pub expires: u64,
    /// Its uses.
    pub uses: u8,
    /// The token to give to the device (a bearer secret).
    pub token: String,
    /// What the person should know (a cut expiry, a steward that ends inside the life).
    pub warnings: Vec<String>,
}

/// The `Steward` entry of `docs` for `steward` when it carries `admit` and is not expired at
/// `now`; its `not_after`.
fn steward_admit_until(docs: &Documents, steward: &StewardSecret, now: u64) -> Result<u64> {
    for entry in &docs.roster_body().stewards {
        let body = entry.decode()?;
        if body.steward_pub == steward.public() {
            if !body.may.iter().any(|right| right == "admit") {
                bail!("this device's steward key is listed without the `admit` right");
            }
            if body.not_after <= now {
                bail!("this device's steward delegation has ended");
            }
            return Ok(body.not_after);
        }
    }
    bail!("this device's steward key is not the one the network's Roster lists")
}

/// `menzil invite create`: see the module comment. `relay` is this device's `relay =` (the token
/// carries it so that the joining device knows where to redeem).
pub fn create(home: &Home, spec: &CreateSpec, relay: &str, now: u64) -> Result<Created> {
    if spec.uses == 0 {
        bail!("an invite needs at least one use");
    }
    if spec.life_secs == 0 || spec.life_secs > MAX_LIFE_SECS {
        bail!("an invite lives from a second to 30 days");
    }
    if let Some(name) = &spec.name {
        menzil_admin::check_name(name)?;
        // A fixed name is unique in the network: every device after the first would be refused
        // `name_taken`, so the invite would be a one use invite in effect (design B4).
        if spec.uses > 1 {
            bail!(
                "a fixed name (--name) can be given to one device only: use --uses 1, or leave the name to each device"
            );
        }
    }
    menzil_carrier::ConnectionInfo::parse(relay)
        .map_err(|e| anyhow!("the relay in config.toml is not usable in a token: {e}"))?;
    let network_id = local::resolve_network(home, spec.network.as_deref())?;
    let _lock = home.lock_network(&network_id)?;
    let signing = local::signing_key(home, &network_id)?;
    let docs = local::load_documents(home, &network_id)?;
    let mut warnings = Vec::new();
    let mut expires = now.saturating_add(spec.life_secs);
    if let Signing::Steward(steward) = &signing {
        let until = steward_admit_until(&docs, steward, now)?;
        if expires > until {
            expires = until;
            warnings.push(format!(
                "this device is a steward until {until} (Unix seconds): the invite ends then, shorter than asked, and dies with the delegation"
            ));
        }
    }
    if expires <= now {
        bail!("the invite would already be over");
    }
    let mut book = load_book(home, &network_id)?;
    book.prune(now);
    if book.invites.len() >= MAX_INVITES {
        bail!(
            "the invite book holds {MAX_INVITES} invites already: revoke or wait for some to expire"
        );
    }
    let mut invite_id = [0u8; 16];
    let mut secret = Zeroizing::new([0u8; 32]);
    let mut rng = rand::rng();
    rng.fill_bytes(&mut invite_id);
    rng.fill_bytes(&mut secret[..]);
    let body = InviteBody {
        v: PROTOCOL_VERSION,
        network_id,
        invite_id: InviteId::from(invite_id),
        secret_hash: hash_invite_secret(&secret[..]),
        roles: vec![],
        expires,
        uses: spec.uses,
        name: spec.name.clone(),
    };
    let signing_key = match &signing {
        Signing::Owner(owner) => owner.signing_key(),
        Signing::Steward(steward) => steward.signing_key(),
    };
    let invite = Invite::sign(signing_key, &body)?;
    book.invites.push(BookEntry {
        invite: invite.clone(),
        secret: ByteArray::from(*secret),
        revoked: false,
        redeemed: vec![],
    });
    save_book(home, &network_id, &mut book, now)?;
    let token = encode_invite(&InviteToken {
        invite,
        secret: ByteArray::from(*secret),
        relay: relay.to_string(),
    });
    Ok(Created {
        network_id,
        invite_id: body.invite_id,
        expires,
        uses: spec.uses,
        token,
        warnings,
    })
}

/// One line of `invite list`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    /// The invite's id.
    pub id: InviteId,
    /// Uses spent.
    pub used: usize,
    /// Uses it has.
    pub total: u8,
    /// Expiry, Unix seconds.
    pub expires: u64,
    /// Revoked.
    pub revoked: bool,
    /// The names of the devices it admitted (a short node id for one the Policy no longer lists).
    pub names: Vec<String>,
}

/// `menzil invite list`: the network and its invites, newest first.
pub fn list(home: &Home, network: Option<&str>) -> Result<(NetworkId, Vec<Listed>)> {
    let network_id = local::resolve_network(home, network)?;
    let book = load_book(home, &network_id)?;
    let policy_names: std::collections::HashMap<NodeId, String> =
        match local::load_documents(home, &network_id) {
            Ok(docs) => docs
                .policy_body()
                .members
                .iter()
                .map(|m| (m.node_id, m.name.clone()))
                .collect(),
            Err(_) => Default::default(),
        };
    let mut listed: Vec<Listed> = book
        .invites
        .iter()
        .filter_map(|entry| {
            let body = entry.invite.decode().ok()?;
            Some(Listed {
                id: body.invite_id,
                used: entry.redeemed.len(),
                total: body.uses,
                expires: body.expires,
                revoked: entry.revoked,
                names: entry
                    .redeemed
                    .iter()
                    .map(|node| {
                        policy_names
                            .get(node)
                            .cloned()
                            .unwrap_or_else(|| node.to_hex()[..8].to_string())
                    })
                    .collect(),
            })
        })
        .collect();
    listed.reverse();
    Ok((network_id, listed))
}

/// `menzil invite revoke <id>`: `prefix` is the start of the invite id in hex (at least 4
/// digits), unique in the book. Returns the id.
pub fn revoke(home: &Home, network: Option<&str>, prefix: &str, now: u64) -> Result<InviteId> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.len() < 4 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("an invite is named by the first hex digits of its id, at least four");
    }
    let network_id = local::resolve_network(home, network)?;
    let _lock = home.lock_network(&network_id)?;
    let mut book = load_book(home, &network_id)?;
    let matching: Vec<InviteId> = book
        .invites
        .iter()
        .filter_map(|entry| entry.invite.decode().ok())
        .map(|body| body.invite_id)
        .filter(|id| id.to_hex().starts_with(&prefix))
        .collect();
    let id = match matching.as_slice() {
        [one] => *one,
        [] => bail!("no invite of this network has an id starting with {prefix}"),
        _ => bail!("more than one invite starts with {prefix}: give more digits"),
    };
    if let Some(entry) = book.get_mut(&id) {
        entry.revoked = true;
    }
    save_book(home, &network_id, &mut book, now)?;
    Ok(id)
}

/// Reads `--expires`: seconds, or a number with `s`, `m`, `h` or `d`, from a second to 30 days.
pub fn parse_life(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (digits, unit) = match text.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&text[..i], c.to_ascii_lowercase()),
        _ => (text, 's'),
    };
    let factor = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => DAY,
        _ => {
            return Err(format!(
                "{text:?}: use seconds or a number with s, m, h or d"
            ));
        }
    };
    let secs = digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(factor))
        .ok_or_else(|| format!("{text:?} is not a length of time"))?;
    if secs == 0 || secs > MAX_LIFE_SECS {
        return Err("an invite lives from a second to 30 days".to_string());
    }
    Ok(secs)
}

// ---- the agent requests and their text --------------------------------------------------------

/// An invite operation: what `menzil invite` asks and what the agent socket carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteOp {
    /// `invite create`.
    Create(CreateSpec),
    /// `invite list`.
    List {
        /// The network.
        network: Option<String>,
    },
    /// `invite revoke`.
    Revoke {
        /// The network.
        network: Option<String>,
        /// The first hex digits of the invite id.
        id: String,
    },
}

fn field_or_dash(value: &Option<String>) -> &str {
    value.as_deref().unwrap_or("-")
}

fn dash_to_none(value: &str) -> Option<String> {
    (value != "-").then(|| value.to_string())
}

impl InviteOp {
    /// The request line (no newline): `invite-create network=<hex|-> uses=<n> expires=<secs>
    /// name=<name|->`, `invite-list network=<hex|->`, `invite-revoke network=<hex|-> id=<hex>`.
    pub fn to_request_line(&self) -> String {
        match self {
            Self::Create(spec) => format!(
                "invite-create network={} uses={} expires={} name={}",
                field_or_dash(&spec.network),
                spec.uses,
                spec.life_secs,
                field_or_dash(&spec.name)
            ),
            Self::List { network } => format!("invite-list network={}", field_or_dash(network)),
            Self::Revoke { network, id } => {
                format!("invite-revoke network={} id={id}", field_or_dash(network))
            }
        }
    }

    /// Reads a request line, strictly: the keys in order, no other, no empty value.
    pub fn parse_request_line(line: &str) -> Result<Self, String> {
        let mut words = line.split(' ');
        let verb = words.next().unwrap_or("");
        let mut fields = Vec::new();
        for word in words {
            let (key, value) = word
                .split_once('=')
                .filter(|(_, value)| !value.is_empty())
                .ok_or_else(|| format!("{word:?} is not key=value"))?;
            fields.push((key, value));
        }
        let take = |keys: &[&str]| -> Result<Vec<String>, String> {
            if fields.len() != keys.len() || fields.iter().zip(keys).any(|((k, _), want)| k != want)
            {
                return Err(format!("`{verb}` takes {}", keys.join(", ")));
            }
            Ok(fields.iter().map(|(_, v)| v.to_string()).collect())
        };
        match verb {
            "invite-create" => {
                let v = take(&["network", "uses", "expires", "name"])?;
                Ok(Self::Create(CreateSpec {
                    network: dash_to_none(&v[0]),
                    uses: v[1].parse().map_err(|_| "uses is 1 to 255".to_string())?,
                    life_secs: v[2]
                        .parse()
                        .map_err(|_| "expires is a number of seconds".to_string())?,
                    name: dash_to_none(&v[3]),
                }))
            }
            "invite-list" => {
                let v = take(&["network"])?;
                Ok(Self::List {
                    network: dash_to_none(&v[0]),
                })
            }
            "invite-revoke" => {
                let v = take(&["network", "id"])?;
                Ok(Self::Revoke {
                    network: dash_to_none(&v[0]),
                    id: v[1].clone(),
                })
            }
            _ => Err("unknown invite request".to_string()),
        }
    }
}

/// Runs `op` on `home` and returns the answer lines the agent sends after `ok` (the same lines
/// the local command renders):
///
/// ```text
/// create: token <menzil1-invite:...> / invite_id <hex> / network <hex> / expires <unix>
///         / uses <n> / warn <text> (repeated)
/// list:   network <hex> / invite <id prefix> <used> <total> <expires> <yes|no revoked> <names|->
///         (newest first, at most 28) / more <n>
/// revoke: revoked <id hex>
/// ```
pub fn execute(home: &Home, op: &InviteOp, now: u64) -> Result<Vec<String>> {
    match op {
        InviteOp::Create(spec) => {
            let config = crate::config::Config::load(home)?;
            let relay = config.relay.as_deref().ok_or_else(|| {
                anyhow!(
                    "no relay is configured: put `relay = \"menzil://...\"` in config.toml, the token carries it"
                )
            })?;
            let made = create(home, spec, relay, now)?;
            let mut lines = vec![
                format!("token {}", made.token),
                format!("invite_id {}", made.invite_id.to_hex()),
                format!("network {}", made.network_id.to_hex()),
                format!("expires {}", made.expires),
                format!("uses {}", made.uses),
            ];
            lines.extend(made.warnings.iter().map(|w| format!("warn {w}")));
            Ok(lines)
        }
        InviteOp::List { network } => {
            let (network_id, listed) = list(home, network.as_deref())?;
            let mut lines = vec![format!("network {}", network_id.to_hex())];
            for item in listed.iter().take(MAX_LIST_LINES) {
                lines.push(format!(
                    "invite {} {} {} {} {} {}",
                    &item.id.to_hex()[..8],
                    item.used,
                    item.total,
                    item.expires,
                    if item.revoked { "yes" } else { "no" },
                    if item.names.is_empty() {
                        "-".to_string()
                    } else {
                        item.names.join(",")
                    }
                ));
            }
            if listed.len() > MAX_LIST_LINES {
                lines.push(format!("more {}", listed.len() - MAX_LIST_LINES));
            }
            Ok(lines)
        }
        InviteOp::Revoke { network, id } => {
            let revoked = revoke(home, network.as_deref(), id, now)?;
            Ok(vec![format!("revoked {}", revoked.to_hex())])
        }
    }
}

/// The text `menzil invite ...` prints for the lines of [`execute`].
pub fn render(op: &InviteOp, lines: &[String], now: u64) -> String {
    let mut out = String::new();
    match op {
        InviteOp::Create(_) => {
            let value = |key: &str| {
                lines
                    .iter()
                    .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix(' ')))
                    .unwrap_or("?")
            };
            let (uses, expires) = (value("uses"), value("expires"));
            let left = expires.parse::<u64>().map_or("?".to_string(), |e| {
                format!("{} days", e.saturating_sub(now) / DAY)
            });
            out.push_str(&format!(
                "invite {} for network {}: {uses} use(s), expires in about {left}\n",
                &value("invite_id")[..value("invite_id").len().min(8)],
                value("network")
            ));
            for line in lines {
                if let Some(warn) = line.strip_prefix("warn ") {
                    out.push_str(&format!("warning: {warn}\n"));
                }
            }
            out.push_str("the token is a bearer secret: whoever holds it can join, once per use; give it to one person over a channel you trust:\n");
            out.push_str(value("token"));
            out.push('\n');
            out.push_str("(the device side, `menzil join <token>`, is not built yet)\n");
        }
        InviteOp::List { .. } => {
            out.push_str("ID        USED  EXPIRES(unix)  REVOKED  REDEEMED BY\n");
            let mut any = false;
            for line in lines {
                let Some(rest) = line.strip_prefix("invite ") else {
                    if let Some(more) = line.strip_prefix("more ") {
                        out.push_str(&format!("... and {more} older\n"));
                    }
                    continue;
                };
                let f: Vec<&str> = rest.splitn(6, ' ').collect();
                if let [id, used, total, expires, revoked, names] = f.as_slice() {
                    any = true;
                    let state = match expires.parse::<u64>() {
                        Ok(e) if e <= now => " (expired)",
                        _ => "",
                    };
                    out.push_str(&format!(
                        "{id:<9} {used}/{total:<4} {expires}{state}  {revoked:<7}  {names}\n"
                    ));
                }
            }
            if !any {
                out.push_str("(no invites)\n");
            }
        }
        InviteOp::Revoke { .. } => {
            let id = lines
                .iter()
                .find_map(|l| l.strip_prefix("revoked "))
                .unwrap_or("?");
            out.push_str(&format!(
                "invite {id} is revoked: it admits nobody more (devices admitted stay: revoke them as any member)\n"
            ));
        }
    }
    out
}

/// `menzil invite ...`: asks a running node over the agent socket, or does it here when none
/// answers. Returns what to print.
pub async fn run(home: &Home, op: InviteOp) -> Result<String> {
    let config = crate::config::Config::load(home)?;
    let socket = crate::node_cmd::agent_socket_path(home, &config);
    let now = unix_now();
    let lines = match crate::agent::request_invite(&socket, &op).await {
        Ok(lines) => lines,
        Err(crate::agent::AskError::Failed(error)) => return Err(error),
        Err(crate::agent::AskError::NoAgent) => {
            let (home, op) = (home.clone(), op.clone());
            tokio::task::spawn_blocking(move || execute(&home, &op, unix_now()))
                .await
                .context("the command did not finish")??
        }
    };
    Ok(render(&op, &lines, now))
}

// ---- the admission handler ----------------------------------------------------------------------

/// The issuer of this home for the node's admission handler.
pub struct CliIssuer {
    home: Home,
    /// Woken after the documents are saved, so that the node's reload (every 15 seconds) runs
    /// now: the Roster reaches the relay, which answers the devices, and the Policy is pushed.
    wake: Option<Arc<Notify>>,
}

impl CliIssuer {
    /// The issuer of `home`; `wake` is the node's reload trigger.
    pub fn new(home: Home, wake: Option<Arc<Notify>>) -> Self {
        Self { home, wake }
    }

    /// Whether this home holds an owner or steward key for any network it knows: only then a
    /// node needs the admission handler.
    pub fn is_needed(home: &Home) -> bool {
        home.networks().is_ok_and(|networks| {
            networks
                .iter()
                .any(|id| home.owner_key_path(id).exists() || home.steward_key_path(id).exists())
        })
    }
}

/// The key that signs for the network on this device, if it may issue invites: the owner key, or
/// a steward key the held documents list with `admit` and a `not_after` ahead.
fn issuing_key(home: &Home, network: &NetworkId, now: u64) -> Option<Signing> {
    match local::signing_key(home, network).ok()? {
        Signing::Owner(owner) => Some(Signing::Owner(owner)),
        Signing::Steward(steward) => {
            let docs = local::load_documents(home, network).ok()?;
            steward_admit_until(&docs, &steward, now)
                .ok()
                .map(|_| Signing::Steward(steward))
        }
    }
}

impl AdmitIssuer for CliIssuer {
    fn listen_proof(
        &self,
        network: &NetworkId,
        relay: NodeId,
        session: NodeId,
        hello_timestamp: Tai64N,
        now: u64,
    ) -> Option<AdmitListenBody> {
        let signing = issuing_key(&self.home, network, now)?;
        let key = match &signing {
            Signing::Owner(owner) => owner.signing_key(),
            Signing::Steward(steward) => steward.signing_key(),
        };
        Some(AdmitListenBody::sign(
            *network,
            key,
            relay,
            session,
            hello_timestamp,
        ))
    }

    fn begin(&self, network: &NetworkId, now: u64) -> Result<Box<dyn AdmitTxn>, NotIssuer> {
        let lock = self.home.lock_network(network).map_err(|e| NotIssuer {
            why: format!("{e:#}"),
            retry: true,
        })?;
        let gone = |why: String| NotIssuer { why, retry: false };
        let signing = issuing_key(&self.home, network, now)
            .ok_or_else(|| gone("this device holds no issuer key for the network".to_string()))?;
        let docs = local::load_documents(&self.home, network)
            .map_err(|e| gone(format!("the documents: {e:#}")))?;
        let book =
            load_book(&self.home, network).map_err(|e| gone(format!("the invite book: {e:#}")))?;
        Ok(Box::new(FileTxn {
            _lock: lock,
            home: self.home.clone(),
            network: *network,
            signing,
            docs,
            book,
            now,
            wake: self.wake.clone(),
        }))
    }
}

/// One network's book and documents under its lock.
pub struct FileTxn {
    _lock: FileLock,
    home: Home,
    network: NetworkId,
    signing: Signing,
    docs: Documents,
    book: InviteBook,
    now: u64,
    wake: Option<Arc<Notify>>,
}

impl AdmitTxn for FileTxn {
    fn invite(&self, id: &InviteId) -> Option<InviteRecord> {
        let entry = self.book.get(id)?;
        Some(InviteRecord {
            invite: entry.invite.clone(),
            secret: Zeroizing::new(entry.secret.0.to_vec()),
            revoked: entry.revoked,
            redeemed: entry.redeemed.clone(),
        })
    }

    fn signed_here(&self, invite: &Invite) -> bool {
        // The key this device signs with: the owner's (the network id) or its steward key. An
        // invite another key signed is another issuer's.
        let key: VerifyingKey = match &self.signing {
            Signing::Owner(owner) => owner.signing_key().verifying_key(),
            Signing::Steward(steward) => steward.signing_key().verifying_key(),
        };
        invite.verify(&key).is_ok()
    }

    fn standing(&self, node: &NodeId) -> Standing {
        if self
            .docs
            .roster_body()
            .revoked
            .iter()
            .any(|revoked| revoked.node_id == *node)
        {
            Standing::Revoked
        } else if self.docs.is_member(node) {
            Standing::Member
        } else {
            Standing::Absent
        }
    }

    fn names(&self) -> Vec<(NodeId, String)> {
        self.docs
            .policy_body()
            .members
            .iter()
            .map(|m| (m.node_id, m.name.clone()))
            .collect()
    }

    fn record_redeemed(&mut self, changes: &[(InviteId, Vec<NodeId>)]) -> Result<(), IssueFault> {
        for (id, redeemed) in changes {
            if let Some(entry) = self.book.get_mut(id) {
                entry.redeemed = redeemed.clone();
            }
        }
        save_book(&self.home, &self.network, &mut self.book, self.now)
            .map_err(|e| IssueFault(format!("{e:#}")))
    }

    fn admit(&mut self, devices: &[(NodeCert, String)]) -> Result<(), IssueFault> {
        let fault = |e: &dyn std::fmt::Display| IssueFault(e.to_string());
        let next = match &self.signing {
            Signing::Owner(owner) => menzil_admin::admit_many(owner, &self.docs, devices, self.now),
            Signing::Steward(steward) => {
                menzil_admin::steward_admit_many(steward, &self.docs, devices, self.now)
            }
        }
        .map_err(|e| fault(&e))?;
        local::save_documents(&self.home, &next).map_err(|e| IssueFault(format!("{e:#}")))?;
        self.docs = next;
        if let Some(wake) = &self.wake {
            wake.notify_one();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
