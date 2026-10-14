//! The operations on a user's menzil directory: what `menzil init`, `network create`, `admit`,
//! `grant`, `join`, `renew` and `status` do. No printing and no clock here: the caller passes the
//! time and prints what these return.
//!
//! A device has one identity ([`init`]). It may own networks ([`network_create`]), in which case
//! the owner key is kept beside the documents and [`admit`], [`grant`] and [`renew`] work on
//! them; every member, the owner included, keeps the current Roster and Policy of each network
//! it belongs to as one file, updated by [`join`] when an owner hands over a newer pair. Until
//! `menzil:docs` exists (TODO.md L4j) that hand over is a pasted token.

use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::VerifyingKey;
use menzil_admin::{Documents, NodeKeys, OwnerKey};
use menzil_proto::{
    Grant, NetworkId, NodeCert, NodeId, NodeOrWildcard, Principal, PrincipalTarget, ServiceId,
};
use zeroize::Zeroizing;

use crate::home::{Home, parse_hex32};
use crate::text;
use crate::token::{
    decode_documents, decode_join_request, documents_from_bytes, documents_to_bytes,
    encode_documents, encode_join_request, encode_roster,
};

/// Seconds in a day.
const DAY: u64 = 24 * 60 * 60;

/// How long a NodeCert lives: protocol.md 2.2 allows at most 400 days.
const CERT_LIFETIME_SECS: u64 = 400 * DAY;

/// How far before now a new certificate is valid, so that a peer whose clock is a little behind
/// does not find it "not yet valid".
const CERT_BACKDATE_SECS: u64 = 300;

/// What [`init`] made.
#[derive(Debug, Clone)]
pub struct InitOutcome {
    /// This device's identity.
    pub node_id: NodeId,
    /// The join request to give to a network owner.
    pub join_request: String,
}

/// Makes this device's identity: the secret keys and a certificate for them. Refuses to touch an
/// existing identity (replacing one would orphan every network it is a member of). The
/// certificate is written first and the key last: the key's existence is what says "initialised",
/// so a failure in between can be retried.
pub fn init(home: &Home, now: u64) -> Result<InitOutcome> {
    let key_path = home.identity_key_path();
    if key_path.exists() {
        bail!(
            "{} exists: this device already has an identity, and nothing was changed",
            key_path.display()
        );
    }
    let keys = NodeKeys::generate();
    // The window is counted from its start: 400 days from `not_before`, the most protocol.md 2.2
    // allows, which is a few minutes short of 400 days from now.
    let not_before = now.saturating_sub(CERT_BACKDATE_SECS);
    let cert = keys.issue_cert(1, not_before, not_before.saturating_add(CERT_LIFETIME_SECS))?;
    home.write_public(&home.identity_cert_path(), &cert.encode())?;
    home.write_secret(&key_path, &Zeroizing::new(keys.secret_bytes())[..])?;
    Ok(InitOutcome {
        node_id: keys.node_id(),
        join_request: encode_join_request(&cert),
    })
}

/// This device's keys and certificate, checked to belong together.
pub fn load_identity(home: &Home) -> Result<(NodeKeys, NodeCert)> {
    let key_path = home.identity_key_path();
    let cert_path = home.identity_cert_path();
    let secret = Zeroizing::new(fs::read(&key_path).with_context(|| {
        format!(
            "reading {}: this device has no identity yet, run `menzil init`",
            key_path.display()
        )
    })?);
    let keys = NodeKeys::from_secret_bytes(&secret)
        .with_context(|| format!("{} is damaged", key_path.display()))?;
    let cert_bytes =
        fs::read(&cert_path).with_context(|| format!("reading {}", cert_path.display()))?;
    let cert = NodeCert::decode_strict(&cert_bytes)
        .with_context(|| format!("{} is damaged", cert_path.display()))?;
    let body = cert.decode()?;
    if body.node_id != keys.node_id() || body.x25519_pub != keys.x25519_public() {
        bail!(
            "{} and {} do not belong together",
            key_path.display(),
            cert_path.display()
        );
    }
    Ok((keys, cert))
}

/// This device's join request again, for giving to another owner.
pub fn join_request(home: &Home) -> Result<String> {
    Ok(encode_join_request(&load_identity(home)?.1))
}

fn network_key(network_id: &NetworkId) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(&<[u8; 32]>::from(*network_id))
        .map_err(|_| anyhow!("{network_id} is not a valid network id"))
}

/// Makes a new network owned by this device, with the device as its first member under
/// `device_name`. The owner key is saved before the documents: documents without their key would
/// be a network nobody can change.
pub fn network_create(home: &Home, device_name: &str, now: u64) -> Result<NetworkId> {
    let (_, cert) = load_identity(home)?;
    let owner = OwnerKey::generate();
    let docs = menzil_admin::create_network(&owner, &cert, device_name, now)?;
    let network_id = owner.network_id();
    home.write_secret(
        &home.owner_key_path(&network_id),
        &Zeroizing::new(owner.secret_bytes())[..],
    )?;
    save_documents(home, &docs)?;
    Ok(network_id)
}

/// The network a command is about: the one named, or the only one this device knows.
pub fn resolve_network(home: &Home, named: Option<&str>) -> Result<NetworkId> {
    if let Some(text) = named {
        let id = parse_hex32(text.trim())
            .ok_or_else(|| anyhow!("{text:?} is not a network id (64 hex digits)"))?;
        return Ok(NetworkId::from(id));
    }
    let mut known = home.networks()?;
    match known.len() {
        0 => {
            bail!("this device is in no network: `menzil network create` or `menzil join <token>`")
        }
        1 => Ok(known.remove(0)),
        _ => bail!(
            "this device is in several networks, name one with --network: {}",
            known
                .iter()
                .map(|id| id.to_hex())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The documents this device holds for a network, with both signatures checked against the
/// network's own key: a file that was edited or damaged is refused, not trusted.
pub fn load_documents(home: &Home, network_id: &NetworkId) -> Result<Documents> {
    let path = home.documents_path(network_id);
    let bytes = fs::read(&path).with_context(|| {
        format!(
            "reading {}: this device holds no documents for {network_id}",
            path.display()
        )
    })?;
    let (roster, policy) =
        documents_from_bytes(&bytes).with_context(|| format!("{} is damaged", path.display()))?;
    let docs = Documents::from_signed(roster, policy)?;
    if docs.network_id() != *network_id {
        bail!("{} holds documents of another network", path.display());
    }
    let key = network_key(network_id)?;
    docs.roster()
        .verify(&key)
        .and_then(|()| docs.policy().verify(&key))
        .with_context(|| format!("{} was not signed by the network's owner", path.display()))?;
    Ok(docs)
}

/// Keeps `docs` as this device's current documents for their network, readable by this user
/// only: the Policy says who may use what and names every device.
pub fn save_documents(home: &Home, docs: &Documents) -> Result<()> {
    home.write_secret(
        &home.documents_path(&docs.network_id()),
        &documents_to_bytes(docs.roster(), docs.policy()),
    )
}

/// The owner key of a network, if this device owns it.
pub fn load_owner(home: &Home, network_id: &NetworkId) -> Result<OwnerKey> {
    let path = home.owner_key_path(network_id);
    let secret = Zeroizing::new(fs::read(&path).with_context(|| {
        format!(
            "this device does not own network {network_id} ({} is missing)",
            path.display()
        )
    })?);
    let owner = OwnerKey::from_secret_bytes(&secret)
        .with_context(|| format!("{} is damaged", path.display()))?;
    if owner.network_id() != *network_id {
        bail!("{} is the key of another network", path.display());
    }
    Ok(owner)
}

/// What [`admit`], [`grant`] and [`renew`] hand back: the new pair's number and the token that
/// carries it to the members.
#[derive(Debug, Clone)]
pub struct Issued {
    /// The network.
    pub network_id: NetworkId,
    /// The sequence number of the new Roster and Policy.
    pub seq: u64,
    /// The node that was admitted, for [`admit`].
    pub member: Option<NodeId>,
    /// The membership token for the new pair.
    pub token: String,
}

fn issued(docs: &Documents, member: Option<NodeId>) -> Issued {
    Issued {
        network_id: docs.network_id(),
        seq: docs.seq(),
        member,
        token: encode_documents(docs.roster(), docs.policy()),
    }
}

/// Admits the node a join request names to a network this device owns (protocol.md 7.1) under
/// `name`, with `roles`. It can reach nothing until a [`grant`] says what.
pub fn admit(
    home: &Home,
    network: Option<&str>,
    join_request: &str,
    name: &str,
    roles: &[String],
    now: u64,
) -> Result<Issued> {
    let network_id = resolve_network(home, network)?;
    // Held from reading the documents to writing the next ones.
    let _lock = home.lock_network(&network_id)?;
    let owner = load_owner(home, &network_id)?;
    let current = load_documents(home, &network_id)?;
    let cert = decode_join_request(join_request)?;
    let member = cert.decode()?.node_id;
    let next = menzil_admin::admit(&owner, &current, &cert, name, roles, now)?;
    save_documents(home, &next)?;
    Ok(issued(&next, Some(member)))
}

/// A member named in the Policy: by name, or by the start of its NodeId in hex (at least 8
/// digits, unique).
pub fn resolve_member(docs: &Documents, who: &str) -> Result<NodeId> {
    let members = &docs.policy_body().members;
    if let Some(member) = members.iter().find(|m| m.name == who) {
        return Ok(member.node_id);
    }
    let prefix = who.to_ascii_lowercase();
    if prefix.len() >= 8 && prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut hits = members
            .iter()
            .filter(|m| m.node_id.to_hex().starts_with(&prefix));
        if let (Some(hit), None) = (hits.next(), hits.next()) {
            return Ok(hit.node_id);
        }
    }
    bail!(
        "no member called {who:?} (members: {})",
        members
            .iter()
            .map(|m| m.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Lets `from` use `services` on `to` (protocol.md 2.3). `from` is a member's name, or
/// `role:<name>` for everyone holding a role; `to` is a member's name, or `*` for every node. A
/// grant may expire at a Unix time.
pub fn grant(
    home: &Home,
    network: Option<&str>,
    from: &str,
    to: &str,
    services: &[ServiceId],
    expires: Option<u64>,
    now: u64,
) -> Result<Issued> {
    let network_id = resolve_network(home, network)?;
    let _lock = home.lock_network(&network_id)?;
    let owner = load_owner(home, &network_id)?;
    let current = load_documents(home, &network_id)?;
    let from = match from.strip_prefix("role:") {
        Some(role) => PrincipalTarget::Role(role.to_string()),
        None => PrincipalTarget::Node(resolve_member(&current, from)?),
    };
    let to_node = if to == "*" {
        NodeOrWildcard::Any
    } else {
        NodeOrWildcard::Node(resolve_member(&current, to)?)
    };
    let grant = Grant {
        from: Principal {
            network_id,
            target: from,
        },
        to_node,
        services: services.to_vec(),
        expires,
    };
    let next = menzil_admin::grant(&owner, &current, grant, now)?;
    save_documents(home, &next)?;
    Ok(issued(&next, None))
}

/// Re-issues the documents of a network this device owns with a fresh lifetime, which a network
/// needs at least every 14 days (protocol.md 7.3).
pub fn renew(home: &Home, network: Option<&str>, now: u64) -> Result<Issued> {
    let network_id = resolve_network(home, network)?;
    let _lock = home.lock_network(&network_id)?;
    let owner = load_owner(home, &network_id)?;
    let next = menzil_admin::renew(&owner, &load_documents(home, &network_id)?, now)?;
    save_documents(home, &next)?;
    Ok(issued(&next, None))
}

/// The token for the documents this device holds now, to hand to a member again.
pub fn token(home: &Home, network: Option<&str>) -> Result<String> {
    let docs = load_documents(home, &resolve_network(home, network)?)?;
    Ok(encode_documents(docs.roster(), docs.policy()))
}

/// The token for a relay: the Roster of the documents this device holds now, without the Policy
/// (threat-model.md: hidden from relays).
pub fn token_for_relay(home: &Home, network: Option<&str>) -> Result<String> {
    let docs = load_documents(home, &resolve_network(home, network)?)?;
    Ok(encode_roster(docs.roster()))
}

/// What [`join`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Joined {
    /// A network this device did not know.
    New {
        /// The network.
        network_id: NetworkId,
        /// The sequence number of the documents.
        seq: u64,
    },
    /// Newer documents for a network it knew.
    Updated {
        /// The network.
        network_id: NetworkId,
        /// The sequence number before.
        from_seq: u64,
        /// The sequence number now.
        seq: u64,
    },
    /// The device holds this pair or a newer one already.
    AlreadyCurrent {
        /// The network.
        network_id: NetworkId,
        /// The sequence number it holds.
        held_seq: u64,
    },
}

/// Installs the documents in a membership token. Refused unless both were signed by the
/// network's own key, belong together, have not expired, and name this device as a member of
/// both: a token meant for another device pasted here by mistake is an error, not a network this
/// device cannot use. An older or equal pair than the one held is left alone (protocol.md 2.3:
/// never accept a lower `seq`).
pub fn join(home: &Home, token: &str, now: u64) -> Result<Joined> {
    let (_, cert) = load_identity(home)
        .context("a device needs an identity before it can join: run `menzil init`")?;
    let me = cert.decode()?.node_id;
    let (roster, policy) = decode_documents(token)?;
    let docs = Documents::from_signed(roster, policy)?;
    let network_id = docs.network_id();
    let key = network_key(&network_id)?;
    docs.roster()
        .verify(&key)
        .and_then(|()| docs.policy().verify(&key))
        .context("these documents were not signed by the network's owner")?;
    let (roster, policy) = (docs.roster_body(), docs.policy_body());
    if roster.expires <= now || policy.expires <= now {
        bail!("these documents have expired: ask the owner for new ones");
    }
    if !docs.is_member(&me) || !policy.members.iter().any(|m| m.node_id == me) {
        bail!("node {me} is not a member in these documents: they were made for another device");
    }
    // Whoever signed them, a name is typed in an address and printed on a terminal, and a role
    // in a grant: hold them to the rules an owner using `menzil admit` is held to. A name that
    // reads as the start of a node id would also take the address of the node it imitates.
    for member in &policy.members {
        menzil_admin::check_name(&member.name).with_context(|| {
            format!(
                "these documents name a member {:?} that this tool would not have issued",
                text::escaped(&member.name)
            )
        })?;
        for role in &member.roles {
            menzil_admin::check_role(role).with_context(|| {
                format!(
                    "these documents give {:?} a role {:?} that this tool would not have issued",
                    text::escaped(&member.name),
                    text::escaped(role)
                )
            })?;
        }
    }
    let _lock = home.lock_network(&network_id)?;
    match load_documents(home, &network_id) {
        Ok(held) if held.seq() >= docs.seq() => Ok(Joined::AlreadyCurrent {
            network_id,
            held_seq: held.seq(),
        }),
        Ok(held) => {
            save_documents(home, &docs)?;
            Ok(Joined::Updated {
                network_id,
                from_seq: held.seq(),
                seq: docs.seq(),
            })
        }
        Err(_) if !home.documents_path(&network_id).exists() => {
            save_documents(home, &docs)?;
            Ok(Joined::New {
                network_id,
                seq: docs.seq(),
            })
        }
        // Held documents exist but are damaged: do not write over evidence of that silently.
        Err(error) => Err(error.context("the documents held for this network cannot be read")),
    }
}

/// One member as `status` shows it.
#[derive(Debug, Clone)]
pub struct MemberStatus {
    /// The name in the Policy.
    pub name: String,
    /// The node.
    pub node_id: NodeId,
    /// Roles held.
    pub roles: Vec<String>,
    /// Whether this is the device itself.
    pub is_self: bool,
}

/// One network as `status` shows it.
#[derive(Debug, Clone)]
pub struct NetworkStatus {
    /// The network.
    pub network_id: NetworkId,
    /// Whether this device holds the owner key.
    pub owned: bool,
    /// Sequence number of the documents held.
    pub seq: u64,
    /// When they expire, Unix seconds.
    pub expires: u64,
    /// The members.
    pub members: Vec<MemberStatus>,
    /// How many grants the Policy holds.
    pub grants: usize,
    /// Set when the documents could not be read.
    pub problem: Option<String>,
}

/// What `status` shows.
#[derive(Debug, Clone)]
pub struct Status {
    /// This device's node id, if it has an identity.
    pub node_id: Option<NodeId>,
    /// When its certificate expires.
    pub cert_expires: Option<u64>,
    /// The networks it holds documents for.
    pub networks: Vec<NetworkStatus>,
}

/// Reads the state of the directory. A network whose documents cannot be read is listed with the
/// problem instead of failing the whole report.
pub fn status(home: &Home) -> Result<Status> {
    let identity = load_identity(home).ok();
    let me = identity.as_ref().map(|(keys, _)| keys.node_id());
    let cert_expires = identity
        .as_ref()
        .and_then(|(_, cert)| cert.decode().ok())
        .map(|body| body.not_after);
    let mut networks = Vec::new();
    for network_id in home.networks()? {
        let owned = load_owner(home, &network_id).is_ok();
        networks.push(match load_documents(home, &network_id) {
            Ok(docs) => NetworkStatus {
                network_id,
                owned,
                seq: docs.seq(),
                expires: docs.roster_body().expires.min(docs.policy_body().expires),
                members: docs
                    .policy_body()
                    .members
                    .iter()
                    .map(|member| MemberStatus {
                        name: member.name.clone(),
                        node_id: member.node_id,
                        roles: member.roles.clone(),
                        is_self: Some(member.node_id) == me,
                    })
                    .collect(),
                grants: docs.policy_body().grants.len(),
                problem: None,
            },
            Err(error) => NetworkStatus {
                network_id,
                owned,
                seq: 0,
                expires: 0,
                members: vec![],
                grants: 0,
                problem: Some(format!("{error:#}")),
            },
        });
    }
    Ok(Status {
        node_id: me,
        cert_expires,
        networks,
    })
}

/// "in 13 days", "in 5 hours", "3 days ago": how far `at` is from `now`.
pub fn relative(at: u64, now: u64) -> String {
    let (distance, future) = if at >= now {
        (at - now, true)
    } else {
        (now - at, false)
    };
    let text = if distance >= DAY {
        let days = distance / DAY;
        format!("{days} day{}", if days == 1 { "" } else { "s" })
    } else if distance >= 3600 {
        let hours = distance / 3600;
        format!("{hours} hour{}", if hours == 1 { "" } else { "s" })
    } else {
        let minutes = distance / 60;
        format!("{minutes} minute{}", if minutes == 1 { "" } else { "s" })
    };
    if future {
        format!("in {text}")
    } else {
        format!("{text} ago")
    }
}

impl Status {
    /// The report as text, with times relative to `now`.
    pub fn render(&self, now: u64) -> String {
        let mut out = String::new();
        match (&self.node_id, self.cert_expires) {
            (Some(id), Some(expires)) => out.push_str(&format!(
                "this device: {id}\n  certificate {} {}\n",
                if expires <= now { "EXPIRED" } else { "expires" },
                relative(expires, now)
            )),
            (Some(id), None) => out.push_str(&format!("this device: {id}\n")),
            _ => out.push_str("this device has no identity yet: run `menzil init`\n"),
        }
        if self.networks.is_empty() {
            out.push_str("no networks\n");
        }
        for network in &self.networks {
            out.push_str(&format!(
                "network {}{}\n",
                network.network_id,
                if network.owned {
                    " (owned by this device)"
                } else {
                    ""
                }
            ));
            if let Some(problem) = &network.problem {
                out.push_str(&format!("  cannot be read: {}\n", text::escaped(problem)));
                continue;
            }
            let state = if network.expires <= now {
                "EXPIRED"
            } else {
                "expires"
            };
            out.push_str(&format!(
                "  documents #{}, {state} {}, {} grant{}\n",
                network.seq,
                relative(network.expires, now),
                network.grants,
                if network.grants == 1 { "" } else { "s" }
            ));
            for member in &network.members {
                // Names and roles were signed by the owner, whose tool would not have issued
                // anything but plain words; a hand made Policy could carry a terminal escape.
                out.push_str(&format!(
                    "  {}{}  {}{}\n",
                    text::escaped(&member.name),
                    if member.is_self { " (this device)" } else { "" },
                    member.node_id,
                    if member.roles.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "  roles: {}",
                            member
                                .roles
                                .iter()
                                .map(|role| text::escaped(role))
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    }
                ));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests;
