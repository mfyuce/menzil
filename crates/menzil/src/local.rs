//! The operations on a user's menzil directory: what `menzil init`, `network create`, `admit`,
//! `grant`, `join`, `renew`, `steward` and `status` do. No printing and no clock here: the caller passes the
//! time and prints what these return.
//!
//! A device has one identity ([`init`]). It may own networks ([`network_create`]), in which case
//! the owner key is kept beside the documents and [`admit`], [`grant`] and [`renew`] work on
//! them; every member, the owner included, keeps the current Roster and Policy of each network
//! it belongs to as one file, updated by [`join`] when an owner hands over a newer pair. Until
//! `menzil:docs` exists (TODO.md L4j) that hand over is a pasted token.
//!
//! A device may also hold a steward key for a network ([`steward_request`]): the owner lists
//! its public half ([`steward_add`]), and from then on [`admit`] and [`renew`] on that device
//! sign with it. Documents a steward signed are kept and passed on together with the owner
//! signed pair they were made from, and every document that comes in, from a file or a token,
//! goes through the acceptance predicate of `menzil_proto::trust` (protocol.md 2.3).

use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use menzil_admin::{Documents, NodeKeys, OwnerKey, StewardSecret};
use menzil_proto::trust::{Reason, Verdict, check_bundle};
use menzil_proto::{
    Grant, NetworkId, NodeCert, NodeId, NodeOrWildcard, Principal, PrincipalTarget, ServiceId,
    StewardKey,
};
use zeroize::Zeroizing;

use crate::home::{Home, parse_hex32};
use crate::text;
use crate::token::{
    decode_documents, decode_join_request, decode_steward_request, documents_from_bytes,
    documents_to_bytes, encode_documents, encode_join_request, encode_roster,
    encode_steward_request,
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
    // From the check to the last write: two `init`s at once would otherwise both pass the check
    // and leave a key and a certificate that do not belong together.
    let _lock = home.lock_init()?;
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

/// The documents this device holds for a network, checked to stand on the network's own key
/// or on a steward it lists ([`Documents::verify`]): a file that was edited or damaged is
/// refused, not trusted.
pub fn load_documents(home: &Home, network_id: &NetworkId) -> Result<Documents> {
    let path = home.documents_path(network_id);
    let bytes = fs::read(&path).with_context(|| {
        format!(
            "reading {}: this device holds no documents for {network_id}",
            path.display()
        )
    })?;
    let docs =
        documents_from_bytes(&bytes).with_context(|| format!("{} is damaged", path.display()))?;
    if docs.network_id() != *network_id {
        bail!("{} holds documents of another network", path.display());
    }
    docs.into_verified().with_context(|| {
        format!(
            "{} was not signed by the network's owner (or by a steward the owner listed)",
            path.display()
        )
    })
}

/// Keeps `docs` as this device's current documents for their network, readable by this user
/// only: the Policy says who may use what and names every device. A pair a steward signed is
/// kept with its base.
pub fn save_documents(home: &Home, docs: &Documents) -> Result<()> {
    home.write_secret(
        &home.documents_path(&docs.network_id()),
        &documents_to_bytes(docs),
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

/// The steward key of a network, if this device has one.
pub fn load_steward(home: &Home, network_id: &NetworkId) -> Result<StewardSecret> {
    let path = home.steward_key_path(network_id);
    let secret = Zeroizing::new(fs::read(&path).with_context(|| {
        format!(
            "this device is no steward of network {network_id} ({} is missing)",
            path.display()
        )
    })?);
    StewardSecret::from_secret_bytes(&secret)
        .with_context(|| format!("{} is damaged", path.display()))
}

/// What [`steward_request`] made.
#[derive(Debug, Clone)]
pub struct StewardRequest {
    /// The network the key is for.
    pub network_id: NetworkId,
    /// The public key.
    pub public: StewardKey,
    /// The request to give to the owner (`menzil1-steward:...`).
    pub token: String,
    /// False when the device had a key for the network already, which was left as it was.
    pub created: bool,
}

/// Makes this device's steward key for a network (protocol.md 7.3: the steward device
/// generates it and the owner only ever sees the public half), or finds the one it made
/// before, and returns the request that names the public half. A key that exists is never
/// replaced: the owner may have listed it already.
pub fn steward_request(home: &Home, network: Option<&str>) -> Result<StewardRequest> {
    let network_id = resolve_network(home, network)?;
    let _lock = home.lock_network(&network_id)?;
    let path = home.steward_key_path(&network_id);
    let (secret, created) = if path.exists() {
        (load_steward(home, &network_id)?, false)
    } else {
        let secret = StewardSecret::generate();
        home.write_secret(&path, &Zeroizing::new(secret.secret_bytes())[..])?;
        (secret, true)
    };
    Ok(StewardRequest {
        network_id,
        public: secret.public(),
        token: encode_steward_request(network_id, secret.public()),
        created,
    })
}

/// The longest a steward is listed for, in days (protocol.md 7.3).
pub const STEWARD_MAX_DAYS: u64 = 90;

/// What [`steward_add`] did.
#[derive(Debug, Clone)]
pub struct StewardAdded {
    /// The new pair.
    pub issued: Issued,
    /// The steward's public key.
    pub steward: StewardKey,
    /// When the delegation ends, Unix seconds.
    pub not_after: u64,
}

/// Lists the steward a request names (protocol.md 2.3), for `days` days from `now`, with the
/// rights `may` (`admit`, `renew`). Owner only; replaces any steward listed before.
pub fn steward_add(
    home: &Home,
    network: Option<&str>,
    request: &str,
    may: &[String],
    days: u64,
    now: u64,
) -> Result<StewardAdded> {
    let (network_id, steward) = decode_steward_request(request)?;
    if let Some(named) = network
        && resolve_network(home, Some(named))? != network_id
    {
        bail!("this steward request is for network {network_id}, not for the one named");
    }
    if days == 0 || days > STEWARD_MAX_DAYS {
        bail!("a steward is listed for 1 to {STEWARD_MAX_DAYS} days");
    }
    let _lock = home.lock_network(&network_id)?;
    let owner = load_owner(home, &network_id)?;
    let current = load_documents(home, &network_id)?;
    let not_after = now.saturating_add(days * DAY);
    let next = menzil_admin::delegate_steward(&owner, &current, steward, may, not_after, now)?;
    save_documents(home, &next)?;
    Ok(StewardAdded {
        issued: issued(&next, None),
        steward,
        not_after,
    })
}

/// Removes the steward from a network this device owns (protocol.md 7.3). The new documents
/// outrank everything the steward can sign.
pub fn steward_remove(home: &Home, network: Option<&str>, now: u64) -> Result<Issued> {
    let network_id = resolve_network(home, network)?;
    let _lock = home.lock_network(&network_id)?;
    let owner = load_owner(home, &network_id)?;
    let current = load_documents(home, &network_id)?;
    let next = menzil_admin::remove_steward(&owner, &current, now)?;
    save_documents(home, &next)?;
    Ok(issued(&next, None))
}

/// Who signs the next documents on this device: the owner key if there is one, else a steward
/// key, else nobody (and the error says what `admit` and `renew` need).
enum Signing {
    Owner(OwnerKey),
    Steward(StewardSecret),
}

fn signing_key(home: &Home, network_id: &NetworkId) -> Result<Signing> {
    if !home.owner_key_path(network_id).exists() && home.steward_key_path(network_id).exists() {
        return Ok(Signing::Steward(load_steward(home, network_id)?));
    }
    Ok(Signing::Owner(load_owner(home, network_id)?))
}

/// What [`admit`], [`grant`], [`renew`] and the steward commands hand back: the new pair's number and the token that
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
        token: encode_documents(docs),
    }
}

/// Admits the node a join request names to a network this device owns, or is a steward of
/// (protocol.md 7.1), under `name`, with `roles`. It can reach nothing until a [`grant`] says
/// what. A steward admits without roles: roles are grants, and granting is the owner's.
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
    let signing = signing_key(home, &network_id)?;
    let current = load_documents(home, &network_id)?;
    let cert = decode_join_request(join_request)?;
    let member = cert.decode()?.node_id;
    let next = match signing {
        Signing::Owner(owner) => menzil_admin::admit(&owner, &current, &cert, name, roles, now)?,
        Signing::Steward(steward) => {
            if !roles.is_empty() {
                bail!(
                    "this device is a steward of the network, and a steward admits members without roles: the owner grants roles"
                );
            }
            menzil_admin::steward_admit(&steward, &current, &cert, name, now)?
        }
    };
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

/// Re-issues the documents of a network this device owns, or is a steward of, with a fresh
/// lifetime, which a network needs at least every 14 days (protocol.md 7.3).
pub fn renew(home: &Home, network: Option<&str>, now: u64) -> Result<Issued> {
    let network_id = resolve_network(home, network)?;
    let _lock = home.lock_network(&network_id)?;
    let signing = signing_key(home, &network_id)?;
    let current = load_documents(home, &network_id)?;
    let next = match signing {
        Signing::Owner(owner) => menzil_admin::renew(&owner, &current, now)?,
        Signing::Steward(steward) => menzil_admin::steward_renew(&steward, &current, now)?,
    };
    save_documents(home, &next)?;
    Ok(issued(&next, None))
}

/// The token for the documents this device holds now, to hand to a member again.
pub fn token(home: &Home, network: Option<&str>) -> Result<String> {
    let docs = load_documents(home, &resolve_network(home, network)?)?;
    Ok(encode_documents(&docs))
}

/// The token for a relay: the Roster of the documents this device holds now, without the Policy
/// (threat-model.md: hidden from relays).
pub fn token_for_relay(home: &Home, network: Option<&str>) -> Result<String> {
    let docs = load_documents(home, &resolve_network(home, network)?)?;
    Ok(encode_roster(
        docs.roster(),
        docs.base().map(|(roster, _)| roster),
    ))
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

/// What a person is told when the acceptance predicate (`menzil_proto::trust`, protocol.md 2.3)
/// refuses documents.
pub(crate) fn refusal(reason: Reason) -> String {
    let text = match reason {
        Reason::Expired => "these documents have expired: ask the owner for new ones",
        Reason::BadSignature => "these documents were not signed by the network's owner",
        // Without a base there is no telling a steward's documents from a forger's: both are
        // "not the owner's, and nothing to show that a steward may have signed them".
        Reason::MissingBase => {
            "these documents were not signed by the network's owner, and they come without the owner signed documents that documents from a steward are made from"
        }
        Reason::NotYetValid => {
            "these documents were issued in the future by this device's clock: is the clock right?"
        }
        Reason::LifetimeTooLong => "these documents are valid for longer than 14 days",
        Reason::Malformed => "these documents do not decode",
        Reason::WrongNetwork => "these documents belong to different networks",
        Reason::TooManyStewards => "the Roster lists more than one steward",
        Reason::PairMismatch => "the Roster and the Policy are not a pair",
        Reason::PairSigner => "the Roster and the Policy were not signed by the same key",
        Reason::BadBase => "the owner signed documents these were made from do not belong to them",
        Reason::SeqOutOfSpan => {
            "the steward's sequence number is outside the range its base allows"
        }
        Reason::BaseOlderThanHeld => {
            "the steward made these from documents older than ones this device holds"
        }
        Reason::NoSteward => "the owner signed documents they were made from list no steward",
        Reason::BadStewardEntry => "the steward entry is not valid or not signed by the owner",
        Reason::StewardExpired => "the steward's time is up: ask the owner for new documents",
        Reason::ExpiresAfterNotAfter => "the steward signed documents that outlive its time",
        Reason::RightMissing => "the steward changed something its rights do not allow",
        Reason::FieldChanged => "the steward changed something a steward may not",
        Reason::BadAppend => "the steward admitted members it may not",
        Reason::BadCert => "a certificate the steward added does not verify",
        Reason::BadName => "a member the steward admitted has a name or role it may not",
        Reason::AppendedDropped => "the steward dropped members that it admitted earlier",
    };
    format!("{text} ({reason:?})")
}

/// Installs the documents in a membership token. Refused unless the acceptance predicate
/// (`menzil_proto::trust`, protocol.md 2.3) takes them: both signed by the network's own key,
/// or by the steward the owner listed with the owner signed documents they were made from;
/// belong together; have not expired; and then, here, name this device as a member of both: a
/// token meant for another device pasted here by mistake is an error, not a network this
/// device cannot use. Documents a steward signed come with their base, and are refused
/// without it. An older or equal pair than the one held is left alone (protocol.md 2.3: never
/// accept a lower `seq`).
pub fn join(home: &Home, token: &str, now: u64) -> Result<Joined> {
    let (_, cert) = load_identity(home)
        .context("a device needs an identity before it can join: run `menzil init`")?;
    let me = cert.decode()?.node_id;
    let docs = decode_documents(token)?;
    let network_id = docs.network_id();
    let nothing_held = menzil_proto::trust::HeldView {
        network_id,
        roster: None,
        policy_seq: None,
    };
    match check_bundle(&nothing_held, &docs.bundle(), now) {
        Verdict::Adopt(_) => {}
        Verdict::Held => bail!("these documents hold nothing"),
        Verdict::Reject(reason) => bail!("{}", refusal(reason)),
    }
    // What is kept is what the owner's own signature or the steward's base stands on.
    let docs = docs.into_verified().map_err(|e| anyhow!("{e}"))?;
    let policy = docs.policy_body();
    if !docs.is_member(&me) || !policy.members.iter().any(|m| m.node_id == me) {
        bail!("node {me} is not a member in these documents: they were made for another device");
    }
    // Whoever signed them, a name is typed in an address and printed on a terminal, and a role
    // in a grant: hold them to the rules an owner using `menzil admit` is held to. A name that
    // reads as the start of a node id would also take the address of the node it imitates.
    let mut lowercased: HashMap<String, &str> = HashMap::new();
    for member in &policy.members {
        menzil_admin::check_name(&member.name).with_context(|| {
            format!(
                "these documents name a member {:?} that this tool would not have issued",
                text::escaped(&member.name)
            )
        })?;
        // `admit` treats "Laptop" and "laptop" as one name (a person typing an address, and
        // `ssh`, which lowercases it, cannot tell them apart): so does `join`.
        if let Some(other) = lowercased.insert(member.name.to_lowercase(), &member.name) {
            bail!(
                "these documents name two members {:?} and {:?} that differ only in letter case, which this tool would not have issued",
                text::escaped(other),
                text::escaped(&member.name)
            );
        }
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
    keep_documents(home, &docs, now, true)?.ok_or_else(|| anyhow!("the documents were not kept"))
}

/// Keeps `docs` as this device's documents for their network if the acceptance predicate
/// (protocol.md 2.3) takes them against what is held on disk at `now`, under the network lock:
/// a lower or equal `seq` is left alone (never an older pair over a newer one), a steward may
/// not build on a base older than the held one, and a file that exists but cannot be read is
/// not written over. [`join`] after its own checks, and a running node for documents it
/// adopted over the network. The caller has verified `docs` (they stand on the network's key
/// or on a steward it lists); the device being a member is not asked here, since a pair that
/// removes this device is exactly the one that must reach the disk.
///
/// `create` says whether a network not held yet may be brought in (`join`: yes). A running node
/// keeping documents it adopted over the network passes `false`: only an existing pair is
/// updated, the network directory is not even made for the lock, and the answer is `None` (there
/// is no `leave`, so deleting the directory by hand is how a device leaves, and the next pair
/// the network's owner or steward issues must not bring it back).
pub fn keep_documents(
    home: &Home,
    docs: &Documents,
    now: u64,
    create: bool,
) -> Result<Option<Joined>> {
    let network_id = docs.network_id();
    let _lock = if create {
        home.lock_network(&network_id)?
    } else {
        match home.lock_network_if_held(&network_id)? {
            Some(lock) => lock,
            None => return Ok(None),
        }
    };
    match load_documents(home, &network_id) {
        Ok(held) => {
            // Against what is held: a lower or equal `seq` is left alone, a steward may not
            // build on a base older than the held one.
            match check_bundle(&held.held_view()?, &docs.bundle(), now) {
                Verdict::Adopt(adoption)
                    if adoption.roster.is_some() && adoption.policy.is_some() =>
                {
                    save_documents(home, docs)?;
                    Ok(Some(Joined::Updated {
                        network_id,
                        from_seq: held.seq(),
                        seq: docs.seq(),
                    }))
                }
                Verdict::Adopt(_) | Verdict::Held => Ok(Some(Joined::AlreadyCurrent {
                    network_id,
                    held_seq: held.seq(),
                })),
                Verdict::Reject(reason) => bail!("{}", refusal(reason)),
            }
        }
        Err(_) if !home.documents_path(&network_id).exists() => {
            if !create {
                return Ok(None);
            }
            save_documents(home, docs)?;
            Ok(Some(Joined::New {
                network_id,
                seq: docs.seq(),
            }))
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
    /// The steward the Roster lists, if any.
    pub steward: Option<StewardStatus>,
    /// Set when the documents could not be read.
    pub problem: Option<String>,
}

/// The steward a Roster lists, as `status` shows it.
#[derive(Debug, Clone)]
pub struct StewardStatus {
    /// Its public key.
    pub key: StewardKey,
    /// When its time is up, Unix seconds.
    pub not_after: u64,
    /// Whether this device holds the key.
    pub is_this_device: bool,
    /// Whether the documents this device holds were signed by the steward.
    pub signed_by_steward: bool,
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
                steward: docs
                    .roster_body()
                    .stewards
                    .first()
                    .and_then(|entry| entry.decode().ok())
                    .map(|entry| StewardStatus {
                        key: entry.steward_pub,
                        not_after: entry.not_after,
                        is_this_device: load_steward(home, &network_id)
                            .is_ok_and(|mine| mine.public() == entry.steward_pub),
                        signed_by_steward: docs.base().is_some(),
                    }),
                problem: None,
            },
            Err(error) => NetworkStatus {
                network_id,
                owned,
                seq: 0,
                expires: 0,
                members: vec![],
                grants: 0,
                steward: None,
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
            if let Some(steward) = &network.steward {
                let state = if steward.not_after <= now {
                    "ended"
                } else {
                    "until"
                };
                out.push_str(&format!(
                    "  steward {}{}, {state} {}{}\n",
                    steward.key,
                    if steward.is_this_device {
                        " (this device)"
                    } else {
                        ""
                    },
                    relative(steward.not_after, now),
                    if steward.signed_by_steward {
                        "; these documents are the steward's"
                    } else {
                        ""
                    }
                ));
            }
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
