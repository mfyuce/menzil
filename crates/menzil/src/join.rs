//! `menzil join <invite-token>`: the device side of invite redemption (protocol.md 7.2, design
//! note `relay-key-and-invites-design.md` B2 steps 2 and 6 and B5, slice D3 B4).
//!
//! # The flow
//!
//! 1. [`prepare`] reads the token (`menzil1-invite:`), and refuses before any network use an
//!    invite that has expired, carries roles (version 1: none), whose secret does not match its
//!    `secret_hash` (a damaged token) or whose network id is not a key. It picks the device's
//!    name (the one the invite fixes, else `--name`, else the host name), checks it with
//!    `check_name`, and builds the ADMIT_REQUEST with its tag (`compute_admit_tag`).
//! 2. [`redeem`] opens a one shot L3 session to the token's relay ([`Session::connect_redeem`]: a
//!    HELLO that claims no network, no ATTACH), sends the request as its first transport record
//!    and waits for ADMIT_RESULT. `{ pending }` keeps waiting on the session (the issuer is not
//!    reachable yet); when the session ends it asks again with a fresh one after 30 seconds,
//!    doubling to 5 minutes, until `--wait` or the invite's expiry. `{ refused }` and the relay's
//!    ERROR end it with a message per code.
//! 3. [`judge`] judges the Roster of the answer with `check_bundle` (a Roster alone, nothing
//!    held, the invite's network), and requires that the device itself is listed in it, not
//!    revoked, with a `min_serial` not above its certificate's serial.
//! 4. The Roster is written to `<home>/networks/<id>/roster-only.bin` ([`write_roster_only`],
//!    atomically, 0600, under the network lock); `relay =` goes into a `config.toml` that has
//!    none ([`ensure_relay`]); the relay's certificate was stored in `known-relays.cbor` by the
//!    handshake itself (the same file, lock and rules as a node's).
//!
//! # What a device cannot check
//!
//! The invite carries no signer field. A device can verify an invite signed by the owner key
//! (the network id is that key), but one that does not verify may be signed by a steward, whose
//! key only the Roster names, and the device holds no Roster. So the signature is checked
//! ([`Signature::Owner`]) and a failure is not a refusal ([`Signature::NotOwner`]): the relay and
//! the issuer check it against the Roster and refuse with `bad_invite`, which this command shows.
//!
//! # The Roster only state
//!
//! The node loads `roster-only.bin` at start ([`load_roster_only`]) and claims the network; the
//! issuer's push (protocol.md 5.5) brings the Policy over a docs only session; when the pair is
//! written to `documents.bin` the Roster only file is removed
//! (`local::save_documents`). A file that does not decode, does not verify, is for another
//! network, is expired, or does not list this device in good standing is ignored with a warning
//! and never grants anything.

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, anyhow};
use ed25519_dalek::VerifyingKey;
use menzil_carrier::DialConfig;
use menzil_node::{KnownRelays, LocalIdentity, Session, SessionConfig, roster_standing};
use menzil_proto::trust::{Bundle, HeldView, Verdict, check_bundle};
use menzil_proto::{
    AdmitRequestBody, AdmitResultBody, ErrorCode, InviteBody, NetworkId, NodeCert, NodeId, Record,
    Roster, RosterBody, compute_admit_tag, hash_invite_secret,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::Config;
use crate::home::Home;
use crate::local;
use crate::node_cmd::{HomeRelayFile, text_environment};
use crate::token::{InviteToken, decode_invite};

/// How long `menzil join` waits for an answer by default.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(10 * 60);
/// The first pause before a fresh session after one that ended without an answer.
pub const RETRY_FIRST: Duration = Duration::from_secs(30);
/// The longest pause between two sessions.
pub const RETRY_MAX: Duration = Duration::from_secs(5 * 60);

/// Why a join did not complete.
#[derive(Debug, Error)]
pub enum JoinError {
    /// The token, the name or this device's state is not usable; nothing was sent.
    #[error("{0}")]
    Invalid(String),
    /// The relay or the issuer refused the request (`code` is the registry code).
    #[error("{message}")]
    Refused {
        /// The refusal.
        code: ErrorCode,
        /// What to tell the person.
        message: String,
    },
    /// The relay cannot be trusted or reached for good (identity, certificate, first connect).
    #[error("{0}")]
    Relay(String),
    /// The Roster the relay answered with is not acceptable for this device.
    #[error("{0}")]
    BadRoster(String),
    /// No answer within the wait.
    #[error("{0}")]
    TimedOut(String),
    /// Anything else (files, locks).
    #[error("{0:#}")]
    Other(#[from] anyhow::Error),
}

/// What the person is told for a refusal code.
pub fn refusal_message(code: ErrorCode, name: &str) -> String {
    match code {
        ErrorCode::BadInvite => "the invite is not valid: it is used up, revoked, expired, or not \
             known to the network (or its token is damaged); ask for a new invite"
            .to_string(),
        ErrorCode::BadTag => "the invite's secret did not match what the issuer holds: the token \
             is damaged or is not the one the issuer made; ask for a new invite"
            .to_string(),
        ErrorCode::BadCert => "this device's certificate was refused (it must be valid now and \
             last at most 400 days): `menzil cert renew`, then try again"
            .to_string(),
        ErrorCode::Revoked => "this device is revoked in the network: the network's owner must \
             admit a new identity (`menzil init --new-identity`)"
            .to_string(),
        ErrorCode::NameTaken => {
            format!("the name `{name}` is taken in the network: choose another with --name")
        }
        ErrorCode::RateLimited => "the relay or the issuer is handling too many requests; try \
             again in a few minutes"
            .to_string(),
        other => format!(
            "the invite was refused ({} , code {})",
            other.name(),
            u16::from(other)
        ),
    }
}

/// How far the invite's signature could be checked on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signature {
    /// It verifies under the network id, the owner's key.
    Owner,
    /// It does not verify under the owner's key; a steward may have signed it (the key is in a
    /// Roster this device does not hold), so the relay and the issuer decide.
    NotOwner,
}

/// A token read and checked, with the request it makes.
#[derive(Debug)]
pub struct Prepared {
    /// The decoded token.
    pub token: InviteToken,
    /// The invite's body.
    pub body: InviteBody,
    /// The device name the request carries.
    pub name: String,
    /// The request, tag included.
    pub request: AdmitRequestBody,
    /// This device's certificate (the one the HELLO presents).
    pub cert: NodeCert,
    /// How far the signature could be checked.
    pub signature: Signature,
}

/// The device name to use when none is fixed or given: the host name, made into a word
/// `check_name` accepts, or `None`.
pub fn default_name() -> Option<String> {
    let raw = fs::read_to_string("/etc/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())?;
    let host = raw.trim().split('.').next().unwrap_or("").to_lowercase();
    let cleaned: String = host
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '-' })
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    menzil_admin::check_name(&cleaned).ok().map(|()| cleaned)
}

/// Reads and checks `token_text` for the device of `home`, without any network use.
pub fn prepare(
    home: &Home,
    token_text: &str,
    name: Option<&str>,
    now: u64,
) -> Result<Prepared, JoinError> {
    let token = decode_invite(token_text).map_err(|e| JoinError::Invalid(e.to_string()))?;
    let body = token
        .invite
        .decode()
        .map_err(|_| JoinError::Invalid("the invite in the token is damaged".to_string()))?;
    if body.expires <= now {
        return Err(JoinError::Invalid(
            "this invite has expired; ask for a new one".to_string(),
        ));
    }
    if body.check_roles_empty().is_err() {
        return Err(JoinError::Invalid(
            "this invite carries roles, which version 1 does not allow; ask for a new one"
                .to_string(),
        ));
    }
    if hash_invite_secret(token.secret.as_ref()) != body.secret_hash {
        return Err(JoinError::Invalid(
            "the token is damaged: its secret does not match the invite".to_string(),
        ));
    }
    let owner = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.network_id)).map_err(|_| {
        JoinError::Invalid("the invite's network id is not a key; the token is damaged".to_string())
    })?;
    let signature = match token.invite.verify(&owner) {
        Ok(()) => Signature::Owner,
        Err(_) => Signature::NotOwner,
    };
    menzil_carrier::ConnectionInfo::parse(&token.relay)
        .map_err(|e| JoinError::Invalid(format!("the relay in the token is not usable: {e}")))?;

    let chosen = match (&body.name, name) {
        (Some(fixed), Some(given)) if fixed != given => {
            return Err(JoinError::Invalid(format!(
                "this invite fixes the device name `{fixed}`; --name {given} does not match it"
            )));
        }
        (Some(fixed), _) => fixed.clone(),
        (None, Some(given)) => given.to_string(),
        (None, None) => default_name().ok_or_else(|| {
            JoinError::Invalid(
                "this device's host name is not usable as a name here: choose one with --name"
                    .to_string(),
            )
        })?,
    };
    menzil_admin::check_name(&chosen)
        .map_err(|e| JoinError::Invalid(format!("the device name: {e}")))?;

    let (_, cert) = local::load_identity(home)
        .context("this device has no identity: run `menzil init` first")?;
    let network_id = body.network_id;
    if home.documents_path(&network_id).exists() {
        return Err(JoinError::Invalid(format!(
            "this device is in network {network_id} already"
        )));
    }
    let tag = compute_admit_tag(token.secret.as_ref(), body.invite_id, &cert, &chosen);
    let request = AdmitRequestBody {
        invite: token.invite.clone(),
        node_cert: cert.clone(),
        name: chosen.clone(),
        tag,
    };
    Ok(Prepared {
        token,
        body,
        name: chosen,
        request,
        cert,
        signature,
    })
}

/// The Roster this device was admitted with, as `roster-only.bin` holds it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosterOnly {
    /// The Roster that lists this device.
    pub roster: Roster,
    /// The owner signed base of a steward signed Roster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_roster: Option<Roster>,
}

/// Judges the Roster of an ADMIT_RESULT for the device `cert` and the invite of `network_id`:
/// `check_bundle` with the Roster alone and nothing held (so another network, a bad signature, an
/// expired or malformed Roster are refused), then the device itself must be listed, not
/// revoked, with a `min_serial` not above its certificate's serial.
pub fn judge(
    network_id: NetworkId,
    cert: &NodeCert,
    answer: RosterOnly,
    now: u64,
) -> Result<RosterOnly, JoinError> {
    let bundle = Bundle {
        roster: Some(answer.roster.clone()),
        base_roster: answer.base_roster.clone(),
        ..Bundle::default()
    };
    let held = HeldView {
        network_id,
        roster: None,
        policy_seq: None,
    };
    let adoption = match check_bundle(&held, &bundle, now) {
        Verdict::Adopt(adoption) => adoption,
        Verdict::Held => {
            return Err(JoinError::BadRoster(
                "the Roster in the answer is not usable".to_string(),
            ));
        }
        Verdict::Reject(reason) => {
            return Err(JoinError::BadRoster(format!(
                "the Roster in the answer was refused ({reason:?}): it is not a Roster of this \
                 network, or it does not verify"
            )));
        }
    };
    let Some(body) = adoption.roster else {
        return Err(JoinError::BadRoster(
            "the answer holds no Roster".to_string(),
        ));
    };
    let body: RosterBody = body;
    let me = cert
        .decode()
        .map_err(|e| JoinError::Other(anyhow!("this device's certificate: {e}")))?;
    match roster_standing(&body, &me.node_id) {
        Ok(min_serial) if me.serial >= min_serial => Ok(answer),
        Ok(min_serial) => Err(JoinError::BadRoster(format!(
            "the Roster requires a certificate of serial {min_serial} or above, this device's is {}",
            me.serial
        ))),
        Err(ErrorCode::Revoked) => Err(JoinError::BadRoster(
            "the Roster in the answer lists this device as revoked".to_string(),
        )),
        Err(_) => Err(JoinError::BadRoster(
            "the Roster in the answer does not list this device".to_string(),
        )),
    }
}

/// Writes `roster-only.bin` of `network_id` (atomically, 0600, under the network lock).
pub fn write_roster_only(
    home: &Home,
    network_id: &NetworkId,
    state: &RosterOnly,
) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    ciborium::into_writer(state, &mut bytes).context("encoding the Roster only state")?;
    let _lock = home.lock_network(network_id)?;
    home.write_secret(&home.roster_only_path(network_id), &bytes)
}

/// What a start of the node takes from the Roster only files: for each network with one, the
/// Roster, when it is good (it decodes, verifies for that network now, and lists `me` unrevoked
/// with a `min_serial` not above `serial`). A file that is not is ignored with a warning; it
/// never grants anything.
pub fn load_roster_only(
    home: &Home,
    me: &NodeId,
    serial: u32,
    now: u64,
) -> anyhow::Result<Vec<(NetworkId, RosterOnly)>> {
    let mut out = Vec::new();
    for network_id in home.roster_only_networks()? {
        let path = home.roster_only_path(&network_id);
        let state: RosterOnly = match fs::read(&path)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| ciborium::from_reader(bytes.as_slice()).map_err(anyhow::Error::from))
        {
            Ok(state) => state,
            Err(error) => {
                warn(&path, &format!("it cannot be read: {error:#}"));
                continue;
            }
        };
        let cert_for_me = |roster: &RosterBody| {
            roster_standing(roster, me)
                .map_err(|code| format!("it does not list this device in good standing ({code:?})"))
                .and_then(|min| {
                    if serial >= min {
                        Ok(())
                    } else {
                        Err("it requires a newer certificate than this device's".to_string())
                    }
                })
        };
        let bundle = Bundle {
            roster: Some(state.roster.clone()),
            base_roster: state.base_roster.clone(),
            ..Bundle::default()
        };
        let held = HeldView {
            network_id,
            roster: None,
            policy_seq: None,
        };
        match check_bundle(&held, &bundle, now) {
            Verdict::Adopt(adoption) => match adoption.roster {
                Some(body) => match cert_for_me(&body) {
                    Ok(()) => out.push((network_id, state)),
                    Err(why) => warn(&path, &why),
                },
                None => warn(&path, "it holds no Roster"),
            },
            Verdict::Held => warn(&path, "it is not usable"),
            Verdict::Reject(reason) => warn(&path, &format!("it was refused ({reason:?})")),
        }
    }
    Ok(out)
}

fn warn(path: &std::path::Path, why: &str) {
    tracing::warn!(file = %path.display(), "ignoring the Roster only file: {why}");
    eprintln!("warning: ignoring {}: {why}", path.display());
}

/// Removes the Roster only file of `network_id` (the documents have replaced it).
pub fn remove_roster_only(home: &Home, network_id: &NetworkId) {
    match fs::remove_file(home.roster_only_path(network_id)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            tracing::warn!(network = %network_id, %error, "could not remove roster-only.bin; it is ignored beside documents.bin");
        }
    }
}

/// What [`ensure_relay`] did with `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayConfig {
    /// `relay =` was written (there was none).
    Written,
    /// The configuration names this very relay already.
    Already,
    /// The configuration names another relay: the line to add or change by hand.
    Differs {
        /// What `config.toml` has.
        configured: String,
    },
}

/// Puts `relay = "<relay>"` into `config.toml` when it has no `relay` (the line goes first: a
/// top level key must precede the tables). A configuration that names a relay is never changed.
pub fn ensure_relay(home: &Home, relay: &str) -> anyhow::Result<RelayConfig> {
    let _lock = home.lock_config()?;
    let existing = match fs::read_to_string(home.config_path()) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).context("reading config.toml"),
    };
    let config = Config::parse(&existing).context("config.toml")?;
    match config.relay {
        Some(configured) if configured == relay => Ok(RelayConfig::Already),
        Some(configured) => Ok(RelayConfig::Differs { configured }),
        None => {
            let line = toml::Value::String(relay.to_string());
            let text = format!("relay = {line}\n{existing}");
            home.write_config(text.as_bytes())?;
            Ok(RelayConfig::Written)
        }
    }
}

/// What a completed join did.
#[derive(Debug)]
pub struct Joined {
    /// The network.
    pub network_id: NetworkId,
    /// The device's name in it.
    pub name: String,
    /// The `seq` of the Roster that lists the device.
    pub roster_seq: u64,
    /// What happened to `config.toml`.
    pub relay_config: RelayConfig,
    /// The relay of the token.
    pub relay: String,
}

/// The pacing of [`redeem`].
#[derive(Debug, Clone)]
pub struct JoinOptions {
    /// The device name to ask for (`--name`).
    pub name: Option<String>,
    /// How long to wait for the answer at most (`--wait`); the invite's expiry also ends it.
    pub wait: Duration,
    /// The pause before the second session; doubled for each further one.
    pub retry_first: Duration,
    /// The longest pause.
    pub retry_max: Duration,
}

impl Default for JoinOptions {
    fn default() -> Self {
        Self {
            name: None,
            wait: DEFAULT_WAIT,
            retry_first: RETRY_FIRST,
            retry_max: RETRY_MAX,
        }
    }
}

enum Answer {
    Roster(RosterOnly),
    /// The session ended without an answer; ask again.
    Again(String),
}

/// `menzil join <invite-token>`: see the module comment. `progress` receives the lines meant for
/// the person while it waits.
pub async fn redeem(
    home: &Home,
    token_text: &str,
    options: &JoinOptions,
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<Joined, JoinError> {
    let now = unix_now();
    // Refused while a node runs on this home (it would not know about the Roster), and held for
    // the whole join so that none starts in between.
    let _instance = home.lock_node().map_err(|e| {
        JoinError::Invalid(format!(
            "{e:#}; stop the node first, `menzil join` changes the files it uses"
        ))
    })?;
    let prepared = prepare(home, token_text, options.name.as_deref(), now)?;
    let network_id = prepared.body.network_id;
    let config = Config::load(home).map_err(JoinError::Other)?;
    let (keys, cert) = local::load_identity(home).map_err(JoinError::Other)?;
    let session_config = SessionConfig {
        dial: DialConfig {
            connection_info: menzil_carrier::ConnectionInfo::parse(&prepared.token.relay)
                .map_err(|e| JoinError::Invalid(e.to_string()))?,
            proxy_override: config.proxy_override(),
        },
        identity: LocalIdentity {
            node_cert: cert,
            x25519_private: *keys.x25519_private(),
        }
        .into(),
        networks: vec![],
        caps: vec![],
        e2e_protos: vec![0x01],
        known_relays: Arc::new(KnownRelays::open(
            Box::new(HomeRelayFile { home: home.clone() }),
            now,
        )),
    };
    let env = text_environment(std::env::vars_os());

    let started = Instant::now();
    let invite_left = Duration::from_secs(prepared.body.expires.saturating_sub(now));
    let deadline = started + options.wait.min(invite_left);
    let mut pause = options.retry_first;
    let mut connected_once = false;
    let answer = loop {
        let outcome = one_session(
            &session_config,
            &env,
            &prepared,
            deadline,
            &mut connected_once,
            progress,
        )
        .await?;
        match outcome {
            Answer::Roster(answer) => break answer,
            Answer::Again(why) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(JoinError::TimedOut(timeout_message(&why)));
                }
                progress(&format!("{why}; asking again in {} s", pause.as_secs()));
                tokio::time::sleep(pause.min(left)).await;
                pause = (pause * 2).min(options.retry_max);
                if Instant::now() >= deadline {
                    return Err(JoinError::TimedOut(timeout_message(&why)));
                }
            }
        }
    };

    let judged = judge(network_id, &prepared.cert, answer, unix_now())?;
    let roster_seq = judged
        .roster
        .decode()
        .map(|body| body.seq)
        .map_err(|e| JoinError::BadRoster(e.to_string()))?;
    write_roster_only(home, &network_id, &judged).map_err(JoinError::Other)?;
    let relay_config = ensure_relay(home, &prepared.token.relay).map_err(JoinError::Other)?;
    Ok(Joined {
        network_id,
        name: prepared.name,
        roster_seq,
        relay_config,
        relay: prepared.token.relay,
    })
}

fn timeout_message(why: &str) -> String {
    format!(
        "no answer within the wait ({why}): the issuer is unreachable or slow; the invite is \
         still good until it expires, run `menzil join` again"
    )
}

/// One redeem session: connect, send the request, wait for the answer until `deadline`.
async fn one_session(
    config: &SessionConfig,
    env: &HashMap<String, String>,
    prepared: &Prepared,
    deadline: Instant,
    connected_once: &mut bool,
    progress: &mut (dyn FnMut(&str) + Send),
) -> Result<Answer, JoinError> {
    use menzil_node::NodeError;
    let connecting = Session::connect_redeem(config, env);
    let left = deadline.saturating_duration_since(Instant::now());
    let mut session = match tokio::time::timeout(left, connecting).await {
        Err(_) => return Err(JoinError::TimedOut(timeout_message("connecting"))),
        Ok(Ok(session)) => session,
        Ok(Err(error)) => {
            let transient = matches!(error, NodeError::Carrier(_)) && *connected_once;
            return if transient {
                Ok(Answer::Again(format!(
                    "the relay is not reachable ({error})"
                )))
            } else {
                Err(JoinError::Relay(format!(
                    "cannot redeem through the relay in the token: {error}"
                )))
            };
        }
    };
    *connected_once = true;
    if let Err(error) = session
        .send(Record::AdmitRequest(prepared.request.clone()))
        .await
    {
        return Ok(Answer::Again(format!("the request was not sent ({error})")));
    }
    let mut waiting_said = false;
    let result = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let record = match tokio::time::timeout(left, session.recv()).await {
            Err(_) => {
                break Err(JoinError::TimedOut(timeout_message(
                    "waiting for the issuer",
                )));
            }
            Ok(Ok(record)) => record,
            // The session ended (the relay's cap on a held request, a lost link): ask again.
            Ok(Err(error)) => break Ok(Answer::Again(format!("the session ended ({error})"))),
        };
        match record {
            Record::AdmitResult(AdmitResultBody::Admitted {
                roster,
                base_roster,
            }) => {
                break Ok(Answer::Roster(RosterOnly {
                    roster,
                    base_roster,
                }));
            }
            Record::AdmitResult(AdmitResultBody::Pending) => {
                if !waiting_said {
                    progress(
                        "the issuer is not reachable yet: the request is held at the relay; waiting",
                    );
                    waiting_said = true;
                }
            }
            Record::AdmitResult(AdmitResultBody::Refused(code)) => {
                let code = ErrorCode::from(code);
                break Err(JoinError::Refused {
                    code,
                    message: refusal_message(code, &prepared.name),
                });
            }
            Record::Error(body) if body.code == ErrorCode::RateLimited => {
                break Ok(Answer::Again(
                    "the relay is busy (rate_limited)".to_string(),
                ));
            }
            Record::Error(body) => {
                break Err(JoinError::Refused {
                    code: body.code,
                    message: refusal_message(body.code, &prepared.name),
                });
            }
            _ => {}
        }
    };
    session.close().await;
    result
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests;
