//! The relay's static key and certificate over time (design note
//! `relay-key-and-invites-design.md` A5 and A6, slice A2): `menzil relay rotate-key`,
//! `renew-cert` and `forget`, and the `relay/previous.key` file the running relay answers IK
//! with for a window after a rotation.
//!
//! The relay's identity is the home's device identity (`identity.key` holds the Ed25519 seed and
//! the X25519 private key, `identity.cert` the certificate). A rotation makes a new X25519 key
//! under the same seed (K2), a renewal only a new certificate over the same keys (K1). Both
//! need the seed on this machine and refuse while a relay runs on the home.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use ciborium::Value;
use menzil_admin::NodeKeys;
use menzil_proto::{NodeCert, NodeId, check_definite_lengths};
use menzil_relay::PreviousKey;
use zeroize::Zeroizing;

use crate::home::{Home, parse_hex32};
use crate::local::load_identity;

/// One day in seconds.
const DAY: u64 = 24 * 60 * 60;

/// The longest window the previous key answers in, and the default.
pub const MAX_WINDOW_DAYS: u64 = 30;

/// The end of a certificate's life: 400 days from its `not_before` (protocol.md 2.2).
const CERT_LIFETIME_SECS: u64 = 400 * DAY;

/// The version of `previous.key`.
const PREVIOUS_VERSION: u64 = 1;

/// The most bytes of `previous.key` that are read: a certificate is about 200 bytes.
const MAX_PREVIOUS_BYTES: usize = 4096;

/// The relay warns about its certificate from this far before its `not_after`.
pub const CERT_WARN_BEFORE_SECS: u64 = 60 * DAY;

/// One write of a rotation, reported to the step hook after it happened (tests stop a rotation
/// between two writes to see what a crash would leave).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// `relay/previous.key` was written (or, with no window, removed).
    PreviousKey,
    /// `identity.cert` was written.
    IdentityCert,
    /// `identity.key` was written.
    IdentityKey,
}

/// `menzil relay rotate-key` options.
#[derive(Debug, Clone, Copy, Default)]
pub struct RotateOptions {
    /// How long the previous key answers, in days; `None` is [`MAX_WINDOW_DAYS`], 0 is none.
    pub window_days: Option<u64>,
    /// A serial the new one must beat (after a restored backup, the serial the nodes hold).
    pub serial: Option<u32>,
    /// Rotate although the previous key is still inside its window.
    pub force: bool,
}

/// What a rotation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    /// The serial of the certificate that was current.
    pub old_serial: u32,
    /// The serial of the new certificate.
    pub new_serial: u32,
    /// The window of the previous key in days (0: none was kept).
    pub window_days: u64,
    /// When the previous key stops answering, Unix seconds, if one was kept.
    pub retire_at: Option<u64>,
    /// The relay's NodeId.
    pub relay_id: NodeId,
    /// The new connection information, with `RELAY-HOST` for the name.
    pub connection_info: String,
}

/// What a renewal did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renewed {
    /// The serial of the certificate that was current.
    pub old_serial: u32,
    /// The serial of the new one.
    pub new_serial: u32,
    /// The end of the new certificate, Unix seconds.
    pub not_after: u64,
}

/// `relay/previous.key` read back.
pub struct PreviousFile {
    /// The previous certificate.
    pub cert: NodeCert,
    /// The previous X25519 private key.
    pub x25519_private: Zeroizing<[u8; 32]>,
    /// When it stops answering, Unix seconds.
    pub retire_at: u64,
}

impl PreviousFile {
    /// The relay's in memory form of the key.
    pub fn into_key(&self) -> PreviousKey {
        PreviousKey {
            node_cert: self.cert.clone(),
            x25519_private: *self.x25519_private,
            retire_at: self.retire_at,
        }
    }

    /// Whether the key may still answer at `now`.
    pub fn answers_at(&self, now: u64) -> bool {
        menzil_relay::previous_key_answers(&self.cert, self.retire_at, now)
    }
}

fn encode_previous(cert: &NodeCert, x25519_private: &[u8; 32], retire_at: u64) -> Vec<u8> {
    let value = Value::Map(vec![
        (
            Value::Text("v".into()),
            Value::Integer(PREVIOUS_VERSION.into()),
        ),
        (
            Value::Text("x25519_private".into()),
            Value::Bytes(x25519_private.to_vec()),
        ),
        (Value::Text("cert".into()), Value::Bytes(cert.encode())),
        (
            Value::Text("retire_at".into()),
            Value::Integer(retire_at.into()),
        ),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

fn decode_previous(bytes: &[u8]) -> Result<PreviousFile> {
    if bytes.len() > MAX_PREVIOUS_BYTES {
        bail!("larger than any file this relay writes");
    }
    check_definite_lengths(bytes).map_err(|e| anyhow!("{e}"))?;
    let value: Value = ciborium::from_reader(bytes).map_err(|e| anyhow!("{e}"))?;
    let Value::Map(entries) = value else {
        bail!("not a map");
    };
    let (mut version, mut private, mut cert, mut retire_at) = (None, None, None, None);
    for (key, value) in entries {
        match (key, value) {
            (Value::Text(k), Value::Integer(i)) if k == "v" && version.is_none() => {
                version = u64::try_from(i).ok()
            }
            (Value::Text(k), Value::Bytes(b)) if k == "x25519_private" && private.is_none() => {
                private = Some(Zeroizing::new(b))
            }
            (Value::Text(k), Value::Bytes(b)) if k == "cert" && cert.is_none() => cert = Some(b),
            (Value::Text(k), Value::Integer(i)) if k == "retire_at" && retire_at.is_none() => {
                retire_at = u64::try_from(i).ok()
            }
            _ => bail!("unknown, repeated or mistyped key"),
        }
    }
    if version != Some(PREVIOUS_VERSION) {
        bail!("unknown version");
    }
    let (Some(private), Some(cert), Some(retire_at)) = (private, cert, retire_at) else {
        bail!("a key is missing");
    };
    let private: [u8; 32] = private
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("x25519_private is not 32 bytes"))?;
    let cert = NodeCert::decode_strict(&cert).map_err(|e| anyhow!("{e}"))?;
    Ok(PreviousFile {
        cert,
        x25519_private: Zeroizing::new(private),
        retire_at,
    })
}

/// `relay/previous.key`, `None` when there is none. A damaged file is an error naming it.
pub fn load_previous(home: &Home) -> Result<Option<PreviousFile>> {
    let path = home.previous_key_path();
    let bytes = match fs::read(&path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    decode_previous(&bytes)
        .map(Some)
        .with_context(|| format!("{} is damaged", path.display()))
}

/// Overwrites the file with zeros, then deletes it.
fn wipe_and_delete(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        let zeros = vec![0u8; usize::try_from(meta.len()).unwrap_or(0)];
        if let Ok(mut file) = fs::OpenOptions::new().write(true).open(path) {
            use std::io::Write as _;
            let _ = file.write_all(&zeros);
            let _ = file.sync_all();
        }
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

/// N2: replaces a secret file atomically (the new content is renamed over it, so a crash never
/// leaves no file) and then overwrites the old content with zeros: before the rename the old
/// inode is kept under a second name (a hard link), which is wiped and deleted afterwards.
fn replace_secret_wiping(home: &Home, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut old_name = path.as_os_str().to_owned();
    old_name.push(".old");
    let old_name = std::path::PathBuf::from(old_name);
    wipe_and_delete(&old_name)?;
    let linked = fs::hard_link(path, &old_name).is_ok();
    home.write_secret(path, bytes)?;
    if linked {
        wipe_and_delete(&old_name)?;
    }
    Ok(())
}

/// Wipes and deletes `relay/previous.key` when its `retire_at` or its certificate's `not_after`
/// has passed. Returns the key while it can still answer, `None` otherwise (including when
/// there is none). A damaged file is left alone and is an error.
pub fn retire_previous_if_due(home: &Home, now: u64) -> Result<Option<PreviousFile>> {
    let Some(previous) = load_previous(home)? else {
        return Ok(None);
    };
    if previous.answers_at(now) {
        return Ok(Some(previous));
    }
    wipe_and_delete(&home.previous_key_path())?;
    Ok(None)
}

/// The identity of the home for a rotation: the keys, and the certificate if it still belongs to
/// them. A certificate that does not (an interrupted rotation) is `None`, so that the same
/// command can be run again to finish the job.
fn load_for_rotation(home: &Home) -> Result<(NodeKeys, Option<NodeCert>, Option<u32>)> {
    match load_identity(home) {
        Ok((keys, cert)) => {
            let serial = cert.decode().ok().map(|body| body.serial);
            Ok((keys, Some(cert), serial))
        }
        Err(error) => {
            // Only a certificate that does not match the key (or is unreadable) is tolerated;
            // a missing key is the usual "no identity" error.
            let key_path = home.identity_key_path();
            let secret = Zeroizing::new(fs::read(&key_path).with_context(|| {
                format!(
                    "reading {}: this machine has no relay identity (the seed must be here to rotate)",
                    key_path.display()
                )
            })?);
            let keys = NodeKeys::from_secret_bytes(&secret)
                .with_context(|| format!("{} is damaged", key_path.display()))?;
            tracing::warn!(error = %format!("{error:#}"), "the identity does not load whole; continuing from the key file alone");
            // The serial still counts: the certificate that does not fit the key may be the
            // one an interrupted rotation wrote, and nodes may already hold its serial. It is
            // read when its signature holds under this seed (a key mismatch is ignored).
            let serial = fs::read(home.identity_cert_path())
                .ok()
                .and_then(|bytes| NodeCert::decode_strict(&bytes).ok())
                .filter(|cert| cert.verify(&keys.signing_key().verifying_key()).is_ok())
                .and_then(|cert| cert.decode().ok())
                .filter(|body| body.node_id == keys.node_id())
                .map(|body| body.serial);
            Ok((keys, None, serial))
        }
    }
}

/// [`rotate_key`] with a hook called after each write.
pub fn rotate_key_with(
    home: &Home,
    options: &RotateOptions,
    now: u64,
    after_write: &mut dyn FnMut(Step) -> Result<()>,
) -> Result<Rotated> {
    let window_days = options.window_days.unwrap_or(MAX_WINDOW_DAYS);
    if window_days > MAX_WINDOW_DAYS {
        bail!("--window-days is at most {MAX_WINDOW_DAYS}");
    }
    let _running = home.lock_relay_running()?;
    let (keys, current, cert_serial) = load_for_rotation(home)?;
    // A previous key that is due is dropped first, so it is not "inside its window" below.
    let held = match retire_previous_if_due(home, now) {
        Ok(held) => held,
        Err(error) => {
            if options.force {
                tracing::warn!(error = %format!("{error:#}"), "the previous key file is unreadable: replaced (--force)");
                None
            } else {
                return Err(error.context("use --force to replace it"));
            }
        }
    };
    if let Some(held) = &held
        && !options.force
    {
        bail!(
            "the previous key is still inside its window (until Unix time {}): nodes dialing it would fall back to XX; wait, or pass --force",
            held.retire_at
        );
    }
    if cert_serial.is_none() && options.serial.is_none() {
        bail!(
            "no certificate of this identity can be read, so the serial the nodes hold is not known: pass --serial N (the highest serial your nodes hold)"
        );
    }
    let current_serial = cert_serial.unwrap_or(0);
    let held_serial = held
        .as_ref()
        .map(|held| held.cert.decode())
        .transpose()?
        .map_or(0, |body| body.serial);
    let new_serial = current_serial
        .max(held_serial)
        .max(options.serial.unwrap_or(0))
        .checked_add(1)
        .ok_or_else(|| anyhow!("the certificate serial cannot go up any more (u32 range)"))?;

    // The new X25519 key under the same Ed25519 seed.
    let mut secret = Zeroizing::new([0u8; NodeKeys::SECRET_LEN]);
    secret[..32].copy_from_slice(&keys.secret_bytes()[..32]);
    secret[32..].copy_from_slice(&NodeKeys::generate().x25519_private()[..]);
    let new_keys = NodeKeys::from_secret_bytes(&secret[..])?;
    let not_before = now.saturating_sub(DAY);
    let new_cert = new_keys.issue_cert(
        new_serial,
        not_before,
        not_before.saturating_add(CERT_LIFETIME_SECS),
    )?;

    // What the previous key will be: the key and certificate that are current now, if they
    // belong together. After an interrupted rotation they do not, and the previous key the
    // interrupted run wrote stays.
    let keep_previous = window_days > 0
        && current.as_ref().is_some_and(|cert| {
            cert.decode()
                .is_ok_and(|body| body.x25519_pub == keys.x25519_public())
        });
    let retire_at = now.saturating_add(window_days * DAY);

    eprintln!(
        "writing relay/previous.key, then identity.cert, then identity.key; if this is interrupted, run `menzil relay rotate-key --force --serial {new_serial}` again"
    );
    // Order matters: a crash after the first write leaves the old identity whole and a
    // previous key that nothing uses; after the second, a certificate the key does not match,
    // which `load_identity` refuses loudly (and this command can finish).
    if keep_previous {
        let old_private = keys.x25519_private();
        let cert = current
            .as_ref()
            .expect("keep_previous implies a certificate");
        replace_secret_wiping(
            home,
            &home.previous_key_path(),
            &encode_previous(cert, &old_private, retire_at),
        )?;
        after_write(Step::PreviousKey)?;
    } else if window_days == 0 {
        wipe_and_delete(&home.previous_key_path())?;
        after_write(Step::PreviousKey)?;
    }
    home.write_secret(&home.identity_cert_path(), &new_cert.encode())?;
    after_write(Step::IdentityCert)?;
    replace_secret_wiping(
        home,
        &home.identity_key_path(),
        &new_keys.secret_bytes()[..],
    )?;
    after_write(Step::IdentityKey)?;

    let body = new_cert.decode()?;
    let connection_info = format!(
        "menzil://RELAY-HOST:443{}?id={}&key={}",
        super::DEFAULT_PATH,
        body.node_id.to_hex(),
        body.x25519_pub.to_hex()
    );
    Ok(Rotated {
        old_serial: current_serial,
        new_serial,
        window_days: if keep_previous { window_days } else { 0 },
        retire_at: keep_previous.then_some(retire_at),
        relay_id: body.node_id,
        connection_info,
    })
}

/// `menzil relay rotate-key`: a new X25519 key under the same NodeId (design note A6). Refused
/// while a relay runs on the home, and while the previous key is inside its window without
/// `force`.
pub fn rotate_key(home: &Home, options: &RotateOptions, now: u64) -> Result<Rotated> {
    rotate_key_with(home, options, now, &mut |_| Ok(()))
}

/// `menzil relay renew-cert`: a new certificate over the same keys, serial + 1, a day back to 400
/// days. The previous key, if one is held, is not touched. Refused while a relay runs.
pub fn renew_cert(home: &Home, now: u64) -> Result<Renewed> {
    let _running = home.lock_relay_running()?;
    let (keys, current, cert_serial) = load_for_rotation(home)?;
    if current.is_none() {
        bail!(
            "the identity does not load whole (identity.cert and identity.key do not belong together, a rotation was interrupted): renewing would certify a key the serial {} may already have replaced; finish it with `menzil relay rotate-key --force --serial N` instead",
            cert_serial.map_or_else(|| "of the nodes".to_string(), |serial| serial.to_string())
        );
    }
    let old_serial = cert_serial.unwrap_or(0);
    let new_serial = old_serial
        .checked_add(1)
        .ok_or_else(|| anyhow!("the certificate serial cannot go up any more (u32 range)"))?;
    let not_before = now.saturating_sub(DAY);
    let not_after = not_before.saturating_add(CERT_LIFETIME_SECS);
    let cert = keys.issue_cert(new_serial, not_before, not_after)?;
    home.write_secret(&home.identity_cert_path(), &cert.encode())?;
    Ok(Renewed {
        old_serial,
        new_serial,
        not_after,
    })
}

/// `menzil relay forget <id>`: deletes one record of the known relays file of this home (the
/// relay a node used to dial; for tidying after a new relay identity, never needed for safety).
/// Refused while a node runs on the home. Returns whether a record was there.
pub fn forget_relay(home: &Home, relay_id: &str, now: u64) -> Result<bool> {
    let id = parse_hex32(relay_id.trim())
        .ok_or_else(|| anyhow!("{relay_id:?} is not a relay id (64 hex digits)"))?;
    let _node = home
        .lock_node()
        .context("refusing to edit the known relays while a node runs here")?;
    let file = crate::node_cmd::HomeRelayFile { home: home.clone() };
    let removed = menzil_node::forget_in_file(&file, &NodeId::from(id), now)
        .with_context(|| format!("editing {}", home.known_relays_path().display()))?;
    Ok(removed)
}

/// Loads the previous key into `relay` as the reload does: a key that is due is wiped and
/// deleted and the relay drops it; one that can answer is set (once) on the relay. A damaged
/// file is warned about and changes nothing.
pub fn sync_previous(relay: &menzil_relay::Relay, home: &Home, now: u64) {
    match retire_previous_if_due(home, now) {
        Ok(Some(previous)) => {
            if !relay.holds_previous() {
                tracing::info!(
                    retire_at = previous.retire_at,
                    "the relay answers its previous key until then"
                );
                relay.set_previous(Some(previous.into_key()));
            }
        }
        Ok(None) => {
            if relay.holds_previous() {
                tracing::info!("the previous relay key is retired and wiped");
                relay.set_previous(None);
            }
        }
        Err(error) => {
            tracing::warn!(error = %format!("{error:#}"), "the previous relay key cannot be read; it is not answered");
            relay.set_previous(None);
        }
    }
}

/// What `menzil relay run` says about its certificate: an error when it has expired, a warning
/// from 60 days before its end, nothing otherwise.
pub fn cert_standing(cert: &NodeCert, now: u64) -> Result<Option<String>> {
    let body = cert.decode()?;
    if body.not_after <= now {
        bail!(
            "the relay's certificate expired at Unix time {}; run `menzil relay renew-cert` (every node refuses it)",
            body.not_after
        );
    }
    let left = body.not_after - now;
    if left <= CERT_WARN_BEFORE_SECS {
        return Ok(Some(format!(
            "the relay's certificate ends in {} day(s) (Unix time {}); run `menzil relay renew-cert` while the relay is stopped",
            left.div_ceil(DAY),
            body.not_after
        )));
    }
    Ok(None)
}
