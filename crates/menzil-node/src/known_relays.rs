//! What this node remembers of the relays it has dialed: the highest relay certificate it has
//! verified for each relay `NodeId` (protocol.md 4.1; design note `relay-key-and-invites-design.md`
//! A3 and A4, slice A1).
//!
//! A relay is pinned by its `NodeId` only (it is in no Policy), so the one thing that stops a
//! stolen, older relay static key from being answered as the relay again is this memory: a node
//! that saw serial 2 refuses serial 1. The record is the certificate itself, verbatim, so serial,
//! key and window are read from a signed value and re-verified on load, never trusted from the
//! file's own say so.
//!
//! The memory is per relay `NodeId`, in process and (when a [`RelayFile`] is given) on disk. The
//! disk side belongs to the caller, which owns the home directory and its locks: this crate
//! holds only the format, the merge rule and the serial rule. Writers (the running node, later
//! `menzil join`) merge by the higher serial under the file's lock, so no writer lowers a record.
//!
//! The file is strict CBOR, `{ v: 1, relays: [ { relay_id: bytes32, cert: bstr, seen: u64 } ] }`.
//! A corrupt file is set aside (`known-relays.cbor.corrupt-<unix>`) and the node starts with an
//! empty memory (fail open: the `NodeId` anchor still holds, the cost is the rollback window
//! until the next contact with the real relay); a single bad record is dropped with a warning
//! and the others stay.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::sync::{Mutex, PoisonError};

use ciborium::Value;
use ed25519_dalek::VerifyingKey;
use menzil_proto::{NodeCert, NodeCertBody, NodeId, X25519PublicKey, check_definite_lengths};

use crate::error::NodeError;

/// The most relays remembered. Past it the record whose certificate expired longest ago goes.
pub const MAX_KNOWN_RELAYS: usize = 64;

/// The version of the file format.
const FILE_VERSION: u64 = 1;

/// The most bytes of the file that are read: 64 records of a cert (about 200 bytes) with room.
const MAX_FILE_BYTES: usize = 256 * 1024;

/// The file side of the memory, supplied by the caller that owns the home directory.
pub trait RelayFile: Send + Sync + fmt::Debug {
    /// Takes the lock every writer of the file holds around its read, merge and write. The guard
    /// releases it when dropped.
    fn lock(&self) -> io::Result<Box<dyn Send>>;
    /// The file's bytes, `None` when there is none.
    fn read(&self) -> io::Result<Option<Vec<u8>>>;
    /// Replaces the file whole and atomically.
    fn write(&self, bytes: &[u8]) -> io::Result<()>;
    /// Renames the file to `<name>.corrupt-<unix>`.
    fn set_aside(&self, unix: u64) -> io::Result<()>;
}

/// One remembered relay: the highest certificate verified for `relay_id`.
#[derive(Debug, Clone)]
struct Record {
    cert: NodeCert,
    body: NodeCertBody,
    seen: u64,
}

/// What `menzil status` shows of one record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRecordView {
    /// The relay's `NodeId`.
    pub relay_id: NodeId,
    /// The highest serial seen.
    pub serial: u32,
    /// The X25519 static key of that certificate.
    pub x25519: X25519PublicKey,
    /// The end of that certificate's window, Unix seconds.
    pub not_after: u64,
    /// When the record last rose, Unix seconds.
    pub seen: u64,
}

/// How a verified certificate stood against the memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// No record: the certificate was stored (trust on first use beyond the `NodeId` anchor).
    First,
    /// The same serial with the same key: nothing changed, nothing written.
    Same,
    /// A higher serial: the record rose, and was written before this returned.
    Raised,
}

#[derive(Debug, Default)]
struct State {
    records: HashMap<NodeId, Record>,
    /// Relays whose last IK handshake failed in the handshake itself: the next attempt is XX.
    ik_failed: HashSet<NodeId>,
    /// Relays for which a config key that disagrees with the record has been logged.
    mismatch_logged: HashSet<NodeId>,
}

/// The relays this node remembers. Shared (`Arc`) by every connection attempt of a node.
#[derive(Debug, Default)]
pub struct KnownRelays {
    file: Option<Box<dyn RelayFile>>,
    state: Mutex<State>,
}

impl KnownRelays {
    /// A memory that lives and dies with the process (tests, and callers with no home).
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// The memory kept in `file`, loaded now (`now` is the Unix time used to name a corrupt file
    /// set aside). Never fails: a file that cannot be read or is corrupt means an empty memory.
    pub fn open(file: Box<dyn RelayFile>, now: u64) -> Self {
        let mut records = HashMap::new();
        match file.read() {
            Ok(None) => tracing::info!("no known-relays file yet: no relay is remembered"),
            Ok(Some(bytes)) => match parse_file(&bytes) {
                Ok(parsed) => records = parsed,
                Err(why) => {
                    tracing::warn!(error = %why, "the known-relays file is corrupt: setting it aside and starting empty");
                    if let Err(error) = file.set_aside(now) {
                        tracing::warn!(%error, "could not set the corrupt known-relays file aside");
                    }
                }
            },
            Err(error) => {
                tracing::warn!(%error, "could not read the known-relays file: starting empty")
            }
        }
        evict(&mut records);
        Self {
            file: Some(file),
            state: Mutex::new(State {
                records,
                ..State::default()
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The serial and key remembered for `relay`.
    pub fn stored(&self, relay: &NodeId) -> Option<(u32, X25519PublicKey)> {
        let state = self.state();
        let body = &state.records.get(relay)?.body;
        Some((body.serial, body.x25519_pub))
    }

    /// The records, most recently risen first, for `menzil status`.
    pub fn views(&self) -> Vec<RelayRecordView> {
        let state = self.state();
        let mut views: Vec<_> = state
            .records
            .iter()
            .map(|(id, record)| RelayRecordView {
                relay_id: *id,
                serial: record.body.serial,
                x25519: record.body.x25519_pub,
                not_after: record.body.not_after,
                seen: record.seen,
            })
            .collect();
        views.sort_by(|a, b| {
            b.seen
                .cmp(&a.seen)
                .then(a.relay_id.as_ref().cmp(b.relay_id.as_ref()))
        });
        views
    }

    /// The static key to dial `relay` with under IK, or `None` for XX: the stored key when a
    /// record exists (the config key is then ignored, a mismatch is logged once), else the
    /// config key, else none. After an IK handshake failure the answer is `None` until a
    /// handshake succeeds ([`Self::ik_succeeded`]).
    pub fn dial_key(
        &self,
        relay: &NodeId,
        config_key: Option<X25519PublicKey>,
    ) -> Option<X25519PublicKey> {
        let mut state = self.state();
        if state.ik_failed.contains(relay) {
            return None;
        }
        match state.records.get(relay).map(|r| r.body.x25519_pub) {
            Some(stored) => {
                if let Some(configured) = config_key
                    && configured != stored
                    && state.mismatch_logged.insert(*relay)
                {
                    tracing::warn!(
                        relay = %relay.fingerprint(),
                        "the configured relay key differs from the one this node remembers for the relay: the remembered key is used"
                    );
                }
                Some(stored)
            }
            None => config_key,
        }
    }

    /// An IK attempt failed in the handshake itself (no message 2 in time, or it did not
    /// decrypt): the next attempt uses XX, which authenticates the relay by the same signed
    /// certificate and the same serial rule.
    pub fn ik_failed(&self, relay: &NodeId) {
        if self.state().ik_failed.insert(*relay) {
            tracing::warn!(
                relay = %relay.fingerprint(),
                "the IK handshake with the relay failed: the next attempt uses XX"
            );
        }
    }

    /// A handshake with the relay verified: back to IK with the stored key.
    pub fn ik_succeeded(&self, relay: &NodeId) {
        self.state().ik_failed.remove(relay);
    }

    /// The serial rule (A3) for a certificate that already passed the signature, `node_id`,
    /// window and key checks. `cert` and `body` are the same certificate.
    ///
    /// - no record: store it;
    /// - a lower serial: [`NodeError::RelayRollback`];
    /// - the same serial with another key: refused, never resolved by picking one;
    /// - the same serial and key: accepted, nothing written;
    /// - a higher serial: accepted; the record rises in memory at once and is written before
    ///   this returns (the caller sends ATTACH after it). A failed write is a warning, the
    ///   memory stays risen.
    pub fn accept(
        &self,
        relay: &NodeId,
        cert: &NodeCert,
        body: &NodeCertBody,
        now: u64,
    ) -> Result<Accepted, NodeError> {
        let accepted = {
            let mut state = self.state();
            let accepted = match state.records.get(relay) {
                None => Accepted::First,
                Some(stored) if body.serial < stored.body.serial => {
                    return Err(NodeError::RelayRollback {
                        stored: stored.body.serial,
                        presented: body.serial,
                    });
                }
                Some(stored) if body.serial == stored.body.serial => {
                    if body.x25519_pub != stored.body.x25519_pub {
                        return Err(NodeError::RelayIdentityMismatch(
                            "the relay presented another key under a serial this node already holds",
                        ));
                    }
                    return Ok(Accepted::Same);
                }
                Some(_) => Accepted::Raised,
            };
            state.records.insert(
                *relay,
                Record {
                    cert: cert.clone(),
                    body: body.clone(),
                    seen: now,
                },
            );
            evict(&mut state.records);
            accepted
        };
        match accepted {
            Accepted::First => tracing::info!(
                relay = %relay.fingerprint(),
                serial = body.serial,
                "first contact with this relay: its certificate is remembered"
            ),
            _ => tracing::info!(
                relay = %relay.fingerprint(),
                serial = body.serial,
                "the relay presented a higher certificate serial: remembered"
            ),
        }
        self.persist(relay, cert, body, now);
        Ok(accepted)
    }

    /// Merges the record into the file under its lock; a failure is a warning.
    fn persist(&self, relay: &NodeId, cert: &NodeCert, body: &NodeCertBody, now: u64) {
        let Some(file) = &self.file else { return };
        let result = (|| -> io::Result<()> {
            let _guard = file.lock()?;
            let mut on_disk = match file.read()? {
                None => HashMap::new(),
                Some(bytes) => match parse_file(&bytes) {
                    Ok(records) => records,
                    Err(why) => {
                        tracing::warn!(error = %why, "the known-relays file is corrupt: setting it aside");
                        file.set_aside(now)?;
                        HashMap::new()
                    }
                },
            };
            // The higher serial wins, so a writer that is behind cannot lower a record.
            let lower = on_disk
                .get(relay)
                .is_some_and(|held| held.body.serial >= body.serial);
            if !lower {
                on_disk.insert(
                    *relay,
                    Record {
                        cert: cert.clone(),
                        body: body.clone(),
                        seen: now,
                    },
                );
            }
            evict(&mut on_disk);
            file.write(&encode_file(&on_disk))
        })();
        if let Err(error) = result {
            tracing::warn!(
                %error,
                "could not write the known-relays file: the record is kept in memory and written at the next rise"
            );
        }
    }
}

/// Deletes the record of `relay` from the file, under the file's lock (`menzil relay forget`,
/// for tidying after a new relay identity; never needed for safety). Returns whether a record
/// was there. A file that is not there, or has no such record, is left as it is; a corrupt one
/// is set aside like the node does and counts as having no record.
pub fn forget_in_file(file: &dyn RelayFile, relay: &NodeId, now: u64) -> io::Result<bool> {
    let _guard = file.lock()?;
    let Some(bytes) = file.read()? else {
        return Ok(false);
    };
    let mut records = match parse_file(&bytes) {
        Ok(records) => records,
        Err(_) => {
            file.set_aside(now)?;
            return Ok(false);
        }
    };
    if records.remove(relay).is_none() {
        return Ok(false);
    }
    file.write(&encode_file(&records))?;
    Ok(true)
}

/// Drops records past [`MAX_KNOWN_RELAYS`], the one whose certificate expired longest ago first.
fn evict(records: &mut HashMap<NodeId, Record>) {
    while records.len() > MAX_KNOWN_RELAYS {
        let Some(oldest) = records
            .iter()
            .min_by(|a, b| {
                a.1.body
                    .not_after
                    .cmp(&b.1.body.not_after)
                    .then(a.0.as_ref().cmp(b.0.as_ref()))
            })
            .map(|(id, _)| *id)
        else {
            return;
        };
        records.remove(&oldest);
    }
}

fn encode_file(records: &HashMap<NodeId, Record>) -> Vec<u8> {
    let mut ordered: Vec<_> = records.iter().collect();
    ordered.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
    let relays = ordered
        .into_iter()
        .map(|(id, record)| {
            Value::Map(vec![
                (
                    Value::Text("relay_id".into()),
                    Value::Bytes(<[u8; 32]>::from(*id).to_vec()),
                ),
                (
                    Value::Text("cert".into()),
                    Value::Bytes(record.cert.encode()),
                ),
                (
                    Value::Text("seen".into()),
                    Value::Integer(record.seen.into()),
                ),
            ])
        })
        .collect();
    let file = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(FILE_VERSION.into())),
        (Value::Text("relays".into()), Value::Array(relays)),
    ]);
    let mut out = Vec::new();
    ciborium::into_writer(&file, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

/// Reads the file strictly. `Err` is a corrupt file (the caller sets it aside); a record that
/// does not verify is dropped with a warning and the rest are kept.
fn parse_file(bytes: &[u8]) -> Result<HashMap<NodeId, Record>, String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err("larger than any file this node writes".into());
    }
    check_definite_lengths(bytes).map_err(|e| e.to_string())?;
    let value: Value = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    let Value::Map(entries) = value else {
        return Err("not a map".into());
    };
    let (mut version, mut relays) = (None, None);
    for (key, value) in entries {
        match key {
            Value::Text(k) if k == "v" && version.is_none() => version = Some(value),
            Value::Text(k) if k == "relays" && relays.is_none() => relays = Some(value),
            _ => return Err("unknown or repeated key".into()),
        }
    }
    match version {
        Some(Value::Integer(v)) if u64::try_from(v) == Ok(FILE_VERSION) => {}
        _ => return Err("unknown version".into()),
    }
    let Some(Value::Array(relays)) = relays else {
        return Err("no relays array".into());
    };
    let mut out: HashMap<NodeId, Record> = HashMap::new();
    for entry in relays {
        match parse_record(entry) {
            Ok((id, record)) => {
                // Two records for one relay: the higher serial stays.
                if out
                    .get(&id)
                    .is_none_or(|held| record.body.serial > held.body.serial)
                {
                    out.insert(id, record);
                }
            }
            Err(why) => {
                tracing::warn!(error = %why, "dropping a bad record of the known-relays file")
            }
        }
    }
    Ok(out)
}

fn parse_record(entry: Value) -> Result<(NodeId, Record), String> {
    let Value::Map(fields) = entry else {
        return Err("a record is not a map".into());
    };
    let (mut relay_id, mut cert, mut seen) = (None, None, None);
    for (key, value) in fields {
        match (key, value) {
            (Value::Text(k), Value::Bytes(b)) if k == "relay_id" && relay_id.is_none() => {
                relay_id = Some(b)
            }
            (Value::Text(k), Value::Bytes(b)) if k == "cert" && cert.is_none() => cert = Some(b),
            (Value::Text(k), Value::Integer(i)) if k == "seen" && seen.is_none() => {
                seen = u64::try_from(i).ok()
            }
            _ => return Err("unknown, repeated or mistyped field".into()),
        }
    }
    let (Some(relay_id), Some(cert), Some(seen)) = (relay_id, cert, seen) else {
        return Err("a field is missing".into());
    };
    let id_bytes: [u8; 32] = relay_id
        .try_into()
        .map_err(|_| "relay_id is not 32 bytes")?;
    let id = NodeId::from(id_bytes);
    let cert = NodeCert::decode_strict(&cert).map_err(|e| e.to_string())?;
    let key = VerifyingKey::from_bytes(&id_bytes).map_err(|e| e.to_string())?;
    cert.verify(&key).map_err(|e| e.to_string())?;
    let body = cert.decode().map_err(|e| e.to_string())?;
    if body.node_id != id {
        return Err("the certificate is for another node_id".into());
    }
    Ok((id, Record { cert, body, seen }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    const NOW: u64 = 1_800_000_000;

    pub(crate) fn relay_key() -> SigningKey {
        SigningKey::generate(&mut rand::rng())
    }

    pub(crate) fn cert(key: &SigningKey, serial: u32, x25519: u8) -> (NodeCert, NodeCertBody) {
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: NodeId::from(key.verifying_key().to_bytes()),
            x25519_pub: X25519PublicKey::from([x25519; 32]),
            serial,
            not_before: NOW - 86_400,
            not_after: NOW + 400 * 86_400,
        };
        (NodeCert::sign(key, &body).unwrap(), body)
    }

    fn id_of(key: &SigningKey) -> NodeId {
        NodeId::from(key.verifying_key().to_bytes())
    }

    /// A file in memory that counts its writes and can be made to fail.
    #[derive(Debug, Default)]
    pub(crate) struct MemFile {
        pub bytes: Mutex<Option<Vec<u8>>>,
        pub writes: Mutex<u32>,
        pub fail_writes: Mutex<bool>,
        pub set_aside: Mutex<Vec<u64>>,
    }

    #[derive(Debug, Clone, Default)]
    pub(crate) struct SharedFile(pub Arc<MemFile>);

    impl RelayFile for SharedFile {
        fn lock(&self) -> io::Result<Box<dyn Send>> {
            Ok(Box::new(()))
        }
        fn read(&self) -> io::Result<Option<Vec<u8>>> {
            Ok(self.0.bytes.lock().unwrap().clone())
        }
        fn write(&self, bytes: &[u8]) -> io::Result<()> {
            if *self.0.fail_writes.lock().unwrap() {
                return Err(io::Error::other("disk full"));
            }
            *self.0.bytes.lock().unwrap() = Some(bytes.to_vec());
            *self.0.writes.lock().unwrap() += 1;
            Ok(())
        }
        fn set_aside(&self, unix: u64) -> io::Result<()> {
            self.0.set_aside.lock().unwrap().push(unix);
            *self.0.bytes.lock().unwrap() = None;
            Ok(())
        }
    }

    fn with_file() -> (KnownRelays, SharedFile) {
        let file = SharedFile::default();
        (KnownRelays::open(Box::new(file.clone()), NOW), file)
    }

    #[test]
    fn forget_in_file_deletes_one_record_and_keeps_the_others() {
        let (known, file) = with_file();
        let (a, b) = (relay_key(), relay_key());
        let (ca, ba) = cert(&a, 1, 7);
        let (cb, bb) = cert(&b, 1, 8);
        known.accept(&id_of(&a), &ca, &ba, NOW).unwrap();
        known.accept(&id_of(&b), &cb, &bb, NOW).unwrap();
        assert!(forget_in_file(&file, &id_of(&a), NOW).unwrap());
        // Not there any more: a second forget finds nothing.
        assert!(!forget_in_file(&file, &id_of(&a), NOW).unwrap());
        let reopened = KnownRelays::open(Box::new(file.clone()), NOW);
        assert_eq!(reopened.stored(&id_of(&a)), None);
        assert!(reopened.stored(&id_of(&b)).is_some());
        // No file at all: nothing to forget, nothing created.
        let empty = SharedFile::default();
        assert!(!forget_in_file(&empty, &id_of(&a), NOW).unwrap());
        assert!(empty.0.bytes.lock().unwrap().is_none());
    }

    #[test]
    fn no_record_accepts_and_stores() {
        let (known, file) = with_file();
        let key = relay_key();
        let (c, b) = cert(&key, 3, 7);
        assert_eq!(
            known.accept(&id_of(&key), &c, &b, NOW).unwrap(),
            Accepted::First
        );
        assert_eq!(known.stored(&id_of(&key)), Some((3, b.x25519_pub)));
        assert_eq!(*file.0.writes.lock().unwrap(), 1);
    }

    #[test]
    fn a_lower_serial_is_a_rollback() {
        let known = KnownRelays::in_memory();
        let key = relay_key();
        let (c2, b2) = cert(&key, 2, 7);
        known.accept(&id_of(&key), &c2, &b2, NOW).unwrap();
        let (c1, b1) = cert(&key, 1, 6);
        let err = known.accept(&id_of(&key), &c1, &b1, NOW).unwrap_err();
        assert!(
            matches!(
                err,
                NodeError::RelayRollback {
                    stored: 2,
                    presented: 1
                }
            ),
            "{err:?}"
        );
        // Memory is untouched.
        assert_eq!(known.stored(&id_of(&key)).unwrap().0, 2);
    }

    #[test]
    fn the_same_serial_with_another_key_is_refused_and_with_the_same_key_is_accepted_unwritten() {
        let (known, file) = with_file();
        let key = relay_key();
        let (c, b) = cert(&key, 2, 7);
        known.accept(&id_of(&key), &c, &b, NOW).unwrap();
        let (other, other_body) = cert(&key, 2, 8);
        let err = known
            .accept(&id_of(&key), &other, &other_body, NOW)
            .unwrap_err();
        assert!(
            matches!(err, NodeError::RelayIdentityMismatch(_)),
            "{err:?}"
        );
        assert_eq!(known.stored(&id_of(&key)).unwrap().1, b.x25519_pub);
        let writes = *file.0.writes.lock().unwrap();
        assert_eq!(
            known.accept(&id_of(&key), &c, &b, NOW).unwrap(),
            Accepted::Same
        );
        assert_eq!(
            *file.0.writes.lock().unwrap(),
            writes,
            "no write for the same record"
        );
    }

    #[test]
    fn a_higher_serial_is_written_before_accept_returns_and_survives_a_reopen() {
        let (known, file) = with_file();
        let key = relay_key();
        let (c1, b1) = cert(&key, 1, 6);
        known.accept(&id_of(&key), &c1, &b1, NOW).unwrap();
        let (c2, b2) = cert(&key, 2, 7);
        assert_eq!(
            known.accept(&id_of(&key), &c2, &b2, NOW + 5).unwrap(),
            Accepted::Raised
        );
        // On disk already, with no further call.
        let reopened = KnownRelays::open(Box::new(file.clone()), NOW);
        assert_eq!(reopened.stored(&id_of(&key)), Some((2, b2.x25519_pub)));
    }

    #[test]
    fn a_failed_write_is_a_warning_and_memory_still_rises() {
        let (known, file) = with_file();
        let key = relay_key();
        let (c1, b1) = cert(&key, 1, 6);
        known.accept(&id_of(&key), &c1, &b1, NOW).unwrap();
        *file.0.fail_writes.lock().unwrap() = true;
        let (c2, b2) = cert(&key, 2, 7);
        assert_eq!(
            known.accept(&id_of(&key), &c2, &b2, NOW).unwrap(),
            Accepted::Raised
        );
        assert_eq!(known.stored(&id_of(&key)).unwrap().0, 2);
        // The file still holds serial 1.
        let reopened = KnownRelays::open(Box::new(file.clone()), NOW);
        assert_eq!(reopened.stored(&id_of(&key)).unwrap().0, 1);
    }

    #[test]
    fn records_are_per_relay_node_id() {
        let known = KnownRelays::in_memory();
        let (a, b) = (relay_key(), relay_key());
        let (ca, ba) = cert(&a, 5, 1);
        let (cb, bb) = cert(&b, 1, 2);
        known.accept(&id_of(&a), &ca, &ba, NOW).unwrap();
        // Another relay at serial 1 is not a rollback of the first.
        known.accept(&id_of(&b), &cb, &bb, NOW).unwrap();
        assert_eq!(known.views().len(), 2);
    }

    #[test]
    fn dial_key_prefers_the_stored_key_over_the_config_key_over_xx() {
        let known = KnownRelays::in_memory();
        let key = relay_key();
        let id = id_of(&key);
        let configured = X25519PublicKey::from([9; 32]);
        assert_eq!(known.dial_key(&id, None), None);
        assert_eq!(known.dial_key(&id, Some(configured)), Some(configured));
        let (c, b) = cert(&key, 1, 7);
        known.accept(&id, &c, &b, NOW).unwrap();
        assert_eq!(known.dial_key(&id, Some(configured)), Some(b.x25519_pub));
        assert_eq!(known.dial_key(&id, None), Some(b.x25519_pub));
    }

    #[test]
    fn an_ik_failure_means_xx_until_a_handshake_succeeds() {
        let known = KnownRelays::in_memory();
        let key = relay_key();
        let id = id_of(&key);
        let configured = X25519PublicKey::from([9; 32]);
        assert_eq!(known.dial_key(&id, Some(configured)), Some(configured));
        known.ik_failed(&id);
        assert_eq!(known.dial_key(&id, Some(configured)), None);
        assert_eq!(known.dial_key(&id, Some(configured)), None);
        known.ik_succeeded(&id);
        assert_eq!(known.dial_key(&id, Some(configured)), Some(configured));
    }

    #[test]
    fn the_file_round_trips_and_a_tampered_record_is_dropped_with_the_others_kept() {
        let (known, file) = with_file();
        let (a, b) = (relay_key(), relay_key());
        let (ca, ba) = cert(&a, 2, 1);
        let (cb, bb) = cert(&b, 4, 2);
        known.accept(&id_of(&a), &ca, &ba, NOW).unwrap();
        known.accept(&id_of(&b), &cb, &bb, NOW).unwrap();
        let reopened = KnownRelays::open(Box::new(file.clone()), NOW);
        assert_eq!(reopened.stored(&id_of(&a)).unwrap().0, 2);
        assert_eq!(reopened.stored(&id_of(&b)).unwrap().0, 4);

        // A record whose certificate is signed by someone else is dropped.
        let forger = relay_key();
        let (cf, _) = cert(&forger, 9, 3);
        let mut records = parse_file(&encode_file(&reopened.state().records)).unwrap();
        records.insert(
            id_of(&a),
            Record {
                cert: cf.clone(),
                body: cert(&forger, 9, 3).1,
                seen: 1,
            },
        );
        let bytes = encode_file(&records);
        let parsed = parse_file(&bytes).unwrap();
        assert!(!parsed.contains_key(&id_of(&a)), "forged record dropped");
        assert_eq!(parsed[&id_of(&b)].body.serial, 4, "the others stay");
    }

    /// A record the load must drop although it is well formed: each check is exercised alone.
    #[test]
    fn a_record_whose_signature_or_node_id_does_not_fit_its_relay_id_is_dropped_each_alone() {
        let (honest, other) = (relay_key(), relay_key());
        let (good_cert, good_body) = cert(&honest, 2, 1);
        let honest_id = id_of(&honest);
        let load = |records: HashMap<NodeId, Record>| parse_file(&encode_file(&records)).unwrap();
        let mut ok = HashMap::new();
        ok.insert(
            honest_id,
            Record {
                cert: good_cert,
                body: good_body,
                seen: 1,
            },
        );
        assert_eq!(load(ok).len(), 1, "control: an honest record loads");

        // The body names the relay id, but another key signed it (a bad signature).
        let (_, body_naming_honest) = cert(&honest, 9, 3);
        let forged = NodeCert::sign(&other, &body_naming_honest).unwrap();
        let mut bad_signature = HashMap::new();
        bad_signature.insert(
            honest_id,
            Record {
                cert: forged,
                body: body_naming_honest,
                seen: 1,
            },
        );
        assert!(load(bad_signature).is_empty(), "signature checked on load");

        // The relay id's own key signed it, but the body names another node.
        let (_, mut body_naming_other) = cert(&honest, 9, 3);
        body_naming_other.node_id = id_of(&other);
        let signed_by_honest = NodeCert::sign(&honest, &body_naming_other).unwrap();
        let mut bad_node_id = HashMap::new();
        bad_node_id.insert(
            honest_id,
            Record {
                cert: signed_by_honest,
                body: body_naming_other,
                seen: 1,
            },
        );
        assert!(load(bad_node_id).is_empty(), "node_id checked on load");
    }

    #[test]
    fn a_corrupt_file_is_set_aside_and_the_memory_starts_empty() {
        let file = SharedFile::default();
        *file.0.bytes.lock().unwrap() = Some(vec![0xff, 0x00, 0x13]);
        let known = KnownRelays::open(Box::new(file.clone()), 1234);
        assert!(known.views().is_empty());
        assert_eq!(*file.0.set_aside.lock().unwrap(), vec![1234]);
        // Indefinite length is corrupt too.
        *file.0.bytes.lock().unwrap() = Some(vec![0xbf, 0xff]);
        let _ = KnownRelays::open(Box::new(file.clone()), 99);
        assert_eq!(file.0.set_aside.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_writer_that_is_behind_cannot_lower_the_file() {
        let file = SharedFile::default();
        let first = KnownRelays::open(Box::new(file.clone()), NOW);
        let second = KnownRelays::open(Box::new(file.clone()), NOW);
        let key = relay_key();
        let id = id_of(&key);
        let (c1, b1) = cert(&key, 1, 6);
        let (c3, b3) = cert(&key, 3, 8);
        first.accept(&id, &c3, &b3, NOW).unwrap();
        // The second process never saw serial 3 and writes serial 1.
        second.accept(&id, &c1, &b1, NOW).unwrap();
        let reopened = KnownRelays::open(Box::new(file.clone()), NOW);
        assert_eq!(reopened.stored(&id).unwrap().0, 3);
    }

    #[test]
    fn past_the_cap_the_record_expired_longest_ago_goes() {
        let known = KnownRelays::in_memory();
        let mut oldest = None;
        for n in 0..=MAX_KNOWN_RELAYS {
            let key = relay_key();
            let (_, mut body) = cert(&key, 1, 1);
            // The first one expires earliest.
            body.not_after = NOW + 1000 + n as u64;
            let cert = NodeCert::sign(&key, &body).unwrap();
            if n == 0 {
                oldest = Some(id_of(&key));
            }
            known.accept(&id_of(&key), &cert, &body, NOW).unwrap();
        }
        assert_eq!(known.views().len(), MAX_KNOWN_RELAYS);
        assert!(known.stored(&oldest.unwrap()).is_none());
    }
}
