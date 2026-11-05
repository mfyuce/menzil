//! The relay's durable name state on disk: `<home>/relay/names.state` (multi tenant design 2.1
//! and 2.2, slice MT9). The text form and the rules are `menzil_relay::NameState`; this module
//! reads and writes the file.
//!
//! Two writers share the file, each owning a part, both under the relay lock (`lock_relay`) and
//! each writing atomically (`Home::write_public`: a temporary file, `sync_all`, a rename):
//!
//! - The running relay owns the held names and the quarantine of flat names. Its keeper (a
//!   [`crate::persist::Worker`] thread, one coalescing job) writes the state it holds, and keeps
//!   the slug entries it finds on disk.
//! - `relay remove-tenant` owns the quarantine of the removed tenant's slug and keeps the rest
//!   as it finds it.
//!
//! A file that is damaged is never written over and never half used: the relay does not start
//! with it, a reload keeps what it has, and every command that would read it says so
//! ([`read`]). The file `relay/tenants/.quarantine` of the first tenant slice (one `<slug> <unix>`
//! per line) is read as slug entries and moved in here the first time anything writes the state
//! under the lock ([`migrate_legacy_locked`]).

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use menzil_relay::NameState;

use super::{relay_dir, tenants};
use crate::home::Home;

/// The state file.
pub fn state_path(home: &Home) -> PathBuf {
    relay_dir(home).join("names.state")
}

/// The file the first tenant slice kept removed slugs in.
fn legacy_path(home: &Home) -> PathBuf {
    tenants::tenants_dir(home).join(".quarantine")
}

fn damaged(home: &Home, error: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(
        "the name state {} is damaged ({error}): it keeps released names and removed tenant names from being taken over, so it is not used and not written over; repair it, or move it away to start with no names held",
        state_path(home).display()
    )
}

/// The state file as it is, with no legacy entries. A missing file is an empty state; a file
/// that cannot be read or parsed is an error (fail closed).
fn read_file(home: &Home) -> Result<NameState> {
    let path = state_path(home);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(NameState::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    NameState::parse(&text).map_err(|e| damaged(home, e))
}

/// The slug entries of the first slice's `.quarantine` file, `<slug> <unix>` per line.
fn read_legacy(home: &Home) -> Result<BTreeMap<String, u64>> {
    let path = legacy_path(home);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut removed = BTreeMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let (slug, at) = line
            .split_once(' ')
            .and_then(|(slug, at)| Some((slug, at.trim().parse::<u64>().ok()?)))
            .ok_or_else(|| anyhow!("{} has a line that is not `<slug> <unix>`", path.display()))?;
        removed.insert(slug.to_string(), at);
    }
    Ok(removed)
}

/// The name state: the file, plus the slug entries a legacy `.quarantine` file still holds.
pub fn read(home: &Home) -> Result<NameState> {
    let mut state = read_file(home)?;
    for (slug, at) in read_legacy(home)? {
        state.quarantine_slug(&slug, at);
    }
    Ok(state)
}

/// Moves the legacy slug entries into the state file and deletes the legacy file. The caller
/// holds the relay lock. Nothing happens (and nothing is written) without a legacy file.
pub fn migrate_legacy_locked(home: &Home) -> Result<()> {
    if !legacy_path(home).exists() {
        return Ok(());
    }
    let state = read(home)?;
    write_locked(home, &state)?;
    match fs::remove_file(legacy_path(home)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context("removing the migrated slug quarantine file"),
    }
}

/// Writes `state` atomically. The caller holds the relay lock.
fn write_locked(home: &Home, state: &NameState) -> Result<()> {
    home.write_public(&state_path(home), state.render().as_bytes())
}

/// What a relay starting needs: the migration, then the state it holds. A damaged file stops
/// the start.
pub fn load_for_start(home: &Home) -> Result<NameState> {
    if let Some(_lock) = home.lock_relay_if_held()? {
        migrate_legacy_locked(home)?;
    }
    read(home)
}

/// The keeper's write: `snapshot` is the relay's part (held names and flat quarantine); the
/// slug entries on disk stay. A damaged file on disk is not written over.
pub fn write_relay_part(home: &Home, snapshot: &NameState) -> Result<()> {
    let Some(_lock) = home.lock_relay_if_held()? else {
        // The relay directory was removed under a running relay: nothing to write into.
        return Ok(());
    };
    migrate_legacy_locked(home)?;
    let on_disk = read_file(home)?;
    let mut merged = snapshot.relay_part();
    for (name, entry) in on_disk.quarantine {
        if entry.kind == menzil_relay::QuarantineKind::Slug {
            merged.quarantine.insert(name, entry);
        }
    }
    write_locked(home, &merged)
}

/// `remove-tenant`: puts `slug` in quarantine from `now`, keeping the rest of the file. The
/// caller holds the relay lock.
pub fn quarantine_slug_locked(home: &Home, slug: &str, now: u64) -> Result<()> {
    migrate_legacy_locked(home)?;
    let mut state = read_file(home)?;
    state.quarantine_slug(slug, now);
    write_locked(home, &state)
}

/// Removed slugs still in quarantine at `now`, with the moment each is free again.
pub fn quarantined_slugs(home: &Home, now: u64) -> Result<BTreeMap<String, u64>> {
    Ok(read(home)?.quarantined_slugs(now))
}

/// The flat names the default tenant has been accepted for or is quarantined for: a tenant
/// name or an operator grant equal to one is refused (design 2.2, rule 4 and 10).
pub fn default_flat_names(home: &Home) -> Result<HashSet<String>> {
    Ok(read(home)?.default_flat_names())
}
