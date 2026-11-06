//! The decisions of certificate rotation (cert-rotation design Q7, Q9, O3) as pure functions: no
//! files, no clock, no node. The callers ([`crate::cert_node`] on the node's side,
//! [`crate::steward_loop`] on the steward's) read what is held, pass it in with the time and do
//! what the answer says.
//!
//! * [`renew_due`]: the node renews its own certificate (same keys, serial + 1) once the one in
//!   its file runs out within [`RENEW_WITHIN`], or when it does not start yet.
//! * [`unlisted_days`] and [`warn_due`]: a network whose held Policy lists an older certificate
//!   of this node than the current one is told in `status`; the log says it daily from
//!   [`WARN_WITHIN`] before the listed one expires.
//! * [`rotation_plan`]: which of the renewed certificates peers pushed a steward lists, in one
//!   pair, at most once an hour ([`ROTATE_EVERY`]), and only a renewal that extends the listed
//!   expiry by at least [`ROTATE_MIN_EXTENSION`] (which makes the step idempotent without any
//!   stored state: once listed, the same certificate no longer qualifies).

use ed25519_dalek::VerifyingKey;
use menzil_admin::{CERT_ISSUE_MARGIN_SECS, Documents, MAX_CERT_LIFETIME_SECS};
use menzil_proto::{NodeCert, NodeCertBody, NodeId, PolicyBody};

/// Seconds in a day.
pub const DAY: u64 = 24 * 60 * 60;
/// A node renews its own certificate when the one it has expires within this long, in seconds
/// (design O3: 60 days).
pub const RENEW_WITHIN: u64 = 60 * DAY;
/// The log warns about an unlisted renewal from this long before the listed certificate
/// expires, in seconds (design O3: 30 days).
pub const WARN_WITHIN: u64 = 30 * DAY;
/// How often the node looks at its certificate, in seconds (design Q9: 6 hours).
pub const CHECK_EVERY_SECS: u64 = 6 * 60 * 60;
/// A steward lists a renewal only when it extends the listed certificate's `not_after` by at
/// least this long, in seconds (design Q7: 30 days). It bounds a hostile member to one issued
/// pair per 30 days.
pub const ROTATE_MIN_EXTENSION: u64 = 30 * DAY;
/// A steward issues at most one rotation pair per network in this long, in seconds.
pub const ROTATE_EVERY: u64 = 60 * 60;

/// A timing the live tests shorten (cert-rotation design S8): the value of the environment
/// variable `MENZIL_TEST_<name>` in seconds, read by debug builds only (`cargo test` builds
/// them; a release build never looks), `None` when it is not set or not a number. The names in
/// use: `RENEW_WITHIN` (this module's [`RENEW_WITHIN`]), `CHECK_EVERY` ([`CHECK_EVERY_SECS`]),
/// `POLL` (the steward loop's look) and `RELOAD_EVERY` (the node's reload of the documents).
/// Not part of the command line or the configuration, and not documented for users.
pub fn test_knob(name: &str) -> Option<u64> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var(format!("MENZIL_TEST_{name}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Whether the node renews its own certificate: the file's `not_after` is within
/// [`RENEW_WITHIN`] of `now`, or past; or it does not start yet (`not_before` after `now`: the
/// certificate was made while the clock ran ahead, round C L2, and nothing but a new one with a
/// `not_before` a day before the real time can be shown to a relay or a steward). The renewal
/// starts a day before `now`, so it does not make the certificate due again.
pub fn renew_due(not_before: u64, not_after: u64, now: u64) -> bool {
    not_before > now
        || not_after.saturating_sub(now) <= test_knob("RENEW_WITHIN").unwrap_or(RENEW_WITHIN)
}

/// The highest serial of `node` among the certificates `policy` lists (the Policy's certificates
/// are a flat list, so there may be several, and a steward's tail one). `None` when it lists
/// none. The serial a renewal has to beat (design Q9).
pub fn listed_max_serial<'a>(
    policies: impl IntoIterator<Item = &'a PolicyBody>,
    node: &NodeId,
) -> Option<u32> {
    policies
        .into_iter()
        .filter_map(|policy| listed_cert(policy, node))
        .map(|listed| listed.serial)
        .max()
}

/// What a Policy lists for a node: the certificate that wins by [`NodeCertBody::rank`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listed {
    /// Its serial.
    pub serial: u32,
    /// When it expires, Unix seconds.
    pub not_after: u64,
}

/// The reference certificate `policy` lists for `node`, if it lists one.
pub fn listed_cert(policy: &PolicyBody, node: &NodeId) -> Option<Listed> {
    policy
        .certs
        .iter()
        .filter_map(|cert| cert.decode().ok())
        .filter(|body| body.node_id == *node)
        .max_by_key(|body| body.rank())
        .map(|body| Listed {
            serial: body.serial,
            not_after: body.not_after,
        })
}

/// For one network: how many whole days the listed certificate of this node has left, when the
/// network's held Policy does not list the node's current certificate (`own_serial`) yet. `None`
/// when the Policy lists none of this node's certificates (it is not a member there) or already
/// lists the current one or a newer. An expired listed certificate gives 0.
pub fn unlisted_days(listed: Option<Listed>, own_serial: u32, now: u64) -> Option<u64> {
    let listed = listed.filter(|listed| listed.serial < own_serial)?;
    Some(listed.not_after.saturating_sub(now) / DAY)
}

/// Whether the log warns about an unlisted renewal on this network: the current certificate is
/// not listed ([`unlisted_days`]) and the listed one expires within [`WARN_WITHIN`] of `now` (or
/// has). Gives the days left. How often the same warning is repeated is
/// `steward_loop::warn_due`.
pub fn warn_due(listed: Option<Listed>, own_serial: u32, now: u64) -> Option<u64> {
    let days = unlisted_days(listed, own_serial, now)?;
    let remaining = listed?.not_after.saturating_sub(now);
    (remaining <= WARN_WITHIN).then_some(days)
}

/// The renewals a steward lists now, in one pair (design Q7): from `candidates` (what peers
/// pushed and the node judged), those that pass the same rules `menzil_admin::steward_rotate`
/// applies against the held pair `docs`, plus the 30 day rule. A candidate qualifies when
///
/// * its node is a member and not revoked in `docs` (the Policy lists a certificate of it:
///   `revoke` takes a node's certificates out with it, so a node without a listed certificate
///   is not a member, and the steward's operation refuses it as well);
/// * it verifies, is valid at `now`, has been valid for [`CERT_ISSUE_MARGIN_SECS`], and its
///   window is at most [`MAX_CERT_LIFETIME_SECS`];
/// * its serial is above the highest the Policy lists for the node, its `x25519_pub` is that
///   certificate's, and its `not_after` is at least [`ROTATE_MIN_EXTENSION`] after that one's.
///
/// At most one certificate per node (the highest serial). Nothing when a rotation pair was
/// issued less than [`ROTATE_EVERY`] ago (`last`; a `last` ahead of the clock counts as long
/// ago, so a clock that was wrong once does not stop rotations until it catches up). Ordered by
/// node id, so the answer does not depend on the order candidates were kept in.
pub fn rotation_plan(
    candidates: &[NodeCert],
    docs: &Documents,
    last: Option<u64>,
    now: u64,
) -> Vec<NodeCert> {
    if last.is_some_and(|at| at <= now && now - at < ROTATE_EVERY) {
        return Vec::new();
    }
    let policy = docs.policy_body();
    let mut best: Vec<(NodeCertBody, &NodeCert)> = Vec::new();
    for cert in candidates {
        let Ok(body) = cert.decode() else { continue };
        if !body.is_valid_at(now)
            || body.not_before > now.saturating_sub(CERT_ISSUE_MARGIN_SECS)
            || body.not_after < body.not_before
            || body.not_after - body.not_before > MAX_CERT_LIFETIME_SECS
        {
            continue;
        }
        let Ok(key) = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id)) else {
            continue;
        };
        if cert.verify(&key).is_err() {
            continue;
        }
        let Some(listed) = policy
            .certs
            .iter()
            .filter_map(|listed| listed.decode().ok())
            .filter(|listed| listed.node_id == body.node_id)
            .max_by_key(|listed| listed.rank())
        else {
            continue;
        };
        if body.serial <= listed.serial
            || body.x25519_pub != listed.x25519_pub
            || body.not_after < listed.not_after.saturating_add(ROTATE_MIN_EXTENSION)
        {
            continue;
        }
        match best
            .iter_mut()
            .find(|(other, _)| other.node_id == body.node_id)
        {
            Some(slot) if slot.0.serial < body.serial => *slot = (body, cert),
            Some(_) => {}
            None => best.push((body, cert)),
        }
    }
    best.sort_by_key(|(body, _)| <[u8; 32]>::from(body.node_id));
    best.into_iter().map(|(_, cert)| cert.clone()).collect()
}

#[cfg(test)]
mod tests;
