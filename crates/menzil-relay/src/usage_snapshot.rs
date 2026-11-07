//! What the relay counts per tenant right now, for the operator's status export
//! (`menzil relay status`, the `status.json` file the admin agent's `GetUsage` reads).
//!
//! The counters live where the rules that use them live: attached sessions in
//! [`crate::tenant::TenantUsage`], live forwarding pairs in the forward table, the volume of the
//! period in the tenant's bucket ([`crate::shaping`]), names in the label registry. This module
//! only reads them together. It reveals nothing but counts: no NodeId, network id, key, token or
//! address.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::relay::Relay;
use crate::tenant::TenantId;

/// One tenant's counters at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TenantUsageNow {
    /// Devices attached now (distinct NodeIds; a session that claimed several tenants' networks
    /// counts in each).
    pub attached_sessions: u32,
    /// Live forwarding pairs.
    pub live_pairs: u32,
    /// Bytes charged in the tenant's current volume period.
    pub bytes_period: u64,
    /// Names the tenant holds (the count its `names` figure is held to).
    pub names: u32,
    /// When the volume period ends (Unix seconds); 0 while the tenant has not moved data, since
    /// its period starts with its first byte (and for a tenant without figures, which has none).
    pub period_end_unix: i64,
}

fn clamp_u32(count: usize) -> u32 {
    u32::try_from(count).unwrap_or(u32::MAX)
}

impl Relay {
    /// The counters of every tenant of the current book (the default tenant included), at this
    /// moment. A suspended tenant's live counts (attached sessions, live pairs) are zero: its
    /// networks are not served; what its period and names hold stays as it is.
    pub fn usage_snapshot(&self) -> BTreeMap<TenantId, TenantUsageNow> {
        let book = self.tenants();
        let attached = self.usage.attached_counts();
        let pairs = self.forwarding.pair_counts();
        let names = self.labels.name_counts();
        let now = tokio::time::Instant::now();
        let unix_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut out = BTreeMap::new();
        for tenant in book.tenants() {
            let id = &tenant.id;
            let live = |count: Option<&usize>| {
                if tenant.suspended {
                    0
                } else {
                    clamp_u32(count.copied().unwrap_or(0))
                }
            };
            let (bytes_period, period_end_unix) = match self.forwarding.volume_status(id, now) {
                Some((bytes, left)) => (
                    bytes,
                    i64::try_from(unix_now.saturating_add(left.as_secs())).unwrap_or(i64::MAX),
                ),
                None => (0, 0),
            };
            out.insert(
                id.clone(),
                TenantUsageNow {
                    attached_sessions: live(attached.get(id)),
                    live_pairs: live(pairs.get(id)),
                    bytes_period,
                    names: clamp_u32(
                        names
                            .get(&id.slug().map(str::to_string))
                            .copied()
                            .unwrap_or(0),
                    ),
                    period_end_unix,
                },
            );
        }
        out
    }
}
