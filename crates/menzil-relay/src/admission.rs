//! Admission caps for the relay (multi tenant slice MT4; threats A9 and A14 of
//! `multitenant-design.md`): how many connections one peer address may open per minute, how
//! many sessions one address or one NodeId may keep waiting to ATTACH, and how many sessions
//! are attached in all.
//!
//! Three kinds of slot, each an RAII guard that gives the count back when dropped, so no
//! error path or cancelled task can leak one:
//!
//! - [`IpSlot`] is taken at accept time, before any byte is read, and held until the session
//!   attaches or ends. It bounds what one address can hold in the handshake and pre ATTACH
//!   phases together. The connection rate limit lives here too: the connection that would be
//!   the 61st within a minute from one address is still taken (it needs a slot while it is
//!   answered) but is flagged so the WebSocket upgrade refuses it with HTTP 429.
//! - [`NodeSlot`] is taken once the HELLO is verified (the NodeId is then proven, so a
//!   stranger cannot use up the slots of a NodeId it merely names) and held until ATTACH or the
//!   end of the session. A third unattached session of one NodeId is refused.
//! - [`AttachedSlot`] counts the attached sessions of the whole relay.
//!
//! # Reverse proxy caveat
//!
//! The address counted is the TCP peer address the relay sees. When the relay is placed behind
//! a TLS terminating reverse proxy or a TCP load balancer without PROXY protocol support, every
//! peer shares the proxy's address and the per address figures (60 connections a minute, 32
//! unattached) become figures for the whole relay. Such a deployment must raise them through
//! [`AdmissionLimits`] (`Relay::with_admission_limits`). An IPv6 peer is counted by its /64
//! prefix, because one subscriber commonly holds a whole /64 and a single host can pick any
//! address in it.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use menzil_proto::NodeId;
use tokio::time::Instant;

/// How many connections one peer address may open per [`RATE_WINDOW`].
pub const CONNECTIONS_PER_IP_PER_MINUTE: usize = 60;

/// The window over which [`AdmissionLimits::connections_per_ip_per_minute`] counts.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// How many sessions one peer address may have in the handshake or pre ATTACH phase at once.
/// An honest device holds such a slot for well under a second; the ATTACH deadline (10 s) and
/// the handshake timeout bound a hostile one.
pub const MAX_UNATTACHED_PER_IP: usize = 32;

/// How many handshaken but not yet attached sessions one NodeId may have. One is the normal
/// case; the second covers a reconnect that races the first one's teardown.
pub const MAX_UNATTACHED_PER_NODE: usize = 2;

/// How many sessions may be attached at once, in all.
pub const MAX_ATTACHED: usize = 10_000;

/// The caps [`Admission`] enforces. [`Default`] is the figures above. See the module comment
/// for what to change behind a reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Connections one peer address may open per minute; the next one gets HTTP 429 at the
    /// WebSocket upgrade.
    pub connections_per_ip_per_minute: usize,
    /// Sessions one peer address may have unattached (handshaking or waiting for ATTACH); a
    /// connection over it is closed at once.
    pub max_unattached_per_ip: usize,
    /// Verified but unattached sessions one NodeId may have; the next one is refused with
    /// ERROR `rate_limited`.
    pub max_unattached_per_node: usize,
    /// Attached sessions in all; an ATTACH over it is refused with ERROR `rate_limited`.
    pub max_attached: usize,
}

impl Default for AdmissionLimits {
    fn default() -> Self {
        Self {
            connections_per_ip_per_minute: CONNECTIONS_PER_IP_PER_MINUTE,
            max_unattached_per_ip: MAX_UNATTACHED_PER_IP,
            max_unattached_per_node: MAX_UNATTACHED_PER_NODE,
            max_attached: MAX_ATTACHED,
        }
    }
}

/// What is counted for one peer: an IPv4 address, or the /64 of an IPv6 one (an IPv4 mapped
/// IPv6 address counts as the IPv4 address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PeerKey {
    V4([u8; 4]),
    V6Prefix([u8; 8]),
}

impl PeerKey {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => PeerKey::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => PeerKey::V4(v4.octets()),
                None => PeerKey::V6Prefix(prefix64(v6)),
            },
        }
    }
}

fn prefix64(ip: Ipv6Addr) -> [u8; 8] {
    let octets = ip.octets();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&octets[..8]);
    prefix
}

#[derive(Default)]
struct State {
    /// Admission times within the window, per peer, oldest first. An entry is dropped when its
    /// queue is empty.
    recent: HashMap<PeerKey, VecDeque<Instant>>,
    /// The size of `recent` at which the next sweep of expired peers runs.
    sweep_at: usize,
    unattached_by_peer: HashMap<PeerKey, usize>,
    unattached_by_node: HashMap<NodeId, usize>,
    attached: usize,
}

/// The relay's admission counters. Shared (`Arc`) by the accept loop and every session task.
pub(crate) struct Admission {
    limits: AdmissionLimits,
    state: Mutex<State>,
}

/// The result of [`Admission::admit_connection`] for a connection that gets a slot.
pub(crate) struct Admitted {
    pub(crate) slot: IpSlot,
    /// The peer is over its connection rate: answer the WebSocket upgrade with 429.
    pub(crate) rate_limited: bool,
}

impl Admission {
    /// Counters with `limits`, all at zero.
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    /// Counts a new connection from `ip`. `None` means the peer already holds its share of
    /// unattached sessions and the connection is to be dropped without an answer. Otherwise
    /// the slot is held until the session attaches or ends, and `rate_limited` says whether
    /// this connection is over the per minute figure (it is then not counted towards it, so a
    /// peer that keeps knocking can still get in once its older connections leave the window).
    pub(crate) fn admit_connection(self: &Arc<Self>, ip: IpAddr) -> Option<Admitted> {
        let key = PeerKey::of(ip);
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let held = state.unattached_by_peer.get(&key).copied().unwrap_or(0);
        if held >= self.limits.max_unattached_per_ip {
            return None;
        }
        *state.unattached_by_peer.entry(key).or_insert(0) += 1;

        let rate_limited = {
            if state.recent.len() >= state.sweep_at.max(1024) {
                state.recent.retain(|_, times| {
                    while times
                        .front()
                        .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
                    {
                        times.pop_front();
                    }
                    !times.is_empty()
                });
                state.sweep_at = state.recent.len() * 2;
            }
            let times = state.recent.entry(key).or_default();
            while times
                .front()
                .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
            {
                times.pop_front();
            }
            if times.len() >= self.limits.connections_per_ip_per_minute {
                if times.is_empty() {
                    state.recent.remove(&key);
                }
                true
            } else {
                times.push_back(now);
                false
            }
        };
        drop(state);
        Some(Admitted {
            slot: IpSlot {
                admission: Arc::clone(self),
                key,
            },
            rate_limited,
        })
    }

    /// Counts a verified, not yet attached session of `node_id`; `None` when the NodeId
    /// already has its share.
    pub(crate) fn admit_node(self: &Arc<Self>, node_id: NodeId) -> Option<NodeSlot> {
        let mut state = self.state.lock().unwrap();
        let held = state.unattached_by_node.entry(node_id).or_insert(0);
        if *held >= self.limits.max_unattached_per_node {
            return None;
        }
        *held += 1;
        drop(state);
        Some(NodeSlot {
            admission: Arc::clone(self),
            node_id,
        })
    }

    /// Counts an attached session; `None` when `max_attached` sessions are attached already.
    /// `replacing` says the NodeId is attached already (this session supersedes that one), in
    /// which case the count is allowed one over, for the moment both exist.
    pub(crate) fn admit_attached(self: &Arc<Self>, replacing: bool) -> Option<AttachedSlot> {
        let mut state = self.state.lock().unwrap();
        if state.attached >= self.limits.max_attached && !replacing {
            return None;
        }
        state.attached += 1;
        drop(state);
        Some(AttachedSlot {
            admission: Arc::clone(self),
        })
    }

    /// Sessions currently attached, by this count (tests).
    #[cfg(test)]
    pub(crate) fn attached(&self) -> usize {
        self.state.lock().unwrap().attached
    }

    /// Unattached sessions held for `node_id` right now (tests).
    #[cfg(test)]
    pub(crate) fn unattached_of_node(&self, node_id: &NodeId) -> usize {
        self.state
            .lock()
            .unwrap()
            .unattached_by_node
            .get(node_id)
            .copied()
            .unwrap_or(0)
    }

    /// Unattached sessions held by `ip`'s peer right now (tests).
    #[cfg(test)]
    pub(crate) fn unattached_of_peer(&self, ip: IpAddr) -> usize {
        self.state
            .lock()
            .unwrap()
            .unattached_by_peer
            .get(&PeerKey::of(ip))
            .copied()
            .unwrap_or(0)
    }
}

/// One unattached session of a peer address; see [`Admission::admit_connection`].
pub(crate) struct IpSlot {
    admission: Arc<Admission>,
    key: PeerKey,
}

impl IpSlot {
    /// The peer this slot counts, as a key for `crate::log_throttle` (never equal to a NodeId
    /// key by accident: the first byte tags the address family and the rest is zero padded).
    pub(crate) fn log_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        match self.key {
            PeerKey::V4(octets) => {
                key[0] = 4;
                key[1..5].copy_from_slice(&octets);
            }
            PeerKey::V6Prefix(prefix) => {
                key[0] = 6;
                key[1..9].copy_from_slice(&prefix);
            }
        }
        key
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        let mut state = self.admission.state.lock().unwrap();
        if let Some(count) = state.unattached_by_peer.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                state.unattached_by_peer.remove(&self.key);
            }
        }
    }
}

/// One verified but unattached session of a NodeId; see [`Admission::admit_node`].
pub(crate) struct NodeSlot {
    admission: Arc<Admission>,
    node_id: NodeId,
}

impl Drop for NodeSlot {
    fn drop(&mut self) {
        let mut state = self.admission.state.lock().unwrap();
        if let Some(count) = state.unattached_by_node.get_mut(&self.node_id) {
            *count -= 1;
            if *count == 0 {
                state.unattached_by_node.remove(&self.node_id);
            }
        }
    }
}

/// One attached session; see [`Admission::admit_attached`].
pub(crate) struct AttachedSlot {
    admission: Arc<Admission>,
}

impl Drop for AttachedSlot {
    fn drop(&mut self) {
        let mut state = self.admission.state.lock().unwrap();
        state.attached -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn admission(limits: AdmissionLimits) -> Arc<Admission> {
        Arc::new(Admission::new(limits))
    }

    fn roomy() -> AdmissionLimits {
        AdmissionLimits {
            max_unattached_per_ip: usize::MAX,
            ..AdmissionLimits::default()
        }
    }

    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

    /// Admits one connection and drops its slot at once (the session is over), so only the
    /// rate counts.
    fn knock(admission: &Arc<Admission>, ip: IpAddr) -> bool {
        admission.admit_connection(ip).unwrap().rate_limited
    }

    #[tokio::test(start_paused = true)]
    async fn the_61st_connection_in_a_minute_from_one_address_is_rate_limited() {
        let admission = admission(roomy());
        for n in 1..=60 {
            assert!(!knock(&admission, IP_A), "connection {n} must be admitted");
        }
        assert!(knock(&admission, IP_A), "the 61st must be rate limited");
        // Another address is unaffected.
        assert!(!knock(&admission, IP_B));
    }

    #[tokio::test(start_paused = true)]
    async fn the_rate_window_slides_and_refused_knocks_do_not_extend_it() {
        let admission = admission(roomy());
        for _ in 0..60 {
            assert!(!knock(&admission, IP_A));
        }
        assert!(knock(&admission, IP_A));
        tokio::time::advance(Duration::from_secs(59)).await;
        assert!(
            knock(&admission, IP_A),
            "59 s later the window is still full"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert!(
            !knock(&admission, IP_A),
            "the 60 admissions are older than a minute now, the refused knocks did not count"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_rate_figure_is_configurable() {
        let admission = admission(AdmissionLimits {
            connections_per_ip_per_minute: 3,
            ..roomy()
        });
        assert!(!knock(&admission, IP_A));
        assert!(!knock(&admission, IP_A));
        assert!(!knock(&admission, IP_A));
        assert!(knock(&admission, IP_A));
    }

    #[tokio::test(start_paused = true)]
    async fn an_ipv6_peer_is_counted_by_its_64_prefix_and_a_mapped_v4_as_v4() {
        let admission = admission(AdmissionLimits {
            connections_per_ip_per_minute: 2,
            ..roomy()
        });
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let same_64: IpAddr = "2001:db8:1:2:ffff::7".parse().unwrap();
        let other_64: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert!(!knock(&admission, a));
        assert!(!knock(&admission, same_64));
        assert!(knock(&admission, a), "the same /64 shares one count");
        assert!(!knock(&admission, other_64));

        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert!(!knock(&admission, IP_A));
        assert!(!knock(&admission, mapped));
        assert!(
            knock(&admission, IP_A),
            "a v4 mapped address is the v4 address"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_peers_are_swept_so_the_table_does_not_grow_with_every_address_seen() {
        let admission = admission(roomy());
        for n in 0..5_000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
            knock(&admission, ip);
        }
        tokio::time::advance(Duration::from_secs(61)).await;
        for n in 0..5_000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + n));
            knock(&admission, ip);
        }
        let tracked = admission.state.lock().unwrap().recent.len();
        assert!(
            tracked < 5_000 + 1_024 + 1,
            "the first 5000 expired peers must have been swept, {tracked} are tracked"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_over_its_unattached_share_is_refused_and_the_slot_comes_back_on_drop() {
        let admission = admission(AdmissionLimits {
            max_unattached_per_ip: 2,
            ..AdmissionLimits::default()
        });
        let first = admission.admit_connection(IP_A).unwrap();
        let _second = admission.admit_connection(IP_A).unwrap();
        assert!(admission.admit_connection(IP_A).is_none());
        assert!(admission.admit_connection(IP_B).is_some(), "per address");
        drop(first);
        assert_eq!(admission.unattached_of_peer(IP_A), 1);
        assert!(admission.admit_connection(IP_A).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_third_unattached_session_of_one_node_is_refused() {
        let admission = admission(AdmissionLimits::default());
        let node = NodeId::from([1u8; 32]);
        let other = NodeId::from([2u8; 32]);
        let first = admission.admit_node(node).unwrap();
        let _second = admission.admit_node(node).unwrap();
        assert!(admission.admit_node(node).is_none());
        assert!(admission.admit_node(other).is_some(), "per NodeId");
        drop(first);
        assert_eq!(admission.unattached_of_node(&node), 1);
        assert!(admission.admit_node(node).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn attached_sessions_are_capped_in_all_but_a_replacement_is_let_in() {
        let admission = admission(AdmissionLimits {
            max_attached: 2,
            ..AdmissionLimits::default()
        });
        let first = admission.admit_attached(false).unwrap();
        let _second = admission.admit_attached(false).unwrap();
        assert!(admission.admit_attached(false).is_none());
        let _replacement = admission.admit_attached(true).unwrap();
        assert_eq!(admission.attached(), 3);
        drop(first);
        assert_eq!(admission.attached(), 2);
    }
}
