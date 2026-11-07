//! Admission caps for the relay (multi tenant slice MT4; threats A9 and A14 of
//! `multitenant-design.md`): how many connections one peer address may open per minute, how
//! many handshakes and how many sessions one address may keep in flight, how many sessions one
//! NodeId may keep waiting to ATTACH, and how many sessions are attached in all.
//!
//! The figures differ from the design's table in two places, on purpose: 32 unattached sessions
//! per address (the design said 64) and 10,000 attached in all (the design said 4,096). The
//! design's "10 HELLOs per NodeId per minute after the DH" is not built; what bounds a NodeId is
//! its unattached cap ([`MAX_UNATTACHED_PER_NODE`]) and the per address connection rate.
//!
//! Three kinds of slot, each an RAII guard that gives the count back when dropped, so no
//! error path or cancelled task can leak one:
//!
//! - [`IpSlot`] is taken at accept time, before any byte is read, and held until the session
//!   attaches or ends. It bounds what one address can hold in the handshake and pre ATTACH
//!   phases together, and, for the TLS and WebSocket handshake alone, a smaller number
//!   ([`MAX_HANDSHAKES_PER_IP`] per address, [`MAX_HANDSHAKES_PER_V6_48`] per IPv6 /48): the
//!   relay has 256 handshake permits ([`crate::relay::MAX_INFLIGHT_HANDSHAKES`]) and a handful
//!   of addresses must not be able to hold them all (round T3, M4). The connection rate limit
//!   lives here too: the connection that would be the 61st within a minute from one address
//!   gets no slot at all and is dropped before TLS. (Answering it with HTTP 429 needs a TLS
//!   handshake first, which is exactly the work a peer over its rate has no right to; the 429
//!   of the first MT4 build was given up for that.)
//! - [`NodeSlot`] is taken once the HELLO is verified (the NodeId is then proven, so a
//!   stranger cannot use up the slots of a NodeId it merely names) and held until ATTACH or the
//!   end of the session. A third unattached session of one NodeId is refused.
//! - [`AttachedSlot`] counts the attached sessions of the whole relay.
//!
//! # Reverse proxy caveat
//!
//! The address counted is the TCP peer address the relay sees. When the relay is placed behind
//! a TLS terminating reverse proxy or a TCP load balancer without PROXY protocol support, every
//! peer shares the proxy's address and the per address figures (60 connections a minute, 8
//! handshakes in flight, 32 unattached) become figures for the whole relay. Such a deployment must raise them through
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

/// How many sessions one peer address (an IPv6 /64) may have in the handshake or pre ATTACH
/// phase at once. An honest device holds such a slot for well under a second; the ATTACH
/// deadline (10 s) and the handshake timeout bound a hostile one. (The design said 64.)
pub const MAX_UNATTACHED_PER_IP: usize = 32;

/// How many TLS and WebSocket handshakes one peer address (an IPv6 /64) may have in flight at
/// once: a quarter of [`MAX_UNATTACHED_PER_IP`], and 1/32 of the relay's 256 handshake permits,
/// so it takes 32 addresses to hold them all.
pub const MAX_HANDSHAKES_PER_IP: usize = 8;

/// How many handshakes in flight one IPv6 /48 may have in all: a subscriber's /48 holds 65,536
/// /64s, each of which counts as a peer of its own above. 1/16 of the permits.
pub const MAX_HANDSHAKES_PER_V6_48: usize = 16;

/// The most peers the connection rate table tracks. Past it the oldest are forgotten (their
/// rate history with them), so a peer that rotates addresses cannot grow the table without
/// bound. Each entry holds up to [`CONNECTIONS_PER_IP_PER_MINUTE`] times, so the table is at
/// most a few tens of megabytes.
pub const MAX_TRACKED_PEERS: usize = 65_536;

/// How many handshaken but not yet attached sessions one NodeId may have. One is the normal
/// case; the second covers a reconnect that races the first one's teardown.
pub const MAX_UNATTACHED_PER_NODE: usize = 2;

/// How many sessions may be attached at once, in all. (The design said 4,096.)
pub const MAX_ATTACHED: usize = 10_000;

/// The caps [`Admission`] enforces. [`Default`] is the figures above. See the module comment
/// for what to change behind a reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Connections one peer address may open per minute; the next one is closed at once,
    /// before TLS.
    pub connections_per_ip_per_minute: usize,
    /// Sessions one peer address may have unattached (handshaking or waiting for ATTACH); a
    /// connection over it is closed at once.
    pub max_unattached_per_ip: usize,
    /// Handshakes (TLS and WebSocket upgrade) one peer address may have in flight; a connection
    /// over it is closed at once. An IPv6 peer is counted by its /64.
    pub max_handshakes_per_ip: usize,
    /// Handshakes in flight one IPv6 /48 may have in all; a connection over it is closed at
    /// once. Has no effect on IPv4 peers.
    pub max_handshakes_per_v6_48: usize,
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
            max_handshakes_per_ip: MAX_HANDSHAKES_PER_IP,
            max_handshakes_per_v6_48: MAX_HANDSHAKES_PER_V6_48,
            max_unattached_per_node: MAX_UNATTACHED_PER_NODE,
            max_attached: MAX_ATTACHED,
        }
    }
}

/// What is counted for one peer: an IPv4 address, or the /64 of an IPv6 one (an IPv4 mapped
/// IPv6 address counts as the IPv4 address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PeerKey {
    V4([u8; 4]),
    V6Prefix([u8; 8]),
}

impl PeerKey {
    pub(crate) fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => PeerKey::V4(v4.octets()),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => PeerKey::V4(v4.octets()),
                None => PeerKey::V6Prefix(prefix64(v6)),
            },
        }
    }
}

impl PeerKey {
    /// The IPv6 /48 this peer is in, for the handshake cap; `None` for an IPv4 peer.
    pub(crate) fn prefix48(self) -> Option<[u8; 6]> {
        match self {
            PeerKey::V4(_) => None,
            PeerKey::V6Prefix(prefix) => {
                let mut short = [0u8; 6];
                short.copy_from_slice(&prefix[..6]);
                Some(short)
            }
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
    /// Handshakes in flight, per peer and per IPv6 /48; see [`IpSlot::end_handshake`].
    handshaking_by_peer: HashMap<PeerKey, usize>,
    handshaking_by_v6_48: HashMap<[u8; 6], usize>,
    unattached_by_node: HashMap<NodeId, usize>,
    attached: usize,
}

impl State {
    /// Keeps `recent` within bounds before an entry is added: expired peers are swept when the
    /// table has doubled since the last sweep, and if that leaves it at [`MAX_TRACKED_PEERS`]
    /// the oldest eighth is forgotten (so a flood of fresh addresses costs one pass per
    /// eighth of the table, not one per connection).
    fn make_room(&mut self, now: Instant) {
        if self.recent.len() < self.sweep_at.max(SWEEP_FLOOR) {
            return;
        }
        self.recent.retain(|_, times| {
            while times
                .front()
                .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        if self.recent.len() >= MAX_TRACKED_PEERS {
            let mut newest: Vec<(Instant, PeerKey)> = self
                .recent
                .iter()
                .filter_map(|(key, times)| times.back().map(|t| (*t, *key)))
                .collect();
            newest.sort_unstable_by_key(|(t, _)| *t);
            for (_, key) in newest.into_iter().take(MAX_TRACKED_PEERS / 8) {
                self.recent.remove(&key);
            }
        }
        self.sweep_at = (self.recent.len() * 2).min(MAX_TRACKED_PEERS);
    }
}

/// The table size below which the rate table is not swept.
const SWEEP_FLOOR: usize = 1024;

/// The relay's admission counters. Shared (`Arc`) by the accept loop and every session task.
pub(crate) struct Admission {
    limits: AdmissionLimits,
    state: Mutex<State>,
}

impl Admission {
    /// Counters with `limits`, all at zero.
    pub fn new(limits: AdmissionLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    /// Counts a new connection from `ip`. `None` means the connection is to be dropped without
    /// an answer: the peer already holds its share of unattached sessions or of handshakes in
    /// flight (or its /48 does), or it is over its connection rate (such a connection takes no
    /// slot, and is not counted towards the rate, so a peer that keeps knocking can still get in
    /// once its older connections leave the window). Otherwise the slot is held until the
    /// session attaches or ends, and counts as a handshake in flight until
    /// [`IpSlot::end_handshake`].
    pub(crate) fn admit_connection(self: &Arc<Self>, ip: IpAddr) -> Option<IpSlot> {
        let key = PeerKey::of(ip);
        let now = Instant::now();
        let mut state = self.state.lock().unwrap();
        let held = state.unattached_by_peer.get(&key).copied().unwrap_or(0);
        if held >= self.limits.max_unattached_per_ip {
            return None;
        }
        let shaking = state.handshaking_by_peer.get(&key).copied().unwrap_or(0);
        if shaking >= self.limits.max_handshakes_per_ip {
            return None;
        }
        let prefix48 = key.prefix48();
        if let Some(prefix) = prefix48
            && state
                .handshaking_by_v6_48
                .get(&prefix)
                .copied()
                .unwrap_or(0)
                >= self.limits.max_handshakes_per_v6_48
        {
            return None;
        }

        // The rate: the table of recent admissions has a hard bound (`MAX_TRACKED_PEERS`).
        state.make_room(now);
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
            return None;
        }
        times.push_back(now);

        *state.unattached_by_peer.entry(key).or_insert(0) += 1;
        *state.handshaking_by_peer.entry(key).or_insert(0) += 1;
        if let Some(prefix) = prefix48 {
            *state.handshaking_by_v6_48.entry(prefix).or_insert(0) += 1;
        }
        drop(state);
        Some(IpSlot {
            admission: Arc::clone(self),
            key,
            handshaking: true,
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
    /// Still counted as a handshake in flight.
    handshaking: bool,
}

impl IpSlot {
    /// The TLS and WebSocket handshake of this connection is over (done, failed or timed out):
    /// it no longer counts against the peer's handshakes in flight, only against its unattached
    /// sessions, until the session attaches or ends. Idempotent; dropping the slot does it too.
    pub(crate) fn end_handshake(&mut self) {
        if !std::mem::replace(&mut self.handshaking, false) {
            return;
        }
        let mut state = self.admission.state.lock().unwrap();
        if let Some(count) = state.handshaking_by_peer.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                state.handshaking_by_peer.remove(&self.key);
            }
        }
        if let Some(prefix) = self.key.prefix48()
            && let Some(count) = state.handshaking_by_v6_48.get_mut(&prefix)
        {
            *count -= 1;
            if *count == 0 {
                state.handshaking_by_v6_48.remove(&prefix);
            }
        }
    }

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
        self.end_handshake();
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
            max_handshakes_per_ip: usize::MAX,
            max_handshakes_per_v6_48: usize::MAX,
            ..AdmissionLimits::default()
        }
    }

    const IP_A: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const IP_B: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));

    /// Admits one connection and drops its slot at once (the session is over), so only the
    /// rate counts. True when the connection was refused (over its rate).
    fn knock(admission: &Arc<Admission>, ip: IpAddr) -> bool {
        admission.admit_connection(ip).is_none()
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

    /// Round T3, M4: handshakes in flight are capped per address, well below the relay's 256
    /// handshake permits; `end_handshake` gives the count back (once) while the unattached
    /// session stays counted, and a dropped slot gives back whatever it still held.
    #[tokio::test(start_paused = true)]
    async fn handshakes_in_flight_are_capped_per_address_and_freed_when_they_end() {
        let admission = admission(AdmissionLimits::default());
        let mut slots: Vec<IpSlot> = (0..MAX_HANDSHAKES_PER_IP)
            .map(|_| admission.admit_connection(IP_A).unwrap())
            .collect();
        assert!(
            admission.admit_connection(IP_A).is_none(),
            "the {}th handshake of one address",
            MAX_HANDSHAKES_PER_IP + 1
        );
        assert!(admission.admit_connection(IP_B).is_some(), "per address");

        slots[0].end_handshake();
        slots[0].end_handshake();
        assert_eq!(
            admission.unattached_of_peer(IP_A),
            MAX_HANDSHAKES_PER_IP,
            "the finished handshake is still an unattached session"
        );
        let again = admission.admit_connection(IP_A).unwrap();
        assert!(
            admission.admit_connection(IP_A).is_none(),
            "ending a handshake twice freed two places"
        );
        drop(again);
        drop(slots);
        let state = admission.state.lock().unwrap();
        assert!(state.handshaking_by_peer.is_empty() && state.unattached_by_peer.len() <= 1);
        assert!(state.handshaking_by_v6_48.is_empty());
    }

    /// Round T3, M4: the caps are a small part of the permits, so it takes dozens of addresses,
    /// not eight, to hold the 256 (the arithmetic of the reviewer's probe).
    #[tokio::test(start_paused = true)]
    async fn a_few_addresses_cannot_hold_the_handshake_permits() {
        use crate::relay::MAX_INFLIGHT_HANDSHAKES;
        const { assert!(MAX_HANDSHAKES_PER_IP * 16 <= MAX_INFLIGHT_HANDSHAKES) };
        const { assert!(MAX_HANDSHAKES_PER_V6_48 * 8 <= MAX_INFLIGHT_HANDSHAKES) };
        let admission = admission(AdmissionLimits::default());
        let mut held = Vec::new();
        // Eight IPv6 /64s in eight different /48s, each knocking 32 times.
        for p in 0..8u16 {
            let ip: IpAddr = format!("2001:db8:{p:x}::1").parse().unwrap();
            for _ in 0..MAX_UNATTACHED_PER_IP {
                held.extend(admission.admit_connection(ip));
            }
        }
        // Eight IPv4 addresses too.
        for n in 0..8u8 {
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, n));
            for _ in 0..MAX_UNATTACHED_PER_IP {
                held.extend(admission.admit_connection(ip));
            }
        }
        assert_eq!(held.len(), 16 * MAX_HANDSHAKES_PER_IP);
        assert!(held.len() * 2 <= MAX_INFLIGHT_HANDSHAKES);
    }

    /// Round T3, M4: the /64s of one IPv6 /48 (a subscriber's whole allocation holds 65,536 of
    /// them) share a cap of their own.
    #[tokio::test(start_paused = true)]
    async fn the_64s_of_one_ipv6_48_share_a_handshake_cap() {
        let admission = admission(AdmissionLimits::default());
        let mut held = Vec::new();
        for n in 0..100u16 {
            let ip: IpAddr = format!("2001:db8:7:{n:x}::1").parse().unwrap();
            held.extend(admission.admit_connection(ip));
        }
        assert_eq!(held.len(), MAX_HANDSHAKES_PER_V6_48);
        let elsewhere: IpAddr = "2001:db8:8::1".parse().unwrap();
        assert!(admission.admit_connection(elsewhere).is_some());
        // A finished handshake frees a place in the /48.
        held[0].end_handshake();
        let another: IpAddr = "2001:db8:7:ffff::1".parse().unwrap();
        let _taken = admission.admit_connection(another).unwrap();
        assert!(admission.admit_connection(another).is_none());
    }

    /// Round T3, M4: a connection over its rate gets no slot at all (it is dropped before TLS
    /// and takes no handshake permit), and is not counted towards the rate.
    #[tokio::test(start_paused = true)]
    async fn a_connection_over_its_rate_takes_no_slot() {
        let admission = admission(AdmissionLimits {
            connections_per_ip_per_minute: 3,
            ..AdmissionLimits::default()
        });
        let held: Vec<IpSlot> = (0..3)
            .map(|_| admission.admit_connection(IP_A).unwrap())
            .collect();
        for _ in 0..5 {
            assert!(admission.admit_connection(IP_A).is_none());
        }
        assert_eq!(admission.unattached_of_peer(IP_A), 3, "no slot was taken");
        assert_eq!(
            admission
                .state
                .lock()
                .unwrap()
                .handshaking_by_peer
                .get(&PeerKey::of(IP_A)),
            Some(&3)
        );
        drop(held);
    }

    /// Round T3, N2: the rate table has a hard bound whatever the addresses do; past it the
    /// oldest peers are forgotten, the newest kept.
    #[tokio::test(start_paused = true)]
    async fn the_rate_table_never_holds_more_than_its_bound() {
        let admission = admission(roomy());
        let first = IpAddr::V4(Ipv4Addr::from(0x0a00_0000));
        let mut last = first;
        let mut peak = 0;
        for n in 0..(2 * MAX_TRACKED_PEERS as u32 + 1_000) {
            last = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + n));
            knock(&admission, last);
            peak = peak.max(admission.state.lock().unwrap().recent.len());
            // Every address a distinct (paused) instant, so "oldest" is well defined.
            tokio::time::advance(Duration::from_micros(1)).await;
        }
        assert!(
            peak <= MAX_TRACKED_PEERS,
            "{peak} peers tracked, bound {MAX_TRACKED_PEERS}"
        );
        let state = admission.state.lock().unwrap();
        assert!(
            state.recent.len() > MAX_TRACKED_PEERS / 2,
            "not emptied wholesale"
        );
        assert!(
            !state.recent.contains_key(&PeerKey::of(first)),
            "oldest forgotten"
        );
        assert!(state.recent.contains_key(&PeerKey::of(last)), "newest kept");
    }
}
