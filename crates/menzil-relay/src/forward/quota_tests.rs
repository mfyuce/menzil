//! The data plane quotas of one relay (multi tenant design 2.3, slice MT8): pair and destination
//! caps at pair creation, the tenant's droppable cap, the bandwidth bucket and volume counter
//! with their delayed CREDIT, and the release of every count on every path. The live tests (real
//! sockets, real sessions) are in `session_tests.rs`.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use menzil_proto::{Roster, RosterBody, RosterMember};
use tokio::sync::{mpsc, oneshot};

use super::*;
use crate::tenant::{Class, Slug, TenantSpec};

type Handles = (
    oneshot::Receiver<()>,
    mpsc::Receiver<Record>,
    mpsc::UnboundedReceiver<ForwardItem>,
);

fn limits(max_peers: u32) -> Limits {
    Limits {
        max_record: 65_535,
        max_peers,
        credit: 1_048_576,
    }
}

/// A tenant for [`World::tenants_of`]: its slug, its networks and the figures it overrides.
type TenantFigures<'a> = (&'a str, &'a [&'a Net], &'a [(&'a str, u64)]);

/// One network of attached members; `nodes[0]` is the one the tests send from.
struct Net {
    id: NetworkId,
    nodes: Vec<NodeId>,
}

/// A relay's data plane: Rosters, attached sessions, a pair table that judges tenants by `tenants`.
struct World {
    rosters: RosterStore,
    registry: SessionRegistry,
    labels: LabelRegistry,
    table: ForwardTable,
    tenants: Arc<RwLock<Arc<TenantBook>>>,
    handles: HashMap<NodeId, Handles>,
    limits: Limits,
    next_session: u32,
    next_node: u8,
}

impl World {
    fn new(max_peers: u32) -> Self {
        let tenants = Arc::new(RwLock::new(Arc::new(TenantBook::default())));
        Self {
            rosters: RosterStore::new(),
            registry: SessionRegistry::new(),
            labels: LabelRegistry::new(),
            table: ForwardTable::with_tenants(Arc::clone(&tenants)),
            tenants,
            handles: HashMap::new(),
            limits: limits(max_peers),
            next_session: 1,
            next_node: 1,
        }
    }

    /// A network of `count` members, all attached and claiming it.
    fn network(&mut self, count: u8) -> Net {
        let nodes: Vec<NodeId> = (0..count)
            .map(|_| {
                self.next_node += 1;
                NodeId::from([self.next_node; 32])
            })
            .collect();
        let id = self.roster(&nodes);
        for node_id in &nodes {
            self.attach(*node_id, vec![id]);
        }
        Net { id, nodes }
    }

    /// A Roster listing `nodes`, held by the relay.
    fn roster(&mut self, nodes: &[NodeId]) -> NetworkId {
        let owner = SigningKey::generate(&mut rand::rng());
        let id = NetworkId::from(owner.verifying_key().to_bytes());
        let body = RosterBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id: id,
            seq: 1,
            issued: 0,
            expires: 4_000_000_000,
            members: nodes
                .iter()
                .map(|node_id| RosterMember {
                    node_id: *node_id,
                    min_serial: 1,
                })
                .collect(),
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        self.rosters
            .set(&Roster::sign(&owner, &body).unwrap())
            .unwrap();
        id
    }

    /// `node_id` attaches, claiming `claims`.
    fn attach(&mut self, node_id: NodeId, claims: Vec<NetworkId>) {
        let handles = self.registry.attach(node_id, self.next_session, claims);
        self.next_session += 1;
        self.handles.insert(node_id, handles);
    }

    /// Makes `slug` a friend tenant owning `nets`, with `overrides` on its figures.
    fn tenant(&self, slug: &str, nets: &[&Net], overrides: &[(&str, u64)]) {
        self.tenants_of(&[(slug, nets, overrides)]);
    }

    fn tenants_of(&self, tenants: &[TenantFigures<'_>]) {
        let specs = tenants
            .iter()
            .map(|(slug, nets, overrides)| TenantSpec {
                slug: Slug::parse(slug).unwrap(),
                networks: nets.iter().map(|net| net.id).collect(),
                class: Class::Friend,
                overrides: overrides
                    .iter()
                    .map(|(k, v)| (k.to_string(), *v))
                    .collect::<BTreeMap<_, _>>(),
                terminated: false,
                extra_names: vec![],
                added: 1,
            })
            .collect();
        let book = TenantBook::build(specs, vec![], &Default::default());
        assert!(book.refused().is_empty(), "{:?}", book.refused());
        *self.tenants.write().unwrap() = Arc::new(book);
    }

    fn send_with(
        &self,
        net: &Net,
        src: NodeId,
        dst: NodeId,
        reliable: bool,
        len: usize,
    ) -> ForwardOutcome {
        self.send_claiming(&[net.id], src, dst, reliable, len)
    }

    /// A SEND from a session whose HELLO claimed `claims`.
    fn send_claiming(
        &self,
        claims: &[NetworkId],
        src: NodeId,
        dst: NodeId,
        reliable: bool,
        len: usize,
    ) -> ForwardOutcome {
        self.table.forward(
            &self.rosters,
            &self.registry,
            &self.labels,
            &self.limits,
            &src,
            claims,
            &dst,
            0x01,
            if reliable { 0x00 } else { 0x01 },
            vec![0u8; len],
            1_000,
        )
    }

    /// One reliable SEND of `len` bytes from the net's first node to its node `to`.
    fn send(&self, net: &Net, to: usize, len: usize) -> ForwardOutcome {
        self.send_with(net, net.nodes[0], net.nodes[to], true, len)
    }

    /// What `dst` hands to its connection: every queued RECV is "sent" and settled. Returns the
    /// bytes settled.
    fn drain(&mut self, dst: NodeId) -> u64 {
        let mut total = 0;
        while let Ok(item) = self.handles.get_mut(&dst).unwrap().2.try_recv() {
            if let ForwardItem::Recv {
                src,
                charge,
                reliable,
                generation,
                src_session_id,
                shared,
                ..
            } = item
            {
                self.table.drained(
                    &self.registry,
                    &src,
                    &dst,
                    charge,
                    reliable,
                    generation,
                    src_session_id,
                    &shared,
                );
                total += u64::from(charge);
            }
        }
        total
    }

    /// The CREDIT bytes that reached `src` since the last call, by peer.
    fn credits(&mut self, src: NodeId) -> HashMap<NodeId, u64> {
        let mut by_peer = HashMap::new();
        while let Ok(item) = self.handles.get_mut(&src).unwrap().2.try_recv() {
            if let ForwardItem::Credit { peer, bytes } = item {
                *by_peer.entry(peer).or_insert(0) += u64::from(bytes);
            }
        }
        by_peer
    }

    fn credit_total(&mut self, src: NodeId) -> u64 {
        self.credits(src).values().sum()
    }
}

fn queued(outcome: &ForwardOutcome) -> bool {
    matches!(outcome, ForwardOutcome::Queued)
}

fn quota_of(outcome: ForwardOutcome) -> (DataQuota, ErrorBody, TenantId) {
    match outcome {
        ForwardOutcome::OverQuota {
            error,
            tenant,
            quota,
        } => (quota, error, tenant),
        other => panic!("expected OverQuota, got {other:?}"),
    }
}

fn ali() -> TenantId {
    TenantId::Named(Slug::parse("ali").unwrap())
}

#[test]
fn the_pair_cap_refuses_only_new_pairs() {
    let mut w = World::new(1024);
    let net = w.network(5);
    w.tenant("ali", &[&net], &[("forwarding_pairs", 2)]);

    assert!(queued(&w.send(&net, 1, 100)));
    assert!(queued(&w.send(&net, 2, 100)));
    // A third pair of the tenant is refused with `over_quota`, the credit reimbursed, no pair
    // made.
    let (quota, error, tenant) = quota_of(w.send(&net, 3, 100));
    assert_eq!(quota, DataQuota::Pairs);
    assert_eq!(error.code, ErrorCode::OverQuota);
    assert_eq!(tenant, ali());
    assert_eq!(w.credits(net.nodes[0]).get(&net.nodes[3]), Some(&100));
    assert!(
        w.table
            .remaining_credit(&net.nodes[0], &net.nodes[3])
            .is_none()
    );
    assert_eq!(w.table.tenant_counts(&ali()).0, 2);

    // The pairs that exist keep working at the cap, again and again.
    for _ in 0..5 {
        assert!(queued(&w.send(&net, 1, 100)));
        assert!(queued(&w.send(&net, 2, 100)));
    }
    // Another sender of the same tenant is still held to the tenant's total.
    let (quota, _, _) = quota_of(w.send_with(&net, net.nodes[1], net.nodes[3], true, 100));
    assert_eq!(quota, DataQuota::Pairs);
}

#[test]
fn destinations_per_node_are_counted_per_sender() {
    let mut w = World::new(1024);
    let net = w.network(4);
    w.tenant("ali", &[&net], &[("destinations_per_node", 1)]);

    assert!(queued(&w.send(&net, 1, 100)));
    let (quota, _, _) = quota_of(w.send(&net, 2, 100));
    assert_eq!(quota, DataQuota::DestinationsPerNode);
    // The existing destination still works; another sender has its own destinations.
    assert!(queued(&w.send(&net, 1, 100)));
    assert!(queued(&w.send_with(
        &net,
        net.nodes[1],
        net.nodes[2],
        true,
        100
    )));
    let (quota, _, _) = quota_of(w.send_with(&net, net.nodes[1], net.nodes[3], true, 100));
    assert_eq!(quota, DataQuota::DestinationsPerNode);
}

#[test]
fn the_relays_max_peers_holds_every_tenant_the_default_included() {
    // No tenant file: the default tenant has no figures, and `max_peers` is still the ceiling.
    let mut w = World::new(2);
    let net = w.network(4);
    assert!(queued(&w.send(&net, 1, 100)));
    assert!(queued(&w.send(&net, 2, 100)));
    let (quota, error, tenant) = quota_of(w.send(&net, 3, 100));
    assert_eq!(quota, DataQuota::MaxPeers);
    assert_eq!(error.code, ErrorCode::OverQuota);
    assert_eq!(tenant, TenantId::Default);
    assert!(
        queued(&w.send(&net, 1, 100)),
        "an existing pair is not refused"
    );
    let _ = &mut w;
}

#[test]
fn a_tenant_without_figures_has_no_pair_cap() {
    // The default tenant at a `max_peers` far above what it uses: 50 pairs, nothing refused.
    let w = World::new(1024);
    let mut w = w;
    let net = w.network(51);
    for to in 1..51 {
        assert!(queued(&w.send(&net, to, 100)), "pair {to}");
    }
}

#[test]
fn every_count_is_released_when_the_pairs_go() {
    let mut w = World::new(1024);
    let net = w.network(4);
    w.tenant(
        "ali",
        &[&net],
        &[("forwarding_pairs", 3), ("droppable_mib", 1)],
    );
    for to in 1..4 {
        assert!(queued(&w.send(&net, to, 100)));
    }
    // A droppable record, whose bytes are in the tenant's total.
    assert!(queued(&w.send_with(
        &net,
        net.nodes[0],
        net.nodes[2],
        false,
        1000
    )));
    assert_eq!(w.table.tenant_counts(&ali()), (3, 1000));
    assert!(matches!(
        w.send_with(&net, net.nodes[1], net.nodes[3], true, 10),
        ForwardOutcome::OverQuota { .. }
    ));

    // The destination of the pair with the droppable bytes reconnects: the pair goes, with its
    // counts.
    w.table.clear_for(&net.nodes[2]);
    assert_eq!(w.table.tenant_counts(&ali()), (2, 0));
    // A freed place is usable at once.
    assert!(queued(&w.send_with(
        &net,
        net.nodes[1],
        net.nodes[3],
        true,
        10
    )));
    // The sender goes: everything it was in goes.
    w.table.clear_for(&net.nodes[0]);
    w.table.clear_for(&net.nodes[1]);
    assert!(w.table.counts_are_empty());
}

#[test]
fn a_drained_droppable_gives_its_bytes_back_to_the_tenant() {
    let mut w = World::new(1024);
    let net = w.network(2);
    w.tenant("ali", &[&net], &[]);
    assert!(queued(&w.send_with(
        &net,
        net.nodes[0],
        net.nodes[1],
        false,
        5000
    )));
    assert_eq!(w.table.tenant_counts(&ali()), (1, 5000));
    assert_eq!(w.drain(net.nodes[1]), 5000);
    assert_eq!(w.table.tenant_counts(&ali()), (1, 0));
    assert_eq!(w.table.queued_bytes(&net.nodes[0], &net.nodes[1]), Some(0));
}

#[test]
fn the_tenants_droppable_cap_holds_over_all_its_pairs() {
    // 1 MiB over all pairs; each pair alone may queue 256 KiB (its datagram bucket's burst).
    let mut w = World::new(1024);
    let net = w.network(7);
    w.tenant("ali", &[&net], &[("droppable_mib", 1)]);
    let mut admitted = 0u64;
    for to in 1..7 {
        for _ in 0..4 {
            match w.send_with(&net, net.nodes[0], net.nodes[to], false, 60_000) {
                ForwardOutcome::Queued => admitted += 60_000,
                ForwardOutcome::Dropped => {}
                other => panic!("unexpected {other:?}"),
            }
        }
    }
    assert!(
        admitted <= 1 << 20 && admitted > (1 << 20) - 60_000,
        "{admitted} bytes admitted under a 1 MiB cap"
    );
    assert_eq!(w.table.tenant_counts(&ali()).1 as u64, admitted);
    // The default tenant, with no figures, has no such cap: the same traffic is all admitted by
    // the pairs' own limits.
    let other = w.network(7);
    let mut total = 0;
    for to in 1..7 {
        for _ in 0..4 {
            if queued(&w.send_with(&other, other.nodes[0], other.nodes[to], false, 60_000)) {
                total += 60_000;
            }
        }
    }
    assert_eq!(total, 6 * 4 * 60_000);
}

#[test]
fn a_reload_changes_the_figures_for_the_next_new_pair() {
    let mut w = World::new(1024);
    let net = w.network(4);
    w.tenant("ali", &[&net], &[("forwarding_pairs", 1)]);
    assert!(queued(&w.send(&net, 1, 10)));
    assert!(matches!(
        w.send(&net, 2, 10),
        ForwardOutcome::OverQuota { .. }
    ));
    w.tenant("ali", &[&net], &[("forwarding_pairs", 3)]);
    assert!(queued(&w.send(&net, 2, 10)));
    assert!(queued(&w.send(&net, 3, 10)));
}

#[test]
fn a_pair_is_counted_for_the_tenant_of_the_network_that_authorized_it() {
    // A node in two tenants' networks: its pair with a member of the second one counts there.
    let mut w = World::new(1024);
    let a = w.network(1);
    let b = w.network(2);
    w.tenants_of(&[
        ("ali", &[&a], &[("forwarding_pairs", 1)]),
        ("bob", &[&b], &[("forwarding_pairs", 1)]),
    ]);
    assert!(queued(&w.send(&b, 1, 10)));
    assert_eq!(w.table.tenant_counts(&ali()), (0, 0));
    assert_eq!(
        w.table
            .tenant_counts(&TenantId::Named(Slug::parse("bob").unwrap())),
        (1, 0)
    );
}

#[test]
fn an_evicted_senders_queued_items_are_marked_to_be_dropped() {
    let mut w = World::new(1024);
    let net = w.network(3);
    assert!(queued(&w.send(&net, 1, 100)));
    assert!(queued(&w.send_with(
        &net,
        net.nodes[2],
        net.nodes[1],
        true,
        100
    )));
    w.table.revoke_sender(&net.nodes[0]);
    let mut revoked = HashMap::new();
    while let Ok(item) = w.handles.get_mut(&net.nodes[1]).unwrap().2.try_recv() {
        if let ForwardItem::Recv { src, shared, .. } = item {
            revoked.insert(src, shared.is_revoked());
        }
    }
    assert_eq!(revoked.get(&net.nodes[0]), Some(&true));
    assert_eq!(
        revoked.get(&net.nodes[2]),
        Some(&false),
        "only the evicted sender's"
    );
}

#[test]
fn released_items_free_the_pair_and_credit_without_charging_the_tenant() {
    // Dropped unsent (the sender was evicted, or the destination left): the pair's queue and
    // ledger come back, but the bandwidth bucket is not charged for bytes that did not travel.
    let mut w = World::new(1024);
    let net = w.network(2);
    w.tenant("ali", &[&net], &[("bandwidth_mbit", 1), ("burst_mib", 1)]);
    assert!(queued(&w.send(&net, 1, 1000)));
    let item = w
        .handles
        .get_mut(&net.nodes[1])
        .unwrap()
        .2
        .try_recv()
        .unwrap();
    let ForwardItem::Recv {
        src,
        charge,
        reliable,
        generation,
        src_session_id,
        shared,
        ..
    } = item
    else {
        panic!("expected a RECV")
    };
    w.table.released(
        &w.registry,
        &src,
        &net.nodes[1],
        charge,
        reliable,
        generation,
        src_session_id,
        &shared,
    );
    assert_eq!(w.table.queued_bytes(&src, &net.nodes[1]), Some(0));
    assert_eq!(w.table.remaining_credit(&src, &net.nodes[1]), Some(1 << 20));
    assert_eq!(w.credit_total(src), 1000);
    assert!(
        w.table.shaper_of(&ali()).is_none(),
        "nothing travelled, nothing charged"
    );
}

/// Sends `bytes` from the first node to node 1 in records of up to 64 KiB, settling each as the
/// destination would. Returns the bytes settled.
fn pump(w: &mut World, net: &Net, bytes: usize) -> u64 {
    let mut left = bytes;
    let mut total = 0;
    while left > 0 {
        let len = left.min(65_536);
        assert!(queued(&w.send(net, 1, len)));
        total += w.drain(net.nodes[1]);
        left -= len;
    }
    total
}

const BURST: usize = 1 << 20;

#[tokio::test(start_paused = true)]
async fn within_the_burst_credit_comes_back_at_once() {
    let mut w = World::new(1024);
    let net = w.network(2);
    w.tenant("ali", &[&net], &[("bandwidth_mbit", 1), ("burst_mib", 1)]);
    let consumed = pump(&mut w, &net, BURST);
    assert_eq!(w.credit_total(net.nodes[0]), consumed);
    assert_eq!(w.table.shaper_of(&ali()).unwrap().volume_used(), consumed);
}

#[tokio::test(start_paused = true)]
async fn over_the_bandwidth_credit_is_delayed_and_never_lost() {
    // 1 Mbit/s is 125,000 bytes/s; burst 1 MiB. Pump 3 MiB through: the first MiB is inside the
    // burst, the other 2 MiB are a debt of about 16.8 s.
    let mut w = World::new(1024);
    let net = w.network(2);
    w.tenant("ali", &[&net], &[("bandwidth_mbit", 1), ("burst_mib", 1)]);
    let consumed = pump(&mut w, &net, 3 * BURST);
    assert_eq!(consumed, 3 * BURST as u64);
    let src = net.nodes[0];

    let at_once = w.credit_total(src);
    assert_eq!(
        at_once, BURST as u64,
        "only the burst is granted back at once"
    );
    assert_eq!(w.table.shaper_of(&ali()).unwrap().held(), 2 * BURST as u64);

    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(w.credit_total(src), 0, "still in debt at 10 s: nothing yet");

    tokio::time::sleep(Duration::from_secs(8)).await;
    let later = w.credit_total(src);
    assert_eq!(
        at_once + later,
        consumed,
        "after the stall the credit granted equals the credit consumed"
    );
    assert_eq!(w.table.shaper_of(&ali()).unwrap().held(), 0);
    // And the ledger itself was whole all along.
    assert_eq!(w.table.remaining_credit(&src, &net.nodes[1]), Some(1 << 20));
}

#[tokio::test(start_paused = true)]
async fn credit_of_a_sender_that_reconnected_is_dropped_when_released() {
    let mut w = World::new(1024);
    let net = w.network(2);
    w.tenant("ali", &[&net], &[("bandwidth_mbit", 1), ("burst_mib", 1)]);
    pump(&mut w, &net, 2 * BURST);
    let src = net.nodes[0];
    let _ = w.credit_total(src);
    // The sender reconnects while its credit is held.
    let fresh = w.registry.attach(src, 999, vec![net.id]);
    w.handles.insert(src, fresh);
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert_eq!(
        w.credit_total(src),
        0,
        "a new session starts with a fresh ledger and is owed nothing for the old one"
    );
    assert_eq!(w.table.shaper_of(&ali()).unwrap().held(), 0);
}

#[tokio::test(start_paused = true)]
async fn the_floor_slows_a_tenant_that_used_its_volume() {
    let mut w = World::new(1024);
    let net = w.network(2);
    // 1 GiB per 30 days, then 1 Mbit/s.
    w.tenant(
        "ali",
        &[&net],
        &[
            ("bandwidth_mbit", 100),
            ("burst_mib", 256),
            ("volume_gib", 1),
            ("floor_mbit", 1),
        ],
    );
    // Fast while under the volume: 2 MiB come back at once.
    let first = pump(&mut w, &net, 2 * BURST);
    assert_eq!(w.credit_total(net.nodes[0]), first);

    // The volume is used up: the bucket's burst falls to a second of the floor rate.
    w.table.shaper_of(&ali()).unwrap().add_volume(1 << 30);
    let consumed = pump(&mut w, &net, BURST);
    let at_once = w.credit_total(net.nodes[0]);
    assert!(
        at_once < consumed,
        "at the floor a MiB cannot all come back at once ({at_once} of {consumed})"
    );
    // About (1 MiB - 125,000) / 125,000 = 7.4 s of debt.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(w.credit_total(net.nodes[0]), 0);
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(at_once + w.credit_total(net.nodes[0]), consumed);
}

#[tokio::test(start_paused = true)]
async fn one_tenants_stall_does_not_delay_another_tenants_credit() {
    let mut w = World::new(1024);
    let a = w.network(2);
    let b = w.network(2);
    w.tenants_of(&[
        ("ali", &[&a], &[("bandwidth_mbit", 1), ("burst_mib", 1)]),
        ("bob", &[&b], &[("bandwidth_mbit", 1), ("burst_mib", 1)]),
    ]);
    // Ali is far over its rate.
    let consumed = pump(&mut w, &a, 3 * BURST);
    assert!(w.credit_total(a.nodes[0]) < consumed);
    // Bob, within his burst, gets every CREDIT back at once while Ali's are held.
    let bob = pump(&mut w, &b, 512 * 1024);
    assert_eq!(w.credit_total(b.nodes[0]), bob);
    assert!(w.table.shaper_of(&ali()).unwrap().held() > 0);
}

#[tokio::test(start_paused = true)]
async fn the_default_tenant_is_never_shaped() {
    let mut w = World::new(1024);
    let net = w.network(2);
    let consumed = pump(&mut w, &net, 8 * BURST);
    assert_eq!(w.credit_total(net.nodes[0]), consumed);
    assert!(w.table.shaper_of(&TenantId::Default).is_none());
}

#[test]
fn without_a_runtime_delayed_credit_is_granted_not_kept_for_ever() {
    // A caller outside any runtime has no timer to wait on: the credit is granted at once.
    let mut w = World::new(1024);
    let net = w.network(2);
    w.tenant("ali", &[&net], &[("bandwidth_mbit", 1), ("burst_mib", 1)]);
    let consumed = {
        let mut total = 0;
        for _ in 0..48 {
            assert!(queued(&w.send(&net, 1, 65_536)));
            total += w.drain(net.nodes[1]);
        }
        total
    };
    assert_eq!(w.credit_total(net.nodes[0]), consumed);
}

#[tokio::test(start_paused = true)]
async fn at_the_default_floor_16_mib_complete_and_no_credit_waits_near_a_nodes_give_up_time() {
    // The design's figures: a tenant that used its volume is held to 5 Mbit/s. The sender below
    // spends only credit it holds (1 MiB to start), as a node does; the clock is virtual.
    let mut w = World::new(1024);
    let net = w.network(2);
    w.tenant("ali", &[&net], &[("volume_gib", 1)]);
    let figures = *w.tenants.read().unwrap().figures_of(&ali()).unwrap();
    assert_eq!((figures.floor_mbit, figures.bandwidth_mbit), (5, 100));
    w.table.use_up_volume(&ali(), &figures);

    let (src, dst) = (net.nodes[0], net.nodes[1]);
    let total: u64 = 16 << 20;
    let chunk = 16 * 1024;
    let started = tokio::time::Instant::now();
    let (mut credit, mut sent, mut spent, mut returned) = (1u64 << 20, 0u64, 0u64, 0u64);
    let mut longest = Duration::ZERO;
    while sent < total || returned < spent {
        while sent < total && credit >= chunk {
            assert!(
                queued(&w.send(&net, 1, chunk as usize)),
                "no refusal, no violation"
            );
            w.drain(dst);
            credit -= chunk;
            sent += chunk;
            spent += chunk;
        }
        let waiting = tokio::time::Instant::now();
        loop {
            let back = w.credit_total(src);
            if back > 0 {
                credit += back;
                returned += back;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        longest = longest.max(waiting.elapsed());
    }
    let elapsed = started.elapsed();
    eprintln!("16 MiB at the 5 Mbit/s floor: {elapsed:?} virtual, longest CREDIT wait {longest:?}");
    assert_eq!(returned, total, "every byte consumed was granted back");
    // 16 MiB at 625,000 bytes/s is 26.8 s, less the floor's one second burst.
    assert!(
        elapsed > Duration::from_secs(24) && elapsed < Duration::from_secs(29),
        "{elapsed:?}"
    );
    assert!(
        longest < Duration::from_secs(5),
        "the longest wait for CREDIT was {longest:?}; a node gives up a staged frame after 35 s"
    );
}

#[test]
fn a_pair_is_counted_for_the_first_network_both_sides_claimed() {
    // `s` and `d` are listed in two networks, and `s` claimed both; `d` claimed only the second.
    // The first network of the sender's list that authorizes the pair AND that `d` claimed is
    // the second, so the pair is Bob's, not Ali's.
    let mut w = World::new(1024);
    let (s, d) = (NodeId::from([100; 32]), NodeId::from([101; 32]));
    let first = w.roster(&[s, d]);
    let second = w.roster(&[s, d]);
    w.attach(s, vec![first, second]);
    w.attach(d, vec![second]);
    let nets = [first, second];
    let ali_net = Net {
        id: first,
        nodes: vec![],
    };
    let bob_net = Net {
        id: second,
        nodes: vec![],
    };
    w.tenants_of(&[("ali", &[&ali_net], &[]), ("bob", &[&bob_net], &[])]);
    assert!(queued(&w.send_claiming(&nets, s, d, true, 100)));
    let bob = TenantId::Named(Slug::parse("bob").unwrap());
    assert_eq!(w.table.tenant_counts(&bob), (1, 0));
    assert_eq!(w.table.tenant_counts(&ali()), (0, 0));
}
