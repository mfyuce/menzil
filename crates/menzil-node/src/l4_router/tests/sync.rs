//! The document triggers (TODO.md L4j S6) over the routers of the parent module: a session that
//! comes up reconciles, a docs only push is followed by one handshake, a Roster newer than the
//! Policy fetches the Policy, expiring documents ask for new ones, an issuer pushes. The rules
//! themselves (who is asked, how often, how many) are in `docs_sync/tests.rs`.

use super::*;
use crate::docs_access::{DocsGate, DocsLimits};
use crate::docs_sync::{DocsSync, SyncConfig};
use crate::node::RefuseAll;

pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The sync tasks of `node`, with no jitter.
pub(super) fn sync_for(node: &TestNode, party: &Party, stores: &Stores) -> Arc<DocsSync> {
    DocsSync::new(
        node.handle.clone(),
        stores.rosters.clone(),
        stores.policies.clone(),
        party.id,
        SyncConfig {
            policy_jitter_max: Duration::ZERO,
        },
    )
}

/// Serves every session `node` announces from now on, the way a running node does, with the
/// sync triggers when `sync` is given.
pub(super) fn auto_serve(
    node: &mut TestNode,
    party: &Party,
    stores: &Stores,
    sync: Option<&Arc<DocsSync>>,
) -> Arc<DocsGate> {
    let (_unused, empty) = mpsc::unbounded_channel();
    let mut ready = std::mem::replace(&mut node.ready, empty);
    let (policies, rosters, me, me_static, sync) = (
        stores.policies.clone(),
        stores.rosters.clone(),
        party.id,
        party.x25519_public,
        sync.cloned(),
    );
    let gate = DocsGate::new(DocsLimits::default());
    let counted = gate.clone();
    tokio::spawn(async move {
        let handler = Arc::new(RefuseAll);
        while let Some(session) = ready.recv().await {
            crate::node::serve_session(
                session,
                &policies,
                &rosters,
                me,
                1,
                me_static,
                &handler,
                &gate,
                sync.as_ref(),
                None,
            );
        }
    });
    counted
}

async fn settle() {
    tokio::time::sleep(Duration::from_secs(5)).await;
}

pub(super) fn held(stores: &Stores, network: NetworkId) -> (Option<u64>, Option<u64>) {
    (stores.rosters.seq(&network), stores.policies.seq(&network))
}

/// Re-signs a pair with other expiry times (seconds from now).
fn expiring_in(w: &World, pair: (Roster, Policy), roster: u64, policy: u64) -> (Roster, Policy) {
    let mut r = pair.0.decode().unwrap();
    r.expires = now() + roster;
    let mut p = pair.1.decode().unwrap();
    p.expires = now() + policy;
    (
        Roster::sign(&w.owner, &r).unwrap(),
        Policy::sign(&w.owner, &p).unwrap(),
    )
}

// ---- a session came up ---------------------------------------------------

#[tokio::test(start_paused = true)]
async fn an_initiator_that_is_ahead_pushes_to_the_responder() {
    let w = world();
    let (a, b) = (party(), party());
    let (r1, p1) = w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (stores_a, stores_b) = (stores_from(&r2, &p2), stores_from(&r1, &p1));
    let net = Net::new();
    let mut na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    let sync_b = sync_for(&nb, &b, &stores_b);
    let gate_a = auto_serve(&mut na, &a, &stores_a, Some(&sync_a));
    let gate_b = auto_serve(&mut nb, &b, &stores_b, Some(&sync_b));

    ensure(&na, b.id, w.network).await.unwrap();
    settle().await;
    assert_eq!(
        held(&stores_b, w.network),
        (Some(2), Some(2)),
        "pushed to the responder"
    );
    // One stream, from the initiator: the responder does not compare, it has nothing to compare
    // with (message 1 carries no seqs).
    assert_eq!(gate_b.started_by(&a.id), 1);
    assert_eq!(gate_a.started_by(&b.id), 0);
    assert_eq!(held(&stores_a, w.network), (Some(2), Some(2)));
    // What the push taught A about B is remembered for the next question of whom to ask.
    assert_eq!(sync_a.live_peers(w.network), vec![(b.id, Some(2))]);
}

#[tokio::test(start_paused = true)]
async fn an_initiator_that_is_behind_fetches_from_the_responder() {
    let w = world();
    let (a, b) = (party(), party());
    let (r1, p1) = w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (stores_a, stores_b) = (stores_from(&r1, &p1), stores_from(&r2, &p2));
    let net = Net::new();
    let mut na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    let sync_b = sync_for(&nb, &b, &stores_b);
    let gate_a = auto_serve(&mut na, &a, &stores_a, Some(&sync_a));
    let gate_b = auto_serve(&mut nb, &b, &stores_b, Some(&sync_b));

    ensure(&na, b.id, w.network).await.unwrap();
    settle().await;
    assert_eq!(
        held(&stores_a, w.network),
        (Some(2), Some(2)),
        "fetched from the responder"
    );
    assert_eq!(gate_b.started_by(&a.id), 1, "one fetch");
    assert_eq!(gate_a.started_by(&b.id), 0);
    assert_eq!(held(&stores_b, w.network), (Some(2), Some(2)));
    assert_eq!(sync_a.live_peers(w.network), vec![(b.id, Some(2))]);
}

#[tokio::test(start_paused = true)]
async fn each_side_ahead_in_one_document_pushes_the_roster_over() {
    let w = world();
    let (a, b) = (party(), party());
    // A holds Roster 3 beside Policy 1 (the Roster came alone, over the relay); B holds pair 2.
    let (r1, p1) = w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r3, _) = w.fresh_pair(3, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (stores_a, stores_b) = (stores_from(&r1, &p1), stores_from(&r2, &p2));
    assert!(stores_a.rosters.adopt_owner(&r3, now()).unwrap());
    let net = Net::new();
    let mut na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    let sync_b = sync_for(&nb, &b, &stores_b);
    auto_serve(&mut na, &a, &stores_a, Some(&sync_a));
    auto_serve(&mut nb, &b, &stores_b, Some(&sync_b));

    ensure(&na, b.id, w.network).await.unwrap();
    settle().await;
    assert_eq!(
        stores_b.rosters.seq(&w.network),
        Some(3),
        "A's Roster was pushed"
    );
}

#[tokio::test(start_paused = true)]
async fn equal_documents_on_both_sides_open_no_stream() {
    let w = world();
    let (a, b) = (party(), party());
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (stores_a, stores_b) = (stores_from(&r2, &p2), stores_from(&r2, &p2));
    let net = Net::new();
    let mut na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    let sync_b = sync_for(&nb, &b, &stores_b);
    auto_serve(&mut na, &a, &stores_a, Some(&sync_a));
    let gate_b = auto_serve(&mut nb, &b, &stores_b, Some(&sync_b));

    ensure(&na, b.id, w.network).await.unwrap();
    settle().await;
    assert_eq!(gate_b.started_by(&a.id), 0);
    // The initiator knows what the responder holds from its handshake payload; the responder
    // learns nothing of the initiator's (message 1 carries no payload).
    assert_eq!(sync_a.live_peers(w.network), vec![(b.id, Some(2))]);
    assert_eq!(sync_b.live_peers(w.network), vec![(a.id, None)]);
}

#[tokio::test(start_paused = true)]
async fn a_peer_ahead_only_in_the_policy_is_fetched_from_and_not_pushed_to() {
    let w = world();
    let (a, b) = (party(), party());
    // Both hold Roster 3 beside an older Policy: A's is 1, B's is 2.
    let (r1, p1) = w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r3, _) = w.fresh_pair(3, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (stores_a, stores_b) = (stores_from(&r1, &p1), stores_from(&r2, &p2));
    assert!(stores_a.rosters.adopt_owner(&r3, now()).unwrap());
    assert!(stores_b.rosters.adopt_owner(&r3, now()).unwrap());
    let net = Net::new();
    let mut na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    let sync_b = sync_for(&nb, &b, &stores_b);
    auto_serve(&mut na, &a, &stores_a, Some(&sync_a));
    let gate_b = auto_serve(&mut nb, &b, &stores_b, Some(&sync_b));

    ensure(&na, b.id, w.network).await.unwrap();
    settle().await;
    // One stream (the fetch). A push as well would be two.
    assert_eq!(gate_b.started_by(&a.id), 1);
}

// ---- a docs only session ------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_docs_only_push_that_was_adopted_is_followed_by_one_new_handshake() {
    let w = world();
    let (r, m) = (party(), party());
    // R is behind: its Policy has no cert for M. M holds seq 2, which has.
    let (r1, _) = w.fresh_pair(1, &[&r, &m], &[&r, &m], &[&r, &m]);
    let p1 = w.policy(&[&r, &m], &[&r], vec![]);
    let (r2, p2) = w.fresh_pair(2, &[&r, &m], &[&r, &m], &[&r, &m]);
    let (stores_r, stores_m) = (stores_from(&r1, &p1), stores_from(&r2, &p2));
    let net = Net::new();
    let mut nr = node(&net, &r, &stores_r).await;
    let mut nm = node(&net, &m, &stores_m).await;
    let sync_r = sync_for(&nr, &r, &stores_r);
    let sync_m = sync_for(&nm, &m, &stores_m);
    auto_serve(&mut nr, &r, &stores_r, Some(&sync_r));
    auto_serve(&mut nm, &m, &stores_m, Some(&sync_m));

    let since = tokio::time::Instant::now();
    assert_eq!(
        ensure(&nm, r.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    assert!(
        sync_m.wait_docs_only_push(r.id, w.network, since).await,
        "adopted and the fresh session came up: a caller may retry"
    );
    settle().await;
    assert_eq!(
        held(&stores_r, w.network),
        (Some(2), Some(2)),
        "the push was adopted"
    );
    assert_eq!(
        net.count_from(&m.id, "init"),
        2,
        "the docs only handshake and one more"
    );
    // The session the second handshake made is a full one, and no third is started.
    assert!(ensure(&nm, r.id, w.network).await.is_ok());
    assert_eq!(net.count_from(&m.id, "init"), 2);
}

#[tokio::test(start_paused = true)]
async fn a_second_docs_only_follow_up_within_a_minute_starts_no_handshake() {
    let w = world();
    let (r, m) = (party(), party());
    let (r1, p1) = w.fresh_pair(1, &[&r, &m], &[&r, &m], &[&r, &m]);
    let (stores_r, stores_m) = (stores_from(&r1, &p1), stores_from(&r1, &p1));
    let net = Net::new();
    let mut nr = node(&net, &r, &stores_r).await;
    let mut nm = node(&net, &m, &stores_m).await;
    let sync_m = sync_for(&nm, &m, &stores_m);
    auto_serve(&mut nr, &r, &stores_r, None);
    auto_serve(&mut nm, &m, &stores_m, None);
    let session = ensure(&nm, r.id, w.network).await.unwrap();
    let inits = net.count_from(&m.id, "init");

    // The follow-up is called while a session stands: it starts nothing, but is written down,
    // and says truthfully that a session is up.
    assert!(sync_m.rehandshake(r.id, w.network).await);
    assert_eq!(net.count_from(&m.id, "init"), inits);
    session.close(None);
    settle().await;
    // Within the minute the session is gone and still no new handshake starts, and none is up.
    assert!(!sync_m.rehandshake(r.id, w.network).await);
    assert_eq!(net.count_from(&m.id, "init"), inits, "the window holds");
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert!(sync_m.rehandshake(r.id, w.network).await);
    assert_eq!(
        net.count_from(&m.id, "init"),
        inits + 1,
        "after the window it may"
    );
    // Rate limited again, and a full session stands (the one just made): true (round 14 L2).
    assert!(sync_m.rehandshake(r.id, w.network).await);
    assert_eq!(net.count_from(&m.id, "init"), inits + 1);
}

#[tokio::test(start_paused = true)]
async fn a_follow_up_handshake_that_gets_no_answer_does_not_say_it_came_up() {
    let w = world();
    let (r, m) = (party(), party());
    let (r1, p1) = w.fresh_pair(1, &[&r, &m], &[&r, &m], &[&r, &m]);
    let (stores_r, stores_m) = (stores_from(&r1, &p1), stores_from(&r1, &p1));
    let net = Net::new();
    let mut nr = node(&net, &r, &stores_r).await;
    let mut nm = node(&net, &m, &stores_m).await;
    let sync_m = sync_for(&nm, &m, &stores_m);
    auto_serve(&mut nr, &r, &stores_r, None);
    auto_serve(&mut nm, &m, &stores_m, None);
    net.set_up(&r.id, false);
    assert!(!sync_m.rehandshake(r.id, w.network).await);
    assert!(net.count_from(&m.id, "init") >= 1, "a handshake was tried");
}

#[tokio::test(start_paused = true)]
async fn a_docs_only_push_that_was_not_adopted_starts_no_new_handshake() {
    let w = world();
    let (r, m) = (party(), party());
    // M has nothing newer to give: both hold seq 1, and R's Policy has no cert for M.
    let (r1, _) = w.fresh_pair(1, &[&r, &m], &[&r, &m], &[&r]);
    let p1 = w.policy(&[&r, &m], &[&r], vec![]);
    let stores_r = stores_from(&r1, &p1);
    let stores_m = stores_from(&r1, &p1);
    let net = Net::new();
    let mut nr = node(&net, &r, &stores_r).await;
    let mut nm = node(&net, &m, &stores_m).await;
    let sync_r = sync_for(&nr, &r, &stores_r);
    let sync_m = sync_for(&nm, &m, &stores_m);
    auto_serve(&mut nr, &r, &stores_r, Some(&sync_r));
    auto_serve(&mut nm, &m, &stores_m, Some(&sync_m));

    // M's own Policy has no cert for R's key either? It has R's cert only: M dials R fine.
    let since = tokio::time::Instant::now();
    assert_eq!(
        ensure(&nm, r.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    assert!(
        !sync_m.wait_docs_only_push(r.id, w.network, since).await,
        "not adopted: no retry"
    );
    // A completion older than the attempt does not count, and the wait ends at its bound.
    tokio::time::sleep(Duration::from_millis(1)).await;
    let later = tokio::time::Instant::now();
    assert!(!sync_m.wait_docs_only_push(r.id, w.network, later).await);
    assert!(later.elapsed() >= crate::docs_sync::DOCS_ONLY_WAIT);
    settle().await;
    assert_eq!(held(&stores_r, w.network), (Some(1), Some(1)));
    assert_eq!(
        net.count_from(&m.id, "init"),
        1,
        "nothing was adopted: no new handshake"
    );
}

// ---- round 14: waiters, concurrent callers, the bounds ----------------------------------

/// Delivers the first held frame of `kind` (the rest stay held).
fn pass_held(net: &Net, kind: &str) -> bool {
    let frame = {
        let mut inner = net.inner.lock().unwrap();
        let pos = inner.held.iter().position(|h| {
            let k = match E2eFrame::decode(&h.4) {
                Ok(E2eFrame::Init { .. }) => "init",
                Ok(E2eFrame::Resp { .. }) => "resp",
                Ok(E2eFrame::Data { .. }) => "data",
                Err(_) => "other",
            };
            k == kind
        });
        match pos {
            Some(p) => inner.held.remove(p),
            None => return false,
        }
    };
    net.inner.lock().unwrap().holding = false;
    net.deliver(frame.0, frame.1, frame.2, frame.3, frame.4);
    net.inner.lock().unwrap().holding = true;
    true
}

async fn pass_until(net: &Net, kind: &str) {
    for _ in 0..10_000 {
        if pass_held(net, kind) {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("no {kind} frame was held");
}

/// R is behind (its Policy has no cert for M), M holds seq 2.
async fn behind_responder() -> (
    World,
    Party,
    Party,
    Stores,
    Net,
    TestNode,
    TestNode,
    Arc<DocsSync>,
) {
    let w = world();
    let (r, m) = (party(), party());
    let (r1, _) = w.fresh_pair(1, &[&r, &m], &[&r, &m], &[&r, &m]);
    let p1 = w.policy(&[&r, &m], &[&r], vec![]);
    let (r2, p2) = w.fresh_pair(2, &[&r, &m], &[&r, &m], &[&r, &m]);
    let (stores_r, stores_m) = (stores_from(&r1, &p1), stores_from(&r2, &p2));
    let net = Net::new();
    let mut nr = node(&net, &r, &stores_r).await;
    let mut nm = node(&net, &m, &stores_m).await;
    let sync_r = sync_for(&nr, &r, &stores_r);
    let sync_m = sync_for(&nm, &m, &stores_m);
    auto_serve(&mut nr, &r, &stores_r, Some(&sync_r));
    auto_serve(&mut nm, &m, &stores_m, Some(&sync_m));
    (w, r, m, stores_r, net, nr, nm, sync_m)
}

#[tokio::test(start_paused = true)]
async fn two_callers_to_a_peer_that_is_behind_both_see_the_push_adopted() {
    let (w, r, m, _stores_r, net, _nr, nm, sync_m) = behind_responder().await;
    let (rid, nid) = (r.id, w.network);

    net.hold();
    // Caller A: its init, R's docs only resp.
    let since_a = tokio::time::Instant::now();
    let h1 = nm.handle.clone();
    let a_task = tokio::spawn(async move { h1.ensure_session(rid, nid).await.err() });
    pass_until(&net, "init").await;
    pass_until(&net, "resp").await;
    assert_eq!(a_task.await.unwrap(), Some(EnsureError::DocsOnly));
    // Caller B, a moment later: its init reaches R before any frame of A's push, so R replaces
    // A's docs only session with a second one and A's push fails.
    let since_b = tokio::time::Instant::now();
    let h2 = nm.handle.clone();
    let b_task = tokio::spawn(async move { h2.ensure_session(rid, nid).await.err() });
    pass_until(&net, "init").await;
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    net.release();
    assert_eq!(b_task.await.unwrap(), Some(EnsureError::DocsOnly));
    let wa = tokio::spawn({
        let s = sync_m.clone();
        async move { s.wait_docs_only_push(rid, nid, since_a).await }
    });
    let wb = tokio::spawn({
        let s = sync_m.clone();
        async move { s.wait_docs_only_push(rid, nid, since_b).await }
    });
    assert!(wa.await.unwrap(), "A: the second push was adopted");
    assert!(wb.await.unwrap(), "B: the second push was adopted");
    settle().await;
    // The session that came up is found without a new init.
    let inits = net.count_from(&m.id, "init");
    assert!(ensure(&nm, rid, nid).await.is_ok());
    assert_eq!(net.count_from(&m.id, "init"), inits);
}

#[tokio::test(start_paused = true)]
async fn a_waiter_at_its_bound_says_yes_while_the_follow_up_handshake_is_still_out() {
    let (w, r, m, stores_r, net, _nr, nm, sync_m) = behind_responder().await;
    let (rid, nid) = (r.id, w.network);

    net.hold();
    let since = tokio::time::Instant::now();
    let h = nm.handle.clone();
    let task = tokio::spawn(async move { h.ensure_session(rid, nid).await.err() });
    // Everything passes except the second init of M (the follow up handshake).
    for _ in 0..20_000 {
        if net.count_from(&m.id, "init") >= 2 {
            break;
        }
        if !(pass_held(&net, "init") && net.count_from(&m.id, "init") < 2
            || pass_held(&net, "resp")
            || pass_held(&net, "data"))
        {
            tokio::task::yield_now().await;
        }
    }
    assert_eq!(task.await.unwrap(), Some(EnsureError::DocsOnly));
    assert_eq!(
        net.count_from(&m.id, "init"),
        2,
        "the follow up init is out"
    );
    assert_eq!(held(&stores_r, nid), (Some(2), Some(2)), "and was adopted");
    let waited = sync_m.wait_docs_only_push(rid, nid, since).await;
    assert!(waited, "adopted, handshake pending at the bound: retry");
    assert!(since.elapsed() >= crate::docs_sync::DOCS_ONLY_WAIT);
    // The retry joins the pending handshake once the wire is back.
    net.release();
    assert!(ensure(&nm, rid, nid).await.is_ok());
}

#[tokio::test(start_paused = true)]
async fn the_memory_of_finished_pushes_evicts_the_oldest_not_all() {
    let w = world();
    let (a, b) = (party(), party());
    let stores_a = w.stores(&[&a, &b], vec![]);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let sync = sync_for(&na, &a, &stores_a);
    let since = tokio::time::Instant::now();
    let peer = |i: u32| {
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&i.to_be_bytes());
        NodeId::from(id)
    };
    // One more than the cap, one tick apart.
    for i in 0..=256u32 {
        tokio::time::sleep(Duration::from_millis(1)).await;
        sync.end_push((peer(i), w.network), u64::from(i), true);
    }
    // The newest and the second oldest are still there; only the oldest went.
    assert!(sync.wait_docs_only_push(peer(256), w.network, since).await);
    assert!(sync.wait_docs_only_push(peer(1), w.network, since).await);
    let before = tokio::time::Instant::now();
    assert!(!sync.wait_docs_only_push(peer(0), w.network, since).await);
    assert!(before.elapsed() >= crate::docs_sync::DOCS_ONLY_WAIT);
}

// ---- the registry of live sessions -----------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_end_of_an_older_session_does_not_forget_the_session_that_replaced_it() {
    let w = world();
    let (a, b) = (party(), party());
    let stores_a = w.stores(&[&a, &b], vec![]);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let sync = sync_for(&na, &a, &stores_a);

    let old = sync.register(b.id, w.network, Some(1), Some(1));
    let new = sync.register(b.id, w.network, Some(2), Some(2));
    assert_ne!(old, new);
    sync.forget(b.id, w.network, old);
    assert_eq!(sync.live_peers(w.network), vec![(b.id, Some(2))]);
    sync.forget(b.id, w.network, new);
    assert!(sync.live_peers(w.network).is_empty());
    // Another network's sessions are not this one's.
    sync.register(b.id, NetworkId::from([9u8; 32]), Some(1), Some(1));
    assert!(sync.live_peers(w.network).is_empty());
}

// ---- a Roster newer than the Policy ---------------------------------------------------

/// A holds Roster 2 beside Policy 1; B holds pair 2.
fn roster_ahead_of_policy() -> (World, Party, Party, Stores, Stores) {
    let w = world();
    let (a, b) = (party(), party());
    let (r1, p1) = w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let stores_a = stores_from(&r1, &p1);
    assert!(stores_a.rosters.adopt_owner(&r2, now()).unwrap());
    let stores_b = stores_from(&r2, &p2);
    (w, a, b, stores_a, stores_b)
}

#[tokio::test(start_paused = true)]
async fn a_policy_behind_the_roster_is_fetched_from_a_member() {
    let (w, a, b, stores_a, stores_b) = roster_ahead_of_policy();
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    auto_serve(&mut nb, &b, &stores_b, None);

    assert_eq!(held(&stores_a, w.network), (Some(2), Some(1)));
    sync_a.clone().catch_up_policy(w.network).await;
    assert_eq!(held(&stores_a, w.network), (Some(2), Some(2)));
}

#[tokio::test(start_paused = true)]
async fn nothing_is_fetched_when_the_policy_is_not_behind() {
    let w = world();
    let (a, b) = (party(), party());
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let stores_a = stores_from(&r2, &p2);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    sync_a.clone().catch_up_policy(w.network).await;
    assert_eq!(net.count_from(&a.id, "init"), 0);
}

#[tokio::test(start_paused = true)]
async fn a_newer_roster_stored_while_the_watch_runs_starts_a_policy_fetch() {
    let w = world();
    let (a, b) = (party(), party());
    let (r1, p1) = w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (stores_a, stores_b) = (stores_from(&r1, &p1), stores_from(&r2, &p2));
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    auto_serve(&mut nb, &b, &stores_b, None);
    tokio::spawn(sync_a.clone().run_roster_watch(vec![w.network]));
    settle().await;
    assert_eq!(
        held(&stores_a, w.network),
        (Some(1), Some(1)),
        "nothing to fetch yet"
    );
    assert_eq!(net.count_from(&a.id, "init"), 0);

    // The relay hands A the Roster alone.
    assert!(stores_a.rosters.adopt_owner(&r2, now()).unwrap());
    settle().await;
    assert_eq!(held(&stores_a, w.network), (Some(2), Some(2)));
}

#[tokio::test(start_paused = true)]
async fn the_watch_looks_at_start_too_and_ignores_networks_it_was_not_given() {
    let (w, a, b, stores_a, stores_b) = roster_ahead_of_policy();
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    auto_serve(&mut nb, &b, &stores_b, None);

    // Not a network of this node: nothing happens.
    tokio::spawn(
        sync_a
            .clone()
            .run_roster_watch(vec![NetworkId::from([5u8; 32])]),
    );
    settle().await;
    assert_eq!(held(&stores_a, w.network), (Some(2), Some(1)));
    assert_eq!(net.count_from(&a.id, "init"), 0);

    // Its own network: the Policy that is behind at start is fetched with no change to prompt it.
    tokio::spawn(sync_a.clone().run_roster_watch(vec![w.network]));
    settle().await;
    assert_eq!(held(&stores_a, w.network), (Some(2), Some(2)));
}

// ---- documents about to expire ------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn documents_that_expire_within_a_day_are_fetched_anew() {
    let w = world();
    let (a, b) = (party(), party());
    let day = 86_400;
    // The Policy is the one about to go: the pair expires when its earlier document does.
    let old = expiring_in(
        &w,
        w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]),
        5 * day,
        day / 2,
    );
    let (r2, p2) = w.fresh_pair(2, &[&a, &b], &[&a, &b], &[&a, &b]);
    let (stores_a, stores_b) = (stores_from(&old.0, &old.1), stores_from(&r2, &p2));
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    auto_serve(&mut nb, &b, &stores_b, None);

    let asked = sync_a.expiry_round(w.network).await;
    assert_eq!(asked, 1, "the first peer had it");
    assert_eq!(held(&stores_a, w.network), (Some(2), Some(2)));
}

#[tokio::test(start_paused = true)]
async fn a_peer_with_nothing_newer_does_not_end_the_expiry_round_and_a_live_one_is_asked_first() {
    let w = world();
    let (a, b, c) = (party(), party(), party());
    let all = [&a, &b, &c];
    let day = 86_400;
    let old = expiring_in(&w, w.fresh_pair(1, &all, &all, &all), day / 2, day / 2);
    let (r2, p2) = w.fresh_pair(2, &all, &all, &all);
    let (stores_a, stores_b, stores_c) = (
        stores_from(&old.0, &old.1),
        stores_from(&old.0, &old.1),
        stores_from(&r2, &p2),
    );
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let mut nc = node(&net, &c, &stores_c).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    auto_serve(&mut nb, &b, &stores_b, None);
    auto_serve(&mut nc, &c, &stores_c, None);
    // B is the one A has a session with: it is asked first, whatever order members come in. It
    // holds nothing newer, so C is asked too.
    sync_a.register(b.id, w.network, Some(1), Some(1));

    assert_eq!(sync_a.expiry_round(w.network).await, 2);
    assert_eq!(held(&stores_a, w.network), (Some(2), Some(2)));
}

#[tokio::test(start_paused = true)]
async fn documents_with_more_than_a_day_left_are_not_asked_about() {
    let w = world();
    let (a, b) = (party(), party());
    let day = 86_400;
    let old = expiring_in(
        &w,
        w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]),
        5 * day,
        3 * day,
    );
    let stores_a = stores_from(&old.0, &old.1);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    assert_eq!(sync_a.expiry_round(w.network).await, 0);
    assert_eq!(net.count_from(&a.id, "init"), 0);
}

#[tokio::test(start_paused = true)]
async fn the_expiry_timer_asks_again_every_half_hour_to_ninety_minutes() {
    let w = world();
    let (a, b) = (party(), party());
    let day = 86_400;
    let old = expiring_in(
        &w,
        w.fresh_pair(1, &[&a, &b], &[&a, &b], &[&a, &b]),
        day / 2,
        day / 2,
    );
    let stores_a = stores_from(&old.0, &old.1);
    let stores_b = stores_from(&old.0, &old.1);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let _nb = node(&net, &b, &stores_b).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    // B never answers.
    net.set_up(&b.id, false);
    let timer = tokio::spawn(sync_a.clone().run_expiry(w.network));

    tokio::time::sleep(Duration::from_secs(60)).await;
    let first = net.count_from(&a.id, "init");
    assert!(first > 0, "the first look comes at once");
    tokio::time::sleep(Duration::from_secs(60 * 28)).await;
    assert_eq!(
        net.count_from(&a.id, "init"),
        first,
        "nothing before half an hour"
    );
    tokio::time::sleep(Duration::from_secs(60 * 63)).await;
    assert!(
        net.count_from(&a.id, "init") > first,
        "and another by ninety minutes"
    );
    timer.abort();
}

// ---- the issuer's push ---------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn an_issuer_pushes_to_every_unrevoked_member_and_retries_one_that_was_away() {
    let w = world();
    let (a, b, c, d) = (party(), party(), party(), party());
    let all = [&a, &b, &c, &d];
    let (r1, p1) = w.fresh_pair(1, &all, &all, &all);
    let (mut r2, p2) = w.fresh_pair(2, &all, &all, &all);
    // D is revoked in the new Roster: it is not pushed to.
    let mut body = r2.decode().unwrap();
    body.revoked = vec![menzil_proto::RevokedMember {
        node_id: d.id,
        since: now(),
    }];
    body.members.retain(|m| m.node_id != d.id);
    r2 = Roster::sign(&w.owner, &body).unwrap();
    let (stores_a, stores_b, stores_c, stores_d) = (
        stores_from(&r2, &p2),
        stores_from(&r1, &p1),
        stores_from(&r1, &p1),
        stores_from(&r1, &p1),
    );
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let mut nc = node(&net, &c, &stores_c).await;
    let mut nd = node(&net, &d, &stores_d).await;
    let sync_a = sync_for(&na, &a, &stores_a);
    auto_serve(&mut nb, &b, &stores_b, None);
    auto_serve(&mut nc, &c, &stores_c, None);
    auto_serve(&mut nd, &d, &stores_d, None);
    // C is away at first.
    net.set_up(&c.id, false);

    let push = tokio::spawn({
        let sync_a = sync_a.clone();
        let network = w.network;
        async move { sync_a.push_to_members(network).await }
    });
    tokio::time::sleep(Duration::from_secs(40)).await;
    assert_eq!(held(&stores_b, w.network), (Some(2), Some(2)));
    assert_eq!(held(&stores_c, w.network), (Some(1), Some(1)), "away");
    assert_eq!(
        net.count_from(&a.id, "init"),
        1 + 3,
        "B once, C three tries; D never"
    );

    net.set_up(&c.id, true);
    let report = push.await.unwrap();
    assert_eq!(
        held(&stores_c, w.network),
        (Some(2), Some(2)),
        "after the retry"
    );
    assert_eq!(
        held(&stores_d, w.network),
        (Some(1), Some(1)),
        "revoked: left alone"
    );
    assert_eq!(
        report,
        crate::PushReport {
            done: 2,
            rejected: 0,
            gave_up: 0
        }
    );
}

// ---- whom the sync tasks may ask ------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn only_unrevoked_members_other_than_this_node_are_asked_or_pushed_to() {
    let w = world();
    let (a, b, c, d, e) = (party(), party(), party(), party(), party());
    let all = [&a, &b, &c, &d, &e];
    // E is in the Policy but not in the Roster, D is revoked; the Roster lists A to D.
    let (r, p) = w.fresh_pair(2, &all[..4], &all, &all);
    let mut body = r.decode().unwrap();
    body.revoked = vec![menzil_proto::RevokedMember {
        node_id: d.id,
        since: now(),
    }];
    body.members.retain(|m| m.node_id != d.id);
    let r = Roster::sign(&w.owner, &body).unwrap();
    let stores_a = stores_from(&r, &p);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let sync_a = sync_for(&na, &a, &stores_a);

    let mut asked = sync_a.member_peers(w.network);
    asked.sort_by_key(|id| id.to_string());
    let mut expected = vec![b.id, c.id];
    expected.sort_by_key(|id| id.to_string());
    assert_eq!(
        asked, expected,
        "not itself, not the revoked, not one the Roster lacks"
    );
    let mut pushed = sync_a.push_targets(w.network);
    pushed.sort_by_key(|id| id.to_string());
    assert_eq!(pushed, expected);
}
