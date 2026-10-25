//! Round 8: docs only sessions (admitted for a `src` that nobody has proved) must not take the
//! places of real sessions; a lying peer must not be the only one asked for the Policy; a member
//! whose own documents expired can still fetch the renewed pair.

use super::sync::{auto_serve, held, now, sync_for};
use super::*;

/// What a relay can be: an identity that carries a Roster member's NodeId but its own X25519
/// key (the relay puts the member's NodeId on the RECV `src`).
fn forged_as(member: &Party) -> Party {
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();
    let keypair = snow::Builder::new(params).generate_keypair().unwrap();
    let x25519_private = <[u8; 32]>::try_from(keypair.private).unwrap();
    let x25519_public = X25519PublicKey::from(<[u8; 32]>::try_from(keypair.public).unwrap());
    // Signed by a key that is not the member's: only decoded, never verified, on our side.
    let junk = SigningKey::generate(&mut rand::rng());
    let cert = NodeCert::sign(
        &junk,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: member.id,
            x25519_pub: x25519_public,
            serial: 1,
            not_before: 0,
            not_after: 4_000_000_000,
        },
    )
    .unwrap();
    Party {
        signing: junk,
        id: member.id,
        x25519_private,
        x25519_public,
        cert,
    }
}

/// A forged initiator for `member` against `target`: a docs only session whose one
/// `menzil:docs` stream is open and silent. Everything is returned so that it stays up.
async fn silent_forged_stream(
    net: &Net,
    member: &Party,
    target: &Party,
    w: &World,
    stores: &Stores,
) -> (TestNode, SessionReady, menzil_stream::Stream) {
    let forged = forged_as(member);
    let mut node = node(net, &forged, stores).await;
    assert_eq!(
        ensure(&node, target.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    let at = node.next_ready().await;
    assert!(at.docs_only);
    let stream = crate::l5_stream::open(&at.handle, crate::admission::docs_service(), None)
        .await
        .expect("the target lets the forged member open menzil:docs");
    (node, at, stream)
}

/// B holds the older pair, H the newer one, and `forged` members of B's network are forged by a
/// relay, each with a silent docs stream open at B. H then dials B: its push must land.
async fn honest_push_with_forged_streams(forged_members: usize, forge_the_pusher: bool) {
    let w = world();
    let (b, h) = (party(), party());
    let ms: Vec<Party> = (0..forged_members).map(|_| party()).collect();
    let mut everyone: Vec<&Party> = vec![&b, &h];
    everyone.extend(ms.iter());
    let (r1, p1) = w.fresh_pair(1, &everyone, &everyone, &everyone);
    let (r2, p2) = w.fresh_pair(2, &everyone, &everyone, &everyone);
    let stores_b = stores_from(&r1, &p1);
    let stores_h = stores_from(&r2, &p2);
    let stores_f = stores_from(&r1, &p1);
    let net = Net::new();
    let mut nb = node(&net, &b, &stores_b).await;
    auto_serve(&mut nb, &b, &stores_b, None);

    let mut held_streams = Vec::new();
    for m in &ms {
        held_streams.push(silent_forged_stream(&net, m, &b, &w, &stores_f).await);
    }
    if forge_the_pusher {
        held_streams.push(silent_forged_stream(&net, &h, &b, &w, &stores_f).await);
    }

    let mut nh = node(&net, &h, &stores_h).await;
    let sync_h = sync_for(&nh, &h, &stores_h);
    auto_serve(&mut nh, &h, &stores_h, Some(&sync_h));
    ensure(&nh, b.id, w.network).await.unwrap();
    // Less than the first message timeout: the forged streams are still silent and still open.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        held(&stores_b, w.network),
        (Some(2), Some(2)),
        "the honest push was refused"
    );
    drop(held_streams);
}

/// Control: no forged streams, the honest push lands.
#[tokio::test(start_paused = true)]
async fn an_honest_push_lands_without_forged_streams() {
    honest_push_with_forged_streams(0, false).await;
}

/// A relay forges the `src` of the one member that is ahead and holds a silent docs stream: the
/// real push of that member is not refused `rate_limited`.
#[tokio::test(start_paused = true)]
async fn a_forged_docs_only_stream_does_not_take_the_pushers_per_peer_place() {
    honest_push_with_forged_streams(0, true).await;
}

/// A relay forges four members and holds four silent docs streams: the node's four docs places
/// are not taken.
#[tokio::test(start_paused = true)]
async fn forged_docs_only_streams_do_not_take_the_nodes_docs_places() {
    honest_push_with_forged_streams(4, false).await;
}

/// A member that claims a huge `policy_seq` (handshake payload or `end`, recorded unverified)
/// is not the only peer a Policy catch-up asks: the members that hold the Policy are asked in
/// the same round.
#[tokio::test(start_paused = true)]
async fn one_lying_live_peer_does_not_suppress_the_policy_catch_up() {
    let w = world();
    let (a, liar, c) = (party(), party(), party());
    let all = [&a, &liar, &c];
    let (r1, p1) = w.fresh_pair(1, &all, &all, &all);
    let (r2, p2) = w.fresh_pair(2, &all, &all, &all);
    let stores_a = stores_from(&r1, &p1);
    assert!(stores_a.rosters.adopt_owner(&r2, now()).unwrap());
    let stores_l = stores_from(&r1, &p1);
    let stores_c = stores_from(&r2, &p2);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nl = node(&net, &liar, &stores_l).await;
    let mut nc = node(&net, &c, &stores_c).await;
    auto_serve(&mut nl, &liar, &stores_l, None);
    auto_serve(&mut nc, &c, &stores_c, None);
    let sync_a = sync_for(&na, &a, &stores_a);
    // What `serve_session` registers from the liar's handshake payload.
    sync_a.register(liar.id, w.network, Some(u64::MAX), Some(u64::MAX));

    sync_a.clone().catch_up_policy(w.network).await;
    assert_eq!(
        held(&stores_a, w.network),
        (Some(2), Some(2)),
        "the Policy was never fetched"
    );
}

/// The documents of `a` are past their `expires`; `b` holds the renewed pair.
struct ExpiredMember {
    w: World,
    a: Party,
    b: Party,
    stores_a: Stores,
    net: Net,
    na: TestNode,
    _nb: TestNode,
}

async fn expired_member_and_a_peer_with_the_renewed_pair() -> ExpiredMember {
    let w = world();
    let (a, b) = (party(), party());
    let all = [&a, &b];
    let (r1, p1) = w.fresh_pair(1, &all, &all, &all);
    let mut rb = r1.decode().unwrap();
    rb.expires = now() - 60;
    let mut pb = p1.decode().unwrap();
    pb.expires = now() - 60;
    let expired = (
        Roster::sign(&w.owner, &rb).unwrap(),
        Policy::sign(&w.owner, &pb).unwrap(),
    );
    let (r2, p2) = w.fresh_pair(2, &all, &all, &all);
    let stores_a = stores_from(&expired.0, &expired.1);
    let stores_b = stores_from(&r2, &p2);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    auto_serve(&mut nb, &b, &stores_b, None);
    ExpiredMember {
        w,
        a,
        b,
        stores_a,
        net,
        na,
        _nb: nb,
    }
}

/// A member whose own documents have expired fetches the renewed pair from a peer that holds it.
#[tokio::test(start_paused = true)]
async fn a_member_with_expired_documents_fetches_the_renewed_pair() {
    let e = expired_member_and_a_peer_with_the_renewed_pair().await;
    let sync_a = sync_for(&e.na, &e.a, &e.stores_a);
    let asked = sync_a.expiry_round(e.w.network).await;
    assert_eq!(asked, 1);
    assert_eq!(held(&e.stores_a, e.w.network), (Some(2), Some(2)));
}

/// Only the fetch gets that: any other use of a session still refuses a dial with expired
/// documents of one's own.
#[tokio::test(start_paused = true)]
async fn other_dials_with_expired_documents_are_still_refused() {
    let e = expired_member_and_a_peer_with_the_renewed_pair().await;
    assert_eq!(
        ensure(&e.na, e.b.id, e.w.network).await.err(),
        Some(EnsureError::NotAMember)
    );
    assert_eq!(e.net.frames("init").len(), 0, "nothing was sent");
    assert_eq!(held(&e.stores_a, e.w.network), (Some(1), Some(1)));
}

/// Revocation and the serial floor still count for the docs dial: a member that its own
/// (expired) Roster revoked is not dialed even to fetch.
#[tokio::test(start_paused = true)]
async fn a_docs_dial_with_expired_documents_still_refuses_a_revoked_self() {
    let w = world();
    let (a, b) = (party(), party());
    let all = [&a, &b];
    let (r1, p1) = w.fresh_pair(1, &all, &all, &all);
    let mut rb = r1.decode().unwrap();
    rb.expires = now() - 60;
    rb.revoked.push(menzil_proto::RevokedMember {
        node_id: a.id,
        since: now() - 100,
    });
    let mut pb = p1.decode().unwrap();
    pb.expires = now() - 60;
    let stores_a = stores_from(
        &Roster::sign(&w.owner, &rb).unwrap(),
        &Policy::sign(&w.owner, &pb).unwrap(),
    );
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    assert_eq!(
        na.handle
            .ensure_session_for_docs(b.id, w.network)
            .await
            .err(),
        Some(EnsureError::NotAMember)
    );
}

/// A session the peer started never replaces or removes the entry of one this node started.
#[tokio::test(start_paused = true)]
async fn a_responder_session_does_not_overwrite_or_remove_the_initiator_entry() {
    let w = world();
    let (a, b) = (party(), party());
    let all = [&a, &b];
    let (r1, p1) = w.fresh_pair(1, &all, &all, &all);
    let stores_a = stores_from(&r1, &p1);
    let net = Net::new();
    let na = node(&net, &a, &stores_a).await;
    let sync = sync_for(&na, &a, &stores_a);

    let ours = sync.register_as(b.id, w.network, true, Some(1), Some(7));
    let theirs = sync.register_as(b.id, w.network, false, Some(1), Some(1));
    assert_eq!(
        sync.live_peers(w.network),
        vec![(b.id, Some(7))],
        "the initiator entry's claim is not overwritten"
    );
    sync.forget(b.id, w.network, theirs);
    assert_eq!(
        sync.live_peers(w.network),
        vec![(b.id, Some(7))],
        "forgetting the responder session leaves ours"
    );
    sync.forget(b.id, w.network, ours);
    assert!(sync.live_peers(w.network).is_empty());
}
