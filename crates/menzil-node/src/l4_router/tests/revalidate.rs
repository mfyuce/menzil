//! The revalidator (L4k K4) over the routers of the parent module: real sessions between two
//! in-memory nodes, B serving with a [`Revalidator`] and A observing. What a pass decides for
//! each kind of session (`plan`), that the running task acts on a change of either store and on
//! a session that registers late, that the sweep is a safety net, and that a session leaves the
//! registry when it ends. The pure deadline arithmetic is in `revalidate.rs`; real time (a grant
//! that expires) is in `tests/grant_expiry_live.rs`.

use super::*;
use crate::docs_access::{DocsGate, DocsLimits};
use crate::l5_stream::open as open_stream;
use crate::node::serve_session;
use crate::revalidate::{Action, Kind, Revalidator};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use std::sync::atomic::Ordering;

/// A service handler that accepts every stream and holds it open until its task is dropped,
/// which is what resets it.
struct Hold;

impl ServiceHandler<Stream> for Hold {
    type Opened = ();
    type Handling = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    async fn open(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Ok(())
    }

    fn handle(&self, stream: Stream, _request: OpenRequest, _opened: ()) -> Self::Handling {
        Box::pin(async move {
            let _stream = stream;
            std::future::pending::<()>().await;
        })
    }
}

fn grant_for(w: &World, from: &Party, to: &Party, services: &[&str]) -> Grant {
    Grant {
        from: Principal {
            network_id: w.network,
            target: PrincipalTarget::Node(from.id),
        },
        to_node: NodeOrWildcard::Node(to.id),
        services: services.iter().map(|s| s.parse().unwrap()).collect(),
        expires: None,
    }
}

fn edit_policy_of(w: &World, stores: &Stores, edit: impl FnOnce(&mut PolicyBody)) {
    let mut body = stores.policies.body(&w.network).unwrap().as_ref().clone();
    body.seq += 1;
    edit(&mut body);
    assert!(
        stores
            .policies
            .set(&Policy::sign(&w.owner, &body).unwrap())
            .unwrap()
    );
}

/// Replaces the Policy certificate of `who` with one changed by `edit`, re signed by `who`.
fn change_cert_of(
    w: &World,
    stores: &Stores,
    who: &Party,
    edit: impl Fn(&mut menzil_proto::NodeCertBody),
) {
    edit_policy_of(w, stores, |body| {
        for cert in &mut body.certs {
            let mut cert_body = cert.decode().unwrap();
            if cert_body.node_id == who.id {
                edit(&mut cert_body);
                *cert = NodeCert::sign(&who.signing, &cert_body).unwrap();
            }
        }
    });
}

fn revoke_in(w: &World, stores: &Stores, who: NodeId) {
    edit_roster_of(w, stores, |body| {
        body.revoked.push(menzil_proto::RevokedMember {
            node_id: who,
            since: 0,
        });
    });
}

/// B serves what A opens, with a revalidator at B.
struct Live {
    w: World,
    a: Party,
    b: Party,
    stores_a: Stores,
    stores_b: Stores,
    _net: Net,
    _na: TestNode,
    _nb: TestNode,
    /// A's end of the session, to open streams on.
    handle_a: L4SessionHandle,
    /// A's acceptor, never served: it only tells how the session ended.
    ready_a: SessionReady,
    reval: Arc<Revalidator>,
    ready_b: Option<SessionReady>,
}

async fn live(grants: impl FnOnce(&World, &Party, &Party) -> Vec<Grant>) -> Live {
    let w = world();
    let (a, b) = (party(), party());
    let grants = grants(&w, &a, &b);
    let stores_a = w.stores(&[&a, &b], grants.clone());
    let stores_b = w.stores(&[&a, &b], grants);
    let net = Net::new();
    let mut na = node(&net, &a, &stores_a).await;
    let mut nb = node(&net, &b, &stores_b).await;
    let handle_a = ensure(&na, b.id, w.network).await.unwrap();
    let ready_a = na.next_ready().await;
    let ready_b = nb.next_ready().await;
    let reval = Revalidator::new(
        stores_b.policies.clone(),
        stores_b.rosters.clone(),
        b.id,
        1,
        b.x25519_public,
    );
    Live {
        w,
        a,
        b,
        stores_a,
        stores_b,
        _net: net,
        _na: na,
        _nb: nb,
        handle_a,
        ready_a,
        reval,
        ready_b: Some(ready_b),
    }
}

impl Live {
    /// Starts serving B's end of the session with the revalidator.
    fn serve_b(&mut self) {
        let ready = self.ready_b.take().expect("served once");
        serve_session(
            ready,
            &self.stores_b.policies,
            &self.stores_b.rosters,
            self.b.id,
            1,
            self.b.x25519_public,
            &Arc::new(Hold),
            &DocsGate::new(DocsLimits::default()),
            None,
            Some(&self.reval),
        );
    }
}

fn service(s: &str) -> menzil_proto::ServiceId {
    s.parse().unwrap()
}

// ---- what a pass decides ----------------------------------------------------

type Edit = fn(&Live);

#[tokio::test(start_paused = true)]
async fn a_full_session_is_closed_or_rechecked_by_the_documents_held() {
    let cases: Vec<(&str, Edit, u64, Action)> = vec![
        ("nothing changed", |_| {}, 1_000, Action::Recheck),
        (
            "the peer is revoked",
            |l| revoke_in(&l.w, &l.stores_b, l.a.id),
            1_000,
            Action::Close(ErrorCode::Revoked),
        ),
        (
            "the peer is dropped from the Roster",
            |l| {
                edit_roster_of(&l.w, &l.stores_b, |b| {
                    b.members.retain(|m| m.node_id != l.a.id);
                })
            },
            1_000,
            Action::Close(ErrorCode::NotMember),
        ),
        (
            "the peer is dropped from the Policy",
            |l| {
                edit_policy_of(&l.w, &l.stores_b, |b| {
                    b.members.retain(|m| m.node_id != l.a.id);
                })
            },
            1_000,
            Action::Close(ErrorCode::NotMember),
        ),
        (
            "the peer's cert is gone from the Policy",
            |l| {
                edit_policy_of(&l.w, &l.stores_b, |b| {
                    b.certs.retain(|c| c.decode().unwrap().node_id != l.a.id);
                })
            },
            1_000,
            Action::Close(ErrorCode::BadCert),
        ),
        (
            "the peer's cert has expired",
            |_| {},
            4_000_000_001,
            Action::Close(ErrorCode::BadCert),
        ),
        (
            "the peer's min_serial is above its cert",
            |l| {
                edit_roster_of(&l.w, &l.stores_b, |b| {
                    for m in &mut b.members {
                        if m.node_id == l.a.id {
                            m.min_serial = 2;
                        }
                    }
                })
            },
            1_000,
            Action::Close(ErrorCode::StaleSerial),
        ),
        (
            "this node is revoked",
            |l| revoke_in(&l.w, &l.stores_b, l.b.id),
            1_000,
            Action::Close(ErrorCode::Revoked),
        ),
        (
            "this node's min_serial is above its cert",
            |l| {
                edit_roster_of(&l.w, &l.stores_b, |b| {
                    for m in &mut b.members {
                        if m.node_id == l.b.id {
                            m.min_serial = 2;
                        }
                    }
                })
            },
            1_000,
            Action::Close(ErrorCode::StaleSerial),
        ),
        (
            "this node is dropped from the Policy",
            |l| {
                edit_policy_of(&l.w, &l.stores_b, |b| {
                    b.members.retain(|m| m.node_id != l.b.id);
                })
            },
            1_000,
            Action::Close(ErrorCode::NotMember),
        ),
        (
            "this node's own cert is gone from the Policy (round 11 N1)",
            |l| {
                edit_policy_of(&l.w, &l.stores_b, |b| {
                    b.certs.retain(|c| c.decode().unwrap().node_id != l.b.id);
                })
            },
            1_000,
            Action::Close(ErrorCode::BadCert),
        ),
        (
            "this node's own cert in the Policy has run out",
            |l| change_cert_of(&l.w, &l.stores_b, &l.b, |c| c.not_after = 500),
            1_000,
            Action::Close(ErrorCode::BadCert),
        ),
        (
            "this node's own cert in the Policy names another key",
            |l| {
                change_cert_of(&l.w, &l.stores_b, &l.b, |c| {
                    c.x25519_pub = X25519PublicKey::from([0x77; 32]);
                })
            },
            1_000,
            Action::Close(ErrorCode::BadCert),
        ),
        (
            "the grant is removed: the streams are asked again, the session stays",
            |l| edit_policy_of(&l.w, &l.stores_b, |b| b.grants.clear()),
            1_000,
            Action::Recheck,
        ),
        (
            "the documents have expired: no session ends",
            |l| {
                edit_roster_of(&l.w, &l.stores_b, |b| b.expires = 1);
                edit_policy_of(&l.w, &l.stores_b, |b| b.expires = 1);
            },
            1_000,
            Action::Recheck,
        ),
    ];
    for (label, edit, now, expected) in cases {
        let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
        live.serve_b();
        edit(&live);
        assert_eq!(
            live.reval.plan(&live.w.network, now),
            vec![(0, expected)],
            "{label}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_pass_over_another_network_plans_nothing() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    live.serve_b();
    assert!(
        live.reval
            .plan(&NetworkId::from([9u8; 32]), 1_000)
            .is_empty()
    );
}

/// A docs only session exists for a peer the Policy cannot vouch for, or a node the Policy does
/// not list yet; the full rules would end it before the push it is for.
#[tokio::test(start_paused = true)]
async fn a_docs_only_session_is_judged_by_the_roster_alone() {
    let w = world();
    let (r, m) = (party(), party());
    // R's Roster lists both; its older Policy lists M with a cert but not R itself.
    let r_stores = w.split_stores(&[&r, &m], &[&m], &[&m]);
    let m_stores = w.stores(&[&r, &m], vec![]);
    let net = Net::new();
    let mut nm = node(&net, &m, &m_stores).await;
    let mut nr = node(&net, &r, &r_stores).await;
    assert_eq!(
        ensure(&nm, r.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    let at_r = nr.next_ready().await;
    let _at_m = nm.next_ready().await;
    assert!(at_r.docs_only);

    let reval = Revalidator::new(
        r_stores.policies.clone(),
        r_stores.rosters.clone(),
        r.id,
        1,
        r.x25519_public,
    );
    serve_session(
        at_r,
        &r_stores.policies,
        &r_stores.rosters,
        r.id,
        1,
        r.x25519_public,
        &Arc::new(Hold),
        &DocsGate::new(DocsLimits::default()),
        None,
        Some(&reval),
    );
    // Neither side is in good standing by the full rules (R is missing from its Policy), and the
    // session is fine: nothing to do.
    assert_eq!(reval.plan(&w.network, 1_000), vec![]);
    // The Roster is another matter.
    revoke_in(&w, &r_stores, m.id);
    assert_eq!(
        reval.plan(&w.network, 1_000),
        vec![(0, Action::Close(ErrorCode::Revoked))]
    );
}

#[tokio::test(start_paused = true)]
async fn a_docs_only_session_ends_when_this_node_loses_its_standing_in_the_roster() {
    let w = world();
    let (r, m) = (party(), party());
    let r_stores = w.split_stores(&[&r, &m], &[&m], &[&m]);
    let m_stores = w.stores(&[&r, &m], vec![]);
    let net = Net::new();
    let mut nm = node(&net, &m, &m_stores).await;
    let mut nr = node(&net, &r, &r_stores).await;
    assert_eq!(
        ensure(&nm, r.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    let at_r = nr.next_ready().await;
    let _at_m = nm.next_ready().await;
    let reval = Revalidator::new(
        r_stores.policies.clone(),
        r_stores.rosters.clone(),
        r.id,
        1,
        r.x25519_public,
    );
    serve_session(
        at_r,
        &r_stores.policies,
        &r_stores.rosters,
        r.id,
        1,
        r.x25519_public,
        &Arc::new(Hold),
        &DocsGate::new(DocsLimits::default()),
        None,
        Some(&reval),
    );
    edit_roster_of(&w, &r_stores, |b| {
        for member in &mut b.members {
            if member.node_id == r.id {
                member.min_serial = 2;
            }
        }
    });
    assert_eq!(
        reval.plan(&w.network, 1_000),
        vec![(0, Action::Close(ErrorCode::StaleSerial))]
    );
}

/// The initiator of a docs only session is registered too: when its own Roster revokes the
/// responder, the session goes.
#[tokio::test(start_paused = true)]
async fn the_initiator_of_a_docs_only_session_is_watched_as_well() {
    let w = world();
    let (r, m) = (party(), party());
    let r_stores = w.split_stores(&[&r, &m], &[&m], &[&m]);
    let m_stores = w.stores(&[&r, &m], vec![]);
    let net = Net::new();
    let mut nm = node(&net, &m, &m_stores).await;
    let _nr = node(&net, &r, &r_stores).await;
    assert_eq!(
        ensure(&nm, r.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    let at_m = nm.next_ready().await;
    assert!(at_m.docs_only && at_m.role == Role::Initiator);
    let reval = Revalidator::new(
        m_stores.policies.clone(),
        m_stores.rosters.clone(),
        m.id,
        1,
        m.x25519_public,
    );
    serve_session(
        at_m,
        &m_stores.policies,
        &m_stores.rosters,
        m.id,
        1,
        m.x25519_public,
        &Arc::new(Hold),
        &DocsGate::new(DocsLimits::default()),
        None,
        Some(&reval),
    );
    assert_eq!(reval.plan(&w.network, 1_000), vec![]);
    revoke_in(&w, &m_stores, r.id);
    assert_eq!(
        reval.plan(&w.network, 1_000),
        vec![(0, Action::Close(ErrorCode::Revoked))]
    );
}

/// The window the docs only rules exist for: R's Roster lists it, its older Policy does not, and
/// the push that brings the Policy is taken.
#[tokio::test(start_paused = true)]
async fn a_docs_only_push_is_taken_by_a_node_its_own_policy_does_not_list_yet() {
    let w = world();
    let (r, m) = (party(), party());
    let (r1, _) = w.fresh_pair(1, &[&r, &m], &[&m], &[&m]);
    let p1 = w.policy(&[&m], &[&m], vec![]);
    let (r2, p2) = w.fresh_pair(2, &[&r, &m], &[&r, &m], &[&r, &m]);
    let (stores_r, stores_m) = (stores_from(&r1, &p1), stores_from(&r2, &p2));
    let net = Net::new();
    let mut nr = node(&net, &r, &stores_r).await;
    let mut nm = node(&net, &m, &stores_m).await;
    assert_eq!(
        ensure(&nm, r.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    let mut at_m = nm.next_ready().await;
    let at_r = nr.next_ready().await;
    let reval = Revalidator::new(
        stores_r.policies.clone(),
        stores_r.rosters.clone(),
        r.id,
        1,
        r.x25519_public,
    );
    tokio::spawn(reval.clone().run());
    let handle = at_m.handle.clone();
    let mut closed = std::pin::pin!(at_m.acceptor.closed());
    serve_session(
        at_r,
        &stores_r.policies,
        &stores_r.rosters,
        r.id,
        1,
        r.x25519_public,
        &Arc::new(Hold),
        &DocsGate::new(DocsLimits::default()),
        None,
        Some(&reval),
    );

    let source = crate::docs::StoreDocs::new(&stores_m.rosters, &stores_m.policies, w.network);
    let bundle = crate::docs::bundle_to_push(&source, docs_params(w.network).now);
    let mut docs = open_stream(&handle, crate::docs_service(), None)
        .await
        .expect("R is in the Roster: it takes the push");
    let result = crate::docs::push(&mut docs, &bundle, &docs_params(w.network))
        .await
        .unwrap();
    assert_eq!(result.policy, menzil_proto::docs::Outcome::Adopted);
    assert_eq!(stores_r.policies.seq(&w.network), Some(2));
    docs.close().await.unwrap();
    let reason = timeout(Duration::from_secs(5), &mut closed)
        .await
        .expect("the session ends with the push");
    assert!(
        matches!(
            reason.as_ref(),
            EndReason::PeerClosed {
                code: ErrorCode::DocsOnly,
                ..
            }
        ),
        "the revalidator must not have ended it first: {reason:?}"
    );
}

// ---- the running task -------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_roster_that_revokes_the_peer_ends_the_session_and_the_registry_lets_go_of_it() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    tokio::spawn(live.reval.clone().run());
    live.serve_b();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(live.reval.session_count(), 1);
    // The session is fine until the Roster says otherwise.
    assert!(
        timeout(Duration::from_secs(3), live.ready_a.acceptor.closed())
            .await
            .is_err()
    );

    revoke_in(&live.w, &live.stores_b, live.a.id);
    match ended(&mut live.ready_a.acceptor).await.as_ref() {
        EndReason::PeerClosed { code, .. } => assert_eq!(*code, ErrorCode::GrantRemoved),
        other => panic!("expected the peer's close with grant_removed, got {other:?}"),
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        live.reval.session_count(),
        0,
        "an ended session leaves the registry"
    );
}

#[tokio::test(start_paused = true)]
async fn a_policy_without_the_grant_resets_that_stream_only_and_the_session_stays() {
    let mut live = live(|w, a, b| {
        vec![
            grant_for(w, a, b, &["tcp:ssh"]),
            grant_for(w, a, b, &["tcp:web"]),
        ]
    })
    .await;
    tokio::spawn(live.reval.clone().run());
    live.serve_b();
    let mut ssh = open_stream(&live.handle_a, service("tcp:ssh"), None)
        .await
        .unwrap();
    let mut web = open_stream(&live.handle_a, service("tcp:web"), None)
        .await
        .unwrap();

    // Only the Policy changes: the Roster is as it was, and the store that signals is the
    // Policy's.
    let ssh_grant = grant_for(&live.w, &live.a, &live.b, &["tcp:ssh"]);
    edit_policy_of(&live.w, &live.stores_b, |b| {
        b.grants.retain(|g| g != &ssh_grant);
    });

    let mut byte = [0u8; 1];
    let error = timeout(Duration::from_secs(2), ssh.read(&mut byte))
        .await
        .expect("the stream whose grant went is reset at once")
        .expect_err("a reset, not an end of file");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(
        timeout(Duration::from_secs(2), web.read(&mut byte))
            .await
            .is_err(),
        "the other stream goes on"
    );
    // The session stays and the grant is refused from now on, while menzil:docs is served.
    assert!(
        timeout(Duration::from_secs(1), live.ready_a.acceptor.closed())
            .await
            .is_err()
    );
    match open_stream(&live.handle_a, service("tcp:ssh"), None).await {
        Err(crate::l5_stream::OpenStreamError::Refused { code, .. }) => {
            assert_eq!(code, ErrorCode::NoGrant)
        }
        other => panic!("expected no_grant, got {:?}", other.map(|_| ())),
    }
    assert!(
        open_stream(&live.handle_a, crate::docs_service(), None)
            .await
            .is_ok(),
        "a member with no grant still fetches documents"
    );
    drop(web);
}

#[tokio::test(start_paused = true)]
async fn a_roster_alone_that_revokes_this_node_ends_a_session_it_initiated() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    // A's side: A is the initiator here, and its own Roster revokes it.
    let reval_a = Revalidator::new(
        live.stores_a.policies.clone(),
        live.stores_a.rosters.clone(),
        live.a.id,
        1,
        live.a.x25519_public,
    );
    tokio::spawn(reval_a.clone().run());
    let ready_a = std::mem::replace(
        &mut live.ready_a,
        // B's end, left unserved, tells how the session ended.
        live.ready_b.take().unwrap(),
    );
    assert_eq!(ready_a.role, Role::Initiator);
    serve_session(
        ready_a,
        &live.stores_a.policies,
        &live.stores_a.rosters,
        live.a.id,
        1,
        live.a.x25519_public,
        &Arc::new(Hold),
        &DocsGate::new(DocsLimits::default()),
        None,
        Some(&reval_a),
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    revoke_in(&live.w, &live.stores_a, live.a.id);
    match ended(&mut live.ready_a.acceptor).await.as_ref() {
        EndReason::PeerClosed { code, .. } => assert_eq!(*code, ErrorCode::GrantRemoved),
        other => panic!("expected the peer's close with grant_removed, got {other:?}"),
    }
}

/// The documents may change between the router's decision and the registration: the
/// registration alone has the network looked at, no notice of a change will come.
#[tokio::test(start_paused = true)]
async fn a_session_that_registers_after_the_documents_changed_is_checked_at_once() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    tokio::spawn(live.reval.clone().run());
    tokio::time::sleep(Duration::from_secs(1)).await;
    revoke_in(&live.w, &live.stores_b, live.a.id);
    tokio::time::sleep(Duration::from_secs(1)).await;
    live.serve_b();
    match ended(&mut live.ready_a.acceptor).await.as_ref() {
        EndReason::PeerClosed { code, .. } => assert_eq!(*code, ErrorCode::GrantRemoved),
        other => panic!("expected the peer's close with grant_removed, got {other:?}"),
    }
}

/// The sweep looks at every network with a session whatever else happens.
#[tokio::test(start_paused = true)]
async fn the_sweep_looks_again_at_every_session_on_its_interval() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    live.reval = Revalidator::with_sweep(
        live.stores_b.policies.clone(),
        live.stores_b.rosters.clone(),
        live.b.id,
        1,
        live.b.x25519_public,
        Duration::from_secs(60),
    );
    tokio::spawn(live.reval.clone().run());
    live.serve_b();
    tokio::time::sleep(Duration::from_secs(5)).await;
    let after_registration = live.reval.passes();
    assert!(after_registration >= 1, "the registration is a pass");

    tokio::time::sleep(Duration::from_secs(30)).await;
    assert_eq!(
        live.reval.passes(),
        after_registration,
        "not before it is due"
    );
    tokio::time::sleep(Duration::from_secs(35)).await;
    assert_eq!(
        live.reval.passes(),
        after_registration + 1,
        "one pass for the one network, at the sweep"
    );
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(live.reval.passes(), after_registration + 2);
}

// ---- round 11: cost, own certificate, supervision ----------------------------------

fn full_kind(live: &Live) -> Kind {
    Kind::Full {
        streams: crate::l5_stream::AcceptedStreams::new(),
        authorizer: crate::PolicyAuthorizer::new(
            live.stores_b.policies.clone(),
            live.stores_b.rosters.clone(),
            live.w.network,
            live.b.id,
            1,
            live.b.x25519_public,
        ),
    }
}

/// L1: the certificates of a Policy are decoded once, when it is adopted; judging sessions,
/// however many, and working out the next deadline decode none.
#[tokio::test(start_paused = true)]
async fn judging_decodes_no_certificate_however_many_sessions_there_are() {
    use crate::cert_index::decodes_on_this_thread;
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    live.serve_b();
    let network = live.w.network;
    let built = decodes_on_this_thread();
    assert!(built >= 2, "the adopted Policy was indexed: {built}");
    assert_eq!(live.reval.plan(&network, 1_000).len(), 1);
    assert_eq!(decodes_on_this_thread(), built, "one session");
    for _ in 0..40 {
        live.reval.register(
            live.a.id,
            network,
            live.a.x25519_public,
            live.handle_a.clone(),
            full_kind(&live),
        );
    }
    assert_eq!(live.reval.plan(&network, 1_000).len(), 41);
    live.reval.deadline(&network, 1_000);
    assert_eq!(decodes_on_this_thread(), built, "forty one sessions");
    // A newer Policy is indexed once, on adoption.
    edit_policy_of(&live.w, &live.stores_b, |b| b.issued += 1);
    let adopted = decodes_on_this_thread();
    assert_eq!(adopted, built + 2, "the new Policy's two certificates");
    assert_eq!(live.reval.plan(&network, 1_000).len(), 41);
    assert_eq!(decodes_on_this_thread(), adopted);
}

/// L1: the sessions are judged without the registry lock, so `register` and `forget` never wait
/// for a pass.
#[tokio::test(start_paused = true)]
async fn sessions_are_judged_without_the_registry_lock() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    live.serve_b();
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let (reval, seen) = (Arc::downgrade(&live.reval), seen.clone());
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            let free = reval.upgrade().is_some_and(|reval| reval.state_is_free());
            seen.lock().unwrap().push(free);
        });
        *live.reval.judge_hook.lock().unwrap() = Some(hook);
    }
    assert_eq!(live.reval.plan(&live.w.network, 1_000).len(), 1);
    assert_eq!(*seen.lock().unwrap(), vec![true], "judged once, lock free");
}

/// L1: a pass runs on the blocking pool, not on the runtime worker that runs the task.
#[tokio::test]
async fn a_pass_runs_off_the_runtime_worker() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    tokio::spawn(live.reval.clone().run());
    live.serve_b();
    wait_for(|| live.reval.passes() >= 1).await;
    let ran_on = live.reval.last_pass_thread.lock().unwrap().unwrap();
    assert_ne!(ran_on, std::thread::current().id());
}

async fn wait_for(mut done: impl FnMut() -> bool) {
    for _ in 0..1_000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("gave up waiting");
}

/// A panic in the revalidator is survived: the task starts again with every network looked at,
/// and keeps acting on changes.
#[tokio::test]
async fn a_panic_in_the_revalidator_restarts_it_with_every_network_looked_at() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    live.serve_b();
    live.reval.panic_next_pass.store(true, Ordering::SeqCst);
    let task = tokio::spawn(live.reval.clone().run());
    // The pass the registration asked for panics; nothing else is pending, so only the restart's
    // look at every network makes a second one.
    wait_for(|| live.reval.passes() >= 2).await;
    assert!(!task.is_finished(), "the supervisor goes on");
    // And the restarted task still acts on a change.
    revoke_in(&live.w, &live.stores_b, live.a.id);
    match ended(&mut live.ready_a.acceptor).await.as_ref() {
        EndReason::PeerClosed { code, .. } => assert_eq!(*code, ErrorCode::GrantRemoved),
        other => panic!("expected the peer's close with grant_removed, got {other:?}"),
    }
    task.abort();
}

const T_INITIAL: Duration = Duration::from_millis(40);
const T_MAX: Duration = Duration::from_millis(160);

/// The same revalidator with short restart waits, serving B's end.
fn timed(live: &mut Live) {
    live.reval = Revalidator::with_timing(
        live.stores_b.policies.clone(),
        live.stores_b.rosters.clone(),
        live.b.id,
        1,
        live.b.x25519_public,
        Duration::from_secs(300),
        (T_INITIAL, T_MAX),
    );
    live.serve_b();
}

/// The wait before a restart: the first is `initial`, a panic in a row doubles it, the longest
/// is `max`, and a run that completed a pass starts over at `initial`.
#[test]
fn the_restart_wait_doubles_is_capped_and_resets_after_progress() {
    use crate::revalidate::restart_delay;
    let (i, m) = (Duration::from_millis(100), Duration::from_secs(30));
    assert_eq!(restart_delay(None, false, i, m), i, "the first panic");
    assert_eq!(restart_delay(None, true, i, m), i);
    assert_eq!(restart_delay(Some(i), false, i, m), 2 * i, "doubles");
    assert_eq!(restart_delay(Some(4 * i), false, i, m), 8 * i);
    assert_eq!(restart_delay(Some(m), false, i, m), m, "capped");
    assert_eq!(restart_delay(Some(Duration::from_secs(20)), false, i, m), m);
    assert_eq!(restart_delay(Some(8 * i), true, i, m), i, "progress resets");
    assert_eq!(restart_delay(Some(m), true, i, m), i);
    // Neither overflows nor passes the maximum when the maximum is the smaller.
    assert_eq!(restart_delay(Some(Duration::MAX), false, i, m), m);
    assert_eq!(restart_delay(None, false, m, i), i);
}

/// A panic that every pass hits does not make a busy loop: the waits between restarts double up
/// to the maximum, and each restart really waits that long.
#[tokio::test]
async fn a_persistent_panic_restarts_with_growing_waits() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    timed(&mut live);
    live.reval
        .panic_passes_left
        .store(u32::MAX, Ordering::SeqCst);
    let task = tokio::spawn(live.reval.clone().run());
    wait_for(|| live.reval.restart_waits.lock().unwrap().len() >= 6).await;
    task.abort();
    let waits = live.reval.restart_waits.lock().unwrap().clone();
    let ms = |n: u64| Duration::from_millis(n);
    assert_eq!(
        waits[..6],
        [ms(40), ms(80), ms(160), ms(160), ms(160), ms(160)],
        "doubling, then the cap"
    );
    // Each pass began no sooner than the wait after the one before it.
    let starts = live.reval.pass_starts.lock().unwrap().clone();
    assert!(starts.len() >= 6, "{} passes", starts.len());
    for (n, wait) in waits.iter().take(starts.len() - 1).enumerate() {
        let gap = starts[n + 1] - starts[n];
        assert!(
            gap + Duration::from_millis(2) >= *wait,
            "restart {n} came after {gap:?}, the wait was {wait:?}"
        );
    }
}

/// A run that completed a pass before it panicked again starts the waits over.
#[tokio::test]
async fn a_pass_that_completes_resets_the_restart_wait() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    timed(&mut live);
    // Two panics in a row (waits of 40 and 80 ms), then a pass that completes.
    live.reval.panic_passes_left.store(2, Ordering::SeqCst);
    let task = tokio::spawn(live.reval.clone().run());
    wait_for(|| live.reval.completed_passes() >= 1).await;
    // A pass that follows panics for a new reason.
    live.reval.panic_next_pass.store(true, Ordering::SeqCst);
    revoke_in(&live.w, &live.stores_b, live.a.id);
    wait_for(|| live.reval.restart_waits.lock().unwrap().len() >= 3).await;
    task.abort();
    let waits = live.reval.restart_waits.lock().unwrap().clone();
    assert_eq!(waits[0], T_INITIAL);
    assert_eq!(waits[1], 2 * T_INITIAL);
    assert_eq!(
        waits[2], T_INITIAL,
        "a completed pass starts the waits over"
    );
}

/// Round 13 L2: one network whose pass always panics, next to one whose pass completes. The
/// networks are judged in no set order; a completed pass of the good one must not start the
/// waits over, or the node restarts several times a second. The waits double to the cap.
#[tokio::test]
async fn a_bad_network_next_to_a_good_one_does_not_reset_the_restart_wait() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    timed(&mut live);
    let bad = NetworkId::from([0x5au8; 32]);
    *live.reval.panic_network.lock().unwrap() = Some(bad);
    live.reval.register(
        live.a.id,
        bad,
        live.a.x25519_public,
        live.handle_a.clone(),
        Kind::DocsOnly,
    );
    let task = tokio::spawn(live.reval.clone().run());
    wait_for(|| live.reval.restart_waits.lock().unwrap().len() >= 12).await;
    task.abort();
    let waits = live.reval.restart_waits.lock().unwrap().clone();
    let ms = |n: u64| Duration::from_millis(n);
    assert_eq!(
        waits[..8],
        [
            ms(40),
            ms(80),
            ms(160),
            ms(160),
            ms(160),
            ms(160),
            ms(160),
            ms(160)
        ],
        "doubling, then the cap, whichever network was judged first"
    );
    assert!(
        waits.iter().all(|w| *w >= T_INITIAL && *w <= T_MAX),
        "{waits:?}"
    );
}

/// A run that judged everything due after its restart, and panics later for a new reason, starts
/// the waits over (this is what `a_pass_that_completes_resets_the_restart_wait` also shows, with
/// one network): here the restart is clean, with two networks.
#[tokio::test]
async fn a_restart_that_judged_every_network_resets_the_restart_wait() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    timed(&mut live);
    let other = NetworkId::from([0x5au8; 32]);
    live.reval.register(
        live.a.id,
        other,
        live.a.x25519_public,
        live.handle_a.clone(),
        Kind::DocsOnly,
    );
    // The first pass panics, then the restart's pass over both networks panics once more (its
    // first network), then everything completes.
    live.reval.panic_passes_left.store(2, Ordering::SeqCst);
    let task = tokio::spawn(live.reval.clone().run());
    wait_for(|| live.reval.completed_passes() >= 2).await;
    live.reval.panic_next_pass.store(true, Ordering::SeqCst);
    revoke_in(&live.w, &live.stores_b, live.a.id);
    wait_for(|| live.reval.restart_waits.lock().unwrap().len() >= 3).await;
    task.abort();
    let waits = live.reval.restart_waits.lock().unwrap().clone();
    assert_eq!(
        waits[..3],
        [T_INITIAL, 2 * T_INITIAL, T_INITIAL],
        "{waits:?}"
    );
}

/// Dropping the supervisor drops the work: the node aborts the one task it holds, and the task
/// it supervises goes with it (each holds an `Arc` of the revalidator).
#[tokio::test]
async fn aborting_the_revalidator_stops_the_task_it_supervises() {
    let live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    let base = Arc::strong_count(&live.reval);
    let task = tokio::spawn(live.reval.clone().run());
    wait_for(|| Arc::strong_count(&live.reval) > base + 1).await;
    task.abort();
    let _ = task.await;
    wait_for(|| Arc::strong_count(&live.reval) == base).await;
}

/// N1 (deadline): this node's own certificate running out is an instant to wake for.
#[tokio::test(start_paused = true)]
async fn this_nodes_own_certificate_expiry_is_a_deadline() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    live.serve_b();
    let network = live.w.network;
    assert_eq!(live.reval.deadline(&network, 100), Some(4_000_000_000));
    change_cert_of(&live.w, &live.stores_b, &live.b, |c| c.not_after = 500);
    assert_eq!(live.reval.deadline(&network, 100), Some(501));
}

/// N1 (responder): a node whose own Policy does not carry its certificate takes only the docs
/// push; a session it would have to end at once is not started.
#[tokio::test(start_paused = true)]
async fn a_responder_without_its_own_certificate_in_the_policy_answers_docs_only() {
    let w = world();
    let (r, m) = (party(), party());
    // R's Policy lists both as members and holds M's certificate, but not R's own.
    let r_stores = w.split_stores(&[&r, &m], &[&r, &m], &[&m]);
    let m_stores = w.stores(&[&r, &m], vec![]);
    let net = Net::new();
    let nm = node(&net, &m, &m_stores).await;
    let mut nr = node(&net, &r, &r_stores).await;
    assert_eq!(
        ensure(&nm, r.id, w.network).await.err(),
        Some(EnsureError::DocsOnly)
    );
    let at_r = nr.next_ready().await;
    assert!(at_r.docs_only);
}

/// N1 (router): a session is not handed out while this node's own certificate is not in the
/// Policy it now holds: it is closed with CLOSE `grant_removed` first.
#[tokio::test(start_paused = true)]
async fn a_session_is_closed_not_handed_out_once_this_nodes_own_certificate_left_the_policy() {
    let mut live = live(|w, a, b| vec![grant_for(w, a, b, &["tcp:ssh"])]).await;
    edit_policy_of(&live.w, &live.stores_a, |b| {
        b.certs.retain(|c| c.decode().unwrap().node_id != live.a.id);
    });
    let _ = ensure(&live._na, live.b.id, live.w.network).await;
    assert!(matches!(
        ended(&mut live.ready_a.acceptor).await.as_ref(),
        EndReason::ClosedLocally(Some(close)) if close.code == ErrorCode::GrantRemoved
    ));
}
