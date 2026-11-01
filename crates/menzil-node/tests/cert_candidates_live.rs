//! A renewed certificate reaches a steward over a real relay (cert rotation S5, design Q7 c).
//!
//! A holds a steward key (it was told so with `set_candidate_holder`) and B is a member. B's
//! certificate is serial 1 and the Policy lists it, so B pushes nothing and A records nothing.
//! B then restarts, renews to serial 2 (`Node::renew_identity`) before it opens its first
//! session, and the session it opens to A pushes the new certificate on `menzil:docs`: A judges
//! it (B is the session's peer and a Roster member, the static key is the session's, the
//! signature holds, the window is valid and at most 400 days, the serial is above what A knows)
//! and keeps it as the candidate for B. When a Policy that lists serial 2 reaches A, the
//! candidate is gone.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global (see that file's own doc comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{
    Identity, PATIENCE, echo_round_trip, echo_server, grant, identity, node_cert, policy, reissue,
    seed_roster, service, session_config, start_relay, trust_test_certificate, unix_now,
};
use menzil_node::{
    Holder, LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RefuseAll, RosterStore,
};
use menzil_proto::{NodeCert, NodeCertBody, PROTOCOL_VERSION};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};

/// `id`'s certificate at `serial`, valid now for 300 days.
fn renewal(id: &Identity, serial: u32) -> NodeCert {
    let now = unix_now();
    NodeCert::sign(
        &id.signing,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: id.node_id,
            x25519_pub: id.x25519_public,
            serial,
            not_before: now - 1_000,
            not_after: now + 300 * 86_400,
        },
    )
    .unwrap()
}

fn start(
    relay: &common::TestRelay,
    id: &Identity,
    network_id: menzil_proto::NetworkId,
    policies: &Arc<PolicyStore>,
    rosters: &Arc<RosterStore>,
    services: Option<LocalServices>,
) -> Node {
    let config = NodeConfig {
        session: session_config(relay, id, network_id),
        env: HashMap::new(),
        policies: policies.clone(),
        rosters: rosters.clone(),
    };
    match services {
        Some(services) => Node::start(config, services).unwrap(),
        None => Node::start(config, RefuseAll).unwrap(),
    }
}

#[tokio::test]
async fn a_renewed_node_hands_its_certificate_to_a_steward_which_keeps_it_as_a_candidate() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    let base = policy(
        &owner,
        network_id,
        &a,
        &b,
        vec![grant(network_id, b.node_id, a.node_id, &["tcp:echo"], None)],
    );
    let (a_policies, a_rosters) = (Arc::new(PolicyStore::new()), Arc::new(RosterStore::new()));
    let (b_policies, b_rosters) = (Arc::new(PolicyStore::new()), Arc::new(RosterStore::new()));
    for (policies, rosters) in [(&a_policies, &a_rosters), (&b_policies, &b_rosters)] {
        policies.set(&base).unwrap();
        rosters.set(&roster1).unwrap();
    }

    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_port = app.local_addr().unwrap().port();
    let (ended_tx, _ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(app, ended_tx));
    let services = LocalServices::new()
        .serve(service("tcp:echo"), LocalTarget::new("127.0.0.1", app_port))
        .unwrap();

    // A is the steward node.
    let na = start(
        &relay,
        &a,
        network_id,
        &a_policies,
        &a_rosters,
        Some(services),
    );
    na.set_candidate_holder(
        network_id,
        Some(Holder::Steward {
            admit: true,
            renew: true,
            not_after: unix_now() + 86_400,
        }),
    );
    na.wait_attached(PATIENCE).await.expect("A attaches");

    // ---- serial 1, listed: B pushes nothing --------------------------------------------
    let nb = start(&relay, &b, network_id, &b_policies, &b_rosters, None);
    nb.wait_attached(PATIENCE).await.expect("B attaches");
    let mut stream = nb
        .open_stream(a.node_id, network_id, service("tcp:echo"), None)
        .await
        .expect("B reaches A");
    echo_round_trip(&mut stream, b"serial one").await;
    drop(stream);
    sleep(Duration::from_millis(500)).await;
    assert!(
        na.cert_candidates(network_id).is_empty(),
        "the Policy lists serial 1: nothing to tell"
    );
    nb.shutdown().await;

    // ---- B restarts, renews, and its next session carries the certificate ----------------
    let nb = start(&relay, &b, network_id, &b_policies, &b_rosters, None);
    let cert2 = renewal(&b, 2);
    nb.renew_identity(cert2.clone()).unwrap();
    nb.wait_attached(PATIENCE).await.expect("B attaches again");
    let mut stream = nb
        .open_stream(a.node_id, network_id, service("tcp:echo"), None)
        .await
        .expect("B reaches A again");
    echo_round_trip(&mut stream, b"serial two").await;

    let deadline = Instant::now() + PATIENCE;
    let candidates = loop {
        let candidates = na.cert_candidates(network_id);
        if !candidates.is_empty() || Instant::now() > deadline {
            break candidates;
        }
        sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(candidates, vec![cert2.clone()], "A holds B's renewal");

    // ---- a Policy that lists serial 2 clears the candidate ------------------------------
    let (_, listed) = reissue(
        &owner,
        &roster1,
        &base,
        2,
        |_| {},
        |p| p.certs = vec![node_cert(&a), cert2.clone()],
    );
    a_policies.set(&listed).unwrap();
    assert!(na.cert_candidates(network_id).is_empty());

    drop(stream);
    nb.shutdown().await;
    na.shutdown().await;
}
