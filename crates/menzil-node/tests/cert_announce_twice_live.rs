//! A second renewal announced while the push of the first is still running reaches the steward
//! too (cert rotation round C, E1; `DocsSync::push_node_cert` looks again), over a real relay and
//! the real clock.
//!
//! A (a steward by `set_candidate_holder`) and B have a session and a stream through it. B's first
//! certificate (serial 1) is listed. B renews to serial 2 and calls `Node::announce_renewed_cert`,
//! then renews to serial 3 and announces at once, so the second request finds the first push
//! running. A has to end up with serial 3 as its candidate for B.
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
    Holder, LocalIdentity, LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RefuseAll,
    RosterStore,
};
use menzil_proto::{NodeCert, NodeCertBody, PROTOCOL_VERSION};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};

/// `id`'s certificate at `serial` for `[not_before, not_after]`.
fn cert_at(id: &Identity, serial: u32, not_before: u64, not_after: u64) -> NodeCert {
    NodeCert::sign(
        &id.signing,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: id.node_id,
            x25519_pub: id.x25519_public,
            serial,
            not_before,
            not_after,
        },
    )
    .unwrap()
}

/// A renewal as `NodeKeys::next_cert` makes one: a day back, 300 days on.
fn renewal(id: &Identity, serial: u32) -> NodeCert {
    let now = unix_now();
    cert_at(id, serial, now - 86_400, now + 300 * 86_400)
}

#[tokio::test]
async fn a_second_announcement_during_a_push_is_not_lost() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    // B's first certificate runs out a quarter of an hour from now (the push of the renewals is
    // what this test is about, not the instant it runs out).
    let started = unix_now();
    let short = cert_at(&b, 1, started - 1_000, started + 900);
    let base = {
        let (_, listed) = reissue(
            &owner,
            &roster1,
            &policy(
                &owner,
                network_id,
                &a,
                &b,
                vec![grant(network_id, b.node_id, a.node_id, &["tcp:echo"], None)],
            ),
            1,
            |_| {},
            |p| p.certs = vec![node_cert(&a), short.clone()],
        );
        listed
    };
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

    let na = Node::start(
        NodeConfig {
            session: session_config(&relay, &a, network_id),
            env: HashMap::new(),
            policies: a_policies.clone(),
            rosters: a_rosters.clone(),
        },
        services,
    )
    .unwrap();
    na.set_candidate_holder(
        network_id,
        Some(Holder::Steward {
            admit: true,
            renew: true,
            not_after: unix_now() + 86_400,
        }),
    );
    na.wait_attached(PATIENCE).await.expect("A attaches");

    let mut b_session = session_config(&relay, &b, network_id);
    b_session.identity = LocalIdentity {
        node_cert: short.clone(),
        x25519_private: b.x25519_private,
    }
    .into();
    let nb = Node::start(
        NodeConfig {
            session: b_session,
            env: HashMap::new(),
            policies: b_policies.clone(),
            rosters: b_rosters.clone(),
        },
        RefuseAll,
    )
    .unwrap();
    nb.wait_attached(PATIENCE).await.expect("B attaches");

    // The stream that has to outlive serial 1.
    let mut stream = nb
        .open_stream(a.node_id, network_id, service("tcp:echo"), None)
        .await
        .expect("B reaches A");
    echo_round_trip(&mut stream, b"before the renewal").await;
    assert!(
        na.cert_candidates(network_id).is_empty(),
        "serial 1 is listed: nothing was pushed"
    );

    // Two renewals back to back, each announced once: the second request arrives while the
    // push of the first is running.
    let cert2 = renewal(&b, 2);
    nb.renew_identity(cert2).unwrap();
    nb.announce_renewed_cert();
    // Let the push of serial 2 start and read the certificate before it changes again.
    tokio::task::yield_now().await;
    let cert3 = renewal(&b, 3);
    nb.renew_identity(cert3.clone()).unwrap();
    nb.announce_renewed_cert();
    let started = Instant::now();
    while na.cert_candidates(network_id) != vec![cert3.clone()] {
        let serials: Vec<u32> = na
            .cert_candidates(network_id)
            .iter()
            .map(|c| c.decode().unwrap().serial)
            .collect();
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "the second announcement was dropped: A holds serials {serials:?}, B is at 3"
        );
        sleep(Duration::from_millis(50)).await;
    }
    drop(stream);
    nb.shutdown().await;
    na.shutdown().await;
}
