//! A renewal reaches a steward over the session that is already up, and the session outlives the
//! certificate it started with (cert rotation S8, design Q6, Q7 c, Q9), over a real relay and
//! the real clock.
//!
//! B's first certificate is valid for half a minute. A (a steward by `set_candidate_holder`) and B
//! have a session and a stream through it, B being granted `tcp:echo` on A. Then:
//!
//! 1. B renews to serial 2 (`Node::renew_identity`) and calls `Node::announce_renewed_cert`; no
//!    new session is made, so the push can only ride the live one. A keeps the certificate as its
//!    candidate for B.
//! 2. B renews again, serial 3, and announces: the candidate is the newer one.
//! 3. The owner lists serial 3 in place of serial 1 (what `menzil cert accept` does): A and B
//!    adopt the pair, and A drops the candidate.
//! 4. The stream goes on across the instant serial 1 runs out, and a new stream opens after it.
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
async fn a_renewal_is_announced_over_the_live_session_and_the_stream_outlives_the_old_certificate()
{
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    // B's first certificate runs out half a minute from now.
    let started = unix_now();
    let short = cert_at(&b, 1, started - 1_000, started + 30);
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

    // ---- serial 2 over the live session: no new session is made ---------------------------
    let cert2 = renewal(&b, 2);
    nb.renew_identity(cert2.clone()).unwrap();
    nb.announce_renewed_cert();
    wait_for_candidate(&na, &nb, network_id, &cert2).await;

    // ---- serial 3 replaces it as the candidate --------------------------------------------
    let cert3 = renewal(&b, 3);
    nb.renew_identity(cert3.clone()).unwrap();
    nb.announce_renewed_cert();
    wait_for_candidate(&na, &nb, network_id, &cert3).await;
    echo_round_trip(&mut stream, b"after the announcements").await;

    // ---- the owner lists serial 3 in place of serial 1 -------------------------------------
    let (roster2, listed) = reissue(
        &owner,
        &roster1,
        &base,
        2,
        |_| {},
        |p| p.certs = vec![node_cert(&a), cert3.clone()],
    );
    for (policies, rosters) in [(&a_policies, &a_rosters), (&b_policies, &b_rosters)] {
        rosters.set(&roster2).unwrap();
        policies.set(&listed).unwrap();
    }
    assert!(
        na.cert_candidates(network_id).is_empty(),
        "the Policy lists serial 3: the candidate is gone"
    );

    // ---- across the instant serial 1 runs out ----------------------------------------------
    let old_end =
        Instant::now() + Duration::from_secs((short.decode().unwrap().not_after) - unix_now());
    let mut round = 0u32;
    while Instant::now() < old_end + Duration::from_secs(4) {
        echo_round_trip(&mut stream, format!("round {round}").as_bytes()).await;
        round += 1;
        sleep(Duration::from_millis(500)).await;
    }
    assert!(unix_now() > started + 30, "the old certificate has run out");
    let mut fresh = nb
        .open_stream(a.node_id, network_id, service("tcp:echo"), None)
        .await
        .expect("B reaches A after serial 1 ran out");
    echo_round_trip(&mut fresh, b"a new stream").await;
    echo_round_trip(&mut stream, b"the old stream still").await;

    drop(stream);
    drop(fresh);
    nb.shutdown().await;
    na.shutdown().await;
}

/// Waits until A's candidates for the network are exactly `cert`, announcing from B again every
/// second. A second `announce_renewed_cert` that comes while the push of the first renewal is
/// still finishing on the same session returns at once and is not repeated (`push_node_cert`
/// runs one push per session at a time and does not look again once it is done), which a test
/// that renews twice within milliseconds hits under load; a person renewing twice does not.
async fn wait_for_candidate(
    na: &Node,
    nb: &Node,
    network_id: menzil_proto::NetworkId,
    cert: &NodeCert,
) {
    let deadline = Instant::now() + PATIENCE;
    let mut announced = Instant::now();
    loop {
        let candidates = na.cert_candidates(network_id);
        if candidates == vec![cert.clone()] {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "A holds serials {:?} as candidates, not the announced {}",
            candidates
                .iter()
                .map(|c| c.decode().unwrap().serial)
                .collect::<Vec<_>>(),
            cert.decode().unwrap().serial
        );
        if announced.elapsed() >= Duration::from_secs(1) {
            nb.announce_renewed_cert();
            announced = Instant::now();
        }
        sleep(Duration::from_millis(50)).await;
    }
}
