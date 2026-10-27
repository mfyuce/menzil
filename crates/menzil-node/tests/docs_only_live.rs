//! L4j Q3 "docs only admission" end to end over a real relay (TODO.md: "M reaches a member
//! offline at issue time"). The owner has issued a newer Roster and Policy that bring M into the
//! Policy (cert, member entry and a grant to X's service) while X was offline, so nothing was
//! pushed to X. X then comes online holding the old pair: its Roster already lists M (unrevoked)
//! but its Policy has no cert or entry for M. M, holding the new pair, opens a stream to X; X
//! answers the handshake docs only, M pushes the Policy, X adopts it, M's fresh initiation is a
//! full session and the stream carries bytes.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE`
//! is process-global (see that file's own doc comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common::{
    PATIENCE, echo_round_trip, echo_server, grant, identity, policy, reissue, seed_roster, service,
    session_config, start_relay, trust_test_certificate,
};
use menzil_node::{
    LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RefuseAll, RosterStore, SyncConfig,
};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn a_member_offline_at_issue_time_learns_the_policy_from_the_new_member_and_serves_it() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (x, m) = (identity(), identity());
    // The Roster lists both from the start; the Policy X holds does not know M yet.
    let (owner, network_id, roster1) = seed_roster(&relay, &[&x, &m]);
    let base = policy(&owner, network_id, &x, &m, vec![]);
    let (_, old_policy) = reissue(
        &owner,
        &roster1,
        &base,
        1,
        |_| {},
        |p| {
            p.members.retain(|member| member.node_id != m.node_id);
            p.certs
                .retain(|cert| cert.decode().is_ok_and(|c| c.node_id != m.node_id));
        },
    );
    let (new_roster, new_policy) = reissue(
        &owner,
        &roster1,
        &base,
        2,
        |_| {},
        |p| {
            p.grants = vec![grant(network_id, m.node_id, x.node_id, &["tcp:echo"], None)];
        },
    );

    // X holds the old pair (Roster 1 with M, Policy 1 without M); M holds the new pair.
    let x_policies = Arc::new(PolicyStore::new());
    x_policies.set(&old_policy).unwrap();
    let x_rosters = Arc::new(RosterStore::new());
    x_rosters.set(&roster1).unwrap();
    let m_policies = Arc::new(PolicyStore::new());
    m_policies.set(&new_policy).unwrap();
    let m_rosters = Arc::new(RosterStore::new());
    m_rosters.set(&new_roster).unwrap();

    // A day of jitter: the Policy cannot reach X through the ordinary fetch during the test.
    let no_fetch = SyncConfig {
        policy_jitter_max: Duration::from_secs(86_400),
    };

    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_port = app.local_addr().unwrap().port();
    let (ended_tx, _ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(app, ended_tx));
    let services = LocalServices::new()
        .serve(service("tcp:echo"), LocalTarget::new("127.0.0.1", app_port))
        .unwrap();

    // M is attached and X is offline: no push can reach X.
    let nm = Node::start_with_sync(
        NodeConfig {
            session: session_config(&relay, &m, network_id),
            env: HashMap::new(),
            policies: m_policies.clone(),
            rosters: m_rosters.clone(),
        },
        RefuseAll,
        no_fetch,
    )
    .unwrap();
    nm.wait_attached(PATIENCE).await.expect("M attaches");
    sleep(Duration::from_millis(300)).await;
    assert_eq!(x_policies.seq(&network_id), Some(1));

    // X comes online with the old pair.
    let nx = Node::start_with_sync(
        NodeConfig {
            session: session_config(&relay, &x, network_id),
            env: HashMap::new(),
            policies: x_policies.clone(),
            rosters: x_rosters.clone(),
        },
        services,
        no_fetch,
    )
    .unwrap();
    nx.wait_attached(PATIENCE).await.expect("X attaches");

    // M's first attempt meets the docs only answer, pushes the Policy it holds in the background,
    // and open_stream retries once by itself when the push was adopted and the fresh session is up.
    let mut stream = timeout(
        PATIENCE,
        nm.open_stream(x.node_id, network_id, service("tcp:echo"), None),
    )
    .await
    .expect("the OPEN must be answered")
    .expect("the first attempt reaches X after the docs only push");
    echo_round_trip(&mut stream, b"hello from the new member").await;

    // X adopted M's documents.
    assert_eq!(x_policies.seq(&network_id), Some(2));
    assert_eq!(x_rosters.seq(&network_id), Some(2));
    assert_eq!(x_policies.get(&network_id), m_policies.get(&network_id));
    assert_eq!(x_rosters.get(&network_id), m_rosters.get(&network_id));

    nm.shutdown().await;
    nx.shutdown().await;
}
