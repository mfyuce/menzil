//! Connection limits: peers that never finish a TLS handshake cannot keep a real client out
//! (expose round 3, L2), and the cap on served connections still holds.

mod common;

use std::time::{Duration, Instant};

use common::Fixture;
use menzil_relay_admin::pb::*;
use menzil_relay_admin::{ConnLimits, tls};

fn list() -> ListTenantsRequest {
    ListTenantsRequest {
        page_size: 0,
        page_token: String::new(),
    }
}

/// A silent peer (it opens a TCP connection and says nothing) holds a handshake slot for the
/// handshake timeout only: 64 of them delay a real client by about that, not by tens of seconds.
#[tokio::test(flavor = "multi_thread")]
async fn sixty_four_silent_connections_delay_a_real_client_by_the_handshake_timeout_at_most() {
    let fx = Fixture::start().await;
    let mut silent = Vec::new();
    for _ in 0..tls::MAX_HANDSHAKES {
        silent.push(tokio::net::TcpStream::connect(fx.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    let answer = tokio::time::timeout(Duration::from_secs(30), async {
        let mut client = fx.client().await;
        client.list_tenants(list()).await
    })
    .await;
    let waited = started.elapsed();
    assert!(
        matches!(answer, Ok(Ok(_))),
        "the real client was not served: {answer:?}"
    );
    // A literal, not the crate's constant: the bound must not move with the code under test.
    assert!(
        waited < Duration::from_secs(7),
        "served after {waited:?} behind {} silent connections (the handshake timeout is 3 s)",
        silent.len()
    );
    drop(silent);
    fx.shutdown().await;
}

/// Silent peers hold no served slot: with room for two served connections and three silent
/// peers, two real clients are served; a third is dropped; when one leaves, another is served.
#[tokio::test(flavor = "multi_thread")]
async fn silent_peers_take_no_served_slot_and_the_served_cap_holds() {
    let fx = Fixture::start_with_limits(ConnLimits {
        max_handshakes: 8,
        handshake_timeout: Duration::from_secs(30),
        max_connections: 2,
    })
    .await;
    let mut silent = Vec::new();
    for _ in 0..3 {
        silent.push(tokio::net::TcpStream::connect(fx.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut a = fx.client().await;
    let mut b = fx.client().await;
    a.list_tenants(list()).await.expect("first served");
    b.list_tenants(list()).await.expect("second served");
    // The third is dropped after its handshake: its request fails.
    let third = tokio::time::timeout(Duration::from_secs(10), async {
        match common::connect(
            fx.addr,
            &fx.certs.ca_cert,
            Some((&fx.certs.client_cert, &fx.certs.client_key)),
        )
        .await
        {
            Ok(mut client) => client.list_tenants(list()).await.map(|_| ()).is_err(),
            Err(_) => true,
        }
    })
    .await;
    assert_eq!(third, Ok(true), "a third client must not be served");
    // One leaves; its slot is given back and a new client is served.
    drop(a);
    let mut served = false;
    for _ in 0..50 {
        let again = tokio::time::timeout(Duration::from_secs(5), async {
            match common::connect(
                fx.addr,
                &fx.certs.ca_cert,
                Some((&fx.certs.client_cert, &fx.certs.client_key)),
            )
            .await
            {
                Ok(mut client) => client.list_tenants(list()).await.is_ok(),
                Err(_) => false,
            }
        })
        .await;
        if again == Ok(true) {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        served,
        "the slot of the client that left was not given back"
    );
    drop(b);
    drop(silent);
    fx.shutdown().await;
}
