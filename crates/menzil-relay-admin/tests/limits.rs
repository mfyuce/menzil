//! Limits: token and message size, one change at a time, 32 RPCs at once, the 15 second deadline.
#![allow(clippy::await_holding_lock)] // the tests hold the write mutex on purpose, across awaits

mod common;

use std::time::Duration;

use common::{Fixture, Owner};
use menzil_relay_admin::pb::*;
use tonic::Code;

fn create(slug: &str, token: &str) -> CreateTenantRequest {
    CreateTenantRequest {
        slug: slug.into(),
        tokens: vec![token.into()],
        class: String::new(),
        idempotency_key: String::new(),
    }
}

fn terminate(slug: &str, on: bool) -> UpdateTenantRequest {
    UpdateTenantRequest {
        slug: slug.into(),
        terminated: Some(on),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn tokens_over_64_kib_and_messages_over_4_mib_are_refused() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    for len in [64 * 1024 + 1, 200_000] {
        let e = c
            .add_network(AddNetworkRequest {
                slug: "alpha".into(),
                token: "A".repeat(len),
            })
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "{len}");
        assert!(e.message().contains("too large"));
    }
    // Over the message limit the server does not even decode it.
    let e = c
        .add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: "A".repeat(5 * 1024 * 1024),
        })
        .await
        .unwrap_err();
    assert_ne!(
        e.code(),
        Code::InvalidArgument,
        "refused before the handler: {e:?}"
    );
    assert_ne!(e.code(), Code::Ok);
    assert_eq!(
        c.get_tenant(TenantRef {
            slug: "alpha".into()
        })
        .await
        .unwrap()
        .into_inner()
        .network_ids
        .len(),
        1
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_change_waits_for_the_write_mutex_and_a_read_does_not() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    let guard = fx.admin.hold_writes();
    let mut c2 = fx.client().await;
    let update = tokio::spawn(async move { c2.update_tenant(terminate("alpha", true)).await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        !update.is_finished(),
        "a change ran while the mutex was held"
    );
    // Reads go on.
    let t = c
        .get_tenant(TenantRef {
            slug: "alpha".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!t.terminated);
    drop(guard);
    let t = update.await.unwrap().unwrap().into_inner();
    assert!(t.terminated);
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn parallel_changes_leave_a_valid_consistent_file() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let owners: Vec<Owner> = (0..8).map(|_| Owner::new()).collect();
    c.create_tenant(create("alpha", &owners[0].token()))
        .await
        .unwrap();
    c.update_tenant(UpdateTenantRequest {
        slug: "alpha".into(),
        replace_quota_overrides: true,
        quota_overrides: [("max_networks".to_string(), 50u64)].into(),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut tasks = Vec::new();
    for o in &owners[1..] {
        let mut c = fx.client().await;
        let token = o.token();
        tasks.push(tokio::spawn(async move {
            c.add_network(AddNetworkRequest {
                slug: "alpha".into(),
                token,
            })
            .await
            .map(|_| ())
        }));
    }
    for i in 0..12 {
        let mut c = fx.client().await;
        tasks.push(tokio::spawn(async move {
            if i % 3 == 0 {
                // Keeps max_networks at 50: only the other figure changes.
                c.update_tenant(UpdateTenantRequest {
                    slug: "alpha".into(),
                    replace_quota_overrides: true,
                    quota_overrides: [
                        ("max_networks".to_string(), 50u64),
                        ("names".to_string(), 10 + i),
                    ]
                    .into(),
                    ..Default::default()
                })
                .await
                .map(|_| ())
            } else {
                c.update_tenant(terminate("alpha", i % 2 == 0))
                    .await
                    .map(|_| ())
            }
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let t = c
        .get_tenant(TenantRef {
            slug: "alpha".into(),
        })
        .await
        .unwrap()
        .into_inner();
    // Every network landed once; the file parses; the figures are one of the writes, whole.
    let mut ids = t.network_ids.clone();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 8);
    assert_eq!(t.quota_overrides["max_networks"], 50);
    assert!(t.quota_overrides["names"] >= 10);
    for o in &owners {
        assert!(t.network_ids.contains(&o.id.to_hex()));
        let roster = fx
            .relay_home
            .join("relay")
            .join(format!("{}.roster", o.id.to_hex()));
        assert!(roster.is_file());
    }
    assert_eq!(
        c.list_tenants(ListTenantsRequest::default())
            .await
            .unwrap()
            .into_inner()
            .tenants
            .len(),
        1
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn at_most_32_rpcs_run_at_once() {
    // A long deadline: the held changes must not time out however starved the machine is.
    let fx = Fixture::start_with_timeout(Some(Duration::from_secs(300))).await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    // Every change waits on the held mutex, so the first 32 hold their permits and the rest are
    // turned away. Several connections: one HTTP/2 connection carries 32 streams at most.
    let guard = fx.admin.hold_writes();
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let c = fx.client().await;
        for _ in 0..10 {
            let mut c = c.clone();
            tasks.push(tokio::spawn(async move {
                c.update_tenant(terminate("alpha", true)).await
            }));
        }
    }
    // The 8 turned away answer at once; wait for them instead of for a fixed time.
    let waiting = std::time::Instant::now();
    while tasks.iter().filter(|t| t.is_finished()).count() < 8 {
        assert!(
            waiting.elapsed() < Duration::from_secs(120),
            "the refusals never came"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let turned_away = tasks.iter().filter(|t| t.is_finished()).count();
    assert_eq!(turned_away, 8, "40 requests, 32 allowed");
    drop(guard);
    let mut refused = 0;
    let mut done = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => done += 1,
            Err(e) => {
                assert_eq!(e.code(), Code::ResourceExhausted, "{e:?}");
                refused += 1;
            }
        }
    }
    assert_eq!((done, refused), (32, 8));
    fx.shutdown().await;
}

/// A change still queued when its request times out must not run afterwards. The agent's own
/// deadline is short here and the transport's backstop is longer, so the agent's deadline is the
/// one that fires (the order that hid a defect: with the agent's deadline first, the cancel flag
/// was never set and the abandoned change ran when the mutex was released).
#[tokio::test(flavor = "multi_thread")]
async fn a_request_over_its_deadline_is_dropped_and_its_change_never_runs() {
    let fx = Fixture::start_with_timeout(Some(Duration::from_millis(400))).await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    let guard = fx.admin.hold_writes();
    let e = c.update_tenant(terminate("alpha", true)).await.unwrap_err();
    assert_eq!(e.code(), Code::DeadlineExceeded, "{e:?}");
    drop(guard);
    // The abandoned change, if it were going to run, runs as soon as the mutex is free.
    tokio::time::sleep(Duration::from_millis(800)).await;
    let t = c
        .get_tenant(TenantRef {
            slug: "alpha".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(!t.terminated, "the abandoned change ran after its deadline");
    fx.shutdown().await;
}
