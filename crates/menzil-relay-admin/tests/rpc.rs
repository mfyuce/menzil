//! Every RPC against a real server over mutual TLS on 127.0.0.1, on a temporary relay home.

mod common;

use common::{Fixture, Owner};
use menzil_relay_admin::pb::*;
use tonic::Code;

fn create(slug: &str, token: &str) -> CreateTenantRequest {
    CreateTenantRequest {
        slug: slug.into(),
        tokens: vec![token.into()],
        class: String::new(),
        idempotency_key: "ignored".into(),
    }
}

fn aref(slug: &str) -> TenantRef {
    TenantRef { slug: slug.into() }
}

#[tokio::test(flavor = "multi_thread")]
async fn create_get_add_remove_and_list_happy_paths() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let (a, b) = (Owner::new(), Owner::new());

    let t = c
        .create_tenant(create("alpha", &a.token()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.slug, "alpha");
    assert_eq!(t.network_ids, vec![a.id.to_hex()]);
    assert_eq!(t.class, "friend");
    assert!(!t.terminated && !t.suspended);
    assert!(t.added_unix > 0);
    assert!(t.quota_overrides.is_empty());

    let got = c.get_tenant(aref("alpha")).await.unwrap().into_inner();
    assert_eq!(got, t);

    let t = c
        .add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: b.token(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.network_ids.len(), 2);
    assert!(t.network_ids.contains(&b.id.to_hex()));

    let t = c
        .remove_network(RemoveNetworkRequest {
            slug: "alpha".into(),
            network_id: b.id.to_hex(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.network_ids, vec![a.id.to_hex()]);

    let listed = c
        .list_tenants(ListTenantsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.tenants.len(), 1);
    assert_eq!(listed.next_page_token, "");

    let gone = c.remove_tenant(aref("alpha")).await.unwrap().into_inner();
    assert!(gone.existed);
    assert_eq!(
        c.get_tenant(aref("alpha")).await.unwrap_err().code(),
        Code::NotFound
    );
    let again = c.remove_tenant(aref("alpha")).await.unwrap().into_inner();
    assert!(!again.existed);
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn create_is_idempotent_and_refuses_other_networks_quarantine_and_reserved_names() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let (a, b) = (Owner::new(), Owner::new());
    let first = c
        .create_tenant(create("alpha", &a.token()))
        .await
        .unwrap()
        .into_inner();
    let again = c
        .create_tenant(create("alpha", &a.token()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(first, again);
    assert_eq!(
        c.create_tenant(create("alpha", &b.token()))
            .await
            .unwrap_err()
            .code(),
        Code::AlreadyExists
    );
    // A reserved name.
    assert_eq!(
        c.create_tenant(create("admin", &b.token()))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    // A syntax error.
    assert_eq!(
        c.create_tenant(create("Bad Name", &b.token()))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    // The name of a removed tenant is held for 180 days.
    c.remove_tenant(aref("alpha")).await.unwrap();
    assert_eq!(
        c.create_tenant(create("alpha", &a.token()))
            .await
            .unwrap_err()
            .code(),
        Code::FailedPrecondition
    );
    // Not exactly one token, bad class, bad token.
    let mut two = create("beta", &b.token());
    two.tokens.push(a.token());
    assert_eq!(
        c.create_tenant(two).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut none = create("beta", &b.token());
    none.tokens.clear();
    assert_eq!(
        c.create_tenant(none).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut class = create("beta", &b.token());
    class.class = "gold".into();
    assert_eq!(
        c.create_tenant(class).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(
        c.create_tenant(create("beta", "menzil1-roster:AAAA"))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    // Nothing was made by the refusals.
    assert!(!fx.tenant_file("beta").exists());
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn create_with_the_personal_class() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    let mut req = create("alpha", &a.token());
    req.class = "personal".into();
    let t = c.create_tenant(req).await.unwrap().into_inner();
    assert_eq!(t.class, "personal");
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn add_network_rules() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let owners: Vec<Owner> = (0..5).map(|_| Owner::new()).collect();
    // No tenant yet: AddNetwork does not make one.
    assert_eq!(
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: owners[0].token()
        })
        .await
        .unwrap_err()
        .code(),
        Code::NotFound
    );
    c.create_tenant(create("alpha", &owners[0].token()))
        .await
        .unwrap();
    c.create_tenant(create("gamma", &owners[1].token()))
        .await
        .unwrap();
    // Another tenant's network is not moved.
    assert_eq!(
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: owners[1].token()
        })
        .await
        .unwrap_err()
        .code(),
        Code::FailedPrecondition
    );
    // The same network again: success, nothing doubled.
    let t = c
        .add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: owners[0].token(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.network_ids.len(), 1);
    // The class allows 3 networks: the fourth is refused.
    for o in &owners[2..4] {
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: o.token(),
        })
        .await
        .unwrap();
    }
    assert_eq!(
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: owners[4].token()
        })
        .await
        .unwrap_err()
        .code(),
        Code::FailedPrecondition
    );
    // A renewal with a newer token keeps the network where it is.
    menzil_cli::local::renew(&owners[0].home, None, common::clock()).unwrap();
    let t = c
        .add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: owners[0].token(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.network_ids.len(), 3);
    // Bad input.
    assert_eq!(
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: String::new()
        })
        .await
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_network_rules() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let (a, b) = (Owner::new(), Owner::new());
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    c.create_tenant(create("gamma", &b.token())).await.unwrap();
    let remove = |slug: &str, id: String| RemoveNetworkRequest {
        slug: slug.into(),
        network_id: id,
    };
    // A network of another tenant is not removed through this one.
    assert_eq!(
        c.remove_network(remove("alpha", b.id.to_hex()))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        c.get_tenant(aref("gamma"))
            .await
            .unwrap()
            .into_inner()
            .network_ids
            .len(),
        1
    );
    assert_eq!(
        c.remove_network(remove("nobody", a.id.to_hex()))
            .await
            .unwrap_err()
            .code(),
        Code::NotFound
    );
    assert_eq!(
        c.remove_network(remove("alpha", "zz".into()))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn update_tenant_rules() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    let upd = |f: &dyn Fn(&mut UpdateTenantRequest)| {
        let mut r = UpdateTenantRequest {
            slug: "alpha".into(),
            ..Default::default()
        };
        f(&mut r);
        r
    };
    // terminated alone changes nothing else.
    let t = c
        .update_tenant(upd(&|r| r.terminated = Some(true)))
        .await
        .unwrap()
        .into_inner();
    assert!(t.terminated);
    assert_eq!(t.class, "friend");
    // Overrides replace the whole set; the flag decides.
    let t = c
        .update_tenant(upd(&|r| {
            r.replace_quota_overrides = true;
            r.quota_overrides.insert("names".into(), 7);
            r.quota_overrides.insert("max_networks".into(), 2);
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.quota_overrides.len(), 2);
    assert!(t.terminated, "terminated stays when not given");
    let t = c
        .update_tenant(upd(&|r| {
            r.replace_quota_overrides = true;
            r.quota_overrides.insert("names".into(), 9);
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.quota_overrides.len(), 1, "replaced, not merged");
    assert_eq!(t.quota_overrides["names"], 9);
    // Without the flag the field is not applied; a map with no flag is refused.
    let t = c
        .update_tenant(upd(&|r| r.terminated = Some(false)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.quota_overrides["names"], 9);
    assert_eq!(
        c.update_tenant(upd(&|r| {
            r.quota_overrides.insert("names".into(), 1);
        }))
        .await
        .unwrap_err()
        .code(),
        Code::InvalidArgument
    );
    // Empty map with the flag: back to the class defaults.
    let t = c
        .update_tenant(upd(&|r| r.replace_quota_overrides = true))
        .await
        .unwrap()
        .into_inner();
    assert!(t.quota_overrides.is_empty());
    // Unknown key, zero, above the maximum, floor above bandwidth.
    for (key, value) in [("nope", 1u64), ("names", 0), ("names", 100_001)] {
        let e = c
            .update_tenant(upd(&|r| {
                r.replace_quota_overrides = true;
                r.quota_overrides.insert(key.into(), value);
            }))
            .await
            .unwrap_err();
        assert_eq!(e.code(), Code::InvalidArgument, "{key} {value}");
    }
    let e = c
        .update_tenant(upd(&|r| {
            r.replace_quota_overrides = true;
            r.quota_overrides.insert("floor_mbit".into(), 50);
            r.quota_overrides.insert("bandwidth_mbit".into(), 10);
        }))
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::InvalidArgument);
    // Class: unknown value, personal with overrides, then personal for real.
    assert_eq!(
        c.update_tenant(upd(&|r| r.class = Some("gold".into())))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    c.update_tenant(upd(&|r| {
        r.replace_quota_overrides = true;
        r.quota_overrides.insert("names".into(), 3);
    }))
    .await
    .unwrap();
    assert_eq!(
        c.update_tenant(upd(&|r| r.class = Some("personal".into())))
            .await
            .unwrap_err()
            .code(),
        Code::InvalidArgument
    );
    c.update_tenant(upd(&|r| r.replace_quota_overrides = true))
        .await
        .unwrap();
    let t = c
        .update_tenant(upd(&|r| r.class = Some("personal".into())))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(t.class, "personal");
    // max_networks below the networks the tenant has.
    c.update_tenant(upd(&|r| r.class = Some("friend".into())))
        .await
        .unwrap();
    let (b, d) = (Owner::new(), Owner::new());
    c.add_network(AddNetworkRequest {
        slug: "alpha".into(),
        token: b.token(),
    })
    .await
    .unwrap();
    c.add_network(AddNetworkRequest {
        slug: "alpha".into(),
        token: d.token(),
    })
    .await
    .unwrap();
    assert_eq!(
        c.update_tenant(upd(&|r| {
            r.replace_quota_overrides = true;
            r.quota_overrides.insert("max_networks".into(), 1);
        }))
        .await
        .unwrap_err()
        .code(),
        Code::FailedPrecondition
    );
    // No such tenant.
    let missing = UpdateTenantRequest {
        slug: "nobody".into(),
        terminated: Some(true),
        ..Default::default()
    };
    assert_eq!(
        c.update_tenant(missing).await.unwrap_err().code(),
        Code::NotFound
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn suspend_and_resume() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    c.update_tenant(UpdateTenantRequest {
        slug: "alpha".into(),
        terminated: Some(true),
        ..Default::default()
    })
    .await
    .unwrap();
    let t = c.suspend_tenant(aref("alpha")).await.unwrap().into_inner();
    assert!(t.suspended);
    assert!(t.terminated, "suspension leaves terminated alone");
    let again = c.suspend_tenant(aref("alpha")).await.unwrap().into_inner();
    assert_eq!(t, again);
    // A suspended tenant takes no network (the library refuses it).
    let b = Owner::new();
    assert_eq!(
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: b.token()
        })
        .await
        .unwrap_err()
        .code(),
        Code::FailedPrecondition
    );
    let t = c.resume_tenant(aref("alpha")).await.unwrap().into_inner();
    assert!(!t.suspended);
    assert_eq!(
        c.suspend_tenant(aref("nobody")).await.unwrap_err().code(),
        Code::NotFound
    );
    assert_eq!(
        c.resume_tenant(aref("nobody")).await.unwrap_err().code(),
        Code::NotFound
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn remove_tenant_ends_the_tenant_and_quarantines_the_name() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    assert!(fx.tenant_file("alpha").exists());
    assert!(
        c.remove_tenant(aref("alpha"))
            .await
            .unwrap()
            .into_inner()
            .existed
    );
    assert!(!fx.tenant_file("alpha").exists());
    // The Roster file went with it.
    let roster = fx
        .relay_home
        .join("relay")
        .join(format!("{}.roster", a.id.to_hex()));
    assert!(!roster.exists());
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tenants_pages_in_slug_order() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let owners: Vec<Owner> = (0..5).map(|_| Owner::new()).collect();
    // Created out of order.
    for (slug, o) in ["delta", "alpha", "echo", "bravo", "charlie"]
        .iter()
        .zip(&owners)
    {
        c.create_tenant(create(slug, &o.token())).await.unwrap();
    }
    let page = |token: &str, size: u32| ListTenantsRequest {
        page_token: token.into(),
        page_size: size,
    };
    let p1 = c.list_tenants(page("", 2)).await.unwrap().into_inner();
    let slugs: Vec<_> = p1.tenants.iter().map(|t| t.slug.as_str()).collect();
    assert_eq!(slugs, ["alpha", "bravo"]);
    assert_eq!(p1.next_page_token, "bravo");
    let p2 = c
        .list_tenants(page(&p1.next_page_token, 2))
        .await
        .unwrap()
        .into_inner();
    let slugs: Vec<_> = p2.tenants.iter().map(|t| t.slug.as_str()).collect();
    assert_eq!(slugs, ["charlie", "delta"]);
    assert_eq!(p2.next_page_token, "delta");
    let p3 = c
        .list_tenants(page(&p2.next_page_token, 2))
        .await
        .unwrap()
        .into_inner();
    let slugs: Vec<_> = p3.tenants.iter().map(|t| t.slug.as_str()).collect();
    assert_eq!(slugs, ["echo"]);
    assert_eq!(p3.next_page_token, "");
    // Exactly a full last page has no next token.
    let exact = c
        .list_tenants(page("charlie", 2))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exact.tenants.len(), 2);
    assert_eq!(exact.next_page_token, "");
    // Size 0 is the default (all five here); an oversize page is allowed and capped.
    assert_eq!(
        c.list_tenants(page("", 0))
            .await
            .unwrap()
            .into_inner()
            .tenants
            .len(),
        5
    );
    assert_eq!(
        c.list_tenants(page("", 100_000))
            .await
            .unwrap()
            .into_inner()
            .tenants
            .len(),
        5
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn get_figures_lists_every_key() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let figs = c
        .get_figures(GetFiguresRequest {})
        .await
        .unwrap()
        .into_inner()
        .figures;
    assert_eq!(figs.len(), menzil_relay::Figures::KEYS.len());
    assert!(figs.len() >= 18);
    for f in &figs {
        assert!(
            f.class_default_friend >= 1 && f.class_default_friend <= f.max,
            "{}",
            f.key
        );
    }
    let names = figs.iter().find(|f| f.key == "names").unwrap();
    assert_eq!((names.class_default_friend, names.max), (20, 100_000));
    fx.shutdown().await;
}

/// Statuses never carry a path, token text or key material.
#[tokio::test(flavor = "multi_thread")]
async fn status_messages_hold_no_path_or_token() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let (a, b) = (Owner::new(), Owner::new());
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    // A tenant file the relay cannot use: reading it names a path in the library's own text.
    std::fs::write(
        fx.tenant_file("broken"),
        "class = \"gold\"\nnetworks = []\n",
    )
    .unwrap();
    let home = fx.relay_home.to_string_lossy().to_string();
    let tokens = [a.token(), b.token()];
    let mut statuses = Vec::new();
    statuses.push(c.get_tenant(aref("broken")).await.unwrap_err());
    statuses.push(c.suspend_tenant(aref("broken")).await.unwrap_err());
    statuses.push(
        c.update_tenant(UpdateTenantRequest {
            slug: "broken".into(),
            terminated: Some(true),
            ..Default::default()
        })
        .await
        .unwrap_err(),
    );
    statuses.push(
        c.create_tenant(create("alpha", &b.token()))
            .await
            .unwrap_err(),
    );
    statuses.push(c.create_tenant(create("zz", &b.token())).await.unwrap_err());
    statuses.push(
        c.create_tenant(create("beta", "menzil1-roster:AAAA"))
            .await
            .unwrap_err(),
    );
    statuses.push(
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: "x".repeat(70_000),
        })
        .await
        .unwrap_err(),
    );
    statuses.push(c.get_usage(aref("alpha")).await.unwrap_err());
    // A token for a network another tenant holds.
    c.create_tenant(create("gamma", &b.token())).await.unwrap();
    statuses.push(
        c.add_network(AddNetworkRequest {
            slug: "alpha".into(),
            token: b.token(),
        })
        .await
        .unwrap_err(),
    );
    assert!(statuses.len() >= 9);
    for s in &statuses {
        let m = s.message();
        assert!(!m.is_empty());
        assert!(
            !m.contains('/') && !m.contains(&home) && !m.contains("menzil1-"),
            "{m}"
        );
        assert!(!m.contains(".toml") && !m.contains(".roster"), "{m}");
        for t in &tokens {
            assert!(!m.contains(t.as_str()));
        }
    }
    // A file that is not even TOML makes the directory unreadable: INTERNAL, a fixed text.
    std::fs::write(fx.tenant_file("garbled"), "networks = [[[ not toml").unwrap();
    let e = c
        .list_tenants(ListTenantsRequest::default())
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::Internal);
    assert!(
        !e.message().contains('/')
            && !e.message().contains("garbled")
            && !e.message().contains(&home)
    );
    // The broken file really did reach the library and was refused with a fixed text.
    assert_eq!(statuses[0].code(), Code::FailedPrecondition);
    assert_eq!(statuses[1].code(), Code::FailedPrecondition);
    fx.shutdown().await;
}

#[test]
fn every_figure_key_has_a_class_default() {
    for f in menzil_relay_admin::service::figures() {
        assert!(f.class_default_friend > 0, "no default read for {}", f.key);
    }
}

#[test]
fn library_errors_map_to_their_codes() {
    use menzil_cli::home::Home;
    use menzil_cli::relay_cmd::tenants::TenantError;
    use menzil_relay_admin::service::status_of;
    let home = Home::new("/nonexistent/menzil-home");
    let code = |e: TenantError| status_of(&e, &home).code();
    assert_eq!(code(TenantError::NotFound), Code::NotFound);
    assert_eq!(code(TenantError::AlreadyExists), Code::AlreadyExists);
    assert_eq!(
        code(TenantError::Invalid("x".into())),
        Code::InvalidArgument
    );
    assert_eq!(
        code(TenantError::Precondition("x".into())),
        Code::FailedPrecondition
    );
    assert_eq!(code(TenantError::Io("x".into())), Code::Internal);
    // A text with a path or the home in it is replaced.
    let leaky = status_of(
        &TenantError::Precondition("cannot read /nonexistent/menzil-home/relay/x.toml".into()),
        &home,
    );
    assert!(!leaky.message().contains("nonexistent"));
    let leaky = status_of(&TenantError::Io("/etc/shadow".into()), &home);
    assert!(!leaky.message().contains("shadow"));
    let fine = status_of(
        &TenantError::Invalid("names must be 1 to 100000, not 0".into()),
        &home,
    );
    assert_eq!(fine.message(), "names must be 1 to 100000, not 0");
}
