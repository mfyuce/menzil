//! `GetUsage` answers from the relay's `status.json` (slice: usage export): the counters of the
//! tenant asked for, zeros for what the relay has not listed yet, and a fixed FAILED_PRECONDITION
//! when the relay is not exporting.

mod common;

use std::collections::BTreeMap;

use common::{Fixture, Owner, clock};
use menzil_cli::relay_cmd::status::{self, DEFAULT_KEY, MAX_BYTES, StatusDoc, TenantEntry};
use menzil_relay_admin::pb::*;
use tonic::Code;

fn aref(slug: &str) -> TenantRef {
    TenantRef { slug: slug.into() }
}

fn create(slug: &str, token: &str) -> CreateTenantRequest {
    CreateTenantRequest {
        slug: slug.into(),
        tokens: vec![token.into()],
        ..Default::default()
    }
}

fn entry(seed: u32) -> TenantEntry {
    TenantEntry {
        attached_sessions: seed,
        live_pairs: seed + 1,
        bytes_period: u64::from(seed) * 1_000_000_007,
        names: seed + 2,
        period_end_unix: 1_900_000_000 + i64::from(seed),
    }
}

fn doc(generated_unix: u64, tenants: &[(&str, TenantEntry)]) -> StatusDoc {
    StatusDoc {
        version: status::VERSION,
        generated_unix,
        tenants: tenants
            .iter()
            .map(|(key, entry)| ((*key).to_string(), *entry))
            .collect::<BTreeMap<_, _>>(),
    }
}

/// The fixed texts the agent answers a missing or unusable export with.
const NOT_EXPORTING: &str = "the relay is not exporting its usage: it is down, not running here, or has stopped writing its status";
const UNUSABLE: &str = "the relay's usage export cannot be used";

fn status_file(fx: &Fixture) -> std::path::PathBuf {
    status::status_path(&fx.home())
}

fn write_raw(fx: &Fixture, bytes: &[u8]) {
    let path = status_file(fx);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn usage_is_the_tenants_own_entry_of_the_status_file() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let (a, b) = (Owner::new(), Owner::new());
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    c.create_tenant(create("beta", &b.token())).await.unwrap();
    let generated = clock() - 3;
    status::write(
        &fx.home(),
        &doc(
            generated,
            &[
                ("alpha", entry(4)),
                ("beta", entry(40)),
                (DEFAULT_KEY, entry(400)),
            ],
        ),
    )
    .unwrap();
    let usage = c.get_usage(aref("alpha")).await.unwrap().into_inner();
    assert_eq!(
        usage,
        Usage {
            attached_sessions: 4,
            live_pairs: 5,
            bytes_period: 4_000_000_028,
            names: 6,
            period_end_unix: 1_900_000_004,
            generated_unix: i64::try_from(generated).unwrap(),
        }
    );
    let usage = c.get_usage(aref("beta")).await.unwrap().into_inner();
    assert_eq!((usage.attached_sessions, usage.names), (40, 42));
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tenant_the_file_does_not_list_has_zero_usage_and_a_tenant_without_a_file_is_not_found() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    // A tenant file the relay does not use is still a tenant file: zeros, not an error.
    std::fs::write(
        fx.tenant_file("broken"),
        "class = \"gold\"\nnetworks = []\n",
    )
    .unwrap();
    // The file lists another tenant (a removed one, say) and the default one, not alpha.
    status::write(
        &fx.home(),
        &doc(clock(), &[("zeta", entry(9)), (DEFAULT_KEY, entry(8))]),
    )
    .unwrap();
    for slug in ["alpha", "broken"] {
        let usage = c.get_usage(aref(slug)).await.unwrap().into_inner();
        assert_eq!(
            (
                usage.attached_sessions,
                usage.live_pairs,
                usage.bytes_period,
                usage.names,
                usage.period_end_unix
            ),
            (0, 0, 0, 0, 0),
            "{slug}"
        );
        assert!(usage.generated_unix > 0);
    }
    // The file lists "zeta" but no tenant file exists for it: NOT_FOUND, whatever the file says.
    assert_eq!(
        c.get_usage(aref("zeta")).await.unwrap_err().code(),
        Code::NotFound
    );
    // And without any status file a tenant that does not exist is still NOT_FOUND.
    std::fs::remove_file(status_file(&fx)).unwrap();
    assert_eq!(
        c.get_usage(aref("ghost")).await.unwrap_err().code(),
        Code::NotFound
    );
    // The default tenant's key is not a slug: it cannot be asked for by name.
    assert_eq!(
        c.get_usage(aref(DEFAULT_KEY)).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_or_stale_status_file_is_failed_precondition_with_a_fixed_text() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    let home = fx.relay_home.to_string_lossy().to_string();
    let mut refusals = Vec::new();
    // No file.
    refusals.push(c.get_usage(aref("alpha")).await.unwrap_err());
    // Older than a minute, and dated well ahead of the clock.
    for generated in [clock() - 90, clock() + 300] {
        status::write(&fx.home(), &doc(generated, &[("alpha", entry(1))])).unwrap();
        refusals.push(c.get_usage(aref("alpha")).await.unwrap_err());
    }
    for refusal in &refusals {
        assert_eq!(refusal.code(), Code::FailedPrecondition);
        assert_eq!(refusal.message(), NOT_EXPORTING);
        assert!(!refusal.message().contains(&home));
    }
    // Half a minute old is current.
    status::write(&fx.home(), &doc(clock() - 30, &[("alpha", entry(1))])).unwrap();
    assert_eq!(
        c.get_usage(aref("alpha"))
            .await
            .unwrap()
            .into_inner()
            .attached_sessions,
        1
    );
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_or_oversized_status_file_is_refused_with_a_fixed_text() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    let now = clock();
    let good = format!(
        "{{\"version\":1,\"generated_unix\":{now},\"tenants\":{{\"alpha\":{{\"attached_sessions\":1,\"live_pairs\":0,\"bytes_period\":0,\"names\":0,\"period_end_unix\":0}}}}}}"
    );
    // The control: the text above is a good document.
    write_raw(&fx, good.as_bytes());
    assert_eq!(
        c.get_usage(aref("alpha"))
            .await
            .unwrap()
            .into_inner()
            .attached_sessions,
        1
    );
    let mut bad: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("garbage", b"not json at all".to_vec()),
        ("truncated", good.as_bytes()[..good.len() / 2].to_vec()),
        ("trailing", format!("{good} x").into_bytes()),
        (
            "version",
            good.replace("\"version\":1", "\"version\":2").into_bytes(),
        ),
        (
            "unknown field",
            good.replace(
                "\"live_pairs\":0",
                "\"live_pairs\":0,\"client_ip\":\"1.2.3.4\"",
            )
            .into_bytes(),
        ),
        (
            "missing field",
            good.replace("\"live_pairs\":0,", "").into_bytes(),
        ),
        (
            "unknown top field",
            good.replacen("{\"version\"", "{\"x\":1,\"version\"", 1)
                .into_bytes(),
        ),
        (
            "bad key",
            good.replace("\"alpha\":", "\"Not A Slug\":").into_bytes(),
        ),
        (
            "negative count",
            good.replace("\"attached_sessions\":1", "\"attached_sessions\":-1")
                .into_bytes(),
        ),
    ];
    // A valid document padded past the cap: refused by size, never parsed.
    let mut big = good.clone().into_bytes();
    big.resize(usize::try_from(MAX_BYTES).unwrap() + 1, b' ');
    bad.push(("oversized", big));
    for (what, bytes) in &bad {
        write_raw(&fx, bytes);
        let refusal = c.get_usage(aref("alpha")).await.unwrap_err();
        assert_eq!(refusal.code(), Code::FailedPrecondition, "{what}");
        assert_eq!(refusal.message(), UNUSABLE, "{what}");
    }
    // Exactly at the cap is read (and is a valid document).
    let mut at_cap = good.into_bytes();
    at_cap.resize(usize::try_from(MAX_BYTES).unwrap(), b' ');
    write_raw(&fx, &at_cap);
    assert!(c.get_usage(aref("alpha")).await.is_ok());
    // A directory in place of the file is not read.
    std::fs::remove_file(status_file(&fx)).unwrap();
    std::fs::create_dir(status_file(&fx)).unwrap();
    let refusal = c.get_usage(aref("alpha")).await.unwrap_err();
    assert_eq!(refusal.code(), Code::Internal);
    assert!(!refusal.message().contains('/'));
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_suspended_tenant_reports_zero_live_counts() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    let a = Owner::new();
    c.create_tenant(create("alpha", &a.token())).await.unwrap();
    status::write(&fx.home(), &doc(clock(), &[("alpha", entry(7))])).unwrap();
    let live = c.get_usage(aref("alpha")).await.unwrap().into_inner();
    assert_eq!((live.attached_sessions, live.live_pairs), (7, 8));
    c.suspend_tenant(aref("alpha")).await.unwrap();
    // The running relay has not reloaded yet: the file still shows sessions.
    let suspended = c.get_usage(aref("alpha")).await.unwrap().into_inner();
    assert_eq!((suspended.attached_sessions, suspended.live_pairs), (0, 0));
    assert_eq!(suspended.bytes_period, live.bytes_period);
    assert_eq!(suspended.names, live.names);
    assert_eq!(suspended.period_end_unix, live.period_end_unix);
    c.resume_tenant(aref("alpha")).await.unwrap();
    let resumed = c.get_usage(aref("alpha")).await.unwrap().into_inner();
    assert_eq!(resumed.attached_sessions, 7);
    fx.shutdown().await;
}
