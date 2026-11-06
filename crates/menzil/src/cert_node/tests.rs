use std::path::Path;

use super::*;
use crate::agent::{query_node_status, renew_cert};
use crate::config::Config;
use crate::local::{init, load_identity, network_create};
use crate::node_cmd::{RunningNode, start};

const DAY: u64 = 24 * 60 * 60;

/// The real clock: the stores and the node's identity cell judge by it.
fn real_now() -> u64 {
    unix_now()
}

fn config(home: &Home) -> Config {
    let info = crate::relay_cmd::connection_info(
        // An address, not a name: nothing waits for a resolver, and the connection is refused
        // at once (the node keeps trying with backoff; none of these tests needs a relay).
        "127.0.0.1",
        9,
        crate::relay_cmd::DEFAULT_PATH,
        &crate::relay_cmd::relay_identity(home).unwrap(),
    )
    .unwrap();
    Config::parse(&format!("relay = \"{info}\"\nproxy = \"direct\"\n")).unwrap()
}

/// A device whose certificate has `left` of its 400 days to run, the owner of a network it is
/// the only member of, and a node running on it (no relay answers; none is needed).
async fn running(dir: &Path, left: u64) -> (Home, menzil_proto::NetworkId, RunningNode) {
    let home = Home::new(dir.join("home"));
    let now = real_now();
    init(&home, now - (400 * DAY - left)).unwrap();
    let network_id = network_create(&home, "laptop", now).unwrap();
    let node = start(&home, &config(&home), &dir.join("a.sock"))
        .await
        .unwrap();
    (home, network_id, node)
}

fn renewer(home: &Home, node: &RunningNode) -> CertRenewer {
    CertRenewer::new(
        home.clone(),
        node.node.clone(),
        node.node.policies().clone(),
    )
}

fn file_serial(home: &Home) -> u32 {
    load_identity(home).unwrap().1.decode().unwrap().serial
}

#[tokio::test]
async fn a_running_node_renews_writes_the_file_and_switches_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (home, network_id, node) = running(dir.path(), 300 * DAY).await;
    let renewer = renewer(&home, &node);
    let key_before = std::fs::read(home.identity_key_path()).unwrap();
    assert_eq!(node.node.own_cert().decode().unwrap().serial, 1);

    let renewed = renewer.renew(real_now()).await.unwrap();
    assert_eq!(renewed.serial, 2);
    // The file, the node and the answer agree; the key file is as it was.
    let (_, cert) = load_identity(&home).unwrap();
    assert_eq!(node.node.own_cert(), cert);
    assert_eq!(cert.decode().unwrap().serial, 2);
    assert_eq!(
        crate::token::decode_cert_request(&renewed.token).unwrap(),
        cert
    );
    assert_eq!(std::fs::read(home.identity_key_path()).unwrap(), key_before);

    // `status` says which networks do not list it: this one lists serial 1.
    let status = renewer.status(real_now()).unwrap();
    assert_eq!(status.serial, 2);
    assert_eq!(status.not_after, renewed.not_after);
    assert_eq!(status.unlisted.len(), 1);
    assert_eq!(status.unlisted[0].network, network_id);
    assert_eq!(status.unlisted[0].days, 299);
}

#[tokio::test]
async fn a_renewal_gets_above_the_serial_a_held_policy_lists_for_this_node() {
    // The file has serial 1; the network's documents list a serial 4 certificate of this device
    // (a restored backup is the usual way to get here).
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    let now = real_now();
    init(&home, now - 100 * DAY).unwrap();
    network_create(&home, "laptop", now).unwrap();
    let (keys, cert) = load_identity(&home).unwrap();
    let four = keys.next_cert(&cert, Some(3), now).unwrap();
    crate::local::cert_accept(
        &home,
        None,
        &crate::token::encode_cert_request(&four),
        now + 1,
    )
    .unwrap();
    assert_eq!(file_serial(&home), 1);
    let node = start(&home, &config(&home), &dir.path().join("a.sock"))
        .await
        .unwrap();
    let renewer = renewer(&home, &node);
    let renewed = renewer.renew(real_now()).await.unwrap();
    assert_eq!(renewed.serial, 5);
    assert_eq!(file_serial(&home), 5);
}

#[tokio::test]
async fn two_renewals_at_once_get_two_serials() {
    let dir = tempfile::tempdir().unwrap();
    let (home, _, node) = running(dir.path(), 300 * DAY).await;
    let renewer = renewer(&home, &node);
    let (a, b) = tokio::join!(renewer.renew(real_now()), renewer.renew(real_now()));
    let mut serials = [a.unwrap().serial, b.unwrap().serial];
    serials.sort_unstable();
    assert_eq!(serials, [2, 3]);
    assert_eq!(file_serial(&home), 3);
    assert_eq!(node.node.own_cert().decode().unwrap().serial, 3);
}

#[tokio::test]
async fn a_node_with_a_certificate_inside_sixty_days_renews_it_by_itself_at_start() {
    let dir = tempfile::tempdir().unwrap();
    // 20 days left: the check the node runs at start renews it, once.
    let (home, _, node) = running(dir.path(), 20 * DAY).await;
    let started = std::time::Instant::now();
    // The file is written first and the node switches right after: wait for the later one.
    while node.node.own_cert().decode().unwrap().serial < 2 {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "the node did not renew its certificate by itself"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(file_serial(&home), 2);
    assert_eq!(node.node.own_cert().decode().unwrap().serial, 2);
    // The next check finds 400 days left.
    let renewer = renewer(&home, &node);
    let mut state = CheckState::default();
    let checked = renewer.check(&mut state, real_now()).await;
    assert!(checked.renewal.is_none());
    assert_eq!(file_serial(&home), 2);
}

#[tokio::test]
async fn a_node_whose_certificate_does_not_start_yet_renews_it_by_itself_at_start() {
    // Round C L2: the certificate was made while the clock ran ahead (10 days), so it starts in
    // the future and has 390 days to run: only the start counts, not the 60 day rule.
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    let now = real_now();
    init(&home, now + 10 * DAY).unwrap();
    network_create(&home, "laptop", now + 10 * DAY).unwrap();
    let before = load_identity(&home).unwrap().1.decode().unwrap();
    assert!(before.not_before > now);
    let node = start(&home, &config(&home), &dir.path().join("a.sock"))
        .await
        .unwrap();
    let started = std::time::Instant::now();
    while node.node.own_cert().decode().unwrap().serial < 2 {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "the node did not renew a certificate that does not start yet"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let after = load_identity(&home).unwrap().1.decode().unwrap();
    assert_eq!(after.serial, 2);
    assert!(after.is_valid_at(real_now()));
    // The renewal is valid now, so the next check leaves it alone.
    let renewer = renewer(&home, &node);
    let mut state = CheckState::default();
    assert!(
        renewer
            .check(&mut state, real_now())
            .await
            .renewal
            .is_none()
    );
    assert_eq!(file_serial(&home), 2);
}

#[tokio::test]
async fn the_check_warns_once_a_day_about_a_network_that_lists_an_older_certificate_ending_soon() {
    let dir = tempfile::tempdir().unwrap();
    let home = Home::new(dir.path().join("home"));
    let now = real_now();
    // The network lists serial 1, which ends in 20 days; the device has renewed since (400 days,
    // so the node has nothing to renew), and nobody has listed the renewal yet.
    init(&home, now - 380 * DAY).unwrap();
    let network_id = network_create(&home, "laptop", now).unwrap();
    crate::local::cert_renew(&home, now).unwrap();
    let node = start(&home, &config(&home), &dir.path().join("a.sock"))
        .await
        .unwrap();
    let renewer = renewer(&home, &node);
    let mut state = CheckState::default();

    let first = renewer.check(&mut state, now).await;
    assert!(first.renewal.is_none());
    assert_eq!(first.warnings, vec![(network_id, 19)]);
    // Six hours later it was said today.
    let second = renewer.check(&mut state, now + 6 * 60 * 60).await;
    assert!(second.warnings.is_empty());
    // A day later it is said again.
    let third = renewer.check(&mut state, now + DAY).await;
    assert_eq!(third.warnings.len(), 1);
    assert_eq!(file_serial(&home), 2);
    // `status` names the same network.
    let status = renewer.status(now).unwrap();
    assert_eq!(status.unlisted.len(), 1);
    assert_eq!(status.unlisted[0].network, network_id);
}

#[tokio::test]
async fn the_check_leaves_a_certificate_with_time_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (home, _, node) = running(dir.path(), 61 * DAY).await;
    let renewer = renewer(&home, &node);
    let mut state = CheckState::default();
    let checked = renewer.check(&mut state, real_now()).await;
    assert!(checked.renewal.is_none() && checked.warnings.is_empty());
    assert_eq!(file_serial(&home), 1);
}

#[tokio::test]
async fn the_agent_socket_renews_for_the_cli_and_reports_the_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let (home, network_id, node) = running(dir.path(), 300 * DAY).await;

    let renewed = renew_cert(&node.socket).await.unwrap();
    assert_eq!(renewed.serial, 2);
    assert_eq!(file_serial(&home), 2);
    assert_eq!(node.node.own_cert().decode().unwrap().serial, 2);

    let status = query_node_status(&node.socket).await.unwrap();
    let cert = status.cert.expect("the node reports its certificate");
    assert_eq!(cert.serial, 2);
    assert_eq!(cert.unlisted.len(), 1);
    assert_eq!(cert.unlisted[0].network, network_id);
    assert!(status.relay.attached.is_some());
}

#[tokio::test]
async fn an_offline_renewal_is_refused_while_the_node_runs_and_works_after_it_stops() {
    let dir = tempfile::tempdir().unwrap();
    let (home, _, node) = running(dir.path(), 300 * DAY).await;
    let error = format!(
        "{:#}",
        crate::local::cert_renew(&home, real_now()).unwrap_err()
    );
    assert!(error.contains("`menzil node` is running"), "{error}");
    assert_eq!(file_serial(&home), 1);
    drop(node);
    let renewed = crate::local::cert_renew(&home, real_now()).unwrap();
    assert_eq!(renewed.serial, 2);
}

#[tokio::test]
async fn a_steward_node_considers_its_own_certificate_beside_the_pushed_ones() {
    let dir = tempfile::tempdir().unwrap();
    let (home, network_id, node) = running(dir.path(), 300 * DAY).await;
    let first = crate::steward_loop::candidates_of(&node.node, network_id);
    assert_eq!(first, vec![node.node.own_cert()]);
    let renewer = renewer(&home, &node);
    renewer.renew(real_now()).await.unwrap();
    let after = crate::steward_loop::candidates_of(&node.node, network_id);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].decode().unwrap().serial, 2);
}
