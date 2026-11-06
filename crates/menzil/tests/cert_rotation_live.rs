//! Certificate rotation end to end (cert-rotation design S8, Q6, Q7, Q9, Q11), with real nodes
//! (`menzil_cli::node_cmd::start`, the code `menzil node` runs), a real relay with TLS and the real
//! clock. A device's first certificate is valid for a minute only, and the test knobs
//! (`menzil_cli::cert_renew::test_knob`, debug builds) shorten the node's timers to seconds.
//!
//! * **A steward network.** A member's certificate comes within the renewal threshold, the node
//!   renews, pushes the `node_cert` over the session it has, the steward node lists it, the
//!   member and the peer adopt the pair. A stream opened before the renewal stays up across all
//!   of it and past the instant the old certificate ran out.
//! * **An owner only network.** The renewed certificate is handed over as a token and nobody
//!   lists it: the sessions close at the old `not_after`, and no stream opens. A late
//!   `cert accept` brings the device back.
//! * **A new identity.** `init --new-identity` and `admit --replace`: the new device reaches what
//!   the old one could, and the old identity is turned away at the relay.
//! * **An unlisted renewal offered again.** The steward node loses the candidate it recorded; the
//!   device's periodic check offers the renewal again over the session that is up.
//!
//! The flows run side by side in one `#[tokio::test]` (each with its own relay and homes), for
//! the same reason the other live tests have exactly one: `SSL_CERT_FILE` and the knobs are
//! process-global.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::time::{Duration, Instant};

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_cli::agent::renew_cert;
use menzil_cli::cert_renew::listed_cert;
use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::local::{
    admit, cert_accept, cert_request, cert_show, grant, init, join, load_identity, network_create,
    new_identity, replace, steward_add, steward_request, token_for_relay,
};
use menzil_cli::node_cmd::{self, RunningNode};
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use menzil_node::Holder;
use menzil_proto::{NetworkId, NodeId};
use menzil_stream::Stream;
use tokio::net::TcpListener;

const DAY: u64 = 24 * 60 * 60;
const WAIT: Duration = Duration::from_secs(60);
/// How long a device's first certificate lives in the flows that renew it, seconds.
const SHORT_LIFE: u64 = 60;
/// The renewal threshold the knob sets, seconds: a node renews when its certificate has this
/// long left.
const RENEW_WITHIN: u64 = 35;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The `now` to give `init` so that the certificate it makes runs out `life` seconds from the
/// real clock: `init` counts 400 days from five minutes before the `now` it is given.
fn init_clock_for(life: u64) -> u64 {
    unix_now() + life + 300 - 400 * DAY
}

async fn until(flow: &str, what: &str, mut check: impl FnMut() -> bool) {
    let started = Instant::now();
    while !check() {
        assert!(
            started.elapsed() < WAIT,
            "{flow}: timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Echoes every byte until the peer's end of file.
async fn echo_server(listener: TcpListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            while let Ok(n) = socket.read(&mut buf).await {
                if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = socket.shutdown().await;
        });
    }
}

/// Sends `data` through the stream and waits for as many bytes back.
async fn echo(stream: &mut Stream, data: &[u8]) -> Result<(), String> {
    let round = async {
        stream.write_all(data).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        let mut back = vec![0u8; data.len()];
        stream
            .read_exact(&mut back)
            .await
            .map_err(|e| e.to_string())?;
        if back == data {
            Ok(())
        } else {
            Err("the echo came back changed".to_string())
        }
    };
    match tokio::time::timeout(Duration::from_secs(10), round).await {
        Ok(result) => result,
        Err(_) => Err("no echo within 10 s".to_string()),
    }
}

/// Opens a stream to `service` on `peer` and echoes once through it, or says why not.
async fn reach(
    node: &RunningNode,
    peer: NodeId,
    network_id: NetworkId,
    service: &str,
    data: &[u8],
) -> Result<Stream, String> {
    let opened = tokio::time::timeout(
        Duration::from_secs(20),
        node.node
            .open_stream(peer, network_id, service.parse().unwrap(), None),
    )
    .await
    .map_err(|_| "opening the stream took over 20 s".to_string())?
    .map_err(|e| e.to_string());
    let mut stream = opened?;
    echo(&mut stream, data).await?;
    Ok(stream)
}

fn write_config(home: &Home, relay: &str, services: &str) {
    std::fs::create_dir_all(home.root()).unwrap();
    std::fs::write(
        home.config_path(),
        format!("relay = \"{relay}\"\nproxy = \"direct\"\n{services}"),
    )
    .unwrap();
}

async fn start_node(home: &Home, socket: &Path) -> RunningNode {
    let node = node_cmd::start(home, &Config::load(home).unwrap(), socket)
        .await
        .unwrap();
    node.node
        .wait_attached(WAIT)
        .await
        .expect("the node attaches");
    node
}

struct Tls {
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
}

async fn start_relay(root: &Path, tls: &Tls, owner_home: &Home) -> relay_cmd::RunningRelay {
    let relay_home = Home::new(root.join("relay"));
    init(&relay_home, unix_now()).unwrap();
    relay_cmd::add_network(
        &relay_home,
        &token_for_relay(owner_home, None).unwrap(),
        unix_now(),
    )
    .unwrap();
    relay_cmd::start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: tls.cert.clone(),
            tls_key: tls.key.clone(),
            path: DEFAULT_PATH.to_string(),
            host: Some("localhost".to_string()),
            reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
        },
    )
    .await
    .unwrap()
}

fn lists_serial(node: &RunningNode, network_id: &NetworkId, who: &NodeId, serial: u32) -> bool {
    node.node
        .policies()
        .body(network_id)
        .and_then(|body| listed_cert(&body, who))
        .is_some_and(|listed| listed.serial >= serial)
}

// ---- flow A: a steward network ------------------------------------------------------------

async fn steward_flow(root: &Path, tls: &Tls) {
    const FLOW: &str = "steward network";
    let real = unix_now();
    let owner_home = Home::new(root.join("owner"));
    let steward_home = Home::new(root.join("steward"));
    let server_home = Home::new(root.join("server"));
    let phone_home = Home::new(root.join("phone"));
    init(&owner_home, real).unwrap();
    let network_id = network_create(&owner_home, "owner", real).unwrap();
    let steward = init(&steward_home, real).unwrap();
    let server = init(&server_home, real).unwrap();
    // The phone's certificate runs out a minute from now.
    let phone = init(&phone_home, init_clock_for(SHORT_LIFE)).unwrap();
    let old_not_after = cert_show(&phone_home).unwrap().not_after;

    let admitted = admit(
        &owner_home,
        None,
        &steward.join_request,
        "steward",
        &[],
        real,
    )
    .unwrap();
    join(&steward_home, &admitted.token, real).unwrap();
    admit(&owner_home, None, &server.join_request, "server", &[], real).unwrap();
    admit(&owner_home, None, &phone.join_request, "phone", &[], real).unwrap();
    let echo_service = ["tcp:echo".parse().unwrap()];
    grant(
        &owner_home,
        None,
        "phone",
        "server",
        &echo_service,
        None,
        real,
    )
    .unwrap();
    grant(
        &owner_home,
        None,
        "phone",
        "steward",
        &echo_service,
        None,
        real,
    )
    .unwrap();
    let asked = steward_request(&steward_home, None).unwrap();
    let may = ["admit".to_string(), "renew".to_string()];
    let listed = steward_add(&owner_home, None, &asked.token, &may, 30, real).unwrap();
    for home in [&steward_home, &server_home, &phone_home] {
        join(home, &listed.issued.token, real).unwrap();
    }
    let relay = start_relay(root, tls, &owner_home).await;

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo_listener));
    let services = format!("[services]\n\"tcp:echo\" = \"127.0.0.1:{echo_port}\"\n");
    write_config(&steward_home, &relay.connection_info, &services);
    write_config(&server_home, &relay.connection_info, &services);
    write_config(&phone_home, &relay.connection_info, "");

    let server_node = start_node(&server_home, &root.join("server.sock")).await;
    let steward_node = start_node(&steward_home, &root.join("steward.sock")).await;
    let phone_node = start_node(&phone_home, &root.join("phone.sock")).await;
    assert!(
        unix_now() + RENEW_WITHIN + 5 < old_not_after,
        "{FLOW}: setup took too long, the renewal threshold has passed already"
    );

    // Two streams opened before the renewal: to the server (the one that has to survive), and
    // to the steward, which makes the session the renewed certificate is pushed over.
    let mut to_server = reach(
        &phone_node,
        server.node_id,
        network_id,
        "tcp:echo",
        b"first",
    )
    .await
    .expect("phone reaches the server");
    let mut to_steward = reach(
        &phone_node,
        steward.node_id,
        network_id,
        "tcp:echo",
        b"first",
    )
    .await
    .expect("phone reaches the steward");
    assert_eq!(phone_node.node.own_cert().decode().unwrap().serial, 1);

    // The phone's node renews once the certificate has `RENEW_WITHIN` left.
    until(FLOW, "the phone to renew", || {
        phone_node.node.own_cert().decode().unwrap().serial == 2
    })
    .await;
    assert!(
        unix_now() < old_not_after,
        "{FLOW}: the renewal came after the old certificate ran out"
    );
    let on_disk = load_identity(&phone_home).unwrap().1.decode().unwrap();
    assert_eq!(on_disk.serial, 2, "{FLOW}: the renewal is on the disk");

    // The steward lists it, and the phone and the server take the pair.
    until(FLOW, "the steward to list the renewal", || {
        lists_serial(&steward_node, &network_id, &phone.node_id, 2)
    })
    .await;
    until(FLOW, "the phone and the server to adopt it", || {
        lists_serial(&phone_node, &network_id, &phone.node_id, 2)
            && lists_serial(&server_node, &network_id, &phone.node_id, 2)
    })
    .await;
    until(FLOW, "the phone's disk to list it", || {
        cert_show(&phone_home).is_ok_and(|report| {
            report
                .networks
                .first()
                .and_then(|n| n.listed)
                .map(|l| l.serial)
                == Some(2)
        })
    })
    .await;

    // Across the instant the old certificate runs out, the stream goes on, round after round.
    let mut round = 0u32;
    while unix_now() < old_not_after + 4 {
        let data = format!("round {round}");
        echo(&mut to_server, data.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("{FLOW}: the stream to the server broke: {e}"));
        echo(&mut to_steward, data.as_bytes())
            .await
            .unwrap_or_else(|e| panic!("{FLOW}: the stream to the steward broke: {e}"));
        round += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let mut fresh = reach(
        &phone_node,
        server.node_id,
        network_id,
        "tcp:echo",
        b"fresh",
    )
    .await
    .unwrap_or_else(|e| panic!("{FLOW}: a new stream after the old certificate: {e}"));
    echo(&mut fresh, b"and again").await.unwrap();

    drop((to_server, to_steward, fresh));
    drop((phone_node, steward_node, server_node));
    relay.stop();
}

// ---- flow B: an owner only network --------------------------------------------------------

async fn owner_only_flow(root: &Path, tls: &Tls) {
    const FLOW: &str = "owner only network";
    let real = unix_now();
    let owner_home = Home::new(root.join("owner"));
    let phone_home = Home::new(root.join("phone"));
    let owner = init(&owner_home, real).unwrap();
    let network_id = network_create(&owner_home, "owner", real).unwrap();
    let phone = init(&phone_home, init_clock_for(SHORT_LIFE)).unwrap();
    let old_not_after = cert_show(&phone_home).unwrap().not_after;
    admit(&owner_home, None, &phone.join_request, "phone", &[], real).unwrap();
    let echo_service = ["tcp:echo".parse().unwrap()];
    let issued = grant(
        &owner_home,
        None,
        "phone",
        "owner",
        &echo_service,
        None,
        real,
    )
    .unwrap();
    join(&phone_home, &issued.token, real).unwrap();
    let relay = start_relay(root, tls, &owner_home).await;

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo_listener));
    write_config(
        &owner_home,
        &relay.connection_info,
        &format!("[services]\n\"tcp:echo\" = \"127.0.0.1:{echo_port}\"\n"),
    );
    write_config(&phone_home, &relay.connection_info, "");
    let owner_node = start_node(&owner_home, &root.join("owner.sock")).await;
    let phone_node = start_node(&phone_home, &root.join("phone.sock")).await;
    assert!(
        unix_now() + RENEW_WITHIN + 5 < old_not_after,
        "{FLOW}: setup took too long, the renewal threshold has passed already"
    );

    let mut stream = reach(&phone_node, owner.node_id, network_id, "tcp:echo", b"first")
        .await
        .expect("phone reaches the owner");

    // The phone renews by itself, and nobody lists it: the report says so, and the token is
    // what the owner is handed.
    until(FLOW, "the phone to renew", || {
        phone_node.node.own_cert().decode().unwrap().serial == 2
    })
    .await;
    let report = cert_show(&phone_home).unwrap();
    assert_eq!(report.serial, 2);
    assert_eq!(
        report.networks[0].listed.map(|l| l.serial),
        Some(1),
        "{FLOW}: the held documents still list serial 1"
    );
    let token = cert_request(&phone_home).unwrap();
    assert!(token.starts_with("menzil1-cert:"), "{FLOW}: {token}");
    // The owner's node (no steward listed) only logs the renewal: it keeps no candidate.
    assert!(owner_node.node.cert_candidates(network_id).is_empty());

    // Until the old certificate runs out the stream is fine; right after, it is closed.
    while unix_now() + 3 < old_not_after {
        echo(&mut stream, b"still listed")
            .await
            .unwrap_or_else(|e| panic!("{FLOW}: the stream broke before the old not_after: {e}"));
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let closed = Instant::now();
    loop {
        if echo(&mut stream, b"after").await.is_err() {
            break;
        }
        assert!(
            closed.elapsed() < Duration::from_secs(25),
            "{FLOW}: the stream was still up 25 s after the old certificate ran out"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        unix_now() + 1 >= old_not_after,
        "{FLOW}: the stream closed before the old certificate ran out"
    );
    drop(stream);
    assert!(
        reach(&phone_node, owner.node_id, network_id, "tcp:echo", b"x")
            .await
            .is_err(),
        "{FLOW}: no stream opens while no Policy lists the renewal"
    );

    // The owner accepts the token late; its node pushes the pair; the phone is whole again.
    let accepted = cert_accept(&owner_home, None, &token, unix_now()).unwrap();
    until(FLOW, "the phone to adopt the accepted certificate", || {
        lists_serial(&phone_node, &network_id, &phone.node_id, 2)
    })
    .await;
    assert!(accepted.seq > issued.seq);
    let started = Instant::now();
    let mut back = loop {
        match reach(&phone_node, owner.node_id, network_id, "tcp:echo", b"back").await {
            Ok(stream) => break stream,
            Err(error) => {
                assert!(
                    started.elapsed() < WAIT,
                    "{FLOW}: no stream after the late accept: {error}"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };
    echo(&mut back, b"and again").await.unwrap();

    drop(back);
    drop((phone_node, owner_node));
    relay.stop();
}

// ---- flow C: a new identity replaces an old one -------------------------------------------

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

async fn replace_flow(root: &Path, tls: &Tls) {
    const FLOW: &str = "new identity";
    let real = unix_now();
    let owner_home = Home::new(root.join("owner"));
    let phone_home = Home::new(root.join("phone"));
    let owner = init(&owner_home, real).unwrap();
    let network_id = network_create(&owner_home, "owner", real).unwrap();
    let phone = init(&phone_home, real).unwrap();
    admit(&owner_home, None, &phone.join_request, "phone", &[], real).unwrap();
    let echo_service = ["tcp:echo".parse().unwrap()];
    let issued = grant(
        &owner_home,
        None,
        "phone",
        "owner",
        &echo_service,
        None,
        real,
    )
    .unwrap();
    join(&phone_home, &issued.token, real).unwrap();
    let relay = start_relay(root, tls, &owner_home).await;

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo_listener));
    write_config(
        &owner_home,
        &relay.connection_info,
        &format!("[services]\n\"tcp:echo\" = \"127.0.0.1:{echo_port}\"\n"),
    );
    write_config(&phone_home, &relay.connection_info, "");
    let owner_node = start_node(&owner_home, &root.join("owner.sock")).await;

    // The old device reaches the owner.
    let phone_node = start_node(&phone_home, &root.join("phone.sock")).await;
    let first = reach(&phone_node, owner.node_id, network_id, "tcp:echo", b"old")
        .await
        .expect("the old phone reaches the owner");
    drop(first);
    // A copy of the old device: what is left on a stolen or restored disk.
    let old_home = Home::new(root.join("old-phone"));
    copy_dir(phone_home.root(), old_home.root());
    drop(phone_node);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // The user starts again on the same home: `init --new-identity`.
    let renewed = new_identity(&phone_home, real).unwrap();
    assert_eq!(renewed.old, phone.node_id);
    assert_ne!(renewed.made.node_id, phone.node_id);
    assert!(renewed.retired.key.exists() && renewed.retired.cert.exists());
    assert_eq!(
        renewed.networks,
        vec![(network_id, "phone".to_string())],
        "{FLOW}: the old node's place is named for the owner"
    );
    // The owner moves the name, the role and the grants to the new device and revokes the old.
    let replaced = replace(
        &owner_home,
        None,
        "phone",
        &renewed.made.join_request,
        unix_now(),
    )
    .unwrap();
    assert_eq!(replaced.old, phone.node_id);
    assert_eq!(replaced.name, "phone");
    join(&phone_home, &replaced.issued.token, unix_now()).unwrap();

    // The new device reaches what the old one could.
    let new_phone = start_node(&phone_home, &root.join("phone-new.sock")).await;
    let started = Instant::now();
    let mut stream = loop {
        match reach(&new_phone, owner.node_id, network_id, "tcp:echo", b"new").await {
            Ok(stream) => break stream,
            Err(error) => {
                assert!(
                    started.elapsed() < WAIT,
                    "{FLOW}: the new device cannot reach the owner: {error}"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    };
    echo(&mut stream, b"again").await.unwrap();
    drop(stream);

    // The owner's node holds the revocation, and so tells the relay.
    until(FLOW, "the owner's node to hold the replacement", || {
        owner_node
            .node
            .rosters()
            .body(&network_id)
            .is_some_and(|body| body.revoked.iter().any(|r| r.node_id == phone.node_id))
    })
    .await;

    // The old identity is turned away at the relay (it was granted a stream once), and cannot
    // reach the owner.
    let old = start_old(&old_home, &root.join("old.sock")).await;
    until(FLOW, "the relay to turn the old identity away", || {
        old.node.last_relay_error().is_some()
    })
    .await;
    let error = old.node.last_relay_error().unwrap();
    eprintln!("the relay said to the old identity: {error:?}");
    assert!(
        reach(&old, owner.node_id, network_id, "tcp:echo", b"old again")
            .await
            .is_err(),
        "{FLOW}: the old identity reached the owner"
    );

    drop((old, new_phone, owner_node));
    relay.stop();
}

// ---- flow D: an unlisted renewal is offered again ----------------------------------------

/// Round C M1. The phone renews and the steward node records the renewal as its candidate (the
/// steward lists a renewal only when it extends the listed certificate by 30 days, and this one
/// does not). The steward then loses its candidates (what a changed steward entry or a Policy
/// that stops listing the serial does), and nothing new is announced by a renewal: the phone's
/// periodic check has to offer the unlisted certificate again over the session that is up.
async fn relist_flow(root: &Path, tls: &Tls) {
    const FLOW: &str = "unlisted renewal offered again";
    let real = unix_now();
    let owner_home = Home::new(root.join("owner"));
    let steward_home = Home::new(root.join("steward"));
    let phone_home = Home::new(root.join("phone"));
    init(&owner_home, real).unwrap();
    let network_id = network_create(&owner_home, "owner", real).unwrap();
    let steward = init(&steward_home, real).unwrap();
    let phone = init(&phone_home, real).unwrap();
    let admitted = admit(
        &owner_home,
        None,
        &steward.join_request,
        "steward",
        &[],
        real,
    )
    .unwrap();
    join(&steward_home, &admitted.token, real).unwrap();
    admit(&owner_home, None, &phone.join_request, "phone", &[], real).unwrap();
    grant(
        &owner_home,
        None,
        "phone",
        "steward",
        &["tcp:echo".parse().unwrap()],
        None,
        real,
    )
    .unwrap();
    let asked = steward_request(&steward_home, None).unwrap();
    let may = ["admit".to_string(), "renew".to_string()];
    let listed = steward_add(&owner_home, None, &asked.token, &may, 30, real).unwrap();
    for home in [&steward_home, &phone_home] {
        join(home, &listed.issued.token, real).unwrap();
    }
    let relay = start_relay(root, tls, &owner_home).await;

    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo_listener));
    write_config(
        &steward_home,
        &relay.connection_info,
        &format!("[services]\n\"tcp:echo\" = \"127.0.0.1:{echo_port}\"\n"),
    );
    write_config(&phone_home, &relay.connection_info, "");
    let steward_node = start_node(&steward_home, &root.join("steward.sock")).await;
    let phone_node = start_node(&phone_home, &root.join("phone.sock")).await;
    let serials = |node: &RunningNode| -> Vec<u32> {
        node.node
            .cert_candidates(network_id)
            .iter()
            .map(|cert| cert.decode().unwrap().serial)
            .collect()
    };

    // The session the pushes ride on.
    let stream = reach(
        &phone_node,
        steward.node_id,
        network_id,
        "tcp:echo",
        b"first",
    )
    .await
    .expect("phone reaches the steward");
    renew_cert(&phone_node.socket).await.unwrap();
    until(FLOW, "the steward to record the renewal", || {
        serials(&steward_node) == [2]
    })
    .await;

    // The steward forgets it (and takes the entry again, as its loop does at the next change).
    steward_node.node.set_candidate_holder(network_id, None);
    assert!(serials(&steward_node).is_empty());
    steward_node.node.set_candidate_holder(
        network_id,
        Some(Holder::Steward {
            admit: true,
            renew: true,
            not_after: unix_now() + DAY,
        }),
    );
    until(FLOW, "the phone to offer the renewal again", || {
        serials(&steward_node) == [2]
    })
    .await;

    drop(stream);
    drop((phone_node, steward_node));
    relay.stop();
}

/// The old identity's node: it may attach for a moment (the relay answers after WELCOME).
async fn start_old(home: &Home, socket: &Path) -> RunningNode {
    node_cmd::start(home, &Config::load(home).unwrap(), socket)
        .await
        .unwrap()
}

#[tokio::test]
async fn certificates_rotate_in_a_steward_network_an_owner_network_and_a_new_identity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let tls = Tls {
        cert: root.join("fullchain.pem"),
        key: root.join("privkey.pem"),
    };
    std::fs::write(&tls.cert, certified.cert.pem()).unwrap();
    std::fs::write(&tls.key, certified.signing_key.serialize_pem()).unwrap();
    // SAFETY: the first thing the only test in this binary does, before any dial or other thread
    // that could read the environment.
    unsafe {
        std::env::set_var("SSL_CERT_FILE", &tls.cert);
        // The hidden timing knobs (`cert_renew::test_knob`): the node looks at its certificate
        // every second and renews at `RENEW_WITHIN` seconds, the steward loop and the document
        // reload look every second.
        std::env::set_var("MENZIL_TEST_RENEW_WITHIN", RENEW_WITHIN.to_string());
        std::env::set_var("MENZIL_TEST_CHECK_EVERY", "1");
        std::env::set_var("MENZIL_TEST_POLL", "1");
        std::env::set_var("MENZIL_TEST_RELOAD_EVERY", "1");
    }

    // The knobs are not a user feature: the command line does not mention them.
    for args in [
        &["--help"][..],
        &["cert", "--help"][..],
        &["node", "--help"][..],
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_menzil"))
            .args(args)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase()
            + &String::from_utf8_lossy(&out.stderr).to_lowercase();
        assert!(
            !text.contains("menzil_test") && !text.contains("knob"),
            "{text}"
        );
    }

    let (a, b, c, d) = (
        root.join("a"),
        root.join("b"),
        root.join("c"),
        root.join("d"),
    );
    tokio::join!(
        steward_flow(&a, &tls),
        owner_only_flow(&b, &tls),
        replace_flow(&c, &tls),
        relist_flow(&d, &tls)
    );
}
