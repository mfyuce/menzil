//! Invite redemption end to end against a real relay and a steward node (slice D3 B5, design
//! note B3, B6, B7): the steward (not the owner) signs the invites and is the issuer.
//!
//! * Two devices race for a `uses = 1` invite: exactly one is admitted (the Roster lists it, the
//!   steward's invite book counts one NodeId), the other is refused `bad_invite`.
//! * The winner's request replayed with a third NodeCert is refused `bad_tag` and spends
//!   nothing; the exact request replayed to the relay again is answered with the Roster again
//!   and counts nothing (idempotence per NodeId).
//! * A `uses = 3` invite redeemed by five devices at once admits exactly three.
//! * An expired and a revoked invite are refused.
//! * The issuer node restarted: the book still counts, a repeat is still idempotent and a
//!   partly used invite has exactly its remaining uses.
//! * The winner's own node then gets the Policy by the steward's push and, once the owner grants
//!   it, opens a stream to the steward.
//!
//! One `#[tokio::test]`: `SSL_CERT_FILE` is process-global and must be set before anything dials.

#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_carrier::{ConnectionInfo, DialConfig, ProxyOverride};
use menzil_cli::config::Config;
use menzil_cli::home::Home;
use menzil_cli::invite::{self, CreateSpec, load_book};
use menzil_cli::join::{self, JoinError, JoinOptions, Joined, redeem};
use menzil_cli::local::{
    admit, grant, init, join as join_documents, load_identity, network_create, steward_add,
    steward_request, token, token_for_relay,
};
use menzil_cli::node_cmd::{self, RunningNode};
use menzil_cli::relay_cmd::{self, DEFAULT_PATH, RunOptions};
use menzil_node::{KnownRelays, LocalIdentity, Session, SessionConfig};
use menzil_proto::{
    AdmitRequestBody, AdmitResultBody, ErrorCode, InviteId, NetworkId, NodeId, Record, Roster,
};
use tokio::net::TcpListener;

const WAIT: Duration = Duration::from_secs(60);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn until(what: &str, mut check: impl FnMut() -> bool) {
    let started = Instant::now();
    while !check() {
        assert!(started.elapsed() < WAIT, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn options(name: &str) -> JoinOptions {
    JoinOptions {
        name: Some(name.to_string()),
        wait: Duration::from_secs(40),
        retry_first: Duration::from_secs(1),
        retry_max: Duration::from_secs(2),
    }
}

/// A device home with an identity and a config that dials directly.
fn device(root: &Path, label: &str, real: u64) -> (Home, String) {
    let home = Home::new(root.join(label));
    init(&home, real).unwrap();
    std::fs::write(home.config_path(), "proxy = \"direct\"\n").unwrap();
    (home, label.to_string())
}

fn node_id_of(home: &Home) -> NodeId {
    load_identity(home).unwrap().1.decode().unwrap().node_id
}

/// The code that refused a redeem attempt, if one did.
fn refusal(result: &Result<Joined, JoinError>) -> Option<ErrorCode> {
    match result {
        Err(JoinError::Refused { code, .. }) => Some(*code),
        _ => None,
    }
}

/// Redeems `token` from each `(home, name)` at once; the results in the same order.
async fn race(token: &str, devices: &[(Home, String)]) -> Vec<Result<Joined, JoinError>> {
    let handles: Vec<_> = devices
        .iter()
        .map(|(home, name)| {
            let (home, name, token) = (home.clone(), name.clone(), token.to_string());
            tokio::spawn(async move { redeem(&home, &token, &options(&name), &mut |_| {}).await })
        })
        .collect();
    let mut results = Vec::new();
    for handle in handles {
        results.push(tokio::time::timeout(WAIT, handle).await.unwrap().unwrap());
    }
    results
}

/// The relay's answer to a request, as a code or the Roster.
#[derive(Debug)]
enum Answer {
    Admitted(Box<Roster>),
    Refused(ErrorCode),
}

/// Sends `request` over a redeem session of `home`'s identity (the HELLO presents that
/// identity's certificate, the request carries whatever certificate it carries) and waits for the
/// answer.
async fn ask(home: &Home, relay: &str, request: AdmitRequestBody) -> Answer {
    let (keys, cert) = load_identity(home).unwrap();
    let config = SessionConfig {
        dial: DialConfig {
            connection_info: ConnectionInfo::parse(relay).unwrap(),
            proxy_override: Some(ProxyOverride::Direct),
        },
        identity: LocalIdentity {
            node_cert: cert,
            x25519_private: *keys.x25519_private(),
        }
        .into(),
        networks: vec![],
        caps: vec![],
        e2e_protos: vec![0x01],
        known_relays: Arc::new(KnownRelays::in_memory()),
    };
    let mut session = Session::connect_redeem(&config, &Default::default())
        .await
        .expect("the redeem session opens");
    session.send(Record::AdmitRequest(request)).await.unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match session.recv().await.expect("the session stays up") {
                Record::AdmitResult(AdmitResultBody::Pending) => {}
                Record::AdmitResult(AdmitResultBody::Admitted { roster, .. }) => {
                    return Answer::Admitted(Box::new(roster));
                }
                Record::AdmitResult(AdmitResultBody::Refused(code)) => {
                    return Answer::Refused(ErrorCode::from(code));
                }
                Record::Error(body) => return Answer::Refused(body.code),
                _ => {}
            }
        }
    })
    .await
    .expect("the relay answers");
    session.close().await;
    answer
}

fn redeemed(steward_home: &Home, network_id: &NetworkId, id: &InviteId) -> Vec<NodeId> {
    load_book(steward_home, network_id)
        .unwrap()
        .get(id)
        .expect("the invite is in the book")
        .redeemed
        .clone()
}

fn is_member(node: &RunningNode, network_id: &NetworkId, who: &NodeId) -> bool {
    node.node
        .rosters()
        .body(network_id)
        .is_some_and(|body| body.members.iter().any(|m| m.node_id == *who))
}

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

async fn start_node(home: &Home, socket: &Path) -> RunningNode {
    let node = node_cmd::start(home, &Config::load(home).unwrap(), socket)
        .await
        .unwrap();
    node.node.wait_attached(WAIT).await.expect("node attaches");
    node
}

#[tokio::test]
async fn invites_redeem_exactly_as_often_as_they_allow() {
    let real = unix_now();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = root.join("fullchain.pem");
    let key_pem = root.join("privkey.pem");
    std::fs::write(&cert_pem, certified.cert.pem()).unwrap();
    std::fs::write(&key_pem, certified.signing_key.serialize_pem()).unwrap();
    // SAFETY: the first thing the only test in this binary does, before any dial or other thread
    // that could read the environment.
    unsafe { std::env::set_var("SSL_CERT_FILE", &cert_pem) };

    // ---- the network: an owner, a steward that may admit, a relay ---------------------------
    let relay_home = Home::new(root.join("relay"));
    let owner_home = Home::new(root.join("owner"));
    let steward_home = Home::new(root.join("steward"));
    init(&relay_home, real).unwrap();
    init(&owner_home, real).unwrap();
    let network_id = network_create(&owner_home, "owner", real).unwrap();
    let steward_join = init(&steward_home, real).unwrap().join_request;
    let steward_id = node_id_of(&steward_home);
    let admitted = admit(&owner_home, None, &steward_join, "steward", &[], real).unwrap();
    join_documents(&steward_home, &admitted.token, real).unwrap();
    let asked = steward_request(&steward_home, None).unwrap();
    let may = ["admit".to_string()];
    let listed = steward_add(&owner_home, None, &asked.token, &may, 30, real).unwrap();
    join_documents(&steward_home, &listed.issued.token, real).unwrap();
    relay_cmd::add_network(
        &relay_home,
        &token_for_relay(&owner_home, None).unwrap(),
        real,
    )
    .unwrap();
    let relay = relay_cmd::start(
        &relay_home,
        &RunOptions {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_cert: cert_pem.clone(),
            tls_key: key_pem.clone(),
            path: DEFAULT_PATH.to_string(),
            host: Some("localhost".to_string()),
            reload_every: relay_cmd::DEFAULT_RELOAD_EVERY,
            fallback_page: None,
            admission: None,
            audit_file: None,
        },
    )
    .await
    .unwrap();
    let relay_line = relay.connection_info.to_string();
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo_listener.local_addr().unwrap().port();
    tokio::spawn(echo_server(echo_listener));
    std::fs::write(
        steward_home.config_path(),
        format!(
            "relay = \"{relay_line}\"\nproxy = \"direct\"\n[services]\n\"tcp:echo\" = \"127.0.0.1:{echo_port}\"\n"
        ),
    )
    .unwrap();
    let mut steward = start_node(&steward_home, &root.join("steward.sock")).await;

    let make =
        |spec: &CreateSpec| invite::create(&steward_home, spec, &relay_line, unix_now()).unwrap();

    // ---- (1) two devices race for one use --------------------------------------------------
    let one = make(&CreateSpec::default());
    let devices = [device(root, "alpha", real), device(root, "bravo", real)];
    let results = race(&one.token, &devices).await;
    let won: Vec<usize> = (0..2).filter(|i| results[*i].is_ok()).collect();
    assert_eq!(won.len(), 1, "exactly one device wins the use: {results:?}");
    let (winner, loser) = (won[0], 1 - won[0]);
    assert_eq!(
        refusal(&results[loser]),
        Some(ErrorCode::BadInvite),
        "the other finds it used up: {results:?}"
    );
    let (winner_home, winner_name) = devices[winner].clone();
    let loser_home = devices[loser].0.clone();
    let (winner_id, loser_id) = (node_id_of(&winner_home), node_id_of(&loser_home));
    let joined = results[winner].as_ref().unwrap();
    assert_eq!(joined.network_id, network_id);
    assert!(winner_home.roster_only_path(&network_id).is_file());
    assert!(loser_home.roster_only_networks().unwrap().is_empty());
    assert_eq!(
        redeemed(&steward_home, &network_id, &one.invite_id),
        [winner_id]
    );
    assert!(is_member(&steward, &network_id, &winner_id));
    assert!(!is_member(&steward, &network_id, &loser_id));
    let seq_after_one = steward.node.rosters().seq(&network_id).unwrap();
    assert_eq!(joined.roster_seq, seq_after_one);

    // ---- (2) the winner's request with another certificate: bad_tag, nothing spent -----------
    let original = join::prepare(&winner_home, &one.token, Some(&winner_name), unix_now())
        .unwrap()
        .request;
    let (mallory, _) = device(root, "mallory", real);
    let mallory_cert = load_identity(&mallory).unwrap().1;
    let swapped = AdmitRequestBody {
        node_cert: mallory_cert.clone(),
        ..original.clone()
    };
    match ask(&mallory, &relay_line, swapped).await {
        Answer::Refused(code) => assert_eq!(code, ErrorCode::BadTag),
        other => panic!("a swapped certificate must be refused, got {other:?}"),
    }
    assert_eq!(
        redeemed(&steward_home, &network_id, &one.invite_id),
        [winner_id]
    );
    assert_eq!(steward.node.rosters().seq(&network_id), Some(seq_after_one));

    // ---- (3) the exact request again: the Roster again, nothing counted ---------------------
    // (A device the relay's Roster lists is answered by the relay itself; the issuer's own
    // idempotence per NodeId, for a Roster the relay does not hold, is tested at handler level.)
    let seq_before = steward.node.rosters().seq(&network_id).unwrap();
    match ask(&winner_home, &relay_line, original.clone()).await {
        Answer::Admitted(roster) => {
            let body = roster.decode().unwrap();
            assert!(body.members.iter().any(|m| m.node_id == winner_id));
        }
        other => panic!("a repeat of the exact request is answered again, got {other:?}"),
    }
    assert_eq!(
        redeemed(&steward_home, &network_id, &one.invite_id),
        [winner_id]
    );
    assert_eq!(steward.node.rosters().seq(&network_id), Some(seq_before));

    // ---- (4) five devices, three uses (beside a revoked invite, a short one and a half used one,
    // all at once: the issuer batches and the relay's holding figures push some back) -----------
    let three = make(&CreateSpec {
        uses: 3,
        ..CreateSpec::default()
    });
    let five: Vec<(Home, String)> = (0..5)
        .map(|i| device(root, &format!("five{i}"), real))
        .collect();
    let short = make(&CreateSpec {
        life_secs: 3,
        ..CreateSpec::default()
    });
    let late = device(root, "late", real);
    let late_request = join::prepare(&late.0, &short.token, Some("late"), unix_now())
        .unwrap()
        .request;
    let revoked = make(&CreateSpec::default());
    invite::revoke(
        &steward_home,
        None,
        &revoked.invite_id.to_hex()[..8],
        unix_now(),
    )
    .unwrap();
    let echo_device = [device(root, "echo", real)];
    // A swapped certificate on an invite with uses left: refused, nobody admitted, and the race
    // below still finds all three uses (nothing was spent) with mallory outside.
    let honest = join::prepare(&five[0].0, &three.token, Some(&five[0].1), unix_now())
        .unwrap()
        .request;
    let swapped = AdmitRequestBody {
        node_cert: mallory_cert.clone(),
        ..honest
    };
    match ask(&mallory, &relay_line, swapped).await {
        Answer::Refused(code) => assert_eq!(code, ErrorCode::BadTag),
        other => panic!("a swapped certificate must be refused, got {other:?}"),
    }
    assert!(redeemed(&steward_home, &network_id, &three.invite_id).is_empty());
    let (results, revoked_results) = tokio::join!(
        race(&three.token, &five),
        race(&revoked.token, &echo_device),
    );
    let admitted_n = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(admitted_n, 3, "exactly three of five: {results:?}");
    for result in results.iter().filter(|r| r.is_err()) {
        assert_eq!(refusal(result), Some(ErrorCode::BadInvite), "{results:?}");
    }
    let counted: HashSet<NodeId> = redeemed(&steward_home, &network_id, &three.invite_id)
        .into_iter()
        .collect();
    let members: HashSet<NodeId> = five
        .iter()
        .zip(&results)
        .filter(|(_, r)| r.is_ok())
        .map(|((home, _), _)| node_id_of(home))
        .collect();
    assert_eq!(
        counted, members,
        "the book counts exactly the admitted devices"
    );
    for id in &members {
        assert!(is_member(&steward, &network_id, id));
    }
    let five_winner = five
        .iter()
        .zip(&results)
        .find(|(_, r)| r.is_ok())
        .map(|(device, _)| device.clone())
        .unwrap();

    // ---- (5) expired and revoked invites ----------------------------------------------------
    assert_eq!(
        refusal(&revoked_results[0]),
        Some(ErrorCode::BadInvite),
        "a revoked invite: {revoked_results:?}"
    );
    assert!(redeemed(&steward_home, &network_id, &revoked.invite_id).is_empty());
    // The short invite is over by now (the request was made while it was good).
    tokio::time::sleep(Duration::from_secs(
        (short.expires + 1).saturating_sub(unix_now()),
    ))
    .await;
    match ask(&late.0, &relay_line, late_request).await {
        Answer::Refused(code) => assert_eq!(code, ErrorCode::BadInvite, "an expired invite"),
        other => panic!("an expired invite must be refused, got {other:?}"),
    }
    assert!(matches!(
        redeem(&late.0, &short.token, &options("late"), &mut |_| {}).await,
        Err(JoinError::Invalid(_))
    ));
    assert!(redeemed(&steward_home, &network_id, &short.invite_id).is_empty());

    // ---- (6) the issuer node restarted twice: the book is the count -------------------------
    assert!(
        !is_member(&steward, &network_id, &node_id_of(&mallory)),
        "the swapped certificate admitted nobody"
    );
    // Stopped the polite way: a bare drop of the handle leaves the node's relay session running
    // (it would fight its successor for the NodeId).
    assert!(steward.node.close_gracefully(Duration::from_secs(10)).await);
    drop(steward);
    steward = start_node(&steward_home, &root.join("steward2.sock")).await;
    // A device the old process admitted asks again: the Roster again, nothing counted.
    let again = join::prepare(
        &five_winner.0,
        &three.token,
        Some(&five_winner.1),
        unix_now(),
    )
    .unwrap()
    .request;
    assert!(matches!(
        ask(&five_winner.0, &relay_line, again).await,
        Answer::Admitted(_)
    ));
    assert_eq!(
        redeemed(&steward_home, &network_id, &three.invite_id).len(),
        3
    );
    // The used up invite stays used up.
    let results = race(&three.token, &[device(root, "quebec", real)]).await;
    assert_eq!(
        refusal(&results[0]),
        Some(ErrorCode::BadInvite),
        "{results:?}"
    );
    // A half used invite: one use before the next restart, one after.
    let partly = make(&CreateSpec {
        uses: 2,
        ..CreateSpec::default()
    });
    let results = race(&partly.token, &[device(root, "papa", real)]).await;
    assert!(results[0].is_ok(), "{results:?}");
    assert_eq!(
        redeemed(&steward_home, &network_id, &partly.invite_id).len(),
        1
    );
    assert!(steward.node.close_gracefully(Duration::from_secs(10)).await);
    drop(steward);
    steward = start_node(&steward_home, &root.join("steward3.sock")).await;
    assert_eq!(
        redeemed(&steward_home, &network_id, &partly.invite_id).len(),
        1
    );
    let pair = [device(root, "romeo", real), device(root, "sierra", real)];
    let results = race(&partly.token, &pair).await;
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "one use was left after the restart: {results:?}"
    );
    assert_eq!(
        redeemed(&steward_home, &network_id, &partly.invite_id).len(),
        2
    );

    // ---- the winner's node: the Policy by push, then a stream to the steward -------------------
    let winner_node = start_node(&winner_home, &root.join("winner.sock")).await;
    until("the Policy to reach the winner", || {
        winner_node.node.policies().seq(&network_id).is_some()
    })
    .await;
    until("documents.bin to replace roster-only.bin", || {
        winner_home.documents_path(&network_id).is_file()
            && !winner_home.roster_only_path(&network_id).exists()
    })
    .await;

    // Membership carries no grant (a steward admits, granting is the owner's): the owner takes
    // the steward's documents and runs its node; a grant it then makes from the command line is
    // picked up by the node's reload and pushed to the members (no wait for the random delay of
    // a Policy catch-up).
    join_documents(
        &owner_home,
        &token(&steward_home, None).unwrap(),
        unix_now(),
    )
    .unwrap();
    std::fs::write(
        owner_home.config_path(),
        format!("relay = \"{relay_line}\"\nproxy = \"direct\"\n"),
    )
    .unwrap();
    let owner_node = start_node(&owner_home, &root.join("owner.sock")).await;
    let echo_service = ["tcp:echo".parse().unwrap()];
    let granted = grant(
        &owner_home,
        None,
        &winner_name,
        "steward",
        &echo_service,
        None,
        unix_now(),
    )
    .unwrap();
    until("the winner and the steward to adopt the grant", || {
        winner_node.node.policies().seq(&network_id) == Some(granted.seq)
            && steward.node.policies().seq(&network_id) == Some(granted.seq)
    })
    .await;
    let mut stream = tokio::time::timeout(
        Duration::from_secs(20),
        winner_node
            .node
            .open_stream(steward_id, network_id, "tcp:echo".parse().unwrap(), None),
    )
    .await
    .expect("the stream opens within 20 s")
    .expect("the admitted device reaches the steward");
    let data = b"admitted by invite";
    stream.write_all(data).await.unwrap();
    stream.flush().await.unwrap();
    let mut back = vec![0u8; data.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut back))
        .await
        .expect("the echo comes back")
        .unwrap();
    assert_eq!(&back, data);

    drop(stream);
    drop(owner_node);
    drop(winner_node);
    drop(steward);
    relay.stop();
}
