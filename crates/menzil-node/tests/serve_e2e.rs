//! L4i over a real relay: a node serving local TCP services to another node
//! (TODO.md L4i). Two [`menzil_node::Node`]s against a real in-process
//! `menzil_relay::Relay`; B is started with [`LocalServices`] pointing at
//! sockets this test listens on, A opens streams to it.
//!
//! What it proves that `serve.rs`'s own tests (in-memory yamux pairs) do not:
//! that the whole stack, grant check included, ends in the right
//! place. Bytes flow both ways through a real session; a dead target is a
//! refusal in the OPEN_ACK, not an accepted stream that ends; a granted but
//! unconfigured service is `unknown_service` while an ungranted one is still
//! refused by the grant check first; the abnormal ends are visible at
//! the far end as resets, not as clean ends of file, in both directions;
//! and a node going down resets the local target of a stream the client had
//! half-closed, even when that target is silent.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly
//! one: `SSL_CERT_FILE` is process-global (see that file's own doc
//! comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use common::{
    PATIENCE, identity, policy, seed_roster, session_config, start_relay, trust_test_certificate,
};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_node::{
    LocalServices, LocalTarget, Node, NodeConfig, NodeOpenError, OpenStreamError, PolicyStore,
    RefuseAll, RosterStore,
};
use menzil_proto::{
    ErrorCode, Grant, NetworkId, NodeId, NodeOrWildcard, Principal, PrincipalTarget, ServiceId,
};
use menzil_stream::Stream;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

fn service(s: &str) -> ServiceId {
    s.parse().unwrap()
}

fn grant(network_id: NetworkId, from: NodeId, to: NodeId, services: &[&str]) -> Grant {
    Grant {
        from: Principal {
            network_id,
            target: PrincipalTarget::Node(from),
        },
        to_node: NodeOrWildcard::Node(to),
        services: services.iter().map(|s| service(s)).collect(),
        expires: None,
    }
}

/// How a connection to the echo server ended, as the server saw it.
type Ended = Result<(), io::ErrorKind>;

/// Echoes every byte until the peer's end of file, then closes. Each
/// connection reports how it ended on `ended`.
async fn echo_server(listener: TcpListener, ended: mpsc::UnboundedSender<Ended>) {
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let ended = ended.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let outcome = loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break Ok(()),
                    Ok(n) => {
                        if let Err(e) = socket.write_all(&buf[..n]).await {
                            break Err(e.kind());
                        }
                    }
                    Err(e) => break Err(e.kind()),
                }
            };
            let _ = socket.shutdown().await;
            let _ = ended.send(outcome);
        });
    }
}

/// Reads one byte, then fails the connection with an RST.
async fn resetting_server(listener: TcpListener) {
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut one = [0u8; 1];
            let _ = socket.read_exact(&mut one).await;
            socket2::SockRef::from(&socket)
                .set_linger(Some(Duration::ZERO))
                .unwrap();
            drop(socket);
        });
    }
}

/// Reads the request to its end of file and then stays silent, watching only its own
/// socket's error (an RST sets it; a read would see a clean end of file whatever follows).
/// Reports `()` on `request_ended` when it saw the end of file, and the error it found on
/// `outcome`.
async fn silent_server(
    listener: TcpListener,
    request_ended: mpsc::UnboundedSender<()>,
    outcome: mpsc::UnboundedSender<Option<io::ErrorKind>>,
) {
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut request = Vec::new();
    socket.read_to_end(&mut request).await.unwrap();
    let _ = request_ended.send(());
    let started = std::time::Instant::now();
    let error = loop {
        if let Some(error) = socket.take_error().unwrap() {
            break Some(error.kind());
        }
        if started.elapsed() > PATIENCE {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let _ = outcome.send(error);
}

async fn echo_round_trip(stream: &mut Stream, data: &[u8]) {
    let mut back = vec![0u8; data.len()];
    let (mut reader, mut writer) = stream.split();
    let (_, read) = tokio::join!(
        async {
            writer.write_all(data).await.unwrap();
            writer.flush().await.unwrap();
        },
        async { reader.read_exact(&mut back).await },
    );
    read.unwrap();
    assert_eq!(back, data);
}

fn refused_with(error: &NodeOpenError) -> (ErrorCode, &str) {
    match error {
        NodeOpenError::Open(OpenStreamError::Refused { code, msg }) => (*code, msg),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_node_serves_local_targets_to_a_granted_peer() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster) = seed_roster(&relay, &[&a, &b]);
    // A may use four of B's services; `tcp:other` is not among them.
    let policy = policy(
        &owner,
        network_id,
        &a,
        &b,
        vec![grant(
            network_id,
            a.node_id,
            b.node_id,
            &[
                "tcp:app",
                "tcp:resetter",
                "tcp:dead",
                "tcp:ghost",
                "tcp:silent",
            ],
        )],
    );
    let stores = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster).unwrap();
        (policies, rosters)
    };
    let (a_policies, a_rosters) = stores();
    let (b_policies, b_rosters) = stores();

    // The targets B serves from.
    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app_port = app.local_addr().unwrap().port();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(app, ended_tx));
    let resetter = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let resetter_port = resetter.local_addr().unwrap().port();
    tokio::spawn(resetting_server(resetter));
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = dead.local_addr().unwrap().port();
    drop(dead); // nothing listens there
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let silent_port = silent.local_addr().unwrap().port();
    let (request_ended_tx, mut request_ended_rx) = mpsc::unbounded_channel();
    let (silent_outcome_tx, mut silent_outcome_rx) = mpsc::unbounded_channel();
    tokio::spawn(silent_server(silent, request_ended_tx, silent_outcome_tx));

    let services = LocalServices::new()
        .serve(service("tcp:app"), LocalTarget::new("127.0.0.1", app_port))
        .unwrap()
        .serve(
            service("tcp:resetter"),
            LocalTarget::new("127.0.0.1", resetter_port),
        )
        .unwrap()
        .serve(
            service("tcp:dead"),
            LocalTarget::new("127.0.0.1", dead_port),
        )
        .unwrap()
        .serve(
            service("tcp:silent"),
            LocalTarget::new("127.0.0.1", silent_port),
        )
        .unwrap();
    let nb = Node::start(
        NodeConfig {
            session: session_config(&relay, &b, network_id),
            env: HashMap::new(),
            policies: b_policies,
            rosters: b_rosters,
        },
        services,
    )
    .unwrap();
    let na = Node::start(
        NodeConfig {
            session: session_config(&relay, &a, network_id),
            env: HashMap::new(),
            policies: a_policies,
            rosters: a_rosters,
        },
        RefuseAll,
    )
    .unwrap();
    nb.wait_attached(PATIENCE).await.expect("B must attach");
    na.wait_attached(PATIENCE).await.expect("A must attach");
    let open = |name: &'static str| {
        let na = &na;
        async move {
            timeout(
                PATIENCE,
                na.open_stream(b.node_id, network_id, service(name), None),
            )
            .await
            .expect("the OPEN must be answered")
        }
    };

    // --- bytes both ways through a real session and a real local socket ----
    let mut stream = open("tcp:app").await.expect("a served service opens");
    echo_round_trip(&mut stream, b"ping").await;
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    echo_round_trip(&mut stream, &big).await;
    // A clean close from this side ends the target's connection cleanly.
    stream.close().await.unwrap();
    let mut rest = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut rest))
        .await
        .unwrap()
        .expect("the echo server closed cleanly");
    assert!(rest.is_empty());
    assert_eq!(
        timeout(PATIENCE, ended_rx.recv()).await.unwrap(),
        Some(Ok(())),
        "a clean close must reach the target as a clean end of file"
    );

    // --- a target that fails is a reset at this end, not an end of file ----
    let mut stream = open("tcp:resetter").await.expect("the resetter accepts");
    stream.write_all(b"x").await.unwrap();
    let mut got = Vec::new();
    let error = timeout(PATIENCE, stream.read_to_end(&mut got))
        .await
        .unwrap()
        .expect_err("a target that reset must not look like a clean end");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);

    // --- aborting a stream here resets the target's connection ------------
    let mut stream = open("tcp:app").await.expect("a served service opens");
    echo_round_trip(&mut stream, b"hello").await;
    stream.reset();
    let outcome = timeout(PATIENCE, ended_rx.recv()).await.unwrap().unwrap();
    assert!(
        matches!(
            outcome,
            Err(io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted)
        ),
        "an aborted stream must reach the target as a reset, got {outcome:?}"
    );

    // --- what is refused, and by whom ---------------------------------------
    // Configured, granted, but nothing listens: refused in the OPEN_ACK.
    let error = open("tcp:dead")
        .await
        .expect_err("a dead target is a refusal");
    let (code, msg) = refused_with(&error);
    assert_eq!(code, ErrorCode::TargetUnreachable);
    assert!(!msg.contains("127.0.0.1"), "{msg}");
    // Granted but not configured on B.
    let error = open("tcp:ghost")
        .await
        .expect_err("an unconfigured service");
    assert_eq!(refused_with(&error).0, ErrorCode::UnknownService);
    // Not granted: the grant check answers before the handler is asked.
    let error = open("tcp:other").await.expect_err("an ungranted service");
    let (code, msg) = refused_with(&error);
    assert_eq!(code, ErrorCode::NoGrant);
    assert_eq!(msg, "no grant");

    // --- and all of that left the session healthy ---------------------------
    let mut stream = open("tcp:app").await.expect("still serving");
    echo_round_trip(&mut stream, b"still here").await;

    // --- the serving node going down resets a target that is silent ---------
    // The client half-closes, so the pipe has nothing left to read from the stream and waits
    // on the silent target; only the end of the session can tell it anything (the second
    // L4i review, M1: it did not, and the target's connection stayed open).
    let mut silent_stream = open("tcp:silent").await.expect("the silent target accepts");
    silent_stream.write_all(b"request").await.unwrap();
    silent_stream.close().await.unwrap();
    timeout(PATIENCE, request_ended_rx.recv())
        .await
        .expect("the target must see the request end")
        .unwrap();
    nb.shutdown().await;
    let outcome = timeout(PATIENCE * 2, silent_outcome_rx.recv())
        .await
        .expect("the silent target must report")
        .unwrap();
    assert!(
        matches!(
            outcome,
            Some(io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe)
        ),
        "a node going down must reset the target of a half-closed stream, got {outcome:?}"
    );

    na.shutdown().await;
}
