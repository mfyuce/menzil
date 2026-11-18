//! D1 R3 over a real relay: streams across the replacement of full L4 sessions (protocol.md
//! 5.2, `docs/private/rehandshake-design.md`). Real nodes, a real in-process relay, the real
//! router and actors; only the clock figures are shortened (`Node::start_with_replace`): a
//! session is replaced from 2 s of age and ends at 6 s.
//!
//! 1. A copies a continuous, numbered byte stream through B's `tcp:` echo service for as long
//!    as it takes to see at least three continued replacements at each end: not a byte lost,
//!    repeated or reordered, the one stream throughout, no replacement afresh.
//! 2. A "restarts" (its node is dropped, everything it held is gone) while B still holds the
//!    session: B offers `held`, A's new session cannot continue it, and its first record
//!    replaces the old one as before: the old stream is reset, a new one works.
//! 3. With the continuation off at both ends (an old build's behaviour), every replacement
//!    resets the stream and nothing else breaks: a new stream opens and works, twice.
//! 4. B learns of a revocation of A: the session ends at both ends and the stream is reset.
//!
//! What the router did is read from its own log lines (one per replacement), captured by a
//! global `tracing` subscriber below.
//!
//! One `#[tokio::test]`: `SSL_CERT_FILE` is process-global (see `live_session.rs`).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    PATIENCE, echo_round_trip, echo_server, grant, identity, policy, seed_roster, service,
    session_config, start_relay, trust_test_certificate, unix_now,
};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_e2e::ReplaceDurations;
use menzil_node::{
    LocalServices, LocalTarget, Node, NodeConfig, PolicyStore, RefuseAll, RosterStore,
};
use menzil_proto::{RevokedMember, Roster};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::time::timeout;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// A session is due at 2 s and ends at 6 s; a failed replacement is retried after a second.
fn durations() -> ReplaceDurations {
    ReplaceDurations {
        lifetime: secs(2),
        max_jitter: Duration::ZERO,
        pending_timeout: secs(10),
        retry_delays: vec![secs(1)],
        steady_delay: secs(1),
        hard_cap: secs(6),
    }
}

// ---- the router's log lines ----------------------------------------------------------------

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<String>>>);

struct MessageOf(String);

impl tracing::field::Visit for MessageOf {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

impl tracing::Subscriber for Captured {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target().starts_with("menzil_node") && *metadata.level() <= tracing::Level::INFO
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut message = MessageOf(String::new());
        event.record(&mut message);
        self.0.lock().unwrap().push(message.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

impl Captured {
    fn dump(&self) -> String {
        self.0.lock().unwrap().join("\n")
    }

    fn count(&self, needle: &str) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|line| line.contains(needle))
            .count()
    }
}

const CONTINUED_INITIATOR: &str = "its streams continue (initiator)";
const CONTINUED_RESPONDER: &str = "its streams continue (responder)";
const AFRESH: &str = "replaced an L4 session afresh";

// ---- a numbered stream through the echo service --------------------------------------------

const CHUNK: usize = 1024;

/// What the copier found when it ended.
struct Copied {
    written: u64,
    verified: u64,
    error: Option<String>,
}

/// Writes numbered chunks (`CHUNK` bytes: 128 big endian u64 counters, in order) to `stream`
/// every few milliseconds until `stop`, and verifies the echo byte for byte as it comes back.
/// A reader that finds a byte out of place, a read error or the end of the stream reports it.
fn start_copier(
    stream: menzil_stream::Stream,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<Copied> {
    tokio::spawn(async move {
        let (mut reader, mut writer) = stream.split();
        let written = Arc::new(AtomicU64::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let writing = {
            let (stop, written, done) = (stop.clone(), written.clone(), done.clone());
            tokio::spawn(async move {
                let mut counter = 0u64;
                let mut chunk = vec![0u8; CHUNK];
                while !stop.load(Ordering::Relaxed) {
                    for slot in chunk.as_chunks_mut::<8>().0 {
                        slot.copy_from_slice(&counter.to_be_bytes());
                        counter += 1;
                    }
                    if writer.write_all(&chunk).await.is_err() || writer.flush().await.is_err() {
                        break;
                    }
                    written.fetch_add(CHUNK as u64, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                done.store(true, Ordering::Relaxed);
            })
        };
        let mut verified = 0u64;
        let mut buf = vec![0u8; CHUNK];
        let mut error = None;
        let mut idle = tokio::time::Instant::now();
        loop {
            // Everything written has come back: nothing more to wait for.
            if done.load(Ordering::Relaxed) && verified >= written.load(Ordering::Relaxed) {
                break;
            }
            match timeout(Duration::from_millis(500), reader.read_exact(&mut buf)).await {
                Err(_) => {
                    // Nothing for a moment: look at the end condition again; give up only
                    // after a long silence.
                    if idle.elapsed() > secs(20) {
                        error = Some(format!("no echo for 20 s (verified {verified})"));
                        break;
                    }
                    continue;
                }
                Ok(Err(e)) => {
                    error = Some(format!("read: {e}"));
                    break;
                }
                Ok(Ok(())) => idle = tokio::time::Instant::now(),
            }
            for (i, slot) in buf.as_chunks::<8>().0.iter().enumerate() {
                let expected = verified / 8 + i as u64;
                if *slot != expected.to_be_bytes() {
                    error = Some(format!("byte {} out of place", verified + i as u64 * 8));
                }
            }
            if error.is_some() {
                break;
            }
            verified += CHUNK as u64;
        }
        stop.store(true, Ordering::Relaxed);
        let _ = writing.await;
        Copied {
            written: written.load(Ordering::Relaxed),
            verified,
            error,
        }
    })
}

/// Waits until `counts()` is true or `within` passes.
async fn until(within: Duration, what: &str, mut ready: impl FnMut() -> bool) {
    let end = tokio::time::Instant::now() + within;
    while !ready() {
        assert!(tokio::time::Instant::now() < end, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Opens a stream to `tcp:echo` on `target`, waiting for the answer.
async fn open_echo(
    node: &Node,
    target: menzil_proto::NodeId,
    network: menzil_proto::NetworkId,
) -> Result<menzil_stream::Stream, menzil_node::NodeOpenError> {
    timeout(
        PATIENCE,
        node.open_stream(target, network, service("tcp:echo"), None),
    )
    .await
    .expect("the OPEN must be answered")
}

#[tokio::test]
async fn streams_survive_the_replacement_of_their_session_and_everything_else_ends_cleanly() {
    let logs = Captured::default();
    tracing::subscriber::set_global_default(logs.clone()).unwrap();
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;

    // ---- a network of A and B; B serves a numbered echo ---------------------------------
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster1) = seed_roster(&relay, &[&a, &b]);
    let policy1 = policy(
        &owner,
        network_id,
        &a,
        &b,
        vec![grant(network_id, a.node_id, b.node_id, &["tcp:echo"], None)],
    );
    let stores = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy1).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster1).unwrap();
        (policies, rosters)
    };
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let (ended_tx, mut ended) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(echo, ended_tx));
    let services = LocalServices::new()
        .serve(
            service("tcp:echo"),
            LocalTarget::new("127.0.0.1", echo_port),
        )
        .unwrap();
    let (b_policies, b_rosters) = stores();
    let nb = Node::start_with_replace(
        NodeConfig {
            session: session_config(&relay, &b, network_id),
            env: HashMap::new(),
            policies: b_policies,
            rosters: b_rosters.clone(),
        },
        services,
        durations(),
        true,
    )
    .unwrap();
    let start_a = || {
        let (policies, rosters) = stores();
        Node::start_with_replace(
            NodeConfig {
                session: session_config(&relay, &a, network_id),
                env: HashMap::new(),
                policies,
                rosters,
            },
            RefuseAll,
            durations(),
            true,
        )
        .unwrap()
    };
    let na = start_a();
    nb.wait_attached(PATIENCE).await.expect("B must attach");
    na.wait_attached(PATIENCE).await.expect("A must attach");
    // ---- 1. one stream, at least three continued replacements, not a byte astray ---------
    let stream = open_echo(&na, b.node_id, network_id)
        .await
        .expect("granted");
    let stop = Arc::new(AtomicBool::new(false));
    let copier = start_copier(stream, stop.clone());
    until(secs(60), "three continued replacements at each end", || {
        logs.count(CONTINUED_INITIATOR) >= 3 && logs.count(CONTINUED_RESPONDER) >= 3
    })
    .await;
    assert!(
        !copier.is_finished(),
        "the stream must still be running after the replacements"
    );
    stop.store(true, Ordering::Relaxed);
    let copied = timeout(PATIENCE, copier).await.unwrap().unwrap();
    assert_eq!(
        copied.error,
        None,
        "the stream broke: {:?}\nrouter log:\n{}",
        copied.error,
        logs.dump()
    );
    assert!(
        copied.verified > 0 && copied.verified == copied.written,
        "every byte written came back in order: {} of {}",
        copied.verified,
        copied.written
    );
    assert_eq!(
        logs.count(AFRESH),
        0,
        "no replacement may have started afresh"
    );
    // The service saw that one stream's connection end (the copier dropped it).
    let _first_end = timeout(PATIENCE, ended.recv()).await.unwrap().unwrap();

    // ---- 2. A restarts while B still holds the session ----------------------------------
    let mut old = open_echo(&na, b.node_id, network_id)
        .await
        .expect("granted");
    echo_round_trip(&mut old, b"before the restart").await;
    let afresh_before = logs.count(AFRESH);
    drop(na); // aborts its tasks: everything A held is gone
    let na = start_a();
    na.wait_attached(PATIENCE).await.expect("A must re-attach");
    let mut renewed = open_echo(&na, b.node_id, network_id)
        .await
        .expect("granted");
    echo_round_trip(&mut renewed, b"after the restart").await;
    // B ended the connection of the old stream: its session was replaced, not continued.
    let reset = timeout(PATIENCE, ended.recv()).await.unwrap().unwrap();
    let _ = reset;
    until(secs(10), "B replaced the session afresh", || {
        logs.count(AFRESH) > afresh_before
    })
    .await;

    // ---- 4. a revocation reaches B: both ends end ---------------------------------------
    let mut roster2 = roster1.decode().unwrap();
    roster2.seq = 2;
    roster2.issued = unix_now() - 100;
    roster2.expires = unix_now() + 10 * 86_400;
    roster2.members.retain(|member| member.node_id != a.node_id);
    roster2.revoked.push(RevokedMember {
        node_id: a.node_id,
        since: unix_now(),
    });
    let mut byte = [0u8; 1];
    b_rosters
        .set(&Roster::sign(&owner, &roster2).unwrap())
        .unwrap();
    let error = timeout(secs(10), renewed.read(&mut byte))
        .await
        .expect("the stream must end when B ends the session")
        .map_or_else(
            |e| Some(e.kind()),
            |n| (n == 0).then_some(io::ErrorKind::UnexpectedEof),
        );
    assert!(error.is_some(), "the stream of a revoked peer must end");
    let again = timeout(secs(8), open_echo(&na, b.node_id, network_id)).await;
    assert!(
        !matches!(again, Ok(Ok(_))),
        "a revoked node must not get a stream"
    );
    drop(old);
    na.shutdown().await;
    nb.shutdown().await;

    // ---- 3. the continuation off at both ends: an old build's daily reset ----------------
    let (c, d) = (identity(), identity());
    let (owner2, network2, roster_cd) = seed_roster(&relay, &[&c, &d]);
    let policy_cd = policy(
        &owner2,
        network2,
        &c,
        &d,
        vec![grant(network2, c.node_id, d.node_id, &["tcp:echo"], None)],
    );
    let stores_cd = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy_cd).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster_cd).unwrap();
        (policies, rosters)
    };
    let echo2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo2_port = echo2.local_addr().unwrap().port();
    let (ended2_tx, mut ended2) = mpsc::unbounded_channel();
    tokio::spawn(echo_server(echo2, ended2_tx));
    let (d_policies, d_rosters) = stores_cd();
    let nd = Node::start_with_replace(
        NodeConfig {
            session: session_config(&relay, &d, network2),
            env: HashMap::new(),
            policies: d_policies,
            rosters: d_rosters,
        },
        LocalServices::new()
            .serve(
                service("tcp:echo"),
                LocalTarget::new("127.0.0.1", echo2_port),
            )
            .unwrap(),
        durations(),
        false,
    )
    .unwrap();
    let (c_policies, c_rosters) = stores_cd();
    let nc = Node::start_with_replace(
        NodeConfig {
            session: session_config(&relay, &c, network2),
            env: HashMap::new(),
            policies: c_policies,
            rosters: c_rosters,
        },
        RefuseAll,
        durations(),
        false,
    )
    .unwrap();
    nd.wait_attached(PATIENCE).await.expect("D must attach");
    nc.wait_attached(PATIENCE).await.expect("C must attach");
    let continued_before = logs.count(CONTINUED_INITIATOR) + logs.count(CONTINUED_RESPONDER);
    let afresh_before = logs.count(AFRESH);
    for round in 0..2 {
        let mut stream = timeout(
            PATIENCE,
            nc.open_stream(d.node_id, network2, service("tcp:echo"), None),
        )
        .await
        .expect("the OPEN must be answered")
        .unwrap_or_else(|e| panic!("round {round}: a new stream must open: {e}"));
        echo_round_trip(&mut stream, b"hello").await;
        // The replacement (afresh) ends the stream within a few seconds.
        let outcome = timeout(secs(20), stream.read(&mut byte))
            .await
            .unwrap_or_else(|_| {
                panic!("round {round}: the stream must be reset by the replacement")
            });
        assert!(
            !matches!(outcome, Ok(n) if n > 0),
            "round {round}: nothing more is echoed on a reset stream"
        );
        let _ = timeout(PATIENCE, ended2.recv()).await;
    }
    assert_eq!(
        logs.count(CONTINUED_INITIATOR) + logs.count(CONTINUED_RESPONDER),
        continued_before,
        "with the continuation off nothing may be continued"
    );
    assert!(
        logs.count(AFRESH) >= afresh_before + 2,
        "each replacement started afresh"
    );
    nc.shutdown().await;
    nd.shutdown().await;
}
