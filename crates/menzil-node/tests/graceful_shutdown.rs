//! A node that stops on purpose (TODO.md L6): `Node::close_gracefully` over a real relay.
//!
//! Before it, a stopping node simply vanished. Its L4 sessions were dropped without a CLOSE and
//! its relay connection without a WebSocket Close, so a peer found out only from the dead peer
//! timeout (about 40 s), and a restarted node was unreachable until the stale session died: the
//! peer's table still held the old session as the one to use, and an OPEN sent over it went to a
//! node that had never heard of it.
//!
//! What this checks, end to end: the carrier's `close` is a WebSocket Close that comes after
//! everything sent before it; a peer's stream ends at once, as a reset, when the node closes; the
//! closing node opens nothing new; and a node that comes back under the same identity is reached
//! by the peer's very next `open_stream`. The seconds in the assertions are far below the 40 s a
//! peer would otherwise take.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{
    PATIENCE, Wire, controlled_proxy, identity, policy, seed_roster, session_config, start_relay,
};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_carrier::{Carrier, ConnectionInfo, DialConfig, ProxyOverride};
use menzil_node::{
    EnsureError, Node, NodeConfig, NodeOpenError, PolicyStore, RefuseAll, RosterStore,
};
use menzil_proto::{
    ErrorCode, Grant, NetworkId, NodeId, NodeOrWildcard, Principal, PrincipalTarget, ServiceId,
};
use menzil_relay::{Listener, RelayError, server_config};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use rustls::pki_types::PrivateKeyDer;
use tokio::time::timeout;

/// How long a peer may take to notice a graceful end. A dead peer takes about 40 s.
const QUICK: Duration = Duration::from_secs(10);

/// Serves `tcp:ssh` by echoing every byte back until the stream ends.
struct Echo;

impl ServiceHandler<Stream> for Echo {
    type Opened = ();
    type Handling = Pin<Box<dyn Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<(), OpenRefusal> {
        if request.service == ssh() {
            Ok(())
        } else {
            Err(OpenRefusal {
                code: ErrorCode::NoGrant,
                msg: "not served".to_string(),
            })
        }
    }

    fn handle(&self, mut stream: Stream, _request: OpenRequest, _opened: ()) -> Self::Handling {
        Box::pin(async move {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
        })
    }
}

fn ssh() -> ServiceId {
    "tcp:ssh".parse().unwrap()
}

fn grant(network_id: NetworkId, from: NodeId, to: NodeId) -> Grant {
    Grant {
        from: Principal {
            network_id,
            target: PrincipalTarget::Node(from),
        },
        to_node: NodeOrWildcard::Node(to),
        services: vec![ssh()],
        expires: None,
    }
}

async fn echo_once(stream: &mut Stream, data: &[u8]) {
    stream.write_all(data).await.unwrap();
    stream.flush().await.unwrap();
    let mut back = vec![0u8; data.len()];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(back, data);
}

#[tokio::test]
async fn a_node_that_closes_gracefully_is_noticed_at_once_and_reached_again_when_back() {
    let trust = common::trust_test_certificate();

    // --- the carrier's close is a WebSocket Close after everything sent ---------------------
    {
        let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
        let tls = server_config(trust.chain.clone(), key).unwrap();
        let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls, "/_menzil/v1")
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = tokio::spawn(async move { listener.accept().await });
        let mut carrier = Carrier::dial(
            &DialConfig {
                connection_info: ConnectionInfo {
                    host: "localhost".to_string(),
                    port,
                    path: "/_menzil/v1".to_string(),
                    relay_node_id: NodeId::from([1; 32]),
                    relay_x25519: None,
                },
                proxy_override: Some(ProxyOverride::Direct),
            },
            &HashMap::new(),
        )
        .await
        .unwrap();
        let mut server = accepted.await.unwrap().unwrap();
        carrier.send(b"last words".to_vec()).await.unwrap();
        // The relay's session loop answers a Close as it reads; here the test reads.
        let (_, seen) = timeout(Duration::from_secs(10), async {
            tokio::join!(carrier.close(), async {
                let first = server.recv().await;
                let second = server.recv().await;
                (first, second)
            })
        })
        .await
        .expect("a polite close ends the exchange");
        let (first, second) = seen;
        assert_eq!(first.unwrap(), b"last words");
        // A Close frame, not a connection that vanished.
        assert!(matches!(second, Err(RelayError::Closed)), "{second:?}");
    }

    // --- two nodes over a real relay ---------------------------------------------------------
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster) = seed_roster(&relay, &[&a, &b]);
    let policy = policy(
        &owner,
        network_id,
        &a,
        &b,
        vec![
            grant(network_id, a.node_id, b.node_id),
            grant(network_id, b.node_id, a.node_id),
        ],
    );
    let stores = || {
        let policies = Arc::new(PolicyStore::new());
        policies.set(&policy).unwrap();
        let rosters = Arc::new(RosterStore::new());
        rosters.set(&roster).unwrap();
        (policies, rosters)
    };
    let start = |who: &common::Identity, serves: bool| {
        let (policies, rosters) = stores();
        let config = NodeConfig {
            session: session_config(&relay, who, network_id),
            env: HashMap::new(),
            policies,
            rosters,
        };
        if serves {
            Node::start(config, Echo).unwrap()
        } else {
            Node::start(config, RefuseAll).unwrap()
        }
    };
    let na = start(&a, false);
    let nb = start(&b, true);
    na.wait_attached(PATIENCE).await.expect("A attaches");
    nb.wait_attached(PATIENCE).await.expect("B attaches");

    // A has a stream to B, with bytes going through.
    let mut stream = timeout(PATIENCE, na.open_stream(b.node_id, network_id, ssh(), None))
        .await
        .expect("the handshake and OPEN finish")
        .expect("and succeed");
    echo_once(&mut stream, b"before").await;

    // --- B closes gracefully: A's stream is reset at once ------------------------------------
    let closed_at = Instant::now();
    assert!(
        nb.close_gracefully(Duration::from_secs(5)).await,
        "everything should finish well inside five seconds"
    );
    let mut byte = [0u8; 1];
    let ended = timeout(QUICK, stream.read(&mut byte))
        .await
        .expect("A's stream must end when B closes, not after the dead peer timeout");
    let error =
        ended.expect_err("a stream cut by the other node's end is reset, not at end of file");
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset, "{error:?}");
    assert!(
        closed_at.elapsed() < QUICK,
        "took {:?}",
        closed_at.elapsed()
    );

    // The closing node opens nothing any more.
    let refused = timeout(QUICK, nb.open_stream(a.node_id, network_id, ssh(), None))
        .await
        .expect("a node that is shutting down answers at once")
        .expect_err("a node that is shutting down opens no stream");
    assert!(
        matches!(refused, NodeOpenError::Session(EnsureError::ShuttingDown)),
        "{refused:?}"
    );

    // --- B comes back under the same identity: A's very next open reaches it ------------------
    nb.shutdown().await;
    let nb = start(&b, true);
    nb.wait_attached(PATIENCE).await.expect("B attaches again");
    let opened_at = Instant::now();
    let mut again = timeout(PATIENCE, na.open_stream(b.node_id, network_id, ssh(), None))
        .await
        .expect("the open must finish")
        .expect("A must reach the node that came back (its stale session was ended by the CLOSE)");
    echo_once(&mut again, b"after the restart").await;
    assert!(
        opened_at.elapsed() < QUICK,
        "reaching the node again took {:?}",
        opened_at.elapsed()
    );

    // --- a link that has stalled does not hold the shutdown up ---------------------------------
    // B goes through a proxy that can be paused, A has a stream to it and is pushing a megabyte
    // through the echo; the wire stalls with B's answers queued behind a blocked write. The polite
    // way out cannot work now, and what it must not do is wait for it: `close_gracefully` returns
    // when its grace is up.
    // (B leaves the polite way, so that A does not keep a session to a node that is gone.)
    assert!(nb.close_gracefully(Duration::from_secs(5)).await);
    nb.shutdown().await;
    let proxy = controlled_proxy(relay.addr).await;
    let mut stalled_config = session_config(&relay, &b, network_id);
    stalled_config.dial.connection_info.port = proxy.port;
    let (policies, rosters) = stores();
    let nb = Node::start(
        NodeConfig {
            session: stalled_config,
            env: HashMap::new(),
            policies,
            rosters,
        },
        Echo,
    )
    .unwrap();
    nb.wait_attached(PATIENCE)
        .await
        .expect("B attaches through the proxy");
    let mut through = timeout(PATIENCE, na.open_stream(b.node_id, network_id, ssh(), None))
        .await
        .expect("the open must finish")
        .expect("and succeed");
    echo_once(&mut through, b"through the proxy").await;
    proxy.wire.send(Wire::Paused).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pushing = tokio::spawn(async move {
        let megabyte = vec![7u8; 1 << 20];
        let _ = through.write_all(&megabyte).await;
        through
    });
    // Let B's echo fill the stalled wire.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let grace = Duration::from_secs(2);
    let started = Instant::now();
    // Whether everything finished in time depends on whether the wire had really stalled by
    // now (it has when the machine is idle, not always when it is not): the bound is what
    // is checked.
    let _finished = timeout(Duration::from_secs(10), nb.close_gracefully(grace))
        .await
        .expect("a stalled link must not hold the shutdown past its grace");
    assert!(
        started.elapsed() < grace + Duration::from_secs(3),
        "took {:?}",
        started.elapsed()
    );
    pushing.abort();

    na.shutdown().await;
    nb.shutdown().await;
}
