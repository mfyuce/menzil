//! The running node (TODO.md L4h7) over a real relay: two
//! [`menzil_node::Node`]s, each a real relay session, router and accept
//! loops, in one process against a real in-process `menzil_relay::Relay`
//! (real TLS, WebSocket and Noise). What it proves that the router's own
//! live test does not: that `Node::open_stream` finds or creates the
//! session and runs the OPEN exchange on it, that the grant check refuses
//! what the Policy does not allow, that the accept loop runs on a session
//! whichever side initiated it, and that a relay reconnect ends the streams
//! and the next `open_stream` starts over.
//!
//! One `#[tokio::test]` for the same reason `live_session.rs` has exactly
//! one: `SSL_CERT_FILE` is process-global (see that file's own doc
//! comment).

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use common::{
    PATIENCE, identity, policy, seed_roster, session_config, start_relay, trust_test_certificate,
};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_node::{
    EnsureError, Node, NodeConfig, NodeOpenError, OpenStreamError, PolicyStore, RefuseAll,
    RosterStore, Session, SessionEvent, StartError,
};
use menzil_proto::{
    ErrorCode, Grant, NetworkId, NodeId, NodeOrWildcard, Principal, PrincipalTarget, ServiceId,
};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use tokio::time::timeout;

/// Serves `tcp:ssh` by echoing every byte back until the stream ends.
struct Echo;

impl ServiceHandler<Stream> for Echo {
    type Handling = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn accepts(&self, request: &OpenRequest) -> Result<(), OpenRefusal> {
        if request.service == ssh() {
            Ok(())
        } else {
            Err(OpenRefusal {
                code: ErrorCode::NoGrant,
                msg: "not served".to_string(),
            })
        }
    }

    fn handle(&self, mut stream: Stream, _request: OpenRequest) -> Self::Handling {
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

/// Writes `data` and reads the same number of bytes back, concurrently, so
/// that neither direction waits on the other's window.
async fn echo_round_trip(stream: &mut Stream, data: &[u8]) {
    let mut back = vec![0u8; data.len()];
    let (mut reader, mut writer) = stream.split();
    let (written, read) = tokio::join!(
        async {
            writer.write_all(data).await.unwrap();
            writer.flush().await.unwrap();
        },
        async { reader.read_exact(&mut back).await.unwrap() },
    );
    let _ = (written, read);
    assert_eq!(back, data);
}

#[tokio::test]
async fn two_nodes_over_a_real_relay() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let (a, b) = (identity(), identity());
    let (owner, network_id, roster) = seed_roster(&relay, &[&a, &b]);
    // Both may use `tcp:ssh` on the other, and nothing else.
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
    let (a_policies, a_rosters) = stores();
    let (b_policies, b_rosters) = stores();
    let a_session_config = session_config(&relay, &a, network_id);

    // A node that does not offer the L4 session protocol would never be sent
    // an `init`, so it is refused at the start.
    let mut without_l4 = session_config(&relay, &a, network_id);
    without_l4.e2e_protos = vec![];
    let refused = Node::start(
        NodeConfig {
            session: without_l4,
            env: HashMap::new(),
            policies: a_policies.clone(),
            rosters: a_rosters.clone(),
        },
        RefuseAll,
    );
    assert!(matches!(refused, Err(StartError::NoL4Protocol)));

    // B serves `tcp:ssh`; A serves nothing.
    let mut nb = Node::start(
        NodeConfig {
            session: session_config(&relay, &b, network_id),
            env: HashMap::new(),
            policies: b_policies,
            rosters: b_rosters,
        },
        Echo,
    )
    .unwrap();
    let na = Node::start(
        NodeConfig {
            session: a_session_config.clone(),
            env: HashMap::new(),
            policies: a_policies,
            rosters: a_rosters.clone(),
        },
        RefuseAll,
    )
    .unwrap();
    assert_eq!(na.local_node_id(), a.node_id);

    // The events channel is handed out once, and carries the attachment.
    let mut b_events = nb.take_events().unwrap();
    assert!(nb.take_events().is_none());
    let epoch_b = nb
        .wait_attached(PATIENCE)
        .await
        .expect("B must attach to the relay");
    let first_event = timeout(PATIENCE, b_events.recv()).await.unwrap().unwrap();
    assert!(
        matches!(first_event, SessionEvent::Attached { epoch, .. } if epoch == epoch_b),
        "{first_event:?}"
    );
    let epoch1 = na
        .wait_attached(PATIENCE)
        .await
        .expect("A must attach to the relay");

    // --- a stream, bytes both ways -------------------------------------
    let mut first = timeout(PATIENCE, na.open_stream(b.node_id, network_id, ssh(), None))
        .await
        .expect("the handshake and OPEN must finish")
        .expect("and succeed");
    echo_round_trip(&mut first, b"ping").await;
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    echo_round_trip(&mut first, &big).await;

    // --- the grant check refuses what the Policy does not allow ---------
    let refused = na
        .open_stream(b.node_id, network_id, "tcp:other".parse().unwrap(), None)
        .await
        .expect_err("an ungranted service must be refused");
    // The grant check's own answer ("no grant"), not Echo's ("not served"),
    // which it would also give: the Policy refused it before the handler
    // was asked.
    match &refused {
        NodeOpenError::Open(OpenStreamError::Refused { code, msg }) => {
            assert_eq!(*code, ErrorCode::NoGrant);
            assert_eq!(msg, "no grant");
        }
        other => panic!("{other:?}"),
    }
    // ...and the session is none the worse for it.
    let mut second = na
        .open_stream(b.node_id, network_id, ssh(), None)
        .await
        .unwrap();
    echo_round_trip(&mut second, b"again").await;

    // --- the accept loop runs on a session this side initiated ----------
    // B opens a stream to A over the session A started. A's Policy grants
    // it, so the refusal is A's handler's (it serves nothing), not the
    // grant check's.
    let refused = nb
        .open_stream(a.node_id, network_id, ssh(), None)
        .await
        .expect_err("A serves nothing");
    match &refused {
        NodeOpenError::Open(OpenStreamError::Refused { code, msg }) => {
            assert_eq!(*code, ErrorCode::NoGrant);
            assert!(msg.contains("serves no services"), "{msg}");
        }
        other => panic!("{other:?}"),
    }

    // --- what cannot be asked for --------------------------------------
    let unknown = na
        .open_stream(identity().node_id, network_id, ssh(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(unknown, NodeOpenError::Session(EnsureError::UnknownPeer)),
        "{unknown:?}"
    );
    let own = na
        .open_stream(a.node_id, network_id, ssh(), None)
        .await
        .unwrap_err();
    assert!(
        matches!(own, NodeOpenError::Session(EnsureError::SelfPeer)),
        "{own:?}"
    );

    // --- a relay reconnect ends the streams; the next open starts over --
    let usurper = Session::connect(&a_session_config, &HashMap::new(), a_rosters.clone())
        .await
        .unwrap();
    drop(usurper);
    let mut buf = [0u8; 16];
    let ended = timeout(PATIENCE, first.read(&mut buf))
        .await
        .expect("a stream must end with its attachment");
    assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");

    let epoch2 = timeout(PATIENCE, async {
        loop {
            match na.wait_attached(Duration::from_millis(200)).await {
                Some(epoch) if epoch > epoch1 => break epoch,
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    })
    .await
    .expect("A must attach again");
    assert!(epoch2 > epoch1);
    let mut third = timeout(PATIENCE, na.open_stream(b.node_id, network_id, ssh(), None))
        .await
        .expect("the second handshake and OPEN must finish")
        .expect("and succeed");
    echo_round_trip(&mut third, b"after the reconnect").await;

    na.shutdown().await;
    nb.shutdown().await;
}
