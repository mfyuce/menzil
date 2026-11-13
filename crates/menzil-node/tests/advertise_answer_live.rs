//! What a node does when the relay does not answer its ADVERTISE the way it should (expose round 1,
//! M1): an ACK that never comes ends the attachment, and the node states its shares again on a
//! fresh one; an ERROR (`rate_limited`) is a failed advertise that is tried again, an empty set
//! included, so a withdrawn share does not stay claimed at the relay.
//!
//! Real relays, real sessions, short figures through [`ShareBook::set_advertise_timing`]. One
//! `#[tokio::test]` for the same reason `live_session.rs` has exactly one: `SSL_CERT_FILE` is
//! process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{
    Identity, PATIENCE, TestRelay, TestTrust, identity, node_cert, session_config, start_relay,
    trust_test_certificate, unix_now,
};
use ed25519_dalek::SigningKey;
use menzil_node::{RosterStore, SessionConfig, SessionEvent, ShareBook, run_session_observed};
use menzil_proto::{
    Label, Limits, NetworkId, NodeId, PROTOCOL_VERSION, Roster, RosterBody, RosterMember, Share,
    ShareMode,
};
use menzil_relay::{Listener, Relay, RelayIdentity, SessionRates, server_config};
use rustls::pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

fn roster(owner: &SigningKey, node: NodeId, labels: &[&str]) -> (NetworkId, Roster) {
    let network_id = NetworkId::from(owner.verifying_key().to_bytes());
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id,
        seq: 1,
        issued: unix_now() - 60,
        expires: unix_now() + 7 * 86_400,
        members: vec![RosterMember {
            node_id: node,
            min_serial: 1,
        }],
        revoked: vec![],
        stewards: vec![],
        labels: labels
            .iter()
            .map(|name| Label {
                name: name.to_string(),
                node_id: node,
            })
            .collect(),
    };
    (network_id, Roster::sign(owner, &body).unwrap())
}

fn blind(name: &str) -> Share {
    Share {
        name: name.to_string(),
        mode: ShareMode::Blind,
        service: format!("tls:{name}").parse().unwrap(),
        alpn: vec![],
    }
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    timeout(PATIENCE, async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("gave up waiting for {what}"));
}

/// A relay like `common::start_relay`, with the given per session rates.
async fn start_relay_with(trust: &TestTrust, rates: SessionRates) -> TestRelay {
    let key = PrivateKeyDer::Pkcs8(trust.key_der.clone().into());
    let tls = server_config(trust.chain.clone(), key).unwrap();
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), tls, "/_menzil/v1")
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let id: Identity = identity();
    let relay = Relay::new(
        RelayIdentity {
            node_cert: node_cert(&id),
            x25519_private: id.x25519_private,
        },
        Limits {
            max_record: 65_535,
            max_peers: 10,
            credit: 1 << 20,
        },
    )
    .with_session_rates(rates);
    let serving = relay.clone();
    tokio::spawn(async move { serving.serve(&listener).await });
    TestRelay { addr, id, relay }
}

/// A TCP proxy between a node and a relay that can go silent toward the node for the connections
/// that exist at that moment (their relay-to-node bytes are held back, the other direction is
/// untouched): the relay answers, the node never hears it. Connections made afterwards flow.
struct SilencingProxy {
    port: u16,
    /// Connections with an index below this one are silent.
    silent_below: watch::Sender<usize>,
    accepted: Arc<AtomicUsize>,
}

impl SilencingProxy {
    async fn start(relay: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (silent_below, silent_rx) = watch::channel(0usize);
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            while let Ok((down, _)) = listener.accept().await {
                let index = count.fetch_add(1, Ordering::SeqCst);
                let up = TcpStream::connect(relay).await.unwrap();
                let (mut down_read, mut down_write) = down.into_split();
                let (mut up_read, mut up_write) = up.into_split();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    while let Ok(n) = down_read.read(&mut buf).await {
                        if n == 0 || up_write.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
                let mut silent_rx = silent_rx.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    loop {
                        while index < *silent_rx.borrow() {
                            if silent_rx.changed().await.is_err() {
                                return;
                            }
                        }
                        let n = match up_read.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        // Read while flowing; if it went silent meanwhile, these bytes are
                        // held back with the rest: the proxy simply stops forwarding.
                        while index < *silent_rx.borrow() {
                            if silent_rx.changed().await.is_err() {
                                return;
                            }
                        }
                        if down_write.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            port,
            silent_below,
            accepted,
        }
    }

    /// Silences every connection made so far.
    fn silence_existing(&self) {
        self.silent_below
            .send_replace(self.accepted.load(Ordering::SeqCst));
    }
}

struct Running {
    book: ShareBook,
    attachments: Arc<AtomicUsize>,
    stop: watch::Sender<bool>,
}

fn run_node(config: SessionConfig, own: Arc<RosterStore>) -> Running {
    let book = ShareBook::new();
    // Short figures: the real ones are 30 s and 10 s.
    book.set_advertise_timing(Duration::from_secs(2), Duration::from_secs(2));
    let (events_tx, mut events_rx) = mpsc::channel::<SessionEvent>(64);
    let (_outbound_tx, outbound_rx) = mpsc::channel(16);
    let (stop, stop_rx) = watch::channel(false);
    let attachments = Arc::new(AtomicUsize::new(0));
    let seen = attachments.clone();
    tokio::spawn(async move {
        while let Some(event) = events_rx.recv().await {
            if matches!(event, SessionEvent::Attached { .. }) {
                seen.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    let observers = menzil_node::Observers {
        notes: menzil_node::RelayNotes::new(),
        shares: book.clone(),
    };
    tokio::spawn(run_session_observed(
        config,
        HashMap::new(),
        events_tx,
        outbound_rx,
        own,
        stop_rx,
        observers,
    ));
    // Keep the sender alive for the test's life.
    Running {
        book,
        attachments,
        stop,
    }
}

#[tokio::test]
async fn a_relay_that_does_not_answer_or_refuses_an_advertise_does_not_keep_a_node_in_the_dark() {
    let trust = trust_test_certificate();

    // 1. The relay answers, the node does not hear it: the attachment ends and the next one
    // states the shares again.
    {
        let relay = start_relay(&trust, 1 << 20).await;
        let node = identity();
        let owner = SigningKey::generate(&mut rand::rng());
        let (network_id, roster1) = roster(&owner, node.node_id, &["myapp"]);
        relay.relay.rosters().set(&roster1).unwrap();
        let own = Arc::new(RosterStore::new());
        own.set(&roster1).unwrap();
        let proxy = SilencingProxy::start(relay.addr).await;
        let mut config = session_config(&relay, &node, network_id);
        config.dial.connection_info.port = proxy.port;
        let running = run_node(config, own);

        until("the first attachment", || {
            running.attachments.load(Ordering::SeqCst) == 1
        })
        .await;
        proxy.silence_existing();
        running.book.set_shares(vec![blind("myapp")]).unwrap();
        // The relay holds the claim (it received the ADVERTISE), the node never saw the ACK.
        until("the relay to hold myapp", || {
            !relay.relay.labels().shares_for(&node.node_id).is_empty()
        })
        .await;
        assert!(!running.book.snapshot().acked, "the node heard nothing");
        // After the deadline the node ends that attachment and attaches again; the new one
        // advertises and its ACK arrives.
        // Within a few times the 2 s deadline: the session's own keepalive would take far longer.
        timeout(Duration::from_secs(15), async {
            while running.attachments.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the node must end the attachment whose ADVERTISE got no answer");
        until("the ACK of the new attachment", || {
            running.book.accepted_service(&blind("myapp").service)
        })
        .await;
        let _ = running.stop.send(true);
    }

    // 2. The relay refuses the second ADVERTISE as over its rate: the node tries again, and the
    // empty set that drops the claim gets through.
    {
        let relay = start_relay_with(
            &trust,
            SessionRates {
                advertise_burst: 1,
                advertise_per_minute: 60,
                ..SessionRates::default()
            },
        )
        .await;
        let node = identity();
        let owner = SigningKey::generate(&mut rand::rng());
        let (network_id, roster1) = roster(&owner, node.node_id, &["myapp"]);
        relay.relay.rosters().set(&roster1).unwrap();
        let own = Arc::new(RosterStore::new());
        own.set(&roster1).unwrap();
        let running = run_node(session_config(&relay, &node, network_id), own);

        running.book.set_shares(vec![blind("myapp")]).unwrap();
        until("myapp to be accepted", || {
            running.book.accepted_service(&blind("myapp").service)
        })
        .await;
        assert_eq!(relay.relay.labels().shares_for(&node.node_id).len(), 1);
        // Withdrawn at once: the burst is spent, so the relay answers ERROR rate_limited.
        running.book.set_shares(vec![]).unwrap();
        until("the relay to hold nothing", || {
            relay.relay.labels().shares_for(&node.node_id).is_empty()
        })
        .await;
        assert!(running.book.accepted().is_empty());
        assert_eq!(
            running.attachments.load(Ordering::SeqCst),
            1,
            "a refusal is retried on the same attachment"
        );
        let _ = running.stop.send(true);
    }
}
