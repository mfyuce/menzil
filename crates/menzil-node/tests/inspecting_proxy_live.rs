//! Threat model test 12 (docs/spec/threat-model.md section 5): a TLS inspecting HTTP proxy
//! between a node and the relay, the way a company gateway sits on port 443.
//!
//! The proxy answers `CONNECT localhost:<relay port>`, then terminates the node's TLS with a
//! certificate of its own that a company CA signed (the node trusts that CA, as a managed
//! machine does) and opens a second TLS connection to the real relay. It reads every byte in
//! the clear on both sides: the HTTP upgrade head and the WebSocket frames, unmasked. The test
//! checks, with a real relay and real nodes:
//!
//! 1. The node connects and works through it: a record sent to a peer arrives intact.
//! 2. What the proxy sees after the upgrade is only ciphertext: the request head is readable
//!    (the point of an inspecting proxy), but no marker payload and no NodeId appears in any
//!    WebSocket payload, in either direction.
//! 3. A record the proxy injects towards the relay (one flipped bit in a binary frame) is
//!    rejected: the relay ends the node's session, and nothing sent after it reaches the peer.
//! 4. A record the proxy injects towards the node is rejected the same way: the node's session
//!    ends and it never delivers what the proxy altered.
//! 5. With the proxy honest again the node reattaches and a record arrives.
//!
//! One `#[tokio::test]` because `SSL_CERT_FILE` is process-global (see `live_session.rs`).
//! Every wait is bounded.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{PATIENCE, TestTrust, identity, seed_roster, session_config, start_relay};
use menzil_carrier::ProxyOverride;
use menzil_node::{Epoch, OutboundSend, RosterStore, SessionEvent, run_session, run_session_until};
use menzil_proto::{NodeId, Record};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Which direction the proxy tampers with next (0 none, 1 towards the relay, 2 towards the node).
const TAMPER_NONE: u8 = 0;
const TAMPER_UP: u8 = 1;
const TAMPER_DOWN: u8 = 2;

/// What the proxy saw, in the clear.
#[derive(Default)]
struct Seen {
    /// The `CONNECT` request lines.
    connects: Vec<String>,
    /// The HTTP heads, per direction (0 node to relay, 1 relay to node).
    heads: [Vec<u8>; 2],
    /// The unmasked WebSocket payloads after the upgrade, per direction.
    payloads: [Vec<u8>; 2],
}

struct Inspector {
    port: u16,
    seen: Arc<Mutex<Seen>>,
    tamper: Arc<AtomicU8>,
    tampered: [Arc<AtomicUsize>; 2],
}

/// Walks WebSocket frames in `buf`: returns the complete frames, each with its header length,
/// payload length and whether it is masked, and keeps the rest.
fn take_frames(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    loop {
        if buf.len() < 2 {
            break;
        }
        let masked = buf[1] & 0x80 != 0;
        let (ext, len) = match buf[1] & 0x7f {
            126 if buf.len() >= 4 => (2, usize::from(u16::from_be_bytes([buf[2], buf[3]]))),
            126 => break,
            127 if buf.len() >= 10 => {
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[2..10]);
                (8, usize::try_from(u64::from_be_bytes(b)).unwrap())
            }
            127 => break,
            n => (0, usize::from(n)),
        };
        let header = 2 + ext + if masked { 4 } else { 0 };
        if buf.len() < header + len {
            break;
        }
        frames.push(buf.drain(..header + len).collect());
    }
    frames
}

/// The payload of a whole `frame`, unmasked, and the offset where it starts.
fn payload_of(frame: &[u8]) -> (Vec<u8>, usize) {
    let masked = frame[1] & 0x80 != 0;
    let ext = match frame[1] & 0x7f {
        126 => 2,
        127 => 8,
        _ => 0,
    };
    let start = 2 + ext + if masked { 4 } else { 0 };
    let mut payload = frame[start..].to_vec();
    if masked {
        let key = &frame[start - 4..start];
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }
    (payload, start)
}

#[allow(clippy::too_many_arguments)]
async fn pump(
    mut from: impl AsyncReadExt + Unpin,
    mut to: impl AsyncWrite + Unpin,
    dir: usize,
    seen: Arc<Mutex<Seen>>,
    tamper: Arc<AtomicU8>,
    tampered: Arc<AtomicUsize>,
) {
    let wanted = if dir == 0 { TAMPER_UP } else { TAMPER_DOWN };
    let mut head: Vec<u8> = Vec::new();
    let mut head_done = false;
    let mut frames: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if !head_done {
            head.extend_from_slice(&chunk[..n]);
            let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let rest = head.split_off(end + 4);
            seen.lock().unwrap().heads[dir] = head.clone();
            if to.write_all(&head).await.is_err() {
                return;
            }
            head_done = true;
            frames.extend_from_slice(&rest);
        } else {
            frames.extend_from_slice(&chunk[..n]);
        }
        for mut frame in take_frames(&mut frames) {
            let (payload, start) = payload_of(&frame);
            let opcode = frame[0] & 0x0f;
            seen.lock().unwrap().payloads[dir].extend_from_slice(&payload);
            if opcode == 2
                && payload.len() >= 16
                && tamper
                    .compare_exchange(wanted, TAMPER_NONE, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                // One flipped bit in the last payload byte (the AEAD tag).
                let last = frame.len() - 1;
                debug_assert!(last >= start);
                frame[last] ^= 0x01;
                tampered.fetch_add(1, Ordering::SeqCst);
            }
            if to.write_all(&frame).await.is_err() {
                return;
            }
        }
    }
    let _ = to.shutdown().await;
}

async fn inspecting_proxy(
    relay: std::net::SocketAddr,
    leaf_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    leaf_key: Vec<u8>,
) -> Inspector {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let tamper = Arc::new(AtomicU8::new(TAMPER_NONE));
    let tampered = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
    let acceptor = TlsAcceptor::from(
        menzil_relay::server_config(leaf_chain, PrivateKeyDer::Pkcs8(leaf_key.into())).unwrap(),
    );
    let connector = TlsConnector::from(menzil_carrier::client_config().unwrap());
    let (s, t, c) = (seen.clone(), tamper.clone(), tampered.clone());
    tokio::spawn(async move {
        while let Ok((mut node_side, _)) = listener.accept().await {
            let (acceptor, connector) = (acceptor.clone(), connector.clone());
            let (s, t, c) = (s.clone(), t.clone(), c.clone());
            tokio::spawn(async move {
                // The CONNECT request.
                let mut request = Vec::new();
                let mut byte = [0u8; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    if node_side.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                s.lock().unwrap().connects.push(line);
                if node_side
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                // Inspect: our own certificate towards the node, the real one towards the relay.
                let Ok(node_tls) = acceptor.accept(node_side).await else {
                    return;
                };
                let Ok(tcp) = TcpStream::connect(relay).await else {
                    return;
                };
                let Ok(relay_tls) = connector
                    .connect(ServerName::try_from("localhost").unwrap(), tcp)
                    .await
                else {
                    return;
                };
                let (node_read, node_write) = tokio::io::split(node_tls);
                let (relay_read, relay_write) = tokio::io::split(relay_tls);
                tokio::spawn(pump(
                    node_read,
                    relay_write,
                    0,
                    s.clone(),
                    t.clone(),
                    c[0].clone(),
                ));
                tokio::spawn(pump(relay_read, node_write, 1, s, t, c[1].clone()));
            });
        }
    });
    Inspector {
        port,
        seen,
        tamper,
        tampered,
    }
}

fn send(dst: NodeId, epoch: Epoch, payload: &[u8]) -> OutboundSend {
    let (outcome, _rx) = oneshot::channel();
    OutboundSend {
        dst,
        e2e_proto: 0x01,
        flags: 0x00,
        payload: payload.to_vec(),
        epoch,
        outcome,
        permit: None,
    }
}

/// The epoch of the next `Attached` on `events`, within [`PATIENCE`].
async fn next_attached(events: &mut mpsc::Receiver<SessionEvent>) -> Epoch {
    timeout(PATIENCE, async {
        loop {
            if let Some(SessionEvent::Attached { epoch, .. }) = events.recv().await {
                return epoch;
            }
        }
    })
    .await
    .expect("the node never attached")
}

/// How long a session may take to end after the proxy injected a record. The record fails
/// authentication, so the end is immediate; the liveness timeout (about a minute) ends a
/// session whose later records merely fail, and must not pass for the answer.
const REJECTED_WITHIN: Duration = Duration::from_secs(10);

/// Waits for the next `Detached` on `events`: the session ended.
async fn next_detached(events: &mut mpsc::Receiver<SessionEvent>) {
    timeout(REJECTED_WITHIN, async {
        loop {
            match events.recv().await {
                Some(SessionEvent::Detached { .. }) => return,
                Some(_) => {}
                None => panic!("the events channel closed"),
            }
        }
    })
    .await
    .expect("the injected record did not end the session at once");
}

/// Everything `Recv`ed on `events` from `src` for `window`.
async fn payloads_for(
    events: &mut mpsc::Receiver<SessionEvent>,
    src: NodeId,
    window: Duration,
) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    let _ = timeout(window, async {
        while let Some(event) = events.recv().await {
            if let SessionEvent::Record { record, .. } = event
                && let Record::Recv {
                    src: from, payload, ..
                } = *record
                && from == src
            {
                got.push(payload);
            }
        }
    })
    .await;
    got
}

/// Sends `probe` records from `outbound` to `to` until one arrives on `to_events`.
async fn until_routable(
    outbound: &mpsc::Sender<OutboundSend>,
    epoch: Epoch,
    from: NodeId,
    to: NodeId,
    to_events: &mut mpsc::Receiver<SessionEvent>,
) {
    timeout(PATIENCE, async {
        loop {
            outbound.send(send(to, epoch, b"probe")).await.unwrap();
            if let Ok(Some(SessionEvent::Record { record, .. })) =
                timeout(Duration::from_millis(100), to_events.recv()).await
                && let Record::Recv { src, .. } = *record
                && src == from
            {
                return;
            }
        }
    })
    .await
    .expect("the two nodes never became routable");
    tokio::time::sleep(Duration::from_millis(200)).await;
    while to_events.try_recv().is_ok() {}
}

#[tokio::test]
async fn an_inspecting_proxy_sees_ciphertext_and_cannot_inject() {
    // The relay's own certificate, a company CA and the certificate the proxy shows nodes.
    let relay_key = KeyPair::generate().unwrap();
    let relay_cert = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&relay_key)
        .unwrap();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Company Inspection CA");
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();

    // The platform trust of this process holds the company CA (a managed machine) and the
    // relay's certificate (the proxy dials it with the same configuration).
    let pem_path = std::env::temp_dir().join(format!("menzil-inspect-{}.pem", std::process::id()));
    std::fs::write(&pem_path, format!("{}{}", ca.pem(), relay_cert.pem())).unwrap();
    // SAFETY: the first thing the only test in this binary does, before any other thread.
    unsafe { std::env::set_var("SSL_CERT_FILE", &pem_path) };
    let trust = TestTrust {
        chain: vec![relay_cert.der().clone()],
        key_der: relay_key.serialize_der(),
        pem_path,
    };

    let relay = start_relay(&trust, 4 * 1024 * 1024).await;
    let (sender, receiver) = (identity(), identity());
    let (_owner, network_id, _roster) = seed_roster(&relay, &[&sender, &receiver]);
    let proxy = inspecting_proxy(
        relay.addr,
        vec![leaf.der().clone(), ca.der().clone()],
        leaf_key.serialize_der(),
    )
    .await;

    // The receiver goes straight to the relay, the sender through the inspecting proxy.
    let (receiver_events_tx, mut receiver_events) = mpsc::channel(256);
    let (receiver_outbound, receiver_outbound_rx) = mpsc::channel(64);
    let receiver_task = tokio::spawn(run_session(
        session_config(&relay, &receiver, network_id),
        HashMap::new(),
        receiver_events_tx,
        receiver_outbound_rx,
        Arc::new(RosterStore::new()),
    ));
    let (sender_events_tx, mut sender_events) = mpsc::channel(256);
    let (sender_outbound, sender_outbound_rx) = mpsc::channel(64);
    let mut sender_config = session_config(&relay, &sender, network_id);
    sender_config.dial.proxy_override = Some(ProxyOverride::Use(format!(
        "http://127.0.0.1:{}",
        proxy.port
    )));
    let (_stop, stop_rx) = watch::channel(false);
    let sender_task = tokio::spawn(run_session_until(
        sender_config,
        HashMap::new(),
        sender_events_tx,
        sender_outbound_rx,
        Arc::new(RosterStore::new()),
        stop_rx,
    ));
    let receiver_epoch = next_attached(&mut receiver_events).await;

    // 1. The node connects and works through the proxy.
    let epoch1 = next_attached(&mut sender_events).await;
    until_routable(
        &sender_outbound,
        epoch1,
        sender.node_id,
        receiver.node_id,
        &mut receiver_events,
    )
    .await;
    let marker: &[u8] = b"PLAINTEXT-MARKER-0123456789-abcdefghijklmnopqrstuvwxyz";
    sender_outbound
        .send(send(receiver.node_id, epoch1, marker))
        .await
        .unwrap();
    let got = payloads_for(&mut receiver_events, sender.node_id, Duration::from_secs(2)).await;
    assert_eq!(got, vec![marker.to_vec()], "the record arrived intact");

    // 2. The proxy read the head in the clear and nothing but ciphertext after it.
    {
        let seen = proxy.seen.lock().unwrap();
        assert!(
            seen.connects[0].starts_with(&format!("CONNECT localhost:{} ", relay.addr.port())),
            "{:?}",
            seen.connects
        );
        let head = String::from_utf8_lossy(&seen.heads[0]).to_lowercase();
        assert!(
            head.contains("upgrade: websocket"),
            "the proxy read the head: {head}"
        );
        assert!(
            !seen.payloads[0].is_empty() && !seen.payloads[1].is_empty(),
            "the proxy saw frames in both directions"
        );
        let needles: [(&str, &[u8]); 4] = [
            ("the marker", marker),
            ("the sender's NodeId", sender.node_id.as_ref()),
            ("the receiver's NodeId", receiver.node_id.as_ref()),
            ("the relay's NodeId", relay.id.node_id.as_ref()),
        ];
        for (dir, payload) in seen.payloads.iter().enumerate() {
            for (what, needle) in needles {
                assert!(
                    !payload.windows(needle.len()).any(|window| window == needle),
                    "{what} is visible to the proxy in direction {dir}"
                );
            }
        }
    }

    // 3. A record injected towards the relay is rejected: the session ends, and what the
    // sender sends after it never reaches the receiver.
    proxy.tamper.store(TAMPER_UP, Ordering::SeqCst);
    let after_up: &[u8] = b"SENT-AFTER-THE-UPSTREAM-INJECTION-0123456789";
    sender_outbound
        .send(send(receiver.node_id, epoch1, after_up))
        .await
        .unwrap();
    next_detached(&mut sender_events).await;
    assert_eq!(proxy.tampered[0].load(Ordering::SeqCst), 1);
    let got = payloads_for(&mut receiver_events, sender.node_id, Duration::from_secs(2)).await;
    assert!(
        !got.iter().any(|p| p == after_up),
        "the receiver got {got:?}"
    );

    // 4. A record injected towards the node is rejected: its session ends.
    let epoch2 = next_attached(&mut sender_events).await;
    assert!(epoch2 > epoch1);
    until_routable(
        &sender_outbound,
        epoch2,
        sender.node_id,
        receiver.node_id,
        &mut receiver_events,
    )
    .await;
    proxy.tamper.store(TAMPER_DOWN, Ordering::SeqCst);
    let downstream: &[u8] = b"SENT-TO-THE-NODE-THROUGH-THE-INJECTION-0123";
    receiver_outbound
        .send(send(sender.node_id, receiver_epoch, downstream))
        .await
        .unwrap();
    let delivered = payloads_for_until_detached(&mut sender_events, receiver.node_id).await;
    assert_eq!(proxy.tampered[1].load(Ordering::SeqCst), 1);
    assert!(
        !delivered.iter().any(|p| p == downstream),
        "the node delivered what the proxy altered: {delivered:?}"
    );

    // 5. With the proxy honest again the node reattaches and a record arrives.
    let epoch3 = next_attached(&mut sender_events).await;
    assert!(epoch3 > epoch2);
    until_routable(
        &sender_outbound,
        epoch3,
        sender.node_id,
        receiver.node_id,
        &mut receiver_events,
    )
    .await;
    let last: &[u8] = b"AFTER-RECOVERY-0123456789";
    sender_outbound
        .send(send(receiver.node_id, epoch3, last))
        .await
        .unwrap();
    let got = payloads_for(&mut receiver_events, sender.node_id, Duration::from_secs(2)).await;
    assert_eq!(got, vec![last.to_vec()]);
    assert_eq!(proxy.tamper.load(Ordering::SeqCst), TAMPER_NONE);

    sender_task.abort();
    receiver_task.abort();
}

/// What `events` delivered from `src` until the session ended (a `Detached`).
async fn payloads_for_until_detached(
    events: &mut mpsc::Receiver<SessionEvent>,
    src: NodeId,
) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    timeout(REJECTED_WITHIN, async {
        loop {
            match events.recv().await {
                Some(SessionEvent::Detached { .. }) => return,
                Some(SessionEvent::Record { record, .. }) => {
                    if let Record::Recv {
                        src: from, payload, ..
                    } = *record
                        && from == src
                    {
                        got.push(payload);
                    }
                }
                Some(_) => {}
                None => panic!("the events channel closed"),
            }
        }
    })
    .await
    .expect("the node's session was not ended by the injected record");
    got
}
