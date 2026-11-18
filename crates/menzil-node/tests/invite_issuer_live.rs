//! The issuer's side of invite redemption over a real relay (slice D3 B3): a node whose
//! `Observers` carry an admission handler registers with ADMIT_LISTEN after ATTACH, receives the
//! relay's ADMIT_PENDING, admits the device in one new Roster the relay adopts (and answers the
//! device with), and refuses a device whose invite is used up with ADMIT_REFUSED, which the relay
//! turns into ADMIT_RESULT `{ refused }`. The device is a raw L3 client (`menzil join` is slice
//! B4). One `#[tokio::test]`: `SSL_CERT_FILE` is process-global.

#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    Identity, TestRelay, identity, seed_roster, session_config, start_relay,
    trust_test_certificate, unix_now,
};
use ed25519_dalek::SigningKey;
use menzil_carrier::Carrier;
use menzil_node::admit_handler::{
    AdmitHandler, AdmitIssuer, AdmitTxn, InviteRecord, IssueFault, NotIssuer, Standing,
};
use menzil_node::{Observers, RelayNotes, RosterStore, SessionEvent, run_session_observed};
use menzil_proto::{
    AdmitListenBody, AdmitRequestBody, AdmitResultBody, ErrorCode, HelloBody, Invite, InviteBody,
    InviteId, NetworkId, NodeCert, NodeCertBody, NodeId, PROTOCOL_VERSION, Record, Roster,
    RosterMember, Tai64N, compute_admit_tag, hash_invite_secret,
};
use menzil_session::{HandshakePattern, NodeHandshake, Transport, prologue};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

const SECRET: [u8; 32] = [0x42; 32];

struct State {
    owner: SigningKey,
    rosters: Arc<RosterStore>,
    network: NetworkId,
    invite: InviteRecord,
    admits: usize,
}

#[derive(Clone)]
struct Issuer(Arc<Mutex<State>>);

struct Txn(Arc<Mutex<State>>);

impl AdmitIssuer for Issuer {
    fn listen_proof(
        &self,
        network: &NetworkId,
        relay: NodeId,
        session: NodeId,
        hello_timestamp: Tai64N,
        _now: u64,
    ) -> Option<AdmitListenBody> {
        let state = self.0.lock().unwrap();
        (*network == state.network)
            .then(|| AdmitListenBody::sign(*network, &state.owner, relay, session, hello_timestamp))
    }

    fn begin(&self, _: &NetworkId, _: u64) -> Result<Box<dyn AdmitTxn>, NotIssuer> {
        Ok(Box::new(Txn(self.0.clone())))
    }
}

impl AdmitTxn for Txn {
    fn invite(&self, _: &InviteId) -> Option<InviteRecord> {
        Some(self.0.lock().unwrap().invite.clone())
    }
    fn signed_here(&self, invite: &Invite) -> bool {
        let state = self.0.lock().unwrap();
        invite.verify(&state.owner.verifying_key()).is_ok()
    }
    fn standing(&self, node: &NodeId) -> Standing {
        let state = self.0.lock().unwrap();
        let body = state.rosters.body(&state.network).unwrap();
        if body.members.iter().any(|m| m.node_id == *node) {
            Standing::Member
        } else {
            Standing::Absent
        }
    }
    fn names(&self) -> Vec<(NodeId, String)> {
        vec![]
    }
    fn record_redeemed(&mut self, changes: &[(InviteId, Vec<NodeId>)]) -> Result<(), IssueFault> {
        self.0.lock().unwrap().invite.redeemed = changes[0].1.clone();
        Ok(())
    }
    fn admit(&mut self, devices: &[(NodeCert, String)]) -> Result<(), IssueFault> {
        let mut state = self.0.lock().unwrap();
        let mut body = (*state.rosters.body(&state.network).unwrap()).clone();
        body.seq += 1;
        body.issued = unix_now() - 60;
        body.expires = unix_now() + 7 * 86_400;
        for (cert, _) in devices {
            body.members.push(RosterMember {
                node_id: cert.decode().unwrap().node_id,
                min_serial: 1,
            });
        }
        let roster = Roster::sign(&state.owner, &body).unwrap();
        // The node's store takes the Roster; the session pushes it to the relay at once.
        state.rosters.set(&roster).unwrap();
        state.admits += 1;
        Ok(())
    }
}

/// A certificate an issuer accepts: valid now, for at most 400 days (the common one lasts until
/// 2096).
fn device_cert(who: &Identity) -> NodeCert {
    NodeCert::sign(
        &who.signing,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: who.node_id,
            x25519_pub: who.x25519_public,
            serial: 1,
            not_before: unix_now() - 100,
            not_after: unix_now() + 100 * 86_400,
        },
    )
    .unwrap()
}

fn tai64n(unix: u64) -> Tai64N {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + unix).to_be_bytes());
    Tai64N::from(bytes)
}

/// A device's redeem session: HELLO without a network, then ADMIT_REQUEST.
struct Device {
    carrier: Carrier,
    transport: Transport,
}

impl Device {
    async fn connect(relay: &TestRelay, who: &Identity) -> Self {
        let config = session_config(relay, who, NetworkId::from([0u8; 32]));
        let mut carrier = Carrier::dial(&config.dial, &HashMap::new()).await.unwrap();
        let selected = carrier.selected_subprotocol.clone().unwrap();
        let pattern = HandshakePattern::Ik;
        let pro = prologue(&carrier.offered_subprotocol, &selected, pattern);
        let hello = HelloBody {
            v: PROTOCOL_VERSION,
            node_cert: device_cert(who),
            networks: vec![],
            timestamp: tai64n(unix_now()),
            roster_seq: Default::default(),
            caps: vec![],
            e2e_protos: vec![],
        };
        let (handshake, message1) = NodeHandshake::start(
            pattern,
            &who.x25519_private,
            Some(&relay.id.x25519_public),
            &pro,
            &hello,
        )
        .unwrap();
        carrier.send(message1).await.unwrap();
        let message2 = carrier.recv().await.unwrap();
        let (transport, _welcome, _static, message3) = handshake.finish(&message2).unwrap();
        assert!(message3.is_none(), "IK has no third message");
        Self { carrier, transport }
    }

    async fn send(&mut self, record: Record) {
        let bytes = self.transport.encrypt_record(&record).unwrap();
        self.carrier.send(bytes).await.unwrap();
    }

    async fn recv(&mut self) -> Record {
        loop {
            let bytes = self.carrier.recv().await.unwrap();
            match self.transport.decrypt_record(&bytes).unwrap() {
                Record::Ping { nonce } => self.send(Record::Pong { nonce }).await,
                other => return other,
            }
        }
    }

    /// The first ADMIT_RESULT that is not `pending`.
    async fn answer(&mut self) -> AdmitResultBody {
        timeout(Duration::from_secs(20), async {
            loop {
                match self.recv().await {
                    Record::AdmitResult(AdmitResultBody::Pending) => {}
                    Record::AdmitResult(body) => return body,
                    other => panic!("expected ADMIT_RESULT, got {other:?}"),
                }
            }
        })
        .await
        .expect("the relay answers the device")
    }
}

fn request(invite: &Invite, who: &Identity, name: &str) -> AdmitRequestBody {
    let cert = device_cert(who);
    let id = invite.decode().unwrap().invite_id;
    AdmitRequestBody {
        invite: invite.clone(),
        tag: compute_admit_tag(&SECRET, id, &cert, name),
        node_cert: cert,
        name: name.to_string(),
    }
}

#[tokio::test]
async fn a_node_issuer_registers_receives_the_request_and_admits_or_refuses() {
    let trust = trust_test_certificate();
    let relay = start_relay(&trust, 1 << 20).await;
    let node = identity();
    let (owner, network_id, roster1) = seed_roster(&relay, &[&node]);
    let own = Arc::new(RosterStore::new());
    own.set(&roster1).unwrap();

    let invite = Invite::sign(
        &owner,
        &InviteBody {
            v: PROTOCOL_VERSION,
            network_id,
            invite_id: InviteId::from([7u8; 16]),
            secret_hash: hash_invite_secret(&SECRET),
            roles: vec![],
            expires: unix_now() + 3600,
            uses: 1,
            name: None,
        },
    )
    .unwrap();
    let issuer = Issuer(Arc::new(Mutex::new(State {
        owner: owner.clone(),
        rosters: own.clone(),
        network: network_id,
        invite: InviteRecord {
            invite: invite.clone(),
            secret: zeroize::Zeroizing::new(SECRET.to_vec()),
            revoked: false,
            redeemed: vec![],
        },
        admits: 0,
    })));
    let handler =
        AdmitHandler::spawn_with_window(Arc::new(issuer.clone()), Duration::from_millis(100));

    let (events_tx, mut events_rx) = mpsc::channel::<SessionEvent>(64);
    let (_outbound_tx, outbound_rx) = mpsc::channel(16);
    let (stop, stop_rx) = watch::channel(false);
    tokio::spawn(async move { while events_rx.recv().await.is_some() {} });
    tokio::spawn(run_session_observed(
        session_config(&relay, &node, network_id),
        HashMap::new(),
        events_tx,
        outbound_rx,
        own.clone(),
        stop_rx,
        Observers {
            notes: RelayNotes::new(),
            admit: Some(handler),
            ..Default::default()
        },
    ));

    // The first device redeems: whether its request reaches the relay before or after the
    // issuer registered, it is answered with the Roster that lists it.
    let (first, second) = (identity(), identity());
    let mut device = Device::connect(&relay, &first).await;
    device
        .send(Record::AdmitRequest(request(&invite, &first, "phone")))
        .await;
    match device.answer().await {
        AdmitResultBody::Admitted { roster, .. } => {
            let body = roster.decode().unwrap();
            assert_eq!(body.seq, 2, "one new Roster");
            assert!(body.members.iter().any(|m| m.node_id == first.node_id));
        }
        other => panic!("expected the Roster, got {other:?}"),
    }
    assert_eq!(relay.relay.rosters().seq_of(&network_id), Some(2));

    // The invite had one use: the second device is refused by the issuer, through the relay.
    let mut device = Device::connect(&relay, &second).await;
    device
        .send(Record::AdmitRequest(request(&invite, &second, "tablet")))
        .await;
    assert_eq!(
        device.answer().await,
        AdmitResultBody::Refused(u16::from(ErrorCode::BadInvite))
    );

    // The first device asks again (a lost answer): the Roster lists it, so it is answered at once
    // and nothing more is issued.
    let mut device = Device::connect(&relay, &first).await;
    device
        .send(Record::AdmitRequest(request(&invite, &first, "phone")))
        .await;
    assert!(matches!(
        device.answer().await,
        AdmitResultBody::Admitted { .. }
    ));
    assert_eq!(issuer.0.lock().unwrap().admits, 1);
    let _ = stop.send(true);
}
