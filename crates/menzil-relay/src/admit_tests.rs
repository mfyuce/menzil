//! Live tests of the relay's side of invite redemption (`crate::admit`, protocol.md 7.2, slice
//! D3 B2): redeem sessions, the uniform refusal, the holding figures, the issuer registration,
//! ADMIT_PENDING delivery, refusals and the answer on Roster adoption. A child of
//! `session_tests` for its live relay and client helpers.

use super::*;
use crate::admit::RedeemLimits;
use menzil_proto::{
    AdmitListenBody, AdmitRefusedBody, AdmitRequestBody, AdmitResultBody, ErrorBody, Invite,
    InviteBody, InviteId, RevokedMember, Steward, StewardBody, StewardKey, compute_admit_tag,
    hash_invite_secret,
};

const SECRET: [u8; 32] = [9; 32];

struct OwnerNet {
    owner: SigningKey,
    id: NetworkId,
}

fn roster_of(
    net: &OwnerNet,
    seq: u64,
    members: &[&TestIdentity],
    revoked: &[&TestIdentity],
    stewards: Vec<Steward>,
) -> Roster {
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id: net.id,
        seq,
        issued: 0,
        expires: 4_000_000_000,
        members: members
            .iter()
            .map(|who| RosterMember {
                node_id: who.node_id,
                min_serial: 1,
            })
            .collect(),
        revoked: revoked
            .iter()
            .map(|who| RevokedMember {
                node_id: who.node_id,
                since: 1,
            })
            .collect(),
        stewards,
        labels: vec![],
    };
    Roster::sign(&net.owner, &body).unwrap()
}

fn new_net() -> OwnerNet {
    let owner = SigningKey::generate(&mut rand::rng());
    let id = NetworkId::from(owner.verifying_key().to_bytes());
    OwnerNet { owner, id }
}

/// A served network of `members` with no steward.
fn owner_net(relay: &Relay, members: &[&TestIdentity]) -> OwnerNet {
    let net = new_net();
    relay
        .rosters()
        .set(&roster_of(&net, 1, members, &[], vec![]))
        .unwrap();
    net
}

/// A served network whose Roster names one steward with `may` and `not_after`.
fn steward_net(
    relay: &Relay,
    members: &[&TestIdentity],
    may: &[&str],
    not_after: u64,
) -> (OwnerNet, SigningKey) {
    let net = new_net();
    let steward = SigningKey::generate(&mut rand::rng());
    let entry = Steward::sign(
        &net.owner,
        &StewardBody {
            v: PROTOCOL_VERSION,
            network_id: net.id,
            steward_pub: StewardKey::from(steward.verifying_key().to_bytes()),
            may: may.iter().map(ToString::to_string).collect(),
            not_after,
        },
    )
    .unwrap();
    relay
        .rosters()
        .set(&roster_of(&net, 1, members, &[], vec![entry]))
        .unwrap();
    (net, steward)
}

fn soon() -> u64 {
    real_now() + 3600
}

fn invite_with(
    signer: &SigningKey,
    network: NetworkId,
    id: u8,
    expires: u64,
    roles: Vec<String>,
) -> Invite {
    Invite::sign(
        signer,
        &InviteBody {
            v: PROTOCOL_VERSION,
            network_id: network,
            invite_id: InviteId::from([id; 16]),
            secret_hash: hash_invite_secret(&SECRET),
            roles,
            expires,
            uses: 1,
            name: None,
        },
    )
    .unwrap()
}

fn invite(signer: &SigningKey, network: NetworkId, id: u8) -> Invite {
    invite_with(signer, network, id, soon(), vec![])
}

fn request_with_cert(cert_of: &TestIdentity, invite: &Invite) -> AdmitRequestBody {
    let cert = node_cert_for(cert_of, 1);
    let id = invite.decode().unwrap().invite_id;
    AdmitRequestBody {
        invite: invite.clone(),
        tag: compute_admit_tag(&SECRET, id, &cert, "laptop"),
        node_cert: cert,
        name: "laptop".to_string(),
    }
}

fn request(who: &TestIdentity, invite: &Invite) -> AdmitRequestBody {
    request_with_cert(who, invite)
}

struct Harness {
    relay: Relay,
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    relay_x25519: X25519PublicKey,
}

async fn start_with(tweak: impl FnOnce(Relay) -> Relay) -> Harness {
    let (relay, listener, cert, relay_x25519) = bind_test_relay().await;
    let relay = tweak(relay);
    let addr = listener.local_addr().unwrap();
    let serving = relay.clone();
    tokio::spawn(async move { serving.serve(&listener).await });
    Harness {
        relay,
        addr,
        cert,
        relay_x25519,
    }
}

async fn start() -> Harness {
    start_with(|relay| relay).await
}

fn limits(per_network: usize, per_invite: usize, per_address: usize) -> RedeemLimits {
    RedeemLimits {
        per_network,
        per_invite,
        per_address,
        ..RedeemLimits::default()
    }
}

fn ts_of(byte: u8) -> Tai64N {
    let mut timestamp = [0u8; 12];
    timestamp[7] = byte;
    Tai64N::from(timestamp)
}

impl Harness {
    /// A redeem session: a HELLO that claims no network.
    async fn redeem(&self, who: &TestIdentity) -> TestClient {
        let (client, welcome) = TestClient::connect(
            self.addr,
            self.cert.clone(),
            who,
            self.relay_x25519,
            vec![],
            HashMap::new(),
            1,
            10,
        )
        .await;
        assert!(
            welcome.rosters.is_empty(),
            "a redeem session learns no Roster"
        );
        client
    }

    /// An attached member of `network` (its Roster, seq 1, already held by the node).
    async fn member(&self, who: &TestIdentity, network: NetworkId, ts: u8) -> TestClient {
        let (mut client, _) = TestClient::connect(
            self.addr,
            self.cert.clone(),
            who,
            self.relay_x25519,
            vec![network],
            HashMap::from([(network, 1)]),
            1,
            ts,
        )
        .await;
        client.send(Record::Attach).await;
        ping_pong(&mut client, [1; 8]).await;
        client
    }

    fn proof(&self, network: &OwnerNet, signer: &SigningKey, who: &TestIdentity, ts: u8) -> Record {
        Record::AdmitListen(AdmitListenBody::sign(
            network.id,
            signer,
            self.relay.relay_id().unwrap(),
            who.node_id,
            ts_of(ts),
        ))
    }

    /// An attached member that registered as the issuer of `network` with the owner's key.
    async fn issuer(&self, who: &TestIdentity, net: &OwnerNet, ts: u8) -> TestClient {
        let mut client = self.member(who, net.id, ts).await;
        client.send(self.proof(net, &net.owner, who, ts)).await;
        ping_pong(&mut client, [2; 8]).await;
        assert!(
            self.relay.admit.has_listener(&net.id),
            "the proof was refused"
        );
        client
    }
}

async fn recv_skipping_pings(client: &mut TestClient) -> Option<Record> {
    loop {
        match client.recv().await {
            Some(Record::Ping { nonce }) => client.send(Record::Pong { nonce }).await,
            other => return other,
        }
    }
}

async fn expect_error(client: &mut TestClient) -> ErrorBody {
    match recv_skipping_pings(client).await {
        Some(Record::Error(body)) => body,
        other => panic!("expected ERROR, got {other:?}"),
    }
}

async fn expect_result(client: &mut TestClient) -> AdmitResultBody {
    match recv_skipping_pings(client).await {
        Some(Record::AdmitResult(body)) => body,
        other => panic!("expected ADMIT_RESULT, got {other:?}"),
    }
}

/// True when nothing but keepalives arrives for a moment.
async fn quiet(client: &mut TestClient) -> bool {
    tokio::time::timeout(Duration::from_millis(250), recv_skipping_pings(client))
        .await
        .is_err()
}

async fn held_count(relay: &Relay, want: usize) {
    for _ in 0..300 {
        if relay.admit.held() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "held requests never became {want}, now {}",
        relay.admit.held()
    );
}

/// A request held, with the device answered `pending` (no issuer registered).
async fn hold(h: &Harness, who: &TestIdentity, invite: &Invite) -> TestClient {
    let mut client = h.redeem(who).await;
    client
        .send(Record::AdmitRequest(request(who, invite)))
        .await;
    assert_eq!(expect_result(&mut client).await, AdmitResultBody::Pending);
    client
}

// --- the uniform refusal --------------------------------------------------------------------

/// An unserved network, a bad signature, an expired or ineligible steward, an invite with roles
/// or past its expiry, and another device's certificate all get the same ERROR; the ones that
/// reach the signatures do the same signature work whatever the Roster holds.
#[tokio::test]
async fn every_failed_check_gets_the_same_error_and_the_same_signature_work() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let ghost = new_net(); // never seeded: not served
    let (st_expired, st_expired_key) = steward_net(&h.relay, &[&issuer], &["admit"], 1_000);
    let (st_renew_only, st_renew_key) =
        steward_net(&h.relay, &[&issuer], &["renew"], 4_000_000_000);
    let stranger = SigningKey::generate(&mut rand::rng());

    // (name, invite, who whose cert goes in the request, signature checks expected)
    let someone = generate_identity();
    let cases: Vec<(&str, Invite, Option<u32>)> = vec![
        (
            "unserved network",
            invite(&ghost.owner, ghost.id, 1),
            Some(2),
        ),
        (
            "signed by a stranger",
            invite(&stranger, net.id, 2),
            Some(2),
        ),
        (
            "expired steward",
            invite(&st_expired_key, st_expired.id, 3),
            Some(2),
        ),
        (
            "steward without admit",
            invite(&st_renew_key, st_renew_only.id, 4),
            Some(2),
        ),
        (
            "roles",
            invite_with(&net.owner, net.id, 5, soon(), vec!["admin".into()]),
            None,
        ),
        (
            "expired invite",
            invite_with(&net.owner, net.id, 6, 1_000, vec![]),
            None,
        ),
    ];
    let mut errors = Vec::new();
    for (name, invite, work) in &cases {
        let who = generate_identity();
        let mut client = h.redeem(&who).await;
        let before = h.relay.admit.verify_count();
        client
            .send(Record::AdmitRequest(request(&who, invite)))
            .await;
        let error = expect_error(&mut client).await;
        assert_eq!(error.code, ErrorCode::BadInvite, "{name}");
        if let Some(work) = work {
            assert_eq!(
                h.relay.admit.verify_count() - before,
                *work as usize,
                "{name}: the signature work must not depend on the Roster"
            );
        }
        errors.push((name, error));
    }
    // Another device's certificate in the request.
    let who = generate_identity();
    let mut client = h.redeem(&who).await;
    client
        .send(Record::AdmitRequest(request_with_cert(
            &someone,
            &invite(&net.owner, net.id, 7),
        )))
        .await;
    errors.push((&"foreign certificate", expect_error(&mut client).await));
    for (name, error) in &errors {
        assert_eq!(
            Record::Error(error.clone()).encode(),
            Record::Error(errors[0].1.clone()).encode(),
            "{name}: the refusal differs from the first one"
        );
    }
    assert_eq!(h.relay.admit.held(), 0);
}

/// A served network with an eligible steward does the same two checks as one without.
#[tokio::test]
async fn a_served_network_with_and_without_a_steward_does_the_same_work() {
    let h = start().await;
    let issuer = generate_identity();
    let plain = owner_net(&h.relay, &[&issuer]);
    let (stewarded, _key) = steward_net(&h.relay, &[&issuer], &["admit"], 4_000_000_000);
    let stranger = SigningKey::generate(&mut rand::rng());
    for (net, id) in [(&plain, 1u8), (&stewarded, 2u8)] {
        let who = generate_identity();
        let mut client = h.redeem(&who).await;
        let before = h.relay.admit.verify_count();
        client
            .send(Record::AdmitRequest(request(
                &who,
                &invite(&stranger, net.id, id),
            )))
            .await;
        assert_eq!(expect_error(&mut client).await.code, ErrorCode::BadInvite);
        assert_eq!(h.relay.admit.verify_count() - before, 2);
    }
}

/// The owner's and a steward's invites are accepted and held; the device hears `pending`.
#[tokio::test]
async fn an_owner_signed_and_a_steward_signed_invite_are_held() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let (st, key) = steward_net(&h.relay, &[&issuer], &["admit", "renew"], 4_000_000_000);
    let (a, b) = (generate_identity(), generate_identity());
    let _ca = hold(&h, &a, &invite(&net.owner, net.id, 1)).await;
    let _cb = hold(&h, &b, &invite(&key, st.id, 2)).await;
    assert_eq!(h.relay.admit.held(), 2);
}

// --- redeem sessions ---------------------------------------------------------------------

#[tokio::test]
async fn nothing_but_an_admit_request_is_taken_on_a_redeem_session() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let junk_proof = Record::AdmitListen(AdmitListenBody::sign(
        net.id,
        &net.owner,
        h.relay.relay_id().unwrap(),
        issuer.node_id,
        ts_of(10),
    ));
    let records = vec![
        Record::Attach,
        Record::Send {
            dst: issuer.node_id,
            e2e_proto: 1,
            flags: 0,
            payload: vec![1, 2, 3],
        },
        junk_proof,
        Record::AdmitRefused(AdmitRefusedBody {
            invite_id: InviteId::from([1; 16]),
            node_id: issuer.node_id,
            code: ErrorCode::BadInvite,
        }),
    ];
    for record in records {
        let who = generate_identity();
        let mut client = h.redeem(&who).await;
        client.send(record).await;
        assert_eq!(expect_error(&mut client).await.code, ErrorCode::NotMember);
        assert_eq!(
            recv_skipping_pings(&mut client).await,
            None,
            "the session ends"
        );
        assert_eq!(h.relay.registry.attached_session_id(&who.node_id), None);
    }
    assert!(!h.relay.admit.has_listener(&net.id));
    // A second request on one session ends it too (one per session).
    let who = generate_identity();
    let mut client = h.redeem(&who).await;
    let held = invite(&net.owner, net.id, 1);
    client
        .send(Record::AdmitRequest(request(&who, &held)))
        .await;
    assert_eq!(expect_result(&mut client).await, AdmitResultBody::Pending);
    client
        .send(Record::AdmitRequest(request(&who, &held)))
        .await;
    assert_eq!(expect_error(&mut client).await.code, ErrorCode::NotMember);
    assert_eq!(recv_skipping_pings(&mut client).await, None);
    held_count(&h.relay, 0).await;
}

// --- the holding figures ---------------------------------------------------------------------

#[test]
fn the_default_figures_are_the_documented_ones() {
    let figures = RedeemLimits::default();
    assert_eq!(figures.per_network, 100);
    assert_eq!(figures.per_invite, 8);
    assert_eq!(figures.per_address, 4);
    assert_eq!(figures.max_wait, Duration::from_secs(600));
    assert_eq!(crate::admit::HOLD_PER_NODE, 1);
    let admission = AdmissionLimits::default();
    assert_eq!(admission.max_unattached_per_ip, 32);
    assert_eq!(admission.max_unattached_per_node, 2);
}

#[tokio::test]
async fn a_network_holds_at_most_its_figure() {
    let h = start_with(|relay| relay.with_redeem_limits(limits(2, 100, 100))).await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let other = owner_net(&h.relay, &[&issuer]);
    let (a, b, c, d) = (
        generate_identity(),
        generate_identity(),
        generate_identity(),
        generate_identity(),
    );
    let _ca = hold(&h, &a, &invite(&net.owner, net.id, 1)).await;
    let _cb = hold(&h, &b, &invite(&net.owner, net.id, 2)).await;
    let mut cc = h.redeem(&c).await;
    cc.send(Record::AdmitRequest(request(
        &c,
        &invite(&net.owner, net.id, 3),
    )))
    .await;
    assert_eq!(expect_error(&mut cc).await.code, ErrorCode::RateLimited);
    // Another network has its own count.
    let _cd = hold(&h, &d, &invite(&other.owner, other.id, 4)).await;
}

#[tokio::test]
async fn an_invite_id_holds_at_most_its_figure() {
    let h = start_with(|relay| relay.with_redeem_limits(limits(100, 2, 100))).await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let same = invite(&net.owner, net.id, 1);
    let (a, b, c, d) = (
        generate_identity(),
        generate_identity(),
        generate_identity(),
        generate_identity(),
    );
    let _ca = hold(&h, &a, &same).await;
    let _cb = hold(&h, &b, &same).await;
    let mut cc = h.redeem(&c).await;
    cc.send(Record::AdmitRequest(request(&c, &same))).await;
    assert_eq!(expect_error(&mut cc).await.code, ErrorCode::RateLimited);
    // Another invite of the network still fits.
    let _cd = hold(&h, &d, &invite(&net.owner, net.id, 2)).await;
}

#[tokio::test]
async fn a_source_address_holds_at_most_its_figure() {
    let h = start_with(|relay| relay.with_redeem_limits(limits(100, 100, 2))).await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let (a, b, c) = (
        generate_identity(),
        generate_identity(),
        generate_identity(),
    );
    let _ca = hold(&h, &a, &invite(&net.owner, net.id, 1)).await;
    let _cb = hold(&h, &b, &invite(&net.owner, net.id, 2)).await;
    let mut cc = h.redeem(&c).await;
    cc.send(Record::AdmitRequest(request(
        &c,
        &invite(&net.owner, net.id, 3),
    )))
    .await;
    assert_eq!(expect_error(&mut cc).await.code, ErrorCode::RateLimited);
}

#[tokio::test]
async fn a_node_holds_one_request_and_gets_the_place_back() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let who = generate_identity();
    let first = hold(&h, &who, &invite(&net.owner, net.id, 1)).await;
    // A second session of the same NodeId (two unattached are allowed) may not hold another.
    let mut second = h.redeem(&who).await;
    second
        .send(Record::AdmitRequest(request(
            &who,
            &invite(&net.owner, net.id, 2),
        )))
        .await;
    assert_eq!(expect_error(&mut second).await.code, ErrorCode::RateLimited);
    // The first one's end frees the place, and the same device may ask again.
    drop(first);
    held_count(&h.relay, 0).await;
    let _again = hold(&h, &who, &invite(&net.owner, net.id, 3)).await;
}

#[tokio::test]
async fn redeem_sessions_count_against_the_unattached_figures_of_the_node() {
    let h = start().await;
    let who = generate_identity();
    let _one = h.redeem(&who).await;
    let _two = h.redeem(&who).await;
    let (mut three, _) = TestClient::connect(
        h.addr,
        h.cert.clone(),
        &who,
        h.relay_x25519,
        vec![],
        HashMap::new(),
        1,
        10,
    )
    .await;
    assert_eq!(expect_error(&mut three).await.code, ErrorCode::RateLimited);
}

#[tokio::test]
async fn redeem_sessions_count_against_the_unattached_figure_of_the_address() {
    let admission = AdmissionLimits {
        connections_per_ip_per_minute: 1_000_000,
        max_unattached_per_ip: 2,
        max_handshakes_per_ip: 1_000_000,
        max_handshakes_per_v6_48: 1_000_000,
        ..AdmissionLimits::default()
    };
    let h = start_with(|relay| relay.with_admission_limits(admission)).await;
    let _a = h.redeem(&generate_identity()).await;
    let _b = h.redeem(&generate_identity()).await;
    assert_eq!(h.relay.admission.unattached_of_peer(LOOPBACK), 2);
    // The third connection is dropped before TLS: nothing is ever answered.
    let mut tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut tcp, &mut buf),
    )
    .await
    .expect("the connection was not closed");
    assert!(matches!(read, Ok(0) | Err(_)));
}

// --- the issuer's registration ---------------------------------------------------------------

#[tokio::test]
async fn a_valid_proof_registers_and_a_forged_or_misbound_one_does_not() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let relay_id = h.relay.relay_id().unwrap();
    let mut client = h.member(&issuer, net.id, 10).await;

    let stranger = SigningKey::generate(&mut rand::rng());
    let other_node = generate_identity();
    let bad = [
        // A key that is neither the owner nor a steward, with a valid signature.
        (
            "a stranger's key",
            AdmitListenBody::sign(net.id, &stranger, relay_id, issuer.node_id, ts_of(10)),
        ),
        // The owner's key as `signer`, but another key's signature.
        ("a forged signature", {
            let mut body =
                AdmitListenBody::sign(net.id, &stranger, relay_id, issuer.node_id, ts_of(10));
            body.signer = menzil_proto::ByteArray::from(net.owner.verifying_key().to_bytes());
            body
        }),
        (
            "another relay",
            AdmitListenBody::sign(
                net.id,
                &net.owner,
                other_node.node_id,
                issuer.node_id,
                ts_of(10),
            ),
        ),
        (
            "another session",
            AdmitListenBody::sign(net.id, &net.owner, relay_id, other_node.node_id, ts_of(10)),
        ),
        (
            "another timestamp",
            AdmitListenBody::sign(net.id, &net.owner, relay_id, issuer.node_id, ts_of(11)),
        ),
        // The session's own proof for a network it did not claim.
        ("an unclaimed network", {
            let elsewhere = owner_net(&h.relay, &[&issuer]);
            AdmitListenBody::sign(
                elsewhere.id,
                &elsewhere.owner,
                relay_id,
                issuer.node_id,
                ts_of(10),
            )
        }),
    ];
    for (what, body) in bad {
        client.send(Record::AdmitListen(body.clone())).await;
        ping_pong(&mut client, [3; 8]).await;
        assert!(!h.relay.admit.has_listener(&net.id), "{what} registered");
        assert!(
            !h.relay.admit.has_listener(&body.network_id),
            "{what} registered"
        );
    }
    client.send(h.proof(&net, &net.owner, &issuer, 10)).await;
    ping_pong(&mut client, [4; 8]).await;
    assert!(h.relay.admit.has_listener(&net.id));
}

#[tokio::test]
async fn a_steward_with_admit_registers_one_without_or_expired_does_not() {
    let h = start().await;
    let issuer = generate_identity();
    let (ok, ok_key) = steward_net(&h.relay, &[&issuer], &["admit"], 4_000_000_000);
    let (renew_only, renew_key) = steward_net(&h.relay, &[&issuer], &["renew"], 4_000_000_000);
    let (expired, expired_key) = steward_net(&h.relay, &[&issuer], &["admit"], 1_000);
    for (n, (net, key, accepted)) in [
        (&ok, &ok_key, true),
        (&renew_only, &renew_key, false),
        (&expired, &expired_key, false),
    ]
    .into_iter()
    .enumerate()
    {
        // The HELLO timestamp of one NodeId must advance with each session.
        let ts = 10 + n as u8;
        let mut client = h.member(&issuer, net.id, ts).await;
        client.send(h.proof(net, key, &issuer, ts)).await;
        ping_pong(&mut client, [5; 8]).await;
        assert_eq!(h.relay.admit.has_listener(&net.id), accepted);
        drop(client);
        held_count(&h.relay, 0).await;
        for _ in 0..300 {
            if h.relay
                .registry
                .attached_session_id(&issuer.node_id)
                .is_none()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

#[tokio::test]
async fn a_proof_before_attach_is_ignored_and_a_registration_ends_with_its_session() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    // Before ATTACH the session is not current: ignored.
    let (mut early, _) = TestClient::connect(
        h.addr,
        h.cert.clone(),
        &issuer,
        h.relay_x25519,
        vec![net.id],
        HashMap::from([(net.id, 1)]),
        1,
        10,
    )
    .await;
    early.send(h.proof(&net, &net.owner, &issuer, 10)).await;
    ping_pong(&mut early, [6; 8]).await;
    assert!(!h.relay.admit.has_listener(&net.id));
    drop(early);

    let issuing = h.issuer(&issuer, &net, 11).await;
    drop(issuing);
    for _ in 0..300 {
        if !h.relay.admit.has_listener(&net.id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the registration outlived its session");
}

// --- delivery and refusals ---------------------------------------------------------------------

#[tokio::test]
async fn a_request_is_delivered_to_the_newest_registered_issuer() {
    let h = start().await;
    let (first, second) = (generate_identity(), generate_identity());
    let owner_dev = generate_identity();
    let net = owner_net(&h.relay, &[&first, &second, &owner_dev]);
    let mut one = h.issuer(&first, &net, 10).await;
    let device = generate_identity();
    let req = request(&device, &invite(&net.owner, net.id, 1));
    let mut dev = h.redeem(&device).await;
    dev.send(Record::AdmitRequest(req.clone())).await;
    // Delivered, so the device is not told `pending`.
    match recv_skipping_pings(&mut one).await {
        Some(Record::AdmitPending(body)) => assert_eq!(body, req),
        other => panic!("expected ADMIT_PENDING, got {other:?}"),
    }
    assert!(quiet(&mut dev).await);
    // A newer registration receives the held request, and the next ones.
    let mut two = h.member(&second, net.id, 12).await;
    two.send(h.proof(&net, &net.owner, &second, 12)).await;
    match recv_skipping_pings(&mut two).await {
        Some(Record::AdmitPending(body)) => assert_eq!(body, req),
        other => panic!("expected the held request, got {other:?}"),
    }
    let device2 = generate_identity();
    let req2 = request(&device2, &invite(&net.owner, net.id, 2));
    let mut dev2 = h.redeem(&device2).await;
    dev2.send(Record::AdmitRequest(req2.clone())).await;
    match recv_skipping_pings(&mut two).await {
        Some(Record::AdmitPending(body)) => assert_eq!(body, req2),
        other => panic!("expected ADMIT_PENDING, got {other:?}"),
    }
    assert!(
        quiet(&mut one).await,
        "the older registration gets nothing more"
    );
}

#[tokio::test]
async fn a_refusal_counts_only_from_the_registered_session() {
    let h = start().await;
    let (issuer, member) = (generate_identity(), generate_identity());
    let net = owner_net(&h.relay, &[&issuer, &member]);
    let mut registered = h.issuer(&issuer, &net, 10).await;
    let mut other = h.member(&member, net.id, 11).await;
    let device = generate_identity();
    let inv = invite(&net.owner, net.id, 1);
    let mut dev = h.redeem(&device).await;
    dev.send(Record::AdmitRequest(request(&device, &inv))).await;
    assert!(matches!(
        recv_skipping_pings(&mut registered).await,
        Some(Record::AdmitPending(_))
    ));
    let refusal = |code| {
        Record::AdmitRefused(AdmitRefusedBody {
            invite_id: InviteId::from([1; 16]),
            node_id: device.node_id,
            code,
        })
    };
    // A member that is not the registered issuer: ignored.
    other.send(refusal(ErrorCode::BadTag)).await;
    ping_pong(&mut other, [7; 8]).await;
    assert!(
        quiet(&mut dev).await,
        "a refusal from another session was taken"
    );
    // A refusal naming another invite is not for this request.
    registered
        .send(Record::AdmitRefused(AdmitRefusedBody {
            invite_id: InviteId::from([2; 16]),
            node_id: device.node_id,
            code: ErrorCode::BadTag,
        }))
        .await;
    ping_pong(&mut registered, [8; 8]).await;
    assert!(quiet(&mut dev).await);
    // The registered issuer's refusal is the device's answer, and the session ends.
    registered.send(refusal(ErrorCode::NameTaken)).await;
    assert_eq!(
        expect_result(&mut dev).await,
        AdmitResultBody::Refused(u16::from(ErrorCode::NameTaken))
    );
    assert_eq!(recv_skipping_pings(&mut dev).await, None);
    held_count(&h.relay, 0).await;
}

// --- the answer on Roster adoption -----------------------------------------------------------

#[tokio::test]
async fn adopting_a_roster_that_lists_the_device_answers_it() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let device = generate_identity();
    let bystander = generate_identity();
    let mut dev = hold(&h, &device, &invite(&net.owner, net.id, 1)).await;
    let mut other = hold(&h, &bystander, &invite(&net.owner, net.id, 2)).await;

    let admitted = roster_of(&net, 2, &[&issuer, &device], &[], vec![]);
    assert!(h.relay.rosters().set(&admitted).unwrap());
    assert_eq!(
        expect_result(&mut dev).await,
        AdmitResultBody::Admitted {
            roster: admitted,
            base_roster: None
        }
    );
    assert_eq!(
        recv_skipping_pings(&mut dev).await,
        None,
        "the session ends"
    );
    // The bystander is not listed: still waiting.
    assert!(quiet(&mut other).await);
    held_count(&h.relay, 1).await;
}

#[tokio::test]
async fn a_roster_that_revokes_the_device_or_omits_it_does_not_answer() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let device = generate_identity();
    let mut dev = hold(&h, &device, &invite(&net.owner, net.id, 1)).await;
    // Listed and revoked at once.
    let both = roster_of(&net, 2, &[&issuer, &device], &[&device], vec![]);
    assert!(h.relay.rosters().set(&both).unwrap());
    assert!(quiet(&mut dev).await, "a revoked device was admitted");
    // Not listed.
    let without = roster_of(&net, 3, &[&issuer], &[], vec![]);
    assert!(h.relay.rosters().set(&without).unwrap());
    assert!(quiet(&mut dev).await);
    assert_eq!(h.relay.admit.held(), 1);
}

#[tokio::test]
async fn a_steward_roster_is_answered_with_its_base() {
    let h = start().await;
    let issuer = generate_identity();
    let net = StewardNet::new(10, real_now(), issuer.node_id);
    h.relay.rosters().set(&net.base).unwrap();
    let device = generate_identity();
    let mut dev = hold(&h, &device, &invite(&net.steward, net.network_id, 1)).await;
    let listing = net.renewal_listing(&net.steward, 11, device.node_id);
    assert!(
        h.relay
            .rosters()
            .adopt(&listing, Some(&net.base), real_now())
            .unwrap()
    );
    assert_eq!(
        expect_result(&mut dev).await,
        AdmitResultBody::Admitted {
            roster: listing,
            base_roster: Some(net.base.clone())
        }
    );
}

#[tokio::test]
async fn a_device_the_roster_already_lists_is_answered_at_once() {
    let h = start().await;
    let device = generate_identity();
    let net = owner_net(&h.relay, &[&device]);
    let mut dev = h.redeem(&device).await;
    dev.send(Record::AdmitRequest(request(
        &device,
        &invite(&net.owner, net.id, 1),
    )))
    .await;
    match expect_result(&mut dev).await {
        AdmitResultBody::Admitted {
            roster,
            base_roster,
        } => {
            assert_eq!(roster.decode().unwrap().network_id, net.id);
            assert_eq!(base_roster, None);
        }
        other => panic!("expected the Roster, got {other:?}"),
    }
}

// --- lifetime ----------------------------------------------------------------------------------

#[tokio::test]
async fn a_held_request_ends_after_the_wait_and_gives_its_places_back() {
    let h = start_with(|relay| {
        relay.with_redeem_limits(RedeemLimits {
            max_wait: Duration::from_secs(30),
            ..RedeemLimits::default()
        })
    })
    .await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let device = generate_identity();
    let mut dev = hold(&h, &device, &invite(&net.owner, net.id, 1)).await;
    assert_eq!(h.relay.admit.held(), 1);

    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(25)).await;
    assert_eq!(h.relay.admit.held(), 1, "ended before the wait");
    tokio::time::advance(Duration::from_secs(10)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(h.relay.admit.held(), 0, "still held past the wait");
    assert_eq!(h.relay.admission.unattached_of_node(&device.node_id), 0);
    assert_eq!(h.relay.admission.unattached_of_peer(LOOPBACK), 0);
    let closed = tokio::time::timeout(Duration::from_secs(60), recv_skipping_pings(&mut dev)).await;
    assert_eq!(closed.expect("never closed"), None);
}

#[tokio::test]
async fn a_redeem_session_that_never_asks_ends_after_the_first_record_deadline() {
    let h = start_with(|relay| {
        relay.with_timeouts(crate::relay::SessionTimeouts {
            attach: Duration::from_secs(10),
            write: crate::connection::WRITE_TIMEOUT,
        })
    })
    .await;
    let who = generate_identity();
    let mut client = h.redeem(&who).await;
    ping_pong(&mut client, [9; 8]).await;
    assert_eq!(h.relay.admission.unattached_of_node(&who.node_id), 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(9)).await;
    assert_eq!(h.relay.admission.unattached_of_node(&who.node_id), 1);
    tokio::time::advance(Duration::from_millis(1_500)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(h.relay.admission.unattached_of_node(&who.node_id), 0);
}

#[tokio::test]
async fn nothing_is_persisted_a_new_relay_holds_nothing() {
    let h = start().await;
    let issuer = generate_identity();
    let net = owner_net(&h.relay, &[&issuer]);
    let device = generate_identity();
    let _dev = hold(&h, &device, &invite(&net.owner, net.id, 1)).await;
    assert_eq!(h.relay.admit.held(), 1);
    let (restarted, _listener, _cert, _x) = bind_test_relay().await;
    assert_eq!(restarted.admit.held(), 0);
}

/// A registration whose signer the Roster no longer names (a steward the owner removed) hears
/// nothing: the device is told `pending`.
#[tokio::test]
async fn a_registration_whose_steward_was_removed_receives_nothing() {
    let h = start().await;
    let issuer = generate_identity();
    let (net, steward) = steward_net(&h.relay, &[&issuer], &["admit"], 4_000_000_000);
    let mut client = h.member(&issuer, net.id, 10).await;
    client.send(h.proof(&net, &steward, &issuer, 10)).await;
    ping_pong(&mut client, [1; 8]).await;
    assert!(h.relay.admit.has_listener(&net.id));
    // The owner's next Roster names no steward.
    h.relay
        .rosters()
        .set(&roster_of(&net, 2, &[&issuer], &[], vec![]))
        .unwrap();
    let device = generate_identity();
    let mut dev = h.redeem(&device).await;
    dev.send(Record::AdmitRequest(request(
        &device,
        &invite(&net.owner, net.id, 1),
    )))
    .await;
    assert_eq!(expect_result(&mut dev).await, AdmitResultBody::Pending);
    assert!(
        quiet(&mut client).await,
        "a removed steward still receives requests"
    );
    // Its registration is only ever reached by invites it signed, which no longer verify; it
    // is dropped when one is delivered or when its session ends.
}

// --- round R-B regressions -----------------------------------------------------------------------

/// M1: the owner's issuer and a steward's issuer are both registered; a request goes to the
/// registration of the key that signed its invite, and the steward leaving takes only its own
/// registration away.
#[tokio::test]
async fn owner_and_steward_issuers_each_get_their_own_invites() {
    let h = start().await;
    let (owner_dev, steward_dev) = (generate_identity(), generate_identity());
    let (net, steward_key) = steward_net(
        &h.relay,
        &[&owner_dev, &steward_dev],
        &["admit"],
        4_000_000_000,
    );
    let mut owner_session = h.issuer(&owner_dev, &net, 10).await;
    let mut st = h.member(&steward_dev, net.id, 11).await;
    st.send(h.proof(&net, &steward_key, &steward_dev, 11)).await;
    ping_pong(&mut st, [3; 8]).await;
    // An owner signed invite reaches the owner's issuer, not the steward's.
    let d1 = generate_identity();
    let mut c1 = h.redeem(&d1).await;
    let req1 = request(&d1, &invite(&net.owner, net.id, 1));
    c1.send(Record::AdmitRequest(req1.clone())).await;
    match recv_skipping_pings(&mut owner_session).await {
        Some(Record::AdmitPending(body)) => assert_eq!(body, req1),
        other => panic!("expected ADMIT_PENDING for the owner, got {other:?}"),
    }
    assert!(quiet(&mut st).await, "the steward got an owner's invite");
    // A steward signed invite reaches the steward's issuer, not the owner's.
    let d2 = generate_identity();
    let mut c2 = h.redeem(&d2).await;
    let req2 = request(&d2, &invite(&steward_key, net.id, 2));
    c2.send(Record::AdmitRequest(req2.clone())).await;
    match recv_skipping_pings(&mut st).await {
        Some(Record::AdmitPending(body)) => assert_eq!(body, req2),
        other => panic!("expected ADMIT_PENDING for the steward, got {other:?}"),
    }
    assert!(quiet(&mut owner_session).await);
    // The steward leaves: the owner's registration stays.
    drop(st);
    for _ in 0..300 {
        if !h
            .relay
            .admit
            .has_listener_of(&net.id, &steward_key.verifying_key().to_bytes())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let d3 = generate_identity();
    let mut c3 = h.redeem(&d3).await;
    let req3 = request(&d3, &invite(&net.owner, net.id, 3));
    c3.send(Record::AdmitRequest(req3.clone())).await;
    match recv_skipping_pings(&mut owner_session).await {
        Some(Record::AdmitPending(body)) => assert_eq!(body, req3),
        other => panic!("the owner's issuer was lost, got {other:?}"),
    }
}

/// M1: a signer with no registration leaves the device answered `pending` even when another
/// signer's issuer is attached.
#[tokio::test]
async fn a_request_without_an_issuer_of_its_signer_is_answered_pending() {
    let h = start().await;
    let (owner_dev, steward_dev) = (generate_identity(), generate_identity());
    let (net, steward_key) = steward_net(
        &h.relay,
        &[&owner_dev, &steward_dev],
        &["admit"],
        4_000_000_000,
    );
    let mut owner_session = h.issuer(&owner_dev, &net, 10).await;
    let d = generate_identity();
    let mut c = h.redeem(&d).await;
    c.send(Record::AdmitRequest(request(
        &d,
        &invite(&steward_key, net.id, 1),
    )))
    .await;
    assert_eq!(expect_result(&mut c).await, AdmitResultBody::Pending);
    assert!(quiet(&mut owner_session).await);
}

/// L2: the signature work does not depend on how many stewards a Roster lists.
#[tokio::test]
async fn signature_work_is_the_same_for_any_number_of_stewards() {
    let h = start().await;
    let issuer = generate_identity();
    let net = new_net();
    let stewards: Vec<Steward> = (0..5)
        .map(|_| {
            let key = SigningKey::generate(&mut rand::rng());
            Steward::sign(
                &net.owner,
                &StewardBody {
                    v: PROTOCOL_VERSION,
                    network_id: net.id,
                    steward_pub: StewardKey::from(key.verifying_key().to_bytes()),
                    may: vec!["admit".to_string()],
                    not_after: 4_000_000_000,
                },
            )
            .unwrap()
        })
        .collect();
    h.relay
        .rosters()
        .set(&roster_of(&net, 1, &[&issuer], &[], stewards))
        .unwrap();
    let unserved = new_net();
    let stranger = SigningKey::generate(&mut rand::rng());
    let mut counts = Vec::new();
    for (id, n) in [(net.id, 1u8), (unserved.id, 2u8)] {
        let who = generate_identity();
        let mut client = h.redeem(&who).await;
        let before = h.relay.admit.verify_count();
        client
            .send(Record::AdmitRequest(request(
                &who,
                &invite(&stranger, id, n),
            )))
            .await;
        assert_eq!(expect_error(&mut client).await.code, ErrorCode::BadInvite);
        counts.push(h.relay.admit.verify_count() - before);
    }
    assert_eq!(counts[0], counts[1], "served and unserved cost differently");
}

/// L3: a steward removed from the Roster cannot refuse a held request any more.
#[tokio::test]
async fn a_removed_steward_cannot_refuse() {
    let h = start().await;
    let steward_dev = generate_identity();
    let (net, steward_key) = steward_net(&h.relay, &[&steward_dev], &["admit"], 4_000_000_000);
    let mut st = h.member(&steward_dev, net.id, 11).await;
    st.send(h.proof(&net, &steward_key, &steward_dev, 11)).await;
    ping_pong(&mut st, [3; 8]).await;
    let d = generate_identity();
    let mut c = h.redeem(&d).await;
    c.send(Record::AdmitRequest(request(
        &d,
        &invite(&steward_key, net.id, 1),
    )))
    .await;
    assert!(matches!(
        recv_skipping_pings(&mut st).await,
        Some(Record::AdmitPending(_))
    ));
    h.relay
        .rosters()
        .set(&roster_of(&net, 2, &[&steward_dev], &[], vec![]))
        .unwrap();
    st.send(Record::AdmitRefused(AdmitRefusedBody {
        invite_id: InviteId::from([1; 16]),
        node_id: d.node_id,
        code: ErrorCode::BadTag,
    }))
    .await;
    ping_pong(&mut st, [4; 8]).await;
    assert!(quiet(&mut c).await, "a removed steward refused a request");
}

/// L3: a steward cannot refuse a request whose invite the owner signed.
#[tokio::test]
async fn a_steward_cannot_refuse_an_owner_signed_request() {
    let h = start().await;
    let (owner_dev, steward_dev) = (generate_identity(), generate_identity());
    let (net, steward_key) = steward_net(
        &h.relay,
        &[&owner_dev, &steward_dev],
        &["admit"],
        4_000_000_000,
    );
    let mut owner_session = h.issuer(&owner_dev, &net, 10).await;
    let mut st = h.member(&steward_dev, net.id, 11).await;
    st.send(h.proof(&net, &steward_key, &steward_dev, 11)).await;
    ping_pong(&mut st, [3; 8]).await;
    let d = generate_identity();
    let mut c = h.redeem(&d).await;
    c.send(Record::AdmitRequest(request(
        &d,
        &invite(&net.owner, net.id, 1),
    )))
    .await;
    assert!(matches!(
        recv_skipping_pings(&mut owner_session).await,
        Some(Record::AdmitPending(_))
    ));
    st.send(Record::AdmitRefused(AdmitRefusedBody {
        invite_id: InviteId::from([1; 16]),
        node_id: d.node_id,
        code: ErrorCode::BadTag,
    }))
    .await;
    ping_pong(&mut st, [4; 8]).await;
    assert!(quiet(&mut c).await, "a steward refused an owner's request");
}

/// M1/L3: a steward's refusal of a request its own invite produced reaches the device, while an
/// owner's issuer is attached too.
#[tokio::test]
async fn a_steward_refuses_a_request_of_its_own_invite() {
    let h = start().await;
    let (owner_dev, steward_dev) = (generate_identity(), generate_identity());
    let (net, steward_key) = steward_net(
        &h.relay,
        &[&owner_dev, &steward_dev],
        &["admit"],
        4_000_000_000,
    );
    let _owner_session = h.issuer(&owner_dev, &net, 10).await;
    let mut st = h.member(&steward_dev, net.id, 11).await;
    st.send(h.proof(&net, &steward_key, &steward_dev, 11)).await;
    ping_pong(&mut st, [3; 8]).await;
    let d = generate_identity();
    let mut c = h.redeem(&d).await;
    c.send(Record::AdmitRequest(request(
        &d,
        &invite(&steward_key, net.id, 1),
    )))
    .await;
    assert!(matches!(
        recv_skipping_pings(&mut st).await,
        Some(Record::AdmitPending(_))
    ));
    st.send(Record::AdmitRefused(AdmitRefusedBody {
        invite_id: InviteId::from([1; 16]),
        node_id: d.node_id,
        code: ErrorCode::BadTag,
    }))
    .await;
    assert_eq!(
        expect_result(&mut c).await,
        AdmitResultBody::Refused(u16::from(ErrorCode::BadTag))
    );
}
