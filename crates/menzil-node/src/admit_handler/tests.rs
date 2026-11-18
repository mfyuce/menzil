//! The invite admission rules at handler level (threat model item 2): a fake issuer stands in for
//! the files, so that faults between the book write and the save can be injected.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use menzil_proto::{
    ByteArray, InviteBody, NodeCertBody, X25519PublicKey, compute_admit_tag, hash_invite_secret,
};

use super::*;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

struct Dev {
    cert: NodeCert,
    id: NodeId,
}

fn cert_body(id: NodeId, not_before: u64, not_after: u64) -> NodeCertBody {
    NodeCertBody {
        v: menzil_proto::PROTOCOL_VERSION,
        node_id: id,
        x25519_pub: X25519PublicKey::from([7u8; 32]),
        serial: 1,
        not_before,
        not_after,
    }
}

fn device(seed: u8) -> Dev {
    device_at(seed, NOW)
}

/// A device whose certificate is valid at `now`.
fn device_at(seed: u8, now: u64) -> Dev {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let id = NodeId::from(key.verifying_key().to_bytes());
    let cert = NodeCert::sign(&key, &cert_body(id, now - 100, now + 100 * DAY)).unwrap();
    Dev { cert, id }
}

/// For the tests that run the handler's worker, which reads the real clock.
fn real_device(seed: u8) -> Dev {
    device_at(seed, unix_now())
}

struct State {
    network: NetworkId,
    owner: SigningKey,
    invites: HashMap<InviteId, InviteRecord>,
    members: Vec<(NodeId, String)>,
    revoked: Vec<NodeId>,
    /// Fail the next `record_redeemed`.
    fail_book: bool,
    /// Fail the next this many `admit` calls.
    fail_admit: u32,
    /// Failing to open the transaction: (retry, calls left).
    busy: u32,
    book_writes: u32,
    admits: Vec<Vec<NodeId>>,
    /// The order of the writes: "book" and "save".
    log: Vec<&'static str>,
}

#[derive(Clone)]
struct Fake(Arc<Mutex<State>>);

impl Fake {
    fn new() -> Self {
        let owner = SigningKey::from_bytes(&[200u8; 32]);
        let network = NetworkId::from(owner.verifying_key().to_bytes());
        Self(Arc::new(Mutex::new(State {
            network,
            owner,
            invites: HashMap::new(),
            members: vec![],
            revoked: vec![],
            fail_book: false,
            fail_admit: 0,
            busy: 0,
            book_writes: 0,
            admits: vec![],
            log: vec![],
        })))
    }

    fn network(&self) -> NetworkId {
        self.0.lock().unwrap().network
    }

    /// Makes an invite in the book and returns it with its secret.
    fn invite(&self, id: u8, uses: u8, mutate: impl FnOnce(&mut InviteBody)) -> (Invite, [u8; 32]) {
        let mut state = self.0.lock().unwrap();
        let secret = [id ^ 0x5a; 32];
        let mut body = InviteBody {
            v: menzil_proto::PROTOCOL_VERSION,
            network_id: state.network,
            invite_id: InviteId::from([id; 16]),
            secret_hash: hash_invite_secret(&secret),
            roles: vec![],
            expires: NOW + 7 * DAY,
            uses,
            name: None,
        };
        mutate(&mut body);
        let invite = Invite::sign(&state.owner, &body).unwrap();
        state.invites.insert(
            body.invite_id,
            InviteRecord {
                invite: invite.clone(),
                secret: Zeroizing::new(secret.to_vec()),
                revoked: false,
                redeemed: vec![],
            },
        );
        (invite, secret)
    }

    fn redeemed(&self, id: u8) -> Vec<NodeId> {
        self.0.lock().unwrap().invites[&InviteId::from([id; 16])]
            .redeemed
            .clone()
    }

    fn is_member(&self, dev: &Dev) -> bool {
        self.0
            .lock()
            .unwrap()
            .members
            .iter()
            .any(|(n, _)| *n == dev.id)
    }

    fn members(&self) -> Vec<(NodeId, String)> {
        self.0.lock().unwrap().members.clone()
    }
}

struct FakeTxn(Fake);

impl AdmitIssuer for Fake {
    fn listen_proof(
        &self,
        _: &NetworkId,
        _: NodeId,
        _: NodeId,
        _: Tai64N,
        _: u64,
    ) -> Option<AdmitListenBody> {
        None
    }

    fn begin(&self, network: &NetworkId, _now: u64) -> Result<Box<dyn AdmitTxn>, NotIssuer> {
        let mut state = self.0.lock().unwrap();
        if state.busy > 0 {
            state.busy -= 1;
            return Err(NotIssuer {
                why: "busy".to_string(),
                retry: true,
            });
        }
        if *network != state.network {
            return Err(NotIssuer {
                why: "not ours".to_string(),
                retry: false,
            });
        }
        drop(state);
        Ok(Box::new(FakeTxn(self.clone())))
    }
}

impl AdmitTxn for FakeTxn {
    fn invite(&self, id: &InviteId) -> Option<InviteRecord> {
        self.0.0.lock().unwrap().invites.get(id).cloned()
    }

    fn signed_here(&self, invite: &Invite) -> bool {
        let state = self.0.0.lock().unwrap();
        invite.verify(&state.owner.verifying_key()).is_ok()
    }

    fn standing(&self, node: &NodeId) -> Standing {
        let state = self.0.0.lock().unwrap();
        if state.revoked.contains(node) {
            Standing::Revoked
        } else if state.members.iter().any(|(n, _)| n == node) {
            Standing::Member
        } else {
            Standing::Absent
        }
    }

    fn names(&self) -> Vec<(NodeId, String)> {
        self.0.0.lock().unwrap().members.clone()
    }

    fn record_redeemed(&mut self, changes: &[(InviteId, Vec<NodeId>)]) -> Result<(), IssueFault> {
        let mut state = self.0.0.lock().unwrap();
        if state.fail_book {
            state.fail_book = false;
            return Err(IssueFault("disk full".to_string()));
        }
        for (id, redeemed) in changes {
            state.invites.get_mut(id).unwrap().redeemed = redeemed.clone();
        }
        state.book_writes += 1;
        state.log.push("book");
        Ok(())
    }

    fn admit(&mut self, devices: &[(NodeCert, String)]) -> Result<(), IssueFault> {
        let mut state = self.0.0.lock().unwrap();
        if state.fail_admit > 0 {
            state.fail_admit -= 1;
            return Err(IssueFault("signing failed".to_string()));
        }
        let ids: Vec<NodeId> = devices
            .iter()
            .map(|(cert, _)| cert.decode().unwrap().node_id)
            .collect();
        for ((_, name), id) in devices.iter().zip(&ids) {
            state.members.push((*id, name.clone()));
        }
        state.admits.push(ids);
        state.log.push("save");
        Ok(())
    }
}

fn request(invite: &Invite, secret: &[u8; 32], dev: &Dev, name: &str) -> AdmitRequestBody {
    let id = invite.decode().unwrap().invite_id;
    AdmitRequestBody {
        invite: invite.clone(),
        node_cert: dev.cert.clone(),
        name: name.to_string(),
        tag: compute_admit_tag(secret, id, &dev.cert, name),
    }
}

fn run(fake: &Fake, requests: Vec<AdmitRequestBody>) -> BatchOutcome {
    process_batch(fake, &fake.network(), requests, NOW)
}

fn codes(outcome: &BatchOutcome) -> Vec<(NodeId, ErrorCode)> {
    outcome
        .refused
        .iter()
        .map(|r| (r.node_id, r.code))
        .collect()
}

#[test]
fn one_request_through_two_relays_admits_and_counts_once() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(1, 1, |_| {});
    let dev = device(1);
    let req = request(&invite, &secret, &dev, "laptop");
    // Both copies in one batch.
    let outcome = run(&fake, vec![req.clone(), req.clone()]);
    assert_eq!(outcome.admitted, 1);
    assert!(outcome.refused.is_empty());
    assert_eq!(fake.redeemed(1), vec![dev.id]);
    assert_eq!(fake.0.lock().unwrap().admits.len(), 1, "one pair");
    // A later copy (another relay, a restart): success again, nothing new, no use spent.
    let again = run(&fake, vec![req]);
    assert!(again.resend, "the held Roster goes to the relay again");
    assert_eq!((again.admitted, again.refused.len()), (0, 0));
    assert_eq!(fake.redeemed(1).len(), 1);
    assert_eq!(fake.0.lock().unwrap().admits.len(), 1);
}

#[test]
fn uses_is_exact_for_n_plus_three_devices_one_by_one() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(2, 5, |_| {});
    let mut admitted = 0;
    let mut refused = vec![];
    for seed in 1..=8u8 {
        let dev = device(seed);
        let out = run(
            &fake,
            vec![request(&invite, &secret, &dev, &format!("d{seed}"))],
        );
        admitted += out.admitted;
        refused.extend(codes(&out));
    }
    assert_eq!(admitted, 5);
    assert_eq!(fake.redeemed(2).len(), 5);
    assert_eq!(fake.members().len(), 5);
    assert_eq!(refused.len(), 3);
    assert!(
        refused
            .iter()
            .all(|(_, code)| *code == ErrorCode::BadInvite)
    );
}

#[test]
fn uses_is_exact_in_one_batch_and_costs_one_pair() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(3, 5, |_| {});
    let requests: Vec<_> = (1..=8u8)
        .map(|seed| request(&invite, &secret, &device(seed), &format!("d{seed}")))
        .collect();
    let out = run(&fake, requests);
    assert_eq!(out.admitted, 5);
    assert_eq!(out.refused.len(), 3);
    let state = fake.0.lock().unwrap();
    assert_eq!(state.admits.len(), 1, "five devices, one pair");
    assert_eq!(state.admits[0].len(), 5);
    assert_eq!(state.book_writes, 1, "one book write for the batch");
}

#[test]
fn a_fault_between_the_book_write_and_the_save_costs_no_use() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(4, 2, |_| {});
    let (a, b, c) = (device(1), device(2), device(3));
    fake.0.lock().unwrap().fail_admit = 1;
    let req = request(&invite, &secret, &a, "a");
    let first = run(&fake, vec![req.clone()]);
    assert_eq!(first.admitted, 0);
    assert!(first.refused.is_empty(), "no refusal: the device retries");
    assert!(!fake.is_member(&a));
    assert_eq!(fake.redeemed(4), vec![a.id], "the use is written");
    // The retry admits without counting again.
    let retry = run(&fake, vec![req]);
    assert_eq!(retry.admitted, 1);
    assert!(fake.is_member(&a));
    assert_eq!(fake.redeemed(4), vec![a.id]);
    // One use is left, and exactly one.
    assert_eq!(
        run(&fake, vec![request(&invite, &secret, &b, "b")]).admitted,
        1
    );
    let last = run(&fake, vec![request(&invite, &secret, &c, "c")]);
    assert_eq!(codes(&last), vec![(c.id, ErrorCode::BadInvite)]);
}

#[test]
fn the_book_is_written_before_the_documents_and_a_failed_book_admits_nobody() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(5, 3, |_| {});
    let dev = device(1);
    fake.0.lock().unwrap().fail_book = true;
    let out = run(&fake, vec![request(&invite, &secret, &dev, "a")]);
    assert_eq!(out.admitted, 0);
    assert!(
        !fake.is_member(&dev),
        "nothing is issued when the book cannot be written"
    );
    assert!(fake.redeemed(5).is_empty());
    // Order of the writes on success.
    let ok = run(&fake, vec![request(&invite, &secret, &dev, "a")]);
    assert_eq!(ok.admitted, 1);
    assert_eq!(fake.0.lock().unwrap().log, vec!["book", "save"]);
}

#[test]
fn revoked_expired_and_role_carrying_invites_refuse_bad_invite() {
    let fake = Fake::new();
    let (live, s1) = fake.invite(6, 3, |_| {});
    let (expired, s2) = fake.invite(7, 3, |b| b.expires = NOW);
    let (roles, s3) = fake.invite(8, 3, |b| b.roles = vec!["admin".to_string()]);
    let dev = device(1);
    // Revoked in the book.
    fake.0
        .lock()
        .unwrap()
        .invites
        .get_mut(&InviteId::from([6; 16]))
        .unwrap()
        .revoked = true;
    for (invite, secret) in [(&live, &s1), (&expired, &s2), (&roles, &s3)] {
        let out = run(&fake, vec![request(invite, secret, &dev, "a")]);
        assert_eq!(codes(&out), vec![(dev.id, ErrorCode::BadInvite)]);
        assert_eq!(out.admitted, 0);
    }
    // One second before the expiry it still works.
    let (almost, s4) = fake.invite(9, 1, |b| b.expires = NOW + 1);
    assert_eq!(
        run(&fake, vec![request(&almost, &s4, &dev, "a")]).admitted,
        1
    );
}

#[test]
fn a_secret_that_does_not_match_the_signed_hash_refuses_bad_invite() {
    let fake = Fake::new();
    let (invite, _) = fake.invite(10, 1, |_| {});
    // The book's secret was damaged: its hash is no longer the signed one. The tag is made with
    // the damaged secret, so only the hash check can refuse it.
    let damaged = [0x11u8; 32];
    fake.0
        .lock()
        .unwrap()
        .invites
        .get_mut(&InviteId::from([10; 16]))
        .unwrap()
        .secret = Zeroizing::new(damaged.to_vec());
    let dev = device(1);
    let out = run(&fake, vec![request(&invite, &damaged, &dev, "a")]);
    assert_eq!(codes(&out), vec![(dev.id, ErrorCode::BadInvite)]);
}

#[test]
fn a_wrong_tag_refuses_bad_tag_whoever_it_was_made_for() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(11, 3, |_| {});
    let (dev, other) = (device(1), device(2));
    // A tag for another certificate (a relay swapping the cert).
    let mut swapped = request(&invite, &secret, &other, "a");
    swapped.node_cert = dev.cert.clone();
    // A tag for another name (a relay renaming the device).
    let mut renamed = request(&invite, &secret, &dev, "a");
    renamed.name = "b".to_string();
    // A tag made with another secret.
    let mut other_secret = request(&invite, &[9u8; 32], &dev, "a");
    other_secret.name = "a".to_string();
    for req in [swapped, renamed, other_secret] {
        let out = run(&fake, vec![req]);
        assert_eq!(codes(&out), vec![(dev.id, ErrorCode::BadTag)]);
    }
    assert!(fake.members().is_empty());
    assert!(fake.redeemed(11).is_empty());
}

#[test]
fn a_bad_certificate_refuses_bad_cert() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(12, 9, |_| {});
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let id = NodeId::from(key.verifying_key().to_bytes());
    let other_key = SigningKey::from_bytes(&[2u8; 32]);
    let certs = [
        // Expired.
        NodeCert::sign(&key, &cert_body(id, NOW - 10 * DAY, NOW - DAY)).unwrap(),
        // Not yet valid.
        NodeCert::sign(&key, &cert_body(id, NOW + DAY, NOW + 2 * DAY)).unwrap(),
        // Valid for 401 days.
        NodeCert::sign(&key, &cert_body(id, NOW - 100, NOW - 100 + 401 * DAY)).unwrap(),
        // Not signed by the NodeId's own key.
        NodeCert::sign(&other_key, &cert_body(id, NOW - 100, NOW + DAY)).unwrap(),
    ];
    for cert in certs {
        let dev = Dev { cert, id };
        let out = run(&fake, vec![request(&invite, &secret, &dev, "a")]);
        assert_eq!(codes(&out), vec![(id, ErrorCode::BadCert)]);
    }
    // 400 days exactly is fine.
    let cert = NodeCert::sign(&key, &cert_body(id, NOW - 100, NOW - 100 + 400 * DAY)).unwrap();
    let dev = Dev { cert, id };
    assert_eq!(
        run(&fake, vec![request(&invite, &secret, &dev, "a")]).admitted,
        1
    );
}

#[test]
fn a_revoked_node_is_refused_revoked_and_costs_no_use() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(13, 1, |_| {});
    let dev = device(1);
    fake.0.lock().unwrap().revoked.push(dev.id);
    let out = run(&fake, vec![request(&invite, &secret, &dev, "a")]);
    assert_eq!(codes(&out), vec![(dev.id, ErrorCode::Revoked)]);
    assert!(fake.redeemed(13).is_empty());
}

#[test]
fn names_are_checked_unique_ignoring_case_and_fixed_by_the_invite() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(14, 9, |_| {});
    let (a, b, c) = (device(1), device(2), device(3));
    assert_eq!(
        run(&fake, vec![request(&invite, &secret, &a, "Laptop")]).admitted,
        1
    );
    // The same name in another case.
    let out = run(&fake, vec![request(&invite, &secret, &b, "laptop")]);
    assert_eq!(codes(&out), vec![(b.id, ErrorCode::NameTaken)]);
    // A name that cannot head an address.
    let out = run(&fake, vec![request(&invite, &secret, &b, "bad name")]);
    assert_eq!(codes(&out), vec![(b.id, ErrorCode::NameTaken)]);
    // Two devices of one batch with names that differ in case only: the first wins.
    let out = run(
        &fake,
        vec![
            request(&invite, &secret, &b, "Desk"),
            request(&invite, &secret, &c, "desk"),
        ],
    );
    assert_eq!(out.admitted, 1);
    assert_eq!(codes(&out), vec![(c.id, ErrorCode::NameTaken)]);
    // A member asking again with its own name is not refused for it.
    let again = run(&fake, vec![request(&invite, &secret, &a, "Laptop")]);
    assert!(again.resend);
    assert!(again.refused.is_empty());
    assert_eq!(fake.redeemed(14).len(), 2);

    // A fixed name: the request's name must be it, and it is still unique.
    let (fixed, fs) = fake.invite(15, 9, |b| b.name = Some("kiosk".to_string()));
    let d = device(4);
    let wrong = run(&fake, vec![request(&fixed, &fs, &d, "other")]);
    assert_eq!(codes(&wrong), vec![(d.id, ErrorCode::NameTaken)]);
    assert_eq!(
        run(&fake, vec![request(&fixed, &fs, &d, "kiosk")]).admitted,
        1
    );
    let e = device(5);
    let dup = run(&fake, vec![request(&fixed, &fs, &e, "kiosk")]);
    assert_eq!(codes(&dup), vec![(e.id, ErrorCode::NameTaken)]);
}

#[test]
fn a_member_that_was_dropped_is_admitted_again_without_counting() {
    // An owner fold dropped the device: it is in `redeemed` and no longer a member.
    let fake = Fake::new();
    let (invite, secret) = fake.invite(16, 1, |_| {});
    let dev = device(1);
    let req = request(&invite, &secret, &dev, "a");
    assert_eq!(run(&fake, vec![req.clone()]).admitted, 1);
    fake.0.lock().unwrap().members.clear();
    let out = run(&fake, vec![req]);
    assert_eq!(out.admitted, 1);
    assert_eq!(fake.redeemed(16).len(), 1);
    assert!(fake.is_member(&dev));
}

#[test]
fn another_issuers_invite_and_unknown_ids_are_met_with_silence() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(17, 1, |_| {});
    let dev = device(1);
    // Signed by another key.
    let stranger = SigningKey::from_bytes(&[77u8; 32]);
    let body = invite.decode().unwrap();
    let foreign = Invite::sign(&stranger, &body).unwrap();
    let out = run(&fake, vec![request(&foreign, &secret, &dev, "a")]);
    assert_eq!(out, BatchOutcome::default());
    // An id the book does not hold (signed by us).
    let (ours, s) = fake.invite(18, 1, |_| {});
    fake.0
        .lock()
        .unwrap()
        .invites
        .remove(&InviteId::from([18; 16]));
    let out = run(&fake, vec![request(&ours, &s, &dev, "a")]);
    assert_eq!(out, BatchOutcome::default());
    // An invite for another network is not this batch's.
    let mut elsewhere = body.clone();
    elsewhere.network_id = NetworkId::from([5u8; 32]);
    let other = Invite::sign(&fake.0.lock().unwrap().owner, &elsewhere).unwrap();
    let out = run(&fake, vec![request(&other, &secret, &dev, "a")]);
    assert_eq!(out, BatchOutcome::default());
    assert!(fake.members().is_empty());
}

#[test]
fn a_device_with_two_invites_in_one_batch_is_admitted_once() {
    let fake = Fake::new();
    let (i1, s1) = fake.invite(19, 1, |_| {});
    let (i2, s2) = fake.invite(20, 1, |_| {});
    let dev = device(1);
    let out = run(
        &fake,
        vec![request(&i1, &s1, &dev, "a"), request(&i2, &s2, &dev, "a")],
    );
    assert_eq!(out.admitted, 1);
    assert!(
        fake.redeemed(20).is_empty(),
        "the second invite spent nothing"
    );
}

#[test]
fn a_busy_network_defers_the_batch() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(21, 1, |_| {});
    fake.0.lock().unwrap().busy = 1;
    let dev = device(1);
    let out = run(&fake, vec![request(&invite, &secret, &dev, "a")]);
    assert_eq!(out.deferred.len(), 1);
    assert!(out.refused.is_empty());
    assert!(fake.members().is_empty());
}

#[tokio::test]
async fn the_handler_batches_what_arrives_together_and_answers_the_relay() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(22, 2, |_| {});
    let handler =
        AdmitHandler::spawn_with_window(Arc::new(fake.clone()), Duration::from_millis(80));
    let (a, b, c) = (real_device(1), real_device(2), real_device(3));
    for (dev, name) in [(&a, "a"), (&b, "b"), (&c, "c")] {
        handler.submit(request(&invite, &secret, dev, name));
    }
    // The third is over the uses: refused once the batch ran.
    let out = tokio::time::timeout(Duration::from_secs(5), handler.next_out())
        .await
        .unwrap();
    assert_eq!(
        out,
        AdmitOut::Refused(AdmitRefusedBody {
            invite_id: InviteId::from([22; 16]),
            node_id: c.id,
            code: ErrorCode::BadInvite,
        })
    );
    assert_eq!(
        fake.0.lock().unwrap().admits.len(),
        1,
        "one pair for the batch"
    );
    assert_eq!(fake.members().len(), 2);
    // A member asking again: the Roster goes to the relay again.
    handler.submit(request(&invite, &secret, &a, "a"));
    let out = tokio::time::timeout(Duration::from_secs(5), handler.next_out())
        .await
        .unwrap();
    assert_eq!(out, AdmitOut::ResendRoster(fake.network()));
}

#[tokio::test]
async fn a_busy_network_is_tried_again_and_then_admits() {
    let fake = Fake::new();
    let (invite, secret) = fake.invite(23, 1, |_| {});
    fake.0.lock().unwrap().busy = 1;
    let handler =
        AdmitHandler::spawn_with_window(Arc::new(fake.clone()), Duration::from_millis(20));
    let dev = real_device(1);
    handler.submit(request(&invite, &secret, &dev, "a"));
    for _ in 0..200 {
        if fake.is_member(&dev) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(fake.is_member(&dev));
    assert_eq!(fake.redeemed(23).len(), 1);
}

#[test]
fn byte_arrays_are_what_the_helpers_take() {
    // The tag helper binds invite id, certificate and name: the test helpers above rely on it.
    let dev = device(1);
    let a = compute_admit_tag(&[1u8; 32], InviteId::from([1; 16]), &dev.cert, "x");
    let b = compute_admit_tag(&[1u8; 32], InviteId::from([1; 16]), &dev.cert, "y");
    assert_ne!(a, b);
    let _ = ByteArray::<32>::from([0u8; 32]);
}
