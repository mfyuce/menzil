use ed25519_dalek::SigningKey;
use menzil_proto::{
    PROTOCOL_VERSION, Policy, PolicyBody, PolicyMember, RevokedMember, Roster, RosterBody,
    RosterMember,
};

use super::*;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

struct Member {
    signing: SigningKey,
    id: NodeId,
    x25519: X25519PublicKey,
}

fn member(seed: u8) -> Member {
    let signing = SigningKey::from_bytes(&[seed; 32]);
    Member {
        id: NodeId::from(signing.verifying_key().to_bytes()),
        signing,
        x25519: X25519PublicKey::from([seed.wrapping_add(100); 32]),
    }
}

/// `m`'s certificate with its own key, serial `serial` and the window `[not_before, not_after]`.
fn cert(m: &Member, serial: u32, not_before: u64, not_after: u64) -> NodeCert {
    cert_for_key(m, m.x25519, serial, not_before, not_after)
}

fn cert_for_key(
    m: &Member,
    x25519_pub: X25519PublicKey,
    serial: u32,
    not_before: u64,
    not_after: u64,
) -> NodeCert {
    NodeCert::sign(
        &m.signing,
        &NodeCertBody {
            v: PROTOCOL_VERSION,
            node_id: m.id,
            x25519_pub,
            serial,
            not_before,
            not_after,
        },
    )
    .unwrap()
}

/// A valid renewal of `m` at `serial`.
fn renewal(m: &Member, serial: u32) -> NodeCert {
    cert(m, serial, NOW - DAY, NOW + 300 * DAY)
}

/// A CBOR byte string header and body (lengths up to 65,535).
fn cbor_bstr(bytes: &[u8]) -> Vec<u8> {
    let mut out = match bytes.len() {
        n if n < 24 => vec![0x40 | n as u8],
        n if n < 256 => vec![0x58, n as u8],
        n => vec![0x59, (n >> 8) as u8, n as u8],
    };
    out.extend_from_slice(bytes);
    out
}

/// The signature of `signed_by` over the body of `body_of`: a certificate edited after signing.
fn with_body_of(signed_by: &NodeCert, body_of: &NodeCert) -> NodeCert {
    let mut bytes = vec![0x82];
    bytes.extend(cbor_bstr(body_of.body_bytes()));
    bytes.extend(cbor_bstr(signed_by.signature_bytes()));
    NodeCert::decode_strict(&bytes).unwrap()
}

struct World {
    owner: SigningKey,
    network: NetworkId,
    rosters: Arc<RosterStore>,
    policies: Arc<PolicyStore>,
}

impl World {
    /// A network whose Roster lists `m` with `min_serial` and whose Policy lists the
    /// certificates `listed` (serials of `m`).
    fn new(m: &Member, min_serial: u32, listed: &[u32]) -> Self {
        let owner = SigningKey::from_bytes(&[0xAA; 32]);
        let network = NetworkId::from(owner.verifying_key().to_bytes());
        let world = Self {
            owner,
            network,
            rosters: Arc::new(RosterStore::new()),
            policies: Arc::new(PolicyStore::new()),
        };
        world.set_roster(1, |roster| {
            roster.members = vec![RosterMember {
                node_id: m.id,
                min_serial,
            }];
        });
        world.set_policy(1, m, listed);
        world
    }

    fn set_roster(&self, seq: u64, edit: impl FnOnce(&mut RosterBody)) {
        let mut body = RosterBody {
            v: PROTOCOL_VERSION,
            network_id: self.network,
            seq,
            issued: NOW - DAY,
            expires: NOW + 10 * DAY,
            members: vec![],
            revoked: vec![],
            stewards: vec![],
            labels: vec![],
        };
        edit(&mut body);
        self.rosters
            .set(&Roster::sign(&self.owner, &body).unwrap())
            .unwrap();
    }

    fn set_policy(&self, seq: u64, m: &Member, listed: &[u32]) {
        let body = PolicyBody {
            v: PROTOCOL_VERSION,
            network_id: self.network,
            seq,
            issued: NOW - DAY,
            expires: NOW + 10 * DAY,
            members: vec![PolicyMember {
                node_id: m.id,
                name: "node".to_string(),
                roles: vec![],
            }],
            certs: listed.iter().map(|&s| renewal(m, s)).collect(),
            grants: vec![],
            egress: vec![],
            accept: vec![],
        };
        self.policies
            .set(&Policy::sign(&self.owner, &body).unwrap())
            .unwrap();
    }

    fn store(&self) -> CertCandidates {
        let store = CertCandidates::new(self.rosters.clone(), self.policies.clone());
        store.set_holder(self.network, Some(steward()), NOW);
        store
    }

    fn from(&self, m: &Member) -> Offerer {
        Offerer {
            network_id: self.network,
            peer: m.id,
            peer_static: m.x25519,
        }
    }
}

fn steward() -> Holder {
    Holder::Steward {
        admit: true,
        renew: true,
        not_after: NOW + 30 * DAY,
    }
}

// ---------------------------------------------------------------- the holder

#[test]
fn a_node_that_holds_no_steward_key_ignores_and_stores_nothing() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = CertCandidates::new(w.rosters.clone(), w.policies.clone());
    // Not even a refusal: nothing was judged (a certificate that would be refused is Ignored).
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Ignored
    );
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 1), NOW),
        Offer::Ignored
    );
    assert!(store.candidates(w.network).is_empty());
    // A holder of another network is no holder of this one.
    store.set_holder(NetworkId::from([7u8; 32]), Some(steward()), NOW);
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Ignored
    );
    assert!(store.candidates(w.network).is_empty());
}

#[test]
fn a_steward_entry_needs_admit_and_renew_and_a_not_after_ahead() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    for (admit, renew, not_after, recorded) in [
        (true, true, NOW + 1, true),
        (false, true, NOW + DAY, false),
        (true, false, NOW + DAY, false),
        (true, true, NOW, false),
        (true, true, NOW - 1, false),
    ] {
        let store = CertCandidates::new(w.rosters.clone(), w.policies.clone());
        store.set_holder(
            w.network,
            Some(Holder::Steward {
                admit,
                renew,
                not_after,
            }),
            NOW,
        );
        let offer = store.offer(&w.from(&m), &renewal(&m, 2), NOW);
        assert_eq!(
            offer == Offer::Recorded,
            recorded,
            "admit {admit} renew {renew} not_after {not_after}: {offer:?}"
        );
        assert_eq!(store.candidates(w.network).len(), usize::from(recorded));
        if !recorded {
            assert_eq!(offer, Offer::Ignored);
        }
    }
}

#[test]
fn the_owner_notes_a_newer_certificate_once_per_member_and_stores_nothing() {
    let (m, n) = (member(1), member(2));
    let w = World::new(&m, 1, &[1]);
    w.set_roster(2, |roster| {
        roster.members = vec![
            RosterMember {
                node_id: m.id,
                min_serial: 1,
            },
            RosterMember {
                node_id: n.id,
                min_serial: 1,
            },
        ];
    });
    let store = CertCandidates::new(w.rosters.clone(), w.policies.clone());
    store.set_holder(w.network, Some(Holder::Owner), NOW);
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Noted,
        "the line is written"
    );
    assert!(store.candidates(w.network).is_empty());
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Ignored,
        "once per member"
    );
    assert_eq!(
        store.offer(&w.from(&n), &renewal(&n, 2), NOW),
        Offer::Noted,
        "the next member has its own line"
    );
    // It is still judged: a certificate that fails a check is refused, not noted.
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 1), NOW),
        Offer::Refused(Refusal::Replay)
    );
}

#[test]
fn the_owner_says_nothing_when_a_steward_is_listed() {
    use menzil_proto::{Steward, StewardBody, StewardKey};
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let entry = Steward::sign(
        &w.owner,
        &StewardBody {
            v: PROTOCOL_VERSION,
            network_id: w.network,
            steward_pub: StewardKey::from([5u8; 32]),
            may: vec!["admit".to_string(), "renew".to_string()],
            not_after: NOW + 30 * DAY,
        },
    )
    .unwrap();
    w.set_roster(2, |roster| {
        roster.members = vec![RosterMember {
            node_id: m.id,
            min_serial: 1,
        }];
        roster.stewards = vec![entry];
    });
    let store = CertCandidates::new(w.rosters.clone(), w.policies.clone());
    store.set_holder(w.network, Some(Holder::Owner), NOW);
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Ignored,
        "the steward takes it from here"
    );
    assert!(store.candidates(w.network).is_empty());
}

#[test]
fn dropping_the_holder_drops_its_candidates() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Recorded
    );
    store.set_holder(w.network, None, NOW);
    assert!(store.candidates(w.network).is_empty());
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 3), NOW),
        Offer::Ignored
    );
}

// ---------------------------------------------------------------- the checks

#[test]
fn a_valid_renewal_is_recorded_for_the_member() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    let cert = renewal(&m, 2);
    assert_eq!(store.offer(&w.from(&m), &cert, NOW), Offer::Recorded);
    assert_eq!(store.candidates(w.network), vec![cert]);
    // Another network has none.
    assert!(store.candidates(NetworkId::from([9u8; 32])).is_empty());
}

#[test]
fn a_certificate_whose_node_id_is_not_the_session_peer_is_refused() {
    let (m, other) = (member(1), member(2));
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    // `other` signs a perfectly good certificate of its own and pushes it on m's session.
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&other, 2), NOW),
        Offer::Refused(Refusal::NotThePeer)
    );
    // And the same certificate on a session whose peer is `other` (who is no member) is refused
    // for that.
    assert_eq!(
        store.offer(&w.from(&other), &renewal(&other, 2), NOW),
        Offer::Refused(Refusal::NotAMember)
    );
    assert!(store.candidates(w.network).is_empty());
}

#[test]
fn a_peer_that_is_not_an_unrevoked_roster_member_is_refused() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    // Listed in the Policy, not in the Roster.
    w.set_roster(2, |roster| roster.members.clear());
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Refused(Refusal::NotAMember)
    );
    // In the Roster and revoked.
    w.set_roster(3, |roster| {
        roster.members = vec![RosterMember {
            node_id: m.id,
            min_serial: 1,
        }];
        roster.revoked = vec![RevokedMember {
            node_id: m.id,
            since: 0,
        }];
    });
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Refused(Refusal::NotAMember)
    );
    // No Roster at all for the network.
    let empty = CertCandidates::new(Arc::new(RosterStore::new()), w.policies.clone());
    empty.set_holder(w.network, Some(steward()), NOW);
    assert_eq!(
        empty.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Refused(Refusal::NotAMember)
    );
    assert!(store.candidates(w.network).is_empty());
}

#[test]
fn a_certificate_for_another_static_key_than_the_sessions_is_refused() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    // m signed a certificate binding its NodeId to some other X25519 key; the session's static
    // key is m.x25519.
    let other_key = X25519PublicKey::from([0x55; 32]);
    let moved = cert_for_key(&m, other_key, 2, NOW - DAY, NOW + 300 * DAY);
    assert_eq!(
        store.offer(&w.from(&m), &moved, NOW),
        Offer::Refused(Refusal::WrongStaticKey)
    );
    // The same certificate on a session whose static key it names is judged further. The
    // Policy lists serial 1 with m's own key, so the new key is refused as such...
    let session = Offerer {
        peer_static: other_key,
        ..w.from(&m)
    };
    assert_eq!(
        store.offer(&session, &moved, NOW),
        Offer::Refused(Refusal::NewKey)
    );
    // ...while a Policy that lists no certificate of the node leaves the key to the session,
    // which shows the session key is what the WrongStaticKey check above stopped.
    let w = World::new(&m, 1, &[]);
    let store = w.store();
    assert_eq!(store.offer(&session, &moved, NOW), Offer::Recorded);
}

#[test]
fn a_certificate_not_signed_by_its_node_id_is_refused() {
    let (m, thief) = (member(1), member(2));
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    // The body names m, the signature is another key's.
    let body = NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id: m.id,
        x25519_pub: m.x25519,
        serial: 2,
        not_before: NOW - DAY,
        not_after: NOW + 300 * DAY,
    };
    let forged = NodeCert::sign(&thief.signing, &body).unwrap();
    assert_eq!(
        store.offer(&w.from(&m), &forged, NOW),
        Offer::Refused(Refusal::BadSignature)
    );
    // A body edited after signing breaks the signature too.
    let tampered = with_body_of(&renewal(&m, 2), &renewal(&m, 9));
    assert_eq!(
        store.offer(&w.from(&m), &tampered, NOW),
        Offer::Refused(Refusal::BadSignature)
    );
    assert!(store.candidates(w.network).is_empty());
}

#[test]
fn an_expired_or_not_yet_valid_certificate_is_refused() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    let expired = cert(&m, 2, NOW - 200 * DAY, NOW - 1);
    assert_eq!(
        store.offer(&w.from(&m), &expired, NOW),
        Offer::Refused(Refusal::NotValidNow)
    );
    let future = cert(&m, 2, NOW + 1, NOW + 300 * DAY);
    assert_eq!(
        store.offer(&w.from(&m), &future, NOW),
        Offer::Refused(Refusal::NotValidNow)
    );
    // The edges of the window are inside it.
    let first = cert(&m, 2, NOW, NOW + 300 * DAY);
    assert_eq!(store.offer(&w.from(&m), &first, NOW), Offer::Recorded);
    let last = cert(&m, 3, NOW - 300 * DAY, NOW);
    assert_eq!(store.offer(&w.from(&m), &last, NOW), Offer::Recorded);
}

#[test]
fn a_window_over_400_days_is_refused_and_exactly_400_is_not() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    let exact = cert(&m, 2, NOW - DAY, NOW - DAY + NODE_CERT_MAX_LIFETIME);
    assert_eq!(store.offer(&w.from(&m), &exact, NOW), Offer::Recorded);
    let over = cert(&m, 3, NOW - DAY, NOW - DAY + NODE_CERT_MAX_LIFETIME + 1);
    assert_eq!(
        store.offer(&w.from(&m), &over, NOW),
        Offer::Refused(Refusal::WindowTooLong)
    );
    // A window that ends before it starts is no window.
    let backwards = cert(&m, 3, NOW + DAY, NOW - 1);
    assert_eq!(
        store.offer(&w.from(&m), &backwards, NOW),
        Offer::Refused(Refusal::NotValidNow)
    );
    // The test fixtures' own 4,000,000,000 second windows are over the bound.
    let fixture = cert(&m, 3, 0, 4_000_000_000);
    assert_eq!(
        store.offer(&w.from(&m), &fixture, NOW),
        Offer::Refused(Refusal::WindowTooLong)
    );
}

#[test]
fn a_replayed_certificate_is_refused_whatever_the_source_of_the_serial() {
    let m = member(1);
    // Listed by the Policy at 2.
    let w = World::new(&m, 1, &[1, 2]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Refused(Refusal::Replay),
        "the Policy lists serial 2"
    );
    // The Roster floor.
    let w = World::new(&m, 4, &[]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 4), NOW),
        Offer::Refused(Refusal::Replay),
        "min_serial is 4"
    );
    // The candidate already stored.
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 3), NOW),
        Offer::Recorded
    );
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 3), NOW),
        Offer::Refused(Refusal::Replay),
        "the same candidate again"
    );
    assert_eq!(store.candidates(w.network).len(), 1);
}

#[test]
fn an_older_certificate_is_refused_as_a_rollback_whatever_the_source_of_the_serial() {
    let m = member(1);
    // Policy lists 5, the Roster floor is 2, nothing stored: the Policy is the highest.
    let w = World::new(&m, 2, &[3, 5]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 4), NOW),
        Offer::Refused(Refusal::Rollback),
        "below the Policy's 5"
    );
    // Roster floor 6 is the highest, the Policy lists 3.
    let w = World::new(&m, 6, &[3]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 5), NOW),
        Offer::Refused(Refusal::Rollback),
        "below min_serial 6"
    );
    // A stored candidate at 9 is the highest.
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 9), NOW),
        Offer::Recorded
    );
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 8), NOW),
        Offer::Refused(Refusal::Rollback),
        "below the candidate's 9"
    );
    assert_eq!(
        store.candidates(w.network),
        vec![renewal(&m, 9)],
        "the stored one is untouched"
    );
}

#[test]
fn the_serial_must_beat_the_roster_floor_by_more_than_nothing() {
    let m = member(1);
    let w = World::new(&m, 3, &[3]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 3), NOW),
        Offer::Refused(Refusal::Replay)
    );
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 4), NOW),
        Offer::Recorded
    );
}

#[test]
fn a_higher_serial_replaces_the_candidate() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Recorded
    );
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 4), NOW),
        Offer::Recorded
    );
    assert_eq!(store.candidates(w.network), vec![renewal(&m, 4)]);
    // Still one per member.
    assert_eq!(store.candidates(w.network).len(), 1);
}

#[test]
fn a_candidate_is_dropped_once_the_policy_lists_its_serial_or_a_higher_one() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 3), NOW),
        Offer::Recorded
    );
    // A Policy that lists serial 2 does not make the candidate at 3 moot.
    w.set_policy(2, &m, &[1, 2]);
    assert_eq!(store.candidates(w.network), vec![renewal(&m, 3)]);
    // One that lists 3 does.
    w.set_policy(3, &m, &[3]);
    assert!(store.candidates(w.network).is_empty());

    // And a higher serial listed drops it too.
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    store.offer(&w.from(&m), &renewal(&m, 3), NOW);
    w.set_policy(2, &m, &[4]);
    assert!(store.candidates(w.network).is_empty());
}

#[test]
fn a_candidate_dropped_as_listed_is_not_offered_again() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    store.offer(&w.from(&m), &renewal(&m, 3), NOW);
    w.set_policy(2, &m, &[3]);
    assert!(store.candidates(w.network).is_empty());
    // The listed serial is the floor now: the same certificate is a replay.
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 3), NOW),
        Offer::Refused(Refusal::Replay)
    );
}

#[test]
fn candidates_are_kept_per_member_and_network() {
    let (a, b) = (member(1), member(2));
    let w = World::new(&a, 1, &[1]);
    w.set_roster(2, |roster| {
        roster.members = vec![
            RosterMember {
                node_id: a.id,
                min_serial: 1,
            },
            RosterMember {
                node_id: b.id,
                min_serial: 1,
            },
        ];
    });
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&a), &renewal(&a, 2), NOW),
        Offer::Recorded
    );
    assert_eq!(
        store.offer(&w.from(&b), &renewal(&b, 2), NOW),
        Offer::Recorded
    );
    let mut got = store.candidates(w.network);
    got.sort_by_key(|c| <[u8; 32]>::from(c.decode().unwrap().node_id));
    let mut want = vec![renewal(&a, 2), renewal(&b, 2)];
    want.sort_by_key(|c| <[u8; 32]>::from(c.decode().unwrap().node_id));
    assert_eq!(got, want);
}

// ---------------------------------------------------------------- round B: L1, L2

#[test]
fn a_new_key_certificate_is_refused_and_does_not_shadow_the_real_renewal() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    // The hostile one: serial far above, a key the Policy never listed, on a session that
    // presents that key.
    let hostile_key = X25519PublicKey::from([0x66; 32]);
    let hostile = cert_for_key(&m, hostile_key, u32::MAX, NOW - DAY, NOW + 300 * DAY);
    let session = Offerer {
        peer_static: hostile_key,
        ..w.from(&m)
    };
    assert_eq!(
        store.offer(&session, &hostile, NOW),
        Offer::Refused(Refusal::NewKey)
    );
    assert!(store.candidates(w.network).is_empty());
    // The legitimate same key renewal that follows is not shadowed by it.
    let legit = renewal(&m, 2);
    assert_eq!(store.offer(&w.from(&m), &legit, NOW), Offer::Recorded);
    assert_eq!(store.candidates(w.network), vec![legit]);
}

#[test]
fn the_key_is_compared_with_the_highest_listed_certificate() {
    let m = member(1);
    let w = World::new(&m, 1, &[]);
    // The Policy lists serial 1 with another key and serial 2 with m's key: the highest wins.
    let old_key = X25519PublicKey::from([0x55; 32]);
    let body = |serial, key| NodeCertBody {
        v: PROTOCOL_VERSION,
        node_id: m.id,
        x25519_pub: key,
        serial,
        not_before: NOW - DAY,
        not_after: NOW + 300 * DAY,
    };
    let listed = [
        NodeCert::sign(&m.signing, &body(1, old_key)).unwrap(),
        NodeCert::sign(&m.signing, &body(2, m.x25519)).unwrap(),
    ];
    let policy = PolicyBody {
        v: PROTOCOL_VERSION,
        network_id: w.network,
        seq: 2,
        issued: NOW - DAY,
        expires: NOW + 10 * DAY,
        members: vec![PolicyMember {
            node_id: m.id,
            name: "node".to_string(),
            roles: vec![],
        }],
        certs: listed.to_vec(),
        grants: vec![],
        egress: vec![],
        accept: vec![],
    };
    w.policies
        .set(&Policy::sign(&w.owner, &policy).unwrap())
        .unwrap();
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 3), NOW),
        Offer::Recorded,
        "m's key is the key of the highest listed certificate"
    );
}

#[test]
fn a_candidate_is_dropped_when_its_member_is_revoked_or_removed() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Recorded
    );
    assert_eq!(store.candidates(w.network).len(), 1);
    // Revoked.
    w.set_roster(2, |roster| {
        roster.members = vec![RosterMember {
            node_id: m.id,
            min_serial: 1,
        }];
        roster.revoked = vec![RevokedMember {
            node_id: m.id,
            since: 0,
        }];
    });
    assert!(store.candidates(w.network).is_empty());
    assert!(
        store.lock().candidates.is_empty(),
        "the entry is freed, not only hidden"
    );

    // Removed from the Roster.
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    store.offer(&w.from(&m), &renewal(&m, 2), NOW);
    w.set_roster(2, |roster| roster.members.clear());
    assert!(store.candidates(w.network).is_empty());
    assert!(store.lock().candidates.is_empty());
}

#[test]
fn a_candidate_below_a_raised_min_serial_is_dropped_and_one_at_it_is_kept() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Recorded
    );
    // A floor equal to the candidate's serial still admits it.
    w.set_roster(2, |roster| {
        roster.members = vec![RosterMember {
            node_id: m.id,
            min_serial: 2,
        }];
    });
    assert_eq!(store.candidates(w.network), vec![renewal(&m, 2)]);
    // A floor above it does not.
    w.set_roster(3, |roster| {
        roster.members = vec![RosterMember {
            node_id: m.id,
            min_serial: 9,
        }];
    });
    assert!(store.candidates(w.network).is_empty());
    assert!(store.lock().candidates.is_empty());
}

#[test]
fn a_holder_that_cannot_use_candidates_clears_the_networks_candidates() {
    let m = member(1);
    let other_network = NetworkId::from([7u8; 32]);
    for (name, holder) in [
        ("none", None),
        ("owner", Some(Holder::Owner)),
        (
            "no admit",
            Some(Holder::Steward {
                admit: false,
                renew: true,
                not_after: NOW + DAY,
            }),
        ),
        (
            "no renew",
            Some(Holder::Steward {
                admit: true,
                renew: false,
                not_after: NOW + DAY,
            }),
        ),
        (
            "not_after passed",
            Some(Holder::Steward {
                admit: true,
                renew: true,
                not_after: NOW,
            }),
        ),
    ] {
        let w = World::new(&m, 1, &[1]);
        let store = w.store();
        assert_eq!(
            store.offer(&w.from(&m), &renewal(&m, 2), NOW),
            Offer::Recorded,
            "{name}"
        );
        // A change of another network's holder leaves this one alone.
        store.set_holder(other_network, holder, NOW);
        assert_eq!(store.candidates(w.network).len(), 1, "{name}");
        store.set_holder(w.network, holder, NOW);
        assert!(store.lock().candidates.is_empty(), "{name}");
        assert!(store.candidates(w.network).is_empty(), "{name}");
    }
}

#[test]
fn a_holder_that_still_uses_candidates_keeps_them() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    store.offer(&w.from(&m), &renewal(&m, 2), NOW);
    // A steward entry with a later not_after is a changed entry, not a lost one.
    store.set_holder(
        w.network,
        Some(Holder::Steward {
            admit: true,
            renew: true,
            not_after: NOW + 90 * DAY,
        }),
        NOW,
    );
    assert_eq!(store.candidates(w.network), vec![renewal(&m, 2)]);
}

#[test]
fn a_steward_entry_that_lapses_between_offers_drops_the_candidates() {
    let m = member(1);
    let w = World::new(&m, 1, &[1]);
    let store = w.store();
    assert_eq!(
        store.offer(&w.from(&m), &renewal(&m, 2), NOW),
        Offer::Recorded
    );
    // The entry's not_after is NOW + 30 days; a push 31 days on finds it ended.
    let later = NOW + 31 * DAY;
    let cert = cert(&m, 3, later - DAY, later + 300 * DAY);
    assert_eq!(store.offer(&w.from(&m), &cert, later), Offer::Ignored);
    assert!(store.lock().candidates.is_empty());
}
