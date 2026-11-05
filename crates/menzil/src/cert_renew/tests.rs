use menzil_admin::{NodeKeys, OwnerKey, admit, create_network, revoke};
use menzil_proto::NodeCert;

use super::*;

const NOW: u64 = 1_800_000_000;

// ---- renew_due ----

#[test]
fn a_node_renews_when_its_certificate_expires_within_sixty_days_and_not_before() {
    let at = |left: i64| NOW.checked_add_signed(left).unwrap();
    // Exactly sixty days left is already due; one second more is not.
    assert!(renew_due(NOW + 60 * DAY, NOW));
    assert!(!renew_due(NOW + 60 * DAY + 1, NOW));
    assert!(renew_due(NOW + 60 * DAY - 1, NOW));
    // Long valid, nearly out, out on this very second, long out.
    assert!(!renew_due(NOW + 399 * DAY, NOW));
    assert!(renew_due(NOW + 1, NOW));
    assert!(renew_due(NOW, NOW));
    assert!(renew_due(at(-1), NOW));
    assert!(renew_due(0, NOW));
}

#[test]
fn the_renewal_threshold_is_sixty_days_and_the_check_runs_every_six_hours() {
    assert_eq!(RENEW_WITHIN, 60 * 24 * 60 * 60);
    assert_eq!(WARN_WITHIN, 30 * 24 * 60 * 60);
    assert_eq!(CHECK_EVERY_SECS, 6 * 60 * 60);
    assert_eq!(ROTATE_MIN_EXTENSION, 30 * 24 * 60 * 60);
    assert_eq!(ROTATE_EVERY, 60 * 60);
}

// ---- what a Policy lists ----

/// An owner's network of `members` nodes, all with a serial 1 certificate that expires in 20
/// days (so a renewal of 400 days is far beyond the 30 day rule).
struct World {
    owner: OwnerKey,
    keys: Vec<NodeKeys>,
    docs: Documents,
}

fn cert_of(keys: &NodeKeys, serial: u32, not_before: u64, not_after: u64) -> NodeCert {
    keys.issue_cert(serial, not_before, not_after).unwrap()
}

fn world(members: usize) -> World {
    let owner = OwnerKey::generate();
    let keys: Vec<NodeKeys> = (0..members).map(|_| NodeKeys::generate()).collect();
    let first = cert_of(&keys[0], 1, NOW - 380 * DAY, NOW + 20 * DAY);
    let mut docs = create_network(&owner, &first, "node0", NOW).unwrap();
    for (n, member) in keys.iter().enumerate().skip(1) {
        let cert = cert_of(member, 1, NOW - 380 * DAY, NOW + 20 * DAY);
        docs = admit(&owner, &docs, &cert, &format!("node{n}"), &[], NOW).unwrap();
    }
    World { owner, keys, docs }
}

/// A renewal of `keys`' certificate whose `not_after` is `extension` after the listed one
/// (`NOW + 20 days`), valid since a day ago.
fn renewal(keys: &NodeKeys, serial: u32, extension: u64) -> NodeCert {
    cert_of(keys, serial, NOW - DAY, NOW + 20 * DAY + extension)
}

fn plan(world: &World, candidates: &[NodeCert]) -> Vec<NodeCert> {
    rotation_plan(candidates, &world.docs, None, NOW)
}

#[test]
fn listed_certs_are_read_by_rank_and_the_max_is_taken_across_policies() {
    let w = world(2);
    let id = w.keys[0].node_id();
    let body = w.docs.policy_body();
    assert_eq!(
        listed_cert(body, &id),
        Some(Listed {
            serial: 1,
            not_after: NOW + 20 * DAY
        })
    );
    assert_eq!(listed_cert(body, &NodeId::from([9u8; 32])), None);

    // A Policy that lists two certificates of the node (a base cert and a steward's tail one):
    // the higher serial wins whatever the order.
    let mut two = body.clone();
    two.certs.push(renewal(&w.keys[0], 3, 300 * DAY));
    two.certs.push(renewal(&w.keys[0], 2, 100 * DAY));
    let listed = listed_cert(&two, &id).unwrap();
    assert_eq!(listed.serial, 3);
    assert_eq!(listed_max_serial([body, &two], &id), Some(3));
    assert_eq!(listed_max_serial([body], &id), Some(1));
    assert_eq!(listed_max_serial([body], &NodeId::from([9u8; 32])), None);
    assert_eq!(listed_max_serial(std::iter::empty(), &id), None);
}

// ---- unlisted_days / warn_due ----

fn listed(serial: u32, left: u64) -> Option<Listed> {
    Some(Listed {
        serial,
        not_after: NOW + left,
    })
}

#[test]
fn a_network_is_unlisted_only_when_it_lists_an_older_certificate_than_the_current_one() {
    // Lists nothing of this node: not a member there, nothing to say.
    assert_eq!(unlisted_days(None, 2, NOW), None);
    // Lists the current serial, or a newer one: listed.
    assert_eq!(unlisted_days(listed(2, 10 * DAY), 2, NOW), None);
    assert_eq!(unlisted_days(listed(3, 10 * DAY), 2, NOW), None);
    // Lists an older one: whole days left of that one.
    assert_eq!(unlisted_days(listed(1, 10 * DAY), 2, NOW), Some(10));
    assert_eq!(
        unlisted_days(listed(1, 10 * DAY + DAY - 1), 2, NOW),
        Some(10)
    );
    assert_eq!(unlisted_days(listed(1, DAY - 1), 2, NOW), Some(0));
    // An expired listed certificate is 0 days, not a wrapped number.
    assert_eq!(
        unlisted_days(
            Some(Listed {
                serial: 1,
                not_after: NOW - 5
            }),
            2,
            NOW
        ),
        Some(0)
    );
}

#[test]
fn the_log_warns_from_thirty_days_before_the_listed_certificate_expires() {
    assert_eq!(warn_due(listed(1, 30 * DAY), 2, NOW), Some(30));
    assert_eq!(warn_due(listed(1, 30 * DAY + 1), 2, NOW), None);
    assert_eq!(warn_due(listed(1, 30 * DAY - 1), 2, NOW), Some(29));
    assert_eq!(warn_due(listed(1, 3 * DAY), 2, NOW), Some(3));
    assert_eq!(
        warn_due(
            Some(Listed {
                serial: 1,
                not_after: NOW - 1
            }),
            2,
            NOW
        ),
        Some(0),
        "expired is the loudest case"
    );
    // The current certificate is listed (or nothing is): nothing to warn about, however near.
    assert_eq!(warn_due(listed(2, 3 * DAY), 2, NOW), None);
    assert_eq!(warn_due(None, 2, NOW), None);
    // Far from expiry the status shows it, the log does not warn.
    assert_eq!(unlisted_days(listed(1, 200 * DAY), 2, NOW), Some(200));
    assert_eq!(warn_due(listed(1, 200 * DAY), 2, NOW), None);
}

// ---- rotation_plan ----

#[test]
fn a_renewal_that_extends_the_listed_expiry_by_thirty_days_is_listed() {
    let w = world(1);
    let good = renewal(&w.keys[0], 2, 30 * DAY);
    assert_eq!(plan(&w, std::slice::from_ref(&good)), vec![good.clone()]);
    // One second short of the 30 days is not.
    let short = renewal(&w.keys[0], 2, 30 * DAY - 1);
    assert!(plan(&w, &[short]).is_empty());
    // A full 400 day renewal is.
    let full = cert_of(&w.keys[0], 2, NOW - DAY, NOW - DAY + 400 * DAY);
    assert_eq!(plan(&w, std::slice::from_ref(&full)), vec![full]);
}

#[test]
fn a_renewal_must_beat_the_serial_and_keep_the_key() {
    let w = world(1);
    // Equal serial, lower serial.
    assert!(plan(&w, &[renewal(&w.keys[0], 1, 100 * DAY)]).is_empty());
    assert!(plan(&w, &[renewal(&w.keys[0], 0, 100 * DAY)]).is_empty());
    // The same node id under another Noise key is a new identity, not a renewal.
    let mut secret = w.keys[0].secret_bytes();
    secret[32] ^= 0xff;
    let rekeyed = NodeKeys::from_secret_bytes(&secret).unwrap();
    assert_eq!(rekeyed.node_id(), w.keys[0].node_id());
    assert_ne!(rekeyed.x25519_public(), w.keys[0].x25519_public());
    assert!(plan(&w, &[renewal(&rekeyed, 2, 100 * DAY)]).is_empty());
    // And against a tail cert already listed: the serial must beat that one too.
    let mut listed = w.docs.clone();
    let tail = renewal(&w.keys[0], 2, 100 * DAY);
    let next = menzil_admin::accept_cert(&w.owner, &listed, &tail, NOW).unwrap();
    listed = next;
    let world = World {
        owner: w.owner.clone(),
        keys: w.keys.clone(),
        docs: listed,
    };
    assert!(plan(&world, std::slice::from_ref(&tail)).is_empty());
    let higher = cert_of(&w.keys[0], 3, NOW - DAY, NOW - DAY + 400 * DAY);
    assert_eq!(plan(&world, std::slice::from_ref(&higher)), vec![higher]);
    // 30 days beyond the *listed* tail (not the base) is the bar.
    let barely = cert_of(
        &w.keys[0],
        3,
        NOW - DAY,
        NOW + 20 * DAY + 100 * DAY + 29 * DAY,
    );
    assert!(plan(&world, &[barely]).is_empty());
}

#[test]
fn only_members_and_never_revoked_ones_are_listed() {
    let w = world(2);
    let stranger = NodeKeys::generate();
    assert!(plan(&w, &[renewal(&stranger, 2, 100 * DAY)]).is_empty());
    let gone = revoke(&w.owner, &w.docs, w.keys[1].node_id(), NOW).unwrap();
    let world = World {
        owner: w.owner.clone(),
        keys: w.keys.clone(),
        docs: gone,
    };
    assert!(plan(&world, &[renewal(&w.keys[1], 2, 100 * DAY)]).is_empty());
    // The other member still qualifies.
    let ok = renewal(&w.keys[0], 2, 100 * DAY);
    assert_eq!(plan(&world, std::slice::from_ref(&ok)), vec![ok]);
}

#[test]
fn a_certificate_the_issuer_would_refuse_is_left_out_so_it_cannot_block_the_batch() {
    let w = world(1);
    let keys = &w.keys[0];
    let good = renewal(keys, 2, 100 * DAY);
    // A damaged signature.
    let mut bytes = good.encode();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    if let Ok(damaged) = NodeCert::decode_strict(&bytes) {
        assert!(damaged.decode().is_ok());
        assert!(plan(&w, &[damaged]).is_empty());
    }
    // Not valid yet; valid for less than the issue margin; exactly the margin; expired.
    let starting = cert_of(keys, 2, NOW + 10, NOW + 300 * DAY);
    assert!(plan(&w, &[starting]).is_empty());
    let fresh = cert_of(keys, 2, NOW - CERT_ISSUE_MARGIN_SECS + 1, NOW + 300 * DAY);
    assert!(plan(&w, &[fresh]).is_empty());
    let margin = cert_of(keys, 2, NOW - CERT_ISSUE_MARGIN_SECS, NOW + 300 * DAY);
    assert_eq!(plan(&w, std::slice::from_ref(&margin)), vec![margin]);
    let expired = cert_of(keys, 2, NOW - 100 * DAY, NOW - 1);
    assert!(plan(&w, &[expired]).is_empty());
    // Garbage that does not decode.
    let junk = NodeCert::decode_strict(&[0u8; 3]);
    assert!(junk.is_err());
}

#[test]
fn a_rotation_pair_is_made_once_an_hour() {
    let w = world(1);
    let good = renewal(&w.keys[0], 2, 100 * DAY);
    let at = |last: Option<u64>| rotation_plan(std::slice::from_ref(&good), &w.docs, last, NOW);
    assert!(at(Some(NOW)).is_empty());
    assert!(at(Some(NOW - ROTATE_EVERY + 1)).is_empty());
    assert_eq!(at(Some(NOW - ROTATE_EVERY)).len(), 1);
    assert_eq!(at(None).len(), 1);
    // A last time ahead of the clock (it was wrong once) does not stop the rotations.
    assert_eq!(at(Some(NOW + 5)).len(), 1);
    assert_eq!(at(Some(NOW + 10 * DAY)).len(), 1);
}

#[test]
fn the_highest_serial_per_node_goes_in_and_the_order_is_by_node_id() {
    let w = world(3);
    let mut candidates = Vec::new();
    let mut expected = Vec::new();
    for keys in &w.keys {
        let low = renewal(keys, 2, 100 * DAY);
        let high = renewal(keys, 5, 100 * DAY);
        candidates.push(high.clone());
        candidates.push(low);
        expected.push((keys.node_id(), high));
    }
    candidates.reverse();
    expected.sort_by_key(|(id, _)| <[u8; 32]>::from(*id));
    let planned = plan(&w, &candidates);
    assert_eq!(
        planned,
        expected.into_iter().map(|(_, c)| c).collect::<Vec<_>>()
    );
    // The pair they make passes the issuer's own checks, so the plan and the operation agree.
    let secret = menzil_admin::StewardSecret::generate();
    let listed = menzil_admin::delegate_steward(
        &w.owner,
        &w.docs,
        secret.public(),
        &["admit".to_string(), "renew".to_string()],
        NOW + 30 * DAY,
        NOW,
    )
    .unwrap();
    let rotated = menzil_admin::steward_rotate(&secret, &listed, &planned, NOW + 1).unwrap();
    assert_eq!(rotated.policy_body().certs.len(), 3 + 3);
}
