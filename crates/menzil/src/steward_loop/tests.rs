use std::collections::HashMap;
use std::sync::RwLock;

use super::*;
use crate::local::{
    admit, init, join, network_create, steward_add, steward_remove, steward_request,
};
use crate::node_cmd::{Directory, load_stores, reload_adopting};
use menzil_node::Adopted;
use menzil_proto::trust::Signer;

const DAY: u64 = 24 * 60 * 60;
const NOW: u64 = 1_800_000_000;

fn key() -> StewardKey {
    StewardKey::from([1u8; 32])
}

/// Facts of a pair that expires at `expires`, with an entry for [`key`].
fn facts(expires: u64, not_after: u64, may_renew: bool) -> Facts {
    Facts {
        seq: 5,
        expires,
        entry: Some(EntryFacts {
            key: key(),
            may_renew,
            not_after,
        }),
    }
}

fn plan(now: u64, facts: &Facts) -> Plan {
    decide(now, Some(key()), Some(facts))
}

// ---- the pure rules ----

#[test]
fn it_renews_when_the_pair_expires_within_seven_days_and_not_when_later() {
    let not_after = NOW + 80 * DAY;
    assert!(plan(NOW, &facts(NOW + 7 * DAY, not_after, true)).renew);
    assert!(!plan(NOW, &facts(NOW + 7 * DAY + 1, not_after, true)).renew);
    // Long expired is the case that matters most.
    assert!(plan(NOW, &facts(NOW - 3 * DAY, not_after, true)).renew);
    assert!(plan(NOW, &facts(0, not_after, true)).renew);
}

#[test]
fn it_never_renews_at_or_after_not_after() {
    let held = facts(NOW - 5, NOW + 1, true);
    assert!(plan(NOW, &held).renew, "one second of the entry is left");
    let held = facts(NOW - 5, NOW, true);
    let answer = plan(NOW, &held);
    assert!(!answer.renew);
    assert_eq!(answer.warning, Some(Warning::Ended));
    assert!(!plan(NOW + 1, &facts(NOW - 5, NOW, true)).renew);
}

#[test]
fn it_never_renews_without_the_right_renew() {
    let answer = plan(NOW, &facts(NOW + DAY, NOW + 80 * DAY, false));
    assert!(!answer.renew);
    assert_eq!(answer.warning, Some(Warning::LacksRenew));
}

#[test]
fn it_never_renews_when_the_held_documents_do_not_list_this_key() {
    let mut held = facts(NOW + DAY, NOW + 80 * DAY, true);
    held.entry.as_mut().unwrap().key = StewardKey::from([2u8; 32]);
    let answer = plan(NOW, &held);
    assert!(!answer.renew);
    assert_eq!(answer.warning, Some(Warning::NotListed));
    held.entry = None;
    let answer = plan(NOW, &held);
    assert!(!answer.renew);
    assert_eq!(answer.warning, Some(Warning::NotListed));
}

#[test]
fn it_does_nothing_without_a_key_or_without_documents() {
    let held = facts(NOW + DAY, NOW + 80 * DAY, true);
    assert_eq!(decide(NOW, None, Some(&held)), Plan::default());
    assert_eq!(decide(NOW, Some(key()), None), Plan::default());
}

#[test]
fn it_warns_from_fourteen_days_before_not_after() {
    let held = |not_after| facts(NOW + 12 * DAY, not_after, true);
    assert_eq!(
        plan(NOW, &held(NOW + 14 * DAY)).warning,
        Some(Warning::EndsSoon { days: 14 })
    );
    assert_eq!(plan(NOW, &held(NOW + 14 * DAY + 1)).warning, None);
    assert_eq!(
        plan(NOW, &held(NOW + 3 * DAY + 5)).warning,
        Some(Warning::EndsSoon { days: 3 })
    );
    // Not renewing and warning are independent: here both.
    let near = facts(NOW + DAY, NOW + 10 * DAY, true);
    let answer = plan(NOW, &near);
    assert!(answer.renew);
    assert_eq!(answer.warning, Some(Warning::EndsSoon { days: 10 }));
}

#[test]
fn an_ended_entry_that_also_lacks_renew_says_ended() {
    let answer = plan(NOW, &facts(NOW, NOW - 1, false));
    assert_eq!(answer.warning, Some(Warning::Ended));
}

#[test]
fn a_pair_cut_short_by_not_after_is_not_signed_again() {
    // The pair already ends where the entry does: a renewal would only burn a `seq`.
    let not_after = NOW + 2 * DAY;
    assert!(!plan(NOW, &facts(not_after, not_after, true)).renew);
    assert!(plan(NOW, &facts(not_after - 1, not_after, true)).renew);
}

#[test]
fn a_renewal_lasts_fourteen_days_or_until_not_after() {
    assert_eq!(renewed_expires(NOW, NOW + 20 * DAY), NOW + 14 * DAY);
    assert_eq!(renewed_expires(NOW, NOW + 14 * DAY), NOW + 14 * DAY);
    assert_eq!(renewed_expires(NOW, NOW + 3 * DAY), NOW + 3 * DAY);
}

#[test]
fn a_network_is_looked_at_once_an_hour_or_when_its_seq_changes() {
    let seen = Some(Tick {
        at: NOW,
        seq: Some(5),
    });
    assert!(tick_due(None, NOW, 5));
    assert!(!tick_due(seen, NOW, 5));
    assert!(!tick_due(seen, NOW + TICK_SECS - 1, 5));
    assert!(tick_due(seen, NOW + TICK_SECS, 5));
    assert!(tick_due(seen, NOW + 1, 6), "documents arrived");
    // A failed look that never read the seq is not made due by one.
    let failed = Some(Tick { at: NOW, seq: None });
    assert!(!tick_due(failed, NOW + 1, 6));
    assert!(tick_due(failed, NOW + TICK_SECS, 6));
    // A clock that went back is not an hour.
    assert!(!tick_due(seen, NOW - 10, 5));
}

#[test]
fn a_warning_is_repeated_once_a_day() {
    assert!(warn_due(None, NOW));
    assert!(!warn_due(Some(NOW), NOW));
    assert!(!warn_due(Some(NOW), NOW + DAY - 1));
    assert!(warn_due(Some(NOW), NOW + DAY));
    assert!(!warn_due(Some(NOW), NOW - 10));
}

// ---- the wiring over real documents ----

/// The real clock: what the stores adopt is judged against it, like in `node_cmd`'s tests.
fn clock() -> u64 {
    static BASE: std::sync::LazyLock<u64> = std::sync::LazyLock::new(unix_now);
    *BASE
}

struct Fixture {
    _dirs: Vec<tempfile::TempDir>,
    owner: Home,
    steward: Home,
    id: NetworkId,
}

/// An owner, and a steward device that is a member and holds the owner's pair (`seq` 3) that
/// lists its key for 30 days with `may`.
fn fixture(may: &[&str]) -> Fixture {
    let owner_dir = tempfile::tempdir().unwrap();
    let owner = Home::new(owner_dir.path());
    init(&owner, clock()).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let steward_dir = tempfile::tempdir().unwrap();
    let steward = Home::new(steward_dir.path());
    let request = init(&steward, clock()).unwrap().join_request;
    let admitted = admit(&owner, None, &request, "steward", &[], clock()).unwrap();
    join(&steward, &admitted.token, clock()).unwrap();
    let asked = steward_request(&steward, None).unwrap();
    let may: Vec<String> = may.iter().map(ToString::to_string).collect();
    let listed = steward_add(&owner, None, &asked.token, &may, 30, clock()).unwrap();
    join(&steward, &listed.issued.token, clock()).unwrap();
    Fixture {
        _dirs: vec![owner_dir, steward_dir],
        owner,
        steward,
        id,
    }
}

fn both() -> Fixture {
    fixture(&["admit", "renew"])
}

#[test]
fn the_facts_come_from_the_owner_signed_roster_behind_the_pair() {
    let f = both();
    let owner_pair = crate::local::load_documents(&f.steward, &f.id).unwrap();
    let facts = Facts::of(&owner_pair).unwrap();
    assert_eq!((facts.seq, facts.expires), (3, clock() + 14 * DAY));
    let entry = facts.entry.unwrap();
    assert_eq!(entry.not_after, clock() + 30 * DAY);
    assert!(entry.may_renew);
    // After the steward signed one, the entry still comes from the base.
    let key = crate::local::load_steward(&f.steward, &f.id).unwrap();
    assert_eq!(entry.key, key.public());
    let renewed = menzil_admin::steward_renew(&key, &owner_pair, clock() + 60).unwrap();
    assert!(renewed.base().is_some());
    let again = Facts::of(&renewed).unwrap();
    assert_eq!(again.seq, 4);
    assert_eq!(again.entry, Some(entry));
    // A steward with only `admit` has no `renew`.
    let g = fixture(&["admit"]);
    let docs = crate::local::load_documents(&g.steward, &g.id).unwrap();
    assert!(!Facts::of(&docs).unwrap().entry.unwrap().may_renew);
}

#[test]
fn a_due_network_is_renewed_written_adopted_and_acceptable_to_a_member() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let (member_policies, member_rosters, _) = load_stores(&f.owner).unwrap();
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Renewed { seq: 4 });
    // On disk, where the CLI keeps it.
    let disk = crate::local::load_documents(&f.steward, &f.id).unwrap();
    assert_eq!(disk.seq(), 4);
    assert_eq!(disk.roster_body().issued, now);
    assert_eq!(disk.roster_body().expires, now + 14 * DAY);
    assert_eq!(disk.base().unwrap().0.decode().unwrap().seq, 3);
    // In the stores, as the steward's.
    assert_eq!(
        (rosters.seq(&f.id), policies.seq(&f.id)),
        (Some(4), Some(4))
    );
    assert!(matches!(
        rosters.signer(&f.id),
        Some(Signer::Steward { base_seq: 3, .. })
    ));
    // A member that holds the owner's pair takes it.
    let adopted = DocStore::new(&member_rosters, &member_policies)
        .adopt(&disk.bundle(), now)
        .unwrap();
    assert_eq!(
        adopted,
        Adopted {
            roster: true,
            policy: true
        }
    );
    // No warning yet (the entry has 22 days left), and no second renewal at once.
    assert_eq!(state.last_warning, None);
    let again = tick_network(&f.steward, &rosters, &policies, &f.id, now + 60, &mut state);
    assert_eq!(again.unwrap(), Outcome::Idle);
    let later = tick_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        now + TICK_SECS,
        &mut state,
    );
    assert_eq!(later.unwrap(), Outcome::Checked);
    assert_eq!(rosters.seq(&f.id), Some(4));
    // The reload that follows finds nothing new, so nothing is pushed twice.
    let mut adopted_from_disk = Vec::new();
    reload_adopting(
        &f.steward,
        &policies,
        &rosters,
        &RwLock::new(Directory::default()),
        &mut HashMap::new(),
        &mut adopted_from_disk,
    )
    .unwrap();
    assert!(adopted_from_disk.is_empty());
}

#[test]
fn nothing_is_renewed_before_the_seven_days() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let mut state = NetState::default();
    let now = clock() + 6 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    assert_eq!(rosters.seq(&f.id), Some(3));
    assert_eq!(
        crate::local::load_documents(&f.steward, &f.id)
            .unwrap()
            .seq(),
        3
    );
    // The boundary itself: expires - now is exactly seven days.
    let now = clock() + 7 * DAY;
    let mut state = NetState::default();
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Renewed { seq: 4 });
}

#[test]
fn a_device_without_a_steward_key_renews_nothing() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    std::fs::remove_file(f.steward.steward_key_path(&f.id)).unwrap();
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Idle);
    assert_eq!(rosters.seq(&f.id), Some(3));
    assert_eq!(
        crate::local::load_documents(&f.steward, &f.id)
            .unwrap()
            .seq(),
        3
    );
}

#[test]
fn a_steward_the_owner_removed_renews_nothing_and_says_so() {
    let f = both();
    let removed = steward_remove(&f.owner, None, clock() + 1).unwrap();
    join(&f.steward, &removed.token, clock() + 1).unwrap();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    assert_eq!(rosters.seq(&f.id), Some(removed.seq));
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    assert_eq!(rosters.seq(&f.id), Some(removed.seq));
    assert_eq!(
        crate::local::load_documents(&f.steward, &f.id)
            .unwrap()
            .seq(),
        removed.seq
    );
    assert_eq!(state.last_warning, Some(now), "it warns");
}

#[test]
fn documents_held_in_memory_that_are_newer_than_the_disk_win() {
    // The owner's pair without the steward reached the node over the relay and was never
    // written to disk; the file still lists the steward. Renewing from the file would sign
    // what the network no longer allows.
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let removed = steward_remove(&f.owner, None, clock() + 1).unwrap();
    let pair = crate::token::decode_documents(&removed.token).unwrap();
    DocStore::new(&rosters, &policies)
        .adopt(&pair.bundle(), clock() + 1)
        .unwrap();
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    assert_eq!(
        crate::local::load_documents(&f.steward, &f.id)
            .unwrap()
            .seq(),
        3
    );
    assert_eq!(rosters.seq(&f.id), Some(removed.seq));
}

#[test]
fn a_steward_that_may_only_admit_does_not_renew() {
    let f = fixture(&["admit"]);
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    assert_eq!(rosters.seq(&f.id), Some(3));
    assert_eq!(state.last_warning, Some(now));
}

#[test]
fn documents_that_ran_out_are_renewed_and_the_warning_repeats_once_a_day() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let mut state = NetState::default();
    // Twenty days on: the pair ran out six days ago, the entry has ten days left.
    let now = clock() + 20 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Renewed { seq: 4 });
    let disk = crate::local::load_documents(&f.steward, &f.id).unwrap();
    assert_eq!(
        disk.roster_body().expires,
        now + 10 * DAY,
        "cut short by not_after"
    );
    assert_eq!(state.last_warning, Some(now));
    // An hour later: looked at, said nothing again.
    let hour = now + TICK_SECS + 1;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, hour, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    assert_eq!(state.last_warning, Some(now));
    // A day later: the same warning again, and still no second renewal (the pair already
    // ends where the entry does, so a renewal would reach no further).
    let day = now + DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, day, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    assert_eq!(state.last_warning, Some(day));
    let late = now + 4 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, late, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    assert_eq!(rosters.seq(&f.id), Some(4));
}

#[test]
fn a_failed_look_waits_for_the_hour_even_when_it_never_read_the_documents() {
    let f = both();
    // Nothing in the stores and a damaged file: there is nothing to read.
    let (policies, rosters) = (PolicyStore::new(), RosterStore::new());
    std::fs::write(f.steward.documents_path(&f.id), b"damaged").unwrap();
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    assert!(tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).is_err());
    let soon = tick_network(&f.steward, &rosters, &policies, &f.id, now + 60, &mut state);
    assert_eq!(soon.unwrap(), Outcome::Idle);
    let hour = now + TICK_SECS;
    assert!(tick_network(&f.steward, &rosters, &policies, &f.id, hour, &mut state).is_err());
}

#[test]
fn a_failure_after_the_documents_were_read_waits_for_the_hour() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    std::fs::write(f.steward.steward_key_path(&f.id), b"damaged").unwrap();
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    assert!(tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).is_err());
    let soon = tick_network(&f.steward, &rosters, &policies, &f.id, now + 60, &mut state);
    assert_eq!(soon.unwrap(), Outcome::Idle);
    assert!(
        tick_network(
            &f.steward,
            &rosters,
            &policies,
            &f.id,
            now + TICK_SECS,
            &mut state
        )
        .is_err()
    );
}

#[test]
fn documents_the_device_wrote_while_the_node_ran_are_reported_for_the_push() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let directory = RwLock::new(Directory::load(&f.steward).unwrap());
    let mut last = HashMap::new();
    let mut adopted = Vec::new();
    reload_adopting(
        &f.steward,
        &policies,
        &rosters,
        &directory,
        &mut last,
        &mut adopted,
    )
    .unwrap();
    assert!(adopted.is_empty(), "nothing is new yet");
    // The steward admits a device from the command line while the node runs.
    let phone_dir = tempfile::tempdir().unwrap();
    let phone = Home::new(phone_dir.path());
    let request = init(&phone, clock()).unwrap().join_request;
    admit(&f.steward, None, &request, "phone", &[], clock() + 60).unwrap();
    reload_adopting(
        &f.steward,
        &policies,
        &rosters,
        &directory,
        &mut last,
        &mut adopted,
    )
    .unwrap();
    assert_eq!(adopted, vec![f.id]);
    assert_eq!(rosters.seq(&f.id), Some(4));
    adopted.clear();
    reload_adopting(
        &f.steward,
        &policies,
        &rosters,
        &directory,
        &mut last,
        &mut adopted,
    )
    .unwrap();
    assert!(adopted.is_empty(), "the same documents are not new again");
}

#[test]
fn only_a_device_that_holds_a_key_of_the_network_issues() {
    let f = both();
    assert!(is_issuer(&f.owner, &f.id));
    assert!(is_issuer(&f.steward, &f.id));
    // A member that holds the documents and no key.
    let member_dir = tempfile::tempdir().unwrap();
    let member = Home::new(member_dir.path());
    let request = init(&member, clock()).unwrap().join_request;
    let admitted = admit(&f.owner, None, &request, "member", &[], clock() + 1).unwrap();
    join(&member, &admitted.token, clock() + 1).unwrap();
    assert!(!is_issuer(&member, &f.id));
    // A steward key alone is enough, and so is the owner key alone.
    std::fs::remove_file(f.steward.steward_key_path(&f.id)).unwrap();
    assert!(!is_issuer(&f.steward, &f.id));
}

#[test]
fn the_renewal_waits_for_a_command_that_holds_the_network_lock() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let (held_tx, held_rx) = std::sync::mpsc::channel();
    let (home, id) = (f.steward.clone(), f.id);
    let holder = std::thread::spawn(move || {
        let _lock = home.lock_network(&id).unwrap();
        held_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(800));
    });
    held_rx.recv().unwrap();
    let started = std::time::Instant::now();
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Renewed { seq: 4 });
    assert!(
        started.elapsed() >= Duration::from_millis(700),
        "it signed while another command held the lock"
    );
    holder.join().unwrap();
}
