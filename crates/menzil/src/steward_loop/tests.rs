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
            may_admit: true,
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
    // (round 9, L2: one that went back is due at once, see the test below.)
}

#[test]
fn a_warning_is_repeated_once_a_day() {
    assert!(warn_due(None, NOW));
    assert!(!warn_due(Some(NOW), NOW));
    assert!(!warn_due(Some(NOW), NOW + DAY - 1));
    assert!(warn_due(Some(NOW), NOW + DAY));
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

/// Round 9, L2: a `last.at` ahead of the clock (the device booted with a clock a year ahead,
/// looked once, then the clock was set right) is due, and a warning said then is due again.
#[test]
fn a_look_or_warning_stamped_in_the_future_is_due() {
    let ahead = Tick {
        at: NOW + 365 * DAY,
        seq: Some(3),
    };
    for later in [NOW, NOW + DAY, NOW + 30 * DAY, NOW + 364 * DAY] {
        assert!(tick_due(Some(ahead), later, 3), "+{}d", (later - NOW) / DAY);
    }
    assert!(warn_due(Some(NOW + 365 * DAY), NOW + 30 * DAY));
    // The ordinary cases stay as they were: just stamped is not due, an hour later is.
    assert!(!tick_due(
        Some(Tick {
            at: NOW,
            seq: Some(3)
        }),
        NOW,
        3
    ));
    assert!(!warn_due(Some(NOW), NOW));
}

/// Adopts the Roster alone of the pair in `token` (as the relay's DOC carries it: the Policy is
/// still to be fetched from a peer) and returns its `seq`.
fn adopt_roster_alone(token: &str, rosters: &RosterStore, policies: &PolicyStore, now: u64) -> u64 {
    let pair = crate::token::decode_documents(token).unwrap();
    let alone = menzil_proto::trust::Bundle {
        roster: Some(pair.roster().clone()),
        ..Default::default()
    };
    let adopted = DocStore::new(rosters, policies).adopt(&alone, now).unwrap();
    assert!(adopted.roster && !adopted.policy);
    pair.seq()
}

/// Round 9, L1: the owner's removal Roster held alone (its Policy still to come) stops the
/// removed steward: no renewal from the older disk pair, the warning says it is not listed.
#[test]
fn a_removal_roster_held_alone_stops_the_removed_steward() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let removed = steward_remove(&f.owner, None, clock() + 1).unwrap();
    let seq = adopt_roster_alone(&removed.token, &rosters, &policies, clock() + 1);
    assert_eq!(
        (rosters.seq(&f.id), policies.seq(&f.id)),
        (Some(seq), Some(3))
    );
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    let disk = crate::local::load_documents(&f.steward, &f.id).unwrap();
    assert_eq!(disk.seq(), 3, "nothing was signed or written");
    assert_eq!(rosters.seq(&f.id), Some(seq));
    assert_eq!(
        state.last_warning,
        Some(now),
        "it says the key is not listed"
    );
}

/// Round 9, L1: a newer Roster held without its Policy makes the loop wait, even when it still
/// lists the steward: renewing from the older pair would sign over it and fail on adoption.
#[test]
fn a_newer_roster_held_without_its_policy_makes_the_loop_wait() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let renewed = crate::local::renew(&f.owner, None, clock() + 1).unwrap();
    let seq = adopt_roster_alone(&renewed.token, &rosters, &policies, clock() + 1);
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked);
    let disk = crate::local::load_documents(&f.steward, &f.id).unwrap();
    assert_eq!(disk.seq(), 3, "nothing was signed or written");
    assert_eq!(rosters.seq(&f.id), Some(seq));
    // With the Policy arrived the loop is back on the held pair and renews from it when due.
    let pair = crate::token::decode_documents(&renewed.token).unwrap();
    DocStore::new(&rosters, &policies)
        .adopt(&pair.bundle(), clock() + 1)
        .unwrap();
    let later = tick_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        now + TICK_SECS,
        &mut state,
    )
    .unwrap();
    assert_eq!(later, Outcome::Renewed { seq: seq + 1 });
}

/// TOBEDECIDED 19d: the pair that removes a steward reaches the node over the network (never
/// as a token), and is on disk by the time the node restarts, so the restarted steward does not
/// renew from its stale disk pair again.
#[test]
fn a_removal_adopted_over_the_network_survives_a_restart_of_the_removed_steward() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let keeper = crate::node_cmd::keep_adopted_documents(&f.steward, &rosters).unwrap();
    let removed = steward_remove(&f.owner, None, clock() + 1).unwrap();
    let pair = crate::token::decode_documents(&removed.token).unwrap();
    DocStore::new(&rosters, &policies)
        .adopt(&pair.bundle(), clock() + 1)
        .unwrap();
    assert!(keeper.flush(std::time::Duration::from_secs(10)));
    assert_eq!(
        crate::local::load_documents(&f.steward, &f.id)
            .unwrap()
            .seq(),
        removed.seq
    );
    // The restart: the stores are read from disk again.
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    assert_eq!(rosters.seq(&f.id), Some(removed.seq));
    let mut state = NetState::default();
    let now = clock() + 8 * DAY;
    let outcome = tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    assert_eq!(outcome, Outcome::Checked, "nothing is renewed");
    assert_eq!(rosters.seq(&f.id), Some(removed.seq));
    assert_eq!(
        state.last_warning,
        Some(now),
        "it warns that it is not listed"
    );
}

/// A steward signed pair that a member adopts over the network is kept with its bases (it is
/// never held, passed on or written without them).
#[test]
fn a_steward_signed_pair_adopted_over_the_network_is_kept_with_its_bases() {
    let f = both();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let now = clock() + 8 * DAY;
    let mut state = NetState::default();
    tick_network(&f.steward, &rosters, &policies, &f.id, now, &mut state).unwrap();
    let steward_pair = crate::local::load_documents(&f.steward, &f.id).unwrap();
    assert!(steward_pair.base().is_some());

    // The owner's device stands in for a member that holds the owner signed pair.
    let (member_policies, member_rosters, _) = load_stores(&f.owner).unwrap();
    let keeper = crate::node_cmd::keep_adopted_documents(&f.owner, &member_rosters).unwrap();
    DocStore::new(&member_rosters, &member_policies)
        .adopt(&steward_pair.bundle(), now)
        .unwrap();
    assert!(keeper.flush(std::time::Duration::from_secs(10)));
    let kept = crate::local::load_documents(&f.owner, &f.id).unwrap();
    assert_eq!(kept.seq(), steward_pair.seq());
    assert_eq!(
        kept.base().unwrap().0.decode().unwrap().seq,
        steward_pair.base().unwrap().0.decode().unwrap().seq
    );
}

// ---- listing members' renewed certificates (cert rotation S6, design Q7) ----

/// Like [`fixture`], but both devices were made 380 days ago: their first certificates run out
/// in 20 days, so a renewal made now extends them by far more than the 30 days a steward
/// requires.
fn aged_fixture(may: &[&str]) -> Fixture {
    let born = clock() - 380 * DAY;
    let owner_dir = tempfile::tempdir().unwrap();
    let owner = Home::new(owner_dir.path());
    init(&owner, born).unwrap();
    let id = network_create(&owner, "laptop", clock()).unwrap();
    let steward_dir = tempfile::tempdir().unwrap();
    let steward = Home::new(steward_dir.path());
    let request = init(&steward, born).unwrap().join_request;
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

/// The renewed certificate of the owner's device, made `days` after the fixture.
fn owners_renewal(f: &Fixture, days: u64) -> menzil_proto::NodeCert {
    crate::local::cert_renew(&f.owner, clock() + days * DAY)
        .unwrap()
        .cert
}

fn serials_of(docs: &Documents, node: &menzil_proto::NodeId) -> Vec<u32> {
    docs.policy_body()
        .certs
        .iter()
        .map(|cert| cert.decode().unwrap())
        .filter(|body| body.node_id == *node)
        .map(|body| body.serial)
        .collect()
}

#[test]
fn a_steward_lists_a_pushed_renewal_writes_it_and_adopts_it() {
    let f = aged_fixture(&["admit", "renew"]);
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let mut state = NetState::default();
    let cert = owners_renewal(&f, 1);
    let owner_id = cert.decode().unwrap().node_id;
    let now = clock() + 2 * DAY;

    let outcome = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        std::slice::from_ref(&cert),
        now,
        &mut state,
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Rotated { seq: 4, certs: 1 });
    // On disk and in the stores, as the steward's pair listing the renewal in its tail.
    let disk = crate::local::load_documents(&f.steward, &f.id).unwrap();
    assert_eq!(disk.seq(), 4);
    assert!(disk.base().is_some());
    assert_eq!(serials_of(&disk, &owner_id), vec![1, 2]);
    assert_eq!(
        (rosters.seq(&f.id), policies.seq(&f.id)),
        (Some(4), Some(4))
    );
    assert!(policies.body(&f.id).unwrap().certs.contains(&cert));
    // The owner's device takes the pair like any member.
    let (member_policies, member_rosters, _) = load_stores(&f.owner).unwrap();
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
    assert!(state.last_rotation == Some(now));
}

#[test]
fn a_renewal_that_does_not_qualify_makes_no_pair_and_does_not_use_up_the_hour() {
    let f = aged_fixture(&["admit", "renew"]);
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let mut state = NetState::default();
    let now = clock() + 2 * DAY;
    let short = {
        // The owner device's certificate has 20 days left; a renewal that ends 5 days after it
        // extends it by 5 only, under the 30 days a steward requires.
        let (keys, current) = crate::local::load_identity(&f.owner).unwrap();
        let listed_not_after = current.decode().unwrap().not_after;
        keys.issue_cert(2, clock() - DAY, listed_not_after + 5 * DAY)
            .unwrap()
    };
    let outcome = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        std::slice::from_ref(&short),
        now,
        &mut state,
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Idle);
    assert_eq!(rosters.seq(&f.id), Some(3), "no pair was made");
    assert_eq!(state.last_rotation, None);
    // A qualifying one right after is not held back by the earlier look.
    let good = owners_renewal(&f, 1);
    let outcome = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        &[short, good],
        now + 1,
        &mut state,
    )
    .unwrap();
    assert_eq!(outcome, Outcome::Rotated { seq: 4, certs: 1 });
}

#[test]
fn at_most_one_rotation_pair_an_hour() {
    let f = aged_fixture(&["admit", "renew"]);
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let mut state = NetState::default();
    let owner = owners_renewal(&f, 1);
    let now = clock() + 2 * DAY;
    let first = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        std::slice::from_ref(&owner),
        now,
        &mut state,
    );
    assert_eq!(first.unwrap(), Outcome::Rotated { seq: 4, certs: 1 });
    // The steward's own device renews too (its own first certificate is listed as a member).
    let other = crate::local::cert_renew(&f.steward, clock() + DAY)
        .unwrap()
        .cert;
    let within = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        std::slice::from_ref(&other),
        now + crate::cert_renew::ROTATE_EVERY - 1,
        &mut state,
    );
    assert_eq!(within.unwrap(), Outcome::Idle);
    assert_eq!(rosters.seq(&f.id), Some(4));
    let after = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        std::slice::from_ref(&other),
        now + crate::cert_renew::ROTATE_EVERY,
        &mut state,
    );
    assert_eq!(after.unwrap(), Outcome::Rotated { seq: 5, certs: 1 });
}

#[test]
fn only_a_steward_with_both_rights_and_time_left_rotates() {
    let now = clock() + 2 * DAY;
    // `admit` alone: the pair would be refused for want of `renew`, so none is attempted.
    let f = aged_fixture(&["admit"]);
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let cert = owners_renewal(&f, 1);
    let mut state = NetState::default();
    let outcome = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        std::slice::from_ref(&cert),
        now,
        &mut state,
    );
    assert_eq!(outcome.unwrap(), Outcome::Idle);
    // `renew` alone.
    let g = aged_fixture(&["renew"]);
    let (policies, rosters, _) = load_stores(&g.steward).unwrap();
    let cert = owners_renewal(&g, 1);
    let outcome = rotate_network(
        &g.steward,
        &rosters,
        &policies,
        &g.id,
        std::slice::from_ref(&cert),
        now,
        &mut state,
    );
    assert_eq!(outcome.unwrap(), Outcome::Idle);
    assert_eq!(rosters.seq(&g.id), Some(3));
    // Both rights, but the delegation is over.
    let h = aged_fixture(&["admit", "renew"]);
    let (policies, rosters, _) = load_stores(&h.steward).unwrap();
    let cert = owners_renewal(&h, 1);
    let outcome = rotate_network(
        &h.steward,
        &rosters,
        &policies,
        &h.id,
        std::slice::from_ref(&cert),
        clock() + 31 * DAY,
        &mut state,
    );
    assert_eq!(outcome.unwrap(), Outcome::Idle);
    assert_eq!(rosters.seq(&h.id), Some(3));
    // The owner's device holds no steward key: nothing.
    let (policies, rosters, _) = load_stores(&h.owner).unwrap();
    let outcome = rotate_network(
        &h.owner,
        &rosters,
        &policies,
        &h.id,
        std::slice::from_ref(&cert),
        now,
        &mut state,
    );
    assert_eq!(outcome.unwrap(), Outcome::Idle);
    // And no candidates, no look at all.
    let outcome = rotate_network(&h.steward, &rosters, &policies, &h.id, &[], now, &mut state);
    assert_eq!(outcome.unwrap(), Outcome::Idle);
}

#[test]
fn a_device_is_the_owner_a_listed_steward_or_nothing_for_the_candidates() {
    let f = aged_fixture(&["admit", "renew"]);
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let (owner_policies, owner_rosters, _) = load_stores(&f.owner).unwrap();
    assert_eq!(
        holder_of(&f.owner, &owner_rosters, &owner_policies, &f.id).unwrap(),
        Some(Holder::Owner)
    );
    assert_eq!(
        holder_of(&f.steward, &rosters, &policies, &f.id).unwrap(),
        Some(Holder::Steward {
            admit: true,
            renew: true,
            not_after: clock() + 30 * DAY,
        })
    );
    // The rights are the entry's.
    let g = aged_fixture(&["admit"]);
    let (policies, rosters, _) = load_stores(&g.steward).unwrap();
    assert_eq!(
        holder_of(&g.steward, &rosters, &policies, &g.id).unwrap(),
        Some(Holder::Steward {
            admit: true,
            renew: false,
            not_after: clock() + 30 * DAY,
        })
    );
    let g = aged_fixture(&["renew"]);
    let (policies, rosters, _) = load_stores(&g.steward).unwrap();
    assert_eq!(
        holder_of(&g.steward, &rosters, &policies, &g.id).unwrap(),
        Some(Holder::Steward {
            admit: false,
            renew: true,
            not_after: clock() + 30 * DAY,
        })
    );
    // A steward key the documents do not list (the owner removed the steward) is nothing.
    let removed = steward_remove(&f.owner, None, clock() + 1).unwrap();
    join(&f.steward, &removed.token, clock() + 1).unwrap();
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    assert_eq!(
        holder_of(&f.steward, &rosters, &policies, &f.id).unwrap(),
        None
    );
    // The documents list another steward than this device's key: nothing either.
    let g = aged_fixture(&["admit", "renew"]);
    let other = steward_request(&g.owner, None).unwrap();
    let relisted = steward_add(
        &g.owner,
        None,
        &other.token,
        &["admit".into(), "renew".into()],
        30,
        clock() + 1,
    )
    .unwrap();
    join(&g.steward, &relisted.issued.token, clock() + 1).unwrap();
    let (policies, rosters, _) = load_stores(&g.steward).unwrap();
    assert_eq!(
        holder_of(&g.steward, &rosters, &policies, &g.id).unwrap(),
        None
    );
    // A device with no key of the network reads nothing and is nothing.
    std::fs::remove_file(f.steward.steward_key_path(&f.id)).unwrap();
    assert_eq!(
        holder_of(&f.steward, &rosters, &policies, &f.id).unwrap(),
        None
    );
}

#[test]
fn a_look_with_nothing_to_list_does_not_take_the_network_lock() {
    let f = aged_fixture(&["admit", "renew"]);
    let (policies, rosters, _) = load_stores(&f.steward).unwrap();
    let mut state = NetState::default();
    let _held_elsewhere = f.steward.lock_network(&f.id).unwrap();
    // A candidate that extends the listed certificate by too little: nothing to do, and the
    // lock another command holds is not waited for.
    let (keys, current) = crate::local::load_identity(&f.owner).unwrap();
    let not_after = current.decode().unwrap().not_after;
    let short = keys
        .issue_cert(2, clock() - DAY, not_after + 5 * DAY)
        .unwrap();
    let started = std::time::Instant::now();
    let outcome = rotate_network(
        &f.steward,
        &rosters,
        &policies,
        &f.id,
        &[short],
        clock() + 2 * DAY,
        &mut state,
    );
    assert_eq!(outcome.unwrap(), Outcome::Idle);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}
