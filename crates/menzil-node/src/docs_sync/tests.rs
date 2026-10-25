//! The rules of the sync triggers, one at a time: pure functions and the generic loops with fake
//! peers, under a paused clock. The flows over real routers are in `l4_router/tests/sync.rs`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

fn node(n: u8) -> NodeId {
    NodeId::from([n; 32])
}

fn net() -> NetworkId {
    NetworkId::from([7u8; 32])
}

fn held(roster: Option<u64>, policy: Option<u64>) -> HeldDocs {
    HeldDocs {
        roster_seq: roster,
        policy_seq: policy,
        base_seq: None,
        policy_base_seq: None,
    }
}

// ---- plan_sync ----------------------------------------------------

#[test]
fn a_peer_ahead_in_either_document_is_fetched_from() {
    let ours = held(Some(3), Some(3));
    assert_eq!(
        plan_sync(ours, Some(4), Some(3)),
        SyncPlan::Fetch,
        "newer Roster"
    );
    assert_eq!(
        plan_sync(ours, Some(3), Some(4)),
        SyncPlan::Fetch,
        "newer Policy"
    );
    // A node that holds nothing is behind a peer that holds something.
    assert_eq!(
        plan_sync(held(None, None), Some(0), Some(0)),
        SyncPlan::Fetch
    );
}

#[test]
fn a_peer_behind_in_either_document_is_pushed_to() {
    let ours = held(Some(3), Some(3));
    assert_eq!(
        plan_sync(ours, Some(2), Some(3)),
        SyncPlan::Push,
        "older Roster"
    );
    assert_eq!(
        plan_sync(ours, Some(3), Some(2)),
        SyncPlan::Push,
        "older Policy"
    );
    assert_eq!(plan_sync(ours, None, None), SyncPlan::Push);
}

#[test]
fn each_side_ahead_in_one_document_is_a_push_then_a_fetch() {
    let ours = held(Some(3), Some(1));
    assert_eq!(plan_sync(ours, Some(2), Some(2)), SyncPlan::PushThenFetch);
    let ours = held(Some(2), Some(2));
    assert_eq!(plan_sync(ours, Some(3), Some(1)), SyncPlan::PushThenFetch);
}

#[test]
fn equal_seqs_are_nothing_to_do() {
    assert_eq!(
        plan_sync(held(Some(3), Some(3)), Some(3), Some(3)),
        SyncPlan::Nothing
    );
    assert_eq!(plan_sync(held(None, None), None, None), SyncPlan::Nothing);
}

struct Order(Vec<&'static str>);

impl Exchange for Order {
    async fn push(&mut self) {
        self.0.push("push");
    }
    async fn fetch(&mut self) {
        self.0.push("fetch");
    }
}

#[tokio::test]
async fn a_plan_is_carried_out_with_the_push_before_the_fetch() {
    for (plan, expected) in [
        (SyncPlan::Nothing, vec![]),
        (SyncPlan::Fetch, vec!["fetch"]),
        (SyncPlan::Push, vec!["push"]),
        (SyncPlan::PushThenFetch, vec!["push", "fetch"]),
    ] {
        let mut order = Order(vec![]);
        run_plan(plan, &mut order).await;
        assert_eq!(order.0, expected, "{plan:?}");
    }
}

// ---- waits and thresholds -------------------------------------------

#[test]
fn the_policy_jitter_spans_zero_to_the_maximum_and_no_more() {
    let max = Duration::from_secs(60);
    assert_eq!(policy_jitter(max, 0), Duration::ZERO);
    assert_eq!(
        policy_jitter(max, u64::MAX),
        max,
        "the top of the range is the maximum"
    );
    // Not a value above the maximum for any draw, including ones that a modulo by a slightly
    // wrong range would map past it.
    for r in [1, 60_000, 60_001, 60_002, u64::MAX / 2, u64::MAX - 1] {
        assert!(policy_jitter(max, r) <= max, "{r}");
    }
    // It is spread: the middle draw is about the middle.
    let mid = policy_jitter(max, u64::MAX / 2);
    assert!(
        mid >= Duration::from_secs(29) && mid <= Duration::from_secs(31),
        "{mid:?}"
    );
    assert_eq!(policy_jitter(Duration::ZERO, u64::MAX), Duration::ZERO);
    assert_eq!(POLICY_JITTER_MAX, max, "the default is a minute");
}

#[test]
fn the_expiry_interval_spans_thirty_to_ninety_minutes() {
    assert_eq!(expiry_interval(0), Duration::from_secs(30 * 60));
    assert_eq!(expiry_interval(u64::MAX), Duration::from_secs(90 * 60));
    for r in [1, 2, u64::MAX / 3, u64::MAX / 2, u64::MAX - 1] {
        let wait = expiry_interval(r);
        assert!(
            wait >= Duration::from_secs(30 * 60) && wait <= Duration::from_secs(90 * 60),
            "{r}: {wait:?}"
        );
    }
    let mid = expiry_interval(u64::MAX / 2);
    assert!(
        mid >= Duration::from_secs(59 * 60) && mid <= Duration::from_secs(61 * 60),
        "{mid:?}"
    );
}

#[test]
fn documents_are_about_to_expire_within_twenty_four_hours_inclusive() {
    let now = 1_800_000_000;
    let day = 24 * 60 * 60;
    assert!(
        expires_within(now + day, now, EXPIRY_WINDOW),
        "exactly 24 h counts"
    );
    assert!(
        !expires_within(now + day + 1, now, EXPIRY_WINDOW),
        "one second more does not"
    );
    assert!(expires_within(now + 1, now, EXPIRY_WINDOW));
    assert!(expires_within(now, now, EXPIRY_WINDOW));
    assert!(
        expires_within(now - 5, now, EXPIRY_WINDOW),
        "already expired counts"
    );
    assert_eq!(EXPIRY_WINDOW, Duration::from_secs(day));
}

#[test]
fn the_policy_is_behind_when_it_is_older_than_the_roster_or_missing() {
    assert_eq!(policy_behind(Some(5), Some(4)), Some(5));
    assert_eq!(policy_behind(Some(5), None), Some(5));
    assert_eq!(policy_behind(Some(5), Some(5)), None);
    assert_eq!(policy_behind(Some(5), Some(6)), None);
    assert_eq!(policy_behind(None, Some(1)), None);
    assert_eq!(policy_behind(None, None), None);
}

// ---- whom to ask ------------------------------------------------------

#[test]
fn the_policy_is_asked_of_live_peers_that_hold_it_and_never_more_than_three() {
    let live: Vec<(NodeId, Option<u64>)> = vec![
        (node(1), Some(4)),
        (node(2), Some(5)), // exactly the Roster's seq
        (node(3), None),
        (node(4), Some(9)),
        (node(5), Some(6)),
        (node(6), Some(7)),
    ];
    let members = [node(20), node(21)];
    let picked = pick_for_policy(&live, &members, 5);
    assert_eq!(
        picked,
        vec![node(2), node(4), node(5)],
        "in order, three, none that is behind"
    );
    let picked = pick_for_policy(&live[..2], &members, 5);
    assert_eq!(
        picked,
        vec![node(2)],
        "a live peer that holds it is enough: no members"
    );
}

#[test]
fn without_a_live_peer_that_holds_the_policy_three_members_are_asked() {
    let live: Vec<(NodeId, Option<u64>)> = vec![(node(1), Some(4)), (node(3), None)];
    let members: Vec<NodeId> = (20..26).map(node).collect();
    assert_eq!(
        pick_for_policy(&live, &members, 5),
        vec![node(20), node(21), node(22)]
    );
    assert_eq!(
        pick_for_policy(&[], &members[..2], 5),
        vec![node(20), node(21)]
    );
    assert!(pick_for_policy(&[], &[], 5).is_empty());
}

#[test]
fn expiring_documents_are_asked_of_live_peers_first_then_members_three_in_all() {
    let live = [node(1), node(2)];
    let members = [node(2), node(10), node(11), node(12)];
    assert_eq!(
        pick_for_expiry(&live, &members),
        vec![node(1), node(2), node(10)],
        "live first, a member that is also live is not asked twice"
    );
    let live4 = [node(1), node(2), node(3), node(4)];
    assert_eq!(
        pick_for_expiry(&live4, &members),
        vec![node(1), node(2), node(3)],
        "three live peers fill it"
    );
    assert_eq!(
        pick_for_expiry(&[], &members[1..]),
        vec![node(10), node(11), node(12)]
    );
    assert!(pick_for_expiry(&[], &[]).is_empty());
}

#[tokio::test]
async fn a_round_asks_in_order_and_stops_at_the_first_that_says_so() {
    let asked = Mutex::new(Vec::new());
    let peers = [node(1), node(2), node(3)];
    let count = fetch_round(
        &peers,
        |peer| {
            asked.lock().unwrap().push(peer);
            async move {
                if peer == node(2) {
                    Attempt::Adopted
                } else {
                    Attempt::Nothing
                }
            }
        },
        |attempt| attempt == Attempt::Adopted,
    )
    .await;
    assert_eq!(count, 2);
    assert_eq!(*asked.lock().unwrap(), vec![node(1), node(2)]);

    // A peer that failed or had nothing does not end the round.
    let count = fetch_round(
        &peers,
        |peer| async move {
            if peer == node(1) {
                Attempt::Failed
            } else {
                Attempt::Nothing
            }
        },
        |attempt| attempt == Attempt::Adopted,
    )
    .await;
    assert_eq!(count, 3);
}

// ---- one new handshake after a docs only push ---------------------------

#[tokio::test(start_paused = true)]
async fn one_new_handshake_per_peer_within_a_minute() {
    let mut guard = RehandshakeGuard::default();
    let t0 = Instant::now();
    assert!(guard.allow(node(1), net(), t0));
    assert!(!guard.allow(node(1), net(), t0), "not twice at once");
    assert!(
        !guard.allow(node(1), net(), t0 + Duration::from_secs(59)),
        "nor within the window"
    );
    assert!(guard.allow(node(2), net(), t0), "another peer is its own");
    assert!(
        guard.allow(node(1), NetworkId::from([8u8; 32]), t0),
        "another network is its own"
    );
    assert!(
        guard.allow(node(1), net(), t0 + Duration::from_secs(60)),
        "after the window it may"
    );
    assert_eq!(REHANDSHAKE_WINDOW, Duration::from_secs(60));
}

// ---- the issuer's push ------------------------------------------------------

/// A pusher that answers from a script and writes down when and how many at once.
struct Script {
    /// What each member's attempts answer, in order; the last answer repeats.
    answers: Mutex<std::collections::HashMap<NodeId, Vec<PushStep>>>,
    /// When every attempt was made (since `start`), per member.
    attempts: Mutex<Vec<(NodeId, Duration)>>,
    start: Instant,
    running: AtomicUsize,
    most_at_once: AtomicUsize,
    /// How long one attempt takes.
    takes: Duration,
    current: Mutex<bool>,
}

impl Script {
    fn new(takes: Duration) -> Self {
        Self {
            answers: Mutex::default(),
            attempts: Mutex::default(),
            start: Instant::now(),
            running: AtomicUsize::new(0),
            most_at_once: AtomicUsize::new(0),
            takes,
            current: Mutex::new(true),
        }
    }

    fn answer(&self, member: NodeId, steps: Vec<PushStep>) {
        self.answers.lock().unwrap().insert(member, steps);
    }

    fn times_of(&self, member: NodeId) -> Vec<u64> {
        self.attempts
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, _)| *m == member)
            .map(|(_, at)| at.as_secs())
            .collect()
    }
}

impl MemberPusher for Script {
    async fn push(&self, member: NodeId) -> PushStep {
        let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.most_at_once.fetch_max(now, Ordering::SeqCst);
        self.attempts
            .lock()
            .unwrap()
            .push((member, Instant::now() - self.start));
        tokio::time::sleep(self.takes).await;
        self.running.fetch_sub(1, Ordering::SeqCst);
        let mut answers = self.answers.lock().unwrap();
        let steps = answers
            .entry(member)
            .or_insert_with(|| vec![PushStep::Done]);
        if steps.len() > 1 {
            steps.remove(0)
        } else {
            steps[0]
        }
    }

    fn current(&self) -> bool {
        *self.current.lock().unwrap()
    }
}

#[tokio::test(start_paused = true)]
async fn at_most_eight_members_are_pushed_to_at_a_time() {
    let script = Script::new(Duration::from_secs(10));
    let members: Vec<NodeId> = (1..=20).map(node).collect();
    let report = push_to_members(&script, &members, PUSH_AT_ONCE, &PUSH_RETRY).await;
    assert_eq!(report.done, 20);
    assert_eq!(script.most_at_once.load(Ordering::SeqCst), 8);
    assert_eq!(PUSH_AT_ONCE, 8);
    // Twenty members, eight at a time, ten seconds each: three waves.
    assert_eq!(Instant::now() - script.start, Duration::from_secs(30));
}

#[tokio::test(start_paused = true)]
async fn a_member_that_does_not_answer_is_tried_after_one_five_thirty_minutes_and_two_hours() {
    let script = Script::new(Duration::from_secs(1));
    script.answer(node(1), vec![PushStep::NoAnswer]);
    let report = push_to_members(&script, &[node(1)], PUSH_AT_ONCE, &PUSH_RETRY).await;
    assert_eq!(
        report,
        PushReport {
            done: 0,
            rejected: 0,
            gave_up: 1
        }
    );
    // Each wait starts when the attempt before it failed (an attempt takes one second here).
    let m = 60;
    assert_eq!(
        script.times_of(node(1)),
        vec![
            0,
            1 + m,
            1 + m + 1 + 5 * m,
            1 + m + 1 + 5 * m + 1 + 30 * m,
            1 + m + 1 + 5 * m + 1 + 30 * m + 1 + 120 * m,
        ],
        "one first attempt and four retries, then it is given up"
    );
}

#[tokio::test(start_paused = true)]
async fn a_member_that_answers_late_is_done_and_not_tried_again() {
    let script = Script::new(Duration::from_secs(1));
    script.answer(
        node(1),
        vec![PushStep::NoAnswer, PushStep::NoAnswer, PushStep::Done],
    );
    let report = push_to_members(&script, &[node(1), node(2)], PUSH_AT_ONCE, &PUSH_RETRY).await;
    assert_eq!(
        report,
        PushReport {
            done: 2,
            rejected: 0,
            gave_up: 0
        }
    );
    assert_eq!(script.times_of(node(1)).len(), 3);
    assert_eq!(script.times_of(node(2)).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_rejected_member_and_one_that_cannot_be_dialed_are_not_tried_again() {
    let script = Script::new(Duration::from_secs(1));
    script.answer(node(1), vec![PushStep::Rejected]);
    script.answer(node(2), vec![PushStep::Skip]);
    let report = push_to_members(&script, &[node(1), node(2)], PUSH_AT_ONCE, &PUSH_RETRY).await;
    assert_eq!(
        report,
        PushReport {
            done: 0,
            rejected: 1,
            gave_up: 1
        }
    );
    assert_eq!(script.times_of(node(1)).len(), 1);
    assert_eq!(script.times_of(node(2)).len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_retry_is_dropped_when_newer_documents_have_overtaken_the_ones_pushed() {
    let script = Script::new(Duration::from_secs(1));
    script.answer(node(1), vec![PushStep::NoAnswer]);
    *script.current.lock().unwrap() = false;
    let report = push_to_members(&script, &[node(1)], PUSH_AT_ONCE, &PUSH_RETRY).await;
    assert_eq!(report.gave_up, 1);
    assert_eq!(
        script.times_of(node(1)).len(),
        1,
        "no retry for old documents"
    );
}

#[tokio::test(start_paused = true)]
async fn a_member_waiting_for_its_retry_does_not_hold_one_of_the_eight_places() {
    // Eight members never answer; a ninth would wait forever for a place if the eight kept
    // theirs through their one-minute wait.
    let script = Script::new(Duration::from_secs(1));
    for n in 1..=8 {
        script.answer(node(n), vec![PushStep::NoAnswer]);
    }
    let members: Vec<NodeId> = (1..=9).map(node).collect();
    let report = push_to_members(&script, &members, PUSH_AT_ONCE, &PUSH_RETRY).await;
    assert_eq!(report.done, 1);
    assert_eq!(report.gave_up, 8);
    // The ninth was served in the first seconds, while the eight waited for their retry.
    assert!(
        script.times_of(node(9))[0] <= 2,
        "{:?}",
        script.times_of(node(9))
    );
}

// ---- classifying outcomes ------------------------------------------------------

#[test]
fn what_a_failed_session_means_for_the_issuer() {
    assert_eq!(step_for_ensure_error(EnsureError::DocsOnly), PushStep::Done);
    for retry in [
        EnsureError::Timeout,
        EnsureError::NotAttached,
        EnsureError::Detached,
        EnsureError::SessionEnded,
        EnsureError::TableFull,
    ] {
        assert_eq!(
            step_for_ensure_error(retry),
            PushStep::NoAnswer,
            "{retry:?}"
        );
    }
    for skip in [
        EnsureError::UnknownPeer,
        EnsureError::SelfPeer,
        EnsureError::NotAMember,
        EnsureError::Refused,
        EnsureError::RouterGone,
        EnsureError::ShuttingDown,
    ] {
        assert_eq!(step_for_ensure_error(skip), PushStep::Skip, "{skip:?}");
    }
}

fn result(roster: Outcome, policy: Outcome) -> PushResult {
    PushResult {
        roster,
        policy,
        code: None,
        roster_seq: None,
        policy_seq: None,
    }
}

#[test]
fn a_member_that_adopted_or_held_the_documents_is_done_and_one_that_refused_is_not() {
    assert_eq!(
        step_for_result(&result(Outcome::Adopted, Outcome::Adopted)),
        PushStep::Done
    );
    assert_eq!(
        step_for_result(&result(Outcome::Held, Outcome::NotSent)),
        PushStep::Done
    );
    assert_eq!(
        step_for_result(&result(Outcome::Rejected, Outcome::Held)),
        PushStep::Rejected
    );
    assert_eq!(
        step_for_result(&result(Outcome::Adopted, Outcome::Rejected)),
        PushStep::Rejected
    );
}
