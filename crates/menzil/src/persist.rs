//! A thread that does slow, blocking work one job at a time, in the order the jobs were
//! submitted: how documents a relay or a node adopts over the network reach the disk.
//!
//! The work takes file locks (a bounded wait) and writes files, which an async task must not
//! do and which a caller that already holds the same lock (the steward loop adopts what it has
//! just written, under the network lock) would deadlock on if it ran inline. A job whose work
//! fails for good is the work's own business to report; a job whose work asks for a retry
//! ([`Outcome::Retry`]) goes into a retry book and is run again with a backoff, until it is
//! done, a newer job with its key replaces it, or the worker is gone. A panic in the work is
//! caught and logged, and the job is dropped.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// What the work says about a job it has run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Finished, or refused for good (the work has said so itself): not run again.
    Done,
    /// A transient failure (a lock held by another process, an I/O error): run again later.
    /// `class` tells kinds of failure apart for the log (a changed class is logged at once).
    Retry {
        /// The kind of failure, a short stable word.
        class: &'static str,
        /// What went wrong, for the log.
        error: String,
    },
}

/// What the work is told about the run it is doing.
#[derive(Debug, Clone, Copy)]
pub struct Attempt {
    /// How many runs of this job failed before (0 on the first).
    pub failures: u32,
    /// When a flush (a clean stop) wants everything done, the end of its grace.
    pub deadline: Option<Instant>,
}

impl Attempt {
    /// How long a lock wait may last: `wanted`, and not past the end of a flush's grace.
    pub fn lock_wait(&self, wanted: Duration) -> Duration {
        match self.deadline {
            None => wanted,
            Some(deadline) => wanted.min(deadline.saturating_duration_since(Instant::now())),
        }
    }
}

/// First wait after a failure.
const BACKOFF_FIRST: Duration = Duration::from_secs(1);
/// The longest wait between two runs of a failing job.
const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// How often a job that keeps failing is logged at warn level.
const WARN_EVERY: Duration = Duration::from_secs(600);

/// The wait after `failures` failed runs (1, 2, 4, ... seconds, at most 60).
fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    BACKOFF_FIRST
        .saturating_mul(1u32 << doublings)
        .min(BACKOFF_CAP)
}

/// How a failure is to be logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogDecision {
    /// A warn line: the first failure, or a new kind of failure.
    Warn,
    /// A warn line saying it is still failing (at most one per [`WARN_EVERY`]).
    WarnStill,
    /// Debug only.
    Debug,
}

/// A job waiting for its next run.
pub(crate) struct Pending<T> {
    key: String,
    job: T,
    failures: u32,
    due: Instant,
    class: Option<&'static str>,
    last_warn: Option<Instant>,
}

impl<T> Pending<T> {
    fn new(key: String, job: T, now: Instant) -> Self {
        Self {
            key,
            job,
            failures: 0,
            due: now,
            class: None,
            last_warn: None,
        }
    }
}

/// The jobs that failed and wait for a retry, one per key. Pure: it never reads the clock.
pub(crate) struct RetryBook<T> {
    entries: Vec<Pending<T>>,
}

impl<T> RetryBook<T> {
    pub(crate) fn new() -> Self {
        Self { entries: vec![] }
    }

    /// Records a failed run of `pending`: it waits [`backoff`] from `now`. A pending entry of the
    /// same key is replaced.
    pub(crate) fn fail(
        &mut self,
        mut pending: Pending<T>,
        class: &'static str,
        now: Instant,
    ) -> LogDecision {
        pending.failures += 1;
        pending.due = now + backoff(pending.failures);
        let decision = if pending.class != Some(class) {
            LogDecision::Warn
        } else if pending
            .last_warn
            .is_none_or(|at| now.saturating_duration_since(at) >= WARN_EVERY)
        {
            LogDecision::WarnStill
        } else {
            LogDecision::Debug
        };
        if decision != LogDecision::Debug {
            pending.last_warn = Some(now);
        }
        pending.class = Some(class);
        self.entries.retain(|e| e.key != pending.key);
        self.entries.push(pending);
        decision
    }

    /// Drops the entry of `key` (a newer job for it supersedes it); whether there was one.
    pub(crate) fn supersede(&mut self, key: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.key != key);
        self.entries.len() != before
    }

    /// When the first entry is due.
    pub(crate) fn next_due(&self) -> Option<Instant> {
        self.entries.iter().map(|e| e.due).min()
    }

    /// The entry that is due at `now` and has waited longest, removed.
    pub(crate) fn take_due(&mut self, now: Instant) -> Option<Pending<T>> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.due <= now)
            .min_by_key(|(_, e)| e.due)
            .map(|(i, _)| i)?;
        Some(self.entries.remove(index))
    }

    /// Every entry, removed, longest waiting first (a flush runs them whatever their backoff).
    pub(crate) fn take_all(&mut self) -> Vec<Pending<T>> {
        let mut all = std::mem::take(&mut self.entries);
        all.sort_by_key(|e| e.due);
        all
    }

    /// Makes every entry due at once.
    #[cfg(test)]
    pub(crate) fn make_due(&mut self, now: Instant) {
        for entry in &mut self.entries {
            entry.due = now;
        }
    }

    pub(crate) fn keys(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.key.clone()).collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

enum Message<T> {
    Job(T),
    /// A flush: on this the thread runs what is in the retry book once more, then answers.
    Barrier(std::sync::mpsc::Sender<()>),
}

struct Queue<T> {
    messages: VecDeque<Message<T>>,
    book: RetryBook<T>,
    /// The key of the job being run now (set when the thread takes the job, so there is no gap
    /// in which a taken job is in neither the book, the queue nor here).
    running: Option<String>,
    /// The keys a flush barrier took out of the book and has not started yet.
    barrier_left: Vec<String>,
    /// While a flush is on, the end of its grace: the latest of the flushes that are on (several
    /// callers may flush at once; one that ends must not take the others' grace away).
    deadline: Option<Instant>,
    /// The flushes that are on: an id and the end of the grace of each.
    flushes: Vec<(u64, Instant)>,
    /// The id of the next flush.
    next_flush: u64,
    /// Set when the [`Worker`] is gone: the thread ends once the queue is empty.
    closed: bool,
}

struct Shared<T> {
    queue: Mutex<Queue<T>>,
    wake: Condvar,
}

impl<T> Shared<T> {
    /// The queue; a poisoned lock is still a usable queue (the work runs outside it).
    fn lock(&self) -> MutexGuard<'_, Queue<T>> {
        self.queue.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// How a flush went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlushReport {
    /// Whether every job submitted before the flush was run (once more, for those that
    /// failed) within the timeout.
    pub reached: bool,
    /// The keys of the jobs that are not done: waiting for a retry, or (when `reached` is
    /// false) not run yet or still running.
    pub unwritten: Vec<String>,
}

impl FlushReport {
    /// Everything is done.
    pub fn is_clean(&self) -> bool {
        self.reached && self.unwritten.is_empty()
    }
}

type KeyOf<T> = Arc<dyn Fn(&T) -> String + Send + Sync>;

/// A worker thread running `work` on each job submitted. At most one job per key waits in the
/// queue (or in the retry book): a job submitted while an older one with the same key has not
/// started replaces it (in the older one's place), so a flood for one key costs memory for one
/// job and one run of the work. The thread ends once the worker is gone and the jobs already
/// submitted are done (jobs waiting for a retry are given up then).
pub struct Worker<T> {
    shared: Arc<Shared<T>>,
    key: KeyOf<T>,
}

impl<T: Send + 'static> Worker<T> {
    /// Starts the thread, named `name`. Two jobs with the same `key` are one job to the queue.
    pub fn spawn(
        name: &str,
        key: impl Fn(&T) -> String + Send + Sync + 'static,
        mut work: impl FnMut(&T, &Attempt) -> Outcome + Send + 'static,
    ) -> Result<Arc<Self>> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                messages: VecDeque::new(),
                book: RetryBook::new(),
                running: None,
                barrier_left: vec![],
                deadline: None,
                flushes: Vec::new(),
                next_flush: 0,
                closed: false,
            }),
            wake: Condvar::new(),
        });
        let key: KeyOf<T> = Arc::new(key);
        let thread_shared = Arc::clone(&shared);
        let thread_key = Arc::clone(&key);
        let thread_name = name.to_string();
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                // Runs one job (a first run or a retry) and files the result.
                let mut run = |pending: Pending<T>| {
                    let attempt = {
                        let mut queue = thread_shared.lock();
                        queue.running = Some(pending.key.clone());
                        queue.barrier_left.retain(|k| *k != pending.key);
                        Attempt {
                            failures: pending.failures,
                            deadline: queue.deadline,
                        }
                    };
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        work(&pending.job, &attempt)
                    }));
                    let mut queue = thread_shared.lock();
                    queue.running = None;
                    match result {
                        Err(_) => {
                            tracing::warn!(
                                worker = %thread_name,
                                "a background job panicked; going on with the next"
                            );
                        }
                        Ok(Outcome::Done) => {
                            if pending.failures > 0 {
                                tracing::info!(
                                    worker = %thread_name,
                                    key = %pending.key,
                                    attempts = pending.failures + 1,
                                    "done after failed attempts"
                                );
                            }
                        }
                        Ok(Outcome::Retry { class, error }) => {
                            let superseded = queue.messages.iter().any(|m| {
                                matches!(m, Message::Job(newer) if thread_key(newer) == pending.key)
                            });
                            if !superseded {
                                let (key, failures) = (pending.key.clone(), pending.failures + 1);
                                match queue.book.fail(pending, class, Instant::now()) {
                                    LogDecision::Warn => tracing::warn!(
                                        worker = %thread_name, key = %key, class, %error,
                                        "failed; will retry with a backoff"
                                    ),
                                    LogDecision::WarnStill => tracing::warn!(
                                        worker = %thread_name, key = %key, class, %error,
                                        "still not done after {failures} attempts; will retry"
                                    ),
                                    LogDecision::Debug => tracing::debug!(
                                        worker = %thread_name, key = %key, class, %error,
                                        "failed again; will retry"
                                    ),
                                }
                            }
                        }
                    }
                };
                loop {
                    enum Step<T> {
                        Job(T),
                        Retry(Pending<T>),
                        Barrier(std::sync::mpsc::Sender<()>, Vec<Pending<T>>),
                    }
                    let step = {
                        let mut queue = thread_shared.lock();
                        loop {
                            match queue.messages.pop_front() {
                                Some(Message::Barrier(done)) => {
                                    let all = queue.book.take_all();
                                    queue.barrier_left =
                                        all.iter().map(|p| p.key.clone()).collect();
                                    break Step::Barrier(done, all);
                                }
                                Some(Message::Job(job)) => {
                                    queue.running = Some(thread_key(&job));
                                    break Step::Job(job);
                                }
                                None => {}
                            }
                            if queue.closed {
                                return;
                            }
                            let now = Instant::now();
                            if let Some(pending) = queue.book.take_due(now) {
                                queue.running = Some(pending.key.clone());
                                break Step::Retry(pending);
                            }
                            queue = match queue.book.next_due() {
                                Some(due) => {
                                    thread_shared
                                        .wake
                                        .wait_timeout(queue, due.saturating_duration_since(now))
                                        .unwrap_or_else(|e| e.into_inner())
                                        .0
                                }
                                None => thread_shared
                                    .wake
                                    .wait(queue)
                                    .unwrap_or_else(|e| e.into_inner()),
                            };
                        }
                    };
                    match step {
                        Step::Retry(pending) => run(pending),
                        Step::Job(job) => {
                            let key = thread_key(&job);
                            run(Pending::new(key, job, Instant::now()));
                        }
                        Step::Barrier(done, all) => {
                            for pending in all {
                                run(pending);
                            }
                            thread_shared.lock().barrier_left.clear();
                            let _ = done.send(());
                        }
                    }
                }
            })
            .with_context(|| format!("starting the {name} thread"))?;
        Ok(Arc::new(Self { shared, key }))
    }

    /// Queues a job; never waits for the work. An unstarted job with the same key is replaced,
    /// and so is a failed one waiting for a retry (a retry of an older job never runs after
    /// a newer one).
    pub fn submit(&self, job: T) {
        let key = (self.key)(&job);
        let mut queue = self.shared.lock();
        queue.book.supersede(&key);
        let waiting = queue.messages.iter_mut().find_map(|message| match message {
            Message::Job(old) if (self.key)(old) == key => Some(old),
            _ => None,
        });
        match waiting {
            Some(old) => *old = job,
            None => queue.messages.push_back(Message::Job(job)),
        }
        drop(queue);
        self.shared.wake.notify_one();
    }

    /// Waits until every job submitted before this call is done (or replaced by a later one with
    /// its key, which then is done), at most `timeout`; the jobs that failed and wait for a
    /// retry are run once more at once, with lock waits that end with `timeout`. What got
    /// done and what did not: for a clean shutdown, and for tests.
    pub fn flush(&self, timeout: Duration) -> FlushReport {
        let (done, wait) = std::sync::mpsc::channel();
        let id = {
            let mut queue = self.shared.lock();
            let id = queue.next_flush;
            queue.next_flush += 1;
            queue.flushes.push((id, Instant::now() + timeout));
            queue.deadline = queue.flushes.iter().map(|(_, end)| *end).max();
            queue.messages.push_back(Message::Barrier(done));
            id
        };
        self.shared.wake.notify_one();
        let reached = wait.recv_timeout(timeout).is_ok();
        let mut queue = self.shared.lock();
        queue.flushes.retain(|(other, _)| *other != id);
        queue.deadline = queue.flushes.iter().map(|(_, end)| *end).max();
        let mut unwritten = queue.book.keys();
        // Over-reporting is fine, under-reporting is not: what is running, and what the barrier
        // took out of the book and has not run, count whether or not the flush was reached.
        unwritten.extend(queue.running.clone());
        unwritten.extend(queue.barrier_left.iter().cloned());
        if !reached {
            for message in &queue.messages {
                if let Message::Job(job) = message {
                    unwritten.push((self.key)(job));
                }
            }
        }
        unwritten.sort();
        unwritten.dedup();
        FlushReport { reached, unwritten }
    }

    /// The keys of the jobs that failed and wait for a retry.
    pub fn pending_keys(&self) -> Vec<String> {
        self.shared.lock().book.keys()
    }

    /// Makes the jobs waiting for a retry due now, without waiting out their backoff.
    #[cfg(test)]
    pub fn retry_now(&self) {
        self.shared.lock().book.make_due(Instant::now());
        self.shared.wake.notify_one();
    }
}

impl<T> Drop for Worker<T> {
    fn drop(&mut self) {
        self.shared.lock().closed = true;
        self.shared.wake.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    /// A worker whose work blocks on `gate` for the job named `(0, 0)`, reports every job it
    /// starts on `started` and every one it finishes on `done`.
    #[allow(clippy::type_complexity)]
    fn gated() -> (
        Arc<Worker<(u32, u32)>>,
        mpsc::Sender<()>,
        mpsc::Receiver<(u32, u32)>,
        mpsc::Receiver<(u32, u32)>,
    ) {
        let (open, gate) = mpsc::channel::<()>();
        let (start_tx, started) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let worker = Worker::spawn(
            "test-persist",
            |job: &(u32, u32)| job.0.to_string(),
            move |job, _| {
                let job = *job;
                let _ = start_tx.send(job);
                if job == (0, 0) {
                    let _ = gate.recv();
                }
                let _ = done_tx.send(job);
                Outcome::Done
            },
        )
        .unwrap();
        (worker, open, started, done)
    }

    const WAIT: Duration = Duration::from_secs(10);

    /// At most one waiting job per key, the latest one, in the place of the first; jobs of other
    /// keys keep their order; a job already running is not replaced.
    #[test]
    fn the_latest_job_for_a_key_replaces_an_unstarted_older_one() {
        let (worker, open, started, done) = gated();
        worker.submit((0, 0));
        assert_eq!(started.recv_timeout(WAIT).unwrap(), (0, 0));
        worker.submit((1, 1));
        worker.submit((1, 2));
        worker.submit((2, 0));
        worker.submit((1, 3));
        open.send(()).unwrap();
        assert!(worker.flush(WAIT).is_clean());
        let ran: Vec<_> = done.try_iter().collect();
        assert_eq!(ran, vec![(0, 0), (1, 3), (2, 0)]);
    }

    /// The memory is bounded too: a flood for one key leaves one job in the queue.
    #[test]
    fn a_flood_for_one_key_leaves_one_job_waiting() {
        let (worker, open, started, _done) = gated();
        worker.submit((0, 0));
        assert_eq!(started.recv_timeout(WAIT).unwrap(), (0, 0));
        for i in 0..10_000 {
            worker.submit((5, i));
        }
        assert_eq!(worker.shared.lock().messages.len(), 1);
        open.send(()).unwrap();
        assert!(worker.flush(WAIT).is_clean());
        assert_eq!(started.try_iter().collect::<Vec<_>>(), vec![(5, 9_999)]);
    }

    /// A flush that is not reached in time says so, and a later one gets there.
    #[test]
    fn flush_reports_whether_the_jobs_before_it_are_done() {
        let (worker, open, started, _done) = gated();
        worker.submit((0, 0));
        assert_eq!(started.recv_timeout(WAIT).unwrap(), (0, 0));
        worker.submit((1, 1));
        assert!(!worker.flush(Duration::from_millis(100)).reached);
        open.send(()).unwrap();
        assert!(worker.flush(WAIT).is_clean());
        assert_eq!(started.try_iter().collect::<Vec<_>>(), vec![(1, 1)]);
    }

    /// Dropping the worker does not lose the jobs already queued.
    #[test]
    fn jobs_queued_when_the_worker_is_dropped_still_run() {
        let (worker, open, started, done) = gated();
        worker.submit((0, 0));
        assert_eq!(started.recv_timeout(WAIT).unwrap(), (0, 0));
        worker.submit((1, 1));
        drop(worker);
        open.send(()).unwrap();
        assert_eq!(done.recv_timeout(WAIT).unwrap(), (0, 0));
        assert_eq!(done.recv_timeout(WAIT).unwrap(), (1, 1));
    }

    // ---- the retry book (explicit instants, no sleeping) ----

    fn pending(key: &str) -> Pending<u32> {
        Pending::new(key.to_string(), 0, Instant::now())
    }

    /// 1, 2, 4, ... seconds, at most 60, and no overflow for a huge count.
    #[test]
    fn the_backoff_doubles_up_to_its_cap() {
        let secs = |n| backoff(n).as_secs();
        assert_eq!(
            (1..=7).map(secs).collect::<Vec<_>>(),
            vec![1, 2, 4, 8, 16, 32, 60]
        );
        assert_eq!(secs(8), 60);
        assert_eq!(secs(u32::MAX), 60);
    }

    /// Each failure moves the due time by the next backoff step; a key is in the book once.
    #[test]
    fn the_book_schedules_each_failure_with_the_next_backoff() {
        let t0 = Instant::now();
        let mut book = RetryBook::new();
        let mut p = pending("a");
        let mut expected = vec![];
        for _ in 0..8 {
            book.fail(p, "io", t0);
            expected.push(book.next_due().unwrap() - t0);
            assert_eq!(book.len(), 1);
            p = book.take_all().pop().unwrap();
        }
        let secs: Vec<u64> = expected.iter().map(Duration::as_secs).collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 16, 32, 60, 60]);
    }

    /// A newer job for the key removes the pending entry; `next_due` is the earliest.
    #[test]
    fn the_book_drops_a_superseded_entry_and_knows_the_earliest_due() {
        let t0 = Instant::now();
        let mut book = RetryBook::new();
        assert!(book.next_due().is_none());
        let mut late = pending("late");
        late.failures = 3;
        book.fail(late, "io", t0);
        book.fail(pending("early"), "io", t0);
        assert_eq!(book.next_due(), Some(t0 + Duration::from_secs(1)));
        assert!(book.supersede("early"));
        assert!(!book.supersede("early"));
        assert_eq!(book.keys(), vec!["late".to_string()]);
        assert_eq!(book.next_due(), Some(t0 + Duration::from_secs(8)));
        assert!(book.take_due(t0 + Duration::from_secs(7)).is_none());
        assert!(book.take_due(t0 + Duration::from_secs(8)).is_some());
        assert_eq!(book.len(), 0);
    }

    /// Warn on the first failure and on a new class; debug after; one warn per ten minutes.
    #[test]
    fn the_log_decision_bounds_the_noise() {
        let t0 = Instant::now();
        let mut book = RetryBook::new();
        let mut step = |p: Pending<u32>, class, at| {
            let d = book.fail(p, class, at);
            (d, book.take_all().pop().unwrap())
        };
        let (d, p) = step(pending("a"), "busy", t0);
        assert_eq!(d, LogDecision::Warn);
        let (d, p) = step(p, "busy", t0 + Duration::from_secs(1));
        assert_eq!(d, LogDecision::Debug);
        let (d, p) = step(p, "io", t0 + Duration::from_secs(2));
        assert_eq!(d, LogDecision::Warn, "a changed class is logged at once");
        let (d, p) = step(p, "io", t0 + Duration::from_secs(601));
        assert_eq!(
            d,
            LogDecision::Debug,
            "ten minutes from the last warn, not before"
        );
        let (d, p) = step(p, "io", t0 + Duration::from_secs(602));
        assert_eq!(d, LogDecision::WarnStill);
        let (d, _) = step(p, "io", t0 + Duration::from_secs(603));
        assert_eq!(d, LogDecision::Debug);
    }

    // ---- the worker with retries ----

    /// A worker whose work answers from a script: `Retry` while `fail` holds a count, then Done.
    #[allow(clippy::type_complexity)]
    fn flaky(
        failures: u32,
    ) -> (
        Arc<Worker<(u32, u32)>>,
        Arc<std::sync::atomic::AtomicU32>,
        Arc<std::sync::atomic::AtomicU32>,
    ) {
        use std::sync::atomic::{AtomicU32, Ordering};
        let runs = Arc::new(AtomicU32::new(0));
        let left = Arc::new(AtomicU32::new(failures));
        let (r, l) = (Arc::clone(&runs), Arc::clone(&left));
        let worker = Worker::spawn(
            "test-flaky",
            |job: &(u32, u32)| job.0.to_string(),
            move |_, _| {
                r.fetch_add(1, Ordering::SeqCst);
                if l.load(Ordering::SeqCst) > 0 {
                    l.fetch_sub(1, Ordering::SeqCst);
                    Outcome::Retry {
                        class: "io",
                        error: "scripted".into(),
                    }
                } else {
                    Outcome::Done
                }
            },
        )
        .unwrap();
        (worker, runs, left)
    }

    /// A job that fails twice runs three times; `retry_now` makes each retry run at once.
    #[test]
    fn a_job_that_fails_is_run_again_until_it_is_done() {
        use std::sync::atomic::Ordering;
        let (worker, runs, _) = flaky(2);
        worker.submit((1, 1));
        let first = worker.flush(WAIT);
        // The flush itself runs the failed job once more (it ignores the backoff), twice
        // in all here; the third run needs the second flush.
        assert!(first.reached);
        assert_eq!(runs.load(Ordering::SeqCst), 2);
        assert_eq!(first.unwritten, vec!["1".to_string()]);
        worker.retry_now();
        assert!(worker.flush(WAIT).is_clean());
        assert_eq!(runs.load(Ordering::SeqCst), 3);
        assert!(worker.pending_keys().is_empty());
    }

    /// The thread retries by itself after the backoff (the first step is one second).
    #[test]
    fn a_failed_job_is_retried_by_the_thread_without_a_flush() {
        use std::sync::atomic::Ordering;
        let (worker, runs, _) = flaky(1);
        worker.submit((1, 1));
        let started = Instant::now();
        while runs.load(Ordering::SeqCst) < 2 {
            assert!(started.elapsed() < WAIT, "no retry came");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(worker.flush(WAIT).is_clean());
        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    /// A flush reports the key that still fails, and a newer job clears the pending retry.
    #[test]
    fn a_flush_names_the_failing_key_and_a_newer_job_supersedes_the_retry() {
        use std::sync::atomic::Ordering;
        let (worker, runs, left) = flaky(1000);
        worker.submit((7, 1));
        worker.submit((8, 1));
        let report = worker.flush(WAIT);
        assert!(report.reached);
        assert_eq!(report.unwritten, vec!["7".to_string(), "8".to_string()]);
        let before = runs.load(Ordering::SeqCst);
        left.store(0, Ordering::SeqCst);
        worker.submit((7, 2));
        let report = worker.flush(WAIT);
        assert!(report.is_clean());
        assert!(worker.pending_keys().is_empty());
        // (7, 2) ran once and 8 got through once; the thread's own retry of 8 (the 1 s backoff
        // may fall inside this test on a busy machine) may add runs, never fewer. The count
        // used to be compared for equality: flaky 4 in 30 runs.
        assert!(runs.load(Ordering::SeqCst) >= before + 2);
    }

    /// Jobs failing for ever do not grow the book beyond one entry per key.
    #[test]
    fn the_book_holds_one_entry_per_key_under_a_flood() {
        let (worker, _, _) = flaky(u32::MAX);
        for i in 0..200 {
            worker.submit((i % 3, i));
            if i % 20 == 0 {
                worker.flush(WAIT);
            }
        }
        worker.flush(WAIT);
        assert_eq!(worker.pending_keys().len(), 3);
    }

    /// While a flush is on, the work is told when its grace ends.
    #[test]
    fn the_work_sees_the_end_of_the_flush_grace() {
        let (tx, rx) = mpsc::channel();
        let worker = Worker::spawn(
            "test-deadline",
            |job: &u32| job.to_string(),
            move |_, attempt| {
                let _ = tx.send(attempt.lock_wait(Duration::from_secs(1)));
                Outcome::Done
            },
        )
        .unwrap();
        worker.submit(1);
        assert!(worker.flush(Duration::from_millis(200)).is_clean());
        let waits: Vec<_> = rx.try_iter().collect();
        assert_eq!(waits.len(), 1);
        assert!(waits[0] <= Duration::from_millis(200), "{waits:?}");
        worker.submit(2);
        assert!(worker.flush(WAIT).is_clean());
        assert_eq!(rx.try_recv().unwrap(), Duration::from_secs(1));
    }

    /// K1 residual 1: a flush that ends (here by its timeout) must not take the grace of another
    /// flush that is still on: the job that runs under the first one still sees its end.
    #[test]
    fn a_flush_that_ends_leaves_the_grace_of_another_that_is_on() {
        let (gate_tx, gate_rx) = mpsc::channel::<()>();
        let gate_rx = Mutex::new(gate_rx);
        let (seen_tx, seen_rx) = mpsc::channel();
        let worker = Arc::new(
            Worker::spawn(
                "test-two-flushes",
                |job: &u32| job.to_string(),
                move |job, attempt| {
                    if *job == 0 {
                        let _ = gate_rx.lock().unwrap().recv();
                    } else {
                        let _ = seen_tx.send(attempt.deadline);
                    }
                    Outcome::Done
                },
            )
            .unwrap(),
        );
        worker.submit(0);
        worker.submit(1);
        let long = {
            let worker = Arc::clone(&worker);
            std::thread::spawn(move || worker.flush(Duration::from_secs(20)))
        };
        // The long flush is on before the short one starts.
        std::thread::sleep(Duration::from_millis(300));
        let short = worker.flush(Duration::from_millis(100));
        assert!(!short.reached, "job 0 holds the worker");
        gate_tx.send(()).unwrap();
        let deadline = seen_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert!(
            deadline.is_some(),
            "the end of the short flush took the grace of the long one"
        );
        assert!(long.join().unwrap().is_clean());
    }

    /// A flush that times out while the barrier is running the retry book's entries still names
    /// the entries the barrier took but has not run yet (over-reporting is fine, under-reporting
    /// is not).
    #[test]
    fn a_timed_out_flush_names_every_pending_key() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let slow = Arc::new(AtomicBool::new(false));
        let s = Arc::clone(&slow);
        let worker = Worker::spawn(
            "test-persist",
            |job: &(u32, u32)| job.0.to_string(),
            move |job, _| {
                if job.0 == 1 && s.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(600));
                }
                Outcome::Retry {
                    class: "busy",
                    error: "held".into(),
                }
            },
        )
        .unwrap();
        worker.submit((1, 0));
        worker.submit((2, 0));
        worker.submit((3, 0));
        let first = worker.flush(WAIT);
        assert!(first.reached);
        assert_eq!(first.unwritten.len(), 3, "{first:?}");
        slow.store(true, Ordering::SeqCst);
        let report = worker.flush(Duration::from_millis(100));
        assert!(!report.reached);
        assert_eq!(
            report.unwritten,
            vec!["1".to_string(), "2".to_string(), "3".to_string()],
            "keys taken by the barrier but not yet run are not reported"
        );
    }
}
