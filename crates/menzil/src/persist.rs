//! A thread that does slow, blocking work one job at a time, in the order the jobs were
//! submitted: how documents a relay or a node adopts over the network reach the disk.
//!
//! The work takes file locks (up to ten seconds of waiting) and writes files, which an async
//! task must not do and which a caller that already holds the same lock (the steward loop
//! adopts what it has just written, under the network lock) would deadlock on if it ran inline.
//! A job whose work fails is the work's own business to report; the worker goes on with the
//! next one, and a panic in the work is caught and logged for the same reason.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};

enum Message<T> {
    Job(T),
    Barrier(std::sync::mpsc::Sender<()>),
}

struct Queue<T> {
    messages: VecDeque<Message<T>>,
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

/// Whether two jobs have the same key.
type SameKey<T> = Box<dyn Fn(&T, &T) -> bool + Send + Sync>;

/// A worker thread running `work` on each job submitted. At most one job per key waits in the
/// queue: a job submitted while an older one with the same key has not started replaces it (in
/// the older one's place), so a flood for one key costs memory for one job and one run of the
/// work. The thread ends once the worker is gone and the jobs already submitted are done.
pub struct Worker<T> {
    shared: Arc<Shared<T>>,
    same_key: SameKey<T>,
}

impl<T: Send + 'static> Worker<T> {
    /// Starts the thread, named `name`. Two jobs with the same `key` are one job to the queue.
    pub fn spawn<K: PartialEq>(
        name: &str,
        key: impl Fn(&T) -> K + Send + Sync + 'static,
        mut work: impl FnMut(T) + Send + 'static,
    ) -> Result<Arc<Self>> {
        let shared = Arc::new(Shared {
            queue: Mutex::new(Queue {
                messages: VecDeque::new(),
                closed: false,
            }),
            wake: Condvar::new(),
        });
        let thread_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                loop {
                    let message = {
                        let mut queue = thread_shared.lock();
                        loop {
                            if let Some(message) = queue.messages.pop_front() {
                                break message;
                            }
                            if queue.closed {
                                return;
                            }
                            queue = thread_shared
                                .wake
                                .wait(queue)
                                .unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    match message {
                        Message::Job(job) => {
                            let outcome =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    work(job)
                                }));
                            if outcome.is_err() {
                                tracing::warn!("a background job panicked; going on with the next");
                            }
                        }
                        Message::Barrier(done) => {
                            let _ = done.send(());
                        }
                    }
                }
            })
            .with_context(|| format!("starting the {name} thread"))?;
        Ok(Arc::new(Self {
            shared,
            same_key: Box::new(move |a, b| key(a) == key(b)),
        }))
    }

    /// Queues a job; never waits for the work. An unstarted job with the same key is replaced.
    pub fn submit(&self, job: T) {
        let mut queue = self.shared.lock();
        let waiting = queue.messages.iter_mut().find_map(|message| match message {
            Message::Job(old) if (self.same_key)(old, &job) => Some(old),
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
    /// its key, which then is done), at most `timeout`. Whether it got there: for a clean
    /// shutdown, and for tests.
    pub fn flush(&self, timeout: Duration) -> bool {
        let (done, wait) = std::sync::mpsc::channel();
        self.shared
            .lock()
            .messages
            .push_back(Message::Barrier(done));
        self.shared.wake.notify_one();
        wait.recv_timeout(timeout).is_ok()
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
            |job: &(u32, u32)| job.0,
            move |job| {
                let _ = start_tx.send(job);
                if job == (0, 0) {
                    let _ = gate.recv();
                }
                let _ = done_tx.send(job);
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
        assert!(worker.flush(WAIT));
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
        assert!(worker.flush(WAIT));
        assert_eq!(started.try_iter().collect::<Vec<_>>(), vec![(5, 9_999)]);
    }

    /// A flush that is not reached in time says so, and a later one gets there.
    #[test]
    fn flush_reports_whether_the_jobs_before_it_are_done() {
        let (worker, open, started, _done) = gated();
        worker.submit((0, 0));
        assert_eq!(started.recv_timeout(WAIT).unwrap(), (0, 0));
        worker.submit((1, 1));
        assert!(!worker.flush(Duration::from_millis(100)));
        open.send(()).unwrap();
        assert!(worker.flush(WAIT));
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
}
