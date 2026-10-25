//! A thread that does slow, blocking work one job at a time, in the order the jobs were
//! submitted: how documents a relay or a node adopts over the network reach the disk.
//!
//! The work takes file locks (up to ten seconds of waiting) and writes files, which an async
//! task must not do and which a caller that already holds the same lock (the steward loop
//! adopts what it has just written, under the network lock) would deadlock on if it ran inline.
//! A job whose work fails is the work's own business to report; the worker goes on with the
//! next one, and a panic in the work is caught and logged for the same reason.

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use anyhow::{Context, Result};

enum Message<T> {
    Job(T),
    Barrier(mpsc::Sender<()>),
}

/// A worker thread running `work` on each job submitted. The thread ends once the worker, and
/// with it every clone of its [`Arc`], is gone and the jobs already submitted are done.
pub struct Worker<T> {
    sender: Mutex<mpsc::Sender<Message<T>>>,
}

impl<T: Send + 'static> Worker<T> {
    /// Starts the thread, named `name`.
    pub fn spawn(name: &str, mut work: impl FnMut(T) + Send + 'static) -> Result<Arc<Self>> {
        let (sender, receiver) = mpsc::channel::<Message<T>>();
        std::thread::Builder::new()
            .name(name.to_string())
            .spawn(move || {
                for message in receiver {
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
            sender: Mutex::new(sender),
        }))
    }

    /// Queues a job; never waits for the work.
    pub fn submit(&self, job: T) {
        if self.sender.lock().unwrap().send(Message::Job(job)).is_err() {
            tracing::warn!("the background thread is gone; a job was dropped");
        }
    }

    /// Waits until every job submitted before this call is done, at most `timeout`. Whether it
    /// got there: for a clean shutdown, and for tests.
    pub fn flush(&self, timeout: Duration) -> bool {
        let (done, wait) = mpsc::channel();
        if self
            .sender
            .lock()
            .unwrap()
            .send(Message::Barrier(done))
            .is_err()
        {
            return false;
        }
        wait.recv_timeout(timeout).is_ok()
    }
}
