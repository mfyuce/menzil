//! Who may use `menzil:docs` and how often (protocol.md 5.1, 5.5): the node-side wiring of the
//! [`crate::docs`] library into the accept loop of an L4 session.
//!
//! * The grant exemption and the per-OPEN Roster check are [`crate::PolicyAuthorizer`]'s: it
//!   lets `menzil:docs` through for a peer that is an unrevoked member of the session's network
//!   in the held Roster, looked up again on every OPEN, and on a docs only session it lets
//!   nothing else through.
//! * [`DocsGate`] is the rate limit: one docs stream per peer at a time, four in all, six per peer
//!   per minute. An OPEN past a limit is answered `rate_limited`.
//! * [`SessionHandler`] sits in front of the node's own [`ServiceHandler`] (`LocalServices` in
//!   production) for one session: `menzil:docs` goes to [`crate::docs::serve`] over the node's
//!   stores and never to the inner handler, and on a docs only session nothing else is served.
//!   A docs only session is ended with CLOSE `docs_only` as soon as its one stream is over.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use menzil_proto::{ErrorCode, NodeId};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use tokio::time::Instant;

use crate::admission::is_docs_service;
use crate::docs::{DocsParams, STREAM_DEADLINE, ServeMode, StoreDocs, serve};
use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;

/// The limits on `menzil:docs` streams (protocol.md 5.5).
#[derive(Debug, Clone, Copy)]
pub struct DocsLimits {
    /// Streams per peer at a time. Default 1.
    pub per_peer_at_once: usize,
    /// Streams in all, over every session. Default 4.
    pub in_all: usize,
    /// Streams a peer may start in one [`Self::window`]. Default 6.
    pub per_peer_per_window: usize,
    /// The window of [`Self::per_peer_per_window`]. Default one minute.
    pub window: Duration,
}

impl Default for DocsLimits {
    fn default() -> Self {
        Self {
            per_peer_at_once: 1,
            in_all: 4,
            per_peer_per_window: 6,
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Default)]
struct GateState {
    active: usize,
    active_by_peer: HashMap<NodeId, usize>,
    started: HashMap<NodeId, VecDeque<Instant>>,
}

/// Counts the `menzil:docs` streams of a node: shared by every session.
pub struct DocsGate {
    limits: DocsLimits,
    state: Mutex<GateState>,
}

/// One `menzil:docs` stream's place under the limits; dropping it gives the place back (the
/// minute count keeps it).
#[must_use]
pub struct DocsPermit {
    gate: Arc<DocsGate>,
    peer: NodeId,
}

impl Drop for DocsPermit {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active = state.active.saturating_sub(1);
        if let Some(count) = state.active_by_peer.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.active_by_peer.remove(&self.peer);
            }
        }
    }
}

impl DocsGate {
    /// A gate with these limits.
    pub fn new(limits: DocsLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: Mutex::default(),
        })
    }

    /// A place for one more stream of `peer`, or `None` when a limit says no. A refusal costs the
    /// peer nothing against the per minute count.
    pub fn try_acquire(self: &Arc<Self>, peer: NodeId) -> Option<DocsPermit> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.active_by_peer.get(&peer).copied().unwrap_or(0) >= self.limits.per_peer_at_once {
            return None;
        }
        if state.active >= self.limits.in_all {
            return None;
        }
        // Forget what is older than the window, for everyone, so that the map holds only peers
        // that were active within it.
        let window = self.limits.window;
        state.started.retain(|_, times| {
            while times
                .front()
                .is_some_and(|t| now.saturating_duration_since(*t) >= window)
            {
                times.pop_front();
            }
            !times.is_empty()
        });
        let recent = state.started.entry(peer).or_default();
        if recent.len() >= self.limits.per_peer_per_window {
            return None;
        }
        recent.push_back(now);
        state.active += 1;
        *state.active_by_peer.entry(peer).or_default() += 1;
        Some(DocsPermit {
            gate: Arc::clone(self),
            peer,
        })
    }
}

/// What a [`SessionHandler`] prepared in `open` for `handle`.
pub enum SessionOpened<T> {
    /// A `menzil:docs` stream, with its place under the limits.
    Docs(DocsPermit),
    /// Whatever the inner handler prepared.
    Inner(T),
}

/// The handler of one L4 session. See the module docs.
pub struct SessionHandler<H> {
    inner: Arc<H>,
    gate: Arc<DocsGate>,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    /// `Some` on a docs only session: what ends the session once its one stream is over.
    docs_only: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl<H> SessionHandler<H> {
    /// The handler of an ordinary session: `menzil:docs` (fetch and push) and then `inner`.
    pub fn full(
        inner: Arc<H>,
        gate: Arc<DocsGate>,
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
    ) -> Self {
        Self {
            inner,
            gate,
            policies,
            rosters,
            docs_only: None,
        }
    }

    /// The handler of a docs only session this node answered: one `menzil:docs` push and nothing
    /// else. `end_session` is called when that stream is over, whatever came of it (the node
    /// passes a closure that closes the session with CLOSE `docs_only`).
    pub fn docs_only(
        inner: Arc<H>,
        gate: Arc<DocsGate>,
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        end_session: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner,
            gate,
            policies,
            rosters,
            docs_only: Some(Arc::new(end_session)),
        }
    }
}

fn no_grant() -> OpenRefusal {
    OpenRefusal {
        code: ErrorCode::NoGrant,
        msg: "no grant".to_string(),
    }
}

impl<H> ServiceHandler<Stream> for SessionHandler<H>
where
    H: ServiceHandler<Stream> + Send + Sync + 'static,
    H::Handling: Send + 'static,
{
    type Opened = SessionOpened<H::Opened>;
    type Handling = Pin<Box<dyn Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<Self::Opened, OpenRefusal> {
        if is_docs_service(&request.service) {
            // The authorizer has let the OPEN through, so the peer is an unrevoked member; what
            // is left is how much of this service the node gives it at once.
            return match self.gate.try_acquire(request.initiator) {
                Some(permit) => Ok(SessionOpened::Docs(permit)),
                None => Err(OpenRefusal {
                    code: ErrorCode::RateLimited,
                    msg: "too many documents streams".to_string(),
                }),
            };
        }
        if self.docs_only.is_some() {
            return Err(no_grant());
        }
        self.inner.open(request).await.map(SessionOpened::Inner)
    }

    fn handle(&self, stream: Stream, request: OpenRequest, opened: Self::Opened) -> Self::Handling {
        match opened {
            SessionOpened::Inner(opened) => Box::pin(self.inner.handle(stream, request, opened)),
            SessionOpened::Docs(permit) => {
                let policies = Arc::clone(&self.policies);
                let rosters = Arc::clone(&self.rosters);
                let end_session = self.docs_only.clone();
                Box::pin(async move {
                    run_docs(stream, &request, &rosters, &policies, end_session.is_some()).await;
                    drop(permit);
                    if let Some(end_session) = end_session {
                        // One try per docs only session, whatever came of it.
                        end_session();
                    }
                })
            }
        }
    }
}

/// How long a docs only session waits, after answering, for the opener to finish the stream
/// before it is closed anyway.
const DOCS_ONLY_FLUSH_GRACE: Duration = Duration::from_secs(5);

/// Reads and drops whatever the peer still sends until it finishes (or resets) the stream. At
/// most a few kilobytes: this only exists to see the end.
async fn wait_for_peer_to_finish(stream: &mut Stream) {
    let mut buf = [0u8; 256];
    for _ in 0..16 {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Serves one `menzil:docs` stream whose OPEN_ACK has gone out, over the node's own stores.
async fn run_docs(
    mut stream: Stream,
    request: &OpenRequest,
    rosters: &RosterStore,
    policies: &PolicyStore,
    docs_only: bool,
) {
    let docs = StoreDocs::new(rosters, policies, request.network_id);
    let params = DocsParams {
        network_id: request.network_id,
        now: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        deadline: STREAM_DEADLINE,
    };
    let mode = if docs_only {
        ServeMode::PushOnly
    } else {
        ServeMode::Full
    };
    match serve(&mut stream, docs, docs, &params, mode).await {
        Ok(_) => {
            let _ = stream.close().await;
            if docs_only {
                // The session is about to be closed, and a CLOSE does not wait for the
                // frames still on their way: let the opener read the `result` and finish
                // its side first (or give up on it after a moment).
                let _ = tokio::time::timeout(
                    DOCS_ONLY_FLUSH_GRACE,
                    wait_for_peer_to_finish(&mut stream),
                )
                .await;
            }
        }
        Err(error) => {
            tracing::debug!(peer = %request.initiator, %error, "a menzil:docs stream failed");
            stream.reset();
        }
    }
}

#[cfg(test)]
mod tests;
