//! The running node: what the L3 and L4 modules built, joined into one
//! object a consumer asks for streams (TODO.md L4h7). Library only; the
//! agent and the commands that need a node (`reach`, `expose`, `stdio`)
//! are built on this.
//!
//! [`Node::start`] spawns and owns three tasks:
//!
//! * [`run_session`], the L3 session with the relay (protocol.md 3 and 4):
//!   dialing, the handshake, reconnecting with backoff, and the SEND/RECV
//!   data plane;
//! * the L4 router ([`new_router`], TODO.md L4h6), which turns that
//!   session's records into L4 sessions, answers peers' `init`s and runs
//!   the handshakes callers ask for;
//! * a server, which for every L4 session that comes up, **in either
//!   role**, runs [`accept_loop`] on it: a session is bidirectional, so the
//!   peer may open streams over a session this node initiated as well as
//!   over one it answered. Each inbound OPEN is authorized against the
//!   Policy ([`PolicyAuthorizer`]) and, if allowed, handed to the node's
//!   [`ServiceHandler`].
//!
//! **Asking for a stream** ([`Node::open_stream`]): the router finds or
//! creates the L4 session to that peer in that network (concurrent callers
//! share one handshake), then the OPEN exchange runs on it (protocol.md
//! 5.3). A stream lives exactly as long as its L4 session, which ends with
//! the L3 attachment it was opened under (a relay reconnect), with the peer
//! restarting, with a dead peer or with a revocation (decision 0001's first
//! consequence), so a caller's contract is "a stream may be reset at any
//! time; ask again". The next `open_stream` after such an end starts a new
//! handshake.
//!
//! **Judgment calls**, none dictated by protocol.md:
//!
//! * **The network is named by the caller.** protocol.md 12's
//!   `node/service` addressing names none, and a node may be in several
//!   networks; picking one for the caller would be a guess. A front end
//!   with a single network can supply it itself.
//! * **`open_stream` does not wait for the relay.** With no L3 attachment
//!   it fails at once with [`EnsureError::NotAttached`]; a caller that wants
//!   to wait (right after [`Node::start`], say) uses [`Node::wait_attached`].
//! * **Nothing is retried.** A session can end between the router handing
//!   it out and the OPEN going over it, and a failure after the OPEN
//!   header went out may have reached the peer, which may already have
//!   acted on it; whether repeating that is harmless depends on the
//!   service, so the caller decides. The error says which stage failed
//!   ([`NodeOpenError`]).
//! * **The stream type is [`menzil_stream::Stream`] for now.** TODO.md's
//!   `yamux::Stream` newtype (the force-reset line, TOBEDECIDED item 11)
//!   will replace it, and L4i, which dispatches an accepted stream to a
//!   local target, defines what serving means; until then the default
//!   handler is [`RefuseAll`].
//!
//! Dropping a [`Node`] aborts its tasks: the relay connection closes and
//! every session and stream of it ends. [`Node::shutdown`] does the same
//! and waits for the tasks to finish.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use menzil_proto::{ErrorCode, NetworkId, NodeId, OpenTarget, ProtoError, ServiceId};
use menzil_stream::{OpenRefusal, OpenRequest, ServiceHandler, Stream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::admission::PolicyAuthorizer;
use crate::l4_router::{
    EnsureError, RouterConfig, RouterHandle, RouterParts, SessionReady, new_router,
};
use crate::l4_session::E2E_PROTO_TAG;
use crate::l5_stream::{OpenStreamError, accept_loop, open};
use crate::outbound::{Epoch, SendBudgets};
use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;
use crate::session::{SessionConfig, SessionEvent, run_session};

/// Capacity of each of the two channels between [`run_session`] and the
/// router. Any size works (`run_session` is written not to deadlock on a
/// small one); this only sets how much may queue while the router is busy.
const L3_CHANNEL_CAPACITY: usize = 256;

/// Everything [`Node::start`] needs.
pub struct NodeConfig {
    /// The relay to attach to and how, this node's identity (its
    /// `identity` also drives the L4 handshakes), the networks it claims
    /// and its capabilities. `e2e_protos` must include the L4 session
    /// protocol, 0x01.
    pub session: SessionConfig,
    /// The process environment's proxy settings, as [`run_session`] takes
    /// them (`HTTPS_PROXY` and friends), passed in rather than read so a
    /// test controls them.
    pub env: HashMap<String, String>,
    /// The verified Policies this node holds. The out-of-band seed (the
    /// stopgap until `menzil:docs`, TODO.md L4j) goes in through
    /// [`Node::policies`] or here before the node starts.
    pub policies: Arc<PolicyStore>,
    /// The Rosters this node holds; the L3 session also stores the ones
    /// the relay sends it (protocol.md 4.3).
    pub rosters: Arc<RosterStore>,
}

/// Why [`Node::start`] refused to start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// The local NodeCert does not decode.
    #[error("the local NodeCert does not decode: {0}")]
    Identity(#[from] ProtoError),
    /// `SessionConfig::e2e_protos` lacks 0x01, so no peer's `init` would
    /// ever be forwarded to this node and none of its own would be.
    #[error("SessionConfig::e2e_protos must include the L4 session protocol, 0x01")]
    NoL4Protocol,
}

/// Why [`Node::open_stream`] gave no stream.
#[derive(Debug, thiserror::Error)]
pub enum NodeOpenError {
    /// There was no session to the peer, and none could be made.
    #[error("no session to the peer: {0}")]
    Session(#[from] EnsureError),
    /// The session was there, but the OPEN exchange failed or was refused.
    #[error("{0}")]
    Open(#[from] OpenStreamError),
}

/// The handler of a node that serves nothing, which is what a node is until
/// TODO.md L4i exists. An OPEN that passes the grant check is refused with
/// [`ErrorCode::NoGrant`], the nearest code the registry has: there is none
/// for "granted, but not served here", and L4i, which defines serving, is
/// where to add one if it is wanted. A peer without the grant is refused
/// earlier, before this handler is asked, so it learns nothing about what
/// is configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAll;

impl ServiceHandler<Stream> for RefuseAll {
    type Handling = std::future::Ready<()>;

    fn accepts(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Err(OpenRefusal {
            code: ErrorCode::NoGrant,
            msg: "this node serves no services".to_string(),
        })
    }

    fn handle(&self, _stream: Stream, _request: OpenRequest) -> Self::Handling {
        std::future::ready(())
    }
}

/// A running node. See the module docs.
pub struct Node {
    local_node_id: NodeId,
    router: RouterHandle,
    attachment: watch::Receiver<Option<Epoch>>,
    events: Option<mpsc::Receiver<SessionEvent>>,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    tasks: Vec<JoinHandle<()>>,
}

impl Node {
    /// Starts the node: connects to the relay in the background, answers
    /// peers, and serves inbound streams through `handler` (pass
    /// [`RefuseAll`] to serve nothing). Must be called inside a Tokio
    /// runtime; returns at once, before the node is attached (see
    /// [`Self::wait_attached`]).
    pub fn start<H>(config: NodeConfig, handler: H) -> Result<Self, StartError>
    where
        H: ServiceHandler<Stream> + Send + Sync + 'static,
        H::Handling: Send + 'static,
    {
        let NodeConfig {
            session,
            env,
            policies,
            rosters,
        } = config;
        if !session.e2e_protos.contains(&E2E_PROTO_TAG) {
            return Err(StartError::NoL4Protocol);
        }
        let local_node_id = session.identity.node_cert.decode()?.node_id;
        let router_config = RouterConfig::new(
            session.identity.clone(),
            session.dial.connection_info.relay_node_id,
            policies.clone(),
            rosters.clone(),
            SendBudgets::new(),
        )?;

        let (events_tx, events_rx) = mpsc::channel(L3_CHANNEL_CAPACITY);
        let (outbound_tx, outbound_rx) = mpsc::channel(L3_CHANNEL_CAPACITY);
        let RouterParts {
            handle,
            ready,
            passthrough,
            attachment,
            task: router,
        } = new_router(router_config, outbound_tx, events_rx);

        let tasks = vec![
            tokio::spawn(run_session(
                session,
                env,
                events_tx,
                outbound_rx,
                rosters.clone(),
            )),
            tokio::spawn(router),
            tokio::spawn(serve_sessions(
                ready,
                policies.clone(),
                rosters.clone(),
                local_node_id,
                Arc::new(handler),
            )),
        ];
        Ok(Self {
            local_node_id,
            router: handle,
            attachment,
            events: Some(passthrough),
            policies,
            rosters,
            tasks,
        })
    }

    /// This node's own NodeId.
    pub fn local_node_id(&self) -> NodeId {
        self.local_node_id
    }

    /// The Policies this node holds, to seed or update.
    pub fn policies(&self) -> &Arc<PolicyStore> {
        &self.policies
    }

    /// The Rosters this node holds, to seed or update.
    pub fn rosters(&self) -> &Arc<RosterStore> {
        &self.rosters
    }

    /// Waits up to `within` for the node to be attached to its relay and
    /// returns the epoch it is attached under, or `None` if it is not by
    /// then. Returns at once if it already is.
    pub async fn wait_attached(&self, within: Duration) -> Option<Epoch> {
        let mut attachment = self.attachment.clone();
        match tokio::time::timeout(within, attachment.wait_for(|epoch| epoch.is_some())).await {
            Ok(Ok(epoch)) => *epoch,
            _ => None,
        }
    }

    /// A stream to `service` on `peer` in `network`, once the peer has
    /// authorized it (protocol.md 5.3). `target` is only for the
    /// `egress:*` service. Neither waits for the relay nor retries; see the
    /// module docs.
    pub async fn open_stream(
        &self,
        peer: NodeId,
        network: NetworkId,
        service: ServiceId,
        target: Option<OpenTarget>,
    ) -> Result<Stream, NodeOpenError> {
        let session = self.router.ensure_session(peer, network).await?;
        Ok(open(&session, service, target).await?)
    }

    /// The L3 records the router does not consume, and a copy of every
    /// `Attached` and `Detached` (see [`RouterParts::passthrough`]), for the
    /// consumers that need them (ADVERTISE_ACK for `expose`, ADMIT_* for
    /// admission). Yields the receiver once; `None` after that. Bounded:
    /// when its reader falls behind, further events are dropped (with a
    /// warning at most once a second), so take it only if it will be
    /// read.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<SessionEvent>> {
        self.events.take()
    }

    /// Stops the node and waits for its three tasks (the relay session, the
    /// router and the server) to finish. The relay connection closes and
    /// every session ends, but the session tasks, and the ones that serve
    /// accepted streams, wind down just after this returns rather than
    /// before it.
    pub async fn shutdown(mut self) {
        let tasks = std::mem::take(&mut self.tasks);
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// [`ServiceHandler`] over a handler shared by every session's accept loop.
struct SharedHandler<H>(Arc<H>);

impl<H: ServiceHandler<Stream>> ServiceHandler<Stream> for SharedHandler<H> {
    type Handling = H::Handling;

    fn accepts(&self, request: &OpenRequest) -> Result<(), OpenRefusal> {
        self.0.accepts(request)
    }

    fn handle(&self, stream: Stream, request: OpenRequest) -> Self::Handling {
        self.0.handle(stream, request)
    }
}

/// Runs an accept loop for every session the router announces, until the
/// router is gone. A loop ends by itself when its session does.
async fn serve_sessions<H>(
    mut ready: mpsc::UnboundedReceiver<SessionReady>,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    local_node_id: NodeId,
    handler: Arc<H>,
) where
    H: ServiceHandler<Stream> + Send + Sync + 'static,
    H::Handling: Send + 'static,
{
    while let Some(session) = ready.recv().await {
        // The handle is dropped here, with the rest of `session`: the
        // router's table holds its own clone for as long as the session is
        // the one in use.
        let SessionReady {
            network_id,
            mut acceptor,
            ..
        } = session;
        let authorizer =
            PolicyAuthorizer::new(policies.clone(), rosters.clone(), network_id, local_node_id);
        let handler = SharedHandler(Arc::clone(&handler));
        tokio::spawn(async move {
            accept_loop(&mut acceptor, authorizer, handler).await;
        });
    }
}
