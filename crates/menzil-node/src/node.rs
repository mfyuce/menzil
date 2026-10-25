//! The running node: what the L3 and L4 modules built, joined into one
//! object a consumer asks for streams (TODO.md L4h7). Library only; the
//! agent and the commands that need a node (`reach`, `expose`, `stdio`)
//! are built on this.
//!
//! [`Node::start`] spawns and owns these tasks:
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
//!   [`ServiceHandler`];
//! * the revalidator (`revalidate`, protocol.md 5.3, L4k): one task that asks again, whenever
//!   the Roster or the Policy changes and whenever a grant, the documents or a certificate
//!   expire, whether each session may go on (else CLOSE `grant_removed`) and whether each
//!   served stream still has its grant (else it is reset);
//! * the document sync tasks (`docs_sync`, protocol.md 5.5 and 7.3): the watch
//!   that fetches the Policy once the Roster is ahead of it, and one expiry
//!   timer per claimed network. The comparison of seqs when a session comes up
//!   runs in the server above, on the session's own task.
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
//! * **The stream type is [`menzil_stream::Stream`]**: reading one that was
//!   reset is an error, not an end of file, and [`menzil_stream::Stream::reset`]
//!   aborts it in any state. L4i, which dispatches an accepted stream to a
//!   local target, defines what serving means; until then the default
//!   handler is [`RefuseAll`].
//!
//! Dropping a [`Node`] aborts its tasks: the relay connection closes and
//! every session and stream of it ends, but nothing tells the peers, who
//! learn it from the dead peer timeout (about 40 s). [`Node::shutdown`] does
//! the same and waits for the tasks to finish. A node that stops on purpose
//! calls [`Node::close_gracefully`] first: every session ends with a CLOSE
//! `shutting_down`, the relay session writes them out and closes its
//! connection politely, and the peers reset the streams at once (protocol.md
//! 5.2).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use menzil_e2e::Role;
use menzil_proto::{ErrorCode, NetworkId, NodeId, OpenTarget, ProtoError, ServiceId};
use menzil_stream::{Authorizer, OpenDecision, OpenRefusal, OpenRequest, ServiceHandler, Stream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::admission::PolicyAuthorizer;
use crate::docs_access::{DocsGate, DocsLimits, SessionHandler};
use crate::docs_sync::{DocsSync, PushReport, SyncConfig};
use crate::l4_router::{
    EnsureError, RouterConfig, RouterHandle, RouterParts, SessionReady, new_router,
};
use crate::l4_session::{CloseReason, E2E_PROTO_TAG, L4SessionHandle};
use crate::l5_stream::{AcceptedStreams, OpenStreamError, accept_loop, accept_loop_tracked, open};
use crate::outbound::{Epoch, SendBudgets};
use crate::policy_store::PolicyStore;
use crate::revalidate::{Kind, Revalidator};
use crate::roster_store::RosterStore;
use crate::session::{SessionConfig, SessionEvent, run_session_until};

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

/// The handler of a node that serves nothing: what a node is until it is
/// given [`crate::LocalServices`] or a handler of its own. An OPEN that
/// passes the grant check is refused with [`ErrorCode::UnknownService`]. A
/// peer without the grant is refused earlier, before this handler is
/// asked, so it learns nothing about what is configured.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseAll;

impl ServiceHandler<Stream> for RefuseAll {
    type Opened = ();
    type Handling = std::future::Ready<()>;

    async fn open(&self, _request: &OpenRequest) -> Result<(), OpenRefusal> {
        Err(OpenRefusal {
            code: ErrorCode::UnknownService,
            msg: "this node serves no services".to_string(),
        })
    }

    fn handle(&self, _stream: Stream, _request: OpenRequest, _opened: ()) -> Self::Handling {
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
    sync: Arc<DocsSync>,
    /// Tells the relay session to write what it holds and close.
    stop_session: watch::Sender<bool>,
    /// Turns `true` when the relay session task has returned.
    session_ended: watch::Receiver<bool>,
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
        Self::start_with_sync(config, handler, SyncConfig::default())
    }

    /// [`Self::start`] with other timing for the document sync tasks (protocol.md 5.5, 7.3; see
    /// [`SyncConfig`]).
    pub fn start_with_sync<H>(
        config: NodeConfig,
        handler: H,
        sync_config: SyncConfig,
    ) -> Result<Self, StartError>
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
        let local_cert = session.identity.node_cert.decode()?;
        let (local_node_id, local_serial) = (local_cert.node_id, local_cert.serial);
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

        let sync = DocsSync::new(
            handle.clone(),
            rosters.clone(),
            policies.clone(),
            local_node_id,
            sync_config,
        );
        let networks = session.networks.clone();
        let revalidator = Revalidator::new(
            policies.clone(),
            rosters.clone(),
            local_node_id,
            local_serial,
        );
        let (stop_session, stop_rx) = watch::channel(false);
        let (ended_tx, session_ended) = watch::channel(false);
        let mut tasks = vec![
            tokio::spawn({
                let rosters = rosters.clone();
                async move {
                    run_session_until(session, env, events_tx, outbound_rx, rosters, stop_rx).await;
                    let _ = ended_tx.send(true);
                }
            }),
            tokio::spawn(router),
            tokio::spawn(serve_sessions(
                ready,
                policies.clone(),
                rosters.clone(),
                local_node_id,
                local_serial,
                Arc::new(handler),
                DocsGate::new(DocsLimits::default()),
                Some(sync.clone()),
                Some(revalidator.clone()),
            )),
            // Grants, sessions and served streams, asked again on every change (protocol.md 5.3).
            tokio::spawn(revalidator.run()),
            // A Roster newer than the Policy: fetch the Policy (protocol.md 5.5).
            tokio::spawn(sync.clone().run_roster_watch(networks.clone())),
        ];
        // Documents about to expire: ask for new ones (protocol.md 7.3).
        for network_id in networks {
            tasks.push(tokio::spawn(sync.clone().run_expiry(network_id)));
        }
        Ok(Self {
            local_node_id,
            router: handle,
            attachment,
            events: Some(passthrough),
            policies,
            rosters,
            sync,
            stop_session,
            session_ended,
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

    /// For a node that issued new documents (a steward node that renewed, a device where the
    /// owner ran `admit`): pushes the held Roster and Policy to every unrevoked member of
    /// `network_id`, eight at a time, retrying a member that does not answer after 1, 5 and 30
    /// minutes and 2 hours (protocol.md 5.5). Takes as long as that schedule needs: spawn it.
    /// The relay gets a newer Roster by itself, as soon as the store takes it.
    pub async fn push_to_members(&self, network_id: NetworkId) -> PushReport {
        self.sync.push_to_members(network_id).await
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

    /// Ends the node the polite way, within `grace`: every L4 session is
    /// closed with a CLOSE `shutting_down` (so its peer ends it and resets its
    /// streams at once), the relay session writes those out and closes its
    /// connection with a WebSocket Close, and no session is opened from now
    /// on ([`Node::open_stream`] fails with [`EnsureError::ShuttingDown`]).
    /// Returns whether all of it finished in time; either way the node is
    /// done afterwards: drop it, or call [`Node::shutdown`], to end the tasks
    /// (and with them the streams being served). A node that is only dropped
    /// leaves its peers to find out by the dead peer timeout.
    pub async fn close_gracefully(&self, grace: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + grace;
        let closed = self
            .router
            .stop(
                CloseReason {
                    code: ErrorCode::ShuttingDown,
                    msg: "this node is shutting down".to_string(),
                },
                grace,
            )
            .await;
        // The CLOSE records are in the relay session's queue now (or the time
        // for them is up): have it write them and leave.
        let _ = self.stop_session.send(true);
        let mut ended = self.session_ended.clone();
        let written = tokio::time::timeout_at(deadline, ended.wait_for(|ended| *ended))
            .await
            .is_ok_and(|result| result.is_ok());
        closed && written
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

/// Refuses every OPEN, for a session on which the peer has no business opening anything.
struct DenyAll;

impl Authorizer for DenyAll {
    fn authorize(&self, _request: &OpenRequest) -> OpenDecision {
        OpenDecision::Deny(OpenRefusal {
            code: ErrorCode::NoGrant,
            msg: "no grant".to_string(),
        })
    }
}

/// Runs an accept loop for every session the router announces, until the
/// router is gone. A loop ends by itself when its session does.
// One more independent input of the node's own identity (its cert serial).
#[allow(clippy::too_many_arguments)]
async fn serve_sessions<H>(
    mut ready: mpsc::UnboundedReceiver<SessionReady>,
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    local_node_id: NodeId,
    local_serial: u32,
    handler: Arc<H>,
    gate: Arc<DocsGate>,
    sync: Option<Arc<DocsSync>>,
    revalidator: Option<Arc<Revalidator>>,
) where
    H: ServiceHandler<Stream> + Send + Sync + 'static,
    H::Handling: Send + 'static,
{
    while let Some(session) = ready.recv().await {
        serve_session(
            session,
            &policies,
            &rosters,
            local_node_id,
            local_serial,
            &handler,
            &gate,
            sync.as_ref(),
            revalidator.as_ref(),
        );
    }
}

/// Takes a session out of the revalidator's registry when dropped, so the handle and the
/// stream registry it holds go with the session however its accept loop ends.
struct Forget(Option<(Arc<Revalidator>, u64)>);

impl Drop for Forget {
    fn drop(&mut self) {
        if let Some((revalidator, id)) = self.0.take() {
            revalidator.forget(id);
        }
    }
}

/// Starts the accept loop of one session.
///
/// An ordinary session is authorized against the Policy plus the `menzil:docs`
/// exemption and served by [`SessionHandler`] in front of `handler`. A docs only
/// session this node answered takes one `menzil:docs` push and nothing else, and
/// is closed with CLOSE `docs_only` once that stream is over; one this node
/// initiated (the peer admitted it docs only) takes no stream at all.
///
/// With `sync`, the document triggers of protocol.md 5.5 run as well: the session is
/// noted as live for as long as its accept loop runs; as the initiator of an ordinary
/// session this node compares the responder's seqs with its own and fetches and/or pushes
/// ([`DocsSync::reconcile`]); as the initiator of a docs only session it pushes, and
/// when that was adopted starts one new handshake ([`DocsSync::docs_only_push`]).
///
/// With `revalidator`, every kind of session is registered with it before its accept loop
/// starts and forgotten when the loop ends (protocol.md 5.3, L4k); an ordinary session's accept
/// loop keeps a registry of the streams it serves for the revalidator to ask again.
// One more independent input of the node's own identity (its cert serial).
#[allow(clippy::too_many_arguments)]
pub(crate) fn serve_session<H>(
    session: SessionReady,
    policies: &Arc<PolicyStore>,
    rosters: &Arc<RosterStore>,
    local_node_id: NodeId,
    local_serial: u32,
    handler: &Arc<H>,
    gate: &Arc<DocsGate>,
    sync: Option<&Arc<DocsSync>>,
    revalidator: Option<&Arc<Revalidator>>,
) where
    H: ServiceHandler<Stream> + Send + Sync + 'static,
    H::Handling: Send + 'static,
{
    let SessionReady {
        peer,
        network_id,
        peer_static,
        mut acceptor,
        handle,
        role,
        docs_only,
        peer_roster_seq,
        peer_policy_seq,
        ..
    } = session;
    let authorizer = PolicyAuthorizer::new(
        policies.clone(),
        rosters.clone(),
        network_id,
        local_node_id,
        local_serial,
    );
    // Registered before the accept loop starts, so no OPEN is served unwatched; the
    // registration also has the network looked at once, for documents that changed since the
    // router decided to hand this session out.
    let register = |handle: &L4SessionHandle, kind: Kind| {
        Forget(revalidator.map(|revalidator| {
            let id = revalidator.register(peer, network_id, peer_static, handle.clone(), kind);
            (Arc::clone(revalidator), id)
        }))
    };
    if docs_only && role == Role::Initiator {
        let forget = register(&handle, Kind::DocsOnly);
        if let Some(sync) = sync {
            let sync = Arc::clone(sync);
            let handle = handle.clone();
            tokio::spawn(async move { sync.docs_only_push(handle).await });
        }
        tokio::spawn(async move {
            accept_loop(&mut acceptor, DenyAll, RefuseAll).await;
            drop(forget);
        });
    } else if docs_only {
        let forget = register(&handle, Kind::DocsOnly);
        let handler = SessionHandler::docs_only(
            Arc::clone(handler),
            gate.clone(),
            policies.clone(),
            rosters.clone(),
            move || {
                handle.close(Some(CloseReason {
                    code: ErrorCode::DocsOnly,
                    msg: "docs only session over".to_string(),
                }));
            },
        );
        let authorizer = authorizer.docs_only();
        tokio::spawn(async move {
            accept_loop(&mut acceptor, authorizer, handler).await;
            drop(forget);
        });
    } else {
        let streams = AcceptedStreams::new();
        let forget = register(
            &handle,
            Kind::Full {
                streams: streams.clone(),
                authorizer: authorizer.clone(),
            },
        );
        // The router's table holds its own clone of the handle for as long as the
        // session is the one in use.
        let handler = SessionHandler::full(
            Arc::clone(handler),
            gate.clone(),
            policies.clone(),
            rosters.clone(),
        );
        let live = sync.map(|sync| {
            let id = sync.register_as(
                peer,
                network_id,
                role == Role::Initiator,
                peer_roster_seq,
                peer_policy_seq,
            );
            (Arc::clone(sync), id)
        });
        if let Some((sync, _)) = &live
            && role == Role::Initiator
        {
            let sync = Arc::clone(sync);
            tokio::spawn(async move {
                sync.reconcile(handle, peer_roster_seq, peer_policy_seq)
                    .await;
            });
        }
        tokio::spawn(async move {
            accept_loop_tracked(&mut acceptor, authorizer, handler, streams).await;
            drop(forget);
            if let Some((sync, id)) = live {
                sync.forget(peer, network_id, id);
            }
        });
    }
}
