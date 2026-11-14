//! Serving the relay principal's session (protocol.md 6.1, expose design S-E4): what the
//! relay may open on this node, with which `meta`, and how many streams of it the node holds.
//!
//! The relay opens streams to a node only to serve a public share the node itself configured
//! (`[[share]]`, [`crate::ShareBook`]) and the relay accepted. There is no Policy grant behind
//! such a stream and the relay is no member, so none of [`crate::PolicyAuthorizer`]'s rules apply,
//! and this module has its own gates:
//!
//! * [`RelayAuthorizer`] decides each OPEN: the service is one of an accepted share that this
//!   session's network grants this node ([`accepted_shares`]), of kind `tls:`, `http:` or
//!   `tcp:`, or an `acme-http:` for a *blind* share's name; `target` is null; this node's own
//!   standing in the network (listed, unrevoked, its serial and own certificate good) holds now
//!   and its documents are unexpired. Everything else (`menzil:docs`, a service the node serves
//!   to members, `egress:*`, `udp:`) is `no_grant`, the same refusal an unshared service gets,
//!   so the relay learns nothing about what is configured.
//! * [`RelayHandler`] wraps the node's handler. It validates `meta` instead of scrubbing it
//!   (`client_ip` must parse as an address, `sni` must be a name of an accepted share; else the
//!   field is dropped), since the relay principal is the one sender whose `meta` is honored, and
//!   it bounds the streams it holds ([`RelayLimits`]): 64 per share and 256 in all, counted
//!   apart from [`crate::ServeLimits`] (the inner handler is asked through
//!   `ServiceHandler::open_with_own_limits`, which takes no place in them) so that public traffic
//!   cannot take the slots members need and members cannot take the relay's.
//! * `meta` is information for the node's logs and the service behind it, never authorization.
//!
//! No document stream, no certificate push and no candidate offer exist for this session, and it
//! is never a source of documents: [`crate::node`] does not register it with the document sync
//! at all.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use menzil_proto::{
    ErrorCode, NetworkId, NodeId, OpenMeta, ServiceId, ServiceKind, Share, ShareMode,
    X25519PublicKey,
};
use menzil_stream::{Authorizer, OpenDecision, OpenRefusal, OpenRequest, ServiceHandler, Stream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::admission::own_standing_in;
use crate::identity::OwnSerial;
use crate::policy_store::PolicyStore;
use crate::roster_store::RosterStore;
use crate::shares::ShareBook;

/// How many streams the relay principal may hold open to one share of this node.
pub const MAX_RELAY_STREAMS_PER_SHARE: usize = 64;

/// How many streams the relay principal may hold open to this node in all, every share and
/// every network together.
pub const MAX_RELAY_STREAMS: usize = 256;

/// The longest SNI a name can be (RFC 1035).
const MAX_SNI_BYTES: usize = 253;

/// The shares of the latest ADVERTISE that the relay accepted in this attachment **and** that
/// the Roster this node holds for `network_id` grants it: the Roster's `labels` list the share's
/// name for this node. The book is per relay attachment and names no network (the ACK does not),
/// so this is as strong a tie from a share to one network as the data allows.
///
/// What remains open: a label that two networks of the node both grant is accepted by the relay
/// in each zone it can, or only in one (a quota can refuse the other), and the ACK does not say
/// which; the node then takes the share for both networks. The relay only opens a network's
/// session for a name it holds for that network, so the effect is that the node answers a
/// session for the second network too, and its own standing in that network is checked all the
/// same.
pub(crate) fn accepted_shares(
    book: &ShareBook,
    rosters: &RosterStore,
    network_id: &NetworkId,
    local: &NodeId,
) -> Vec<Share> {
    let accepted = book.accepted();
    if accepted.is_empty() {
        return accepted;
    }
    let Some(roster) = rosters.body(network_id) else {
        return Vec::new();
    };
    accepted
        .into_iter()
        .filter(|share| {
            roster.labels.iter().any(|label| {
                &label.node_id == local && label.name.eq_ignore_ascii_case(&share.name)
            })
        })
        .collect()
}

/// The share a stream for `service` is for, if the relay principal may open it given `shares`:
/// `tls:`, `http:` and `tcp:` exactly as an accepted share points at them, and `acme-http:<name>`
/// for the name of a *blind* share (a terminated share's certificate is the relay's business, so
/// the node answers no challenge for it). Any other kind is refused whatever the book holds.
/// The one place the rule lives: the authorizer asks it, and the handler counts the stream against
/// the share it returns.
fn matching_share<'a>(shares: &'a [Share], service: &ServiceId) -> Option<&'a Share> {
    match service.kind {
        ServiceKind::Tls | ServiceKind::Http | ServiceKind::Tcp => {
            shares.iter().find(|share| &share.service == service)
        }
        ServiceKind::AcmeHttp => shares.iter().find(|share| {
            share.mode == ShareMode::Blind && share.name.eq_ignore_ascii_case(&service.label)
        }),
        ServiceKind::Udp | ServiceKind::Egress | ServiceKind::Menzil => None,
    }
}

fn no_grant() -> OpenDecision {
    OpenDecision::Deny(OpenRefusal {
        code: ErrorCode::NoGrant,
        msg: "no grant".to_string(),
    })
}

/// Decides every OPEN of one relay principal session. See the module docs. One per session,
/// scoped to the network its `init` named.
#[derive(Clone)]
pub struct RelayAuthorizer {
    policies: Arc<PolicyStore>,
    rosters: Arc<RosterStore>,
    shares: ShareBook,
    network_id: NetworkId,
    /// The relay's NodeId, the only initiator this session has.
    relay: NodeId,
    local: NodeId,
    /// Read at each check, so a renewed certificate counts at once.
    local_serial: OwnSerial,
    local_static: X25519PublicKey,
}

impl RelayAuthorizer {
    /// An authorizer for the relay principal session of `relay` on `network_id`, for the node
    /// `local` (its certificate serial `local_serial`, its static key `local_static`).
    // Independent inputs of one session, like `PolicyAuthorizer::new`'s.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policies: Arc<PolicyStore>,
        rosters: Arc<RosterStore>,
        shares: ShareBook,
        network_id: NetworkId,
        relay: NodeId,
        local: NodeId,
        local_serial: impl Into<OwnSerial>,
        local_static: X25519PublicKey,
    ) -> Self {
        Self {
            policies,
            rosters,
            shares,
            network_id,
            relay,
            local,
            local_serial: local_serial.into(),
            local_static,
        }
    }

    /// The shares this session may serve now (see [`accepted_shares`]).
    fn shares_now(&self) -> Vec<Share> {
        accepted_shares(&self.shares, &self.rosters, &self.network_id, &self.local)
    }

    /// Whether this node's own standing in the network holds now, with or without the expiry of
    /// the documents.
    fn standing(&self, now: u64, check_expiry: bool) -> Result<(), ErrorCode> {
        own_standing_in(
            &self.policies,
            &self.rosters,
            &self.network_id,
            &self.local,
            self.local_serial.get(),
            &self.local_static,
            now,
            check_expiry,
        )
    }

    /// Whether the session itself may go on (the revalidator's question): this node's own
    /// standing holds, and some accepted share of this network is left. Expired documents end no
    /// session (protocol.md 5.3); they only stop what is served on it, which [`Self::authorize`]
    /// sees at every OPEN and the revalidator's stream recheck at the moment they expire. The
    /// error is for the local log.
    pub(crate) fn session_standing(&self, now: u64) -> Result<(), ErrorCode> {
        self.standing(now, false)?;
        if self.shares_now().is_empty() {
            return Err(ErrorCode::LabelUnclaimed);
        }
        Ok(())
    }
}

impl Authorizer for RelayAuthorizer {
    fn authorize(&self, request: &OpenRequest) -> OpenDecision {
        if request.network_id != self.network_id || request.initiator != self.relay {
            return no_grant();
        }
        // `target` is null for every service this session may open; the stream layer refuses a
        // target on anything but `egress:*` before this runs, and this is the second lock.
        if request.target.is_some() {
            return no_grant();
        }
        // This node's own standing and documents, on every OPEN: a revocation of this node, or
        // documents that expired, stops the next stream at once.
        if self.standing(unix_now(), true).is_err() {
            return no_grant();
        }
        if matching_share(&self.shares_now(), &request.service).is_some() {
            OpenDecision::Allow
        } else {
            no_grant()
        }
    }
}

/// How many streams the relay principal holds on this node, per share and in all. One per node,
/// shared by all its relay principal sessions.
pub struct RelayLimits {
    total: Arc<Semaphore>,
    max_per_share: usize,
    per_share: Mutex<HashMap<String, usize>>,
}

impl RelayLimits {
    /// The figures of the design: [`MAX_RELAY_STREAMS_PER_SHARE`] and [`MAX_RELAY_STREAMS`].
    pub fn new() -> Arc<Self> {
        Self::with_figures(MAX_RELAY_STREAMS_PER_SHARE, MAX_RELAY_STREAMS)
    }

    /// Other figures (at least 1 each), for tests and for an operator who sets them.
    pub fn with_figures(per_share: usize, total: usize) -> Arc<Self> {
        let total = total.clamp(1, Semaphore::MAX_PERMITS);
        Arc::new(Self {
            total: Arc::new(Semaphore::new(total)),
            max_per_share: per_share.max(1),
            per_share: Mutex::new(HashMap::new()),
        })
    }

    fn take(self: &Arc<Self>, share: &str) -> Option<RelayPermit> {
        let permit = Arc::clone(&self.total).try_acquire_owned().ok()?;
        let mut held = self
            .per_share
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let count = held.entry(share.to_string()).or_insert(0);
        if *count >= self.max_per_share {
            if *count == 0 {
                held.remove(share);
            }
            return None;
        }
        *count += 1;
        Some(RelayPermit {
            _permit: permit,
            share: share.to_string(),
            limits: Arc::clone(self),
        })
    }
}

/// One stream's place in [`RelayLimits`]; gives it back on drop.
pub struct RelayPermit {
    _permit: OwnedSemaphorePermit,
    share: String,
    limits: Arc<RelayLimits>,
}

impl Drop for RelayPermit {
    fn drop(&mut self) {
        let mut held = self
            .limits
            .per_share
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.share) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.share);
            }
        }
    }
}

/// The node's wiring for relay principal sessions: the book they are judged against and the
/// limits they share. [`crate::Node`] makes one; `serve_session` takes it.
#[derive(Clone)]
pub struct RelayServing {
    pub(crate) shares: ShareBook,
    pub(crate) limits: Arc<RelayLimits>,
}

impl RelayServing {
    /// With the design's limits.
    pub fn new(shares: ShareBook) -> Self {
        Self {
            shares,
            limits: RelayLimits::new(),
        }
    }

    /// With other limits.
    pub fn with_limits(shares: ShareBook, limits: Arc<RelayLimits>) -> Self {
        Self { shares, limits }
    }
}

/// `inner` for the relay principal's session: validates `meta` and bounds the streams, see the
/// module docs. The authorizer has already allowed the request when this is asked.
pub struct RelayHandler<H> {
    inner: Arc<H>,
    rosters: Arc<RosterStore>,
    serving: RelayServing,
    network_id: NetworkId,
    local: NodeId,
}

impl<H> RelayHandler<H> {
    /// A handler for the session on `network_id` of the node `local`, in front of `inner`.
    pub fn new(
        inner: Arc<H>,
        rosters: Arc<RosterStore>,
        serving: RelayServing,
        network_id: NetworkId,
        local: NodeId,
    ) -> Self {
        Self {
            inner,
            rosters,
            serving,
            network_id,
            local,
        }
    }

    fn shares_now(&self) -> Vec<Share> {
        accepted_shares(
            &self.serving.shares,
            &self.rosters,
            &self.network_id,
            &self.local,
        )
    }

    /// The share name a stream for `service` counts against, if it is still accepted.
    fn share_name(&self, shares: &[Share], service: &ServiceId) -> Option<String> {
        matching_share(shares, service).map(|share| share.name.clone())
    }

    /// `request` with its `meta` validated against the names this session serves.
    fn validated(&self, shares: &[Share], request: &OpenRequest) -> OpenRequest {
        let full_names = self.serving.shares.names();
        let names = serving_names(shares, &full_names);
        OpenRequest {
            meta: validate_meta(&request.meta, &names),
            ..request.clone()
        }
    }
}

impl<H> ServiceHandler<Stream> for RelayHandler<H>
where
    H: ServiceHandler<Stream> + Send + Sync + 'static,
    H::Handling: Send + 'static,
{
    type Opened = (H::Opened, RelayPermit);
    type Handling = Pin<Box<dyn Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<Self::Opened, OpenRefusal> {
        let shares = self.shares_now();
        // The authorizer has just allowed this; a share withdrawn since is refused the same way.
        let Some(name) = self.share_name(&shares, &request.service) else {
            return Err(OpenRefusal {
                code: ErrorCode::NoGrant,
                msg: "no grant".to_string(),
            });
        };
        // Before anything is connected to: past a limit the OPEN costs the refusal.
        let Some(permit) = self.serving.limits.take(&name) else {
            tracing::debug!(share = %name, "refused a relay principal OPEN: a limit is reached");
            return Err(OpenRefusal {
                code: ErrorCode::RateLimited,
                msg: "too many connections".to_string(),
            });
        };
        let request = self.validated(&shares, request);
        // The relay's streams are bounded by `RelayLimits` above, so they take no place in the
        // limits the inner handler applies to members (expose round 1, L1).
        let opened = self.inner.open_with_own_limits(&request).await?;
        Ok((opened, permit))
    }

    fn handle(
        &self,
        stream: Stream,
        request: OpenRequest,
        (opened, permit): Self::Opened,
    ) -> Self::Handling {
        let request = self.validated(&self.shares_now(), &request);
        let handling = self.inner.handle(stream, request, opened);
        Box::pin(async move {
            // Held until the stream is over, however it ends.
            let _permit = permit;
            handling.await;
        })
    }
}

/// The names an SNI may sit under: the full names the relay's ACK listed (relative to its share
/// domain, `app` or `app.ali`) whose first label is the name of a share this session serves,
/// and, for a relay that sends none, those share names themselves.
fn serving_names(shares: &[Share], full_names: &[String]) -> Vec<String> {
    let mut names: Vec<String> = full_names
        .iter()
        .filter(|full| {
            let first = full.split('.').next().unwrap_or_default();
            shares
                .iter()
                .any(|share| share.name.eq_ignore_ascii_case(first))
        })
        .map(|full| full.to_ascii_lowercase())
        .collect();
    if names.is_empty() {
        names = shares
            .iter()
            .map(|share| share.name.to_ascii_lowercase())
            .collect();
    }
    names
}

/// The `meta` of an OPEN from the relay principal, kept only where it holds up: `client_ip` as
/// the canonical text of the address it parses to, else dropped; `sni` in lowercase, of at most
/// 253 bytes, made of letters, digits, hyphens and dots, and equal to one of `names`, or below
/// one (`<name>.<the relay's domain>`, which is how the relay composes it from a name relative
/// to its share domain, or a subdomain of a name that is a domain, one with a dot), else dropped.
///
/// Known limit: this check does not hold the relay's share domain, so `<name>.<anything>` passes
/// the prefix rule, `app.attacker.example` included. The field is information the relay claims
/// and never picks a target, so this is accepted. ADVERTISE_ACK does carry `share_domain` now
/// (TBD 53), but it is informational only (protocol.md 4.4): nothing is decided from it, so it
/// does not close this.
///
/// Dropping is not refusing: `meta` is information the relay claims, never authorization, and a
/// stream with a bad field is served with that field empty.
pub(crate) fn validate_meta(meta: &OpenMeta, names: &[String]) -> OpenMeta {
    let client_ip = meta
        .client_ip
        .as_deref()
        .and_then(|text| text.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string());
    let sni = meta
        .sni
        .as_deref()
        .filter(|sni| sni.len() <= MAX_SNI_BYTES)
        .map(str::to_ascii_lowercase)
        .filter(|sni| {
            !sni.is_empty()
                && sni
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        })
        .filter(|sni| {
            names.iter().any(|name| {
                !name.is_empty()
                    && (sni == name
                        || sni.starts_with(&format!("{name}."))
                        // Below a name that is a domain of its own (`web.ali` is a zone, and a
                        // custom domain later is one). A single label (`app`) is relative to the
                        // relay's share domain and is no domain: `x.app` is somebody else's
                        // `.app` name, not a subdomain of this share.
                        || (name.contains('.') && sni.ends_with(&format!(".{name}"))))
            })
        });
    OpenMeta { client_ip, sni }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
