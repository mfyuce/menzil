//! The node side of the relay principal (expose design S-E4): the router's `on_relay_init`
//! branch, `RelayAuthorizer` and `RelayHandler` behind `serve_session_with_relay`, and the
//! revalidator's `Kind::RelayPrincipal`. The relay is played by a second router (`nrel`, the
//! relay's identity as an ordinary party that is a member of nothing in the node's documents) or
//! by a scripted initiator (`Manual`); no real relay is involved (`tests/` has no live test for
//! this slice, S-E5 does that).
//!
//! Every test that expects silence waits out the relay router's three attempts under the paused
//! clock, so a mutant that answers fails it by `resp` count, never by hanging.

use super::*;
use crate::docs_access::{DocsGate, DocsLimits};
use crate::node::serve_session_with_relay;
use crate::relay_serve::{RelayAuthorizer, RelayHandler, RelayLimits, RelayServing, validate_meta};
use crate::revalidate::Revalidator;
use crate::serve::{LocalServices, LocalTarget, ServeLimits};
use crate::shares::ShareBook;
use menzil_proto::{
    AdvertiseAckBody, Label, OpenAckBody, OpenBody, OpenMeta, OpenTarget, RevokedMember, Share,
    ShareMode,
};
use menzil_stream::{
    Authorizer, OpenDecision, OpenRefusal, OpenRequest, ServiceHandler, Stream, initiate_open,
};
use std::sync::atomic::{AtomicUsize, Ordering};

// ---- fixtures ---------------------------------------------------------------

fn share(name: &str, mode: ShareMode, service: &str) -> Share {
    Share {
        name: name.to_string(),
        mode,
        service: service.parse().unwrap(),
        alpn: vec![],
    }
}

/// A blind share `name` pointing at `tls:<name>`.
fn blind(name: &str) -> Share {
    share(name, ShareMode::Blind, &format!("tls:{name}"))
}

/// A book in which the relay accepted every one of `shares`.
fn book_accepting(shares: &[Share]) -> ShareBook {
    let book = ShareBook::new();
    book.note_sent(shares);
    book.note_ack(&AdvertiseAckBody {
        accepted: shares.iter().map(|s| s.name.clone()).collect(),
        rejected: vec![],
        names: vec![],
    });
    book
}

/// The documents of `parties` with `labels` granting names to nodes, in one network.
fn labeled_stores(w: &World, parties: &[&Party], labels: &[(&str, NodeId)]) -> Stores {
    let body = RosterBody {
        v: PROTOCOL_VERSION,
        network_id: w.network,
        seq: 1,
        issued: 0,
        expires: 4_000_000_000,
        members: parties
            .iter()
            .map(|p| RosterMember {
                node_id: p.id,
                min_serial: 1,
            })
            .collect(),
        revoked: vec![],
        stewards: vec![],
        labels: labels
            .iter()
            .map(|(name, node_id)| Label {
                name: name.to_string(),
                node_id: *node_id,
            })
            .collect(),
    };
    let rosters = RosterStore::new();
    rosters
        .set(&Roster::sign(&w.owner, &body).unwrap())
        .unwrap();
    let policies = PolicyStore::new();
    policies.set(&w.policy(parties, parties, vec![])).unwrap();
    Stores {
        policies: Arc::new(policies),
        rosters: Arc::new(rosters),
    }
}

fn edit_policy(w: &World, stores: &Stores, edit: impl FnOnce(&mut PolicyBody)) {
    let mut body = stores.policies.body(&w.network).unwrap().as_ref().clone();
    body.seq += 1;
    edit(&mut body);
    assert!(
        stores
            .policies
            .set(&Policy::sign(&w.owner, &body).unwrap())
            .unwrap()
    );
}

fn revoke(w: &World, stores: &Stores, who: NodeId) {
    edit_roster_of(w, stores, |b| {
        b.revoked.push(RevokedMember {
            node_id: who,
            since: 0,
        })
    });
}

/// Accepts every OPEN, counts them, remembers them, and holds each stream open until reset.
#[derive(Default)]
struct Recorder {
    opens: AtomicUsize,
    seen: Mutex<Vec<OpenRequest>>,
}

impl ServiceHandler<Stream> for Recorder {
    type Opened = ();
    type Handling = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

    async fn open(&self, request: &OpenRequest) -> Result<(), OpenRefusal> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(request.clone());
        Ok(())
    }

    fn handle(&self, stream: Stream, _request: OpenRequest, _opened: ()) -> Self::Handling {
        Box::pin(async move {
            let _stream = stream;
            std::future::pending::<()>().await;
        })
    }
}

/// The node under test, its documents and shares, and the relay router that opens to it.
struct Rp {
    w: World,
    b: Party,
    rel: Party,
    stores_b: Stores,
    net: Net,
    nb: TestNode,
    nrel: Option<TestNode>,
    book: ShareBook,
    rec: Arc<Recorder>,
}

/// `shares` are accepted by the relay (in the book); the node's Roster grants `labels` to it.
async fn rp(shares: &[Share], labels: &[&str]) -> Rp {
    rp_on(Net::with_relay_party, shares, labels).await
}

async fn rp_on(make_net: impl FnOnce(&Party) -> Net, shares: &[Share], labels: &[&str]) -> Rp {
    let w = world();
    let (b, rel, m) = (party(), party(), party());
    let granted: Vec<(&str, NodeId)> = labels.iter().map(|l| (*l, b.id)).collect();
    let stores_b = labeled_stores(&w, &[&b, &m], &granted);
    let net = make_net(&rel);
    let book = book_accepting(shares);
    let nb = node_full(&net, &b, &stores_b, TableConfig::default(), book.clone()).await;
    Rp {
        w,
        b,
        rel,
        stores_b,
        net,
        nb,
        nrel: None,
        book,
        rec: Arc::new(Recorder::default()),
    }
}

/// An `Rp` whose relay is `rel` but whose attachment negotiated `other` as the relay's key.
async fn rp_with_static(other: X25519PublicKey, shares: &[Share], labels: &[&str]) -> Rp {
    rp_on(
        move |rel| {
            let mut net = Net::with_relay_party(rel);
            net.relay_static = other;
            net
        },
        shares,
        labels,
    )
    .await
}

/// What a session that came up gives the test.
struct Up {
    /// The relay's end, to open streams on.
    relay: L4SessionHandle,
    /// The relay's end's acceptor, only to learn how the session ended.
    relay_ready: SessionReady,
    /// The node's end, to be served.
    node_ready: SessionReady,
}

impl Rp {
    async fn start_relay(&mut self) {
        let stores_rel = self.w.stores(&[&self.rel, &self.b], vec![]);
        self.nrel = Some(node(&self.net, &self.rel, &stores_rel).await);
    }

    async fn ask(&mut self) -> Result<L4SessionHandle, EnsureError> {
        if self.nrel.is_none() {
            self.start_relay().await;
        }
        ensure(self.nrel.as_ref().unwrap(), self.b.id, self.w.network).await
    }

    async fn up(&mut self) -> Up {
        let relay = self
            .ask()
            .await
            .expect("the relay principal's session comes up");
        let relay_ready = self.nrel.as_mut().unwrap().next_ready().await;
        let node_ready = self.nb.next_ready().await;
        Up {
            relay,
            relay_ready,
            node_ready,
        }
    }

    /// Asks for a session and asserts that nobody answered it.
    async fn assert_silence(&mut self) {
        assert!(self.ask().await.is_err(), "the node must not answer");
        assert_eq!(self.net.count_from(&self.b.id, "resp"), 0);
        assert!(self.nb.ready.try_recv().is_err());
    }

    fn serving(&self, limits: Option<Arc<RelayLimits>>) -> RelayServing {
        match limits {
            Some(limits) => RelayServing::with_limits(self.book.clone(), limits),
            None => RelayServing::new(self.book.clone()),
        }
    }

    fn serve(
        &self,
        ready: SessionReady,
        reval: Option<&Arc<Revalidator>>,
        relay: Option<&RelayServing>,
    ) {
        serve_session_with_relay(
            ready,
            &self.stores_b.policies,
            &self.stores_b.rosters,
            self.b.id,
            1,
            self.b.x25519_public,
            &self.rec,
            &DocsGate::new(DocsLimits::default()),
            None,
            reval,
            relay,
        );
    }

    fn revalidator(&self) -> Arc<Revalidator> {
        let reval = Revalidator::new(
            self.stores_b.policies.clone(),
            self.stores_b.rosters.clone(),
            self.b.id,
            1,
            self.b.x25519_public,
        );
        tokio::spawn(reval.clone().run());
        reval
    }

    fn authorizer(&self) -> RelayAuthorizer {
        RelayAuthorizer::new(
            self.stores_b.policies.clone(),
            self.stores_b.rosters.clone(),
            self.book.clone(),
            self.w.network,
            self.rel.id,
            self.b.id,
            1,
            self.b.x25519_public,
        )
    }
}

/// What the relay does to open a stream: the OPEN exchange with `meta` and `target` as given.
async fn relay_open(
    handle: &L4SessionHandle,
    service: &str,
    target: Option<OpenTarget>,
    meta: OpenMeta,
) -> (Stream, OpenAckBody) {
    let mut stream = handle.open_stream().await.expect("a stream opens");
    let open = OpenBody {
        v: PROTOCOL_VERSION,
        service: service.parse().unwrap(),
        target,
        meta,
    };
    let ack = timeout(Duration::from_secs(20), initiate_open(&mut stream, &open))
        .await
        .expect("the OPEN is answered")
        .expect("the OPEN exchange works");
    (stream, ack)
}

async fn open_plain(handle: &L4SessionHandle, service: &str) -> (Stream, OpenAckBody) {
    relay_open(handle, service, None, OpenMeta::default()).await
}

fn assert_refused(ack: &OpenAckBody, code: ErrorCode, what: &str) {
    assert!(!ack.ok, "{what}: must be refused");
    assert_eq!(ack.code, code, "{what}");
}

// ---- the router: who is answered --------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_relay_principal_comes_up_when_every_check_passes() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let ready = &up.node_ready;
    assert!(ready.relay_principal);
    assert_eq!(ready.peer, rp.rel.id);
    assert_eq!(ready.peer_static, rp.rel.x25519_public);
    assert_eq!(ready.network_id, rp.w.network);
    assert_eq!(ready.role, Role::Responder);
    assert!(!ready.docs_only);
    assert!(
        !up.relay_ready.relay_principal,
        "only the node's end is the principal's"
    );
    assert_eq!(rp.net.count_from(&rp.b.id, "resp"), 1);
    // The node answered with its own certificate and Roster seq, and 0 for the Policy: the
    // relay is never told what the Policy holds.
    assert_eq!(up.relay_ready.peer_roster_seq, Some(1));
    assert_eq!(up.relay_ready.peer_policy_seq, Some(0));
}

#[tokio::test(start_paused = true)]
async fn an_init_from_another_static_key_than_the_relays_gets_silence() {
    // The L3 attachment negotiated another key for the relay than the one the initiator holds.
    let mut rp = rp_with_static(X25519PublicKey::from([0x55; 32]), &[blind("app")], &["app"]).await;
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn a_member_that_puts_the_relays_node_id_in_its_init_gets_silence() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let member = party();
    // The handshake is valid in itself: the prologue names the relay as the initiator. The key is
    // the member's, not the relay's.
    let (_hs, forged) = E2eInitiatorHandshake::start(
        &member.x25519_private,
        &rp.b.x25519_public,
        rp.w.network,
        rp.rel.id,
        rp.b.id,
        7,
    )
    .unwrap();
    rp.net.inject(rp.rel.id, rp.b.id, &forged);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rp.net.count_from(&rp.b.id, "resp"), 0);
    assert!(rp.nb.ready.try_recv().is_err());

    // The same frame from the relay's own key is answered: the setup is not what silenced it.
    let relay = Manual::new(&rp.net, rp.rel.clone_for_test());
    let (_hs, init) = relay.init(&rp.b, rp.w.network, 8);
    rp.net.inject(rp.rel.id, rp.b.id, &init);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rp.net.count_from(&rp.b.id, "resp"), 1);
}

#[tokio::test(start_paused = true)]
async fn the_relays_key_is_the_one_of_the_current_attachment_only() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    // The node reconnects and this attachment's L3 handshake negotiated another key.
    rp.nb.detach(Epoch::first()).await;
    let second = Epoch::first().next();
    if let Some(link) = rp.net.inner.lock().unwrap().links.get_mut(&rp.b.id) {
        link.epoch = second;
    }
    rp.nb
        .events
        .send(SessionEvent::Attached {
            epoch: second,
            limits: LIMITS,
            relay_static: X25519PublicKey::from([0x66; 32]),
        })
        .await
        .unwrap();
    rp.nb.barrier().await;
    // The shares are accepted again in the new attachment (the book was cleared by the real
    // session; here it was never cleared), so only the key is what is wrong.
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn an_init_for_a_network_with_no_accepted_share_gets_silence() {
    // The Roster grants the label, but the relay accepted no share.
    let mut rp = rp(&[], &["app"]).await;
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn a_share_the_relay_accepted_for_another_network_does_not_open_this_one() {
    // The relay accepted `app`, but this network's Roster does not grant it to this node.
    let mut rp = rp(&[blind("app")], &[]).await;
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn a_label_this_networks_roster_grants_to_another_node_is_not_ours() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let other = party().id;
    edit_roster_of(&rp.w, &rp.stores_b, |b| {
        b.labels = vec![Label {
            name: "app".to_string(),
            node_id: other,
        }]
    });
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn a_label_of_another_name_does_not_make_the_share_ours() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let me = rp.b.id;
    edit_roster_of(&rp.w, &rp.stores_b, |b| {
        b.labels = vec![Label {
            name: "web".to_string(),
            node_id: me,
        }]
    });
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn an_init_for_a_network_we_hold_no_documents_for_gets_silence() {
    let rp = rp(&[blind("app")], &["app"]).await;
    let relay = Manual::new(&rp.net, rp.rel.clone_for_test());
    let (_hs, init) = relay.init(&rp.b, NetworkId::from([0x42; 32]), 1);
    rp.net.inject(rp.rel.id, rp.b.id, &init);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rp.net.count_from(&rp.b.id, "resp"), 0);
}

#[tokio::test(start_paused = true)]
async fn an_init_while_our_documents_have_expired_gets_silence() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    edit_roster_of(&rp.w, &rp.stores_b, |b| b.expires = 1);
    edit_policy(&rp.w, &rp.stores_b, |b| b.expires = 1);
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn an_init_while_this_node_is_revoked_gets_silence() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    revoke(&rp.w, &rp.stores_b, rp.b.id);
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn an_init_while_our_own_certificate_is_not_in_the_policy_gets_silence() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let me = rp.b.id;
    edit_policy(&rp.w, &rp.stores_b, |b| {
        b.certs.retain(|c| c.decode().unwrap().node_id != me)
    });
    rp.assert_silence().await;
}

#[tokio::test(start_paused = true)]
async fn the_relays_inits_are_rate_limited_like_any_peers() {
    let rp = rp(&[blind("app")], &["app"]).await;
    let relay = Manual::new(&rp.net, rp.rel.clone_for_test());
    for index in 1..=11 {
        let (_hs, init) = relay.init(&rp.b, rp.w.network, index);
        rp.net.inject(rp.rel.id, rp.b.id, &init);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        rp.net.count_from(&rp.b.id, "resp"),
        10,
        "ten a minute in all, the eleventh gets silence"
    );
}

#[tokio::test(start_paused = true)]
async fn an_l3_reconnect_ends_the_principal_session() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let mut up = rp.up().await;
    rp.nb.detach(Epoch::first()).await;
    let reason = ended(&mut up.node_ready.acceptor).await;
    assert!(
        matches!(reason.as_ref(), EndReason::EpochEnded),
        "pinned to the relay path it came up on: {reason:?}"
    );
}

// ---- what the relay may open ------------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_relay_opens_a_shared_service_and_the_handler_serves_it() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    rp.serve(up.node_ready, None, Some(&relay));
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert!(ack.ok, "{ack:?}");
    assert_eq!(rp.rec.opens.load(Ordering::SeqCst), 1);
}

/// Threat model test 6: the relay cannot reach a service that is not shared, even one the node
/// serves to its members.
#[tokio::test(start_paused = true)]
async fn the_relay_cannot_reach_a_service_that_is_not_shared() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    rp.serve(up.node_ready, None, Some(&relay));
    for service in [
        "tcp:ssh",
        "tls:other",
        "http:app",
        "tcp:app",
        "udp:app",
        "egress:*",
    ] {
        let (_stream, ack) = open_plain(&up.relay, service).await;
        assert_refused(&ack, ErrorCode::NoGrant, service);
    }
    assert_eq!(
        rp.rec.opens.load(Ordering::SeqCst),
        0,
        "the handler is never asked for what is not shared"
    );
}

#[tokio::test(start_paused = true)]
async fn the_relay_cannot_open_menzil_docs() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    rp.serve(up.node_ready, None, Some(&relay));
    let (_stream, ack) = open_plain(&up.relay, "menzil:docs").await;
    assert_refused(&ack, ErrorCode::NoGrant, "menzil:docs");
    assert_eq!(rp.rec.opens.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn an_open_with_a_target_is_refused() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    rp.serve(up.node_ready, None, Some(&relay));
    let target = OpenTarget {
        host: "127.0.0.1".to_string(),
        port: 22,
    };
    let (_stream, ack) = relay_open(&up.relay, "tls:app", Some(target), OpenMeta::default()).await;
    assert!(!ack.ok);
    assert_eq!(rp.rec.opens.load(Ordering::SeqCst), 0);
}

/// The stream layer refuses a target before any gate; this is the authorizer's own lock behind
/// it.
#[tokio::test(start_paused = true)]
async fn the_authorizer_itself_refuses_a_target() {
    let rp = rp(&[blind("app")], &["app"]).await;
    let authorizer = rp.authorizer();
    let request = |target: Option<OpenTarget>, initiator: NodeId, network: NetworkId| OpenRequest {
        network_id: network,
        initiator,
        service: "tls:app".parse().unwrap(),
        target,
        meta: OpenMeta::default(),
    };
    let allowed = |decision: OpenDecision| matches!(decision, OpenDecision::Allow);
    assert!(allowed(authorizer.authorize(&request(
        None,
        rp.rel.id,
        rp.w.network
    ))));
    let target = Some(OpenTarget {
        host: "h".to_string(),
        port: 1,
    });
    assert!(!allowed(authorizer.authorize(&request(
        target,
        rp.rel.id,
        rp.w.network
    ))));
    // Another initiator, or another network, is no one this authorizer serves.
    assert!(!allowed(authorizer.authorize(&request(
        None,
        party().id,
        rp.w.network
    ))));
    assert!(!allowed(authorizer.authorize(&request(
        None,
        rp.rel.id,
        NetworkId::from([0x42; 32])
    ))));
}

#[tokio::test(start_paused = true)]
async fn acme_http_is_for_blind_shares_only() {
    let terminated = share("site", ShareMode::Terminated, "http:site");
    let mut rp = rp(&[blind("app"), terminated], &["app", "site"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    rp.serve(up.node_ready, None, Some(&relay));

    let (_stream, ack) = open_plain(&up.relay, "acme-http:app").await;
    assert!(ack.ok, "a blind share's challenge: {ack:?}");
    let (_stream, ack) = open_plain(&up.relay, "acme-http:site").await;
    assert_refused(&ack, ErrorCode::NoGrant, "a terminated share's challenge");
    let (_stream, ack) = open_plain(&up.relay, "acme-http:nope").await;
    assert_refused(&ack, ErrorCode::NoGrant, "a name that is not shared");
    // The terminated share itself is reachable as its http service.
    let (_stream, ack) = open_plain(&up.relay, "http:site").await;
    assert!(ack.ok, "{ack:?}");
    assert_eq!(rp.rec.opens.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn own_standing_is_checked_on_every_open() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    // No revalidator: only the authorizer stands between the relay and the next stream.
    rp.serve(up.node_ready, None, Some(&relay));
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert!(ack.ok, "{ack:?}");

    revoke(&rp.w, &rp.stores_b, rp.b.id);
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert_refused(&ack, ErrorCode::NoGrant, "this node was revoked");
    assert_eq!(rp.rec.opens.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn nothing_is_served_on_expired_documents() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    rp.serve(up.node_ready, None, Some(&relay));
    edit_roster_of(&rp.w, &rp.stores_b, |b| b.expires = 1);
    edit_policy(&rp.w, &rp.stores_b, |b| b.expires = 1);
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert_refused(&ack, ErrorCode::NoGrant, "expired documents");
}

#[tokio::test(start_paused = true)]
async fn a_session_with_no_relay_wiring_is_refused_every_stream() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    rp.serve(up.node_ready, None, None);
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert!(!ack.ok);
    assert_eq!(rp.rec.opens.load(Ordering::SeqCst), 0);
}

// ---- the revalidator --------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_withdrawn_share_resets_its_stream_and_the_session_keeps_the_others() {
    let mut rp = rp(&[blind("app"), blind("other")], &["app", "other"]).await;
    let mut up = rp.up().await;
    let reval = rp.revalidator();
    let relay = rp.serving(None);
    rp.serve(up.node_ready, Some(&reval), Some(&relay));
    let (mut app, ack) = open_plain(&up.relay, "tls:app").await;
    assert!(ack.ok);
    let (mut other, ack) = open_plain(&up.relay, "tls:other").await;
    assert!(ack.ok);

    // The relay's answer to a new ADVERTISE no longer accepts `app`.
    rp.book.note_sent(&[blind("app"), blind("other")]);
    rp.book.note_ack(&AdvertiseAckBody {
        accepted: vec!["other".to_string()],
        rejected: vec![],
        names: vec![],
    });

    let mut byte = [0u8; 1];
    let error = timeout(Duration::from_secs(2), app.read(&mut byte))
        .await
        .expect("the stream of the withdrawn share is reset at once")
        .expect_err("a reset, not an end of file");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    assert!(
        timeout(Duration::from_secs(2), other.read(&mut byte))
            .await
            .is_err(),
        "the other share's stream goes on"
    );
    assert!(
        timeout(Duration::from_secs(1), up.relay_ready.acceptor.closed())
            .await
            .is_err(),
        "the session stays"
    );
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert_refused(&ack, ErrorCode::NoGrant, "the withdrawn share");
    let (_stream, ack) = open_plain(&up.relay, "tls:other").await;
    assert!(ack.ok, "{ack:?}");
}

/// The probe of expose round 1, M1: the owner takes `app` out of the set and the relay never
/// answers the ADVERTISE (it is silent, or refused it as over its rate). Nothing but `note_sent`
/// has run, and `app` must stop being served at once, not stay until an ACK that does not come.
#[tokio::test(start_paused = true)]
async fn a_share_the_owner_withdrew_is_not_served_while_the_relay_has_not_answered() {
    let mut rp = rp(&[blind("app"), blind("other")], &["app", "other"]).await;
    let mut up = rp.up().await;
    let reval = rp.revalidator();
    let relay = rp.serving(None);
    rp.serve(up.node_ready, Some(&reval), Some(&relay));
    let (mut app, ack) = open_plain(&up.relay, "tls:app").await;
    assert!(ack.ok);
    let (mut other, ack) = open_plain(&up.relay, "tls:other").await;
    assert!(ack.ok);

    // What the session does when the configured set changes: the book is set and the ADVERTISE
    // without `app` is about to be written. No ACK follows, whatever the time.
    rp.book.set_shares(vec![blind("other")]).unwrap();
    rp.book.note_sent(&[blind("other")]);

    let mut byte = [0u8; 1];
    let error = timeout(Duration::from_secs(2), app.read(&mut byte))
        .await
        .expect("the stream of the withdrawn share is reset at once")
        .expect_err("a reset, not an end of file");
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    tokio::time::sleep(Duration::from_secs(120)).await;
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert_refused(&ack, ErrorCode::NoGrant, "the withdrawn share, 120 s on");
    assert!(
        timeout(Duration::from_secs(1), other.read(&mut byte))
            .await
            .is_err(),
        "the share that stays goes on"
    );
    let (_stream, ack) = open_plain(&up.relay, "tls:other").await;
    assert!(ack.ok, "{ack:?}");
    assert!(
        timeout(Duration::from_secs(1), up.relay_ready.acceptor.closed())
            .await
            .is_err(),
        "the session stays"
    );
}

#[tokio::test(start_paused = true)]
async fn losing_every_share_closes_the_session_with_grant_removed() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let mut up = rp.up().await;
    let reval = rp.revalidator();
    let relay = rp.serving(None);
    rp.serve(up.node_ready, Some(&reval), Some(&relay));
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert!(ack.ok);

    rp.book.note_sent(&[blind("app")]);
    rp.book.note_ack(&AdvertiseAckBody {
        accepted: vec![],
        rejected: vec![],
        names: vec![],
    });
    match ended(&mut up.relay_ready.acceptor).await.as_ref() {
        EndReason::PeerClosed { code, .. } => assert_eq!(*code, ErrorCode::GrantRemoved),
        other => panic!("expected the node's close with grant_removed, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_roster_that_drops_the_label_closes_the_session() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let mut up = rp.up().await;
    let reval = rp.revalidator();
    let relay = rp.serving(None);
    rp.serve(up.node_ready, Some(&reval), Some(&relay));
    tokio::time::sleep(Duration::from_secs(1)).await;
    edit_roster_of(&rp.w, &rp.stores_b, |b| b.labels.clear());
    match ended(&mut up.relay_ready.acceptor).await.as_ref() {
        EndReason::PeerClosed { code, .. } => assert_eq!(*code, ErrorCode::GrantRemoved),
        other => panic!("expected the node's close with grant_removed, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_revoked_node_closes_the_principal_session() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let mut up = rp.up().await;
    let reval = rp.revalidator();
    let relay = rp.serving(None);
    rp.serve(up.node_ready, Some(&reval), Some(&relay));
    tokio::time::sleep(Duration::from_secs(1)).await;
    revoke(&rp.w, &rp.stores_b, rp.b.id);
    match ended(&mut up.relay_ready.acceptor).await.as_ref() {
        EndReason::PeerClosed { code, .. } => assert_eq!(*code, ErrorCode::GrantRemoved),
        other => panic!("expected the node's close with grant_removed, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn the_revalidator_judges_the_principal_by_standing_and_shares() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let reval = Revalidator::new(
        rp.stores_b.policies.clone(),
        rp.stores_b.rosters.clone(),
        rp.b.id,
        1,
        rp.b.x25519_public,
    );
    let relay = rp.serving(None);
    rp.serve(up.node_ready, Some(&reval), Some(&relay));
    use crate::revalidate::Action;
    let w = rp.w.network;
    assert_eq!(reval.plan(&w, 1_000), vec![(0, Action::Recheck)]);
    // Expired documents end no session, they only stop what is served.
    edit_roster_of(&rp.w, &rp.stores_b, |b| b.expires = 1);
    edit_policy(&rp.w, &rp.stores_b, |b| b.expires = 1);
    assert_eq!(reval.plan(&w, 1_000), vec![(0, Action::Recheck)]);
    // Documents that expire are a deadline of the pass.
    assert_eq!(reval.deadline(&w, 0), Some(1));
    edit_roster_of(&rp.w, &rp.stores_b, |b| b.labels.clear());
    assert_eq!(
        reval.plan(&w, 1_000),
        vec![(0, Action::Close(ErrorCode::LabelUnclaimed))]
    );
}

// ---- limits and meta --------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_relay_principal_has_its_own_limits_per_share_and_in_all() {
    let mut rp = rp(&[blind("app"), blind("other")], &["app", "other"]).await;
    let up = rp.up().await;
    let relay = rp.serving(Some(RelayLimits::with_figures(2, 3)));
    rp.serve(up.node_ready, None, Some(&relay));
    let mut held = Vec::new();
    for _ in 0..2 {
        let (stream, ack) = open_plain(&up.relay, "tls:app").await;
        assert!(ack.ok, "{ack:?}");
        held.push(stream);
    }
    let (_stream, ack) = open_plain(&up.relay, "tls:app").await;
    assert_refused(
        &ack,
        ErrorCode::RateLimited,
        "the third stream of one share",
    );
    let (stream, ack) = open_plain(&up.relay, "tls:other").await;
    assert!(ack.ok, "another share has its own count: {ack:?}");
    held.push(stream);
    let (_stream, ack) = open_plain(&up.relay, "tls:other").await;
    assert_refused(&ack, ErrorCode::RateLimited, "the fourth stream in all");
    assert_eq!(
        rp.rec.opens.load(Ordering::SeqCst),
        3,
        "a refused OPEN connects to nothing"
    );
}

/// Expose round 1, L1: the relay's streams are counted by `RelayLimits` only. They take no place
/// in the members' `ServeLimits` (so 64 of them neither refuse a member nor use up the node-wide
/// count), and a relay stream is refused at the `RelayLimits` figure, not at the members'
/// per peer one. Real clock: the targets are real sockets.
#[tokio::test]
async fn relay_streams_take_no_place_in_the_members_serve_limits() {
    use tokio::net::TcpListener;
    let w = world();
    let (b, m) = (party(), party());
    let stores = labeled_stores(&w, &[&b, &m], &[("app", b.id)]);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            held.push(socket);
        }
    });
    // Members: 2 a peer, 3 in all. The relay: 5 in all, 5 a share.
    let services = Arc::new(
        LocalServices::new()
            .serve(
                "tls:app".parse().unwrap(),
                LocalTarget::new("127.0.0.1", port),
            )
            .unwrap()
            .with_limits(ServeLimits {
                max_connections: 3,
                max_connections_per_peer: 2,
                ..ServeLimits::default()
            }),
    );
    let handler = RelayHandler::new(
        services.clone(),
        stores.rosters.clone(),
        RelayServing::with_limits(
            book_accepting(&[blind("app")]),
            RelayLimits::with_figures(5, 5),
        ),
        w.network,
        b.id,
    );
    let (relay_id, other_member) = (party().id, party().id);
    let request = |initiator: NodeId| OpenRequest {
        network_id: w.network,
        initiator,
        service: "tls:app".parse().unwrap(),
        target: None,
        meta: OpenMeta::default(),
    };

    // Two streams of one member: its own figure.
    let _m1 = services
        .open(&request(m.id))
        .await
        .expect("member stream 1");
    let _m2 = services
        .open(&request(m.id))
        .await
        .expect("member stream 2");
    assert_eq!(
        services.open(&request(m.id)).await.err().map(|e| e.code),
        Some(ErrorCode::RateLimited),
        "the member's third"
    );
    // Five relay streams, more than the members' per peer figure and than the free places of
    // the node-wide count (1 of 3).
    let mut relay_held = Vec::new();
    for n in 0..5 {
        match handler.open(&request(relay_id)).await {
            Ok(opened) => relay_held.push(opened),
            Err(refusal) => panic!("relay stream {n} refused: {refusal:?}"),
        }
    }
    assert_eq!(
        services.connections(),
        2,
        "relay streams hold no member place"
    );
    // The sixth is refused at the relay's own figure.
    assert_eq!(
        handler.open(&request(relay_id)).await.err().map(|e| e.code),
        Some(ErrorCode::RateLimited),
        "the relay's sixth"
    );
    // A member of another peer still has the node-wide place the relay did not take.
    let _other = services
        .open(&request(other_member))
        .await
        .expect("a member is not refused for lack of places the relay holds");
    assert_eq!(services.connections(), 3);
    // And the relay is not refused because members hold every place.
    drop(relay_held.pop());
    handler
        .open(&request(relay_id))
        .await
        .map(drop)
        .map_err(|e| e.code)
        .expect("a relay stream while the members hold the whole node-wide count");
}

#[tokio::test(start_paused = true)]
async fn the_relays_meta_is_validated_not_scrubbed() {
    let mut rp = rp(&[blind("app")], &["app"]).await;
    let up = rp.up().await;
    let relay = rp.serving(None);
    rp.serve(up.node_ready, None, Some(&relay));

    let meta = |client_ip: &str, sni: &str| OpenMeta {
        client_ip: Some(client_ip.to_string()),
        sni: Some(sni.to_string()),
    };
    let (_s1, ack) = relay_open(
        &up.relay,
        "tls:app",
        None,
        meta("203.0.113.9", "App.relay.example"),
    )
    .await;
    assert!(ack.ok);
    let (_s2, ack) = relay_open(
        &up.relay,
        "tls:app",
        None,
        meta("not an address", "evil.example"),
    )
    .await;
    assert!(ack.ok, "a bad field is dropped, the stream is served");
    let (_s3, ack) = relay_open(
        &up.relay,
        "tls:app",
        None,
        meta("2001:db8::1", &format!("app.{}", "a".repeat(250))),
    )
    .await;
    assert!(ack.ok);

    let seen: Vec<OpenMeta> = rp
        .rec
        .seen
        .lock()
        .unwrap()
        .iter()
        .map(|r| r.meta.clone())
        .collect();
    assert_eq!(seen.len(), 3);
    assert_eq!(
        seen[0],
        OpenMeta {
            client_ip: Some("203.0.113.9".to_string()),
            sni: Some("app.relay.example".to_string())
        }
    );
    assert_eq!(seen[1], OpenMeta::default());
    assert_eq!(
        seen[2],
        OpenMeta {
            client_ip: Some("2001:db8::1".to_string()),
            sni: None
        },
        "an SNI over 253 bytes is dropped"
    );
}

#[test]
fn meta_validation_keeps_only_what_holds_up() {
    let names = vec!["app".to_string(), "web.ali".to_string()];
    let meta = |ip: Option<&str>, sni: Option<&str>| OpenMeta {
        client_ip: ip.map(str::to_string),
        sni: sni.map(str::to_string),
    };
    // Addresses: canonical text, or nothing.
    assert_eq!(
        validate_meta(&meta(Some("192.0.2.1"), None), &names)
            .client_ip
            .as_deref(),
        Some("192.0.2.1")
    );
    assert_eq!(
        validate_meta(&meta(Some("::ffff:192.0.2.1"), None), &names)
            .client_ip
            .as_deref(),
        Some("::ffff:192.0.2.1")
    );
    for bad in [
        "",
        "192.0.2.256",
        "1.2.3.4:80",
        "1.2.3.4\n",
        " 1.2.3.4",
        "localhost",
        "1.2.3.4, 5.6.7.8",
    ] {
        assert_eq!(
            validate_meta(&meta(Some(bad), None), &names).client_ip,
            None,
            "{bad:?}"
        );
    }
    // Names: equal, below, or the name followed by the relay's domain.
    for good in [
        "app",
        "app.relay.example",
        "x.web.ali",
        "web.ali",
        "web.ali.relay.example",
        "APP.RELAY.EXAMPLE",
    ] {
        assert!(
            validate_meta(&meta(None, Some(good)), &names).sni.is_some(),
            "{good}"
        );
    }
    for bad in [
        "",
        // A single label names a share relative to the relay's domain: `x.app` is not below it.
        "x.app",
        "x.y.app",
        "apple.relay.example",
        "xapp",
        "web.relay.example",
        "ali",
        "app\0.example",
        "app.exa mple",
        "app.é.example",
        "other.example",
    ] {
        assert_eq!(
            validate_meta(&meta(None, Some(bad)), &names).sni,
            None,
            "{bad:?}"
        );
    }
    let long = format!("app.{}", "a".repeat(249));
    assert_eq!(long.len(), 253);
    assert!(
        validate_meta(&meta(None, Some(&long)), &names)
            .sni
            .is_some()
    );
    assert_eq!(
        validate_meta(&meta(None, Some(&format!("{long}a"))), &names).sni,
        None
    );
}

/// A member's `meta` is still scrubbed, with the relay principal's path in the build: the
/// existing scrub test (`l5_stream`) must pass beside these; this one adds a member session next
/// to a relay session on the same node.
#[tokio::test(start_paused = true)]
async fn a_members_meta_is_still_scrubbed_beside_a_relay_session() {
    let w = world();
    let (a, b, rel) = (party(), party(), party());
    let stores_b = labeled_stores(&w, &[&a, &b], &[("app", b.id)]);
    let grant = Grant {
        from: Principal {
            network_id: w.network,
            target: PrincipalTarget::Node(a.id),
        },
        to_node: NodeOrWildcard::Node(b.id),
        services: vec!["tls:app".parse().unwrap()],
        expires: None,
    };
    edit_policy(&w, &stores_b, |p| p.grants.push(grant.clone()));
    let stores_a = labeled_stores(&w, &[&a, &b], &[]);
    let net = Net::with_relay_party(&rel);
    let book = book_accepting(&[blind("app")]);
    let mut nb = node_full(&net, &b, &stores_b, TableConfig::default(), book.clone()).await;
    let na = node(&net, &a, &stores_a).await;
    let handle = ensure(&na, b.id, w.network).await.unwrap();
    let ready_b = nb.next_ready().await;
    assert!(!ready_b.relay_principal);
    let rec = Arc::new(Recorder::default());
    serve_session_with_relay(
        ready_b,
        &stores_b.policies,
        &stores_b.rosters,
        b.id,
        1,
        b.x25519_public,
        &rec,
        &DocsGate::new(DocsLimits::default()),
        None,
        None,
        Some(&RelayServing::new(book)),
    );
    let (_stream, ack) = relay_open(
        &handle,
        "tls:app",
        None,
        OpenMeta {
            client_ip: Some("203.0.113.9".to_string()),
            sni: Some("app.relay.example".to_string()),
        },
    )
    .await;
    assert!(ack.ok, "{ack:?}");
    assert_eq!(rec.seen.lock().unwrap()[0].meta, OpenMeta::default());
}
