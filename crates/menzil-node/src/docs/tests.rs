use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use ed25519_dalek::SigningKey;
use futures_util::io::Cursor;
use menzil_proto::docs::{MAX_FRAME_LEN, MAX_MESSAGES};
use menzil_proto::{
    NodeId, PROTOCOL_VERSION, PolicyBody, PolicyMember, RosterBody, RosterMember, Steward,
    StewardBody, StewardKey,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};

use super::*;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;

// ---------------------------------------------------------------- streams

/// A tokio stream seen through the futures traits the library takes.
struct Compat<T>(T);

impl<T: tokio::io::AsyncRead + Unpin> AsyncRead for Compat<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> AsyncWrite for Compat<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

fn pair() -> (Compat<DuplexStream>, Compat<DuplexStream>) {
    let (a, b) = duplex(1 << 21);
    (Compat(a), Compat(b))
}

/// One end for the library, the other raw for a test that writes bytes by hand.
fn raw_pair() -> (Compat<DuplexStream>, DuplexStream) {
    let (a, b) = duplex(1 << 21);
    (Compat(a), b)
}

/// A stream that yields a fixed prefix and then fails, remembering that it was read past it.
struct PrefixThenFail {
    prefix: Vec<u8>,
    pos: usize,
    overread: Arc<AtomicBool>,
}

impl AsyncRead for PrefixThenFail {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.pos >= self.prefix.len() {
            self.overread.store(true, Ordering::SeqCst);
            return Poll::Ready(Err(io::Error::other("read past the length prefix")));
        }
        let n = buf.len().min(self.prefix.len() - self.pos);
        buf[..n].copy_from_slice(&self.prefix[self.pos..self.pos + n]);
        self.pos += n;
        Poll::Ready(Ok(n))
    }
}

impl AsyncWrite for PrefixThenFail {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------- documents

struct Net {
    owner: SigningKey,
    steward: SigningKey,
    network_id: NetworkId,
    roster: RosterBody,
    policy: PolicyBody,
    base_roster: Roster,
    base_policy: Policy,
}

impl Net {
    fn new() -> Self {
        let owner = SigningKey::generate(&mut rand::rng());
        let steward = SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let entry = Steward::sign(
            &owner,
            &StewardBody {
                v: PROTOCOL_VERSION,
                network_id,
                steward_pub: StewardKey::from(steward.verifying_key().to_bytes()),
                may: vec!["renew".to_string()],
                not_after: NOW + 30 * DAY,
            },
        )
        .unwrap();
        let roster = RosterBody {
            v: PROTOCOL_VERSION,
            network_id,
            seq: 10,
            issued: NOW - DAY,
            expires: NOW + 5 * DAY,
            members: vec![RosterMember {
                node_id: NodeId::from([1u8; 32]),
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![entry],
            labels: vec![],
        };
        let policy = PolicyBody {
            v: PROTOCOL_VERSION,
            network_id,
            seq: 10,
            issued: NOW - DAY,
            expires: NOW + 5 * DAY,
            members: vec![PolicyMember {
                node_id: NodeId::from([1u8; 32]),
                name: "laptop".to_string(),
                roles: vec![],
            }],
            certs: vec![],
            grants: vec![],
            egress: vec![],
            accept: vec![],
        };
        Self {
            base_roster: Roster::sign(&owner, &roster).unwrap(),
            base_policy: Policy::sign(&owner, &policy).unwrap(),
            owner,
            steward,
            network_id,
            roster,
            policy,
        }
    }

    fn base_bundle(&self) -> Bundle {
        Bundle {
            roster: Some(self.base_roster.clone()),
            policy: Some(self.base_policy.clone()),
            ..Bundle::default()
        }
    }

    /// A renewal pair at `seq` signed by `signer`, with the bases when it is the steward's.
    fn renewal(&self, signer: &SigningKey, seq: u64) -> Bundle {
        let mut roster = self.roster.clone();
        let mut policy = self.policy.clone();
        roster.seq = seq;
        policy.seq = seq;
        roster.issued = NOW;
        policy.issued = NOW;
        roster.expires = NOW + 7 * DAY;
        policy.expires = NOW + 7 * DAY;
        let steward = signer.verifying_key() == self.steward.verifying_key();
        Bundle {
            base_roster: steward.then(|| self.base_roster.clone()),
            base_policy: steward.then(|| self.base_policy.clone()),
            roster: Some(Roster::sign(signer, &roster).unwrap()),
            policy: Some(Policy::sign(signer, &policy).unwrap()),
        }
    }
}

struct Stores {
    rosters: RosterStore,
    policies: PolicyStore,
}

impl Stores {
    fn empty() -> Self {
        Self {
            rosters: RosterStore::new(),
            policies: PolicyStore::new(),
        }
    }

    /// Holding the owner signed pair at seq 10.
    fn with_base(net: &Net) -> Self {
        let stores = Self::empty();
        stores.adopt(net, &net.base_bundle());
        stores
    }

    /// Holding the steward signed pair at `seq` (and its bases).
    fn with_steward_pair(net: &Net, seq: u64) -> Self {
        let stores = Self::with_base(net);
        stores.adopt(net, &net.renewal(&net.steward, seq));
        stores
    }

    fn adopt(&self, net: &Net, bundle: &Bundle) -> Adopted {
        self.docs(net).adopt(bundle, NOW).unwrap()
    }

    fn docs(&self, net: &Net) -> StoreDocs<'_> {
        StoreDocs::new(&self.rosters, &self.policies, net.network_id)
    }
}

fn params(net: &Net) -> DocsParams {
    DocsParams {
        network_id: net.network_id,
        now: NOW,
        deadline: STREAM_DEADLINE,
    }
}

fn kinds(messages: &[Message]) -> Vec<&'static str> {
    messages
        .iter()
        .map(|m| match m {
            Message::Doc {
                kind: DocKind::BaseRoster,
                ..
            } => "base_roster",
            Message::Doc {
                kind: DocKind::BasePolicy,
                ..
            } => "base_policy",
            Message::Doc {
                kind: DocKind::Roster,
                ..
            } => "roster",
            Message::Doc {
                kind: DocKind::Policy,
                ..
            } => "policy",
            Message::End { .. } => "end",
            _ => "other",
        })
        .collect()
}

// ---------------------------------------------------------------- plan_fetch

#[test]
fn a_fetch_from_nothing_gets_both_documents_and_an_end_with_our_seqs() {
    let net = Net::new();
    let stores = Stores::with_base(&net);
    let plan = plan_fetch(&stores.docs(&net), None, None, None, None, NOW);
    assert_eq!(kinds(&plan), vec!["roster", "policy", "end"]);
    assert_eq!(
        plan.last(),
        Some(&Message::End {
            roster_seq: Some(10),
            policy_seq: Some(10)
        })
    );
    // The verbatim encodings, owner signed, so no bases.
    assert_eq!(
        plan[0],
        Message::Doc {
            kind: DocKind::Roster,
            doc: net.base_roster.encode()
        }
    );
}

#[test]
fn nothing_newer_means_only_an_end() {
    let net = Net::new();
    let stores = Stores::with_base(&net);
    for (r, p) in [(Some(10), Some(10)), (Some(11), Some(12))] {
        let plan = plan_fetch(&stores.docs(&net), r, p, None, None, NOW);
        assert_eq!(kinds(&plan), vec!["end"], "requester at {r:?} {p:?}");
    }
    // A requester behind on the Roster only gets the Roster... and the Policy it is behind on.
    let plan = plan_fetch(&stores.docs(&net), Some(9), Some(10), None, None, NOW);
    assert_eq!(kinds(&plan), vec!["roster", "end"]);
    let plan = plan_fetch(&stores.docs(&net), Some(10), Some(9), None, None, NOW);
    assert_eq!(kinds(&plan), vec!["policy", "end"]);
}

#[test]
fn a_policy_is_served_only_with_a_roster_of_the_same_seq() {
    let net = Net::new();
    // The Roster moved on to 11 alone; the Policy is still at 10.
    let stores = Stores::with_base(&net);
    let mut roster_only = net.renewal(&net.owner, 11);
    roster_only.policy = None;
    assert!(stores.adopt(&net, &roster_only).roster);
    assert_eq!(stores.rosters.seq(&net.network_id), Some(11));
    assert_eq!(stores.policies.seq(&net.network_id), Some(10));
    let plan = plan_fetch(&stores.docs(&net), None, None, None, None, NOW);
    assert_eq!(kinds(&plan), vec!["roster", "end"]);
    // The pair is complete at 11: the Policy follows.
    let mut policy_only = net.renewal(&net.owner, 11);
    policy_only.roster = None;
    assert!(stores.adopt(&net, &policy_only).policy);
    let plan = plan_fetch(&stores.docs(&net), None, None, None, None, NOW);
    assert_eq!(kinds(&plan), vec!["roster", "policy", "end"]);
}

#[test]
fn a_policy_without_a_roster_goes_only_to_a_requester_holding_that_roster() {
    let net = Net::new();
    let stores = Stores::with_steward_pair(&net, 11);
    // The requester holds the Roster of seq 11 but an older Policy: the Policy alone fits.
    let plan = plan_fetch(&stores.docs(&net), Some(11), Some(10), None, None, NOW);
    assert_eq!(kinds(&plan), vec!["base_policy", "policy", "end"]);
    let plan = plan_fetch(
        &stores.docs(&net),
        Some(11),
        Some(10),
        Some(10),
        Some(10),
        NOW,
    );
    assert_eq!(kinds(&plan), vec!["policy", "end"]);
    // A requester ahead on the Roster (12) would be sent a Policy it cannot pair: nothing.
    let plan = plan_fetch(&stores.docs(&net), Some(12), Some(10), None, None, NOW);
    assert_eq!(kinds(&plan), vec!["end"]);
    // A requester with no Roster is sent the Roster, so the Policy comes along.
    let plan = plan_fetch(&stores.docs(&net), None, Some(10), None, None, NOW);
    assert_eq!(
        kinds(&plan),
        vec!["base_roster", "base_policy", "roster", "policy", "end"]
    );
}

#[test]
fn bases_go_first_and_are_omitted_when_the_requester_holds_them() {
    let net = Net::new();
    let stores = Stores::with_steward_pair(&net, 11);
    let docs = stores.docs(&net);
    assert_eq!(docs.held().base_seq, Some(10));
    // Nothing held: all four, bases first.
    let plan = plan_fetch(&docs, None, None, None, None, NOW);
    assert_eq!(
        kinds(&plan),
        vec!["base_roster", "base_policy", "roster", "policy", "end"]
    );
    assert_eq!(
        plan[0],
        Message::Doc {
            kind: DocKind::BaseRoster,
            doc: net.base_roster.encode()
        }
    );
    assert_eq!(
        plan[1],
        Message::Doc {
            kind: DocKind::BasePolicy,
            doc: net.base_policy.encode()
        }
    );
    // The requester's base is the one we hold (10): bases omitted, documents kept.
    let plan = plan_fetch(&docs, Some(10), Some(10), Some(10), Some(10), NOW);
    assert_eq!(kinds(&plan), vec!["roster", "policy", "end"]);
    // Another base seq than ours: sent again.
    let plan = plan_fetch(&docs, Some(10), Some(10), Some(9), Some(9), NOW);
    assert_eq!(
        kinds(&plan),
        vec!["base_roster", "base_policy", "roster", "policy", "end"]
    );
    // Only the Roster is sent: only its base comes.
    let plan = plan_fetch(&docs, Some(10), Some(11), None, None, NOW);
    assert_eq!(kinds(&plan), vec!["base_roster", "roster", "end"]);
}

#[test]
fn an_expired_document_is_not_sent() {
    let net = Net::new();
    let stores = Stores::with_base(&net);
    // The pair expires at NOW + 5 days: at that second it no longer counts.
    let plan = plan_fetch(&stores.docs(&net), None, None, None, None, NOW + 5 * DAY);
    assert_eq!(kinds(&plan), vec!["end"]);
    let plan = plan_fetch(
        &stores.docs(&net),
        None,
        None,
        None,
        None,
        NOW + 5 * DAY - 1,
    );
    assert_eq!(kinds(&plan), vec!["roster", "policy", "end"]);
    // The Policy on its own (the requester holds the Roster) expires at the same second.
    let plan = plan_fetch(
        &stores.docs(&net),
        Some(9),
        None,
        None,
        None,
        NOW + 5 * DAY - 1,
    );
    assert_eq!(kinds(&plan), vec!["roster", "policy", "end"]);
    let plan = plan_fetch(
        &stores.docs(&net),
        Some(10),
        None,
        None,
        None,
        NOW + 5 * DAY - 1,
    );
    assert_eq!(kinds(&plan), vec!["policy", "end"]);
    let plan = plan_fetch(
        &stores.docs(&net),
        Some(10),
        None,
        None,
        None,
        NOW + 5 * DAY,
    );
    assert_eq!(kinds(&plan), vec!["end"]);
}

#[test]
fn a_store_with_nothing_answers_with_an_empty_end() {
    let net = Net::new();
    let stores = Stores::empty();
    let plan = plan_fetch(&stores.docs(&net), None, None, None, None, NOW);
    assert_eq!(
        plan,
        vec![Message::End {
            roster_seq: None,
            policy_seq: None
        }]
    );
}

#[test]
fn bundle_to_push_carries_the_pair_with_bases_and_skips_what_does_not_fit() {
    let net = Net::new();
    let stores = Stores::with_steward_pair(&net, 11);
    let bundle = bundle_to_push(&stores.docs(&net), NOW);
    assert!(bundle.roster.is_some() && bundle.policy.is_some());
    assert!(bundle.base_roster.is_some() && bundle.base_policy.is_some());
    // Expired: nothing.
    let bundle = bundle_to_push(&stores.docs(&net), NOW + 8 * DAY);
    assert!(bundle.roster.is_none() && bundle.policy.is_none());
    // A Policy that does not pair with the Roster stays home.
    let stores = Stores::with_base(&net);
    let mut roster_only = net.renewal(&net.owner, 11);
    roster_only.policy = None;
    stores.adopt(&net, &roster_only);
    let bundle = bundle_to_push(&stores.docs(&net), NOW);
    assert!(bundle.roster.is_some());
    assert!(bundle.policy.is_none());
    // A Policy whose own expiry has passed stays home too.
    let stores = Stores::with_base(&net);
    let mut late_roster = net.renewal(&net.owner, 11);
    late_roster.policy = None;
    stores.adopt(&net, &late_roster);
    let mut short = net.renewal(&net.owner, 11);
    let mut body = net.policy.clone();
    body.seq = 11;
    body.issued = NOW;
    body.expires = NOW + DAY;
    short.policy = Some(Policy::sign(&net.owner, &body).unwrap());
    short.roster = None;
    stores.adopt(&net, &short);
    let bundle = bundle_to_push(&stores.docs(&net), NOW + 2 * DAY);
    assert!(bundle.roster.is_some());
    assert!(bundle.policy.is_none());
    // The boundary is the second of `expires`.
    assert!(
        bundle_to_push(&stores.docs(&net), NOW + DAY - 1)
            .policy
            .is_some()
    );
    assert!(
        bundle_to_push(&stores.docs(&net), NOW + DAY)
            .policy
            .is_none()
    );
    assert!(
        bundle_to_push(&stores.docs(&net), NOW + 7 * DAY - 1)
            .roster
            .is_some()
    );
    assert!(
        bundle_to_push(&stores.docs(&net), NOW + 7 * DAY)
            .roster
            .is_none()
    );
}

#[test]
fn a_push_is_push_then_bases_first_then_end_with_the_bundles_seqs() {
    let net = Net::new();
    let stores = Stores::with_steward_pair(&net, 11);
    let bundle = bundle_to_push(&stores.docs(&net), NOW);
    let messages = push_messages(&bundle);
    assert_eq!(messages[0], Message::Push);
    assert_eq!(
        kinds(&messages[1..]),
        vec!["base_roster", "base_policy", "roster", "policy", "end"]
    );
    assert_eq!(
        messages.last(),
        Some(&Message::End {
            roster_seq: Some(11),
            policy_seq: Some(11)
        })
    );
    // The most a push can be is the six messages a receiver admits.
    assert_eq!(messages.len(), MAX_MESSAGES);
    let empty = push_messages(&Bundle::default());
    assert_eq!(
        empty,
        vec![
            Message::Push,
            Message::End {
                roster_seq: None,
                policy_seq: None
            }
        ]
    );
}

// ---------------------------------------------------------------- over a stream

#[tokio::test]
async fn a_fetch_over_a_stream_brings_the_steward_pair_and_its_bases() {
    let net = Net::new();
    let server = Stores::with_steward_pair(&net, 11);
    let client = Stores::with_base(&net);
    let (mut a, mut b) = pair();
    let p = params(&net);
    let (fetched, served) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    let report = fetched.unwrap();
    assert_eq!(served.unwrap(), Served::Fetch);
    assert_eq!(
        report.adopted,
        Adopted {
            roster: true,
            policy: true
        }
    );
    assert_eq!(report.peer_roster_seq, Some(11));
    assert_eq!(report.peer_policy_seq, Some(11));
    assert_eq!(client.rosters.seq(&net.network_id), Some(11));
    assert_eq!(client.policies.seq(&net.network_id), Some(11));
    assert_eq!(client.docs(&net).held().base_seq, Some(10));
    // A second fetch finds nothing new and adopts nothing.
    let (mut a, mut b) = pair();
    let (fetched, _) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    assert_eq!(fetched.unwrap().adopted, Adopted::default());

    // A Roster alone brings only a Roster, and that is adopted too.
    let mut roster_only = net.renewal(&net.owner, 12);
    roster_only.policy = None;
    server.adopt(&net, &roster_only);
    let (mut a, mut b) = pair();
    let (fetched, _) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    assert_eq!(
        fetched.unwrap().adopted,
        Adopted {
            roster: true,
            policy: false
        }
    );
    assert_eq!(client.rosters.seq(&net.network_id), Some(12));
    assert_eq!(client.policies.seq(&net.network_id), Some(11));
}

/// Protocol.md 5.5: the answer leaves out a base the opener announced, so the opener has to put
/// its own back before the predicate judges a steward renewal made from that same base.
#[tokio::test]
async fn a_steward_renewal_on_the_base_the_opener_holds_is_adopted_without_a_base_on_the_wire() {
    let net = Net::new();
    let server = Stores::with_steward_pair(&net, 12);
    let client = Stores::with_steward_pair(&net, 11);
    assert_eq!(client.docs(&net).held().base_seq, Some(10));
    // The server sends no base: the opener holds the one it would send.
    let planned = plan_fetch(
        &server.docs(&net),
        Some(11),
        Some(11),
        Some(10),
        Some(10),
        NOW,
    );
    assert_eq!(kinds(&planned), ["roster", "policy", "end"]);
    let (mut a, mut b) = pair();
    let p = params(&net);
    let (fetched, served) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    assert_eq!(served.unwrap(), Served::Fetch);
    assert_eq!(
        fetched.unwrap().adopted,
        Adopted {
            roster: true,
            policy: true
        }
    );
    assert_eq!(client.rosters.seq(&net.network_id), Some(12));
    assert_eq!(client.policies.seq(&net.network_id), Some(12));
    // The base was kept with the new documents.
    let (_, base) = client.docs(&net).roster().unwrap();
    assert_eq!(roster_seq_of(&base.unwrap()), Some(10));
    let (_, base) = client.docs(&net).policy().unwrap();
    assert_eq!(policy_seq_of(&base.unwrap()), Some(10));
}

/// A sink that holds a base of another `seq` than it announced gets nothing filled in.
#[test]
fn a_base_is_filled_in_only_when_its_seq_is_the_announced_one() {
    let net = Net::new();
    let mut bundle = net.renewal(&net.steward, 12);
    bundle.base_roster = None;
    bundle.base_policy = None;
    let bases = HeldBases {
        roster: Some(net.base_roster.clone()),
        policy: Some(net.base_policy.clone()),
    };
    let mut other = bundle.clone();
    fill_bases(&mut other, Some(9), Some(9), bases.clone());
    assert!(other.base_roster.is_none() && other.base_policy.is_none());
    fill_bases(&mut other, None, None, bases.clone());
    assert!(other.base_roster.is_none() && other.base_policy.is_none());
    // Each base is judged against its own announcement.
    fill_bases(&mut other, Some(10), Some(9), bases.clone());
    assert!(other.base_roster.is_some() && other.base_policy.is_none());
    fill_bases(&mut bundle, Some(10), Some(10), bases);
    assert!(bundle.base_roster.is_some() && bundle.base_policy.is_some());
}

/// `StoreDocs` is for one network: a bundle of another is refused, not adopted into the store.
#[test]
fn store_docs_refuses_a_bundle_of_another_network() {
    let net = Net::new();
    let other = Net::new();
    let stores = Stores::empty();
    let error = stores
        .docs(&net)
        .adopt(&other.base_bundle(), NOW)
        .unwrap_err();
    assert!(matches!(
        error,
        NodeError::DocumentRejected(Reason::WrongNetwork)
    ));
    assert_eq!(stores.rosters.seq(&other.network_id), None);
    assert_eq!(stores.policies.seq(&other.network_id), None);
    // Its own network's bundle goes in.
    assert_eq!(
        stores.docs(&net).adopt(&net.base_bundle(), NOW).unwrap(),
        Adopted {
            roster: true,
            policy: true
        }
    );
}

/// The Policy and its base come from one read.
#[test]
fn the_policy_and_its_base_are_read_together() {
    let net = Net::new();
    let owned = Stores::with_base(&net);
    let (policy, base) = owned.docs(&net).policy().unwrap();
    assert_eq!(policy_seq_of(&policy), Some(10));
    assert!(base.is_none());
    let stewarded = Stores::with_steward_pair(&net, 11);
    let (policy, base) = stewarded.policies.get_with_base(&net.network_id).unwrap();
    assert_eq!(policy_seq_of(&policy), Some(11));
    assert_eq!(policy_seq_of(&base.unwrap()), Some(10));
    assert!(
        Stores::empty()
            .policies
            .get_with_base(&net.network_id)
            .is_none()
    );
}

#[tokio::test]
async fn a_fetch_of_documents_of_another_network_is_refused_and_nothing_is_stored() {
    let net = Net::new();
    let other = Net::new();
    let server = Stores::with_steward_pair(&other, 11);
    let client = Stores::with_base(&net);
    let (mut a, mut b) = pair();
    // The server serves its own network's documents on a session of `net`.
    let server_params = DocsParams {
        network_id: other.network_id,
        ..params(&net)
    };
    let p = params(&net);
    let (fetched, _) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&other),
            server.docs(&other),
            &server_params,
            ServeMode::Full
        ),
    );
    assert!(matches!(
        fetched,
        Err(DocsStreamError::Rejected(Reason::WrongNetwork))
    ));
    assert_eq!(client.rosters.seq(&net.network_id), Some(10));
}

async fn push_to(
    net: &Net,
    receiver: &Stores,
    bundle: &Bundle,
    mode: ServeMode,
) -> (
    Result<PushResult, DocsStreamError>,
    Result<Served, DocsStreamError>,
) {
    let (mut a, mut b) = pair();
    let p = params(net);
    tokio::join!(
        push(&mut a, bundle, &p),
        serve(&mut b, receiver.docs(net), receiver.docs(net), &p, mode),
    )
}

#[tokio::test]
async fn a_push_is_adopted_then_reported_held_then_not_sent() {
    let net = Net::new();
    let receiver = Stores::with_base(&net);
    let sender = Stores::with_steward_pair(&net, 11);
    let bundle = bundle_to_push(&sender.docs(&net), NOW);

    let (pushed, served) = push_to(&net, &receiver, &bundle, ServeMode::Full).await;
    let expected = PushResult {
        roster: Outcome::Adopted,
        policy: Outcome::Adopted,
        code: None,
        roster_seq: Some(11),
        policy_seq: Some(11),
    };
    assert_eq!(pushed.unwrap(), expected);
    assert_eq!(served.unwrap(), Served::Push(expected));
    assert_eq!(receiver.rosters.seq(&net.network_id), Some(11));

    // The same again: already held (1, 1), nothing changes.
    let (pushed, _) = push_to(&net, &receiver, &bundle, ServeMode::Full).await;
    assert_eq!(
        pushed.unwrap(),
        PushResult {
            roster: Outcome::Held,
            policy: Outcome::Held,
            code: None,
            roster_seq: Some(11),
            policy_seq: Some(11),
        }
    );

    // Roster only: the Policy was not sent (3).
    let mut roster_only = net.renewal(&net.owner, 12);
    roster_only.policy = None;
    let (pushed, _) = push_to(&net, &receiver, &roster_only, ServeMode::Full).await;
    assert_eq!(
        pushed.unwrap(),
        PushResult {
            roster: Outcome::Adopted,
            policy: Outcome::NotSent,
            code: None,
            roster_seq: Some(12),
            policy_seq: Some(11),
        }
    );

    // Policy only, paired with the Roster the receiver holds: adopted (0), Roster not sent (3).
    let mut policy_only = net.renewal(&net.owner, 12);
    policy_only.roster = None;
    let (pushed, _) = push_to(&net, &receiver, &policy_only, ServeMode::Full).await;
    assert_eq!(
        pushed.unwrap(),
        PushResult {
            roster: Outcome::NotSent,
            policy: Outcome::Adopted,
            code: None,
            roster_seq: Some(12),
            policy_seq: Some(12),
        }
    );

    // Nothing at all: (3, 3), no code.
    let (pushed, _) = push_to(&net, &receiver, &Bundle::default(), ServeMode::Full).await;
    assert_eq!(
        pushed.unwrap(),
        PushResult {
            roster: Outcome::NotSent,
            policy: Outcome::NotSent,
            code: None,
            roster_seq: Some(12),
            policy_seq: Some(12),
        }
    );
}

#[tokio::test]
async fn an_older_roster_with_a_newer_policy_gets_a_mixed_result() {
    let net = Net::new();
    let receiver = Stores::with_steward_pair(&net, 12);
    // A pair of seq 12 from the owner: both held already.
    let (pushed, _) = push_to(
        &net,
        &receiver,
        &net.renewal(&net.owner, 12),
        ServeMode::Full,
    )
    .await;
    let pushed = pushed.unwrap();
    assert_eq!(
        (pushed.roster, pushed.policy),
        (Outcome::Held, Outcome::Held)
    );
}

#[tokio::test]
async fn a_rejected_push_gets_code_25_stores_nothing_and_marks_what_was_sent() {
    let net = Net::new();
    let receiver = Stores::with_base(&net);
    // A good Roster beside a Policy signed by a stranger: refused whole.
    let mut bundle = net.renewal(&net.owner, 11);
    let stranger = SigningKey::generate(&mut rand::rng());
    let mut forged = net.policy.clone();
    forged.seq = 11;
    forged.issued = NOW;
    forged.expires = NOW + 7 * DAY;
    bundle.policy = Some(Policy::sign(&stranger, &forged).unwrap());
    let (pushed, served) = push_to(&net, &receiver, &bundle, ServeMode::Full).await;
    let expected = PushResult {
        roster: Outcome::Rejected,
        policy: Outcome::Rejected,
        code: Some(ErrorCode::BadDocument),
        roster_seq: Some(10),
        policy_seq: Some(10),
    };
    assert_eq!(pushed.unwrap(), expected);
    assert_eq!(served.unwrap(), Served::Push(expected));
    assert_eq!(receiver.rosters.seq(&net.network_id), Some(10));

    // A Roster alone, rejected: the Policy stays "not sent" (3), not "rejected".
    let mut roster_only = net.renewal(&net.steward, 11);
    roster_only.policy = None;
    roster_only.base_roster = None; // a steward signed Roster without its base
    let (pushed, _) = push_to(&net, &receiver, &roster_only, ServeMode::Full).await;
    let pushed = pushed.unwrap();
    assert_eq!(pushed.roster, Outcome::Rejected);
    assert_eq!(pushed.policy, Outcome::NotSent);
    assert_eq!(pushed.code, Some(ErrorCode::BadDocument));
}

#[tokio::test]
async fn an_expired_push_gets_roster_expired() {
    let net = Net::new();
    let receiver = Stores::empty();
    // The sender's clock is fine; the receiver's is a month later.
    let (mut a, mut b) = pair();
    let late = DocsParams {
        now: NOW + 30 * DAY,
        ..params(&net)
    };
    let base_bundle = net.base_bundle();
    let (pushed, _) = tokio::join!(
        push(&mut a, &base_bundle, &late),
        serve(
            &mut b,
            receiver.docs(&net),
            receiver.docs(&net),
            &late,
            ServeMode::Full
        ),
    );
    let pushed = pushed.unwrap();
    assert_eq!(pushed.code, Some(ErrorCode::RosterExpired));
    assert_eq!(
        (pushed.roster, pushed.policy),
        (Outcome::Rejected, Outcome::Rejected)
    );
    assert_eq!(pushed.roster_seq, None);
}

#[tokio::test]
async fn a_push_of_another_networks_documents_is_answered_25_and_not_adopted() {
    let net = Net::new();
    let other = Net::new();
    let receiver = Stores::empty();
    // `other`'s documents are perfectly valid for `other`; the session is `net`'s.
    let (pushed, _) = push_to(&net, &receiver, &other.base_bundle(), ServeMode::Full).await;
    let pushed = pushed.unwrap();
    assert_eq!(pushed.code, Some(ErrorCode::BadDocument));
    assert_eq!(pushed.roster, Outcome::Rejected);
    assert!(receiver.rosters.get(&other.network_id).is_none());
    // A base of another network is refused as well.
    let mut bundle = net.renewal(&net.steward, 11);
    bundle.base_policy = Some(other.base_policy.clone());
    let receiver = Stores::with_base(&net);
    let (pushed, _) = push_to(&net, &receiver, &bundle, ServeMode::Full).await;
    assert_eq!(pushed.unwrap().code, Some(ErrorCode::BadDocument));
    assert_eq!(receiver.rosters.seq(&net.network_id), Some(10));
}

#[tokio::test]
async fn one_foreign_document_alone_is_refused_whatever_the_stores_would_make_of_it() {
    let net = Net::new();
    let other = Net::new();
    // A receiver that holds `other`'s pair at seq 10 would adopt `other`'s seq 11 documents if
    // nothing checked the network of the session first.
    let renewal = other.renewal(&other.owner, 11);
    let cases: Vec<(&str, Bundle)> = vec![
        (
            "roster alone",
            Bundle {
                roster: renewal.roster.clone(),
                ..Bundle::default()
            },
        ),
        (
            "policy alone",
            Bundle {
                policy: renewal.policy.clone(),
                ..Bundle::default()
            },
        ),
    ];
    for (name, bundle) in cases {
        let receiver = Stores::with_base(&other);
        let (pushed, _) = push_to(&net, &receiver, &bundle, ServeMode::Full).await;
        let pushed = pushed.unwrap();
        assert_eq!(pushed.code, Some(ErrorCode::BadDocument), "{name}");
        assert_eq!(receiver.rosters.seq(&other.network_id), Some(10), "{name}");
        assert_eq!(receiver.policies.seq(&other.network_id), Some(10), "{name}");
    }
    // A Policy alone pairs with a Roster of its seq that the receiver holds already.
    let receiver = Stores::with_base(&other);
    let roster_only = Bundle {
        roster: renewal.roster.clone(),
        ..Bundle::default()
    };
    receiver.adopt(&other, &roster_only);
    let policy_only = Bundle {
        policy: renewal.policy.clone(),
        ..Bundle::default()
    };
    let (pushed, _) = push_to(&net, &receiver, &policy_only, ServeMode::Full).await;
    assert_eq!(pushed.unwrap().code, Some(ErrorCode::BadDocument));
    assert_eq!(receiver.policies.seq(&other.network_id), Some(10));
    // The same documents on a session of their own network are adopted.
    let receiver = Stores::with_base(&other);
    let (pushed, _) = push_to(&other, &receiver, &renewal, ServeMode::Full).await;
    assert_eq!(pushed.unwrap().roster, Outcome::Adopted);
}

#[tokio::test]
async fn a_document_that_does_not_decode_is_answered_25() {
    let net = Net::new();
    let receiver = Stores::empty();
    let (mut a, mut raw) = raw_pair();
    let p = params(&net);
    let writer = async {
        for message in [
            Message::Push,
            Message::Doc {
                kind: DocKind::Roster,
                doc: vec![0xde, 0xad],
            },
            Message::End {
                roster_seq: None,
                policy_seq: None,
            },
        ] {
            raw.write_all(&encode_frame(&message).unwrap())
                .await
                .unwrap();
        }
        let mut head = [0u8; 4];
        raw.read_exact(&mut head).await.unwrap();
        let mut body = vec![0u8; u32::from_be_bytes(head) as usize];
        raw.read_exact(&mut body).await.unwrap();
        decode_message(&body).unwrap()
    };
    let (reply, served) = tokio::join!(
        writer,
        serve(
            &mut a,
            receiver.docs(&net),
            receiver.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    assert!(matches!(
        reply,
        Message::Result {
            roster: Outcome::Rejected,
            policy: Outcome::NotSent,
            code: Some(ErrorCode::BadDocument),
            ..
        }
    ));
    served.unwrap();
}

#[tokio::test]
async fn a_docs_only_session_refuses_a_fetch_and_sends_nothing() {
    let net = Net::new();
    let server = Stores::with_base(&net);
    let (mut a, mut raw) = raw_pair();
    let p = params(&net);
    let writer = async {
        let fetch = Message::Fetch {
            roster_seq: None,
            policy_seq: None,
            base_seq: None,
            policy_base_seq: None,
        };
        raw.write_all(&encode_frame(&fetch).unwrap()).await.unwrap();
    };
    let (_, served) = tokio::join!(
        writer,
        serve(
            &mut a,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::PushOnly
        ),
    );
    assert!(matches!(served, Err(DocsStreamError::Unexpected(_))));
    drop(a);
    let mut rest = Vec::new();
    raw.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty(), "no document, no end, nothing was sent");
    // The same server in full mode answers.
    let (mut a, mut b) = pair();
    let client = Stores::empty();
    let (fetched, _) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    assert!(fetched.unwrap().adopted.roster);
}

// ---------------------------------------------------------------- limits

fn frame_with_prefix(prefix: u32) -> Vec<u8> {
    prefix.to_be_bytes().to_vec()
}

#[tokio::test]
async fn an_oversize_length_is_refused_before_anything_beyond_the_prefix_is_read() {
    for prefix in [MAX_FRAME_LEN as u32 + 1, 2_000_000, u32::MAX] {
        let overread = Arc::new(AtomicBool::new(false));
        let mut stream = PrefixThenFail {
            prefix: frame_with_prefix(prefix),
            pos: 0,
            overread: overread.clone(),
        };
        let net = Net::new();
        let stores = Stores::empty();
        let served = serve(
            &mut stream,
            stores.docs(&net),
            stores.docs(&net),
            &params(&net),
            ServeMode::Full,
        )
        .await;
        assert!(
            matches!(
                served,
                Err(DocsStreamError::Frame(DocsError::FrameTooLarge { .. }))
            ),
            "prefix {prefix}: {served:?}"
        );
        assert!(!overread.load(Ordering::SeqCst), "read past the prefix");
    }
}

#[tokio::test]
async fn the_largest_frame_length_is_read_not_refused() {
    // At exactly the limit the body is read (here the stream then fails: an io error, not a
    // framing one).
    let overread = Arc::new(AtomicBool::new(false));
    let mut stream = PrefixThenFail {
        prefix: frame_with_prefix(MAX_FRAME_LEN as u32),
        pos: 0,
        overread: overread.clone(),
    };
    let mut counter = MessageCounter::new();
    let result = read_message(&mut stream, &mut counter).await;
    assert!(matches!(result, Err(DocsStreamError::Io(_))), "{result:?}");
    assert!(overread.load(Ordering::SeqCst));
}

#[tokio::test]
async fn the_seventh_message_is_refused_before_its_header_is_read() {
    let push = encode_frame(&Message::Push).unwrap();
    let mut bytes = Vec::new();
    for _ in 0..=MAX_MESSAGES {
        bytes.extend_from_slice(&push);
    }
    let mut cursor = Cursor::new(bytes);
    let mut counter = MessageCounter::new();
    for _ in 0..MAX_MESSAGES {
        assert_eq!(
            read_message(&mut cursor, &mut counter).await.unwrap(),
            Message::Push
        );
    }
    let at = cursor.position();
    let seventh = read_message(&mut cursor, &mut counter).await;
    assert!(matches!(
        seventh,
        Err(DocsStreamError::Frame(DocsError::TooManyMessages { .. }))
    ));
    assert_eq!(cursor.position(), at, "the seventh header was not read");
}

#[tokio::test]
async fn a_push_may_use_all_six_messages() {
    // push, four documents, end: six, and the stream is accepted (the documents are junk, so
    // the answer is 25 and not an error of the stream).
    let net = Net::new();
    let receiver = Stores::empty();
    let (mut a, mut raw) = raw_pair();
    let p = params(&net);
    let writer = async {
        raw.write_all(&encode_frame(&Message::Push).unwrap())
            .await
            .unwrap();
        for kind in [
            DocKind::BaseRoster,
            DocKind::BasePolicy,
            DocKind::Roster,
            DocKind::Policy,
        ] {
            let doc = Message::Doc { kind, doc: vec![0] };
            raw.write_all(&encode_frame(&doc).unwrap()).await.unwrap();
        }
        let end = Message::End {
            roster_seq: None,
            policy_seq: None,
        };
        raw.write_all(&encode_frame(&end).unwrap()).await.unwrap();
    };
    let (_, served) = tokio::join!(
        writer,
        serve(
            &mut a,
            receiver.docs(&net),
            receiver.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    assert!(matches!(served, Ok(Served::Push(_))), "{served:?}");
}

#[tokio::test]
async fn a_document_over_the_limit_is_a_violation_but_one_at_the_limit_is_judged() {
    let net = Net::new();
    for (len, too_large) in [(MAX_DOC_BYTES + 1, true), (MAX_DOC_BYTES, false)] {
        let receiver = Stores::empty();
        let (mut a, mut raw) = raw_pair();
        let p = params(&net);
        let writer = async {
            raw.write_all(&encode_frame(&Message::Push).unwrap())
                .await
                .unwrap();
            let doc = Message::Doc {
                kind: DocKind::Roster,
                doc: vec![0; len],
            };
            raw.write_all(&encode_frame(&doc).unwrap()).await.unwrap();
            let end = Message::End {
                roster_seq: None,
                policy_seq: None,
            };
            raw.write_all(&encode_frame(&end).unwrap()).await.unwrap();
        };
        let (_, served) = tokio::join!(
            writer,
            serve(
                &mut a,
                receiver.docs(&net),
                receiver.docs(&net),
                &p,
                ServeMode::Full
            ),
        );
        if too_large {
            assert!(matches!(
                served,
                Err(DocsStreamError::DocTooLarge { len: l, .. }) if l == len
            ));
        } else {
            // Junk of the largest allowed size is a bad document, answered; the stream is fine.
            let Ok(Served::Push(result)) = served else {
                panic!("{served:?}")
            };
            assert_eq!(result.code, Some(ErrorCode::BadDocument));
        }
    }
}

#[tokio::test]
async fn documents_out_of_order_or_repeated_are_a_violation() {
    let net = Net::new();
    let orders: Vec<Vec<DocKind>> = vec![
        vec![DocKind::Roster, DocKind::BaseRoster],
        vec![DocKind::Policy, DocKind::Roster],
        vec![DocKind::Roster, DocKind::Roster],
    ];
    for order in orders {
        let receiver = Stores::empty();
        let (mut a, mut raw) = raw_pair();
        let p = params(&net);
        let writer = async {
            raw.write_all(&encode_frame(&Message::Push).unwrap())
                .await
                .unwrap();
            for kind in order.iter().copied() {
                let doc = Message::Doc { kind, doc: vec![0] };
                raw.write_all(&encode_frame(&doc).unwrap()).await.unwrap();
            }
            drop(raw);
        };
        let (_, served) = tokio::join!(
            writer,
            serve(
                &mut a,
                receiver.docs(&net),
                receiver.docs(&net),
                &p,
                ServeMode::Full
            ),
        );
        assert!(
            matches!(served, Err(DocsStreamError::Unexpected(_))),
            "{order:?}: {served:?}"
        );
    }
}

#[tokio::test]
async fn messages_out_of_turn_are_a_violation() {
    let net = Net::new();
    let stores = Stores::empty();
    let end = Message::End {
        roster_seq: None,
        policy_seq: None,
    };
    // As a first message: end, doc, result.
    for first in [
        end.clone(),
        Message::Doc {
            kind: DocKind::Roster,
            doc: vec![],
        },
        Message::Result {
            roster: Outcome::Held,
            policy: Outcome::Held,
            code: None,
            roster_seq: None,
            policy_seq: None,
        },
    ] {
        let (mut a, mut raw) = raw_pair();
        raw.write_all(&encode_frame(&first).unwrap()).await.unwrap();
        let served = serve(
            &mut a,
            stores.docs(&net),
            stores.docs(&net),
            &params(&net),
            ServeMode::Full,
        )
        .await;
        assert!(
            matches!(served, Err(DocsStreamError::Unexpected(_))),
            "{first:?}"
        );
    }
    // A push followed by a message that is neither doc nor end.
    let (mut a, mut raw) = raw_pair();
    raw.write_all(&encode_frame(&Message::Push).unwrap())
        .await
        .unwrap();
    raw.write_all(&encode_frame(&Message::Push).unwrap())
        .await
        .unwrap();
    let served = serve(
        &mut a,
        stores.docs(&net),
        stores.docs(&net),
        &params(&net),
        ServeMode::Full,
    )
    .await;
    assert!(matches!(served, Err(DocsStreamError::Unexpected(_))));
    // The initiator of a push is answered with something that is not a result.
    let (mut a, mut raw) = raw_pair();
    raw.write_all(&encode_frame(&end).unwrap()).await.unwrap();
    let pushed = push(&mut a, &Bundle::default(), &params(&net)).await;
    assert!(matches!(pushed, Err(DocsStreamError::Unexpected(_))));
    // The initiator of a fetch is answered with a push.
    let (mut a, mut raw) = raw_pair();
    raw.write_all(&encode_frame(&Message::Push).unwrap())
        .await
        .unwrap();
    let fetched = fetch(&mut a, stores.docs(&net), &params(&net)).await;
    assert!(matches!(fetched, Err(DocsStreamError::Unexpected(_))));
}

/// The frame of a push whose map has one more entry, as raw bytes.
fn push_frame_with_extra(entry: &[u8]) -> Vec<u8> {
    let frame = encode_frame(&Message::Push).unwrap();
    let mut body = frame[4..].to_vec();
    assert_eq!(body[0], 0xa2, "a two entry map");
    body[0] = 0xa3;
    body.extend_from_slice(entry);
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out
}

#[tokio::test]
async fn strict_cbor_is_enforced_on_the_wire() {
    let net = Net::new();
    let stores = Stores::empty();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("unknown key", push_frame_with_extra(&[0x61, b'x', 0x01])),
        ("duplicate key", push_frame_with_extra(&[0x61, b'v', 0x01])),
        ("not cbor", {
            let mut f = 3u32.to_be_bytes().to_vec();
            f.extend_from_slice(&[0xff, 0xff, 0xff]);
            f
        }),
        ("empty body", 0u32.to_be_bytes().to_vec()),
    ];
    for (name, frame) in cases {
        let (mut a, mut raw) = raw_pair();
        raw.write_all(&frame).await.unwrap();
        let served = serve(
            &mut a,
            stores.docs(&net),
            stores.docs(&net),
            &params(&net),
            ServeMode::Full,
        )
        .await;
        assert!(
            matches!(served, Err(DocsStreamError::Frame(DocsError::Decode(_)))),
            "{name}: {served:?}"
        );
    }
}

#[tokio::test]
async fn a_stream_that_ends_early_is_an_io_error() {
    let net = Net::new();
    let stores = Stores::empty();
    let (mut a, mut raw) = raw_pair();
    let frame = encode_frame(&Message::Push).unwrap();
    raw.write_all(&frame[..frame.len() - 1]).await.unwrap();
    drop(raw);
    let served = serve(
        &mut a,
        stores.docs(&net),
        stores.docs(&net),
        &params(&net),
        ServeMode::Full,
    )
    .await;
    assert!(matches!(served, Err(DocsStreamError::Io(_))));
}

// ---------------------------------------------------------------- deadline

#[tokio::test(start_paused = true)]
async fn every_operation_is_cut_off_at_its_deadline() {
    let net = Net::new();
    let stores = Stores::empty();
    let p = DocsParams {
        deadline: Duration::from_secs(7),
        ..params(&net)
    };

    // The peer never answers or never speaks: the other end stays open and silent.
    let (mut a, _silent) = pair();
    let started = tokio::time::Instant::now();
    let pushed = push(&mut a, &Bundle::default(), &p).await;
    assert!(matches!(pushed, Err(DocsStreamError::Timeout)));
    assert_eq!(started.elapsed(), Duration::from_secs(7));

    let (mut a, _silent) = pair();
    let started = tokio::time::Instant::now();
    let fetched = fetch(&mut a, stores.docs(&net), &p).await;
    assert!(matches!(fetched, Err(DocsStreamError::Timeout)));
    assert_eq!(started.elapsed(), Duration::from_secs(7));

    let (mut a, _silent) = pair();
    let started = tokio::time::Instant::now();
    let served = serve(
        &mut a,
        stores.docs(&net),
        stores.docs(&net),
        &p,
        ServeMode::Full,
    )
    .await;
    assert!(matches!(served, Err(DocsStreamError::Timeout)));
    // The responder gives a silent opener less than the deadline (see the test below).
    assert_eq!(started.elapsed(), FIRST_MESSAGE_TIMEOUT);

    // The deadline covers the whole stream, not each read: a peer that sends the first message
    // and then stalls in the middle of a push is cut off at the deadline too.
    let (mut a, mut raw) = raw_pair();
    raw.write_all(&encode_frame(&Message::Push).unwrap())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let served = serve(
        &mut a,
        stores.docs(&net),
        stores.docs(&net),
        &p,
        ServeMode::Full,
    )
    .await;
    assert!(matches!(served, Err(DocsStreamError::Timeout)));
    assert_eq!(started.elapsed(), Duration::from_secs(7));
}

#[tokio::test(start_paused = true)]
async fn a_responder_gives_a_silent_opener_five_seconds_not_the_whole_deadline() {
    let net = Net::new();
    let stores = Stores::empty();
    let p = params(&net);
    assert!(FIRST_MESSAGE_TIMEOUT < p.deadline);
    for mode in [ServeMode::Full, ServeMode::PushOnly] {
        // Opened and never spoken to: the place it holds is back after five seconds.
        let (mut a, _silent) = pair();
        let started = tokio::time::Instant::now();
        let served = serve(&mut a, stores.docs(&net), stores.docs(&net), &p, mode).await;
        assert!(matches!(served, Err(DocsStreamError::Timeout)));
        assert_eq!(started.elapsed(), Duration::from_secs(5));
    }

    // The limit is for the first message only: an opener that has sent it (here, a `push`
    // and then nothing) keeps the rest of the deadline.
    let (mut a, mut raw) = raw_pair();
    raw.write_all(&encode_frame(&Message::Push).unwrap())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let served = serve(
        &mut a,
        stores.docs(&net),
        stores.docs(&net),
        &p,
        ServeMode::Full,
    )
    .await;
    assert!(matches!(served, Err(DocsStreamError::Timeout)));
    assert_eq!(started.elapsed(), p.deadline);
}

#[tokio::test(start_paused = true)]
async fn the_default_deadline_is_thirty_seconds() {
    let net = Net::new();
    let (mut a, _silent) = pair();
    let started = tokio::time::Instant::now();
    let pushed = push(&mut a, &Bundle::default(), &params(&net)).await;
    assert!(matches!(pushed, Err(DocsStreamError::Timeout)));
    assert_eq!(started.elapsed(), Duration::from_secs(30));
}

// ---------------------------------------------------------------- sinks

/// A sink that answers every adoption with the error it was given.
struct FailingSink {
    error: std::sync::Mutex<Option<NodeError>>,
    calls: AtomicUsize,
}

impl FailingSink {
    fn new(error: NodeError) -> Self {
        Self {
            error: std::sync::Mutex::new(Some(error)),
            calls: AtomicUsize::new(0),
        }
    }
}

impl DocsSink for FailingSink {
    fn adopt(&self, _bundle: &Bundle, _now: u64) -> Result<Adopted, NodeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(self.error.lock().unwrap().take().expect("called once"))
    }
    fn held(&self) -> HeldDocs {
        HeldDocs::default()
    }
}

async fn push_into_sink<K: DocsSink>(net: &Net, sink: &K) -> Result<Served, DocsStreamError> {
    let source = Stores::empty();
    let (mut a, mut raw) = raw_pair();
    // The push is written first (the buffer takes it whole), then served; a serve that fails
    // answers nothing, and the test does not wait for an answer.
    for message in push_messages(&net.base_bundle()) {
        raw.write_all(&encode_frame(&message).unwrap())
            .await
            .unwrap();
    }
    serve(
        &mut a,
        source.docs(net),
        sink,
        &params(net),
        ServeMode::Full,
    )
    .await
}

#[tokio::test]
async fn a_sink_verdict_is_answered_and_a_sink_failure_resets_the_stream() {
    let net = Net::new();

    let sink = FailingSink::new(NodeError::DocumentRejected(Reason::SeqOutOfSpan));
    let Ok(Served::Push(result)) = push_into_sink(&net, &sink).await else {
        panic!("a verdict is answered")
    };
    assert_eq!(result.code, Some(ErrorCode::BadDocument));
    assert_eq!(result.roster, Outcome::Rejected);

    let sink = FailingSink::new(NodeError::DocumentRejected(Reason::Expired));
    let Ok(Served::Push(result)) = push_into_sink(&net, &sink).await else {
        panic!()
    };
    assert_eq!(result.code, Some(ErrorCode::RosterExpired));

    let sink = FailingSink::new(NodeError::Proto(menzil_proto::ProtoError::Decode(
        "x".to_string(),
    )));
    let Ok(Served::Push(result)) = push_into_sink(&net, &sink).await else {
        panic!()
    };
    assert_eq!(result.code, Some(ErrorCode::BadDocument));

    let sink = FailingSink::new(NodeError::DocumentTooLarge { len: 5, max: 4 });
    assert!(matches!(
        push_into_sink(&net, &sink).await,
        Err(DocsStreamError::DocTooLarge { len: 5, max: 4 })
    ));

    let sink = FailingSink::new(NodeError::LinkDead);
    assert!(matches!(
        push_into_sink(&net, &sink).await,
        Err(DocsStreamError::Sink(NodeError::LinkDead))
    ));
}

#[tokio::test]
async fn a_push_with_nothing_to_adopt_does_not_reach_the_sink() {
    let net = Net::new();
    let sink = FailingSink::new(NodeError::LinkDead);
    let source = Stores::empty();
    let (mut a, mut b) = pair();
    let p = params(&net);
    let empty = Bundle::default();
    let (pushed, served) = tokio::join!(
        push(&mut a, &empty, &p),
        serve(&mut b, source.docs(&net), &sink, &p, ServeMode::Full),
    );
    assert!(pushed.is_ok() && served.is_ok());
    assert_eq!(sink.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_fetch_sink_failure_is_reported_as_such() {
    let net = Net::new();
    let server = Stores::with_base(&net);
    for (error, check) in [
        (
            NodeError::DocumentRejected(Reason::BadSignature),
            "rejected",
        ),
        (NodeError::DocumentTooLarge { len: 5, max: 4 }, "too large"),
        (NodeError::LinkDead, "sink"),
    ] {
        let sink = FailingSink::new(error);
        let (mut a, mut b) = pair();
        let p = params(&net);
        let (fetched, _) = tokio::join!(
            fetch(&mut a, &sink, &p),
            serve(
                &mut b,
                server.docs(&net),
                server.docs(&net),
                &p,
                ServeMode::Full
            ),
        );
        match (check, fetched) {
            ("rejected", Err(DocsStreamError::Rejected(Reason::BadSignature))) => {}
            ("too large", Err(DocsStreamError::DocTooLarge { len: 5, max: 4 })) => {}
            ("sink", Err(DocsStreamError::Sink(NodeError::LinkDead))) => {}
            (check, other) => panic!("{check}: {other:?}"),
        }
    }
}

/// Round 7 M1, first shape: a node holds the owner pair (seq 10), then the steward's Roster 11
/// arrives alone (the relay's L3 DOC). Its Policy is owner signed, so it announces no Policy
/// base; the server therefore sends the Policy's base and the Policy 11 is adopted.
#[tokio::test]
async fn a_policy_fetch_after_a_roster_first_steward_renewal_is_adopted() {
    let net = Net::new();
    let server = Stores::with_steward_pair(&net, 11);
    let client = Stores::with_base(&net);
    let renewal = net.renewal(&net.steward, 11);
    let roster_only = Bundle {
        base_roster: renewal.base_roster.clone(),
        roster: renewal.roster.clone(),
        ..Bundle::default()
    };
    client.docs(&net).adopt(&roster_only, NOW).unwrap();
    let held = client.docs(&net).held();
    assert_eq!(held.base_seq, Some(10));
    assert_eq!(held.policy_base_seq, None);
    let planned = plan_fetch(
        &server.docs(&net),
        held.roster_seq,
        held.policy_seq,
        held.base_seq,
        held.policy_base_seq,
        NOW,
    );
    assert_eq!(kinds(&planned), ["base_policy", "policy", "end"]);
    let (mut a, mut b) = pair();
    let p = params(&net);
    let (fetched, served) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    served.unwrap();
    assert!(fetched.unwrap().adopted.policy);
    assert_eq!(client.policies.seq(&net.network_id), Some(11));
}

/// Round 7 M1, second shape: the opener holds the steward pair 11 (base 10) and takes the Roster
/// of a newer base alone. The Policy it holds stands on base 10, not on the Roster's base, so
/// the server must send the new base Policy.
#[tokio::test]
async fn a_policy_fetch_after_a_roster_on_a_newer_base_is_adopted() {
    let net = Net::new();
    let b2 = 10 + menzil_proto::trust::STEWARD_SEQ_SPAN + 1;
    let mut r2 = net.roster.clone();
    let mut p2 = net.policy.clone();
    r2.seq = b2;
    p2.seq = b2;
    let base2 = Bundle {
        roster: Some(Roster::sign(&net.owner, &r2).unwrap()),
        policy: Some(Policy::sign(&net.owner, &p2).unwrap()),
        ..Bundle::default()
    };
    let mut r3 = r2.clone();
    let mut p3 = p2.clone();
    r3.seq = b2 + 1;
    p3.seq = b2 + 1;
    r3.issued = NOW;
    p3.issued = NOW;
    let renewal2 = Bundle {
        base_roster: base2.roster.clone(),
        base_policy: base2.policy.clone(),
        roster: Some(Roster::sign(&net.steward, &r3).unwrap()),
        policy: Some(Policy::sign(&net.steward, &p3).unwrap()),
    };
    let server = Stores::with_steward_pair(&net, 11);
    server.docs(&net).adopt(&renewal2, NOW).unwrap();
    let client = Stores::with_steward_pair(&net, 11);
    let roster_only = Bundle {
        base_roster: renewal2.base_roster.clone(),
        roster: renewal2.roster.clone(),
        ..Bundle::default()
    };
    client.docs(&net).adopt(&roster_only, NOW).unwrap();
    let held = client.docs(&net).held();
    assert_eq!(held.base_seq, Some(b2));
    assert_eq!(held.policy_base_seq, Some(10));
    let (mut a, mut b) = pair();
    let p = params(&net);
    let (fetched, served) = tokio::join!(
        fetch(&mut a, client.docs(&net), &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    served.unwrap();
    assert!(fetched.unwrap().adopted.policy);
    assert_eq!(client.policies.seq(&net.network_id), Some(b2 + 1));
}

/// The Policy's base is judged against `policy_base_seq`, the Roster's against `base_seq`.
#[test]
fn the_roster_and_policy_bases_are_announced_separately() {
    let net = Net::new();
    let stores = Stores::with_steward_pair(&net, 11);
    let docs = stores.docs(&net);
    let plan = plan_fetch(&docs, Some(10), Some(10), Some(10), None, NOW);
    assert_eq!(kinds(&plan), ["base_policy", "roster", "policy", "end"]);
    let plan = plan_fetch(&docs, Some(10), Some(10), None, Some(10), NOW);
    assert_eq!(kinds(&plan), ["base_roster", "roster", "policy", "end"]);
}

/// A sink whose Roster base announcement differs from its Policy base announcement.
struct SkewedSink<K: DocsSink>(K);

impl<K: DocsSink> DocsSink for SkewedSink<K> {
    fn adopt(&self, bundle: &Bundle, now: u64) -> Result<Adopted, NodeError> {
        self.0.adopt(bundle, now)
    }
    fn held(&self) -> HeldDocs {
        HeldDocs {
            base_seq: Some(9),
            ..self.0.held()
        }
    }
    fn held_bases(&self) -> HeldBases {
        self.0.held_bases()
    }
}

/// The Policy base left out of a fetch answer is put back by the Policy's own announcement, not
/// the Roster's.
#[tokio::test]
async fn a_left_out_policy_base_is_filled_by_the_policy_announcement() {
    let net = Net::new();
    let server = Stores::with_steward_pair(&net, 12);
    let client = Stores::with_steward_pair(&net, 11);
    let sink = SkewedSink(client.docs(&net));
    let (mut a, mut b) = pair();
    let p = params(&net);
    let (fetched, served) = tokio::join!(
        fetch(&mut a, &sink, &p),
        serve(
            &mut b,
            server.docs(&net),
            server.docs(&net),
            &p,
            ServeMode::Full
        ),
    );
    served.unwrap();
    assert!(fetched.unwrap().adopted.policy);
    assert_eq!(client.policies.seq(&net.network_id), Some(12));
}
