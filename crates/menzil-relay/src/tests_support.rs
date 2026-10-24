//! Test-only helpers shared across this crate's test modules: a
//! self-signed certificate and a matching client-side TLS connector that
//! trusts exactly that certificate (not the platform verifier — there is
//! no real CA here, this is test-only trust).
//!
//! `#[cfg(test)]` on this module's declaration in `lib.rs` already gates
//! the whole thing out of non-test builds; nothing here repeats that.

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub(crate) fn self_signed_cert(
    subject_alt_name: &str,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed([subject_alt_name.to_string()]).unwrap();
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

pub(crate) fn test_tls_connector(cert: CertificateDer<'static>) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(std::sync::Arc::new(config))
}

pub(crate) async fn test_client(
    addr: std::net::SocketAddr,
    cert: CertificateDer<'static>,
    path: &str,
) -> WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await.unwrap();
    let connector = test_tls_connector(cert);
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let mut request = format!("wss://localhost{path}")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        "Sec-WebSocket-Protocol",
        menzil_carrier::SUBPROTOCOL.parse().unwrap(),
    );
    let (ws, _resp) = tokio_tungstenite::client_async(request, tls).await.unwrap();
    ws
}

/// A network with one steward, for the tests of steward signed Rosters (protocol.md 2.3): the
/// owner signed base Roster at `base_seq` lists `node 1` and the steward, and every Roster it
/// makes is valid at `now`.
pub(crate) struct StewardNet {
    pub(crate) owner: ed25519_dalek::SigningKey,
    pub(crate) steward: ed25519_dalek::SigningKey,
    pub(crate) network_id: menzil_proto::NetworkId,
    pub(crate) now: u64,
    pub(crate) base: menzil_proto::Roster,
    body: menzil_proto::RosterBody,
}

pub(crate) const DAY: u64 = 86_400;

/// The real clock in Unix seconds, for tests that go through a running session.
pub(crate) fn real_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

impl StewardNet {
    pub(crate) fn new(base_seq: u64, now: u64, member: menzil_proto::NodeId) -> Self {
        use menzil_proto::{
            NetworkId, PROTOCOL_VERSION, Roster, RosterBody, RosterMember, Steward, StewardBody,
            StewardKey,
        };
        let owner = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let steward = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let network_id = NetworkId::from(owner.verifying_key().to_bytes());
        let entry = Steward::sign(
            &owner,
            &StewardBody {
                v: PROTOCOL_VERSION,
                network_id,
                steward_pub: StewardKey::from(steward.verifying_key().to_bytes()),
                may: vec!["admit".to_string(), "renew".to_string()],
                not_after: now + 30 * DAY,
            },
        )
        .unwrap();
        let body = RosterBody {
            v: PROTOCOL_VERSION,
            network_id,
            seq: base_seq,
            issued: now - DAY,
            expires: now + 5 * DAY,
            members: vec![RosterMember {
                node_id: member,
                min_serial: 1,
            }],
            revoked: vec![],
            stewards: vec![entry],
            labels: vec![],
        };
        let base = Roster::sign(&owner, &body).unwrap();
        Self {
            owner,
            steward,
            network_id,
            now,
            base,
            body,
        }
    }

    /// The same network with `member` also listed, in the base and in everything made from it.
    pub(crate) fn with_member(mut self, member: menzil_proto::NodeId) -> Self {
        self.body.members.push(menzil_proto::RosterMember {
            node_id: member,
            min_serial: 1,
        });
        self.base = menzil_proto::Roster::sign(&self.owner, &self.body).unwrap();
        self
    }

    /// The same network and steward with an older (or newer) owner signed base at `base_seq`.
    pub(crate) fn rebase(&self, base_seq: u64) -> Self {
        let mut body = self.body.clone();
        body.seq = base_seq;
        Self {
            owner: self.owner.clone(),
            steward: self.steward.clone(),
            network_id: self.network_id,
            now: self.now,
            base: menzil_proto::Roster::sign(&self.owner, &body).unwrap(),
            body,
        }
    }

    /// A renewal of the base at `seq`, signed by `signer`.
    pub(crate) fn renewal(
        &self,
        signer: &ed25519_dalek::SigningKey,
        seq: u64,
    ) -> menzil_proto::Roster {
        let mut body = self.body.clone();
        body.seq = seq;
        body.issued = self.now;
        body.expires = self.now + 7 * DAY;
        menzil_proto::Roster::sign(signer, &body).unwrap()
    }
}
