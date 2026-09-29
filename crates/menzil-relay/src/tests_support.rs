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
