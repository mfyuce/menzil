//! The security of the listener: who is let in, and that nobody gets to a handler without a
//! client certificate of the one CA, over TLS 1.3.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use common::{Fixture, connect, connect_with, files_of};
use menzil_relay_admin::certs::generate;
use menzil_relay_admin::pb::tenant_admin_client::TenantAdminClient;
use menzil_relay_admin::pb::*;
use menzil_relay_admin::server_config;
use tonic::transport::Endpoint;

const GOOD: &str = "a good client is served";

/// A request that would make a tenant file if it reached its handler.
async fn try_create(
    c: &mut TenantAdminClient<tonic::transport::Channel>,
) -> Result<(), tonic::Status> {
    let owner = common::Owner::new();
    c.create_tenant(CreateTenantRequest {
        slug: "intruder".into(),
        tokens: vec![owner.token()],
        class: String::new(),
        idempotency_key: String::new(),
    })
    .await
    .map(|_| ())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_with_the_right_certificate_is_served() {
    let fx = Fixture::start().await;
    let mut c = fx.client().await;
    try_create(&mut c).await.expect(GOOD);
    assert!(fx.tenant_file("intruder").exists());
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_certificate_from_another_ca_never_reaches_a_handler() {
    let fx = Fixture::start().await;
    let other = generate(&fx._dir.path().join("other-ca"), "localhost", "menzil-ui").unwrap();
    // It trusts the server's CA (so the server is accepted) but presents a certificate of its own CA.
    let mut c = match connect(
        fx.addr,
        &fx.certs.ca_cert,
        Some((&other.client_cert, &other.client_key)),
    )
    .await
    {
        Ok(c) => c,
        Err(_) => {
            assert!(!fx.tenant_file("intruder").exists());
            fx.shutdown().await;
            return;
        }
    };
    assert!(
        try_create(&mut c).await.is_err(),
        "a certificate of another CA must be refused"
    );
    assert!(c.get_figures(GetFiguresRequest {}).await.is_err());
    assert!(!fx.tenant_file("intruder").exists(), "the handler ran");
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_without_a_certificate_is_refused() {
    let fx = Fixture::start().await;
    let mut c = match connect(fx.addr, &fx.certs.ca_cert, None).await {
        Ok(c) => c,
        Err(_) => {
            assert!(!fx.tenant_file("intruder").exists());
            fx.shutdown().await;
            return;
        }
    };
    assert!(try_create(&mut c).await.is_err());
    assert!(c.get_figures(GetFiguresRequest {}).await.is_err());
    assert!(!fx.tenant_file("intruder").exists());
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plaintext_connection_is_refused() {
    let fx = Fixture::start().await;
    let url = format!("http://{}", fx.addr);
    let channel = Endpoint::from_shared(url)
        .unwrap()
        .connect_timeout(std::time::Duration::from_secs(5))
        .connect()
        .await;
    if let Ok(channel) = channel {
        let mut c = TenantAdminClient::new(channel);
        assert!(try_create(&mut c).await.is_err());
        assert!(c.get_figures(GetFiguresRequest {}).await.is_err());
    }
    assert!(!fx.tenant_file("intruder").exists());
    // The agent still serves a good client afterwards.
    let mut good = fx.client().await;
    good.get_figures(GetFiguresRequest {}).await.expect(GOOD);
    fx.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tls_1_2_is_refused() {
    let fx = Fixture::start().await;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // The same identity and trust, but a client that offers TLS 1.2 only.
    let mut roots = rustls::RootCertStore::empty();
    let base = {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        for cert in CertificateDer::pem_file_iter(&fx.certs.ca_cert).unwrap() {
            roots.add(cert.unwrap()).unwrap();
        }
        let chain = CertificateDer::pem_file_iter(&fx.certs.client_cert)
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let mut base = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                chain,
                PrivateKeyDer::from_pem_file(&fx.certs.client_key).unwrap(),
            )
            .unwrap();
        base.alpn_protocols = vec![b"h2".to_vec()];
        base
    };
    let tls12 = connect_with(fx.addr, base).await;
    if let Ok(mut c) = tls12 {
        assert!(
            try_create(&mut c).await.is_err(),
            "TLS 1.2 must not be served"
        );
    }
    assert!(!fx.tenant_file("intruder").exists());
    fx.shutdown().await;
}

#[test]
fn a_key_file_that_others_can_read_stops_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let g = generate(dir.path(), "localhost", "c").unwrap();
    let files = files_of(&g);
    assert!(server_config(&files).is_ok(), "mode 0600 is fine");
    for mode in [0o640, 0o604, 0o660, 0o644, 0o666, 0o620] {
        std::fs::set_permissions(&g.server_key, std::fs::Permissions::from_mode(mode)).unwrap();
        let e = server_config(&files).unwrap_err().to_string();
        assert!(e.contains("chmod 600"), "{mode:o}: {e}");
    }
    for mode in [0o400, 0o600] {
        std::fs::set_permissions(&g.server_key, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(server_config(&files).is_ok(), "{mode:o}");
    }
    // A missing key is an error too.
    std::fs::remove_file(&g.server_key).unwrap();
    assert!(server_config(&files).is_err());
}

#[test]
fn the_server_needs_a_ca_and_a_certificate_in_its_files() {
    let dir = tempfile::tempdir().unwrap();
    let g = generate(dir.path(), "localhost", "c").unwrap();
    let mut files = files_of(&g);
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    files.client_ca = empty.clone();
    assert!(server_config(&files).is_err());
    let mut files = files_of(&g);
    files.cert = empty;
    assert!(server_config(&files).is_err());
}
