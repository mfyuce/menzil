//! TLS for the relay's own hostname (protocol.md 3.1 step 3, mirrored
//! server-side): TLS 1.2 and 1.3, ALPN `http/1.1`. Certificate and
//! private key material is supplied by the caller as already-loaded
//! `rustls` types; loading it from disk, and any future ACME automation,
//! are out of scope here (protocol.md 11).

use std::sync::{Arc, OnceLock};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::RelayError;

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!(
    "menzil-relay requires either the \"aws-lc-rs\" (default) or \"ring\" feature to select a TLS crypto provider"
);

/// The rustls crypto provider this build selects, mirroring
/// `menzil-carrier`'s own choice for TOBEDECIDED.md item 3: `aws-lc-rs`
/// by default, `ring` for a consumer built with `--no-default-features
/// --features ring`.
#[cfg(feature = "aws-lc-rs")]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

/// Installs this crate's selected `CryptoProvider` as the process
/// default, if nothing has installed one yet. Idempotent; if
/// `menzil-carrier` (or anything else in this process) already installed
/// one first, that one wins and this is a no-op — both crates default to
/// the same provider anyway, so in the ordinary case this changes
/// nothing either way.
pub fn ensure_crypto_provider() {
    PROVIDER_INIT.get_or_init(|| {
        let _ = default_provider().install_default();
    });
}

/// Builds the `rustls::ServerConfig` used to accept connections to the
/// relay's own hostname: the supplied certificate chain and private key,
/// no client certificate required, and ALPN `http/1.1`. TLS 1.2 and 1.3
/// are both offered because this crate's `rustls` dependency is compiled
/// with the `tls12` feature (the same workspace-level setting
/// `menzil-carrier`'s client-side config relies on), which is what
/// `ServerConfig::builder()`'s default protocol version list actually
/// depends on.
pub fn server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, RelayError> {
    ensure_crypto_provider();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| RelayError::TlsSetup(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::self_signed_cert;
    use rustls::ProtocolVersion;

    #[test]
    fn config_offers_tls12_and_tls13_and_http11_alpn() {
        let (chain, key) = self_signed_cert("relay.example");
        let config = server_config(chain, key).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let provider = config.crypto_provider();
        let has = |v: ProtocolVersion| {
            provider
                .cipher_suites
                .iter()
                .any(|cs| cs.version().version == v)
        };
        assert!(
            has(ProtocolVersion::TLSv1_2),
            "TLS 1.2 must be offered (protocol.md 3.1 step 3)"
        );
        assert!(has(ProtocolVersion::TLSv1_3), "TLS 1.3 must be offered");
    }
}
