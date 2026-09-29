//! TLS to the relay (protocol.md 3.1 step 3): TLS 1.2 and 1.3, the
//! platform certificate verifier, ALPN `http/1.1`, never pinned. Nothing
//! above L1 trusts L1 for peer authenticity (protocol.md 1); that trust
//! is anchored later, at L3, by the relay's NodeCert.

use std::sync::{Arc, OnceLock};

use rustls_platform_verifier::ConfigVerifierExt as _;

use crate::error::CarrierError;

#[cfg(not(any(feature = "aws-lc-rs", feature = "ring")))]
compile_error!(
    "menzil-carrier requires either the \"aws-lc-rs\" (default) or \"ring\" feature to select a TLS crypto provider"
);

/// The rustls crypto provider this build selects (TOBEDECIDED.md item 3):
/// `aws-lc-rs` by default for the personal binary, `ring` for a consumer
/// built with `--no-default-features --features ring` (e.g. ng_sdwan,
/// which already standardizes on ring).
#[cfg(feature = "aws-lc-rs")]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

#[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
fn default_provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

static PROVIDER_INIT: OnceLock<()> = OnceLock::new();

/// Installs this crate's selected `CryptoProvider` as the process default,
/// if nothing has installed one yet. Idempotent and safe to call before
/// every dial; if some other user of rustls in this process already
/// installed a provider first, that one wins and this is a no-op.
pub fn ensure_crypto_provider() {
    PROVIDER_INIT.get_or_init(|| {
        let _ = default_provider().install_default();
    });
}

/// Builds the `rustls::ClientConfig` used for every dial: the platform
/// verifier (protocol.md 3.1 step 3: "the platform verifier plus the
/// system bundle on Linux"), no client certificate, and ALPN `http/1.1`.
/// TLS 1.2 and 1.3 are both offered because this crate's `rustls`
/// dependency is compiled with the `tls12` feature, which is what
/// `ClientConfig::builder()`'s default protocol version list actually
/// depends on (not anything set here).
pub fn client_config() -> Result<Arc<rustls::ClientConfig>, CarrierError> {
    ensure_crypto_provider();
    let mut config = rustls::ClientConfig::with_platform_verifier()
        .map_err(|e| CarrierError::TlsSetup(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::ProtocolVersion;

    #[test]
    fn config_offers_tls12_and_tls13_and_http11_alpn() {
        let config = client_config().unwrap();
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
