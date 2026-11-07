//! An in process CA, a TLS client as a CA validator sees the responder, and a few helpers, for the
//! tests of this crate and (feature `testing`) of crates that run the client against a fake CA.
//! Not for production use.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use ring_crate::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{Value, json};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::FromDer as _;

use crate::client::{AccountKey, AcmeClient, Timing};
use crate::http::{AcmeTransport, HttpRequest, HttpResponse};
use crate::*;

pub const WAIT: Duration = Duration::from_secs(10);
pub const DOMAIN: &str = "app.relay.example";

pub fn sha256(data: &[u8]) -> Vec<u8> {
    ring_crate::digest::digest(&ring_crate::digest::SHA256, data)
        .as_ref()
        .to_vec()
}

pub fn b64(data: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

// ---- the client side of a validation: what a CA sees ----

#[derive(Debug)]
pub struct AcceptAny;

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn client_config(alpn: &[&str]) -> Arc<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Arc::new(config)
}

/// What a validation connection learned: the leaf certificate and the ALPN the server chose.
pub struct Seen {
    pub leaf: Vec<u8>,
    pub alpn: Option<Vec<u8>>,
}

/// Connects as a CA would (SNI `sni`, ALPN `alpn`) to [`answer_or_pass`] over an in memory pipe.
pub async fn validate(book: &ChallengeBook, sni: &str, alpn: &[&str]) -> (Served, Option<Seen>) {
    let (mut server_io, client_io) = tokio::io::duplex(64 * 1024);
    let server = {
        let (book, sni) = (book.clone(), sni.to_string());
        tokio::spawn(async move { answer_or_pass(&mut server_io, &sni, &book).await })
    };
    let connector = TlsConnector::from(client_config(alpn));
    let name = ServerName::try_from(sni.to_string()).unwrap();
    let (seen, _tls) = match tokio::time::timeout(WAIT, connector.connect(name, client_io)).await {
        Ok(Ok(tls)) => {
            let (_, conn) = tls.get_ref();
            let seen = Seen {
                leaf: conn.peer_certificates().unwrap()[0].as_ref().to_vec(),
                alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
            };
            // Kept until the server is done, as a CA that reads to the end would.
            (Some(seen), Some(tls))
        }
        _ => (None, None),
    };
    let served = tokio::time::timeout(WAIT, server).await.unwrap().unwrap();
    (served, seen)
}

pub fn issue_leaf(domain: &str, public: &[u8]) -> String {
    use rcgen::{BasicConstraints, CertifiedIssuer, IsCa};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(
        ca_params,
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap(),
    )
    .unwrap();
    let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2090, 1, 1);
    let leaf = params
        .signed_by(&RawPublicKey(public.to_vec()), &ca)
        .unwrap();
    format!(
        "{}{}",
        leaf.pem(),
        AsRef::<rcgen::Certificate>::as_ref(&ca).pem()
    )
}

pub struct RawPublicKey(Vec<u8>);

impl rcgen::PublicKeyData for RawPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

// ---- the client against an in process CA ----

#[derive(Default, Clone)]
pub struct Flags {
    /// Answer the first POST to newOrder with badNonce.
    pub bad_nonce_once: bool,
    /// Answer every POST with badNonce.
    pub bad_nonce_always: bool,
    /// Authorization polls that say `pending` after the validation.
    pub pending_polls: usize,
    /// The authorization is for a wildcard.
    pub wildcard: bool,
    /// The authorization is for another name.
    pub other_identifier: bool,
    /// The order lists another name.
    pub order_other_identifier: bool,
    /// No tls-alpn-01 challenge is offered.
    pub no_alpn_challenge: bool,
    /// The token is not base64url.
    pub bad_token: bool,
    /// The CA's validation fails.
    pub validation_fails: bool,
    /// The CA never validates (the authorization stays pending).
    pub never_validates: bool,
    /// The leaf names another domain.
    pub cert_for_other_domain: bool,
    /// The leaf carries another key than the request's.
    pub cert_with_other_key: bool,
    /// Finalize answers `processing`.
    pub finalize_processing: bool,
    /// newAccount is refused.
    pub refuse_account: bool,
}

#[derive(Default)]
pub struct CaState {
    pub nonce_counter: u64,
    pub live_nonces: HashSet<String>,
    pub jwk: Option<Value>,
    pub validated: Option<bool>,
    pub polls_after_validation: usize,
    pub finalized: bool,
    pub domain: String,
    pub log: Vec<String>,
    pub bad_nonce_answers: usize,
    pub challenge_posts: usize,
    pub pending_at_challenge: Option<bool>,
    pub digest_seen: Option<Vec<u8>>,
    pub expected_digest: Option<Vec<u8>>,
    pub order_posts: usize,
    pub accept_header_ok: bool,
    pub chain: Option<String>,
}

pub struct FakeCa {
    pub book: ChallengeBook,
    pub flags: Flags,
    pub state: Mutex<CaState>,
}

pub const CA: &str = "https://ca.test";
pub const TOKEN: &str = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";

impl FakeCa {
    pub fn new(book: &ChallengeBook, flags: Flags) -> Arc<Self> {
        Arc::new(Self {
            book: book.clone(),
            flags,
            state: Mutex::new(CaState::default()),
        })
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, CaState> {
        self.state.lock().unwrap()
    }

    pub fn reply(
        &self,
        status: u16,
        extra: &[(&str, String)],
        body: Option<Value>,
    ) -> HttpResponse {
        let mut state = self.state();
        state.nonce_counter += 1;
        let nonce = format!("nonce-{}", state.nonce_counter);
        state.live_nonces.insert(nonce.clone());
        let mut headers = vec![("replay-nonce".to_string(), nonce)];
        headers.extend(extra.iter().map(|(n, v)| (n.to_string(), v.clone())));
        HttpResponse {
            status,
            headers,
            body: body.map(|b| b.to_string().into_bytes()).unwrap_or_default(),
        }
    }

    pub fn problem(&self, status: u16, kind: &str, detail: &str) -> HttpResponse {
        self.reply(
            status,
            &[],
            Some(json!({"type": format!("urn:ietf:params:acme:error:{kind}"), "detail": detail})),
        )
    }

    /// Verifies the JWS of `request` the way a CA must; returns the payload (`None` for
    /// POST-as-GET) or the answer to give.
    pub fn check_jws(&self, request: &HttpRequest) -> Result<Option<Value>, HttpResponse> {
        if self.flags.bad_nonce_always {
            self.state().bad_nonce_answers += 1;
            return Err(self.problem(400, "badNonce", "no"));
        }
        let content_type = request
            .headers
            .iter()
            .find(|(n, _)| *n == "Content-Type")
            .map(|(_, v)| v.as_str());
        assert_eq!(content_type, Some("application/jose+json"));
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let protected_text = body["protected"].as_str().unwrap();
        let payload_text = body["payload"].as_str().unwrap();
        let protected: Value = serde_json::from_slice(&unb64(protected_text)).unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["url"], request.url.as_str(), "the url is signed");
        let nonce = protected["nonce"].as_str().unwrap().to_string();
        let first_order_post = request.url.ends_with("/order") && {
            let mut state = self.state();
            state.order_posts += 1;
            state.order_posts == 1
        };
        if first_order_post && self.flags.bad_nonce_once {
            self.state().bad_nonce_answers += 1;
            // The nonce is spent either way.
            self.state().live_nonces.remove(&nonce);
            return Err(self.problem(400, "badNonce", "try again"));
        }
        if !self.state().live_nonces.remove(&nonce) {
            self.state().bad_nonce_answers += 1;
            return Err(self.problem(400, "badNonce", "a nonce that was not issued or was used"));
        }
        let jwk = match (protected.get("jwk"), protected.get("kid")) {
            (Some(jwk), None) => {
                assert!(request.url.ends_with("/acct"), "jwk only for newAccount");
                self.state().jwk = Some(jwk.clone());
                jwk.clone()
            }
            (None, Some(kid)) => {
                assert_eq!(kid, &format!("{CA}/acct/1"));
                self.state().jwk.clone().expect("an account")
            }
            _ => panic!("exactly one of jwk and kid"),
        };
        let mut point = vec![4u8];
        point.extend(unb64(jwk["x"].as_str().unwrap()));
        point.extend(unb64(jwk["y"].as_str().unwrap()));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(
                format!("{protected_text}.{payload_text}").as_bytes(),
                &unb64(body["signature"].as_str().unwrap()),
            )
            .expect("the JWS signature verifies");
        Ok((!payload_text.is_empty())
            .then(|| serde_json::from_slice(&unb64(payload_text)).unwrap()))
    }

    pub fn thumbprint(&self) -> String {
        let jwk = self.state().jwk.clone().unwrap();
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap()
        );
        b64(sha256(canonical.as_bytes()))
    }

    pub fn authz_body(&self, status: &str) -> Value {
        let domain = self.state().domain.clone();
        let value = if self.flags.other_identifier {
            "other.relay.example".to_string()
        } else {
            domain
        };
        let token = if self.flags.bad_token {
            "../evil token"
        } else {
            TOKEN
        };
        let mut challenges =
            vec![json!({"type": "dns-01", "url": format!("{CA}/chal/0"), "token": TOKEN})];
        if !self.flags.no_alpn_challenge {
            challenges.push(json!({"type": "tls-alpn-01", "url": format!("{CA}/chal/1"), "token": token, "status": status}));
        }
        let mut body = json!({
            "status": status,
            "identifier": {"type": "dns", "value": value},
            "challenges": challenges,
        });
        if status == "invalid" {
            let last = challenges_len(&body) - 1;
            body["challenges"][last]["error"] =
                json!({"detail": "the validation connection failed"});
        }
        if self.flags.wildcard {
            body["wildcard"] = json!(true);
        }
        body
    }

    pub async fn run_validation(&self) {
        let domain = self.state().domain.clone();
        let pending = self.book.is_pending(&domain);
        self.state().pending_at_challenge = Some(pending);
        let key_authorization = format!("{TOKEN}.{}", self.thumbprint());
        let expected = sha256(key_authorization.as_bytes());
        self.state().expected_digest = Some(expected.clone());
        if self.flags.never_validates {
            return;
        }
        if self.flags.validation_fails {
            self.state().validated = Some(false);
            return;
        }
        let (served, seen) = validate(&self.book, &domain, &["acme-tls/1"]).await;
        let digest = seen
            .filter(|_| served == Served::Answered)
            .and_then(|seen| acme_identifier(&seen.leaf))
            .map(|(_, value)| value[2..].to_vec());
        let mut state = self.state();
        state.validated = Some(digest.as_deref() == Some(expected.as_slice()));
        state.digest_seen = digest;
    }

    pub fn issue(&self, csr_b64: &str) -> Result<String, HttpResponse> {
        let der = unb64(csr_b64);
        let (_, csr) = x509_parser::certification_request::X509CertificationRequest::from_der(&der)
            .map_err(|_| self.problem(400, "badCSR", "does not parse"))?;
        let domain = self.state().domain.clone();
        let names: Vec<String> = csr
            .requested_extensions()
            .into_iter()
            .flatten()
            .filter_map(|ext| match ext {
                x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) => Some(
                    san.general_names
                        .iter()
                        .filter_map(|n| match n {
                            x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .flatten()
            .collect();
        if names != vec![domain.clone()] {
            return Err(self.problem(400, "badCSR", "the CSR names other identifiers"));
        }
        let mut point = csr
            .certification_request_info
            .subject_pki
            .subject_public_key
            .data
            .to_vec();
        if self.flags.cert_with_other_key {
            point = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                .unwrap()
                .public_key_raw()
                .to_vec();
        }
        let named = if self.flags.cert_for_other_domain {
            "someone-else.example".to_string()
        } else {
            domain
        };
        Ok(issue_leaf(&named, &point))
    }

    pub async fn handle(&self, request: HttpRequest) -> HttpResponse {
        let route = request.url.strip_prefix(CA).unwrap_or("?").to_string();
        self.state()
            .log
            .push(format!("{:?} {route}", request.method));
        match (request.method, route.as_str()) {
            (Method::Get, "/dir") => {
                return self.reply(
                    200,
                    &[],
                    Some(json!({
                        "newNonce": format!("{CA}/nonce"),
                        "newAccount": format!("{CA}/acct"),
                        "newOrder": format!("{CA}/order"),
                    })),
                );
            }
            (Method::Head, "/nonce") => return self.reply(200, &[], None),
            (Method::Post, _) => {}
            other => panic!("unexpected request {other:?}"),
        }
        let payload = match self.check_jws(&request) {
            Ok(payload) => payload,
            Err(answer) => return answer,
        };
        match route.as_str() {
            "/acct" => {
                if self.flags.refuse_account {
                    return self.problem(403, "unauthorized", "no accounts today");
                }
                assert_eq!(payload.unwrap()["termsOfServiceAgreed"], true);
                self.reply(
                    201,
                    &[("location", format!("{CA}/acct/1"))],
                    Some(json!({"status": "valid"})),
                )
            }
            "/order" => {
                let payload = payload.unwrap();
                let identifiers = payload["identifiers"].as_array().unwrap();
                assert_eq!(identifiers.len(), 1);
                assert_eq!(identifiers[0]["type"], "dns");
                self.state().domain = identifiers[0]["value"].as_str().unwrap().to_string();
                let listed = if self.flags.order_other_identifier {
                    "other.relay.example".to_string()
                } else {
                    self.state().domain.clone()
                };
                self.reply(
                    201,
                    &[("location", format!("{CA}/order/1"))],
                    Some(json!({
                        "status": "pending",
                        "identifiers": [{"type": "dns", "value": listed}],
                        "authorizations": [format!("{CA}/authz/1")],
                        "finalize": format!("{CA}/finalize/1"),
                    })),
                )
            }
            "/authz/1" => {
                assert!(payload.is_none(), "POST-as-GET");
                let (validated, polls) = {
                    let mut state = self.state();
                    if state.validated.is_some() {
                        state.polls_after_validation += 1;
                    }
                    (state.validated, state.polls_after_validation)
                };
                let status = match validated {
                    None => "pending",
                    Some(_) if polls <= self.flags.pending_polls => "pending",
                    Some(true) => "valid",
                    Some(false) => "invalid",
                };
                self.reply(200, &[], Some(self.authz_body(status)))
            }
            "/chal/1" => {
                assert_eq!(payload.unwrap(), json!({}));
                self.state().challenge_posts += 1;
                self.run_validation().await;
                self.reply(200, &[], Some(json!({"status": "processing", "type": "tls-alpn-01", "url": format!("{CA}/chal/1"), "token": TOKEN})))
            }
            "/order/1" => {
                assert!(payload.is_none());
                let (validated, finalized) = {
                    let state = self.state();
                    (state.validated, state.finalized)
                };
                let status = if finalized {
                    "valid"
                } else if validated == Some(true) {
                    "ready"
                } else {
                    "pending"
                };
                self.reply(200, &[], Some(self.order_body(status)))
            }
            "/finalize/1" => {
                let payload = payload.unwrap();
                match self.issue(payload["csr"].as_str().unwrap()) {
                    Ok(chain) => {
                        let mut state = self.state();
                        state.chain = Some(chain);
                        state.finalized = true;
                        drop(state);
                        let status = if self.flags.finalize_processing {
                            "processing"
                        } else {
                            "valid"
                        };
                        self.reply(200, &[], Some(self.order_body(status)))
                    }
                    Err(answer) => answer,
                }
            }
            "/cert/1" => {
                assert!(payload.is_none());
                let accepts = request
                    .headers
                    .iter()
                    .any(|(n, v)| *n == "Accept" && v == "application/pem-certificate-chain");
                self.state().accept_header_ok = accepts;
                let chain = self.state().chain.clone().unwrap();
                let mut response = self.reply(
                    200,
                    &[(
                        "content-type",
                        "application/pem-certificate-chain".to_string(),
                    )],
                    None,
                );
                response.body = chain.into_bytes();
                response
            }
            other => panic!("unexpected route {other}"),
        }
    }

    pub fn order_body(&self, status: &str) -> Value {
        let mut body = json!({
            "status": status,
            "identifiers": [{"type": "dns", "value": self.state().domain.clone()}],
            "authorizations": [format!("{CA}/authz/1")],
            "finalize": format!("{CA}/finalize/1"),
        });
        if status == "valid" {
            body["certificate"] = json!(format!("{CA}/cert/1"));
        }
        body
    }
}

pub fn challenges_len(body: &Value) -> usize {
    body["challenges"].as_array().unwrap().len()
}

impl AcmeTransport for Arc<FakeCa> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, AcmeError> {
        Ok(self.handle(request).await)
    }
}

pub fn fast() -> Timing {
    Timing {
        poll_interval: Duration::from_millis(1),
        poll_max_interval: Duration::from_millis(5),
        poll_deadline: Duration::from_secs(5),
    }
}

pub fn client_for(ca: &Arc<FakeCa>) -> AcmeClient<Arc<FakeCa>> {
    AcmeClient::new(
        ca.clone(),
        format!("{CA}/dir"),
        AccountKey::generate().unwrap(),
        Some("mailto:ops@example.org".to_string()),
    )
    .with_timing(fast())
}

/// The `id-pe-acmeIdentifier` extension of `der`: whether it is critical and its value.
pub fn acme_identifier(der: &[u8]) -> Option<(bool, Vec<u8>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    cert.extensions()
        .iter()
        .find(|ext| ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
        .map(|ext| (ext.critical, ext.value.to_vec()))
}

pub fn dns_names(der: &[u8]) -> Vec<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
    cert.subject_alternative_name()
        .unwrap()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    x509_parser::extensions::GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}
