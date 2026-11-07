//! A small RFC 8555 client: one ES256 account key, one DNS identifier per order, the
//! `tls-alpn-01` challenge only (RFC 8737). It is the node's own affair; the CA is whatever
//! directory URL the caller names.
//!
//! The state machine, in the order [`AcmeClient::obtain`] runs it: directory, account
//! (`newAccount`, once), `newOrder`, per authorization: read it (POST-as-GET), make the name
//! pending in the [`ChallengeBook`] **before** telling the CA to validate, poll the
//! authorization, drop the pending entry; poll the order to `ready`, finalize with a CSR for a
//! fresh key, poll to `valid`, download the chain, and check what came back (the leaf names the
//! domain and carries the key of the CSR) before returning it.
//!
//! Everything the CA sends is data: identifiers must be the one asked for, a wildcard
//! authorization is refused, a challenge token must be base64url, and every wait is bounded.

use std::path::Path;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rcgen::{CertificateParams, DistinguishedName, KeyPair, PKCS_ECDSA_P256_SHA256, SigningKey};
use serde_json::{Value, json};

use super::http::{AcmeTransport, HttpRequest, HttpResponse, Method};
use super::{AcmeError, ChallengeBook, PENDING_TTL, check_domain};

/// The challenge type this client answers.
const CHALLENGE_TYPE: &str = "tls-alpn-01";

/// How many `badNonce` answers one request retries through.
const NONCE_RETRIES: usize = 3;

/// The longest a challenge token may be (RFC 8555 asks for 128 bits of entropy; this is slack).
const MAX_TOKEN_BYTES: usize = 256;

/// The most authorizations one order may list.
const MAX_AUTHORIZATIONS: usize = 4;

/// How the client waits.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Between two polls when the CA gives no `Retry-After`.
    pub poll_interval: Duration,
    /// The longest `Retry-After` honored.
    pub poll_max_interval: Duration,
    /// How long an authorization or an order is polled in all.
    pub poll_deadline: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            poll_max_interval: Duration::from_secs(30),
            // Inside the pending window: past it the challenge is no longer answered.
            poll_deadline: PENDING_TTL.saturating_sub(Duration::from_secs(10)),
        }
    }
}

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The ACME account key: ECDSA P-256, kept as a PKCS#8 PEM file readable by the owner only.
pub struct AccountKey {
    pair: KeyPair,
}

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountKey(..)")
    }
}

impl AccountKey {
    /// A new key.
    pub fn generate() -> Result<Self, AcmeError> {
        let pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::Cert(e.to_string()))?;
        Ok(Self { pair })
    }

    /// The key of a PKCS#8 PEM.
    pub fn from_pem(pem: &str) -> Result<Self, AcmeError> {
        let pair = KeyPair::from_pem_and_sign_algo(pem, &PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::Cert(format!("the account key: {e}")))?;
        Ok(Self { pair })
    }

    /// The key as a PKCS#8 PEM.
    pub fn to_pem(&self) -> String {
        self.pair.serialize_pem()
    }

    /// Reads the key at `path`, or makes one and writes it there (mode 0600, atomically). A
    /// file that anyone but the owner can read is refused, and so is one that is not a key:
    /// neither is replaced.
    pub fn load_or_create(path: &Path) -> Result<Self, AcmeError> {
        let store =
            |e: &dyn std::fmt::Display| AcmeError::Store(format!("{}: {e}", path.display()));
        match std::fs::read_to_string(path) {
            Ok(pem) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    let mode = std::fs::metadata(path)
                        .map_err(|e| store(&e))?
                        .permissions()
                        .mode();
                    if mode & 0o077 != 0 {
                        return Err(AcmeError::Store(format!(
                            "{}: the account key is readable by others (mode {:o}); chmod 600 it",
                            path.display(),
                            mode & 0o777
                        )));
                    }
                }
                Self::from_pem(&pem)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                super::renew::write_private(path, key.to_pem().as_bytes())?;
                Ok(key)
            }
            Err(e) => Err(store(&e)),
        }
    }

    /// The public key as the two coordinates of a JWK.
    pub(crate) fn coordinates(&self) -> Result<(String, String), AcmeError> {
        let point = self.pair.public_key_raw();
        if point.len() != 65 || point[0] != 4 {
            return Err(AcmeError::Cert(
                "the account key is not a P-256 point".to_string(),
            ));
        }
        Ok((b64(&point[1..33]), b64(&point[33..65])))
    }

    fn jwk(&self) -> Result<Value, AcmeError> {
        let (x, y) = self.coordinates()?;
        Ok(json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
    }

    /// The JWK thumbprint (RFC 7638): base64url of the SHA-256 of the members in lexicographic
    /// order, no whitespace.
    pub fn thumbprint(&self) -> Result<String, AcmeError> {
        let (x, y) = self.coordinates()?;
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        Ok(b64(super::key_authorization_digest(&canonical)))
    }

    /// An ES256 signature (the 64 bytes r and s, RFC 7515 appendix A.3) of `message`.
    pub(crate) fn sign(&self, message: &[u8]) -> Result<[u8; 64], AcmeError> {
        let der =
            SigningKey::sign(&self.pair, message).map_err(|e| AcmeError::Cert(e.to_string()))?;
        der_to_raw_p256(&der)
            .ok_or_else(|| AcmeError::Cert("the signature is not an ECDSA signature".to_string()))
    }
}

/// An ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }` as the 64 bytes `r || s`.
pub(crate) fn der_to_raw_p256(der: &[u8]) -> Option<[u8; 64]> {
    fn length(bytes: &[u8]) -> Option<(usize, &[u8])> {
        let (&first, rest) = bytes.split_first()?;
        if first < 0x80 {
            Some((usize::from(first), rest))
        } else if first == 0x81 {
            let (&n, rest) = rest.split_first()?;
            Some((usize::from(n), rest))
        } else {
            None
        }
    }
    fn integer(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
        let (&tag, rest) = bytes.split_first()?;
        if tag != 0x02 {
            return None;
        }
        let (len, rest) = length(rest)?;
        if len == 0 || rest.len() < len {
            return None;
        }
        Some((&rest[..len], &rest[len..]))
    }
    let (&tag, rest) = der.split_first()?;
    if tag != 0x30 {
        return None;
    }
    let (len, rest) = length(rest)?;
    if rest.len() != len {
        return None;
    }
    let (r, rest) = integer(rest)?;
    let (s, rest) = integer(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; 64];
    let (r_slot, s_slot) = out.split_at_mut(32);
    for (value, slot) in [(r, r_slot), (s, s_slot)] {
        let trimmed = match value.iter().position(|&b| b != 0) {
            Some(start) => &value[start..],
            None => &value[value.len() - 1..],
        };
        if trimmed.len() > 32 {
            return None;
        }
        slot[32 - trimmed.len()..].copy_from_slice(trimmed);
    }
    Some(out)
}

/// What [`AcmeClient::obtain`] returns.
#[derive(Clone)]
pub struct Issued {
    /// The certificate chain, leaf first, PEM.
    pub chain_pem: String,
    /// The private key of the leaf, PKCS#8 PEM.
    pub key_pem: String,
    /// The leaf's `notBefore`, Unix seconds.
    pub not_before: u64,
    /// The leaf's `notAfter`, Unix seconds.
    pub not_after: u64,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

/// The client. One per CA and account; not shared between tasks (`obtain` takes `&mut self`:
/// the nonce and the account URL are its state).
pub struct AcmeClient<T> {
    transport: T,
    directory_url: String,
    key: AccountKey,
    contact: Option<String>,
    timing: Timing,
    directory: Option<Directory>,
    nonce: Option<String>,
    kid: Option<String>,
}

fn problem(response: &HttpResponse) -> AcmeError {
    let doc: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    let text = |key: &str| {
        doc.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(300)
            .collect::<String>()
    };
    AcmeError::Problem {
        status: response.status,
        kind: text("type"),
        detail: text("detail"),
    }
}

fn json_body(response: &HttpResponse) -> Result<Value, AcmeError> {
    serde_json::from_slice(&response.body)
        .map_err(|e| AcmeError::Protocol(format!("a body that is not JSON: {e}")))
}

fn str_field<'a>(doc: &'a Value, key: &str) -> Result<&'a str, AcmeError> {
    doc.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| AcmeError::Protocol(format!("no `{key}` in the answer")))
}

impl<T: AcmeTransport> AcmeClient<T> {
    /// A client for the CA at `directory_url`, with the account `key` and an optional contact
    /// (`mailto:...`).
    pub fn new(
        transport: T,
        directory_url: impl Into<String>,
        key: AccountKey,
        contact: Option<String>,
    ) -> Self {
        Self {
            transport,
            directory_url: directory_url.into(),
            key,
            contact,
            timing: Timing::default(),
            directory: None,
            nonce: None,
            kid: None,
        }
    }

    /// Other waits (tests).
    pub fn with_timing(mut self, timing: Timing) -> Self {
        self.timing = timing;
        self
    }

    async fn directory(&mut self) -> Result<&Directory, AcmeError> {
        if self.directory.is_none() {
            let response = self
                .transport
                .send(HttpRequest {
                    method: Method::Get,
                    url: self.directory_url.clone(),
                    headers: vec![("Accept", "application/json".to_string())],
                    body: Vec::new(),
                })
                .await?;
            if response.status != 200 {
                return Err(problem(&response));
            }
            let doc = json_body(&response)?;
            self.directory = Some(Directory {
                new_nonce: str_field(&doc, "newNonce")?.to_string(),
                new_account: str_field(&doc, "newAccount")?.to_string(),
                new_order: str_field(&doc, "newOrder")?.to_string(),
            });
        }
        self.directory
            .as_ref()
            .ok_or_else(|| AcmeError::Protocol("no directory".to_string()))
    }

    async fn fresh_nonce(&mut self) -> Result<String, AcmeError> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }
        let url = self.directory().await?.new_nonce.clone();
        let response = self
            .transport
            .send(HttpRequest {
                method: Method::Head,
                url,
                headers: Vec::new(),
                body: Vec::new(),
            })
            .await?;
        response
            .header("replay-nonce")
            .map(str::to_string)
            .ok_or_else(|| AcmeError::Protocol("no Replay-Nonce from newNonce".to_string()))
    }

    /// A signed POST. `payload` `None` is POST-as-GET (an empty payload). The account is named
    /// by its `kid` once there is one, by its `jwk` before. A 2xx answer is returned; anything
    /// else is an error, after retrying `badNonce`.
    async fn post(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        accept: Option<&str>,
    ) -> Result<HttpResponse, AcmeError> {
        let mut tries = 0;
        loop {
            tries += 1;
            let nonce = self.fresh_nonce().await?;
            let mut protected = json!({"alg": "ES256", "nonce": nonce, "url": url});
            match &self.kid {
                Some(kid) => protected["kid"] = Value::String(kid.clone()),
                None => protected["jwk"] = self.key.jwk()?,
            }
            let protected = b64(protected.to_string());
            let payload = payload.map(|p| b64(p.to_string())).unwrap_or_default();
            let signature = self.key.sign(format!("{protected}.{payload}").as_bytes())?;
            let body =
                json!({"protected": protected, "payload": payload, "signature": b64(signature)});
            let mut headers = vec![("Content-Type", "application/jose+json".to_string())];
            if let Some(accept) = accept {
                headers.push(("Accept", accept.to_string()));
            }
            let response = self
                .transport
                .send(HttpRequest {
                    method: Method::Post,
                    url: url.to_string(),
                    headers,
                    body: body.to_string().into_bytes(),
                })
                .await?;
            self.nonce = response.header("replay-nonce").map(str::to_string);
            if (200..300).contains(&response.status) {
                return Ok(response);
            }
            let error = problem(&response);
            let bad_nonce =
                matches!(&error, AcmeError::Problem { kind, .. } if kind.ends_with(":badNonce"));
            if bad_nonce && tries < NONCE_RETRIES && self.nonce.is_some() {
                continue;
            }
            return Err(error);
        }
    }

    /// Creates the account, or finds the one this key already has (RFC 8555 7.3: the CA answers
    /// 200 for a known key).
    async fn register(&mut self) -> Result<(), AcmeError> {
        if self.kid.is_some() {
            return Ok(());
        }
        let url = self.directory().await?.new_account.clone();
        let mut payload = json!({"termsOfServiceAgreed": true});
        if let Some(contact) = &self.contact {
            payload["contact"] = json!([contact]);
        }
        let response = self.post(&url, Some(&payload), None).await?;
        let kid = response
            .header("location")
            .ok_or_else(|| AcmeError::Protocol("no account URL (Location)".to_string()))?;
        self.kid = Some(kid.to_string());
        Ok(())
    }

    fn wait_for(&self, response: &HttpResponse) -> Duration {
        response
            .header("retry-after")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(self.timing.poll_interval)
            .min(self.timing.poll_max_interval)
    }

    /// POST-as-GET on `url` until its `status` is one of `done` (returned) or `invalid` (an
    /// error with the CA's reason), for at most the timing's deadline.
    async fn poll(
        &mut self,
        url: &str,
        done: &[&str],
        what: &'static str,
    ) -> Result<Value, AcmeError> {
        let deadline = tokio::time::Instant::now() + self.timing.poll_deadline;
        loop {
            let response = self.post(url, None, None).await?;
            let doc = json_body(&response)?;
            let status = str_field(&doc, "status")?;
            if done.contains(&status) {
                return Ok(doc);
            }
            if status == "invalid" {
                return Err(AcmeError::Failed(format!(
                    "the {what} is invalid: {}",
                    failure_reason(&doc)
                )));
            }
            let pause = self.wait_for(&response);
            if tokio::time::Instant::now() + pause > deadline {
                return Err(AcmeError::Timeout(what));
            }
            tokio::time::sleep(pause).await;
        }
    }

    /// Obtains a certificate for `domain`: the whole of the module docs' state machine.
    /// `still_wanted` is asked before the name is made pending; false ends the attempt with
    /// [`AcmeError::NotWanted`] (the share was withdrawn or no longer lists `acme-tls/1`).
    pub async fn obtain(
        &mut self,
        domain: &str,
        book: &ChallengeBook,
        still_wanted: &(dyn Fn() -> bool + Sync),
    ) -> Result<Issued, AcmeError> {
        check_domain(domain)?;
        self.register().await?;
        let new_order = self.directory().await?.new_order.clone();
        let order_payload = json!({"identifiers": [{"type": "dns", "value": domain}]});
        let response = self.post(&new_order, Some(&order_payload), None).await?;
        let order_url = response
            .header("location")
            .ok_or_else(|| AcmeError::Protocol("no order URL (Location)".to_string()))?
            .to_string();
        let order = json_body(&response)?;
        check_identifiers(&order, domain)?;
        let finalize = str_field(&order, "finalize")?.to_string();
        let authorizations: Vec<String> = order
            .get("authorizations")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if authorizations.is_empty() || authorizations.len() > MAX_AUTHORIZATIONS {
            return Err(AcmeError::Protocol(
                "the order lists no authorization, or too many".to_string(),
            ));
        }
        for authorization in &authorizations {
            self.authorize(authorization, domain, book, still_wanted)
                .await?;
        }
        self.poll(&order_url, &["ready", "valid"], "order").await?;
        // The certificate gets its own key; the account key never signs a certificate.
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| AcmeError::Cert(e.to_string()))?;
        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| AcmeError::Cert(e.to_string()))?;
        params.distinguished_name = DistinguishedName::new();
        let csr = params
            .serialize_request(&key)
            .map_err(|e| AcmeError::Cert(e.to_string()))?;
        let finalized = self
            .post(
                &finalize,
                Some(&json!({"csr": b64(csr.der().as_ref())})),
                None,
            )
            .await?;
        let mut order = json_body(&finalized)?;
        if str_field(&order, "status")? != "valid" {
            order = self.poll(&order_url, &["valid"], "order").await?;
        }
        let certificate = str_field(&order, "certificate")?.to_string();
        let downloaded = self
            .post(
                &certificate,
                None,
                Some("application/pem-certificate-chain"),
            )
            .await?;
        let chain_pem = String::from_utf8(downloaded.body)
            .map_err(|_| AcmeError::Protocol("the certificate is not PEM text".to_string()))?;
        let (not_before, not_after) =
            super::renew::check_issued(&chain_pem, domain, key.public_key_raw())?;
        Ok(Issued {
            chain_pem,
            key_pem: key.serialize_pem(),
            not_before,
            not_after,
        })
    }

    async fn authorize(
        &mut self,
        url: &str,
        domain: &str,
        book: &ChallengeBook,
        still_wanted: &(dyn Fn() -> bool + Sync),
    ) -> Result<(), AcmeError> {
        let response = self.post(url, None, None).await?;
        let authz = json_body(&response)?;
        let identifier = authz.get("identifier");
        let is_domain = identifier.is_some_and(|id| {
            id.get("type").and_then(Value::as_str) == Some("dns")
                && id.get("value").and_then(Value::as_str) == Some(domain)
        });
        if !is_domain || authz.get("wildcard").and_then(Value::as_bool) == Some(true) {
            return Err(AcmeError::Protocol(
                "an authorization for another identifier, or a wildcard".to_string(),
            ));
        }
        match str_field(&authz, "status")? {
            "valid" => return Ok(()),
            "pending" => {}
            other => {
                return Err(AcmeError::Failed(format!(
                    "the authorization is {other}: {}",
                    failure_reason(&authz)
                )));
            }
        }
        let challenge = authz
            .get("challenges")
            .and_then(Value::as_array)
            .and_then(|list| {
                list.iter()
                    .find(|c| c.get("type").and_then(Value::as_str) == Some(CHALLENGE_TYPE))
            })
            .ok_or_else(|| {
                AcmeError::Failed(format!("the CA offers no {CHALLENGE_TYPE} challenge"))
            })?;
        let token = str_field(challenge, "token")?;
        if token.is_empty()
            || token.len() > MAX_TOKEN_BYTES
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(AcmeError::Protocol(
                "a challenge token that is not base64url".to_string(),
            ));
        }
        let challenge_url = str_field(challenge, "url")?.to_string();
        let key_authorization = format!("{token}.{}", self.key.thumbprint()?);
        if !still_wanted() {
            return Err(AcmeError::NotWanted);
        }
        // Pending before the CA is told to look: the validation can come at once.
        let pending = book.begin(domain, &key_authorization)?;
        let result = async {
            self.post(&challenge_url, Some(&json!({})), None).await?;
            self.poll(url, &["valid"], "authorization").await
        }
        .await;
        drop(pending);
        result.map(|_| ())
    }
}

fn check_identifiers(order: &Value, domain: &str) -> Result<(), AcmeError> {
    let list = order.get("identifiers").and_then(Value::as_array);
    // An order that does not repeat the identifiers is tolerated; one that does must match.
    if let Some(list) = list {
        let matches = list.len() == 1
            && list[0].get("type").and_then(Value::as_str) == Some("dns")
            && list[0].get("value").and_then(Value::as_str) == Some(domain);
        if !matches {
            return Err(AcmeError::Protocol(
                "the order is for other identifiers than asked".to_string(),
            ));
        }
    }
    Ok(())
}

/// The CA's reason out of an invalid authorization or order (its first challenge error, or the
/// order's), shortened.
fn failure_reason(doc: &Value) -> String {
    let error = doc.get("error").or_else(|| {
        doc.get("challenges")
            .and_then(Value::as_array)
            .and_then(|list| list.iter().find_map(|c| c.get("error")))
    });
    error
        .and_then(|e| e.get("detail"))
        .and_then(Value::as_str)
        .unwrap_or("no reason given")
        .chars()
        .take(300)
        .collect()
}
