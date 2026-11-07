//! The HTTP exchange of the ACME client: a transport trait ([`AcmeTransport`], so that the
//! client's state machine is tested against an in process CA) and the one real implementation,
//! HTTP/1.1 over TLS with the platform verifier ([`HttpsTransport`]).
//!
//! Deliberately small: `https` only, one request per connection (`Connection: close`), no
//! redirects, no proxy, bodies of at most [`MAX_RESPONSE_BYTES`], a heads of at most
//! [`MAX_HEAD_BYTES`], and one deadline over the whole exchange.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use super::AcmeError;

/// The most a response may carry (a certificate chain is a few KiB).
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// The most a response head may carry.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The deadline of one exchange, connect to last byte.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// The methods RFC 8555 uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Directory.
    Get,
    /// New nonce.
    Head,
    /// Everything signed.
    Post,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
        }
    }
}

/// One request to the CA.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// The method.
    pub method: Method,
    /// The absolute URL.
    pub url: String,
    /// Extra headers (`Accept`, `Content-Type`), name and value; no CR or LF in either.
    pub headers: Vec<(&'static str, String)>,
    /// The body of a POST.
    pub body: Vec<u8>,
}

/// One answer of the CA.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// The headers, names in lowercase.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first header called `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// What the ACME client needs of HTTP.
pub trait AcmeTransport: Send + Sync {
    /// Sends `request` and returns the answer, whatever its status.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, AcmeError>> + Send;
}

/// HTTPS to the CA with a rustls client configuration.
#[derive(Clone)]
pub struct HttpsTransport {
    config: Arc<tokio_rustls::rustls::ClientConfig>,
}

impl HttpsTransport {
    /// With the platform verifier (the system trust store), as the relay dial does.
    pub fn platform() -> Result<Self, AcmeError> {
        let config = menzil_carrier::client_config().map_err(|e| AcmeError::Tls(e.to_string()))?;
        Ok(Self { config })
    }

    /// With another client configuration (tests trust their own CA).
    pub fn with_config(config: Arc<tokio_rustls::rustls::ClientConfig>) -> Self {
        Self { config }
    }

    async fn exchange(&self, request: &HttpRequest) -> Result<HttpResponse, AcmeError> {
        let http = |e: &dyn std::fmt::Display| AcmeError::Http(e.to_string());
        let url = url::Url::parse(&request.url).map_err(|e| http(&e))?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(AcmeError::Http(
                "the CA's URL must be https without credentials".to_string(),
            ));
        }
        let host = url
            .host_str()
            .ok_or_else(|| AcmeError::Http("the CA's URL has no host".to_string()))?;
        let port = url.port().unwrap_or(443);
        let mut target = url.path().to_string();
        if let Some(query) = url.query() {
            target.push('?');
            target.push_str(query);
        }
        let bytes = encode_request(request, host, port, &target)?;
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| http(&e))?;
        let name = ServerName::try_from(host.to_string()).map_err(|e| http(&e))?;
        let mut tls = TlsConnector::from(self.config.clone())
            .connect(name, tcp)
            .await
            .map_err(|e| http(&e))?;
        tls.write_all(&bytes).await.map_err(|e| http(&e))?;
        tls.flush().await.map_err(|e| http(&e))?;
        let head_only = request.method == Method::Head;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            if let Some(response) = parse_response(&raw, false, head_only)? {
                return Ok(response);
            }
            if raw.len() > MAX_RESPONSE_BYTES + MAX_HEAD_BYTES {
                return Err(AcmeError::Http("the response is too long".to_string()));
            }
            let n = match tls.read(&mut chunk).await {
                Ok(n) => n,
                // A peer that closes without close_notify after a complete body is common.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                Err(e) => return Err(http(&e)),
            };
            if n == 0 {
                return parse_response(&raw, true, head_only)?
                    .ok_or_else(|| AcmeError::Http("the response ended early".to_string()));
            }
            raw.extend_from_slice(&chunk[..n]);
        }
    }
}

impl AcmeTransport for HttpsTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, AcmeError> {
        tokio::time::timeout(EXCHANGE_TIMEOUT, self.exchange(&request))
            .await
            .map_err(|_| AcmeError::Timeout("the exchange with the CA"))?
    }
}

fn clean(value: &str) -> Result<&str, AcmeError> {
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        Err(AcmeError::Http("a header holds a line break".to_string()))
    } else {
        Ok(value)
    }
}

fn encode_request(
    request: &HttpRequest,
    host: &str,
    port: u16,
    target: &str,
) -> Result<Vec<u8>, AcmeError> {
    let host_header = if port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: menzil\r\nConnection: close\r\n",
        request.method.as_str(),
        clean(target)?,
        clean(&host_header)?
    );
    for (name, value) in &request.headers {
        head.push_str(&format!("{}: {}\r\n", clean(name)?, clean(value)?));
    }
    if request.method == Method::Post {
        head.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    if request.method == Method::Post {
        bytes.extend_from_slice(&request.body);
    }
    Ok(bytes)
}

/// Parses `raw` as one HTTP/1.1 response. `Ok(None)` while it is incomplete; with `eof` a body
/// without a length ends where `raw` ends. Refuses a 1xx status, a head over [`MAX_HEAD_BYTES`],
/// a body over [`MAX_RESPONSE_BYTES`], and a malformed chunked body.
pub(crate) fn parse_response(
    raw: &[u8],
    eof: bool,
    head_request: bool,
) -> Result<Option<HttpResponse>, AcmeError> {
    let bad = |why: &str| AcmeError::Http(format!("the response is malformed: {why}"));
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    let head_len = match parsed.parse(raw) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return if raw.len() > MAX_HEAD_BYTES {
                Err(bad("the head is too long"))
            } else {
                Ok(None)
            };
        }
        Err(e) => return Err(bad(&e.to_string())),
    };
    if head_len > MAX_HEAD_BYTES {
        return Err(bad("the head is too long"));
    }
    let status = parsed.code.ok_or_else(|| bad("no status"))?;
    if status < 200 {
        return Err(bad("an informational status"));
    }
    let mut out_headers = Vec::new();
    for header in parsed.headers.iter() {
        let value = std::str::from_utf8(header.value).map_err(|_| bad("a header is not text"))?;
        out_headers.push((header.name.to_ascii_lowercase(), value.trim().to_string()));
    }
    let find = |name: &str| {
        out_headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    };
    let rest = &raw[head_len..];
    let no_body = head_request || status == 204 || status == 304;
    let body = if no_body {
        Vec::new()
    } else if find("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        match decode_chunked(rest)? {
            Some(body) => body,
            None if eof => return Err(bad("the chunked body ended early")),
            None => return Ok(None),
        }
    } else if let Some(length) = find("content-length") {
        let length: usize = length.parse().map_err(|_| bad("a bad content-length"))?;
        if length > MAX_RESPONSE_BYTES {
            return Err(bad("the body is too long"));
        }
        if rest.len() < length {
            return if eof {
                Err(bad("the body ended early"))
            } else {
                Ok(None)
            };
        }
        rest[..length].to_vec()
    } else if eof {
        if rest.len() > MAX_RESPONSE_BYTES {
            return Err(bad("the body is too long"));
        }
        rest.to_vec()
    } else {
        return Ok(None);
    };
    Ok(Some(HttpResponse {
        status,
        headers: out_headers,
        body,
    }))
}

/// Decodes a chunked body; `Ok(None)` while it is incomplete.
fn decode_chunked(mut rest: &[u8]) -> Result<Option<Vec<u8>>, AcmeError> {
    let bad = |why: &str| AcmeError::Http(format!("the chunked body is malformed: {why}"));
    let mut body = Vec::new();
    loop {
        let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let line = std::str::from_utf8(&rest[..line_end]).map_err(|_| bad("a size line"))?;
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|_| bad("a size"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            // Trailers up to the empty line.
            loop {
                let Some(end) = rest.windows(2).position(|w| w == b"\r\n") else {
                    return Ok(None);
                };
                let empty = end == 0;
                rest = &rest[end + 2..];
                if empty {
                    return Ok(Some(body));
                }
            }
        }
        if body.len() + size > MAX_RESPONSE_BYTES {
            return Err(bad("too long"));
        }
        if rest.len() < size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&rest[..size]);
        if &rest[size..size + 2] != b"\r\n" {
            return Err(bad("a chunk is not followed by a line break"));
        }
        rest = &rest[size + 2..];
    }
}
