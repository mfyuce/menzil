//! Reading the SNI and ALPN of a TLS ClientHello without terminating TLS (protocol.md 6.2, the
//! front door of `crate::front_door`).
//!
//! [`parse`] is a pure function over the bytes read so far: it reassembles the ClientHello across
//! TLS records (a hello may be split in several), reads the `server_name` and ALPN extensions and
//! says what is still missing. [`read_client_hello`] feeds it from a socket under the front
//! door's bounds: at most [`PEEK_LIMIT`] bytes (16 KiB) and one deadline for the whole hello.
//!
//! The parser is strict where two parsers could disagree, because the relay routes on the name it
//! reads and the node's TLS stack later reads the same bytes: a second `server_name` extension,
//! two `host_name` entries, a duplicated extension of any kind, bytes after the hello inside its
//! record, a hostname that is not plain ASCII DNS, or a hello that does not end where its length
//! says are all [`Invalid`] and never routed. The bytes are not consumed from the point of view
//! of the path that takes the connection: the caller replays them (`crate::prefixed`).

use std::collections::HashSet;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// The most bytes read while looking for the end of the ClientHello (protocol.md 6.2: "up to 16
/// KiB"): records headers included. A hello that is not complete by then is refused.
pub(crate) const PEEK_LIMIT: usize = 16 * 1024;
/// How long a peer has to deliver the whole ClientHello (protocol.md 6.2).
pub(crate) const PEEK_DEADLINE: Duration = Duration::from_secs(10);
/// The most connections reading a ClientHello at once (protocol.md 10).
pub(crate) const MAX_PEEKS: usize = 1_024;
/// The most TLS records a ClientHello may be spread over. Honest clients use one or two; the
/// bound keeps the work of reassembling it small whatever a peer sends.
const MAX_RECORDS: usize = 32;
/// The longest DNS name the relay will look at.
const MAX_NAME: usize = 253;

const RECORD_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const EXT_ALPN: u16 = 16;
const NAME_TYPE_HOST: u8 = 0;

/// What a ClientHello says that routing needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ClientHello {
    /// The `host_name` of the `server_name` extension, lowercased; `None` if the hello has no
    /// such extension.
    pub(crate) sni: Option<String>,
    /// The ALPN protocol ids offered, in order, as sent.
    pub(crate) alpn: Vec<Vec<u8>>,
}

/// Why the bytes are not a ClientHello the relay will route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Invalid {
    /// The first bytes are not a TLS handshake record.
    NotTls,
    /// The records or the hello are malformed or ambiguous (see the module docs).
    Malformed,
    /// The hello needs more than [`PEEK_LIMIT`] bytes.
    TooLarge,
    /// The `host_name` is not a plain ASCII DNS name.
    BadName,
}

/// The result of [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// The hello is not all here: the buffer must hold at least `need` bytes before parsing can
    /// get any further.
    Incomplete { need: usize },
    /// A complete ClientHello.
    Hello(ClientHello),
    /// Not a ClientHello the relay routes.
    Invalid(Invalid),
}

/// Parses the ClientHello at the start of `buf` (everything read so far).
pub(crate) fn parse(buf: &[u8]) -> Parsed {
    // The first bytes decide "this is not TLS" without waiting for a whole record header.
    if buf.first().is_some_and(|b| *b != RECORD_HANDSHAKE) || buf.get(1).is_some_and(|b| *b != 3) {
        return Parsed::Invalid(Invalid::NotTls);
    }
    let mut handshake: Vec<u8> = Vec::new();
    let mut total: Option<usize> = None;
    let mut pos = 0usize;
    let mut records = 0usize;
    loop {
        if let Some(total) = total
            && handshake.len() >= total
        {
            if handshake.len() > total {
                // Something follows the hello inside its record.
                return Parsed::Invalid(Invalid::Malformed);
            }
            break;
        }
        if buf.len() < pos + 5 {
            return Parsed::Incomplete { need: pos + 5 };
        }
        let header = &buf[pos..pos + 5];
        if header[0] != RECORD_HANDSHAKE || header[1] != 3 {
            return Parsed::Invalid(if records == 0 {
                Invalid::NotTls
            } else {
                Invalid::Malformed
            });
        }
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if len == 0 || len > 16_384 {
            return Parsed::Invalid(Invalid::Malformed);
        }
        records += 1;
        if records > MAX_RECORDS {
            return Parsed::Invalid(Invalid::Malformed);
        }
        if buf.len() < pos + 5 + len {
            return Parsed::Incomplete {
                need: pos + 5 + len,
            };
        }
        handshake.extend_from_slice(&buf[pos + 5..pos + 5 + len]);
        pos += 5 + len;
        if total.is_none() && handshake.len() >= 4 {
            if handshake[0] != HANDSHAKE_CLIENT_HELLO {
                return Parsed::Invalid(Invalid::Malformed);
            }
            let body = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            // At least one record header goes with it.
            if body + 4 + 5 > PEEK_LIMIT {
                return Parsed::Invalid(Invalid::TooLarge);
            }
            total = Some(body + 4);
        }
    }
    match parse_body(&handshake[4..]) {
        Ok(hello) => Parsed::Hello(hello),
        Err(invalid) => Parsed::Invalid(invalid),
    }
}

/// A cursor over a byte slice whose reads fail instead of panicking.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn rest(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.rest() < n {
            return None;
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    /// A vector with a one byte length.
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    /// A vector with a two byte length.
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

fn parse_body(body: &[u8]) -> Result<ClientHello, Invalid> {
    let bad = Invalid::Malformed;
    let mut c = Cursor::new(body);
    c.take(2).ok_or(bad)?; // legacy_version
    c.take(32).ok_or(bad)?; // random
    let session_id = c.vec8().ok_or(bad)?;
    if session_id.len() > 32 {
        return Err(bad);
    }
    let suites = c.vec16().ok_or(bad)?;
    if suites.len() < 2 || suites.len() % 2 != 0 {
        return Err(bad);
    }
    let compression = c.vec8().ok_or(bad)?;
    if compression.is_empty() {
        return Err(bad);
    }
    let mut hello = ClientHello {
        sni: None,
        alpn: Vec::new(),
    };
    if c.rest() == 0 {
        // TLS 1.2 and older may omit the extensions block.
        return Ok(hello);
    }
    let extensions = c.vec16().ok_or(bad)?;
    if c.rest() != 0 {
        return Err(bad);
    }
    let mut seen: HashSet<u16> = HashSet::new();
    let mut e = Cursor::new(extensions);
    while e.rest() > 0 {
        let kind = e.u16().ok_or(bad)?;
        let data = e.vec16().ok_or(bad)?;
        if !seen.insert(kind) {
            return Err(bad);
        }
        match kind {
            EXT_SERVER_NAME => hello.sni = Some(parse_server_name(data)?),
            EXT_ALPN => hello.alpn = parse_alpn(data)?,
            _ => {}
        }
    }
    Ok(hello)
}

fn parse_server_name(data: &[u8]) -> Result<String, Invalid> {
    let bad = Invalid::Malformed;
    let mut c = Cursor::new(data);
    let list = c.vec16().ok_or(bad)?;
    if c.rest() != 0 || list.is_empty() {
        return Err(bad);
    }
    let mut l = Cursor::new(list);
    let mut host: Option<&[u8]> = None;
    while l.rest() > 0 {
        let name_type = l.u8().ok_or(bad)?;
        let name = l.vec16().ok_or(bad)?;
        if name_type == NAME_TYPE_HOST && host.replace(name).is_some() {
            // Two names: the relay and the node could pick different ones.
            return Err(bad);
        }
    }
    let host = host.ok_or(bad)?;
    normalize_host(host).ok_or(Invalid::BadName)
}

fn parse_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, Invalid> {
    let bad = Invalid::Malformed;
    let mut c = Cursor::new(data);
    let list = c.vec16().ok_or(bad)?;
    if c.rest() != 0 || list.is_empty() {
        return Err(bad);
    }
    let mut l = Cursor::new(list);
    let mut out = Vec::new();
    while l.rest() > 0 {
        let protocol = l.vec8().ok_or(bad)?;
        if protocol.is_empty() {
            return Err(bad);
        }
        out.push(protocol.to_vec());
    }
    Ok(out)
}

/// A hostname as the relay compares it: ASCII letters, digits and hyphens in dot separated
/// labels of 1 to 63 bytes (not starting or ending with a hyphen), no trailing dot (RFC 6066),
/// 253 bytes at most, lowercased. An internationalized name arrives as its `xn--` form; a UTF-8
/// one is refused, and so is an empty name.
pub(crate) fn normalize_host(name: &[u8]) -> Option<String> {
    if name.is_empty() || name.len() > MAX_NAME {
        return None;
    }
    let mut out = String::with_capacity(name.len());
    for label in name.split(|b| *b == b'.') {
        if label.is_empty()
            || label.len() > 63
            || label[0] == b'-'
            || label[label.len() - 1] == b'-'
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
    }
    Some(out)
}

/// What reading a connection's first bytes gave.
#[derive(Debug)]
pub(crate) enum Peeked {
    /// A ClientHello; `bytes` is everything read, to be replayed.
    Hello { bytes: Vec<u8>, hello: ClientHello },
    /// The bytes read are not a ClientHello the relay routes (nothing is replayed: the caller
    /// answers with the static refusal).
    Invalid(Invalid),
    /// The peer closed, failed, or did not deliver the hello before the deadline: the
    /// connection is dropped without an answer.
    Dropped,
}

/// Reads from `tcp` until it holds a whole ClientHello, at most [`PEEK_LIMIT`] bytes and
/// `deadline` in all.
pub(crate) async fn read_client_hello(tcp: &mut TcpStream, deadline: Duration) -> Peeked {
    let read = async {
        let mut bytes: Vec<u8> = Vec::with_capacity(2048);
        let mut need = 5usize;
        let mut chunk = [0u8; 4096];
        loop {
            while bytes.len() < need {
                let room = (PEEK_LIMIT - bytes.len()).min(chunk.len());
                if room == 0 {
                    return Peeked::Invalid(Invalid::TooLarge);
                }
                match tcp.read(&mut chunk[..room]).await {
                    Ok(0) | Err(_) => return Peeked::Dropped,
                    Ok(n) => bytes.extend_from_slice(&chunk[..n]),
                }
            }
            match parse(&bytes) {
                Parsed::Hello(hello) => return Peeked::Hello { bytes, hello },
                Parsed::Invalid(invalid) => return Peeked::Invalid(invalid),
                Parsed::Incomplete { need: more } => {
                    if more > PEEK_LIMIT {
                        return Peeked::Invalid(Invalid::TooLarge);
                    }
                    need = more;
                }
            }
        }
    };
    tokio::time::timeout(deadline, read)
        .await
        .unwrap_or(Peeked::Dropped)
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Builds ClientHello bytes for tests.

    /// A ClientHello body (after the 4 byte handshake header) with the given extensions block.
    pub(crate) fn body(extensions: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend_from_slice(&[7u8; 32]);
        b.push(0); // session id
        b.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02]); // suites
        b.extend_from_slice(&[1, 0]); // compression
        if let Some(ext) = extensions {
            b.extend_from_slice(&(ext.len() as u16).to_be_bytes());
            b.extend_from_slice(ext);
        }
        b
    }

    pub(crate) fn extension(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut e = kind.to_be_bytes().to_vec();
        e.extend_from_slice(&(data.len() as u16).to_be_bytes());
        e.extend_from_slice(data);
        e
    }

    pub(crate) fn server_name_ext(names: &[(u8, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (kind, name) in names {
            list.push(*kind);
            list.extend_from_slice(&(name.len() as u16).to_be_bytes());
            list.extend_from_slice(name);
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        extension(0, &data)
    }

    pub(crate) fn alpn_ext(protocols: &[&[u8]]) -> Vec<u8> {
        let mut list = Vec::new();
        for p in protocols {
            list.push(p.len() as u8);
            list.extend_from_slice(p);
        }
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        extension(16, &data)
    }

    /// The handshake message: type 1, 24 bit length, `body`.
    pub(crate) fn handshake(body: &[u8]) -> Vec<u8> {
        let mut h = vec![
            1,
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
        ];
        h.extend_from_slice(body);
        h
    }

    /// `message` cut into records of at most `chunk` bytes each.
    pub(crate) fn records(message: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for part in message.chunks(chunk) {
            out.extend_from_slice(&[22, 3, 1]);
            out.extend_from_slice(&(part.len() as u16).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// A whole ClientHello for `sni` (none if `None`) offering `alpn`, in one record.
    pub(crate) fn client_hello(sni: Option<&str>, alpn: &[&[u8]]) -> Vec<u8> {
        let mut ext = Vec::new();
        if let Some(name) = sni {
            ext.extend(server_name_ext(&[(0, name.as_bytes())]));
        }
        if !alpn.is_empty() {
            ext.extend(alpn_ext(alpn));
        }
        // An extension block is always written, as modern clients do.
        records(&handshake(&body(Some(&ext))), 16_384)
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn hello_of(bytes: &[u8]) -> ClientHello {
        match parse(bytes) {
            Parsed::Hello(hello) => hello,
            other => panic!("expected a hello, got {other:?}"),
        }
    }

    #[test]
    fn reads_the_sni_and_the_alpn_in_order() {
        let bytes = client_hello(
            Some("App.Example.Test"),
            &[b"h2", b"http/1.1", b"acme-tls/1"],
        );
        let hello = hello_of(&bytes);
        assert_eq!(hello.sni.as_deref(), Some("app.example.test"));
        assert_eq!(
            hello.alpn,
            vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"acme-tls/1".to_vec()]
        );
    }

    #[test]
    fn no_server_name_extension_is_no_sni_and_so_is_no_extensions_block() {
        assert_eq!(hello_of(&client_hello(None, &[])).sni, None);
        let bare = records(&handshake(&body(None)), 16_384);
        let hello = hello_of(&bare);
        assert_eq!(hello.sni, None);
        assert!(hello.alpn.is_empty());
    }

    #[test]
    fn a_truncated_hello_is_incomplete_at_every_cut_and_never_a_hello() {
        let bytes = client_hello(Some("app.example.test"), &[b"h2"]);
        for cut in 0..bytes.len() {
            match parse(&bytes[..cut]) {
                Parsed::Incomplete { need } => {
                    assert!(
                        need > cut,
                        "need {need} must be beyond the {cut} bytes held"
                    );
                    assert!(need <= bytes.len(), "never asks for more than there is");
                }
                other => panic!("cut {cut}: {other:?}"),
            }
        }
        assert!(matches!(parse(&bytes), Parsed::Hello(_)));
    }

    #[test]
    fn a_hello_fragmented_across_records_parses_the_same_at_every_chunk_size() {
        let ext = [
            server_name_ext(&[(0, b"app.ali.example.test")]),
            alpn_ext(&[b"acme-tls/1"]),
        ]
        .concat();
        let message = handshake(&body(Some(&ext)));
        let whole = hello_of(&records(&message, 16_384));
        for chunk in [1usize, 2, 3, 7, 11, 40, 100] {
            let fragmented = records(&message, chunk);
            if message.len().div_ceil(chunk) > MAX_RECORDS {
                assert_eq!(
                    parse(&fragmented),
                    Parsed::Invalid(Invalid::Malformed),
                    "chunk {chunk}: more records than the bound"
                );
                continue;
            }
            assert_eq!(hello_of(&fragmented), whole, "chunk {chunk}");
        }
    }

    #[test]
    fn the_record_count_is_bounded() {
        let message = handshake(&body(Some(&server_name_ext(&[(0, b"a.example.test")]))));
        let many = records(&message, 1);
        assert!(message.len() > MAX_RECORDS);
        assert_eq!(parse(&many), Parsed::Invalid(Invalid::Malformed));
    }

    #[test]
    fn something_that_is_not_tls_is_refused_from_the_first_bytes() {
        assert_eq!(
            parse(b"G"),
            Parsed::Invalid(Invalid::NotTls),
            "an HTTP request needs no more than one byte to be told"
        );
        assert_eq!(
            parse(b"GET / HTTP/1.1\r\n\r\n"),
            Parsed::Invalid(Invalid::NotTls)
        );
        assert_eq!(parse(&[22, 2, 0]), Parsed::Invalid(Invalid::NotTls));
        assert_eq!(parse(&[]), Parsed::Incomplete { need: 5 });
        assert_eq!(parse(&[22]), Parsed::Incomplete { need: 5 });
    }

    #[test]
    fn a_handshake_that_is_not_a_client_hello_is_malformed() {
        let mut message = handshake(&body(None));
        message[0] = 2; // ServerHello
        assert_eq!(
            parse(&records(&message, 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
    }

    #[test]
    fn malformed_lengths_are_refused() {
        // A zero length record and an oversized one.
        assert_eq!(
            parse(&[22, 3, 1, 0, 0]),
            Parsed::Invalid(Invalid::Malformed)
        );
        assert_eq!(
            parse(&[22, 3, 1, 0x40, 0x01]),
            Parsed::Invalid(Invalid::Malformed)
        );
        // A hello whose declared length runs past its record's end is incomplete (the next
        // record may carry it), and one whose declared length is short leaves bytes behind.
        let mut message = handshake(&body(None));
        let real = message.len() - 4;
        message[3] = (real - 1) as u8;
        assert_eq!(
            parse(&records(&message, 16_384)),
            Parsed::Invalid(Invalid::Malformed),
            "a trailing byte after the hello"
        );
        let mut long = handshake(&body(None));
        long[3] = (real + 1) as u8;
        assert!(matches!(
            parse(&records(&long, 16_384)),
            Parsed::Incomplete { .. }
        ));
        // A session id longer than 32, a cipher suites vector of odd length, a hello cut inside
        // a vector: all malformed.
        let mut b = body(None);
        b[34] = 33;
        assert_eq!(
            parse(&records(&handshake(&b), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
        let short = handshake(&body(None)[..40]);
        assert_eq!(
            parse(&records(&short, 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
        // An extension longer than the block.
        let mut ext = server_name_ext(&[(0, b"a.example.test")]);
        let n = ext.len();
        ext[3] = ext[3].wrapping_add(9);
        assert_eq!(n, ext.len());
        assert_eq!(
            parse(&records(&handshake(&body(Some(&ext))), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
    }

    #[test]
    fn a_hello_that_cannot_fit_in_sixteen_kib_is_too_large() {
        // Declared length 24 bits: 20,000.
        let mut message = vec![1, 0, 0x4e, 0x20];
        message.extend_from_slice(&[0u8; 100]);
        assert_eq!(
            parse(&records(&message, 16_384)),
            Parsed::Invalid(Invalid::TooLarge)
        );
        // Huge: 16 MiB declared.
        let huge = [vec![1, 0xff, 0xff, 0xff], vec![0u8; 50]].concat();
        assert_eq!(
            parse(&records(&huge, 16_384)),
            Parsed::Invalid(Invalid::TooLarge)
        );
        // Right at the bound: 16,384 - 5 - 4 body bytes is accepted as incomplete, one more is
        // too large.
        let ok = [vec![1, 0, 0x3f, 0xf7], vec![0u8; 20]].concat();
        assert!(matches!(
            parse(&records(&ok, 16_384)),
            Parsed::Incomplete { .. }
        ));
        let over = [vec![1, 0, 0x3f, 0xf8], vec![0u8; 20]].concat();
        assert_eq!(
            parse(&records(&over, 16_384)),
            Parsed::Invalid(Invalid::TooLarge)
        );
    }

    #[test]
    fn upper_case_is_lowered_and_an_idn_must_arrive_as_its_a_label() {
        let bytes = client_hello(Some("XN--Bcher-Kva.Example.TEST"), &[]);
        assert_eq!(
            hello_of(&bytes).sni.as_deref(),
            Some("xn--bcher-kva.example.test")
        );
        // The U-label form, UTF-8 on the wire, is not a name the relay routes.
        let utf8 = [server_name_ext(&[(
            0,
            "b\u{fc}cher.example.test".as_bytes(),
        )])]
        .concat();
        assert_eq!(
            parse(&records(&handshake(&body(Some(&utf8))), 16_384)),
            Parsed::Invalid(Invalid::BadName)
        );
    }

    #[test]
    fn bad_host_names_are_refused() {
        let long_label = "a".repeat(64);
        let too_long = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63)
        );
        for name in [
            "",
            ".",
            "a..b",
            "app.example.test.",
            ".app",
            "-a.example",
            "a-.example",
            "a b.example",
            "a_b.example",
            "app/x.example",
            long_label.as_str(),
            too_long.as_str(),
        ] {
            assert_eq!(normalize_host(name.as_bytes()), None, "{name:?}");
        }
        assert_eq!(
            normalize_host("127.0.0.1".as_bytes()).as_deref(),
            Some("127.0.0.1"),
            "an address is a syntactically fine name that nothing resolves"
        );
        assert!(normalize_host(&[b'a'; 63]).is_some());
    }

    #[test]
    fn ambiguity_is_refused() {
        // Two server_name extensions.
        let two_ext = [
            server_name_ext(&[(0, b"a.example.test")]),
            server_name_ext(&[(0, b"b.example.test")]),
        ]
        .concat();
        assert_eq!(
            parse(&records(&handshake(&body(Some(&two_ext))), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
        // Two host_name entries in one extension.
        let two_names = server_name_ext(&[(0, b"a.example.test"), (0, b"b.example.test")]);
        assert_eq!(
            parse(&records(&handshake(&body(Some(&two_names))), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
        // A duplicated extension of another kind.
        let dup = [alpn_ext(&[b"h2"]), alpn_ext(&[b"h2"])].concat();
        assert_eq!(
            parse(&records(&handshake(&body(Some(&dup))), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
        // A server_name extension without a host_name, and an empty one.
        let other_type = server_name_ext(&[(1, b"a.example.test")]);
        assert_eq!(
            parse(&records(&handshake(&body(Some(&other_type))), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
        assert_eq!(
            parse(&records(
                &handshake(&body(Some(&extension(0, &[])))),
                16_384
            )),
            Parsed::Invalid(Invalid::Malformed)
        );
        // An unknown name type next to a host_name is skipped.
        let mixed = server_name_ext(&[(7, b"ignored"), (0, b"a.example.test")]);
        assert_eq!(
            hello_of(&records(&handshake(&body(Some(&mixed))), 16_384))
                .sni
                .as_deref(),
            Some("a.example.test")
        );
    }

    #[test]
    fn alpn_with_an_empty_protocol_or_a_ragged_list_is_malformed() {
        let empty_protocol = extension(16, &[0, 3, 0, 2, b'h']);
        assert_eq!(
            parse(&records(&handshake(&body(Some(&empty_protocol))), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
        let ragged = extension(16, &[0, 3, 5, b'h', b'2']);
        assert_eq!(
            parse(&records(&handshake(&body(Some(&ragged))), 16_384)),
            Parsed::Invalid(Invalid::Malformed)
        );
    }

    #[test]
    fn a_real_rustls_client_hello_parses() {
        use std::sync::Arc;

        crate::tls::ensure_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        let (chain, _) = crate::tests_support::self_signed_cert("x.example.test");
        roots.add(chain[0].clone()).unwrap();
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec(), b"acme-tls/1".to_vec()];
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            rustls::pki_types::ServerName::try_from("app.Example.test").unwrap(),
        )
        .unwrap();
        let mut bytes = Vec::new();
        client.write_tls(&mut bytes).unwrap();
        let hello = hello_of(&bytes);
        assert_eq!(hello.sni.as_deref(), Some("app.example.test"));
        assert_eq!(hello.alpn, vec![b"h2".to_vec(), b"acme-tls/1".to_vec()]);
    }

    mod socket {
        use super::*;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        async fn pair() -> (TcpStream, TcpStream) {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (client, server) = tokio::join!(TcpStream::connect(addr), async {
                listener.accept().await.unwrap().0
            });
            (client.unwrap(), server)
        }

        #[tokio::test]
        async fn a_hello_arriving_in_dribbles_is_read_whole_and_handed_back_byte_for_byte() {
            let (mut client, mut server) = pair().await;
            let bytes = client_hello(Some("app.example.test"), &[b"h2"]);
            let sent = bytes.clone();
            let writer = tokio::spawn(async move {
                for part in sent.chunks(7) {
                    client.write_all(part).await.unwrap();
                    client.flush().await.unwrap();
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                client
            });
            match read_client_hello(&mut server, Duration::from_secs(10)).await {
                Peeked::Hello { bytes: got, hello } => {
                    assert_eq!(got, bytes, "the bytes are handed back unchanged");
                    assert_eq!(hello.sni.as_deref(), Some("app.example.test"));
                }
                other => panic!("{other:?}"),
            }
            let _keep = writer.await.unwrap();
        }

        #[tokio::test(start_paused = true)]
        async fn a_peer_that_stalls_is_dropped_at_the_deadline() {
            let (mut client, mut server) = pair().await;
            let bytes = client_hello(Some("app.example.test"), &[]);
            client.write_all(&bytes[..10]).await.unwrap();
            let began = tokio::time::Instant::now();
            let peeked = read_client_hello(&mut server, PEEK_DEADLINE).await;
            assert!(matches!(peeked, Peeked::Dropped), "{peeked:?}");
            assert_eq!(began.elapsed(), PEEK_DEADLINE);
        }

        #[tokio::test]
        async fn a_peer_that_closes_early_is_dropped() {
            let (mut client, mut server) = pair().await;
            client.write_all(&[22, 3, 1]).await.unwrap();
            drop(client);
            assert!(matches!(
                read_client_hello(&mut server, Duration::from_secs(10)).await,
                Peeked::Dropped
            ));
        }

        #[tokio::test]
        async fn reading_stops_at_sixteen_kib() {
            let (mut client, mut server) = pair().await;
            // A record that claims 16,384 bytes of a hello that wants more, and then data.
            let mut bytes = vec![22, 3, 1, 0x40, 0x00, 1, 0x00, 0x3f, 0xf0];
            bytes.extend(std::iter::repeat_n(0u8, PEEK_LIMIT * 2));
            let writer = tokio::spawn(async move {
                let _ = client.write_all(&bytes).await;
                client
            });
            let peeked = read_client_hello(&mut server, Duration::from_secs(10)).await;
            assert!(
                matches!(peeked, Peeked::Invalid(Invalid::TooLarge)),
                "{peeked:?}"
            );
            let _ = writer.await;
        }
    }
}
