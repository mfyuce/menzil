//! The strings people paste between machines (TOBEDECIDED 14: phase 1 has no invites, a new
//! member is admitted by hand). Four kinds, told apart by their prefix so that pasting the wrong
//! one fails with a clear message instead of a decode error:
//!
//! * `menzil1-join:` + base64url of a NodeCert: what `menzil init` prints, what the owner pastes
//!   into `menzil admit`.
//! * `menzil1-docs:` + base64url of a Roster and a Policy ([`documents_to_bytes`]): what `menzil
//!   admit` prints, what the new member pastes into `menzil join`. Documents a steward signed
//!   come with the owner signed pair they were made from, the base (protocol.md 2.3; payload
//!   version 2); a token for documents the owner signed is version 1, as it always was.
//! * `menzil1-roster:` + base64url of a Roster alone: what `menzil token --for-relay` prints,
//!   what a relay's operator pastes into `menzil relay add-network`. The Policy (who may use
//!   what, and the members' device names) is hidden from relays (threat-model.md), so a relay
//!   is never handed it: not on its command line, not in its shell history. A Roster a steward
//!   signed comes with its base Roster ([`encode_roster`]).
//! * `menzil1-steward:` + base64url of a network id and a steward public key
//!   ([`encode_steward_request`]): what `menzil steward request` prints on the device that will
//!   hold the steward key, what the owner pastes into `menzil steward add`. Public data only.
//!
//! A token carries only public, signed material. Nothing here verifies a signature; the caller
//! does, against the key the document names (an unsigned or forged token must not be trusted
//! because it decoded).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use menzil_admin::Documents;
use menzil_proto::{MAX_DOC_BYTES, NetworkId, NodeCert, Policy, Roster, StewardKey};
use thiserror::Error;

/// Prefix of a join request.
pub const JOIN_PREFIX: &str = "menzil1-join:";
/// Prefix of a membership token.
pub const DOCS_PREFIX: &str = "menzil1-docs:";
/// Prefix of a token that carries a Roster alone, for a relay.
pub const ROSTER_PREFIX: &str = "menzil1-roster:";
/// Prefix of a steward request: the public half of a steward key and the network it is for.
pub const STEWARD_PREFIX: &str = "menzil1-steward:";

/// The longest token text accepted: four documents (a pair and its base) at the size verifiers
/// allow, base64 encoded, with room for the framing. Checked before any decoding.
pub const MAX_TOKEN_CHARS: usize = (4 * MAX_DOC_BYTES + 32).div_ceil(3) * 4;

/// Reads a token from `source` (standard input, when a command is given `-`): the whole text,
/// trimmed. At most a token's length plus a little room for a newline and spaces is read; more
/// than that is not a token and is refused without reading on (the fourth red-team round, N5: a
/// file piped by mistake, or a stream that never ends, was read into memory whole before any
/// length check).
pub fn read_token(source: impl std::io::Read) -> anyhow::Result<String> {
    use anyhow::Context;
    use std::io::Read;
    let limit = MAX_TOKEN_CHARS as u64 + 64;
    let mut text = String::new();
    source
        .take(limit + 1)
        .read_to_string(&mut text)
        .context("reading the token from standard input")?;
    if text.len() as u64 > limit {
        anyhow::bail!(
            "standard input holds more than any token can be ({limit} bytes at most): nothing more was read"
        );
    }
    Ok(text.trim().to_string())
}

/// Why a pasted token was not accepted.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TokenError {
    /// The text does not start with the prefix for what was expected.
    #[error("expected a token starting with {expected:?}{hint}")]
    WrongKind {
        /// The prefix that was expected.
        expected: &'static str,
        /// A pointer to the other kind, if that is what was pasted.
        hint: &'static str,
    },
    /// Longer than any token can be.
    #[error("the token is too long to be a menzil token")]
    TooLong,
    /// The text after the prefix is not base64url.
    #[error("the token is not valid base64url (was it cut off or split over lines?)")]
    BadBase64,
    /// The bytes do not decode as what the prefix says.
    #[error("the token does not hold a valid {0}")]
    Malformed(&'static str),
}

fn strip<'a>(
    token: &'a str,
    expected: &'static str,
    others: &[(&'static str, &'static str)],
) -> Result<&'a str, TokenError> {
    let token = token.trim();
    if let Some(rest) = token.strip_prefix(expected) {
        return Ok(rest);
    }
    let hint = others
        .iter()
        .find(|(prefix, _)| token.starts_with(prefix))
        .map_or("", |(_, hint)| hint);
    Err(TokenError::WrongKind { expected, hint })
}

const OTHER_KIND: &str = " (this is another kind of token)";

fn decode_base64(text: &str) -> Result<Vec<u8>, TokenError> {
    if text.len() > MAX_TOKEN_CHARS {
        return Err(TokenError::TooLong);
    }
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| TokenError::BadBase64)
}

/// A join request for `cert`: the certificate `menzil init` made.
pub fn encode_join_request(cert: &NodeCert) -> String {
    format!("{JOIN_PREFIX}{}", URL_SAFE_NO_PAD.encode(cert.encode()))
}

/// The certificate in a join request. Its signature is not checked here.
pub fn decode_join_request(token: &str) -> Result<NodeCert, TokenError> {
    let bytes = decode_base64(strip(
        token,
        JOIN_PREFIX,
        &[
            (DOCS_PREFIX, OTHER_KIND),
            (ROSTER_PREFIX, OTHER_KIND),
            (STEWARD_PREFIX, OTHER_KIND),
        ],
    )?)?;
    NodeCert::decode_strict(&bytes).map_err(|_| TokenError::Malformed("node certificate"))
}

/// Appends `doc` preceded by its length as a big endian `u32`.
fn push_part(bytes: &mut Vec<u8>, doc: &[u8]) {
    bytes.extend_from_slice(&(doc.len() as u32).to_be_bytes());
    bytes.extend_from_slice(doc);
}

/// Takes a part written by [`push_part`] off the front of `bytes`, if it is there and no larger
/// than a verifier accepts.
fn take_part<'a>(bytes: &mut &'a [u8]) -> Option<&'a [u8]> {
    let (len, rest) = bytes.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    if len > MAX_DOC_BYTES || len > rest.len() {
        return None;
    }
    let (part, rest) = rest.split_at(len);
    *bytes = rest;
    Some(part)
}

/// A Roster and the Policy issued with it as one byte string (and, for documents a steward
/// signed, the owner signed pair they were made from). This is the payload of a membership
/// token and also the file a node keeps for each network, so the documents are written and
/// read as one unit.
///
/// Version 1, for documents the owner signed: a version byte (1), the Roster's encoding
/// preceded by its length as a big endian `u32`, then the Policy's encoding. Version 2, for
/// documents with a base: the byte 2, then the Roster, the Policy and the base Roster, each
/// preceded by its length, then the base Policy to the end.
pub fn documents_to_bytes(docs: &Documents) -> Vec<u8> {
    let (roster, policy) = (docs.roster().encode(), docs.policy().encode());
    let mut bytes = Vec::with_capacity(5 + roster.len() + policy.len());
    let Some((base_roster, base_policy)) = docs.base() else {
        bytes.push(1);
        push_part(&mut bytes, &roster);
        bytes.extend_from_slice(&policy);
        return bytes;
    };
    bytes.push(2);
    push_part(&mut bytes, &roster);
    push_part(&mut bytes, &policy);
    push_part(&mut bytes, &base_roster.encode());
    bytes.extend_from_slice(&base_policy.encode());
    bytes
}

/// The documents back from [`documents_to_bytes`]. Signatures are not checked here (that is
/// [`Documents::verify`]); the documents are paired, and so are the bases.
pub fn documents_from_bytes(bytes: &[u8]) -> Result<Documents, TokenError> {
    let malformed = TokenError::Malformed("pair of documents");
    let (version, mut rest) = bytes.split_first().ok_or(malformed.clone())?;
    let parts: Vec<&[u8]> = match version {
        1 => {
            let roster = take_part(&mut rest).ok_or(malformed.clone())?;
            vec![roster, rest]
        }
        2 => {
            let roster = take_part(&mut rest).ok_or(malformed.clone())?;
            let policy = take_part(&mut rest).ok_or(malformed.clone())?;
            let base_roster = take_part(&mut rest).ok_or(malformed.clone())?;
            vec![roster, policy, base_roster, rest]
        }
        _ => return Err(malformed),
    };
    if parts.iter().any(|part| part.len() > MAX_DOC_BYTES) {
        return Err(TokenError::Malformed("pair of documents"));
    }
    let roster = Roster::decode_strict(parts[0]).map_err(|_| TokenError::Malformed("Roster"))?;
    let policy = Policy::decode_strict(parts[1]).map_err(|_| TokenError::Malformed("Policy"))?;
    let docs = if parts.len() == 2 {
        Documents::from_signed(roster, policy)
    } else {
        let base_roster =
            Roster::decode_strict(parts[2]).map_err(|_| TokenError::Malformed("base Roster"))?;
        let base_policy =
            Policy::decode_strict(parts[3]).map_err(|_| TokenError::Malformed("base Policy"))?;
        Documents::from_signed_with_base(roster, policy, base_roster, base_policy)
    };
    docs.map_err(|_| TokenError::Malformed("pair of documents"))
}

/// A membership token for a Roster and the Policy issued with it (and their base, if a
/// steward signed them).
pub fn encode_documents(docs: &Documents) -> String {
    format!(
        "{DOCS_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(documents_to_bytes(docs))
    )
}

/// The documents in a membership token. Signatures are not checked here.
pub fn decode_documents(token: &str) -> Result<Documents, TokenError> {
    documents_from_bytes(&decode_base64(strip(
        token,
        DOCS_PREFIX,
        &[
            (JOIN_PREFIX, OTHER_KIND),
            (ROSTER_PREFIX, OTHER_KIND),
            (STEWARD_PREFIX, OTHER_KIND),
        ],
    )?)?)
}

/// The Roster, and its base Roster when a steward signed it, as one byte string: the Roster's
/// own encoding when the owner signed it (the first byte of that is a CBOR array header, 0x82),
/// else the byte 2, the Roster preceded by its length, then the base Roster.
pub fn roster_to_bytes(roster: &Roster, base: Option<&Roster>) -> Vec<u8> {
    let Some(base) = base else {
        return roster.encode();
    };
    let mut bytes = vec![2];
    push_part(&mut bytes, &roster.encode());
    bytes.extend_from_slice(&base.encode());
    bytes
}

/// The Roster and its base from [`roster_to_bytes`]. Signatures are not checked here.
pub fn roster_from_bytes(bytes: &[u8]) -> Result<(Roster, Option<Roster>), TokenError> {
    let Some((&2, mut rest)) = bytes.split_first() else {
        let roster = Roster::decode_strict(bytes).map_err(|_| TokenError::Malformed("Roster"))?;
        return Ok((roster, None));
    };
    let roster = take_part(&mut rest).ok_or(TokenError::Malformed("Roster"))?;
    if rest.len() > MAX_DOC_BYTES {
        return Err(TokenError::Malformed("Roster"));
    }
    let roster = Roster::decode_strict(roster).map_err(|_| TokenError::Malformed("Roster"))?;
    let base = Roster::decode_strict(rest).map_err(|_| TokenError::Malformed("base Roster"))?;
    Ok((roster, Some(base)))
}

/// A token for a Roster alone: what a relay is given. It carries none of the Policy. `base` is
/// the owner signed Roster a steward signed `roster` was made from.
pub fn encode_roster(roster: &Roster, base: Option<&Roster>) -> String {
    format!(
        "{ROSTER_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(roster_to_bytes(roster, base))
    )
}

/// The Roster in a relay token, and its base when a steward signed it. Signatures are not
/// checked here. A full membership token is refused with a pointer to the right command:
/// pasting it would hand the relay the Policy.
pub fn decode_roster(token: &str) -> Result<(Roster, Option<Roster>), TokenError> {
    const FULL_TOKEN: &str = " (this is a full membership token, which carries the Policy; a relay is given the Roster alone: make its token with `menzil token --for-relay`)";
    let bytes = decode_base64(strip(
        token,
        ROSTER_PREFIX,
        &[
            (DOCS_PREFIX, FULL_TOKEN),
            (JOIN_PREFIX, OTHER_KIND),
            (STEWARD_PREFIX, OTHER_KIND),
        ],
    )?)?;
    roster_from_bytes(&bytes)
}

/// A steward request: the version byte 1, the network id and the public key of a steward key
/// that the device holding the secret half made for that network.
pub fn encode_steward_request(network_id: NetworkId, steward: StewardKey) -> String {
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&<[u8; 32]>::from(network_id));
    bytes.extend_from_slice(&<[u8; 32]>::from(steward));
    format!("{STEWARD_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// The network and the steward public key in a steward request.
pub fn decode_steward_request(token: &str) -> Result<(NetworkId, StewardKey), TokenError> {
    let bytes = decode_base64(strip(
        token,
        STEWARD_PREFIX,
        &[
            (JOIN_PREFIX, OTHER_KIND),
            (DOCS_PREFIX, OTHER_KIND),
            (ROSTER_PREFIX, OTHER_KIND),
        ],
    )?)?;
    let [1, rest @ ..] = bytes.as_slice() else {
        return Err(TokenError::Malformed("steward request"));
    };
    let rest: &[u8; 64] = rest
        .try_into()
        .map_err(|_| TokenError::Malformed("steward request"))?;
    let (network, steward) = rest.split_at(32);
    Ok((
        NetworkId::from(<[u8; 32]>::try_from(network).expect("32 bytes")),
        StewardKey::from(<[u8; 32]>::try_from(steward).expect("32 bytes")),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use menzil_admin::{NodeKeys, OwnerKey, create_network};

    const NOW: u64 = 1_800_000_000;

    fn documents() -> (NodeCert, menzil_admin::Documents) {
        let keys = NodeKeys::generate();
        let cert = keys.issue_cert(1, NOW - 10, NOW + 1000).unwrap();
        let docs = create_network(&OwnerKey::generate(), &cert, "laptop", NOW).unwrap();
        (cert, docs)
    }

    #[test]
    fn a_join_request_round_trips() {
        let (cert, _) = documents();
        let token = encode_join_request(&cert);
        assert!(token.starts_with(JOIN_PREFIX));
        assert!(!token.contains(char::is_whitespace));
        assert_eq!(decode_join_request(&token).unwrap(), cert);
        // Pasting brings a newline, or a space, along.
        assert_eq!(decode_join_request(&format!("  {token}\n")).unwrap(), cert);
    }

    #[test]
    fn a_membership_token_round_trips_both_documents() {
        let (_, docs) = documents();
        let token = encode_documents(&docs);
        assert!(token.starts_with(DOCS_PREFIX));
        let back = decode_documents(&token).unwrap();
        assert_eq!(back.roster(), docs.roster());
        assert_eq!(back.policy(), docs.policy());
        assert!(back.base().is_none());
        // The bytes are version 1, as they always were for documents the owner signed.
        assert_eq!(documents_to_bytes(&docs)[0], 1);
    }

    #[test]
    fn the_wrong_kind_of_token_says_so() {
        let (cert, docs) = documents();
        let join = encode_join_request(&cert);
        let membership = encode_documents(&docs);
        match decode_documents(&join) {
            Err(TokenError::WrongKind { expected, hint }) => {
                assert_eq!(expected, DOCS_PREFIX);
                assert!(hint.contains("other kind"));
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            decode_join_request(&membership),
            Err(TokenError::WrongKind { hint, .. }) if hint.contains("other kind")
        ));
        assert!(matches!(
            decode_join_request("hello"),
            Err(TokenError::WrongKind { hint: "", .. })
        ));
    }

    #[test]
    fn damaged_tokens_are_refused_not_misread() {
        let (cert, docs) = documents();
        let join = encode_join_request(&cert);
        let membership = encode_documents(&docs);
        // Cut off, or with a character that is not base64url.
        assert_eq!(
            decode_join_request(&format!("{JOIN_PREFIX}!!!")),
            Err(TokenError::BadBase64)
        );
        assert!(decode_join_request(&join[..join.len() - 7]).is_err());
        assert!(decode_documents(&membership[..membership.len() - 7]).is_err());
        // Valid base64url of something else.
        for body in ["", "AAAA", "AQAAAAA"] {
            assert!(
                matches!(
                    decode_documents(&format!("{DOCS_PREFIX}{body}")),
                    Err(TokenError::Malformed(_))
                ),
                "{body}"
            );
        }
        // A roster length that points past the end.
        let mut bytes = vec![1u8];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend_from_slice(b"short");
        let token = format!("{DOCS_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
        assert_eq!(
            decode_documents(&token).unwrap_err(),
            TokenError::Malformed("pair of documents")
        );
        // Either document longer than a verifier accepts is refused by its size, before it is
        // looked at (the whole token may still be under the limit of two).
        for (roster_len, policy_len) in [(MAX_DOC_BYTES + 1, 10), (10, MAX_DOC_BYTES + 1)] {
            let mut bytes = vec![1u8];
            bytes.extend_from_slice(&(roster_len as u32).to_be_bytes());
            bytes.extend_from_slice(&vec![0u8; roster_len + policy_len]);
            let token = format!("{DOCS_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
            assert_eq!(
                decode_documents(&token).unwrap_err(),
                TokenError::Malformed("pair of documents"),
                "{roster_len} and {policy_len}"
            );
        }
        // The wrong version byte.
        let mut other = URL_SAFE_NO_PAD
            .decode(membership.strip_prefix(DOCS_PREFIX).unwrap())
            .unwrap();
        other[0] = 2;
        let token = format!("{DOCS_PREFIX}{}", URL_SAFE_NO_PAD.encode(other));
        assert!(matches!(
            decode_documents(&token),
            Err(TokenError::Malformed(_))
        ));
    }

    /// The fourth red-team round, N5: `-` read all of standard input before any length check.
    #[test]
    fn a_token_is_read_from_a_stream_up_to_its_length_and_no_further() {
        use std::io::Read;
        // A counting reader over far more than any token: the reading stops near the limit.
        struct Counting<R>(R, std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl<R: Read> Read for Counting<R> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(buf)?;
                self.1.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
                Ok(n)
            }
        }
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let enormous = Counting(
            std::io::repeat(b'A').take(4 * MAX_TOKEN_CHARS as u64),
            count.clone(),
        );
        let error = format!("{:#}", read_token(enormous).unwrap_err());
        assert!(error.contains("more than any token"), "{error}");
        let read = count.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            read <= MAX_TOKEN_CHARS + 64 + 1 + 64 * 1024,
            "read {read} bytes of {}",
            4 * MAX_TOKEN_CHARS
        );

        // A token with its newline, and spaces around it, is read and trimmed.
        assert_eq!(
            read_token(&b"  menzil1-join:abc \r\n"[..]).unwrap(),
            "menzil1-join:abc"
        );
        // The longest token is not refused.
        let longest = vec![b'A'; MAX_TOKEN_CHARS];
        assert_eq!(read_token(&longest[..]).unwrap().len(), MAX_TOKEN_CHARS);
        // Nothing, and what is not text, are errors of their own.
        assert_eq!(read_token(&b""[..]).unwrap(), "");
        assert!(read_token(&[0xff, 0xfe][..]).is_err());
    }

    #[test]
    fn an_enormous_token_is_refused_before_it_is_decoded() {
        let text = format!("{JOIN_PREFIX}{}", "A".repeat(MAX_TOKEN_CHARS + 1));
        assert_eq!(decode_join_request(&text), Err(TokenError::TooLong));
    }

    /// Documents a steward signed, with the owner signed pair they were made from.
    fn steward_documents() -> menzil_admin::Documents {
        let owner = OwnerKey::generate();
        let cert = NodeKeys::generate()
            .issue_cert(1, NOW - 10, NOW + 1000)
            .unwrap();
        let docs = create_network(&owner, &cert, "laptop", NOW).unwrap();
        let steward = menzil_admin::StewardSecret::generate();
        let listed = menzil_admin::delegate_steward(
            &owner,
            &docs,
            steward.public(),
            &["renew".to_string()],
            NOW + 1000,
            NOW,
        )
        .unwrap();
        menzil_admin::steward_renew(&steward, &listed, NOW + 1).unwrap()
    }

    #[test]
    fn documents_a_steward_signed_travel_with_their_base_as_version_two() {
        let docs = steward_documents();
        assert!(docs.base().is_some());
        let bytes = documents_to_bytes(&docs);
        assert_eq!(bytes[0], 2);
        let back = documents_from_bytes(&bytes).unwrap();
        assert_eq!(back.roster(), docs.roster());
        assert_eq!(back.policy(), docs.policy());
        assert_eq!(back.base(), docs.base());
        assert_eq!(back.verify().unwrap(), docs.verify().unwrap());
        let token = encode_documents(&docs);
        assert_eq!(decode_documents(&token).unwrap().base(), docs.base());
        // Every cut-off of the payload is refused, never read as something shorter.
        for len in 0..bytes.len() {
            assert!(documents_from_bytes(&bytes[..len]).is_err(), "{len}");
        }
        // A part that claims more than a verifier accepts, or more than there is.
        let mut oversize = bytes.clone();
        oversize[1..5].copy_from_slice(&(MAX_DOC_BYTES as u32 + 1).to_be_bytes());
        assert_eq!(
            documents_from_bytes(&oversize).unwrap_err(),
            TokenError::Malformed("pair of documents")
        );
        // A base of another network is not a pair.
        let (_, other) = documents();
        let mut mixed = vec![2u8];
        for part in [
            docs.roster().encode(),
            docs.policy().encode(),
            other.roster().encode(),
        ] {
            push_part(&mut mixed, &part);
        }
        mixed.extend_from_slice(&other.policy().encode());
        assert_eq!(
            documents_from_bytes(&mixed).unwrap_err(),
            TokenError::Malformed("pair of documents")
        );
        // Version 3 does not exist.
        let mut future = bytes;
        future[0] = 3;
        assert!(documents_from_bytes(&future).is_err());
        // A token of the owner's own documents is still version 1, and carries no base.
        let (_, owner_docs) = documents();
        assert_eq!(documents_to_bytes(&owner_docs)[0], 1);
    }

    #[test]
    fn a_relay_token_carries_the_base_of_a_steward_roster() {
        let docs = steward_documents();
        let (base, _) = docs.base().unwrap();
        let token = encode_roster(docs.roster(), Some(base));
        let (roster, got) = decode_roster(&token).unwrap();
        assert_eq!(&roster, docs.roster());
        assert_eq!(got.as_ref(), Some(base));
        // Without a base it is the Roster's own encoding, as it always was.
        let plain = encode_roster(docs.roster(), None);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(plain.strip_prefix(ROSTER_PREFIX).unwrap())
                .unwrap(),
            docs.roster().encode()
        );
        assert_eq!(
            decode_roster(&plain).unwrap(),
            (docs.roster().clone(), None)
        );
        // Cut-off or padded payloads are refused.
        let bytes = roster_to_bytes(docs.roster(), Some(base));
        assert_eq!(bytes[0], 2);
        for len in 0..bytes.len() {
            assert!(roster_from_bytes(&bytes[..len]).is_err(), "{len}");
        }
        let mut padded = bytes;
        padded.push(0);
        assert!(roster_from_bytes(&padded).is_err());
        // The full membership token is still not a relay token, the Policy being in it.
        assert!(matches!(
            decode_roster(&encode_documents(&docs)),
            Err(TokenError::WrongKind { hint, .. }) if hint.contains("Policy")
        ));
    }

    #[test]
    fn a_steward_request_names_a_network_and_a_public_key_and_nothing_else() {
        let (network, steward) = (NetworkId::from([7u8; 32]), StewardKey::from([9u8; 32]));
        let token = encode_steward_request(network, steward);
        assert!(token.starts_with(STEWARD_PREFIX) && !token.contains(char::is_whitespace));
        assert_eq!(decode_steward_request(&token).unwrap(), (network, steward));
        assert_eq!(
            decode_steward_request(&format!(" {token}\n")).unwrap(),
            (network, steward)
        );
        // Wrong lengths, wrong version, other kinds.
        let bytes = URL_SAFE_NO_PAD
            .decode(token.strip_prefix(STEWARD_PREFIX).unwrap())
            .unwrap();
        assert_eq!(bytes.len(), 65);
        for bad in [
            &bytes[..64],
            &bytes[..1],
            &bytes[1..],
            &[bytes.clone(), vec![0]].concat()[..],
        ] {
            assert_eq!(
                decode_steward_request(&format!("{STEWARD_PREFIX}{}", URL_SAFE_NO_PAD.encode(bad))),
                Err(TokenError::Malformed("steward request"))
            );
        }
        let mut v2 = bytes;
        v2[0] = 2;
        assert!(
            decode_steward_request(&format!("{STEWARD_PREFIX}{}", URL_SAFE_NO_PAD.encode(v2)))
                .is_err()
        );
        let (cert, docs) = documents();
        for other in [
            encode_join_request(&cert),
            encode_documents(&docs),
            encode_roster(docs.roster(), None),
        ] {
            assert!(matches!(
                decode_steward_request(&other),
                Err(TokenError::WrongKind { hint, .. }) if hint.contains("other kind")
            ));
        }
        // And the other way round: each kind points at the others.
        assert!(matches!(
            decode_join_request(&token),
            Err(TokenError::WrongKind { hint, .. }) if hint.contains("other kind")
        ));
        assert!(matches!(
            decode_documents(&token),
            Err(TokenError::WrongKind { hint, .. }) if hint.contains("other kind")
        ));
        assert!(matches!(
            decode_roster(&token),
            Err(TokenError::WrongKind { hint, .. }) if hint.contains("other kind")
        ));
    }
}
