//! The strings people paste between machines (TOBEDECIDED 14: phase 1 has no invites, a new
//! member is admitted by hand). Two kinds, told apart by their prefix so that pasting the wrong
//! one fails with a clear message instead of a decode error:
//!
//! * `menzil1-join:` + base64url of a NodeCert: what `menzil init` prints, what the owner pastes
//!   into `menzil admit`.
//! * `menzil1-docs:` + base64url of a Roster and a Policy ([`documents_to_bytes`]): what `menzil
//!   admit` prints, what the new member pastes into `menzil join`.
//!
//! A token carries only public, signed material. Nothing here verifies a signature; the caller
//! does, against the key the document names (an unsigned or forged token must not be trusted
//! because it decoded).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use menzil_proto::{MAX_DOC_BYTES, NodeCert, Policy, Roster};
use thiserror::Error;

/// Prefix of a join request.
pub const JOIN_PREFIX: &str = "menzil1-join:";
/// Prefix of a membership token.
pub const DOCS_PREFIX: &str = "menzil1-docs:";

/// The longest token text accepted: two documents at the size verifiers allow, base64 encoded,
/// with room for the framing. Checked before any decoding.
const MAX_TOKEN_CHARS: usize = (2 * MAX_DOC_BYTES + 16).div_ceil(3) * 4;

/// Why a pasted token was not accepted.
#[derive(Debug, Error, PartialEq, Eq)]
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
    other: &'static str,
) -> Result<&'a str, TokenError> {
    let token = token.trim();
    if let Some(rest) = token.strip_prefix(expected) {
        return Ok(rest);
    }
    let hint = if token.starts_with(other) {
        " (this is the other kind of token)"
    } else {
        ""
    };
    Err(TokenError::WrongKind { expected, hint })
}

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
    let bytes = decode_base64(strip(token, JOIN_PREFIX, DOCS_PREFIX)?)?;
    NodeCert::decode_strict(&bytes).map_err(|_| TokenError::Malformed("node certificate"))
}

/// A Roster and the Policy issued with it as one byte string: a version byte (1), the Roster's
/// encoding preceded by its length as a big endian `u32`, then the Policy's encoding. This is
/// the payload of a membership token and also the file a node keeps for each network, so the
/// pair is written and read as one unit.
pub fn documents_to_bytes(roster: &Roster, policy: &Policy) -> Vec<u8> {
    let (roster, policy) = (roster.encode(), policy.encode());
    let mut bytes = Vec::with_capacity(5 + roster.len() + policy.len());
    bytes.push(1);
    bytes.extend_from_slice(&(roster.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&roster);
    bytes.extend_from_slice(&policy);
    bytes
}

/// The pair back from [`documents_to_bytes`]. Signatures are not checked here.
pub fn documents_from_bytes(bytes: &[u8]) -> Result<(Roster, Policy), TokenError> {
    let malformed = TokenError::Malformed("pair of documents");
    let [1, a, b, c, d, rest @ ..] = bytes else {
        return Err(malformed);
    };
    let roster_len = u32::from_be_bytes([*a, *b, *c, *d]) as usize;
    if roster_len > rest.len()
        || roster_len > MAX_DOC_BYTES
        || rest.len() - roster_len > MAX_DOC_BYTES
    {
        return Err(malformed);
    }
    let (roster, policy) = rest.split_at(roster_len);
    let roster = Roster::decode_strict(roster).map_err(|_| TokenError::Malformed("Roster"))?;
    let policy = Policy::decode_strict(policy).map_err(|_| TokenError::Malformed("Policy"))?;
    Ok((roster, policy))
}

/// A membership token for a Roster and the Policy issued with it.
pub fn encode_documents(roster: &Roster, policy: &Policy) -> String {
    format!(
        "{DOCS_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(documents_to_bytes(roster, policy))
    )
}

/// The Roster and the Policy in a membership token. Signatures are not checked here.
pub fn decode_documents(token: &str) -> Result<(Roster, Policy), TokenError> {
    documents_from_bytes(&decode_base64(strip(token, DOCS_PREFIX, JOIN_PREFIX)?)?)
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
        let token = encode_documents(docs.roster(), docs.policy());
        assert!(token.starts_with(DOCS_PREFIX));
        let (roster, policy) = decode_documents(&token).unwrap();
        assert_eq!(&roster, docs.roster());
        assert_eq!(&policy, docs.policy());
    }

    #[test]
    fn the_wrong_kind_of_token_says_so() {
        let (cert, docs) = documents();
        let join = encode_join_request(&cert);
        let membership = encode_documents(docs.roster(), docs.policy());
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
        let membership = encode_documents(docs.roster(), docs.policy());
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
            decode_documents(&token),
            Err(TokenError::Malformed("pair of documents"))
        );
        // Either document longer than a verifier accepts is refused by its size, before it is
        // looked at (the whole token may still be under the limit of two).
        for (roster_len, policy_len) in [(MAX_DOC_BYTES + 1, 10), (10, MAX_DOC_BYTES + 1)] {
            let mut bytes = vec![1u8];
            bytes.extend_from_slice(&(roster_len as u32).to_be_bytes());
            bytes.extend_from_slice(&vec![0u8; roster_len + policy_len]);
            let token = format!("{DOCS_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
            assert_eq!(
                decode_documents(&token),
                Err(TokenError::Malformed("pair of documents")),
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

    #[test]
    fn an_enormous_token_is_refused_before_it_is_decoded() {
        let text = format!("{JOIN_PREFIX}{}", "A".repeat(MAX_TOKEN_CHARS + 1));
        assert_eq!(decode_join_request(&text), Err(TokenError::TooLong));
    }
}
