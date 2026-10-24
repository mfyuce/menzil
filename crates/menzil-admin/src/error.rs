//! Errors from issuing identities and documents.

use menzil_proto::trust::Reason;
use menzil_proto::{NameError, NodeId, ProtoError};
use thiserror::Error;

/// Why an identity or a document could not be made.
#[derive(Debug, Error)]
pub enum AdminError {
    /// Encoding or signing failed, or a document would not decode.
    #[error("{0}")]
    Proto(#[from] ProtoError),
    /// Secret key bytes of the wrong length.
    #[error("a key file of this kind holds {expected} bytes, this one holds {found}")]
    BadKeyLength {
        /// The length this kind of key has.
        expected: usize,
        /// The length that was given.
        found: usize,
    },
    /// A Roster and Policy that do not belong together: other networks or
    /// other sequence numbers.
    #[error("the Roster and the Policy are not a pair: {0}")]
    MismatchedDocuments(&'static str),
    /// The documents were not signed for this owner key, so signing a
    /// successor with it would make documents nobody accepts.
    #[error("these documents belong to another network than this owner key")]
    NotThisOwner,
    /// A certificate's signature does not verify against its own NodeId, or
    /// its NodeId is not a valid key.
    #[error("the node certificate does not verify against its own node id")]
    CertDoesNotVerify,
    /// The certificate is not valid at the time of issuing.
    #[error("the node certificate is not valid now")]
    CertNotValidNow,
    /// The certificate's validity window is longer than protocol.md 2.2 allows.
    #[error("a node certificate is valid for at most 400 days, this one for longer")]
    CertLifetimeTooLong,
    /// The node is a member already.
    #[error("node {0:?} is a member of this network already")]
    AlreadyMember(NodeId),
    /// The node is on the Roster's revoked list, where it would stay whatever else is said:
    /// verifiers refuse a revoked node, a member or not.
    #[error("node {0:?} is revoked in this network")]
    Revoked(NodeId),
    /// A member name that cannot head a `name/service` address.
    #[error(
        "member name {0:?} must be 1 to 63 bytes of letters, digits, '-', '_' and '.', starting with a letter or a digit"
    )]
    BadName(String),
    /// A name of eight or more hexadecimal digits, which an address could take for the start
    /// of a node id (`menzil stdio 1a2b3c4d/ssh`).
    #[error(
        "member name {0:?} is eight or more hexadecimal digits only, which could be taken for the start of a node id"
    )]
    NameLooksLikeNodeId(String),
    /// A role that is not letters, digits, '-', '_' and '.'.
    #[error(
        "role {0:?} must be 1 to 63 bytes of letters, digits, '-', '_' and '.', starting with a letter or a digit"
    )]
    BadRole(String),
    /// Another member has the name, or one that differs from it in letter case only.
    #[error("the name {0:?} is taken")]
    NameTaken(String),
    /// A grant names a node that is not a member.
    #[error("the grant names node {0:?}, which is not a member")]
    NotAMember(NodeId),
    /// A grant for another network than the documents.
    #[error("the grant is scoped to another network")]
    ForeignGrant,
    /// A grant naming no service.
    #[error("the grant names no service")]
    EmptyGrant,
    /// The sequence number cannot go up any more.
    #[error("the sequence number is at its maximum")]
    SeqOverflow,
    /// Verifiers would refuse the documents (or documents held for a network do not stand on
    /// the owner's signature or a steward's valid one): the acceptance predicate
    /// (`menzil_proto::trust`, protocol.md 2.3) says why.
    #[error("verifiers would not accept these documents: {0:?}")]
    Rejected(Reason),
    /// A steward operation on documents whose Roster lists no steward.
    #[error("the Roster lists no steward")]
    NoSteward,
    /// The steward key is not the one the Roster lists.
    #[error("this steward key is not the one the Roster lists")]
    StewardNotListed,
    /// The public key is not a valid Ed25519 key.
    #[error("the steward key is not a valid Ed25519 public key")]
    BadStewardKey,
    /// A right that is neither `admit` nor `renew`, or none at all.
    #[error("a steward may hold the rights \"admit\" and \"renew\" and no other, at least one")]
    BadStewardRights,
    /// A `not_after` in the past, or more than 90 days away (protocol.md 7.3).
    #[error("a steward lasts from now to at most 90 days ahead")]
    BadStewardLifetime,
    /// A steward has used up the sequence numbers its base allows (protocol.md 2.3).
    #[error(
        "the steward has no sequence numbers left from its base: the owner must issue new documents"
    )]
    SeqSpanExhausted,
    /// A document would be larger than verifiers accept.
    #[error("the {what} would be {len} bytes, more than the {max} bytes verifiers accept")]
    TooLarge {
        /// Which document.
        what: &'static str,
        /// Its encoded size.
        len: usize,
        /// The limit.
        max: usize,
    },
}

impl From<NameError> for AdminError {
    fn from(error: NameError) -> Self {
        match error {
            NameError::BadName(name) => Self::BadName(name),
            NameError::NameLooksLikeNodeId(name) => Self::NameLooksLikeNodeId(name),
            NameError::BadRole(role) => Self::BadRole(role),
        }
    }
}
