//! Errors from issuing identities and documents.

use menzil_proto::{NodeId, ProtoError};
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
