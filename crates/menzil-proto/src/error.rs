//! This crate's own `Result` error type, and the L3 `ERROR` record's code
//! registry (protocol.md 4.2: "Error codes are a registry in
//! `menzil-proto`").

use serde::de::{Deserialize, Deserializer};
use serde::ser::{Serialize, Serializer};
use thiserror::Error;

use crate::strict::StrictCborError;

/// Failure from encoding, decoding, or verifying a menzil wire value.
#[derive(Debug, Error)]
pub enum ProtoError {
    /// CBOR encoding failed.
    #[error("cbor encode failed: {0}")]
    Encode(String),
    /// CBOR decoding failed (including `deny_unknown_fields` and
    /// duplicate-field rejections from serde_derive).
    #[error("cbor decode failed: {0}")]
    Decode(String),
    /// The raw structural scan in [`crate::strict`] rejected the bytes
    /// before typed decoding was attempted.
    #[error("strict cbor check failed: {0}")]
    Strict(#[from] StrictCborError),
    /// Ed25519 signature verification failed.
    #[error("signature verification failed: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
    /// An L3 record's leading type byte did not match any entry in the
    /// protocol.md 4.2 table.
    #[error("unknown record type byte {0:#04x}")]
    UnknownRecordType(u8),
    /// An L4 frame's leading tag byte matched none of `init`/`resp`/`data`
    /// (protocol.md 5.1).
    #[error("unknown L4 frame tag byte {0:#04x}")]
    UnknownE2eFrameTag(u8),
    /// An L4 `data` frame's `kind` byte matched none of MUX/DGRAM/CLOSE/
    /// KEEP/REKEY (protocol.md 5.2). Per protocol.md 9, the caller must
    /// treat this as session-ending, not tolerate it the way an unknown
    /// L3 record type is tolerated.
    #[error("unknown L4 data record kind byte {0:#04x}")]
    UnknownE2eDataKind(u8),
    /// A record's fixed-layout (non-CBOR) fields did not fit the bytes
    /// available.
    #[error("malformed record: {0}")]
    MalformedRecord(String),
}

/// The L3 `ERROR` record's `code: u16` registry (protocol.md 4.2, plus
/// `unknown_type` from section 9). Numeric values are this crate's own
/// assignment: the spec names the codes but leaves numbering to us.
/// `Unknown` preserves a code this build doesn't recognize instead of
/// failing to decode it, so a future addition to the registry doesn't
/// break an older peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `bad_cert`: a NodeCert failed to verify.
    BadCert,
    /// `stale_serial`: a NodeCert serial was not higher than one already seen.
    StaleSerial,
    /// `stale_timestamp`: a HELLO timestamp did not advance.
    StaleTimestamp,
    /// `unknown_network`: the claimed network has no Roster here.
    UnknownNetwork,
    /// `not_member`: the node is not listed in the network's Roster.
    NotMember,
    /// `revoked`: the node is listed as revoked.
    Revoked,
    /// `roster_expired`: the network's Roster has passed its `expires`.
    RosterExpired,
    /// `forbidden`: no Roster permits this forwarding.
    Forbidden,
    /// `peer_offline`: the destination is not attached.
    PeerOffline,
    /// `unknown_e2e`: the claimed `e2e_proto` tag is not recognized.
    UnknownE2e,
    /// `credit_exceeded`: a reliable SEND exceeded granted credit.
    CreditExceeded,
    /// `too_large`: a record or document exceeded its size limit.
    TooLarge,
    /// `rate_limited`: a limit in protocol.md section 10 was exceeded.
    RateLimited,
    /// `label_taken`: an advertised name is already claimed.
    LabelTaken,
    /// `label_unclaimed`: an advertised name is not claimed by this node.
    LabelUnclaimed,
    /// `bad_invite`: an Invite failed to verify.
    BadInvite,
    /// `bad_tag`: an ADMIT_REQUEST's keyed tag did not match.
    BadTag,
    /// `unknown_type` (protocol.md section 9): an L3 record's type byte
    /// was not recognized.
    UnknownType,
    /// `no_grant` (protocol.md 5.1): an L4 CLOSE sent right after the
    /// handshake because the responder has no grant for the initiator.
    NoGrant,
    /// `grant_removed` (protocol.md 5.3): an L5 stream or channel closed
    /// because the grant that authorized it no longer exists.
    GrantRemoved,
    /// `invalid_target` (protocol.md 5.3): an OPEN named a non-null
    /// `target` for a `service` other than `egress:*`, which the spec
    /// states is never valid ("`target` must be null unless `service` is
    /// `egress:*`"). Not named by the spec as a literal OPEN_ACK string
    /// (menzil-proto's own `stream` module doc comment leaves this check,
    /// and so its refusal code, to TODO.md L4g); this crate assigns it a
    /// number the same way it does for every other code in this registry.
    InvalidTarget,
    /// `unknown_service` (protocol.md 5.3): an OPEN named a service this
    /// node does not serve. Answered only to a peer whose grant covers the
    /// service, so it tells a member nothing about services it could not
    /// have asked for; a service that is configured but whose local target
    /// cannot be reached is [`Self::TargetUnreachable`] instead.
    UnknownService,
    /// `target_unreachable` (protocol.md 5.3): the node serves the service
    /// but could not connect to its configured local target (refused,
    /// unreachable, or no answer within the node's connect timeout). May be
    /// transient: retrying later can succeed.
    TargetUnreachable,
    /// `shutting_down` (protocol.md 5.2): an L4 CLOSE a node sends on each of its
    /// sessions when it stops on purpose, so that its peers end the session and
    /// reset its streams at once instead of waiting for the dead peer timeout. A
    /// new session works as soon as the node is back.
    ShuttingDown,
    /// `bad_document` (protocol.md 4.2): a Roster or Policy offered to a node or a relay did
    /// not decode, did not verify, broke a steward rule (section 2.3) or did not pair with its
    /// Roster. The local log keeps the detail; the peer is told this and nothing more.
    BadDocument,
    /// `docs_only` (protocol.md 5.1): the L4 CLOSE of a session that was admitted only to push
    /// documents (`menzil:docs`), sent once the push is answered or its time has run out.
    DocsOnly,
    /// A code this build does not recognize, preserved verbatim.
    Unknown(u16),
}

impl ErrorCode {
    const BAD_CERT: u16 = 1;
    const STALE_SERIAL: u16 = 2;
    const STALE_TIMESTAMP: u16 = 3;
    const UNKNOWN_NETWORK: u16 = 4;
    const NOT_MEMBER: u16 = 5;
    const REVOKED: u16 = 6;
    const ROSTER_EXPIRED: u16 = 7;
    const FORBIDDEN: u16 = 8;
    const PEER_OFFLINE: u16 = 9;
    const UNKNOWN_E2E: u16 = 10;
    const CREDIT_EXCEEDED: u16 = 11;
    const TOO_LARGE: u16 = 12;
    const RATE_LIMITED: u16 = 13;
    const LABEL_TAKEN: u16 = 14;
    const LABEL_UNCLAIMED: u16 = 15;
    const BAD_INVITE: u16 = 16;
    const BAD_TAG: u16 = 17;
    const UNKNOWN_TYPE: u16 = 18;
    const NO_GRANT: u16 = 19;
    const GRANT_REMOVED: u16 = 20;
    const INVALID_TARGET: u16 = 21;
    const UNKNOWN_SERVICE: u16 = 22;
    const TARGET_UNREACHABLE: u16 = 23;
    const SHUTTING_DOWN: u16 = 24;
    const BAD_DOCUMENT: u16 = 25;
    const DOCS_ONLY: u16 = 26;

    /// The symbolic name from protocol.md, e.g. `"bad_cert"`.
    pub fn name(self) -> &'static str {
        match self {
            Self::BadCert => "bad_cert",
            Self::StaleSerial => "stale_serial",
            Self::StaleTimestamp => "stale_timestamp",
            Self::UnknownNetwork => "unknown_network",
            Self::NotMember => "not_member",
            Self::Revoked => "revoked",
            Self::RosterExpired => "roster_expired",
            Self::Forbidden => "forbidden",
            Self::PeerOffline => "peer_offline",
            Self::UnknownE2e => "unknown_e2e",
            Self::CreditExceeded => "credit_exceeded",
            Self::TooLarge => "too_large",
            Self::RateLimited => "rate_limited",
            Self::LabelTaken => "label_taken",
            Self::LabelUnclaimed => "label_unclaimed",
            Self::BadInvite => "bad_invite",
            Self::BadTag => "bad_tag",
            Self::UnknownType => "unknown_type",
            Self::NoGrant => "no_grant",
            Self::GrantRemoved => "grant_removed",
            Self::InvalidTarget => "invalid_target",
            Self::UnknownService => "unknown_service",
            Self::TargetUnreachable => "target_unreachable",
            Self::ShuttingDown => "shutting_down",
            Self::BadDocument => "bad_document",
            Self::DocsOnly => "docs_only",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl From<ErrorCode> for u16 {
    fn from(code: ErrorCode) -> u16 {
        match code {
            ErrorCode::BadCert => ErrorCode::BAD_CERT,
            ErrorCode::StaleSerial => ErrorCode::STALE_SERIAL,
            ErrorCode::StaleTimestamp => ErrorCode::STALE_TIMESTAMP,
            ErrorCode::UnknownNetwork => ErrorCode::UNKNOWN_NETWORK,
            ErrorCode::NotMember => ErrorCode::NOT_MEMBER,
            ErrorCode::Revoked => ErrorCode::REVOKED,
            ErrorCode::RosterExpired => ErrorCode::ROSTER_EXPIRED,
            ErrorCode::Forbidden => ErrorCode::FORBIDDEN,
            ErrorCode::PeerOffline => ErrorCode::PEER_OFFLINE,
            ErrorCode::UnknownE2e => ErrorCode::UNKNOWN_E2E,
            ErrorCode::CreditExceeded => ErrorCode::CREDIT_EXCEEDED,
            ErrorCode::TooLarge => ErrorCode::TOO_LARGE,
            ErrorCode::RateLimited => ErrorCode::RATE_LIMITED,
            ErrorCode::LabelTaken => ErrorCode::LABEL_TAKEN,
            ErrorCode::LabelUnclaimed => ErrorCode::LABEL_UNCLAIMED,
            ErrorCode::BadInvite => ErrorCode::BAD_INVITE,
            ErrorCode::BadTag => ErrorCode::BAD_TAG,
            ErrorCode::UnknownType => ErrorCode::UNKNOWN_TYPE,
            ErrorCode::NoGrant => ErrorCode::NO_GRANT,
            ErrorCode::GrantRemoved => ErrorCode::GRANT_REMOVED,
            ErrorCode::InvalidTarget => ErrorCode::INVALID_TARGET,
            ErrorCode::UnknownService => ErrorCode::UNKNOWN_SERVICE,
            ErrorCode::TargetUnreachable => ErrorCode::TARGET_UNREACHABLE,
            ErrorCode::ShuttingDown => ErrorCode::SHUTTING_DOWN,
            ErrorCode::BadDocument => ErrorCode::BAD_DOCUMENT,
            ErrorCode::DocsOnly => ErrorCode::DOCS_ONLY,
            ErrorCode::Unknown(code) => code,
        }
    }
}

impl From<u16> for ErrorCode {
    fn from(code: u16) -> Self {
        match code {
            Self::BAD_CERT => Self::BadCert,
            Self::STALE_SERIAL => Self::StaleSerial,
            Self::STALE_TIMESTAMP => Self::StaleTimestamp,
            Self::UNKNOWN_NETWORK => Self::UnknownNetwork,
            Self::NOT_MEMBER => Self::NotMember,
            Self::REVOKED => Self::Revoked,
            Self::ROSTER_EXPIRED => Self::RosterExpired,
            Self::FORBIDDEN => Self::Forbidden,
            Self::PEER_OFFLINE => Self::PeerOffline,
            Self::UNKNOWN_E2E => Self::UnknownE2e,
            Self::CREDIT_EXCEEDED => Self::CreditExceeded,
            Self::TOO_LARGE => Self::TooLarge,
            Self::RATE_LIMITED => Self::RateLimited,
            Self::LABEL_TAKEN => Self::LabelTaken,
            Self::LABEL_UNCLAIMED => Self::LabelUnclaimed,
            Self::BAD_INVITE => Self::BadInvite,
            Self::BAD_TAG => Self::BadTag,
            Self::UNKNOWN_TYPE => Self::UnknownType,
            Self::NO_GRANT => Self::NoGrant,
            Self::GRANT_REMOVED => Self::GrantRemoved,
            Self::INVALID_TARGET => Self::InvalidTarget,
            Self::UNKNOWN_SERVICE => Self::UnknownService,
            Self::TARGET_UNREACHABLE => Self::TargetUnreachable,
            Self::SHUTTING_DOWN => Self::ShuttingDown,
            Self::BAD_DOCUMENT => Self::BadDocument,
            Self::DOCS_ONLY => Self::DocsOnly,
            other => Self::Unknown(other),
        }
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        u16::from(*self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        u16::deserialize(deserializer).map(ErrorCode::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_code_round_trips_through_u16() {
        let codes = [
            ErrorCode::BadCert,
            ErrorCode::StaleSerial,
            ErrorCode::StaleTimestamp,
            ErrorCode::UnknownNetwork,
            ErrorCode::NotMember,
            ErrorCode::Revoked,
            ErrorCode::RosterExpired,
            ErrorCode::Forbidden,
            ErrorCode::PeerOffline,
            ErrorCode::UnknownE2e,
            ErrorCode::CreditExceeded,
            ErrorCode::TooLarge,
            ErrorCode::RateLimited,
            ErrorCode::LabelTaken,
            ErrorCode::LabelUnclaimed,
            ErrorCode::BadInvite,
            ErrorCode::BadTag,
            ErrorCode::UnknownType,
            ErrorCode::NoGrant,
            ErrorCode::GrantRemoved,
            ErrorCode::InvalidTarget,
            ErrorCode::UnknownService,
            ErrorCode::TargetUnreachable,
            ErrorCode::ShuttingDown,
            ErrorCode::BadDocument,
            ErrorCode::DocsOnly,
        ];
        for code in codes {
            let wire: u16 = code.into();
            assert_eq!(ErrorCode::from(wire), code);
        }
    }

    #[test]
    fn the_serving_codes_keep_their_numbers_and_names() {
        // Wire values: a peer built from another checkout must read these the same.
        assert_eq!(u16::from(ErrorCode::UnknownService), 22);
        assert_eq!(u16::from(ErrorCode::TargetUnreachable), 23);
        assert_eq!(ErrorCode::UnknownService.name(), "unknown_service");
        assert_eq!(ErrorCode::TargetUnreachable.name(), "target_unreachable");
    }

    #[test]
    fn shutting_down_keeps_its_number_and_name() {
        assert_eq!(u16::from(ErrorCode::ShuttingDown), 24);
        assert_eq!(ErrorCode::from(24), ErrorCode::ShuttingDown);
        assert_eq!(ErrorCode::ShuttingDown.name(), "shutting_down");
    }

    #[test]
    fn the_document_codes_keep_their_numbers_and_names() {
        assert_eq!(u16::from(ErrorCode::BadDocument), 25);
        assert_eq!(ErrorCode::from(25), ErrorCode::BadDocument);
        assert_eq!(ErrorCode::BadDocument.name(), "bad_document");
        assert_eq!(u16::from(ErrorCode::DocsOnly), 26);
        assert_eq!(ErrorCode::from(26), ErrorCode::DocsOnly);
        assert_eq!(ErrorCode::DocsOnly.name(), "docs_only");
    }

    #[test]
    fn unrecognized_code_round_trips_as_unknown() {
        let wire: u16 = 65000;
        assert_eq!(ErrorCode::from(wire), ErrorCode::Unknown(wire));
        assert_eq!(u16::from(ErrorCode::Unknown(wire)), wire);
    }

    #[test]
    fn error_code_serializes_as_plain_u16() {
        let mut buf = Vec::new();
        ciborium::into_writer(&ErrorCode::BadCert, &mut buf).unwrap();
        let mut expected = Vec::new();
        ciborium::into_writer(&1u16, &mut expected).unwrap();
        assert_eq!(buf, expected);
    }
}
