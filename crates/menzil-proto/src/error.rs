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
        ];
        for code in codes {
            let wire: u16 = code.into();
            assert_eq!(ErrorCode::from(wire), code);
        }
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
