//! Wire types, framing, and signing for the menzil protocol.
//!
//! This crate defines the identities and owner-signed documents
//! (`NodeCert`, `Roster`, `Policy`, `Invite`, `Steward`), the Noise
//! handshake payloads HELLO and WELCOME, the service naming scheme, the
//! L3 relay-session record framing, the L4 end to end session and L5
//! stream-opening wire formats, and the shared error registry, all per
//! `docs/spec/protocol.md` sections 1, 2, 4.1, 4.2, 4.4, 5, and 7.2. It
//! has no transport or async runtime dependencies (in particular, no
//! `snow` and no yamux): it only describes bytes on the wire, how they
//! are signed and verified, and the identifiers used to route them.
//! Sessions, timeouts, rate limits, forwarding decisions, and actually
//! running a Noise handshake or a mux belong to the relay, node, and (for
//! L4/L5) the not-yet-built `menzil-e2e`/`menzil-stream` crates.

#![forbid(unsafe_code)]

mod bytes;
mod doc;
mod e2e;
mod error;
mod handshake;
mod identity;
mod invite;
mod network;
mod record;
mod service;
mod signed;
mod stream;
mod strict;

pub use bytes::{
    ByteArray, DocId, InviteId, NetworkId, NodeId, SecretHash, StewardKey, Tai64N, X25519PublicKey,
};
pub use doc::{
    DocReassembler, DocReassemblyError, MAX_DOC_BYTES, MAX_DOC_CHUNK_BYTES, split_into_doc_records,
};
pub use e2e::{
    E2eDataBody, E2eDataKind, E2eFrame, E2eFrameTag, E2eHandshakePayload, RecordClass,
    e2e_data_frame_len, max_e2e_data_plaintext,
};
pub use error::{ErrorCode, ProtoError};
pub use handshake::{Capability, HelloBody, Limits, WelcomeBody};
pub use identity::{NodeCert, NodeCertBody};
pub use invite::{
    AdmitPendingBody, AdmitRequestBody, Invite, InviteBody, compute_admit_tag, hash_invite_secret,
};
pub use network::{
    AcceptEntry, EgressRule, Grant, HostPortPattern, Label, NodeOrWildcard, Policy, PolicyBody,
    PolicyMember, Principal, PrincipalTarget, RevokedMember, Roster, RosterBody, RosterMember,
    Steward, StewardBody,
};
pub use record::{
    Addr, AdmitResult, AdvertiseAckBody, AdvertiseBody, CreditBody, DocBody, DocType, ErrorBody,
    GoawayBody, L3_AEAD_TAG_LEN, MIN_SEND_CHARGE_BYTES, PeerStateBody, Record, RecordType,
    RejectedShare, Share, ShareMode, max_send_payload,
};
pub use service::{
    ServiceId, ServiceIdParseError, ServiceKind, ServicePattern, UnknownServiceKind,
};
pub use signed::{Signed, SignedBody};
pub use stream::{OpenAckBody, OpenBody, OpenMeta, OpenTarget};

/// Current wire protocol version, bumped whenever the framing format
/// changes in a way that is not backward compatible.
pub const PROTOCOL_VERSION: u16 = 1;
