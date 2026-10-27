//! What an owner or steward does with a network's documents, and what a
//! node does to get an identity: no I/O, no clock, no files (those belong to
//! the command line that calls this).
//!
//! * [`NodeKeys`]: the secret material of a node (its Ed25519 identity key
//!   and its X25519 Noise key) and the [`NodeCert`](menzil_proto::NodeCert)
//!   that binds them (protocol.md 2.2). A node makes this once, `menzil
//!   init`, and sends the certificate to whoever admits it.
//! * [`OwnerKey`]: the key a network is named after (protocol.md 2.3: the
//!   NetworkId *is* the owner's public key).
//! * [`Documents`], [`create_network`], [`admit`], [`grant`], [`renew`]:
//!   the owner-signed [`Roster`](menzil_proto::Roster) and
//!   [`Policy`](menzil_proto::Policy) pair, and the operations that issue
//!   its successor (protocol.md 2.3, 7.1, 7.3). Every operation returns a new
//!   pair with `seq + 1`, signed by the owner, and leaves the old one alone;
//!   the clock is a parameter.
//!
//! * [`accept_cert`]: the owner lists a member's renewed certificate (protocol.md 2.2),
//!   [`NodeKeys::next_cert`] makes it.
//!
//! * [`revoke`], [`remove_grants`]: the owner takes a node out of the network for good (protocol.md
//!   7.3: always as a revocation, because a steward could admit a merely removed node again) or
//!   takes grants out of the Policy.
//!
//! * [`StewardSecret`], [`delegate_steward`], [`remove_steward`], [`steward_renew`],
//!   [`steward_admit`]: a steward (protocol.md 2.3, 7.3) signs re-issues and admissions with
//!   its own key; its pair travels with the owner signed base it was made from, and the owner's
//!   next pair jumps 2^20 past that base ([`Documents::next_owner_seq`]). What a steward
//!   issues is judged by `menzil_proto::trust::check_bundle`, the same predicate every verifier
//!   runs, before it is returned.
//!
//! What is checked here is what the issuer is responsible for and the types
//! do not enforce: a joining certificate must verify against its own NodeId,
//! be valid now and not for longer than 400 days, a revoked node is not admitted again,
//! names must be unique (letter case aside) and usable as the first part of a
//! `name/service` address, a grant must name members, a document must fit
//! the size every verifier accepts, and its lifetime is at most 14 days.

#![forbid(unsafe_code)]

mod error;
mod issue;
mod keys;

pub use error::AdminError;
pub use issue::{
    DOCUMENT_LIFETIME_SECS, Documents, accept_cert, admit, check_name, check_role, create_network,
    delegate_steward, grant, is_invisible, is_unsafe, remove_grants, remove_steward, renew, revoke,
    steward_admit, steward_renew,
};
pub use keys::{MAX_CERT_LIFETIME_SECS, NodeKeys, OwnerKey, StewardSecret};
pub use menzil_proto::trust::{STEWARD_MAX_LIFETIME, STEWARD_SEQ_SPAN};
