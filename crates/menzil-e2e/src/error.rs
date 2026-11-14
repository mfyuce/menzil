//! Errors from driving the L4 handshake or transport in this crate.

use thiserror::Error;

/// Everything that can go wrong in this crate.
#[derive(Debug, Error)]
pub enum E2eError {
    /// The underlying Noise handshake or transport cipher failed (bad
    /// input, decryption failure, wrong turn, exhausted nonce space, and
    /// so on — see `snow::Error`'s own variants).
    #[error("noise error: {0}")]
    Noise(#[from] snow::Error),
    /// An [`menzil_proto::E2eFrame`], [`menzil_proto::E2eHandshakePayload`]
    /// or [`menzil_proto::E2eDataBody`] failed to encode or decode.
    #[error("proto error: {0}")]
    Proto(#[from] menzil_proto::ProtoError),
    /// [`crate::handshake::E2eInitiatorHandshake::finish`] was called on a
    /// handshake that an authenticated `resp` already completed (or
    /// consumed): its Noise state is gone and cannot be reused.
    #[error("the initiator handshake already consumed an authenticated resp")]
    HandshakeSpent,
    /// A caller passed an [`menzil_proto::E2eFrame`] variant other than
    /// the one a given step expects (e.g. a `Resp` where an `Init` was
    /// required).
    #[error("expected an E2E {expected} frame, got a different one")]
    UnexpectedFrame {
        /// The frame kind that was expected, for a human-readable error.
        expected: &'static str,
    },
    /// Message 1 decrypted to a non-empty payload. protocol.md 5.1 is
    /// explicit that "there is no application data in message 1"; a
    /// compliant initiator ([`crate::handshake::E2eInitiatorHandshake`])
    /// never sends one, so a non-empty payload here means a non-compliant
    /// or malicious peer.
    #[error("message 1 carried a non-empty payload, which protocol.md 5.1 never allows")]
    UnexpectedHandshakePayload,
    /// [`crate::handshake::E2eInitiatorHandshake::finish`]'s `resp` carried
    /// a `receiver_index` other than the `sender_index` this handshake
    /// actually sent in `init` — either a misrouted response or a
    /// confused/malicious peer, never a valid continuation of this
    /// handshake.
    #[error("resp echoed index {actual}, expected {expected}")]
    EchoedIndexMismatch {
        /// The `sender_index` this handshake sent in `init`.
        expected: u32,
        /// The `receiver_index` the `resp` frame actually carried.
        actual: u32,
    },
    /// A caller tried to [`crate::E2eTransport::encrypt_data`] an
    /// [`menzil_proto::E2eDataBody::Dgram`] body: the datagram class
    /// (protocol.md 5.2's top counter bit) has no working send or
    /// receive path in this crate; see [`crate`]'s own doc comment for
    /// why. Phase 2, TODO.md. A purely local refusal — nothing was sent,
    /// no session exists to end, there is nothing to drop. Distinct from
    /// [`Self::UnauthenticatedDatagramCounter`], the receive-side
    /// counterpart: that one is about untrusted input and must never be
    /// treated the same way a caller treats this one.
    #[error(
        "refused to send a datagram-class body: no working send/receive path yet (protocol.md 5.4, phase 2)"
    )]
    DatagramUnsupported,
    /// An incoming `data` frame's `counter` named the datagram class
    /// (protocol.md 5.2's top bit). [`crate::E2eTransport::decrypt_data`]
    /// refuses it *before* attempting decryption — see
    /// [`crate::transport`]'s doc comment — so this can be produced by
    /// pure guesswork, no key required. **Not session-fatal: drop the
    /// frame and continue, the same as any other frame that fails to
    /// authenticate.** Treating this the same as
    /// [`Self::ReliableContiguityViolation`] or
    /// [`Self::RecordClassMismatch`] (both of which only ever fire on
    /// already-authenticated input) would hand an attacker who merely
    /// knows a live `receiver_index` — 32 bits, never secret — a free
    /// way to end any session, exactly the free-DoS this crate's
    /// decrypt-before-contiguity ordering exists to prevent.
    #[error(
        "dropped an incoming datagram-class counter before attempting decryption (no replay protection exists for it yet)"
    )]
    UnauthenticatedDatagramCounter,
    /// A `data` frame decrypted and decoded successfully, landed on the
    /// expected reliable-class counter, but its *kind* belongs to the
    /// other class (in practice: an [`menzil_proto::E2eDataBody::Dgram`]
    /// body under a reliable-class counter — the reverse direction is
    /// impossible, since [`crate::E2eTransport::decrypt_data`] already
    /// refuses every datagram-class counter before decryption). Reported
    /// only for already-authenticated input, the same as
    /// [`Self::ReliableContiguityViolation`]; a compliant peer never
    /// produces this, so the caller should end the session over it
    /// (protocol.md 9's "unknown L4 kinds close the session" is the
    /// closest named case for a kind that doesn't belong where it
    /// arrived). `recv_reliable_next` is left unadvanced.
    #[error("a {kind_class:?}-class kind arrived under a {counter_class:?}-class counter")]
    RecordClassMismatch {
        /// The class the `counter` itself belongs to.
        counter_class: menzil_proto::RecordClass,
        /// The class the decoded body's own kind belongs to.
        kind_class: menzil_proto::RecordClass,
    },
    /// A body passed to [`crate::E2eTransport::encrypt_data`] encodes
    /// larger than `menzil_proto::max_e2e_data_plaintext`'s budget for
    /// the `max_record` this transport was built with — it could never
    /// actually be carried inside the L3 SEND/RECV record it would ride
    /// in (decision 0001). Refused before any counter is assigned or any
    /// encryption attempted, so nothing is consumed on this path.
    #[error("body of {len} bytes exceeds this session's {max}-byte L4 plaintext budget")]
    BodyTooLarge {
        /// The encoded body's actual length.
        len: usize,
        /// The budget it was checked against.
        max: usize,
    },
    /// [`crate::E2eTransport::encrypt_data`] refused to assign a
    /// reliable-class counter at or past `2^63`: the top bit protocol.md
    /// 5.2 uses to select the datagram class. Sending one anyway would
    /// silently produce a frame any receiver (including this crate's own
    /// `decrypt_data`) reads back as datagram-class, not reliable-class —
    /// wrong, not merely refused. Unreachable in any realistic session
    /// lifetime (REKEY fires every 2^20 records or hourly, long before
    /// this), kept as a correctness boundary rather than an assumption.
    #[error("the reliable-class counter has reached its 2^63 ceiling")]
    ReliableCounterExhausted,
    /// A peer's negotiated Noise static key was the all-zero point — the
    /// simplest X25519 low-order/degenerate key. WireGuard's own
    /// reference implementations reject exactly this value (checking
    /// their Diffie-Hellman *output* for all-zero; this crate only has
    /// safe access to the *input* public key through `snow`'s API, so it
    /// checks that instead — a narrower, defense-in-depth check, not an
    /// exhaustive small-subgroup rejection: the other seven low-order
    /// Curve25519 points are not individually enumerated here).
    /// Rejected during the handshake, before any
    /// [`crate::E2eTransport`] exists: [`menzil_proto::NodeCert`] never
    /// validates `x25519_pub` either, so without this, a malformed or
    /// malicious NodeCert could make two honest peers "negotiate" a key
    /// with no real secrecy at all.
    #[error("a peer's negotiated Noise static key was the all-zero point")]
    DegenerateStaticKey,
    /// A reliable-class `data` frame's counter was not exactly one more
    /// than the last one this side accepted (protocol.md 5.2: "any gap,
    /// duplicate or reordering ends the session and resets every
    /// stream"). Reported only for a frame that already decrypted
    /// successfully — see [`crate::transport`]'s doc comment on why that
    /// ordering matters. This type only reports the violation; ending the
    /// session is the caller's job, the same division
    /// `menzil_session::CreditLedger::consume` already draws for its own
    /// violation.
    #[error("reliable-class counter out of sequence: expected {expected}, got {actual}")]
    ReliableContiguityViolation {
        /// The only counter value that would have been accepted.
        expected: u64,
        /// The counter value the frame actually carried.
        actual: u64,
    },
    /// A datagram-class `data` frame's sequence was already received
    /// (its bit in the 2048 position replay window is set). Checked
    /// *before* any decryption. **Not session-fatal: drop it.** Free for
    /// anyone to trigger by repeating a counter.
    #[error("datagram replayed: its sequence was already received")]
    DatagramReplayed,
    /// A datagram-class `data` frame's sequence is 2048 or more behind
    /// the highest authenticated one. Checked *before* any decryption.
    /// **Not session-fatal: drop it.**
    #[error("datagram too old: 2048 or more sequences behind the window top")]
    DatagramTooOld,
    /// [`crate::E2eTransport::encrypt_dgram`] refused to assign a datagram
    /// sequence past `2^63 - 2`: sequence `2^63 - 1` would make the Noise
    /// nonce `2^64 - 1`, which Noise reserves for `Rekey()`. Nothing was
    /// sent and no counter was consumed. Unreachable in practice (REKEY
    /// fires every 2^20 records), checked rather than assumed.
    #[error("the datagram sequence has reached its 2^63 - 2 ceiling")]
    DatagramCounterExhausted,
    /// [`crate::E2eTransport::decrypt_dgram`] was given a counter of the
    /// reliable class. A routing mistake of the caller, refused before any
    /// decryption. **Not session-fatal: drop it.**
    #[error("a reliable-class counter was passed to the datagram path")]
    NotADatagramCounter,
    /// A datagram-class counter whose sequence is `2^63 - 1` (the whole
    /// counter is `u64::MAX`): the nonce Noise reserves for `Rekey()`, never
    /// produced by a compliant sender. Refused before any decryption.
    /// **Not session-fatal: drop it.**
    #[error("the reserved datagram counter 2^64 - 1 was refused before decryption")]
    ReservedDatagramCounter,
    /// A datagram payload passed to [`crate::E2eTransport::encrypt_dgram`]
    /// is larger than this session's budget
    /// ([`crate::E2eTransport::max_dgram_payload`]). Datagrams are never
    /// split; nothing was consumed.
    #[error("datagram payload of {len} bytes exceeds this session's {max}-byte budget")]
    DatagramTooLarge {
        /// The payload's length.
        len: usize,
        /// The budget it was checked against.
        max: usize,
    },
}
