//! The post-handshake L4 transport (protocol.md 5.1, 5.2): encrypts and
//! decrypts [`menzil_proto::E2eDataBody`] records against explicit,
//! caller-visible counters, and applies REKEY to the Noise cipher this
//! side owns.
//!
//! **Why `snow::StatelessTransportState`, not the auto-incrementing
//! `TransportState` `menzil-session` uses for L3**: protocol.md 5.2's
//! counter is not one monotonic sequence. Its top bit splits it into two
//! classes that "both count from zero per session and per direction," so
//! the raw wire values interleave non-monotonically whenever both
//! classes are in use (a datagram-class counter's top bit alone makes it
//! numerically larger than any reliable-class counter could ever be).
//! `TransportState::write_message`/`read_message` require the nonce to
//! match an internal counter that only ever increments by exactly one
//! per call; it cannot represent that split. `StatelessTransportState`
//! takes the nonce explicitly on every call instead, so this module can
//! pass the wire `counter` straight through as the AEAD nonce, which is
//! also exactly what keeps the two classes from ever reusing a nonce
//! against each other: same cipher state, disjoint nonce spaces by
//! construction (the top bit never collides).
//!
//! **Why [`E2eTransport::decrypt_data`] checks the reliable-class
//! contiguity rule only *after* a successful decrypt, never before**:
//! this crate's own scoping pass flagged the ordering explicitly,
//! pointing at the lesson TODO.md's L3h review already taught the rest
//! of this project (`menzil-relay`'s forwarding rule, finding M2) —
//! whatever gates a *consequential* action must run on *authenticated*
//! input, not on a claim an attacker could make for free. An L4 `data`
//! frame arrives by way of a relay that forwards it blind (decision
//! 0001); nothing stops an attacker who merely knows (or guesses — it is
//! only 32 bits and never secret) a live `receiver_index` from injecting
//! a frame with an arbitrary `counter`. If the contiguity rule ran
//! before decryption, that single unauthenticated frame would already
//! satisfy protocol.md 5.2's "ends the session" clause — a free,
//! unforgeable-key-required-for-nothing denial of service against any
//! L4 session on the relay path. Running the AEAD decrypt first means
//! only a frame actually produced by the holder of the negotiated key
//! (the real peer) can ever reach the contiguity check at all; an
//! injected frame simply fails to decrypt and is dropped, same as any
//! other corrupt ciphertext, without touching the receive counter or
//! ending anything. The same reasoning is why
//! [`E2eError::UnauthenticatedDatagramCounter`] (pre-auth) must never be
//! treated the same way as [`E2eError::RecordClassMismatch`] or
//! [`E2eError::ReliableContiguityViolation`] (both post-auth) by a
//! caller: the first is free for anyone to trigger, the other two are
//! not.
//!
//! **Why REKEY is applied automatically inside [`E2eTransport::encrypt_data`]
//! and [`E2eTransport::decrypt_data`], rather than left as a separate
//! caller-driven step** (an earlier version of this module split them,
//! mirroring `menzil_session::Transport`'s decoupled
//! `rekey_outgoing`/`rekey_incoming`, which a red-team pass on *this*
//! crate flagged as a footgun specific to how REKEY is used here): a
//! REKEY body carries no information beyond its own kind byte, so
//! "send/decode a REKEY record" and "apply `Rekey()`" are never two
//! independent decisions — any caller that did the first without the
//! second would desync the two sides' ciphers with no way back short of
//! a full new handshake, and nothing about that desync is visible until
//! the *next* real record silently fails to decrypt. Coupling them
//! removes that failure mode entirely at zero cost in flexibility.
//! [`Self::rekey_outgoing`]/[`Self::rekey_incoming`] stay as small
//! private helpers rather than being inlined, purely for readability.
//!
//! **Why [`E2eTransport::decrypt_data`] cross-checks the decoded body's
//! own kind against the counter's class** (also a red-team finding on
//! this crate): the up-front check only rules out a *counter* that
//! names the datagram class; nothing stopped an authenticated peer from
//! sending an [`menzil_proto::E2eDataBody::Dgram`]-kind body *under* a
//! reliable-class counter, which `menzil_proto::E2eDataKind::class`
//! already has the information to catch — this module just wasn't
//! calling it. The reverse (a reliable-only kind under a datagram
//! counter) cannot happen, since every datagram-class counter is
//! already refused before decryption.

use menzil_proto::{E2eDataBody, E2eFrame, RecordClass};

use crate::error::E2eError;

/// Matches the Noise Protocol's own hard limit on one transport message
/// (protocol.md 5.1's cipher suite); see `menzil_session::transport`'s
/// identical constant and doc comment for the same reasoning. Distinct
/// from [`E2eTransport::max_plaintext`] (this session's own, usually
/// much smaller, L4 budget derived from WELCOME's `limits.max_record` —
/// see [`Self::encrypt_data`]'s docs): this constant is only ever used to
/// size a scratch buffer large enough for whatever Noise itself allows,
/// never as a size check in its own right.
const MAX_NOISE_MESSAGE: usize = 65_535;

/// protocol.md 5.2's top bit, past which a reliable-class counter would
/// read back as datagram-class to any receiver (including this crate's
/// own [`E2eTransport::decrypt_data`]) — see
/// [`E2eError::ReliableCounterExhausted`].
const RELIABLE_COUNTER_CEILING: u64 = 1 << 63;

/// A finished L4 Noise session: ready to encrypt outgoing
/// [`E2eDataBody`] records and decrypt incoming ones, against the
/// reliable class's contiguous counter (protocol.md 5.2). Produced by
/// [`crate::E2eInitiatorHandshake::finish`] or
/// [`crate::E2eResponderHandshake::finish`].
#[derive(Debug)]
pub struct E2eTransport {
    inner: snow::StatelessTransportState,
    /// The index this side must stamp as `receiver_index` on every
    /// outgoing `data` frame: the peer's own local index for this
    /// session (protocol.md 5.1 — the initiator's `sender_index` as the
    /// responder sees it, or the responder's `receiver_index` as the
    /// initiator sees it).
    peer_index: u32,
    /// The largest [`E2eDataBody`] plaintext (`u8 kind | body`) this
    /// session may encrypt — `menzil_proto::max_e2e_data_plaintext`
    /// applied to the `max_record` this transport was built with. See
    /// [`Self::encrypt_data`]'s docs for why this crate enforces it at
    /// all, rather than leaving it to the natural Noise failure the way
    /// `menzil_session::Transport` does for L3.
    max_plaintext: usize,
    /// The next reliable-class counter this side will assign on send.
    send_reliable_next: u64,
    /// The next reliable-class counter this side will accept on
    /// receive; both directions count from zero (protocol.md 5.2).
    recv_reliable_next: u64,
}

impl E2eTransport {
    pub(crate) fn from_finished(
        hs: snow::HandshakeState,
        peer_index: u32,
        max_record: u32,
    ) -> Result<Self, E2eError> {
        Ok(Self {
            inner: hs.into_stateless_transport_mode()?,
            peer_index,
            max_plaintext: menzil_proto::max_e2e_data_plaintext(max_record),
            send_reliable_next: 0,
            recv_reliable_next: 0,
        })
    }

    /// The peer's local index for this session; see the field's own doc
    /// comment.
    pub fn peer_index(&self) -> u32 {
        self.peer_index
    }

    /// Encrypts `body` as the next reliable-class `data` frame,
    /// returning it as a complete, ready-to-send
    /// [`E2eFrame::Data`] (`receiver_index` already set to
    /// [`Self::peer_index`]). Assigns and advances the send counter
    /// internally; the caller supplies nothing but the body. For an
    /// [`E2eDataBody::Rekey`] body, also rekeys this side's own sending
    /// cipher once the frame is actually produced — see this module's
    /// doc comment on why that is no longer a separate caller step.
    ///
    /// Refuses, without consuming a counter or encrypting anything:
    /// - an [`E2eDataBody::Dgram`] body outright
    ///   (`E2eError::DatagramUnsupported`) — no receive-side protection
    ///   exists yet for anything carried on the datagram class, see this
    ///   module's doc comment;
    /// - a body whose encoding exceeds this session's
    ///   [`Self::max_plaintext`] budget (`E2eError::BodyTooLarge`) —
    ///   `menzil_proto::max_e2e_data_plaintext`'s own doc comment assigns
    ///   enforcing this to this crate specifically, since (unlike L3's
    ///   single layer of framing) an over-budget body here would
    ///   encrypt "successfully" into an L4 frame that can never actually
    ///   fit inside the L3 SEND/RECV record it must ride in (decision
    ///   0001), burning a reliable-class counter on a frame that could
    ///   never be delivered;
    /// - once [`Self::send_reliable_next`](field) has reached
    ///   `2^63` (`E2eError::ReliableCounterExhausted`) — astronomically
    ///   unreachable given REKEY fires every 2^20 records or hourly, but
    ///   checked rather than assumed; see that error's own doc comment.
    pub fn encrypt_data(&mut self, body: &E2eDataBody) -> Result<E2eFrame, E2eError> {
        if body.kind().class() == RecordClass::Datagram {
            return Err(E2eError::DatagramUnsupported);
        }
        if self.send_reliable_next >= RELIABLE_COUNTER_CEILING {
            return Err(E2eError::ReliableCounterExhausted);
        }
        let plaintext = body.encode()?;
        if plaintext.len() > self.max_plaintext {
            return Err(E2eError::BodyTooLarge {
                len: plaintext.len(),
                max: self.max_plaintext,
            });
        }
        let counter = self.send_reliable_next;
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self.inner.write_message(counter, &plaintext, &mut out)?;
        out.truncate(n);
        self.send_reliable_next = self.send_reliable_next.saturating_add(1);
        if matches!(body, E2eDataBody::Rekey) {
            self.rekey_outgoing();
        }
        Ok(E2eFrame::Data {
            receiver_index: self.peer_index,
            counter,
            ciphertext: out,
        })
    }

    /// Decrypts an incoming `data` frame's `counter` and `ciphertext`
    /// (pulled out of an already-routed [`E2eFrame::Data`] — this
    /// crate's own `receiver_index` has nothing further to say about
    /// routing, see [`crate`]'s doc comment on what L4e's peer table owns
    /// instead). For a decoded [`E2eDataBody::Rekey`], also rekeys this
    /// side's own receiving cipher — see this module's doc comment on
    /// why that is no longer a separate caller step.
    ///
    /// Checks, strictly in this order, each gating the next:
    /// 1. A datagram-class `counter` is refused *before* any decryption
    ///    is attempted (`E2eError::UnauthenticatedDatagramCounter` — see
    ///    this module's doc comment: **not session-fatal, this one
    ///    specifically means "drop it"**, unlike every other error this
    ///    function returns).
    /// 2. The frame must actually decrypt (a `snow`/Noise error
    ///    otherwise) — see this module's doc comment for why this runs
    ///    before the next two checks, not after.
    /// 3. The counter must be exactly the next expected reliable-class
    ///    one (`E2eError::ReliableContiguityViolation` otherwise —
    ///    protocol.md 5.2: "ends the session and resets every stream").
    /// 4. The decoded body's own kind must belong to the reliable class
    ///    too (`E2eError::RecordClassMismatch` otherwise — see this
    ///    module's doc comment).
    ///
    /// `recv_reliable_next` only advances once every check has passed;
    /// a failure at step 3 or 4 leaves it untouched, the same "no state
    /// change on failure" rule [`Self::encrypt_data`] already follows.
    /// Steps 3 and 4 are both reported, never silently corrected: the
    /// caller must end the session, which this type has no means to do
    /// itself.
    pub fn decrypt_data(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
    ) -> Result<E2eDataBody, E2eError> {
        if RecordClass::of_counter(counter) == RecordClass::Datagram {
            return Err(E2eError::UnauthenticatedDatagramCounter);
        }
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self.inner.read_message(counter, ciphertext, &mut out)?;
        out.truncate(n);

        let expected = self.recv_reliable_next;
        if counter != expected {
            return Err(E2eError::ReliableContiguityViolation {
                expected,
                actual: counter,
            });
        }
        // Parse (and class-check) before committing the advance, not
        // after: a frame that authenticates and lands on the expected
        // counter but still fails one of these leaves
        // `recv_reliable_next` untouched, the same "no state change on
        // failure" rule `Self::encrypt_data` already follows.
        let body = E2eDataBody::decode(&out)?;
        if body.kind().class() != RecordClass::Reliable {
            return Err(E2eError::RecordClassMismatch {
                counter_class: RecordClass::Reliable,
                kind_class: body.kind().class(),
            });
        }
        self.recv_reliable_next = expected.saturating_add(1);
        if matches!(body, E2eDataBody::Rekey) {
            self.rekey_incoming();
        }
        Ok(body)
    }

    /// Rekeys this side's own sending cipher (protocol.md 5.2: "a sender
    /// emits REKEY... and applies Noise `Rekey()` to its sending
    /// state"). Private: [`Self::encrypt_data`] is this type's only
    /// caller, applying it automatically for an [`E2eDataBody::Rekey`]
    /// body — see this module's doc comment on why that coupling is
    /// deliberate, not merely where this call happens to live today.
    fn rekey_outgoing(&mut self) {
        self.inner.rekey_outgoing();
    }

    /// Rekeys this side's own receiving cipher (protocol.md 5.2: "the
    /// receiver applies it on receipt"). Private — see
    /// [`Self::rekey_outgoing`]'s docs for the same reasoning in the
    /// other direction.
    fn rekey_incoming(&mut self) {
        self.inner.rekey_incoming();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::handshake::{E2eInitiatorHandshake, E2eResponderHandshake};
    use menzil_proto::{NetworkId, NodeCert, NodeCertBody, NodeId, X25519PublicKey};

    fn node_cert(seed: u8) -> NodeCert {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: NodeId::from([seed; 32]),
            x25519_pub: X25519PublicKey::from([seed; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }

    /// Drives one full live `IK` handshake (initiator and responder),
    /// returning both sides' finished [`E2eTransport`]s, each built with
    /// `max_record`. This, not any isolated unit test elsewhere, is the
    /// test that actually matters: a real two-sided Noise handshake
    /// producing transports that can talk to each other, the same role
    /// `menzil_session::transport::tests::run_live_handshake` plays for
    /// L3.
    pub(crate) fn run_live_handshake_with_max_record(
        max_record: u32,
    ) -> (E2eTransport, E2eTransport) {
        let initiator_kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        let initiator_priv = <[u8; 32]>::try_from(initiator_kp.private).unwrap();

        let responder_kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        let responder_priv = <[u8; 32]>::try_from(responder_kp.private).unwrap();
        let responder_pub =
            X25519PublicKey::from(<[u8; 32]>::try_from(responder_kp.public).unwrap());

        let network_id = NetworkId::from([1u8; 32]);
        let initiator_node_id = NodeId::from([2u8; 32]);
        let responder_node_id = NodeId::from([3u8; 32]);

        let (initiator_hs, init_frame) = E2eInitiatorHandshake::start(
            &initiator_priv,
            &responder_pub,
            network_id,
            initiator_node_id,
            responder_node_id,
            0xAAAA_AAAA,
        )
        .unwrap();

        let responder_hs = E2eResponderHandshake::start(
            &responder_priv,
            initiator_node_id,
            responder_node_id,
            &init_frame,
        )
        .unwrap();

        let (responder_transport, resp_frame) = responder_hs
            .finish(node_cert(9), 5, 7, vec![0x01], 0xBBBB_BBBB, max_record)
            .unwrap();

        let (initiator_transport, payload, _responder_static) =
            initiator_hs.finish(&resp_frame, max_record).unwrap();
        assert_eq!(payload.roster_seq, 5);
        assert_eq!(payload.policy_seq, 7);

        (initiator_transport, responder_transport)
    }

    /// [`run_live_handshake_with_max_record`] with a generous, realistic
    /// `max_record` (WELCOME's own wire ceiling) — what every test that
    /// isn't specifically about the plaintext budget itself should use.
    pub(crate) fn run_live_handshake() -> (E2eTransport, E2eTransport) {
        run_live_handshake_with_max_record(65_535)
    }

    fn ik_params() -> snow::params::NoiseParams {
        "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap()
    }

    /// Whether `transport` can decrypt `ciphertext` at `counter` *right
    /// now*, against its own cipher state, bypassing `decrypt_data`
    /// entirely (so this never touches `recv_reliable_next`).
    /// `read_message` takes `&self` (stateless, explicit nonce), so this
    /// has no side effects and is safe as a read-only probe. Used by
    /// tests that need to tell whether a key actually changed: unlike
    /// [`probe_ciphertext`], which always reflects *this transport's own
    /// sending* cipher regardless of role, this reflects whichever
    /// cipher *this transport uses to receive* — for a responder that is
    /// a genuinely different cipher than the one `probe_ciphertext`
    /// would exercise on it (`snow`'s `StatelessTransportState` keeps
    /// one cipher per direction, and a responder's send/receive split is
    /// the mirror image of an initiator's).
    fn probe_decrypts(transport: &E2eTransport, counter: u64, ciphertext: &[u8]) -> bool {
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        transport
            .inner
            .read_message(counter, ciphertext, &mut out)
            .is_ok()
    }

    /// Encrypts `plaintext` at `counter` directly against `transport`'s
    /// own *sending* cipher, bypassing `encrypt_data` entirely.
    /// `write_message` takes `&self` (stateless, explicit nonce), so
    /// this has no side effects on `transport` and is safe to call as a
    /// read-only probe — used by tests that need to tell whether this
    /// side's own sending key changed, or to construct a frame
    /// `encrypt_data`'s own checks would refuse to produce (simulating a
    /// non-compliant peer). See [`probe_decrypts`]'s docs for why a
    /// *receiving*-side check needs that one instead, not this one with
    /// the roles swapped.
    fn probe_ciphertext(transport: &E2eTransport, counter: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = transport
            .inner
            .write_message(counter, plaintext, &mut out)
            .unwrap();
        out.truncate(n);
        out
    }

    #[test]
    fn live_handshake_yields_matching_peer_indices() {
        let (initiator, responder) = run_live_handshake();
        // Each side's `peer_index` is the *other* side's own index.
        assert_eq!(initiator.peer_index(), 0xBBBB_BBBB);
        assert_eq!(responder.peer_index(), 0xAAAA_AAAA);
    }

    #[test]
    fn the_plaintext_budget_is_derived_from_max_record_at_construction() {
        let (initiator, responder) = run_live_handshake_with_max_record(1024);
        assert_eq!(
            initiator.max_plaintext,
            menzil_proto::max_e2e_data_plaintext(1024)
        );
        assert_eq!(
            responder.max_plaintext,
            menzil_proto::max_e2e_data_plaintext(1024)
        );
    }

    #[test]
    fn encrypt_then_decrypt_round_trips_each_reliable_kind() {
        let (mut initiator, mut responder) = run_live_handshake();
        for body in [
            E2eDataBody::Mux(vec![1, 2, 3]),
            E2eDataBody::Close {
                code: menzil_proto::ErrorCode::NoGrant,
                msg: "no grant".to_string(),
            },
            E2eDataBody::Keep,
            E2eDataBody::Rekey,
        ] {
            let frame = initiator.encrypt_data(&body).unwrap();
            let (receiver_index, counter, ciphertext) = match frame {
                E2eFrame::Data {
                    receiver_index,
                    counter,
                    ciphertext,
                } => (receiver_index, counter, ciphertext),
                _ => unreachable!("encrypt_data always returns a Data frame"),
            };
            // `receiver_index` names the responder's own local index
            // (0xBBBB_BBBB in this test's fixed setup), not the
            // initiator's — the responder is who must recognize itself
            // by this value.
            assert_eq!(receiver_index, 0xBBBB_BBBB);
            let decoded = responder.decrypt_data(counter, &ciphertext).unwrap();
            assert_eq!(decoded, body);
        }
    }

    #[test]
    fn reliable_counters_start_at_zero_and_advance_by_one() {
        let (mut initiator, mut responder) = run_live_handshake();
        for expected in 0u64..5 {
            let frame = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
            let E2eFrame::Data {
                counter,
                ciphertext,
                ..
            } = frame
            else {
                unreachable!()
            };
            assert_eq!(counter, expected);
            responder.decrypt_data(counter, &ciphertext).unwrap();
        }
    }

    #[test]
    fn out_of_order_counter_is_rejected_only_after_successful_decryption() {
        let (mut initiator, mut responder) = run_live_handshake();
        // Counter 1 "from the future": not yet encrypted by initiator at
        // all, so this ciphertext cannot possibly authenticate under the
        // real cipher state at nonce 1 — an attacker-injected frame, not
        // a reordering of genuine traffic.
        let forged = vec![0xffu8; 32];
        let err = responder.decrypt_data(1, &forged).unwrap_err();
        assert!(
            matches!(err, E2eError::Noise(_)),
            "a frame that never decrypts must fail as a Noise error, not a contiguity violation: {err:?}"
        );
        // The receive counter must be untouched: counter 0, sent for
        // real, still decrypts and is accepted next.
        let frame = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = frame
        else {
            unreachable!()
        };
        assert_eq!(counter, 0);
        assert_eq!(
            responder.decrypt_data(counter, &ciphertext).unwrap(),
            E2eDataBody::Keep
        );
    }

    #[test]
    fn a_genuinely_decrypted_but_out_of_sequence_counter_is_a_contiguity_violation() {
        let (mut initiator, mut responder) = run_live_handshake();
        // Encrypt two records for real (counters 0 and 1), then feed the
        // responder counter 1's frame first: it decrypts fine (real
        // ciphertext, real nonce) but is out of sequence.
        let _frame0 = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
        let frame1 = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = frame1
        else {
            unreachable!()
        };
        assert_eq!(counter, 1);
        let err = responder.decrypt_data(counter, &ciphertext).unwrap_err();
        assert!(matches!(
            err,
            E2eError::ReliableContiguityViolation {
                expected: 0,
                actual: 1
            }
        ));
    }

    #[test]
    fn a_duplicate_counter_is_a_contiguity_violation() {
        let (mut initiator, mut responder) = run_live_handshake();
        let frame = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = frame
        else {
            unreachable!()
        };
        responder.decrypt_data(counter, &ciphertext).unwrap();
        let err = responder.decrypt_data(counter, &ciphertext).unwrap_err();
        assert!(matches!(
            err,
            E2eError::ReliableContiguityViolation {
                expected: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn datagram_class_counter_is_dropped_before_decryption_is_attempted() {
        let (_initiator, mut responder) = run_live_handshake();
        let datagram_counter = RecordClass::Datagram.wire_counter(0);
        // Garbage ciphertext: if this were handed to Noise at all, it
        // would fail as a Noise error, not this one. Getting
        // `UnauthenticatedDatagramCounter` back proves the class check
        // runs first.
        let err = responder
            .decrypt_data(datagram_counter, &[0xaa; 8])
            .unwrap_err();
        assert!(matches!(err, E2eError::UnauthenticatedDatagramCounter));
        // Pre-auth and not session-fatal: the receive counter is
        // untouched, and the genuine next frame still works.
        assert_eq!(responder.recv_reliable_next, 0);
    }

    #[test]
    fn a_dgram_kind_body_under_a_reliable_counter_is_a_class_mismatch() {
        let (initiator, mut responder) = run_live_handshake();
        // Hand-craft a DGRAM-kind plaintext and encrypt it at the next
        // *reliable* counter directly, bypassing `encrypt_data`'s own
        // refusal to ever produce this — simulating a non-compliant
        // peer, not anything this crate's public API can construct.
        let dgram_body = E2eDataBody::Dgram {
            channel: 7,
            bytes: vec![1, 2, 3],
        };
        let plaintext = dgram_body.encode().unwrap();
        let ciphertext = probe_ciphertext(&initiator, 0, &plaintext);

        let err = responder.decrypt_data(0, &ciphertext).unwrap_err();
        assert!(matches!(
            err,
            E2eError::RecordClassMismatch {
                counter_class: RecordClass::Reliable,
                kind_class: RecordClass::Datagram,
            }
        ));
        // Authenticated but still rejected: receive counter untouched.
        assert_eq!(responder.recv_reliable_next, 0);
    }

    #[test]
    fn encrypting_a_dgram_body_is_refused() {
        let (mut initiator, _responder) = run_live_handshake();
        let err = initiator
            .encrypt_data(&E2eDataBody::Dgram {
                channel: 1,
                bytes: vec![1, 2, 3],
            })
            .unwrap_err();
        assert!(matches!(err, E2eError::DatagramUnsupported));
        assert_eq!(initiator.send_reliable_next, 0);
    }

    #[test]
    fn encrypt_data_refuses_a_body_over_this_sessions_plaintext_budget() {
        let (mut initiator, _responder) = run_live_handshake_with_max_record(200);
        let max = initiator.max_plaintext;
        let body = E2eDataBody::Mux(vec![0u8; max]); // kind byte + max > max
        let err = initiator.encrypt_data(&body).unwrap_err();
        assert!(matches!(
            err,
            E2eError::BodyTooLarge { len, max: m } if len == max + 1 && m == max
        ));
        assert_eq!(initiator.send_reliable_next, 0);
    }

    #[test]
    fn encrypt_data_refuses_once_the_reliable_counter_reaches_its_ceiling() {
        let (mut initiator, mut responder) = run_live_handshake();
        initiator.send_reliable_next = RELIABLE_COUNTER_CEILING - 1;
        responder.recv_reliable_next = RELIABLE_COUNTER_CEILING - 1;

        let frame = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = frame
        else {
            unreachable!()
        };
        assert_eq!(counter, RELIABLE_COUNTER_CEILING - 1);
        assert_eq!(
            responder.decrypt_data(counter, &ciphertext).unwrap(),
            E2eDataBody::Keep
        );

        let err = initiator.encrypt_data(&E2eDataBody::Keep).unwrap_err();
        assert!(matches!(err, E2eError::ReliableCounterExhausted));
    }

    #[test]
    fn sending_and_receiving_a_rekey_body_automatically_changes_both_keys() {
        let (mut initiator, mut responder) = run_live_handshake();
        let probe_counter = 999u64; // far outside the real contiguity sequence, never touches it
        let probe_plaintext = b"never actually sent, just a fixed probe plaintext";

        // Baseline, proving the probe itself is meaningful: right now,
        // what the initiator's sending cipher produces, the responder's
        // receiving cipher can still open.
        let before = probe_ciphertext(&initiator, probe_counter, probe_plaintext);
        assert!(probe_decrypts(&responder, probe_counter, &before));

        let initiator_sending_before = probe_ciphertext(&initiator, probe_counter, probe_plaintext);

        let frame = initiator.encrypt_data(&E2eDataBody::Rekey).unwrap();
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = frame
        else {
            unreachable!()
        };
        assert_eq!(
            responder.decrypt_data(counter, &ciphertext).unwrap(),
            E2eDataBody::Rekey
        );

        // No manual rekey call anywhere above. If `encrypt_data` really
        // rekeyed the initiator's own sending cipher, the same
        // (counter, plaintext) now encrypts to something different.
        let initiator_sending_after = probe_ciphertext(&initiator, probe_counter, probe_plaintext);
        assert_ne!(
            initiator_sending_before, initiator_sending_after,
            "encrypt_data(Rekey) must rekey the sender's own sending cipher automatically"
        );

        // If `decrypt_data` really rekeyed the responder's receiving
        // cipher to match, the pre-rekey ciphertext no longer opens
        // there, but the post-rekey one does — proving both sides
        // actually landed on the *same* new key, not just that
        // something merely changed on each side independently.
        assert!(
            !probe_decrypts(&responder, probe_counter, &before),
            "responder's receiving cipher must no longer accept the pre-rekey key"
        );
        assert!(
            probe_decrypts(&responder, probe_counter, &initiator_sending_after),
            "decrypt_data must rekey the receiver automatically on a decoded Rekey body, to the same key the sender just moved to"
        );

        // And a real round trip still works afterward, no manual
        // intervention, through the normal contiguity-checked path.
        let frame = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = frame
        else {
            unreachable!()
        };
        assert_eq!(
            responder.decrypt_data(counter, &ciphertext).unwrap(),
            E2eDataBody::Keep
        );
    }

    #[test]
    fn decrypting_with_a_stale_key_after_rekey_fails() {
        let (mut initiator, mut responder) = run_live_handshake();
        let frame = initiator.encrypt_data(&E2eDataBody::Keep).unwrap();
        // Responder rekeys its receiving state (directly — `rekey_incoming`
        // is private but still reachable from this crate's own test
        // module) without ever having decrypted the message above: the
        // stale key must not still work, and (since decryption now
        // fails) the receive counter must not advance either.
        responder.rekey_incoming();
        let E2eFrame::Data {
            counter,
            ciphertext,
            ..
        } = frame
        else {
            unreachable!()
        };
        assert!(responder.decrypt_data(counter, &ciphertext).is_err());
        assert_eq!(responder.recv_reliable_next, 0);
    }
}
