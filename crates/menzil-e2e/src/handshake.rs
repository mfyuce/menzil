//! The L4 `Noise_IK` handshake (protocol.md 5.1): `init`/`resp`, completing
//! in two messages into an [`E2eTransport`].
//!
//! Always `IK`, never `XX` — unlike L3 (`menzil-session`'s own choice
//! between the two patterns), an L4 initiator "knows B's current
//! NodeCert from the Policy `certs`" by construction (protocol.md 5.1),
//! so there is no case where the initiator doesn't already know its
//! peer's static key.
//!
//! **Handshake-payload placement is asymmetric, on purpose, following
//! the more specific of two sentences protocol.md 5.1 gives** (the same
//! reading `menzil_proto::e2e`'s own doc comment already settles and
//! this module simply obeys): the one CBOR payload shape it defines is
//! carried in `resp` (message 2, responder to initiator) only. `init`
//! (message 1) is empty — [`E2eInitiatorHandshake::start`] always sends
//! an empty payload, and [`E2eResponderHandshake::start`] rejects a
//! non-empty one (`E2eError::UnexpectedHandshakePayload`) rather than
//! silently ignoring it. A practical consequence worth repeating here:
//! only the initiator ever receives the peer's `node_cert`,
//! `roster_seq`, and `policy_seq` through this handshake; a responder
//! learns its peer's Noise static key from message 1 (IK transmits it
//! there), but nothing else about it — any further verification needs
//! identity supplied from outside this handshake (see below).
//!
//! **This module performs none of protocol.md 5.1's "Checks" paragraph**
//! — not the initiator's "`node_cert.node_id` equals the NodeId it
//! dialed" check, not the responder's membership/serial/revocation
//! checks, not the grant decision. It has no access to Policy or Roster
//! state (by design — see [`crate`]'s doc comment) and would have
//! nowhere to get it from even if it wanted to. What it does instead,
//! mirroring `menzil_session::handshake`'s identical choice for L3: it
//! surfaces the raw material those checks need — the negotiated peer
//! static key ([`E2eResponderHandshake::initiator_static`], and
//! [`E2eInitiatorHandshake::finish`]'s returned responder static key —
//! both *before* [`crate::E2eTransport`] can be used for anything, so a
//! caller can refuse to proceed on a mismatch) and the handshake
//! payload's `node_cert` (unverified: this module never calls
//! `NodeCert::verify`, since verifying it needs a decision about *which*
//! key to check it against that only Policy can make).
//!
//! **The initiator's own claimed peer identity is taken on faith by this
//! module, and checking it is exactly what the prologue is for.**
//! [`E2eResponderHandshake::start`] takes `initiator_node_id` as a
//! parameter — protocol.md 5.1's "the responder verifies the
//! initiator's `node_id` equals the RECV `src`" names a value only the
//! caller's L3 routing has (this crate never sees a RECV record). If the
//! caller passes the wrong one, the prologue this builds will not match
//! the one the real initiator built, and the handshake fails outright
//! (a wrong prologue breaks the Noise transcript) rather than silently
//! completing against the wrong identity.
//!
//! **Each side's own index is caller-supplied, not generated here**
//! (`init`'s `sender_index` for the initiator, `resp`'s `sender_index` for
//! the responder) — allocating one without colliding with other concurrent
//! sessions needs a table of what's already in use, which is TODO.md
//! L4e's job ("peer/session table"), not a single session's. A frame's
//! `sender_index` is always the index its sender chose and its
//! `receiver_index` the one its receiver chose, so `resp` carries the
//! responder's own index as `sender_index` and echoes the initiator's, from
//! `init`, as `receiver_index`.
//!
//! **Defense in depth: an all-zero Noise static key is rejected outright**
//! (a red-team finding on this crate), on whichever side first learns
//! one — [`E2eInitiatorHandshake::start`] for a caller-supplied
//! `responder_public_key`, [`E2eResponderHandshake::start`] for the
//! initiator's key as negotiated from message 1. The all-zero point is
//! X25519's simplest degenerate/low-order key: WireGuard's reference
//! implementations reject it by checking their Diffie-Hellman *output*;
//! this module only has safe access to the *input* public key through
//! `snow`'s API, so it checks that instead (narrower — the other seven
//! low-order Curve25519 points are not individually enumerated). Worth
//! having because [`menzil_proto::NodeCert`] never validates
//! `x25519_pub` either, so without this, a malformed or malicious
//! NodeCert could otherwise make two honest peers "negotiate" a key with
//! no real secrecy, with nothing downstream able to tell.
//!
//! **A known, deliberately unfixed gap** (also a red-team finding,
//! rated low severity): [`E2eInitiatorHandshake::finish`] consumes
//! `self` even when `resp` fails to decrypt or doesn't match. Since
//! `snow` itself restores a `HandshakeState`'s symmetric state on a
//! failed read, a non-consuming API (returning `self` back alongside
//! the error) is possible in principle and would let a caller retry
//! against a later, genuine `resp` after an earlier forged or
//! misrouted one — relevant if a relay (which could simply drop
//! traffic instead, no better off either way) or a confused co-member
//! delivers garbage before the real response arrives. Not implemented:
//! the fix needs `hs: Option<snow::HandshakeState>` plus `.take()` so a
//! field can be conditionally moved out of `&mut self`, which is more
//! structure than this already-minimal crate's stated scope calls for
//! on its own; tracked in TODO.md as a specific follow-up for whichever
//! of L4e/L4h ends up owning handshake retry behavior, not silently
//! left as a surprise.

use menzil_proto::{E2eFrame, E2eHandshakePayload, NetworkId, NodeCert, NodeId, X25519PublicKey};

use crate::error::E2eError;
use crate::transport::E2eTransport;

fn ik_params() -> snow::params::NoiseParams {
    "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .expect("this crate's own pattern string always parses")
}

/// Builds the L4 prologue (protocol.md 5.1): `"menzil.v1.e2e" ||
/// network_id || initiator_node_id || responder_node_id`. Unlike L3's
/// prologue (`menzil_session::handshake::prologue`), no `0x00`
/// separators are needed: every field here is a fixed-width 32-byte
/// value, so concatenation alone is already unambiguous.
pub fn prologue(
    network_id: NetworkId,
    initiator_node_id: NodeId,
    responder_node_id: NodeId,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(b"menzil.v1.e2e".len() + 32 * 3);
    out.extend_from_slice(b"menzil.v1.e2e");
    out.extend_from_slice(network_id.as_ref());
    out.extend_from_slice(initiator_node_id.as_ref());
    out.extend_from_slice(responder_node_id.as_ref());
    out
}

/// Matches [`crate::transport::E2eTransport`]'s own message-size
/// ceiling; see its docs for why this crate doesn't enforce a smaller
/// one during the handshake either.
const MAX_NOISE_MESSAGE: usize = 65_535;

fn write(hs: &mut snow::HandshakeState, payload: &[u8]) -> Result<Vec<u8>, E2eError> {
    let mut out = vec![0u8; MAX_NOISE_MESSAGE];
    let n = hs.write_message(payload, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn read(hs: &mut snow::HandshakeState, message: &[u8]) -> Result<Vec<u8>, E2eError> {
    let mut out = vec![0u8; MAX_NOISE_MESSAGE];
    let n = hs.read_message(message, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn remote_static(hs: &snow::HandshakeState) -> Option<X25519PublicKey> {
    hs.get_remote_static()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(X25519PublicKey::from)
}

/// Whether `key` is the all-zero point; see this module's doc comment
/// on why both `start()` methods below reject it.
fn is_all_zero(key: &X25519PublicKey) -> bool {
    key.as_ref() == [0u8; 32]
}

// ---------------------------------------------------------------------
// Initiator (A) side
// ---------------------------------------------------------------------

/// An initiator-side handshake after sending `init`, awaiting `resp`.
#[derive(Debug)]
pub struct E2eInitiatorHandshake {
    hs: snow::HandshakeState,
    /// The index this side chose and sent in `init`; `resp` must echo it.
    own_index: u32,
}

impl E2eInitiatorHandshake {
    /// Starts an initiator-side handshake: builds the `IK` Noise state
    /// and sends an empty message 1 (protocol.md 5.1: "There is no
    /// application data in message 1"). Returns the handshake and the
    /// `init` frame to send.
    ///
    /// `responder_public_key` is the peer's current Noise static key,
    /// already known from Policy (protocol.md 5.1) — this is the
    /// defining property of `IK`, not optional the way it was for L3's
    /// choice between `Ik`/`Xx`.
    pub fn start(
        local_private_key: &[u8; 32],
        responder_public_key: &X25519PublicKey,
        network_id: NetworkId,
        initiator_node_id: NodeId,
        responder_node_id: NodeId,
        sender_index: u32,
    ) -> Result<(Self, E2eFrame), E2eError> {
        if is_all_zero(responder_public_key) {
            return Err(E2eError::DegenerateStaticKey);
        }
        let prologue_bytes = prologue(network_id, initiator_node_id, responder_node_id);
        let mut hs = snow::Builder::new(ik_params())
            .local_private_key(local_private_key)?
            .remote_public_key(responder_public_key.as_ref())?
            .prologue(&prologue_bytes)?
            .build_initiator()?;
        let noise_msg1 = write(&mut hs, &[])?;
        let frame = E2eFrame::Init {
            sender_index,
            network_id,
            noise_msg1,
        };
        Ok((
            Self {
                hs,
                own_index: sender_index,
            },
            frame,
        ))
    }

    /// Consumes `resp`, decoding its payload as [`E2eHandshakePayload`]
    /// and completing the handshake (`IK` finishes in two messages — no
    /// message 3 exists). Also returns the responder's Noise static key
    /// as actually negotiated, for the caller to check against the
    /// payload's `node_cert.x25519_pub` (see this module's doc comment:
    /// this crate surfaces that comparison, it does not perform it).
    ///
    /// Fails with `E2eError::UnexpectedFrame` if `resp` is not an
    /// [`E2eFrame::Resp`], or `E2eError::EchoedIndexMismatch` if its
    /// `receiver_index` is not the `sender_index` this handshake actually
    /// sent in `init`.
    ///
    /// `max_record` (WELCOME's `limits.max_record`) becomes the new
    /// [`E2eTransport`]'s plaintext budget ceiling — see its own
    /// `encrypt_data` docs for why this crate enforces one at all.
    pub fn finish(
        mut self,
        resp: &E2eFrame,
        max_record: u32,
    ) -> Result<(E2eTransport, E2eHandshakePayload, X25519PublicKey), E2eError> {
        let (echoed_index, responder_index, noise_msg2) = match resp {
            E2eFrame::Resp {
                sender_index,
                receiver_index,
                noise_msg2,
            } => (*receiver_index, *sender_index, noise_msg2),
            _ => return Err(E2eError::UnexpectedFrame { expected: "resp" }),
        };
        if echoed_index != self.own_index {
            return Err(E2eError::EchoedIndexMismatch {
                expected: self.own_index,
                actual: echoed_index,
            });
        }
        let payload_bytes = read(&mut self.hs, noise_msg2)?;
        let payload = E2eHandshakePayload::decode(&payload_bytes)?;
        let responder_static = remote_static(&self.hs).expect(
            "IK's initiator already knows the responder's static key from the start; by \
             message 2 it is necessarily still known",
        );
        let transport = E2eTransport::from_finished(self.hs, responder_index, max_record)?;
        Ok((transport, payload, responder_static))
    }
}

// ---------------------------------------------------------------------
// Responder (B) side
// ---------------------------------------------------------------------

/// A responder-side handshake after reading `init`, before deciding what
/// to answer with (or whether to answer at all — see this module's doc
/// comment on why that decision belongs to the caller, not here).
#[derive(Debug)]
pub struct E2eResponderHandshake {
    hs: snow::HandshakeState,
    /// The initiator's own index, from `init`'s `sender_index`: echoed in
    /// `resp`, and stamped as `receiver_index` on this side's `data`.
    initiator_index: u32,
    initiator_static: X25519PublicKey,
}

impl E2eResponderHandshake {
    /// Starts a responder-side handshake by reading `init`'s message 1,
    /// which `IK` guarantees already reveals the initiator's Noise
    /// static key ([`Self::initiator_static`]) — available before any
    /// response is sent, so a caller can check it (and run its own
    /// membership/serial checks) against Policy and choose not to
    /// respond at all on a mismatch, protocol.md 5.1's "checks"
    /// paragraph not actually specifying a wire-level rejection for that
    /// case (only the later grant check gets one, via a post-handshake
    /// CLOSE `no_grant` data record).
    ///
    /// `initiator_node_id` is the peer's claimed identity from outside
    /// this handshake (protocol.md 5.1: "the RECV `src`") — see this
    /// module's doc comment on why a wrong value here simply makes the
    /// handshake fail rather than needing its own explicit check.
    ///
    /// Fails with `E2eError::UnexpectedFrame` if `init` is not an
    /// [`E2eFrame::Init`], or `E2eError::UnexpectedHandshakePayload` if
    /// message 1 decrypts to a non-empty payload.
    pub fn start(
        local_private_key: &[u8; 32],
        initiator_node_id: NodeId,
        responder_node_id: NodeId,
        init: &E2eFrame,
    ) -> Result<Self, E2eError> {
        let (sender_index, network_id, noise_msg1) = match init {
            E2eFrame::Init {
                sender_index,
                network_id,
                noise_msg1,
            } => (*sender_index, *network_id, noise_msg1),
            _ => return Err(E2eError::UnexpectedFrame { expected: "init" }),
        };
        let prologue_bytes = prologue(network_id, initiator_node_id, responder_node_id);
        let mut hs = snow::Builder::new(ik_params())
            .local_private_key(local_private_key)?
            .prologue(&prologue_bytes)?
            .build_responder()?;
        let payload_bytes = read(&mut hs, noise_msg1)?;
        if !payload_bytes.is_empty() {
            return Err(E2eError::UnexpectedHandshakePayload);
        }
        let initiator_static = remote_static(&hs).expect(
            "IK's message 1 (e, es, s, ss) always reveals the initiator's static key to the \
             responder",
        );
        if is_all_zero(&initiator_static) {
            return Err(E2eError::DegenerateStaticKey);
        }
        Ok(Self {
            hs,
            initiator_index: sender_index,
            initiator_static,
        })
    }

    /// The initiator's Noise static key, known since [`Self::start`]
    /// returned — see its docs for why this is exposed before
    /// [`Self::finish`] is called.
    pub fn initiator_static(&self) -> &X25519PublicKey {
        &self.initiator_static
    }

    /// Writes `resp`'s message 2, carrying this responder's own
    /// [`E2eHandshakePayload`] (`node_cert`, `roster_seq`, `policy_seq`,
    /// `e2e_protos` — all caller-supplied; this module has no source for
    /// any of them), and completes the handshake.
    ///
    /// `own_index` is this responder's own freshly chosen local index for
    /// the new session (caller-allocated — see this module's doc
    /// comment); it goes out as `resp`'s `sender_index`. `max_record` (WELCOME's `limits.max_record`)
    /// becomes the new [`E2eTransport`]'s plaintext budget ceiling —
    /// see its own `encrypt_data` docs for why this crate enforces one
    /// at all.
    pub fn finish(
        mut self,
        responder_node_cert: NodeCert,
        roster_seq: u64,
        policy_seq: u64,
        e2e_protos: Vec<u8>,
        own_index: u32,
        max_record: u32,
    ) -> Result<(E2eTransport, E2eFrame), E2eError> {
        let payload = E2eHandshakePayload {
            v: menzil_proto::PROTOCOL_VERSION,
            node_cert: responder_node_cert,
            roster_seq,
            policy_seq,
            e2e_protos,
        };
        let noise_msg2 = write(&mut self.hs, &payload.encode()?)?;
        let frame = E2eFrame::Resp {
            sender_index: own_index,
            receiver_index: self.initiator_index,
            noise_msg2,
        };
        let transport = E2eTransport::from_finished(self.hs, self.initiator_index, max_record)?;
        Ok((transport, frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use menzil_proto::{NodeCertBody, X25519PublicKey as X25519Pub};

    #[test]
    fn prologue_layout_is_the_fixed_concatenation() {
        let network_id = NetworkId::from([1u8; 32]);
        let a = NodeId::from([2u8; 32]);
        let b = NodeId::from([3u8; 32]);
        let bytes = prologue(network_id, a, b);
        let expected = [
            b"menzil.v1.e2e".as_slice(),
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        ]
        .concat();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn prologue_order_matters_initiator_then_responder() {
        let network_id = NetworkId::from([9u8; 32]);
        let a = NodeId::from([1u8; 32]);
        let b = NodeId::from([2u8; 32]);
        assert_ne!(prologue(network_id, a, b), prologue(network_id, b, a));
    }

    // The real correctness test for this module lives in
    // `crate::transport::tests::run_live_handshake`, exercised by every
    // test in that module. The tests below cover this module's own
    // defensive checks instead.

    #[test]
    fn initiator_finish_rejects_a_non_resp_frame() {
        let (initiator_hs, _init_frame) = E2eInitiatorHandshake::start(
            &fresh_private_key(),
            &fresh_public_key(),
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            NodeId::from([3u8; 32]),
            1,
        )
        .unwrap();
        let not_resp = E2eFrame::Init {
            sender_index: 1,
            network_id: NetworkId::from([1u8; 32]),
            noise_msg1: vec![],
        };
        let err = initiator_hs.finish(&not_resp, 65_535).unwrap_err();
        assert!(matches!(
            err,
            E2eError::UnexpectedFrame { expected: "resp" }
        ));
    }

    #[test]
    fn responder_start_rejects_a_non_init_frame() {
        let not_init = E2eFrame::Resp {
            sender_index: 2,
            receiver_index: 1,
            noise_msg2: vec![],
        };
        let err = E2eResponderHandshake::start(
            &fresh_private_key(),
            NodeId::from([2u8; 32]),
            NodeId::from([3u8; 32]),
            &not_init,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            E2eError::UnexpectedFrame { expected: "init" }
        ));
    }

    #[test]
    fn resp_carries_the_responders_own_index_and_echoes_the_initiators() {
        // protocol.md 5.1: in every frame `sender_index` is the index the
        // sender chose and `receiver_index` the one its receiver chose; each
        // side then stamps the other's index on its `data` frames.
        let (responder_priv, responder_pub) = fresh_keypair();
        let (initiator_hs, init_frame) = E2eInitiatorHandshake::start(
            &fresh_private_key(),
            &responder_pub,
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            NodeId::from([3u8; 32]),
            42,
        )
        .unwrap();
        let responder_hs = E2eResponderHandshake::start(
            &responder_priv,
            NodeId::from([2u8; 32]),
            NodeId::from([3u8; 32]),
            &init_frame,
        )
        .unwrap();
        let (mut responder_transport, resp_frame) = responder_hs
            .finish(sample_cert(), 0, 0, vec![0x01], 99, 65_535)
            .unwrap();
        match &resp_frame {
            E2eFrame::Resp {
                sender_index,
                receiver_index,
                ..
            } => {
                assert_eq!(*sender_index, 99, "the responder's own index");
                assert_eq!(*receiver_index, 42, "the initiator's, echoed from init");
            }
            other => panic!("not a resp: {other:?}"),
        }
        let (mut initiator_transport, _payload, _static) =
            initiator_hs.finish(&resp_frame, 65_535).unwrap();

        let data_index = |frame: E2eFrame| match frame {
            E2eFrame::Data { receiver_index, .. } => receiver_index,
            other => panic!("not data: {other:?}"),
        };
        let body = menzil_proto::E2eDataBody::Keep;
        assert_eq!(
            data_index(initiator_transport.encrypt_data(&body).unwrap()),
            99,
            "the initiator addresses the responder by the responder's index"
        );
        assert_eq!(
            data_index(responder_transport.encrypt_data(&body).unwrap()),
            42,
            "and the responder the initiator by the initiator's"
        );
    }

    #[test]
    fn initiator_finish_rejects_a_resp_that_echoes_another_index() {
        let (responder_priv, responder_pub) = fresh_keypair();
        let (initiator_hs, init_frame) = E2eInitiatorHandshake::start(
            &fresh_private_key(),
            &responder_pub,
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            NodeId::from([3u8; 32]),
            42,
        )
        .unwrap();
        let responder_hs = E2eResponderHandshake::start(
            &responder_priv,
            NodeId::from([2u8; 32]),
            NodeId::from([3u8; 32]),
            &init_frame,
        )
        .unwrap();
        let (_transport, resp_frame) = responder_hs
            .finish(sample_cert(), 0, 0, vec![0x01], 99, 65_535)
            .unwrap();
        let tampered = match resp_frame {
            E2eFrame::Resp {
                sender_index,
                noise_msg2,
                ..
            } => E2eFrame::Resp {
                sender_index,
                receiver_index: 42 + 1, // wrong on purpose
                noise_msg2,
            },
            _ => unreachable!(),
        };
        let err = initiator_hs.finish(&tampered, 65_535).unwrap_err();
        assert!(matches!(
            err,
            E2eError::EchoedIndexMismatch {
                expected: 42,
                actual: 43
            }
        ));
    }

    #[test]
    fn responder_start_rejects_a_non_empty_message_1_payload() {
        let (responder_priv, responder_pub) = fresh_keypair();
        let (initiator_priv, _initiator_pub) = fresh_keypair();
        let network_id = NetworkId::from([5u8; 32]);
        let initiator_node_id = NodeId::from([6u8; 32]);
        let responder_node_id = NodeId::from([7u8; 32]);

        // Built directly with `snow`, bypassing `E2eInitiatorHandshake`
        // on purpose, to simulate a non-compliant initiator that puts
        // something in message 1 (protocol.md 5.1 never allows this).
        let prologue_bytes = prologue(network_id, initiator_node_id, responder_node_id);
        let mut hs = snow::Builder::new(ik_params())
            .local_private_key(&initiator_priv)
            .unwrap()
            .remote_public_key(responder_pub.as_ref())
            .unwrap()
            .prologue(&prologue_bytes)
            .unwrap()
            .build_initiator()
            .unwrap();
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = hs.write_message(b"not allowed here", &mut out).unwrap();
        out.truncate(n);
        let malicious_init = E2eFrame::Init {
            sender_index: 1,
            network_id,
            noise_msg1: out,
        };

        let err = E2eResponderHandshake::start(
            &responder_priv,
            initiator_node_id,
            responder_node_id,
            &malicious_init,
        )
        .unwrap_err();
        assert!(matches!(err, E2eError::UnexpectedHandshakePayload));
    }

    #[test]
    fn is_all_zero_matches_literal_zero_and_rejects_a_real_key() {
        assert!(is_all_zero(&X25519Pub::from([0u8; 32])));
        assert!(!is_all_zero(&fresh_public_key()));
    }

    #[test]
    fn initiator_start_rejects_an_all_zero_responder_key() {
        let err = E2eInitiatorHandshake::start(
            &fresh_private_key(),
            &X25519Pub::from([0u8; 32]),
            NetworkId::from([1u8; 32]),
            NodeId::from([2u8; 32]),
            NodeId::from([3u8; 32]),
            1,
        )
        .unwrap_err();
        assert!(matches!(err, E2eError::DegenerateStaticKey));
    }

    fn fresh_private_key() -> [u8; 32] {
        let kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        <[u8; 32]>::try_from(kp.private).unwrap()
    }

    fn fresh_public_key() -> X25519Pub {
        let kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        X25519Pub::from(<[u8; 32]>::try_from(kp.public).unwrap())
    }

    /// A matched (private, public) pair, for tests that need to
    /// actually complete a handshake rather than just reach a defensive
    /// check before any real cryptography matters.
    fn fresh_keypair() -> ([u8; 32], X25519Pub) {
        let kp = snow::Builder::new(ik_params()).generate_keypair().unwrap();
        let private = <[u8; 32]>::try_from(kp.private).unwrap();
        let public = X25519Pub::from(<[u8; 32]>::try_from(kp.public).unwrap());
        (private, public)
    }

    fn sample_cert() -> NodeCert {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: NodeId::from([8u8; 32]),
            x25519_pub: X25519Pub::from([9u8; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }
}
