//! The L3 Noise handshake (protocol.md 4.1): `IK`/`XX`, the HELLO/WELCOME
//! exchange, transitioning into [`Transport`].
//!
//! Synchronous: this crate does no I/O. A caller drives it by handing
//! over bytes it has already read from the wire and sending whatever
//! bytes each step returns; wiring that to a real connection (dialing
//! via `menzil-carrier` on the node side, accepting connections on the
//! relay side) is session behavior for a different crate (TODO.md L3d,
//! L3e), not here.
//!
//! Deliberately unresolved here: how a relay decides which pattern
//! (`Ik` or `Xx`) an inbound handshake uses before it can even parse the
//! first message. protocol.md 4.1 states the pattern choice from the
//! node's side only ("`Ik` when the relay's static key is known" —
//! known to the node, that is), and nothing in the spec says how a
//! relay would know in advance which pattern an inbound connection is
//! about to speak. [`RelayHandshake::start`] therefore takes an
//! explicit [`HandshakePattern`] parameter; deciding it is the caller's
//! problem, not solved here.

use menzil_proto::{HelloBody, WelcomeBody, X25519PublicKey};
use snow::params::NoiseParams;

use crate::error::SessionError;
use crate::transport::Transport;

/// The Noise pattern a handshake uses (protocol.md 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePattern {
    /// `Noise_IK_25519_ChaChaPoly_BLAKE2s`: the initiator already knows
    /// the responder's static key.
    Ik,
    /// `Noise_XX_25519_ChaChaPoly_BLAKE2s`: neither side knows the
    /// other's static key in advance.
    Xx,
}

impl HandshakePattern {
    fn params_str(self) -> &'static str {
        match self {
            Self::Ik => "Noise_IK_25519_ChaChaPoly_BLAKE2s",
            Self::Xx => "Noise_XX_25519_ChaChaPoly_BLAKE2s",
        }
    }

    fn params(self) -> NoiseParams {
        self.params_str()
            .parse()
            .expect("this crate's own pattern strings always parse")
    }
}

/// Builds the L3 prologue (protocol.md 4.1): `"menzil.v1.relay" || 0x00
/// || offered_subprotocols || 0x00 || selected_subprotocol || 0x00 ||
/// pattern_name`. `offered_subprotocol` and `selected_subprotocol` come
/// from `menzil-carrier`'s WebSocket upgrade (its `HandshakeOutcome`
/// type); this crate has no dependency on that one, so takes the two
/// strings directly rather than that type. protocol.md's grammar says
/// "offered_subprotocols" (plural) but this implementation only ever
/// offers the single value `"menzil.v1"` (`menzil_carrier::SUBPROTOCOL`)
/// — there is only ever one string to include either way, so the
/// plural in the spec text doesn't change anything here.
pub fn prologue(
    offered_subprotocol: &str,
    selected_subprotocol: &str,
    pattern: HandshakePattern,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"menzil.v1.relay");
    out.push(0);
    out.extend_from_slice(offered_subprotocol.as_bytes());
    out.push(0);
    out.extend_from_slice(selected_subprotocol.as_bytes());
    out.push(0);
    out.extend_from_slice(pattern.params_str().as_bytes());
    out
}

fn build_state(
    pattern: HandshakePattern,
    is_initiator: bool,
    local_private_key: &[u8; 32],
    remote_public_key: Option<&X25519PublicKey>,
    prologue: &[u8],
) -> Result<snow::HandshakeState, SessionError> {
    let mut builder = snow::Builder::new(pattern.params())
        .local_private_key(local_private_key)?
        .prologue(prologue)?;
    if let Some(remote) = remote_public_key {
        builder = builder.remote_public_key(remote.as_ref())?;
    }
    Ok(if is_initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    })
}

/// Matches [`crate::Transport`]'s own message-size ceiling; see its
/// docs for why this crate doesn't enforce a smaller one during the
/// handshake either.
const MAX_NOISE_MESSAGE: usize = 65_535;

fn write(hs: &mut snow::HandshakeState, payload: &[u8]) -> Result<Vec<u8>, SessionError> {
    let mut out = vec![0u8; MAX_NOISE_MESSAGE];
    let n = hs.write_message(payload, &mut out)?;
    out.truncate(n);
    Ok(out)
}

fn read(hs: &mut snow::HandshakeState, message: &[u8]) -> Result<Vec<u8>, SessionError> {
    let mut out = vec![0u8; MAX_NOISE_MESSAGE];
    let n = hs.read_message(message, &mut out)?;
    out.truncate(n);
    Ok(out)
}

/// [`NodeHandshake::finish`]'s result: the finished transport, the
/// decoded WELCOME, the relay's negotiated Noise static key, and (`Xx`
/// only) the final outgoing message.
type NodeFinishOutcome = (Transport, WelcomeBody, X25519PublicKey, Option<Vec<u8>>);

fn remote_static(hs: &snow::HandshakeState) -> Option<X25519PublicKey> {
    hs.get_remote_static()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(X25519PublicKey::from)
}

// ---------------------------------------------------------------------
// Node (initiator) side
// ---------------------------------------------------------------------

/// A node-side handshake after sending message 1, awaiting the relay's
/// response.
pub struct NodeHandshake {
    hs: snow::HandshakeState,
    pattern: HandshakePattern,
    /// `Xx` only: HELLO's encoded bytes, stashed to send in message 3.
    pending_hello: Option<Vec<u8>>,
}

impl NodeHandshake {
    /// Starts a node-side handshake: builds the Noise state and sends
    /// `hello` as message 1's payload for `Ik` (protocol.md 4.1: "In IK
    /// the node's payload rides message 1"), or an empty message 1 for
    /// `Xx` (protocol.md 4.1: "There is no application data in message
    /// 1"), stashing `hello` to send in message 3 instead ("in XX the
    /// node's payload rides message 3"). Returns the handshake and the
    /// bytes to send as message 1.
    ///
    /// `relay_public_key` is required for `Ik` (the whole point of that
    /// pattern is that the initiator already knows it) and should be
    /// `None` for `Xx` (neither side's static key is known in advance).
    /// This isn't validated up front; `snow`'s own builder already
    /// rejects an inconsistent combination, and that surfaces as a
    /// [`SessionError`] from here rather than a separate check.
    pub fn start(
        pattern: HandshakePattern,
        local_private_key: &[u8; 32],
        relay_public_key: Option<&X25519PublicKey>,
        prologue: &[u8],
        hello: &HelloBody,
    ) -> Result<(Self, Vec<u8>), SessionError> {
        let mut hs = build_state(pattern, true, local_private_key, relay_public_key, prologue)?;
        let (message1, pending_hello) = match pattern {
            HandshakePattern::Ik => (write(&mut hs, &hello.encode()?)?, None),
            HandshakePattern::Xx => (write(&mut hs, &[])?, Some(hello.encode()?)),
        };
        Ok((
            Self {
                hs,
                pattern,
                pending_hello,
            },
            message1,
        ))
    }

    /// Consumes the relay's response (`Ik`'s or `Xx`'s message 2),
    /// decoding its payload as WELCOME. For `Xx` this also writes and
    /// returns message 3 (carrying HELLO); for `Ik` there is nothing
    /// more to send, so the returned `Option` is `None` and the
    /// handshake is already complete.
    ///
    /// Also returns the relay's Noise static key as actually negotiated,
    /// for the caller to check against `welcome.relay_cert`'s
    /// `x25519_pub` (protocol.md 4.1: "the node verifies...
    /// `relay_cert.x25519_pub` equals the relay static key of the
    /// handshake"): this crate surfaces both sides of that comparison,
    /// it does not perform it, since it has no notion of what a
    /// `NodeCert` should be checked against beyond what the Noise layer
    /// itself negotiated.
    pub fn finish(mut self, incoming: &[u8]) -> Result<NodeFinishOutcome, SessionError> {
        let welcome_bytes = read(&mut self.hs, incoming)?;
        let welcome = WelcomeBody::decode(&welcome_bytes)?;
        let outgoing = match self.pattern {
            HandshakePattern::Ik => None,
            HandshakePattern::Xx => {
                let hello_bytes = self
                    .pending_hello
                    .as_deref()
                    .expect("Xx always stashes hello in start()");
                Some(write(&mut self.hs, hello_bytes)?)
            }
        };
        let relay_static = remote_static(&self.hs)
            .expect("both patterns learn the responder's static key by the final message");
        let transport = Transport::from_finished(self.hs)?;
        Ok((transport, welcome, relay_static, outgoing))
    }
}

// ---------------------------------------------------------------------
// Relay (responder) side
// ---------------------------------------------------------------------

/// A relay-side handshake after reading message 1, awaiting the
/// caller's decision on what to put in WELCOME.
pub struct RelayHandshake {
    hs: snow::HandshakeState,
    pattern: HandshakePattern,
    /// `Ik`: known already, read from message 1. `Xx`: not seen yet.
    hello: Option<HelloBody>,
}

impl RelayHandshake {
    /// Starts a relay-side handshake by reading `message1`: for `Ik`
    /// this carries HELLO, for `Xx` it carries no payload.
    ///
    /// `pattern` is the caller's decision — see this module's docs on
    /// why detecting it isn't solved here.
    pub fn start(
        pattern: HandshakePattern,
        local_private_key: &[u8; 32],
        prologue: &[u8],
        message1: &[u8],
    ) -> Result<Self, SessionError> {
        let mut hs = build_state(pattern, false, local_private_key, None, prologue)?;
        let hello = match pattern {
            HandshakePattern::Ik => {
                let bytes = read(&mut hs, message1)?;
                Some(HelloBody::decode(&bytes)?)
            }
            HandshakePattern::Xx => {
                read(&mut hs, message1)?; // empty payload, nothing to decode
                None
            }
        };
        Ok(Self { hs, pattern, hello })
    }

    /// The node's HELLO, if already known at this point (`Ik` only;
    /// `Xx` doesn't see it until [`RelayHandshakeAwaitingHello::finish`]).
    pub fn hello(&self) -> Option<&HelloBody> {
        self.hello.as_ref()
    }

    /// Writes `welcome` as message 2. For `Ik` the handshake is now
    /// complete (nothing more to read), so the result carries the
    /// finished [`Transport`] and HELLO directly via
    /// [`RelayHandshakeStep::Finished`]. For `Xx`, message 3 (carrying
    /// HELLO) is still expected, so the result carries a continuation
    /// via [`RelayHandshakeStep::AwaitingHello`] instead.
    ///
    /// Also returns the node's Noise static key as negotiated so far,
    /// when already known at this point (`Ik` only — see
    /// [`NodeHandshake::finish`]'s docs on why this crate surfaces
    /// rather than checks it; for `Xx` the equivalent value comes back
    /// from [`RelayHandshakeAwaitingHello::finish`] instead, once it's
    /// actually known).
    pub fn write_welcome(
        mut self,
        welcome: &WelcomeBody,
    ) -> Result<(RelayHandshakeStep, Option<X25519PublicKey>, Vec<u8>), SessionError> {
        let message2 = write(&mut self.hs, &welcome.encode()?)?;
        match self.pattern {
            HandshakePattern::Ik => {
                let node_static = remote_static(&self.hs);
                let hello = self
                    .hello
                    .expect("Ik always has hello by the time write_welcome is called");
                let transport = Transport::from_finished(self.hs)?;
                Ok((
                    RelayHandshakeStep::Finished {
                        transport,
                        hello: Box::new(hello),
                    },
                    node_static,
                    message2,
                ))
            }
            HandshakePattern::Xx => Ok((
                RelayHandshakeStep::AwaitingHello(Box::new(RelayHandshakeAwaitingHello {
                    hs: self.hs,
                })),
                None,
                message2,
            )),
        }
    }
}

/// What remains after [`RelayHandshake::write_welcome`].
pub enum RelayHandshakeStep {
    /// `Ik`: the handshake is already complete.
    Finished {
        /// The ready-to-use transport.
        transport: Transport,
        /// The node's HELLO, read in [`RelayHandshake::start`]. Boxed
        /// for the same enum-size reason as `AwaitingHello`'s payload.
        hello: Box<HelloBody>,
    },
    /// `Xx`: message 3 (carrying HELLO) is still expected. Boxed: the
    /// `Finished` variant's `Transport` already carries a `snow`
    /// transport state, so without this the enum's overall size would
    /// be driven up by whichever variant embeds the larger `snow` state
    /// (here, the still-mid-handshake one held for `Xx`).
    AwaitingHello(Box<RelayHandshakeAwaitingHello>),
}

/// `Xx` only: awaiting message 3.
pub struct RelayHandshakeAwaitingHello {
    hs: snow::HandshakeState,
}

impl RelayHandshakeAwaitingHello {
    /// Consumes message 3, decoding its payload as HELLO and completing
    /// the handshake. Also returns the node's Noise static key as
    /// negotiated, for the same caller-side check described in
    /// [`NodeHandshake::finish`]'s docs.
    pub fn finish(
        mut self,
        message3: &[u8],
    ) -> Result<(Transport, HelloBody, X25519PublicKey), SessionError> {
        let hello_bytes = read(&mut self.hs, message3)?;
        let hello = HelloBody::decode(&hello_bytes)?;
        let node_static =
            remote_static(&self.hs).expect("Xx learns the initiator's static key by message 3");
        let transport = Transport::from_finished(self.hs)?;
        Ok((transport, hello, node_static))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tests::run_live_handshake;

    #[test]
    fn prologue_layout_is_field_0x00_separated() {
        let bytes = prologue("menzil.v1", "menzil.v1", HandshakePattern::Ik);
        let expected = [
            b"menzil.v1.relay".as_slice(),
            &[0],
            b"menzil.v1",
            &[0],
            b"menzil.v1",
            &[0],
            b"Noise_IK_25519_ChaChaPoly_BLAKE2s",
        ]
        .concat();
        assert_eq!(bytes, expected);
    }

    #[test]
    fn ik_and_xx_use_their_own_pattern_string() {
        assert_eq!(
            HandshakePattern::Ik.params_str(),
            "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        );
        assert_eq!(
            HandshakePattern::Xx.params_str(),
            "Noise_XX_25519_ChaChaPoly_BLAKE2s"
        );
    }

    // The real correctness test for this whole module: does a live,
    // two-sided handshake for each pattern actually produce transports
    // that can talk to each other? `run_live_handshake` itself already
    // asserts HELLO/WELCOME/remote-static exposure along the way; see
    // `crate::transport::tests` for the encrypt/decrypt-level assertions
    // built on top of it.
    #[test]
    fn live_ik_handshake_completes() {
        run_live_handshake(HandshakePattern::Ik);
    }

    #[test]
    fn live_xx_handshake_completes() {
        run_live_handshake(HandshakePattern::Xx);
    }
}
