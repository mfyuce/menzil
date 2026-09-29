//! The post-handshake Noise transport (protocol.md 4.1, 4.2): encrypts
//! and decrypts whole [`menzil_proto::Record`]s, and applies the hourly
//! REKEY this side owns for each direction independently.

use menzil_proto::Record;

use crate::error::SessionError;

/// The Noise Protocol's own hard limit on one transport message,
/// ciphertext included (protocol.md 3.3 calls this "the Noise message
/// limit"). protocol.md's own "L3 record 65,535 bytes payload" (section
/// 10) and "SEND payload is at most 65,535 minus 35 bytes" (section 4.2)
/// both measure the *plaintext* record against this same 65,535 figure,
/// which is the ciphertext limit; a transport-mode message's AEAD tag
/// (16 bytes for `ChaChaPoly`) means the actual usable plaintext budget
/// for one record is nearer 65,519 bytes, not 65,535. This crate does
/// not paper over that: it does not enforce a separate, smaller
/// plaintext limit of its own, so a record that is too large to fit
/// surfaces naturally as `SessionError::Noise(snow::Error::Input)` from
/// [`Transport::encrypt_record`], rather than from an earlier check
/// here.
const MAX_NOISE_MESSAGE: usize = 65_535;

/// A Noise transport-mode session: one side of an established L3
/// handshake, ready to encrypt outgoing records and decrypt incoming
/// ones.
pub struct Transport {
    inner: snow::TransportState,
}

impl Transport {
    pub(crate) fn from_finished(hs: snow::HandshakeState) -> Result<Self, SessionError> {
        Ok(Self {
            inner: hs.into_transport_mode()?,
        })
    }

    /// Encodes `record` and Noise-encrypts it into one outgoing message
    /// (protocol.md 3.3: "one message is one L3 record").
    pub fn encrypt_record(&mut self, record: &Record) -> Result<Vec<u8>, SessionError> {
        let plaintext = record.encode();
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self.inner.write_message(&plaintext, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Noise-decrypts `ciphertext` and decodes the result as a
    /// [`Record`].
    pub fn decrypt_record(&mut self, ciphertext: &[u8]) -> Result<Record, SessionError> {
        let mut out = vec![0u8; MAX_NOISE_MESSAGE];
        let n = self.inner.read_message(ciphertext, &mut out)?;
        out.truncate(n);
        Ok(Record::decode(&out)?)
    }

    /// Rekeys this side's own sending cipher (protocol.md 4.1: "Noise
    /// `Rekey()` runs in both directions on REKEY"; 4.2: "the sender
    /// rekeys its sending state after this record"). Call after sending
    /// a REKEY record, driven by [`crate::RekeySchedule`].
    pub fn rekey_outgoing(&mut self) {
        self.inner.rekey_outgoing();
    }

    /// Rekeys this side's own receiving cipher (protocol.md 4.2: "the
    /// receiver rekeys its receiving state on receipt"). Call after
    /// receiving a REKEY record.
    pub fn rekey_incoming(&mut self) {
        self.inner.rekey_incoming();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::handshake::{HandshakePattern, NodeHandshake, RelayHandshake, RelayHandshakeStep};
    use menzil_proto::{HelloBody, Limits, NodeCert, NodeCertBody, NodeId, WelcomeBody};
    use std::collections::HashMap;

    fn node_cert(seed: u8) -> NodeCert {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let body = NodeCertBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_id: NodeId::from([seed; 32]),
            x25519_pub: menzil_proto::X25519PublicKey::from([seed; 32]),
            serial: 1,
            not_before: 0,
            not_after: 1_000_000_000,
        };
        NodeCert::sign(&key, &body).unwrap()
    }

    fn sample_hello() -> HelloBody {
        HelloBody {
            v: menzil_proto::PROTOCOL_VERSION,
            node_cert: node_cert(1),
            networks: vec![],
            timestamp: menzil_proto::Tai64N::from([0u8; 12]),
            roster_seq: HashMap::new(),
            caps: vec![],
            e2e_protos: vec![0x01],
        }
    }

    fn sample_welcome() -> WelcomeBody {
        WelcomeBody {
            v: menzil_proto::PROTOCOL_VERSION,
            relay_cert: node_cert(2),
            session: 1,
            time: 0,
            limits: Limits {
                max_record: 65_535,
                max_peers: 1,
                credit: 1_048_576,
            },
            rosters: HashMap::new(),
        }
    }

    /// Drives one full live handshake (node initiator, relay responder)
    /// for `pattern`, returning both sides' finished [`Transport`]s.
    /// This, not any of the isolated per-step unit tests elsewhere, is
    /// the test that actually matters: a real two-sided Noise handshake
    /// producing transport states that can talk to each other.
    pub(crate) fn run_live_handshake(pattern: HandshakePattern) -> (Transport, Transport) {
        let node_priv = {
            let kp = snow::Builder::new(pattern_params(pattern))
                .generate_keypair()
                .unwrap();
            <[u8; 32]>::try_from(kp.private).unwrap()
        };
        let relay_kp = snow::Builder::new(pattern_params(pattern))
            .generate_keypair()
            .unwrap();
        let relay_priv = <[u8; 32]>::try_from(relay_kp.private.clone()).unwrap();
        let relay_pub =
            menzil_proto::X25519PublicKey::from(<[u8; 32]>::try_from(relay_kp.public).unwrap());

        let prologue = crate::handshake::prologue("menzil.v1", "menzil.v1", pattern);
        let hello = sample_hello();
        let welcome = sample_welcome();

        let relay_pub_for_node = match pattern {
            HandshakePattern::Ik => Some(&relay_pub),
            HandshakePattern::Xx => None,
        };

        let (node_state, msg1) =
            NodeHandshake::start(pattern, &node_priv, relay_pub_for_node, &prologue, &hello)
                .unwrap();

        let relay_state = RelayHandshake::start(pattern, &relay_priv, &prologue, &msg1).unwrap();
        if pattern == HandshakePattern::Ik {
            assert_eq!(relay_state.hello().unwrap(), &hello);
        } else {
            assert!(relay_state.hello().is_none());
        }

        let (step, _node_static_seen_by_relay, msg2) = relay_state.write_welcome(&welcome).unwrap();

        match (pattern, step) {
            (
                HandshakePattern::Ik,
                RelayHandshakeStep::Finished {
                    transport,
                    hello: seen,
                },
            ) => {
                assert_eq!(*seen, hello);
                let (node_transport, welcome_seen, relay_static, outgoing) =
                    node_state.finish(&msg2).unwrap();
                assert_eq!(welcome_seen, welcome);
                assert_eq!(relay_static.as_ref(), relay_pub.as_ref());
                assert!(outgoing.is_none());
                (node_transport, transport)
            }
            (HandshakePattern::Xx, RelayHandshakeStep::AwaitingHello(awaiting)) => {
                let (node_transport, welcome_seen, _relay_static, outgoing) =
                    node_state.finish(&msg2).unwrap();
                assert_eq!(welcome_seen, welcome);
                let msg3 = outgoing.expect("Xx always has a message 3");
                let (relay_transport, hello_seen, _node_static) = awaiting.finish(&msg3).unwrap();
                assert_eq!(hello_seen, hello);
                (node_transport, relay_transport)
            }
            _ => unreachable!("pattern and step always correspond"),
        }
    }

    fn pattern_params(pattern: HandshakePattern) -> snow::params::NoiseParams {
        match pattern {
            HandshakePattern::Ik => "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap(),
            HandshakePattern::Xx => "Noise_XX_25519_ChaChaPoly_BLAKE2s".parse().unwrap(),
        }
    }

    #[test]
    fn live_ik_handshake_yields_matching_transport_keys() {
        let (mut node, mut relay) = run_live_handshake(HandshakePattern::Ik);
        let record = Record::Ping { nonce: [7; 8] };
        let ciphertext = node.encrypt_record(&record).unwrap();
        let decrypted = relay.decrypt_record(&ciphertext).unwrap();
        assert_eq!(decrypted, record);
    }

    #[test]
    fn live_xx_handshake_yields_matching_transport_keys() {
        let (mut node, mut relay) = run_live_handshake(HandshakePattern::Xx);
        let record = Record::Ping { nonce: [9; 8] };
        let ciphertext = node.encrypt_record(&record).unwrap();
        let decrypted = relay.decrypt_record(&ciphertext).unwrap();
        assert_eq!(decrypted, record);
    }

    #[test]
    fn both_directions_work_after_a_live_handshake() {
        let (mut node, mut relay) = run_live_handshake(HandshakePattern::Ik);
        let to_relay = Record::Rekey;
        let ciphertext = node.encrypt_record(&to_relay).unwrap();
        assert_eq!(relay.decrypt_record(&ciphertext).unwrap(), to_relay);

        let to_node = Record::Goaway(menzil_proto::GoawayBody {
            reason: "superseded".to_string(),
            retry_after_ms: 500,
        });
        let ciphertext = relay.encrypt_record(&to_node).unwrap();
        assert_eq!(node.decrypt_record(&ciphertext).unwrap(), to_node);
    }

    #[test]
    fn rekey_outgoing_then_incoming_keeps_the_stream_working() {
        let (mut node, mut relay) = run_live_handshake(HandshakePattern::Ik);
        node.rekey_outgoing();
        relay.rekey_incoming();
        let record = Record::Ping { nonce: [1; 8] };
        let ciphertext = node.encrypt_record(&record).unwrap();
        assert_eq!(relay.decrypt_record(&ciphertext).unwrap(), record);
    }

    #[test]
    fn decrypting_with_a_stale_key_after_rekey_fails() {
        let (mut node, mut relay) = run_live_handshake(HandshakePattern::Ik);
        let record = Record::Ping { nonce: [1; 8] };
        let ciphertext = node.encrypt_record(&record).unwrap();
        // Relay rekeys its receiving state without ever having decrypted
        // the message above: the stale key must not still work.
        relay.rekey_incoming();
        assert!(relay.decrypt_record(&ciphertext).is_err());
    }
}
