//! An index of the certificates of one adopted Policy (round 11 L1).
//!
//! Resolving "the certificate that backs this node's session key" used to decode every entry of
//! the Policy's `certs` on every call, so a re evaluation pass cost sessions x certificates and
//! `Engine::ensure` paid for the whole list on the router actor. A [`CertIndex`] decodes the
//! list once, when a Policy is adopted ([`crate::policy_store`] builds it with the entry), and
//! answers by node id; only the entries that match are checked for their self signature and
//! validity window. The index lives and dies with the held Policy, so an adoption replaces it.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use menzil_proto::{NodeCert, NodeCertBody, NodeId, X25519PublicKey};

/// One certificate with its decoded body.
struct Indexed {
    cert: NodeCert,
    body: NodeCertBody,
}

/// The certificates of one Policy, by the node they are for.
pub(crate) struct CertIndex {
    by_node: HashMap<NodeId, Vec<Indexed>>,
}

#[cfg(test)]
thread_local! {
    /// How many certificates [`CertIndex::build`] decoded on this thread, for the tests that
    /// pin that resolving a certificate does not decode the list again.
    static DECODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Certificates decoded by index builds on this thread so far.
#[cfg(test)]
pub(crate) fn decodes_on_this_thread() -> usize {
    DECODES.with(std::cell::Cell::get)
}

impl CertIndex {
    /// Decodes `certs` once. An entry that does not decode backs nobody and is left out (it
    /// could not be resolved before either).
    pub(crate) fn build(certs: &[NodeCert]) -> Self {
        let mut by_node: HashMap<NodeId, Vec<Indexed>> = HashMap::new();
        for cert in certs {
            #[cfg(test)]
            DECODES.with(|count| count.set(count.get() + 1));
            if let Ok(body) = cert.decode() {
                by_node.entry(body.node_id).or_default().push(Indexed {
                    cert: cert.clone(),
                    body,
                });
            }
        }
        Self { by_node }
    }

    /// The decoded bodies of the certificates for `node_id` that are self signed and valid at
    /// `now`, in list order.
    pub(crate) fn valid_for_node<'a>(
        &'a self,
        node_id: &NodeId,
        now: u64,
    ) -> impl Iterator<Item = NodeCertBody> + 'a {
        self.by_node
            .get(node_id)
            .into_iter()
            .flatten()
            .filter_map(move |entry| verify_decoded(&entry.cert, &entry.body, now))
    }

    /// The certificate that must back `node_id`'s Noise static key `claimed_key` at `now`
    /// (the stateless "highest serial" rule, cert rotation design Q5 b): among the certificates
    /// listed for `node_id` that are self signed and valid at `now`, only the one with the
    /// highest serial counts (the list order is not trusted), and it is returned only when its
    /// key is `claimed_key`. A lower serial listed next to it is never used, so once a higher
    /// serial cert with another key is valid the older key resolves no more; while the higher
    /// one is not yet valid (or no longer signed or valid) the lower one still resolves. The
    /// Policy never goes backwards, so it is the verifier's memory and no state is kept.
    pub(crate) fn resolve(
        &self,
        node_id: &NodeId,
        claimed_key: &X25519PublicKey,
        now: u64,
    ) -> Option<NodeCertBody> {
        self.by_node
            .get(node_id)
            .into_iter()
            .flatten()
            .filter_map(|entry| verify_decoded(&entry.cert, &entry.body, now))
            .max_by_key(|body| body.serial)
            .filter(|body| &body.x25519_pub == claimed_key)
    }
}

/// `body` (the decoded form of `cert`) when `cert` is signed by the key its own `node_id`
/// names and is valid at `now`.
pub(crate) fn verify_decoded(
    cert: &NodeCert,
    body: &NodeCertBody,
    now: u64,
) -> Option<NodeCertBody> {
    let verifying_key = VerifyingKey::from_bytes(&<[u8; 32]>::from(body.node_id)).ok()?;
    cert.verify(&verifying_key).ok()?;
    body.is_valid_at(now).then(|| body.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use menzil_proto::PROTOCOL_VERSION;

    fn cert_of(key: &SigningKey, x: u8, serial: u32, not_after: u64) -> NodeCert {
        NodeCert::sign(
            key,
            &NodeCertBody {
                v: PROTOCOL_VERSION,
                node_id: NodeId::from(key.verifying_key().to_bytes()),
                x25519_pub: X25519PublicKey::from([x; 32]),
                serial,
                not_before: 0,
                not_after,
            },
        )
        .unwrap()
    }

    #[test]
    fn building_decodes_each_certificate_once_and_resolving_none() {
        let keys: Vec<SigningKey> = (0..5)
            .map(|_| SigningKey::generate(&mut rand::rng()))
            .collect();
        let certs: Vec<NodeCert> = keys.iter().map(|k| cert_of(k, 1, 1, 100)).collect();
        let before = decodes_on_this_thread();
        let index = CertIndex::build(&certs);
        assert_eq!(decodes_on_this_thread(), before + 5);
        let id = NodeId::from(keys[3].verifying_key().to_bytes());
        for _ in 0..10 {
            assert!(
                index
                    .resolve(&id, &X25519PublicKey::from([1; 32]), 50)
                    .is_some()
            );
        }
        assert_eq!(decodes_on_this_thread(), before + 5);
    }

    #[test]
    fn resolve_wants_the_node_the_key_the_signature_and_the_window() {
        let key = SigningKey::generate(&mut rand::rng());
        let other = SigningKey::generate(&mut rand::rng());
        let id = NodeId::from(key.verifying_key().to_bytes());
        // Claims `id` but is signed by another key: never resolves.
        let forged = NodeCert::sign(
            &other,
            &NodeCertBody {
                v: PROTOCOL_VERSION,
                node_id: id,
                x25519_pub: X25519PublicKey::from([9; 32]),
                serial: 9,
                not_before: 0,
                not_after: 100,
            },
        )
        .unwrap();
        let index = CertIndex::build(&[
            cert_of(&key, 1, 1, 100),
            cert_of(&key, 1, 4, 100),
            cert_of(&key, 1, 3, 100),
            forged,
        ]);
        let one = X25519PublicKey::from([1; 32]);
        assert_eq!(index.resolve(&id, &one, 50).unwrap().serial, 4, "highest");
        assert!(index.resolve(&id, &one, 101).is_none(), "past not_after");
        assert!(index.resolve(&id, &one, 100).is_some(), "at not_after");
        assert!(
            index
                .resolve(&id, &X25519PublicKey::from([9; 32]), 50)
                .is_none(),
            "the forged one"
        );
        assert!(
            index.resolve(&NodeId::from([5; 32]), &one, 50).is_none(),
            "another node"
        );
        assert_eq!(
            index.valid_for_node(&id, 50).count(),
            3,
            "all valid for the node"
        );
    }

    fn cert_window(key: &SigningKey, x: u8, serial: u32, from: u64, to: u64) -> NodeCert {
        NodeCert::sign(
            key,
            &NodeCertBody {
                v: PROTOCOL_VERSION,
                node_id: NodeId::from(key.verifying_key().to_bytes()),
                x25519_pub: X25519PublicKey::from([x; 32]),
                serial,
                not_before: from,
                not_after: to,
            },
        )
        .unwrap()
    }

    /// Two certs for one node with different keys: once the higher serial one is valid the
    /// lower serial key resolves no more (the highest of the key's own certs is not used).
    #[test]
    fn a_lower_serial_cert_with_another_key_stops_resolving_once_the_higher_is_valid() {
        let key = SigningKey::generate(&mut rand::rng());
        let id = NodeId::from(key.verifying_key().to_bytes());
        let index = CertIndex::build(&[
            cert_window(&key, 1, 1, 0, 1000),
            cert_window(&key, 2, 2, 0, 1000),
        ]);
        let (k1, k2) = (
            X25519PublicKey::from([1; 32]),
            X25519PublicKey::from([2; 32]),
        );
        assert!(index.resolve(&id, &k1, 50).is_none());
        assert_eq!(index.resolve(&id, &k2, 50).unwrap().serial, 2);
    }

    /// A higher serial cert that is not yet valid (or already expired) leaves the lower one
    /// resolvable.
    #[test]
    fn a_higher_cert_not_yet_valid_leaves_the_lower_resolvable() {
        let key = SigningKey::generate(&mut rand::rng());
        let id = NodeId::from(key.verifying_key().to_bytes());
        let index = CertIndex::build(&[
            cert_window(&key, 1, 1, 0, 1000),
            cert_window(&key, 2, 2, 500, 2000),
        ]);
        let (k1, k2) = (
            X25519PublicKey::from([1; 32]),
            X25519PublicKey::from([2; 32]),
        );
        assert_eq!(index.resolve(&id, &k1, 100).unwrap().serial, 1);
        assert!(index.resolve(&id, &k2, 100).is_none(), "not yet valid");
        assert!(index.resolve(&id, &k1, 600).is_none(), "superseded");
        assert_eq!(index.resolve(&id, &k2, 600).unwrap().serial, 2);
    }

    /// The same key at several serials: the highest wins whatever the list order.
    #[test]
    fn same_key_the_highest_serial_wins_in_any_order() {
        let key = SigningKey::generate(&mut rand::rng());
        let id = NodeId::from(key.verifying_key().to_bytes());
        let k1 = X25519PublicKey::from([1; 32]);
        for order in [[1, 2, 3], [3, 2, 1], [2, 3, 1]] {
            let certs: Vec<NodeCert> = order
                .iter()
                .map(|serial| cert_window(&key, 1, *serial, 0, 1000))
                .collect();
            assert_eq!(
                CertIndex::build(&certs)
                    .resolve(&id, &k1, 5)
                    .unwrap()
                    .serial,
                3
            );
        }
    }
}
