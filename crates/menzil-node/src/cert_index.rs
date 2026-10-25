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

    /// The certificate that must back `node_id`'s Noise static key `claimed_key` at `now`:
    /// one for both, self signed and valid, the highest serial among duplicates (the list order
    /// is not trusted).
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
            .filter(|entry| &entry.body.x25519_pub == claimed_key)
            .filter_map(|entry| verify_decoded(&entry.cert, &entry.body, now))
            .max_by_key(|body| body.serial)
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
            cert_of(&key, 2, 8, 100),
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
            4,
            "all valid for the node"
        );
    }
}
