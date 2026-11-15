//! The X25519 private key of a node (and of a relay) is wiped when its identity is dropped.
//!
//! Reading memory after a drop needs `unsafe`, which the library crates forbid, so this is an
//! integration test (its own crate): the identity sits in a `ManuallyDrop`, is dropped in place,
//! and the key's bytes are read back with a volatile read. The memory is still ours (the array
//! lives inline in the struct), so the read is of initialized bytes; what the test asserts is
//! that they are no longer the key.

mod common;

use std::mem::ManuallyDrop;

use common::{identity, node_cert};
use menzil_node::LocalIdentity;
use menzil_relay::RelayIdentity;

const KEY: [u8; 32] = [0xA5; 32];

#[test]
fn a_nodes_private_key_is_wiped_when_its_identity_is_dropped() {
    let id = identity();
    let mut local = ManuallyDrop::new(LocalIdentity {
        node_cert: node_cert(&id),
        x25519_private: KEY,
    });
    // A clone is an identity of its own and wipes its own copy, not the original's.
    let clone = (*local).clone();
    drop(clone);
    assert_eq!(
        local.x25519_private, KEY,
        "dropping a clone left the original alone"
    );
    // SAFETY: the value is dropped once, in place, and never used as a whole afterwards; only
    // the inline key array is read, through a pointer to memory that is still allocated.
    let after = unsafe {
        ManuallyDrop::drop(&mut local);
        std::ptr::read_volatile(&raw const local.x25519_private)
    };
    assert_eq!(after, [0u8; 32], "the key was still there after the drop");
}

#[test]
fn a_relays_private_key_is_wiped_when_its_identity_is_dropped() {
    let id = identity();
    let mut relay = ManuallyDrop::new(RelayIdentity {
        node_cert: node_cert(&id),
        x25519_private: KEY,
    });
    // SAFETY: as above.
    let after = unsafe {
        ManuallyDrop::drop(&mut relay);
        std::ptr::read_volatile(&raw const relay.x25519_private)
    };
    assert_eq!(after, [0u8; 32], "the key was still there after the drop");
}
