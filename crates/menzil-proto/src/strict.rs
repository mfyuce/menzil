//! Raw structural validation of CBOR bytes, ahead of typed decoding.
//!
//! protocol.md section 1 requires "Signed bodies are decoded strictly ...
//! definite lengths only", applied here to every CBOR body this crate
//! handles (both signed documents and the unsigned control-record
//! bodies, which per the same section only get a carve-out on unknown
//! *keys*, not on length encoding). This module walks the encoded bytes
//! major-type by major-type, without involving serde, and rejects any
//! array, map, byte string, or text string that uses CBOR's
//! indefinite-length encoding (RFC 8949 section 3.2.1) instead of a
//! definite one. It also rejects trailing bytes after the one top-level
//! value, since every body handled here is exactly one CBOR item.
//!
//! Duplicate map keys are deliberately not checked here: a hand-crafted
//! test in this module's test suite confirms that serde_derive's
//! generated `visit_map` already rejects a duplicate of a *known* field
//! regardless of `deny_unknown_fields`, so a second, byte-level check
//! would be redundant for every struct in this crate (all of which are
//! fully enumerated, not open-ended maps).

use thiserror::Error;

/// A CBOR document nested this deep is rejected outright: every body
/// this crate decodes is at most a few levels deep, so this is a
/// generous bound whose only purpose is to stop a hostile input from
/// exhausting the stack.
const MAX_DEPTH: u32 = 64;

/// Failure from the structural scan in [`check_definite_lengths`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StrictCborError {
    /// The input ended before a complete item could be read.
    #[error("truncated CBOR input")]
    Truncated,
    /// An array, map, byte string, or text string used indefinite-length
    /// encoding.
    #[error("indefinite-length CBOR encoding is not allowed")]
    IndefiniteLength,
    /// The additional-info nibble was one of the reserved values 28-30.
    #[error("reserved CBOR additional-info value")]
    Reserved,
    /// Nesting exceeded [`MAX_DEPTH`].
    #[error("CBOR nesting too deep")]
    TooDeep,
    /// Bytes remained after the single top-level value.
    #[error("trailing bytes after the CBOR value")]
    TrailingBytes,
}

/// Confirms that `bytes` is exactly one well-formed, definite-length CBOR
/// item with no trailing bytes. Does not interpret field names or
/// values; typed decoding happens afterward.
pub fn check_definite_lengths(bytes: &[u8]) -> Result<(), StrictCborError> {
    let mut pos = 0usize;
    check_item(bytes, &mut pos, 0)?;
    if pos != bytes.len() {
        return Err(StrictCborError::TrailingBytes);
    }
    Ok(())
}

fn check_item(bytes: &[u8], pos: &mut usize, depth: u32) -> Result<(), StrictCborError> {
    if depth > MAX_DEPTH {
        return Err(StrictCborError::TooDeep);
    }
    let (major, arg) = read_head(bytes, pos)?;
    match major {
        // Unsigned int, negative int: the argument already read by
        // read_head is the entire value, nothing further to skip.
        0 | 1 => {}
        // Byte string, text string: skip `arg` content bytes.
        2 | 3 => {
            let len = usize::try_from(arg).map_err(|_| StrictCborError::Truncated)?;
            let end = pos.checked_add(len).ok_or(StrictCborError::Truncated)?;
            if end > bytes.len() {
                return Err(StrictCborError::Truncated);
            }
            *pos = end;
        }
        // Array: `arg` items follow.
        4 => {
            for _ in 0..arg {
                check_item(bytes, pos, depth + 1)?;
            }
        }
        // Map: `arg` key/value pairs follow.
        5 => {
            for _ in 0..arg {
                check_item(bytes, pos, depth + 1)?;
                check_item(bytes, pos, depth + 1)?;
            }
        }
        // Tag: one tagged item follows; `arg` itself is just the tag number.
        6 => {
            check_item(bytes, pos, depth + 1)?;
        }
        // Simple value or float: read_head already consumed every byte
        // this item has (the argument encodes the simple value or the
        // float bits directly), nothing further to skip.
        7 => {}
        _ => unreachable!("major type is a 3-bit field, always 0..=7"),
    }
    Ok(())
}

/// Reads one initial-byte head and its argument, advancing `pos` past
/// both. Returns `(major_type, argument)`. Rejects additional-info 31
/// (indefinite length) unconditionally: every context this scanner is
/// used in forbids it, so there is no major type for which seeing it is
/// valid input.
fn read_head(bytes: &[u8], pos: &mut usize) -> Result<(u8, u64), StrictCborError> {
    let head = *bytes.get(*pos).ok_or(StrictCborError::Truncated)?;
    *pos += 1;
    let major = head >> 5;
    let info = head & 0x1f;
    let arg = match info {
        0..=23 => u64::from(info),
        24 => read_uint::<1>(bytes, pos)?,
        25 => read_uint::<2>(bytes, pos)?,
        26 => read_uint::<4>(bytes, pos)?,
        27 => read_uint::<8>(bytes, pos)?,
        28..=30 => return Err(StrictCborError::Reserved),
        31 => return Err(StrictCborError::IndefiniteLength),
        _ => unreachable!("info is a 5-bit field, always 0..=31"),
    };
    Ok((major, arg))
}

fn read_uint<const K: usize>(bytes: &[u8], pos: &mut usize) -> Result<u64, StrictCborError> {
    let end = pos.checked_add(K).ok_or(StrictCborError::Truncated)?;
    if end > bytes.len() {
        return Err(StrictCborError::Truncated);
    }
    let mut buf = [0u8; 8];
    buf[8 - K..].copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(u64::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Probe {
        #[allow(dead_code)] // only the decode outcome matters below, not the value
        a: u8,
    }

    /// Empirical check (see the module doc): does ciborium/serde_derive
    /// already reject a duplicate of a known field on its own, with no
    /// help from this module? CBOR bytes for `{"a": 1, "a": 2}`: map(2),
    /// text-string key "a" (0x61 0x61), uint 1, text-string key "a"
    /// again, uint 2.
    #[test]
    fn ciborium_rejects_duplicate_known_field_without_our_help() {
        let bytes = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];
        let result: Result<Probe, _> = ciborium::from_reader(&bytes[..]);
        assert!(
            result.is_err(),
            "expected serde_derive's generated visitor to reject a duplicate \
             field on its own; if this ever starts passing, strict.rs needs \
             its own duplicate-key scan added back"
        );
    }

    #[test]
    fn well_formed_definite_map_passes() {
        // {"a": 1}: map(1), key "a", value 1.
        let bytes = [0xa1, 0x61, 0x61, 0x01];
        assert_eq!(check_definite_lengths(&bytes), Ok(()));
    }

    #[test]
    fn indefinite_length_map_is_rejected() {
        // {_ "a": 1}: indefinite map, key "a", value 1, break.
        let bytes = [0xbf, 0x61, 0x61, 0x01, 0xff];
        assert_eq!(
            check_definite_lengths(&bytes),
            Err(StrictCborError::IndefiniteLength)
        );
        // Confirm this is exactly the gap our scanner exists to close:
        // ciborium itself decodes this indefinite map without complaint.
        let decoded: Result<Probe, _> = ciborium::from_reader(&bytes[..]);
        assert!(decoded.is_ok());
    }

    #[test]
    fn indefinite_length_array_is_rejected() {
        // [_ 1, 2]: indefinite array, 1, 2, break.
        let bytes = [0x9f, 0x01, 0x02, 0xff];
        assert_eq!(
            check_definite_lengths(&bytes),
            Err(StrictCborError::IndefiniteLength)
        );
    }

    #[test]
    fn indefinite_length_byte_string_is_rejected() {
        // (_ h'01' h'02'): indefinite byte string made of two chunks, break.
        let bytes = [0x5f, 0x41, 0x01, 0x41, 0x02, 0xff];
        assert_eq!(
            check_definite_lengths(&bytes),
            Err(StrictCborError::IndefiniteLength)
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        // A complete `1` followed by a stray extra byte.
        let bytes = [0x01, 0x00];
        assert_eq!(
            check_definite_lengths(&bytes),
            Err(StrictCborError::TrailingBytes)
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        // Header claims a 4-byte string but only 1 byte follows.
        let bytes = [0x44, 0x01];
        assert_eq!(
            check_definite_lengths(&bytes),
            Err(StrictCborError::Truncated)
        );
    }

    #[test]
    fn deeply_nested_array_is_rejected() {
        // MAX_DEPTH + 2 levels of `[ ... ]`, each a definite 1-element array.
        let mut bytes = vec![0x81; (MAX_DEPTH + 2) as usize]; // array(1), repeated
        bytes.push(0x00); // innermost element: 0
        assert_eq!(
            check_definite_lengths(&bytes),
            Err(StrictCborError::TooDeep)
        );
    }
}
