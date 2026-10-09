//! Reimplements just enough of yamux's own wire format (spec version 0,
//! <https://github.com/hashicorp/yamux/blob/master/spec.md>) to find where
//! one frame ends inside a byte buffer, without depending on the `yamux`
//! crate's internal `frame`/`header` modules — both `mod`, not `pub mod`,
//! in `yamux` 0.14.1, so nothing there is reachable from outside that
//! crate. The format itself (a 12 byte header: `u8 version | u8 type |
//! u16 flags | u32 stream_id | u32 length`, a `Data` frame's `length`
//! naming its body's byte count, every other type's `length` meaning
//! something else and carrying no body at all) is stable and
//! specification-defined, confirmed against `yamux` 0.14.1's own
//! `src/frame/header.rs` (`encode`/`decode`) and `src/frame/io.rs`
//! (`ReadState`) while writing this module, not assumed from memory.
//!
//! Why this crate needs its own copy of this logic at all, rather than
//! treating the bytes `yamux::Connection` reads and writes as an opaque
//! stream: protocol.md 5.3's wire table is explicit that one `MUX`-kind
//! [`menzil_proto::E2eDataBody`] carries "one yamux frame", not an
//! arbitrary byte chunk, and the 2026-09-26 red team review's finding 1
//! explains why that alignment matters operationally (relay-level
//! reordering or drops are caught by this project's own L4 reliable-class
//! contiguity check, not by yamux, which assumes a reliable ordered
//! transport and has no sequence numbers of its own). [`crate::record_io`]
//! is where that one-frame-per-record boundary is actually enforced, both
//! ways, using [`leading_frame_len`] to split `yamux`'s outbound byte
//! stream back into individual frames and to validate that an inbound
//! record is exactly one.

/// The serialized header size in bytes — fixed by the spec, reconfirmed
/// against `yamux::frame::header::HEADER_SIZE` (private to that crate, so
/// not reusable directly).
pub(crate) const HEADER_LEN: usize = 12;

/// An otherwise-well-formed header named a version or frame type this
/// module does not know. Both are detectable from the header's first two
/// bytes alone, before any body bytes are available, so this is never
/// returned merely because `buf` is a genuine, as-yet-incomplete prefix —
/// see [`leading_frame_len`]'s own docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameFormatError {
    /// Byte 0 was not `0` (yamux spec version 0 is the only version this
    /// crate, or `yamux` 0.14.1 itself, speaks).
    #[error("unsupported yamux frame version {0} (menzil-stream only speaks yamux spec version 0)")]
    Version(u8),
    /// Byte 1 was not one of the four frame types the spec defines (`0`
    /// Data, `1` WindowUpdate, `2` Ping, `3` GoAway).
    #[error("unknown yamux frame type {0}")]
    Type(u8),
    /// [`is_exactly_one_frame`] found a buffer that was not exactly one
    /// well-formed frame: either too short to complete the frame its own
    /// header describes, or longer than that one frame (trailing bytes).
    /// Never produced by [`leading_frame_len`] itself, which only ever
    /// reports where a leading frame ends, never objects to what follows
    /// it.
    #[error("buffer of {len} bytes is not exactly one well-formed yamux frame")]
    NotExactlyOneFrame {
        /// The buffer's own length, for a useful error message.
        len: usize,
    },
    /// A Data frame's header declared a body `length` so large that
    /// `HEADER_LEN + length` does not fit in this platform's `usize` —
    /// unreachable on any 64 bit target (where `usize` comfortably
    /// outranges any `u32` length), but a real, checked possibility on a
    /// 32 bit one, found by a 2026-10-02 red team review of this crate
    /// (`wasm32` build; the untrusted-input path this guards,
    /// [`is_exactly_one_frame`], can only ever see a buffer at most a few
    /// tens of KiB long anyway, so any `length` this large is already
    /// nonsensical before this check even runs). Computing `total` via
    /// [`u64`] and checking the final cast, rather than adding directly
    /// in `usize`, is what turns a silent wraparound (which on a 32 bit
    /// target could make an oversized declared length read back as a
    /// small, satisfiable one — the review's own finding) into this
    /// explicit error instead.
    #[error("a declared frame length of {length} does not fit this platform's usize")]
    LengthOverflow {
        /// The frame header's own declared body length.
        length: u32,
    },
}

/// The total size (header plus body) of the frame whose leading bytes are
/// `prefix`, as soon as `prefix` holds the whole 12 byte header and not
/// before: `Ok(None)` means `prefix` is a genuine prefix of a well-formed
/// header that simply needs more bytes before a length can be known
/// (never returned for an actually-invalid one — version and type are both
/// checked as soon as their own byte is available, before the length
/// field is consulted). Does *not* require the body to be present, unlike
/// [`leading_frame_len`]: [`crate::record_io::RecordIo::poll_write`] needs
/// the answer before it has accepted the body bytes, to decide whether
/// accepting them would complete a frame it has nowhere to put yet.
pub(crate) fn declared_frame_len(prefix: &[u8]) -> Result<Option<usize>, FrameFormatError> {
    // Version and type are each checked the moment their own one byte is
    // in, independently of the rest of the 12 byte header: both are
    // cheap, fixed-position checks, and failing fast on either avoids
    // accumulating bytes behind a header that (whatever its declared
    // length later turns out to be) can never resolve to a frame this
    // module understands.
    let Some(&version) = prefix.first() else {
        return Ok(None);
    };
    if version != 0 {
        return Err(FrameFormatError::Version(version));
    }
    let Some(&tag) = prefix.get(1) else {
        return Ok(None);
    };
    if !matches!(tag, 0..=3) {
        return Err(FrameFormatError::Type(tag));
    }
    if prefix.len() < HEADER_LEN {
        return Ok(None);
    }
    let total = match tag {
        // Data: header, then a body of exactly `length` bytes. Computed
        // in `u64` and only then cast down — see
        // `FrameFormatError::LengthOverflow`'s own doc comment for why a
        // direct `usize` addition is not safe on every platform.
        0 => {
            let length = u32::from_be_bytes([prefix[8], prefix[9], prefix[10], prefix[11]]);
            let total = HEADER_LEN as u64 + length as u64;
            usize::try_from(total).map_err(|_| FrameFormatError::LengthOverflow { length })?
        }
        // WindowUpdate, Ping, GoAway: header only. `length` means credit,
        // ping id, or error code respectively — never a body size.
        _ => HEADER_LEN,
    };
    Ok(Some(total))
}

/// How many bytes `buf`'s leading yamux frame occupies, once that many
/// are actually present: `Ok(None)` means `buf` is a genuine prefix of a
/// well-formed frame that simply needs more bytes before a length can be
/// known (never returned for an actually-invalid header — version and
/// type are both checked as soon as the first two bytes are available,
/// before the length field or any body is consulted).
pub(crate) fn leading_frame_len(buf: &[u8]) -> Result<Option<usize>, FrameFormatError> {
    Ok(declared_frame_len(buf)?.filter(|&total| buf.len() >= total))
}

/// Whether `buf` is *exactly* one well-formed yamux frame — no fewer
/// bytes (an incomplete frame) and no more (trailing bytes after one).
/// This, not [`leading_frame_len`], is what validates an inbound `Mux`
/// record end to end: protocol.md 5.3 states a `Mux` body *is* one yamux
/// frame, not a prefix or a concatenation of several (see
/// [`crate::error::StreamMuxError::MalformedFrame`]'s doc comment for
/// what a caller does with the error this produces).
pub(crate) fn is_exactly_one_frame(buf: &[u8]) -> Result<(), FrameFormatError> {
    match leading_frame_len(buf)? {
        Some(len) if len == buf.len() => Ok(()),
        _ => Err(FrameFormatError::NotExactlyOneFrame { len: buf.len() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u8, tag: u8, length: u32) -> Vec<u8> {
        let mut buf = vec![version, tag, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&length.to_be_bytes());
        buf
    }

    #[test]
    fn incomplete_header_needs_more_bytes() {
        let buf = header(0, 0, 5);
        for n in 0..HEADER_LEN {
            assert_eq!(leading_frame_len(&buf[..n]), Ok(None), "n={n}");
        }
    }

    #[test]
    fn data_frame_needs_its_full_body_before_resolving() {
        let mut buf = header(0, 0, 5);
        buf.extend_from_slice(b"hello");
        for n in HEADER_LEN..buf.len() {
            assert_eq!(leading_frame_len(&buf[..n]), Ok(None), "n={n}");
        }
        assert_eq!(leading_frame_len(&buf), Ok(Some(buf.len())));
    }

    #[test]
    fn a_zero_length_data_frame_is_exactly_the_header() {
        let buf = header(0, 0, 0);
        assert_eq!(leading_frame_len(&buf), Ok(Some(HEADER_LEN)));
    }

    #[test]
    fn control_frames_never_wait_on_a_body_even_with_a_nonzero_length_field() {
        // WindowUpdate (1), Ping (2), GoAway (3): `length` is credit / id /
        // code, not a body size, so the frame is complete at the header.
        for tag in [1u8, 2, 3] {
            let buf = header(0, tag, 0xffff_ffff);
            assert_eq!(leading_frame_len(&buf), Ok(Some(HEADER_LEN)), "tag={tag}");
        }
    }

    #[test]
    fn trailing_bytes_past_one_frame_are_not_consumed() {
        let mut buf = header(0, 0, 3);
        buf.extend_from_slice(b"abc");
        buf.extend_from_slice(b"next frame's bytes go here");
        assert_eq!(leading_frame_len(&buf), Ok(Some(HEADER_LEN + 3)));
    }

    #[test]
    fn an_unknown_version_is_rejected_as_soon_as_its_byte_is_available() {
        let buf = header(1, 0, 0);
        assert_eq!(
            leading_frame_len(&buf[..1]),
            Err(FrameFormatError::Version(1))
        );
    }

    #[test]
    fn an_unknown_type_is_rejected_as_soon_as_its_byte_is_available() {
        let buf = header(0, 4, 0);
        assert_eq!(leading_frame_len(&buf[..2]), Err(FrameFormatError::Type(4)));
    }

    #[test]
    fn exactly_one_frame_is_accepted() {
        let mut buf = header(0, 0, 3);
        buf.extend_from_slice(b"abc");
        assert_eq!(is_exactly_one_frame(&buf), Ok(()));
    }

    #[test]
    fn a_short_buffer_is_not_exactly_one_frame() {
        let mut buf = header(0, 0, 3);
        buf.extend_from_slice(b"abc");
        let short = &buf[..buf.len() - 1];
        assert_eq!(
            is_exactly_one_frame(short),
            Err(FrameFormatError::NotExactlyOneFrame { len: short.len() })
        );
    }

    #[test]
    fn trailing_bytes_after_one_frame_are_not_exactly_one_frame() {
        let mut buf = header(0, 0, 3);
        buf.extend_from_slice(b"abc");
        buf.push(0xff);
        assert_eq!(
            is_exactly_one_frame(&buf),
            Err(FrameFormatError::NotExactlyOneFrame { len: buf.len() })
        );
    }

    #[test]
    fn a_bare_control_frame_is_exactly_one_frame() {
        let buf = header(0, 2, 42); // Ping
        assert_eq!(is_exactly_one_frame(&buf), Ok(()));
    }

    #[test]
    fn a_data_frames_total_is_known_from_its_header_alone() {
        let buf = header(0, 0, 5);
        for n in 0..HEADER_LEN {
            assert_eq!(declared_frame_len(&buf[..n]), Ok(None), "n={n}");
        }
        // No body bytes present at all, yet the total is already known —
        // the difference from `leading_frame_len`, which would say `None`.
        assert_eq!(declared_frame_len(&buf), Ok(Some(HEADER_LEN + 5)));
        assert_eq!(leading_frame_len(&buf), Ok(None));
    }

    #[test]
    fn a_control_frames_declared_total_is_the_header_whatever_its_length_field_says() {
        for tag in [1u8, 2, 3] {
            let buf = header(0, tag, 0xffff_ffff);
            assert_eq!(declared_frame_len(&buf), Ok(Some(HEADER_LEN)), "tag={tag}");
        }
    }

    #[test]
    fn declared_frame_len_rejects_a_bad_version_or_type_before_the_header_is_complete() {
        assert_eq!(declared_frame_len(&[1]), Err(FrameFormatError::Version(1)));
        assert_eq!(declared_frame_len(&[0, 9]), Err(FrameFormatError::Type(9)));
        assert_eq!(declared_frame_len(&[]), Ok(None));
        assert_eq!(declared_frame_len(&[0]), Ok(None));
    }
}
