// Copyright (c) 2019 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 or MIT license, at your option.
//
// A copy of the Apache License, Version 2.0 is included in the software as
// LICENSE-APACHE and a copy of the MIT license is included in the software
// as LICENSE-MIT. You may also obtain a copy of the Apache License, Version 2.0
// at https://www.apache.org/licenses/LICENSE-2.0 and a copy of the MIT license
// at https://opensource.org/licenses/MIT.

use std::{collections::VecDeque, io};

/// menzil patch: a body shorter than this is appended to the previous chunk, see
/// [`Chunks::push`].
const COALESCE_BELOW: usize = 1024;

/// menzil patch: a chunk grown by appending never holds more than this many bytes.
const COALESCE_UP_TO: usize = 8 * 1024;

/// A sequence of [`Chunk`] values.
///
/// [`Chunks::len`] considers all [`Chunk`] elements and computes the total
/// result, i.e. the length of all bytes, by summing up the lengths of all
/// [`Chunk`] elements.
#[derive(Debug)]
pub(crate) struct Chunks {
    seq: VecDeque<Chunk>,
    len: usize,
}

impl Chunks {
    /// A new empty chunk list.
    pub(crate) fn new() -> Self {
        Chunks {
            seq: VecDeque::new(),
            len: 0,
        }
    }

    /// The total length of bytes yet-to-be-read in all `Chunk`s.
    pub(crate) fn len(&self) -> usize {
        self.len - self.seq.front().map(|c| c.offset()).unwrap_or(0)
    }

    /// Add another chunk of bytes to the end.
    ///
    /// menzil patch (vendor/yamux/PATCHES.md, patch 1): a body shorter than [`COALESCE_BELOW`]
    /// is appended to the last chunk while that chunk stays within [`COALESCE_UP_TO`], instead
    /// of becoming a chunk of its own. A chunk costs a `Vec` and a queue slot, about 65 bytes
    /// of heap, while the receive window charges only the body's length, so without this a
    /// peer cutting its data into one-byte frames makes every byte of window cost 65 bytes of
    /// memory. With it, every chunk but the first and the last holds at least
    /// [`COALESCE_BELOW`] bytes, or follows a chunk of more than `COALESCE_UP_TO -
    /// COALESCE_BELOW` bytes, so the memory held is a small constant factor of the window
    /// (about twice, at worst: appending to an exact-fit body doubles its capacity). The cap
    /// compares the whole `Vec`, consumed bytes included, so a chunk a reader keeps up with
    /// still fills and is replaced. The byte stream a reader sees is the same; only the
    /// boundaries of the `Packet`s of the `futures::Stream` impl move.
    pub(crate) fn push(&mut self, x: Vec<u8>) {
        self.len += x.len();
        if x.is_empty() {
            return;
        }
        if x.len() < COALESCE_BELOW {
            if let Some(last) = self.seq.back_mut() {
                if last.cursor.get_ref().len() + x.len() <= COALESCE_UP_TO {
                    last.cursor.get_mut().extend_from_slice(&x);
                    return;
                }
            }
        }
        self.seq.push_back(Chunk {
            cursor: io::Cursor::new(x),
        })
    }

    /// Remove and return the first chunk.
    pub(crate) fn pop(&mut self) -> Option<Chunk> {
        let chunk = self.seq.pop_front();
        self.len -= chunk.as_ref().map(|c| c.len() + c.offset()).unwrap_or(0);
        chunk
    }

    /// Get a mutable reference to the first chunk.
    pub(crate) fn front_mut(&mut self) -> Option<&mut Chunk> {
        self.seq.front_mut()
    }
}

/// A `Chunk` wraps a `std::io::Cursor<Vec<u8>>`.
///
/// It provides a byte-slice view and a way to advance the cursor so the
/// vector can be consumed in steps.
#[derive(Debug)]
pub(crate) struct Chunk {
    cursor: io::Cursor<Vec<u8>>,
}

impl Chunk {
    /// Is this chunk empty?
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The remaining number of bytes in this `Chunk`.
    pub(crate) fn len(&self) -> usize {
        self.cursor.get_ref().len() - self.offset()
    }

    /// The sum of bytes that the cursor has been `advance`d over.
    pub(crate) fn offset(&self) -> usize {
        self.cursor.position() as usize
    }

    /// Move the cursor position by `amount` bytes.
    ///
    /// The `AsRef<[u8]>` impl of `Chunk` provides a byte-slice view
    /// from the current position to the end.
    pub(crate) fn advance(&mut self, amount: usize) {
        assert!({
            // the new position must not exceed the vector's length
            let pos = self.offset().checked_add(amount);
            let max = self.cursor.get_ref().len();
            pos.is_some() && pos <= Some(max)
        });

        self.cursor
            .set_position(self.cursor.position() + amount as u64);
    }

    /// Consume `self` and return the inner vector.
    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.cursor.into_inner()
    }
}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        &self.cursor.get_ref()[self.offset()..]
    }
}

// menzil patch: tests for the coalescing in `Chunks::push`.
#[cfg(test)]
mod tests {
    use super::*;

    /// Takes every chunk out the way a reader finishing the stream would.
    fn drain(chunks: &mut Chunks) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(chunk) = chunks.pop() {
            out.extend_from_slice(chunk.as_ref());
        }
        out
    }

    #[test]
    fn one_byte_bodies_share_chunks() {
        let mut chunks = Chunks::new();
        for i in 0..100_000u32 {
            chunks.push(vec![(i % 251) as u8]);
        }
        assert_eq!(chunks.len(), 100_000);
        // Every chunk is filled to the cap before the next one starts.
        assert_eq!(chunks.seq.len(), 100_000usize.div_ceil(COALESCE_UP_TO));
        let bytes = drain(&mut chunks);
        assert_eq!(bytes.len(), 100_000);
        assert!(bytes.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn a_chunk_may_be_filled_exactly_to_the_cap() {
        let mut chunks = Chunks::new();
        for _ in 0..COALESCE_UP_TO {
            chunks.push(vec![7]);
        }
        assert_eq!(chunks.seq.len(), 1);
        chunks.push(vec![7]);
        assert_eq!(chunks.seq.len(), 2);
    }

    #[test]
    fn a_body_at_the_threshold_keeps_a_chunk_of_its_own() {
        let mut chunks = Chunks::new();
        chunks.push(vec![1; COALESCE_BELOW]);
        chunks.push(vec![2; COALESCE_BELOW]);
        assert_eq!(chunks.seq.len(), 2);
        // One byte shorter is a short body: it joins the last chunk.
        chunks.push(vec![3; COALESCE_BELOW - 1]);
        assert_eq!(chunks.seq.len(), 2);
        assert_eq!(chunks.len(), 3 * COALESCE_BELOW - 1);
    }

    #[test]
    fn a_short_body_that_would_pass_the_cap_starts_a_new_chunk() {
        let mut chunks = Chunks::new();
        chunks.push(vec![0; COALESCE_UP_TO]);
        chunks.push(vec![1]);
        assert_eq!(chunks.seq.len(), 2);
        chunks.push(vec![2]);
        assert_eq!(chunks.seq.len(), 2);
        let bytes = drain(&mut chunks);
        assert_eq!(bytes.len(), COALESCE_UP_TO + 2);
        assert_eq!(&bytes[COALESCE_UP_TO..], &[1, 2]);
    }

    #[test]
    fn len_stays_exact_when_a_partly_read_chunk_grows() {
        let mut chunks = Chunks::new();
        chunks.push(vec![1, 2, 3, 4, 5]);
        chunks.front_mut().unwrap().advance(3);
        assert_eq!(chunks.len(), 2);
        // Appended to the chunk the reader is in the middle of.
        chunks.push(vec![6, 7]);
        assert_eq!(chunks.seq.len(), 1);
        assert_eq!(chunks.len(), 4);
        let chunk = chunks.pop().unwrap();
        assert_eq!(chunk.as_ref(), &[4, 5, 6, 7]);
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn a_fully_read_chunk_still_takes_an_appended_body() {
        let mut chunks = Chunks::new();
        chunks.push(vec![1, 2]);
        let front = chunks.front_mut().unwrap();
        front.advance(2);
        assert!(front.is_empty());
        chunks.push(vec![3]);
        assert_eq!(chunks.len(), 1);
        assert!(!chunks.front_mut().unwrap().is_empty());
        assert_eq!(drain(&mut chunks), vec![3]);
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn empty_bodies_are_dropped() {
        let mut chunks = Chunks::new();
        chunks.push(Vec::new());
        assert_eq!(chunks.seq.len(), 0);
        assert_eq!(chunks.len(), 0);
        chunks.push(vec![1]);
        chunks.push(Vec::new());
        assert_eq!(chunks.seq.len(), 1);
        assert_eq!(chunks.len(), 1);
    }

    /// A reader that keeps up with the writer must not make a chunk grow without bound: the
    /// cap compares the length of the whole `Vec`, not what is left unread in it. Mirrors the
    /// `poll_read` loop (an empty front chunk is popped when the next read finds it).
    #[test]
    fn a_reader_that_keeps_pace_does_not_make_a_chunk_grow_without_bound() {
        let mut chunks = Chunks::new();
        let mut buf = [0u8; 100];
        for round in 0..20_000u32 {
            for i in 0..100u32 {
                chunks.push(vec![(round + i) as u8]);
            }
            // What `poll_read` does for a 100 byte buffer.
            let mut n = 0;
            while let Some(chunk) = chunks.front_mut() {
                if chunk.is_empty() {
                    chunks.pop();
                    continue;
                }
                let k = std::cmp::min(chunk.len(), buf.len() - n);
                buf[n..n + k].copy_from_slice(&chunk.as_ref()[..k]);
                n += k;
                chunk.advance(k);
                if n == buf.len() {
                    break;
                }
            }
            assert_eq!(n, 100);
            assert_eq!(chunks.len(), 0);
            for (i, b) in buf.iter().enumerate() {
                assert_eq!(*b, (round + i as u32) as u8);
            }
            assert!(chunks.seq.len() <= 2, "{} chunks", chunks.seq.len());
            let widest = chunks
                .seq
                .iter()
                .map(|c| c.cursor.get_ref().len())
                .max()
                .unwrap_or(0);
            assert!(
                widest <= COALESCE_UP_TO + COALESCE_BELOW,
                "a chunk of {widest} bytes"
            );
        }
    }

    /// Whatever sizes arrive, the bytes come out unchanged and in order, and the chunk count
    /// stays proportional to the bytes held, so memory cannot be inflated by cutting the data
    /// into small bodies: every chunk but the first and the last holds at least
    /// `COALESCE_BELOW` bytes, or follows one holding more than `COALESCE_UP_TO -
    /// COALESCE_BELOW`.
    #[test]
    fn chunk_count_is_bounded_whatever_the_body_sizes() {
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..60usize {
            let max = [3, 40, 700, 1100, 3000, 9000][round % 6];
            let mut chunks = Chunks::new();
            let mut expected = Vec::new();
            for _ in 0..1500 {
                let n = 1 + next() as usize % max;
                let body: Vec<u8> = (0..n).map(|_| next() as u8).collect();
                expected.extend_from_slice(&body);
                chunks.push(body);
                let total = expected.len();
                assert!(
                    chunks.seq.len()
                        <= total / COALESCE_BELOW + total / (COALESCE_UP_TO - COALESCE_BELOW) + 2,
                    "{} chunks for {total} bytes",
                    chunks.seq.len(),
                );
            }
            assert_eq!(chunks.len(), expected.len());
            assert_eq!(drain(&mut chunks), expected);
        }
    }
}
