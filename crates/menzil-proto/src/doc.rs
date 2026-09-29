//! Chunking and reassembly for the `DOC` record (protocol.md 4.2, 4.3):
//! splits an encoded document's bytes into `DocBody` chunks bounded by
//! [`MAX_DOC_CHUNK_BYTES`], and reassembles inbound chunks back into one
//! buffer, enforcing protocol.md 4.2's "whole document at most 1 MiB"
//! limit as bytes arrive rather than only once a transfer completes.
//!
//! What travels over DOC is always a whole `Signed<T>`'s own CBOR
//! encoding (protocol.md 4.2: "chunk is a raw byte slice of the
//! document's own encoded bytes"), not just the inner body — chunking
//! and reassembly here never look inside that further; decoding the
//! reassembled bytes into a typed, verified `Signed<T>` is the caller's
//! job, via [`crate::Signed::decode_strict`].

use std::collections::HashMap;

use thiserror::Error;

use crate::bytes::DocId;
use crate::record::{DocBody, DocType, Record};

/// protocol.md 4.2: "whole document at most 1 MiB".
pub const MAX_DOC_BYTES: usize = 1024 * 1024;

/// One DOC chunk's own payload size, chosen well under the Noise
/// transport message limit (protocol.md 3.3's 65,535 bytes, minus the
/// AEAD tag and this record's own fixed header — see `menzil-session`'s
/// `Transport` docs for the exact ciphertext accounting, which this
/// crate does not depend on and so does not import here). A
/// conservative, round number comfortably under the real maximum, not a
/// byte-exact one.
pub const MAX_DOC_CHUNK_BYTES: usize = 60_000;

/// How many distinct `doc_id` transfers [`DocReassembler`] tracks
/// concurrently before it refuses a new one; bounds the memory an
/// already-authenticated but misbehaving peer can make it hold for
/// abandoned transfers. protocol.md 10 has no stated figure for this —
/// DOC reassembly is new in this item — so this is a conservative,
/// documented implementation choice, not a spec value.
const MAX_CONCURRENT_TRANSFERS: usize = 8;

/// The highest `count` [`DocReassembler::accept`] tolerates a transfer
/// claiming, derived from the size limits themselves: no legitimate
/// transfer built by [`split_into_doc_records`] ever needs more than this
/// many chunks to carry [`MAX_DOC_BYTES`] at [`MAX_DOC_CHUNK_BYTES`] each.
/// Rejected up front, before a single chunk is stored: `count` is
/// otherwise bounded only by `u16` (up to 65,535), and
/// [`DocReassembler::accept`] recomputes its running total over every
/// chunk held so far on every call, so admitting a transfer with a
/// needlessly large `count` (nothing stops a chunk from being empty)
/// would let a peer spend a few hundred KB of traffic to cost this side
/// several seconds of CPU reassembling nothing.
const MAX_CHUNKS_PER_TRANSFER: u16 = MAX_DOC_BYTES.div_ceil(MAX_DOC_CHUNK_BYTES) as u16;

/// Splits `bytes` (a document's own encoded form, e.g. a `Signed<Roster>`
/// CBOR encoding) into one or more [`Record::Doc`] records sharing one
/// fresh, random `doc_id`, each carrying at most [`MAX_DOC_CHUNK_BYTES`].
///
/// `bytes` must not exceed [`MAX_DOC_BYTES`]. This is an internal
/// invariant a caller is expected to already know holds (every document
/// this crate's own types can sign and encode is far under the limit in
/// practice), not user input this function is meant to validate, so it
/// panics rather than returning a `Result` a caller would have no
/// sensible way to recover from.
pub fn split_into_doc_records(doc_type: DocType, bytes: &[u8]) -> Vec<Record> {
    assert!(
        bytes.len() <= MAX_DOC_BYTES,
        "document of {} bytes exceeds the {MAX_DOC_BYTES}-byte limit",
        bytes.len()
    );
    let mut doc_id_bytes = [0u8; 16];
    fastrand::fill(&mut doc_id_bytes);
    let doc_id = DocId::from(doc_id_bytes);

    let chunks: Vec<&[u8]> = if bytes.is_empty() {
        vec![&[][..]]
    } else {
        bytes.chunks(MAX_DOC_CHUNK_BYTES).collect()
    };
    let count = chunks.len() as u16;
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| {
            Record::Doc(DocBody {
                doc_type,
                doc_id,
                index: index as u16,
                count,
                chunk: chunk.to_vec(),
            })
        })
        .collect()
}

/// Failure from [`DocReassembler::accept`]. Every variant leaves the
/// reassembler in a valid state (the offending transfer, if any, is
/// dropped) — a caller may keep using the same instance for further
/// chunks or transfers afterward.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DocReassemblyError {
    /// This chunk's `count` was zero, or its `index` was not less than
    /// its own `count`.
    #[error("DOC chunk index {index} is not less than its own count {count}")]
    InvalidIndex {
        /// The offending index.
        index: u16,
        /// The offending count.
        count: u16,
    },
    /// A later chunk of this `doc_id` claimed a different `doc_type` or
    /// `count` than an earlier one did.
    #[error("DOC chunk for an in-progress transfer changed doc_type or count mid-transfer")]
    Inconsistent,
    /// The transfer's total bytes exceeded [`MAX_DOC_BYTES`] (protocol.md
    /// 4.2).
    #[error("document exceeds the {MAX_DOC_BYTES} byte limit")]
    TooLarge,
    /// A new `doc_id` arrived while [`MAX_CONCURRENT_TRANSFERS`] others
    /// were already in progress.
    #[error("too many concurrent DOC transfers in progress")]
    TooManyConcurrentTransfers,
}

struct Transfer {
    doc_type: DocType,
    count: u16,
    chunks: HashMap<u16, Vec<u8>>,
}

/// Reassembles inbound `DOC` chunks (protocol.md 4.2) into complete
/// document bytes, keyed by `doc_id`. One instance is meant to live for
/// one connection's whole lifetime; chunks from different connections
/// never share a `doc_id` namespace, so nothing here needs to know about
/// session or peer identity.
#[derive(Default)]
pub struct DocReassembler {
    in_progress: HashMap<DocId, Transfer>,
}

impl DocReassembler {
    /// No transfers in progress yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one chunk in. Returns the reassembled bytes and the
    /// transfer's `doc_type` once every chunk for its `doc_id` has
    /// arrived; `Ok(None)` while a transfer is still incomplete.
    pub fn accept(
        &mut self,
        body: &DocBody,
    ) -> Result<Option<(DocType, Vec<u8>)>, DocReassemblyError> {
        if body.count == 0 || body.index >= body.count {
            return Err(DocReassemblyError::InvalidIndex {
                index: body.index,
                count: body.count,
            });
        }
        if body.count > MAX_CHUNKS_PER_TRANSFER {
            return Err(DocReassemblyError::TooLarge);
        }

        let mismatched = self.in_progress.get(&body.doc_id).is_some_and(|existing| {
            existing.doc_type != body.doc_type || existing.count != body.count
        });
        if mismatched {
            self.in_progress.remove(&body.doc_id);
            return Err(DocReassemblyError::Inconsistent);
        }
        if !self.in_progress.contains_key(&body.doc_id)
            && self.in_progress.len() >= MAX_CONCURRENT_TRANSFERS
        {
            return Err(DocReassemblyError::TooManyConcurrentTransfers);
        }

        let transfer = self
            .in_progress
            .entry(body.doc_id)
            .or_insert_with(|| Transfer {
                doc_type: body.doc_type,
                count: body.count,
                chunks: HashMap::new(),
            });
        transfer.chunks.insert(body.index, body.chunk.clone());
        let total_len: usize = transfer.chunks.values().map(Vec::len).sum();
        let complete = transfer.chunks.len() == transfer.count as usize;

        if total_len > MAX_DOC_BYTES {
            self.in_progress.remove(&body.doc_id);
            return Err(DocReassemblyError::TooLarge);
        }
        if !complete {
            return Ok(None);
        }
        let transfer = self
            .in_progress
            .remove(&body.doc_id)
            .expect("just inserted or matched above");
        let mut out = Vec::with_capacity(total_len);
        for index in 0..transfer.count {
            out.extend_from_slice(&transfer.chunks[&index]);
        }
        Ok(Some((transfer.doc_type, out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble_all(records: &[Record]) -> Option<(DocType, Vec<u8>)> {
        let mut reassembler = DocReassembler::new();
        let mut result = None;
        for record in records {
            let Record::Doc(body) = record else {
                panic!("expected a Doc record")
            };
            if let Some(done) = reassembler.accept(body).unwrap() {
                assert!(result.is_none(), "completed twice");
                result = Some(done);
            }
        }
        result
    }

    #[test]
    fn a_single_chunk_document_round_trips() {
        let bytes = b"hello roster".to_vec();
        let records = split_into_doc_records(DocType::Roster, &bytes);
        assert_eq!(records.len(), 1);
        let (doc_type, out) = reassemble_all(&records).unwrap();
        assert_eq!(doc_type, DocType::Roster);
        assert_eq!(out, bytes);
    }

    #[test]
    fn an_empty_document_round_trips_as_one_empty_chunk() {
        let records = split_into_doc_records(DocType::Roster, &[]);
        assert_eq!(records.len(), 1);
        let (_, out) = reassemble_all(&records).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn a_multi_chunk_document_round_trips_in_order() {
        let bytes: Vec<u8> = (0..(MAX_DOC_CHUNK_BYTES * 3 + 17))
            .map(|i| (i % 256) as u8)
            .collect();
        let records = split_into_doc_records(DocType::Policy, &bytes);
        assert_eq!(records.len(), 4);
        let (doc_type, out) = reassemble_all(&records).unwrap();
        assert_eq!(doc_type, DocType::Policy);
        assert_eq!(out, bytes);
    }

    #[test]
    fn chunks_reassemble_out_of_order() {
        let bytes: Vec<u8> = (0..(MAX_DOC_CHUNK_BYTES * 2 + 5))
            .map(|i| (i % 256) as u8)
            .collect();
        let mut records = split_into_doc_records(DocType::Roster, &bytes);
        records.reverse();
        let (_, out) = reassemble_all(&records).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn interleaved_transfers_do_not_cross_contaminate() {
        let a = split_into_doc_records(DocType::Roster, b"first document");
        let b = split_into_doc_records(DocType::Roster, b"second, different document");
        let mut reassembler = DocReassembler::new();
        let Record::Doc(body_a) = &a[0] else {
            unreachable!()
        };
        let Record::Doc(body_b) = &b[0] else {
            unreachable!()
        };
        let (_, out_a) = reassembler.accept(body_a).unwrap().unwrap();
        let (_, out_b) = reassembler.accept(body_b).unwrap().unwrap();
        assert_eq!(out_a, b"first document");
        assert_eq!(out_b, b"second, different document");
    }

    #[test]
    fn zero_count_is_rejected() {
        let mut reassembler = DocReassembler::new();
        let body = DocBody {
            doc_type: DocType::Roster,
            doc_id: DocId::from([1u8; 16]),
            index: 0,
            count: 0,
            chunk: vec![],
        };
        assert_eq!(
            reassembler.accept(&body).unwrap_err(),
            DocReassemblyError::InvalidIndex { index: 0, count: 0 }
        );
    }

    #[test]
    fn an_index_not_below_count_is_rejected() {
        let mut reassembler = DocReassembler::new();
        let body = DocBody {
            doc_type: DocType::Roster,
            doc_id: DocId::from([1u8; 16]),
            index: 2,
            count: 2,
            chunk: vec![],
        };
        assert_eq!(
            reassembler.accept(&body).unwrap_err(),
            DocReassemblyError::InvalidIndex { index: 2, count: 2 }
        );
    }

    #[test]
    fn a_count_above_the_derived_chunk_cap_is_rejected_immediately() {
        // Regression test: this must be rejected on the very first
        // chunk, before any per-chunk bookkeeping happens at all — the
        // whole point of `MAX_CHUNKS_PER_TRANSFER` is to make a
        // needlessly-high `count` (many tiny or empty chunks) cheap to
        // refuse rather than something that costs real work to discover
        // is oversized only once enough chunks have accumulated.
        let mut reassembler = DocReassembler::new();
        let over_the_cap = MAX_CHUNKS_PER_TRANSFER + 1;
        let body = DocBody {
            doc_type: DocType::Roster,
            doc_id: DocId::from([5u8; 16]),
            index: 0,
            count: over_the_cap,
            chunk: vec![],
        };
        assert_eq!(
            reassembler.accept(&body).unwrap_err(),
            DocReassemblyError::TooLarge
        );
        assert_eq!(
            reassembler.in_progress.len(),
            0,
            "an over-the-cap transfer must never be stored, even partially"
        );
    }

    #[test]
    fn a_changed_count_mid_transfer_is_rejected_and_drops_the_transfer() {
        let mut reassembler = DocReassembler::new();
        let doc_id = DocId::from([2u8; 16]);
        reassembler
            .accept(&DocBody {
                doc_type: DocType::Roster,
                doc_id,
                index: 0,
                count: 2,
                chunk: vec![1],
            })
            .unwrap();
        let err = reassembler
            .accept(&DocBody {
                doc_type: DocType::Roster,
                doc_id,
                index: 1,
                count: 3,
                chunk: vec![2],
            })
            .unwrap_err();
        assert_eq!(err, DocReassemblyError::Inconsistent);

        // The dropped transfer does not linger: starting over with a
        // consistent count from scratch succeeds.
        reassembler
            .accept(&DocBody {
                doc_type: DocType::Roster,
                doc_id,
                index: 0,
                count: 1,
                chunk: vec![9],
            })
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_changed_doc_type_mid_transfer_is_rejected() {
        let mut reassembler = DocReassembler::new();
        let doc_id = DocId::from([3u8; 16]);
        reassembler
            .accept(&DocBody {
                doc_type: DocType::Roster,
                doc_id,
                index: 0,
                count: 2,
                chunk: vec![1],
            })
            .unwrap();
        let err = reassembler
            .accept(&DocBody {
                doc_type: DocType::Policy,
                doc_id,
                index: 1,
                count: 2,
                chunk: vec![2],
            })
            .unwrap_err();
        assert_eq!(err, DocReassemblyError::Inconsistent);
    }

    #[test]
    fn a_transfer_exceeding_the_size_limit_is_rejected() {
        let mut reassembler = DocReassembler::new();
        let doc_id = DocId::from([4u8; 16]);
        let big_chunk = vec![0u8; MAX_DOC_CHUNK_BYTES];
        // count claims enough chunks to exceed MAX_DOC_BYTES once
        // fully sized like the first.
        let count = (MAX_DOC_BYTES / MAX_DOC_CHUNK_BYTES + 2) as u16;
        for index in 0..count {
            let result = reassembler.accept(&DocBody {
                doc_type: DocType::Roster,
                doc_id,
                index,
                count,
                chunk: big_chunk.clone(),
            });
            if let Err(err) = result {
                assert_eq!(err, DocReassemblyError::TooLarge);
                return;
            }
        }
        panic!("expected TooLarge before every chunk was accepted");
    }

    #[test]
    fn more_than_the_concurrent_transfer_limit_is_rejected() {
        let mut reassembler = DocReassembler::new();
        for i in 0..MAX_CONCURRENT_TRANSFERS {
            reassembler
                .accept(&DocBody {
                    doc_type: DocType::Roster,
                    doc_id: DocId::from([i as u8; 16]),
                    index: 0,
                    count: 2,
                    chunk: vec![i as u8],
                })
                .unwrap();
        }
        let err = reassembler
            .accept(&DocBody {
                doc_type: DocType::Roster,
                doc_id: DocId::from([200u8; 16]),
                index: 0,
                count: 2,
                chunk: vec![],
            })
            .unwrap_err();
        assert_eq!(err, DocReassemblyError::TooManyConcurrentTransfers);
    }

    #[test]
    #[should_panic(expected = "exceeds the")]
    fn split_panics_on_a_document_over_the_limit() {
        let bytes = vec![0u8; MAX_DOC_BYTES + 1];
        split_into_doc_records(DocType::Roster, &bytes);
    }
}
