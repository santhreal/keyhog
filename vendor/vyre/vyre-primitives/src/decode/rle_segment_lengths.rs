//! `rle_segment_lengths` — run-length-encoded segment-length scan with
//! per-segment output start positions.
//!
//! Op id: `vyre-primitives::decode::rle_segment_lengths`. Soundness: `Exact`
//! over the RLE segment header layout where each segment is a (length, value)
//! pair packed into one u32. The CPU reference at the bottom of this file is
//! the contract.
//!
//! ## Why it matters
//!
//! Block-oriented compression formats (LZ4 literal/match runs, zstd FSE
//! literal counts, PNG IDAT zlib chunks, snappy raw runs) decode via a
//! sequence of "emit N copies of value V" segments. The bottleneck on GPU
//! is figuring out *where each segment writes* — segment K's output offset
//! depends on the cumulative segment-length sum of segments 0..K. Naive
//! sequential scan serializes the whole decode.
//!
//! This primitive ships the prefix-sum pre-pass: read the segment headers,
//! emit a per-segment "starts here" offset array. Once each thread knows
//! its absolute output range it can launch a separate, fully parallel,
//! load-balanced expand pass. This is the LZ4-style "decode in two passes"
//! trick lifted to the GPU.
//!
//! ## Wire layout
//!
//! Inputs:
//!   - `segments_in` — u32 stream where each u32 packs `(length << 8) | value`
//!     (24-bit length max ≈ 16 MB per segment, 8-bit value).
//!
//! Outputs:
//!   - `segment_lengths_out` — u32 per segment: just the length field.
//!   - `segment_values_out` — u32 per segment: just the value field
//!     (zero-extended into u32; consumer down-casts to u8).
//!
//! The prefix-sum that converts `segment_lengths_out` into per-segment
//! start offsets is the existing `prefix_scan` primitive (math/#5).
//! This module emits the unpacked length + value arrays it consumes.
//!
//! ## Why split, not fuse
//!
//! Splitting unpack from prefix-sum is the right separation: the unpack is
//! one-load-per-segment with no inter-thread dependency, while prefix-sum
//! is a tree-reduction with logarithmic-depth communication. Different
//! launch-grid shapes, different optimization trade-offs. Fusing them
//! would force the prefix-sum to wait on the unpack inside the same
//! warp's lifetime — strictly worse occupancy.

use std::sync::Arc;

use vyre_foundation::ir::model::expr::Ident;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

/// Canonical op id for region-chain audits and bench attribution.
pub const OP_ID: &str = "vyre-primitives::decode::rle_segment_lengths";

/// Canonical binding indices.
pub const BINDING_SEGMENTS_IN: u32 = 0;
/// Per-segment length output binding.
pub const BINDING_SEGMENT_LENGTHS_OUT: u32 = 1;
/// Per-segment value output binding.
pub const BINDING_SEGMENT_VALUES_OUT: u32 = 2;

/// Maximum segment length representable in the 24-bit length field
/// (= 16777215 ≈ 16 MB per segment).
pub const MAX_SEGMENT_LENGTH: u32 = (1 << 24) - 1;

/// Maximum segment value representable in the 8-bit value field.
pub const MAX_SEGMENT_VALUE: u32 = 0xFF;

/// Pack errors raised by the host-side packer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PackError {
    /// Segment length exceeded the 24-bit field budget.
    LengthTooLarge {
        /// The segment index whose length overflowed.
        segment: usize,
        /// The length that exceeded `MAX_SEGMENT_LENGTH`.
        length: u32,
    },
    /// Segment value exceeded the 8-bit field budget.
    ValueTooLarge {
        /// The segment index whose value overflowed.
        segment: usize,
        /// The value that exceeded `MAX_SEGMENT_VALUE`.
        value: u32,
    },
}

/// Build the IR `Program` that unpacks `(length, value)` segments from the
/// packed RLE header stream.
///
/// One thread per segment. Each thread:
///   1. Loads `segments_in[gid]`.
///   2. Extracts `length = segment >> 8` and `value = segment & 0xFF`.
///   3. Stores both into the per-segment output buffers.
///
/// `segment_count` must be > 0; workgroup size is fixed at 256 lanes.
#[must_use]
pub fn rle_segment_lengths(segment_count: u32) -> Program {
    let body = vec![
        Node::let_bind("seg_idx", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(Expr::var("seg_idx"), Expr::u32(segment_count)),
            vec![
                Node::let_bind("packed", Expr::load("segments_in", Expr::var("seg_idx"))),
                Node::let_bind("length", Expr::shr(Expr::var("packed"), Expr::u32(8))),
                Node::let_bind("value", Expr::bitand(Expr::var("packed"), Expr::u32(0xFF))),
                Node::store(
                    "segment_lengths_out",
                    Expr::var("seg_idx"),
                    Expr::var("length"),
                ),
                Node::store(
                    "segment_values_out",
                    Expr::var("seg_idx"),
                    Expr::var("value"),
                ),
            ],
        ),
    ];

    let buffers = vec![
        BufferDecl::storage(
            "segments_in",
            BINDING_SEGMENTS_IN,
            BufferAccess::ReadOnly,
            DataType::U32,
        )
        .with_count(segment_count),
        BufferDecl::storage(
            "segment_lengths_out",
            BINDING_SEGMENT_LENGTHS_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(segment_count),
        BufferDecl::storage(
            "segment_values_out",
            BINDING_SEGMENT_VALUES_OUT,
            BufferAccess::ReadWrite,
            DataType::U32,
        )
        .with_count(segment_count),
    ];

    let entry = vec![Node::Region {
        generator: Ident::from(OP_ID),
        source_region: None,
        body: Arc::new(body),
    }];
    Program::wrapped(buffers, [256, 1, 1], entry)
}

/// Pack `(length, value)` pairs into the canonical u32 wire format.
///
/// # Errors
///
/// Returns the first encoding overflow encountered. Caller fixes by
/// splitting overlong segments (length > 24 bits) or refusing to
/// register a value > 255.
pub fn pack_rle_segments(segments: &[(u32, u8)]) -> Result<Vec<u32>, PackError> {
    let mut packed = Vec::with_capacity(segments.len());
    pack_rle_segments_into(segments, &mut packed)?;
    Ok(packed)
}

/// Pack `(length, value)` pairs into caller-owned storage.
///
/// Clears `out`, then reuses its capacity.
///
/// # Errors
///
/// Returns the first encoding overflow encountered. On error, `out` is
/// cleared and contains only segments packed before the failing one.
pub fn pack_rle_segments_into(segments: &[(u32, u8)], out: &mut Vec<u32>) -> Result<(), PackError> {
    out.clear();
    out.reserve(segments.len());
    for (idx, (length, value)) in segments.iter().enumerate() {
        if *length > MAX_SEGMENT_LENGTH {
            return Err(PackError::LengthTooLarge {
                segment: idx,
                length: *length,
            });
        }
        let value_u32 = u32::from(*value);
        if value_u32 > MAX_SEGMENT_VALUE {
            // Unreachable for u8 input but kept defensively for parallel
            // u16/u32 entry points added later.
            return Err(PackError::ValueTooLarge {
                segment: idx,
                value: value_u32,
            });
        }
        out.push((length << 8) | value_u32);
    }
    Ok(())
}

/// CPU reference. Returns `(lengths, values)` matching the GPU `Program`
/// lane-for-lane.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn rle_segment_lengths_cpu(segments_in: &[u32]) -> (Vec<u32>, Vec<u32>) {
    let mut lengths = Vec::new();
    let mut values = Vec::new();
    rle_segment_lengths_cpu_into(segments_in, &mut lengths, &mut values);
    (lengths, values)
}

/// CPU reference into caller-owned output buffers.
///
/// Clears `lengths` and `values`, then reuses their allocations.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn rle_segment_lengths_cpu_into(
    segments_in: &[u32],
    lengths: &mut Vec<u32>,
    values: &mut Vec<u32>,
) {
    lengths.clear();
    values.clear();
    lengths.reserve(segments_in.len());
    values.reserve(segments_in.len());
    for packed in segments_in {
        lengths.push(packed >> 8);
        values.push(packed & 0xFF);
    }
}

/// Compute per-segment output start offsets via exclusive prefix sum
/// over `segment_lengths`. CPU reference for the canonical
/// "RLE → expand-pass start offsets" pipeline. The GPU version of this
/// step is `math::prefix_scan` (#5).
///
/// Returns `(start_offsets, total_output_length)`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn rle_segment_start_offsets_cpu(segment_lengths: &[u32]) -> (Vec<u32>, u32) {
    let mut offsets = Vec::new();
    let total = rle_segment_start_offsets_cpu_into(segment_lengths, &mut offsets);
    (offsets, total)
}

/// Compute exclusive start offsets into caller-owned storage.
///
/// Clears `offsets`, then reuses its capacity. Returns the saturated total
/// output length.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn rle_segment_start_offsets_cpu_into(segment_lengths: &[u32], offsets: &mut Vec<u32>) -> u32 {
    offsets.clear();
    offsets.reserve(segment_lengths.len());
    let mut acc: u32 = 0;
    for length in segment_lengths {
        offsets.push(acc);
        acc = acc.saturating_add(*length);
    }
    acc
}

/// Decode a packed RLE stream to its expanded byte sequence. Composes
/// the unpack + start-offset + emit-bytes passes. CPU reference for
/// end-to-end RLE decode used by integration tests.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn rle_decode_cpu(segments_in: &[u32]) -> Vec<u8> {
    let mut output = Vec::new();
    rle_decode_cpu_into(segments_in, &mut output);
    output
}

/// Decode packed RLE into caller-owned output storage.
///
/// Clears `output`, pre-reserves the saturated decoded byte length, and emits
/// each run directly from the packed header stream without building temporary
/// length/value vectors.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn rle_decode_cpu_into(segments_in: &[u32], output: &mut Vec<u8>) {
    output.clear();
    let total = segments_in
        .iter()
        .map(|packed| packed >> 8)
        .fold(0_u32, u32::saturating_add);
    output.reserve(total as usize);
    for packed in segments_in {
        let length = (packed >> 8) as usize;
        let value = (packed & 0xFF) as u8;
        let new_len = output.len().saturating_add(length);
        output.resize(new_len, value);
    }
}

#[cfg(feature = "inventory-registry")]
fn fixture_u32(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

#[cfg(feature = "inventory-registry")]
inventory::submit! {
    crate::harness::OpEntry::new(
        OP_ID,
        || rle_segment_lengths(3),
        Some(|| {
            let packed = pack_rle_segments(&[(2, b'A'), (0, b'X'), (3, b'B')])
                .unwrap_or_else(|_| unreachable!("fixture RLE segments fit the 24-bit length field"));
            vec![vec![
                fixture_u32(&packed),
                fixture_u32(&[0, 0, 0]),
                fixture_u32(&[0, 0, 0]),
            ]]
        }),
        Some(|| vec![vec![
            fixture_u32(&[2, 0, 3]),
            fixture_u32(&[u32::from(b'A'), u32::from(b'X'), u32::from(b'B')]),
        ]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_then_unpack_round_trips_simple_segments() {
        let segments = [(1u32, 0xABu8), (5u32, 0xCDu8)];
        let packed = pack_rle_segments(&segments).expect("pack must succeed");
        let (lengths, values) = rle_segment_lengths_cpu(&packed);
        assert_eq!(lengths, vec![1, 5]);
        assert_eq!(values, vec![0xAB, 0xCD]);
    }

    #[test]
    fn pack_rejects_length_at_field_boundary() {
        let segments = [(1u32 << 24, 0u8)]; // exactly the limit + 1
        match pack_rle_segments(&segments) {
            Err(PackError::LengthTooLarge { segment: 0, length }) => {
                assert_eq!(length, 1u32 << 24);
            }
            other => panic!("expected LengthTooLarge at the 24-bit boundary; got {other:?}"),
        }
    }

    #[test]
    fn pack_handles_max_representable_length() {
        let segments = [(MAX_SEGMENT_LENGTH, 0xFFu8)];
        let packed = pack_rle_segments(&segments).expect("max-length must pack");
        let (lengths, values) = rle_segment_lengths_cpu(&packed);
        assert_eq!(lengths, vec![MAX_SEGMENT_LENGTH]);
        assert_eq!(values, vec![0xFF]);
    }

    #[test]
    fn pack_handles_zero_length_segment_as_no_op() {
        // Zero-length segments are valid (some encoders emit them as
        // padding); they expand to nothing.
        let segments = [(0u32, 0xABu8)];
        let packed = pack_rle_segments(&segments).expect("zero-length must pack");
        let (lengths, _values) = rle_segment_lengths_cpu(&packed);
        assert_eq!(lengths, vec![0]);
    }

    #[test]
    fn pack_preserves_per_segment_index_in_error() {
        // Segment 3 is the bad one; error must report segment = 3.
        let mut segments: Vec<(u32, u8)> = (0..10).map(|i| (i as u32, 0u8)).collect();
        segments[3].0 = 1u32 << 25; // overflow
        match pack_rle_segments(&segments) {
            Err(PackError::LengthTooLarge { segment: 3, .. }) => {}
            other => panic!("expected error at segment 3; got {other:?}"),
        }
    }

    #[test]
    fn start_offsets_are_exclusive_prefix_sum() {
        let lengths = [3u32, 5, 2, 7];
        let (offsets, total) = rle_segment_start_offsets_cpu(&lengths);
        assert_eq!(offsets, vec![0, 3, 8, 10]);
        assert_eq!(total, 17, "sum of lengths");
    }

    #[test]
    fn start_offsets_handle_zero_length_runs_correctly() {
        let lengths = [3u32, 0, 5, 0, 2];
        let (offsets, total) = rle_segment_start_offsets_cpu(&lengths);
        assert_eq!(offsets, vec![0, 3, 3, 8, 8]);
        assert_eq!(total, 10);
    }

    #[test]
    fn start_offsets_handle_empty_input() {
        let (offsets, total) = rle_segment_start_offsets_cpu(&[]);
        assert!(offsets.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn end_to_end_decode_expands_runs_in_order() {
        // [(3, 'A'), (2, 'B'), (1, 'C')] → "AAABBC"
        let segments = [(3u32, b'A'), (2u32, b'B'), (1u32, b'C')];
        let packed = pack_rle_segments(&segments).expect("pack must succeed");
        let decoded = rle_decode_cpu(&packed);
        assert_eq!(decoded, b"AAABBC".to_vec());
    }

    #[test]
    fn end_to_end_decode_handles_long_run() {
        // 1000 copies of 0x42 in a single segment.
        let segments = [(1000u32, 0x42u8)];
        let packed = pack_rle_segments(&segments).expect("pack must succeed");
        let decoded = rle_decode_cpu(&packed);
        assert_eq!(decoded.len(), 1000);
        assert!(decoded.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn end_to_end_decode_handles_alternating_short_runs() {
        // 256 alternating (1, 0xAA), (1, 0xBB) segments → 256 bytes.
        let mut segments = Vec::with_capacity(256);
        for i in 0..256 {
            segments.push((1u32, if i % 2 == 0 { 0xAAu8 } else { 0xBBu8 }));
        }
        let packed = pack_rle_segments(&segments).expect("pack must succeed");
        let decoded = rle_decode_cpu(&packed);
        assert_eq!(decoded.len(), 256);
        for (i, byte) in decoded.iter().enumerate() {
            let expected = if i % 2 == 0 { 0xAA } else { 0xBB };
            assert_eq!(*byte, expected);
        }
    }

    #[test]
    fn end_to_end_decode_handles_empty_input() {
        let decoded = rle_decode_cpu(&[]);
        assert!(decoded.is_empty());
    }

    #[test]
    fn end_to_end_decode_handles_zero_length_segments_as_skips() {
        let segments = [(2u32, b'A'), (0u32, b'X'), (3u32, b'B')];
        let packed = pack_rle_segments(&segments).expect("pack must succeed");
        let decoded = rle_decode_cpu(&packed);
        assert_eq!(decoded, b"AABBB".to_vec());
    }

    #[test]
    fn pack_into_reuses_existing_capacity() {
        let segments = [(2u32, b'A'), (4u32, b'B')];
        let mut out = Vec::with_capacity(64);
        let before = out.capacity();
        pack_rle_segments_into(&segments, &mut out).expect("pack_into must succeed");
        assert_eq!(out.len(), 2);
        assert_eq!(
            out.capacity(),
            before,
            "pack_into must reuse caller-owned capacity"
        );
    }

    #[test]
    fn cpu_unpack_into_reuses_existing_capacity() {
        let segments = [(2u32, b'A'), (4u32, b'B')];
        let packed = pack_rle_segments(&segments).expect("pack must succeed");
        let mut lengths = Vec::with_capacity(64);
        let mut values = Vec::with_capacity(64);
        let lengths_capacity = lengths.capacity();
        let values_capacity = values.capacity();

        rle_segment_lengths_cpu_into(&packed, &mut lengths, &mut values);

        assert_eq!(lengths, vec![2, 4]);
        assert_eq!(values, vec![u32::from(b'A'), u32::from(b'B')]);
        assert_eq!(lengths.capacity(), lengths_capacity);
        assert_eq!(values.capacity(), values_capacity);
    }

    #[test]
    fn start_offsets_into_reuses_existing_capacity() {
        let mut offsets = Vec::with_capacity(64);
        let capacity = offsets.capacity();
        let total = rle_segment_start_offsets_cpu_into(&[2, 0, 4], &mut offsets);

        assert_eq!(offsets, vec![0, 2, 2]);
        assert_eq!(total, 6);
        assert_eq!(offsets.capacity(), capacity);
    }

    #[test]
    fn decode_into_reuses_existing_capacity_without_intermediate_vectors() {
        let segments = [(2u32, b'A'), (0u32, b'X'), (3u32, b'B')];
        let packed = pack_rle_segments(&segments).expect("pack must succeed");
        let mut decoded = Vec::with_capacity(64);
        let capacity = decoded.capacity();

        rle_decode_cpu_into(&packed, &mut decoded);

        assert_eq!(decoded, b"AABBB".to_vec());
        assert_eq!(decoded.capacity(), capacity);
    }

    #[test]
    fn build_program_returns_well_formed_program() {
        let program = rle_segment_lengths(8);
        assert_eq!(
            program.buffers().len(),
            3,
            "segments_in + lengths_out + values_out"
        );
        assert_eq!(program.workgroup_size(), [256, 1, 1]);
    }

    #[test]
    fn build_program_is_deterministic_across_calls() {
        let p1 = rle_segment_lengths(32);
        let p2 = rle_segment_lengths(32);
        assert_eq!(p1.buffers().len(), p2.buffers().len());
        assert_eq!(p1.workgroup_size(), p2.workgroup_size());
    }

    #[test]
    fn op_id_is_canonical_and_stable() {
        assert_eq!(OP_ID, "vyre-primitives::decode::rle_segment_lengths");
    }

    #[test]
    fn binding_indices_are_canonical_and_stable() {
        assert_eq!(BINDING_SEGMENTS_IN, 0);
        assert_eq!(BINDING_SEGMENT_LENGTHS_OUT, 1);
        assert_eq!(BINDING_SEGMENT_VALUES_OUT, 2);
    }

    #[test]
    fn max_segment_length_is_canonical_24_bit_field_max() {
        assert_eq!(MAX_SEGMENT_LENGTH, (1u32 << 24) - 1);
        assert_eq!(MAX_SEGMENT_VALUE, 0xFF);
    }
}
