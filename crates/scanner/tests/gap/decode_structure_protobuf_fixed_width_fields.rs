//! Gap test: the protobuf-wire decode-structure verdict handles fixed-width
//! fields through one shared bounds-checked advance.
//!
//! `parse_protobuf_wire` decides whether decoded bytes are a serialized
//! protobuf message (a binary-payload signal that keeps a base64-of-protobuf
//! decoy from scoring as a credential). Wire type 1 (64-bit fixed) and wire
//! type 5 (32-bit fixed) advance the cursor by a width looked up from
//! `FIXED_WIRE_WIDTHS` by the runtime wire type, so they share ONE arm, the
//! per-width difference lives in the table, not in duplicated arm bodies. Pin
//! the exact verdict: a whole-buffer stream of >= 3 fields using BOTH fixed
//! widths parses true, a truncated fixed-32 field fails closed, and a single
//! fixed-64 field falls under the >= 3 field floor.
//!
//! Tags are `(field_no << 3) | wire_type`: 0x09 = field 1/wire 1, 0x15 =
//! field 2/wire 5, 0x18 = field 3/wire 0.

use keyhog_scanner::testing::parse_protobuf_wire_for_test as parse;

#[test]
fn whole_buffer_with_both_fixed_widths_parses() {
    // field1 wire1 (8 bytes) + field2 wire5 (4 bytes) + field3 wire0 (varint 1).
    // 1 + 8 + 1 + 4 + 1 + 1 = 16 bytes, 3 fields, fully consumed.
    let data = [
        0x09, 0, 0, 0, 0, 0, 0, 0, 0, // tag + 64-bit fixed
        0x15, 0, 0, 0, 0, // tag + 32-bit fixed
        0x18, 0x01, // tag + varint
    ];
    assert_eq!(data.len(), 16);
    assert!(parse(&data));
}

#[test]
fn truncated_fixed32_field_fails_closed() {
    // wire-5 field declares a 32-bit value but only 3 bytes follow → the
    // bounds-checked advance returns false rather than reading past the end.
    let data = [0x15, 0, 0, 0];
    assert!(!parse(&data));
}

#[test]
fn single_fixed64_field_is_below_min_field_count() {
    // One complete wire-1 field consumes the whole 9-byte buffer, but a real
    // message needs >= 3 fields, so the verdict is false.
    let data = [0x09, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(data.len(), 9);
    assert!(!parse(&data));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example each; these SWEEP the parser's accept/reject
// conditions (source: `i == n && fields >= 3`, with `n >= 8`, per-wire advance).
// Constructive valids build fully-consumed ≥8-byte, ≥3-field streams (pure wire-0,
// and the mixed wire-1/wire-5/wire-0 shape); negatives isolate the field-count
// floor (1–2 complete fields) and the fail-closed truncation (4 valid fields then
// a trailing fixed field with fewer bytes than its width). Traced against
// decode_structure.rs:429. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// A fully-consumed stream of ≥4 single-byte-varint (wire-0) fields parses 
    /// ≥4 fields is ≥8 bytes (the length floor) and ≥3 fields (the count floor).
    #[test]
    fn wire0_fields_stream_parses(
        n in 4usize..=10,
        vals in prop::collection::vec(0u8..128, 10),
    ) {
        let mut data = Vec::new();
        for i in 0..n {
            data.push(((i as u8 + 1) << 3) | 0); // field i+1, wire 0
            data.push(vals[i]); // single-byte varint (high bit clear)
        }
        prop_assert!(parse(&data));
    }

    /// The mixed shape (wire-1 fixed64, wire-5 fixed32, wire-0 varint) parses for
    /// any field-value bytes: 16 bytes, 3 fields, fully consumed.
    #[test]
    fn mixed_fixed_width_stream_parses(
        v64 in prop::collection::vec(any::<u8>(), 8),
        v32 in prop::collection::vec(any::<u8>(), 4),
        vlast in 0u8..128,
    ) {
        let mut data = vec![(1u8 << 3) | 1]; // field 1, wire 1
        data.extend_from_slice(&v64);
        data.push((2u8 << 3) | 5); // field 2, wire 5
        data.extend_from_slice(&v32);
        data.push((3u8 << 3) | 0); // field 3, wire 0
        data.push(vlast);
        prop_assert!(parse(&data));
    }

    /// One or two complete fixed-64 fields are fully consumed but below the ≥3
    /// field floor → rejected.
    #[test]
    fn one_or_two_fixed64_fields_are_below_floor(
        count in 1usize..=2,
        filler in prop::collection::vec(any::<u8>(), 16),
    ) {
        let mut data = Vec::new();
        for k in 0..count {
            data.push(((k as u8 + 1) << 3) | 1); // field, wire 1 (fixed64)
            data.extend_from_slice(&filler[k * 8..k * 8 + 8]);
        }
        prop_assert!(!parse(&data));
    }

    /// A trailing fixed-width field with fewer bytes than its width fails CLOSED,
    /// even after 4 valid fields (≥8 bytes, ≥3 fields), the bounds-checked advance
    /// refuses to read past the end.
    #[test]
    fn truncated_trailing_fixed_field_fails_closed(
        fixed64 in any::<bool>(),
        present_seed in 0usize..8,
    ) {
        let (wire, width) = if fixed64 { (1u8, 8usize) } else { (5u8, 4usize) };
        let present = present_seed % width; // strictly fewer than the width
        let mut data = Vec::new();
        for i in 0..4 {
            data.push(((i as u8 + 1) << 3) | 0); // 4 complete wire-0 fields = 8 bytes
            data.push(0);
        }
        data.push((5u8 << 3) | wire); // trailing fixed field, field 5
        data.extend(std::iter::repeat(0u8).take(present));
        prop_assert!(!parse(&data));
    }
}
