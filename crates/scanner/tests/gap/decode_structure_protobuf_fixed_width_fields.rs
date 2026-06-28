//! Gap test: the protobuf-wire decode-structure verdict handles fixed-width
//! fields through one shared bounds-checked advance.
//!
//! `parse_protobuf_wire` decides whether decoded bytes are a serialized
//! protobuf message (a binary-payload signal that keeps a base64-of-protobuf
//! decoy from scoring as a credential). Wire type 1 (64-bit fixed) and wire
//! type 5 (32-bit fixed) advance the cursor by a width looked up from
//! `FIXED_WIRE_WIDTHS` by the runtime wire type, so they share ONE arm — the
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
