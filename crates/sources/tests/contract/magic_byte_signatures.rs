//! Byte-signature classifier contracts (`src/magic.rs`) — the binary-vs-text
//! detectors that gate `filesystem/read/decode.rs`. A wrong classifier scans a
//! binary blob as text (FP noise + wasted work) or skips a real text file, so
//! each format's exact positive and a TIGHT near-miss negative are pinned.
//! Reached through the `testing` facade (the `src` no-inline-tests contract keeps
//! unit coverage in `tests/`). Property invariants (no-panic, prefix-implication,
//! full digit range) live in `property/magic_byte_signatures_proptest.rs`.

use keyhog_sources::testing::{
    blocking_thread_panic_error_message_for_test, has_bmp_header_for_test,
    has_bzip2_header_for_test, has_pe_header_for_test, has_unambiguous_binary_prefix_for_test,
    starts_with_pdf_for_test, starts_with_python_pickle_protocol2_for_test,
    starts_with_zip_container_prefix_for_test,
};

// ── BMP: "BM" + reserved [0;4] at 6..10 + pixel-data offset >= 14 ─────────────

#[test]
fn bmp_header_accepts_a_well_formed_bmp() {
    // "BM", 4-byte size (any), 4 reserved zero bytes, 4-byte pixel offset = 14.
    let bmp = [b'B', b'M', 0x36, 0, 0, 0, 0, 0, 0, 0, 0x0e, 0, 0, 0];
    assert!(has_bmp_header_for_test(&bmp));
}

#[test]
fn bmp_header_rejects_pixel_offset_below_fourteen() {
    // Same shape but the pixel-data offset is 13 (< the 14-byte header) → not BMP.
    let bmp = [b'B', b'M', 0x36, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0];
    assert!(!has_bmp_header_for_test(&bmp));
}

#[test]
fn bmp_header_rejects_nonzero_reserved_field() {
    let bmp = [b'B', b'M', 0x36, 0, 0, 0, 1, 0, 0, 0, 0x0e, 0, 0, 0]; // reserved[0] = 1
    assert!(!has_bmp_header_for_test(&bmp));
}

#[test]
fn bmp_header_rejects_too_short_and_wrong_prefix() {
    assert!(!has_bmp_header_for_test(b"BM\x00\x00")); // < 14 bytes
    assert!(!has_bmp_header_for_test(
        b"MB\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00"
    )); // "MB", not "BM"
}

// ── PE: "MZ" + >= 64 bytes + e_lfanew (60..64) >= 64 + "PE\0\0" at e_lfanew ────

#[test]
fn pe_header_accepts_a_well_formed_pe() {
    let mut pe = vec![0u8; 68];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[60..64].copy_from_slice(&64u32.to_le_bytes()); // e_lfanew = 64
    pe[64..68].copy_from_slice(b"PE\0\0");
    assert!(has_pe_header_for_test(&pe));
}

#[test]
fn pe_header_rejects_missing_pe_signature_at_offset() {
    let mut pe = vec![0u8; 68];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[60..64].copy_from_slice(&64u32.to_le_bytes());
    // "PE\0\0" left zero at offset 64 → not a PE.
    assert!(!has_pe_header_for_test(&pe));
}

#[test]
fn pe_header_rejects_out_of_bounds_offset_and_short_input() {
    let mut pe = vec![0u8; 68];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[60..64].copy_from_slice(&9999u32.to_le_bytes()); // e_lfanew past the buffer
    assert!(!has_pe_header_for_test(&pe));
    assert!(!has_pe_header_for_test(b"MZ")); // < 64 bytes
}

// ── bzip2: "BZh" + block-size digit 1..=9 ────────────────────────────────────

#[test]
fn bzip2_header_accepts_valid_block_sizes() {
    assert!(has_bzip2_header_for_test(b"BZh1"));
    assert!(has_bzip2_header_for_test(b"BZh9"));
}

#[test]
fn bzip2_header_rejects_zero_non_digit_and_short() {
    assert!(!has_bzip2_header_for_test(b"BZh0")); // 0 is outside 1..=9
    assert!(!has_bzip2_header_for_test(b"BZhA"));
    assert!(!has_bzip2_header_for_test(b"BZh")); // too short
}

// ── PDF / ZIP-container / pickle prefixes ────────────────────────────────────

#[test]
fn pdf_prefix_matches_only_the_exact_magic() {
    assert!(starts_with_pdf_for_test(b"%PDF-1.7\nrest"));
    assert!(!starts_with_pdf_for_test(b"%PDX-1.7")); // one byte off
    assert!(!starts_with_pdf_for_test(b" %PDF-")); // leading space
}

#[test]
fn zip_container_prefix_accepts_local_and_eocd_only() {
    assert!(starts_with_zip_container_prefix_for_test(b"PK\x03\x04rest")); // local file header
    assert!(starts_with_zip_container_prefix_for_test(b"PK\x05\x06rest")); // end-of-central-dir
    assert!(!starts_with_zip_container_prefix_for_test(b"PK\x01\x02")); // central-dir header (not a container start)
    assert!(!starts_with_zip_container_prefix_for_test(b"PKplain"));
}

#[test]
fn python_pickle_protocol2_matches_exact_opcode() {
    assert!(starts_with_python_pickle_protocol2_for_test(
        b"\x80\x02rest"
    ));
    assert!(!starts_with_python_pickle_protocol2_for_test(b"\x80\x03")); // protocol 3
    assert!(!starts_with_python_pickle_protocol2_for_test(b"\x80")); // too short
}

// ── the unambiguous-binary-prefix union list ─────────────────────────────────

#[test]
fn unambiguous_binary_prefix_matches_known_formats() {
    assert!(has_unambiguous_binary_prefix_for_test(
        b"\x7fELF\x02\x01\x01"
    )); // ELF
    assert!(has_unambiguous_binary_prefix_for_test(b"\xff\xd8\xff\xe0")); // JPEG
    assert!(has_unambiguous_binary_prefix_for_test(b"GIF89a and more")); // GIF
    assert!(has_unambiguous_binary_prefix_for_test(b"\x89PNG\r\n\x1a\n")); // PNG
}

#[test]
fn unambiguous_binary_prefix_rejects_plain_text() {
    assert!(!has_unambiguous_binary_prefix_for_test(
        b"export API_KEY=ghp_example"
    ));
    assert!(!has_unambiguous_binary_prefix_for_test(b"")); // empty
    assert!(!has_unambiguous_binary_prefix_for_test(b"#!/bin/bash")); // shebang is text
}

// ── WASM (web feature) ───────────────────────────────────────────────────────

#[cfg(feature = "web")]
#[test]
fn wasm_module_matches_exact_magic() {
    use keyhog_sources::testing::starts_with_wasm_module_for_test;
    assert!(starts_with_wasm_module_for_test(b"\x00asm\x01\x00\x00\x00"));
    assert!(!starts_with_wasm_module_for_test(b"\x00asx")); // one byte off
    assert!(!starts_with_wasm_module_for_test(b"\x00as")); // too short
}

// ── blocking-thread panic safety ─────────────────────────────────────────────

#[test]
fn blocking_thread_panic_becomes_a_counted_source_error() {
    // A fetch closure that panics must be converted to a named SourceError, never
    // unwind into (or abort) the caller — otherwise one bad remote source would
    // crash the whole scan instead of counting a skipped source.
    let msg = blocking_thread_panic_error_message_for_test("s3")
        .expect("a panicking fetch closure must surface an Err, not succeed or unwind");
    assert!(
        msg.contains("s3") && msg.contains("fetch thread panicked"),
        "the panic must convert to a named SourceError; got {msg:?}"
    );
}
