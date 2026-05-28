//! Adversarial tests for fused GPU decode→scan.
//!
//! Exercises malformed, edge-case, and hostile inputs against the fused
//! decode→scan pipeline to ensure graceful degradation (never panics,
//! never produces phantom matches on invalid input).

use keyhog_scanner::engine::gpu_decode_scan::{
    detect_encoding, FusedEncoding,
};

// ────────────────────────────────────────────────────────────
// Encoding detection adversarial
// ────────────────────────────────────────────────────────────

#[test]
fn detect_encoding_empty_input() {
    assert_eq!(detect_encoding(b""), None);
}

#[test]
fn detect_encoding_single_byte() {
    // Single byte — too short for meaningful detection.
    let result = detect_encoding(b"A");
    // Should not panic; result is implementation-defined.
    let _ = result;
}

#[test]
fn detect_encoding_all_zeros() {
    // NUL bytes everywhere — binary, not encoded text.
    let input = vec![0u8; 64];
    assert_eq!(detect_encoding(&input), None);
}

#[test]
fn detect_encoding_all_whitespace() {
    let input = b"   \n\t\r\n   \t   ";
    // Pure whitespace — no useful content.
    assert_eq!(detect_encoding(input), None);
}

#[test]
fn detect_encoding_mixed_binary() {
    // Mix of valid hex chars and binary garbage.
    let mut input = Vec::new();
    input.extend_from_slice(b"48656c6c6f");
    input.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x80, 0x90, 0xAB, 0xCD, 0xEF]);
    // Should reject as too much binary content.
    assert_eq!(detect_encoding(&input), None);
}

#[test]
fn detect_encoding_base64_with_crlf() {
    // Base64 with embedded CRLF (MIME format).
    let input = b"SGVsbG8g\r\nV29ybGQ=";
    let result = detect_encoding(input);
    assert!(result.is_some(), "base64 with CRLF should be detected");
}

#[test]
fn detect_encoding_hex_odd_length() {
    // Odd-length string of hex chars — can't be valid hex pairs.
    let input = b"48656c6c6f2"; // 11 chars
    let result = detect_encoding(input);
    // Should NOT be detected as hex (odd length).
    assert_ne!(result, Some(FusedEncoding::Hex));
}

#[test]
fn detect_encoding_base64_no_padding_long() {
    // Long base64-ish string without padding.
    let input = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let result = detect_encoding(input);
    assert_eq!(result, Some(FusedEncoding::Base64));
}

#[test]
fn detect_encoding_pure_hex_lowercase() {
    let input = b"deadbeefcafe1234567890abcdef";
    let result = detect_encoding(input);
    assert_eq!(result, Some(FusedEncoding::Hex));
}

#[test]
fn detect_encoding_pure_hex_uppercase() {
    let input = b"DEADBEEFCAFE1234567890ABCDEF";
    let result = detect_encoding(input);
    assert_eq!(result, Some(FusedEncoding::Hex));
}

#[test]
fn detect_encoding_one_mb_base64() {
    // 1 MiB of base64 characters — should detect quickly (samples 256 bytes).
    let input = vec![b'A'; 1024 * 1024];
    let result = detect_encoding(&input);
    // Should not hang or OOM; detection samples only 256 bytes.
    let _ = result;
}

#[test]
fn detect_encoding_nested_base64_of_hex() {
    // Base64-encoded hex string. The outer encoding is base64.
    // "48656c6c6f" (hex for "Hello") in base64 is "NDg2NTZjNmM2Zg=="
    let input = b"NDg2NTZjNmM2Zg==";
    let result = detect_encoding(input);
    assert_eq!(result, Some(FusedEncoding::Base64));
}

#[test]
fn detect_encoding_base64_only_padding() {
    // Degenerate: only padding characters.
    let input = b"====";
    let result = detect_encoding(input);
    // This is technically valid base64 (zero decoded bytes).
    assert_eq!(result, Some(FusedEncoding::Base64));
}

#[test]
fn detect_encoding_base64_invalid_chars() {
    // Base64 alphabet + characters that shouldn't be in base64.
    let input = b"SGVsbG8!@#$%^&*()";
    let result = detect_encoding(input);
    // High ratio of "other" chars → should reject.
    assert_eq!(result, None);
}

// ────────────────────────────────────────────────────────────
// FusedEncoding enum
// ────────────────────────────────────────────────────────────

#[test]
fn fused_encoding_debug_repr() {
    // Verify Debug formatting doesn't panic.
    let _ = format!("{:?}", FusedEncoding::Base64);
    let _ = format!("{:?}", FusedEncoding::Hex);
}

#[test]
fn fused_encoding_eq_and_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(FusedEncoding::Base64);
    set.insert(FusedEncoding::Hex);
    set.insert(FusedEncoding::Base64); // duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn fused_encoding_clone() {
    let e = FusedEncoding::Base64;
    let e2 = e;
    assert_eq!(e, e2);
}
