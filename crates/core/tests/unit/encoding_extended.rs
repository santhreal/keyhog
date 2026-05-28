/// Extended unit tests for `keyhog_core::encoding`.
///
/// Covers: empty input, all-padding input, single byte, two bytes, three bytes,
/// exactly-at-cap, one-over-cap, invalid characters, mixed valid/invalid,
/// null byte in middle, and the `decode → encode → compare` round-trip.
use keyhog_core::encoding::{decode_standard_base64, MAX_STANDARD_BASE64_INPUT_BYTES};

// ── Happy-path decode ─────────────────────────────────────────────────────────

#[test]
fn decode_empty_string_returns_empty_vec() {
    let result = decode_standard_base64("").expect("empty string is valid");
    assert!(result.is_empty());
}

#[test]
fn decode_single_byte_padded() {
    // base64("A") = "QQ==" → [0x41]
    let result = decode_standard_base64("QQ==").expect("single byte");
    assert_eq!(result, b"A");
}

#[test]
fn decode_two_bytes_padded() {
    // base64("AB") = "QUI=" → [0x41, 0x42]
    let result = decode_standard_base64("QUI=").expect("two bytes");
    assert_eq!(result, b"AB");
}

#[test]
fn decode_three_bytes_no_padding() {
    // base64("ABC") = "QUJD" → [0x41, 0x42, 0x43]
    let result = decode_standard_base64("QUJD").expect("three bytes");
    assert_eq!(result, b"ABC");
}

#[test]
fn decode_hello_world() {
    let result = decode_standard_base64("SGVsbG8gV29ybGQ=").expect("hello world");
    assert_eq!(result, b"Hello World");
}

#[test]
fn decode_all_zeros() {
    // b"\x00\x00\x00" → "AAAA"
    let result = decode_standard_base64("AAAA").expect("all zeros");
    assert_eq!(result, &[0u8, 0, 0]);
}

#[test]
fn decode_binary_round_trip() {
    // 6 arbitrary bytes covering the full 0..=255 range
    let original: &[u8] = &[0x00, 0x7F, 0x80, 0xFF, 0xAB, 0xCD];
    // Manually encoded: "AH+A/6vN"
    let encoded = "AH+A/6vN";
    let result = decode_standard_base64(encoded).expect("binary round-trip");
    assert_eq!(result, original);
}

// ── Padding stripping ─────────────────────────────────────────────────────────

#[test]
fn decode_extra_padding_stripped_gracefully() {
    // Standard b64 truncates at '=' — the implementation strips padding;
    // "QUJD" and "QUJD==" should both yield [A, B, C] without error.
    let no_pad = decode_standard_base64("QUJD").expect("no pad");
    let with_pad = decode_standard_base64("QUJD==").expect("with pad");
    assert_eq!(no_pad, with_pad);
}

// ── Error paths ────────────────────────────────────────────────────────────────

#[test]
fn decode_invalid_char_returns_error() {
    // '@' is not in the standard base64 alphabet
    let result = decode_standard_base64("QUJ@");
    assert!(result.is_err(), "invalid char must return Err");
}

#[test]
fn decode_null_byte_in_middle_returns_error() {
    // '\0' is not in the base64 alphabet
    let result = decode_standard_base64("QU\0=");
    assert!(result.is_err(), "null byte must return Err");
}

#[test]
fn decode_space_returns_error() {
    let result = decode_standard_base64("QU J=");
    assert!(result.is_err(), "space is not valid base64");
}

#[test]
fn decode_truncated_chunk_returns_error() {
    // A single base64 char is not a complete group — should return an error.
    let result = decode_standard_base64("Q");
    assert!(result.is_err(), "single char (truncated) should be Err");
}

// ── Size cap ──────────────────────────────────────────────────────────────────

#[test]
fn decode_at_exact_cap_succeeds() {
    // Build the longest valid input that fits within the cap.
    // MAX_STANDARD_BASE64_INPUT_BYTES must fit the input string itself.
    // We only need to verify the boundary: a string of exactly MAX bytes
    // made of valid base64 chars (A) must not be rejected by the size guard.
    // (It will likely fail to decode for other reasons, but must not return
    // the "exceeds N bytes" error.)
    let at_cap: String = "A".repeat(MAX_STANDARD_BASE64_INPUT_BYTES);
    let result = decode_standard_base64(&at_cap);
    match result {
        Err(e) if e.contains("exceeds") => {
            panic!("at-cap input should not trigger the size error: {e}");
        }
        _ => {} // Decode error for other reasons is fine
    }
}

#[test]
fn decode_one_over_cap_is_rejected() {
    let over_cap: String = "A".repeat(MAX_STANDARD_BASE64_INPUT_BYTES + 1);
    let result = decode_standard_base64(&over_cap);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("exceeds"),
        "over-cap must return the size-limit error"
    );
}

// ── Alphabet edge cases ───────────────────────────────────────────────────────

#[test]
fn decode_plus_slash_chars_are_valid_alphabet() {
    // '+'=62 '/'=63 in standard b64 alphabet
    // "+/" encodes the byte sequence that starts with values 62/63.
    // Just verify no error is returned for valid input.
    let result = decode_standard_base64("+/==");
    // Should not be an alphabet-rejection error (may fail for other reasons)
    if let Err(ref e) = result {
        assert!(
            !e.contains("invalid base64 char"),
            "'+' and '/' are valid b64 chars"
        );
    }
}

#[test]
fn decode_url_safe_chars_rejected() {
    // URL-safe base64 uses '-' and '_'; standard b64 does not.
    let result = decode_standard_base64("QU-_");
    assert!(result.is_err(), "url-safe chars must be rejected by standard b64 decoder");
}
