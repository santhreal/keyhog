/// Extended unit tests for `keyhog_core::encoding`.
///
/// Covers empty input, canonical padding, exact size boundaries, invalid
/// characters, null bytes, and standard-alphabet edge cases.
use keyhog_core::decode_standard_base64;
use keyhog_core::testing::{CoreTestApi, TestApi};

fn max_standard_base64_input_bytes() -> usize {
    CoreTestApi::max_standard_base64_input_bytes(&TestApi)
}

#[test]
fn encode_standard_base64_uses_canonical_padding() {
    assert_eq!(CoreTestApi::encode_standard_base64(&TestApi, b""), "");
    assert_eq!(CoreTestApi::encode_standard_base64(&TestApi, b"A"), "QQ==");
    assert_eq!(CoreTestApi::encode_standard_base64(&TestApi, b"AB"), "QUI=");
    assert_eq!(
        CoreTestApi::encode_standard_base64(&TestApi, b"ABC"),
        "QUJD"
    );
    assert_eq!(
        CoreTestApi::encode_standard_base64(&TestApi, b"Hello World"),
        "SGVsbG8gV29ybGQ="
    );
}

#[test]
fn credential_does_not_own_a_second_base64_encoder() {
    let credential_src = include_str!("../../src/credential.rs");
    assert!(
        !credential_src.contains("fn base64_encode"),
        "Credential serialization must use core::encoding::encode_standard_base64"
    );
    assert!(
        credential_src.contains("crate::encoding::encode_standard_base64"),
        "Credential serialization must call the shared standard-base64 encoder"
    );
}

#[test]
fn decode_empty_string_returns_empty_vec() {
    let result = decode_standard_base64("").expect("empty string is valid");
    assert!(result.is_empty());
}

#[test]
fn decode_single_byte_padded() {
    assert_eq!(decode_standard_base64("QQ==").expect("single byte"), b"A");
}

#[test]
fn decode_two_bytes_padded() {
    assert_eq!(decode_standard_base64("QUI=").expect("two bytes"), b"AB");
}

#[test]
fn decode_three_bytes_no_padding() {
    assert_eq!(decode_standard_base64("QUJD").expect("three bytes"), b"ABC");
}

#[test]
fn decode_hello_world() {
    assert_eq!(
        decode_standard_base64("SGVsbG8gV29ybGQ=").expect("hello world"),
        b"Hello World"
    );
}

#[test]
fn decode_all_zeros() {
    assert_eq!(
        decode_standard_base64("AAAA").expect("all zeros"),
        &[0u8, 0, 0]
    );
}

#[test]
fn decode_binary_round_trip() {
    let original: &[u8] = &[0x00, 0x7F, 0x80, 0xFF, 0xAB, 0xCD];
    let encoded = "AH+A/6vN";
    assert_eq!(
        decode_standard_base64(encoded).expect("binary round-trip"),
        original
    );
}

#[test]
fn decode_extra_padding_stripped_gracefully() {
    let no_pad = decode_standard_base64("QUJD").expect("no pad");
    let with_pad = decode_standard_base64("QUJD==").expect("with pad");
    assert_eq!(no_pad, with_pad);
}

#[test]
fn decode_invalid_char_returns_error() {
    let result = decode_standard_base64("QUJ@");
    assert!(result.is_err(), "invalid char must return Err");
}

#[test]
fn decode_null_byte_in_middle_returns_error() {
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
    let result = decode_standard_base64("Q");
    assert!(result.is_err(), "single char must be rejected");
}

#[test]
fn decode_at_exact_cap_does_not_trigger_size_guard() {
    let at_cap = "A".repeat(max_standard_base64_input_bytes());
    let result = decode_standard_base64(&at_cap);
    if let Err(error) = result {
        assert!(
            !error.contains("exceeds"),
            "at-cap input should not trigger the size error: {error}"
        );
    }
}

#[test]
fn decode_one_over_cap_is_rejected() {
    let over_cap = "A".repeat(max_standard_base64_input_bytes() + 1);
    let error = decode_standard_base64(&over_cap).expect_err("over-cap input");
    assert!(
        error.contains("exceeds"),
        "over-cap must return the size-limit error"
    );
}

#[test]
fn decode_plus_slash_chars_are_valid_alphabet() {
    let result = decode_standard_base64("+/==");
    if let Err(error) = result {
        assert!(
            !error.contains("invalid base64 char"),
            "'+' and '/' are valid standard-base64 chars"
        );
    }
}

#[test]
fn decode_url_safe_chars_rejected() {
    let result = decode_standard_base64("QU-_");
    assert!(
        result.is_err(),
        "URL-safe chars must be rejected by standard-base64 decoder"
    );
}
