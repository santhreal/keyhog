//! Unit gates for `decode_structure`: the decode-through -> scoring signal.
//!
//! Positive direction: real base64-encoded binary assets (magic bytes) and a
//! real serialized protobuf must read as binary payloads. Negative direction:
//! random high-entropy secrets and realistic API-key tokens must NOT, so the
//! generic-detector confidence penalty never suppresses a real credential.

use base64::Engine;
use keyhog_scanner::testing::decode_structure::{
    analyze, decoded_contains_nul_byte, decoded_contains_placeholder, decoded_is_hex_key_material,
    decodes_to_printable_text, is_encoded_binary, looks_like_uniform_base64_blob, DecodeStructure,
};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn png_blob_is_binary_payload() {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    let s = b64(&png);
    let a = analyze(&s);
    assert_eq!(a.magic, Some("png"));
    assert!(a.is_binary_payload());
    assert!(is_encoded_binary(&s));
}

#[test]
fn gzip_zlib_pdf_elf_are_binary_payloads() {
    for (sig, name) in [
        (&b"\x1f\x8b\x08\x00"[..], "gzip"),
        (&b"\x78\x9c\x01\x02\x03\x04"[..], "zlib"),
        (&b"%PDF-1.4\n%abc"[..], "pdf"),
        (&b"\x7fELF\x02\x01\x01\x00"[..], "elf"),
    ] {
        let mut blob = sig.to_vec();
        blob.extend_from_slice(&[9u8; 24]);
        let s = b64(&blob);
        assert_eq!(analyze(&s).magic, Some(name), "magic for {name}");
        assert!(is_encoded_binary(&s), "{name} must read as binary");
    }
}

#[test]
fn real_protobuf_message_is_binary_payload() {
    // field 1 (varint) = 150; field 2 (len-delimited) = "testing";
    // field 3 (varint) = 1; field 4 (32-bit) = 0xdeadbeef.
    let msg = [
        0x08, 0x96, 0x01, // field 1, varint 150
        0x12, 0x07, b't', b'e', b's', b't', b'i', b'n', b'g', // field 2, "testing"
        0x18, 0x01, // field 3, varint 1
        0x25, 0xef, 0xbe, 0xad, 0xde, // field 4, 32-bit
    ];
    let s = b64(&msg);
    assert!(analyze(&s).protobuf_wire, "valid protobuf must parse");
    assert!(is_encoded_binary(&s));
}

#[test]
fn random_secret_is_not_binary_payload() {
    // Deterministic pseudo-random 36-byte "secret" values: essentially none
    // should be mistaken for binary (no magic header, not a full protobuf
    // parse). Bounds the false-suppress rate well under 0.5%.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut false_suppress = 0;
    for _ in 0..3000 {
        let raw: Vec<u8> = (0..36)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (state >> 33) as u8
            })
            .collect();
        let s = b64(&raw);
        if is_encoded_binary(&s) {
            false_suppress += 1;
        }
    }
    assert!(
        false_suppress <= 6,
        "random secrets must not read as binary (got {false_suppress}/3000)"
    );
}

#[test]
fn realistic_api_key_tokens_are_not_binary() {
    // alnum API-key-shaped tokens, treated as candidates, must not suppress.
    let tokens = [
        "ghp_aBcD1234EFgh5678ijkl9012MNop3456qrST",
        "AKIAIOSFODNN7EXAMPLE0000",
        "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    ];
    for t in tokens {
        assert!(!is_encoded_binary(t), "token {t} must not read as binary");
    }
}

#[test]
fn short_candidates_are_skipped() {
    assert!(!is_encoded_binary("short"));
    assert_eq!(analyze("short"), DecodeStructure::default());
}

#[test]
fn non_encoded_text_is_not_decodable() {
    let a = analyze("this is a normal sentence with spaces!!");
    assert!(!a.decodable);
    assert!(!a.is_binary_payload());
}

#[test]
fn impossible_base64_length_does_not_decode_through_shape_analysis() {
    // Same impossible len%4==1 base64 shape as the decode primitive test. This
    // verifies decode-structure analysis imports the scanner decoder contract
    // instead of padding/reclassifying candidates privately.
    let a = analyze("QUtJQUlPU0ZPRE5ON");
    assert!(!a.decodable);
    assert!(!a.is_binary_payload());
}

// ---- decoded_contains_placeholder -------------------------------------

#[test]
fn base64_wrapping_aws_example_credential_is_caught() {
    // base64("AKIAEXAMPLEEXAMPLE12") = "QUtJQUVYQU1QTEVFWEFNUExFMTI="
    assert!(decoded_contains_placeholder("QUtJQUVYQU1QTEVFWEFNUExFMTI="));
}

#[test]
fn underscore_hex_uses_shared_hex_decode_contract() {
    // hex("AKIAEXAMPLEEXAMPLE12") with readability separators. decode_structure
    // must use the same underscore-stripping hex decoder as the decode pipeline.
    assert!(decoded_contains_placeholder(
        "414b_4941_4558_414d_504c_4545_5841_4d50_4c45_3132"
    ));
}

#[test]
fn decoded_nul_byte_fact_is_cached_with_decode_structure() {
    let encoded = base64::engine::general_purpose::STANDARD.encode(b"prefix\0suffix-binary");
    assert!(
        decoded_contains_nul_byte(&encoded),
        "decoded NUL evidence must be preserved by the consolidated decode facts"
    );
}

#[test]
fn base64_wrapping_stripe_placeholder_is_caught() {
    // base64("sk_live_PLACEHOLDER_NOT_A_REAL_KEY")
    let s = base64::engine::general_purpose::STANDARD.encode("sk_live_PLACEHOLDER_NOT_A_REAL_KEY");
    assert!(decoded_contains_placeholder(&s));
}

#[test]
fn base64_wrapping_shared_placeholder_words_is_caught() {
    for raw in [
        "MOCK_API_TOKEN_for_unit_tests_4",
        "service_CHANGEME_token_1234",
    ] {
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(
            decoded_contains_placeholder(&encoded),
            "decoded placeholder-word detection must catch shared Tier-B word in {raw:?}"
        );
    }
}

#[test]
fn base64_wrapping_hex_key_material_is_not_a_decoded_placeholder() {
    let encoded = "YTFiMmMzZDRlNWY2MDcxODI5M2E0YjVjNmQ3ZThmOTAxYTJiM2M0ZDVlNmY3MDgx";
    assert!(
        !decoded_contains_placeholder(encoded),
        "decoded hex key material must not trip substring placeholder detection"
    );
    assert!(
        decodes_to_printable_text(encoded),
        "base64-wrapped hex key material is encoded printable secret text, not a binary blob"
    );
    assert!(
        decoded_is_hex_key_material(encoded),
        "base64-wrapped hex32/hex40/hex48 key material must be an explicit decode fact"
    );
}

#[test]
fn base64_of_real_random_secret_passes() {
    // base64 of a random-looking 24-byte secret must NOT be flagged.
    let s = base64::engine::general_purpose::STANDARD.encode(b"random_24_byte_secret_aBc");
    assert!(!decoded_contains_placeholder(&s));
}

#[test]
fn short_credentials_skip_decode() {
    // Below MIN_DECODE_LEN - should return false without attempting decode.
    assert!(!decoded_contains_placeholder("short"));
    assert!(!decoded_contains_placeholder("AKIA"));
}

// ---- looks_like_uniform_base64_blob -----------------------------------

#[test]
fn pure_base64_blob_60_plus_chars_with_punct_matches() {
    // 64-char base64-ish with `+/` and padding - the random-base64-protobuf
    // corpus shape.
    let s = "ABCDEFghij+/klmn0123abcdefghijklmnop+/qrstuvwxyz0123456789ABCD==";
    assert_eq!(s.len(), 64);
    assert!(looks_like_uniform_base64_blob(s));
}

#[test]
fn aws_secret_access_key_shape_passes() {
    // 40 base62 chars - AWS spec - no `+/` or padding. Must NOT match
    // (would be a recall loss on real AWS secrets).
    let s = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY12";
    assert_eq!(s.len(), 40);
    assert!(!looks_like_uniform_base64_blob(s));
}

#[test]
fn github_pat_shape_passes() {
    // ghp_<base62> - has `_` which is outside the std base64 alphabet.
    // Must NOT match.
    let s = "ghp_AbCdEf1234567890ZyXwVu9876543210QqRr";
    assert!(!looks_like_uniform_base64_blob(s));
}

#[test]
fn jwt_shape_passes() {
    // JWT has `.` separators - outside base64 alphabet.
    let s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.AbCdEf";
    assert!(!looks_like_uniform_base64_blob(s));
}

#[test]
fn short_base64_below_60_chars_passes() {
    // 40-char pure base64 - too short to flag (might be a legit OAuth bearer).
    let s = "ABCDEFGHIJKLMNOPQRSTUVWX/+abcdefghijklmn"; // 40 chars
    assert_eq!(s.len(), 40);
    assert!(!looks_like_uniform_base64_blob(s));
}
