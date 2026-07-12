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
fn real_pe_image_is_binary_payload() {
    // A real PE: 'MZ' DOS header whose e_lfanew (u32 LE @ 0x3C) points at the
    // PE\0\0 NT signature. is_pe_image requires this structure, so a genuine
    // embedded PE still classifies as binary.
    let mut pe = vec![0u8; 0x40];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    pe.extend_from_slice(b"PE\x00\x00");
    pe.extend_from_slice(&[0u8; 8]);
    let s = b64(&pe);
    let a = analyze(&s);
    assert_eq!(a.magic, Some("pe"), "a real PE image must classify as pe");
    assert!(a.is_binary_payload());
    assert!(is_encoded_binary(&s));
}

#[test]
fn bare_mz_prefix_secret_is_not_suppressed_as_pe() {
    // Regression: a 36-byte high-entropy secret whose decoded bytes merely begin
    // with the two printable ASCII letters 'M','Z' is NOT a PE (no e_lfanew /
    // PE\0\0 structure, and shorter than the 0x40 DOS header). A 2-byte magic
    // must not drive suppression, or genuine credentials are silently dropped.
    let mut blob = vec![b'M', b'Z'];
    blob.extend_from_slice(&[0x42u8; 34]);
    let s = b64(&blob);
    let a = analyze(&s);
    assert_eq!(a.magic, None, "bare 'MZ' prefix must not classify as pe");
    assert!(
        !a.is_binary_payload(),
        "bare 'MZ' secret must not be suppressed as binary"
    );
    assert!(!is_encoded_binary(&s));
}

#[test]
fn mz_without_pe_signature_at_e_lfanew_is_not_pe() {
    // Long enough to hold e_lfanew, but the pointed-at bytes are not PE\0\0.
    let mut blob = vec![0u8; 0x40];
    blob[0] = b'M';
    blob[1] = b'Z';
    blob[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    blob.extend_from_slice(b"NOPE");
    blob.extend_from_slice(&[0u8; 8]);
    let s = b64(&blob);
    assert_eq!(
        analyze(&s).magic,
        None,
        "MZ without PE\\0\\0 at e_lfanew is not a PE"
    );
}

#[test]
fn gzip_wrong_compression_method_is_not_gzip() {
    // 0x1f 0x8b but CM != 8 (gzip only ever uses DEFLATE): not a real gzip
    // stream, so the 2-byte magic must not suppress.
    let mut blob = vec![0x1f, 0x8b, 0x07];
    blob.extend_from_slice(&[9u8; 24]);
    let s = b64(&blob);
    let a = analyze(&s);
    assert_eq!(a.magic, None, "gzip magic with CM!=8 is not gzip");
    assert!(!a.is_binary_payload());
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
