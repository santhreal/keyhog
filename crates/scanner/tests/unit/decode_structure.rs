//! Unit gates for `decode_structure`: the decode-through -> scoring signal.
//!
//! Positive direction: real base64-encoded binary assets (magic bytes) and a
//! real serialized protobuf must read as binary payloads. Negative direction:
//! random high-entropy secrets and realistic API-key tokens must NOT, so the
//! generic-detector confidence penalty never suppresses a real credential.

use base64::Engine;
use keyhog_scanner::decode_structure::{analyze, is_encoded_binary, DecodeStructure};

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
