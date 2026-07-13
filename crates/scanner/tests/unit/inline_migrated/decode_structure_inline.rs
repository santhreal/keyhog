//! Migrated from src/decode_structure.rs, uniform-base64-blob and
//! double-base64 (k8s `data:`) shape gates (KH-GAP-004).

use base64::Engine as _;
use keyhog_scanner::testing::decode_structure::{
    decoded_is_base64_blob, decodes_to_printable_text, looks_like_uniform_base64_blob,
};

// Round 1 FP-killer: base64-protobuf cause #1, #2, #4, #7. Pure-alphanumeric
// base64 in [44, 80] without +/ punct must hit the gate via the high-diversity
// admit. This is the 25-FP wedge in the mirror corpus.
#[test]
fn looks_like_uniform_base64_blob_admits_pure_alnum_at_44() {
    // 44 chars, mult-of-4, all base64 alphabet, no +/, 32+ distinct
    // alphanumeric chars: a random-bytes-encoded protobuf shape.
    let v = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1JRcor";
    assert_eq!(v.len(), 44);
    let distinct: std::collections::BTreeSet<char> = v.chars().collect();
    assert!(
        distinct.len() >= 32,
        "fixture must have >= 32 distinct chars"
    );
    assert!(
        looks_like_uniform_base64_blob(v),
        "44-char pure-alphanumeric mult-of-4 base64 with high alphabet \
         diversity must hit the gate (random protobuf-of-bytes shape)",
    );
}

// Negative twin: a short value (< 44) must NOT hit the gate even when it would
// otherwise pass the alphabet / padding checks. AWS secret access keys (40
// chars base62) live in this band and would regress if the gate fired.
#[test]
fn looks_like_uniform_base64_blob_rejects_below_44() {
    let v = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; // 40 chars
    assert_eq!(v.len(), 40);
    assert!(
        !looks_like_uniform_base64_blob(v),
        "40-char base64 below the floor must not fire (AWS-secret-key \
         length band preserved)",
    );
}

// Negative twin: low-diversity alphanumeric blob (placeholder-shape) is already
// caught by other gates; the diversity floor of 32 distinct alphanumeric chars
// protects against suppressing only-a-few-distinct values.
#[test]
fn looks_like_uniform_base64_blob_rejects_low_diversity_alnum() {
    // 44 chars mult-of-4, few distinct chars total.
    let v = "aabbccABCabcABCabcABCabcABCabcABCabcABCabcABC";
    let mut set = std::collections::BTreeSet::new();
    for ch in v.chars() {
        set.insert(ch);
    }
    let v = &v[..44];
    assert_eq!(v.len(), 44);
    assert!(set.len() < 32);
    assert!(
        !looks_like_uniform_base64_blob(v),
        "low-alphabet-diversity 44-char no-punct no-pad base64 must \
         not fire (diversity gate keeps placeholders out)",
    );
}

// Positive truth case: k8s `data:` outer wrapper is base64-of-base64. The
// decoded bytes are themselves an all-base64-alphabet string of >= 32 chars.
// This is categorically a binary-data wrapper, not a credential.
#[test]
fn decoded_is_base64_blob_detects_double_b64() {
    let inner = "A".repeat(40);
    let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
    assert!(
        decoded_is_base64_blob(&outer),
        "base64-of-base64 (k8s data: shape) must be flagged as a \
         binary blob, not a credential",
    );
}

// Negative twin: a real (random-bytes) secret base64-encoded once decodes to
// random bytes that are NOT in the base64 alphabet. The helper must return
// false on this shape so real secrets stay live.
#[test]
fn decoded_is_base64_blob_rejects_random_secret_bytes() {
    let raw: [u8; 30] = [
        0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x7f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    ];
    let outer = base64::engine::general_purpose::STANDARD.encode(raw);
    assert!(
        !decoded_is_base64_blob(&outer),
        "base64 of random secret bytes must NOT be flagged as a \
         double-b64 blob (real secrets must stay live)",
    );
}

#[test]
fn decodes_to_printable_text_accepts_base64_wrapped_secret_text() {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(b"hello-world-this-is-a-secret-value");
    assert!(
        decodes_to_printable_text(&encoded),
        "credential-keyword-anchored base64 text must be distinguishable from random binary blobs",
    );
}

#[test]
fn decodes_to_printable_text_rejects_binary_bytes() {
    let raw: [u8; 12] = [
        0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x7f, 0x10, 0x11, 0x12, 0x13, 0x14,
    ];
    let encoded = base64::engine::general_purpose::STANDARD.encode(raw);
    assert!(
        !decodes_to_printable_text(&encoded),
        "binary base64 payloads must stay in the blob/data-envelope class",
    );
}
