//! UUID / bare-hex-digest FP-suppression shape contracts
//! (`crates/scanner/src/suppression/shape/canonical.rs`).
//!
//! Two precision gates that keep hash digests and UUIDs out of the findings:
//!   • `is_uuid_v4_shape`: a canonical 36-char `8-4-4-4-12` UUID (any RFC-4122
//!     version) with UNIFORM-case hex bodies. A standard-shaped UUID is a decoy.
//!   • `looks_like_bare_hex_digest`: a uniform-case pure-hex value at a hash or
//!     truncated-hash-prefix length (32/40/48/56/64/72/128). Real keys of those
//!     widths are base64, not hex, so a pure-hex hit there is a digest FP.
//! Both reject MIXED case (`aB…`), a real digest/UUID is emitted uniform-case,
//! and mixed case signals a coincidental non-digest value that other gates judge.

use keyhog_scanner::testing::{is_uuid_v4_shape_for_test, looks_like_bare_hex_digest_for_test};
use proptest::prelude::*;

// ── UUID shape ───────────────────────────────────────────────────────────────

#[test]
fn canonical_uuids_of_any_version_match() {
    assert!(is_uuid_v4_shape_for_test(
        "550e8400-e29b-41d4-a716-446655440000"
    )); // v4
    assert!(is_uuid_v4_shape_for_test(
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    )); // v1
    assert!(is_uuid_v4_shape_for_test(
        "00000000-0000-0000-0000-000000000000"
    )); // nil
    assert!(is_uuid_v4_shape_for_test(
        "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"
    )); // upper
}

#[test]
fn non_uuid_shapes_are_rejected() {
    assert!(!is_uuid_v4_shape_for_test(
        "550e8400-e29b-41d4-a716-44665544000"
    )); // 35 chars
    assert!(!is_uuid_v4_shape_for_test(
        "550e8400e29b41d4a716446655440000"
    )); // no dashes
    assert!(!is_uuid_v4_shape_for_test(
        "550e8400-e29b-41d4-a716-44665544zzzz"
    )); // non-hex
    assert!(!is_uuid_v4_shape_for_test(
        "550e8400-E29b-41d4-a716-446655440000"
    )); // MIXED case
    assert!(!is_uuid_v4_shape_for_test("")); // empty
}

// ── bare hex digest ──────────────────────────────────────────────────────────

#[test]
fn bare_hex_digests_at_hash_lengths_match() {
    assert!(looks_like_bare_hex_digest_for_test(&"a".repeat(32))); // md5
    assert!(looks_like_bare_hex_digest_for_test(&"a".repeat(40))); // sha1
    assert!(looks_like_bare_hex_digest_for_test(&"a".repeat(48))); // truncated-prefix
    assert!(looks_like_bare_hex_digest_for_test(&"a".repeat(64))); // sha256
    assert!(looks_like_bare_hex_digest_for_test(&"F".repeat(128))); // sha512, upper
}

#[test]
fn off_length_or_mixed_case_hex_is_not_a_bare_digest() {
    assert!(!looks_like_bare_hex_digest_for_test(&"a".repeat(33))); // 33 not a hash width
    assert!(!looks_like_bare_hex_digest_for_test(&"a".repeat(16))); // too short
                                                                    // 64 chars but MIXED case → not a uniform digest.
    let mixed = format!("{}{}", "a".repeat(32), "A".repeat(32));
    assert!(!looks_like_bare_hex_digest_for_test(&mixed));
    // 64 chars with a non-hex byte.
    let non_hex = format!("{}z", "a".repeat(63));
    assert!(!looks_like_bare_hex_digest_for_test(&non_hex));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A UUID match IMPLIES exactly 36 bytes with dashes at 8/13/18/23, the gate
    /// can never fire on a differently-shaped string.
    #[test]
    fn uuid_match_implies_canonical_layout(value in "[0-9a-fA-F-]{0,40}") {
        if is_uuid_v4_shape_for_test(&value) {
            let b = value.as_bytes();
            prop_assert_eq!(b.len(), 36);
            prop_assert!(b[8] == b'-' && b[13] == b'-' && b[18] == b'-' && b[23] == b'-');
        }
    }

    /// A uniform-LOWER-case pure-hex string is a bare digest IFF its length is one
    /// of the seven recognized hash / truncated-prefix widths (exact membership).
    #[test]
    fn lowercase_hex_is_digest_iff_recognized_length(len in 1usize..160) {
        let value = "a".repeat(len);
        let expected = matches!(len, 32 | 40 | 48 | 56 | 64 | 72 | 128);
        prop_assert_eq!(looks_like_bare_hex_digest_for_test(&value), expected);
    }

    /// A digest hit ALWAYS has a recognized length and is all-hex, no false hit on
    /// an off-length or non-hex value.
    #[test]
    fn digest_match_implies_hash_length_and_hex(value in "[0-9a-fA-F]{0,140}") {
        if looks_like_bare_hex_digest_for_test(&value) {
            prop_assert!(matches!(value.len(), 32 | 40 | 48 | 56 | 64 | 72 | 128));
            prop_assert!(value.bytes().all(|b| b.is_ascii_hexdigit()));
        }
    }
}
