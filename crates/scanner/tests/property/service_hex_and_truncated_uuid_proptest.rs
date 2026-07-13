//! Service-hex-key + truncated-UUID-v4 shape contracts
//! (`crates/scanner/src/suppression/shape/canonical.rs`).
//!
//! Two more shape gates, plus a length-set DIVERGENCE this suite pins so the two
//! hex gates are never conflated:
//!   • `is_canonical_service_hex_key`: uniform-case pure hex at a SERVICE-KEY
//!     width `32/40/48/64` (a real anchored service key).
//!   • `looks_like_bare_hex_digest`: the BROADER digest widths
//!     `32/40/48/56/64/72/128`. So `56/72/128`-hex is a digest but NOT a service
//!     key; the service set is a strict subset.
//!   • `looks_like_truncated_uuid_v4_suffix`: a UUID v4 with its 2 leading hex
//!     chars dropped (34 chars, `6-4-4-4-12`, version `4` at 12, variant at 17).

use keyhog_scanner::testing::{
    is_canonical_service_hex_key_for_test, looks_like_bare_hex_digest_for_test,
    looks_like_truncated_uuid_v4_suffix_for_test,
};
use proptest::prelude::*;

// ── service hex key ↔ bare digest length divergence ──────────────────────────

#[test]
fn service_key_widths_are_a_strict_subset_of_digest_widths() {
    // Shared widths: both accept 32/40/48/64.
    for len in [32usize, 40, 48, 64] {
        let hex = "a".repeat(len);
        assert!(is_canonical_service_hex_key_for_test(&hex), "service {len}");
        assert!(looks_like_bare_hex_digest_for_test(&hex), "digest {len}");
    }
    // Digest-only widths: 56/72/128 are digests but NOT service keys.
    for len in [56usize, 72, 128] {
        let hex = "a".repeat(len);
        assert!(
            !is_canonical_service_hex_key_for_test(&hex),
            "service must reject {len}"
        );
        assert!(
            looks_like_bare_hex_digest_for_test(&hex),
            "digest must accept {len}"
        );
    }
}

#[test]
fn service_key_rejects_mixed_case_and_non_hex() {
    let mixed = format!("{}{}", "a".repeat(16), "A".repeat(16)); // 32 chars, mixed
    assert!(!is_canonical_service_hex_key_for_test(&mixed));
    let non_hex = format!("{}z", "a".repeat(31)); // 32 chars, one non-hex
    assert!(!is_canonical_service_hex_key_for_test(&non_hex));
}

// ── truncated UUID v4 ────────────────────────────────────────────────────────

#[test]
fn a_truncated_uuid_v4_is_recognized() {
    // 6-4-4-4-12 with version 4 at index 12 and variant 8 at index 17.
    assert!(looks_like_truncated_uuid_v4_suffix_for_test(
        "abcdef-0123-4bcd-8def-0123456789ab"
    ));
}

#[test]
fn non_truncated_uuid_shapes_are_rejected() {
    assert!(!looks_like_truncated_uuid_v4_suffix_for_test(
        "abcdef-0123-4bcd-8def-0123456789a"
    )); // 33 chars
    assert!(!looks_like_truncated_uuid_v4_suffix_for_test(
        "abcdef-0123-1bcd-8def-0123456789ab"
    )); // version '1', not '4' at index 12
    assert!(!looks_like_truncated_uuid_v4_suffix_for_test(
        "abcdef-0123-4bcd-cdef-0123456789ab"
    )); // variant 'c' (not 8/9/a/b) at index 17
    assert!(!looks_like_truncated_uuid_v4_suffix_for_test(
        "abcdef-0123-4Bcd-8def-0123456789ab"
    )); // MIXED case
    assert!(!looks_like_truncated_uuid_v4_suffix_for_test(
        "550e8400-e29b-41d4-a716-446655440000"
    )); // a FULL (36-char) uuid, not truncated
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// A uniform-lowercase hex string is a service key IFF its length is one of the
    /// four service widths (exact membership, and NEVER a 56/72/128 digest width).
    #[test]
    fn lowercase_hex_is_service_key_iff_service_width(len in 1usize..140) {
        let hex = "a".repeat(len);
        let expected = matches!(len, 32 | 40 | 48 | 64);
        prop_assert_eq!(is_canonical_service_hex_key_for_test(&hex), expected);
        // The divergence guard: 56/72/128 must never be a service key.
        if matches!(len, 56 | 72 | 128) {
            prop_assert!(!is_canonical_service_hex_key_for_test(&hex));
        }
    }

    /// A truncated-UUID match IMPLIES 34 bytes with the exact `6-4-4-4-12` dash
    /// layout, a `4` at index 12, and a variant byte at index 17.
    #[test]
    fn truncated_uuid_match_implies_layout(value in "[0-9a-fA-F-]{0,40}") {
        if looks_like_truncated_uuid_v4_suffix_for_test(&value) {
            let b = value.as_bytes();
            prop_assert_eq!(b.len(), 34);
            prop_assert!(b[6] == b'-' && b[11] == b'-' && b[16] == b'-' && b[21] == b'-');
            prop_assert_eq!(b[12], b'4');
            prop_assert!(matches!(b[17], b'8' | b'9' | b'a' | b'b' | b'A' | b'B'));
        }
    }
}
