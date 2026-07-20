//! Behavioral contract for the Stripe checksum validator
//! (crates/scanner/src/checksum/stripe.rs), exercised through the REAL public
//! API `keyhog_scanner::checksum::{validate_checksum, checksum_adjusted_confidence}`.
//!
//! Stripe publishes NO checksum, so a structurally-valid Stripe key must report
//! `StructurallyValid`: NOT `Valid`: which means its confidence passes through
//! UNCHANGED and it never receives the `CHECKSUM_VALID_FLOOR` (0.9) that a real
//! CRC-checksummed token (GitHub/npm/…) earns. That distinction is the load-
//! bearing detection-truth contract: treating a Stripe shape as checksum-proven
//! would wrongly lift every `sk_live_`-shaped false positive over the
//! high-precision bar. These pin it with exact `ChecksumResult` values and the
//! exact confidence each verdict produces.

use keyhog_scanner::checksum::{checksum_adjusted_confidence, validate_checksum, ChecksumResult};

/// `sk_live_` + `n` alphanumeric payload chars.
fn stripe_key(prefix: &str, payload_len: usize) -> String {
    format!("{prefix}{}", "a".repeat(payload_len))
}

#[test]
fn valid_stripe_shape_is_structurally_valid_not_checksum_valid() {
    let key = stripe_key("sk_live_", 24);
    assert_eq!(
        validate_checksum(&key),
        ChecksumResult::StructurallyValid,
        "a valid Stripe shape has no checksum to verify -> StructurallyValid, never Valid"
    );
}

#[test]
fn structurally_valid_stripe_passes_confidence_through_with_no_checksum_floor() {
    // The whole point: a Stripe key must NOT be lifted to the 0.9 checksum floor
    // a CRC-valid token gets. 0.5 in -> 0.5 out (unchanged), not 0.9.
    let key = stripe_key("pk_live_", 24);
    assert_eq!(
        checksum_adjusted_confidence(0.5, &key),
        Some(0.5),
        "StructurallyValid passes confidence through unchanged (no embedded-checksum floor)"
    );
}

#[test]
fn stripe_payload_length_floor_is_24() {
    // 23 payload chars is below the documented "24+" floor -> Invalid (wrong
    // family shape); exactly 24 is the boundary and is StructurallyValid.
    assert_eq!(
        validate_checksum(&stripe_key("sk_live_", 23)),
        ChecksumResult::Invalid,
        "a 23-char payload is below the 24 floor"
    );
    assert_eq!(
        validate_checksum(&stripe_key("sk_live_", 24)),
        ChecksumResult::StructurallyValid,
        "a 24-char payload is exactly at the floor"
    );
}

#[test]
fn stripe_payload_length_ceiling_is_128() {
    assert_eq!(
        validate_checksum(&stripe_key("sk_test_", 128)),
        ChecksumResult::StructurallyValid,
        "a 128-char payload is exactly at the ceiling"
    );
    assert_eq!(
        validate_checksum(&stripe_key("sk_test_", 129)),
        ChecksumResult::Invalid,
        "a 129-char payload is above the 128 ceiling"
    );
}

#[test]
fn stripe_payload_must_be_all_ascii_alphanumeric() {
    // 24 chars but one is a non-alphanumeric byte -> Invalid alphabet.
    let key = format!("rk_live_{}!", "a".repeat(23));
    assert_eq!(
        validate_checksum(&key),
        ChecksumResult::Invalid,
        "a non-alphanumeric payload byte fails the alphabet gate"
    );
}

#[test]
fn all_four_secret_stripe_prefixes_claim_the_token() {
    for prefix in ["sk_live_", "sk_test_", "rk_live_", "rk_test_"] {
        assert_eq!(
            validate_checksum(&stripe_key(prefix, 24)),
            ChecksumResult::StructurallyValid,
            "prefix {prefix} must be claimed as a structurally-valid Stripe key"
        );
    }
    for prefix in ["pk_live_", "pk_test_"] {
        assert_eq!(
            validate_checksum(&stripe_key(prefix, 24)),
            ChecksumResult::NotApplicable,
            "publishable prefix {prefix} must not be claimed by the secret-key validator"
        );
    }
}

#[test]
fn invalid_stripe_shape_drops_the_match() {
    // The Invalid verdict (here: too-short payload) makes the confidence policy
    // return None so the caller DROPS the match (even from a high 0.9 input).
    let key = stripe_key("sk_live_", 23);
    assert_eq!(
        checksum_adjusted_confidence(0.9, &key),
        None,
        "an Invalid Stripe shape drops the match regardless of incoming confidence"
    );
}
