//! Gap test: the generic-secret confidence formula.
//!
//! `generic_secret_confidence` is the owner of the generic-emitter base score
//! (context base + entropy boost + length boost, capped at 0.95). The only
//! existing coverage is a source-shape gate that checks the function *exists*;
//! its computed values were never pinned. Pin the exact formula, including the
//! context-base gating and the deliberate asymmetry: the entropy term has NO
//! lower bound (a low-entropy generic value is penalised) while the length term
//! is clamped to >= 0 (a short value is never penalised for length).
//!
//! Boost-zeroing inputs: entropy == 3.5 makes `(entropy - 3.5) * 0.1 == 0`, and
//! value_len == 16 makes `(len - 16) * 0.005 == 0`, so the result is exactly the
//! context base — keeping these assertions off float-rounding fragility.

use keyhog_scanner::testing::generic_secret_confidence_for_test as conf;

#[test]
fn context_base_confidence_and_gating_are_exact() {
    // Ordinary source (Unknown) -> 0.60, regardless of flags.
    assert_eq!(conf("source", false, true, 3.5, 16), 0.60);
    // Comment is 0.30 by default, but lifts to the source floor with --scan-comments.
    assert_eq!(conf("comment", false, false, 3.5, 16), 0.30);
    assert_eq!(conf("comment", true, false, 3.5, 16), 0.60);
    // TestCode/Documentation are haircut ONLY when test paths are penalised;
    // with --no-suppress-test-fixtures they fall back to the source floor.
    assert_eq!(conf("test", false, true, 3.5, 16), 0.25);
    assert_eq!(conf("test", false, false, 3.5, 16), 0.60);
    assert_eq!(conf("doc", false, true, 3.5, 16), 0.30);
    assert_eq!(conf("doc", false, false, 3.5, 16), 0.60);
}

#[test]
fn entropy_and_length_boosts_saturate_at_the_ceiling() {
    // High entropy (boost caps at 0.25) + long value (boost caps at 0.15) push
    // 0.60 + 0.25 + 0.15 = 1.00 past the 0.95 confidence ceiling.
    assert_eq!(conf("source", false, true, 10.0, 100), 0.95);
}

#[test]
fn short_value_gets_no_negative_length_penalty() {
    // value_len 10 (< 16) would make the length term negative, but it clamps to
    // 0, so the result is exactly the un-boosted base (not below it).
    assert_eq!(conf("source", false, true, 3.5, 10), 0.60);
}

#[test]
fn low_entropy_lowers_confidence_below_the_unboosted_base() {
    // The entropy term has no lower clamp, so a below-3.5-entropy generic value
    // scores strictly under the 0.60 base (deterministic, asserted relationally
    // to avoid float-equality fragility on the negative term).
    let baseline = conf("source", false, true, 3.5, 16);
    let low_entropy = conf("source", false, true, 1.5, 16);
    assert_eq!(baseline, 0.60);
    assert!(
        low_entropy < baseline,
        "low-entropy generic value should score below the base, got {low_entropy}"
    );
    assert!(
        low_entropy > 0.0,
        "confidence stays positive, got {low_entropy}"
    );
}
