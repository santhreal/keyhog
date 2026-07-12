//! `generic_secret_confidence` policy: the entropy and length boosts floor at
//! zero (a low-entropy value never becomes a NEGATIVE penalty) and the total
//! clamps to the 0.95 upper bound. Migrated from an inline `#[cfg(test)]` block
//! in `src/confidence/policy.rs`; reached via the `keyhog_scanner::testing`
//! `generic_secret_confidence_for_test` facade (context passed as a label).

use keyhog_scanner::testing::generic_secret_confidence_for_test as conf;

#[test]
fn low_entropy_never_drives_confidence_below_base() {
    // Entropy well below the pivot must NOT become a negative penalty: the boost
    // floors at 0.0, so a low-base TestCode credential keeps its 0.25 base rather
    // than collapsing toward zero.
    let c = conf("test", false, true, 0.0, 16);
    assert!(
        (c - 0.25).abs() < 1e-9,
        "entropy 0.0 must not subtract from the base, got {c}"
    );

    // The positive-entropy path is unchanged and still caps at +0.25.
    let boosted = conf("assignment", false, true, 10.0, 16);
    assert!(
        (boosted - 0.85).abs() < 1e-9,
        "0.60 base + capped 0.25 entropy boost, got {boosted}"
    );
}

#[test]
fn confidence_is_clamped_to_the_upper_bound() {
    // Max base (0.60) + max entropy boost (0.25) + max length boost (0.15) = 1.0
    // raw, which the clamp caps at 0.95.
    let c = conf("assignment", false, true, 20.0, 4096);
    assert!(
        (c - 0.95).abs() < 1e-9,
        "saturated signals must clamp to 0.95, got {c}"
    );
}
