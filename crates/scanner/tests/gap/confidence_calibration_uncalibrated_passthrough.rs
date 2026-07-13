//! KH-GAP-016: uncalibrated detectors must not halve confidence on fresh install.

use keyhog_scanner::testing::confidence::apply_calibration_multiplier;

#[test]
fn confidence_calibration_uncalibrated_passthrough() {
    let score = apply_calibration_multiplier(0.84, "nonexistent-detector-id-lr1-a4");
    assert!(
        (score - 0.84).abs() < 1e-9,
        "zero-observation detector must pass score through unchanged, got {score}"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector pins one score/detector; these SWEEP the fresh-install
// passthrough. The 2-arg facade supplies `None` calibration (the no-history-loaded
// state), so the multiplier is never applied, every in-range score returns
// unchanged, for ANY detector id, and the result is independent of the id (proving
// no per-detector multiplier leaks in on a fresh install, the KH-GAP-016 recall
// guarantee: uncalibrated detectors must not halve confidence). Traced against
// `apply_calibration_multiplier` (penalties.rs). No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// An in-range score passes through unchanged for any detector id (no
    /// calibration multiplier on a fresh install).
    #[test]
    fn uncalibrated_score_passes_through(
        score in 0.0f64..=1.0,
        id in "[a-zA-Z0-9_-]{0,24}",
    ) {
        let out = apply_calibration_multiplier(score, &id);
        prop_assert!(
            (out - score).abs() < 1e-9,
            "score {score} for detector {id:?} must pass through, got {out}"
        );
    }

    /// The passthrough is independent of the detector id: two different ids give the
    /// exact same output for the same score (no per-detector shaping without history).
    #[test]
    fn passthrough_is_independent_of_detector_id(
        score in 0.0f64..=1.0,
        id1 in "[a-zA-Z0-9_-]{0,24}",
        id2 in "[a-zA-Z0-9_-]{0,24}",
    ) {
        prop_assert_eq!(
            apply_calibration_multiplier(score, &id1),
            apply_calibration_multiplier(score, &id2)
        );
    }
}
