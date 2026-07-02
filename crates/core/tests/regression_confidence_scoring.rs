//! Regression coverage for the CORE confidence-scoring contract.
//!
//! Distinct from `regression_calibration_beta.rs` (which pins raw counter
//! increments and the persisted-cache error variants): this file exercises the
//! confidence *score* the scanner actually consumes. The scanner's
//! `scanner::confidence::penalties::apply_calibration_multiplier` reads exactly
//! two things out of this crate: the per-detector multiplier
//! (`Calibration::confidence_multiplier`, surfaced host-independently via
//! `CoreTestApi::calibration_confidence_multiplier`) and the observation-count
//! gate (`BetaCounters::observations`, via `CoreTestApi::beta_observations`).
//! Its shaping rule is: keep the raw score unchanged while a detector is still
//! at the Beta(1,1) prior (0 observations), otherwise multiply the score by the
//! posterior mean, then clamp to [MIN, MAX].
//!
//! Every test pins a concrete value: an exact multiplier for a reliable
//! exact-format detector, a strictly lower multiplier for a noisy generic
//! detector, the exact shaped score `raw * multiplier`, a strict [0, 1] bound
//! across adversarial `u32::MAX` extremes, and the fresh-detector gate boundary.
//! Access goes through the `doc(hidden)` `testing` facade rather than weakening
//! production visibility. The math here is pure f64 (no accelerator), so the
//! assertions are identical on every host.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{BetaCounters, Calibration};

const EPS: f64 = 1e-12;

/// The per-detector confidence multiplier the scanner multiplies a raw
/// heuristic score by. Equals the Beta posterior mean of the detector's
/// counters; 0.5 for a never-calibrated detector.
fn mult(c: &Calibration, id: &str) -> f64 {
    TestApi.calibration_confidence_multiplier(c, id)
}

/// Observations beyond the Beta(1,1) prior. The scanner gate: 0 => the
/// multiplier is NOT applied (raw score preserved); >0 => it shapes the score.
fn obs(c: &Calibration, id: &str) -> u32 {
    let counters = c.counters(id);
    TestApi.beta_observations(&counters)
}

// ---------------------------------------------------------------------------
// Neutral prior: an uncalibrated detector must not shape the score
// ---------------------------------------------------------------------------

#[test]
fn uncalibrated_detector_multiplier_is_neutral_half_and_gate_off() {
    let c = Calibration::default();
    // Never-seen detector sits at the Beta(1,1) uniform prior.
    assert_eq!(
        mult(&c, "never-seen"),
        0.5,
        "prior multiplier is exactly 1/2"
    );
    // ...but the observation gate is 0, so the scanner leaves the raw score
    // untouched instead of halving every fresh finding.
    assert_eq!(obs(&c, "never-seen"), 0, "prior has zero observations");
}

// ---------------------------------------------------------------------------
// High-confidence exact-format detector scores its exact multiplier
// ---------------------------------------------------------------------------

#[test]
fn reliable_exact_format_detector_scores_its_exact_high_multiplier() {
    // A long clean history for an exact-format detector (e.g. aws-access-key):
    // 14 confirmed TPs on the prior => alpha=15, beta=1 => 15/16 = 0.9375,
    // which is exactly representable in f64.
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "aws-access-key", 15, 1);
    assert_eq!(mult(&c, "aws-access-key"), 0.9375, "15/16 exact");
    assert_eq!(
        obs(&c, "aws-access-key"),
        14,
        "14 observations past the prior"
    );
}

// ---------------------------------------------------------------------------
// Negative twin: a low-entropy generic detector scores strictly lower
// ---------------------------------------------------------------------------

#[test]
fn noisy_generic_detector_scores_lower_multiplier_than_exact_format() {
    let c = Calibration::default();
    // Reliable exact-format detector.
    TestApi.seed_calibration_counters(&c, "exact", 15, 1); // 0.9375
                                                           // Noisy generic keyword detector: 3 confirmed FPs on the prior =>
                                                           // alpha=1, beta=4 => 1/5 = 0.2 (1.0/5.0 rounds to the same f64 as 0.2).
    TestApi.seed_calibration_counters(&c, "generic", 1, 4); // 0.2

    let exact = mult(&c, "exact");
    let generic = mult(&c, "generic");
    assert_eq!(exact, 0.9375, "exact-format multiplier");
    assert_eq!(generic, 0.2, "generic multiplier");
    assert!(
        generic < exact,
        "generic {generic} must rank below exact {exact}"
    );
}

// ---------------------------------------------------------------------------
// Headline shaping: raw * multiplier orders exact-format above generic,
// and the exact-format match keeps its exact shaped confidence.
// ---------------------------------------------------------------------------

#[test]
fn calibrated_score_shaping_orders_exact_above_generic() {
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "exact", 15, 1); // 0.9375
    TestApi.seed_calibration_counters(&c, "generic", 1, 4); // 0.2

    // Same raw heuristic score entering the calibration multiplier.
    let raw = 0.8_f64;
    let exact_shaped = raw * mult(&c, "exact"); // 0.8 * 0.9375 = 0.75 (exact)
    let generic_shaped = raw * mult(&c, "generic"); // 0.8 * 0.2   = 0.16

    assert_eq!(exact_shaped, 0.75, "0.8 * 0.9375 = 0.75 exactly");
    assert!(
        (generic_shaped - 0.16).abs() < EPS,
        "0.8 * 0.2 ≈ 0.16, got {generic_shaped}"
    );
    assert!(
        exact_shaped > generic_shaped,
        "exact-format shaped {exact_shaped} must outrank generic {generic_shaped}"
    );
}

// ---------------------------------------------------------------------------
// The multiplier the scanner reads == the stored counters' posterior mean
// ---------------------------------------------------------------------------

#[test]
fn multiplier_equals_stored_counter_posterior_mean() {
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "d", 7, 3); // 7/10 = 0.7
    let via_facade = mult(&c, "d");
    let counters = c.counters("d");
    let via_posterior = TestApi.beta_posterior_mean(&counters);
    assert_eq!(
        via_facade.to_bits(),
        via_posterior.to_bits(),
        "multiplier must be bit-identical to the posterior mean"
    );
    assert!(
        (via_facade - 0.7).abs() < EPS,
        "7/10 ≈ 0.7, got {via_facade}"
    );
}

// ---------------------------------------------------------------------------
// A history of true positives monotonically raises the multiplier
// ---------------------------------------------------------------------------

#[test]
fn true_positive_history_monotonically_raises_multiplier() {
    let c = Calibration::default();
    assert_eq!(mult(&c, "d"), 0.5, "start at the prior");
    let mut prev = mult(&c, "d");
    // 1/2 -> 2/3 -> 3/4 -> 4/5 -> 5/6 -> 6/7
    for _ in 0..5 {
        c.record_outcome("d", true);
        let now = mult(&c, "d");
        assert!(now > prev, "each TP must strictly raise: {prev} -> {now}");
        prev = now;
    }
    assert_eq!(c.counters("d"), BetaCounters { alpha: 6, beta: 1 });
    assert!(
        (mult(&c, "d") - 6.0 / 7.0).abs() < EPS,
        "final multiplier is 6/7"
    );
}

// ---------------------------------------------------------------------------
// A history of false positives monotonically lowers the multiplier
// ---------------------------------------------------------------------------

#[test]
fn false_positive_history_monotonically_lowers_multiplier() {
    let c = Calibration::default();
    let mut prev = mult(&c, "noisy");
    // 1/2 -> 1/3 -> 1/4 -> 1/5
    for _ in 0..3 {
        c.record_outcome("noisy", false);
        let now = mult(&c, "noisy");
        assert!(now < prev, "each FP must strictly lower: {prev} -> {now}");
        prev = now;
    }
    assert_eq!(c.counters("noisy"), BetaCounters { alpha: 1, beta: 4 });
    assert_eq!(mult(&c, "noisy"), 0.2, "final multiplier is 1/5 = 0.2");
}

// ---------------------------------------------------------------------------
// Symmetric history scores exactly one half (seeded and accumulated forms)
// ---------------------------------------------------------------------------

#[test]
fn symmetric_history_multiplier_is_exactly_half() {
    let seeded = Calibration::default();
    TestApi.seed_calibration_counters(&seeded, "d", 5, 5); // 5/10
    assert_eq!(mult(&seeded, "d"), 0.5, "seeded symmetric counts => 0.5");

    let accumulated = Calibration::default();
    accumulated.record_outcome("d", true);
    accumulated.record_outcome("d", false);
    accumulated.record_outcome("d", true);
    accumulated.record_outcome("d", false);
    assert_eq!(
        accumulated.counters("d"),
        BetaCounters { alpha: 3, beta: 3 }
    );
    assert_eq!(mult(&accumulated, "d"), 0.5, "2 TP + 2 FP => 3/6 = 0.5");
}

// ---------------------------------------------------------------------------
// Boundedness: multiplier stays strictly within (0, 1) across extremes
// ---------------------------------------------------------------------------

#[test]
fn multiplier_bounded_unit_interval_across_extremes() {
    let c = Calibration::default();
    let cases = [
        ("prior", 1u32, 1u32),
        ("exact", 15, 1),
        ("generic", 1, 4),
        ("three_quarters", 3, 1),
        ("max_alpha", u32::MAX, 1),
        ("max_beta", 1, u32::MAX),
    ];
    for (id, a, b) in cases {
        TestApi.seed_calibration_counters(&c, id, a, b);
        let m = mult(&c, id);
        assert!(m.is_finite(), "{id}: multiplier must be finite, got {m}");
        assert!(
            m > 0.0 && m < 1.0,
            "{id}: multiplier must lie strictly in (0,1), got {m}"
        );
    }
    // Exact anchor inside the sweep: 3/(3+1) = 0.75.
    assert_eq!(mult(&c, "three_quarters"), 0.75);
}

// ---------------------------------------------------------------------------
// Adversarial saturation: a fully-saturated TP counter never claims certainty
// ---------------------------------------------------------------------------

#[test]
fn saturated_true_positive_multiplier_stays_below_one() {
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "d", u32::MAX, 1);
    let m = mult(&c, "d");
    // u32::MAX / (u32::MAX + 1) = 1 - 2^-32 ≈ 0.99999999977, strictly < 1.
    assert!(
        m < 1.0,
        "saturated confidence must never reach 1.0, got {m}"
    );
    assert!(m > 0.999_999_9, "but must be very close to 1.0, got {m}");
    // Recording another TP saturates alpha at u32::MAX: the score is unchanged,
    // never wrapping to a lower (or exactly-1.0) value.
    TestApi.calibration_record_true_positive(&c, "d");
    assert_eq!(
        mult(&c, "d").to_bits(),
        m.to_bits(),
        "saturated multiplier must be frozen, not wrapped"
    );
}

// ---------------------------------------------------------------------------
// Adversarial saturation: a fully-saturated FP counter never claims impossible
// ---------------------------------------------------------------------------

#[test]
fn saturated_false_positive_multiplier_stays_above_zero() {
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "d", 1, u32::MAX);
    let m = mult(&c, "d");
    // 1 / (1 + u32::MAX) = 2^-32 ≈ 2.33e-10, strictly > 0 (never fully mutes).
    assert!(
        m > 0.0,
        "saturated FP confidence must stay above 0.0, got {m}"
    );
    assert!(m < 1e-6, "but must be tiny, got {m}");
}

// ---------------------------------------------------------------------------
// Detectors score independently: no cross-talk between calibrated ids
// ---------------------------------------------------------------------------

#[test]
fn detectors_score_independently_no_crosstalk() {
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "a", 3, 1); // 0.75
    TestApi.seed_calibration_counters(&c, "b", 1, 3); // 0.25
    assert_eq!(mult(&c, "a"), 0.75);
    assert_eq!(mult(&c, "b"), 0.25);
    // A third, untouched detector remains at the neutral prior.
    assert_eq!(mult(&c, "c"), 0.5);
    assert!(
        mult(&c, "a") != mult(&c, "b"),
        "distinct histories, distinct scores"
    );
}

// ---------------------------------------------------------------------------
// record_outcome and the explicit TP/FP paths produce identical scores
// ---------------------------------------------------------------------------

#[test]
fn record_outcome_and_explicit_paths_score_identically() {
    let via_outcome = Calibration::default();
    via_outcome.record_outcome("d", true);
    via_outcome.record_outcome("d", true);
    via_outcome.record_outcome("d", false);

    let via_explicit = Calibration::default();
    TestApi.calibration_record_true_positive(&via_explicit, "d");
    TestApi.calibration_record_true_positive(&via_explicit, "d");
    TestApi.calibration_record_false_positive(&via_explicit, "d");

    // Both reach alpha=3, beta=2 => 3/5 = 0.6.
    assert_eq!(
        via_outcome.counters("d"),
        BetaCounters { alpha: 3, beta: 2 }
    );
    assert_eq!(
        mult(&via_outcome, "d").to_bits(),
        mult(&via_explicit, "d").to_bits(),
        "the two recording paths must yield a bit-identical multiplier"
    );
    assert!((mult(&via_outcome, "d") - 0.6).abs() < EPS, "3/5 ≈ 0.6");
}

// ---------------------------------------------------------------------------
// The observation gate boundary: fresh score is preserved, calibrated is shaped
// ---------------------------------------------------------------------------

#[test]
fn observation_gate_preserves_fresh_score_but_shapes_calibrated() {
    let c = Calibration::default();
    // Reliable-but-imperfect detector: 6 TP + 1 FP on the prior =>
    // alpha=7, beta=1 => 7/8 = 0.875, observations = 6.
    TestApi.seed_calibration_counters(&c, "calibrated", 7, 1);

    let raw = 0.8_f64;

    // Fresh detector: gate is 0, so the scanner leaves the raw score untouched.
    assert_eq!(obs(&c, "fresh"), 0, "fresh detector has no observations");
    let fresh_score = if obs(&c, "fresh") == 0 {
        raw
    } else {
        raw * mult(&c, "fresh")
    };
    assert_eq!(fresh_score, 0.8, "uncalibrated score is preserved verbatim");

    // Calibrated detector: gate > 0, so the multiplier shapes the score.
    assert_eq!(obs(&c, "calibrated"), 6, "6 observations past the prior");
    assert_eq!(mult(&c, "calibrated"), 0.875, "7/8 exact");
    let calibrated_score = if obs(&c, "calibrated") == 0 {
        raw
    } else {
        raw * mult(&c, "calibrated")
    };
    assert!(
        (calibrated_score - 0.7).abs() < EPS,
        "0.8 * 0.875 = 0.7, got {calibrated_score}"
    );
    assert!(
        calibrated_score < fresh_score,
        "a good-but-imperfect history should pull the score below the raw value"
    );
}
