//! Regression coverage for the Bayesian Beta(α, β) calibration store.
//!
//! Every assertion pins a concrete value: exact counter increments after
//! `record_outcome`, the exact Beta posterior mean for known counts (with an
//! f64 epsilon), exact save→try_load round-trips, and the exact error variant
//! for each way a persisted cache can be untrustworthy. Posterior-mean access
//! goes through the crate's `doc(hidden)` testing facade
//! (`CoreTestApi::beta_posterior_mean`) rather than weakening production
//! visibility.

use keyhog_core::testing::{CoreTestApi, TestApi};
use keyhog_core::{BetaCounters, Calibration, CalibrationLoadError};

const EPS: f64 = 1e-12;

fn mean(counters: &BetaCounters) -> f64 {
    TestApi.beta_posterior_mean(counters)
}

// ---------------------------------------------------------------------------
// Counter increments
// ---------------------------------------------------------------------------

#[test]
fn record_true_increments_alpha_only_from_prior() {
    let c = Calibration::default();
    // Fresh detector starts at the Beta(1,1) uniform prior.
    assert_eq!(c.counters("d"), BetaCounters { alpha: 1, beta: 1 });
    c.record_outcome("d", true);
    let after = c.counters("d");
    assert_eq!(after.alpha, 2, "true positive bumps alpha");
    assert_eq!(after.beta, 1, "true positive leaves beta untouched");
}

#[test]
fn record_false_increments_beta_only_from_prior() {
    let c = Calibration::default();
    c.record_outcome("d", false);
    let after = c.counters("d");
    assert_eq!(after.alpha, 1, "false positive leaves alpha untouched");
    assert_eq!(after.beta, 2, "false positive bumps beta");
}

#[test]
fn interleaved_outcomes_yield_exact_counts() {
    let c = Calibration::default();
    // 3 TP, 2 FP interleaved.
    c.record_outcome("mixed", true);
    c.record_outcome("mixed", false);
    c.record_outcome("mixed", true);
    c.record_outcome("mixed", true);
    c.record_outcome("mixed", false);
    let after = c.counters("mixed");
    // prior (1,1) + 3 TP + 2 FP = (4, 3)
    assert_eq!(after.alpha, 4);
    assert_eq!(after.beta, 3);
}

#[test]
fn detectors_have_independent_counters() {
    let c = Calibration::default();
    c.record_outcome("aws", true);
    c.record_outcome("aws", true);
    c.record_outcome("gh", false);
    assert_eq!(c.counters("aws"), BetaCounters { alpha: 3, beta: 1 });
    assert_eq!(c.counters("gh"), BetaCounters { alpha: 1, beta: 2 });
    // A third, untouched id remains at the exact prior.
    assert_eq!(c.counters("other"), BetaCounters { alpha: 1, beta: 1 });
}

// ---------------------------------------------------------------------------
// Posterior mean = α / (α + β)
// ---------------------------------------------------------------------------

#[test]
fn unknown_id_yields_exact_prior_mean() {
    let c = Calibration::default();
    let counters = c.counters("never-seen");
    assert_eq!(counters, BetaCounters { alpha: 1, beta: 1 });
    // Beta(1,1) posterior mean = 1/2 = 0.5 exactly.
    assert_eq!(mean(&counters), 0.5);
}

#[test]
fn posterior_mean_three_quarters_is_exact() {
    // α=3, β=1 → 3/4 = 0.75 (exactly representable in f64).
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "d", 3, 1);
    assert_eq!(mean(&c.counters("d")), 0.75);
}

#[test]
fn posterior_mean_symmetric_counts_is_half() {
    // α=β=5 → 5/10 = 0.5 exactly.
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "d", 5, 5);
    assert_eq!(mean(&c.counters("d")), 0.5);
}

#[test]
fn posterior_mean_ten_over_eleven_within_epsilon() {
    // 9 true positives on a fresh detector → α=10, β=1 → 10/11 ≈ 0.909090...
    let c = Calibration::default();
    for _ in 0..9 {
        c.record_outcome("aws", true);
    }
    assert_eq!(c.counters("aws"), BetaCounters { alpha: 10, beta: 1 });
    let m = mean(&c.counters("aws"));
    assert!((m - 10.0_f64 / 11.0).abs() < EPS, "got {m}");
}

#[test]
fn posterior_mean_driven_down_by_false_positives() {
    // 3 false positives on a fresh detector → α=1, β=4 → 1/5 = 0.2 exactly.
    let c = Calibration::default();
    for _ in 0..3 {
        c.record_outcome("noisy", false);
    }
    assert_eq!(c.counters("noisy"), BetaCounters { alpha: 1, beta: 4 });
    assert_eq!(mean(&c.counters("noisy")), 0.2);
}

#[test]
fn posterior_mean_seven_over_ten_within_epsilon() {
    // α=7, β=3 → 0.7 (NOT exactly representable → epsilon compare).
    let c = Calibration::default();
    TestApi.seed_calibration_counters(&c, "d", 7, 3);
    let m = mean(&c.counters("d"));
    assert!((m - 0.7).abs() < EPS, "got {m}");
}

// ---------------------------------------------------------------------------
// save → try_load round-trip (strict loader, public API)
// ---------------------------------------------------------------------------

#[test]
fn save_then_try_load_roundtrips_exact_counts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");

    let c = Calibration::default();
    c.record_outcome("aws-access-key", true);
    c.record_outcome("aws-access-key", false);
    c.record_outcome("github-pat", true);
    c.record_outcome("github-pat", true);
    c.save(&path).unwrap();

    let loaded = Calibration::try_load(&path)
        .expect("strict load must not error on a well-formed cache")
        .expect("a cache we just wrote must be present");
    assert_eq!(
        loaded.counters("aws-access-key"),
        BetaCounters { alpha: 2, beta: 2 }
    );
    assert_eq!(
        loaded.counters("github-pat"),
        BetaCounters { alpha: 3, beta: 1 }
    );
    // Entries preserved exactly, sorted by id.
    let e = loaded.entries();
    assert_eq!(e.len(), 2);
    assert_eq!(e[0].0, "aws-access-key");
    assert_eq!(e[1].0, "github-pat");
}

#[test]
fn try_load_missing_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("does-not-exist.json");
    let result =
        Calibration::try_load(&path).expect("missing cache is a clean cold start, not an error");
    assert!(result.is_none(), "missing file must map to Ok(None)");
}

// ---------------------------------------------------------------------------
// Fail-closed error variants for an untrustworthy cache
// ---------------------------------------------------------------------------

#[test]
fn try_load_rejects_future_schema_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    std::fs::write(&path, br#"{"version":999,"detectors":{}}"#).unwrap();
    let err = Calibration::try_load(&path).expect_err("unknown schema version must fail closed");
    match err {
        CalibrationLoadError::SchemaVersion {
            found, expected, ..
        } => {
            assert_eq!(found, 999);
            assert_eq!(expected, 1);
        }
        other => panic!("expected SchemaVersion, got {other:?}"),
    }
}

#[test]
fn try_load_rejects_zero_counter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    std::fs::write(
        &path,
        br#"{"version":1,"detectors":{"aws":{"alpha":0,"beta":3}}}"#,
    )
    .unwrap();
    let err = Calibration::try_load(&path).expect_err("alpha=0 violates the Beta(1,1) floor");
    match err {
        CalibrationLoadError::InvalidCounters {
            detector_id,
            alpha,
            beta,
            ..
        } => {
            assert_eq!(detector_id, "aws");
            assert_eq!(alpha, 0);
            assert_eq!(beta, 3);
        }
        other => panic!("expected InvalidCounters, got {other:?}"),
    }
}

#[test]
fn try_load_rejects_empty_detector_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    std::fs::write(
        &path,
        br#"{"version":1,"detectors":{"":{"alpha":1,"beta":1}}}"#,
    )
    .unwrap();
    let err = Calibration::try_load(&path)
        .expect_err("empty detector id is not a valid routing identity");
    assert!(
        matches!(err, CalibrationLoadError::EmptyDetectorId { .. }),
        "expected EmptyDetectorId, got {err:?}"
    );
}

#[test]
fn try_load_rejects_unknown_json_field() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calibration.json");
    // `deny_unknown_fields` on the on-disk schema → serde parse failure.
    std::fs::write(&path, br#"{"version":1,"detectors":{},"rogue":true}"#).unwrap();
    let err = Calibration::try_load(&path).expect_err("unknown top-level field must be rejected");
    assert!(
        matches!(err, CalibrationLoadError::Parse { .. }),
        "expected Parse, got {err:?}"
    );
}
