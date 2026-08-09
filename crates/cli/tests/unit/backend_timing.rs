use super::paired_candidate_is_faster_95;

/// Regression: paired timing must cancel shared host drift instead of hiding a consistently faster candidate.
#[test]
fn paired_difference_separates_shared_host_drift() {
    let candidate = [100, 300, 120, 280, 140, 260, 160];
    let competitor = [110, 310, 130, 290, 150, 270, 170];
    assert!(paired_candidate_is_faster_95(&candidate, &competitor));
}

/// Regression: paired timing must not select a candidate when trials tie or the candidate is slower.
#[test]
fn paired_difference_rejects_ties_and_reversed_routes() {
    let candidate = [100, 300, 120, 280, 140, 260, 160];
    assert!(!paired_candidate_is_faster_95(&candidate, &candidate));
    let faster_competitor = [90, 290, 110, 270, 130, 250, 150];
    assert!(!paired_candidate_is_faster_95(
        &candidate,
        &faster_competitor
    ));
}

/// Pairing uses deltas before floating-point conversion so a large shared baseline cannot erase speedups.
#[test]
fn paired_difference_preserves_small_deltas_at_u128_scale() {
    let candidate = [u128::MAX - 100; 7];
    let competitor = [u128::MAX - 90; 7];
    assert!(paired_candidate_is_faster_95(&candidate, &competitor));
}
#[test]
fn cold_warm_statistical_model_requires_exact_trials() {
    use super::{BackendTimingEvidence, ColdWarmStatisticalModel};

    let timing = BackendTimingEvidence::from_trial_ns(vec![
        500_000, 100_000, 300_000, 120_000, 280_000, 140_000, 260_000,
    ])
    .unwrap();
    let model = ColdWarmStatisticalModel::from_timing(&timing).unwrap();
    assert_eq!(model.cold_one_shot_ns, 500_000);
    assert_eq!(model.warm_trials_ns.len(), 6);
    assert_eq!(model.warm_median_ns, 200_000);

    let extra_trial = BackendTimingEvidence::from_trial_ns(vec![
        500_000, 100_000, 300_000, 120_000, 280_000, 140_000, 260_000, 160_000,
    ])
    .unwrap();
    assert!(ColdWarmStatisticalModel::from_timing(&extra_trial).is_none());
    let missing_trial = BackendTimingEvidence::from_trial_ns(vec![
        500_000, 100_000, 300_000, 120_000, 280_000, 140_000,
    ])
    .unwrap();
    assert!(ColdWarmStatisticalModel::from_timing(&missing_trial).is_none());

    let zero_cold = BackendTimingEvidence::from_trial_ns(vec![
        0, 100_000, 300_000, 120_000, 280_000, 140_000, 260_000,
    ])
    .unwrap();
    assert!(ColdWarmStatisticalModel::from_timing(&zero_cold).is_none());
}
