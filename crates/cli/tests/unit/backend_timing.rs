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
#[test]
fn cold_warm_statistical_model_computes_distributions() {
    use super::{BackendTimingEvidence, ColdWarmStatisticalModel};

    let candidate_timing = BackendTimingEvidence::from_trial_ns(vec![
        500_000, 100_000, 300_000, 120_000, 280_000, 140_000, 260_000, 160_000,
    ])
    .unwrap();
    let competitor_timing = BackendTimingEvidence::from_trial_ns(vec![
        600_000, 110_000, 310_000, 130_000, 290_000, 150_000, 270_000, 170_000,
    ])
    .unwrap();

    let candidate_model = ColdWarmStatisticalModel::from_timing(&candidate_timing).unwrap();
    let competitor_model = ColdWarmStatisticalModel::from_timing(&competitor_timing).unwrap();

    assert_eq!(candidate_model.cold_one_shot_ns, 500_000);
    assert_eq!(competitor_model.cold_one_shot_ns, 600_000);
    assert_eq!(candidate_model.warm_trials_ns.len(), 7);

    let diff = candidate_model.paired_difference(&competitor_model);
    assert!(diff.is_statistically_faster_95);
    assert!(diff.mean_diff_ns > 0.0);
}
