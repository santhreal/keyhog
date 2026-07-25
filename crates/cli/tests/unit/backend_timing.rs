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
