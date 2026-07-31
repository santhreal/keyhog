use keyhog_core::timing::{
    median_duration, paired_ratio_confidence_95, select_confidently_fastest_index,
};
use std::time::Duration;

#[test]
fn paired_ratio_interval_distinguishes_a_consistent_winner() {
    let reference: Vec<_> = [100, 102, 98, 101, 99, 103, 97]
        .into_iter()
        .map(Duration::from_millis)
        .collect();
    let candidate: Vec<_> = [70, 71, 69, 70, 70, 72, 68]
        .into_iter()
        .map(Duration::from_millis)
        .collect();
    let interval = paired_ratio_confidence_95(&reference, &candidate).expect("paired evidence");

    assert_eq!(interval.sample_count, 7);
    assert!(interval.low_ratio > 0.0);
    assert!(interval.geometric_mean_ratio < 1.0);
    assert!(interval.high_ratio < 1.0);
}

#[test]
fn paired_ratio_rejects_unpaired_zero_and_single_samples() {
    assert!(paired_ratio_confidence_95(&[Duration::from_nanos(1)], &[]).is_none());
    assert!(
        paired_ratio_confidence_95(&[Duration::from_nanos(1)], &[Duration::from_nanos(1)])
            .is_none()
    );
    assert!(paired_ratio_confidence_95(
        &[Duration::ZERO, Duration::from_nanos(1)],
        &[Duration::from_nanos(1), Duration::from_nanos(1)]
    )
    .is_none());
}

#[test]
fn median_duration_averages_even_center_pair() {
    let values = [
        Duration::from_nanos(40),
        Duration::from_nanos(10),
        Duration::from_nanos(30),
        Duration::from_nanos(20),
    ];
    assert_eq!(median_duration(&values), Some(Duration::from_nanos(25)));
    assert_eq!(
        median_duration(&[Duration::MAX, Duration::MAX]),
        Some(Duration::MAX)
    );
    assert_eq!(median_duration(&[]), None);
}

/// Locks out median-only route flips when a nominally faster candidate is not
/// statistically distinguishable from the deterministic first candidate.
#[test]
fn confidently_fastest_keeps_the_first_statistical_tie() {
    let baseline: Vec<_> = [100, 100, 100, 100, 100, 100, 100]
        .into_iter()
        .map(Duration::from_millis)
        .collect();
    let noisy_lower_median: Vec<_> = [90, 110, 90, 110, 90, 110, 90]
        .into_iter()
        .map(Duration::from_millis)
        .collect();

    assert_eq!(
        select_confidently_fastest_index([baseline.as_slice(), noisy_lower_median.as_slice()]),
        Some(0)
    );
}

/// Proves that deterministic tie handling does not prevent a later route with
/// a repeatable measured advantage from becoming the selected route.
#[test]
fn confidently_fastest_selects_a_proven_later_winner() {
    let baseline = [Duration::from_millis(100); 7];
    let tied = [
        Duration::from_millis(90),
        Duration::from_millis(110),
        Duration::from_millis(90),
        Duration::from_millis(110),
        Duration::from_millis(90),
        Duration::from_millis(110),
        Duration::from_millis(90),
    ];
    let proven_winner = [Duration::from_millis(70); 7];

    assert_eq!(
        select_confidently_fastest_index([
            baseline.as_slice(),
            tied.as_slice(),
            proven_winner.as_slice(),
        ]),
        Some(2)
    );
}

/// Proves that the selector can replace one proven winner with a still faster
/// route instead of pinning the first statistically significant improvement.
#[test]
fn confidently_fastest_can_replace_a_previous_winner() {
    let baseline = [Duration::from_millis(100); 7];
    let faster = [Duration::from_millis(80); 7];
    let fastest = [Duration::from_millis(60); 7];

    assert_eq!(
        select_confidently_fastest_index([
            baseline.as_slice(),
            faster.as_slice(),
            fastest.as_slice(),
        ]),
        Some(2)
    );
}

/// Locks out fabricated route verdicts when selection evidence is missing,
/// unpaired, too small to estimate variance, or contains zero durations.
#[test]
fn confidently_fastest_rejects_invalid_evidence() {
    let one_sample = [Duration::from_millis(100)];
    let two_samples = [Duration::from_millis(100); 2];
    let three_samples = [Duration::from_millis(90); 3];
    let zero_sample = [Duration::ZERO, Duration::from_millis(90)];

    assert_eq!(
        select_confidently_fastest_index(std::iter::empty::<&[Duration]>()),
        None
    );
    assert_eq!(
        select_confidently_fastest_index([one_sample.as_slice()]),
        None
    );
    assert_eq!(
        select_confidently_fastest_index([two_samples.as_slice(), three_samples.as_slice()]),
        None
    );
    assert_eq!(
        select_confidently_fastest_index([two_samples.as_slice(), zero_sample.as_slice()]),
        None
    );
}
