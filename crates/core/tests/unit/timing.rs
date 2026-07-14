use keyhog_core::timing::{median_duration, paired_ratio_confidence_95};
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
