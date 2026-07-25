use super::*;

/// Regression: calibration parity diagnostics must count duplicate multiset differences exactly, not just distinct records.
#[test]
fn calibration_difference_reports_exact_multiset_count() {
    let mut left = vec!["record-00".to_string(); 4];
    left.extend((1..37).map(|index| format!("record-{index:02}")));
    let right = vec!["record-00".to_string()];

    assert_eq!(sorted_calibration_difference_count(&left, &right), 39);
}
