//! Adversarial: empty cross-detector input yields empty output.

use keyhog_core::dedup_cross_detector;

#[test]
fn dedup_cross_detector_empty_vec_yields_empty() {
    let out = dedup_cross_detector(vec![]);
    assert_eq!(out.len(), 0);
}
