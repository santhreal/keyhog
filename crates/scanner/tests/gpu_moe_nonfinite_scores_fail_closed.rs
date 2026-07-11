#![cfg(feature = "gpu")]

use keyhog_scanner::testing::finite_gpu_scores_for_test;

#[test]
fn finite_gpu_scores_preserve_bounds() {
    assert_eq!(
        finite_gpu_scores_for_test(&[-0.25, 0.0, 0.5, 1.0, 1.25]),
        Ok(vec![0.0, 0.0, 0.5, 1.0, 1.0])
    );
}

#[test]
fn one_nonfinite_score_rejects_the_entire_gpu_vector() {
    assert_eq!(
        finite_gpu_scores_for_test(&[0.1, f32::NAN, 0.9]),
        Err(1)
    );
    assert_eq!(
        finite_gpu_scores_for_test(&[f32::INFINITY, 0.5, f32::NEG_INFINITY]),
        Err(2)
    );
}
