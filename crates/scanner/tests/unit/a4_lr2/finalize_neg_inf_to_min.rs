#[test]
fn finalize_neg_inf_to_min() {
    assert_eq!(
        keyhog_scanner::testing::confidence::finalize_confidence(f64::NEG_INFINITY),
        0.0
    );
}
