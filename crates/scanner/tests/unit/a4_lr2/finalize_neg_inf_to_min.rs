use keyhog_scanner::confidence;

#[test]
fn finalize_neg_inf_to_min() {
    assert_eq!(keyhog_scanner::testing::finalize_confidence(f64::NEG_INFINITY), 0.0);
}
