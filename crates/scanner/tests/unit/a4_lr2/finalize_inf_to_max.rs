#[test]
fn finalize_inf_to_max() {
    assert_eq!(
        keyhog_scanner::testing::confidence::finalize_confidence(f64::INFINITY),
        1.0
    );
}
