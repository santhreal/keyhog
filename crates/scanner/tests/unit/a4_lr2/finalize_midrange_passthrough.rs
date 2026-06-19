#[test]
fn finalize_midrange_passthrough() {
    assert_eq!(
        keyhog_scanner::testing::confidence::finalize_confidence(0.5),
        0.5
    );
}
