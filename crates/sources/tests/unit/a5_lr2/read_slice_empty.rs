#[test]
fn read_slice_empty() {
    assert!(keyhog_sources::testing::slice_into_windows(&[], 64, 8).is_empty());
}
