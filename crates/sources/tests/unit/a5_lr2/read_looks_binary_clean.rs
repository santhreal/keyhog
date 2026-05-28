#[test]
fn read_looks_binary_clean() {
    assert!(!keyhog_sources::testing::looks_binary("hello world\n".repeat(100).as_bytes()));
}
