//! LR2-A8 harness integration: isolated a3_all_tests.rs must be merged into all_tests

#[test]
fn a3_all_tests_rs_no_longer_exists() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/a3_all_tests.rs");
    assert!(!path.exists(), "a3_all_tests.rs must be removed after LR2-A8 merge");
}
