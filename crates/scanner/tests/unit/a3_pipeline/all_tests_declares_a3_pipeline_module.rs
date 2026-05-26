use std::fs;
use std::path::PathBuf;

#[test]
fn all_tests_wires_a3_pipeline_unit() {
    let all_tests = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/all_tests.rs"),
    )
    .unwrap();
    let unit_mod = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/unit/mod.rs"),
    )
    .unwrap();
    assert!(all_tests.contains("pub mod unit"));
    assert!(unit_mod.contains("a3_pipeline"));
}
