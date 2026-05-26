//! LR2-A8 harness integration: core all_tests excludes gate

#[test]
fn core_all_tests_has_no_gate_export() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/all_tests.rs"),
    ).expect("all_tests.rs");
    assert!(!src.contains("pub mod gate;"));
}
