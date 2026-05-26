//! LR2-A8 harness integration: verifier gate pre-wired from LR1-A8

#[test]
fn all_tests_exports_gate() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/all_tests.rs"),
    ).expect("all_tests.rs");
    assert!(src.contains("pub mod gate;"));
}
