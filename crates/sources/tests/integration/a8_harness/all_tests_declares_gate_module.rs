//! LR2-A8 harness integration: gate/ wired in sources all_tests.rs

#[test]
fn all_tests_exports_gate() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/all_tests.rs"),
    )
    .expect("all_tests.rs");
    assert!(src.contains("pub mod gate;"));
}
