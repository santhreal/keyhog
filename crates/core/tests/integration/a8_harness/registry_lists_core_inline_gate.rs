//! LR2-A8 harness integration: core no_inline_tests registered

#[test]
fn registry_references_core_no_inline_tests() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("GAP_FINDINGS.toml")).expect("registry");
    assert!(raw.contains("crates/core/tests/gap/no_inline_tests_in_src.rs"));
}
