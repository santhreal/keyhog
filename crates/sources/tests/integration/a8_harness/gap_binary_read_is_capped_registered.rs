//! LR2-A8 harness integration: fixed binary cap in registry

#[test]
fn registry_lists_binary_read_is_capped_as_fixed() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
    let raw = std::fs::read_to_string(repo.join("GAP_FINDINGS.toml")).expect("registry");
    assert!(raw.contains("crates/sources/tests/gap/binary_read_is_capped.rs"));
    assert!(raw.contains(r#"status = "fixed"#));
}
