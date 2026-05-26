//! LR2-A8 harness integration: core has no gate/ (scanner/cli/sources/verifier only)

#[test]
fn core_has_no_gate_directory() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gate");
    assert!(!p.exists(), "core crate should not have gate/ — gates live in feature crates");
}
