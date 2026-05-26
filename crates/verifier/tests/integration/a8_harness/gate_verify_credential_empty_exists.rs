//! LR2-A8 harness integration: credential gate on disk

#[test]
fn verify_credential_gate_present() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gate/verify_credential_empty_rejected.rs");
    assert!(p.is_file());
}
