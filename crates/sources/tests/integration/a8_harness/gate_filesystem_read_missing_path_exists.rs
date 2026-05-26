//! LR2-A8 harness integration: filesystem gate on disk

#[test]
fn filesystem_read_gate_present() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gate/filesystem_read_missing_path_err.rs");
    assert!(p.is_file());
}
