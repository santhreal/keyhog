//! LR2-A8 harness integration: daemon wire gate on disk

#[test]
fn daemon_wire_version_gate_present() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gate/daemon_wire_version_nonzero.rs");
    assert!(p.is_file());
}
