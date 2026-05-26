//! LR2-A8 harness integration: oob gate on disk

#[test]
fn oob_config_gate_present() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gate/oob_config_default_server.rs");
    assert!(p.is_file());
}
