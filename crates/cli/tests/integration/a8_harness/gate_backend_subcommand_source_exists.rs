//! LR2-A8 harness integration: backend gate file on disk

#[test]
fn backend_subcommand_gate_file_present() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/gate/backend_subcommand_parses.rs");
    assert!(p.is_file());
}
