//! LR2-A8 harness integration: scan gate file on disk

#[test]
fn scan_subcommand_gate_file_present() {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/gate/scan_subcommand_parses.rs");
    assert!(p.is_file());
}
