//! Contract gate: detectors subcommand defines audit failure exit 3.

#[test]
fn detectors_audit_exit_code_three_in_src() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/subcommands/detectors.rs"));
    assert!(src.contains("const EXIT_AUDIT_FAILED: u8 = 3"));
}
