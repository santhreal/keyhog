//! KH-GAP-142: macro e2e binaries must be real standalone Cargo test targets,
//! not orphaned files hidden from the primary all-tests manifest.

#[test]
fn macro_e2e_targets_are_standalone_cargo_tests_with_oracles() {
    let tests_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    for module in ["e2e_binary", "break_it", "live_verify"] {
        let path = tests_dir.join(format!("{module}.rs"));
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{module} must exist as tests/{module}.rs"));
        assert!(
            src.contains("#[test]"),
            "tests/{module}.rs must contain real #[test] oracles so Cargo auto-discovers it"
        );
    }
}
