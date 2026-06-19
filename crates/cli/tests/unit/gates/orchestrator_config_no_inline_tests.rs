//! Gate `orchestrator_config`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn orchestrator_config_no_inline_tests() {
    for path in [
        concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator_config.rs"),
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/orchestrator_config/detectors.rs"
        ),
    ] {
        let src = std::fs::read_to_string(path).expect("source readable");
        assert!(
            !src.contains("#[cfg(test)]"),
            "{path}: move inline tests to crates/cli/tests/"
        );
    }
}
