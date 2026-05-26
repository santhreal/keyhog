#[test]
fn orchestrator_config_module_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator_config.rs");
    let src = std::fs::read_to_string(path).expect("orchestrator_config.rs");
    assert!(src.contains("build_scanner_config"));
}
