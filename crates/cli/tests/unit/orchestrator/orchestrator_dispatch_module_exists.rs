#[test]
fn orchestrator_dispatch_module_exists() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/dispatch.rs");
    let src = std::fs::read_to_string(path).expect("dispatch.rs");
    assert!(src.contains("scan_sources"), "dispatch module must own scan dispatch");
}
