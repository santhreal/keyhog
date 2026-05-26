#[test]
fn orchestrator_allowlist_module_exists() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/allowlist.rs");
    let src = std::fs::read_to_string(path).expect("allowlist.rs");
    assert!(src.contains("load_allowlist"));
}
