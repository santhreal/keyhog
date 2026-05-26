#[test]
fn orchestrator_reporting_module_exists() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/reporting.rs");
    let src = std::fs::read_to_string(path).expect("reporting.rs");
    assert!(src.contains("dump_dogfood_trace"));
}
