//! LR2-A8 harness integration: source extraction and cap work lives in the
//! single execution plan.

#[test]
fn execution_plan_lists_source_extraction_and_caps() {
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let raw = std::fs::read_to_string(repo.join("docs/EXECUTION_PLAN.md")).expect("plan");
    assert!(raw.contains("binary/              # strings, sections, literals, Ghidra output caps"));
    assert!(raw.contains("Source Coverage"));
}
