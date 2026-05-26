#[test]
fn orchestrator_postprocess_module_exists() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/postprocess.rs"
    );
    let src = std::fs::read_to_string(path).expect("postprocess.rs");
    assert!(src.contains("filter_and_resolve"));
}
