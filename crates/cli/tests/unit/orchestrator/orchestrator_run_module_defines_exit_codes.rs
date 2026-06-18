#[test]
fn orchestrator_run_module_imports_exit_code_owner() {
    let src = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/run.rs"
    ));
    assert!(src.contains("crate::exit_codes"));
    assert!(!src.contains("const EXIT_LIVE_CREDENTIALS"));
    assert!(!src.contains("const EXIT_SCANNER_PANIC"));
}
