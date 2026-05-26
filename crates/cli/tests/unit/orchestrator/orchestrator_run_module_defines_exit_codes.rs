#[test]
fn orchestrator_run_module_defines_exit_codes() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/run.rs"));
    assert!(src.contains("EXIT_LIVE_CREDENTIALS: u8 = 10"));
    assert!(src.contains("EXIT_SCANNER_PANIC: u8 = 11"));
}
