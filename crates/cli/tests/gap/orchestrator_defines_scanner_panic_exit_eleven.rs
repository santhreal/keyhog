//! Contract gate: orchestrator defines EXIT_SCANNER_PANIC = 11.

#[test]
fn orchestrator_defines_scanner_panic_exit_eleven() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator/run.rs"));
    assert!(
        src.contains("const EXIT_SCANNER_PANIC: u8 = 11"),
        "orchestrator/run.rs must define EXIT_SCANNER_PANIC = 11"
    );
}
