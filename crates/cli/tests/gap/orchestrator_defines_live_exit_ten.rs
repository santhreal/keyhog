//! Contract gate: orchestrator defines EXIT_LIVE_CREDENTIALS = 10.

#[test]
fn orchestrator_defines_live_exit_ten() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/orchestrator.rs"));
    assert!(src.contains("const EXIT_LIVE_CREDENTIALS: u8 = 10"), "orchestrator must define EXIT_LIVE_CREDENTIALS = 10");
}
