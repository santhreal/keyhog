#[test]
fn fused_source_drain_panic_is_a_hard_error() {
    let fused = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/fused.rs"
    ))
    .expect("read fused dispatch source");
    let panic_arm = fused
        .split("if drain.join().is_err() {")
        .nth(1)
        .and_then(|tail| tail.split("let routing_error =").next())
        .expect("fused drain panic arm extractable");

    assert!(
        panic_arm.contains("crate::record_scanner_panic()"),
        "fused drain panic must record scanner-panic exit semantics"
    );
    assert!(
        panic_arm.contains("anyhow::bail!"),
        "fused drain panic must stop the scan before cache finalization/reporting"
    );
}
