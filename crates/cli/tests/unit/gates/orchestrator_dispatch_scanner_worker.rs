#[test]
fn coalesced_scanner_worker_owns_backend_routing() {
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch source readable");

    for required in [
        "struct CoalescedScannerWorker",
        "enum CoalescedBatchRouter",
        "fn coalesced_scanner_worker(&self",
        "fn append_scanned_batch_findings(",
        "scanner_worker.run(rx)",
    ] {
        assert!(
            dispatch.contains(required),
            "coalesced scan dispatch must keep scanner-worker boundary `{required}`"
        );
    }

    let scan_sources = dispatch
        .split("pub(crate) fn scan_sources(")
        .nth(1)
        .and_then(|tail| tail.split("let mut batch: Vec<keyhog_core::Chunk>").next())
        .expect("scan_sources scanner-thread section extractable");

    for forbidden in [
        "BatchBackendRouter",
        "MeasuredBackendRouter::new",
        "scan_chunks_with_backend",
        "scan_coalesced",
        "GPU_SCANNED_CHUNKS",
        "dump_profile_reports",
        "runtime_status().pattern_count",
    ] {
        assert!(
            !scan_sources.contains(forbidden),
            "scan_sources must not re-own scanner routing/counter detail `{forbidden}`"
        );
    }
}
