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

#[test]
fn selected_simd_backend_uses_fail_loud_coalesced_boundary() {
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch source readable");
    let fused = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/fused.rs"
    ))
    .expect("fused dispatch source readable");
    let scanner = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../scanner/src/engine/scan_coalesced.rs"
    ))
    .expect("scanner coalesced source readable");

    assert!(
        scanner.contains("pub fn try_scan_coalesced_with_backend_admission_route_and_recovery(")
            && scanner.contains("self.try_initialize_simd_backend().map_err(")
            && scanner.contains("matches: self.scan_coalesced_simd("),
        "scanner must expose one fallible coalesced selected-backend boundary that proves SIMD initialization before dispatch"
    );
    assert!(
        dispatch.contains("try_scan_coalesced_with_backend_admission_route_and_recovery(")
            && dispatch.contains("backend,")
            && !dispatch.contains("ScanBackend::SimdCpu => self.scanner.scan_coalesced(batch)"),
        "coalesced dispatch must route every selected backend through the fallible scanner boundary"
    );
    assert!(
        fused.contains("super::scan_selected_batch(")
            && fused.contains("AutorouteRoutingError::selected_backend_dispatch_failed(")
            && !fused.contains("_ => scanner_ref.scan_coalesced(&batch)"),
        "fused dispatch must use the same fail-loud selected-backend boundary"
    );
}
