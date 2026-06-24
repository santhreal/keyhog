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
        scanner.contains("pub fn scan_coalesced_with_backend(")
            && scanner.contains("self.deny_silent_selected_backend_degrade(backend);")
            && scanner.contains("backend == crate::hw_probe::ScanBackend::SimdCpu")
            && scanner.contains("return self.scan_coalesced(chunks);"),
        "scanner must expose one coalesced selected-backend boundary that guards before preserving the SIMD coalesced path"
    );
    assert!(
        dispatch.contains("ScanBackend::SimdCpu => self")
            && dispatch.contains(".scan_coalesced_with_backend(batch, ScanBackend::SimdCpu)")
            && !dispatch.contains("ScanBackend::SimdCpu => self.scanner.scan_coalesced(batch)"),
        "coalesced dispatch must not let selected SimdCpu call unguarded scan_coalesced"
    );
    assert!(
        fused.contains("ScanBackend::SimdCpu =>")
            && fused.contains("scan_coalesced_with_backend(")
            && !fused.contains("_ => scanner_ref.scan_coalesced(&batch)")
            && fused.contains("AutorouteRoutingError::unsupported_backend(backend)"),
        "fused dispatch must guard selected SimdCpu and fail loud for unsupported future backends"
    );
}
