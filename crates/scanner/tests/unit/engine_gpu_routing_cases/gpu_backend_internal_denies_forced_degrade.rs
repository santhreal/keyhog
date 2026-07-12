//! KH-GAP-002: forced GPU/MegaScan requests must hit the loud degrade guard
//! before public scan entry points or runtime GPU fallbacks route to CPU.

#[test]
fn gpu_backend_internal_denies_forced_degrade() {
    let engine = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    let compiled_api = std::fs::read_to_string(format!("{engine}compiled_api.rs"))
        .expect("compiled_api.rs readable");
    // Public scan paths fail closed when a caller-selected backend would silently
    // route to CPU: `scan_with_backend` and `scan_chunks_with_backend` go through
    // the `deny_silent_selected_backend_degrade` guard, and
    // `scan_with_deadline_and_backend` calls `deny_silent_gpu_degrade` directly.
    // `warm_backend` is a bool PROBE — it reports readiness (`false`) in-band
    // rather than hard-stopping, which is NOT a silent fallback (the caller acts
    // on it and the scan itself still fails closed at these guards), so it is
    // intentionally not one of the guard sites.
    let scan_path_guards = compiled_api
        .matches("self.deny_silent_selected_backend_degrade(")
        .count()
        + compiled_api
            .matches("gpu_forced::deny_silent_gpu_degrade(self,")
            .count();
    assert!(
        scan_path_guards >= 3,
        "public scan paths must forbid silent CPU fallback when GPU is selected \
         (found {scan_path_guards} deny-silent guards, need >= 3)"
    );

    let backend_triggered = std::fs::read_to_string(format!("{engine}backend_triggered.rs"))
        .expect("backend_triggered.rs readable");
    assert!(
        backend_triggered.contains("deny_silent_gpu_degrade_with_reason(self, backend"),
        "per-chunk GPU trigger fallback must pass a concrete reason to the loud degrade guard"
    );

    let gpu_dispatch = std::fs::read_to_string(format!("{engine}gpu_region_dispatch.rs"))
        .expect("gpu_region_dispatch.rs readable");
    assert!(
        gpu_dispatch.contains("deny_silent_gpu_degrade_with_reason(\n                self,\n                ScanBackend::Gpu,\n                Some(&reason),")
            && gpu_dispatch.matches("deny_silent_gpu_degrade_with_reason(\n").count() >= 4,
        "coalesced GPU fallback and GPU auxiliary dispatch losses must pass concrete reasons to the loud degrade guard"
    );
}
