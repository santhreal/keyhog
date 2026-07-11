//! KH-GAP-002: forced GPU/MegaScan requests must hit the loud degrade guard
//! before public scan entry points or runtime GPU fallbacks route to CPU.

#[test]
fn gpu_backend_internal_denies_forced_degrade() {
    let engine = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    let compiled_api = std::fs::read_to_string(format!("{engine}compiled_api.rs"))
        .expect("compiled_api.rs readable");
    assert!(
        compiled_api
            .matches("gpu_forced::deny_silent_gpu_degrade(self,")
            .count()
            >= 3,
        "public scan/warm paths must forbid silent CPU fallback when GPU is selected"
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
            && gpu_dispatch.matches("deny_silent_gpu_degrade_with_reason(\n").count() >= 3,
        "coalesced GPU fallback and both phase-2 GPU admission losses must pass concrete reasons to the loud degrade guard"
    );
}
