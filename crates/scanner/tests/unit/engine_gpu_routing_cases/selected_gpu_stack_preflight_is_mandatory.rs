//! KH-GAP-002: an explicitly selected GPU backend must pass the complete GPU
//! stack preflight before any public scan path can execute.

#[test]
fn selected_gpu_stack_preflight_is_mandatory() {
    let engine = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    let compiled_api = std::fs::read_to_string(format!("{engine}compiled_api.rs"))
        .expect("compiled_api.rs readable");
    // Public scan paths fail closed when a caller-selected backend would route
    // to CPU: `scan_with_backend` and `scan_chunks_with_backend` use the shared
    // selected-backend guard, while `scan_with_deadline_and_backend` validates
    // the selected GPU stack directly. `warm_backend` is a readiness probe: it
    // reports `false` in-band and never initiates a scan.
    let scan_path_guards = compiled_api
        .matches("self.require_selected_backend_stack(")
        .count()
        + compiled_api
            .matches("gpu_forced::require_selected_gpu_stack(self,")
            .count();
    assert!(
        scan_path_guards >= 3,
        "public scan paths must forbid CPU substitution when GPU is selected \
         (found {scan_path_guards} selected-backend guards, need >= 3)"
    );

    let backend_triggered = std::fs::read_to_string(format!("{engine}backend_triggered.rs"))
        .expect("backend_triggered.rs readable");
    assert!(
        backend_triggered.contains("fail_selected_gpu_dispatch(self, &reason)"),
        "per-chunk GPU trigger failure must pass a concrete reason to the hard-failure owner"
    );

    let gpu_dispatch = std::fs::read_to_string(format!("{engine}gpu_region_dispatch.rs"))
        .expect("gpu_region_dispatch.rs readable");
    assert!(
        gpu_dispatch.contains("fail_selected_gpu_dispatch_error(self, error)")
            && gpu_dispatch.contains("SelectedGpuDispatchError::new(reason)")
            && gpu_dispatch
                .matches("return dispatch_failure(reason);")
                .count()
                >= 2,
        "coalesced and phase-2 GPU failures must propagate concrete structured errors to the hard-failure owner"
    );
}
