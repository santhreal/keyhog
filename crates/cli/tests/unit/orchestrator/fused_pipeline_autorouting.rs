//! Autorouting calibrates installer/maintenance workload buckets, persists the
//! result, and lets the fused filesystem path consume cache-only decisions.

#[test]
fn dispatch_autoroute_calibrates_missing_buckets_and_persists() {
    let dispatch = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch.rs"
    ))
    .expect("dispatch.rs readable");
    let fused = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/fused.rs"
    ))
    .expect("dispatch/fused.rs readable");
    let backend = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/backend.rs"
    ))
    .expect("dispatch/backend.rs readable");
    let calibration = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/backend/calibration.rs"
    ))
    .expect("dispatch/backend/calibration.rs readable");
    let mut evidence = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/backend/evidence.rs"
    ))
    .expect("dispatch/backend/evidence.rs readable");
    let backend_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/orchestrator/dispatch/backend");
    for file in ["evidence/match_identity.rs", "evidence/timing.rs"] {
        evidence.push_str(
            &std::fs::read_to_string(backend_dir.join(file))
                .unwrap_or_else(|error| panic!("dispatch/backend/{file} readable: {error}")),
        );
    }
    let mut store = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/orchestrator/dispatch/backend/store.rs"
    ))
    .expect("dispatch/backend/store.rs readable");
    for file in [
        "store/artifact_identity.rs",
        "store/build_identity.rs",
        "store/codec.rs",
        "store/persistence.rs",
        "store/schema.rs",
        "store/validation.rs",
    ] {
        store.push_str(
            &std::fs::read_to_string(backend_dir.join(file))
                .unwrap_or_else(|error| panic!("dispatch/backend/{file} readable: {error}")),
        );
    }
    let cache_path = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/autoroute_cache_path.rs"
    ))
    .expect("autoroute_cache_path.rs readable");

    assert!(
        dispatch.contains("MeasuredBackendRouter::new"),
        "serialized scan dispatch must route through the calibrated backend router"
    );
    assert!(
        fused.contains("MeasuredBackendRouter::new")
            && fused.contains("CachedBackendRouter::new")
            && fused.contains("router.choose(scanner_ref, None, &batch)")
            && fused.contains("routing_error")
            && !fused.contains("has_gpu_decision()")
            && !fused.contains("let backend = keyhog_scanner::hw_probe::ScanBackend::SimdCpu;"),
        "fused filesystem dispatch must consume cache-only autoroute evidence per batch during normal scans, and calibration mode must persist decisions for the same fused batch shape"
    );
    assert!(
        backend.contains("struct CachedBackendRouter")
            && backend.contains("load_persistent_autoroute_decisions")
            && !backend.contains("pub(crate) fn has_gpu_decision")
            && backend.contains("AutorouteRoutingError::missing_decision")
            && !backend
                .contains("autoroute cache miss outside calibration mode; using safe default"),
        "fused autoroute must share cache validation, fail loud when no measured bucket exists, and avoid cache-wide GPU switches"
    );
    assert!(
        backend.contains("calibrate_fastest_correct_backend")
            && evidence.contains("canonical_matches")
            && evidence.contains("struct CanonicalMatch<'a>")
            && evidence.contains("&'a str")
            && evidence.contains("m.detector_id.as_ref()")
            && evidence.contains("m.location.file_path.as_deref()")
            && !evidence.contains("Arc<str>")
            && !evidence.contains("m.detector_id.clone()")
            && !evidence.contains("m.location.file_path.clone()")
            && !evidence.contains("m.detector_id.to_string()")
            && !evidence.contains("ToString::to_string")
            && calibration.contains("backend rejected by autoroute parity check")
            && calibration.contains("clear_fragment_cache")
            && backend.contains("pub(super) fn commit")
            && backend.contains("self.save_cache()")
            && dispatch.contains("self.router.commit()?")
            && fused.contains("guard.commit()")
            && dispatch.contains("fn batch_has_no_scan_bytes(batch: &[Chunk]) -> bool")
            && dispatch.contains("if batch_has_no_scan_bytes(batch)")
            && fused.contains("if super::batch_has_no_scan_bytes(&batch)")
            && !backend.contains("self.save_cache()?;\n        Ok(backend)")
            && !calibration.contains("sampling_closed"),
        "autoroute must probe missing buckets only in calibration mode, reject parity-divergent candidates, skip zero-byte no-op batches before routing, and persist measured decisions only after the whole scan succeeds"
    );
    assert!(
        !calibration.contains("gpu_could_engage")
            && calibration.contains("gpu_candidate_allowed")
            && backend.contains("eligible_backend_labels")
            && backend.contains("scanner.gpu_backend_candidates()")
            && calibration.contains("ScanBackend::GpuCuda => gpu_cuda_timing = Some(measured)")
            && calibration.contains("ScanBackend::GpuWgpu => gpu_wgpu_timing = Some(measured)"),
        "explicit autoroute GPU calibration must measure each acquired CUDA and WGPU candidate independently; candidate census belongs to the router boundary and fixed heuristic thresholds must not decide whether calibration probes GPU"
    );
    assert!(
        !dispatch.contains("select_backend_for_batch(")
            && !fused.contains("select_backend_for_batch("),
        "dispatch paths must not use fixed-threshold backend selection"
    );
    assert!(
        !fused.contains("KEYHOG_FUSED_BATCH")
            && !fused.contains("KEYHOG_FUSED_DEPTH")
            && fused.contains("self.effective_config.fused_batch")
            && fused.contains("fused_depth_default(rayon::current_num_threads())"),
        "fused pipeline tuning must come from explicit resolved config instead of ambient env"
    );

    // Persistent idempotent autoroute cache: calibrated decisions are written to
    // disk and reused across runs for the same host + detector digest.
    assert!(
        backend.contains("detector_digest")
            && backend.contains("AutorouteHostProfile")
            && cache_path.contains("--autoroute-cache <PATH|off>")
            && store.contains("load_autoroute_cache")
            && store.contains("save_autoroute_cache")
            && store.contains("AutorouteCache"),
        "autoroute must persist decisions to an on-disk cache keyed by detector digest and host profile"
    );
    assert!(
        backend.contains("pub(super) fn commit")
            && backend.contains("self.save_cache()")
            && dispatch.contains("self.router.commit()?")
            && fused.contains("guard.commit()")
            && !backend.contains("self.save_cache()?;\n        Ok(backend)")
            && !backend.contains("impl Drop for MeasuredBackendRouter")
            && !backend.contains("fn drop(&mut self)"),
        "autoroute cache persistence must be explicit and successful before routing trust; Drop must not flush partial dirty calibration state"
    );
    assert!(
        cache_path.contains("[system].autoroute_cache"),
        "autoroute cache path must be overridable/disablable via explicit CLI/TOML config"
    );
}
