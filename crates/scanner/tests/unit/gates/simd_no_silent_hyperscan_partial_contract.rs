#[test]
fn hyperscan_runtime_failures_are_not_silent_partial_scans() {
    let scan = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/simd/backend/scan.rs"
    ))
    .expect("simd backend scan source readable");
    let backend =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/simd/backend.rs"))
            .expect("simd backend source readable");
    let engine_backend_prepared = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_prepared.rs"
    ))
    .expect("engine backend_prepared source readable");
    let engine_scan = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/scan_coalesced.rs"
    ))
    .expect("engine coalesced scan source readable");
    let compiled_api = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/compiled_api.rs"
    ))
    .expect("engine compiled_api source readable");
    let hw_select = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/hw_probe/select.rs"
    ))
    .expect("hardware backend selector source readable");
    let triggered = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_triggered.rs"
    ))
    .expect("backend trigger source readable");
    let phase2_hs = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_hs.rs"
    ))
    .expect("phase-2 HS source readable");
    let phase2_prefilter = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_prefilter.rs"
    ))
    .expect("phase-2 prefilter source readable");

    for forbidden in [
        "shard skipped",
        "matches are partial",
        "marked set is partial",
        "scratch allocation failed; shard skipped",
    ] {
        assert!(
            !scan.contains(forbidden),
            "Hyperscan runtime failure must not be represented as a skipped shard: {forbidden}"
        );
    }
    assert!(
        backend.contains("fn scratch_pool_size()")
            && backend.contains("Vec::with_capacity(scratch_count)")
            && backend.contains("scratch_pool.push("),
        "Hyperscan scratches must be preallocated per shard to seed the warm-start fast path"
    );
    assert!(
        scan.contains("shard.db.alloc_scratch()")
            && scan.contains("hyperscan scratch on-demand growth failed"),
        "scratch-pool exhaustion under thread oversubscription must GROW the pool on demand \
         (the same precise full-chunk scan), never degrade into a partial or over-marked scan"
    );
    assert!(
        !scan.contains("hyperscan scratch pool exhausted"),
        "the hard scratch-exhaustion error is forbidden: it forced the non-deterministic \
         over-marking degrade that silently varied findings and aborted autoroute calibration"
    );
    assert!(
        backend.contains("keyhog_core::HYPERSCAN_CACHE_FILE_BYTES")
            && backend.contains("fn read_hs_cache_file(")
            && backend
                .contains("file.take(keyhog_core::HYPERSCAN_CACHE_FILE_BYTES.saturating_add(1))")
            && backend.contains("read_hs_cache_file(cache_path)")
            && !backend.contains("std::fs::read(&cache_path)"),
        "Hyperscan shard cache loads must be capped before reading cache bytes"
    );
    assert!(
        backend.contains("HS shard cache header is invalid or truncated; compiling from patterns"),
        "present but invalid Hyperscan cache artifacts must be operator-visible before recompilation"
    );
    assert!(
        engine_backend_prepared
            .contains("HS compile returned unsupported pattern id outside the deduped AC table")
            && engine_backend_prepared.contains("compiled scanner invariant violation")
            && engine_backend_prepared.contains("refusing to disable the SIMD prefilter")
            && !engine_backend_prepared.contains(".filter_map(|&hs_id| index_map.get(hs_id))")
            && phase2_hs.contains(
                "HS always-active prefilter returned unsupported pattern id outside refs"
            )
            && phase2_hs.contains("compiled scanner invariant violation")
            && phase2_hs.contains("refusing to disable the prefilter")
            && !phase2_hs.contains(".filter_map(|&i| refs.get(i).map(|r| r.0))"),
        "Hyperscan unsupported-id mapping must fail closed instead of disabling SIMD/prefilter routes"
    );
    assert!(
        scan.contains("static SCRATCH_TLS")
            && scan.contains("fn take_scratch(")
            && scan.contains("fn put_scratch(")
            && scan.contains("struct CachedScratch")
            && scan.contains("owner: Weak<()>")
            && scan.contains("SCRATCH_TLS_PRUNE_THRESHOLD")
            && scan.contains("fn prune_dead_scanner_scratch(")
            && scan.contains("fn purge_scanner_scratch(")
            && scan.contains("prune_dead_scanner_scratch(&mut tls);")
            && !scan.contains("retain_current_scanner_scratch")
            && scan.contains("put_scratch(self.scanner_id, shard_idx, &self.scratch_owner, scratch);")
            && backend.contains("impl Drop for HsScanner")
            && backend.contains("scratch_owner: Arc<()>")
            && backend.contains("scan::purge_scanner_scratch(scanner_id);")
            && !backend.contains("rayon::broadcast(|_| scan::purge_scanner_scratch(scanner_id));"),
        "fallible Hyperscan scan paths must return scratch, keep live interleaved scanner caches, and prune/drop retained thread-local scratches"
    );
    assert!(
        !scan.contains("alloc_scratch().ok()"),
        "Hyperscan scratch allocation errors must keep their error text instead of being erased with .ok()"
    );
    assert!(
        engine_scan.contains("scanner.scan_each_result(data")
            && triggered.contains("scanner.scan_matches_result(text.as_bytes()")
            && phase2_hs.contains("scan_each_result")
            && phase2_hs.contains("any_match_result")
            && phase2_prefilter
                .contains("HS always-active prefilter failed; using RegexSet path for this chunk")
            && phase2_prefilter.contains(
                "HS always-active admission gate failed; using RegexSet path for this chunk"
            )
            && triggered.contains(
                "hyperscan confirmed-trigger scan failed; over-marking SIMD-covered patterns for this chunk"
            )
            && triggered.contains("for hs_id in 0..scanner.pattern_count()")
            && engine_scan.contains(
                "hyperscan coalesced phase-1 scan failed; over-marking SIMD-covered patterns for this chunk"
            ),
        "production engine callers must use fallible SIMD helpers and route failures to conservative explicit paths that warn before over-marking"
    );
    assert!(
        scan.contains("fn scan_matches_result(")
            && !scan.contains("fn scan_result(")
            && !scan.contains("Vec::with_capacity(32)"),
        "Hyperscan scan hot paths must stream matches through callbacks instead of allocating a per-chunk Vec"
    );
    assert!(
        engine_scan.contains("normalize_coalesced_phase2_triggers")
            && engine_scan.contains("coalesced phase-2 trigger row count mismatch")
            && engine_scan.contains("collect_triggered_patterns_for_backend(")
            && engine_scan.contains("ScanBackend::SimdCpu"),
        "shared coalesced phase-2 must normalize trigger rows before zipping, so cardinality drift cannot silently truncate scanned chunks"
    );
    assert!(
        hw_select.contains("if caps.hyperscan_available {\n        ScanBackend::SimdCpu")
            && !hw_select.contains(
                "caps.hyperscan_available || caps.has_avx512 || caps.has_avx2 || caps.has_neon"
            ),
        "CPU-tier routing must not label AVX/NEON-only hosts as simd-regex when no live Hyperscan/Vectorscan prefilter exists"
    );
    let selected_simd_guard = compiled_api
        .split("if selected_backend == ScanBackend::SimdCpu && !self.simd_backend_usable()")
        .nth(1)
        .and_then(|tail| tail.split("selected_backend\n    }").next())
        .expect("selected SimdCpu unavailable guard extractable");
    assert!(
        selected_simd_guard.contains("crate::process_exit::backend_unavailable(")
            && selected_simd_guard.contains("silent cpu-fallback execution is forbidden")
            && !selected_simd_guard.contains("warn_simd_auto_degrade")
            && !selected_simd_guard.contains("return ScanBackend::CpuFallback"),
        "selected simd-regex without a live prefilter must fail closed, not warn and reroute to cpu-fallback"
    );
}
