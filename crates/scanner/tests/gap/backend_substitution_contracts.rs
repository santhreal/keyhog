use std::fs;
use std::path::PathBuf;

fn scanner_source(path: &str) -> String {
    let mut full = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full.push("src");
    full.push(path);
    fs::read_to_string(full).expect("read scanner source")
}

#[test]
fn forced_simd_backend_without_prefilter_is_not_cpu_fallback() {
    let source = scanner_source("compiled_scanner/runtime.rs");
    let triggered = scanner_source("engine/backend_triggered.rs");
    assert!(
        source.contains("selected_backend: crate::hw_probe::ScanBackend")
            && source.contains("crate::process_exit::backend_unavailable"),
        "forced SimdCpu must fail loudly when the SIMD prefilter is absent"
    );
    assert!(
        source.contains("pub(crate) fn live_cpu_backend(&self) -> ScanBackend")
            && source.contains("ScanBackend::CpuFallback"),
        "automatic CPU-tier routing must relabel to CpuFallback when the SIMD prefilter is absent"
    );
    let scan_entry = source
        .split("pub(crate) fn scan_with_deadline_and_backend(")
        .nth(1)
        .and_then(|tail| tail.split("// Direct-match prefilters").next())
        .expect("scan entry prefilter guard block extractable");
    assert!(
        scan_entry.contains("self.require_selected_backend_stack(selected_backend);"),
        "explicit selected backends must be validated before prefilter skip/no-hit branches can return"
    );
    let simd_trigger_collector = triggered
        .split("fn collect_triggered_patterns_simd(&self, text: &str) -> Vec<u64> {")
        .nth(1)
        .and_then(|tail| {
            tail.split("pub(crate) fn collect_triggered_patterns_cpu")
                .next()
        })
        .expect("SIMD trigger collector source extractable");
    let missing_prefilter_branch = simd_trigger_collector
        .split("return triggered_patterns;")
        .nth(1)
        .expect("missing-prefilter branch extractable");
    assert!(
        missing_prefilter_branch.contains("crate::process_exit::backend_unavailable(")
            && missing_prefilter_branch.contains("silent cpu-fallback execution is forbidden")
            && !missing_prefilter_branch.contains("warn_simd_auto_degrade")
            && !missing_prefilter_branch.contains("collect_triggered_patterns_cpu(text)"),
        "internal SimdCpu trigger collection without a live prefilter must fail closed, not warn and rescan through AC"
    );
}

#[test]
fn gpu_dispatch_failure_has_no_cpu_substitution_path() {
    let source = scanner_source("engine/gpu_region_dispatch.rs");
    assert!(
        source.contains("fail_selected_gpu_dispatch_error(self, error)")
            && source.contains("SelectedGpuDispatchError::new(reason)")
            && !source.contains("degraded_backend_after_gpu_failure")
            && !source.contains("scan_with_backend(chunk, degraded)"),
        "a selected GPU dispatch failure must terminate with exit 12, not retain a CPU/SIMD substitution"
    );
}

#[test]
fn missing_simd_prefilter_batch_path_runs_boundary_reassembly() {
    let source = scanner_source("engine/scan_coalesced.rs");
    let fallback = source
        .split("let Some(scanner) = &self.simd_prefilter else")
        .nth(1)
        .expect("missing SIMD prefilter fallback branch present");
    assert!(
        fallback.contains("scan_chunk_boundaries(self, chunks, &mut results)"),
        "coalesced SIMD fallback must preserve cross-chunk boundary recall"
    );
    assert!(
        fallback.contains("ScanBackend::CpuFallback"),
        "missing SIMD prefilter path must relabel to CpuFallback instead of claiming SimdCpu"
    );
}
