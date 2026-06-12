use std::fs;
use std::path::PathBuf;

fn scanner_source(path: &str) -> String {
    let mut full = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full.push("src");
    full.push(path);
    fs::read_to_string(full).expect("read scanner source")
}

#[test]
fn gpu_degrade_batch_path_runs_boundary_reassembly() {
    // The 78046450 consolidation moved the GPU-batch degrade closure from
    // backend_dispatch.rs into the megakernel dispatch (`scan_coalesced_megakernel`):
    // it picks `degraded_backend_after_gpu_failure()` then re-runs the per-chunk
    // boundary reassembly so the loud CPU degrade keeps cross-chunk recall.
    let source = scanner_source("engine/megakernel_dispatch.rs");
    // Position-based (robust to the comment that also names the helper): the
    // degrade closure picks the live CPU backend, THEN re-runs boundary reassembly.
    let degrade_at = source
        .find("self.degraded_backend_after_gpu_failure()")
        .expect("gpu degrade must pick the live CPU backend");
    let boundary_at = source
        .find("scan_chunk_boundaries(self, chunks, &mut results)")
        .expect("gpu degrade must run cross-chunk boundary reassembly");
    assert!(
        boundary_at > degrade_at,
        "GPU batch degrade to CPU must run boundary reassembly AFTER picking the degraded backend, \
         preserving cross-chunk recall"
    );
}

#[test]
fn missing_simd_prefilter_batch_path_runs_boundary_reassembly() {
    let source = scanner_source("engine/scan.rs");
    let fallback = source
        .split("let Some(scanner) = &self.simd_prefilter else")
        .nth(1)
        .expect("missing SIMD prefilter fallback branch present");
    assert!(
        fallback.contains("scan_chunk_boundaries(self, chunks, &mut results)"),
        "coalesced SIMD fallback must preserve cross-chunk boundary recall"
    );
}
