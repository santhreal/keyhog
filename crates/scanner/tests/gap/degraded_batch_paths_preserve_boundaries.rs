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
    let source = scanner_source("engine/backend_dispatch.rs");
    let fallback = source
        .split("degraded_backend_after_gpu_failure")
        .nth(1)
        .expect("gpu degrade fallback branch present");
    assert!(
        fallback.contains("scan_chunk_boundaries(self, chunks, &mut results)"),
        "GPU batch degrade to CPU must preserve cross-chunk boundary recall"
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
