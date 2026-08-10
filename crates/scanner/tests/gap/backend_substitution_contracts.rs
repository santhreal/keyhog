use std::fs;
use std::path::PathBuf;

fn scanner_source(path: &str) -> String {
    let mut full = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full.push("src");
    for part in path.split('/') {
        full.push(part);
    }
    fs::read_to_string(full).expect("read scanner source")
}

#[test]
fn gpu_dispatch_failure_has_no_cpu_substitution_path() {
    let dispatch = scanner_source("engine/backend/dispatch.rs");
    let gpu_region = scanner_source("engine/gpu_region_dispatch/mod.rs");
    assert!(
        dispatch.contains("self.scan_coalesced_gpu_region_presence(chunks, backend, route)")
            && dispatch.contains("crate::error::ScanError::Gpu(error.to_string())")
            && !dispatch.contains("process_exit")
            && gpu_region.contains("SelectedGpuDispatchError::new(reason)")
            && !gpu_region.contains("degraded_backend_after_gpu_failure")
            && !gpu_region.contains("scan_with_backend(chunk, degraded)"),
        "a selected GPU dispatch failure must surface as a structured scanner error without CPU/SIMD substitution or process-exit ownership"
    );
}
