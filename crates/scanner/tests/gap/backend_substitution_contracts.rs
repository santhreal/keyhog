use std::fs;
use std::path::PathBuf;

fn scanner_source(path: &str) -> String {
    let mut full = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full.push("src");
    full.push(path);
    fs::read_to_string(full).expect("read scanner source")
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
