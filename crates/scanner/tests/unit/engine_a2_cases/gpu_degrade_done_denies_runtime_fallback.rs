//! KH-GAP-002: GPU dispatch degrade must call `deny_gpu_runtime_degrade`.

#[test]
fn gpu_degrade_done_denies_runtime_fallback() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/gpu_scan_wrappers.rs");
    let src = std::fs::read_to_string(path).expect("gpu_scan_wrappers.rs readable");
    assert!(
        src.contains("gpu_forced::deny_gpu_runtime_degrade"),
        "gpu_degrade_done must forbid silent CPU fallback when GPU dispatch fails"
    );
}
