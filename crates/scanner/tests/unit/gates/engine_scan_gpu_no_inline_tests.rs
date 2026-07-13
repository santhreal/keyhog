//! Gate the GPU phase-2 scan path: no inline `#[cfg(test)]` (Santh folder
//! contract). The old single `engine/gpu_phase2.rs` was split (commit 78046450)
//! into the files below; this gate covers the whole set.

/// `src/engine/`-relative files that together form the GPU phase-2 scan path.
const GPU_SCAN_SRCS: &[&str] = &[
    "gpu_forced.rs",
    "gpu_forced_helpers.rs",
    "gpu_lazy.rs",
    "gpu_lazy_helpers.rs",
    "gpu_literal_scratch.rs",
    "gpu_cache.rs",
    "gpu_region_batch.rs",
    "gpu_region_dispatch.rs",
    "gpu_region_dispatch_helpers.rs",
    "gpu_resident_presence.rs",
];

const INLINE_TEST_ALLOWLIST: &[&str] = &["gpu_region_dispatch.rs"];

#[test]
fn engine_scan_gpu_no_inline_tests() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    for rel in GPU_SCAN_SRCS {
        let path = format!("{base}{rel}");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "GPU phase-2 source {rel} not readable ({e}); the file set was renamed - \
                 update GPU_SCAN_SRCS to match engine/"
            )
        });
        assert!(
            INLINE_TEST_ALLOWLIST.contains(rel)
                || !super::inline_gate::contains_inline_test_module_or_function(&src),
            "GPU phase-2 scan path: {rel} has inline #[cfg(test)] - move it to crates/scanner/tests/"
        );
    }
}
