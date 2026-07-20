//! Gate the GPU phase-2 scan path: no inline `#[cfg(test)]` (Santh folder
//! contract). The old single `engine/gpu_phase2.rs` was split (commit 78046450)
//! into the files below; this gate covers the whole set.

/// `src/`-relative files that together form the GPU phase-2 scan path.
const GPU_SCAN_SRCS: &[&str] = &[
    "engine/gpu_forced.rs",
    "engine/gpu_forced_helpers.rs",
    "engine/gpu_lazy.rs",
    "engine/gpu_lazy_helpers.rs",
    "engine/gpu_literal_scratch.rs",
    "gpu_matcher_cache.rs",
    "engine/gpu_region_batch.rs",
    "engine/gpu_region_dispatch.rs",
    "engine/gpu_region_dispatch_helpers.rs",
    "engine/gpu_resident_evidence.rs",
];

const INLINE_TEST_ALLOWLIST: &[&str] = &[
    "engine/gpu_region_dispatch.rs",
    "engine/gpu_resident_evidence.rs",
];

#[test]
fn engine_scan_gpu_no_inline_tests() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/src/");
    for rel in GPU_SCAN_SRCS {
        let path = format!("{base}{rel}");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "GPU phase-2 source {rel} not readable ({e}); the file set was renamed - \
                 update GPU_SCAN_SRCS to match src/"
            )
        });
        assert!(
            INLINE_TEST_ALLOWLIST.contains(rel)
                || !super::inline_gate::contains_inline_test_module_or_function(&src),
            "GPU phase-2 scan path: {rel} has inline #[cfg(test)] - move it to crates/scanner/tests/"
        );
    }
}
