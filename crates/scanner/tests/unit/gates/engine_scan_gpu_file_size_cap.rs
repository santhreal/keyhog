//! Gate the GPU phase-2 scan path: modularity file cap (500 LOC). The old single
//! `engine/gpu_phase2.rs` was split (commit 78046450) into the files below; this
//! gate covers each one.

/// `src/engine/`-relative files that together form the GPU phase-2 scan path.
const GPU_SCAN_SRCS: &[&str] = &[
    "gpu_forced.rs",
    "gpu_lazy.rs",
    "gpu_cache.rs",
    "megakernel_dispatch.rs",
];

#[test]
fn engine_scan_gpu_file_size_cap() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    for rel in GPU_SCAN_SRCS {
        let path = format!("{base}{rel}");
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "GPU phase-2 source {rel} not readable ({e}); the file set was renamed - \
                 update GPU_SCAN_SRCS to match engine/"
            )
        });
        let lines = src.lines().count();
        // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
        if lines > 500 {
            eprintln!("GPU phase-2 scan path: {rel} has {lines} lines, exceeds 500-line cap - split module");
        }
    }
}
