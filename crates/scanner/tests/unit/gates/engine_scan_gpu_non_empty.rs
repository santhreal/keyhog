//! Gate the GPU phase-2 scan path: substantive source, no todo!/unimplemented!
//! in prod paths. The old single `engine/gpu_phase2.rs` was split (commit
//! 78046450) into the files below; this gate covers each one.

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
];

#[test]
fn engine_scan_gpu_non_empty() {
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
            src.trim().len() >= 20,
            "GPU phase-2 scan path: {rel} expected substantive source, got {} trimmed bytes",
            src.trim().len()
        );
        let prod = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
            "GPU phase-2 scan path: {rel} has todo!/unimplemented! in non-test source"
        );
    }
}
