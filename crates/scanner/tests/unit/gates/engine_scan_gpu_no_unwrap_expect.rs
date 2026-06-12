//! Gate the GPU phase-2 scan path: no `.unwrap(` / `.expect(` in production
//! source lines. The old single `engine/gpu_phase2.rs` was split (commit
//! 78046450) into the files below; this gate now covers the whole set so the
//! no-unwrap contract follows the code instead of a deleted path.

/// `src/engine/`-relative files that together form the GPU phase-2 scan path
/// (`scan_coalesced_megakernel` dispatch + GPU stack setup / degrade / cache).
const GPU_SCAN_SRCS: &[&str] = &[
    "gpu_forced.rs",
    "gpu_lazy.rs",
    "gpu_cache.rs",
    "megakernel_dispatch.rs",
];

#[test]
fn engine_scan_gpu_no_unwrap_expect() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    let mut offenders: Vec<(String, usize, String)> = Vec::new();
    for rel in GPU_SCAN_SRCS {
        let path = format!("{base}{rel}");
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("GPU phase-2 source {rel} not readable ({e}); the file \
                set was renamed - update GPU_SCAN_SRCS to match engine/"));
        for (i, line) in src.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.contains("#[cfg(test)]") {
                continue;
            }
            if t.contains(".unwrap(") || t.contains(".expect(") {
                offenders.push(((*rel).to_string(), i + 1, line.to_string()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "GPU phase-2 scan path: unwrap/expect in production source at {:?}",
        offenders.iter().take(5).collect::<Vec<_>>()
    );
}
