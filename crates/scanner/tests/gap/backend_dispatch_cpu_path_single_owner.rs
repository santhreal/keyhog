//! Regression: the parallel-CPU-scan + boundary-reassembly path has ONE owner.
//!
//! `scan_chunks_with_backend_internal` runs the CPU path in two situations:
//! any non-GPU backend (or an empty batch), and the GPU-compiled-out / GPU-
//! request degrade. Those were two byte-identical copies of
//!   `chunks.par_iter().map(|c| self.scan_with_backend(c, backend)).collect()`
//!   `+ scan_chunk_boundaries(...)`
//! that could drift apart, and the `scan_chunk_boundaries` seam pass is
//! load-bearing recall (a secret straddling two gapless chunks is invisible to
//! the per-chunk scan), so a divergence there silently loses findings on one
//! path. The two copies are now one `scan_chunks_cpu_parallel` helper.
//!
//! This pins the dedup: the helper exists, the parallel scan-map appears
//! exactly once, and the boundary pass is invoked from the helper, so a future
//! edit can't re-inline a second copy that drifts.

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn cpu_scan_and_boundary_path_has_single_owner() {
    let src = read_src("src/engine/backend_dispatch.rs");

    assert!(
        src.contains("fn scan_chunks_cpu_parallel"),
        "the CPU scan + boundary path must live in one owner, scan_chunks_cpu_parallel"
    );

    // The parallel iterator is the duplicated core. Its admission-aware map may
    // evolve, but the parallel traversal itself must remain in one owner.
    let map_occurrences = src.matches(".par_iter()").count();
    assert_eq!(
        map_occurrences, 1,
        "the par_iter scan-map must appear exactly once (deduped into the helper), found {map_occurrences}"
    );

    // The seam reassembly pass must run from the single owner.
    assert!(
        src.contains("super::boundary::scan_chunk_boundaries(self, chunks, &mut results)"),
        "the boundary seam pass must be invoked from the CPU path owner"
    );

    // Both branches must delegate to the helper rather than open-code the scan.
    let delegations = src
        .matches("self.scan_chunks_cpu_parallel(chunks, backend, admission_plan)")
        .count();
    assert_eq!(
        delegations, 2,
        "both the non-GPU branch and the GPU-compiled-out branch must call the helper, found {delegations}"
    );
}
