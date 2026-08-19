//! Regression: the parallel-CPU-scan + boundary-reassembly path has ONE owner.
//!
//! `scan_chunks_with_backend_internal` delegates non-GPU work to one helper.
//! A GPU route compiled without GPU support now fails closed instead of calling
//! the CPU helper, so there is exactly one delegation.
//!   `chunks.par_iter().map(|c| self.scan_with_backend(c, backend)).collect()`
//!   `+ scan_chunk_boundaries(...)`
//! that could drift apart, and the `scan_chunk_boundaries` seam pass is
//! load-bearing recall (a secret straddling two gapless chunks is invisible to
//! the per-chunk scan), so a divergence there silently loses findings on one
//! path. The two copies are now one `scan_chunks_cpu_parallel` helper.
//!
//! This pins the dedup: the helper owns both mutually exclusive parallel
//! traversals and the boundary pass, so another backend path cannot re-inline a
//! copy that drifts.

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn cpu_scan_and_boundary_path_has_single_owner() {
    let src = read_src("src/engine/backend/dispatch.rs");

    assert!(
        src.contains("fn scan_chunks_cpu_parallel"),
        "the CPU scan + boundary path must live in one owner, scan_chunks_cpu_parallel"
    );

    // The direct and coalesced-lane traversals are mutually exclusive branches
    // inside the same owner. No other backend path may add a traversal.
    let scan_invocations = src.matches("scan_one(index,").count();
    assert_eq!(
        scan_invocations, 2,
        "the CPU owner must contain exactly its direct and coalesced-lane traversals, found {scan_invocations}"
    );

    // The seam reassembly pass must run from the single owner. The route-carrying
    // variant threads the calibrated ScanExecutionRoute into the seam scan so the
    // boundary pass uses the same backend the per-chunk scan did.
    assert!(
        src.contains(
            "super::boundary::scan_chunk_boundaries_with_route(self, chunks, &mut results, route)"
        ),
        "the boundary seam pass must be invoked from the CPU path owner"
    );

    let delegations = src
        .matches("self.scan_chunks_cpu_parallel(chunks, backend, admission_plan, route)")
        .count();
    assert_eq!(
        delegations, 1,
        "the non-GPU branch must call the helper once"
    );
    let compiled_out_gpu = src
        .split_once("#[cfg(not(feature = \"gpu\"))]")
        .and_then(|(_, rest)| {
            rest.split_once("\n        }\n    }\n\n    ///")
                .map(|(body, _)| body)
        })
        .expect("compiled-out GPU branch must remain inspectable");
    assert!(
        compiled_out_gpu.contains("Err(crate::error::ScanError::Gpu(")
            && !compiled_out_gpu.contains("scan_chunks_cpu_parallel")
            && !compiled_out_gpu.contains("process_exit"),
        "a compiled-out GPU route must return a structured GPU error without CPU delegation or process-exit ownership"
    );
}
