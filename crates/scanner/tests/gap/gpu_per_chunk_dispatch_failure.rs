//! Law 10 guard: the per-chunk GPU trigger path (`collect_triggered_patterns_gpu`,
//! the `scan_inner` entry) must never SILENTLY swap to SIMD/CPU. Every path off the
//! GPU, missing matcher, missing backend handle, or a failed presence dispatch
//! must record a concrete reason in `gpu_last_degrade_reason` and return a
//! structured `ScanError::Gpu` through the selected-backend boundary instead
//! of substituting CPU/SIMD or taking process-exit ownership.
//!
//! The pre-fix code returned `self.collect_triggered_patterns_simd(text)` directly
//! on a missing backend and merely `tracing::debug!`'d a failed dispatch before
//! falling through, both silent substitutions (a `tracing::debug!`-then-continue is
//! explicitly silent). This guard pins the loud, reason-carrying replacement.

use std::fs;
use std::path::PathBuf;

fn backend_triggered_src() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/backend/triggered.rs"),
    )
    .expect("backend_triggered.rs readable")
}

#[test]
fn per_chunk_gpu_failure_is_hard_and_reason_carrying() {
    let src = backend_triggered_src();

    // The failure must record runtime status and return a structured GPU error.
    assert!(
        src.contains("self.record_gpu_runtime_fault(reason.clone())")
            && src.contains("Err(crate::error::ScanError::Gpu(reason))"),
        "collect_triggered_patterns_gpu must return every off-GPU path as a recorded structured GPU error"
    );

    // Each distinct off-GPU cause must carry its own operator-visible reason.
    assert!(
        src.contains("gpu literal matcher not built for this scanner")
            && src.contains("self.gpu_backend_unavailable_reason(route)")
            && src.contains("gpu presence scan failed:"),
        "each off-GPU cause (no matcher / no backend / failed dispatch) must carry a concrete reason"
    );
}

#[test]
fn per_chunk_gpu_has_no_silent_simd_swap() {
    let src = backend_triggered_src();

    // Isolate the function body so we only inspect this path.
    let start = src
        .find("fn collect_triggered_patterns_gpu(")
        .expect("collect_triggered_patterns_gpu present");
    let body = &src[start..];
    let end = body
        .find("\n    fn ")
        .or_else(|| body.find("\n    pub(crate) fn "))
        .map(|off| start + off)
        .unwrap_or(src.len());
    let func = &src[start..end];

    assert!(
        func.contains("self.record_gpu_runtime_fault(reason.clone())")
            && func.contains("Err(crate::error::ScanError::Gpu(reason))")
            && func.matches("return dispatch_failure(").count() >= 2
            && func.contains("Err(error) => dispatch_failure(")
            && !func.contains("degraded_backend_after_gpu_failure")
            && !func.contains("process_exit"),
        "the per-chunk GPU path must return dispatch failures without a CPU/SIMD substitution or process-exit ownership"
    );

    // The old silent `tracing::debug!`-then-fall-through on a failed dispatch must be gone.
    assert!(
        !func.contains("tracing::debug!(\"gpu presence scan failed"),
        "a failed presence dispatch must terminate visibly, not continue after tracing::debug!"
    );
}
