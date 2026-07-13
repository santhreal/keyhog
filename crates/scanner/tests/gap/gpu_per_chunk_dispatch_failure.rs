//! Law 10 guard: the per-chunk GPU trigger path (`collect_triggered_patterns_gpu`,
//! the `scan_inner` entry) must never SILENTLY swap to SIMD/CPU. Every path off the
//! GPU, missing matcher, missing backend handle, or a failed presence dispatch
//! must record a concrete reason in `gpu_last_degrade_reason` and route through
//! `fail_selected_gpu_dispatch`, which terminates the selected route with exit
//! 12 instead of substituting CPU/SIMD.
//!
//! The pre-fix code returned `self.collect_triggered_patterns_simd(text)` directly
//! on a missing backend and merely `tracing::debug!`'d a failed dispatch before
//! falling through, both silent substitutions (a `tracing::debug!`-then-continue is
//! explicitly silent). This guard pins the loud, reason-carrying replacement.

use std::fs;
use std::path::PathBuf;

fn backend_triggered_src() -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/engine/backend_triggered.rs"),
    )
    .expect("backend_triggered.rs readable")
}

#[test]
fn per_chunk_gpu_failure_is_hard_and_reason_carrying() {
    let src = backend_triggered_src();

    // The failure must go through the divergent, reason-carrying helper.
    assert!(
        src.contains("fail_selected_gpu_dispatch(self, &reason)"),
        "collect_triggered_patterns_gpu must route every off-GPU path through fail_selected_gpu_dispatch"
    );

    // Each distinct off-GPU cause must carry its own operator-visible reason.
    assert!(
        src.contains("gpu literal matcher not built for this scanner")
            && src.contains("no gpu backend acquired for per-chunk trigger dispatch")
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
        func.contains("fail_selected_gpu_dispatch(self, &reason)")
            && !func.contains("degraded_backend_after_gpu_failure")
            && !func.contains("collect_triggered_patterns_for_backend(\n                text,"),
        "the per-chunk GPU path must terminate the selected route without a CPU/SIMD substitution"
    );

    // The old silent `tracing::debug!`-then-fall-through on a failed dispatch must be gone.
    assert!(
        !func.contains("tracing::debug!(\"gpu presence scan failed"),
        "a failed presence dispatch must terminate visibly, not continue after tracing::debug!"
    );
}
