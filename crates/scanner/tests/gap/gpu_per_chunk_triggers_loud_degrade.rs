//! Law 10 guard: the per-chunk GPU trigger path (`collect_triggered_patterns_gpu`,
//! the `scan_inner` entry) must never SILENTLY swap to SIMD/CPU. Every path off the
//! GPU — missing matcher, missing backend handle, or a failed presence dispatch —
//! must record a concrete reason in `gpu_last_degrade_reason` AND route through
//! `deny_silent_gpu_degrade_with_reason` (which hard-fails under forced backend
//! or require-GPU policy and otherwise emits the one-shot warning).
//!
//! The pre-fix code returned `self.collect_triggered_patterns_simd(text)` directly
//! on a missing backend and merely `tracing::debug!`'d a failed dispatch before
//! falling through — both SILENT degrades (a `tracing::debug!`-then-continue is
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
fn per_chunk_gpu_degrade_is_loud_and_reason_carrying() {
    let src = backend_triggered_src();

    // The degrade must go through the loud, reason-carrying helper.
    assert!(
        src.contains("deny_silent_gpu_degrade_with_reason(self, backend, Some(&reason))"),
        "collect_triggered_patterns_gpu must route every off-GPU path through \
         deny_silent_gpu_degrade_with_reason"
    );

    // The concrete cause must be recorded for machine-readable self-test output.
    assert!(
        src.contains("self.record_gpu_degrade(reason.clone());"),
        "the degrade must record the reason through the shared GPU degrade owner so health probes don't scrape stderr"
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

    // The degrade closure must route through the live degraded backend helper,
    // not directly into SimdCpu, because SimdCpu is only honest when its
    // prefilter actually exists.
    assert_eq!(
        func.matches(
            "self.collect_triggered_patterns_for_backend(\n                text,\n                self.degraded_backend_after_gpu_failure(),\n            )"
        )
            .count(),
        1,
        "the per-chunk GPU path must route through the live degraded backend exactly once \
         inside the loud degrade closure"
    );

    // The old silent `tracing::debug!`-then-fall-through on a failed dispatch must be gone.
    assert!(
        !func.contains("tracing::debug!(\"gpu presence scan failed"),
        "a failed presence dispatch must degrade LOUDLY, not via tracing::debug! then continue"
    );
}
