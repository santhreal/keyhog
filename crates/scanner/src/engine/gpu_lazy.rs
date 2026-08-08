//! Lazy compile and hot-loop dispatch scratch for the GPU literal-set matcher.
//!
//! This builds KeyHog's GPU literal-set primitive. The main matcher is the
//! literal-presence phase-1 prefilter. It is not a final matcher:
//! downstream phase-2 extraction confirms every candidate via its full regex.
//! The retired per-rule megakernel catalog is not a production engine module.
//!
//! Two parallel GPU dispatch builders that once lived here were removed as dead
//! routes (DEDUP / INSUFFICIENCY):
//!   * `ac_gpu_program` (a `classic_ac_bounded_ranges` `vyre::Program`), had
//!     zero callers; `GpuLiteralSet` is the single on-GPU AC trigger engine.
//!   * `rule_pipeline` (the retired `RulePipeline` regex-NFA engine), its
//!     `scan` was never invoked. The cached wrapper, duplicate backend identity,
//!     diagnostic builder, and fixed-size aliases were deleted as dead surface;
//!     only adaptive byte-budget sizing remains in [`super::gpu_input_budget`].
//! [`GpuLiteralSet`]: vyre::scan::GpuLiteralSet

use super::gpu_lazy_helpers::{compile_gpu_literal_set, report_gpu_literal_matcher_unavailable};
use super::*;

impl CompiledScanner {
    /// Lazily compile the GPU literal-set on first call. Returns `None`
    /// when no compatible adapter was detected at probe time.
    ///
    /// Persists the compiled matcher to `~/.cache/keyhog/programs/<hash>.bin`
    /// when a user cache directory is available. The cache is a pure latency
    /// optimization: a miss, stale/corrupt blob, or unavailable cache directory
    /// compiles the identical matcher without changing the selected backend.
    pub(crate) fn gpu_matcher(&self) -> Option<&vyre::scan::GpuLiteralSet> {
        self.gpu_matcher
            .get_or_init(|| {
                // Decision-driving: autoroute folds this cold cost into the
                // first calibration trial and persists it, so it must be
                // measured whether or not profiling is on. `decision_timer`
                // guarantees that and records the same interval into the
                // profiler when a runtime is current, so the number that picks
                // the backend is the number an operator reads.
                let cold =
                    keyhog_profile::decision_timer(keyhog_profile::Stage::AutorouteCalibration);
                let Some(literals) = &self.gpu_literals else {
                    return None;
                };
                let matcher = match compile_gpu_literal_set(literals, "lit-ci") {
                    Ok(matcher) => Some(matcher),
                    Err(error) => {
                        report_gpu_literal_matcher_unavailable(&error);
                        None
                    }
                };
                if matcher.is_some() {
                    // LAW10: profiler duration saturates on impossible u128-to-u64 overflow; matcher behavior is unchanged.
                    let elapsed = u64::try_from(cold.finish().as_nanos()).unwrap_or(u64::MAX);
                    self.autoroute_gpu_shared_cold_ns
                        .store(elapsed.max(1), std::sync::atomic::Ordering::Release);
                }
                matcher
            })
            .as_ref()
    }
}
