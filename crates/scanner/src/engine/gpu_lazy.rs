//! Lazy compile and hot-loop dispatch scratch for the GPU literal-set matcher.
//!
//! This builds Keyhog's GPU literal-set primitive. The main matcher is the
//! literal-presence phase-1 prefilter; the smaller positioned matcher feeds
//! candidate positions to post-phase-1 accelerators. Neither is a final matcher:
//! downstream phase-2 extraction confirms every candidate via its full regex.
//! The retired per-rule megakernel catalog is not a production engine module.
//!
//! Two parallel GPU dispatch builders that once lived here were removed as dead
//! routes (DEDUP / INSUFFICIENCY):
//!   * `ac_gpu_program` (a `classic_ac_bounded_ranges` `vyre::Program`) — had
//!     zero callers; `GpuLiteralSet` is the single on-GPU AC trigger engine.
//!   * `rule_pipeline` (the `RulePipeline` regex-NFA "MegaScan" engine) — its
//!     `scan` was never invoked; `--backend mega-scan`
//!     routes to the SAME region-presence backend as `--backend gpu`. The
//!     cached wrapper, its diagnostic builder, and fixed-size aliases were
//!     deleted as dead surface; only adaptive byte-budget sizing remains in
//!     [`super::rule_pipeline`].
//! [`GpuLiteralSet`]: vyre_libs::scan::GpuLiteralSet

use super::gpu_lazy_helpers::{compile_gpu_literal_set, report_gpu_matcher_unavailable};
use super::*;

impl CompiledScanner {
    /// Lazily compile the GPU literal-set on first call. Returns `None`
    /// when no compatible adapter was detected at probe time.
    ///
    /// Persists the compiled matcher to `~/.cache/keyhog/programs/<hash>.bin`
    /// when a user cache directory is available. The cache is a pure latency
    /// optimization: a miss, stale/corrupt blob, or unavailable cache directory
    /// compiles the identical matcher without changing the selected backend.
    pub(crate) fn gpu_matcher(&self) -> Option<&vyre_libs::scan::GpuLiteralSet> {
        self.gpu_matcher
            .get_or_init(|| {
                let Some(literals) = &self.gpu_literals else {
                    return None;
                };
                match compile_gpu_literal_set(literals, "lit") {
                    Ok(matcher) => Some(matcher),
                    Err(error) => {
                        report_gpu_matcher_unavailable(&error, "literal");
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Lazily compile the smaller positioned-candidate literal set used by GPU
    /// confirmed-anchor and generic-keyword accelerators.
    #[cfg(feature = "gpu")]
    pub(crate) fn gpu_position_matcher(&self) -> Option<&vyre_libs::scan::GpuLiteralSet> {
        self.gpu_position_matcher
            .get_or_init(|| {
                let Some(literals) = &self.gpu_position_literals else {
                    return None;
                };
                match compile_gpu_literal_set(literals, "pos-lit") {
                    Ok(matcher) => Some(matcher),
                    Err(error) => {
                        report_gpu_matcher_unavailable(&error, "positioned literal");
                        None
                    }
                }
            })
            .as_ref()
    }
}
