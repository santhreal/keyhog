//! Lazy compile and hot-loop dispatch scratch for the GPU literal-set matcher.
//!
//! This is the ONLY GPU primitive built here. The batch on-GPU detection
//! engine also routes through the same [`GpuLiteralSet`] via
//! `scan_presence_by_region_with_scratch`; the retired per-rule megakernel
//! catalog is not a production engine module. The matcher is a literal-presence
//! prefilter, not a final matcher; downstream phase-2 extraction confirms every
//! candidate via its full regex.
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
                let literal_refs: Vec<&[u8]> = literals.iter().map(|v| v.as_slice()).collect();
                let cache_key = format!(
                    "lit-{}",
                    super::gpu_cache::gpu_matcher_cache_key(&literal_refs)
                );
                let started = std::time::Instant::now();
                let matcher = match super::gpu_cache::gpu_matcher_cache_dir() {
                    Ok(cache_dir) => vyre_libs::scan::cached_load_or_compile(
                        &cache_dir,
                        &cache_key,
                        || vyre_libs::scan::GpuLiteralSet::compile(&literal_refs),
                    ),
                    Err(error) => {
                        tracing::warn!(
                            target: "keyhog::routing",
                            %error,
                            "GPU matcher disk cache unavailable; compiling literal set without cache"
                        );
                        vyre_libs::scan::GpuLiteralSet::compile(&literal_refs)
                    }
                };
                tracing::debug!(
                    target: "keyhog::routing",
                    patterns = literal_refs.len(),
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "GpuLiteralSet ready (warm cache or compiled)"
                );
                Some(matcher)
            })
            .as_ref()
    }
}
