//! Lazy compile of the per-chunk GPU literal-set matcher.
//!
//! This is the ONLY GPU primitive built here. The batch on-GPU detection
//! engine — the megakernel ([`super::megakernel`]) — owns its own catalog
//! build/dispatch and does NOT route through this module. The [`GpuLiteralSet`]
//! compiled here backs exactly one live path: the per-chunk GPU trigger
//! producer ([`super::CompiledScanner::collect_triggered_patterns_gpu`], reached
//! from `scan_inner` for decode-recursion / windowed sub-chunks). It is a
//! literal-presence prefilter, not a final matcher; downstream phase-2
//! extraction confirms every candidate via its full regex.
//!
//! Two parallel GPU dispatch builders that once lived here were removed as dead
//! routes (DEDUP / INSUFFICIENCY):
//!   * `ac_gpu_program` (a `classic_ac_bounded_ranges` `vyre::Program`) — had
//!     zero callers; the megakernel is the single on-GPU AC engine.
//!   * `rule_pipeline` (the `RulePipeline` regex-NFA "MegaScan" engine) — its
//!     `scan` was never invoked; `--backend mega-scan`
//!     routes to the SAME megakernel as `--backend gpu`. The cached wrapper,
//!     its diagnostic builder, and fixed-size aliases were deleted as dead
//!     surface; only adaptive byte-budget sizing remains in
//!     [`super::rule_pipeline`].
//! [`GpuLiteralSet`]: vyre_libs::scan::GpuLiteralSet

use super::*;

impl CompiledScanner {
    /// Lazily compile the GPU literal-set on first call. Returns `None`
    /// when no compatible adapter was detected at probe time.
    ///
    /// Persists the compiled matcher to `~/.cache/keyhog/programs/<hash>.bin`.
    /// On a cache hit the matcher is loaded from disk and the GPU
    /// recompile is skipped entirely - biggest cold-start win on
    /// `keyhog scan` / `scan-system` runs that re-launch repeatedly.
    /// Cache misses (no file, version-mismatch, corrupt blob) silently
    /// recompile and re-cache.
    pub(crate) fn gpu_matcher(&self) -> Option<&vyre_libs::scan::GpuLiteralSet> {
        self.gpu_matcher
            .get_or_init(|| {
                let Some(literals) = &self.gpu_literals else {
                    return None;
                };
                let literal_refs: Vec<&[u8]> = literals.iter().map(|v| v.as_slice()).collect();
                let cache_dir = super::gpu_cache::gpu_matcher_cache_dir()?;
                let cache_key = format!(
                    "lit-{}",
                    super::gpu_cache::gpu_matcher_cache_key(&literal_refs)
                );
                let started = std::time::Instant::now();
                // One-line lego-block cache wiring courtesy of
                // `vyre_libs::scan::cached_load_or_compile`. The
                // helper handles atomic-rename, stale-blob deletion,
                // and silent fall-through on cache-side I/O errors -
                // every behaviour the previous hand-rolled
                // load/save pair tried to match. We log compile cost
                // here so the operator can still see warm-vs-cold
                // start latency in `--verbose` output.
                let matcher =
                    vyre_libs::scan::cached_load_or_compile(&cache_dir, &cache_key, || {
                        vyre_libs::scan::GpuLiteralSet::compile(&literal_refs)
                    });
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
