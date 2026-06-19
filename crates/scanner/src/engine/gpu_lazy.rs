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
use std::cell::RefCell;

thread_local! {
    static GPU_LITERAL_SCAN_SCRATCH: RefCell<vyre_libs::scan::dispatch_io::ScanDispatchScratch> =
        RefCell::new(vyre_libs::scan::dispatch_io::ScanDispatchScratch::default());
}

struct ZeroGpuLiteralScratch<'a> {
    scratch: &'a mut vyre_libs::scan::dispatch_io::ScanDispatchScratch,
}

impl<'a> ZeroGpuLiteralScratch<'a> {
    fn new(scratch: &'a mut vyre_libs::scan::dispatch_io::ScanDispatchScratch) -> Self {
        Self { scratch }
    }

    fn as_mut(&mut self) -> &mut vyre_libs::scan::dispatch_io::ScanDispatchScratch {
        &mut *self.scratch
    }
}

impl Drop for ZeroGpuLiteralScratch<'_> {
    fn drop(&mut self) {
        zero_gpu_literal_scratch(self.scratch);
    }
}

fn zero_gpu_literal_scratch(scratch: &mut vyre_libs::scan::dispatch_io::ScanDispatchScratch) {
    scratch.haystack_bytes.fill(0);
    scratch.hit_bytes.fill(0);
}

fn with_gpu_literal_scratch<R>(
    f: impl FnOnce(
        &mut vyre_libs::scan::dispatch_io::ScanDispatchScratch,
    ) -> std::result::Result<R, String>,
) -> std::result::Result<R, String> {
    GPU_LITERAL_SCAN_SCRATCH
        .try_with(|cell| {
            let mut scratch = cell.try_borrow_mut().map_err(|_| {
                "gpu literal-set scratch already borrowed on this thread; recursive GPU trigger \
                 dispatch is unsupported"
                    .to_string()
            })?;
            let mut zero_on_drop = ZeroGpuLiteralScratch::new(&mut scratch);
            f(zero_on_drop.as_mut())
        })
        .map_err(|_| "gpu literal-set scratch unavailable during thread shutdown".to_string())?
}

pub(super) fn scan_gpu_literal_presence_with_scratch(
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &dyn vyre::VyreBackend,
    haystack: &[u8],
) -> std::result::Result<Vec<u32>, String> {
    with_gpu_literal_scratch(|scratch| {
        matcher
            .scan_presence_with_scratch(backend, haystack, scratch)
            .map_err(|error| error.to_string())
    })
}

#[cfg(feature = "gpu")]
pub(super) fn scan_gpu_literal_presence_by_region_with_scratch(
    matcher: &vyre_libs::scan::GpuLiteralSet,
    backend: &dyn vyre::VyreBackend,
    haystack: &[u8],
    region_starts: &[u32],
) -> std::result::Result<Vec<u32>, String> {
    with_gpu_literal_scratch(|scratch| {
        matcher
            .scan_presence_by_region_with_scratch(backend, haystack, region_starts, 0, scratch)
            .map_err(|error| error.to_string())
    })
}

impl CompiledScanner {
    /// Lazily compile the GPU literal-set on first call. Returns `None`
    /// when no compatible adapter was detected at probe time.
    ///
    /// Persists the compiled matcher to `~/.cache/keyhog/programs/<hash>.bin`.
    /// On a cache hit the matcher is loaded from disk and the GPU
    /// recompile is skipped entirely - biggest cold-start win on
    /// `keyhog scan` / `scan-system` runs that re-launch repeatedly.
    /// The blob is a pure-optimization cache, never a detection input: a miss
    /// (no file, version-mismatch, corrupt blob) recompiles the IDENTICAL
    /// matcher and re-caches, so a miss costs only the recompile and changes no
    /// match result — it is not a Law-10 fallback to a weaker path.
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
