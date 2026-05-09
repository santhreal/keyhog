//! Megakernel-batched GPU dispatch — bundles many files × many DFA
//! rules into one persistent kernel launch via vyre's
//! `vyre_runtime::megakernel::BatchDispatcher`.
//!
//! Status (v0.5.5 scaffolding): compiled DFA per detector literal +
//! `BatchDispatcher` infrastructure are in place. The actual scan
//! call still routes to `scan_coalesced_gpu` (the literal-set
//! sharded path) until the per-DFA rule table is populated and the
//! HitRecord → keyhog trigger-bitmask attribution is wired. Tracked
//! in `docs/vyre-usage.md` next-wires #8.
//!
//! Why megakernel matters for keyhog:
//!  - One persistent dispatch instead of N `GpuLiteralSet::scan`
//!    shards (`engine/scan_gpu.rs` currently shards at the wgpu
//!    65535-workgroup-per-dimension cap = ~2 MiB per dispatch).
//!  - The work queue inside the megakernel is `(file, rule)` pairs,
//!    so per-detector parallelism comes for free instead of being
//!    serialised behind the per-pattern AC pre-filter.
//!  - Foundation for the next architectural step: also bundling the
//!    per-chunk extraction (entropy / regex / ML scoring) onto GPU.
//!    The current bottleneck on dense corpora is exactly this
//!    extraction phase running CPU-side after the prefilter.

use std::sync::Arc;

use vyre_libs::matching::dfa::dfa_compile;
use vyre_runtime::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchRuleProgram,
};

/// Per-scanner megakernel state. Holds one compiled `BatchDispatcher`
/// and the per-detector DFA tables produced from each detector's
/// literal prefixes. Built lazily on first dispatch via
/// [`MegakernelScanner::try_compile`] and cached on the scanner.
pub struct MegakernelScanner {
    /// Backend the dispatcher was compiled against. Held so we can
    /// rebuild the dispatcher on driver-fault recovery without
    /// reaching back into `CompiledScanner`.
    backend: vyre_driver_wgpu::WgpuBackend,
    /// Compiled persistent megakernel pipeline. Reused across every
    /// scan dispatch so we pay the compile cost once.
    dispatcher: BatchDispatcher,
    /// One DFA per detector literal. `rules[i].rule_idx == i` so the
    /// HitRecord's `rule_idx` field round-trips back to keyhog's
    /// detector-index space without an extra lookup table.
    rules: Vec<BatchRuleProgram>,
}

impl MegakernelScanner {
    /// Compile the per-detector DFAs and the persistent pipeline.
    /// Returns `None` when the scanner has no GPU literal prefixes
    /// (no GpuLiteralSet was built, e.g. `simd` feature off) or when
    /// the dispatcher cannot be created on this adapter.
    ///
    /// The DFA-per-literal layout matches the existing
    /// `GpuLiteralSet` pattern_id space, so swapping engines does
    /// not require remapping detector triggers downstream.
    pub fn try_compile(
        backend: Arc<vyre_driver_wgpu::WgpuBackend>,
        gpu_literals: &Arc<Vec<Vec<u8>>>,
    ) -> Option<Self> {
        if gpu_literals.is_empty() {
            return None;
        }

        // One small DFA per literal. dfa_compile accepts a slice of
        // byte patterns; we pass each literal as its own one-pattern
        // DFA so the BatchRuleProgram's rule_idx maps 1:1 to the
        // literal index = pattern_id consumed by the rest of the
        // scan pipeline.
        let mut rules = Vec::with_capacity(gpu_literals.len());
        for (idx, lit) in gpu_literals.iter().enumerate() {
            let single = [lit.as_slice()];
            let compiled = dfa_compile(&single);
            // BatchRuleProgram expects (rule_idx, transitions, accept,
            // state_count). dfa_compile returns transitions packed
            // as `state * 256 + byte -> next_state` which is exactly
            // what the megakernel kernel consumes.
            match BatchRuleProgram::new(
                idx as u32,
                compiled.transitions,
                compiled.accept,
                compiled.state_count,
            ) {
                Ok(rule) => rules.push(rule),
                Err(error) => {
                    tracing::warn!(
                        literal_idx = idx,
                        %error,
                        "Megakernel: rule compile failed for literal; skipping"
                    );
                }
            }
        }

        if rules.is_empty() {
            tracing::warn!(
                "Megakernel: zero rules compiled — every literal failed dfa_compile?"
            );
            return None;
        }

        // Clone the backend out of the Arc — vyre's BatchDispatcher
        // takes WgpuBackend by value (it's `Clone` and internally
        // holds Arc<ArcSwap<(Device, Queue)>>, so the clone is cheap).
        let backend_owned: vyre_driver_wgpu::WgpuBackend = (*backend).clone();
        let config = BatchDispatchConfig::default();
        let dispatcher = match BatchDispatcher::new(backend_owned.clone(), config) {
            Ok(d) => d,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Megakernel: BatchDispatcher::new failed; falling back to literal-set GPU"
                );
                return None;
            }
        };

        tracing::info!(
            target: "keyhog::routing",
            literals = rules.len(),
            "Megakernel: BatchDispatcher compiled"
        );
        Some(Self {
            backend: backend_owned,
            dispatcher,
            rules,
        })
    }

    /// Number of compiled DFA rules (one per literal prefix).
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Mutable handle to the dispatcher. Used by the scan path that
    /// will replace `scan_coalesced_gpu`'s sharded inner loop with a
    /// single `BatchDispatcher::dispatch` call (TODO).
    pub fn dispatcher_mut(&mut self) -> &mut BatchDispatcher {
        &mut self.dispatcher
    }

    /// Read-only access to the rule table for diagnostics.
    pub fn rules(&self) -> &[BatchRuleProgram] {
        &self.rules
    }

    /// Return the held WgpuBackend for FileBatch::upload. Cheap clone
    /// (internally Arc<ArcSwap<...>>).
    pub fn backend(&self) -> &vyre_driver_wgpu::WgpuBackend {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_compile_returns_none_for_empty_literals() {
        // Without an Arc<WgpuBackend> we can't fully exercise the
        // dispatcher path here — but the early-out for an empty
        // literal set is testable without GPU.
        let empty: Arc<Vec<Vec<u8>>> = Arc::new(Vec::new());
        // Construction needs a backend; build one lazily and skip
        // the test on systems without an adapter (CI containers).
        let Ok(backend) = vyre_driver_wgpu::WgpuBackend::shared() else {
            eprintln!("SKIP: no wgpu backend on this host");
            return;
        };
        assert!(MegakernelScanner::try_compile(backend, &empty).is_none());
    }
}
