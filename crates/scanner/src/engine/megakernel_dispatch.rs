//! Megakernel-batched GPU dispatch — bundles many files × many DFA
//! rules into one persistent kernel launch via vyre's
//! `vyre_runtime::megakernel::BatchDispatcher`.
//!
//! **Status:** scaffolded + dispatch loop wired (`dispatch_triggers`
//! returns per-chunk per-pattern triggers via vyre megakernel),
//! gated behind `KEYHOG_USE_MEGAKERNEL=1` while we settle the
//! architectural mismatch documented below. Defaults OFF; the
//! production GPU path stays on `scan_coalesced_gpu`'s sharded
//! `GpuLiteralSet::scan` until megakernel becomes a measured win.
//!
//! **Why off-by-default:** vyre's `BatchDispatcher` is optimised for
//! "many files × few rules" (e.g. mass scanning with a small
//! curated rule pack). Keyhog's production corpus is the opposite —
//! 6000+ literal patterns scanned across a smaller per-batch file
//! count. With `BatchRuleProgram` modelling one rule = one literal,
//! the dispatcher allocates `chunks × rules` work items inside the
//! persistent kernel. At keyhog's scale that's hundreds of
//! thousands of work items per dispatch, which negates the kernel-
//! launch saving we wanted from megakernel in the first place.
//!
//! **Real megakernel win path (next architectural step):** keyhog
//! needs ONE multi-pattern DFA per batch (passing all literals into
//! a single `dfa_compile` call, accept-table → `output_records`
//! returning per-pattern hits) plus a custom megakernel
//! `OpcodeHandler` set to record per-pattern hits via
//! `output_records` instead of the built-in per-rule HitRecord.
//! That's a vyre-side feature request: the current `BatchRuleProgram`
//! / `HitRecord` API has no per-pattern field on the hit (only
//! `file_idx`, `rule_idx`, `layer_idx`, `match_offset`).
//!
//! What this module DOES deliver today:
//!  - Cross-platform wiring of vyre-runtime into keyhog (the
//!    `PhantomData<&'a ()>` fix in `vendor/vyre/vyre-runtime/src/
//!    lib.rs::GpuStream` that this commit ships unblocks Windows /
//!    macOS users).
//!  - DFA-per-literal compilation via `vyre_libs::matching::dfa::
//!    dfa_compile` + lazy `BatchDispatcher::new` cached on
//!    `CompiledScanner` — proves the megakernel path resolves and
//!    initialises against a live wgpu adapter.
//!  - End-to-end `dispatch_triggers` that hands back the same
//!    per-chunk per-pattern trigger bitmask the literal-set GPU
//!    path produces, so when the vyre-side API gains per-pattern
//!    hit reporting, the keyhog dispatcher will work as a one-line
//!    swap.
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

use keyhog_core::Chunk;
use vyre_libs::matching::dfa::dfa_compile;
use vyre_runtime::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, BatchRuleProgram, FileBatch, HitRecord,
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

    /// Dispatch one batch: upload `chunks` as a `FileBatch`, run the
    /// persistent megakernel against the cached DFA rules, decode the
    /// returned `HitRecord`s into a per-chunk per-pattern trigger
    /// bitmask. Caller runs the per-chunk extraction phase on top of
    /// these triggers (same shape as `scan_coalesced_gpu` after the
    /// `GpuLiteralSet::scan` call returns).
    ///
    /// Returns `None` when the dispatch errors at the wgpu layer (the
    /// caller should fall back to `scan_coalesced_gpu` in that case).
    /// `Some(triggers)` is `triggers[chunk_idx][pattern_word_idx]`.
    pub fn dispatch_triggers(
        &mut self,
        chunks: &[Chunk],
    ) -> Option<Vec<Vec<u64>>> {
        if chunks.is_empty() {
            return Some(Vec::new());
        }

        // Build the host-side batch input. `path_hash` is just the
        // chunk index (no need for a real path hash — the megakernel
        // returns per-file `file_idx` which round-trips back to this
        // index unchanged). `decoded_layer_index` stays at 0 because
        // keyhog's GPU dispatch operates on raw bytes, not decoded
        // archive layers.
        let batch_files: Vec<BatchFile> = chunks
            .iter()
            .enumerate()
            .map(|(idx, chunk)| {
                BatchFile::new(idx as u64, 0, chunk.data.as_ref().as_bytes().to_vec())
            })
            .collect();

        let device_queue = self.backend.device_queue();
        let rule_count = self.rules.len() as u32;
        // Hit capacity scales with chunks × rules but capped to keep
        // the device-side ring small. Real-world keyhog corpora hit
        // <50 patterns per chunk; allocate room for 256/chunk × rules
        // bounded at 16M total to mirror the literal-set cap.
        let target_hits = (chunks.len() as u64)
            .saturating_mul(256)
            .saturating_mul(rule_count.min(64) as u64);
        let hit_capacity: u32 = target_hits.clamp(100_000, 16_000_000) as u32;

        let batch = match FileBatch::upload(
            device_queue,
            &batch_files,
            rule_count,
            hit_capacity,
        ) {
            Ok(b) => b,
            Err(error) => {
                tracing::warn!(
                    %error,
                    chunks = chunks.len(),
                    "Megakernel: FileBatch::upload failed; caller should fall back"
                );
                return None;
            }
        };

        let started = std::time::Instant::now();
        let report = match self.dispatcher.dispatch(&batch, &self.rules) {
            Ok(r) => r,
            Err(error) => {
                tracing::warn!(
                    %error,
                    chunks = chunks.len(),
                    rules = self.rules.len(),
                    "Megakernel: dispatch failed; caller should fall back"
                );
                return None;
            }
        };

        tracing::debug!(
            target: "keyhog::routing",
            chunks = chunks.len(),
            rules = self.rules.len(),
            hits = report.hit_count,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "Megakernel batch dispatched"
        );

        // Flatten HitRecord stream into per-chunk per-pattern triggers.
        // rule_idx == pattern_id (we built BatchRuleProgram with
        // rule_idx == literal index = ac_map index for a literal-only
        // detector). Patterns with no matches stay zero.
        let total_patterns = self.rules.len();
        let words_per_chunk = total_patterns.div_ceil(64);
        let mut triggers: Vec<Vec<u64>> = chunks
            .iter()
            .map(|_| vec![0u64; words_per_chunk])
            .collect();

        for HitRecord { file_idx, rule_idx, .. } in &report.hits {
            let chunk_index = *file_idx as usize;
            let pattern_index = *rule_idx as usize;
            if chunk_index < triggers.len() && pattern_index < total_patterns {
                triggers[chunk_index][pattern_index / 64] |= 1u64 << (pattern_index % 64);
            }
        }

        Some(triggers)
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
