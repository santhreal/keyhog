//! Live wiring of the megakernel detection path (`engine/megakernel.rs`) into a
//! coalesced GPU scan.
//!
//! Trigger production is the ONLY thing this path changes. It builds the rule
//! catalog from `ac_map` once, dispatches the whole chunk batch in ONE GPU
//! launch, and turns the resulting `(file, detector)` firings into the SAME
//! per-chunk `Option<Vec<u64>>` trigger bitmap the Hyperscan prefilter produces
//! — then hands it to the SHARED `scan_coalesced_phase2`. So windowing,
//! confirmed extraction, fallback, generic, entropy, ML, suppression, dedup,
//! cross-file reassembly and cross-chunk boundary scan are byte-for-byte the
//! coalesced CPU path: the GPU only replaces phase 1.
//!
//! Recall (this step): the megakernel firings are UNIONED on top of the CPU
//! Hyperscan prefilter (`compute_coalesced_triggers`), which already scans every
//! `ac_map` pattern — including the un-lowerable `host_detectors` that stay in
//! `ac_map`. So the trigger set is provably ⊇ the default coalesced scan: this
//! path can never drop a detector the CPU path fires. The perf win — dropping
//! the CPU net and trusting `mk ∪ host-only` — lands once a parity gate proves
//! that union is a sound superset. Dispatch errors degrade LOUDLY to SIMD CPU,
//! never a silent empty result (Law 10).

use super::*;
use crate::hw_probe::ScanBackend;

impl CompiledScanner {
    /// The megakernel rule catalog, built once from `ac_map` (or loaded from the
    /// on-disk cache) and held resident. Returns `None` when the catalog has no
    /// GPU rules (nothing lowered / pack failed — both LOUDLY logged at build),
    /// so the caller degrades loudly rather than dispatching an empty catalog.
    #[cfg(feature = "gpu")]
    fn megakernel_catalog(&self) -> Option<&super::megakernel::MegakernelCatalog> {
        let catalog = self.megakernel_catalog.get_or_init(|| {
            let patterns: Vec<(String, usize)> = self
                .ac_map
                .iter()
                .enumerate()
                .map(|(i, p)| (p.regex.as_str().to_string(), i))
                .collect();
            super::megakernel::MegakernelCatalog::build_cached(&patterns)
        });
        (catalog.rule_count() > 0).then_some(catalog)
    }

    /// Coalesced megakernel scan: one GPU dispatch over the whole `chunks` batch
    /// produces the per-chunk trigger bitmap, then the SHARED coalesced phase-2
    /// tail runs the identical per-chunk extraction every other backend uses.
    /// Degrades LOUDLY to the per-chunk SIMD path when the catalog or backend is
    /// unavailable, or the dispatch errors — never a silent empty result.
    pub(crate) fn scan_coalesced_megakernel(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        if chunks.is_empty() {
            return Vec::new();
        }

        let degrade = |reason: String| -> Vec<Vec<keyhog_core::RawMatch>> {
            super::gpu_forced::deny_silent_gpu_degrade(self, ScanBackend::Gpu);
            // Degrade to the backend that is ACTUALLY live, not a hardcoded
            // `SimdCpu`: with the `simd` feature compiled but no Hyperscan
            // prefilter built (`simd_prefilter == None`), routing through
            // `SimdCpu` would itself silently re-degrade to the pure-CPU AC
            // path inside `scan_with_backend`. `degraded_backend_after_gpu_failure`
            // returns `SimdCpu` only when the prefilter is live and
            // `CpuFallback` otherwise, so the operator-visible backend matches
            // what runs (Law 10).
            let degraded = self.degraded_backend_after_gpu_failure();
            // Record the reason so operators (and the GPU self-test) can see WHY
            // the GPU path fell back, not just that it did.
            if let Ok(mut slot) = self.gpu_last_degrade_reason.lock() {
                *slot = Some(reason.clone());
            }
            tracing::warn!(
                target: "keyhog::gpu",
                %reason,
                ?degraded,
                "megakernel scan degraded off GPU (loud, recall-preserving)",
            );
            use rayon::prelude::*;
            let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, degraded))
                .collect();
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            results
        };

        // The shared coalesced phase-2 tail is `#[cfg(feature = "simd")]` (it is
        // the Hyperscan path's extraction). `gpu` implies `simd` at the feature
        // level (see keyhog-scanner Cargo.toml: `gpu = ["simd", ...]`), so this
        // body is ALWAYS compiled under `gpu` and the megakernel always has its
        // tail. The `#[cfg(feature = "simd")]` is retained as a fail-closed
        // assertion of that invariant: were the dependency ever dropped, this
        // function would fail to compile rather than silently lose its tail.
        #[cfg(feature = "simd")]
        {
            let kh = std::env::var_os("KH_PERF").is_some();
            let t_cat = std::time::Instant::now();
            let Some(catalog) = self.megakernel_catalog() else {
                return degrade("catalog: no ac_map pattern lowered to a GPU DFA".to_string());
            };
            let cat_s = t_cat.elapsed();
            let Some(backend) = self.wgpu_backend.as_ref() else {
                return degrade("no wgpu backend acquired at compile time".to_string());
            };

            // Recall-safe net: the full CPU Hyperscan prefilter (covers every
            // ac_map pattern, host_detectors included). Megakernel firings are
            // unioned in below, so this path is provably ⊇ the default scan.
            let t_hs = std::time::Instant::now();
            let mut triggers: Vec<Option<Vec<u64>>> = match &self.simd_prefilter {
                Some(scanner) => self.compute_coalesced_triggers(chunks, scanner),
                None => vec![None; chunks.len()],
            };
            let hs_s = t_hs.elapsed();

            let t_co = std::time::Instant::now();
            let files: Vec<(u64, Vec<u8>)> = chunks
                .iter()
                .enumerate()
                .map(|(i, c)| (i as u64, c.data.as_bytes().to_vec()))
                .collect();
            let co_s = t_co.elapsed();

            let t_dis = std::time::Instant::now();
            let firings = match catalog.scan(backend, &files) {
                Ok(f) => f,
                Err(error) => return degrade(format!("dispatch error: {error}")),
            };
            let dis_s = t_dis.elapsed();

            let words = self.ac_map.len().div_ceil(64).max(1);
            for f in &firings {
                if f.file_index < chunks.len() && f.detector < self.ac_map.len() {
                    let slot = triggers[f.file_index].get_or_insert_with(|| vec![0u64; words]);
                    if slot.len() < words {
                        slot.resize(words, 0);
                    }
                    slot[f.detector / 64] |= 1u64 << (f.detector % 64);
                }
            }

            let t_p2 = std::time::Instant::now();
            let results = self.scan_coalesced_phase2(chunks, triggers);
            if kh {
                eprintln!(
                    "KH_PERF megakernel: chunks={} catalog={:.3}s hs_net={:.3}s coalesce={:.3}s dispatch={:.3}s phase2={:.3}s firings={} gpu_rules={} host_only={}",
                    chunks.len(),
                    cat_s.as_secs_f64(),
                    hs_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    dis_s.as_secs_f64(),
                    t_p2.elapsed().as_secs_f64(),
                    firings.len(),
                    catalog.rule_count(),
                    // Detectors that did NOT lower to a GPU DFA and therefore
                    // ran only on the CPU Hyperscan net this dispatch — the
                    // GPU-coverage gap, surfaced rather than hidden.
                    catalog.host_detectors().len(),
                );
            }
            results
        }
    }
}
