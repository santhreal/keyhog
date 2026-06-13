//! On-GPU detection via vyre's batched DFA rule-catalog megakernel.
//!
//! This is the REAL megakernel path (not the dead persistent-ring stub this
//! file used to hold): the `vyre_driver_wgpu::megakernel::BatchDispatcher`
//! engine, proven end-to-end in `tests/megakernel_cpu_parity.rs` (GPU≡CPU
//! firings on 1500 real files, one dispatch). It is the dispatch-overhead-free
//! vehicle the GPU-detection rewrite targets (`docs/GPU_DETECTION_REWRITE.md`).
//!
//! # Model
//!
//! Detection is a two-stage split (doc "Core abstraction: the candidate"):
//!
//! * **GPU generate** — one unanchored DFA per detector pattern, packed into a
//!   resident rule catalog, dispatched over a COALESCED batch of files in a
//!   single launch. Emits `(file, detector, match_end)` firings.
//! * **Host tail** — for each firing, the existing per-detector extraction runs
//!   on that file (capture + checksum + companion + ML + confidence). The
//!   megakernel REPLACES the prefilter ("which detectors fire where"), not the
//!   extraction, so recall/precision policy is unchanged.
//!
//! Patterns the unanchored DFA can't carry (PCRE lookaround/backref, or DFA
//! state-budget blowups) take a **loud host path** (Law 10) — never a silent
//! drop. `MegakernelCatalog::build` records every one in `host_detectors`.
//!
//! # Status
//!
//! The catalog build + GPU scan + firing decode are implemented and tested here
//! (`tests/megakernel_catalog_scan.rs`). Wiring this as the live GPU backend
//! (routing `ScanBackend::Gpu` through it, fail-closed, and retiring the
//! `RulePipeline` / `GpuLiteralSet` parallel paths) is the next step.
#![cfg(feature = "gpu")]

use std::sync::Arc;

use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_driver_wgpu::WgpuBackend;
use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::rule_catalog::pack_rule_catalog;
use vyre_runtime::megakernel::BatchRuleProgram;

/// Per-rule DFA state budget for the unanchored catalog. Unanchored DFAs run
/// ~3x the anchored state count; 16384 admits the AKIA-class bodies
/// (`AKIA[A-Z0-9]{16}` = 2468 states) while still rejecting the genuine
/// large-charclass×long-body explosions (`AIza[A-Za-z0-9_-]{35}`) to the loud
/// host path. Tunable as detection coverage vs transition-table memory.
const PER_RULE_MAX_DFA_STATES: usize = 16_384;
/// Per-rule match cap fed to the DFA builder (metadata only; the dispatcher's
/// hit ring is sized separately at scan time).
const PER_RULE_MAX_MATCHES: u32 = 200_000;
/// Stable hit-ring capacity for EVERY megakernel dispatch. Fixed (not scaled
/// per batch) so the reused dispatcher compiles exactly ONE pipeline variant —
/// `BatchPipelineShape` keys on `hit_capacity`, so a per-batch capacity forced a
/// fresh `compile_persistent` (~10s) every batch. 1M entries (~16 MiB ring)
/// comfortably holds any single batch's firings; overflow is surfaced LOUDLY by
/// the dispatcher report, never silently dropped (Law 10).
const MEGAKERNEL_HIT_CAPACITY: u32 = 1_000_000;
/// Cache-key namespace version for the on-disk compiled catalog. Bump on any
/// change to the catalog's MEANING that the wire format alone can't catch —
/// e.g. a vyre `build_regex_dfa_unanchored` semantics change that produces
/// different DFAs from the same regex. (Wire-FORMAT changes bump
/// `MegakernelCatalog::WIRE_VERSION` instead.)
const MEGAKERNEL_CATALOG_CACHE_VERSION: u32 = 1;
/// Magic stamped on the cached-catalog blob and folded into the cache key.
/// `pub(super)` so the sibling [`super::megakernel_wire`] module (the catalog
/// cache wire format) and the cache-key here share one source of truth.
pub(super) const CATALOG_WIRE_MAGIC: [u8; 4] = *b"KHMK";

/// A compiled on-GPU detection catalog: one DFA rule per lowerable detector
/// pattern, plus the detectors that must run on the host (loud path).
///
/// Built once at scanner compile (the per-pattern subset construction is the
/// expensive part — parallelised here) and held resident for every scan.
pub(crate) struct MegakernelCatalog {
    // Fields are `pub(super)` so the sibling `super::megakernel_wire` module
    // (the catalog cache wire format — `to_bytes`/`from_bytes`) can read and
    // reconstruct them; they stay private to the `engine` module otherwise.
    /// Dense unanchored-DFA rule programs, `rule_idx == position in this vec`.
    pub(super) rules: Vec<BatchRuleProgram>,
    /// `rule_to_detector[rule_idx]` = the detector index that rule belongs to,
    /// so a GPU `HitRecord.rule_idx` decodes back to a keyhog detector.
    pub(super) rule_to_detector: Vec<usize>,
    /// Detector indices whose pattern the unanchored DFA could NOT carry
    /// (PCRE feature / state-budget blowup). These run on the host — LOUD, never
    /// silently dropped.
    pub(super) host_detectors: Vec<usize>,
    /// The batched-megakernel dispatcher, created lazily on the first `scan` and
    /// REUSED across every batch. Reuse is the whole perf story: the dispatcher
    /// holds the compiled WGSL pipeline and the GPU-resident rule catalog
    /// (`ensure_rule_buffers` no-ops when the rule fingerprints are unchanged),
    /// so batches after the first pay only file upload + GPU scan + readback.
    /// Recreating it per batch (the old code) recompiled the pipeline and
    /// re-uploaded the entire DFA catalog every time (~10s/batch). `Mutex`
    /// because `dispatch_into` needs `&mut` while the catalog is shared `&self`;
    /// batches are dispatched sequentially so it is never contended.
    pub(super) dispatcher: std::sync::Mutex<Option<BatchDispatcher>>,
}

/// One GPU detection firing: detector `detector` matched in coalesced file
/// `file_index`, with the match ending `match_end` bytes into that file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Firing {
    pub file_index: usize,
    pub detector: usize,
    pub match_end: usize,
}

impl MegakernelCatalog {
    /// Compile `(regex, detector_index)` patterns into the resident catalog.
    ///
    /// Patterns are compiled to unanchored DFAs in parallel (rayon); each that
    /// fails to lower is recorded in `host_detectors` (the loud host path),
    /// never dropped. Always returns a catalog: if NOT ONE pattern lowered (or
    /// the catalog fails to pack) it returns one with zero GPU rules — both
    /// cases LOUDLY logged — and the caller treats `rule_count() == 0` as "no
    /// GPU path" and degrades loudly. Always returning `Self` (not `Option`)
    /// lets the on-disk cache compose with the generic `cached_load_or_compile`.
    pub(crate) fn build(patterns: &[(String, usize)]) -> Self {
        use rayon::prelude::*;

        // The unanchored-DFA subset construction is the expensive part — minutes
        // for the full detector set. A cold build prints NOTHING for that whole
        // time, which dogfooding showed reads as a hang. Surface it LOUDLY on
        // stderr (it runs only on a cache MISS via `build_cached`, so this is
        // one-time per pattern set + DFA budget; the result is cached at
        // ~/.cache/keyhog/programs/).
        let announce = patterns.len() > 256;
        if announce {
            eprintln!(
                "keyhog: building GPU detection catalog for {} detectors \
                 (one-time, can take a few minutes; cached afterward)…",
                patterns.len()
            );
        }

        // (Option<dfa>, detector_index): Some => lowered to a DFA, None => host.
        let built: Vec<(Option<(Vec<u32>, Vec<u32>, u32)>, usize)> = patterns
            .par_iter()
            .map(|(regex, detector)| {
                let lowered = build_regex_dfa_unanchored(
                    std::slice::from_ref(&regex.as_str()),
                    PER_RULE_MAX_MATCHES,
                    PER_RULE_MAX_DFA_STATES,
                )
                .ok()
                .map(|pipe| (pipe.dfa.transitions, pipe.dfa.accept, pipe.dfa.state_count));
                (lowered, *detector)
            })
            .collect();

        let mut rules = Vec::new();
        let mut rule_to_detector = Vec::new();
        let mut host_detectors = Vec::new();
        for (lowered, detector) in built {
            match lowered {
                Some((transitions, accept, state_count)) => {
                    match BatchRuleProgram::new(
                        rules.len() as u32,
                        transitions,
                        accept,
                        state_count,
                    ) {
                        Ok(rule) => {
                            rules.push(rule);
                            rule_to_detector.push(detector);
                        }
                        // A validated-shape failure is also a loud host path,
                        // not a drop.
                        Err(_) => host_detectors.push(detector),
                    }
                }
                None => host_detectors.push(detector),
            }
        }

        if rules.is_empty() {
            tracing::error!(
                target: "keyhog::gpu",
                host_path = host_detectors.len(),
                "megakernel catalog: NO detector pattern lowered to a GPU DFA — the whole pass runs on the loud host path",
            );
        } else if !host_detectors.is_empty() {
            tracing::info!(
                target: "keyhog::gpu",
                gpu_rules = rules.len(),
                host_path = host_detectors.len(),
                "megakernel catalog: {} detector pattern(s) on the loud host path (un-lowerable)",
                host_detectors.len(),
            );
        }
        // Validate the catalog packs (the resident layout the dispatcher uses);
        // a pack failure means it can't be dispatched — drop ALL rules to the
        // loud host path rather than ship an undispatchable catalog (so the
        // caller sees rule_count()==0 and degrades loudly, never a silent empty).
        if !rules.is_empty() && pack_rule_catalog(&rules).is_err() {
            tracing::error!(
                target: "keyhog::gpu",
                "megakernel catalog: rule catalog failed to pack — disabling all {} GPU rules (host path only)",
                rules.len(),
            );
            host_detectors.extend(rule_to_detector.drain(..));
            rules.clear();
        }
        if std::env::var_os("KH_PERF").is_some() {
            let bytes_of =
                |r: &BatchRuleProgram| (r.transitions.len() + r.accept.len()) * std::mem::size_of::<u32>();
            let words: usize = rules.iter().map(|r| r.transitions.len() + r.accept.len()).sum();
            // State-count buckets + MiB attributable to each, to see whether a
            // few explosive DFAs dominate the catalog size (lower the cap, push
            // them to the host/HS path) or it is uniform.
            let hi = [512usize, 2048, 8192, usize::MAX];
            let mut cnt = [0usize; 4];
            let mut mib = [0f64; 4];
            for r in &rules {
                let sc = r.state_count as usize;
                let b = hi.iter().position(|&h| sc <= h).unwrap_or(3);
                cnt[b] += 1;
                mib[b] += bytes_of(r) as f64 / (1024.0 * 1024.0);
            }
            eprintln!(
                "KH_PERF megakernel catalog: {} gpu rules, {} host, {:.1} MiB total",
                rules.len(),
                host_detectors.len(),
                (words * std::mem::size_of::<u32>()) as f64 / (1024.0 * 1024.0),
            );
            eprintln!(
                "KH_PERF megakernel states: <=512: {} rules {:.0}MiB | <=2048: {} {:.0}MiB | <=8192: {} {:.0}MiB | >8192: {} {:.0}MiB",
                cnt[0], mib[0], cnt[1], mib[1], cnt[2], mib[2], cnt[3], mib[3],
            );
        }
        Self {
            rules,
            rule_to_detector,
            host_detectors,
            dispatcher: std::sync::Mutex::new(None),
        }
    }

    /// On-disk-cached [`build`](Self::build): loads the compiled catalog from
    /// `~/.cache/keyhog/programs/` when a blob for this exact pattern set + DFA
    /// parameters exists, else runs the (minutes-long) subset construction and
    /// caches it. The key folds in the pattern set, DFA budgets, and a catalog
    /// format version, so any of those changing invalidates automatically; a
    /// stale/corrupt blob is dropped and rebuilt by `cached_load_or_compile`.
    /// A missing cache directory just means a direct build (identical catalog,
    /// no recall difference — not a silent fallback).
    pub(crate) fn build_cached(patterns: &[(String, usize)]) -> Self {
        let Some(cache_dir) = super::gpu_cache::gpu_matcher_cache_dir() else {
            return Self::build(patterns);
        };
        let key = megakernel_catalog_cache_key(patterns);
        vyre_libs::scan::cached_load_or_compile(&cache_dir, &key, || Self::build(patterns))
    }

    /// Detector indices on the loud host path (un-lowerable patterns).
    pub(crate) fn host_detectors(&self) -> &[usize] {
        &self.host_detectors
    }

    /// Number of GPU-resident DFA rules.
    pub(crate) fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a coalesced batch of files on the GPU, returning detection firings.
    ///
    /// `files[i]` is `(path_hash, bytes)`; the returned `Firing.file_index`
    /// indexes `files`. One device dispatch covers the whole batch. Errors
    /// (upload / dispatch / readback) propagate so the caller fails CLOSED
    /// rather than silently returning an empty result.
    ///
    /// # Errors
    ///
    /// Returns the dispatcher's error string on upload/dispatch/readback failure.
    pub(crate) fn scan(
        &self,
        backend: &Arc<WgpuBackend>,
        files: &[(u64, Vec<u8>)],
    ) -> Result<Vec<Firing>, String> {
        if files.is_empty() || self.rules.is_empty() {
            return Ok(Vec::new());
        }

        // Fixed hit-ring capacity (see MEGAKERNEL_HIT_CAPACITY): the batch ring
        // and the reused dispatcher's compiled pipeline MUST agree on capacity,
        // and a stable value keeps it to a single compiled pipeline variant.
        let hit_capacity = MEGAKERNEL_HIT_CAPACITY;

        let batch_files: Vec<BatchFile> = files
            .iter()
            .enumerate()
            .map(|(i, (hash, bytes))| BatchFile::new(*hash ^ i as u64, 0, bytes.clone()))
            .collect();

        let batch = FileBatch::upload(
            backend.device_queue(),
            &batch_files,
            self.rules.len() as u32,
            hit_capacity,
        )
        .map_err(|e| format!("megakernel FileBatch upload: {e:?}"))?;

        // Create the dispatcher ONCE and reuse it for every batch. The first
        // dispatch compiles the WGSL pipeline and uploads the DFA catalog;
        // subsequent dispatches reuse the cached pipeline and skip the rule
        // upload (fingerprints unchanged). Recreating it per batch — the old
        // code — recompiled + re-uploaded the whole catalog every batch (~10s).
        let mut guard = self
            .dispatcher
            .lock()
            .map_err(|e| format!("megakernel dispatcher mutex poisoned: {e}"))?;
        if guard.is_none() {
            let config = BatchDispatchConfig {
                workgroup_size_x: 64,
                // 0 => the dispatcher derives worker_groups from device limits.
                worker_groups: 0,
                hit_capacity,
                timeout: std::time::Duration::from_secs(30),
                ..Default::default()
            };
            *guard = Some(
                BatchDispatcher::new((**backend).clone(), config)
                    .map_err(|e| format!("megakernel dispatcher init: {e:?}"))?,
            );
        }
        let dispatcher = guard
            .as_mut()
            .expect("dispatcher initialized immediately above");

        let mut hits: Vec<HitRecord> = Vec::with_capacity(4096);
        dispatcher
            .dispatch_into(&batch, &self.rules, &mut hits)
            .map_err(|e| format!("megakernel dispatch: {e:?}"))?;

        Ok(hits
            .iter()
            .filter_map(|h| {
                self.rule_to_detector
                    .get(h.rule_idx as usize)
                    .map(|&detector| Firing {
                        file_index: h.file_idx as usize,
                        detector,
                        match_end: h.match_offset as usize,
                    })
            })
            .collect())
    }
}

/// Cache key for the on-disk compiled catalog: SHA-256 over the catalog magic +
/// version, the DFA budgets, and every `(detector_index, regex)` in order. Any
/// change to the pattern set, the budgets, or the version yields a fresh key, so
/// a stale catalog is never loaded for a changed detector set.
fn megakernel_catalog_cache_key(patterns: &[(String, usize)]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(CATALOG_WIRE_MAGIC);
    h.update(MEGAKERNEL_CATALOG_CACHE_VERSION.to_le_bytes());
    h.update((PER_RULE_MAX_DFA_STATES as u64).to_le_bytes());
    h.update((PER_RULE_MAX_MATCHES as u64).to_le_bytes());
    h.update((patterns.len() as u64).to_le_bytes());
    for (regex, detector) in patterns {
        h.update((*detector as u64).to_le_bytes());
        h.update((regex.len() as u64).to_le_bytes());
        h.update(regex.as_bytes());
    }
    let digest = h.finalize();
    let mut key = String::with_capacity(67);
    key.push_str("mk-");
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(key, "{b:02x}");
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog build must lower the overlap-free / bounded-body patterns to
    /// GPU DFA rules and route the genuine state-explosion (`AIza` — 64-char
    /// class × 35) to the loud host path — never silently drop it.
    #[test]
    fn catalog_classifies_lowerable_vs_host() {
        let patterns = vec![
            ("ghp_[A-Za-z0-9]{36}".to_string(), 0),   // overlap-free → GPU
            ("AKIA[A-Z0-9]{16}".to_string(), 1),      // 2468 states < budget → GPU
            ("AIza[A-Za-z0-9_-]{35}".to_string(), 2), // explodes → host path
        ];
        let catalog = MegakernelCatalog::build(&patterns);
        assert!(
            catalog.rule_count() >= 2,
            "ghp_ and AKIA must lower to GPU rules, got {}",
            catalog.rule_count()
        );
        assert!(
            catalog.host_detectors().contains(&2),
            "AIza (state explosion) must take the loud host path, host={:?}",
            catalog.host_detectors()
        );
    }

    /// An all-unlowerable set yields a catalog with ZERO GPU rules (the caller
    /// treats `rule_count() == 0` as "no GPU path" and degrades loudly) rather
    /// than a catalog that would silently match nothing.
    #[test]
    fn catalog_empty_when_nothing_lowers() {
        // A backreference is not a regular language — the DFA builder rejects it.
        let patterns = vec![(r"(\w+)\s+\1".to_string(), 0)];
        let catalog = MegakernelCatalog::build(&patterns);
        assert_eq!(catalog.rule_count(), 0);
        // The un-lowerable detector must land on the loud host path, not vanish.
        assert_eq!(catalog.host_detectors(), &[0]);
    }

}
