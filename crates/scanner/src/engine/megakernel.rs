//! On-GPU detection via vyre's batched DFA rule-catalog megakernel.
#![cfg(feature = "gpu")]

use std::sync::Arc;

use vyre_driver_wgpu::WgpuBackend;
use vyre_driver_wgpu::megakernel::{
    BatchDispatchConfig, BatchDispatcher, BatchFile, FileBatch, HitRecord,
};
use vyre_libs::scan::build_regex_dfa_unanchored;
use vyre_runtime::megakernel::BatchRuleProgram;
use vyre_runtime::megakernel::rule_catalog::pack_rule_catalog;

const PER_RULE_MAX_DFA_STATES: usize = 16_384;
const PER_RULE_MAX_MATCHES: u32 = 200_000;
const MEGAKERNEL_HIT_CAPACITY: u32 = 1_000_000;
// v7: Keyhog now builds against the published `vyre-driver-wgpu 0.6.2`
// megakernel API only. That surface has whole-file batch geometry and no
// segmentation/dropped-hit extensions, so cached catalogs from the live-tree
// prototype must not be reused.
const MEGAKERNEL_CATALOG_CACHE_VERSION: u32 = 7;
pub(super) const CATALOG_WIRE_MAGIC: [u8; 4] = *b"KHMK";

pub(crate) struct MegakernelCatalog {
    pub(super) rules: Vec<BatchRuleProgram>,
    pub(super) rule_to_detector: Vec<usize>,
    pub(super) host_detectors: Vec<usize>,
    pub(super) dispatcher: std::sync::Mutex<Option<BatchDispatcher>>,
    pub(super) resident_batch: std::sync::Mutex<Option<FileBatch>>,
}

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
        // Build only against the published Vyre registry surface. Detector rules
        // that do not lower are kept on the loud host path; nothing is dropped.
        let built: Vec<(Option<(Vec<u32>, Vec<u32>, u32)>, usize)> = patterns
            .par_iter()
            .map(|(regex, detector)| {
                let lowered = build_regex_dfa_unanchored(
                    std::slice::from_ref(&regex.as_str()),
                    PER_RULE_MAX_MATCHES,
                    PER_RULE_MAX_DFA_STATES,
                )
                .ok()  // LAW10: GPU lower/acquire failure => host path (recall-preserving, counted host_lower_failed + surfaced via tracing::info/last_gpu_degrade_reason)
                .map(|pipe| {
                    (pipe.dfa.transitions, pipe.dfa.accept, pipe.dfa.state_count)
                });
                (lowered, *detector)
            })
            .collect();

        let mut rules = Vec::new();
        let mut rule_to_detector = Vec::new();
        let mut host_detectors = Vec::new();
        let mut host_lower_failed = 0usize; // DFA build / BatchRuleProgram failure
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
                        // LAW10: recall-safe — a BatchRuleProgram build failure does
                        // NOT drop the detector; it is pushed onto host_detectors and
                        // runs on the host fallback engine instead (same as the `None`
                        // arm below). The GPU batch is a faster path for the same
                        // detector set, never the only path.
                        Err(_) => { // LAW10: DFA-lower failure ⇒ detector runs on the loud host fallback path (recall preserved, same detector set), counted in host_lower_failed and surfaced via the tracing::info "un-lowerable" log (or tracing::error if all fail); host runs that set anyway, so the speed cost is a rounding error.
                            host_detectors.push(detector);
                            host_lower_failed += 1;
                        }
                    }
                }
                None => {
                    host_detectors.push(detector);
                    host_lower_failed += 1;
                }
            }
        }
        if std::env::var_os("KH_PERF").is_some() {
            // Dedup ceiling: how many of the GPU rules are DISTINCT pattern strings.
            // The kernel cost is ~linear in rule_count x files, so collapsing
            // duplicate literal rules (many detectors share a prefix like `key`) to
            // one rule fanning out to N detectors is the lever that keeps the kernel
            // cheap as the catalog grows (e.g. absorbing the fallback anchors).
            let unique_patterns: std::collections::HashSet<&str> =
                patterns.iter().map(|(p, _)| p.as_str()).collect();
            eprintln!(
                "KH_PERF megakernel classify: gpu={} unique_patterns={}/{} | host: lower_failed={host_lower_failed}",
                rules.len(),
                unique_patterns.len(),
                patterns.len(),
            );
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
            let bytes_of = |r: &BatchRuleProgram| {
                (r.transitions.len() + r.accept.len()) * std::mem::size_of::<u32>()
            };
            let words: usize = rules
                .iter()
                .map(|r| r.transitions.len() + r.accept.len())
                .sum();
            // State-count buckets + MiB attributable to each, to see whether a
            // few explosive DFAs dominate the catalog size (lower the cap, push
            // them to the host/HS path) or it is uniform.
            let hi = [512usize, 2048, 8192, usize::MAX];
            let mut cnt = [0usize; 4];
            let mut mib = [0f64; 4];
            for r in &rules {
                let sc = r.state_count as usize;
                let b = hi.iter().position(|&h| sc <= h).unwrap_or(3);  // LAW10: empty/absent => documented numeric/sentinel default, recall-safe
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
            resident_batch: std::sync::Mutex::new(None),
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
        files: Vec<(u64, Vec<u8>)>,
    ) -> Result<Vec<Firing>, String> {
        if files.is_empty() || self.rules.is_empty() {
            return Ok(Vec::new());
        }
        let file_count = files.len();

        // Fixed hit-ring capacity (see MEGAKERNEL_HIT_CAPACITY): the batch ring
        // and the reused dispatcher's compiled pipeline MUST agree on capacity,
        // and a stable value keeps it to a single compiled pipeline variant.
        let hit_capacity = MEGAKERNEL_HIT_CAPACITY;

        let batch_files: Vec<BatchFile> = files
            .into_iter()
            .enumerate()
            .map(|(i, (hash, bytes))| BatchFile::new(hash ^ i as u64, 0, bytes))
            .collect();

        // Resident GPU batch: upload once, then REFRESH in place every scan.
        // `FileBatch::upload` allocates all six GPU buffers (haystack, offsets,
        // metadata, segments, queue_state, hit_ring) via
        // `device.create_buffer` — a driver round-trip that dominated dispatch
        // time (the realloc, not the compute). `refresh` reuses the resident
        // buffers (`queue.write_buffer`) when the new batch fits the fixed
        // `MEGAKERNEL_HIT_CAPACITY` ring, so only the FIRST scan pays the
        // allocation. Fail-closed: `refresh` returns `Err` on a shape it can't
        // fit, never a silent stale-buffer reuse.
        let mut batch_guard = self
            .resident_batch
            .lock()
            .map_err(|e| format!("megakernel batch mutex poisoned: {e}"))?;
        match batch_guard.as_mut() {
            Some(batch) => batch
                .refresh(&batch_files, self.rules.len() as u32, hit_capacity)
                .map_err(|e| format!("megakernel FileBatch refresh: {e:?}"))?,
            None => {
                *batch_guard = Some(
                    FileBatch::upload(
                        backend.device_queue(),
                        &batch_files,
                        self.rules.len() as u32,
                        hit_capacity,
                    )
                    .map_err(|e| format!("megakernel FileBatch upload: {e:?}"))?,
                );
            }
        }
        // Published `vyre-driver-wgpu 0.6.2` exposes one work item per
        // `(file, rule, layer)`. There is no segmentation knob in that registry
        // surface, so Keyhog keeps exact whole-file scanning here and relies on a
        // later Vyre release for tiled large-file geometry.
        let batch = batch_guard
            .as_ref()
            .expect("resident batch initialized immediately above");

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
                // Occupancy is NOT the megakernel bottleneck: at 100% occupancy
                // proxy the kernel is already ~0.4 s/batch; the dominant single-
                // scan cost is the ~1 GB DFA-catalog upload (one-time/process)
                // and the CPU phase-2 tail, neither of which worker_groups moves
                // (measured task #35, RTX 5090: WG 255→1024 left dispatch flat).
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
        let summary = dispatcher
            .dispatch_into(batch, &self.rules, &mut hits)
            .map_err(|e| format!("megakernel dispatch: {e:?}"))?;
        if std::env::var_os("KH_PERF").is_some() {
            let t = &summary.telemetry;
            eprintln!(
                "KH_PERF mk-dispatch: files={} rules={} kernel_wall={:.3}s items={} hits={} occupancy_bps={} bytes_up={} bytes_back={} launches={}",
                file_count,
                self.rules.len(),
                summary.wall_time.as_secs_f64(),
                summary.items_processed,
                summary.hit_count,
                t.occupancy_proxy_bps,
                t.bytes_uploaded,
                t.bytes_read_back,
                t.kernel_launches,
            );
        }

        // LAW 10: published Vyre 0.6.2 caps the device hit counter at the ring
        // capacity and does not expose a separate dropped-hit counter. An exact
        // full ring is therefore ambiguous: it may be exactly full or it may have
        // saturated. Fail CLOSED and let the caller run the complete CPU scan for
        // this batch rather than returning a potentially truncated firing set.
        if hits.len() >= hit_capacity as usize {
            static OVERFLOW_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            if OVERFLOW_WARNED.set(()).is_ok() {
                eprintln!(
                    "keyhog: GPU megakernel hit ring reached capacity {}; \
                     falling back to the complete CPU scan for this batch. \
                     Fix: raise MEGAKERNEL_HIT_CAPACITY or shard the batch.",
                    MEGAKERNEL_HIT_CAPACITY,
                );
            }
            tracing::warn!(
                target: "keyhog::gpu",
                returned = hits.len(),
                capacity = MEGAKERNEL_HIT_CAPACITY,
                "GPU megakernel hit-ring capacity reached; degrading this batch to the CPU scan for complete recall",
            );
            return Err(format!(
                "GPU hit ring reached capacity {MEGAKERNEL_HIT_CAPACITY}; degrading to CPU for complete recall",
            ));
        }

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
    let digest: [u8; 32] = h.finalize().into();
    format!("mk-{}", keyhog_core::hex_encode(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The catalog build must lower compact regular patterns to GPU DFA rules
    /// and route the genuine state-explosion (`AIza` with a 64-byte alphabet
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

    /// The over-firing mask in `scan_coalesced_megakernel` is sound ONLY if the
    /// catalog partitions detectors into EXACTLY two disjoint sets that together
    /// cover every detector: GPU-covered (`rule_to_detector`) and host-only
    /// (`host_detectors`). If a detector were in BOTH, masking the CPU bits to
    /// host-only would drop nothing but seeding from GPU would double-count it;
    /// if a detector were in NEITHER, it would be silently uncovered on the GPU
    /// path (a recall hole, Law 10). This pins the precondition so a future
    /// catalog change that leaks or drops a detector goes red.
    #[test]
    fn every_detector_is_covered_by_exactly_one_path() {
        use std::collections::BTreeSet;
        let patterns = vec![
            ("ghp_[A-Za-z0-9]{36}".to_string(), 0),   // GPU
            ("AKIA[A-Z0-9]{16}".to_string(), 1),      // GPU
            (r"(\w+)\s+\1".to_string(), 2),           // host (backref)
            ("AIza[A-Za-z0-9_-]{35}".to_string(), 3), // host (state explosion)
        ];
        let catalog = MegakernelCatalog::build(&patterns);
        let gpu: BTreeSet<usize> = catalog.rule_to_detector.iter().copied().collect();
        let host: BTreeSet<usize> = catalog.host_detectors.iter().copied().collect();

        // Disjoint: no detector is on both paths (no double-counting).
        assert!(
            gpu.is_disjoint(&host),
            "a detector appears on BOTH the GPU and host path: gpu={gpu:?} host={host:?}"
        );
        // Complete: every input detector index is covered exactly once.
        let mut union: BTreeSet<usize> = gpu.clone();
        union.extend(host.iter().copied());
        let expected: BTreeSet<usize> = (0..patterns.len()).collect();
        assert_eq!(
            union, expected,
            "detector coverage gap: every detector must be on exactly one path"
        );
        // No index collisions in the dense rule_to_detector map either.
        assert_eq!(
            catalog.rule_to_detector.len(),
            gpu.len(),
            "rule_to_detector must map each GPU rule to a DISTINCT detector"
        );
    }
}
