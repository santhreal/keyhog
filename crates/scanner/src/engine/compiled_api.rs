use super::*;
use crate::hw_probe::ScanBackend;

static SIMD_AUTO_DEGRADE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

/// Family + homoglyph breakdown of the always-active (`phase2_always_active_indices`)
/// pool, used to pin the true composition behind the F3 perf floor.
///
/// The distinction that matters: `*_homoglyph` patterns are ASCII-fold-skippable
/// on a pure-ASCII chunk (the CredData common case) they are SKIPPED by
/// `homoglyph_ascii_skip` and contribute NOTHING to the ASCII prefilter cost. So
/// the pool that actually runs the 84.3%-of-scan HS pass on ASCII source is the
/// `*_real` (non-homoglyph) subset. Splitting these apart is what tells whether the
/// ASCII prefilter cost is generic/entropy-bound or vendor-bound.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct Phase2PoolBreakdown {
    pub(crate) generic_entropy_real: usize,
    pub(crate) generic_entropy_homoglyph: usize,
    pub(crate) vendor_real: usize,
    pub(crate) vendor_homoglyph: usize,
    pub(crate) vendor_real_ids: Vec<String>,
}

impl CompiledScanner {
    /// Whether a SIMD (Hyperscan/Vectorscan) prefilter is compiled in and live.
    ///
    /// The GPU phase-1 paths reroute a batch through the SIMD coalesced scan
    /// when the GPU prefix output is too dense for phase 2. That reroute only
    /// exists when the `simd` feature is on; in `--no-default-features`
    /// (portable / macOS no-system-libs) builds the `simd_prefilter` field is
    /// `#[cfg]`-compiled out entirely, so there is nothing to reroute into and
    /// the answer is always `false`. This accessor keeps the reroute guards
    /// compiling in every feature combination without scattering
    /// `#[cfg(feature = "simd")]` across each call site.
    ///
    #[inline]
    pub(crate) fn simd_backend_usable(&self) -> bool {
        #[cfg(feature = "simd")]
        {
            return self.simd_prefilter.is_some();
        }
        #[cfg(not(feature = "simd"))]
        {
            false
        }
    }

    #[inline]
    pub(crate) fn live_cpu_backend(&self) -> ScanBackend {
        if self.simd_backend_usable() {
            ScanBackend::SimdCpu
        } else {
            ScanBackend::CpuFallback
        }
    }

    pub(crate) fn warn_simd_auto_degrade(&self, context: &str) {
        if SIMD_AUTO_DEGRADE_WARNED.set(()).is_ok() {
            eprintln!(
                "keyhog: SIMD backend unavailable ({context}); routing this automatic CPU-tier scan through cpu-fallback. \
Forced --backend simd is rejected instead of silently running another backend."
            );
        }
        tracing::warn!(
            target: "keyhog::routing",
            %context,
            "SIMD backend unavailable; automatic CPU-tier route changed to cpu-fallback"
        );
    }

    /// Exit before a caller-selected backend can silently run a different path.
    pub(crate) fn require_selected_backend_stack(&self, backend: ScanBackend) {
        if backend == ScanBackend::SimdCpu && !self.simd_backend_usable() {
            crate::process_exit::backend_unavailable(
                "simd-regex selected but the SIMD/Hyperscan prefilter is unavailable; \
silent cpu-fallback execution is forbidden. Run `keyhog backend --self-test` or choose \
`--backend cpu-fallback` explicitly.",
            );
        }
        gpu_forced::require_selected_gpu_stack(self, backend);
    }

    /// Number of loaded detectors.
    pub(crate) fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Pre-interned `(detector_id, detector_name, service)` triple for the
    /// detector at `detector_index`. Three `Arc::clone`s, zero hashing, the
    /// hot-path replacement for three `ScanState::intern_metadata` calls on
    /// frozen detector metadata (PERF-locality_intern-1). Returns byte-for-byte
    /// the same `Arc<str>` values `static_intern.lookup(...)` would, because
    /// they ARE the same arena entries, so emitted findings are unchanged.
    #[inline]
    pub(crate) fn interned_detector_metadata(
        &self,
        detector_index: usize,
    ) -> (Arc<str>, Arc<str>, Arc<str>) {
        let (id, name, service) = &self.metadata_by_index[detector_index];
        (Arc::clone(id), Arc::clone(name), Arc::clone(service))
    }

    /// Effective weak-anchor for the matched pattern `entry`.
    ///
    /// Combines the precomputed per-detector [`crate::suppression::WeakAnchorBase`]
    /// (indexed by `entry.detector_index`, built from the same detector list that
    /// creates every `CompiledPattern::detector_index`) with the per-PATTERN
    /// broad-identifier check resolved against `entry.regex` (memoized on the
    /// `LazyRegex`). Index directly so an index-parallel construction bug is loud.
    #[inline]
    pub(crate) fn detector_pattern_weak_anchor(
        &self,
        entry: &crate::types::CompiledPattern,
    ) -> bool {
        match self.detector_weak_anchor_base_by_index[entry.detector_index] {
            crate::suppression::WeakAnchorBase::Always => true,
            crate::suppression::WeakAnchorBase::Never => false,
            crate::suppression::WeakAnchorBase::PerPattern => {
                entry.regex.has_broad_identifier_capture()
            }
        }
    }

    /// Total number of patterns (AC + phase-2 capture).
    pub(crate) fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.phase2_patterns.len()
    }

    /// This scanner's performance route tuning. Differential parity tests use
    /// `keyhog_scanner::testing` helpers to flip a route on one scanner and
    /// drive a single input down both code paths without process-global state.
    #[cfg(test)]
    pub(crate) fn tuning(&self) -> &phase2::ScannerTuning {
        &self.tuning
    }

    /// Diagnostic: `(phase2_total, always_active, always_active_eligible)`
    /// how much the shared-anchor index shrinks the RegexSet prefilter. The
    /// prefilter cost scales with `always_active - always_active_eligible`.
    #[cfg(test)]
    pub(crate) fn phase2_anchor_stats(&self) -> (usize, usize, usize) {
        let total = self.phase2_patterns.len();
        let always_active = self.phase2_always_active_indices.len();
        let aae = self.phase2_anchor_index.as_ref().map_or(0, |idx| {
            self.phase2_always_active_indices
                .iter()
                .filter(|&&i| idx.is_always_active_eligible(i))
                .count()
        });
        (total, always_active, aae)
    }

    /// Benchmark helper: directly time `mark_matches` on a no-candidate text
    /// without the phase-1 HS scan overhead. Returns the mean nanoseconds per
    /// `mark_matches` call over `n_calls` iterations on `text`.
    ///
    /// Used by `phase2_no_candidate_gate_perf` to assert the isolated gate
    /// path (bloom → AC early-exit → return) is well below the 30931 ns/call
    /// pre-fix baseline. The method bypasses the whole scan pipeline
    /// (`scan_chunks_with_backend`) so only the `mark_matches` body is timed.
    #[cfg(test)]
    pub(crate) fn mark_matches_gate_ns_per_call(&self, text: &str, n_calls: u32) -> f64 {
        let Some(prefilter) = &self.phase2_always_active_prefilter else {
            return 0.0;
        };
        let tuning = self.tuning().resolve();
        // Warm: one call to initialise any thread-local state before timing.
        let mut scratch = phase2::ActivePatternsScratch::new();
        scratch.begin(self.phase2_patterns.len());
        prefilter.mark_matches(&self.phase2_patterns, text, &mut scratch, false, &tuning);
        // Timed loop.
        let t0 = std::time::Instant::now();
        for _ in 0..n_calls {
            scratch.begin(self.phase2_patterns.len());
            prefilter.mark_matches(&self.phase2_patterns, text, &mut scratch, false, &tuning);
        }
        let elapsed_ns = t0.elapsed().as_nanos() as f64;
        elapsed_ns / n_calls as f64
    }

    /// F3 perf experiment: time the always-active HS `mark` on `haystack` with the
    /// FULL always-active DB vs a lean DB that EXCLUDES homoglyph variants.
    ///
    /// On a pure-ASCII chunk the homoglyph variants (99.9% of the pool) cannot
    /// match, their prefixes are unicode look-alikes absent from ASCII bytes, and
    /// the base ASCII prefix is already covered by the AC/confirmed path (the same
    /// invariant `homoglyph_ascii_skip` relies on). The RegexSet path already skips
    /// them on ASCII; the HS path does NOT. This measures whether that missing skip
    /// costs real time or whether HS's own literal prefilter (Teddy/FDR) already
    /// gates the unicode-prefixed patterns for free. Returns
    /// `(full_ns_per_call, lean_ns_per_call, full_pattern_count, lean_pattern_count)`.
    #[cfg(all(test, feature = "simd"))]
    pub(crate) fn bench_hs_homoglyph_skip(
        &self,
        haystack: &str,
        n_calls: u32,
    ) -> (f64, f64, usize, usize) {
        use super::phase2::ActivePatternsScratch;
        use super::phase2_hs::Phase2HsEngine;
        let all: Vec<usize> = self.phase2_always_active_indices.clone();
        let lean_n = all
            .iter()
            .filter(|&&i| !self.phase2_patterns[i].0.homoglyph_variant)
            .count();
        // ONE engine, the production object, which now holds both the full DB and
        // the lean ASCII sub-DB. Time the two routes exactly as the hot path selects
        // them (`skip_homoglyph_ascii` false vs true).
        let engine = Phase2HsEngine::build(&self.phase2_patterns, &all).expect("HS engine");
        let mut scratch = ActivePatternsScratch::new();
        let mut time_one = |skip_homoglyph_ascii: bool| -> f64 {
            scratch.begin(self.phase2_patterns.len());
            if let Err(error) = engine.mark(haystack, &mut scratch, skip_homoglyph_ascii) {
                panic!("HS benchmark warmup failed: {error}");
            }
            let t0 = std::time::Instant::now();
            for _ in 0..n_calls {
                scratch.begin(self.phase2_patterns.len());
                if let Err(error) = engine.mark(haystack, &mut scratch, skip_homoglyph_ascii) {
                    panic!("HS benchmark trial failed: {error}");
                }
            }
            t0.elapsed().as_nanos() as f64 / n_calls as f64
        };
        let full_ns = time_one(false);
        let lean_ns = time_one(true);
        (full_ns, lean_ns, all.len(), lean_n)
    }

    /// Recall-neutrality proof for the HS homoglyph-ASCII skip: on `ascii_text`,
    /// mark once with the full DB and once with the lean ASCII DB, and return
    /// `(full_marked, lean_marked, non_homoglyph_dropped, lean_extra)`:
    ///   * `non_homoglyph_dropped`: patterns the full DB marked that the lean DB
    ///     did NOT, which are NOT homoglyph variants. MUST be empty: the lean DB may
    ///     only ever drop homoglyph variants (whose ASCII matches the base AC path
    ///     already covers), never a real pattern.
    ///   * `lean_extra`: patterns the lean DB marked that the full DB did not. MUST
    ///     be empty: lean is a strict subset, so it can never over-mark.
    /// Both empty ⇒ the lean DB differs from the full DB by EXACTLY the homoglyph
    /// variants, so on ASCII (base covers homoglyph) findings are unchanged.
    #[cfg(all(test, feature = "simd"))]
    pub(crate) fn hs_mark_full_vs_lean_diff(
        &self,
        ascii_text: &str,
    ) -> (usize, usize, Vec<usize>, Vec<usize>) {
        use super::phase2::ActivePatternsScratch;
        use super::phase2_hs::Phase2HsEngine;
        use std::collections::HashSet;
        let all: Vec<usize> = self.phase2_always_active_indices.clone();
        let engine = Phase2HsEngine::build(&self.phase2_patterns, &all).expect("HS engine");
        let mut scratch = ActivePatternsScratch::new();
        scratch.begin(self.phase2_patterns.len());
        engine
            .mark(ascii_text, &mut scratch, false)
            .expect("full mark");
        let full: HashSet<usize> = scratch.active.iter().copied().collect();
        scratch.begin(self.phase2_patterns.len());
        engine
            .mark(ascii_text, &mut scratch, true)
            .expect("lean mark");
        let lean: HashSet<usize> = scratch.active.iter().copied().collect();
        let non_homoglyph_dropped: Vec<usize> = full
            .iter()
            .copied()
            .filter(|i| !lean.contains(i) && !self.phase2_patterns[*i].0.homoglyph_variant)
            .collect();
        let lean_extra: Vec<usize> = lean.iter().copied().filter(|i| !full.contains(i)).collect();
        (full.len(), lean.len(), non_homoglyph_dropped, lean_extra)
    }

    /// Diagnostic: `(regex_source, keywords)` for every keyword-gated phase-2
    /// pattern, in phase-2 order. These are the no-literal-prefix detectors
    /// that `scan_phase2_patterns` runs over the whole chunk once their
    /// keyword fires. Used by anchor-localization analysis to classify which
    /// carry a regex-required literal that can drive a windowed (rather than
    /// whole-chunk) scan. Diagnostic surface only (not part of the scan path).
    #[cfg(test)]
    pub(crate) fn phase2_pattern_diagnostics(&self) -> Vec<(String, Vec<String>)> {
        self.phase2_patterns
            .iter()
            .map(|(p, kw)| (p.regex.as_str().to_string(), kw.clone()))
            .collect()
    }

    /// Diagnostic: family composition of the always-active (`phase2_n`) pool
    /// `(generic_entropy_count, other_count, distinct_other_ids)`.
    ///
    /// The recall-neutral decode-path perf lever (F3) rests on what `other_count`
    /// is. On decoded sub-chunks the adjudicator's decode-guard
    /// (`record_decoded_generic_entropy_suppression`) UNCONDITIONALLY suppresses
    /// every `is_generic_or_entropy_detector` finding, so marking that subset of
    /// the always-active pool during a decode rescan is pure discarded work
    /// (Law 7). If `other_count == 0`, the ENTIRE `phase2_n` prefilter can be
    /// skipped on the decode path with zero recall change; if `other_count > 0`,
    /// the skip must exclude ONLY the generic/entropy subset so the no-keyword
    /// vendor patterns (which the decode-guard KEEPS) still run. This diagnostic
    /// is the durable proof of which case holds. Diagnostic only, not on the
    /// scan path.
    #[cfg(test)]
    pub(crate) fn phase2_always_active_family_breakdown(&self) -> Phase2PoolBreakdown {
        let mut b = Phase2PoolBreakdown::default();
        for &idx in &self.phase2_always_active_indices {
            let pattern = &self.phase2_patterns[idx].0;
            let id = self.metadata_by_index[pattern.detector_index].0.as_ref();
            let generic_entropy = crate::detector_ids::is_generic_or_entropy_detector(id);
            let homoglyph = pattern.homoglyph_variant;
            match (generic_entropy, homoglyph) {
                (true, false) => b.generic_entropy_real += 1,
                (true, true) => b.generic_entropy_homoglyph += 1,
                (false, false) => {
                    b.vendor_real += 1;
                    if !b.vendor_real_ids.iter().any(|existing| existing == id) {
                        b.vendor_real_ids.push(id.to_string());
                    }
                }
                (false, true) => b.vendor_homoglyph += 1,
            }
        }
        b
    }

    /// Warm regex transition caches in parallel before scanning.
    ///
    /// Detector regexes are already builder-validated and seeded during scanner
    /// construction (see [`crate::types::LazyRegex`]), so this is now mostly
    /// DFA/transition-cache first-touch work plus generated/plain fallback
    /// regexes. For a LONG-lived or LARGE scan - the daemon, `watch`,
    /// `scan-system`, or a big repo where a detector fires across thousands of
    /// files - paying that warmup once, in parallel, avoids stalling worker
    /// threads inside the first hot source batch. Callers on those paths should
    /// `warm()` after building the scanner.
    ///
    /// Idempotent and cheap to repeat: an already-compiled pattern is a
    /// `OnceLock` hit. Also the correct setup for a per-scan perf benchmark,
    /// which means to measure match throughput, not one-time compilation.
    pub fn warm(&self) {
        use rayon::prelude::*;
        // Warm the lazy regex transition caches in parallel so the first real
        // source batch does not serialize DFA first-touch under worker load.
        const WARM_SAMPLE: &str = concat!(
            "int main(void){ char *buf = malloc(4096); for(size_t i=0;i<len;i++){ ",
            "config.timeout_ms = 30000; user_id=0x1f3b9c; const KEY = \"abcDEF0123456789\"; ",
            "https://example.org/api/v2?token=eyJhbGciOi&id=550e8400-e29b-41d4-a716; ",
            "base64=QUtJQUlPU0ZPRE5ON0VYQU1QTEU= sha=da39a3ee5e6b4b0d3255bfef95601890; ",
            "snake_case_name camelCaseName SCREAMING_CASE path/to/file.rs node_modules ",
            "} /* comment */ // trailing\n\t<xml attr='v'>text</xml> {\"json\":true,\"n\":42}"
        );
        self.ac_map.par_iter().for_each(|p| {
            let _ = p.regex.get().find(WARM_SAMPLE); // LAW10: forces lazy-static/regex eager init (warm-up); not a fallback
        });
        self.phase2_patterns.par_iter().for_each(|(p, _)| {
            let _ = p.regex.get().find(WARM_SAMPLE); // LAW10: forces lazy-static/regex eager init (warm-up); not a fallback
        });
        crate::shared_regexes::warm_runtime_regexes();
        if let Some(generic_assignment_re) = &self.generic_assignment_re {
            let _ = generic_assignment_re.find(WARM_SAMPLE); // LAW10: warm-up result is intentionally discarded; this eagerly initializes the exact regex used by later scans
        }
        crate::multiline::warm_runtime_regexes();
        crate::checksum::warm_runtime_regexes();
    }

    /// Iterator over the FINAL regex source strings (post anchoring /
    /// group extraction / normalization) the scanner uses.
    pub(crate) fn pattern_regex_strs(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(self.ac_map.len() + self.phase2_patterns.len());
        out.extend(self.ac_map.iter().map(|p| p.regex.as_str()));
        out.extend(self.phase2_patterns.iter().map(|(p, _)| p.regex.as_str()));
        out
    }

    /// Stable scanner runtime status for CLI reporting and autoroute cache
    /// invalidation. This is the public diagnostics boundary; raw corpus
    /// inspection helpers stay crate-private so tests do not grow a second
    /// production API around internal matcher layout.
    pub fn runtime_status(&self) -> CompiledScannerRuntime {
        CompiledScannerRuntime {
            detector_count: self.detector_count(),
            pattern_count: self.pattern_count(),
            detector_digest: self.detector_digest(),
            preferred_backend: self.preferred_backend_label(),
            gpu_backend: self.gpu_backend_label(),
            gpu_degrade_count: self
                .gpu_degrade_count
                .load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Cumulative count of runtime GPU dispatch failures and recall-floor
    /// faults/recoveries recorded by this scanner (via the private runtime-fault recorder). Cheap
    /// (one relaxed atomic load) so routing and calibration can reject poisoned
    /// GPU evidence without recomputing the digests in `runtime_status()`.
    pub fn gpu_degrade_count(&self) -> u64 {
        self.gpu_degrade_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Dump and reset every scanner-owned profile stream collected under the
    /// unified explicit profile switch. This is the only public
    /// boundary the CLI needs; it prevents CLI/orchestrator code from growing
    /// its own env reads for individual profiler shards.
    pub fn dump_profile_reports(&self, label: &str) {
        if !profile::enabled() {
            return;
        }
        profile::dump(label);
        self.phase2_profile_dump(label);
        self.confirmed_profile_dump(label);
    }

    pub fn reset_profile_reports(&self) {
        profile::reset();
        self.phase2_profile_reset();
        self.confirmed_profile_reset();
    }

    pub(crate) fn detector_digest(&self) -> u64 {
        let patterns = self.pattern_regex_strs();
        let mut hasher = blake3::Hasher::new();
        detector_digest_update(&mut hasher, b"domain", b"keyhog-scanner-detector-digest-v1");
        detector_digest_update_u64(&mut hasher, b"pattern_count", patterns.len() as u64);
        for src in patterns {
            detector_digest_update(&mut hasher, b"regex", src.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(bytes)
    }

    /// Identifier of the GPU backend acquired at compile time, or
    /// None if scanning routes to CPU/SIMD only. Mirrors
    /// `VyreBackend::id()` which returns "cuda", "wgpu", or the
    /// driver-defined name. The startup banner uses this so the
    /// operator can tell at a glance whether they got CUDA (the
    /// headline 5-10x faster path on NVIDIA hardware) or the WGPU
    /// fallback, rather than just "Gpu" which collapses both.
    #[must_use]
    pub(crate) fn gpu_backend_label(&self) -> Option<&'static str> {
        self.gpu_backend.as_ref().map(|b| b.id())
    }

    /// Most recent concrete GPU runtime-degrade reason for this compiled
    /// scanner, if one has occurred. Used by health probes to emit
    /// machine-readable failure causes without scraping stderr.
    #[cfg(feature = "gpu")]
    pub(crate) fn last_gpu_degrade_reason(&self) -> Option<String> {
        self.gpu_last_degrade_reason
            .lock()
            .ok() // LAW10: poisoned lock => None; read-only health/diagnostic accessor, recall-irrelevant
            .and_then(|guard| guard.clone())
    }

    /// Return the backend used by no-backend library scan APIs.
    #[must_use]
    pub(crate) fn preferred_backend_label(&self) -> &'static str {
        crate::hw_probe::ScanBackend::CpuFallback.label()
    }

    /// Warm backend resources that are initialized lazily during scanning.
    pub fn warm_backend(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        // GPU readiness means the one production on-GPU engine: GpuLiteralSet
        // region presence. Retired per-rule routes do not keep compatibility
        // identities here.
        let ready = match backend {
            crate::hw_probe::ScanBackend::Gpu => self.gpu_stack_usable(),
            crate::hw_probe::ScanBackend::SimdCpu => self.simd_backend_usable(),
            crate::hw_probe::ScanBackend::CpuFallback => true,
        };
        // Warming is a PROBE with an in-band `bool` channel: report readiness
        // honestly (`false` when a forced GPU stack is unusable) instead
        // of hard-stopping the process. This is NOT a silent fallback (Law 10)
        // the caller receives the `false` and decides. The no-silent-fallback
        // hard-stop lives where it MUST: `--require-gpu` is caught by the CLI
        // preflight (`gpu::require_gpu_preflight`) before any scan, and a forced
        // backend that reaches GPU dispatch fails closed via
        // `require_selected_backend_stack` inside `scan_with_backend`
        // (the `par_iter` closure with no `Result` channel, the ONLY place the
        // M12 process-exit is justified). Exiting here instead broke the `-> bool`
        // contract and killed the whole process (exit 12) on any GPU-less warm.
        ready
    }

    /// Scan a chunk of text and return all raw credential matches.
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        self.scan_with_deadline(chunk, self.config.per_chunk_deadline())
    }

    /// Scan a chunk using a caller-selected backend.
    ///
    /// This infallible API treats backend selection as a process contract. It
    /// terminates with exit `3` when selected SIMD is unavailable or exit `12`
    /// when a selected GPU stack or runtime dispatch cannot be honored; it
    /// never returns findings produced by another backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, self.config.per_chunk_deadline(), backend)
    }

    /// Scan multiple chunks using a caller-selected backend.
    ///
    /// This infallible API has the same hard process contract as
    /// [`Self::scan_with_backend`]: unavailable SIMD exits `3`, and unavailable
    /// or failed GPU execution exits `12` instead of substituting CPU/SIMD.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        self.require_selected_backend_stack(backend);
        profile::add_bytes(chunks.iter().map(|c| c.data.len() as u64).sum());
        profile::add_files(chunks.len() as u64);
        self.scan_chunks_with_backend_internal(chunks, backend)
    }

    /// Reset the cross-file fragment-reassembly cache.
    pub fn clear_fragment_cache(&self) {
        self.fragment_cache.clear();
    }

    /// Scan a chunk of text against all compiled detectors.
    pub(crate) fn scan_with_deadline(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        // The library default is the deterministic portable reference. Hardware
        // acceleration requires an explicit backend or the CLI's persisted
        // fastest-correct router; a library call must not invent a heuristic
        // route from host state and input size.
        self.scan_with_deadline_and_backend(
            chunk,
            deadline,
            crate::hw_probe::ScanBackend::CpuFallback,
        )
    }

    pub(crate) fn scan_with_deadline_and_backend(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        selected_backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        if crate::deadline::expired(deadline) {
            return Vec::new();
        }
        self.require_selected_backend_stack(selected_backend);
        // Direct-match prefilters: skip chunks that carry none of any
        // detector's literal bytes (`AlphabetScreen`) or bigrams (bloom). A
        // FULLY-ENCODED secret carries none of those - its plaintext prefix
        // only appears AFTER decoding - so the prefilters would drop it before
        // decode-through could recover it, silently defeating the
        // decode-through feature on encoded-only inputs. When the prefilter
        // rejects but the chunk carries a decode-shaped payload, fall through
        // to a DECODE-ONLY pass instead of skipping. Bounded: only
        // encoded-looking rejected chunks pay the decode cost, so normal
        // traffic keeps the fast skip.
        let alphabet_ok = self
            .alphabet_screen
            .as_ref()
            .is_none_or(|screen| screen.screen(chunk.data.as_bytes()));
        let bigram_ok = chunk.data.len() < super::BIGRAM_BLOOM_MIN_CHUNK_BYTES
            || self.bigram_bloom.maybe_overlaps(chunk.data.as_bytes());
        if !(alphabet_ok && bigram_ok) {
            #[cfg(feature = "simd")]
            if self.should_scan_no_hit_chunk(chunk) {
                let prepared = self.prepare_chunk(chunk);
                let triggered = if prepared.preprocessed.text.as_bytes() == chunk.data.as_bytes() {
                    Vec::new()
                } else {
                    self.collect_triggered_patterns_for_backend(
                        &prepared.preprocessed.text,
                        selected_backend,
                    )
                };
                let mut matches = self.scan_prepared_with_triggered(
                    prepared,
                    selected_backend,
                    &triggered,
                    deadline,
                    None,
                    None,
                    None,
                    None,
                );
                if crate::deadline::expired(deadline) {
                    return matches;
                }
                self.post_process_matches(chunk, &mut matches, deadline);
                return matches;
            }

            if self.chunk_needs_decode_postprocess(chunk) {
                if crate::deadline::expired(deadline) {
                    return Vec::new();
                }
                let mut matches = Vec::new();
                self.post_process_matches(chunk, &mut matches, deadline);
                return matches;
            }
            crate::telemetry::record_file_skipped();
            return Vec::new();
        }

        tracing::trace!(
            target: "keyhog::routing",
            backend = selected_backend.label(),
            chunk_bytes = chunk.data.len(),
            source_type = chunk.metadata.source_type.as_ref(),
            "scan dispatch"
        );
        let mut matches = if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
            self.scan_windowed(chunk, selected_backend, deadline)
        } else {
            self.scan_inner(chunk, selected_backend, deadline)
        };

        if crate::deadline::expired(deadline) {
            return matches;
        }
        self.post_process_matches(chunk, &mut matches, deadline);

        matches
    }
}

fn detector_digest_update(hasher: &mut blake3::Hasher, tag: &[u8], value: &[u8]) {
    hasher.update(&(tag.len() as u64).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn detector_digest_update_u64(hasher: &mut blake3::Hasher, tag: &[u8], value: u64) {
    detector_digest_update(hasher, tag, &value.to_le_bytes());
}
