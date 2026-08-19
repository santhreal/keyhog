use super::*;
use crate::hw_probe::ScanBackend;

/// Every early return driven by `--per-chunk-timeout-ms` hands back a short (often
/// empty) match set for a chunk whose tail was never matched. That empty set reads as
/// "nothing found", so the abort is counted here and surfaced by the CLI as the
/// `ScannerChunkDeadlineAbort` FAIL-class coverage gap; a deadline-truncated scan can
/// never report as complete.
#[inline]
fn scan_deadline_expired(deadline: Option<std::time::Instant>) -> bool {
    let expired = crate::deadline::expired(deadline);
    if expired {
        crate::telemetry::record_chunk_deadline_abort();
    }
    expired
}

fn backend_driver_name(backend: ScanBackend) -> &'static str {
    match backend {
        ScanBackend::GpuCuda => "cuda",
        ScanBackend::GpuMetal => "metal",
        ScanBackend::GpuWgpu => "wgpu",
        _ => "",
    }
}

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
    /// Configured recall-equivalent route used when a caller does not provide
    /// workload-specific autoroute evidence.
    #[must_use]
    pub fn default_execution_route(&self) -> crate::ScanExecutionRoute {
        self.execution_route_for_backend(ScanBackend::CpuFallback)
    }

    #[must_use]
    pub fn execution_route_for_backend(&self, backend: ScanBackend) -> crate::ScanExecutionRoute {
        crate::ScanExecutionRoute {
            decode_backend: if backend.is_gpu() {
                ScanBackend::CpuFallback
            } else {
                backend
            },
            phase2_plain_localizer: self.tuning.phase2_plain_localizer_enabled(),
            phase2_keyword_localizer: true,
            gpu_pipeline_depth: 1,
        }
    }

    /// Compile the immutable GPU literal and phase-2 programs once for an
    /// autoroute sweep and remember their measured one-time costs. Per-workload
    /// calibration retains those programs while composing their costs into
    /// every matching GPU one-shot observation.
    pub fn prepare_autoroute_calibration_gpu_artifact(&self) -> std::result::Result<(), String> {
        let eligible_gpu = self
            .gpu_backend_candidates()
            .into_iter()
            .filter(|candidate| candidate.is_eligible())
            .collect::<Vec<_>>();
        if eligible_gpu.is_empty() {
            self.autoroute_gpu_shared_cold_ns
                .store(0, std::sync::atomic::Ordering::Relaxed);
            return Ok(());
        }
        if self.gpu_matcher().is_none() {
            return Err(
                "eligible GPU peers exist but the shared literal program could not be prepared"
                    .to_string(),
            );
        }
        if self
            .autoroute_gpu_shared_cold_ns
            .load(std::sync::atomic::Ordering::Acquire)
            == 0
        {
            return Err(
                "the shared GPU literal program initialized without recording its preparation duration"
                    .to_string(),
            );
        }
        #[cfg(feature = "gpu")]
        for candidate in eligible_gpu {
            let backend_id = candidate.driver_id.ok_or_else(|| {
                "eligible GPU peer has no driver identity during phase-2 preparation".to_string()
            })?;
            let _catalog = self.phase2_gpu_dfa_catalog(Some(backend_id));
            if self.phase2_gpu_dfa.preparation_ns(Some(backend_id)) == 0 {
                return Err(format!(
                    "the {backend_id} phase-2 GPU program initialized without recording its preparation duration"
                ));
            }
        }
        Ok(())
    }

    /// Materialize the SIMD peer and preserve its exact initialization error.
    pub fn initialize_simd_backend(&self) -> std::result::Result<(), String> {
        self.try_initialize_simd_backend().map_err(str::to_owned)
    }

    /// One-time Hyperscan materialization cost recorded by this scanner.
    #[must_use]
    pub fn simd_initialization_ns(&self) -> Option<u128> {
        #[cfg(feature = "simd")]
        {
            let ns = self
                .simd_initialization_ns
                .load(std::sync::atomic::Ordering::Acquire);
            return (self.simd_backend_initialized() && ns > 0).then_some(ns as u128);
        }
        #[cfg(not(feature = "simd"))]
        {
            None
        }
    }

    /// Reset workload-shaped GPU state while retaining immutable literal and
    /// phase-2 programs whose measured preparation costs are composed into cold
    /// evidence.
    pub fn reset_autoroute_calibration_gpu_workload(&self) -> std::result::Result<(), String> {
        #[cfg(feature = "gpu")]
        {
            self.reset_gpu_resident_literal_for_calibration()?;
        }
        Ok(())
    }

    #[must_use]
    pub fn autoroute_calibration_gpu_shared_cold_ns(&self) -> u128 {
        self.autoroute_gpu_shared_cold_ns
            .load(std::sync::atomic::Ordering::Acquire) as u128
    }

    /// Measured one-time phase-2 program preparation cost for an eligible GPU
    /// backend. `None` means the backend is not eligible or was not prepared.
    #[must_use]
    pub fn autoroute_calibration_gpu_backend_cold_ns(&self, backend: ScanBackend) -> Option<u128> {
        #[cfg(feature = "gpu")]
        {
            let candidate = self
                .gpu_backend_candidates()
                .into_iter()
                .find(|candidate| candidate.backend == backend && candidate.is_eligible())?;
            let preparation_ns = self.phase2_gpu_dfa.preparation_ns(candidate.driver_id);
            return (preparation_ns > 0).then_some(preparation_ns);
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _backend = backend;
            None
        }
    }

    /// Materialize and return the exact phase-one Hyperscan backend.
    #[cfg(feature = "simd")]
    pub(crate) fn try_simd_prefilter(
        &self,
    ) -> std::result::Result<&crate::engine::SimdPhase1Prefilter, &str> {
        if !self.simd_candidate_available {
            return Err("the detector corpus produced no Hyperscan phase-one plan");
        }
        self.simd_prefilter
            .get_or_init(|| {
                let cold =
                    keyhog_profile::decision_timer(keyhog_profile::Stage::AutorouteCalibration);
                let plan = self
                    .simd_compile_plan
                    .lock()
                    .map_err(|_| "Hyperscan compile-plan lock was poisoned".to_string())?
                    .take()
                    .ok_or_else(|| "Hyperscan compile plan was already consumed".to_string())?;
                let result = plan.materialize();
                self.simd_initialization_ns.store(
                    u64::try_from(cold.finish().as_nanos())
                        // LAW10: reporting-only telemetry saturation preserves monotonic timing without changing scan execution or findings.
                        .unwrap_or(u64::MAX)
                        .max(1),
                    std::sync::atomic::Ordering::Release,
                );
                result
            })
            .as_ref()
            .map_err(String::as_str)
    }

    pub(crate) fn try_initialize_simd_backend(&self) -> std::result::Result<(), &str> {
        #[cfg(feature = "simd")]
        {
            self.try_simd_prefilter().map(|_| ())
        }
        #[cfg(not(feature = "simd"))]
        {
            Err("this scanner build has no Hyperscan/SIMD backend")
        }
    }

    /// Whether this scanner has a backend-neutral SIMD candidate plan.
    /// This census does not materialize a Hyperscan database.
    #[must_use]
    pub fn simd_backend_available(&self) -> bool {
        #[cfg(feature = "simd")]
        {
            self.simd_candidate_available
        }
        #[cfg(not(feature = "simd"))]
        {
            false
        }
    }

    /// Whether this process has successfully materialized the SIMD candidate.
    #[must_use]
    pub fn simd_backend_initialized(&self) -> bool {
        #[cfg(feature = "simd")]
        {
            self.simd_prefilter
                .get()
                .is_some_and(std::result::Result::is_ok)
        }
        #[cfg(not(feature = "simd"))]
        {
            false
        }
    }

    /// Number of loaded detectors.
    pub fn detector_count(&self) -> usize {
        self.detector_plans.len()
    }

    /// Resolve overlapping findings with the exact detector corpus compiled
    /// into this scanner. Reporting service names never select execution or
    /// resolution semantics, and an unknown finding identity is an error.
    pub fn try_resolve_matches(
        &self,
        matches: Vec<keyhog_core::RawMatch>,
    ) -> std::result::Result<Vec<keyhog_core::RawMatch>, String> {
        crate::resolution::try_resolve_matches_with_compiled_plan(matches, &self.detector_plans)
    }

    /// Pre-interned `(detector_id, detector_name, service)` triple for the
    /// detector at `detector_index`. Three `Arc::clone`s, zero hashing, the
    /// hot-path replacement for three `ScanState::intern_metadata` calls on
    /// frozen detector metadata (PERF-locality_intern-1). Returns byte-for-byte
    /// the same `Arc<str>` values `static_intern.lookup(...)` would, because
    /// they ARE the same arena entries, so emitted findings are unchanged.
    #[cfg(test)]
    #[inline]
    pub(crate) fn interned_detector_metadata(
        &self,
        detector_index: usize,
    ) -> (Arc<str>, Arc<str>, Arc<str>) {
        self.detector_plans.get(detector_index).cloned_metadata()
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
        scratch
            .begin(self.phase2_patterns.len())
            .expect("scratch begin");
        prefilter.mark_matches(
            &self.phase2_patterns,
            text,
            &mut scratch,
            false,
            false,
            &tuning,
            true,
        );
        // Timed loop.
        let t0 = std::time::Instant::now();
        for _ in 0..n_calls {
            scratch
                .begin(self.phase2_patterns.len())
                .expect("scratch begin");
            prefilter.mark_matches(
                &self.phase2_patterns,
                text,
                &mut scratch,
                false,
                false,
                &tuning,
                true,
            );
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
        use super::Phase2HsEngine;
        let all = &self.phase2_always_active_indices;
        let lean_n = all
            .iter()
            .filter(|&&i| !self.phase2_patterns[i].0.homoglyph_variant)
            .count();
        // ONE engine, the production object, which now holds both the full DB and
        // the lean ASCII sub-DB. Time the two routes exactly as the hot path selects
        // them (`skip_homoglyph_ascii` false vs true).
        let engine = Phase2HsEngine::build(&self.phase2_patterns, &all)
            .expect("HS engine build")
            .expect("HS engine");
        let mut scratch = ActivePatternsScratch::new();
        let mut time_one = |skip_homoglyph_ascii: bool| -> f64 {
            scratch
                .begin(self.phase2_patterns.len())
                .expect("scratch begin");
            if let Err(error) = engine.mark(haystack, &mut scratch, skip_homoglyph_ascii) {
                panic!("HS benchmark warmup failed: {error}");
            }
            let t0 = std::time::Instant::now();
            for _ in 0..n_calls {
                scratch
                    .begin(self.phase2_patterns.len())
                    .expect("scratch begin");
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
        use super::Phase2HsEngine;
        use std::collections::HashSet;
        let all = &self.phase2_always_active_indices;
        let engine = Phase2HsEngine::build(&self.phase2_patterns, &all)
            .expect("HS engine build")
            .expect("HS engine");
        let mut scratch = ActivePatternsScratch::new();
        scratch
            .begin(self.phase2_patterns.len())
            .expect("scratch begin");
        engine
            .mark(ascii_text, &mut scratch, false)
            .expect("full mark");
        let full: HashSet<usize> = scratch.active.iter().copied().collect();
        scratch
            .begin(self.phase2_patterns.len())
            .expect("scratch begin");
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
    /// The decode guard suppresses entropy-only findings, but detector-owned
    /// phase-2 generic assignments remain recall-bearing when their keyword
    /// survives decoding. This diagnostic therefore reports composition only;
    /// it must never justify skipping the generic pool wholesale.
    #[cfg(test)]
    pub(crate) fn phase2_always_active_family_breakdown(&self) -> Phase2PoolBreakdown {
        let mut b = Phase2PoolBreakdown::default();
        for &idx in &self.phase2_always_active_indices {
            let pattern = &self.phase2_patterns[idx].0;
            let id = self
                .detector_plans
                .get(pattern.detector_index)
                .metadata
                .0
                .as_ref();
            let generic_entropy = matches!(
                self.detector_plans.resolution_class(id),
                Some(
                    crate::detector_plan::DetectorResolutionClass::Generic
                        | crate::detector_plan::DetectorResolutionClass::Entropy
                )
            );
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

    /// Warm the scanner's SHARED runtime regexes before scanning.
    ///
    /// These are the handful of process-wide matchers every chunk touches
    /// regardless of which detectors fire: the multiline structural regexes,
    /// the shared assignment regex, and the generic-assignment value bridge.
    /// They are worth building up front because the first chunk pays them
    /// serially otherwise.
    ///
    /// It deliberately does NOT force-compile the per-detector patterns. Doing
    /// that materialized a compiled `Regex` for every pattern, companion and
    /// generated homoglyph variant in the corpus (~450 MB) on every
    /// invocation, including one-shot single-file and pre-commit scans
    /// that reach a handful of detectors, and it made resident memory scale
    /// with corpus size instead of workload. Detector patterns are validated at
    /// construction and compiled on the first chunk that reaches them (see
    /// [`crate::types::LazyRegex`]), so the work still happens once per
    /// pattern, in parallel across whichever workers need it, and only for the
    /// patterns the scan actually uses.
    ///
    /// Idempotent and cheap to repeat: every target is a `OnceLock` hit after
    /// the first call.
    pub fn warm(&self) {
        // A sample carrying the assignment / URL / structural shapes the shared
        // matchers key on, so warming touches their transition caches and not
        // just their construction.
        const WARM_SAMPLE: &str = concat!(
            "int main(void){ char *buf = malloc(4096); for(size_t i=0;i<len;i++){ ",
            "config.timeout_ms = 30000; user_id=0x1f3b9c; const KEY = \"abcDEF0123456789\"; ",
            "https://example.org/api/v2?payload=eyJhbGciOi&id=550e8400-e29b-41d4-a716; ",
            "base64=QUtJQUlPU0ZPRE5ON0VYQU1QTEU= sha=da39a3ee5e6b4b0d3255bfef95601890; ",
            "snake_case_name camelCaseName SCREAMING_CASE path/to/file.rs node_modules ",
            "} /* comment */ // trailing\n\t<xml attr='v'>text</xml> {\"json\":true,\"n\":42}"
        );
        crate::shared_regexes::warm_runtime_regexes();
        if let Some(generic_assignment) = self.detector_plans.generic_assignment() {
            let _ = generic_assignment.matcher().find(WARM_SAMPLE); // LAW10: warm-up result is intentionally discarded; this eagerly initializes the exact regex used by later scans
        }
        crate::multiline::warm_runtime_regexes();
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
            compiled_plan_digest: self.compiled_plan_digest,
            preferred_backend: self.preferred_backend_label(),
            gpu_backends: self.backend_state.gpu_availability(),
            gpu_degrade_count: self.gpu_degrade_count(),
        }
    }

    /// Return the evidence plan after compilation has resolved capture selection,
    /// compatibility fields, detector targets, and dependency constraints.
    ///
    /// This allocates only on explicit introspection calls. Scan paths never
    /// construct this diagnostic projection.
    #[must_use]
    pub fn compiled_evidence_plan(&self, detector_id: &str) -> Option<CompiledEvidencePlan<'_>> {
        let plan = self.detector_plans.find_by_id(detector_id)?;
        let relations = plan
            .companions
            .iter()
            .map(|relation| CompiledEvidenceRelation {
                name: relation.name.as_ref(),
                regex: relation.regex.as_str(),
                capture_group: relation.capture_group,
                within_lines: relation.within_lines,
                within_bytes: relation.within_bytes,
                direction: relation.direction,
                scope: relation.scope,
                requirement: relation.requirement,
                value_relation: relation.value_relation,
            })
            .collect();
        let detector_relations = self
            .detector_plans
            .detector_relations(detector_id)
            .iter()
            .map(|relation| CompiledDetectorEvidenceRelation {
                detector_id: relation.detector_id.as_ref(),
                kind: relation.kind,
                within_lines: relation.within_lines,
                within_bytes: relation.within_bytes,
                direction: relation.direction,
            })
            .collect();
        Some(CompiledEvidencePlan {
            detector_id: plan.metadata.0.as_ref(),
            relations,
            detector_relations,
        })
    }
    /// Build-time Layer-0.5 bigram-prefilter density and health.
    ///
    /// This performs one 1024-word population-count pass on explicit status
    /// requests. It is never called from the per-chunk scan path.
    #[must_use]
    pub fn bigram_prefilter_status(&self) -> crate::bigram_bloom::BigramPrefilterStatus {
        self.route_classification.bigram_bloom.status()
    }

    /// Measure Layer-0.5 rejection over one explicitly named diagnostic corpus.
    ///
    /// Inputs are borrowed and walked without collection. Saturated or invalid
    /// filters are fail-open and therefore report zero rejected inputs.
    #[must_use]
    pub fn bigram_prefilter_corpus_status<'a, I>(
        &self,
        corpus_name: &'a str,
        inputs: I,
    ) -> crate::bigram_bloom::BigramPrefilterCorpusStatus<'a>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        self.route_classification.bigram_bloom.corpus_status(
            corpus_name,
            inputs,
            crate::engine::BIGRAM_BLOOM_MIN_CHUNK_BYTES,
        )
    }

    /// Cumulative count of scanner-local VYRE region-dispatch failures.
    ///
    /// Request-scoped recovery evidence is returned on `CoalescedScanOutcome`
    /// and cannot affect another concurrent request.
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
        self.detector_digest
    }

    /// GPU peers retained by this scanner's backend state.
    #[must_use]
    pub fn gpu_backend_candidates(&self) -> Vec<GpuBackendCandidateStatus> {
        use crate::hw_probe::ScanBackend;
        self.backend_state
            .gpu_candidate_backends()
            .map(|backend| {
                let available = self.backend_state.gpu_backend_available(backend);
                GpuBackendCandidateStatus {
                    backend,
                    available,
                    acquired: self.backend_state.gpu_backend_acquired(backend),
                    driver_id: available.then(|| backend_driver_name(backend)),
                    driver_version: available.then(|| match backend {
                        ScanBackend::GpuCuda => env!("KEYHOG_VYRE_CUDA_VERSION"),
                        ScanBackend::GpuMetal => env!("KEYHOG_VYRE_METAL_VERSION"),
                        ScanBackend::GpuWgpu => env!("KEYHOG_VYRE_WGPU_VERSION"),
                        _ => unreachable!("candidate state contains only GPU backends"),
                    }),
                    device_identity: self.backend_state.gpu_backend_device_identity(backend),
                    runtime_identity: self.backend_state.gpu_backend_runtime_identity(backend),
                    is_software: self.backend_state.gpu_backend_is_software(backend),
                    acquisition_error: self
                        .backend_state
                        .gpu_backend_initialization_error(backend)
                        .map(str::to_owned),
                }
            })
            .collect()
    }

    /// Materialize one GPU route and return the identity of the exact peer that
    /// will execute it. Autoroute persists this value with timing evidence.
    pub fn acquired_gpu_peer_identity(
        &self,
        backend: crate::hw_probe::ScanBackend,
    ) -> std::result::Result<String, String> {
        if !backend.is_gpu() {
            return Err(format!("{} is not a GPU backend", backend.label()));
        }
        if !self.warm_backend(backend) {
            return Err(self.gpu_backend_unavailable_reason(backend));
        }
        let candidate = self
            .gpu_backend_candidates()
            .into_iter()
            .find(|candidate| candidate.backend == backend)
            .ok_or_else(|| format!("{} is not a compiled GPU peer", backend.label()))?;
        if !candidate.acquired || !candidate.available || candidate.is_software {
            return Err(self.gpu_backend_unavailable_reason(backend));
        }
        let (Some(driver_id), Some(driver_version), Some(device_identity), Some(runtime_identity)) = (
            candidate
                .driver_id
                .as_deref()
                .filter(|value| !value.trim().is_empty()),
            candidate
                .driver_version
                .as_deref()
                .filter(|value| !value.trim().is_empty()),
            candidate
                .device_identity
                .as_deref()
                .filter(|value| !value.trim().is_empty()),
            candidate
                .runtime_identity
                .as_deref()
                .filter(|value| !value.trim().is_empty()),
        ) else {
            let missing = [
                (
                    "driver_id",
                    candidate
                        .driver_id
                        .as_deref()
                        .is_none_or(|value| value.trim().is_empty()),
                ),
                (
                    "driver_version",
                    candidate
                        .driver_version
                        .as_deref()
                        .is_none_or(|value| value.trim().is_empty()),
                ),
                (
                    "device_identity",
                    candidate
                        .device_identity
                        .as_deref()
                        .is_none_or(|value| value.trim().is_empty()),
                ),
                (
                    "runtime_identity",
                    candidate
                        .runtime_identity
                        .as_deref()
                        .is_none_or(|value| value.trim().is_empty()),
                ),
            ]
            .into_iter()
            .filter_map(|(field, absent)| absent.then_some(field))
            .collect::<Vec<_>>()
            .join(", ");
            return Err(format!(
                "{} reported acquired eligibility with missing identity fields: {missing}; reinitialize the GPU backend and recalibrate autoroute",
                backend.label()
            ));
        };
        let identity = (
            candidate.backend.label(),
            driver_id,
            driver_version,
            device_identity,
            runtime_identity,
        );
        serde_json::to_string(&identity)
            .map_err(|error| format!("GPU peer identity serialization failed: {error}"))
    }

    pub(crate) fn gpu_backend_unavailable_reason(
        &self,
        backend: crate::hw_probe::ScanBackend,
    ) -> String {
        let Some(candidate) = self
            .gpu_backend_candidates()
            .into_iter()
            .find(|candidate| candidate.backend == backend)
        else {
            return format!("{} is not a compiled GPU peer", backend.label());
        };
        if let Some(error) = candidate.acquisition_error {
            return format!(
                "{} execution backend initialization failed: {error}",
                backend.label()
            );
        }
        if !candidate.available {
            return format!(
                "{} is absent from the current hardware peer census",
                backend.label()
            );
        }
        if !candidate.has_complete_identity() {
            return format!(
                "{} has incomplete driver, device, or runtime identity",
                backend.label()
            );
        }
        if candidate.acquired {
            return format!("{} execution backend initialized", backend.label());
        }
        format!(
            "{} did not publish an initialized execution handle",
            backend.label()
        )
    }

    /// Most recent concrete GPU runtime-degrade reason for this compiled
    /// scanner, if one has occurred. Used by health probes to emit
    /// machine-readable failure causes without scraping stderr.
    #[cfg(feature = "gpu")]
    pub(crate) fn last_gpu_degrade_reason(&self) -> Option<String> {
        match self.gpu_last_degrade_reason.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => match poisoned.into_inner().clone() {
                Some(reason) => Some(format!(
                    "GPU runtime diagnostic lock was poisoned after recording: {reason}"
                )),
                None => Some(
                    "GPU runtime degradation occurred, but its diagnostic lock was poisoned"
                        .to_owned(),
                ),
            },
        }
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
            crate::hw_probe::ScanBackend::GpuCuda
            | crate::hw_probe::ScanBackend::GpuMetal
            | crate::hw_probe::ScanBackend::GpuWgpu => self.gpu_stack_usable_for(backend),
            crate::hw_probe::ScanBackend::SimdCpu => {
                #[cfg(feature = "simd")]
                {
                    match self.try_simd_prefilter() {
                        Ok(prefilter) => prefilter.scanner().warm().is_ok(),
                        Err(_) => false, // LAW10: this operator-visible bool is the honest resource status; warm_backend never begins a scan.
                    }
                }
                #[cfg(not(feature = "simd"))]
                {
                    false
                }
            }
            crate::hw_probe::ScanBackend::CpuFallback => true,
        };
        // Warming is a probe with an in-band `bool` channel: `false` honestly
        // reports unavailable resources. Selected-backend scans use a separate
        // API and return `ScanError` for initialization or dispatch failures.
        ready
    }

    /// Scan a chunk on the deterministic portable backend.
    ///
    /// Runtime failures return `ScanError` and never terminate the host.
    pub fn scan(&self, chunk: &Chunk) -> crate::error::Result<Vec<RawMatch>> {
        self.scan_with_deadline(chunk, self.config.per_chunk_deadline())
    }

    /// Scan a chunk using exactly the caller-selected backend.
    ///
    /// Backend initialization and runtime dispatch failures return `ScanError`;
    /// this library boundary never terminates the embedding process or invents
    /// a clean empty scan for a failed backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> crate::error::Result<Vec<RawMatch>> {
        let results = self.scan_coalesced_with_backend_and_admission(
            std::slice::from_ref(chunk),
            backend,
            None,
        )?;
        results.into_iter().next().ok_or_else(|| {
            crate::error::ScanError::Config(
                "single-chunk backend dispatch returned no result row".to_owned(),
            )
        })
    }

    /// Scan one chunk with optional reusable admission evidence.
    ///
    /// The outcome retains an exact recovery receipt when mismatched admission
    /// evidence is discarded and recomputed by the shared coalesced boundary.
    /// Backend failures return `ScanError` without terminating the host.
    pub fn scan_with_backend_and_admission_plan(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&crate::engine::Phase1AdmissionPlan>,
    ) -> crate::error::Result<crate::engine::CoalescedScanOutcome> {
        self.scan_coalesced_with_backend_admission_route_and_recovery(
            std::slice::from_ref(chunk),
            backend,
            plan,
            self.execution_route_for_backend(backend),
            false,
        )
    }
    /// Scan a single chunk with concurrent pipeline partitioning across `worker_count` workers.
    /// Preserves seam safety and finding determinism across chunk partition boundaries.
    pub fn scan_chunk_partitioned(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        worker_count: usize,
    ) -> crate::error::Result<Vec<RawMatch>> {
        crate::pipeline::scan_chunk_partitioned(self, chunk, backend, worker_count)
    }

    /// Scan multiple chunks using exactly the caller-selected backend.
    ///
    /// Backend initialization and runtime dispatch failures return `ScanError`;
    /// successful results preserve one output row per input chunk.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> crate::error::Result<Vec<Vec<RawMatch>>> {
        self.scan_coalesced_with_backend_and_admission(chunks, backend, None)
    }

    /// Scan multiple chunks with the bigram gate explicitly bypassed.
    ///
    /// This diagnostic-only oracle preserves the alphabet screen, selected
    /// backend, and all downstream matching. Comparing its result with
    /// [`Self::scan_chunks_with_backend`] proves whether bigram rejection
    /// changed any finding identity or location.
    pub fn scan_chunks_with_backend_bypassing_bigram_for_diagnostics(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> crate::error::Result<Vec<Vec<RawMatch>>> {
        let plan = self.phase1_admission_plan_bypassing_bigram_for_diagnostics(chunks);
        self.scan_coalesced_with_backend_and_admission(chunks, backend, Some(&plan))
    }

    /// Reset the cross-file fragment-reassembly cache.
    pub fn clear_fragment_cache(&self) {
        self.fragment_cache.clear();
        // In-place config mutations (tests / advanced callers) pair with this
        // clear; drop the cached entropy digest so absence keys track live policy.
        *self.entropy_config_digest_cache.lock() = None;
    }

    /// Scan a chunk of text against all compiled detectors.
    pub(crate) fn scan_with_deadline(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> crate::error::Result<Vec<RawMatch>> {
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
    ) -> crate::error::Result<Vec<RawMatch>> {
        self.scan_with_deadline_and_backend_and_admission(chunk, deadline, selected_backend, None)
    }
    pub(crate) fn scan_with_deadline_and_backend_and_admission(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        selected_backend: crate::hw_probe::ScanBackend,
        admission: Option<crate::engine::Phase1Admission>,
    ) -> crate::error::Result<Vec<RawMatch>> {
        self.scan_with_deadline_and_backend_admission_and_route(
            chunk,
            deadline,
            selected_backend,
            admission,
            self.execution_route_for_backend(selected_backend),
        )
    }

    pub(crate) fn scan_with_deadline_and_backend_admission_and_route(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        selected_backend: crate::hw_probe::ScanBackend,
        admission: Option<crate::engine::Phase1Admission>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        self.scan_with_deadline_and_backend_admission_route_and_hints(
            chunk,
            deadline,
            selected_backend,
            admission,
            false,
            false,
            None,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
            route,
        )
    }

    pub(crate) fn scan_proven_direct_absence(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
        decoder_absence: bool,
    ) -> crate::error::Result<Vec<RawMatch>> {
        crate::telemetry::record_file_scanned(chunk.data.len());
        self.record_decode_size_decline(chunk);
        #[cfg(debug_assertions)]
        self.direct_scan_absence_skipped_bytes.fetch_add(
            // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
            u64::try_from(chunk.data.len()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        let mut matches = Vec::new();
        self.post_process_matches_with_decoder_absence(
            chunk,
            &mut matches,
            deadline,
            route,
            decoder_absence,
        )?;
        Ok(matches)
    }

    pub(crate) fn scan_with_deadline_and_backend_admission_route_and_hints(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        selected_backend: crate::hw_probe::ScanBackend,
        admission: Option<crate::engine::Phase1Admission>,
        normalization_passthrough: bool,
        multiline_absence: bool,
        line_context_index: Option<&std::sync::Arc<crate::context::LineContextIndex>>,
        confirmed_patterns_absence: bool,
        entropy_absence: bool,
        decoder_absence: bool,
        direct_scan_absence: bool,
        cpu_trigger_hints: Option<&[u64]>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_evidence: Option<
            crate::engine::phase2::Phase2AlwaysActiveGpuEvidence<'_>,
        >,
        generic_keyword_positions: Option<&[u32]>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        if scan_deadline_expired(deadline) {
            return Ok(Vec::new());
        }
        if let Some(materialized) = self.selected_backend() {
            if materialized != selected_backend {
                return Err(crate::error::ScanError::BackendPlanMismatch {
                    materialized: materialized.label(),
                    requested: selected_backend.label(),
                });
            }
        }
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
        // LAW10: recall-preserving; `None` computes the identical admission predicate once rather than changing routes or findings.
        let admission = admission.unwrap_or_else(|| self.phase1_admission(chunk.data.as_bytes()));
        if admission == Phase1Admission::Admitted
            && direct_scan_absence
            && crate::structured::preprocessing_is_impossible_for_path(
                chunk.metadata.path.as_deref(),
            )
        {
            return self.scan_proven_direct_absence(chunk, deadline, route, decoder_absence);
        }
        if admission != Phase1Admission::Admitted {
            if chunk.metadata.decoded_span.is_none()
                && chunk.metadata.source_type.as_ref() == "filesystem/windowed"
                && crate::engine::vocab_previously_clean(
                    &self.vocab_stage_absence_cache,
                    self.detector_digest,
                    self.entropy_evidence_config_digest(),
                    crate::engine::vocab_path_class(
                        chunk.metadata.source_type.as_ref(),
                        chunk.metadata.path.as_deref(),
                    ),
                    &chunk.data,
                )
            {
                // Matcher stages are proven empty; still decode-through.
                if self.chunk_needs_decode_postprocess_with_absence(chunk, decoder_absence) {
                    let mut matches = Vec::new();
                    self.post_process_matches_with_decoder_absence(
                        chunk,
                        &mut matches,
                        deadline,
                        route,
                        decoder_absence,
                    )?;
                    return Ok(matches);
                }
                crate::telemetry::record_file_skipped();
                return Ok(Vec::new());
            }
            if self.should_scan_no_hit_chunk(chunk, route) {
                let prepared = self.prepare_chunk_with_normalization_passthrough(
                    chunk,
                    normalization_passthrough,
                    multiline_absence,
                    line_context_index,
                );
                let mut matches = self.scan_prepared_with_triggered(
                    prepared,
                    &[],
                    deadline,
                    false,
                    entropy_absence,
                    phase2_keyword_hints,
                    phase2_always_active_evidence,
                    None,
                    generic_keyword_positions,
                    selected_backend,
                    route,
                )?;
                if scan_deadline_expired(deadline) {
                    return Ok(matches);
                }
                self.post_process_matches_with_decoder_absence(
                    chunk,
                    &mut matches,
                    deadline,
                    route,
                    decoder_absence,
                )?;
                if scan_deadline_expired(deadline) {
                    return Ok(matches);
                }
                return Ok(matches);
            }

            if self.chunk_needs_decode_postprocess_with_absence(chunk, decoder_absence) {
                if scan_deadline_expired(deadline) {
                    return Ok(Vec::new());
                }
                let mut matches = Vec::new();
                self.post_process_matches_with_decoder_absence(
                    chunk,
                    &mut matches,
                    deadline,
                    route,
                    decoder_absence,
                )?;
                if scan_deadline_expired(deadline) {
                    return Ok(matches);
                }
                return Ok(matches);
            }
            crate::telemetry::record_file_skipped();
            return Ok(Vec::new());
        }

        tracing::trace!(
            target: "keyhog::routing",
            backend = selected_backend.label(),
            chunk_bytes = chunk.data.len(),
            source_type = chunk.metadata.source_type.as_ref(),
            "scan dispatch"
        );
        let mut matches = if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
            self.scan_windowed(chunk, selected_backend, deadline, route)?
        } else {
            self.scan_inner_with_admission_hints(
                chunk,
                selected_backend,
                deadline,
                normalization_passthrough,
                multiline_absence,
                line_context_index,
                confirmed_patterns_absence,
                entropy_absence,
                cpu_trigger_hints,
                phase2_keyword_hints,
                phase2_always_active_evidence,
                generic_keyword_positions,
                route,
            )?
        };

        if scan_deadline_expired(deadline) {
            return Ok(matches);
        }
        self.post_process_matches_with_decoder_absence(
            chunk,
            &mut matches,
            deadline,
            route,
            decoder_absence,
        )?;
        if scan_deadline_expired(deadline) {
            return Ok(matches);
        }

        Ok(matches)
    }
}
