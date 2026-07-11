use super::*;
use crate::hw_probe::ScanBackend;

static SIMD_AUTO_DEGRADE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
static GPU_AUTO_DEGRADE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

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

    pub(crate) fn warn_gpu_auto_degrade(&self, selected_backend: ScanBackend, context: &str) {
        if GPU_AUTO_DEGRADE_WARNED.set(()).is_ok() {
            eprintln!(
                "keyhog: {} auto-selected but this scanner has no live GPU stack ({context}); \
routing this automatic scan through {}. Forced GPU backends still fail closed.",
                selected_backend.label(),
                self.live_cpu_backend().label()
            );
        }
        tracing::warn!(
            target: "keyhog::routing",
            backend = selected_backend.label(),
            fallback = self.live_cpu_backend().label(),
            %context,
            "GPU backend auto-selected but scanner GPU stack is unavailable; automatic route changed to live CPU tier"
        );
    }

    fn resolve_backend_for_scan(
        &self,
        requested_backend: Option<ScanBackend>,
        chunk_bytes: u64,
    ) -> ScanBackend {
        let selected_backend = match requested_backend {
            Some(backend) => backend,
            None => self.select_backend_for_file(chunk_bytes),
        };
        if selected_backend == ScanBackend::SimdCpu && !self.simd_backend_usable() {
            crate::process_exit::backend_unavailable(
                "simd-regex selected but the SIMD/Hyperscan prefilter is unavailable; \
silent cpu-fallback execution is forbidden. Run `keyhog backend --self-test` or choose \
`--backend cpu-fallback` explicitly.",
            );
        }
        selected_backend
    }

    /// Exit before a caller-selected backend can silently run a different path.
    pub(crate) fn deny_silent_selected_backend_degrade(&self, backend: ScanBackend) {
        if backend == ScanBackend::SimdCpu && !self.simd_backend_usable() {
            crate::process_exit::backend_unavailable(
                "simd-regex selected but the SIMD/Hyperscan prefilter is unavailable; \
silent cpu-fallback execution is forbidden. Run `keyhog backend --self-test` or choose \
`--backend cpu-fallback` explicitly.",
            );
        }
        gpu_forced::deny_silent_gpu_degrade(self, backend);
    }

    /// Number of loaded detectors.
    pub(crate) fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    /// Pre-interned `(detector_id, detector_name, service)` triple for the
    /// detector at `detector_index`. Three `Arc::clone`s, zero hashing — the
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

    /// Diagnostic: `(phase2_total, always_active, always_active_eligible)` —
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

    /// Diagnostic: `(regex_source, keywords)` for every keyword-gated phase-2
    /// pattern, in phase-2 order. These are the no-literal-prefix detectors
    /// that `scan_phase2_patterns` runs over the whole chunk once their
    /// keyword fires. Used by anchor-localization analysis to classify which
    /// carry a regex-required literal that can drive a windowed (rather than
    /// whole-chunk) scan. Diagnostic surface only — not part of the scan path.
    #[cfg(test)]
    pub(crate) fn phase2_pattern_diagnostics(&self) -> Vec<(String, Vec<String>)> {
        self.phase2_patterns
            .iter()
            .map(|(p, kw)| (p.regex.as_str().to_string(), kw.clone()))
            .collect()
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
        phase2_generic::warm_generic_assignment_runtime();
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

    /// Cumulative count of runtime GPU dispatch degrades recorded by this
    /// scanner. This relaxed atomic load lets benchmarks and dispatch reporting
    /// distinguish real GPU execution from a loud CPU degradation without
    /// rebuilding the full runtime-status digest.
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

    /// Return the preferred backend for a file of the given size.
    #[must_use]
    pub(crate) fn select_backend_for_file(&self, file_size: u64) -> crate::hw_probe::ScanBackend {
        let selected = crate::hw_probe::select_backend_for_file(
            crate::hw_probe::probe_hardware(),
            file_size,
            self.pattern_count(),
        );
        if matches!(
            selected,
            crate::hw_probe::ScanBackend::Gpu | crate::hw_probe::ScanBackend::MegaScan
        ) && !self.gpu_stack_usable()
        {
            if crate::gpu::gpu_required_by_policy() {
                crate::process_exit::require_gpu_unmet(format!(
                    "{} auto-selected under required GPU policy, but this scanner has no live GPU stack \
(gpu_literals={}, gpu_backend={}, gpu_matcher={}); refusing to run on CPU/SIMD.",
                    selected.label(),
                    self.gpu_literals.is_some(),
                    self.gpu_backend.is_some(),
                    self.gpu_matcher().is_some()
                ));
            }
            self.warn_gpu_auto_degrade(
                selected,
                "auto route selected GPU without acquired scanner GPU stack",
            );
            return self.live_cpu_backend();
        }
        // The hardware probe can pick SimdCpu from host capability + pattern count
        // alone, but THIS scanner may have built no Hyperscan prefilter — e.g. a
        // detector set whose patterns expose no anchorable literal (`[a-z]{16}`), so
        // `simd_prefilter` is None. Auto-route such a scan to the live CPU backend
        // (CpuFallback) instead of returning a SimdCpu the scan path cannot honor:
        // `resolve_backend_for_scan`'s fail-closed abort is reserved for an EXPLICIT
        // `--backend simd-regex` request, not for auto-selection, which must always
        // resolve to a backend this scanner can actually run (Law 10: no silent — and
        // here, no fatal — degrade on the auto path).
        if selected == crate::hw_probe::ScanBackend::SimdCpu && !self.simd_backend_usable() {
            return self.live_cpu_backend();
        }
        selected
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

    /// Return the steady-state backend label used for startup reporting.
    #[must_use]
    pub(crate) fn preferred_backend_label(&self) -> &'static str {
        self.select_backend_for_file(0).label()
    }

    /// Warm backend resources that are initialized lazily during scanning.
    pub fn warm_backend(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        // `Gpu` and `MegaScan` are the SAME live on-GPU engine now: the
        // GpuLiteralSet region-presence route. The separate `RulePipeline`
        // regex-NFA engine `MegaScan` once warmed was a dead route (its `scan`
        // was never invoked) and was removed, so warming both arms is exactly
        // "is the GPU region-presence stack usable".
        let ready = match backend {
            crate::hw_probe::ScanBackend::Gpu | crate::hw_probe::ScanBackend::MegaScan => {
                self.gpu_stack_usable()
            }
            crate::hw_probe::ScanBackend::SimdCpu => self.simd_backend_usable(),
            crate::hw_probe::ScanBackend::CpuFallback => true,
        };
        if !ready {
            gpu_forced::deny_silent_gpu_degrade(self, backend);
        }
        ready
    }

    /// Scan a chunk of text and return all raw credential matches.
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        self.scan_with_deadline(chunk, self.config.per_chunk_deadline())
    }

    /// Scan a chunk using a caller-selected backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, self.config.per_chunk_deadline(), Some(backend))
    }

    /// Scan multiple chunks using a caller-selected backend.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        self.deny_silent_selected_backend_degrade(backend);
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
        self.scan_with_deadline_and_backend(chunk, deadline, None)
    }

    pub(crate) fn scan_with_deadline_and_backend(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        backend: Option<crate::hw_probe::ScanBackend>,
    ) -> Vec<RawMatch> {
        if crate::deadline::expired(deadline) {
            return Vec::new();
        }
        if let Some(selected_backend) = backend {
            self.deny_silent_selected_backend_degrade(selected_backend);
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
                let live_backend = self.live_cpu_backend();
                if live_backend == crate::hw_probe::ScanBackend::CpuFallback {
                    self.warn_simd_auto_degrade(
                        "decode-shaped no-hit chunk had no live SIMD prefilter",
                    );
                }
                let triggered = if prepared.preprocessed.text.as_bytes() == chunk.data.as_bytes() {
                    Vec::new()
                } else {
                    self.collect_triggered_patterns_for_backend(
                        &prepared.preprocessed.text,
                        live_backend,
                    )
                };
                let mut matches = self.scan_prepared_with_triggered(
                    prepared,
                    live_backend,
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
                self.record_and_reassemble_for_no_hit_chunk(chunk, &mut matches);
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

        let selected_backend = self.resolve_backend_for_scan(backend, chunk.data.len() as u64); // LAW10: operator-visible — the automatic CPU-tier choice is relabeled to the backend that actually runs; not a silent degrade
        gpu_forced::deny_silent_gpu_degrade(self, selected_backend);
        tracing::trace!(
            target: "keyhog::routing",
            backend = selected_backend.label(),
            chunk_bytes = chunk.data.len(),
            source_type = chunk.metadata.source_type.as_str(),
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
