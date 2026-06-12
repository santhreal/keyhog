//! `impl CompiledScanner` public-API surface — accessors (detector/pattern
//! counts, backend labels, diagnostics) and the `scan*` entry points —
//! extracted from `engine/mod.rs` (Law 5, 500-LOC ceiling). The struct and its
//! private helpers (`env_per_chunk_deadline`, `MAX_SCAN_CHUNK_BYTES`) stay in
//! `mod.rs` and are reached through `use super::*`. Pure move, no behaviour
//! change.
use super::*;

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
    /// Compiled only under `gpu`: its SOLE consumer is
    /// `degraded_backend_after_gpu_failure` on the GPU dispatch path, so a
    /// no-`gpu` build never asks the question. Gating it here keeps the
    /// no-`gpu` profiles warning-clean (Law 11) without changing any answer.
    /// `gpu` implies `simd` at the feature level (see keyhog-scanner Cargo.toml
    /// — the megakernel reuses the SIMD phase-2 tail), so the `simd_prefilter`
    /// field is always present here; the runtime `is_some()` still reflects
    /// whether the Hyperscan database actually built.
    #[cfg(feature = "gpu")]
    #[inline]
    pub(crate) fn has_simd_prefilter(&self) -> bool {
        self.simd_prefilter.is_some()
    }

    /// Number of loaded detectors.
    pub fn detector_count(&self) -> usize {
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

    /// Total number of patterns (AC + fallback).
    pub fn pattern_count(&self) -> usize {
        self.ac_map.len() + self.fallback.len()
    }

    /// This scanner's performance route tuning. Differential parity tests flip a
    /// route on ONE scanner — e.g. `scanner.tuning().set_fallback_hs(Some(false))`
    /// — to drive a single input down both code paths without any process-global
    /// state; production code never calls the setters, so every override stays at
    /// "follow env". See [`fallback::ScannerTuning`].
    pub fn tuning(&self) -> &fallback::ScannerTuning {
        &self.tuning
    }

    /// Diagnostic: `(fallback_total, always_active, always_active_eligible)` —
    /// how much the shared-anchor index shrinks the RegexSet prefilter. The
    /// prefilter cost scales with `always_active - always_active_eligible`.
    pub fn fallback_anchor_stats(&self) -> (usize, usize, usize) {
        let total = self.fallback.len();
        let always_active = self.fallback_always_active_indices.len();
        let aae = self.fallback_anchor_index.as_ref().map_or(0, |idx| {
            self.fallback_always_active_indices
                .iter()
                .filter(|&&i| idx.is_always_active_eligible(i))
                .count()
        });
        (total, always_active, aae)
    }

    /// Diagnostic: `(regex_source, keywords)` for every keyword-gated fallback
    /// pattern, in `fallback` order. These are the no-literal-prefix detectors
    /// that `scan_fallback_patterns` runs over the whole chunk once their
    /// keyword fires. Used by anchor-localization analysis to classify which
    /// carry a regex-required literal that can drive a windowed (rather than
    /// whole-chunk) scan. Diagnostic surface only — not part of the scan path.
    pub fn fallback_pattern_diagnostics(&self) -> Vec<(String, Vec<String>)> {
        self.fallback
            .iter()
            .map(|(p, kw)| (p.regex.as_str().to_string(), kw.clone()))
            .collect()
    }

    /// Eagerly compile every pattern's regex, in parallel, up front.
    ///
    /// Patterns compile lazily on first use (see [`crate::types::LazyRegex`]),
    /// which makes a one-shot CLI scan start in milliseconds instead of
    /// paying ~450ms-2.3s to build the whole corpus. For a LONG-lived or
    /// LARGE scan - the daemon, `watch`, `scan-system`, or a big repo where a
    /// detector fires across thousands of files - it's better to pay the
    /// compile once, in parallel, before the hot loop rather than stalling
    /// the first file that touches each detector. Callers on those paths
    /// should `warm()` after building the scanner.
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
            let _ = p.regex.get().find(WARM_SAMPLE);
        });
        self.fallback.par_iter().for_each(|(p, _)| {
            let _ = p.regex.get().find(WARM_SAMPLE);
        });
        crate::shared_regexes::warm_runtime_regexes();
        fallback_generic::warm_generic_assignment_runtime();
        crate::multiline::warm_runtime_regexes();
        crate::checksum::warm_runtime_regexes();
    }

    /// Iterator over the FINAL regex source strings (post anchoring /
    /// group extraction / normalization) the scanner uses.
    pub fn pattern_regex_strs(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(self.ac_map.len() + self.fallback.len());
        out.extend(self.ac_map.iter().map(|p| p.regex.as_str()));
        out.extend(self.fallback.iter().map(|(p, _)| p.regex.as_str()));
        out
    }

    /// Return the preferred backend for a file of the given size.
    #[must_use]
    pub fn select_backend_for_file(&self, file_size: u64) -> crate::hw_probe::ScanBackend {
        crate::hw_probe::select_backend(
            crate::hw_probe::probe_hardware(),
            file_size,
            self.pattern_count(),
        )
    }

    /// Identifier of the GPU backend acquired at compile time, or
    /// None if scanning routes to CPU/SIMD only. Mirrors
    /// `VyreBackend::id()` which returns "cuda", "wgpu", or the
    /// driver-defined name. The startup banner uses this so the
    /// operator can tell at a glance whether they got CUDA (the
    /// headline 5-10x faster path on NVIDIA hardware) or the WGPU
    /// fallback, rather than just "Gpu" which collapses both.
    #[must_use]
    pub fn gpu_backend_label(&self) -> Option<&'static str> {
        self.gpu_backend.as_ref().map(|b| b.id())
    }

    /// Most recent concrete GPU runtime-degrade reason for this compiled
    /// scanner, if one has occurred. Used by health probes to emit
    /// machine-readable failure causes without scraping stderr.
    pub fn last_gpu_degrade_reason(&self) -> Option<String> {
        self.gpu_last_degrade_reason
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    /// Return the steady-state backend label used for startup reporting.
    #[must_use]
    pub fn preferred_backend_label(&self) -> &'static str {
        self.select_backend_for_file(0).label()
    }

    /// Warm backend resources that are initialized lazily during scanning.
    pub fn warm_backend(&self, backend: crate::hw_probe::ScanBackend) -> bool {
        let ready = match backend {
            crate::hw_probe::ScanBackend::Gpu => self.gpu_stack_usable(),
            crate::hw_probe::ScanBackend::MegaScan => {
                let pipeline_ready = self.rule_pipeline().is_some();
                let stack_ready = self.gpu_stack_usable();
                if !pipeline_ready && stack_ready {
                    gpu_forced::deny_silent_megascan_degrade(
                        "regex pipeline compile rejected the detector set",
                    );
                }
                pipeline_ready && stack_ready
            }
            crate::hw_probe::ScanBackend::SimdCpu | crate::hw_probe::ScanBackend::CpuFallback => {
                true
            }
        };
        if !ready {
            gpu_forced::deny_silent_gpu_degrade(self, backend);
        }
        ready
    }

    /// Scan a chunk of text and return all raw credential matches.
    pub fn scan(&self, chunk: &Chunk) -> Vec<RawMatch> {
        self.scan_with_deadline(chunk, env_per_chunk_deadline())
    }

    /// Scan a chunk using a caller-selected backend.
    pub fn scan_with_backend(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, env_per_chunk_deadline(), Some(backend))
    }

    /// Scan multiple chunks using a caller-selected backend.
    pub fn scan_chunks_with_backend(
        &self,
        chunks: &[Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        gpu_forced::deny_silent_gpu_degrade(self, backend);
        profile::add_bytes(chunks.iter().map(|c| c.data.len() as u64).sum());
        profile::add_files(chunks.len() as u64);
        self.scan_chunks_with_backend_internal(chunks, backend)
    }

    /// Reset the cross-file fragment-reassembly cache.
    pub fn clear_fragment_cache(&self) {
        self.fragment_cache.clear();
    }

    /// Scan a chunk of text against all compiled detectors.
    pub fn scan_with_deadline(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        self.scan_with_deadline_and_backend(chunk, deadline, None)
    }

    pub fn scan_with_deadline_and_backend(
        &self,
        chunk: &Chunk,
        deadline: Option<std::time::Instant>,
        backend: Option<crate::hw_probe::ScanBackend>,
    ) -> Vec<RawMatch> {
        if let Some(path) = chunk.metadata.path.as_deref() {
            let filename = path.rsplit(['/', '\\']).next().unwrap_or(path);
            if filename == ".keyhog"
                || filename == ".keyhogignore"
                || path.split(['/', '\\']).any(|c| c == "detectors")
            {
                crate::telemetry::record_file_skipped();
                return Vec::new();
            }
        }

        // Direct-match prefilters: skip chunks that carry none of any
        // detector's literal bytes (`AlphabetScreen`) or bigrams (bloom). A
        // FULLY-ENCODED secret (e.g. `data = "<base64-of-ghp_…>"`) carries none
        // of those - its plaintext prefix only appears AFTER decoding - so the
        // prefilters would drop it before decode-through could recover it,
        // silently defeating the decode-through feature on the encoded-only
        // case. When the prefilter rejects but decode is enabled AND the chunk
        // carries a long base64/hex run, fall through to a DECODE-ONLY pass
        // instead of skipping. Bounded: only encoded-looking rejected chunks
        // pay the decode cost, so normal traffic keeps the fast skip.
        let alphabet_ok = self
            .alphabet_screen
            .as_ref()
            .map_or(true, |screen| screen.screen(chunk.data.as_bytes()));
        let bigram_ok =
            chunk.data.len() < 64 || self.bigram_bloom.maybe_overlaps(chunk.data.as_bytes());
        if !(alphabet_ok && bigram_ok) {
            #[cfg(feature = "decode")]
            if self.config.max_decode_depth > 0
                && chunk.data.len() <= self.config.max_decode_bytes
                && crate::decode::has_decodable_payload(chunk.data.as_bytes())
            {
                // Direct scan is skipped (the outer bytes match nothing); only
                // the decoded sub-chunks are scanned, inside post_process.
                let mut matches = Vec::new();
                self.post_process_matches(chunk, &mut matches, deadline);
                return matches;
            }
            crate::telemetry::record_file_skipped();
            return Vec::new();
        }

        let selected_backend =
            backend.unwrap_or_else(|| self.select_backend_for_file(chunk.data.len() as u64));
        gpu_forced::deny_silent_gpu_degrade(self, selected_backend);
        tracing::trace!(
            target: "keyhog::routing",
            backend = selected_backend.label(),
            chunk_bytes = chunk.data.len(),
            source_type = chunk.metadata.source_type.as_str(),
            "scan dispatch"
        );
        let mut matches = if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
            self.scan_windowed(chunk, deadline)
        } else {
            self.scan_inner(chunk, selected_backend, deadline)
        };

        self.post_process_matches(chunk, &mut matches, deadline);

        matches
    }
}
