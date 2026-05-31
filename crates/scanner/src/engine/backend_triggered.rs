use super::*;
use crate::context;
use crate::hw_probe::ScanBackend;
use keyhog_core::RawMatch;
use vyre_libs::scan::LiteralMatch;

impl CompiledScanner {
    pub(crate) fn scan_prepared_with_triggered(
        &self,
        prepared: PreparedChunk<'_>,
        _backend: ScanBackend,
        triggered_patterns: Vec<u64>,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        // Borrow the OnceLock-cached line offsets instead of cloning: the
        // cache (backend_prepared.rs) exists precisely to avoid recomputing
        // the offset table, and every downstream consumer
        // (extract_confirmed_patterns / scan_fallback_patterns /
        // scan_generic_assignments / scan_entropy_fallback) takes `&[usize]`.
        // The `.to_vec()` heap-cloned one usize per line of the file on every
        // chunk for no reason. The borrow stays valid for the whole function
        // because `prepared` is only read (never moved/mutated) afterward.
        let line_offsets: &[usize] = prepared.line_offsets();
        let code_lines: Vec<&str> = prepared.chunk.data.lines().collect();
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());

        #[cfg(feature = "simdsieve")]
        self.scan_hot_patterns_fast(
            &prepared.preprocessed.text,
            &prepared.preprocessed,
            line_offsets,
            prepared.chunk,
            &mut scan_state,
        );

        let expanded_patterns = self.expand_triggered_patterns(&triggered_patterns);
        // `documentation_lines` is consumed unconditionally below by
        // `scan_fallback_patterns` (fallback detectors run on every chunk,
        // see Task #69), so it must exist on both the trigger and no-trigger
        // paths. Compute it exactly once here rather than once in each arm of
        // a trigger branch - the old dual-arm shape recomputed nothing extra
        // but obscured that the flags scan happens once per chunk.
        let documentation_lines = context::documentation_line_flags(&code_lines);

        // No-trigger fast path: when no AC pattern fired, the entire
        // confirmed-pattern extraction pipeline is dead work. Skip
        // building the `confirmed_patterns: Vec<usize>` (allocation saved)
        // and the `extract_confirmed_patterns` call. The downstream
        // fallbacks (`scan_fallback_patterns`, `scan_generic_assignments`,
        // `scan_entropy_fallback`, `apply_ml_batch_scores`) run unchanged
        // since they have their own input shapes.
        if expanded_patterns.iter().any(|&w| w != 0) {
            let confirmed_patterns: Vec<usize> = (0..self.ac_map.len())
                .filter(|&i| (expanded_patterns[i / 64] & (1 << (i % 64))) != 0)
                .collect();

            self.extract_confirmed_patterns(
                &confirmed_patterns,
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
                deadline,
            );
        }

        // Fallback patterns (no usable literal prefix; e.g. asana-pat
        // shaped `1/[0-9]{16,20}/...`) never enter the AC-trigger
        // bitmap, so they would never extract via the path above.
        // Task #69 - these detectors were silently dead in EVERY hot
        // code path that builds a triggered bitmap. The keyword-AC
        // pre-filter inside `scan_fallback_patterns` keeps cost
        // bounded to detectors whose >=4-char keyword appears in the
        // chunk; fallback patterns with no usable keyword are seeded
        // from `fallback_always_active_indices` so they run on every chunk.
        self.scan_fallback_patterns(
            &prepared.preprocessed,
            line_offsets,
            &code_lines,
            &documentation_lines,
            prepared.chunk,
            &mut scan_state,
            deadline,
        );

        self.scan_generic_assignments(&code_lines, line_offsets, prepared.chunk, &mut scan_state);

        #[cfg(feature = "entropy")]
        self.scan_entropy_fallback(
            &prepared.preprocessed,
            line_offsets,
            prepared.chunk,
            &mut scan_state,
        );

        #[cfg(feature = "ml")]
        self.apply_ml_batch_scores(&mut scan_state);

        scan_state.into_matches()
    }

    pub(crate) fn collect_triggered_patterns_for_backend(
        &self,
        text: &str,
        backend: ScanBackend,
    ) -> Vec<u64> {
        match backend {
            // MegaScan currently reuses the literal-set trigger
            // collection - its own regex-NFA trigger pass is open and
            // unfinished. The trigger bitmask shape is identical to
            // the literal-set output so upstream consumers don't
            // branch; the gap is precision, not correctness (extra
            // patterns enter the cheap-filter, but evaluation still
            // filters them on the per-pattern match step).
            ScanBackend::Gpu | ScanBackend::MegaScan => self.collect_triggered_patterns_gpu(text),
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => self.collect_triggered_patterns_cpu(text),
        }
    }

    fn collect_triggered_patterns_gpu(&self, text: &str) -> Vec<u64> {
        if let Some(matcher) = self.gpu_matcher() {
            let Some(backend) = self.gpu_backend.as_ref() else {
                return self.collect_triggered_patterns_simd(text);
            };
            match matcher.scan(&**backend, text.as_bytes(), 10000) {
                Ok(matches) => {
                    // Union with the AC literal triggers for the same
                    // soundness reason as the SIMD path: the GPU literal
                    // matcher must not be the sole gate for literal-anchored
                    // patterns, or context-anchored detectors with large
                    // bounded-repeat bodies silently never fire on GPU.
                    let mut triggered = self.collect_triggered_patterns_cpu(text);
                    let gpu = self.triggered_patterns_from_gpu_matches(&matches);
                    for (slot, bits) in triggered.iter_mut().zip(gpu.iter()) {
                        *slot |= *bits;
                    }
                    return triggered;
                }
                Err(error) => {
                    tracing::debug!("gpu scan failed: {error}");
                }
            }
        }
        self.collect_triggered_patterns_simd(text)
    }

    fn collect_triggered_patterns_simd(&self, text: &str) -> Vec<u64> {
        #[cfg(feature = "simd")]
        if let Some(scanner) = &self.simd_prefilter {
            // Seed with the Aho-Corasick literal triggers. Hyperscan is the
            // primary prefilter, but it is NOT a sound superset of the AC
            // literal set: HS compiles some patterns (e.g. a context anchor
            // followed by a large `{100,200}` bounded repeat - line /
            // paloalto / tower / keystonejs / snowflake / bandwidth) without
            // erroring, yet never reports a match for them at scan time, so
            // they never enter the triggered bitmap and silently never fire
            // under the HS backend (the default on Linux/CI) while passing
            // under the CPU backend. A prefilter that drops a literal-
            // anchored pattern is unsound; union the AC literal triggers so
            // every pattern whose literal prefix appears is at least
            // evaluated. Extraction still confirms via the full regex, so
            // precision is unchanged - only the candidate set widens.
            let mut triggered_patterns = self.collect_triggered_patterns_cpu(text);
            for (hs_id, _start, _end) in scanner.scan(text.as_bytes()) {
                let Some((_detector_index, dedup_id, _has_group)) = scanner.pattern_info(hs_id)
                else {
                    continue;
                };
                if let Some(original_indices) = self.hs_index_map.get(dedup_id) {
                    for &pattern_index in original_indices {
                        self.mark_triggered_pattern(
                            &mut triggered_patterns,
                            pattern_index as usize,
                        );
                    }
                }
            }
            return triggered_patterns;
        }

        self.collect_triggered_patterns_cpu(text)
    }

    pub(crate) fn collect_triggered_patterns_cpu(&self, text: &str) -> Vec<u64> {
        let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
        if let Some(ac) = &self.ac {
            for ac_match in ac.find_iter(text.as_bytes()) {
                self.mark_triggered_pattern(&mut triggered_patterns, ac_match.pattern().as_usize());
            }
        }
        triggered_patterns
    }

    fn triggered_patterns_from_gpu_matches(&self, matches: &[LiteralMatch]) -> Vec<u64> {
        let mut triggered = vec![0u64; self.ac_map.len().div_ceil(64)];
        for matched in matches {
            self.mark_triggered_pattern(&mut triggered, matched.pattern_id as usize);
        }
        triggered
    }

    fn mark_triggered_pattern(&self, triggered_patterns: &mut [u64], pattern_index: usize) {
        if pattern_index / 64 >= triggered_patterns.len() {
            return;
        }
        triggered_patterns[pattern_index / 64] |= 1u64 << (pattern_index % 64);
        if let Some(propagated_indices) = self.prefix_propagation.get(pattern_index) {
            for &propagated_index in propagated_indices {
                let propagated_index = propagated_index as usize;
                if propagated_index / 64 < triggered_patterns.len() {
                    triggered_patterns[propagated_index / 64] |= 1u64 << (propagated_index % 64);
                }
            }
        }
    }

    pub(crate) fn degraded_backend_after_gpu_failure(&self) -> ScanBackend {
        #[cfg(feature = "simd")]
        if self.simd_prefilter.is_some() {
            return ScanBackend::SimdCpu;
        }
        ScanBackend::CpuFallback
    }
}
