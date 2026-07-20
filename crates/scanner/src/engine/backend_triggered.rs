use super::phase2::Phase2AlwaysActiveGpuEvidence;
use super::*;
use crate::context;
use crate::hw_probe::ScanBackend;
use keyhog_core::RawMatch;

impl CompiledScanner {
    pub(crate) fn scan_prepared_with_triggered(
        &self,
        prepared: PreparedChunk<'_>,
        triggered_patterns: &[u64],
        deadline: Option<std::time::Instant>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
        generic_keyword_positions: Option<&[u32]>,
        route: crate::ScanExecutionRoute,
    ) -> Vec<RawMatch> {
        let scan_state = self.scan_prepared_state_with_triggered(
            prepared,
            triggered_patterns,
            deadline,
            phase2_keyword_hints,
            phase2_always_active_gpu_evidence,
            confirmed_anchor_literal_matches,
            generic_keyword_positions,
            route,
        );
        #[cfg(feature = "ml")]
        {
            let mut scan_state = scan_state;
            if !crate::deadline::expired(deadline) {
                let _g = profile::span(profile::P::Ml);
                self.apply_ml_batch_scores(&mut scan_state);
            }
            scan_state.into_matches()
        }
        #[cfg(not(feature = "ml"))]
        {
            scan_state.into_matches()
        }
    }

    pub(crate) fn scan_prepared_state_with_triggered(
        &self,
        prepared: PreparedChunk<'_>,
        triggered_patterns: &[u64],
        deadline: Option<std::time::Instant>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        confirmed_anchor_literal_matches: Option<&[(u32, u32)]>,
        generic_keyword_positions: Option<&[u32]>,
        route: crate::ScanExecutionRoute,
    ) -> ScanState {
        if crate::deadline::expired(deadline) {
            return ScanState::with_static_intern(self.static_intern.clone());
        }
        // Borrow cached line offsets; downstream consumers take `&[usize]`.
        let line_offsets: &[usize] = prepared.line_offsets();
        let code_lines = prepared.code_lines(line_offsets);
        // Needed by both the hot SIMD accelerator and phase-2 capture paths so
        // every canonical detector candidate uses the same context-aware
        // suppression/adjudication chain.
        let documentation_lines = context::documentation_line_flags(&code_lines);
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());

        // Unified profiler; phase-2 capture has its own internal sub-spans.
        {
            let _g = profile::span(profile::P::Hot);
            #[cfg(feature = "simdsieve")]
            self.scan_hot_patterns_fast(
                &prepared.preprocessed.text,
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
            );
        }
        if crate::deadline::expired(deadline) {
            return scan_state;
        }

        let raw_text_unchanged =
            prepared.preprocessed.text.as_bytes() == prepared.chunk.data.as_bytes();
        let normalized_triggered;
        let triggered_patterns = if raw_text_unchanged {
            triggered_patterns
        } else {
            normalized_triggered = {
                let mut normalized = self.collect_triggered_patterns_for_backend(
                    &prepared.preprocessed.text,
                    ScanBackend::CpuFallback,
                );
                for (word, raw_word) in normalized.iter_mut().zip(triggered_patterns) {
                    *word |= *raw_word;
                }
                normalized
            };
            normalized_triggered.as_slice()
        };
        let expanded_patterns = self.expand_triggered_patterns(triggered_patterns);
        // Producer trigger bits and GPU evidence describe raw bytes. When
        // preprocessing changes those bytes, union fresh canonical phase-one
        // triggers and discard every raw position or absence claim.
        let phase2_keyword_hints = phase2_keyword_hints.filter(|_| raw_text_unchanged);
        let phase2_always_active_gpu_evidence =
            phase2_always_active_gpu_evidence.filter(|_| raw_text_unchanged);
        let confirmed_anchor_literal_matches =
            confirmed_anchor_literal_matches.filter(|_| raw_text_unchanged);
        let generic_keyword_positions = generic_keyword_positions.filter(|_| raw_text_unchanged);

        // No-trigger fast path: when no AC pattern fired, the entire
        // confirmed-pattern extraction pipeline is dead work. Skip
        // building the `confirmed_patterns: Vec<usize>` (allocation saved)
        // and the `extract_confirmed_patterns` call. The downstream
        // phase-2 lanes (`scan_phase2_patterns`, `scan_generic_assignments`,
        // `scan_entropy_fallback`, `apply_ml_batch_scores`) run unchanged
        // since they have their own input shapes.
        //
        // NOTE: the confirmed pass is deliberately NOT decode-focus restricted
        // (unlike `scan_phase2_patterns` below). A decode sub-chunk splices the
        // decoded text in place of the encoded blob, which creates new byte
        // adjacencies at the junction AND new token boundaries inside what was a
        // contiguous base64 run, so a confirmed/companion detector
        // (cloudflare-api-token, mysql-connection-string, …) can fire on spliced
        // context arbitrarily far from the decoded span where the PARENT (which
        // saw the still-encoded bytes) did not. The decode-focus theorem
        // ("outside the span is a parent duplicate") therefore does NOT hold for
        // confirmed detectors; windowing it dropped real findings on the mirror
        // corpus (the `confirmed_focus_parity` differential rejected M=256). It
        // holds for phase-2 capture because those detectors are self-contained at the
        // decoded credential itself.
        if expanded_patterns.iter().any(|&w| w != 0) {
            let _g = profile::span(profile::P::Confirmed);
            // Walk only set bits instead of testing every pattern slot.
            let set_bits: usize = expanded_patterns
                .iter()
                .map(|w| w.count_ones() as usize)
                .sum();
            let mut confirmed_patterns: Vec<usize> = Vec::with_capacity(set_bits);
            super::trigger_bitmap::for_each_set_bit(&expanded_patterns, |idx| {
                if idx < self.ac_map.len() {
                    confirmed_patterns.push(idx);
                }
            });

            self.extract_confirmed_patterns(
                &confirmed_patterns,
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
                deadline,
                confirmed_anchor_literal_matches,
            );
        }
        if crate::deadline::expired(deadline) {
            return scan_state;
        }

        // Phase-2 capture patterns (no usable literal prefix; e.g. asana-pat
        // shaped `1/[0-9]{16,20}/...`) never enter the AC-trigger
        // bitmap, so they would never extract via the path above.
        // Task #69 - these detectors were silently dead in EVERY hot
        // code path that builds a triggered bitmap. The keyword-AC
        // pre-filter inside `scan_phase2_patterns` keeps cost
        // bounded to detectors whose >=4-char keyword appears in the
        // chunk; phase-2 patterns with no usable keyword are seeded
        // from `phase2_always_active_indices` so they run on every chunk.
        // Decode-recursion FOCUS: a decode sub-chunk carries `decoded_span`, the
        // byte range of the freshly decoded text inside its (mostly already-
        // scanned) parent-context splice. Window the expensive phase-2 pass to
        // that span + margin instead of the whole splice, the rest of the splice
        // was scanned (and any finding deduped) by the parent chunk. Requires
        // `preprocessed.text` to be byte-aligned with `chunk.data` (the homoglyph
        // no-op passthrough) so the span, in `chunk.data` coordinates, indexes
        // `preprocessed.text`; otherwise the full scan runs.
        let focus = prepared.chunk.metadata.decoded_span.filter(|_| {
            self.tuning.decode_focus_enabled()
                && std::ptr::eq(
                    prepared.preprocessed.text.as_ptr(),
                    prepared.chunk.data.as_ptr(),
                )
                && prepared.preprocessed.text.len() == prepared.chunk.data.len()
        });
        match focus {
            Some(span) => self.scan_phase2_patterns_focused(
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
                deadline,
                span,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            ),
            None => self.scan_phase2_patterns(
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
                deadline,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            ),
        }
        if crate::deadline::expired(deadline) {
            return scan_state;
        }

        {
            let _g = profile::span(profile::P::Generic);
            self.scan_generic_assignments(
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
                generic_keyword_positions,
                deadline,
            );
        }
        if crate::deadline::expired(deadline) {
            return scan_state;
        }

        #[cfg(feature = "entropy")]
        {
            let _g = profile::span(profile::P::Entropy);
            self.scan_entropy_fallback(
                &prepared.preprocessed,
                line_offsets,
                prepared.chunk,
                &mut scan_state,
            );
        }
        if crate::deadline::expired(deadline) {
            return scan_state;
        }

        scan_state
    }

    /// Test/diagnostic: run ONLY the phase-2 pass on `chunk` and return its
    /// raw matches, with no triggered-pattern, generic, entropy, ML, or
    /// post-process/reassembly stages. Isolates `scan_phase2_patterns` so the
    /// anchored-vs-whole-chunk differential test compares exactly that pass,
    /// free of downstream reassembly that would mask which pass diverged.
    #[doc(hidden)]
    #[cfg(test)]
    pub(crate) fn debug_scan_phase2_only(&self, chunk: &keyhog_core::Chunk) -> Vec<RawMatch> {
        let prepared = self.prepare_chunk(chunk);
        let line_offsets: &[usize] = prepared.line_offsets();
        let code_lines = prepared.code_lines(line_offsets);
        let documentation_lines = context::documentation_line_flags(&code_lines);
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());
        self.scan_phase2_patterns(
            &prepared.preprocessed,
            line_offsets,
            &code_lines,
            &documentation_lines,
            prepared.chunk,
            &mut scan_state,
            None,
            None,
            None,
            self.default_execution_route(),
        );
        scan_state.into_matches()
    }

    pub(crate) fn collect_triggered_patterns_for_backend(
        &self,
        text: &str,
        backend: ScanBackend,
    ) -> Vec<u64> {
        let _g = profile::span(profile::P::Phase1Triggers);
        match backend {
            ScanBackend::GpuCuda | ScanBackend::GpuWgpu => {
                self.collect_triggered_patterns_gpu(text, backend)
            }
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => self.collect_triggered_patterns_cpu(text),
        }
    }

    /// Per-chunk GPU trigger production. Every dispatch failure records its
    /// concrete reason and terminates the selected route.
    fn collect_triggered_patterns_gpu(&self, text: &str, route: ScanBackend) -> Vec<u64> {
        let dispatch_failure = |reason: String| -> Vec<u64> {
            super::gpu_forced::fail_selected_gpu_dispatch(self, &reason)
        };

        let Some(matcher) = self.gpu_matcher() else {
            return dispatch_failure("gpu literal matcher not built for this scanner".to_string());
        };
        let Some(gpu_backend) = self.gpu_backends.get(route) else {
            return dispatch_failure(self.gpu_backend_unavailable_reason(route));
        };
        // Presence bitmap is the phase-1 path: no per-hit triples and no match
        // cap, with the same pattern-id mapping.
        match super::gpu_literal_scratch::scan_gpu_literal_presence_with_scratch(
            matcher,
            &**gpu_backend,
            text.as_bytes(),
        ) {
            Ok(presence) => {
                let expected_presence_words = self.gpu_literal_count().div_ceil(32).max(1);
                if presence.len() != expected_presence_words {
                    return dispatch_failure(format!(
                        "per-chunk GPU presence readback length mismatch: got {} u32 word(s), need {}",
                        presence.len(),
                        expected_presence_words
                    ));
                }
                if let Some((word_idx, stray_bits)) = self.gpu_presence_stray_tail_bits(&presence) {
                    return dispatch_failure(format!(
                        "per-chunk GPU presence readback has out-of-range detector bit(s): word {word_idx} bits 0x{stray_bits:08x} beyond {} literal(s)",
                        self.gpu_literal_count()
                    ));
                }
                // Union with AC triggers so the GPU literal matcher is never
                // the sole gate for context-anchored detectors. Mark the GPU
                // presence bits straight into the CPU-trigger bitmap rather than
                // allocating a second per-chunk `Vec<u64>` only to OR it in.
                let mut triggered = self.collect_triggered_patterns_cpu(text);
                self.mark_gpu_presence_into(&mut triggered, &presence);
                triggered
            }
            Err(error) => dispatch_failure(format!("gpu presence scan failed: {error}")),
        }
    }

    fn collect_triggered_patterns_simd(&self, _text: &str) -> Vec<u64> {
        #[cfg(feature = "simd")]
        {
            // LAW10: fail-closed/security; backend_unavailable terminates the selected-backend scan with an operator-visible error.
            let prefilter = self.try_simd_prefilter().unwrap_or_else(|error| {
                crate::process_exit::backend_unavailable(format!(
                    "selected Hyperscan trigger backend was not initialized: {error}"
                ))
            });
            let scanner = prefilter.scanner();
            // AC and HS trigger sets are incomparable; union then confirm.
            let mut triggered_patterns = self.collect_triggered_patterns_cpu(_text);
            let scan_result =
                scanner.scan_matches_result(_text.as_bytes(), |hs_id, _start, _end| {
                    if let Some(original_indices) = prefilter.original_indices(hs_id) {
                        for &pattern_index in original_indices {
                            self.mark_triggered_pattern(
                                &mut triggered_patterns,
                                pattern_index as usize,
                            );
                        }
                    }
                });
            if let Err(error) = scan_result {
                crate::process_exit::backend_unavailable(format!(
                    "selected Hyperscan trigger scan failed: {error}. The scan did not complete; rerun with `--backend cpu` or recalibrate autoroute"
                ));
            }
            return triggered_patterns;
        }

        #[cfg(not(feature = "simd"))]
        crate::process_exit::backend_unavailable(
            "simd-regex trigger collection reached without a live SIMD/Hyperscan prefilter; \
silent cpu-fallback execution is forbidden. Run `keyhog backend --self-test` or choose \
`--backend cpu` explicitly.",
        )
    }

    pub(crate) fn collect_triggered_patterns_cpu(&self, text: &str) -> Vec<u64> {
        self.collect_triggered_patterns_cpu_bytes(text.as_bytes())
    }

    pub(crate) fn collect_triggered_patterns_cpu_bytes(&self, bytes: &[u8]) -> Vec<u64> {
        let mut triggered_patterns = super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
        if let Some(ac) = &self.ac {
            // OVERLAPPING iteration, not leftmost `find_iter`: a non-overlapping
            // sweep reports the longest literal at each position and SKIPS PAST it,
            // so a shorter literal nested inside a longer one is shadowed and never
            // marks its detector. Concretely `client_secret` (pattern 5's quoted-
            // JSON literal) swallows the `secret` inside it, so generic-password
            // pattern 4 (`(?:…|secret)\s*=\s*"…"`) is never AC-confirmed and only
            // the always-active homoglyph variant catches it on ASCII, the exact
            // base-AC coverage gap that blocked the homoglyph ASCII-skip. Triggers
            // are position-independent bits (the confirmed pass re-scans the whole
            // chunk and filters by full regex), so marking every literal that
            // occurs, overlaps included, only ever ADDS sound confirmation work,
            // never a false positive, and closes the shadow gap for every backend.
            // Phase-1 is ~1.7% of scan and literals are sparse in real source, so
            // the extra overlap matches are negligible; proven recall-neutral for
            // the skip by `homoglyph_ascii_skip_parity_default`.
            for ac_match in ac.find_overlapping_iter(bytes) {
                self.mark_triggered_pattern(&mut triggered_patterns, ac_match.pattern().as_usize());
            }
        }
        triggered_patterns
    }

    /// Number of rows in the fused GPU literal matcher. Presence bits exist for
    /// every row, but only the leading trigger segments may activate detectors;
    /// the appended rows own positioned phase-two evidence.
    #[inline]
    pub(crate) fn gpu_literal_count(&self) -> usize {
        let shared_literal_count =
            self.ac_map.len() + self.phase2_keyword_count + self.phase2_always_anchor_literal_count;
        #[cfg(feature = "gpu")]
        {
            shared_literal_count
                + self.confirmed_anchor_literal_count
                + self.generic_keyword_literal_count
        }
        #[cfg(not(feature = "gpu"))]
        {
            shared_literal_count
        }
    }

    pub(crate) fn gpu_presence_stray_tail_bits(&self, presence: &[u32]) -> Option<(usize, u32)> {
        let literal_count = self.gpu_literal_count();
        let used_tail_bits = literal_count % 32;
        if literal_count != 0 && used_tail_bits == 0 {
            return None;
        }
        let tail_word_idx = literal_count / 32;
        let valid_mask = if used_tail_bits == 0 {
            0
        } else {
            (1u32 << used_tail_bits) - 1
        };
        let stray_bits = *presence.get(tail_word_idx)? & !valid_mask;
        (stray_bits != 0).then_some((tail_word_idx, stray_bits))
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn triggered_patterns_from_gpu_presence(&self, presence: &[u32]) -> Vec<u64> {
        let mut triggered = super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
        self.mark_gpu_presence_into(&mut triggered, presence);
        triggered
    }

    /// Union GPU literal-presence bits INTO an existing trigger bitmap (marking,
    /// via [`Self::mark_triggered_pattern`], every set presence bit and its prefix
    /// propagation). The buffer-reusing counterpart of
    /// [`Self::triggered_patterns_from_gpu_presence`]: the GPU-union path
    /// (`collect_triggered_patterns_gpu`) already holds the CPU-trigger bitmap, so
    /// marking straight into it avoids allocating and then discarding a SECOND
    /// per-chunk `Vec<u64>` just to OR it in, the fresh-per-chunk allocation the
    /// GPU trigger path used to pay on every chunk.
    pub(crate) fn mark_gpu_presence_into(&self, triggered: &mut [u64], presence: &[u32]) {
        for (word_idx, &word) in presence.iter().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let literal_idx = word_idx * 32 + bit;
                if literal_idx < self.ac_map.len() {
                    self.mark_triggered_pattern(triggered, literal_idx);
                }
                bits &= bits - 1;
            }
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn phase2_keyword_hints_from_gpu_presence(&self, presence: &[u32]) -> Vec<u32> {
        let keyword_count = self.phase2_keyword_count;
        if keyword_count == 0 {
            return Vec::new();
        }
        let base = self.ac_map.len();
        let mut hints = Vec::new();
        for keyword_idx in 0..keyword_count {
            let literal_idx = base + keyword_idx;
            let word_idx = literal_idx / 32;
            let bit = literal_idx % 32;
            if presence
                .get(word_idx)
                .is_some_and(|word| (word & (1u32 << bit)) != 0)
            {
                hints.push(keyword_idx as u32);
            }
        }
        hints
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn phase2_always_anchor_present_from_gpu_presence(&self, presence: &[u32]) -> bool {
        let anchor_count = self.phase2_always_anchor_literal_count;
        if anchor_count == 0 {
            return false;
        }
        let base = self.ac_map.len() + self.phase2_keyword_count;
        for anchor_idx in 0..anchor_count {
            let literal_idx = base + anchor_idx;
            let word_idx = literal_idx / 32;
            let bit = literal_idx % 32;
            if presence
                .get(word_idx)
                .is_some_and(|word| (word & (1u32 << bit)) != 0)
            {
                return true;
            }
        }
        false
    }

    pub(crate) fn mark_triggered_pattern(
        &self,
        triggered_patterns: &mut [u64],
        pattern_index: usize,
    ) {
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
}
