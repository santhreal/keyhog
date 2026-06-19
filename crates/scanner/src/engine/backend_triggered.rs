use super::*;
use crate::context;
use crate::hw_probe::ScanBackend;
use keyhog_core::RawMatch;

impl CompiledScanner {
    pub(crate) fn scan_prepared_with_triggered(
        &self,
        prepared: PreparedChunk<'_>,
        _backend: ScanBackend,
        triggered_patterns: Vec<u64>,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        // Borrow cached line offsets; downstream consumers take `&[usize]`.
        let line_offsets: &[usize] = prepared.line_offsets();
        let code_lines: Vec<&str> = prepared.chunk.data.lines().collect();
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());

        // Unified profiler; fallback has its own internal sub-spans.
        {
            let _g = profile::span(profile::P::Hot);
            #[cfg(feature = "simdsieve")]
            self.scan_hot_patterns_fast(
                &prepared.preprocessed.text,
                &prepared.preprocessed,
                line_offsets,
                prepared.chunk,
                &mut scan_state,
            );
        }

        let expanded_patterns = self.expand_triggered_patterns(&triggered_patterns);
        // Needed by fallback on both trigger and no-trigger paths.
        let documentation_lines = context::documentation_line_flags(&code_lines);

        // No-trigger fast path: when no AC pattern fired, the entire
        // confirmed-pattern extraction pipeline is dead work. Skip
        // building the `confirmed_patterns: Vec<usize>` (allocation saved)
        // and the `extract_confirmed_patterns` call. The downstream
        // fallbacks (`scan_phase2_patterns`, `scan_generic_assignments`,
        // `scan_entropy_fallback`, `apply_ml_batch_scores`) run unchanged
        // since they have their own input shapes.
        //
        // NOTE: the confirmed pass is deliberately NOT decode-focus restricted
        // (unlike `scan_phase2_patterns` below). A decode sub-chunk splices the
        // decoded text in place of the encoded blob, which creates new byte
        // adjacencies at the junction AND new token boundaries inside what was a
        // contiguous base64 run — so a confirmed/companion detector
        // (cloudflare-api-token, mysql-connection-string, …) can fire on spliced
        // context arbitrarily far from the decoded span where the PARENT (which
        // saw the still-encoded bytes) did not. The decode-focus theorem
        // ("outside the span is a parent duplicate") therefore does NOT hold for
        // confirmed detectors; windowing it dropped real findings on the mirror
        // corpus (the `confirmed_focus_parity` differential rejected M=256). It
        // holds for fallback because those detectors are self-contained at the
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
            );
        }

        // Fallback patterns (no usable literal prefix; e.g. asana-pat
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
        // that span + margin instead of the whole splice — the rest of the splice
        // was scanned (and any finding deduped) by the parent chunk. Requires
        // `preprocessed.text` to be byte-aligned with `chunk.data` (the homoglyph
        // no-op passthrough) so the span — in `chunk.data` coordinates — indexes
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
            ),
            None => self.scan_phase2_patterns(
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
                deadline,
            ),
        }

        {
            let _g = profile::span(profile::P::Generic);
            self.scan_generic_assignments(
                &code_lines,
                line_offsets,
                prepared.chunk,
                &mut scan_state,
            );
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

        #[cfg(feature = "ml")]
        {
            let _g = profile::span(profile::P::Ml);
            self.apply_ml_batch_scores(&mut scan_state);
        }

        scan_state.into_matches()
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
        let code_lines: Vec<&str> = prepared.chunk.data.lines().collect();
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
            ScanBackend::Gpu | ScanBackend::MegaScan => {
                self.collect_triggered_patterns_gpu(text, backend)
            }
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => self.collect_triggered_patterns_cpu(text),
        }
    }

    /// Per-chunk GPU trigger production; every degrade records the reason and
    /// routes through the explicit GPU-failure policy.
    fn collect_triggered_patterns_gpu(&self, text: &str, backend: ScanBackend) -> Vec<u64> {
        let degrade = |reason: String| -> Vec<u64> {
            if let Ok(mut slot) = self.gpu_last_degrade_reason.lock() {
                *slot = Some(reason.clone());
            }
            self.gpu_degrade_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            super::gpu_forced::deny_silent_gpu_degrade_with_reason(self, backend, Some(&reason));
            self.collect_triggered_patterns_simd(text)
        };

        let Some(matcher) = self.gpu_matcher() else {
            return degrade("gpu literal matcher not built for this scanner".to_string());
        };
        let Some(gpu_backend) = self.gpu_backend.as_ref() else {
            return degrade("no gpu backend acquired for per-chunk trigger dispatch".to_string());
        };
        // Presence bitmap is the phase-1 path: no per-hit triples and no match
        // cap, with the same pattern-id mapping.
        match matcher.scan_presence(&**gpu_backend, text.as_bytes()) {
            Ok(presence) => {
                // Union with AC triggers so the GPU literal matcher is never
                // the sole gate for context-anchored detectors.
                let mut triggered = self.collect_triggered_patterns_cpu(text);
                let gpu = self.triggered_patterns_from_gpu_presence(&presence);
                for (slot, bits) in triggered.iter_mut().zip(gpu.iter()) {
                    *slot |= *bits;
                }
                triggered
            }
            Err(error) => degrade(format!("gpu presence scan failed: {error}")),
        }
    }

    fn collect_triggered_patterns_simd(&self, text: &str) -> Vec<u64> {
        #[cfg(feature = "simd")]
        if let Some(scanner) = &self.simd_prefilter {
            // AC and HS trigger sets are incomparable; union then confirm.
            let mut triggered_patterns = self.collect_triggered_patterns_cpu(text);
            match scanner.scan_result(text.as_bytes()) {
                Ok(matches) => {
                    for (hs_id, _start, _end) in matches {
                        let Some((_detector_index, dedup_id, _has_group)) =
                            scanner.pattern_info(hs_id)
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
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        "hyperscan confirmed-trigger scan failed; over-marking SIMD-covered patterns for this chunk"
                    );
                    for hs_id in 0..scanner.pattern_count() {
                        let Some((_detector_index, dedup_id, _has_group)) =
                            scanner.pattern_info(hs_id)
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
                }
            }
            return triggered_patterns;
        }

        self.collect_triggered_patterns_cpu(text)
    }

    pub(crate) fn collect_triggered_patterns_cpu(&self, text: &str) -> Vec<u64> {
        let mut triggered_patterns = super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
        if let Some(ac) = &self.ac {
            // OVERLAPPING iteration, not leftmost `find_iter`: a non-overlapping
            // sweep reports the longest literal at each position and SKIPS PAST it,
            // so a shorter literal nested inside a longer one is shadowed and never
            // marks its detector. Concretely `client_secret` (pattern 5's quoted-
            // JSON literal) swallows the `secret` inside it, so generic-password
            // pattern 4 (`(?:…|secret)\s*=\s*"…"`) is never AC-confirmed and only
            // the always-active homoglyph variant catches it on ASCII — the exact
            // base-AC coverage gap that blocked the homoglyph ASCII-skip. Triggers
            // are position-independent bits (the confirmed pass re-scans the whole
            // chunk and filters by full regex), so marking every literal that
            // occurs — overlaps included — only ever ADDS sound confirmation work,
            // never a false positive, and closes the shadow gap for every backend.
            // Phase-1 is ~1.7% of scan and literals are sparse in real source, so
            // the extra overlap matches are negligible; proven recall-neutral for
            // the skip by `homoglyph_ascii_skip_parity_default`.
            for ac_match in ac.find_overlapping_iter(text.as_bytes()) {
                self.mark_triggered_pattern(&mut triggered_patterns, ac_match.pattern().as_usize());
            }
        }
        triggered_patterns
    }

    /// Build the keyhog trigger bitmap from a GPU literal-set PRESENCE bitmap
    /// (`scan_presence`): word `w`, bit `b` set means literal pattern `w*32+b`
    /// occurred. Maps each set bit through `mark_triggered_pattern` — the compact
    /// per-pattern counterpart of consuming per-hit match triples (the triple path
    /// was removed; see `collect_triggered_patterns_gpu`).
    fn triggered_patterns_from_gpu_presence(&self, presence: &[u32]) -> Vec<u64> {
        let mut triggered = super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
        for (word_idx, &word) in presence.iter().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                self.mark_triggered_pattern(&mut triggered, word_idx * 32 + bit);
                bits &= bits - 1;
            }
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

    // `#[cfg(feature = "gpu")]`: the ONLY caller is the GPU megakernel
    // dispatch's failure path (`megakernel_dispatch.rs`), so this — and its
    // `has_simd_prefilter` helper — are needed exactly when `gpu` is compiled.
    // A no-`gpu` build never recovers from a GPU failure, so leaving it
    // ungated is dead code there (Law 11).
    #[cfg(feature = "gpu")]
    pub(crate) fn degraded_backend_after_gpu_failure(&self) -> ScanBackend {
        // Route to the backend that is ACTUALLY live: `SimdCpu` only when a
        // Hyperscan prefilter is compiled in and built, else the pure-CPU AC
        // `CpuFallback` — otherwise the operator-visible backend would claim
        // SimdCpu while silently running the weaker AC path (Law 10). `gpu`
        // implies `simd`, so the prefilter is always compiled in here; the
        // `has_simd_prefilter` accessor still gates on whether the Hyperscan
        // database actually BUILT at runtime (it can be `None` on a build
        // failure), keeping the degraded-backend label honest.
        if self.has_simd_prefilter() {
            ScanBackend::SimdCpu
        } else {
            ScanBackend::CpuFallback
        }
    }
}
