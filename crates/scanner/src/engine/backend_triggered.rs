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

        // Unified profiler (env `KEYHOG_PROFILE=1`; see `engine::profile`). Each
        // pass opens a leaf span; the fallback pass is timed by its own internal
        // sub-spans (prefilter / shared-AC / verify / whole-chunk), so it has no
        // outer guard here — that would double-count its leaves.
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
        //
        // NOTE: the confirmed pass is deliberately NOT decode-focus restricted
        // (unlike `scan_fallback_patterns` below). A decode sub-chunk splices the
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
        // Decode-recursion FOCUS: a decode sub-chunk carries `decoded_span`, the
        // byte range of the freshly decoded text inside its (mostly already-
        // scanned) parent-context splice. Window the expensive fallback pass to
        // that span + margin instead of the whole splice — the rest of the splice
        // was scanned (and any finding deduped) by the parent chunk. Requires
        // `preprocessed.text` to be byte-aligned with `chunk.data` (the homoglyph
        // no-op passthrough) so the span — in `chunk.data` coordinates — indexes
        // `preprocessed.text`; otherwise the full scan runs.
        let focus = prepared.chunk.metadata.decoded_span.filter(|_| {
            fallback::decode_focus_enabled()
                && std::ptr::eq(
                    prepared.preprocessed.text.as_ptr(),
                    prepared.chunk.data.as_ptr(),
                )
                && prepared.preprocessed.text.len() == prepared.chunk.data.len()
        });
        match focus {
            Some(span) => self.scan_fallback_patterns_focused(
                &prepared.preprocessed,
                line_offsets,
                &code_lines,
                &documentation_lines,
                prepared.chunk,
                &mut scan_state,
                deadline,
                span,
            ),
            None => self.scan_fallback_patterns(
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

    /// Test/diagnostic: run ONLY the fallback pass on `chunk` and return its
    /// raw matches, with no triggered-pattern, generic, entropy, ML, or
    /// post-process/reassembly stages. Isolates `scan_fallback_patterns` so the
    /// anchored-vs-whole-chunk differential test compares exactly that pass,
    /// free of downstream reassembly that would mask which pass diverged.
    #[doc(hidden)]
    pub fn debug_scan_fallback_only(&self, chunk: &keyhog_core::Chunk) -> Vec<RawMatch> {
        let prepared = self.prepare_chunk(chunk);
        let line_offsets: &[usize] = prepared.line_offsets();
        let code_lines: Vec<&str> = prepared.chunk.data.lines().collect();
        let documentation_lines = context::documentation_line_flags(&code_lines);
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());
        self.scan_fallback_patterns(
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
            // Per-chunk GPU trigger production uses the GPU literal-set PRESENCE
            // bitmap; its bitmap shape is identical to the CPU paths so
            // downstream extraction never branches on backend. NOTE: the
            // coalesced BATCH path produces its triggers differently — via the
            // megakernel's on-GPU DFA catalog in `scan_coalesced_megakernel` —
            // so this per-chunk method runs only for the `scan_inner` entry, not
            // the batch megakernel.
            ScanBackend::Gpu | ScanBackend::MegaScan => {
                self.collect_triggered_patterns_gpu(text, backend)
            }
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => self.collect_triggered_patterns_cpu(text),
        }
    }

    /// Per-chunk GPU trigger production (`scan_inner` entry only — the batch path
    /// is the megakernel). Every path off the GPU is a LOUD, reason-recording
    /// degrade, never a silent SIMD swap: a missing matcher/backend or a failed
    /// dispatch records the concrete cause in `gpu_last_degrade_reason` and routes
    /// through `deny_silent_gpu_degrade_with_reason`, which hard-fails under forced
    /// `KEYHOG_BACKEND` / `KEYHOG_REQUIRE_GPU` and otherwise emits the one-shot
    /// stderr warning (suppressed only on `KEYHOG_NO_GPU` / CI, where CPU is the
    /// correct path). The degraded trigger set comes from the backend that is
    /// actually live — SIMD prefilter if compiled, else pure-CPU AC (Law 10).
    fn collect_triggered_patterns_gpu(&self, text: &str, backend: ScanBackend) -> Vec<u64> {
        // Loud, recall-preserving degrade off the per-chunk GPU trigger path.
        let degrade = |reason: String| -> Vec<u64> {
            if let Ok(mut slot) = self.gpu_last_degrade_reason.lock() {
                *slot = Some(reason.clone());
            }
            super::gpu_forced::deny_silent_gpu_degrade_with_reason(self, backend, Some(&reason));
            self.collect_triggered_patterns_simd(text)
        };

        let Some(matcher) = self.gpu_matcher() else {
            return degrade("gpu literal matcher not built for this scanner".to_string());
        };
        let Some(gpu_backend) = self.gpu_backend.as_ref() else {
            return degrade("no gpu backend acquired for per-chunk trigger dispatch".to_string());
        };
        // Use the PRESENCE-bitmap dispatch, not the match-triple `scan`. Phase-1
        // only needs WHICH literal patterns fired (it discards positions one
        // line below in `triggered_patterns_from_gpu_presence`), so the triple
        // path was pure waste: it atomic-appended an (id,start,end) triple per
        // hit and read them all back, which on match-dense source collapses GPU
        // throughput ~888x (measured: 2.3 MB/s triples vs 2047 MB/s presence on
        // a 5090). The presence bitmap is strictly >= the triple triggers: it
        // has NO match cap, whereas `scan(.., 10000)` truncated at 10k hits and
        // could drop a pattern id beyond the cap. Same per-pattern-id mapping
        // (`mark_triggered_pattern`), so the trigger set is recall-identical-or-
        // -better. Validated by `gpu_presence_trigger_parity`.
        match matcher.scan_presence(&**gpu_backend, text.as_bytes()) {
            Ok(presence) => {
                // Union with the AC literal triggers for the same
                // soundness reason as the SIMD path: the GPU literal
                // matcher must not be the sole gate for literal-anchored
                // patterns, or context-anchored detectors with large
                // bounded-repeat bodies silently never fire on GPU.
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
            // The trigger bitmap is the UNION of two INCOMPARABLE prefilters,
            // not one superset of the other. PERF-simd_scan-1 proposed dropping
            // the Hyperscan scan on the theory that "AC ⊇ HS so HS is pure
            // overhead" — that is FALSE and the inversion silently regressed
            // ~30 context-anchored detectors (twilio / sendgrid / slack-bot /
            // digitalocean / …) on contracts_runner. Do NOT re-derive it.
            //
            //   * AC \ HS ≠ ∅: Hyperscan compiles some patterns (a context
            //     anchor + a large `{100,200}` bounded repeat — line / paloalto
            //     / tower / keystonejs / snowflake / bandwidth) without erroring
            //     yet never reports a match at scan time, so the AC literal seed
            //     is what makes them fire. (This is all the old comment claimed.)
            //   * HS \ AC ≠ ∅: the AC sweep marks pattern `i` only when its
            //     EXTRACTED literal appears, but for patterns whose literal is
            //     not a *required* substring of every match (alternations,
            //     optional-literal bodies) Hyperscan's full-regex scan fires
            //     where the AC literal is absent. These are exactly the detectors
            //     the inversion lost.
            //
            // The sets are incomparable, so neither prefilter alone is sound;
            // the union is load-bearing for recall. Precision is unchanged —
            // every triggered candidate is still confirmed by its full regex in
            // `extract_confirmed_patterns`. (Patterns Hyperscan cannot compile
            // are rerouted to the keyword fallback at construction; see compile.rs
            // `unsupported_ac`.) The GPU path unions for the identical reason.
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
        let mut triggered_patterns = super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
        if let Some(ac) = &self.ac {
            for ac_match in ac.find_iter(text.as_bytes()) {
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
