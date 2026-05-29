use super::*;
use crate::context;
use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    /// Per-thread pool for the `active_fallback_patterns` bitmap.
    ///
    /// Every fallback scan previously did `vec![false; self.fallback.len()]` -
    /// a fresh allocation per chunk. With ~1000 fallback patterns and a
    /// 100k-file scan, that's a million tiny allocations hammering the
    /// global allocator across rayon workers. Pool one buffer per worker;
    /// it's resized once and resliced thereafter.
    static ACTIVE_PATTERNS_POOL: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
}

impl CompiledScanner {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn scan_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                return;
            }
        }

        if preprocessed.text.len() > LARGE_FALLBACK_SCAN_THRESHOLD && !self.fallback.is_empty() {
            self.scan_large_fallback_patterns(
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                deadline,
            );
            return;
        }
        self.with_active_fallback_patterns(&chunk.data, |this, active_patterns| {
            for (index, (entry, _keywords)) in this.fallback.iter().enumerate() {
                if !active_patterns[index] {
                    continue;
                }
                if let Some(deadline) = deadline {
                    if index.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                this.extract_matches(
                    entry,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    0,
                    0,
                    deadline,
                );
            }
        });
    }

    /// Compute the active-fallback bitmap into the thread-local pool, run the
    /// caller's closure with a borrow, and return whatever the closure
    /// returns. The bitmap is reset (not freed) on exit, so the next chunk
    /// the same worker handles reuses the allocation.
    fn with_active_fallback_patterns<R>(
        &self,
        data: &str,
        f: impl FnOnce(&Self, &[bool]) -> R,
    ) -> R {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut buf = cell.borrow_mut();
            buf.clear();
            buf.resize(self.fallback.len(), false);
            self.populate_active_fallback(data, &mut buf);
            f(self, &buf)
        })
    }

    fn populate_active_fallback(&self, data: &str, active: &mut [bool]) {
        debug_assert_eq!(active.len(), self.fallback.len());
        if let Some(keyword_ac) = &self.fallback_keyword_ac {
            // Seed the bitmap from the precomputed `fallback_always_active`
            // table - this collapses the previous `O(F × K)` per-chunk loop
            // (walking each pattern's keywords looking for any ≥4-char
            // entry) into one `copy_from_slice`. The table is built once
            // at scanner construction.
            let always = &self.fallback_always_active;
            debug_assert_eq!(always.len(), active.len());
            active.copy_from_slice(always);
            for mat in keyword_ac.find_iter(data) {
                let keyword_idx = mat.pattern().as_usize();
                if keyword_idx < self.fallback_keyword_to_patterns.len() {
                    for &pattern_idx in &self.fallback_keyword_to_patterns[keyword_idx] {
                        if pattern_idx < active.len() {
                            active[pattern_idx] = true;
                        }
                    }
                }
            }
        } else {
            // No keyword prefilter compiled - every fallback pattern is
            // considered active. `slice::fill` lowers to a memset.
            active.fill(true);
        }
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    fn scan_large_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        self.with_active_fallback_patterns(&chunk.data, |this, active_set| {
            // Walk in fallback-index order without the prior `Vec<&CompiledPattern>`
            // collect step - the bitmap already encodes which entries are
            // active and we don't need a second allocation just to filter.
            let mut tested: usize = 0;
            for (index, (entry, _)) in this.fallback.iter().enumerate() {
                if !active_set[index] {
                    continue;
                }
                if let Some(deadline) = deadline {
                    if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                this.extract_matches(
                    entry,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    0,
                    0,
                    deadline,
                );
                tested += 1;
            }
        });
    }

    pub(crate) fn match_companions(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText,
        line: usize,
    ) -> Option<HashMap<String, String>> {
        let mut results = HashMap::new();
        if let Some(detector_companions) = self.companions.get(entry.detector_index) {
            for companion in detector_companions {
                if let Some(val) = find_companion(preprocessed, line, companion) {
                    results.insert(companion.name.clone(), val);
                } else if companion.required {
                    return None;
                }
            }
        }
        Some(results)
    }

    pub(crate) fn match_confidence<'a>(
        &self,
        entry: &CompiledPattern,
        chunk: &Chunk,
        credential: &'a str,
        data: &'a str,
        line: usize,
        entropy: f64,
        has_companion: bool,
        // The context is computed once in `process_match` (where the
        // suppression checks already need it) and threaded through -
        // halves the per-match context-inference work.
        context: context::CodeContext,
        // `keyword_nearby` and `sensitive_file` are constant across
        // every match of a single (chunk, pattern) pair: keyword_nearby
        // depends only on the detector + chunk text, sensitive_file
        // only on the chunk's path. Hoisted to `extract_matches`'s
        // pre-loop preamble so the inner per-match path doesn't keep
        // re-running an O(K) substring scan over the whole chunk +
        // an Aho-Corasick scan over the path.
        keyword_nearby: bool,
        sensitive_file: bool,
        // True when the firing detector is service-anchored (not generic-* /
        // entropy-* / private-key). Such a detector's regex is itself the
        // positive evidence, so the generic probabilistic-promise gate must
        // not bury it - see the rationale in `process_match`.
        is_named_detector: bool,
        scan_state: &mut ScanState,
    ) -> Option<MlScoreResult<'a>> {
        let raw_conf =
            crate::confidence::compute_confidence(&crate::confidence::ConfidenceSignals {
                has_literal_prefix: extract_literal_prefix(entry.regex.as_str()).is_some(),
                has_context_anchor: entry.group.is_some(),
                entropy,
                keyword_nearby,
                sensitive_file,
                match_length: credential.len(),
                has_companion,
            });

        // Checksum validation is handled in process_match (early reject for Invalid,
        // confidence floor for Valid). No need to re-validate here.
        let heuristic_conf = raw_conf * context.confidence_multiplier();
        let score_result = self.calculate_final_score(
            heuristic_conf,
            context,
            credential,
            data,
            line,
            chunk,
            is_named_detector,
            scan_state,
        )?;

        match score_result {
            MlScoreResult::Final(confidence) => {
                let final_score = if let Some(floor) =
                    crate::confidence::known_prefix_confidence_floor(credential)
                {
                    confidence.max(floor)
                } else {
                    confidence
                };

                if context.should_hard_suppress(final_score) {
                    None
                } else {
                    Some(MlScoreResult::Final(final_score))
                }
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending { .. } => Some(score_result),
            #[cfg(not(feature = "ml"))]
            MlScoreResult::_Lifetime(_) => {
                unreachable!("_Lifetime is a never-constructed placeholder variant")
            }
        }
    }

    fn calculate_final_score<'a>(
        &self,
        heuristic_conf: f64,
        context: context::CodeContext,
        credential: &'a str,
        data: &'a str,
        line: usize,
        chunk: &Chunk,
        is_named_detector: bool,
        _scan_state: &mut ScanState,
    ) -> Option<MlScoreResult<'a>> {
        #[cfg(not(feature = "ml"))]
        {
            let _ = (context, credential, data, line, chunk, is_named_detector);
            Some(MlScoreResult::Final(heuristic_conf))
        }

        #[cfg(feature = "ml")]
        {
            if !self.config.ml_enabled {
                return Some(MlScoreResult::Final(heuristic_conf));
            }

            // The probabilistic-promise gate fast-rejects low-diversity /
            // UUID / structured strings to 0.1 (below the 0.3 report floor).
            // That is correct for generic-* / entropy-* detectors - their
            // only evidence is shape - but a NAMED service-anchored detector
            // proved via its own regex that these bytes are the credential
            // (Heroku / Braze / Codecov / Consul / Linode UUID & hex keys).
            // generic-no-prefix-not-promising matches were already dropped
            // upstream in `process_match`, so the only hits reaching here with
            // `!looks_promising` are named detectors or known-prefix generics.
            if !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential) {
                // A named detector bypasses the 0.1 slam ONLY for genuinely
                // structured secrets (UUID / hex / random tokens). A weak-prefix
                // detector (e.g. stackblitz `sb_[A-Za-z0-9_-]{20,}`) can still
                // match a CODE IDENTIFIER like `sb_get_string_descriptor` or
                // `SB_ENDPOINT_ADDRESS_MASK` - those are never secrets, so they
                // stay slammed even for named detectors. A UUID/hex credential
                // is never identifier-shaped (digit-only segments, no `_`/`-`
                // word structure), so the recall win for the 90+ real
                // structured-key detectors is preserved.
                let identifier_shaped =
                    crate::pipeline::looks_like_word_separated_identifier(credential)
                        || crate::pipeline::looks_like_pure_identifier(credential);
                if !is_named_detector || identifier_shaped {
                    return Some(MlScoreResult::Final(0.1));
                }
            }

            let text_context = local_context_window(data, line, ML_CONTEXT_RADIUS_LINES);
            let ml_context = match chunk.metadata.path.as_deref() {
                Some(path) => format!("file:{path}\n{text_context}"),
                None => text_context,
            };

            Some(MlScoreResult::Pending {
                heuristic_conf,
                code_context: context,
                credential: std::borrow::Cow::Borrowed(credential),
                ml_context: std::borrow::Cow::Owned(ml_context),
            })
        }
    }
}
