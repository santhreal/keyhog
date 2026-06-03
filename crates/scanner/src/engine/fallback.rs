use super::*;
use crate::context;
use std::cell::RefCell;
use std::collections::HashMap;

/// Per-thread scratch for computing the active-fallback set of a chunk.
///
/// Previously this was a dense `Vec<bool>` of `fallback.len()` (~1000) that
/// was zero-filled, `copy_from_slice`-seeded, and then fully iterated by the
/// caller every chunk - O(F) per chunk even when only a handful of patterns
/// fire. We now carry a SPARSE list of active fallback indices instead, so
/// callers visit only the active patterns. Two pieces:
///   * `active`: the sparse index list, refilled (not reallocated) per chunk.
///   * `stamp` + `generation`: a versioned "seen" set used to dedup a pattern
///     that is both always-active and keyword-triggered, without the O(F)
///     per-chunk clear a dense bitmap would need. The generation counter just
///     increments; `stamp` is grown once and reused.
struct ActivePatternsScratch {
    active: Vec<usize>,
    stamp: Vec<u32>,
    generation: u32,
}

impl ActivePatternsScratch {
    const fn new() -> Self {
        Self {
            active: Vec::new(),
            stamp: Vec::new(),
            generation: 0,
        }
    }

    /// Begin a fresh chunk: bump the generation so all previous stamps are
    /// stale, ensure the stamp vector covers `len` patterns, and clear the
    /// sparse list (retaining its capacity). On generation wraparound the
    /// stamp vector is reset so a stale `u32::MAX` stamp can't alias.
    fn begin(&mut self, len: usize) {
        if self.stamp.len() < len {
            self.stamp.resize(len, 0);
        }
        self.generation = self.generation.wrapping_add(1);
        if self.generation == 0 {
            // Wrapped: every stamp must be treated as stale.
            self.stamp.iter_mut().for_each(|s| *s = 0);
            self.generation = 1;
        }
        self.active.clear();
    }

    /// Record `index` as active if it has not already been recorded this
    /// generation. Returns nothing; dedup is silent.
    #[inline]
    fn mark(&mut self, index: usize) {
        if let Some(slot) = self.stamp.get_mut(index) {
            if *slot != self.generation {
                *slot = self.generation;
                self.active.push(index);
            }
        }
    }
}

thread_local! {
    /// Per-thread pool for the active-fallback scratch. Pool one per worker;
    /// it is grown once and reused thereafter (no per-chunk allocation).
    static ACTIVE_PATTERNS_POOL: RefCell<ActivePatternsScratch> =
        const { RefCell::new(ActivePatternsScratch::new()) };
}

impl CompiledScanner {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn scan_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
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
            // `active_patterns` is the SPARSE list of active fallback indices,
            // so we touch only the patterns that can fire on this chunk rather
            // than the full `fallback.len()` vector.
            for (tested, &index) in active_patterns.iter().enumerate() {
                if let Some(deadline) = deadline {
                    if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                let (entry, _keywords) = &this.fallback[index];
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

    /// Compute the active-fallback set into the thread-local pool, run the
    /// caller's closure with a borrow of the SPARSE active-index list, and
    /// return whatever the closure returns. The scratch is reset (not freed)
    /// on entry, so the next chunk the same worker handles reuses the
    /// allocation. The closure receives `&[usize]` - the fallback indices
    /// that are active for this chunk, so it visits only those patterns
    /// rather than the full `fallback.len()` vector.
    fn with_active_fallback_patterns<R>(
        &self,
        data: &str,
        f: impl FnOnce(&Self, &[usize]) -> R,
    ) -> R {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.begin(self.fallback.len());
            self.populate_active_fallback(data, &mut scratch);
            f(self, &scratch.active)
        })
    }

    pub(crate) fn has_active_fallback_patterns_for_chunk(&self, data: &str) -> bool {
        if self.fallback.is_empty() {
            return false;
        }
        if !self.fallback_always_active_indices.is_empty() || self.fallback_keyword_ac.is_none() {
            return true;
        }
        self.with_active_fallback_patterns(data, |_, active_patterns| !active_patterns.is_empty())
    }

    fn populate_active_fallback(&self, data: &str, scratch: &mut ActivePatternsScratch) {
        if let Some(keyword_ac) = &self.fallback_keyword_ac {
            // Seed from the precomputed sparse always-active list. Patterns
            // with no >=4-char keyword run on every admitted fallback chunk;
            // storing their indices directly avoids a full bool-table scan per
            // chunk. Then keyword AC adds patterns whose keyword is present.
            // `mark` dedups if a pattern is both always-active and keyworded.
            for &index in &self.fallback_always_active_indices {
                scratch.mark(index);
            }
            for mat in keyword_ac.find_iter(data) {
                let keyword_idx = mat.pattern().as_usize();
                if let Some(pattern_indices) = self.fallback_keyword_to_patterns.get(keyword_idx) {
                    for &pattern_idx in pattern_indices {
                        scratch.mark(pattern_idx as usize);
                    }
                }
            }
        } else {
            // No keyword prefilter compiled - every fallback pattern is
            // considered active.
            for index in 0..self.fallback.len() {
                scratch.mark(index);
            }
        }
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    fn scan_large_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        self.with_active_fallback_patterns(&chunk.data, |this, active_set| {
            // `active_set` is the sparse list of active fallback indices, so
            // we iterate only the patterns that can fire - no second
            // `Vec<&CompiledPattern>` collect and no scan over the inactive
            // entries of the full fallback vector.
            for (tested, &index) in active_set.iter().enumerate() {
                if let Some(deadline) = deadline {
                    if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                let (entry, _) = &this.fallback[index];
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

    pub(crate) fn match_companions(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText<'_>,
        line: usize,
    ) -> Option<HashMap<String, String>> {
        // Most detectors declare no companions. Return the empty map without
        // sizing a bucket array (`HashMap::new()` is allocation-free until the
        // first insert) and without entering the search loop. Only detectors
        // that actually have companions pay for the map.
        let Some(detector_companions) = self.companions.get(entry.detector_index) else {
            return Some(HashMap::new());
        };
        if detector_companions.is_empty() {
            return Some(HashMap::new());
        }
        let mut results = HashMap::with_capacity(detector_companions.len());
        for companion in detector_companions {
            if let Some(val) = find_companion(preprocessed, line, companion) {
                results.insert(companion.name.clone(), val);
            } else if companion.required {
                return None;
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
        // The fixture opt-out must also bypass this pre-ML context multiplier;
        // otherwise the lower score is baked into `heuristic_conf`.
        let context_multiplier = match context {
            crate::context::CodeContext::TestCode | crate::context::CodeContext::Documentation
                if !self.config.penalize_test_paths =>
            {
                1.0
            }
            _ => context.confidence_multiplier(),
        };
        let heuristic_conf = raw_conf * context_multiplier;
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

                // Keep comment hard-suppression separate from the fixture
                // opt-out; comments stay controlled by `--scan-comments`.
                let hard_suppressed = context.should_hard_suppress(final_score)
                    && (self.config.penalize_test_paths
                        || matches!(context, crate::context::CodeContext::Comment));
                if hard_suppressed {
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
                // `local_context_window` returns `&str`; the Some arm is an
                // owned `String`, and `ml_context` feeds `Cow::Owned` below,
                // so both arms must be `String`.
                None => text_context.to_string(),
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
