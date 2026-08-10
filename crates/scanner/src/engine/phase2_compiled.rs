//! `impl CompiledScanner` phase-2 capture/prefilter scan methods, extracted from
//! `phase2.rs`. The `CompiledScanner` struct is defined in `mod.rs`; this is a
//! satellite impl block reached via `use super::*`. Shared toggle/profiling
//! helpers and `ActivePatternsScratch` live in `phase2.rs` (pub(crate)) and are
//! glob-imported below. Pure move, no behaviour change.
use super::phase2::*;
use super::phase2_truncate::{
    focus_ceil_boundary, focus_floor_boundary, regex_prefix_anchorable, truncate_src,
};
use super::*;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

impl CompiledScanner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_phase2_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<()> {
        if crate::deadline::expired(deadline) {
            return Ok(());
        }

        // Shared-anchor fast path: one Aho-Corasick pass over all eligible
        // patterns' required-prefix literals yields candidate positions, each
        // verified by an anchored regex - replacing each pattern's own
        // whole-chunk walk. Recall-identical (see `phase2_anchor`); handles
        // any chunk size, so it supersedes the small/large split below. Active
        // patterns with no required-literal anchor keep the whole-chunk path
        // inside `scan_phase2_with_anchors`.
        if !self.phase2_patterns.is_empty() && self.tuning.phase2_anchor_enabled() {
            if let Some(anchor_idx) = &self.phase2_anchor_index {
                return self.scan_phase2_with_anchors(
                    anchor_idx,
                    preprocessed,
                    line_index,
                    chunk,
                    scan_state,
                    deadline,
                    None,
                    phase2_keyword_hints,
                    phase2_always_active_gpu_evidence,
                    route,
                );
            }
        }

        if preprocessed.text.len() > LARGE_FALLBACK_SCAN_THRESHOLD
            && !self.phase2_patterns.is_empty()
        {
            return self.scan_large_phase2_patterns(
                preprocessed,
                line_index,
                chunk,
                scan_state,
                deadline,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            );
        }
        let prof = phase2_pattern_prof_enabled();
        self.with_active_phase2_patterns(
            &preprocessed.text,
            &preprocessed.text,
            phase2_keyword_hints,
            phase2_always_active_gpu_evidence,
            route,
            |this, active_patterns| {
                // `active_patterns` is the SPARSE list of active phase-2 indices,
                // so we touch only the patterns that can fire on this chunk rather
                // than the full `phase2_patterns.len()` vector.
                this.extract_active_phase2_patterns(
                    active_patterns,
                    preprocessed,
                    line_index,
                    chunk,
                    scan_state,
                    deadline,
                    prof,
                );
            },
        )?;
        Ok(())
    }

    /// Decode-recursion FOCUS variant of `scan_phase2_patterns`. A decode
    /// sub-chunk is a small window of already-scanned parent context with the
    /// freshly decoded text spliced in at `focus = (start, end)`. Everything
    /// outside `[start,end)` was scanned (and any finding deduped against
    /// `seen`) when the parent chunk was scanned, so the only NEW phase-2
    /// matches are those that touch the decoded text.
    ///
    /// This windows the always-active prefilter and per-pattern extraction while
    /// keeping full-splice signals (`keyword_nearby`, keyword index, line/context
    /// tables, base offsets) so matches starting inside the focus window stay
    /// byte-identical to the whole-splice scan (`decode_focus_parity`).
    ///
    /// PRECONDITION: `preprocessed.text` must be byte-aligned with `chunk.data`
    /// (the homoglyph-normalisation no-op passthrough), so `focus`: computed in
    /// `chunk.data` coordinates, indexes `preprocessed.text` correctly. The
    /// caller checks this; a non-passthrough chunk takes the full-scan path.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_phase2_patterns_focused(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        focus: (usize, usize),
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<()> {
        if crate::deadline::expired(deadline) {
            return Ok(());
        }
        if self.phase2_patterns.is_empty() {
            return Ok(());
        }
        let text: &str = &preprocessed.text;
        // Expand the decoded span by the margin and snap to char boundaries.
        let fs = focus_floor_boundary(text, focus.0.saturating_sub(DECODE_FOCUS_MARGIN));
        let fe = focus_ceil_boundary(
            text,
            focus.1.saturating_add(DECODE_FOCUS_MARGIN).min(text.len()),
        );
        if fs >= fe {
            return Ok(());
        }
        // If the focus window already covers (almost) the whole chunk, the
        // restriction buys nothing, run the normal path so we don't pay the
        // extra slice setup for no gain.
        if fe - fs >= text.len() {
            return self.scan_phase2_patterns(
                preprocessed,
                line_index,
                chunk,
                scan_state,
                deadline,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            );
        }
        let focus = Some((fs, fe));

        // Prefer the optimized shared-anchor path (the default), now focus-aware:
        // its AC candidate scan + always-active prefilter run over the window
        // while signals/lines stay full. This is what makes the restriction a net
        // win, the non-anchor whole-chunk prefilter, even windowed, barely beats
        // the anchor path on full text.
        if self.tuning.phase2_anchor_enabled() {
            if let Some(anchor_idx) = &self.phase2_anchor_index {
                return self.scan_phase2_with_anchors(
                    anchor_idx,
                    preprocessed,
                    line_index,
                    chunk,
                    scan_state,
                    deadline,
                    focus,
                    phase2_keyword_hints,
                    phase2_always_active_gpu_evidence,
                    route,
                );
            }
        }

        // Anchor index unavailable: prefilter the focus slice, seed the keyword
        // index from normalized full text, and cursor-bound extraction to the window.
        let match_text = &text[fs..fe];
        let cursor = focus;
        let prof = phase2_pattern_prof_enabled();
        self.with_active_phase2_patterns(
            &preprocessed.text,
            match_text,
            phase2_keyword_hints,
            phase2_always_active_gpu_evidence,
            route,
            |this, active_patterns| {
                for (tested, &index) in active_patterns.iter().enumerate() {
                    if crate::deadline::expired_on_cadence(
                        deadline,
                        tested,
                        crate::deadline::COMPILED_PHASE2_DEADLINE_CADENCE,
                    ) {
                        break;
                    }
                    let (entry, _keywords) = &this.phase2_patterns[index];
                    let t0 = if prof { Some(Instant::now()) } else { None };
                    this.extract_matches_inner(
                        entry,
                        preprocessed,
                        line_index,
                        chunk,
                        scan_state,
                        cursor,
                        deadline,
                    );
                    if let Some(t0) = t0 {
                        phase2_pattern_prof_record(
                            this.phase2_patterns.len(),
                            index,
                            t0.elapsed().as_nanos() as u64,
                        );
                    }
                }
            },
        )?;
        Ok(())
    }

    /// Compute the active phase-2 set into the thread-local pool, run the
    /// caller's closure with a borrow of the SPARSE active-index list, and
    /// return whatever the closure returns. The scratch is reset (not freed)
    /// on entry, so the next chunk the same worker handles reuses the
    /// allocation. The closure receives `&[usize]` - the phase-2 indices
    /// that are active for this chunk, so it visits only those patterns
    /// rather than the full `phase2_patterns.len()` vector.
    /// `data` seeds the keyword-AC prefilter.
    /// `match_text` is the always-active RegexSet prefilter text and must match
    /// extraction text so prefiltering is sound under unicode normalization.
    fn with_active_phase2_patterns<R>(
        &self,
        data: &str,
        match_text: &str,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        route: crate::ScanExecutionRoute,
        f: impl FnOnce(&Self, &[usize]) -> R,
    ) -> crate::error::Result<R> {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.begin(self.phase2_patterns.len())?;
            // anchor_mode = false: the legacy whole-chunk path has no AC gating,
            // so every always-active pattern must be marked for recall.
            self.populate_active_phase2(
                data,
                match_text,
                &mut scratch,
                false,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            );
            if self.tuning.phase2_reverse_enabled() {
                scratch.active.reverse();
            }
            Ok(f(self, &scratch.active))
        })
    }

    /// True iff scanning `data` through the phase-2 path would activate at
    /// least one pattern, i.e. the always-active RegexSet prefilter marks a
    /// pattern OR a phase-2 keyword occurs in `data`.
    ///
    /// This is the EXACT, cheap necessary condition for a phase-2 match and is
    /// the recall-load-bearing admission gate for no-Hyperscan-hit chunks (see
    /// `should_scan_no_hit_chunk`): without it, a chunk that fires no literal
    /// prefix but contains a prefix-less / keyword-less detector (asana-pat and
    /// ~3100 similar, issue #69) is silently dropped (Law 10).
    ///
    /// It runs the SAME `populate_active_phase2` the production scan runs, so
    /// it can never admit a chunk the scan then finds inert nor reject one the
    /// scan would mark (admission and extraction share one active-set contract).
    /// Note the earlier coarse form short-circuited to `true` whenever ANY
    /// always-active pattern existed (so it answered "is there unconditional
    /// phase-2 work?", admitting EVERY chunk); running the prefilter answers the
    /// per-chunk question instead, which is what no-hit admission needs.
    //
    // Every backend uses this admission proof before the phase-2 tail so a
    // no-hit chunk cannot bypass anchorless detection.
    pub(crate) fn has_active_phase2_patterns_for_chunk(
        &self,
        data: &str,
        route: crate::ScanExecutionRoute,
    ) -> bool {
        if self.phase2_patterns.is_empty() {
            return false;
        }
        // No keyword index compiled => `populate_active_phase2` marks EVERY
        // phase-2 pattern (its `else` arm), so the answer is unconditionally
        // yes; skip the scan.
        let Some(keyword_index) = &self.route_classification.phase2_keyword_index else {
            return true;
        };
        // Boolean admission: does any phase-2 keyword OR any always-active
        // prefilter pattern fire on this chunk? This is the SAME union the
        // production scan marks (`populate_active_phase2`, `anchor_mode=false`,
        // `match_text == data`), but each side EARLY-EXITS at its first hit
        // instead of building the full marked set. Building that set is the
        // measured #1 scan cost (`phase2:prefilter`), and extraction rebuilds it
        // when the chunk is admitted, so the gate's own marked set was pure
        // redundant work. The compact keyword index is tried first, so a
        // keyword-admitted chunk skips the prefilter scan entirely.
        {
            let _g = super::profile::span(keyhog_profile::Stage::Phase2KeywordAc);
            for keyword_idx in keyword_index.find_iter(data) {
                if self
                    .phase2_keyword_to_patterns
                    .get(keyword_idx)
                    .is_some_and(|patterns| !patterns.is_empty())
                {
                    return true;
                }
            }
        }
        // Markerless single-line blobs without phase-2 keywords cannot usefully
        // run always-active presence scans: every opaque alphanumeric token
        // looks like a candidate and the non-anchorable set over-admits. Keyword
        // hits above still admit; Stripe-style anchored secrets keep working.
        if super::scan::text_is_dense_markerless_single_line(data) {
            return false;
        }
        let _g = super::profile::span(keyhog_profile::Stage::Phase2Prefilter);
        match &self.phase2_always_active_prefilter {
            Some(prefilter) => {
                let tuning = self.tuning.resolve();
                prefilter.any_active_match(
                    &self.phase2_patterns,
                    data,
                    &tuning,
                    route.owns_hyperscan_phase2(),
                )
            }
            // No always-active prefilter compiled (degraded build): there is no
            // discriminating prefilter to run, so defer to the REAL marking path
            // (`populate_active_phase2`, anchor_mode = false) and admit iff it
            // produces an active pattern, exactly what the production scan would
            // mark for this chunk. Never a coarse count short-circuit over the
            // always-active index set (that admits EVERY chunk and defeats no-hit
            // admission; see `phase2_always_active_sparse`).
            None => ACTIVE_PATTERNS_POOL.with(|cell| {
                let mut scratch = cell.borrow_mut();
                if scratch.begin(self.phase2_patterns.len()).is_err() {
                    return true;
                }
                self.populate_active_phase2(data, data, &mut scratch, false, None, None, route);
                !scratch.active.is_empty()
            }),
        }
    }

    /// True iff `idx` is an eligible always-active pattern handled by the shared
    /// anchor AC (and therefore excluded from the RegexSet prefilter).
    #[inline]
    fn anchor_always_active_eligible(&self, idx: usize) -> bool {
        self.phase2_anchor_index
            .as_ref()
            .is_some_and(|a| a.is_always_active_eligible(idx))
    }

    fn validated_phase2_gpu_candidates<'a>(
        &self,
        evidence: Phase2AlwaysActiveGpuEvidence<'a>,
    ) -> Option<(&'a [u32], &'a [u32])> {
        if !evidence.prefixless_complete {
            return None;
        }
        let (bits, map) = evidence.prefixless_candidates()?;
        let any_candidate = bits.iter().any(|&word| word != 0);
        if any_candidate != evidence.prefixless_admitted {
            return None;
        }
        let mut prior_phase2_index = None;
        for (slot, &phase2_index) in map.iter().enumerate() {
            let bit_is_set = bits
                .get(slot / u32::BITS as usize)
                .is_some_and(|word| word & (1u32 << (slot % u32::BITS as usize)) != 0);
            if phase2_index == u32::MAX {
                if bit_is_set {
                    return None;
                }
                continue;
            }
            let phase2_index = phase2_index as usize;
            let Some((pattern, _)) = self.phase2_patterns.get(phase2_index) else {
                return None;
            };
            if self
                .phase2_always_active_indices
                .binary_search(&phase2_index)
                .is_err()
                || pattern.homoglyph_variant
                || super::phase2::gate_prefix_literals(pattern.regex.as_str()).is_some()
                || prior_phase2_index.is_some_and(|prior| prior >= phase2_index)
            {
                return None;
            }
            prior_phase2_index = Some(phase2_index);
        }
        let expected = self
            .phase2_always_active_indices
            .iter()
            .copied()
            .filter(|&index| {
                let pattern = &self.phase2_patterns[index].0;
                !pattern.homoglyph_variant
                    && super::phase2::gate_prefix_literals(pattern.regex.as_str()).is_none()
            });
        let actual = map
            .iter()
            .copied()
            .filter(|&index| index != u32::MAX)
            .map(|index| index as usize);
        if !expected.eq(actual) {
            return None;
        }
        Some((bits, map))
    }

    pub(crate) fn phase2_prefixless_gpu_absence_proven(
        &self,
        evidence: Phase2AlwaysActiveGpuEvidence<'_>,
    ) -> bool {
        self.validated_phase2_gpu_candidates(evidence).is_some() && !evidence.prefixless_admitted
    }

    /// Compute the active phase-2 set. `anchor_mode` selects how always-active
    /// patterns are gated:
    ///   * `true` (shared-anchor path): the RegexSet prefilter covers only the
    ///     NON-eligible always-active patterns; eligible ones are gated later by
    ///     the shared AC (see `scan_phase2_with_anchors`), so they are NOT
    ///     marked here. This is the ~10x-smaller prefilter that is the win.
    ///   * `false` (legacy whole-chunk path): every always-active pattern is
    ///     marked (the reduced prefilter doesn't cover the eligible ones, and
    ///     there is no AC gating on this path), so recall is preserved.
    pub(crate) fn populate_active_phase2(
        &self,
        data: &str,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
        anchor_mode: bool,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        route: crate::ScanExecutionRoute,
    ) {
        let gpu_candidates = phase2_always_active_gpu_evidence
            .and_then(|evidence| self.validated_phase2_gpu_candidates(evidence));
        let cpu_prefilter_required = gpu_candidates.is_none()
            || self.phase2_always_active_indices.iter().any(|&index| {
                let pattern = &self.phase2_patterns[index].0;
                let covered = !pattern.homoglyph_variant
                    && super::phase2::gate_prefix_literals(pattern.regex.as_str()).is_none();
                !covered && !(anchor_mode && self.anchor_always_active_eligible(index))
            });
        if let Some(keyword_index) = &self.route_classification.phase2_keyword_index {
            // Always-active patterns (no >=4-char keyword) would each run their
            // capture regex over the whole chunk. Gate them through a combined
            // RegexSet so only patterns that can actually match are activated;
            // the rest extract nothing and are dead work. The set is built with
            // each pattern's own flags, so this drops cost, never recall. When
            // the set could not be compiled, fall back to marking all of them.
            // The always-active prefilter marks the patterns that can fire. Its
            // plain (homoglyph) batches use a fast ASCII-folded alternate on
            // pure-ASCII chunks (identical marking, far faster) (the perf win).
            // When anchor localization is on, the prefilter covers only the
            // non-eligible always-active set (eligible ones are handled by the
            // shared AC); on the legacy path every always-active pattern must be
            // marked, so a `None` prefilter falls back to marking them all.
            // On the shared-anchor path, plain (homoglyph) patterns are handled
            // by the localized AC on ASCII chunks, so the prefilter skips them.
            let localize_plain = anchor_mode
                && self
                    .phase2_anchor_index
                    .as_ref()
                    .is_some_and(|a| a.has_plain_localizer(route.phase2_plain_localizer));
            let mut tuning = self.tuning.resolve();
            tuning.fallback_localizer = route.phase2_plain_localizer;
            // No stopwatch: the prefilter span below IS this interval, and the
            // keyword span below covers both marking routes. Two process-wide
            // `AtomicU64`s used to re-time exactly these two regions.
            {
                // The anchorless always-active RegexSet, the detectors that run
                // on EVERY chunk. This span is the cost the old vague label hid.
                let _g = super::profile::span(keyhog_profile::Stage::Phase2Prefilter);
                if cpu_prefilter_required {
                    #[cfg(debug_assertions)]
                    self.phase2_prefilter_scanned_bytes.fetch_add(
                        // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                        u64::try_from(match_text.len()).unwrap_or(u64::MAX),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    match &self.phase2_always_active_prefilter {
                        Some(prefilter) => prefilter.mark_matches(
                            &self.phase2_patterns,
                            match_text,
                            scratch,
                            anchor_mode,
                            localize_plain,
                            &tuning,
                            route.owns_hyperscan_phase2(),
                        ),
                        None => {
                            for &index in &self.phase2_always_active_indices {
                                if anchor_mode && self.anchor_always_active_eligible(index) {
                                    continue;
                                }
                                scratch.mark(index);
                            }
                        }
                    }
                }
            }
            {
                // Covers BOTH marking routes. The span used to sit only on the
                // Aho-Corasick branch, so the keyword-hint fast path (the GPU
                // route) contributed nothing to `phase2-keyword-ac` and its
                // cost was visible only through a private atomic.
                let _g = super::profile::span(keyhog_profile::Stage::Phase2KeywordAc);
                if let Some(keyword_hints) = phase2_keyword_hints {
                    for &keyword_idx in keyword_hints {
                        if let Some(pattern_indices) =
                            self.phase2_keyword_to_patterns.get(keyword_idx as usize)
                        {
                            for &pattern_idx in pattern_indices {
                                scratch.mark(pattern_idx as usize);
                            }
                        }
                    }
                } else {
                    #[cfg(debug_assertions)]
                    self.phase2_keyword_scanned_bytes.fetch_add(
                        // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                        u64::try_from(data.len()).unwrap_or(u64::MAX),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    for keyword_idx in keyword_index.find_iter(data) {
                        if let Some(pattern_indices) =
                            self.phase2_keyword_to_patterns.get(keyword_idx)
                        {
                            for &pattern_idx in pattern_indices {
                                scratch.mark(pattern_idx as usize);
                            }
                        }
                    }
                }
            }
        } else {
            // No keyword prefilter compiled - every phase-2 pattern is
            // considered active.
            if cpu_prefilter_required {
                for index in 0..self.phase2_patterns.len() {
                    scratch.mark(index);
                }
            }
        }
        if let Some((bits, map)) = gpu_candidates {
            scratch.remove_indices(map);
            for (slot, &phase2_index) in map.iter().enumerate() {
                if phase2_index == u32::MAX
                    || bits[slot / u32::BITS as usize] & (1u32 << (slot % u32::BITS as usize)) == 0
                {
                    continue;
                }
                let phase2_index = phase2_index as usize;
                if !anchor_mode || !self.anchor_always_active_eligible(phase2_index) {
                    scratch.mark(phase2_index);
                }
            }
        }
    }

    /// Run per-pattern phase-2 extraction over the SPARSE active set: the
    /// deadline-cadence (`is_multiple_of(16)`) + per-pattern profiling loop that
    /// the small-chunk (`scan_phase2_patterns`) and large-chunk
    /// (`scan_large_phase2_patterns`) whole-chunk paths share. Keeping it in one
    /// place means the abort cadence and profiling stay in lockstep between the
    /// two paths. (The decode-focus path keeps its own loop because it is
    /// cursor-bounded via `extract_matches_inner`. Whole-chunk callers pass an
    /// explicit `None` range to the same owner.)
    #[allow(clippy::too_many_arguments)]
    fn extract_active_phase2_patterns(
        &self,
        active_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        prof: bool,
    ) {
        for (tested, &index) in active_patterns.iter().enumerate() {
            if crate::deadline::expired_on_cadence(
                deadline,
                tested,
                crate::deadline::COMPILED_PHASE2_DEADLINE_CADENCE,
            ) {
                break;
            }
            let (entry, _) = &self.phase2_patterns[index];
            let t0 = if prof { Some(Instant::now()) } else { None };
            self.extract_matches_inner(
                entry,
                preprocessed,
                line_index,
                chunk,
                scan_state,
                None,
                deadline,
            );
            if let Some(t0) = t0 {
                phase2_pattern_prof_record(
                    self.phase2_patterns.len(),
                    index,
                    t0.elapsed().as_nanos() as u64,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_large_phase2_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<()> {
        let prof = phase2_pattern_prof_enabled();
        self.with_active_phase2_patterns(
            &preprocessed.text,
            &preprocessed.text,
            phase2_keyword_hints,
            phase2_always_active_gpu_evidence,
            route,
            |this, active_set| {
                // `active_set` is the sparse list of active phase-2 indices, so
                // we iterate only the patterns that can fire - no second
                // `Vec<&CompiledPattern>` collect and no scan over the inactive
                // entries of the full phase-2 vector.
                this.extract_active_phase2_patterns(
                    active_set,
                    preprocessed,
                    line_index,
                    chunk,
                    scan_state,
                    deadline,
                    prof,
                );
            },
        )?;
        Ok(())
    }

    /// Print and reset the per-pattern phase-2 profile (top 30 by time). Call
    /// after a unified profile run (`keyhog scan --profile`). Each line is the
    /// phase-2 detector's regex, total ms, run count, and ns/run, plus whether
    /// it carries a regex-required prefix anchor (the localization candidate).
    pub(crate) fn phase2_profile_dump(&self, label: &str) {
        let len = self.phase2_patterns.len();
        let (ns, runs) = phase2_pattern_prof_vecs(len);
        let mut rows: Vec<(usize, u64, u64)> = (0..len)
            .map(|i| (i, ns[i].swap(0, Relaxed), runs[i].swap(0, Relaxed)))
            .filter(|&(_, n, _)| n > 0)
            .collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        let grand: u64 = rows.iter().map(|r| r.1).sum();
        eprintln!(
            "=== PHASE2 per-pattern profile [{label}] ===\n  populate: see the `phase2-prefilter` and `phase2-keyword-ac` rows of the profile tree\n  extract: {:.1} ms over {} active patterns\n  route: [ELIG]=compiled shared-anchor eligible, [PREFIX]=prefix-shaped but not anchor-eligible in this scanner",
            grand as f64 / 1e6,
            rows.len()
        );
        let anchor_idx = self.phase2_anchor_index.as_ref();
        for (i, n, r) in rows.iter().take(30) {
            let src = self.phase2_patterns[*i].0.regex.as_str();
            let route = if anchor_idx.is_some_and(|idx| idx.is_eligible(*i)) {
                "ELIG"
            } else if regex_prefix_anchorable(src) {
                "PREFIX"
            } else {
                "  --  "
            };
            let per_run = if *r > 0 { *n / *r } else { 0 };
            eprintln!(
                "  {:>6.1}ms {:>5.1}%  runs={:<6} {:>7}ns/run  [{}] {}",
                *n as f64 / 1e6,
                100.0 * *n as f64 / grand.max(1) as f64,
                r,
                per_run,
                route,
                truncate_src(src, 64),
            );
        }
    }

    pub(crate) fn phase2_profile_reset(&self) {
        phase2_pattern_prof_reset(self.phase2_patterns.len());
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_phase2_keyword_scanned_bytes_for_diagnostics(&self) {
        self.phase2_keyword_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn phase2_keyword_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.phase2_keyword_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_phase2_prefilter_scanned_bytes_for_diagnostics(&self) {
        self.phase2_prefilter_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn phase2_prefilter_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.phase2_prefilter_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
