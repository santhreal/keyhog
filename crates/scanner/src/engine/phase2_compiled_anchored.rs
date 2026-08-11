//! Shared-anchor localized phase-two scan. One Aho-Corasick pass produces
//! anchored verification candidates while preserving legacy active-set recall.
use super::phase2::*;
use super::*;
use std::time::Instant;

impl CompiledScanner {
    /// Exposes the full active-pattern scratch so shared anchors can test
    /// membership in constant time.
    fn with_active_phase2_scratch<R>(
        &self,
        data: &str,
        match_text: &str,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        route: crate::ScanExecutionRoute,
        f: impl FnOnce(&Self, &ActivePatternsScratch) -> R,
    ) -> crate::error::Result<R> {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.begin(self.phase2_patterns.len())?;
            // Shared anchors gate eligible always-active patterns through AC.
            self.populate_active_phase2(
                data,
                match_text,
                &mut scratch,
                true,
                phase2_keyword_hints,
                phase2_always_active_gpu_evidence,
                route,
            );
            if self.tuning.phase2_reverse_enabled() {
                scratch.active.reverse();
            }
            Ok(f(self, &scratch))
        })
    }

    /// Verify candidates by pattern so each signal cache builds once. Missing
    /// anchored regexes fall back to the cursor-bounded whole-chunk walk, which
    /// preserves recall for both shared-anchor candidate paths.
    #[allow(clippy::too_many_arguments)]
    fn verify_anchored_candidates(
        &self,
        anchor_idx: &phase2_anchor::Phase2AnchorIndex,
        cands: &[(u32, u32)],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        cursor: Option<(usize, usize)>,
        deadline: Option<std::time::Instant>,
        prof: bool,
    ) {
        let mut i = 0usize;
        while i < cands.len() {
            if crate::deadline::expired(deadline) {
                break;
            }
            let pat = cands[i].0 as usize;
            let mut j = i + 1;
            while j < cands.len() && cands[j].0 as usize == pat {
                j += 1;
            }
            let group = &cands[i..j];
            let (entry, _) = &self.phase2_patterns[pat];
            let t0 = if prof { Some(Instant::now()) } else { None };
            match anchor_idx.anchored_regex(pat) {
                Some(re) => self.extract_anchored(
                    entry,
                    re,
                    group,
                    preprocessed,
                    line_index,
                    chunk,
                    scan_state,
                    deadline,
                ),
                None => self.extract_matches_inner(
                    entry,
                    preprocessed,
                    line_index,
                    chunk,
                    scan_state,
                    cursor,
                    deadline,
                ),
            }
            if let Some(t0) = t0 {
                phase2_pattern_prof_record(
                    self.phase2_patterns.len(),
                    pat,
                    t0.elapsed().as_nanos() as u64,
                );
            }
            i = j;
        }
    }

    /// Collect shared-anchor candidates once, verify active eligible patterns at
    /// those offsets, then run active non-eligible patterns through the legacy
    /// whole-chunk path. Together both sets equal the legacy active set.
    ///
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_phase2_with_anchors(
        &self,
        anchor_idx: &phase2_anchor::Phase2AnchorIndex,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        // Window candidate collection and extraction; keep keyword and context
        // signals on full raw and normalized text.
        focus: Option<(usize, usize)>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_gpu_evidence: Option<Phase2AlwaysActiveGpuEvidence<'_>>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<()> {
        let prof = phase2_pattern_prof_enabled();
        // Text the AC candidate scan and the always-active prefilter run on.
        let scan_text: &str = match focus {
            Some((fs, fe)) => &preprocessed.text[fs..fe],
            None => &preprocessed.text,
        };
        let scan_text_is_ascii = scan_text.is_ascii();
        let skip_homoglyph =
            homoglyph_skip_applies(scan_text, self.tuning.homoglyph_ascii_skip_enabled());
        let shift = focus.map_or(0u32, |(fs, _)| fs as u32);
        // Whole-chunk extraction restricts match starts to the focus window.
        // Keyword seeding still uses normalized full text.
        self.with_active_phase2_scratch(
            &preprocessed.text,
            scan_text,
            phase2_keyword_hints,
            phase2_always_active_gpu_evidence,
            route,
            |this, scratch| {
                let pattern_is_live =
                    |pat: usize| !skip_homoglyph || !this.phase2_patterns[pat].0.homoglyph_variant;
                let localize_keyword_anchors = route.phase2_keyword_localizer;
                super::with_candidate_scratch(|candidate_scratch| {
                    let cands = &mut candidate_scratch.candidates;
                    let mut candidates_are_full_text_offsets = false;
                    {
                        let _g = super::profile::span(keyhog_profile::Stage::Phase2SharedAc);
                        if localize_keyword_anchors {
                            anchor_idx.collect_candidates(
                                scan_text,
                                |pat| scratch.is_active(pat),
                                pattern_is_live,
                                cands,
                            );
                        } else if let Some(literal_matches) = phase2_always_active_gpu_evidence
                            .and_then(|evidence| evidence.anchor_literal_matches)
                        {
                            anchor_idx.collect_always_active_candidates_from_literal_matches(
                                literal_matches,
                                pattern_is_live,
                                cands,
                            );
                            if let Some((start, end)) = focus {
                                cands.retain(|&(_, pos)| {
                                    let pos = pos as usize;
                                    pos >= start && pos < end
                                });
                            }
                            candidates_are_full_text_offsets = true;
                        } else if phase2_always_active_gpu_evidence
                            .is_some_and(|evidence| !evidence.anchor_present)
                        {
                            cands.clear();
                        } else {
                            anchor_idx.collect_always_active_candidates(
                                scan_text,
                                pattern_is_live,
                                cands,
                            );
                        }
                    }
                    // Candidate positions are relative to `scan_text`; lift them back
                    // into full-text coordinates so anchored verification indexes the
                    // real (full) `preprocessed.text`.
                    if shift != 0 && !candidates_are_full_text_offsets {
                        for c in cands.iter_mut() {
                            c.1 += shift;
                        }
                    }
                    // Candidates are sorted by (pattern, pos); verify each
                    // pattern's contiguous run together so its per-pattern
                    // signal cache is built at most once.
                    let _verify_g =
                        super::profile::span(keyhog_profile::Stage::Phase2AnchoredVerify);
                    this.verify_anchored_candidates(
                        anchor_idx,
                        &cands[..],
                        preprocessed,
                        line_index,
                        chunk,
                        scan_state,
                        cursor,
                        deadline,
                        prof,
                    );
                });

                // Localized plain-pattern path (ASCII chunks): verify live
                // patterns from folded-literal AC positions. Inert generated
                // homoglyph variants are excluded by the shared predicate; plain
                // fallbacks without a folded literal still run whole-chunk. A
                // complete negative GPU prefixless receipt already covers every
                // live member of this family, so it suppresses the second pass.
                if self.tuning.homoglyph_gate_enabled()
                    && scan_text_is_ascii
                    && anchor_idx.has_plain_localizer(route.phase2_plain_localizer)
                    && !phase2_always_active_gpu_evidence
                        .is_some_and(|evidence| self.phase2_prefixless_gpu_absence_proven(evidence))
                {
                    super::with_candidate_scratch(|candidate_scratch| {
                        let cands = &mut candidate_scratch.candidates;
                        {
                            let _g = super::profile::span(keyhog_profile::Stage::Phase2SharedAc);
                            anchor_idx.collect_plain_candidates(scan_text, pattern_is_live, cands);
                        }
                        if shift != 0 {
                            for c in cands.iter_mut() {
                                c.1 += shift;
                            }
                        }
                        {
                            let _g =
                                super::profile::span(keyhog_profile::Stage::Phase2AnchoredVerify);
                            this.verify_anchored_candidates(
                                anchor_idx,
                                &cands[..],
                                preprocessed,
                                line_index,
                                chunk,
                                scan_state,
                                cursor,
                                deadline,
                                prof,
                            );
                        }
                    });
                    {
                        let _g = super::profile::span(keyhog_profile::Stage::Phase2WholeChunk);
                        for &idx in anchor_idx.plain_always_mark() {
                            if crate::deadline::expired(deadline) {
                                break;
                            }
                            let pat = idx as usize;
                            let (entry, _) = &this.phase2_patterns[pat];
                            if !pattern_is_live(pat) {
                                continue;
                            }
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
                                    pat,
                                    t0.elapsed().as_nanos() as u64,
                                );
                            }
                        }
                    }
                }

                // Active patterns with no required-literal anchor: whole-chunk
                // (windowed to the focus cursor when focus-restricting).
                let _wholechunk_g = super::profile::span(keyhog_profile::Stage::Phase2WholeChunk);
                for (tested, &index) in scratch.active.iter().enumerate() {
                    if localize_keyword_anchors && anchor_idx.is_eligible(index) {
                        continue;
                    }
                    if crate::deadline::expired_on_cadence(
                        deadline,
                        tested,
                        crate::deadline::COMPILED_PHASE2_DEADLINE_CADENCE,
                    ) {
                        break;
                    }
                    let (entry, _) = &this.phase2_patterns[index];
                    if !pattern_is_live(index) {
                        continue;
                    }
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
}
