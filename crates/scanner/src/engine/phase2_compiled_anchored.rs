//! Shared-anchor localized phase-2 scan, extracted from `phase2_compiled.rs`
//! (Law 5). `scan_phase2_with_anchors` (+ its anchor-only scratch helper
//! `with_active_phase2_scratch`) collapses the per-pattern whole-chunk walks
//! into one Aho-Corasick pass plus anchored verification; recall is identical to
//! the legacy active-set loop (`phase2_anchor_parity`). Reached via the same
//! `use super::*` / `use super::phase2::*` globs the parent uses.
use super::phase2::*;
use super::*;
use std::time::Instant;

const KEYWORD_ANCHOR_WHOLE_CHUNK_CUTOFF: usize = 2;

impl CompiledScanner {
    /// As `with_active_phase2_patterns`, but hands the closure the full
    /// `ActivePatternsScratch` (not just the sparse list) so it can also test
    /// `is_active(idx)` in O(1) - the shared-anchor path needs that to gate
    /// candidate positions to the active set.
    fn with_active_phase2_scratch<R>(
        &self,
        data: &str,
        match_text: &str,
        phase2_keyword_hints: Option<&[u32]>,
        f: impl FnOnce(&Self, &ActivePatternsScratch) -> R,
    ) -> R {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.begin(self.phase2_patterns.len());
            // anchor_mode = true: this method only runs on the shared-anchor
            // path, where eligible always-active patterns are gated by the AC.
            self.populate_active_phase2(data, match_text, &mut scratch, true, phase2_keyword_hints);
            if self.tuning.phase2_reverse_enabled() {
                scratch.active.reverse();
            }
            f(self, &scratch)
        })
    }

    /// Verify a run of anchored `(pattern, pos)` candidates, grouped by pattern
    /// (each pattern's contiguous run verified together so its per-pattern signal
    /// cache builds at most once). A pattern whose anchored regex compiled runs
    /// `extract_anchored` at its candidate positions; one whose anchored regex
    /// failed to compile falls back LOUDLY to the cursor-bounded whole-chunk walk
    /// so recall is preserved. Shared by the main shared-anchor candidate pass
    /// and the localized-homoglyph plain candidate pass, the two passes ran
    /// byte-identical copies of this loop, a drift hazard for the
    /// anchored-vs-fallback verify logic.
    #[allow(clippy::too_many_arguments)]
    fn verify_anchored_candidates(
        &self,
        anchor_idx: &phase2_anchor::Phase2AnchorIndex,
        cands: &[(u32, u32)],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
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
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    deadline,
                ),
                None => self.extract_matches_inner(
                    entry,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
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

    /// Shared-anchor phase-2 scan. Computes the active set once, then:
    ///   1. runs ONE Aho-Corasick pass over the chunk for every eligible
    ///      pattern's required-prefix literals, collecting `(pattern, pos)`
    ///      candidates for the patterns that are active;
    ///   2. verifies each active eligible pattern anchored at its candidate
    ///      positions (O(match length) each, no per-pattern chunk scan);
    ///   3. runs the remaining active NON-eligible patterns on the legacy
    ///      whole-chunk path.
    /// The union of (2) and (3) is exactly the active set the legacy loop would
    /// have scanned, producing an identical match set (asserted by
    /// `phase2_anchor_parity`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_phase2_with_anchors(
        &self,
        anchor_idx: &phase2_anchor::Phase2AnchorIndex,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        // Decode focus window in preprocessed/chunk coordinates. AC candidates,
        // prefiltering and extraction are windowed; keyword/context signals use
        // full raw plus normalized text so in-window matches stay byte-identical.
        focus: Option<(usize, usize)>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_anchor_present: Option<bool>,
    ) {
        let prof = phase2_pattern_prof_enabled();
        // Text the AC candidate scan and the always-active prefilter run on.
        let scan_text: &str = match focus {
            Some((fs, fe)) => &preprocessed.text[fs..fe],
            None => &preprocessed.text,
        };
        let shift = focus.map_or(0u32, |(fs, _)| fs as u32);
        // `cursor_range` for whole-chunk phase-2 extraction: restrict match
        // STARTS to the focus window (matches still extend right freely).
        let cursor = focus;
        // Keyword AC seeds from normalized full text; only the always-active
        // prefilter text is windowed under decode focus.
        self.with_active_phase2_scratch(
            &preprocessed.text,
            scan_text,
            phase2_keyword_hints,
            |this, scratch| {
                let active_keyword_anchors = scratch
                    .active
                    .iter()
                    .filter(|&&pat| anchor_idx.is_eligible(pat))
                    .count();
                let localize_keyword_anchors =
                    active_keyword_anchors > KEYWORD_ANCHOR_WHOLE_CHUNK_CUTOFF;
                ANCHOR_CANDIDATES.with(|cell| {
                    let mut cands = cell.borrow_mut();
                    {
                        let _g = super::profile::span(super::profile::P::Phase2SharedAc);
                        if localize_keyword_anchors {
                            anchor_idx.collect_candidates(
                                scan_text,
                                |pat| scratch.is_active(pat),
                                &mut cands,
                            );
                        } else if phase2_always_anchor_present == Some(false) {
                            cands.clear();
                        } else {
                            anchor_idx.collect_always_active_candidates(scan_text, &mut cands);
                        }
                    }
                    // Candidate positions are relative to `scan_text`; lift them back
                    // into full-text coordinates so anchored verification indexes the
                    // real (full) `preprocessed.text`.
                    if shift != 0 {
                        for c in cands.iter_mut() {
                            c.1 += shift;
                        }
                    }
                    // Candidates are sorted by (pattern, pos); verify each
                    // pattern's contiguous run together so its per-pattern
                    // signal cache is built at most once.
                    let _verify_g = super::profile::span(super::profile::P::Phase2AnchoredVerify);
                    this.verify_anchored_candidates(
                        anchor_idx,
                        &cands[..],
                        preprocessed,
                        line_offsets,
                        code_lines,
                        documentation_lines,
                        chunk,
                        scan_state,
                        cursor,
                        deadline,
                        prof,
                    );
                });

                // Localized homoglyph path (ASCII chunks): the prefilter skipped
                // the plain (homoglyph) patterns, so verify them here from the
                // folded-literal AC candidate positions via `extract_anchored`
                // (O(match) each, dense over-marking from a short literal is a
                // cheap quick-fail, not a whole-chunk scan). Plain patterns with
                // no folded literal run whole-chunk (they are few).
                if self.tuning.homoglyph_gate_enabled()
                    && scan_text.is_ascii()
                    && anchor_idx.has_plain_localizer(&self.tuning)
                {
                    ANCHOR_CANDIDATES.with(|cell| {
                        let mut cands = cell.borrow_mut();
                        anchor_idx.collect_plain_candidates(scan_text, &mut cands);
                        if shift != 0 {
                            for c in cands.iter_mut() {
                                c.1 += shift;
                            }
                        }
                        this.verify_anchored_candidates(
                            anchor_idx,
                            &cands[..],
                            preprocessed,
                            line_offsets,
                            code_lines,
                            documentation_lines,
                            chunk,
                            scan_state,
                            cursor,
                            deadline,
                            prof,
                        );
                    });
                    for &idx in anchor_idx.plain_always_mark() {
                        if crate::deadline::expired(deadline) {
                            break;
                        }
                        let pat = idx as usize;
                        let (entry, _) = &this.phase2_patterns[pat];
                        let t0 = if prof { Some(Instant::now()) } else { None };
                        this.extract_matches_inner(
                            entry,
                            preprocessed,
                            line_offsets,
                            code_lines,
                            documentation_lines,
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

                // Active patterns with no required-literal anchor: whole-chunk
                // (windowed to the focus cursor when focus-restricting).
                let _wholechunk_g = super::profile::span(super::profile::P::Phase2WholeChunk);
                for (tested, &index) in scratch.active.iter().enumerate() {
                    if localize_keyword_anchors && anchor_idx.is_eligible(index) {
                        continue;
                    }
                    if crate::deadline::expired_on_cadence(deadline, tested, 16) {
                        break;
                    }
                    let (entry, _) = &this.phase2_patterns[index];
                    let t0 = if prof { Some(Instant::now()) } else { None };
                    this.extract_matches_inner(
                        entry,
                        preprocessed,
                        line_offsets,
                        code_lines,
                        documentation_lines,
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
        );
    }
}
