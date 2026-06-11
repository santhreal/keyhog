//! `impl CompiledScanner` fallback/prefilter scan methods, extracted from
//! `fallback.rs`. The `CompiledScanner` struct is defined in `mod.rs`; this is a
//! satellite impl block reached via `use super::*`. Shared toggle/profiling
//! helpers and `ActivePatternsScratch` live in `fallback.rs` (pub(crate)) and are
//! glob-imported below. Pure move, no behaviour change.
use super::fallback::*;
use super::fallback_truncate::{
    focus_ceil_boundary, focus_floor_boundary, regex_prefix_anchorable, truncate_src,
};
use super::*;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;


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

        // Shared-anchor fast path: one Aho-Corasick pass over all eligible
        // patterns' required-prefix literals yields candidate positions, each
        // verified by an anchored regex - replacing each pattern's own
        // whole-chunk walk. Recall-identical (see `fallback_anchor`); handles
        // any chunk size, so it supersedes the small/large split below. Active
        // patterns with no required-literal anchor keep the whole-chunk path
        // inside `scan_fallback_with_anchors`.
        if !self.fallback.is_empty() && fallback_anchor_enabled() {
            if let Some(anchor_idx) = &self.fallback_anchor_index {
                self.scan_fallback_with_anchors(
                    anchor_idx,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    deadline,
                    None,
                );
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
        let prof = fallback_pat_prof_enabled();
        self.with_active_fallback_patterns(
            &chunk.data,
            &preprocessed.text,
            |this, active_patterns| {
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
                    let t0 = if prof { Some(Instant::now()) } else { None };
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
                    if let Some(t0) = t0 {
                        fallback_prof_record(
                            this.fallback.len(),
                            index,
                            t0.elapsed().as_nanos() as u64,
                        );
                    }
                }
            },
        );
    }

    /// Decode-recursion FOCUS variant of `scan_fallback_patterns`. A decode
    /// sub-chunk is a small window of already-scanned parent context with the
    /// freshly decoded text spliced in at `focus = (start, end)`. Everything
    /// outside `[start,end)` was scanned (and any finding deduped against
    /// `seen`) when the parent chunk was scanned, so the only NEW fallback
    /// matches are those that touch the decoded text.
    ///
    /// This windows the two expensive parts of the fallback pass — the
    /// always-active prefilter RegexSet and the per-pattern regex extraction —
    /// to `[start-margin, end+margin)`, while keeping the FULL splice for every
    /// signal that decides whether/how a match is reported:
    ///   - `keyword_nearby` (`compute_pattern_signals` reads the full `chunk`),
    ///   - the keyword Aho-Corasick prefilter (`data = &chunk.data`, so a
    ///     keyword in far context still activates its pattern),
    ///   - `line_offsets` / `documentation_lines` / `base_offset` / `base_line`.
    /// So for any match that STARTS inside the focus window the produced
    /// `(detector, credential, location, confidence)` is byte-identical to the
    /// whole-splice scan. Matches outside the window are either pure-context
    /// (already found by the parent → deduped) or unreachable, so the reported
    /// set is unchanged (validated by `decode_focus_parity`).
    ///
    /// PRECONDITION: `preprocessed.text` must be byte-aligned with `chunk.data`
    /// (the homoglyph-normalisation no-op passthrough), so `focus` — computed in
    /// `chunk.data` coordinates — indexes `preprocessed.text` correctly. The
    /// caller checks this; a non-passthrough chunk takes the full-scan path.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scan_fallback_patterns_focused(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
        focus: (usize, usize),
    ) {
        if let Some(deadline) = deadline {
            if std::time::Instant::now() >= deadline {
                return;
            }
        }
        if self.fallback.is_empty() {
            return;
        }
        let text: &str = &preprocessed.text;
        // Expand the decoded span by the margin and snap to char boundaries.
        let fs = focus_floor_boundary(text, focus.0.saturating_sub(DECODE_FOCUS_MARGIN));
        let fe = focus_ceil_boundary(
            text,
            focus.1.saturating_add(DECODE_FOCUS_MARGIN).min(text.len()),
        );
        if fs >= fe {
            return;
        }
        // If the focus window already covers (almost) the whole chunk, the
        // restriction buys nothing — run the normal path so we don't pay the
        // extra slice setup for no gain.
        if fe - fs >= text.len() {
            self.scan_fallback_patterns(
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
        let focus = Some((fs, fe));

        // Prefer the optimized shared-anchor path (the default), now focus-aware:
        // its AC candidate scan + always-active prefilter run over the window
        // while signals/lines stay full. This is what makes the restriction a net
        // win — the non-anchor whole-chunk prefilter, even windowed, barely beats
        // the anchor path on full text.
        if fallback_anchor_enabled() {
            if let Some(anchor_idx) = &self.fallback_anchor_index {
                self.scan_fallback_with_anchors(
                    anchor_idx,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    deadline,
                    focus,
                );
                return;
            }
        }

        // Anchor index unavailable: windowed non-anchor path (prefilter over the
        // focus slice, keyword AC over full `chunk.data`, extraction cursor-bound
        // to the window).
        let match_text = &text[fs..fe];
        let cursor = focus;
        let prof = fallback_pat_prof_enabled();
        self.with_active_fallback_patterns(&chunk.data, match_text, |this, active_patterns| {
            for (tested, &index) in active_patterns.iter().enumerate() {
                if let Some(deadline) = deadline {
                    if tested.is_multiple_of(16) && std::time::Instant::now() >= deadline {
                        break;
                    }
                }
                let (entry, _keywords) = &this.fallback[index];
                let t0 = if prof { Some(Instant::now()) } else { None };
                this.extract_matches_inner(
                    entry,
                    preprocessed,
                    line_offsets,
                    code_lines,
                    documentation_lines,
                    chunk,
                    scan_state,
                    0,
                    0,
                    cursor,
                    deadline,
                );
                if let Some(t0) = t0 {
                    fallback_prof_record(
                        this.fallback.len(),
                        index,
                        t0.elapsed().as_nanos() as u64,
                    );
                }
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
    /// `data` seeds the keyword-AC prefilter (raw chunk bytes, as before).
    /// `match_text` is the text the always-active RegexSet prefilter runs on and
    /// MUST be the same text per-pattern extraction uses (`preprocessed.text`)
    /// so the prefilter is sound under unicode normalization.
    fn with_active_fallback_patterns<R>(
        &self,
        data: &str,
        match_text: &str,
        f: impl FnOnce(&Self, &[usize]) -> R,
    ) -> R {
        ACTIVE_PATTERNS_POOL.with(|cell| {
            let mut scratch = cell.borrow_mut();
            scratch.begin(self.fallback.len());
            // anchor_mode = false: the legacy whole-chunk path has no AC gating,
            // so every always-active pattern must be marked for recall.
            self.populate_active_fallback(data, match_text, &mut scratch, false);
            if fallback_reverse_enabled() {
                scratch.active.reverse();
            }
            f(self, &scratch.active)
        })
    }

    /// True iff scanning `data` through the fallback path would activate at
    /// least one pattern — i.e. the always-active RegexSet prefilter marks a
    /// pattern OR a fallback keyword occurs in `data`.
    ///
    /// This is the EXACT, cheap necessary condition for a fallback match and is
    /// the recall-load-bearing admission gate for no-Hyperscan-hit chunks (see
    /// `should_scan_no_hit_chunk`): without it, a chunk that fires no literal
    /// prefix but contains a prefix-less / keyword-less detector (asana-pat and
    /// ~3100 similar, issue #69) is silently dropped (Law 10).
    ///
    /// It runs the SAME `populate_active_fallback` the production scan runs, so
    /// it can never admit a chunk the scan then finds inert nor reject one the
    /// scan would mark — admission and extraction share one active-set contract.
    /// Note the earlier coarse form short-circuited to `true` whenever ANY
    /// always-active pattern existed (so it answered "is there unconditional
    /// fallback work?", admitting EVERY chunk); running the prefilter answers the
    /// per-chunk question instead, which is what no-hit admission needs.
    //
    // `any(simd, gpu)`: the only caller is `should_scan_no_hit_chunk`, the
    // no-phase-1-trigger admission gate that exists solely on the coalesced
    // (`simd`) and megakernel (`gpu`) phase-2 tail. A no-`simd`-no-`gpu` build
    // scans every chunk through the AC+fallback path unconditionally (no
    // trigger-skip step), so it never asks this question — gating here keeps
    // that profile warning-clean (Law 11) without dropping any chunk (Law 10).
    #[cfg(any(feature = "simd", feature = "gpu"))]
    pub(crate) fn has_active_fallback_patterns_for_chunk(&self, data: &str) -> bool {
        if self.fallback.is_empty() {
            return false;
        }
        // No keyword AC compiled => `populate_active_fallback` marks EVERY
        // fallback pattern (its `else` arm), so the answer is unconditionally
        // yes; skip the scan.
        if self.fallback_keyword_ac.is_none() {
            return true;
        }
        // Run the real active-set computation: the always-active RegexSet
        // prefilter (marks the anchorless patterns that can fire on THIS chunk)
        // plus the keyword AC. `match_text == data` because admission runs on the
        // raw chunk before any structured preprocessing.
        self.with_active_fallback_patterns(data, data, |_, active_patterns| {
            !active_patterns.is_empty()
        })
    }

    /// True iff `idx` is an eligible always-active pattern handled by the shared
    /// anchor AC (and therefore excluded from the RegexSet prefilter).
    #[inline]
    fn anchor_always_active_eligible(&self, idx: usize) -> bool {
        self.fallback_anchor_index
            .as_ref()
            .is_some_and(|a| a.is_always_active_eligible(idx))
    }

    /// Compute the active fallback set. `anchor_mode` selects how always-active
    /// patterns are gated:
    ///   * `true` (shared-anchor path): the RegexSet prefilter covers only the
    ///     NON-eligible always-active patterns; eligible ones are gated later by
    ///     the shared AC (see `scan_fallback_with_anchors`), so they are NOT
    ///     marked here. This is the ~10x-smaller prefilter that is the win.
    ///   * `false` (legacy whole-chunk path): every always-active pattern is
    ///     marked (the reduced prefilter doesn't cover the eligible ones, and
    ///     there is no AC gating on this path), so recall is preserved.
    pub(crate) fn populate_active_fallback(
        &self,
        data: &str,
        match_text: &str,
        scratch: &mut ActivePatternsScratch,
        anchor_mode: bool,
    ) {
        if let Some(keyword_ac) = &self.fallback_keyword_ac {
            let prof = fallback_pat_prof_enabled();
            // Always-active patterns (no >=4-char keyword) would each run their
            // capture regex over the whole chunk. Gate them through a combined
            // RegexSet so only patterns that can actually match are activated;
            // the rest extract nothing and are dead work. The set is built with
            // each pattern's own flags, so this drops cost, never recall. When
            // the set could not be compiled, fall back to marking all of them.
            // The always-active prefilter marks the patterns that can fire. Its
            // plain (homoglyph) batches use a fast ASCII-folded alternate on
            // pure-ASCII chunks (identical marking, far faster) — the perf win.
            // When anchor localization is on, the prefilter covers only the
            // non-eligible always-active set (eligible ones are handled by the
            // shared AC); on the legacy path every always-active pattern must be
            // marked, so a `None` prefilter falls back to marking them all.
            // On the shared-anchor path, plain (homoglyph) patterns are handled
            // by the localized AC on ASCII chunks, so the prefilter skips them.
            let localize_plain = anchor_mode
                && self
                    .fallback_anchor_index
                    .as_ref()
                    .is_some_and(|a| a.has_plain_localizer());
            let t0 = if prof { Some(Instant::now()) } else { None };
            {
                // The anchorless always-active RegexSet — the detectors that run
                // on EVERY chunk. This span is the cost the "fallback" name hides.
                let _g = super::profile::span(super::profile::P::FbPrefilter);
                match &self.fallback_always_active_prefilter {
                    Some(prefilter) => prefilter.mark_matches(match_text, scratch, localize_plain),
                    None => {
                        for &index in &self.fallback_always_active_indices {
                            if anchor_mode && self.anchor_always_active_eligible(index) {
                                continue;
                            }
                            scratch.mark(index);
                        }
                    }
                }
            }
            if let Some(t0) = t0 {
                POPULATE_PREFILTER_NS.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
            }
            let t1 = if prof { Some(Instant::now()) } else { None };
            {
                let _g = super::profile::span(super::profile::P::FbKeywordAc);
                for mat in keyword_ac.find_iter(data) {
                    let keyword_idx = mat.pattern().as_usize();
                    if let Some(pattern_indices) =
                        self.fallback_keyword_to_patterns.get(keyword_idx)
                    {
                        for &pattern_idx in pattern_indices {
                            scratch.mark(pattern_idx as usize);
                        }
                    }
                }
            }
            if let Some(t1) = t1 {
                POPULATE_KEYWORD_NS.fetch_add(t1.elapsed().as_nanos() as u64, Relaxed);
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
        let prof = fallback_pat_prof_enabled();
        self.with_active_fallback_patterns(&chunk.data, &preprocessed.text, |this, active_set| {
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
                let t0 = if prof { Some(Instant::now()) } else { None };
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
                if let Some(t0) = t0 {
                    fallback_prof_record(
                        this.fallback.len(),
                        index,
                        t0.elapsed().as_nanos() as u64,
                    );
                }
            }
        });
    }

    /// Print and reset the per-pattern fallback profile (top 30 by time). Call
    /// after a profiled run (`KEYHOG_PROFILE_FALLBACK=1`). Each line is the
    /// fallback detector's regex, total ms, run count, and ns/run, plus whether
    /// it carries a regex-required prefix anchor (the localization candidate).
    pub fn fallback_profile_dump(&self, label: &str) {
        let len = self.fallback.len();
        let (ns, runs) = fallback_prof_vecs(len);
        let mut rows: Vec<(usize, u64, u64)> = (0..len)
            .map(|i| (i, ns[i].swap(0, Relaxed), runs[i].swap(0, Relaxed)))
            .filter(|&(_, n, _)| n > 0)
            .collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        let grand: u64 = rows.iter().map(|r| r.1).sum();
        let prefilter_ms = POPULATE_PREFILTER_NS.swap(0, Relaxed) as f64 / 1e6;
        let keyword_ms = POPULATE_KEYWORD_NS.swap(0, Relaxed) as f64 / 1e6;
        eprintln!(
            "=== FALLBACK per-pattern profile [{label}] ===\n  populate: always-active RegexSet prefilter={prefilter_ms:.1} ms, keyword-AC={keyword_ms:.1} ms\n  extract: {:.1} ms over {} active patterns",
            grand as f64 / 1e6,
            rows.len()
        );
        for (i, n, r) in rows.iter().take(30) {
            let src = self.fallback[*i].0.regex.as_str();
            let anchored = regex_prefix_anchorable(src);
            let per_run = if *r > 0 { *n / *r } else { 0 };
            eprintln!(
                "  {:>6.1}ms {:>5.1}%  runs={:<6} {:>7}ns/run  [{}] {}",
                *n as f64 / 1e6,
                100.0 * *n as f64 / grand.max(1) as f64,
                r,
                per_run,
                if anchored { "ANCHOR" } else { "  --  " },
                truncate_src(src, 64),
            );
        }
    }
}
