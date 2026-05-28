use super::*;
use keyhog_core::RawMatch;

impl CompiledScanner {
    pub(crate) fn scan_prepared_with_pattern_hits(
        &self,
        prepared: PreparedChunk<'_>,
        per_pattern_hits: Vec<(u32, u32, u32)>,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let line_offsets = prepared.line_offsets().to_vec();
        let code_lines: Vec<&str> = prepared.chunk.data.lines().collect();
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());

        #[cfg(feature = "simdsieve")]
        self.scan_hot_patterns_fast(
            &prepared.preprocessed.text,
            &line_offsets,
            prepared.chunk,
            &mut scan_state,
        );

        // Preprocessor offset-invariance check: if multiline reassembly
        // or unicode normalization changed the text length, raw-chunk
        // offsets no longer map 1:1 to preprocessed-text offsets and
        // anchored extraction would emit matches at the wrong column.
        // For small drift (~hundreds of bytes on a 64 MiB chunk —
        // typical for Rust/Go/Python source after multiline string
        // reassembly), we still run the cheap-filter against
        // `chunk.data` (which IS the GPU's coordinate system) and let
        // the downstream `extract_confirmed_patterns` recover the
        // multiline-reassembled positions via its own full-chunk
        // sweep. We only fall all the way back to the legacy bitmap
        // path when drift exceeds the largest credential we expect
        // (matches the literal-set engine would have triggered on
        // the multiline-reassembled credential alone).
        let offset_drift = prepared
            .chunk
            .data
            .len()
            .abs_diff(prepared.preprocessed.text.len());
        // ~10 KiB drift bound — covers heavy multiline reassembly on
        // a 64 MiB file (vendor/vyre source drifts ~0.0005% of the
        // chunk).
        const MAX_TOLERATED_DRIFT: usize = 10 * 1024;
        let drift_tolerable = offset_drift <= MAX_TOLERATED_DRIFT;
        let scan_text = if prepared.preprocessed.text.len() == prepared.chunk.data.len() {
            // Strict offset parity — scan the preprocessed text (the
            // same one extract_confirmed_patterns will walk later).
            prepared.preprocessed.text.as_str()
        } else {
            // Drift present — the cheap-filter needs to scan the
            // chunk.data coordinate system the GPU returned, so the
            // literal-hit positions land inside the right window.
            // Extraction still uses preprocessed.text downstream,
            // so it remains the source of truth for credentials.
            prepared.chunk.data.as_ref()
        };
        let offsets_safe = drift_tolerable;
        let start_ts = std::time::Instant::now();
        tracing::debug!(
            target: "keyhog::routing",
            hits = per_pattern_hits.len(),
            offsets_safe,
            chunk_bytes = prepared.chunk.data.len(),
            preprocessed_bytes = prepared.preprocessed.text.len(),
            "scan_prepared_with_pattern_hits",
        );

        if !per_pattern_hits.is_empty() {
            let total_patterns = self.ac_map.len() + self.fallback.len();
            let documentation_lines = crate::context::documentation_line_flags(&code_lines);

            if offsets_safe {
                // Cheap per-pattern pre-filter to shrink the bitmap
                // before the (still whole-chunk) regex extraction
                // pass. The GPU literal-set matches *prefixes* with
                // weaker discrimination than Hyperscan's NFA match —
                // on a 64 MiB random alphanumeric blob ~2 k distinct
                // detector prefixes fire spuriously and feed
                // `extract_confirmed_patterns` ~128 GB of redundant
                // regex work (60× slower than SIMD). For each unique
                // hit position we ask the pattern's own regex
                // anchored at the literal: did this prefix actually
                // belong to a match? Only patterns that pass make it
                // into the bitmap, so extract walks ~10-50 patterns
                // (Hyperscan-equivalent) instead of ~2 000.
                const PRE_MARGIN: u32 = 128;
                const POST_MARGIN: u32 = 1024;
                // A pattern's *first* literal hit may sit at a
                // position where the full regex doesn't match yet —
                // e.g. `z85` appearing in random alphanumerics at
                // mid-line vs at end-of-line where the regex
                // `(?:z85)[=:\s]+[…]{20,}` actually fires. Earlier
                // versions of the filter `Rejected` a pattern on the
                // first window miss and skipped its remaining hits;
                // that collapsed Corpus B recall from 207 → 23. The
                // current scheme is "confirm once, then skip": every
                // remaining hit of a pattern is checked until one
                // returns true OR the hit list is exhausted. Worst
                // case = 320 k `is_match` calls on 1 KiB windows
                // (~3 s); typical case = ~2 k confirms quickly and
                // the rest of the hits short-circuit on
                // `confirmed[pat_idx]`.
                let mut tight_bitmap = vec![0u64; total_patterns.div_ceil(64)];
                let mut confirmed = vec![false; total_patterns];
                let text = scan_text;
                let text_len = text.len();
                for &(pid, start, end) in &per_pattern_hits {
                    let pat_idx = pid as usize;
                    if pat_idx >= total_patterns {
                        continue;
                    }
                    let scan_start = start.saturating_sub(PRE_MARGIN) as usize;
                    let window_end = (end.saturating_add(POST_MARGIN) as usize).min(text_len);
                    if scan_start >= window_end {
                        continue;
                    }
                    let mut snap_start = scan_start;
                    while snap_start > 0 && !text.is_char_boundary(snap_start) {
                        snap_start -= 1;
                    }
                    let mut snap_end = window_end;
                    while snap_end < text_len && !text.is_char_boundary(snap_end) {
                        snap_end += 1;
                    }
                    let window = &text[snap_start..snap_end];

                    // The GPU AC DFA folds patterns that share a literal
                    // prefix into one trie node — only one pid is emitted
                    // per literal hit. If that one's regex doesn't match,
                    // siblings (via same_prefix_patterns) never get
                    // checked. Task #56 reproducer: keyhog has both
                    // `sb_(?:publishable|secret)_…` and stackblitz's
                    // `sb_[a-zA-Z0-9_-]{20,}`; the kernel emits only the
                    // first pid, and its regex doesn't match the
                    // stackblitz token. So we check `pid` AND every
                    // `same_prefix_patterns[pid]` sibling against this
                    // hit's window — the first sibling whose regex
                    // matches gets confirmed (its own bit), and the
                    // downstream `expand_triggered_patterns` then fans
                    // out to the rest of the sibling set. Correctness:
                    // bitmap is by-pid, never by-literal, so we cannot
                    // confuse two pids that share a prefix.
                    let siblings = if pat_idx < self.same_prefix_patterns.len() {
                        self.same_prefix_patterns[pat_idx].as_slice()
                    } else {
                        &[]
                    };
                    let candidates = std::iter::once(pat_idx).chain(siblings.iter().copied());
                    for cand_idx in candidates {
                        if cand_idx >= total_patterns {
                            continue;
                        }
                        if confirmed[cand_idx] {
                            continue;
                        }
                        let entry = if cand_idx < self.ac_map.len() {
                            &self.ac_map[cand_idx]
                        } else {
                            let fb = cand_idx - self.ac_map.len();
                            if fb >= self.fallback.len() {
                                confirmed[cand_idx] = true;
                                continue;
                            }
                            &self.fallback[fb].0
                        };
                        if entry.regex.is_match(window) {
                            tight_bitmap[cand_idx / 64] |= 1u64 << (cand_idx % 64);
                            confirmed[cand_idx] = true;
                        }
                    }
                }
                // Expand the cheap-filter-confirmed roots to their
                // AC prefix siblings before extract. The cheap-filter
                // already filtered out spurious literal hits whose
                // own regex doesn't match; the resulting tight_bitmap
                // is a strict *root set*, not the final pattern set.
                // SIMD's path always fans these roots out via
                // `same_prefix_patterns` so that a literal anchor
                // shared between (e.g.) a tight Stripe-secret detector
                // and a permissive generic-high-entropy detector
                // surfaces both. Without this fan-out, the cheap
                // filter loses recall against SIMD on multi-detector
                // credentials (gpu_parity test: missed the Stripe
                // finding on the third chunk because the generic
                // sibling never made it into the bitmap).
                //
                // The 142× over-broadening the original
                // skip-expand was guarding against came from
                // expand FIRST → extract on the whole expanded set
                // (~2 k AC-roots × all-siblings = ~20 k patterns
                // walked over 64 MiB). Cheap-filter FIRST → expand
                // confirmed roots produces a much smaller working
                // set (~5 confirmed roots × siblings = ~50 patterns)
                // because the cheap-filter already discards the
                // ~99 % of literal hits whose regex doesn't match.
                if tight_bitmap.iter().any(|&w| w != 0) {
                    let expanded = self.expand_triggered_patterns(&tight_bitmap);
                    let confirmed_patterns: Vec<usize> = (0..self.ac_map.len())
                        .filter(|&i| (expanded[i / 64] & (1 << (i % 64))) != 0)
                        .collect();
                    self.extract_confirmed_patterns(
                        &confirmed_patterns,
                        &prepared.preprocessed,
                        &line_offsets,
                        &code_lines,
                        &documentation_lines,
                        prepared.chunk,
                        &mut scan_state,
                        deadline,
                    );
                }
            } else {
                // Offset-unsafe fallback: rebuild the bitmap from the
                // hit list and route through the legacy path so the
                // same chunk still gets every confirmed credential.
                let mut triggered: Vec<u64> = vec![0u64; total_patterns.div_ceil(64)];
                for &(pid, _start, _end) in &per_pattern_hits {
                    let pat_idx = pid as usize;
                    if pat_idx < total_patterns {
                        triggered[pat_idx / 64] |= 1u64 << (pat_idx % 64);
                    }
                }
                let expanded_patterns = self.expand_triggered_patterns(&triggered);
                if expanded_patterns.iter().any(|&w| w != 0) {
                    let confirmed_patterns: Vec<usize> = (0..self.ac_map.len())
                        .filter(|&i| (expanded_patterns[i / 64] & (1 << (i % 64))) != 0)
                        .collect();
                    self.extract_confirmed_patterns(
                        &confirmed_patterns,
                        &prepared.preprocessed,
                        &line_offsets,
                        &code_lines,
                        &documentation_lines,
                        prepared.chunk,
                        &mut scan_state,
                        deadline,
                    );
                }
            }
        }

        // Patterns without a usable literal prefix live in `self.fallback`
        // and never enter the cheap-filter trigger bitmap — task #69
        // caught asana-pat, mailchimp pattern 3, and likely a long tail
        // of similar prefix-less detectors silently failing here. Run
        // the keyword-AC-gated fallback sweep on every chunk; the AC
        // pre-filter keeps the cost bounded to detectors whose ≥4-char
        // keyword actually appears in the chunk.
        let documentation_lines = crate::context::documentation_line_flags(&code_lines);
        self.scan_fallback_patterns(
            &prepared.preprocessed,
            &line_offsets,
            &code_lines,
            &documentation_lines,
            prepared.chunk,
            &mut scan_state,
            deadline,
        );

        self.scan_generic_assignments(&code_lines, &line_offsets, prepared.chunk, &mut scan_state);

        #[cfg(feature = "entropy")]
        self.scan_entropy_fallback(
            &prepared.preprocessed,
            &line_offsets,
            prepared.chunk,
            &mut scan_state,
        );

        #[cfg(feature = "ml")]
        self.apply_ml_batch_scores(&mut scan_state);

        let matches = scan_state.into_matches();
        tracing::debug!(
            target: "keyhog::routing",
            elapsed_ms = start_ts.elapsed().as_millis() as u64,
            matches = matches.len(),
            "scan_prepared_with_pattern_hits done",
        );
        matches
    }
}
