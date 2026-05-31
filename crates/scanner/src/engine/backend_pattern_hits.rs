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
            &prepared.preprocessed,
            &line_offsets,
            prepared.chunk,
            &mut scan_state,
        );

        // Preprocessor offset-invariance check: if structured decoding,
        // multiline reassembly, or unicode normalization changed the text
        // length, raw-chunk offsets no longer map 1:1 to preprocessed-text
        // offsets. Phase-2 confirmation and extraction must still read the
        // preprocessed text because it is the only place decoded credentials
        // exist (for example k8s Secret data). GPU hit coordinates are not
        // trusted below; they are used only as pids.
        let offset_drift = prepared
            .chunk
            .data
            .len()
            .abs_diff(prepared.preprocessed.text.len());
        // ~10 KiB drift bound - covers heavy multiline reassembly on
        // a 64 MiB file (vendor/vyre source drifts ~0.0005% of the
        // chunk).
        const MAX_TOLERATED_DRIFT: usize = 10 * 1024;
        let drift_tolerable = offset_drift <= MAX_TOLERATED_DRIFT;
        let scan_text = prepared.preprocessed.text.as_str();
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

        let total_patterns = self.ac_map.len() + self.fallback.len();
        let documentation_lines = crate::context::documentation_line_flags(&code_lines);

        if offsets_safe {
            // Cheap per-pattern pre-filter to shrink the bitmap
            // before the (still whole-chunk) regex EXTRACTION pass.
            // The GPU literal-set/AC matches *prefixes* with weaker
            // discrimination than Hyperscan's NFA match - on a 64 MiB
            // random alphanumeric blob ~2 k distinct detector prefixes
            // fire spuriously and would feed `extract_confirmed_patterns`
            // ~128 GB of redundant regex work (60× slower than SIMD). For
            // each distinct hit pid we ask the pattern's own regex: does it
            // match this chunk at all? Only patterns that pass enter the
            // bitmap, so extract walks ~10-50 patterns (Hyperscan-
            // equivalent) instead of ~2 000.
            //
            // is_match runs over the WHOLE chunk, not a window around the
            // hit: the GPU AC positions are unreliable (see the loop
            // below), and a window derived from them dropped real matches
            // deep in large files. `confirmed[]` guarantees each pid's
            // regex runs at most once, and the fold above deduped
            // `per_pattern_hits` to ~one entry per distinct pid, so the
            // is_match count is bounded by the number of distinct detector
            // literals present - the same prune the cheap-filter always
            // did, now position-independent and sound vs SIMD.
            let mut tight_bitmap = vec![0u64; total_patterns.div_ceil(64)];
            let mut confirmed = vec![false; total_patterns];
            let text = scan_text;
            let mut confirm_pattern_and_siblings = |pat_idx: usize| {
                let siblings = self.same_prefix_patterns.get(pat_idx).unwrap_or(&[]);
                let candidates =
                    std::iter::once(pat_idx).chain(siblings.iter().map(|&idx| idx as usize));
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
                    if entry.regex.get().is_match(text) {
                        tight_bitmap[cand_idx / 64] |= 1u64 << (cand_idx % 64);
                    }
                    // Mark checked regardless of outcome: the whole-chunk
                    // is_match verdict is position-independent and
                    // deterministic, so a subsequent hit for the same pid would
                    // reach the same result - never re-scan the chunk for
                    // an already-evaluated pid.
                    confirmed[cand_idx] = true;
                }
            };
            // GPU AC match POSITIONS are unreliable: the
            // classic_ac_bounded_ranges kernel reports degenerate
            // `(start,end)` (observed `(0,0)`), and
            // `fold_overlapping_same_pid_inplace` then collapses a pid's
            // many literal hits into one such span. A window derived from
            // those positions made the cheap-filter confirm only matches
            // in the first ~1 KiB of the chunk, silently dropping every
            // match deeper in a large file - the gpu_parity violation:
            // soc21_enum.h has 4 `codesandbox-api-token` matches at line
            // 20267+, all missed because the folded hit's window was
            // `[0,1024]`. So we confirm each hit pid against the WHOLE
            // chunk, position-independent and identical to SIMD's "literal
            // triggered -> the full regex decides over the whole chunk".
            // `per_pattern_hits` is deduped to ~one entry per distinct pid
            // by the fold above, so the is_match count is bounded by the
            // number of distinct detector literals present in the chunk,
            // not the raw hit count - and `confirmed[]` makes each pid's
            // regex run at most once. extract_confirmed_patterns still does
            // the precise extraction; this only decides which roots enter
            // the bitmap (the spurious-prefix prune the cheap-filter exists
            // for).
            for &(pid, _start, _end) in &per_pattern_hits {
                let pat_idx = pid as usize;
                if pat_idx >= total_patterns {
                    continue;
                }

                // The GPU AC DFA folds patterns that share a literal
                // prefix into one trie node - only one pid is emitted
                // per literal hit. If that one's regex doesn't match,
                // siblings (via same_prefix_patterns) never get
                // checked. Task #56 reproducer: keyhog has both
                // `sb_(?:publishable|secret)_…` and stackblitz's
                // `sb_[a-zA-Z0-9_-]{20,}`; the kernel emits only the
                // first pid, and its regex doesn't match the
                // stackblitz token. So we check `pid` AND every
                // `same_prefix_patterns[pid]` sibling against the
                // whole chunk - the first sibling whose regex
                // matches gets confirmed (its own bit), and the
                // downstream `expand_triggered_patterns` then fans
                // out to the rest of the sibling set. Correctness:
                // bitmap is by-pid, never by-literal, so we cannot
                // confuse two pids that share a prefix.
                confirm_pattern_and_siblings(pat_idx);
            }
            // Fail closed against GPU literal-set drift: phase 2 is already
            // on CPU and already runs full regex extraction, so union the
            // canonical CPU AC trigger roots before extraction. The GPU
            // hit list remains the accelerator; the CPU AC bitmap prevents
            // a stale or divergent GPU literal set from silently dropping
            // a detector whose regex matches this chunk.
            let cpu_triggered = self.collect_triggered_patterns_cpu(text);
            for (word_idx, &word) in cpu_triggered.iter().enumerate() {
                let mut bits = word;
                while bits != 0 {
                    let bit = bits.trailing_zeros() as usize;
                    let pat_idx = word_idx * 64 + bit;
                    if pat_idx >= self.ac_map.len() {
                        break;
                    }
                    confirm_pattern_and_siblings(pat_idx);
                    bits &= bits - 1;
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
            let mut triggered: Vec<u64> = self.collect_triggered_patterns_cpu(scan_text);
            triggered.resize(total_patterns.div_ceil(64), 0);
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

        // Patterns without a usable literal prefix live in `self.fallback`
        // and never enter the cheap-filter trigger bitmap - task #69
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
