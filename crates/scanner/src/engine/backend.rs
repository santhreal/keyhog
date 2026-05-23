use super::*;
use crate::hw_probe::ScanBackend;
use keyhog_core::Chunk;

pub(crate) struct PreparedChunk<'a> {
    /// Borrowed handle on the caller's chunk. Was `Chunk` (owned)
    /// historically — every consumer reads `prepared.chunk.foo` via
    /// auto-deref, never moves out, and the caller already owns the
    /// chunk for the call's duration. Borrowing drops one full
    /// ChunkMetadata clone per chunk (5+ String allocations on
    /// every code-tree scan).
    pub(crate) chunk: &'a Chunk,
    pub(crate) preprocessed: ScannerPreprocessedText,
    /// Cached `compute_line_offsets(&preprocessed.text)`. Both the
    /// triggered-pattern path and the pattern-hits path used to call
    /// `compute_line_offsets` separately, walking the entire
    /// preprocessed text twice per chunk to count newlines. Cache
    /// it once at first access via OnceLock so the second caller
    /// hits a memoized Vec instead of re-scanning. Task #93.
    pub(crate) line_offsets: std::sync::OnceLock<Vec<usize>>,
}

impl<'a> PreparedChunk<'a> {
    /// Lazily-computed cumulative line-start offsets for the
    /// preprocessed text. Cheap to call repeatedly; the first call
    /// walks the text once, subsequent calls return a borrow into
    /// the cached Vec.
    pub(crate) fn line_offsets(&self) -> &[usize] {
        self.line_offsets
            .get_or_init(|| compute_line_offsets(&self.preprocessed.text))
    }
}

#[cfg(feature = "simd")]
pub(crate) fn build_simd_scanner(
    ac_map: &[CompiledPattern],
    _fallback: &[(CompiledPattern, Vec<String>)],
) -> Option<(crate::simd::backend::HsScanner, Vec<Vec<usize>>)> {
    use std::collections::HashMap;

    let mut regex_to_hs_id: HashMap<String, usize> = HashMap::new();
    let mut hs_patterns: Vec<(usize, usize, String, bool)> = Vec::new();
    let mut index_map: Vec<Vec<usize>> = Vec::new();

    for (idx, entry) in ac_map.iter().enumerate() {
        let regex_str = entry.regex.as_str();
        let hs_id = *regex_to_hs_id
            .entry(regex_str.to_string())
            .or_insert_with(|| {
                let id = hs_patterns.len();
                hs_patterns.push((
                    entry.detector_index,
                    id,
                    regex_str.to_string(),
                    entry.group.is_some(),
                ));
                index_map.push(Vec::new());
                id
            });
        index_map[hs_id].push(idx);
    }

    let pattern_refs: Vec<(usize, usize, &str, bool)> = hs_patterns
        .iter()
        .map(|(a, b, c, d)| (*a, *b, c.as_str(), *d))
        .collect();

    tracing::info!(
        unique = hs_patterns.len(),
        raw = ac_map.len(),
        "compiling deduplicated AC regexes into Hyperscan"
    );

    match crate::simd::backend::HsScanner::compile(&pattern_refs) {
        Ok((scanner, unsupported)) => {
            tracing::info!(
                compiled = scanner.pattern_count(),
                unsupported = unsupported.len(),
                "HS ready"
            );
            Some((scanner, index_map))
        }
        Err(error) => {
            tracing::warn!("HS compilation failed: {error}");
            None
        }
    }
}

impl CompiledScanner {
    pub(crate) fn scan_chunks_with_backend_internal(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        // GPU paths: literal-set (Gpu) and regex-NFA (MegaScan). Both
        // require a working GPU adapter + compiled matchers; the lazy
        // compile is gated below so a missing GPU silently degrades to
        // SIMD via `scan_with_backend` per chunk.
        let gpu_path = matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan);
        if !gpu_path || chunks.is_empty() {
            // Parallel CPU path: rayon's global pool is configured by the
            // CLI orchestrator with --threads / KEYHOG_THREADS / physical
            // core count. Hyperscan + AC scans are CPU-bound and trivially
            // independent per-chunk, so par_iter() saturates cores cleanly
            // — was previously a serial iter().map() that pinned to one
            // worker even on 32-core boxes.
            use rayon::prelude::*;
            let mut results: Vec<Vec<RawMatch>> = chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, backend))
                .collect();
            // Cross-chunk window-boundary reassembly. Without this, a
            // secret straddling the seam between two adjacent gapless
            // chunks from the same file is invisible — both halves are
            // too short to match the regex on their own. The GPU paths
            // below call `scan_chunk_boundaries` after their batch
            // dispatch (see `scan_coalesced_megascan`/`scan_coalesced_gpu`);
            // the CPU path historically did NOT, so callers using
            // `scan_chunks_with_backend(_, SimdCpu | CpuFallback)` lost
            // boundary recall silently. P3 proptest regression: a 38-byte
            // tail chunk plus 911-byte head chunk dropped an ASIA…
            // credential that straddled byte 911. Boundary scan
            // synthesises a 2 KiB tail+head buffer per adjacent pair
            // (`MAX_BOUNDARY` per side) and runs a fresh in-chunk scan;
            // cost is `(N-1) × ~2 KiB` total, negligible vs per-chunk
            // scan cost on the same dataset.
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            return results;
        }

        // GPU batch path: `scan_coalesced_gpu` produces full per-chunk
        // RawMatch results in one device dispatch + parallel post-process.
        // The previous `populate_gpu_batch_triggers` was a comment-only TODO
        // that threw the GPU results away — see audit release-2026-04-26.
        if self.gpu_literals.is_none() || self.gpu_backend.is_none() {
            let fallback_backend = self.degraded_backend_after_gpu_failure();
            use rayon::prelude::*;
            return chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, fallback_backend))
                .collect();
        }

        match backend {
            ScanBackend::MegaScan => self.scan_coalesced_megascan(chunks),
            _ => self.scan_coalesced_gpu(chunks),
        }
    }

    pub(crate) fn prepare_chunk<'a>(&self, chunk: &'a Chunk) -> PreparedChunk<'a> {
        // Note: non-ASCII normalization used to swap `chunk` to an
        // owned `Chunk` via `normalize_scannable_chunk`. That path
        // is rarely-hit (most source code is pure ASCII) and the
        // returned Chunk was immediately consumed via clone into the
        // owned PreparedChunk anyway, so the borrow design works:
        // for non-ASCII inputs we still feed the normalization
        // through `unicode_hardening::normalize_homoglyphs` Cow
        // below, which lands the normalized text in
        // `preprocessed.text`. The raw `chunk.data` borrow remains
        // intact for the few downstream consumers that read it
        // (extract_confirmed_patterns uses preprocessed.text by
        // default; raw `chunk.data` only via the drift fallback).

        // Homoglyph normalization: zero-allocation Cow fast path. Pure-ASCII
        // and evasion-free inputs (the 99% case) borrow `chunk.data` directly.
        // Only inputs containing actual homoglyphs/zero-width/RTL allocate.
        let data_to_pp: std::borrow::Cow<'_, str> = if self.config.unicode_normalization {
            unicode_hardening::normalize_homoglyphs(&chunk.data)
        } else {
            std::borrow::Cow::Borrowed(&chunk.data)
        };
        let data_ref: &str = &data_to_pp;

        let preprocessed = if let Some(pp) =
            crate::structured::preprocess(data_ref, chunk.metadata.path.as_deref())
        {
            pp
        } else {
            #[cfg(feature = "multiline")]
            if crate::multiline::has_concatenation_indicators(data_ref) {
                crate::multiline::preprocess_multiline(
                    data_ref,
                    &self.config.multiline,
                    &self.fragment_cache,
                )
            } else {
                ScannerPreprocessedText::passthrough(data_ref)
            }
            #[cfg(not(feature = "multiline"))]
            ScannerPreprocessedText::passthrough(data_ref)
        };

        PreparedChunk {
            chunk,
            preprocessed,
            line_offsets: std::sync::OnceLock::new(),
        }
    }

    /// Like [`scan_prepared_with_triggered`], but extraction is anchored
    /// at the byte positions the GPU literal-set engine reported. Each
    /// hit produces at most one regex confirmation pass restricted to a
    /// small window around the literal — avoiding the
    /// triggered-bitmap → full-chunk-rescan path that turned the GPU
    /// path into a 60× regression vs SIMD on dense corpora
    /// (320k literal hits × 2000 distinct patterns × 64 MiB chunk =
    /// 128 GB of regex work).
    ///
    /// When the multiline / unicode preprocessor altered the chunk
    /// text the raw-chunk offsets the GPU returned no longer line up
    /// with `prepared.preprocessed.text` — in that case the
    /// implementation transparently falls back to the legacy
    /// triggered-bitmap path so correctness is preserved.
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
            let documentation_lines = context::documentation_line_flags(&code_lines);

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
        let documentation_lines = context::documentation_line_flags(&code_lines);
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

    pub(crate) fn scan_prepared_with_triggered(
        &self,
        prepared: PreparedChunk<'_>,
        _backend: ScanBackend,
        triggered_patterns: Vec<u64>,
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

        let expanded_patterns = self.expand_triggered_patterns(&triggered_patterns);
        // No-trigger fast path: when no AC pattern fired, the entire
        // confirmed-pattern extraction pipeline is dead work. Skip
        // building the `confirmed_patterns: Vec<usize>` (allocation
        // saved), the per-line `documentation_line_flags` scan
        // (~6 µs saved on profile), and the `extract_confirmed_patterns`
        // call. The downstream fallbacks (`scan_generic_assignments`,
        // `scan_entropy_fallback`, `apply_ml_batch_scores`) run
        // unchanged since they have their own input shapes.
        let documentation_lines = if expanded_patterns.iter().any(|&w| w != 0) {
            let confirmed_patterns: Vec<usize> = (0..self.ac_map.len())
                .filter(|&i| (expanded_patterns[i / 64] & (1 << (i % 64))) != 0)
                .collect();
            let documentation_lines = context::documentation_line_flags(&code_lines);

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
            documentation_lines
        } else {
            context::documentation_line_flags(&code_lines)
        };

        // Fallback patterns (no usable literal prefix; e.g. asana-pat
        // shaped `1/[0-9]{16,20}/...`) never enter the AC-trigger
        // bitmap, so they would never extract via the path above.
        // Task #69 — these detectors were silently dead in EVERY hot
        // code path that builds a triggered bitmap. The keyword-AC
        // pre-filter inside `scan_fallback_patterns` keeps cost
        // bounded to detectors whose ≥4-char keyword appears in the
        // chunk; fallback patterns with no usable keyword are marked
        // `fallback_always_active = true` so they run on every chunk.
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

        scan_state.into_matches()
    }

    pub(crate) fn collect_triggered_patterns_for_backend(
        &self,
        text: &str,
        backend: ScanBackend,
    ) -> Vec<u64> {
        match backend {
            // MegaScan reuses the literal-set trigger collection until
            // the regex-NFA pipeline is wired in (task #105). The
            // trigger bitmask shape is identical across both engines so
            // the upstream consumers do not branch.
            ScanBackend::Gpu | ScanBackend::MegaScan => self.collect_triggered_patterns_gpu(text),
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => self.collect_triggered_patterns_cpu(text),
        }
    }

    fn collect_triggered_patterns_gpu(&self, text: &str) -> Vec<u64> {
        if let Some(matcher) = self.gpu_matcher() {
            let Some(backend) = self.gpu_backend.as_ref() else {
                return self.collect_triggered_patterns_simd(text);
            };
            match matcher.scan(&**backend, text.as_bytes(), 10000) {
                Ok(matches) => return self.triggered_patterns_from_gpu_matches(&matches),
                Err(error) => {
                    tracing::debug!("gpu scan failed: {error}");
                }
            }
        }
        self.collect_triggered_patterns_simd(text)
    }

    fn collect_triggered_patterns_simd(&self, text: &str) -> Vec<u64> {
        #[cfg(feature = "simd")]
        if let Some(scanner) = &self.simd_prefilter {
            let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
            for (hs_id, _start, _end) in scanner.scan(text.as_bytes()) {
                let Some((_detector_index, dedup_id, _has_group)) = scanner.pattern_info(hs_id)
                else {
                    continue;
                };
                if let Some(original_indices) = self.hs_index_map.get(dedup_id) {
                    for &pattern_index in original_indices {
                        self.mark_triggered_pattern(&mut triggered_patterns, pattern_index);
                    }
                }
            }
            return triggered_patterns;
        }

        self.collect_triggered_patterns_cpu(text)
    }

    fn collect_triggered_patterns_cpu(&self, text: &str) -> Vec<u64> {
        let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
        if let Some(ac) = &self.ac {
            for ac_match in ac.find_iter(text.as_bytes()) {
                self.mark_triggered_pattern(&mut triggered_patterns, ac_match.pattern().as_usize());
            }
        }
        triggered_patterns
    }

    fn triggered_patterns_from_gpu_matches(&self, matches: &[LiteralMatch]) -> Vec<u64> {
        let mut triggered = vec![0u64; self.ac_map.len().div_ceil(64)];
        for matched in matches {
            self.mark_triggered_pattern(&mut triggered, matched.pattern_id as usize);
        }
        triggered
    }

    fn mark_triggered_pattern(&self, triggered_patterns: &mut [u64], pattern_index: usize) {
        if pattern_index / 64 >= triggered_patterns.len() {
            return;
        }
        triggered_patterns[pattern_index / 64] |= 1u64 << (pattern_index % 64);
        if pattern_index < self.prefix_propagation.len() {
            for &propagated_index in &self.prefix_propagation[pattern_index] {
                if propagated_index / 64 < triggered_patterns.len() {
                    triggered_patterns[propagated_index / 64] |= 1u64 << (propagated_index % 64);
                }
            }
        }
    }

    fn degraded_backend_after_gpu_failure(&self) -> ScanBackend {
        #[cfg(feature = "simd")]
        if self.simd_prefilter.is_some() {
            return ScanBackend::SimdCpu;
        }
        ScanBackend::CpuFallback
    }
}
