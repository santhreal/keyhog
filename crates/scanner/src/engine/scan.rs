use super::*;
#[cfg(feature = "simd")]
use std::cell::RefCell;
use std::collections::HashMap;

use super::scan_filters::*;

// The trigger-buffer pool is only used in the Hyperscan-prefilter
// scratch path of `scan_coalesced` (gated `#[cfg(feature = "simd")]`).
// Without `simd`, both the pool and the helper become dead code,
// so gate them too — otherwise `cargo build --no-default-features`
// (the no-Hyperscan Windows build) emits dead-code warnings.
//
// Note: a previous attempt extended this pool to the per-chunk
// `collect_triggered_patterns_*` builders. That regressed the
// long-lines bench by ~12% because those builders return
// `Vec<u64>` to their callers — the pool can't save the
// allocation, only adds the thread_local + RefCell overhead.
// The pool's win is reuse of buffers that stay inside the pool.
#[cfg(feature = "simd")]
thread_local! {
    /// Per-thread pool of trigger-bitmask vectors. Phase-1 of `scan_coalesced`
    /// allocates one `Vec<u64>` of size `ac_len.div_ceil(64)` per chunk. On a
    /// 100k-file scan with 1500 patterns that's ~2.4M tiny allocations
    /// hammering the global allocator. With this pool, each rayon worker
    /// reuses a single buffer across all the chunks it processes.
    static TRIGGER_POOL: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

#[cfg(feature = "simd")]
#[inline]
fn with_trigger_buffer<R>(words_needed: usize, f: impl FnOnce(&mut [u64]) -> R) -> R {
    TRIGGER_POOL.with(|cell| {
        let mut buf = cell.borrow_mut();
        if buf.len() < words_needed {
            buf.resize(words_needed, 0);
        }
        let slice = &mut buf[..words_needed];
        slice.fill(0);
        f(slice)
    })
}

/// Compute the two per-pattern-constant confidence signals.
/// Extracted so both `extract_grouped_matches` and
/// `extract_plain_matches` share the same lazy `OnceCell` init
/// closure body (Rust can't `impl FnOnce<>` to share inline).
fn compute_pattern_signals(detector: &DetectorSpec, chunk: &Chunk) -> (bool, bool) {
    let kw = detector
        .keywords
        .iter()
        .any(|keyword| chunk.data.contains(keyword.as_str()));
    let sf = chunk
        .metadata
        .path
        .as_deref()
        .map(crate::confidence::is_sensitive_path)
        .unwrap_or(false);
    (kw, sf)
}

impl CompiledScanner {
    /// High-throughput coalesced scan: all files scanned in parallel,
    /// zero overhead for non-hit files.
    ///
    /// Architecture:
    ///   Phase 1: Parallel HS prefilter on raw bytes (no prep, no alloc)
    ///   Phase 2: Full extraction only on hit files (~5% of total)
    #[allow(clippy::needless_return)] // return needed under non-simd cfg branch
    pub fn scan_coalesced(&self, chunks: &[keyhog_core::Chunk]) -> Vec<Vec<keyhog_core::RawMatch>> {
        #[cfg(feature = "simd")]
        use crate::hw_probe::ScanBackend;
        use rayon::prelude::*;

        #[cfg(not(feature = "simd"))]
        {
            // Parallel CPU dispatch — same reasoning as scan_chunks_with_backend:
            // the per-chunk scan is independent and CPU-bound.
            let mut results: Vec<Vec<keyhog_core::RawMatch>> =
                chunks.par_iter().map(|c| self.scan(c)).collect();
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            return results;
        }

        #[cfg(feature = "simd")]
        {
            let Some(scanner) = &self.simd_prefilter else {
                // Hyperscan failed to initialize at compile time — fall back
                // to per-chunk parallel SimdCpu (or whichever backend the
                // scanner picks). Was serial; now uses rayon.
                return chunks.par_iter().map(|c| self.scan(c)).collect();
            };

            let ac_len = self.ac_map.len();

            // Phase 1: Parallel HS scan on RAW bytes. No prepare, no Arc, no alloc
            // for non-hit files. Thread-local scratch + a per-worker bitmask
            // POOL eliminate the per-chunk `vec![0u64; …]` alloc — we still
            // need owned Vecs in the result so phase 2 can consume them, but
            // empty-result chunks return `None` and skip the alloc entirely.
            let words_needed = ac_len.div_ceil(64);
            let triggers: Vec<Option<Vec<u64>>> = chunks
                .par_iter()
                .map(|chunk| {
                    let data = chunk.data.as_bytes();
                    with_trigger_buffer(words_needed, |scratch| {
                        for (hs_id, _start, _end) in scanner.scan(data) {
                            let Some((_det, dedup_id, _grp)) = scanner.pattern_info(hs_id) else {
                                continue;
                            };
                            if let Some(orig) = self.hs_index_map.get(dedup_id) {
                                for &idx in orig {
                                    if idx < ac_len {
                                        scratch[idx / 64] |= 1u64 << (idx % 64);
                                    }
                                }
                            }
                        }
                        if scratch.iter().any(|&w| w != 0) {
                            Some(scratch.to_vec())
                        } else {
                            None
                        }
                    })
                })
                .collect();

            let hit_count = triggers.iter().filter(|t| t.is_some()).count();
            let total_hs_matches: usize = triggers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|t| t.iter().map(|w| w.count_ones() as usize).sum::<usize>())
                .sum();
            tracing::info!(
                files = chunks.len(),
                hits = hit_count,
                hs_matches = total_hs_matches,
                "coalesced scan phase 1 complete"
            );

            // Phase 2: Full extraction on hit files + multiline fallback (parallel).
            let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                .par_iter()
                .zip(triggers.into_par_iter())
                .map(|(chunk, triggered_opt)| {
                    if let Some(triggered) = triggered_opt {
                        let prepared = self.prepare_chunk(chunk);
                        return self.scan_prepared_with_triggered(
                            prepared,
                            ScanBackend::SimdCpu,
                            triggered,
                            None,
                        );
                    }
                    // Multiline fallback: files with concatenation indicators AND
                    // secret-related keywords may contain secrets split across lines
                    // that HS can't match on raw bytes. Only scan these selectively.
                    #[cfg(feature = "multiline")]
                    if crate::multiline::has_concatenation_indicators(&chunk.data)
                        && has_secret_keyword_fast(chunk.data.as_bytes())
                    {
                        return self.scan(chunk);
                    }

                    // Generic key=value fallback: run on SMALL non-hit files only.
                    // Large source files (>32KB) are almost never config; scanning them
                    // for generic assignments wastes CPU on Go/Java/Python framework code.
                    if chunk.data.len() <= 32 * 1024
                        && has_generic_assignment_keyword(chunk.data.as_bytes())
                    {
                        let code_lines: Vec<&str> = chunk.data.lines().collect();
                        let line_offsets = crate::pipeline::compute_line_offsets(&chunk.data);
                        let mut scan_state =
                            crate::types::ScanState::with_static_intern(self.static_intern.clone());
                        self.scan_generic_assignments(
                            &code_lines,
                            &line_offsets,
                            chunk,
                            &mut scan_state,
                        );
                        let mut matches = scan_state.into_matches();
                        // Record fragments for cross-file secret reassembly.
                        // When scanning a monorepo, secrets are often split across
                        // config files (e.g., AWS_ACCESS_KEY in one, SECRET_KEY in another).
                        let mut reassembled_candidates = Vec::new();
                        for m in &matches {
                            if let Some(ref path) = chunk.metadata.path {
                                let fragment = crate::fragment_cache::SecretFragment {
                                    prefix: m.detector_id.to_string(),
                                    var_name: m.detector_name.to_string(),
                                    value: zeroize::Zeroizing::new(m.credential.to_string()),
                                    line: m.location.line.unwrap_or(0),
                                    path: Some(std::sync::Arc::from(path.to_string())),
                                };
                                let reassembled =
                                    self.fragment_cache.record_and_reassemble(fragment);
                                reassembled_candidates.extend(reassembled);
                            }
                        }
                        for candidate in reassembled_candidates {
                            // `candidate` is `Zeroizing<String>` — scrubbed
                            // when this loop iteration ends.
                            let entropy = crate::pipeline::match_entropy(candidate.as_bytes());
                            if entropy < 3.0 || candidate.len() < 16 {
                                continue;
                            }
                            // Build the dummy chunk's text in a `Zeroizing`
                            // and clone into the Chunk only as long as we
                            // need it; the original `Zeroizing` then drops
                            // and scrubs. Chunk.data is plain `String`
                            // because the scan API consumes `&Chunk` and
                            // we can't change that; we explicitly zero
                            // the chunk's data after the scan completes.
                            let mut dummy_data = String::with_capacity(candidate.len() + 24);
                            dummy_data.push_str("reassembled_key = \"");
                            dummy_data.push_str(candidate.as_str());
                            dummy_data.push('"');
                            let dummy_chunk = Chunk {
                                data: dummy_data.into(),
                                metadata: chunk.metadata.clone(),
                            };
                            let backend =
                                self.select_backend_for_file(dummy_chunk.data.len() as u64);
                            let mut reassembled_matches =
                                self.scan_inner(&dummy_chunk, backend, None);
                            matches.append(&mut reassembled_matches);
                            // Zeroized automatically (SensitiveString)
                        }
                        if !matches.is_empty() {
                            return matches;
                        }
                    }

                    Vec::new()
                })
                .collect();

            // Cross-chunk reassembly: synthesize a thin boundary buffer
            // from the tail of each chunk + head of its right neighbour
            // (same file, gapless) and scan it. Catches secrets split
            // across the 64 MiB scan-window boundary that in-chunk scan
            // can't see.
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            results
        } // #[cfg(feature = "simd")] block
    } // scan_coalesced

    pub(crate) fn scan_inner(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let prepared = self.prepare_chunk(chunk);
        let triggered =
            self.collect_triggered_patterns_for_backend(&prepared.preprocessed.text, backend);
        self.scan_prepared_with_triggered(prepared, backend, triggered, deadline)
    }

    pub(crate) fn extract_matches(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
        // Per-pattern deadline. Inner regex loops can produce many
        // matches on adversarial inputs (false_prefix_storm); without
        // a deadline-check inside those loops, --timeout is a lie for
        // those chunks. Threaded down to the inner loops below.
        deadline: Option<std::time::Instant>,
    ) {
        // Resilient lookup: a malformed `entry.detector_index` would otherwise
        // panic mid-scan and abort the whole rayon worker. The compiler should
        // never produce out-of-range indices, but this is the kind of
        // invariant whose violation should degrade one finding gracefully
        // rather than crash an entire repository scan.
        let Some(detector) = self.detectors.get(entry.detector_index) else {
            tracing::warn!(
                detector_index = entry.detector_index,
                detectors_len = self.detectors.len(),
                "extract_matches: detector_index out of range; skipping pattern"
            );
            return;
        };

        if let Some(group) = entry.group {
            self.extract_grouped_matches(
                entry,
                detector,
                group,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                base_line,
                base_offset,
                deadline,
            );
            return;
        }
        self.extract_plain_matches(
            entry,
            detector,
            preprocessed,
            line_offsets,
            code_lines,
            documentation_lines,
            chunk,
            scan_state,
            base_line,
            base_offset,
            deadline,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_grouped_matches(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        group: usize,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
        deadline: Option<std::time::Instant>,
    ) {
        let search_text = &preprocessed.text;
        // Lazy per-pattern dedup of two signals that are constant
        // across this pattern's matches but expensive to compute:
        //   `keyword_nearby` = `O(K × |chunk|)` substring scans.
        //   `sensitive_file` = Aho-Corasick scan over the file path.
        // Computing eagerly at `extract_matches` level regressed the
        // entropy_noise bench by -36% — many patterns trigger via
        // AC but produce zero matches, paying for compute they
        // never use. The OnceCell here keeps: zero-match patterns
        // pay nothing; first-match populates; subsequent matches
        // reuse the cached value.
        let signals = std::cell::OnceCell::<(bool, bool)>::new();
        // Reuse one CaptureLocations buffer across every iter tick instead of
        // allocating a fresh `Captures` per match. For a 100k-file scan
        // hitting 10k matches across a handful of hot patterns, that's tens
        // of thousands of avoided allocations per scan.
        let mut locs = entry.regex.capture_locations();
        let groups_total = locs.len();
        let mut cursor = 0usize;
        let bytes_total = search_text.len();
        // Inner-loop deadline check counter. Same `is_multiple_of(64)`
        // cadence as `scan_fallback_patterns` — frequent enough that
        // a hung pattern aborts within a few ms, infrequent enough
        // that the `Instant::now()` syscall isn't a hot-path tax.
        // Without this, a single regex producing 100k+ matches on an
        // adversarial chunk (false_prefix_storm, regex catastrophic
        // backtracking) would run unboundedly even with --timeout.
        let mut match_count: usize = 0;
        while cursor <= bytes_total {
            if let Some(deadline) = deadline {
                if match_count.is_multiple_of(64)
                    && match_count > 0
                    && std::time::Instant::now() >= deadline
                {
                    break;
                }
            }
            match_count += 1;
            let Some(whole) = entry.regex.captures_read_at(&mut locs, search_text, cursor) else {
                break;
            };
            let full_start = whole.start();
            let full_end = whole.end();
            // Advance the cursor up front so any `continue` below keeps the
            // loop progressing. Zero-width matches bump by one byte (and
            // align onto a UTF-8 boundary) to avoid an infinite loop.
            let mut next = if full_end == cursor {
                full_end + 1
            } else {
                full_end
            };
            while next < bytes_total && !search_text.is_char_boundary(next) {
                next += 1;
            }
            cursor = next;

            // Skip zero-width matches without surfacing them. The previous
            // `captures_iter`-based implementation never emitted these — its
            // internal iter advanced past them silently — so any downstream
            // logic (entropy, ML scoring, dedup) was never asked to grade
            // an empty credential. Replicating that semantics avoids a
            // behavior change disguised as a perf optimization.
            if full_end == full_start {
                continue;
            }

            // Resolve the configured capture group, falling back to the full
            // match when the group didn't participate (e.g. a top-level
            // alternation where one branch lacks the inner group).
            let credential_range = locs.get(group).unwrap_or((full_start, full_end));
            let mut credential = &search_text[credential_range.0..credential_range.1];

            // Variable-name heuristic: if the captured group looks like a
            // variable name rather than a secret, scan the other groups for
            // a value-shaped candidate. Same semantics as before, just
            // reading from CaptureLocations directly.
            if looks_like_variable_name(credential) && groups_total > 2 {
                for g in 1..groups_total {
                    if g == group {
                        continue;
                    }
                    if let Some((s, e)) = locs.get(g) {
                        let candidate_str = &search_text[s..e];
                        if !looks_like_variable_name(candidate_str) && candidate_str.len() >= 8 {
                            credential = candidate_str;
                            break;
                        }
                    }
                }
            }

            let &(keyword_nearby, sensitive_file) =
                signals.get_or_init(|| compute_pattern_signals(detector, chunk));
            self.process_match(
                entry,
                detector,
                search_text,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                credential,
                full_start,
                full_end,
                base_line,
                base_offset,
                keyword_nearby,
                sensitive_file,
            );
        }
    }

    #[allow(clippy::too_many_arguments, clippy::explicit_counter_loop)]
    fn extract_plain_matches(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        base_line: usize,
        base_offset: usize,
        deadline: Option<std::time::Instant>,
    ) {
        let search_text = &preprocessed.text;
        // Same lazy-on-first-match dedup as `extract_grouped_matches`;
        // see that function's doc-comment for the rationale.
        let signals = std::cell::OnceCell::<(bool, bool)>::new();
        // Inner-loop deadline counter — same `is_multiple_of(64)`
        // cadence as the grouped path so --timeout aborts cleanly
        // even on patterns that fire 100k+ matches per chunk.
        // `match_count` is named for readability (it represents an
        // iteration index used for deadline gating, not a generic
        // enumerator); the function-level `clippy::explicit_counter_loop`
        // allow keeps that clearer naming.
        let mut match_count: usize = 0;
        for matched in entry.regex.find_iter(search_text) {
            if let Some(deadline) = deadline {
                if match_count.is_multiple_of(64)
                    && match_count > 0
                    && std::time::Instant::now() >= deadline
                {
                    break;
                }
            }
            match_count += 1;
            let &(keyword_nearby, sensitive_file) =
                signals.get_or_init(|| compute_pattern_signals(detector, chunk));
            self.process_match(
                entry,
                detector,
                search_text,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                matched.as_str(),
                matched.start(),
                matched.end(),
                base_line,
                base_offset,
                keyword_nearby,
                sensitive_file,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_match(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        data: &str,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        credential: &str,
        match_start: usize,
        match_end: usize,
        base_line: usize,
        base_offset: usize,
        keyword_nearby: bool,
        sensitive_file: bool,
    ) {
        let (credential, match_end) =
            extend_known_prefix_credential(data, credential, match_start, match_end);
        let line = match_line_number(preprocessed, line_offsets, match_start);
        if is_within_hex_context(data, match_start, match_end) {
            return;
        }
        // Probabilistic gate: fast rejection of obvious non-secrets (UUIDs, low-diversity
        // strings) BEFORE the expensive false-positive context check and ML scoring.
        // Only applied to generic detectors — specific detectors with known prefixes
        // already have high confidence from the prefix match.
        if detector.id.starts_with("generic-")
            && crate::confidence::known_prefix_confidence_floor(credential).is_none()
            && !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential)
        {
            return;
        }
        if context::is_false_positive_context(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
        ) || context::is_false_positive_match_context(
            data,
            match_start,
            chunk.metadata.path.as_deref(),
        ) {
            return;
        }

        let inferred_context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        if crate::pipeline::should_suppress_known_example_credential_with_source(
            credential,
            chunk.metadata.path.as_deref(),
            inferred_context,
            Some(chunk.metadata.source_type.as_str()),
        ) {
            return;
        }

        // `match_companions` returns `None` when a `required = true`
        // companion isn't found within the search radius — that is a
        // hard skip signal, not "no companions found." The previous
        // `.unwrap_or_default()` swallowed it and let the match fire
        // anyway, silently nullifying the `required` field on every
        // detector that uses it (notably `twilio-auth-token`).
        let companions = if self.companions.is_empty() {
            HashMap::new()
        } else {
            match self.match_companions(entry, preprocessed, line) {
                Some(c) => c,
                None => return,
            }
        };
        let entropy = match_entropy(credential.as_bytes());

        if detector.id.starts_with("generic-") && detector.id != "generic-private-key" {
            // Per-detector entropy floor. Structured tokens (UUIDs, short API keys)
            // have lower entropy than random strings. A blanket 3.5 floor misses them.
            let entropy_floor = generic_entropy_floor(detector.id.as_str(), credential.len());
            if entropy < entropy_floor {
                return;
            }
            let camel_transitions = credential
                .as_bytes()
                .windows(2)
                .filter(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
                .count();
            if camel_transitions >= 2 && !credential.chars().any(|ch| ch.is_ascii_digit()) {
                return;
            }
        }

        // Checksum validation: tokens with embedded checksums (GitHub, npm, Slack,
        // Stripe, GitLab, PyPI) can be verified without network requests.
        // Valid checksum → floor confidence at 0.9 (confirmed real token format).
        // Invalid checksum → cap confidence at 0.1 (confirmed false positive).
        let checksum_result = crate::checksum::validate_checksum(credential);
        if checksum_result == crate::checksum::ChecksumResult::Invalid {
            // Checksum failed — this is NOT a real token. Skip expensive ML scoring.
            return;
        }

        let Some(score_result) = self.match_confidence(
            entry,
            chunk,
            credential,
            data,
            line,
            entropy,
            !companions.is_empty(),
            inferred_context,
            keyword_nearby,
            sensitive_file,
            scan_state,
        ) else {
            return;
        };

        match score_result {
            MlScoreResult::Final(mut confidence) => {
                // Boost confidence for checksum-validated tokens
                if checksum_result == crate::checksum::ChecksumResult::Valid {
                    confidence = confidence.max(0.9);
                }
                let raw_match = build_raw_match(
                    detector,
                    chunk,
                    credential,
                    companions,
                    match_start + base_offset,
                    line + base_line,
                    entropy,
                    confidence,
                    scan_state,
                );
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending {
                heuristic_conf,
                code_context,
                credential: pending_credential,
                ml_context,
            } => {
                let raw_match = build_raw_match(
                    detector,
                    chunk,
                    credential,
                    companions,
                    match_start + base_offset,
                    line + base_line,
                    entropy,
                    heuristic_conf,
                    scan_state,
                );
                scan_state.ml_pending.push(crate::types::MlPendingMatch {
                    raw_match,
                    heuristic_conf,
                    code_context,
                    credential: pending_credential,
                    ml_context,
                });
            }
        }
    }
}
