use super::CompiledScanner;
use crate::types::*;
use keyhog_core::{Chunk, RawMatch};
use std::collections::HashSet;
use std::sync::Arc;

impl CompiledScanner {
    pub(crate) fn post_process_matches(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        self.post_process_matches_inner(chunk, matches, deadline);
    }

    pub(crate) fn post_process_matches_inner(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        let pp_start = std::time::Instant::now();
        self.scan_cross_chunk_fragments(chunk, matches, deadline);

        #[cfg(feature = "decode")]
        if chunk.data.len() <= self.config.max_decode_bytes {
            // Dedup keys reuse the existing `Arc<str>` from `RawMatch` instead
            // of cloning to `String`. For 50+ pre-existing matches per chunk
            // this saves ~10-30 µs of allocator pressure per call.
            let mut seen: HashSet<(Arc<str>, Arc<str>)> = matches
                .iter()
                .map(|m| (Arc::clone(&m.detector_id), Arc::clone(&m.credential)))
                .collect();
            for decoded_chunk in crate::decode::decode_chunk(
                chunk,
                self.config.max_decode_depth,
                self.config.validate_decode,
                deadline,
                self.alphabet_screen.as_ref(),
            ) {
                // kimi-wave1 finding 5.LOW: a single decoded chunk that
                // exceeds `max_decode_bytes` slips past the outer guard
                // (which only checked the *input* chunk size). Skip
                // anything that grew past the configured ceiling - the
                // input was already a decode bomb if we got here.
                if decoded_chunk.data.len() > self.config.max_decode_bytes {
                    tracing::debug!(
                        path = ?chunk.metadata.path,
                        decoded_len = decoded_chunk.data.len(),
                        ceiling = self.config.max_decode_bytes,
                        "decoded chunk exceeds max_decode_bytes; skipping"
                    );
                    continue;
                }
                let decoded_matches = if decoded_chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                    self.scan_windowed(&decoded_chunk, deadline)
                } else {
                    // Decoded sub-chunks are post-process recursion;
                    // they're typically tiny (base64/hex/url payloads
                    // sliced out of the outer chunk). NEVER route them
                    // to the GPU literal-set: per-dispatch overhead
                    // (driver init + queue submit + sync) is 10-100 ms,
                    // and `KEYHOG_BACKEND=gpu` would otherwise force
                    // every decoded chunk through that path. On a
                    // 64 MiB chunk that decodes into 1 000 sub-chunks
                    // that's a 50-second tax - exactly the wall-clock
                    // delta keyhog used to show vs SIMD on messy
                    // corpora. Force a CPU backend here regardless of
                    // env override.
                    let decoded_backend = {
                        #[cfg(feature = "simd")]
                        {
                            crate::hw_probe::ScanBackend::SimdCpu
                        }
                        #[cfg(not(feature = "simd"))]
                        {
                            crate::hw_probe::ScanBackend::CpuFallback
                        }
                    };
                    self.scan_inner(&decoded_chunk, decoded_backend, deadline)
                };
                for m in decoded_matches {
                    if crate::context::is_known_example_credential(&m.credential)
                        && chunk.data.as_str().contains(m.credential.as_ref())
                    {
                        continue;
                    }
                    // Reverse-decoder example guard: a credential surfaced from a
                    // `/reverse` chunk whose REVERSED form carries a documentation
                    // marker (`…ELPMAXE…` is `EXAMPLE` reversed) is a reversed
                    // placeholder, not a hidden real secret. The forward checks
                    // miss it because the marker bytes are themselves reversed,
                    // and `is_known_example_credential` only matches a *trailing*
                    // EXAMPLE - reversal moves the marker mid-string. Without this,
                    // reversing a negative fixture that embeds EXAMPLE/PLACEHOLDER
                    // surfaces a false positive (smartsheet contract negative).
                    if decoded_chunk.metadata.source_type.contains("/reverse") {
                        let rev = crate::decode::reverse::reverse_str(&m.credential).to_uppercase();
                        if rev.contains("EXAMPLE")
                            || rev.contains("PLACEHOLDER")
                            || rev.contains("SAMPLE")
                            || rev.contains("YOUR_")
                        {
                            continue;
                        }
                    }
                    let key = (Arc::clone(&m.detector_id), Arc::clone(&m.credential));
                    if seen.insert(key) {
                        matches.push(m);
                    }
                }
            }
        }
        tracing::debug!(
            target: "keyhog::routing",
            chunk_bytes = chunk.data.len(),
            matches = matches.len(),
            elapsed_ms = pp_start.elapsed().as_millis() as u64,
            "post_process_matches_inner done",
        );
    }

    fn scan_cross_chunk_fragments(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
    ) {
        if !Self::has_fragment_assignment_syntax(chunk.data.as_bytes()) {
            return;
        }

        let Some(assign_re) = crate::shared_regexes::ASSIGN_RE.as_ref() else {
            return;
        };

        for (line_idx, line) in chunk.data.lines().enumerate() {
            if let Some(caps) = assign_re.captures(line) {
                let Some(var_name_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };

                let fragment_line = line_idx + 1;
                // Compute the trigger value's byte offset within chunk.data.
                // `line` borrows from chunk.data so pointer arithmetic gives
                // the line's offset; value_match.start() is offset within
                // `line`. Used below to give reassembled findings a REAL
                // source-file position instead of the synthetic
                // dummy_chunk offset (which used to read ~19 - the length
                // of the `reassembled_key = "` prefix). Synthetic offsets
                // broke the chunk-boundary recall invariant (proptest
                // gpu_proptest_invariants P3): identical credentials got
                // different offsets depending on whether the source was
                // scanned as one chunk or two, making the test see false
                // "drops". Real-source-offset removes that asymmetry.
                let fragment_value_offset = {
                    let line_offset =
                        line.as_ptr() as usize - chunk.data.as_ref().as_ptr() as usize;
                    line_offset + value_match.start()
                };
                // The contributing fragment's path. Reassembly is same-path
                // only (see `FragmentCache::record_and_reassemble`), so this
                // is the authoritative attribution for every candidate the
                // trigger fragment produces. Captured before the move below
                // so the reassembled finding's `file_path` can be stamped
                // from it instead of inherited from `chunk.metadata.clone()`.
                let fragment_path: Option<std::sync::Arc<str>> = chunk
                    .metadata
                    .path
                    .as_ref()
                    .map(|p| std::sync::Arc::from(p.as_str()));
                let fragment = crate::fragment_cache::SecretFragment {
                    prefix: crate::multiline::extract_prefix(var_name_match.as_str()),
                    var_name: var_name_match.as_str().to_string(),
                    value: zeroize::Zeroizing::new(value_match.as_str().to_string()),
                    line: fragment_line,
                    path: fragment_path.clone(),
                };

                let candidates = self.fragment_cache.record_and_reassemble(fragment);
                for candidate in candidates {
                    // `candidate` is `Zeroizing<String>` (kimi-wave1 fix).
                    let entropy = crate::pipeline::match_entropy(candidate.as_str().as_bytes());
                    if entropy < 3.0 || candidate.len() < 16 {
                        continue;
                    }

                    let mut dummy_data = String::with_capacity(candidate.len() + 24);
                    dummy_data.push_str("reassembled_key = \"");
                    dummy_data.push_str(candidate.as_str());
                    dummy_data.push('"');
                    let dummy_chunk = Chunk {
                        data: dummy_data.into(),
                        metadata: chunk.metadata.clone(),
                    };

                    // Tiny synthesized chunk - NEVER dispatch through
                    // GPU even if `KEYHOG_BACKEND=gpu` is set; the
                    // per-dispatch overhead (~10-100 ms) is orders of
                    // magnitude larger than scanning ~50 bytes on the
                    // CPU. The previous flow leaked the env override
                    // into `select_backend_for_file` and turned a
                    // 64 MiB messy-corpus scan into ~60 s of dummy
                    // GPU launches.
                    let backend = {
                        #[cfg(feature = "simd")]
                        {
                            crate::hw_probe::ScanBackend::SimdCpu
                        }
                        #[cfg(not(feature = "simd"))]
                        {
                            crate::hw_probe::ScanBackend::CpuFallback
                        }
                    };
                    let mut reassembled_matches = self.scan_inner(&dummy_chunk, backend, deadline);
                    for m in &mut reassembled_matches {
                        m.detector_id = format!("{}:reassembled", m.detector_id).into();
                        // Stamp the finding's path from the CONTRIBUTING
                        // fragment, not the synthetic `dummy_chunk` (which
                        // cloned the outer chunk's metadata). A candidate can
                        // be glued from a fragment recorded by an earlier
                        // chunk plus this trigger fragment; inheriting the
                        // dummy chunk's path mis-attributed the reassembled
                        // finding to whatever chunk happened to be scanning
                        // when reassembly fired - the cross-file attribution
                        // mangling that produced `:reassembled` FPs. Reassembly
                        // is same-path only, so `fragment_path` is the correct
                        // source for every candidate this fragment yields.
                        m.location.file_path = fragment_path.clone();
                        // Point the finding to the trigger fragment's
                        // line AND byte offset in the source chunk.
                        // Previously offset was the synthetic position
                        // inside `"reassembled_key = \"…\""` (~19 bytes
                        // from dummy_chunk start), which broke the
                        // chunk-boundary recall invariant since the
                        // same credential got different synthetic
                        // offsets depending on chunk topology.
                        m.location.line = Some(fragment_line);
                        // kimi-engine audit: chunk metadata can carry
                        // `base_offset` near usize::MAX (custom sources
                        // synthesizing chunks). Unchecked addition would
                        // panic in debug / wrap in release; saturating
                        // pins to MAX which is a benign garbage offset
                        // (no legitimate file is 18 EB long) but does
                        // not panic mid-scan.
                        m.location.offset =
                            fragment_value_offset.saturating_add(chunk.metadata.base_offset);
                    }
                    matches.append(&mut reassembled_matches);
                    // Zeroized automatically on drop (SensitiveString)
                }
            }
        }
    }

    fn has_fragment_assignment_syntax(data: &[u8]) -> bool {
        let has_assignment =
            memchr::memchr(b'=', data).is_some() || memchr::memchr(b':', data).is_some();
        let has_quote = memchr::memchr(b'"', data).is_some()
            || memchr::memchr(b'\'', data).is_some()
            || memchr::memchr(b'`', data).is_some();
        has_assignment && has_quote
    }

    pub(crate) fn expand_triggered_patterns(&self, triggered_patterns: &[u64]) -> Vec<u64> {
        // Propagate ONLY via `same_prefix_patterns`: when AC matches a
        // literal prefix shared by patterns X and Y, both X and Y need
        // to be evaluated since they're different regexes that happen
        // to share the same fixed prefix.
        //
        // The previous flow ALSO propagated via `detector_to_patterns`,
        // expanding to every other pattern of the same detector. That
        // was wasted work: each pattern is in `ac_map` *because* it has
        // a literal AC prefix, and if Y's prefix was not matched in
        // this chunk, Y's regex (which starts with that prefix) can't
        // match either. The expansion forced full-text regex passes on
        // patterns that were guaranteed to return no matches - the
        // dominant cost of the per-detector regex pass on chunks that
        // trigger multiple AC patterns of multi-pattern detectors.
        // No-trigger fast path: if no AC pattern fired, every word is
        // zero, so same-prefix expansion has nothing to propagate. Bail
        // BEFORE the `to_vec()` clone and the O(words) bit-scan loop -
        // the caller's `expanded.iter().any(|&w| w != 0)` would be false
        // anyway, so an empty vec is an equivalent (and cheaper) "no
        // patterns" signal. On the dominant no-hit chunk this drops the
        // expansion clone + scan to a single all-zero pass.
        if !triggered_patterns.iter().any(|&w| w != 0) {
            return Vec::new();
        }
        let mut expanded = triggered_patterns.to_vec();
        for (word_idx, &word) in triggered_patterns.iter().enumerate() {
            if word == 0 {
                continue;
            }
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let pat_idx = word_idx * 64 + bit;
                if pat_idx >= self.ac_map.len() {
                    break;
                }
                // kimi-engine audit: defensive bounds check. ac_map and
                // same_prefix_patterns SHOULD be the same length after
                // compilation, but if a future deserialization path
                // restores compiled state from disk with a mismatched
                // shape (or a bug in the compiler tears the invariant)
                // we'd panic on the indexed access. .get() turns that
                // into a benign skip - we lose the same-prefix expansion
                // for this pattern rather than crashing the scan.
                if let Some(siblings) = self.same_prefix_patterns.get(pat_idx) {
                    for &other_idx in siblings {
                        let other_idx = other_idx as usize;
                        // Same defensive bound on the expanded write -
                        // a stale sibling index past the bitmask end
                        // would otherwise panic via bounds-checked
                        // slice index. We compute the bucket up front
                        // and silently skip out-of-range writes.
                        let bucket = other_idx / 64;
                        if let Some(slot) = expanded.get_mut(bucket) {
                            *slot |= 1u64 << (other_idx % 64);
                        }
                    }
                }
                bits &= bits - 1; // clear lowest set bit
            }
        }
        expanded
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn extract_confirmed_patterns(
        &self,
        confirmed_patterns: &[usize],
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        for &pat_idx in confirmed_patterns {
            if let Some(deadline) = deadline {
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            let entry = if pat_idx < self.ac_map.len() {
                &self.ac_map[pat_idx]
            } else {
                let fallback_idx = pat_idx - self.ac_map.len();
                if fallback_idx >= self.fallback.len() {
                    continue;
                }
                &self.fallback[fallback_idx].0
            };
            self.extract_matches(
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
    }

    #[cfg(feature = "ml")]
    pub(crate) fn apply_ml_batch_scores(&self, scan_state: &mut ScanState) {
        if scan_state.ml_pending.is_empty() {
            return;
        }

        if !self.config.ml_enabled {
            let pending = scan_state.ml_pending.drain(..).collect::<Vec<_>>();
            for p in pending {
                let mut raw_match = p.raw_match;
                raw_match.confidence = Some(p.heuristic_conf);
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
            return;
        }

        // Borrow rather than clone - `ml_pending` is alive for the duration
        // of the call, so `&str` references stay valid through ML scoring.
        // On a wide scan with hundreds of pending matches this drops 2N
        // owned-string allocations per batch.
        let candidates: Vec<(&str, &str)> = scan_state
            .ml_pending
            .iter()
            .map(|pending| (pending.credential.as_str(), pending.ml_context.as_str()))
            .collect();

        let scores = crate::gpu::batch_ml_inference(&candidates, &self.config);
        let pending_matches: Vec<_> = scan_state.ml_pending.drain(..).collect();
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores) {
            // Honour the runtime `--ml-weight` / `ml_weight` knob instead
            // of the compile-time ML_WEIGHT/HEURISTIC_WEIGHT consts: the
            // blend is `w·ml + (1-w)·heuristic` with `w` already clamped to
            // [0,1] by `ScannerConfig::sanitise`. A hardcoded 0.6/0.4 made
            // the tuned knob a no-op (the tuned!=shipped trap) - now the
            // value the user / benchmark sets is the value the blend uses.
            let ml_weight = self.config.ml_weight;
            let mut final_score =
                (ml_weight * ml_conf) + ((1.0 - ml_weight) * pending.heuristic_conf);
            final_score = final_score.max(pending.heuristic_conf).max(ml_conf);

            // `--scan-comments` opts the Comment context out of the
            // ML-blended confidence multiplier so a real credential in
            // a `// TODO: rotate this …` comment surfaces with the
            // same weight as one on a bare assignment line. Test/docs contexts
            // stay penalized unless `--no-suppress-test-fixtures` is active.
            let context_penalty_applies = match pending.code_context {
                crate::context::CodeContext::Comment => !self.config.scan_comments,
                crate::context::CodeContext::TestCode
                | crate::context::CodeContext::Documentation => self.config.penalize_test_paths,
                _ => false,
            };
            if context_penalty_applies && final_score < 0.95 {
                final_score *= pending.code_context.confidence_multiplier();
            }

            let final_score = crate::confidence::apply_post_ml_penalties(
                final_score,
                &pending.credential,
                crate::confidence::is_service_anchored_detector(&pending.raw_match.detector_id),
            );
            let final_score = crate::confidence::apply_path_confidence_penalties(
                final_score,
                pending.raw_match.location.file_path.as_deref(),
                self.config.penalize_test_paths,
            );
            let final_score = if let Some(floor) =
                crate::confidence::known_prefix_confidence_floor(&pending.credential)
            {
                final_score.max(floor)
            } else {
                final_score
            };

            // Bayesian calibration multiplier (Tier-B #4). No-op when no
            // calibration cache exists or the detector has zero recorded
            // observations beyond the Beta(1,1) prior. Detectors with a
            // long clean track get amplified; chronic FP-emitters muted.
            let final_score = crate::confidence::apply_calibration_multiplier(
                final_score,
                &pending.raw_match.detector_id,
            );

            // Embedded-checksum adjudication - the FINAL confidence step so a
            // cryptographically-confirmed token (GitHub/npm/Slack/Stripe/GitLab/
            // PyPI) clears the `--precision` 0.85 bar regardless of how ML or
            // calibration scored its shape, and a checksum-failing one is
            // dropped. `process_match` already rejects `Invalid` before a match
            // reaches `ml_pending`, but the Pending branch never applied the
            // `Valid` floor that the non-ML `Final` branch did - so a confirmed
            // GitHub PAT was scored only on its 0.8 prefix floor and silently
            // suppressed under precision. Routing through the one shared policy
            // closes that gap and keeps the ML path self-consistent.
            let Some(final_score) =
                crate::checksum::checksum_adjusted_confidence(final_score, &pending.credential)
            else {
                continue;
            };

            // The fixture opt-out disables test/docs hard suppression too; low
            // confidence comments still follow `--scan-comments`.
            let hard_suppressed = pending.code_context.should_hard_suppress(final_score)
                && (self.config.penalize_test_paths
                    || matches!(pending.code_context, crate::context::CodeContext::Comment));
            if !hard_suppressed {
                let mut raw_match = pending.raw_match;
                raw_match.confidence = Some(final_score);
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
            }
        }
    }
}
