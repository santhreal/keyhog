pub(crate) mod confirmed_anchor;

use super::CompiledScanner;
use crate::types::*;
#[cfg(feature = "decode")]
use keyhog_core::SensitiveString;
use keyhog_core::{Chunk, RawMatch};
#[cfg(feature = "decode")]
use std::collections::HashSet;
use std::sync::atomic::Ordering::Relaxed;
#[cfg(feature = "decode")]
use std::sync::Arc;

// Profiling + suffix-gate machinery and the cross-chunk fragment scan were
// split into sibling satellites (Law 5). Re-export the public/crate interface
// so external paths (`scan_postprocess::{decode_profile_dump,
// build_confirmed_suffix_gate, ml_batch_profile_dump}`) keep resolving, and pull
// the recorder symbols this file's impl still pokes. The confirmed-suffix-gate
// ENABLE/override toggle now lives on the per-scanner `ScannerTuning`
// (`self.tuning.confirmed_suffix_gate_enabled()`); only the gate BUILDER remains
// in the suffix-gate satellite.
use super::scan_postprocess_profile::{
    confirmed_prof_enabled, confirmed_prof_reset, confirmed_prof_vecs,
};
#[cfg(feature = "decode")]
use super::scan_postprocess_profile::{
    decode_prof_enabled, DECODE_GEN_NS, DECODE_PARENTS, DECODE_SCAN_NS, DECODE_SUBCHUNKS,
    DECODE_SUBCHUNK_BYTES,
};
pub(crate) use super::scan_postprocess_profile::{decode_profile_dump, decode_profile_reset};
#[cfg(feature = "ml")]
use super::scan_postprocess_profile::{ml_batch_prof_enabled, ml_batch_record};
pub(crate) use super::scan_postprocess_profile::{ml_batch_profile_dump, ml_batch_profile_reset};
pub(crate) use super::scan_postprocess_suffix_gate::build_confirmed_suffix_gate;

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
            let prof_decode = decode_prof_enabled();
            // Dedup keys reuse the shared zeroizing credential from `RawMatch`
            // instead of cloning to `String`. For 50+ pre-existing matches per
            // chunk this saves ~10-30 µs of allocator pressure per call.
            let mut seen: HashSet<(Arc<str>, SensitiveString)> = matches
                .iter()
                .map(|m| (Arc::clone(&m.detector_id), m.credential.clone()))
                .collect();
            let gen_start = prof_decode.then(std::time::Instant::now);
            let decoded_chunks = {
                let _g = super::profile::span(super::profile::P::Decode);
                crate::decode::decode_chunk(
                    chunk,
                    self.config.max_decode_depth,
                    self.config.validate_decode,
                    deadline,
                    self.alphabet_screen.as_ref(),
                )
            };
            if let Some(t) = gen_start {
                DECODE_GEN_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
                if !decoded_chunks.is_empty() {
                    DECODE_PARENTS.fetch_add(1, Relaxed);
                    DECODE_SUBCHUNKS.fetch_add(decoded_chunks.len() as u64, Relaxed);
                }
            }
            // Buffer every surviving decoded match (after the per-sub-chunk
            // example/reverse guards) before the (detector, credential) dedup.
            // The SAME decoded credential can surface at more than one source
            // offset: once from the original encoded run and once from the
            // structured preprocessor's APPENDED copy (offset >= original_end+1,
            // i.e. inside synthesized text that isn't in the real chunk). The
            // dedup keeps only one alias, so WHICH offset wins must be the real,
            // lowest one - not whichever the (cmp/scan-order-dependent) iteration
            // happens to reach first. A higher synthetic-append offset is an
            // invalid source coordinate (it can point PAST the real chunk, e.g.
            // a boundary-buffer straddle match then fails its seam test and the
            // finding silently vanishes). Sort offset-ascending so the dedup
            // keeps the lowest (real) offset - the same primary-location rule
            // dedup_cross_detector applies (Law 10: no order-dependent recall).
            let mut decoded_candidates: Vec<RawMatch> = Vec::new();
            for decoded_chunk in decoded_chunks {
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
                if prof_decode {
                    DECODE_SUBCHUNK_BYTES.fetch_add(decoded_chunk.data.len() as u64, Relaxed);
                }
                let scan_start = prof_decode.then(std::time::Instant::now);
                // Mark the rescan so the phase-2 profiler can separate sub-chunk
                // per-pass cost from parent-chunk cost (cheap thread-local swap).
                let restore_rescan = super::profile::set_in_decode(true);
                let decoded_matches = if decoded_chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                    self.scan_windowed(&decoded_chunk, deadline)
                } else {
                    // Decoded sub-chunks are post-process recursion;
                    // they're typically tiny (base64/hex/url payloads
                    // sliced out of the outer chunk). NEVER route them
                    // to the GPU literal-set: per-dispatch overhead
                    // (driver init + queue submit + sync) is 10-100 ms,
                    // and `--backend gpu` would otherwise force
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
                super::profile::set_in_decode(restore_rescan);
                if let Some(t) = scan_start {
                    DECODE_SCAN_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
                }
                for m in decoded_matches {
                    if crate::context::is_known_example_credential(&m.credential)
                        && chunk.data.as_ref().contains(m.credential.as_ref())
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
                    decoded_candidates.push(m);
                }
            }
            // Prefer the lowest (real) source offset for each decoded
            // (detector, credential): a stable offset-ascending sort puts the
            // original encoded run ahead of any higher synthetic-append alias,
            // and the first-wins `seen` dedup below then keeps the real one.
            // Stable so equal-offset entries retain their (deterministic) scan
            // order. `seen` is still seeded from the pre-decode `matches`, so a
            // credential the base scan already reported suppresses every decoded
            // alias as before.
            decoded_candidates.sort_by_key(|m| m.location.offset);
            for m in decoded_candidates {
                let key = (Arc::clone(&m.detector_id), m.credential.clone());
                if seen.insert(key) {
                    matches.push(m);
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
        super::trigger_bitmap::for_each_set_bit(triggered_patterns, |pat_idx| {
            // kimi-engine audit: defensive bounds check. ac_map and
            // same_prefix_patterns SHOULD be the same length after
            // compilation, but if a future deserialization path
            // restores compiled state from disk with a mismatched
            // shape (or a bug in the compiler tears the invariant)
            // we'd panic on the indexed access. .get() turns that
            // into a benign skip - we lose the same-prefix expansion
            // for this pattern rather than crashing the scan.
            if pat_idx >= self.ac_map.len() {
                return;
            }
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
        });
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
        let prof = confirmed_prof_enabled();
        let total = self.ac_map.len() + self.phase2_patterns.len();
        // Suffix gate: one AC pass marks which required-suffix literals are
        // present in the chunk; a triggered pattern whose suffix literals are
        // ALL absent cannot match (every match ends with one of them), so its
        // whole-chunk regex run is skipped. `None` when the gate is disabled or
        // no pattern is gateable.
        let suffix_present: Option<std::collections::HashSet<usize>> = match &self.suffix_gate_ac {
            Some(ac) if self.tuning.confirmed_suffix_gate_enabled() => Some(
                ac.find_overlapping_iter(&*preprocessed.text)
                    .map(|m| m.pattern().as_usize())
                    .collect(),
            ),
            _ => None,
        };
        let suffix_allows = |pat_idx: usize| -> bool {
            if let Some(present) = &suffix_present {
                if let Some(gate) = self.ac_suffix_gate.get(pat_idx) {
                    if !gate.is_empty() && !gate.iter().any(|id| present.contains(&(*id as usize)))
                    {
                        return false;
                    }
                }
            }
            true
        };
        if let Some(anchor_index) = &self.confirmed_anchor_index {
            let has_active_anchored = confirmed_patterns
                .iter()
                .any(|&pat_idx| anchor_index.is_eligible(pat_idx) && suffix_allows(pat_idx));
            if has_active_anchored {
                confirmed_anchor::CONFIRMED_ANCHOR_CANDIDATES.with(|cell| {
                    let mut candidates = cell.borrow_mut();
                    anchor_index.collect_candidates(
                        &preprocessed.text,
                        |pat_idx| {
                            confirmed_patterns.binary_search(&pat_idx).is_ok()
                                && suffix_allows(pat_idx)
                        },
                        &mut candidates,
                    );
                    let mut i = 0usize;
                    while i < candidates.len() {
                        if let Some(deadline) = deadline {
                            if std::time::Instant::now() > deadline {
                                break;
                            }
                        }
                        let pat_idx = candidates[i].0 as usize;
                        let mut j = i + 1;
                        while j < candidates.len() && candidates[j].0 as usize == pat_idx {
                            j += 1;
                        }
                        let group = &candidates[i..j];
                        if let Some(entry) = self.ac_map.get(pat_idx) {
                            let t0 = if prof {
                                Some(std::time::Instant::now())
                            } else {
                                None
                            };
                            match anchor_index.anchored_regex(pat_idx) {
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
                                None => self.extract_matches(
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
                                ),
                            }
                            if let Some(t0) = t0 {
                                let (ns, runs) = confirmed_prof_vecs(total);
                                if let (Some(n), Some(r)) = (ns.get(pat_idx), runs.get(pat_idx)) {
                                    n.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
                                    r.fetch_add(1, Relaxed);
                                }
                            }
                        }
                        i = j;
                    }
                });
            }
        }
        for &pat_idx in confirmed_patterns {
            if let Some(deadline) = deadline {
                if std::time::Instant::now() > deadline {
                    break;
                }
            }
            // Skip a gated ac_map pattern whose required suffix literal is absent.
            if !suffix_allows(pat_idx) {
                continue;
            }
            if self
                .confirmed_anchor_index
                .as_ref()
                .is_some_and(|anchor_index| anchor_index.is_eligible(pat_idx))
            {
                continue;
            }
            let entry = if pat_idx < self.ac_map.len() {
                &self.ac_map[pat_idx]
            } else {
                let phase2_idx = pat_idx - self.ac_map.len();
                if phase2_idx >= self.phase2_patterns.len() {
                    continue;
                }
                &self.phase2_patterns[phase2_idx].0
            };
            let t0 = if prof {
                Some(std::time::Instant::now())
            } else {
                None
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
            if let Some(t0) = t0 {
                let (ns, runs) = confirmed_prof_vecs(total);
                if let (Some(n), Some(r)) = (ns.get(pat_idx), runs.get(pat_idx)) {
                    n.fetch_add(t0.elapsed().as_nanos() as u64, Relaxed);
                    r.fetch_add(1, Relaxed);
                }
            }
        }
    }

    /// Print and reset the per-pattern confirmed-pass profile (top 30 by time).
    pub(crate) fn confirmed_profile_dump(&self, label: &str) {
        let total = self.ac_map.len() + self.phase2_patterns.len();
        let (ns, runs) = confirmed_prof_vecs(total);
        let mut rows: Vec<(usize, u64, u64)> = (0..total)
            .map(|i| (i, ns[i].swap(0, Relaxed), runs[i].swap(0, Relaxed)))
            .filter(|&(_, n, _)| n > 0)
            .collect();
        rows.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        let grand: u64 = rows.iter().map(|r| r.1).sum();
        eprintln!(
            "=== CONFIRMED per-pattern [{label}] total={:.1} ms over {} triggered patterns ===",
            grand as f64 / 1e6,
            rows.len()
        );
        for (i, n, r) in rows.iter().take(30) {
            let src = if *i < self.ac_map.len() {
                self.ac_map[*i].regex.as_str()
            } else {
                self.phase2_patterns[*i - self.ac_map.len()]
                    .0
                    .regex
                    .as_str()
            };
            let per = if *r > 0 { *n / *r } else { 0 };
            let s: String = src.chars().take(60).collect();
            eprintln!(
                "  {:>6.1}ms {:>5.1}%  runs={:<6} {:>7}ns/run  {}",
                *n as f64 / 1e6,
                100.0 * *n as f64 / grand.max(1) as f64,
                r,
                per,
                s
            );
        }
    }

    pub(crate) fn confirmed_profile_reset(&self) {
        confirmed_prof_reset(self.ac_map.len() + self.phase2_patterns.len());
    }

    #[cfg(feature = "ml")]
    fn score_ml_pending_cpu(&self, pending_matches: &[MlPendingMatch]) -> Vec<f64> {
        pending_matches
            .iter()
            .map(|pending| {
                crate::ml_scorer::score_with_config(
                    pending.credential.as_str(),
                    pending.ml_context.as_str(),
                    &self.config.known_prefixes,
                    &self.config.secret_keywords,
                    &self.config.test_keywords,
                    &self.config.placeholder_keywords,
                )
            })
            .collect()
    }

    #[cfg(feature = "ml")]
    pub(crate) fn apply_ml_batch_scores(&self, scan_state: &mut ScanState) {
        if ml_batch_prof_enabled() {
            ml_batch_record(scan_state.ml_pending.len());
        }
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

        let scores = crate::gpu::batch_ml_inference_with_timeout(
            &candidates,
            &self.config,
            self.tuning.gpu_moe_timeout(),
        );
        let pending_matches: Vec<_> = scan_state.ml_pending.drain(..).collect();
        let scores = if scores.len() == pending_matches.len() {
            scores
        } else {
            tracing::warn!(
                pending = pending_matches.len(),
                scores = scores.len(),
                "ML score count mismatch; recomputing CPU MoE scores before confidence blending"
            );
            self.score_ml_pending_cpu(&pending_matches)
        };
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores.into_iter()) {
            // Honour the runtime `--ml-weight` / `ml_weight` knob instead
            // of the compile-time ML_WEIGHT/HEURISTIC_WEIGHT consts: the
            // blend is `w·ml + (1-w)·heuristic` with `w` already clamped to
            // [0,1] by `ScannerConfig::sanitise`. A hardcoded 0.6/0.4 made
            // the tuned knob a no-op (the tuned!=shipped trap) - now the
            // value the user / benchmark sets is the value the blend uses.
            let ml_weight = self.config.ml_weight;
            let mut final_score = if pending.model_authoritative {
                // Entropy-fallback candidate: the MoE is the unified scorer. The
                // "heuristic" here is bare entropy magnitude, which is precisely
                // what mislabels high-entropy non-secrets (FQDNs, git SHAs,
                // base64 blobs) - so it must NOT floor the model. Taking the
                // model score directly lets the MoE suppress those FPs (probe:
                // structured non-secrets score ~0.01, real secrets ~0.98) while
                // the downstream penalty/checksum/floor pipeline below still
                // applies uniformly. The shape gates in scan_entropy_fallback
                // already removed the cheap non-secrets before this point.
                ml_conf
            } else {
                // Detector/generic match: the regex is positive evidence, so the
                // heuristic is a confidence FLOOR and the model can only raise.
                let blended = (ml_weight * ml_conf) + ((1.0 - ml_weight) * pending.heuristic_conf);
                blended.max(pending.heuristic_conf).max(ml_conf)
            };

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

            // Bayesian calibration multiplier (Tier-B #4). No-op unless the
            // resolved scan config explicitly supplied a calibration store, or
            // when the detector has zero recorded observations beyond the
            // Beta(1,1) prior. Detectors with a long clean track get amplified;
            // chronic FP-emitters muted.
            let final_score = crate::confidence::apply_calibration_multiplier(
                final_score,
                &pending.raw_match.detector_id,
                self.config.calibration.as_deref(),
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
