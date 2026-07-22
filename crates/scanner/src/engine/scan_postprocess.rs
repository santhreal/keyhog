pub(crate) mod confirmed_anchor;

use super::CompiledScanner;
#[cfg(feature = "decode")]
use crate::types::MAX_SCAN_CHUNK_BYTES;
#[cfg(feature = "decode")]
use keyhog_core::SensitiveString;
use keyhog_core::{Chunk, RawMatch};
#[cfg(feature = "decode")]
use std::collections::HashSet;
#[cfg(feature = "decode")]
use std::sync::atomic::Ordering::Relaxed;
#[cfg(feature = "decode")]
use std::sync::Arc;

// Re-export the post-processing satellites through their established engine paths.
// Scanner tuning owns enablement; the suffix-gate satellite only builds the gate.
#[cfg(feature = "decode")]
use super::scan_postprocess_profile::{
    decode_prof_enabled, DECODE_GEN_NS, DECODE_PARENTS, DECODE_SCAN_NS, DECODE_SUBCHUNKS,
    DECODE_SUBCHUNK_BYTES,
};
pub(crate) use super::scan_postprocess_profile::{decode_profile_dump, decode_profile_reset};
pub(crate) use super::scan_postprocess_profile::{ml_batch_profile_dump, ml_batch_profile_reset};
pub(crate) use super::scan_postprocess_suffix_gate::build_confirmed_suffix_gate;

impl CompiledScanner {
    pub(crate) fn post_process_matches(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
    ) {
        self.post_process_matches_inner(chunk, matches, deadline, route);
    }

    pub(crate) fn post_process_matches_inner(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
    ) {
        if crate::deadline::expired(deadline) {
            return;
        }
        let pp_start = tracing::enabled!(target: "keyhog::routing", tracing::Level::DEBUG)
            .then(std::time::Instant::now);
        self.scan_cross_chunk_fragments(chunk, matches, deadline, route);
        if crate::deadline::expired(deadline) {
            return;
        }

        #[cfg(feature = "decode")]
        if chunk.data.len() <= self.config.max_decode_bytes {
            let prof_decode = decode_prof_enabled();
            let gen_start = prof_decode.then(std::time::Instant::now);
            let decoded_chunks = {
                let _g = super::profile::span(super::profile::P::Decode);
                crate::decode::decode_chunk_with_policy(
                    chunk,
                    self.detector_plans.decode_transforms(),
                    self.detector_plans.decoder_plan(),
                    self.config.max_decode_depth,
                    self.config.validate_decode,
                    deadline,
                    self.alphabet_screen.as_ref(),
                )
            };
            if crate::deadline::expired(deadline) {
                return;
            }
            if let Some(t) = gen_start {
                DECODE_GEN_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
                if !decoded_chunks.is_empty() {
                    DECODE_PARENTS.fetch_add(1, Relaxed);
                    DECODE_SUBCHUNKS.fetch_add(decoded_chunks.len() as u64, Relaxed);
                }
            }
            // Avoid allocating dedup state when decoding produced no sub-chunks.
            if !decoded_chunks.is_empty() {
                // Decoding is monotonic: a transform may add evidence, but it
                // must never erase a finding already established on source
                // bytes. Keep the raw set so conflict resolution over the
                // combined evidence can be unioned back into it below.
                let raw_findings = matches.clone();
                let mut seen: HashSet<(Arc<str>, SensitiveString)> = matches
                    .iter()
                    .map(|m| (Arc::clone(&m.detector_id), m.credential.clone()))
                    .collect();
                // Buffer, then sort by source offset so synthesized aliases cannot
                // win `(detector, credential)` dedup over a real source coordinate.
                let mut decoded_candidates: Vec<RawMatch> = Vec::new();
                for decoded_chunk in decoded_chunks {
                    if crate::deadline::expired(deadline) {
                        break;
                    }
                    if decoded_chunk.data.len() > self.config.max_decode_bytes {
                        crate::telemetry::record_decode_truncation();
                        // LAW10: decode truncation is counted in scanner coverage
                        // telemetry before this debug detail is emitted.
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
                    // Track recursive decode work separately and preserve the
                    // calibrated route's explicit small-buffer backend.
                    let restore_rescan = super::profile::set_in_decode(true);
                    let decoded_backend = route.decode_backend;
                    let decoded_matches = if decoded_chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                        self.scan_windowed(&decoded_chunk, decoded_backend, deadline, route)
                    } else {
                        self.scan_inner(&decoded_chunk, decoded_backend, deadline, route)
                    };
                    super::profile::set_in_decode(restore_rescan);
                    if crate::deadline::expired(deadline) {
                        break;
                    }
                    if let Some(t) = scan_start {
                        DECODE_SCAN_NS.fetch_add(t.elapsed().as_nanos() as u64, Relaxed);
                    }
                    for m in decoded_matches {
                        // Generic decoded matches retain structural assignment evidence.
                        if crate::adjudicate::record_decoded_unanchored_entropy_suppression(
                            &m,
                            chunk.metadata.path.as_deref(),
                            self.detector_plans.is_entropy(m.detector_id.as_ref()),
                        ) {
                            continue;
                        }
                        if crate::adjudicate::record_decoded_parent_example_suppression(
                            &m,
                            chunk.metadata.path.as_deref(),
                            chunk.data.as_ref(),
                        ) {
                            continue;
                        }
                        if crate::adjudicate::record_decoded_reverse_placeholder_suppression(
                            &m,
                            decoded_chunk
                                .metadata
                                .path
                                .as_deref()
                                .or(chunk.metadata.path.as_deref()),
                            &decoded_chunk.metadata.source_type,
                        ) {
                            continue;
                        }
                        decoded_candidates.push(m);
                    }
                }
                // Lowest real source offset wins aliases; `seen` starts with raw findings.
                decoded_candidates.sort_by_key(|m| m.location.offset);
                for m in decoded_candidates {
                    let key = (Arc::clone(&m.detector_id), m.credential.clone());
                    if seen.insert(key) {
                        matches.push(m);
                    }
                }
                let resolved = crate::resolution::try_resolve_matches_with_compiled_plan(
                    std::mem::take(matches),
                    &self.detector_plans,
                )
                .expect(
                    "compiled detector resolution must remain valid after decoded finding merge",
                );
                let mut merged = raw_findings;
                let mut merged_seen: HashSet<(Arc<str>, SensitiveString)> = merged
                    .iter()
                    .map(|m| (Arc::clone(&m.detector_id), m.credential.clone()))
                    .collect();
                for m in resolved {
                    let key = (Arc::clone(&m.detector_id), m.credential.clone());
                    if merged_seen.insert(key) {
                        merged.push(m);
                    }
                }
                *matches = merged;
            }
        }
        tracing::debug!(
            target: "keyhog::routing",
            chunk_bytes = chunk.data.len(),
            matches = matches.len(),
            elapsed_ms = pp_start.map_or(0, |t| t.elapsed().as_millis() as u64),
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
            if pat_idx >= self.ac_map.len() {
                crate::telemetry::record_invalid_pattern_index_skip();
                return;
            }
            let Some(siblings) = self.same_prefix_patterns.get(pat_idx) else {
                crate::telemetry::record_invalid_pattern_index_skip();
                return;
            };
            for &other_idx in siblings {
                let other_idx = other_idx as usize;
                let bucket = other_idx / 64;
                if let Some(slot) = expanded.get_mut(bucket) {
                    *slot |= 1u64 << (other_idx % 64);
                } else {
                    crate::telemetry::record_invalid_pattern_index_skip();
                }
            }
        });
        expanded
    }
}
