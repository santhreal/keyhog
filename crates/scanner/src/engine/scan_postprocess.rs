pub(crate) mod confirmed_anchor;
#[cfg(feature = "decode")]
pub(crate) mod decode;

use super::CompiledScanner;
#[cfg(feature = "decode")]
use crate::types::MAX_SCAN_CHUNK_BYTES;
use keyhog_core::{Chunk, RawMatch};

/// Deduplicate a literal into a shared `literals` Vec, returning its index.
/// Avoids the `entry(lit.clone()).or_insert_with(|| push(lit.clone()))`
/// double-clone by checking `get` first: zero clones when the literal is
/// already known, two clones only on first insertion (one for the Vec, one
/// for the HashMap key).
pub(crate) fn register_literal(
    literals: &mut Vec<String>,
    ids: &mut std::collections::HashMap<String, usize>,
    lit: &str,
) -> usize {
    if let Some(&id) = ids.get(lit) {
        return id;
    }
    let id = literals.len();
    let owned = lit.to_string();
    literals.push(owned.clone());
    ids.insert(owned, id);
    id
}

// Re-export the post-processing satellites through their established engine paths.
// Scanner tuning owns enablement; the suffix-gate satellite only builds the gate.
#[cfg(feature = "decode")]
pub(crate) use super::scan_postprocess_profile::{
    decode_recursion_from_typed, format_decode_recursion,
};
#[cfg(feature = "ml")]
pub(crate) use super::scan_postprocess_profile::{
    format_ml_batch_profile, ml_batch_profile_from_parts,
};
pub(crate) use super::scan_postprocess_suffix_gate::build_confirmed_suffix_gate_with_hints;

impl CompiledScanner {
    pub(crate) fn post_process_matches(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<()> {
        self.post_process_matches_with_decoder_absence(chunk, matches, deadline, route, false)
    }

    pub(crate) fn post_process_matches_with_decoder_absence(
        &self,
        chunk: &Chunk,
        matches: &mut Vec<RawMatch>,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
        #[cfg_attr(not(feature = "decode"), allow(unused_variables))] decoder_absence: bool,
    ) -> crate::error::Result<()> {
        if crate::deadline::expired(deadline) {
            return Ok(());
        }
        // No stopwatch here. This region is inclusive of the `Stage::Decode`
        // span opened below and of the phase-2 leaves the resolution tail
        // re-enters, so its wall was never an addend of anything. It also used
        // to be gated on a tracing LEVEL rather than on the measurement switch,
        // which made `tracing` a second place that decided whether to measure.
        self.scan_cross_chunk_fragments(chunk, matches, deadline, route)?;
        if crate::deadline::expired(deadline) {
            return Ok(());
        }

        #[cfg(feature = "decode")]
        {
            let decode_parent = |chunk: &Chunk,
                                 matches: &mut Vec<RawMatch>|
             -> crate::error::Result<()> {
                // Generation time is owned by the profile runtime's Decode stage
                // span; rescan time by its Decoded attribution on every leaf span
                // inside the rescans below. The counts/bytes are typed counters in
                // the same runtime (no-ops when no runtime is active).
                let decoded_chunks = {
                    let _g = super::profile::span(keyhog_profile::Stage::Decode);
                    crate::decode::decode_chunk_with_policy(
                        chunk,
                        self.detector_plans.decode_transforms(),
                        self.detector_plans.decoder_plan(),
                        self.config.max_decode_depth,
                        self.config.validate_decode,
                        deadline,
                        self.route_classification.alphabet_screen.as_ref(),
                    )
                };
                if crate::deadline::expired(deadline) {
                    return Ok(());
                }
                // Empty decode-through on this line vocabulary: later windows
                // with the same unique-line fingerprint can skip the pipeline.
                // Only record proofs for parent filesystem/windowed slices so
                // unrelated sources cannot fill/clear the shared memo.
                if decoded_chunks.is_empty()
                    && chunk.metadata.decoded_span.is_none()
                    && chunk.metadata.source_type.as_ref() == "filesystem/windowed"
                {
                    super::scan::mark_decode_vocab_empty(
                        &self.vocab_stage_absence_cache,
                        self.detector_digest,
                        self.entropy_evidence_config_digest(),
                        super::scan::vocab_path_class(
                            chunk.metadata.source_type.as_ref(),
                            chunk.metadata.path.as_deref(),
                        ),
                        &chunk.data,
                    );
                }
                if !decoded_chunks.is_empty() {
                    keyhog_profile::add_counter(keyhog_profile::CounterId::DecodeParentChunks, 1);
                    keyhog_profile::add_counter(
                        keyhog_profile::CounterId::DecodeDerivedChunks,
                        decoded_chunks.len() as u64,
                    );
                }
                // Avoid allocating dedup state when decoding produced no sub-chunks.
                if !decoded_chunks.is_empty() {
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
                        keyhog_profile::add_counter(
                            keyhog_profile::CounterId::DecodeDerivedBytes,
                            decoded_chunk.data.len() as u64,
                        );
                        // Track recursive decode work separately and preserve the
                        // calibrated route's explicit small-buffer backend.
                        let restore_rescan = super::profile::set_in_decode(true);
                        let decoded_backend = route.decode_backend;
                        let decoded_result = if decoded_chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                            self.scan_windowed(&decoded_chunk, decoded_backend, deadline, route)
                        } else {
                            self.scan_inner(&decoded_chunk, decoded_backend, deadline, route)
                        };
                        super::profile::set_in_decode(restore_rescan);
                        let decoded_matches = decoded_result?;
                        if crate::deadline::expired(deadline) {
                            break;
                        }
                        for m in decoded_matches {
                            // Generic decoded matches retain structural assignment evidence.
                            let path = chunk.metadata.path.as_deref();
                            let is_entropy = self.detector_plans.is_entropy(m.detector_id.as_ref());
                            let suppressed = crate::adjudicate::record_decoded_unanchored_entropy_suppression(
                                &m, path, is_entropy,
                            ) || crate::adjudicate::record_decoded_parent_example_suppression(
                                &m, path, chunk.data.as_ref(),
                            ) || crate::adjudicate::record_decoded_reverse_placeholder_suppression(
                                &m,
                                decoded_chunk.metadata.path.as_deref().or(path),
                                &decoded_chunk.metadata.source_type,
                            );
                            if suppressed {
                                continue;
                            }
                            decoded_candidates.push(m);
                        }
                    }
                    if decoded_candidates.is_empty() {
                        return Ok(());
                    }
                    // Decoding is monotonic: keep raw findings and union resolved decoded evidence.
                    let raw_findings = matches.clone();

                    decoded_candidates.sort_by(|a, b| {
                        a.location
                            .offset
                            .cmp(&b.location.offset)
                            .then_with(|| a.cmp(b))
                    });
                    decode::union_unique_matches(matches, decoded_candidates);
                    let resolved = crate::resolution::try_resolve_matches_with_compiled_plan(
                        std::mem::take(matches),
                        &self.detector_plans,
                    )
                    .map_err(|error| {
                        crate::ScanError::Config(format!(
                            "compiled detector resolution failed: {error}"
                        ))
                    })?;
                    let mut merged = raw_findings;
                    decode::union_unique_matches(&mut merged, resolved);
                    *matches = merged;
                }
                Ok(())
            };
            if chunk.data.len() <= self.config.max_decode_bytes
                && self.chunk_needs_decode_postprocess_with_absence(chunk, decoder_absence)
            {
                decode_parent(chunk, matches)?;
            } else if self.chunk_uses_bounded_decode_windows(chunk) {
                let overlap = self.decode_window_overlap_bytes();
                decode::decode_source_windows(self.config.max_decode_bytes, chunk, overlap, |w| {
                    self.chunk_needs_decode_postprocess(w)
                        .then(|| decode_parent(w, matches))
                        .unwrap_or(Ok(()))
                })?;
            }
        }
        tracing::debug!(
            target: "keyhog::routing",
            chunk_bytes = chunk.data.len(),
            matches = matches.len(),
            "post_process_matches done",
        );
        Ok(())
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
