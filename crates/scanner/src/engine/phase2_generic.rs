use super::*;
use std::sync::Mutex;

pub(crate) mod keywords;
mod metrics;
mod pattern;

use self::keywords::{
    collect_generic_keyword_lines_from_positions, collect_generic_keyword_lines_with,
    is_strong_keyword_anchored_encoded_text_secret,
};
pub(crate) use self::metrics::{format_generic_profile, generic_profile_from_typed};
pub(crate) use self::pattern::{
    build_generic_re, compile_generic_re_with_max, compile_generic_re_with_policy,
    generic_keyword_alternation, generic_keyword_alternation_from, generic_vendor_suffix_arm,
};

const MAX_IDLE_KEYWORD_LINE_BUFFERS: usize = 4;
static KEYWORD_LINES_POOL: Mutex<Vec<Vec<u32>>> = Mutex::new(Vec::new());

fn normalize_keyword_lines_scratch(lines: &mut Vec<u32>) {
    lines.clear();
    if lines.capacity().saturating_mul(std::mem::size_of::<u32>())
        > super::MAX_RETAINED_WORKER_SCRATCH_BYTES
    {
        *lines = Vec::new();
    }
}

fn take_keyword_lines_scratch() -> Vec<u32> {
    KEYWORD_LINES_POOL
        .lock()
        // LAW10: poison recovery retains the complete scratch pool value.
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pop()
        // LAW10: no idle buffer means a fresh empty scratch vector with identical matching behavior.
        .unwrap_or_default()
}

fn release_keyword_lines_scratch(mut lines: Vec<u32>) {
    normalize_keyword_lines_scratch(&mut lines);
    if lines.capacity() == 0 {
        return;
    }
    let mut pool = KEYWORD_LINES_POOL
        .lock()
        // LAW10: poison recovery retains the complete scratch pool before bounded reinsertion.
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if pool.len() < MAX_IDLE_KEYWORD_LINE_BUFFERS {
        pool.push(lines);
    }
}

#[cfg(test)]
pub(crate) fn retained_keyword_line_bytes_after_for_test(requested_bytes: usize) -> usize {
    let elements = requested_bytes.div_ceil(std::mem::size_of::<u32>());
    let mut lines = Vec::with_capacity(elements);
    normalize_keyword_lines_scratch(&mut lines);
    lines.capacity().saturating_mul(std::mem::size_of::<u32>())
}

impl CompiledScanner {
    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_generic_keyword_scanned_bytes_for_diagnostics(&self) {
        self.generic_keyword_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn generic_keyword_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.generic_keyword_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Scans generic assignments after keyword, entropy, and placeholder admission.
    /// Named and generic evidence is reconciled by the shared resolution pass.
    pub(crate) fn scan_generic_assignments(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        generic_keyword_positions: Option<&[u32]>,
        deadline: Option<std::time::Instant>,
    ) {
        let Some(generic_plan) = self.detector_plans.generic_assignment() else {
            return;
        };
        let generic_re = generic_plan.matcher();
        let generic_keyword_stems = generic_plan.stems();

        // Derive candidate lines in one chunk-level stem scan before regex extraction.
        let scan_text: &str = &preprocessed.text;
        let identity_offsets = std::ptr::eq(scan_text.as_ptr(), chunk.data.as_ptr())
            && scan_text.len() == chunk.data.len();
        // `prepare_chunk` runs `normalize_homoglyphs` over the WHOLE chunk when
        // unicode normalization is on, and only hands back the original buffer
        // when every char normalized to itself. So `identity_offsets` (the scan
        // text IS `chunk.data`) is a proof that this chunk holds no homoglyph,
        // zero-width, RTL, combining mark or evasion control. Each line below is
        // a char-boundary substring of that same buffer, so the per-line
        // normalization is then a proven identity and its whole-line rescan is
        // pure overhead. With normalization off the chunk was never normalized,
        // so the per-line pass still has real work and stays.
        let lines_already_normalized = identity_offsets && self.config.unicode_normalization;
        // Take ownership so the RefCell is not borrowed during the consume loop.
        let mut lines_with_keyword = take_keyword_lines_scratch();
        let prefilter = metrics::prefilter_span();
        if let Some(positions) = generic_keyword_positions {
            collect_generic_keyword_lines_from_positions(
                line_index,
                positions,
                &mut lines_with_keyword,
            );
        } else {
            #[cfg(debug_assertions)]
            self.generic_keyword_scanned_bytes.fetch_add(
                // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                u64::try_from(scan_text.len()).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
            collect_generic_keyword_lines_with(
                generic_keyword_stems,
                scan_text,
                &mut lines_with_keyword,
            );
        }
        drop(prefilter);
        metrics::record_prefilter_call(lines_with_keyword.len());
        if lines_with_keyword.is_empty() {
            release_keyword_lines_scratch(lines_with_keyword);
            return;
        }
        if crate::deadline::expired(deadline) {
            release_keyword_lines_scratch(lines_with_keyword);
            return;
        }

        // One guard replaces four hand-placed `record_extract_ns` calls. The
        // two early deadline returns below used to have to remember to record,
        // and a future third return would have silently lost its time. Dropped
        // explicitly at the end so the measured interval still stops exactly
        // where the old call did, before the buffer returns to the pool.
        let extract = metrics::extract_span();
        for line_iter in 0..lines_with_keyword.len() {
            if crate::deadline::expired_on_cadence(
                deadline,
                line_iter,
                crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
            ) {
                release_keyword_lines_scratch(lines_with_keyword);
                return;
            }
            let line_idx = lines_with_keyword[line_iter] as usize;
            let Some(line_offset) = line_index.line_start(line_idx) else {
                continue;
            };
            let Some(raw_line) = line_index.line(scan_text, line_idx) else {
                continue;
            };
            // Extract from normalized text so in-value zero-width characters cannot
            // truncate the candidate. Pure ASCII remains borrowed and offsets stay raw.
            let normalized_line;
            let line: &str = if lines_already_normalized {
                raw_line
            } else {
                normalized_line = crate::unicode_hardening::normalize_homoglyphs(raw_line);
                &normalized_line
            };
            if generic_keyword_positions.is_some()
                && !generic_keyword_stems.has_assignment_delimiter_after_stem(line.as_bytes())
            {
                continue;
            }
            let mut covered_until = 0;

            for (capture_iter, caps) in generic_re.captures_iter(line).enumerate() {
                if crate::deadline::expired_on_cadence(
                    deadline,
                    capture_iter,
                    crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
                ) {
                    release_keyword_lines_scratch(lines_with_keyword);
                    return;
                }
                metrics::record_regex_capture();
                let Some(keyword_match) = caps.get(1) else {
                    continue;
                };
                if keyword_match.start() < covered_until {
                    continue;
                }
                let Some(value_match) = caps.get(2) else {
                    continue;
                };
                let keyword = keyword_match.as_str();
                if crate::adjudicate::generic_bridge_keyword_boundary_rejected(
                    keyword,
                    line,
                    keyword_match.start(),
                ) {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::KeywordBoundary,
                    );
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        keyword,
                        &generic_ctx,
                    );
                    continue;
                }
                let whole_value = crate::detector_execution_policy::whole_assignment_value(
                    line,
                    value_match.start(),
                    value_match.end(),
                );
                covered_until = covered_until.max(whole_value.covered_end);
                let value = whole_value.as_str(line);
                // Resolve the detector before any detector-specific value gate.
                // The bare-auth bridge must use the same compiled TOML policy as
                // the entropy, shape, and BPE stages below.
                let Some(owner_resolution) =
                    self.detector_plans.generic_ownership().resolve(keyword)
                else {
                    tracing::error!(
                    keyword,
                    "compiled generic assignment matched without a detector owner; dropping candidate"
                );
                    continue;
                };
                let owning_detector_index = owner_resolution.owning_index;
                let detector_plan = self.detector_plans.get(owning_detector_index);
                let match_confidence = self.detector_plans.match_confidence(owning_detector_index);
                let execution_policy = &detector_plan.execution;
                let metadata = &detector_plan.metadata;
                let preprocessed_offset = line_offset + whole_value.start;
                let source_start =
                    preprocessed.source_offset_for_match(&chunk.data, preprocessed_offset, value);
                let source_end = source_start + value.len();
                let source_whole = chunk
                    .data
                    .get(source_start..source_end)
                    .filter(|source_value| *source_value == value)
                    .map(|_| {
                        crate::detector_execution_policy::whole_assignment_value(
                            &chunk.data,
                            source_start,
                            source_end,
                        )
                    });
                let candidate_len = source_whole.map_or(value.len(), |span| span.end - span.start);
                let partial_source_value =
                    source_whole.is_some_and(|span| !span.is_exact(source_start, source_end));
                let telemetry_value = source_whole.map_or(value, |span| span.as_str(&chunk.data));
                let length_stage = crate::adjudicate::generic_bridge_length_stage(
                    execution_policy.length.rejection(candidate_len),
                    partial_source_value,
                );
                if let Some(stage_id) = length_stage {
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        telemetry_value,
                        &crate::adjudicate::MatchCtx::for_stage(stage_id),
                    );
                    continue;
                }
                let Some(owning_policy) = self.detector_plans.entropy(owning_detector_index) else {
                    tracing::error!(
                    detector_id = metadata.0.as_ref(),
                    "generic assignment owner has no compiled entropy policy; dropping candidate"
                );
                    continue;
                };
                let transport_decoded =
                    preprocessed.transport_decoded_for_offset(preprocessed_offset);
                if crate::adjudicate::generic_bridge_bare_auth_rejected(
                    keyword,
                    value,
                    owning_policy,
                ) {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::BareAuthUnstructured,
                    );
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        &generic_ctx,
                    );
                    continue;
                }
                // Entropy gate: reject low-entropy values (variable names, prose).
                // Routed through the SINGLE threshold-aware
                // `crate::adjudicate::generic_entropy_floor` owner (via
                // `generic_entropy_below_floor`), the same source of truth
                // the named-detector generic path uses, so the per-family,
                // length-bucketed base floor (Tier-B `entropy_floor` data in each
                // generic detector's TOML) is identical AND the operator's Tier-A
                // `--entropy-threshold` tightens this gate too. The shared owner
                // compares the raw scan setting with the selected detector's
                // `entropy_high`, then lifts the floor when the setting is
                // stricter. This bridge must not pre-resolve against a global
                // threshold because detector-local calibration can differ.
                let entropy = crate::pipeline::match_entropy(value.as_bytes());
                let canonical_key_material_policy =
                    self.detector_plans.get(owner_resolution.canonical_index);
                // A complete pure-hex value admitted by the detector that
                // declares its canonical policy is key material rather than a
                // digest. Missing detector policy fails closed. Ordinary
                // keyword policy ownership remains separate for entropy/BPE.
                let allow_canonical_hex_key = {
                    if transport_decoded {
                        canonical_key_material_policy
                            .key_material
                            .allows_decoded_hex(value)
                    } else {
                        canonical_key_material_policy
                            .key_material
                            .allows_canonical_hex(keyword_match.as_str(), value)
                    }
                };
                let allow_encoded_text_secret =
                    is_strong_keyword_anchored_encoded_text_secret(keyword_match.as_str(), value)
                        || crate::decode_structure::decodes_to_printable_text(value);
                let allow_decoded_hex_key_material = self
                    .detector_plans
                    .get(owning_detector_index)
                    .key_material
                    .allows_decoded_hex_len(
                        crate::decode_structure::evidence(value).decoded_hex_text_len(),
                    );

                let exact_structural_slot = |pattern: &crate::types::CompiledPattern| {
                    pattern.captures_exact_slot(line, whole_value.start, whole_value.end)
                };
                let structural_password_slot = execution_policy.structural_password_slot
                    || self.structural_confirmed_patterns[owning_detector_index]
                        .iter()
                        .any(|&index| exact_structural_slot(&self.ac_map[index as usize]))
                    || self.structural_phase2_patterns[owning_detector_index]
                        .iter()
                        .any(|&index| {
                            exact_structural_slot(&self.phase2_patterns[index as usize].0)
                        });

                // Surface every generic shape rejection through dogfood accounting.
                let shape_rejected = if self
                    .detector_plans
                    .assignment_has_public_identifier(line.as_bytes(), whole_value.start)
                {
                    Some(crate::adjudicate::GenericValueShapeStage::PublicIdentifierAssignment)
                } else {
                    self.generic_value_shape_rejected(
                        value,
                        entropy,
                        chunk,
                        owning_detector_index,
                        structural_password_slot,
                        owning_policy,
                        allow_canonical_hex_key,
                        allow_encoded_text_secret,
                        allow_decoded_hex_key_material,
                    )
                };

                // Apply the costlier BPE language-likeness gate last. Structural,
                // encoded-text, and canonical-hex evidence bypasses this heuristic.
                #[cfg(feature = "entropy")]
                let shape_rejected = shape_rejected.or_else(|| {
                    if structural_password_slot
                        || allow_canonical_hex_key
                        || allow_encoded_text_secret
                    {
                        return None;
                    }
                    owning_policy
                        .bpe_bound(self.config.entropy_bpe_max_bytes_per_token_override)
                        .filter(|bound| crate::entropy::bpe::is_word_like_low_bpe(value, *bound))
                        .map(|_| crate::adjudicate::GenericValueShapeStage::WordLikeLowBpe)
                });

                if let Some(reason) = shape_rejected {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::ValueShape(reason),
                    );
                    // A VALUE-SHAPE rejection is about the captured value's shape,
                    // so the suppression telemetry must be keyed on `value`: NOT
                    // the anchoring `keyword` (matching the `BareAuthUnstructured`
                    // value-based drop above). Keying it on the keyword hid the
                    // gate name (`base64_blob`, …) behind the keyword token, so the
                    // dropped value was untraceable through `--dogfood` (KH-L-0412).
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        &generic_ctx,
                    );
                    continue;
                }

                if let Some(stage_id) = self
                    .detector_plans
                    .suppression(owning_detector_index)
                    .and_then(|policy| {
                        policy.full_stage(
                            chunk.metadata.path.as_deref(),
                            Some(
                                self.detector_plans
                                    .decoded_source_family(&chunk.metadata.source_type),
                            ),
                            value,
                        )
                    })
                {
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        &crate::adjudicate::MatchCtx::for_stage(stage_id),
                    );
                    continue;
                }

                let checksum_decision = self.detector_plans.validate_any(value);
                if checksum_decision.is_invalid() {
                    crate::adjudicate::record_checksum_invalid_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                    );
                    continue;
                }

                let context = crate::context::infer_context_with_index(
                    scan_text,
                    line_index,
                    line_idx,
                    chunk.metadata.path.as_deref(),
                );
                let policy_conf = crate::confidence::policy::generic_assignment_confidence(
                    context,
                    self.config.scan_comments,
                    self.config.penalize_test_paths,
                    entropy,
                    value.len(),
                    owning_policy.generic_assignment_confidence,
                );

                // Route through the SAME report-confidence finalizer the ML and
                // named-detector emit paths use. `is_named=false` keeps the
                // generic fallback's shape penalties active; the encoded-text
                // lift is the one extra raw signal this path contributes.
                let min_confidence_floor = crate::adjudicate::detector_min_confidence_floor(
                    execution_policy.min_confidence,
                    self.config.min_confidence,
                );
                // Defect #80: this branch hard-coded `offset: 0` for every
                // generic-secret finding, so a `KEY = <secret>` on line 845
                // of a 137 KiB file reported offset 0 - the start of the
                // file - making the JSON impossible to navigate or grep.
                // The real offset is the start of the value within the
                // line, plus the line's start in the chunk, plus the
                // chunk's base offset in the original file (non-zero on
                // windowed >64 MiB scans).
                let mapped_line = preprocessed
                    .line_for_offset(preprocessed_offset)
                    // LAW10: missing transformed-line mapping uses the exact original line index.
                    .unwrap_or_else(|| line_index.line_number_for_offset(preprocessed_offset));
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, preprocessed_offset, value);
                let Some(absolute_offset) =
                    absolute_offset(chunk.metadata.base_offset, source_offset)
                else {
                    continue;
                };
                let line_number = absolute_line(chunk.metadata.base_line, mapped_line);
                let provenance =
                    crate::candidate_provenance::CandidateProvenance::generic_assignment();
                let build_raw = |scan_state: &mut ScanState, confidence| {
                    crate::pipeline::build_synthetic_raw_match(
                        (
                            Arc::clone(&metadata.0),
                            Arc::clone(&metadata.1),
                            Arc::clone(&metadata.2),
                        ),
                        execution_policy.severity,
                        chunk,
                        value,
                        absolute_offset,
                        Some(line_number),
                        Some(entropy),
                        confidence,
                        scan_state,
                    )
                };

                #[cfg(feature = "ml")]
                let ml_policy = detector_plan.ml;
                #[cfg(feature = "ml")]
                if let Some(ml_mode) = self
                    .config
                    .ml_enabled
                    .then_some(ml_policy.match_mode)
                    .flatten()
                {
                    let ml_features = crate::types::ml_features_for_candidate(
                        scan_text,
                        line_index,
                        line_idx,
                        chunk.metadata.path.as_deref(),
                        value,
                        ml_policy.context_radius_lines,
                        &self.config,
                        metadata.2.as_ref(),
                        ml_policy.features,
                        crate::ml_scorer::MlCandidateChannel::Pattern,
                    );
                    let pending_raw_match = crate::pipeline::build_pending_synthetic_raw_match(
                        (
                            Arc::clone(&metadata.0),
                            Arc::clone(&metadata.1),
                            Arc::clone(&metadata.2),
                        ),
                        execution_policy.severity,
                        chunk,
                        value,
                        absolute_offset,
                        Some(line_number),
                        Some(entropy),
                        scan_state,
                        provenance,
                    );
                    let inserted = scan_state.push_detector_ml_pending(
                        pending_raw_match,
                        policy_conf,
                        context,
                        match_confidence.context_multiplier(context),
                        match_confidence.context_suppression_threshold(context),
                        match_confidence.post_match(),
                        ml_features,
                        ml_policy.effective_weight(&self.config),
                        min_confidence_floor,
                        false,
                        true,
                        allow_canonical_hex_key,
                        allow_encoded_text_secret,
                        checksum_decision,
                        ml_mode,
                    );
                    if inserted {
                        metrics::record_emit();
                    }
                    continue;
                }

                let Some(report_conf) = crate::adjudicate::finalize_report_candidate(
                    chunk.metadata.path.as_deref(),
                    value,
                    crate::adjudicate::ReportAdjudicationPolicy {
                        detector_id: metadata.0.as_ref(),
                        code_context: context,
                        confidence: policy_conf,
                        min_confidence_floor,
                        penalize_test_paths: self.config.penalize_test_paths,
                        context_suppression_threshold: match_confidence
                            .context_suppression_threshold(context),
                        post_match: match_confidence.post_match(),
                        file_path: chunk.metadata.path.as_deref(),
                        is_named_detector: false,
                        is_generic_detector: true,
                        allow_encoded_text_lift: allow_encoded_text_secret,
                        allow_canonical_hex_key,
                        checksum: checksum_decision,
                        calibration: self.config.calibration.as_deref(),
                    },
                ) else {
                    continue;
                };
                let raw = build_raw(scan_state, report_conf);
                scan_state.push_match_with_provenance(
                    raw,
                    provenance,
                    self.config.max_matches_per_chunk,
                );
                metrics::record_emit();
            }
        }
        drop(extract);
        release_keyword_lines_scratch(lines_with_keyword);
    }
}
