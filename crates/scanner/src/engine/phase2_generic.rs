use super::*;
use std::cell::RefCell;

pub(crate) mod keywords;
mod line_mapping;
mod metrics;
mod pattern;

use self::keywords::{
    collect_generic_keyword_lines_from_positions, collect_generic_keyword_lines_with,
    is_strong_keyword_anchored_encoded_text_secret,
};
use self::line_mapping::line_at_index;
pub(crate) use self::metrics::{generic_profile_dump, generic_profile_reset};
pub(crate) use self::pattern::{
    build_generic_re, compile_generic_re_with_max, compile_generic_re_with_policy,
    generic_keyword_alternation, generic_keyword_alternation_from, generic_vendor_suffix_arm,
};

thread_local! {
    /// Reuses one keyword-line buffer per worker to avoid an allocation per chunk.
    static KEYWORD_LINES_POOL: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
}

impl CompiledScanner {
    /// Scans generic assignments after keyword, entropy, and placeholder admission.
    /// Named and generic evidence is reconciled by the shared resolution pass.
    pub(crate) fn scan_generic_assignments(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
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
        // Take ownership so the RefCell is not borrowed during the consume loop.
        let mut lines_with_keyword = KEYWORD_LINES_POOL.with(|cell| cell.take());
        lines_with_keyword.clear();
        let profile_enabled = super::profile::enabled();
        let prefilter_start = profile_enabled.then(std::time::Instant::now);
        if let Some(positions) = generic_keyword_positions {
            collect_generic_keyword_lines_from_positions(
                line_offsets,
                positions,
                &mut lines_with_keyword,
            );
        } else {
            collect_generic_keyword_lines_with(
                generic_keyword_stems,
                scan_text,
                &mut lines_with_keyword,
            );
        }
        metrics::record_prefilter_ns(prefilter_start);
        if profile_enabled {
            metrics::record_prefilter_call(lines_with_keyword.len());
        }
        if lines_with_keyword.is_empty() {
            // Preserve buffer capacity across chunks.
            KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
            return;
        }
        if crate::deadline::expired(deadline) {
            KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
            return;
        }

        let extract_start = profile_enabled.then(std::time::Instant::now);
        let mut preprocessed_code_lines_cache: Option<Vec<&str>> = None;
        let mut preprocessed_documentation_lines_cache: Option<Vec<bool>> = None;
        for line_iter in 0..lines_with_keyword.len() {
            if crate::deadline::expired_on_cadence(
                deadline,
                line_iter,
                crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
            ) {
                metrics::record_extract_ns(extract_start);
                KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
                return;
            }
            let line_idx = lines_with_keyword[line_iter];
            let Some(&line_offset) = line_offsets.get(line_idx) else {
                continue;
            };
            let Some(raw_line) = line_at_index(scan_text, line_offsets, line_idx) else {
                continue;
            };
            // Extract from normalized text so in-value zero-width characters cannot
            // truncate the candidate. Pure ASCII remains borrowed and offsets stay raw.
            let normalized_line = crate::unicode_hardening::normalize_homoglyphs(raw_line);
            let line: &str = &normalized_line;

            for (capture_iter, caps) in generic_re.captures_iter(line).enumerate() {
                if crate::deadline::expired_on_cadence(
                    deadline,
                    capture_iter,
                    crate::deadline::HOT_LOOP_DEADLINE_CADENCE,
                ) {
                    metrics::record_extract_ns(extract_start);
                    KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
                    return;
                }
                if profile_enabled {
                    metrics::record_regex_capture();
                }
                let Some(keyword_match) = caps.get(1) else {
                    continue;
                };
                let Some(value_match) = caps.get(2) else {
                    continue;
                };
                // Whole-word left boundary, enforced ONLY for the short,
                // substring-ambiguous abbreviation `pass` (the tail of
                // `bypass`/`compass`/`surpass`/...). The longer keywords
                // (`password`, `token`, `secret`, `api_key`, ...) deliberately
                // keep substring matching so concatenated no-separator keys like
                // `DBPASSWORD=` / `apitoken=` still bridge, measured on CredData,
                // enforcing the boundary on every keyword cost ~36 real positives
                // for no precision gain. `pass` alone needs the guard because its
                // false-substring family (`bypass=`/`compass=`) is common.
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
                let value = value_match.as_str();
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
                let execution_policy = &detector_plan.execution;
                let metadata = &detector_plan.metadata;
                let length_stage = match execution_policy.length.rejection(value.len()) {
                    Some(crate::detector_execution_policy::CandidateLengthRejection::TooShort) => {
                        Some(crate::adjudicate::GenericValueShapeStage::ValueTooShort)
                    }
                    Some(crate::detector_execution_policy::CandidateLengthRejection::TooLong) => {
                        Some(crate::adjudicate::GenericValueShapeStage::ValueTooLong)
                    }
                    None => None,
                };
                if let Some(stage) = length_stage {
                    let generic_ctx = crate::adjudicate::MatchCtx::for_generic_bridge(
                        crate::adjudicate::GenericBridgeSignal::ValueShape(stage),
                    );
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        value,
                        &generic_ctx,
                    );
                    continue;
                }
                let Some(owning_policy) = detector_plan.entropy.as_ref() else {
                    tracing::error!(
                        detector_id = metadata.0.as_ref(),
                        "generic assignment owner has no compiled entropy policy; dropping candidate"
                    );
                    continue;
                };
                let preprocessed_offset = line_offset + value_match.start();
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
                    pattern.captures_exact_slot(line, value_match.start(), value_match.end())
                };
                let structural_password_slot = execution_policy.structural_password_slot
                    || self.structural_confirmed_patterns[owning_detector_index]
                        .iter()
                        .any(|&index| exact_structural_slot(&self.ac_map[index]))
                    || self.structural_phase2_patterns[owning_detector_index]
                        .iter()
                        .any(|&index| exact_structural_slot(&self.phase2_patterns[index].0));

                // Surface every generic shape rejection through dogfood accounting.
                let shape_rejected = if self
                    .detector_plans
                    .assignment_has_public_identifier(line.as_bytes(), value_match.start())
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

                if let Some(stage_id) = detector_plan
                    .suppression
                    .as_ref()
                    .and_then(|policy| policy.full_stage(chunk.metadata.path.as_deref(), value))
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

                // Context suppression: test files get lower confidence. On the
                // byte-identical common path, reuse the lines and documentation
                // flags already computed by the phase-2 caller; recomputing
                // documentation flags for every generic candidate was
                // O(candidates * lines). Synthesized structured/multiline text
                // still builds its own cached context view so appended lines
                // keep correct line indices.
                let context = if identity_offsets {
                    crate::context::infer_context_with_documentation(
                        code_lines,
                        line_idx,
                        chunk.metadata.path.as_deref(),
                        documentation_lines,
                    )
                } else {
                    let preprocessed_code_lines = preprocessed_code_lines_cache
                        .get_or_insert_with(|| scan_text.lines().collect());
                    let preprocessed_documentation_lines = preprocessed_documentation_lines_cache
                        .get_or_insert_with(|| {
                            crate::context::documentation_line_flags(
                                preprocessed_code_lines.as_slice(),
                            )
                        });
                    crate::context::infer_context_with_documentation(
                        preprocessed_code_lines.as_slice(),
                        line_idx,
                        chunk.metadata.path.as_deref(),
                        preprocessed_documentation_lines.as_slice(),
                    )
                };
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
                let mapped_line = crate::pipeline::match_line_number(
                    preprocessed,
                    line_offsets,
                    preprocessed_offset,
                );
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, preprocessed_offset, value);
                let Some(absolute_offset) =
                    absolute_offset(chunk.metadata.base_offset, source_offset)
                else {
                    continue;
                };
                let line_number = absolute_line(chunk.metadata.base_line, mapped_line);
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
                        line_idx,
                        chunk.metadata.path.as_deref(),
                        value,
                        ml_policy.context_radius_lines,
                        &self.config,
                        metadata.2.as_ref(),
                        ml_policy.features,
                        crate::ml_scorer::MlCandidateChannel::Pattern,
                    );
                    let raw = build_raw(scan_state, policy_conf);
                    let inserted = scan_state.push_detector_ml_pending(
                        raw,
                        policy_conf,
                        context,
                        detector_plan.match_confidence.context_multiplier(context),
                        detector_plan
                            .match_confidence
                            .context_suppression_threshold(context),
                        detector_plan.match_confidence.post_match(),
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
                    if profile_enabled && inserted {
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
                        context_suppression_threshold: detector_plan
                            .match_confidence
                            .context_suppression_threshold(context),
                        post_match: detector_plan.match_confidence.post_match(),
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
                scan_state.push_match(raw, self.config.max_matches_per_chunk);
                if profile_enabled {
                    metrics::record_emit();
                }
            }
        }
        metrics::record_extract_ns(extract_start);
        // Return the scratch buffer to the pool, preserving its capacity for
        // the next chunk this worker handles.
        KEYWORD_LINES_POOL.with(|cell| cell.replace(lines_with_keyword));
    }
}
