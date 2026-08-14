//! `process_match`: the per-match post-processing chain.
//!
//! Runs the suppression chain, companion-required gate, entropy + camel-shape
//! filters for generic detectors, checksum validation, and finally ML /
//! heuristic scoring. Outputs either a `Final` finding into `scan_state.matches`
//! or queues an `MlPendingMatch` for the post-scan ML batch.

use super::scan_filters::*;
use super::CompiledScanner;
use crate::confidence::policy::MlScoreResult;
use crate::context;
use crate::pipeline::*;
use crate::types::*;
use keyhog_core::{Chunk, CompanionMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompanionRejection {
    MissingRequired,
    ForbiddenPresent,
}

impl CompiledScanner {
    pub(crate) fn match_companions(
        detector_companions: &[CompiledCompanion],
        preprocessed: &ScannerPreprocessedText<'_>,
        line: usize,
        primary_start: usize,
        primary_end: usize,
        primary_value: &str,
    ) -> Result<CompanionMap, CompanionRejection> {
        if detector_companions.is_empty() {
            return Ok(CompanionMap::new());
        }
        let mut results = CompanionMap::with_capacity(detector_companions.len());
        for companion in detector_companions {
            let found = find_companion(
                preprocessed,
                line,
                primary_start,
                primary_end,
                primary_value,
                companion,
            );
            match (companion.requirement, found) {
                (keyhog_core::EvidenceRequirement::Required, None) => {
                    return Err(CompanionRejection::MissingRequired);
                }
                (keyhog_core::EvidenceRequirement::Forbidden, Some(_)) => {
                    return Err(CompanionRejection::ForbiddenPresent);
                }
                (_, Some(value)) => {
                    results.insert(companion.name.clone(), value);
                }
                (_, None) => {}
            }
        }
        Ok(results)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_match(
        &self,
        entry: &CompiledPattern,
        detector_plan: &crate::detector_plan::CompiledDetectorPlan,
        data: &str,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
        credential: &str,
        credential_start: usize,
        credential_end: usize,
        keyword_nearby: bool,
        sensitive_file: bool,
    ) {
        let (credential, match_end, checksum_decision) = extend_known_prefix_credential(
            data,
            credential,
            credential_end,
            |candidate, pattern_proven| {
                detector_plan.validators.validate(candidate, pattern_proven)
            },
        );
        let line = preprocessed
            .line_for_offset(credential_start)
            // LAW10: missing transformed-line mapping uses the exact original line index.
            .unwrap_or_else(|| line_index.line_number_for_offset(credential_start));
        let execution_policy = &detector_plan.execution;
        let match_confidence = self.detector_plans.match_confidence(entry.detector_index);
        let credential_shape = self.detector_plans.credential_shape(entry.detector_index);
        let suppression = self.detector_plans.suppression(entry.detector_index);
        let entropy_floor = self.detector_plans.entropy_floor(entry.detector_index);
        let entropy_policy = self.detector_plans.entropy(entry.detector_index);
        let is_generic = execution_policy.is_generic;
        let whole_value = is_generic.then(|| {
            let source_start =
                preprocessed.source_offset_for_match(&chunk.data, credential_start, credential);
            let source_end = source_start.saturating_add(credential.len());
            let (span_data, span_start, span_end) = if chunk
                .data
                .get(source_start..source_end)
                .is_some_and(|source_value| source_value == credential)
            {
                (chunk.data.as_ref(), source_start, source_end)
            } else {
                // A synthesized match without an exact source mapping still
                // receives detector policy against its exact preprocessed span.
                (
                    data,
                    credential_start,
                    credential_start.saturating_add(credential.len()),
                )
            };
            (
                crate::detector_execution_policy::whole_assignment_value(
                    span_data, span_start, span_end,
                ),
                span_data,
                span_start,
                span_end,
            )
        });
        let whole_value_len =
            whole_value.map_or(credential.len(), |(span, _, _, _)| span.end - span.start);
        let partial_assignment_value =
            whole_value.is_some_and(|(span, _, start, end)| !span.is_exact(start, end));
        let suppression_value =
            whole_value.map_or(credential, |(span, span_data, _, _)| span.as_str(span_data));
        let structural_password_slot =
            execution_policy.structural_password_slot || entry.structural_password_slot;
        // A declared structural slot is exact syntactic evidence even when the
        // owning detector is generic, so generic probabilistic admission must
        // not veto it before the slot-specific placeholder policy runs.
        let apply_generic_candidate_gates = is_generic && !structural_password_slot;

        let process_signals = crate::adjudicate::ProcessCandidateSignals::from_match(
            apply_generic_candidate_gates,
            execution_policy.length,
            credential_shape,
            match_confidence.post_match().degenerate_run_min_length,
            credential,
            whole_value_len,
            partial_assignment_value,
            data,
            credential_start,
            match_end,
        );
        let process_ctx = crate::adjudicate::MatchCtx::for_process_signals(process_signals);
        if crate::adjudicate::record_suppression(
            chunk.metadata.path.as_deref(),
            suppression_value,
            &process_ctx,
        )
        .is_some()
        {
            return;
        }
        let false_positive_context = context::is_false_positive_context_indexed(
            &preprocessed.text,
            line_index,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
        ) || context::is_false_positive_match_context(
            data,
            credential_start,
            chunk.metadata.path.as_deref(),
        );
        let false_positive_ctx = crate::adjudicate::MatchCtx::for_process_signals(
            crate::adjudicate::ProcessCandidateSignals::from_false_positive_context(
                false_positive_context,
            ),
        );
        if crate::adjudicate::record_suppression(
            chunk.metadata.path.as_deref(),
            credential,
            &false_positive_ctx,
        )
        .is_some()
        {
            return;
        }

        let inferred_context = context::infer_context_with_index(
            &preprocessed.text,
            line_index,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
        );
        // Combine the construction-time detector base with the explicit policy
        // bit compiled beside this exact regex. Index mismatch is an internal
        // construction bug and remains loud.
        let weak_anchor = detector_plan.pattern_weak_anchor(entry.weak_anchor);
        let key_material_policy = &detector_plan.key_material;
        let allow_decoded_hex_key_material = key_material_policy.allows_decoded_hex_len(
            crate::decode_structure::evidence(credential).decoded_hex_text_len(),
        );
        let allow_canonical_hex_key_material = allow_decoded_hex_key_material
            || (credential.bytes().all(|byte| byte.is_ascii_hexdigit())
                && key_material_policy.allows_canonical_hex_len(credential.len()));
        // Raw binary sections lack source context, so the binary-strings noise
        // gate (`suppression::api`, `native_binary_strings`) drops a named
        // detector unless the match carries its own structural proof.
        //
        // That proof used to be `[detector.credential_shape]` alone. Exactly 4
        // of 924 detector TOMLs declare one, so 920 named detectors could never
        // fire on ANY binary-derived chunk: not an ELF on disk, not a `.so`
        // inside a `.tar.gz`, not an executable in a container layer. Same
        // bytes, `aws-access-key` reported and `slack-bot-token` silently
        // suppressed, purely because one TOML has the block (KH-1064). A
        // 4-of-924 allowlist nobody maintained is not a precision policy.
        //
        // A declared shape is still the strongest proof and still admits. The
        // general proof is lexical: the match occupies a whole token of the
        // extracted text rather than a substring of surrounding identifier
        // soup. Both are per-match evidence, neither is an id list.
        //
        // A structural password slot is excluded from both. Its captured value
        // is by definition "whatever token followed the keyword", so it has no
        // shape to satisfy and being a whole token proves nothing about it.
        // Measured over 249 MiB of system ELF binaries, dropping the slot
        // family removes 12 of the 15 residual false positives and costs
        // nothing a shaped detector would have caught.
        let allow_validated_binary_credential = !is_generic
            && !weak_anchor
            && !structural_password_slot
            && (credential_shape.is_some()
                || crate::suppression::binary_match_is_lexically_isolated(
                    data,
                    credential_start,
                    match_end,
                ));
        let named_suppression_ctx =
        crate::suppression::NamedDetectorSuppressionCtx::with_weak_anchor_and_key_material_policy(
            chunk.metadata.path.as_deref(),
            inferred_context,
            Some(chunk.metadata.source_type.as_ref()),
            Some(
                self.detector_plans
                    .decoded_source_family(chunk.metadata.source_type.as_ref()),
            ),
            suppression,
            !is_generic,
            weak_anchor,
            structural_password_slot,
            allow_canonical_hex_key_material,
            allow_validated_binary_credential,
        );
        let match_ctx = crate::adjudicate::MatchCtx::for_named_detector(named_suppression_ctx);
        if crate::adjudicate::record_suppression(
            chunk.metadata.path.as_deref(),
            credential,
            &match_ctx,
        )
        .is_some()
        {
            // KH-L-0412 (Law-10): named-detector context/example suppression
            // was the last silent `return` on this path. Trace it through the
            // adjudicator so a dropped match is visible to `--dogfood` with
            // the deciding stage name.
            return;
        }

        let companions = match Self::match_companions(
            &detector_plan.companions,
            preprocessed,
            line,
            credential_start,
            match_end,
            credential,
        ) {
            Ok(companions) => companions,
            Err(CompanionRejection::MissingRequired) => {
                crate::adjudicate::record_missing_required_companion_suppression(
                    chunk.metadata.path.as_deref(),
                    credential,
                );
                return;
            }
            Err(CompanionRejection::ForbiddenPresent) => {
                crate::adjudicate::record_forbidden_companion_suppression(
                    chunk.metadata.path.as_deref(),
                    credential,
                );
                return;
            }
        };
        let entropy = match_entropy(credential.as_bytes());

        let is_weakly_anchored = weak_anchor;
        let effective_entropy_floor = (is_generic || is_weakly_anchored)
            .then(|| {
                entropy_floor.map(|policy| {
                    policy.effective_floor(credential.len(), self.config.entropy_threshold)
                })
            })
            .flatten();
        let entropy_shape_ctx = crate::adjudicate::MatchCtx::for_process_signals(
            crate::adjudicate::ProcessCandidateSignals::from_process_entropy_shape(
                is_generic,
                is_weakly_anchored,
                entropy,
                effective_entropy_floor,
                credential,
            ),
        );
        if crate::adjudicate::record_suppression(
            chunk.metadata.path.as_deref(),
            credential,
            &entropy_shape_ctx,
        )
        .is_some()
        {
            return;
        }

        // Detector policy follows the candidate across producers. Generic
        // regex envelopes must not bypass the BPE gate that the same detector
        // applies to assignment and entropy candidates. Keep tokenization
        // after the cheaper shape and entropy checks.
        #[cfg(feature = "entropy")]
        let bpe_bound = if is_generic {
            entropy_policy.and_then(|policy| {
                policy.bpe_bound(self.config.entropy_bpe_max_bytes_per_token_override)
            })
        } else {
            None
        };
        #[cfg(feature = "entropy")]
        if let Some(bpe_bound) = bpe_bound {
            // The explicit generic regex proves an owning detector field, but
            // this stage no longer retains the textual assignment key.
            // Preserve the detector's exact canonical length evidence instead
            // of letting BPE reinterpret declared hex key material as text.
            let allow_canonical_hex_key = credential.bytes().all(|byte| byte.is_ascii_hexdigit())
                && key_material_policy.allows_canonical_hex_len(credential.len());
            let allow_encoded_text_secret = !allow_canonical_hex_key
                && crate::decode_structure::decodes_to_printable_text(credential);
            if !allow_canonical_hex_key
                && !allow_encoded_text_secret
                && !allow_decoded_hex_key_material
            {
                if crate::entropy::bpe::is_word_like_low_bpe(credential, bpe_bound) {
                    let bpe_ctx = crate::adjudicate::MatchCtx::for_stage(
                        crate::adjudicate::StageId::GenericValueShape(
                            crate::adjudicate::GenericValueShapeStage::WordLikeLowBpe,
                        ),
                    );
                    crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        credential,
                        &bpe_ctx,
                    );
                    return;
                }
            }
        }

        // Checksum validation: tokens with embedded checksums (GitHub, npm, Slack,
        // Stripe, GitLab, PyPI) can be verified without network requests. The
        // confidence policy owner makes the drop/floor rule shared with hot,
        // generic, entropy, and ML emitters.
        let checksum_ctx = crate::adjudicate::MatchCtx::for_process_signals(
            crate::adjudicate::ProcessCandidateSignals::from_checksum_invalid(
                checksum_decision.is_invalid(),
            ),
        );
        if crate::adjudicate::record_suppression(
            chunk.metadata.path.as_deref(),
            credential,
            &checksum_ctx,
        )
        .is_some()
        {
            // Checksum failed: NOT a real token. Skip expensive ML scoring.
            return;
        }

        // Service-anchored detector regexes are positive evidence; generic
        // shape gates stay load-bearing only for generic/entropy/private-key
        // fallbacks and weak anchors.
        let is_named_detector = !is_generic && !weak_anchor;
        #[cfg(feature = "ml")]
        let detector_ml_policy = detector_plan.ml;
        #[cfg(feature = "ml")]
        let detector_ml_mode = self
            .config
            .ml_enabled
            .then_some(detector_ml_policy.match_mode)
            .flatten();
        let policy_result = crate::confidence::policy::candidate_match_score(
            crate::confidence::policy::CandidateMatchScorePolicy {
                // Per-PATTERN constant, memoized on the `LazyRegex` (see
                // `LazyRegex::has_literal_prefix`): the prior inline
                // `extract_literal_prefix(entry.regex.as_str()).is_some()`
                // re-ran the allocating prefix parser on every surviving
                // candidate. Identical value, computed at most once.
                has_literal_prefix: entry.regex.has_literal_prefix(),
                has_context_anchor: entry.group.is_some(),
                entropy,
                entropy_threshold: self.config.entropy_threshold,
                keyword_nearby,
                sensitive_file,
                match_length: credential.len(),
                has_companion: !companions.is_empty(),
                code_context: inferred_context,
                penalize_test_paths: self.config.penalize_test_paths,
                confidence: &match_confidence,
                named_anchor_floor_eligible: !weak_anchor,
                #[cfg(feature = "ml")]
                ml_mode: detector_ml_mode,
                #[cfg(not(feature = "ml"))]
                ml_enabled: false,
                credential,
                // Per-PATTERN constant, memoized on the `LazyRegex`: the matched
                // regex requires a distinctive literal infix (terraform
                // `\.atlasv1\.`) that no prefix/keyword-group anchor captures.
                has_distinctive_inner_literal: entry.regex.has_distinctive_inner_literal(),
            },
        );

        let min_confidence_floor = crate::adjudicate::detector_min_confidence_floor(
            execution_policy.min_confidence,
            self.config.min_confidence,
        );

        let source_offset =
            preprocessed.source_offset_for_match(&chunk.data, credential_start, credential);
        let provenance = crate::candidate_provenance::CandidateProvenance::named(
            entry.detector_index,
            entry.pattern_index,
        );
        let provenance = crate::source_semantics::classify_exact_structured_candidate(
            &chunk.data,
            chunk.metadata.path.as_deref(),
            source_offset,
            credential,
        )
        .map_or(provenance, |evidence| {
            provenance.with_source_semantics(evidence)
        });
        match policy_result {
            MlScoreResult::Final(policy_conf) => {
                let Some(report_conf) = crate::adjudicate::finalize_report_candidate(
                    chunk.metadata.path.as_deref(),
                    credential,
                    crate::adjudicate::ReportAdjudicationPolicy {
                        detector_id: detector_plan.metadata.0.as_ref(),
                        code_context: inferred_context,
                        confidence: policy_conf,
                        min_confidence_floor,
                        penalize_test_paths: self.config.penalize_test_paths,
                        context_suppression_threshold: match_confidence
                            .context_suppression_threshold(inferred_context),
                        post_match: match_confidence.post_match(),
                        file_path: chunk.metadata.path.as_deref(),
                        is_named_detector,
                        is_generic_detector: is_generic,
                        allow_encoded_text_lift: false,
                        allow_canonical_hex_key: allow_canonical_hex_key_material,
                        checksum: checksum_decision,
                        calibration: self.config.calibration.as_deref(),
                    },
                ) else {
                    return;
                };
                let raw_match = build_raw_match(
                    execution_policy.severity,
                    detector_plan.cloned_metadata(),
                    chunk,
                    credential,
                    companions,
                    source_offset,
                    line,
                    entropy,
                    report_conf,
                    scan_state,
                    entry.client_safe,
                );
                if scan_state.push_match_with_provenance(
                    raw_match,
                    provenance,
                    self.config.max_matches_per_chunk,
                ) {
                    crate::telemetry::record_match_found();
                }
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending {
                heuristic_conf,
                code_context,
                context_multiplier,
                mode,
            } => {
                let ml_features = crate::types::ml_features_for_candidate(
                    data,
                    line_index,
                    line,
                    chunk.metadata.path.as_deref(),
                    credential,
                    detector_ml_policy.context_radius_lines,
                    &self.config,
                    detector_plan.metadata.2.as_ref(),
                    detector_ml_policy.features,
                    crate::ml_scorer::MlCandidateChannel::Pattern,
                );
                let pending_raw_match = crate::pipeline::build_pending_raw_match(
                    execution_policy.severity,
                    detector_plan.cloned_metadata(),
                    chunk,
                    credential,
                    companions,
                    source_offset,
                    line,
                    entropy,
                    scan_state,
                    provenance,
                    entry.client_safe,
                );
                if scan_state.push_detector_ml_pending(
                    pending_raw_match,
                    heuristic_conf,
                    code_context,
                    context_multiplier,
                    match_confidence.context_suppression_threshold(code_context),
                    match_confidence.post_match(),
                    ml_features,
                    detector_ml_policy.effective_weight(&self.config),
                    min_confidence_floor,
                    is_named_detector,
                    is_generic,
                    allow_canonical_hex_key_material,
                    false,
                    checksum_decision,
                    mode,
                ) {
                    crate::telemetry::record_match_found();
                }
            }
        }
    }
}
