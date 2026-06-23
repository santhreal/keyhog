#[cfg(feature = "entropy")]
mod gates;
#[cfg(feature = "entropy")]
pub(crate) mod helpers;
#[cfg(feature = "entropy")]
use super::*;
#[cfg(feature = "entropy")]
use gates::{entropy_match_suppression_stage, entropy_value_line};
#[cfg(feature = "entropy")]
use std::sync::Arc;

#[cfg(feature = "entropy")]
impl CompiledScanner {
    pub(crate) fn scan_entropy_fallback(
        &self,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        if !self.config.entropy_enabled {
            return;
        }
        if chunk.metadata.source_type.contains("/caesar") {
            return;
        }
        let entropy_lines: Vec<&str> = preprocessed.text.lines().collect();
        let path_entropy_appropriate = crate::entropy::is_entropy_appropriate_with_content_lines(
            chunk.metadata.path.as_deref(),
            self.config.entropy_in_source_files,
            &entropy_lines,
            &self.config.secret_keywords,
        );
        let source_entropy_requires_same_line_credential = !self.config.entropy_in_source_files
            && crate::decode::caesar::is_program_source_code_path(chunk.metadata.path.as_deref());
        let isolated_bare_candidate = !path_entropy_appropriate
            && crate::entropy::scanner::has_isolated_bare_secret_candidate_with_lines(
                &entropy_lines,
                self.config.entropy_threshold,
                &self.config.placeholder_keywords,
            );
        #[cfg(feature = "simd")]
        let lower_dash_app_password_candidate = path_entropy_appropriate
            && crate::entropy::scanner::has_lower_dash_app_password_candidate_with_lines(
                &entropy_lines,
                &self.config,
            );
        if !path_entropy_appropriate && !isolated_bare_candidate {
            return;
        }

        // Avoid the full Shannon sweep unless a run proof or isolated candidate
        // already exists.
        #[cfg(feature = "simd")]
        if !isolated_bare_candidate
            && !lower_dash_app_password_candidate
            && !super::scan_filters::has_high_entropy_run_at_least(
                preprocessed.text.as_bytes(),
                self.config.min_secret_len,
            )
        {
            return;
        }

        // Avoid entropy duplicates on lines already claimed by named detectors.
        let mut skip_lines = std::collections::HashSet::new();
        if !scan_state.matches.is_empty() {
            for m in &scan_state.matches {
                let id = &*m.detector_id;
                if !crate::detector_ids::is_generic_or_entropy_detector(id) {
                    if let Some(line_idx) =
                        entropy_skip_line_index(m.location.line, chunk.metadata.base_line)
                    {
                        skip_lines.insert(line_idx);
                    }
                }
            }
        }
        #[cfg(feature = "ml")]
        if !scan_state.ml_pending.is_empty() {
            for pending in &scan_state.ml_pending {
                let id = &*pending.raw_match.detector_id;
                if !crate::detector_ids::is_generic_or_entropy_detector(id) {
                    if let Some(line_idx) = entropy_skip_line_index(
                        pending.raw_match.location.line,
                        chunk.metadata.base_line,
                    ) {
                        skip_lines.insert(line_idx);
                    }
                }
            }
        }

        let keyword_free_threshold =
            if crate::entropy::is_sensitive_file(chunk.metadata.path.as_deref()) {
                crate::entropy::SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD
            } else {
                crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD
            };

        // With authoritative ML, credential-anchored canonical hash/UUID/serial
        // candidates may be generated for model arbitration.
        #[cfg(feature = "ml")]
        let allow_canonical_lift = self.config.ml_enabled && self.config.entropy_ml_authoritative;
        #[cfg(not(feature = "ml"))]
        let allow_canonical_lift = false;
        let entropy_matches =
            crate::entropy::scanner::find_entropy_secrets_with_canonical_lift_and_lines(
                &entropy_lines,
                line_offsets,
                self.config.min_secret_len,
                1,
                self.config.entropy_threshold,
                keyword_free_threshold,
                &self.config.secret_keywords,
                &self.config.test_keywords,
                &self.config.placeholder_keywords,
                Some(&skip_lines),
                allow_canonical_lift,
            );
        for entropy_match in entropy_matches {
            // Resolve metadata once; emit clones the pre-interned triple.
            let entropy_meta_idx = helpers::classify_entropy_detector_index(&entropy_match.keyword);
            let confidence = super::scoring::entropy_fallback_confidence(
                entropy_match.entropy,
                &entropy_match.keyword,
            );
            let mapped_line = crate::pipeline::match_line_number(
                preprocessed,
                line_offsets,
                entropy_match.offset,
            );
            let source_offset = preprocessed.source_offset_for_match(
                &chunk.data,
                entropy_match.offset,
                &entropy_match.value,
            );
            let offset = source_offset + chunk.metadata.base_offset;

            // Pass the lift switch only after generation; the gauntlet still
            // owns every non-canonical precision gate.
            if let Some(stage_id) = entropy_match_suppression_stage(
                &entropy_match,
                preprocessed,
                line_offsets,
                chunk,
                allow_canonical_lift,
                source_entropy_requires_same_line_credential,
            ) {
                crate::adjudicate::record_stage_suppression(
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    stage_id,
                );
                continue;
            }
            if self.entropy_match_owned_by_named_assignment(
                &entropy_match,
                preprocessed,
                line_offsets,
            ) {
                crate::adjudicate::record_stage_suppression(
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    crate::adjudicate::StageId::EntropyNamedDetectorOwnedAssignment,
                );
                continue;
            }

            let metadata = &self.entropy_metadata_by_index[entropy_meta_idx];
            let absolute_line = mapped_line + chunk.metadata.base_line;
            let build_raw_match = |scan_state: &mut ScanState, confidence| {
                // Clone metadata only for candidates that need an owned RawMatch.
                let detector_id = Arc::clone(&metadata.0);
                let detector_name = Arc::clone(&metadata.1);
                let service = Arc::clone(&metadata.2);
                crate::pipeline::build_synthetic_raw_match(
                    (detector_id, detector_name, service),
                    keyhog_core::Severity::High,
                    chunk,
                    &entropy_match.value,
                    offset,
                    Some(absolute_line),
                    Some(entropy_match.entropy),
                    confidence,
                    scan_state,
                )
            };

            // UNIFIED SCORING. When ML is live, route the entropy candidate
            // through the SAME MoE batch the detector/generic matches use, with
            // the model AUTHORITATIVE (no entropy-magnitude floor — see
            // `MlPendingMatch::model_authoritative`). The MoE separates real
            // high-entropy secrets (~0.98) from high-entropy NON-secrets (FQDNs,
            // git SHAs, base64 blobs ~0.01) that the shape gates above don't
            // catch, and `apply_ml_batch_scores` then runs the ONE canonical
            // penalty / path / calibration / checksum / floor pipeline — so this
            // path no longer needs a bespoke `apply_post_ml_penalties` +
            // `checksum_adjusted_confidence` tail (the batch path applies both,
            // identically). The shape gates above remain cheap, recall-safe
            // pre-filters.
            #[cfg(feature = "ml")]
            if self.config.ml_enabled && self.config.entropy_ml_authoritative {
                let raw_match = build_raw_match(scan_state, confidence);
                let text_context = crate::pipeline::local_context_window(
                    &preprocessed.text,
                    entropy_match.line,
                    crate::types::ML_CONTEXT_RADIUS_LINES,
                );
                let ml_context = match chunk.metadata.path.as_deref() {
                    Some(path) => format!("file:{path}\n{text_context}"),
                    None => text_context.to_string(),
                };
                scan_state.ml_pending.push(crate::types::MlPendingMatch {
                    raw_match,
                    heuristic_conf: confidence,
                    // The entropy fallback infers no rich code context (its anchor
                    // is keyword PROXIMITY, not an assignment parse) and the
                    // surrounding gates already handle test/docs shapes; Unknown
                    // applies no extra context multiplier, matching the
                    // pre-unification entropy emit.
                    code_context: crate::context::CodeContext::Unknown,
                    credential: entropy_match.value.to_string(),
                    ml_context,
                    min_confidence_floor: self.config.min_confidence,
                    model_authoritative: true,
                });
                continue;
            }

            // Non-ML path emits directly through the same report-confidence
            // finalizer used by ML and detector hits.
            let Some(confidence) = super::scoring::finalize_report_confidence(
                confidence,
                super::scoring::ReportConfidencePolicy {
                    credential: &entropy_match.value,
                    detector_id: metadata.0.as_ref(),
                    file_path: chunk.metadata.path.as_deref(),
                    is_named_detector: false,
                    penalize_test_paths: self.config.penalize_test_paths,
                    allow_encoded_text_lift: false,
                    calibration: self.config.calibration.as_deref(),
                },
            ) else {
                crate::adjudicate::record_stage_suppression(
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    crate::adjudicate::StageId::ChecksumInvalid,
                );
                continue;
            };
            let final_emit_ctx = crate::adjudicate::MatchCtx::for_final_emit(
                crate::adjudicate::FinalEmitSignals::new(
                    metadata.0.as_ref(),
                    crate::context::CodeContext::Unknown,
                    confidence,
                    self.config.min_confidence,
                    self.config.penalize_test_paths,
                ),
            );
            if crate::adjudicate::record_suppression(
                chunk.metadata.path.as_deref(),
                &entropy_match.value,
                &final_emit_ctx,
            )
            .is_some()
            {
                continue;
            }
            scan_state.push_match_lazy(
                crate::scanner_config::RawMatchPriority {
                    confidence: Some(confidence),
                    severity: keyhog_core::Severity::High,
                    detector_id: metadata.0.as_ref(),
                    credential: &entropy_match.value,
                    offset,
                    line: Some(absolute_line),
                },
                self.config.max_matches_per_chunk,
                |scan_state| build_raw_match(scan_state, confidence),
            );
        }
    }

    fn entropy_match_owned_by_named_assignment(
        &self,
        entropy_match: &crate::entropy::EntropyMatch,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
    ) -> bool {
        if crate::generic_keyword_owner::candidate_embeds_owned_assignment_key(
            &self.generic_named_assignment_keywords,
            &entropy_match.value,
        ) {
            return true;
        }
        entropy_value_line(entropy_match, preprocessed, line_offsets).is_some_and(|line| {
            crate::generic_keyword_owner::line_assignment_owned_by_named_detector(
                &self.generic_named_assignment_keywords,
                line,
            )
        })
    }
}

#[cfg(feature = "entropy")]
fn entropy_skip_line_index(absolute_line: Option<usize>, chunk_base_line: usize) -> Option<usize> {
    absolute_line?.checked_sub(chunk_base_line + 1)
}
