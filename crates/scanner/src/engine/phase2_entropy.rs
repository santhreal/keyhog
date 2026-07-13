#[cfg(feature = "entropy")]
mod gates;
#[cfg(feature = "entropy")]
pub(crate) mod helpers;
#[cfg(feature = "entropy")]
pub(crate) mod line_context;
#[cfg(feature = "entropy")]
use super::*;
#[cfg(feature = "entropy")]
use gates::entropy_match_suppression_stage;
#[cfg(feature = "entropy")]
use line_context::entropy_value_line;
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
        // Compute keyword assignment lines ONCE and reuse across the
        // appropriateness gate, the lower-dash app-password gate, and the
        // full entropy scan. Previously `find_keyword_assignment_lines` was
        // called 2-3 times per chunk (O(lines × 19 keywords) each), which
        // was the dominant entropy-scan cost at 8 MiB (~33% of the 18.3ms
        // per-chunk entropy time).
        let keyword_assignment_lines = crate::entropy::keywords::find_keyword_assignment_lines(
            &entropy_lines,
            &self.config.secret_keywords,
        );
        let source_path =
            crate::decode::caesar::is_program_source_code_path(chunk.metadata.path.as_deref());
        // `is_entropy_appropriate_inner` needs `has_secret_keyword_line`. For
        // source files without `entropy_in_source_files`, the keyword-presence
        // signal is `line_has_credential_assignment_surface` (a stricter check
        // that requires a credential-shaped assignment, not just any secret
        // keyword). For all other paths, `find_keyword_assignment_lines` is
        // the signal. We reuse the pre-computed `keyword_assignment_lines`
        // for the latter case.
        let has_secret_keyword_line = if source_path && !self.config.entropy_in_source_files {
            entropy_lines
                .iter()
                .copied()
                .any(crate::entropy::keywords::line_has_credential_assignment_surface)
        } else {
            !keyword_assignment_lines.is_empty()
        };
        let path_entropy_appropriate = crate::entropy::is_entropy_appropriate_inner(
            chunk.metadata.path.as_deref(),
            self.config.entropy_in_source_files,
            has_secret_keyword_line,
        );
        let source_entropy_requires_same_line_credential =
            !self.config.entropy_in_source_files && source_path;
        let generic_keyword_secret_min_len = self
            .generic_owning_detector
            .generic_keyword_secret_index()
            .and_then(|index| self.detectors.get(index))
            .and_then(|spec| spec.keyword_free_min_len)
            .map_or(crate::entropy::KEYWORD_FREE_MIN_LEN, |min_len| min_len);
        let isolated_bare_candidate = !path_entropy_appropriate
            && crate::entropy::scanner::has_isolated_bare_secret_candidate_with_lines(
                &entropy_lines,
                self.config.entropy_threshold,
                &self.config.placeholder_keywords,
                generic_keyword_secret_min_len,
            );
        #[cfg(feature = "simd")]
        let lower_dash_app_password_candidate = path_entropy_appropriate
            && crate::entropy::scanner::has_lower_dash_app_password_candidate_with_precomputed_keywords_and_policy(
                &keyword_assignment_lines,
                &self.config,
                Some(crate::entropy::scanner::ActiveDetectorPolicy::new(
                    &self.detectors,
                    &self.generic_owning_detector,
                )),
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
        scan_state.for_each_named_pending_ml_line(|absolute_line| {
            if let Some(line_idx) = entropy_skip_line_index(absolute_line, chunk.metadata.base_line)
            {
                skip_lines.insert(line_idx);
            }
        });

        let keyword_free_threshold = if chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(crate::confidence::is_sensitive_path)
        {
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
            crate::entropy::scanner::find_entropy_secrets_with_precomputed_keywords_and_policy(
                &entropy_lines,
                line_offsets,
                &keyword_assignment_lines,
                self.config.min_secret_len,
                1,
                self.config.entropy_threshold,
                keyword_free_threshold,
                &self.config.secret_keywords,
                &self.config.test_keywords,
                &self.config.placeholder_keywords,
                Some(&skip_lines),
                allow_canonical_lift,
                Some(crate::entropy::scanner::ActiveDetectorPolicy::new(
                    &self.detectors,
                    &self.generic_owning_detector,
                )),
            );
        for mut entropy_match in entropy_matches {
            // Resolve metadata once; emit clones the pre-interned triple.
            let entropy_meta_idx = helpers::classify_entropy_detector_index(&entropy_match.keyword);
            let policy_detector_id =
                crate::entropy::scanner::classify_keyword_to_detector_id(&entropy_match.keyword);
            let policy_detector = self
                .generic_owning_detector
                .index_for_id(policy_detector_id)
                .map(|index| &self.detectors[index]);
            let bpe_bound = crate::entropy::bpe::enabled_for_detector(policy_detector).then(|| {
                crate::entropy::bpe::max_bytes_per_token_for_detector(
                    policy_detector,
                    self.config.entropy_bpe_max_bytes_per_token,
                    self.config.entropy_bpe_max_bytes_per_token_override,
                )
            });
            let policy_conf = crate::confidence::policy::entropy_fallback_confidence(
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
            let Some(offset) = absolute_offset(chunk.metadata.base_offset, source_offset) else {
                continue;
            };

            // Pass the lift switch only after generation; the gauntlet still
            // owns every non-canonical precision gate.
            if let Some(shape_stage) = entropy_match_suppression_stage(
                &entropy_match,
                preprocessed,
                line_offsets,
                chunk,
                allow_canonical_lift,
                source_entropy_requires_same_line_credential,
                bpe_bound,
            ) {
                let entropy_ctx = crate::adjudicate::MatchCtx::for_entropy_fallback(
                    crate::adjudicate::EntropyFallbackSignal::ValueShape(shape_stage),
                );
                crate::adjudicate::record_suppression(
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    &entropy_ctx,
                );
                continue;
            }
            if crate::generic_keyword_owner::entropy_candidate_owned_by_named_assignment(
                &self.generic_named_assignment_keywords,
                &entropy_match.value,
                entropy_value_line(&entropy_match, preprocessed, line_offsets),
            ) {
                let entropy_ctx = crate::adjudicate::MatchCtx::for_entropy_fallback(
                    crate::adjudicate::EntropyFallbackSignal::NamedDetectorOwnedAssignment,
                );
                crate::adjudicate::record_suppression(
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    &entropy_ctx,
                );
                continue;
            }

            let metadata = &self.entropy_metadata_by_index[entropy_meta_idx];
            let line_number = absolute_line(chunk.metadata.base_line, mapped_line);
            let build_raw_match = |scan_state: &mut ScanState, report_conf| {
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
                    Some(line_number),
                    Some(entropy_match.entropy),
                    report_conf,
                    scan_state,
                )
            };

            // UNIFIED SCORING. When ML is live, route the entropy candidate
            // through the SAME MoE batch the detector/generic matches use, with
            // the model AUTHORITATIVE (no entropy-magnitude floor, see
            // `MlPendingMatch::model_authoritative`). The MoE separates real
            // high-entropy secrets (~0.98) from high-entropy NON-secrets (FQDNs,
            // git SHAs, base64 blobs ~0.01) that the shape gates above don't
            // catch, and `apply_ml_batch_scores` then runs the ONE canonical
            // penalty / path / calibration / checksum / floor pipeline, so this
            // path no longer needs a bespoke `apply_post_ml_penalties` +
            // `checksum_adjusted_confidence` tail (the batch path applies both,
            // identically). The shape gates above remain cheap, recall-safe
            // pre-filters.
            let min_confidence_floor = crate::adjudicate::detector_min_confidence_floor(
                policy_detector.and_then(|detector| detector.min_confidence),
                self.config.min_confidence,
            );
            #[cfg(feature = "ml")]
            if self.config.ml_enabled && self.config.entropy_ml_authoritative {
                let raw_match = build_raw_match(scan_state, policy_conf);
                let ml_context = crate::types::ml_context_for_candidate(
                    &preprocessed.text,
                    entropy_match.line,
                    chunk.metadata.path.as_deref(),
                );
                scan_state.push_entropy_authoritative_ml_pending(
                    raw_match,
                    policy_conf,
                    std::mem::take(&mut entropy_match.value),
                    ml_context,
                    min_confidence_floor,
                );
                continue;
            }

            // Non-ML path emits directly through the same report-confidence
            // finalizer used by ML and detector hits.
            let Some(report_conf) = crate::adjudicate::finalize_report_candidate(
                chunk.metadata.path.as_deref(),
                &entropy_match.value,
                crate::adjudicate::ReportAdjudicationPolicy {
                    detector_id: metadata.0.as_ref(),
                    code_context: crate::context::CodeContext::Unknown,
                    confidence: policy_conf,
                    min_confidence_floor,
                    penalize_test_paths: self.config.penalize_test_paths,
                    file_path: chunk.metadata.path.as_deref(),
                    is_named_detector: false,
                    allow_encoded_text_lift: false,
                    calibration: self.config.calibration.as_deref(),
                },
            ) else {
                continue;
            };
            scan_state.push_match_lazy(
                crate::types::RawMatchPriority {
                    confidence: Some(report_conf),
                    severity: keyhog_core::Severity::High,
                    detector_id: metadata.0.as_ref(),
                    credential: &entropy_match.value,
                    offset,
                    line: Some(line_number),
                },
                self.config.max_matches_per_chunk,
                |scan_state| build_raw_match(scan_state, report_conf),
            );
        }
    }
}

#[cfg(feature = "entropy")]
fn entropy_skip_line_index(absolute_line: Option<usize>, chunk_base_line: usize) -> Option<usize> {
    absolute_line?.checked_sub(chunk_base_line + 1)
}
