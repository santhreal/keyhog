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
    fn keyword_free_entropy_threshold(&self, sensitive_path: bool) -> Option<f64> {
        self.generic_owning_detector
            .keyword_free_owner_index()
            .and_then(|index| self.detector_plans.get(index).entropy.as_ref())
            .map(|policy| {
                if sensitive_path {
                    policy.sensitive_path_entropy_very_high
                } else {
                    policy.entropy_very_high
                }
            })
    }

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
        let source_path =
            crate::decode::caesar::is_program_source_code_path(chunk.metadata.path.as_deref());
        let source_entropy_requires_same_line_credential =
            !self.config.entropy_in_source_files && source_path;
        let restrict_source_entropy_to_assignments =
            source_entropy_requires_same_line_credential && !crate::telemetry::is_dogfood_enabled();
        // Compute keyword assignment lines ONCE and reuse across the
        // appropriateness gate, the lower-dash app-password gate, and the
        // full entropy scan. This avoids repeating the keyword search for the
        // appropriateness, special-shape, and emission decisions.
        // In source-restricted mode the emitter already rejects candidates
        // without a same-line credential assignment. Keep that exact predicate
        // at admission too, so ordinary source lines never enter the expensive
        // keyword-free entropy pass only to be rejected after extraction.
        let keyword_assignment_lines = if restrict_source_entropy_to_assignments {
            entropy_lines
                .iter()
                .enumerate()
                .filter_map(|(index, line)| {
                    (memchr::memchr3(b'=', b':', b'<', line.as_bytes()).is_some()
                        && crate::entropy::keywords::line_has_credential_assignment_surface(line))
                    .then_some((index, *line))
                })
                .collect()
        } else {
            crate::entropy::keywords::find_keyword_assignment_lines_with_policy(
                &entropy_lines,
                &self.config.secret_keywords,
                self.generic_owning_detector.policy_keywords(),
            )
        };
        // `is_entropy_appropriate_inner` needs `has_secret_keyword_line`. For
        // source files without `entropy_in_source_files`, the keyword-presence
        // signal is `line_has_credential_assignment_surface` (a stricter check
        // that requires a credential-shaped assignment, not just any secret
        // keyword). For all other paths, `find_keyword_assignment_lines` is
        // the signal. We reuse the pre-computed `keyword_assignment_lines`
        // for the latter case.
        let has_secret_keyword_line = if source_entropy_requires_same_line_credential
            && !restrict_source_entropy_to_assignments
        {
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
        let generic_keyword_secret_policy = self
            .generic_owning_detector
            .isolated_bare_owner_index()
            .and_then(|index| self.detector_plans.get(index).entropy.as_ref());
        let isolated_bare_candidate = !path_entropy_appropriate
            && generic_keyword_secret_policy.is_some_and(|policy| {
                crate::entropy::scanner::has_isolated_bare_secret_candidate_with_lines_and_policy(
                    &entropy_lines,
                    self.config.entropy_threshold,
                    &self.config.placeholder_keywords,
                    policy.keyword_free_min_len,
                    policy.entropy_shape,
                    Some(*policy),
                )
            });
        if !path_entropy_appropriate && !isolated_bare_candidate {
            return;
        }

        // Avoid entropy duplicates on lines already claimed by named detectors.
        let mut skip_lines = std::collections::HashSet::new();
        if !scan_state.matches.is_empty() {
            for m in &scan_state.matches {
                // Phase-2 entropy runs once after regex and generic producers,
                // so all matches already present are stronger line evidence.
                if let Some(line_idx) =
                    entropy_skip_line_index(m.location.line, chunk.metadata.base_line)
                {
                    skip_lines.insert(line_idx);
                }
            }
        }
        #[cfg(feature = "ml")]
        scan_state.for_each_pre_entropy_pending_ml_line(|absolute_line| {
            if let Some(line_idx) = entropy_skip_line_index(absolute_line, chunk.metadata.base_line)
            {
                skip_lines.insert(line_idx);
            }
        });

        // Admission must examine the same unclaimed lines the entropy emitter
        // can actually use. A strong named finding on one long random token used
        // to force a full-chunk Shannon sweep even though that line was excluded
        // from emission below. Ignoring already-owned lines is output-equivalent
        // and removes the dominant clean/sparse-corpus tail cost.
        #[cfg(feature = "simd")]
        let lower_dash_app_password_candidate = path_entropy_appropriate
            && crate::entropy::scanner::has_lower_dash_app_password_candidate_with_precomputed_keywords_and_policy(
                &keyword_assignment_lines,
                &self.config,
                Some(crate::entropy::scanner::ActiveDetectorPolicy::new(
                    &self.generic_owning_detector,
                    &self.detector_plans,
                )),
                &skip_lines,
            );
        #[cfg(feature = "simd")]
        let has_unclaimed_entropy_run = if restrict_source_entropy_to_assignments {
            keyword_assignment_lines.iter().any(|(line_index, line)| {
                !skip_lines.contains(line_index)
                    && super::scan_filters::has_high_entropy_run_at_least(
                        line.as_bytes(),
                        self.config.min_secret_len,
                    )
            })
        } else if skip_lines.is_empty() {
            super::scan_filters::has_high_entropy_run_at_least(
                preprocessed.text.as_bytes(),
                self.config.min_secret_len,
            )
        } else {
            entropy_lines.iter().enumerate().any(|(line_index, line)| {
                !skip_lines.contains(&line_index)
                    && super::scan_filters::has_high_entropy_run_at_least(
                        line.as_bytes(),
                        self.config.min_secret_len,
                    )
            })
        };
        #[cfg(feature = "simd")]
        if !isolated_bare_candidate
            && !lower_dash_app_password_candidate
            && !has_unclaimed_entropy_run
        {
            return;
        }

        let sensitive_path = chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(crate::confidence::is_sensitive_path);
        let keyword_free_threshold = self.keyword_free_entropy_threshold(sensitive_path);

        let entropy_matches =
            crate::entropy::scanner::find_entropy_secrets_with_precomputed_keywords_and_policy(
                &entropy_lines,
                line_offsets,
                &keyword_assignment_lines,
                self.config.min_secret_len,
                usize::from(!restrict_source_entropy_to_assignments),
                self.config.entropy_threshold,
                keyword_free_threshold,
                &self.config.secret_keywords,
                &self.config.test_keywords,
                &self.config.placeholder_keywords,
                Some(&skip_lines),
                Some(crate::entropy::scanner::ActiveDetectorPolicy::new(
                    &self.generic_owning_detector,
                    &self.detector_plans,
                )),
                if restrict_source_entropy_to_assignments {
                    crate::entropy::scanner::KeywordFreeLineScope::KeywordAssignments
                } else {
                    crate::entropy::scanner::KeywordFreeLineScope::All
                },
            );
        for entropy_match in entropy_matches {
            // Resolve the complete synthetic identity from the active policy
            // owner. There is no keyword classifier or scanner-global identity
            // table: an incomplete custom corpus fails closed instead of
            // silently relabelling the candidate as a built-in entropy class.
            let policy_detector_index = crate::entropy::scanner::active_policy_detector_index(
                &self.generic_owning_detector,
                &entropy_match.keyword,
            );
            let detector_plan = policy_detector_index.map(|index| self.detector_plans.get(index));
            let execution_policy = detector_plan.map(|plan| &plan.execution);
            let compiled_policy = detector_plan.and_then(|plan| plan.entropy.as_ref());
            let canonical_detector_index = self
                .generic_owning_detector
                .canonical_index(&entropy_match.keyword)
                .or(policy_detector_index);
            let transport_decoded = preprocessed.transport_decoded_for_offset(entropy_match.offset);
            let detector_owned_canonical_hex_key = canonical_detector_index.is_some_and(|index| {
                let policy = &self.detector_plans.get(index).key_material;
                if transport_decoded {
                    policy.allows_decoded_hex(&entropy_match.value)
                } else {
                    policy.allows_canonical_hex(&entropy_match.keyword, &entropy_match.value)
                }
            });
            let bpe_bound = if detector_owned_canonical_hex_key {
                None
            } else if let Some(policy) = compiled_policy {
                policy.bpe_bound(self.config.entropy_bpe_max_bytes_per_token_override)
            } else {
                None
            };
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

            // Pass detector-owned canonical-key evidence after generation. ML
            // authority can score an admitted candidate, but cannot bypass the
            // owning detector's exact TOML policy. The gauntlet still owns every
            // unrelated precision gate.
            if let Some(shape_stage) = entropy_match_suppression_stage(
                &entropy_match,
                preprocessed,
                line_offsets,
                chunk,
                detector_owned_canonical_hex_key,
                source_entropy_requires_same_line_credential,
                bpe_bound,
                compiled_policy,
                execution_policy,
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

            let Some(metadata) = policy_detector_index
                .and_then(|index| self.detector_plans.get(index).entropy_metadata.as_ref())
            else {
                tracing::error!(
                    target: "keyhog::detection",
                    keyword = %entropy_match.keyword,
                    detector_index = ?policy_detector_index,
                    "entropy candidate suppressed because its active detector lacks entropy_fallback metadata"
                );
                let entropy_ctx = crate::adjudicate::MatchCtx::for_entropy_fallback(
                    crate::adjudicate::EntropyFallbackSignal::ValueShape(
                        crate::adjudicate::EntropyShapeStage::MissingFallbackMetadata,
                    ),
                );
                crate::adjudicate::record_suppression(
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    &entropy_ctx,
                );
                continue;
            };
            let line_number = absolute_line(chunk.metadata.base_line, mapped_line);
            let checksum_decision = self.detector_plans.validate_any(&entropy_match.value);
            if checksum_decision.is_invalid() {
                crate::adjudicate::record_checksum_invalid_suppression(
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                );
                continue;
            }
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
            // through the same MoE batch as detector and generic matches. The
            // owning detector's compiled `ml.entropy_mode` applies to fallback
            // candidates; structurally proven canonical key material uses that
            // detector's `ml.match_mode`. The MoE separates otherwise unowned real
            // high-entropy secrets (~0.98) from high-entropy NON-secrets (FQDNs,
            // git SHAs, base64 blobs ~0.01) that the shape gates above don't
            // catch, and `apply_ml_batch_scores` then runs the ONE canonical
            // penalty / path / calibration / checksum / floor pipeline, so this
            // path no longer needs a bespoke `apply_post_ml_penalties` +
            // `checksum_adjusted_confidence` tail (the batch path applies both,
            // identically). The shape gates above remain cheap, recall-safe
            // pre-filters.
            let min_confidence_floor = crate::adjudicate::detector_min_confidence_floor(
                execution_policy.and_then(|policy| policy.min_confidence),
                self.config.min_confidence,
            );
            #[cfg(feature = "ml")]
            let entropy_ml_policy = detector_plan.map(|plan| plan.ml);
            #[cfg(feature = "ml")]
            let entropy_ml_mode = entropy_ml_policy.and_then(|policy| {
                if detector_owned_canonical_hex_key {
                    policy.match_mode
                } else {
                    policy.entropy_mode
                }
            });
            #[cfg(feature = "ml")]
            if let Some(((detector_index, policy), mode)) = policy_detector_index
                .zip(entropy_ml_policy)
                .zip(entropy_ml_mode)
                .filter(|_| self.config.ml_enabled && self.config.entropy_ml_authoritative)
            {
                let raw_match = build_raw_match(scan_state, policy_conf);
                let ml_features = crate::types::ml_features_for_candidate(
                    &preprocessed.text,
                    entropy_match.line,
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    policy.context_radius_lines,
                    &self.config,
                    self.detector_plans.get(detector_index).metadata.2.as_ref(),
                    policy.features,
                    crate::ml_scorer::MlCandidateChannel::Entropy,
                );
                scan_state.push_entropy_ml_pending(
                    raw_match,
                    policy_conf,
                    ml_features,
                    policy.effective_weight(&self.config),
                    min_confidence_floor,
                    detector_owned_canonical_hex_key,
                    checksum_decision,
                    mode,
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
                    is_generic_detector: true,
                    allow_encoded_text_lift: false,
                    allow_canonical_hex_key: detector_owned_canonical_hex_key,
                    checksum: checksum_decision,
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
