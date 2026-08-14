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
thread_local! {
    static ENTROPY_SKIP_LINES_SCRATCH: std::cell::RefCell<std::collections::HashSet<usize>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

pub(crate) const SCRATCH_CAPACITY_CEILING: usize = 4096;
struct SkipLinesGuard(std::collections::HashSet<usize>);

impl Drop for SkipLinesGuard {
    fn drop(&mut self) {
        self.0.clear();
        if self.0.capacity() > SCRATCH_CAPACITY_CEILING {
            self.0 = std::collections::HashSet::new();
        }
        ENTROPY_SKIP_LINES_SCRATCH.with(|cell| {
            cell.replace(std::mem::take(&mut self.0));
        });
    }
}

pub(crate) fn exercise_entropy_skip_lines_scratch_for_test(entries: usize) -> usize {
    {
        let mut scratch = SkipLinesGuard(ENTROPY_SKIP_LINES_SCRATCH.with(|cell| cell.take()));
        scratch.0.extend(0..entries);
    }
    ENTROPY_SKIP_LINES_SCRATCH.with(|cell| cell.borrow().capacity())
}

#[cfg(feature = "entropy")]
impl CompiledScanner {
    pub(crate) fn keyword_free_entropy_threshold(&self, sensitive_path: bool) -> Option<f64> {
        self.detector_plans
            .generic_ownership()
            .keyword_free_owner_index()
            .and_then(|index| self.detector_plans.entropy(index))
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
        line_index: &crate::context::LineContextIndex,
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        if !self.config.entropy_enabled {
            return;
        }
        if chunk.metadata.source_type.contains("/caesar") {
            return;
        }
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
        // Production discovery uses only active detector TOML keywords and the
        // operator's Tier-A list. The compatibility assignment vocabulary must
        // not widen a replacement corpus, including source-restricted scans.
        let keyword_matcher = self
            .assignment_keyword_matcher
            .lock()
            // LAW10: recall-preserving; Mutex poison does not invalidate the matcher cache value, and retaining it avoids dropping entropy candidates.
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .resolve(
                &self.config.secret_keywords,
                self.detector_plans.generic_ownership().policy_keywords(),
            );
        let keyword_assignment_lines =
            crate::entropy::keywords::find_keyword_assignment_line_ids_with_matcher(
                &preprocessed.text,
                line_index,
                &keyword_matcher,
            );
        let has_secret_keyword_line = !keyword_assignment_lines.is_empty();
        let path_entropy_appropriate = crate::entropy::is_entropy_appropriate_inner(
            chunk.metadata.path.as_deref(),
            self.config.entropy_in_source_files,
            has_secret_keyword_line,
        );
        let generic_keyword_secret_policy = self
            .detector_plans
            .generic_ownership()
            .isolated_bare_owner_index()
            .and_then(|index| self.detector_plans.entropy(index));
        let isolated_bare_candidate = !path_entropy_appropriate
            && generic_keyword_secret_policy.is_some_and(|policy| {
                crate::entropy::scanner::has_isolated_bare_secret_candidate_indexed(
                    &preprocessed.text,
                    line_index,
                    self.config.entropy_threshold,
                    &self.config.placeholder_keywords,
                    policy.keyword_free_min_len,
                    policy,
                )
            });
        if !path_entropy_appropriate && !isolated_bare_candidate {
            return;
        }

        // Avoid entropy duplicates on lines already claimed by named detectors.
        let mut skip_lines_owned =
            SkipLinesGuard(ENTROPY_SKIP_LINES_SCRATCH.with(|cell| cell.take()));
        skip_lines_owned.0.clear();
        let skip_lines = &mut skip_lines_owned.0;
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
            && crate::entropy::scanner::has_lower_dash_app_password_candidate_indexed(
                &preprocessed.text,
                line_index,
                &keyword_assignment_lines,
                &self.config,
                Some(crate::entropy::scanner::ActiveDetectorPolicy::new(
                    &self.detector_plans.generic_ownership(),
                    &self.detector_plans,
                )),
                &skip_lines,
            );
        #[cfg(feature = "simd")]
        let has_unclaimed_entropy_run = if restrict_source_entropy_to_assignments {
            keyword_assignment_lines.iter().any(|&line_idx| {
                !skip_lines.contains(&line_idx)
                    && line_index
                        .line(&preprocessed.text, line_idx)
                        .is_some_and(|line| {
                            super::scan_filters::has_high_entropy_run_at_least(
                                line.as_bytes(),
                                self.config.min_secret_len,
                            )
                        })
            })
        } else if skip_lines.is_empty() {
            super::scan_filters::has_high_entropy_run_at_least(
                preprocessed.text.as_bytes(),
                self.config.min_secret_len,
            )
        } else {
            line_index
                .lines(&preprocessed.text)
                .enumerate()
                .any(|(line_index_value, line)| {
                    !skip_lines.contains(&line_index_value)
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

        let entropy_matches = crate::entropy::scanner::find_classified_entropy_secrets_indexed(
            &preprocessed.text,
            line_index,
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
                &self.detector_plans.generic_ownership(),
                &self.detector_plans,
            )),
            if restrict_source_entropy_to_assignments {
                crate::entropy::scanner::KeywordFreeLineScope::KeywordAssignments
            } else {
                crate::entropy::scanner::KeywordFreeLineScope::All
            },
        );
        for classified_match in entropy_matches {
            let declared_credential_context = classified_match.is_credential_context;
            let same_line_credential_context = classified_match.is_same_line_credential_context;
            let entropy_match = classified_match.matched;
            // Resolve the complete synthetic identity from the active policy
            // owner. There is no keyword classifier or scanner-global identity
            // table: an incomplete custom corpus fails closed instead of
            // silently relabelling the candidate as a built-in entropy class.
            let Some(policy_detector_index) = crate::entropy::scanner::active_policy_detector_index(
                &self.detector_plans.generic_ownership(),
                &entropy_match.keyword,
            ) else {
                tracing::error!(
                    target: "keyhog::detection",
                    keyword = %entropy_match.keyword,
                    "generated entropy candidate has no compiled detector owner"
                );
                continue;
            };
            let detector_plan = self.detector_plans.get(policy_detector_index);
            let match_confidence = self.detector_plans.match_confidence(policy_detector_index);
            let execution_policy = &detector_plan.execution;
            let Some(compiled_policy) = self.detector_plans.entropy(policy_detector_index) else {
                tracing::error!(
                    target: "keyhog::detection",
                    keyword = %entropy_match.keyword,
                    detector_index = policy_detector_index,
                    "generated entropy candidate owner has no compiled entropy policy"
                );
                continue;
            };
            let canonical_detector_index = self
                .detector_plans
                .generic_ownership()
                .canonical_index(&entropy_match.keyword)
                // LAW10: canonical default; operator-added Tier-A keywords have no TOML owner, so their resolved entropy owner remains authoritative.
                .unwrap_or(policy_detector_index);
            let transport_decoded = preprocessed.transport_decoded_for_offset(entropy_match.offset);
            let detector_owned_canonical_hex_key = {
                let policy = &self
                    .detector_plans
                    .get(canonical_detector_index)
                    .key_material;
                if transport_decoded {
                    policy.allows_decoded_hex(&entropy_match.value)
                } else {
                    policy.allows_canonical_hex(&entropy_match.keyword, &entropy_match.value)
                }
            };
            let bpe_bound = if detector_owned_canonical_hex_key {
                None
            } else {
                compiled_policy.bpe_bound(self.config.entropy_bpe_max_bytes_per_token_override)
            };
            // Sensitive-path keyword-free admission uses
            // `sensitive_path_entropy_very_high` as the floor. Score the same
            // band here so a candidate that cleared that floor is not stuck in
            // the ordinary "high" tier and then erased by soft confidence.
            let entropy_very_high_for_confidence =
                if sensitive_path && entropy_match.keyword == crate::entropy::KEYWORD_FREE_LABEL {
                    compiled_policy.sensitive_path_entropy_very_high
                } else {
                    compiled_policy.entropy_very_high
                };
            let policy_conf = crate::confidence::policy::entropy_fallback_confidence(
                entropy_match.entropy,
                &entropy_match.keyword,
                compiled_policy.entropy_high,
                entropy_very_high_for_confidence,
                compiled_policy.fallback_confidence,
            );
            let mapped_line = preprocessed
                .line_for_offset(entropy_match.offset)
                // LAW10: missing transformed-line mapping uses the exact original line index.
                .unwrap_or_else(|| line_index.line_number_for_offset(entropy_match.offset));
            let source_offset = preprocessed.source_offset_for_match(
                &chunk.data,
                entropy_match.offset,
                &entropy_match.value,
            );
            let provenance = crate::candidate_provenance::CandidateProvenance::entropy();
            let provenance = scan_state
                .source_semantic_evidence(chunk, source_offset, &entropy_match.value)
                .map_or(provenance, |evidence| {
                    provenance.with_source_semantics(evidence)
                });
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
                line_index,
                chunk,
                declared_credential_context,
                same_line_credential_context,
                detector_owned_canonical_hex_key,
                source_entropy_requires_same_line_credential,
                bpe_bound,
                compiled_policy,
                execution_policy,
                match_confidence.post_match().degenerate_run_min_length,
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
                self.detector_plans.generic_named_assignment_keywords(),
                &entropy_match.value,
                entropy_value_line(&entropy_match, preprocessed, line_index),
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

            let Some(metadata) = detector_plan.entropy_metadata.as_ref() else {
                tracing::error!(
                    target: "keyhog::detection",
                    keyword = %entropy_match.keyword,
                    detector_index = policy_detector_index,
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
                execution_policy.min_confidence,
                self.config.min_confidence,
            );
            #[cfg(feature = "ml")]
            let entropy_ml_policy = detector_plan.ml;
            #[cfg(feature = "ml")]
            let entropy_ml_mode = if detector_owned_canonical_hex_key {
                entropy_ml_policy.match_mode
            } else if sensitive_path && entropy_match.keyword == crate::entropy::KEYWORD_FREE_LABEL
            {
                // Keyword-free on a sensitive path already cleared the
                // detector's sensitive entropy floor (e.g. VALUE=<token> in
                // secrets.env). Authoritative ML must not veto that structural
                // evidence when nearby assignment context looks generic; keep
                // ML as a lift on top of the heuristic floor.
                entropy_ml_policy
                    .entropy_mode
                    .map(|_| crate::detector_ml_policy::ActiveMlMode::Lift)
            } else {
                entropy_ml_policy.entropy_mode
            };
            #[cfg(feature = "ml")]
            if let Some(mode) = entropy_ml_mode
                .filter(|_| self.config.ml_enabled && self.config.entropy_ml_authoritative)
            {
                let policy = entropy_ml_policy;
                let ml_features = crate::types::ml_features_for_candidate(
                    &preprocessed.text,
                    line_index,
                    entropy_match.line,
                    chunk.metadata.path.as_deref(),
                    &entropy_match.value,
                    policy.context_radius_lines,
                    &self.config,
                    detector_plan.metadata.2.as_ref(),
                    policy.features,
                    crate::ml_scorer::MlCandidateChannel::Entropy,
                );
                let pending_raw_match = crate::pipeline::build_pending_synthetic_raw_match(
                    (
                        Arc::clone(&metadata.0),
                        Arc::clone(&metadata.1),
                        Arc::clone(&metadata.2),
                    ),
                    keyhog_core::Severity::High,
                    chunk,
                    &entropy_match.value,
                    offset,
                    Some(line_number),
                    Some(entropy_match.entropy),
                    scan_state,
                    provenance,
                );
                scan_state.push_entropy_ml_pending(
                    pending_raw_match,
                    policy_conf,
                    match_confidence.context_multiplier(crate::context::CodeContext::Unknown),
                    match_confidence
                        .context_suppression_threshold(crate::context::CodeContext::Unknown),
                    match_confidence.post_match(),
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
                    context_suppression_threshold: match_confidence
                        .context_suppression_threshold(crate::context::CodeContext::Unknown),
                    post_match: match_confidence.post_match(),
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
            scan_state.push_match_lazy_with_provenance(
                crate::types::RawMatchPriority {
                    confidence: Some(report_conf),
                    severity: keyhog_core::Severity::High,
                    detector_id: metadata.0.as_ref(),
                    credential: &entropy_match.value,
                    offset,
                    line: Some(line_number),
                },
                provenance,
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
