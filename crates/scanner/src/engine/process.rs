//! `process_match`: the per-match post-processing chain.
//!
//! Runs the suppression chain, companion-required gate, entropy + camel-shape
//! filters for generic detectors, checksum validation, and finally ML /
//! heuristic scoring. Outputs either a `Final` finding into `scan_state.matches`
//! or queues an `MlPendingMatch` for the post-scan ML batch.

use super::CompiledScanner;
use super::scan_filters::*;
use crate::confidence::policy::MlScoreResult;
use crate::context;
use crate::pipeline::*;
use crate::types::*;
use keyhog_core::{Chunk, DetectorSpec};
use std::collections::HashMap;

impl CompiledScanner {
    pub(crate) fn match_companions(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText<'_>,
        line: usize,
    ) -> Option<HashMap<String, String>> {
        // Most detectors declare no companions. Return the empty map without
        // sizing a bucket array (`HashMap::new()` is allocation-free until the
        // first insert) and without entering the search loop. Only detectors
        // that actually have companions pay for the map.
        let Some(detector_companions) = self.companions.get(entry.detector_index) else {
            return Some(HashMap::new());
        };
        if detector_companions.is_empty() {
            return Some(HashMap::new());
        }
        let mut results = HashMap::with_capacity(detector_companions.len());
        for companion in detector_companions {
            if let Some(val) = find_companion(preprocessed, line, companion) {
                results.insert(companion.name.clone(), val);
            } else if companion.required {
                return None;
            }
        }
        Some(results)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn process_match(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        data: &str,
        preprocessed: &ScannerPreprocessedText<'_>,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        credential: &str,
        credential_start: usize,
        credential_end: usize,
        base_line: usize,
        base_offset: usize,
        keyword_nearby: bool,
        sensitive_file: bool,
    ) {
        let (credential, match_end) =
            extend_known_prefix_credential(data, credential, credential_end);
        let line = match_line_number(preprocessed, line_offsets, credential_start);

        let process_signals = crate::adjudicate::ProcessCandidateSignals::from_match(
            detector.id.as_ref(),
            self.credential_shape_by_detector_index
                .get(entry.detector_index)
                .and_then(Option::as_ref),
            credential,
            data,
            credential_start,
            match_end,
        );
        let process_ctx = crate::adjudicate::MatchCtx::for_process_signals(process_signals);
        if crate::adjudicate::record_suppression(
            chunk.metadata.path.as_deref(),
            credential,
            &process_ctx,
        )
        .is_some()
        {
            return;
        }
        let false_positive_context = context::is_false_positive_context(
            code_lines,
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

        let inferred_context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        // Per-detector constant, resolved once at scanner construction.
        // `CompiledPattern::detector_index` and the weak-anchor cache are
        // index-parallel with `detectors`; a mismatch is an internal
        // construction bug and must be loud instead of recomputing policy here.
        let weak_anchor = self.detector_weak_anchor_by_detector_index(entry.detector_index);
        let named_suppression_ctx =
            crate::suppression::NamedDetectorSuppressionCtx::with_weak_anchor(
                chunk.metadata.path.as_deref(),
                inferred_context,
                Some(chunk.metadata.source_type.as_str()),
                detector.id.as_ref(),
                weak_anchor,
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

        // `None` means a required companion is missing; record that hard skip
        // instead of treating it like an empty companion set.
        let companions = if self.companions.is_empty() {
            HashMap::new()
        } else {
            match self.match_companions(entry, preprocessed, line) {
                Some(c) => c,
                None => {
                    crate::adjudicate::record_missing_required_companion_suppression(
                        chunk.metadata.path.as_deref(),
                        credential,
                    );
                    return;
                }
            }
        };
        let entropy = match_entropy(credential.as_bytes());

        let is_generic = crate::detector_ids::is_generic_detector(detector.id.as_ref());
        let is_weakly_anchored = weak_anchor;
        let entropy_shape_ctx = crate::adjudicate::MatchCtx::for_process_signals(
            crate::adjudicate::ProcessCandidateSignals::from_process_entropy_shape(
                is_generic,
                is_weakly_anchored,
                entropy,
                self.config.entropy_threshold,
                detector.id.as_ref(),
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

        // Checksum validation: tokens with embedded checksums (GitHub, npm, Slack,
        // Stripe, GitLab, PyPI) can be verified without network requests. The
        // confidence policy owner makes the drop/floor rule shared with hot,
        // generic, entropy, and ML emitters.
        let checksum_ctx = crate::adjudicate::MatchCtx::for_process_signals(
            crate::adjudicate::ProcessCandidateSignals::from_checksum_policy(credential),
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
        let is_named_detector =
            crate::confidence::is_service_anchored_detector(&detector.id) && !weak_anchor;
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
                keyword_nearby,
                sensitive_file,
                match_length: credential.len(),
                has_companion: !companions.is_empty(),
                code_context: inferred_context,
                penalize_test_paths: self.config.penalize_test_paths,
                ml_enabled: self.config.ml_enabled,
                credential,
                is_named_detector,
            },
        );

        let min_confidence_floor = crate::adjudicate::detector_min_confidence_floor(
            detector.min_confidence,
            self.config.min_confidence,
        );

        match policy_result {
            MlScoreResult::Final(policy_conf) => {
                let Some(report_conf) = crate::adjudicate::finalize_report_candidate(
                    chunk.metadata.path.as_deref(),
                    credential,
                    crate::adjudicate::ReportAdjudicationPolicy {
                        detector_id: detector.id.as_ref(),
                        code_context: inferred_context,
                        confidence: policy_conf,
                        min_confidence_floor,
                        penalize_test_paths: self.config.penalize_test_paths,
                        file_path: chunk.metadata.path.as_deref(),
                        is_named_detector,
                        allow_encoded_text_lift: false,
                        calibration: self.config.calibration.as_deref(),
                    },
                ) else {
                    return;
                };
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, credential_start, credential);
                let raw_match = build_raw_match(
                    detector,
                    self.interned_detector_metadata(entry.detector_index),
                    chunk,
                    credential,
                    companions,
                    source_offset + base_offset,
                    line + base_line,
                    entropy,
                    report_conf,
                    scan_state,
                    entry.client_safe,
                );
                if !scan_state.claim_stripe_secret_key_offset(
                    raw_match.detector_id.as_ref(),
                    raw_match.location.offset,
                ) {
                    return;
                }
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
                crate::telemetry::record_match_found();
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending {
                heuristic_conf,
                code_context,
                credential: pending_credential,
            } => {
                let source_offset =
                    preprocessed.source_offset_for_match(&chunk.data, credential_start, credential);
                let ml_context = crate::types::ml_context_for_candidate(
                    data,
                    line,
                    chunk.metadata.path.as_deref(),
                );
                let raw_match = build_raw_match(
                    detector,
                    self.interned_detector_metadata(entry.detector_index),
                    chunk,
                    credential,
                    companions,
                    source_offset + base_offset,
                    line + base_line,
                    entropy,
                    heuristic_conf,
                    scan_state,
                    entry.client_safe,
                );
                if !scan_state.claim_stripe_secret_key_offset(
                    raw_match.detector_id.as_ref(),
                    raw_match.location.offset,
                ) {
                    return;
                }
                scan_state.push_detector_ml_pending(
                    raw_match,
                    heuristic_conf,
                    code_context,
                    pending_credential.into_owned(),
                    ml_context,
                    min_confidence_floor,
                    is_named_detector,
                );
                crate::telemetry::record_match_found();
            }
            #[cfg(not(feature = "ml"))]
            MlScoreResult::_Lifetime(_) => {
                unreachable!("_Lifetime is a never-constructed placeholder variant")
            }
        }
    }
}
