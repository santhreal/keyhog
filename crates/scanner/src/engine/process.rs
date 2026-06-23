//! `process_match`: the per-match post-processing chain.
//!
//! Runs the suppression chain, companion-required gate, entropy + camel-shape
//! filters for generic detectors, checksum validation, and finally ML /
//! heuristic scoring. Outputs either a `Final` finding into `scan_state.matches`
//! or queues an `MlPendingMatch` for the post-scan ML batch.

use super::scan_filters::*;
use super::CompiledScanner;
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
        // Per-detector constant, resolved once at scanner construction
        // (`detector_weak_anchor_by_index`) instead of re-running
        // `detector_weak_anchor`'s regex-string scan for every surviving
        // candidate. `.get(...).copied().unwrap_or_else(...)` falls back to the
        // live computation only if the index is somehow out of range (it never
        // is — the vec is index-parallel with `detectors` — but the fallback
        // keeps this byte-identical to the prior inline call rather than
        // panicking on a malformed index, matching the resilience the extract
        // path already applies to `detector_index`).
        let weak_anchor = self
            .detector_weak_anchor_by_index
            .get(entry.detector_index)
            .copied()
            .unwrap_or_else(|| crate::suppression::detector_weak_anchor(detector)); // LAW10: bounds-checked lookup; out-of-range => documented default (total fn), recall-safe
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
                    let companion_ctx = crate::adjudicate::MatchCtx::for_process_signals(
                        crate::adjudicate::ProcessCandidateSignals::from_missing_required_companion(
                            true,
                        ),
                    );
                    let recorded = crate::adjudicate::record_suppression(
                        chunk.metadata.path.as_deref(),
                        credential,
                        &companion_ctx,
                    );
                    debug_assert_eq!(
                        recorded,
                        Some(crate::adjudicate::StageId::MissingRequiredCompanion)
                    );
                    return;
                }
            }
        };
        let entropy = match_entropy(credential.as_bytes());

        let is_generic = crate::detector_ids::is_generic_detector(detector.id.as_ref())
            && detector.id.as_str() != crate::detector_ids::GENERIC_PRIVATE_KEY;
        let is_weakly_anchored = weak_anchor;
        let mut entropy_below_floor = false;
        let mut camel_case_no_digit = false;
        if is_generic || is_weakly_anchored {
            // Per-detector entropy floor. Structured tokens (UUIDs, short API keys)
            // have lower entropy than random strings. A blanket 3.5 floor misses them.
            let floor_id = if is_weakly_anchored {
                crate::detector_ids::GENERIC_API_KEY
            } else {
                detector.id.as_str()
            };
            let entropy_floor =
                generic_entropy_floor(self.config.entropy_threshold, floor_id, credential.len());
            if entropy < entropy_floor {
                entropy_below_floor = true;
            } else if !credential.bytes().any(|b| b.is_ascii_digit()) {
                // camelCase-without-digits is the false-positive shape (Java/Go
                // identifiers like `getUserName`); real tokens almost always carry
                // a digit. The cheap digit scan (ASCII bytes, no UTF-8 decode via
                // `chars()`) runs first so any credential containing a digit skips
                // the O(n) camel-transition window walk entirely. Only no-digit
                // credentials pay for the count, and `take(2)` stops it as soon as
                // the >=2 threshold is reached. Behavior is identical to the prior
                // `transitions >= 2 && !has_digit` gate.
                let camel_transitions = credential
                    .as_bytes()
                    .windows(2)
                    .filter(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase())
                    .take(2)
                    .count();
                if camel_transitions >= 2 {
                    camel_case_no_digit = true;
                }
            }
        }
        let entropy_shape_ctx = crate::adjudicate::MatchCtx::for_process_signals(
            crate::adjudicate::ProcessCandidateSignals::from_entropy_shape(
                entropy_below_floor,
                camel_case_no_digit,
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
        let checksum_policy = crate::confidence::policy::checksum_policy_for(credential);
        let checksum_ctx = crate::adjudicate::MatchCtx::for_process_signals(
            crate::adjudicate::ProcessCandidateSignals::from_checksum_invalid(
                checksum_policy.is_invalid(),
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
        let is_named_detector =
            crate::confidence::is_service_anchored_detector(&detector.id) && !weak_anchor;
        let Some(score_result) = self.match_confidence(
            entry,
            chunk,
            credential,
            data,
            line,
            entropy,
            !companions.is_empty(),
            inferred_context,
            keyword_nearby,
            sensitive_file,
            is_named_detector,
            scan_state,
        ) else {
            let scoring_ctx = crate::adjudicate::MatchCtx::for_process_signals(
                crate::adjudicate::ProcessCandidateSignals::from_scoring_rejected(true),
            );
            let recorded = crate::adjudicate::record_suppression(
                chunk.metadata.path.as_deref(),
                credential,
                &scoring_ctx,
            );
            debug_assert_eq!(recorded, Some(crate::adjudicate::StageId::ScoringRejected));
            return;
        };

        let min_confidence_floor = match detector.min_confidence {
            Some(detector_floor) => detector_floor,
            None => self.config.min_confidence,
        };

        match score_result {
            super::MlScoreResult::Final(confidence) => {
                let Some(confidence) = crate::adjudicate::finalize_report_candidate(
                    chunk.metadata.path.as_deref(),
                    credential,
                    crate::adjudicate::ReportAdjudicationPolicy {
                        detector_id: detector.id.as_ref(),
                        code_context: inferred_context,
                        confidence,
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
                    confidence,
                    scan_state,
                    entry.client_safe,
                );
                scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
                crate::telemetry::record_match_found();
            }
            #[cfg(feature = "ml")]
            super::MlScoreResult::Pending {
                heuristic_conf,
                code_context,
                credential: pending_credential,
                ml_context,
            } => {
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
                    heuristic_conf,
                    scan_state,
                    entry.client_safe,
                );
                scan_state.ml_pending.push(crate::types::MlPendingMatch {
                    raw_match,
                    heuristic_conf,
                    code_context,
                    credential: pending_credential.into_owned(),
                    ml_context: ml_context.into_owned(),
                    min_confidence_floor,
                    is_named_detector,
                    // Detector/generic matches: the firing regex is positive
                    // evidence, so the heuristic stays a confidence FLOOR (the
                    // model can only raise). Not model-authoritative.
                    model_authoritative: false,
                });
                crate::telemetry::record_match_found();
            }
            #[cfg(not(feature = "ml"))]
            super::MlScoreResult::_Lifetime(_) => {
                unreachable!("_Lifetime is a never-constructed placeholder variant")
            }
        }
    }
}
