//! ML pending-match scoring for the postprocess tail.
//!
//! This owns the feature-gated MoE/CPU score blend for matches queued by
//! detector, generic, and entropy paths. The non-ML postprocess owner should not
//! also carry model scoring policy.

use super::{scan_postprocess_profile, CompiledScanner};
use crate::types::{MlPendingMatch, ScanState};

impl CompiledScanner {
    fn emit_finalized_pending_match(
        &self,
        scan_state: &mut ScanState,
        pending: MlPendingMatch,
        mut final_score: f64,
    ) {
        let Some(adjusted_score) = super::scoring::finalize_report_confidence(
            final_score,
            super::scoring::ReportConfidencePolicy {
                credential: &pending.credential,
                detector_id: pending.raw_match.detector_id.as_ref(),
                file_path: pending.raw_match.location.file_path.as_deref(),
                is_named_detector: crate::confidence::is_service_anchored_detector(
                    &pending.raw_match.detector_id,
                ),
                penalize_test_paths: self.config.penalize_test_paths,
                allow_encoded_text_lift: false,
                calibration: self.config.calibration.as_deref(),
            },
        ) else {
            crate::adjudicate::record_stage_suppression(
                pending.raw_match.location.file_path.as_deref(),
                &pending.credential,
                crate::adjudicate::StageId::ChecksumInvalid,
            );
            return;
        };
        final_score = adjusted_score;
        if let Some(stage_id) = crate::adjudicate::final_emit_suppression_stage(
            pending.raw_match.detector_id.as_ref(),
            &pending.credential,
            pending.code_context,
            final_score,
            pending.min_confidence_floor,
            self.config.penalize_test_paths,
        ) {
            crate::adjudicate::record_stage_suppression(
                pending.raw_match.location.file_path.as_deref(),
                &pending.credential,
                stage_id,
            );
            return;
        }
        let mut raw_match = pending.raw_match;
        raw_match.confidence = Some(final_score);
        scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
    }

    fn score_ml_pending_cpu(&self, pending_matches: &[MlPendingMatch]) -> Vec<f64> {
        pending_matches
            .iter()
            .map(|pending| {
                crate::ml_scorer::score_with_config(
                    pending.credential.as_str(),
                    pending.ml_context.as_str(),
                    &self.config.known_prefixes,
                    &self.config.secret_keywords,
                    &self.config.test_keywords,
                    &self.config.placeholder_keywords,
                )
            })
            .collect()
    }

    pub(crate) fn apply_ml_batch_scores(&self, scan_state: &mut ScanState) {
        if scan_postprocess_profile::ml_batch_prof_enabled() {
            scan_postprocess_profile::ml_batch_record(scan_state.ml_pending.len());
        }
        if scan_state.ml_pending.is_empty() {
            return;
        }

        if !self.config.ml_enabled {
            let pending = scan_state.ml_pending.drain(..).collect::<Vec<_>>();
            for p in pending {
                let heuristic_conf = p.heuristic_conf;
                self.emit_finalized_pending_match(scan_state, p, heuristic_conf);
            }
            return;
        }

        // Borrow rather than clone - `ml_pending` is alive for the duration
        // of the call, so `&str` references stay valid through ML scoring.
        // On a wide scan with hundreds of pending matches this drops 2N
        // owned-string allocations per batch.
        let candidates: Vec<(&str, &str)> = scan_state
            .ml_pending
            .iter()
            .map(|pending| (pending.credential.as_str(), pending.ml_context.as_str()))
            .collect();

        let scores = crate::gpu::batch_ml_inference_with_timeout(
            &candidates,
            &self.config,
            self.tuning.gpu_moe_timeout(),
        );
        let pending_matches: Vec<_> = scan_state.ml_pending.drain(..).collect();
        let scores = if scores.len() == pending_matches.len() {
            scores
        } else {
            tracing::warn!(
                pending = pending_matches.len(),
                scores = scores.len(),
                "ML score count mismatch; recomputing CPU MoE scores before confidence blending"
            );
            self.score_ml_pending_cpu(&pending_matches)
        };
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores.into_iter()) {
            // Honour the runtime `--ml-weight` / `ml_weight` knob instead
            // of the compile-time ML_WEIGHT/HEURISTIC_WEIGHT consts: the
            // blend is `w·ml + (1-w)·heuristic` with `w` already clamped to
            // [0,1] by `ScannerConfig::sanitise`. A hardcoded 0.6/0.4 made
            // the tuned knob a no-op (the tuned!=shipped trap) - now the
            // value the user / benchmark sets is the value the blend uses.
            let ml_weight = self.config.ml_weight;
            let mut final_score = if pending.model_authoritative {
                // Entropy-fallback candidate: the MoE is the unified scorer. The
                // "heuristic" here is bare entropy magnitude, which is precisely
                // what mislabels high-entropy non-secrets (FQDNs, git SHAs,
                // base64 blobs) - so it must NOT floor the model. Taking the
                // model score directly lets the MoE suppress those FPs (probe:
                // structured non-secrets score ~0.01, real secrets ~0.98) while
                // the downstream penalty/checksum/floor pipeline below still
                // applies uniformly. The shape gates in scan_entropy_fallback
                // already removed the cheap non-secrets before this point.
                ml_conf
            } else {
                // Detector/generic match: the regex is positive evidence, so the
                // heuristic is a confidence FLOOR and the model can only raise.
                let blended = (ml_weight * ml_conf) + ((1.0 - ml_weight) * pending.heuristic_conf);
                blended.max(pending.heuristic_conf).max(ml_conf)
            };

            // `--scan-comments` opts the Comment context out of the
            // ML-blended confidence multiplier so a real credential in
            // a `// TODO: rotate this ...` comment surfaces with the
            // same weight as one on a bare assignment line. Test/docs contexts
            // stay penalized unless `--no-suppress-test-fixtures` is active.
            let context_penalty_applies = match pending.code_context {
                crate::context::CodeContext::Comment => !self.config.scan_comments,
                crate::context::CodeContext::TestCode
                | crate::context::CodeContext::Documentation => self.config.penalize_test_paths,
                _ => false,
            };
            if context_penalty_applies && final_score < 0.95 {
                final_score *= pending.code_context.confidence_multiplier();
            }

            self.emit_finalized_pending_match(scan_state, pending, final_score);
        }
    }
}
