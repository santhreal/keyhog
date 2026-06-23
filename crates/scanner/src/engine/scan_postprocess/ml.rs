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
            let checksum_ctx = crate::adjudicate::MatchCtx::for_process_signals(
                crate::adjudicate::ProcessCandidateSignals::from_checksum_invalid(true),
            );
            crate::adjudicate::record_suppression(
                pending.raw_match.location.file_path.as_deref(),
                &pending.credential,
                &checksum_ctx,
            );
            return;
        };
        final_score = adjusted_score;
        let final_emit_ctx =
            crate::adjudicate::MatchCtx::for_final_emit(crate::adjudicate::FinalEmitSignals::new(
                pending.raw_match.detector_id.as_ref(),
                pending.code_context,
                final_score,
                pending.min_confidence_floor,
                self.config.penalize_test_paths,
            ));
        if crate::adjudicate::record_suppression(
            pending.raw_match.location.file_path.as_deref(),
            &pending.credential,
            &final_emit_ctx,
        )
        .is_some()
        {
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

        let tuning = self.tuning.resolve();
        let scores = crate::gpu::batch_ml_inference_with_timeout(
            &candidates,
            &self.config,
            tuning.gpu_moe_timeout(),
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
            let final_score =
                super::scoring::ml_pending_confidence(super::scoring::MlConfidencePolicy {
                    heuristic_confidence: pending.heuristic_conf,
                    model_confidence: ml_conf,
                    ml_weight: self.config.ml_weight,
                    model_authoritative: pending.model_authoritative,
                    code_context: pending.code_context,
                    scan_comments: self.config.scan_comments,
                    penalize_test_paths: self.config.penalize_test_paths,
                });

            self.emit_finalized_pending_match(scan_state, pending, final_score);
        }
    }
}
