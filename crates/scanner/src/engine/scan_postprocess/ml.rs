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
        report_conf: f64,
    ) {
        let detector_id = pending.raw_match.detector_id.clone();
        let file_path = pending.raw_match.location.file_path.clone();
        let Some(raw_match) = crate::adjudicate::finalize_report_raw_match(
            pending.raw_match,
            crate::adjudicate::ReportAdjudicationPolicy {
                detector_id: detector_id.as_ref(),
                code_context: pending.code_context,
                confidence: report_conf,
                min_confidence_floor: pending.min_confidence_floor,
                penalize_test_paths: self.config.penalize_test_paths,
                file_path: file_path.as_deref(),
                is_named_detector: pending.is_named_detector,
                allow_encoded_text_lift: false,
                calibration: self.config.calibration.as_deref(),
            },
        ) else {
            return;
        };
        scan_state.push_match(raw_match, self.config.max_matches_per_chunk);
    }

    pub(crate) fn apply_ml_batch_scores(&self, scan_state: &mut ScanState) {
        if scan_postprocess_profile::ml_batch_prof_enabled() {
            scan_postprocess_profile::ml_batch_record(scan_state.ml_pending.len());
        }
        if scan_state.ml_pending.is_empty() {
            return;
        }

        if !self.config.ml_enabled {
            let pending = scan_state.ml_pending.len();
            tracing::error!(
                pending,
                "internal invariant violation: ML pending queue populated while ML is disabled; dropping pending ML matches instead of silently using heuristic fallback"
            );
            scan_state.ml_pending.clear();
            return;
        }

        let candidates = crate::ml_scorer::pending_match_score_inputs(&scan_state.ml_pending);

        let tuning = self.tuning.resolve();
        let scores = crate::gpu::batch_ml_inference_with_timeout(
            &candidates,
            &self.config,
            tuning.gpu_moe_timeout(),
        );
        let pending_matches: Vec<_> = scan_state.ml_pending.drain(..).collect();
        let scores = crate::ml_scorer::complete_pending_match_scores_with_config(
            scores,
            &pending_matches,
            &self.config.known_prefixes,
            &self.config.secret_keywords,
            &self.config.test_keywords,
            &self.config.placeholder_keywords,
        );
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores.into_iter()) {
            let report_conf = crate::confidence::policy::ml_pending_match_confidence(
                &pending,
                ml_conf,
                self.config.ml_weight,
                self.config.scan_comments,
                self.config.penalize_test_paths,
            );

            self.emit_finalized_pending_match(scan_state, pending, report_conf);
        }
    }
}
