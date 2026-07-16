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
                is_generic_detector: pending.is_generic_detector,
                allow_encoded_text_lift: pending.allow_encoded_text_lift,
                allow_canonical_hex_key: pending.allow_canonical_hex_key,
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
            panic!(
                "internal invariant violation: ML pending queue populated while ML is disabled; pending={pending}"
            );
        }

        let tuning = self.tuning.resolve();
        let pending_matches = std::mem::take(&mut scan_state.ml_pending);
        let scores = crate::gpu::batch_ml_inference_with_timeout(
            &pending_matches,
            &self.config,
            tuning.gpu_moe_timeout(),
        );
        let scores = crate::ml_scorer::complete_batch_scores_with_config(
            scores,
            &pending_matches,
            &self.config,
        );
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores.into_iter()) {
            let report_conf = crate::confidence::policy::ml_pending_match_confidence(
                &pending,
                ml_conf,
                self.config.scan_comments,
                self.config.penalize_test_paths,
            );
            self.emit_finalized_pending_match(scan_state, pending, report_conf);
        }
    }
}
