//! ML pending-match scoring for the postprocess tail.
//!
//! This owns the feature-gated MoE/CPU score blend for matches queued by
//! detector, generic, and entropy paths. The non-ML postprocess owner should not
//! also carry model scoring policy.

use super::{scan_postprocess_profile, CompiledScanner};
use crate::types::{MlPendingMatch, ScanState};

impl CompiledScanner {
    fn score_pending_batch(&self, pending_matches: &[MlPendingMatch]) -> Vec<f64> {
        let tuning = self.tuning.resolve();
        let scores = crate::gpu::batch_ml_inference_with_timeout(
            pending_matches,
            &self.config,
            tuning.gpu_moe_timeout(),
        );
        crate::ml_scorer::complete_batch_scores_with_config(scores, pending_matches, &self.config)
    }

    fn pending_report_confidence(&self, pending: &MlPendingMatch, ml_conf: f64) -> f64 {
        crate::confidence::policy::ml_pending_match_confidence(
            pending,
            ml_conf,
            self.config.scan_comments,
            self.config.penalize_test_paths,
        )
    }

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
                context_suppression_threshold: pending.context_suppression_threshold,
                post_match: pending.post_match,
                file_path: file_path.as_deref(),
                is_named_detector: pending.is_named_detector,
                is_generic_detector: pending.is_generic_detector,
                allow_encoded_text_lift: pending.allow_encoded_text_lift,
                allow_canonical_hex_key: pending.allow_canonical_hex_key,
                checksum: pending.checksum,
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

        let pending_matches = scan_state.take_ml_pending();
        let scores = self.score_pending_batch(&pending_matches);
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores.into_iter()) {
            let report_conf = self.pending_report_confidence(&pending, ml_conf);
            self.emit_finalized_pending_match(scan_state, pending, report_conf);
        }
    }

    /// Score all pending candidates from one coalesced scan as a single model
    /// batch, then return each finalized finding to its originating chunk
    /// state. This is the production path that lets sparse per-file candidates
    /// reach GPU-sized batches without changing per-chunk caps or attribution.
    #[cfg(feature = "simd")]
    pub(crate) fn apply_ml_batch_scores_across(&self, scan_states: &mut [ScanState]) {
        let total_pending: usize = scan_states.iter().map(|state| state.ml_pending.len()).sum();
        if total_pending == 0 {
            return;
        }
        if !self.config.ml_enabled {
            panic!(
                "internal invariant violation: coalesced ML pending queues populated while ML is disabled; pending={total_pending}"
            );
        }
        if scan_postprocess_profile::ml_batch_prof_enabled() {
            scan_postprocess_profile::ml_batch_record(total_pending);
        }

        let mut owner_counts = Vec::with_capacity(scan_states.len());
        let mut pending_matches = Vec::with_capacity(total_pending);
        for state in scan_states.iter_mut() {
            let pending = state.take_ml_pending();
            owner_counts.push(pending.len());
            pending_matches.extend(pending);
        }

        let scores = self.score_pending_batch(&pending_matches);
        assert_eq!(
            scores.len(),
            total_pending,
            "internal invariant violation: coalesced ML scoring returned the wrong row count"
        );
        let mut scored = pending_matches.into_iter().zip(scores);
        for (owner_index, (scan_state, count)) in
            scan_states.iter_mut().zip(owner_counts).enumerate()
        {
            for _ in 0..count {
                let Some((pending, ml_conf)) = scored.next() else {
                    panic!(
                        "internal invariant violation: ML batch lost scores while restoring coalesced owner {owner_index}"
                    );
                };
                let report_conf = self.pending_report_confidence(&pending, ml_conf);
                self.emit_finalized_pending_match(scan_state, pending, report_conf);
            }
        }
        debug_assert!(scored.next().is_none());
    }
}
