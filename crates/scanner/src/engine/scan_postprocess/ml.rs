//! ML pending-match scoring for the postprocess tail.
//!
//! This owns the feature-gated MoE/CPU score blend for matches queued by
//! detector, generic, and entropy paths. The non-ML postprocess owner should not
//! also carry model scoring policy.

use super::{scan_postprocess_profile, CompiledScanner};
use crate::types::{MlPendingMatch, ScanState};

fn finalize_pending_match(
    config: &crate::types::ScannerConfig,
    pending: MlPendingMatch,
    report_conf: f64,
) -> Option<crate::scan_state::AttributedRawMatch> {
    let payload = &pending.pending_raw_match;
    let final_confidence = crate::adjudicate::finalize_report_candidate(
        payload.location.file_path.as_deref(),
        payload.credential.as_ref(),
        crate::adjudicate::ReportAdjudicationPolicy {
            detector_id: payload.detector_id.as_ref(),
            code_context: pending.code_context,
            confidence: report_conf,
            min_confidence_floor: pending.min_confidence_floor,
            penalize_test_paths: config.penalize_test_paths,
            context_suppression_threshold: pending.context_suppression_threshold,
            post_match: pending.post_match,
            file_path: payload.location.file_path.as_deref(),
            is_named_detector: pending.is_named_detector,
            is_generic_detector: pending.is_generic_detector,
            allow_encoded_text_lift: pending.allow_encoded_text_lift,
            allow_canonical_hex_key: pending.allow_canonical_hex_key,
            checksum: pending.checksum,
            calibration: config.calibration.as_deref(),
        },
    )?;
    Some(pending.pending_raw_match.materialize(final_confidence))
}

#[cfg(test)]
pub(crate) fn finalize_pending_match_for_test(
    config: &crate::types::ScannerConfig,
    pending: MlPendingMatch,
    report_conf: f64,
) -> Option<keyhog_core::RawMatch> {
    finalize_pending_match(config, pending, report_conf).map(|matched| matched.into_raw(0))
}

impl CompiledScanner {
    fn score_pending_batch(
        &self,
        pending_matches: &[MlPendingMatch],
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
    ) -> crate::Result<Vec<f64>> {
        #[cfg(feature = "gpu")]
        if backend.is_gpu() {
            if !self.quantized_confidence_authenticated {
                return Err(crate::ScanError::Gpu(format!(
                    "selected {} route lacks an authenticated quantized-confidence artifact binding. Fix: rebuild and recalibrate the execution pack for this exact model and backend",
                    backend.label()
                )));
            }
            let gpu_backend = self.gpu_backend(backend).ok_or_else(|| {
                crate::ScanError::Gpu(self.gpu_backend_unavailable_reason(backend))
            })?;
            let scores = crate::ml_scorer::score_input_batch_quantized_vyre(
                pending_matches,
                &self.config,
                gpu_backend.as_ref(),
                deadline,
            )?;
            return crate::ml_scorer::complete_batch_scores_with_config(
                scores,
                pending_matches,
                &self.config,
            );
        }
        if self.quantized_confidence_authenticated {
            let scores =
                crate::ml_scorer::score_input_batch_quantized_cpu(pending_matches, &self.config)?;
            return crate::ml_scorer::complete_batch_scores_with_config(
                scores,
                pending_matches,
                &self.config,
            );
        }
        #[cfg(not(feature = "gpu"))]
        let _ = backend;
        #[cfg(not(feature = "gpu"))]
        let _ = deadline;
        let scores = crate::ml_scorer::score_input_batch(pending_matches, &self.config);
        crate::ml_scorer::complete_batch_scores_with_config(scores, pending_matches, &self.config)
    }

    #[cfg(all(test, feature = "gpu"))]
    pub(crate) fn score_pending_batch_for_test(
        &self,
        pending_matches: &[MlPendingMatch],
        backend: crate::hw_probe::ScanBackend,
    ) -> crate::Result<Vec<f64>> {
        self.score_pending_batch(pending_matches, backend, None)
    }

    fn pending_report_confidence(&self, pending: &MlPendingMatch, ml_conf: f64) -> f64 {
        crate::confidence::policy::ml_pending_match_confidence(
            pending,
            ml_conf,
            self.config.scan_comments,
            self.config.penalize_test_paths,
            crate::pattern_calibration::allows_model_lowering(self.detector_digest, pending),
        )
    }

    fn emit_finalized_pending_match(
        &self,
        scan_state: &mut ScanState,
        pending: MlPendingMatch,
        report_conf: f64,
    ) {
        if let Some(attributed_match) = finalize_pending_match(&self.config, pending, report_conf) {
            scan_state.push_attributed_match(attributed_match, self.config.max_matches_per_chunk);
        }
    }

    pub(crate) fn apply_ml_batch_scores(
        &self,
        scan_state: &mut ScanState,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
    ) -> crate::Result<()> {
        scan_postprocess_profile::ml_batch_record(scan_state.ml_pending.len());
        if scan_state.ml_pending.is_empty() {
            return Ok(());
        }

        if !self.config.ml_enabled {
            return Err(crate::ScanError::Config(format!(
                "internal invariant violation: ML pending queue populated while ML is disabled; pending={}",
                scan_state.ml_pending.len()
            )));
        }

        let pending_matches = scan_state.take_ml_pending();
        let scores = self.score_pending_batch(&pending_matches, backend, deadline)?;
        for (pending, ml_conf) in pending_matches.into_iter().zip(scores.into_iter()) {
            let report_conf = self.pending_report_confidence(&pending, ml_conf);
            self.emit_finalized_pending_match(scan_state, pending, report_conf);
        }
        Ok(())
    }

    /// Score all pending candidates from one coalesced scan as a single model
    /// batch, then return each finalized finding to its originating chunk state.
    #[allow(dead_code)]
    pub(crate) fn apply_ml_batch_scores_across(
        &self,
        scan_states: &mut [ScanState],
        backend: crate::hw_probe::ScanBackend,
    ) -> crate::Result<()> {
        let total_pending: usize = scan_states.iter().map(|state| state.ml_pending.len()).sum();
        if total_pending == 0 {
            return Ok(());
        }
        if !self.config.ml_enabled {
            return Err(crate::ScanError::Config(format!(
                "internal invariant violation: coalesced ML pending queues populated while ML is disabled; pending={total_pending}"
            )));
        }
        scan_postprocess_profile::ml_batch_record(total_pending);

        let mut owner_counts = Vec::with_capacity(scan_states.len());
        let mut pending_matches = Vec::with_capacity(total_pending);
        for state in scan_states.iter_mut() {
            let pending = state.take_ml_pending();
            owner_counts.push(pending.len());
            pending_matches.extend(pending);
        }

        let scores = self.score_pending_batch(&pending_matches, backend, None)?;
        if scores.len() != total_pending {
            return Err(crate::ScanError::Config(format!(
                "internal invariant violation: coalesced ML scoring returned the wrong row count: expected {total_pending}, received {}",
                scores.len()
            )));
        }
        let mut scored = pending_matches.into_iter().zip(scores);
        for (owner_index, (scan_state, count)) in
            scan_states.iter_mut().zip(owner_counts).enumerate()
        {
            for _ in 0..count {
                let Some((pending, ml_conf)) = scored.next() else {
                    return Err(crate::ScanError::Config(format!(
                        "internal invariant violation: ML batch lost scores while restoring coalesced owner {owner_index}"
                    )));
                };
                let report_conf = self.pending_report_confidence(&pending, ml_conf);
                self.emit_finalized_pending_match(scan_state, pending, report_conf);
            }
        }
        if scored.next().is_some() {
            return Err(crate::ScanError::Config(
                "internal invariant violation: ML batch returned extra scores after restoring coalesced owners".to_string(),
            ));
        }
        Ok(())
    }
}
