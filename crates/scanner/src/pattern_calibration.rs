//! Pattern-conditioned permission for model-driven confidence reduction.

use std::sync::LazyLock;

use crate::candidate_provenance::CandidateChannel;
use crate::pattern_calibration_contract::{entry_key, metrics_meet_floors, PatternCalibration};
use crate::types::MlPendingMatch;

const EMBEDDED_ARTIFACT: &str = include_str!("pattern_calibration.json");

static CALIBRATION: LazyLock<Result<PatternCalibration, String>> =
    LazyLock::new(|| PatternCalibration::parse(EMBEDDED_ARTIFACT));

impl PatternCalibration {
    fn allows_lowering(&self, detector_digest: u64, pending: &MlPendingMatch) -> bool {
        if self.detector_digest != Some(detector_digest)
            || self.model_version != crate::ml_scorer::model_version()
        {
            return false;
        }
        let provenance = pending.pending_raw_match.provenance;
        let Some(pattern) = provenance.pattern() else {
            return false;
        };
        if !matches!(provenance.channel(), CandidateChannel::NamedPattern) {
            return false;
        }
        let detector_id =
            crate::detector_ids::policy_detector_id(pending.pending_raw_match.detector_id.as_ref());
        let key = (
            detector_id,
            pattern.pattern_index,
            "pattern",
            provenance.source_role().as_str(),
            provenance.context_class().as_str(),
        );
        let Ok(index) = self
            .entries
            .binary_search_by(|entry| entry_key(entry).cmp(&key))
        else {
            return false;
        };
        metrics_meet_floors(self.entries[index].metrics, self.floors)
    }
}

pub(crate) fn allows_model_lowering(detector_digest: u64, pending: &MlPendingMatch) -> bool {
    CALIBRATION
        .as_ref()
        .is_ok_and(|calibration| calibration.allows_lowering(detector_digest, pending))
}

pub(crate) fn evaluate_artifact_key(
    raw: &str,
    detector_digest: u64,
    detector_id: &str,
    pattern_index: u32,
    candidate_channel: &str,
    source_role: &str,
    context_class: &str,
) -> Result<bool, String> {
    let calibration = PatternCalibration::parse(raw)?;
    if calibration.detector_digest != Some(detector_digest)
        || calibration.model_version != crate::ml_scorer::model_version()
        || candidate_channel != "pattern"
    {
        return Ok(false);
    }
    let detector_id = crate::detector_ids::policy_detector_id(detector_id);
    let key = (
        detector_id,
        pattern_index,
        candidate_channel,
        source_role,
        context_class,
    );
    Ok(calibration
        .entries
        .binary_search_by(|entry| entry_key(entry).cmp(&key))
        .ok()
        .is_some_and(|index| {
            metrics_meet_floors(calibration.entries[index].metrics, calibration.floors)
        }))
}
