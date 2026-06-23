//! Shared detector-catalog validation helpers for scanner Tier-B rule files.

use std::collections::HashSet;
use std::sync::OnceLock;

pub(crate) fn bundled_detector_ids() -> Result<&'static HashSet<String>, String> {
    static DETECTOR_IDS: OnceLock<Result<HashSet<String>, String>> = OnceLock::new();
    DETECTOR_IDS
        .get_or_init(|| {
            keyhog_core::load_embedded_detectors_or_fail()
                .map(|detectors| {
                    detectors
                        .into_iter()
                        .map(|detector| detector.id)
                        .collect::<HashSet<_>>()
                })
                .map_err(|error| format!("failed to validate detector rule ids: {error}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub(crate) fn validate_rule_detector_ids<'a>(
    rule_name: &str,
    detector_ids: impl IntoIterator<Item = &'a str>,
    valid_detector_ids: &HashSet<String>,
) -> Result<(), String> {
    for detector_id in detector_ids {
        if !valid_detector_ids.contains(detector_id) {
            return Err(format!(
                "{rule_name} references unknown detector '{detector_id}'"
            ));
        }
    }
    Ok(())
}
