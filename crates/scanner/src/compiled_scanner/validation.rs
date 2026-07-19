use keyhog_core::{DetectorSpec, QualityIssue};
use std::collections::{hash_map::Entry, HashMap};

const MAX_REPORTED_ERRORS: usize = 32;

pub(super) fn validate_detector_corpus(detectors: &[DetectorSpec]) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut first_index_by_id = HashMap::with_capacity(detectors.len());

    for (index, detector) in detectors.iter().enumerate() {
        match first_index_by_id.entry(detector.id.as_str()) {
            Entry::Occupied(first) => errors.push(format!(
                "detectors[{index}] duplicates id {:?} first declared at detectors[{}]",
                detector.id,
                first.get()
            )),
            Entry::Vacant(slot) => {
                slot.insert(index);
            }
        }

        for issue in keyhog_core::validate_detector(detector) {
            match issue {
                QualityIssue::Error(error) => {
                    errors.push(format!("detectors[{index}] {:?}: {error}", detector.id))
                }
                QualityIssue::Warning(warning) => tracing::debug!(
                    detector_index = index,
                    detector_id = %detector.id,
                    %warning,
                    "programmatic detector quality warning"
                ),
            }
        }
    }

    if errors.is_empty() {
        return Ok(());
    }

    let total = errors.len();
    errors.truncate(MAX_REPORTED_ERRORS);
    let mut detail = errors.join("; ");
    if total > MAX_REPORTED_ERRORS {
        detail.push_str(&format!(
            "; and {} more error(s)",
            total - MAX_REPORTED_ERRORS
        ));
    }
    Err(format!(
        "detector corpus quality gate rejected {total} error(s): {detail}. Fix the programmatic DetectorSpec values before compiling the scanner"
    ))
}
