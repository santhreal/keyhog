//! Named-detector ownership for generic assignment-key anchors.
//!
//! The generic `KEY=value` bridge is intentionally broad for unknown vendor
//! keys, but it must not second-guess service-specific assignment names already
//! owned by loaded named detectors (`segment_write_key`, `aws_secret_access_key`,
//! etc.). This module precomputes that owned-key set once during scanner build.

use super::phase2_generic::keywords::{
    normalize_assignment_keyword, normalized_assignment_keyword_has_secret_suffix,
};
use crate::detector_ids::is_generic_detector;
use keyhog_core::DetectorSpec;
use std::collections::BTreeSet;
use std::sync::Arc;

pub(crate) fn build_generic_named_assignment_keywords(detectors: &[DetectorSpec]) -> Vec<Arc<str>> {
    let mut owned = BTreeSet::<String>::new();
    for detector in detectors {
        if is_generic_detector(&detector.id) || detector.service == "generic" {
            continue;
        }
        let Some(service) = normalize_assignment_keyword(&detector.service) else {
            continue;
        };
        if service.len() < 3 {
            continue;
        }
        for keyword in &detector.keywords {
            let Some(normalized) = normalize_assignment_keyword(keyword) else {
                continue;
            };
            if !normalized_assignment_keyword_has_secret_suffix(&normalized) {
                continue;
            }
            if normalized.contains(service.as_str()) {
                owned.insert(normalized);
            }
        }
    }
    owned.into_iter().map(Arc::from).collect()
}
