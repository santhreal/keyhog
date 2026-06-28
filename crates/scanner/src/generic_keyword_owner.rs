//! Named-detector ownership for generic assignment-key anchors.
//!
//! The generic `KEY=value` bridge is intentionally broad for unknown vendor
//! keys, but it must not second-guess service-specific assignment names already
//! owned by loaded named detectors (`segment_write_key`, `aws_secret_access_key`,
//! etc.). This module precomputes that owned-key set once during scanner build.

use crate::detector_ids::is_generic_detector;
use crate::engine::phase2_generic::keywords::{
    normalize_assignment_keyword, normalized_assignment_keyword_has_secret_suffix,
};
use keyhog_core::DetectorSpec;
use std::collections::BTreeSet;
use std::sync::Arc;

/// Minimum normalized service-name length for a named detector to contribute
/// owned assignment keywords. Two-character service markers (`ci`, `db`, `io`)
/// are too generic to safely claim ownership of a `KEY=value` anchor, so they
/// are skipped rather than suppressing the broad generic bridge.
const MIN_SERVICE_NAME_LEN: usize = 3;

pub(crate) fn build_generic_named_assignment_keywords(detectors: &[DetectorSpec]) -> Vec<Arc<str>> {
    let mut owned = BTreeSet::<String>::new();
    for detector in detectors {
        if is_generic_detector(&detector.id) || detector.service == "generic" {
            continue;
        }
        let Some(service) = normalize_assignment_keyword(&detector.service) else {
            continue;
        };
        if service.len() < MIN_SERVICE_NAME_LEN {
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

pub(crate) fn assignment_keyword_owned_by_named_detector(
    owned_keywords: &[Arc<str>],
    keyword: &str,
) -> bool {
    if owned_keywords.is_empty() {
        return false;
    }
    let Some(normalized) = normalize_assignment_keyword(keyword) else {
        return false;
    };
    if !normalized_assignment_keyword_has_secret_suffix(&normalized) {
        return false;
    }
    normalized_assignment_keyword_owned_by_named_detector(owned_keywords, &normalized)
}

pub(crate) fn line_assignment_owned_by_named_detector(
    owned_keywords: &[Arc<str>],
    line: &str,
) -> bool {
    if owned_keywords.is_empty() {
        return false;
    }
    crate::entropy::keywords::assignment_keyword_for_line(line)
        .as_deref()
        .is_some_and(|normalized| {
            normalized_assignment_keyword_owned_by_named_detector(owned_keywords, normalized)
        })
}

pub(crate) fn candidate_embeds_owned_assignment_key(
    owned_keywords: &[Arc<str>],
    candidate: &str,
) -> bool {
    if owned_keywords.is_empty() {
        return false;
    }
    let Some(key) = leading_assignment_key(candidate) else {
        return candidate_starts_with_owned_assignment_key(owned_keywords, candidate);
    };
    assignment_keyword_owned_by_named_detector(owned_keywords, key)
        || candidate_starts_with_owned_assignment_key(owned_keywords, candidate)
}

pub(crate) fn entropy_candidate_owned_by_named_assignment(
    owned_keywords: &[Arc<str>],
    candidate: &str,
    same_line: Option<&str>,
) -> bool {
    candidate_embeds_owned_assignment_key(owned_keywords, candidate)
        || same_line
            .is_some_and(|line| line_assignment_owned_by_named_detector(owned_keywords, line))
}

pub(crate) fn keyword_span_owned_by_named_detector(
    owned_keywords: &[Arc<str>],
    line: &str,
    keyword_start: usize,
    keyword_end: usize,
) -> bool {
    if keyword_start > keyword_end || keyword_end > line.len() {
        return false;
    }
    if assignment_keyword_owned_by_named_detector(owned_keywords, &line[keyword_start..keyword_end])
    {
        return true;
    }
    let bytes = line.as_bytes();
    let mut start = keyword_start;
    while start > 0 && is_assignment_key_byte(bytes[start - 1]) {
        start -= 1;
    }
    let mut end = keyword_end;
    while end < bytes.len() && is_assignment_key_byte(bytes[end]) {
        end += 1;
    }
    (start != keyword_start || end != keyword_end)
        && assignment_keyword_owned_by_named_detector(owned_keywords, &line[start..end])
}

fn normalized_assignment_keyword_owned_by_named_detector(
    owned_keywords: &[Arc<str>],
    normalized: &str,
) -> bool {
    owned_keywords
        .binary_search_by(|owned| owned.as_ref().cmp(normalized))
        .is_ok()
}

fn leading_assignment_key(candidate: &str) -> Option<&str> {
    let bytes = candidate.as_bytes();
    let mut end = 0usize;
    while end < bytes.len() && is_assignment_key_byte(bytes[end]) {
        end += 1;
    }
    if end == 0 || end == bytes.len() {
        return None;
    }
    matches!(bytes[end], b'=' | b':' | b'~').then_some(&candidate[..end])
}

fn candidate_starts_with_owned_assignment_key(
    owned_keywords: &[Arc<str>],
    candidate: &str,
) -> bool {
    let Some(normalized) = normalize_assignment_keyword(candidate) else {
        return false;
    };
    owned_keywords.iter().any(|owned| {
        normalized.len() > owned.len()
            && normalized.starts_with(owned.as_ref())
            && normalized_assignment_keyword_has_secret_suffix(owned.as_ref())
    })
}

fn is_assignment_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}
