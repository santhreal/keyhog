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
use keyhog_core::{DetectorKind, DetectorSpec};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Compiled generic-assignment keyword → owning generic `Phase2Generic`
/// detector index. Replaces the per-candidate linear
/// `detectors.iter().find(...)` scan (O(detectors × keywords) for EVERY generic
/// value-shape candidate, the hot generic path) in `phase2_generic` with an
/// O(1) lookup, built ONCE at scanner construction (Tier: compiled).
///
/// Two maps preserve the EXACT original semantics: "the first detector, in
/// spec order, that matches the keyword by exact-lowercase OR by
/// `normalize_assignment_keyword` equivalence": `exact` keys the raw lowercased
/// keyword, `normalized` keys its normalized form, each recording the FIRST
/// (smallest) detector index for that key (insertion in ascending spec order +
/// `or_insert` gives first-wins). A query returns the smaller of the two hits,
/// so the earliest detector wins across BOTH conditions exactly as the linear
/// `find` did. `generic_secret_index` is the cached `GENERIC_SECRET` fallback
/// (formerly a second linear `find`).
///
/// Entropy policy uses separate maps. Phase-2 generic detectors participate by
/// default, regex detectors opt in through `entropy_policy_priority`, and the
/// highest declared priority wins an overlap. Compiled order breaks an equal
/// priority tie deterministically. This keeps candidate-emitter compatibility
/// separate from explicit entropy-policy ownership.
#[derive(Debug, Default)]
pub(crate) struct GenericOwningDetectorIndex {
    exact: HashMap<String, usize>,
    normalized: HashMap<String, usize>,
    policy_exact: HashMap<String, PolicyOwner>,
    policy_normalized: HashMap<String, PolicyOwner>,
    policy_keywords: Vec<String>,
    by_id: HashMap<String, usize>,
    generic_secret_index: Option<usize>,
    generic_keyword_secret_index: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct PolicyOwner {
    index: usize,
    priority: u16,
}

fn insert_policy_owner(
    owners: &mut HashMap<String, PolicyOwner>,
    keyword: String,
    candidate: PolicyOwner,
) {
    owners
        .entry(keyword)
        .and_modify(|current| {
            if candidate.priority > current.priority
                || (candidate.priority == current.priority && candidate.index < current.index)
            {
                *current = candidate;
            }
        })
        .or_insert(candidate);
}

impl GenericOwningDetectorIndex {
    pub(crate) fn build(detectors: &[DetectorSpec]) -> Self {
        let mut exact = HashMap::new();
        let mut normalized = HashMap::new();
        let mut policy_exact = HashMap::new();
        let mut policy_normalized = HashMap::new();
        let mut policy_keywords = BTreeSet::new();
        let mut by_id = HashMap::new();
        let mut generic_secret_index = None;
        let mut generic_keyword_secret_index = None;
        for (index, detector) in detectors.iter().enumerate() {
            if generic_secret_index.is_none() && detector.id == crate::detector_ids::GENERIC_SECRET
            {
                generic_secret_index = Some(index);
            }
            if generic_keyword_secret_index.is_none()
                && detector.id == crate::detector_ids::GENERIC_KEYWORD_SECRET
            {
                generic_keyword_secret_index = Some(index);
            }
            if detector.service == "generic" {
                by_id.entry(detector.id.clone()).or_insert(index);
            }
            // Phase-2 generic detectors own their entropy keywords by default.
            // Regex detectors opt in with an explicit TOML priority. Overlap
            // resolution uses that priority as its primary ordering.
            if detector.service == "generic"
                && (detector.kind == DetectorKind::Phase2Generic
                    || detector.entropy_policy_priority.is_some())
            {
                let owner = PolicyOwner {
                    index,
                    priority: detector.entropy_policy_priority.unwrap_or(0),
                };
                for keyword in &detector.keywords {
                    let kw_lower = keyword.to_ascii_lowercase();
                    policy_keywords.insert(kw_lower.clone());
                    if let Some(norm) = normalize_assignment_keyword(&kw_lower) {
                        insert_policy_owner(&mut policy_normalized, norm, owner);
                    }
                    insert_policy_owner(&mut policy_exact, kw_lower, owner);
                }
            }
            if detector.service != "generic" || detector.kind != DetectorKind::Phase2Generic {
                continue;
            }
            for keyword in &detector.keywords {
                let kw_lower = keyword.to_ascii_lowercase();
                if let Some(norm) = normalize_assignment_keyword(&kw_lower) {
                    normalized.entry(norm).or_insert(index);
                }
                exact.entry(kw_lower).or_insert(index);
            }
        }
        Self {
            exact,
            normalized,
            policy_exact,
            policy_normalized,
            policy_keywords: policy_keywords.into_iter().collect(),
            by_id,
            generic_secret_index,
            generic_keyword_secret_index,
        }
    }

    /// The owning generic detector's index for a matched assignment `keyword`
    /// (need not be pre-lowercased), or the `GENERIC_SECRET` fallback index when
    /// no generic detector claims the keyword. `None` only when neither a
    /// keyword owner nor a `GENERIC_SECRET` detector is loaded, the caller then
    /// applies its literal defaults, identical to the old `find(...).or_else(..)`
    /// returning `None`.
    pub(crate) fn owning_index(&self, keyword: &str) -> Option<usize> {
        let kw_lower = keyword.to_ascii_lowercase();
        let exact_hit = self.exact.get(&kw_lower).copied();
        let norm_hit = normalize_assignment_keyword(&kw_lower)
            .and_then(|norm| self.normalized.get(&norm).copied());
        let keyword_owner = match (exact_hit, norm_hit) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        keyword_owner.or(self.generic_secret_index)
    }

    /// Generic detector that explicitly claims `keyword`, without applying the
    /// broad generic-secret fallback. Context discovery uses this distinction:
    /// an explicit detector keyword is positive credential evidence, while an
    /// arbitrary assignment that only reaches the fallback is not.
    pub(crate) fn claimed_policy_index(&self, keyword: &str) -> Option<usize> {
        let kw_lower = keyword.to_ascii_lowercase();
        let exact_hit = self.policy_exact.get(&kw_lower).copied();
        let norm_hit = normalize_assignment_keyword(&kw_lower)
            .and_then(|norm| self.policy_normalized.get(&norm).copied());
        match (exact_hit, norm_hit) {
            (Some(a), Some(b)) => Some(
                if a.priority > b.priority || (a.priority == b.priority && a.index < b.index) {
                    a
                } else {
                    b
                }
                .index,
            ),
            (a, b) => a.or(b).map(|owner| owner.index),
        }
    }

    /// Lowercased keyword vocabulary contributed by active entropy-policy
    /// owners. The entropy line finder consumes this alongside Tier-A scan
    /// keywords so a custom detector TOML works without duplicating its anchor
    /// in scanner configuration.
    pub(crate) fn policy_keywords(&self) -> &[String] {
        &self.policy_keywords
    }

    /// Index of the loaded `GENERIC_SECRET` detector, if any. This is the ONE
    /// cached location every generic-secret lookup resolves through, both the
    /// owning-detector fallback above and `generic_secret_shape_floors` used to
    /// run their own separate linear `detectors.iter().find(id == GENERIC_SECRET)`.
    pub(crate) fn generic_secret_index(&self) -> Option<usize> {
        self.generic_secret_index
    }

    #[inline]
    pub(crate) fn generic_keyword_secret_index(&self) -> Option<usize> {
        self.generic_keyword_secret_index
    }

    /// Index of an active generic policy detector by its stable id. Synthetic
    /// entropy findings use this to resolve BPE and confidence policy from the
    /// corpus that actually compiled, rather than the embedded registry.
    pub(crate) fn index_for_id(&self, detector_id: &str) -> Option<usize> {
        self.by_id.get(detector_id).copied()
    }
}

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

pub(crate) fn normalized_assignment_keyword_owned_by_named_detector(
    owned_keywords: &[Arc<str>],
    normalized: &str,
) -> bool {
    owned_keywords
        .binary_search_by(|owned| owned.as_ref().cmp(normalized))
        .is_ok()
}

pub(crate) fn leading_assignment_key(candidate: &str) -> Option<&str> {
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

pub(crate) fn candidate_starts_with_owned_assignment_key(
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


#[cfg(test)]
#[path = "../tests/unit/generic_keyword_owner.rs"]
mod tests;
