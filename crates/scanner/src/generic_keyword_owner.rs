//! Named-detector ownership for generic assignment-key anchors.
//!
//! The generic `KEY=value` bridge is intentionally broad for unknown vendor
//! keys, but it must not second-guess service-specific assignment names already
//! owned by loaded named detectors (`segment_write_key`, `aws_secret_access_key`,
//! etc.). This module precomputes that owned-key set once during scanner build.

use crate::engine::phase2_generic::keywords::{
    normalize_assignment_keyword, normalized_assignment_keyword_has_secret_suffix,
};
use keyhog_core::{DetectorKind, DetectorSpec};
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;

/// Compiled generic-assignment keyword → owning generic `Phase2Generic`
/// detector index. Replaces the per-candidate linear
/// `detectors.iter().find(...)` scan (O(detectors × keywords) for EVERY generic
/// value-shape candidate, the hot generic path) in `phase2_generic` with an
/// O(1) lookup, built ONCE at scanner construction (Tier: compiled).
///
/// Exact and normalized assignment keys resolve through the same detector-owned
/// priority table used by entropy policy. Phase-2 generic detectors participate
/// by default, regex detectors opt in through `entropy_policy_priority`, and the
/// highest priority wins an overlap. Stable detector identity breaks an
/// equal-priority tie. Structural vendor suffixes use the one detector that
/// declares a non-empty `generic_vendor_suffixes` list.
#[derive(Debug, Default)]
pub(crate) struct GenericOwningDetectorIndex {
    policy_exact: HashMap<String, PolicyOwner>,
    policy_normalized: HashMap<String, PolicyOwner>,
    policy_keywords: Vec<String>,
    canonical_exact: HashMap<String, usize>,
    canonical_normalized: HashMap<String, usize>,
    stable_rank: Box<[usize]>,
    keyword_free_owner_index: Option<usize>,
    isolated_bare_owner_index: Option<usize>,
    unclaimed_keyword_owner_index: Option<usize>,
    vendor_suffix_fallback_index: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
struct PolicyOwner {
    index: usize,
    priority: u16,
    stable_rank: usize,
}

/// Generic assignment ownership resolved from one lowercase/normalized key
/// pass. The hot bridge needs both ordinary entropy ownership and the optional
/// canonical-hex override; resolving them together avoids normalizing the same
/// captured LHS twice.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GenericDetectorResolution {
    pub(crate) owning_index: usize,
    pub(crate) canonical_index: usize,
}

fn insert_policy_owner(
    owners: &mut HashMap<String, PolicyOwner>,
    keyword: String,
    candidate: PolicyOwner,
) {
    owners
        .entry(keyword)
        .and_modify(|current| {
            if policy_owner_precedes(candidate, *current) {
                *current = candidate;
            }
        })
        .or_insert(candidate);
}

fn policy_owner_precedes(candidate: PolicyOwner, current: PolicyOwner) -> bool {
    candidate.priority > current.priority
        || (candidate.priority == current.priority && candidate.stable_rank < current.stable_rank)
}

fn insert_stable_index(
    owners: &mut HashMap<String, usize>,
    keyword: String,
    candidate: usize,
    stable_rank: &[usize],
) {
    owners
        .entry(keyword)
        .and_modify(|current| {
            if stable_rank[candidate] < stable_rank[*current] {
                *current = candidate;
            }
        })
        .or_insert(candidate);
}

impl GenericOwningDetectorIndex {
    pub(crate) fn build(detectors: &[DetectorSpec]) -> Result<Self, String> {
        let mut stable_order: Vec<usize> = (0..detectors.len()).collect();
        stable_order.sort_unstable_by(|left, right| {
            detectors[*left]
                .id
                .cmp(&detectors[*right].id)
                .then_with(|| left.cmp(right))
        });
        let mut stable_rank = vec![0usize; detectors.len()];
        for (rank, index) in stable_order.into_iter().enumerate() {
            stable_rank[index] = rank;
        }
        let mut policy_exact = HashMap::new();
        let mut policy_normalized = HashMap::new();
        let mut policy_keywords = BTreeSet::new();
        let mut canonical_exact = HashMap::new();
        let mut canonical_normalized = HashMap::new();
        let mut keyword_free_owner_index: Option<usize> = None;
        let mut isolated_bare_owner_index: Option<usize> = None;
        let mut unclaimed_keyword_owner_index: Option<usize> = None;
        let mut vendor_suffix_fallback_index: Option<usize> = None;
        for (index, detector) in detectors.iter().enumerate() {
            for role in &detector.entropy_roles {
                let slot = match role {
                    keyhog_core::EntropyDetectionRole::KeywordFree => &mut keyword_free_owner_index,
                    keyhog_core::EntropyDetectionRole::IsolatedBare => {
                        &mut isolated_bare_owner_index
                    }
                    keyhog_core::EntropyDetectionRole::UnclaimedKeyword => {
                        &mut unclaimed_keyword_owner_index
                    }
                };
                if let Some(previous) = *slot {
                    return Err(format!(
                        "entropy role {:?} is claimed by both {:?} and {:?}; each role must have exactly one detector TOML owner",
                        role.as_str(), detectors[previous].id, detector.id
                    ));
                }
                *slot = Some(index);
            }
            if !detector.generic_vendor_suffixes.is_empty() {
                if let Some(previous) = vendor_suffix_fallback_index {
                    return Err(format!(
                        "generic vendor suffixes are claimed by both {:?} and {:?}; exactly one detector TOML may own them",
                        detectors[previous].id, detector.id
                    ));
                }
                vendor_suffix_fallback_index = Some(index);
            }
            // Phase-2 generic detectors own their entropy keywords by default.
            // Regex detectors opt in with an explicit TOML priority. Overlap
            // resolution uses that priority as its primary ordering.
            if detector.kind == DetectorKind::Phase2Generic
                || detector.entropy_policy_priority.is_some()
            {
                let owner = PolicyOwner {
                    index,
                    priority: match detector.entropy_policy_priority {
                        Some(priority) => priority,
                        None => 0,
                    },
                    stable_rank: stable_rank[index],
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
            // Canonical pure-hex ownership is independent of broad entropy
            // priority. A detector that declares an exact canonical keyword
            // owns that shape even when a broader keyword detector wins the
            // ordinary low-entropy policy for the same assignment.
            if detector.kind == DetectorKind::Phase2Generic
                && !detector.canonical_hex_key_material.is_empty()
            {
                for policy in &detector.canonical_hex_key_material {
                    for keyword in &policy.keywords {
                        let kw_lower = keyword.to_ascii_lowercase();
                        insert_stable_index(&mut canonical_exact, kw_lower, index, &stable_rank);
                        if let Some(normalized) = normalize_assignment_keyword(keyword) {
                            insert_stable_index(
                                &mut canonical_normalized,
                                normalized,
                                index,
                                &stable_rank,
                            );
                        }
                    }
                }
            }
        }
        Ok(Self {
            policy_exact,
            policy_normalized,
            policy_keywords: policy_keywords.into_iter().collect(),
            canonical_exact,
            canonical_normalized,
            stable_rank: stable_rank.into_boxed_slice(),
            keyword_free_owner_index,
            isolated_bare_owner_index,
            unclaimed_keyword_owner_index,
            vendor_suffix_fallback_index,
        })
    }

    /// Resolve ordinary and canonical policy owners with one key
    /// normalization. Ordinary ownership includes the detector-declared vendor
    /// suffix fallback. `None` means no detector owns the generic assignment.
    pub(crate) fn resolve(&self, keyword: &str) -> Option<GenericDetectorResolution> {
        let kw_lower = keyword.to_ascii_lowercase();
        let normalized = normalize_assignment_keyword(&kw_lower);
        let owning_index = self
            .claimed_policy_index_from(&kw_lower, normalized.as_deref())
            .or(self.vendor_suffix_fallback_index)?;
        let canonical_index = self
            .canonical_index_from(&kw_lower, normalized.as_deref())
            // LAW10: canonical default; no canonical-hex override leaves the already-resolved entropy owner authoritative.
            .unwrap_or(owning_index);
        Some(GenericDetectorResolution {
            owning_index,
            canonical_index,
        })
    }

    /// Generic detector that explicitly claims `keyword`, without applying the
    /// broad generic-secret fallback. Context discovery uses this distinction:
    /// an explicit detector keyword is positive credential evidence, while an
    /// arbitrary assignment that only reaches the fallback is not.
    pub(crate) fn claimed_policy_index(&self, keyword: &str) -> Option<usize> {
        let kw_lower = keyword.to_ascii_lowercase();
        let normalized = normalize_assignment_keyword(&kw_lower);
        self.claimed_policy_index_from(&kw_lower, normalized.as_deref())
    }

    fn claimed_policy_index_from(&self, lower: &str, normalized: Option<&str>) -> Option<usize> {
        let exact_hit = self.policy_exact.get(lower).copied();
        let norm_hit = normalized.and_then(|norm| self.policy_normalized.get(norm).copied());
        match (exact_hit, norm_hit) {
            (Some(a), Some(b)) => Some(if policy_owner_precedes(a, b) { a } else { b }.index),
            (a, b) => a.or(b).map(|owner| owner.index),
        }
    }

    /// Lowercased keyword vocabulary contributed by active generic-policy
    /// owners. Entropy and multiline admission consume it alongside Tier-A scan
    /// keywords, so a custom owner does not duplicate anchors in scanner config.
    pub(crate) fn policy_keywords(&self) -> &[String] {
        &self.policy_keywords
    }

    /// Detector index that declares canonical pure-hex policy for an exact or
    /// normalized assignment keyword. Suffix-only policies intentionally do
    /// not claim arbitrary names here; callers fall back to their ordinary
    /// generic owner for vendor-prefixed assignments.
    pub(crate) fn canonical_index(&self, keyword: &str) -> Option<usize> {
        let kw_lower = keyword.to_ascii_lowercase();
        let normalized = normalize_assignment_keyword(&kw_lower);
        self.canonical_index_from(&kw_lower, normalized.as_deref())
    }

    fn canonical_index_from(&self, lower: &str, normalized: Option<&str>) -> Option<usize> {
        let exact = self.canonical_exact.get(lower).copied();
        let normalized = normalized.and_then(|key| self.canonical_normalized.get(key).copied());
        match (exact, normalized) {
            (Some(left), Some(right)) => {
                Some(if self.stable_rank[left] <= self.stable_rank[right] {
                    left
                } else {
                    right
                })
            }
            (left, right) => left.or(right),
        }
    }

    /// Detector that explicitly owns anchor-free entropy candidates.
    pub(crate) fn keyword_free_owner_index(&self) -> Option<usize> {
        self.keyword_free_owner_index
    }

    /// Detector that explicitly owns isolated bare entropy candidates.
    #[inline]
    pub(crate) fn isolated_bare_owner_index(&self) -> Option<usize> {
        self.isolated_bare_owner_index
    }

    /// Detector that explicitly owns otherwise-unclaimed credential keywords.
    #[inline]
    pub(crate) fn unclaimed_keyword_owner_index(&self) -> Option<usize> {
        self.unclaimed_keyword_owner_index
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
        if detector.kind == DetectorKind::Phase2Generic {
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
