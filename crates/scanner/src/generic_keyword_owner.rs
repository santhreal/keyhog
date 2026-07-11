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
/// value-shape candidate — the hot generic path) in `phase2_generic` with an
/// O(1) lookup, built ONCE at scanner construction (Tier: compiled).
///
/// Two maps preserve the EXACT original semantics — "the first detector, in
/// spec order, that matches the keyword by exact-lowercase OR by
/// `normalize_assignment_keyword` equivalence": `exact` keys the raw lowercased
/// keyword, `normalized` keys its normalized form, each recording the FIRST
/// (smallest) detector index for that key (insertion in ascending spec order +
/// `or_insert` gives first-wins). A query returns the smaller of the two hits,
/// so the earliest detector wins across BOTH conditions exactly as the linear
/// `find` did. `generic_secret_index` is the cached `GENERIC_SECRET` fallback
/// (formerly a second linear `find`).
#[derive(Debug, Default)]
pub(crate) struct GenericOwningDetectorIndex {
    exact: HashMap<String, usize>,
    normalized: HashMap<String, usize>,
    by_id: HashMap<String, usize>,
    generic_secret_index: Option<usize>,
}

impl GenericOwningDetectorIndex {
    pub(crate) fn build(detectors: &[DetectorSpec]) -> Self {
        let mut exact = HashMap::new();
        let mut normalized = HashMap::new();
        let mut by_id = HashMap::new();
        let mut generic_secret_index = None;
        for (index, detector) in detectors.iter().enumerate() {
            if generic_secret_index.is_none() && detector.id == crate::detector_ids::GENERIC_SECRET
            {
                generic_secret_index = Some(index);
            }
            if detector.service != "generic" || detector.kind != DetectorKind::Phase2Generic {
                continue;
            }
            by_id.entry(detector.id.clone()).or_insert(index);
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
            by_id,
            generic_secret_index,
        }
    }

    /// The owning generic detector's index for a matched assignment `keyword`
    /// (need not be pre-lowercased), or the `GENERIC_SECRET` fallback index when
    /// no generic detector claims the keyword. `None` only when neither a
    /// keyword owner nor a `GENERIC_SECRET` detector is loaded — the caller then
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

    /// Index of the loaded `GENERIC_SECRET` detector, if any. This is the ONE
    /// cached location every generic-secret lookup resolves through — both the
    /// owning-detector fallback above and `generic_secret_shape_floors` used to
    /// run their own separate linear `detectors.iter().find(id == GENERIC_SECRET)`.
    pub(crate) fn generic_secret_index(&self) -> Option<usize> {
        self.generic_secret_index
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
mod tests {
    use super::*;

    /// Callers pass SORTED keys — the real builder emits a `BTreeSet` and every
    /// ownership lookup `binary_search`es the slice.
    fn owned(keys: &[&str]) -> Vec<Arc<str>> {
        keys.iter().map(|k| Arc::from(*k)).collect()
    }

    #[test]
    fn leading_assignment_key_extracts_key_before_delimiter() {
        assert_eq!(leading_assignment_key("stripe_key=abc"), Some("stripe_key"));
        assert_eq!(leading_assignment_key("api-key:tok"), Some("api-key"));
        assert_eq!(leading_assignment_key("a.b~c"), Some("a.b"));
    }

    #[test]
    fn leading_assignment_key_rejects_non_assignments() {
        assert_eq!(leading_assignment_key("nodelimiter"), None); // no delimiter, run == whole string
        assert_eq!(leading_assignment_key("=leading"), None); // empty key before delimiter
        assert_eq!(leading_assignment_key("key = spaced"), None); // space breaks the key run before '='
        assert_eq!(leading_assignment_key(""), None);
    }

    #[test]
    fn is_assignment_key_byte_admits_identifier_bytes_only() {
        for b in [b'a', b'Z', b'5', b'_', b'-', b'.'] {
            assert!(
                is_assignment_key_byte(b),
                "{} should be a key byte",
                b as char
            );
        }
        for b in [b' ', b'=', b':', b'"', b'/'] {
            assert!(
                !is_assignment_key_byte(b),
                "{} must not be a key byte",
                b as char
            );
        }
    }

    #[test]
    fn normalized_lookup_is_exact_binary_search() {
        let set = owned(&["aws_secret_key", "stripe_secret_key"]); // sorted
        assert!(normalized_assignment_keyword_owned_by_named_detector(
            &set,
            "stripe_secret_key"
        ));
        assert!(normalized_assignment_keyword_owned_by_named_detector(
            &set,
            "aws_secret_key"
        ));
        assert!(!normalized_assignment_keyword_owned_by_named_detector(
            &set,
            "gcp_secret_key"
        ));
        assert!(!normalized_assignment_keyword_owned_by_named_detector(
            &set, "stripe"
        )); // prefix, not exact
    }

    #[test]
    fn owned_keyword_normalizes_and_requires_secret_suffix() {
        let set = owned(&["stripe_secret_key"]);
        // Case/separator variants normalize onto the owned key.
        assert!(assignment_keyword_owned_by_named_detector(
            &set,
            "Stripe-Secret-Key"
        ));
        assert!(assignment_keyword_owned_by_named_detector(
            &set,
            "STRIPE.SECRET.KEY"
        ));
        // No secret suffix -> rejected before the lookup even runs.
        assert!(!assignment_keyword_owned_by_named_detector(
            &set,
            "stripe_id"
        ));
        // Secret-suffixed but not an owned key.
        assert!(!assignment_keyword_owned_by_named_detector(
            &set,
            "unknown_key"
        ));
        // Empty owned set is never ownership.
        assert!(!assignment_keyword_owned_by_named_detector(
            &owned(&[]),
            "stripe_secret_key"
        ));
    }

    #[test]
    fn candidate_prefix_ownership_requires_longer_secret_suffixed_prefix() {
        let set = owned(&["stripe_secret_key"]);
        assert!(candidate_starts_with_owned_assignment_key(
            &set,
            "stripe_secret_key_prod"
        ));
        // Exact length is not a strict prefix, so it is not claimed by this predicate.
        assert!(!candidate_starts_with_owned_assignment_key(
            &set,
            "stripe_secret_key"
        ));
        assert!(!candidate_starts_with_owned_assignment_key(
            &set,
            "other_secret_key"
        ));
    }

    #[test]
    fn candidate_embeds_owned_key_via_delimiter_or_prefix() {
        let set = owned(&["stripe_secret_key"]);
        // Delimited assignment: the leading key matches an owned key.
        assert!(candidate_embeds_owned_assignment_key(
            &set,
            "stripe_secret_key=abc123"
        ));
        // No delimiter, but the candidate starts with the owned key.
        assert!(candidate_embeds_owned_assignment_key(
            &set,
            "stripe_secret_key_prod_xyz"
        ));
        assert!(!candidate_embeds_owned_assignment_key(
            &set,
            "random_token=v"
        ));
    }

    #[test]
    fn keyword_span_expands_to_the_full_owned_key() {
        let set = owned(&["stripe_secret_key"]);
        let line = "stripe_secret_key=v";
        assert!(keyword_span_owned_by_named_detector(&set, line, 0, 17)); // exact span
        assert!(keyword_span_owned_by_named_detector(&set, line, 7, 17)); // sub-span expands left to full key
        assert!(!keyword_span_owned_by_named_detector(
            &set,
            "user_id=5",
            0,
            7
        )); // unowned
        assert!(!keyword_span_owned_by_named_detector(&set, line, 5, 3)); // start > end fails closed
        assert!(!keyword_span_owned_by_named_detector(&set, line, 0, 999)); // end past line fails closed
    }

    #[test]
    fn entropy_candidate_ownership_uses_embedded_key_without_a_line() {
        let set = owned(&["stripe_secret_key"]);
        assert!(entropy_candidate_owned_by_named_assignment(
            &set,
            "stripe_secret_key=abc123",
            None
        ));
        assert!(!entropy_candidate_owned_by_named_assignment(
            &set,
            "plain_value",
            None
        ));
    }

    fn generic_detector(id: &str, keywords: &[&str]) -> DetectorSpec {
        DetectorSpec {
            id: id.to_string(),
            name: id.to_string(),
            service: "generic".to_string(),
            kind: DetectorKind::Phase2Generic,
            keywords: keywords.iter().map(|k| k.to_string()).collect(),
            ..Default::default()
        }
    }

    fn generic_secret_detector() -> DetectorSpec {
        DetectorSpec {
            id: crate::detector_ids::GENERIC_SECRET.to_string(),
            name: "Generic Secret".to_string(),
            service: "generic".to_string(),
            kind: DetectorKind::Phase2Generic,
            keywords: vec!["secret".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn owning_index_earliest_detector_wins_across_exact_and_normalized() {
        // Detector 0 owns "api_token"; detector 1 owns the literal "api-token".
        // Both normalize to "api_token". A query that hits detector 1 EXACTLY and
        // detector 0 via NORMALIZATION must resolve to the EARLIER detector (0),
        // exactly like the old linear `find` returning the first match by either
        // condition.
        let detectors = vec![
            generic_detector("api-a", &["api_token"]),
            generic_detector("api-b", &["api-token"]),
            generic_secret_detector(),
        ];
        let index = GenericOwningDetectorIndex::build(&detectors);

        assert_eq!(
            index.owning_index("API-TOKEN"),
            Some(0),
            "exact hit on detector 1 + normalized hit on detector 0 -> earliest (0) wins"
        );
        assert_eq!(
            index.owning_index("api_token"),
            Some(0),
            "exact match on detector 0's literal keyword"
        );
        assert_eq!(
            index.owning_index("totally_unknown_lhs"),
            Some(2),
            "unmatched keyword falls back to the GENERIC_SECRET detector index"
        );
        assert_eq!(index.index_for_id("api-a"), Some(0));
        assert_eq!(index.index_for_id("api-b"), Some(1));
        assert_eq!(
            index.index_for_id(crate::detector_ids::GENERIC_SECRET),
            Some(2),
            "synthetic entropy policy must resolve the active generic-secret spec"
        );
        assert_eq!(index.index_for_id("not-loaded"), None);
    }

    #[test]
    fn owning_index_is_none_without_a_match_or_generic_secret() {
        let detectors = vec![generic_detector("api-a", &["api_token"])];
        let index = GenericOwningDetectorIndex::build(&detectors);
        assert_eq!(index.owning_index("api_token"), Some(0));
        assert_eq!(
            index.owning_index("unowned"),
            None,
            "no keyword owner AND no GENERIC_SECRET detector -> None (caller uses defaults)"
        );
    }

    #[test]
    fn owning_index_ignores_non_generic_service_detectors() {
        // A named (service != "generic") detector must not claim its assignment
        // keyword through the generic owner index, even if its kind is
        // Phase2Generic; the keyword falls through to GENERIC_SECRET.
        let named = DetectorSpec {
            id: "stripe".to_string(),
            name: "Stripe".to_string(),
            service: "stripe".to_string(),
            kind: DetectorKind::Phase2Generic,
            keywords: vec!["stripe_key".to_string()],
            ..Default::default()
        };
        let detectors = vec![named, generic_secret_detector()];
        let index = GenericOwningDetectorIndex::build(&detectors);
        assert_eq!(index.owning_index("stripe_key"), Some(1));
    }
}
