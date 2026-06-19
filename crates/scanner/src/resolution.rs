//! Match resolution: when multiple detectors match the same region, keep only
//! the most specific, highest-confidence match. Eliminates duplicates.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use keyhog_core::RawMatch;

const ADJACENT_LINE_DISTANCE: usize = 2;
const SINGLE_MATCH_COUNT: usize = 1;
const SCORE_EPSILON: f64 = 1e-9;
const ENTROPY_MATCH_SCORE: f64 = 0.0;
const NAMED_DETECTOR_SCORE: f64 = 10.0;
const CONFIDENCE_WEIGHT: f64 = 5.0;
const DETECTOR_ID_LENGTH_WEIGHT: f64 = 0.1;
const MAX_CREDENTIAL_SCORE_LENGTH: usize = 200;
const CREDENTIAL_LENGTH_WEIGHT: f64 = 0.01;

/// Resolve overlapping matches: for each credential text region,
/// keep only the best match. Also suppress entropy findings when
/// a named detector already found a secret on the same line.
pub fn resolve_matches(mut matches: Vec<RawMatch>) -> Vec<RawMatch> {
    if matches.len() <= SINGLE_MATCH_COUNT {
        return matches;
    }
    suppress_entropy_matches_near_named_detectors(&mut matches);
    resolve_match_groups(matches)
}

fn suppress_entropy_matches_near_named_detectors(matches: &mut Vec<RawMatch>) {
    // Use (Arc<str>, usize) to avoid per-match String allocation.
    let named_lines: HashSet<(Arc<str>, usize)> = matches
        .iter()
        .filter(|m| is_service_specific_detector(m.detector_id.as_ref()))
        .filter_map(|m| {
            let path = m
                .location
                .file_path
                .clone()
                .unwrap_or_else(|| Arc::from("")); // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
            m.location.line.map(|line| (path, line))
        })
        .collect();
    matches.retain(|m| {
        if m.detector_id.as_ref() != "entropy" && !m.detector_id.as_ref().starts_with("entropy-") {
            return true;
        }
        let path = m
            .location
            .file_path
            .clone()
            .unwrap_or_else(|| Arc::from("")); // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
        if let Some(line) = m.location.line {
            for offset in 0..=ADJACENT_LINE_DISTANCE {
                if named_lines.contains(&(Arc::clone(&path), line.saturating_sub(offset)))
                    || named_lines.contains(&(Arc::clone(&path), line.saturating_add(offset)))
                {
                    return false;
                }
            }
        }
        true
    });
}

fn is_entropy_detector(detector_id: &str) -> bool {
    detector_id == "entropy" || detector_id.starts_with("entropy-")
}

fn is_generic_detector(detector_id: &str) -> bool {
    detector_id.starts_with("generic-") || detector_id == "private-key"
}

fn is_service_specific_detector(detector_id: &str) -> bool {
    !is_entropy_detector(detector_id) && !is_generic_detector(detector_id)
}

fn resolve_match_groups(mut matches: Vec<RawMatch>) -> Vec<RawMatch> {
    // Group by (file_path, line) - matches on the same line in the same file
    // are competing for the same secret, even if their credential strings differ
    // slightly (e.g., exact-length vs greedy regex match).
    let mut groups: HashMap<(Arc<str>, usize), Vec<RawMatch>> = HashMap::new();
    for m in matches.drain(..) {
        let file = m
            .location
            .file_path
            .clone()
            .unwrap_or_else(|| Arc::from("")); // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
        let line = m.location.line.unwrap_or(0); // LAW10: line not located => placeholder line for REPORTING only; finding still emitted, recall-safe
        groups.entry((file, line)).or_default().push(m);
    }
    // Iterate groups in a deterministic key order. `HashMap::into_values` yields
    // groups in RandomState order, so `resolved` came out shuffled run-to-run;
    // the downstream total sort in `dedup_matches` washes that out for the final
    // report, but emitting a stable order here keeps every intermediate consumer
    // (and the resolution unit tests) reproducible. The `(file, line)` key is
    // unique per group, so this is a total order.
    let mut grouped: Vec<((Arc<str>, usize), Vec<RawMatch>)> = groups.into_iter().collect();
    grouped.sort_by(|a, b| a.0.cmp(&b.0));
    let mut resolved = Vec::new();
    for (_key, group) in grouped {
        if group.len() == SINGLE_MATCH_COUNT {
            resolved.extend(group);
            continue;
        }
        resolved.extend(best_matches_for_group(group));
    }
    resolved
}

fn best_matches_for_group(group: Vec<RawMatch>) -> Vec<RawMatch> {
    let mut scored: Vec<(f64, RawMatch)> = group
        .into_iter()
        .map(|matched| (match_priority_score(&matched), matched))
        .collect();
    // Total order: score desc via `total_cmp` (not `partial_cmp().unwrap_or`,
    // which collapses NaN/ties to Equal and leaves the survivor at insertion
    // order), then the `RawMatch` total `Ord` so equal-score matches break ties
    // by content, not by the HashMap-iteration order they arrived in.
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let top_score = scored[0].0;
    scored
        .into_iter()
        .take_while(|(score, _)| (*score - top_score).abs() < SCORE_EPSILON)
        .map(|(_, matched)| matched)
        .collect()
}

/// Compute the priority score used to break ties between overlapping matches.
fn match_priority_score(m: &RawMatch) -> f64 {
    let mut score = ENTROPY_MATCH_SCORE;

    // Service-specific detectors beat generic/entropy fallbacks. A
    // high-confidence generic password that captures only the URL password
    // must not outrank a lower-confidence database-URL detector on the same
    // line; the URL detector carries the service contract and fuller
    // credential boundary.
    if is_service_specific_detector(m.detector_id.as_ref()) {
        score += NAMED_DETECTOR_SCORE;
    }

    // Confidence score contributes directly.
    if let Some(conf) = m.confidence {
        score += conf * CONFIDENCE_WEIGHT;
    }

    // Longer detector ID prefix in the credential = more specific match.
    score += (m.detector_id.len() as f64) * DETECTOR_ID_LENGTH_WEIGHT;

    // Credential length matters: longer credentials are more specific matches.
    score +=
        (m.credential.len().min(MAX_CREDENTIAL_SCORE_LENGTH) as f64) * CREDENTIAL_LENGTH_WEIGHT;

    // Prefer specific detectors over generic ones for credentials with known prefixes.
    if crate::confidence::known_prefix_confidence_floor(&m.credential).is_some()
        && m.detector_id.as_ref() != "entropy"
        && !m.detector_id.as_ref().starts_with("entropy-")
        && !m.detector_id.as_ref().starts_with("generic-")
    {
        score += 5.0;
    }

    score
}
