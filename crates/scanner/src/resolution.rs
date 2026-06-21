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
    suppress_matches_nested_in_private_key_blocks(&mut matches);
    suppress_entropy_matches_near_named_detectors(&mut matches);
    resolve_match_groups(matches)
}

fn suppress_matches_nested_in_private_key_blocks(matches: &mut Vec<RawMatch>) {
    let private_key_spans: Vec<(Arc<str>, usize, usize)> = matches
        .iter()
        .filter(|m| is_private_key_block_detector(m.detector_id.as_ref()))
        .filter_map(match_span)
        .collect();
    if private_key_spans.is_empty() {
        return;
    }

    matches.retain(|m| {
        if is_private_key_block_detector(m.detector_id.as_ref()) {
            return true;
        }
        let Some((file, start, end)) = match_span(m) else {
            return true;
        };
        !private_key_spans
            .iter()
            .any(|(block_file, block_start, block_end)| {
                block_file.as_ref() == file.as_ref() && *block_start <= start && end <= *block_end
            })
    });
}

fn match_span(m: &RawMatch) -> Option<(Arc<str>, usize, usize)> {
    let file = m.location.file_path.clone()?;
    let start = m.location.offset;
    let end = start.saturating_add(m.credential.len());
    Some((file, start, end))
}

fn suppress_entropy_matches_near_named_detectors(matches: &mut Vec<RawMatch>) {
    // Index service-specific detector lines as path -> {line}, so the adjacency
    // check below is a pure HashSet lookup with zero per-match Arc clones: we
    // look up by `&str` via `Arc<str>: Borrow<str>`.
    let mut named_lines: HashMap<Arc<str>, HashSet<usize>> = HashMap::new();
    for m in matches.iter() {
        if !is_service_specific_detector(m.detector_id.as_ref()) {
            continue;
        }
        if let Some(line) = m.location.line {
            let path = m
                .location
                .file_path
                .clone()
                .unwrap_or_else(|| Arc::from("")); // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
            named_lines.entry(path).or_default().insert(line);
        }
    }
    matches.retain(|m| {
        if !crate::detector_ids::is_entropy_detector(m.detector_id.as_ref()) {
            return true;
        }
        let Some(line) = m.location.line else {
            return true;
        };
        // Empty path for the intern-miss case mirrors the `Arc::from("")` key
        // used when indexing above; lookup is by `&str`, no allocation.
        let path = match m.location.file_path.as_deref() {
            Some(path) => path,
            None => "",
        };
        if let Some(lines) = named_lines.get(path) {
            for offset in 0..=ADJACENT_LINE_DISTANCE {
                if lines.contains(&line.saturating_sub(offset))
                    || lines.contains(&line.saturating_add(offset))
                {
                    return false;
                }
            }
        }
        true
    });
}

fn is_entropy_detector(detector_id: &str) -> bool {
    crate::detector_ids::is_entropy_detector(detector_id)
}

fn is_generic_detector(detector_id: &str) -> bool {
    crate::detector_ids::is_generic_or_private_key_detector(detector_id)
}

fn is_private_key_block_detector(detector_id: &str) -> bool {
    crate::detector_ids::is_private_key_block_detector(detector_id)
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
        && crate::detector_ids::is_service_anchored_detector(m.detector_id.as_ref())
    {
        score += 5.0;
    }

    score
}
