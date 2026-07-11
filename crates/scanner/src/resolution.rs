//! Match resolution: when multiple detectors match the same region, keep only
//! the most specific, highest-confidence match. Eliminates duplicates.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use keyhog_core::RawMatch;

const ADJACENT_LINE_DISTANCE: usize = 2;
const SINGLE_MATCH_COUNT: usize = 1;
const PRIORITY_EPSILON: f64 = 1e-9;
const ENTROPY_MATCH_PRIORITY: f64 = 0.0;
const NAMED_DETECTOR_PRIORITY: f64 = 10.0;
const CONFIDENCE_WEIGHT: f64 = 5.0;
const DETECTOR_ID_LENGTH_WEIGHT: f64 = 0.1;
const MAX_CREDENTIAL_PRIORITY_LENGTH: usize = 200;
const CREDENTIAL_LENGTH_WEIGHT: f64 = 0.01;
const KNOWN_PREFIX_SERVICE_BONUS: f64 = 5.0;

/// Resolve overlapping matches: for each credential text region,
/// keep only the best match. Also suppress entropy findings when
/// a named detector already found a secret on the same line.
pub fn resolve_matches(matches: Vec<RawMatch>) -> Vec<RawMatch> {
    match try_resolve_matches(matches) {
        Ok(resolved) => resolved,
        Err(error) => {
            panic!(
                "detector classification is invalid during match resolution: {error}"
            );
        }
    }
}

/// Checked match resolution for operator paths that must report rule failures
/// instead of aborting through the compatibility API.
pub fn try_resolve_matches(mut matches: Vec<RawMatch>) -> Result<Vec<RawMatch>, String> {
    try_resolve_matches_with_policy(&mut matches, None)?;
    Ok(matches)
}

/// Resolve matches using the private-key-block family declared by the active
/// detector corpus. Custom detector directories call this path so resolution
/// never re-reads embedded classification policy by detector id.
pub fn try_resolve_matches_with_private_key_blocks(
    mut matches: Vec<RawMatch>,
    private_key_block_detectors: &HashSet<String>,
) -> Result<Vec<RawMatch>, String> {
    try_resolve_matches_with_policy(&mut matches, Some(private_key_block_detectors))?;
    Ok(matches)
}

fn try_resolve_matches_with_policy(
    matches: &mut Vec<RawMatch>,
    private_key_block_detectors: Option<&HashSet<String>>,
) -> Result<(), String> {
    if matches.len() <= SINGLE_MATCH_COUNT {
        return Ok(());
    }
    suppress_matches_nested_in_private_key_blocks(matches, private_key_block_detectors)?;
    suppress_entropy_matches_near_named_detectors(matches);
    *matches = resolve_match_groups(std::mem::take(matches));
    Ok(())
}

fn suppress_matches_nested_in_private_key_blocks(
    matches: &mut Vec<RawMatch>,
    private_key_block_detectors: Option<&HashSet<String>>,
) -> Result<(), String> {
    let private_key_spans: Vec<(Arc<str>, usize, usize)> = matches
        .iter()
        .filter_map(|m| {
            is_private_key_block_detector(m.detector_id.as_ref(), private_key_block_detectors)
                .map(|is_block| is_block.then(|| m))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(match_span)
        .collect();
    if private_key_spans.is_empty() {
        return Ok(());
    }

    // Index the spans per file as (sorted starts, running prefix-maximum of end).
    // A match [start,end] is nested in SOME private-key span of its file iff,
    // among the spans whose `block_start <= start`, the maximum `block_end` is
    // `>= end` (that max-end span has start <= start, so it contains the match).
    // A `partition_point` on the sorted starts answers each query in O(log P),
    // turning the previous O(matches x spans) containment scan into
    // O((matches + spans) log spans). Without this, a crafted file packed with
    // thousands of tiny PEM blocks (each a private-key-block match) drives a
    // quadratic blow-up in this suppression pass (algorithmic-DoS, Law 7).
    let by_file = index_spans_by_file(private_key_spans);

    let mut retain = Vec::with_capacity(matches.len());
    for m in matches.iter() {
        if is_private_key_block_detector(m.detector_id.as_ref(), private_key_block_detectors)? {
            retain.push(true);
            continue;
        }
        let Some((file, start, end)) = match_span(m) else {
            retain.push(true);
            continue;
        };
        retain.push(!span_contains(&by_file, file.as_ref(), start, end));
    }
    let mut retained = Vec::with_capacity(matches.len());
    for (m, keep) in matches.drain(..).zip(retain) {
        if keep {
            retained.push(m);
        }
    }
    *matches = retained;
    Ok(())
}

fn match_span(m: &RawMatch) -> Option<(Arc<str>, usize, usize)> {
    let file = m.location.file_path.clone()?;
    let start = m.location.offset;
    let end = start.saturating_add(m.credential.len());
    Some((file, start, end))
}

/// Private-key spans for one file, sorted by start with a running prefix-maximum
/// of `end`. This is the index `span_contains` binary-searches to answer interval
/// containment in O(log P) rather than scanning all P spans per match.
struct FileKeySpans {
    /// Span start offsets, strictly ascending positions (ties allowed).
    starts: Vec<usize>,
    /// `prefix_max_end[i]` is the maximum `end` over `starts[0..=i]`.
    prefix_max_end: Vec<usize>,
}

/// Group `(file, start, end)` private-key spans by file and, per file, sort by
/// `start` and precompute the prefix-maximum of `end`. The prefix-max lets a
/// single binary search decide containment for arbitrary (even overlapping)
/// spans: among the spans whose `start <= q_start`, if the largest `end` reaches
/// `q_end`, then that very span (its `start` is in the prefix, its `end` is the
/// max) fully contains `[q_start, q_end]`.
fn index_spans_by_file(spans: Vec<(Arc<str>, usize, usize)>) -> HashMap<Arc<str>, FileKeySpans> {
    let mut grouped: HashMap<Arc<str>, Vec<(usize, usize)>> = HashMap::new();
    for (file, start, end) in spans {
        grouped.entry(file).or_default().push((start, end));
    }
    grouped
        .into_iter()
        .map(|(file, mut spans)| {
            spans.sort_unstable_by_key(|&(start, _)| start);
            let starts: Vec<usize> = spans.iter().map(|&(start, _)| start).collect();
            let mut prefix_max_end = Vec::with_capacity(spans.len());
            let mut running = 0usize;
            for &(_, end) in &spans {
                running = running.max(end);
                prefix_max_end.push(running);
            }
            (
                file,
                FileKeySpans {
                    starts,
                    prefix_max_end,
                },
            )
        })
        .collect()
}

/// Whether `[start, end]` is fully nested in SOME private-key span of `file`.
/// `partition_point` finds how many spans begin at or before `start` (a prefix of
/// the sorted starts); if the prefix's maximum `end` reaches `end`, a containing
/// span exists. O(log P). Looks up the file key by `&str` via `Arc<str>: Borrow`.
fn span_contains(
    by_file: &HashMap<Arc<str>, FileKeySpans>,
    file: &str,
    start: usize,
    end: usize,
) -> bool {
    let Some(spans) = by_file.get(file) else {
        return false;
    };
    let count = spans
        .starts
        .partition_point(|&span_start| span_start <= start);
    count > 0 && spans.prefix_max_end[count - 1] >= end
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

fn is_private_key_block_detector(
    detector_id: &str,
    active: Option<&HashSet<String>>,
) -> Result<bool, String> {
    match active {
        Some(detectors) => Ok(detectors.contains(detector_id)),
        None => crate::detector_ids::is_private_key_block_detector(detector_id),
    }
}

/// Whether a detector carries a service contract — not generic, not entropy,
/// and not the private-key fallback. Single owner:
/// `detector_ids::is_service_anchored_detector`. This previously recomputed the
/// same boolean through local `is_entropy_detector` / `is_generic_detector`
/// wrappers (`!entropy && !(generic || private_key_fallback)`), algebraically
/// identical to the canonical `!generic && !entropy && !private_key_fallback`
/// but a silent-drift hazard if either definition changed independently.
pub(crate) fn is_service_specific_detector(detector_id: &str) -> bool {
    crate::detector_ids::is_service_anchored_detector(detector_id)
}

fn resolve_match_groups(mut matches: Vec<RawMatch>) -> Vec<RawMatch> {
    // Group by (file_path, line). For a source with no line attribution, build
    // connected components of overlapping credential spans: slightly different
    // regex captures of one secret still compete, while disjoint binary findings
    // remain independent instead of collapsing into a synthetic line zero.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum GroupLocation {
        Line(usize),
        Offset(usize),
    }

    let mut groups: BTreeMap<(Arc<str>, GroupLocation), Vec<RawMatch>> = BTreeMap::new();
    let mut line_free: BTreeMap<Arc<str>, Vec<RawMatch>> = BTreeMap::new();
    for m in matches.drain(..) {
        let file = m
            .location
            .file_path
            .clone()
            .unwrap_or_else(|| Arc::from("")); // LAW10: string-intern miss => owned Arc of identical bytes, recall-safe
        if let Some(line) = m.location.line {
            groups
                .entry((file, GroupLocation::Line(line)))
                .or_default()
                .push(m);
        } else {
            line_free.entry(file).or_default().push(m);
        }
    }

    for (file, mut file_matches) in line_free {
        file_matches.sort_by_key(|matched| {
            (
                matched.location.offset,
                matched
                    .location
                    .offset
                    .saturating_add(matched.credential.as_ref().len()),
            )
        });

        let mut component = Vec::new();
        let mut component_end = 0usize;
        for matched in file_matches {
            let start = matched.location.offset;
            let end = start.saturating_add(matched.credential.as_ref().len());
            let overlaps = component.first().is_some_and(|first: &RawMatch| {
                start < component_end || start == first.location.offset
            });
            if !overlaps && !component.is_empty() {
                let component_start = component[0].location.offset;
                groups.insert(
                    (file.clone(), GroupLocation::Offset(component_start)),
                    std::mem::take(&mut component),
                );
                component_end = 0;
            }
            component_end = component_end.max(end);
            component.push(matched);
        }
        if !component.is_empty() {
            let component_start = component[0].location.offset;
            groups.insert((file, GroupLocation::Offset(component_start)), component);
        }
    }

    let mut resolved = Vec::new();
    for (_key, group) in groups {
        if group.len() == SINGLE_MATCH_COUNT {
            resolved.extend(group);
            continue;
        }
        resolved.extend(best_matches_for_group(group));
    }
    resolved
}

fn best_matches_for_group(group: Vec<RawMatch>) -> Vec<RawMatch> {
    let mut prioritized: Vec<(f64, RawMatch)> = group
        .into_iter()
        .map(|matched| (match_priority(&matched), matched))
        .collect();
    // Total order: priority desc via `total_cmp` (not `partial_cmp().unwrap_or`,
    // which collapses NaN/ties to Equal and leaves the survivor at insertion
    // order), then the `RawMatch` total `Ord` so equal-priority matches break ties
    // by content, not by the HashMap-iteration order they arrived in.
    prioritized.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let top_priority = prioritized[0].0;
    prioritized
        .into_iter()
        .take_while(|(priority, _)| (*priority - top_priority).abs() < PRIORITY_EPSILON)
        .map(|(_, matched)| matched)
        .collect()
}

/// Compute the resolver priority used to break ties between overlapping matches.
pub(crate) fn match_priority(m: &RawMatch) -> f64 {
    let mut priority = ENTROPY_MATCH_PRIORITY;

    // Service-specific detectors beat generic/entropy fallbacks. A
    // high-confidence generic password that captures only the URL password
    // must not outrank a lower-confidence database-URL detector on the same
    // line; the URL detector carries the service contract and fuller
    // credential boundary.
    if is_service_specific_detector(m.detector_id.as_ref()) {
        priority += NAMED_DETECTOR_PRIORITY;
    }

    // Report confidence contributes directly to resolver priority.
    if let Some(conf) = m.confidence {
        priority += conf * CONFIDENCE_WEIGHT;
    }

    // Longer detector ID prefix in the credential = more specific match.
    priority += (m.detector_id.len() as f64) * DETECTOR_ID_LENGTH_WEIGHT;

    // Credential length matters: longer credentials are more specific matches.
    priority +=
        (m.credential.len().min(MAX_CREDENTIAL_PRIORITY_LENGTH) as f64) * CREDENTIAL_LENGTH_WEIGHT;

    // Prefer specific detectors over generic ones for credentials with known prefixes.
    if crate::confidence::known_prefix_confidence_floor(&m.credential).is_some()
        && crate::detector_ids::is_service_anchored_detector(m.detector_id.as_ref())
    {
        priority += KNOWN_PREFIX_SERVICE_BONUS;
    }

    priority
}
