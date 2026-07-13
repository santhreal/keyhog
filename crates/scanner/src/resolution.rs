//! Match resolution: when multiple detectors match the same region, keep only
//! the most specific, highest-confidence match. Eliminates duplicates.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use keyhog_core::RawMatch;

const NAMED_DUPLICATE_LINE_DISTANCE: usize = 2;
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
/// keep only the best match. Also suppress duplicate entropy findings when
/// a named detector already covers the same evidence nearby.
pub fn resolve_matches(matches: Vec<RawMatch>) -> Vec<RawMatch> {
    match try_resolve_matches(matches) {
        Ok(resolved) => resolved,
        Err(error) => {
            panic!(
                "detector classification rules are invalid during match resolution: {error}. Fix: correct rules/detector-classification.toml"
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
    let source_families = SourceFamilyIndex::new(matches);
    suppress_matches_nested_in_private_key_blocks(
        matches,
        private_key_block_detectors,
        &source_families,
    )?;
    suppress_entropy_duplicates_near_named_detectors(matches, &source_families);
    *matches = resolve_match_groups(std::mem::take(matches), &source_families);
    Ok(())
}

fn suppress_matches_nested_in_private_key_blocks(
    matches: &mut Vec<RawMatch>,
    private_key_block_detectors: Option<&HashSet<String>>,
    source_families: &SourceFamilyIndex,
) -> Result<(), String> {
    let private_key_spans: Vec<(MatchOrigin, usize, usize)> = matches
        .iter()
        .filter_map(|m| {
            is_private_key_block_detector(m.detector_id.as_ref(), private_key_block_detectors)
                .map(|is_block| is_block.then(|| m))
                .transpose()
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter_map(|matched| match_span(matched, source_families))
        .collect();
    if private_key_spans.is_empty() {
        return Ok(());
    }

    // Index spans per source, path, and revision with a running prefix-maximum.
    // A match [start,end] is nested in SOME private-key span of its origin iff,
    // among the spans whose `block_start <= start`, the maximum `block_end` is
    // `>= end` (that max-end span has start <= start, so it contains the match).
    // A `partition_point` on the sorted starts answers each query in O(log P),
    // turning the previous O(matches x spans) containment scan into
    // O((matches + spans) log spans). Without this, a crafted file packed with
    // thousands of tiny PEM blocks (each a private-key-block match) drives a
    // quadratic blow-up in this suppression pass (algorithmic-DoS, Law 7).
    let by_origin = index_spans_by_origin(private_key_spans);

    let mut retain = Vec::with_capacity(matches.len());
    for m in matches.iter() {
        if is_private_key_block_detector(m.detector_id.as_ref(), private_key_block_detectors)? {
            retain.push(true);
            continue;
        }
        let Some((origin, start, end)) = match_span(m, source_families) else {
            retain.push(true);
            continue;
        };
        retain.push(!span_contains(&by_origin, &origin, start, end));
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

fn match_span(
    m: &RawMatch,
    source_families: &SourceFamilyIndex,
) -> Option<(MatchOrigin, usize, usize)> {
    m.location.file_path.as_ref()?;
    let start = m.location.offset;
    let end = start.saturating_add(m.credential.len());
    Some((MatchOrigin::from_match(m, source_families), start, end))
}

struct SourceFamilyIndex {
    sources: HashSet<Arc<str>>,
}

impl SourceFamilyIndex {
    fn new(matches: &[RawMatch]) -> Self {
        Self {
            sources: matches
                .iter()
                .map(|matched| matched.location.source.clone())
                .collect(),
        }
    }

    fn family_for(&self, source: &Arc<str>) -> Arc<str> {
        // Decoder and extraction views append `/...` to their parent source.
        // Collapse only to an ancestor that is present in this match batch.
        // Opaque sibling namespaces such as `git/tag` and `git/unreachable`
        // therefore remain distinct.
        let mut family = source.clone();
        let mut candidate = source.as_ref();
        while let Some((parent, _)) = candidate.rsplit_once('/') {
            if let Some(ancestor) = self.sources.get(parent) {
                family = ancestor.clone();
            }
            candidate = parent;
        }
        family
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct MatchOrigin {
    source_family: Arc<str>,
    file_path: Option<Arc<str>>,
    commit: Option<Arc<str>>,
}

impl MatchOrigin {
    fn from_match(matched: &RawMatch, source_families: &SourceFamilyIndex) -> Self {
        Self {
            source_family: source_families.family_for(&matched.location.source),
            file_path: matched.location.file_path.clone(),
            commit: matched.location.commit.clone(),
        }
    }
}

/// Match spans for one origin, sorted by start with a running prefix-maximum
/// of `end`. This is the index `span_contains` binary-searches to answer interval
/// containment in O(log P) rather than scanning all P spans per match.
struct SpanIndex {
    /// Span start offsets in nondecreasing order.
    starts: Vec<usize>,
    /// `prefix_max_end[i]` is the maximum `end` over `starts[0..=i]`.
    prefix_max_end: Vec<usize>,
}

impl SpanIndex {
    fn from_unsorted(mut spans: Vec<(usize, usize)>) -> Self {
        spans.retain(|&(start, end)| start < end);
        spans.sort_unstable_by_key(|&(start, _)| start);
        let starts: Vec<usize> = spans.iter().map(|&(start, _)| start).collect();
        let mut prefix_max_end = Vec::with_capacity(spans.len());
        let mut running = 0usize;
        for &(_, end) in &spans {
            running = running.max(end);
            prefix_max_end.push(running);
        }
        Self {
            starts,
            prefix_max_end,
        }
    }

    fn contains(&self, start: usize, end: usize) -> bool {
        if start >= end {
            return false;
        }
        let count = self
            .starts
            .partition_point(|&span_start| span_start <= start);
        count > 0 && self.prefix_max_end[count - 1] >= end
    }

    fn overlaps(&self, start: usize, end: usize) -> bool {
        if start >= end {
            return false;
        }
        let count = self.starts.partition_point(|&span_start| span_start < end);
        count > 0 && self.prefix_max_end[count - 1] > start
    }
}

/// Group private-key spans by source, path, and revision, then sort by `start`
/// and precompute the prefix-maximum of `end`. The prefix-max lets a
/// single binary search decide containment for arbitrary (even overlapping)
/// spans: among the spans whose `start <= q_start`, if the largest `end` reaches
/// `q_end`, then that very span (its `start` is in the prefix, its `end` is the
/// max) fully contains `[q_start, q_end]`.
fn index_spans_by_origin(
    spans: Vec<(MatchOrigin, usize, usize)>,
) -> HashMap<MatchOrigin, SpanIndex> {
    let mut grouped: HashMap<MatchOrigin, Vec<(usize, usize)>> = HashMap::new();
    for (origin, start, end) in spans {
        grouped.entry(origin).or_default().push((start, end));
    }
    grouped
        .into_iter()
        .map(|(origin, spans)| (origin, SpanIndex::from_unsorted(spans)))
        .collect()
}

/// Whether `[start, end]` is fully nested in a private-key span of `origin`.
/// `partition_point` finds how many spans begin at or before `start` (a prefix of
/// the sorted starts); if the prefix's maximum `end` reaches `end`, a containing
/// span exists. O(log P).
fn span_contains(
    by_origin: &HashMap<MatchOrigin, SpanIndex>,
    origin: &MatchOrigin,
    start: usize,
    end: usize,
) -> bool {
    let Some(spans) = by_origin.get(origin) else {
        return false;
    };
    spans.contains(start, end)
}

fn suppress_entropy_duplicates_near_named_detectors(
    matches: &mut Vec<RawMatch>,
    source_families: &SourceFamilyIndex,
) {
    let mut named_lines: HashMap<MatchOrigin, HashMap<usize, Vec<(usize, usize)>>> = HashMap::new();
    for m in matches.iter() {
        if !is_service_specific_detector(m.detector_id.as_ref()) {
            continue;
        }
        if let Some(line) = m.location.line {
            let evidence = named_lines
                .entry(MatchOrigin::from_match(m, source_families))
                .or_default();
            let spans = evidence.entry(line).or_default();
            let start = m.location.offset;
            spans.push((start, start.saturating_add(m.credential.len())));
        }
    }
    let named_lines: HashMap<MatchOrigin, HashMap<usize, SpanIndex>> = named_lines
        .into_iter()
        .map(|(origin, lines)| {
            let lines = lines
                .into_iter()
                .map(|(line, spans)| (line, SpanIndex::from_unsorted(spans)))
                .collect();
            (origin, lines)
        })
        .collect();
    matches.retain(|m| {
        if !crate::detector_ids::is_entropy_detector(m.detector_id.as_ref()) {
            return true;
        }
        let Some(line) = m.location.line else {
            return true;
        };
        let origin = MatchOrigin::from_match(m, source_families);
        let Some(lines) = named_lines.get(&origin) else {
            return true;
        };
        let start = m.location.offset;
        let end = start.saturating_add(m.credential.len());
        for offset in 0..=NAMED_DUPLICATE_LINE_DISTANCE {
            for candidate_line in [line.saturating_sub(offset), line.saturating_add(offset)] {
                let Some(named_spans) = lines.get(&candidate_line) else {
                    continue;
                };
                if named_spans.overlaps(start, end) {
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

/// Whether a detector carries a service contract, not generic, not entropy,
/// and not the private-key fallback. Single owner:
/// `detector_ids::is_service_anchored_detector`. This previously recomputed the
/// same boolean through local `is_entropy_detector` / `is_generic_detector`
/// wrappers (`!entropy && !(generic || private_key_fallback)`), algebraically
/// identical to the canonical `!generic && !entropy && !private_key_fallback`
/// but a silent-drift hazard if either definition changed independently.
pub(crate) fn is_service_specific_detector(detector_id: &str) -> bool {
    crate::detector_ids::is_service_anchored_detector(detector_id)
}

fn resolve_match_groups(
    mut matches: Vec<RawMatch>,
    source_families: &SourceFamilyIndex,
) -> Vec<RawMatch> {
    // A line is only an attribution boundary. Within it, slightly different
    // captures of one secret compete, while disjoint credentials remain
    // independent findings.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    enum GroupLocation {
        Line(usize),
        NoLine,
    }

    let mut groups: BTreeMap<(MatchOrigin, GroupLocation), Vec<RawMatch>> = BTreeMap::new();
    for m in matches.drain(..) {
        let origin = MatchOrigin::from_match(&m, source_families);
        let location = m
            .location
            .line
            .map_or(GroupLocation::NoLine, GroupLocation::Line);
        groups.entry((origin, location)).or_default().push(m);
    }

    let mut resolved = Vec::new();
    for (_key, mut group) in groups {
        group.sort_by_key(match_offsets);
        let mut component = Vec::new();
        let mut component_end = 0usize;
        for matched in group {
            let start = matched.location.offset;
            let end = start.saturating_add(matched.credential.as_ref().len());
            if start == end {
                if !component.is_empty() {
                    resolve_component(&mut resolved, std::mem::take(&mut component));
                    component_end = 0;
                }
                resolved.push(matched);
                continue;
            }
            let overlaps = component.first().is_some_and(|first: &RawMatch| {
                start < component_end || start == first.location.offset
            });
            if !overlaps && !component.is_empty() {
                resolve_component(&mut resolved, std::mem::take(&mut component));
                component_end = 0;
            }
            component_end = component_end.max(end);
            component.push(matched);
        }
        if !component.is_empty() {
            resolve_component(&mut resolved, component);
        }
    }
    resolved
}

fn match_offsets(matched: &RawMatch) -> (usize, usize) {
    let start = matched.location.offset;
    (
        start,
        start.saturating_add(matched.credential.as_ref().len()),
    )
}

fn resolve_component(resolved: &mut Vec<RawMatch>, component: Vec<RawMatch>) {
    if component.len() == SINGLE_MATCH_COUNT {
        resolved.extend(component);
    } else {
        resolved.extend(best_matches_for_group(component));
    }
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
