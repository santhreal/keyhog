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
                "detector classification policy is invalid during match resolution: {error}. Fix: correct the affected detector TOML in detectors/"
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
    /// `suffix_min_end[i]` is the minimum `end` over `starts[i..]`.
    suffix_min_end: Vec<usize>,
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
        let mut suffix_min_end = vec![usize::MAX; spans.len()];
        let mut running = usize::MAX;
        for (index, &(_, end)) in spans.iter().enumerate().rev() {
            running = running.min(end);
            suffix_min_end[index] = running;
        }
        Self {
            starts,
            prefix_max_end,
            suffix_min_end,
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

    /// Whether `[start,end)` contains any indexed interval.
    fn is_contained_by(&self, start: usize, end: usize) -> bool {
        if start >= end {
            return false;
        }
        let first = self
            .starts
            .partition_point(|&span_start| span_start < start);
        first < self.starts.len() && self.suffix_min_end[first] <= end
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
    #[derive(Default)]
    struct PendingNamedEvidence {
        spans: Vec<(usize, usize)>,
        by_credential: HashMap<keyhog_core::SensitiveString, Vec<(usize, usize)>>,
    }

    struct NamedEvidence {
        spans: SpanIndex,
        by_credential: HashMap<keyhog_core::SensitiveString, SpanIndex>,
    }

    let mut named_lines: HashMap<MatchOrigin, HashMap<usize, PendingNamedEvidence>> =
        HashMap::new();
    for m in matches.iter() {
        if !is_service_specific_detector(m.detector_id.as_ref()) {
            continue;
        }
        if let Some(line) = m.location.line {
            let evidence = named_lines
                .entry(MatchOrigin::from_match(m, source_families))
                .or_default();
            let evidence = evidence.entry(line).or_default();
            let start = m.location.offset;
            let span = (start, start.saturating_add(m.credential.len()));
            evidence.spans.push(span);
            evidence
                .by_credential
                .entry(m.credential.clone())
                .or_default()
                .push(span);
        }
    }
    let named_lines: HashMap<MatchOrigin, HashMap<usize, NamedEvidence>> = named_lines
        .into_iter()
        .map(|(origin, lines)| {
            let lines = lines
                .into_iter()
                .map(|(line, evidence)| {
                    let by_credential = evidence
                        .by_credential
                        .into_iter()
                        .map(|(credential, spans)| (credential, SpanIndex::from_unsorted(spans)))
                        .collect();
                    (
                        line,
                        NamedEvidence {
                            spans: SpanIndex::from_unsorted(evidence.spans),
                            by_credential,
                        },
                    )
                })
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
                let Some(named_evidence) = lines.get(&candidate_line) else {
                    continue;
                };
                let contained = named_evidence.spans.contains(start, end)
                    || named_evidence.spans.is_contained_by(start, end);
                let equivalent_overlap = named_evidence
                    .by_credential
                    .get(&m.credential)
                    .is_some_and(|spans| spans.overlaps(start, end));
                if contained || equivalent_overlap {
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
    // A line is only an attribution boundary. Within it, direct containment or
    // equivalent overlapping evidence competes. Partial overlap does not.
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
        // Establish a stable index before the interval queries. Input order must
        // not affect either equal-priority selection or final output order.
        group.sort_by(|a, b| {
            match_offsets(a)
                .cmp(&match_offsets(b))
                .then_with(|| a.cmp(b))
        });
        resolved.extend(resolve_direct_conflicts(group));
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

#[derive(Debug, Clone, Copy)]
struct MatchInterval {
    start: usize,
    end: usize,
}

impl MatchInterval {
    fn from_match(matched: &RawMatch) -> Self {
        let (start, end) = match_offsets(matched);
        Self { start, end }
    }

    fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

/// Dynamic interval index over already-retained, strictly higher-priority
/// matches. A prefix maximum answers "does a kept span contain this one?" and
/// a suffix minimum answers "does this span contain a kept one?" in O(log n).
/// The segment-tree leaves are compressed start offsets.
struct KeptIntervalIndex {
    starts: Vec<usize>,
    leaf_count: usize,
    max_end: Vec<usize>,
    min_end: Vec<usize>,
}

impl KeptIntervalIndex {
    fn new(intervals: &[MatchInterval]) -> Self {
        let mut starts: Vec<usize> = intervals
            .iter()
            .filter(|interval| !interval.is_empty())
            .map(|interval| interval.start)
            .collect();
        starts.sort_unstable();
        starts.dedup();
        let leaf_count = starts.len().next_power_of_two().max(1);
        Self {
            starts,
            leaf_count,
            max_end: vec![0; leaf_count * 2],
            min_end: vec![usize::MAX; leaf_count * 2],
        }
    }

    fn insert(&mut self, interval: MatchInterval) {
        if interval.is_empty() {
            return;
        }
        let rank = self.starts.partition_point(|&start| start < interval.start);
        debug_assert_eq!(self.starts.get(rank), Some(&interval.start));
        let mut position = self.leaf_count + rank;
        self.max_end[position] = self.max_end[position].max(interval.end);
        self.min_end[position] = self.min_end[position].min(interval.end);
        position /= 2;
        while position > 0 {
            self.max_end[position] = self.max_end[position * 2].max(self.max_end[position * 2 + 1]);
            self.min_end[position] = self.min_end[position * 2].min(self.min_end[position * 2 + 1]);
            position /= 2;
        }
    }

    fn range_max_end(&self, mut left: usize, mut right: usize) -> usize {
        left += self.leaf_count;
        right += self.leaf_count;
        let mut maximum = 0;
        while left < right {
            if left % 2 == 1 {
                maximum = maximum.max(self.max_end[left]);
                left += 1;
            }
            if right % 2 == 1 {
                right -= 1;
                maximum = maximum.max(self.max_end[right]);
            }
            left /= 2;
            right /= 2;
        }
        maximum
    }

    fn range_min_end(&self, mut left: usize, mut right: usize) -> usize {
        left += self.leaf_count;
        right += self.leaf_count;
        let mut minimum = usize::MAX;
        while left < right {
            if left % 2 == 1 {
                minimum = minimum.min(self.min_end[left]);
                left += 1;
            }
            if right % 2 == 1 {
                right -= 1;
                minimum = minimum.min(self.min_end[right]);
            }
            left /= 2;
            right /= 2;
        }
        minimum
    }

    fn has_containment_conflict(&self, interval: MatchInterval) -> bool {
        if interval.is_empty() {
            return false;
        }
        let starts_at_or_before = self
            .starts
            .partition_point(|&start| start <= interval.start);
        if self.range_max_end(0, starts_at_or_before) >= interval.end {
            return true;
        }
        let first_start_at_or_after = self.starts.partition_point(|&start| start < interval.start);
        self.range_min_end(first_start_at_or_after, self.starts.len()) <= interval.end
    }
}

#[derive(Default)]
struct KeptEquivalentEvidence {
    starts: HashMap<
        keyhog_core::CredentialHash,
        HashMap<keyhog_core::SensitiveString, BTreeMap<usize, usize>>,
    >,
}

impl KeptEquivalentEvidence {
    fn overlaps(&self, matched: &RawMatch, interval: MatchInterval) -> bool {
        if interval.is_empty() {
            return false;
        }
        let Some(starts) = self
            .starts
            .get(&matched.credential_hash)
            .and_then(|by_value| by_value.get(&matched.credential))
        else {
            return false;
        };
        let previous_overlaps = starts
            .range(..interval.start)
            .next_back()
            .is_some_and(|(_, &end)| end > interval.start);
        let next_overlaps = starts
            .range(interval.start..)
            .next()
            .is_some_and(|(&start, _)| start < interval.end);
        previous_overlaps || next_overlaps
    }

    fn insert(&mut self, matched: &RawMatch, interval: MatchInterval) {
        if interval.is_empty() {
            return;
        }
        self.starts
            .entry(matched.credential_hash)
            .or_default()
            .entry(matched.credential.clone())
            .or_default()
            .entry(interval.start)
            .and_modify(|end| *end = (*end).max(interval.end))
            .or_insert(interval.end);
    }
}

fn priorities_tie(left: f64, right: f64) -> bool {
    left.total_cmp(&right).is_eq() || (left - right).abs() < PRIORITY_EPSILON
}

fn resolve_direct_conflicts(group: Vec<RawMatch>) -> Vec<RawMatch> {
    if group.len() <= SINGLE_MATCH_COUNT {
        return group;
    }
    let intervals: Vec<MatchInterval> = group.iter().map(MatchInterval::from_match).collect();
    let priorities: Vec<f64> = group.iter().map(match_priority).collect();
    let mut prioritized: Vec<(f64, usize)> =
        priorities.iter().copied().zip(0..group.len()).collect();
    prioritized.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| group[left.1].cmp(&group[right.1]))
    });

    let mut dominant_containment = KeptIntervalIndex::new(&intervals);
    let mut dominant_equivalent = KeptEquivalentEvidence::default();
    let mut retained = vec![false; group.len()];
    let mut pending_retained: Vec<(f64, usize)> = Vec::new();
    let mut dominant_cursor = 0usize;
    for &(priority, index) in &prioritized {
        // Epsilon ties are pairwise, not transitive. Promote each retained
        // match into the suppressing index only when it is independently more
        // than epsilon above the current candidate. An unrelated higher match
        // therefore cannot split two directly conflicting tied candidates.
        while let Some(&(retained_priority, retained_index)) = pending_retained.get(dominant_cursor)
        {
            if priorities_tie(retained_priority, priority) {
                break;
            }
            dominant_containment.insert(intervals[retained_index]);
            dominant_equivalent.insert(&group[retained_index], intervals[retained_index]);
            dominant_cursor += 1;
        }

        let interval = intervals[index];
        retained[index] = !dominant_containment.has_containment_conflict(interval)
            && !dominant_equivalent.overlaps(&group[index], interval);
        if retained[index] {
            pending_retained.push((priority, index));
        }
    }

    retained_in_direct_conflict_order(group, retained, &priorities)
}

struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<u8>,
}

impl DisjointSet {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            rank: vec![0; len],
        }
    }

    fn find(&mut self, index: usize) -> usize {
        if self.parent[index] != index {
            self.parent[index] = self.find(self.parent[index]);
        }
        self.parent[index]
    }

    fn union(&mut self, left: usize, right: usize) -> usize {
        let mut left_root = self.find(left);
        let mut right_root = self.find(right);
        if left_root == right_root {
            return left_root;
        }
        if self.rank[left_root] < self.rank[right_root] {
            std::mem::swap(&mut left_root, &mut right_root);
        }
        self.parent[right_root] = left_root;
        if self.rank[left_root] == self.rank[right_root] {
            self.rank[left_root] = self.rank[left_root].saturating_add(1);
        }
        left_root
    }
}

/// Preserve coordinate order between independent findings while retaining the
/// established priority order among tied direct conflicts. Ordinary partial
/// overlap is not a conflict, so it cannot drag an unrelated finding into a
/// priority-sorted component.
fn retained_in_direct_conflict_order(
    group: Vec<RawMatch>,
    retained: Vec<bool>,
    priorities: &[f64],
) -> Vec<RawMatch> {
    let intervals: Vec<MatchInterval> = group.iter().map(MatchInterval::from_match).collect();
    let retained_indices: Vec<usize> = retained
        .iter()
        .enumerate()
        .filter_map(|(index, &keep)| keep.then_some(index))
        .collect();
    if retained_indices.len() <= SINGLE_MATCH_COUNT {
        return group
            .into_iter()
            .enumerate()
            .filter_map(|(index, matched)| retained[index].then_some(matched))
            .collect();
    }

    let mut components = DisjointSet::new(group.len());

    // With start ascending and end descending, a processed interval can only
    // contain the current interval, not the reverse. One active entry is kept
    // per current component, keyed by its largest end. Every entry at or beyond
    // the current end therefore has a concrete containing interval. Removing
    // and merging those entries is amortized O(n log n).
    let mut containment_order = retained_indices.clone();
    containment_order.sort_by(|&left, &right| {
        intervals[left]
            .start
            .cmp(&intervals[right].start)
            .then_with(|| intervals[right].end.cmp(&intervals[left].end))
            .then_with(|| group[left].cmp(&group[right]))
    });
    let mut active_by_max_end: BTreeMap<usize, usize> = BTreeMap::new();
    for index in containment_order {
        let interval = intervals[index];
        if interval.is_empty() {
            continue;
        }
        let containing = active_by_max_end.split_off(&interval.end);
        let mut root = index;
        let mut max_end = interval.end;
        for (component_end, other) in containing {
            root = components.union(root, other);
            max_end = max_end.max(component_end);
        }
        active_by_max_end.insert(max_end, root);
    }

    // Equal credential evidence conflicts on strict overlap even when neither
    // span contains the other. Connecting each interval to the current
    // farthest-reaching interval produces the exact overlap components without
    // enumerating every pair.
    let mut equivalent: HashMap<
        (keyhog_core::CredentialHash, keyhog_core::SensitiveString),
        Vec<usize>,
    > = HashMap::new();
    for &index in &retained_indices {
        if !intervals[index].is_empty() {
            equivalent
                .entry((
                    group[index].credential_hash,
                    group[index].credential.clone(),
                ))
                .or_default()
                .push(index);
        }
    }
    for indices in equivalent.values_mut() {
        indices.sort_by(|&left, &right| {
            intervals[left]
                .start
                .cmp(&intervals[right].start)
                .then_with(|| intervals[right].end.cmp(&intervals[left].end))
                .then_with(|| group[left].cmp(&group[right]))
        });
        let mut run_representative = None;
        let mut run_max_end = 0usize;
        for &index in indices.iter() {
            let interval = intervals[index];
            if let Some(representative) = run_representative {
                if interval.start < run_max_end {
                    components.union(index, representative);
                    if interval.end > run_max_end {
                        run_representative = Some(index);
                        run_max_end = interval.end;
                    }
                    continue;
                }
            }
            run_representative = Some(index);
            run_max_end = interval.end;
        }
    }

    let mut slots_by_component: HashMap<usize, Vec<usize>> = HashMap::new();
    for &index in &retained_indices {
        let root = components.find(index);
        slots_by_component.entry(root).or_default().push(index);
    }
    let mut source_for_slot = vec![None; group.len()];
    for slots in slots_by_component.values() {
        let mut members = slots.clone();
        members.sort_by(|&left, &right| {
            priorities[right]
                .total_cmp(&priorities[left])
                .then_with(|| group[left].cmp(&group[right]))
        });
        for (&slot, member) in slots.iter().zip(members) {
            source_for_slot[slot] = Some(member);
        }
    }

    let mut rows: Vec<Option<RawMatch>> = group.into_iter().map(Some).collect();
    retained_indices
        .into_iter()
        .map(|slot| {
            rows[source_for_slot[slot].expect("retained direct-conflict slot has a source")]
                .take()
                .expect("direct-conflict source is used exactly once")
        })
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
