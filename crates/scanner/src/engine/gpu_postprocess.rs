//! Shared post-processing for GPU phase-1 outputs.
//!
//! `gpu_ac_phase1` and `gpu_literal_phase1` previously ended with two
//! byte-identical blocks:
//!
//! 1. Sort `LiteralMatch` by `(pid, start, end)`, fold same-pid
//!    overlapping spans in-place, re-sort by `start`.
//! 2. Walk the coalesce `entries` and attribute each global match to
//!    a chunk-local `(pid, local_start, local_end)`.
//!
//! Two copies of the same loop in two different files. Per the
//! repo-wide dedup audit, that's the kind of "helper duplicated per
//! walker" pattern that grows into 8 versions of pack_u32. The
//! consolidation here lets the two phase-1 callers focus on the
//! GPU-specific dispatch path and share the host-side fold/attribute
//! tail without drift.

use vyre_libs::scan::LiteralMatch;

/// Sort by `(pid, start, end)`, fold same-pid overlapping spans, then
/// re-sort by `start`. The downstream chunk-attribution walk expects
/// matches in start-ascending order; the per-pid fold collapses the
/// duplicate `(pid, start, end)` triples that subgroup-ballot can
/// emit when a hit straddles a workgroup boundary.
pub(crate) fn fold_overlapping_same_pid_inplace(matches: &mut Vec<LiteralMatch>) {
    matches.sort_unstable_by(|a, b| {
        a.pattern_id
            .cmp(&b.pattern_id)
            .then(a.start.cmp(&b.start))
            .then(a.end.cmp(&b.end))
    });
    let mut write = 0;
    for read in 1..matches.len() {
        if matches[read].pattern_id == matches[write].pattern_id
            && matches[read].start <= matches[write].end
        {
            if matches[read].end > matches[write].end {
                matches[write] = LiteralMatch::new(
                    matches[write].pattern_id,
                    matches[write].start,
                    matches[read].end,
                );
            }
        } else {
            write += 1;
            matches[write] = matches[read];
        }
    }
    if !matches.is_empty() {
        matches.truncate(write + 1);
    }
    matches.sort_unstable_by_key(|matched| matched.start);
}

/// Attribute each global GPU match to its source chunk using the
/// coalesce-entry table `(chunk_index, offset, len)`. Matches that
/// straddle a chunk boundary are dropped (the coalesce separator
/// makes a true cross-chunk hit impossible; this skip is the safety
/// net for any pid > `total_patterns` smuggled through).
///
/// `entries` MUST be ordered by `offset` ascending (the coalesce
/// builder produces them that way). `matches` MUST be sorted by
/// `start` ascending (call `fold_overlapping_same_pid_inplace` first).
pub(crate) fn attribute_matches_to_chunks(
    matches: &[LiteralMatch],
    entries: &[(usize, usize, usize)],
    total_patterns: usize,
    chunk_count: usize,
) -> Vec<Vec<(u32, u32, u32)>> {
    let mut per_chunk_hits: Vec<Vec<(u32, u32, u32)>> =
        (0..chunk_count).map(|_| Vec::new()).collect();
    let mut cursor = 0usize;
    for matched in matches {
        let global_start = matched.start as usize;
        let global_end = matched.end as usize;
        while cursor < entries.len() {
            let (_, offset, len) = entries[cursor];
            if global_start < offset + len {
                break;
            }
            cursor += 1;
        }
        if cursor >= entries.len() {
            break;
        }
        let (chunk_index, offset, len) = entries[cursor];
        if global_start < offset || global_end > offset + len {
            continue;
        }
        let pattern_index = matched.pattern_id as usize;
        if pattern_index < total_patterns {
            let local_start = (global_start - offset) as u32;
            let local_end = (global_end - offset) as u32;
            per_chunk_hits[chunk_index].push((matched.pattern_id, local_start, local_end));
        }
    }
    per_chunk_hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_collapses_same_pid_overlap() {
        let mut matches = vec![
            LiteralMatch::new(1, 10, 20),
            LiteralMatch::new(1, 15, 25),
            LiteralMatch::new(2, 30, 35),
        ];
        fold_overlapping_same_pid_inplace(&mut matches);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].pattern_id, 1);
        assert_eq!(matches[0].start, 10);
        assert_eq!(matches[0].end, 25);
        assert_eq!(matches[1].pattern_id, 2);
    }

    #[test]
    fn fold_keeps_distinct_pids_with_same_range() {
        let mut matches = vec![LiteralMatch::new(1, 10, 20), LiteralMatch::new(2, 10, 20)];
        fold_overlapping_same_pid_inplace(&mut matches);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn attribute_routes_to_correct_chunk() {
        let entries = vec![(0, 0, 100), (1, 108, 50), (2, 166, 80)];
        let matches = vec![
            LiteralMatch::new(7, 50, 60),
            LiteralMatch::new(7, 120, 130),
            LiteralMatch::new(7, 200, 210),
        ];
        let per_chunk = attribute_matches_to_chunks(&matches, &entries, 10, 3);
        assert_eq!(per_chunk[0], vec![(7, 50, 60)]);
        assert_eq!(per_chunk[1], vec![(7, 12, 22)]);
        assert_eq!(per_chunk[2], vec![(7, 34, 44)]);
    }

    #[test]
    fn attribute_drops_cross_boundary_match() {
        let entries = vec![(0, 0, 100), (1, 108, 50)];
        let matches = vec![LiteralMatch::new(7, 95, 110)];
        let per_chunk = attribute_matches_to_chunks(&matches, &entries, 10, 2);
        assert!(per_chunk[0].is_empty());
        assert!(per_chunk[1].is_empty());
    }

    #[test]
    fn attribute_drops_unknown_pid() {
        let entries = vec![(0, 0, 100)];
        let matches = vec![LiteralMatch::new(999, 10, 20)];
        let per_chunk = attribute_matches_to_chunks(&matches, &entries, 10, 1);
        assert!(per_chunk[0].is_empty());
    }
}
