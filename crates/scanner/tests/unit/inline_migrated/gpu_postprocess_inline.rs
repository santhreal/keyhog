//! Migrated from src/engine/gpu_postprocess.rs
use keyhog_scanner::testing::{attribute_matches_to_chunks, fold_overlapping_same_pid_inplace};
use vyre_libs::scan::LiteralMatch;

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
fn fold_empty_input() {
    let mut matches: Vec<LiteralMatch> = vec![];
    fold_overlapping_same_pid_inplace(&mut matches);
    assert!(matches.is_empty());
}

#[test]
fn fold_single_match() {
    let mut matches = vec![LiteralMatch::new(1, 10, 20)];
    fold_overlapping_same_pid_inplace(&mut matches);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start, 10);
    assert_eq!(matches[0].end, 20);
}

#[test]
fn fold_exact_duplicates() {
    let mut matches = vec![
        LiteralMatch::new(1, 10, 20),
        LiteralMatch::new(1, 10, 20),
        LiteralMatch::new(1, 10, 20),
    ];
    fold_overlapping_same_pid_inplace(&mut matches);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start, 10);
    assert_eq!(matches[0].end, 20);
}

#[test]
fn fold_touching_spans_same_pid_merge() {
    // Touching spans (end of one == start of next) should merge.
    let mut matches = vec![LiteralMatch::new(1, 10, 20), LiteralMatch::new(1, 20, 30)];
    fold_overlapping_same_pid_inplace(&mut matches);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start, 10);
    assert_eq!(matches[0].end, 30);
}

#[test]
fn fold_non_touching_spans_same_pid_stay_separate() {
    // Gap between spans: should NOT merge.
    let mut matches = vec![LiteralMatch::new(1, 10, 20), LiteralMatch::new(1, 21, 30)];
    fold_overlapping_same_pid_inplace(&mut matches);
    assert_eq!(matches.len(), 2);
}

#[test]
fn fold_three_way_chain_merge() {
    // Three overlapping spans should merge into one.
    let mut matches = vec![
        LiteralMatch::new(1, 10, 20),
        LiteralMatch::new(1, 15, 25),
        LiteralMatch::new(1, 22, 35),
    ];
    fold_overlapping_same_pid_inplace(&mut matches);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].start, 10);
    assert_eq!(matches[0].end, 35);
}

#[test]
fn fold_unsorted_input_still_works() {
    // Input in reverse order: the sort should fix it.
    let mut matches = vec![
        LiteralMatch::new(1, 30, 40),
        LiteralMatch::new(1, 10, 20),
        LiteralMatch::new(1, 15, 25),
    ];
    fold_overlapping_same_pid_inplace(&mut matches);
    assert_eq!(matches.len(), 2);
    // After fold + re-sort by start:
    assert_eq!(matches[0].start, 10);
    assert_eq!(matches[0].end, 25);
    assert_eq!(matches[1].start, 30);
    assert_eq!(matches[1].end, 40);
}

#[test]
fn fold_output_sorted_by_start() {
    // Multiple PIDs with interleaved start offsets.
    let mut matches = vec![
        LiteralMatch::new(2, 50, 60),
        LiteralMatch::new(1, 10, 20),
        LiteralMatch::new(2, 5, 15),
    ];
    fold_overlapping_same_pid_inplace(&mut matches);
    // Output should be sorted by start.
    for w in matches.windows(2) {
        assert!(w[0].start <= w[1].start, "output not sorted by start");
    }
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

#[test]
fn attribute_empty_matches_returns_empty_chunks() {
    let entries = vec![(0, 0, 100), (1, 108, 50)];
    let matches: Vec<LiteralMatch> = vec![];
    let per_chunk = attribute_matches_to_chunks(&matches, &entries, 10, 2);
    assert!(per_chunk[0].is_empty());
    assert!(per_chunk[1].is_empty());
}

#[test]
fn attribute_empty_entries_returns_empty_chunks() {
    let entries: Vec<(usize, usize, usize)> = vec![];
    let matches = vec![LiteralMatch::new(1, 10, 20)];
    let per_chunk = attribute_matches_to_chunks(&matches, &entries, 10, 0);
    assert!(per_chunk.is_empty());
}

#[test]
fn attribute_match_at_chunk_boundary() {
    // Match exactly at the start of a chunk.
    let entries = vec![(0, 0, 100), (1, 108, 50)];
    let matches = vec![LiteralMatch::new(1, 108, 118)];
    let per_chunk = attribute_matches_to_chunks(&matches, &entries, 10, 2);
    assert_eq!(per_chunk[1], vec![(1, 0, 10)]);
}

#[test]
fn attribute_match_at_chunk_end() {
    // Match exactly at the end of a chunk.
    let entries = vec![(0, 0, 100)];
    let matches = vec![LiteralMatch::new(1, 90, 100)];
    let per_chunk = attribute_matches_to_chunks(&matches, &entries, 10, 1);
    assert_eq!(per_chunk[0], vec![(1, 90, 100)]);
}
