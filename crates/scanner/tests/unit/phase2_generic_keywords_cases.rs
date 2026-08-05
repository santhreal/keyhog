use super::collect_generic_keyword_lines_from_positions;

#[test]
fn maps_positions_to_line_indexes_sorted_deduped() {
    // Three lines starting at byte 0, 10, 25.
    let line_offsets = [0usize, 10, 25];
    let positions = [0u32, 5, 10, 24, 25, 30];
    let mut out = Vec::new();
    collect_generic_keyword_lines_from_positions(&line_offsets, &positions, &mut out);
    assert_eq!(out, vec![0, 1, 2]);
}

#[test]
fn positions_within_one_line_dedup_to_that_line() {
    let line_offsets = [0usize, 10, 25];
    let positions = [10u32, 12, 20, 24];
    let mut out = Vec::new();
    collect_generic_keyword_lines_from_positions(&line_offsets, &positions, &mut out);
    assert_eq!(out, vec![1]);
}

#[test]
fn empty_line_offsets_yields_empty() {
    let mut out = vec![7, 8, 9];
    collect_generic_keyword_lines_from_positions(&[], &[3u32], &mut out);
    assert!(out.is_empty());
}
