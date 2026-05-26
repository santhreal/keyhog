use keyhog_scanner::compute_line_offsets;

#[test]
fn empty_lines_still_record_starts() {
    let offsets = compute_line_offsets("\n\n\n");
    assert_eq!(offsets.len(), 4);
    assert_eq!(offsets[0], 0);
}
