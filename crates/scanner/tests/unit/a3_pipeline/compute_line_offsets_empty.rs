use keyhog_scanner::compute_line_offsets;

#[test]
fn empty_string_yields_single_zero_offset() {
    assert_eq!(compute_line_offsets(""), vec![0]);
}
