use keyhog_scanner::testing::compute_line_offsets;

#[test]
fn single_line_has_one_offset_at_zero() {
    assert_eq!(compute_line_offsets("hello"), vec![0]);
}
