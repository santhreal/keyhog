use keyhog_scanner::testing::compute_line_offsets;

#[test]
fn trailing_newline_adds_final_line_offset() {
    let offsets = compute_line_offsets("a\nb\n");
    assert_eq!(offsets, vec![0, 2, 4]);
}
