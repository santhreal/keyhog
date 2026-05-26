use keyhog_scanner::compute_line_offsets;

#[test]
fn two_line_file_has_two_starts() {
    let offsets = compute_line_offsets("alpha\nbeta");
    assert_eq!(offsets, vec![0, 6]);
}
