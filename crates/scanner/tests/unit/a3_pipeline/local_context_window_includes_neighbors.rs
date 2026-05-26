use keyhog_scanner::pipeline::local_context_window;

#[test]
fn radius_one_includes_adjacent_lines() {
    let text = "a\nb\nc";
    assert_eq!(local_context_window(text, 2, 1), "a\nb\nc");
}
