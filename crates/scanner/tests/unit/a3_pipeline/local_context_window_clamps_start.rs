use keyhog_scanner::pipeline::local_context_window;

#[test]
fn context_window_does_not_go_before_first_line() {
    let text = "one\ntwo\nthree";
    let window = local_context_window(text, 1, 5);
    assert!(window.starts_with("one"));
    assert!(!window.contains("\nzero\n"));
}
