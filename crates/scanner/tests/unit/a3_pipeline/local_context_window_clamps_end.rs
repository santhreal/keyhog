use keyhog_scanner::pipeline::local_context_window;

#[test]
fn context_window_stops_at_last_line() {
    let text = "one\ntwo\nthree";
    let window = local_context_window(text, 3, 5);
    assert!(window.ends_with("three"));
}
