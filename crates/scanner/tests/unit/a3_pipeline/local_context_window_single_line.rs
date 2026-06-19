use keyhog_scanner::testing::local_context_window;

#[test]
fn radius_zero_returns_single_line() {
    let text = "first\nsecond\nthird";
    assert_eq!(local_context_window(text, 2, 0), "second");
}
