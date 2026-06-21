use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn html_color_code_suppressed() {
    assert!(known_example_suppressed(
        "#AABBCC",
        None,
        CodeContext::Unknown,
    ));
}
