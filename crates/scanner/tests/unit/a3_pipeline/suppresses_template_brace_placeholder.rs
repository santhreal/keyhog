use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn brace_template_suppressed() {
    assert!(known_example_suppressed(
        "{API_TOKEN}",
        None,
        CodeContext::Assignment,
    ));
}
