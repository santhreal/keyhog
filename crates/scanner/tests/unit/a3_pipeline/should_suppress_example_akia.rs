use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn aws_example_key_suppressed_in_assignment() {
    assert!(known_example_suppressed(
        concat!("AK", "IAIOSFODNN7EXAMPLE"),
        None,
        CodeContext::Assignment,
    ));
}
