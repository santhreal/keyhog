use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn iam_role_arn_suppressed() {
    assert!(known_example_suppressed(
        "arn:aws:iam::123456789012:role/ReadOnly",
        None,
        CodeContext::Unknown,
    ));
}
