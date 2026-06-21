use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn insert_fragment_suppresses() {
    assert!(known_example_suppressed(
        "INSERT_YOUR_TOKEN",
        None,
        CodeContext::Assignment,
    ));
}
