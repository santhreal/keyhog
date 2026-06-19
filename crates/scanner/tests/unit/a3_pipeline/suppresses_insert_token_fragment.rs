use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn insert_fragment_suppresses() {
    assert!(should_suppress_known_example_credential(
        "INSERT_YOUR_TOKEN",
        None,
        CodeContext::Assignment,
    ));
}
