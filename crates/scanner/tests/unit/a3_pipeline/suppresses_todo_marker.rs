use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

#[test]
fn todo_marker_suppresses() {
    assert!(should_suppress_known_example_credential(
        "TODO_replace_with_real_key",
        None,
        CodeContext::Comment,
    ));
}
