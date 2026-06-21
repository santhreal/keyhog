use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::known_example_suppressed;

#[test]
fn todo_marker_suppresses() {
    assert!(known_example_suppressed(
        "TODO_replace_with_real_key",
        None,
        CodeContext::Comment,
    ));
}
