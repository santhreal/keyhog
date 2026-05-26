//! Path component `tests/` forces TestCode context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_test_directory_component() {
    let lines = vec!["export API_KEY=sk-live-123"];
    assert_eq!(
        infer_context(&lines, 0, Some("tests/fixtures/config.env")),
        CodeContext::TestCode,
        "any path under tests/ directory is test context"
    );
}
