//! Path component `fixtures/` forces TestCode context.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_fixtures_directory() {
    let lines = vec!["SECRET=placeholder"];
    assert_eq!(
        infer_context(&lines, 0, Some("data/fixtures/sample.env")),
        CodeContext::TestCode,
        "fixtures/ directory marks test context"
    );
}
