//! Lines with string quotes infer StringLiteral when not assignment.

use keyhog_scanner::context::{infer_context, CodeContext};

#[test]
fn context_string_literal_detects_quotes() {
    let lines = vec![r#"    log("configured")"#];
    assert_eq!(
        infer_context(&lines, 0, None),
        CodeContext::StringLiteral,
        "quoted call argument without assignment is a string literal context"
    );
}
